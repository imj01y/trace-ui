use std::io::Write;

use crate::api_types::{ExportConfig, SliceOptions, SliceResult};
use crate::error::{Result, TraceError};
use crate::flat::line_index::LineIndexView;
use crate::flat::mem_last_def::MemLastDefView;
use crate::query::slice::{bfs_slice, bfs_slice_with_options};
use crate::scanner::{RegLastDef, PAIR_HALF2_BIT, PAIR_SHARED_BIT};
use crate::session::SliceOrigin;
use super::TraceEngine;
use trace_parser::types::{parse_reg, RegId, TraceFormat};
use trace_parser::insn_class::InsnClass;
use trace_parser::{parser, insn_class, def_use};
use trace_parser::gumtrace as gumtrace_parser;
use trace_parser::qbdi as qbdi_parser;

const MAX_RESOLVE_SCAN: u32 = 50000;

/// 解析 from_spec 字符串并找到 BFS 起点行号
pub(crate) fn resolve_start_index(
    spec: &str,
    reg_last_def: &RegLastDef,
    mem_last_def: &MemLastDefView,
    mmap: &[u8],
    line_index: &LineIndexView<'_>,
    format: TraceFormat,
) -> std::result::Result<u32, String> {
    if let Some(rest) = spec.strip_prefix("reg:") {
        let (name, suffix) = rest.rsplit_once('@')
            .ok_or_else(|| format!("缺少 @ 分隔符: {}", spec))?;
        let reg = parse_reg(&name.to_lowercase())
            .ok_or_else(|| format!("未知寄存器: {}", name))?;

        if suffix == "last" {
            reg_last_def.get(&reg)
                .copied()
                .ok_or_else(|| format!("寄存器 {} 在 trace 中从未被定义", name))
        } else {
            let line: u32 = suffix.parse::<u32>()
                .map_err(|_| format!("无效行号: {}", suffix))?
                .checked_sub(1)
                .ok_or("行号必须 >= 1".to_string())?;
            resolve_reg_def(reg, line, mmap, line_index, format)
        }
    } else if let Some(rest) = spec.strip_prefix("mem:") {
        let (addr_str, suffix) = rest.rsplit_once('@')
            .ok_or_else(|| format!("缺少 @ 分隔符: {}", spec))?;
        let addr_hex = addr_str.strip_prefix("0x").unwrap_or(addr_str);
        // Strip optional ":SIZE" suffix (e.g. "bffff010:4" -> "bffff010")
        let addr_hex = addr_hex.split(':').next().unwrap_or(addr_hex);
        let addr = u64::from_str_radix(addr_hex, 16)
            .map_err(|_| format!("无效十六进制地址: {}", addr_str))?;

        if suffix == "last" {
            mem_last_def.get(&addr)
                .map(|(line, _)| line)
                .ok_or_else(|| format!("地址 0x{:x} 在 trace 中从未被写入", addr))
        } else {
            let line: u32 = suffix.parse::<u32>()
                .map_err(|_| format!("无效行号: {}", suffix))?
                .checked_sub(1)
                .ok_or("行号必须 >= 1".to_string())?;
            resolve_mem_store(addr, line, mmap, line_index, format)
        }
    } else {
        Err(format!("不支持的 spec 格式: {} (需要 reg:NAME@... 或 mem:ADDR@...)", spec))
    }
}

fn resolve_reg_def(
    target_reg: RegId,
    from_line: u32,
    mmap: &[u8],
    line_index: &LineIndexView<'_>,
    format: TraceFormat,
) -> std::result::Result<u32, String> {
    let scan_start = from_line.saturating_sub(MAX_RESOLVE_SCAN);
    for s in (scan_start..=from_line).rev() {
        if let Some(raw) = line_index.get_line(mmap, s) {
            if let Ok(line_str) = std::str::from_utf8(raw) {
                let parsed = match format {
                    TraceFormat::Unidbg => parser::parse_line(line_str),
                    TraceFormat::Gumtrace => gumtrace_parser::parse_line_gumtrace(line_str),
                    TraceFormat::Qbdi => qbdi_parser::parse_line_qbdi(line_str),
                };
                if let Some(parsed) = parsed {
                    let cls = insn_class::classify_and_refine(&parsed);
                    let (defs, _) = def_use::determine_def_use(cls, &parsed);
                    if defs.iter().any(|r| *r == target_reg) {
                        // For pair instructions, tag the line number with the
                        // correct half bit so BFS follows the right dependencies.
                        // This mirrors the logic in scanner.rs Step 4.
                        if cls == InsnClass::LoadPair {
                            let has_base_wb = parsed.writeback && parsed.base_reg.is_some();
                            let data_defs = if has_base_wb { &defs[..defs.len() - 1] } else { &defs[..] };
                            let mid = data_defs.len() / 2;
                            if data_defs[mid..].iter().any(|r| *r == target_reg) {
                                return Ok(s | PAIR_HALF2_BIT);
                            }
                            if has_base_wb && defs.last() == Some(&target_reg) {
                                return Ok(s | PAIR_SHARED_BIT);
                            }
                        } else if cls == InsnClass::StorePair {
                            return Ok(s | PAIR_SHARED_BIT);
                        }
                        return Ok(s);
                    }
                }
            }
        }
    }
    Err(format!("在 {} 行范围内未找到寄存器 {:?} 的 DEF", MAX_RESOLVE_SCAN, target_reg))
}

fn resolve_mem_store(
    target_addr: u64,
    from_line: u32,
    mmap: &[u8],
    line_index: &LineIndexView<'_>,
    format: TraceFormat,
) -> std::result::Result<u32, String> {
    let scan_start = from_line.saturating_sub(MAX_RESOLVE_SCAN);
    for s in (scan_start..=from_line).rev() {
        if let Some(raw) = line_index.get_line(mmap, s) {
            if let Ok(line_str) = std::str::from_utf8(raw) {
                let parsed = match format {
                    TraceFormat::Unidbg => parser::parse_line(line_str),
                    TraceFormat::Gumtrace => gumtrace_parser::parse_line_gumtrace(line_str),
                    TraceFormat::Qbdi => qbdi_parser::parse_line_qbdi(line_str),
                };
                if let Some(parsed) = parsed {
                    if let Some(ref mem) = parsed.mem_op {
                        if mem.is_write {
                            let width = mem.elem_width as u64;
                            if (0..width).any(|off| mem.abs + off == target_addr) {
                                return Ok(s);
                            }
                        }
                    }
                }
            }
        }
    }
    Err(format!("在 {} 行范围内未找到地址 0x{:x} 的 STORE", MAX_RESOLVE_SCAN, target_addr))
}

impl TraceEngine {
    pub fn run_slice(
        &self,
        session_id: &str,
        from_specs: &[String],
        options: SliceOptions,
    ) -> Result<SliceResult> {
        // Phase 1: read lock — resolve specs, run BFS, apply range filter
        let marked = {
            let handle = self.get_handle(session_id)?;
            let state = handle.state.read()
                .map_err(|e| TraceError::Internal(e.to_string()))?;

            let reg_last_def = state.reg_last_def.as_ref()
                .ok_or(TraceError::IndexNotReady)?;
            let mem_last_def = state.mem_last_def_view()
                .ok_or(TraceError::IndexNotReady)?;
            let scan_view = state.scan_view()
                .ok_or(TraceError::IndexNotReady)?;
            let format = state.trace_format;

            let mut start_indices = Vec::new();
            for spec in from_specs {
                let lidx_view = state.line_index_view()
                    .ok_or(TraceError::IndexNotReady)?;
                let idx = resolve_start_index(
                    spec,
                    reg_last_def,
                    &mem_last_def,
                    &state.mmap,
                    &lidx_view,
                    format,
                ).map_err(|e| TraceError::InvalidArgument(e))?;
                start_indices.push(idx);
            }

            let mut marked = if options.data_only {
                bfs_slice_with_options(&scan_view, &start_indices, true)
            } else {
                bfs_slice(&scan_view, &start_indices)
            };

            // Apply optional range filter
            if let Some(s) = options.start_seq {
                let end = (s as usize).min(marked.len());
                marked[..end].fill(false);
            }
            if let Some(e) = options.end_seq {
                let start = ((e as usize) + 1).min(marked.len());
                marked[start..].fill(false);
            }

            marked
        };

        let marked_count = marked.count_ones() as u32;
        let total_lines = marked.len() as u32;
        let percentage = if total_lines > 0 {
            marked_count as f64 / total_lines as f64 * 100.0
        } else {
            0.0
        };

        // Phase 2: write lock — store result + slice_origin
        {
            let handle = self.get_handle(session_id)?;
            let mut state = handle.state.write()
                .map_err(|e| TraceError::Internal(e.to_string()))?;
            state.slice_result = Some(marked);
            state.slice_origin = Some(SliceOrigin {
                from_specs: from_specs.to_vec(),
                data_only: options.data_only,
                start_seq: options.start_seq,
                end_seq: options.end_seq,
            });
        }

        Ok(SliceResult { marked_count, total_lines, percentage })
    }

    pub fn clear_slice(&self, session_id: &str) -> Result<()> {
        let handle = self.get_handle(session_id)?;
        let mut state = handle.state.write()
            .map_err(|e| TraceError::Internal(e.to_string()))?;
        state.slice_result = None;
        state.slice_origin = None;
        Ok(())
    }

    pub fn get_slice_origin(&self, session_id: &str) -> Result<Option<SliceOrigin>> {
        let handle = self.get_handle(session_id)?;
        let state = handle.state.read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;
        Ok(state.slice_origin.clone())
    }

    pub fn get_tainted_seqs(&self, session_id: &str) -> Result<Vec<u32>> {
        let handle = self.get_handle(session_id)?;
        let state = handle.state.read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;

        match &state.slice_result {
            Some(marked) => Ok(marked.iter_ones().map(|i| i as u32).collect()),
            None => Ok(vec![]),
        }
    }

    pub fn get_slice_status(
        &self,
        session_id: &str,
        start_seq: u32,
        count: u32,
    ) -> Result<Vec<bool>> {
        let handle = self.get_handle(session_id)?;
        let state = handle.state.read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;

        match &state.slice_result {
            Some(marked) => {
                let total = marked.len() as u32;
                let end = (start_seq + count).min(total);
                Ok((start_seq..end).map(|i| marked[i as usize]).collect())
            }
            None => Ok(vec![false; count as usize]),
        }
    }

    pub fn export_taint_results(
        &self,
        session_id: &str,
        output_path: &str,
        format: &str,
        config: ExportConfig,
    ) -> Result<()> {
        let handle = self.get_handle(session_id)?;
        let state = handle.state.read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;

        let marked = state.slice_result.as_ref()
            .ok_or_else(|| TraceError::InvalidArgument("没有活跃的污点分析结果".to_string()))?;
        let line_index = state.line_index_view()
            .ok_or(TraceError::IndexNotReady)?;

        // Fallback: if from_specs is empty, use stored slice_origin
        let actual_from_specs = if config.from_specs.is_empty() {
            state.slice_origin.as_ref()
                .map(|o| o.from_specs.clone())
                .unwrap_or_default()
        } else {
            config.from_specs
        };

        let marked_count = marked.count_ones() as u32;
        let total_lines = marked.len() as u32;

        let file = std::fs::File::create(output_path)
            .map_err(|e| TraceError::Io(e))?;
        let mut writer = std::io::BufWriter::new(file);

        if format == "json" {
            // 收集污点行
            let mut tainted_lines = Vec::with_capacity(marked_count as usize);
            for seq in marked.iter_ones() {
                if let Some(raw) = line_index.get_line(&state.mmap, seq as u32) {
                    let text = String::from_utf8_lossy(raw);
                    tainted_lines.push(serde_json::json!({
                        "seq": seq + 1,
                        "text": text.as_ref(),
                    }));
                }
            }

            let percentage = if total_lines > 0 {
                marked_count as f64 / total_lines as f64 * 100.0
            } else {
                0.0
            };

            let json = serde_json::json!({
                "source": {
                    "file": state.file_path,
                    "totalLines": total_lines,
                },
                "config": {
                    "fromSpecs": actual_from_specs,
                    "startSeq": config.start_seq,
                    "endSeq": config.end_seq,
                },
                "stats": {
                    "markedCount": marked_count,
                    "percentage": percentage,
                },
                "taintedLines": tainted_lines,
            });

            serde_json::to_writer_pretty(&mut writer, &json)
                .map_err(|e| TraceError::Internal(format!("JSON 写入失败: {}", e)))?;
        } else {
            // TXT: 纯污点行原文
            for seq in marked.iter_ones() {
                if let Some(raw) = line_index.get_line(&state.mmap, seq as u32) {
                    writer.write_all(raw)
                        .map_err(|e| TraceError::Io(e))?;
                    writer.write_all(b"\n")
                        .map_err(|e| TraceError::Io(e))?;
                }
            }
        }

        writer.flush().map_err(|e| TraceError::Io(e))?;
        Ok(())
    }
}
