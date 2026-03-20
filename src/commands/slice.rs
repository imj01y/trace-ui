use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager, State};
use crate::state::AppState;
use crate::taint::types::{parse_reg, TraceFormat};
use crate::taint::def_use::determine_def_use;
use crate::taint::insn_class;
use crate::taint::parser;
use crate::taint::gumtrace_parser;
use crate::taint::slicer;

const MAX_RESOLVE_SCAN: u32 = 50000;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SliceResult {
    pub marked_count: u32,
    pub total_lines: u32,
    pub percentage: f64,
}

/// 解析 from_spec 字符串并找到 BFS 起点行号
pub fn resolve_start_index(
    spec: &str,
    reg_last_def: &crate::taint::scanner::RegLastDef,
    mem_last_def: &crate::flat::mem_last_def::MemLastDefView,
    mmap: &[u8],
    line_index: &crate::flat::line_index::LineIndexView<'_>,
    format: TraceFormat,
) -> Result<u32, String> {
    if let Some(rest) = spec.strip_prefix("reg:") {
        let (name, suffix) = rest.rsplit_once('@')
            .ok_or_else(|| format!("缺少 @ 分隔符: {}", spec))?;
        let reg = parse_reg(name)
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
    target_reg: crate::taint::types::RegId,
    from_line: u32,
    mmap: &[u8],
    line_index: &crate::flat::line_index::LineIndexView<'_>,
    format: TraceFormat,
) -> Result<u32, String> {
    let scan_start = from_line.saturating_sub(MAX_RESOLVE_SCAN);
    for s in (scan_start..=from_line).rev() {
        if let Some(raw) = line_index.get_line(mmap, s) {
            if let Ok(line_str) = std::str::from_utf8(raw) {
                let parsed = match format {
                    TraceFormat::Unidbg => parser::parse_line(line_str),
                    TraceFormat::Gumtrace => gumtrace_parser::parse_line_gumtrace(line_str),
                };
                if let Some(parsed) = parsed {
                    let cls = insn_class::classify_and_refine(&parsed);
                    let (defs, _) = determine_def_use(cls, &parsed);
                    if defs.iter().any(|r| *r == target_reg) {
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
    line_index: &crate::flat::line_index::LineIndexView<'_>,
    format: TraceFormat,
) -> Result<u32, String> {
    let scan_start = from_line.saturating_sub(MAX_RESOLVE_SCAN);
    for s in (scan_start..=from_line).rev() {
        if let Some(raw) = line_index.get_line(mmap, s) {
            if let Ok(line_str) = std::str::from_utf8(raw) {
                let parsed = match format {
                    TraceFormat::Unidbg => parser::parse_line(line_str),
                    TraceFormat::Gumtrace => gumtrace_parser::parse_line_gumtrace(line_str),
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

fn run_slice_inner(
    session_id: &str,
    from_specs: &[String],
    start_seq: Option<u32>,
    end_seq: Option<u32>,
    data_only: bool,
    state: &AppState,
) -> Result<SliceResult, String> {
    // Phase 1: read lock - resolve specs and run BFS (read-only)
    let marked = {
        let sessions = state.sessions.read().map_err(|e| e.to_string())?;
        let session = sessions.get(session_id)
            .ok_or_else(|| format!("Session {} 不存在", session_id))?;
        let reg_last_def = session.reg_last_def.as_ref()
            .ok_or("索引尚未构建完成，请等待构建完成后再执行切片")?;
        let mem_last_def = session.mem_last_def_view()
            .ok_or("索引尚未构建完成，请等待构建完成后再执行切片")?;
        let scan_view = session.scan_view()
            .ok_or("索引尚未构建完成，请等待构建完成后再执行切片")?;

        let format = session.trace_format;
        let mut start_indices = Vec::new();
        for spec in from_specs {
            let lidx_view = session.line_index_view().ok_or_else(|| "索引尚未构建完成".to_string())?;
            let idx = resolve_start_index(spec, reg_last_def, &mem_last_def, &session.mmap, &lidx_view, format)?;
            start_indices.push(idx);
        }

        let mut marked = if data_only {
            slicer::bfs_slice_with_options(&scan_view, &start_indices, true)
        } else {
            slicer::bfs_slice(&scan_view, &start_indices)
        };

        // Apply optional range filter
        if let Some(s) = start_seq {
            let end = (s as usize).min(marked.len());
            marked[..end].fill(false);
        }
        if let Some(e) = end_seq {
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

    // Phase 2: write lock - store result
    {
        let mut sessions = state.sessions.write().map_err(|e| e.to_string())?;
        if let Some(session) = sessions.get_mut(session_id) {
            session.slice_result = Some(marked);
            session.slice_origin = Some(crate::state::SliceOrigin {
                from_specs: from_specs.to_vec(),
                data_only,
            });
        }
    }

    Ok(SliceResult { marked_count, total_lines, percentage })
}

#[tauri::command]
pub async fn run_slice(
    session_id: String,
    from_specs: Vec<String>,
    start_seq: Option<u32>,
    end_seq: Option<u32>,
    data_only: Option<bool>,
    app: AppHandle,
) -> Result<SliceResult, String> {
    let data_only = data_only.unwrap_or(false);
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<AppState>();
        run_slice_inner(&session_id, &from_specs, start_seq, end_seq, data_only, &state)
    })
    .await
    .map_err(|e| format!("Task execution failed: {}", e))?
}

#[tauri::command]
pub fn get_slice_status(
    session_id: String,
    start_seq: u32,
    count: u32,
    state: State<'_, AppState>,
) -> Result<Vec<bool>, String> {
    let sessions = state.sessions.read().map_err(|e| e.to_string())?;
    let session = sessions.get(&session_id)
        .ok_or_else(|| format!("Session {} 不存在", session_id))?;

    match &session.slice_result {
        Some(marked) => {
            let total = marked.len() as u32;
            let end = (start_seq + count).min(total);
            Ok((start_seq..end).map(|i| marked[i as usize]).collect())
        }
        None => Ok(vec![false; count as usize]),
    }
}

#[tauri::command]
pub fn clear_slice(
    session_id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let mut sessions = state.sessions.write().map_err(|e| e.to_string())?;
    if let Some(session) = sessions.get_mut(&session_id) {
        session.slice_result = None;
        session.slice_origin = None;
    }
    Ok(())
}

#[tauri::command]
pub fn get_tainted_seqs(
    session_id: String,
    state: State<'_, AppState>,
) -> Result<Vec<u32>, String> {
    let sessions = state.sessions.read().map_err(|e| e.to_string())?;
    let session = sessions.get(&session_id)
        .ok_or_else(|| format!("Session {} 不存在", session_id))?;

    match &session.slice_result {
        Some(marked) => {
            Ok(marked.iter_ones().map(|i| i as u32).collect())
        }
        None => Ok(vec![]),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportConfig {
    pub from_specs: Vec<String>,
    pub start_seq: Option<u32>,
    pub end_seq: Option<u32>,
}

#[tauri::command]
pub fn export_taint_results(
    session_id: String,
    output_path: String,
    format: String,
    config: ExportConfig,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let sessions = state.sessions.read().map_err(|e| e.to_string())?;
    let session = sessions.get(&session_id)
        .ok_or_else(|| format!("Session {} 不存在", session_id))?;
    let marked = session.slice_result.as_ref()
        .ok_or("没有活跃的污点分析结果")?;
    let line_index = session.line_index_view().ok_or_else(|| "索引尚未构建完成".to_string())?;

    let marked_count = marked.count_ones() as u32;
    let total_lines = marked.len() as u32;

    use std::io::Write;
    let file = std::fs::File::create(&output_path)
        .map_err(|e| format!("无法创建文件: {}", e))?;
    let mut writer = std::io::BufWriter::new(file);

    if format == "json" {
        // 收集污点行
        let mut tainted_lines = Vec::with_capacity(marked_count as usize);
        for seq in marked.iter_ones() {
            if let Some(raw) = line_index.get_line(&session.mmap, seq as u32) {
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
                "file": session.file_path,
                "totalLines": total_lines,
            },
            "config": {
                "fromSpecs": config.from_specs,
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
            .map_err(|e| format!("JSON 写入失败: {}", e))?;
    } else {
        // TXT: 纯污点行原文
        for seq in marked.iter_ones() {
            if let Some(raw) = line_index.get_line(&session.mmap, seq as u32) {
                writer.write_all(raw).map_err(|e| format!("写入失败: {}", e))?;
                writer.write_all(b"\n").map_err(|e| format!("写入失败: {}", e))?;
            }
        }
    }

    writer.flush().map_err(|e| format!("刷新失败: {}", e))?;
    Ok(())
}
