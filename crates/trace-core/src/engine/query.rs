use std::collections::HashMap;
use std::sync::atomic::Ordering;

use crate::api_types::*;
use crate::browse::{parse_trace_line, parse_trace_line_gumtrace, parse_trace_line_qbdi};
use crate::error::{TraceError, Result};
use crate::flat::line_index::LineIndexView;
use crate::phase2::extract_insn_offset;
use crate::query::call_tree::CallTreeNode;
use crate::query::crypto::CryptoScanResult;
use crate::query::strings::{StringEncoding, StringRw, StringBuilder};
use trace_parser::types::{parse_reg, TraceFormat, RegId};
use trace_parser::{parser, insn_class, def_use, gumtrace as gumtrace_parser};

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Private helpers
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// 从 trace 行提取偏移地址，回退到绝对地址
fn resolve_offset(
    seq: u32,
    abs_addr: u64,
    line_index: Option<&LineIndexView<'_>>,
    data: &[u8],
) -> String {
    if let Some(li) = line_index {
        if let Some(line_bytes) = li.get_line(data, seq) {
            if let Ok(line_str) = std::str::from_utf8(line_bytes) {
                let offset = extract_insn_offset(line_str);
                if offset != 0 {
                    return format!("0x{:x}", offset);
                }
            }
        }
    }
    format!("0x{:x}", abs_addr)
}

/// 将 CallTreeNode 转为 DTO
fn node_to_dto(
    n: &CallTreeNode,
    line_index: Option<&LineIndexView<'_>>,
    data: &[u8],
) -> CallTreeNodeDto {
    let func_addr = {
        if let Some(li) = line_index {
            if let Some(line_bytes) = li.get_line(data, n.entry_seq) {
                if let Ok(line_str) = std::str::from_utf8(line_bytes) {
                    let offset = extract_insn_offset(line_str);
                    if offset != 0 {
                        format!("0x{:x}", offset)
                    } else {
                        format!("0x{:x}", n.func_addr)
                    }
                } else {
                    format!("0x{:x}", n.func_addr)
                }
            } else {
                format!("0x{:x}", n.func_addr)
            }
        } else {
            format!("0x{:x}", n.func_addr)
        }
    };

    CallTreeNodeDto {
        id: n.id,
        func_addr,
        func_name: n.func_name.clone(),
        entry_seq: n.entry_seq,
        exit_seq: n.exit_seq,
        parent_id: n.parent_id,
        children_ids: n.children_ids.clone(),
        line_count: n.exit_seq.saturating_sub(n.entry_seq) + 1,
    }
}

// ── Registers helpers ──

const REG_NAMES: &[(&str, u8)] = &[
    ("X0", 0), ("X1", 1), ("X2", 2), ("X3", 3), ("X4", 4),
    ("X5", 5), ("X6", 6), ("X7", 7), ("X8", 8), ("X9", 9),
    ("X10", 10), ("X11", 11), ("X12", 12), ("X13", 13), ("X14", 14),
    ("X15", 15), ("X16", 16), ("X17", 17), ("X18", 18), ("X19", 19),
    ("X20", 20), ("X21", 21), ("X22", 22), ("X23", 23), ("X24", 24),
    ("X25", 25), ("X26", 26), ("X27", 27), ("X28", 28),
    ("X29", 29), ("X30", 30), ("SP", 31), ("NZCV", 65),
];

fn reg_id_to_name(r: RegId) -> Option<&'static str> {
    match r.0 {
        0 => Some("X0"), 1 => Some("X1"), 2 => Some("X2"), 3 => Some("X3"),
        4 => Some("X4"), 5 => Some("X5"), 6 => Some("X6"), 7 => Some("X7"),
        8 => Some("X8"), 9 => Some("X9"), 10 => Some("X10"), 11 => Some("X11"),
        12 => Some("X12"), 13 => Some("X13"), 14 => Some("X14"), 15 => Some("X15"),
        16 => Some("X16"), 17 => Some("X17"), 18 => Some("X18"), 19 => Some("X19"),
        20 => Some("X20"), 21 => Some("X21"), 22 => Some("X22"), 23 => Some("X23"),
        24 => Some("X24"), 25 => Some("X25"), 26 => Some("X26"), 27 => Some("X27"),
        28 => Some("X28"), 29 => Some("X29"), 30 => Some("X30"),
        31 => Some("SP"),
        65 => Some("NZCV"),
        _ => None,
    }
}

// ── DEF/USE helpers ──

const MAX_SCAN_RANGE: u32 = 50000;

fn parse_line_for_format(line: &str, format: TraceFormat) -> Option<trace_parser::types::ParsedLine> {
    match format {
        TraceFormat::Unidbg => parser::parse_line(line),
        TraceFormat::Gumtrace => gumtrace_parser::parse_line_gumtrace(line),
        TraceFormat::Qbdi => trace_parser::qbdi::parse_line_qbdi(line),
    }
}

// ── Crypto helpers ──

/// 28 crypto algorithms with their magic number constants.
const CRYPTO_MAGIC_NUMBERS: &[(&str, &[u32])] = &[
    ("MD5",          &[0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE]),
    ("SHA1",         &[0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6]),
    ("SHA256",       &[0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5]),
    ("SM3",          &[0x79CC4519, 0x7A879D8A]),
    ("CRC32",        &[0x77073096, 0xEE0E612C, 0xEDB88320, 0x04C11DB7]),
    ("CRC32C",       &[0x82F63B78]),
    ("ChaCha20/Salsa20", &[0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]),
    ("HMAC (generic)", &[0x36363636, 0x5C5C5C5C]),
    ("TEA",          &[0x9E3779B9]),
    ("Twofish",      &[0xBCBC3275, 0xECEC21F3, 0x202043C6, 0xB3B3C9F4]),
    ("Blowfish",     &[0x243F6A88, 0x85A308D3]),
    ("RC6",          &[0xB7E15163, 0x9E3779B9]),
    ("AES",          &[0xC66363A5, 0xF87C7C84]),
    ("APLib",        &[0x32335041]),
    ("RC4",          &[0x4F3B2B74, 0x4E27D213]),
    ("Threefish",    &[0x1B22B279, 0xAE23C8A4, 0xBC6F0C0D, 0x5E27A878]),
    ("Camellia",     &[0x4D49E62D, 0x934F19C8, 0x34E72602, 0xF75E005E]),
    ("Serpent",      &[0xC43FFF8B, 0x1D03D043, 0x1B2A04D0, 0x9AC28989]),
    ("AES_SBOX",     &[0x637C777B, 0xF26B6FC5, 0x3001672B, 0xFEFED7AB]),
    ("SHA256_K2",    &[0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5]),
    ("SHA512_IV",    &[0x6A09E667, 0xF3BCC908, 0xBB67AE85, 0x84CAA73B]),
    ("Camellia_IV",  &[0xA09E667F, 0x3BCC908B, 0xB67AE858, 0x4CAA73B2]),
    ("Whirlpool_T0", &[0x18186018, 0xC07830D8, 0x60281818, 0xD8181860]),
    ("Poly1305",     &[0xEB44ACC0, 0xD8DFB523]),
    ("DES",          &[0xFEE1A2B3, 0xD7BEF080]),
    ("DES1",         &[0x3A322A22, 0x2A223A32]),
    ("DES_SBOX",     &[0x2C1E241B, 0x5A7F361D, 0x3D4793C6, 0x0B0EEDF8]),
];

/// Pre-compute all needle bytes (lowercase hex of each magic number).
fn build_needles() -> Vec<(&'static str, String, Vec<u8>)> {
    let mut needles = Vec::new();
    for &(algo, magics) in CRYPTO_MAGIC_NUMBERS {
        for &val in magics {
            let hex_display = format!("0x{:08X}", val);
            let needle = format!("{:x}", val).into_bytes();
            needles.push((algo, hex_display, needle));
        }
    }
    needles
}

/// Scan a chunk of the trace file for crypto magic numbers.
fn scan_chunk(
    data: &[u8],
    start_seq: u32,
    end_seq: u32,
    start_offset: usize,
    needles: &[(&str, String, Vec<u8>)],
    trace_format: TraceFormat,
) -> Vec<crate::query::crypto::CryptoMatch> {
    let estimated = end_seq.saturating_sub(start_seq) as usize / 200;
    let mut matches = Vec::with_capacity(estimated);
    let mut pos = start_offset;
    let mut seq = start_seq;

    while pos < data.len() && seq < end_seq {
        let end = memchr::memchr(b'\n', &data[pos..])
            .map(|i| pos + i)
            .unwrap_or(data.len());

        let line = &data[pos..end];

        for (algo, hex_display, needle) in needles {
            if crate::utils::ascii_contains(line, needle) {
                let parsed = match trace_format {
                    TraceFormat::Unidbg => parse_trace_line(seq, line),
                    TraceFormat::Gumtrace => parse_trace_line_gumtrace(seq, line),
                    TraceFormat::Qbdi => parse_trace_line_qbdi(seq, line),
                };
                if let Some(p) = parsed {
                    matches.push(crate::query::crypto::CryptoMatch {
                        algorithm: algo.to_string(),
                        magic_hex: hex_display.clone(),
                        seq,
                        address: p.address,
                        disasm: p.disasm,
                        changes: p.changes,
                    });
                }
                break; // one match per line is enough
            }
        }

        pos = end + 1;
        seq += 1;
    }

    matches
}

// ── Dep tree constants ──

const DEFAULT_MAX_NODES: u32 = 10_000;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  TraceEngine query methods
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

impl super::TraceEngine {
    // ━━━━━━━━━━━━━━━━━━━━━━ Memory ━━━━━━━━━━━━━━━━━━━━━━

    pub fn get_memory_at(
        &self,
        session_id: &str,
        addr: u64,
        seq: u32,
        length: u32,
    ) -> Result<MemorySnapshot> {
        let handle = self.get_handle(session_id)?;
        let state = handle.state.read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;

        let mem_view = state.mem_accesses_view()
            .ok_or(TraceError::IndexNotReady)?;

        // 对齐到 16 字节边界
        let base = addr & !0xF;
        let len = length.max(16) as usize;

        let mut bytes = vec![0u8; len];
        let mut known = vec![false; len];

        for offset in 0..len {
            let byte_addr = base + offset as u64;

            // 检查 byte_addr-7 .. byte_addr 共 8 个可能的基地址
            let mut best_seq: Option<u32> = None;
            let mut best_byte: u8 = 0;

            for check_offset in 0u64..=7 {
                if byte_addr < check_offset {
                    continue;
                }
                let check_addr = byte_addr - check_offset;

                if let Some(records) = mem_view.query(check_addr) {
                    let pos = records.partition_point(|r| r.seq <= seq);
                    if pos > 0 {
                        let rec = &records[pos - 1];
                        let candidate_seq = rec.seq;
                        let candidate_data = rec.data;
                        let candidate_size = rec.size;

                        if check_offset < candidate_size as u64 {
                            if best_seq.is_none() || candidate_seq > best_seq.unwrap() {
                                best_seq = Some(candidate_seq);
                                best_byte = ((candidate_data >> (check_offset * 8)) & 0xFF) as u8;
                            }
                        }
                    }
                }
            }

            if best_seq.is_some() {
                bytes[offset] = best_byte;
                known[offset] = true;
            }
        }

        Ok(MemorySnapshot {
            base_addr: format!("0x{:x}", base),
            bytes,
            known,
            length: len as u32,
        })
    }

    pub fn get_mem_history_meta(
        &self,
        session_id: &str,
        addr: u64,
        center_seq: u32,
    ) -> Result<MemHistoryMeta> {
        let handle = self.get_handle(session_id)?;
        let state = handle.state.read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;

        let mem_view = state.mem_accesses_view()
            .ok_or(TraceError::IndexNotReady)?;

        let records = match mem_view.query(addr) {
            Some(r) => r,
            None => return Ok(MemHistoryMeta { total: 0, center_index: 0, samples: Vec::new() }),
        };

        let center_index = records.partition_point(|r| r.seq < center_seq);
        let center_index = center_index.min(records.len().saturating_sub(1));

        // Minimap 采样：等间距取 ~300 条记录
        const SAMPLE_COUNT: usize = 300;
        let samples = if records.len() <= SAMPLE_COUNT {
            Vec::new()
        } else {
            let line_index = state.line_index_view();
            let data: &[u8] = &state.mmap;
            let format = state.trace_format;
            (0..SAMPLE_COUNT)
                .map(|i| {
                    let idx = i * records.len() / SAMPLE_COUNT;
                    let rec = &records[idx];
                    let disasm = line_index.as_ref()
                        .and_then(|li| li.get_line(data, rec.seq))
                        .and_then(|raw| match format {
                            TraceFormat::Unidbg => parse_trace_line(rec.seq, raw),
                            TraceFormat::Gumtrace => parse_trace_line_gumtrace(rec.seq, raw),
                            TraceFormat::Qbdi => parse_trace_line_qbdi(rec.seq, raw),
                        })
                        .map(|parsed| parsed.disasm)
                        .unwrap_or_default();
                    MemHistoryRecord {
                        seq: rec.seq,
                        rw: if rec.is_read() { "R".to_string() } else { "W".to_string() },
                        data: format!("0x{:x}", rec.data),
                        size: rec.size,
                        insn_addr: resolve_offset(rec.seq, rec.insn_addr, line_index.as_ref(), data),
                        disasm,
                    }
                })
                .collect()
        };

        Ok(MemHistoryMeta {
            total: records.len(),
            center_index,
            samples,
        })
    }

    pub fn get_mem_history_range(
        &self,
        session_id: &str,
        addr: u64,
        start_index: usize,
        limit: usize,
    ) -> Result<Vec<MemHistoryRecord>> {
        let handle = self.get_handle(session_id)?;
        let state = handle.state.read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;

        let mem_view = state.mem_accesses_view()
            .ok_or(TraceError::IndexNotReady)?;

        let records = match mem_view.query(addr) {
            Some(r) => r,
            None => return Ok(Vec::new()),
        };

        let start = start_index.min(records.len());
        let end = (start + limit).min(records.len());
        let slice = &records[start..end];

        let line_index = state.line_index_view()
            .ok_or(TraceError::IndexNotReady)?;
        let data: &[u8] = &state.mmap;
        let format = state.trace_format;

        let result: Vec<MemHistoryRecord> = slice
            .iter()
            .map(|rec| {
                let disasm = line_index.get_line(data, rec.seq)
                    .and_then(|raw| match format {
                        TraceFormat::Unidbg => parse_trace_line(rec.seq, raw),
                        TraceFormat::Gumtrace => parse_trace_line_gumtrace(rec.seq, raw),
                        TraceFormat::Qbdi => parse_trace_line_qbdi(rec.seq, raw),
                    })
                    .map(|parsed| parsed.disasm)
                    .unwrap_or_default();
                MemHistoryRecord {
                    seq: rec.seq,
                    rw: if rec.is_read() { "R".to_string() } else { "W".to_string() },
                    data: format!("0x{:x}", rec.data),
                    size: rec.size,
                    insn_addr: resolve_offset(rec.seq, rec.insn_addr, Some(&line_index), data),
                    disasm,
                }
            })
            .collect();

        Ok(result)
    }

    // ━━━━━━━━━━━━━━━━━━━━━━ Registers ━━━━━━━━━━━━━━━━━━━━━━

    pub fn get_registers_at(
        &self,
        session_id: &str,
        seq: u32,
    ) -> Result<HashMap<String, String>> {
        let handle = self.get_handle(session_id)?;
        let state = handle.state.read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;

        let reg_view = state.reg_checkpoints_view()
            .ok_or(TraceError::IndexNotReady)?;
        let line_index = state.line_index_view()
            .ok_or(TraceError::IndexNotReady)?;

        // 找最近检查点
        let (ckpt_seq, snapshot) = reg_view
            .nearest_before(seq)
            .ok_or_else(|| TraceError::Internal("无可用检查点".to_string()))?;

        let mut values = *snapshot;

        // 从检查点重放到目标 seq
        for replay_seq in ckpt_seq..=seq {
            if let Some(raw) = line_index.get_line(&state.mmap, replay_seq) {
                if let Ok(line_str) = std::str::from_utf8(raw) {
                    crate::phase2::update_reg_values(&mut values, line_str);
                }
            }
        }

        // 构建返回结果
        let mut result = HashMap::new();
        for &(name, idx) in REG_NAMES {
            let val = values[idx as usize];
            if val != u64::MAX {
                result.insert(name.to_string(), format!("0x{:016x}", val));
            } else {
                result.insert(name.to_string(), "?".to_string());
            }
        }

        // PC = 当前行的指令地址 + 提取当前行被修改的寄存器名
        let format = state.trace_format;
        if let Some(raw) = line_index.get_line(&state.mmap, seq) {
            let parsed = match format {
                TraceFormat::Unidbg => parse_trace_line(seq, raw),
                TraceFormat::Gumtrace => parse_trace_line_gumtrace(seq, raw),
                TraceFormat::Qbdi => parse_trace_line_qbdi(seq, raw),
            };
            if let Some(parsed) = parsed {
                let pc_display = if let Some(hex_str) = parsed.address.strip_prefix("0x")
                    .or_else(|| parsed.address.strip_prefix("0X"))
                {
                    if let Ok(addr_val) = u64::from_str_radix(hex_str, 16) {
                        format!("0x{:016x}", addr_val)
                    } else {
                        parsed.address
                    }
                } else {
                    parsed.address
                };
                result.insert("PC".to_string(), pc_display);
            }
            if let Ok(line_str) = std::str::from_utf8(raw) {
                let mut changed = Vec::new();
                if let Some(arrow_pos) = line_str.find(" => ").or_else(|| line_str.find(" -> ")) {
                    let changes = &line_str[arrow_pos + 4..];
                    for part in changes.split_whitespace() {
                        if let Some(eq_pos) = part.find('=') {
                            let reg_name = &part[..eq_pos];
                            changed.push(reg_name.to_uppercase());
                        }
                    }
                }
                if !changed.is_empty() {
                    result.insert("__changed".to_string(), changed.join(","));
                }

                // 提取 USE（读取）寄存器
                if let Some(parsed) = parser::parse_line(line_str) {
                    let first_reg = parsed.operands.first().and_then(|op| op.as_reg());
                    let cls = insn_class::classify(parsed.mnemonic.as_str(), first_reg);
                    let (_, uses) = def_use::determine_def_use(cls, &parsed);
                    let read_names: Vec<&str> = uses.iter()
                        .filter_map(|r| reg_id_to_name(*r))
                        .collect();
                    if !read_names.is_empty() {
                        result.insert("__read".to_string(), read_names.join(","));
                    }
                }
            }
        }

        Ok(result)
    }

    // ━━━━━━━━━━━━━━━━━━━━━━ Call Tree ━━━━━━━━━━━━━━━━━━━━━━

    pub fn get_call_tree(&self, session_id: &str) -> Result<Vec<CallTreeNodeDto>> {
        let handle = self.get_handle(session_id)?;
        let state = handle.state.read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;

        let call_tree = state.call_tree.as_ref()
            .ok_or(TraceError::IndexNotReady)?;

        let data: &[u8] = &state.mmap;
        let line_index = state.line_index_view();

        let nodes: Vec<CallTreeNodeDto> = call_tree
            .nodes
            .iter()
            .map(|n| node_to_dto(n, line_index.as_ref(), data))
            .collect();

        Ok(nodes)
    }

    pub fn get_call_tree_children(
        &self,
        session_id: &str,
        node_id: u32,
        include_self: bool,
    ) -> Result<Vec<CallTreeNodeDto>> {
        let handle = self.get_handle(session_id)?;
        let state = handle.state.read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;

        let call_tree = state.call_tree.as_ref()
            .ok_or(TraceError::IndexNotReady)?;

        let data: &[u8] = &state.mmap;
        let line_index = state.line_index_view();

        let node = call_tree.nodes.get(node_id as usize)
            .ok_or_else(|| TraceError::InvalidArgument(format!("节点 {} 不存在", node_id)))?;

        let mut result = Vec::new();

        if include_self {
            result.push(node_to_dto(node, line_index.as_ref(), data));
        }

        for &child_id in &node.children_ids {
            if let Some(child) = call_tree.nodes.get(child_id as usize) {
                result.push(node_to_dto(child, line_index.as_ref(), data));
            }
        }

        Ok(result)
    }

    pub fn get_call_tree_node_count(&self, session_id: &str) -> Result<u32> {
        let handle = self.get_handle(session_id)?;
        let state = handle.state.read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;

        let call_tree = state.call_tree.as_ref()
            .ok_or(TraceError::IndexNotReady)?;

        Ok(call_tree.nodes.len() as u32)
    }

    // ━━━━━━━━━━━━━━━━━━━━━━ Strings ━━━━━━━━━━━━━━━━━━━━━━

    pub fn get_strings(
        &self,
        session_id: &str,
        options: StringQueryOptions,
    ) -> Result<StringsResult> {
        let handle = self.get_handle(session_id)?;
        let state = handle.state.read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;

        let string_index = state.string_index.as_ref()
            .ok_or(TraceError::IndexNotReady)?;

        let search_lower = options.search.as_ref().map(|s| s.to_lowercase());

        let filtered: Vec<(usize, &crate::query::strings::StringRecord)> = string_index.strings
            .iter()
            .enumerate()
            .filter(|(_, r)| r.byte_len >= options.min_len)
            .filter(|(_, r)| {
                match &search_lower {
                    Some(q) => r.content.to_lowercase().contains(q.as_str()),
                    None => true,
                }
            })
            .collect();

        let total = filtered.len() as u32;
        let page: Vec<StringRecordDto> = filtered
            .into_iter()
            .skip(options.offset as usize)
            .take(options.limit as usize)
            .map(|(idx, r)| StringRecordDto {
                idx: idx as u32,
                addr: format!("0x{:x}", r.addr),
                content: r.content.clone(),
                encoding: match r.encoding {
                    StringEncoding::Ascii => "ASCII".to_string(),
                    StringEncoding::Utf8 => "UTF-8".to_string(),
                },
                byte_len: r.byte_len,
                seq: r.seq,
                xref_count: r.xref_count,
                rw: match r.rw {
                    StringRw::Read => "R".to_string(),
                    StringRw::Write => "W".to_string(),
                },
            })
            .collect();

        Ok(StringsResult { strings: page, total })
    }

    pub fn get_string_xrefs(
        &self,
        session_id: &str,
        addr: u64,
        byte_len: u32,
    ) -> Result<Vec<StringXRef>> {
        let handle = self.get_handle(session_id)?;
        let state = handle.state.read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;

        let mem_view = state.mem_accesses_view()
            .ok_or(TraceError::IndexNotReady)?;

        let line_index = state.line_index_view()
            .ok_or(TraceError::IndexNotReady)?;
        let mmap = &state.mmap;
        let format = state.trace_format;

        let mut xrefs: Vec<StringXRef> = Vec::new();
        let mut seen_seqs = std::collections::HashSet::new();

        for offset in 0..byte_len as u64 {
            let target = addr + offset;
            if let Some(records) = mem_view.query(target) {
                for rec in records {
                    if seen_seqs.insert(rec.seq) {
                        let rw_str = if rec.is_read() { "R" } else { "W" };
                        let disasm = line_index.get_line(mmap, rec.seq)
                            .and_then(|raw| match format {
                                TraceFormat::Unidbg => parse_trace_line(rec.seq, raw),
                                TraceFormat::Gumtrace => parse_trace_line_gumtrace(rec.seq, raw),
                                TraceFormat::Qbdi => parse_trace_line_qbdi(rec.seq, raw),
                            })
                            .map(|t| t.disasm)
                            .unwrap_or_default();
                        let insn_addr_str = line_index.get_line(mmap, rec.seq)
                            .and_then(|raw| std::str::from_utf8(raw).ok())
                            .map(|line_str| {
                                let off = extract_insn_offset(line_str);
                                if off != 0 { format!("0x{:x}", off) } else { format!("0x{:x}", rec.insn_addr) }
                            })
                            .unwrap_or_else(|| format!("0x{:x}", rec.insn_addr));
                        xrefs.push(StringXRef {
                            seq: rec.seq,
                            rw: rw_str.to_string(),
                            insn_addr: insn_addr_str,
                            disasm,
                        });
                    }
                }
            }
        }

        xrefs.sort_by_key(|x| x.seq);
        Ok(xrefs)
    }

    pub fn scan_strings(&self, session_id: &str) -> Result<()> {
        let handle = self.get_handle(session_id)?;

        // 使用 compare_exchange 防止并发扫描
        if handle.scanning_strings.compare_exchange(
            false, true, Ordering::SeqCst, Ordering::SeqCst
        ).is_err() {
            return Err(TraceError::OperationInProgress("scan_strings already running".to_string()));
        }

        // 确保无论成功与否都重置 scanning_strings
        let result = (|| -> Result<()> {
            // 1. Collect READ+WRITE records and reset cancel flag
            let mut accesses: Vec<(u64, u64, u8, u32, StringRw)>;
            {
                let state = handle.state.read()
                    .map_err(|e| TraceError::Internal(e.to_string()))?;
                let mem_view = state.mem_accesses_view()
                    .ok_or(TraceError::IndexNotReady)?;

                accesses = Vec::new();
                for (addr, rec) in mem_view.iter_all() {
                    if rec.size <= 8 {
                        let rw = if rec.is_write() { StringRw::Write } else { StringRw::Read };
                        accesses.push((addr, rec.data, rec.size, rec.seq, rw));
                    }
                }
            }

            // 2. Sort by seq
            accesses.sort_unstable_by_key(|a| a.3);

            // 3. Reset cancellation flag
            handle.scan_strings_cancel.store(false, Ordering::SeqCst);

            // 4. Run StringBuilder
            let estimated_pages = (accesses.len() / 500).max(1024);
            let mut sb = StringBuilder::with_capacity(estimated_pages);
            for (i, &(addr, data, size, seq, rw)) in accesses.iter().enumerate() {
                if i % 10000 == 0 && handle.scan_strings_cancel.load(Ordering::SeqCst) {
                    return Err(TraceError::Cancelled);
                }
                sb.process_access(addr, data, size, seq, rw);
            }

            // 5. finish + fill_xref_counts
            let mut string_index = sb.finish();
            {
                let state = handle.state.read()
                    .map_err(|e| TraceError::Internal(e.to_string()))?;
                let mem_view = state.mem_accesses_view()
                    .ok_or(TraceError::IndexNotReady)?;
                StringBuilder::fill_xref_counts_view(&mut string_index, &mem_view);
            }

            // 6. Write results and update cache
            {
                let mut state = handle.state.write()
                    .map_err(|e| TraceError::Internal(e.to_string()))?;
                crate::cache::save_string_cache(&state.file_path, &state.mmap, &string_index);
                state.string_index = Some(string_index);
            }

            Ok(())
        })();

        // Always reset scanning_strings
        handle.scanning_strings.store(false, Ordering::SeqCst);

        result
    }

    pub fn cancel_scan_strings(&self, session_id: &str) {
        // Fire-and-forget, silently ignore if session not found
        if let Ok(handle) = self.get_handle(session_id) {
            handle.scan_strings_cancel.store(true, Ordering::SeqCst);
        }
    }

    // ━━━━━━━━━━━━━━━━━━━━━━ Dep Tree ━━━━━━━━━━━━━━━━━━━━━━

    pub fn build_dep_tree(
        &self,
        session_id: &str,
        seq: u32,
        target: &str,
        options: DepTreeOptions,
    ) -> Result<crate::query::dep_tree::DependencyGraph> {
        let handle = self.get_handle(session_id)?;
        let state = handle.state.read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;

        let format = state.trace_format;
        let lidx_view = state.line_index_view()
            .ok_or(TraceError::IndexNotReady)?;

        let spec = if target.starts_with("mem:") {
            format!("{}@{}", target, seq + 1)
        } else {
            let reg_name = target.strip_prefix("reg:").unwrap_or(target);
            format!("reg:{}@{}", reg_name, seq + 1)
        };

        let reg_last_def = state.reg_last_def.as_ref()
            .ok_or(TraceError::IndexNotReady)?;
        let mem_last_def = state.mem_last_def_view()
            .ok_or(TraceError::IndexNotReady)?;

        let max_nodes = options.max_nodes.unwrap_or(DEFAULT_MAX_NODES);
        let start_idx = super::slice::resolve_start_index(
            &spec, reg_last_def, &mem_last_def, &state.mmap, &lidx_view, format,
        ).map_err(|e| TraceError::InvalidArgument(e))?;

        let scan_view = state.scan_view()
            .ok_or(TraceError::IndexNotReady)?;

        let mut graph = crate::query::dep_tree::build_graph(&scan_view, start_idx, options.data_only, max_nodes);
        crate::query::dep_tree::populate_graph_info(&mut graph, &state.mmap, &lidx_view, format);
        Ok(graph)
    }

    pub fn build_dep_tree_from_slice(
        &self,
        session_id: &str,
        options: DepTreeOptions,
    ) -> Result<crate::query::dep_tree::DependencyGraph> {
        let handle = self.get_handle(session_id)?;
        let state = handle.state.read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;

        let origin = state.slice_origin.as_ref()
            .ok_or_else(|| TraceError::InvalidArgument(
                "No active taint analysis result, please run taint tracking first".to_string()
            ))?;
        let spec = origin.from_specs.first()
            .ok_or_else(|| TraceError::InvalidArgument("No from_specs in SliceOrigin".to_string()))?;
        let data_only = options.data_only || origin.data_only;
        let max_nodes = options.max_nodes.unwrap_or(DEFAULT_MAX_NODES);

        let reg_last_def = state.reg_last_def.as_ref()
            .ok_or(TraceError::IndexNotReady)?;
        let mem_last_def = state.mem_last_def_view()
            .ok_or(TraceError::IndexNotReady)?;
        let lidx_view = state.line_index_view()
            .ok_or(TraceError::IndexNotReady)?;
        let format = state.trace_format;

        let start_idx = super::slice::resolve_start_index(
            spec, reg_last_def, &mem_last_def, &state.mmap, &lidx_view, format,
        ).map_err(|e| TraceError::InvalidArgument(e))?;

        let scan_view = state.scan_view()
            .ok_or(TraceError::IndexNotReady)?;

        let mut graph = crate::query::dep_tree::build_graph(&scan_view, start_idx, data_only, max_nodes);
        crate::query::dep_tree::populate_graph_info(&mut graph, &state.mmap, &lidx_view, format);
        Ok(graph)
    }

    pub fn get_line_def_registers(
        &self,
        session_id: &str,
        seq: u32,
    ) -> Result<Vec<String>> {
        let handle = self.get_handle(session_id)?;
        let state = handle.state.read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;

        let lidx_view = state.line_index_view()
            .ok_or(TraceError::IndexNotReady)?;
        let format = state.trace_format;

        if let Some(raw) = lidx_view.get_line(&state.mmap, seq) {
            if let Ok(line_str) = std::str::from_utf8(raw) {
                let parsed = parse_line_for_format(line_str, format);
                if let Some(ref p) = parsed {
                    let cls = insn_class::classify_and_refine(p);
                    let (defs, _) = def_use::determine_def_use(cls, p);
                    return Ok(defs.iter().map(|r| format!("{:?}", r)).collect());
                }
            }
        }
        Ok(vec![])
    }

    // ━━━━━━━━━━━━━━━━━━━━━━ DEF/USE ━━━━━━━━━━━━━━━━━━━━━━

    pub fn get_def_use_chain(
        &self,
        session_id: &str,
        seq: u32,
        reg: &str,
    ) -> Result<DefUseChain> {
        let handle = self.get_handle(session_id)?;
        let state = handle.state.read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;

        let target_reg = parse_reg(reg)
            .ok_or_else(|| TraceError::InvalidArgument(format!("未知寄存器: {}", reg)))?;

        let total = state.total_lines;
        let format = state.trace_format;
        let line_index = state.line_index_view()
            .ok_or(TraceError::IndexNotReady)?;

        // === 分析 anchor 行：判断 target_reg 在当前行是 DEF 还是 USE ===
        let mut anchor_is_use = false;
        let mut anchor_is_def = false;
        if let Some(raw) = line_index.get_line(&state.mmap, seq) {
            if let Ok(line_str) = std::str::from_utf8(raw) {
                if let Some(parsed) = parse_line_for_format(line_str, format) {
                    let first_reg = parsed.operands.first().and_then(|op| op.as_reg());
                    let cls = insn_class::classify(parsed.mnemonic.as_str(), first_reg);
                    let (defs, uses) = def_use::determine_def_use(cls, &parsed);
                    anchor_is_def = defs.iter().any(|r| *r == target_reg);
                    anchor_is_use = uses.iter().any(|r| *r == target_reg);
                }
            }
        }

        // === 向上扫描：仅当 anchor 行 USE 了该寄存器时才查找上游 DEF ===
        let mut def_seq: Option<u32> = None;
        if anchor_is_use && seq > 0 {
            let scan_start = seq.saturating_sub(MAX_SCAN_RANGE);
            for s in (scan_start..seq).rev() {
                if let Some(raw) = line_index.get_line(&state.mmap, s) {
                    if let Ok(line_str) = std::str::from_utf8(raw) {
                        if let Some(parsed) = parse_line_for_format(line_str, format) {
                            let first_reg = parsed.operands.first().and_then(|op| op.as_reg());
                            let cls = insn_class::classify(parsed.mnemonic.as_str(), first_reg);
                            let (defs, _) = def_use::determine_def_use(cls, &parsed);
                            if defs.iter().any(|r| *r == target_reg) {
                                def_seq = Some(s);
                                break;
                            }
                        }
                    }
                }
            }
        }

        // === 向下扫描：仅当 anchor 行 DEF 了该寄存器时才收集下游 USE ===
        let mut use_seqs: Vec<u32> = Vec::new();
        let mut redefined_seq: Option<u32> = None;
        if anchor_is_def {
            let scan_end = total.min(seq + MAX_SCAN_RANGE);
            for s in (seq + 1)..scan_end {
                if let Some(raw) = line_index.get_line(&state.mmap, s) {
                    if let Ok(line_str) = std::str::from_utf8(raw) {
                        if let Some(parsed) = parse_line_for_format(line_str, format) {
                            let first_reg = parsed.operands.first().and_then(|op| op.as_reg());
                            let cls = insn_class::classify(parsed.mnemonic.as_str(), first_reg);
                            let (defs, uses) = def_use::determine_def_use(cls, &parsed);

                            // 先检查 USE（同一行可能既 USE 又 DEF，如 add x0, x0, #1）
                            if uses.iter().any(|r| *r == target_reg) {
                                use_seqs.push(s);
                            }

                            // 再检查 DEF（重新定义 = 扫描终点）
                            if defs.iter().any(|r| *r == target_reg) {
                                redefined_seq = Some(s);
                                break;
                            }
                        }
                    }
                }
            }
        }

        Ok(DefUseChain {
            def_seq,
            use_seqs,
            redefined_seq,
        })
    }

    // ━━━━━━━━━━━━━━━━━━━━━━ Crypto ━━━━━━━━━━━━━━━━━━━━━━

    pub fn scan_crypto(
        &self,
        session_id: &str,
    ) -> Result<CryptoScanResult> {
        let handle = self.get_handle(session_id)?;

        // 检查内存缓存
        {
            let state = handle.state.read()
                .map_err(|e| TraceError::Internal(e.to_string()))?;
            if let Some(cached) = &state.crypto_cache {
                return Ok(cached.clone());
            }
            // 检查磁盘缓存
            if let Some(cached) = crate::cache::load_crypto_cache(&state.file_path, &state.mmap) {
                drop(state);
                let mut state = handle.state.write()
                    .map_err(|e| TraceError::Internal(e.to_string()))?;
                state.crypto_cache = Some(cached.clone());
                return Ok(cached);
            }
        }

        let start_time = std::time::Instant::now();

        let num_cpus = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);

        let (mmap_ref, total_lines, trace_format, chunks) = {
            let state = handle.state.read()
                .map_err(|e| TraceError::Internal(e.to_string()))?;
            let total_lines = state.lidx_store.as_ref()
                .map(|s| s.total_lines())
                .unwrap_or(0);

            let chunks: Option<Vec<(u32, u32, usize)>> = if num_cpus > 1 && total_lines > 10000 {
                state.line_index_view().map(|li| {
                    let data: &[u8] = &state.mmap;
                    let num_chunks = num_cpus.min(16);
                    let lines_per_chunk = (total_lines as usize + num_chunks - 1) / num_chunks;
                    let mut chunks = Vec::with_capacity(num_chunks);
                    for i in 0..num_chunks {
                        let start_seq = (i * lines_per_chunk) as u32;
                        if start_seq >= total_lines { break; }
                        let end_seq = ((i + 1) * lines_per_chunk).min(total_lines as usize) as u32;
                        let start_offset = li.line_byte_offset(data, start_seq).unwrap_or(0) as usize;
                        chunks.push((start_seq, end_seq, start_offset));
                    }
                    chunks
                })
            } else {
                None
            };

            (state.mmap.clone(), total_lines, state.trace_format, chunks)
        };

        let data: &[u8] = &mmap_ref;
        let needles = build_needles();

        let all_matches = if let Some(chunks) = chunks {
            use rayon::prelude::*;
            let chunk_results: Vec<Vec<crate::query::crypto::CryptoMatch>> = chunks.par_iter()
                .map(|&(start_seq, end_seq, start_offset)| {
                    scan_chunk(data, start_seq, end_seq, start_offset, &needles, trace_format)
                })
                .collect();

            chunk_results.into_iter().flatten().collect()
        } else {
            scan_chunk(data, 0, total_lines, 0, &needles, trace_format)
        };

        // Collect unique algorithms found
        let mut algos: Vec<String> = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for m in &all_matches {
            if seen.insert(&m.algorithm) {
                algos.push(m.algorithm.clone());
            }
        }

        let result = CryptoScanResult {
            matches: all_matches,
            algorithms_found: algos,
            total_lines_scanned: total_lines,
            scan_duration_ms: start_time.elapsed().as_millis() as u64,
        };

        // 写入内存缓存 + 磁盘缓存
        {
            let mut state = handle.state.write()
                .map_err(|e| TraceError::Internal(e.to_string()))?;
            crate::cache::save_crypto_cache(&state.file_path, &state.mmap, &result);
            state.crypto_cache = Some(result.clone());
        }

        Ok(result)
    }

    pub fn load_crypto_cache(
        &self,
        session_id: &str,
    ) -> Result<Option<CryptoScanResult>> {
        let handle = self.get_handle(session_id)?;
        let mut state = handle.state.write()
            .map_err(|e| TraceError::Internal(e.to_string()))?;

        if state.crypto_cache.is_some() {
            return Ok(state.crypto_cache.clone());
        }
        if let Some(cached) = crate::cache::load_crypto_cache(&state.file_path, &state.mmap) {
            state.crypto_cache = Some(cached.clone());
            return Ok(Some(cached));
        }
        Ok(None)
    }

    // ━━━━━━━━━━━━━━━━━━━━━━ Functions ━━━━━━━━━━━━━━━━━━━━━━

    pub fn get_function_calls(
        &self,
        session_id: &str,
    ) -> Result<FunctionCallsResult> {
        let handle = self.get_handle(session_id)?;
        let state = handle.state.read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;

        // Group by func_name
        let mut groups: HashMap<String, (bool, Vec<FunctionCallOccurrence>)> = HashMap::new();
        for (&seq, ann) in &state.call_annotations {
            let entry = groups.entry(ann.func_name.clone())
                .or_insert_with(|| (ann.is_jni, Vec::new()));
            entry.1.push(FunctionCallOccurrence {
                seq,
                summary: ann.summary(),
            });
        }

        let mut total_calls = 0usize;
        let mut functions: Vec<FunctionCallEntry> = groups.into_iter()
            .map(|(func_name, (is_jni, mut occs))| {
                occs.sort_by_key(|o| o.seq);
                total_calls += occs.len();
                FunctionCallEntry { func_name, is_jni, occurrences: occs }
            })
            .collect();

        // Sort by first occurrence seq
        functions.sort_by_key(|f| f.occurrences.first().map(|o| o.seq).unwrap_or(u32::MAX));

        Ok(FunctionCallsResult { functions, total_calls })
    }
}
