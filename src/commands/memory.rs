use serde::Serialize;
use tauri::State;
use crate::state::AppState;
use crate::line_index::LineIndex;
use crate::phase2::extract_insn_offset;

/// 从 trace 行提取偏移地址，回退到绝对地址
fn resolve_offset(seq: u32, abs_addr: u64, line_index: Option<&LineIndex>, data: &[u8]) -> String {
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
#[derive(Serialize)]
pub struct MemorySnapshot {
    pub base_addr: String,
    pub bytes: Vec<u8>,
    pub known: Vec<bool>,
    pub length: u32,
}

#[derive(Serialize)]
pub struct MemHistoryRecord {
    pub seq: u32,
    pub rw: String,
    pub data: String,
    pub size: u8,
    pub insn_addr: String,
    pub disasm: String,
}

#[tauri::command]
pub fn get_memory_at(
    session_id: String,
    seq: u32,
    addr: String,
    length: u32,
    state: State<'_, AppState>,
) -> Result<MemorySnapshot, String> {
    let sessions = state.sessions.read().map_err(|e| e.to_string())?;
    let session = sessions.get(&session_id).ok_or_else(|| format!("Session {} 不存在", session_id))?;
    let mem_view = session.mem_accesses_view().ok_or("索引尚未构建完成")?;



    // 解析地址
    let addr_str = addr.trim_start_matches("0x").trim_start_matches("0X");
    let target_addr = u64::from_str_radix(addr_str, 16)
        .map_err(|_| format!("无效地址: {}", addr))?;

    // 对齐到 16 字节边界
    let base = target_addr & !0xF;
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
                // records 按 seq 升序，从后向前找第一个 seq <= target 的记录（Read 或 Write）
                let mut candidate_seq: Option<u32> = None;
                let mut candidate_data: u64 = 0;
                let mut candidate_size: u8 = 0;

                // records 按 seq 升序，用 partition_point 找第一个 seq > target 的位置
                let pos = records.partition_point(|r| r.seq <= seq);
                if pos > 0 {
                    let rec = &records[pos - 1];
                    candidate_seq = Some(rec.seq);
                    candidate_data = rec.data;
                    candidate_size = rec.size;
                }

                if let Some(cs) = candidate_seq {
                    if check_offset < candidate_size as u64 {
                        if best_seq.is_none() || cs > best_seq.unwrap() {
                            best_seq = Some(cs);
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

#[tauri::command]
pub fn get_mem_history(
    session_id: String,
    addr: String,
    state: State<'_, AppState>,
) -> Result<Vec<MemHistoryRecord>, String> {
    let sessions = state.sessions.read().map_err(|e| e.to_string())?;
    let session = sessions.get(&session_id).ok_or_else(|| format!("Session {} 不存在", session_id))?;
    let mem_view = session.mem_accesses_view().ok_or("索引尚未构建完成")?;



    let addr_str = addr.trim_start_matches("0x").trim_start_matches("0X");
    let target_addr = u64::from_str_radix(addr_str, 16)
        .map_err(|_| format!("无效地址: {}", addr))?;

    let records = match mem_view.query(target_addr) {
        Some(r) => r,
        None => return Ok(Vec::new()),
    };

    use crate::commands::browse::parse_trace_line;
    let line_index = session.line_index.as_ref().ok_or_else(|| "索引尚未构建完成".to_string())?;
    let data: &[u8] = &session.mmap;
    let result: Vec<MemHistoryRecord> = records
        .iter()
        .map(|rec| {
            let disasm = line_index.get_line(data, rec.seq)
                .and_then(|raw| parse_trace_line(rec.seq, raw))
                .map(|parsed| parsed.disasm)
                .unwrap_or_default();
            MemHistoryRecord {
                seq: rec.seq,
                rw: if rec.is_read() { "R".to_string() } else { "W".to_string() },
                data: format!("0x{:x}", rec.data),
                size: rec.size,
                insn_addr: resolve_offset(rec.seq, rec.insn_addr, Some(line_index), data),
                disasm,
            }
        })
        .collect();

    Ok(result)
}
