use serde::Serialize;
use tauri::State;
use crate::state::AppState;
use crate::taint::mem_access::MemRw;
use crate::taint::strings::StringEncoding;

#[derive(Serialize)]
pub struct StringRecordDto {
    pub idx: u32,
    pub addr: String,
    pub content: String,
    pub encoding: String,
    pub byte_len: u32,
    pub seq: u32,
    pub xref_count: u32,
}

#[derive(Serialize)]
pub struct StringsResult {
    pub strings: Vec<StringRecordDto>,
    pub total: u32,
}

#[derive(Serialize)]
pub struct StringXRef {
    pub seq: u32,
    pub rw: String,
    pub insn_addr: String,
    pub disasm: String,
}

#[tauri::command]
pub fn get_strings(
    session_id: String,
    min_len: u32,
    offset: u32,
    limit: u32,
    search: Option<String>,
    state: State<'_, AppState>,
) -> Result<StringsResult, String> {
    let sessions = state.sessions.read().map_err(|e| e.to_string())?;
    let session = sessions.get(&session_id)
        .ok_or_else(|| format!("Session {} 不存在", session_id))?;
    let phase2 = session.phase2.as_ref().ok_or("索引尚未构建完成")?;

    let search_lower = search.as_ref().map(|s| s.to_lowercase());

    let filtered: Vec<(usize, &crate::taint::strings::StringRecord)> = phase2.string_index.strings
        .iter()
        .enumerate()
        .filter(|(_, r)| r.byte_len >= min_len)
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
        .skip(offset as usize)
        .take(limit as usize)
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
        })
        .collect();

    Ok(StringsResult { strings: page, total })
}

#[tauri::command]
pub fn get_string_xrefs(
    session_id: String,
    addr: String,
    byte_len: u32,
    state: State<'_, AppState>,
) -> Result<Vec<StringXRef>, String> {
    let sessions = state.sessions.read().map_err(|e| e.to_string())?;
    let session = sessions.get(&session_id)
        .ok_or_else(|| format!("Session {} 不存在", session_id))?;
    let phase2 = session.phase2.as_ref().ok_or("索引尚未构建完成")?;

    let addr_str = addr.trim_start_matches("0x").trim_start_matches("0X");
    let base_addr = u64::from_str_radix(addr_str, 16)
        .map_err(|_| format!("无效地址: {}", addr))?;

    let mem_idx = &phase2.mem_accesses;
    let line_index = session.line_index.as_ref().ok_or("行索引未就绪")?;
    let mmap = &session.mmap;

    let mut xrefs: Vec<StringXRef> = Vec::new();
    let mut seen_seqs = std::collections::HashSet::new();

    for offset in 0..byte_len as u64 {
        let target = base_addr + offset;
        if let Some(records) = mem_idx.get(target) {
            for rec in records {
                if seen_seqs.insert(rec.seq) {
                    let rw_str = match rec.rw {
                        MemRw::Read => "R",
                        MemRw::Write => "W",
                    };
                    let disasm = line_index.get_line(mmap, rec.seq)
                        .and_then(|raw| {
                            crate::commands::browse::parse_trace_line(rec.seq, raw)
                                .map(|t| t.disasm)
                        })
                        .unwrap_or_default();
                    xrefs.push(StringXRef {
                        seq: rec.seq,
                        rw: rw_str.to_string(),
                        insn_addr: format!("0x{:x}", rec.insn_addr),
                        disasm,
                    });
                }
            }
        }
    }

    xrefs.sort_by_key(|x| x.seq);
    Ok(xrefs)
}
