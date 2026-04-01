use crate::error::{TraceError, Result};
use crate::api_types::{TraceLine, CallInfoDto};
use crate::scan_unified::bytes_to_hex_escaped;
use trace_parser::types::TraceFormat;

impl super::TraceEngine {
    pub fn get_lines(&self, session_id: &str, seqs: &[u32]) -> Result<Vec<TraceLine>> {
        let handle = self.get_handle(session_id)?;
        let state = handle.state.read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;

        let line_index = state.line_index_view()
            .ok_or(TraceError::IndexNotReady)?;
        let format = state.trace_format;

        let mut results = Vec::with_capacity(seqs.len());
        for &seq in seqs {
            if let Some(raw) = line_index.get_line(&state.mmap, seq) {
                let parsed = match format {
                    TraceFormat::Unidbg => crate::browse::parse_trace_line(seq, raw),
                    TraceFormat::Gumtrace => crate::browse::parse_trace_line_gumtrace(seq, raw),
                    TraceFormat::Qbdi => crate::browse::parse_trace_line_qbdi(seq, raw),
                };
                if let Some(mut line) = parsed {
                    // Fill call_info from call_annotations
                    if let Some(ann) = state.call_annotations.get(&seq) {
                        line.call_info = Some(CallInfoDto {
                            func_name: ann.func_name.clone(),
                            is_jni: ann.is_jni,
                            summary: ann.summary(),
                            tooltip: ann.tooltip(),
                        });
                    }
                    results.push(line);
                    continue;
                }
                // 非指令行（hexdump、call func、ret 等特殊行）：显示原始文本
                let raw_text = std::str::from_utf8(raw)
                    .map(|s| s.to_string())
                    .unwrap_or_else(|_| bytes_to_hex_escaped(raw));
                results.push(TraceLine {
                    seq,
                    address: String::new(),
                    so_offset: String::new(),
                    so_name: None,
                    disasm: raw_text.clone(),
                    changes: String::new(),
                    reg_before: String::new(),
                    mem_rw: None,
                    mem_addr: None,
                    mem_size: None,
                    raw: raw_text,
                    call_info: None,
                });
                continue;
            }
            results.push(TraceLine {
                seq,
                address: String::new(),
                so_offset: String::new(),
                so_name: None,
                disasm: format!("(line {} unparseable)", seq + 1),
                changes: String::new(),
                reg_before: String::new(),
                mem_rw: None,
                mem_addr: None,
                mem_size: None,
                raw: format!("(line {} unparseable)", seq + 1),
                call_info: None,
            });
        }
        Ok(results)
    }

    pub fn get_consumed_seqs(&self, session_id: &str) -> Result<Vec<u32>> {
        let handle = self.get_handle(session_id)?;
        let state = handle.state.read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;
        Ok(state.consumed_seqs.clone())
    }
}
