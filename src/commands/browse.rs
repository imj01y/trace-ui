use serde::Serialize;
use tauri::State;
use crate::state::AppState;

#[derive(Serialize)]
pub struct CallInfoDto {
    pub func_name: String,
    pub is_jni: bool,
    pub summary: String,
    pub tooltip: String,
}

#[derive(Serialize)]
pub struct TraceLine {
    pub seq: u32,
    pub address: String,
    pub so_offset: String,
    pub disasm: String,
    pub changes: String,
    pub mem_rw: Option<String>,
    pub mem_addr: Option<String>,  // 内存访问绝对地址 "0xbffff6b0"
    pub mem_size: Option<u8>,      // 内存访问字节宽度 (1/2/4/8/16)
    pub raw: String,               // 原始 trace 行文本
    pub call_info: Option<CallInfoDto>,
}

/// 从原始 trace 行提取结构化数据
pub fn parse_trace_line(seq: u32, raw: &[u8]) -> Option<TraceLine> {
    let line = std::str::from_utf8(raw).ok()?;

    let so_offset = extract_so_offset(line);
    let address = extract_address(line);
    let disasm = extract_disasm(line);
    let mem_rw = extract_mem_rw(line);
    let mem_addr = extract_mem_addr(line);
    let mem_size = extract_mem_size(&disasm);
    let changes = extract_changes(line);

    Some(TraceLine {
        seq,
        address,
        so_offset,
        disasm,
        changes,
        mem_rw,
        mem_addr,
        mem_size,
        raw: line.to_string(),
        call_info: None,
    })
}

/// 解析 gumtrace 格式的 trace 行
pub fn parse_trace_line_gumtrace(seq: u32, raw: &[u8]) -> Option<TraceLine> {
    let line = std::str::from_utf8(raw).ok()?;

    // 非指令行（特殊行）返回 None
    if !line.starts_with('[') {
        return None;
    }

    // [module] 0xABS!0xOFFSET instruction...
    let bracket_end = line.find("] ")?;
    let rest = &line[bracket_end + 2..];

    // Address: 0xABS!0xOFFSET
    let bang = rest.find('!')?;
    let address = &rest[..bang];

    let offset_start = bang + 1;
    let offset_end = rest[offset_start..].find(' ').map(|p| offset_start + p).unwrap_or(rest.len());
    let so_offset = &rest[offset_start..offset_end];

    // Instruction text
    let insn_start = if offset_end < rest.len() { offset_end + 1 } else { rest.len() };
    let semicolon_pos = rest[insn_start..].find(';').map(|p| insn_start + p);
    let (insn_end, annot_start) = if let Some(semi) = semicolon_pos {
        (semi, semi + 1)
    } else {
        let annot = find_annotation_start_str(rest, insn_start);
        (annot, annot)
    };
    let disasm = rest[insn_start..insn_end].trim().to_string();

    // Memory operation (search in annotation area)
    let annot_area = &rest[annot_start..];
    let mem_rw = if annot_area.contains("mem_w=0x") {
        Some("W".to_string())
    } else if annot_area.contains("mem_r=0x") {
        Some("R".to_string())
    } else {
        None
    };

    let mem_addr = extract_gumtrace_mem_addr(annot_area);
    let mem_size = extract_mem_size(&disasm);

    // Changes: after " -> " in annotation area
    let changes = if let Some(pos) = annot_area.find(" -> ") {
        annot_area[pos + 4..].trim().to_string()
    } else {
        String::new()
    };

    Some(TraceLine {
        seq,
        address: address.to_string(),
        so_offset: so_offset.to_string(),
        disasm,
        changes,
        mem_rw,
        mem_addr,
        mem_size,
        raw: line.to_string(),
        call_info: None,
    })
}

/// 当行内没有 ';' 分隔符时，通过 '=0x' 模式找到寄存器注解的起始位置。
fn find_annotation_start_str(text: &str, insn_start: usize) -> usize {
    let search = &text[insn_start..];
    let mut pos = 0;
    while pos + 3 < search.len() {
        if let Some(eq_pos) = search[pos..].find("=0x") {
            let abs_eq = pos + eq_pos;
            if abs_eq == 0 {
                pos = abs_eq + 3;
                continue;
            }
            let bytes = search.as_bytes();
            let mut name_start = abs_eq;
            while name_start > 0 && bytes[name_start - 1].is_ascii_alphanumeric() {
                name_start -= 1;
            }
            let name_len = abs_eq - name_start;
            if name_len >= 2 && bytes[name_start].is_ascii_alphabetic() {
                return insn_start + name_start;
            }
            pos = abs_eq + 3;
        } else {
            break;
        }
    }
    text.len()
}

fn extract_gumtrace_mem_addr(line: &str) -> Option<String> {
    for marker in &["mem_w=", "mem_r="] {
        if let Some(pos) = line.find(marker) {
            let val_start = pos + marker.len();
            let rest = &line[val_start..];
            let val_end = rest.find(|c: char| !c.is_ascii_hexdigit() && c != 'x' && c != 'X')
                .unwrap_or(rest.len());
            return Some(rest[..val_end].to_string());
        }
    }
    None
}

fn extract_so_offset(line: &str) -> String {
    // 格式: [timestamp][libtiny.so 0x174250] [encoding] 0xADDR: ...
    // 找 "] [" 模式（module bracket 结束 + encoding bracket 开始之间）
    if let Some(pos) = line.find("] [") {
        let before = &line[..pos];
        if let Some(bracket_start) = before.rfind('[') {
            let module_info = &line[bracket_start + 1..pos];
            // module_info = "libtiny.so 0x174250"
            if let Some(space_pos) = module_info.rfind(' ') {
                return module_info[space_pos + 1..].to_string();
            }
        }
    }
    String::new()
}

fn extract_address(line: &str) -> String {
    // 格式: [timestamp][module offset] [encoding] 0xADDR: ...
    // 需要跳过 3 个 ']' 字符（timestamp, module, encoding）
    let mut start = 0;
    for _ in 0..3 {
        if let Some(pos) = line[start..].find(']') {
            start += pos + 1;
        } else {
            return String::new();
        }
    }
    let rest = &line[start..];
    // rest 应该形如 " 0x40174250: ..."
    let trimmed = rest.trim_start();
    if trimmed.starts_with("0x") || trimmed.starts_with("0X") {
        if let Some(colon) = trimmed.find(':') {
            return trimmed[..colon].to_string();
        }
    }
    String::new()
}

fn extract_disasm(line: &str) -> String {
    // 在第一对引号之间: "stp x29, x30, [sp, #-0x60]!"
    if let Some(q1) = line.find('"') {
        if let Some(q2) = line[q1 + 1..].find('"') {
            return line[q1 + 1..q1 + 1 + q2].to_string();
        }
    }
    String::new()
}

fn extract_mem_rw(line: &str) -> Option<String> {
    if line.contains("mem[WRITE]") {
        Some("W".to_string())
    } else if line.contains("mem[READ]") {
        Some("R".to_string())
    } else {
        None
    }
}

fn extract_mem_addr(line: &str) -> Option<String> {
    let pos = line.find("abs=0x")?;
    let val_start = pos + 4; // "abs=" 之后
    let rest = &line[val_start..];
    let val_end = rest.find(|c: char| !c.is_ascii_hexdigit() && c != 'x' && c != 'X')
        .unwrap_or(rest.len());
    Some(rest[..val_end].to_string())
}

/// 从反汇编文本推断内存访问宽度（字节数）
fn extract_mem_size(disasm: &str) -> Option<u8> {
    let mnemonic = disasm.split_whitespace().next().unwrap_or("");
    let mn = mnemonic.to_lowercase();
    // 字节操作: ldrb, strb, ldurb, sturb, ldarb, stlrb, ldaxrb, stlxrb, ...
    if mn.ends_with('b') && (mn.starts_with("ldr") || mn.starts_with("str") || mn.starts_with("ldu") || mn.starts_with("stu") || mn.starts_with("lda") || mn.starts_with("stl") || mn.starts_with("lda") || mn.starts_with("cas")) {
        return Some(1);
    }
    // 半字操作: ldrh, strh, ldurh, sturh, ...
    if mn.ends_with('h') && (mn.starts_with("ldr") || mn.starts_with("str") || mn.starts_with("ldu") || mn.starts_with("stu")) {
        return Some(2);
    }
    // SIMD/FP: 看目标寄存器前缀
    // stp/ldp q寄存器 = 16字节 pair (32), d = 8字节 pair (16), s = 4字节 pair (8)
    // str/ldr q = 16, d = 8, s = 4
    if mn.starts_with("ldr") || mn.starts_with("str") || mn.starts_with("ldu") || mn.starts_with("stu") || mn.starts_with("ldp") || mn.starts_with("stp") {
        // 检查第一个操作数的寄存器前缀
        let args = &disasm[mnemonic.len()..].trim_start();
        let first_reg = args.split([',', ' ']).next().unwrap_or("");
        let is_pair = mn.starts_with("ldp") || mn.starts_with("stp");
        if first_reg.starts_with('q') || first_reg.starts_with('Q') {
            return Some(if is_pair { 32 } else { 16 });
        }
        if first_reg.starts_with('d') || first_reg.starts_with('D') {
            // 排除 "d0" 是 SIMD，但 "d" 也可能是其他
            if first_reg.len() > 1 && first_reg[1..].chars().next().map_or(false, |c| c.is_ascii_digit()) {
                return Some(if is_pair { 16 } else { 8 });
            }
        }
        if first_reg.starts_with('s') || first_reg.starts_with('S') {
            if first_reg.len() > 1 && first_reg[1..].chars().next().map_or(false, |c| c.is_ascii_digit()) {
                return Some(if is_pair { 8 } else { 4 });
            }
        }
        // x寄存器 = 8字节, w寄存器 = 4字节
        if first_reg.starts_with('x') || first_reg.starts_with('X') {
            return Some(if is_pair { 16 } else { 8 });
        }
        if first_reg.starts_with('w') || first_reg.starts_with('W') {
            return Some(if is_pair { 8 } else { 4 });
        }
    }
    None
}

fn extract_changes(line: &str) -> String {
    // "=>" (unidbg) 或 "->" (gumtrace) 之后的内容是变更后的寄存器值
    if let Some(pos) = line.find(" => ").or_else(|| line.find(" -> ")) {
        line[pos + 4..].trim().to_string()
    } else {
        String::new()
    }
}

#[tauri::command]
pub fn get_lines(session_id: String, seqs: Vec<u32>, state: State<'_, AppState>) -> Result<Vec<TraceLine>, String> {
    let sessions = state
        .sessions
        .read()
        .map_err(|e| format!("锁获取失败: {}", e))?;
    let session = sessions.get(&session_id).ok_or_else(|| format!("Session {} 不存在", session_id))?;
    let line_index = session.line_index.as_ref()
        .ok_or_else(|| "索引尚未构建完成".to_string())?;
    let format = session.trace_format;

    let mut results = Vec::with_capacity(seqs.len());
    for &seq in &seqs {
        if let Some(raw) = line_index.get_line(&session.mmap, seq) {
            let parsed = match format {
                crate::taint::types::TraceFormat::Unidbg => parse_trace_line(seq, raw),
                crate::taint::types::TraceFormat::Gumtrace => parse_trace_line_gumtrace(seq, raw),
            };
            if let Some(mut line) = parsed {
                // Fill call_info from session state
                if let Some(ann) = session.call_annotations.get(&seq) {
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
        }
        results.push(TraceLine {
            seq,
            address: String::new(),
            so_offset: String::new(),
            disasm: format!("(line {} unparseable)", seq + 1),
            changes: String::new(),
            mem_rw: None,
            mem_addr: None,
            mem_size: None,
            raw: format!("(line {} unparseable)", seq + 1),
            call_info: None,
        });
    }
    Ok(results)
}

#[tauri::command]
pub fn get_consumed_seqs(session_id: String, state: State<'_, AppState>) -> Result<Vec<u32>, String> {
    let sessions = state.sessions.read().map_err(|e| e.to_string())?;
    let session = sessions.get(&session_id).ok_or_else(|| format!("Session {} 不存在", session_id))?;
    Ok(session.consumed_seqs.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_typical_line() {
        let raw = br#"[07:17:13 488][libtiny.so 0x174250] [fd7bbaa9] 0x40174250: "stp x29, x30, [sp, #-0x60]!" ; mem[WRITE] abs=0xbffff6b0 x29=0x0 x30=0x7ffff0000 sp=0xbffff710 => x29=0x0 x30=0x7ffff0000 sp=0xbffff6b0"#;
        let result = parse_trace_line(42, raw).unwrap();
        assert_eq!(result.seq, 42);
        assert_eq!(result.so_offset, "0x174250");
        assert_eq!(result.address, "0x40174250");
        assert_eq!(result.disasm, "stp x29, x30, [sp, #-0x60]!");
        assert_eq!(result.mem_rw, Some("W".to_string()));
        assert_eq!(result.mem_addr, Some("0xbffff6b0".to_string()));
        assert_eq!(result.mem_size, Some(16)); // stp x29, x30 = pair of 8-byte regs
        assert_eq!(result.changes, "x29=0x0 x30=0x7ffff0000 sp=0xbffff6b0");
    }

    #[test]
    fn test_parse_line_no_mem() {
        let raw = br#"[07:17:13 488][libtiny.so 0x530B20] [aa0003e8] 0x40530b20: "mov x8, x0" x0=0x12345 => x8=0x12345"#;
        let result = parse_trace_line(0, raw).unwrap();
        assert_eq!(result.so_offset, "0x530B20");
        assert_eq!(result.address, "0x40530b20");
        assert_eq!(result.disasm, "mov x8, x0");
        assert_eq!(result.mem_rw, None);
        assert_eq!(result.mem_addr, None);
        assert_eq!(result.changes, "x8=0x12345");
    }

    #[test]
    fn test_parse_line_no_changes() {
        let raw = br#"[07:17:13 488][libtiny.so 0x530B20] [aa0003e8] 0x40530b20: "nop""#;
        let result = parse_trace_line(0, raw).unwrap();
        assert_eq!(result.disasm, "nop");
        assert_eq!(result.changes, "");
        assert_eq!(result.mem_rw, None);
        assert_eq!(result.mem_addr, None);
    }

    #[test]
    fn test_extract_so_offset() {
        let line = r#"[07:17:13 488][libtiny.so 0x174250] [fd7bbaa9] 0x40174250: "stp""#;
        assert_eq!(extract_so_offset(line), "0x174250");
    }

    #[test]
    fn test_extract_address() {
        let line = r#"[07:17:13 488][libtiny.so 0x174250] [fd7bbaa9] 0x40174250: "stp""#;
        assert_eq!(extract_address(line), "0x40174250");
    }

    #[test]
    fn test_empty_line() {
        let raw = b"";
        let result = parse_trace_line(0, raw);
        // 空行也能返回 Some，只是字段为空
        assert!(result.is_some());
        let r = result.unwrap();
        assert_eq!(r.disasm, "");
        assert_eq!(r.mem_addr, None);
    }
}
