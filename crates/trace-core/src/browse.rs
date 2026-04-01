use crate::api_types::TraceLine;
use crate::scan_unified::bytes_to_hex_escaped;

/// 从原始 trace 行提取结构化数据
pub fn parse_trace_line(seq: u32, raw: &[u8]) -> Option<TraceLine> {
    let line = std::str::from_utf8(raw).ok()?;

    let (so_offset, so_name) = extract_so_info(line);
    let address = extract_address(line);
    let disasm = extract_disasm(line);
    let mem_rw = extract_mem_rw(line);
    let mem_addr = extract_mem_addr(line);
    let mem_size = extract_mem_size(&disasm);
    let changes = extract_changes(line);
    let reg_before = extract_reg_before(line, &changes);

    Some(TraceLine {
        seq,
        address,
        so_offset,
        so_name,
        disasm,
        changes,
        reg_before,
        mem_rw,
        mem_addr,
        mem_size,
        raw: line.to_string(),
        call_info: None,
    })
}

/// 解析 gumtrace 格式的 trace 行
pub fn parse_trace_line_gumtrace(seq: u32, raw: &[u8]) -> Option<TraceLine> {
    let line_owned: String;
    let line: &str = match std::str::from_utf8(raw) {
        Ok(s) => s,
        Err(_) => {
            line_owned = bytes_to_hex_escaped(raw);
            &line_owned
        }
    };

    // 非指令行（特殊行）返回 None
    if !line.starts_with('[') {
        return None;
    }

    // [module] 0xABS!0xOFFSET instruction...
    let bracket_end = line.find("] ")?;
    let so_name = Some(line[1..bracket_end].to_string());
    let rest = &line[bracket_end + 2..];

    // Address: 0xABS!0xOFFSET — 绝对地址!偏移地址
    let bang = rest.find('!')?;

    let abs_end = bang;
    let address = &rest[..abs_end]; // 绝对地址
    let offset_start = bang + 1;
    let offset_end = rest[offset_start..].find(' ').map(|p| offset_start + p).unwrap_or(rest.len());
    let so_offset = &rest[offset_start..offset_end]; // 偏移地址

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
    // reg_before: before " -> "，显示全部寄存器旧值
    // 当没有 " -> " 时（如 store 指令不改变寄存器），整个 annotation 区域都是 before 值
    let (changes, reg_before) = if let Some(pos) = annot_area.find(" -> ") {
        let changes = annot_area[pos + 4..].trim().to_string();
        let before = annot_area[..pos].trim();
        let reg_before = before.split_whitespace()
            .filter(|tok| !tok.starts_with("mem_w=") && !tok.starts_with("mem_r="))
            .collect::<Vec<_>>()
            .join(" ");
        (changes, reg_before)
    } else {
        // 没有 " -> "：无寄存器变化（如 str/strb 等 store 指令），
        // annotation 中的寄存器值即为 before 值
        let reg_before = annot_area.trim().split_whitespace()
            .filter(|tok| !tok.starts_with("mem_w=") && !tok.starts_with("mem_r="))
            .collect::<Vec<_>>()
            .join(" ");
        (String::new(), reg_before)
    };

    Some(TraceLine {
        seq,
        address: address.to_string(),
        so_offset: so_offset.to_string(),
        so_name,
        disasm,
        changes,
        reg_before,
        mem_rw,
        mem_addr,
        mem_size,
        raw: line.to_string(),
        call_info: None,
    })
}

/// 解析 QBDI 格式的 trace 行
pub fn parse_trace_line_qbdi(seq: u32, raw: &[u8]) -> Option<TraceLine> {
    let line_owned: String;
    let line: &str = match std::str::from_utf8(raw) {
        Ok(s) => s,
        Err(_) => {
            line_owned = bytes_to_hex_escaped(raw);
            &line_owned
        }
    };

    let bytes = line.as_bytes();
    if bytes.len() < 4 || bytes[0] != b'0' || bytes[1] != b'x' {
        return None;
    }

    // 1. Parse absolute address: 0xHEXDIGITS
    let hex_end = bytes[2..]
        .iter()
        .position(|b| !b.is_ascii_hexdigit())
        .map(|p| 2 + p)
        .unwrap_or(bytes.len());

    if hex_end <= 2 || hex_end >= bytes.len() {
        return None;
    }

    let address = line[..hex_end].to_string();

    // 2. Parse optional module info and find instruction start
    let after_addr = bytes[hex_end];
    let (so_name, so_offset, insn_start) = if after_addr == b':' {
        let start = if hex_end + 2 <= bytes.len() && bytes[hex_end + 1] == b' ' {
            hex_end + 2
        } else {
            hex_end + 1
        };
        (None, String::new(), start)
    } else if after_addr == b' ' {
        let rest = &line[hex_end + 1..];
        if let Some(colon_space) = rest.find(": ") {
            let module_part = &rest[..colon_space];
            let (name, offset) = if let Some(plus) = module_part.rfind('+') {
                (Some(module_part[..plus].to_string()), module_part[plus + 1..].to_string())
            } else {
                (Some(module_part.to_string()), String::new())
            };
            (name, offset, hex_end + 1 + colon_space + 2)
        } else {
            return None;
        }
    } else {
        return None;
    };

    if insn_start >= line.len() {
        return None;
    }

    // 3. Extract instruction text and annotation area
    let rest_str = &line[insn_start..];
    let semicolon_pos = rest_str.find(';');
    let (insn_end_rel, annot_start_rel) = if let Some(semi) = semicolon_pos {
        (semi, semi + 1)
    } else {
        let annot = find_annotation_start_str(rest_str, 0);
        (annot, annot)
    };
    let disasm = rest_str[..insn_end_rel].trim().to_string();
    let annot_area = &rest_str[annot_start_rel..];

    // 4. Memory operation
    let mem_rw = if annot_area.contains("mem_w=0x") {
        Some("W".to_string())
    } else if annot_area.contains("mem_r=0x") {
        Some("R".to_string())
    } else {
        None
    };
    let mem_addr = extract_gumtrace_mem_addr(annot_area);
    let mem_size = extract_mem_size(&disasm);

    // 5. Changes and reg_before (same arrow convention as GumTrace)
    let (changes, reg_before) = if let Some(pos) = annot_area.find(" -> ") {
        let changes = annot_area[pos + 4..].trim().to_string();
        let before = annot_area[..pos].trim();
        let reg_before = before.split_whitespace()
            .filter(|tok| !tok.starts_with("mem_w=") && !tok.starts_with("mem_r="))
            .collect::<Vec<_>>()
            .join(" ");
        (changes, reg_before)
    } else {
        let reg_before = annot_area.trim().split_whitespace()
            .filter(|tok| !tok.starts_with("mem_w=") && !tok.starts_with("mem_r="))
            .collect::<Vec<_>>()
            .join(" ");
        (String::new(), reg_before)
    };

    Some(TraceLine {
        seq,
        address,
        so_offset,
        so_name,
        disasm,
        changes,
        reg_before,
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

fn extract_so_info(line: &str) -> (String, Option<String>) {
    // 格式: [timestamp][libtiny.so 0x174250] [encoding] 0xADDR: ...
    // 找 "] [" 模式（module bracket 结束 + encoding bracket 开始之间）
    if let Some(pos) = line.find("] [") {
        let before = &line[..pos];
        if let Some(bracket_start) = before.rfind('[') {
            let module_info = &line[bracket_start + 1..pos];
            // module_info = "libtiny.so 0x174250"
            if let Some(space_pos) = module_info.rfind(' ') {
                let so_name = module_info[..space_pos].to_string();
                let offset = module_info[space_pos + 1..].to_string();
                return (offset, Some(so_name));
            }
        }
    }
    (String::new(), None)
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
    if mn.ends_with('b') && (mn.starts_with("ldr") || mn.starts_with("str") || mn.starts_with("ldu") || mn.starts_with("stu") || mn.starts_with("lda") || mn.starts_with("stl") || mn.starts_with("cas")) {
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

/// 提取 unidbg 格式的 reg_before（=> 之前全部寄存器旧值）
fn extract_reg_before(line: &str, _changes: &str) -> String {
    let arrow_pos = match line.find(" => ") {
        Some(pos) => pos,
        None => return String::new(),
    };

    // 找到反汇编结束的引号位置
    let start = if let Some(q1) = line.find('"') {
        if let Some(q2) = line[q1 + 1..].find('"') {
            q1 + 1 + q2 + 1 // 第二个引号之后
        } else {
            return String::new();
        }
    } else {
        return String::new();
    };

    let between = line[start..arrow_pos].trim();
    // 过滤掉 "; "、"mem[WRITE]"、"mem[READ]"、"abs=0xHEX" token，返回全部寄存器值
    between.split_whitespace()
        .filter(|tok| {
            *tok != ";" &&
            *tok != "mem[WRITE]" &&
            *tok != "mem[READ]" &&
            !tok.starts_with("abs=0x")
        })
        .collect::<Vec<_>>()
        .join(" ")
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
        assert_eq!(result.so_name, Some("libtiny.so".to_string()));
        assert_eq!(result.address, "0x40174250");
        assert_eq!(result.disasm, "stp x29, x30, [sp, #-0x60]!");
        assert_eq!(result.mem_rw, Some("W".to_string()));
        assert_eq!(result.mem_addr, Some("0xbffff6b0".to_string()));
        assert_eq!(result.mem_size, Some(16)); // stp x29, x30 = pair of 8-byte regs
        assert_eq!(result.changes, "x29=0x0 x30=0x7ffff0000 sp=0xbffff6b0");
        assert_eq!(result.reg_before, "x29=0x0 x30=0x7ffff0000 sp=0xbffff710");
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
        assert_eq!(result.reg_before, "x0=0x12345"); // 显示全部 before 寄存器
    }

    #[test]
    fn test_parse_line_no_changes() {
        let raw = br#"[07:17:13 488][libtiny.so 0x530B20] [aa0003e8] 0x40530b20: "nop""#;
        let result = parse_trace_line(0, raw).unwrap();
        assert_eq!(result.disasm, "nop");
        assert_eq!(result.changes, "");
        assert_eq!(result.reg_before, "");
        assert_eq!(result.mem_rw, None);
        assert_eq!(result.mem_addr, None);
    }

    #[test]
    fn test_extract_so_info() {
        let line = r#"[07:17:13 488][libtiny.so 0x174250] [fd7bbaa9] 0x40174250: "stp""#;
        let (offset, so_name) = extract_so_info(line);
        assert_eq!(offset, "0x174250");
        assert_eq!(so_name, Some("libtiny.so".to_string()));
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
