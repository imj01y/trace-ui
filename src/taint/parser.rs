use memchr::memchr;
use memchr::memmem;
use smallvec::SmallVec;

use super::types::*;

/// 从行中提取引号内的反汇编文本，同时返回第二个引号的位置。
/// 返回 (disasm_str, quote2_position) 以便后续搜索从 quote2 之后继续。
fn find_disasm_with_pos(line: &[u8]) -> Option<(&str, usize)> {
    // unidbg 格式前 ~40 字节是固定格式（时间戳+模块名+地址），引号不会出现在这里
    let skip = 40.min(line.len());
    let q1 = memchr(b'"', &line[skip..])? + skip;
    let q2 = memchr(b'"', &line[q1 + 1..])? + q1 + 1;
    // SAFETY: trace lines are ASCII (ARM64 disassembly text)
    let s = unsafe { std::str::from_utf8_unchecked(&line[q1 + 1..q2]) };
    Some((s, q2))
}

/// 手动解析十六进制字节序列到 u64。
fn parse_hex_u64(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() {
        return None;
    }
    let mut result: u64 = 0;
    for &b in bytes {
        let digit = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => return None,
        };
        result = result.checked_mul(16)?.checked_add(digit as u64)?;
    }
    Some(result)
}

/// 从 `line[from..]` 中提取 mem[READ/WRITE] abs=0xADDR。
/// `from` 允许调用者跳过行首已扫描的部分，避免重复搜索。
fn find_mem_op_raw(line: &[u8], from: usize) -> Option<(bool, u64)> {
    let search = &line[from..];
    let rel_pos = memmem::find(search, b"mem[")?;
    let pos = from + rel_pos;
    let is_write = *line.get(pos + 4)? == b'W';
    let abs_marker = memmem::find(&line[pos..], b"abs=0x")?;
    let val_start = pos + abs_marker + 6;
    let val_end = line[val_start..]
        .iter()
        .position(|b| !b.is_ascii_hexdigit())
        .map(|p| val_start + p)
        .unwrap_or(line.len());
    let addr = parse_hex_u64(&line[val_start..val_end])?;
    Some((is_write, addr))
}

/// Parse a trace line (lightweight mode for scan — skips arrow register extraction).
///
/// Returns `None` for lines that don't match the expected trace format
/// (empty lines, log lines without disassembly, etc.).
pub fn parse_line(raw: &str) -> Option<ParsedLine> {
    parse_line_inner(raw, false)
}

/// Parse a trace line (full mode for validate — includes arrow register extraction).
#[allow(dead_code)]
pub fn parse_line_full(raw: &str) -> Option<ParsedLine> {
    parse_line_inner(raw, true)
}

fn parse_line_inner(raw: &str, extract_regs: bool) -> Option<ParsedLine> {
    let bytes = raw.as_bytes();

    // 1. Extract disassembly inside quotes + cursor position after quote2
    let (disasm, q2) = find_disasm_with_pos(bytes)?;

    // 2. Split mnemonic and operand text
    let (mnemonic, operand_text) = match disasm.find(' ') {
        Some(pos) => (&disasm[..pos], disasm[pos + 1..].trim()),
        None => (disasm, ""),
    };

    // Reject empty mnemonic (e.g., from `""` in trace)
    if mnemonic.is_empty() {
        return None;
    }

    // 3. Parse operand list (searches only within operand_text — no full-line scan)
    let mut result_line = ParsedLine::default();
    let raw_first_reg_prefix = parse_operands_into(operand_text, &mut result_line);

    // 4. Find arrow — search only from quote2 onward (not from line start)
    let tail = &bytes[q2..];
    let arrow_rel = memmem::find(tail, b" => ");
    let has_arrow = arrow_rel.is_some();

    let (pre_arrow_regs, post_arrow_regs);
    if extract_regs {
        if let Some(rel) = arrow_rel {
            let arrow_abs = q2 + rel;
            pre_arrow_regs = Some(Box::new(extract_reg_values(&raw[..arrow_abs])));
            post_arrow_regs = Some(Box::new(extract_reg_values(&raw[arrow_abs + 4..])));
        } else {
            pre_arrow_regs = Some(Box::new(extract_reg_values(raw)));
            post_arrow_regs = Some(Box::new(SmallVec::new()));
        }
    } else {
        pre_arrow_regs = None;
        post_arrow_regs = None;
    }

    // 5. Parse mem[READ/WRITE] — search from quote2 onward (mem always appears after disasm)
    let mem_op = find_mem_op_raw(bytes, q2).map(|(is_write, abs)| {
        let elem_width = determine_elem_width(mnemonic, raw_first_reg_prefix);
        // 5b. Extract value for pass-through pruning
        let value = if elem_width <= 8 {
            first_data_reg_name(operand_text).and_then(|reg_name| {
                let search_start = if is_write {
                    q2 // STORE: search from after quotes
                } else {
                    // LOAD: search after => to get loaded value
                    match arrow_rel {
                        Some(rel) => q2 + rel + 4,
                        None => return None,
                    }
                };
                let raw_val = find_reg_value(bytes, reg_name.as_bytes(), search_start)?;
                let mask = if elem_width >= 8 {
                    u64::MAX
                } else {
                    (1u64 << (elem_width as u32 * 8)) - 1
                };
                Some(raw_val & mask)
            })
        } else {
            None // SIMD 128-bit: skip
        };
        MemOp {
            is_write,
            abs,
            elem_width,
            value,
        }
    });

    // 6. Detect writeback (searches only operand_text — no full-line scan)
    let op_bytes = operand_text.as_bytes();
    let writeback = memchr(b'!', op_bytes).is_some() || memmem::find(op_bytes, b"], #").is_some();

    result_line.mnemonic = Mnemonic::new(mnemonic);
    result_line.mem_op = mem_op;
    result_line.has_arrow = has_arrow;
    result_line.writeback = writeback;
    result_line.pre_arrow_regs = pre_arrow_regs;
    result_line.post_arrow_regs = post_arrow_regs;

    Some(result_line)
}

/// 从文本中提取所有 `name=0xHEX` 寄存器值对（手写替换 REG_VAL_RE）。
///
/// 扫描 `=0x` 模式，向左提取寄存器名，向右提取十六进制值。
/// 128-bit SIMD 值溢出 u64 时截断为 0。
fn extract_reg_values(text: &str) -> SmallVec<[(RegId, u64); 4]> {
    let bytes = text.as_bytes();
    let mut result = SmallVec::new();
    let mut pos = 0;

    while pos + 3 <= bytes.len() {
        // 查找 "=0x" 模式
        let eq_pos = match memmem::find(&bytes[pos..], b"=0x") {
            Some(p) => pos + p,
            None => break,
        };

        // 向左提取寄存器名：连续的 ASCII 字母+数字
        let name_start = bytes[..eq_pos]
            .iter()
            .rposition(|b| !b.is_ascii_alphanumeric())
            .map(|p| p + 1)
            .unwrap_or(0);

        // 名字至少 2 字符（如 "x0"），且首字符为小写字母
        let name_bytes = &bytes[name_start..eq_pos];
        let valid_name = name_bytes.len() >= 2 && name_bytes[0].is_ascii_lowercase();

        // 向右提取十六进制值
        let val_start = eq_pos + 3; // 跳过 "=0x"
        let val_end = bytes[val_start..]
            .iter()
            .position(|b| !b.is_ascii_hexdigit())
            .map(|p| val_start + p)
            .unwrap_or(bytes.len());

        if valid_name {
            // SAFETY: name_bytes are already validated as ASCII alphanumeric above
            let name_str = unsafe { std::str::from_utf8_unchecked(name_bytes) };
            if let Some(reg) = parse_reg(name_str) {
                let val = parse_hex_u64(&bytes[val_start..val_end]).unwrap_or(0);
                result.push((reg, val));
            }
        }

        pos = val_end.max(eq_pos + 3); // 至少前进到 "=0x" 之后
    }

    result
}

/// Parse operand text (comma-separated), writing results directly into `out`.
///
/// Returns the first operand's raw register prefix byte (needed for memory access
/// width before register normalization, e.g., 'w' -> 4 bytes, 'x' -> 8 bytes).
///
/// Also populates `out.operands`, `out.base_reg`, and `out.lane_index`.
fn parse_operands_into(text: &str, out: &mut ParsedLine) -> Option<u8> {
    let mut first_reg_prefix: Option<u8> = None;

    if text.is_empty() {
        return first_reg_prefix;
    }

    let tokens = split_operands(text);

    for (i, token) in tokens.iter().enumerate() {
        let token = token.trim();

        // Strip curly braces (SIMD register list markers), zero allocation
        let token = token.trim_matches(['{', '}']);

        // Square brackets → memory address operand with base register
        if token.starts_with('[') {
            let inner = token
                .trim_start_matches('[')
                .trim_end_matches(']')
                .trim_end_matches('!');
            for part in inner.split(',') {
                let part = part.trim();
                if let Some(reg) = try_parse_reg_operand(part) {
                    if out.base_reg.is_none() {
                        out.base_reg = Some(reg);
                    }
                    out.operands.push(Operand::Reg(reg));
                }
            }
            continue;
        }

        // Extract lane index if present (e.g., "v0.s[1]" → "v0.s", Some(1))
        let (token, extracted_lane) = extract_lane_index(token);
        if extracted_lane.is_some() {
            out.lane_index = extracted_lane;
        }

        // Register operand
        if let Some(reg) = try_parse_reg_operand(token) {
            if i == 0 && first_reg_prefix.is_none() {
                first_reg_prefix = token.as_bytes().first().copied();
            }
            out.operands.push(Operand::Reg(reg));
            continue;
        }

        // Immediate (#0x1234, #-5, #123)
        if let Some(val_str) = token.strip_prefix('#') {
            if let Some(val) = parse_imm(val_str) {
                out.operands.push(Operand::Imm(val));
            }
            continue;
        }

        // Address literal (0x... as in branch targets)
        if token.starts_with("0x") || token.starts_with("0X") {
            if let Some(val) = parse_imm(token) {
                out.operands.push(Operand::Imm(val));
            }
            continue;
        }

        // Unrecognized tokens → skip (e.g., shift specifiers like "lsl #3")
    }

    first_reg_prefix
}

/// 按顶层逗号分割操作数，不分割方括号内的逗号。
/// 返回切片引用而非 String，零堆分配。
fn split_operands(text: &str) -> SmallVec<[&str; 6]> {
    let mut result = SmallVec::new();
    let bytes = text.as_bytes();
    let mut start = 0;
    let mut bracket_depth: i32 = 0;

    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'[' => bracket_depth += 1,
            b']' => bracket_depth -= 1,
            b',' if bracket_depth == 0 => {
                result.push(&text[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    if start < text.len() {
        result.push(&text[start..]);
    }
    result
}

/// Try parsing a token as a register, stripping arrangement specifiers (e.g., v0.16b → v0).
fn try_parse_reg_operand(token: &str) -> Option<RegId> {
    let clean = token.split('.').next().unwrap_or(token);
    parse_reg(clean)
}

/// Extract lane index from token like "v0.s[1]".
/// Returns (token without lane bracket, optional lane index).
fn extract_lane_index(token: &str) -> (&str, Option<u8>) {
    // Only look for lane index if there's an arrangement specifier (contains '.')
    if let Some(dot_pos) = token.find('.') {
        // Look for [N] after the dot
        if let Some(bracket_start) = token[dot_pos..].find('[') {
            let abs_bracket = dot_pos + bracket_start;
            if let Some(bracket_end) = token[abs_bracket..].find(']') {
                let idx_str = &token[abs_bracket + 1..abs_bracket + bracket_end];
                if let Ok(idx) = idx_str.parse::<u8>() {
                    return (&token[..abs_bracket], Some(idx));
                }
            }
        }
    }
    (token, None)
}

/// Parse an immediate value from a string.
/// Handles hex (0x...), negative hex (-0x...), and decimal formats.
fn parse_imm(s: &str) -> Option<i64> {
    if s.starts_with("0x") || s.starts_with("0X") {
        u64::from_str_radix(&s[2..], 16).ok().map(|v| v as i64)
    } else if s.starts_with("-0x") || s.starts_with("-0X") {
        i64::from_str_radix(&s[3..], 16).ok().map(|v| -v)
    } else {
        s.parse::<i64>().ok()
    }
}

/// Extract the first data register's raw name from operand text (e.g., "w8" from "w8, [sp, #0x10]").
///
/// Used for value extraction: we need the original (pre-normalization) register name
/// to search for `regname=0xHEX` patterns in the trace line text.
fn first_data_reg_name(operand_text: &str) -> Option<&str> {
    let first_tok = operand_text.split(',').next()?.trim();
    let first_tok = first_tok
        .trim_start_matches('{')
        .trim_end_matches('}')
        .trim();
    let first_tok = first_tok.split('.').next()?; // strip arrangement specifier
    let b = first_tok.as_bytes();
    if b.len() >= 2
        && matches!(
            b[0],
            b'w' | b'x' | b'q' | b'd' | b's' | b'b' | b'h' | b'v'
        )
        && b[1..].iter().all(|c| c.is_ascii_digit())
    {
        Some(first_tok)
    } else {
        None
    }
}

/// Find `reg_name=0xHEX` in `bytes[start_pos..]`, return parsed hex value.
///
/// Ensures exact register name match (no prefix collisions like "x1" matching "x10")
/// by checking the character before the name is not alphanumeric and "=0x" follows immediately.
fn find_reg_value(bytes: &[u8], reg_name: &[u8], start_pos: usize) -> Option<u64> {
    let search = &bytes[start_pos..];
    let mut pos = 0;
    while pos + reg_name.len() + 3 <= search.len() {
        let found = memmem::find(&search[pos..], reg_name)?;
        let abs = pos + found;
        let eq_pos = abs + reg_name.len();
        // Check "=0x" follows
        if eq_pos + 3 <= search.len()
            && search[eq_pos] == b'='
            && search[eq_pos + 1] == b'0'
            && search[eq_pos + 2] == b'x'
        {
            // Verify the character before reg_name is not alphanumeric
            let char_before = if abs == 0 {
                b' '
            } else {
                search[abs - 1]
            };
            if !char_before.is_ascii_alphanumeric() {
                let val_start = eq_pos + 3;
                let val_end = search[val_start..]
                    .iter()
                    .position(|b| !b.is_ascii_hexdigit())
                    .map(|p| val_start + p)
                    .unwrap_or(search.len());
                return parse_hex_u64(&search[val_start..val_end]);
            }
        }
        pos = abs + 1;
    }
    None
}

/// Infer memory access width from mnemonic and the first operand's raw register prefix.
///
/// The prefix must be captured BEFORE register normalization (w→x, d→v, etc.)
/// because it determines the access width:
/// - w → 4 bytes (32-bit)
/// - x → 8 bytes (64-bit)
/// - s → 4 bytes (single float)
/// - d → 8 bytes (double float)
/// - q → 16 bytes (128-bit vector)
/// - v → 16 bytes (full vector, default)
fn determine_elem_width(mnemonic: &str, first_reg_prefix: Option<u8>) -> u8 {
    match mnemonic {
        "ldrb" | "strb" | "ldrsb" | "ldarb" | "stlrb" | "ldurb" | "sturb" | "ldtrb" | "sttrb"
        | "ldaprb" => 1,
        "ldrh" | "strh" | "ldrsh" | "ldarh" | "stlrh" | "ldurh" | "sturh" | "ldtrh" | "sttrh"
        | "ldaprh" => 2,
        "ldrsw" | "ldursw" | "ldtrsw" | "ldpsw" => 4,
        _ => match first_reg_prefix {
            Some(b'w') => 4,
            Some(b'x') => 8,
            Some(b's') => 4,
            Some(b'd') => 8,
            Some(b'q') => 16,
            Some(b'v') => 16, // default full vector
            _ => 8,           // conservative default
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_standard_computation() {
        let raw = r#"[22:39:18 210][lib.so 0x100] [8b090108] 0x40000108: "add x8, x8, x9" x8=0x5 x9=0xa => x8=0xf"#;
        let line = parse_line(raw).expect("should parse");
        assert_eq!(line.mnemonic.as_str(), "add");
        assert_eq!(line.operands.len(), 3);
        assert_eq!(line.operands[0].as_reg(), Some(RegId::X8));
        assert_eq!(line.operands[1].as_reg(), Some(RegId::X8));
        assert_eq!(line.operands[2].as_reg(), Some(RegId::X9));
        assert!(line.has_arrow);
        assert!(line.mem_op.is_none());
    }

    #[test]
    fn test_parse_memory_write() {
        let raw = r#"[22:39:18 210][lib.so 0x10c] [f9000be8] 0x4000010c: "str x8, [sp, #0x10]" ; mem[WRITE] abs=0xbffff010 x8=0xf sp=0xbffff000 => x8=0xf"#;
        let line = parse_line(raw).expect("should parse");
        assert_eq!(line.mnemonic.as_str(), "str");
        assert_eq!(line.operands.len(), 2); // x8, sp
        assert_eq!(line.operands[0].as_reg(), Some(RegId::X8));
        assert_eq!(line.operands[1].as_reg(), Some(RegId::SP));
        assert_eq!(line.base_reg, Some(RegId::SP));
        let mem = line.mem_op.as_ref().unwrap();
        assert!(mem.is_write);
        assert_eq!(mem.abs, 0xbffff010);
        assert_eq!(mem.elem_width, 8); // x register → 8 bytes
    }

    #[test]
    fn test_parse_memory_read() {
        let raw = r#"[22:39:18 210][lib.so 0x110] [f9400fe0] 0x40000110: "ldr x0, [sp, #0x10]" ; mem[READ] abs=0xbffff010 sp=0xbffff000 => x0=0xf"#;
        let line = parse_line(raw).expect("should parse");
        assert_eq!(line.mnemonic.as_str(), "ldr");
        let mem = line.mem_op.as_ref().unwrap();
        assert!(!mem.is_write);
        assert_eq!(mem.abs, 0xbffff010);
    }

    #[test]
    fn test_parse_mov_pure() {
        let raw = r#"[22:39:18 210][lib.so 0x100] [d2800108] 0x40000100: "mov x8, #5" => x8=0x5"#;
        let line = parse_line(raw).expect("should parse");
        assert_eq!(line.mnemonic.as_str(), "mov");
        assert_eq!(line.operands.len(), 2);
        assert_eq!(line.operands[0].as_reg(), Some(RegId::X8));
        assert!(matches!(line.operands[1], Operand::Imm(5)));
        assert!(line.has_arrow);
    }

    #[test]
    fn test_parse_branch_no_arrow() {
        let raw = r#"[22:39:18 210][lib.so 0x200] [14000010] 0x40000200: "b #0x40000240""#;
        let line = parse_line(raw).expect("should parse");
        assert_eq!(line.mnemonic.as_str(), "b");
        assert!(!line.has_arrow);
    }

    #[test]
    fn test_parse_cmp_nzcv() {
        let raw = r#"[22:39:18 210][lib.so 0x300] [6b09011f] 0x40000300: "cmp x8, x9" x8=0x5 x9=0xa => nzcv=0x80000000"#;
        let line = parse_line(raw).expect("should parse");
        assert_eq!(line.mnemonic.as_str(), "cmp");
        assert_eq!(line.operands[0].as_reg(), Some(RegId::X8));
        assert_eq!(line.operands[1].as_reg(), Some(RegId::X9));
    }

    #[test]
    fn test_parse_cond_branch() {
        let raw = r#"[22:39:18 210][lib.so 0x304] [54000040] 0x40000304: "b.eq #0x4000030c" nzcv=0x40000000"#;
        let line = parse_line(raw).expect("should parse");
        assert_eq!(line.mnemonic.as_str(), "b.eq");
        assert!(!line.has_arrow);
    }

    #[test]
    fn test_parse_invalid_line() {
        assert!(parse_line("").is_none());
        assert!(parse_line("some random log line").is_none());
    }

    #[test]
    fn test_parse_w_register_width() {
        let raw = r#"[22:39:18 210][lib.so 0x10c] [b9001008] 0x4000010c: "str w8, [x0, #0x10]" ; mem[WRITE] abs=0xbffff010 w8=0xf x0=0xbffff000 => w8=0xf"#;
        let line = parse_line(raw).expect("should parse");
        let mem = line.mem_op.as_ref().unwrap();
        assert_eq!(mem.elem_width, 4); // w register → 4 bytes
    }

    // Additional edge-case tests

    #[test]
    fn test_parse_imm_hex() {
        assert_eq!(parse_imm("0x10"), Some(0x10));
        assert_eq!(parse_imm("0xFF"), Some(0xFF));
        assert_eq!(parse_imm("-0x1"), Some(-1));
    }

    #[test]
    fn test_parse_imm_decimal() {
        assert_eq!(parse_imm("5"), Some(5));
        assert_eq!(parse_imm("-3"), Some(-3));
        assert_eq!(parse_imm("0"), Some(0));
    }

    #[test]
    fn test_split_operands_simple() {
        let result = split_operands("x8, x9, x10");
        assert_eq!(result.as_slice(), &["x8", " x9", " x10"]);
    }

    #[test]
    fn test_split_operands_with_brackets() {
        let result = split_operands("[sp, #0x10]");
        assert_eq!(result.as_slice(), &["[sp, #0x10]"]);
    }

    #[test]
    fn test_split_operands_reg_and_bracket() {
        let result = split_operands("x8, [sp, #0x10]");
        assert_eq!(result.as_slice(), &["x8", " [sp, #0x10]"]);
    }

    #[test]
    fn test_determine_elem_width_byte_mnemonics() {
        assert_eq!(determine_elem_width("ldrb", None), 1);
        assert_eq!(determine_elem_width("strb", None), 1);
        assert_eq!(determine_elem_width("ldarb", None), 1);
    }

    #[test]
    fn test_determine_elem_width_half_mnemonics() {
        assert_eq!(determine_elem_width("ldrh", None), 2);
        assert_eq!(determine_elem_width("strh", None), 2);
    }

    #[test]
    fn test_determine_elem_width_by_prefix() {
        assert_eq!(determine_elem_width("ldr", Some(b'w')), 4);
        assert_eq!(determine_elem_width("ldr", Some(b'x')), 8);
        assert_eq!(determine_elem_width("ldr", Some(b's')), 4);
        assert_eq!(determine_elem_width("ldr", Some(b'd')), 8);
        assert_eq!(determine_elem_width("ldr", Some(b'q')), 16);
    }

    #[test]
    fn test_ldpsw_elem_width_is_4() {
        // ldpsw loads 32-bit words (sign-extended to 64-bit x registers)
        // elem_width should be 4, not 8 from the x register prefix
        assert_eq!(determine_elem_width("ldpsw", Some(b'x')), 4);
    }

    #[test]
    fn test_parse_pre_post_arrow_regs() {
        let raw = r#"[22:39:18 210][lib.so 0x100] [8b090108] 0x40000108: "add x8, x8, x9" x8=0x5 x9=0xa => x8=0xf"#;
        let line = parse_line_full(raw).expect("should parse");
        let pre = line.pre_arrow_regs.as_ref().unwrap();
        let post = line.post_arrow_regs.as_ref().unwrap();
        assert!(pre.iter().any(|(r, v)| *r == RegId::X9 && *v == 0xa));
        assert!(pre.iter().any(|(r, v)| *r == RegId::X8 && *v == 0x5));
        assert!(post.iter().any(|(r, v)| *r == RegId::X8 && *v == 0xf));
        assert!(!post.iter().any(|(r, _)| *r == RegId::X9));
    }

    #[test]
    fn test_parse_no_arrow_all_pre() {
        let raw = r#"[22:39:18 210][lib.so 0x200] [14000010] 0x40000200: "b #0x40000240""#;
        let line = parse_line(raw).expect("should parse");
        assert!(!line.has_arrow);
        assert!(line.post_arrow_regs.is_none());
    }

    #[test]
    fn test_parse_cmp_nzcv_arrow_split() {
        let raw = r#"[22:39:18 210][lib.so 0x300] [6b09011f] 0x40000300: "cmp x8, x9" x8=0x5 x9=0xa => nzcv=0x80000000"#;
        let line = parse_line_full(raw).expect("should parse");
        let pre = line.pre_arrow_regs.as_ref().unwrap();
        let post = line.post_arrow_regs.as_ref().unwrap();
        assert_eq!(pre.len(), 2);
        assert_eq!(post.len(), 1);
        assert!(post.iter().any(|(r, _)| *r == RegId::NZCV));
    }

    #[test]
    fn test_parse_mnemonic_only_no_operands() {
        let raw = r#"[22:39:18 210][lib.so 0x100] [d503201f] 0x40000100: "nop""#;
        let line = parse_line(raw).expect("should parse");
        assert_eq!(line.mnemonic.as_str(), "nop");
        assert!(line.operands.is_empty());
        assert!(!line.has_arrow);
    }

    #[test]
    fn test_parse_post_index_writeback() {
        // Post-index form: [sp], #0x10 — no '!' but sp is still modified
        let raw = r#"[00:00:00 001][lib.so 0x100] [a8c17bfd] 0x40000100: "ldp x29, x30, [sp], #0x10" ; mem[READ] abs=0xbffff000 x29=0x0 x30=0x0 sp=0xbffff000 => x29=0x0 x30=0x0 sp=0xbffff010"#;
        let line = parse_line(raw).expect("should parse");
        assert_eq!(line.mnemonic.as_str(), "ldp");
        assert!(
            line.writeback,
            "post-index form should be detected as writeback"
        );
        assert_eq!(line.base_reg, Some(RegId::SP));
    }

    #[test]
    fn test_parse_writeback() {
        let raw = r#"[22:39:18 210][lib.so 0x100] [a9bf7bfd] 0x40000100: "stp x29, x30, [sp, #-0x10]!" ; mem[WRITE] abs=0xbfffeff0 x29=0x0 x30=0x0 sp=0xbffff000 => x29=0x0"#;
        let line = parse_line(raw).expect("should parse");
        assert_eq!(line.mnemonic.as_str(), "stp");
        assert!(line.writeback);
        assert_eq!(line.base_reg, Some(RegId::SP));
    }

    #[test]
    fn test_parse_simd_lane_load() {
        let raw = r#"[00:00:00 001][lib.so 0x100] [0d401de0] 0x40000100: "ld1 {v0.s}[1], [x15]" ; mem[READ] abs=0x40500000 q0=0x0 x15=0x40500000 => q0=0x100"#;
        let line = parse_line(raw).expect("should parse");
        assert_eq!(line.mnemonic.as_str(), "ld1");
        assert_eq!(line.operands.len(), 2);
        assert_eq!(line.operands[0].as_reg(), Some(RegId::V0));
        assert_eq!(line.operands[1].as_reg(), Some(RegId::X15));
        assert_eq!(line.lane_index, Some(1));
    }

    #[test]
    fn test_parse_simd_full_store() {
        let raw = r#"[00:00:00 001][lib.so 0x100] [4c000000] 0x40000100: "st1 {v0.16b}, [x0]" ; mem[WRITE] abs=0x40500000 q0=0xff x0=0x40500000 => q0=0xff"#;
        let line = parse_line(raw).expect("should parse");
        assert_eq!(line.mnemonic.as_str(), "st1");
        assert_eq!(line.operands.len(), 2);
        assert_eq!(line.operands[0].as_reg(), Some(RegId::V0));
        assert_eq!(line.operands[1].as_reg(), Some(RegId::X0));
        assert_eq!(line.lane_index, None);
    }

    #[test]
    fn test_parse_simd_multi_reg() {
        let raw = r#"[00:00:00 001][lib.so 0x100] [4c402000] 0x40000100: "ld1 {v0.16b, v1.16b}, [x0]" ; mem[READ] abs=0x40500000 q0=0x0 q1=0x0 x0=0x40500000 => q0=0x1 q1=0x2"#;
        let line = parse_line(raw).expect("should parse");
        assert_eq!(line.mnemonic.as_str(), "ld1");
        assert!(line.operands.len() >= 3);
        assert_eq!(line.operands[0].as_reg(), Some(RegId::V0));
        assert_eq!(line.operands[1].as_reg(), Some(RegId::V1));
        assert_eq!(line.operands[2].as_reg(), Some(RegId::X0));
    }

    #[test]
    fn test_extract_lane_index_with_lane() {
        let (rest, lane) = extract_lane_index("v0.s[1]");
        assert_eq!(rest, "v0.s");
        assert_eq!(lane, Some(1));
    }

    #[test]
    fn test_extract_lane_index_without_lane() {
        let (rest, lane) = extract_lane_index("v0.16b");
        assert_eq!(rest, "v0.16b");
        assert_eq!(lane, None);
    }

    #[test]
    fn test_extract_lane_index_no_dot() {
        let (rest, lane) = extract_lane_index("x15");
        assert_eq!(rest, "x15");
        assert_eq!(lane, None);
    }

    #[test]
    fn test_parse_line_empty_string() {
        assert!(parse_line("").is_none());
    }

    #[test]
    fn test_parse_line_no_quotes() {
        let line = r#"[00:00:00 001][lib.so 0x100] [d2800108] 0x40000100: no_quotes_here"#;
        assert!(parse_line(line).is_none());
    }

    #[test]
    fn test_parse_line_single_quote() {
        let line = r#"[00:00:00 001][lib.so 0x100] [d2800108] 0x40000100: "incomplete"#;
        assert!(parse_line(line).is_none());
    }

    #[test]
    fn test_parse_line_empty_mnemonic() {
        let line = r#"[00:00:00 001][lib.so 0x100] [d2800108] 0x40000100: "" => x0=0x0"#;
        assert!(parse_line(line).is_none());
    }

    // =========================================================================
    // Value extraction tests (pass-through pruning)
    // =========================================================================

    #[test]
    fn test_store_value_extraction() {
        let raw = r#"[00:00:00 001][lib.so 0x10c] [f9000000] 0x4000010c: "str x8, [sp, #0x10]" ; mem[WRITE] abs=0xbffff010 x8=0xf sp=0xbffff000 => x8=0xf"#;
        let line = parse_line(raw).expect("should parse");
        let mem = line.mem_op.as_ref().unwrap();
        assert!(mem.is_write);
        assert_eq!(mem.value, Some(0xf));
    }

    #[test]
    fn test_load_value_extraction() {
        let raw = r#"[00:00:00 001][lib.so 0x110] [f9400000] 0x40000110: "ldr x0, [sp, #0x10]" ; mem[READ] abs=0xbffff010 sp=0xbffff000 => x0=0xf"#;
        let line = parse_line(raw).expect("should parse");
        let mem = line.mem_op.as_ref().unwrap();
        assert!(!mem.is_write);
        assert_eq!(mem.value, Some(0xf));
    }

    #[test]
    fn test_strb_value_masking() {
        // strb w8 with full 32-bit value in trace → should mask to 1 byte
        let raw = r#"[00:00:00 001][lib.so 0x10c] [39000108] 0x4000010c: "strb w8, [x0, #0]" ; mem[WRITE] abs=0xbffff010 w8=0x8ecb0cc7 x0=0xbffff010 => w8=0x8ecb0cc7"#;
        let line = parse_line(raw).expect("should parse");
        let mem = line.mem_op.as_ref().unwrap();
        assert_eq!(mem.elem_width, 1);
        assert_eq!(mem.value, Some(0xc7));
    }

    #[test]
    fn test_simd_value_none() {
        // q register (128-bit) → value should be None
        let raw = r#"[00:00:00 001][lib.so 0x100] [3dc00000] 0x40000100: "ldr q0, [x0]" ; mem[READ] abs=0x40500000 x0=0x40500000 => q0=0x12345678"#;
        let line = parse_line(raw).expect("should parse");
        let mem = line.mem_op.as_ref().unwrap();
        assert_eq!(mem.elem_width, 16);
        assert_eq!(mem.value, None);
    }

    #[test]
    fn test_load_value_from_post_arrow_only() {
        // x0 appears before and after arrow with different values
        // LOAD should extract from post-arrow
        let raw = r#"[00:00:00 001][lib.so 0x110] [f9400000] 0x40000110: "ldr x0, [sp, #0x10]" ; mem[READ] abs=0xbffff010 x0=0xdead sp=0xbffff000 => x0=0xbeef"#;
        let line = parse_line(raw).expect("should parse");
        let mem = line.mem_op.as_ref().unwrap();
        assert_eq!(mem.value, Some(0xbeef));
    }

    #[test]
    fn test_first_data_reg_name() {
        assert_eq!(first_data_reg_name("x8, [sp, #0x10]"), Some("x8"));
        assert_eq!(first_data_reg_name("w0, [x1]"), Some("w0"));
        assert_eq!(first_data_reg_name("q0, [x0]"), Some("q0"));
        assert_eq!(first_data_reg_name("{v0.16b}, [x0]"), Some("v0"));
        assert_eq!(first_data_reg_name("[sp, #0x10]"), None);
        assert_eq!(first_data_reg_name(""), None);
    }

    #[test]
    fn test_find_reg_value_basic() {
        let line = b"x8=0xf sp=0xbffff000";
        assert_eq!(find_reg_value(line, b"x8", 0), Some(0xf));
        assert_eq!(find_reg_value(line, b"sp", 0), Some(0xbffff000));
    }

    #[test]
    fn test_find_reg_value_no_prefix_collision() {
        // Searching for "x1" should not match "x10"
        let line = b" x10=0xaaa x1=0xbbb";
        assert_eq!(find_reg_value(line, b"x1", 0), Some(0xbbb));
    }

    #[test]
    fn test_find_reg_value_not_found() {
        let line = b"x8=0xf";
        assert_eq!(find_reg_value(line, b"x9", 0), None);
    }
}
