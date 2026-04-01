use memchr::memmem;
use smallvec::SmallVec;

use crate::gumtrace::{find_annotation_start, find_dbi_mem_op};
use crate::parser::{extract_reg_values, parse_operands_into};
use crate::types::*;

/// QBDI trace 格式说明：
///
/// 指令行格式 (带模块信息):
///   0xADDR module+0xOFF: mnemonic operands; reg=val ... mem_r=addr/mem_w=addr -> reg=val ...
///
/// 指令行格式 (无模块信息):
///   0xADDR: mnemonic operands; reg=val ... mem_r=addr/mem_w=addr -> reg=val ...
///
/// 注释/元数据行:
///   # comment
///   # module libfoo.so 0x7f000000 0x10000

/// Parse a QBDI trace line (lightweight mode — skips arrow register extraction).
pub fn parse_line_qbdi(raw: &str) -> Option<ParsedLine> {
    parse_line_qbdi_inner(raw, false)
}

/// Parse a QBDI trace line (full mode — includes arrow register extraction).
#[allow(dead_code)]
pub fn parse_line_qbdi_full(raw: &str) -> Option<ParsedLine> {
    parse_line_qbdi_inner(raw, true)
}

fn parse_line_qbdi_inner(raw: &str, extract_regs: bool) -> Option<ParsedLine> {
    let bytes = raw.as_bytes();

    if bytes.len() < 4 {
        return None;
    }

    // QBDI lines start with "0x"; skip comments (#) and empty lines
    if bytes[0] != b'0' || bytes[1] != b'x' {
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

    // 2. After address: either ':' (no module) or ' ' (module info follows)
    let after_addr = bytes[hex_end];

    let insn_start = if after_addr == b':' {
        // "0xADDR: instruction"
        let start = hex_end + 1;
        if start < bytes.len() && bytes[start] == b' ' {
            start + 1
        } else {
            start
        }
    } else if after_addr == b' ' {
        // "0xADDR module+0xOFF: instruction" or "0xADDR: instruction" with space
        // Find the ': ' that separates module/offset from instruction
        let rest = &bytes[hex_end + 1..];
        if let Some(colon_pos) = find_insn_colon(rest) {
            let abs = hex_end + 1 + colon_pos;
            if abs + 2 <= bytes.len() && bytes[abs + 1] == b' ' {
                abs + 2
            } else {
                abs + 1
            }
        } else {
            return None;
        }
    } else {
        return None;
    };

    if insn_start >= bytes.len() {
        return None;
    }

    // 3. Extract instruction text: from insn_start to ';' (or annotation start)
    let semicolon_pos = memchr::memchr(b';', &bytes[insn_start..]).map(|p| insn_start + p);
    let (insn_end, annot_start) = if let Some(semi) = semicolon_pos {
        (semi, semi + 1)
    } else {
        let annot = find_annotation_start(bytes, insn_start);
        (annot, annot)
    };

    let insn_text = std::str::from_utf8(&bytes[insn_start..insn_end]).ok()?.trim();

    if insn_text.is_empty() {
        return None;
    }

    // 4. Split mnemonic and operand text
    let (mnemonic, operand_text) = match insn_text.find(' ') {
        Some(pos) => (&insn_text[..pos], insn_text[pos + 1..].trim()),
        None => (insn_text, ""),
    };

    if mnemonic.is_empty() {
        return None;
    }

    // 5. Parse operands
    let mut result_line = ParsedLine::default();
    let raw_first_reg_prefix = parse_operands_into(operand_text, &mut result_line);

    // 6. Find " -> " arrow (same as GumTrace)
    let tail = &bytes[annot_start..];
    let arrow_rel = memmem::find(tail, b" -> ");
    let has_arrow = arrow_rel.is_some();
    let arrow_abs_pos = arrow_rel.map(|rel| annot_start + rel);

    // 7. Extract register values if in full mode
    let (pre_arrow_regs, post_arrow_regs);
    if extract_regs {
        if let Some(arrow_pos) = arrow_abs_pos {
            pre_arrow_regs = Some(Box::new(extract_reg_values(&raw[..arrow_pos])));
            post_arrow_regs = Some(Box::new(extract_reg_values(&raw[arrow_pos + 4..])));
        } else {
            pre_arrow_regs = Some(Box::new(extract_reg_values(raw)));
            post_arrow_regs = Some(Box::new(SmallVec::new()));
        }
    } else {
        pre_arrow_regs = None;
        post_arrow_regs = None;
    }

    // 8. Parse memory ops: mem_w=0xADDR or mem_r=0xADDR (shared with GumTrace)
    let mem_op = if annot_start < bytes.len() {
        find_dbi_mem_op(
            &bytes[annot_start..],
            mnemonic,
            operand_text,
            raw_first_reg_prefix,
            bytes,
            arrow_abs_pos,
            result_line.lane_index,
            result_line.lane_elem_width,
        )
    } else {
        None
    };

    // 9. Detect writeback
    let op_bytes = operand_text.as_bytes();
    let writeback =
        memchr::memchr(b'!', op_bytes).is_some() || memmem::find(op_bytes, b"], #").is_some();

    result_line.mnemonic = Mnemonic::new(mnemonic);
    result_line.mem_op = mem_op;
    result_line.has_arrow = has_arrow;
    result_line.arrow_pos = arrow_abs_pos;
    result_line.writeback = writeback;
    result_line.pre_arrow_regs = pre_arrow_regs;
    result_line.post_arrow_regs = post_arrow_regs;

    Some(result_line)
}

/// 在 QBDI 行中查找指令文本的起始冒号。
/// 对于 `module+0xOFF: insn` 格式，找到 `+0x` 后面的 `: `。
/// 对于 `: insn` 格式（地址后直接是冒号），找到第一个 `:`。
fn find_insn_colon(bytes: &[u8]) -> Option<usize> {
    // 查找 ": " 模式
    for i in 0..bytes.len().saturating_sub(1) {
        if bytes[i] == b':' && bytes[i + 1] == b' ' {
            return Some(i);
        }
    }
    // 回退：查找单独的 ':'
    memchr::memchr(b':', bytes)
}

/// Returns true if this is a QBDI comment/metadata line (starts with '#') or empty.
pub fn is_qbdi_comment_line(raw: &str) -> bool {
    let trimmed = raw.trim();
    trimmed.is_empty() || trimmed.starts_with('#')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_qbdi_basic_no_module() {
        let raw = "0x7522e85ce0: sub x0, x29, #0x80; x0=0x75150f2e20 fp=0x75150f2ec0 -> x0=0x75150f2e40";
        let line = parse_line_qbdi(raw).unwrap();
        assert_eq!(line.mnemonic.as_str(), "sub");
        assert_eq!(line.operands.len(), 3);
        assert_eq!(line.operands[0].as_reg(), Some(RegId::X0));
        assert_eq!(line.operands[1].as_reg(), Some(RegId::X29));
        assert!(matches!(line.operands[2], Operand::Imm(0x80)));
        assert!(line.has_arrow);
    }

    #[test]
    fn test_parse_qbdi_with_module() {
        let raw = "0x7522e85ce0 libfoo.so+0x82ce0: sub x0, x29, #0x80; x0=0x0 x29=0x100 -> x0=0x80";
        let line = parse_line_qbdi(raw).unwrap();
        assert_eq!(line.mnemonic.as_str(), "sub");
        assert!(line.has_arrow);
    }

    #[test]
    fn test_parse_qbdi_mem_write() {
        let raw = "0x7522f46438: str x21, [sp, #-0x30]!; x21=0x1 sp=0x75150f2be0 mem_w=0x75150f2bb0";
        let line = parse_line_qbdi(raw).unwrap();
        assert_eq!(line.mnemonic.as_str(), "str");
        let mem = line.mem_op.as_ref().unwrap();
        assert!(mem.is_write);
        assert_eq!(mem.abs, 0x75150f2bb0);
        assert!(line.writeback);
    }

    #[test]
    fn test_parse_qbdi_mem_read() {
        let raw = "0x7522e31a94 libfoo.so+0x2ea94: ldr x17, [x16, #0xf80]; x17=0x51 x16=0x7522fe1000 mem_r=0x7522fe1f80 -> x17=0x79b745a4c0";
        let line = parse_line_qbdi(raw).unwrap();
        let mem = line.mem_op.as_ref().unwrap();
        assert!(!mem.is_write);
        assert_eq!(mem.abs, 0x7522fe1f80);
    }

    #[test]
    fn test_parse_qbdi_no_annotation() {
        let raw = "0x7522e85ce4: bl #0x7522f46438";
        let line = parse_line_qbdi(raw).unwrap();
        assert_eq!(line.mnemonic.as_str(), "bl");
        assert!(!line.has_arrow);
    }

    #[test]
    fn test_parse_qbdi_ret() {
        let raw = "0x7522f464bc: ret";
        let line = parse_line_qbdi(raw).unwrap();
        assert_eq!(line.mnemonic.as_str(), "ret");
    }

    #[test]
    fn test_parse_qbdi_comment_returns_none() {
        assert!(parse_line_qbdi("# QBDI trace").is_none());
        assert!(parse_line_qbdi("# module libfoo.so 0x7f000000 0x10000").is_none());
        assert!(parse_line_qbdi("").is_none());
    }

    #[test]
    fn test_parse_qbdi_ldp() {
        let raw = "0x7a39cae364: ldp x29, x30, [sp, #0x20]; fp=0x75150f2bd0 lr=0x7522f46484 sp=0x75150f2bb0 mem_r=0x75150f2bd0 -> fp=0x75150f2ec0 lr=0x7522e85ce8";
        let line = parse_line_qbdi(raw).unwrap();
        assert_eq!(line.mnemonic.as_str(), "ldp");
        let mem = line.mem_op.as_ref().unwrap();
        assert!(!mem.is_write);
        assert_eq!(mem.elem_width, 8);
    }

    #[test]
    fn test_is_qbdi_comment() {
        assert!(is_qbdi_comment_line("# comment"));
        assert!(is_qbdi_comment_line("  # indented comment"));
        assert!(is_qbdi_comment_line(""));
        assert!(is_qbdi_comment_line("   "));
        assert!(!is_qbdi_comment_line("0x1234: mov x0, x1"));
    }
}
