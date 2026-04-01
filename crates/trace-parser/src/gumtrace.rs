use memchr::memmem;
use smallvec::SmallVec;

use crate::parser::{
    self, determine_elem_width, extract_reg_values, extract_simd_lane_value, find_reg_value,
    find_reg_value_u128, first_data_reg_name, is_simd_reg_name, parse_hex_u64,
    parse_operands_into, simd_arrangement_total_width,
};
use crate::types::*;
use crate::types::TraceFormat;

/// 外部函数调用的注释信息（关联到 bl/blr 指令行）
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CallAnnotation {
    pub func_name: String,
    pub is_jni: bool,
    pub args: Vec<(String, String)>,  // (index, decoded_value)
    pub ret_value: Option<String>,
    pub raw_lines: Vec<String>,       // 所有原始特殊行（用于 tooltip）
}

impl CallAnnotation {
    /// 生成紧凑摘要，如: strlen("HttpRequestCallback") → 0x13
    pub fn summary(&self) -> String {
        let decoded_args: Vec<String> = self.args.iter()
            .map(|(_, v)| {
                if v.starts_with("0x") || v.starts_with("0X") {
                    v.clone()
                } else {
                    format!("\"{}\"", v)
                }
            })
            .collect();
        let args_str = if decoded_args.is_empty() {
            String::new()
        } else {
            format!("({})", decoded_args.join(", "))
        };

        let ret_str = self.ret_value.as_deref().unwrap_or("");

        if ret_str.is_empty() {
            format!("{}{}", self.func_name, args_str)
        } else {
            format!("{}{} → {}", self.func_name, args_str, ret_str)
        }
    }

    /// 生成完整 tooltip 文本
    pub fn tooltip(&self) -> String {
        self.raw_lines.join("\n")
    }

    /// 将 raw_lines 中的 hexdump 行解析为连续字节流，返回 (hex_string, ascii_string)。
    /// hex_string: "48 74 74 70 52 65 71 75 ..." 连续的 hex 字节，跨行拼接
    /// ascii_string: "HttpRequestCallback\0" 连续的 ASCII 文本，跨行拼接
    pub fn merged_hexdump(&self) -> (String, Vec<u8>) {
        let mut hex_parts = Vec::new();
        let mut bytes = Vec::new();
        for line in &self.raw_lines {
            let trimmed = line.trim();
            // hexdump 数据行格式: "ADDR: XX XX XX ... |ASCII...|"
            // 跳过 "hexdump at address ..." 头行
            if trimmed.starts_with("hexdump ") || trimmed.is_empty() {
                continue;
            }
            // 检测是否是 hex 数据行：首字符是十六进制数字且含 ": "
            if let Some(colon_pos) = trimmed.find(": ") {
                let addr_part = &trimmed[..colon_pos];
                if addr_part.chars().all(|c| c.is_ascii_hexdigit()) {
                    // 提取 hex 部分（冒号后到 | 之前）
                    let after_colon = &trimmed[colon_pos + 2..];
                    let hex_end = after_colon.find('|').unwrap_or(after_colon.len());
                    let hex_str = after_colon[..hex_end].trim();
                    hex_parts.push(hex_str.to_string());
                    // 解析 hex 字节
                    for part in hex_str.split_whitespace() {
                        if let Ok(b) = u8::from_str_radix(part, 16) {
                            bytes.push(b);
                        }
                    }
                }
            }
        }
        (hex_parts.join(" "), bytes)
    }

    /// 生成用于搜索的完整文本，包含 summary + tooltip + 连续 hexdump ASCII
    pub fn searchable_text(&self) -> String {
        let mut text = format!("{}\n{}", self.summary(), self.tooltip());
        let (hex_str, raw_bytes) = self.merged_hexdump();
        if !hex_str.is_empty() {
            text.push('\n');
            text.push_str(&hex_str);
            // 追加无空格 hex（支持紧凑 hex 搜索如 "da487d00000029"）
            text.push('\n');
            text.push_str(&hex_str.replace(" ", ""));
            // 追加连续 ASCII 表示（可打印字符保留，不可打印用 . 替换）
            let ascii: String = raw_bytes.iter().map(|&b| {
                if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' }
            }).collect();
            text.push('\n');
            text.push_str(&ascii);
        }
        text
    }
}

/// 从文件的前几行自动检测 trace 格式
pub fn detect_format(data: &[u8]) -> TraceFormat {
    let mut pos = 0;
    let mut checked = 0;
    while pos < data.len() && checked < 20 {
        let end = memchr::memchr(b'\n', &data[pos..])
            .map(|i| pos + i)
            .unwrap_or(data.len());
        let line = &data[pos..end];

        if !line.is_empty() {
            // unidbg: starts with [HH:MM:SS (timestamp)
            if line.len() > 10 && line[0] == b'['
                && line[1].is_ascii_digit() && line[2].is_ascii_digit()
                && line[3] == b':'
            {
                return TraceFormat::Unidbg;
            }
            // gumtrace: starts with [module], has ! (address separator)
            if line[0] == b'[' && memchr::memchr(b'!', line).is_some() {
                return TraceFormat::Gumtrace;
            }
            // qbdi: starts with "0x" followed by hex digits, then space or ':'
            if line.len() > 4 && line[0] == b'0' && line[1] == b'x' {
                let hex_end = line[2..].iter()
                    .position(|b| !b.is_ascii_hexdigit())
                    .unwrap_or(line.len() - 2);
                if hex_end > 0 {
                    let after = line[2 + hex_end];
                    if after == b':' || after == b' ' {
                        return TraceFormat::Qbdi;
                    }
                }
            }
        }

        pos = end + 1;
        checked += 1;
    }
    TraceFormat::Unidbg // default
}

/// Returns true if line doesn't start with `[` (i.e., not an instruction line).
pub fn is_special_line(raw: &str) -> bool {
    !raw.starts_with('[')
}

/// Classification of special (non-instruction) lines in gumtrace output.
#[derive(Debug, Clone)]
pub enum SpecialLine {
    /// `call func: name(args...)` or `call jni func: name(args...)`
    CallFunc {
        name: String,
        is_jni: bool,
    },
    /// `args<N>: value`
    Arg { index: String, value: String },
    /// `ret: value`
    Ret { value: String },
    /// `hexdump at address 0x... with length 0x...:` or hex dump data lines
    HexDump,
}

/// Parse a special (non-instruction) line into a SpecialLine variant.
pub fn parse_special_line(raw: &str) -> Option<SpecialLine> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }

    // call jni func: Name(args...)
    if let Some(rest) = raw.strip_prefix("call jni func: ") {
        return parse_call_func(rest, true);
    }

    // call func: Name(args...)
    if let Some(rest) = raw.strip_prefix("call func: ") {
        return parse_call_func(rest, false);
    }

    // args<N>: value
    if let Some(rest) = raw.strip_prefix("args") {
        if let Some(colon_pos) = rest.find(": ") {
            let index = rest[..colon_pos].to_string();
            let value = rest[colon_pos + 2..].to_string();
            return Some(SpecialLine::Arg { index, value });
        }
    }

    // ret: value
    if let Some(rest) = raw.strip_prefix("ret: ") {
        return Some(SpecialLine::Ret {
            value: rest.to_string(),
        });
    }

    // hexdump lines or hex data lines
    if raw.starts_with("hexdump ") || raw.chars().next().map_or(false, |c| c.is_ascii_hexdigit()) {
        return Some(SpecialLine::HexDump);
    }

    None
}

fn parse_call_func(rest: &str, is_jni: bool) -> Option<SpecialLine> {
    let paren_pos = rest.find('(')?;
    let name = rest[..paren_pos].to_string();
    Some(SpecialLine::CallFunc { name, is_jni })
}

/// Parse a gumtrace line (lightweight mode — skips arrow register extraction).
///
/// Returns `None` for special lines, empty lines, and unparseable lines.
pub fn parse_line_gumtrace(raw: &str) -> Option<ParsedLine> {
    parse_line_gumtrace_inner(raw, false)
}

/// Parse a gumtrace line (full mode — includes arrow register extraction).
#[allow(dead_code)]
pub fn parse_line_gumtrace_full(raw: &str) -> Option<ParsedLine> {
    parse_line_gumtrace_inner(raw, true)
}

fn parse_line_gumtrace_inner(raw: &str, extract_regs: bool) -> Option<ParsedLine> {
    let bytes = raw.as_bytes();

    // Empty or special lines
    if bytes.is_empty() || bytes[0] != b'[' {
        return None;
    }

    // 1. Extract module name from [module_name]
    let close_bracket = memchr::memchr(b']', bytes)?;
    // After "] " we expect the address
    let after_module = close_bracket + 2; // skip "] "
    if after_module >= bytes.len() {
        return None;
    }

    // 2. Extract absolute address and offset: 0xABS!0xOFFSET
    // Find the '!' separator
    let rest = &bytes[after_module..];
    let excl_pos = memchr::memchr(b'!', rest)?;
    let abs_excl = after_module + excl_pos;

    // Find the space after offset
    let after_excl = abs_excl + 1;
    let space_after_offset = memchr::memchr(b' ', &bytes[after_excl..])
        .map(|p| after_excl + p)
        .unwrap_or(bytes.len());

    // 3. Extract instruction text: from after offset space to ';' (or end of line)
    let insn_start = space_after_offset + 1;
    if insn_start >= bytes.len() {
        return None;
    }

    let semicolon_pos = memchr::memchr(b';', &bytes[insn_start..]).map(|p| insn_start + p);
    // 当没有 ';' 时，通过 '=0x' 模式定位注解起始位置
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

    // 6. Find " -> " arrow (gumtrace uses -> instead of =>)
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

    // 8. Parse memory ops: mem_w=0xADDR or mem_r=0xADDR
    let mem_op = if annot_start < bytes.len() {
        find_dbi_mem_op(&bytes[annot_start..], mnemonic, operand_text, raw_first_reg_prefix, bytes, arrow_abs_pos, result_line.lane_index, result_line.lane_elem_width)
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

/// 当行内没有 ';' 分隔符时，通过 '=0x' 模式找到寄存器注解的起始位置。
/// 例如 `stp xzr, xzr, [x0]x0=0x7c78c651b0` → 返回 `x0=0x` 中 `x` 的位置。
pub fn find_annotation_start(bytes: &[u8], insn_start: usize) -> usize {
    let search = &bytes[insn_start..];
    let mut pos = 0;
    while pos + 3 < search.len() {
        if let Some(eq_pos) = memmem::find(&search[pos..], b"=0x") {
            let abs_eq = pos + eq_pos;
            if abs_eq == 0 {
                pos = abs_eq + 3;
                continue;
            }
            // 向前查找寄存器名（连续的字母数字字符）
            let mut name_start = abs_eq;
            while name_start > 0 && search[name_start - 1].is_ascii_alphanumeric() {
                name_start -= 1;
            }
            // 至少 2 字符且以字母开头才算寄存器名
            let name_len = abs_eq - name_start;
            if name_len >= 2 && search[name_start].is_ascii_alphabetic() {
                return insn_start + name_start;
            }
            pos = abs_eq + 3;
        } else {
            break;
        }
    }
    bytes.len()
}

/// 寄存器别名：x29↔fp, x30↔lr。
/// 操作数文本用架构名（x29, x30），但 DBI 注解可能用别名（fp, lr）。
pub fn reg_alias(reg_name: &str) -> Option<&'static str> {
    match reg_name {
        "x29" => Some("fp"),
        "x30" => Some("lr"),
        _ => None,
    }
}

/// 在 DBI 注解中查找寄存器值，先尝试原名再尝试别名。
pub fn find_reg_value_with_alias(bytes: &[u8], reg_name: &str, start_pos: usize) -> Option<u64> {
    find_reg_value(bytes, reg_name.as_bytes(), start_pos)
        .or_else(|| {
            reg_alias(reg_name)
                .and_then(|alias| find_reg_value(bytes, alias.as_bytes(), start_pos))
        })
}

/// Find mem_w=0xADDR or mem_r=0xADDR in DBI trace annotation.
pub fn find_dbi_mem_op(
    search: &[u8],
    mnemonic: &str,
    operand_text: &str,
    raw_first_reg_prefix: Option<u8>,
    full_bytes: &[u8],
    arrow_abs_pos: Option<usize>,
    lane_index: Option<u8>,
    lane_elem_width: Option<u8>,
) -> Option<MemOp> {
    // Look for mem_w= or mem_r=
    let (raw_is_write, addr) = if let Some(pos) = memmem::find(search, b"mem_w=0x") {
        let val_start = pos + 8; // len("mem_w=0x")
        let val_end = search[val_start..]
            .iter()
            .position(|b| !b.is_ascii_hexdigit())
            .map(|p| val_start + p)
            .unwrap_or(search.len());
        let addr = parse_hex_u64(&search[val_start..val_end])?;
        (true, addr)
    } else if let Some(pos) = memmem::find(search, b"mem_r=0x") {
        let val_start = pos + 8; // len("mem_r=0x")
        let val_end = search[val_start..]
            .iter()
            .position(|b| !b.is_ascii_hexdigit())
            .map(|p| val_start + p)
            .unwrap_or(search.len());
        let addr = parse_hex_u64(&search[val_start..val_end])?;
        (false, addr)
    } else {
        return None;
    };
    // 根据助记符覆盖 is_write：GumTrace 可能对 ldp 等 LOAD 指令错误标记 mem_w
    let is_write = if mnemonic.starts_with("ld") {
        false
    } else if mnemonic.starts_with("st") {
        true
    } else {
        raw_is_write
    };

    let mut elem_width = determine_elem_width(mnemonic, raw_first_reg_prefix);
    // 修正 elem_width：lane load 用 lane 元素宽度，SIMD 向量用排列说明符宽度
    if let (Some(_), Some(lew)) = (lane_index, lane_elem_width) {
        elem_width = lew;
    } else if matches!(mnemonic, "ld1" | "ld2" | "ld3" | "ld4" | "st1" | "st2" | "st3" | "st4") {
        if let Some(arr_width) = simd_arrangement_total_width(operand_text) {
            elem_width = arr_width;
        }
    }

    // Extract value for pass-through pruning
    let sc_abs = full_bytes.len() - search.len();
    let search_start = if is_write {
        Some(sc_abs)
    } else {
        arrow_abs_pos.map(|apos| apos + 4)
    };
    let (value, value_lo, value_hi) = if elem_width <= 8 {
        let v = first_data_reg_name(operand_text).and_then(|reg_name| {
            let ss = search_start?;
            if is_simd_reg_name(reg_name) {
                let full = find_reg_value_u128(full_bytes, reg_name.as_bytes(), ss)?;
                Some(extract_simd_lane_value(full, elem_width, lane_index))
            } else {
                let raw_val = find_reg_value_with_alias(full_bytes, reg_name, ss)?;
                let mask = if elem_width >= 8 {
                    u64::MAX
                } else {
                    (1u64 << (elem_width as u32 * 8)) - 1
                };
                Some(raw_val & mask)
            }
        });
        (v, None, None)
    } else if elem_width == 16 {
        // 128-bit SIMD: 用 u128 解析后拆为 low/high 两个 u64
        let v128 = first_data_reg_name(operand_text).and_then(|reg_name| {
            find_reg_value_u128(full_bytes, reg_name.as_bytes(), search_start?)
        });
        match v128 {
            Some(val) => (None, Some(val as u64), Some((val >> 64) as u64)),
            None => (None, None, None),
        }
    } else {
        (None, None, None)
    };

    // Pair / multi-register SIMD：提取第二个寄存器的值
    let (value2, value2_lo, value2_hi) = if parser::is_pair_mnemonic(mnemonic)
        || parser::is_simd_multi_reg(mnemonic, operand_text)
    {
        if elem_width <= 8 {
            let v2 = parser::second_data_reg_name(operand_text).and_then(|reg_name| {
                let ss = search_start?;
                if is_simd_reg_name(reg_name) {
                    let full = find_reg_value_u128(full_bytes, reg_name.as_bytes(), ss)?;
                    Some(extract_simd_lane_value(full, elem_width, None))
                } else {
                    let raw_val = find_reg_value_with_alias(full_bytes, reg_name, ss)?;
                    let mask = if elem_width >= 8 { u64::MAX } else { (1u64 << (elem_width as u32 * 8)) - 1 };
                    Some(raw_val & mask)
                }
            });
            (v2, None, None)
        } else if elem_width == 16 {
            let v128 = parser::second_data_reg_name(operand_text).and_then(|reg_name| {
                find_reg_value_u128(full_bytes, reg_name.as_bytes(), search_start?)
            });
            match v128 {
                Some(val) => (None, Some(val as u64), Some((val >> 64) as u64)),
                None => (None, None, None),
            }
        } else {
            (None, None, None)
        }
    } else {
        (None, None, None)
    };

    Some(MemOp {
        is_write,
        abs: addr,
        elem_width,
        value,
        value2,
        value_lo,
        value_hi,
        value2_lo,
        value2_hi,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;

    #[test]
    fn test_detect_format_unidbg() {
        let data = br#"[07:17:13 488][libtiny.so 0x174250] [fd7bbaa9] 0x40174250: "stp x29, x30, [sp, #-0x60]!""#;
        assert_eq!(detect_format(data), TraceFormat::Unidbg);
    }

    #[test]
    fn test_detect_format_gumtrace() {
        let data = b"[libmetasec_ov.so] 0x7522e85ce0!0x82ce0 sub x0, x29, #0x80; x0=0x75150f2e20\n";
        assert_eq!(detect_format(data), TraceFormat::Gumtrace);
    }

    #[test]
    fn test_detect_format_qbdi_no_module() {
        let data = b"0x7522e85ce0: sub x0, x29, #0x80; x0=0x0 x29=0x100 -> x0=0x80\n";
        assert_eq!(detect_format(data), TraceFormat::Qbdi);
    }

    #[test]
    fn test_detect_format_qbdi_with_module() {
        let data = b"0x7522e85ce0 libfoo.so+0x82ce0: sub x0, x29, #0x80; x0=0x0 -> x0=0x80\n";
        assert_eq!(detect_format(data), TraceFormat::Qbdi);
    }

    #[test]
    fn test_detect_format_qbdi_with_comment() {
        let data = b"# QBDI ARM64 Trace\n0x7522e85ce0: sub x0, x29, #0x80\n";
        assert_eq!(detect_format(data), TraceFormat::Qbdi);
    }

    #[test]
    fn test_call_annotation_summary() {
        let ann = CallAnnotation {
            func_name: "strlen".to_string(),
            is_jni: false,
            args: vec![("0".to_string(), "HttpRequestCallback".to_string())],
            ret_value: Some("0x13".to_string()),
            raw_lines: vec![],
        };
        assert_eq!(ann.summary(), "strlen(\"HttpRequestCallback\") → 0x13");
    }

    #[test]
    fn test_call_annotation_summary_hex_args() {
        let ann = CallAnnotation {
            func_name: "malloc".to_string(),
            is_jni: false,
            args: vec![("0".to_string(), "0x14".to_string())],
            ret_value: Some("0x7724646770".to_string()),
            raw_lines: vec![],
        };
        assert_eq!(ann.summary(), "malloc(0x14) → 0x7724646770");
    }

    #[test]
    fn test_call_annotation_summary_no_args() {
        let ann = CallAnnotation {
            func_name: "getpid".to_string(),
            is_jni: false,
            args: vec![],
            ret_value: Some("0x1234".to_string()),
            raw_lines: vec![],
        };
        assert_eq!(ann.summary(), "getpid → 0x1234");
    }

    #[test]
    fn test_parse_gumtrace_basic_insn() {
        let raw = "[libmetasec_ov.so] 0x7522e85ce0!0x82ce0 sub x0, x29, #0x80; x0=0x75150f2e20 fp=0x75150f2ec0 -> x0=0x75150f2e40";
        let line = parse_line_gumtrace(raw).unwrap();
        assert_eq!(line.mnemonic.as_str(), "sub");
        assert_eq!(line.operands.len(), 3);
        assert_eq!(line.operands[0].as_reg(), Some(RegId::X0));
        assert_eq!(line.operands[1].as_reg(), Some(RegId::X29));
        assert!(matches!(line.operands[2], Operand::Imm(0x80)));
        assert!(line.has_arrow);
    }

    #[test]
    fn test_parse_gumtrace_mem_write() {
        let raw = "[libmetasec_ov.so] 0x7522f46438!0x143438 str x21, [sp, #-0x30]!; x21=0x1 sp=0x75150f2be0 mem_w=0x75150f2bb0";
        let line = parse_line_gumtrace(raw).unwrap();
        assert_eq!(line.mnemonic.as_str(), "str");
        let mem = line.mem_op.as_ref().unwrap();
        assert!(mem.is_write);
        assert_eq!(mem.abs, 0x75150f2bb0);
        assert!(line.writeback);
    }

    #[test]
    fn test_parse_gumtrace_mem_read() {
        let raw = "[libmetasec_ov.so] 0x7522e31a94!0x2ea94 ldr x17, [x16, #0xf80]; x17=0x51 x16=0x7522fe1000 mem_r=0x7522fe1f80 -> x17=0x79b745a4c0";
        let line = parse_line_gumtrace(raw).unwrap();
        let mem = line.mem_op.as_ref().unwrap();
        assert!(!mem.is_write);
        assert_eq!(mem.abs, 0x7522fe1f80);
    }

    #[test]
    fn test_gumtrace_ldp_is_write_override() {
        // GumTrace 对 ldp (LOAD) 错误标记 mem_w，解析器应覆盖为 is_write=false
        let raw = "[libsscronet.so] 0x7a39cae364!0x2ad364 ldp x29, x30, [sp], #0x60; fp=0x798484e030 lr=0x7a39cae338 sp=0x798484e030 mem_w=0x798484e030 -> fp=0x798484e190 lr=0x7a39cae298";
        let line = parse_line_gumtrace(raw).expect("should parse");
        let mem = line.mem_op.as_ref().expect("should have mem_op");
        assert!(!mem.is_write, "ldp should be overridden to is_write=false");
        assert_eq!(mem.abs, 0x798484e030);
    }

    #[test]
    fn test_gumtrace_ldp_alias_value_extraction() {
        // 正常 ldp + mem_r，验证 x29→fp、x30→lr 别名回退
        let raw = "[libsscronet.so] 0x7a39cae364!0x2ad364 ldp x29, x30, [sp, #0x20]; fp=0x75150f2bd0 lr=0x7522f46484 sp=0x75150f2bb0 mem_r=0x75150f2bd0 -> fp=0x75150f2ec0 lr=0x7522e85ce8";
        let line = parse_line_gumtrace(raw).expect("should parse");
        let mem = line.mem_op.as_ref().expect("should have mem_op");
        assert!(!mem.is_write);
        assert_eq!(mem.elem_width, 8);
        // x29 在注解中记为 fp，应通过别名找到
        assert_eq!(mem.value, Some(0x75150f2ec0), "x29 value via fp alias");
        // x30 在注解中记为 lr，应通过别名找到
        assert_eq!(mem.value2, Some(0x7522e85ce8), "x30 value via lr alias");
    }

    #[test]
    fn test_gumtrace_ldp_mem_w_with_alias() {
        // 综合场景：ldp + 错误的 mem_w + 别名
        // is_write 被覆盖为 false → 搜索 -> 之后的值
        let raw = "[libsscronet.so] 0x7a39cae364!0x2ad364 ldp x29, x30, [sp], #0x60; fp=0x798484e030 lr=0x7a39cae338 sp=0x798484e030 mem_w=0x798484e030 -> fp=0x798484e190 lr=0x7a39cae298";
        let line = parse_line_gumtrace(raw).expect("should parse");
        let mem = line.mem_op.as_ref().expect("should have mem_op");
        assert!(!mem.is_write);
        assert_eq!(mem.value, Some(0x798484e190), "x29 loaded value via fp alias after ->");
        assert_eq!(mem.value2, Some(0x7a39cae298), "x30 loaded value via lr alias after ->");
    }

    #[test]
    fn test_parse_gumtrace_no_semicolon() {
        let raw = "[libmetasec_ov.so] 0x7522e85ce4!0x82ce4 bl #0x7522f46438";
        let line = parse_line_gumtrace(raw).unwrap();
        assert_eq!(line.mnemonic.as_str(), "bl");
        assert!(!line.has_arrow);
    }

    #[test]
    fn test_parse_gumtrace_br_instruction() {
        let raw = "[libmetasec_ov.so] 0x7522e31a9c!0x2ea9c br x17; x17=0x79b745a4c0";
        let line = parse_line_gumtrace(raw).unwrap();
        assert_eq!(line.mnemonic.as_str(), "br");
    }

    #[test]
    fn test_parse_gumtrace_cbz() {
        let raw = "[libmetasec_ov.so] 0x7522f4644c!0x14344c cbz x1, #0x7522f46488; x1=0x75150f2e20";
        let line = parse_line_gumtrace(raw).unwrap();
        assert_eq!(line.mnemonic.as_str(), "cbz");
    }

    #[test]
    fn test_parse_gumtrace_special_lines_return_none() {
        assert!(parse_line_gumtrace("call func: __strlen_aarch64(0x75150f2e20)").is_none());
        assert!(parse_line_gumtrace("args0: HttpRequestCallback").is_none());
        assert!(parse_line_gumtrace("ret: 0x13").is_none());
        assert!(
            parse_line_gumtrace("hexdump at address 0x75150f2e20 with length 0x14:").is_none()
        );
        assert!(parse_line_gumtrace(
            "75150f2e20: 48 74 74 70 52 65 71 75 65 73 74 43 61 6c 6c 62 |HttpRequestCallb|"
        )
        .is_none());
        assert!(parse_line_gumtrace("").is_none());
    }

    #[test]
    fn test_parse_gumtrace_ret_insn() {
        let raw = "[libmetasec_ov.so] 0x7522f464bc!0x1434bc ret";
        let line = parse_line_gumtrace(raw).unwrap();
        assert_eq!(line.mnemonic.as_str(), "ret");
    }

    #[test]
    fn test_parse_special_line_call_func() {
        let sl = parse_special_line("call func: __strlen_aarch64(0x75150f2e20)").unwrap();
        match sl {
            SpecialLine::CallFunc { name, is_jni, .. } => {
                assert_eq!(name, "__strlen_aarch64");
                assert!(!is_jni);
            }
            _ => panic!("expected CallFunc"),
        }
    }

    #[test]
    fn test_parse_special_line_jni() {
        let sl =
            parse_special_line("call jni func: GetMethodID(0x78f4342950, 0x799ac3f209)").unwrap();
        match sl {
            SpecialLine::CallFunc { name, is_jni, .. } => {
                assert_eq!(name, "GetMethodID");
                assert!(is_jni);
            }
            _ => panic!("expected JNI CallFunc"),
        }
    }

    #[test]
    fn test_parse_special_line_arg() {
        let sl = parse_special_line("args0: HttpRequestCallback").unwrap();
        match sl {
            SpecialLine::Arg { index, value } => {
                assert_eq!(index, "0");
                assert_eq!(value, "HttpRequestCallback");
            }
            _ => panic!("expected Arg"),
        }
    }

    #[test]
    fn test_parse_special_line_ret() {
        let sl = parse_special_line("ret: 0x13").unwrap();
        match sl {
            SpecialLine::Ret { value } => assert_eq!(value, "0x13"),
            _ => panic!("expected Ret"),
        }
    }

    #[test]
    fn test_parse_gumtrace_no_semicolon_mem_write() {
        // 有些 gumtrace 行没有 ';' 分隔符
        let raw = "[libc++_shared.so] 0x7b00797c7c!0x96c7c stp xzr, xzr, [x0]x0=0x7c78c651b0 mem_w=0x7c78c651b0";
        let line = parse_line_gumtrace(raw).unwrap();
        assert_eq!(line.mnemonic.as_str(), "stp");
        assert_eq!(line.operands.len(), 3); // xzr, xzr, x0(base)
        let mem = line.mem_op.as_ref().unwrap();
        assert!(mem.is_write);
        assert_eq!(mem.abs, 0x7c78c651b0);
    }

    #[test]
    fn test_parse_gumtrace_no_semicolon_with_arrow() {
        let raw = "[libsscronet.so] 0x7a39fa11e4!0x5a01e4 mov x0, x1 x0=0xdead x1=0xbeef -> x0=0xbeef";
        let line = parse_line_gumtrace(raw).unwrap();
        assert_eq!(line.mnemonic.as_str(), "mov");
        assert!(line.has_arrow);
    }
}
