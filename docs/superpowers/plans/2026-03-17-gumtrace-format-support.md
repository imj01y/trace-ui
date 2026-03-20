# Gumtrace 日志格式适配 Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 让 trace-ui 支持 Frida GumStalker 输出的 gumtrace 日志格式，包括指令行解析、外部函数调用注释内联展示、hover tooltip 查看完整调用详情。

**Architecture:** 在现有 unidbg 解析流水线旁新增 gumtrace 解析路径，通过格式自动检测路由。特殊行（call func/args/ret/hexdump）在扫描阶段被"消化"为 `CallAnnotation`，关联到发起调用的 `bl`/`blr` 指令行。前端从 `TraceLine.call_info` 读取摘要，在 disasm 文本尾部内联渲染，hover 时显示完整 tooltip。

**Tech Stack:** Rust (Tauri 2), React 19 + TypeScript, Canvas 2D rendering

---

## 文件结构

| 操作 | 文件路径 | 职责 |
|------|---------|------|
| Create | `src/taint/gumtrace_parser.rs` | gumtrace 格式行解析器 |
| Modify | `src/taint/types.rs` | 新增 `TraceFormat` 枚举、`fp`/`lr` 别名支持 |
| Modify | `src/taint/mod.rs` | `scan_unified` 适配：格式检测、gumtrace 解析、CallAnnotation 收集 |
| Modify | `src/state.rs` | `SessionState` 新增 `trace_format` 和 `call_annotations` / `consumed_seqs` |
| Modify | `src/commands/browse.rs` | `parse_trace_line` 适配 gumtrace 格式、`TraceLine` 新增 `call_info` |
| Modify | `src/commands/index.rs` | 格式检查逻辑适配、返回 consumed_seqs |
| Modify | `src/commands/call_tree.rs` | `CallTreeNodeDto` 新增 `func_name` |
| Modify | `src/taint/call_tree.rs` | `CallTreeNode` 新增 `func_name` |
| Modify | `src/phase2.rs` | `extract_insn_addr` 适配 gumtrace 地址格式 |
| Modify | `src/main.rs` | 注册新命令 `get_consumed_seqs` |
| Modify | `src-web/src/types/trace.ts` | `TraceLine` 新增 `call_info`、`CallTreeNodeDto` 新增 `func_name` |
| Modify | `src-web/src/components/TraceTable.tsx` | 内联渲染 call_info + hover tooltip |
| Modify | `src-web/src/components/FunctionTree.tsx` | 显示 func_name |
| Modify | `src-web/src/utils/canvasColors.ts` | 新增 callInfo / jniCallInfo 颜色 |
| Modify | `src-web/src/hooks/useTraceStore.ts` | 加载 consumed_seqs 并自动隐藏 |

---

## Task 1: 格式枚举 + `fp`/`lr` 寄存器别名

**Files:**
- Modify: `src/taint/types.rs`

- [ ] **Step 1: 在 `types.rs` 新增 `TraceFormat` 枚举**

```rust
/// Trace 日志格式
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TraceFormat {
    Unidbg,
    Gumtrace,
}
```

在文件顶部（`RegId` 定义之前）添加。

- [ ] **Step 2: 在 `parse_reg` 中增加 `fp` 和 `lr` 别名**

在 `parse_reg` 函数的 `len == 2` 分支中添加：

```rust
2 => {
    if bytes == b"sp" {
        return Some(RegId::SP);
    }
    if bytes == b"fp" {
        return Some(RegId::X29);
    }
    if bytes == b"lr" {
        return Some(RegId::X30);
    }
}
```

- [ ] **Step 3: 添加测试**

```rust
#[test]
fn test_parse_reg_fp_lr_alias() {
    assert_eq!(parse_reg("fp"), Some(RegId::X29));
    assert_eq!(parse_reg("lr"), Some(RegId::X30));
}
```

- [ ] **Step 4: 运行测试验证**

Run: `cd /Users/richman/Documents/reverse/codes/trace-ui && cargo test --lib taint::types::tests`
Expected: ALL PASS

- [ ] **Step 5: Commit**

```bash
git add src/taint/types.rs
git commit -m "feat: add TraceFormat enum and fp/lr register aliases"
```

---

## Task 2: Gumtrace 行解析器

**Files:**
- Create: `src/taint/gumtrace_parser.rs`
- Modify: `src/taint/mod.rs` (添加 `pub mod gumtrace_parser;`)

- [ ] **Step 1: 创建 `gumtrace_parser.rs` 骨架并编写测试**

测试用例基于实际 gumtrace 行格式：

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::taint::types::*;

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
    fn test_parse_gumtrace_no_semicolon() {
        // bl 指令没有寄存器值（无分号）
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
        assert!(parse_line_gumtrace("hexdump at address 0x75150f2e20 with length 0x14:").is_none());
        assert!(parse_line_gumtrace("75150f2e20: 48 74 74 70 52 65 71 75 65 73 74 43 61 6c 6c 62 |HttpRequestCallb|").is_none());
        assert!(parse_line_gumtrace("").is_none());
    }

    #[test]
    fn test_parse_gumtrace_ret_insn() {
        let raw = "[libmetasec_ov.so] 0x7522f464bc!0x1434bc ret";
        let line = parse_line_gumtrace(raw).unwrap();
        assert_eq!(line.mnemonic.as_str(), "ret");
    }
}
```

- [ ] **Step 2: 运行测试，确认全部 FAIL**

Run: `cd /Users/richman/Documents/reverse/codes/trace-ui && cargo test --lib taint::gumtrace_parser::tests 2>&1 | tail -5`
Expected: compilation error (parse_line_gumtrace not yet implemented)

- [ ] **Step 3: 实现 `parse_line_gumtrace` 函数**

核心解析逻辑：

```rust
use memchr::memchr;
use memchr::memmem;
use smallvec::SmallVec;

use super::types::*;
use super::parser::{parse_operands_into, determine_elem_width, extract_reg_values, parse_hex_u64, find_reg_value, first_data_reg_name};

/// 检测行是否为 gumtrace 特殊行（call func / args / ret / hexdump）
pub fn is_special_line(raw: &str) -> bool {
    let bytes = raw.as_bytes();
    if bytes.is_empty() { return false; }
    // 特殊行不以 '[' 开头
    bytes[0] != b'['
}

/// 从特殊行中提取类型和内容
pub enum SpecialLine<'a> {
    CallFunc { name: &'a str, args_raw: &'a str, is_jni: bool },
    Arg { index: &'a str, value: &'a str },
    Ret { value: &'a str },
    HexdumpHeader { addr: &'a str, length: &'a str },
    HexdumpData { line: &'a str },
}

pub fn parse_special_line(raw: &str) -> Option<SpecialLine<'_>> {
    if raw.starts_with("call func: ") {
        let rest = &raw[11..];
        let paren = rest.find('(')?;
        let name = &rest[..paren];
        let args_raw = &rest[paren..];
        Some(SpecialLine::CallFunc { name, args_raw, is_jni: false })
    } else if raw.starts_with("call jni func: ") {
        let rest = &raw[15..];
        let paren = rest.find('(')?;
        let name = &rest[..paren];
        let args_raw = &rest[paren..];
        Some(SpecialLine::CallFunc { name, args_raw, is_jni: true })
    } else if raw.starts_with("args") && raw.len() > 5 {
        let colon = raw.find(": ")?;
        let index = &raw[4..colon];
        let value = &raw[colon + 2..];
        Some(SpecialLine::Arg { index, value })
    } else if raw.starts_with("ret: ") {
        Some(SpecialLine::Ret { value: &raw[5..] })
    } else if raw.starts_with("hexdump at address ") {
        let addr_start = 19; // "hexdump at address " 的长度
        let rest = &raw[addr_start..];
        let space = rest.find(' ')?;
        let addr = &rest[..space];
        let len_marker = rest.find("length ")?;
        let len_start = len_marker + 7;
        let colon = rest[len_start..].find(':')?;
        let length = &rest[len_start..len_start + colon];
        Some(SpecialLine::HexdumpHeader { addr, length })
    } else if raw.len() > 10 && raw.as_bytes().iter().take(16).all(|b| b.is_ascii_hexdigit() || *b == b' ') {
        // hexdump 数据行: "75150f2e20: 48 74 ..."
        if raw.contains(": ") && raw.contains('|') {
            Some(SpecialLine::HexdumpData { line: raw })
        } else {
            None
        }
    } else {
        None
    }
}

/// 解析 gumtrace 指令行，返回 ParsedLine。
/// 特殊行（call func / args / ret / hexdump）返回 None。
pub fn parse_line_gumtrace(raw: &str) -> Option<ParsedLine> {
    parse_line_gumtrace_inner(raw, false)
}

pub fn parse_line_gumtrace_full(raw: &str) -> Option<ParsedLine> {
    parse_line_gumtrace_inner(raw, true)
}

fn parse_line_gumtrace_inner(raw: &str, extract_regs: bool) -> Option<ParsedLine> {
    let bytes = raw.as_bytes();

    // 1. 必须以 '[' 开头
    if bytes.first()? != &b'[' {
        return None;
    }

    // 2. 找到 '] ' —— module 名结束
    let bracket_end = memmem::find(bytes, b"] ")?;
    let after_bracket = bracket_end + 2;

    // 3. 找到 '!' 分隔符 —— 地址格式 0xABS!0xOFFSET
    let rest = &bytes[after_bracket..];
    let bang = memchr(b'!', rest)?;
    let abs_bang = after_bracket + bang;

    // 4. 找到偏移量后面的空格 —— 指令文本开始
    let after_bang = abs_bang + 1;
    let insn_space = memchr(b' ', &bytes[after_bang..])? + after_bang;

    // 5. 指令文本：从 insn_space+1 到 ';'（或行尾）
    let insn_start = insn_space + 1;
    let semicolon_pos = memchr(b';', &bytes[insn_start..])
        .map(|p| insn_start + p);
    let insn_end = semicolon_pos.unwrap_or(bytes.len());

    let insn_text = std::str::from_utf8(&bytes[insn_start..insn_end]).ok()?.trim();

    // 6. 分割助记符和操作数
    let (mnemonic, operand_text) = match insn_text.find(' ') {
        Some(pos) => (&insn_text[..pos], insn_text[pos + 1..].trim()),
        None => (insn_text, ""),
    };

    if mnemonic.is_empty() {
        return None;
    }

    // 7. 解析操作数（复用现有逻辑）
    let mut result_line = ParsedLine::default();
    let raw_first_reg_prefix = super::parser::parse_operands_into(operand_text, &mut result_line);

    // 8. 找箭头 " -> "（gumtrace 用 -> 而非 =>）
    let tail_start = semicolon_pos.unwrap_or(bytes.len());
    let arrow_rel = memmem::find(&bytes[tail_start..], b" -> ");
    let has_arrow = arrow_rel.is_some();

    // 寄存器值提取
    let (pre_arrow_regs, post_arrow_regs);
    if extract_regs && semicolon_pos.is_some() {
        let semi = semicolon_pos.unwrap();
        if let Some(rel) = arrow_rel {
            let arrow_abs = tail_start + rel;
            let pre_text = std::str::from_utf8(&bytes[semi + 1..arrow_abs]).ok()?;
            let post_text = std::str::from_utf8(&bytes[arrow_abs + 4..]).ok()?;
            pre_arrow_regs = Some(Box::new(super::parser::extract_reg_values(pre_text)));
            post_arrow_regs = Some(Box::new(super::parser::extract_reg_values(post_text)));
        } else {
            let text = std::str::from_utf8(&bytes[semi + 1..]).ok()?;
            pre_arrow_regs = Some(Box::new(super::parser::extract_reg_values(text)));
            post_arrow_regs = Some(Box::new(SmallVec::new()));
        }
    } else {
        pre_arrow_regs = None;
        post_arrow_regs = None;
    }

    // 9. 内存操作：mem_w=0x... 或 mem_r=0x...
    let mem_op = if let Some(semi) = semicolon_pos {
        let tail = &bytes[semi..];
        let (is_write, marker) = if let Some(p) = memmem::find(tail, b"mem_w=0x") {
            (true, semi + p)
        } else if let Some(p) = memmem::find(tail, b"mem_r=0x") {
            (false, semi + p)
        } else {
            (false, 0)
        };
        if marker > 0 {
            let val_start = marker + 8; // "mem_w=0x" 长度
            let val_end = bytes[val_start..]
                .iter()
                .position(|b| !b.is_ascii_hexdigit())
                .map(|p| val_start + p)
                .unwrap_or(bytes.len());
            let abs = super::parser::parse_hex_u64(&bytes[val_start..val_end])?;
            let elem_width = determine_elem_width(mnemonic, raw_first_reg_prefix);
            // 提取值（与 unidbg parser 相同逻辑）
            let value = if elem_width <= 8 {
                super::parser::first_data_reg_name(operand_text).and_then(|reg_name| {
                    let search_start = if is_write {
                        semicolon_pos.unwrap_or(0)
                    } else {
                        match arrow_rel {
                            Some(rel) => tail_start + rel + 4,
                            None => return None,
                        }
                    };
                    let raw_val = super::parser::find_reg_value(bytes, reg_name.as_bytes(), search_start)?;
                    let mask = if elem_width >= 8 { u64::MAX } else { (1u64 << (elem_width as u32 * 8)) - 1 };
                    Some(raw_val & mask)
                })
            } else {
                None
            };
            Some(MemOp { is_write, abs, elem_width, value })
        } else {
            None
        }
    } else {
        None
    };

    // 10. 回写检测
    let op_bytes = operand_text.as_bytes();
    let writeback = memchr(b'!', op_bytes).is_some() || memmem::find(op_bytes, b"], #").is_some();

    // Arrow position: 转换为绝对位置（兼容 phase2 的 update_reg_values_at）
    // gumtrace 用 " -> "，需要在 scan_unified 中特殊处理
    let arrow_pos = arrow_rel.map(|rel| tail_start + rel);

    result_line.mnemonic = Mnemonic::new(mnemonic);
    result_line.mem_op = mem_op;
    result_line.has_arrow = has_arrow;
    result_line.arrow_pos = arrow_pos;
    result_line.writeback = writeback;
    result_line.pre_arrow_regs = pre_arrow_regs;
    result_line.post_arrow_regs = post_arrow_regs;

    Some(result_line)
}
```

- [ ] **Step 3b: 修改 `parser.rs` 中的函数可见性**

将以下函数从 `fn` 改为 `pub(crate) fn`（在 `src/taint/parser.rs` 中）：
- `parse_operands_into`（约第 215 行）
- `determine_elem_width`（约第 420 行）
- `extract_reg_values`（约第 163 行）
- `parse_hex_u64`（约第 20 行）
- `find_reg_value`（约第 376 行）
- `first_data_reg_name`（约第 351 行）

每个函数只需在 `fn` 前加 `pub(crate)`。

- [ ] **Step 4: 在 `src/taint/mod.rs` 顶部添加模块声明**

```rust
pub mod gumtrace_parser;
```

- [ ] **Step 5: 运行测试验证**

Run: `cd /Users/richman/Documents/reverse/codes/trace-ui && cargo test --lib taint::gumtrace_parser::tests`
Expected: ALL PASS

- [ ] **Step 6: Commit**

```bash
git add src/taint/gumtrace_parser.rs src/taint/mod.rs src/taint/parser.rs
git commit -m "feat: add gumtrace format parser with special line detection"
```

---

## Task 3: CallAnnotation 数据结构 + 格式检测

**Files:**
- Modify: `src/state.rs`
- Modify: `src/taint/gumtrace_parser.rs`

- [ ] **Step 1: 在 `gumtrace_parser.rs` 中新增 `CallAnnotation` 结构体**

```rust
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
                // 十六进制值不加引号，字符串值加引号
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
}
```

- [ ] **Step 2: 新增格式检测函数**

在 `gumtrace_parser.rs` 中添加：

```rust
use super::types::TraceFormat;

/// 从文件的前几行自动检测 trace 格式
pub fn detect_format(data: &[u8]) -> TraceFormat {
    // 检查前 20 行
    let mut pos = 0;
    let mut checked = 0;
    while pos < data.len() && checked < 20 {
        let end = memchr(b'\n', &data[pos..])
            .map(|i| pos + i)
            .unwrap_or(data.len());
        let line = &data[pos..end];

        if !line.is_empty() {
            // unidbg: 以 [HH:MM:SS 开头（时间戳）
            if line.len() > 10 && line[0] == b'['
                && line[1].is_ascii_digit() && line[2].is_ascii_digit()
                && line[3] == b':'
            {
                return TraceFormat::Unidbg;
            }
            // gumtrace: 以 [module] 开头，后面有 !（地址分隔符）
            if line[0] == b'[' && memchr(b'!', line).is_some() {
                return TraceFormat::Gumtrace;
            }
        }

        pos = end + 1;
        checked += 1;
    }
    TraceFormat::Unidbg // 默认
}
```

- [ ] **Step 3: 在 `state.rs` 中扩展 `SessionState`**

```rust
use crate::taint::types::TraceFormat;
use crate::taint::gumtrace_parser::CallAnnotation;
use std::collections::HashMap as StdHashMap;

// SessionState 新增字段：
pub trace_format: TraceFormat,
pub call_annotations: StdHashMap<u32, CallAnnotation>,  // bl_seq -> annotation
pub consumed_seqs: Vec<u32>,  // 被消化的特殊行 seq（有序）
```

在 `SessionState` 初始化处（`commands/file.rs` 的 `create_session`）给新字段设默认值：
```rust
trace_format: TraceFormat::Unidbg,
call_annotations: StdHashMap::new(),
consumed_seqs: Vec::new(),
```

- [ ] **Step 4: 添加格式检测测试**

```rust
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
```

- [ ] **Step 5: 运行测试验证**

Run: `cd /Users/richman/Documents/reverse/codes/trace-ui && cargo test --lib taint::gumtrace_parser::tests`
Expected: ALL PASS

- [ ] **Step 6: Commit**

```bash
git add src/taint/gumtrace_parser.rs src/state.rs
git commit -m "feat: add CallAnnotation struct and format auto-detection"
```

---

## Task 4: `scan_unified` 适配 gumtrace

**Files:**
- Modify: `src/taint/mod.rs`

这是核心改动——让统一扫描支持 gumtrace 格式，包括格式检测、gumtrace 解析路由、特殊行消化为 CallAnnotation、收集 consumed_seqs。

- [ ] **Step 1: 修改 `scan_unified` 签名，返回新增数据**

将返回类型从 `(ScanState, Phase2State, LineIndex)` 改为包含格式和注释信息的新结构：

```rust
pub struct ScanResult {
    pub scan_state: ScanState,
    pub phase2: Phase2State,
    pub line_index: crate::line_index::LineIndex,
    pub format: types::TraceFormat,
    pub call_annotations: std::collections::HashMap<u32, gumtrace_parser::CallAnnotation>,
    pub consumed_seqs: Vec<u32>,
}
```

- [ ] **Step 2: 在 `scan_unified` 开头添加格式检测**

```rust
let format = gumtrace_parser::detect_format(data);
```

- [ ] **Step 3: 添加 gumtrace 特殊行处理状态变量**

```rust
// Gumtrace 特有的调用注释收集
let mut call_annotations: std::collections::HashMap<u32, gumtrace_parser::CallAnnotation> = std::collections::HashMap::new();
let mut consumed_seqs: Vec<u32> = Vec::new();
let mut pending_call_seq: Option<u32> = None;  // 最近的 bl/blr 指令 seq
let mut current_annotation: Option<(u32, gumtrace_parser::CallAnnotation)> = None;
```

- [ ] **Step 4: 在主循环中，根据格式选择解析器**

**关键注意事项**: 特殊行检测必须在 `deps.start_row()` 和 `init_mem_loads.push()` 之前，否则会导致 seq/deps 索引不对齐。同时特殊行仍需要递增 `state.line_count` 以保持与 LineIndex 一致。

在 `let i = state.line_count;` 之前（即 `li_builder.add_line(pos as u64);` 之后），插入 gumtrace 特殊行的早期拦截：

```rust
li_builder.add_line(pos as u64);
pos = if line_end < len { line_end + 1 } else { len };

// ── Gumtrace 特殊行早期拦截（在 deps.start_row 之前） ──
if format == types::TraceFormat::Gumtrace && gumtrace_parser::is_special_line(raw_line) {
    let i = state.line_count;
    // 特殊行仍占 deps 中的一个空行（保持索引对齐）
    state.deps.start_row();
    state.init_mem_loads.push(false);

    if let Some(special) = gumtrace_parser::parse_special_line(raw_line) {
        consumed_seqs.push(i);
        match special {
            gumtrace_parser::SpecialLine::CallFunc { name, args_raw: _, is_jni } => {
                // 先 flush 上一个未完成的 annotation（如果有）
                if let Some((bl_seq, ann)) = current_annotation.take() {
                    ct_builder.set_func_name_by_entry_seq(bl_seq, &ann.func_name);
                    call_annotations.insert(bl_seq, ann);
                }
                if let Some(bl_seq) = pending_call_seq.take() {
                    current_annotation = Some((bl_seq, gumtrace_parser::CallAnnotation {
                        func_name: name.to_string(),
                        is_jni,
                        args: Vec::new(),
                        ret_value: None,
                        raw_lines: vec![raw_line.to_string()],
                    }));
                }
            }
            gumtrace_parser::SpecialLine::Arg { index, value } => {
                if let Some((_, ref mut ann)) = current_annotation {
                    ann.args.push((index.to_string(), value.to_string()));
                    ann.raw_lines.push(raw_line.to_string());
                }
            }
            gumtrace_parser::SpecialLine::Ret { value } => {
                if let Some((bl_seq, mut ann)) = current_annotation.take() {
                    ann.ret_value = Some(value.to_string());
                    ann.raw_lines.push(raw_line.to_string());
                    ct_builder.set_func_name_by_entry_seq(bl_seq, &ann.func_name);
                    call_annotations.insert(bl_seq, ann);
                }
            }
            gumtrace_parser::SpecialLine::HexdumpHeader { .. }
            | gumtrace_parser::SpecialLine::HexdumpData { .. } => {
                if let Some((_, ref mut ann)) = current_annotation {
                    ann.raw_lines.push(raw_line.to_string());
                }
                consumed_seqs.push(i);
            }
        }
    }
    // 不认识的非指令行（无法解析为 special）：不加入 consumed_seqs，保留为可见的 unparseable 行

    state.line_count += 1;
    if state.line_count % CHECKPOINT_INTERVAL == 0 {
        reg_ckpts.save_checkpoint(&reg_values);
    }
    if let Some(ref cb) = progress_fn {
        if pos - last_report >= progress_interval {
            cb(pos, len);
            last_report = pos;
        }
    }
    continue;
}

let i = state.line_count;
state.deps.start_row();
state.init_mem_loads.push(false);
```

然后把原来的 `let Some(line) = parser::parse_line(raw_line)` 改为格式路由：

```rust
let parsed = match format {
    types::TraceFormat::Unidbg => parser::parse_line(raw_line),
    types::TraceFormat::Gumtrace => gumtrace_parser::parse_line_gumtrace(raw_line),
};

let Some(line) = parsed else {
    // ... 现有的跳过逻辑（line_count++, checkpoint, progress） ...
    continue;
};
```

- [ ] **Step 5: 在 BranchLink/BranchLinkReg 处理中记录 pending_call_seq**

在现有的 Phase2 CallTree 逻辑处（`InsnClass::BranchLink` 和 `InsnClass::BranchLinkReg` 分支），当格式为 Gumtrace 时额外设置 `pending_call_seq`：

```rust
InsnClass::BranchLink => {
    // ... 现有 bl 处理 ...
    if format == types::TraceFormat::Gumtrace {
        pending_call_seq = Some(i);
    }
}
InsnClass::BranchLinkReg => {
    // ... 现有 blr 处理 ...
    if format == types::TraceFormat::Gumtrace {
        pending_call_seq = Some(i);
    }
}
```

- [ ] **Step 6: 适配 `extract_insn_addr` 和 `update_reg_values_at` 以支持 gumtrace 格式**

在 `phase2.rs` 中修改 `extract_insn_addr`，使其也能处理 gumtrace 的 `0xADDR!0xOFFSET` 格式：

```rust
pub fn extract_insn_addr(line: &str) -> u64 {
    // unidbg 格式: ... ] 0xADDR: "mnemonic ..."
    if let Some(pos) = line.find("] 0x") {
        let rest = &line[pos + 4..];
        // gumtrace: 0xADDR!0xOFFSET（! 分隔）
        if let Some(bang) = rest.find('!') {
            if let Ok(addr) = u64::from_str_radix(&rest[..bang], 16) {
                return addr;
            }
        }
        // unidbg: 0xADDR:
        if let Some(colon) = rest.find(':') {
            if let Ok(addr) = u64::from_str_radix(&rest[..colon], 16) {
                return addr;
            }
        }
    }
    0
}
```

修改 `update_reg_values_at`，使其也能处理 gumtrace 的 ` -> ` 箭头：

目前 `arrow_pos` 已经由各自的解析器正确计算，`update_reg_values_at` 只需从 `arrow_pos + 4` 开始提取。但 gumtrace 的箭头是 `" -> "` 也是 4 字节，所以 **不需要修改** `update_reg_values_at`——长度一致。

- [ ] **Step 7: 适配 `extract_blr_target` 以支持 gumtrace**

gumtrace 的 blr 行格式为 `blr x8; x8=0x76ff7983e0`，`extract_blr_target` 中查找 `" => "` 需要改为也查找 `" -> "`。不过该函数只是从行文本中找 `regname=0x` 模式，实际搜索区域用了 `find(" => ")`。需要修改为同时支持 `" -> "`：

```rust
let search_area = if let Some(arrow_pos) = line_str.find(" => ").or_else(|| line_str.find(" -> ")) {
    &line_str[..arrow_pos]
} else {
    line_str
};
```

- [ ] **Step 8: 在 scan_unified 结束前 flush 未完成的 annotation**

在主循环结束后（`// ── 结束 ──` 注释处），添加：

```rust
// Flush 未完成的 CallAnnotation（log 截断或函数不返回时）
if let Some((bl_seq, ann)) = current_annotation.take() {
    ct_builder.set_func_name_by_entry_seq(bl_seq, &ann.func_name);
    call_annotations.insert(bl_seq, ann);
}
```

- [ ] **Step 9: 在结果中返回 ScanResult**

更新 `scan_unified` 返回值。同时更新 `commands/index.rs` 中的调用处以匹配新的返回类型。

- [ ] **Step 9: 运行编译验证**

Run: `cd /Users/richman/Documents/reverse/codes/trace-ui && cargo build 2>&1 | tail -20`
Expected: BUILD SUCCESS

- [ ] **Step 10: Commit**

```bash
git add src/taint/mod.rs src/phase2.rs src/commands/index.rs
git commit -m "feat: integrate gumtrace parsing into scan_unified with call annotation collection"
```

---

## Task 5: `CallTreeNode` 新增 `func_name`

**Files:**
- Modify: `src/taint/call_tree.rs`
- Modify: `src/commands/call_tree.rs`
- Modify: `src-web/src/types/trace.ts`
- Modify: `src-web/src/components/FunctionTree.tsx`

- [ ] **Step 1: `CallTreeNode` 新增 `func_name` 字段**

```rust
pub struct CallTreeNode {
    pub id: u32,
    pub func_addr: u64,
    #[serde(default)]  // 向后兼容旧缓存的反序列化
    pub func_name: Option<String>,  // NEW: from gumtrace call func lines
    pub entry_seq: u32,
    pub exit_seq: u32,
    pub parent_id: Option<u32>,
    pub children_ids: Vec<u32>,
}
```

在 `CallTreeBuilder::on_call` 中初始化 `func_name: None`。

- [ ] **Step 2: 新增 `set_func_name_by_entry_seq` 方法**

```rust
/// 根据 entry_seq 查找节点并设置 func_name
pub fn set_func_name_by_entry_seq(&mut self, entry_seq: u32, name: &str) {
    // entry_seq 就是 bl/blr 指令的 seq，节点的 entry_seq 也是同一个值
    for node in self.nodes.iter_mut().rev() {
        if node.entry_seq == entry_seq {
            node.func_name = Some(name.to_string());
            return;
        }
    }
}
```

- [ ] **Step 3: `CallTreeNodeDto` 新增 `func_name`**

在 `commands/call_tree.rs` 中：

```rust
pub struct CallTreeNodeDto {
    // ... 现有字段 ...
    pub func_name: Option<String>,  // NEW
}

fn node_to_dto(n: &CallTreeNode) -> CallTreeNodeDto {
    CallTreeNodeDto {
        // ... 现有字段 ...
        func_name: n.func_name.clone(),
    }
}
```

- [ ] **Step 4: 前端 `CallTreeNodeDto` 类型更新**

在 `src-web/src/types/trace.ts` 中 `CallTreeNodeDto` 新增：

```typescript
func_name: string | null;
```

- [ ] **Step 5: `FunctionTree.tsx` 优先显示 `func_name`**

在 `FunctionTree.tsx` 中，行显示逻辑处（约第 187-200 行），`customName` 的回退逻辑中加入 `func_name`：

找到以下代码段并修改，让 funcRename 之外还能使用 func_name：

将 `const customName = funcRename.getName(row.func_addr);` 改为：

```typescript
const customName = funcRename.getName(row.func_addr);
const displayName = customName || row.func_name;
```

然后把后续用到 `customName` 的地方替换为 `displayName`（当 `displayName` 为 null 时仍显示地址）。同时 `FlatRow` 接口新增 `func_name: string | null` 字段。

- [ ] **Step 6: 运行编译验证**

Run: `cd /Users/richman/Documents/reverse/codes/trace-ui && cargo build 2>&1 | tail -5`
Expected: BUILD SUCCESS

- [ ] **Step 7: Commit**

```bash
git add src/taint/call_tree.rs src/commands/call_tree.rs src-web/src/types/trace.ts src-web/src/components/FunctionTree.tsx
git commit -m "feat: add func_name to CallTreeNode from gumtrace call annotations"
```

---

## Task 6: `browse.rs` 适配 + `TraceLine` 新增 `call_info`

**Files:**
- Modify: `src/commands/browse.rs`
- Modify: `src-web/src/types/trace.ts`

- [ ] **Step 1: `TraceLine` 新增 `call_info` 字段**

```rust
#[derive(Serialize)]
pub struct CallInfoDto {
    pub func_name: String,
    pub is_jni: bool,
    pub summary: String,
    pub tooltip: String,
}

#[derive(Serialize)]
pub struct TraceLine {
    // ... 所有现有字段 ...
    pub call_info: Option<CallInfoDto>,
}
```

- [ ] **Step 2: 新增 `parse_trace_line_gumtrace` 函数**

处理 gumtrace 格式的行解析（用于 `get_lines` 命令）：

```rust
pub fn parse_trace_line_gumtrace(seq: u32, raw: &[u8]) -> Option<TraceLine> {
    let line = std::str::from_utf8(raw).ok()?;

    // 特殊行返回 None（它们已被消化）
    if !line.starts_with('[') {
        return None;
    }

    // [module] 0xABS!0xOFFSET instruction...
    let bracket_end = line.find("] ")?;
    let rest = &line[bracket_end + 2..];

    // 地址: 0xABS!0xOFFSET
    let bang = rest.find('!')?;
    let address = &rest[..bang];

    let offset_start = bang + 1;
    let offset_end = rest[offset_start..].find(' ').map(|p| offset_start + p).unwrap_or(rest.len());
    let so_offset = &rest[offset_start..offset_end];

    // 指令文本
    let insn_start = offset_end + 1;
    let semicolon_pos = rest[insn_start..].find(';').map(|p| insn_start + p);
    let insn_end = semicolon_pos.unwrap_or(rest.len());
    let disasm = rest[insn_start..insn_end].trim().to_string();

    // 内存操作
    let mem_rw = if line.contains("mem_w=0x") {
        Some("W".to_string())
    } else if line.contains("mem_r=0x") {
        Some("R".to_string())
    } else {
        None
    };

    let mem_addr = extract_gumtrace_mem_addr(line);
    let mem_size = extract_mem_size(&disasm);

    // changes: " -> " 后面的寄存器变化
    let changes = if let Some(pos) = line.find(" -> ") {
        line[pos + 4..].trim().to_string()
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
        call_info: None, // 在 get_lines 中从 session state 填充
    })
}

fn extract_gumtrace_mem_addr(line: &str) -> Option<String> {
    let markers = ["mem_w=", "mem_r="];
    for marker in &markers {
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
```

- [ ] **Step 3: 修改 `get_lines` 命令以支持格式路由和 `call_info` 填充**

```rust
#[tauri::command]
pub fn get_lines(session_id: String, seqs: Vec<u32>, state: State<'_, AppState>) -> Result<Vec<TraceLine>, String> {
    let sessions = state.sessions.read().map_err(|e| e.to_string())?;
    let session = sessions.get(&session_id).ok_or_else(|| format!("Session {} 不存在", session_id))?;
    let line_index = session.line_index.as_ref().ok_or_else(|| "索引尚未构建完成".to_string())?;
    let format = session.trace_format;

    let mut results = Vec::with_capacity(seqs.len());
    for &seq in &seqs {
        if let Some(raw) = line_index.get_line(&session.mmap, seq) {
            let parsed = match format {
                crate::taint::types::TraceFormat::Unidbg => parse_trace_line(seq, raw),
                crate::taint::types::TraceFormat::Gumtrace => parse_trace_line_gumtrace(seq, raw),
            };
            if let Some(mut line) = parsed {
                // 填充 call_info
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
            seq, address: String::new(), so_offset: String::new(),
            disasm: format!("(line {} unparseable)", seq + 1),
            changes: String::new(), mem_rw: None, mem_addr: None, mem_size: None,
            raw: format!("(line {} unparseable)", seq + 1),
            call_info: None,
        });
    }
    Ok(results)
}
```

- [ ] **Step 4: 更新前端 `TraceLine` 类型**

```typescript
export interface CallInfoDto {
  func_name: string;
  is_jni: boolean;
  summary: string;
  tooltip: string;
}

export interface TraceLine {
  // ... 现有字段 ...
  call_info: CallInfoDto | null;
}
```

- [ ] **Step 5: 现有 `parse_trace_line` 也需要返回 `call_info: None`**

在原始 `parse_trace_line` 的 `Some(TraceLine { ... })` 中添加 `call_info: None`。

- [ ] **Step 6: 运行编译验证**

Run: `cd /Users/richman/Documents/reverse/codes/trace-ui && cargo build 2>&1 | tail -10`
Expected: BUILD SUCCESS

- [ ] **Step 7: Commit**

```bash
git add src/commands/browse.rs src-web/src/types/trace.ts
git commit -m "feat: adapt browse.rs for gumtrace format with call_info support"
```

---

## Task 7: `build_index` 适配 + `get_consumed_seqs` 命令

**Files:**
- Modify: `src/commands/index.rs`
- Create or Modify: `src/commands/browse.rs`（新增命令）
- Modify: `src/main.rs`

- [ ] **Step 1: 更新 `build_index_inner` 以使用 `ScanResult`**

适配 `scan_unified` 的新返回类型。将 `trace_format`、`call_annotations`、`consumed_seqs` 写入 session state。

同时更新格式检查逻辑：gumtrace 格式不要求 `mem[WRITE]`/`mem[READ]` 字段：

```rust
// 格式检查：gumtrace 用 mem_w/mem_r 替代 mem[WRITE]/mem[READ]
if scan_result.scan_state.parsed_count > 0
    && scan_result.scan_state.mem_op_count == 0
    && scan_result.format == TraceFormat::Unidbg
{
    return Err("Trace 日志缺少内存访问注解...".to_string());
}
```

写入 session state 时：
```rust
session.trace_format = scan_result.format;
session.call_annotations = scan_result.call_annotations;
session.consumed_seqs = scan_result.consumed_seqs;
```

**缓存兼容性**: 当从缓存加载 Phase2State/ScanState 时（`build_index_inner` 的缓存分支），`call_annotations` 和 `consumed_seqs` 不在缓存中。需要在缓存命中分支中，仍然执行格式检测 + 快速重扫特殊行来重建这些数据。或者更简单的方案：将 `call_annotations` 和 `consumed_seqs` 作为新字段加入 `Phase2State`（带 `#[serde(default)]`），让它们随 Phase2 缓存一起序列化/反序列化。推荐后者：

```rust
// state.rs - Phase2State 新增字段
#[derive(Serialize, Deserialize)]
pub struct Phase2State {
    // ... 现有字段 ...
    #[serde(default)]
    pub call_annotations: std::collections::HashMap<u32, CallAnnotation>,
    #[serde(default)]
    pub consumed_seqs: Vec<u32>,
    #[serde(default)]
    pub trace_format: TraceFormat,
}
```

这样从旧缓存加载时，新字段默认为空/Unidbg，不会报错。新缓存则包含完整数据。

- [ ] **Step 2: 新增 `get_consumed_seqs` Tauri 命令**

在 `commands/browse.rs` 中添加：

```rust
#[tauri::command]
pub fn get_consumed_seqs(session_id: String, state: State<'_, AppState>) -> Result<Vec<u32>, String> {
    let sessions = state.sessions.read().map_err(|e| e.to_string())?;
    let session = sessions.get(&session_id).ok_or_else(|| format!("Session {} 不存在", session_id))?;
    Ok(session.consumed_seqs.clone())
}
```

- [ ] **Step 3: 在 `main.rs` 中注册新命令**

```rust
commands::browse::get_consumed_seqs,
```

- [ ] **Step 4: 运行编译验证**

Run: `cd /Users/richman/Documents/reverse/codes/trace-ui && cargo build 2>&1 | tail -5`
Expected: BUILD SUCCESS

- [ ] **Step 5: Commit**

```bash
git add src/commands/index.rs src/commands/browse.rs src/main.rs
git commit -m "feat: add get_consumed_seqs command and adapt build_index for gumtrace"
```

---

## Task 8: 前端 consumed_seqs 自动隐藏

**Files:**
- Modify: `src-web/src/hooks/useTraceStore.ts`（或加载 index 的逻辑处）

- [ ] **Step 1: 在 index 构建完成后，调用 `get_consumed_seqs` 并自动隐藏**

在 `useTraceStore.ts`（或 `App.tsx`）中，index 构建完成的回调处，新增逻辑：

```typescript
// Index 构建完成后，获取 consumed seqs 并自动隐藏
const consumedSeqs: number[] = await invoke("get_consumed_seqs", { sessionId });
if (consumedSeqs.length > 0) {
  // 利用现有 highlight hidden 机制自动隐藏这些行
  const hiddenUpdates = consumedSeqs.map(seq => ({
    seq,
    update: { hidden: true } as HighlightInfo,
  }));
  onSetHighlight?.(consumedSeqs, { hidden: true });
}
```

具体位置需要根据 `useTraceStore.ts` 的实际结构调整。关键是在 `index-progress` 事件的 `done: true` 处理中调用。

- [ ] **Step 2: 运行前端编译验证**

Run: `cd /Users/richman/Documents/reverse/codes/trace-ui/src-web && npx tsc --noEmit 2>&1 | tail -10`
Expected: No errors

- [ ] **Step 3: Commit**

```bash
git add src-web/src/hooks/useTraceStore.ts
git commit -m "feat: auto-hide consumed gumtrace lines after index build"
```

---

## Task 9: TraceTable 内联渲染 call_info + hover tooltip

**Files:**
- Modify: `src-web/src/utils/canvasColors.ts`
- Modify: `src-web/src/components/TraceTable.tsx`

- [ ] **Step 1: 新增颜色常量**

在 `canvasColors.ts` 的 `TRACE_TABLE_COLORS` 中添加：

```typescript
callInfoNormal: "#56d4dd",   // 青色：普通外部函数调用
callInfoJni: "#c792ea",      // 紫色：JNI 调用
```

- [ ] **Step 2: 在 canvas 绘制 disasm 之后追加 call_info 渲染**

在 `TraceTable.tsx` 的 disasm 绘制循环**内部**（约第 1726 行 `// 尾部文字` 之后、disasm `if` 块的闭合括号之前），添加 call_info 渲染。`curX` 在 disasm 块内有效，所以必须在块内部添加：

```typescript
        // 尾部文字 (已有代码)
        if (lastIdx < line.disasm.length) { ... curX += tail.length * charW; }

        // ↓ 新增: Call info 内联渲染（紧跟 disasm 尾部文字之后）
        if (line.call_info) {
          const ci = line.call_info;
          const gap = charW * 2; // 2 字符间距
          const ciX = curX + gap;
          ctx.font = FONT_ITALIC;
          ctx.fillStyle = ci.is_jni ? COLORS.callInfoJni : COLORS.callInfoNormal;
          const ciText = ci.summary;
          const maxCiChars = Math.floor((canvasSize.width - ciX - RIGHT_GUTTER) / charW);
          const displayText = ciText.length > maxCiChars && maxCiChars > 1
            ? ciText.slice(0, maxCiChars - 1) + "…"
            : ciText;
          if (maxCiChars > 0) {
            ctx.fillText(displayText, ciX, textY);
            const ciWidth = displayText.length * charW;
            hitboxes.push({ x: ciX, width: ciWidth, rowIndex: i, token: `__call_info__${seq}`, seq });
          }
          ctx.font = FONT; // 恢复字体
        }
      } // ← disasm if 块结束
```

**注意**: `TokenHitbox` 接口需要确认包含 `seq` 字段。如果没有，需要在接口定义处新增 `seq: number`。

- [ ] **Step 3: 新增 call_info tooltip 状态**

在组件顶部新增状态：

```typescript
const [callInfoTooltip, setCallInfoTooltip] = useState<{ x: number; y: number; text: string; isJni: boolean } | null>(null);
```

- [ ] **Step 4: 在 mousemove 处理中检测 call_info hitbox hover**

在 `handleMouseMove` 的 hitbox 检测循环中，检测 `__call_info__` 前缀的 token：

```typescript
for (const hb of hitboxesRef.current) {
  if (x >= hb.x && x <= hb.x + hb.width && y >= rowTop && y < rowTop + ROW_HEIGHT) {
    if (hb.token.startsWith("__call_info__")) {
      const seq = hb.seq;
      const line = visibleLines.get(seq);
      if (line?.call_info) {
        const container = containerRef.current;
        if (container) {
          const rect = container.getBoundingClientRect();
          setCallInfoTooltip({
            x: rect.left + hb.x,
            y: rect.top + rowIdx * ROW_HEIGHT + ROW_HEIGHT,
            text: line.call_info.tooltip,
            isJni: line.call_info.is_jni,
          });
        }
        if (textOverlayRef.current) textOverlayRef.current.style.cursor = "default";
        return;
      }
    }
    // ... 现有的寄存器 hitbox 处理 ...
  }
}
// 不在 call info 区域时关闭
if (callInfoTooltip) setCallInfoTooltip(null);
```

- [ ] **Step 5: 渲染 call_info tooltip（Portal）**

在 JSX 的 tooltip 区域（commentTooltip Portal 附近）添加：

```tsx
{callInfoTooltip && createPortal(
  <div
    style={{
      position: "fixed",
      left: callInfoTooltip.x,
      top: callInfoTooltip.y,
      background: "var(--bg-dialog, #2b2d30)",
      border: `1px solid ${callInfoTooltip.isJni ? "#c792ea" : "#56d4dd"}`,
      borderRadius: 4,
      boxShadow: "0 2px 8px rgba(0,0,0,0.4)",
      padding: "8px 12px",
      maxWidth: 500,
      maxHeight: 300,
      overflow: "auto",
      zIndex: 10000,
      fontSize: 12,
      fontFamily: '"JetBrains Mono", "Fira Code", monospace',
      color: "var(--text-primary, #abb2bf)",
      whiteSpace: "pre-wrap",
      wordBreak: "break-word",
      pointerEvents: "none",
    }}
  >
    {callInfoTooltip.text}
  </div>,
  document.body,
)}
```

- [ ] **Step 6: 运行前端编译验证**

Run: `cd /Users/richman/Documents/reverse/codes/trace-ui/src-web && npx tsc --noEmit 2>&1 | tail -10`
Expected: No errors

- [ ] **Step 7: Commit**

```bash
git add src-web/src/utils/canvasColors.ts src-web/src/components/TraceTable.tsx
git commit -m "feat: render call_info inline after disasm with hover tooltip"
```

---

## Task 10: 端到端验证

**Files:** 无新改动

- [ ] **Step 1: Rust 全量测试**

Run: `cd /Users/richman/Documents/reverse/codes/trace-ui && cargo test 2>&1 | tail -20`
Expected: ALL PASS

- [ ] **Step 2: 前端编译检查**

Run: `cd /Users/richman/Documents/reverse/codes/trace-ui/src-web && npx tsc --noEmit`
Expected: No errors

- [ ] **Step 3: 完整构建**

Run: `cd /Users/richman/Documents/reverse/codes/trace-ui && cargo tauri build --debug 2>&1 | tail -20`
Expected: BUILD SUCCESS

- [ ] **Step 4: 手动测试（使用 gumtrace日志格式.txt）**

1. 启动应用
2. 打开 `/Users/richman/Documents/reverse/codes/gumtrace日志格式.txt`
3. 验证：
   - 格式自动检测为 gumtrace
   - 指令行正确显示（地址、反汇编、寄存器变化）
   - 特殊行（call func/args/ret/hexdump）不显示为独立行
   - `bl` 指令行右侧显示青色的调用摘要
   - `blr` + JNI 调用显示紫色摘要
   - hover 摘要文本时弹出完整 tooltip
   - 函数调用树显示函数名称
   - 搜索功能正常
   - 内存面板正常

- [ ] **Step 5: 最终 commit**

```bash
git add -A
git commit -m "feat: complete gumtrace format support with inline call annotations"
```
