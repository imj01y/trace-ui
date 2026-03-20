# Strings View Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an IDA-like Strings View that extracts strings from trace memory operations, displays them in a searchable panel, and supports jump/highlight/xref/taint integration.

**Architecture:** StringBuilder integrates into the existing `scan_unified()` loop in `src/taint/mod.rs`. It maintains a paged byte-level memory image and tracks active strings. Results are cached with Phase2State via bincode. Frontend adds a new "Strings" tab to the bottom TabPanel with virtual scrolling.

**Tech Stack:** Rust (Tauri 2, serde, bincode, rustc-hash), TypeScript/React 19, @tanstack/react-virtual

**Spec:** `docs/superpowers/specs/2026-03-16-strings-view-design.md`

---

## File Structure

### Rust Backend (new files)
| File | Responsibility |
|------|----------------|
| `src/taint/strings.rs` | StringRecord, StringEncoding, StringIndex, PagedMemory, StringBuilder — all core data structures and extraction algorithm |
| `src/commands/strings.rs` | `get_strings` and `get_string_xrefs` Tauri commands |

### Rust Backend (modified files)
| File | Change |
|------|--------|
| `src/taint/mod.rs` | Add `pub mod strings;`, integrate StringBuilder into `scan_unified()` loop, add StringIndex to return |
| `src/state.rs` | Add `string_index: StringIndex` field to Phase2State |
| `src/cache.rs` | Update MAGIC from `TCACHE01` to `TCACHE02` |
| `src/commands/mod.rs` | Add `pub mod strings;` |
| `src/main.rs` | Register `get_strings` and `get_string_xrefs` commands |

### Frontend (new files)
| File | Responsibility |
|------|----------------|
| `src-web/src/components/StringsPanel.tsx` | Strings list panel with search, filter, virtual scroll, context menu |

### Frontend (modified files)
| File | Change |
|------|--------|
| `src-web/src/types/trace.ts` | Add StringRecord, StringsResult, StringXRef interfaces |
| `src-web/src/components/TabPanel.tsx` | Add "Strings" tab, render StringsPanel |
| `src-web/src/FloatingPanel.tsx` | Add `case "strings"` rendering |
| `src-web/src/App.tsx` | Add strings panel size preset and window title |

---

## Chunk 1: Backend Core — Data Structures & Algorithm

### Task 1: Create `src/taint/strings.rs` with data structures

**Files:**
- Create: `src/taint/strings.rs`

- [ ] **Step 1: Create strings.rs with all data structures**

```rust
use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};

// ── 持久化数据结构 ──

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum StringEncoding {
    Ascii,
    Utf8,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct StringRecord {
    pub addr: u64,
    pub content: String,
    pub encoding: StringEncoding,
    pub byte_len: u32,
    pub seq: u32,
    pub xref_count: u32,
}

#[derive(Serialize, Deserialize, Default)]
pub struct StringIndex {
    pub strings: Vec<StringRecord>,
}

// ── 页式内存镜像 ──

const PAGE_SIZE: usize = 4096;
const PAGE_MASK: u64 = !(PAGE_SIZE as u64 - 1);

struct Page {
    data: [u8; PAGE_SIZE],
    valid: [bool; PAGE_SIZE],
}

impl Page {
    fn new() -> Self {
        Page {
            data: [0; PAGE_SIZE],
            valid: [false; PAGE_SIZE],
        }
    }
}

pub(crate) struct PagedMemory {
    pages: FxHashMap<u64, Box<Page>>,
}

impl PagedMemory {
    pub fn new() -> Self {
        Self { pages: FxHashMap::default() }
    }

    pub fn set_byte(&mut self, addr: u64, value: u8) {
        let page_addr = addr & PAGE_MASK;
        let offset = (addr & !PAGE_MASK) as usize;
        let page = self.pages.entry(page_addr).or_insert_with(|| Box::new(Page::new()));
        page.data[offset] = value;
        page.valid[offset] = true;
    }

    pub fn get_byte(&self, addr: u64) -> Option<u8> {
        let page_addr = addr & PAGE_MASK;
        let offset = (addr & !PAGE_MASK) as usize;
        self.pages.get(&page_addr).and_then(|page| {
            if page.valid[offset] { Some(page.data[offset]) } else { None }
        })
    }
}

// ── 活跃字符串 ──

struct ActiveString {
    addr: u64,
    byte_len: u32,
    content: String,
    encoding: StringEncoding,
    seq: u32,
}

// ── StringBuilder ──

const MAX_SCAN_LEN: u64 = 1024;
const MIN_CACHE_LEN: u32 = 2; // 缓存中的最低阈值

pub(crate) struct StringBuilder {
    byte_image: PagedMemory,
    byte_owner: FxHashMap<u64, u32>,  // byte_addr → active string id
    active: FxHashMap<u32, ActiveString>,
    results: Vec<StringRecord>,
    next_id: u32,
}

impl StringBuilder {
    pub fn new() -> Self {
        Self {
            byte_image: PagedMemory::new(),
            byte_owner: FxHashMap::default(),
            active: FxHashMap::default(),
            results: Vec::new(),
            next_id: 0,
        }
    }

    /// 处理一条 WRITE 操作
    pub fn process_write(&mut self, addr: u64, data: u64, size: u8, seq: u32) {
        // 1. 展开 data 为字节（小端序），更新 byte_image
        for i in 0..size as u64 {
            let byte_val = ((data >> (i * 8)) & 0xFF) as u8;
            self.byte_image.set_byte(addr + i, byte_val);
        }

        // 2. 收集受影响的活跃字符串 id
        let mut affected_ids: Vec<u32> = Vec::new();
        for i in 0..size as u64 {
            if let Some(&id) = self.byte_owner.get(&(addr + i)) {
                if !affected_ids.contains(&id) {
                    affected_ids.push(id);
                }
            }
        }

        // 3. 移除受影响的活跃字符串（稍后重新扫描判断）
        for &id in &affected_ids {
            if let Some(old) = self.active.remove(&id) {
                // 存入 results（旧版本快照）
                if old.byte_len >= MIN_CACHE_LEN {
                    self.results.push(StringRecord {
                        addr: old.addr,
                        content: old.content,
                        encoding: old.encoding,
                        byte_len: old.byte_len,
                        seq: old.seq,
                        xref_count: 0,
                    });
                }
                // 清除 byte_owner
                for j in 0..old.byte_len as u64 {
                    self.byte_owner.remove(&(old.addr + j));
                }
            }
        }

        // 4. 局部扫描：从写入范围向两端扩展，找出连续可打印区域
        let scan_start = self.scan_backward(addr);
        let scan_end = self.scan_forward(addr + size as u64 - 1);

        // 5. 在 [scan_start, scan_end] 中提取所有字符串
        self.extract_strings_in_range(scan_start, scan_end, seq);
    }

    /// 向前（低地址）扫描，返回连续可打印区域的起始地址
    fn scan_backward(&self, addr: u64) -> u64 {
        let limit = addr.saturating_sub(MAX_SCAN_LEN);
        let mut cur = addr;
        while cur > limit {
            let prev = cur - 1;
            match self.byte_image.get_byte(prev) {
                Some(b) if is_printable_or_utf8(b) => cur = prev,
                _ => break,
            }
        }
        cur
    }

    /// 向后（高地址）扫描，返回连续可打印区域的结束地址（inclusive）
    fn scan_forward(&self, addr: u64) -> u64 {
        let limit = addr.saturating_add(MAX_SCAN_LEN);
        let mut cur = addr;
        while cur < limit {
            let next = cur + 1;
            match self.byte_image.get_byte(next) {
                Some(b) if is_printable_or_utf8(b) => cur = next,
                _ => break,
            }
        }
        cur
    }

    /// 在给定范围内提取所有 ≥ MIN_CACHE_LEN 的字符串
    fn extract_strings_in_range(&mut self, start: u64, end: u64, seq: u32) {
        let mut pos = start;
        while pos <= end {
            // 跳过非可打印字节
            match self.byte_image.get_byte(pos) {
                Some(b) if is_printable_or_utf8(b) => {}
                _ => { pos += 1; continue; }
            }

            // 收集连续可打印字节
            let str_start = pos;
            let mut bytes: Vec<u8> = Vec::new();
            while pos <= end {
                match self.byte_image.get_byte(pos) {
                    Some(b) if is_printable_or_utf8(b) => {
                        bytes.push(b);
                        pos += 1;
                    }
                    _ => break,
                }
            }

            if bytes.len() < MIN_CACHE_LEN as usize {
                continue;
            }

            // 如果该区域已被某个活跃字符串覆盖且内容相同，跳过
            if let Some(&existing_id) = self.byte_owner.get(&str_start) {
                if let Some(existing) = self.active.get(&existing_id) {
                    if existing.addr == str_start && existing.byte_len == bytes.len() as u32 {
                        // 内容未变，跳过
                        continue;
                    }
                }
            }

            // UTF-8 验证
            let (content, encoding) = match std::str::from_utf8(&bytes) {
                Ok(s) => {
                    let has_multibyte = bytes.iter().any(|&b| b >= 0x80);
                    (s.to_string(), if has_multibyte { StringEncoding::Utf8 } else { StringEncoding::Ascii })
                }
                Err(_) => {
                    // 降级为纯 ASCII
                    let ascii_bytes: Vec<u8> = bytes.iter()
                        .copied()
                        .take_while(|&b| b >= 0x20 && b <= 0x7E)
                        .collect();
                    if ascii_bytes.len() < MIN_CACHE_LEN as usize {
                        continue;
                    }
                    let s = String::from_utf8(ascii_bytes.clone()).unwrap();
                    // 调整 pos 回退到 ASCII 结束位置
                    pos = str_start + ascii_bytes.len() as u64;
                    (s, StringEncoding::Ascii)
                }
            };

            let byte_len = content.len() as u32;

            // 注册为活跃字符串
            let id = self.next_id;
            self.next_id += 1;
            for j in 0..byte_len as u64 {
                self.byte_owner.insert(str_start + j, id);
            }
            self.active.insert(id, ActiveString {
                addr: str_start,
                byte_len,
                content,
                encoding,
                seq,
            });
        }
    }

    /// Phase2 结束时调用：将所有活跃字符串存入 results，返回 StringIndex
    pub fn finish(mut self) -> StringIndex {
        for (_, s) in self.active.drain() {
            if s.byte_len >= MIN_CACHE_LEN {
                self.results.push(StringRecord {
                    addr: s.addr,
                    content: s.content,
                    encoding: s.encoding,
                    byte_len: s.byte_len,
                    seq: s.seq,
                    xref_count: 0,
                });
            }
        }
        // 按 seq 排序
        self.results.sort_by_key(|r| r.seq);
        StringIndex { strings: self.results }
    }

    /// 统计每个字符串的 xref_count（传入 MemAccessIndex 引用）
    pub fn fill_xref_counts(index: &mut StringIndex, mem_idx: &crate::taint::mem_access::MemAccessIndex) {
        use crate::taint::mem_access::MemRw;
        for record in &mut index.strings {
            let mut count = 0u32;
            for offset in 0..record.byte_len as u64 {
                let addr = record.addr + offset;
                if let Some(records) = mem_idx.get(addr) {
                    count += records.iter().filter(|r| r.rw == MemRw::Read).count() as u32;
                }
            }
            record.xref_count = count;
        }
    }
}

/// 判断字节是否为可打印字符（用于字符串扫描）
/// 范围：0x20-0x7E (ASCII 可打印) + 0x80-0xF4 (UTF-8 多字节)
fn is_printable_or_utf8(b: u8) -> bool {
    (b >= 0x20 && b <= 0x7E) || (b >= 0x80 && b <= 0xF4)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_paged_memory_basic() {
        let mut mem = PagedMemory::new();
        assert_eq!(mem.get_byte(0x1000), None);
        mem.set_byte(0x1000, 0x41);
        assert_eq!(mem.get_byte(0x1000), Some(0x41));
        assert_eq!(mem.get_byte(0x1001), None);
    }

    #[test]
    fn test_paged_memory_cross_page() {
        let mut mem = PagedMemory::new();
        mem.set_byte(0xFFF, 0x41); // 末页
        mem.set_byte(0x1000, 0x42); // 下一页
        assert_eq!(mem.get_byte(0xFFF), Some(0x41));
        assert_eq!(mem.get_byte(0x1000), Some(0x42));
    }

    #[test]
    fn test_is_printable_or_utf8() {
        assert!(is_printable_or_utf8(b'A'));
        assert!(is_printable_or_utf8(b' '));
        assert!(is_printable_or_utf8(b'~'));
        assert!(is_printable_or_utf8(0xC0)); // UTF-8 首字节
        assert!(!is_printable_or_utf8(0x00)); // null
        assert!(!is_printable_or_utf8(0x0A)); // newline
        assert!(!is_printable_or_utf8(0x19)); // control char
        assert!(!is_printable_or_utf8(0xF5)); // 超出 UTF-8 范围
    }

    #[test]
    fn test_simple_string_extraction() {
        let mut sb = StringBuilder::new();
        // 写入 "Hello" 到地址 0x1000 (小端序: 0x6F6C6C6548)
        sb.process_write(0x1000, 0x6F6C6C6548, 5, 100);
        let index = sb.finish();
        assert_eq!(index.strings.len(), 1);
        assert_eq!(index.strings[0].content, "Hello");
        assert_eq!(index.strings[0].addr, 0x1000);
        assert_eq!(index.strings[0].encoding, StringEncoding::Ascii);
        assert_eq!(index.strings[0].seq, 100);
    }

    #[test]
    fn test_string_overwrite_creates_snapshot() {
        let mut sb = StringBuilder::new();
        // 写入 "ABCD" 到 0x1000
        sb.process_write(0x1000, 0x44434241, 4, 100);
        // 覆写为 "WXYZ"
        sb.process_write(0x1000, 0x5A595857, 4, 200);
        let index = sb.finish();
        // 应该有 2 条记录：旧版本 "ABCD" + 新版本 "WXYZ"
        assert_eq!(index.strings.len(), 2);
        assert_eq!(index.strings[0].content, "ABCD");
        assert_eq!(index.strings[0].seq, 100);
        assert_eq!(index.strings[1].content, "WXYZ");
        assert_eq!(index.strings[1].seq, 200);
    }

    #[test]
    fn test_string_destroyed_by_null() {
        let mut sb = StringBuilder::new();
        // 写入 "ABCD" 到 0x1000
        sb.process_write(0x1000, 0x44434241, 4, 100);
        // 在中间写 \0，切断字符串
        sb.process_write(0x1002, 0x00, 1, 200);
        let index = sb.finish();
        // "ABCD" 被销毁并记录，可能留下 "AB" 和 "D"（取决于 min_len）
        let full = index.strings.iter().find(|s| s.content == "ABCD");
        assert!(full.is_some(), "Original 'ABCD' should be recorded as snapshot");
    }

    #[test]
    fn test_too_short_string_ignored() {
        let mut sb = StringBuilder::new();
        // 写入单个字节 'A'
        sb.process_write(0x1000, 0x41, 1, 100);
        let index = sb.finish();
        // 长度 1 < MIN_CACHE_LEN(2)，不应记录
        assert_eq!(index.strings.len(), 0);
    }

    #[test]
    fn test_incremental_string_building() {
        let mut sb = StringBuilder::new();
        // 逐字节写入 "ABC"
        sb.process_write(0x1000, 0x41, 1, 100); // 'A'
        sb.process_write(0x1001, 0x42, 1, 101); // 'B'
        sb.process_write(0x1002, 0x43, 1, 102); // 'C'
        let index = sb.finish();
        // 最终应该有 "ABC"（可能还有中间的 "AB"）
        let abc = index.strings.iter().find(|s| s.content == "ABC");
        assert!(abc.is_some(), "Final 'ABC' should exist");
    }
}
```

- [ ] **Step 2: Register the module**

Add to `src/taint/mod.rs` at the top with other module declarations (after line 9):
```rust
pub mod strings;
```

- [ ] **Step 3: Run tests to verify**

Run: `cd /Users/richman/Documents/reverse/codes/trace-ui && cargo test --lib taint::strings`

Expected: All 7 tests pass.

- [ ] **Step 4: Commit**

```bash
git add src/taint/strings.rs src/taint/mod.rs
git commit -m "feat: add string extraction core — PagedMemory, StringBuilder, StringIndex"
```

---

### Task 2: Integrate StringBuilder into scan_unified

**Files:**
- Modify: `src/taint/mod.rs` (scan_unified function)
- Modify: `src/state.rs` (Phase2State struct)
- Modify: `src/cache.rs` (MAGIC version)

- [ ] **Step 1: Add StringIndex to Phase2State**

In `src/state.rs`, add import and field:

```rust
// Add to imports (after line 7):
use crate::taint::strings::StringIndex;

// Add field to Phase2State (after line 15, before closing brace):
    pub string_index: StringIndex,
```

- [ ] **Step 2: Update MAGIC in cache.rs**

In `src/cache.rs` line 8, change:
```rust
const MAGIC: &[u8; 8] = b"TCACHE02";
```

- [ ] **Step 3: Integrate StringBuilder into scan_unified**

In `src/taint/mod.rs`, add these changes:

At the top, add import (with other `use` statements):
```rust
use crate::taint::strings::StringBuilder;
```

Inside `scan_unified()`, after `let mut mem_idx = MemAccessIndex::new();` (around line 60), add:
```rust
    let mut string_builder = StringBuilder::new();
```

After the `mem_idx.add(...)` call (after line 398), add the StringBuilder integration:
```rust
            // ── Phase2: 字符串提取 ──
            if mem_op.is_write && mem_op.elem_width <= 8 {
                if let Some(value) = mem_op.value {
                    string_builder.process_write(mem_op.abs, value, mem_op.elem_width, i);
                }
            }
```

At the end of scan_unified, before constructing Phase2State (around line 424-429), add:
```rust
    let mut string_index = string_builder.finish();
    StringBuilder::fill_xref_counts(&mut string_index, &mem_idx);
```

Update the Phase2State construction to include string_index:
```rust
    let phase2_state = Phase2State {
        call_tree,
        mem_accesses: mem_idx,
        reg_checkpoints: reg_ckpts,
        string_index,
    };
```

- [ ] **Step 4: Build to verify compilation**

Run: `cd /Users/richman/Documents/reverse/codes/trace-ui && cargo build 2>&1 | head -30`

Expected: Successful compilation (warnings are OK).

- [ ] **Step 5: Run string extraction tests again**

Run: `cargo test --lib taint::strings`

Expected: All tests pass.

- [ ] **Step 6: Commit**

```bash
git add src/taint/mod.rs src/state.rs src/cache.rs
git commit -m "feat: integrate StringBuilder into scan_unified, update cache MAGIC to TCACHE02"
```

---

### Task 3: Add Tauri commands for strings

**Files:**
- Create: `src/commands/strings.rs`
- Modify: `src/commands/mod.rs`
- Modify: `src/main.rs`

- [ ] **Step 1: Create commands/strings.rs**

```rust
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
```

- [ ] **Step 2: Register module in commands/mod.rs**

Add to `src/commands/mod.rs` (after the `slice` line):
```rust
pub mod strings;
```

- [ ] **Step 3: Register commands in main.rs**

In `src/main.rs`, add to the `invoke_handler` array (after `commands::cache::clear_all_cache,`):
```rust
            commands::strings::get_strings,
            commands::strings::get_string_xrefs,
```

- [ ] **Step 4: Build to verify compilation**

Run: `cargo build 2>&1 | head -30`

Expected: Successful compilation.

- [ ] **Step 5: Commit**

```bash
git add src/commands/strings.rs src/commands/mod.rs src/main.rs
git commit -m "feat: add get_strings and get_string_xrefs Tauri commands"
```

---

## Chunk 2: Frontend — StringsPanel & Integration

### Task 4: Add TypeScript type definitions

**Files:**
- Modify: `src-web/src/types/trace.ts`

- [ ] **Step 1: Add string-related interfaces**

Append to `src-web/src/types/trace.ts`:

```typescript

export interface StringRecordDto {
  idx: number;
  addr: string;
  content: string;
  encoding: string;
  byte_len: number;
  seq: number;
  xref_count: number;
}

export interface StringsResult {
  strings: StringRecordDto[];
  total: number;
}

export interface StringXRef {
  seq: number;
  rw: string;
  insn_addr: string;
  disasm: string;
}
```

- [ ] **Step 2: Commit**

```bash
git add src-web/src/types/trace.ts
git commit -m "feat: add StringRecordDto, StringsResult, StringXRef types"
```

---

### Task 5: Create StringsPanel component

**Files:**
- Create: `src-web/src/components/StringsPanel.tsx`

- [ ] **Step 1: Create the StringsPanel component**

```tsx
import React, { useState, useEffect, useRef, useCallback, useMemo } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useVirtualizerNoSync } from "../hooks/useVirtualizerNoSync";
import type { StringRecordDto, StringsResult, StringXRef } from "../types/trace";

const PAGE_SIZE = 500;
const ROW_HEIGHT = 22;

interface Props {
  sessionId: string | null;
  isPhase2Ready: boolean;
  onJumpToSeq: (seq: number) => void;
}

export default function StringsPanel({ sessionId, isPhase2Ready, onJumpToSeq }: Props) {
  const [strings, setStrings] = useState<StringRecordDto[]>([]);
  const [total, setTotal] = useState(0);
  const [minLen, setMinLen] = useState(4);
  const [search, setSearch] = useState("");
  const [loading, setLoading] = useState(false);
  const [selectedIdx, setSelectedIdx] = useState<number | null>(null);
  const [contextMenu, setContextMenu] = useState<{ x: number; y: number; record: StringRecordDto } | null>(null);
  const [xrefs, setXrefs] = useState<{ record: StringRecordDto; items: StringXRef[] } | null>(null);

  const parentRef = useRef<HTMLDivElement>(null);
  const searchTimerRef = useRef<ReturnType<typeof setTimeout>>();
  const minLenTimerRef = useRef<ReturnType<typeof setTimeout>>();
  const pendingRef = useRef(0);

  // ── 数据加载 ──
  const loadStrings = useCallback(async (offset: number, reset: boolean) => {
    if (!sessionId || !isPhase2Ready) return;
    const reqId = ++pendingRef.current;
    if (reset) setLoading(true);

    try {
      const result = await invoke<StringsResult>("get_strings", {
        sessionId,
        minLen,
        offset,
        limit: PAGE_SIZE,
        search: search || null,
      });
      if (reqId !== pendingRef.current) return; // stale
      if (reset) {
        setStrings(result.strings);
      } else {
        setStrings(prev => [...prev, ...result.strings]);
      }
      setTotal(result.total);
    } catch (e) {
      console.error("get_strings failed:", e);
    } finally {
      if (reqId === pendingRef.current) setLoading(false);
    }
  }, [sessionId, isPhase2Ready, minLen, search]);

  // 初始加载 & 搜索/minLen 变化时重新加载
  useEffect(() => {
    loadStrings(0, true);
  }, [loadStrings]);

  // ── 搜索 debounce ──
  const [searchInput, setSearchInput] = useState("");
  useEffect(() => {
    clearTimeout(searchTimerRef.current);
    searchTimerRef.current = setTimeout(() => setSearch(searchInput), 300);
    return () => clearTimeout(searchTimerRef.current);
  }, [searchInput]);

  // ── minLen debounce ──
  const [minLenInput, setMinLenInput] = useState(4);
  useEffect(() => {
    clearTimeout(minLenTimerRef.current);
    minLenTimerRef.current = setTimeout(() => setMinLen(minLenInput), 200);
    return () => clearTimeout(minLenTimerRef.current);
  }, [minLenInput]);

  // ── 虚拟滚动 ──
  const virtualizer = useVirtualizerNoSync({
    count: strings.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 20,
  });

  // ── 无限滚动加载更多 ──
  const virtualItems = virtualizer.getVirtualItems();
  const lastVirtualItemIndex = virtualItems.length > 0 ? virtualItems[virtualItems.length - 1].index : -1;
  useEffect(() => {
    if (lastVirtualItemIndex >= strings.length - 50 && strings.length < total && !loading) {
      loadStrings(strings.length, false);
    }
  }, [lastVirtualItemIndex, strings.length, total, loading, loadStrings]);

  // ── 点击行 ──
  const handleRowClick = useCallback((record: StringRecordDto) => {
    setSelectedIdx(record.idx);
    onJumpToSeq(record.seq);
  }, [onJumpToSeq]);

  // ── 右键菜单 ──
  const handleContextMenu = useCallback((e: React.MouseEvent, record: StringRecordDto) => {
    e.preventDefault();
    setContextMenu({ x: e.clientX, y: e.clientY, record });
  }, []);

  // 关闭右键菜单
  useEffect(() => {
    const close = () => setContextMenu(null);
    window.addEventListener("click", close);
    return () => window.removeEventListener("click", close);
  }, []);

  // ── 右键菜单操作 ──
  const handleCopyString = useCallback(() => {
    if (contextMenu) navigator.clipboard.writeText(contextMenu.record.content);
    setContextMenu(null);
  }, [contextMenu]);

  const handleCopyAddr = useCallback(() => {
    if (contextMenu) navigator.clipboard.writeText(contextMenu.record.addr);
    setContextMenu(null);
  }, [contextMenu]);

  const handleViewInMemory = useCallback(() => {
    // TODO: 需要 TabPanel 暴露切换 tab 的回调，或通过事件系统
    // V1 暂时通过 onJumpToSeq 跳转到对应行，用户可手动切到 Memory tab
    if (contextMenu) onJumpToSeq(contextMenu.record.seq);
    setContextMenu(null);
  }, [contextMenu, onJumpToSeq]);

  const handleShowXrefs = useCallback(async () => {
    if (!contextMenu || !sessionId) return;
    const record = contextMenu.record;
    setContextMenu(null);
    try {
      const items = await invoke<StringXRef[]>("get_string_xrefs", {
        sessionId,
        addr: record.addr,
        byteLen: record.byte_len,
      });
      setXrefs({ record, items });
    } catch (e) {
      console.error("get_string_xrefs failed:", e);
    }
  }, [contextMenu, sessionId]);

  // ── 非就绪状态 ──
  if (!isPhase2Ready) {
    return (
      <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center" }}>
        <span style={{ color: "var(--text-secondary)", fontSize: 12 }}>Index not ready</span>
      </div>
    );
  }

  return (
    <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
      {/* 工具栏 */}
      <div style={{
        display: "flex", alignItems: "center", gap: 8, padding: "4px 8px",
        borderBottom: "1px solid var(--border-color)", flexShrink: 0,
      }}>
        <input
          value={searchInput}
          onChange={e => setSearchInput(e.target.value)}
          placeholder="Search strings..."
          style={{
            flex: 1, background: "var(--input-bg)", border: "1px solid var(--border-color)",
            color: "var(--text-primary)", padding: "3px 8px", borderRadius: 3, fontSize: 12,
          }}
        />
        <span style={{ color: "var(--text-secondary)", fontSize: 11, whiteSpace: "nowrap" }}>Min len:</span>
        <input
          type="range" min={2} max={20} value={minLenInput}
          onChange={e => setMinLenInput(Number(e.target.value))}
          style={{ width: 60 }}
        />
        <span style={{ color: "var(--text-secondary)", fontSize: 11, minWidth: 16 }}>{minLenInput}</span>
        <span style={{ color: "var(--text-tertiary)", fontSize: 11, whiteSpace: "nowrap" }}>
          {total.toLocaleString()} strings
        </span>
      </div>

      {/* 表头 */}
      <div style={{
        display: "grid",
        gridTemplateColumns: "70px 110px 1fr 56px 44px 56px",
        padding: "3px 8px",
        borderBottom: "1px solid var(--border-color)",
        background: "var(--bg-secondary)",
        fontSize: 11, color: "var(--text-secondary)", flexShrink: 0,
      }}>
        <span>Seq</span>
        <span>Address</span>
        <span>Content</span>
        <span>Enc</span>
        <span>Len</span>
        <span>XRefs</span>
      </div>

      {/* 虚拟滚动列表 */}
      <div ref={parentRef} style={{ flex: 1, overflow: "auto" }}>
        <div style={{ height: virtualizer.getTotalSize(), width: "100%", position: "relative" }}>
          {virtualizer.getVirtualItems().map(virtualRow => {
            const record = strings[virtualRow.index];
            if (!record) return null;
            const isSelected = record.idx === selectedIdx;
            return (
              <div
                key={virtualRow.key}
                data-index={virtualRow.index}
                ref={virtualizer.measureElement}
                onClick={() => handleRowClick(record)}
                onContextMenu={e => handleContextMenu(e, record)}
                style={{
                  position: "absolute",
                  top: 0,
                  left: 0,
                  width: "100%",
                  height: ROW_HEIGHT,
                  transform: `translateY(${virtualRow.start}px)`,
                  display: "grid",
                  gridTemplateColumns: "70px 110px 1fr 56px 44px 56px",
                  padding: "0 8px",
                  alignItems: "center",
                  fontSize: 12,
                  fontFamily: "var(--font-mono)",
                  cursor: "pointer",
                  background: isSelected ? "var(--selection-bg)" : "transparent",
                  borderBottom: "1px solid var(--border-subtle)",
                }}
              >
                <span style={{ color: "var(--syntax-number)" }}>{record.seq}</span>
                <span style={{ color: "var(--syntax-literal)" }}>{record.addr}</span>
                <span style={{
                  color: "var(--syntax-string)",
                  overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                }}>"{record.content}"</span>
                <span style={{ color: "var(--text-secondary)" }}>{record.encoding}</span>
                <span>{record.byte_len}</span>
                <span style={{ color: record.xref_count > 0 ? "var(--syntax-keyword)" : "var(--text-secondary)" }}>
                  {record.xref_count}
                </span>
              </div>
            );
          })}
        </div>
      </div>

      {loading && (
        <div style={{
          padding: "3px 8px", flexShrink: 0,
          borderTop: "1px solid var(--border-color)",
          background: "var(--bg-secondary)",
          fontSize: 11, color: "var(--text-secondary)",
        }}>
          Loading...
        </div>
      )}

      {/* 右键菜单 */}
      {contextMenu && (
        <div style={{
          position: "fixed", left: contextMenu.x, top: contextMenu.y, zIndex: 9999,
          background: "var(--bg-secondary)", border: "1px solid var(--border-color)",
          borderRadius: 4, padding: "4px 0", boxShadow: "0 4px 12px rgba(0,0,0,0.3)",
          minWidth: 160,
        }}>
          {[
            { label: "Copy String", action: handleCopyString },
            { label: "Copy Address", action: handleCopyAddr },
            { label: "View in Memory", action: handleViewInMemory },
            { label: "Show XRefs", action: handleShowXrefs },
          ].map(item => (
            <div
              key={item.label}
              onClick={item.action}
              style={{
                padding: "5px 12px", fontSize: 12, cursor: "pointer",
                color: "var(--text-primary)",
              }}
              onMouseEnter={e => (e.currentTarget.style.background = "var(--selection-bg)")}
              onMouseLeave={e => (e.currentTarget.style.background = "transparent")}
            >
              {item.label}
            </div>
          ))}
        </div>
      )}

      {/* XRefs 弹窗 */}
      {xrefs && (
        <div style={{
          position: "fixed", left: "50%", top: "50%", transform: "translate(-50%, -50%)",
          zIndex: 9999, background: "var(--bg-primary)", border: "1px solid var(--border-color)",
          borderRadius: 6, boxShadow: "0 8px 24px rgba(0,0,0,0.4)",
          width: 500, maxHeight: 400, display: "flex", flexDirection: "column",
        }}>
          <div style={{
            padding: "8px 12px", borderBottom: "1px solid var(--border-color)",
            display: "flex", justifyContent: "space-between", alignItems: "center",
          }}>
            <span style={{ fontSize: 12, color: "var(--text-primary)" }}>
              XRefs for "{xrefs.record.content.slice(0, 30)}{xrefs.record.content.length > 30 ? "..." : ""}" ({xrefs.items.length})
            </span>
            <button
              onClick={() => setXrefs(null)}
              style={{
                background: "none", border: "none", color: "var(--text-secondary)",
                cursor: "pointer", fontSize: 16, padding: "0 4px",
              }}
            >×</button>
          </div>
          <div style={{ flex: 1, overflow: "auto" }}>
            {xrefs.items.map((xref, i) => (
              <div
                key={i}
                onClick={() => { onJumpToSeq(xref.seq); setXrefs(null); }}
                style={{
                  padding: "4px 12px", fontSize: 12, fontFamily: "var(--font-mono)",
                  cursor: "pointer", borderBottom: "1px solid var(--border-subtle)",
                  display: "flex", gap: 12,
                }}
                onMouseEnter={e => (e.currentTarget.style.background = "var(--selection-bg)")}
                onMouseLeave={e => (e.currentTarget.style.background = "transparent")}
              >
                <span style={{ color: "var(--syntax-number)", minWidth: 60 }}>{xref.seq}</span>
                <span style={{ color: xref.rw === "R" ? "var(--syntax-keyword)" : "var(--syntax-literal)", minWidth: 16 }}>{xref.rw}</span>
                <span style={{ color: "var(--text-secondary)", minWidth: 90 }}>{xref.insn_addr}</span>
                <span style={{ color: "var(--text-primary)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{xref.disasm}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
```

- [ ] **Step 2: Verify frontend build**

Run: `cd /Users/richman/Documents/reverse/codes/trace-ui && npm run --prefix src-web build 2>&1 | tail -10`

Expected: Build may fail (StringsPanel not yet wired up), but no internal errors.

- [ ] **Step 3: Commit**

```bash
git add src-web/src/components/StringsPanel.tsx
git commit -m "feat: add StringsPanel component with search, filter, xrefs, context menu"
```

---

### Task 6: Wire up StringsPanel to TabPanel, FloatingPanel, and App

**Files:**
- Modify: `src-web/src/components/TabPanel.tsx`
- Modify: `src-web/src/FloatingPanel.tsx`
- Modify: `src-web/src/App.tsx`

- [ ] **Step 1: Add Strings tab to TabPanel.tsx**

In `src-web/src/components/TabPanel.tsx`:

1. Add import (after line 6):
```typescript
import StringsPanel from "./StringsPanel";
```

2. Update TABS array (line 8):
```typescript
const TABS = ["Memory", "Accesses", "Taint State", "Search", "Strings"] as const;
```

3. Add to TAB_TO_PANEL (after "Search" entry, line 15):
```typescript
  "Strings": "strings",
```

4. Add case to renderContent switch (before the `default:` case, around line 146):
```typescript
      case "Strings":
        return (
          <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
            <StringsPanel
              sessionId={sessionId}
              isPhase2Ready={isPhase2Ready}
              onJumpToSeq={onJumpToSeq}
            />
          </div>
        );
```

- [ ] **Step 2: Add strings to FloatingPanel.tsx**

In `src-web/src/FloatingPanel.tsx`:

1. Add to PANEL_TITLES (after "search" entry):
```typescript
    strings: "Strings",
```

2. Add import for StringsPanel at the top (with other component imports):
```typescript
import StringsPanel from "./components/StringsPanel";
```

3. Add case to panel rendering switch (before the `default:` case):
```typescript
        case "strings":
          return (
            <StringsPanel
              sessionId={syncState.sessionId}
              isPhase2Ready={syncState.isPhase2Ready}
              onJumpToSeq={handleJumpToSeq}
            />
          );
```

- [ ] **Step 3: Add strings panel size preset in App.tsx**

In `src-web/src/App.tsx`:

1. Add to PANEL_SIZES (after "search" entry):
```typescript
    strings: { width: 900, height: 450 },
```

2. If there's a PANEL_WINDOW_TITLES object, add:
```typescript
    strings: "Strings - Trace UI",
```

- [ ] **Step 4: Verify full build**

Run: `cd /Users/richman/Documents/reverse/codes/trace-ui && npm run --prefix src-web build 2>&1 | tail -10`

Expected: Successful build.

- [ ] **Step 5: Full Tauri build check**

Run: `cd /Users/richman/Documents/reverse/codes/trace-ui && cargo build 2>&1 | tail -10`

Expected: Successful compilation.

- [ ] **Step 6: Commit**

```bash
git add src-web/src/components/TabPanel.tsx src-web/src/FloatingPanel.tsx src-web/src/App.tsx
git commit -m "feat: wire up Strings tab in TabPanel, FloatingPanel, and App"
```

---

### Task 7: End-to-end verification

- [ ] **Step 1: Run all Rust tests**

Run: `cargo test 2>&1 | tail -20`

Expected: All tests pass, including the new string extraction tests.

- [ ] **Step 2: Run full Tauri dev build**

Run: `cd /Users/richman/Documents/reverse/codes/trace-ui && cargo tauri dev 2>&1 &`

Manual verification:
1. Open a trace file
2. Wait for Phase2 indexing to complete
3. Click "Strings" tab in bottom panel
4. Verify strings are listed with Seq, Address, Content, Encoding, Length, XRefs columns
5. Test search filtering
6. Test min_len slider
7. Click a string row → verify TraceTable jumps to that seq
8. Right-click → Copy String, Copy Address, Show XRefs
9. Drag "Strings" tab to float it as a window

- [ ] **Step 3: Final commit**

```bash
git add -A
git commit -m "feat: Strings View — IDA-style string extraction from trace memory operations"
```
