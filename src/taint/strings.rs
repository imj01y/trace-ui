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
const MIN_CACHE_LEN: u32 = 2;

pub(crate) struct StringBuilder {
    byte_image: PagedMemory,
    byte_owner: FxHashMap<u64, u32>,
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
                for j in 0..old.byte_len as u64 {
                    self.byte_owner.remove(&(old.addr + j));
                }
            }
        }

        // 4. 局部扫描
        let scan_start = self.scan_backward(addr);
        let scan_end = self.scan_forward(addr + size as u64 - 1);

        // 5. 提取字符串
        self.extract_strings_in_range(scan_start, scan_end, seq);
    }

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

    fn extract_strings_in_range(&mut self, start: u64, end: u64, seq: u32) {
        let mut pos = start;
        while pos <= end {
            match self.byte_image.get_byte(pos) {
                Some(b) if is_printable_or_utf8(b) => {}
                _ => { pos += 1; continue; }
            }

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
                    let ascii_bytes: Vec<u8> = bytes.iter()
                        .copied()
                        .take_while(|&b| b >= 0x20 && b <= 0x7E)
                        .collect();
                    if ascii_bytes.len() < MIN_CACHE_LEN as usize {
                        continue;
                    }
                    let s = String::from_utf8(ascii_bytes.clone()).unwrap();
                    pos = str_start + ascii_bytes.len() as u64;
                    (s, StringEncoding::Ascii)
                }
            };

            let byte_len = content.len() as u32;

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
        self.results.sort_by_key(|r| r.seq);
        StringIndex { strings: self.results }
    }

    pub fn fill_xref_counts(index: &mut StringIndex, mem_idx: &crate::taint::mem_access::MemAccessIndex) {
        use crate::taint::mem_access::MemRw;
        use rustc_hash::FxHashMap;

        // 预计算每个地址的 Read 次数（一次遍历所有记录，O(N)）
        // 避免对每个字符串的每个字节重复遍历热门地址的数百万条记录
        let mut read_counts: FxHashMap<u64, u32> = FxHashMap::default();
        for (addr, records) in mem_idx.iter_all() {
            if records.rw == MemRw::Read {
                *read_counts.entry(addr).or_insert(0) += 1;
            }
        }

        // 查表：O(1) per byte
        for record in &mut index.strings {
            let mut count = 0u32;
            for offset in 0..record.byte_len as u64 {
                count += read_counts.get(&(record.addr + offset)).copied().unwrap_or(0);
            }
            record.xref_count = count;
        }
    }
}

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
        mem.set_byte(0xFFF, 0x41);
        mem.set_byte(0x1000, 0x42);
        assert_eq!(mem.get_byte(0xFFF), Some(0x41));
        assert_eq!(mem.get_byte(0x1000), Some(0x42));
    }

    #[test]
    fn test_is_printable_or_utf8() {
        assert!(is_printable_or_utf8(b'A'));
        assert!(is_printable_or_utf8(b' '));
        assert!(is_printable_or_utf8(b'~'));
        assert!(is_printable_or_utf8(0xC0));
        assert!(!is_printable_or_utf8(0x00));
        assert!(!is_printable_or_utf8(0x0A));
        assert!(!is_printable_or_utf8(0x19));
        assert!(!is_printable_or_utf8(0xF5));
    }

    #[test]
    fn test_simple_string_extraction() {
        let mut sb = StringBuilder::new();
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
        sb.process_write(0x1000, 0x44434241, 4, 100);
        sb.process_write(0x1000, 0x5A595857, 4, 200);
        let index = sb.finish();
        assert_eq!(index.strings.len(), 2);
        assert_eq!(index.strings[0].content, "ABCD");
        assert_eq!(index.strings[0].seq, 100);
        assert_eq!(index.strings[1].content, "WXYZ");
        assert_eq!(index.strings[1].seq, 200);
    }

    #[test]
    fn test_string_destroyed_by_null() {
        let mut sb = StringBuilder::new();
        sb.process_write(0x1000, 0x44434241, 4, 100);
        sb.process_write(0x1002, 0x00, 1, 200);
        let index = sb.finish();
        let full = index.strings.iter().find(|s| s.content == "ABCD");
        assert!(full.is_some(), "Original 'ABCD' should be recorded as snapshot");
    }

    #[test]
    fn test_too_short_string_ignored() {
        let mut sb = StringBuilder::new();
        sb.process_write(0x1000, 0x41, 1, 100);
        let index = sb.finish();
        assert_eq!(index.strings.len(), 0);
    }

    #[test]
    fn test_incremental_string_building() {
        let mut sb = StringBuilder::new();
        sb.process_write(0x1000, 0x41, 1, 100);
        sb.process_write(0x1001, 0x42, 1, 101);
        sb.process_write(0x1002, 0x43, 1, 102);
        let index = sb.finish();
        let abc = index.strings.iter().find(|s| s.content == "ABC");
        assert!(abc.is_some(), "Final 'ABC' should exist");
    }
}
