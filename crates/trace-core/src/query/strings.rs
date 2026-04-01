use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};

// ── 持久化数据结构 ──

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum StringEncoding {
    Ascii,
    Utf8,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum StringRw {
    Read,
    Write,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct StringRecord {
    pub addr: u64,
    pub content: String,
    pub encoding: StringEncoding,
    pub byte_len: u32,
    pub seq: u32,
    pub xref_count: u32,
    pub rw: StringRw,
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
    valid: [u64; PAGE_SIZE / 64], // bitset: 512 bytes vs 4096 bytes
    owner: [u32; PAGE_SIZE],      // string ID per byte, 0 = no owner
}

impl Page {
    fn new() -> Self {
        Page {
            data: [0; PAGE_SIZE],
            valid: [0u64; PAGE_SIZE / 64],
            owner: [0u32; PAGE_SIZE],
        }
    }

    #[inline]
    fn is_valid(&self, offset: usize) -> bool {
        let word = offset / 64;
        let bit = offset % 64;
        (self.valid[word] >> bit) & 1 != 0
    }

    #[inline]
    fn set_valid(&mut self, offset: usize) {
        let word = offset / 64;
        let bit = offset % 64;
        self.valid[word] |= 1u64 << bit;
    }

    #[inline]
    fn get_owner(&self, offset: usize) -> u32 {
        self.owner[offset]
    }

    #[inline]
    fn set_owner(&mut self, offset: usize, id: u32) {
        self.owner[offset] = id;
    }

    #[inline]
    fn clear_owner(&mut self, offset: usize) {
        self.owner[offset] = 0;
    }
}

pub struct PagedMemory {
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
        page.set_valid(offset);
    }

    pub fn get_byte(&self, addr: u64) -> Option<u8> {
        let page_addr = addr & PAGE_MASK;
        let offset = (addr & !PAGE_MASK) as usize;
        self.pages.get(&page_addr).and_then(|page| {
            if page.is_valid(offset) { Some(page.data[offset]) } else { None }
        })
    }

    pub fn get_owner(&self, addr: u64) -> u32 {
        let page_addr = addr & PAGE_MASK;
        let offset = (addr & !PAGE_MASK) as usize;
        self.pages.get(&page_addr)
            .map(|page| page.get_owner(offset))
            .unwrap_or(0)
    }

    pub fn set_owner(&mut self, addr: u64, id: u32) {
        let page_addr = addr & PAGE_MASK;
        let offset = (addr & !PAGE_MASK) as usize;
        if let Some(page) = self.pages.get_mut(&page_addr) {
            page.set_owner(offset, id);
        }
    }

    pub fn clear_owner(&mut self, addr: u64) {
        let page_addr = addr & PAGE_MASK;
        let offset = (addr & !PAGE_MASK) as usize;
        if let Some(page) = self.pages.get_mut(&page_addr) {
            page.clear_owner(offset);
        }
    }

    /// Get page reference for batch byte access (used by scan functions)
    #[inline]
    fn get_page(&self, page_addr: u64) -> Option<&Page> {
        self.pages.get(&page_addr).map(|p| &**p)
    }
}

// ── 活跃字符串 ──

struct ActiveString {
    addr: u64,
    byte_len: u32,
    content: String,
    encoding: StringEncoding,
    seq: u32,
    rw: StringRw,
}

// ── StringBuilder ──

const MAX_SCAN_LEN: u64 = 1024;
const MIN_CACHE_LEN: u32 = 2;

pub struct StringBuilder {
    byte_image: PagedMemory,
    active: FxHashMap<u32, ActiveString>,
    results: Vec<StringRecord>,
    next_id: u32,
}

impl StringBuilder {
    pub fn new() -> Self {
        Self {
            byte_image: PagedMemory::new(),
            active: FxHashMap::default(),
            results: Vec::new(),
            next_id: 1, // start from 1, 0 = no owner
        }
    }

    #[cfg(test)]
    fn active_count(&self) -> usize {
        self.active.len()
    }

    /// 处理一条内存访问操作（READ 或 WRITE）
    pub fn process_access(&mut self, addr: u64, data: u64, size: u8, seq: u32, rw: StringRw) {
        // Fast path: skip if all bytes unchanged (avoids duplicate snapshots from repeated READs)
        // Note: is_valid returns false for unset bytes, so unset != val correctly proceeds
        let mut all_same = true;
        {
            let pg_addr = addr & PAGE_MASK;
            let end_pg_addr = (addr + size as u64 - 1) & PAGE_MASK;

            if pg_addr == end_pg_addr {
                // Common case: all bytes on same page
                if let Some(pg) = self.byte_image.get_page(pg_addr) {
                    for i in 0..size as u64 {
                        let byte_val = ((data >> (i * 8)) & 0xFF) as u8;
                        let off = ((addr + i) & !PAGE_MASK) as usize;
                        if !pg.is_valid(off) || pg.data[off] != byte_val {
                            all_same = false;
                            break;
                        }
                    }
                } else {
                    all_same = false;
                }
            } else {
                // Rare: cross-page boundary (size<=8, only near page edge)
                for i in 0..size as u64 {
                    let byte_val = ((data >> (i * 8)) & 0xFF) as u8;
                    if self.byte_image.get_byte(addr + i) != Some(byte_val) {
                        all_same = false;
                        break;
                    }
                }
            }
        }
        if all_same { return; }

        // 1. 展开 data 为字节（小端序），更新 byte_image
        for i in 0..size as u64 {
            let byte_val = ((data >> (i * 8)) & 0xFF) as u8;
            self.byte_image.set_byte(addr + i, byte_val);
        }

        // 2. 收集受影响的活跃字符串 id（页级访问优化）
        let mut affected_ids: Vec<u32> = Vec::new();
        {
            let pg_addr = addr & PAGE_MASK;
            let end_pg_addr = (addr + size as u64 - 1) & PAGE_MASK;

            if pg_addr == end_pg_addr {
                if let Some(pg) = self.byte_image.get_page(pg_addr) {
                    for i in 0..size as u64 {
                        let off = ((addr + i) & !PAGE_MASK) as usize;
                        let owner_id = pg.get_owner(off);
                        if owner_id != 0 && !affected_ids.contains(&owner_id) {
                            affected_ids.push(owner_id);
                        }
                    }
                }
            } else {
                for i in 0..size as u64 {
                    let owner_id = self.byte_image.get_owner(addr + i);
                    if owner_id != 0 && !affected_ids.contains(&owner_id) {
                        affected_ids.push(owner_id);
                    }
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
                        rw: old.rw,
                    });
                }
                for j in 0..old.byte_len as u64 {
                    self.byte_image.clear_owner(old.addr + j);
                }
            }
        }

        // 4. 局部扫描
        let scan_start = self.scan_backward(addr);
        let scan_end = self.scan_forward(addr + size as u64 - 1);

        // 5. 提取字符串
        self.extract_strings_in_range(scan_start, scan_end, seq, rw);
    }

    fn scan_backward(&self, addr: u64) -> u64 {
        let limit = addr.saturating_sub(MAX_SCAN_LEN);
        let mut cur = addr;
        let mut pg_addr = cur & PAGE_MASK;
        let mut pg = self.byte_image.get_page(pg_addr);

        while cur > limit {
            let prev = cur - 1;
            let prev_pg_addr = prev & PAGE_MASK;
            if prev_pg_addr != pg_addr {
                pg_addr = prev_pg_addr;
                pg = self.byte_image.get_page(pg_addr);
            }
            let off = (prev & !PAGE_MASK) as usize;
            match pg {
                Some(p) if p.is_valid(off) && is_printable_or_utf8(p.data[off]) => cur = prev,
                _ => break,
            }
        }
        cur
    }

    fn scan_forward(&self, addr: u64) -> u64 {
        let limit = addr.saturating_add(MAX_SCAN_LEN);
        let mut cur = addr;
        let mut pg_addr = cur & PAGE_MASK;
        let mut pg = self.byte_image.get_page(pg_addr);

        while cur < limit {
            let next = cur + 1;
            let next_pg_addr = next & PAGE_MASK;
            if next_pg_addr != pg_addr {
                pg_addr = next_pg_addr;
                pg = self.byte_image.get_page(pg_addr);
            }
            let off = (next & !PAGE_MASK) as usize;
            match pg {
                Some(p) if p.is_valid(off) && is_printable_or_utf8(p.data[off]) => cur = next,
                _ => break,
            }
        }
        cur
    }

    fn extract_strings_in_range(&mut self, start: u64, end: u64, seq: u32, rw: StringRw) {
        let mut pos = start;
        while pos <= end {
            // Check current byte using page-level access
            let pg_addr = pos & PAGE_MASK;
            let off = (pos & !PAGE_MASK) as usize;
            let is_printable = self.byte_image.get_page(pg_addr)
                .map(|p| p.is_valid(off) && is_printable_or_utf8(p.data[off]))
                .unwrap_or(false);
            if !is_printable {
                pos += 1;
                continue;
            }

            let str_start = pos;
            let mut bytes: Vec<u8> = Vec::new();

            // Collect consecutive printable bytes with page-level access
            let mut cur_pg_addr = pg_addr;
            let mut cur_pg = self.byte_image.get_page(cur_pg_addr);
            while pos <= end {
                let new_pg_addr = pos & PAGE_MASK;
                if new_pg_addr != cur_pg_addr {
                    cur_pg_addr = new_pg_addr;
                    cur_pg = self.byte_image.get_page(cur_pg_addr);
                }
                let o = (pos & !PAGE_MASK) as usize;
                match cur_pg {
                    Some(p) if p.is_valid(o) && is_printable_or_utf8(p.data[o]) => {
                        bytes.push(p.data[o]);
                        pos += 1;
                    }
                    _ => break,
                }
            }

            if bytes.len() < MIN_CACHE_LEN as usize {
                continue;
            }

            // 如果该区域已被某个活跃字符串覆盖且内容相同，跳过
            let existing_id = self.byte_image.get_owner(str_start);
            if existing_id != 0 {
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
                let a = str_start + j;
                let old_id = self.byte_image.get_owner(a);
                self.byte_image.set_owner(a, id);
                if old_id != 0 && old_id != id {
                    if let Some(old) = self.active.remove(&old_id) {
                        // 清理被驱逐字符串在新字符串覆盖范围外的残留 owner 条目
                        for k in 0..old.byte_len as u64 {
                            let old_a = old.addr + k;
                            if old_a < str_start || old_a >= str_start + byte_len as u64 {
                                // 仅清理新字符串覆盖范围外的条目；
                                // 范围内的条目已被/将被当前循环覆写。
                                self.byte_image.clear_owner(old_a);
                            }
                        }
                        if old.byte_len >= MIN_CACHE_LEN {
                            self.results.push(StringRecord {
                                addr: old.addr,
                                content: old.content,
                                encoding: old.encoding,
                                byte_len: old.byte_len,
                                seq: old.seq,
                                xref_count: 0,
                                rw: old.rw,
                            });
                        }
                    }
                }
            }
            self.active.insert(id, ActiveString {
                addr: str_start,
                byte_len,
                content,
                encoding,
                seq,
                rw,
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
                    rw: s.rw,
                });
            }
        }
        self.results.sort_by_key(|r| r.seq);
        StringIndex { strings: self.results }
    }

    pub fn fill_xref_counts(index: &mut StringIndex, mem_idx: &crate::query::mem_access::MemAccessIndex) {
        use crate::query::mem_access::MemRw;
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

    pub fn fill_xref_counts_view(index: &mut StringIndex, mem_view: &crate::flat::mem_access::MemAccessView<'_>) {
        use rustc_hash::FxHashMap;

        let mut read_counts: FxHashMap<u64, u32> = FxHashMap::default();
        for (addr, rec) in mem_view.iter_all() {
            if rec.is_read() {
                *read_counts.entry(addr).or_insert(0) += 1;
            }
        }

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
        sb.process_access(0x1000, 0x6F6C6C6548, 5, 100, StringRw::Write);
        let index = sb.finish();
        assert_eq!(index.strings.len(), 1);
        assert_eq!(index.strings[0].content, "Hello");
        assert_eq!(index.strings[0].addr, 0x1000);
        assert_eq!(index.strings[0].encoding, StringEncoding::Ascii);
        assert_eq!(index.strings[0].seq, 100);
        assert_eq!(index.strings[0].rw, StringRw::Write);
    }

    #[test]
    fn test_string_overwrite_creates_snapshot() {
        let mut sb = StringBuilder::new();
        sb.process_access(0x1000, 0x44434241, 4, 100, StringRw::Write);
        sb.process_access(0x1000, 0x5A595857, 4, 200, StringRw::Write);
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
        sb.process_access(0x1000, 0x44434241, 4, 100, StringRw::Write);
        sb.process_access(0x1002, 0x00, 1, 200, StringRw::Write);
        let index = sb.finish();
        let full = index.strings.iter().find(|s| s.content == "ABCD");
        assert!(full.is_some(), "Original 'ABCD' should be recorded as snapshot");
    }

    #[test]
    fn test_too_short_string_ignored() {
        let mut sb = StringBuilder::new();
        sb.process_access(0x1000, 0x41, 1, 100, StringRw::Write);
        let index = sb.finish();
        assert_eq!(index.strings.len(), 0);
    }

    #[test]
    fn test_incremental_string_building() {
        let mut sb = StringBuilder::new();
        sb.process_access(0x1000, 0x41, 1, 100, StringRw::Write);
        sb.process_access(0x1001, 0x42, 1, 101, StringRw::Write);
        sb.process_access(0x1002, 0x43, 1, 102, StringRw::Write);
        let index = sb.finish();
        let abc = index.strings.iter().find(|s| s.content == "ABC");
        assert!(abc.is_some(), "Final 'ABC' should exist");
    }

    #[test]
    fn test_read_string_extraction() {
        let mut sb = StringBuilder::new();
        sb.process_access(0x1000, 0x6F6C6C6548, 5, 50, StringRw::Read);
        let index = sb.finish();
        assert_eq!(index.strings.len(), 1);
        assert_eq!(index.strings[0].content, "Hello");
        assert_eq!(index.strings[0].rw, StringRw::Read);
    }

    #[test]
    fn test_repeated_read_dedup() {
        let mut sb = StringBuilder::new();
        sb.process_access(0x1000, 0x44434241, 4, 50, StringRw::Read);
        sb.process_access(0x1000, 0x44434241, 4, 100, StringRw::Read);
        sb.process_access(0x1000, 0x44434241, 4, 200, StringRw::Read);
        let index = sb.finish();
        assert_eq!(index.strings.len(), 1);
        assert_eq!(index.strings[0].seq, 50);
        assert_eq!(index.strings[0].rw, StringRw::Read);
    }

    #[test]
    fn test_read_then_write_overwrite() {
        let mut sb = StringBuilder::new();
        sb.process_access(0x1000, 0x44434241, 4, 50, StringRw::Read);
        sb.process_access(0x1000, 0x5A595857, 4, 200, StringRw::Write);
        let index = sb.finish();
        assert_eq!(index.strings.len(), 2);
        assert_eq!(index.strings[0].content, "ABCD");
        assert_eq!(index.strings[0].rw, StringRw::Read);
        assert_eq!(index.strings[1].content, "WXYZ");
        assert_eq!(index.strings[1].rw, StringRw::Write);
    }

    #[test]
    fn test_pair_value2_extraction() {
        let mut sb = StringBuilder::new();
        sb.process_access(0x1000, 0x44434241, 4, 100, StringRw::Write);
        sb.process_access(0x1004, 0x48474645, 4, 100, StringRw::Write);
        let index = sb.finish();
        let full = index.strings.iter().find(|s| s.content == "ABCDEFGH");
        assert!(full.is_some(), "Should find concatenated 'ABCDEFGH'");
    }

    #[test]
    fn test_sequential_writes_no_orphan_leak() {
        let mut sb = StringBuilder::new();
        let mut max_active = 0usize;
        for i in 0u32..1000 {
            let addr = 0x1000 + i as u64 * 4;
            sb.process_access(addr, 0x41424344, 4, i, StringRw::Write);
            let ac = sb.active_count();
            if ac > max_active { max_active = ac; }
        }
        // active 中应始终只有少量活跃字符串，不应随写入次数线性增长
        assert!(max_active < 10,
            "active peaked at {} entries, expected < 10 (orphan leak?)", max_active);
    }

    #[test]
    fn test_evicted_string_is_snapshotted() {
        let mut sb = StringBuilder::new();
        sb.process_access(0x1000, 0x44434241, 4, 100, StringRw::Write);
        sb.process_access(0x1004, 0x48474645, 4, 200, StringRw::Write);
        let index = sb.finish();
        assert!(index.strings.iter().any(|s| s.content == "ABCD"),
            "Evicted 'ABCD' should be snapshotted");
        assert!(index.strings.iter().any(|s| s.content == "ABCDEFGH"),
            "Final 'ABCDEFGH' should exist");
    }

    #[test]
    fn test_paged_memory_bitset_valid() {
        let mut mem = PagedMemory::new();

        // 基本 set/get
        mem.set_byte(0x2000, 0xAA);
        assert_eq!(mem.get_byte(0x2000), Some(0xAA));
        assert_eq!(mem.get_byte(0x2001), None);

        // 覆盖写入
        mem.set_byte(0x2000, 0xBB);
        assert_eq!(mem.get_byte(0x2000), Some(0xBB));

        // 跨页边界
        mem.set_byte(0x2FFF, 0x11); // page 0x2000 最后一个字节
        mem.set_byte(0x3000, 0x22); // page 0x3000 第一个字节
        assert_eq!(mem.get_byte(0x2FFF), Some(0x11));
        assert_eq!(mem.get_byte(0x3000), Some(0x22));
        assert_eq!(mem.get_byte(0x2FFE), None);
        assert_eq!(mem.get_byte(0x3001), None);

        // 页内各 bit 位置（offset 0, 63, 64, 127, 4095）
        let base: u64 = 0x5000;
        for &off in &[0u64, 63, 64, 127, 4095] {
            mem.set_byte(base + off, off as u8);
        }
        for &off in &[0u64, 63, 64, 127, 4095] {
            assert_eq!(mem.get_byte(base + off), Some(off as u8),
                "offset {} should be valid", off);
        }
        // 未设置的偏移仍为 None
        assert_eq!(mem.get_byte(base + 1), None);
        assert_eq!(mem.get_byte(base + 128), None);
    }

    #[test]
    fn test_scan_long_string_cross_page() {
        let mut sb = StringBuilder::new();
        // Write ASCII chars across a 4KB page boundary (0x0F00 to 0x1100)
        for i in 0..0x200u64 {
            let addr = 0x0F00 + i;
            let val = 0x41 + (i % 26) as u8; // 'A'-'Z' cycling
            sb.process_access(addr, val as u64, 1, i as u32, StringRw::Write);
        }
        let index = sb.finish();
        let longest = index.strings.iter().max_by_key(|s| s.byte_len).unwrap();
        assert!(longest.byte_len >= 100, "longest string should be >= 100 bytes, got {}", longest.byte_len);
    }

    #[test]
    fn test_sequential_writes_active_bounded_at_scale() {
        let mut sb = StringBuilder::new();
        let mut max_active = 0usize;
        for i in 0u32..10_000 {
            let addr = 0x1000 + i as u64 * 4;
            sb.process_access(addr, 0x41424344, 4, i, StringRw::Write);
            if i % 1000 == 999 {
                let ac = sb.active_count();
                if ac > max_active { max_active = ac; }
            }
        }
        // 即使 10K 次写入，active 也应保持有界（不随写入次数线性增长）
        assert!(max_active < 10,
            "active peaked at {} after 10K writes, expected < 10 (orphan leak?)", max_active);
    }
}
