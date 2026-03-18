use memchr::{memchr, memchr_iter};

const BLOCK_SIZE: u32 = 256;

/// 采样行偏移索引：每 256 行记录一个字节偏移，查找时从最近采样点向前扫描。
/// 内存占用从 O(n) 降至 O(n/256)。
#[derive(serde::Serialize, serde::Deserialize)]
pub struct LineIndex {
    /// sampled_offsets[i] = 第 i * BLOCK_SIZE 行的起始字节偏移
    sampled_offsets: Vec<u64>,
    /// 总行数
    total: u32,
}

/// 增量式行索引构建器。
///
/// 供 scan_unified 在逐行遍历时调用 `add_line(byte_offset)`，
/// 最终 `finish()` 生成 LineIndex。
pub struct LineIndexBuilder {
    sampled_offsets: Vec<u64>,
    line_count: u32,
}

impl LineIndexBuilder {
    #[cfg(test)]
    pub fn new() -> Self {
        Self {
            sampled_offsets: Vec::new(),
            line_count: 0,
        }
    }

    /// 记录一行的起始字节偏移。必须按行顺序调用。
    #[inline]
    pub fn add_line(&mut self, byte_offset: u64) {
        if self.line_count % BLOCK_SIZE == 0 {
            self.sampled_offsets.push(byte_offset);
        }
        self.line_count += 1;
    }

    /// 用预估行数预分配内部存储。
    pub fn with_capacity_hint(estimated_lines: usize) -> Self {
        Self {
            sampled_offsets: Vec::with_capacity(estimated_lines / BLOCK_SIZE as usize + 1),
            line_count: 0,
        }
    }

    /// 创建从指定行号开始的构建器（用于并行分块扫描）。
    ///
    /// `start_line` 是全局行号，确保 BLOCK_SIZE (256) 对齐在全局一致。
    /// 仅当 `start_line % BLOCK_SIZE == 0` 时第一次 `add_line` 会记录采样点。
    pub fn with_start_line(start_line: u32, capacity_hint: usize) -> Self {
        Self {
            sampled_offsets: Vec::with_capacity(capacity_hint / BLOCK_SIZE as usize + 1),
            line_count: start_line,
        }
    }

    /// 完成构建，返回 LineIndex。
    pub fn finish(self) -> LineIndex {
        LineIndex {
            sampled_offsets: self.sampled_offsets,
            total: self.line_count,
        }
    }
}

impl LineIndex {
    /// 从内存映射的字节数据构建行偏移索引。
    #[allow(dead_code)]
    pub fn build(data: &[u8]) -> Self {
        Self::build_with_progress(data, None)
    }

    /// 带进度回调的构建。callback 参数: (已处理字节, 总字节)
    pub fn build_with_progress(data: &[u8], progress: Option<&dyn Fn(usize, usize)>) -> Self {
        let estimated_blocks = data.len() / 120 / BLOCK_SIZE as usize + 1;
        let mut sampled_offsets = Vec::with_capacity(estimated_blocks);
        // 第 0 行偏移总是 0
        sampled_offsets.push(0u64);

        let data_len = data.len();
        let report_interval = data_len / 100 + 1;
        let mut last_report = 0usize;
        let mut line_count: u32 = 1; // 从 1 开始，因为第 0 行已经存在

        for pos in memchr_iter(b'\n', data) {
            if (pos + 1) < data_len {
                // 这是一个新行的起始
                if line_count % BLOCK_SIZE == 0 {
                    sampled_offsets.push((pos + 1) as u64);
                }
                line_count += 1;
            }
            if let Some(cb) = &progress {
                if pos - last_report >= report_interval {
                    cb(pos, data_len);
                    last_report = pos;
                }
            }
        }

        Self {
            sampled_offsets,
            total: line_count,
        }
    }

    pub fn total_lines(&self) -> u32 {
        self.total
    }

    /// Merge multiple LineIndex instances (for parallel scanning).
    /// Each chunk's LineIndexBuilder starts counting from start_line (global offset),
    /// so each chunk's `total` = start_line + chunk_lines = global ending line number.
    /// The last chunk's `total` is therefore the global total line count.
    pub(crate) fn merge(indices: Vec<LineIndex>) -> LineIndex {
        let mut all_offsets = Vec::new();
        // Last chunk's total IS the global total (start_of_last + lines_in_last)
        let total = indices.last().map(|idx| idx.total).unwrap_or(0);
        for idx in indices {
            all_offsets.extend(idx.sampled_offsets);
        }
        LineIndex {
            sampled_offsets: all_offsets,
            total,
        }
    }

    /// 获取指定行的原始字节切片
    pub fn get_line<'a>(&self, data: &'a [u8], seq: u32) -> Option<&'a [u8]> {
        if seq >= self.total {
            return None;
        }
        let block = (seq / BLOCK_SIZE) as usize;
        let offset_in_block = (seq % BLOCK_SIZE) as usize;

        let mut pos = self.sampled_offsets[block] as usize;

        // 从采样点向前扫描 offset_in_block 个换行符
        for _ in 0..offset_in_block {
            match memchr(b'\n', &data[pos..]) {
                Some(rel) => pos = pos + rel + 1,
                None => return None,
            }
        }

        // pos 现在是目标行的起始位置，找行尾
        let start = pos;
        let end = match memchr(b'\n', &data[start..]) {
            Some(rel) => start + rel + 1,
            None => data.len(),
        };

        let line = &data[start..end];
        let line = line.strip_suffix(b"\n").unwrap_or(line);
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        Some(line)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_indexing() {
        let data = b"line0\nline1\nline2\n";
        let idx = LineIndex::build(data);
        assert_eq!(idx.total_lines(), 3);
        assert_eq!(idx.get_line(data, 0), Some(b"line0".as_slice()));
        assert_eq!(idx.get_line(data, 1), Some(b"line1".as_slice()));
        assert_eq!(idx.get_line(data, 2), Some(b"line2".as_slice()));
        assert_eq!(idx.get_line(data, 3), None);
    }

    #[test]
    fn test_no_trailing_newline() {
        let data = b"line0\nline1";
        let idx = LineIndex::build(data);
        assert_eq!(idx.total_lines(), 2);
        assert_eq!(idx.get_line(data, 1), Some(b"line1".as_slice()));
    }

    #[test]
    fn test_empty_data() {
        let data = b"";
        let idx = LineIndex::build(data);
        // 空数据也有 1 行（偏移 0 开始，但内容为空）
        assert_eq!(idx.total_lines(), 1);
        assert_eq!(idx.get_line(data, 0), Some(b"".as_slice()));
    }

    #[test]
    fn test_single_line_no_newline() {
        let data = b"hello world";
        let idx = LineIndex::build(data);
        assert_eq!(idx.total_lines(), 1);
        assert_eq!(idx.get_line(data, 0), Some(b"hello world".as_slice()));
    }

    #[test]
    fn test_windows_line_endings() {
        let data = b"line0\r\nline1\r\n";
        let idx = LineIndex::build(data);
        assert_eq!(idx.total_lines(), 2);
        assert_eq!(idx.get_line(data, 0), Some(b"line0".as_slice()));
        assert_eq!(idx.get_line(data, 1), Some(b"line1".as_slice()));
    }

    #[test]
    fn test_sampled_boundary() {
        // 300 行，跨越 256 行的块边界
        let mut content = String::new();
        for i in 0..300 {
            content.push_str(&format!("line{}\n", i));
        }
        let data = content.as_bytes();
        let idx = LineIndex::build(data);
        assert_eq!(idx.total_lines(), 300);

        // 验证第一个块的首行
        assert_eq!(idx.get_line(data, 0), Some(b"line0".as_slice()));
        // 块边界前一行 (line 255)
        assert_eq!(idx.get_line(data, 255), Some(b"line255".as_slice()));
        // 第二个块的首行 (line 256)
        assert_eq!(idx.get_line(data, 256), Some(b"line256".as_slice()));
        // 第二个块中的行
        assert_eq!(idx.get_line(data, 257), Some(b"line257".as_slice()));
        // 最后一行
        assert_eq!(idx.get_line(data, 299), Some(b"line299".as_slice()));
        // 越界
        assert_eq!(idx.get_line(data, 300), None);

        // 验证 sampled_offsets 数量：块 0 和块 1，共 2 个采样点
        assert_eq!(idx.sampled_offsets.len(), 2);
    }

    #[test]
    fn test_sampled_memory_reduction() {
        // 10000 行，验证边界正确性和内存缩减
        let mut content = String::new();
        for i in 0..10000 {
            content.push_str(&format!("L{:05}\n", i));
        }
        let data = content.as_bytes();
        let idx = LineIndex::build(data);
        assert_eq!(idx.total_lines(), 10000);

        // 验证采样点数量：ceil(10000/256) = 40 个块，但只有完整块起始被记录
        // 块数 = 10000/256 = 39 个完整块 + 1 个不完整块 = 40 个采样点
        let expected_samples = (10000 + BLOCK_SIZE - 1) / BLOCK_SIZE;
        assert_eq!(idx.sampled_offsets.len(), expected_samples as usize);

        // 内存缩减：采样索引只存 expected_samples 个 u64，而非 10000 个
        let sampled_mem = idx.sampled_offsets.len() * std::mem::size_of::<u64>();
        let full_mem = 10000 * std::mem::size_of::<u64>();
        assert!(sampled_mem < full_mem / 100, "采样索引内存应远小于全量索引");

        // 验证每个块边界处的行
        for block in 0..expected_samples {
            let line_num = block * BLOCK_SIZE;
            if line_num < 10000 {
                let expected = format!("L{:05}", line_num);
                assert_eq!(
                    idx.get_line(data, line_num),
                    Some(expected.as_bytes()),
                    "块边界行 {} 不正确",
                    line_num
                );
            }
        }

        // 验证一些块内的行
        assert_eq!(idx.get_line(data, 0), Some(b"L00000".as_slice()));
        assert_eq!(idx.get_line(data, 128), Some(b"L00128".as_slice()));
        assert_eq!(idx.get_line(data, 255), Some(b"L00255".as_slice()));
        assert_eq!(idx.get_line(data, 256), Some(b"L00256".as_slice()));
        assert_eq!(idx.get_line(data, 9999), Some(b"L09999".as_slice()));
        assert_eq!(idx.get_line(data, 10000), None);
    }

    #[test]
    fn test_builder_matches_build() {
        let mut content = String::new();
        for i in 0..600 {
            content.push_str(&format!("line{}\n", i));
        }
        let data = content.as_bytes();

        // 用现有 build 方法构建（基准）
        let expected = LineIndex::build(data);

        // 用 builder 增量构建
        let mut builder = LineIndexBuilder::new();
        let mut pos = 0usize;
        while pos < data.len() {
            let line_end = memchr(b'\n', &data[pos..])
                .map(|p| pos + p)
                .unwrap_or(data.len());
            builder.add_line(pos as u64);
            pos = if line_end < data.len() { line_end + 1 } else { data.len() };
        }
        let built = builder.finish();

        assert_eq!(built.total_lines(), expected.total_lines());
        for seq in 0..expected.total_lines() {
            assert_eq!(
                built.get_line(data, seq),
                expected.get_line(data, seq),
                "mismatch at seq {}",
                seq
            );
        }
    }

    #[test]
    fn test_builder_empty() {
        let builder = LineIndexBuilder::new();
        let idx = builder.finish();
        assert_eq!(idx.total_lines(), 0);
    }

    #[test]
    fn test_builder_single_line() {
        let mut builder = LineIndexBuilder::new();
        builder.add_line(0);
        let idx = builder.finish();
        assert_eq!(idx.total_lines(), 1);
    }
}
