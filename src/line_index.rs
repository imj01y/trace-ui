use memchr::memchr_iter;

/// 行偏移索引：记录每行在文件中的起始字节偏移。
pub struct LineIndex {
    offsets: Vec<u64>,
}

impl LineIndex {
    /// 从内存映射的字节数据构建行偏移索引。
    #[allow(dead_code)]
    pub fn build(data: &[u8]) -> Self {
        Self::build_with_progress(data, None)
    }

    /// 带进度回调的构建。callback 参数: (已处理字节, 总字节)
    pub fn build_with_progress(data: &[u8], progress: Option<&dyn Fn(usize, usize)>) -> Self {
        let estimated = data.len() / 120;
        let mut offsets = Vec::with_capacity(estimated);
        offsets.push(0);
        let total = data.len();
        let report_interval = total / 100 + 1; // 大约每 1% 报告一次
        let mut last_report = 0usize;
        for pos in memchr_iter(b'\n', data) {
            let next_line_start = (pos + 1) as u64;
            if (pos + 1) < data.len() {
                offsets.push(next_line_start);
            }
            if let Some(cb) = &progress {
                if pos - last_report >= report_interval {
                    cb(pos, total);
                    last_report = pos;
                }
            }
        }
        Self { offsets }
    }

    pub fn total_lines(&self) -> u32 {
        self.offsets.len() as u32
    }

    /// 获取指定行的原始字节切片
    pub fn get_line<'a>(&self, data: &'a [u8], seq: u32) -> Option<&'a [u8]> {
        let idx = seq as usize;
        if idx >= self.offsets.len() {
            return None;
        }
        let start = self.offsets[idx] as usize;
        let end = if idx + 1 < self.offsets.len() {
            self.offsets[idx + 1] as usize
        } else {
            data.len()
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
}
