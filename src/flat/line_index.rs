use memchr::memchr;

const BLOCK_SIZE: u32 = 256;

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct LineIndexArchive {
    pub sampled_offsets: Vec<u64>,
    pub total: u32,
}

impl LineIndexArchive {
    pub fn view(&self) -> LineIndexView<'_> {
        LineIndexView {
            sampled_offsets: &self.sampled_offsets,
            total: self.total,
        }
    }
}

impl ArchivedLineIndexArchive {
    pub fn view(&self) -> LineIndexView<'_> {
        let total: u32 = self.total.into();
        // SAFETY: On little-endian platforms, u64_le and u64 have identical bit layout.
        let sampled_offsets: &[u64] = unsafe {
            core::slice::from_raw_parts(
                self.sampled_offsets.as_ptr() as *const u64,
                self.sampled_offsets.len(),
            )
        };
        LineIndexView {
            sampled_offsets,
            total,
        }
    }
}

pub struct LineIndexView<'a> {
    sampled_offsets: &'a [u64],
    total: u32,
}

impl<'a> LineIndexView<'a> {
    /// Return the total number of lines.
    pub fn total_lines(&self) -> u32 {
        self.total
    }

    /// Return the byte offset of the given line in `data`, or None if out of range.
    pub fn line_byte_offset(&self, data: &[u8], seq: u32) -> Option<u64> {
        if seq >= self.total {
            return None;
        }
        let block = (seq / BLOCK_SIZE) as usize;
        let offset_in_block = (seq % BLOCK_SIZE) as usize;
        let mut pos = self.sampled_offsets[block] as usize;
        for _ in 0..offset_in_block {
            match memchr(b'\n', &data[pos..]) {
                Some(rel) => pos = pos + rel + 1,
                None => return None,
            }
        }
        Some(pos as u64)
    }

    /// Return the raw bytes for the given line in `data` (newline stripped), or None.
    pub fn get_line<'d>(&self, data: &'d [u8], seq: u32) -> Option<&'d [u8]> {
        if seq >= self.total {
            return None;
        }
        let block = (seq / BLOCK_SIZE) as usize;
        let offset_in_block = (seq % BLOCK_SIZE) as usize;

        let mut pos = self.sampled_offsets[block] as usize;

        // Scan forward offset_in_block newlines from the sampled position.
        for _ in 0..offset_in_block {
            match memchr(b'\n', &data[pos..]) {
                Some(rel) => pos = pos + rel + 1,
                None => return None,
            }
        }

        // pos is now the start of the target line; find line end.
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
    use crate::line_index::LineIndex;

    /// Build a LineIndexArchive from an existing LineIndex (for testing cross-compatibility).
    fn from_line_index(idx: &LineIndex) -> LineIndexArchive {
        // Access private fields via the public interface: re-build from data.
        // Since we can't access private fields directly, build independently.
        // Use the same algorithm as LineIndex::build.
        LineIndexArchive {
            sampled_offsets: extract_sampled_offsets(idx),
            total: idx.total_lines(),
        }
    }

    /// Extract sampled_offsets from LineIndex by probing get_line offsets.
    /// We don't have direct field access, so we rebuild from scratch using the same data.
    fn build_archive(data: &[u8]) -> LineIndexArchive {
        use memchr::memchr_iter;
        let estimated_blocks = data.len() / 120 / BLOCK_SIZE as usize + 1;
        let mut sampled_offsets = Vec::with_capacity(estimated_blocks);
        sampled_offsets.push(0u64);

        let data_len = data.len();
        let mut line_count: u32 = 1;

        for pos in memchr_iter(b'\n', data) {
            if (pos + 1) < data_len {
                if line_count % BLOCK_SIZE == 0 {
                    sampled_offsets.push((pos + 1) as u64);
                }
                line_count += 1;
            }
        }

        LineIndexArchive {
            sampled_offsets,
            total: line_count,
        }
    }

    // Placeholder to satisfy the from_line_index function signature (unused directly).
    fn extract_sampled_offsets(_idx: &LineIndex) -> Vec<u64> {
        vec![] // not used directly; we use build_archive instead
    }

    #[test]
    fn test_basic() {
        let data = b"line0\nline1\nline2\n";
        let arch = build_archive(data);
        let view = arch.view();
        assert_eq!(view.total_lines(), 3);
        assert_eq!(view.get_line(data, 0), Some(b"line0".as_slice()));
        assert_eq!(view.get_line(data, 1), Some(b"line1".as_slice()));
        assert_eq!(view.get_line(data, 2), Some(b"line2".as_slice()));
        assert_eq!(view.get_line(data, 3), None);
    }

    #[test]
    fn test_no_trailing_newline() {
        let data = b"line0\nline1";
        let arch = build_archive(data);
        let view = arch.view();
        assert_eq!(view.total_lines(), 2);
        assert_eq!(view.get_line(data, 1), Some(b"line1".as_slice()));
    }

    #[test]
    fn test_windows_line_endings() {
        let data = b"line0\r\nline1\r\n";
        let arch = build_archive(data);
        let view = arch.view();
        assert_eq!(view.total_lines(), 2);
        assert_eq!(view.get_line(data, 0), Some(b"line0".as_slice()));
        assert_eq!(view.get_line(data, 1), Some(b"line1".as_slice()));
    }

    #[test]
    fn test_out_of_range() {
        let data = b"only one line";
        let arch = build_archive(data);
        let view = arch.view();
        assert_eq!(view.total_lines(), 1);
        assert_eq!(view.get_line(data, 0), Some(b"only one line".as_slice()));
        assert_eq!(view.get_line(data, 1), None);
    }

    #[test]
    fn test_line_byte_offset() {
        let data = b"abc\ndef\nghi\n";
        let arch = build_archive(data);
        let view = arch.view();
        assert_eq!(view.line_byte_offset(data, 0), Some(0));
        assert_eq!(view.line_byte_offset(data, 1), Some(4));
        assert_eq!(view.line_byte_offset(data, 2), Some(8));
        assert_eq!(view.line_byte_offset(data, 3), None);
    }

    #[test]
    fn test_sampled_boundary() {
        let mut content = String::new();
        for i in 0..300 {
            content.push_str(&format!("line{}\n", i));
        }
        let data = content.as_bytes();
        let arch = build_archive(data);
        let view = arch.view();
        assert_eq!(view.total_lines(), 300);
        assert_eq!(view.get_line(data, 0), Some(b"line0".as_slice()));
        assert_eq!(view.get_line(data, 255), Some(b"line255".as_slice()));
        assert_eq!(view.get_line(data, 256), Some(b"line256".as_slice()));
        assert_eq!(view.get_line(data, 299), Some(b"line299".as_slice()));
        assert_eq!(view.get_line(data, 300), None);
    }

    #[test]
    fn test_total_lines() {
        let arch = LineIndexArchive {
            sampled_offsets: vec![0],
            total: 42,
        };
        assert_eq!(arch.view().total_lines(), 42);
    }
}
