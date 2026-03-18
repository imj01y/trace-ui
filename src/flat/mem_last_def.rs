#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct FlatMemLastDef {
    pub addrs: Vec<u64>,  // sorted
    pub lines: Vec<u32>,
    pub values: Vec<u64>,
}

impl FlatMemLastDef {
    pub fn view(&self) -> MemLastDefView<'_> {
        MemLastDefView {
            addrs: &self.addrs,
            lines: &self.lines,
            values: &self.values,
        }
    }
}

impl ArchivedFlatMemLastDef {
    pub fn view(&self) -> MemLastDefView<'_> {
        // SAFETY: On little-endian platforms, u64_le == u64 and u32_le == u32 in bit layout.
        let addrs: &[u64] = unsafe {
            core::slice::from_raw_parts(self.addrs.as_ptr() as *const u64, self.addrs.len())
        };
        let lines: &[u32] = unsafe {
            core::slice::from_raw_parts(self.lines.as_ptr() as *const u32, self.lines.len())
        };
        let values: &[u64] = unsafe {
            core::slice::from_raw_parts(self.values.as_ptr() as *const u64, self.values.len())
        };
        MemLastDefView {
            addrs,
            lines,
            values,
        }
    }
}

pub struct MemLastDefView<'a> {
    addrs: &'a [u64],
    lines: &'a [u32],
    values: &'a [u64],
}

impl<'a> MemLastDefView<'a> {
    /// Binary search by address; returns (line, value) if found.
    pub fn get(&self, addr: &u64) -> Option<(u32, u64)> {
        let idx = self.addrs.binary_search(addr).ok()?;
        Some((self.lines[idx], self.values[idx]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> FlatMemLastDef {
        FlatMemLastDef {
            addrs: vec![0x1000, 0x2000, 0x3000],
            lines: vec![5, 10, 15],
            values: vec![0xAA, 0xBB, 0xCC],
        }
    }

    #[test]
    fn test_get_hit() {
        let flat = sample();
        let view = flat.view();
        assert_eq!(view.get(&0x1000), Some((5, 0xAA)));
        assert_eq!(view.get(&0x2000), Some((10, 0xBB)));
        assert_eq!(view.get(&0x3000), Some((15, 0xCC)));
    }

    #[test]
    fn test_get_miss() {
        let flat = sample();
        let view = flat.view();
        assert_eq!(view.get(&0x9999), None);
        assert_eq!(view.get(&0x0), None);
    }

    #[test]
    fn test_empty() {
        let flat = FlatMemLastDef {
            addrs: vec![],
            lines: vec![],
            values: vec![],
        };
        assert_eq!(flat.view().get(&0x1000), None);
    }
}
