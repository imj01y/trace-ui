#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct FlatPairSplit {
    pub keys: Vec<u32>,        // sorted line numbers
    pub seg_offsets: Vec<u32>, // len = keys.len() * 3 + 1 (sentinel)
    pub data: Vec<u32>,
}

/// Helper: reinterpret an ArchivedVec<u32_le> as &[u32].
///
/// SAFETY: On little-endian platforms, u32_le and u32 have identical bit layout.
unsafe fn archived_u32_slice(v: &rkyv::vec::ArchivedVec<rkyv::rend::u32_le>) -> &[u32] {
    core::slice::from_raw_parts(v.as_ptr() as *const u32, v.len())
}

impl FlatPairSplit {
    pub fn view(&self) -> PairSplitView<'_> {
        PairSplitView {
            keys: &self.keys,
            seg_offsets: &self.seg_offsets,
            data: &self.data,
        }
    }
}

impl ArchivedFlatPairSplit {
    pub fn view(&self) -> PairSplitView<'_> {
        // SAFETY: little-endian only; u32_le == u32 in bit layout.
        unsafe {
            PairSplitView {
                keys: archived_u32_slice(&self.keys),
                seg_offsets: archived_u32_slice(&self.seg_offsets),
                data: archived_u32_slice(&self.data),
            }
        }
    }
}

pub struct PairSplitView<'a> {
    keys: &'a [u32],
    seg_offsets: &'a [u32],
    data: &'a [u32],
}

pub struct PairSplitEntry<'a> {
    pub shared: &'a [u32],
    pub half1_deps: &'a [u32],
    pub half2_deps: &'a [u32],
}

impl<'a> PairSplitView<'a> {
    /// Binary search keys, return entry with 3 slices if found.
    pub fn get(&self, key: &u32) -> Option<PairSplitEntry<'a>> {
        let idx = self.keys.binary_search(key).ok()?;
        // seg_offsets layout: [shared_start, half1_start, half2_start, sentinel] per entry
        // base = idx * 3
        let base = idx * 3;
        let shared_start = self.seg_offsets[base] as usize;
        let half1_start = self.seg_offsets[base + 1] as usize;
        let half2_start = self.seg_offsets[base + 2] as usize;
        let end = self.seg_offsets[base + 3] as usize;
        Some(PairSplitEntry {
            shared: &self.data[shared_start..half1_start],
            half1_deps: &self.data[half1_start..half2_start],
            half2_deps: &self.data[half2_start..end],
        })
    }

    /// Return true if the key exists.
    pub fn contains_key(&self, key: &u32) -> bool {
        self.keys.binary_search(key).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two entries:
    ///   key=10: shared=[1,2], half1=[3], half2=[4,5]
    ///   key=20: shared=[],    half1=[6], half2=[]
    fn sample() -> FlatPairSplit {
        // Entry 0 (key=10): data[0..2]=shared, data[2..3]=half1, data[3..5]=half2
        // Entry 1 (key=20): data[5..5]=shared, data[5..6]=half1, data[6..6]=half2
        //
        // seg_offsets layout per entry: [shared_start, half1_start, half2_start, end]
        // idx=0 (key=10): offsets[0..4] = [0, 2, 3, 5]
        //   shared   = data[0..2] = [1,2]
        //   half1    = data[2..3] = [3]
        //   half2    = data[3..5] = [4,5]
        // idx=1 (key=20): offsets[3..7] = [5, 5, 6, 6]
        //   shared   = data[5..5] = []
        //   half1    = data[5..6] = [6]
        //   half2    = data[6..6] = []
        //
        // Full seg_offsets = [0, 2, 3, 5,  5, 6, 6]
        //                     ^--entry0---^ ^entry1^
        // Wait: entry0 sentinel (5) == entry1 shared_start, so:
        // seg_offsets = [0, 2, 3, 5, 5, 6, 6]  — 7 elements for 2 keys (2*3+1)
        FlatPairSplit {
            keys: vec![10, 20],
            seg_offsets: vec![0, 2, 3, 5, 5, 6, 6],
            data: vec![1, 2, 3, 4, 5, 6],
        }
    }

    #[test]
    fn test_get_hit() {
        let flat = sample();
        let view = flat.view();

        let e = view.get(&10).unwrap();
        assert_eq!(e.shared, &[1u32, 2]);
        assert_eq!(e.half1_deps, &[3u32]);
        assert_eq!(e.half2_deps, &[4u32, 5]);
    }

    #[test]
    fn test_get_empty_slices() {
        let flat = sample();
        let view = flat.view();

        let e = view.get(&20).unwrap();
        assert_eq!(e.shared, &[] as &[u32]);
        assert_eq!(e.half1_deps, &[6u32]);
        assert_eq!(e.half2_deps, &[] as &[u32]);
    }

    #[test]
    fn test_get_miss() {
        let flat = sample();
        let view = flat.view();
        assert!(view.get(&99).is_none());
    }

    #[test]
    fn test_contains_key() {
        let flat = sample();
        let view = flat.view();
        assert!(view.contains_key(&10));
        assert!(view.contains_key(&20));
        assert!(!view.contains_key(&0));
        assert!(!view.contains_key(&15));
    }

    #[test]
    fn test_empty() {
        let flat = FlatPairSplit {
            keys: vec![],
            seg_offsets: vec![],
            data: vec![],
        };
        let view = flat.view();
        assert!(!view.contains_key(&0));
        assert!(view.get(&0).is_none());
    }
}
