#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct FlatBitVec {
    pub data: Vec<u8>,
    pub len: u32,
}

impl FlatBitVec {
    pub fn view(&self) -> BitView<'_> {
        BitView {
            data: &self.data,
            len: self.len as usize,
        }
    }
}

impl ArchivedFlatBitVec {
    pub fn view(&self) -> BitView<'_> {
        let len: u32 = self.len.into();
        // ArchivedVec<u8>: u8 archived as u8 (no endian conversion needed).
        BitView {
            data: self.data.as_slice(),
            len: len as usize,
        }
    }
}

pub struct BitView<'a> {
    data: &'a [u8],
    len: usize,
}

impl<'a> BitView<'a> {
    /// Return the bit at position `idx` (little-endian bit order within each byte).
    #[inline]
    pub fn get(&self, idx: usize) -> bool {
        if idx >= self.len {
            return false;
        }
        let byte_idx = idx / 8;
        let bit_idx = idx % 8;
        (self.data[byte_idx] >> bit_idx) & 1 == 1
    }

    /// Return the number of logical bits.
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Return true if there are no bits.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_bitvec(bits: &[bool]) -> FlatBitVec {
        let len = bits.len() as u32;
        let byte_count = (bits.len() + 7) / 8;
        let mut data = vec![0u8; byte_count];
        for (i, &b) in bits.iter().enumerate() {
            if b {
                data[i / 8] |= 1 << (i % 8);
            }
        }
        FlatBitVec { data, len }
    }

    #[test]
    fn test_basic_get() {
        // bits: [1, 0, 1, 1, 0, 0, 0, 1, 0, 1]
        let bits = [true, false, true, true, false, false, false, true, false, true];
        let flat = make_bitvec(&bits);
        let view = flat.view();
        assert_eq!(view.len(), 10);
        for (i, &expected) in bits.iter().enumerate() {
            assert_eq!(view.get(i), expected, "mismatch at bit {}", i);
        }
    }

    #[test]
    fn test_out_of_bounds() {
        let flat = make_bitvec(&[true, false]);
        let view = flat.view();
        assert_eq!(view.get(0), true);
        assert_eq!(view.get(1), false);
        assert_eq!(view.get(2), false); // out of bounds → false
        assert_eq!(view.get(100), false);
    }

    #[test]
    fn test_empty() {
        let flat = FlatBitVec { data: vec![], len: 0 };
        let view = flat.view();
        assert!(view.is_empty());
        assert_eq!(view.len(), 0);
        assert_eq!(view.get(0), false);
    }

    #[test]
    fn test_all_zeros() {
        let flat = make_bitvec(&[false; 16]);
        let view = flat.view();
        for i in 0..16 {
            assert_eq!(view.get(i), false);
        }
    }

    #[test]
    fn test_all_ones() {
        let flat = make_bitvec(&[true; 16]);
        let view = flat.view();
        for i in 0..16 {
            assert_eq!(view.get(i), true);
        }
    }

    #[test]
    fn test_byte_boundary() {
        // bit 7 (last of first byte) and bit 8 (first of second byte)
        let mut bits = [false; 16];
        bits[7] = true;
        bits[8] = true;
        let flat = make_bitvec(&bits);
        let view = flat.view();
        assert_eq!(view.get(6), false);
        assert_eq!(view.get(7), true);
        assert_eq!(view.get(8), true);
        assert_eq!(view.get(9), false);
    }
}
