use std::collections::HashMap;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemRw {
    Read,
    Write,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemAccessRecord {
    pub seq: u32,
    pub insn_addr: u64,
    pub rw: MemRw,
    pub data: u64,
    pub size: u8,
}

#[derive(Serialize, Deserialize)]
pub struct MemAccessIndex {
    index: HashMap<u64, Vec<MemAccessRecord>>,
}

#[allow(dead_code)]
impl MemAccessIndex {
    pub fn new() -> Self {
        Self {
            index: HashMap::new(),
        }
    }

    pub fn add(&mut self, addr: u64, record: MemAccessRecord) {
        self.index.entry(addr).or_default().push(record);
    }

    pub fn get(&self, addr: u64) -> Option<&[MemAccessRecord]> {
        self.index.get(&addr).map(|v| v.as_slice())
    }

    pub fn total_records(&self) -> usize {
        self.index.values().map(|v| v.len()).sum()
    }

    pub fn total_addresses(&self) -> usize {
        self.index.len()
    }
}
