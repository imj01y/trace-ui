use super::deps::DepsView;
use super::pair_split::PairSplitView;
use super::bitvec::BitView;

pub struct ScanView<'a> {
    pub deps: DepsView<'a>,
    pub pair_split: PairSplitView<'a>,
    pub init_mem_loads: BitView<'a>,
    pub line_count: u32,
}
