use crate::taint::call_tree::CallTree;
use crate::taint::scanner::RegLastDef;
use crate::taint::types::RegId;
use std::sync::Arc;
use memmap2::Mmap;

use super::mem_access::{FlatMemAccess, MemAccessView};
use super::reg_checkpoints::{FlatRegCheckpoints, RegCheckpointsView};
use super::deps::{FlatDeps, DepsView};
use super::mem_last_def::{FlatMemLastDef, MemLastDefView};
use super::pair_split::{FlatPairSplit, PairSplitView};
use super::bitvec::{FlatBitVec, BitView};
use super::line_index::{LineIndexArchive, ArchivedLineIndexArchive, LineIndexView};
use super::scan_view::ScanView;

pub const HEADER_LEN: usize = 64;

// ── Phase2Archive ────────────────────────────────────────────────────────────

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct Phase2Archive {
    pub mem_accesses: FlatMemAccess,
    pub reg_checkpoints: FlatRegCheckpoints,
    pub call_tree: CallTree,
}

// ── ScanArchive ──────────────────────────────────────────────────────────────

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct ScanArchive {
    pub deps: FlatDeps,
    pub mem_last_def: FlatMemLastDef,
    pub pair_split: FlatPairSplit,
    pub init_mem_loads: FlatBitVec,
    pub reg_last_def_inner: Vec<u32>, // [u32; 98] serialized as Vec
    pub line_count: u32,
    pub parsed_count: u32,
    pub mem_op_count: u32,
}

// ── CachedStore ──────────────────────────────────────────────────────────────

pub enum CachedStore<A: rkyv::Archive> {
    Owned(A),
    Mapped(Arc<Mmap>),
}

// ── CachedStore<Phase2Archive> ───────────────────────────────────────────────

impl CachedStore<Phase2Archive> {
    pub fn mem_accesses_view(&self) -> MemAccessView<'_> {
        match self {
            Self::Owned(a) => a.mem_accesses.view(),
            Self::Mapped(mmap) => {
                let archived = unsafe {
                    rkyv::access_unchecked::<ArchivedPhase2Archive>(&mmap[HEADER_LEN..])
                };
                archived.mem_accesses.view()
            }
        }
    }

    pub fn reg_checkpoints_view(&self) -> RegCheckpointsView<'_> {
        match self {
            Self::Owned(a) => a.reg_checkpoints.view(),
            Self::Mapped(mmap) => {
                let archived = unsafe {
                    rkyv::access_unchecked::<ArchivedPhase2Archive>(&mmap[HEADER_LEN..])
                };
                archived.reg_checkpoints.view()
            }
        }
    }

    pub fn deserialize_call_tree(&self) -> CallTree {
        match self {
            Self::Owned(a) => a.call_tree.clone(),
            Self::Mapped(mmap) => {
                let archived = unsafe {
                    rkyv::access_unchecked::<ArchivedPhase2Archive>(&mmap[HEADER_LEN..])
                };
                rkyv::deserialize::<CallTree, rkyv::rancor::BoxedError>(&archived.call_tree)
                    .expect("failed to deserialize CallTree")
            }
        }
    }
}

// ── CachedStore<ScanArchive> ─────────────────────────────────────────────────

impl CachedStore<ScanArchive> {
    pub fn deps_view(&self) -> DepsView<'_> {
        match self {
            Self::Owned(a) => a.deps.view(),
            Self::Mapped(mmap) => {
                let archived = unsafe {
                    rkyv::access_unchecked::<ArchivedScanArchive>(&mmap[HEADER_LEN..])
                };
                archived.deps.view()
            }
        }
    }

    pub fn mem_last_def_view(&self) -> MemLastDefView<'_> {
        match self {
            Self::Owned(a) => a.mem_last_def.view(),
            Self::Mapped(mmap) => {
                let archived = unsafe {
                    rkyv::access_unchecked::<ArchivedScanArchive>(&mmap[HEADER_LEN..])
                };
                archived.mem_last_def.view()
            }
        }
    }

    pub fn pair_split_view(&self) -> PairSplitView<'_> {
        match self {
            Self::Owned(a) => a.pair_split.view(),
            Self::Mapped(mmap) => {
                let archived = unsafe {
                    rkyv::access_unchecked::<ArchivedScanArchive>(&mmap[HEADER_LEN..])
                };
                archived.pair_split.view()
            }
        }
    }

    pub fn init_mem_loads_view(&self) -> BitView<'_> {
        match self {
            Self::Owned(a) => a.init_mem_loads.view(),
            Self::Mapped(mmap) => {
                let archived = unsafe {
                    rkyv::access_unchecked::<ArchivedScanArchive>(&mmap[HEADER_LEN..])
                };
                archived.init_mem_loads.view()
            }
        }
    }

    pub fn line_count(&self) -> u32 {
        match self {
            Self::Owned(a) => a.line_count,
            Self::Mapped(mmap) => {
                let archived = unsafe {
                    rkyv::access_unchecked::<ArchivedScanArchive>(&mmap[HEADER_LEN..])
                };
                archived.line_count.into()
            }
        }
    }

    pub fn reg_last_def_inner(&self) -> &[u32] {
        match self {
            Self::Owned(a) => &a.reg_last_def_inner,
            Self::Mapped(mmap) => {
                let archived = unsafe {
                    rkyv::access_unchecked::<ArchivedScanArchive>(&mmap[HEADER_LEN..])
                };
                // SAFETY: On little-endian platforms, u32_le and u32 have identical bit layout.
                unsafe {
                    core::slice::from_raw_parts(
                        archived.reg_last_def_inner.as_ptr() as *const u32,
                        archived.reg_last_def_inner.len(),
                    )
                }
            }
        }
    }

    pub fn deserialize_reg_last_def(&self) -> RegLastDef {
        let inner = self.reg_last_def_inner();
        let mut rld = RegLastDef::new();
        for (i, &v) in inner.iter().enumerate().take(RegId::COUNT) {
            if v != u32::MAX {
                rld.insert(RegId(i as u8), v);
            }
        }
        rld
    }

    pub fn scan_view(&self) -> ScanView<'_> {
        ScanView {
            deps: self.deps_view(),
            pair_split: self.pair_split_view(),
            init_mem_loads: self.init_mem_loads_view(),
            line_count: self.line_count(),
        }
    }
}

// ── CachedStore<LineIndexArchive> ────────────────────────────────────────────

impl CachedStore<LineIndexArchive> {
    pub fn total_lines(&self) -> u32 {
        self.view().total_lines()
    }

    pub fn view(&self) -> LineIndexView<'_> {
        match self {
            Self::Owned(a) => a.view(),
            Self::Mapped(mmap) => {
                let archived = unsafe {
                    rkyv::access_unchecked::<ArchivedLineIndexArchive>(&mmap[HEADER_LEN..])
                };
                archived.view()
            }
        }
    }
}
