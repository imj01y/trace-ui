//! Per-chunk scanning logic for parallel trace analysis.
//!
//! `scan_chunk` mirrors `scan_unified` but operates on a byte range within the
//! memory-mapped file, producing a `ChunkResult` with unresolved-item tracking
//! for cross-chunk boundary handling.

#![allow(dead_code)]

use bitvec::prelude::BitVec;
use memchr::memchr;
use rustc_hash::FxHashMap;
use smallvec::SmallVec;
use std::sync::Arc;

use crate::line_index::LineIndexBuilder;
use crate::phase2;
use crate::parallel_types::*;
use crate::query::mem_access::{MemAccessIndex, MemAccessRecord, MemRw};
use crate::query::registers::RegCheckpoints;
use crate::query::strings::{StringBuilder, StringRw};
use crate::scanner::{
    mem_access_width, push_unique, CompactDeps, MemLastDef, PairSplitDeps, RegLastDef,
    CONTROL_DEP_BIT, PAIR_HALF2_BIT, PAIR_SHARED_BIT,
};
use crate::scan_unified::bytes_to_hex_escaped;
use trace_parser::gumtrace as gumtrace_parser;
use trace_parser::insn_class::{self, InsnClass};
use trace_parser::parser;
use trace_parser::qbdi as qbdi_parser;
use trace_parser::types::{Operand, RegId, TraceFormat};

const CHECKPOINT_INTERVAL: u32 = 1000;

/// Scan a single chunk of trace data, producing a `ChunkResult`.
///
/// This mirrors `scan_unified` logic but:
/// - Operates on `data[start_byte..end_byte]` only
/// - Uses global line numbers starting at `start_line`
/// - Records unresolved items (loads/regs/pairs) for cross-chunk fixup
/// - Logs CallTree and Gumtrace annotation events instead of building them directly
pub fn scan_chunk(
    data: &[u8],
    start_byte: usize,
    end_byte: usize,
    start_line: u32,
    format: TraceFormat,
    data_only: bool,
    no_prune: bool,
    skip_strings: bool,
    progress_cb: Option<Arc<dyn Fn(usize) + Send + Sync>>,
) -> ChunkResult {
    // ── Estimate line count for this chunk ──
    let chunk_len = end_byte - start_byte;
    let line_count_est = chunk_len / 110 + 1;

    // ── ScanState-like initialization ──
    let mut reg_last_def = RegLastDef::new();
    let mut mem_last_def = MemLastDef::default();
    let mut last_cond_branch: Option<u32> = None;
    let mut deps = CompactDeps::with_capacity(line_count_est, line_count_est * 2);
    let mut line_count: u32 = start_line;
    let mut parsed_count: u32 = 0;
    let mut mem_op_count: u32 = 0;
    let mut unknown_mnemonics: FxHashMap<String, (u32, u32)> = FxHashMap::default();
    let mut init_mem_loads = BitVec::with_capacity(line_count_est);
    let mut pair_split: FxHashMap<u32, PairSplitDeps> = FxHashMap::default();

    // ── Phase2 data ──
    let mut mem_idx = MemAccessIndex::new();
    let mut string_builder = if skip_strings {
        None
    } else {
        Some(StringBuilder::new())
    };
    let mut reg_ckpts = RegCheckpoints::new(CHECKPOINT_INTERVAL);
    let mut reg_values = [u64::MAX; RegId::COUNT];

    // Save initial checkpoint (aligned to global line numbering)
    if line_count % CHECKPOINT_INTERVAL == 0 {
        reg_ckpts.save_checkpoint(&reg_values);
    }

    // ── String writes (for precise string scanning in merge phase) ──
    let mut string_accesses: Vec<(u64, u64, u8, u32, StringRw)> = Vec::new();

    // ── Unresolved tracking ──
    let mut unresolved_loads: Vec<UnresolvedLoad> = Vec::new();
    let mut partial_unresolved_loads: Vec<PartialUnresolvedLoad> = Vec::new();
    let mut unresolved_pair_loads: Vec<UnresolvedPairLoad> = Vec::new();
    let mut partial_unresolved_pair_loads: Vec<PartialUnresolvedPairLoad> = Vec::new();
    let mut unresolved_reg_uses: Vec<UnresolvedRegUse> = Vec::new();

    // ── Control dep tracking ──
    let mut first_local_cond_branch: Option<u32> = None;
    let mut needs_control_dep = BitVec::with_capacity(line_count_est);

    // ── Event logs ──
    let mut call_tree_events: Vec<CallTreeEvent> = Vec::new();
    let mut gumtrace_annot_events: Vec<GumtraceAnnotEvent> = Vec::new();
    let mut consumed_seqs: Vec<u32> = Vec::new();

    // ── LineIndex builder ──
    let mut li_builder = LineIndexBuilder::with_start_line(start_line, line_count_est);

    // Track whether we've emitted SetRootAddr
    let mut root_addr_set = false;

    // Track BLR state for selective LineAddr emission
    let mut prev_was_blr = false;
    let mut is_first_parsed_line = true;

    // ── Progress tracking ──
    let chunk_total = end_byte - start_byte;
    let progress_interval = chunk_total / 100 + 1;
    let mut bytes_since_report = 0usize;

    // ── Main loop ──
    let mut pos = start_byte;

    while pos < end_byte {
        // Find next newline (or end of chunk)
        let search_end = end_byte.min(data.len());
        let line_end = match memchr(b'\n', &data[pos..search_end]) {
            Some(p) => pos + p,
            None => search_end,
        };

        // Trim trailing \r (Windows CRLF)
        let end = if line_end > pos && data[line_end - 1] == b'\r' {
            line_end - 1
        } else {
            line_end
        };

        // UTF-8 handling
        let raw_line_owned: String;
        let raw_line: &str = match std::str::from_utf8(&data[pos..end]) {
            Ok(s) => s,
            Err(_) => {
                raw_line_owned = bytes_to_hex_escaped(&data[pos..end]);
                &raw_line_owned
            }
        };

        // LineIndex: record line offset
        li_builder.add_line(pos as u64);

        let prev_pos = pos;
        pos = if line_end < search_end {
            line_end + 1
        } else {
            search_end
        };

        // ── Progress reporting ──
        let line_bytes = pos - prev_pos;
        bytes_since_report += line_bytes;
        if let Some(ref cb) = progress_cb {
            if bytes_since_report >= progress_interval {
                cb(bytes_since_report);
                bytes_since_report = 0;
            }
        }

        // ── QBDI comment line skip ──
        if format == TraceFormat::Qbdi && qbdi_parser::is_qbdi_comment_line(raw_line) {
            line_count += 1;
            if line_count % CHECKPOINT_INTERVAL == 0 {
                reg_ckpts.save_checkpoint(&reg_values);
            }
            continue;
        }

        // ── Gumtrace special line early interception ──
        if format == TraceFormat::Gumtrace && gumtrace_parser::is_special_line(raw_line) {
            let i = line_count;
            // Special lines still occupy a row in deps
            deps.start_row();
            init_mem_loads.push(false);
            needs_control_dep.push(false);

            if let Some(special) = gumtrace_parser::parse_special_line(raw_line) {
                consumed_seqs.push(i);
                match special {
                    gumtrace_parser::SpecialLine::CallFunc { name, is_jni, .. } => {
                        gumtrace_annot_events.push(GumtraceAnnotEvent::SpecialLine {
                            seq: i,
                            special: SpecialLineData::CallFunc {
                                name: name.to_string(),
                                is_jni,
                                raw: raw_line.to_string(),
                            },
                        });
                    }
                    gumtrace_parser::SpecialLine::Arg { index, value } => {
                        gumtrace_annot_events.push(GumtraceAnnotEvent::SpecialLine {
                            seq: i,
                            special: SpecialLineData::Arg {
                                index: index.to_string(),
                                value: value.to_string(),
                                raw: raw_line.to_string(),
                            },
                        });
                    }
                    gumtrace_parser::SpecialLine::Ret { value } => {
                        gumtrace_annot_events.push(GumtraceAnnotEvent::SpecialLine {
                            seq: i,
                            special: SpecialLineData::Ret {
                                value: value.to_string(),
                                raw: raw_line.to_string(),
                            },
                        });
                    }
                    gumtrace_parser::SpecialLine::HexDump => {
                        gumtrace_annot_events.push(GumtraceAnnotEvent::SpecialLine {
                            seq: i,
                            special: SpecialLineData::HexDump {
                                raw: raw_line.to_string(),
                            },
                        });
                    }
                }
            } else {
                // Unrecognized line — record as OrphanLine for annotation replay
                gumtrace_annot_events.push(GumtraceAnnotEvent::OrphanLine { seq: i });
            }

            line_count += 1;
            if line_count % CHECKPOINT_INTERVAL == 0 {
                reg_ckpts.save_checkpoint(&reg_values);
            }
            continue;
        }

        let i = line_count;
        deps.start_row();
        init_mem_loads.push(false);

        // Parse line
        let parsed = match format {
            TraceFormat::Unidbg => parser::parse_line(raw_line),
            TraceFormat::Gumtrace => gumtrace_parser::parse_line_gumtrace(raw_line),
            TraceFormat::Qbdi => qbdi_parser::parse_line_qbdi(raw_line),
        };
        let Some(line) = parsed else {
            needs_control_dep.push(false);
            line_count += 1;
            if line_count % CHECKPOINT_INTERVAL == 0 {
                reg_ckpts.save_checkpoint(&reg_values);
            }
            continue;
        };

        // ── Classification + DEF/USE ──
        let class = insn_class::classify_and_refine(&line);

        // Collect unknown mnemonics
        if class == InsnClass::Nop && !insn_class::is_known_nop(line.mnemonic.as_str()) {
            let entry = unknown_mnemonics
                .entry(line.mnemonic.as_str().to_string())
                .or_insert((i, 0));
            entry.1 += 1;
        }

        let (defs, uses) = trace_parser::def_use::determine_def_use(class, &line);

        // ── Dependency tracking ──
        let is_pair = class == InsnClass::LoadPair || class == InsnClass::StorePair;

        // Track needs_control_dep for this line
        let line_needs_control_dep = !is_pair && !data_only;
        needs_control_dep.push(line_needs_control_dep);

        // Non-pair LOAD with pruning
        let is_non_pair_load = !is_pair && line.mem_op.as_ref().is_some_and(|m| !m.is_write);
        let mut is_pass_through = false;
        let mut skip_register_deps = false;

        if is_non_pair_load && !no_prune {
            let mem = line.mem_op.as_ref().unwrap();
            let width = mem_access_width(class, mem.elem_width, &line);
            let mut fully_unresolved = true;
            let mut any_byte_unresolved = false;
            let mut missing_addrs: SmallVec<[u64; 8]> = SmallVec::new();
            let mut all_same_store = true;
            let mut first_store_raw: Option<u32> = None;
            let mut store_val: Option<u64> = None;
            let mut has_init_mem = false;

            for offset in 0..width as u64 {
                if let Some((def_line, def_val)) = mem_last_def.get(&(mem.abs + offset)) {
                    fully_unresolved = false;
                    deps.push_unique(def_line);
                    match first_store_raw {
                        None => {
                            first_store_raw = Some(def_line);
                            store_val = Some(def_val);
                        }
                        Some(first) if first != def_line => {
                            all_same_store = false;
                        }
                        _ => {}
                    }
                } else {
                    any_byte_unresolved = true;
                    has_init_mem = true;
                    all_same_store = false;
                    missing_addrs.push(mem.abs + offset);
                }
            }

            if has_init_mem {
                let idx = init_mem_loads.len() - 1;
                init_mem_loads.set(idx, true);
            }

            if fully_unresolved {
                // Case 1: All bytes unresolved — defer memory deps to fixup.
                // Register deps with LOCAL definitions are added directly here;
                // only truly unresolved registers are deferred to merge-time fixup.
                // (Previously, ALL register deps were skipped and deferred, which
                // caused the merge pass to use stale global_reg_last_def values
                // instead of correct local definitions from the same chunk.)
                let mut deferred_uses = SmallVec::new();
                for r in &uses {
                    if let Some(&def_line) = reg_last_def.get(r) {
                        deps.push_unique(def_line);
                    } else {
                        deferred_uses.push(*r);
                    }
                }
                unresolved_loads.push(UnresolvedLoad {
                    line: i,
                    addr: mem.abs,
                    width,
                    load_value: mem.value,
                    uses: deferred_uses,
                });
                skip_register_deps = true;
            } else if any_byte_unresolved {
                // Case 2: Mixed — local mem deps already added, record missing addrs
                partial_unresolved_loads.push(PartialUnresolvedLoad {
                    line: i,
                    missing_addrs,
                });
                // pass-through is always false for mixed case
                // Reg deps added normally below
            } else {
                // Case 3: Fully local — check pass-through
                if all_same_store
                    && store_val.is_some()
                    && mem.value.is_some()
                    && store_val.unwrap() == mem.value.unwrap()
                {
                    is_pass_through = true;
                }
            }
        }

        // Step 3a: Register data dependencies
        // Skip for pair (handled in 3d), pass-through LOADs, and fully unresolved LOADs
        if !is_pair && !is_pass_through && !skip_register_deps {
            for r in &uses {
                if let Some(&def_line) = reg_last_def.get(r) {
                    deps.push_unique(def_line);
                } else {
                    // Register never defined in this chunk — unresolved
                    unresolved_reg_uses.push(UnresolvedRegUse { line: i, reg: *r });
                }
            }
        }

        // Step 3b: Memory data dependencies
        // Non-pair LOADs with pruning enabled are already handled above;
        // handle: pair LOADs, non-pair LOADs with pruning disabled
        if let Some(ref mem) = line.mem_op {
            if !mem.is_write && !(is_non_pair_load && !no_prune) {
                let width = mem_access_width(class, mem.elem_width, &line);
                let mut has_init_mem = false;
                for offset in 0..width as u64 {
                    if let Some((def_line, _)) = mem_last_def.get(&(mem.abs + offset)) {
                        if !is_pair {
                            deps.push_unique(def_line);
                        }
                    } else {
                        has_init_mem = true;
                    }
                }
                if has_init_mem {
                    let idx = init_mem_loads.len() - 1;
                    init_mem_loads.set(idx, true);
                }
            }
        }

        // Step 3c: Control dependencies (skip for pair — handled in 3d)
        if !is_pair && !data_only {
            if let Some(cb) = last_cond_branch {
                deps.push_unique(cb | CONTROL_DEP_BIT);
            }
            // If last_cond_branch is None, control deps will be added in fixup
        }

        // Step 3d: Pair-specific split tracking (LoadPair/StorePair)
        if class == InsnClass::LoadPair || class == InsnClass::StorePair {
            if let Some(ref mem) = line.mem_op {
                let ew = mem.elem_width;

                match class {
                    InsnClass::LoadPair => {
                        // Check unresolved status for each half
                        let mut half1_unresolved = true;
                        let mut half2_unresolved = true;
                        let mut half1_deps_local: SmallVec<[u32; 4]> = SmallVec::new();
                        let mut half2_deps_local: SmallVec<[u32; 4]> = SmallVec::new();

                        // half1 mem deps (first elem_width bytes)
                        for offset in 0..ew as u64 {
                            if let Some((raw, _)) = mem_last_def.get(&(mem.abs + offset)) {
                                half1_unresolved = false;
                                push_unique(&mut half1_deps_local, raw);
                            }
                        }
                        // half2 mem deps (second elem_width bytes)
                        for offset in ew as u64..2 * ew as u64 {
                            if let Some((raw, _)) = mem_last_def.get(&(mem.abs + offset)) {
                                half2_unresolved = false;
                                push_unique(&mut half2_deps_local, raw);
                            }
                        }

                        let fully_unresolved = half1_unresolved && half2_unresolved;

                        // Check base reg unresolved
                        let base_reg_unresolved = line
                            .base_reg
                            .map(|base| reg_last_def.get(&base).is_none())
                            .unwrap_or(false);

                        if fully_unresolved {
                            // Record as fully unresolved pair load
                            unresolved_pair_loads.push(UnresolvedPairLoad {
                                line: i,
                                addr: mem.abs,
                                elem_width: ew,
                                base_reg: line.base_reg,
                                defs: defs.iter().copied().collect(),
                            });
                            // Don't create PairSplitDeps — will be created in fixup
                        } else if half1_unresolved || half2_unresolved {
                            // Partially unresolved — create PairSplitDeps for resolved halves
                            let mut split = PairSplitDeps::default();

                            if !half1_unresolved {
                                split.half1_deps = half1_deps_local;
                            }
                            if !half2_unresolved {
                                split.half2_deps = half2_deps_local;
                            }

                            // shared: base reg dep
                            if let Some(base) = line.base_reg {
                                if let Some(&raw) = reg_last_def.get(&base) {
                                    push_unique(&mut split.shared, raw);
                                }
                            }
                            // shared: control dep
                            if !data_only {
                                if let Some(cb) = last_cond_branch {
                                    push_unique(&mut split.shared, cb | CONTROL_DEP_BIT);
                                }
                            }

                            pair_split.insert(i, split);

                            partial_unresolved_pair_loads.push(PartialUnresolvedPairLoad {
                                line: i,
                                addr: mem.abs,
                                elem_width: ew,
                                half1_unresolved,
                                half2_unresolved,
                                base_reg: line.base_reg,
                                base_reg_unresolved,
                            });
                        } else {
                            // Fully local — same as scan_unified
                            let mut split = PairSplitDeps::default();
                            split.half1_deps = half1_deps_local;
                            split.half2_deps = half2_deps_local;

                            // shared: base reg dep
                            if let Some(base) = line.base_reg {
                                if let Some(&raw) = reg_last_def.get(&base) {
                                    push_unique(&mut split.shared, raw);
                                }
                            }
                            // shared: control dep
                            if !data_only {
                                if let Some(cb) = last_cond_branch {
                                    push_unique(&mut split.shared, cb | CONTROL_DEP_BIT);
                                }
                            }

                            pair_split.insert(i, split);
                        }
                    }
                    InsnClass::StorePair => {
                        // StorePair: same logic as scan_unified
                        let mut split = PairSplitDeps::default();

                        // half1: first source register dep
                        if let Some(r) = line.operands.first().and_then(|op| op.as_reg()) {
                            if let Some(&raw) = reg_last_def.get(&r) {
                                push_unique(&mut split.half1_deps, raw);
                            }
                        }
                        // half2: second source register dep
                        if let Some(r) = line.operands.get(1).and_then(|op| op.as_reg()) {
                            if let Some(&raw) = reg_last_def.get(&r) {
                                push_unique(&mut split.half2_deps, raw);
                            }
                        }

                        // shared: base reg dep
                        if let Some(base) = line.base_reg {
                            if let Some(&raw) = reg_last_def.get(&base) {
                                push_unique(&mut split.shared, raw);
                            }
                        }
                        // shared: control dep
                        if !data_only {
                            if let Some(cb) = last_cond_branch {
                                push_unique(&mut split.shared, cb | CONTROL_DEP_BIT);
                            }
                        }

                        pair_split.insert(i, split);
                    }
                    _ => unreachable!(),
                }
            }
        }

        // ── State updates ──

        // Step 4: Update reg_last_def (identical to scan_unified)
        if class == InsnClass::LoadPair {
            // After SIMD expansion, defs may be [rt1_lo, rt1_hi, rt2_lo, rt2_hi, base?]
            // or [rt1, rt2, base?] for scalar. Split data defs at midpoint.
            let has_base_wb = line.writeback && line.base_reg.is_some();
            let data_defs = if has_base_wb { &defs[..defs.len() - 1] } else { &defs[..] };
            let mid = data_defs.len() / 2;

            for r in &data_defs[..mid] {
                reg_last_def.insert(*r, i); // half1: no tag
            }
            for r in &data_defs[mid..] {
                reg_last_def.insert(*r, i | PAIR_HALF2_BIT); // half2
            }
            if has_base_wb {
                reg_last_def.insert(*defs.last().unwrap(), i | PAIR_SHARED_BIT);
            }
        } else if class == InsnClass::StorePair {
            for r in &defs {
                reg_last_def.insert(*r, i | PAIR_SHARED_BIT);
            }
        } else {
            for r in &defs {
                reg_last_def.insert(*r, i);
            }
        }

        // Step 5: Update mem_last_def (identical to scan_unified)
        if let Some(ref mem) = line.mem_op {
            if mem.is_write {
                let masked_val = mem.value.unwrap_or(0);
                if class == InsnClass::StorePair {
                    let ew = mem.elem_width;
                    for offset in 0..ew as u64 {
                        mem_last_def.insert(mem.abs + offset, (i, masked_val));
                    }
                    for offset in ew as u64..2 * ew as u64 {
                        mem_last_def.insert(mem.abs + offset, (i | PAIR_HALF2_BIT, 0));
                    }
                } else {
                    let width = mem_access_width(class, mem.elem_width, &line);
                    for offset in 0..width as u64 {
                        mem_last_def.insert(mem.abs + offset, (i, masked_val));
                    }
                }
            }
        }

        // Step 6: Update last_cond_branch
        match class {
            InsnClass::CondBranchNzcv | InsnClass::CondBranchReg => {
                if first_local_cond_branch.is_none() {
                    first_local_cond_branch = Some(i);
                }
                last_cond_branch = Some(i);
            }
            _ => {}
        }

        // ── CallTree events ──
        let insn_addr_for_ct = phase2::extract_insn_addr(raw_line);
        if insn_addr_for_ct != 0 {
            if !root_addr_set {
                call_tree_events.push(CallTreeEvent::SetRootAddr {
                    addr: insn_addr_for_ct,
                });
                root_addr_set = true;
            }
            // Only emit LineAddr when needed for BLR pending detection:
            // - After a BLR instruction (prev_was_blr flag)
            // - First line of chunk (might follow cross-chunk BLR)
            if prev_was_blr || is_first_parsed_line {
                call_tree_events.push(CallTreeEvent::LineAddr {
                    seq: i,
                    addr: insn_addr_for_ct,
                });
                is_first_parsed_line = false;
            }
        }

        // Reset prev_was_blr before setting it for current instruction
        prev_was_blr = false;

        match class {
            InsnClass::BranchLink => {
                let target = line
                    .operands
                    .first()
                    .and_then(|op| match op {
                        Operand::Imm(val) => Some(*val as u64),
                        _ => None,
                    })
                    .unwrap_or(0);
                call_tree_events.push(CallTreeEvent::Call { seq: i, target });
                if format == TraceFormat::Gumtrace {
                    gumtrace_annot_events.push(GumtraceAnnotEvent::BranchInstr { seq: i });
                }
            }
            InsnClass::BranchLinkReg => {
                let target = phase2::extract_blr_target(&line, raw_line);
                let blr_pc = phase2::extract_insn_addr(raw_line);
                call_tree_events.push(CallTreeEvent::Call { seq: i, target });
                call_tree_events.push(CallTreeEvent::BlrPending { seq: i, pc: blr_pc });
                if format == TraceFormat::Gumtrace {
                    gumtrace_annot_events.push(GumtraceAnnotEvent::BranchInstr { seq: i });
                }
                prev_was_blr = true; // Next line needs LineAddr for BLR pending detection
            }
            InsnClass::BranchReg => {
                if format == TraceFormat::Gumtrace {
                    gumtrace_annot_events.push(GumtraceAnnotEvent::BranchInstr { seq: i });
                }
            }
            InsnClass::Return => {
                call_tree_events.push(CallTreeEvent::Ret { seq: i });
            }
            _ => {}
        }

        // ── Phase2: MemAccess ──
        if let Some(ref mem_op) = line.mem_op {
            mem_op_count += 1;
            let rw = if mem_op.is_write { MemRw::Write } else { MemRw::Read };
            let insn_addr = phase2::extract_insn_addr(raw_line);

            if mem_op.elem_width <= 8 {
                // Scalar 路径
                mem_idx.add(
                    mem_op.abs,
                    MemAccessRecord {
                        seq: i,
                        insn_addr,
                        rw,
                        data: mem_op.value.unwrap_or(0),
                        size: mem_op.elem_width,
                    },
                );

                // Pair 指令：在 abs + elem_width 处创建第二条记录
                if let Some(val2) = mem_op.value2 {
                    mem_idx.add(
                        mem_op.abs + mem_op.elem_width as u64,
                        MemAccessRecord {
                            seq: i,
                            insn_addr,
                            rw,
                            data: val2,
                            size: mem_op.elem_width,
                        },
                    );
                }
            } else if mem_op.elem_width == 16 {
                // 128-bit: 拆为两条 size=8 的记录
                if let Some(lo) = mem_op.value_lo {
                    mem_idx.add(mem_op.abs, MemAccessRecord {
                        seq: i, insn_addr, rw, data: lo, size: 8,
                    });
                }
                if let Some(hi) = mem_op.value_hi {
                    mem_idx.add(mem_op.abs + 8, MemAccessRecord {
                        seq: i, insn_addr, rw, data: hi, size: 8,
                    });
                }
                // Pair 128-bit: 第二个寄存器
                if let Some(lo2) = mem_op.value2_lo {
                    mem_idx.add(mem_op.abs + 16, MemAccessRecord {
                        seq: i, insn_addr, rw, data: lo2, size: 8,
                    });
                }
                if let Some(hi2) = mem_op.value2_hi {
                    mem_idx.add(mem_op.abs + 24, MemAccessRecord {
                        seq: i, insn_addr, rw, data: hi2, size: 8,
                    });
                }
            }

            // ── 记录内存访问（merge 阶段用于精确字符串构建） ──
            if mem_op.elem_width <= 8 {
                if let Some(value) = mem_op.value {
                    let rw = if mem_op.is_write { StringRw::Write } else { StringRw::Read };
                    string_accesses.push((mem_op.abs, value, mem_op.elem_width, i, rw));
                }
                if let Some(val2) = mem_op.value2 {
                    let rw = if mem_op.is_write { StringRw::Write } else { StringRw::Read };
                    string_accesses.push((mem_op.abs + mem_op.elem_width as u64, val2, mem_op.elem_width, i, rw));
                }
            }

            // ── Phase2: String extraction ──
            if let Some(ref mut sb) = string_builder {
                if mem_op.elem_width <= 8 {
                    if let Some(value) = mem_op.value {
                        let rw = if mem_op.is_write { StringRw::Write } else { StringRw::Read };
                        sb.process_access(mem_op.abs, value, mem_op.elem_width, i, rw);
                    }
                    if let Some(val2) = mem_op.value2 {
                        let rw = if mem_op.is_write { StringRw::Write } else { StringRw::Read };
                        sb.process_access(mem_op.abs + mem_op.elem_width as u64, val2, mem_op.elem_width, i, rw);
                    }
                }
            }
        }

        // ── Phase2: RegCheckpoints ──
        if let Some(arrow_pos) = line.arrow_pos {
            phase2::update_reg_values_at(&mut reg_values, raw_line, arrow_pos);
        }

        parsed_count += 1;
        line_count += 1;

        // Checkpoint save
        if line_count % CHECKPOINT_INTERVAL == 0 {
            reg_ckpts.save_checkpoint(&reg_values);
        }
    }

    // ── Finalize ──

    // Report any remaining progress bytes
    if let Some(ref cb) = progress_cb {
        if bytes_since_report > 0 {
            cb(bytes_since_report);
        }
    }

    // Build string index (xref counts left at 0 — MemAccessIndex not built yet)
    let string_index = match string_builder {
        Some(sb) => sb.finish(),
        None => Default::default(),
    };

    // Build line index
    let line_index = li_builder.finish();

    // Extract final mem_last_def as HashMap
    let final_mem_last_def = match mem_last_def {
        MemLastDef::Map(m) => m,
        MemLastDef::Sorted(_) => {
            // Shouldn't happen during scanning, but handle gracefully
            FxHashMap::default()
        }
    };

    let end_line = line_count;

    ChunkResult {
        deps,
        init_mem_loads,
        pair_split,
        line_index,
        mem_access_index: mem_idx,
        reg_checkpoints: reg_ckpts,
        string_index,
        string_accesses,

        unresolved_loads,
        partial_unresolved_loads,
        unresolved_pair_loads,
        partial_unresolved_pair_loads,
        unresolved_reg_uses,
        first_local_cond_branch,
        needs_control_dep,

        call_tree_events,
        gumtrace_annot_events,
        consumed_seqs,

        boundary: ChunkBoundaryState {
            final_reg_last_def: reg_last_def,
            final_mem_last_def,
            final_last_cond_branch: last_cond_branch,
            final_reg_values: reg_values,
            final_line_count: line_count,
            final_parsed_count: parsed_count,
            final_mem_op_count: mem_op_count,
        },

        start_line,
        end_line,
        start_byte,
        end_byte,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::CONTROL_DEP_BIT;

    fn mov_line(rd: &str, val: u64) -> String {
        format!(
            r#"[00:00:00 001][lib.so 0x100] [d2800000] 0x40000100: "mov {rd}, #{val}" => {rd}=0x{val:x}"#,
        )
    }

    fn add_line(rd: &str, rn: &str, rm: &str) -> String {
        format!(
            r#"[00:00:00 001][lib.so 0x108] [8b000000] 0x40000108: "add {rd}, {rn}, {rm}" {rn}=0x1 {rm}=0x2 => {rd}=0x3"#,
        )
    }

    fn str_line(rt: &str, base: &str, abs: u64) -> String {
        format!(
            r#"[00:00:00 001][lib.so 0x10c] [f9000000] 0x4000010c: "str {rt}, [{base}, #0x10]" ; mem[WRITE] abs=0x{abs:x} {rt}=0x3 {base}=0x{:x} => {rt}=0x3"#,
            abs - 0x10,
        )
    }

    fn ldr_line(rt: &str, base: &str, abs: u64) -> String {
        format!(
            r#"[00:00:00 001][lib.so 0x110] [f9400000] 0x40000110: "ldr {rt}, [{base}, #0x10]" ; mem[READ] abs=0x{abs:x} {base}=0x{:x} => {rt}=0x3"#,
            abs - 0x10,
        )
    }

    #[test]
    fn test_scan_chunk_single_chunk_register_chain() {
        // Build a simple trace: mov x8, mov x9, add x0 = x8 + x9
        let lines = vec![
            mov_line("x8", 5),
            mov_line("x9", 10),
            add_line("x0", "x8", "x9"),
        ];
        let trace = lines.join("\n");
        let data = trace.as_bytes();

        let result = scan_chunk(data, 0, data.len(), 0, TraceFormat::Unidbg, false, false, true, None);

        // Basic counts
        assert_eq!(result.end_line, 3);
        assert_eq!(result.boundary.final_parsed_count, 3);

        // add x0 (line 2) should depend on mov x8 (line 0) and mov x9 (line 1)
        let row2 = result.deps.row(2);
        assert!(row2.iter().any(|&d| d == 0), "add should depend on mov x8 (line 0)");
        assert!(row2.iter().any(|&d| d == 1), "add should depend on mov x9 (line 1)");

        // No unresolved items since all defs are local
        assert!(result.unresolved_reg_uses.is_empty());
        assert!(result.unresolved_loads.is_empty());
    }

    #[test]
    fn test_scan_chunk_memory_dependency() {
        let lines = vec![
            mov_line("x8", 42),
            str_line("x8", "sp", 0xbffff010),
            ldr_line("x0", "sp", 0xbffff010),
        ];
        let trace = lines.join("\n");
        let data = trace.as_bytes();

        let result = scan_chunk(data, 0, data.len(), 0, TraceFormat::Unidbg, true, false, true, None);

        // ldr (line 2) should depend on str (line 1) via memory
        let row2 = result.deps.row(2);
        assert!(
            row2.iter().any(|&d| d == 1),
            "ldr should depend on str via memory"
        );

        // No unresolved loads
        assert!(result.unresolved_loads.is_empty());
    }

    #[test]
    fn test_scan_chunk_unresolved_register() {
        // Single line using x8 which was never defined in this chunk
        let lines = vec![add_line("x0", "x8", "x9")];
        let trace = lines.join("\n");
        let data = trace.as_bytes();

        let result = scan_chunk(data, 0, data.len(), 0, TraceFormat::Unidbg, true, false, true, None);

        // x8 and x9 have no local def → should be unresolved
        assert!(
            result.unresolved_reg_uses.len() >= 2,
            "should have unresolved reg uses for x8 and x9, got {}",
            result.unresolved_reg_uses.len()
        );
    }

    #[test]
    fn test_scan_chunk_unresolved_load() {
        // A load from memory that was never written in this chunk
        let lines = vec![
            ldr_line("x0", "sp", 0xbffff010),
        ];
        let trace = lines.join("\n");
        let data = trace.as_bytes();

        let result = scan_chunk(data, 0, data.len(), 0, TraceFormat::Unidbg, true, false, true, None);

        // Fully unresolved load
        assert_eq!(
            result.unresolved_loads.len(),
            1,
            "should have 1 unresolved load"
        );
        assert_eq!(result.unresolved_loads[0].addr, 0xbffff010);
    }

    #[test]
    fn test_scan_chunk_with_start_line() {
        // Test that line numbering starts at start_line
        let lines = vec![
            mov_line("x8", 5),
            mov_line("x9", 10),
        ];
        let trace = lines.join("\n");
        let data = trace.as_bytes();

        let result = scan_chunk(data, 0, data.len(), 100, TraceFormat::Unidbg, false, false, true, None);

        assert_eq!(result.start_line, 100);
        assert_eq!(result.end_line, 102);
        assert_eq!(result.boundary.final_line_count, 102);

        // reg_last_def should use global line numbers
        assert_eq!(
            result.boundary.final_reg_last_def.get(&RegId::X8),
            Some(&100)
        );
        assert_eq!(
            result.boundary.final_reg_last_def.get(&RegId::X9),
            Some(&101)
        );
    }

    #[test]
    fn test_scan_chunk_calltree_events() {
        let lines = vec![
            r#"[00:00:00 001][lib.so 0x100] [94000000] 0x40000100: "bl #0x40000200" => x30=0x40000104"#.to_string(),
        ];
        let trace = lines.join("\n");
        let data = trace.as_bytes();

        let result = scan_chunk(data, 0, data.len(), 0, TraceFormat::Unidbg, false, false, true, None);

        // Should have CallTreeEvent::SetRootAddr, LineAddr, and Call
        let has_root = result.call_tree_events.iter().any(|e| matches!(e, CallTreeEvent::SetRootAddr { .. }));
        let has_call = result.call_tree_events.iter().any(|e| matches!(e, CallTreeEvent::Call { .. }));
        assert!(has_root, "should emit SetRootAddr");
        assert!(has_call, "should emit Call event for bl");
    }

    #[test]
    fn test_scan_chunk_control_dep_tracking() {
        let lines = vec![
            r#"[00:00:00 001][lib.so 0x300] [6b09011f] 0x40000300: "cmp x8, x9" x8=0x5 x9=0xa => nzcv=0x80000000"#.to_string(),
            r#"[00:00:00 001][lib.so 0x304] [54000040] 0x40000304: "b.eq #0x4000030c" nzcv=0x40000000"#.to_string(),
            mov_line("x0", 42),
        ];
        let trace = lines.join("\n");
        let data = trace.as_bytes();

        let result = scan_chunk(data, 0, data.len(), 0, TraceFormat::Unidbg, false, false, true, None);

        // b.eq sets first_local_cond_branch
        assert_eq!(result.first_local_cond_branch, Some(1));

        // mov x0 (line 2) should have control dep on b.eq (line 1)
        let row2 = result.deps.row(2);
        assert!(
            row2.iter().any(|&d| d == (1 | CONTROL_DEP_BIT)),
            "mov should have control dep on b.eq"
        );
    }

    #[test]
    fn test_scan_chunk_empty_trace() {
        let data = b"";
        let result = scan_chunk(data, 0, 0, 0, TraceFormat::Unidbg, false, false, true, None);
        assert_eq!(result.start_line, 0);
        assert_eq!(result.end_line, 0);
        assert!(result.deps.is_empty());
    }
}
