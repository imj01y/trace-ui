// Cross-chunk merge and fixup logic

#![allow(dead_code)]

use std::collections::HashMap;

use bitvec::prelude::BitVec;
use rustc_hash::FxHashMap;
use smallvec::SmallVec;

use crate::line_index::LineIndex;
use crate::query::call_tree::{CallTree, CallTreeBuilder};
use crate::query::mem_access::MemAccessIndex;
use crate::parallel_types::{
    CallTreeEvent, GumtraceAnnotEvent, PartialUnresolvedLoad, PartialUnresolvedPairLoad,
    SpecialLineData, UnresolvedLoad, UnresolvedPairLoad, UnresolvedRegUse,
};
use crate::query::registers::RegCheckpoints;
use crate::scanner::{push_unique, CompactDeps, PairSplitDeps, RegLastDef, CONTROL_DEP_BIT};
use crate::query::strings::StringIndex;
use trace_parser::gumtrace::CallAnnotation;
use trace_parser::types::RegId;

/// Resolve a fully unresolved load using global state.
/// Determines pass-through exactly as single-threaded scan would.
pub fn resolve_unresolved_load(
    load: &UnresolvedLoad,
    global_mem_last_def: &FxHashMap<u64, (u32, u64)>,
    global_reg_last_def: &RegLastDef,
    patch_edges: &mut Vec<(u32, u32)>,
    init_corrections: &mut Vec<(u32, bool)>,
) {
    let mut all_same_store = true;
    let mut first_store_raw: Option<u32> = None;
    let mut store_val: Option<u64> = None;
    let mut has_init_mem = false;

    for offset in 0..load.width as u64 {
        if let Some(&(def_line, def_val)) = global_mem_last_def.get(&(load.addr + offset)) {
            patch_edges.push((load.line, def_line));
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
            has_init_mem = true;
            all_same_store = false;
        }
    }

    // Pass-through check: exact same logic as scan_unified
    let is_pass_through = all_same_store
        && store_val.is_some()
        && load.load_value.is_some()
        && store_val.unwrap() == load.load_value.unwrap();

    if !is_pass_through {
        // Not pass-through → add register deps
        for r in &load.uses {
            if let Some(&def_line) = global_reg_last_def.get(r) {
                patch_edges.push((load.line, def_line));
            }
        }
    }

    // Correct init_mem_loads
    if !has_init_mem {
        init_corrections.push((load.line, false));
    }
}

/// Resolve partially unresolved loads — supplement missing mem deps.
/// Pass-through is already determined as false (mixed case). Reg deps already added.
pub fn resolve_partial_unresolved_loads(
    partials: &[PartialUnresolvedLoad],
    global_mem_last_def: &FxHashMap<u64, (u32, u64)>,
    patch_edges: &mut Vec<(u32, u32)>,
    init_corrections: &mut Vec<(u32, bool)>,
) {
    for partial in partials {
        let mut all_found = true;
        for &addr in &partial.missing_addrs {
            if let Some(&(def_line, _)) = global_mem_last_def.get(&addr) {
                patch_edges.push((partial.line, def_line));
            } else {
                all_found = false;
            }
        }
        if all_found {
            init_corrections.push((partial.line, false));
        }
    }
}

/// Resolve a fully unresolved pair load. Builds complete PairSplitDeps from global state.
pub fn resolve_unresolved_pair_load(
    pair: &UnresolvedPairLoad,
    global_mem_last_def: &FxHashMap<u64, (u32, u64)>,
    global_reg_last_def: &RegLastDef,
    global_last_cond_branch: Option<u32>,
    data_only: bool,
) -> (PairSplitDeps, Vec<(u32, u32)>) {
    let mut split = PairSplitDeps::default();
    let mut patch_edges = Vec::new();
    let ew = pair.elem_width;

    // half1 mem deps (first elem_width bytes)
    for offset in 0..ew as u64 {
        if let Some(&(raw, _)) = global_mem_last_def.get(&(pair.addr + offset)) {
            push_unique(&mut split.half1_deps, raw);
            patch_edges.push((pair.line, raw));
        }
    }
    // half2 mem deps (second elem_width bytes)
    for offset in ew as u64..2 * ew as u64 {
        if let Some(&(raw, _)) = global_mem_last_def.get(&(pair.addr + offset)) {
            push_unique(&mut split.half2_deps, raw);
            patch_edges.push((pair.line, raw));
        }
    }
    // shared: base reg dep
    if let Some(base) = pair.base_reg {
        if let Some(&raw) = global_reg_last_def.get(&base) {
            push_unique(&mut split.shared, raw);
            patch_edges.push((pair.line, raw));
        }
    }
    // shared: control dep
    if !data_only {
        if let Some(cb) = global_last_cond_branch {
            push_unique(&mut split.shared, cb | CONTROL_DEP_BIT);
            patch_edges.push((pair.line, cb | CONTROL_DEP_BIT));
        }
    }

    (split, patch_edges)
}

/// Resolve a partially unresolved pair load. Supplements missing half deps in existing PairSplitDeps.
pub fn resolve_partial_pair_load(
    partial: &PartialUnresolvedPairLoad,
    global_mem_last_def: &FxHashMap<u64, (u32, u64)>,
    global_reg_last_def: &RegLastDef,
    pair_split: &mut FxHashMap<u32, PairSplitDeps>,
    patch_edges: &mut Vec<(u32, u32)>,
) {
    let ew = partial.elem_width;
    let split = pair_split.entry(partial.line).or_default();

    if partial.half1_unresolved {
        for offset in 0..ew as u64 {
            if let Some(&(raw, _)) = global_mem_last_def.get(&(partial.addr + offset)) {
                push_unique(&mut split.half1_deps, raw);
                patch_edges.push((partial.line, raw));
            }
        }
    }
    if partial.half2_unresolved {
        for offset in ew as u64..2 * ew as u64 {
            if let Some(&(raw, _)) = global_mem_last_def.get(&(partial.addr + offset)) {
                push_unique(&mut split.half2_deps, raw);
                patch_edges.push((partial.line, raw));
            }
        }
    }
    if partial.base_reg_unresolved {
        if let Some(base) = partial.base_reg {
            if let Some(&raw) = global_reg_last_def.get(&base) {
                push_unique(&mut split.shared, raw);
                patch_edges.push((partial.line, raw));
            }
        }
    }
}

/// Resolve register uses that had no local definition.
pub fn resolve_unresolved_reg_uses(
    uses: &[UnresolvedRegUse],
    global_reg_last_def: &RegLastDef,
) -> Vec<(u32, u32)> {
    let mut patch_edges = Vec::new();
    for u in uses {
        if let Some(&def_line) = global_reg_last_def.get(&u.reg) {
            patch_edges.push((u.line, def_line));
        }
    }
    patch_edges
}

/// Add control deps for lines before the first local conditional branch.
/// Only adds for lines where needs_control_dep is true (non-pair, parsed, !data_only).
pub fn resolve_control_deps(
    chunk_start: u32,
    first_local_cond: Option<u32>,
    prev_last_cond: Option<u32>,
    chunk_end: u32,
    needs_control_dep: &BitVec,
    data_only: bool,
) -> Vec<(u32, u32)> {
    if data_only {
        return Vec::new();
    }
    let Some(prev_cond) = prev_last_cond else {
        return Vec::new();
    };
    let end = first_local_cond.unwrap_or(chunk_end);
    let mut patches = Vec::new();
    for line in chunk_start..end {
        let local_idx = (line - chunk_start) as usize;
        if local_idx < needs_control_dep.len() && needs_control_dep[local_idx] {
            patches.push((line, prev_cond | CONTROL_DEP_BIT));
        }
    }
    patches
}

/// Rebuild a single CompactDeps from multiple chunk deps + patch edges.
/// patch_edges are (source_line, dep_line) tuples from the fixup phase.
/// Uses push_unique for deduplication within each row.
pub fn rebuild_compact_deps(
    chunk_deps: &[CompactDeps],
    chunk_start_lines: &[u32],
    patch_edges: &[(u32, u32)],
    progress_fn: Option<&dyn Fn(f64)>,
) -> CompactDeps {
    // Group patch_edges by source line for efficient lookup
    let mut patches: FxHashMap<u32, Vec<u32>> = FxHashMap::default();
    for &(from, to) in patch_edges {
        patches.entry(from).or_default().push(to);
    }

    // Calculate total capacity
    let total_lines: usize = chunk_deps.iter().map(|c| c.offsets.len()).sum();
    let total_deps: usize =
        chunk_deps.iter().map(|c| c.data.len()).sum::<usize>() + patch_edges.len();

    let mut merged = CompactDeps::with_capacity(total_lines, total_deps);

    let report_interval = (total_lines / 100).max(1);
    let mut rows_processed = 0usize;

    for (chunk_id, chunk) in chunk_deps.iter().enumerate() {
        let num_rows = chunk.offsets.len();
        for local_row in 0..num_rows {
            let global_line = chunk_start_lines[chunk_id] + local_row as u32;
            merged.start_row();

            // Add original deps from this chunk
            for &dep in chunk.row(local_row) {
                merged.push_unique(dep);
            }

            // Add patch deps from fixup
            if let Some(extras) = patches.get(&global_line) {
                for &dep in extras {
                    merged.push_unique(dep);
                }
            }

            rows_processed += 1;
            if let Some(ref cb) = progress_fn {
                if rows_processed % report_interval == 0 {
                    cb(rows_processed as f64 / total_lines as f64);
                }
            }
        }
    }

    merged
}

/// Replay CallTree events sequentially through a single CallTreeBuilder.
/// This handles blr_pending_pc logic correctly across chunk boundaries.
pub fn replay_call_tree_events(events: &[CallTreeEvent], total_lines: u32) -> CallTree {
    let mut builder = CallTreeBuilder::new();
    let mut blr_pending_pc: Option<u64> = None;
    let mut root_addr_set = false;

    for event in events {
        match event {
            CallTreeEvent::SetRootAddr { addr } => {
                if !root_addr_set {
                    builder.set_root_addr(*addr);
                    root_addr_set = true;
                }
            }
            CallTreeEvent::LineAddr { seq, addr } => {
                // Handle BLR pending check (same logic as scan_unified/phase2)
                if let Some(blr_pc) = blr_pending_pc.take() {
                    if *addr != 0 {
                        builder.update_current_func_addr(*addr);
                        if *addr == blr_pc + 4 {
                            // unidbg intercepted call — no function body
                            builder.on_ret(seq.saturating_sub(1));
                        }
                    } else {
                        // Can't extract address, keep pending
                        blr_pending_pc = Some(blr_pc);
                    }
                }
            }
            CallTreeEvent::Call { seq, target } => {
                builder.on_call(*seq, *target);
            }
            CallTreeEvent::Ret { seq } => {
                builder.on_ret(*seq);
            }
            CallTreeEvent::BlrPending { seq: _, pc } => {
                blr_pending_pc = Some(*pc);
            }
            CallTreeEvent::SetFuncName { entry_seq, name } => {
                builder.set_func_name_by_entry_seq(*entry_seq, name);
            }
        }
    }

    builder.finish(total_lines)
}

/// Replay Gumtrace annotation events sequentially.
/// Produces exact call_annotations and extra consumed_seqs.
pub fn replay_gumtrace_annotations(
    events: &[GumtraceAnnotEvent],
) -> (HashMap<u32, CallAnnotation>, Vec<u32>) {
    let mut call_annotations = HashMap::new();
    let mut extra_consumed = Vec::new();
    let mut pending_call_seq: Option<u32> = None;
    let mut current_annotation: Option<(u32, CallAnnotation)> = None;

    for event in events {
        match event {
            GumtraceAnnotEvent::BranchInstr { seq } => {
                pending_call_seq = Some(*seq);
            }
            GumtraceAnnotEvent::SpecialLine { seq: _, special } => {
                match special {
                    SpecialLineData::CallFunc { name, is_jni, raw } => {
                        // Flush previous unfinished annotation
                        if let Some((bl_seq, ann)) = current_annotation.take() {
                            call_annotations.insert(bl_seq, ann);
                        }
                        if let Some(bl_seq) = pending_call_seq.take() {
                            current_annotation = Some((bl_seq, CallAnnotation {
                                func_name: name.clone(),
                                is_jni: *is_jni,
                                args: Vec::new(),
                                ret_value: None,
                                raw_lines: vec![raw.clone()],
                            }));
                        }
                    }
                    SpecialLineData::Arg { index, value, raw } => {
                        if let Some((_, ref mut ann)) = current_annotation {
                            ann.args.push((index.clone(), value.clone()));
                            ann.raw_lines.push(raw.clone());
                        }
                    }
                    SpecialLineData::Ret { value, raw } => {
                        if let Some((bl_seq, mut ann)) = current_annotation.take() {
                            ann.ret_value = Some(value.clone());
                            ann.raw_lines.push(raw.clone());
                            call_annotations.insert(bl_seq, ann);
                        }
                    }
                    SpecialLineData::HexDump { raw } => {
                        if let Some((_, ref mut ann)) = current_annotation {
                            ann.raw_lines.push(raw.clone());
                        }
                    }
                }
            }
            GumtraceAnnotEvent::OrphanLine { seq } => {
                if current_annotation.is_some() {
                    extra_consumed.push(*seq);
                }
            }
        }
    }

    // Flush remaining
    if let Some((bl_seq, ann)) = current_annotation.take() {
        call_annotations.insert(bl_seq, ann);
    }

    (call_annotations, extra_consumed)
}

/// Fix RegCheckpoints by propagating previous chunk's final register values.
/// For each snapshot, if a register value is u64::MAX (unknown), replace with prev chunk's value.
pub fn fix_reg_checkpoints(
    ckpts: &mut RegCheckpoints,
    prev_final_reg_values: &[u64; RegId::COUNT],
) {
    for snapshot in &mut ckpts.snapshots {
        for r in 0..RegId::COUNT {
            if snapshot.0[r] == u64::MAX && prev_final_reg_values[r] != u64::MAX {
                snapshot.0[r] = prev_final_reg_values[r];
            }
        }
    }
}

/// Merge multiple MemAccessIndex. Records within same address preserve chunk order.
pub fn merge_mem_access_indices(indices: Vec<MemAccessIndex>) -> MemAccessIndex {
    let mut merged = MemAccessIndex::new();
    for idx in indices {
        for (addr, record) in idx.iter_all() {
            merged.add(addr, record.clone());
        }
    }
    merged
}

/// Merge LineIndex from chunks. Each chunk used global byte offsets and
/// LineIndexBuilder with correct start_line, so sampled_offsets are globally aligned.
/// Simply concatenate sampled_offsets and sum totals.
pub fn merge_line_indices(indices: Vec<LineIndex>) -> LineIndex {
    LineIndex::merge(indices)
}

/// Merge init_mem_loads BitVecs and apply corrections.
pub fn merge_init_mem_loads(
    chunk_inits: Vec<BitVec>,
    corrections: &[(u32, bool)],
) -> BitVec {
    let total_bits: usize = chunk_inits.iter().map(|b| b.len()).sum();
    let mut merged = BitVec::with_capacity(total_bits);
    for chunk in chunk_inits {
        merged.extend_from_bitslice(&chunk);
    }
    for &(line, value) in corrections {
        if (line as usize) < merged.len() {
            merged.set(line as usize, value);
        }
    }
    merged
}

/// Merge pair_split HashMaps from chunks + fixup additions.
pub fn merge_pair_splits(
    chunk_splits: Vec<FxHashMap<u32, PairSplitDeps>>,
    fixup_splits: Vec<(u32, PairSplitDeps)>,
) -> FxHashMap<u32, PairSplitDeps> {
    let mut merged = FxHashMap::default();
    for chunk in chunk_splits {
        merged.extend(chunk);
    }
    for (line, split) in fixup_splits {
        merged.insert(line, split);
    }
    merged
}

/// Merge StringIndex from chunks. Concatenate and sort by seq.
pub fn merge_string_indices(indices: Vec<StringIndex>) -> StringIndex {
    let mut all_strings = Vec::new();
    for idx in indices {
        all_strings.extend(idx.strings);
    }
    all_strings.sort_by_key(|r| r.seq);
    StringIndex { strings: all_strings }
}

use crate::scan_unified::ScanResult;
use crate::scan_unified::Phase2State;
use crate::scanner::{ScanState, MemLastDef};
use trace_parser::types::TraceFormat;
use crate::parallel_types::ChunkResult;

/// Phase 2 orchestrator: merge all chunk results into a single ScanResult.
///
/// Performs sequential forward propagation to resolve cross-chunk dependencies,
/// then merges all data structures into unified output.
pub fn merge_all_chunks(
    chunk_results: Vec<ChunkResult>,
    format: TraceFormat,
    data_only: bool,
    skip_strings: bool,
    progress_fn: Option<&dyn Fn(f64)>,
    cancel_flag: Option<&std::sync::atomic::AtomicBool>,
) -> std::result::Result<ScanResult, crate::error::TraceError> {
    let num_chunks = chunk_results.len();
    let mut all_patch_edges: Vec<(u32, u32)> = Vec::new();
    let mut all_pair_fixups: Vec<(u32, PairSplitDeps)> = Vec::new();
    let mut init_corrections: Vec<(u32, bool)> = Vec::new();
    let mut all_call_events: Vec<CallTreeEvent> = Vec::new();
    let mut all_gumtrace_events: Vec<GumtraceAnnotEvent> = Vec::new();

    // Sequential forward propagation of global state
    let mut global_mem_last_def: FxHashMap<u64, (u32, u64)> = FxHashMap::default();
    let mut global_reg_last_def = RegLastDef::new();
    let mut global_last_cond_branch: Option<u32> = None;

    // Lightweight deferred pair deps — resolved inline from global state (no cloning)
    struct DeferredPairDep {
        line: u32,
        chunk_idx: usize,
        extra_half1: SmallVec<[u32; 4]>,
        extra_half2: SmallVec<[u32; 4]>,
        extra_shared: SmallVec<[u32; 2]>,
    }
    let mut deferred_pair_deps: Vec<DeferredPairDep> = Vec::new();

    let num_chunks_f64 = num_chunks as f64;

    // Pass 1: Forward propagation + fixup (borrow chunk_results)
    for (i, chunk) in chunk_results.iter().enumerate() {
        if i > 0 {
            // === Resolve fully unresolved loads ===
            for load in &chunk.unresolved_loads {
                resolve_unresolved_load(
                    load,
                    &global_mem_last_def,
                    &global_reg_last_def,
                    &mut all_patch_edges,
                    &mut init_corrections,
                );
            }

            // === Resolve partially unresolved loads (mixed case) ===
            resolve_partial_unresolved_loads(
                &chunk.partial_unresolved_loads,
                &global_mem_last_def,
                &mut all_patch_edges,
                &mut init_corrections,
            );

            // === Resolve fully unresolved pair loads ===
            for pair in &chunk.unresolved_pair_loads {
                let (split, edges) = resolve_unresolved_pair_load(
                    pair,
                    &global_mem_last_def,
                    &global_reg_last_def,
                    global_last_cond_branch,
                    data_only,
                );
                all_pair_fixups.push((pair.line, split));
                all_patch_edges.extend(edges);
            }

            // === Resolve partial pair loads inline (no snapshot cloning) ===
            if !chunk.partial_unresolved_pair_loads.is_empty() {
                for partial in &chunk.partial_unresolved_pair_loads {
                    let mut extra_half1 = SmallVec::<[u32; 4]>::new();
                    let mut extra_half2 = SmallVec::<[u32; 4]>::new();
                    let mut extra_shared = SmallVec::<[u32; 2]>::new();

                    if partial.half1_unresolved {
                        for offset in 0..partial.elem_width as u64 {
                            if let Some(&(raw, _)) = global_mem_last_def.get(&(partial.addr + offset)) {
                                push_unique(&mut extra_half1, raw);
                                all_patch_edges.push((partial.line, raw));
                            }
                        }
                    }
                    if partial.half2_unresolved {
                        for offset in partial.elem_width as u64..2 * partial.elem_width as u64 {
                            if let Some(&(raw, _)) = global_mem_last_def.get(&(partial.addr + offset)) {
                                push_unique(&mut extra_half2, raw);
                                all_patch_edges.push((partial.line, raw));
                            }
                        }
                    }
                    if partial.base_reg_unresolved {
                        if let Some(base) = partial.base_reg {
                            if let Some(&raw) = global_reg_last_def.get(&base) {
                                push_unique(&mut extra_shared, raw);
                                all_patch_edges.push((partial.line, raw));
                            }
                        }
                    }

                    if !extra_half1.is_empty() || !extra_half2.is_empty() || !extra_shared.is_empty() {
                        deferred_pair_deps.push(DeferredPairDep {
                            line: partial.line,
                            chunk_idx: i,
                            extra_half1,
                            extra_half2,
                            extra_shared,
                        });
                    }
                }
            }

            // === Resolve unresolved register uses ===
            let reg_patches = resolve_unresolved_reg_uses(
                &chunk.unresolved_reg_uses,
                &global_reg_last_def,
            );
            all_patch_edges.extend(reg_patches);

            // === Resolve control deps ===
            let ctrl_patches = resolve_control_deps(
                chunk.start_line,
                chunk.first_local_cond_branch,
                global_last_cond_branch,
                chunk.end_line,
                &chunk.needs_control_dep,
                data_only,
            );
            all_patch_edges.extend(ctrl_patches);
        }

        // Update global state from this chunk's boundary
        for (&addr, &val) in &chunk.boundary.final_mem_last_def {
            global_mem_last_def.insert(addr, val);
        }
        // Per-register merge: only overwrite registers actually defined in this chunk
        let chunk_reg = chunk.boundary.final_reg_last_def.inner();
        let global_reg = global_reg_last_def.inner_mut();
        for idx in 0..RegId::COUNT {
            if chunk_reg[idx] != u32::MAX {
                global_reg[idx] = chunk_reg[idx];
            }
        }
        if chunk.boundary.final_last_cond_branch.is_some() {
            global_last_cond_branch = chunk.boundary.final_last_cond_branch;
        }

        // Report Pass 1 progress: maps to 0.0-0.10
        if let Some(ref cb) = progress_fn {
            cb(0.10 * (i + 1) as f64 / num_chunks_f64);
        }
    }

    // === Compact global_mem_last_def immediately after Pass 1 ===
    // HashMap 存储 200M+ 条目可达 10-16GB（桶数组 + entries）。
    // 立即转为 sorted Vec（~4GB）释放 HashMap 的巨大开销。
    // Pass 1 之后不再需要 HashMap 的查询能力。
    let global_mem_sorted: Vec<(u64, u32, u64)> = {
        let mut sorted: Vec<(u64, u32, u64)> = global_mem_last_def
            .drain()
            .map(|(addr, (line, val))| (addr, line, val))
            .collect();
        drop(global_mem_last_def); // 立即释放 HashMap 桶数组
        if let Some(ref cb) = progress_fn { cb(0.12); }
        sorted.sort_unstable_by_key(|(addr, _, _)| *addr);
        sorted
    };

    if let Some(ref cb) = progress_fn { cb(0.15); }

    // === Pass 2: Decompose chunk_results (move out data) ===
    let mut chunk_deps = Vec::with_capacity(num_chunks);
    let mut chunk_inits = Vec::with_capacity(num_chunks);
    let mut chunk_pair_splits = Vec::with_capacity(num_chunks);
    let mut chunk_reg_ckpts = Vec::with_capacity(num_chunks);
    let mut chunk_line_indices = Vec::with_capacity(num_chunks);
    let mut chunk_mem_indices = Vec::with_capacity(num_chunks);
    let mut chunk_string_accesses: Vec<Vec<(u64, u64, u8, u32, crate::query::strings::StringRw)>> = Vec::with_capacity(num_chunks);
    let mut all_consumed_seqs = Vec::new();
    let mut chunk_start_lines = Vec::with_capacity(num_chunks);
    let mut total_parsed_count = 0u32;
    let mut total_mem_op_count = 0u32;

    let mut prev_final_reg_values = [u64::MAX; RegId::COUNT];

    for (i, chunk) in chunk_results.into_iter().enumerate() {
        chunk_start_lines.push(chunk.start_line);
        chunk_deps.push(chunk.deps);
        chunk_inits.push(chunk.init_mem_loads);
        chunk_pair_splits.push(chunk.pair_split);
        chunk_line_indices.push(chunk.line_index);
        chunk_mem_indices.push(chunk.mem_access_index);
        chunk_string_accesses.push(chunk.string_accesses);
        all_consumed_seqs.extend(chunk.consumed_seqs);

        // Move events (not clone) — saves ~20GB for large files
        all_call_events.extend(chunk.call_tree_events);
        all_gumtrace_events.extend(chunk.gumtrace_annot_events);
        total_parsed_count += chunk.boundary.final_parsed_count;
        total_mem_op_count += chunk.boundary.final_mem_op_count;

        // Fix reg checkpoints using previous chunk's final values
        let mut ckpts = chunk.reg_checkpoints;
        if i > 0 {
            fix_reg_checkpoints(&mut ckpts, &prev_final_reg_values);
        }
        chunk_reg_ckpts.push(ckpts);
        prev_final_reg_values = chunk.boundary.final_reg_values;
    }

    // === Apply deferred pair deps (lightweight, no snapshot needed) ===
    for dep in &deferred_pair_deps {
        let pair_split = &mut chunk_pair_splits[dep.chunk_idx];
        let split = pair_split.entry(dep.line).or_default();
        for &d in &dep.extra_half1 {
            push_unique(&mut split.half1_deps, d);
        }
        for &d in &dep.extra_half2 {
            push_unique(&mut split.half2_deps, d);
        }
        for &d in &dep.extra_shared {
            push_unique(&mut split.shared, d);
        }
    }

    if let Some(ref cb) = progress_fn { cb(0.20); }

    let phase2_timer = std::time::Instant::now();

    // === Rebuild unified data structures ===

    // Total lines (compute before dropping chunk_deps)
    let total_lines = chunk_start_lines.last().copied().unwrap_or(0)
        + chunk_deps.last().map(|d| d.offsets.len() as u32).unwrap_or(0);

    // Build DepsStorage::Chunked — avoids the expensive O(n) rebuild_compact_deps.
    // Group patch_edges by source line (sorted) for efficient binary-search lookup.
    use rustc_hash::FxHashMap as PatchMap;
    let mut patch_map: PatchMap<u32, Vec<u32>> = PatchMap::default();
    for &(from, to) in &all_patch_edges {
        patch_map.entry(from).or_default().push(to);
    }
    // Dedup within each group (same logic as rebuild_compact_deps used push_unique)
    for deps in patch_map.values_mut() {
        deps.sort_unstable();
        deps.dedup();
    }
    let mut patch_groups: Vec<(u32, Vec<u32>)> = patch_map.into_iter().collect();
    patch_groups.sort_unstable_by_key(|&(line, _)| line);

    let merged_deps = crate::scanner::DepsStorage::Chunked {
        chunks: chunk_deps,
        chunk_start_lines: chunk_start_lines.clone(),
        patch_groups,
    };
    drop(all_patch_edges); // Free patch edges

    eprintln!("[perf] DepsStorage::Chunked built (skipped rebuild_compact_deps): {:?}", phase2_timer.elapsed());

    if let Some(ref cb) = progress_fn { cb(0.70); }

    let t = std::time::Instant::now();
    // CallTree
    let call_tree = replay_call_tree_events(&all_call_events, total_lines);

    // Gumtrace annotations
    let (call_annotations, extra_consumed) = if format == TraceFormat::Gumtrace {
        replay_gumtrace_annotations(&all_gumtrace_events)
    } else {
        (HashMap::new(), Vec::new())
    };

    eprintln!("[perf] CallTree + annotations: {:?}", t.elapsed());

    if let Some(ref cb) = progress_fn { cb(0.73); }

    let t = std::time::Instant::now();
    // consumed_seqs
    all_consumed_seqs.extend(extra_consumed);
    all_consumed_seqs.sort_unstable();

    // MemAccessIndex — 逐 chunk 合并（0.75-0.85）
    let total_mem_chunks = chunk_mem_indices.len();
    let mem_accesses = {
        let mut merged = MemAccessIndex::new();
        for (ci, chunk_idx) in chunk_mem_indices.into_iter().enumerate() {
            for (addr, record) in chunk_idx.iter_all() {
                merged.add(addr, record.clone());
            }
            if let Some(ref cb) = progress_fn {
                cb(0.75 + 0.10 * (ci + 1) as f64 / total_mem_chunks as f64);
            }
        }
        merged
    };

    eprintln!("[perf] MemAccessIndex merge: {:?} ({} addresses, {} records)",
        t.elapsed(), mem_accesses.total_addresses(), mem_accesses.total_records());

    if let Some(ref cb) = progress_fn { cb(0.85); }

    // RegCheckpoints: merge all snapshots
    let merged_ckpts = {
        let mut all_snapshots = Vec::new();
        for ckpt in chunk_reg_ckpts {
            all_snapshots.extend(ckpt.snapshots);
        }
        RegCheckpoints {
            interval: 1000,
            snapshots: all_snapshots,
        }
    };

    let t = std::time::Instant::now();
    // StringIndex — 从 scan_chunk 收集的内存访问记录精确构建（0.85-0.97）
    // 记录已按 chunk 顺序排列（每个 chunk 内部是 seq 顺序），直接逐 chunk 处理
    // = 全局 seq 顺序，无需排序
    let string_index = if !skip_strings {
        let total_accesses: usize = chunk_string_accesses.iter().map(|w| w.len()).sum();
        let report_interval = (total_accesses / 100).max(1);
        let mut processed = 0usize;

        let estimated_pages = {
            let mut min_addr = u64::MAX;
            let mut max_addr = 0u64;
            for chunk in &chunk_string_accesses {
                for &(addr, _, _, _, _) in chunk {
                    min_addr = min_addr.min(addr);
                    max_addr = max_addr.max(addr);
                }
            }
            if max_addr > min_addr {
                ((max_addr - min_addr) / 4096 + 1) as usize
            } else {
                1024
            }
        };
        let mut sb = crate::query::strings::StringBuilder::with_capacity(estimated_pages);
        for chunk_accesses in chunk_string_accesses.into_iter() {
            for &(addr, data, size, seq, rw) in &chunk_accesses {
                sb.process_access(addr, data, size, seq, rw);
                processed += 1;
                if processed % report_interval == 0 {
                    // Check cancellation
                    if let Some(flag) = cancel_flag {
                        if flag.load(std::sync::atomic::Ordering::Relaxed) {
                            return Err(crate::error::TraceError::Cancelled);
                        }
                    }
                    if let Some(ref cb) = progress_fn {
                        cb(0.85 + 0.12 * (processed as f64 / total_accesses as f64));
                    }
                }
            }
            // chunk_accesses 在这里 drop，释放内存
        }

        if let Some(ref cb) = progress_fn { cb(0.97); }

        let t2 = std::time::Instant::now();
        let si = sb.finish();
        eprintln!("[perf] StringBuilder.finish(): {:?} ({} strings)", t2.elapsed(), si.strings.len());

        eprintln!("[perf] StringIndex total (build+finish, xref deferred): {:?}", t.elapsed());
        si
    } else {
        Default::default()
    };

    // LineIndex
    let line_index = merge_line_indices(chunk_line_indices);

    // init_mem_loads
    let init_mem_loads = merge_init_mem_loads(chunk_inits, &init_corrections);

    // pair_split
    let pair_split = merge_pair_splits(chunk_pair_splits, all_pair_fixups);

    if let Some(ref cb) = progress_fn { cb(0.98); }

    // Build ScanState — use pre-compacted sorted Vec (already freed HashMap in Pass 1)
    let mem_last_def_map = MemLastDef::Sorted(global_mem_sorted);

    let scan_state = ScanState {
        reg_last_def: global_reg_last_def,
        mem_last_def: mem_last_def_map,
        last_cond_branch: global_last_cond_branch,
        deps: merged_deps,
        line_count: total_lines,
        parsed_count: total_parsed_count,
        mem_op_count: total_mem_op_count,
        resolved_targets: FxHashMap::default(),
        unknown_mnemonics: FxHashMap::default(),
        init_mem_loads,
        pair_split,
    };

    let phase2 = Phase2State {
        call_tree,
        mem_accesses,
        reg_checkpoints: merged_ckpts,
        string_index,
    };

    if let Some(ref cb) = progress_fn { cb(1.0); }

    Ok(ScanResult {
        scan_state,
        phase2,
        line_index,
        format,
        call_annotations,
        consumed_seqs: all_consumed_seqs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use smallvec::smallvec;

    #[test]
    fn test_resolve_load_passthrough() {
        let mut global_mem = FxHashMap::default();
        for i in 0..8u64 {
            global_mem.insert(0x8000 + i, (10u32, 0x42u64));
        }
        let load = UnresolvedLoad {
            line: 20,
            addr: 0x8000,
            width: 8,
            load_value: Some(0x42),
            uses: smallvec![RegId(1), RegId(2)],
        };
        let mut global_reg = RegLastDef::new();
        global_reg.insert(RegId(1), 5);
        global_reg.insert(RegId(2), 8);

        let mut patch_edges = Vec::new();
        let mut init_corrections = Vec::new();
        resolve_unresolved_load(
            &load,
            &global_mem,
            &global_reg,
            &mut patch_edges,
            &mut init_corrections,
        );

        // Pass-through: only memory dep (one unique store line), no register deps
        assert!(patch_edges.iter().all(|&(from, _)| from == 20));
        assert!(patch_edges.iter().any(|&(_, to)| to == 10)); // mem dep
        assert!(!patch_edges.iter().any(|&(_, to)| to == 5)); // no reg dep x1
        assert!(!patch_edges.iter().any(|&(_, to)| to == 8)); // no reg dep x2
        assert_eq!(init_corrections, vec![(20, false)]);
    }

    #[test]
    fn test_resolve_load_not_passthrough_different_value() {
        let mut global_mem = FxHashMap::default();
        for i in 0..8u64 {
            global_mem.insert(0x8000 + i, (10u32, 0x99u64));
        }
        let load = UnresolvedLoad {
            line: 20,
            addr: 0x8000,
            width: 8,
            load_value: Some(0x42), // != 0x99
            uses: smallvec![RegId(1)],
        };
        let mut global_reg = RegLastDef::new();
        global_reg.insert(RegId(1), 5);

        let mut patch_edges = Vec::new();
        let mut init_corrections = Vec::new();
        resolve_unresolved_load(
            &load,
            &global_mem,
            &global_reg,
            &mut patch_edges,
            &mut init_corrections,
        );

        assert!(patch_edges.iter().any(|&(_, to)| to == 10)); // mem dep
        assert!(patch_edges.iter().any(|&(_, to)| to == 5)); // reg dep
    }

    #[test]
    fn test_resolve_load_init_mem() {
        // No global store exists → truly initial memory
        let global_mem = FxHashMap::default();
        let load = UnresolvedLoad {
            line: 20,
            addr: 0x8000,
            width: 4,
            load_value: None,
            uses: smallvec![RegId(1)],
        };
        let mut global_reg = RegLastDef::new();
        global_reg.insert(RegId(1), 5);

        let mut patch_edges = Vec::new();
        let mut init_corrections = Vec::new();
        resolve_unresolved_load(
            &load,
            &global_mem,
            &global_reg,
            &mut patch_edges,
            &mut init_corrections,
        );

        // No mem deps (no store found), but reg deps added (not pass-through)
        assert!(patch_edges.iter().any(|&(_, to)| to == 5));
        // init_mem_loads should NOT be corrected (it IS truly initial)
        assert!(init_corrections.is_empty());
    }

    #[test]
    fn test_resolve_partial_loads() {
        let mut global_mem = FxHashMap::default();
        global_mem.insert(0x8002u64, (15u32, 0u64));
        global_mem.insert(0x8003u64, (15u32, 0u64));

        let partials = vec![PartialUnresolvedLoad {
            line: 25,
            missing_addrs: smallvec![0x8002, 0x8003],
        }];

        let mut patch_edges = Vec::new();
        let mut init_corrections = Vec::new();
        resolve_partial_unresolved_loads(
            &partials,
            &global_mem,
            &mut patch_edges,
            &mut init_corrections,
        );

        assert!(patch_edges.iter().any(|&(from, to)| from == 25 && to == 15));
        assert_eq!(init_corrections, vec![(25, false)]);
    }

    #[test]
    fn test_resolve_pair_load() {
        let mut global_mem = FxHashMap::default();
        for i in 0..4u64 {
            global_mem.insert(0x8000 + i, (10, 0));
        }
        for i in 4..8u64 {
            global_mem.insert(0x8000 + i, (15, 0));
        }
        let mut global_reg = RegLastDef::new();
        global_reg.insert(RegId(3), 7);

        let pair = UnresolvedPairLoad {
            line: 25,
            addr: 0x8000,
            elem_width: 4,
            base_reg: Some(RegId(3)),
            defs: smallvec![RegId(0), RegId(1), RegId(3)],
        };
        let (split, _patches) = resolve_unresolved_pair_load(
            &pair,
            &global_mem,
            &global_reg,
            None,
            false,
        );
        assert!(split.half1_deps.contains(&10));
        assert!(split.half2_deps.contains(&15));
        assert!(split.shared.contains(&7));
    }

    #[test]
    fn test_resolve_reg_uses() {
        let mut global_reg = RegLastDef::new();
        global_reg.insert(RegId(5), 42);
        let uses = vec![
            UnresolvedRegUse { line: 100, reg: RegId(5) },
            UnresolvedRegUse { line: 101, reg: RegId(6) }, // not defined
        ];
        let patches = resolve_unresolved_reg_uses(&uses, &global_reg);
        assert_eq!(patches.len(), 1);
        assert_eq!(patches[0], (100, 42));
    }

    #[test]
    fn test_resolve_control_deps() {
        use bitvec::prelude::*;
        let mut needs = BitVec::new();
        // 10 lines: chunk starts at 100
        for i in 0..10 {
            needs.push(i != 3 && i != 7); // lines 103 and 107 don't need control dep
        }
        let patches = resolve_control_deps(100, Some(105), Some(95), 110, &needs, false);
        // Lines 100-104 (before first_local_cond=105), except 103
        assert!(patches.contains(&(100, 95 | CONTROL_DEP_BIT)));
        assert!(patches.contains(&(101, 95 | CONTROL_DEP_BIT)));
        assert!(patches.contains(&(102, 95 | CONTROL_DEP_BIT)));
        assert!(!patches.iter().any(|&(line, _)| line == 103)); // pair/unparsed
        assert!(patches.contains(&(104, 95 | CONTROL_DEP_BIT)));
        assert!(!patches.iter().any(|&(line, _)| line >= 105)); // after first local cond
    }

    #[test]
    fn test_rebuild_compact_deps() {
        // Chunk 0: 3 lines (lines 0,1,2)
        let mut c0 = CompactDeps::with_capacity(3, 6);
        c0.start_row(); // line 0: no deps
        c0.start_row();
        c0.push_unique(0); // line 1 → line 0
        c0.start_row();
        c0.push_unique(1); // line 2 → line 1

        // Chunk 1: 2 lines (lines 3,4)
        let mut c1 = CompactDeps::with_capacity(2, 4);
        c1.start_row(); // line 3: no local deps
        c1.start_row();
        c1.push_unique(3); // line 4 → line 3

        let patch_edges = vec![
            (3u32, 2u32), // line 3 depends on line 2 (cross-chunk)
        ];

        let merged = rebuild_compact_deps(&[c0, c1], &[0, 3], &patch_edges, None);

        // Verify
        assert_eq!(merged.row(0).len(), 0); // line 0: no deps
        assert_eq!(merged.row(1), &[0]); // line 1 → 0
        assert_eq!(merged.row(2), &[1]); // line 2 → 1

        let mut line3: Vec<u32> = merged.row(3).to_vec();
        line3.sort();
        assert_eq!(line3, vec![2]); // line 3 → 2 (from patch)

        assert_eq!(merged.row(4), &[3]); // line 4 → 3
    }

    #[test]
    fn test_rebuild_compact_deps_dedup() {
        let mut c0 = CompactDeps::with_capacity(2, 4);
        c0.start_row(); // line 0
        c0.start_row();
        c0.push_unique(0); // line 1 → 0

        // Patch also adds line 1 → 0 (duplicate)
        let patch_edges = vec![(1u32, 0u32)];

        let merged = rebuild_compact_deps(&[c0], &[0], &patch_edges, None);
        assert_eq!(merged.row(1).len(), 1); // deduped to single entry
        assert_eq!(merged.row(1), &[0]);
    }

    #[test]
    fn test_replay_call_tree_basic() {
        let events = vec![
            CallTreeEvent::Call { seq: 5, target: 0x2000 },
            CallTreeEvent::Ret { seq: 10 },
            CallTreeEvent::Call { seq: 15, target: 0x3000 },
            CallTreeEvent::Call { seq: 20, target: 0x4000 },
            CallTreeEvent::Ret { seq: 25 },
            CallTreeEvent::Ret { seq: 30 },
        ];
        let tree = replay_call_tree_events(&events, 35);
        // Root + 3 calls
        assert_eq!(tree.nodes.len(), 4);
        assert_eq!(tree.nodes[0].children_ids, vec![1, 2]);
        assert_eq!(tree.nodes[1].entry_seq, 5);
        assert_eq!(tree.nodes[1].exit_seq, 10);
        assert_eq!(tree.nodes[2].entry_seq, 15);
        assert_eq!(tree.nodes[2].children_ids, vec![3]);
        assert_eq!(tree.nodes[3].entry_seq, 20);
        assert_eq!(tree.nodes[3].exit_seq, 25);
    }

    #[test]
    fn test_replay_call_tree_blr_intercept() {
        // BLR at seq 10 with PC 0x2010, next line addr = 0x2014 = PC+4 → intercepted
        let events = vec![
            CallTreeEvent::Call { seq: 10, target: 0x3000 },
            CallTreeEvent::BlrPending { seq: 10, pc: 0x2010 },
            CallTreeEvent::LineAddr { seq: 11, addr: 0x2014 }, // PC+4 → intercepted
        ];
        let tree = replay_call_tree_events(&events, 20);
        // Root + 1 call that was immediately returned
        assert_eq!(tree.nodes.len(), 2);
        assert_eq!(tree.nodes[1].entry_seq, 10);
        assert_eq!(tree.nodes[1].exit_seq, 10); // ret at seq 10 (11-1)
    }

    #[test]
    fn test_replay_call_tree_func_name() {
        let events = vec![
            CallTreeEvent::Call { seq: 5, target: 0x2000 },
            CallTreeEvent::SetFuncName { entry_seq: 5, name: "malloc".to_string() },
            CallTreeEvent::Ret { seq: 10 },
        ];
        let tree = replay_call_tree_events(&events, 15);
        assert_eq!(tree.nodes[1].func_name, Some("malloc".to_string()));
    }

    #[test]
    fn test_replay_gumtrace_annotations() {
        let events = vec![
            GumtraceAnnotEvent::BranchInstr { seq: 10 },
            GumtraceAnnotEvent::SpecialLine {
                seq: 11,
                special: SpecialLineData::CallFunc {
                    name: "strcmp".to_string(),
                    is_jni: false,
                    raw: "call func: strcmp".to_string(),
                },
            },
            GumtraceAnnotEvent::SpecialLine {
                seq: 12,
                special: SpecialLineData::Arg {
                    index: "0".to_string(),
                    value: "0x1234".to_string(),
                    raw: "args0: 0x1234".to_string(),
                },
            },
            GumtraceAnnotEvent::SpecialLine {
                seq: 13,
                special: SpecialLineData::Ret {
                    value: "0".to_string(),
                    raw: "ret: 0".to_string(),
                },
            },
        ];

        let (annotations, extra) = replay_gumtrace_annotations(&events);
        assert_eq!(annotations.len(), 1);
        assert!(annotations.contains_key(&10));
        let ann = &annotations[&10];
        assert_eq!(ann.func_name, "strcmp");
        assert_eq!(ann.args.len(), 1);
        assert_eq!(ann.ret_value, Some("0".to_string()));
        assert!(extra.is_empty());
    }

    #[test]
    fn test_replay_gumtrace_orphan_lines() {
        let events = vec![
            GumtraceAnnotEvent::BranchInstr { seq: 5 },
            GumtraceAnnotEvent::SpecialLine {
                seq: 6,
                special: SpecialLineData::CallFunc {
                    name: "test".to_string(),
                    is_jni: false,
                    raw: "call func: test".to_string(),
                },
            },
            GumtraceAnnotEvent::OrphanLine { seq: 7 }, // unrecognized line while annotation active
            GumtraceAnnotEvent::SpecialLine {
                seq: 8,
                special: SpecialLineData::Ret {
                    value: "1".to_string(),
                    raw: "ret: 1".to_string(),
                },
            },
        ];

        let (annotations, extra) = replay_gumtrace_annotations(&events);
        assert_eq!(annotations.len(), 1);
        assert_eq!(extra, vec![7]); // orphan line added to consumed
    }

    #[test]
    fn test_fix_reg_checkpoints() {
        use crate::query::registers::RegCheckpoints;
        let mut ckpts = RegCheckpoints::new(1000);
        let mut vals = [u64::MAX; RegId::COUNT];
        ckpts.save_checkpoint(&vals);  // first checkpoint: all unknown
        vals[0] = 0x55;
        ckpts.save_checkpoint(&vals);  // second: x0 = 0x55, rest unknown

        let mut prev_final = [u64::MAX; RegId::COUNT];
        prev_final[0] = 0x42;
        prev_final[1] = 0x99;

        fix_reg_checkpoints(&mut ckpts, &prev_final);

        assert_eq!(ckpts.snapshots[0].0[0], 0x42); // was MAX, now prev value
        assert_eq!(ckpts.snapshots[0].0[1], 0x99); // was MAX, now prev value
        assert_eq!(ckpts.snapshots[1].0[0], 0x55); // was set in chunk, kept
        assert_eq!(ckpts.snapshots[1].0[1], 0x99); // was MAX, now prev value
    }

    #[test]
    fn test_merge_init_mem_loads() {
        use bitvec::prelude::*;
        let mut b1: BitVec = BitVec::new();
        b1.push(true); b1.push(false); b1.push(true);
        let mut b2: BitVec = BitVec::new();
        b2.push(false); b2.push(true);

        let corrections = vec![(0u32, false), (4, false)]; // clear bits 0 and 4

        let merged = merge_init_mem_loads(vec![b1, b2], &corrections);
        assert_eq!(merged.len(), 5);
        assert_eq!(merged[0], false); // corrected from true
        assert_eq!(merged[1], false); // original
        assert_eq!(merged[2], true);  // original
        assert_eq!(merged[3], false); // original
        assert_eq!(merged[4], false); // corrected from true
    }

    #[test]
    fn test_merge_mem_access_indices() {
        use crate::query::mem_access::{MemAccessIndex, MemAccessRecord, MemRw};
        let mut idx1 = MemAccessIndex::new();
        idx1.add(0x1000, MemAccessRecord { seq: 1, insn_addr: 0x100, rw: MemRw::Read, data: 0, size: 4 });
        let mut idx2 = MemAccessIndex::new();
        idx2.add(0x1000, MemAccessRecord { seq: 5, insn_addr: 0x200, rw: MemRw::Write, data: 42, size: 4 });
        idx2.add(0x2000, MemAccessRecord { seq: 6, insn_addr: 0x204, rw: MemRw::Read, data: 0, size: 1 });

        let merged = merge_mem_access_indices(vec![idx1, idx2]);
        assert_eq!(merged.total_addresses(), 2);
        assert_eq!(merged.total_records(), 3);
        let records_at_1000 = merged.get(0x1000).unwrap();
        assert_eq!(records_at_1000.len(), 2);
    }

    #[test]
    fn test_merge_string_indices() {
        use crate::query::strings::{StringIndex, StringRecord, StringEncoding, StringRw};
        let idx1 = StringIndex {
            strings: vec![
                StringRecord { addr: 0x1000, content: "hello".to_string(), encoding: StringEncoding::Ascii, byte_len: 5, seq: 10, xref_count: 0, rw: StringRw::Write },
                StringRecord { addr: 0x2000, content: "world".to_string(), encoding: StringEncoding::Ascii, byte_len: 5, seq: 30, xref_count: 0, rw: StringRw::Write },
            ],
        };
        let idx2 = StringIndex {
            strings: vec![
                StringRecord { addr: 0x3000, content: "foo".to_string(), encoding: StringEncoding::Ascii, byte_len: 3, seq: 20, xref_count: 0, rw: StringRw::Write },
            ],
        };

        let merged = merge_string_indices(vec![idx1, idx2]);
        assert_eq!(merged.strings.len(), 3);
        // sorted by seq
        assert_eq!(merged.strings[0].seq, 10);
        assert_eq!(merged.strings[1].seq, 20);
        assert_eq!(merged.strings[2].seq, 30);
    }

    #[test]
    fn test_merge_pair_splits() {
        let mut c1: FxHashMap<u32, PairSplitDeps> = FxHashMap::default();
        c1.insert(10, PairSplitDeps::default());
        let mut c2: FxHashMap<u32, PairSplitDeps> = FxHashMap::default();
        c2.insert(20, PairSplitDeps::default());

        let fixups = vec![(30u32, PairSplitDeps::default())];

        let merged = merge_pair_splits(vec![c1, c2], fixups);
        assert_eq!(merged.len(), 3);
        assert!(merged.contains_key(&10));
        assert!(merged.contains_key(&20));
        assert!(merged.contains_key(&30));
    }
}
