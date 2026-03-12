use std::collections::VecDeque;
use std::io::Write;

use anyhow::Result;
use bitvec::prelude::*;
use rustc_hash::FxHashMap;

use crate::taint::scanner::{ScanState, PAIR_HALF2_BIT, PAIR_SHARED_BIT, LINE_MASK, PairSplitDeps};

/// BFS backward slice: given starting line indices, mark all transitively
/// reachable lines in the dependency graph.
///
/// Supports bit-tagged pair precision:
/// - bit 31 (PAIR_HALF2_BIT): arrive via second half of pair instruction
/// - bit 30 (PAIR_SHARED_BIT): arrive via shared path (writeback base)
/// - no tag: arrive via first half of pair instruction
///
/// Returns a bitvec where `marked[i] == true` means line `i` is in the slice.
pub fn bfs_slice(state: &ScanState, start_indices: &[u32]) -> BitVec {
    let n = state.line_count as usize;
    let mut marked = bitvec![0; n];
    let mut queue: VecDeque<u32> = VecDeque::new();
    // For pair lines: bit 0 = half1 visited, bit 1 = half2 visited, bit 2 = shared visited
    let mut pair_visited: FxHashMap<u32, u8> = FxHashMap::default();

    // Seed the BFS (start_indices may carry tag bits)
    for &raw in start_indices {
        enqueue_dep(raw, n, &mut queue, &mut marked, &mut pair_visited, &state.pair_split);
    }

    // BFS: follow dependency edges backward
    while let Some(raw) = queue.pop_front() {
        let line = raw & LINE_MASK;

        if let Some(split) = state.pair_split.get(&line) {
            // Pair instruction: determine which deps to follow based on arrival tag
            if (raw & PAIR_SHARED_BIT) != 0 {
                // Shared arrival (via writeback base): follow only shared deps
                for &dep in &split.shared {
                    enqueue_dep(dep, n, &mut queue, &mut marked, &mut pair_visited, &state.pair_split);
                }
            } else {
                // Data arrival: follow shared + relevant half deps
                for &dep in &split.shared {
                    enqueue_dep(dep, n, &mut queue, &mut marked, &mut pair_visited, &state.pair_split);
                }
                let half_deps = if (raw & PAIR_HALF2_BIT) != 0 {
                    &split.half2_deps
                } else {
                    &split.half1_deps
                };
                for &dep in half_deps {
                    enqueue_dep(dep, n, &mut queue, &mut marked, &mut pair_visited, &state.pair_split);
                }
            }
        } else {
            // Non-pair instruction: follow all deps (deps may carry tags)
            for &dep in &state.deps[line as usize] {
                enqueue_dep(dep, n, &mut queue, &mut marked, &mut pair_visited, &state.pair_split);
            }
        }
    }

    marked
}

/// Try to enqueue a (potentially tagged) dependency into the BFS queue.
///
/// For pair lines, tracks half1/half2/shared visits separately via `pair_visited`.
/// For non-pair lines, uses the `marked` bitvec to prevent re-visits.
fn enqueue_dep(
    raw: u32,
    n: usize,
    queue: &mut VecDeque<u32>,
    marked: &mut BitVec,
    pair_visited: &mut FxHashMap<u32, u8>,
    pair_split: &FxHashMap<u32, PairSplitDeps>,
) {
    let line = raw & LINE_MASK;
    if (line as usize) >= n {
        return;
    }

    if pair_split.contains_key(&line) {
        // Determine which visit bit: half1=1, half2=2, shared=4
        let visit_bit = if (raw & PAIR_SHARED_BIT) != 0 {
            4u8
        } else if (raw & PAIR_HALF2_BIT) != 0 {
            2u8
        } else {
            1u8
        };
        let visited = pair_visited.entry(line).or_insert(0);
        if *visited & visit_bit != 0 {
            return;
        }
        *visited |= visit_bit;
    } else if marked[line as usize] {
        return;
    }

    marked.set(line as usize, true);
    queue.push_back(raw);
}

/// Pass 2: output only marked lines from already-mapped data.
///
/// Iterates with memchr (zero-copy, no UTF-8 validation).
/// Returns the number of lines written.
#[allow(dead_code)]
pub fn write_sliced_bytes<W: Write>(
    data: &[u8],
    marked: &BitVec,
    init_mem_loads: &BitVec,
    writer: &mut W,
) -> Result<u32> {
    let mut count = 0u32;
    let mut line_idx = 0usize;
    let mut pos = 0usize;
    let len = data.len();

    while pos < len {
        let line_end = match memchr::memchr(b'\n', &data[pos..]) {
            Some(p) => pos + p,
            None => len,
        };

        // Trim trailing \r
        let end = if line_end > pos && data[line_end - 1] == b'\r' {
            line_end - 1
        } else {
            line_end
        };

        if line_idx < marked.len() && marked[line_idx] {
            writer.write_all(&data[pos..end])?;
            if line_idx < init_mem_loads.len() && init_mem_loads[line_idx] {
                writer.write_all(b" ; [INIT_MEM]")?;
            }
            writer.write_all(b"\n")?;
            count += 1;
        }

        pos = if line_end < len { line_end + 1 } else { len };
        line_idx += 1;
    }

    Ok(count)
}

/// Pass 2 variant: read from a string (for testing).
#[cfg(test)]
pub fn write_sliced_from_string<W: Write>(
    trace: &str,
    marked: &BitVec,
    init_mem_loads: &BitVec,
    writer: &mut W,
) -> Result<u32> {
    write_sliced_bytes(trace.as_bytes(), marked, init_mem_loads, writer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::taint::scanner;
    use crate::taint::types::RegId;

    // =========================================================================
    // Test: BFS traverses full chain
    // =========================================================================

    #[test]
    fn test_bfs_full_chain() {
        let trace = [
            r#"[00:00:00 001][lib.so 0x100] [d2800108] 0x40000100: "mov x8, #5" => x8=0x5"#,
            r#"[00:00:00 001][lib.so 0x104] [d2800149] 0x40000104: "mov x9, #10" => x9=0xa"#,
            r#"[00:00:00 001][lib.so 0x108] [8b090108] 0x40000108: "add x0, x8, x9" x8=0x5 x9=0xa => x0=0xf"#,
        ]
        .join("\n");

        let state = scanner::scan_from_string(&trace, false).unwrap();
        let start = vec![*state.reg_last_def.get(&RegId::X0).unwrap()];
        let marked = bfs_slice(&state, &start);

        assert!(marked[0], "mov x8 should be in slice");
        assert!(marked[1], "mov x9 should be in slice");
        assert!(marked[2], "add x0 should be in slice");
    }

    // =========================================================================
    // Test: BFS excludes dead code
    // =========================================================================

    #[test]
    fn test_bfs_excludes_dead_code() {
        let trace = [
            r#"[00:00:00 001][lib.so 0x100] [d2800108] 0x40000100: "mov x8, #5" => x8=0x5"#,
            r#"[00:00:00 001][lib.so 0x104] [d280e1ef] 0x40000104: "mov x15, #999" => x15=0x3e7"#,
            r#"[00:00:00 001][lib.so 0x108] [aa0803e0] 0x40000108: "mov x0, x8" x8=0x5 => x0=0x5"#,
        ]
        .join("\n");

        let state = scanner::scan_from_string(&trace, false).unwrap();
        let start = vec![*state.reg_last_def.get(&RegId::X0).unwrap()];
        let marked = bfs_slice(&state, &start);

        assert!(marked[0], "mov x8 should be in slice");
        assert!(!marked[1], "mov x15 should NOT be in slice (dead code)");
        assert!(marked[2], "mov x0 should be in slice");
    }

    // =========================================================================
    // Test: BFS follows memory chain
    // =========================================================================

    #[test]
    fn test_bfs_memory_chain() {
        let trace = [
            r#"[00:00:00 001][lib.so 0x100] [d2800548] 0x40000100: "mov x8, #42" => x8=0x2a"#,
            r#"[00:00:00 001][lib.so 0x104] [f9000be8] 0x40000104: "str x8, [sp, #0x10]" ; mem[WRITE] abs=0xbffff010 x8=0x2a sp=0xbffff000 => x8=0x2a"#,
            r#"[00:00:00 001][lib.so 0x108] [f9400be0] 0x40000108: "ldr x0, [sp, #0x10]" ; mem[READ] abs=0xbffff010 sp=0xbffff000 => x0=0x2a"#,
        ]
        .join("\n");

        let state = scanner::scan_from_string(&trace, false).unwrap();
        let start = vec![*state.reg_last_def.get(&RegId::X0).unwrap()];
        let marked = bfs_slice(&state, &start);

        assert!(marked[0], "mov x8 should be in slice");
        assert!(marked[1], "str should be in slice");
        assert!(marked[2], "ldr should be in slice");
    }

    // =========================================================================
    // Test: BFS with multiple start points
    // =========================================================================

    #[test]
    fn test_bfs_multiple_starts() {
        let trace = [
            r#"[00:00:00 001][lib.so 0x100] [d2800108] 0x40000100: "mov x8, #5" => x8=0x5"#,
            r#"[00:00:00 001][lib.so 0x104] [d2800149] 0x40000104: "mov x9, #10" => x9=0xa"#,
            r#"[00:00:00 001][lib.so 0x108] [aa0803e0] 0x40000108: "mov x0, x8" x8=0x5 => x0=0x5"#,
            r#"[00:00:00 001][lib.so 0x10c] [aa0903e1] 0x4000010c: "mov x1, x9" x9=0xa => x1=0xa"#,
        ]
        .join("\n");

        let state = scanner::scan_from_string(&trace, false).unwrap();
        // Slice from both x0 and x1
        let start = vec![
            *state.reg_last_def.get(&RegId::X0).unwrap(),
            *state.reg_last_def.get(&RegId::X1).unwrap(),
        ];
        let marked = bfs_slice(&state, &start);

        assert!(marked[0], "mov x8 should be in slice (via x0)");
        assert!(marked[1], "mov x9 should be in slice (via x1)");
        assert!(marked[2], "mov x0 should be in slice (start)");
        assert!(marked[3], "mov x1 should be in slice (start)");
    }

    // =========================================================================
    // Test: BFS handles empty deps
    // =========================================================================

    #[test]
    fn test_bfs_single_line_no_deps() {
        let trace = r#"[00:00:00 001][lib.so 0x100] [d2800108] 0x40000100: "mov x0, #5" => x0=0x5"#;

        let state = scanner::scan_from_string(trace, false).unwrap();
        let start = vec![0u32];
        let marked = bfs_slice(&state, &start);

        assert_eq!(marked.len(), 1);
        assert!(marked[0]);
    }

    // =========================================================================
    // Test: BFS with empty start returns nothing
    // =========================================================================

    #[test]
    fn test_bfs_empty_start() {
        let trace = r#"[00:00:00 001][lib.so 0x100] [d2800108] 0x40000100: "mov x0, #5" => x0=0x5"#;

        let state = scanner::scan_from_string(trace, false).unwrap();
        let marked = bfs_slice(&state, &[]);

        assert_eq!(marked.count_ones(), 0);
    }

    // =========================================================================
    // Test: write_sliced outputs only marked lines
    // =========================================================================

    #[test]
    fn test_write_sliced_output() {
        let trace = [
            r#"[00:00:00 001][lib.so 0x100] [d2800108] 0x40000100: "mov x8, #5" => x8=0x5"#,
            r#"[00:00:00 001][lib.so 0x104] [d280e1ef] 0x40000104: "mov x15, #999" => x15=0x3e7"#,
            r#"[00:00:00 001][lib.so 0x108] [aa0803e0] 0x40000108: "mov x0, x8" x8=0x5 => x0=0x5"#,
        ]
        .join("\n");

        let state = scanner::scan_from_string(&trace, false).unwrap();
        let start = vec![*state.reg_last_def.get(&RegId::X0).unwrap()];
        let marked = bfs_slice(&state, &start);

        let mut output = Vec::new();
        let empty_init = BitVec::repeat(false, state.line_count as usize);
        let count = write_sliced_from_string(&trace, &marked, &empty_init, &mut output).unwrap();

        assert_eq!(count, 2); // mov x8 + mov x0 (x15 excluded)
        let output_str = String::from_utf8(output).unwrap();
        assert!(output_str.contains("mov x8, #5"));
        assert!(!output_str.contains("mov x15, #999"));
        assert!(output_str.contains("mov x0, x8"));
    }

    // =========================================================================
    // Test: diamond dependency (two paths to same root)
    // =========================================================================

    #[test]
    fn test_bfs_diamond_dependency() {
        // x8 = 5 (line 0)
        // x9 = x8 (line 1, depends on 0)
        // x10 = x8 (line 2, depends on 0)
        // x0 = x9 + x10 (line 3, depends on 1 and 2)
        let trace = [
            r#"[00:00:00 001][lib.so 0x100] [d2800108] 0x40000100: "mov x8, #5" => x8=0x5"#,
            r#"[00:00:00 001][lib.so 0x104] [aa0803e9] 0x40000104: "mov x9, x8" x8=0x5 => x9=0x5"#,
            r#"[00:00:00 001][lib.so 0x108] [aa0803ea] 0x40000108: "mov x10, x8" x8=0x5 => x10=0x5"#,
            r#"[00:00:00 001][lib.so 0x10c] [8b0a0120] 0x4000010c: "add x0, x9, x10" x9=0x5 x10=0x5 => x0=0xa"#,
        ]
        .join("\n");

        let state = scanner::scan_from_string(&trace, false).unwrap();
        let start = vec![*state.reg_last_def.get(&RegId::X0).unwrap()];
        let marked = bfs_slice(&state, &start);

        // All 4 lines should be in the slice
        assert!(marked[0], "mov x8 should be in slice (root)");
        assert!(marked[1], "mov x9 should be in slice");
        assert!(marked[2], "mov x10 should be in slice");
        assert!(marked[3], "add x0 should be in slice");
    }

    // =========================================================================
    // Test: INIT_MEM annotation appears for initial memory load
    // =========================================================================

    #[test]
    fn test_write_sliced_init_mem_annotation() {
        let trace = r#"[00:00:00 001][lib.so 0x100] [f9400be0] 0x40000100: "ldr x0, [sp]" ; mem[READ] abs=0xbffff000 sp=0xbffff000 => x0=0x2a"#;
        let state = scanner::scan_from_string(trace, true).unwrap();
        let start = vec![0u32];
        let marked = bfs_slice(&state, &start);

        let mut output = Vec::new();
        write_sliced_from_string(trace, &marked, &state.init_mem_loads, &mut output).unwrap();
        let output_str = String::from_utf8(output).unwrap();
        assert!(output_str.contains("; [INIT_MEM]"), "should have INIT_MEM annotation");
    }

    // =========================================================================
    // Test: no INIT_MEM annotation for load from previously-stored address
    // =========================================================================

    #[test]
    fn test_write_sliced_no_init_mem_for_stored() {
        let trace = [
            r#"[00:00:00 001][lib.so 0x100] [d2800548] 0x40000100: "mov x8, #42" => x8=0x2a"#,
            r#"[00:00:00 001][lib.so 0x104] [f9000be8] 0x40000104: "str x8, [sp, #0x10]" ; mem[WRITE] abs=0xbffff010 x8=0x2a sp=0xbffff000 => x8=0x2a"#,
            r#"[00:00:00 001][lib.so 0x108] [f9400be0] 0x40000108: "ldr x0, [sp, #0x10]" ; mem[READ] abs=0xbffff010 sp=0xbffff000 => x0=0x2a"#,
        ].join("\n");
        let state = scanner::scan_from_string(&trace, true).unwrap();
        let start = vec![*state.reg_last_def.get(&RegId::X0).unwrap()];
        let marked = bfs_slice(&state, &start);

        let mut output = Vec::new();
        write_sliced_from_string(&trace, &marked, &state.init_mem_loads, &mut output).unwrap();
        let output_str = String::from_utf8(output).unwrap();
        assert!(!output_str.contains("; [INIT_MEM]"), "should NOT have INIT_MEM annotation for stored memory");
    }
}
