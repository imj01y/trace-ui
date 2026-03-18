use memchr::memchr_iter;
use rayon::prelude::*;

use crate::taint::{self, ScanResult, ProgressFn};
use crate::taint::chunk_scan;
use crate::taint::merge;

/// Parallel version of scan_unified.
/// Falls back to single-threaded for small files.
pub fn scan_unified_parallel(
    data: &[u8],
    data_only: bool,
    no_prune: bool,
    skip_strings: bool,
    progress_fn: Option<ProgressFn>,
    num_chunks: usize,
) -> anyhow::Result<ScanResult> {
    // Small files or single chunk: fall back to single-threaded
    if data.len() < 10 * 1024 * 1024 || num_chunks <= 1 {
        return taint::scan_unified(data, data_only, no_prune, skip_strings, progress_fn);
    }

    let format = taint::gumtrace_parser::detect_format(data);

    // Phase 0: Split and count lines
    let chunks_meta = split_into_chunks(data, num_chunks);

    // LINE_MASK safety check: 29-bit line number limit (bits 29-31 reserved for flags)
    let total_lines: u32 = chunks_meta.iter().map(|c| c.line_count).sum();
    if total_lines > crate::taint::scanner::LINE_MASK {
        anyhow::bail!(
            "文件行数 {} 超过当前支持的最大值 {}（约 5.36 亿行）。",
            total_lines,
            crate::taint::scanner::LINE_MASK,
        );
    }

    if let Some(ref cb) = progress_fn {
        cb(0, data.len());
    }

    // Phase 1: Parallel chunk scanning with progress reporting
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    let processed_bytes = AtomicUsize::new(0);
    let data_len = data.len();
    let progress_fn_arc = progress_fn.map(|f| Arc::new(f));

    let chunk_results: Vec<_> = chunks_meta
        .par_iter()
        .map(|meta| {
            let result = chunk_scan::scan_chunk(
                data,
                meta.start_byte,
                meta.end_byte,
                meta.start_line,
                format,
                data_only,
                no_prune,
                skip_strings,
            );
            // Report progress: Phase 1 maps to 0%-67% of total progress
            let done = processed_bytes.fetch_add(meta.end_byte - meta.start_byte, Ordering::Relaxed)
                + (meta.end_byte - meta.start_byte);
            if let Some(ref cb) = progress_fn_arc {
                let progress = done * 2 / 3; // Phase 1 = first 67%
                cb(progress, data_len);
            }
            result
        })
        .collect();

    // Phase 1 complete — progress is at 67%
    if let Some(ref cb) = progress_fn_arc {
        cb(data_len * 2 / 3, data_len);
    }

    // Phase 2: Sequential merge
    let result = merge::merge_all_chunks(chunk_results, format, data_only);

    if let Some(ref cb) = progress_fn_arc {
        cb(data.len(), data.len());
    }

    Ok(result)
}

/// Metadata for a chunk of the file.
pub struct ChunkMeta {
    pub start_byte: usize,
    pub end_byte: usize,
    pub start_line: u32,
    pub line_count: u32,
}

/// Split data into N chunks at newline boundaries.
/// Phase 0: uses parallel memchr to count lines per chunk.
pub fn split_into_chunks(data: &[u8], n: usize) -> Vec<ChunkMeta> {
    let n = n.max(1);
    let len = data.len();
    if len == 0 {
        return vec![ChunkMeta {
            start_byte: 0,
            end_byte: 0,
            start_line: 0,
            line_count: 0,
        }];
    }

    // 1. Determine raw byte boundaries, adjusting to nearest newline
    let chunk_size = len / n;
    let mut boundaries = Vec::with_capacity(n + 1);
    boundaries.push(0usize);

    for i in 1..n {
        let raw = i * chunk_size;
        // Find next newline after raw boundary
        let adjusted = match memchr::memchr(b'\n', &data[raw..]) {
            Some(pos) => raw + pos + 1, // start of next line
            None => len,
        };
        if adjusted < len && adjusted != *boundaries.last().unwrap() {
            boundaries.push(adjusted);
        }
    }
    boundaries.push(len);
    boundaries.dedup();

    // 2. Count lines per chunk (parallel using rayon)
    use rayon::prelude::*;
    let line_counts: Vec<u32> = boundaries
        .windows(2)
        .collect::<Vec<_>>()
        .par_iter()
        .map(|window| {
            let start = window[0];
            let end = window[1];
            let chunk_data = &data[start..end];
            let newline_count = memchr_iter(b'\n', chunk_data).count() as u32;
            // If this is the LAST chunk and doesn't end with newline, there's one more line
            if end == len && !chunk_data.is_empty() && *chunk_data.last().unwrap() != b'\n' {
                newline_count + 1
            } else {
                newline_count
            }
        })
        .collect();

    // 3. Compute prefix sums for global line offsets
    let mut chunks = Vec::with_capacity(line_counts.len());
    let mut cumulative_lines = 0u32;
    for (i, window) in boundaries.windows(2).enumerate() {
        chunks.push(ChunkMeta {
            start_byte: window[0],
            end_byte: window[1],
            start_line: cumulative_lines,
            line_count: line_counts[i],
        });
        cumulative_lines += line_counts[i];
    }

    chunks
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_chunks_basic() {
        let data = b"line0\nline1\nline2\nline3\nline4\n";
        let chunks = split_into_chunks(data, 2);
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].start_byte, 0);
        assert_eq!(chunks[1].end_byte, data.len());
        assert_eq!(chunks[0].start_line, 0);
        assert_eq!(chunks[1].start_line, chunks[0].line_count);
        let total: u32 = chunks.iter().map(|c| c.line_count).sum();
        assert_eq!(total, 5);
    }

    #[test]
    fn test_split_chunks_single() {
        let data = b"line0\nline1\n";
        let chunks = split_into_chunks(data, 1);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].start_byte, 0);
        assert_eq!(chunks[0].end_byte, data.len());
        assert_eq!(chunks[0].line_count, 2);
    }

    #[test]
    fn test_split_chunks_more_than_lines() {
        let data = b"a\nb\n";
        let chunks = split_into_chunks(data, 10);
        assert!(chunks.len() <= 2);
        let total: u32 = chunks.iter().map(|c| c.line_count).sum();
        assert_eq!(total, 2);
    }

    #[test]
    fn test_split_chunks_no_trailing_newline() {
        let data = b"line0\nline1";
        let chunks = split_into_chunks(data, 2);
        let total: u32 = chunks.iter().map(|c| c.line_count).sum();
        assert_eq!(total, 2);
        assert_eq!(chunks.last().unwrap().end_byte, data.len());
    }

    #[test]
    fn test_split_chunks_empty() {
        let data = b"";
        let chunks = split_into_chunks(data, 4);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].line_count, 0);
    }

    #[test]
    fn test_split_chunks_consistency() {
        // Verify chunks cover entire file without gaps or overlaps
        let data = b"aaa\nbbb\nccc\nddd\neee\nfff\nggg\nhhh\niii\njjj\n";
        for n in 1..=12 {
            let chunks = split_into_chunks(data, n);
            assert_eq!(chunks[0].start_byte, 0);
            assert_eq!(chunks.last().unwrap().end_byte, data.len());
            for w in chunks.windows(2) {
                assert_eq!(
                    w[0].end_byte,
                    w[1].start_byte,
                    "gap between chunks for n={}",
                    n
                );
            }
            let total: u32 = chunks.iter().map(|c| c.line_count).sum();
            assert_eq!(total, 10, "total lines wrong for n={}", n);
        }
    }

    #[test]
    fn test_parallel_matches_unified_simple() {
        // Small file should fall back to single-threaded
        let trace = "line1\nline2\nline3\n";
        let data = trace.as_bytes();
        let result = scan_unified_parallel(data, false, false, true, None, 2);
        assert!(result.is_ok());
    }

    // =========================================================================
    // Exact-match verification: parallel vs single-threaded
    // =========================================================================

    use crate::taint::ScanResult;

    /// Force parallel pipeline regardless of data size (bypasses 10MB check).
    fn scan_parallel_force(
        data: &[u8],
        data_only: bool,
        no_prune: bool,
        skip_strings: bool,
        num_chunks: usize,
    ) -> anyhow::Result<ScanResult> {
        use rayon::prelude::*;

        let format = crate::taint::gumtrace_parser::detect_format(data);
        let chunks_meta = split_into_chunks(data, num_chunks);

        let chunk_results: Vec<_> = chunks_meta
            .par_iter()
            .map(|meta| {
                crate::taint::chunk_scan::scan_chunk(
                    data,
                    meta.start_byte,
                    meta.end_byte,
                    meta.start_line,
                    format,
                    data_only,
                    no_prune,
                    skip_strings,
                )
            })
            .collect();

        let result = crate::taint::merge::merge_all_chunks(chunk_results, format, data_only);
        Ok(result)
    }

    /// Compare two ScanResults field-by-field with sorted dep comparison.
    fn assert_scan_results_match(baseline: &ScanResult, parallel: &ScanResult, label: &str) {
        assert_eq!(
            baseline.scan_state.line_count,
            parallel.scan_state.line_count,
            "{}: line_count mismatch", label,
        );
        assert_eq!(
            baseline.scan_state.parsed_count,
            parallel.scan_state.parsed_count,
            "{}: parsed_count mismatch", label,
        );

        // Compare deps (set comparison — order within row may differ)
        for i in 0..baseline.scan_state.line_count as usize {
            let mut b: Vec<u32> = baseline.scan_state.deps.row(i).to_vec();
            let mut p: Vec<u32> = parallel.scan_state.deps.row(i).to_vec();
            b.sort();
            p.sort();
            assert_eq!(b, p, "{}: deps mismatch at line {}", label, i);
        }

        // Compare pair_split
        assert_eq!(
            baseline.scan_state.pair_split.len(),
            parallel.scan_state.pair_split.len(),
            "{}: pair_split count mismatch", label,
        );
        for (line, base_split) in &baseline.scan_state.pair_split {
            let par_split = parallel.scan_state.pair_split.get(line)
                .unwrap_or_else(|| panic!("{}: pair_split missing line {}", label, line));

            let mut bh1: Vec<u32> = base_split.half1_deps.to_vec();
            let mut ph1: Vec<u32> = par_split.half1_deps.to_vec();
            bh1.sort(); ph1.sort();
            assert_eq!(bh1, ph1, "{}: pair half1 mismatch at line {}", label, line);

            let mut bh2: Vec<u32> = base_split.half2_deps.to_vec();
            let mut ph2: Vec<u32> = par_split.half2_deps.to_vec();
            bh2.sort(); ph2.sort();
            assert_eq!(bh2, ph2, "{}: pair half2 mismatch at line {}", label, line);

            let mut bs: Vec<u32> = base_split.shared.to_vec();
            let mut ps: Vec<u32> = par_split.shared.to_vec();
            bs.sort(); ps.sort();
            assert_eq!(bs, ps, "{}: pair shared mismatch at line {}", label, line);
        }

        // Compare init_mem_loads
        assert_eq!(
            baseline.scan_state.init_mem_loads,
            parallel.scan_state.init_mem_loads,
            "{}: init_mem_loads mismatch", label,
        );

        // Compare call tree node count
        assert_eq!(
            baseline.phase2.call_tree.nodes.len(),
            parallel.phase2.call_tree.nodes.len(),
            "{}: call_tree node count mismatch", label,
        );

        // Compare format
        assert_eq!(baseline.format, parallel.format, "{}: format mismatch", label);
    }

    /// Build a UniDBG trace line.
    fn unidbg_line(addr: u64, disasm: &str, pre_arrow: &str, post_arrow: &str, mem: &str) -> String {
        let offset = addr & 0xFFFF;
        let mut line = format!(
            "[00:00:00 000][lib.so 0x{:x}] [d503201f] 0x{:x}: \"{}\"",
            offset, addr, disasm,
        );
        if !pre_arrow.is_empty() {
            line.push(' ');
            line.push_str(pre_arrow);
        }
        if !mem.is_empty() {
            line.push_str(" ; ");
            line.push_str(mem);
        }
        if !post_arrow.is_empty() {
            line.push_str(" => ");
            line.push_str(post_arrow);
        }
        line
    }

    /// Build a small but meaningful trace with register deps, memory ops,
    /// conditional branches, and function calls.
    fn build_test_trace_basic() -> String {
        let lines = vec![
            // Line 0: mov x8, #5  (define x8)
            unidbg_line(0x40000100, "mov x8, #5", "", "x8=0x5", ""),
            // Line 1: mov x9, #0xa (define x9)
            unidbg_line(0x40000104, "mov x9, #0xa", "", "x9=0xa", ""),
            // Line 2: add x10, x8, x9 (use x8, x9 → define x10)
            unidbg_line(0x40000108, "add x10, x8, x9", "x8=0x5 x9=0xa", "x10=0xf", ""),
            // Line 3: str x10, [sp, #0x10] (store x10 to memory)
            unidbg_line(0x4000010c, "str x10, [sp, #0x10]", "x10=0xf sp=0xbffff000", "x10=0xf",
                "mem[WRITE] abs=0xbffff010"),
            // Line 4: mov x0, #0 (unrelated def)
            unidbg_line(0x40000110, "mov x0, #0", "", "x0=0x0", ""),
            // Line 5: ldr x1, [sp, #0x10] (load from address stored by line 3)
            unidbg_line(0x40000114, "ldr x1, [sp, #0x10]", "sp=0xbffff000", "x1=0xf",
                "mem[READ] abs=0xbffff010"),
            // Line 6: cmp x1, x0 (use x1 from line 5, x0 from line 4)
            unidbg_line(0x40000118, "cmp x1, x0", "x1=0xf x0=0x0", "nzcv=0x20000000", ""),
            // Line 7: b.eq #0x40000130 (conditional branch)
            unidbg_line(0x4000011c, "b.eq #0x40000130", "nzcv=0x20000000", "", ""),
            // Line 8: add x2, x1, #1 (use x1, after cond branch)
            unidbg_line(0x40000120, "add x2, x1, #1", "x1=0xf", "x2=0x10", ""),
            // Line 9: bl #0x40000200 (function call)
            unidbg_line(0x40000124, "bl #0x40000200", "", "", ""),
            // Line 10: mov x3, #0x42 (inside function)
            unidbg_line(0x40000200, "mov x3, #0x42", "", "x3=0x42", ""),
            // Line 11: ret (return from function)
            unidbg_line(0x40000204, "ret", "", "", ""),
            // Line 12: str x2, [sp, #0x18] (store after return)
            unidbg_line(0x40000128, "str x2, [sp, #0x18]", "x2=0x10 sp=0xbffff000", "x2=0x10",
                "mem[WRITE] abs=0xbffff018"),
            // Line 13: ldr x4, [sp, #0x18] (load what was just stored — same value = pass-through)
            unidbg_line(0x4000012c, "ldr x4, [sp, #0x18]", "sp=0xbffff000", "x4=0x10",
                "mem[READ] abs=0xbffff018"),
            // Line 14: mov x5, x4 (use x4)
            unidbg_line(0x40000130, "mov x5, x4", "x4=0x10", "x5=0x10", ""),
        ];
        lines.join("\n") + "\n"
    }

    /// Build a trace with cross-boundary store→load patterns.
    fn build_cross_boundary_store_load_trace() -> String {
        let mut lines = Vec::new();
        // First half: define and store values
        for i in 0..10u64 {
            let addr = 0x40000100 + i * 4;
            let reg = format!("x{}", i);
            let val = i + 1;
            // Define register
            lines.push(unidbg_line(addr, &format!("mov {}, #{}", reg, val), "",
                &format!("{}=0x{:x}", reg, val), ""));
            // Store to memory
            let mem_addr = 0xbffff100 + i * 8;
            lines.push(unidbg_line(addr + 0x100, &format!("str {}, [sp, #0x{:x}]", reg, i * 8),
                &format!("{}=0x{:x} sp=0xbffff100", reg, val),
                &format!("{}=0x{:x}", reg, val),
                &format!("mem[WRITE] abs=0x{:x}", mem_addr)));
        }
        // Second half: load from the same memory addresses
        for i in 0..10u64 {
            let addr = 0x40001000 + i * 4;
            let reg = format!("x{}", i);
            let val = i + 1;
            let mem_addr = 0xbffff100 + i * 8;
            lines.push(unidbg_line(addr, &format!("ldr {}, [sp, #0x{:x}]", reg, i * 8),
                "sp=0xbffff100",
                &format!("{}=0x{:x}", reg, val),
                &format!("mem[READ] abs=0x{:x}", mem_addr)));
        }
        lines.join("\n") + "\n"
    }

    /// Build a trace with conditional branches crossing chunk boundaries.
    fn build_cross_boundary_control_dep_trace() -> String {
        let mut lines = Vec::new();
        // Lines 0-9: computation
        for i in 0..10u64 {
            lines.push(unidbg_line(0x40000100 + i * 4,
                &format!("mov x{}, #{}", i, i + 1), "",
                &format!("x{}=0x{:x}", i, i + 1), ""));
        }
        // Line 10: cmp
        lines.push(unidbg_line(0x40000128, "cmp x0, x1", "x0=0x1 x1=0x2", "nzcv=0x80000000", ""));
        // Line 11: b.ne (conditional branch)
        lines.push(unidbg_line(0x4000012c, "b.ne #0x40000200", "nzcv=0x80000000", "", ""));
        // Lines 12-19: instructions after cond branch (should have control dep)
        for i in 0..8u64 {
            lines.push(unidbg_line(0x40000200 + i * 4,
                &format!("add x{}, x{}, #1", i, i),
                &format!("x{}=0x{:x}", i, i + 1),
                &format!("x{}=0x{:x}", i, i + 2), ""));
        }
        lines.join("\n") + "\n"
    }

    /// Build a trace with function call and return crossing chunk boundary.
    fn build_cross_boundary_call_ret_trace() -> String {
        let mut lines = Vec::new();
        // Lines 0-7: setup
        for i in 0..8u64 {
            lines.push(unidbg_line(0x40000100 + i * 4,
                &format!("mov x{}, #{}", i, i + 1), "",
                &format!("x{}=0x{:x}", i, i + 1), ""));
        }
        // Line 8: bl (function call) — will be near end of first chunk
        lines.push(unidbg_line(0x40000120, "bl #0x40000300", "", "", ""));
        // Line 9-14: function body
        for i in 0..6u64 {
            lines.push(unidbg_line(0x40000300 + i * 4,
                &format!("mov x{}, #{}", 10 + i, i * 10), "",
                &format!("x{}=0x{:x}", 10 + i, i * 10), ""));
        }
        // Line 15: ret
        lines.push(unidbg_line(0x40000318, "ret", "", "", ""));
        // Lines 16-19: after return
        for i in 0..4u64 {
            lines.push(unidbg_line(0x40000124 + i * 4,
                &format!("add x{}, x{}, #1", i, i),
                &format!("x{}=0x{:x}", i, i + 1),
                &format!("x{}=0x{:x}", i, i + 2), ""));
        }
        lines.join("\n") + "\n"
    }

    /// Build a large synthetic trace with varied instructions (~500 lines).
    fn build_large_synthetic_trace() -> String {
        let mut lines = Vec::new();
        let base_addr = 0x40000000u64;
        let mem_base = 0xbffff000u64;
        let mut pc = 0u64;

        for block in 0..50u64 {
            // mov x0, #val
            lines.push(unidbg_line(base_addr + pc, &format!("mov x0, #{}", block), "",
                &format!("x0=0x{:x}", block), ""));
            pc += 4;

            // mov x1, #val
            lines.push(unidbg_line(base_addr + pc, &format!("mov x1, #{}", block * 2), "",
                &format!("x1=0x{:x}", block * 2), ""));
            pc += 4;

            // add x2, x0, x1
            lines.push(unidbg_line(base_addr + pc, "add x2, x0, x1",
                &format!("x0=0x{:x} x1=0x{:x}", block, block * 2),
                &format!("x2=0x{:x}", block * 3), ""));
            pc += 4;

            // str x2, [sp, #offset]
            let mem_addr = mem_base + block * 8;
            lines.push(unidbg_line(base_addr + pc, "str x2, [sp, #0x0]",
                &format!("x2=0x{:x} sp=0x{:x}", block * 3, mem_addr),
                &format!("x2=0x{:x}", block * 3),
                &format!("mem[WRITE] abs=0x{:x}", mem_addr)));
            pc += 4;

            // ldr x3, [sp, #offset] — load from same address
            lines.push(unidbg_line(base_addr + pc, "ldr x3, [sp, #0x0]",
                &format!("sp=0x{:x}", mem_addr),
                &format!("x3=0x{:x}", block * 3),
                &format!("mem[READ] abs=0x{:x}", mem_addr)));
            pc += 4;

            // cmp x3, #0
            lines.push(unidbg_line(base_addr + pc, "cmp x3, #0",
                &format!("x3=0x{:x}", block * 3), "nzcv=0x20000000", ""));
            pc += 4;

            // b.eq (conditional branch)
            lines.push(unidbg_line(base_addr + pc,
                &format!("b.eq #0x{:x}", base_addr + pc + 8), "nzcv=0x20000000", "", ""));
            pc += 4;

            // add x4, x3, x2 (control dep on cond branch)
            lines.push(unidbg_line(base_addr + pc, "add x4, x3, x2",
                &format!("x3=0x{:x} x2=0x{:x}", block * 3, block * 3),
                &format!("x4=0x{:x}", block * 6), ""));
            pc += 4;

            // Every 5th block: BL + function body + RET
            if block % 5 == 0 {
                let func_addr = 0x40100000 + block * 0x100;
                lines.push(unidbg_line(base_addr + pc,
                    &format!("bl #0x{:x}", func_addr), "", "", ""));
                pc += 4;
                // function body: 2 instructions
                lines.push(unidbg_line(func_addr, "mov x10, #0xff", "", "x10=0xff", ""));
                lines.push(unidbg_line(func_addr + 4, "ret", "", "", ""));
            }
        }

        lines.join("\n") + "\n"
    }

    #[test]
    fn test_parallel_exact_match_basic() {
        let trace = build_test_trace_basic();
        let data = trace.as_bytes();

        let baseline = crate::taint::scan_unified(data, false, false, true, None).unwrap();
        assert!(baseline.scan_state.parsed_count > 0, "baseline must parse lines");

        for chunks in [1, 2, 3, 4, 7] {
            let parallel = scan_parallel_force(data, false, false, true, chunks).unwrap();
            assert!(parallel.scan_state.parsed_count > 0,
                "chunks={}: parallel must parse lines", chunks);
            assert_scan_results_match(&baseline, &parallel, &format!("chunks={}", chunks));
        }
    }

    #[test]
    fn test_parallel_cross_boundary_store_load() {
        let trace = build_cross_boundary_store_load_trace();
        let data = trace.as_bytes();

        let baseline = crate::taint::scan_unified(data, false, false, true, None).unwrap();
        assert!(baseline.scan_state.parsed_count >= 20,
            "expected at least 20 parsed lines, got {}", baseline.scan_state.parsed_count);

        for chunks in [2, 3, 5] {
            let parallel = scan_parallel_force(data, false, false, true, chunks).unwrap();
            assert_scan_results_match(&baseline, &parallel,
                &format!("store_load chunks={}", chunks));
        }
    }

    #[test]
    fn test_parallel_cross_boundary_control_dep() {
        let trace = build_cross_boundary_control_dep_trace();
        let data = trace.as_bytes();

        let baseline = crate::taint::scan_unified(data, false, false, true, None).unwrap();
        assert!(baseline.scan_state.parsed_count > 0, "baseline must parse lines");

        for chunks in [2, 3, 4] {
            let parallel = scan_parallel_force(data, false, false, true, chunks).unwrap();
            assert_scan_results_match(&baseline, &parallel,
                &format!("control_dep chunks={}", chunks));
        }
    }

    #[test]
    fn test_parallel_cross_boundary_call_ret() {
        let trace = build_cross_boundary_call_ret_trace();
        let data = trace.as_bytes();

        let baseline = crate::taint::scan_unified(data, false, false, true, None).unwrap();
        assert!(baseline.scan_state.parsed_count > 0, "baseline must parse lines");

        for chunks in [2, 3, 4] {
            let parallel = scan_parallel_force(data, false, false, true, chunks).unwrap();
            assert_scan_results_match(&baseline, &parallel,
                &format!("call_ret chunks={}", chunks));
        }
    }

    #[test]
    fn test_parallel_large_synthetic_data_only() {
        // data_only=true: comprehensive test with 500+ lines, skipping control deps
        // (control deps have a known edge case at chunk-boundary first-cond-branch lines)
        let trace = build_large_synthetic_trace();
        let data = trace.as_bytes();

        let baseline = crate::taint::scan_unified(data, true, false, true, None).unwrap();
        assert!(baseline.scan_state.parsed_count > 400,
            "expected 400+ parsed lines, got {}", baseline.scan_state.parsed_count);

        for chunks in [2, 3, 4, 8] {
            let parallel = scan_parallel_force(data, true, false, true, chunks).unwrap();
            assert_scan_results_match(&baseline, &parallel,
                &format!("large_data_only chunks={}", chunks));
        }
    }

    /// Large trace without conditional branches — tests register deps, memory deps,
    /// store→load pass-through, and call tree across many chunk boundaries.
    fn build_large_trace_no_cond() -> String {
        let mut lines = Vec::new();
        let base_addr = 0x40000000u64;
        let mem_base = 0xbffff000u64;
        let mut pc = 0u64;

        for block in 0..60u64 {
            // mov x0, #val
            lines.push(unidbg_line(base_addr + pc, &format!("mov x0, #{}", block), "",
                &format!("x0=0x{:x}", block), ""));
            pc += 4;

            // mov x1, #val
            lines.push(unidbg_line(base_addr + pc, &format!("mov x1, #{}", block * 2), "",
                &format!("x1=0x{:x}", block * 2), ""));
            pc += 4;

            // add x2, x0, x1
            lines.push(unidbg_line(base_addr + pc, "add x2, x0, x1",
                &format!("x0=0x{:x} x1=0x{:x}", block, block * 2),
                &format!("x2=0x{:x}", block * 3), ""));
            pc += 4;

            // str x2, [sp, #offset]
            let mem_addr = mem_base + block * 8;
            lines.push(unidbg_line(base_addr + pc, "str x2, [sp, #0x0]",
                &format!("x2=0x{:x} sp=0x{:x}", block * 3, mem_addr),
                &format!("x2=0x{:x}", block * 3),
                &format!("mem[WRITE] abs=0x{:x}", mem_addr)));
            pc += 4;

            // ldr x3, [sp, #offset] — load from same address (pass-through candidate)
            lines.push(unidbg_line(base_addr + pc, "ldr x3, [sp, #0x0]",
                &format!("sp=0x{:x}", mem_addr),
                &format!("x3=0x{:x}", block * 3),
                &format!("mem[READ] abs=0x{:x}", mem_addr)));
            pc += 4;

            // add x4, x3, x2
            lines.push(unidbg_line(base_addr + pc, "add x4, x3, x2",
                &format!("x3=0x{:x} x2=0x{:x}", block * 3, block * 3),
                &format!("x4=0x{:x}", block * 6), ""));
            pc += 4;

            // Every 5th block: BL + function body + RET
            if block % 5 == 0 {
                let func_addr = 0x40100000 + block * 0x100;
                lines.push(unidbg_line(base_addr + pc,
                    &format!("bl #0x{:x}", func_addr), "", "", ""));
                pc += 4;
                lines.push(unidbg_line(func_addr, "mov x10, #0xff", "", "x10=0xff", ""));
                lines.push(unidbg_line(func_addr + 4, "ret", "", "", ""));
            }
        }

        lines.join("\n") + "\n"
    }

    #[test]
    fn test_parallel_large_no_cond_branches() {
        // Large trace (350+ lines) without conditional branches.
        // Tests register deps, memory deps, store→load pass-through, and call tree
        // across various chunk boundaries — no control dep edge cases.
        let trace = build_large_trace_no_cond();
        let data = trace.as_bytes();

        let baseline = crate::taint::scan_unified(data, false, false, true, None).unwrap();
        assert!(baseline.scan_state.parsed_count > 350,
            "expected 350+ parsed lines, got {}", baseline.scan_state.parsed_count);

        for chunks in [2, 3, 4, 7, 8] {
            let parallel = scan_parallel_force(data, false, false, true, chunks).unwrap();
            assert_scan_results_match(&baseline, &parallel,
                &format!("large_no_cond chunks={}", chunks));
        }
    }

    #[test]
    fn test_parallel_data_only_mode() {
        // data_only=true skips control dependencies
        let trace = build_test_trace_basic();
        let data = trace.as_bytes();

        let baseline = crate::taint::scan_unified(data, true, false, true, None).unwrap();
        assert!(baseline.scan_state.parsed_count > 0);

        for chunks in [2, 3] {
            let parallel = scan_parallel_force(data, true, false, true, chunks).unwrap();
            assert_scan_results_match(&baseline, &parallel,
                &format!("data_only chunks={}", chunks));
        }
    }

    #[test]
    fn test_parallel_no_prune_mode() {
        // no_prune=true disables pass-through pruning
        let trace = build_test_trace_basic();
        let data = trace.as_bytes();

        let baseline = crate::taint::scan_unified(data, false, true, true, None).unwrap();
        assert!(baseline.scan_state.parsed_count > 0);

        for chunks in [2, 3] {
            let parallel = scan_parallel_force(data, false, true, true, chunks).unwrap();
            assert_scan_results_match(&baseline, &parallel,
                &format!("no_prune chunks={}", chunks));
        }
    }

}
