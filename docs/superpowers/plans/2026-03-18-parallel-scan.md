# Parallel Chunk Scanning Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Parallelize `scan_unified` into multi-threaded chunk scanning, reducing 60GB/500M-line trace indexing from ~10 minutes to <30 seconds, while producing results 100% functionally identical to the single-threaded version.

**Architecture:** Split the mmap'd file into N chunks at newline boundaries (N = CPU cores). Phase 0 counts lines per chunk (parallel SIMD memchr). Phase 1 scans each chunk independently, recording cross-boundary "unresolved" items instead of making approximate decisions. Phase 2 sequentially propagates boundary state and resolves all unresolved items with exact global context, then rebuilds unified data structures. CallTree and Gumtrace annotations use event-log + sequential-replay for guaranteed correctness.

**Tech Stack:** Rust, rayon (already in Cargo.toml), memchr (SIMD), memmap2, existing taint/scanner infrastructure.

---

## File Structure

### New Files

| File | Responsibility |
|------|---------------|
| `src/taint/parallel.rs` | `scan_unified_parallel()` orchestrator: Phase 0 + chunk dispatch + Phase 2 merge |
| `src/taint/chunk_scan.rs` | `scan_chunk()`: per-chunk scanning with unresolved tracking |
| `src/taint/merge.rs` | All fixup/merge logic: resolve unresolved items, rebuild CompactDeps, replay CallTree/annotations |
| `src/taint/parallel_types.rs` | Data structures: `ChunkResult`, `UnresolvedLoad`, `CallTreeEvent`, `ChunkBoundaryState`, etc. |

### Modified Files

| File | Change |
|------|--------|
| `src/taint/mod.rs` | Add `pub mod parallel; pub mod chunk_scan; pub mod merge; pub mod parallel_types;` |
| `src/taint/scanner.rs` | Make `CompactDeps` fields `pub(crate)`, add `CompactDeps::start_row_no_push()` and `CompactDeps::extend_row()` methods |
| `src/commands/index.rs` | Call `scan_unified_parallel` instead of `scan_unified` for large files |
| `src/taint/call_tree.rs` | No changes needed — we replay events through existing `CallTreeBuilder` |

### Test Files

| File | Purpose |
|------|---------|
| `src/taint/parallel.rs` (inline `#[cfg(test)]`) | Exact-match tests: parallel vs single-threaded on synthetic traces |

---

## Task 1: Parallel Types and Data Structures

**Files:**
- Create: `src/taint/parallel_types.rs`
- Modify: `src/taint/mod.rs` (add module declaration)

### Types to Define

```rust
// === Cross-boundary unresolved items ===

/// A non-pair LOAD where ALL bytes had no local mem_last_def.
/// Deferred to fixup for exact pass-through determination.
/// scan_chunk 对此类 load 不添加任何 dep（既不添加 mem dep 也不添加 reg dep）。
pub struct UnresolvedLoad {
    pub line: u32,                           // global line number
    pub addr: u64,                           // memory address loaded
    pub width: u8,                           // access width in bytes
    pub load_value: Option<u64>,             // value from trace (for pass-through check)
    pub uses: SmallVec<[RegId; 4]>,          // registers USEd by this load instruction
}

/// A non-pair LOAD where SOME bytes had local mem_last_def but others did not.
/// pass-through 对 mixed case 一定是 false（all_same_store 已经为 false），
/// 所以 scan_chunk 已正确添加了 reg deps。但缺少跨 chunk 的 mem deps。
/// fixup 阶段补充缺失的 mem deps 并修正 init_mem_loads。
pub struct PartialUnresolvedLoad {
    pub line: u32,
    pub missing_addrs: SmallVec<[u64; 8]>,   // 在本 chunk 内找不到 mem_last_def 的字节地址
}

/// A pair LOAD (LDP) where ALL memory deps are fully unresolved.
/// scan_chunk 不添加任何 dep 也不创建 PairSplitDeps。
pub struct UnresolvedPairLoad {
    pub line: u32,
    pub addr: u64,
    pub elem_width: u8,
    pub base_reg: Option<RegId>,
    pub defs: SmallVec<[RegId; 3]>,          // DEF registers (for pair_split)
}

/// A pair LOAD where one half is locally resolved but the other is not.
/// scan_chunk 已为本地半区创建了 PairSplitDeps 的对应字段，
/// fixup 阶段补充跨 chunk 半区的依赖。
pub struct PartialUnresolvedPairLoad {
    pub line: u32,
    pub addr: u64,
    pub elem_width: u8,
    pub half1_unresolved: bool,              // true = half1 的字节需要 fixup
    pub half2_unresolved: bool,              // true = half2 的字节需要 fixup
    pub base_reg: Option<RegId>,
    pub base_reg_unresolved: bool,           // base reg 在本 chunk 内未定义
}

/// A register USE where reg_last_def was undefined (no prior DEF in this chunk).
pub struct UnresolvedRegUse {
    pub line: u32,
    pub reg: RegId,
}

// === CallTree event log ===

pub enum CallTreeEvent {
    Call { seq: u32, target: u64 },
    Ret { seq: u32 },
    BlrPending { seq: u32, pc: u64 },
    LineAddr { seq: u32, addr: u64 },
    SetFuncName { entry_seq: u32, name: String },
    SetRootAddr { addr: u64 },
}

// === Gumtrace annotation event log ===

pub enum GumtraceAnnotEvent {
    /// BL/BLR/BR instruction encountered — sets pending_call_seq
    BranchInstr { seq: u32 },
    /// A special line was encountered
    SpecialLine { seq: u32, special: SpecialLineData },
    /// An unrecognized line while current_annotation is active
    OrphanLine { seq: u32 },
}

pub enum SpecialLineData {
    CallFunc { name: String, is_jni: bool, raw: String },
    Arg { index: String, value: String, raw: String },
    Ret { value: String, raw: String },
    HexDump { raw: String },
}

// === Per-chunk boundary state ===

pub struct ChunkBoundaryState {
    pub final_reg_last_def: RegLastDef,
    pub final_mem_last_def: FxHashMap<u64, (u32, u64)>,  // addr → (line, value)
    pub final_last_cond_branch: Option<u32>,
    pub final_reg_values: [u64; RegId::COUNT],
    pub final_line_count: u32,        // chunk 内总行数
    pub final_parsed_count: u32,
    pub final_mem_op_count: u32,
}

// === Per-chunk scan result ===

pub struct ChunkResult {
    // Core data (using global line numbers)
    pub deps: CompactDeps,
    pub init_mem_loads: BitVec,
    pub pair_split: FxHashMap<u32, PairSplitDeps>,
    pub line_index: LineIndex,
    pub mem_access_index: MemAccessIndex,
    pub reg_checkpoints: RegCheckpoints,
    pub string_builder_result: Option<(StringIndex, PagedMemoryBoundary)>,

    // Unresolved items
    pub unresolved_loads: Vec<UnresolvedLoad>,
    pub partial_unresolved_loads: Vec<PartialUnresolvedLoad>,
    pub unresolved_pair_loads: Vec<UnresolvedPairLoad>,
    pub partial_unresolved_pair_loads: Vec<PartialUnresolvedPairLoad>,
    pub unresolved_reg_uses: Vec<UnresolvedRegUse>,
    pub first_local_cond_branch: Option<u32>,  // global line number
    /// 每行是否需要控制依赖（仅非 pair、已成功解析、非 data_only 的行为 true）
    pub needs_control_dep: BitVec,

    // Event logs
    pub call_tree_events: Vec<CallTreeEvent>,
    pub gumtrace_annot_events: Vec<GumtraceAnnotEvent>,
    pub consumed_seqs: Vec<u32>,

    // Boundary state for next chunk's fixup
    pub boundary: ChunkBoundaryState,

    // Chunk metadata
    pub start_line: u32,   // global
    pub end_line: u32,     // global (exclusive)
    pub start_byte: usize,
    pub end_byte: usize,
}

/// String boundary data for cross-chunk string re-scan
pub struct PagedMemoryBoundary {
    /// Last ~1024 bytes of memory writes at chunk end (addr → byte value)
    pub tail_bytes: Vec<(u64, u8)>,
}
```

- [ ] **Step 1: Write the type definitions**

Create `src/taint/parallel_types.rs` with all types above. Import necessary dependencies: `SmallVec`, `RegId`, `CompactDeps`, `PairSplitDeps`, `RegLastDef`, `BitVec`, `FxHashMap`, `LineIndex`, `MemAccessIndex`, `RegCheckpoints`, `StringIndex`.

- [ ] **Step 2: Add module declaration**

In `src/taint/mod.rs`, add at the top:
```rust
pub mod parallel_types;
pub mod chunk_scan;
pub mod merge;
pub mod parallel;
```

- [ ] **Step 3: Verify compilation**

Run: `cargo check 2>&1 | head -20`
Expected: No errors (types not yet used)

- [ ] **Step 4: Commit**

```bash
git add src/taint/parallel_types.rs src/taint/mod.rs
git commit -m "feat: add parallel scanning type definitions"
```

---

## Task 2: CompactDeps Extensions

**Files:**
- Modify: `src/taint/scanner.rs`

The merge phase needs to access CompactDeps internals and extend rows efficiently.

- [ ] **Step 1: Make CompactDeps fields pub(crate)**

In `src/taint/scanner.rs`, change CompactDeps:
```rust
pub struct CompactDeps {
    pub(crate) offsets: Vec<u32>,
    pub(crate) data: Vec<u32>,
}
```

- [ ] **Step 2: Add merge helper methods**

```rust
impl CompactDeps {
    /// Create from raw parts (for merge phase).
    pub(crate) fn from_raw(offsets: Vec<u32>, data: Vec<u32>) -> Self {
        Self { offsets, data }
    }

    /// Number of dependency edges for row i.
    pub(crate) fn row_len(&self, i: usize) -> usize {
        let start = self.offsets[i] as usize;
        let end = if i + 1 < self.offsets.len() {
            self.offsets[i + 1] as usize
        } else {
            self.data.len()
        };
        end - start
    }

    /// Finalize: push the sentinel offset so row(last) works.
    pub(crate) fn finalize(&mut self) {
        // Ensure the sentinel is present for the last row
        if !self.offsets.is_empty() {
            // The sentinel is data.len() — only needed if not already there
            // (start_row pushes at start, not end)
        }
    }
}
```

- [ ] **Step 3: Verify compilation**

Run: `cargo check 2>&1 | head -20`

- [ ] **Step 4: Run existing tests**

Run: `cargo test 2>&1 | tail -5`
Expected: All existing tests pass

- [ ] **Step 5: Commit**

```bash
git add src/taint/scanner.rs
git commit -m "refactor: make CompactDeps fields pub(crate) for parallel merge"
```

---

## Task 3: Phase 0 — Parallel Line Counting & Chunk Splitting

**Files:**
- Create: `src/taint/parallel.rs` (initial version with Phase 0 only)

Phase 0 counts newlines in each chunk using parallel SIMD memchr, computes global line offsets, and determines exact chunk boundaries at newline positions.

- [ ] **Step 1: Write failing test for chunk splitting**

In `src/taint/parallel.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_chunks_basic() {
        let data = b"line0\nline1\nline2\nline3\nline4\n";
        let chunks = split_into_chunks(data, 2);
        assert_eq!(chunks.len(), 2);
        // Each chunk should be at a newline boundary
        assert_eq!(chunks[0].start_byte, 0);
        assert!(data[chunks[0].end_byte - 1] == b'\n' || chunks[0].end_byte == data.len());
        assert_eq!(chunks[1].end_byte, data.len());
        // Global line offsets should be correct
        assert_eq!(chunks[0].start_line, 0);
        assert_eq!(chunks[1].start_line, chunks[0].line_count);
        // Total lines should equal the whole file
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
        // Should not create more chunks than lines
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
}
```

- [ ] **Step 2: Implement chunk splitting**

```rust
use memchr::memchr_iter;

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
            start_byte: 0, end_byte: 0, start_line: 0, line_count: 0,
        }];
    }

    // 1. Determine raw byte boundaries
    let chunk_size = len / n;
    let mut boundaries = Vec::with_capacity(n + 1);
    boundaries.push(0usize);

    for i in 1..n {
        let raw = i * chunk_size;
        // Find next newline after raw boundary
        let adjusted = match memchr::memchr(b'\n', &data[raw..]) {
            Some(pos) => raw + pos + 1,  // start of next line
            None => len,                  // no newline found, extend to end
        };
        if adjusted < len && adjusted != *boundaries.last().unwrap() {
            boundaries.push(adjusted);
        }
    }
    boundaries.push(len);
    boundaries.dedup();

    // 2. Count lines per chunk (parallel)
    use rayon::prelude::*;
    let line_counts: Vec<u32> = boundaries.windows(2)
        .collect::<Vec<_>>()
        .par_iter()
        .map(|window| {
            let start = window[0];
            let end = window[1];
            let chunk_data = &data[start..end];
            let newline_count = memchr_iter(b'\n', chunk_data).count() as u32;
            // If chunk doesn't end with newline, there's one more line
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
```

- [ ] **Step 3: Run tests**

Run: `cargo test taint::parallel::tests -v 2>&1 | tail -20`
Expected: All 4 tests pass

- [ ] **Step 4: Commit**

```bash
git add src/taint/parallel.rs
git commit -m "feat: Phase 0 parallel line counting and chunk splitting"
```

---

## Task 4: scan_chunk — Per-Chunk Scanning

**Files:**
- Create: `src/taint/chunk_scan.rs`

This is the core refactoring: extract the main loop from `scan_unified` into `scan_chunk()`, adding unresolved-item tracking for cross-boundary cases.

### Key differences from `scan_unified`:
1. Operates on a byte sub-slice `data[start_byte..end_byte]` with known `start_line`
2. Tracks `UnresolvedLoad`, `UnresolvedPairLoad`, `UnresolvedRegUse`
3. Records `CallTreeEvent` log instead of directly operating `CallTreeBuilder`
4. Records `GumtraceAnnotEvent` log instead of operating annotation state machine
5. Tracks `first_local_cond_branch`
6. Exports `ChunkBoundaryState` at end

- [ ] **Step 1: Write failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::taint;

    fn make_unidbg_trace(lines: &[&str]) -> String {
        lines.join("\n") + "\n"
    }

    #[test]
    fn test_scan_chunk_single_chunk_matches_unified() {
        // A simple 3-line trace
        let trace = make_unidbg_trace(&[
            "[00:00:00 000][libtiny.so 0x1000] [d503201f] 0x7f001000: \"mov x0, x1\" x1=0x42 => x0=0x42",
            "[00:00:00 000][libtiny.so 0x1004] [d503201f] 0x7f001004: \"add x2, x0, #1\" x0=0x42 => x2=0x43",
            "[00:00:00 000][libtiny.so 0x1008] [d503201f] 0x7f001008: \"str x2, [x3]\" x2=0x43 x3=0x8000 ; mem[WRITE] abs=0x8000",
        ]);
        let data = trace.as_bytes();

        // Single-threaded baseline
        let baseline = taint::scan_unified(data, false, false, true, None).unwrap();

        // Single chunk (should be identical)
        let chunk_result = scan_chunk(
            data,
            0,                          // start_byte
            data.len(),                 // end_byte
            0,                          // start_line
            taint::types::TraceFormat::Unidbg,
            false,                      // data_only
            false,                      // no_prune
            true,                       // skip_strings
        );

        // Compare deps
        assert_eq!(baseline.scan_state.line_count, chunk_result.boundary.final_line_count);
        for i in 0..baseline.scan_state.line_count as usize {
            let mut base_deps: Vec<u32> = baseline.scan_state.deps.row(i).to_vec();
            let mut chunk_deps: Vec<u32> = chunk_result.deps.row(i).to_vec();
            base_deps.sort();
            chunk_deps.sort();
            assert_eq!(base_deps, chunk_deps, "deps mismatch at line {}", i);
        }
    }
}
```

- [ ] **Step 2: Implement scan_chunk**

Create `src/taint/chunk_scan.rs`. The function signature:

```rust
use crate::taint::parallel_types::*;
use crate::taint::{types, parser, gumtrace_parser, insn_class, def_use, phase2};
use crate::taint::scanner::*;
use crate::taint::mem_access::*;
use crate::taint::reg_checkpoint::*;
use crate::taint::strings::StringBuilder;
use crate::line_index::LineIndexBuilder;

pub fn scan_chunk(
    data: &[u8],             // full mmap (needed for context at boundaries)
    start_byte: usize,
    end_byte: usize,
    start_line: u32,
    format: types::TraceFormat,
    data_only: bool,
    no_prune: bool,
    skip_strings: bool,
) -> ChunkResult { ... }
```

The implementation mirrors `scan_unified` (lines 72-599 of `src/taint/mod.rs`) with these modifications:

**A. Initialization:** Use `start_line` as the initial line counter instead of 0.

**B. Unresolved load detection** (replaces lines 286-324 of mod.rs):

三种情况的精确处理：
- **Fully local**（所有字节在本 chunk 内有 mem_last_def）：走原有逻辑，结果与单线程完全一致。
- **Fully unresolved**（所有字节在本 chunk 内无 mem_last_def）：整个 load 推迟到 fixup，不添加任何 dep。
- **Mixed**（部分字节有本地 def，部分没有）：本地字节的 mem dep 正常添加；pass-through 一定是 false（因为 all_same_store = false）；reg deps 正常添加；**但缺失的字节 mem dep 需要记录，由 fixup 补充**。

```rust
let width = mem_access_width(class, mem.elem_width, &line);
let mut fully_unresolved = true;
let mut any_byte_unresolved = false;
let mut missing_addrs: SmallVec<[u64; 8]> = SmallVec::new();

for offset in 0..width as u64 {
    if let Some((def_line, def_val)) = state.mem_last_def.get(&(mem.abs + offset)) {
        fully_unresolved = false;
        state.deps.push_unique(def_line);
        // ... update first_store_raw, all_same_store (same as single-threaded)
    } else {
        any_byte_unresolved = true;
        missing_addrs.push(mem.abs + offset);
        has_init_mem = true;
        all_same_store = false;
    }
}

if fully_unresolved && is_non_pair_load && !no_prune {
    // Case 1: ALL bytes from previous chunk → defer entirely
    // 撤销上面循环中可能添加的 deps（实际上循环没添加任何，因为全部都走了 else 分支）
    unresolved_loads.push(UnresolvedLoad {
        line: i,
        addr: mem.abs,
        width: width as u8,
        load_value: mem.value,
        uses: uses.clone(),
    });
    skip_register_deps = true;
} else if any_byte_unresolved && is_non_pair_load {
    // Case 2: MIXED — some local, some cross-chunk
    // pass-through 一定是 false (all_same_store = false)
    // reg deps 会在下面的 step 3a 正常添加（is_pass_through = false）
    // 但缺失字节的 mem dep 需要 fixup 补充
    partial_unresolved_loads.push(PartialUnresolvedLoad {
        line: i,
        missing_addrs,
    });
}
// Case 3: Fully local — 已在循环中正确处理，无需额外操作
```

**C. Unresolved register use tracking** (in step 3a, register deps):
```rust
if !is_pair && !is_pass_through && !skip_register_deps {
    for r in &uses {
        if let Some(&def_line) = state.reg_last_def.get(r) {
            state.deps.push_unique(def_line);
        } else {
            // Register never defined in this chunk → cross-boundary
            unresolved_reg_uses.push(UnresolvedRegUse { line: i, reg: *r });
        }
    }
}
```

**D. Unresolved pair load tracking** (in step 3d for LoadPair):

三种情况：fully unresolved、mixed（某半区 unresolved）、fully local。

```rust
let half1_unresolved = (0..ew as u64)
    .all(|offset| state.mem_last_def.get(&(mem.abs + offset)).is_none());
let half2_unresolved = (ew as u64..2 * ew as u64)
    .all(|offset| state.mem_last_def.get(&(mem.abs + offset)).is_none());
let base_reg_unresolved = line.base_reg
    .map(|b| state.reg_last_def.get(&b).is_none())
    .unwrap_or(false);

if half1_unresolved && half2_unresolved {
    // Fully unresolved: defer entirely, don't create PairSplitDeps
    unresolved_pair_loads.push(UnresolvedPairLoad {
        line: i,
        addr: mem.abs,
        elem_width: ew,
        base_reg: line.base_reg,
        defs: defs.clone(),
    });
} else if half1_unresolved || half2_unresolved || base_reg_unresolved {
    // Mixed: 为已解析的半区正常构建 PairSplitDeps 对应字段，
    // 记录未解析的半区，由 fixup 补充
    let mut split = PairSplitDeps::default();

    // 处理本地已解析的半区（与单线程逻辑相同）
    if !half1_unresolved {
        for offset in 0..ew as u64 {
            if let Some((raw, _)) = state.mem_last_def.get(&(mem.abs + offset)) {
                push_unique(&mut split.half1_deps, raw);
            }
        }
    }
    if !half2_unresolved {
        for offset in ew as u64..2 * ew as u64 {
            if let Some((raw, _)) = state.mem_last_def.get(&(mem.abs + offset)) {
                push_unique(&mut split.half2_deps, raw);
            }
        }
    }
    if !base_reg_unresolved {
        if let Some(base) = line.base_reg {
            if let Some(&raw) = state.reg_last_def.get(&base) {
                push_unique(&mut split.shared, raw);
            }
        }
    }

    state.pair_split.insert(i, split);

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
    // Fully local: existing pair logic unchanged
}
```

**E. Control dep boundary tracking + needs_control_dep 位向量:**

在 scan_chunk 开头初始化：`let mut needs_control_dep = BitVec::with_capacity(estimated_lines);`

每行处理时：
```rust
// 记录此行是否需要控制依赖（与单线程 step 3c 的条件完全一致）
let needs_ctrl = !is_pair && !data_only && parsed.is_some();
needs_control_dep.push(needs_ctrl);

match class {
    InsnClass::CondBranchNzcv | InsnClass::CondBranchReg => {
        if first_local_cond_branch.is_none() {
            first_local_cond_branch = Some(i);
        }
        state.last_cond_branch = Some(i);
    }
    _ => {}
}
// 如果 last_cond_branch 是 None（chunk 开头还没有本地条件分支），
// 不添加控制依赖 — fixup 阶段用 needs_control_dep 位向量精确补充
```

**F. CallTree event logging** (replaces direct ct_builder calls):
```rust
// Instead of ct_builder.on_call(i, target):
call_tree_events.push(CallTreeEvent::Call { seq: i, target });

// Instead of ct_builder.on_ret(i):
call_tree_events.push(CallTreeEvent::Ret { seq: i });

// Instead of blr_pending_pc logic:
call_tree_events.push(CallTreeEvent::BlrPending { seq: i, pc: blr_pc });
// For every line, record its instruction address for BLR resolution:
let line_addr = phase2::extract_insn_addr(raw_line);
if line_addr != 0 {
    call_tree_events.push(CallTreeEvent::LineAddr { seq: i, addr: line_addr });
}
```

**G. Gumtrace annotation event logging** (replaces direct annotation state machine):
```rust
// Instead of manipulating pending_call_seq/current_annotation:
if format == TraceFormat::Gumtrace {
    match class {
        InsnClass::BranchLink | InsnClass::BranchLinkReg | InsnClass::BranchReg => {
            gumtrace_events.push(GumtraceAnnotEvent::BranchInstr { seq: i });
        }
        _ => {}
    }
}

// For special lines:
// Record the parsed special line data for replay
gumtrace_events.push(GumtraceAnnotEvent::SpecialLine {
    seq: i,
    special: SpecialLineData::CallFunc { name, is_jni, raw: raw_line.to_string() },
});
```

**H. Boundary state export:**
```rust
// At end of scan_chunk:
let boundary = ChunkBoundaryState {
    final_reg_last_def: state.reg_last_def.clone(),
    final_mem_last_def: match &state.mem_last_def {
        MemLastDef::Map(m) => m.clone(),
        _ => unreachable!("not yet compacted"),
    },
    final_last_cond_branch: state.last_cond_branch,
    final_reg_values: reg_values,
    final_line_count: state.line_count - start_line,
    final_parsed_count: state.parsed_count,
    final_mem_op_count: state.mem_op_count,
};
```

- [ ] **Step 3: Run test to verify single-chunk matches unified**

Run: `cargo test taint::chunk_scan::tests -v 2>&1 | tail -20`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add src/taint/chunk_scan.rs
git commit -m "feat: scan_chunk with unresolved tracking for parallel scanning"
```

---

## Task 5: Merge — Unresolved Load Resolution (Pass-Through Exact)

**Files:**
- Create: `src/taint/merge.rs`

This is the most critical fixup: resolving cross-boundary loads with exact pass-through determination.

- [ ] **Step 1: Write failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_unresolved_load_passthrough() {
        // Simulate: chunk 0 stores value 0x42 to address 0x8000 at line 10
        // chunk 1 loads from 0x8000 at line 20 with value 0x42 → should be pass-through
        let mut global_mem = FxHashMap::default();
        global_mem.insert(0x8000u64, (10u32, 0x42u64));
        // ... for all 8 bytes of a 64-bit load
        for i in 0..8u64 {
            global_mem.insert(0x8000 + i, (10u32, 0x42u64));
        }

        let load = UnresolvedLoad {
            line: 20,
            addr: 0x8000,
            width: 8,
            load_value: Some(0x42),
            uses: smallvec![RegId(1), RegId(2)],  // x1, x2
        };

        let mut global_reg = RegLastDef::new();
        global_reg.insert(RegId(1), 5);  // x1 last defined at line 5
        global_reg.insert(RegId(2), 8);  // x2 last defined at line 8

        let mut patch_edges = Vec::new();
        let mut init_corrections = Vec::new();

        resolve_unresolved_load(
            &load,
            &global_mem,
            &global_reg,
            &mut patch_edges,
            &mut init_corrections,
        );

        // Pass-through: only memory dep, no register deps
        assert_eq!(patch_edges.len(), 1);
        assert_eq!(patch_edges[0], (20, 10));  // mem dep only
        // init_mem_loads should be corrected (not truly initial)
        assert_eq!(init_corrections, vec![(20, false)]);
    }

    #[test]
    fn test_resolve_unresolved_load_not_passthrough() {
        let mut global_mem = FxHashMap::default();
        for i in 0..8u64 {
            global_mem.insert(0x8000 + i, (10u32, 0x99u64)); // different value
        }

        let load = UnresolvedLoad {
            line: 20,
            addr: 0x8000,
            width: 8,
            load_value: Some(0x42),  // != 0x99 → not pass-through
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

        // Not pass-through: memory dep + register deps
        assert!(patch_edges.contains(&(20, 10)));  // mem dep
        assert!(patch_edges.contains(&(20, 5)));   // reg dep for x1
        assert_eq!(patch_edges.len(), 2);
    }
}
```

- [ ] **Step 2: Implement resolve_unresolved_load**

```rust
use rustc_hash::FxHashMap;
use crate::taint::scanner::*;
use crate::taint::parallel_types::*;
use crate::taint::types::RegId;

/// Resolve a single unresolved load using global state.
/// Produces exact same deps as single-threaded scan would.
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
            // Add memory dependency
            push_unique_patch(patch_edges, load.line, def_line);
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

    // Determine pass-through (exact same logic as scan_unified lines 317-323)
    let is_pass_through = all_same_store
        && store_val.is_some()
        && load.load_value.is_some()
        && store_val.unwrap() == load.load_value.unwrap();

    if !is_pass_through {
        // Not pass-through → add register deps
        for r in &load.uses {
            if let Some(&def_line) = global_reg_last_def.get(r) {
                push_unique_patch(patch_edges, load.line, def_line);
            }
        }
    }

    // Correct init_mem_loads: if we found stores, it's not truly initial
    if !has_init_mem {
        init_corrections.push((load.line as u32, false));
    }
    // If has_init_mem is true, the original setting was correct
}

fn push_unique_patch(edges: &mut Vec<(u32, u32)>, from: u32, to: u32) {
    if !edges.iter().any(|&(f, t)| f == from && t == to) {
        edges.push((from, to));
    }
}
```

- [ ] **Step 3: Run tests**

Run: `cargo test taint::merge::tests -v 2>&1 | tail -20`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add src/taint/merge.rs
git commit -m "feat: exact unresolved load resolution with pass-through support"
```

---

## Task 6: Merge — Pair Loads, Register Uses, Control Deps Resolution

**Files:**
- Modify: `src/taint/merge.rs`

- [ ] **Step 1: Write tests for pair load and control dep resolution**

```rust
#[test]
fn test_resolve_unresolved_pair_load() {
    let mut global_mem = FxHashMap::default();
    // half1: bytes 0-3 from line 10, half2: bytes 4-7 from line 15
    for i in 0..4u64 { global_mem.insert(0x8000 + i, (10, 0)); }
    for i in 4..8u64 { global_mem.insert(0x8000 + i, (15, 0)); }

    let mut global_reg = RegLastDef::new();
    global_reg.insert(RegId(3), 7);  // base reg x3 last defined at line 7

    let pair = UnresolvedPairLoad {
        line: 25,
        addr: 0x8000,
        elem_width: 4,
        base_reg: Some(RegId(3)),
        defs: smallvec![RegId(0), RegId(1), RegId(3)],
    };

    let (split, patch) = resolve_unresolved_pair_load(
        &pair, &global_mem, &global_reg, false,
    );

    // half1_deps should contain line 10
    assert!(split.half1_deps.contains(&10));
    // half2_deps should contain line 15
    assert!(split.half2_deps.contains(&15));
    // shared should contain base reg dep (line 7)
    assert!(split.shared.contains(&7));
}

#[test]
fn test_resolve_control_deps() {
    // Chunk starts at line 100, first local cond branch at line 110
    // Previous chunk's last_cond_branch was line 95
    let patches = resolve_control_deps(
        100,   // chunk start_line
        Some(110),  // first_local_cond_branch
        Some(95),   // prev chunk's last_cond_branch
        120,   // chunk end_line
        false, // data_only
    );
    // Lines 100-109 should get control dep on line 95
    assert_eq!(patches.len(), 10);
    for &(line, dep) in &patches {
        assert!(line >= 100 && line < 110);
        assert_eq!(dep, 95 | CONTROL_DEP_BIT);
    }
}
```

- [ ] **Step 2: Implement resolution functions**

```rust
pub fn resolve_unresolved_pair_load(
    pair: &UnresolvedPairLoad,
    global_mem_last_def: &FxHashMap<u64, (u32, u64)>,
    global_reg_last_def: &RegLastDef,
    data_only: bool,
) -> (PairSplitDeps, Vec<(u32, u32)>) {
    let mut split = PairSplitDeps::default();
    let mut patch_edges = Vec::new();
    let ew = pair.elem_width;

    // half1 mem deps
    for offset in 0..ew as u64 {
        if let Some(&(raw, _)) = global_mem_last_def.get(&(pair.addr + offset)) {
            push_unique(&mut split.half1_deps, raw);
            patch_edges.push((pair.line, raw));
        }
    }
    // half2 mem deps
    for offset in ew as u64..2 * ew as u64 {
        if let Some(&(raw, _)) = global_mem_last_def.get(&(pair.addr + offset)) {
            push_unique(&mut split.half2_deps, raw);
            patch_edges.push((pair.line, raw));
        }
    }
    // shared: base reg
    if let Some(base) = pair.base_reg {
        if let Some(&raw) = global_reg_last_def.get(&base) {
            push_unique(&mut split.shared, raw);
            patch_edges.push((pair.line, raw));
        }
    }

    (split, patch_edges)
}

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

/// 仅为标记了 needs_control_dep=true 且在 first_local_cond_branch 之前的行添加控制依赖。
/// 这确保只有非 pair、已成功解析的行才获得控制依赖，与单线程行为一致。
pub fn resolve_control_deps(
    chunk_start: u32,
    first_local_cond: Option<u32>,
    prev_last_cond: Option<u32>,
    chunk_end: u32,
    needs_control_dep: &BitVec,  // chunk 内每行的控制依赖标记
    data_only: bool,
) -> Vec<(u32, u32)> {
    if data_only { return Vec::new(); }
    let Some(prev_cond) = prev_last_cond else { return Vec::new(); };
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
```

- [ ] **Step 3: Run tests**

Run: `cargo test taint::merge::tests -v 2>&1 | tail -20`
Expected: All tests pass

- [ ] **Step 4: Commit**

```bash
git add src/taint/merge.rs
git commit -m "feat: pair load, register use, and control dep resolution"
```

---

## Task 7: Merge — CompactDeps Rebuild

**Files:**
- Modify: `src/taint/merge.rs`

Merge all chunk CompactDeps + patch_edges into a single unified CompactDeps.

- [ ] **Step 1: Write test**

```rust
#[test]
fn test_rebuild_compact_deps() {
    // Chunk 0: 3 lines, chunk 1: 2 lines
    let mut c0 = CompactDeps::with_capacity(3, 6);
    c0.start_row(); c0.push_unique(0);           // line 0 depends on nothing (self-init, placeholder)
    c0.start_row(); c0.push_unique(0);           // line 1 → line 0
    c0.start_row(); c0.push_unique(1);           // line 2 → line 1

    let mut c1 = CompactDeps::with_capacity(2, 4);
    c1.start_row();                               // line 3: no local deps
    c1.start_row(); c1.push_unique(3);           // line 4 → line 3

    let patch_edges = vec![
        (3u32, 2u32),  // line 3 depends on line 2 (cross-chunk)
    ];

    let merged = rebuild_compact_deps(
        &[c0, c1],
        &[0, 3],  // chunk_start_lines
        &patch_edges,
    );

    // line 3 should have deps: [2] (from patch) and line 4: [3]
    let mut line3_deps: Vec<u32> = merged.row(3).to_vec();
    line3_deps.sort();
    assert_eq!(line3_deps, vec![2]);

    let line4_deps: Vec<u32> = merged.row(4).to_vec();
    assert_eq!(line4_deps, vec![3]);
}
```

- [ ] **Step 2: Implement rebuild_compact_deps**

```rust
pub fn rebuild_compact_deps(
    chunk_deps: &[CompactDeps],
    chunk_start_lines: &[u32],
    patch_edges: &[(u32, u32)],
) -> CompactDeps {
    // Group patch_edges by source line
    let mut patches: FxHashMap<u32, Vec<u32>> = FxHashMap::default();
    for &(from, to) in patch_edges {
        patches.entry(from).or_default().push(to);
    }

    // Calculate total lines and deps for capacity
    let total_lines: usize = chunk_deps.iter()
        .map(|c| c.offsets.len())
        .sum();
    let total_deps: usize = chunk_deps.iter()
        .map(|c| c.data.len())
        .sum::<usize>() + patch_edges.len();

    let mut merged = CompactDeps::with_capacity(total_lines, total_deps);

    for (chunk_id, chunk) in chunk_deps.iter().enumerate() {
        let num_rows = chunk.offsets.len();
        for local_row in 0..num_rows {
            let global_line = chunk_start_lines[chunk_id] + local_row as u32;
            merged.start_row();

            // Add original deps
            for &dep in chunk.row(local_row) {
                merged.push_unique(dep);
            }

            // Add patch deps
            if let Some(extras) = patches.get(&global_line) {
                for &dep in extras {
                    merged.push_unique(dep);
                }
            }
        }
    }

    merged
}
```

- [ ] **Step 3: Run tests**

Run: `cargo test taint::merge::tests::test_rebuild_compact_deps -v`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add src/taint/merge.rs
git commit -m "feat: CompactDeps merge with patch edges"
```

---

## Task 8: Merge — CallTree Event Replay

**Files:**
- Modify: `src/taint/merge.rs`

Replay CallTree events sequentially through the existing `CallTreeBuilder`.

- [ ] **Step 1: Write test**

```rust
#[test]
fn test_replay_call_tree_events() {
    let events = vec![
        CallTreeEvent::SetRootAddr { addr: 0x1000 },
        CallTreeEvent::LineAddr { seq: 0, addr: 0x1000 },
        CallTreeEvent::Call { seq: 5, target: 0x2000 },
        CallTreeEvent::LineAddr { seq: 5, addr: 0x1014 },
        // BLR at seq 10 with PC 0x2010
        CallTreeEvent::Call { seq: 10, target: 0x3000 },
        CallTreeEvent::BlrPending { seq: 10, pc: 0x2010 },
        // Next line addr = 0x2014 = PC+4 → intercepted call
        CallTreeEvent::LineAddr { seq: 11, addr: 0x2014 },
        CallTreeEvent::Ret { seq: 15 },
    ];

    let tree = replay_call_tree_events(&events, 20);

    // Root + 2 calls (one intercepted immediately)
    assert!(tree.nodes.len() >= 3);
    // The BLR call (seq 10) should have been ret'd at seq 10 (intercepted)
}
```

- [ ] **Step 2: Implement replay_call_tree_events**

```rust
use crate::taint::call_tree::{CallTree, CallTreeBuilder};

pub fn replay_call_tree_events(events: &[CallTreeEvent], total_lines: u32) -> CallTree {
    let mut builder = CallTreeBuilder::new();
    let mut blr_pending_pc: Option<u64> = None;

    for event in events {
        match event {
            CallTreeEvent::SetRootAddr { addr } => {
                builder.set_root_addr(*addr);
            }
            CallTreeEvent::LineAddr { seq, addr } => {
                if let Some(blr_pc) = blr_pending_pc.take() {
                    if *addr != 0 {
                        builder.update_current_func_addr(*addr);
                        if *addr == blr_pc + 4 {
                            builder.on_ret(seq.saturating_sub(1));
                        }
                    } else {
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
```

- [ ] **Step 3: Run tests**

Run: `cargo test taint::merge::tests::test_replay_call_tree -v`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add src/taint/merge.rs
git commit -m "feat: CallTree event replay for parallel merge"
```

---

## Task 9: Merge — Gumtrace Annotation Replay

**Files:**
- Modify: `src/taint/merge.rs`

Replay Gumtrace annotation events sequentially, producing exact `call_annotations` and `consumed_seqs` corrections.

- [ ] **Step 1: Write test**

```rust
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

    let (annotations, extra_consumed) = replay_gumtrace_annotations(&events);

    assert_eq!(annotations.len(), 1);
    assert!(annotations.contains_key(&10));
    let ann = &annotations[&10];
    assert_eq!(ann.func_name, "strcmp");
    assert_eq!(ann.args.len(), 1);
    assert_eq!(ann.ret_value, Some("0".to_string()));
}
```

- [ ] **Step 2: Implement replay_gumtrace_annotations**

```rust
use crate::taint::gumtrace_parser::CallAnnotation;

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
            GumtraceAnnotEvent::SpecialLine { seq, special } => {
                match special {
                    SpecialLineData::CallFunc { name, is_jni, raw } => {
                        // Flush previous
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
```

- [ ] **Step 3: Run tests**

Run: `cargo test taint::merge::tests::test_replay_gumtrace -v`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add src/taint/merge.rs
git commit -m "feat: Gumtrace annotation event replay"
```

---

## Task 10: Merge — Other Data Structures

**Files:**
- Modify: `src/taint/merge.rs`

Merge MemAccessIndex, RegCheckpoints, StringIndex, LineIndex, init_mem_loads, pair_split.

- [ ] **Step 1: Write tests**

```rust
#[test]
fn test_merge_reg_checkpoints() {
    // Chunk 0 final reg_values: x0=0x42, x1=0x99, rest=MAX
    let mut chunk0_final = [u64::MAX; RegId::COUNT];
    chunk0_final[0] = 0x42;
    chunk0_final[1] = 0x99;

    // Chunk 1 checkpoints: first checkpoint has x0=MAX, x1=MAX (unknown)
    let mut ckpts = RegCheckpoints::new(1000);
    let mut vals = [u64::MAX; RegId::COUNT];
    ckpts.save_checkpoint(&vals);
    vals[0] = 0x55; // x0 written in chunk 1
    ckpts.save_checkpoint(&vals);

    fix_reg_checkpoints(&mut ckpts, &chunk0_final);

    // First checkpoint: x0 should be 0x42 (from prev chunk), x1=0x99
    assert_eq!(ckpts.snapshots[0].0[0], 0x42);
    assert_eq!(ckpts.snapshots[0].0[1], 0x99);
    // Second checkpoint: x0=0x55 (written in chunk), x1=0x99 (inherited)
    assert_eq!(ckpts.snapshots[1].0[0], 0x55);
    assert_eq!(ckpts.snapshots[1].0[1], 0x99);
}
```

- [ ] **Step 2: Implement merge functions**

```rust
use crate::taint::mem_access::MemAccessIndex;
use crate::taint::reg_checkpoint::RegCheckpoints;
use crate::taint::strings::StringIndex;
use crate::line_index::LineIndex;

/// Fix RegCheckpoints by propagating prev chunk's final register values.
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

/// Merge multiple MemAccessIndex instances.
/// Records are already in correct seq order within each chunk,
/// and chunks are in global order, so concatenation preserves order.
pub fn merge_mem_access_indices(indices: Vec<MemAccessIndex>) -> MemAccessIndex {
    let mut merged = MemAccessIndex::new();
    for idx in indices {
        for (addr, record) in idx.iter_all() {
            merged.add(addr, record.clone());
        }
    }
    merged
}

/// Merge LineIndex from chunks.
///
/// 关键：每个 chunk 的 LineIndexBuilder 必须使用 start_line 初始化行计数器，
/// 以保持全局 BLOCK_SIZE (256) 对齐。具体做法：
/// - 修改 LineIndexBuilder::with_capacity_hint 接受 start_line_count 参数
/// - add_line 的采样条件变为 (self.line_count % BLOCK_SIZE == 0)
/// - 因为 line_count 从全局偏移开始，采样点与单线程完全一致
///
/// 合并时：直接拼接所有 chunk 的 sampled_offsets（全局字节偏移），
/// total = 所有 chunk line_count 之和。
pub fn merge_line_indices(chunk_indices: Vec<LineIndex>) -> LineIndex {
    let mut all_offsets: Vec<u64> = Vec::new();
    let mut total: u32 = 0;
    for idx in &chunk_indices {
        all_offsets.extend_from_slice(&idx.sampled_offsets);
        total += idx.total_lines();
    }
    LineIndex {
        sampled_offsets: all_offsets,
        total,
    }
}

// 注意：需要修改 LineIndexBuilder 以支持非零 start_line_count：
// pub fn with_start_line(start_line: u32, capacity_hint: usize) -> Self {
//     Self {
//         sampled_offsets: Vec::with_capacity(capacity_hint / BLOCK_SIZE as usize + 1),
//         line_count: start_line,
//     }
// }

/// Merge init_mem_loads BitVecs and apply corrections.
pub fn merge_init_mem_loads(
    chunk_inits: Vec<BitVec>,
    corrections: &[(u32, bool)],
    chunk_start_lines: &[u32],
) -> BitVec {
    let total_bits: usize = chunk_inits.iter().map(|b| b.len()).sum();
    let mut merged = BitVec::with_capacity(total_bits);
    for chunk in &chunk_inits {
        merged.extend_from_bitslice(chunk);
    }
    for &(line, value) in corrections {
        if (line as usize) < merged.len() {
            merged.set(line as usize, value);
        }
    }
    merged
}

/// Merge pair_split HashMaps from all chunks + fixup.
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

/// Merge StringIndex from chunks (simple concatenation + sort by seq).
pub fn merge_string_indices(indices: Vec<StringIndex>) -> StringIndex {
    let mut all_strings = Vec::new();
    for idx in indices {
        all_strings.extend(idx.strings);
    }
    all_strings.sort_by_key(|r| r.seq);
    StringIndex { strings: all_strings }
}
```

- [ ] **Step 3: Run tests**

Run: `cargo test taint::merge::tests -v 2>&1 | tail -20`
Expected: All pass

- [ ] **Step 4: Commit**

```bash
git add src/taint/merge.rs
git commit -m "feat: merge functions for RegCheckpoints, MemAccessIndex, StringIndex, etc."
```

---

## Task 11: scan_unified_parallel Orchestrator

**Files:**
- Modify: `src/taint/parallel.rs`

The main orchestrator that ties Phase 0, Phase 1 (parallel scan), and Phase 2 (merge) together.

- [ ] **Step 1: Write integration test**

```rust
#[test]
fn test_parallel_matches_unified_unidbg() {
    // Multi-line trace that exercises: loads, stores, pairs, branches, control deps
    let trace = [
        r#"[00:00:00 000][lib.so 0x1000] [d503201f] 0x7f001000: "mov x0, #0x42" => x0=0x42"#,
        r#"[00:00:00 000][lib.so 0x1004] [d503201f] 0x7f001004: "str x0, [sp]" x0=0x42 sp=0x7fff0000 ; mem[WRITE] abs=0x7fff0000"#,
        r#"[00:00:00 000][lib.so 0x1008] [d503201f] 0x7f001008: "mov x1, #1" => x1=0x1"#,
        r#"[00:00:00 000][lib.so 0x100c] [d503201f] 0x7f00100c: "cmp x1, #0" x1=0x1"#,
        r#"[00:00:00 000][lib.so 0x1010] [d503201f] 0x7f001010: "b.eq #0x1020""#,
        r#"[00:00:00 000][lib.so 0x1014] [d503201f] 0x7f001014: "ldr x2, [sp]" sp=0x7fff0000 ; mem[READ] abs=0x7fff0000 => x2=0x42"#,
        r#"[00:00:00 000][lib.so 0x1018] [d503201f] 0x7f001018: "add x3, x2, x1" x2=0x42 x1=0x1 => x3=0x43"#,
        r#"[00:00:00 000][lib.so 0x101c] [d503201f] 0x7f00101c: "str x3, [sp, #8]" x3=0x43 sp=0x7fff0000 ; mem[WRITE] abs=0x7fff0008"#,
    ].join("\n") + "\n";

    let data = trace.as_bytes();

    // Baseline: single-threaded
    let baseline = crate::taint::scan_unified(data, false, false, true, None).unwrap();

    // Parallel: try multiple chunk counts
    for num_chunks in [1, 2, 3, 4, 8] {
        let parallel = scan_unified_parallel(data, false, false, true, None, num_chunks).unwrap();

        assert_eq!(
            baseline.scan_state.line_count,
            parallel.scan_state.line_count,
            "line_count mismatch for {} chunks", num_chunks,
        );

        for i in 0..baseline.scan_state.line_count as usize {
            let mut b: Vec<u32> = baseline.scan_state.deps.row(i).to_vec();
            let mut p: Vec<u32> = parallel.scan_state.deps.row(i).to_vec();
            b.sort();
            p.sort();
            assert_eq!(b, p, "deps mismatch at line {} with {} chunks", i, num_chunks);
        }

        // Compare pair_split
        assert_eq!(
            baseline.scan_state.pair_split.len(),
            parallel.scan_state.pair_split.len(),
            "pair_split count mismatch for {} chunks", num_chunks,
        );

        // Compare init_mem_loads
        assert_eq!(
            baseline.scan_state.init_mem_loads,
            parallel.scan_state.init_mem_loads,
            "init_mem_loads mismatch for {} chunks", num_chunks,
        );
    }
}
```

- [ ] **Step 2: Implement scan_unified_parallel**

```rust
use rayon::prelude::*;
use crate::taint::{self, ScanResult, ProgressFn};
use crate::taint::types::TraceFormat;
use crate::state::Phase2State;

pub fn scan_unified_parallel(
    data: &[u8],
    data_only: bool,
    no_prune: bool,
    skip_strings: bool,
    progress_fn: Option<ProgressFn>,
    num_chunks: usize,
) -> anyhow::Result<ScanResult> {
    // Small files: fall back to single-threaded
    if data.len() < 10 * 1024 * 1024 || num_chunks <= 1 {
        return taint::scan_unified(data, data_only, no_prune, skip_strings, progress_fn);
    }

    // === Phase 0: Split & count lines ===
    let format = taint::gumtrace_parser::detect_format(data);
    let chunks_meta = split_into_chunks(data, num_chunks);

    if let Some(ref cb) = progress_fn {
        cb(0, data.len());
    }

    // === Phase 1: Parallel chunk scanning ===
    let chunk_results: Vec<ChunkResult> = chunks_meta
        .par_iter()
        .map(|meta| {
            chunk_scan::scan_chunk(
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

    if let Some(ref cb) = progress_fn {
        cb(data.len() / 2, data.len()); // ~50% after scanning
    }

    // === Phase 2: Sequential merge + fixup ===
    let merged = merge::merge_all_chunks(
        chunk_results,
        &chunks_meta,
        format,
        data_only,
        data.len(),
    );

    if let Some(ref cb) = progress_fn {
        cb(data.len(), data.len()); // 100%
    }

    Ok(merged)
}
```

- [ ] **Step 3: Implement merge_all_chunks in merge.rs**

This is the Phase 2 orchestrator. See the architecture section from the design for the exact algorithm. Key steps:

```rust
pub fn merge_all_chunks(
    chunk_results: Vec<ChunkResult>,
    chunks_meta: &[ChunkMeta],
    format: TraceFormat,
    data_only: bool,
    data_len: usize,
) -> ScanResult {
    let num_chunks = chunk_results.len();
    let mut all_patch_edges: Vec<(u32, u32)> = Vec::new();
    let mut all_pair_fixups: Vec<(u32, PairSplitDeps)> = Vec::new();
    let mut init_corrections: Vec<(u32, bool)> = Vec::new();
    let mut all_call_events: Vec<CallTreeEvent> = Vec::new();
    let mut all_gumtrace_events: Vec<GumtraceAnnotEvent> = Vec::new();

    // Sequential forward propagation
    let mut global_mem_last_def: FxHashMap<u64, (u32, u64)> = FxHashMap::default();
    let mut global_reg_last_def = RegLastDef::new();
    let mut global_last_cond_branch: Option<u32> = None;
    let mut global_reg_values = [u64::MAX; RegId::COUNT];

    for (i, chunk) in chunk_results.iter().enumerate() {
        if i > 0 {
            // Resolve fully unresolved loads (pass-through exact)
            for load in &chunk.unresolved_loads {
                resolve_unresolved_load(
                    load, &global_mem_last_def, &global_reg_last_def,
                    &mut all_patch_edges, &mut init_corrections,
                );
            }

            // Resolve partially unresolved loads (mixed case: supplement missing mem deps)
            for partial in &chunk.partial_unresolved_loads {
                for &addr in &partial.missing_addrs {
                    if let Some(&(def_line, _)) = global_mem_last_def.get(&addr) {
                        all_patch_edges.push((partial.line, def_line));
                    }
                }
                // 修正 init_mem_loads：如果所有缺失字节都找到了 def，则不是真正的 init mem
                let all_found = partial.missing_addrs.iter()
                    .all(|a| global_mem_last_def.contains_key(a));
                if all_found {
                    init_corrections.push((partial.line, false));
                }
            }

            // Resolve fully unresolved pair loads
            for pair in &chunk.unresolved_pair_loads {
                let (split, edges) = resolve_unresolved_pair_load(
                    pair, &global_mem_last_def, &global_reg_last_def, data_only,
                );
                all_pair_fixups.push((pair.line, split));
                all_patch_edges.extend(edges);
            }

            // Resolve partially unresolved pair loads (supplement missing half deps)
            for partial_pair in &chunk.partial_unresolved_pair_loads {
                resolve_partial_pair_load(
                    partial_pair, &global_mem_last_def, &global_reg_last_def,
                    &mut chunk_pair_split_mut, &mut all_patch_edges,
                );
            }

            // Resolve unresolved register uses
            let reg_patches = resolve_unresolved_reg_uses(
                &chunk.unresolved_reg_uses, &global_reg_last_def,
            );
            all_patch_edges.extend(reg_patches);

            // Resolve control deps (只对标记了 needs_control_dep 的行添加)
            let ctrl_patches = resolve_control_deps(
                chunk.start_line,
                chunk.first_local_cond_branch,
                global_last_cond_branch,
                chunk.end_line,
                &chunk.needs_control_dep,
                data_only,
            );
            all_patch_edges.extend(ctrl_patches);

            // Fix RegCheckpoints
            // (done in final assembly)
        }

        // Accumulate events
        all_call_events.extend_from_slice(&chunk.call_tree_events);
        all_gumtrace_events.extend_from_slice(&chunk.gumtrace_annot_events);

        // Update global state
        // C4 修复：逐地址合并 mem_last_def（后续 chunk 覆盖前序 chunk 的同地址条目）
        for (&addr, &val) in &chunk.boundary.final_mem_last_def {
            global_mem_last_def.insert(addr, val);
        }
        // C4 修复：逐寄存器合并 reg_last_def（只覆盖本 chunk 中实际被写过的寄存器）
        // 如果 chunk 内某寄存器从未被定义，保留前序 chunk 的值
        for reg_idx in 0..RegId::COUNT {
            let chunk_val = chunk.boundary.final_reg_last_def.0[reg_idx];
            if chunk_val != u32::MAX {
                global_reg_last_def.0[reg_idx] = chunk_val;
            }
            // else: 保留 global 中已有的值（来自前序 chunk）
        }
        if chunk.boundary.final_last_cond_branch.is_some() {
            global_last_cond_branch = chunk.boundary.final_last_cond_branch;
        }
        global_reg_values = chunk.boundary.final_reg_values;
    }

    // === Rebuild unified data structures ===

    let chunk_start_lines: Vec<u32> = chunks_meta.iter().map(|m| m.start_line).collect();

    // CompactDeps
    let chunk_deps: Vec<CompactDeps> = chunk_results.iter()
        .map(|c| c.deps.clone())  // TODO: move instead of clone
        .collect();
    let merged_deps = rebuild_compact_deps(&chunk_deps, &chunk_start_lines, &all_patch_edges);

    // CallTree
    let total_lines: u32 = chunk_results.iter()
        .map(|c| c.boundary.final_line_count)
        .sum::<u32>()
        + chunks_meta[0].start_line;
    let total_lines = chunk_results.last().unwrap().end_line;
    let call_tree = replay_call_tree_events(&all_call_events, total_lines);

    // Gumtrace annotations
    let (call_annotations, extra_consumed) = if format == TraceFormat::Gumtrace {
        replay_gumtrace_annotations(&all_gumtrace_events)
    } else {
        (HashMap::new(), Vec::new())
    };

    // consumed_seqs
    let mut consumed_seqs: Vec<u32> = chunk_results.iter()
        .flat_map(|c| c.consumed_seqs.iter().copied())
        .collect();
    consumed_seqs.extend(extra_consumed);
    consumed_seqs.sort_unstable();

    // MemAccessIndex
    let mem_indices: Vec<MemAccessIndex> = chunk_results.into_iter()
        .map(|c| c.mem_access_index)
        .collect();
    let mem_accesses = merge_mem_access_indices(mem_indices);

    // RegCheckpoints (merge + fix)
    // ... merge and fix using global_reg_values propagation

    // StringIndex
    // ... merge

    // init_mem_loads
    // ... merge + corrections

    // pair_split
    // ... merge + fixups

    // LineIndex
    // ... merge

    // Build ScanState
    let scan_state = ScanState {
        reg_last_def: global_reg_last_def,
        mem_last_def: MemLastDef::Map(global_mem_last_def),
        last_cond_branch: global_last_cond_branch,
        deps: merged_deps,
        line_count: total_lines,
        parsed_count: /* sum */ 0,
        mem_op_count: /* sum */ 0,
        resolved_targets: FxHashMap::default(),
        unknown_mnemonics: FxHashMap::default(),
        init_mem_loads: /* merged */ Default::default(),
        pair_split: /* merged */ FxHashMap::default(),
    };
    scan_state.compact();

    ScanResult {
        scan_state,
        phase2: Phase2State { call_tree, mem_accesses, reg_checkpoints, string_index },
        line_index: /* merged */ todo!(),
        format,
        call_annotations,
        consumed_seqs,
    }
}
```

NOTE: The above is pseudocode showing the structure. The actual implementation needs to fill in `todo!()` sections using the merge functions from Task 10.

- [ ] **Step 3: Run integration test**

Run: `cargo test taint::parallel::tests::test_parallel_matches -v 2>&1`
Expected: PASS for all chunk counts

- [ ] **Step 4: Commit**

```bash
git add src/taint/parallel.rs src/taint/merge.rs
git commit -m "feat: scan_unified_parallel orchestrator with full merge pipeline"
```

---

## Task 12: Integration — Wire into build_index

**Files:**
- Modify: `src/commands/index.rs`

- [ ] **Step 1: Update build_index to use parallel scan for large files**

In `src/commands/index.rs`, in the "无缓存: 统一扫描" section (lines 127-134), replace:

```rust
// Before:
let mut scan_result = taint::scan_unified(data, false, false, skip_strings, Some(progress_fn))
    .map_err(|e| format!("统一扫描失败: {}", e))?;

// After:
let num_cpus = std::thread::available_parallelism()
    .map(|n| n.get())
    .unwrap_or(4);
let mut scan_result = taint::parallel::scan_unified_parallel(
    data, false, false, skip_strings, Some(progress_fn), num_cpus,
).map_err(|e| format!("统一扫描失败: {}", e))?;
```

Also update the "仅 Phase2 命中" path (lines 109-114) similarly.

- [ ] **Step 2: Add madvise hint for prefetching (per-chunk)**

对于并行扫描，不应使用 `MADV_SEQUENTIAL`（会导致已读页被积极回收，影响其他线程）。
改为在每个 chunk 扫描前对该 chunk 区域使用 `MADV_WILLNEED` 预读取：

```rust
// 在 scan_chunk 开头：
#[cfg(target_os = "macos")]
{
    unsafe {
        libc::madvise(
            data[start_byte..].as_ptr() as *mut libc::c_void,
            end_byte - start_byte,
            libc::MADV_WILLNEED,
        );
    }
}
```

注意：需要在 `Cargo.toml` 中添加 `libc = "0.2"` 依赖。
如果不想引入 libc 依赖，可以在第一版中跳过此步骤（mmap 页缓存在 Phase 0 预扫描后已预热）。

- [ ] **Step 3: Verify build and test**

Run: `cargo check && cargo test 2>&1 | tail -10`
Expected: All pass

- [ ] **Step 4: Commit**

```bash
git add src/commands/index.rs
git commit -m "feat: use parallel scanning in build_index for large files"
```

---

## Task 13: Comprehensive Exact-Match Verification Tests

**Files:**
- Modify: `src/taint/parallel.rs` (add tests)

- [ ] **Step 1: Add edge-case tests**

```rust
#[test]
fn test_parallel_cross_boundary_passthrough() {
    // Store in chunk 0, load same value in chunk 1 → must be pass-through
    // Create trace where chunk boundary falls between store and load
    // ...
}

#[test]
fn test_parallel_cross_boundary_no_passthrough() {
    // Store value A in chunk 0, load different value in chunk 1
    // → must NOT be pass-through, register deps must be present
    // ...
}

#[test]
fn test_parallel_cross_boundary_pair_load() {
    // LDP in chunk 1, both halves stored in chunk 0
    // → PairSplitDeps must be correctly built in fixup
    // ...
}

#[test]
fn test_parallel_cross_boundary_control_dep() {
    // Conditional branch at end of chunk 0
    // Lines at start of chunk 1 must have control dep
    // ...
}

#[test]
fn test_parallel_cross_boundary_blr() {
    // BLR at end of chunk 0, next line in chunk 1
    // → CallTree must correctly handle intercepted call detection
    // ...
}

#[test]
fn test_parallel_cross_boundary_gumtrace_annotation() {
    // BL in chunk 0, "call func:" in chunk 1
    // → annotation must be correctly associated
    // ...
}

#[test]
fn test_parallel_large_synthetic_trace() {
    // Generate a 1000-line synthetic trace with various instruction types
    // Compare parallel (2,3,4,7 chunks) vs single-threaded
    // Check: deps, pair_split, init_mem_loads, call_tree node count
    // ...
}

#[test]
fn test_parallel_slice_result_matches() {
    // Run a taint slice on both parallel and single-threaded results
    // The slice BitVec must be identical
    use crate::taint::slicer::bfs_slice;
    // ...
}
```

- [ ] **Step 2: Implement each test with concrete trace data**

Each test constructs a minimal trace exercising the specific boundary condition, runs both `scan_unified` and `scan_unified_parallel`, and asserts equality of all relevant fields.

- [ ] **Step 3: Run full test suite**

Run: `cargo test 2>&1 | tail -20`
Expected: All tests pass

- [ ] **Step 4: Commit**

```bash
git add src/taint/parallel.rs
git commit -m "test: comprehensive exact-match verification for parallel scanning"
```

---

## Task 14: LINE_MASK Safety Check

**Files:**
- Modify: `src/taint/parallel.rs`
- Modify: `src/taint/scanner.rs`

- [ ] **Step 1: Add line count validation**

In `scan_unified_parallel`, after Phase 0:

```rust
let total_lines: u32 = chunks_meta.iter().map(|c| c.line_count).sum();
if total_lines > LINE_MASK {
    anyhow::bail!(
        "文件行数 {} 超过当前支持的最大值 {}（约 5.36 亿行）。\
         请联系开发者以获取大文件支持。",
        total_lines, LINE_MASK
    );
}
```

- [ ] **Step 2: Commit**

```bash
git add src/taint/parallel.rs src/taint/scanner.rs
git commit -m "fix: validate line count against LINE_MASK to prevent overflow"
```

---

## Summary of Deliverables

| Task | Description | Files | Est. Steps |
|------|------------|-------|------------|
| 1 | Parallel types | parallel_types.rs (new) | 4 |
| 2 | CompactDeps extensions | scanner.rs | 5 |
| 3 | Phase 0 chunk splitting | parallel.rs (new) | 4 |
| 4 | scan_chunk implementation | chunk_scan.rs (new) | 4 |
| 5 | Unresolved load fixup | merge.rs (new) | 4 |
| 6 | Pair/reg/control fixup | merge.rs | 4 |
| 7 | CompactDeps rebuild | merge.rs | 4 |
| 8 | CallTree event replay | merge.rs | 4 |
| 9 | Gumtrace annotation replay | merge.rs | 4 |
| 10 | Other data structure merges | merge.rs | 4 |
| 11 | Orchestrator | parallel.rs | 4 |
| 12 | Integration into build_index | commands/index.rs | 4 |
| 13 | Exact-match verification tests | parallel.rs | 4 |
| 14 | LINE_MASK safety check | parallel.rs, scanner.rs | 2 |

**Total: 14 tasks, ~55 steps**

---

## Appendix: Review Fixes Applied

以下修复基于 spec-document-reviewer 的审查：

### C1 (Critical): Mixed-case load 处理
新增 `PartialUnresolvedLoad` 类型，scan_chunk 对 mixed case（部分字节本地、部分跨 chunk）记录缺失的字节地址，fixup 阶段补充 mem deps。pass-through 对 mixed case 一定为 false，无需特殊处理。

### C2 (Critical): Mixed-case pair load 处理
新增 `PartialUnresolvedPairLoad` 类型，scan_chunk 为本地已解析的半区正常构建 PairSplitDeps，记录未解析的半区，fixup 补充。

### C3 (Critical): 控制依赖误加
新增 `needs_control_dep: BitVec` 字段，scan_chunk 中只对非 pair、已成功解析的行标记为 true。`resolve_control_deps` 只对标记为 true 的行添加控制依赖。

### C4 (Critical): global_reg_last_def 覆盖
改为逐寄存器合并：只覆盖本 chunk 中实际被写过的寄存器，未写过的保留前序 chunk 的值。

### I4 (Important): LineIndex 合并对齐
修改 `LineIndexBuilder` 支持 `start_line` 参数，确保 BLOCK_SIZE 采样点与全局单线程一致。

### S1 (Suggestion): 移除 push_unique_patch
patch_edges 允许重复，由 `rebuild_compact_deps` 中的 `push_unique` 去重。

### S3 (Suggestion): 测试健壮性
在测试中添加 `assert!(chunk_result.boundary.final_parsed_count > 0)` 确保 trace 行确实被解析。

### S4 (Suggestion): madvise 策略
并行扫描使用 `MADV_WILLNEED` per-chunk，而非全局 `MADV_SEQUENTIAL`。

### I5 (Important, 接受限制): 跨 chunk 字符串
首版接受跨 chunk 边界字符串的微小不精确性（可能断裂），后续版本再实现边界重扫。在代码中添加注释文档化此限制。

## Execution Notes

- Tasks 1-3 can be done independently
- Tasks 4-10 should be done in order (each builds on previous)
- Task 11 ties everything together
- Task 12 is the integration point
- Task 13 should be run after Task 11 to catch issues
- Task 14 is a quick safety addition
- The synthetic trace construction in tests is critical — each test must construct traces that specifically exercise the boundary condition being tested
- After all tasks, do a manual test with a real large trace file to verify performance improvement
