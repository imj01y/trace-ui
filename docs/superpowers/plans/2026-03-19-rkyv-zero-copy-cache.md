# rkyv 零拷贝缓存 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 将缓存系统从 bincode 切换到 rkyv 零拷贝，使二次打开 23GB 文件从 14s 降至 < 0.5s。

**Architecture:** 缓存数据扁平化为 CSR 格式纯原始类型数组，rkyv 序列化后通过 mmap 零拷贝访问。每种 Flat 数据提供 View 结构体统一 Owned/Mapped 的切片访问。CallTree 急切反序列化，StringIndex 独立 bincode 可变存储。

**Tech Stack:** rkyv 0.8, memmap2, bincode (保留给 StringIndex)

**Spec:** `docs/superpowers/specs/2026-03-19-rkyv-zero-copy-cache-design.md`

---

## File Structure

### 新建文件

| 文件 | 职责 |
|------|------|
| `src/flat/mod.rs` | Flat 模块入口，re-export 所有类型 |
| `src/flat/mem_access.rs` | FlatMemAccess, FlatMemAccessRecord, MemAccessView |
| `src/flat/reg_checkpoints.rs` | FlatRegCheckpoints, RegCheckpointsView |
| `src/flat/deps.rs` | FlatDeps, DepsView |
| `src/flat/mem_last_def.rs` | FlatMemLastDef, MemLastDefView |
| `src/flat/pair_split.rs` | FlatPairSplit, PairSplitView, PairSplitEntry |
| `src/flat/bitvec.rs` | FlatBitVec, BitView |
| `src/flat/line_index.rs` | LineIndexArchive, LineIndexView |
| `src/flat/archives.rs` | Phase2Archive, ScanArchive, CachedStore |
| `src/flat/convert.rs` | 从原生类型 → Flat 类型的转换函数 |
| `src/flat/scan_view.rs` | ScanView（组合 DepsView + PairSplitView + BitView） |

### 修改文件

| 文件 | 变更 |
|------|------|
| `Cargo.toml` | 添加 rkyv 依赖 |
| `src/main.rs` | 添加 `mod flat;` |
| `src/state.rs` | SessionState 字段重构 |
| `src/cache.rs` | 新增 rkyv load/save，更新 delete/clear |
| `src/commands/index.rs` | 缓存加载/保存流程重写 |
| `src/commands/file.rs` | SessionState 初始化字段更新 |
| `src/commands/call_tree.rs` | `phase2.call_tree` → `session.call_tree` |
| `src/commands/memory.rs` | `phase2.mem_accesses` → `session.mem_accesses_view()` |
| `src/commands/registers.rs` | `phase2.reg_checkpoints` → `session.reg_checkpoints_view()` |
| `src/commands/strings.rs` | string_index 独立，mem_accesses 改 view |
| `src/commands/slice.rs` | `scan_state` → `session.scan_view()` 等 |
| `src/taint/slicer.rs` | `bfs_slice(&ScanState)` → `bfs_slice(&ScanView)` |
| `src/taint/strings.rs` | `fill_xref_counts` 签名改 MemAccessView |

---

## Task 1: 添加 rkyv 依赖 + 创建 flat 模块骨架

**Files:**
- Modify: `Cargo.toml`
- Modify: `src/main.rs`
- Create: `src/flat/mod.rs`

- [ ] **Step 1: 在 Cargo.toml 添加 rkyv 依赖**

```toml
# 在 [dependencies] 中添加
rkyv = { version = "0.8", features = ["alloc"] }
```

- [ ] **Step 2: 创建 src/flat/mod.rs 骨架**

```rust
pub mod mem_access;
pub mod reg_checkpoints;
pub mod deps;
pub mod mem_last_def;
pub mod pair_split;
pub mod bitvec;
pub mod line_index;
pub mod archives;
pub mod convert;
pub mod scan_view;
```

- [ ] **Step 3: 在 src/main.rs 添加 mod flat**

在现有 `mod` 声明区域添加 `mod flat;`。

- [ ] **Step 4: 创建所有子模块空文件**

为 flat/ 下每个子模块创建空的 .rs 文件（仅含注释占位），确保编译通过。

- [ ] **Step 5: 验证编译**

Run: `cargo check`
Expected: 编译通过，无错误

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml src/main.rs src/flat/
git commit -m "feat(cache): add rkyv dependency and flat module skeleton"
```

---

## Task 2: FlatMemAccessRecord + FlatMemAccess + MemAccessView

**Files:**
- Create: `src/flat/mem_access.rs`

- [ ] **Step 1: 编写 FlatMemAccessRecord 和 FlatMemAccess 测试**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn sample_data() -> FlatMemAccess {
        // 两个地址：0x1000 有 2 条记录，0x2000 有 1 条记录
        FlatMemAccess {
            addrs: vec![0x1000, 0x2000],
            offsets: vec![0, 2, 3],
            records: vec![
                FlatMemAccessRecord { insn_addr: 0x100, data: 0x42, seq: 0, size: 4, rw: 1, _pad: [0; 2] },
                FlatMemAccessRecord { insn_addr: 0x104, data: 0x43, seq: 5, size: 4, rw: 0, _pad: [0; 2] },
                FlatMemAccessRecord { insn_addr: 0x200, data: 0xFF, seq: 10, size: 1, rw: 1, _pad: [0; 2] },
            ],
        }
    }

    #[test]
    fn test_query_hit() {
        let flat = sample_data();
        let view = flat.view();
        let recs = view.query(0x1000).unwrap();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].seq, 0);
        assert_eq!(recs[1].seq, 5);
    }

    #[test]
    fn test_query_miss() {
        let flat = sample_data();
        let view = flat.view();
        assert!(view.query(0x9999).is_none());
    }

    #[test]
    fn test_iter_all() {
        let flat = sample_data();
        let view = flat.view();
        let all: Vec<(u64, &FlatMemAccessRecord)> = view.iter_all().collect();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].0, 0x1000);
        assert_eq!(all[2].0, 0x2000);
    }

    #[test]
    fn test_is_read_write() {
        let rec = FlatMemAccessRecord { insn_addr: 0, data: 0, seq: 0, size: 1, rw: 0, _pad: [0; 2] };
        assert!(rec.is_read());
        assert!(!rec.is_write());
        let rec2 = FlatMemAccessRecord { insn_addr: 0, data: 0, seq: 0, size: 1, rw: 1, _pad: [0; 2] };
        assert!(rec2.is_write());
    }

    #[test]
    fn test_record_size() {
        assert_eq!(std::mem::size_of::<FlatMemAccessRecord>(), 24);
    }
}
```

- [ ] **Step 2: 运行测试验证失败**

Run: `cargo test --lib flat::mem_access`
Expected: 编译错误（类型未定义）

- [ ] **Step 3: 实现 FlatMemAccessRecord, FlatMemAccess, MemAccessView**

```rust
use rkyv;

pub const MEM_RW_READ: u8 = 0;
pub const MEM_RW_WRITE: u8 = 1;

#[derive(Clone, Copy, Debug, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(as = "Self")]
#[repr(C)]
pub struct FlatMemAccessRecord {
    pub insn_addr: u64,
    pub data: u64,
    pub seq: u32,
    pub size: u8,
    pub rw: u8,
    pub _pad: [u8; 2],
}

impl FlatMemAccessRecord {
    #[inline]
    pub fn is_read(&self) -> bool { self.rw == MEM_RW_READ }
    #[inline]
    pub fn is_write(&self) -> bool { self.rw == MEM_RW_WRITE }
}

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct FlatMemAccess {
    pub addrs: Vec<u64>,
    pub offsets: Vec<u32>,
    pub records: Vec<FlatMemAccessRecord>,
}

impl FlatMemAccess {
    pub fn view(&self) -> MemAccessView<'_> {
        MemAccessView {
            addrs: &self.addrs,
            offsets: &self.offsets,
            records: &self.records,
        }
    }
}

impl ArchivedFlatMemAccess {
    pub fn view(&self) -> MemAccessView<'_> {
        MemAccessView {
            addrs: self.addrs.as_slice(),
            offsets: self.offsets.as_slice(),
            records: self.records.as_slice(),
        }
    }
}

pub struct MemAccessView<'a> {
    addrs: &'a [u64],
    offsets: &'a [u32],
    records: &'a [FlatMemAccessRecord],
}

impl<'a> MemAccessView<'a> {
    pub fn query(&self, addr: u64) -> Option<&'a [FlatMemAccessRecord]> {
        let idx = self.addrs.binary_search(&addr).ok()?;
        let start = self.offsets[idx] as usize;
        let end = self.offsets[idx + 1] as usize;
        Some(&self.records[start..end])
    }

    pub fn iter_all(&self) -> impl Iterator<Item = (u64, &'a FlatMemAccessRecord)> + '_ {
        self.addrs.iter().enumerate().flat_map(move |(i, &addr)| {
            let start = self.offsets[i] as usize;
            let end = self.offsets[i + 1] as usize;
            self.records[start..end].iter().map(move |r| (addr, r))
        })
    }

    pub fn total_records(&self) -> usize { self.records.len() }
    pub fn total_addresses(&self) -> usize { self.addrs.len() }
}
```

- [ ] **Step 4: 运行测试验证通过**

Run: `cargo test --lib flat::mem_access`
Expected: 全部 PASS

- [ ] **Step 5: Commit**

```bash
git add src/flat/mem_access.rs
git commit -m "feat(flat): add FlatMemAccess with CSR layout and MemAccessView"
```

---

## Task 3: FlatRegCheckpoints + RegCheckpointsView

**Files:**
- Create: `src/flat/reg_checkpoints.rs`

- [ ] **Step 1: 编写测试**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nearest_before() {
        // interval=1000, 3 个快照
        let mut data = vec![u64::MAX; REG_COUNT * 3];
        data[0] = 0x42; // snapshot 0, reg 0
        data[REG_COUNT + 0] = 0x55; // snapshot 1, reg 0
        let flat = FlatRegCheckpoints { interval: 1000, count: 3, data };
        let view = flat.view();
        let (seq, snap) = view.nearest_before(500).unwrap();
        assert_eq!(seq, 0);
        assert_eq!(snap[0], 0x42);
        let (seq2, snap2) = view.nearest_before(1500).unwrap();
        assert_eq!(seq2, 1000);
        assert_eq!(snap2[0], 0x55);
    }

    #[test]
    fn test_empty() {
        let flat = FlatRegCheckpoints { interval: 1000, count: 0, data: vec![] };
        assert!(flat.view().nearest_before(0).is_none());
    }
}
```

- [ ] **Step 2: 实现 FlatRegCheckpoints + RegCheckpointsView**

```rust
use crate::taint::types::RegId;

pub const REG_COUNT: usize = RegId::COUNT; // 98

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct FlatRegCheckpoints {
    pub interval: u32,
    pub count: u32,
    pub data: Vec<u64>,
}

impl FlatRegCheckpoints {
    pub fn view(&self) -> RegCheckpointsView<'_> {
        RegCheckpointsView { interval: self.interval, count: self.count, data: &self.data }
    }
}

impl ArchivedFlatRegCheckpoints {
    pub fn view(&self) -> RegCheckpointsView<'_> {
        RegCheckpointsView {
            interval: self.interval.into(),
            count: self.count.into(),
            data: self.data.as_slice(),
        }
    }
}

pub struct RegCheckpointsView<'a> {
    pub interval: u32,
    count: u32,
    data: &'a [u64],
}

impl<'a> RegCheckpointsView<'a> {
    pub fn nearest_before(&self, seq: u32) -> Option<(u32, &'a [u64; REG_COUNT])> {
        if self.count == 0 { return None; }
        let idx = ((seq / self.interval) as usize).min(self.count as usize - 1);
        let start = idx * REG_COUNT;
        let arr: &[u64; REG_COUNT] = self.data[start..start + REG_COUNT].try_into().ok()?;
        Some((idx as u32 * self.interval, arr))
    }
}
```

- [ ] **Step 3: 运行测试**

Run: `cargo test --lib flat::reg_checkpoints`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add src/flat/reg_checkpoints.rs
git commit -m "feat(flat): add FlatRegCheckpoints with RegCheckpointsView"
```

---

## Task 4: FlatDeps + DepsView

**Files:**
- Create: `src/flat/deps.rs`

- [ ] **Step 1: 编写测试**

测试 single chunk 和 multi-chunk 场景，以及 patch_row 查询。

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn single_chunk() -> FlatDeps {
        // 3 行：行0依赖[], 行1依赖[0], 行2依赖[0,1]
        FlatDeps {
            chunk_start_lines: vec![0],
            chunk_offsets_start: vec![0],
            chunk_data_start: vec![0],
            all_offsets: vec![0, 0, 1, 3],  // 3行 + 1 哨兵
            all_data: vec![0, 0, 1],
            patch_lines: vec![],
            patch_offsets: vec![0],  // 空 patch 的哨兵
            patch_data: vec![],
        }
    }

    #[test]
    fn test_single_chunk_row() {
        let flat = single_chunk();
        let view = flat.view();
        assert!(view.row(0).is_empty());
        assert_eq!(view.row(1), &[0]);
        assert_eq!(view.row(2), &[0, 1]);
    }

    #[test]
    fn test_patch_row_empty() {
        let flat = single_chunk();
        let view = flat.view();
        assert!(view.patch_row(0).is_empty());
        assert!(view.patch_row(1).is_empty());
    }

    #[test]
    fn test_multi_chunk_with_patch() {
        // chunk0: 行0-1, chunk1: 行2-3
        let flat = FlatDeps {
            chunk_start_lines: vec![0, 2],
            chunk_offsets_start: vec![0, 3],   // chunk0 offsets at [0..3], chunk1 at [3..6]
            chunk_data_start: vec![0, 2],      // chunk0 data at [0..2], chunk1 at [2..5]
            all_offsets: vec![0, 0, 2, 0, 1, 3], // chunk0: 行0=[], 行1=[0,1]; chunk1: 行2=[], 行3=[2,3,4] (local refs)
            all_data: vec![0, 1, 100, 101, 102], // chunk0 data: [0,1]; chunk1 data: [100,101,102]
            patch_lines: vec![3],
            patch_offsets: vec![0, 1],
            patch_data: vec![0],  // 行3 补丁依赖行0
        };
        let view = flat.view();
        assert!(view.row(0).is_empty());
        assert_eq!(view.row(1), &[0, 1]);
        // chunk1 行2 (local 0): empty
        assert!(view.row(2).is_empty());
        // chunk1 行3 (local 1): data[2+1..2+3] = [101,102]
        assert_eq!(view.row(3), &[101, 102]);
        // patch for line 3
        assert_eq!(view.patch_row(3), &[0]);
        assert!(view.patch_row(0).is_empty());
    }
}
```

- [ ] **Step 2: 实现 FlatDeps + DepsView**

```rust
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct FlatDeps {
    pub chunk_start_lines: Vec<u32>,
    pub chunk_offsets_start: Vec<u32>,
    pub chunk_data_start: Vec<u32>,
    pub all_offsets: Vec<u32>,
    pub all_data: Vec<u32>,
    pub patch_lines: Vec<u32>,
    pub patch_offsets: Vec<u32>,
    pub patch_data: Vec<u32>,
}

impl FlatDeps {
    pub fn view(&self) -> DepsView<'_> {
        DepsView {
            chunk_start_lines: &self.chunk_start_lines,
            chunk_offsets_start: &self.chunk_offsets_start,
            chunk_data_start: &self.chunk_data_start,
            all_offsets: &self.all_offsets,
            all_data: &self.all_data,
            patch_lines: &self.patch_lines,
            patch_offsets: &self.patch_offsets,
            patch_data: &self.patch_data,
        }
    }
}

impl ArchivedFlatDeps {
    pub fn view(&self) -> DepsView<'_> {
        DepsView {
            chunk_start_lines: self.chunk_start_lines.as_slice(),
            chunk_offsets_start: self.chunk_offsets_start.as_slice(),
            chunk_data_start: self.chunk_data_start.as_slice(),
            all_offsets: self.all_offsets.as_slice(),
            all_data: self.all_data.as_slice(),
            patch_lines: self.patch_lines.as_slice(),
            patch_offsets: self.patch_offsets.as_slice(),
            patch_data: self.patch_data.as_slice(),
        }
    }
}

pub struct DepsView<'a> {
    chunk_start_lines: &'a [u32],
    chunk_offsets_start: &'a [u32],
    chunk_data_start: &'a [u32],
    all_offsets: &'a [u32],
    all_data: &'a [u32],
    patch_lines: &'a [u32],
    patch_offsets: &'a [u32],
    patch_data: &'a [u32],
}

impl<'a> DepsView<'a> {
    pub fn row(&self, global_line: usize) -> &'a [u32] {
        let line = global_line as u32;
        let chunk_idx = match self.chunk_start_lines.binary_search(&line) {
            Ok(i) => i,
            Err(i) => i.saturating_sub(1),
        };
        let offsets_base = self.chunk_offsets_start[chunk_idx] as usize;
        let data_base = self.chunk_data_start[chunk_idx] as usize;
        let local = global_line - self.chunk_start_lines[chunk_idx] as usize;
        let start = self.all_offsets[offsets_base + local] as usize + data_base;
        let end = self.all_offsets[offsets_base + local + 1] as usize + data_base;
        &self.all_data[start..end]
    }

    pub fn patch_row(&self, global_line: usize) -> &'a [u32] {
        let line = global_line as u32;
        match self.patch_lines.binary_search(&line) {
            Ok(idx) => {
                let start = self.patch_offsets[idx] as usize;
                let end = self.patch_offsets[idx + 1] as usize;
                &self.patch_data[start..end]
            }
            Err(_) => &[],
        }
    }
}
```

- [ ] **Step 3: 运行测试**

Run: `cargo test --lib flat::deps`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add src/flat/deps.rs
git commit -m "feat(flat): add FlatDeps with CSR chunk layout and DepsView"
```

---

## Task 5: FlatMemLastDef + FlatPairSplit + FlatBitVec + LineIndexArchive

**Files:**
- Create: `src/flat/mem_last_def.rs`
- Create: `src/flat/pair_split.rs`
- Create: `src/flat/bitvec.rs`
- Create: `src/flat/line_index.rs`

这些是较简单的扁平结构，放在一个 task 里。

- [ ] **Step 1: 编写所有四个模块的测试**

每个模块 2-3 个测试：基本查询、miss 场景、边界条件。

- [ ] **Step 2: 实现所有四个模块**

`FlatMemLastDef`：三平行数组 (addrs, lines, values) + binary_search 查询。

`FlatPairSplit`：keys + seg_offsets (每 key 3 段) + data。构建时 assert `seg_offsets.len() == keys.len() * 3 + 1`。返回 `PairSplitEntry { shared, half1_deps, half2_deps }`（三个 `&[u32]` 切片）。

`FlatBitVec`：`data: Vec<u8>` + `len: u32`。`get(idx)` 返回 bool。

`LineIndexArchive`：`sampled_offsets: Vec<u64>` + `total: u32`。`LineIndexView` 提供 `get_line()` 和 `line_byte_offset()` 方法（逻辑复制自现有 `LineIndex`）。

每个 Archived 类型都提供 `view()` 方法。

- [ ] **Step 3: 运行测试**

Run: `cargo test --lib flat::mem_last_def flat::pair_split flat::bitvec flat::line_index`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add src/flat/mem_last_def.rs src/flat/pair_split.rs src/flat/bitvec.rs src/flat/line_index.rs
git commit -m "feat(flat): add FlatMemLastDef, FlatPairSplit, FlatBitVec, LineIndexArchive"
```

---

## Task 6: ScanView + Archives + CachedStore

**Files:**
- Create: `src/flat/scan_view.rs`
- Create: `src/flat/archives.rs`

- [ ] **Step 1: 实现 ScanView**

```rust
use super::deps::DepsView;
use super::pair_split::PairSplitView;
use super::bitvec::BitView;

pub struct ScanView<'a> {
    pub deps: DepsView<'a>,
    pub pair_split: PairSplitView<'a>,
    pub init_mem_loads: BitView<'a>,
    pub line_count: u32,
}
```

- [ ] **Step 2: 实现 Phase2Archive, ScanArchive, LineIndexArchive 顶层结构**

```rust
use super::*;
use crate::taint::call_tree::CallTree;
use std::sync::Arc;
use memmap2::Mmap;

pub const HEADER_LEN: usize = 64;

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct Phase2Archive {
    pub mem_accesses: mem_access::FlatMemAccess,
    pub reg_checkpoints: reg_checkpoints::FlatRegCheckpoints,
    pub call_tree: CallTree,
}

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct ScanArchive {
    pub deps: deps::FlatDeps,
    pub mem_last_def: mem_last_def::FlatMemLastDef,
    pub pair_split: pair_split::FlatPairSplit,
    pub init_mem_loads: bitvec::FlatBitVec,
    pub reg_last_def_inner: Vec<u32>,
    pub line_count: u32,
    pub parsed_count: u32,
    pub mem_op_count: u32,
}

pub enum CachedStore<A: rkyv::Archive> {
    Owned(A),
    Mapped(Arc<Mmap>),
}
```

- [ ] **Step 3: 为 CachedStore<Phase2Archive> 实现 view 方法**

注意：CallTree 需要 derive `rkyv::Archive, rkyv::Serialize, rkyv::Deserialize`。这需要 `CallTreeNode` 也 derive。在此 task 中先给 `CallTree` 和 `CallTreeNode` 添加 rkyv derive。

```rust
impl CachedStore<Phase2Archive> {
    pub fn mem_accesses_view(&self) -> mem_access::MemAccessView<'_> {
        match self {
            Self::Owned(a) => a.mem_accesses.view(),
            Self::Mapped(mmap) => {
                let archived = unsafe { rkyv::access_unchecked::<Phase2Archive>(&mmap[HEADER_LEN..]) };
                archived.mem_accesses.view()
            }
        }
    }

    pub fn reg_checkpoints_view(&self) -> reg_checkpoints::RegCheckpointsView<'_> {
        match self {
            Self::Owned(a) => a.reg_checkpoints.view(),
            Self::Mapped(mmap) => {
                let archived = unsafe { rkyv::access_unchecked::<Phase2Archive>(&mmap[HEADER_LEN..]) };
                archived.reg_checkpoints.view()
            }
        }
    }

    /// 急切反序列化 CallTree（仅 Mapped 时需要调用一次）
    pub fn deserialize_call_tree(&self) -> CallTree {
        match self {
            Self::Owned(a) => a.call_tree.clone(),  // CallTree 需要 derive Clone
            Self::Mapped(mmap) => {
                let archived = unsafe { rkyv::access_unchecked::<Phase2Archive>(&mmap[HEADER_LEN..]) };
                rkyv::deserialize::<CallTree, rkyv::rancor::Error>(&archived.call_tree).unwrap()
            }
        }
    }
}
```

- [ ] **Step 4: 为 CachedStore<ScanArchive> 实现 view 方法**

同理，提供 `deps_view()`, `mem_last_def_view()`, `pair_split_view()`, `init_mem_loads_view()`, `line_count()`, `reg_last_def_inner()` 等方法。

- [ ] **Step 5: 为 CachedStore<LineIndexArchive> 实现 view 方法**

- [ ] **Step 6: 验证编译**

Run: `cargo check`
Expected: 编译通过（可能需要在 CallTree/CallTreeNode 上添加 rkyv derive）

- [ ] **Step 7: Commit**

```bash
git add src/flat/scan_view.rs src/flat/archives.rs src/taint/call_tree.rs
git commit -m "feat(flat): add CachedStore, Phase2Archive, ScanArchive, ScanView"
```

---

## Task 7: convert 模块 — 原生类型 → Flat 类型转换

**Files:**
- Create: `src/flat/convert.rs`

- [ ] **Step 1: 编写转换测试**

测试 `MemAccessIndex → FlatMemAccess`、`RegCheckpoints → FlatRegCheckpoints`、`DepsStorage → FlatDeps`、`MemLastDef → FlatMemLastDef`、`pair_split HashMap → FlatPairSplit`、`BitVec → FlatBitVec`、`LineIndex → LineIndexArchive` 的正确性。

重点测试：转换后通过 view 查询的结果与原始数据结构查询结果一致。

- [ ] **Step 2: 实现转换函数**

```rust
pub fn mem_access_to_flat(idx: &MemAccessIndex) -> FlatMemAccess { ... }
pub fn reg_checkpoints_to_flat(ckpts: &RegCheckpoints) -> FlatRegCheckpoints { ... }
pub fn deps_to_flat(deps: &DepsStorage) -> FlatDeps { ... }
pub fn mem_last_def_to_flat(mld: &MemLastDef) -> FlatMemLastDef { ... }
pub fn pair_split_to_flat(ps: &FxHashMap<u32, PairSplitDeps>) -> FlatPairSplit { ... }
pub fn bitvec_to_flat(bv: &BitVec) -> FlatBitVec { ... }
pub fn line_index_to_flat(li: &LineIndex) -> LineIndexArchive { ... }
```

关键：`mem_access_to_flat` 需要将 HashMap 按 key 排序，然后构建 CSR。`deps_to_flat` 需要处理 `Single` 和 `Chunked` 两种变体。`pair_split_to_flat` 需要将每个 PairSplitDeps 的 SmallVec 展平到 CSR。

- [ ] **Step 3: 运行测试**

Run: `cargo test --lib flat::convert`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add src/flat/convert.rs
git commit -m "feat(flat): add conversion functions from native types to flat types"
```

---

## Task 8: cache.rs — rkyv 缓存读写

**Files:**
- Modify: `src/cache.rs`

- [ ] **Step 1: 添加新的 MAGIC 和 header 常量**

```rust
const MAGIC_V4: &[u8; 8] = b"TCACHE04";
const HEADER_LEN_V4: usize = 64;
```

- [ ] **Step 2: 实现 rkyv save 函数**

```rust
pub fn save_phase2_rkyv(file_path: &str, data: &[u8], archive: &Phase2Archive) { ... }
pub fn save_scan_rkyv(file_path: &str, data: &[u8], archive: &ScanArchive) { ... }
pub fn save_lidx_rkyv(file_path: &str, data: &[u8], archive: &LineIndexArchive) { ... }
pub fn save_string_cache(file_path: &str, data: &[u8], index: &StringIndex) { ... }
```

每个 save 函数：写 64 字节 header（MAGIC_V4 + file_size + SHA256 + 16 字节填充），然后 `rkyv::to_bytes(archive)` 写入。StringIndex 用 bincode。

- [ ] **Step 3: 实现 rkyv load 函数**

```rust
pub fn load_phase2_rkyv(file_path: &str, data: &[u8]) -> Option<Arc<Mmap>> { ... }
pub fn load_scan_rkyv(file_path: &str, data: &[u8]) -> Option<Arc<Mmap>> { ... }
pub fn load_lidx_rkyv(file_path: &str, data: &[u8]) -> Option<Arc<Mmap>> { ... }
pub fn load_string_cache(file_path: &str, data: &[u8]) -> Option<StringIndex> { ... }
```

每个 load_rkyv 函数：mmap 文件，验证 64 字节 header（MAGIC_V4 + file_size + SHA256），返回 `Arc<Mmap>`。StringIndex 用 bincode。

- [ ] **Step 4: 更新 delete_cache 和 clear_all_cache**

`delete_cache` 清理新后缀 (`.p2.rkyv`, `.scan.rkyv`, `.lidx.rkyv`, `.strings.bin`) 和旧后缀 (`""`, `"-scan"`, `"-lidx"`)。

`clear_all_cache` 清理 `.bin` 和 `.rkyv` 后缀。

- [ ] **Step 5: 验证编译**

Run: `cargo check`
Expected: 编译通过

- [ ] **Step 6: Commit**

```bash
git add src/cache.rs
git commit -m "feat(cache): add rkyv load/save functions and TCACHE04 format"
```

---

## Task 9: SessionState 重构

**Files:**
- Modify: `src/state.rs`
- Modify: `src/commands/file.rs`

- [ ] **Step 1: 重构 SessionState 字段**

```rust
pub struct SessionState {
    pub mmap: Arc<Mmap>,
    pub file_path: String,
    pub total_lines: u32,
    pub file_size: u64,
    pub trace_format: TraceFormat,

    // Phase2 (拆分后)
    pub call_tree: Option<CallTree>,
    pub phase2_store: Option<CachedStore<Phase2Archive>>,
    pub string_index: Option<StringIndex>,

    // Scan
    pub scan_store: Option<CachedStore<ScanArchive>>,
    pub reg_last_def: Option<RegLastDef>,

    // LineIndex
    pub lidx_store: Option<CachedStore<LineIndexArchive>>,

    // 不变
    pub slice_result: Option<bitvec::prelude::BitVec>,
    pub scan_strings_cancelled: Arc<AtomicBool>,
    pub call_annotations: HashMap<u32, CallAnnotation>,
    pub consumed_seqs: Vec<u32>,
    pub call_search_texts: HashMap<u32, String>,
}
```

- [ ] **Step 2: 添加便捷 view 方法**

```rust
impl SessionState {
    pub fn mem_accesses_view(&self) -> Option<MemAccessView<'_>> { ... }
    pub fn reg_checkpoints_view(&self) -> Option<RegCheckpointsView<'_>> { ... }
    pub fn deps_view(&self) -> Option<DepsView<'_>> { ... }
    pub fn mem_last_def_view(&self) -> Option<MemLastDefView<'_>> { ... }
    pub fn pair_split_view(&self) -> Option<PairSplitView<'_>> { ... }
    pub fn init_mem_loads_view(&self) -> Option<BitView<'_>> { ... }
    pub fn line_index_view(&self) -> Option<LineIndexView<'_>> { ... }
    pub fn scan_view(&self) -> Option<ScanView<'_>> { ... }
    pub fn scan_line_count(&self) -> u32 { ... }
}
```

- [ ] **Step 3: 更新 file.rs 中 SessionState 初始化**

`create_session` 中的 `SessionState { ... }` 更新字段名。

- [ ] **Step 4: 删除旧的 Phase2State 结构体**

从 `state.rs` 中移除 `Phase2State`，不再需要。

- [ ] **Step 5: 编译检查（会有大量报错，这是预期的）**

Run: `cargo check 2>&1 | head -50`
Expected: 报错来自 commands/ 和 taint/slicer.rs 中对旧字段的引用。这些在后续 task 中修复。

- [ ] **Step 6: Commit**

```bash
git add src/state.rs src/commands/file.rs
git commit -m "refactor(state): restructure SessionState for rkyv cache"
```

---

## Task 10: 迁移 commands — call_tree, registers, memory

**Files:**
- Modify: `src/commands/call_tree.rs`
- Modify: `src/commands/registers.rs`
- Modify: `src/commands/memory.rs`

- [ ] **Step 1: 迁移 call_tree.rs**

所有 `phase2.call_tree` → `session.call_tree.as_ref().ok_or("索引尚未构建完成")?`。

`node_to_dto` 签名不变（接受 `&CallTreeNode`）。

- [ ] **Step 2: 迁移 registers.rs**

`phase2.reg_checkpoints.get_nearest_before(seq)` → `session.reg_checkpoints_view().ok_or("...")?.nearest_before(seq)`。

返回值类型不变：`(u32, &[u64; REG_COUNT])`。

- [ ] **Step 3: 迁移 memory.rs**

`phase2.mem_accesses.get(addr)` → `session.mem_accesses_view().ok_or("...")?.query(addr)`。

返回值从 `&[MemAccessRecord]` 变为 `&[FlatMemAccessRecord]`。更新字段访问：
- `rec.rw == MemRw::Read` → `rec.is_read()`
- `rec.rw == MemRw::Write` → `rec.is_write()`

`get_mem_history` 中 `records.partition_point(|r| r.seq <= seq)` 逻辑不变（`FlatMemAccessRecord` 也有 `seq` 字段）。

- [ ] **Step 4: 编译检查**

Run: `cargo check`
Expected: 这三个文件的报错消除

- [ ] **Step 5: Commit**

```bash
git add src/commands/call_tree.rs src/commands/registers.rs src/commands/memory.rs
git commit -m "refactor(commands): migrate call_tree, registers, memory to new SessionState"
```

---

## Task 11: 迁移 slicer + slice command

**Files:**
- Modify: `src/taint/slicer.rs`
- Modify: `src/commands/slice.rs`

- [ ] **Step 1: 重构 slicer.rs**

`bfs_slice(state: &ScanState, ...)` → `bfs_slice(view: &ScanView, ...)`。

内部变更：
- `state.line_count` → `view.line_count`
- `state.deps.row(line)` → `view.deps.row(line)`
- `state.deps.patch_row(line)` → `view.deps.patch_row(line)`
- `state.pair_split.get(&line)` → `view.pair_split.get(&line)`，返回 `PairSplitEntry` 而非 `PairSplitDeps`
- `pair_split.contains_key(&line)` → `view.pair_split.contains_key(&line)`
- `enqueue_dep` 的 `pair_split` 参数从 `&FxHashMap<u32, PairSplitDeps>` 改为 `&PairSplitView`

`PairSplitEntry` 的字段名与 `PairSplitDeps` 一致（`shared`, `half1_deps`, `half2_deps`），类型从 `SmallVec<[u32; N]>` 变为 `&[u32]`。遍历代码中 `for &dep in &split.shared` → `for &dep in split.shared` 即可。

`write_sliced_bytes` 的 `init_mem_loads: &BitVec` 参数改为接受 `&BitView`，内部 `init_mem_loads[line_idx]` → `init_mem_loads.get(line_idx)`。

- [ ] **Step 2: 重构 slice.rs**

- `scan_state.reg_last_def.get(&reg)` → `session.reg_last_def.as_ref().ok_or("...")?.get(&reg)`
- `scan_state.mem_last_def.get(&addr)` → `session.mem_last_def_view().ok_or("...")?.get(&addr)`
- `slicer::bfs_slice(scan_state, ...)` → `slicer::bfs_slice(&session.scan_view().ok_or("...")?, ...)`

- [ ] **Step 3: 更新 slicer 测试**

slicer 测试中 `scanner::scan_from_string()` 返回 `ScanState`，需要将其转换为 `ScanView`。添加一个 helper：

```rust
#[cfg(test)]
fn scan_state_to_scan_view(state: &ScanState) -> ScanView<'_> {
    // 直接用 ScanState 内部数据构建 view（测试专用，不走 flat 转换）
    // 这需要 ScanState 的字段提供 view 方法或手动构造
}
```

或者更简单的方案：在测试中先将 ScanState 转换为 Flat 类型再构建 ScanView。使用 convert 模块的转换函数。

- [ ] **Step 4: 运行 slicer 测试**

Run: `cargo test --lib taint::slicer`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/taint/slicer.rs src/commands/slice.rs
git commit -m "refactor(slicer): migrate to ScanView API"
```

---

## Task 12: 迁移 strings command

**Files:**
- Modify: `src/commands/strings.rs`
- Modify: `src/taint/strings.rs`

- [ ] **Step 1: 修改 fill_xref_counts 签名**

```rust
// 之前
pub fn fill_xref_counts(index: &mut StringIndex, mem_idx: &MemAccessIndex)

// 之后
pub fn fill_xref_counts(index: &mut StringIndex, mem_view: &MemAccessView)
```

内部 `mem_idx.iter_all()` → `mem_view.iter_all()`。`records.rw == MemRw::Read` → `records.is_read()`。

- [ ] **Step 2: 迁移 strings.rs 命令**

- `phase2.string_index` → `session.string_index`
- `phase2.mem_accesses` → `session.mem_accesses_view()`
- `save_cache(&fp, data, phase2)` → `save_string_cache(&fp, data, &string_index)`

- [ ] **Step 3: 编译检查**

Run: `cargo check`

- [ ] **Step 4: Commit**

```bash
git add src/commands/strings.rs src/taint/strings.rs
git commit -m "refactor(strings): migrate to MemAccessView and independent StringIndex cache"
```

---

## Task 13: 迁移 index.rs — 缓存加载/保存流程

**Files:**
- Modify: `src/commands/index.rs`

这是最关键的文件——连接扫描结果与缓存系统。

- [ ] **Step 1: 重写缓存命中路径**

```rust
// 三缓存全部命中 → 秒开
if !force && detected_format == TraceFormat::Unidbg {
    if let (Some(p2_mmap), Some(scan_mmap), Some(lidx_mmap)) = (
        cache::load_phase2_rkyv(&file_path, data),
        cache::load_scan_rkyv(&file_path, data),
        cache::load_lidx_rkyv(&file_path, data),
    ) {
        let string_index = cache::load_string_cache(&file_path, data);

        let phase2_store = CachedStore::<Phase2Archive>::Mapped(p2_mmap);
        let call_tree = phase2_store.deserialize_call_tree();

        let scan_store = CachedStore::<ScanArchive>::Mapped(scan_mmap);
        let reg_last_def = scan_store.deserialize_reg_last_def(); // 从 archived.reg_last_def_inner 构造

        let lidx_store = CachedStore::<LineIndexArchive>::Mapped(lidx_mmap);
        let total_lines = lidx_store.view().total_lines();

        // 写入 session...
        return Ok(());
    }
}
```

- [ ] **Step 2: 重写扫描后写入 session 的逻辑**

扫描产出 `ScanResult { scan_state, phase2, line_index, ... }`。需要：
1. 从 phase2 拆出 call_tree、string_index
2. 用 convert 模块将 MemAccessIndex/RegCheckpoints/DepsStorage 等转为 Flat 类型
3. 组装 Phase2Archive、ScanArchive、LineIndexArchive
4. 存入 SessionState 为 `CachedStore::Owned(...)`

- [ ] **Step 3: 重写后台缓存保存**

```rust
// 后台保存（不阻塞）
tauri::async_runtime::spawn(async move {
    let _ = tauri::async_runtime::spawn_blocking(move || {
        cache::save_phase2_rkyv(&fp, data, &phase2_archive);
        cache::save_scan_rkyv(&fp, data, &scan_archive);
        cache::save_lidx_rkyv(&fp, data, &lidx_archive);
        if let Some(ref si) = string_index {
            cache::save_string_cache(&fp, data, si);
        }
    }).await;
});
```

注意：后台保存需要 clone Archive 数据或者从 session 的读锁中取。由于 Archive 数据在 `CachedStore::Owned` 中，需要从 session 读取。保持现有模式：获取读锁 → 引用数据 → 序列化。

- [ ] **Step 4: 更新 index-progress 事件中的 hasStringIndex 字段**

`phase2.string_index.strings.is_empty()` → `session.string_index.as_ref().map(|s| !s.strings.is_empty()).unwrap_or(false)`

- [ ] **Step 5: 编译检查**

Run: `cargo check`
Expected: 编译通过（所有 commands 已迁移）

- [ ] **Step 6: Commit**

```bash
git add src/commands/index.rs
git commit -m "feat(index): rewrite cache load/save with rkyv zero-copy"
```

---

## Task 14: 清理旧代码 + 完整编译

**Files:**
- Modify: `src/state.rs` — 删除 `Phase2State`
- Modify: `src/taint/mem_access.rs` — 标记为 `#[cfg(test)]` 或保留给扫描阶段使用
- Modify: `src/taint/reg_checkpoint.rs` — 扫描阶段仍需要原生类型，保留

- [ ] **Step 1: 清理 state.rs**

删除 `Phase2State`（已拆分）。删除对 `MemAccessIndex`、`RegCheckpoints`、`StringIndex` 的旧 import（如果不再使用）。

- [ ] **Step 2: 确认扫描阶段仍然使用原生类型**

扫描阶段（scanner.rs, chunk_scan.rs, merge.rs, mod.rs）仍然使用 `MemAccessIndex`、`RegCheckpoints`、`DepsStorage` 等原生类型。这些保留不变——只在扫描完成后通过 convert 模块转为 Flat 类型。

- [ ] **Step 3: 完整编译**

Run: `cargo build`
Expected: 编译成功

- [ ] **Step 4: 运行全部测试**

Run: `cargo test`
Expected: 所有测试通过

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "refactor: clean up old Phase2State, verify full build and tests"
```

---

## Task 15: 端到端验证

- [ ] **Step 1: 删除旧缓存**

```bash
rm -f ~/Library/Application\ Support/trace-ui/cache/*.bin
```

- [ ] **Step 2: 启动应用，首次打开大文件**

Run: `cargo tauri dev`

打开 23GB trace 文件。观察：
- 扫描完成后是否在后台生成 `.p2.rkyv`, `.scan.rkyv`, `.lidx.rkyv`, `.strings.bin` 文件
- 检查缓存文件大小是否合理

- [ ] **Step 3: 关闭文件，再次打开同一文件**

观察：
- 是否命中缓存（看 stderr 日志）
- 打开耗时是否 < 1s
- 所有功能是否正常：call tree、内存查看、寄存器查看、字符串搜索、污点切片

- [ ] **Step 4: 测试字符串扫描**

执行 scan_strings，验证结果正确保存到独立的 `.strings.bin`。

- [ ] **Step 5: Commit 最终状态**

```bash
git add -A
git commit -m "feat(cache): rkyv zero-copy cache system complete"
```
