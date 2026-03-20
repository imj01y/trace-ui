# rkyv 零拷贝缓存设计（v2）

## 背景

23GB trace 文件首次打开耗时 ~24s（全量扫描），二次打开命中缓存仍需 ~14s。原因是 bincode 反序列化 4.2GB 缓存数据（Phase2 1.5GB + ScanState 2.7GB + LineIndex 5.7MB）需要逐条重建 HashMap、分配堆内存。

## 目标

缓存命中时文件打开耗时从 14s 降至 < 0.5s。

## 核心思路

用 rkyv 零拷贝替代 bincode 反序列化。缓存数据 mmap 后直接通过 rkyv Archived 类型访问，不做反序列化。

关键原理：rkyv 的 `ArchivedVec<u32>` 虽然 ≠ `Vec<u32>`，但 `ArchivedVec<u32>.as_slice()` 返回 `&[u32]`——与原生 Vec 的切片类型完全一致。因此对于内部只有 `Vec<原始类型>` 的扁平结构体，只需提供返回 `&[u32]`/`&[u64]` 的查询方法，Owned 和 Mapped 两种变体就能返回相同的类型。

不需要 trait 抽象，改用 **View 模式**：为每种数据构建一个轻量 View 结构体（持有 `&[u32]` 等切片引用），Owned 和 Mapped 变体都能构造出相同的 View。

对包含 String/Vec 的小结构体（CallTree）从 rkyv 急切反序列化；StringIndex 独立存储为 bincode（可变，scan_strings 需要修改它）。

## 缓存文件布局

### 文件拆分

| 后缀 | 内容 | 序列化 | 加载方式 |
|------|------|--------|---------|
| `.p2.rkyv` | Phase2Archive (FlatMemAccess + FlatRegCheckpoints + CallTree) | rkyv | mmap 零拷贝 + CallTree 急切反序列化 |
| `.scan.rkyv` | ScanArchive (FlatDeps + FlatMemLastDef + FlatPairSplit + FlatBitVec + RegLastDef 等) | rkyv | mmap 零拷贝 |
| `.lidx.rkyv` | LineIndexArchive | rkyv | mmap 零拷贝 |
| `.strings.bin` | StringIndex | bincode | 传统反序列化 |

MAGIC 版本号从 `TCACHE03` 升级为 `TCACHE04`，旧缓存自动失效。检测到 `TCACHE03` 时主动删除旧缓存文件。

### 文件内部格式

```
[0..8]    MAGIC ("TCACHE04")
[8..16]   原始文件大小 (u64 LE)
[16..48]  原始文件前 1MB 的 SHA-256 hash
[48..64]  保留/填充（确保 64 字节对齐）
[64..]    rkyv archived 数据（或 bincode 数据）
```

Header 从 48 字节填充到 **64 字节**，确保 rkyv 数据起始位置 8 字节对齐。

## 数据结构变更

### Phase2 拆分

当前 `Phase2State` 拆分为独立字段：

```
Phase2State {                     →  独立字段：
    call_tree: CallTree               call_tree: Option<CallTree>         // 原生，急切反序列化
    mem_accesses: MemAccessIndex      phase2_store: Option<CachedStore>   // 零拷贝 (mmap 或 owned)
    reg_checkpoints: RegCheckpoints   （reg_checkpoints 包含在 phase2_store 中）
    string_index: StringIndex         string_index: Option<StringIndex>   // 独立 bincode
}
```

### 纯原始类型记录（支持 `#[rkyv(as = "Self")]`）

仅以下**不含 Vec/String 的 Copy 结构体**使用 `as = "Self"`：

```rust
/// 内存访问记录（纯原始类型，archived = self）
#[derive(Clone, Copy, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(as = "Self")]
#[repr(C)]
pub struct FlatMemAccessRecord {
    pub insn_addr: u64,  // 8  — u64 在前，避免 repr(C) 填充
    pub data: u64,       // 8
    pub seq: u32,        // 4
    pub size: u8,        // 1
    pub rw: u8,          // 1  — 0=Read, 1=Write
    pub _pad: [u8; 2],   // 2  — 凑齐 24 字节
}
// sizeof = 24, 无浪费
```

辅助方法：

```rust
impl FlatMemAccessRecord {
    #[inline]
    pub fn is_read(&self) -> bool { self.rw == 0 }
    #[inline]
    pub fn is_write(&self) -> bool { self.rw == 1 }
}
```

### 扁平化数据结构（含 Vec，使用标准 rkyv archive）

以下结构体内含 `Vec<原始类型>`，**不能**用 `as = "Self"`，使用 rkyv 标准 derive。Archived 类型中 `ArchivedVec<u32>.as_slice() → &[u32]`，查询方法返回原生切片。

#### FlatMemAccess（替代 MemAccessIndex 的 FxHashMap）

```rust
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct FlatMemAccess {
    pub addrs: Vec<u64>,                    // 排序的唯一地址
    pub offsets: Vec<u32>,                  // CSR: addrs[i] 的记录 = records[offsets[i]..offsets[i+1]]
    pub records: Vec<FlatMemAccessRecord>,  // 扁平化记录数组
}
```

查询：`binary_search(&addrs, target_addr)` → `&records[offsets[i]..offsets[i+1]]`。

构建：扫描完成后，从 `FxHashMap<u64, Vec<MemAccessRecord>>` 一次性排序转换。

#### FlatRegCheckpoints（替代 RegCheckpoints）

```rust
const REG_COUNT: usize = 98;  // = RegId::COUNT

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct FlatRegCheckpoints {
    pub interval: u32,
    pub count: u32,         // 快照数量
    pub data: Vec<u64>,     // 扁平化，每 REG_COUNT(98) 个 u64 为一组
}
```

查询 `nearest_before(seq)`：
- `idx = min(seq / interval, count - 1)`
- `&data[idx * 98 .. (idx+1) * 98]`

#### FlatDeps（替代 DepsStorage）

```rust
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct FlatDeps {
    // chunk 信息（Single 时只有 1 个 chunk）
    pub chunk_start_lines: Vec<u32>,
    pub chunk_offsets_start: Vec<u32>,  // chunk i 的 offsets 在 all_offsets 中的起始索引
    pub chunk_data_start: Vec<u32>,     // chunk i 的 data 在 all_data 中的起始索引
    pub all_offsets: Vec<u32>,          // 所有 chunk 的 offsets 拼接
    pub all_data: Vec<u32>,             // 所有 chunk 的 data 拼接

    // patch groups（跨 chunk 补丁依赖）
    pub patch_lines: Vec<u32>,       // 排序的行号
    pub patch_offsets: Vec<u32>,     // CSR: patch_data[patch_offsets[i]..patch_offsets[i+1]]
    pub patch_data: Vec<u32>,
}
```

查询 `row(global_line)`：
1. `binary_search chunk_start_lines` → `chunk_idx`
2. `offsets_base = chunk_offsets_start[chunk_idx]`
3. `data_base = chunk_data_start[chunk_idx]`
4. `local = global_line - chunk_start_lines[chunk_idx]`
5. `start = all_offsets[offsets_base + local] + data_base`
6. `end = all_offsets[offsets_base + local + 1] + data_base`
7. `&all_data[start as usize .. end as usize]`

查询 `patch_row(global_line)`：
1. `binary_search patch_lines`
2. 命中 → `&patch_data[patch_offsets[i]..patch_offsets[i+1]]`
3. 未命中 → `&[]`

#### FlatMemLastDef（替代 MemLastDef::Sorted）

```rust
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct FlatMemLastDef {
    pub addrs: Vec<u64>,   // 排序
    pub lines: Vec<u32>,
    pub values: Vec<u64>,
}
```

查询：`binary_search(&addrs, target)` → `Some((lines[i], values[i]))`。

#### FlatPairSplit（替代 FxHashMap<u32, PairSplitDeps>）

```rust
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct FlatPairSplit {
    pub keys: Vec<u32>,           // 排序的行号
    pub seg_offsets: Vec<u32>,    // 每个 key 有 3 段起始：[shared_start, half1_start, half2_start]
                                  // seg_offsets.len() == keys.len() * 3 + 1（末尾哨兵）
    pub data: Vec<u32>,           // 扁平化的依赖数据
}
```

构建时 assert: `seg_offsets.len() == keys.len() * 3 + 1`

查询 `query(line)` → `binary_search keys` 得到 index `i`：
- `shared = &data[seg_offsets[i*3] .. seg_offsets[i*3+1]]`
- `half1  = &data[seg_offsets[i*3+1] .. seg_offsets[i*3+2]]`
- `half2  = &data[seg_offsets[i*3+2] .. seg_offsets[(i+1)*3]]`

`contains(line)` → `keys.binary_search(&line).is_ok()`

#### FlatBitVec（替代 bitvec::BitVec）

```rust
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct FlatBitVec {
    pub data: Vec<u8>,  // 原始字节（小端位序）
    pub len: u32,       // bit 数
}
```

查询：`(data[idx / 8] >> (idx % 8)) & 1 != 0`。

#### LineIndexArchive

```rust
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct LineIndexArchive {
    pub sampled_offsets: Vec<u64>,
    pub total: u32,
}
```

### 不变的结构体

- **CallTree / CallTreeNode**：包含 `Option<String>` 和 `Vec<u32>`，用 rkyv 标准 archive + 急切反序列化。大小很小（几 MB），反序列化 < 100ms。
- **RegLastDef**：`[u32; 98]` = 392 字节，直接 copy。
- **StringIndex / StringRecord**：独立 bincode 缓存，可变（scan_strings 修改后单独保存）。

## View 模式（替代 Trait 抽象）

### 设计原理

rkyv 的 `ArchivedVec<u32>.as_slice()` → `&[u32]`，与原生 `Vec<u32>.as_slice()` 返回类型一致。利用这一点，为每种数据定义一个 **View 结构体**，持有从 Owned 或 Archived 数据提取的切片引用：

```rust
/// FlatMemAccess 的查询视图（Owned 和 Mapped 通用）
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

### 从 Owned/Archived 构造 View

```rust
// 从原生类型构造
impl FlatMemAccess {
    fn view(&self) -> MemAccessView<'_> {
        MemAccessView {
            addrs: &self.addrs,
            offsets: &self.offsets,
            records: &self.records,
        }
    }
}

// 从 archived 类型构造（ArchivedVec<u64>.as_slice() → &[u64]）
impl ArchivedFlatMemAccess {
    fn view(&self) -> MemAccessView<'_> {
        MemAccessView {
            addrs: self.addrs.as_slice(),           // &[u64]
            offsets: self.offsets.as_slice(),         // &[u32]
            records: self.records.as_slice(),         // &[FlatMemAccessRecord]（因为 as = "Self"）
        }
    }
}
```

### 其他 View 结构体

```rust
pub struct RegCheckpointsView<'a> {
    interval: u32,
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
    pub fn row(&self, global_line: usize) -> &'a [u32] { /* 见上文查询逻辑 */ }
    pub fn patch_row(&self, global_line: usize) -> &'a [u32] { /* 见上文 */ }
}

pub struct MemLastDefView<'a> {
    addrs: &'a [u64],
    lines: &'a [u32],
    values: &'a [u64],
}

impl<'a> MemLastDefView<'a> {
    pub fn get(&self, addr: &u64) -> Option<(u32, u64)> {
        let idx = self.addrs.binary_search(addr).ok()?;
        Some((self.lines[idx], self.values[idx]))
    }
}

pub struct PairSplitView<'a> {
    keys: &'a [u32],
    seg_offsets: &'a [u32],
    data: &'a [u32],
}

pub struct PairSplitEntry<'a> {
    pub shared: &'a [u32],
    pub half1_deps: &'a [u32],
    pub half2_deps: &'a [u32],
}

impl<'a> PairSplitView<'a> {
    pub fn get(&self, line: &u32) -> Option<PairSplitEntry<'a>> {
        let i = self.keys.binary_search(line).ok()?;
        Some(PairSplitEntry {
            shared: &self.data[self.seg_offsets[i*3] as usize .. self.seg_offsets[i*3+1] as usize],
            half1_deps: &self.data[self.seg_offsets[i*3+1] as usize .. self.seg_offsets[i*3+2] as usize],
            half2_deps: &self.data[self.seg_offsets[i*3+2] as usize .. self.seg_offsets[(i+1)*3] as usize],
        })
    }
    pub fn contains_key(&self, line: &u32) -> bool {
        self.keys.binary_search(line).is_ok()
    }
}

pub struct BitView<'a> {
    data: &'a [u8],
    len: u32,
}

impl<'a> BitView<'a> {
    pub fn get(&self, idx: usize) -> bool {
        idx < self.len as usize && (self.data[idx / 8] >> (idx % 8)) & 1 != 0
    }
    pub fn len(&self) -> usize { self.len as usize }
}

pub struct LineIndexView<'a> {
    sampled_offsets: &'a [u64],
    total: u32,
}

impl<'a> LineIndexView<'a> {
    pub fn total_lines(&self) -> u32 { self.total }
    pub fn get_line(&self, data: &'a [u8], seq: u32) -> Option<&'a [u8]> { /* 同现有逻辑 */ }
    pub fn line_byte_offset(&self, data: &[u8], seq: u32) -> Option<u64> { /* 同现有逻辑 */ }
}
```

## CachedStore：统一 mmap 管理

不再为每种 Flat 类型单独管理 mmap。每个缓存文件对应一个 `CachedStore`，持有 `Arc<Mmap>` 或 owned 数据：

```rust
/// 一个 rkyv 缓存文件的存储：mmap 零拷贝或拥有原生数据。
pub enum CachedStore<A: rkyv::Archive> {
    Owned(A),
    Mapped(Arc<Mmap>),
}

const HEADER_LEN: usize = 64;

impl<A: rkyv::Archive> CachedStore<A> {
    /// 获取 archived 引用（仅 Mapped 变体）
    fn archived(&self) -> &A::Archived {
        match self {
            Self::Mapped(mmap) => unsafe {
                rkyv::access_unchecked::<A>(&mmap[HEADER_LEN..])
            },
            Self::Owned(_) => panic!("use view() instead"),
        }
    }
}
```

每种 Archive 类型提供 `view()` 方法：

```rust
impl CachedStore<Phase2Archive> {
    pub fn mem_accesses_view(&self) -> MemAccessView<'_> {
        match self {
            Self::Owned(a) => a.mem_accesses.view(),
            Self::Mapped(_) => self.archived().mem_accesses.view(),
        }
    }

    pub fn reg_checkpoints_view(&self) -> RegCheckpointsView<'_> {
        match self {
            Self::Owned(a) => a.reg_checkpoints.view(),
            Self::Mapped(_) => self.archived().reg_checkpoints.view(),
        }
    }
}

impl CachedStore<ScanArchive> {
    pub fn deps_view(&self) -> DepsView<'_> { /* 同理 */ }
    pub fn mem_last_def_view(&self) -> MemLastDefView<'_> { /* 同理 */ }
    pub fn pair_split_view(&self) -> PairSplitView<'_> { /* 同理 */ }
    pub fn init_mem_loads_view(&self) -> BitView<'_> { /* 同理 */ }
    pub fn line_count(&self) -> u32 { /* 从 archive 或 owned 读取 */ }
}

impl CachedStore<LineIndexArchive> {
    pub fn view(&self) -> LineIndexView<'_> { /* 同理 */ }
}
```

## SessionState 变更

```rust
pub struct SessionState {
    pub mmap: Arc<Mmap>,
    pub file_path: String,
    pub total_lines: u32,
    pub file_size: u64,
    pub trace_format: TraceFormat,

    // Phase2 数据（拆分后）
    pub call_tree: Option<CallTree>,                         // 原生类型，急切反序列化
    pub phase2_store: Option<CachedStore<Phase2Archive>>,    // 零拷贝或 owned
    pub string_index: Option<StringIndex>,                   // 独立 bincode，可变

    // Scan 数据
    pub scan_store: Option<CachedStore<ScanArchive>>,        // 零拷贝或 owned
    pub reg_last_def: Option<RegLastDef>,                    // 392 字节，直接 copy

    // LineIndex
    pub lidx_store: Option<CachedStore<LineIndexArchive>>,   // 零拷贝或 owned

    // 其余字段不变
    pub slice_result: Option<bitvec::prelude::BitVec>,
    pub scan_strings_cancelled: Arc<AtomicBool>,
    pub call_annotations: HashMap<u32, CallAnnotation>,
    pub consumed_seqs: Vec<u32>,
}
```

便捷方法：

```rust
impl SessionState {
    pub fn mem_accesses_view(&self) -> Option<MemAccessView<'_>> {
        self.phase2_store.as_ref().map(|s| s.mem_accesses_view())
    }
    pub fn reg_checkpoints_view(&self) -> Option<RegCheckpointsView<'_>> {
        self.phase2_store.as_ref().map(|s| s.reg_checkpoints_view())
    }
    pub fn deps_view(&self) -> Option<DepsView<'_>> {
        self.scan_store.as_ref().map(|s| s.deps_view())
    }
    pub fn mem_last_def_view(&self) -> Option<MemLastDefView<'_>> {
        self.scan_store.as_ref().map(|s| s.mem_last_def_view())
    }
    pub fn pair_split_view(&self) -> Option<PairSplitView<'_>> {
        self.scan_store.as_ref().map(|s| s.pair_split_view())
    }
    pub fn init_mem_loads_view(&self) -> Option<BitView<'_>> {
        self.scan_store.as_ref().map(|s| s.init_mem_loads_view())
    }
    pub fn line_index_view(&self) -> Option<LineIndexView<'_>> {
        self.lidx_store.as_ref().map(|s| s.view())
    }
    pub fn scan_line_count(&self) -> u32 {
        self.scan_store.as_ref().map(|s| s.line_count()).unwrap_or(0)
    }
}
```

## rkyv 缓存文件内部布局

### `.p2.rkyv` 文件

```rust
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct Phase2Archive {
    pub mem_accesses: FlatMemAccess,
    pub reg_checkpoints: FlatRegCheckpoints,
    pub call_tree: CallTree,  // rkyv 标准 archive（含 ArchivedString 等）
}
```

加载时：
- `mem_accesses` 和 `reg_checkpoints`：零拷贝，通过 view() 访问
- `call_tree`：`archived.call_tree.deserialize(...)` 得到原生 `CallTree`

### `.scan.rkyv` 文件

```rust
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct ScanArchive {
    pub deps: FlatDeps,
    pub mem_last_def: FlatMemLastDef,
    pub pair_split: FlatPairSplit,
    pub init_mem_loads: FlatBitVec,
    pub reg_last_def_inner: Vec<u32>,  // [u32; 98] 序列化为 Vec
    pub line_count: u32,
    pub parsed_count: u32,
    pub mem_op_count: u32,
}
```

### `.lidx.rkyv` 文件

```rust
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct LineIndexArchive {
    pub sampled_offsets: Vec<u64>,
    pub total: u32,
}
```

### `.strings.bin` 文件

```rust
// 与现有 StringIndex 结构相同，bincode 序列化
pub struct StringIndex {
    pub strings: Vec<StringRecord>,
}
```

## slicer API 重构

当前 `bfs_slice` 接受 `&ScanState`，ScanState 拆散后需要改为接受 View 组合：

```rust
/// BFS 所需的 scan 数据视图
pub struct ScanView<'a> {
    pub deps: DepsView<'a>,
    pub pair_split: PairSplitView<'a>,
    pub init_mem_loads: BitView<'a>,
    pub line_count: u32,
}

/// 从 SessionState 构造
impl SessionState {
    pub fn scan_view(&self) -> Option<ScanView<'_>> {
        let store = self.scan_store.as_ref()?;
        Some(ScanView {
            deps: store.deps_view(),
            pair_split: store.pair_split_view(),
            init_mem_loads: store.init_mem_loads_view(),
            line_count: store.line_count(),
        })
    }
}

// slicer.rs 签名变更
pub fn bfs_slice(view: &ScanView, start_indices: &[u32]) -> BitVec { ... }
pub fn bfs_slice_with_options(view: &ScanView, start_indices: &[u32], data_only: bool) -> BitVec { ... }
```

slicer 内部访问变更：
- `state.line_count` → `view.line_count`
- `state.deps.row(line)` → `view.deps.row(line)`
- `state.deps.patch_row(line)` → `view.deps.patch_row(line)`
- `state.pair_split.get(&line)` → `view.pair_split.get(&line)` (返回 `Option<PairSplitEntry>`)
- `pair_split.contains_key(&line)` → `view.pair_split.contains_key(&line)`

`enqueue_dep` 的 `pair_split: &FxHashMap<u32, PairSplitDeps>` 参数改为 `pair_split: &PairSplitView`。

## fill_xref_counts 签名变更

```rust
// 之前：
pub fn fill_xref_counts(index: &mut StringIndex, mem_accesses: &MemAccessIndex)

// 之后：
pub fn fill_xref_counts(index: &mut StringIndex, mem_accesses: &MemAccessView)
```

## 缓存加载流程（命中时）

```
1. detect_format(data)
2. 仅 Unidbg 格式走缓存（Gumtrace 格式需要 call_annotations/consumed_seqs，不在缓存中）
3. 并行 mmap 3 个 rkyv 缓存文件 + bincode 读取 StringIndex
4. 校验每个文件的 header（MAGIC + 文件大小 + SHA-256）
5. Phase2:
   a. mmap .p2.rkyv → Arc<Mmap>
   b. 构造 CachedStore::Mapped(Arc<Mmap>)
   c. 从 archived 急切反序列化 CallTree（< 100ms）
6. Scan:
   a. mmap .scan.rkyv → Arc<Mmap>
   b. 构造 CachedStore::Mapped(Arc<Mmap>)
   c. copy reg_last_def（392 字节）
7. LineIndex:
   a. mmap .lidx.rkyv → Arc<Mmap>
   b. 构造 CachedStore::Mapped(Arc<Mmap>)
8. StringIndex: bincode::deserialize（几百 KB，< 10ms）
9. 写入 SessionState 各字段
```

总耗时：< 0.5s。

## 缓存保存流程（首次扫描后）

后台线程中：

```
1. 从 SessionState 读取原生数据
2. 转换为 Flat 格式：
   - MemAccessIndex (HashMap) → FlatMemAccess（排序 + CSR）
   - RegCheckpoints → FlatRegCheckpoints（展平 snapshots）
   - DepsStorage → FlatDeps（拼接 chunks）
   - MemLastDef → FlatMemLastDef（已是 Sorted 变体，直接拆三数组）
   - pair_split (HashMap<u32, PairSplitDeps>) → FlatPairSplit（排序 + CSR）
   - init_mem_loads (BitVec) → FlatBitVec
   - LineIndex → LineIndexArchive
3. 组装 Phase2Archive / ScanArchive / LineIndexArchive
4. 写入 rkyv 缓存文件（header + rkyv::to_bytes）
5. 写入 StringIndex bincode 缓存文件
```

## scan_strings 修改流程

```rust
// 之前：
phase2.string_index = new_index;
cache::save_cache(&fp, data, phase2);  // 重新序列化整个 1.5GB Phase2

// 之后：
session.string_index = Some(new_index);
cache::save_string_cache(&fp, data, &new_index);  // 只序列化几百 KB StringIndex
```

## cache.rs 变更

### 新增函数

```rust
pub fn load_phase2_rkyv(file_path: &str, data: &[u8]) -> Option<Arc<Mmap>>;
pub fn load_scan_rkyv(file_path: &str, data: &[u8]) -> Option<Arc<Mmap>>;
pub fn load_lidx_rkyv(file_path: &str, data: &[u8]) -> Option<Arc<Mmap>>;
pub fn load_string_cache(file_path: &str, data: &[u8]) -> Option<StringIndex>;

pub fn save_phase2_rkyv(file_path: &str, data: &[u8], archive: &Phase2Archive);
pub fn save_scan_rkyv(file_path: &str, data: &[u8], archive: &ScanArchive);
pub fn save_lidx_rkyv(file_path: &str, data: &[u8], archive: &LineIndexArchive);
pub fn save_string_cache(file_path: &str, data: &[u8], index: &StringIndex);
```

### delete_cache / clear_all_cache 更新

```rust
pub fn delete_cache(file_path: &str) {
    // 新后缀
    for suffix in [".p2.rkyv", ".scan.rkyv", ".lidx.rkyv", ".strings.bin"] {
        if let Some(p) = cache_path(file_path, suffix) {
            let _ = std::fs::remove_file(p);
        }
    }
    // 旧后缀（兼容清理）
    for suffix in ["", "-scan", "-lidx"] {
        if let Some(p) = cache_path(file_path, suffix) {
            let _ = std::fs::remove_file(p);
        }
    }
}

pub fn clear_all_cache() -> (u32, u64) {
    // 清理 .bin 和 .rkyv 后缀
    // ...
}
```

### 旧缓存迁移

检测到 MAGIC = `TCACHE03` 时，`load_cached` 返回 None 并主动删除旧文件。

## 受影响的调用点汇总

### Phase2 相关

| 文件 | 当前访问 | 变更 |
|------|---------|------|
| `commands/call_tree.rs:57-62` | `phase2.call_tree.nodes.iter()` | `session.call_tree.as_ref()?.nodes.iter()` — 不变 |
| `commands/call_tree.rs:73` | `phase2.call_tree.nodes.len()` | `session.call_tree.as_ref()?.nodes.len()` |
| `commands/call_tree.rs:91,101` | `phase2.call_tree.nodes.get(id)` | `session.call_tree.as_ref()?.nodes.get(id)` |
| `commands/memory.rs:65,80` | `phase2.mem_accesses.get(addr)` | `session.mem_accesses_view()?.query(addr)` — 返回 `&[FlatMemAccessRecord]` |
| `commands/memory.rs:137` | `mem_idx.get(target_addr)` | `session.mem_accesses_view()?.query(target_addr)` |
| `commands/registers.rs:43-45` | `phase2.reg_checkpoints.get_nearest_before(seq)` | `session.reg_checkpoints_view()?.nearest_before(seq)` |
| `commands/strings.rs:49` | `phase2.string_index.strings.iter()` | `session.string_index.as_ref()?.strings.iter()` — 不变 |
| `commands/strings.rs:161` | `phase2.mem_accesses.iter_all()` | `session.mem_accesses_view()?.iter_all()` |
| `commands/strings.rs:196` | `fill_xref_counts(&mut idx, &phase2.mem_accesses)` | `fill_xref_counts(&mut idx, &session.mem_accesses_view()?)` |
| `commands/strings.rs:204-206` | `phase2.string_index = ..; save_cache(phase2)` | `session.string_index = ..; save_string_cache(..)` |
| `commands/index.rs:25` | `phase2.string_index.strings.is_empty()` | `session.string_index.as_ref().map(\|s\| !s.strings.is_empty())` |

### ScanState 相关

| 文件 | 当前访问 | 变更 |
|------|---------|------|
| `taint/slicer.rs` (全文件) | `bfs_slice(state: &ScanState, ...)` | `bfs_slice(view: &ScanView, ...)` |
| `commands/slice.rs:36` | `scan_state.reg_last_def.get(&reg)` | `session.reg_last_def.as_ref()?.get(&reg)` |
| `commands/slice.rs:56` | `scan_state.mem_last_def.get(&addr)` | `session.mem_last_def_view()?.get(&addr)` |
| `commands/slice.rs:141-158` | `slicer::bfs_slice(scan_state, &start_indices)` | `slicer::bfs_slice(&session.scan_view()?, &start_indices)` |
| `taint/slicer.rs:123` | `write_sliced_bytes(data, marked, &state.init_mem_loads, writer)` | `write_sliced_bytes(data, marked, &session.init_mem_loads_view()?, writer)` |

### 其他

| 文件 | 变更 |
|------|------|
| `commands/cache.rs` | 无变更（调用 cache:: 模块函数） |
| `commands/file.rs` | SessionState 初始化字段名更新 |
| `cache.rs` | 新增 rkyv load/save 函数，更新 delete/clear |

## 新增依赖

```toml
[dependencies]
rkyv = { version = "0.8", features = ["validation"] }
# bincode 保留（StringIndex 仍用）
# libc 可选（madvise 预热）
```

## 可选优化：madvise 预热

打开文件后在后台线程调用 `madvise(MADV_WILLNEED)` 预热 mmap 数据：

```rust
#[cfg(unix)]
fn prefetch_mmap(mmap: &Mmap) {
    unsafe { libc::madvise(mmap.as_ptr() as _, mmap.len(), libc::MADV_WILLNEED); }
}
```

这不是必须的，但可以减少首次查询的 page fault 延迟。

## 性能预期

| 场景 | 当前 | 改后 |
|------|------|------|
| 首次打开（无缓存） | ~24s | ~24s + 后台转换 Flat 格式（< 2s） |
| 二次打开（缓存命中） | ~14s | **< 0.5s** |
| scan_strings 保存 | 序列化整个 1.5GB Phase2 | 序列化几百 KB StringIndex |
| 内存占用 | 堆上 4.2GB+ HashMap 开销 | 文件系统 page cache（OS 可回收） |
