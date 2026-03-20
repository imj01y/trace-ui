# Strings View 设计文档

## 概述

为 Trace UI 新增类似 IDA Strings 的字符串查看功能。从 trace 执行过程中的内存操作中提取所有字符串，支持快照式多版本记录、搜索过滤、跳转联动和污点分析入口。

## 需求摘要

| 项目 | 决策 |
|------|------|
| 数据来源 | 仅从 trace 内存操作提取（不加载二进制文件） |
| 编码支持 | ASCII + UTF-8 |
| 最小长度 | 用户可配置，默认 4，最低 2 |
| 时序处理 | 快照式——保留同一地址所有历史版本 |
| UI 形态 | 底部 TabPanel 新 Tab + 支持拖拽浮出为独立浮窗 |
| 功能联动 | 跳转 + 高亮关联行 + 右键查看 XRefs / Memory / 发起污点 |

## 后端设计

### 数据结构

```rust
#[derive(Serialize, Deserialize, Clone)]
pub struct StringRecord {
    // id 使用 Vec<StringRecord> 的数组下标，不单独存储
    pub addr: u64,              // 起始内存地址
    pub content: String,        // 字符串内容
    pub encoding: StringEncoding,  // Ascii | Utf8
    pub byte_len: u32,          // 字节长度
    pub seq: u32,               // 触发检测到该字符串的 WRITE 操作的 seq
    pub xref_count: u32,        // READ 引用次数（概览用）
}

#[derive(Serialize, Deserialize, Clone, Copy)]
pub enum StringEncoding {
    Ascii,
    Utf8,
}

#[derive(Serialize, Deserialize)]
pub struct StringIndex {
    pub strings: Vec<StringRecord>, // 所有版本，按 seq 排序
}
```

### 构建时临时结构

```rust
struct StringBuilder {
    byte_image: PagedMemory,               // 页式字节级内存镜像（~12MB for 12M bytes）
    byte_owner: FxHashMap<u64, u32>,       // byte_addr → 活跃字符串 id（仅覆盖活跃字符串字节）
    active: FxHashMap<u32, ActiveString>,   // 活跃字符串集合
    results: Vec<StringRecord>,
    next_id: u32,
}

/// 页式内存镜像——按 4KB 页存储，避免 per-byte HashMap 开销
struct PagedMemory {
    pages: FxHashMap<u64, Box<Page>>,      // page_addr (4K 对齐) → 页
}

struct Page {
    data: [u8; 4096],
    valid: [bool; 4096],                   // 该字节是否被写入过
}

struct ActiveString {
    addr: u64,
    content: String,
    byte_len: u32,
    completed_seq: u32,
}
```

### 提取算法（Phase2 集成）

在 phase2 主扫描循环中，每条 WRITE 指令执行后：

**跳过条件**：`elem_width > 8`（SIMD 128-bit）或 `value` 为 `None`（STP/LDP pair 操作、解析失败）。这些记录的 data 字段不可靠，不应更新 byte_image。注意：在 Phase2 中 `data = mem_op.value.unwrap_or(0)`，因此需要在调用 StringBuilder 前检查原始 `mem_op.value` 是否为 `Some`。

**处理步骤**：

1. **更新 byte_image**：将 `data: u64` 按小端序展开为字节，写入 `byte_image[addr..addr+size]`
2. **局部扫描**：从写入地址向两端扫描 byte_image 中连续的可打印字符区域。**扫描上限 1024 字节**——避免密集可打印区域（如大缓冲区）导致性能退化
3. **对比活跃字符串**（通过 byte_owner 查找受影响的字符串，同时扫描 byte_image 中的相邻字节发现新字符串）：
   - 活跃字符串消失（被不可打印字节切断）→ 将旧版本存入 `results`，从 `active` 和 `byte_owner` 移除
   - 活跃字符串内容变化 → 存旧版本到 `results`，更新 `active` 中的记录
   - 新字符串形成（连续可打印 ≥ 2 字节）→ 加入 `active`，更新 `byte_owner`
4. **Phase2 结束时**：将所有仍活跃的字符串存入 `results`
5. **统计 xref_count**：对每个 StringRecord，逐地址查询 MemAccessIndex（`mem_idx.get(addr)` 遍历 `[addr, addr+byte_len)` 范围），统计 READ 记录数

**`seq` 字段语义**：记录触发检测到该字符串的 WRITE 操作的 seq。对于逐字节写入的字符串，这是写入最后一个使其达到 min_len 的字节的 seq。这比"所有构成字节中最大的 write seq"更简单，且不需要额外的 byte_seq map。

### UTF-8 检测策略

1. 扫描时用宽松定义：`0x20-0x7E、0x80-0xF4`（不含 `\t`/`\n`/`\r`，避免跨行拼接假字符串）
2. 提取连续区域后，用 `str::from_utf8()` 严格验证
3. 验证通过且含多字节序列 → 标记 `Utf8`；纯 ASCII → 标记 `Ascii`
4. UTF-8 验证失败 → 降级为纯 ASCII 模式（只保留 0x20-0x7E 部分）

### Tauri 命令

```rust
#[tauri::command]
pub fn get_strings(
    session_id: String,
    min_len: u32,           // 最小字符串长度过滤
    offset: u32,            // 分页偏移
    limit: u32,             // 分页大小
    search: Option<String>, // 可选搜索关键词
    state: State<'_, AppState>,
) -> Result<StringsResult, String>;

#[derive(Serialize)]
pub struct StringsResult {
    pub strings: Vec<StringRecord>,
    pub total: u32,  // 过滤后的总数（用于分页）
}

#[tauri::command]
pub fn get_string_xrefs(
    session_id: String,
    addr: u64,
    byte_len: u32,
    state: State<'_, AppState>,
) -> Result<Vec<StringXRef>, String>;

#[derive(Serialize)]
pub struct StringXRef {
    pub seq: u32,
    pub rw: String,       // "R" 或 "W"
    pub insn_addr: String,
    pub disasm: String,
}
```

### 缓存

- `StringIndex` 作为 `Phase2State` 的新字段，随 bincode 缓存一起序列化
- 缓存中存 min_len=2 的全量结果，查询时按用户阈值过滤返回
- 二次打开同一文件时从缓存加载，无需重新提取
- **缓存兼容性**：`Phase2State` 结构变化会导致旧缓存反序列化失败。需将 `cache.rs` 中的 `MAGIC` 从 `TCACHE01` 升级为 `TCACHE02`。旧缓存 `validate_header` 失败时返回 `None`，触发自动重建

### 内存开销评估

`byte_image` 和 `byte_owner` 的 FxHashMap 每个 entry 约 25-32 字节。对于 10M 行 trace（假设 ~3M 条 WRITE，每次平均 4 字节 = ~12M 字节地址）：

- `byte_image`: ~12M × 25 bytes ≈ 300MB
- `byte_owner`: 仅覆盖活跃字符串的字节，通常远小于 byte_image（几十 KB ~ 几 MB）

**优化方案**：byte_image 改用页式结构 `FxHashMap<u64, Box<[u8; 4096]>>`（按 4KB 页存储），将 per-byte 开销降至 ~1 byte/entry + per-page 开销。对于 12M 字节地址，约 3000 个页 × 4KB ≈ 12MB + 少量 HashMap 开销。这是显著的改进。

```rust
struct PagedMemory {
    pages: FxHashMap<u64, Box<Page>>,  // page_addr (4K 对齐) → 4KB 页
}

struct Page {
    data: [u8; 4096],
    valid: [bool; 4096],  // 该字节是否被写入过
}
```

## 前端设计

### 组件：StringsPanel

位置：`src-web/src/components/StringsPanel.tsx`

作为底部 TabPanel 的新 Tab（与 Memory / Accesses / Taint State / Search 并列）。

#### 布局

```
┌─────────────────────────────────────────────────────────────┐
│ [Search input............]  Min len: [===|====] 4  1,247 strings │
├───────┬───────────┬──────────────────────┬─────┬─────┬──────┤
│  Seq  │  Address  │      Content         │ Enc │ Len │XRefs │
├───────┼───────────┼──────────────────────┼─────┼─────┼──────┤
│  1042 │ 0xbffff100│ "AES-256-CBC"        │ASCII│  11 │   3  │
│  2871 │ 0x40012a00│ "password123"        │ASCII│  11 │   7  │
│ ▶5523 │ 0x40012a00│ "e3b0c44298fc..."    │ASCII│  64 │  12  │ ← 同地址多版本折叠
│  8910 │ 0xbffff200│ "签名验证失败"         │UTF8 │  21 │   1  │
│  ...  │    ...    │        ...           │ ... │ ... │  ... │
└───────┴───────────┴──────────────────────┴─────┴─────┴──────┘
                        (virtual scroll)
```

#### 技术实现

- **虚拟滚动**：`useVirtualizerNoSync`，行高 22px，overscan 20
- **分页加载**：初始加载 500 条，滚动到底部时加载更多（infinite scroll）
- **搜索**：debounce 300ms，调用 `get_strings` 传 search 参数，后端子串匹配
- **min_len 滑块**：range input，范围 2-20，默认 4，变更时 debounce 200ms 重新查询
- **多版本折叠**：后端 `get_strings` 返回扁平列表（按 seq 排序），前端按 addr 分组做纯 UI 层折叠，显示最新版本，左侧 ▶ 指示器可展开查看历史。注意：分页加载时同一 addr 的记录可能跨页，前端在加载新页时需合并已有分组

### 交互联动

| 操作 | 行为 |
|------|------|
| 单击行 | `navigationStore.navigate(seq)` 跳转到 TraceTable 对应行 |
| 选中字符串 | 该地址范围的所有内存操作行在 TraceTable 高亮（蓝色背景） |
| 右键 → Copy String | 复制字符串内容到剪贴板 |
| 右键 → Copy Address | 复制起始地址 |
| 右键 → View in Memory | 切换到 Memory Tab，定位到该地址 |
| 右键 → Show XRefs | 调用 `get_string_xrefs`，弹出引用列表，点击可跳转 |
| 右键 → Taint from here | 对该地址发起手动污点分析（调用现有 `run_slice(mem:addr@seq)`） |

### 浮窗支持

- 复用现有的 `useDragToFloat` 机制，Tab 可拖拽浮出
- 浮窗通过 Tauri 事件系统同步 `sessionId`、`selectedSeq`、`phase2Ready`
- 浮窗中的 StringsPanel 与主窗口行为一致
- 在 `FloatingPanel.tsx` 中添加 `case "strings"` 渲染分支

### 状态管理

- 使用组件内部 state 管理字符串列表、搜索词、min_len、加载状态
- 通过 `selectedSeqStore` 订阅全局选中行变化
- 通过 `invoke()` 调用后端 Tauri 命令获取数据

## 性能策略

| 策略 | 说明 |
|------|------|
| Phase2 集成构建 | 单次扫描，零额外 I/O |
| bincode 缓存 | 二次打开秒加载 |
| 后端分页 + 过滤 | 避免一次性传输全量数据到前端 |
| 虚拟滚动 | 仅渲染可见行 |
| XRefs 按需加载 | 不预加载引用列表 |
| debounce | 搜索 300ms，min_len 200ms |

## V1 范围

**包含**：
- Phase2 集成字符串提取（ASCII + UTF-8）
- 快照式多版本记录
- StringsPanel（底部 Tab + 浮窗）
- 搜索、过滤、min_len 可配置
- 点击跳转、高亮关联行
- 右键菜单（Copy / View in Memory / Show XRefs / Taint）
- bincode 缓存

**不包含（V2）**：
- 一键字符串联合污点分析（多字节合并切片）
- 从二进制文件静态提取字符串
- UTF-16/UCS-2 宽字符串
- 检测"曾经存在但最终被覆写为非字符串"的历史字符串（仅通过活跃字符串的变化/消亡捕获）

## 文件变更清单

### Rust 后端
| 文件 | 变更 |
|------|------|
| `src/taint/strings.rs` | **新增** — StringRecord、StringIndex、StringBuilder、提取算法 |
| `src/taint/mem_access.rs` | 无需新增迭代器，xref 查询使用现有的 `get(addr)` 逐地址查询 |
| `src/cache.rs` | MAGIC 版本号从 `TCACHE01` 升级为 `TCACHE02` |
| `src/taint/mod.rs` | 添加 `pub mod strings;` |
| `src/phase2.rs` | 集成 StringBuilder 到主扫描循环，StringIndex 加入 Phase2State |
| `src/commands/strings.rs` | **新增** — `get_strings`、`get_string_xrefs` 命令 |
| `src/commands/mod.rs` | 添加 `pub mod strings;` |
| `src/main.rs` | 注册新命令 |

### 前端
| 文件 | 变更 |
|------|------|
| `src-web/src/components/StringsPanel.tsx` | **新增** — 字符串面板组件 |
| `src-web/src/components/TabPanel.tsx` | 添加 "Strings" Tab |
| `src-web/src/FloatingPanel.tsx` | 添加 `case "strings"` 渲染分支 |
| `src-web/src/App.tsx` | 注册 Strings 浮窗创建逻辑 |
| `src-web/src/types/trace.ts` | 添加 StringRecord、StringsResult 等类型定义 |
