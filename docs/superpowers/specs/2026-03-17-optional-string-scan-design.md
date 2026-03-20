# Optional String Scan Design

## Overview

将字符串扫描从 build_index 的必选步骤改为可选，用户可通过 Preferences 控制启动时是否扫描字符串，并可通过 Analysis 菜单手动触发扫描。解决大 trace 文件因字符串扫描导致启动过慢的问题。

## 动机

- 部分 trace 文件规模巨大（千万行以上），StringBuilder 在 scan_unified 中逐条处理 WRITE 操作会显著增加索引构建时间
- 并非所有分析场景都需要字符串数据，用户应能按需开启
- 已扫描过的结果应通过缓存复用，不重复扫描

## 设计

### 1. Preferences — Analysis 选项卡

**数据层（usePreferences.ts）：**

`Preferences` 接口新增字段：

```typescript
scanStringsOnBuild: boolean  // 默认 true
```

DEFAULTS 中 `scanStringsOnBuild: true`，保持现有行为不变。

**UI 层（PreferencesDialog.tsx）：**

TABS 新增 `"Analysis"`，位于 General 和 Cache 之间。

Analysis Tab 内容：
- 分组标题 "Strings"
- Checkbox：**"Scan strings during index build"**
- 描述文字：`When disabled, strings are not extracted during startup indexing. You can manually scan from Analysis → Scan Strings.`

### 2. Analysis 菜单 — Scan Strings

**TitleBar.tsx：**

Analysis 下拉菜单中，Taint Analysis 之后新增：
- 菜单项标签：当前 session 已有 string_index 时显示 **"Rescan Strings"**，否则显示 **"Scan Strings"**
- disabled 条件：`!isLoaded || !phase2Ready || stringsScanning`

**确认弹窗：**
- 复用现有 ConfirmDialog 样式
- 标题："Scan Strings"
- 内容："Scan memory writes to extract strings? This may take a moment for large traces."
- 按钮：Cancel / Scan

**Esc 中断：**
- 扫描进行时，在 App 层现有 keydown 处理逻辑中增加判断：`stringsScanning && key === 'Escape'` 且当前无弹窗打开时触发取消
- 弹窗的 Esc 优先于扫描取消

### 3. 后端 — scan_unified 改造

**scan_unified（taint/mod.rs）：**

新增参数 `skip_strings: bool`：
- `true`：不创建 StringBuilder，Phase2State.string_index 为 `Default::default()`（空）
- `false`：保持现有行为

```rust
pub fn scan_unified(
    data: &[u8],
    data_only: bool,
    no_prune: bool,
    skip_strings: bool,  // 新增
    progress_fn: Option<ProgressFn>,
) -> anyhow::Result<(ScanState, Phase2State, crate::line_index::LineIndex)>
```

**受影响的调用点：**
- `commands/index.rs` — `build_index_inner` 中调用 `taint::scan_unified(data, false, false, Some(progress_fn))` 需加入 `skip_strings` 参数

**build_index 命令（commands/index.rs）：**

新增参数 `skip_strings: Option<bool>`，传递给 scan_unified：

```rust
pub async fn build_index(
    session_id: String,
    app: AppHandle,
    state: State<'_, AppState>,
    force: Option<bool>,
    skip_strings: Option<bool>,  // 新增
) -> Result<(), String>
```

缓存加载路径不受影响 — 如果缓存中已有非空 string_index，照常加载。

**MemAccessIndex 新增遍历 API（taint/mem_access.rs）：**

当前 `MemAccessIndex.index` 是私有字段，缺少遍历方法。需新增：

```rust
pub fn iter_all(&self) -> impl Iterator<Item = (u64, &MemAccessRecord)> + '_ {
    self.index.iter().flat_map(|(&addr, records)| {
        records.iter().map(move |r| (addr, r))
    })
}
```

### 4. 后端 — scan_strings 命令

**新增命令 `scan_strings`（commands/strings.rs）：**

```rust
#[tauri::command]
pub async fn scan_strings(
    session_id: String,
    state: State<'_, AppState>,
) -> Result<(), String>
```

实现步骤：
1. 从 SessionState 中取读锁，通过 `MemAccessIndex::iter_all()` 收集所有 `rw == Write && size <= 8` 的记录为紧凑元组 `Vec<(u64 /*addr*/, u64 /*data*/, u8 /*size*/, u32 /*seq*/)>`，释放读锁。仅拷贝必要字段，减少内存开销
2. 按 seq 全局排序（保证与原始 trace 顺序一致）
3. 重置 `scan_strings_cancelled` AtomicBool 为 false
4. 创建 StringBuilder，逐条调用 `process_write(addr, data, size, seq)`
5. 遍历过程中每 10000 条检查 AtomicBool 取消标志，触发时提前退出
6. **如果被取消**：丢弃结果，不写入 string_index，返回 `Err("cancelled")`
7. **如果完成**：调用 `StringBuilder::finish()` 获取 StringIndex
8. 重新取读锁获取 `&MemAccessIndex` 引用，调用 `StringBuilder::fill_xref_counts` 填充 xref，释放读锁
9. 取写锁，将结果写入 `Phase2State.string_index`
10. 从 SessionState 获取 `file_path` 和 `mmap` 引用，调用 `cache::save_cache` 重新保存 Phase2 缓存

**关于 value=None 的说明**：MemAccessRecord.data 来自 `mem_op.value.unwrap_or(0)`，而 StringBuilder 原本只处理 `value` 为 `Some` 的 WRITE。在当前 trace 格式中，`mem[WRITE]` 行必定包含写入值，`value=None` 不会出现在 WRITE 操作中。因此直接使用 MemAccessRecord.data 是安全的近似。

**新增命令 `cancel_scan_strings`：**

```rust
#[tauri::command]
pub async fn cancel_scan_strings(
    session_id: String,
    state: State<'_, AppState>,
) -> Result<(), String>
```

设置对应 session 的 `scan_strings_cancelled: Arc<AtomicBool>` 为 true。对 session 不存在或扫描已完成的情况静默返回 Ok。

**SessionState 变更（state.rs）：**

```rust
pub struct SessionState {
    // ...existing fields...
    pub scan_strings_cancelled: Arc<AtomicBool>,  // 新增
}
```

### 5. 后端 — index-progress 事件扩展

`build_index` 完成时发送的 done 事件新增 `hasStringIndex` 字段：

```json
{
  "sessionId": "...",
  "progress": 1.0,
  "done": true,
  "totalLines": 12345,
  "hasStringIndex": true
}
```

后端在写入结果后检查 `phase2.string_index.strings.is_empty()` 取反得到该值。

### 6. 前端 — 状态管理

**App.tsx 新增状态：**

```typescript
const [stringsScanningSessionId, setStringsScanningSessionId] = useState<string | null>(null);
const [hasStringIndexMap, setHasStringIndexMap] = useState<Map<string, boolean>>(new Map());
```

- `stringsScanningSessionId`：当前正在扫描字符串的 session ID，null 表示未在扫描
- `hasStringIndexMap`：per-session 的 string_index 状态缓存，切换 session 时直接从 Map 读取，无需查询后端

派生值：`hasStringIndex = hasStringIndexMap.get(activeSessionId) ?? false`

**状态更新时机：**
- `index-progress` done 事件 → 更新 `hasStringIndexMap` 对应 sessionId
- `scan_strings` 完成 → 更新 `hasStringIndexMap` 对应 sessionId 为 true
- `scan_strings` 取消 → 不更新 hasStringIndexMap（保持原状态）
- 切换 activeSession → 从 hasStringIndexMap 读取，无需额外查询

**scanStrings 函数：**

```typescript
const scanStrings = async () => {
  setStringsScanningSessionId(activeSessionId);
  try {
    await invoke("scan_strings", { sessionId: activeSessionId });
    setHasStringIndexMap(prev => new Map(prev).set(activeSessionId, true));
  } catch (e) {
    // 取消或错误时不更新 hasStringIndexMap
    console.warn("scan_strings:", e);
  } finally {
    setStringsScanningSessionId(null);
  }
};
```

**cancelScanStrings 函数：**

```typescript
const cancelScanStrings = async () => {
  await invoke("cancel_scan_strings", { sessionId: stringsScanningSessionId });
};
```

**TitleBar props 新增：**
- `onScanStrings: () => void`
- `hasStringIndex: boolean`
- `stringsScanning: boolean`（派生自 `stringsScanningSessionId === activeSessionId`）

**StringsPanel：**
- 接收 `stringsScanning` prop
- 为 true 时底部显示 "Scanning strings..."
- 从 true 变为 false 时触发重新加载数据

### 7. 缓存策略

| 场景 | 行为 |
|------|------|
| 首次构建，scanStringsOnBuild=true | scan_unified 含 StringBuilder，缓存包含 string_index |
| 首次构建，scanStringsOnBuild=false | scan_unified 跳过 StringBuilder，缓存 string_index 为空 |
| 缓存命中，string_index 非空 | 直接加载，不受 scanStringsOnBuild 限制 |
| 缓存命中，string_index 为空 | 按现状加载，用户可手动 Scan Strings |
| 手动 Scan Strings 完成 | 更新 Phase2State.string_index，重新保存 Phase2 缓存 |
| Rebuild Index（force=true） | 按当前 scanStringsOnBuild 设置决定是否含 strings |

### 8. 不做的事情

- 不改动 MemAccessRecord 结构（不加 has_value 标志位）
- 不加扫描进度条（只用 loading 文字）
- 不改缓存格式 / MAGIC
- 不改动 StringsPanel 的数据加载逻辑（只加 scanning 状态显示）
