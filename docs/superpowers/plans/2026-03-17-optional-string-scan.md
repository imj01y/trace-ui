# Optional String Scan Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 将字符串扫描从 build_index 的必选步骤改为可选，支持通过 Preferences 控制和 Analysis 菜单手动触发。

**Architecture:** 后端 `scan_unified` 新增 `skip_strings` 参数跳过 StringBuilder；新增 `scan_strings` 命令从 MemAccessIndex 回放 Write 记录重建 StringIndex；前端 Preferences 新增 Analysis Tab，TitleBar 新增 Scan Strings 菜单项。

**Tech Stack:** Rust/Tauri 2 (backend), React 19/TypeScript (frontend)

**Spec:** `docs/superpowers/specs/2026-03-17-optional-string-scan-design.md`

---

## Chunk 1: Backend — MemAccessIndex API + scan_unified skip_strings

### Task 1: MemAccessIndex 新增 iter_all 遍历方法

**Files:**
- Modify: `src/taint/mem_access.rs:24-47`

- [ ] **Step 1: 添加 iter_all 方法**

在 `impl MemAccessIndex` 块中（`src/taint/mem_access.rs`），`total_addresses()` 方法之后添加：

```rust
pub fn iter_all(&self) -> impl Iterator<Item = (u64, &MemAccessRecord)> + '_ {
    self.index.iter().flat_map(|(&addr, records)| {
        records.iter().map(move |r| (addr, r))
    })
}
```

- [ ] **Step 2: 验证编译通过**

Run: `cd /Users/richman/Documents/reverse/codes/trace-ui && cargo check 2>&1 | tail -5`
Expected: 编译通过，无 error

- [ ] **Step 3: Commit**

```bash
git add src/taint/mem_access.rs
git commit -m "feat: add iter_all() to MemAccessIndex for full traversal"
```

### Task 2: scan_unified 新增 skip_strings 参数

**Files:**
- Modify: `src/taint/mod.rs:38-43` (函数签名)
- Modify: `src/taint/mod.rs:65` (StringBuilder 创建)
- Modify: `src/taint/mod.rs:403-408` (StringBuilder 调用)
- Modify: `src/taint/mod.rs:435-436` (StringBuilder finish)
- Modify: `src/commands/index.rs:8-13` (build_index 签名)
- Modify: `src/commands/index.rs:105` (scan_unified 调用)

- [ ] **Step 1: 修改 scan_unified 签名**

在 `src/taint/mod.rs`，`scan_unified` 函数签名中新增 `skip_strings: bool` 参数：

```rust
pub fn scan_unified(
    data: &[u8],
    data_only: bool,
    no_prune: bool,
    skip_strings: bool,
    progress_fn: Option<ProgressFn>,
) -> anyhow::Result<(ScanState, Phase2State, crate::line_index::LineIndex)> {
```

- [ ] **Step 2: 条件化 StringBuilder 创建**

在 `src/taint/mod.rs`，将第 65 行的 `let mut string_builder = StringBuilder::new();` 改为：

```rust
let mut string_builder = if skip_strings { None } else { Some(StringBuilder::new()) };
```

- [ ] **Step 3: 条件化 StringBuilder 调用**

在 `src/taint/mod.rs`，将第 403-408 行的 StringBuilder 调用改为：

```rust
// ── Phase2: 字符串提取 ──
if let Some(ref mut sb) = string_builder {
    if mem_op.is_write && mem_op.elem_width <= 8 {
        if let Some(value) = mem_op.value {
            sb.process_write(mem_op.abs, value, mem_op.elem_width, i);
        }
    }
}
```

- [ ] **Step 4: 条件化 StringBuilder finish**

在 `src/taint/mod.rs`，将第 435-436 行改为：

```rust
let string_index = match string_builder {
    Some(sb) => {
        let mut si = sb.finish();
        StringBuilder::fill_xref_counts(&mut si, &mem_idx);
        si
    }
    None => Default::default(),
};
```

- [ ] **Step 5: 修改 build_index 命令签名**

在 `src/commands/index.rs`，`build_index` 函数新增 `skip_strings: Option<bool>` 参数，并传递给 `build_index_inner`：

```rust
#[tauri::command]
pub async fn build_index(
    session_id: String,
    app: AppHandle,
    state: State<'_, AppState>,
    force: Option<bool>,
    skip_strings: Option<bool>,
) -> Result<(), String> {
    let result = build_index_inner(&session_id, &app, &state, force.unwrap_or(false), skip_strings.unwrap_or(false)).await;
```

同步修改 `build_index_inner` 签名：

```rust
async fn build_index_inner(
    session_id: &str,
    app: &AppHandle,
    state: &State<'_, AppState>,
    force: bool,
    skip_strings: bool,
) -> Result<(), String> {
```

- [ ] **Step 6: 传递 skip_strings 给 scan_unified**

在 `src/commands/index.rs`，第 105 行的 `scan_unified` 调用中加入 `skip_strings`：

```rust
let (mut scan_state, phase2, line_index) = taint::scan_unified(data, false, false, skip_strings, Some(progress_fn))
    .map_err(|e| format!("统一扫描失败: {}", e))?;
```

- [ ] **Step 7: 验证编译通过**

Run: `cd /Users/richman/Documents/reverse/codes/trace-ui && cargo check 2>&1 | tail -5`
Expected: 编译通过，无 error

- [ ] **Step 8: Commit**

```bash
git add src/taint/mod.rs src/commands/index.rs
git commit -m "feat: add skip_strings param to scan_unified and build_index"
```

### Task 3: index-progress 事件新增 hasStringIndex

**Files:**
- Modify: `src/commands/index.rs:18-28` (done 事件 JSON)

- [ ] **Step 1: 在 done 事件中添加 hasStringIndex 字段**

在 `src/commands/index.rs` 的 `build_index` 函数中，done 事件发送前，从 session 读取 hasStringIndex：

```rust
let (error, total_lines, has_string_index) = {
    let sessions = state.sessions.read().map_err(|e| e.to_string())?;
    let s = sessions.get(&*session_id);
    (
        result.as_ref().err().cloned(),
        s.map(|s| s.total_lines).unwrap_or(0),
        s.and_then(|s| s.phase2.as_ref())
            .map(|p| !p.string_index.strings.is_empty())
            .unwrap_or(false),
    )
};
let _ = app.emit("index-progress", serde_json::json!({
    "sessionId": session_id,
    "progress": 1.0,
    "done": true,
    "error": error,
    "totalLines": total_lines,
    "hasStringIndex": has_string_index,
}));
```

- [ ] **Step 2: 验证编译通过**

Run: `cd /Users/richman/Documents/reverse/codes/trace-ui && cargo check 2>&1 | tail -5`
Expected: 编译通过

- [ ] **Step 3: Commit**

```bash
git add src/commands/index.rs
git commit -m "feat: include hasStringIndex in index-progress done event"
```

## Chunk 2: Backend — scan_strings + cancel_scan_strings 命令

### Task 4: SessionState 新增 scan_strings_cancelled 字段

**Files:**
- Modify: `src/state.rs:1-44`
- Modify: `src/commands/file.rs:38-46` (SessionState 构造)

- [ ] **Step 1: 在 state.rs 新增字段**

在 `src/state.rs` 的 `use` 区域添加：

```rust
use std::sync::atomic::AtomicBool;
```

在 `SessionState` struct 中新增字段：

```rust
pub scan_strings_cancelled: Arc<AtomicBool>,
```

- [ ] **Step 2: 更新 create_session 中的 SessionState 构造**

在 `src/commands/file.rs` 的 `create_session` 函数中，SessionState 初始化处新增：

```rust
scan_strings_cancelled: Arc::new(AtomicBool::new(false)),
```

- [ ] **Step 3: 验证编译通过**

Run: `cd /Users/richman/Documents/reverse/codes/trace-ui && cargo check 2>&1 | tail -5`
Expected: 编译通过

- [ ] **Step 4: Commit**

```bash
git add src/state.rs src/commands/file.rs
git commit -m "feat: add scan_strings_cancelled AtomicBool to SessionState"
```

### Task 5: 实现 scan_strings 和 cancel_scan_strings 命令

**Files:**
- Modify: `src/commands/strings.rs` (新增两个命令)
- Modify: `src/main.rs:39-64` (注册命令)

- [ ] **Step 1: 在 commands/strings.rs 中新增 scan_strings 命令**

在 `src/commands/strings.rs` 文件末尾，`get_string_xrefs` 函数之后添加：

```rust
use crate::taint::strings::StringBuilder;
use crate::taint::mem_access::MemRw;
use std::sync::atomic::Ordering;

#[tauri::command]
pub async fn scan_strings(
    session_id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    // 1. 收集 Write 记录并获取取消标志
    let (writes, cancelled) = {
        let sessions = state.sessions.read().map_err(|e| e.to_string())?;
        let session = sessions.get(&session_id)
            .ok_or_else(|| format!("Session {} 不存在", session_id))?;
        let phase2 = session.phase2.as_ref().ok_or("索引尚未构建完成")?;

        let mut writes: Vec<(u64, u64, u8, u32)> = Vec::new();
        for (addr, rec) in phase2.mem_accesses.iter_all() {
            if rec.rw == MemRw::Write && rec.size <= 8 {
                writes.push((addr, rec.data, rec.size, rec.seq));
            }
        }
        (writes, session.scan_strings_cancelled.clone())
    };

    // 2. 按 seq 排序
    let mut writes = writes;
    writes.sort_unstable_by_key(|w| w.3);

    // 3. 重置取消标志
    cancelled.store(false, Ordering::SeqCst);

    // 4. 在阻塞线程中执行 StringBuilder
    let result = tauri::async_runtime::spawn_blocking(move || {
        let mut sb = StringBuilder::new();
        for (i, &(addr, data, size, seq)) in writes.iter().enumerate() {
            if i % 10000 == 0 && cancelled.load(Ordering::SeqCst) {
                return Err("cancelled".to_string());
            }
            sb.process_write(addr, data, size, seq);
        }
        Ok(sb)
    })
    .await
    .map_err(|e| format!("扫描线程 panic: {}", e))??;

    // 5. finish + fill_xref_counts
    let mut string_index = result.finish();
    {
        let sessions = state.sessions.read().map_err(|e| e.to_string())?;
        let session = sessions.get(&session_id)
            .ok_or_else(|| format!("Session {} 不存在", session_id))?;
        let phase2 = session.phase2.as_ref().ok_or("索引尚未构建完成")?;
        StringBuilder::fill_xref_counts(&mut string_index, &phase2.mem_accesses);
    }

    // 6. 写入结果并更新缓存
    {
        let mut sessions = state.sessions.write().map_err(|e| e.to_string())?;
        let session = sessions.get_mut(&session_id)
            .ok_or_else(|| format!("Session {} 不存在", session_id))?;
        if let Some(ref mut phase2) = session.phase2 {
            phase2.string_index = string_index;
            // 更新缓存
            crate::cache::save_cache(&session.file_path, &*session.mmap, phase2);
        }
    }

    Ok(())
}

#[tauri::command]
pub async fn cancel_scan_strings(
    session_id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let sessions = state.sessions.read().map_err(|e| e.to_string())?;
    if let Some(session) = sessions.get(&session_id) {
        session.scan_strings_cancelled.store(true, std::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}
```

- [ ] **Step 2: 在 main.rs 注册新命令**

在 `src/main.rs` 的 `invoke_handler` 中，`commands::strings::get_string_xrefs` 之后添加：

```rust
commands::strings::scan_strings,
commands::strings::cancel_scan_strings,
```

- [ ] **Step 3: 确保 StringBuilder 的可见性**

在 `src/taint/strings.rs` 中，`StringBuilder` 当前是 `pub(crate)` 可见。`scan_strings` 命令在 `commands::strings` 中使用它，这在同一 crate 内，所以 `pub(crate)` 已足够。无需修改。

- [ ] **Step 4: 确保 cache::save_cache 签名兼容**

检查 `src/cache.rs` 中 `save_cache` 的签名，确认接受 `&str`（file_path）、`&[u8]`（mmap data）和 `&Phase2State`。如果 `save_cache` 接受 `&Mmap` 也可以，因为 `Mmap` 实现了 `Deref<Target=[u8]>`。

Run: `cd /Users/richman/Documents/reverse/codes/trace-ui && grep -n "pub fn save_cache" src/cache.rs`

根据签名调整调用代码（可能需要 `&*session.mmap` 而不是 `&session.mmap`）。

- [ ] **Step 5: 验证编译通过**

Run: `cd /Users/richman/Documents/reverse/codes/trace-ui && cargo check 2>&1 | tail -10`
Expected: 编译通过

- [ ] **Step 6: Commit**

```bash
git add src/commands/strings.rs src/main.rs
git commit -m "feat: add scan_strings and cancel_scan_strings commands"
```

## Chunk 3: Frontend — Preferences + useTraceStore 改动

### Task 6: usePreferences 新增 scanStringsOnBuild

**Files:**
- Modify: `src-web/src/hooks/usePreferences.ts:6-11` (Preferences 接口)
- Modify: `src-web/src/hooks/usePreferences.ts:33-38` (DEFAULTS)

- [ ] **Step 1: 在 Preferences 接口新增字段**

在 `src-web/src/hooks/usePreferences.ts` 的 `Preferences` 接口中，`cacheDir` 之后添加：

```typescript
scanStringsOnBuild: boolean;
```

在 `DEFAULTS` 中添加：

```typescript
scanStringsOnBuild: true,
```

- [ ] **Step 2: 验证前端编译通过**

Run: `cd /Users/richman/Documents/reverse/codes/trace-ui/src-web && npx tsc --noEmit 2>&1 | tail -5`
Expected: 无 error

- [ ] **Step 3: Commit**

```bash
git add src-web/src/hooks/usePreferences.ts
git commit -m "feat: add scanStringsOnBuild to Preferences"
```

### Task 7: PreferencesDialog 新增 Analysis Tab

**Files:**
- Modify: `src-web/src/components/PreferencesDialog.tsx:17` (TABS)
- Modify: `src-web/src/components/PreferencesDialog.tsx:183-256` (Tab content 区域)

- [ ] **Step 1: 扩展 TABS 数组**

在 `src-web/src/components/PreferencesDialog.tsx`，将第 17 行：

```typescript
const TABS = ["General", "Cache"] as const;
```

改为：

```typescript
const TABS = ["General", "Analysis", "Cache"] as const;
```

- [ ] **Step 2: 添加 Analysis Tab 内容**

在 `PreferencesDialog.tsx` 的 Tab content 区域，`{/* ── General Tab ── */}` 区块结束后、`{/* ── Cache Tab ── */}` 之前，插入：

```tsx
{/* ── Analysis Tab ── */}
{tab === "Analysis" && (
  <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
    <div style={{ fontSize: 11, color: "var(--text-secondary)", fontWeight: 600 }}>
      Strings
    </div>
    <label style={{
      display: "flex", alignItems: "center", gap: 8,
      fontSize: 12, color: "var(--text-primary)", cursor: "pointer",
    }}>
      <input
        type="checkbox"
        checked={local.scanStringsOnBuild}
        onChange={(e) => setLocal(prev => ({ ...prev, scanStringsOnBuild: e.target.checked }))}
        style={{ accentColor: "var(--btn-primary)" }}
      />
      Scan strings during index build
    </label>
    <div style={{ fontSize: 10, color: "var(--text-secondary)", lineHeight: 1.4, marginTop: -6 }}>
      When disabled, strings are not extracted during startup indexing. You can manually scan from Analysis → Scan Strings.
    </div>
  </div>
)}
```

- [ ] **Step 3: 验证前端编译通过**

Run: `cd /Users/richman/Documents/reverse/codes/trace-ui/src-web && npx tsc --noEmit 2>&1 | tail -5`
Expected: 无 error

- [ ] **Step 4: Commit**

```bash
git add src-web/src/components/PreferencesDialog.tsx
git commit -m "feat: add Analysis tab to PreferencesDialog with string scan toggle"
```

### Task 8: useTraceStore 传递 skipStrings + hasStringIndex 状态

**Files:**
- Modify: `src-web/src/hooks/useTraceStore.ts:115-147` (index-progress 监听)
- Modify: `src-web/src/hooks/useTraceStore.ts:199` (build_index 调用)
- Modify: `src-web/src/hooks/useTraceStore.ts:287` (rebuildIndex 调用)

- [ ] **Step 1: 新增 hasStringIndexMap 状态**

在 `src-web/src/hooks/useTraceStore.ts` 中，在现有 state 声明区域新增：

```typescript
const [hasStringIndexMap, setHasStringIndexMap] = useState<Map<string, boolean>>(new Map());
```

- [ ] **Step 2: 在 index-progress 事件中提取 hasStringIndex**

在事件监听器的类型中增加 `hasStringIndex?: boolean`：

```typescript
const unlisten = listen<{ sessionId: string; progress: number; done: boolean; error?: string; totalLines?: number; hasStringIndex?: boolean }>(
```

在 `if (done && ...)` 判断块中添加 hasStringIndex 更新：

```typescript
if (done && event.payload.hasStringIndex != null) {
    setHasStringIndexMap(prev => new Map(prev).set(sessionId, event.payload.hasStringIndex!));
}
```

- [ ] **Step 3: 修改 useTraceStore hook 签名，接收 skipStrings 参数**

修改 `src-web/src/hooks/useTraceStore.ts` 第 24 行的 hook 签名：

```typescript
export function useTraceStore(skipStrings: boolean = false) {
```

修改 `openTrace` 中的 build_index 调用（第 199 行）：

```typescript
invoke("build_index", { sessionId: sid, skipStrings: skipStrings || undefined }).catch(async (e) => {
```

修改 `rebuildIndex` 中的 build_index 调用（第 287 行）：

```typescript
invoke("build_index", { sessionId: sid, force: true, skipStrings: skipStrings || undefined }).catch((e) => {
```

- [ ] **Step 3b: 更新 App.tsx 中 useTraceStore 调用**

在 `src-web/src/App.tsx` 第 84 行，修改 hook 调用（注意 `preferences` 来自同文件第 94 行的 `usePreferences()`，由于 hooks 不能条件调用，需要调整声明顺序或传递默认值）：

最简方案：在 `App.tsx` 中将 `usePreferences()` 的调用移到 `useTraceStore()` 之前，然后传参：

```typescript
const { preferences, updatePreferences } = usePreferences();
// ...
const {
    // ...existing destructured fields...
    hasStringIndexMap,
    setHasStringIndexMap,
} = useTraceStore(!preferences.scanStringsOnBuild);
```

- [ ] **Step 4: 导出 hasStringIndexMap 和更新方法**

在 `useTraceStore` 的返回值中新增：

```typescript
hasStringIndexMap,
setHasStringIndexMap,
```

- [ ] **Step 5: 验证前端编译通过**

Run: `cd /Users/richman/Documents/reverse/codes/trace-ui/src-web && npx tsc --noEmit 2>&1 | tail -10`
Expected: 编译通过（可能有 unused 警告，待后续 Task 消除）

- [ ] **Step 6: Commit**

```bash
git add src-web/src/hooks/useTraceStore.ts
git commit -m "feat: pass skipStrings to build_index, track hasStringIndexMap"
```

## Chunk 4: Frontend — TitleBar 菜单 + App 状态连接

### Task 9: TitleBar 新增 Scan Strings 菜单项

**Files:**
- Modify: `src-web/src/components/TitleBar.tsx:16-45` (Props 接口)
- Modify: `src-web/src/components/TitleBar.tsx:47` (函数参数解构)
- Modify: `src-web/src/components/TitleBar.tsx:270-275` (Analysis 菜单)

- [ ] **Step 1: 扩展 TitleBar Props**

在 `src-web/src/components/TitleBar.tsx` 的 `Props` 接口中，`onTaintAnalysis` 之后新增：

```typescript
onScanStrings: () => void;
hasStringIndex: boolean;
stringsScanning: boolean;
isPhase2Ready: boolean;
```

在函数参数解构中添加这些新 props。

- [ ] **Step 2: 新增 Scan Strings 确认弹窗状态和菜单项**

在 TitleBar 组件内部新增状态：

```typescript
const [showScanStringsConfirm, setShowScanStringsConfirm] = useState(false);
```

在 Analysis 下拉菜单中，`<MenuItem label="Taint Analysis..." .../>` 之后、`<MenuSeparator />` 之前添加：

```tsx
<MenuItem
    label={hasStringIndex ? "Rescan Strings" : "Scan Strings"}
    disabled={!isLoaded || !isPhase2Ready || stringsScanning}
    onClick={() => setShowScanStringsConfirm(true)}
/>
```

- [ ] **Step 3: 添加 Scan Strings 确认弹窗**

在 TitleBar 组件的 JSX 末尾（其他 ConfirmDialog 附近）添加：

```tsx
{showScanStringsConfirm && (
    <ConfirmDialog
        title="Scan Strings"
        message="Scan memory writes to extract strings? This may take a moment for large traces."
        confirmText="Scan"
        onConfirm={() => {
            setShowScanStringsConfirm(false);
            onScanStrings();
        }}
        onCancel={() => setShowScanStringsConfirm(false)}
    />
)}
```

- [ ] **Step 4: 验证前端编译通过**

Run: `cd /Users/richman/Documents/reverse/codes/trace-ui/src-web && npx tsc --noEmit 2>&1 | tail -10`
Expected: 可能有类型错误（App.tsx 尚未传递新 props），在 Task 10 中解决

- [ ] **Step 5: Commit**

```bash
git add src-web/src/components/TitleBar.tsx
git commit -m "feat: add Scan Strings menu item and confirm dialog to TitleBar"
```

### Task 10: App.tsx 连接所有状态

**Files:**
- Modify: `src-web/src/App.tsx` (新增状态、scanStrings/cancelScanStrings、Esc 处理、TitleBar props)

- [ ] **Step 1: 新增 stringsScanningSessionId 状态**

在 `App.tsx` 的状态声明区域新增：

```typescript
const [stringsScanningSessionId, setStringsScanningSessionId] = useState<string | null>(null);
```

- [ ] **Step 2: 实现 scanStrings 函数**

```typescript
const scanStrings = useCallback(async () => {
    if (!activeSessionId) return;
    setStringsScanningSessionId(activeSessionId);
    try {
        await invoke("scan_strings", { sessionId: activeSessionId });
        setHasStringIndexMap(prev => new Map(prev).set(activeSessionId, true));
    } catch (e) {
        console.warn("scan_strings:", e);
    } finally {
        setStringsScanningSessionId(null);
    }
}, [activeSessionId, setHasStringIndexMap]);
```

- [ ] **Step 3: 实现 cancelScanStrings 函数**

```typescript
const cancelScanStrings = useCallback(async () => {
    if (!stringsScanningSessionId) return;
    await invoke("cancel_scan_strings", { sessionId: stringsScanningSessionId });
}, [stringsScanningSessionId]);
```

- [ ] **Step 4: 添加 Esc 中断扫描的键盘处理**

在 App.tsx 现有的 keydown useEffect 中（或新增一个），添加 Esc 取消逻辑：

```typescript
useEffect(() => {
    if (!stringsScanningSessionId) return;
    const handler = (e: KeyboardEvent) => {
        if (e.key === "Escape") {
            // 弹窗的 Esc 优先于扫描取消：如果有任何 dialog overlay 打开，不取消扫描
            const hasOpenDialog = document.querySelector('[style*="position: fixed"][style*="z-index"]');
            if (hasOpenDialog) return;
            cancelScanStrings();
        }
    };
    document.addEventListener("keydown", handler);
    return () => document.removeEventListener("keydown", handler);
}, [stringsScanningSessionId, cancelScanStrings]);
```

- [ ] **Step 5: 传递新 props 给 TitleBar**

在 TitleBar 组件调用处（约第 778 行）添加新 props：

```tsx
onScanStrings={scanStrings}
hasStringIndex={hasStringIndexMap.get(activeSessionId ?? "") ?? false}
stringsScanning={stringsScanningSessionId === activeSessionId}
isPhase2Ready={!!activeSession?.isPhase2Ready}
```

- [ ] **Step 6: 验证前端编译通过**

Run: `cd /Users/richman/Documents/reverse/codes/trace-ui/src-web && npx tsc --noEmit 2>&1 | tail -10`
Expected: 编译通过

- [ ] **Step 7: Commit**

```bash
git add src-web/src/App.tsx
git commit -m "feat: wire up scanStrings, cancelScanStrings, and Esc handler in App"
```

## Chunk 5: Frontend — StringsPanel scanning 状态 + 端到端测试

### Task 11: StringsPanel 显示 scanning 状态

**Files:**
- Modify: `src-web/src/components/StringsPanel.tsx:13-17` (Props)
- Modify: `src-web/src/components/StringsPanel.tsx:19` (函数参数)
- Modify: `src-web/src/components/TabPanel.tsx:21-35` (Props 传递)

- [ ] **Step 1: StringsPanel 新增 stringsScanning prop**

在 `src-web/src/components/StringsPanel.tsx` 的 Props 接口中新增：

```typescript
stringsScanning?: boolean;
```

在函数参数解构中添加 `stringsScanning`。

- [ ] **Step 2: 添加 scanning 状态显示**

在 StringsPanel 的 JSX 中，列表区域底部（或空状态区域），当 `stringsScanning` 为 true 时显示：

```tsx
{stringsScanning && (
    <div style={{
        padding: "8px 12px",
        fontSize: 11,
        color: "var(--text-secondary)",
        textAlign: "center",
        borderTop: "1px solid var(--border-color)",
    }}>
        Scanning strings...
    </div>
)}
```

- [ ] **Step 3: 扫描完成后自动刷新**

添加 useEffect，当 `stringsScanning` 从 true 变为 false 时触发重新加载：

```typescript
const prevScanningRef = useRef(false);
useEffect(() => {
    if (prevScanningRef.current && !stringsScanning) {
        loadStrings(0, true);
    }
    prevScanningRef.current = !!stringsScanning;
}, [stringsScanning, loadStrings]);
```

- [ ] **Step 4: TabPanel 传递 stringsScanning**

在 `TabPanel.tsx` 的 Props 接口中新增 `stringsScanning?: boolean`，并在 StringsPanel 的渲染处传递。

在 `App.tsx` 中 TabPanel 调用处传递 `stringsScanning={stringsScanningSessionId === activeSessionId}`。

- [ ] **Step 5: 验证前端编译通过**

Run: `cd /Users/richman/Documents/reverse/codes/trace-ui/src-web && npx tsc --noEmit 2>&1 | tail -10`
Expected: 编译通过

- [ ] **Step 6: Commit**

```bash
git add src-web/src/components/StringsPanel.tsx src-web/src/components/TabPanel.tsx src-web/src/App.tsx
git commit -m "feat: show scanning status in StringsPanel, auto-refresh on completion"
```

### Task 12: 端到端手动验证

- [ ] **Step 1: 构建并启动应用**

Run: `cd /Users/richman/Documents/reverse/codes/trace-ui && bash build.sh dev`
Expected: 应用启动成功

- [ ] **Step 2: 验证 Preferences — Analysis Tab**

1. 打开 Settings → Preferences
2. 确认出现 Analysis Tab，位于 General 和 Cache 之间
3. 确认 "Scan strings during index build" checkbox 默认勾选
4. 取消勾选，点击 Save
5. 重新打开 Preferences，确认设置被保存

- [ ] **Step 3: 验证 skip_strings 生效**

1. 在 Preferences 中关闭 "Scan strings during index build"
2. 打开一个 trace 文件
3. 索引构建完成后，切换到 Strings Tab
4. 确认 Strings 列表为空（因为跳过了字符串扫描）

- [ ] **Step 4: 验证 Scan Strings 手动触发**

1. 打开 Analysis 菜单，确认出现 "Scan Strings" 选项
2. 点击 "Scan Strings"，确认弹出确认对话框
3. 点击 "Scan"，确认 StringsPanel 底部显示 "Scanning strings..."
4. 扫描完成后，确认 Strings 列表显示字符串数据
5. 再次打开 Analysis 菜单，确认菜单项变为 "Rescan Strings"

- [ ] **Step 5: 验证 Esc 取消**

1. 开启 Scan Strings
2. 扫描过程中按 Esc
3. 确认扫描被取消，Strings 列表保持为空

- [ ] **Step 6: 验证缓存复用**

1. 手动 Scan Strings 完成后，关闭文件
2. 重新打开同一文件
3. 确认 Strings Tab 直接有数据（从缓存加载），即使 "Scan strings during index build" 关闭

- [ ] **Step 7: Commit (如有修复)**

```bash
git add -A
git commit -m "fix: address issues found during manual testing"
```
