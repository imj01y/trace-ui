# Function List Panel Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a "Function List" tab in the left panel that shows all function calls (syscalls + JNI) from gumtrace trace logs, with search, filtering, collapse/expand, and click-to-jump.

**Architecture:** New Rust command `get_function_calls` aggregates `session.call_annotations` into grouped entries. New React component `FunctionListPanel` renders a virtualized, filterable list. A tab bar is added to the left panel's upper area to switch between FunctionTree and FunctionListPanel.

**Tech Stack:** Rust/Tauri (backend command), React/TypeScript (frontend component), existing `useVirtualizerNoSync` hook for virtual scrolling.

**Spec:** `docs/superpowers/specs/2026-03-17-function-list-panel-design.md`

---

### Task 1: Backend — New `get_function_calls` command

**Files:**
- Create: `src/commands/functions.rs`
- Modify: `src/commands/mod.rs`
- Modify: `src/main.rs:66` (add to generate_handler)

- [ ] **Step 1: Create `src/commands/functions.rs` with DTOs and command**

```rust
use serde::Serialize;
use std::collections::HashMap;
use tauri::State;
use crate::state::AppState;

#[derive(Serialize)]
pub struct FunctionCallOccurrence {
    pub seq: u32,
    pub summary: String,
}

#[derive(Serialize)]
pub struct FunctionCallEntry {
    pub func_name: String,
    pub is_jni: bool,
    pub occurrences: Vec<FunctionCallOccurrence>,
}

#[derive(Serialize)]
pub struct FunctionCallsResult {
    pub functions: Vec<FunctionCallEntry>,
    pub total_calls: usize,
}

#[tauri::command]
pub fn get_function_calls(
    session_id: String,
    state: State<'_, AppState>,
) -> Result<FunctionCallsResult, String> {
    let sessions = state.sessions.read().map_err(|e| e.to_string())?;
    let session = sessions.get(&session_id)
        .ok_or_else(|| format!("Session {} not found", session_id))?;

    // Group by func_name
    let mut groups: HashMap<String, (bool, Vec<FunctionCallOccurrence>)> = HashMap::new();
    for (&seq, ann) in &session.call_annotations {
        let entry = groups.entry(ann.func_name.clone()).or_insert_with(|| (ann.is_jni, Vec::new()));
        entry.1.push(FunctionCallOccurrence {
            seq,
            summary: ann.summary(),
        });
    }

    let mut total_calls = 0usize;
    let mut functions: Vec<FunctionCallEntry> = groups.into_iter()
        .map(|(func_name, (is_jni, mut occs))| {
            occs.sort_by_key(|o| o.seq);
            total_calls += occs.len();
            FunctionCallEntry { func_name, is_jni, occurrences: occs }
        })
        .collect();

    // Sort by first occurrence seq
    functions.sort_by_key(|f| f.occurrences.first().map(|o| o.seq).unwrap_or(u32::MAX));

    Ok(FunctionCallsResult { functions, total_calls })
}
```

- [ ] **Step 2: Register the module in `src/commands/mod.rs`**

Add this line after `pub mod file;`:
```rust
pub mod functions;
```

- [ ] **Step 3: Register the command in `src/main.rs`**

Add this line in the `generate_handler!` macro (after `commands::browse::get_consumed_seqs,`):
```rust
commands::functions::get_function_calls,
```

- [ ] **Step 4: Build and verify no compile errors**

Run: `cargo build 2>&1 | tail -5`
Expected: compiles successfully

- [ ] **Step 5: Commit**

```bash
git add src/commands/functions.rs src/commands/mod.rs src/main.rs
git commit -m "feat: add get_function_calls backend command"
```

---

### Task 2: Frontend — TypeScript types

**Files:**
- Modify: `src-web/src/types/trace.ts`

- [ ] **Step 1: Add new interfaces to `src-web/src/types/trace.ts`**

Append at end of file:
```typescript
export interface FunctionCallOccurrence {
  seq: number;
  summary: string;
}

export interface FunctionCallEntry {
  func_name: string;
  is_jni: boolean;
  occurrences: FunctionCallOccurrence[];
}

export interface FunctionCallsResult {
  functions: FunctionCallEntry[];
  total_calls: number;
}
```

Note: field names use snake_case matching Rust's default serde serialization (consistent with `CallTreeNodeDto` pattern).

- [ ] **Step 2: Commit**

```bash
git add src-web/src/types/trace.ts
git commit -m "feat: add FunctionCallsResult TypeScript types"
```

---

### Task 3: Frontend — FunctionListPanel component

**Files:**
- Create: `src-web/src/components/FunctionListPanel.tsx`

**References:**
- `src-web/src/components/FunctionTree.tsx` — sibling component, same panel, similar patterns (virtualizer, styling)
- `src-web/src/hooks/useVirtualizerNoSync.ts` — virtual scrolling hook
- `src-web/src/theme/global.css` — CSS variables

- [ ] **Step 1: Create `src-web/src/components/FunctionListPanel.tsx`**

```tsx
import { useState, useEffect, useMemo, useRef, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useVirtualizerNoSync } from "../hooks/useVirtualizerNoSync";
import type { FunctionCallEntry, FunctionCallsResult } from "../types/trace";

type FilterType = "all" | "syscall" | "jni";

type FlatRow = {
  type: "group";
  entry: FunctionCallEntry;
  isExpanded: boolean;
} | {
  type: "occurrence";
  seq: number;
  summary: string;
  func_name: string;
};

interface Props {
  sessionId: string | null;
  onJumpToSeq: (seq: number) => void;
}

export default function FunctionListPanel({ sessionId, onJumpToSeq }: Props) {
  const [data, setData] = useState<FunctionCallsResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<FilterType>("all");
  const [search, setSearch] = useState("");
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const parentRef = useRef<HTMLDivElement>(null);

  // Fetch data when sessionId changes
  useEffect(() => {
    if (!sessionId) { setData(null); return; }
    setLoading(true);
    setError(null);
    invoke<FunctionCallsResult>("get_function_calls", { sessionId })
      .then((result) => {
        setData(result);
        setExpanded(new Set());
      })
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false));
  }, [sessionId]);

  // Filter + search
  const filtered = useMemo(() => {
    if (!data) return [];
    let fns = data.functions;
    if (filter === "jni") fns = fns.filter(f => f.is_jni);
    else if (filter === "syscall") fns = fns.filter(f => !f.is_jni);
    if (search) {
      const q = search.toLowerCase();
      fns = fns.filter(f => f.func_name.toLowerCase().includes(q));
    }
    return fns;
  }, [data, filter, search]);

  // Flatten for virtual list
  const rows = useMemo(() => {
    const result: FlatRow[] = [];
    for (const entry of filtered) {
      const isExpanded = expanded.has(entry.func_name);
      result.push({ type: "group", entry, isExpanded });
      if (isExpanded) {
        for (const occ of entry.occurrences) {
          result.push({ type: "occurrence", seq: occ.seq, summary: occ.summary, func_name: entry.func_name });
        }
      }
    }
    return result;
  }, [filtered, expanded]);

  const virtualizer = useVirtualizerNoSync({
    count: rows.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 26,
    overscan: 10,
  });

  const toggleExpand = useCallback((funcName: string) => {
    setExpanded(prev => {
      const next = new Set(prev);
      if (next.has(funcName)) next.delete(funcName);
      else next.add(funcName);
      return next;
    });
  }, []);

  // Stats
  const filteredCalls = useMemo(() => filtered.reduce((sum, f) => sum + f.occurrences.length, 0), [filtered]);

  if (!sessionId) {
    return <div style={{ padding: 12, color: "var(--text-secondary)" }}>No file loaded</div>;
  }

  if (loading) {
    return <div style={{ padding: 12, color: "var(--text-secondary)" }}>Loading...</div>;
  }

  if (error) {
    return <div style={{ padding: 12, color: "var(--text-secondary)" }}>{error}</div>;
  }

  if (!data || data.functions.length === 0) {
    return <div style={{ padding: 12, color: "var(--text-secondary)" }}>No function calls found</div>;
  }

  return (
    <div style={{ height: "100%", display: "flex", flexDirection: "column", background: "var(--bg-primary)" }}>
      {/* Search box */}
      <div style={{ padding: "4px 6px", borderBottom: "1px solid var(--border-color)", flexShrink: 0 }}>
        <input
          type="text"
          placeholder="Search functions..."
          value={search}
          onChange={e => setSearch(e.target.value)}
          style={{
            width: "100%",
            padding: "3px 6px",
            background: "var(--bg-input)",
            border: "1px solid var(--border-color)",
            borderRadius: 3,
            color: "var(--text-primary)",
            fontSize: "var(--font-size-sm)",
            fontFamily: "var(--font-mono)",
            outline: "none",
          }}
        />
      </div>

      {/* Filter buttons */}
      <div style={{ display: "flex", gap: 2, padding: "3px 6px", borderBottom: "1px solid var(--border-color)", flexShrink: 0 }}>
        {(["all", "syscall", "jni"] as FilterType[]).map(f => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            style={{
              flex: 1,
              padding: "2px 0",
              background: filter === f ? "var(--btn-primary)" : "transparent",
              color: filter === f ? "#fff" : "var(--text-secondary)",
              border: filter === f ? "none" : "1px solid var(--border-color)",
              borderRadius: 3,
              fontSize: "var(--font-size-sm)",
              fontFamily: "var(--font-mono)",
              cursor: "pointer",
            }}
          >
            {f === "all" ? "All" : f === "syscall" ? "Syscall" : "JNI"}
          </button>
        ))}
      </div>

      {/* Virtual list */}
      <div ref={parentRef} style={{ flex: 1, overflow: "auto" }}>
        <div style={{ height: virtualizer.getTotalSize(), position: "relative" }}>
          {virtualizer.getVirtualItems().map(vItem => {
            const row = rows[vItem.index];
            if (row.type === "group") {
              const { entry, isExpanded } = row;
              return (
                <div
                  key={`g-${entry.func_name}`}
                  data-index={vItem.index}
                  style={{
                    position: "absolute",
                    top: vItem.start,
                    left: 0,
                    right: 0,
                    height: vItem.size,
                    display: "flex",
                    alignItems: "center",
                    padding: "0 6px",
                    cursor: "pointer",
                    borderBottom: "1px solid var(--border-color)",
                    background: "var(--bg-secondary)",
                    fontSize: "var(--font-size-sm)",
                    userSelect: "none",
                  }}
                  onClick={() => toggleExpand(entry.func_name)}
                >
                  <span style={{ width: 16, flexShrink: 0, color: "var(--text-secondary)" }}>
                    {isExpanded ? "\u25BC" : "\u25B6"}
                  </span>
                  <span style={{
                    color: entry.is_jni ? "var(--asm-immediate)" : "var(--asm-mnemonic)",
                    fontWeight: 500,
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                    flex: 1,
                  }}>
                    {entry.func_name}
                  </span>
                  <span style={{
                    marginLeft: 6,
                    color: "var(--text-secondary)",
                    fontSize: 11,
                    flexShrink: 0,
                  }}>
                    {entry.is_jni ? "JNI" : "SYS"} ({entry.occurrences.length})
                  </span>
                </div>
              );
            } else {
              return (
                <div
                  key={`o-${row.func_name}-${row.seq}`}
                  data-index={vItem.index}
                  style={{
                    position: "absolute",
                    top: vItem.start,
                    left: 0,
                    right: 0,
                    height: vItem.size,
                    display: "flex",
                    alignItems: "center",
                    padding: "0 6px 0 22px",
                    cursor: "pointer",
                    borderBottom: "1px solid var(--border-color)",
                    fontSize: "var(--font-size-sm)",
                  }}
                  onClick={() => onJumpToSeq(row.seq)}
                  onMouseEnter={e => (e.currentTarget.style.background = "var(--bg-selected)")}
                  onMouseLeave={e => (e.currentTarget.style.background = "")}
                >
                  <span style={{ color: "var(--text-address)", marginRight: 8, flexShrink: 0 }}>
                    #{row.seq}
                  </span>
                  <span style={{
                    color: "var(--text-primary)",
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                  }}>
                    {row.summary}
                  </span>
                </div>
              );
            }
          })}
        </div>
      </div>

      {/* Status bar */}
      <div style={{
        padding: "3px 8px",
        borderTop: "1px solid var(--border-color)",
        color: "var(--text-secondary)",
        fontSize: 11,
        flexShrink: 0,
        background: "var(--bg-secondary)",
      }}>
        {filtered.length} functions, {filteredCalls} calls
      </div>
    </div>
  );
}
```

- [ ] **Step 2: Verify TypeScript compiles**

Run: `cd src-web && npx tsc --noEmit 2>&1 | tail -10`
Expected: no errors

- [ ] **Step 3: Commit**

```bash
git add src-web/src/components/FunctionListPanel.tsx
git commit -m "feat: add FunctionListPanel component"
```

---

### Task 4: Frontend — Left panel tab integration

**Files:**
- Modify: `src-web/src/App.tsx:939-953` (left panel upper area)

**Key context:**
- Line 939: `<Panel defaultSize={65} minSize={20}>` — this is the upper panel inside the left sidebar (NOT the outermost left panel at line 939 which is `<Panel defaultSize={20} minSize={15}>`)
- Line 942-953: `<FunctionTree ... />` — will be wrapped in tab container
- `consumedSeqs` (line 430) — when `consumedSeqs.length > 0`, the trace is gumtrace format (function list is relevant)

- [ ] **Step 1: Add import for FunctionListPanel in `App.tsx`**

After the existing FunctionTree import (line 10):
```typescript
import FunctionListPanel from "./components/FunctionListPanel";
```

- [ ] **Step 2: Add left tab state**

After existing state declarations (near line 160, around other `useState` calls):
```typescript
const [leftTab, setLeftTab] = useState<"tree" | "list">("tree");
```

- [ ] **Step 3: Wrap FunctionTree panel content with tab container**

Replace the current content of the upper-left Panel (lines 941-954):

From:
```tsx
<Panel defaultSize={65} minSize={20}>
  <FunctionTree
    isPhase2Ready={isPhase2Ready}
    onJumpToSeq={handleJumpToSeq}
    nodeMap={callTreeNodeMap}
    nodeCount={callTreeCount}
    loading={callTreeLoading}
    error={callTreeError}
    lazyMode={callTreeLazyMode}
    loadedNodes={callTreeLoadedNodes}
    onLoadChildren={loadCallTreeChildren}
    funcRename={funcRename}
  />
</Panel>
```

To:
```tsx
<Panel defaultSize={65} minSize={20}>
  <div style={{ height: "100%", display: "flex", flexDirection: "column" }}>
    <div style={{
      display: "flex",
      height: 26,
      flexShrink: 0,
      background: "var(--bg-secondary)",
      borderBottom: "1px solid var(--border-color)",
      fontSize: "var(--font-size-sm)",
      fontFamily: "var(--font-mono)",
    }}>
      {(["tree", "list"] as const).map(tab => (
        <button
          key={tab}
          onClick={() => setLeftTab(tab)}
          style={{
            flex: 1,
            background: leftTab === tab ? "var(--bg-primary)" : "transparent",
            color: leftTab === tab ? "var(--text-primary)" : "var(--text-secondary)",
            border: "none",
            borderBottom: leftTab === tab ? "2px solid var(--btn-primary)" : "2px solid transparent",
            cursor: "pointer",
            fontFamily: "var(--font-mono)",
            fontSize: "var(--font-size-sm)",
          }}
        >
          {tab === "tree" ? "调用树" : "函数列表"}
        </button>
      ))}
    </div>
    <div style={{ flex: 1, overflow: "hidden" }}>
      {leftTab === "tree" ? (
        <FunctionTree
          isPhase2Ready={isPhase2Ready}
          onJumpToSeq={handleJumpToSeq}
          nodeMap={callTreeNodeMap}
          nodeCount={callTreeCount}
          loading={callTreeLoading}
          error={callTreeError}
          lazyMode={callTreeLazyMode}
          loadedNodes={callTreeLoadedNodes}
          onLoadChildren={loadCallTreeChildren}
          funcRename={funcRename}
        />
      ) : (
        <FunctionListPanel
          sessionId={activeSessionId}
          onJumpToSeq={handleJumpToSeq}
        />
      )}
    </div>
  </div>
</Panel>
```

- [ ] **Step 4: Verify TypeScript compiles**

Run: `cd src-web && npx tsc --noEmit 2>&1 | tail -10`
Expected: no errors

- [ ] **Step 5: Build full app and test**

Run: `cargo tauri build --debug 2>&1 | tail -10` (or `cargo tauri dev` for live testing)
Expected: app builds, left panel shows "调用树" / "函数列表" tabs

- [ ] **Step 6: Commit**

```bash
git add src-web/src/App.tsx
git commit -m "feat: add left panel tab switcher for Call Tree / Functions"
```

---

### Task 5: Integration testing and polish

**Files:**
- Potentially adjust: `src-web/src/components/FunctionListPanel.tsx`
- Potentially adjust: `src-web/src/App.tsx`

- [ ] **Step 1: Test with a gumtrace trace file**

Open a gumtrace format trace file in the app:
1. Switch to "Functions" tab in left panel
2. Verify function list loads and displays correctly
3. Verify filter buttons (All / Syscall / JNI) work
4. Verify search filters by function name
5. Verify clicking expand arrow shows occurrences
6. Verify clicking an occurrence jumps to correct seq in TraceTable
7. Verify status bar shows correct counts

- [ ] **Step 2: Test with a Unidbg trace file**

Open a Unidbg format trace file:
1. Switch to "Functions" tab
2. Verify it shows "No function calls found" (graceful degradation)

- [ ] **Step 3: Test edge cases**

- Empty trace file
- Trace file with only JNI calls
- Trace file with only syscalls
- Function with single occurrence (should still be expandable)
- Very long function names (verify text ellipsis)

- [ ] **Step 4: Fix any issues found during testing**

Address any bugs or visual issues discovered.

- [ ] **Step 5: Final commit**

```bash
git add -A
git commit -m "feat: function list panel — integration fixes and polish"
```
