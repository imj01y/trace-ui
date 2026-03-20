# Resizable Columns Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 给 SearchResultList、StringsPanel、StringXRefsPanel（含浮窗）所有列增加鼠标拖动调整宽度并持久化到 localStorage。

**Architecture:** 扩展现有 `useResizableColumn` hook 加入 `persistKey` 参数实现 localStorage 持久化，各面板内部逐列调用 hook 管理列宽，使用 8px 透明拖动手柄（和 TraceTable 一致）。

**Tech Stack:** React, TypeScript, localStorage

**Spec:** `docs/superpowers/specs/2026-03-19-resizable-columns-design.md`

---

### Task 1: 扩展 useResizableColumn hook 支持持久化

**Files:**
- Modify: `src-web/src/hooks/useResizableColumn.ts`

- [ ] **Step 1: 添加 persistKey 参数和 localStorage 读写**

```typescript
import { useState, useCallback, useRef } from "react";

const STORAGE_PREFIX = "col-width:";

function loadWidth(persistKey: string, initialWidth: number, minWidth: number): number {
  try {
    const raw = localStorage.getItem(STORAGE_PREFIX + persistKey);
    if (raw === null) return initialWidth;
    const val = Number(raw);
    if (!Number.isFinite(val) || val < minWidth) return initialWidth;
    return val;
  } catch {
    return initialWidth;
  }
}

function saveWidth(persistKey: string, width: number) {
  try {
    localStorage.setItem(STORAGE_PREFIX + persistKey, String(width));
  } catch { /* 静默降级 */ }
}

/**
 * @param initialWidth 初始宽度
 * @param direction "left" = 向左拖增大（Changes 列），"right" = 向右拖增大（Seq/Address 列）
 * @param minWidth 最小宽度
 * @param persistKey 可选，存在时自动从 localStorage 读写列宽
 */
export function useResizableColumn(
  initialWidth: number,
  direction: "left" | "right" = "left",
  minWidth = 40,
  persistKey?: string,
) {
  const [width, setWidth] = useState(() =>
    persistKey ? loadWidth(persistKey, initialWidth, minWidth) : initialWidth
  );
  const dragging = useRef(false);
  const startX = useRef(0);
  const startW = useRef(0);
  const latestWidth = useRef(width);
  latestWidth.current = width;

  const onMouseDown = useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    dragging.current = true;
    startX.current = e.clientX;
    startW.current = width;
    const onMove = (ev: MouseEvent) => {
      if (!dragging.current) return;
      const delta = direction === "left"
        ? startX.current - ev.clientX
        : ev.clientX - startX.current;
      const newW = Math.max(minWidth, startW.current + delta);
      setWidth(newW);
      latestWidth.current = newW;
    };
    const onUp = () => {
      dragging.current = false;
      document.removeEventListener("mousemove", onMove);
      document.removeEventListener("mouseup", onUp);
      if (persistKey) saveWidth(persistKey, latestWidth.current);
    };
    document.addEventListener("mousemove", onMove);
    document.addEventListener("mouseup", onUp);
  }, [width, direction, minWidth, persistKey]);

  return { width, onMouseDown };
}
```

- [ ] **Step 2: 验证编译通过**

Run: `cd src-web && npx tsc --noEmit`
Expected: 无错误（向后兼容，现有调用方不受影响）

- [ ] **Step 3: Commit**

```bash
git add src-web/src/hooks/useResizableColumn.ts
git commit -m "feat: add persistKey support to useResizableColumn hook"
```

---

### Task 2: SearchResultList 内部管理所有列宽

**Files:**
- Modify: `src-web/src/components/SearchResultList.tsx`
- Modify: `src-web/src/components/TabPanel.tsx`

- [ ] **Step 1: 修改 SearchResultList — 移除外部 props，添加内部 hook**

在 SearchResultList.tsx 中：

1. 移除 props 中的 `changesWidth` 和 `onResizeChanges`：
```typescript
interface SearchResultListProps {
  results: SearchMatch[];
  selectedSeq?: number | null;
  onJumpToSeq: (seq: number) => void;
  onJumpToMatch?: (match: SearchMatch) => void;
}
```

2. 在组件顶部添加 5 个 hook 调用（import useResizableColumn）：
```typescript
import { useResizableColumn } from "../hooks/useResizableColumn";

// 在组件函数内部：
const rwCol = useResizableColumn(30, "right", 20, "search:rw");
const seqCol = useResizableColumn(90, "right", 50, "search:seq");
const addrCol = useResizableColumn(90, "right", 50, "search:addr");
const changesCol = useResizableColumn(
  Math.min(300, Math.round(window.innerWidth * 0.2)), "left", 40, "search:changes"
);
```

3. 定义拖动手柄的内联样式常量（复用）：
```typescript
const HANDLE_STYLE: React.CSSProperties = {
  width: 8, cursor: "col-resize", flexShrink: 0,
  display: "flex", alignItems: "center", justifyContent: "center",
};
```

4. 修改表头（约 L187-208），将硬编码宽度替换为 hook 返回的 width，每列之间插入拖动手柄：
```tsx
{/* 表头 */}
<div style={{ ... }}>
  <span style={{ width: 48, flexShrink: 0 }}></span>
  <span style={{ width: rwCol.width, flexShrink: 0 }}>R/W</span>
  <div onMouseDown={rwCol.onMouseDown} style={HANDLE_STYLE} />
  <span style={{ width: seqCol.width, flexShrink: 0 }}>#</span>
  <div onMouseDown={seqCol.onMouseDown} style={HANDLE_STYLE} />
  <span style={{ width: addrCol.width, flexShrink: 0 }}>Address</span>
  <div onMouseDown={addrCol.onMouseDown} style={HANDLE_STYLE} />
  <span style={{ flex: 1 }}>Disassembly</span>
  <div onMouseDown={changesCol.onMouseDown} style={HANDLE_STYLE} />
  <span style={{ width: changesCol.width, flexShrink: 0 }}>Changes</span>
  <span style={{ width: MINIMAP_WIDTH + 12, flexShrink: 0 }}></span>
</div>
```

5. 修改数据行（约 L268-301），替换列宽为动态值，并加入 8px 占位对齐表头手柄：
```tsx
<span style={{ width: rwCol.width, flexShrink: 0, ... }}>...</span>
<span style={{ width: 8, flexShrink: 0 }} />
<span style={{ width: seqCol.width, flexShrink: 0, ... }}>...</span>
<span style={{ width: 8, flexShrink: 0 }} />
<span style={{ width: addrCol.width, flexShrink: 0, ... }}>...</span>
<span style={{ width: 8, flexShrink: 0 }} />
<span style={{ flex: 1, ... }}>...</span>
<span style={{ width: 8, flexShrink: 0 }} />
<span style={{ width: changesCol.width, ... }}>...</span>
```

注意：数据行中也需要在对应位置插入 8px 宽的空白占位 `<span style={{ width: 8, flexShrink: 0 }} />`，确保表头和数据行列对齐。每个拖动手柄对应一个占位。

- [ ] **Step 2: 修改 TabPanel — 移除 changesCol 相关代码**

在 TabPanel.tsx 中：

1. 移除 L51 的 `const changesCol = useResizableColumn(...)`
2. 移除 L172-173 传递给 SearchResultList 的 `changesWidth={changesCol.width}` 和 `onResizeChanges={changesCol.onMouseDown}`
3. 如果 `useResizableColumn` import 不再被其他代码使用，移除该 import

- [ ] **Step 3: 验证编译通过**

Run: `cd src-web && npx tsc --noEmit`
Expected: 无错误

- [ ] **Step 4: Commit**

```bash
git add src-web/src/components/SearchResultList.tsx src-web/src/components/TabPanel.tsx
git commit -m "feat: add resizable columns to SearchResultList"
```

---

### Task 3: StringsPanel 添加所有列的拖动调整

**Files:**
- Modify: `src-web/src/components/StringsPanel.tsx`

- [ ] **Step 1: 添加 hook 调用和拖动手柄**

在 StringsPanel.tsx 中：

1. import useResizableColumn：
```typescript
import { useResizableColumn } from "../hooks/useResizableColumn";
```

2. 在组件函数内部添加 hook 调用：
```typescript
const seqCol = useResizableColumn(70, "right", 40, "strings:seq");
const addrCol = useResizableColumn(110, "right", 50, "strings:addr");
const encCol = useResizableColumn(56, "left", 30, "strings:enc");
const lenCol = useResizableColumn(44, "left", 30, "strings:len");
const xrefsCol = useResizableColumn(56, "left", 30, "strings:xrefs");
```

3. 定义拖动手柄样式常量：
```typescript
const HANDLE_STYLE: React.CSSProperties = {
  width: 8, cursor: "col-resize", flexShrink: 0,
  display: "flex", alignItems: "center", justifyContent: "center",
};
```

4. 修改表头（L338-350），替换硬编码宽度并插入拖动手柄：
```tsx
<div style={{ ... }}>
  <span style={{ width: seqCol.width, flexShrink: 0 }}>Seq</span>
  <div onMouseDown={seqCol.onMouseDown} style={HANDLE_STYLE} />
  <span style={{ width: addrCol.width, flexShrink: 0 }}>Address</span>
  <div onMouseDown={addrCol.onMouseDown} style={HANDLE_STYLE} />
  <span style={{ flex: 1 }}>Content</span>
  <div onMouseDown={encCol.onMouseDown} style={HANDLE_STYLE} />
  <span style={{ width: encCol.width, flexShrink: 0 }}>Enc</span>
  <div onMouseDown={lenCol.onMouseDown} style={HANDLE_STYLE} />
  <span style={{ width: lenCol.width, flexShrink: 0 }}>Len</span>
  <div onMouseDown={xrefsCol.onMouseDown} style={HANDLE_STYLE} />
  <span style={{ width: xrefsCol.width, flexShrink: 0 }}>XRefs</span>
</div>
```

5. 修改数据行（L378-388），替换硬编码宽度：
```tsx
<span style={{ width: seqCol.width, flexShrink: 0, ... }}>{record.seq + 1}</span>
<span style={{ width: addrCol.width, flexShrink: 0, ... }}>{record.addr}</span>
<span style={{ flex: 1, ... }}>"{record.content}"</span>
<span style={{ width: encCol.width, flexShrink: 0, ... }}>{record.encoding}</span>
<span style={{ width: lenCol.width, flexShrink: 0, ... }}>{record.byte_len}</span>
<span style={{ width: xrefsCol.width, flexShrink: 0, ... }}>{record.xref_count}</span>
```

- [ ] **Step 2: 验证编译通过**

Run: `cd src-web && npx tsc --noEmit`
Expected: 无错误

- [ ] **Step 3: Commit**

```bash
git add src-web/src/components/StringsPanel.tsx
git commit -m "feat: add resizable columns to StringsPanel"
```

---

### Task 4: StringXRefsPanel 添加所有列的拖动调整

**Files:**
- Modify: `src-web/src/components/StringXRefsPanel.tsx`

- [ ] **Step 1: 添加 hook 调用和拖动手柄**

在 StringXRefsPanel.tsx 中：

1. import useResizableColumn：
```typescript
import { useResizableColumn } from "../hooks/useResizableColumn";
```

2. 在组件函数内部添加 hook 调用：
```typescript
const seqCol = useResizableColumn(70, "right", 40, "xrefs:seq");
const rwCol = useResizableColumn(30, "right", 20, "xrefs:rw");
const addrCol = useResizableColumn(110, "right", 50, "xrefs:addr");
```

3. 定义拖动手柄样式常量：
```typescript
const HANDLE_STYLE: React.CSSProperties = {
  width: 8, cursor: "col-resize", flexShrink: 0,
  display: "flex", alignItems: "center", justifyContent: "center",
};
```

4. 修改表头（L66-77），替换硬编码宽度并插入拖动手柄：
```tsx
<div style={{ ... }}>
  <span style={{ width: seqCol.width, flexShrink: 0 }}>Seq</span>
  <div onMouseDown={seqCol.onMouseDown} style={HANDLE_STYLE} />
  <span style={{ width: rwCol.width, flexShrink: 0 }}>R/W</span>
  <div onMouseDown={rwCol.onMouseDown} style={HANDLE_STYLE} />
  <span style={{ width: addrCol.width, flexShrink: 0 }}>Address</span>
  <div onMouseDown={addrCol.onMouseDown} style={HANDLE_STYLE} />
  <span style={{ flex: 1 }}>Disasm</span>
</div>
```

5. 修改数据行（L97-100），替换硬编码宽度：
```tsx
<span style={{ width: seqCol.width, flexShrink: 0, ... }}>{xref.seq + 1}</span>
<span style={{ width: rwCol.width, flexShrink: 0, ... }}>{xref.rw}</span>
<span style={{ width: addrCol.width, flexShrink: 0, ... }}>{xref.insn_addr}</span>
<span style={{ flex: 1, ... }}>{xref.disasm}</span>
```

- [ ] **Step 2: 验证编译通过**

Run: `cd src-web && npx tsc --noEmit`
Expected: 无错误

- [ ] **Step 3: Commit**

```bash
git add src-web/src/components/StringXRefsPanel.tsx
git commit -m "feat: add resizable columns to StringXRefsPanel"
```

---

### Task 5: 最终验证

- [ ] **Step 1: 全量编译检查**

Run: `cd src-web && npx tsc --noEmit`
Expected: 无错误

- [ ] **Step 2: 检查所有面板的拖动手柄对齐**

确认表头和数据行的列宽一致。每个表头拖动手柄（8px）在数据行中有对应的 8px 占位 span。
