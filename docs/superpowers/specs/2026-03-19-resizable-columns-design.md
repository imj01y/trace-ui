# Resizable Columns for Search & Strings Panels

## Overview

给 SearchResultList、StringsPanel、StringXRefsPanel（含浮窗）中的所有列增加鼠标拖动调整宽度的功能，并持久化到 localStorage。

## 方案

扩展现有 `useResizableColumn` hook，加入可选 `persistKey` 参数。各面板内部逐列调用 hook，保持和 TraceTable 一致的交互风格（8px 透明拖动手柄，cursor: col-resize）。

## Hook 扩展：useResizableColumn

```typescript
export function useResizableColumn(
  initialWidth: number,
  direction?: "left" | "right",  // default "left"
  minWidth?: number,             // default 40
  persistKey?: string,           // 新增，可选
)
```

- `persistKey` 存在时，初始值从 `localStorage.getItem("col-width:" + persistKey)` 读取
- localStorage 操作用 try-catch 包装，读取失败（无痕模式、被禁用等）静默降级到 `initialWidth`
- 读取的值验证：必须为有效正数且 >= minWidth，否则用 `initialWidth`
- 拖动结束（mouseup）时写入 `localStorage.setItem("col-width:" + persistKey, width.toString())`
- `persistKey` 不存在时行为完全不变（向后兼容）

## SearchResultList 列配置

| 列 | 默认宽度 | minWidth | persistKey | direction |
|---|---|---|---|---|
| R/W | 30 | 20 | `search:rw` | right |
| # (Seq) | 90 | 50 | `search:seq` | right |
| Address | 90 | 50 | `search:addr` | right |
| Disasm | flex:1 | — | — | — |
| Changes | min(300, 20%vw) | 40 | `search:changes` | left |

关键变化：`changesWidth` / `onResizeChanges` 不再从 TabPanel 外部传入，改为 SearchResultList 内部用 hook 管理。这样 FloatingPanel 中的 SearchResultList 也自动获得拖动能力。

具体改动：
- SearchResultList.tsx：移除 `changesWidth` 和 `onResizeChanges` props，内部调用 5 个 `useResizableColumn` hook
- TabPanel.tsx：移除 `changesCol` hook 调用，移除向 SearchResultList 传递 `changesWidth`/`onResizeChanges`
- FloatingPanel.tsx：SearchResultList 调用处无需改动（已经不传列宽 props）

每列之间放置 8px 透明拖动手柄（和 TraceTable 一致）。Disasm 列保持 `flex: 1` 弹性填充，不需要拖动手柄。

## StringsPanel 列配置

| 列 | 默认宽度 | minWidth | persistKey | direction |
|---|---|---|---|---|
| Seq | 70 | 40 | `strings:seq` | right |
| Address | 110 | 50 | `strings:addr` | right |
| Content | flex:1 | — | — | — |
| Enc | 56 | 30 | `strings:enc` | left |
| Len | 44 | 30 | `strings:len` | left |
| XRefs | 56 | 30 | `strings:xrefs` | left |

Content 列保持 `flex: 1`，左侧列 direction=right，右侧列 direction=left。

具体改动：
- StringsPanel.tsx：将硬编码列宽替换为 hook 返回的 width，表头和数据行均使用动态宽度，添加拖动手柄

## StringXRefsPanel 列配置

| 列 | 默认宽度 | minWidth | persistKey | direction |
|---|---|---|---|---|
| Seq | 70 | 40 | `xrefs:seq` | right |
| R/W | 30 | 20 | `xrefs:rw` | right |
| Address | 110 | 50 | `xrefs:addr` | right |
| Disasm | flex:1 | — | — | — |

具体改动：
- StringXRefsPanel.tsx：同 StringsPanel 的改造模式

## 浮窗兼容

- SearchResultList 改为内部管理列宽后，FloatingPanel 中的调用无需任何改动
- StringsPanel / StringXRefsPanel 列宽 hook 在组件内部，浮窗中渲染时同样自动生效
- 持久化 key 统一，主窗口和浮窗共享同一组列宽设置

## 视觉风格

保持和 TraceTable 一致：
- 8px 宽透明拖动区域
- 鼠标悬停时 cursor 变为 col-resize
- 无可见分隔线

## 涉及文件

| 文件 | 改动 |
|---|---|
| `hooks/useResizableColumn.ts` | 添加 `persistKey` 参数，localStorage 读写（try-catch 包装） |
| `components/SearchResultList.tsx` | 移除 `changesWidth`/`onResizeChanges` props，内部调用 5 个列宽 hook，添加拖动手柄 |
| `components/StringsPanel.tsx` | 硬编码列宽替换为 6 个列宽 hook，添加拖动手柄 |
| `components/StringXRefsPanel.tsx` | 硬编码列宽替换为 4 个列宽 hook，添加拖动手柄 |
| `components/TabPanel.tsx` | 移除 `changesCol` hook 和向 SearchResultList 传递的 `changesWidth`/`onResizeChanges` props |
