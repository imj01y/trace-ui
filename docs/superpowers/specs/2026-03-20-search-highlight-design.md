# 搜索结果高亮设计

## 概述

在搜索结果列表中，对匹配的搜索子串进行亮黄色背景高亮，仅高亮匹配的文本本身（非整行/整列）。覆盖所有文本列。搜索高亮与 DisasmHighlight 语法高亮共存：匹配部分叠加黄色背景，保持原有语法颜色。

## 1. highlightText 工具函数

**文件：** `src-web/src/utils/highlightText.tsx`

**签名：**
```ts
function highlightText(
  text: string,
  query: string,
  caseSensitive: boolean
): React.ReactNode
```

**行为：**
- 将 `text` 按 `query` 匹配拆分为匹配/非匹配片段
- 匹配片段用 `<mark>` 包裹，样式：`background: "rgba(255,210,0,0.45)"`, `color: "inherit"`, `borderRadius: 2`, `padding: 0`
- FuzzyText 支持：当 query 含空格且不是正则模式时，按空格拆分为多个关键词，每个独立高亮
- 正则模式（`/pattern/` 格式）：用正则进行全局匹配
- query 为空或无匹配时直接返回原文本字符串（非 React 元素，避免不必要的包装）

## 2. SearchResultList 改动

**文件：** `src-web/src/components/SearchResultList.tsx`

### 新增 Props

```ts
searchQuery?: string;       // 当前搜索关键词（原始输入）
caseSensitive?: boolean;    // 是否大小写敏感
```

### 应用高亮的位置

| 列 | 当前渲染方式 | 改动 |
|---|---|---|
| `match.mem_rw` | 纯文本 | `highlightText(match.mem_rw, query, caseSensitive)` |
| `match.address` | 纯文本 | `highlightText(match.address, query, caseSensitive)` |
| `match.disasm` | `<DisasmHighlight>` | 传入 `highlightQuery` prop（见第 3 节） |
| `match.call_info.summary` | 纯文本 | `highlightText(summary, query, caseSensitive)` |
| `match.changes` | 纯文本 | `highlightText(match.changes, query, caseSensitive)` |
| `match.hidden_content` | 纯文本 | `highlightText(match.hidden_content, query, caseSensitive)` |

## 3. DisasmHighlight 改动

**文件：** `src-web/src/components/DisasmHighlight.tsx`

### 新增 Props

```ts
highlightQuery?: string;
caseSensitive?: boolean;
```

### 行为

在渲染每个 token 时，如果 `highlightQuery` 存在，对 token 的文本调用 `highlightText(tokenText, highlightQuery, caseSensitive)` 替代原来的纯文本渲染。语法着色（`color`）保持不变，搜索匹配部分叠加黄色背景。

## 4. 数据流

TabPanel / FloatingPanel 将当前搜索 query 和 caseSensitive 状态通过 props 传递给 SearchResultList：

```
TabPanel/FloatingPanel
  → SearchResultList (searchQuery, caseSensitive)
    → highlightText() (纯文本列)
    → DisasmHighlight (highlightQuery, caseSensitive)
      → highlightText() (每个 token)
```

## 涉及文件清单

| 文件 | 操作 |
|------|------|
| `src-web/src/utils/highlightText.tsx` | 新建 |
| `src-web/src/components/SearchResultList.tsx` | 修改（新增 props，应用高亮） |
| `src-web/src/components/DisasmHighlight.tsx` | 修改（新增 props，token 级高亮） |
| `src-web/src/components/TabPanel.tsx` | 修改（传递 searchQuery/caseSensitive） |
| `src-web/src/FloatingPanel.tsx` | 修改（传递 searchQuery/caseSensitive） |
