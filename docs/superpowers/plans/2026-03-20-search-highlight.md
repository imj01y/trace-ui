# 搜索结果高亮 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在搜索结果列表中对匹配的搜索子串进行亮黄色背景高亮显示。

**Architecture:** 创建 `highlightText` 工具函数将文本按搜索关键词拆分为匹配/非匹配片段并用 `<mark>` 包裹；在 SearchResultList 所有文本列和 DisasmHighlight 的 token 中应用该函数。

**Tech Stack:** React + TypeScript

---

### Task 1: 创建 highlightText 工具函数

**Files:**
- Create: `src-web/src/utils/highlightText.tsx`

- [ ] **Step 1: 创建 highlightText 函数**

```tsx
import React from "react";

const MARK_STYLE: React.CSSProperties = {
  background: "rgba(255,210,0,0.45)",
  color: "inherit",
  borderRadius: 2,
  padding: 0,
};

/**
 * 将文本中匹配 query 的子串用 <mark> 高亮包裹。
 * 支持普通文本、FuzzyText（空格分隔多关键词）和 /regex/ 模式。
 * 无匹配时返回原始字符串。
 */
export function highlightText(
  text: string,
  query: string,
  caseSensitive: boolean = false,
): React.ReactNode {
  if (!text || !query) return text;

  // 构建匹配正则
  let regex: RegExp;
  try {
    if (query.startsWith("/") && query.endsWith("/") && query.length > 2) {
      // /regex/ 模式
      const pattern = query.slice(1, -1);
      regex = new RegExp(pattern, caseSensitive ? "g" : "gi");
    } else if (!caseSensitive && query.includes(" ")) {
      // FuzzyText：空格分隔多关键词，每个独立高亮
      const tokens = query.split(/\s+/).filter(Boolean);
      if (tokens.length === 0) return text;
      const escaped = tokens.map(t => t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
      regex = new RegExp(`(${escaped.join("|")})`, "gi");
    } else {
      // 普通文本匹配
      const escaped = query.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      regex = new RegExp(escaped, caseSensitive ? "g" : "gi");
    }
  } catch {
    // 无效正则，不高亮
    return text;
  }

  const parts: React.ReactNode[] = [];
  let lastIndex = 0;
  let match: RegExpExecArray | null;
  let key = 0;

  regex.lastIndex = 0;
  while ((match = regex.exec(text)) !== null) {
    if (match[0].length === 0) {
      regex.lastIndex++;
      continue;
    }
    if (match.index > lastIndex) {
      parts.push(text.slice(lastIndex, match.index));
    }
    parts.push(
      <mark key={key++} style={MARK_STYLE}>{match[0]}</mark>
    );
    lastIndex = regex.lastIndex;
  }

  if (parts.length === 0) return text;
  if (lastIndex < text.length) {
    parts.push(text.slice(lastIndex));
  }
  return <>{parts}</>;
}
```

- [ ] **Step 2: 验证编译**

Run: `cd src-web && npx tsc --noEmit 2>&1 | head -20`
Expected: 无错误

- [ ] **Step 3: Commit**

```bash
git add src-web/src/utils/highlightText.tsx
git commit -m "feat(ui): create highlightText utility for search match highlighting"
```

---

### Task 2: SearchResultList 应用高亮

**Files:**
- Modify: `src-web/src/components/SearchResultList.tsx`

- [ ] **Step 1: 新增 import 和 props**

在 SearchResultList.tsx 顶部新增 import：

```tsx
import { highlightText } from "../utils/highlightText";
```

在 `SearchResultListProps` 接口（第 61-66 行）中新增：

```tsx
searchQuery?: string;
caseSensitive?: boolean;
```

在组件参数解构中新增 `searchQuery, caseSensitive`。

- [ ] **Step 2: 创建高亮辅助函数**

在组件内部（return 之前）添加：

```tsx
const hl = useCallback((text: string | null | undefined) => {
  if (!text || !searchQuery) return text ?? "";
  return highlightText(text, searchQuery, caseSensitive ?? false);
}, [searchQuery, caseSensitive]);
```

新增 `import { useCallback } from "react";`（如已有则忽略——检查第 1 行，当前已有 `useCallback`）。

- [ ] **Step 3: 在所有纯文本列应用高亮**

在渲染行内（约第 280-316 行），逐一替换：

**mem_rw 列**（约第 281 行）：
```tsx
// FROM:
{match.mem_rw === "W" ? "W" : match.mem_rw === "R" ? "R" : ""}
// TO:
{hl(match.mem_rw === "W" ? "W" : match.mem_rw === "R" ? "R" : "")}
```

**address 列**（约第 286 行）：
```tsx
// FROM:
{match.address}
// TO:
{hl(match.address)}
```

**call_info.summary**（约第 299-301 行）：
```tsx
// FROM:
{match.call_info.summary.length > 80
  ? match.call_info.summary.slice(0, 80) + "..."
  : match.call_info.summary}
// TO:
{hl(match.call_info.summary.length > 80
  ? match.call_info.summary.slice(0, 80) + "..."
  : match.call_info.summary)}
```

**changes 列**（约第 315 行）：
```tsx
// FROM:
{match.changes}
// TO:
{hl(match.changes)}
```

**hidden_content**（约第 337 行）：
```tsx
// FROM:
{match.hidden_content}
// TO:
{hl(match.hidden_content)}
```

- [ ] **Step 4: 传递 highlightQuery 给 DisasmHighlight**

找到 `<DisasmHighlight text={match.disasm} />`（约第 289 行），修改为：

```tsx
<DisasmHighlight text={match.disasm} highlightQuery={searchQuery} caseSensitive={caseSensitive} />
```

- [ ] **Step 5: 验证编译**

Run: `cd src-web && npx tsc --noEmit 2>&1 | head -20`
Expected: 可能有 DisasmHighlight 缺少 props 的错误（Task 3 修复）

- [ ] **Step 6: Commit**

```bash
git add src-web/src/components/SearchResultList.tsx
git commit -m "feat(ui): apply search highlight to all SearchResultList columns"
```

---

### Task 3: DisasmHighlight 支持搜索高亮

**Files:**
- Modify: `src-web/src/components/DisasmHighlight.tsx`

- [ ] **Step 1: 新增 import 和 props**

在 DisasmHighlight.tsx 顶部新增：

```tsx
import { highlightText } from "../utils/highlightText";
```

在 `Props` 接口（第 13-17 行）中新增：

```tsx
highlightQuery?: string;
caseSensitive?: boolean;
```

在组件参数解构中新增 `highlightQuery, caseSensitive`。

- [ ] **Step 2: 在 token 渲染中应用搜索高亮**

在 `DisasmHighlight` 函数中，找到 `memo` 的第二个参数或组件本身的渲染逻辑。

找到渲染 token 文本的位置（第 44-69 行的 `parts.map`），将每个 token 的文本渲染改为通过 `highlightText` 包裹。

将第 62 行的 `{p.text}` 替换（寄存器可点击的 token）：
```tsx
// FROM:
{p.text}
// TO:
{highlightQuery ? highlightText(p.text, highlightQuery, caseSensitive ?? false) : p.text}
```

将第 67 行有颜色的 token 替换：
```tsx
// FROM:
? <span key={i} style={{ color: p.color }}>{p.text}</span>
// TO:
? <span key={i} style={{ color: p.color }}>{highlightQuery ? highlightText(p.text, highlightQuery, caseSensitive ?? false) : p.text}</span>
```

将第 68 行无颜色的 token 替换：
```tsx
// FROM:
: <span key={i}>{p.text}</span>
// TO:
: <span key={i}>{highlightQuery ? highlightText(p.text, highlightQuery, caseSensitive ?? false) : p.text}</span>
```

- [ ] **Step 3: 更新 memo 比较**

当前 `DisasmHighlight` 用 `memo` 包裹（第 74 行）。默认的 shallow compare 会正确处理新增的 `highlightQuery` 和 `caseSensitive` string/boolean props，无需自定义比较函数。

- [ ] **Step 4: 验证编译**

Run: `cd src-web && npx tsc --noEmit 2>&1 | head -20`
Expected: 可能有 TabPanel/FloatingPanel 缺少 props 的错误（Task 4 修复）

- [ ] **Step 5: Commit**

```bash
git add src-web/src/components/DisasmHighlight.tsx
git commit -m "feat(ui): add search highlight support to DisasmHighlight tokens"
```

---

### Task 4: TabPanel 和 FloatingPanel 传递搜索 query

**Files:**
- Modify: `src-web/src/components/TabPanel.tsx`
- Modify: `src-web/src/FloatingPanel.tsx`

- [ ] **Step 1: TabPanel 传递 searchQuery 和 caseSensitive**

在 TabPanel.tsx 中找到 `<SearchResultList`（约第 248 行），新增两个 props：

```tsx
<SearchResultList
  results={searchResults}
  selectedSeq={searchResults[selectedSearchIdx]?.seq ?? null}
  onJumpToSeq={onJumpToSeq}
  onJumpToMatch={onJumpToSearchMatch}
  searchQuery={searchQuery}
  caseSensitive={searchOptions.caseSensitive}
/>
```

- [ ] **Step 2: FloatingPanel 传递 searchQuery 和 caseSensitive**

在 FloatingPanel.tsx 的 `FloatingSearchContent` 中，先新增一个 state 追踪 caseSensitive（因为 `currentOptionsRef.current` 不触发重渲染）：

```tsx
const [caseSensitiveState, setCaseSensitiveState] = useState(false);

const handleOptionsChange = useCallback((opts: SearchOptions) => {
  currentOptionsRef.current = opts;
  setCaseSensitiveState(opts.caseSensitive);
}, []);
```

然后找到 `<SearchResultList`（约第 325 行），新增两个 props：

```tsx
<SearchResultList
  results={searchResults}
  selectedSeq={searchResults[selectedIdx]?.seq ?? null}
  onJumpToSeq={onJumpToSeq}
  onJumpToMatch={onJumpToMatch}
  searchQuery={searchQuery}
  caseSensitive={caseSensitiveState}
/>
```

- [ ] **Step 3: 验证编译**

Run: `cd src-web && npx tsc --noEmit 2>&1 | head -20`
Expected: 无错误

- [ ] **Step 4: 全量编译验证**

Run: `cargo build 2>&1 | tail -5`
Expected: 编译成功

- [ ] **Step 5: Commit**

```bash
git add src-web/src/components/TabPanel.tsx src-web/src/FloatingPanel.tsx
git commit -m "feat(ui): wire searchQuery and caseSensitive to SearchResultList for highlighting"
```
