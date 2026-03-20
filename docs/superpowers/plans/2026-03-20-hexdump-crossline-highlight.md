# Hexdump 跨行搜索高亮 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在搜索结果的 hidden_content 中支持 hex 和 ASCII 的跨行匹配与跨行高亮，同时支持带空格 hex、无空格紧凑 hex、ASCII 文本三种搜索格式。

**Architecture:** 后端 `searchable_text()` 追加无空格 hex 行使紧凑 hex 查询可命中；前端新增 `highlightHexdump` 函数解析 hexdump 格式、提取 hex/ASCII 流做跨行匹配、映射高亮回原始行。

**Tech Stack:** Rust（后端）、React + TypeScript（前端）

---

### Task 1: 后端 searchable_text 追加无空格 hex

**Files:**
- Modify: `src/taint/gumtrace_parser.rs:88-103`

- [ ] **Step 1: 在 searchable_text() 中追加无空格 hex 行**

在 `src/taint/gumtrace_parser.rs` 的 `searchable_text()` 方法中，找到第 93-94 行（追加带空格 hex 后），在其后新增无空格版本。

将第 88-103 行替换为：

```rust
    /// 生成用于搜索的完整文本，包含 summary + tooltip + 连续 hexdump ASCII
    pub fn searchable_text(&self) -> String {
        let mut text = format!("{}\n{}", self.summary(), self.tooltip());
        let (hex_str, raw_bytes) = self.merged_hexdump();
        if !hex_str.is_empty() {
            text.push('\n');
            text.push_str(&hex_str);
            // 追加无空格 hex（支持紧凑 hex 搜索如 "da487d00000029"）
            text.push('\n');
            text.push_str(&hex_str.replace(" ", ""));
            // 追加连续 ASCII 表示（可打印字符保留，不可打印用 . 替换）
            let ascii: String = raw_bytes.iter().map(|&b| {
                if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' }
            }).collect();
            text.push('\n');
            text.push_str(&ascii);
        }
        text
    }
```

- [ ] **Step 2: 编译验证**

Run: `cargo build 2>&1 | tail -5`
Expected: 编译成功

- [ ] **Step 3: Commit**

```bash
git add src/taint/gumtrace_parser.rs
git commit -m "feat(search): add compact hex string to searchable_text for spaceless hex queries"
```

---

### Task 2: 前端 highlightHexdump 函数

**Files:**
- Modify: `src-web/src/utils/highlightText.tsx`

- [ ] **Step 1: 在 highlightText.tsx 末尾新增辅助类型和函数**

在文件末尾（第 93 行 `}` 之后）追加以下完整代码：

```tsx
// ── Hexdump 跨行高亮 ──

/** hexdump 行解析结果 */
interface HexdumpLine {
  lineIndex: number;       // 在原始行数组中的索引
  prefix: string;          // 地址前缀 "7b98de36c0: "
  hexPart: string;         // hex 区域 "1f e0 da 48 7d ..."
  hexStart: number;        // hex 区域在原始行中的起始字符位置
  asciiPart: string;       // ASCII 区域 "...H}...'..H}..."
  asciiStart: number;      // ASCII 区域在原始行中的起始字符位置（| 后）
  separator: string;       // hex 和 ASCII 之间的 " |" 部分
  suffix: string;          // 末尾 "|"
  byteCount: number;       // 本行的字节数
}

/** 判断是否为带空格的 hex 格式：如 "da 48 7d 00" */
function isSpacedHex(q: string): boolean {
  return /^[0-9a-f]{2}( [0-9a-f]{2})+$/i.test(q);
}

/** 判断是否为紧凑 hex 格式：如 "da487d00"（全 hex、偶数长度、≥4） */
function isCompactHex(q: string): boolean {
  return q.length >= 4 && q.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(q);
}

/** 紧凑 hex 转带空格形式："da487d" → "da 48 7d" */
function compactToSpaced(q: string): string {
  const pairs: string[] = [];
  for (let i = 0; i < q.length; i += 2) {
    pairs.push(q.slice(i, i + 2));
  }
  return pairs.join(" ");
}

/** 解析一行文本，判断是否为 hexdump 数据行 */
function parseHexdumpLine(line: string, lineIndex: number): HexdumpLine | null {
  // 格式: "ADDR: XX XX XX ... |ASCII...|"
  const match = /^([0-9a-fA-F]+:\s)(.+?)\s*\|(.+)\|$/.exec(line);
  if (!match) return null;

  const prefix = match[1];
  const hexPart = match[2].trim();
  const asciiPart = match[3];
  const hexStart = prefix.length;
  // ASCII 起始位置：找到 "|" 的位置 + 1
  const pipePos = line.indexOf("|", hexStart);
  const asciiStart = pipePos >= 0 ? pipePos + 1 : 0;
  const byteCount = hexPart.split(/\s+/).filter(Boolean).length;

  return {
    lineIndex, prefix, hexPart, hexStart,
    asciiPart, asciiStart, separator: " |", suffix: "|",
    byteCount,
  };
}

/**
 * 在一行文本的指定区域内，对指定字符范围进行高亮渲染。
 * highlightRanges: [start, end) 的数组，相对于区域起始位置。
 */
function renderLineWithHighlights(
  text: string,
  highlights: Array<[number, number]>, // [start, end) 绝对字符位置
  key: number,
): { nodes: React.ReactNode[]; nextKey: number } {
  if (highlights.length === 0) {
    return { nodes: [text], nextKey: key };
  }

  const nodes: React.ReactNode[] = [];
  let lastPos = 0;
  let k = key;

  // 排序并合并重叠区间
  const sorted = [...highlights].sort((a, b) => a[0] - b[0]);
  const merged: Array<[number, number]> = [];
  for (const [s, e] of sorted) {
    if (merged.length > 0 && s <= merged[merged.length - 1][1]) {
      merged[merged.length - 1][1] = Math.max(merged[merged.length - 1][1], e);
    } else {
      merged.push([s, e]);
    }
  }

  for (const [start, end] of merged) {
    if (start > lastPos) {
      nodes.push(text.slice(lastPos, start));
    }
    // 高亮部分中跳过空格
    const hlText = text.slice(start, end);
    const hlNodes = highlightNonSpaces(hlText, k);
    k += hlNodes.filter(n => typeof n !== "string").length;
    nodes.push(...hlNodes);
    lastPos = end;
  }
  if (lastPos < text.length) {
    nodes.push(text.slice(lastPos));
  }

  return { nodes, nextKey: k };
}

/**
 * 对 hidden_content 文本做 hexdump 感知的跨行高亮。
 * 支持带空格 hex、无空格紧凑 hex、ASCII 文本三种搜索格式。
 * 非 hexdump 行 fallback 到普通 highlightText。
 */
export function highlightHexdump(
  text: string,
  query: string,
  caseSensitive: boolean,
  fuzzy: boolean = false,
): React.ReactNode {
  if (!text || !query) return text;

  const lines = text.split("\n");

  // Step 1: 解析所有行，分离 hexdump 行和普通行
  const parsed: Array<{ type: "hex"; data: HexdumpLine } | { type: "text"; line: string; lineIndex: number }> = [];
  const hexLines: HexdumpLine[] = [];

  for (let i = 0; i < lines.length; i++) {
    const hd = parseHexdumpLine(lines[i], i);
    if (hd) {
      parsed.push({ type: "hex", data: hd });
      hexLines.push(hd);
    } else {
      parsed.push({ type: "text", line: lines[i], lineIndex: i });
    }
  }

  // 如果没有 hexdump 行，全部走普通高亮
  if (hexLines.length === 0) {
    return highlightText(text, query, caseSensitive, fuzzy);
  }

  // Step 2: 构建 hex 流和 ASCII 流 + 映射
  // hexStream: "1f e0 da 48 ..."（各行 hex 用空格连接）
  // byteMap[i] = { lineIdx (在 hexLines 中的索引), localByteIdx (行内第几个字节) }
  const hexStreamParts: string[] = [];
  const byteMap: Array<{ lineIdx: number; localByteIdx: number }> = [];
  let asciiStream = "";
  const asciiMap: Array<{ lineIdx: number; localCharIdx: number }> = [];

  for (let li = 0; li < hexLines.length; li++) {
    const hl = hexLines[li];
    const bytes = hl.hexPart.split(/\s+/).filter(Boolean);
    for (let bi = 0; bi < bytes.length; bi++) {
      byteMap.push({ lineIdx: li, localByteIdx: bi });
    }
    hexStreamParts.push(bytes.join(" "));

    for (let ci = 0; ci < hl.asciiPart.length; ci++) {
      asciiMap.push({ lineIdx: li, localCharIdx: ci });
    }
    asciiStream += hl.asciiPart;
  }

  const hexStream = hexStreamParts.join(" ");

  // Step 3: 判断 query 类型并在对应流中匹配
  // 结果: 每个 hexLine 的 hex 区域和 ASCII 区域的高亮字符范围
  const hexHighlights: Map<number, Array<[number, number]>> = new Map();  // lineIdx → hex 区域 [start,end)
  const asciiHighlights: Map<number, Array<[number, number]>> = new Map();

  let matchQuery = query;
  let matchInHex = false;

  if (isSpacedHex(query)) {
    matchInHex = true;
    matchQuery = query;
  } else if (isCompactHex(query)) {
    matchInHex = true;
    matchQuery = compactToSpaced(query);
  }

  if (matchInHex) {
    // 在 hex 流中匹配
    const escaped = matchQuery.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const flags = caseSensitive ? "g" : "gi";
    let regex: RegExp;
    try {
      regex = new RegExp(escaped, flags);
    } catch {
      return highlightText(text, query, caseSensitive, fuzzy);
    }

    regex.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = regex.exec(hexStream)) !== null) {
      if (m[0].length === 0) { regex.lastIndex++; continue; }
      // 将 hex 流中的字符位置转换为字节索引
      // hex 流格式: "xx xx xx"，每个字节占 3 个字符（2 hex + 1 空格），最后一个占 2
      const startCharPos = m.index;
      const endCharPos = m.index + m[0].length;
      const startByteIdx = Math.floor(startCharPos / 3);
      const endByteIdx = Math.ceil(endCharPos / 3);

      // 映射每个字节回原始行
      for (let bi = startByteIdx; bi < endByteIdx && bi < byteMap.length; bi++) {
        const { lineIdx, localByteIdx } = byteMap[bi];
        const hl = hexLines[lineIdx];
        // 计算该字节在 hexPart 中的字符位置
        // 每个字节占 3 字符 "xx "，最后一个占 2
        const byteCharStart = localByteIdx * 3;
        const byteCharEnd = byteCharStart + 2;
        // 转为原始行中的绝对位置
        const absStart = hl.hexStart + byteCharStart;
        const absEnd = hl.hexStart + byteCharEnd;

        if (!hexHighlights.has(lineIdx)) hexHighlights.set(lineIdx, []);
        hexHighlights.get(lineIdx)!.push([absStart, absEnd]);
      }
    }
  } else {
    // 在 ASCII 流中匹配
    const escaped = query.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const flags = caseSensitive ? "g" : "gi";
    let regex: RegExp;
    try {
      regex = new RegExp(escaped, flags);
    } catch {
      return highlightText(text, query, caseSensitive, fuzzy);
    }

    regex.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = regex.exec(asciiStream)) !== null) {
      if (m[0].length === 0) { regex.lastIndex++; continue; }
      const startIdx = m.index;
      const endIdx = m.index + m[0].length;

      for (let ci = startIdx; ci < endIdx && ci < asciiMap.length; ci++) {
        const { lineIdx, localCharIdx } = asciiMap[ci];
        const hl = hexLines[lineIdx];
        const absPos = hl.asciiStart + localCharIdx;
        if (!asciiHighlights.has(lineIdx)) asciiHighlights.set(lineIdx, []);
        asciiHighlights.get(lineIdx)!.push([absPos, absPos + 1]);
      }
    }
  }

  // Step 4: 逐行渲染
  const resultNodes: React.ReactNode[] = [];
  let globalKey = 0;

  for (let pi = 0; pi < parsed.length; pi++) {
    if (pi > 0) resultNodes.push("\n");

    const item = parsed[pi];
    if (item.type === "text") {
      // 非 hexdump 行：普通高亮
      const highlighted = highlightText(item.line, query, caseSensitive, fuzzy);
      if (typeof highlighted === "string") {
        resultNodes.push(highlighted);
      } else {
        resultNodes.push(<React.Fragment key={`t${pi}`}>{highlighted}</React.Fragment>);
      }
    } else {
      // hexdump 行：应用跨行高亮映射
      const lineIdx = hexLines.indexOf(item.data);
      const hexHL = hexHighlights.get(lineIdx) ?? [];
      const ascHL = asciiHighlights.get(lineIdx) ?? [];
      const allHL = [...hexHL, ...ascHL];

      if (allHL.length === 0) {
        resultNodes.push(lines[item.data.lineIndex]);
      } else {
        const { nodes, nextKey } = renderLineWithHighlights(
          lines[item.data.lineIndex], allHL, globalKey
        );
        globalKey = nextKey;
        resultNodes.push(<React.Fragment key={`h${pi}`}>{nodes}</React.Fragment>);
      }
    }
  }

  return <>{resultNodes}</>;
}
```

- [ ] **Step 2: 验证编译**

Run: `cd src-web && npx tsc --noEmit 2>&1 | head -20`
Expected: 无错误

- [ ] **Step 3: Commit**

```bash
git add src-web/src/utils/highlightText.tsx
git commit -m "feat(ui): add highlightHexdump for cross-line hex/ASCII matching and highlighting"
```

---

### Task 3: SearchResultList 使用 highlightHexdump

**Files:**
- Modify: `src-web/src/components/SearchResultList.tsx`

- [ ] **Step 1: 新增 import**

在 SearchResultList.tsx 顶部，将现有的 import：
```tsx
import { highlightText } from "../utils/highlightText";
```
改为：
```tsx
import { highlightText, highlightHexdump } from "../utils/highlightText";
```

- [ ] **Step 2: 替换 hidden_content 的高亮调用**

找到第 349 行：
```tsx
{hl(match.hidden_content)}
```

替换为：
```tsx
{match.hidden_content
  ? highlightHexdump(match.hidden_content, searchQuery ?? "", caseSensitive ?? false, fuzzy ?? false)
  : ""}
```

- [ ] **Step 3: 验证编译**

Run: `cd src-web && npx tsc --noEmit 2>&1 | head -20`
Expected: 无错误

- [ ] **Step 4: 全量编译**

Run: `cargo build 2>&1 | tail -5`
Expected: 编译成功

- [ ] **Step 5: Commit**

```bash
git add src-web/src/components/SearchResultList.tsx
git commit -m "feat(ui): use highlightHexdump for hidden_content cross-line highlighting"
```
