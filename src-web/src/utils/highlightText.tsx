import React from "react";

const MARK_STYLE: React.CSSProperties = {
  background: "transparent",
  color: "rgba(255,210,0,1)",
  borderRadius: 0,
  padding: 0,
};

/**
 * 将匹配片段中的非空格字符用 <mark> 高亮，空格保持原样。
 */
function highlightNonSpaces(matched: string, keyStart: number): React.ReactNode[] {
  const result: React.ReactNode[] = [];
  let k = keyStart;
  // 按空格/非空格交替拆分
  const segments = matched.split(/( +)/);
  for (const seg of segments) {
    if (!seg) continue;
    if (/^ +$/.test(seg)) {
      result.push(seg);
    } else {
      result.push(<mark key={k++} style={MARK_STYLE}>{seg}</mark>);
    }
  }
  return result;
}

/**
 * 将文本中匹配 query 的子串高亮（字体颜色变黄）。
 * fuzzy=false（默认）：含空格的 query 作为整体匹配，空格本身不高亮。
 * fuzzy=true：按空格拆分为多个关键词，每个独立高亮。
 * 支持普通文本和 /regex/ 模式。
 * 无匹配时返回原始字符串。
 */
export function highlightText(
  text: string,
  query: string,
  caseSensitive: boolean = false,
  fuzzy: boolean = false,
  useRegex: boolean = false,
): React.ReactNode {
  if (!text || !query) return text;

  // 构建匹配正则
  let regex: RegExp;
  try {
    if (query.startsWith("/") && query.endsWith("/") && query.length > 2) {
      // /regex/ 包裹模式
      const pattern = query.slice(1, -1);
      regex = new RegExp(pattern, caseSensitive ? "g" : "gi");
    } else if (useRegex) {
      // 正则 toggle 开启：query 直接作为正则
      regex = new RegExp(query, caseSensitive ? "g" : "gi");
    } else if (fuzzy && query.includes(" ")) {
      // 模糊匹配：空格分隔多关键词，每个独立高亮
      const tokens = query.split(/\s+/).filter(Boolean);
      if (tokens.length === 0) return text;
      const escaped = tokens.map(t => t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
      regex = new RegExp(`(${escaped.join("|")})`, caseSensitive ? "g" : "gi");
    } else {
      // 普通文本匹配（含空格时作为整体匹配）
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
    // 高亮匹配部分，但跳过空格
    const highlighted = highlightNonSpaces(match[0], key);
    key += highlighted.filter(n => typeof n !== "string").length;
    parts.push(...highlighted);
    lastIndex = regex.lastIndex;
  }

  if (parts.length === 0) return text;
  if (lastIndex < text.length) {
    parts.push(text.slice(lastIndex));
  }
  return <>{parts}</>;
}

// ── Hexdump 跨行高亮 ──

/** hexdump 行解析结果 */
interface HexdumpLine {
  lineIndex: number;
  prefix: string;
  hexPart: string;
  hexStart: number;
  asciiPart: string;
  asciiStart: number;
  separator: string;
  suffix: string;
  byteCount: number;
}

function isSpacedHex(q: string): boolean {
  return /^[0-9a-f]{2}( [0-9a-f]{2})+$/i.test(q);
}

function isCompactHex(q: string): boolean {
  return q.length >= 4 && q.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(q);
}

function compactToSpaced(q: string): string {
  const pairs: string[] = [];
  for (let i = 0; i < q.length; i += 2) {
    pairs.push(q.slice(i, i + 2));
  }
  return pairs.join(" ");
}

function parseHexdumpLine(line: string, lineIndex: number): HexdumpLine | null {
  const match = /^([0-9a-fA-F]+:\s)(.+?)\s*\|(.+)\|$/.exec(line);
  if (!match) return null;
  const prefix = match[1];
  const hexPart = match[2].trim();
  const asciiPart = match[3];
  const hexStart = prefix.length;
  const pipePos = line.indexOf("|", hexStart);
  const asciiStart = pipePos >= 0 ? pipePos + 1 : 0;
  const byteCount = hexPart.split(/\s+/).filter(Boolean).length;
  return { lineIndex, prefix, hexPart, hexStart, asciiPart, asciiStart, separator: " |", suffix: "|", byteCount };
}

function renderLineWithHighlights(
  text: string,
  highlights: Array<[number, number]>,
  key: number,
): { nodes: React.ReactNode[]; nextKey: number } {
  if (highlights.length === 0) {
    return { nodes: [text], nextKey: key };
  }
  const nodes: React.ReactNode[] = [];
  let lastPos = 0;
  let k = key;
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

export function highlightHexdump(
  text: string,
  query: string,
  caseSensitive: boolean,
  fuzzy: boolean = false,
  useRegex: boolean = false,
): React.ReactNode {
  if (!text || !query) return text;

  const lines = text.split("\n");
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

  if (hexLines.length === 0) {
    return highlightText(text, query, caseSensitive, fuzzy, useRegex);
  }

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
  const hexHighlights: Map<number, Array<[number, number]>> = new Map();
  const asciiHighlights: Map<number, Array<[number, number]>> = new Map();

  // 正则模式或 /pattern/ 模式：每行独立做正则高亮，不走 hex/ASCII 流跨行匹配
  if (useRegex || (query.startsWith("/") && query.endsWith("/") && query.length > 2)) {
    const resultNodes: React.ReactNode[] = [];
    for (let pi = 0; pi < parsed.length; pi++) {
      if (pi > 0) resultNodes.push("\n");
      const item = parsed[pi];
      const line = item.type === "text" ? item.line : lines[item.data.lineIndex];
      const highlighted = highlightText(line, query, caseSensitive, fuzzy, useRegex);
      if (typeof highlighted === "string") {
        resultNodes.push(highlighted);
      } else {
        resultNodes.push(<React.Fragment key={`r${pi}`}>{highlighted}</React.Fragment>);
      }
    }
    return <>{resultNodes}</>;
  }

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
    const escaped = matchQuery.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const flags = caseSensitive ? "g" : "gi";
    let regex: RegExp;
    try { regex = new RegExp(escaped, flags); } catch { return highlightText(text, query, caseSensitive, fuzzy, useRegex); }

    regex.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = regex.exec(hexStream)) !== null) {
      if (m[0].length === 0) { regex.lastIndex++; continue; }
      const startCharPos = m.index;
      const endCharPos = m.index + m[0].length;
      const startByteIdx = Math.floor(startCharPos / 3);
      const endByteIdx = Math.ceil(endCharPos / 3);

      for (let bi = startByteIdx; bi < endByteIdx && bi < byteMap.length; bi++) {
        const { lineIdx, localByteIdx } = byteMap[bi];
        const hl = hexLines[lineIdx];
        const byteCharStart = localByteIdx * 3;
        const byteCharEnd = byteCharStart + 2;
        const absStart = hl.hexStart + byteCharStart;
        const absEnd = hl.hexStart + byteCharEnd;
        if (!hexHighlights.has(lineIdx)) hexHighlights.set(lineIdx, []);
        hexHighlights.get(lineIdx)!.push([absStart, absEnd]);
      }
    }
  } else {
    const escaped = query.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const flags = caseSensitive ? "g" : "gi";
    let regex: RegExp;
    try { regex = new RegExp(escaped, flags); } catch { return highlightText(text, query, caseSensitive, fuzzy, useRegex); }

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

  const resultNodes: React.ReactNode[] = [];
  let globalKey = 0;

  for (let pi = 0; pi < parsed.length; pi++) {
    if (pi > 0) resultNodes.push("\n");
    const item = parsed[pi];
    if (item.type === "text") {
      const highlighted = highlightText(item.line, query, caseSensitive, fuzzy);
      if (typeof highlighted === "string") {
        resultNodes.push(highlighted);
      } else {
        resultNodes.push(<React.Fragment key={`t${pi}`}>{highlighted}</React.Fragment>);
      }
    } else {
      const lineIdx = hexLines.indexOf(item.data);
      const hexHL = hexHighlights.get(lineIdx) ?? [];
      const ascHL = asciiHighlights.get(lineIdx) ?? [];
      const allHL = [...hexHL, ...ascHL];
      if (allHL.length === 0) {
        resultNodes.push(lines[item.data.lineIndex]);
      } else {
        const { nodes, nextKey } = renderLineWithHighlights(lines[item.data.lineIndex], allHL, globalKey);
        globalKey = nextKey;
        resultNodes.push(<React.Fragment key={`h${pi}`}>{nodes}</React.Fragment>);
      }
    }
  }

  return <>{resultNodes}</>;
}
