import { useRef, useCallback, useEffect, useState, useMemo } from "react";
import type { SearchMatch, TraceLine } from "../types/trace";
import type { ResolvedRow } from "../hooks/useFoldState";
import DisasmHighlight from "./DisasmHighlight";
import Minimap, { MINIMAP_WIDTH } from "./Minimap";
import { useSelectedSeq } from "../stores/selectedSeqStore";
import CustomScrollbar from "./CustomScrollbar";
import { useResizableColumn } from "../hooks/useResizableColumn";
import { highlightText, highlightHexdump } from "../utils/highlightText";
import VirtualizedHighlight from "./VirtualizedHighlight";
import { useVirtualScroll } from "../hooks/useVirtualScroll";

const BASE_ROW_HEIGHT = 22;
const DETAIL_LINE_HEIGHT = 16;
const DETAIL_TOP_MARGIN = 4;
const DETAIL_BOTTOM_GAP = 6;
const DETAIL_VERTICAL_PADDING = 6;
const DETAIL_BORDER = 1;
const DETAIL_INDENT = 40 + 30 + 90 + 90;
const DETAIL_LEFT_PADDING = 8 + DETAIL_INDENT;
const DETAIL_MAX_LINES = 16; // hexdump 16 行 = 256 字节
const OVERSCAN = 12;
const WHEEL_SPEED = 3;

/** 检测 hidden_content 是否含有 hexdump 数据行 */
function isHexdumpContent(text: string): boolean {
  return /^[0-9a-fA-F]+:\s+([0-9a-fA-F]{2}\s)/m.test(text);
}

/** 预计算 hidden_content 行的详情区域高度 */
function calcDetailHeight(text: string): number {
  const lines = text.split("\n").length;
  return DETAIL_TOP_MARGIN + Math.min(lines, DETAIL_MAX_LINES) * DETAIL_LINE_HEIGHT + DETAIL_VERTICAL_PADDING * 2 + DETAIL_BOTTOM_GAP;
}

interface SearchResultListProps {
  /** 搜索结果总数 */
  totalCount: number;
  /** 获取指定索引的 seq（分页模式，未加载返回 undefined 并触发加载） */
  getSeqAtIndex: (index: number) => number | undefined;
  /** 确保指定索引范围的页已加载 */
  ensureRange?: (startIndex: number, endIndex: number) => void;
  getMatchDetail: (seq: number) => SearchMatch | undefined;
  selectedSeq?: number | null;
  onJumpToSeq: (seq: number) => void;
  onJumpToMatch?: (match: SearchMatch) => void;
  searchQuery?: string;
  caseSensitive?: boolean;
  fuzzy?: boolean;
  useRegex?: boolean;
  showSoName?: boolean;
  showAbsAddress?: boolean;
  addrColorHighlight?: boolean;
  requestDetails?: (seqs: number[]) => void;
  cacheVersion?: number;
  /** 页加载版本号，变更时触发重渲染 */
  pageVersion?: number;
  /** 查找 seq 在搜索结果中的索引 */
  findSeqIndex?: (seq: number) => number;
}

export default function SearchResultList({
  totalCount,
  getSeqAtIndex,
  ensureRange,
  getMatchDetail,
  selectedSeq: selectedSeqProp,
  onJumpToSeq,
  onJumpToMatch,
  searchQuery,
  caseSensitive,
  fuzzy,
  useRegex,
  showSoName = false,
  showAbsAddress = false,
  addrColorHighlight = false,
  requestDetails,
  cacheVersion = 0,
  pageVersion = 0,
  findSeqIndex,
}: SearchResultListProps) {
  const rwCol = useResizableColumn(30, "right", 20, "search:rw");
  const seqCol = useResizableColumn(90, "right", 50, "search:seq");
  const addrCol = useResizableColumn(90, "right", 50, "search:addr");
  const disasmCol = useResizableColumn(320, "right", 200);
  const beforeCol = useResizableColumn(420, "right", 40);
  const HANDLE_W = 8;

  const [addrWidthEstimated, setAddrWidthEstimated] = useState(false);
  useEffect(() => { setAddrWidthEstimated(false); }, [totalCount]);

  const formatAddr = useCallback((match: SearchMatch) => {
    const parts: string[] = [];
    if (showSoName && match.so_name) parts.push(`[${match.so_name}]`);
    if (showAbsAddress && match.address) {
      parts.push(`${match.address}!${match.so_offset}`);
    } else {
      parts.push(match.so_offset || match.address);
    }
    return parts.join(" ");
  }, [showSoName, showAbsAddress]);

  const HANDLE_STYLE: React.CSSProperties = {
    width: 8, cursor: "col-resize", flexShrink: 0, alignSelf: "stretch",
    display: "flex", alignItems: "center", justifyContent: "center",
  };

  const selectedSeqFromStore = useSelectedSeq();
  const selectedSeq = selectedSeqProp !== undefined ? selectedSeqProp : selectedSeqFromStore;

  const vs = useVirtualScroll({ totalCount, rowHeight: BASE_ROW_HEIGHT, overscan: OVERSCAN, wheelSpeed: WHEEL_SPEED });
  const { currentRow: clampedRow, visibleRows, maxRow, startIdx, endIdx, scrollToRow, containerRef: parentRef, containerHeight, containerWidth, containerStyle: vsContainerStyle } = vs;

  const [selectedIdx, setSelectedIdx] = useState<number | null>(null);

  const colFixedLeft = 40 + rwCol.width + HANDLE_W + seqCol.width + HANDLE_W + addrCol.width + HANDLE_W;
  const MIN_CHANGES_WIDTH = 60;
  const availableForRight = Math.max(0, containerWidth - colFixedLeft - 2 * HANDLE_W - MIN_CHANGES_WIDTH);
  const effectiveDisasmWidth = Math.max(200, Math.min(disasmCol.width, availableForRight - 40));
  const effectiveBeforeWidth = Math.max(40, Math.min(beforeCol.width, availableForRight - effectiveDisasmWidth));

  // ── selectedSeq 同步 ──
  useEffect(() => {
    if (selectedSeq == null) return;
    if (findSeqIndex) {
      const idx = findSeqIndex(selectedSeq);
      if (idx >= 0) {
        setSelectedIdx(idx);
        scrollToRow(Math.max(0, idx - Math.floor(visibleRows / 2)));
      }
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedSeq]);

  const virtualItems = useMemo(() => {
    if (totalCount === 0 || containerHeight === 0) return [];
    const items: { index: number; y: number }[] = [];
    let y = (startIdx - clampedRow) * BASE_ROW_HEIGHT;
    for (let i = startIdx; i <= endIdx; i++) {
      items.push({ index: i, y });
      // hidden_content 行需要额外高度
      const seq = getSeqAtIndex(i);
      const match = seq !== undefined ? getMatchDetail(seq) : undefined;
      const h = match?.hidden_content ? BASE_ROW_HEIGHT + calcDetailHeight(match.hidden_content) : BASE_ROW_HEIGHT;
      y += h;
    }
    return items;
  }, [startIdx, endIdx, clampedRow, totalCount, containerHeight, getSeqAtIndex, getMatchDetail, pageVersion, cacheVersion]);

  const jumpToMatch = useCallback((match: SearchMatch, idx: number) => {
    setSelectedIdx(idx);
    if (onJumpToMatch) {
      onJumpToMatch(match);
      return;
    }
    onJumpToSeq(match.seq);
  }, [onJumpToMatch, onJumpToSeq]);

  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key !== "ArrowUp" && e.key !== "ArrowDown") return;
    e.preventDefault();
    if (totalCount === 0) return;
    const cur = selectedIdx ?? -1;
    const next = e.key === "ArrowDown" ? Math.min(cur + 1, totalCount - 1) : Math.max(cur - 1, 0);
    const seq = getSeqAtIndex(next);
    if (seq === undefined) return;
    setSelectedIdx(next);
    const match = getMatchDetail(seq);
    if (match && onJumpToMatch) {
      onJumpToMatch(match);
    } else {
      onJumpToSeq(seq);
    }
    // 保持选中行在可视区域内
    if (next < clampedRow) scrollToRow(next);
    else if (next >= clampedRow + visibleRows) scrollToRow(next - visibleRows + 1);
  }, [totalCount, selectedIdx, onJumpToMatch, onJumpToSeq, getMatchDetail, getSeqAtIndex, clampedRow, visibleRows, scrollToRow]);

  // ── Minimap / Scrollbar 回调 ──
  const handleScrollbarScroll = useCallback((row: number) => {
    scrollToRow(row);
  }, [scrollToRow]);

  const searchResolve = useCallback((vi: number): ResolvedRow => {
    return { type: "line", seq: getSeqAtIndex(vi) ?? vi } as ResolvedRow;
  }, [getSeqAtIndex, pageVersion]);

  const searchGetLines = useCallback(async (seqs: number[]): Promise<TraceLine[]> => {
    const seqSet = new Set(seqs);
    const lines: TraceLine[] = [];
    const missing: number[] = [];
    for (const seq of seqSet) {
      const match = getMatchDetail(seq);
      if (match) lines.push(match as unknown as TraceLine);
      else missing.push(seq);
    }
    if (missing.length > 0 && requestDetails) {
      requestDetails(missing);
    }
    return lines;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [getMatchDetail, requestDetails, cacheVersion]);

  const hl = useCallback((text: string | null | undefined) => {
    if (!text || !searchQuery) return text ?? "";
    return highlightText(text, searchQuery, caseSensitive ?? false, fuzzy ?? false, useRegex ?? false);
  }, [searchQuery, caseSensitive, fuzzy, useRegex]);

  // ── 地址列宽度自适应 ──
  useEffect(() => {
    if (addrWidthEstimated) return;
    const CHAR_W = 7.2;
    const PAD = 16;
    let maxLen = 0;
    for (const vi of virtualItems) {
      const seq = getSeqAtIndex(vi.index);
      if (seq === undefined) continue;
      const match = getMatchDetail(seq);
      if (!match) continue;
      let len = (match.so_offset || match.address || "").length;
      if (showSoName && match.so_name) len += match.so_name.length + 3;
      if (showAbsAddress && match.address) len += match.address.length + 1;
      if (len > maxLen) maxLen = len;
    }
    if (maxLen > 0) {
      const estimated = Math.max(90, Math.ceil(maxLen * CHAR_W + PAD));
      addrCol.setWidth(estimated);
      setAddrWidthEstimated(true);
    }
  }, [virtualItems, showSoName, showAbsAddress, addrWidthEstimated, getSeqAtIndex, getMatchDetail, pageVersion]);

  // ── 分页加载 + 详情加载触发 ──
  const visibleRange = useMemo(() => `${startIdx}-${endIdx}`, [startIdx, endIdx]);

  useEffect(() => {
    if (totalCount === 0) return;
    ensureRange?.(startIdx, endIdx);
    if (requestDetails) {
      const visibleSeqs: number[] = [];
      for (let i = startIdx; i <= endIdx; i++) {
        const s = getSeqAtIndex(i);
        if (s !== undefined) visibleSeqs.push(s);
      }
      if (visibleSeqs.length > 0) requestDetails(visibleSeqs);
    }
  }, [visibleRange, totalCount, requestDetails, pageVersion]);

  return (
    <>
      <div style={{
        display: "flex",
        alignItems: "center",
        padding: "4px 8px",
        background: "var(--bg-secondary)",
        borderBottom: "1px solid var(--border-color)",
        fontSize: "var(--font-size-sm)",
        color: "var(--text-secondary)",
        flexShrink: 0,
      }}>
        <span style={{ width: 40, flexShrink: 0 }}></span>
        <span style={{ width: rwCol.width, flexShrink: 0 }}>R/W</span>
        <div onMouseDown={rwCol.onMouseDown} style={HANDLE_STYLE}><div style={{ width: 1, height: "100%", background: "var(--border-color)" }} /></div>
        <span style={{ width: seqCol.width, flexShrink: 0 }}>Seq</span>
        <div onMouseDown={seqCol.onMouseDown} style={HANDLE_STYLE}><div style={{ width: 1, height: "100%", background: "var(--border-color)" }} /></div>
        <span style={{ width: addrCol.width, flexShrink: 0 }}>Address</span>
        <div onMouseDown={addrCol.onMouseDown} style={HANDLE_STYLE}><div style={{ width: 1, height: "100%", background: "var(--border-color)" }} /></div>
        <span style={{ width: effectiveDisasmWidth, flexShrink: 0 }}>Disassembly</span>
        <div onMouseDown={disasmCol.onMouseDown} style={HANDLE_STYLE}><div style={{ width: 1, height: "100%", background: "var(--border-color)" }} /></div>
        <span style={{ width: effectiveBeforeWidth, flexShrink: 0 }}>Before</span>
        <div onMouseDown={beforeCol.onMouseDown} style={HANDLE_STYLE}><div style={{ width: 1, height: "100%", background: "var(--border-color)" }} /></div>
        <span style={{ flex: 1 }}>Changes</span>
        <span style={{ width: MINIMAP_WIDTH + 12, flexShrink: 0 }}></span>
      </div>

      <div style={{ flex: 1, display: "flex", overflow: "hidden" }}>
        <div
          ref={parentRef}
          tabIndex={0}
          onKeyDown={handleKeyDown}
          style={{
            flex: 1,
            ...vsContainerStyle,
            outline: "none",
            fontSize: "var(--font-size-sm)",
          }}
        >
          {virtualItems.map((vRow) => {
            const seq = getSeqAtIndex(vRow.index);
            const match = seq !== undefined ? getMatchDetail(seq) : undefined;
            const isSelected = selectedIdx === vRow.index;
            const baseBg = isSelected
              ? "var(--bg-selected)"
              : vRow.index % 2 === 0 ? "var(--bg-row-even)" : "var(--bg-row-odd)";

            if (seq === undefined || !match) {
              return (
                <div
                  key={vRow.index}
                  onClick={() => { if (seq !== undefined) onJumpToSeq(seq); }}
                  style={{
                    position: "absolute", top: 0, left: 0, width: "100%",
                    height: BASE_ROW_HEIGHT,
                    transform: `translateY(${vRow.y}px)`,
                    background: baseBg,
                    display: "flex", alignItems: "center", padding: "0 8px",
                    cursor: seq !== undefined ? "pointer" : "default",
                  }}
                >
                  <span style={{ width: 40, flexShrink: 0 }} />
                  <span style={{ color: "var(--text-disabled, #555)", fontSize: "var(--font-size-sm)" }}>
                    {seq !== undefined ? `#${seq + 1}` : "Loading..."}
                  </span>
                </div>
              );
            }

            return (
              <div
                key={vRow.index}
                onClick={() => jumpToMatch(match, vRow.index)}
                style={{
                  position: "absolute",
                  top: 0,
                  left: 0,
                  width: "100%",
                  transform: `translateY(${vRow.y}px)`,
                  cursor: "pointer",
                  fontSize: "var(--font-size-sm)",
                  background: baseBg,
                  boxSizing: "border-box",
                }}
                onMouseEnter={(e) => {
                  if (!isSelected) {
                    e.currentTarget.style.background = "rgba(255,255,255,0.04)";
                  }
                }}
                onMouseLeave={(e) => {
                  if (!isSelected) {
                    e.currentTarget.style.background = vRow.index % 2 === 0
                      ? "var(--bg-row-even)"
                      : "var(--bg-row-odd)";
                  }
                }}
              >
                <div style={{
                  height: BASE_ROW_HEIGHT,
                  display: "flex",
                  alignItems: "center",
                  padding: "0 8px",
                }}>
                  <span style={{ width: 40, flexShrink: 0 }}></span>
                  <span style={{ width: rwCol.width, flexShrink: 0, color: "var(--text-secondary)" }}>
                    {hl(match.mem_rw === "W" || match.mem_rw === "R" ? match.mem_rw : "")}
                  </span>
                  <span style={{ width: HANDLE_W, flexShrink: 0 }} />
                  <span style={{ width: seqCol.width, flexShrink: 0, color: "var(--text-secondary)" }}>{match.seq + 1}</span>
                  <span style={{ width: HANDLE_W, flexShrink: 0 }} />
                  <span style={{
                    width: addrCol.width, flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                    color: addrColorHighlight ? "var(--text-address)" : "var(--text-secondary)",
                  }}>
                    {addrColorHighlight && showSoName && match.so_name ? (
                      <>
                        <span style={{ color: "var(--text-so-name)" }}>[{match.so_name}] </span>
                        {showAbsAddress && match.address ? (
                          <><span style={{ color: "var(--text-abs-address)" }}>{match.address}</span>!{match.so_offset}</>
                        ) : (match.so_offset || match.address)}
                      </>
                    ) : hl(formatAddr(match))}
                  </span>
                  <span style={{ width: HANDLE_W, flexShrink: 0 }} />
                  <span style={{ width: effectiveDisasmWidth, flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    <DisasmHighlight text={match.disasm} highlightQuery={searchQuery} caseSensitive={caseSensitive} fuzzy={fuzzy} useRegex={useRegex} />
                    {match.call_info && (
                      <span
                        style={{
                          marginLeft: 8,
                          fontStyle: "italic",
                          color: match.call_info.is_jni ? "var(--call-info-jni)" : "var(--call-info-normal)",
                        }}
                        title={match.call_info.tooltip}
                      >
                        {hl(match.call_info.summary.length > 80
                          ? match.call_info.summary.slice(0, 80) + "..."
                          : match.call_info.summary)}
                      </span>
                    )}
                  </span>
                  <span style={{ width: HANDLE_W, flexShrink: 0 }} />
                  <span
                    style={{
                      width: effectiveBeforeWidth, flexShrink: 0,
                      color: "var(--text-secondary)",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    }}
                  >
                    {hl(match.reg_before)}
                  </span>
                  <span style={{ width: HANDLE_W, flexShrink: 0 }} />
                  <span
                    style={{
                      flex: 1,
                      color: "var(--text-changes)",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    }}
                  >
                    {hl(match.changes)}
                  </span>
                </div>

                {match.hidden_content && (
                  <div style={{
                    padding: `${DETAIL_TOP_MARGIN}px 8px ${DETAIL_BOTTOM_GAP}px ${8 + 48 + rwCol.width + 8 + seqCol.width + 8 + addrCol.width + 8}px`,
                  }}>
                    <VirtualizedHighlight
                      text={match.hidden_content}
                      query={searchQuery ?? ""}
                      caseSensitive={caseSensitive ?? false}
                      fuzzy={fuzzy ?? false}
                      useRegex={useRegex ?? false}
                      isHex={isHexdumpContent(match.hidden_content)}
                      lineHeight={DETAIL_LINE_HEIGHT}
                      maxVisibleLines={DETAIL_MAX_LINES}
                      verticalPadding={DETAIL_VERTICAL_PADDING}
                    />
                  </div>
                )}
              </div>
            );
          })}
        </div>
        {containerHeight > 0 && (
          <div style={{ width: MINIMAP_WIDTH + 12, flexShrink: 0, position: "relative" }}>
            <Minimap
              virtualTotalRows={totalCount}
              visibleRows={visibleRows}
              currentRow={clampedRow}
              maxRow={maxRow}
              height={containerHeight}
              onScroll={handleScrollbarScroll}
              resolveVirtualIndex={searchResolve}
              getLines={searchGetLines}
              selectedSeq={selectedSeq}
              rightOffset={12}
              showSoName={showSoName}
              showAbsAddress={showAbsAddress}
            />
            <CustomScrollbar
              currentRow={clampedRow}
              maxRow={maxRow}
              visibleRows={visibleRows}
              virtualTotalRows={totalCount}
              trackHeight={containerHeight}
              onScroll={handleScrollbarScroll}
            />
          </div>
        )}
      </div>
    </>
  );
}
