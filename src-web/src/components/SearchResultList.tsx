import { useRef, useCallback, useEffect, useState, useMemo } from "react";
import { useVirtualizerNoSync } from "../hooks/useVirtualizerNoSync";
import type { SearchMatch, TraceLine } from "../types/trace";
import type { ResolvedRow } from "../hooks/useFoldState";
import DisasmHighlight from "./DisasmHighlight";
import Minimap, { MINIMAP_WIDTH } from "./Minimap";
import { useSelectedSeq } from "../stores/selectedSeqStore";
import CustomScrollbar from "./CustomScrollbar";
import { useResizableColumn } from "../hooks/useResizableColumn";
import { highlightText, highlightHexdump } from "../utils/highlightText";

const BASE_ROW_HEIGHT = 22;
const DETAIL_LINE_HEIGHT = 16;
const DETAIL_TOP_MARGIN = 4;
const DETAIL_BOTTOM_GAP = 6;
const DETAIL_VERTICAL_PADDING = 6;
const DETAIL_BORDER = 1;
const DETAIL_INDENT = 48 + 30 + 90 + 90;
const DETAIL_LEFT_PADDING = 8 + DETAIL_INDENT;
const DETAIL_MAX_LINES = 16; // hexdump 16 行 = 256 字节

function getDetailLineCount(text: string | null | undefined): number {
  if (!text) return 0;
  return text.split("\n").length;
}

function getRowHeight(match: SearchMatch | undefined): number {
  const lineCount = getDetailLineCount(match?.hidden_content);
  if (lineCount === 0) return BASE_ROW_HEIGHT;
  const cappedLines = Math.min(lineCount, DETAIL_MAX_LINES);
  return BASE_ROW_HEIGHT
    + DETAIL_TOP_MARGIN
    + DETAIL_BOTTOM_GAP
    + DETAIL_VERTICAL_PADDING * 2
    + DETAIL_BORDER * 2
    + cappedLines * DETAIL_LINE_HEIGHT;
}

function buildRowOffsets(results: SearchMatch[]): number[] {
  const offsets = new Array<number>(results.length);
  let acc = 0;
  for (let i = 0; i < results.length; i++) {
    offsets[i] = acc;
    acc += getRowHeight(results[i]);
  }
  return offsets;
}

function findRowIndexByOffset(offsets: number[], scrollTop: number): number {
  if (offsets.length === 0) return 0;
  let lo = 0;
  let hi = offsets.length - 1;
  while (lo < hi) {
    const mid = ((lo + hi + 1) / 2) | 0;
    if (offsets[mid] <= scrollTop) {
      lo = mid;
    } else {
      hi = mid - 1;
    }
  }
  return lo;
}

interface SearchResultListProps {
  results: SearchMatch[];
  selectedSeq?: number | null;
  onJumpToSeq: (seq: number) => void;
  onJumpToMatch?: (match: SearchMatch) => void;
  searchQuery?: string;
  caseSensitive?: boolean;
  fuzzy?: boolean;
  useRegex?: boolean;
}

export default function SearchResultList({
  results,
  selectedSeq: selectedSeqProp,
  onJumpToSeq,
  onJumpToMatch,
  searchQuery,
  caseSensitive,
  fuzzy,
  useRegex,
}: SearchResultListProps) {
  const rwCol = useResizableColumn(30, "right", 20, "search:rw");
  const seqCol = useResizableColumn(90, "right", 50, "search:seq");
  const addrCol = useResizableColumn(90, "right", 50, "search:addr");
  const changesCol = useResizableColumn(
    Math.min(300, Math.round(window.innerWidth * 0.2)), "left", 40, "search:changes"
  );

  const HANDLE_STYLE: React.CSSProperties = {
    width: 8, cursor: "col-resize", flexShrink: 0,
    display: "flex", alignItems: "center", justifyContent: "center",
  };

  const selectedSeqFromStore = useSelectedSeq();
  const selectedSeq = selectedSeqProp !== undefined ? selectedSeqProp : selectedSeqFromStore;

  const parentRef = useRef<HTMLDivElement>(null);
  const [selectedIdx, setSelectedIdx] = useState<number | null>(null);
  const [containerHeight, setContainerHeight] = useState(0);
  const [scrollRow, setScrollRow] = useState(0);

  const seqToIndex = useMemo(() => {
    const map = new Map<number, number>();
    results.forEach((result, index) => {
      if (!map.has(result.seq)) {
        map.set(result.seq, index);
      }
    });
    return map;
  }, [results]);

  const rowOffsets = useMemo(() => buildRowOffsets(results), [results]);

  useEffect(() => {
    if (selectedSeq == null) return;
    const idx = seqToIndex.get(selectedSeq);
    if (idx != null) {
      setSelectedIdx(idx);
      // 自动滚动到选中项可见位置
      const container = parentRef.current;
      if (container && rowOffsets[idx] !== undefined) {
        const rowTop = rowOffsets[idx];
        const rowHeight = getRowHeight(results[idx]);
        const scrollTop = container.scrollTop;
        const viewHeight = container.clientHeight;
        if (rowTop < scrollTop) {
          container.scrollTop = rowTop;
        } else if (rowTop + rowHeight > scrollTop + viewHeight) {
          container.scrollTop = rowTop + rowHeight - viewHeight;
        }
      }
    }
  }, [selectedSeq, seqToIndex, rowOffsets, results]);

  const virtualizer = useVirtualizerNoSync({
    count: results.length,
    getScrollElement: () => parentRef.current,
    estimateSize: (index) => getRowHeight(results[index]),
    overscan: 12,
  });

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
    const len = results.length;
    if (len === 0) return;
    const cur = selectedIdx ?? -1;
    const next = e.key === "ArrowDown" ? Math.min(cur + 1, len - 1) : Math.max(cur - 1, 0);
    const match = results[next];
    if (!match) return;
    setSelectedIdx(next);
    if (onJumpToMatch) {
      onJumpToMatch(match);
    } else {
      onJumpToSeq(match.seq);
    }
    virtualizer.scrollToIndex(next, { align: "auto" });
  }, [results, selectedIdx, onJumpToMatch, onJumpToSeq, virtualizer]);

  useEffect(() => {
    const el = parentRef.current;
    if (!el) return;
    const handleScroll = () => {
      setScrollRow(findRowIndexByOffset(rowOffsets, el.scrollTop));
    };
    let timer = 0;
    const ro = new ResizeObserver((entries) => {
      clearTimeout(timer);
      const h = entries[0].contentRect.height;
      timer = window.setTimeout(() => {
        setContainerHeight(h);
      }, document.documentElement.dataset.separatorDrag ? 300 : 0);
    });
    el.addEventListener("scroll", handleScroll);
    handleScroll();
    ro.observe(el);
    return () => {
      clearTimeout(timer);
      el.removeEventListener("scroll", handleScroll);
      ro.disconnect();
    };
  }, [results.length, rowOffsets]);

  const searchResolve = useCallback((vi: number): ResolvedRow => {
    return { type: "line", seq: results[vi]?.seq ?? vi } as ResolvedRow;
  }, [results]);

  const searchGetLines = useCallback(async (seqs: number[]): Promise<TraceLine[]> => {
    const seqSet = new Set(seqs);
    return results.filter(r => seqSet.has(r.seq)) as unknown as TraceLine[];
  }, [results]);

  const hl = useCallback((text: string | null | undefined) => {
    if (!text || !searchQuery) return text ?? "";
    return highlightText(text, searchQuery, caseSensitive ?? false, fuzzy ?? false, useRegex ?? false);
  }, [searchQuery, caseSensitive, fuzzy, useRegex]);

  const visibleRows = Math.max(1, Math.ceil(containerHeight / BASE_ROW_HEIGHT));
  const maxRow = Math.max(0, results.length - visibleRows);
  const virtualItems = virtualizer.getVirtualItems();

  return (
    <>
      <div style={{
        display: "flex",
        padding: "4px 8px",
        background: "var(--bg-secondary)",
        borderBottom: "1px solid var(--border-color)",
        fontSize: "var(--font-size-sm)",
        color: "var(--text-secondary)",
        flexShrink: 0,
      }}>
        <span style={{ width: 48, flexShrink: 0 }}></span>
        <span style={{ width: rwCol.width, flexShrink: 0 }}>R/W</span>
        <div onMouseDown={rwCol.onMouseDown} style={HANDLE_STYLE}><div style={{ width: 1, height: "100%", background: "var(--border-color)" }} /></div>
        <span style={{ width: seqCol.width, flexShrink: 0 }}>Seq</span>
        <div onMouseDown={seqCol.onMouseDown} style={HANDLE_STYLE}><div style={{ width: 1, height: "100%", background: "var(--border-color)" }} /></div>
        <span style={{ width: addrCol.width, flexShrink: 0 }}>Address</span>
        <div onMouseDown={addrCol.onMouseDown} style={HANDLE_STYLE}><div style={{ width: 1, height: "100%", background: "var(--border-color)" }} /></div>
        <span style={{ flex: 1 }}>Disassembly</span>
        <div onMouseDown={changesCol.onMouseDown} style={HANDLE_STYLE}><div style={{ width: 1, height: "100%", background: "var(--border-color)" }} /></div>
        <span style={{ width: changesCol.width, flexShrink: 0 }}>Changes</span>
        <span style={{ width: MINIMAP_WIDTH + 12, flexShrink: 0 }}></span>
      </div>

      <div style={{ flex: 1, display: "flex", overflow: "hidden" }}>
        <div
          ref={parentRef}
          tabIndex={0}
          onKeyDown={handleKeyDown}
          style={{
            flex: 1,
            overflow: "auto",
            outline: "none",
            scrollbarWidth: "none",
            fontSize: "var(--font-size-sm)",
          }}
        >
          <div style={{ height: virtualizer.getTotalSize(), width: "100%", position: "relative" }}>
            {virtualItems.map((vRow) => {
              const match = results[vRow.index];
              if (!match) return null;
              const isSelected = selectedIdx === vRow.index;
              const baseBg = isSelected
                ? "var(--bg-selected)"
                : vRow.index % 2 === 0 ? "var(--bg-row-even)" : "var(--bg-row-odd)";

              return (
                <div
                  key={vRow.index}
                  onClick={() => jumpToMatch(match, vRow.index)}
                  style={{
                    position: "absolute",
                    top: 0,
                    left: 0,
                    width: "100%",
                    height: vRow.size,
                    transform: `translateY(${vRow.start}px)`,
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
                    <span style={{ width: 48, flexShrink: 0 }}></span>
                    <span style={{ width: rwCol.width, flexShrink: 0, color: "var(--text-secondary)" }}>
                      {hl(match.mem_rw === "W" ? "W" : match.mem_rw === "R" ? "R" : "")}
                    </span>
                    <span style={{ width: 8, flexShrink: 0 }} />
                    <span style={{ width: seqCol.width, flexShrink: 0, color: "var(--text-secondary)" }}>{match.seq + 1}</span>
                    <span style={{ width: 8, flexShrink: 0 }} />
                    <span style={{ width: addrCol.width, flexShrink: 0, color: "var(--text-address)" }}>{hl(match.address)}</span>
                    <span style={{ width: 8, flexShrink: 0 }} />
                    <span style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
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
                    <span style={{ width: 8, flexShrink: 0 }} />
                    <span
                      style={{
                        width: changesCol.width,
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
                      <div style={{
                        border: "1px solid rgba(255,255,255,0.08)",
                        background: "rgba(255,255,255,0.03)",
                        borderRadius: 6,
                        padding: `${DETAIL_VERTICAL_PADDING}px 8px`,
                        color: "var(--text-secondary)",
                        fontFamily: "var(--font-mono)",
                        fontSize: 11,
                        lineHeight: `${DETAIL_LINE_HEIGHT}px`,
                        whiteSpace: "pre",
                        overflowX: "auto",
                        overflowY: "auto",
                        maxHeight: DETAIL_MAX_LINES * DETAIL_LINE_HEIGHT + DETAIL_VERTICAL_PADDING * 2,
                        boxShadow: "inset 0 1px 0 rgba(255,255,255,0.03)",
                      }}>
                        {match.hidden_content
                          ? highlightHexdump(match.hidden_content, searchQuery ?? "", caseSensitive ?? false, fuzzy ?? false, useRegex ?? false)
                          : ""}
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
        {containerHeight > 0 && (
          <div style={{ width: MINIMAP_WIDTH + 12, flexShrink: 0, position: "relative" }}>
            <Minimap
              virtualTotalRows={results.length}
              visibleRows={visibleRows}
              currentRow={scrollRow}
              maxRow={maxRow}
              height={containerHeight}
              onScroll={(row) => {
                parentRef.current?.scrollTo({ top: rowOffsets[row] ?? 0 });
              }}
              resolveVirtualIndex={searchResolve}
              getLines={searchGetLines}
              selectedSeq={selectedSeq}
              rightOffset={12}
              showSoName={false}
              showAbsAddress={false}
            />
            <CustomScrollbar
              currentRow={scrollRow}
              maxRow={maxRow}
              visibleRows={visibleRows}
              virtualTotalRows={results.length}
              trackHeight={containerHeight}
              onScroll={(row) => {
                parentRef.current?.scrollTo({ top: rowOffsets[row] ?? 0 });
              }}
            />
          </div>
        )}
      </div>
    </>
  );
}
