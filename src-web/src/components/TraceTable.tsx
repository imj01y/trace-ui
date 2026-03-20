import React, { useRef, useEffect, useLayoutEffect, useState, useCallback, useMemo } from "react";
import { createPortal } from "react-dom";
import { invoke } from "@tauri-apps/api/core";
import { emitTo, listen } from "@tauri-apps/api/event";
import { WebviewWindow } from "@tauri-apps/api/webviewWindow";
import type { TraceLine, CallTreeNodeDto, DefUseChain } from "../types/trace";
import type { HighlightInfo } from "../hooks/useHighlights";
import { useResizableColumn } from "../hooks/useResizableColumn";
import type { useFoldState, ResolvedRow } from "../hooks/useFoldState";
import CustomScrollbar from "./CustomScrollbar";
import Minimap, { MINIMAP_WIDTH } from "./Minimap";
import { getSharedColors, getTraceTableColors } from "../utils/canvasColors";
import { HIGHLIGHT_COLORS } from "../utils/highlightColors";
import ContextMenu, { ContextMenuItem, ContextMenuSeparator } from "./ContextMenu";
import { MenuDropdown, MenuItem } from "./MenuDropdown";
import { useSelectedSeq } from "../stores/selectedSeqStore";
import { useThemeId } from "../stores/themeStore";
import type { Preferences } from "../hooks/usePreferences";

const ROW_HEIGHT = 22;
const ARROW_COL_WIDTH = 20;

// 合并共用颜色和 TraceTable 特有颜色——每次访问动态获取当前主题颜色
function getCOLORS() { return { ...getSharedColors(), ...getTraceTableColors() }; }
type ColorsType = ReturnType<typeof getCOLORS>;
let COLORS: ColorsType = getCOLORS();

const FONT = '12px "JetBrains Mono", "Fira Code", "Cascadia Code", "Consolas", monospace';
const FONT_ITALIC = 'italic 12px "JetBrains Mono", "Fira Code", "Cascadia Code", "Consolas", monospace';
const TEXT_BASELINE_Y = 15;

// 列位置常量（padding 8px）
const COL_PAD = 8;
const COL_ARROW = COL_PAD;          // 8
const COL_FOLD = COL_ARROW + ARROW_COL_WIDTH; // 28
const COL_MEMRW = COL_FOLD + 28;    // 56
const COL_SEQ = COL_MEMRW + 30;     // 86
const DEFAULT_SEQ_WIDTH = 90;
const DEFAULT_ADDR_WIDTH = 90;
const COMMENT_OFFSET = 240; // disasm 开始后的注释列偏移

// 箭头常量
const DOT_X = 16;
const CONN_X = 12;
const VERT_X_DEF = 2;
const VERT_X_USE = 2;
const BEND_R = 4;
const ANCHOR_GAP = 3;
const EDGE_LABEL_PAD = 20;  // 边缘标签区域高度（标签 + 呼吸空间）
const RIGHT_GUTTER = MINIMAP_WIDTH + 12; // minimap(70) + scrollbar(12) = 82

// Tokenizer（共用 ARM64 token 正则）
import { REG_RE, SHIFT_RE, IMM_RE, BRACKET_RE, TOKEN_RE } from "../utils/arm64Tokens";

function canvasTokenColor(token: string, isFirst: boolean): string {
  if (isFirst) return COLORS.asmMnemonic;
  if (BRACKET_RE.test(token)) return COLORS.asmMemory;
  if (IMM_RE.test(token)) return COLORS.asmImmediate;
  if (REG_RE.test(token)) return COLORS.asmRegister;
  if (SHIFT_RE.test(token)) return COLORS.asmShift;
  return COLORS.textPrimary;
}

function lineToTextColumns(
  seq: number,
  line: TraceLine | undefined,
): { memRW: string; seqText: string; addr: string; disasm: string; regBefore: string; changes: string } {
  return {
    memRW: line?.mem_rw === "W" || line?.mem_rw === "R" ? line.mem_rw : "",
    seqText: String(seq + 1),
    addr: line?.address ?? "",
    disasm: line?.disasm ?? "",
    regBefore: line?.reg_before ?? "",
    changes: line?.changes ?? "",
  };
}

interface Props {
  totalLines: number;
  isLoaded: boolean;
  selectedSeq?: number | null;
  onSelectSeq: (seq: number) => void;
  getLines: (seqs: number[]) => Promise<TraceLine[]>;
  savedScrollSeq?: number | null;
  foldState: ReturnType<typeof useFoldState>;
  scrollAlignRef?: React.MutableRefObject<"center" | "auto" | "end">;
  sessionId?: string | null;
  highlights?: Map<number, HighlightInfo>;
  onSetHighlight?: (seqs: number[], update: HighlightInfo | null) => void;
  onToggleStrikethrough?: (seqs: number[]) => void;
  onResetHighlight?: (seqs: number[]) => void;
  onToggleHidden?: (seqs: number[]) => void;
  onUnhideGroup?: (seqs: number[]) => void;
  showAllHidden?: boolean;
  showHiddenIndicators?: boolean;
  onSetComment?: (seq: number, comment: string) => void;
  onDeleteComment?: (seq: number) => void;
  // Slice props
  sliceActive?: boolean;
  getSliceStatus?: (startSeq: number, count: number) => Promise<boolean[]>;
  onTaintRequest?: (seq: number, register?: string) => void;
  onRegSelected?: (info: { seq: number; regName: string } | null) => void;
  sliceFilterMode?: "highlight" | "filter-only";
  taintedSeqs?: number[];
  sliceSourceSeq?: number;
  scrollTrigger?: number;
  consumedSeqs?: number[];
  autoExpandCallInfoRequest?: { seq: number; nonce: number } | null;
  preferences: Preferences;
  updatePreferences: (updates: Partial<Preferences>) => void;
}

interface ArrowState {
  anchorSeq: number;
  regName: string;
  defSeq: number | null;
  useSeqs: number[];
}

interface TokenHitbox {
  x: number;
  width: number;
  rowIndex: number;
  token: string;
  seq: number;
}

interface ArrowLabelHitbox {
  x: number;
  y: number;
  width: number;
  height: number;
  seq: number;
}

export default function TraceTable({
  totalLines,
  isLoaded,
  selectedSeq: selectedSeqProp,
  onSelectSeq,
  getLines,
  savedScrollSeq,
  foldState,
  scrollAlignRef,
  sessionId,
  highlights,
  onSetHighlight,
  onToggleStrikethrough,
  onResetHighlight,
  onToggleHidden,
  onUnhideGroup,
  showAllHidden = false,
  showHiddenIndicators = true,
  onSetComment,
  onDeleteComment,
  sliceActive = false,
  getSliceStatus,
  onTaintRequest,
  onRegSelected,
  sliceFilterMode = "highlight",
  taintedSeqs,
  sliceSourceSeq,
  scrollTrigger = 0,
  consumedSeqs,
  autoExpandCallInfoRequest = null,
  preferences,
  updatePreferences,
}: Props) {
  const selectedSeqFromStore = useSelectedSeq();
  const selectedSeq = selectedSeqProp !== undefined ? selectedSeqProp : selectedSeqFromStore;
  const _themeId = useThemeId(); // 触发主题切换时的重绘

  const [visibleLines, setVisibleLines] = useState<Map<number, TraceLine>>(
    new Map()
  );

  // 滚动预取缓存（ref-based，绕过 React 状态，Canvas 直接读取）
  const prefetchCacheRef = useRef<Map<number, TraceLine>>(new Map());
  // 滚动预取污点状态缓存（ref-based，绕过 React 状态链路，Canvas 直接读取）
  const sliceStatusCacheRef = useRef<Map<number, boolean>>(new Map());

  // 渲染期间同步清空 visibleLines（避免 useEffect 延迟导致旧 session 数据残留）
  const prevVisibleSessionRef = useRef<string | null | undefined>(undefined);
  if (sessionId !== prevVisibleSessionRef.current) {
    prevVisibleSessionRef.current = sessionId;
    setVisibleLines(new Map());
    prefetchCacheRef.current = new Map();
    sliceStatusCacheRef.current = new Map();
  }

  const seqCol = useResizableColumn(DEFAULT_SEQ_WIDTH, "right", 50);
  const addrCol = useResizableColumn(DEFAULT_ADDR_WIDTH, "right", 50, "addr");
  const disasmCol = useResizableColumn(320, "right", 200);
  const regBeforeCol = useResizableColumn(420, "right", 40);

  const handleToggleSoName = useCallback(() => {
    const next = !preferences.showSoName;
    updatePreferences({
      showSoName: next,
      ...(next ? {} : { showAbsAddress: false }),
    });
    addrCol.setWidth(next ? 250 : 90);
  }, [preferences.showSoName, updatePreferences]);

  const handleToggleAbsAddress = useCallback(() => {
    if (!preferences.showSoName) return;
    const next = !preferences.showAbsAddress;
    updatePreferences({ showAbsAddress: next });
    addrCol.setWidth(next ? 380 : 250);
  }, [preferences.showSoName, preferences.showAbsAddress, updatePreferences]);

  // 动态列位置（每个拖动手柄占 8px）
  const HANDLE_W = 8;
  const COL_ADDR = COL_SEQ + seqCol.width + HANDLE_W;
  const COL_DISASM = COL_ADDR + addrCol.width + HANDLE_W;
  const COL_COMMENT = COL_DISASM + COMMENT_OFFSET;

  const {
    blLineMap, virtualTotalRows: foldVirtualTotalRows, resolveVirtualIndex: foldResolveVirtualIndex,
    seqToVirtualIndex: foldSeqToVirtualIndex, toggleFold, isFolded, ensureSeqVisible,
  } = foldState;

  // === Consumed seqs filtering layer (gumtrace special lines) ===
  // Consumed seqs are completely invisible — no indicators, no way to unhide.
  // Uses binary search on sorted consumedSeqs array for O(log n) per lookup.

  const consumedFoldIndices = useMemo(() => {
    if (!consumedSeqs || consumedSeqs.length === 0) return [];
    const indices: number[] = [];
    for (const seq of consumedSeqs) {
      const fvi = foldSeqToVirtualIndex(seq);
      const resolved = foldResolveVirtualIndex(fvi);
      if (resolved.type === "line" && resolved.seq === seq) {
        indices.push(fvi);
      }
    }
    indices.sort((a, b) => a - b);
    return indices;
  }, [consumedSeqs, foldSeqToVirtualIndex, foldResolveVirtualIndex]);

  const consumedFoldSet = useMemo(() => new Set(consumedFoldIndices), [consumedFoldIndices]);

  const virtualTotalRows = useMemo(
    () => foldVirtualTotalRows - consumedFoldIndices.length,
    [foldVirtualTotalRows, consumedFoldIndices],
  );

  // Binary search: count of elements in sorted arr that are <= val
  const upperBound = useCallback((arr: number[], val: number): number => {
    let lo = 0, hi = arr.length;
    while (lo < hi) {
      const mid = (lo + hi) >>> 1;
      if (arr[mid] <= val) lo = mid + 1;
      else hi = mid;
    }
    return lo;
  }, []);

  const resolveVirtualIndex = useCallback(
    (idx: number): ResolvedRow => {
      if (consumedFoldIndices.length === 0) return foldResolveVirtualIndex(idx);
      // Find the fold-space index such that (fvi - consumedBefore(fvi)) == idx
      let lo = idx;
      let hi = idx + consumedFoldIndices.length;
      if (hi >= foldVirtualTotalRows) hi = foldVirtualTotalRows - 1;
      while (lo < hi) {
        const mid = (lo + hi) >>> 1;
        const consumedBefore = upperBound(consumedFoldIndices, mid);
        const rank = mid + 1 - consumedBefore;
        if (rank <= idx) lo = mid + 1;
        else hi = mid;
      }
      return foldResolveVirtualIndex(lo);
    },
    [consumedFoldIndices, foldResolveVirtualIndex, foldVirtualTotalRows, upperBound],
  );

  const seqToVirtualIndex = useCallback(
    (seq: number): number => {
      const fvi = foldSeqToVirtualIndex(seq);
      if (consumedFoldIndices.length === 0) return fvi;
      const consumedBefore = upperBound(consumedFoldIndices, fvi);
      return fvi - consumedBefore;
    },
    [foldSeqToVirtualIndex, consumedFoldIndices, upperBound],
  );

  // === Hidden rows wrapping layer ===
  interface HiddenVirtualRange {
    startVI: number;
    endVI: number;
    count: number;
    seqs: number[];
  }

  const hiddenVirtualRanges = useMemo((): HiddenVirtualRange[] => {
    if (!highlights || showAllHidden) return [];
    const entries: { vi: number; seq: number }[] = [];
    for (const [seq, info] of highlights) {
      if (!info.hidden) continue;
      const vi = seqToVirtualIndex(seq);
      const resolved = resolveVirtualIndex(vi);
      if (resolved.type === "line" && resolved.seq === seq) {
        entries.push({ vi, seq });
      }
    }
    if (entries.length === 0) return [];
    entries.sort((a, b) => a.vi - b.vi);
    const ranges: HiddenVirtualRange[] = [];
    let startVI = entries[0].vi, endVI = startVI, seqs = [entries[0].seq];
    for (let i = 1; i < entries.length; i++) {
      if (entries[i].vi === endVI + 1) {
        endVI = entries[i].vi;
        seqs.push(entries[i].seq);
      } else {
        ranges.push({ startVI, endVI, count: endVI - startVI + 1, seqs });
        startVI = entries[i].vi; endVI = startVI; seqs = [entries[i].seq];
      }
    }
    ranges.push({ startVI, endVI, count: endVI - startVI + 1, seqs });
    return ranges;
  }, [highlights, showAllHidden, seqToVirtualIndex, resolveVirtualIndex]);

  const wrappedVirtualTotalRows = useMemo(() => {
    let reduction = 0;
    for (const r of hiddenVirtualRanges) {
      // showHiddenIndicators=true: 每个范围变成 1 行提示条，净减少 count-1
      // showHiddenIndicators=false: 完全移除，净减少 count
      reduction += showHiddenIndicators ? r.count - 1 : r.count;
    }
    return virtualTotalRows - reduction;
  }, [virtualTotalRows, hiddenVirtualRanges, showHiddenIndicators]);

  const wrappedResolveVirtualIndex = useCallback(
    (idx: number): ResolvedRow => {
      if (hiddenVirtualRanges.length === 0) {
        return resolveVirtualIndex(idx);
      }
      let offset = 0;
      for (const range of hiddenVirtualRanges) {
        const summaryPos = range.startVI - offset;
        if (idx < summaryPos) {
          return resolveVirtualIndex(idx + offset);
        }
        if (showHiddenIndicators) {
          // 有提示条：summary 占 1 行
          if (idx === summaryPos) {
            return { type: "hidden-summary", seqs: range.seqs, count: range.count };
          }
          offset += range.count - 1;
        } else {
          // 无提示条：完全跳过
          offset += range.count;
        }
      }
      return resolveVirtualIndex(idx + offset);
    },
    [resolveVirtualIndex, hiddenVirtualRanges, showHiddenIndicators],
  );

  const wrappedSeqToVirtualIndex = useCallback(
    (seq: number): number => {
      const foldVI = seqToVirtualIndex(seq);
      if (hiddenVirtualRanges.length === 0) return foldVI;
      let offset = 0;
      for (const range of hiddenVirtualRanges) {
        if (foldVI < range.startVI) return foldVI - offset;
        if (foldVI >= range.startVI && foldVI <= range.endVI) {
          return range.startVI - offset;
        }
        offset += showHiddenIndicators ? range.count - 1 : range.count;
      }
      return foldVI - offset;
    },
    [seqToVirtualIndex, hiddenVirtualRanges, showHiddenIndicators],
  );

  // === Taint filter wrapping layer ===
  const taintFilterActive = sliceActive && sliceFilterMode === "filter-only" && !!taintedSeqs && taintedSeqs.length > 0;

  const finalVirtualTotalRows = taintFilterActive
    ? taintedSeqs!.length
    : wrappedVirtualTotalRows;

  const finalResolveVirtualIndex = useCallback(
    (idx: number): ResolvedRow => {
      if (taintFilterActive) {
        const seq = taintedSeqs![idx];
        return seq !== undefined ? { type: "line", seq } : { type: "line", seq: 0 };
      }
      return wrappedResolveVirtualIndex(idx);
    },
    [taintFilterActive, taintedSeqs, wrappedResolveVirtualIndex],
  );

  const finalSeqToVirtualIndex = useCallback(
    (seq: number): number => {
      if (taintFilterActive) {
        let lo = 0, hi = taintedSeqs!.length - 1;
        while (lo <= hi) {
          const mid = (lo + hi) >>> 1;
          if (taintedSeqs![mid] < seq) lo = mid + 1;
          else if (taintedSeqs![mid] > seq) hi = mid - 1;
          else return mid;
        }
        return lo;
      }
      return wrappedSeqToVirtualIndex(seq);
    },
    [taintFilterActive, taintedSeqs, wrappedSeqToVirtualIndex],
  );

  // === Canvas 核心状态 ===
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const textOverlayRef = useRef<HTMLDivElement>(null);
  const [currentRow, setCurrentRow] = useState(0);
  // 防抖行号：滚动期间 IPC 和 DOM 重建延迟执行，只有 canvas 重绘使用 currentRow 即时响应
  const [debouncedRow, setDebouncedRow] = useState(0);
  useEffect(() => {
    const timer = setTimeout(() => setDebouncedRow(currentRow), 80);
    return () => clearTimeout(timer);
  }, [currentRow]);
  const [canvasSize, setCanvasSize] = useState({ width: 0, height: 0 });
  const [fontReady, setFontReady] = useState(false);
  const hitboxesRef = useRef<TokenHitbox[]>([]);
  const arrowLabelHitboxesRef = useRef<ArrowLabelHitbox[]>([]);
  const dirtyRef = useRef(true);
  const rafIdRef = useRef(0);
  const mouseDownPosRef = useRef({ x: 0, y: 0 });
  const hoverRowRef = useRef(-1);

  // 列宽变化时触发 Canvas 重绘
  const prevSeqW = useRef(seqCol.width);
  const prevAddrW = useRef(addrCol.width);
  if (seqCol.width !== prevSeqW.current || addrCol.width !== prevAddrW.current) {
    prevSeqW.current = seqCol.width;
    prevAddrW.current = addrCol.width;
    dirtyRef.current = true;
  }

  // === 多行选择 ===
  const [multiSelect, setMultiSelect] = useState<{ startVi: number; endVi: number } | null>(null);
  const [ctrlSelect, setCtrlSelect] = useState<Set<number>>(new Set()); // Ctrl+Click 任意多选（存储 vi）
  const shiftAnchorVi = useRef<number>(-1); // Shift+Click 锚点（上次普通点击的 vi）
  const isDraggingSelect = useRef(false);
  const dragPending = useRef(false); // mouseDown 后等待方向判定
  const dragStartVi = useRef(-1);
  const dragInTextArea = useRef(false); // mouseDown 是否在文本区域（disasm/changes 列）
  const [ctxMenu, setCtxMenu] = useState<{ x: number; y: number } | null>(null);
  const ctxRegRef = useRef<string | undefined>(undefined);
  const ctxCallInfoRef = useRef<{ tooltip: string; isJni: boolean } | null>(null);
  const [highlightSubmenuOpen, setHighlightSubmenuOpen] = useState(false);

  // === 切片状态缓存（Canvas 同步渲染用） ===
  const [sliceStatuses, setSliceStatuses] = useState<Map<number, boolean>>(new Map());

  // === 注释相关状态 ===
  const [commentTooltip, setCommentTooltip] = useState<{ seq: number; x: number; y: number; text: string } | null>(null);
  const [callInfoTooltip, setCallInfoTooltip] = useState<{ x: number; y: number; text: string; isJni: boolean } | null>(null);
  const callInfoHoveredRef = useRef(false);
  const callInfoClearTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [commentEditor, setCommentEditor] = useState<{ seq: number; x: number; y: number; text: string } | null>(null);
  const commentEditorRef = useRef<HTMLDivElement>(null);
  const textSelectionRef = useRef<string>(""); // 右键菜单打开时保存的文本选区
  const commentTextareaRef = useRef<HTMLTextAreaElement>(null);

  const visibleRows = Math.floor(canvasSize.height / ROW_HEIGHT);

  // === 滚动预取 ref 镜像（供 wheel handler 闭包访问最新值） ===
  const prefetchTimerRef = useRef(0);
  const finalResolveRef = useRef(finalResolveVirtualIndex);
  finalResolveRef.current = finalResolveVirtualIndex;
  const totalRowsRef = useRef(finalVirtualTotalRows);
  totalRowsRef.current = finalVirtualTotalRows;
  const visibleRowsRef = useRef(visibleRows);
  visibleRowsRef.current = visibleRows;
  const getLinesRef = useRef(getLines);
  getLinesRef.current = getLines;
  const sliceActiveRef = useRef(sliceActive);
  sliceActiveRef.current = sliceActive;
  const taintFilterActiveRef = useRef(taintFilterActive);
  taintFilterActiveRef.current = taintFilterActive;
  const getSliceStatusRef = useRef(getSliceStatus);
  getSliceStatusRef.current = getSliceStatus;

  // === 折叠/展开 clip 动画 ===
  const FOLD_ANIM_DURATION = 350; // ms
  const UNFOLD_ANIM_DURATION = 420; // ms
  const foldAnimRef = useRef<{
    startTime: number;
    direction: "fold" | "unfold";
    // clip 区域起始 Y（像素，相对于 canvas 顶部）
    clipTopPx: number;
    // clip 区域最大高度（像素）
    clipMaxHeightPx: number;
    // 折叠时：延迟执行 toggleFold 的 nodeId
    pendingNodeId: number | null;
  } | null>(null);

  /** 带动画的 toggleFold 包装 */
  const animatedToggleFold = useCallback((nodeId: number, clickVi: number) => {
    const isFolding = !isFolded(nodeId);
    let hiddenRows = 0;
    for (const [, node] of blLineMap) {
      if (node.id === nodeId) {
        hiddenRows = node.exit_seq - node.entry_seq;
        break;
      }
    }

    if (hiddenRows <= 0) {
      toggleFold(nodeId);
      return;
    }

    // clip 区域最大高度：限制为可视区域剩余高度
    const renderStart = Math.floor(scrollPosRef.current);
    const subPx = -(scrollPosRef.current - renderStart) * ROW_HEIGHT;
    const clickLocalRow = clickVi - renderStart;
    const clipTop = (clickLocalRow + 1) * ROW_HEIGHT + subPx;
    const clipMaxH = Math.min(hiddenRows * ROW_HEIGHT, canvasSize.height - clipTop);

    if (clipMaxH <= 0) {
      toggleFold(nodeId);
      return;
    }

    if (isFolding) {
      // 折叠：先做动画（clip 从满→0），结束后 toggleFold
      foldAnimRef.current = {
        startTime: performance.now(),
        direction: "fold",
        clipTopPx: clipTop,
        clipMaxHeightPx: clipMaxH,
        pendingNodeId: nodeId,
      };
      dirtyRef.current = true;
      // 不调用 toggleFold，等动画结束
    } else {
      // 展开：先 toggleFold（新行可用），然后 clip 从0→满
      toggleFold(nodeId);
      foldAnimRef.current = {
        startTime: performance.now(),
        direction: "unfold",
        clipTopPx: clipTop,
        clipMaxHeightPx: clipMaxH,
        pendingNodeId: null,
      };
      dirtyRef.current = true;
    }
  }, [toggleFold, isFolded, blLineMap, canvasSize.height]);

  const maxRow = Math.max(0, finalVirtualTotalRows - visibleRows);

  // 渲染期间同步钳位 currentRow 和 debouncedRow（避免 taint filter 切换后超出新范围导致空白）
  if (currentRow > maxRow && maxRow >= 0) {
    setCurrentRow(maxRow);
  }
  if (debouncedRow > maxRow && maxRow >= 0) {
    setDebouncedRow(maxRow);
  }

  // 推式布局：所有列从左到右排列，Changes 吸收剩余宽度
  const MIN_CHANGES_WIDTH = 60;
  const maxLeftCols = Math.max(0, canvasSize.width - COL_DISASM - 2 * HANDLE_W - RIGHT_GUTTER - MIN_CHANGES_WIDTH);
  const effectiveDisasmWidth = Math.max(200, Math.min(disasmCol.width, maxLeftCols - 40));
  const effectiveBeforeWidth = Math.max(40, Math.min(regBeforeCol.width, maxLeftCols - effectiveDisasmWidth));
  const colRegBefore = COL_DISASM + effectiveDisasmWidth + HANDLE_W;
  const colChanges = colRegBefore + effectiveBeforeWidth + HANDLE_W;
  const effectiveChangesWidth = Math.max(MIN_CHANGES_WIDTH, canvasSize.width - colChanges - RIGHT_GUTTER);

  const hasRestoredScroll = useRef(false);
  const isInternalClick = useRef(false);

  // === 字体加载 ===
  useEffect(() => {
    document.fonts.ready.then(() => setFontReady(true));
  }, []);

  // === ResizeObserver（分割线拖拽期间完全跳过 canvas 重绘，拖拽结束后一次性更新） ===
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    // 同步获取初始尺寸，消除 ResizeObserver 异步回调的竞态条件
    // （isLoaded 变 true 时 container 首次出现，若等 observer 异步回调，
    //   drawFrame 可能在 canvasSize={0,0} 时先执行，导致指令行不显示）
    const rect = el.getBoundingClientRect();
    if (rect.width > 0 && rect.height > 0) {
      setCanvasSize(prev =>
        prev.width === rect.width && prev.height === rect.height ? prev : { width: rect.width, height: rect.height }
      );
      dirtyRef.current = true;
    }
    let timer = 0;
    const ro = new ResizeObserver((entries) => {
      const { width, height } = entries[0].contentRect;
      clearTimeout(timer);
      if (document.documentElement.dataset.separatorDrag) {
        // 分割线拖拽中：记录最新尺寸但不触发渲染，等拖拽结束后由最后一次回调更新
        timer = window.setTimeout(() => {
          setCanvasSize(prev =>
            prev.width === width && prev.height === height ? prev : { width, height }
          );
          dirtyRef.current = true;
        }, 300);
        return;
      }
      // 非拖拽：立即更新（避免 RAF 延迟导致首次渲染时 canvasSize 为 0）
      setCanvasSize(prev =>
        prev.width === width && prev.height === height ? prev : { width, height }
      );
      dirtyRef.current = true;
    });
    ro.observe(el);
    return () => { clearTimeout(timer); cancelAnimationFrame(timer); ro.disconnect(); };
  }, [isLoaded]);

  // === HiDPI Canvas 尺寸同步（useLayoutEffect 确保在 rAF/drawFrame 之前完成） ===
  useLayoutEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas || canvasSize.width === 0) return;
    const dpr = window.devicePixelRatio || 1;
    const targetW = Math.round(canvasSize.width * dpr);
    const targetH = Math.round(canvasSize.height * dpr);
    // 尺寸未变时跳过：canvas.width/height 赋值即使值相同也会清空画布 + 重新分配 GPU 纹理
    if (canvas.width === targetW && canvas.height === targetH) return;
    canvas.width = targetW;
    canvas.height = targetH;
    canvas.style.width = canvasSize.width + "px";
    canvas.style.height = canvasSize.height + "px";
    dirtyRef.current = true;
    // isLoaded 在 deps 中：isLoaded false→true 时 canvas 被 React 重建（默认 300×150），
    // 即使 canvasSize 没变也必须重新设置 canvas 尺寸
  }, [canvasSize, isLoaded]);

  // === scrollToSeq ===
  const scrollToSeq = useCallback((seq: number, align: "center" | "auto" | "end") => {
    ensureSeqVisible(seq);
    const vi = finalSeqToVirtualIndex(seq);
    if (align === "center") {
      setCurrentRow(Math.max(0, Math.min(maxRow, vi - Math.floor(visibleRows / 2))));
    } else if (align === "end") {
      // 将目标行置于窗口最后一行
      setCurrentRow(Math.max(0, Math.min(maxRow, vi - visibleRows + 1)));
    } else {
      setCurrentRow(prev => {
        if (vi >= prev && vi < prev + visibleRows) return prev;
        return Math.max(0, Math.min(maxRow, vi - Math.floor(visibleRows / 2)));
      });
    }
  }, [ensureSeqVisible, finalSeqToVirtualIndex, maxRow, visibleRows]);

  // === 恢复滚动位置 ===
  useEffect(() => {
    if (isLoaded && savedScrollSeq != null && savedScrollSeq > 0 && !hasRestoredScroll.current) {
      hasRestoredScroll.current = true;
      requestAnimationFrame(() => scrollToSeq(savedScrollSeq, "center"));
    }
  }, [isLoaded, savedScrollSeq, scrollToSeq]);

  useEffect(() => { hasRestoredScroll.current = false; }, [totalLines, sessionId]);

  // === 外部 selectedSeq 变化时滚动 ===
  const prevSelectedSeqRef = useRef<number | null>(null);
  const prevScrollTriggerRef = useRef(0);
  useEffect(() => {
    if (selectedSeq != null && isLoaded) {
      if (isInternalClick.current) {
        isInternalClick.current = false;
        prevSelectedSeqRef.current = selectedSeq;
        prevScrollTriggerRef.current = scrollTrigger;
        return;
      }
      // scrollTrigger 变化时强制滚动（Go to Source、视图切换等场景）
      const triggerChanged = scrollTrigger !== prevScrollTriggerRef.current;
      // 仅在 selectedSeq 真正变化时滚动，避免 fold/unfold 导致的 scrollToSeq 重建触发跳转
      if (!triggerChanged && selectedSeq === prevSelectedSeqRef.current) {
        return;
      }
      prevSelectedSeqRef.current = selectedSeq;
      prevScrollTriggerRef.current = scrollTrigger;
      const align = scrollAlignRef?.current ?? "center";
      if (scrollAlignRef) scrollAlignRef.current = "center";
      scrollToSeq(selectedSeq, align);
    }
  }, [selectedSeq, isLoaded, scrollAlignRef, scrollToSeq, scrollTrigger]);

  const pendingAutoExpandCallInfoRef = useRef<{ seq: number; nonce: number } | null>(null);
  const lastAutoExpandCallInfoNonceRef = useRef<number | null>(null);
  useEffect(() => {
    if (!autoExpandCallInfoRequest) return;
    if (lastAutoExpandCallInfoNonceRef.current === autoExpandCallInfoRequest.nonce) return;
    lastAutoExpandCallInfoNonceRef.current = autoExpandCallInfoRequest.nonce;
    if (autoExpandCallInfoRequest.seq < 0) {
      // 无 call_info 的行被点击，关闭已有弹框
      pendingAutoExpandCallInfoRef.current = null;
      setCallInfoTooltip(null);
      return;
    }
    pendingAutoExpandCallInfoRef.current = autoExpandCallInfoRequest;
  }, [autoExpandCallInfoRequest]);

  useEffect(() => {
    const pending = pendingAutoExpandCallInfoRef.current;
    if (!pending || !isLoaded || selectedSeq !== pending.seq) return;
    const line = visibleLines.get(pending.seq) ?? prefetchCacheRef.current.get(pending.seq);
    if (!line?.call_info) {
      return;
    }

    const rect = containerRef.current?.getBoundingClientRect();
    if (!rect) return;

    const rowIdx = finalSeqToVirtualIndex(pending.seq) - currentRow;
    if (rowIdx < 0 || rowIdx > visibleRows) return;

    if (callInfoClearTimerRef.current) {
      clearTimeout(callInfoClearTimerRef.current);
      callInfoClearTimerRef.current = null;
    }

    const tooltipWidth = 620;
    const tooltipHeight = 300;
    const preferredX = rect.left + COL_DISASM + 24;
    const preferredY = rect.top + rowIdx * ROW_HEIGHT + 10;
    const x = Math.max(12, Math.min(preferredX, window.innerWidth - tooltipWidth - 12));
    const y = Math.max(12, Math.min(preferredY, window.innerHeight - tooltipHeight - 12));

    callInfoHoveredRef.current = false;
    setCallInfoTooltip({
      x,
      y,
      text: line.call_info.tooltip,
      isJni: line.call_info.is_jni,
    });
    pendingAutoExpandCallInfoRef.current = null;
  }, [currentRow, finalSeqToVirtualIndex, isLoaded, selectedSeq, visibleLines, visibleRows]);

  // === 数据预取（debouncedRow 驱动，滚动期间不触发 IPC） ===
  useEffect(() => {
    if (!isLoaded || visibleRows === 0) return;
    const seqs: number[] = [];
    for (let i = 0; i < visibleRows + 2; i++) {
      const vi = debouncedRow + i;
      if (vi >= finalVirtualTotalRows) break;
      const resolved = finalResolveVirtualIndex(vi);
      if (resolved.type === "line") seqs.push(resolved.seq);
    }
    const missing = seqs.filter(s => !visibleLines.has(s) && !prefetchCacheRef.current.has(s));
    // 将预取缓存中已有的数据合并到 visibleLines
    const fromPrefetch: TraceLine[] = [];
    for (const s of seqs) {
      if (!visibleLines.has(s) && prefetchCacheRef.current.has(s)) {
        fromPrefetch.push(prefetchCacheRef.current.get(s)!);
      }
    }
    if (missing.length === 0 && fromPrefetch.length === 0) return;
    const doMerge = (fetched: TraceLine[]) => {
      setVisibleLines(prev => {
        const next = new Map(prev);
        for (const line of fromPrefetch) next.set(line.seq, line);
        for (const line of fetched) next.set(line.seq, line);
        if (next.size > 2000) {
          const entries = Array.from(next.entries());
          return new Map(entries.slice(-1000));
        }
        return next;
      });
    };
    if (missing.length > 0) {
      getLines(missing).then(lines => {
        // 同步写入预取缓存
        for (const line of lines) prefetchCacheRef.current.set(line.seq, line);
        doMerge(lines);
      });
    } else {
      doMerge([]);
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [debouncedRow, visibleRows, isLoaded, getLines, finalVirtualTotalRows, finalResolveVirtualIndex]);

  // === 切片状态异步获取（debouncedRow 驱动，滚动期间不触发 IPC） ===
  useEffect(() => {
    if (!sliceActive || !getSliceStatus) {
      if (sliceStatuses.size > 0) setSliceStatuses(new Map());
      sliceStatusCacheRef.current = new Map();
      return;
    }
    // 过滤模式下所有可见行都是污点行，直接标记为 true
    if (taintFilterActive) {
      const map = new Map<number, boolean>();
      for (let i = 0; i < visibleRows + 2; i++) {
        const vi = debouncedRow + i;
        if (vi >= finalVirtualTotalRows) break;
        const resolved = finalResolveVirtualIndex(vi);
        if (resolved.type === "line") map.set(resolved.seq, true);
      }
      setSliceStatuses(map);
      dirtyRef.current = true;
      return;
    }
    // 正常模式：按范围获取
    const seqs: number[] = [];
    for (let i = 0; i < visibleRows + 2; i++) {
      const vi = debouncedRow + i;
      if (vi >= finalVirtualTotalRows) break;
      const resolved = finalResolveVirtualIndex(vi);
      if (resolved.type === "line") seqs.push(resolved.seq);
    }
    if (seqs.length === 0) return;
    const minSeq = Math.min(...seqs);
    const maxSeq = Math.max(...seqs);
    const count = maxSeq - minSeq + 1;
    getSliceStatus(minSeq, count).then(statuses => {
      const map = new Map<number, boolean>();
      statuses.forEach((v, i) => {
        map.set(minSeq + i, v);
        sliceStatusCacheRef.current.set(minSeq + i, v);
      });
      setSliceStatuses(map);
      dirtyRef.current = true;
    });
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [debouncedRow, visibleRows, sliceActive, getSliceStatus, finalVirtualTotalRows, finalResolveVirtualIndex, taintFilterActive]);

  // === DEF/USE 箭头状态 ===
  const [arrowState, setArrowState] = useState<ArrowState | null>(null);

  const handleRegClick = useCallback(async (seq: number, regName: string) => {
    if (arrowState && arrowState.anchorSeq === seq && arrowState.regName.toLowerCase() === regName.toLowerCase()) {
      setArrowState(null);
      return;
    }
    if (!sessionId) return;
    try {
      const chain = await invoke<DefUseChain>("get_reg_def_use_chain", {
        sessionId,
        seq,
        regName,
      });
      setArrowState({
        anchorSeq: seq,
        regName,
        defSeq: chain.defSeq,
        useSeqs: chain.useSeqs,
      });
    } catch (e) {
      console.error("get_reg_def_use_chain failed:", e);
    }
  }, [sessionId, arrowState]);

  // 通知外部寄存器选中状态变化
  useEffect(() => {
    onRegSelected?.(arrowState ? { seq: arrowState.anchorSeq, regName: arrowState.regName } : null);
  }, [arrowState, onRegSelected]);

  // 切换 session 或文件时清除箭头
  useEffect(() => { setArrowState(null); }, [sessionId]);

  const handleArrowJump = useCallback((seq: number) => {
    ensureSeqVisible(seq);
    isInternalClick.current = true;
    onSelectSeq(seq);
    scrollToSeq(seq, "center");
  }, [ensureSeqVisible, onSelectSeq, scrollToSeq]);

  // === 滚轮事件（同步更新 scrollPosRef，节流 React 状态以消除渲染开销） ===
  const maxRowRef = useRef(maxRow);
  maxRowRef.current = maxRow;
  const scrollPosRef = useRef(0);        // 连续浮点位置（单位：行），如 42.7 = 第42行 + 70%
  const lastEmittedRowRef = useRef(0);   // 上次发出的整数行号，用于检测外部变化
  // 渲染期间同步钳位 scrollPosRef（配合 currentRow 钳位，避免 canvas 用旧位置绘制空白帧）
  if (scrollPosRef.current > maxRow) {
    scrollPosRef.current = maxRow;
    lastEmittedRowRef.current = maxRow;
  }
  const wheelTimerRef = useRef(0);       // 节流定时器
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const handler = (e: WheelEvent) => {
      e.preventDefault();
      const speed = 3;
      scrollPosRef.current += (e.deltaY / ROW_HEIGHT) * speed;
      const max = maxRowRef.current;
      if (scrollPosRef.current < 0) scrollPosRef.current = 0;
      if (scrollPosRef.current > max) scrollPosRef.current = max;
      dirtyRef.current = true;
      // 节流 React 状态更新：滚轮停止 60ms 后才触发 setCurrentRow，
      // 避免滚动期间大量 React 重渲染导致主线程卡顿
      if (wheelTimerRef.current) clearTimeout(wheelTimerRef.current);
      wheelTimerRef.current = window.setTimeout(() => {
        const newRow = Math.floor(scrollPosRef.current);
        if (newRow !== lastEmittedRowRef.current) {
          lastEmittedRowRef.current = newRow;
          setCurrentRow(newRow);
        }
      }, 60);
      // 节流预取：滚动期间每 50ms 预取可视范围 + overscan 的数据，
      // 绕过 React 状态链路（60ms+80ms 防抖），直接写入 ref 供 Canvas 读取
      if (!prefetchTimerRef.current) {
        prefetchTimerRef.current = window.setTimeout(() => {
          prefetchTimerRef.current = 0;
          const pos = Math.floor(scrollPosRef.current);
          const rows = visibleRowsRef.current;
          const total = totalRowsRef.current;
          const OVERSCAN = 50;
          const seqs: number[] = [];
          const start = Math.max(0, pos - OVERSCAN);
          const end = Math.min(total, pos + rows + OVERSCAN);
          for (let vi = start; vi < end; vi++) {
            const r = finalResolveRef.current(vi);
            if (r.type === "line" && !prefetchCacheRef.current.has(r.seq)) {
              seqs.push(r.seq);
            }
          }
          if (seqs.length > 0) {
            getLinesRef.current(seqs).then(lines => {
              for (const line of lines) prefetchCacheRef.current.set(line.seq, line);
              if (prefetchCacheRef.current.size > 5000) {
                const entries = Array.from(prefetchCacheRef.current.entries());
                prefetchCacheRef.current = new Map(entries.slice(-3000));
              }
              dirtyRef.current = true;
            });
          }
          // 同步预取污点状态（highlight 模式）：绕过 debouncedRow 的 140ms 延迟
          if (sliceActiveRef.current && !taintFilterActiveRef.current && getSliceStatusRef.current) {
            // 只预取可视区域（污点状态查询较快，不需要大 overscan）
            const sliceStart = Math.max(0, pos);
            const sliceEnd = Math.min(total, pos + rows + 2);
            const sliceSeqs: number[] = [];
            for (let vi = sliceStart; vi < sliceEnd; vi++) {
              const r = finalResolveRef.current(vi);
              if (r.type === "line" && !sliceStatusCacheRef.current.has(r.seq)) {
                sliceSeqs.push(r.seq);
              }
            }
            if (sliceSeqs.length > 0) {
              const minS = Math.min(...sliceSeqs);
              const maxS = Math.max(...sliceSeqs);
              getSliceStatusRef.current(minS, maxS - minS + 1).then(statuses => {
                statuses.forEach((v, i) => sliceStatusCacheRef.current.set(minS + i, v));
                if (sliceStatusCacheRef.current.size > 5000) {
                  const entries = Array.from(sliceStatusCacheRef.current.entries());
                  sliceStatusCacheRef.current = new Map(entries.slice(-3000));
                }
                dirtyRef.current = true;
              });
            }
          }
        }, 50);
      }
    };
    el.addEventListener("wheel", handler, { passive: false });
    return () => {
      el.removeEventListener("wheel", handler);
      if (wheelTimerRef.current) clearTimeout(wheelTimerRef.current);
      if (prefetchTimerRef.current) clearTimeout(prefetchTimerRef.current);
    };
  }, [isLoaded]);
  // 外部 currentRow 变化时同步浮点位置（滚动条拖动、键盘跳转等）
  useEffect(() => {
    if (currentRow !== lastEmittedRowRef.current) {
      scrollPosRef.current = currentRow;
      lastEmittedRowRef.current = currentRow;
    }
  }, [currentRow]);

  // === Overlay 事件路由 ===
  const handleOverlayMouseDown = useCallback((e: React.MouseEvent) => {
    mouseDownPosRef.current = { x: e.clientX, y: e.clientY };
    // 确保 container 有焦点（键盘快捷键需要）—— focus() 不影响鼠标文本选择
    containerRef.current?.focus();
    // 关闭右键菜单
    setCtxMenu(null);
    // 左键拖选准备
    if (e.button === 0) {
      const container = containerRef.current;
      if (!container) return;
      const rect = container.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const y = e.clientY - rect.top;
      const scrollFrac = (scrollPosRef.current % 1) * ROW_HEIGHT;
      const rowIdx = Math.floor((y + scrollFrac) / ROW_HEIGHT);
      const vi = Math.floor(scrollPosRef.current) + rowIdx;
      // 仅在非功能区域启动拖选（跳过箭头列和折叠列）
      if (x >= COL_MEMRW && vi < finalVirtualTotalRows) {
        // 检查是否点击了寄存器 hitbox
        let hitReg = false;
        if (x >= COL_DISASM && x < colChanges) {
          for (const hb of hitboxesRef.current) {
            if (hb.rowIndex === rowIdx && x >= hb.x && x <= hb.x + hb.width) {
              hitReg = true;
              break;
            }
          }
        }
        if (!hitReg && !e.ctrlKey && !e.metaKey && !e.shiftKey) {
          if (e.detail >= 2) {
            // 双击/三击：让浏览器处理文本选择，不启动拖选
            return;
          }
          // 记录是否在文本区域（disasm/changes 列），用于后续方向判定
          dragInTextArea.current = x >= COL_DISASM;
          dragPending.current = true;
          dragStartVi.current = vi;
        }
        // Shift+Click：阻止浏览器默认文本扩选
        if (!hitReg && e.shiftKey && !e.ctrlKey && !e.metaKey) {
          window.getSelection()?.removeAllRanges();
          e.preventDefault();
          containerRef.current?.focus();
        }
      }
    }
  }, [finalVirtualTotalRows, canvasSize.width, effectiveChangesWidth, effectiveDisasmWidth, effectiveBeforeWidth]);

  // === call_info 独立窗口 ===
  const openCallInfoWindow = useCallback(async (text: string, isJni: boolean, mouseX: number, mouseY: number) => {
    const winLabel = `panel-call-info-${Date.now()}`;
    const unlisten = await listen(`call-info:ready:${winLabel}`, () => {
      emitTo(winLabel, "call-info:init-data", { text, isJni });
      unlisten();
    });
    new WebviewWindow(winLabel, {
      url: `index.html?panel=call-info`,
      title: isJni ? "JNI Call Info" : "Call Info",
      width: 520,
      height: 360,
      x: Math.round(mouseX),
      y: Math.round(mouseY),
      decorations: false,
      transparent: true,
    });
  }, []);

  // === Canvas 点击 ===
  const handleCanvasClick = useCallback((e: React.MouseEvent) => {
    const container = containerRef.current;
    if (!container) return;
    const rect = container.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;
    const scrollFrac = (scrollPosRef.current % 1) * ROW_HEIGHT;
    const rowIdx = Math.floor((y + scrollFrac) / ROW_HEIGHT);
    const vi = Math.floor(scrollPosRef.current) + rowIdx;
    if (vi >= finalVirtualTotalRows) return;
    const resolved = finalResolveVirtualIndex(vi);

    // 1. 箭头列标签点击（hitbox 可能延伸到 COL_FOLD 之外）
    for (const lb of arrowLabelHitboxesRef.current) {
      if (x >= lb.x && x <= lb.x + lb.width && y >= lb.y && y <= lb.y + lb.height) {
        handleArrowJump(lb.seq);
        return;
      }
    }

    // 2. Fold 列点击 (COL_FOLD ~ COL_MEMRW)
    if (x >= COL_FOLD && x < COL_MEMRW) {
      if (resolved.type === "summary") {
        animatedToggleFold(resolved.nodeId, vi);
        return;
      }
      if (resolved.type === "line") {
        const blNode = blLineMap.get(resolved.seq);
        if (blNode && blNode.exit_seq > blNode.entry_seq && !isFolded(blNode.id)) {
          animatedToggleFold(blNode.id, vi);
          return;
        }
      }
    }

    // 3. 折叠摘要行整行点击 → toggleFold
    if (resolved.type === "summary") {
      animatedToggleFold(resolved.nodeId, vi);
      return;
    }

    // 3.5 隐藏摘要行：仅点击文本区域才 unhide
    if (resolved.type === "hidden-summary") {
      if (onUnhideGroup && x >= COL_MEMRW) {
        // 测量文本宽度，仅在文本范围内点击时触发
        const canvas = canvasRef.current;
        if (canvas) {
          const ctx2 = canvas.getContext("2d");
          if (ctx2) {
            ctx2.font = FONT_ITALIC;
            const textW = ctx2.measureText(`\u2026 ${resolved.count} hidden lines`).width;
            if (x <= COL_MEMRW + textW + 8) {
              onUnhideGroup(resolved.seqs);
              // 恢复后将这些行设为多选状态，标示刚取消隐藏的行
              setMultiSelect({ startVi: vi, endVi: vi + resolved.count - 1 });
              dirtyRef.current = true;
            }
          }
        }
      }
      return;
    }

    // 4. Disasm 列寄存器点击
    if (x >= COL_DISASM && sessionId) {
      if (x < colChanges) {
        for (const hb of hitboxesRef.current) {
          if (hb.rowIndex === rowIdx && x >= hb.x && x <= hb.x + hb.width) {
            if (hb.token.startsWith("__call_info__")) {
              return; // call_info 改为双击打开
            }
            isInternalClick.current = true;
            onSelectSeq(resolved.seq);
            handleRegClick(resolved.seq, hb.token);
            return;
          }
        }
      }
    }

    // 5. Shift+Click：范围批量选中（从锚点到当前行）
    if (e.shiftKey && resolved.type === "line") {
      const anchor = shiftAnchorVi.current >= 0 ? shiftAnchorVi.current : (selectedSeq != null ? finalSeqToVirtualIndex(selectedSeq) : vi);
      const startVi = Math.min(anchor, vi);
      const endVi = Math.max(anchor, vi);
      setMultiSelect({ startVi, endVi });
      setCtrlSelect(prev => prev.size > 0 ? new Set() : prev);
      dirtyRef.current = true;
      return;
    }

    // 6. Ctrl+Click：任意多选
    if ((e.ctrlKey || e.metaKey) && resolved.type === "line") {
      setCtrlSelect(prev => {
        const next = new Set(prev);
        if (next.has(vi)) {
          next.delete(vi);
        } else {
          next.add(vi);
        }
        return next;
      });
      setMultiSelect(null);
      shiftAnchorVi.current = vi;
      dirtyRef.current = true;
      return;
    }

    // 7. 默认：选中行
    isInternalClick.current = true;
    onSelectSeq(resolved.seq);
    if (arrowState) setArrowState(null);
    setCtrlSelect(prev => prev.size > 0 ? new Set() : prev);
    shiftAnchorVi.current = vi;
  }, [finalVirtualTotalRows, finalResolveVirtualIndex, finalSeqToVirtualIndex, animatedToggleFold, blLineMap,
      isFolded, sessionId, canvasSize, effectiveChangesWidth, effectiveDisasmWidth, effectiveBeforeWidth, handleRegClick,
      handleArrowJump, onSelectSeq, onUnhideGroup, selectedSeq, openCallInfoWindow, visibleLines]);

  const handleOverlayMouseUp = useCallback((e: React.MouseEvent) => {
    const wasDragging = isDraggingSelect.current;
    const wasPending = dragPending.current;
    isDraggingSelect.current = false;
    dragPending.current = false;
    // 恢复文本选择能力（拖选期间被 CSS 禁用）
    if (textOverlayRef.current) {
      textOverlayRef.current.style.userSelect = "text";
      textOverlayRef.current.style.webkitUserSelect = "text";
    }
    // 右键不清除多选（交给 contextmenu 处理）
    if (e.button === 2) return;
    // 如果在行拖选，结束拖选（不触发 click）
    if (wasDragging && !wasPending && multiSelect && multiSelect.startVi !== multiSelect.endVi) {
      window.getSelection()?.removeAllRanges();
      return;
    }
    // 双击：检测 call_info hitbox，命中则打开窗口，否则让浏览器处理选词
    if (e.detail >= 2) {
      const container2 = containerRef.current;
      if (container2) {
        const rect2 = container2.getBoundingClientRect();
        const cx = e.clientX - rect2.left;
        const scrollFrac2 = (scrollPosRef.current % 1) * ROW_HEIGHT;
        const rowIdx2 = Math.floor((e.clientY - rect2.top + scrollFrac2) / ROW_HEIGHT);
        for (const hb of hitboxesRef.current) {
          if (hb.rowIndex === rowIdx2 && cx >= hb.x && cx <= hb.x + hb.width && hb.token.startsWith("__call_info__")) {
            const hoveredLine = visibleLines.get(hb.seq) ?? prefetchCacheRef.current.get(hb.seq);
            if (hoveredLine?.call_info) {
              openCallInfoWindow(hoveredLine.call_info.tooltip, hoveredLine.call_info.is_jni, e.clientX, e.clientY);
            }
            return;
          }
        }
      }
      return;
    }
    const dx = e.clientX - mouseDownPosRef.current.x;
    const dy = e.clientY - mouseDownPosRef.current.y;
    const dist = Math.sqrt(dx * dx + dy * dy);
    if (dist < 3) {
      if (!e.ctrlKey && !e.metaKey && !e.shiftKey) {
        setMultiSelect(null);
      }
      dirtyRef.current = true;
      handleCanvasClick(e);
    }
  }, [handleCanvasClick, multiSelect, visibleLines, openCallInfoWindow]);

  // === 关闭注释编辑框并恢复焦点 ===
  const closeCommentEditor = useCallback(() => {
    setCommentEditor(null);
    // 恢复焦点到 container，确保键盘快捷键继续工作
    setTimeout(() => containerRef.current?.focus(), 0);
  }, []);

  // === 打开注释编辑框 ===
  const openCommentEditor = useCallback((seq: number) => {
    const container = containerRef.current;
    if (!container) return;
    const vi = finalSeqToVirtualIndex(seq);
    const renderStart = Math.floor(scrollPosRef.current);
    const subPx = -(scrollPosRef.current - renderStart) * ROW_HEIGHT;
    const localRow = vi - renderStart;
    const rect = container.getBoundingClientRect();
    const existingComment = highlights?.get(seq)?.comment ?? "";
    setCommentTooltip(null);
    setCommentEditor({
      seq,
      x: rect.left + COL_COMMENT,
      y: rect.top + localRow * ROW_HEIGHT + subPx + ROW_HEIGHT,
      text: existingComment,
    });
  }, [finalSeqToVirtualIndex, highlights]);

  // === 双击选词后去除尾随空格并自动复制 ===
  const handleOverlayDblClick = useCallback(() => {
    setTimeout(() => {
      const sel = window.getSelection();
      if (!sel || sel.isCollapsed) return;
      const text = sel.toString();
      const trimLen = text.length - text.trimEnd().length;
      if (trimLen > 0) {
        for (let i = 0; i < trimLen; i++) {
          sel.modify("extend", "backward", "character");
        }
      }
      const finalText = sel.toString().trim();
      if (finalText) navigator.clipboard.writeText(finalText);
    }, 0);
  }, []);

  // === 鼠标悬停效果 ===
  const handleCanvasMouseMove = useCallback((e: React.MouseEvent) => {
    const container = containerRef.current;
    if (!container) return;
    const rect = container.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;
    const scrollFrac = (scrollPosRef.current % 1) * ROW_HEIGHT;
    const rowIdx = Math.floor((y + scrollFrac) / ROW_HEIGHT);

    if (hoverRowRef.current !== rowIdx) {
      hoverRowRef.current = rowIdx;
      dirtyRef.current = true;
    }

    // 检测寄存器 hitbox 和 call_info hitbox
    for (const hb of hitboxesRef.current) {
      if (hb.rowIndex === rowIdx && x >= hb.x && x <= hb.x + hb.width) {
        if (hb.token.startsWith("__call_info__")) {
          const hbSeq = hb.seq;
          const hoveredLine = visibleLines.get(hbSeq) ?? prefetchCacheRef.current.get(hbSeq);
          if (hoveredLine?.call_info) {
            if (callInfoClearTimerRef.current) { clearTimeout(callInfoClearTimerRef.current); callInfoClearTimerRef.current = null; }
            // 仅首次显示时设定位置，避免鼠标移动导致 tooltip 跟随
            if (!callInfoTooltip) {
              setCallInfoTooltip({
                x: e.clientX,
                y: e.clientY + 12,
                text: hoveredLine.call_info.tooltip,
                isJni: hoveredLine.call_info.is_jni,
              });
            }
          }
          if (textOverlayRef.current) textOverlayRef.current.style.cursor = "default";
          return;
        }
        if (textOverlayRef.current) textOverlayRef.current.style.cursor = "pointer";
        if (callInfoTooltip && !callInfoHoveredRef.current) {
          if (callInfoClearTimerRef.current) clearTimeout(callInfoClearTimerRef.current);
          callInfoClearTimerRef.current = setTimeout(() => {
            if (!callInfoHoveredRef.current) setCallInfoTooltip(null);
          }, 150);
        }
        return;
      }
    }
    // 不在 call_info hitbox 上时清除 tooltip（延迟，允许鼠标移入弹窗）
    if (callInfoTooltip && !callInfoHoveredRef.current) {
      if (callInfoClearTimerRef.current) clearTimeout(callInfoClearTimerRef.current);
      callInfoClearTimerRef.current = setTimeout(() => {
        if (!callInfoHoveredRef.current) setCallInfoTooltip(null);
      }, 150);
    }

    // 检测折叠按钮区域或摘要行
    if (x >= COL_FOLD && x < COL_MEMRW) {
      const vi = Math.floor(scrollPosRef.current) + rowIdx;
      if (vi < finalVirtualTotalRows) {
        const resolved = finalResolveVirtualIndex(vi);
        if (resolved.type === "summary") {
          if (textOverlayRef.current) textOverlayRef.current.style.cursor = "pointer";
          return;
        }
        if (resolved.type === "line") {
          const blNode = blLineMap.get(resolved.seq);
          if (blNode && blNode.exit_seq > blNode.entry_seq && !isFolded(blNode.id)) {
            if (textOverlayRef.current) textOverlayRef.current.style.cursor = "pointer";
            return;
          }
        }
      }
    }

    // 检测隐藏摘要行文本区域
    if (x >= COL_MEMRW) {
      const vi = Math.floor(scrollPosRef.current) + rowIdx;
      if (vi < finalVirtualTotalRows) {
        const resolved = finalResolveVirtualIndex(vi);
        if (resolved.type === "hidden-summary") {
          const canvas = canvasRef.current;
          if (canvas) {
            const ctx2 = canvas.getContext("2d");
            if (ctx2) {
              ctx2.font = FONT_ITALIC;
              const textW = ctx2.measureText(`\u2026 ${resolved.count} hidden lines`).width;
              if (x <= COL_MEMRW + textW + 8) {
                if (textOverlayRef.current) textOverlayRef.current.style.cursor = "pointer";
                return;
              }
            }
          }
        }
      }
    }

    // 检测内联注释区域（COL_COMMENT ~ colChanges）→ 显示 tooltip
    if (!commentEditor && x >= COL_COMMENT) {
      const vi = Math.floor(scrollPosRef.current) + rowIdx;
      if (vi < finalVirtualTotalRows) {
        const resolved = finalResolveVirtualIndex(vi);
        if (resolved.type === "line" && highlights) {
          const hlInfo = highlights.get(resolved.seq);
          if (hlInfo?.comment) {
            const canvas = canvasRef.current;
            if (canvas) {
              const ctx2 = canvas.getContext("2d");
              if (ctx2) {
                ctx2.font = FONT;
                const isMultiLine = hlInfo.comment.includes("\n");
                const firstLine = isMultiLine ? hlInfo.comment.split("\n")[0] + " …" : hlInfo.comment;
                const commentLabel = "; " + firstLine;
                const commentW = ctx2.measureText(commentLabel).width;
                const clippedW = Math.min(commentW, colRegBefore - COL_COMMENT);
                if (x <= COL_COMMENT + clippedW) {
                  const container = containerRef.current;
                  if (container) {
                    const rect = container.getBoundingClientRect();
                    setCommentTooltip({
                      seq: resolved.seq,
                      x: rect.left + COL_COMMENT,
                      y: rect.top + rowIdx * ROW_HEIGHT - scrollFrac,
                      text: hlInfo.comment,
                    });
                  }
                  if (textOverlayRef.current) textOverlayRef.current.style.cursor = "pointer";
                  return;
                }
              }
            }
          }
        }
      }
    }
    // 不在注释区域时关闭 tooltip
    if (commentTooltip) setCommentTooltip(null);

    // 检测箭头标签（hitbox 可能延伸到 COL_FOLD 之外）
    for (const lb of arrowLabelHitboxesRef.current) {
      if (x >= lb.x && x <= lb.x + lb.width && y >= lb.y && y <= lb.y + lb.height) {
        if (textOverlayRef.current) textOverlayRef.current.style.cursor = "pointer";
        return;
      }
    }

    // 拖选判定：结合起始位置和拖动方向
    // - 非文本区域（seq/addr 列）：任意方向均为行拖选
    // - 文本区域（disasm/changes 列）：纵向→行拖选，横向→文本选择（交给浏览器）
    if (dragPending.current) {
      const dx = e.clientX - mouseDownPosRef.current.x;
      const dy = e.clientY - mouseDownPosRef.current.y;
      if (dx * dx + dy * dy < 25) return; // 死区 5px
      const shouldRowSelect = !dragInTextArea.current || Math.abs(dy) > Math.abs(dx);
      if (shouldRowSelect) {
        // 行拖选模式
        isDraggingSelect.current = true;
        dragPending.current = false;
        setMultiSelect(null);
        setCtrlSelect(prev => prev.size > 0 ? new Set() : prev);
        dirtyRef.current = true;
        // CSS 禁用文本选择
        if (textOverlayRef.current) {
          textOverlayRef.current.style.userSelect = "none";
          textOverlayRef.current.style.webkitUserSelect = "none";
        }
        window.getSelection()?.removeAllRanges();
      } else {
        // 文本区域横向拖动 → 文本选择，不干预浏览器
        dragPending.current = false;
        return;
      }
    }

    // 行拖选中：更新选择范围
    if (isDraggingSelect.current) {
      const vi = Math.min(Math.floor(scrollPosRef.current) + rowIdx, finalVirtualTotalRows - 1);
      const startVi = Math.min(dragStartVi.current, vi);
      const endVi = Math.max(dragStartVi.current, vi);
      setMultiSelect({ startVi, endVi });
      dirtyRef.current = true;
      if (textOverlayRef.current) textOverlayRef.current.style.cursor = "default";
      return;
    }

    if (textOverlayRef.current) textOverlayRef.current.style.cursor = "text";
  }, [finalVirtualTotalRows, finalResolveVirtualIndex, blLineMap, isFolded, highlights, commentTooltip, callInfoTooltip, commentEditor, visibleLines, canvasSize, effectiveChangesWidth, effectiveDisasmWidth, effectiveBeforeWidth]);

  // 获取当前选中的 seq 列表（多选或单选）
  const getSelectedSeqs = useCallback((): number[] => {
    const seqs: number[] = [];
    const seqSet = new Set<number>();
    // 范围选择
    if (multiSelect) {
      for (let vi = multiSelect.startVi; vi <= multiSelect.endVi; vi++) {
        const r = finalResolveVirtualIndex(vi);
        if (r.type === "line" && !seqSet.has(r.seq)) {
          seqs.push(r.seq);
          seqSet.add(r.seq);
        }
      }
    }
    // Ctrl 任意选择
    for (const vi of ctrlSelect) {
      const r = finalResolveVirtualIndex(vi);
      if (r.type === "line" && !seqSet.has(r.seq)) {
        seqs.push(r.seq);
        seqSet.add(r.seq);
      }
    }
    if (seqs.length > 0) return seqs;
    if (selectedSeq != null) return [selectedSeq];
    return [];
  }, [multiSelect, ctrlSelect, selectedSeq, finalResolveVirtualIndex]);

  // === 复制辅助 ===
  const getSelectedLines = useCallback(async (): Promise<TraceLine[]> => {
    const seqs = getSelectedSeqs();
    if (seqs.length === 0) return [];
    return getLines(seqs);
  }, [getSelectedSeqs, getLines]);

  const copyAs = useCallback(async (format: "raw" | "tab" | "disasm") => {
    const lines = await getSelectedLines();
    if (lines.length === 0) return;
    let text: string;
    if (format === "raw") {
      text = lines.map(l => l.raw).join("\n");
    } else if (format === "tab") {
      text = lines.map(l => `${l.seq + 1}\t${l.address}\t${l.disasm}\t${l.reg_before}\t${l.changes}`).join("\n");
    } else {
      text = lines.map(l => l.disasm).join("\n");
    }
    navigator.clipboard.writeText(text);
    setCtxMenu(null);
  }, [getSelectedLines]);

  // === 右键菜单 ===
  const handleContextMenu = useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    // 清除上次右键的文本选区（防止残留值导致菜单始终显示 Copy）
    textSelectionRef.current = "";
    // 检测右键位置是否命中某个寄存器 hitbox 或 call_info
    const container = containerRef.current;
    ctxRegRef.current = undefined;
    ctxCallInfoRef.current = null;
    if (container) {
      const rect = container.getBoundingClientRect();
      const cx = e.clientX - rect.left;
      const scrollFrac2 = (scrollPosRef.current % 1) * ROW_HEIGHT;
      const rowIdx = Math.floor((e.clientY - rect.top + scrollFrac2) / ROW_HEIGHT);
      // 检测当前行是否有 call_info
      const vi2 = Math.floor(scrollPosRef.current) + rowIdx;
      if (vi2 < finalVirtualTotalRows) {
        const resolved2 = finalResolveVirtualIndex(vi2);
        if (resolved2.type === "line") {
          const line2 = visibleLines.get(resolved2.seq) ?? prefetchCacheRef.current.get(resolved2.seq);
          if (line2?.call_info) {
            ctxCallInfoRef.current = { tooltip: line2.call_info.tooltip, isJni: line2.call_info.is_jni };
          }
        }
      }
      for (const hb of hitboxesRef.current) {
        if (hb.rowIndex === rowIdx && cx >= hb.x && cx <= hb.x + hb.width) {
          ctxRegRef.current = hb.token;
          break;
        }
      }
    }
    const textSel = window.getSelection()?.toString();
    if (textSel && !ctxRegRef.current) {
      // 文本选中模式：保存选中文本（点击菜单项时选区可能已被清除）
      // 注意：命中寄存器 hitbox 时跳过此分支，显示完整菜单
      textSelectionRef.current = textSel;
      setCtxMenu({ x: e.clientX, y: e.clientY });
    } else if (multiSelect || ctrlSelect.size > 0) {
      // 多行选中模式：显示格式选择菜单
      setCtxMenu({ x: e.clientX, y: e.clientY });
    } else if (selectedSeq != null || ctxRegRef.current) {
      // 单行选中或命中寄存器：右键点击时显示完整菜单
      if (!container) return;
      const rect = container.getBoundingClientRect();
      const y = e.clientY - rect.top;
      const scrollFrac = (scrollPosRef.current % 1) * ROW_HEIGHT;
      const rowIdx = Math.floor((y + scrollFrac) / ROW_HEIGHT);
      const vi = Math.floor(scrollPosRef.current) + rowIdx;
      if (vi < finalVirtualTotalRows) {
        const resolved = finalResolveVirtualIndex(vi);
        if (resolved.type === "line" && (resolved.seq === selectedSeq || ctxRegRef.current)) {
          // 临时设置单行 multiSelect 以复用 copyAs 逻辑
          setMultiSelect({ startVi: vi, endVi: vi });
          setCtxMenu({ x: e.clientX, y: e.clientY });
        }
      }
    }
  }, [multiSelect, ctrlSelect, selectedSeq, finalVirtualTotalRows, finalResolveVirtualIndex, visibleLines]);

  // 点击外部自动保存并关闭注释编辑框
  useEffect(() => {
    if (!commentEditor) return;
    const handler = (e: MouseEvent) => {
      if (commentEditorRef.current && !commentEditorRef.current.contains(e.target as Node)) {
        const val = commentTextareaRef.current?.value ?? "";
        if (onSetComment) {
          if (val.trim()) {
            onSetComment(commentEditor.seq, val);
          } else if (onDeleteComment) {
            onDeleteComment(commentEditor.seq);
          }
          dirtyRef.current = true;
        }
        closeCommentEditor();
      }
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [commentEditor, onSetComment, onDeleteComment, closeCommentEditor]);

  // === 键盘事件 ===
  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    // Alt+1~5：高亮颜色
    if (e.altKey && e.key >= "1" && e.key <= "5") {
      e.preventDefault();
      const idx = parseInt(e.key) - 1;
      const seqs = getSelectedSeqs();
      if (seqs.length > 0 && onSetHighlight) {
        onSetHighlight(seqs, { color: HIGHLIGHT_COLORS[idx].key });
        dirtyRef.current = true;
      }
      return;
    }
    // Alt+-：划线
    if (e.altKey && e.key === "-") {
      e.preventDefault();
      const seqs = getSelectedSeqs();
      if (seqs.length > 0 && onToggleStrikethrough) {
        onToggleStrikethrough(seqs);
        dirtyRef.current = true;
      }
      return;
    }
    // Alt+0：重置高亮
    if (e.altKey && e.key === "0") {
      e.preventDefault();
      const seqs = getSelectedSeqs();
      if (seqs.length > 0 && onResetHighlight) {
        onResetHighlight(seqs);
        dirtyRef.current = true;
      }
      return;
    }
    // Ctrl+/：隐藏选中行
    // e.key 在某些键盘布局/系统中可能是 "/" 或通过 e.code 识别为 "Slash"
    if ((e.ctrlKey || e.metaKey) && (e.key === "/" || e.code === "Slash")) {
      e.preventDefault();
      const seqs = getSelectedSeqs();
      if (seqs.length > 0 && onToggleHidden) {
        onToggleHidden(seqs);
        dirtyRef.current = true;
        setMultiSelect(null);
        setCtrlSelect(prev => prev.size > 0 ? new Set() : prev);
      }
      return;
    }
    // ; 打开注释编辑框（IDA 风格）
    // e.key 在某些键盘布局下可能不是 ";"，用 e.code 回退
    if ((e.key === ";" || (e.code === "Semicolon" && !e.shiftKey)) && !e.ctrlKey && !e.metaKey && !e.altKey && !commentEditor) {
      e.preventDefault();
      const seqs = getSelectedSeqs();
      if (seqs.length > 0) {
        openCommentEditor(seqs[0]);
      }
      return;
    }
    // Ctrl+C 复制
    if ((e.ctrlKey || e.metaKey) && e.key === "c") {
      const textSel = window.getSelection()?.toString();
      if (textSel) return; // 让浏览器默认复制文本
      if (multiSelect || ctrlSelect.size > 0) {
        e.preventDefault();
        copyAs("raw");
        return;
      }
    }
    if (e.key === "Escape") {
      if (multiSelect || ctrlSelect.size > 0) {
        setMultiSelect(null);
        setCtrlSelect(prev => prev.size > 0 ? new Set() : prev);
        dirtyRef.current = true;
        return;
      }
      if (arrowState) {
        setArrowState(null);
        return;
      }
      return;
    }
    if (e.key === "PageUp" || e.key === "PageDown") {
      e.preventDefault();
      const delta = e.key === "PageDown" ? visibleRows : -visibleRows;
      setCurrentRow(prev => Math.max(0, Math.min(maxRow, prev + delta)));
      return;
    }
    if (e.key !== "ArrowUp" && e.key !== "ArrowDown") return;
    e.preventDefault();
    if (finalVirtualTotalRows === 0) return;

    const curVIdx = selectedSeq != null ? finalSeqToVirtualIndex(selectedSeq) : -1;
    let nextVIdx: number;
    if (e.key === "ArrowDown") {
      nextVIdx = curVIdx < finalVirtualTotalRows - 1 ? curVIdx + 1 : curVIdx;
    } else {
      nextVIdx = curVIdx > 0 ? curVIdx - 1 : 0;
    }
    const resolved = finalResolveVirtualIndex(nextVIdx);
    const nextSeq = resolved.type === "line" ? resolved.seq : resolved.type === "summary" ? resolved.entrySeq : resolved.seqs[0];
    isInternalClick.current = true;
    onSelectSeq(nextSeq);
    // 自动滚动使该行可见
    if (nextVIdx < currentRow) setCurrentRow(nextVIdx);
    else if (nextVIdx >= currentRow + visibleRows) setCurrentRow(nextVIdx - visibleRows + 1);
  }, [finalVirtualTotalRows, selectedSeq, onSelectSeq, finalSeqToVirtualIndex, finalResolveVirtualIndex,
      arrowState, visibleRows, maxRow, currentRow, multiSelect, copyAs, getSelectedSeqs,
      onSetHighlight, onToggleStrikethrough, onResetHighlight, onToggleHidden, openCommentEditor, commentEditor, ctrlSelect]);

  // === 主绘制函数 ===
  const drawFrame = useCallback(() => {
    COLORS = getCOLORS(); // 刷新当前主题颜色
    const canvas = canvasRef.current;
    if (!canvas || !fontReady) return;
    const ctxOrNull = canvas.getContext("2d");
    if (!ctxOrNull) return;
    const ctx: CanvasRenderingContext2D = ctxOrNull;

    const dpr = window.devicePixelRatio || 1;
    ctx.save();
    ctx.scale(dpr, dpr);
    const W = canvasSize.width;
    const H = canvasSize.height;

    // 清除
    ctx.fillStyle = COLORS.bgPrimary;
    ctx.fillRect(0, 0, W, H);

    ctx.font = FONT;
    ctx.textBaseline = "alphabetic";
    // 等宽字体：所有字符宽度相同，只需测量一次，替代所有 measureText 调用（从 ~1000次/帧 → 1次/帧）
    const charW = ctx.measureText("M").width;

    // 亚像素平滑滚动：从 ref 读取精确位置，绕过 React 状态延迟
    const renderStartRow = Math.floor(scrollPosRef.current);
    const subPxOffset = -(scrollPosRef.current - renderStartRow) * ROW_HEIGHT;

    const hitboxes: TokenHitbox[] = [];
    const useSeqsSet = arrowState ? new Set(arrowState.useSeqs) : null;

    // 折叠/展开 clip 动画
    let clipActive = false;
    let clipTopPx = 0;
    let clipHeightPx = 0;
    let clipBelowOffset = 0; // clip 区域之下的行的 Y 偏移
    const anim = foldAnimRef.current;
    if (anim) {
      const elapsed = performance.now() - anim.startTime;
      const isFoldAnim = anim.direction === "fold";
      const duration = isFoldAnim ? FOLD_ANIM_DURATION : UNFOLD_ANIM_DURATION;
      const t = Math.min(1, elapsed / duration);

      // 缓动函数：折叠用 easeInOutCubic，展开用 easeOutCubic
      let eased: number;
      if (isFoldAnim) {
        // easeInOutCubic：平滑 S 曲线
        eased = t < 0.5
          ? 4 * t * t * t
          : 1 - Math.pow(-2 * t + 2, 3) / 2;
      } else {
        // easeOutCubic：快速开始、缓慢收尾
        eased = 1 - Math.pow(1 - t, 3);
      }

      clipActive = true;
      clipTopPx = anim.clipTopPx;
      // 偏移量预留摘要行空间（ROW_HEIGHT），使动画结束时与 toggleFold 后的状态无缝衔接
      const offsetMax = Math.max(0, anim.clipMaxHeightPx - ROW_HEIGHT);
      if (isFoldAnim) {
        // 折叠：clip 从满高度→0（行从下往上消失）
        clipHeightPx = Math.round(anim.clipMaxHeightPx * (1 - eased));
        // clip 之下的行上移，填补消失的空间（预留摘要行位置）
        clipBelowOffset = Math.round(-(offsetMax * eased));
      } else {
        // 展开：clip 从0→满高度（行从上往下出现）
        clipHeightPx = Math.round(anim.clipMaxHeightPx * eased);
        // clip 之下的行下移，让出空间（预留摘要行已消失的位置）
        clipBelowOffset = Math.round(-(offsetMax * (1 - eased)));
      }

      if (t >= 1) {
        if (isFoldAnim && anim.pendingNodeId != null) {
          toggleFold(anim.pendingNodeId);
          // 折叠完成：保持 clip 遮罩（clipHeight=0）防止旧行在 toggleFold 异步生效前闪现
          // clipHeightPx 已经是 0，clipActive 保持 true，下一帧 foldAnimRef 为 null 自然消除
        } else {
          clipActive = false;
        }
        foldAnimRef.current = null;
        dirtyRef.current = true; // 确保下一帧重绘以反映新的折叠状态
        if (textOverlayRef.current) textOverlayRef.current.style.visibility = "visible";
      } else {
        dirtyRef.current = true;
        if (textOverlayRef.current) textOverlayRef.current.style.visibility = "hidden";
      }
    }

    for (let i = 0; i < visibleRows + 2; i++) {
      const vi = renderStartRow + i;
      if (vi >= finalVirtualTotalRows) break;
      const resolved = finalResolveVirtualIndex(vi);
      const baseY = i * ROW_HEIGHT + subPxOffset;

      // 动画时计算 Y 偏移
      let y = baseY;
      let inClipRegion = false;
      if (clipActive) {
        const clipBottom = clipTopPx + clipHeightPx;
        if (baseY >= clipTopPx && baseY < clipTopPx + anim!.clipMaxHeightPx) {
          // 行在 clip 区域内（被折叠/展开的行）
          inClipRegion = true;
        } else if (baseY >= clipTopPx + anim!.clipMaxHeightPx) {
          // 行在 clip 区域之下：应用偏移
          y = baseY + clipBelowOffset;
        }
      }

      if (y >= H || y + ROW_HEIGHT <= 0) continue;

      // clip 区域内的行：用 clip rect 限制渲染
      if (inClipRegion && clipActive) {
        if (baseY + ROW_HEIGHT > clipTopPx + clipHeightPx) {
          // 行的部分或全部在 clip 可见区域之外，跳过
          if (baseY >= clipTopPx + clipHeightPx) continue;
          // 部分可见：后面会用 clip 处理
        }
        ctx.save();
        ctx.beginPath();
        ctx.rect(0, clipTopPx, W, clipHeightPx);
        ctx.clip();
      }
      const needClipRestore = inClipRegion && clipActive;

      // --- 背景 ---
      let bgColor: string;
      if (resolved.type === "line" && resolved.seq === selectedSeq) {
        bgColor = COLORS.bgSelected;
      } else if (resolved.type === "line" && arrowState) {
        if (resolved.seq === arrowState.anchorSeq) bgColor = COLORS.arrowAnchorBg;
        else if (resolved.seq === arrowState.defSeq) bgColor = COLORS.arrowDefBg;
        else if (useSeqsSet?.has(resolved.seq)) bgColor = COLORS.arrowUseBg;
        else bgColor = vi % 2 === 0 ? COLORS.bgRowEven : COLORS.bgRowOdd;
      } else if (resolved.type === "summary") {
        bgColor = COLORS.bgSecondary;
      } else {
        bgColor = vi % 2 === 0 ? COLORS.bgRowEven : COLORS.bgRowOdd;
      }
      const rowW = W - RIGHT_GUTTER; // 行背景不延伸到 minimap/scrollbar 区域
      ctx.fillStyle = bgColor;
      ctx.fillRect(0, y, rowW, ROW_HEIGHT);

      // hover 高亮（非选中行叠加微弱白色）
      if (i === hoverRowRef.current && !(resolved.type === "line" && resolved.seq === selectedSeq)) {
        ctx.fillStyle = COLORS.bgHover;
        ctx.fillRect(0, y, rowW, ROW_HEIGHT);
      }

      // 持久化高亮背景
      const hlInfo = resolved.type === "line" && highlights ? highlights.get(resolved.seq) : undefined;
      if (hlInfo?.color) {
        const hlColor = HIGHLIGHT_COLORS.find(c => c.key === hlInfo.color);
        if (hlColor) {
          ctx.fillStyle = hlColor.color;
          ctx.fillRect(0, y, rowW, ROW_HEIGHT);
        }
      }

      // 多选高亮（范围选择 + Ctrl 任意选择）
      if ((multiSelect && vi >= multiSelect.startVi && vi <= multiSelect.endVi) || ctrlSelect.has(vi)) {
        ctx.fillStyle = COLORS.bgMultiSelect;
        ctx.fillRect(0, y, rowW, ROW_HEIGHT);
      }

      // 切片高亮
      const lineSeq = resolved.type === "line" ? resolved.seq : -1;
      // filter-only 模式下所有可见行都是污点行，无需查 map；
      // highlight 模式下先查 React state，fallback 到预取缓存 ref
      const isTainted = sliceActive && lineSeq >= 0 && (
        taintFilterActive
          ? true
          : (sliceStatuses.get(lineSeq) ?? sliceStatusCacheRef.current.get(lineSeq) ?? false)
      );
      const isSourceLine = sliceActive && lineSeq >= 0 && lineSeq === sliceSourceSeq;
      if (sliceActive && resolved.type === "line") {
        if (isTainted || isSourceLine) {
          // 左侧竖条：污点源行始终橙色，普通污点行绿色
          ctx.fillStyle = isSourceLine ? COLORS.taintSourceMark : COLORS.taintMark;
          ctx.fillRect(0, y, 3, ROW_HEIGHT);
        } else {
          // 未标记行变灰
          ctx.globalAlpha = 0.3;
        }
      }

      const textY = y + TEXT_BASELINE_Y;

      if (resolved.type === "summary") {
        // --- 折叠摘要行 ---
        ctx.font = FONT;
        ctx.fillStyle = COLORS.textSecondary;
        ctx.fillText("\u25B6", COL_FOLD + 8, textY); // ▶

        const summaryX = COL_MEMRW;
        ctx.font = FONT_ITALIC;
        ctx.fillStyle = COLORS.asmMnemonic;
        const funcLabel = `Func ${resolved.funcAddr}`;
        ctx.fillText(funcLabel, summaryX, textY);
        const funcLabelW = funcLabel.length * charW;

        ctx.font = FONT;
        ctx.fillStyle = COLORS.textSecondary;
        ctx.fillText(`(${resolved.lineCount.toLocaleString()} lines)`, summaryX + funcLabelW + 6, textY);
        if (needClipRestore) ctx.restore();
        continue;
      }

      if (resolved.type === "hidden-summary") {
        // --- 隐藏摘要行 ---
        ctx.font = FONT_ITALIC;
        ctx.fillStyle = COLORS.textSecondary;
        ctx.fillText(`\u2026 ${resolved.count} hidden lines`, COL_MEMRW, textY);
        if (needClipRestore) ctx.restore();
        continue;
      }

      // --- 正常行 ---
      const seq = resolved.seq;
      const line = visibleLines.get(seq) ?? prefetchCacheRef.current.get(seq);

      // Fold 按钮（▼）
      const blNode = blLineMap.get(seq);
      const hasFoldBtn = blNode && blNode.exit_seq > blNode.entry_seq && !isFolded(blNode.id);
      if (hasFoldBtn) {
        ctx.fillStyle = COLORS.textSecondary;
        ctx.fillText("\u25BC", COL_FOLD + 8, textY); // ▼
      }

      // Seq（始终显示）
      ctx.fillStyle = COLORS.textSecondary;
      ctx.fillText(String(seq + 1), COL_SEQ, textY);

      // 数据未加载时显示占位符，避免快速滚动时出现空白区域
      if (!line) {
        const prevAlpha = ctx.globalAlpha;
        ctx.globalAlpha = prevAlpha * 0.2;
        ctx.fillStyle = COLORS.textSecondary;
        ctx.fillText("\u2500\u2500\u2500", COL_DISASM, textY);
        // 恢复切片变灰的 alpha
        if (sliceActive && !isTainted && !isSourceLine) ctx.globalAlpha = 1.0;
        else ctx.globalAlpha = prevAlpha;
        if (needClipRestore) ctx.restore();
        continue;
      }

      // MemRW
      if (line.mem_rw === "W" || line.mem_rw === "R") {
        ctx.fillStyle = COLORS.textSecondary;
        ctx.fillText(line.mem_rw, COL_MEMRW, textY);
      }

      // Address
      if (line.address || line.so_offset) {
        let curX = COL_ADDR;

        if (preferences.showSoName && line.so_name) {
          const soText = `[${line.so_name}] `;
          ctx.fillStyle = COLORS.textSoName;
          ctx.fillText(soText, curX, textY);
          curX += ctx.measureText(soText).width;
        }

        if (preferences.showAbsAddress && line.address) {
          ctx.fillStyle = COLORS.textAbsAddress;
          ctx.fillText(line.address, curX, textY);
          curX += ctx.measureText(line.address).width;
          ctx.fillStyle = COLORS.textAddress;
          ctx.fillText("!", curX, textY);
          curX += ctx.measureText("!").width;
        }

        const offsetText = line.so_offset || line.address;
        ctx.fillStyle = COLORS.textAddress;
        ctx.fillText(offsetText, curX, textY);
      }

      // Disasm（语法高亮 + hitbox）
      if (line?.disasm) {
        ctx.font = FONT;
        let curX = COL_DISASM;
        let isFirst = true;
        let lastIdx = 0;
        let match: RegExpExecArray | null;
        TOKEN_RE.lastIndex = 0;

        const activeReg = arrowState?.anchorSeq === seq ? arrowState.regName : null;

        while ((match = TOKEN_RE.exec(line.disasm)) !== null) {
          // 间隔文字
          if (match.index > lastIdx) {
            const gap = line.disasm.slice(lastIdx, match.index);
            ctx.fillStyle = COLORS.textPrimary;
            ctx.fillText(gap, curX, textY);
            curX += gap.length * charW;
          }
          const token = match[0];
          const color = canvasTokenColor(token, isFirst);
          const isReg = !isFirst && REG_RE.test(token);
          const tokenW = token.length * charW;

          ctx.fillStyle = color;
          ctx.fillText(token, curX, textY);

          // activeReg 下划线
          if (isReg && activeReg && token.toLowerCase() === activeReg.toLowerCase()) {
            ctx.strokeStyle = color;
            ctx.lineWidth = 1;
            ctx.beginPath();
            ctx.moveTo(curX, textY + 2);
            ctx.lineTo(curX + tokenW, textY + 2);
            ctx.stroke();
          }

          if (isReg) {
            hitboxes.push({ x: curX, width: tokenW, rowIndex: i, token, seq });
          }

          curX += tokenW;
          isFirst = false;
          lastIdx = TOKEN_RE.lastIndex;
        }
        // 尾部文字
        if (lastIdx < line.disasm.length) {
          const tail = line.disasm.slice(lastIdx);
          ctx.fillStyle = COLORS.textPrimary;
          ctx.fillText(tail, curX, textY);
          curX += tail.length * charW;
        }

        // Call info inline rendering (gumtrace external function call summary)
        if (line.call_info) {
          const ci = line.call_info;
          const gap = charW * 2; // 2 char spacing
          const ciX = curX + gap;
          ctx.font = FONT_ITALIC;
          ctx.fillStyle = ci.is_jni ? COLORS.callInfoJni : COLORS.callInfoNormal;
          const ciText = ci.summary.length > 80 ? ci.summary.slice(0, 80) + "..." : ci.summary;
          const maxCiChars = Math.floor((colRegBefore - ciX) / charW);
          const displayText = ciText.length > maxCiChars && maxCiChars > 1
            ? ciText.slice(0, maxCiChars - 1) + "\u2026"
            : ciText;
          if (maxCiChars > 0) {
            ctx.fillText(displayText, ciX, textY);
            const ciWidth = displayText.length * charW;
            hitboxes.push({ x: ciX, width: ciWidth, rowIndex: i, token: `__call_info__${seq}`, seq });
          }
          ctx.font = FONT; // restore font
        }
      }

      // 内联注释（固定对齐位置 COL_COMMENT）
      if (hlInfo?.comment) {
        ctx.font = FONT;
        ctx.fillStyle = COLORS.commentInline;
        const isMultiLine = hlInfo.comment.includes("\n");
        const firstLine = isMultiLine ? hlInfo.comment.split("\n")[0] + " …" : hlInfo.comment;
        const commentLabel = "; " + firstLine;
        const commentX = COL_COMMENT;
        // 裁剪到 before 列之前
        ctx.save();
        ctx.beginPath();
        ctx.rect(commentX, y, colRegBefore - commentX, ROW_HEIGHT);
        ctx.clip();
        ctx.fillText(commentLabel, commentX, textY);
        ctx.restore();
      }

      // Before（裁剪到列宽，位于 Disasm 和 Changes 之间）
      if (line?.reg_before) {
        ctx.font = FONT;
        ctx.fillStyle = COLORS.textSecondary;
        ctx.save();
        ctx.beginPath();
        ctx.rect(colRegBefore, y, effectiveBeforeWidth, ROW_HEIGHT);
        ctx.clip();
        ctx.fillText(line.reg_before, colRegBefore, textY);
        ctx.restore();
      }

      // Changes（裁剪到列宽）
      if (line?.changes) {
        ctx.font = FONT;
        ctx.fillStyle = COLORS.textChanges;
        ctx.save();
        ctx.beginPath();
        ctx.rect(colChanges, y, effectiveChangesWidth, ROW_HEIGHT);
        ctx.clip();
        ctx.fillText(line.changes, colChanges, textY);
        ctx.restore();
      }

      // 划线（strikethrough）
      if (hlInfo?.strikethrough) {
        ctx.strokeStyle = COLORS.strikethroughLine;
        ctx.lineWidth = 1;
        ctx.beginPath();
        const strikeY = y + ROW_HEIGHT / 2;
        ctx.moveTo(COL_MEMRW, strikeY);
        ctx.lineTo(W - RIGHT_GUTTER, strikeY);
        ctx.stroke();
      }

      // 恢复切片变灰的 alpha
      if (sliceActive && resolved.type === "line" && !isTainted) {
        ctx.globalAlpha = 1.0;
      }

      if (needClipRestore) ctx.restore();
    }

    hitboxesRef.current = hitboxes;

    // === DEF/USE 箭头绘制 ===
    const arrowLabels: ArrowLabelHitbox[] = [];

    if (arrowState) {
      const anchorVIdx = finalSeqToVirtualIndex(arrowState.anchorSeq);
      const anchorLocalY = (anchorVIdx - renderStartRow) * ROW_HEIGHT + subPxOffset + ROW_HEIGHT / 2;
      const defStartY = anchorLocalY - ANCHOR_GAP;
      const useStartY = anchorLocalY + ANCHOR_GAP;

      const firstVI = renderStartRow;
      const lastVI = renderStartRow + visibleRows;

      // 辅助：虚拟索引 → 本地 y
      const viToY = (vi: number) => (vi - renderStartRow) * ROW_HEIGHT + subPxOffset + ROW_HEIGHT / 2;

      // 圆点
      for (let i = 0; i < visibleRows + 1; i++) {
        const vi = renderStartRow + i;
        if (vi >= finalVirtualTotalRows) break;
        const resolved2 = finalResolveVirtualIndex(vi);
        if (resolved2.type !== "line") continue;
        const dotY = i * ROW_HEIGHT + subPxOffset + ROW_HEIGHT / 2;
        const seq2 = resolved2.seq;

        let fill: string;
        let r: number;
        let alpha: number;

        if (seq2 === arrowState.anchorSeq) {
          fill = COLORS.arrowAnchor; r = 3; alpha = 1;
        } else if (seq2 === arrowState.defSeq || useSeqsSet?.has(seq2)) {
          fill = COLORS.textSecondary; r = 2.5; alpha = 0.6;
        } else {
          fill = COLORS.textSecondary; r = 2; alpha = 0.3;
        }

        ctx.globalAlpha = alpha;
        ctx.fillStyle = fill;
        ctx.beginPath();
        ctx.arc(COL_ARROW + DOT_X, dotY, r, 0, Math.PI * 2);
        ctx.fill();
      }
      ctx.globalAlpha = 1;

      const arrowBaseX = COL_ARROW;

      // 绘制弯曲路径的辅助函数
      function drawCurvedPath(fromY: number, toY: number, vertX: number, color: string) {
        const dy = toY < fromY ? -BEND_R : BEND_R;
        ctx.strokeStyle = color;
        ctx.lineWidth = 1.5;
        ctx.beginPath();
        ctx.moveTo(arrowBaseX + CONN_X, fromY);
        ctx.lineTo(arrowBaseX + vertX + BEND_R, fromY);
        ctx.quadraticCurveTo(arrowBaseX + vertX, fromY, arrowBaseX + vertX, fromY + dy);
        ctx.lineTo(arrowBaseX + vertX, toY - dy);
        ctx.quadraticCurveTo(arrowBaseX + vertX, toY, arrowBaseX + vertX + BEND_R, toY);
        ctx.lineTo(arrowBaseX + CONN_X, toY);
        ctx.stroke();
      }

      function drawTrunkPath(startY: number, endY: number, vertX: number, dir: 1 | -1, color: string) {
        const dy = dir * BEND_R;
        ctx.strokeStyle = color;
        ctx.lineWidth = 1.5;
        ctx.beginPath();
        ctx.moveTo(arrowBaseX + CONN_X, startY);
        ctx.lineTo(arrowBaseX + vertX + BEND_R, startY);
        ctx.quadraticCurveTo(arrowBaseX + vertX, startY, arrowBaseX + vertX, startY + dy);
        ctx.lineTo(arrowBaseX + vertX, endY);
        ctx.stroke();
      }

      function drawArrowHead(x: number, y2: number, color: string) {
        ctx.fillStyle = color;
        ctx.beginPath();
        ctx.moveTo(x, y2);
        ctx.lineTo(x - 4, y2 - 3);
        ctx.lineTo(x - 4, y2 + 3);
        ctx.closePath();
        ctx.fill();
      }

      function drawBranch(vertX: number, y2: number, color: string) {
        ctx.strokeStyle = color;
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.moveTo(arrowBaseX + vertX, y2);
        ctx.lineTo(arrowBaseX + CONN_X, y2);
        ctx.stroke();
      }

      // 绘制边缘标签（越界时的行号提示，可点击跳转）
      function drawEdgeLabel(
        seq: number, atTop: boolean, color: string, prefix: string
      ) {
        ctx.fillStyle = color;
        ctx.font = '9px monospace';
        const label = `${prefix}#${seq + 1}`;
        const labelW = ctx.measureText(label).width;
        const labelX = arrowBaseX;
        const labelY = atTop ? 13 : H - 6;
        ctx.fillText(label, labelX, labelY);
        arrowLabels.push({
          x: labelX,
          y: atTop ? 0 : H - EDGE_LABEL_PAD,
          width: Math.max(labelW, ARROW_COL_WIDTH),
          height: EDGE_LABEL_PAD,
          seq,
        });
        ctx.font = FONT;
      }

      // 绘制竖线段
      function drawVerticalSegment(fromY: number, toY: number, vertX: number, color: string) {
        ctx.strokeStyle = color;
        ctx.lineWidth = 1.5;
        ctx.beginPath();
        ctx.moveTo(arrowBaseX + vertX, fromY);
        ctx.lineTo(arrowBaseX + vertX, toY);
        ctx.stroke();
      }

      const anchorVisible = anchorVIdx >= firstVI && anchorVIdx < lastVI;

      // === DEF 箭头（绿色，向上） ===
      if (arrowState.defSeq !== null) {
        const defVIdx = finalSeqToVirtualIndex(arrowState.defSeq);
        const defY = viToY(defVIdx);
        const defVisible = defVIdx >= firstVI && defVIdx < lastVI;

        if (anchorVisible && defVisible) {
          // 情况 1: 两端都可见 → 完整弯曲路径
          drawCurvedPath(defStartY, defY, VERT_X_DEF, COLORS.arrowDef);
          drawArrowHead(arrowBaseX + CONN_X, defY, COLORS.arrowDef);

        } else if (anchorVisible && !defVisible) {
          // 情况 2/3: 锚点可见，DEF 越界
          if (defVIdx < firstVI) {
            drawTrunkPath(defStartY, EDGE_LABEL_PAD, VERT_X_DEF, -1, COLORS.arrowDef);
            drawEdgeLabel(arrowState.defSeq, true, COLORS.arrowDef, "\u2191");
          } else {
            drawTrunkPath(defStartY, H - EDGE_LABEL_PAD, VERT_X_DEF, 1, COLORS.arrowDef);
            drawEdgeLabel(arrowState.defSeq, false, COLORS.arrowDef, "\u2193");
          }

        } else if (!anchorVisible && defVisible) {
          // 情况 4/5: 锚点越界，DEF 可见
          if (anchorVIdx < firstVI) {
            drawVerticalSegment(EDGE_LABEL_PAD, defY, VERT_X_DEF, COLORS.arrowDef);
            drawBranch(VERT_X_DEF, defY, COLORS.arrowDef);
            drawArrowHead(arrowBaseX + CONN_X, defY, COLORS.arrowDef);
            drawEdgeLabel(arrowState.anchorSeq, true, COLORS.arrowAnchor, "\u2191");
          } else {
            drawVerticalSegment(H - EDGE_LABEL_PAD, defY, VERT_X_DEF, COLORS.arrowDef);
            drawBranch(VERT_X_DEF, defY, COLORS.arrowDef);
            drawArrowHead(arrowBaseX + CONN_X, defY, COLORS.arrowDef);
            drawEdgeLabel(arrowState.anchorSeq, false, COLORS.arrowAnchor, "\u2193");
          }

        } else {
          // 情况 6: 两端都越界
          if ((defVIdx < firstVI && anchorVIdx >= lastVI) ||
              (defVIdx >= lastVI && anchorVIdx < firstVI)) {
            // 对侧越界 → 竖线穿过视口
            drawVerticalSegment(EDGE_LABEL_PAD, H - EDGE_LABEL_PAD, VERT_X_DEF, COLORS.arrowDef);
            if (defVIdx < firstVI) {
              drawEdgeLabel(arrowState.defSeq, true, COLORS.arrowDef, "\u2191");
              drawEdgeLabel(arrowState.anchorSeq, false, COLORS.arrowAnchor, "\u2193");
            } else {
              drawEdgeLabel(arrowState.anchorSeq, true, COLORS.arrowAnchor, "\u2191");
              drawEdgeLabel(arrowState.defSeq, false, COLORS.arrowDef, "\u2193");
            }
          }
          // 同侧越界 → 不绘制
        }
      }

      // === USE 箭头（蓝色，向下） ===
      if (arrowState.useSeqs.length > 0) {
        const firstUseSeq = arrowState.useSeqs[0];
        const lastUseSeq = arrowState.useSeqs[arrowState.useSeqs.length - 1];
        const firstUseVIdx = finalSeqToVirtualIndex(firstUseSeq);
        const lastUseVIdx = finalSeqToVirtualIndex(lastUseSeq);

        // trunk 终点：最后一个 USE 的位置，clamp 到视口
        const trunkEndY = lastUseVIdx < lastVI
          ? viToY(lastUseVIdx)
          : H - EDGE_LABEL_PAD;

        // trunk 起点
        if (anchorVisible) {
          drawTrunkPath(useStartY, trunkEndY, VERT_X_DEF, 1, COLORS.arrowUse);
        } else if (anchorVIdx < firstVI) {
          // 锚点在上方越界
          if (lastUseVIdx >= firstVI) {
            drawVerticalSegment(EDGE_LABEL_PAD, trunkEndY, VERT_X_DEF, COLORS.arrowUse);
          }
          drawEdgeLabel(arrowState.anchorSeq, true, COLORS.arrowAnchor, "\u2191");
        } else {
          // 锚点在下方越界（防御性处理）
          if (firstUseVIdx < lastVI) {
            drawVerticalSegment(H - EDGE_LABEL_PAD, viToY(firstUseVIdx), VERT_X_DEF, COLORS.arrowUse);
          }
          drawEdgeLabel(arrowState.anchorSeq, false, COLORS.arrowAnchor, "\u2193");
        }

        // 分支 + 箭头（仅视口内的 USE）
        for (const useSeq of arrowState.useSeqs) {
          const useVIdx = finalSeqToVirtualIndex(useSeq);
          if (useVIdx >= firstVI && useVIdx < lastVI) {
            const useY = viToY(useVIdx);
            drawBranch(VERT_X_DEF, useY, COLORS.arrowUse);
            drawArrowHead(arrowBaseX + CONN_X, useY, COLORS.arrowUse);
          }
        }

        // 上方越界的 USE 标签
        if (firstUseVIdx < firstVI) {
          drawEdgeLabel(firstUseSeq, true, COLORS.arrowUse, "\u2191");
        }

        // 下方越界的 USE 标签
        if (lastUseVIdx >= lastVI) {
          drawEdgeLabel(lastUseSeq, false, COLORS.arrowUse, "\u2193");
        }
      }
    }

    arrowLabelHitboxesRef.current = arrowLabels;

    ctx.restore();
  }, [canvasSize, visibleRows, finalVirtualTotalRows, finalResolveVirtualIndex,
      visibleLines, selectedSeq, arrowState, effectiveChangesWidth, effectiveDisasmWidth, effectiveBeforeWidth, fontReady,
      blLineMap, isFolded, finalSeqToVirtualIndex, toggleFold, multiSelect, ctrlSelect, highlights,
      sliceActive, sliceStatuses, sliceSourceSeq, taintFilterActive,
      COL_ADDR, COL_DISASM, _themeId, preferences.showSoName, preferences.showAbsAddress]);

  // drawFrame 通过 ref 暴露给 RAF 循环，避免 RAF useEffect 因 drawFrame 重建而重启导致掉帧
  const drawFrameRef = useRef(drawFrame);
  drawFrameRef.current = drawFrame;

  // === DOM 文本层同步（支持文本选择/复制，debouncedRow 驱动避免滚动卡顿） ===
  useEffect(() => {
    const overlay = textOverlayRef.current;
    if (!overlay) return;
    // 清空旧内容
    overlay.textContent = "";

    // CSS Grid 列模板：与 Canvas 列位置精确对齐（推式布局，Changes 为 1fr 吸收剩余宽度）
    const gridCols = `${COL_FOLD}px ${COL_MEMRW - COL_FOLD}px ${COL_SEQ - COL_MEMRW}px ${COL_ADDR - COL_SEQ}px ${COL_DISASM - COL_ADDR}px ${effectiveDisasmWidth}px ${HANDLE_W}px ${effectiveBeforeWidth}px ${HANDLE_W}px ${effectiveChangesWidth}px`;

    for (let i = 0; i < visibleRows + 1; i++) {
      const vi = debouncedRow + i;
      if (vi >= finalVirtualTotalRows) break;
      const resolved = finalResolveVirtualIndex(vi);

      const rowDiv = document.createElement("div");
      rowDiv.style.display = "grid";
      rowDiv.style.gridTemplateColumns = gridCols;
      rowDiv.style.height = ROW_HEIGHT + "px";
      rowDiv.style.lineHeight = ROW_HEIGHT + "px";
      rowDiv.style.whiteSpace = "nowrap";

      // Arrow 列占位
      const arrowSpan = document.createElement("span");
      rowDiv.appendChild(arrowSpan);

      // Fold 列
      const foldSpan = document.createElement("span");
      if (resolved.type === "summary") {
        foldSpan.textContent = "\u25B6";
      }
      rowDiv.appendChild(foldSpan);

      if (resolved.type === "summary") {
        const memSpan = document.createElement("span");
        rowDiv.appendChild(memSpan);
        const seqSpan = document.createElement("span");
        rowDiv.appendChild(seqSpan);
        const addrSpan = document.createElement("span");
        rowDiv.appendChild(addrSpan);

        const disasmSpan = document.createElement("span");
        disasmSpan.textContent = `Func ${resolved.funcAddr} (${resolved.lineCount.toLocaleString()} lines)`;
        rowDiv.appendChild(disasmSpan);
        rowDiv.appendChild(document.createElement("span")); // handle Disasm|Before
        const regBeforeSpan = document.createElement("span");
        rowDiv.appendChild(regBeforeSpan);
        rowDiv.appendChild(document.createElement("span")); // handle Before|Changes
        const changesSpan = document.createElement("span");
        rowDiv.appendChild(changesSpan);
      } else if (resolved.type === "hidden-summary") {
        // hidden-summary: placeholder row for text overlay
        const memSpan = document.createElement("span");
        rowDiv.appendChild(memSpan);
        const seqSpan = document.createElement("span");
        rowDiv.appendChild(seqSpan);
        const addrSpan = document.createElement("span");
        rowDiv.appendChild(addrSpan);
        const disasmSpan = document.createElement("span");
        disasmSpan.textContent = `Hidden (${resolved.count} lines)`;
        rowDiv.appendChild(disasmSpan);
        rowDiv.appendChild(document.createElement("span")); // handle Disasm|Before
        const regBeforeSpan = document.createElement("span");
        rowDiv.appendChild(regBeforeSpan);
        rowDiv.appendChild(document.createElement("span")); // handle Before|Changes
        const changesSpan = document.createElement("span");
        rowDiv.appendChild(changesSpan);
      } else {
        const cols = lineToTextColumns(resolved.seq, visibleLines.get(resolved.seq) ?? prefetchCacheRef.current.get(resolved.seq));

        const memSpan = document.createElement("span");
        memSpan.textContent = cols.memRW;
        rowDiv.appendChild(memSpan);

        const seqSpan = document.createElement("span");
        seqSpan.textContent = cols.seqText;
        rowDiv.appendChild(seqSpan);

        const addrSpan = document.createElement("span");
        addrSpan.textContent = cols.addr;
        rowDiv.appendChild(addrSpan);

        const disasmSpan = document.createElement("span");
        disasmSpan.style.overflow = "hidden";
        disasmSpan.textContent = cols.disasm;
        rowDiv.appendChild(disasmSpan);
        rowDiv.appendChild(document.createElement("span")); // handle

        const regBeforeSpan = document.createElement("span");
        regBeforeSpan.style.overflow = "hidden";
        regBeforeSpan.textContent = cols.regBefore;
        rowDiv.appendChild(regBeforeSpan);
        rowDiv.appendChild(document.createElement("span")); // handle Before|Changes

        const changesSpan = document.createElement("span");
        changesSpan.style.overflow = "hidden";
        changesSpan.textContent = cols.changes;
        rowDiv.appendChild(changesSpan);
      }

      overlay.appendChild(rowDiv);
    }
  }, [debouncedRow, visibleRows, finalVirtualTotalRows, finalResolveVirtualIndex, visibleLines, canvasSize.width, effectiveChangesWidth, effectiveDisasmWidth, effectiveBeforeWidth, COL_DISASM]);

  // === 脏标记（useLayoutEffect 确保在 paint 前同步设置，配合 RAF 实现同帧渲染） ===
  useLayoutEffect(() => { dirtyRef.current = true; }, [
    currentRow, selectedSeq, arrowState, canvasSize, effectiveChangesWidth, effectiveDisasmWidth, effectiveBeforeWidth,
    visibleLines, finalVirtualTotalRows, fontReady, highlights, ctrlSelect,
    sliceActive, sliceStatuses, sliceSourceSeq,
  ]);

  // === rAF 渲染循环（通过 drawFrameRef 解耦，循环永不重启，消除掉帧） ===
  useEffect(() => {
    let running = true;
    const loop = () => {
      if (!running) return;
      if (dirtyRef.current) {
        dirtyRef.current = false;
        drawFrameRef.current();
        // 同步文本覆盖层的亚像素偏移，确保文本选择与 canvas 对齐
        if (textOverlayRef.current) {
          const subPx = -(scrollPosRef.current - Math.floor(scrollPosRef.current)) * ROW_HEIGHT;
          textOverlayRef.current.style.transform = `translateY(${subPx}px)`;
        }
      }
      rafIdRef.current = requestAnimationFrame(loop);
    };
    rafIdRef.current = requestAnimationFrame(loop);
    return () => { running = false; cancelAnimationFrame(rafIdRef.current); };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // === 空状态 ===
  if (!isLoaded) {
    return (
      <div
        style={{
          height: "100%",
          display: "flex",
          flexDirection: "column",
          background: "var(--bg-primary)",
        }}
      >
        <TableHeader disasmWidth={effectiveDisasmWidth} regBeforeWidth={effectiveBeforeWidth} seqWidth={seqCol.width} addrWidth={addrCol.width} onDisasmResizeMouseDown={disasmCol.onMouseDown} onRegBeforeResizeMouseDown={regBeforeCol.onMouseDown} onSeqResizeMouseDown={seqCol.onMouseDown} onAddrResizeMouseDown={addrCol.onMouseDown} showSoName={preferences.showSoName} showAbsAddress={preferences.showAbsAddress} onToggleSoName={handleToggleSoName} onToggleAbsAddress={handleToggleAbsAddress} />
        <div
          style={{
            flex: 1,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
          }}
        >
          <span style={{ color: "var(--text-secondary)" }}>
            Drop or click Open to load a trace file
          </span>
        </div>
      </div>
    );
  }

  return (
    <div style={{ height: "100%", display: "flex", flexDirection: "column", background: "var(--bg-primary)" }}>
      <TableHeader disasmWidth={effectiveDisasmWidth} regBeforeWidth={effectiveBeforeWidth} seqWidth={seqCol.width} addrWidth={addrCol.width} onDisasmResizeMouseDown={disasmCol.onMouseDown} onRegBeforeResizeMouseDown={regBeforeCol.onMouseDown} onSeqResizeMouseDown={seqCol.onMouseDown} onAddrResizeMouseDown={addrCol.onMouseDown} showSoName={preferences.showSoName} showAbsAddress={preferences.showAbsAddress} onToggleSoName={handleToggleSoName} onToggleAbsAddress={handleToggleAbsAddress} />
      <div
        ref={containerRef}
        tabIndex={0}
        onKeyDown={handleKeyDown}
        style={{ flex: 1, position: "relative", outline: "none", overflow: "hidden" }}
      >
        <canvas
          ref={canvasRef}
          style={{ position: "absolute", top: 0, left: 0, pointerEvents: "none" }}
        />
        <div
          ref={textOverlayRef}
          onMouseDown={handleOverlayMouseDown}
          onMouseUp={handleOverlayMouseUp}
          onDoubleClick={handleOverlayDblClick}
          onMouseMove={handleCanvasMouseMove}
          onMouseLeave={() => { isDraggingSelect.current = false; dragPending.current = false; if (hoverRowRef.current !== -1) { hoverRowRef.current = -1; dirtyRef.current = true; } if (textOverlayRef.current) { textOverlayRef.current.style.userSelect = "text"; textOverlayRef.current.style.webkitUserSelect = "text"; } }}
          onContextMenu={handleContextMenu}
          style={{
            position: "absolute",
            top: 0,
            left: 0,
            width: canvasSize.width > 0 ? canvasSize.width - RIGHT_GUTTER : `calc(100% - ${RIGHT_GUTTER}px)`,
            height: `calc(100% + ${ROW_HEIGHT}px)`,
            zIndex: 1,
            color: "transparent",
            font: FONT,
            userSelect: "text",
            WebkitUserSelect: "text",
            cursor: "text",
            overflow: "hidden",
          }}
        />
        {/* 右键菜单 */}
        {ctxMenu && (
          <ContextMenu x={ctxMenu.x} y={ctxMenu.y} onClose={() => { setCtxMenu(null); setHighlightSubmenuOpen(false); textSelectionRef.current = ""; }}>
            {textSelectionRef.current ? (
              <div
                onClick={() => { navigator.clipboard.writeText(textSelectionRef.current); textSelectionRef.current = ""; setCtxMenu(null); }}
                onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.background = "var(--bg-selected)"; setHighlightSubmenuOpen(false); }}
                onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.background = "transparent"; }}
                style={{ padding: "6px 12px", fontSize: 12, color: "var(--text-primary)", cursor: "pointer", whiteSpace: "nowrap" }}
              >Copy</div>
            ) : (
              <>
                <div
                  onClick={() => copyAs("raw")}
                  onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.background = "var(--bg-selected)"; setHighlightSubmenuOpen(false); }}
                  onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.background = "transparent"; }}
                  style={{ padding: "6px 12px", fontSize: 12, color: "var(--text-primary)", cursor: "pointer", whiteSpace: "nowrap" }}
                >Copy as Original Trace</div>
                <div
                  onClick={() => copyAs("tab")}
                  onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.background = "var(--bg-selected)"; setHighlightSubmenuOpen(false); }}
                  onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.background = "transparent"; }}
                  style={{ padding: "6px 12px", fontSize: 12, color: "var(--text-primary)", cursor: "pointer", whiteSpace: "nowrap" }}
                >Copy as Tab-Separated</div>
                <div
                  onClick={() => copyAs("disasm")}
                  onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.background = "var(--bg-selected)"; setHighlightSubmenuOpen(false); }}
                  onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.background = "transparent"; }}
                  style={{ padding: "6px 12px", fontSize: 12, color: "var(--text-primary)", cursor: "pointer", whiteSpace: "nowrap" }}
                >Copy as Disasm Only</div>
                {/* 分隔线 */}
                <ContextMenuSeparator />
                {/* Highlight 子菜单 */}
                <div
                  onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.background = "var(--bg-selected)"; setHighlightSubmenuOpen(true); }}
                  onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.background = "transparent"; setHighlightSubmenuOpen(false); }}
                  style={{ padding: "6px 12px", fontSize: 12, color: "var(--text-primary)", cursor: "pointer", whiteSpace: "nowrap", position: "relative" }}
                >
                  <span>Highlight</span>
                  <span style={{ float: "right", marginLeft: 16 }}>▸</span>
                  {highlightSubmenuOpen && (
                    <div
                      style={{
                        position: "absolute",
                        left: "100%",
                        top: -4,
                        background: "var(--bg-dialog)",
                        border: "1px solid var(--border-color)",
                        borderRadius: 6,
                        boxShadow: "0 4px 16px rgba(0,0,0,0.4)",
                        padding: "4px 0",
                        minWidth: 160,
                        zIndex: 10001,
                      }}
                    >
                      {HIGHLIGHT_COLORS.map(hc => (
                        <div
                          key={hc.key}
                          onClick={() => {
                            const seqs = getSelectedSeqs();
                            if (seqs.length > 0 && onSetHighlight) {
                              onSetHighlight(seqs, { color: hc.key });
                              dirtyRef.current = true;
                            }
                            setCtxMenu(null);
                            setHighlightSubmenuOpen(false);
                          }}
                          onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.background = "var(--bg-selected)"; }}
                          onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.background = "transparent"; }}
                          style={{ padding: "6px 12px", fontSize: 12, color: "var(--text-primary)", cursor: "pointer", whiteSpace: "nowrap", display: "flex", alignItems: "center", gap: 8 }}
                        >
                          <span style={{ display: "inline-block", width: 12, height: 12, borderRadius: 2, background: hc.color, border: "1px solid rgba(255,255,255,0.2)" }} />
                          <span style={{ flex: 1 }}>{hc.label}</span>
                          <span style={{ color: "var(--text-secondary)", fontSize: 11 }}>{hc.shortcut()}</span>
                        </div>
                      ))}
                      {/* 分隔线 */}
                      <ContextMenuSeparator />
                      <div
                        onClick={() => {
                          const seqs = getSelectedSeqs();
                          if (seqs.length > 0 && onToggleStrikethrough) {
                            onToggleStrikethrough(seqs);
                            dirtyRef.current = true;
                          }
                          setCtxMenu(null);
                          setHighlightSubmenuOpen(false);
                        }}
                        onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.background = "var(--bg-selected)"; }}
                        onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.background = "transparent"; }}
                        style={{ padding: "6px 12px", fontSize: 12, color: "var(--text-primary)", cursor: "pointer", whiteSpace: "nowrap", display: "flex", alignItems: "center", justifyContent: "space-between" }}
                      >
                        <span>Strikethrough</span>
                        <span style={{ color: "var(--text-secondary)", fontSize: 11 }}>Alt+-</span>
                      </div>
                      <div
                        onClick={() => {
                          const seqs = getSelectedSeqs();
                          if (seqs.length > 0 && onResetHighlight) {
                            onResetHighlight(seqs);
                            dirtyRef.current = true;
                          }
                          setCtxMenu(null);
                          setHighlightSubmenuOpen(false);
                        }}
                        onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.background = "var(--bg-selected)"; }}
                        onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.background = "transparent"; }}
                        style={{ padding: "6px 12px", fontSize: 12, color: "var(--text-primary)", cursor: "pointer", whiteSpace: "nowrap", display: "flex", alignItems: "center", justifyContent: "space-between" }}
                      >
                        <span>Reset</span>
                        <span style={{ color: "var(--text-secondary)", fontSize: 11 }}>Alt+0</span>
                      </div>
                    </div>
                  )}
                </div>
                {/* 分隔线 */}
                <ContextMenuSeparator />
                {/* Hide */}
                <div
                  onClick={() => {
                    const seqs = getSelectedSeqs();
                    if (seqs.length > 0 && onToggleHidden) {
                      onToggleHidden(seqs);
                      dirtyRef.current = true;
                      setMultiSelect(null);
                    }
                    setCtxMenu(null);
                  }}
                  onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.background = "var(--bg-selected)"; setHighlightSubmenuOpen(false); }}
                  onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.background = "transparent"; }}
                  style={{ padding: "6px 12px", fontSize: 12, color: "var(--text-primary)", cursor: "pointer", whiteSpace: "nowrap", display: "flex", alignItems: "center", justifyContent: "space-between" }}
                >
                  <span>Hide</span>
                  <span style={{ color: "var(--text-secondary)", fontSize: 11 }}>Ctrl+/</span>
                </div>
                {/* 分隔线 */}
                <ContextMenuSeparator />
                {/* Add/Edit Comment */}
                <div
                  onClick={() => {
                    const seqs = getSelectedSeqs();
                    if (seqs.length > 0) {
                      openCommentEditor(seqs[0]);
                    }
                    setCtxMenu(null);
                  }}
                  onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.background = "var(--bg-selected)"; setHighlightSubmenuOpen(false); }}
                  onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.background = "transparent"; }}
                  style={{ padding: "6px 12px", fontSize: 12, color: "var(--text-primary)", cursor: "pointer", whiteSpace: "nowrap", display: "flex", alignItems: "center", justifyContent: "space-between" }}
                >
                  <span>{(() => { const seqs = getSelectedSeqs(); return seqs.length > 0 && highlights?.get(seqs[0])?.comment ? "Edit Comment" : "Add Comment"; })()}</span>
                  <span style={{ color: "var(--text-secondary)", fontSize: 11 }}>;</span>
                </div>
                {/* Delete Comment（仅有注释时显示） */}
                {(() => { const seqs = getSelectedSeqs(); return seqs.length > 0 && highlights?.get(seqs[0])?.comment; })() && (
                  <div
                    onClick={() => {
                      const seqs = getSelectedSeqs();
                      if (seqs.length > 0 && onDeleteComment) {
                        onDeleteComment(seqs[0]);
                        dirtyRef.current = true;
                      }
                      setCtxMenu(null);
                    }}
                    onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.background = "var(--bg-selected)"; setHighlightSubmenuOpen(false); }}
                    onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.background = "transparent"; }}
                    style={{ padding: "6px 12px", fontSize: 12, color: "var(--text-primary)", cursor: "pointer", whiteSpace: "nowrap" }}
                  >Delete Comment</div>
                )}
                {/* Call Info（仅当前行有 call_info 时显示） */}
                {ctxCallInfoRef.current && (
                  <>
                    <ContextMenuSeparator />
                    <div
                      onClick={() => {
                        if (ctxCallInfoRef.current) {
                          openCallInfoWindow(ctxCallInfoRef.current.tooltip, ctxCallInfoRef.current.isJni, ctxMenu!.x, ctxMenu!.y);
                        }
                        setCtxMenu(null);
                      }}
                      onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.background = "var(--bg-selected)"; setHighlightSubmenuOpen(false); }}
                      onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.background = "transparent"; }}
                      style={{ padding: "6px 12px", fontSize: 12, color: "var(--text-primary)", cursor: "pointer", whiteSpace: "nowrap" }}
                    >Call Info</div>
                  </>
                )}
                {/* Taint Trace */}
                {onTaintRequest && (
                  <>
                    <ContextMenuSeparator />
                    <div
                      onClick={() => {
                        const seqs = getSelectedSeqs();
                        if (seqs.length > 0 && onTaintRequest) {
                          onTaintRequest(seqs[0], ctxRegRef.current);
                        }
                        setCtxMenu(null);
                      }}
                      onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.background = "var(--bg-selected)"; setHighlightSubmenuOpen(false); }}
                      onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.background = "transparent"; }}
                      style={{ padding: "6px 12px", fontSize: 12, color: "var(--text-primary)", cursor: "pointer", whiteSpace: "nowrap" }}
                    >Taint Trace</div>
                  </>
                )}
              </>
            )}
          </ContextMenu>
        )}
        {/* 注释悬浮预览 — Portal 到 body，避免祖先 contain:paint 导致 fixed 定位失效 */}
        {commentTooltip && !commentEditor && createPortal(
          <div
            style={{
              position: "fixed",
              left: commentTooltip.x,
              top: commentTooltip.y,
              background: "var(--bg-dialog, #2b2d30)",
              border: "1px solid var(--border-color, #3e4150)",
              borderRadius: 4,
              boxShadow: "0 2px 8px rgba(0,0,0,0.4)",
              padding: "6px 10px",
              maxWidth: 300,
              maxHeight: 200,
              overflow: "auto",
              zIndex: 10000,
              fontSize: 12,
              color: "var(--text-primary, #abb2bf)",
              whiteSpace: "pre-wrap",
              wordBreak: "break-word",
              pointerEvents: "none",
            }}
          >
            {commentTooltip.text}
          </div>,
          document.body,
        )}
        {/* call_info 悬浮提示 — Portal 到 body */}
        {callInfoTooltip && createPortal(
          <div
            style={{
              position: "fixed",
              left: callInfoTooltip.x,
              top: callInfoTooltip.y,
              background: "var(--bg-dialog, #2b2d30)",
              border: "1px solid var(--border-color, #3e4150)",
              borderRadius: 4,
              boxShadow: "0 2px 8px rgba(0,0,0,0.4)",
              padding: "8px 12px",
              minWidth: 520,
              maxWidth: 620,
              maxHeight: 300,
              overflow: "auto",
              zIndex: 10000,
              fontSize: 12,
              fontFamily: '"JetBrains Mono", "Fira Code", monospace',
              color: "var(--text-primary, #abb2bf)",
              whiteSpace: "pre-wrap",
              wordBreak: "break-all",
            }}
            onMouseEnter={() => {
              callInfoHoveredRef.current = true;
              if (callInfoClearTimerRef.current) { clearTimeout(callInfoClearTimerRef.current); callInfoClearTimerRef.current = null; }
            }}
            onMouseLeave={() => {
              callInfoHoveredRef.current = false;
              setCallInfoTooltip(null);
            }}
          >
            {callInfoTooltip.text}
          </div>,
          document.body,
        )}
        {/* 注释编辑框 — Portal 到 body，避免祖先 contain:paint 导致 fixed 定位失效 */}
        {commentEditor && createPortal(
          <div
            ref={commentEditorRef}
            style={{
              position: "fixed",
              left: commentEditor.x,
              top: commentEditor.y,
              background: "var(--bg-dialog, #2b2d30)",
              border: "1px solid var(--border-color, #3e4150)",
              borderRadius: 6,
              boxShadow: "0 4px 16px rgba(0,0,0,0.5)",
              padding: "8px",
              zIndex: 10001,
              minWidth: 320,
              maxWidth: 500,
            }}
            onMouseDown={(e) => e.stopPropagation()}
          >
            <textarea
              ref={commentTextareaRef}
              defaultValue={commentEditor.text}
              autoFocus
              onFocus={(e) => {
                const el = e.currentTarget;
                el.selectionStart = el.selectionEnd = el.value.length;
              }}
              onKeyDown={(e) => {
                if (e.key === "Escape") {
                  e.stopPropagation();
                  closeCommentEditor();
                }
                // Ctrl+Enter 保存
                if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
                  e.preventDefault();
                  const val = commentTextareaRef.current?.value ?? "";
                  if (onSetComment) {
                    if (val.trim()) {
                      onSetComment(commentEditor.seq, val);
                    } else if (onDeleteComment) {
                      onDeleteComment(commentEditor.seq);
                    }
                    dirtyRef.current = true;
                  }
                  closeCommentEditor();
                }
              }}
              style={{
                width: "100%",
                minHeight: 100,
                maxHeight: 300,
                resize: "vertical",
                background: "var(--bg-primary, #1e1f22)",
                border: "1px solid var(--border-color, #3e4150)",
                borderRadius: 4,
                color: "var(--text-primary, #abb2bf)",
                fontSize: 12,
                fontFamily: "inherit",
                padding: "6px 8px",
                outline: "none",
                boxSizing: "border-box",
              }}
            />
            <div style={{ display: "flex", justifyContent: "center", gap: 8, marginTop: 6 }}>
              <button
                onMouseDown={(e) => {
                  e.preventDefault();
                  const val = commentTextareaRef.current?.value ?? "";
                  if (onSetComment) {
                    if (val.trim()) {
                      onSetComment(commentEditor.seq, val);
                    } else if (onDeleteComment) {
                      onDeleteComment(commentEditor.seq);
                    }
                    dirtyRef.current = true;
                  }
                  closeCommentEditor();
                }}
                style={{
                  padding: "4px 16px",
                  fontSize: 11,
                  background: "var(--accent-primary, #4c8ed9)",
                  color: "#fff",
                  border: "none",
                  borderRadius: 4,
                  cursor: "pointer",
                }}
              >Save</button>
              <button
                onMouseDown={(e) => { e.preventDefault(); closeCommentEditor(); }}
                style={{
                  padding: "4px 16px",
                  fontSize: 11,
                  background: "transparent",
                  color: "var(--text-secondary, #636d83)",
                  border: "1px solid var(--border-color, #3e4150)",
                  borderRadius: 4,
                  cursor: "pointer",
                }}
              >Cancel</button>
            </div>
          </div>,
          document.body,
        )}
        <Minimap
          virtualTotalRows={finalVirtualTotalRows}
          visibleRows={visibleRows}
          currentRow={currentRow}
          maxRow={maxRow}
          height={canvasSize.height}
          onScroll={setCurrentRow}
          resolveVirtualIndex={finalResolveVirtualIndex}
          getLines={getLines}
          selectedSeq={selectedSeq}
          showSoName={preferences.showSoName}
          showAbsAddress={preferences.showAbsAddress}
        />
        <CustomScrollbar
          currentRow={currentRow}
          maxRow={maxRow}
          visibleRows={visibleRows}
          virtualTotalRows={finalVirtualTotalRows}
          trackHeight={canvasSize.height}
          onScroll={setCurrentRow}
        />
      </div>
    </div>
  );
}

interface TableHeaderProps {
  disasmWidth: number;
  regBeforeWidth: number;
  seqWidth: number;
  addrWidth: number;
  onDisasmResizeMouseDown: (e: React.MouseEvent) => void;
  onRegBeforeResizeMouseDown: (e: React.MouseEvent) => void;
  onSeqResizeMouseDown: (e: React.MouseEvent) => void;
  onAddrResizeMouseDown: (e: React.MouseEvent) => void;
  showSoName: boolean;
  showAbsAddress: boolean;
  onToggleSoName: () => void;
  onToggleAbsAddress: () => void;
}

function ResizeHandle({ onMouseDown }: { onMouseDown: (e: React.MouseEvent) => void }) {
  return (
    <div
      onMouseDown={onMouseDown}
      style={{
        width: 8, cursor: "col-resize", flexShrink: 0,
        display: "flex", alignItems: "center", justifyContent: "center",
      }}
    >
      <div style={{ width: 1, height: "100%", background: "var(--border-color)" }} />
    </div>
  );
}

function TableHeader({ disasmWidth, regBeforeWidth, seqWidth, addrWidth, onDisasmResizeMouseDown, onRegBeforeResizeMouseDown, onSeqResizeMouseDown, onAddrResizeMouseDown, showSoName, showAbsAddress, onToggleSoName, onToggleAbsAddress }: TableHeaderProps) {
  return (
    <div
      style={{
        display: "flex",
        padding: "4px 8px",
        background: "var(--bg-secondary)",
        borderBottom: "1px solid var(--border-color)",
        fontSize: "var(--font-size-sm)",
        color: "var(--text-secondary)",
      }}
    >
      <span style={{ width: COL_FOLD - COL_ARROW, flexShrink: 0 }}></span>
      <span style={{ width: COL_MEMRW - COL_FOLD, flexShrink: 0 }}></span>
      <span style={{ width: COL_SEQ - COL_MEMRW, flexShrink: 0 }}></span>
      <span style={{ width: seqWidth, flexShrink: 0 }}>Seq</span>
      <ResizeHandle onMouseDown={onSeqResizeMouseDown} />
      <span style={{ width: addrWidth, flexShrink: 0, display: "flex", alignItems: "center" }}>
        <MenuDropdown
          label="Address"
          minWidth={160}
          closeOnSelect={false}
          labelStyle={{
            padding: "0 4px",
            fontSize: "var(--font-size-sm)",
            color: "var(--text-secondary)",
            background: "transparent",
          }}
        >
          <MenuItem
            label="显示模块名"
            checked={showSoName}
            onClick={onToggleSoName}
          />
          <MenuItem
            label="显示绝对地址"
            checked={showAbsAddress}
            disabled={!showSoName}
            onClick={onToggleAbsAddress}
          />
        </MenuDropdown>
      </span>
      <ResizeHandle onMouseDown={onAddrResizeMouseDown} />
      <span style={{ width: disasmWidth, flexShrink: 0 }}>Disassembly</span>
      <ResizeHandle onMouseDown={onDisasmResizeMouseDown} />
      <span style={{ width: regBeforeWidth, flexShrink: 0 }}>Before</span>
      <ResizeHandle onMouseDown={onRegBeforeResizeMouseDown} />
      <span style={{ flex: 1 }}>Changes</span>
      <span style={{ width: RIGHT_GUTTER, flexShrink: 0 }}></span>
    </div>
  );
}
