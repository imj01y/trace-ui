import { useState, useEffect, useCallback, useRef, useMemo } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import type { MemorySnapshot, TraceLine } from "../types/trace";
import { useSelectedSeq } from "../stores/selectedSeqStore";
import type { ResolvedRow } from "../hooks/useFoldState";
import Minimap, { MINIMAP_WIDTH } from "./Minimap";
import CustomScrollbar from "./CustomScrollbar";
import ContextMenu, { ContextMenuItem, ContextMenuSeparator } from "./ContextMenu";

interface MemHistoryRecord {
  seq: number;
  rw: string;
  data: string;
  size: number;
  insn_addr: string;
  disasm: string;
}

interface MemHistoryMeta {
  total: number;
  center_index: number;
  samples: MemHistoryRecord[];
}

interface Props {
  selectedSeq?: number | null;
  isPhase2Ready: boolean;
  memAddr?: string | null;
  memRw?: string | null;
  memSize?: number | null;
  onJumpToSeq: (seq: number) => void;
  sessionId: string | null;
  resetKey?: number;
}

const BYTES_PER_LINE = 16;
const HISTORY_PAGE_SIZE = 500;
const DEFAULT_LENGTH = 1024;
const LENGTH_PRESETS = [256, 512, 1024, 2048, 4096, 8192, 16384];
const HISTORY_ROW_HEIGHT = 20;
const HEX_ROW_HEIGHT = 20;
const ADDR_HISTORY_KEY = "memory-addr-search-history";
const MAX_ADDR_HISTORY = 20;
const MEM_LENGTH_KEY = "memory-hex-length";

function formatHexByte(byte: number): string {
  return byte.toString(16).padStart(2, "0").toUpperCase();
}

function toAsciiChar(byte: number): string {
  return byte >= 0x20 && byte <= 0x7e ? String.fromCharCode(byte) : ".";
}

/** 将 hex 地址字符串解析为 BigInt（支持超过 2^53 的 64 位地址） */
function hexToBigInt(hex: string): bigint {
  const raw = hex.replace(/^0x/i, "");
  if (!raw || !/^[0-9a-fA-F]+$/.test(raw)) return 0n;
  return BigInt("0x" + raw);
}

/** 将 BigInt 转回 hex 字符串 */
function bigIntToHex(n: bigint): string {
  return "0x" + n.toString(16);
}

/** 16 字节对齐（纯字符串操作，无精度丢失） */
function alignHexAddr16(hex: string): string {
  return bigIntToHex(hexToBigInt(hex) & ~0xFn);
}

export default function MemoryPanel({ selectedSeq: selectedSeqProp, isPhase2Ready, memAddr: memAddrProp, memRw: memRwProp, memSize: memSizeProp, onJumpToSeq, sessionId, resetKey }: Props) {
  const selectedSeqFromStore = useSelectedSeq();
  const selectedSeq = selectedSeqProp !== undefined ? selectedSeqProp : selectedSeqFromStore;

  // Internal mem info state (used when memAddrProp is not provided)
  const [memAddrInternal, setMemAddrInternal] = useState<string | null>(null);
  const [memRwInternal, setMemRwInternal] = useState<string | null>(null);
  const [memSizeInternal, setMemSizeInternal] = useState<number | null>(null);

  useEffect(() => {
    if (memAddrProp !== undefined) return;
    if (selectedSeq === null || !sessionId) {
      setMemAddrInternal(null); setMemRwInternal(null); setMemSizeInternal(null);
      return;
    }
    invoke<TraceLine[]>("get_lines", { sessionId, seqs: [selectedSeq] }).then((lines) => {
      if (lines.length > 0) {
        setMemAddrInternal(lines[0].mem_addr ?? null);
        setMemRwInternal(lines[0].mem_rw ?? null);
        setMemSizeInternal(lines[0].mem_size ?? null);
      }
    });
  }, [selectedSeq, sessionId, memAddrProp]);

  const memAddr = memAddrProp !== undefined ? memAddrProp : memAddrInternal;
  const memRw = memRwProp !== undefined ? memRwProp : memRwInternal;
  const memSize = memSizeProp !== undefined ? memSizeProp : memSizeInternal;
  const [autoTrack, setAutoTrack] = useState(true);
  const [inputAddr, setInputAddr] = useState("");
  const [currentAddr, setCurrentAddr] = useState<string | null>(null);
  const [snapshot, setSnapshot] = useState<MemorySnapshot | null>(null);
  const [hexLength, setHexLength] = useState<number>(() => {
    try { const v = parseInt(localStorage.getItem(MEM_LENGTH_KEY) || ""); return v > 0 ? v : DEFAULT_LENGTH; } catch { return DEFAULT_LENGTH; }
  });
  const [showLengthInput, setShowLengthInput] = useState(false);
  const [customLengthInput, setCustomLengthInput] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [historyTotal, setHistoryTotal] = useState(0);
  const [historyCenterIndex, setHistoryCenterIndex] = useState(0);
  const historyPagesRef = useRef<Map<number, MemHistoryRecord[]>>(new Map());
  const [historyPagesVersion, setHistoryPagesVersion] = useState(0);
  const historyLoadingPages = useRef<Set<number>>(new Set());
  const historyMinimapSamples = useRef<MemHistoryRecord[]>([]);
  const [historyAddr, setHistoryAddr] = useState<string | null>(null);
  const historyRef = useRef<HTMLDivElement>(null);
  const [hexContextMenu, setHexContextMenu] = useState<{ x: number; y: number; selText: string } | null>(null);

  const getHistoryRecord = useCallback((globalIndex: number): MemHistoryRecord | undefined => {
    const pageIndex = Math.floor(globalIndex / HISTORY_PAGE_SIZE);
    const page = historyPagesRef.current.get(pageIndex);
    if (!page) return undefined;
    return page[globalIndex - pageIndex * HISTORY_PAGE_SIZE];
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [historyPagesVersion]);

  const loadHistoryPage = useCallback((pageIndex: number, addr: string) => {
    if (historyLoadingPages.current.has(pageIndex)) return;
    if (historyPagesRef.current.has(pageIndex)) return;
    historyLoadingPages.current.add(pageIndex);
    const startIndex = pageIndex * HISTORY_PAGE_SIZE;
    invoke<MemHistoryRecord[]>("get_mem_history_range", {
      sessionId,
      addr,
      startIndex,
      limit: HISTORY_PAGE_SIZE,
    }).then((records) => {
      historyPagesRef.current.set(pageIndex, records);
      setHistoryPagesVersion(v => v + 1);
    }).finally(() => {
      historyLoadingPages.current.delete(pageIndex);
    });
  }, [sessionId]);

  const prevMemAddr = useRef<string | null>(null);

  // ── 地址搜索历史 ──
  const [addrHistory, setAddrHistory] = useState<string[]>(() => {
    try { return JSON.parse(localStorage.getItem(ADDR_HISTORY_KEY) || "[]"); } catch { return []; }
  });
  const [showAddrHistory, setShowAddrHistory] = useState(false);
  const addrInputWrapperRef = useRef<HTMLDivElement>(null);


  // hex dump 容器高度裁剪到行高整数倍，避免部分行露出
  const [hexClippedHeight, setHexClippedHeight] = useState<number | undefined>(undefined);
  const hexWrapperObserver = useRef<ResizeObserver | null>(null);
  const hexWrapperRef = useCallback((el: HTMLDivElement | null) => {
    if (hexWrapperObserver.current) {
      hexWrapperObserver.current.disconnect();
      hexWrapperObserver.current = null;
    }
    if (el) {
      let timer = 0;
      const ro = new ResizeObserver((entries) => {
        const h = entries[0]?.contentRect.height;
        if (h && h > 0) {
          clearTimeout(timer);
          timer = window.setTimeout(() => {
            setHexClippedHeight(Math.floor(h / HEX_ROW_HEIGHT) * HEX_ROW_HEIGHT);
          }, document.documentElement.dataset.separatorDrag ? 300 : 0);
        }
      });
      ro.observe(el);
      hexWrapperObserver.current = ro;
    }
  }, []);

  // hex dump 高亮行引用（用于自动滚动到当前访问位置）
  const highlightLineRef = useRef<HTMLDivElement>(null);

  // 切换指令时重置 auto-track（滚轮滚动会临时关闭 auto-track）
  useEffect(() => {
    setAutoTrack(true);
  }, [selectedSeq]);

  // 双击 Memory tab 时重置 hex dump 到当前指令的内存位置
  useEffect(() => {
    if (resetKey && resetKey > 0) {
      setAutoTrack(true);
    }
  }, [resetKey]);

  // View in Memory：外部指定地址时直接跳转，关闭 autoTrack
  useEffect(() => {
    const unlisten = listen<{ addr: string }>("action:view-in-memory", (e) => {
      const n = hexToBigInt(e.payload.addr);
      if (n === 0n) return;
      setAutoTrack(false);
      setCurrentAddr(bigIntToHex(n & ~0xFn));
      setInputAddr(e.payload.addr);
    });
    return () => { unlisten.then(fn => fn()); };
  }, []);

  // auto-track 时更新 currentAddr，让访问地址出现在第一行
  useEffect(() => {
    if (autoTrack && memAddr) {
      setCurrentAddr(alignHexAddr16(memAddr));
    }
  }, [autoTrack, memAddr]);

  // 查询内存快照（debounce 30ms + 过期检测）
  useEffect(() => {
    if (selectedSeq === null || !isPhase2Ready || !currentAddr || !sessionId) return;

    let cancelled = false;
    const timer = setTimeout(() => {
      setError(null);
      invoke<MemorySnapshot>("get_memory_at", {
        sessionId,
        seq: selectedSeq,
        addr: currentAddr,
        length: hexLength,
      })
        .then((s) => {
          if (cancelled) return;
          setSnapshot(s);
        })
        .catch((e) => {
          if (cancelled) return;
          setError(String(e));
          setSnapshot(null);
        });
    }, 80);
    return () => { cancelled = true; clearTimeout(timer); };
  }, [selectedSeq, isPhase2Ready, currentAddr, sessionId, hexLength]);

  // 查询地址读写历史（分页加载，debounce 150ms）
  useEffect(() => {
    if (!memAddr || !isPhase2Ready || !sessionId || selectedSeq === null) {
      setHistoryTotal(0);
      setHistoryCenterIndex(0);
      historyPagesRef.current = new Map();
      setHistoryPagesVersion(v => v + 1);
      setHistoryAddr(null);
      historyLoadingPages.current.clear();
      prevMemAddr.current = null;
      return;
    }

    const addrChanged = memAddr !== prevMemAddr.current;
    prevMemAddr.current = memAddr;

    let cancelled = false;
    const timer = setTimeout(() => {
      setHistoryAddr(memAddr);

      if (addrChanged) {
        historyPagesRef.current = new Map();
        historyLoadingPages.current.clear();
        historyMinimapSamples.current = [];
        setHistoryPagesVersion(v => v + 1);

        invoke<MemHistoryMeta>("get_mem_history_meta", {
          sessionId,
          addr: memAddr,
          centerSeq: selectedSeq,
        }).then((meta) => {
          if (cancelled) return;
          setHistoryTotal(meta.total);
          setHistoryCenterIndex(meta.center_index);
          historyMinimapSamples.current = meta.samples;
          if (meta.total === 0) return;
          const centerPage = Math.floor(meta.center_index / HISTORY_PAGE_SIZE);
          invoke<MemHistoryRecord[]>("get_mem_history_range", {
            sessionId,
            addr: memAddr,
            startIndex: centerPage * HISTORY_PAGE_SIZE,
            limit: HISTORY_PAGE_SIZE,
          }).then((records) => {
            if (cancelled) return;
            historyPagesRef.current.set(centerPage, records);
            setHistoryPagesVersion(v => v + 1);
          });
        }).catch(() => {
          if (cancelled) return;
          setHistoryTotal(0);
          historyPagesRef.current = new Map();
          setHistoryPagesVersion(v => v + 1);
        });
      } else {
        // Only selectedSeq changed, same address — just re-center, don't clear cache
        invoke<MemHistoryMeta>("get_mem_history_meta", {
          sessionId,
          addr: memAddr,
          centerSeq: selectedSeq,
        }).then((meta) => {
          if (cancelled) return;
          setHistoryCenterIndex(meta.center_index);
          const centerPage = Math.floor(meta.center_index / HISTORY_PAGE_SIZE);
          loadHistoryPage(centerPage, memAddr);
        });
      }
    }, 150);
    return () => { cancelled = true; clearTimeout(timer); };
  }, [memAddr, isPhase2Ready, sessionId, selectedSeq, loadHistoryPage]);

  // Access History minimap state
  const [historyScrollRow, setHistoryScrollRow] = useState(0);
  const [historyContainerHeight, setHistoryContainerHeight] = useState(0);
  const historyObserverRef = useRef<{ ro: ResizeObserver; el: HTMLDivElement } | null>(null);

  const historyVisibleRows = historyContainerHeight > 0
    ? Math.floor(historyContainerHeight / HISTORY_ROW_HEIGHT)
    : 0;
  const historyMaxRow = Math.max(0, historyTotal - historyVisibleRows);

  // 当 history 加载完成或 selectedSeq 变化时，滚动到当前 seq 居中
  useEffect(() => {
    if (historyTotal === 0) return;
    const target = Math.max(0, Math.min(
      historyCenterIndex - Math.floor(historyVisibleRows / 2),
      historyMaxRow,
    ));
    setHistoryScrollRow(target);
  }, [historyCenterIndex, historyTotal, historyVisibleRows, historyMaxRow]);

  const historyVisibleItems = useMemo(() => {
    if (historyTotal === 0 || historyVisibleRows === 0) return [];
    const start = historyScrollRow;
    const end = Math.min(start + historyVisibleRows + 2, historyTotal);
    const items: number[] = [];
    for (let i = start; i < end; i++) items.push(i);
    return items;
  }, [historyScrollRow, historyVisibleRows, historyTotal]);

  // Callback ref: 在元素挂载/卸载时立即设置/清理 ResizeObserver
  const historyRefCallback = useCallback((el: HTMLDivElement | null) => {
    if (historyObserverRef.current) {
      historyObserverRef.current.ro.disconnect();
      historyObserverRef.current = null;
    }
    historyRef.current = el;
    if (!el) {
      setHistoryContainerHeight(0);
      return;
    }
    let timer = 0;
    const ro = new ResizeObserver((entries) => {
      if (entries[0]) {
        clearTimeout(timer);
        const h = entries[0].contentRect.height;
        timer = window.setTimeout(() => {
          setHistoryContainerHeight(h);
        }, document.documentElement.dataset.separatorDrag ? 300 : 0);
      }
    });
    ro.observe(el);
    historyObserverRef.current = { ro, el };
  }, []);

  // 组件卸载时清理 observer
  useEffect(() => {
    return () => {
      if (historyObserverRef.current) {
        historyObserverRef.current.ro.disconnect();
        historyObserverRef.current = null;
      }
    };
  }, []);

  // 根据滚动位置按需加载可见区域的页（独立 useEffect 避免 stale closure）
  useEffect(() => {
    if (historyTotal === 0 || !memAddr) return;
    const firstVisible = historyScrollRow;
    const visibleRows = historyContainerHeight > 0 ? Math.ceil(historyContainerHeight / HISTORY_ROW_HEIGHT) + 10 : 30; // +overscan
    const lastVisible = Math.min(firstVisible + visibleRows, historyTotal - 1);
    const firstPage = Math.floor(firstVisible / HISTORY_PAGE_SIZE);
    const lastPage = Math.floor(lastVisible / HISTORY_PAGE_SIZE);
    for (let p = firstPage; p <= lastPage; p++) {
      loadHistoryPage(p, memAddr);
    }
  }, [historyScrollRow, historyTotal, memAddr, historyContainerHeight, loadHistoryPage]);

  const historyResolve = useCallback((vi: number): ResolvedRow => {
    // 1. 优先从页缓存获取
    const rec = getHistoryRecord(vi);
    if (rec) return { type: "line", seq: rec.seq } as ResolvedRow;
    // 2. 从 Minimap 采样中按比例映射
    const samples = historyMinimapSamples.current;
    if (samples.length > 0 && historyTotal > 0) {
      const sampleIdx = Math.min(
        Math.round(vi / historyTotal * samples.length),
        samples.length - 1,
      );
      return { type: "line", seq: samples[sampleIdx].seq } as ResolvedRow;
    }
    return { type: "line", seq: -1 } as ResolvedRow;
  }, [getHistoryRecord, historyTotal]);

  const historyGetLines = useCallback(async (seqs: number[]): Promise<TraceLine[]> => {
    const seqSet = new Set(seqs);
    const results: TraceLine[] = [];
    const found = new Set<number>();
    // 1. 从页缓存查找
    historyPagesRef.current.forEach((page) => {
      for (const r of page) {
        if (seqSet.has(r.seq) && !found.has(r.seq)) {
          found.add(r.seq);
          results.push({
            seq: r.seq, address: r.insn_addr, disasm: r.disasm,
            changes: `${r.rw} ${r.data}`,
          } as unknown as TraceLine);
        }
      }
    });
    // 2. 从 Minimap 采样补充
    for (const r of historyMinimapSamples.current) {
      if (seqSet.has(r.seq) && !found.has(r.seq)) {
        found.add(r.seq);
        results.push({
          seq: r.seq, address: r.insn_addr, disasm: r.disasm,
          changes: `${r.rw} ${r.data}`,
        } as unknown as TraceLine);
      }
    }
    return results;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [historyPagesVersion]);

  // ── 地址搜索历史：点击外部关闭 ──
  useEffect(() => {
    if (!showAddrHistory) return;
    const handler = (e: MouseEvent) => {
      if (addrInputWrapperRef.current && !addrInputWrapperRef.current.contains(e.target as Node)) {
        setShowAddrHistory(false);
      }
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [showAddrHistory]);

  const removeAddrHistoryItem = useCallback((item: string) => {
    setAddrHistory(prev => {
      const next = prev.filter(h => h !== item);
      localStorage.setItem(ADDR_HISTORY_KEY, JSON.stringify(next));
      return next;
    });
  }, []);

  const clearAllAddrHistory = useCallback(() => {
    setAddrHistory([]);
    localStorage.removeItem(ADDR_HISTORY_KEY);
    setShowAddrHistory(false);
  }, []);

  const addAddrToHistory = useCallback((addr: string) => {
    setAddrHistory(prev => {
      const next = [addr, ...prev.filter(h => h !== addr)].slice(0, MAX_ADDR_HISTORY);
      localStorage.setItem(ADDR_HISTORY_KEY, JSON.stringify(next));
      return next;
    });
  }, []);

  const filteredAddrHistory = inputAddr.trim()
    ? addrHistory.filter(h => h !== inputAddr.trim() && h.toLowerCase().includes(inputAddr.toLowerCase()))
    : addrHistory;

  const handleGo = useCallback(() => {
    const trimmed = inputAddr.trim();
    if (!trimmed) return;
    const clean = trimmed.startsWith("0x") || trimmed.startsWith("0X") ? trimmed : `0x${trimmed}`;
    if (!/^0x[0-9a-fA-F]+$/.test(clean)) {
      setError("Invalid hex address");
      return;
    }
    setAutoTrack(false);
    setCurrentAddr(clean);
    setError(null);
    addAddrToHistory(clean);
    setShowAddrHistory(false);
  }, [inputAddr, addAddrToHistory]);

  // 高亮行变化时自动滚动到可见位置
  useEffect(() => {
    if (highlightLineRef.current) {
      highlightLineRef.current.scrollIntoView({ block: "nearest" });
    }
  }, [snapshot, memAddr]);

  // 将 snapshot 拆分为行（useMemo 避免每次渲染重建）
  // 注意：所有 hooks 必须在 early return 之前调用
  const hexLines = useMemo(() => {
    const lines: { addr: string; bytes: { value: number; known: boolean }[] }[] = [];
    if (snapshot) {
      const base = hexToBigInt(snapshot.base_addr);
      for (let i = 0; i < snapshot.bytes.length; i += BYTES_PER_LINE) {
        const lineAddr = base + BigInt(i);
        const lineBytes: { value: number; known: boolean }[] = [];
        for (let j = 0; j < BYTES_PER_LINE && i + j < snapshot.bytes.length; j++) {
          lineBytes.push({ value: snapshot.bytes[i + j], known: snapshot.known[i + j] });
        }
        lines.push({ addr: bigIntToHex(lineAddr), bytes: lineBytes });
      }
    }
    return lines;
  }, [snapshot]);

  // 高亮当前指令访问的内存范围（useMemo 避免每次渲染重算）
  const { highlightStart, highlightEnd, lastNonZeroOffset } = useMemo(() => {
    let hStart = -1;
    let hEnd = -1;
    if (snapshot && memAddr && memRw) {
      const accessAddr = hexToBigInt(memAddr);
      const base = hexToBigInt(snapshot.base_addr);
      const offset = Number(accessAddr - base);
      if (offset >= 0 && offset < snapshot.bytes.length) {
        hStart = offset;
        hEnd = offset + (memSize ?? 4);
      }
    }

    // 高亮范围内最后一个非零字节的偏移（用于区分有效值字节和尾部高位零）
    let lastNonZero = hStart - 1;
    if (snapshot && hStart >= 0) {
      for (let i = hEnd - 1; i >= hStart; i--) {
        if (snapshot.bytes[i] !== 0) {
          lastNonZero = i;
          break;
        }
      }
    }

    return { highlightStart: hStart, highlightEnd: hEnd, lastNonZeroOffset: lastNonZero };
  }, [snapshot, memAddr, memRw, memSize]);

  // 地址列宽度：根据最长地址文本自适应（ch 单位 + 少量 padding）
  const addrColWidth = useMemo(() => {
    if (hexLines.length === 0) return "10ch";
    const maxLen = Math.max(...hexLines.map(l => l.addr.length));
    return `${maxLen + 2}ch`;
  }, [hexLines]);

  // 字节颜色：有效值字节=绿色，尾部高位零=白色，范围外=灰色
  const byteColor = useCallback((globalOffset: number) => {
    if (globalOffset >= highlightStart && globalOffset < highlightEnd) {
      return globalOffset <= lastNonZeroOffset ? "var(--text-ascii-printable)" : "var(--text-primary)";
    }
    return "var(--text-hex-zero)";
  }, [highlightStart, highlightEnd, lastNonZeroOffset]);

  // hexdump 右键菜单
  const handleHexContextMenu = useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    const selText = window.getSelection()?.toString() ?? "";
    setHexContextMenu({ x: e.clientX, y: e.clientY, selText });
  }, []);

  /** 生成完整 hexdump 文本（地址 + hex + ascii） */
  const buildHexdumpText = useCallback(() => {
    return hexLines.map((line) => {
      const hex1 = line.bytes.slice(0, 8).map(b => b.known ? formatHexByte(b.value) : "??").join(" ");
      const hex2 = line.bytes.slice(8, 16).map(b => b.known ? formatHexByte(b.value) : "??").join(" ");
      const ascii = line.bytes.map(b => (b.known && b.value !== 0) ? toAsciiChar(b.value) : ".").join("");
      return `${line.addr}  ${hex1}  ${hex2}  ${ascii}`;
    }).join("\n");
  }, [hexLines]);

  /** 仅 hex 字节（无空格无换行） */
  const buildHexOnly = useCallback(() => {
    return hexLines.flatMap((line) =>
      line.bytes.map(b => b.known ? formatHexByte(b.value) : "??")
    ).join("");
  }, [hexLines]);

  /** 仅 ASCII（无换行，连续输出） */
  const buildAsciiOnly = useCallback(() => {
    return hexLines.flatMap((line) =>
      line.bytes.map(b => (b.known && b.value !== 0) ? toAsciiChar(b.value) : ".")
    ).join("");
  }, [hexLines]);

  const handleCopyHexdump = useCallback(() => {
    navigator.clipboard.writeText(buildHexdumpText());
    setHexContextMenu(null);
  }, [buildHexdumpText]);

  const handleCopyHex = useCallback(() => {
    navigator.clipboard.writeText(buildHexOnly());
    setHexContextMenu(null);
  }, [buildHexOnly]);

  const handleCopyAscii = useCallback(() => {
    navigator.clipboard.writeText(buildAsciiOnly());
    setHexContextMenu(null);
  }, [buildAsciiOnly]);

  const handleCopySelection = useCallback(() => {
    if (hexContextMenu?.selText) navigator.clipboard.writeText(hexContextMenu.selText);
    setHexContextMenu(null);
  }, [hexContextMenu]);

  if (!isPhase2Ready) {
    return (
      <div style={{ height: "100%", display: "flex", alignItems: "center", justifyContent: "center" }}>
        <span style={{ color: "var(--text-secondary)", fontSize: 12 }}></span>
      </div>
    );
  }

  if (selectedSeq === null) {
    return (
      <div style={{ height: "100%", display: "flex", alignItems: "center", justifyContent: "center" }}>
        <span style={{ color: "var(--text-secondary)", fontSize: 12 }}></span>
      </div>
    );
  }

  const showHistory = !!(historyAddr && historyTotal > 0);

  const toolbar = (
    <div style={{ display: "flex", alignItems: "center", gap: 6, fontSize: "var(--font-size-sm)", width: "100%" }}>
      {/* 左侧：history 信息 */}
      {showHistory && (
        <span style={{ color: "var(--text-secondary)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", fontSize: 11 }}>
          {memRw && <span style={{ color: memRw === "W" ? "var(--text-hex-highlight)" : "var(--text-address)" }}>{memRw}</span>}{" "}
          <span style={{ color: "var(--text-address)" }}>{historyAddr}</span>
          {memSize ? `:${memSize}` : ""}{" "}
        </span>
      )}
      <span style={{ flex: 1 }} />
      {/* 右侧：Auto + 搜索框 */}
      <label title="Auto-track memory address accessed by the current instruction; scrolling temporarily disables tracking" style={{ display: "flex", alignItems: "center", gap: 3, color: "var(--text-secondary)", cursor: "pointer", whiteSpace: "nowrap" }}>
        <input
          type="checkbox"
          checked={autoTrack}
          onChange={(e) => {
            const checked = e.target.checked;
            setAutoTrack(checked);
            if (checked && memAddr) {
              setCurrentAddr(memAddr);
            }
          }}
          style={{ accentColor: "var(--btn-primary)" }}
        />
        Auto
      </label>
      {/* 长度选择器 */}
      <div style={{ position: "relative", display: "inline-flex", alignItems: "center" }}>
        <select
          value={LENGTH_PRESETS.includes(hexLength) ? hexLength : "custom"}
          onChange={(e) => {
            const val = e.target.value;
            if (val === "custom") {
              setCustomLengthInput(String(hexLength));
              setShowLengthInput(true);
            } else {
              const n = parseInt(val);
              setHexLength(n);
              localStorage.setItem(MEM_LENGTH_KEY, String(n));
              setShowLengthInput(false);
            }
          }}
          style={{
            padding: "1px 4px", background: "var(--bg-input)", color: "var(--text-primary)",
            border: "1px solid var(--border-color)", borderRadius: 3,
            fontFamily: "var(--font-mono)", fontSize: "var(--font-size-sm)", cursor: "pointer",
          }}
        >
          {LENGTH_PRESETS.map(v => (
            <option key={v} value={v}>{v}</option>
          ))}
          <option value="custom">{!LENGTH_PRESETS.includes(hexLength) ? hexLength : "Custom"}</option>
        </select>
        {showLengthInput && (
          <input
            type="text"
            autoFocus
            placeholder="bytes"
            value={customLengthInput}
            onChange={(e) => setCustomLengthInput(e.target.value.replace(/[^0-9]/g, ""))}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                const n = parseInt(customLengthInput);
                if (n >= 16 && n <= 65536) {
                  setHexLength(n);
                  localStorage.setItem(MEM_LENGTH_KEY, String(n));
                  setShowLengthInput(false);
                }
              } else if (e.key === "Escape") {
                setShowLengthInput(false);
              }
            }}
            onBlur={() => {
              const n = parseInt(customLengthInput);
              if (n >= 16 && n <= 65536) {
                setHexLength(n);
                localStorage.setItem(MEM_LENGTH_KEY, String(n));
              }
              setShowLengthInput(false);
            }}
            style={{
              width: 64, marginLeft: 4, padding: "1px 4px",
              background: "var(--bg-input)", color: "var(--text-primary)",
              border: "1px solid var(--border-color)", borderRadius: 3,
              fontFamily: "var(--font-mono)", fontSize: "var(--font-size-sm)",
            }}
          />
        )}
      </div>
      <div ref={addrInputWrapperRef} style={{ position: "relative", display: "inline-flex", alignItems: "center" }}>
        <input
          type="text"
          placeholder="Jump to address (hex)"
          value={inputAddr}
          onChange={(e) => setInputAddr(e.target.value)}
          onFocus={() => setShowAddrHistory(true)}
          onKeyDown={(e) => e.key === "Enter" && handleGo()}
          style={{
            width: 164, padding: inputAddr ? "1px 20px 1px 6px" : "1px 6px",
            background: "var(--bg-input)", color: "var(--text-primary)",
            border: error ? "1px solid var(--reg-changed)" : "1px solid var(--border-color)",
            borderRadius: 3, fontFamily: "var(--font-mono)", fontSize: "var(--font-size-sm)",
          }}
        />
        {inputAddr && (
          <span
            onClick={() => { setInputAddr(""); setError(null); setShowAddrHistory(false); }}
            style={{
              position: "absolute", right: 6, top: "50%", transform: "translateY(-50%)",
              cursor: "pointer", color: "var(--text-secondary)", fontSize: 13,
              lineHeight: 1, userSelect: "none",
            }}
          >×</span>
        )}
        {showAddrHistory && filteredAddrHistory.length > 0 && (
          <div style={{
            position: "absolute", top: "100%", left: 0, width: "100%", marginTop: 2,
            background: "var(--bg-dialog)", border: "1px solid var(--border-color)",
            borderRadius: 4, zIndex: 100, maxHeight: 200, overflowY: "auto",
            boxShadow: "0 4px 12px rgba(0,0,0,0.4)",
          }}>
            {filteredAddrHistory.map(item => (
              <div
                key={item}
                style={{
                  display: "flex", alignItems: "center", padding: "4px 8px", fontSize: 12,
                  cursor: "pointer", color: "var(--text-primary)",
                }}
                onMouseEnter={e => (e.currentTarget.style.background = "var(--bg-selected)")}
                onMouseLeave={e => (e.currentTarget.style.background = "transparent")}
                onClick={() => {
                  setInputAddr(item);
                  setShowAddrHistory(false);
                  setAutoTrack(false);
                  setCurrentAddr(item);
                  setError(null);
                }}
              >
                <span style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "var(--font-mono)" }}>{item}</span>
                <span
                  onClick={e => { e.stopPropagation(); removeAddrHistoryItem(item); }}
                  style={{
                    marginLeft: 4, color: "var(--text-secondary)", fontSize: 13, lineHeight: 1,
                    width: 16, height: 16, display: "flex", alignItems: "center", justifyContent: "center",
                    borderRadius: "50%", flexShrink: 0, cursor: "pointer",
                  }}
                  onMouseEnter={e => (e.currentTarget.style.color = "var(--text-primary)")}
                  onMouseLeave={e => (e.currentTarget.style.color = "var(--text-secondary)")}
                >×</span>
              </div>
            ))}
            <div
              style={{
                padding: "4px 8px", fontSize: 11, color: "var(--text-secondary)",
                borderTop: "1px solid var(--border-color)", cursor: "pointer", textAlign: "center",
              }}
              onMouseEnter={e => { e.currentTarget.style.background = "var(--bg-selected)"; e.currentTarget.style.color = "var(--text-primary)"; }}
              onMouseLeave={e => { e.currentTarget.style.background = "transparent"; e.currentTarget.style.color = "var(--text-secondary)"; }}
              onClick={clearAllAddrHistory}
            >Clear All</div>
          </div>
        )}
      </div>
    </div>
  );

  return (
    <div style={{ height: "100%", display: "flex", flexDirection: "column", background: "var(--bg-primary)" }}>
      {/* 主内容区：左 hex dump + 右 history */}
      <div style={{ flex: 1, display: "flex", overflow: "hidden" }}>
        {/* Hex dump */}
        <div
          style={{
            flex: snapshot && showHistory ? "0 0 auto" : 1,
            overflow: "hidden", fontFamily: "var(--font-mono)", fontSize: "var(--font-size-sm)",
            display: "flex", flexDirection: "column", minWidth: 0,
          }}
        >
          {error && !snapshot ? (
            <div style={{ flex: 1, display: "flex", flexDirection: "column" }}>
              <div style={{ flexShrink: 0, display: "flex", alignItems: "center", padding: "4px 8px", borderBottom: "1px solid var(--border-color)" }}>{toolbar}</div>
              <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center", color: "var(--reg-changed)" }}>{error}</div>
            </div>
          ) : !snapshot ? (
            <div style={{ flex: 1, display: "flex", flexDirection: "column" }}>
              <div style={{ flexShrink: 0, display: "flex", alignItems: "center", padding: "4px 8px", borderBottom: "1px solid var(--border-color)" }}>{toolbar}</div>
              <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center", color: "var(--text-secondary)", fontSize: 12 }}>
                {""}
              </div>
            </div>
          ) : (<>
            <div style={{ flexShrink: 0, display: "flex", alignItems: "center", padding: "4px 8px", borderBottom: "1px solid var(--border-color)" }}>{toolbar}</div>
            <div style={{ flexShrink: 0, display: "flex", lineHeight: "20px", whiteSpace: "pre", color: "var(--text-secondary)", padding: "0 8px" }}>
              <span style={{ width: addrColWidth, flexShrink: 0 }}>{"Address"}</span>
              {[0,1,2,3,4,5,6,7].map(i => (
                <span key={i}>{i.toString(16).toUpperCase().padStart(2, "0")}{" "}</span>
              ))}
              <span style={{ width: 4 }}> </span>
              {[8,9,0xA,0xB,0xC,0xD,0xE,0xF].map(i => (
                <span key={i}>{i.toString(16).toUpperCase().padStart(2, "00")}{" "}</span>
              ))}
              <span style={{ width: 8 }}> </span>
              <span>{"ASCII"}</span>
            </div>
            <div ref={hexWrapperRef} style={{ flex: 1, overflow: "hidden" }}>
            <div onContextMenu={handleHexContextMenu} style={{
              height: hexClippedHeight, overflowY: "auto", overflowX: "hidden", padding: "0 8px",
              scrollbarWidth: "thin",
              scrollbarColor: "var(--text-secondary) transparent",
            } as React.CSSProperties}>
              {hexLines.map((line, lineIdx) => {
                const lineStartOffset = lineIdx * BYTES_PER_LINE;
                const isHighlightLine = highlightStart >= 0 && lineStartOffset + BYTES_PER_LINE > highlightStart && lineStartOffset < highlightEnd;
                return (
                  <div
                    key={lineIdx}
                    ref={isHighlightLine && lineStartOffset <= highlightStart ? highlightLineRef : undefined}
                    style={{ display: "flex", lineHeight: "20px", whiteSpace: "pre" }}
                  >
                    <span style={{ color: "var(--text-address)", width: addrColWidth, flexShrink: 0 }}>
                      {line.addr}
                    </span>
                    <span>{line.bytes.slice(0, 8).map((b, i) => {
                      const globalOffset = lineIdx * BYTES_PER_LINE + i;
                      return (
                        <span key={i} style={{ color: b.known ? byteColor(globalOffset) : "var(--text-hex-zero)" }}>
                          {b.known ? formatHexByte(b.value) : "??"}{" "}
                        </span>
                      );
                    })}</span>
                    <span style={{ width: 4 }}> </span>
                    <span>{line.bytes.slice(8, 16).map((b, i) => {
                      const globalOffset = lineIdx * BYTES_PER_LINE + 8 + i;
                      return (
                        <span key={i + 8} style={{ color: b.known ? byteColor(globalOffset) : "var(--text-hex-zero)" }}>
                          {b.known ? formatHexByte(b.value) : "??"}{" "}
                        </span>
                      );
                    })}</span>
                    <span style={{ width: 8 }}> </span>
                    <span>{line.bytes.map((b, i) => {
                      const globalOffset = lineIdx * BYTES_PER_LINE + i;
                      const isHighlight = globalOffset >= highlightStart && globalOffset < highlightEnd;
                      return (
                        <span key={`a${i}`} style={{
                          color: isHighlight ? "var(--text-ascii-printable)" : "var(--text-ascii-nonprint)",
                        }}>
                          {(b.known && b.value !== 0) ? toAsciiChar(b.value) : "."}
                        </span>
                      );
                    })}</span>
                  </div>
                );
              })}
            </div>
            </div>
          </>)}
        </div>

        {/* Hexdump 右键菜单 */}
        {hexContextMenu && (
          <ContextMenu x={hexContextMenu.x} y={hexContextMenu.y} onClose={() => setHexContextMenu(null)}>
            <ContextMenuItem label="Copy Hexdump" onClick={handleCopyHexdump} disabled={hexLines.length === 0} />
            <ContextMenuItem label="Copy Hex" onClick={handleCopyHex} disabled={hexLines.length === 0} />
            <ContextMenuItem label="Copy ASCII" onClick={handleCopyAscii} disabled={hexLines.length === 0} />
            <ContextMenuSeparator />
            <ContextMenuItem label="Copy Selected Text" onClick={handleCopySelection} disabled={!hexContextMenu.selText} />
          </ContextMenu>
        )}

        {/* Access History（右侧，可拖拽宽度） */}
        {showHistory && (
          <>
            <div style={{ width: 6, flexShrink: 0, display: "flex", alignItems: "stretch", justifyContent: "center" }}>
              <div
                style={{
                  width: 1,
                  background: "var(--border-color)",
                }}
              />
            </div>
            <div style={{
              flex: 1, minWidth: 120, display: "flex", flexDirection: "column",
              overflow: "hidden",
            }}>
              <div style={{
                padding: "3px 8px", background: "var(--bg-secondary)",
                borderBottom: "1px solid var(--border-color)",
                fontSize: 11, color: "var(--text-secondary)", flexShrink: 0,
              }}>
                Memory accesses history  Total: {historyTotal.toLocaleString()}
              </div>
              <div style={{ flex: 1, display: "flex", overflow: "hidden" }}>
                <div
                  ref={historyRefCallback}
                  style={{ flex: 1, overflow: "hidden", position: "relative", fontFamily: "var(--font-mono)", fontSize: "var(--font-size-sm)", outline: "none" } as React.CSSProperties}
                  onWheel={(e) => {
                    if (historyTotal === 0) return;
                    let delta: number;
                    if (e.deltaMode === 1) {
                      delta = Math.round(e.deltaY) * 3;
                    } else {
                      delta = Math.round(e.deltaY / HISTORY_ROW_HEIGHT);
                      if (delta === 0 && e.deltaY !== 0) delta = e.deltaY > 0 ? 1 : -1;
                    }
                    setHistoryScrollRow(prev => Math.max(0, Math.min(historyMaxRow, prev + delta)));
                  }}
                >
                  {historyVisibleItems.map((globalIdx) => {
                    const localIdx = globalIdx - historyScrollRow;
                    const rec = getHistoryRecord(globalIdx);
                    const isCurrent = rec ? selectedSeq !== null && rec.seq === selectedSeq : false;
                    return (
                      <div
                        key={globalIdx}
                        onClick={() => rec && onJumpToSeq(rec.seq)}
                        style={{
                          position: "absolute", top: localIdx * HISTORY_ROW_HEIGHT, left: 0, width: "100%", height: HISTORY_ROW_HEIGHT,
                          display: "flex", alignItems: "center", padding: "0 8px", gap: 8,
                          cursor: rec ? "pointer" : "default",
                          background: isCurrent ? "var(--bg-selected)"
                            : globalIdx % 2 === 0 ? "var(--bg-row-even)" : "var(--bg-row-odd)",
                          whiteSpace: "nowrap",
                        }}
                        onMouseEnter={(e) => { if (!isCurrent) e.currentTarget.style.background = "var(--bg-hover)"; }}
                        onMouseLeave={(e) => { if (!isCurrent) e.currentTarget.style.background = globalIdx % 2 === 0 ? "var(--bg-row-even)" : "var(--bg-row-odd)"; }}
                      >
                        {rec ? (
                          <>
                            <span style={{ width: 90, color: "var(--text-secondary)", flexShrink: 0 }}>#{rec.seq + 1}</span>
                            <span style={{
                              width: 20, flexShrink: 0, textAlign: "center",
                              color: rec.rw === "W" ? "var(--text-hex-highlight)" : "var(--text-address)",
                            }}>{rec.rw}</span>
                            <span style={{ width: 280, color: "var(--text-ascii-printable)", flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis" }}>{rec.data}</span>
                            <span style={{ flex: 1, color: "var(--text-secondary)", overflow: "hidden", textOverflow: "ellipsis" }}>{rec.disasm}</span>
                          </>
                        ) : (
                          <span style={{ color: "var(--text-secondary)", opacity: 0.4 }}>loading...</span>
                        )}
                      </div>
                    );
                  })}
                </div>
                {historyTotal > 0 && historyContainerHeight > 0 && (() => {
                  return (
                    <div style={{ width: MINIMAP_WIDTH + 12, flexShrink: 0, position: "relative" }}>
                      <Minimap
                        virtualTotalRows={historyTotal}
                        visibleRows={historyVisibleRows}
                        currentRow={historyScrollRow}
                        maxRow={historyMaxRow}
                        height={historyContainerHeight}
                        onScroll={setHistoryScrollRow}
                        resolveVirtualIndex={historyResolve}
                        getLines={historyGetLines}
                        selectedSeq={selectedSeq}
                        rightOffset={12}
                        showSoName={false}
                        showAbsAddress={false}
                      />
                      <CustomScrollbar
                        currentRow={historyScrollRow}
                        maxRow={historyMaxRow}
                        visibleRows={historyVisibleRows}
                        virtualTotalRows={historyTotal}
                        trackHeight={historyContainerHeight}
                        onScroll={setHistoryScrollRow}
                      />
                    </div>
                  );
                })()}
              </div>
            </div>
          </>
        )}
      </div>

    </div>
  );
}
