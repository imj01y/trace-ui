import { useState, useEffect, useCallback, useRef, useMemo } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { useVirtualizerNoSync } from "../hooks/useVirtualizerNoSync";
import type { MemorySnapshot, TraceLine } from "../types/trace";
import { useSelectedSeq } from "../stores/selectedSeqStore";
import type { ResolvedRow } from "../hooks/useFoldState";
import Minimap, { MINIMAP_WIDTH } from "./Minimap";
import CustomScrollbar from "./CustomScrollbar";

interface MemHistoryRecord {
  seq: number;
  rw: string;
  data: string;
  size: number;
  insn_addr: string;
  disasm: string;
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
const DEFAULT_LENGTH = 1024;
const HISTORY_ROW_HEIGHT = 20;
const HEX_ROW_HEIGHT = 20;
const ADDR_HISTORY_KEY = "memory-addr-search-history";
const MAX_ADDR_HISTORY = 20;

function formatHexByte(byte: number): string {
  return byte.toString(16).padStart(2, "0").toUpperCase();
}

function toAsciiChar(byte: number): string {
  return byte >= 0x20 && byte <= 0x7e ? String.fromCharCode(byte) : ".";
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
  const [error, setError] = useState<string | null>(null);
  const [history, setHistory] = useState<MemHistoryRecord[]>([]);
  const [historyAddr, setHistoryAddr] = useState<string | null>(null);
  const historyRef = useRef<HTMLDivElement>(null);

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
      const raw = e.payload.addr.replace(/^0x/i, "");
      const num = parseInt(raw, 16);
      if (isNaN(num)) return;
      const aligned = num - (num % 16);
      setAutoTrack(false);
      setCurrentAddr(`0x${aligned.toString(16)}`);
      setInputAddr(e.payload.addr);
    });
    return () => { unlisten.then(fn => fn()); };
  }, []);

  // auto-track 时更新 currentAddr，让访问地址出现在第一行
  useEffect(() => {
    if (autoTrack && memAddr) {
      const addr = parseInt(memAddr.replace(/^0x/i, ""), 16);
      if (isNaN(addr)) { setCurrentAddr(memAddr); return; }
      // 对齐到 16 字节边界
      const aligned = addr - (addr % 16);
      setCurrentAddr(`0x${aligned.toString(16)}`);
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
        length: DEFAULT_LENGTH,
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
  }, [selectedSeq, isPhase2Ready, currentAddr, sessionId]);

  // 查询地址读写历史（当 memAddr 变化时，debounce 150ms 让 register/memory 查询先完成）
  useEffect(() => {
    if (!memAddr || !isPhase2Ready || !sessionId) {
      setHistory([]);
      setHistoryAddr(null);
      return;
    }
    let cancelled = false;
    const timer = setTimeout(() => {
      setHistoryAddr(memAddr);
      invoke<MemHistoryRecord[]>("get_mem_history", { sessionId, addr: memAddr })
        .then((h) => {
          if (!cancelled) setHistory(h);
        })
        .catch(() => { if (!cancelled) setHistory([]); });
    }, 150);
    return () => { cancelled = true; clearTimeout(timer); };
  }, [memAddr, isPhase2Ready, sessionId]);

  const historyVirtualizer = useVirtualizerNoSync({
    count: history.length,
    getScrollElement: () => historyRef.current,
    estimateSize: () => 20,
    overscan: 10,
  });

  // 当 history 加载完成或 selectedSeq 变化时，滚动到当前 seq 居中
  useEffect(() => {
    if (history.length === 0 || selectedSeq === null) return;
    const idx = history.findIndex(r => r.seq === selectedSeq);
    if (idx >= 0) {
      historyVirtualizer.scrollToIndex(idx, { align: "center" });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [history, selectedSeq]);

  // Access History minimap state
  const [historyScrollRow, setHistoryScrollRow] = useState(0);
  const [historyContainerHeight, setHistoryContainerHeight] = useState(0);
  const historyObserverRef = useRef<{ ro: ResizeObserver; el: HTMLDivElement } | null>(null);

  const handleHistoryScroll = useCallback(() => {
    const el = historyRef.current;
    if (el) setHistoryScrollRow(Math.floor(el.scrollTop / HISTORY_ROW_HEIGHT));
  }, []);

  // Callback ref: 在元素挂载/卸载时立即设置/清理 ResizeObserver
  const historyRefCallback = useCallback((el: HTMLDivElement | null) => {
    // 清理旧的 observer
    if (historyObserverRef.current) {
      historyObserverRef.current.el.removeEventListener("scroll", handleHistoryScroll);
      historyObserverRef.current.ro.disconnect();
      historyObserverRef.current = null;
    }
    historyRef.current = el;
    if (!el) {
      setHistoryContainerHeight(0);
      return;
    }
    // 设置新的 observer
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
    el.addEventListener("scroll", handleHistoryScroll);
    ro.observe(el);
    historyObserverRef.current = { ro, el };
  }, [handleHistoryScroll]);

  // 组件卸载时清理 observer
  useEffect(() => {
    return () => {
      if (historyObserverRef.current) {
        historyObserverRef.current.el.removeEventListener("scroll", handleHistoryScroll);
        historyObserverRef.current.ro.disconnect();
        historyObserverRef.current = null;
      }
    };
  }, [handleHistoryScroll]);

  const historyResolve = useCallback((vi: number): ResolvedRow => {
    return { type: "line", seq: history[vi]?.seq ?? vi } as ResolvedRow;
  }, [history]);

  const historyGetLines = useCallback(async (seqs: number[]): Promise<TraceLine[]> => {
    const seqSet = new Set(seqs);
    return history.filter(r => seqSet.has(r.seq)).map(r => ({
      seq: r.seq,
      address: r.insn_addr,
      disasm: r.disasm,
      changes: `${r.rw} ${r.data}`,
    })) as unknown as TraceLine[];
  }, [history]);

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
      const base = parseInt(snapshot.base_addr.replace(/^0x/i, ""), 16);
      for (let i = 0; i < snapshot.bytes.length; i += BYTES_PER_LINE) {
        const lineAddr = base + i;
        const lineBytes: { value: number; known: boolean }[] = [];
        for (let j = 0; j < BYTES_PER_LINE && i + j < snapshot.bytes.length; j++) {
          lineBytes.push({ value: snapshot.bytes[i + j], known: snapshot.known[i + j] });
        }
        lines.push({ addr: `0x${lineAddr.toString(16)}`, bytes: lineBytes });
      }
    }
    return lines;
  }, [snapshot]);

  // 高亮当前指令访问的内存范围（useMemo 避免每次渲染重算）
  const { highlightStart, highlightEnd, lastNonZeroOffset } = useMemo(() => {
    let hStart = -1;
    let hEnd = -1;
    if (snapshot && memAddr && memRw) {
      const accessAddr = parseInt(memAddr.replace(/^0x/i, ""), 16);
      const base = parseInt(snapshot.base_addr.replace(/^0x/i, ""), 16);
      const offset = accessAddr - base;
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

  // 字节颜色：有效值字节=绿色，尾部高位零=白色，范围外=灰色
  const byteColor = useCallback((globalOffset: number) => {
    if (globalOffset >= highlightStart && globalOffset < highlightEnd) {
      return globalOffset <= lastNonZeroOffset ? "var(--text-ascii-printable)" : "var(--text-primary)";
    }
    return "var(--text-hex-zero)";
  }, [highlightStart, highlightEnd, lastNonZeroOffset]);

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

  const showHistory = !!(historyAddr && history.length > 0);

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
      <label style={{ display: "flex", alignItems: "center", gap: 3, color: "var(--text-secondary)", cursor: "pointer", whiteSpace: "nowrap" }}>
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
              <span style={{ width: 120, flexShrink: 0 }}>{"Address"}</span>
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
            <div style={{
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
                    <span style={{ color: "var(--text-address)", width: 120, flexShrink: 0 }}>
                      {line.addr}
                    </span>
                    {line.bytes.slice(0, 8).map((b, i) => {
                      const globalOffset = lineIdx * BYTES_PER_LINE + i;
                      return (
                        <span key={i} style={{ color: b.known ? byteColor(globalOffset) : "var(--text-hex-zero)" }}>
                          {b.known ? formatHexByte(b.value) : "??"}{" "}
                        </span>
                      );
                    })}
                    <span style={{ width: 4 }}> </span>
                    {line.bytes.slice(8, 16).map((b, i) => {
                      const globalOffset = lineIdx * BYTES_PER_LINE + 8 + i;
                      return (
                        <span key={i + 8} style={{ color: b.known ? byteColor(globalOffset) : "var(--text-hex-zero)" }}>
                          {b.known ? formatHexByte(b.value) : "??"}{" "}
                        </span>
                      );
                    })}
                    <span style={{ width: 8 }}> </span>
                    {line.bytes.map((b, i) => {
                      const globalOffset = lineIdx * BYTES_PER_LINE + i;
                      const isHighlight = globalOffset >= highlightStart && globalOffset < highlightEnd;
                      return (
                        <span key={`a${i}`} style={{
                          color: isHighlight ? "var(--text-ascii-printable)" : "var(--text-ascii-nonprint)",
                        }}>
                          {(b.known && b.value !== 0) ? toAsciiChar(b.value) : "."}
                        </span>
                      );
                    })}
                  </div>
                );
              })}
            </div>
            </div>
          </>)}
        </div>

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
                Total: {history.length.toLocaleString()}
              </div>
              <div style={{ flex: 1, display: "flex", overflow: "hidden" }}>
                <div
                  ref={historyRefCallback}
                  style={{ flex: 1, overflow: "auto", fontFamily: "var(--font-mono)", fontSize: "var(--font-size-sm)", outline: "none", scrollbarWidth: "none" } as React.CSSProperties}
                >
                  <div style={{ height: historyVirtualizer.getTotalSize(), width: "100%", position: "relative" }}>
                    {historyVirtualizer.getVirtualItems().map((vRow) => {
                      const rec = history[vRow.index];
                      if (!rec) return null;
                      const isCurrent = selectedSeq !== null && rec.seq === selectedSeq;
                      return (
                        <div
                          key={vRow.index}
                          onClick={() => onJumpToSeq(rec.seq)}
                          style={{
                            position: "absolute", top: 0, left: 0, width: "100%", height: 20,
                            transform: `translateY(${vRow.start}px)`,
                            display: "flex", alignItems: "center", padding: "0 8px", gap: 8,
                            cursor: "pointer",
                            background: isCurrent ? "var(--bg-selected)"
                              : vRow.index % 2 === 0 ? "var(--bg-row-even)" : "var(--bg-row-odd)",
                            whiteSpace: "nowrap",
                          }}
                          onMouseEnter={(e) => { if (!isCurrent) e.currentTarget.style.background = "var(--bg-hover)"; }}
                          onMouseLeave={(e) => { if (!isCurrent) e.currentTarget.style.background = vRow.index % 2 === 0 ? "var(--bg-row-even)" : "var(--bg-row-odd)"; }}
                        >
                          <span style={{ width: 90, color: "var(--text-secondary)", flexShrink: 0 }}>#{rec.seq + 1}</span>
                          <span style={{
                            width: 20, flexShrink: 0, textAlign: "center",
                            color: rec.rw === "W" ? "var(--text-hex-highlight)" : "var(--text-address)",
                          }}>{rec.rw}</span>
                          <span style={{ width: 280, color: "var(--text-ascii-printable)", flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis" }}>{rec.data}</span>
                          <span style={{ flex: 1, color: "var(--text-secondary)", overflow: "hidden", textOverflow: "ellipsis" }}>{rec.disasm}</span>
                        </div>
                      );
                    })}
                  </div>
                </div>
                {history.length > 0 && historyContainerHeight > 0 && (() => {
                  const hVisibleRows = Math.floor(historyContainerHeight / HISTORY_ROW_HEIGHT);
                  const hMaxRow = Math.max(0, history.length - hVisibleRows);
                  return (
                    <div style={{ width: MINIMAP_WIDTH + 12, flexShrink: 0, position: "relative" }}>
                      <Minimap
                        virtualTotalRows={history.length}
                        visibleRows={hVisibleRows}
                        currentRow={historyScrollRow}
                        maxRow={hMaxRow}
                        height={historyContainerHeight}
                        onScroll={(row) => { historyRef.current?.scrollTo({ top: row * HISTORY_ROW_HEIGHT }); }}
                        resolveVirtualIndex={historyResolve}
                        getLines={historyGetLines}
                        selectedSeq={selectedSeq}
                        rightOffset={12}
                        showSoName={false}
                        showAbsAddress={false}
                      />
                      <CustomScrollbar
                        currentRow={historyScrollRow}
                        maxRow={hMaxRow}
                        visibleRows={hVisibleRows}
                        virtualTotalRows={history.length}
                        trackHeight={historyContainerHeight}
                        onScroll={(row) => { historyRef.current?.scrollTo({ top: row * HISTORY_ROW_HEIGHT }); }}
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
