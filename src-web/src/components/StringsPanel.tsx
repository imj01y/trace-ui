import React, { useState, useEffect, useRef, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import { emit, emitTo, listen } from "@tauri-apps/api/event";
import { WebviewWindow } from "@tauri-apps/api/webviewWindow";
import { useVirtualizerNoSync } from "../hooks/useVirtualizerNoSync";
import ContextMenu, { ContextMenuItem } from "./ContextMenu";
import type { StringRecordDto, StringsResult, StringXRef } from "../types/trace";


const PAGE_SIZE = 500;
const ROW_HEIGHT = 22;
const HISTORY_KEY = "strings-search-history";
const MAX_HISTORY = 20;

interface Props {
  sessionId: string | null;
  isPhase2Ready: boolean;
  onJumpToSeq: (seq: number) => void;
  stringsScanning?: boolean;
  stringIndexProgress?: number | null; // null = ready, 0-100 = building
}

export default function StringsPanel({ sessionId, isPhase2Ready, onJumpToSeq, stringsScanning, stringIndexProgress }: Props) {
  const [strings, setStrings] = useState<StringRecordDto[]>([]);
  const [total, setTotal] = useState(0);
  const [minLen, setMinLen] = useState(4);
  const [search, setSearch] = useState("");
  const [loading, setLoading] = useState(false);
  const [selectedIdx, setSelectedIdx] = useState<number | null>(null);
  const [contextMenu, setContextMenu] = useState<{ x: number; y: number; record: StringRecordDto } | null>(null);

  const [searchHistory, setSearchHistory] = useState<string[]>(() => {
    try { return JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]"); } catch { return []; }
  });
  const [showHistory, setShowHistory] = useState(false);
  const historyBlurTimer = useRef<ReturnType<typeof setTimeout>>(undefined);
  const searchWrapperRef = useRef<HTMLDivElement>(null);

  const parentRef = useRef<HTMLDivElement>(null);
  const searchTimerRef = useRef<ReturnType<typeof setTimeout>>(undefined);
  const minLenTimerRef = useRef<ReturnType<typeof setTimeout>>(undefined);
  const pendingRef = useRef(0);

  // ── 数据加载 ──
  const loadStrings = useCallback(async (offset: number, reset: boolean) => {
    if (!sessionId || !isPhase2Ready) return;
    const reqId = ++pendingRef.current;
    if (reset) setLoading(true);

    try {
      const result = await invoke<StringsResult>("get_strings", {
        sessionId,
        minLen,
        offset,
        limit: PAGE_SIZE,
        search: search || null,
      });
      if (reqId !== pendingRef.current) return;
      if (reset) {
        setStrings(result.strings);
      } else {
        setStrings(prev => [...prev, ...result.strings]);
      }
      setTotal(result.total);
    } catch (e) {
      console.error("get_strings failed:", e);
    } finally {
      if (reqId === pendingRef.current) setLoading(false);
    }
  }, [sessionId, isPhase2Ready, minLen, search]);

  useEffect(() => {
    loadStrings(0, true);
  }, [loadStrings]);

  // ── scanning 结束后自动刷新 ──
  const prevScanningRef = useRef(false);
  useEffect(() => {
    if (prevScanningRef.current && !stringsScanning) {
      loadStrings(0, true);
    }
    prevScanningRef.current = !!stringsScanning;
  }, [stringsScanning, loadStrings]);

  // 字符串索引构建完成后自动刷新
  const prevStringIndexProgressRef = useRef(stringIndexProgress);
  useEffect(() => {
    if (prevStringIndexProgressRef.current != null && stringIndexProgress == null) {
      loadStrings(0, true);
    }
    prevStringIndexProgressRef.current = stringIndexProgress;
  }, [stringIndexProgress, loadStrings]);

  // ── 搜索 debounce ──
  const [searchInput, setSearchInput] = useState("");
  useEffect(() => {
    clearTimeout(searchTimerRef.current);
    searchTimerRef.current = setTimeout(() => {
      setSearch(searchInput);
      // 记录搜索历史
      if (searchInput.trim()) {
        setSearchHistory(prev => {
          const next = [searchInput.trim(), ...prev.filter(h => h !== searchInput.trim())].slice(0, MAX_HISTORY);
          localStorage.setItem(HISTORY_KEY, JSON.stringify(next));
          return next;
        });
      }
    }, 300);
    return () => clearTimeout(searchTimerRef.current);
  }, [searchInput]);

  // ── 搜索历史：点击外部关闭 ──
  useEffect(() => {
    if (!showHistory) return;
    const handler = (e: MouseEvent) => {
      if (searchWrapperRef.current && !searchWrapperRef.current.contains(e.target as Node)) {
        setShowHistory(false);
      }
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [showHistory]);

  const removeHistoryItem = useCallback((item: string) => {
    setSearchHistory(prev => {
      const next = prev.filter(h => h !== item);
      localStorage.setItem(HISTORY_KEY, JSON.stringify(next));
      return next;
    });
  }, []);

  const clearAllHistory = useCallback(() => {
    setSearchHistory([]);
    localStorage.removeItem(HISTORY_KEY);
    setShowHistory(false);
  }, []);

  const filteredHistory = searchInput.trim()
    ? searchHistory.filter(h => h !== searchInput.trim() && h.toLowerCase().includes(searchInput.toLowerCase()))
    : searchHistory;

  // ── minLen debounce ──
  const [minLenInput, setMinLenInput] = useState(4);
  useEffect(() => {
    clearTimeout(minLenTimerRef.current);
    minLenTimerRef.current = setTimeout(() => setMinLen(minLenInput), 200);
    return () => clearTimeout(minLenTimerRef.current);
  }, [minLenInput]);

  // ── 虚拟滚动 ──
  const virtualizer = useVirtualizerNoSync({
    count: strings.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 20,
  });

  // ── 无限滚动加载更多 ──
  const virtualItems = virtualizer.getVirtualItems();
  const lastVirtualItemIndex = virtualItems.length > 0 ? virtualItems[virtualItems.length - 1].index : -1;
  useEffect(() => {
    if (lastVirtualItemIndex >= strings.length - 50 && strings.length < total && !loading) {
      loadStrings(strings.length, false);
    }
  }, [lastVirtualItemIndex, strings.length, total, loading, loadStrings]);

  // ── 点击行：选中 + 跳转 trace 表 ──
  const handleRowClick = useCallback((record: StringRecordDto) => {
    setSelectedIdx(record.idx);
    onJumpToSeq(record.seq);
  }, [onJumpToSeq]);

  // ── 双击行跳转到 trace 表对应汇编指令行 ──
  const handleRowDoubleClick = useCallback((record: StringRecordDto) => {
    onJumpToSeq(record.seq);
  }, [onJumpToSeq]);

  // ── 右键菜单（同时选中该行） ──
  const handleContextMenu = useCallback((e: React.MouseEvent, record: StringRecordDto) => {
    e.preventDefault();
    setSelectedIdx(record.idx);
    setContextMenu({ x: e.clientX, y: e.clientY, record });
  }, []);

  const handleCopyString = useCallback(() => {
    if (contextMenu) navigator.clipboard.writeText(contextMenu.record.content);
    setContextMenu(null);
  }, [contextMenu]);

  const handleCopyAddr = useCallback(() => {
    if (contextMenu) navigator.clipboard.writeText(contextMenu.record.addr);
    setContextMenu(null);
  }, [contextMenu]);

  const handleViewInMemory = useCallback(() => {
    if (!contextMenu) return;
    const { addr, seq } = contextMenu.record;
    setContextMenu(null);
    emit("action:view-in-memory", { addr, seq });
  }, [contextMenu]);

  const handleViewDetail = useCallback(async () => {
    if (!contextMenu) return;
    const record = contextMenu.record;
    setContextMenu(null);
    const winLabel = `panel-string-detail-${Date.now()}`;
    const unlisten = await listen(`string-detail:ready:${winLabel}`, () => {
      emitTo(winLabel, "string-detail:init-data", record);
      unlisten();
    });
    new WebviewWindow(winLabel, {
      url: `index.html?panel=string-detail`,
      title: `String: ${record.content.slice(0, 40)}`,
      width: 588,
      minWidth: 588,
      maxWidth: 588,
      height: 580,
      decorations: false,
      transparent: true,
    });
  }, [contextMenu]);

  const handleShowXrefs = useCallback(async () => {
    if (!contextMenu || !sessionId) return;
    const record = contextMenu.record;
    setContextMenu(null);
    try {
      const items = await invoke<StringXRef[]>("get_string_xrefs", {
        sessionId,
        addr: record.addr,
        byteLen: record.byte_len,
      });
      const winLabel = `panel-string-xrefs-${Date.now()}`;
      // 先监听子窗口 ready 信号，收到后再发送数据
      const unlisten = await listen(`xrefs:ready:${winLabel}`, () => {
        emitTo(winLabel, "xrefs:init-data", { record, items });
        unlisten();
      });
      new WebviewWindow(winLabel, {
        url: `index.html?panel=string-xrefs`,
        title: `XRefs: ${record.content.slice(0, 30)}`,
        width: 520,
        height: 400,
        decorations: false,
        transparent: true,
      });
    } catch (e) {
      console.error("get_string_xrefs failed:", e);
    }
  }, [contextMenu, sessionId]);

  if (!isPhase2Ready) {
    return (
      <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center" }}>
        <span style={{ color: "var(--text-secondary)", fontSize: 12 }}>Index not ready</span>
      </div>
    );
  }

  if (stringIndexProgress != null) {
    return (
      <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center", flexDirection: "column", gap: 8 }}>
        <span style={{ color: "var(--text-secondary)", fontSize: 12 }}>
          正在构建字符串索引... {stringIndexProgress}%
        </span>
        <div style={{ width: 200, height: 4, background: "var(--border-color)", borderRadius: 2 }}>
          <div style={{ width: `${stringIndexProgress}%`, height: "100%", background: "var(--accent-color, #4a9eff)", borderRadius: 2, transition: "width 0.3s ease" }} />
        </div>
      </div>
    );
  }

  return (
    <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
      {/* 工具栏 */}
      <div style={{
        display: "flex", alignItems: "center", gap: 8, padding: "4px 8px",
        borderBottom: "1px solid var(--border-color)", flexShrink: 0,
      }}>
        <div ref={searchWrapperRef} style={{ position: "relative", width: 420, flexShrink: 0 }}>
          <input
            value={searchInput}
            onChange={e => setSearchInput(e.target.value)}
            onFocus={() => setShowHistory(true)}
            placeholder="Search strings..."
            style={{
              width: "100%", background: "var(--input-bg)", border: "1px solid var(--border-color)",
              color: "var(--text-primary)", padding: "3px 24px 3px 8px", borderRadius: 3, fontSize: 12,
            }}
          />
          {searchInput && (
            <span
              onClick={() => { setSearchInput(""); setShowHistory(false); }}
              style={{
                position: "absolute", right: 4, top: "50%", transform: "translateY(-50%)",
                cursor: "pointer", color: "var(--text-secondary)", fontSize: 14, lineHeight: 1,
                width: 16, height: 16, display: "flex", alignItems: "center", justifyContent: "center",
                borderRadius: "50%",
              }}
              onMouseEnter={e => (e.currentTarget.style.color = "var(--text-primary)")}
              onMouseLeave={e => (e.currentTarget.style.color = "var(--text-secondary)")}
            >×</span>
          )}
          {showHistory && filteredHistory.length > 0 && (
            <div style={{
              position: "absolute", top: "100%", left: 0, width: "100%", marginTop: 2,
              background: "var(--bg-dialog)", border: "1px solid var(--border-color)",
              borderRadius: 4, zIndex: 100, maxHeight: 200, overflowY: "auto",
              boxShadow: "0 4px 12px rgba(0,0,0,0.4)",
            }}>
              {filteredHistory.map(item => (
                <div
                  key={item}
                  style={{
                    display: "flex", alignItems: "center", padding: "4px 8px", fontSize: 12,
                    cursor: "pointer", color: "var(--text-primary)",
                  }}
                  onMouseEnter={e => (e.currentTarget.style.background = "var(--bg-selected)")}
                  onMouseLeave={e => (e.currentTarget.style.background = "transparent")}
                  onClick={() => { setSearchInput(item); setShowHistory(false); }}
                >
                  <span style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{item}</span>
                  <span
                    onClick={e => { e.stopPropagation(); removeHistoryItem(item); }}
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
                onClick={clearAllHistory}
              >Clear All</div>
            </div>
          )}
        </div>
        <span style={{ flex: 1 }} />
        <span style={{ color: "var(--text-tertiary)", fontSize: 11, whiteSpace: "nowrap" }}>
          {total.toLocaleString()} strings
        </span>
        <span style={{ color: "var(--text-secondary)", fontSize: 11, whiteSpace: "nowrap" }}>Min len:</span>
        <input
          type="range" min={2} max={32} value={minLenInput}
          onChange={e => setMinLenInput(Number(e.target.value))}
          style={{ width: 120 }}
        />
        <span style={{ color: "var(--text-secondary)", fontSize: 11, minWidth: 16 }}>{minLenInput}</span>
      </div>

      {/* 表头 */}
      <div style={{
        display: "flex", padding: "4px 8px",
        background: "var(--bg-secondary)",
        borderBottom: "1px solid var(--border-color)",
        fontSize: "var(--font-size-sm)", color: "var(--text-secondary)", flexShrink: 0,
      }}>
        <span style={{ width: 70, flexShrink: 0 }}>Seq</span>
        <span style={{ width: 110, flexShrink: 0 }}>Address</span>
        <span style={{ flex: 1 }}>Content</span>
        <span style={{ width: 56, flexShrink: 0 }}>Enc</span>
        <span style={{ width: 44, flexShrink: 0 }}>Len</span>
        <span style={{ width: 56, flexShrink: 0 }}>XRefs</span>
      </div>

      {/* 虚拟滚动列表 */}
      <div ref={parentRef} style={{ flex: 1, overflow: "auto" }}>
        <div style={{ height: virtualizer.getTotalSize(), width: "100%", position: "relative" }}>
          {virtualItems.map(virtualRow => {
            const record = strings[virtualRow.index];
            if (!record) return null;
            const isSelected = record.idx === selectedIdx;
            return (
              <div
                key={virtualRow.key}
                data-index={virtualRow.index}
                ref={virtualizer.measureElement}
                onClick={() => handleRowClick(record)}
                onDoubleClick={() => handleRowDoubleClick(record)}
                onContextMenu={e => handleContextMenu(e, record)}
                style={{
                  position: "absolute", top: 0, left: 0, width: "100%", height: ROW_HEIGHT,
                  transform: `translateY(${virtualRow.start}px)`,
                  display: "flex", alignItems: "center", padding: "0 8px",
                  cursor: "pointer", fontSize: "var(--font-size-sm)",
                  background: isSelected ? "var(--bg-selected)"
                    : virtualRow.index % 2 === 0 ? "var(--bg-row-even)" : "var(--bg-row-odd)",
                }}
                onMouseEnter={(e) => { if (!isSelected) e.currentTarget.style.background = "rgba(255,255,255,0.04)"; }}
                onMouseLeave={(e) => { if (!isSelected) e.currentTarget.style.background = virtualRow.index % 2 === 0 ? "var(--bg-row-even)" : "var(--bg-row-odd)"; }}
              >
                <span style={{ width: 70, flexShrink: 0, color: "var(--syntax-number)" }}>{record.seq + 1}</span>
                <span style={{ width: 110, flexShrink: 0, color: "var(--syntax-literal)" }}>{record.addr}</span>
                <span style={{
                  flex: 1, color: "var(--syntax-string)",
                  overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                }}>"{record.content}"</span>
                <span style={{ width: 56, flexShrink: 0, color: "var(--text-secondary)" }}>{record.encoding}</span>
                <span style={{ width: 44, flexShrink: 0 }}>{record.byte_len}</span>
                <span style={{ width: 56, flexShrink: 0, color: record.xref_count > 0 ? "var(--syntax-keyword)" : "var(--text-secondary)" }}>
                  {record.xref_count}
                </span>
              </div>
            );
          })}
        </div>
      </div>

      {loading && (
        <div style={{
          padding: "3px 8px", flexShrink: 0,
          borderTop: "1px solid var(--border-color)",
          background: "var(--bg-secondary)",
          fontSize: 11, color: "var(--text-secondary)",
        }}>
          Loading...
        </div>
      )}

      {stringsScanning && (
        <div style={{
          padding: "8px 12px",
          fontSize: 11,
          color: "var(--text-secondary)",
          textAlign: "center",
          borderTop: "1px solid var(--border-color)",
        }}>
          Scanning strings...
        </div>
      )}

      {/* 右键菜单 — Portal 到 body，避免祖先 overflow:hidden 裁剪 */}
      {contextMenu && (
        <ContextMenu x={contextMenu.x} y={contextMenu.y} onClose={() => setContextMenu(null)} minWidth={160}>
          <ContextMenuItem label="View Detail" onClick={handleViewDetail} />
          <ContextMenuItem label="View in Memory" onClick={handleViewInMemory} />
          <ContextMenuItem label="Show XRefs" onClick={handleShowXrefs} />
          <ContextMenuItem label="Copy String" onClick={handleCopyString} />
          <ContextMenuItem label="Copy Address" onClick={handleCopyAddr} />
        </ContextMenu>
      )}

    </div>
  );
}
