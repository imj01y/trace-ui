import React, { useState, useEffect, useRef, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useVirtualizerNoSync } from "../hooks/useVirtualizerNoSync";
import type { StringRecordDto, StringsResult, StringXRef } from "../types/trace";

const PAGE_SIZE = 500;
const ROW_HEIGHT = 22;

interface Props {
  sessionId: string | null;
  isPhase2Ready: boolean;
  onJumpToSeq: (seq: number) => void;
}

export default function StringsPanel({ sessionId, isPhase2Ready, onJumpToSeq }: Props) {
  const [strings, setStrings] = useState<StringRecordDto[]>([]);
  const [total, setTotal] = useState(0);
  const [minLen, setMinLen] = useState(4);
  const [search, setSearch] = useState("");
  const [loading, setLoading] = useState(false);
  const [selectedIdx, setSelectedIdx] = useState<number | null>(null);
  const [contextMenu, setContextMenu] = useState<{ x: number; y: number; record: StringRecordDto } | null>(null);
  const [xrefs, setXrefs] = useState<{ record: StringRecordDto; items: StringXRef[] } | null>(null);
  const [detail, setDetail] = useState<StringRecordDto | null>(null);

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

  // ── 搜索 debounce ──
  const [searchInput, setSearchInput] = useState("");
  useEffect(() => {
    clearTimeout(searchTimerRef.current);
    searchTimerRef.current = setTimeout(() => setSearch(searchInput), 300);
    return () => clearTimeout(searchTimerRef.current);
  }, [searchInput]);

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

  // ── 点击行 ──
  const handleRowClick = useCallback((record: StringRecordDto) => {
    setSelectedIdx(record.idx);
    onJumpToSeq(record.seq);
  }, [onJumpToSeq]);

  // ── 双击行弹出详情 ──
  const handleRowDoubleClick = useCallback((record: StringRecordDto) => {
    setDetail(record);
  }, []);

  // ── 右键菜单 ──
  const handleContextMenu = useCallback((e: React.MouseEvent, record: StringRecordDto) => {
    e.preventDefault();
    setContextMenu({ x: e.clientX, y: e.clientY, record });
  }, []);

  useEffect(() => {
    const close = () => setContextMenu(null);
    window.addEventListener("click", close);
    return () => window.removeEventListener("click", close);
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
    if (contextMenu) onJumpToSeq(contextMenu.record.seq);
    setContextMenu(null);
  }, [contextMenu, onJumpToSeq]);

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
      setXrefs({ record, items });
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

  return (
    <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
      {/* 工具栏 */}
      <div style={{
        display: "flex", alignItems: "center", gap: 8, padding: "4px 8px",
        borderBottom: "1px solid var(--border-color)", flexShrink: 0,
      }}>
        <input
          value={searchInput}
          onChange={e => setSearchInput(e.target.value)}
          placeholder="Search strings..."
          style={{
            flex: 1, background: "var(--input-bg)", border: "1px solid var(--border-color)",
            color: "var(--text-primary)", padding: "3px 8px", borderRadius: 3, fontSize: 12,
          }}
        />
        <span style={{ color: "var(--text-secondary)", fontSize: 11, whiteSpace: "nowrap" }}>Min len:</span>
        <input
          type="range" min={2} max={20} value={minLenInput}
          onChange={e => setMinLenInput(Number(e.target.value))}
          style={{ width: 60 }}
        />
        <span style={{ color: "var(--text-secondary)", fontSize: 11, minWidth: 16 }}>{minLenInput}</span>
        <span style={{ color: "var(--text-tertiary)", fontSize: 11, whiteSpace: "nowrap" }}>
          {total.toLocaleString()} strings
        </span>
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
                <span style={{ width: 70, flexShrink: 0, color: "var(--syntax-number)" }}>{record.seq}</span>
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

      {/* 右键菜单 */}
      {contextMenu && (
        <div style={{
          position: "fixed", left: contextMenu.x, top: contextMenu.y, zIndex: 9999,
          background: "var(--bg-secondary)", border: "1px solid var(--border-color)",
          borderRadius: 4, padding: "4px 0", boxShadow: "0 4px 12px rgba(0,0,0,0.3)",
          minWidth: 160,
        }}>
          {[
            { label: "Copy String", action: handleCopyString },
            { label: "Copy Address", action: handleCopyAddr },
            { label: "View in Memory", action: handleViewInMemory },
            { label: "Show XRefs", action: handleShowXrefs },
          ].map(item => (
            <div
              key={item.label}
              onClick={item.action}
              style={{
                padding: "5px 12px", fontSize: 12, cursor: "pointer",
                color: "var(--text-primary)",
              }}
              onMouseEnter={e => (e.currentTarget.style.background = "var(--selection-bg)")}
              onMouseLeave={e => (e.currentTarget.style.background = "transparent")}
            >
              {item.label}
            </div>
          ))}
        </div>
      )}

      {/* XRefs 弹窗 */}
      {xrefs && (
        <div style={{
          position: "fixed", left: "50%", top: "50%", transform: "translate(-50%, -50%)",
          zIndex: 9999, background: "var(--bg-primary)", border: "1px solid var(--border-color)",
          borderRadius: 6, boxShadow: "0 8px 24px rgba(0,0,0,0.4)",
          width: 500, maxHeight: 400, display: "flex", flexDirection: "column",
        }}>
          <div style={{
            padding: "8px 12px", borderBottom: "1px solid var(--border-color)",
            display: "flex", justifyContent: "space-between", alignItems: "center",
          }}>
            <span style={{ fontSize: 12, color: "var(--text-primary)" }}>
              XRefs for "{xrefs.record.content.slice(0, 30)}{xrefs.record.content.length > 30 ? "..." : ""}" ({xrefs.items.length})
            </span>
            <button
              onClick={() => setXrefs(null)}
              style={{
                background: "none", border: "none", color: "var(--text-secondary)",
                cursor: "pointer", fontSize: 16, padding: "0 4px",
              }}
            >×</button>
          </div>
          <div style={{ flex: 1, overflow: "auto" }}>
            {xrefs.items.map((xref, i) => (
              <div
                key={i}
                onClick={() => { onJumpToSeq(xref.seq); setXrefs(null); }}
                style={{
                  padding: "4px 12px", fontSize: 12, fontFamily: "var(--font-mono)",
                  cursor: "pointer", borderBottom: "1px solid var(--border-subtle)",
                  display: "flex", gap: 12,
                }}
                onMouseEnter={e => (e.currentTarget.style.background = "var(--selection-bg)")}
                onMouseLeave={e => (e.currentTarget.style.background = "transparent")}
              >
                <span style={{ color: "var(--syntax-number)", minWidth: 60 }}>{xref.seq}</span>
                <span style={{ color: xref.rw === "R" ? "var(--syntax-keyword)" : "var(--syntax-literal)", minWidth: 16 }}>{xref.rw}</span>
                <span style={{ color: "var(--text-secondary)", minWidth: 90 }}>{xref.insn_addr}</span>
                <span style={{ color: "var(--text-primary)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{xref.disasm}</span>
              </div>
            ))}
          </div>
        </div>
      )}
      {/* 详情弹窗 */}
      {detail && (
        <div style={{
          position: "fixed", left: "50%", top: "50%", transform: "translate(-50%, -50%)",
          zIndex: 9999, background: "var(--bg-primary)", border: "1px solid var(--border-color)",
          borderRadius: 6, boxShadow: "0 8px 24px rgba(0,0,0,0.4)",
          width: 560, maxHeight: "80vh", display: "flex", flexDirection: "column",
        }}>
          <div style={{
            padding: "8px 12px", borderBottom: "1px solid var(--border-color)",
            display: "flex", justifyContent: "space-between", alignItems: "center",
          }}>
            <span style={{ fontSize: 12, color: "var(--text-primary)", fontWeight: 600 }}>String Detail</span>
            <button
              onClick={() => setDetail(null)}
              style={{
                background: "none", border: "none", color: "var(--text-secondary)",
                cursor: "pointer", fontSize: 16, padding: "0 4px",
              }}
            >×</button>
          </div>
          <div style={{ flex: 1, overflow: "auto", padding: 12, fontSize: 12, fontFamily: "var(--font-mono)" }}>
            {[
              { label: "Address", value: detail.addr },
              { label: "Seq", value: String(detail.seq) },
              { label: "Encoding", value: detail.encoding },
              { label: "Byte Length", value: String(detail.byte_len) },
              { label: "XRef Count", value: String(detail.xref_count) },
            ].map(item => (
              <div key={item.label} style={{ display: "flex", marginBottom: 8 }}>
                <span style={{ width: 100, flexShrink: 0, color: "var(--text-secondary)" }}>{item.label}</span>
                <span style={{ color: "var(--text-primary)" }}>{item.value}</span>
              </div>
            ))}
            <div style={{ marginBottom: 4, color: "var(--text-secondary)" }}>Content</div>
            <div style={{
              padding: "8px 10px", background: "var(--bg-secondary)", borderRadius: 4,
              border: "1px solid var(--border-color)", color: "var(--syntax-string)",
              whiteSpace: "pre-wrap", wordBreak: "break-all", maxHeight: 300, overflow: "auto",
              userSelect: "text", lineHeight: 1.5,
            }}>
              {detail.content}
            </div>
          </div>
          <div style={{
            padding: "8px 12px", borderTop: "1px solid var(--border-color)",
            display: "flex", justifyContent: "flex-end", gap: 8,
          }}>
            <button
              onClick={() => { navigator.clipboard.writeText(detail.content); }}
              style={{
                padding: "4px 12px", fontSize: 12, cursor: "pointer",
                background: "var(--btn-primary)", color: "#fff", border: "none", borderRadius: 3,
              }}
            >Copy Content</button>
            <button
              onClick={() => setDetail(null)}
              style={{
                padding: "4px 12px", fontSize: 12, cursor: "pointer",
                background: "var(--bg-secondary)", color: "var(--text-primary)",
                border: "1px solid var(--border-color)", borderRadius: 3,
              }}
            >Close</button>
          </div>
        </div>
      )}
    </div>
  );
}
