import { useState, useEffect, useMemo, useRef, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useVirtualScroll } from "../hooks/useVirtualScroll";
import type { FunctionCallEntry, FunctionCallsResult } from "../types/trace";
import ContextMenu, { ContextMenuItem } from "./ContextMenu";

type FilterType = "all" | "syscall" | "jni";

const HISTORY_KEY = "func-list-search-history";
const MAX_HISTORY = 20;

type FlatRow = {
  type: "group";
  entry: FunctionCallEntry;
  isExpanded: boolean;
} | {
  type: "occurrence";
  seq: number;
  summary: string;
  func_name: string;
};

interface Props {
  sessionId: string | null;
  isPhase2Ready: boolean;
  onJumpToSeq: (seq: number) => void;
}

export default function FunctionListPanel({ sessionId, isPhase2Ready, onJumpToSeq }: Props) {
  const [data, setData] = useState<FunctionCallsResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<FilterType>("all");
  const [search, setSearch] = useState("");
  const [searchInput, setSearchInput] = useState("");
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [selectedSeq, setSelectedSeq] = useState<number | null>(null);
  const [ctxMenu, setCtxMenu] = useState<{ x: number; y: number; funcName: string } | null>(null);
  const searchTimerRef = useRef<ReturnType<typeof setTimeout>>(undefined);

  // Search history
  const [searchHistory, setSearchHistory] = useState<string[]>(() => {
    try { return JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]"); } catch { return []; }
  });
  const [showHistory, setShowHistory] = useState(false);
  const searchWrapperRef = useRef<HTMLDivElement>(null);

  // Fetch data when sessionId changes or phase2 becomes ready
  useEffect(() => {
    if (!sessionId || !isPhase2Ready) { setData(null); return; }
    setLoading(true);
    setError(null);
    invoke<FunctionCallsResult>("get_function_calls", { sessionId })
      .then((result) => {
        setData(result);
        setExpanded(new Set());
      })
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false));
  }, [sessionId, isPhase2Ready]);

  // Search debounce + history recording
  useEffect(() => {
    clearTimeout(searchTimerRef.current);
    searchTimerRef.current = setTimeout(() => {
      setSearch(searchInput);
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

  // Click outside to close history dropdown
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

  // Filter + search
  const filtered = useMemo(() => {
    if (!data) return [];
    let fns = data.functions;
    if (filter === "jni") fns = fns.filter(f => f.is_jni);
    else if (filter === "syscall") fns = fns.filter(f => !f.is_jni);
    if (search) {
      const q = search.toLowerCase();
      fns = fns.filter(f => f.func_name.toLowerCase().includes(q));
    }
    return fns;
  }, [data, filter, search]);

  // Flatten for virtual list
  const rows = useMemo(() => {
    const result: FlatRow[] = [];
    for (const entry of filtered) {
      const isExpanded = expanded.has(entry.func_name);
      result.push({ type: "group", entry, isExpanded });
      if (isExpanded) {
        for (const occ of entry.occurrences) {
          result.push({ type: "occurrence", seq: occ.seq, summary: occ.summary, func_name: entry.func_name });
        }
      }
    }
    return result;
  }, [filtered, expanded]);

  const vs = useVirtualScroll({ totalCount: rows.length, rowHeight: 22, overscan: 10 });

  const toggleExpand = useCallback((funcName: string) => {
    setExpanded(prev => {
      const next = new Set(prev);
      if (next.has(funcName)) next.delete(funcName);
      else next.add(funcName);
      return next;
    });
  }, []);

  // Stats
  const filteredCalls = useMemo(() => filtered.reduce((sum, f) => sum + f.occurrences.length, 0), [filtered]);

  if (!sessionId) {
    return <div style={{ padding: 12, color: "var(--text-secondary)" }}>No file loaded</div>;
  }

  if (loading) {
    return <div style={{ padding: 12, color: "var(--text-secondary)" }}>Loading...</div>;
  }

  if (error) {
    return <div style={{ padding: 12, color: "var(--text-secondary)" }}>{error}</div>;
  }

  if (!data || data.functions.length === 0) {
    return <div style={{ padding: 12, color: "var(--text-secondary)" }}>No function calls found</div>;
  }

  return (
    <div style={{ height: "100%", display: "flex", flexDirection: "column", background: "var(--bg-primary)" }}>
      {/* Search box */}
      <div style={{ padding: "4px 6px", flexShrink: 0 }}>
        <div ref={searchWrapperRef} style={{ position: "relative" }}>
          <input
            type="text"
            placeholder="Search functions..."
            value={searchInput}
            onChange={e => setSearchInput(e.target.value)}
            onFocus={() => setShowHistory(true)}
            style={{
              width: "100%",
              padding: "3px 24px 3px 6px",
              background: "var(--bg-secondary)",
              border: "none",
              borderRadius: 3,
              color: "var(--text-primary)",
              fontSize: "var(--font-size-sm)",
              fontFamily: "var(--font-mono)",
              outline: "none",
              boxSizing: "border-box",
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
      </div>

      {/* Filter buttons */}
      <div style={{ display: "flex", gap: 2, padding: "3px 6px", flexShrink: 0 }}>
        {(["all", "syscall", "jni"] as FilterType[]).map(f => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            style={{
              flex: 1,
              padding: "2px 0",
              background: filter === f ? "var(--bg-selected)" : "transparent",
              color: filter === f ? "var(--text-primary)" : "var(--text-secondary)",
              border: "none",
              borderRadius: 3,
              fontSize: "var(--font-size-sm)",
              fontFamily: "var(--font-mono)",
              cursor: "pointer",
            }}
          >
            {f === "all" ? "All" : f === "syscall" ? "Syscall" : "JNI"}
          </button>
        ))}
      </div>

      {/* Header */}
      <div style={{
        color: "var(--text-secondary)", fontSize: 11,
        padding: "4px 8px 3px", borderBottom: "1px solid var(--border-color)", flexShrink: 0,
      }}>
        {filtered.length} functions, {filteredCalls} calls
      </div>

      {/* Virtual list */}
      <div ref={vs.containerRef} style={{ flex: 1, ...vs.containerStyle }}>
        {Array.from({ length: Math.max(0, vs.endIdx - vs.startIdx + 1) }, (_, i) => {
          const index = vs.startIdx + i;
          const row = rows[index];
          if (!row) return null;
          const y = vs.getItemY(index);
          if (row.type === "group") {
            const { entry, isExpanded } = row;
            return (
              <div
                key={`g-${entry.func_name}`}
                style={{
                  position: "absolute",
                  top: 0,
                  left: 0,
                  right: 0,
                  height: 22,
                  transform: `translateY(${y}px)`,
                  display: "flex",
                  alignItems: "center",
                  padding: "0 8px",
                  cursor: "pointer",
                  fontSize: 12,
                  userSelect: "none",
                }}
                onClick={() => toggleExpand(entry.func_name)}
                onContextMenu={e => { e.preventDefault(); e.stopPropagation(); setCtxMenu({ x: e.clientX, y: e.clientY, funcName: entry.func_name }); }}
                onMouseEnter={e => (e.currentTarget.style.background = "var(--bg-row-odd)")}
                onMouseLeave={e => (e.currentTarget.style.background = "transparent")}
              >
                <span style={{ width: 12, textAlign: "center", flexShrink: 0, color: "var(--text-secondary)", fontSize: 10 }}>
                  {isExpanded ? "\u25BC" : "\u25B6"}
                </span>
                <span style={{
                  color: entry.is_jni ? "#d16d9e" : "#e06c75",
                  fontWeight: 500,
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                  whiteSpace: "nowrap",
                  flex: 1,
                }}>
                  {entry.func_name}
                </span>
                <span style={{
                  marginLeft: 6,
                  color: "var(--text-secondary)",
                  fontSize: 11,
                  flexShrink: 0,
                }}>
                  {entry.is_jni ? "JNI" : "SYS"} ({entry.occurrences.length})
                </span>
              </div>
            );
          } else {
            return (
              <div
                key={`o-${row.func_name}-${row.seq}`}
                style={{
                  position: "absolute",
                  top: 0,
                  left: 0,
                  right: 0,
                  height: 22,
                  transform: `translateY(${y}px)`,
                  display: "flex",
                  alignItems: "center",
                  padding: "0 8px 0 28px",
                  cursor: "pointer",
                  fontSize: 12,
                  background: selectedSeq === row.seq ? "var(--bg-selected)" : "transparent",
                }}
                onClick={() => { setSelectedSeq(row.seq); onJumpToSeq(row.seq); }}
                onMouseEnter={e => { if (selectedSeq !== row.seq) e.currentTarget.style.background = "var(--bg-row-odd)"; }}
                onMouseLeave={e => { if (selectedSeq !== row.seq) e.currentTarget.style.background = "transparent"; }}
              >
                <span style={{ color: "var(--text-address)", marginRight: 8, flexShrink: 0 }}>
                  #{row.seq + 1}
                </span>
                <span style={{
                  color: "var(--text-primary)",
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                  whiteSpace: "nowrap",
                }}>
                  {row.summary.startsWith(row.func_name) ? row.summary.slice(row.func_name.length) : row.summary}
                </span>
              </div>
            );
          }
        })}
      </div>

      {ctxMenu && (
        <ContextMenu x={ctxMenu.x} y={ctxMenu.y} onClose={() => setCtxMenu(null)}>
          <ContextMenuItem
            label="Copy Function Name"
            onClick={() => { navigator.clipboard.writeText(ctxMenu.funcName); setCtxMenu(null); }}
          />
        </ContextMenu>
      )}

    </div>
  );
}
