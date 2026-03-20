import React, { useState, useCallback, useRef, useEffect } from "react";

export interface SearchOptions {
  caseSensitive: boolean;
  wholeWord: boolean;
  useRegex: boolean;
  fuzzyMatch: boolean;
}

const HISTORY_KEY = "search-panel-history";
const MAX_HISTORY = 20;

interface SearchBarProps {
  query: string;
  onQueryChange: (q: string) => void;
  onSearch: (query: string, options: SearchOptions) => void;
  onPrevMatch: () => void;
  onNextMatch: () => void;
  matchInfo?: string;
  inputRef?: React.RefObject<HTMLInputElement | null>;
  /** 初始 toggle 状态（浮窗打开时从主窗口继承） */
  initialOptions?: SearchOptions;
  /** toggle 状态变化时回调（用于同步状态） */
  onOptionsChange?: (options: SearchOptions) => void;
}

// VSCode 风格 toggle 按钮
function ToggleButton({
  active, onClick, title, children,
}: {
  active: boolean; onClick: () => void; title: string; children: React.ReactNode;
}) {
  const [hovered, setHovered] = useState(false);
  return (
    <button
      onClick={onClick}
      title={title}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        width: 22, height: 22,
        display: "flex", alignItems: "center", justifyContent: "center",
        background: active ? "rgba(255,255,255,0.12)" : hovered ? "rgba(255,255,255,0.06)" : "transparent",
        color: active ? "var(--text-primary)" : "var(--text-secondary)",
        border: "none", borderRadius: 3, cursor: "pointer",
        padding: 0, position: "relative",
        fontSize: 12, fontFamily: "var(--font-mono)",
      }}
    >
      {children}
      {active && (
        <span style={{
          position: "absolute", bottom: 0, left: 3, right: 3, height: 2,
          background: "var(--btn-primary)", borderRadius: 1,
        }} />
      )}
    </button>
  );
}

// 小型图标按钮（上下导航、选项）
function IconButton({
  onClick, title, disabled, children,
}: {
  onClick: () => void; title: string; disabled?: boolean; children: React.ReactNode;
}) {
  const [hovered, setHovered] = useState(false);
  return (
    <button
      onClick={onClick}
      title={title}
      disabled={disabled}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        width: 22, height: 22,
        display: "flex", alignItems: "center", justifyContent: "center",
        background: hovered && !disabled ? "rgba(255,255,255,0.08)" : "transparent",
        color: disabled ? "var(--text-disabled, #555)" : "var(--text-secondary)",
        border: "none", borderRadius: 3,
        cursor: disabled ? "default" : "pointer", padding: 0,
      }}
    >
      {children}
    </button>
  );
}

export default function SearchBar({
  query, onQueryChange, onSearch, onPrevMatch, onNextMatch, matchInfo,
  inputRef: externalRef, initialOptions, onOptionsChange,
}: SearchBarProps) {
  const [options, setOptions] = useState<SearchOptions>(
    initialOptions ?? { caseSensitive: false, wholeWord: false, useRegex: false, fuzzyMatch: false }
  );
  const internalRef = useRef<HTMLInputElement>(null);
  const ref = externalRef || internalRef;

  // ── 搜索历史 ──
  const [searchHistory, setSearchHistory] = useState<string[]>(() => {
    try { return JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]"); } catch { return []; }
  });
  const [showHistory, setShowHistory] = useState(false);
  const searchWrapperRef = useRef<HTMLDivElement>(null);

  const addToHistory = useCallback((q: string) => {
    if (!q.trim()) return;
    setSearchHistory(prev => {
      const next = [q.trim(), ...prev.filter(h => h !== q.trim())].slice(0, MAX_HISTORY);
      localStorage.setItem(HISTORY_KEY, JSON.stringify(next));
      return next;
    });
  }, []);

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

  // 点击外部关闭历史面板
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

  const filteredHistory = query.trim()
    ? searchHistory.filter(h => h !== query.trim() && h.toLowerCase().includes(query.toLowerCase()))
    : searchHistory;

  // 同步外部 initialOptions 变化（ESC 还原时）
  useEffect(() => {
    if (initialOptions) {
      setOptions(initialOptions);
    }
  }, [initialOptions]);

  const toggle = useCallback((key: keyof SearchOptions) => {
    setOptions(prev => {
      const next = { ...prev, [key]: !prev[key] };
      onOptionsChange?.(next);
      return next;
    });
  }, [onOptionsChange]);

  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key === "Enter") {
      e.preventDefault();
      if (e.shiftKey) {
        onPrevMatch();
      } else {
        addToHistory(query);
        setShowHistory(false);
        onSearch(query, options);
        onNextMatch();
      }
    } else if (e.key === "Escape") {
      setShowHistory(false);
    }
  }, [query, options, onSearch, onPrevMatch, onNextMatch, addToHistory]);

  return (
    <div style={{
      display: "flex", gap: 2, padding: "6px 8px",
      borderBottom: "1px solid var(--border-color)", flexShrink: 0,
      alignItems: "center",
    }}>
      {/* 搜索输入框 + 内嵌 toggle + 历史下拉 */}
      <div ref={searchWrapperRef} style={{
        flex: 1, position: "relative",
      }}>
        <div style={{
          display: "flex", alignItems: "center",
          background: "var(--bg-input)", border: "1px solid var(--border-color)",
          borderRadius: 3, overflow: "hidden",
        }}>
          <input
            ref={ref}
            type="text"
            placeholder="Search text or /regex/"
            value={query}
            onChange={(e) => onQueryChange(e.target.value)}
            onKeyDown={handleKeyDown}
            onFocus={() => setShowHistory(true)}
            style={{
              flex: 1, padding: "3px 8px",
              background: "transparent", color: "var(--text-primary)",
              border: "none", outline: "none",
              fontFamily: "var(--font-mono)", fontSize: "var(--font-size-sm)",
              minWidth: 0,
            }}
          />
          <div style={{ display: "flex", gap: 1, paddingRight: 4, flexShrink: 0 }}>
            <ToggleButton
              active={options.caseSensitive}
              onClick={() => toggle("caseSensitive")}
              title="Match Case"
            >
              <span style={{ fontSize: 13, fontFamily: "serif", fontWeight: 600 }}>Aa</span>
            </ToggleButton>
            <ToggleButton
              active={options.wholeWord}
              onClick={() => toggle("wholeWord")}
              title="Match Whole Word"
            >
              <span style={{
                fontSize: 10, fontWeight: 700,
                border: "1.2px solid currentColor", borderRadius: 2,
                padding: "0 2px", lineHeight: "14px",
              }}>ab</span>
            </ToggleButton>
            <ToggleButton
              active={options.useRegex}
              onClick={() => toggle("useRegex")}
              title="Use Regular Expression"
            >
              <span style={{ fontSize: 12 }}>.*</span>
            </ToggleButton>
            <ToggleButton
              active={options.fuzzyMatch}
              onClick={() => toggle("fuzzyMatch")}
              title="Fuzzy Match (split by spaces)"
            >
              <span style={{ fontSize: 11, fontWeight: 600, letterSpacing: -0.5 }}>F</span>
            </ToggleButton>
          </div>
        </div>

        {/* 搜索历史下拉面板 */}
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
                onClick={() => { onQueryChange(item); setShowHistory(false); }}
              >
                <span style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "var(--font-mono)", fontSize: "var(--font-size-sm)" }}>{item}</span>
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

      {/* matchInfo 显示 */}
      {matchInfo && (
        <span style={{
          fontSize: 11, color: "var(--text-secondary)",
          whiteSpace: "nowrap", padding: "0 4px", flexShrink: 0,
        }}>
          {matchInfo}
        </span>
      )}

      {/* 上下导航 + 选项 */}
      <div style={{ display: "flex", gap: 1, alignItems: "center", flexShrink: 0 }}>
        <IconButton onClick={onPrevMatch} title="Previous Match (Shift+Enter)">
          <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor">
            <path d="M8 3.5L3 8.5h3v4h4v-4h3L8 3.5z" />
          </svg>
        </IconButton>
        <IconButton onClick={onNextMatch} title="Next Match (Enter)">
          <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor">
            <path d="M8 12.5L13 7.5h-3v-4H6v4H3L8 12.5z" />
          </svg>
        </IconButton>
        <IconButton onClick={() => {}} title="Search Options" disabled>
          <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor">
            <path d="M1 3h14v1H1zm2 3h10v1H3zm2 3h6v1H5zm2 3h2v1H7z" />
          </svg>
        </IconButton>
      </div>
    </div>
  );
}
