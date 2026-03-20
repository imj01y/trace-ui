import React, { useState, useCallback, useEffect, useMemo, useRef } from "react";
import { listen } from "@tauri-apps/api/event";
import { invoke } from "@tauri-apps/api/core";
import { openDepTreeWindow } from "../utils/openDepTreeWindow";
import { useDragToFloat } from "../hooks/useDragToFloat";
import type { SearchMatch, SliceResult, CryptoScanResult } from "../types/trace";
import MemoryPanel from "./MemoryPanel";
import SearchResultList from "./SearchResultList";
import SearchBar, { SearchOptions } from "./SearchBar";
import StringsPanel from "./StringsPanel";
import CryptoPanel from "./CryptoPanel";

const TABS = ["Memory", "Accesses", "Taint State", "Search", "Strings", "Crypto"] as const;
type TabName = typeof TABS[number];

function DepTreeFromSliceButton({ sessionId }: { sessionId: string | null }) {
  const handleClick = useCallback(() => {
    if (!sessionId) return;
    openDepTreeWindow({ sessionId, fromSlice: true });
  }, [sessionId]);

  return (
    <div style={{ marginTop: 4 }}>
      <button
        onClick={handleClick}
        style={{
          padding: "3px 10px",
          fontSize: 11,
          background: "var(--btn-secondary, #3e4451)",
          color: "var(--text-primary)",
          border: "1px solid var(--border-color)",
          borderRadius: 4,
          cursor: "pointer",
        }}
      >
        View as Dependency Tree
      </button>
    </div>
  );
}

const TAB_TO_PANEL: Record<string, string> = {
  "Memory": "memory",
  "Accesses": "accesses",
  "Taint State": "taint-state",
  "Search": "search",
  "Strings": "strings",
  "Crypto": "crypto",
};

interface Props {
  searchResults: SearchMatch[];
  searchQuery: string;
  isSearching: boolean;
  searchStatus: string;
  searchTotalMatches: number;
  onJumpToSeq: (seq: number) => void;
  onJumpToSearchMatch: (match: SearchMatch) => void;
  isPhase2Ready: boolean;
  floatedPanels: Set<string>;
  onFloat: (panel: string, position?: { x: number; y: number }) => void;
  sessionId: string | null;
  sliceActive: boolean;
  sliceInfo: SliceResult | null;
  sliceFromSpecs: string[];
  isSlicing: boolean;
  sliceDuration: number | null;
  sliceError: string | null;
  stringsScanning?: boolean;
  cryptoResults: CryptoScanResult | null;
  cryptoScanning: boolean;
  onSearch: (query: string, options: SearchOptions) => void;
  showSoName?: boolean;
  showAbsAddress?: boolean;
  addrColorHighlight?: boolean;
}

export default function TabPanel({
  searchResults, searchQuery, isSearching, searchStatus, searchTotalMatches, onJumpToSeq, onJumpToSearchMatch,
  isPhase2Ready,
  floatedPanels, onFloat, sessionId,
  sliceActive, sliceInfo, sliceFromSpecs,
  isSlicing, sliceDuration, sliceError,
  stringsScanning,
  cryptoResults,
  cryptoScanning,
  onSearch,
  showSoName = false,
  showAbsAddress = false,
  addrColorHighlight = false,
}: Props) {
  const [active, setActive] = useState<TabName>("Memory");
  const [memResetKey, setMemResetKey] = useState(0);

  // 过滤已浮动的 tab
  const visibleTabs = useMemo(
    () => TABS.filter(tab => !floatedPanels.has(TAB_TO_PANEL[tab])),
    [floatedPanels],
  );

  // 搜索自动切换（仅在 Search 未浮动时）
  useEffect(() => {
    if (isSearching && !floatedPanels.has("search")) {
      setActive("Search");
    }
  }, [isSearching, floatedPanels]);

  // 污点分析自动切换（仅在 Taint State 未浮动时）
  useEffect(() => {
    if ((isSlicing || sliceActive) && !floatedPanels.has("taint-state")) {
      setActive("Taint State");
    }
  }, [isSlicing, sliceActive, floatedPanels]);

  // Crypto 扫描完成后自动切换
  const prevCryptoScanningRef = useRef(false);
  useEffect(() => {
    if (prevCryptoScanningRef.current && !cryptoScanning && cryptoResults && !floatedPanels.has("crypto")) {
      setActive("Crypto");
    }
    prevCryptoScanningRef.current = cryptoScanning;
  }, [cryptoScanning, cryptoResults, floatedPanels]);

  // View in Memory：自动切换到 Memory tab（仅在 Memory 未浮动时）
  useEffect(() => {
    const unlisten = listen("action:view-in-memory", () => {
      if (!floatedPanels.has("memory")) {
        setActive("Memory");
        setMemResetKey(k => k + 1);
      }
    });
    return () => { unlisten.then(fn => fn()); };
  }, [floatedPanels]);

  // 当前 active tab 被浮动后，自动切到第一个可见 tab
  useEffect(() => {
    if (floatedPanels.has(TAB_TO_PANEL[active]) && visibleTabs.length > 0) {
      setActive(visibleTabs[0]);
    }
  }, [floatedPanels, active, visibleTabs]);

  const searchBadge = searchTotalMatches > 0 ? ` (${searchTotalMatches.toLocaleString()})` : "";

  const searchInputRef = useRef<HTMLInputElement>(null);
  const [localSearchQuery, setLocalSearchQuery] = useState(searchQuery);
  const [selectedSearchIdx, setSelectedSearchIdx] = useState(0);
  const [searchOptions, setSearchOptions] = useState<SearchOptions>({ caseSensitive: false, wholeWord: false, useRegex: false, fuzzyMatch: false });

  // 同步外部 searchQuery 变化
  useEffect(() => { setLocalSearchQuery(searchQuery); }, [searchQuery]);

  // 监听浮窗 ESC 还原时同步的 query 和 toggle 状态
  useEffect(() => {
    const unlistenQuery = listen<{ query: string }>("sync:search-query-back", (e) => {
      setLocalSearchQuery(e.payload.query);
    });
    const unlistenOptions = listen<SearchOptions>("sync:search-options", (e) => {
      setSearchOptions(e.payload);
    });
    return () => {
      unlistenQuery.then(fn => fn());
      unlistenOptions.then(fn => fn());
    };
  }, []);

  // 搜索结果变化时重置选中索引
  useEffect(() => { setSelectedSearchIdx(-1); }, [searchResults]);

  // 监听 action:activate-search-tab 事件
  useEffect(() => {
    const unlisten = listen("action:activate-search-tab", () => {
      if (!floatedPanels.has("search")) {
        setActive("Search");
      }
    });
    return () => { unlisten.then(fn => fn()); };
  }, [floatedPanels]);

  // 监听 search:focus-input 事件（Ctrl+F 时聚焦搜索框）
  useEffect(() => {
    const unlisten = listen("search:focus-input", () => {
      if (!floatedPanels.has("search")) {
        searchInputRef.current?.focus();
        searchInputRef.current?.select();
      }
    });
    return () => { unlisten.then(fn => fn()); };
  }, [floatedPanels]);

  const handlePrevMatch = useCallback(() => {
    if (searchResults.length === 0) return;
    setSelectedSearchIdx(prev =>
      prev <= 0 ? searchResults.length - 1 : prev - 1
    );
  }, [searchResults.length]);

  const handleNextMatch = useCallback(() => {
    if (searchResults.length === 0) return;
    setSelectedSearchIdx(prev =>
      (prev + 1) % searchResults.length
    );
  }, [searchResults.length]);

  const searchMatchInfo = isSearching
    ? "Searching..."
    : searchResults.length === 0
      ? (searchQuery ? "No results" : "")
      : selectedSearchIdx < 0
        ? `${searchTotalMatches.toLocaleString()} results`
        : `${selectedSearchIdx + 1}/${searchTotalMatches.toLocaleString()}`;

  // ── 拖拽浮出逻辑 ──
  const handleFloatPanel = useCallback((panel: string, pos: { x: number; y: number }) => {
    onFloat(panel, pos);
  }, [onFloat]);

  const handleActivateTab = useCallback((panel: string) => {
    // panel key → TabName 反查
    const tab = TABS.find(t => TAB_TO_PANEL[t] === panel);
    if (tab) setActive(tab);
  }, []);

  const startDrag = useDragToFloat({ onFloat: handleFloatPanel, onActivate: handleActivateTab });

  // 容器样式：所有 tab 用 absolute 堆叠，active 可见，其他 visibility:hidden
  // 不用 display:none —— 浏览器会重置 scrollTop，导致虚拟列表焦点丢失
  const tabStyle = (tab: TabName): React.CSSProperties => ({
    position: "absolute", inset: 0,
    display: "flex", flexDirection: "column", overflow: "hidden",
    visibility: active === tab ? "visible" : "hidden",
  });

  // 所有 tab 都浮动时显示空状态
  if (visibleTabs.length === 0) {
    return (
      <div style={{ height: "100%", display: "flex", alignItems: "center", justifyContent: "center", background: "var(--bg-primary)" }}>
        <span style={{ color: "var(--text-secondary)", fontSize: 12 }}>All panels are floating</span>
      </div>
    );
  }

  return (
    <div style={{ height: "100%", display: "flex", flexDirection: "column", background: "var(--bg-primary)", overflow: "hidden" }}>
      <div style={{ display: "flex", alignItems: "center", borderBottom: "1px solid var(--border-color)", flexShrink: 0 }}>
        {visibleTabs.map(tab => (
          <div key={tab} style={{ display: "flex", alignItems: "center" }}>
            <button
              onMouseDown={(e) => startDrag(TAB_TO_PANEL[tab], tab === "Search" ? `Search${searchBadge}` : tab, e)}
              onDoubleClick={() => { if (tab === "Memory") setMemResetKey(k => k + 1); }}
              style={{
                padding: "6px 14px", fontSize: "var(--font-size-sm)",
                background: active === tab ? "var(--bg-secondary)" : "transparent",
                color: active === tab ? "var(--text-primary)" : "var(--text-secondary)",
                cursor: "grab",
                border: "none",
                borderBottom: active === tab ? "2px solid var(--btn-primary)" : "2px solid transparent",
              }}
            >{tab === "Search" ? `Search${searchBadge}` : tab}</button>
          </div>
        ))}
        <div style={{ marginLeft: "auto", paddingRight: 8 }} />
      </div>

      {/* 内容区域：relative 容器，所有 tab 用 absolute 堆叠 */}
      <div style={{ flex: 1, position: "relative", overflow: "hidden" }}>
      <div style={tabStyle("Memory")}>
        <MemoryPanel
          isPhase2Ready={isPhase2Ready}
          onJumpToSeq={onJumpToSeq}
          sessionId={sessionId}
          resetKey={memResetKey}
        />
      </div>

      <div style={tabStyle("Search")}>
        <SearchBar
          query={localSearchQuery}
          onQueryChange={setLocalSearchQuery}
          onSearch={onSearch}
          onPrevMatch={handlePrevMatch}
          onNextMatch={handleNextMatch}
          matchInfo={searchMatchInfo}
          inputRef={searchInputRef}
          initialOptions={searchOptions}
          onOptionsChange={setSearchOptions}
        />
        {isSearching ? (
          <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center" }}>
            <span style={{ color: "var(--text-secondary)", fontSize: 12 }}>Searching...</span>
          </div>
        ) : searchResults.length === 0 ? (
          <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center" }}>
            <span style={{ color: "var(--text-secondary)", fontSize: 12 }}>
              {searchQuery ? `No results found for "${searchQuery}"` : "Enter search query and press Enter"}
            </span>
          </div>
        ) : (
          <>
            <SearchResultList
              results={searchResults}
              selectedSeq={searchResults[selectedSearchIdx]?.seq ?? null}
              onJumpToSeq={onJumpToSeq}
              onJumpToMatch={onJumpToSearchMatch}
              searchQuery={searchQuery}
              caseSensitive={searchOptions.caseSensitive}
              fuzzy={searchOptions.fuzzyMatch}
              useRegex={searchOptions.useRegex}
              showSoName={showSoName}
              showAbsAddress={showAbsAddress}
              addrColorHighlight={addrColorHighlight}
            />
            {searchStatus && (
              <div style={{
                padding: "3px 8px", flexShrink: 0,
                borderTop: "1px solid var(--border-color)",
                background: "var(--bg-secondary)",
                fontSize: 11, color: "var(--text-secondary)",
              }}>
                {searchStatus}
              </div>
            )}
          </>
        )}
      </div>

      <div style={{ ...tabStyle("Taint State"), alignItems: "flex-start", justifyContent: "center", padding: 16 }}>
        {isSlicing ? (
          <div style={{ display: "flex", alignItems: "center", gap: 8, width: "100%", justifyContent: "center" }}>
            <span style={{
              display: "inline-block", width: 14, height: 14,
              border: "2px solid var(--border-color)",
              borderTop: "2px solid var(--btn-primary)",
              borderRadius: "50%",
              animation: "spin 1s linear infinite",
            }} />
            <span style={{ color: "var(--text-secondary)", fontSize: 12 }}>Analyzing...</span>
          </div>
        ) : sliceError ? (
          <div style={{ color: "var(--text-error)", fontSize: 12, lineHeight: 1.6 }}>
            Analysis failed: {sliceError}
          </div>
        ) : sliceActive && sliceInfo ? (
          <div style={{ fontSize: 12, lineHeight: 2, color: "var(--text-secondary)" }}>
            <div>
              <span style={{ color: "var(--text-secondary)", display: "inline-block", width: 52 }}>Source:</span>
              <span style={{ color: "var(--text-primary)" }}>{sliceFromSpecs.join(", ")}</span>
            </div>
            <div>
              <span style={{ color: "var(--text-secondary)", display: "inline-block", width: 52 }}>Result:</span>
              <span style={{ color: "var(--text-primary)" }}>
                {sliceInfo.markedCount.toLocaleString()} / {sliceInfo.totalLines.toLocaleString()} lines ({sliceInfo.percentage.toFixed(1)}%)
              </span>
            </div>
            {sliceDuration != null && (
              <div>
                <span style={{ color: "var(--text-secondary)", display: "inline-block", width: 52 }}>Time:</span>
                <span style={{ color: "var(--text-primary)" }}>{(sliceDuration / 1000).toFixed(2)}s</span>
              </div>
            )}
            <DepTreeFromSliceButton sessionId={sessionId} />
          </div>
        ) : (
          <div style={{ width: "100%", textAlign: "center" }}>
            <span style={{ color: "var(--text-secondary)", fontSize: 12 }}>
              No taint analysis results. Right-click a line to start.
            </span>
          </div>
        )}
      </div>

      <div style={tabStyle("Strings")}>
        <StringsPanel
          sessionId={sessionId}
          isPhase2Ready={isPhase2Ready}
          onJumpToSeq={onJumpToSeq}
          stringsScanning={stringsScanning}
        />
      </div>

      <div style={tabStyle("Crypto")}>
        <CryptoPanel
          cryptoResults={cryptoResults}
          cryptoScanning={cryptoScanning}
          onJumpToSeq={onJumpToSeq}
        />
      </div>

      <div style={tabStyle("Accesses")}>
        <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center" }}>
          <span style={{ color: "var(--text-secondary)", fontSize: 12 }}></span>
        </div>
      </div>
      </div>{/* 关闭 relative 容器 */}
    </div>
  );
}
