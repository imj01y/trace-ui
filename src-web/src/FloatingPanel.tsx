import { useState, useEffect, useCallback, useRef } from "react";
import { emit, emitTo, listen } from "@tauri-apps/api/event";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { invoke } from "@tauri-apps/api/core";
import MemoryPanel from "./components/MemoryPanel";
import FloatingWindowFrame from "./components/FloatingWindowFrame";
import SearchResultList from "./components/SearchResultList";
import StringsPanel from "./components/StringsPanel";
import StringDetailPanel from "./components/StringDetailPanel";
import StringXRefsPanel from "./components/StringXRefsPanel";
import type { SearchMatch, SearchResult } from "./types/trace";
import SearchBar, { SearchOptions } from "./components/SearchBar";

const PANEL_TITLES: Record<string, string> = {
  memory: "Memory",
  accesses: "Accesses",
  "taint-state": "Taint State",
  search: "Search",
  strings: "Strings",
  "string-detail": "String Detail",
  "string-xrefs": "XRefs",
  "call-info": "Call Info",
};

interface SyncState {
  sessionId: string | null;
  selectedSeq: number | null;
  isPhase2Ready: boolean;
  isLoaded: boolean;
  totalLines: number;
  filePath: string | null;
}

export default function FloatingPanel({ panel }: { panel: string }) {
  const title = PANEL_TITLES[panel] ?? panel;

  const [syncState, setSyncState] = useState<SyncState>({
    sessionId: null,
    selectedSeq: null,
    isPhase2Ready: false,
    isLoaded: false,
    totalLines: 0,
    filePath: null,
  });

  // Search 面板状态
  const [searchResults, setSearchResults] = useState<SearchMatch[]>([]);
  const [searchQuery, setSearchQuery] = useState("");
  const [isSearching, setIsSearching] = useState(false);
  const [searchStatus, setSearchStatus] = useState("");
  const [searchTotalMatches, setSearchTotalMatches] = useState(0);

  // 初始化：发送 panel:ready
  useEffect(() => {
    emitTo("main", "panel:ready", { panel });
  }, [panel]);

  // 监听主窗口同步事件
  useEffect(() => {
    const unlisteners: Promise<() => void>[] = [];

    unlisteners.push(listen<SyncState>("sync:init-state", (e) => {
      setSyncState(e.payload);
    }));

    unlisteners.push(listen<{ seq: number | null }>("sync:selected-seq", (e) => {
      setSyncState(prev => ({ ...prev, selectedSeq: e.payload.seq }));
    }));

    unlisteners.push(listen<{ ready: boolean }>("sync:phase2-ready", (e) => {
      setSyncState(prev => ({ ...prev, isPhase2Ready: e.payload.ready }));
    }));

    unlisteners.push(listen<{ isLoaded: boolean; totalLines: number; filePath: string | null }>("sync:file-state", (e) => {
      setSyncState(prev => ({
        ...prev,
        isLoaded: e.payload.isLoaded,
        totalLines: e.payload.totalLines,
        filePath: e.payload.filePath,
      }));
    }));

    unlisteners.push(listen<{ sessionId: string | null }>("sync:session-id", (e) => {
      setSyncState(prev => ({ ...prev, sessionId: e.payload.sessionId }));
    }));

    return () => { unlisteners.forEach(p => p.then(fn => fn())); };
  }, []);

  // Search 面板：监听主窗口搜索转发
  const handleSearch = useCallback(async (query: string, options?: SearchOptions) => {
    if (!syncState.sessionId) return;
    setSearchQuery(query);
    setIsSearching(true);
    setSearchResults([]);
    setSearchTotalMatches(0);
    setSearchStatus("Searching...");
    try {
      let finalQuery = query;
      let finalUseRegex = options?.useRegex ?? false;
      if (options?.wholeWord && query.trim()) {
        const escaped = finalUseRegex ? query : query.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        finalQuery = `\\b${escaped}\\b`;
        finalUseRegex = true;
      }
      const result = await invoke<SearchResult>("search_trace", {
        sessionId: syncState.sessionId,
        request: {
          query: finalQuery,
          max_results: 10000,
          case_sensitive: options?.caseSensitive ?? false,
          use_regex: finalUseRegex,
          fuzzy: options?.fuzzyMatch ?? false,
        },
      });
      setSearchResults(result.matches);
      setSearchTotalMatches(result.total_matches);
      setSearchStatus(result.total_matches === 0
        ? `No results found for "${query}"`
        : `${result.total_matches.toLocaleString()} results`);
      emit("sync:search-results-back", {
        results: result.matches,
        query,
        status: result.total_matches === 0
          ? `No results found for "${query}"`
          : `${result.total_matches.toLocaleString()} results`,
        totalMatches: result.total_matches,
      });
    } catch (e) {
      setSearchStatus(`Search failed: ${e}`);
      setSearchResults([]);
    } finally {
      setIsSearching(false);
    }
  }, [syncState.sessionId]);

  useEffect(() => {
    if (panel !== "search") return;
    const unlisten = listen<{ query: string; options?: SearchOptions }>("action:trigger-search", (e) => {
      handleSearch(e.payload.query, e.payload.options);
    });
    return () => { unlisten.then(fn => fn()); };
  }, [panel, handleSearch]);

  // Search 面板：接收主窗口同步的已有搜索结果
  useEffect(() => {
    if (panel !== "search") return;
    const unlisten = listen<{ results: SearchMatch[]; query: string; status: string; totalMatches: number }>("sync:search-state", (e) => {
      setSearchResults(e.payload.results);
      setSearchQuery(e.payload.query);
      setSearchStatus(e.payload.status);
      setSearchTotalMatches(e.payload.totalMatches);
      setIsSearching(false);
    });
    return () => { unlisten.then(fn => fn()); };
  }, [panel]);

  const handleJumpToSeq = useCallback((seq: number) => {
    emit("action:jump-to-seq", { seq });
  }, []);

  const handleJumpToSearchMatch = useCallback((match: SearchMatch) => {
    if (match.call_info) {
      emit("action:jump-to-search-match", { seq: match.seq });
      return;
    }
    handleJumpToSeq(match.seq);
  }, [handleJumpToSeq]);

  const renderPanelContent = () => {
    switch (panel) {
      case "memory":
        return (
          <MemoryPanel
            selectedSeq={syncState.selectedSeq}
            isPhase2Ready={syncState.isPhase2Ready}
            onJumpToSeq={handleJumpToSeq}
            sessionId={syncState.sessionId}
          />
        );
      case "search":
        return (
          <FloatingSearchContent
            searchResults={searchResults}
            searchQuery={searchQuery}
            isSearching={isSearching}
            searchStatus={searchStatus}
            searchTotalMatches={searchTotalMatches}
            onJumpToSeq={handleJumpToSeq}
            onJumpToMatch={handleJumpToSearchMatch}
            onSearch={handleSearch}
          />
        );
      case "strings":
        return (
          <StringsPanel
            sessionId={syncState.sessionId}
            isPhase2Ready={syncState.isPhase2Ready}
            onJumpToSeq={handleJumpToSeq}
          />
        );
      case "string-detail":
        return <StringDetailPanel />;
      case "string-xrefs":
        return <StringXRefsPanel />;
      case "call-info":
        return <CallInfoContent />;
      default:
        return (
          <div style={{
            height: "100%",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
          }}>
            <span style={{ color: "var(--text-secondary)", fontSize: 12 }}>
              {title} — Panel not yet implemented
            </span>
          </div>
        );
    }
  };

  return (
    <FloatingWindowFrame title={title}>
      {/* 面板内容 */}
      <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
        {renderPanelContent()}
      </div>
    </FloatingWindowFrame>
  );
}

function FloatingSearchContent({
  searchResults, searchQuery, isSearching, searchStatus, searchTotalMatches,
  onJumpToSeq, onJumpToMatch, onSearch,
}: {
  searchResults: SearchMatch[];
  searchQuery: string;
  isSearching: boolean;
  searchStatus: string;
  searchTotalMatches: number;
  onJumpToSeq: (seq: number) => void;
  onJumpToMatch: (match: SearchMatch) => void;
  onSearch: (query: string, options: SearchOptions) => void;
}) {
  const [localQuery, setLocalQuery] = useState(searchQuery);
  const [selectedIdx, setSelectedIdx] = useState(-1);
  const inputRef = useRef<HTMLInputElement>(null);
  const currentOptionsRef = useRef<SearchOptions>({ caseSensitive: false, wholeWord: false, useRegex: false, fuzzyMatch: false });
  const [caseSensitiveState, setCaseSensitiveState] = useState(false);
  const [fuzzyState, setFuzzyState] = useState(false);
  const [useRegexState, setUseRegexState] = useState(false);

  const handleOptionsChange = useCallback((opts: SearchOptions) => {
    currentOptionsRef.current = opts;
    setCaseSensitiveState(opts.caseSensitive);
    setFuzzyState(opts.fuzzyMatch);
    setUseRegexState(opts.useRegex);
  }, []);

  useEffect(() => {
    setTimeout(() => inputRef.current?.focus(), 100);
  }, []);

  useEffect(() => {
    const unlisten = listen("search:focus-input", () => {
      inputRef.current?.focus();
      inputRef.current?.select();
    });
    return () => { unlisten.then(fn => fn()); };
  }, []);

  // ESC 关闭浮窗并同步状态回主窗口
  useEffect(() => {
    const handler = async (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        await emit("action:activate-search-tab");
        await emit("sync:search-query-back", { query: localQuery });
        await emit("sync:search-options", currentOptionsRef.current);
        getCurrentWindow().close();
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [localQuery]);

  useEffect(() => { setLocalQuery(searchQuery); }, [searchQuery]);
  useEffect(() => { setSelectedIdx(-1); }, [searchResults]);

  const handlePrevMatch = useCallback(() => {
    if (searchResults.length === 0) return;
    setSelectedIdx(prev => prev <= 0 ? searchResults.length - 1 : prev - 1);
  }, [searchResults.length]);

  const handleNextMatch = useCallback(() => {
    if (searchResults.length === 0) return;
    setSelectedIdx(prev => (prev + 1) % searchResults.length);
  }, [searchResults.length]);

  const matchInfo = isSearching
    ? "Searching..."
    : searchResults.length === 0
      ? (searchQuery ? "No results" : "")
      : selectedIdx < 0
        ? `${searchTotalMatches.toLocaleString()} results`
        : `${selectedIdx + 1}/${searchTotalMatches.toLocaleString()}`;

  return (
    <div style={{ height: "100%", display: "flex", flexDirection: "column" }}>
      <SearchBar
        query={localQuery}
        onQueryChange={setLocalQuery}
        onSearch={onSearch}
        onPrevMatch={handlePrevMatch}
        onNextMatch={handleNextMatch}
        matchInfo={matchInfo}
        inputRef={inputRef}
        onOptionsChange={handleOptionsChange}
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
        <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
          <SearchResultList
            results={searchResults}
            selectedSeq={searchResults[selectedIdx]?.seq ?? null}
            onJumpToSeq={onJumpToSeq}
            onJumpToMatch={onJumpToMatch}
            searchQuery={searchQuery}
            caseSensitive={caseSensitiveState}
            fuzzy={fuzzyState}
            useRegex={useRegexState}
          />
        </div>
      )}
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
    </div>
  );
}

function CallInfoContent() {
  const [info, setInfo] = useState<{ text: string; isJni: boolean } | null>(null);

  // 事件方案：先注册数据监听，再发送 ready 信号
  useEffect(() => {
    const unlisten = listen<{ text: string; isJni: boolean }>("call-info:init-data", (e) => {
      setInfo(e.payload);
    });
    const winLabel = getCurrentWindow().label;
    emit(`call-info:ready:${winLabel}`);
    return () => { unlisten.then(fn => fn()); };
  }, []);

  // Esc 关闭窗口
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        getCurrentWindow().close();
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, []);

  if (!info) {
    return (
      <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center" }}>
        <span style={{ color: "var(--text-secondary)", fontSize: 12 }}>No data</span>
      </div>
    );
  }

  return (
    <div style={{
      flex: 1,
      overflow: "auto",
      padding: "8px 12px",
      fontSize: 12,
      fontFamily: '"JetBrains Mono", "Fira Code", monospace',
      color: "var(--text-primary, #abb2bf)",
      whiteSpace: "pre",
      borderTop: `2px solid ${info.isJni ? "#c792ea" : "#56d4dd"}`,
    }}>
      {info.text}
    </div>
  );
}
