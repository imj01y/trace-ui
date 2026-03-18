import { useState, useCallback, useRef, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import type { CreateSessionResult, SessionData, SearchMatch, SearchResult } from "../types/trace";
import { useLineCache } from "./useLineCache";
import { selectedSeqStore } from "../stores/selectedSeqStore";
import { navigationStore } from "../stores/navigationStore";

const SCROLL_POS_KEY = "trace-ui-scroll-positions";
function saveScrollPos(filePath: string, seq: number) {
  try {
    const data = JSON.parse(localStorage.getItem(SCROLL_POS_KEY) || "{}");
    data[filePath] = seq;
    localStorage.setItem(SCROLL_POS_KEY, JSON.stringify(data));
  } catch { /* ignore */ }
}
function loadScrollPos(filePath: string): number | null {
  try {
    const data = JSON.parse(localStorage.getItem(SCROLL_POS_KEY) || "{}");
    return data[filePath] ?? null;
  } catch { return null; }
}

export function useTraceStore(skipStrings: boolean = false) {
  // Multi-session state
  const [sessions, setSessions] = useState<Map<string, SessionData>>(new Map());
  const [activeSessionId, setActiveSessionId] = useState<string | null>(null);

  // Loading state (top-level)
  const [isLoading, setIsLoading] = useState(false);
  const [loadingMessage, setLoadingMessage] = useState("");
  const [fileLoadingProgress, setFileLoadingProgress] = useState(0);
  const isRebuildingRef = useRef(false);
  const [savedScrollSeq, setSavedScrollSeq] = useState<number | null>(null);
  const [indexError, setIndexError] = useState<{ message: string; filePath: string } | null>(null);
  const indexErrorRef = useRef<typeof indexError>(null);
  const [hasStringIndexMap, setHasStringIndexMap] = useState<Map<string, boolean>>(new Map());
  const [memIndexProgressMap, setMemIndexProgressMap] = useState<Map<string, number | null>>(new Map());
  const [stringIndexProgressMap, setStringIndexProgressMap] = useState<Map<string, number | null>>(new Map());
  const skipStringsRef = useRef(skipStrings);
  skipStringsRef.current = skipStrings;

  // Search state (top-level, not per-session)
  const [searchResults, setSearchResults] = useState<SearchMatch[]>([]);
  const [searchQuery, setSearchQuery] = useState("");
  const [isSearching, setIsSearching] = useState(false);
  const [searchStatus, setSearchStatus] = useState("");
  const [searchTotalMatches, setSearchTotalMatches] = useState(0);

  // Line cache (extracted to useLineCache hook, per-session)
  const { getLines, removeSessionCache } = useLineCache(activeSessionId);
  const scrollSaveTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const selectedSeqMapRef = useRef<Map<string, number | null>>(new Map());

  // Store subscriber: persist selectedSeq to ref map + debounced localStorage
  useEffect(() => {
    return selectedSeqStore.subscribe(() => {
      const seq = selectedSeqStore.get();
      const sid = activeSessionIdRef.current;
      if (!sid) return;
      selectedSeqMapRef.current.set(sid, seq);
      if (seq !== null) {
        const s = sessionsRef.current.get(sid);
        if (s?.filePath) {
          if (scrollSaveTimer.current) clearTimeout(scrollSaveTimer.current);
          scrollSaveTimer.current = setTimeout(() => saveScrollPos(s.filePath, seq), 1000);
        }
      }
    });
  }, []);

  const clearSearchState = useCallback(() => {
    setSearchResults([]);
    setSearchQuery("");
    setSearchStatus("");
    setSearchTotalMatches(0);
  }, []);

  // Refs for latest values (avoid stale closures)
  const activeSessionIdRef = useRef(activeSessionId);
  activeSessionIdRef.current = activeSessionId;
  const sessionsRef = useRef(sessions);
  sessionsRef.current = sessions;
  indexErrorRef.current = indexError;

  // Computed properties from active session
  const activeSession = activeSessionId ? sessions.get(activeSessionId) : undefined;
  const totalLines = activeSession?.totalLines ?? 0;
  const isLoaded = activeSession?.isLoaded ?? false;
  const isPhase2Ready = activeSession?.isPhase2Ready ?? false;
  const filePath = activeSession?.filePath ?? null;

  // Helper to update a specific session
  const updateSession = useCallback((sid: string, updates: Partial<SessionData>) => {
    setSessions(prev => {
      const next = new Map(prev);
      const existing = next.get(sid);
      if (existing) {
        next.set(sid, { ...existing, ...updates });
      }
      return next;
    });
  }, []);

  // 阶段1：文件加载进度 0-100%
  useEffect(() => {
    const unlisten = listen<{ progress: number }>(
      "file-loading-progress",
      (event) => {
        const pct = Math.round(event.payload.progress * 100);
        setFileLoadingProgress(pct);
        setLoadingMessage(`Loading file... ${pct}%`);
      }
    );
    return () => { unlisten.then((fn) => fn()); };
  }, []);

  // 阶段2：索引构建进度 0-100%
  useEffect(() => {
    const unlisten = listen<{ sessionId: string; progress: number; done: boolean; error?: string; totalLines?: number; hasStringIndex?: boolean }>(
      "index-progress",
      (event) => {
        const { sessionId, progress, done, error, totalLines } = event.payload;
        const updates: Partial<SessionData> = {
          indexProgress: progress,
          isPhase2Ready: done && !error,
        };
        if (done && totalLines != null) {
          updates.totalLines = totalLines;
        }
        if (done && event.payload.hasStringIndex != null) {
            setHasStringIndexMap(prev => new Map(prev).set(sessionId, event.payload.hasStringIndex!));
        }
        updateSession(sessionId, updates);
        if (sessionId === activeSessionIdRef.current) {
          if (done) {
            setIsLoading(false);
            setLoadingMessage("");
            isRebuildingRef.current = false;
            if (error) {
              const s = sessionsRef.current.get(sessionId);
              setIndexError({ message: error, filePath: s?.filePath ?? "" });
            }
          } else {
            const pct = Math.round(progress * 100);
            if (pct === 0) {
              setLoadingMessage("正在加载文件...");
            } else {
              const label = isRebuildingRef.current ? "Rebuilding index" : "Building index";
              setLoadingMessage(`${label}... ${pct}%`);
            }
          }
        }
      }
    );
    return () => {
      unlisten.then((fn) => fn());
    };
  }, [updateSession]);

  // 内存索引后台构建进度
  useEffect(() => {
    const unlistenProgress = listen<{ sessionId: string; progress: number }>(
      "mem-index-progress",
      (event) => {
        const { sessionId: sid, progress } = event.payload;
        setMemIndexProgressMap(prev => new Map(prev).set(sid, Math.round(progress * 100)));
      }
    );
    const unlistenReady = listen<{ sessionId: string }>(
      "mem-index-ready",
      (event) => {
        setMemIndexProgressMap(prev => new Map(prev).set(event.payload.sessionId, null));
      }
    );
    const unlistenStrProgress = listen<{ sessionId: string; progress: number; done?: boolean }>(
      "string-index-progress",
      (event) => {
        const { sessionId: sid, progress, done } = event.payload;
        if (done) {
          setStringIndexProgressMap(prev => new Map(prev).set(sid, null));
        } else {
          setStringIndexProgressMap(prev => new Map(prev).set(sid, Math.round(progress * 100)));
        }
      }
    );
    return () => {
      unlistenProgress.then((fn) => fn());
      unlistenReady.then((fn) => fn());
      unlistenStrProgress.then((fn) => fn());
    };
  }, []);

  const getSelectedSeqForSession = useCallback((sid: string): number | null => {
    return selectedSeqMapRef.current.get(sid) ?? null;
  }, []);

  const openTrace = useCallback(async (path: string) => {
    // Check if already opened
    for (const [id, s] of sessionsRef.current) {
      if (s.filePath === path) {
        setActiveSessionId(id);
        return;
      }
    }

    setIsLoading(true);
    setFileLoadingProgress(0);
    setLoadingMessage("Loading file... 0%");
    try {
      const result = await invoke<CreateSessionResult>("create_session", { path });
      const fileName = path.split(/[/\\]/).pop() || path;
      const sessionData: SessionData = {
        sessionId: result.sessionId,
        filePath: path,
        fileName,
        totalLines: result.totalLines,
        fileSize: result.fileSize,
        isLoaded: true,
        isPhase2Ready: false,
        indexProgress: 0,
      };

      setSessions(prev => new Map(prev).set(result.sessionId, sessionData));
      setActiveSessionId(result.sessionId);
      activeSessionIdRef.current = result.sessionId; // 立即同步 ref，防止 done 事件在渲染前到达

      // Restore scroll position
      const lastSeq = loadScrollPos(path);
      if (lastSeq !== null && lastSeq < result.totalLines) {
        selectedSeqMapRef.current.set(result.sessionId, lastSeq);
        selectedSeqStore.set(lastSeq);
        setSavedScrollSeq(lastSeq);
      } else {
        setSavedScrollSeq(null);
      }

      // Clear search
      clearSearchState();

      // 文件加载完成，前端主动启动索引构建
      setLoadingMessage("Loading file... 100%");
      const sid = result.sessionId;
      invoke("build_index", { sessionId: sid, skipStrings: skipStringsRef.current || undefined }).catch(async (e) => {
        // 索引构建失败：关闭 session，标记错误
        setIsLoading(false);
        setLoadingMessage("");
        try { await invoke("close_session", { sessionId: sid }); } catch { /* ignore */ }
        setSessions(prev => { const next = new Map(prev); next.delete(sid); return next; });
        if (activeSessionIdRef.current === sid) {
          setActiveSessionId(null);
          activeSessionIdRef.current = null;
        }
        if (!indexErrorRef.current) {
          setIndexError({ message: String(e), filePath: path });
        }
      });
    } catch (e) {
      setIsLoading(false);
      setLoadingMessage("");
      throw e;
    }
  }, []);

  // 共用逻辑：关闭 session → 从 Map 删除 → 选择相邻 tab → 清理缓存
  const removeSessionAndSelectNext = useCallback(async (sessionId: string) => {
    await invoke("close_session", { sessionId });
    setSessions(prev => {
      const keys = Array.from(prev.keys());
      const idx = keys.indexOf(sessionId);
      const next = new Map(prev);
      next.delete(sessionId);
      if (activeSessionIdRef.current === sessionId) {
        // 优先切到右边相邻 tab，没有则左边，没有则 null
        const remaining = Array.from(next.keys());
        if (remaining.length === 0) {
          setActiveSessionId(null);
        } else if (idx < remaining.length) {
          setActiveSessionId(remaining[idx]);
        } else {
          setActiveSessionId(remaining[remaining.length - 1]);
        }
      }
      return next;
    });
    selectedSeqMapRef.current.delete(sessionId);
    removeSessionCache(sessionId);
  }, [removeSessionCache]);

  const closeSession = useCallback(async (sessionId: string) => {
    await removeSessionAndSelectNext(sessionId);
  }, [removeSessionAndSelectNext]);

  const closeTrace = useCallback(async () => {
    const sid = activeSessionIdRef.current;
    if (!sid) return;
    await removeSessionAndSelectNext(sid);
    clearSearchState();
    setSavedScrollSeq(null);
    setIsLoading(false);
    setLoadingMessage("");
  }, [removeSessionAndSelectNext, clearSearchState]);

  const cancelLoading = useCallback(async () => {
    const sid = activeSessionIdRef.current;
    if (!sid) return;
    // 关闭正在加载的 session，后端 build_index 线程写入结果时会发现 session 已删除
    await removeSessionAndSelectNext(sid);
    clearSearchState();
    setSavedScrollSeq(null);
    setIsLoading(false);
    setLoadingMessage("");
    isRebuildingRef.current = false;
  }, [removeSessionAndSelectNext, clearSearchState]);

  const switchSession = useCallback((id: string) => {
    setActiveSessionId(id);
    clearSearchState();
    navigationStore.reset();
    const seq = selectedSeqMapRef.current.get(id) ?? null;
    selectedSeqStore.set(seq);
    setSavedScrollSeq(seq);
  }, [clearSearchState]);

  const rebuildIndex = useCallback(async () => {
    const sid = activeSessionIdRef.current;
    if (!sid) return;
    updateSession(sid, { isPhase2Ready: false, indexProgress: 0 });
    isRebuildingRef.current = true;
    setIsLoading(true);
    setLoadingMessage("Rebuilding index... 0%");
    invoke("build_index", { sessionId: sid, force: true, skipStrings: skipStringsRef.current || undefined }).catch((e) => {
      console.error(e);
      setIsLoading(false);
      setLoadingMessage("");
    });
  }, [updateSession]);

  const searchTrace = useCallback(async (query: string) => {
    const sid = activeSessionIdRef.current;
    if (!sid || !query.trim()) {
      setSearchResults([]);
      setSearchQuery("");
      setSearchStatus("");
      return;
    }
    setIsSearching(true);
    setSearchQuery(query);
    setSearchStatus("Searching...");
    try {
      const result = await invoke<SearchResult>("search_trace", {
        sessionId: sid,
        request: { query, max_results: 10000 },
      });
      setSearchResults(result.matches);
      setSearchTotalMatches(result.total_matches);
      setSearchStatus(`${result.total_matches.toLocaleString()} results`);
    } catch (e) {
      setSearchStatus(`Search failed: ${e}`);
      setSearchResults([]);
    } finally {
      setIsSearching(false);
    }
  }, []);

  // 从浮动窗口同步搜索结果回来
  const syncSearchState = useCallback((results: SearchMatch[], query: string, status: string, totalMatches: number) => {
    setSearchResults(results);
    setSearchQuery(query);
    setSearchStatus(status);
    setSearchTotalMatches(totalMatches);
    setIsSearching(false);
  }, []);

  return {
    // Multi-session management
    sessions,
    activeSessionId,
    setActiveSessionId: switchSession,
    closeSession,

    // Backward-compatible (derived from activeSession)
    totalLines,
    fileSize: activeSession?.fileSize ?? 0,
    isLoaded,
    isPhase2Ready,
    getSelectedSeqForSession,
    indexProgress: activeSession?.indexProgress ?? 0,
    isLoading,
    loadingMessage,
    fileLoadingProgress,
    savedScrollSeq,
    openTrace,
    closeTrace,
    getLines,
    searchResults,
    searchQuery,
    isSearching,
    searchStatus,
    searchTotalMatches,
    filePath,
    searchTrace,
    rebuildIndex,
    syncSearchState,
    cancelLoading,
    indexError,
    clearIndexError: () => setIndexError(null),
    hasStringIndexMap,
    setHasStringIndexMap,
    memIndexProgress: activeSessionId ? (memIndexProgressMap.get(activeSessionId) ?? null) : null,
    stringIndexProgress: activeSessionId ? (stringIndexProgressMap.get(activeSessionId) ?? null) : null,
  };
}
