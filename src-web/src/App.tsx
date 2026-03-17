import { useState, useCallback, useEffect, useRef } from "react";
import { Panel, Group, Separator } from "react-resizable-panels";
import type { PanelImperativeHandle } from "react-resizable-panels";
import { invoke } from "@tauri-apps/api/core";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { emit, emitTo, listen } from "@tauri-apps/api/event";
import { WebviewWindow } from "@tauri-apps/api/webviewWindow";
import TitleBar from "./components/TitleBar";
import FunctionTree from "./components/FunctionTree";
import TraceTable from "./components/TraceTable";
import RegisterPanel from "./components/RegisterPanel";
import TabPanel from "./components/TabPanel";
import FileTabBar from "./components/FileTabBar";
import GotoOverlay from "./components/GotoOverlay";
import TaintConfigDialog from "./components/TaintConfigDialog";
import { useTraceStore } from "./hooks/useTraceStore";
import { useSliceState } from "./hooks/useSliceState";
import { useRecentFiles } from "./hooks/useRecentFiles";
import { selectedSeqStore, useSelectedSeq } from "./stores/selectedSeqStore";
import { navigationStore } from "./stores/navigationStore";
import { isModKey } from "./utils/platform";
import { useFoldState } from "./hooks/useFoldState";
import { useFuncRenameStore } from "./hooks/useFuncRenameStore";
import { usePreferences, saveSessionSnapshot, loadSessionSnapshot } from "./hooks/usePreferences";
import { useHighlights } from "./hooks/useHighlights";
import type { SessionSnapshot } from "./hooks/usePreferences";
import type { CallTreeNodeDto, SearchMatch } from "./types/trace";

const PANEL_SIZES: Record<string, { width: number; height: number }> = {
  memory: { width: 1100, height: 390 },
  accesses: { width: 600, height: 400 },
  "taint-state": { width: 600, height: 400 },
  search: { width: 800, height: 500 },
  strings: { width: 900, height: 450 },
};

function clampToScreen(w: number, h: number): { width: number; height: number } {
  const sw = window.screen.availWidth;
  const sh = window.screen.availHeight;
  return {
    width: Math.min(w, Math.round(sw * 0.85)),
    height: Math.min(h, Math.round(sh * 0.85)),
  };
}

const PANEL_WINDOW_TITLES: Record<string, string> = {
  memory: "Memory - Trace UI",
  accesses: "Accesses - Trace UI",
  "taint-state": "Taint State - Trace UI",
  search: "Search - Trace UI",
  strings: "Strings - Trace UI",
};

function App() {
  const { preferences, updatePreferences } = usePreferences();

  const {
    totalLines,
    isLoaded,
    isPhase2Ready,
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
    sessions,
    activeSessionId,
    closeSession,
    setActiveSessionId,
    syncSearchState,
    cancelLoading,
    indexError,
    clearIndexError,
    getSelectedSeqForSession,
    hasStringIndexMap,
    setHasStringIndexMap,
  } = useTraceStore(!preferences.scanStringsOnBuild);

  const slice = useSliceState(activeSessionId);
  const [taintDialogSeq, setTaintDialogSeq] = useState<number | null>(null);
  const [taintDialogReg, setTaintDialogReg] = useState<string | undefined>(undefined);
  const [selectedRegInfo, setSelectedRegInfo] = useState<{ seq: number; regName: string } | null>(null);

  const [showGoto, setShowGoto] = useState(false);

  const { recentFiles, addRecent, removeRecent, clearRecent } = useRecentFiles();
  const { highlights, loadForFile, setHighlight, toggleStrikethrough, resetHighlight, toggleHidden, unhideGroup, setComment, deleteComment } = useHighlights();

  // 文件切换时加载高亮
  useEffect(() => { loadForFile(filePath); }, [filePath, loadForFile]);

  // 控制 TraceTable 滚动对齐方式：back/forward 用 "auto"，其他用 "center"
  const scrollAlignRef = useRef<"center" | "auto" | "end">("center");
  // 强制触发 TraceTable 滚动（即使 selectedSeq 未变化）
  const [scrollTrigger, setScrollTrigger] = useState(0);
  const handleGoBack = useCallback(() => { scrollAlignRef.current = "auto"; navigationStore.goBack(); }, []);
  const handleGoForward = useCallback(() => { scrollAlignRef.current = "auto"; navigationStore.goForward(); }, []);

  const [callTreeNodeMap, setCallTreeNodeMap] = useState<Map<number, CallTreeNodeDto>>(new Map());
  const [callTreeCount, setCallTreeCount] = useState(0);
  const [callTreeLoading, setCallTreeLoading] = useState(false);
  const [callTreeError, setCallTreeError] = useState<string | null>(null);
  const [callTreeLazyMode, setCallTreeLazyMode] = useState(false);
  const [callTreeLoadedNodes, setCallTreeLoadedNodes] = useState<Set<number>>(new Set());

  // 懒加载阈值：超过此节点数时不一次性加载全部 call tree
  const LAZY_CALL_TREE_THRESHOLD = 100_000;

  // per-session CallTree 缓存
  const callTreeCache = useRef<Map<string, {
    nodeMap: Map<number, CallTreeNodeDto>;
    count: number;
    lazyMode: boolean;
    loadedNodes: Set<number>;
  }>>(new Map());

  // 渲染期间同步恢复 callTree（避免 useEffect 延迟一帧导致折叠区间错误）
  const prevCallTreeSessionRef = useRef<string | null>(null);
  if (activeSessionId !== prevCallTreeSessionRef.current) {
    prevCallTreeSessionRef.current = activeSessionId;
    if (!activeSessionId || !isPhase2Ready) {
      setCallTreeNodeMap(new Map());
      setCallTreeCount(0);
      setCallTreeError(null);
      setCallTreeLazyMode(false);
      setCallTreeLoadedNodes(new Set());
    } else {
      const cached = callTreeCache.current.get(activeSessionId);
      if (cached) {
        setCallTreeNodeMap(cached.nodeMap);
        setCallTreeCount(cached.count);
        setCallTreeLazyMode(cached.lazyMode);
        setCallTreeLoadedNodes(cached.loadedNodes);
      }
    }
  }

  // ── 面板自适应尺寸 ──
  // Memory 底部面板高度：TabPanel tab(28) + toolbar(28) + hex header(20) + 16×20(320) + padding(8) = 404px
  // Register 面板高度：padding(16) + header(19) + 15×17(255) + gap(4) + 2×17(34) = 328px
  // 左侧面板宽度：两列寄存器 name(36) + value(~130) × 2 + gap(16) + padding(16) = 364px + 余量
  const MEMORY_PANEL_TARGET_PX = 404;
  const REG_PANEL_TARGET_PX = 328;
  const LEFT_PANEL_TARGET_PX = 376;

  const bottomPanelRef = useRef<PanelImperativeHandle>(null);
  const rightGroupRef = useRef<HTMLDivElement>(null);
  const regPanelRef = useRef<PanelImperativeHandle>(null);
  const leftGroupRef = useRef<HTMLDivElement>(null);
  const leftPanelRef = useRef<PanelImperativeHandle>(null);
  const hGroupRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const resizePanels = () => {
      // Memory 底部面板高度
      const rEl = rightGroupRef.current;
      const bPanel = bottomPanelRef.current;
      if (rEl && bPanel) {
        const h = rEl.offsetHeight;
        if (h > 0) {
          const pct = Math.min(65, Math.max(20, (MEMORY_PANEL_TARGET_PX / h) * 100));
          bPanel.resize(`${pct}%`);
        }
      }

      // Register 面板高度
      const lEl = leftGroupRef.current;
      const rPanel = regPanelRef.current;
      if (lEl && rPanel) {
        const h = lEl.offsetHeight;
        if (h > 0) {
          const pct = Math.min(65, Math.max(20, (REG_PANEL_TARGET_PX / h) * 100));
          rPanel.resize(`${pct}%`);
        }
      }

      // 左侧面板宽度
      const hEl = hGroupRef.current;
      const lPanel = leftPanelRef.current;
      if (hEl && lPanel) {
        const w = hEl.offsetWidth;
        if (w > 0) {
          const pct = Math.min(30, Math.max(12, (LEFT_PANEL_TARGET_PX / w) * 100));
          lPanel.resize(`${pct}%`);
        }
      }
    };

    requestAnimationFrame(resizePanels);

    // 仅在窗口大小变化时重算面板尺寸，避免拖拽分割线时产生反馈循环
    const onWindowResize = () => requestAnimationFrame(resizePanels);
    window.addEventListener("resize", onWindowResize);

    return () => window.removeEventListener("resize", onWindowResize);
  }, []);

  // ── 分割线拖拽即时响应：在 React 渲染管线之前直接操作 DOM ──
  // react-resizable-panels 通过 useSyncExternalStore 更新 flexGrow，
  // React 19 可能将 DOM commit 延迟到下一帧，导致分割线落后鼠标一帧。
  // 此 hook 在 capturing 阶段先于库的 handler 直接设置 flexGrow，
  // 提供零延迟视觉反馈。库后续通过 React 覆写相同值，无副作用。
  useEffect(() => {
    let dragging = false;
    let startPos = 0;
    let leftPanel: HTMLElement | null = null;
    let rightPanel: HTMLElement | null = null;
    let startLeftGrow = 0;
    let startRightGrow = 0;
    let groupSize = 0;
    let isHorizontal = true;

    const onDown = (e: PointerEvent) => {
      const sep = (e.target as HTMLElement).closest("[data-separator]");
      if (!sep) return;
      let prev = sep.previousElementSibling as HTMLElement | null;
      while (prev && !prev.hasAttribute("data-panel")) prev = prev.previousElementSibling as HTMLElement | null;
      let next = sep.nextElementSibling as HTMLElement | null;
      while (next && !next.hasAttribute("data-panel")) next = next.nextElementSibling as HTMLElement | null;
      if (!prev || !next) return;
      leftPanel = prev;
      rightPanel = next;
      startLeftGrow = parseFloat(leftPanel.style.flexGrow) || 1;
      startRightGrow = parseFloat(rightPanel.style.flexGrow) || 1;
      const group = sep.parentElement;
      if (!group) return;
      isHorizontal = getComputedStyle(group).flexDirection === "row";
      groupSize = isHorizontal ? group.offsetWidth : group.offsetHeight;
      startPos = isHorizontal ? e.clientX : e.clientY;
      dragging = true;
      document.documentElement.dataset.separatorDrag = "1";
    };

    const onMove = (e: PointerEvent) => {
      if (!dragging || !leftPanel || !rightPanel || groupSize <= 0) return;
      const pos = isHorizontal ? e.clientX : e.clientY;
      const totalGrow = startLeftGrow + startRightGrow;
      const deltaGrow = ((pos - startPos) / groupSize) * totalGrow;
      leftPanel.style.flexGrow = String(Math.max(0.01, startLeftGrow + deltaGrow));
      rightPanel.style.flexGrow = String(Math.max(0.01, startRightGrow - deltaGrow));
    };

    const onUp = () => {
      dragging = false;
      leftPanel = null;
      rightPanel = null;
      delete document.documentElement.dataset.separatorDrag;
    };

    // capturing 阶段：在库的 handler 之前执行，提供即时视觉反馈
    document.addEventListener("pointerdown", onDown, true);
    document.addEventListener("pointermove", onMove, true);
    document.addEventListener("pointerup", onUp, true);
    return () => {
      document.removeEventListener("pointerdown", onDown, true);
      document.removeEventListener("pointermove", onMove, true);
      document.removeEventListener("pointerup", onUp, true);
    };
  }, []);

  // 浮动面板状态
  const [floatedPanels, setFloatedPanels] = useState<Set<string>>(new Set());

  // 浮出的 session 集合（从 FileTabBar 隐藏）
  const [floatedSessions, setFloatedSessions] = useState<Set<string>>(new Set());
  const floatingSessionRefs = useRef<Map<string, WebviewWindow>>(new Map());

  // 仅处理缓存未命中时的异步加载（缓存命中已在上方渲染期间同步恢复）
  useEffect(() => {
    if (!activeSessionId || !isPhase2Ready) return;
    if (callTreeCache.current.has(activeSessionId)) return;
    setCallTreeLoading(true);
    setCallTreeError(null);
    const sid = activeSessionId;

    // 先获取节点总数，决定全量加载还是懒加载
    invoke<number>("get_call_tree_node_count", { sessionId: sid })
      .then((count) => {
        if (count <= LAZY_CALL_TREE_THRESHOLD) {
          // 小文件：全量加载（保持原有行为）
          return invoke<CallTreeNodeDto[]>("get_call_tree", { sessionId: sid })
            .then((nodes) => {
              const map = new Map<number, CallTreeNodeDto>();
              for (const n of nodes) map.set(n.id, n);
              setCallTreeNodeMap(map);
              setCallTreeCount(count);
              setCallTreeLazyMode(false);
              setCallTreeLoadedNodes(new Set());
              callTreeCache.current.set(sid, {
                nodeMap: map, count, lazyMode: false, loadedNodes: new Set(),
              });
            });
        } else {
          // 大文件：懒加载模式，只加载根节点 + 第一层子节点
          return invoke<CallTreeNodeDto[]>("get_call_tree_children", {
            sessionId: sid, nodeId: 0, includeSelf: true,
          }).then((nodes) => {
            const map = new Map<number, CallTreeNodeDto>();
            for (const n of nodes) map.set(n.id, n);
            const loaded = new Set([0]); // 根节点的子节点已加载
            setCallTreeNodeMap(map);
            setCallTreeCount(count);
            setCallTreeLazyMode(true);
            setCallTreeLoadedNodes(loaded);
            callTreeCache.current.set(sid, {
              nodeMap: map, count, lazyMode: true, loadedNodes: loaded,
            });
          });
        }
      })
      .catch((e) => setCallTreeError(String(e)))
      .finally(() => setCallTreeLoading(false));
  }, [isPhase2Ready, activeSessionId]);

  // 懒加载子节点回调（FunctionTree 展开节点时调用）
  const loadCallTreeChildren = useCallback(async (nodeId: number) => {
    if (!activeSessionId) return;
    const children = await invoke<CallTreeNodeDto[]>("get_call_tree_children", {
      sessionId: activeSessionId, nodeId, includeSelf: false,
    });
    setCallTreeNodeMap(prev => {
      const next = new Map(prev);
      for (const n of children) next.set(n.id, n);
      return next;
    });
    setCallTreeLoadedNodes(prev => {
      const next = new Set(prev);
      next.add(nodeId);
      return next;
    });
    // 更新缓存
    const cached = callTreeCache.current.get(activeSessionId);
    if (cached) {
      for (const n of children) cached.nodeMap.set(n.id, n);
      cached.loadedNodes.add(nodeId);
    }
  }, [activeSessionId]);

  const funcRename = useFuncRenameStore(filePath ?? null);

  const foldState = useFoldState(callTreeNodeMap, totalLines);

  const handleOpenFile = useCallback(
    async (path: string) => {
      try {
        await openTrace(path);
        addRecent(path);
      } catch (e) {
        console.error("Failed to open trace:", e);
        alert(`打开文件失败: ${e}`);
      }
    },
    [openTrace, addRecent]
  );

  // 启动时应用保存的缓存目录配置
  useEffect(() => {
    const dir = preferences.cacheDir?.trim() || null;
    if (dir) {
      invoke("set_cache_dir", { path: dir }).catch(console.error);
    }
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // 启动时恢复上次的会话
  const hasAutoOpened = useRef(false);
  // 待恢复的 taintConfig：filePath → TaintConfig
  const pendingTaintConfigs = useRef<Map<string, import("./hooks/usePreferences").TaintConfig>>(new Map());
  useEffect(() => {
    if (hasAutoOpened.current) return;
    if (!preferences.reopenLastFile) return;
    const snapshot = loadSessionSnapshot();
    if (!snapshot || snapshot.files.length === 0) return;
    hasAutoOpened.current = true;
    (async () => {
      for (const file of snapshot.files) {
        try {
          await openTrace(file.filePath);
          addRecent(file.filePath);
          if (file.taintConfig) {
            pendingTaintConfigs.current.set(file.filePath, file.taintConfig);
          }
        } catch (e) {
          console.error("Failed to restore file:", file.filePath, e);
        }
      }
      // 恢复 activeSessionId — 切换到上次激活的文件
      if (snapshot.activeFilePath) {
        for (const [id, s] of sessions) {
          if (s.filePath === snapshot.activeFilePath) {
            setActiveSessionId(id);
            break;
          }
        }
      }
    })();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // 用 ref 持有 slice 函数，避免 effect 依赖不稳定的 slice 对象
  const sliceRef = useRef(slice);
  sliceRef.current = slice;

  // isPhase2Ready 变为 true 时，检查是否有待恢复的 taintConfig
  useEffect(() => {
    if (!activeSessionId || !isPhase2Ready || !filePath) return;
    const config = pendingTaintConfigs.current.get(filePath);
    if (!config) return;
    pendingTaintConfigs.current.delete(filePath);
    sliceRef.current.runSlice(config.fromSpecs, config.startSeq, config.endSeq, config.sourceSeq, config.dataOnly).then(() => {
      if (config.filterMode) {
        sliceRef.current.setSliceFilterMode(config.filterMode);
      }
    }).catch(e => console.error("Failed to restore taint state:", e));
  }, [activeSessionId, isPhase2Ready, filePath]);

  // 窗口关闭前保存会话快照（含污点配置）
  useEffect(() => {
    const handleBeforeUnload = () => {
      if (!preferences.reopenLastFile) return;
      const files = Array.from(sessions.values()).map(s => {
        const sliceState = slice.getStateForSession(s.sessionId);
        return {
          filePath: s.filePath,
          selectedSeq: getSelectedSeqForSession(s.sessionId),
          taintConfig: sliceState?.sliceActive ? {
            fromSpecs: sliceState.sliceFromSpecs,
            startSeq: sliceState.sliceStartSeq,
            endSeq: sliceState.sliceEndSeq,
            sourceSeq: sliceState.sliceSourceSeq,
            dataOnly: sliceState.sliceDataOnly,
            filterMode: sliceState.sliceFilterMode,
          } : undefined,
        };
      });
      const activeSession = activeSessionId ? sessions.get(activeSessionId) : undefined;
      const snapshot: SessionSnapshot = {
        files,
        activeFilePath: activeSession?.filePath ?? null,
      };
      saveSessionSnapshot(snapshot);
    };
    window.addEventListener("beforeunload", handleBeforeUnload);
    return () => window.removeEventListener("beforeunload", handleBeforeUnload);
  }, [sessions, activeSessionId, preferences.reopenLastFile, slice]);

  // 浮出 session 后自动切换到下一个非浮出的 session
  useEffect(() => {
    if (!activeSessionId || !floatedSessions.has(activeSessionId)) return;
    const nonFloated = Array.from(sessions.values()).find(s => !floatedSessions.has(s.sessionId));
    if (nonFloated) setActiveSessionId(nonFloated.sessionId);
  }, [floatedSessions, activeSessionId, sessions, setActiveSessionId]);

  // 关闭 session 前保存 taint config 到 pendingTaintConfigs，以便重新打开时恢复
  const saveTaintBeforeClose = useCallback((sid: string) => {
    const session = sessions.get(sid);
    const sliceState = slice.getStateForSession(sid);
    if (session && sliceState?.sliceActive) {
      pendingTaintConfigs.current.set(session.filePath, {
        fromSpecs: sliceState.sliceFromSpecs,
        startSeq: sliceState.sliceStartSeq,
        endSeq: sliceState.sliceEndSeq,
        sourceSeq: sliceState.sliceSourceSeq,
        dataOnly: sliceState.sliceDataOnly,
        filterMode: sliceState.sliceFilterMode,
      });
    }
    slice.removeSession(sid);
  }, [sessions, slice]);

  const handleCloseFile = useCallback(async () => {
    const sid = activeSessionId;
    if (sid) saveTaintBeforeClose(sid);
    try { await closeTrace(); } catch (e) { console.error("Failed to close:", e); }
  }, [closeTrace, activeSessionId, saveTaintBeforeClose]);

  const handleJumpToSeq = useCallback((seq: number) => {
    foldState.ensureSeqVisible(seq);
    navigationStore.navigate(seq);
  }, [foldState.ensureSeqVisible]);

  // 搜索路由：Search 已浮动时转发，否则本地搜索
  const handleSearch = useCallback((query: string) => {
    if (floatedPanels.has("search")) {
      emit("action:trigger-search", { query });
    } else {
      searchTrace(query);
    }
  }, [searchTrace, floatedPanels]);

  // 浮动窗口引用（用于主窗口关闭时清理）
  const floatingWindowRefs = useRef<Map<string, WebviewWindow>>(new Map());

  // 浮动窗口创建（可选 position 指定窗口屏幕坐标）
  const handleFloat = useCallback((panel: string, position?: { x: number; y: number }, sizeOverride?: { width: number; height: number }) => {
    const size = sizeOverride ?? PANEL_SIZES[panel] ?? { width: 600, height: 400 };
    const win = new WebviewWindow(`panel-${panel}`, {
      url: `index.html?panel=${panel}`,
      title: PANEL_WINDOW_TITLES[panel] ?? `${panel} - Trace UI`,
      ...clampToScreen(size.width, size.height),
      ...(position ? { x: position.x, y: position.y } : {}),
      decorations: false,
      transparent: true,
    });
    win.once("tauri://created", () => {
      setFloatedPanels(prev => new Set([...prev, panel]));
      floatingWindowRefs.current.set(panel, win);
    });
    // 监听浮动窗口销毁 → 停靠回 TabPanel（不依赖浮动窗口发事件）
    win.once("tauri://destroyed", () => {
      setFloatedPanels(prev => {
        const next = new Set(prev);
        next.delete(panel);
        return next;
      });
      floatingWindowRefs.current.delete(panel);
    });
    win.once("tauri://error", (e) => {
      console.error(`Failed to create floating window for ${panel}:`, e);
    });
  }, []);

  // 浮出 session 窗口
  const handleFloatSession = useCallback((sessionId: string, position?: { x: number; y: number }) => {
    const session = sessions.get(sessionId);
    if (!session) return;

    const urlParams = new URLSearchParams({
      session: sessionId,
      totalLines: String(session.totalLines),
      fileName: session.fileName,
      filePath: session.filePath,
    });

    // 传递当前 taint 状态到浮窗
    const sliceState = slice.getStateForSession(sessionId);
    if (sliceState?.sliceActive) {
      urlParams.set("taintActive", "1");
      urlParams.set("taintFilterMode", sliceState.sliceFilterMode);
      if (sliceState.sliceSourceSeq !== undefined) urlParams.set("taintSourceSeq", String(sliceState.sliceSourceSeq));
    }

    const win = new WebviewWindow(`session-${sessionId}`, {
      url: `index.html?${urlParams.toString()}`,
      title: `${session.fileName} - Trace UI`,
      ...clampToScreen(1000, 600),
      ...(position ? { x: position.x, y: position.y } : {}),
      decorations: false,
      transparent: true,
    });

    win.once("tauri://created", () => {
      setFloatedSessions(prev => new Set([...prev, sessionId]));
      floatingSessionRefs.current.set(sessionId, win);
    });

    win.once("tauri://destroyed", () => {
      setFloatedSessions(prev => {
        const next = new Set(prev);
        next.delete(sessionId);
        return next;
      });
      floatingSessionRefs.current.delete(sessionId);
    });

    win.once("tauri://error", (e) => {
      console.error(`Failed to create floating session window for ${sessionId}:`, e);
    });
  }, [sessions, slice]);

  // Refs 持有最新值，供稳定事件监听器读取（避免监听器因依赖变化频繁重建）
  const activeSessionIdRef = useRef(activeSessionId);
  activeSessionIdRef.current = activeSessionId;
  const isPhase2ReadyRef = useRef(isPhase2Ready);
  isPhase2ReadyRef.current = isPhase2Ready;
  const isLoadedRef = useRef(isLoaded);
  isLoadedRef.current = isLoaded;
  const totalLinesRef = useRef(totalLines);
  totalLinesRef.current = totalLines;
  const filePathRef = useRef(filePath);
  filePathRef.current = filePath;
  const handleJumpToSeqRef = useRef(handleJumpToSeq);
  handleJumpToSeqRef.current = handleJumpToSeq;
  const searchResultsRef = useRef(searchResults);
  searchResultsRef.current = searchResults;
  const searchQueryRef = useRef(searchQuery);
  searchQueryRef.current = searchQuery;
  const searchStatusRef = useRef(searchStatus);
  searchStatusRef.current = searchStatus;
  const searchTotalMatchesRef = useRef(searchTotalMatches);
  searchTotalMatchesRef.current = searchTotalMatches;
  const syncSearchStateRef = useRef(syncSearchState);
  syncSearchStateRef.current = syncSearchState;

  // 监听浮动窗口事件（稳定监听器，空依赖，注册一次永不重建）
  useEffect(() => {
    const unlisteners: Promise<() => void>[] = [];

    // 浮动窗口请求初始状态
    unlisteners.push(listen<{ panel: string }>("panel:ready", (e) => {
      emit("sync:init-state", {
        sessionId: activeSessionIdRef.current,
        selectedSeq: selectedSeqStore.get(),
        isPhase2Ready: isPhase2ReadyRef.current,
        isLoaded: isLoadedRef.current,
        totalLines: totalLinesRef.current,
        filePath: filePathRef.current,
      });
      // search 面板就绪时同步已有搜索结果
      if (e.payload.panel === "search" && searchResultsRef.current.length > 0) {
        emit("sync:search-state", {
          results: searchResultsRef.current,
          query: searchQueryRef.current,
          status: searchStatusRef.current,
          totalMatches: searchTotalMatchesRef.current,
        });
      }
    }));

    // 浮动窗口请求跳转
    unlisteners.push(listen<{ seq: number }>("action:jump-to-seq", (e) => {
      handleJumpToSeqRef.current(e.payload.seq);
    }));

    // View in Memory：跳转到对应 seq（确定内存时间点）
    unlisteners.push(listen<{ addr: string; seq: number }>("action:view-in-memory", (e) => {
      handleJumpToSeqRef.current(e.payload.seq);
    }));

    // 浮动搜索窗口同步搜索结果回主窗口
    unlisteners.push(listen<{ results: SearchMatch[]; query: string; status: string; totalMatches: number }>("sync:search-results-back", (e) => {
      syncSearchStateRef.current(e.payload.results, e.payload.query, e.payload.status, e.payload.totalMatches);
    }));

    return () => { unlisteners.forEach(p => p.then(fn => fn())); };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // 主窗口关闭时销毁所有浮动窗口
  useEffect(() => {
    const win = getCurrentWindow();
    const unlisten = win.onCloseRequested(() => {
      for (const ref of floatingWindowRefs.current.values()) {
        ref.destroy().catch(() => {});
      }
      for (const ref of floatingSessionRefs.current.values()) {
        ref.destroy().catch(() => {});
      }
    });
    return () => { unlisten.then(fn => fn()); };
  }, []);

  // selectedSeq sync via store subscriber (non-React)
  useEffect(() => {
    if (floatedPanels.size === 0) return;
    return selectedSeqStore.subscribe(() => {
      emit("sync:selected-seq", { seq: selectedSeqStore.get() });
    });
  }, [floatedPanels.size]);

  // isPhase2Ready sync (infrequent, keep as React effect)
  useEffect(() => {
    if (floatedPanels.size > 0) {
      emit("sync:phase2-ready", { ready: isPhase2Ready });
    }
  }, [isPhase2Ready, floatedPanels.size]);

  // 状态变化时广播给浮动窗口（session 状态）
  useEffect(() => {
    if (floatedPanels.size > 0) {
      emit("sync:file-state", { isLoaded, totalLines, filePath });
      emit("sync:session-id", { sessionId: activeSessionId });
    }
  }, [isLoaded, totalLines, filePath, activeSessionId, floatedPanels.size]);

  // 全局快捷键：Ctrl+Alt+← 后退，Ctrl+Alt+→ 前进，Ctrl+F 搜索浮窗
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (isModKey(e) && e.altKey && e.key === "ArrowLeft") {
        e.preventDefault();
        handleGoBack();
      } else if (isModKey(e) && e.altKey && e.key === "ArrowRight") {
        e.preventDefault();
        handleGoForward();
      } else if (isModKey(e) && !e.altKey && !e.shiftKey && e.key === "o") {
        // Ctrl+O：打开文件
        e.preventDefault();
        (async () => {
          try {
            const { open } = await import("@tauri-apps/plugin-dialog");
            const selected = await open({
              multiple: false,
              filters: [{ name: "Trace Files", extensions: ["txt", "log", "trace"] }],
            });
            if (selected && typeof selected === "string") {
              handleOpenFile(selected);
            }
          } catch {
            // dialog plugin 不可用，忽略
          }
        })();
      } else if (isModKey(e) && !e.altKey && !e.shiftKey && e.key === "f") {
        // Ctrl+F：打开或聚焦搜索浮窗
        e.preventDefault();
        if (floatedPanels.has("search")) {
          // 搜索浮窗已存在，强制置顶并聚焦输入框
          const win = floatingWindowRefs.current.get("search");
          if (win) {
            (async () => {
              await win.unminimize();
              await win.show();
              await win.setAlwaysOnTop(true);
              await win.setFocus();
              setTimeout(async () => {
                try { await win.setAlwaysOnTop(false); } catch {}
              }, 200);
            })();
          }
          setTimeout(() => emitTo("panel-search", "search:focus-input"), 100);
        } else {
          // 搜索浮窗未打开，按主窗口 60% 比例居中弹出
          const mainWin = getCurrentWindow();
          Promise.all([mainWin.outerPosition(), mainWin.outerSize(), mainWin.scaleFactor()]).then(([pos, size, scale]) => {
            // 物理像素 → 逻辑像素
            const lx = pos.x / scale;
            const ly = pos.y / scale;
            const lw = size.width / scale;
            const lh = size.height / scale;
            // 浮窗尺寸：宽 30%、高 26%
            const pw = Math.max(380, Math.round(lw * 0.30));
            const ph = Math.max(220, Math.round(lh * 0.26));
            const x = Math.round(lx + (lw - pw) / 2);
            const y = Math.round(ly + (lh - ph) / 2);
            handleFloat("search", { x, y }, { width: pw, height: ph });
          });
        }
      } else if (e.key === "g" && !e.ctrlKey && !e.altKey && !e.shiftKey && !e.metaKey) {
        // G 键：跳转覆盖层（排除输入框焦点）
        const el = e.target as HTMLElement;
        if (el.tagName === "INPUT" || el.tagName === "TEXTAREA" || el.isContentEditable) return;
        e.preventDefault();
        setShowGoto(true);
      } else if (e.key === "F12") {
        e.preventDefault();
        invoke("toggle_devtools");
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [handleGoBack, handleGoForward, floatedPanels, handleFloat, handleOpenFile]);

  useEffect(() => {
    const webview = getCurrentWebview();
    const unlisten = webview.onDragDropEvent((event) => {
      if (event.payload.type === "drop") {
        const paths = event.payload.paths;
        if (paths && paths.length > 0) {
          // 顺序打开避免并发竞态
          (async () => {
            for (const p of paths) {
              await handleOpenFile(p);
            }
          })();
        }
      }
    });
    return () => { unlisten.then((fn) => fn()); };
  }, [handleOpenFile]);

  return (
    <div style={{ height: "100vh", display: "flex", flexDirection: "column" }}>
      <TitleBar
        onOpenFile={handleOpenFile}
        onCloseFile={handleCloseFile}
        onRebuildIndex={rebuildIndex}
        onSearch={handleSearch}
        isLoaded={isLoaded}
        recentFiles={recentFiles}
        onRemoveRecent={removeRecent}
        onGoBack={handleGoBack}
        onGoForward={handleGoForward}
        preferences={preferences}
        onUpdatePreferences={updatePreferences}
        onTaintAnalysis={() => {
          const seq = selectedSeqStore.get();
          if (seq !== null) {
            setTaintDialogSeq(seq);
            setTaintDialogReg(undefined);
          }
        }}
        onSaveTaintResults={async () => {
          if (!activeSessionId || !slice.sliceActive) return;
          try {
            const { save } = await import("@tauri-apps/plugin-dialog");
            // 默认文件名: {原文件名}-taint-{时间戳}
            const baseName = filePath?.split(/[/\\]/).pop()?.replace(/\.[^.]+$/, "") ?? "trace";
            const now = new Date();
            const ts = `${now.getFullYear()}${String(now.getMonth() + 1).padStart(2, "0")}${String(now.getDate()).padStart(2, "0")}-${String(now.getHours()).padStart(2, "0")}${String(now.getMinutes()).padStart(2, "0")}${String(now.getSeconds()).padStart(2, "0")}`;
            const defaultName = `${baseName}-taint-${ts}`;
            const selected = await save({
              defaultPath: defaultName,
              filters: [
                { name: "Text", extensions: ["txt"] },
                { name: "JSON", extensions: ["json"] },
              ],
            });
            if (!selected) return;
            const format = selected.endsWith(".txt") ? "txt" : "json";
            await invoke("export_taint_results", {
              sessionId: activeSessionId,
              outputPath: selected,
              format,
              config: {
                fromSpecs: slice.sliceFromSpecs,
                startSeq: slice.sliceStartSeq ?? null,
                endSeq: slice.sliceEndSeq ?? null,
              },
            });
          } catch (e) {
            console.error("Save taint results failed:", e);
          }
        }}
        onHighlight={(color) => { const seq = selectedSeqStore.get(); if (seq !== null) setHighlight([seq], { color }); }}
        onStrikethrough={() => { const seq = selectedSeqStore.get(); if (seq !== null) toggleStrikethrough([seq]); }}
        onResetHighlight={() => { const seq = selectedSeqStore.get(); if (seq !== null) resetHighlight([seq]); }}
        onHide={() => { const seq = selectedSeqStore.get(); if (seq !== null) toggleHidden([seq]); }}
        sliceActive={slice.sliceActive}
        sliceFilterMode={slice.sliceFilterMode}
        sliceInfo={slice.sliceInfo}
        onTaintFilterModeChange={(mode) => {
          slice.setSliceFilterMode(mode);
          const seq = selectedSeqStore.get();
          if (seq !== null) {
            requestAnimationFrame(() => {
              scrollAlignRef.current = "auto";
              setScrollTrigger(c => c + 1);
              navigationStore.navigate(seq);
            });
          }
        }}
        onTaintClear={() => {
          const sourceSeq = slice.sliceSourceSeq;
          slice.clearSlice();
          if (sourceSeq !== undefined) {
            scrollAlignRef.current = "center";
            setScrollTrigger(c => c + 1);
            navigationStore.navigate(sourceSeq);
          }
        }}
        onTaintGoToSource={() => {
          if (slice.sliceSourceSeq !== undefined) {
            scrollAlignRef.current = "end";
            setScrollTrigger(c => c + 1);
            navigationStore.navigate(slice.sliceSourceSeq);
          }
        }}
        onTaintReconfigure={() => {
          if (taintDialogSeq === null) {
            if (selectedRegInfo) {
              setTaintDialogSeq(selectedRegInfo.seq);
              setTaintDialogReg(selectedRegInfo.regName);
            } else {
              const startLine = slice.sliceStartSeq !== undefined ? slice.sliceStartSeq : 0;
              setTaintDialogSeq(startLine);
              setTaintDialogReg(undefined);
            }
          }
        }}
        onClearCache={clearRecent}
        regSelected={selectedRegInfo !== null}
      />
      <Group orientation="horizontal" style={{ flex: 1 }} elementRef={hGroupRef}>
        <Panel defaultSize={20} minSize={15} panelRef={leftPanelRef}>
          <Group orientation="vertical" elementRef={leftGroupRef}>
            <Panel defaultSize={65} minSize={20}>
              <FunctionTree
                isPhase2Ready={isPhase2Ready}
                onJumpToSeq={handleJumpToSeq}
                nodeMap={callTreeNodeMap}
                nodeCount={callTreeCount}
                loading={callTreeLoading}
                error={callTreeError}
                lazyMode={callTreeLazyMode}
                loadedNodes={callTreeLoadedNodes}
                onLoadChildren={loadCallTreeChildren}
                funcRename={funcRename}
              />
            </Panel>
            <Separator style={{ height: 3 }} />
            <Panel defaultSize={35} minSize={15} panelRef={regPanelRef}>
              <RegisterPanel isPhase2Ready={isPhase2Ready} sessionId={activeSessionId} />
            </Panel>
          </Group>
        </Panel>
        <Separator style={{ width: 3 }} />
        <Panel defaultSize={80} minSize={40}>
          <Group orientation="vertical" elementRef={rightGroupRef}>
            <Panel defaultSize={65} minSize={20}>
              <div style={{ height: "100%", display: "flex", flexDirection: "column" }}>
                <FileTabBar
                  tabs={Array.from(sessions.values())
                    .filter(s => !floatedSessions.has(s.sessionId))
                    .map((s) => ({
                      sessionId: s.sessionId,
                      fileName: s.fileName,
                      filePath: s.filePath,
                      isPhase2Ready: s.isPhase2Ready,
                    }))}
                  activeSessionId={activeSessionId}
                  onActivate={setActiveSessionId}
                  onClose={(sid) => { callTreeCache.current.delete(sid); saveTaintBeforeClose(sid); closeSession(sid).catch(console.error); }}
                  onFloat={handleFloatSession}
                />
                <div style={{ flex: 1, overflow: "hidden" }}>
                  <TraceTable
                    totalLines={totalLines}
                    isLoaded={isLoaded}
                    onSelectSeq={navigationStore.navigate}
                    getLines={getLines}
                    savedScrollSeq={savedScrollSeq}
                    foldState={foldState}
                    scrollAlignRef={scrollAlignRef}
                    sessionId={activeSessionId}
                    highlights={highlights}
                    onSetHighlight={setHighlight}
                    onToggleStrikethrough={toggleStrikethrough}
                    onResetHighlight={resetHighlight}
                    onToggleHidden={toggleHidden}
                    onUnhideGroup={unhideGroup}
                    showAllHidden={preferences.showAllHidden}
                    showHiddenIndicators={preferences.showHiddenIndicators}
                    onSetComment={setComment}
                    onDeleteComment={deleteComment}
                    sliceActive={slice.sliceActive}
                    getSliceStatus={slice.getSliceStatus}
                    onTaintRequest={(seq, reg) => { setTaintDialogSeq(seq); setTaintDialogReg(reg); }}
                    onRegSelected={setSelectedRegInfo}
                    sliceFilterMode={slice.sliceFilterMode}
                    taintedSeqs={slice.taintedSeqs}
                    sliceSourceSeq={slice.sliceSourceSeq}
                    scrollTrigger={scrollTrigger}
                  />
                </div>
              </div>
            </Panel>
            <Separator style={{ height: 3 }} />
            <Panel defaultSize={35} minSize={15} panelRef={bottomPanelRef}>
              <TabPanel
                searchResults={searchResults}
                searchQuery={searchQuery}
                isSearching={isSearching}
                searchStatus={searchStatus}
                searchTotalMatches={searchTotalMatches}
                onJumpToSeq={handleJumpToSeq}
                isPhase2Ready={isPhase2Ready}
                floatedPanels={floatedPanels}
                onFloat={handleFloat}
                sessionId={activeSessionId}
                sliceActive={slice.sliceActive}
                sliceInfo={slice.sliceInfo}
                sliceFromSpecs={slice.sliceFromSpecs}
              />
            </Panel>
          </Group>
        </Panel>
      </Group>
      <div style={{
        display: "flex", alignItems: "center", justifyContent: "space-between",
        padding: "2px 12px", flexShrink: 0, height: 22,
        background: "var(--bg-secondary)",
        borderTop: "1px solid var(--border-color)",
        fontSize: 11, color: "var(--text-secondary)",
      }}>
        <span>
          {isLoaded && filePath
            ? `${filePath.split(/[/\\]/).pop()} — ${totalLines.toLocaleString()} lines`
            : ""}
        </span>
        <StatusBarSelection />
      </div>
      {taintDialogSeq !== null && (
        <TaintConfigDialog
          seq={taintDialogSeq}
          totalLines={totalLines}
          defaultDefs={taintDialogReg ? [taintDialogReg] : undefined}
          onExecute={async (specs, startSeq, endSeq, dataOnly) => {
            const sourceSeq = taintDialogSeq;
            setTaintDialogSeq(null);
            await slice.runSlice(specs, startSeq, endSeq, sourceSeq, dataOnly);
            // 跳转到污点源行
            scrollAlignRef.current = "end";
            setScrollTrigger(c => c + 1);
            navigationStore.navigate(sourceSeq);
          }}
          onClose={() => setTaintDialogSeq(null)}
        />
      )}
      {showGoto && (
        <GotoOverlay
          onJumpToSeq={handleJumpToSeq}
          onClose={() => setShowGoto(false)}
          sessionId={activeSessionId}
          totalLines={totalLines}
        />
      )}
      {isLoading && (
        <div
          style={{
            position: "fixed", top: 0, left: 0, right: 0, bottom: 0,
            background: "rgba(0,0,0,0.6)",
            display: "flex", flexDirection: "column",
            alignItems: "center", justifyContent: "center",
            zIndex: 9999,
          }}
          onKeyDown={(e) => { if (e.key === "Escape") cancelLoading(); }}
          tabIndex={-1}
          ref={(el) => el?.focus()}
        >
          <div style={{ color: "var(--text-primary)", fontSize: 16, marginBottom: 12 }}>
            {loadingMessage}
          </div>
          <div style={{
            width: 40, height: 40,
            border: "3px solid var(--border-color)", borderTop: "3px solid var(--btn-primary)",
            borderRadius: "50%", animation: "spin 1s linear infinite",
          }} />
        </div>
      )}
      {indexError && (
        <div style={{
          position: "fixed", top: 0, left: 0, right: 0, bottom: 0,
          background: "rgba(0,0,0,0.6)",
          display: "flex", alignItems: "center", justifyContent: "center",
          zIndex: 10000,
        }}>
          <div style={{
            background: "var(--bg-dialog)", border: "1px solid var(--border-color)",
            borderRadius: 8, padding: "24px 32px", maxWidth: 480, width: "90%",
            boxShadow: "0 8px 32px rgba(0,0,0,0.5)",
          }}>
            <div style={{ color: "var(--text-primary)", fontSize: 15, fontWeight: 600, marginBottom: 12 }}>
              File format error
            </div>
            <div style={{
              color: "var(--text-secondary)", fontSize: 13, marginBottom: 20,
              lineHeight: 1.5, wordBreak: "break-word",
              maxHeight: 200, overflow: "auto",
            }}>
              {indexError.message}
            </div>
            <div style={{ display: "flex", justifyContent: "flex-end" }}>
              <button
                onClick={() => {
                  if (indexError.filePath) {
                    removeRecent(indexError.filePath);
                  }
                  clearIndexError();
                }}
                style={{
                  padding: "6px 20px", background: "var(--btn-primary)", color: "#fff",
                  border: "none", borderRadius: 4, cursor: "pointer", fontSize: 13,
                }}
              >
                OK
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function StatusBarSelection() {
  const selectedSeq = useSelectedSeq();
  if (selectedSeq === null) return null;
  return <span>selected: #{selectedSeq + 1}</span>;
}

export default App;
