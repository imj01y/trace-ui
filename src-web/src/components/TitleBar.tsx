import { useState, useCallback, useEffect, useRef } from "react";
import { openUrl, openPath } from "@tauri-apps/plugin-opener";
import { invoke } from "@tauri-apps/api/core";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { getVersion } from "@tauri-apps/api/app";
import WindowControls from "./WindowControls";
import ConfirmDialog from "./ConfirmDialog";
import PreferencesDialog from "./PreferencesDialog";
import { MenuDropdown, MenuItem, MenuSeparator } from "./MenuDropdown";
import ContextMenu, { ContextMenuItem } from "./ContextMenu";
import type { Preferences } from "../hooks/usePreferences";
import { isMac, modKey } from "../utils/platform";
import { HIGHLIGHT_COLORS } from "../utils/highlightColors";
import { useHasSelectedSeq } from "../stores/selectedSeqStore";
import { useCanGoBack, useCanGoForward } from "../stores/navigationStore";

interface Props {
  onOpenFile: (path: string) => void;
  onCloseFile: () => void;
  onRebuildIndex: () => void;
  onSearch: (query: string) => void;
  isLoaded: boolean;
  recentFiles: string[];
  onRemoveRecent: (path: string) => void;
  onGoBack: () => void;
  onGoForward: () => void;
  preferences: Preferences;
  onUpdatePreferences: (updates: Partial<Preferences>) => void;
  onTaintAnalysis: () => void;
  onScanStrings: () => void;
  hasStringIndex: boolean;
  stringsScanning: boolean;
  onScanCrypto: () => void;
  cryptoScanning: boolean;
  isPhase2Ready: boolean;
  onSaveTaintResults: () => void;
  // Highlight & Hide
  onHighlight: (color: string) => void;
  onStrikethrough: () => void;
  onResetHighlight: () => void;
  onHide: () => void;
  // Taint 菜单
  sliceActive: boolean;
  sliceFilterMode: "highlight" | "filter-only";
  sliceInfo: { markedCount: number; totalLines: number; percentage: number } | null;
  onTaintFilterModeChange: (mode: "highlight" | "filter-only") => void;
  onTaintClear: () => void;
  onTaintGoToSource: () => void;
  onTaintReconfigure: () => void;
  onClearCache?: () => void;
  regSelected?: boolean;
}

export default function TitleBar({ onOpenFile, onCloseFile, onRebuildIndex, onSearch, isLoaded, recentFiles, onRemoveRecent, onGoBack, onGoForward, preferences, onUpdatePreferences, onTaintAnalysis, onScanStrings, hasStringIndex, stringsScanning, onScanCrypto, cryptoScanning, isPhase2Ready, onSaveTaintResults, onHighlight, onStrikethrough, onResetHighlight, onHide, sliceActive, sliceFilterMode, sliceInfo, onTaintFilterModeChange, onTaintClear, onTaintGoToSource, onTaintReconfigure, onClearCache, regSelected }: Props) {
  const hasSelectedSeq = useHasSelectedSeq();
  const canGoBack = useCanGoBack();
  const canGoForward = useCanGoForward();
  const [isFullscreen, setIsFullscreen] = useState(false);

  useEffect(() => {
    if (!isMac) return;
    const win = getCurrentWindow();
    // 初始化检查
    win.isFullscreen().then(setIsFullscreen).catch(() => {});
    // 监听窗口 resize 事件来检测全屏变化
    const unlisten = win.onResized(() => {
      win.isFullscreen().then(setIsFullscreen).catch(() => {});
    });
    return () => { unlisten.then(fn => fn()); };
  }, []);

  const [manualPath, setManualPath] = useState("");
  const [showPathInput, setShowPathInput] = useState(false);
  const [showCloseConfirm, setShowCloseConfirm] = useState(false);
  const [searchInput, setSearchInput] = useState("");
  const [showAbout, setShowAbout] = useState(false);
  const [appVersion, setAppVersion] = useState("");
  useEffect(() => { getVersion().then(setAppVersion).catch(() => {}); }, []);
  const [showPrefs, setShowPrefs] = useState(false);
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((isMac ? e.metaKey : e.ctrlKey) && !e.altKey && !e.shiftKey && e.key === ",") {
        e.preventDefault();
        setShowPrefs(prev => !prev);
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, []);
  const [showRebuildConfirm, setShowRebuildConfirm] = useState(false);
  const [showClearCacheConfirm, setShowClearCacheConfirm] = useState(false);
  const [showScanStringsConfirm, setShowScanStringsConfirm] = useState(false);
  const [showScanCryptoConfirm, setShowScanCryptoConfirm] = useState(false);
  const [recentHover, setRecentHover] = useState(false);
  const [highlightHover, setHighlightHover] = useState(false);
  const [recentCtxMenu, setRecentCtxMenu] = useState<{ path: string; x: number; y: number } | null>(null);

  // ── 搜索历史 ──
  const SEARCH_HISTORY_KEY = "titlebar-search-history";
  const MAX_SEARCH_HISTORY = 20;
  const [searchHistoryList, setSearchHistoryList] = useState<string[]>(() => {
    try { return JSON.parse(localStorage.getItem(SEARCH_HISTORY_KEY) || "[]"); } catch { return []; }
  });
  const [showSearchHistory, setShowSearchHistory] = useState(false);
  const searchWrapperRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!showSearchHistory) return;
    const handler = (e: MouseEvent) => {
      if (searchWrapperRef.current && !searchWrapperRef.current.contains(e.target as Node)) {
        setShowSearchHistory(false);
      }
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [showSearchHistory]);

  const addSearchHistory = useCallback((query: string) => {
    if (!query.trim()) return;
    setSearchHistoryList(prev => {
      const next = [query.trim(), ...prev.filter(h => h !== query.trim())].slice(0, MAX_SEARCH_HISTORY);
      localStorage.setItem(SEARCH_HISTORY_KEY, JSON.stringify(next));
      return next;
    });
  }, []);

  const removeSearchHistoryItem = useCallback((item: string) => {
    setSearchHistoryList(prev => {
      const next = prev.filter(h => h !== item);
      localStorage.setItem(SEARCH_HISTORY_KEY, JSON.stringify(next));
      return next;
    });
  }, []);

  const clearAllSearchHistory = useCallback(() => {
    setSearchHistoryList([]);
    localStorage.removeItem(SEARCH_HISTORY_KEY);
    setShowSearchHistory(false);
  }, []);

  const filteredSearchHistory = searchInput.trim()
    ? searchHistoryList.filter(h => h !== searchInput.trim() && h.toLowerCase().includes(searchInput.toLowerCase()))
    : searchHistoryList;

  const handleOpen = useCallback(async () => {
    try {
      const { open } = await import("@tauri-apps/plugin-dialog");
      const selected = await open({
        multiple: false,
        filters: [{ name: "Trace Files", extensions: ["txt", "log", "trace"] }],
      });
      if (selected && typeof selected === "string") {
        onOpenFile(selected);
      }
    } catch {
      setShowPathInput(true);
    }
  }, [onOpenFile]);

  const handleManualLoad = useCallback(() => {
    if (manualPath.trim()) {
      onOpenFile(manualPath.trim());
      setShowPathInput(false);
      setManualPath("");
    }
  }, [manualPath, onOpenFile]);

  return (
    <>
      <div
        data-tauri-drag-region
        style={{
          display: "flex",
          alignItems: "center",
          gap: 8,
          // macOS Overlay 模式：左侧 78px 留给原生交通灯按钮；全屏时交通灯隐藏，缩小到 12px
          padding: isMac ? (isFullscreen ? "0 0 0 12px" : "0 0 0 78px") : "0 0 0 12px",
          height: 36,
          background: "var(--bg-secondary)",
          borderBottom: "1px solid var(--border-color)",
          flexShrink: 0,
        }}
      >
        {/* File 下拉菜单 */}
        <MenuDropdown label="File">
          <MenuItem label="Open File..." shortcut={modKey("O")} onClick={handleOpen} />
          {/* Recent Files 子菜单 */}
          <div
            style={{ position: "relative" }}
            onMouseEnter={() => setRecentHover(true)}
            onMouseLeave={() => { setRecentHover(false); setRecentCtxMenu(null); }}
          >
            <div
              style={{
                display: "flex", alignItems: "center", padding: "6px 24px 6px 12px", fontSize: 12,
                color: recentFiles.length > 0 ? "var(--text-primary)" : "var(--text-secondary)",
                cursor: recentFiles.length > 0 ? "pointer" : "default", whiteSpace: "nowrap",
              }}
              onMouseEnter={(e) => { e.currentTarget.style.background = "var(--bg-selected)"; }}
              onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
            >
              <span style={{ flex: 1 }}>Recent Files</span>
              <span style={{ marginLeft: 12, fontSize: 10 }}>▶</span>
            </div>
            {recentHover && recentFiles.length > 0 && (
              <div style={{
                position: "absolute", left: "100%", top: 0, marginLeft: 2,
                background: "var(--bg-dialog)", border: "1px solid var(--border-color)",
                borderRadius: 6, boxShadow: "0 4px 16px rgba(0,0,0,0.4)",
                zIndex: 1001, minWidth: 280, maxWidth: Math.min(500, window.innerWidth - 40), padding: "4px 0",
              }}>
                {recentFiles.map((path, i) => (
                  <div
                    key={i}
                    onClick={() => onOpenFile(path)}
                    onContextMenu={(e) => {
                      e.preventDefault();
                      e.stopPropagation();
                      setRecentCtxMenu({ path, x: e.clientX, y: e.clientY });
                    }}
                    onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.background = "var(--bg-selected)"; }}
                    onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.background = "transparent"; }}
                    style={{
                      display: "flex", alignItems: "center", padding: "6px 24px 6px 12px",
                      fontSize: 12, color: "var(--text-primary)", cursor: "pointer",
                      whiteSpace: "nowrap", fontFamily: "var(--font-mono)",
                      overflow: "hidden", textOverflow: "ellipsis",
                    }}
                    title={path}
                  >
                    {path.split(/[/\\]/).pop()}
                  </div>
                ))}
                {recentCtxMenu && (
                  <ContextMenu
                    x={recentCtxMenu.x}
                    y={recentCtxMenu.y}
                    onClose={() => setRecentCtxMenu(null)}
                    minWidth={120}
                  >
                    <ContextMenuItem
                      label="Delete"
                      onClick={() => {
                        onRemoveRecent(recentCtxMenu.path);
                        setRecentCtxMenu(null);
                      }}
                    />
                  </ContextMenu>
                )}
              </div>
            )}
          </div>
          <MenuSeparator />
          <MenuItem label="Save Taint Results..." disabled={!sliceActive} onClick={onSaveTaintResults} />
          <MenuSeparator />
          <MenuItem label="Close File" disabled={!isLoaded} onClick={() => setShowCloseConfirm(true)} />
        </MenuDropdown>

        {/* View 下拉菜单 */}
        <MenuDropdown label="View" minWidth={220}>
          {/* Highlight 子菜单 */}
          <div
            style={{ position: "relative" }}
            onMouseEnter={() => setHighlightHover(true)}
            onMouseLeave={() => setHighlightHover(false)}
            onClick={(e) => e.stopPropagation()}
          >
            <div
              style={{
                display: "flex", alignItems: "center", padding: "6px 24px 6px 12px", fontSize: 12,
                color: hasSelectedSeq ? "var(--text-primary)" : "var(--text-secondary)",
                cursor: hasSelectedSeq ? "pointer" : "default", whiteSpace: "nowrap",
              }}
              onMouseEnter={(e) => { if (hasSelectedSeq) e.currentTarget.style.background = "var(--bg-selected)"; }}
              onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
            >
              <span style={{ flex: 1 }}>Highlight</span>
              <span style={{ marginLeft: 12, fontSize: 10 }}>▶</span>
            </div>
            {highlightHover && hasSelectedSeq && (
              <div style={{
                position: "absolute", left: "100%", top: 0, marginLeft: 2,
                background: "var(--bg-dialog)", border: "1px solid var(--border-color)",
                borderRadius: 6, boxShadow: "0 4px 16px rgba(0,0,0,0.4)",
                zIndex: 1001, minWidth: 160, padding: "4px 0",
              }}>
                {HIGHLIGHT_COLORS.map(hc => (
                  <div
                    key={hc.key}
                    onClick={() => onHighlight(hc.key)}
                    onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.background = "var(--bg-selected)"; }}
                    onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.background = "transparent"; }}
                    style={{
                      display: "flex", alignItems: "center", gap: 8, padding: "6px 12px",
                      fontSize: 12, color: "var(--text-primary)", cursor: "pointer", whiteSpace: "nowrap",
                    }}
                  >
                    <span style={{ display: "inline-block", width: 12, height: 12, borderRadius: 2, background: hc.color, border: "1px solid rgba(255,255,255,0.2)" }} />
                    <span style={{ flex: 1 }}>{hc.label}</span>
                    <span style={{ color: "var(--text-secondary)", fontSize: 11 }}>{hc.shortcut()}</span>
                  </div>
                ))}
                <div style={{ height: 1, background: "var(--border-color)", margin: "4px 0" }} />
                <div
                  onClick={onStrikethrough}
                  onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.background = "var(--bg-selected)"; }}
                  onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.background = "transparent"; }}
                  style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "6px 12px", fontSize: 12, color: "var(--text-primary)", cursor: "pointer", whiteSpace: "nowrap" }}
                >
                  <span>Strikethrough</span>
                  <span style={{ color: "var(--text-secondary)", fontSize: 11 }}>{isMac ? "⌥+-" : "Alt+-"}</span>
                </div>
                <div
                  onClick={onResetHighlight}
                  onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.background = "var(--bg-selected)"; }}
                  onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.background = "transparent"; }}
                  style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "6px 12px", fontSize: 12, color: "var(--text-primary)", cursor: "pointer", whiteSpace: "nowrap" }}
                >
                  <span>Reset</span>
                  <span style={{ color: "var(--text-secondary)", fontSize: 11 }}>{isMac ? "⌥+0" : "Alt+0"}</span>
                </div>
              </div>
            )}
          </div>
          <MenuItem label="Hide" shortcut={modKey("/")} disabled={!hasSelectedSeq} onClick={onHide} />
          <MenuSeparator />
          <MenuItem
            label={preferences.showAllHidden ? "Cancel Show All Hidden" : "Show All Hidden"}
            onClick={() => onUpdatePreferences({ showAllHidden: !preferences.showAllHidden })}
          />
          <MenuItem
            label={preferences.showHiddenIndicators ? "Hide Hidden Indicators" : "Show Hidden Indicators"}
            disabled={preferences.showAllHidden}
            onClick={() => onUpdatePreferences({ showHiddenIndicators: !preferences.showHiddenIndicators })}
          />
        </MenuDropdown>

        {/* Analysis 下拉菜单 */}
        <MenuDropdown label="Analysis" minWidth={200}>
          <MenuItem label="Taint Analysis..." disabled={!hasSelectedSeq} onClick={onTaintAnalysis} />
          <MenuItem
              label={hasStringIndex ? "Rescan Strings" : "Scan Strings"}
              disabled={!isLoaded || !isPhase2Ready || stringsScanning}
              onClick={() => setShowScanStringsConfirm(true)}
          />
          <MenuItem
              label="Scan Crypto"
              disabled={!isLoaded || cryptoScanning}
              onClick={() => setShowScanCryptoConfirm(true)}
          />
          <MenuSeparator />
          <MenuItem label="Rebuild Index" disabled={!isLoaded} onClick={() => setShowRebuildConfirm(true)} />
        </MenuDropdown>

        {/* Settings 下拉菜单 */}
        <MenuDropdown label="Settings" minWidth={200}>
          <MenuItem label="Preferences..." shortcut={modKey(",")} onClick={() => setShowPrefs(true)} />
          <MenuSeparator />
          <MenuItem label="Open Cache Directory" onClick={async () => {
            try {
              const info = await invoke<{ path: string }>("get_cache_dir");
              await openPath(info.path);
            } catch (e) { console.error("open cache dir failed:", e); }
          }} />
          <MenuItem label="Clear Cache..." onClick={() => setShowClearCacheConfirm(true)} />
        </MenuDropdown>

        {/* About 按钮 */}
        <button
          onClick={() => setShowAbout(true)}
          onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.background = "var(--bg-input)"; }}
          onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.background = "transparent"; }}
          style={{
            padding: "4px 10px",
            background: "transparent",
            color: "var(--text-primary)",
            border: "none",
            borderRadius: 4,
            cursor: "pointer",
            fontSize: "var(--font-size-sm)",
          }}
        >
          About
        </button>

        {/* 左侧拖动区域 */}
        <div style={{ flex: 1, minWidth: 0 }} data-tauri-drag-region />

        {/* 中间：导航按钮 + 搜索框 */}
        {/* Taint 按钮/菜单 */}
        {sliceActive ? (
          <MenuDropdown label="Taint" minWidth={200} labelStyle={{ background: "var(--btn-taint)", color: "#fff" }}>
            <MenuItem
              label="Tainted Only"
              checked={sliceFilterMode === "filter-only"}
              onClick={() => onTaintFilterModeChange("filter-only")}
            />
            <MenuItem
              label="Show All (Dimmed)"
              checked={sliceFilterMode === "highlight"}
              onClick={() => onTaintFilterModeChange("highlight")}
            />
            <MenuSeparator />
            <MenuItem label="Go to Source" onClick={onTaintGoToSource} />
            <MenuItem label="Re-configure..." onClick={onTaintReconfigure} />
            <MenuSeparator />
            <MenuItem label="Clear" onClick={onTaintClear} />
          </MenuDropdown>
        ) : regSelected ? (
          <button
            onClick={onTaintReconfigure}
            style={{
              padding: "4px 10px",
              background: "var(--btn-primary)",
              color: "#fff",
              border: "none",
              borderRadius: 4,
              cursor: "pointer",
              fontSize: "var(--font-size-sm)",
            }}
          >
            Taint
          </button>
        ) : (
          <button
            onClick={onTaintAnalysis}
            disabled={!hasSelectedSeq}
            style={{
              padding: "4px 10px",
              background: hasSelectedSeq ? "var(--bg-secondary)" : "transparent",
              color: hasSelectedSeq ? "var(--text-primary)" : "var(--text-secondary)",
              border: "none",
              borderRadius: 4,
              cursor: hasSelectedSeq ? "pointer" : "default",
              fontSize: "var(--font-size-sm)",
              opacity: hasSelectedSeq ? 1 : 0.5,
            }}
          >
            Taint
          </button>
        )}
        <button
          onClick={canGoBack ? onGoBack : undefined}
          style={{ padding: "4px 8px", background: "transparent", color: "var(--text-secondary)", border: "none", borderRadius: 4, cursor: canGoBack ? "pointer" : "default", fontSize: 14, opacity: canGoBack ? 1 : 0.35 }}
          title={`Back (${isMac ? "⌘+⌥+←" : "Ctrl+Alt+←"})`}
        >◀</button>
        <button
          onClick={canGoForward ? onGoForward : undefined}
          style={{ padding: "4px 8px", background: "transparent", color: "var(--text-secondary)", border: "none", borderRadius: 4, cursor: canGoForward ? "pointer" : "default", fontSize: 14, opacity: canGoForward ? 1 : 0.35 }}
          title={`Forward (${isMac ? "⌘+⌥+→" : "Ctrl+Alt+→"})`}
        >▶</button>

        <div ref={searchWrapperRef} style={{ position: "relative", flex: 1, maxWidth: 420, minWidth: 180 }}>
          <input
            type="text"
            placeholder="Search text or /regex/"
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            onFocus={() => setShowSearchHistory(true)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && isLoaded) {
                onSearch(searchInput);
                addSearchHistory(searchInput);
                setShowSearchHistory(false);
              }
            }}
            style={{
              width: "100%",
              padding: "4px 26px 4px 8px",
              background: "var(--bg-input)",
              color: "var(--text-primary)",
              border: "1px solid var(--border-color)",
              borderRadius: 4,
              fontFamily: "var(--font-mono)",
              fontSize: "var(--font-size-sm)",
            }}
          />
          {searchInput && (
            <button
              onClick={() => { setSearchInput(""); setShowSearchHistory(false); }}
              style={{
                position: "absolute",
                right: 4,
                top: "50%",
                transform: "translateY(-50%)",
                width: 18,
                height: 18,
                padding: 0,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                background: "transparent",
                color: "var(--text-secondary)",
                border: "none",
                borderRadius: 3,
                cursor: "pointer",
                fontSize: 12,
                lineHeight: 1,
              }}
              onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.color = "var(--text-primary)"; (e.currentTarget as HTMLElement).style.background = "var(--bg-secondary)"; }}
              onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.color = "var(--text-secondary)"; (e.currentTarget as HTMLElement).style.background = "transparent"; }}
              title="Clear search"
            >✕</button>
          )}
          {showSearchHistory && filteredSearchHistory.length > 0 && (
            <div style={{
              position: "absolute", top: "100%", left: 0, width: "100%", marginTop: 2,
              background: "var(--bg-dialog)", border: "1px solid var(--border-color)",
              borderRadius: 4, zIndex: 100, maxHeight: 200, overflowY: "auto",
              boxShadow: "0 4px 12px rgba(0,0,0,0.4)",
            }}>
              {filteredSearchHistory.map(item => (
                <div
                  key={item}
                  style={{
                    display: "flex", alignItems: "center", padding: "4px 8px", fontSize: 12,
                    cursor: "pointer", color: "var(--text-primary)",
                  }}
                  onMouseEnter={e => (e.currentTarget.style.background = "var(--bg-selected)")}
                  onMouseLeave={e => (e.currentTarget.style.background = "transparent")}
                  onClick={() => {
                    setSearchInput(item);
                    setShowSearchHistory(false);
                    if (isLoaded) { onSearch(item); }
                  }}
                >
                  <span style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{item}</span>
                  <span
                    onClick={e => { e.stopPropagation(); removeSearchHistoryItem(item); }}
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
                onClick={clearAllSearchHistory}
              >Clear All</div>
            </div>
          )}
        </div>

        {/* 手动路径输入（dialog plugin 不可用时显示） */}
        {showPathInput && (
          <>
            <input
              type="text"
              placeholder="Enter trace file path..."
              value={manualPath}
              onChange={(e) => setManualPath(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleManualLoad()}
              style={{
                width: "100%",
                padding: "4px 8px",
                background: "var(--bg-input)",
                color: "var(--text-primary)",
                border: "1px solid var(--border-color)",
                borderRadius: 4,
                fontFamily: "var(--font-mono)",
                fontSize: "var(--font-size-sm)",
              }}
            />
            <button
              onClick={handleManualLoad}
              style={{
                padding: "4px 12px",
                background: "var(--bg-input)",
                color: "var(--text-primary)",
                border: "1px solid var(--border-color)",
                borderRadius: 4,
                cursor: "pointer",
              }}
            >
              Load
            </button>
          </>
        )}

        {/* 右侧拖动区域 */}
        <div style={{ flex: 1, minWidth: 0 }} data-tauri-drag-region />

        {/* 窗口控制按钮 */}
        {!isMac && <WindowControls />}
      </div>

      {/* 关闭确认对话框 */}
      {showCloseConfirm && (
        <ConfirmDialog
          title="Close File"
          message="Are you sure you want to close the current trace file?"
          confirmText="Confirm"
          cancelText="Cancel"
          confirmColor="var(--reg-changed)"
          onConfirm={() => { setShowCloseConfirm(false); onCloseFile(); }}
          onCancel={() => setShowCloseConfirm(false)}
        />
      )}

      {/* Rebuild Index 确认对话框 */}
      {showRebuildConfirm && (
        <ConfirmDialog
          title="Rebuild Index"
          message="Rebuilding the index for large trace files may take a while. Continue?"
          confirmText="Rebuild"
          cancelText="Cancel"
          minWidth={360}
          onConfirm={() => { setShowRebuildConfirm(false); onRebuildIndex(); }}
          onCancel={() => setShowRebuildConfirm(false)}
        />
      )}

      {/* Clear Cache 确认对话框 */}
      {showClearCacheConfirm && (
        <ConfirmDialog
          title="Clear Cache"
          message="Are you sure you want to clear all cache? This cannot be undone."
          confirmText="Clear"
          cancelText="Cancel"
          confirmColor="var(--reg-changed)"
          minWidth={360}
          onConfirm={async () => { setShowClearCacheConfirm(false); try { await invoke("clear_all_cache"); onClearCache?.(); } catch (e) { console.error("clear cache failed:", e); } }}
          onCancel={() => setShowClearCacheConfirm(false)}
        />
      )}

      {/* Scan Strings 确认对话框 */}
      {showScanStringsConfirm && (
        <ConfirmDialog
            title="Scan Strings"
            message="Scan memory writes to extract strings? This may take a moment for large traces."
            confirmText="Scan"
            cancelText="Cancel"
            minWidth={360}
            onConfirm={() => { setShowScanStringsConfirm(false); onScanStrings(); }}
            onCancel={() => setShowScanStringsConfirm(false)}
        />
      )}

      {/* Scan Crypto 确认对话框 */}
      {showScanCryptoConfirm && (
        <ConfirmDialog
            title="Scan Crypto"
            message="Scan trace for known cryptographic algorithm constants (MD5, SHA, AES, etc.)?"
            confirmText="Scan"
            cancelText="Cancel"
            minWidth={360}
            onConfirm={() => { setShowScanCryptoConfirm(false); onScanCrypto(); }}
            onCancel={() => setShowScanCryptoConfirm(false)}
        />
      )}

      {/* About 对话框 */}
      {showAbout && (
        <ConfirmDialog
          title="Trace UI"
          message={
            <>
              <div style={{ fontSize: 20, fontWeight: 700, color: "var(--text-primary)", marginBottom: 4 }}>
                Trace UI
              </div>
              <div style={{ fontSize: 12, color: "var(--text-secondary)", marginBottom: 16 }}>
                v{appVersion || "..."}
              </div>
              <div style={{ fontSize: 13, color: "var(--text-primary)", marginBottom: 16 }}>
                ARM64 Trace Visual Analyzer
              </div>
              <div style={{ marginBottom: 20 }}>
                <span
                  onClick={() => { openUrl("https://github.com/imj01y/trace-ui").catch(e => console.error("openUrl failed:", e)); }}
                  style={{
                    color: "var(--btn-primary)",
                    fontSize: 13,
                    cursor: "pointer",
                    textDecoration: "none",
                  }}
                  onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.textDecoration = "underline"; }}
                  onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.textDecoration = "none"; }}
                >
                  github.com/imj01y/trace-ui
                </span>
              </div>
            </>
          }
          containerPadding="28px 36px"
          containerStyle={{ textAlign: "center" }}
          onCancel={() => setShowAbout(false)}
        />
      )}

      {/* Preferences 对话框 */}
      {showPrefs && (
        <PreferencesDialog
          preferences={preferences}
          onSave={(prefs) => onUpdatePreferences(prefs)}
          onClose={() => setShowPrefs(false)}
          onClearCache={onClearCache}
        />
      )}
    </>
  );
}
