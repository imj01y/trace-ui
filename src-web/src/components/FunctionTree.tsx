import { useState, useMemo, useCallback, useRef } from "react";
import { createPortal } from "react-dom";
import { useVirtualScroll } from "../hooks/useVirtualScroll";
import type { CallTreeNodeDto } from "../types/trace";
import ContextMenu, { ContextMenuItem, ContextMenuSeparator } from "./ContextMenu";

interface FlatRow {
  id: number;
  func_addr: string;
  func_name: string | null;
  entry_seq: number;
  line_count: number;
  depth: number;
  hasChildren: boolean;
  isExpanded: boolean;
  isChildrenLoaded: boolean;
}

interface Props {
  isPhase2Ready: boolean;
  onJumpToSeq: (seq: number) => void;
  nodeMap: Map<number, CallTreeNodeDto>;
  nodeCount: number;
  loading: boolean;
  error: string | null;
  lazyMode?: boolean;
  loadedNodes?: Set<number>;
  onLoadChildren?: (nodeId: number) => Promise<void>;
  funcRename: {
    renameMap: Map<string, string>;
    getName: (addr: string) => string | undefined;
    setName: (addr: string, name: string) => void;
    removeName: (addr: string) => void;
  };
}

function formatLineCount(count: number): string {
  if (count >= 1_000_000) return `${(count / 1_000_000).toFixed(1)}M`;
  if (count >= 1_000) return `${(count / 1_000).toFixed(1)}K`;
  return String(count);
}

export default function FunctionTree({
  isPhase2Ready, onJumpToSeq, nodeMap, nodeCount, loading, error,
  lazyMode = false, loadedNodes, onLoadChildren, funcRename,
}: Props) {
  const [expanded, setExpanded] = useState<Set<number>>(new Set([0]));
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [loadingNodes, setLoadingNodes] = useState<Set<number>>(new Set());
  const [ctxMenu, setCtxMenu] = useState<{ x: number; y: number; row: FlatRow } | null>(null);
  const [renameTarget, setRenameTarget] = useState<{ addr: string; currentName: string } | null>(null);
  const renameInputRef = useRef<HTMLInputElement>(null);
  const [tooltip, setTooltip] = useState<{ x: number; y: number; text: string } | null>(null);
  const tooltipTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const rows = useMemo(() => {
    if (nodeMap.size === 0) return [];
    const result: FlatRow[] = [];
    // 使用显式栈替代递归 DFS，避免深调用树导致 Maximum call stack size exceeded
    const stack: { id: number; depth: number }[] = [{ id: 0, depth: 0 }];
    while (stack.length > 0) {
      const { id, depth } = stack.pop()!;
      const dto = nodeMap.get(id);
      if (!dto) continue;
      const hasChildren = dto.children_ids.length > 0;
      const isExp = expanded.has(id);
      const isChildrenLoaded = !lazyMode || (loadedNodes?.has(id) ?? false);
      result.push({
        id: dto.id, func_addr: dto.func_addr, func_name: dto.func_name ?? null,
        entry_seq: dto.entry_seq,
        line_count: dto.exit_seq - dto.entry_seq + 1,
        depth, hasChildren, isExpanded: isExp, isChildrenLoaded,
      });
      if (hasChildren && isExp && isChildrenLoaded) {
        // 逆序入栈以保持遍历顺序（与递归版一致）
        const children = dto.children_ids;
        for (let i = children.length - 1; i >= 0; i--) {
          stack.push({ id: children[i], depth: depth + 1 });
        }
      }
    }
    return result;
  }, [nodeMap, expanded, lazyMode, loadedNodes]);

  const vs = useVirtualScroll({ totalCount: rows.length, rowHeight: 22, overscan: 20 });

  const toggleExpand = useCallback(async (id: number) => {
    if (expanded.has(id)) {
      setExpanded((prev) => {
        const next = new Set(prev);
        next.delete(id);
        return next;
      });
    } else {
      if (lazyMode && onLoadChildren && !(loadedNodes?.has(id))) {
        setLoadingNodes(prev => { const n = new Set(prev); n.add(id); return n; });
        try {
          await onLoadChildren(id);
        } finally {
          setLoadingNodes(prev => { const n = new Set(prev); n.delete(id); return n; });
        }
      }
      setExpanded((prev) => {
        const next = new Set(prev);
        next.add(id);
        return next;
      });
    }
  }, [expanded, lazyMode, onLoadChildren, loadedNodes]);

  const handleClick = useCallback((row: FlatRow) => {
    setSelectedId(row.id);
    if (row.hasChildren) toggleExpand(row.id);
  }, [toggleExpand]);

  const handleDoubleClick = useCallback((row: FlatRow) => {
    onJumpToSeq(row.entry_seq);
  }, [onJumpToSeq]);

  const handleContextMenu = useCallback((e: React.MouseEvent, row: FlatRow) => {
    e.preventDefault();
    e.stopPropagation();
    setCtxMenu({ x: e.clientX, y: e.clientY, row });
  }, []);

  const handleRenameConfirm = useCallback(() => {
    if (!renameTarget) return;
    const val = renameInputRef.current?.value.trim() ?? "";
    if (val) {
      funcRename.setName(renameTarget.addr, val);
    } else {
      funcRename.removeName(renameTarget.addr);
    }
    setRenameTarget(null);
  }, [renameTarget, funcRename]);

  if (!isPhase2Ready) {
    return (
      <div style={{ height: "100%", display: "flex", alignItems: "center", justifyContent: "center", background: "var(--bg-primary)" }}>
        <div style={{ color: "var(--text-secondary)", fontSize: 12 }}></div>
      </div>
    );
  }
  if (loading) {
    return (
      <div style={{ height: "100%", display: "flex", alignItems: "center", justifyContent: "center", background: "var(--bg-primary)" }}>
        <div style={{ color: "var(--text-secondary)", fontSize: 12 }}>Loading function call tree...</div>
      </div>
    );
  }
  if (error) {
    return (
      <div style={{ height: "100%", display: "flex", alignItems: "center", justifyContent: "center", background: "var(--bg-primary)" }}>
        <div style={{ color: "var(--reg-changed)", fontSize: 12 }}>Failed to load: {error}</div>
      </div>
    );
  }

  return (
    <div style={{ height: "100%", display: "flex", flexDirection: "column", background: "var(--bg-primary)" }}>
      <div style={{
        color: "var(--text-secondary)", fontSize: 11,
        padding: "6px 8px 4px", borderBottom: "1px solid var(--border-color)", flexShrink: 0,
      }}>
        Functions ({nodeCount.toLocaleString()})
      </div>
      <div ref={vs.containerRef} style={{ flex: 1, ...vs.containerStyle }}>
        {Array.from({ length: Math.max(0, vs.endIdx - vs.startIdx + 1) }, (_, i) => {
          const index = vs.startIdx + i;
          const row = rows[index];
          if (!row) return null;
          const isNodeLoading = loadingNodes.has(row.id);
          const customName = funcRename.getName(row.func_addr);
          const displayName = customName || row.func_name;
          return (
            <div
              key={row.id}
              onClick={() => handleClick(row)}
              onDoubleClick={() => handleDoubleClick(row)}
              onContextMenu={(e) => handleContextMenu(e, row)}
              style={{
                position: "absolute", top: 0, left: 0, width: "100%", height: 22,
                transform: `translateY(${vs.getItemY(index)}px)`,
                paddingLeft: row.depth * 16 + 4, paddingRight: 8,
                cursor: "pointer", fontSize: 12, lineHeight: "22px",
                whiteSpace: "nowrap",
                background: selectedId === row.id ? "var(--bg-selected)" : "transparent",
                display: "flex", alignItems: "center", gap: 4,
              }}
              onMouseEnter={(e) => { if (selectedId !== row.id) e.currentTarget.style.background = "var(--bg-row-odd)"; }}
              onMouseLeave={(e) => { if (selectedId !== row.id) e.currentTarget.style.background = "transparent"; }}
            >
              <span style={{ width: 12, textAlign: "center", color: "var(--text-secondary)", fontSize: 10, flexShrink: 0 }}>
                {row.hasChildren
                  ? (isNodeLoading ? "\u23F3" : (row.isExpanded && row.isChildrenLoaded ? "\u25BC" : "\u25B6"))
                  : ""}
              </span>
              {displayName
                ? <span
                    style={{ color: "var(--text-primary)", flexShrink: 0 }}
                    onMouseEnter={(e) => {
                      const mx = e.clientX, my = e.clientY;
                      tooltipTimer.current = setTimeout(() => {
                        setTooltip({ x: mx, y: my + 16, text: row.func_addr });
                      }, 100);
                    }}
                    onMouseLeave={() => {
                      if (tooltipTimer.current) { clearTimeout(tooltipTimer.current); tooltipTimer.current = null; }
                      setTooltip(null);
                    }}
                  >{displayName}</span>
                : <span style={{ color: "var(--text-address)", flexShrink: 0 }}>{row.func_addr}</span>
              }
              <span style={{ color: "var(--text-secondary)", fontSize: 11, marginLeft: "auto", flexShrink: 0 }}>
                {formatLineCount(row.line_count)}
              </span>
            </div>
          );
        })}
      </div>

      {tooltip && createPortal(
        <div style={{
          position: "fixed", left: tooltip.x, top: tooltip.y,
          background: "var(--bg-dialog)", color: "var(--text-primary)",
          border: "1px solid var(--border-color)", borderRadius: 4,
          padding: "2px 8px", fontSize: 11, whiteSpace: "nowrap",
          pointerEvents: "none", zIndex: 9999,
          boxShadow: "0 2px 8px rgba(0,0,0,0.3)",
        }}>
          {tooltip.text}
        </div>,
        document.body,
      )}

      {ctxMenu && (
        <ContextMenu x={ctxMenu.x} y={ctxMenu.y} onClose={() => setCtxMenu(null)}>
          <ContextMenuItem
            label="Rename"
            onClick={() => {
              const row = ctxMenu.row;
              setRenameTarget({
                addr: row.func_addr,
                currentName: funcRename.getName(row.func_addr) ?? "",
              });
              setCtxMenu(null);
            }}
          />
          {funcRename.getName(ctxMenu.row.func_addr) && (
            <ContextMenuItem
              label="Restore Original Address"
              onClick={() => {
                funcRename.removeName(ctxMenu.row.func_addr);
                setCtxMenu(null);
              }}
            />
          )}
          <ContextMenuSeparator />
          <ContextMenuItem
            label="Copy Function Address"
            onClick={() => {
              navigator.clipboard.writeText(ctxMenu.row.func_addr);
              setCtxMenu(null);
            }}
          />
          {funcRename.getName(ctxMenu.row.func_addr) && (
            <ContextMenuItem
              label="Copy Function Name"
              onClick={() => {
                const name = funcRename.getName(ctxMenu.row.func_addr);
                if (name) navigator.clipboard.writeText(name);
                setCtxMenu(null);
              }}
            />
          )}
        </ContextMenu>
      )}

      {renameTarget && (
        <div
          style={{
            position: "fixed", top: 0, left: 0, right: 0, bottom: 0,
            background: "rgba(0,0,0,0.4)", zIndex: 10001,
            display: "flex", alignItems: "center", justifyContent: "center",
          }}
          onMouseDown={() => setRenameTarget(null)}
        >
          <div
            onMouseDown={(e) => e.stopPropagation()}
            style={{
              background: "var(--bg-dialog)", border: "1px solid var(--border-color)",
              borderRadius: 8, padding: "16px 20px", minWidth: 300,
              boxShadow: "0 8px 32px rgba(0,0,0,0.5)",
            }}
          >
            <div style={{ color: "var(--text-secondary)", fontSize: 11, marginBottom: 8 }}>
              {renameTarget.addr}
            </div>
            <input
              ref={renameInputRef}
              autoFocus
              defaultValue={renameTarget.currentName}
              placeholder="Enter function name"
              style={{
                width: "100%", padding: "6px 8px", fontSize: 13,
                background: "var(--bg-primary)", color: "var(--text-primary)",
                border: "1px solid var(--border-color)", borderRadius: 4,
                outline: "none", boxSizing: "border-box",
              }}
              onFocus={(e) => e.target.select()}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  handleRenameConfirm();
                } else if (e.key === "Escape") {
                  setRenameTarget(null);
                }
              }}
            />
            <div style={{ display: "flex", justifyContent: "center", gap: 8, marginTop: 12 }}>
              <button
                onMouseDown={(e) => { e.preventDefault(); setRenameTarget(null); }}
                style={{
                  padding: "4px 12px", fontSize: 12, cursor: "pointer",
                  background: "transparent", color: "var(--text-secondary)",
                  border: "1px solid var(--border-color)", borderRadius: 4,
                }}
              >
                Cancel
              </button>
              <button
                onMouseDown={(e) => {
                  e.preventDefault();
                  handleRenameConfirm();
                }}
                style={{
                  padding: "4px 12px", fontSize: 12, cursor: "pointer",
                  background: "var(--btn-primary)", color: "#fff",
                  border: "none", borderRadius: 4,
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
