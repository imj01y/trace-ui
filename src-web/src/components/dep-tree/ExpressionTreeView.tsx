import React, { useState, useCallback, useRef, useMemo } from "react";
import { emit } from "@tauri-apps/api/event";
import type { DependencyGraph, NodeInfo } from "../../types/trace";
import { getDepthColor } from "../../utils/depthColors";

const DEFAULT_EXPAND_DEPTH = 4;

interface TreeViewNode {
  node: NodeInfo;
  childSeqs: number[];  // 该节点的子节点 seq 列表
  isFirstExpansion: boolean; // 是否为首次展开（非 ref）
}

/** 从扁平 graph 构建树渲染所需的数据结构 */
function buildTreeIndex(graph: DependencyGraph) {
  // nodeMap: seq → NodeInfo
  const nodeMap = new Map<number, NodeInfo>();
  for (const n of graph.nodes) {
    nodeMap.set(n.seq, n);
  }

  // childrenMap: parent_seq → child_seq[]
  const childrenMap = new Map<number, number[]>();
  for (const [parent, child] of graph.edges) {
    let list = childrenMap.get(parent);
    if (!list) {
      list = [];
      childrenMap.set(parent, list);
    }
    list.push(child);
  }

  return { nodeMap, childrenMap };
}

interface TreeNodeProps {
  seq: number;
  depth: number;
  nodeMap: Map<number, NodeInfo>;
  childrenMap: Map<number, number[]>;
  expandedSet: React.MutableRefObject<Set<number>>; // 追踪哪些 seq 已在树中展开过
  sessionId: string;
  scrollContainer: React.RefObject<HTMLDivElement | null>;
  exprMode: "c" | "asm";
}

function TreeNode({ seq, depth, nodeMap, childrenMap, expandedSet, sessionId, scrollContainer, exprMode }: TreeNodeProps) {
  const node = nodeMap.get(seq);
  const childSeqs = childrenMap.get(seq) || [];

  // isRef 只在挂载时计算一次，避免重渲染时误判
  const [isRef] = useState(() => {
    if (expandedSet.current.has(seq)) return true;
    expandedSet.current.add(seq);
    return false;
  });

  const hasChildren = !isRef && childSeqs.length > 0;
  const [expanded, setExpanded] = useState(depth < DEFAULT_EXPAND_DEPTH);
  const color = getDepthColor(depth);

  const handleToggle = useCallback((e: React.MouseEvent) => {
    e.stopPropagation();
    setExpanded(prev => !prev);
  }, []);

  const handleClick = useCallback(() => {
    if (isRef) {
      // 点击 ref 节点：滚动到首次展开位置
      const container = scrollContainer.current;
      if (!container) return;
      const target = container.querySelector(`[data-expanded-seq="${seq}"]`) as HTMLElement | null;
      if (target) {
        target.scrollIntoView({ behavior: "smooth", block: "center" });
        target.style.background = "rgba(97, 175, 239, 0.25)";
        setTimeout(() => { target.style.background = "transparent"; }, 1500);
      }
    } else {
      emit("dep-tree:jump-to-seq", { sessionId, seq });
    }
  }, [sessionId, seq, isRef, scrollContainer]);

  if (!node) return null;

  const exprText = exprMode === "c" ? node.expression : node.asm;

  return (
    <div style={{ marginLeft: depth > 0 ? 16 : 0 }}>
      <div
        {...(!isRef ? { "data-expanded-seq": String(seq) } : {})}
        onClick={handleClick}
        style={{
          display: "flex",
          alignItems: "center",
          padding: "2px 8px",
          cursor: "pointer",
          borderRadius: 3,
          fontSize: 12,
          fontFamily: '"JetBrains Mono", "Fira Code", monospace',
          gap: 6,
          transition: "background 0.3s",
        }}
        onMouseEnter={(e) => { e.currentTarget.style.background = "var(--bg-hover, rgba(255,255,255,0.05))"; }}
        onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
      >
        {/* Toggle button */}
        <span
          onClick={hasChildren ? handleToggle : undefined}
          style={{
            width: 14,
            flexShrink: 0,
            color: "var(--text-secondary)",
            cursor: hasChildren ? "pointer" : "default",
            userSelect: "none",
            fontSize: 10,
            textAlign: "center",
          }}
        >
          {hasChildren ? (expanded ? "\u25BC" : "\u25B6") : "\u00B7"}
        </span>

        {/* Operation badge */}
        <span style={{ color, fontWeight: 600, flexShrink: 0 }}>
          {node.operation}
        </span>

        {/* Expression */}
        <span style={{
          color: "var(--text-primary, #abb2bf)",
          flex: 1,
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
        }}>
          {exprText}
        </span>

        {/* Ref badge */}
        {isRef && (
          <span style={{
            padding: "0 4px",
            borderRadius: 3,
            background: "rgba(97, 175, 239, 0.15)",
            color: "#61afef",
            fontSize: 10,
            flexShrink: 0,
            cursor: "pointer",
          }}>
            → Go to
          </span>
        )}

        {/* Value badge for leaf nodes */}
        {!isRef && node.isLeaf && node.value != null && (
          <span style={{
            padding: "0 4px",
            borderRadius: 3,
            background: "rgba(152, 195, 121, 0.15)",
            color: "#98c379",
            fontSize: 10,
            flexShrink: 0,
            maxWidth: 120,
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
          }}>
            {node.value}
          </span>
        )}

        {/* Seq number */}
        <span style={{
          color: "var(--text-secondary, #5c6370)",
          fontSize: 10,
          flexShrink: 0,
          minWidth: 40,
          textAlign: "right",
        }}>
          #{seq + 1}
        </span>
      </div>

      {/* Children */}
      {expanded && hasChildren && (
        <div>
          {childSeqs.map((childSeq, i) => (
            <TreeNode
              key={`${childSeq}-${i}`}
              seq={childSeq}
              depth={depth + 1}
              nodeMap={nodeMap}
              childrenMap={childrenMap}
              expandedSet={expandedSet}
              sessionId={sessionId}
              scrollContainer={scrollContainer}
              exprMode={exprMode}
            />
          ))}
        </div>
      )}
    </div>
  );
}

interface ExpressionTreeViewProps {
  graph: DependencyGraph;
  sessionId: string;
  exprMode: "c" | "asm";
}

export default function ExpressionTreeView({ graph, sessionId, exprMode }: ExpressionTreeViewProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const expandedSet = useRef(new Set<number>());

  const { nodeMap, childrenMap } = useMemo(() => {
    expandedSet.current = new Set<number>(); // reset on graph change
    return buildTreeIndex(graph);
  }, [graph]);

  return (
    <div
      ref={containerRef}
      style={{
        flex: 1,
        overflow: "auto",
        padding: "4px 0",
      }}
    >
      <TreeNode
        seq={graph.rootSeq}
        depth={0}
        nodeMap={nodeMap}
        childrenMap={childrenMap}
        expandedSet={expandedSet}
        sessionId={sessionId}
        scrollContainer={containerRef}
        exprMode={exprMode}
      />
    </div>
  );
}
