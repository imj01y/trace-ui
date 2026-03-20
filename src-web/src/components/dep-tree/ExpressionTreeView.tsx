import React, { useState, useCallback } from "react";
import { emit } from "@tauri-apps/api/event";
import type { DependencyNode } from "../../types/trace";

const DEPTH_COLORS = [
  "#e06c75", // red (depth 0)
  "#e5c07b", // yellow (depth 1)
  "#98c379", // green (depth 2)
  "#61afef", // blue (depth 3)
  "#c678dd", // purple (depth 4)
  "#abb2bf", // gray (depth 5+)
];

function getDepthColor(depth: number): string {
  return DEPTH_COLORS[Math.min(depth, DEPTH_COLORS.length - 1)];
}

interface TreeNodeProps {
  node: DependencyNode;
  sessionId: string;
  defaultExpandDepth: number;
}

function TreeNode({ node, sessionId, defaultExpandDepth }: TreeNodeProps) {
  const [expanded, setExpanded] = useState(node.depth < defaultExpandDepth);
  const hasChildren = node.children.length > 0;
  const color = getDepthColor(node.depth);

  const handleToggle = useCallback((e: React.MouseEvent) => {
    e.stopPropagation();
    setExpanded(prev => !prev);
  }, []);

  const handleClick = useCallback(() => {
    emit("dep-tree:jump-to-seq", { sessionId, seq: node.seq });
  }, [sessionId, node.seq]);

  return (
    <div style={{ marginLeft: node.depth > 0 ? 16 : 0 }}>
      <div
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
        <span style={{
          color: color,
          fontWeight: 600,
          flexShrink: 0,
        }}>
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
          {node.expression}
        </span>

        {/* Value badge for leaf nodes */}
        {node.isLeaf && node.value != null && (
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
          #{node.seq}
        </span>
      </div>

      {/* Children */}
      {expanded && hasChildren && (
        <div>
          {node.children.map((child, i) => (
            <TreeNode
              key={`${child.seq}-${i}`}
              node={child}
              sessionId={sessionId}
              defaultExpandDepth={defaultExpandDepth}
            />
          ))}
        </div>
      )}
    </div>
  );
}

interface ExpressionTreeViewProps {
  tree: DependencyNode;
  sessionId: string;
}

export default function ExpressionTreeView({ tree, sessionId }: ExpressionTreeViewProps) {
  return (
    <div style={{
      flex: 1,
      overflow: "auto",
      padding: "4px 0",
    }}>
      <TreeNode node={tree} sessionId={sessionId} defaultExpandDepth={4} />
    </div>
  );
}
