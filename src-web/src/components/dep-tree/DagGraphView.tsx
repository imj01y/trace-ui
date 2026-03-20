import React, { useState, useRef, useCallback, useMemo, useEffect } from "react";
import { emit } from "@tauri-apps/api/event";
import dagre from "@dagrejs/dagre";
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

interface FlatNode {
  id: string;
  seq: number;
  expression: string;
  operation: string;
  depth: number;
  isLeaf: boolean;
  value: string | null;
}

interface FlatEdge {
  from: string;
  to: string;
}

function flattenTree(
  root: DependencyNode,
  maxDepth: number
): { nodes: FlatNode[]; edges: FlatEdge[] } {
  const nodeMap = new Map<string, FlatNode>();
  const edges: FlatEdge[] = [];

  function walk(node: DependencyNode, depth: number) {
    if (depth > maxDepth) return;
    const id = `seq-${node.seq}`;
    if (!nodeMap.has(id)) {
      nodeMap.set(id, {
        id,
        seq: node.seq,
        expression: node.expression,
        operation: node.operation,
        depth: node.depth,
        isLeaf: node.isLeaf,
        value: node.value,
      });
    }
    for (const child of node.children) {
      if (child.depth <= maxDepth) {
        const childId = `seq-${child.seq}`;
        edges.push({ from: id, to: childId });
        walk(child, depth + 1);
      }
    }
  }

  walk(root, 0);
  return { nodes: Array.from(nodeMap.values()), edges };
}

const NODE_WIDTH = 180;
const NODE_HEIGHT = 40;

interface DagGraphViewProps {
  tree: DependencyNode;
  sessionId: string;
}

export default function DagGraphView({ tree, sessionId }: DagGraphViewProps) {
  const [maxDepth, setMaxDepth] = useState(5);
  const svgRef = useRef<SVGSVGElement>(null);
  const [pan, setPan] = useState({ x: 50, y: 20 });
  const [zoom, setZoom] = useState(1);
  const [dragging, setDragging] = useState(false);
  const dragStart = useRef({ x: 0, y: 0, panX: 0, panY: 0 });

  const { nodes, edges } = useMemo(() => flattenTree(tree, maxDepth), [tree, maxDepth]);

  const layout = useMemo(() => {
    const g = new dagre.graphlib.Graph();
    g.setGraph({ rankdir: "TB", nodesep: 40, ranksep: 60 });
    g.setDefaultEdgeLabel(() => ({}));

    for (const node of nodes) {
      g.setNode(node.id, { width: NODE_WIDTH, height: NODE_HEIGHT });
    }
    for (const edge of edges) {
      // only add edge if both nodes exist
      if (g.hasNode(edge.from) && g.hasNode(edge.to)) {
        g.setEdge(edge.from, edge.to);
      }
    }

    dagre.layout(g);

    const positioned = nodes.map((n) => {
      const pos = g.node(n.id);
      return { ...n, x: pos.x, y: pos.y, w: pos.width, h: pos.height };
    });

    return positioned;
  }, [nodes, edges]);

  const handleNodeClick = useCallback((seq: number) => {
    emit("dep-tree:jump-to-seq", { sessionId, seq });
  }, [sessionId]);

  // Pan handlers
  const handleMouseDown = useCallback((e: React.MouseEvent) => {
    if (e.button !== 0) return;
    // only start drag if clicking on SVG background
    if ((e.target as Element).tagName !== "svg" && !(e.target as Element).closest("line")) {
      // allow node clicks
      return;
    }
    setDragging(true);
    dragStart.current = { x: e.clientX, y: e.clientY, panX: pan.x, panY: pan.y };
  }, [pan]);

  const handleMouseMove = useCallback((e: React.MouseEvent) => {
    if (!dragging) return;
    setPan({
      x: dragStart.current.panX + (e.clientX - dragStart.current.x),
      y: dragStart.current.panY + (e.clientY - dragStart.current.y),
    });
  }, [dragging]);

  const handleMouseUp = useCallback(() => {
    setDragging(false);
  }, []);

  // Zoom handler
  const handleWheel = useCallback((e: React.WheelEvent) => {
    e.preventDefault();
    setZoom(prev => {
      const next = prev * (e.deltaY > 0 ? 0.9 : 1.1);
      return Math.max(0.1, Math.min(3, next));
    });
  }, []);

  // Reset view when tree changes
  useEffect(() => {
    setPan({ x: 50, y: 20 });
    setZoom(1);
  }, [tree]);

  // Deduplicate edges for rendering
  const uniqueEdges = useMemo(() => {
    const seen = new Set<string>();
    return edges.filter((e) => {
      const key = `${e.from}->${e.to}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }, [edges]);

  const nodeMap = useMemo(() => {
    const m = new Map<string, (typeof layout)[0]>();
    for (const n of layout) m.set(n.id, n);
    return m;
  }, [layout]);

  return (
    <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
      {/* Depth slider */}
      <div style={{
        padding: "6px 12px",
        display: "flex",
        alignItems: "center",
        gap: 8,
        fontSize: 11,
        color: "var(--text-secondary)",
        borderBottom: "1px solid var(--border-color)",
        flexShrink: 0,
      }}>
        <span>Max Depth:</span>
        <input
          type="range"
          min={1}
          max={20}
          value={maxDepth}
          onChange={(e) => setMaxDepth(Number(e.target.value))}
          style={{ width: 120 }}
        />
        <span style={{ color: "var(--text-primary)", minWidth: 20 }}>{maxDepth}</span>
        <span style={{ marginLeft: 8 }}>Nodes: {nodes.length}</span>
      </div>

      {/* SVG graph */}
      <svg
        ref={svgRef}
        style={{
          flex: 1,
          cursor: dragging ? "grabbing" : "grab",
          background: "var(--bg-primary, #1e1e2e)",
        }}
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        onMouseLeave={handleMouseUp}
        onWheel={handleWheel}
      >
        <g transform={`translate(${pan.x}, ${pan.y}) scale(${zoom})`}>
          {/* Edges */}
          {uniqueEdges.map((edge, i) => {
            const fromNode = nodeMap.get(edge.from);
            const toNode = nodeMap.get(edge.to);
            if (!fromNode || !toNode) return null;
            return (
              <line
                key={i}
                x1={fromNode.x}
                y1={fromNode.y + fromNode.h / 2}
                x2={toNode.x}
                y2={toNode.y - toNode.h / 2}
                stroke="var(--border-color, #3e4451)"
                strokeWidth={1}
                opacity={0.6}
              />
            );
          })}

          {/* Nodes */}
          {layout.map((node) => {
            const color = getDepthColor(node.depth);
            const rx = node.x - node.w / 2;
            const ry = node.y - node.h / 2;
            // Truncate expression for display
            const label = node.expression.length > 22
              ? node.expression.slice(0, 20) + "..."
              : node.expression;

            return (
              <g
                key={node.id}
                onClick={() => handleNodeClick(node.seq)}
                style={{ cursor: "pointer" }}
              >
                <rect
                  x={rx}
                  y={ry}
                  width={node.w}
                  height={node.h}
                  rx={6}
                  ry={6}
                  fill="var(--bg-secondary, #282c34)"
                  stroke={color}
                  strokeWidth={1.5}
                />
                <text
                  x={node.x}
                  y={node.y - 2}
                  textAnchor="middle"
                  dominantBaseline="auto"
                  fill={color}
                  fontSize={10}
                  fontFamily='"JetBrains Mono", "Fira Code", monospace'
                >
                  {label}
                </text>
                <text
                  x={node.x}
                  y={node.y + 12}
                  textAnchor="middle"
                  dominantBaseline="auto"
                  fill="var(--text-secondary, #5c6370)"
                  fontSize={9}
                  fontFamily='"JetBrains Mono", "Fira Code", monospace'
                >
                  #{node.seq}
                </text>
              </g>
            );
          })}
        </g>
      </svg>
    </div>
  );
}
