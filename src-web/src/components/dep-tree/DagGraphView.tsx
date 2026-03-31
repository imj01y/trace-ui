import React, { useRef, useCallback, useMemo, useEffect, useState } from "react";
import { emit } from "@tauri-apps/api/event";
import type { DependencyGraph } from "../../types/trace";
import { DEPTH_COLORS } from "../../utils/depthColors";

// ── 常量 ──
const NODE_W = 180;
const NODE_H = 36;
const LAYER_GAP_Y = 80;
const NODE_GAP_X = 24;
const GRID_CELL = 400; // 空间网格单元大小

// ── O(N) 深度分层布局 ──
interface Layout {
  x: Float64Array;
  y: Float64Array;
  totalW: number;
  totalH: number;
}

function computeLayout(graph: DependencyGraph): Layout {
  const n = graph.nodes.length;
  const x = new Float64Array(n);
  const y = new Float64Array(n);

  // ── 1. 按 depth 分组 ──
  const layers = new Map<number, number[]>();
  let maxDepth = 0;
  for (let i = 0; i < n; i++) {
    const d = graph.nodes[i].depth;
    if (d > maxDepth) maxDepth = d;
    let g = layers.get(d);
    if (!g) { g = []; layers.set(d, g); }
    g.push(i);
  }

  // ── 2. 构建邻接表（index → index[]）用于重心计算 ──
  const seqToIdx = new Map<number, number>();
  for (let i = 0; i < n; i++) seqToIdx.set(graph.nodes[i].seq, i);

  const parentOf: number[][] = Array.from({ length: n }, () => []);
  const childOf: number[][] = Array.from({ length: n }, () => []);
  for (const [pSeq, cSeq] of graph.edges) {
    const pi = seqToIdx.get(pSeq);
    const ci = seqToIdx.get(cSeq);
    if (pi !== undefined && ci !== undefined) {
      childOf[pi].push(ci);
      parentOf[ci].push(pi);
    }
  }

  // ── 3. 重心启发式交叉最小化（4 轮前向+反向扫描）──
  function posIndex(layer: number[]): Map<number, number> {
    const m = new Map<number, number>();
    for (let i = 0; i < layer.length; i++) m.set(layer[i], i);
    return m;
  }

  for (let iter = 0; iter < 4; iter++) {
    // 前向：按上层父节点的平均位置排序
    for (let d = 1; d <= maxDepth; d++) {
      const layer = layers.get(d);
      if (!layer || layer.length <= 1) continue;
      const prevIdx = posIndex(layers.get(d - 1) || []);
      const bary: { id: number; val: number }[] = layer.map(idx => {
        const parents = parentOf[idx].filter(p => prevIdx.has(p));
        const val = parents.length === 0
          ? Infinity
          : parents.reduce((s, p) => s + prevIdx.get(p)!, 0) / parents.length;
        return { id: idx, val };
      });
      bary.sort((a, b) => a.val - b.val);
      layers.set(d, bary.map(b => b.id));
    }
    // 反向：按下层子节点的平均位置排序
    for (let d = maxDepth - 1; d >= 0; d--) {
      const layer = layers.get(d);
      if (!layer || layer.length <= 1) continue;
      const nextIdx = posIndex(layers.get(d + 1) || []);
      const bary: { id: number; val: number }[] = layer.map(idx => {
        const children = childOf[idx].filter(c => nextIdx.has(c));
        const val = children.length === 0
          ? Infinity
          : children.reduce((s, c) => s + nextIdx.get(c)!, 0) / children.length;
        return { id: idx, val };
      });
      bary.sort((a, b) => a.val - b.val);
      layers.set(d, bary.map(b => b.id));
    }
  }

  // ── 4. 赋坐标 ──
  let totalW = 0;
  for (let d = 0; d <= maxDepth; d++) {
    const g = layers.get(d);
    if (!g) continue;
    const rowW = g.length * (NODE_W + NODE_GAP_X);
    if (rowW > totalW) totalW = rowW;
    const startX = -(g.length - 1) * (NODE_W + NODE_GAP_X) / 2;
    for (let j = 0; j < g.length; j++) {
      x[g[j]] = startX + j * (NODE_W + NODE_GAP_X);
      y[g[j]] = d * LAYER_GAP_Y;
    }
  }

  return { x, y, totalW: totalW + NODE_W, totalH: (maxDepth + 1) * LAYER_GAP_Y };
}

// ── 空间网格索引 ──
interface Grid {
  cells: Map<number, number[]>;
  offX: number;
  offY: number;
}

function encodeCell(col: number, row: number) { return (col + 500000) * 1000000 + (row + 500000); }

function buildGrid(x: Float64Array, y: Float64Array): Grid {
  let minX = Infinity, minY = Infinity;
  for (let i = 0; i < x.length; i++) {
    if (x[i] < minX) minX = x[i];
    if (y[i] < minY) minY = y[i];
  }
  const offX = minX - NODE_W;
  const offY = minY - NODE_H;
  const cells = new Map<number, number[]>();

  for (let i = 0; i < x.length; i++) {
    const col = Math.floor((x[i] - offX) / GRID_CELL);
    const row = Math.floor((y[i] - offY) / GRID_CELL);
    const key = encodeCell(col, row);
    let list = cells.get(key);
    if (!list) { list = []; cells.set(key, list); }
    list.push(i);
  }

  return { cells, offX, offY };
}

function queryVisible(grid: Grid, vMinX: number, vMinY: number, vMaxX: number, vMaxY: number): number[] {
  const result: number[] = [];
  const c0 = Math.floor((vMinX - grid.offX) / GRID_CELL) - 1;
  const c1 = Math.floor((vMaxX - grid.offX) / GRID_CELL) + 1;
  const r0 = Math.floor((vMinY - grid.offY) / GRID_CELL) - 1;
  const r1 = Math.floor((vMaxY - grid.offY) / GRID_CELL) + 1;
  for (let c = c0; c <= c1; c++) {
    for (let r = r0; r <= r1; r++) {
      const list = grid.cells.get(encodeCell(c, r));
      if (list) for (const idx of list) result.push(idx);
    }
  }
  return result;
}

// ── 邻接表（parent → children indices） ──
function buildAdj(graph: DependencyGraph, seqIdx: Map<number, number>): Map<number, number[]> {
  const adj = new Map<number, number[]>();
  for (const [p, c] of graph.edges) {
    const pi = seqIdx.get(p);
    const ci = seqIdx.get(c);
    if (pi === undefined || ci === undefined) continue;
    let list = adj.get(pi);
    if (!list) { list = []; adj.set(pi, list); }
    list.push(ci);
  }
  return adj;
}

// ── 组件 ──
interface Props {
  graph: DependencyGraph;
  sessionId: string;
  exprMode: "c" | "asm";
}

export default function DagGraphView({ graph, sessionId, exprMode }: Props) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const panRef = useRef({ x: 0, y: 0 });
  const zoomRef = useRef(1);
  const [, forceUpdate] = useState(0);
  const dragRef = useRef({ active: false, startX: 0, startY: 0, panX: 0, panY: 0 });
  const rafRef = useRef(0);
  // 调整 canvas 尺寸（始终使用 Retina 分辨率）
  const resizeCanvas = useCallback(() => {
    const container = containerRef.current;
    const canvas = canvasRef.current;
    if (!container || !canvas) return;
    const dpr = devicePixelRatio;
    canvas.width = container.clientWidth * dpr;
    canvas.height = container.clientHeight * dpr;
    canvas.style.width = container.clientWidth + "px";
    canvas.style.height = container.clientHeight + "px";
  }, []);

  // 预计算
  const layout = useMemo(() => computeLayout(graph), [graph]);
  const grid = useMemo(() => buildGrid(layout.x, layout.y), [layout]);
  const seqIdx = useMemo(() => {
    const m = new Map<number, number>();
    for (let i = 0; i < graph.nodes.length; i++) m.set(graph.nodes[i].seq, i);
    return m;
  }, [graph]);
  const adj = useMemo(() => buildAdj(graph, seqIdx), [graph, seqIdx]);

  // hover 节点索引（-1 表示无 hover）
  const hoverNodeRef = useRef(-1);

  // 子边索引：parentIdx → childIdx → 在该 parent 的出边中的序号
  const childEdgeIdx = useMemo(() => {
    const m = new Map<number, Map<number, number>>();
    for (const [pi, children] of adj) {
      const sorted = [...children].sort((a, b) => layout.x[a] - layout.x[b]);
      const idxMap = new Map<number, number>();
      for (let i = 0; i < sorted.length; i++) idxMap.set(sorted[i], i);
      m.set(pi, idxMap);
    }
    return m;
  }, [adj, layout]);

  // 初始平移：把 root 居中（使用逻辑像素）
  useEffect(() => {
    const rootIdx = seqIdx.get(graph.rootSeq);
    const container = containerRef.current;
    if (rootIdx === undefined || !container) return;
    panRef.current = {
      x: container.clientWidth / 2 - layout.x[rootIdx],
      y: 40 - layout.y[rootIdx],
    };
    zoomRef.current = 1;
    resizeCanvas();
    scheduleDraw();
  }, [graph, layout, seqIdx, resizeCanvas]);

  // resize observer
  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;
    const obs = new ResizeObserver(() => {
      resizeCanvas();
      scheduleDraw();
    });
    obs.observe(container);
    resizeCanvas();
    scheduleDraw();
    return () => obs.disconnect();
  }, [resizeCanvas]);

  // ── 绘制 ──
  const draw = useCallback(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const dpr = devicePixelRatio;
    const cw = canvas.width / dpr;
    const ch = canvas.height / dpr;
    const zoom = zoomRef.current;
    const pan = panRef.current;

    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, cw, ch);

    // 视口 → 图坐标
    const vMinX = -pan.x / zoom - NODE_W;
    const vMinY = -pan.y / zoom - NODE_H;
    const vMaxX = (cw - pan.x) / zoom + NODE_W;
    const vMaxY = (ch - pan.y) / zoom + NODE_H;

    const visible = queryVisible(grid, vMinX, vMinY, vMaxX, vMaxY);
    const visibleSet = new Set(visible);

    ctx.save();
    ctx.translate(pan.x, pan.y);
    ctx.scale(zoom, zoom);

    // LOD 决定：仅根据缩放级别
    const lod = zoom >= 0.4 ? "full" : zoom >= 0.15 ? "simple" : "dot";

    // ── 画边 ──
    const HOVER_COLORS = ["#e06c75", "#98c379"]; // 红 / 绿
    const hv = hoverNodeRef.current;

    if (lod !== "dot" && visible.length < 20000) {
      ctx.lineJoin = "round";
      for (const pi of visible) {
        const children = adj.get(pi);
        if (!children) continue;
        const px = layout.x[pi];
        const py = layout.y[pi] + NODE_H / 2;
        for (const ci of children) {
          if (!visibleSet.has(ci)) continue;
          const cx = layout.x[ci];
          const cy = layout.y[ci] - NODE_H / 2;
          const midY = (py + cy) / 2;

          const isHoverEdge = hv >= 0 && (pi === hv || ci === hv);

          if (hv >= 0) {
            if (isHoverEdge) {
              const edgeOrd = childEdgeIdx.get(pi)?.get(ci) ?? 0;
              ctx.strokeStyle = HOVER_COLORS[edgeOrd % 2];
              ctx.lineWidth = 2.8 / zoom;
            } else {
              ctx.strokeStyle = "rgba(60,65,80,0.12)";
              ctx.lineWidth = 1 / zoom;
            }
          } else {
            ctx.strokeStyle = "rgba(140,145,165,0.35)";
            ctx.lineWidth = 1.6 / zoom;
          }

          ctx.beginPath();
          ctx.moveTo(px, py);
          ctx.lineTo(px, midY);
          ctx.lineTo(cx, midY);
          ctx.lineTo(cx, cy);
          ctx.stroke();

          // 箭头
          if (lod === "full") {
            ctx.fillStyle = ctx.strokeStyle;
            const aw = (isHoverEdge && hv >= 0 ? 5 : 4) / zoom;
            const ah = (isHoverEdge && hv >= 0 ? 8 : 6) / zoom;
            ctx.beginPath();
            ctx.moveTo(cx - aw, cy - ah);
            ctx.lineTo(cx + aw, cy - ah);
            ctx.lineTo(cx, cy);
            ctx.fill();
          }
        }
      }
    }

    // ── 画节点（按颜色分批，减少状态切换） ──
    const nodes = graph.nodes;
    const RENDER_CAP = 10000;
    const toRender = visible.length > RENDER_CAP ? visible.slice(0, RENDER_CAP) : visible;

    // 按 depth 颜色分桶
    const buckets: number[][] = DEPTH_COLORS.map(() => []);
    for (const i of toRender) {
      buckets[nodes[i].depth % DEPTH_COLORS.length].push(i);
    }

    if (lod === "dot") {
      // 极简：彩色圆点，按颜色批量绘制
      for (let c = 0; c < DEPTH_COLORS.length; c++) {
        if (buckets[c].length === 0) continue;
        ctx.fillStyle = DEPTH_COLORS[c];
        for (const i of buckets[c]) {
          ctx.fillRect(layout.x[i] - 2, layout.y[i] - 2, 4, 4);
        }
      }
    } else if (lod === "simple") {
      // 简化：先批量画背景矩形，再按颜色批量画边框和文字
      ctx.fillStyle = "#282c34";
      for (const i of toRender) {
        ctx.fillRect(layout.x[i] - NODE_W / 2, layout.y[i] - NODE_H / 2, NODE_W, NODE_H);
      }
      ctx.lineWidth = 1 / zoom;
      ctx.textAlign = "center";
      ctx.textBaseline = "middle";
      ctx.font = `${Math.max(8, 10 / zoom)}px "JetBrains Mono", monospace`;
      for (let c = 0; c < DEPTH_COLORS.length; c++) {
        if (buckets[c].length === 0) continue;
        ctx.strokeStyle = DEPTH_COLORS[c];
        ctx.fillStyle = DEPTH_COLORS[c];
        for (const i of buckets[c]) {
          ctx.strokeRect(layout.x[i] - NODE_W / 2, layout.y[i] - NODE_H / 2, NODE_W, NODE_H);
          ctx.fillText(nodes[i].operation || `#${nodes[i].seq + 1}`, layout.x[i], layout.y[i], NODE_W - 8);
        }
      }
    } else {
      // 完整：先批量画背景，再按颜色批量画边框+文字
      ctx.font = '10px "JetBrains Mono", monospace';
      ctx.textAlign = "center";
      // 背景
      ctx.fillStyle = "#282c34";
      for (const i of toRender) {
        ctx.beginPath();
        ctx.roundRect(layout.x[i] - NODE_W / 2, layout.y[i] - NODE_H / 2, NODE_W, NODE_H, 6);
        ctx.fill();
      }
      // 边框 + 表达式（按颜色分批）
      ctx.lineWidth = 1.5;
      for (let c = 0; c < DEPTH_COLORS.length; c++) {
        if (buckets[c].length === 0) continue;
        ctx.strokeStyle = DEPTH_COLORS[c];
        ctx.fillStyle = DEPTH_COLORS[c];
        ctx.textBaseline = "bottom";
        for (const i of buckets[c]) {
          if (i === hv) continue;
          ctx.beginPath();
          ctx.roundRect(layout.x[i] - NODE_W / 2, layout.y[i] - NODE_H / 2, NODE_W, NODE_H, 6);
          ctx.stroke();
          const exprText = exprMode === "c" ? nodes[i].expression : nodes[i].asm;
          const label = exprText.length > 22
            ? exprText.slice(0, 20) + "…"
            : exprText;
          ctx.fillText(label, layout.x[i], layout.y[i] + 2, NODE_W - 8);
        }
      }
      // hover 节点：白色边框高亮
      if (hv >= 0 && visibleSet.has(hv)) {
        ctx.fillStyle = "#333848";
        ctx.beginPath();
        ctx.roundRect(layout.x[hv] - NODE_W / 2, layout.y[hv] - NODE_H / 2, NODE_W, NODE_H, 6);
        ctx.fill();
        ctx.strokeStyle = "#ffffff";
        ctx.lineWidth = 2.5;
        ctx.beginPath();
        ctx.roundRect(layout.x[hv] - NODE_W / 2, layout.y[hv] - NODE_H / 2, NODE_W, NODE_H, 6);
        ctx.stroke();
        ctx.fillStyle = "#ffffff";
        ctx.textBaseline = "bottom";
        const exprText = exprMode === "c" ? nodes[hv].expression : nodes[hv].asm;
        const label = exprText.length > 22 ? exprText.slice(0, 20) + "…" : exprText;
        ctx.fillText(label, layout.x[hv], layout.y[hv] + 2, NODE_W - 8);
      }
      // seq 编号（统一灰色）
      ctx.fillStyle = "#5c6370";
      ctx.textBaseline = "top";
      for (const i of toRender) {
        ctx.fillText(`#${nodes[i].seq + 1}`, layout.x[i], layout.y[i] + 2, NODE_W - 8);
      }
    }

    ctx.restore();

    // ── HUD 信息 ──
    ctx.fillStyle = "rgba(30,30,46,0.8)";
    ctx.fillRect(cw - 200, ch - 28, 196, 24);
    ctx.fillStyle = "#888";
    ctx.font = "11px monospace";
    ctx.textAlign = "right";
    ctx.textBaseline = "middle";
    ctx.fillText(
      `visible: ${visible.length} / ${nodes.length}  zoom: ${zoom.toFixed(2)}`,
      cw - 8,
      ch - 16,
    );
  }, [graph, layout, grid, adj, childEdgeIdx, exprMode]);

  const scheduleDraw = useCallback(() => {
    cancelAnimationFrame(rafRef.current);
    rafRef.current = requestAnimationFrame(draw);
  }, [draw]);

  // 数据变化时重绘
  useEffect(() => { scheduleDraw(); }, [draw, scheduleDraw]);

  // ── 交互 ──
  const handleMouseDown = useCallback((e: React.MouseEvent) => {
    if (e.button !== 0) return;
    dragRef.current = {
      active: true,
      startX: e.clientX,
      startY: e.clientY,
      panX: panRef.current.x,
      panY: panRef.current.y,
    };
  }, []);

  const handleMouseMove = useCallback((e: React.MouseEvent) => {
    // 拖拽中：更新平移
    if (dragRef.current.active) {
      panRef.current = {
        x: dragRef.current.panX + (e.clientX - dragRef.current.startX),
        y: dragRef.current.panY + (e.clientY - dragRef.current.startY),
      };
      hoverNodeRef.current = -1;
      scheduleDraw();
      return;
    }

    // 非拖拽：hover 命中检测
    const canvas = canvasRef.current;
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const mx = e.clientX - rect.left;
    const my = e.clientY - rect.top;
    const gx = (mx - panRef.current.x) / zoomRef.current;
    const gy = (my - panRef.current.y) / zoomRef.current;

    let hit = -1;
    const candidates = queryVisible(grid, gx - NODE_W, gy - NODE_H, gx + NODE_W, gy + NODE_H);
    for (const i of candidates) {
      if (gx >= layout.x[i] - NODE_W / 2 && gx <= layout.x[i] + NODE_W / 2 &&
          gy >= layout.y[i] - NODE_H / 2 && gy <= layout.y[i] + NODE_H / 2) {
        hit = i;
        break;
      }
    }

    if (hit !== hoverNodeRef.current) {
      hoverNodeRef.current = hit;
      scheduleDraw();
    }
  }, [scheduleDraw, grid, layout]);

  const handleMouseUp = useCallback(() => {
    dragRef.current.active = false;
    if (hoverNodeRef.current >= 0) {
      hoverNodeRef.current = -1;
      scheduleDraw();
    }
  }, [scheduleDraw]);

  const wheelTimerRef = useRef(0);
  const handleWheel = useCallback((e: React.WheelEvent) => {
    e.preventDefault();
    const canvas = canvasRef.current;
    if (!canvas) return;

    const rect = canvas.getBoundingClientRect();
    const mx = e.clientX - rect.left;
    const my = e.clientY - rect.top;

    const oldZoom = zoomRef.current;
    const factor = e.deltaY > 0 ? 0.9 : 1.1;
    const newZoom = Math.max(0.005, Math.min(5, oldZoom * factor));

    panRef.current = {
      x: mx - (mx - panRef.current.x) * (newZoom / oldZoom),
      y: my - (my - panRef.current.y) * (newZoom / oldZoom),
    };
    zoomRef.current = newZoom;

    // 缩放中：降级 LOD 渲染，停止后 150ms 恢复完整渲染
    dragRef.current.active = true;
    scheduleDraw();
    clearTimeout(wheelTimerRef.current);
    wheelTimerRef.current = window.setTimeout(() => {
      dragRef.current.active = false;
      scheduleDraw();
    }, 150);
  }, [scheduleDraw]);

  // 点击命中检测
  const handleClick = useCallback((e: React.MouseEvent) => {
    if (dragRef.current.active) return;
    const canvas = canvasRef.current;
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const mx = e.clientX - rect.left;
    const my = e.clientY - rect.top;

    // 屏幕坐标 → 图坐标
    const gx = (mx - panRef.current.x) / zoomRef.current;
    const gy = (my - panRef.current.y) / zoomRef.current;

    // 在视口附近查找节点
    const candidates = queryVisible(grid, gx - NODE_W, gy - NODE_H, gx + NODE_W, gy + NODE_H);
    for (const i of candidates) {
      const nx = layout.x[i];
      const ny = layout.y[i];
      if (gx >= nx - NODE_W / 2 && gx <= nx + NODE_W / 2 &&
          gy >= ny - NODE_H / 2 && gy <= ny + NODE_H / 2) {
        emit("dep-tree:jump-to-seq", { sessionId, seq: graph.nodes[i].seq });
        return;
      }
    }
  }, [graph, layout, grid, sessionId]);

  // 检测拖动距离，区分 click 和 drag
  const mouseDownPos = useRef({ x: 0, y: 0 });
  const handleMouseDownWrapped = useCallback((e: React.MouseEvent) => {
    mouseDownPos.current = { x: e.clientX, y: e.clientY };
    handleMouseDown(e);
  }, [handleMouseDown]);

  const handleClickWrapped = useCallback((e: React.MouseEvent) => {
    const dx = e.clientX - mouseDownPos.current.x;
    const dy = e.clientY - mouseDownPos.current.y;
    if (Math.abs(dx) < 3 && Math.abs(dy) < 3) {
      handleClick(e);
    }
  }, [handleClick]);

  return (
    <div
      ref={containerRef}
      style={{
        flex: 1,
        overflow: "hidden",
        cursor: dragRef.current.active ? "grabbing" : "grab",
        position: "relative",
      }}
    >
      <canvas
        ref={canvasRef}
        onMouseDown={handleMouseDownWrapped}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        onMouseLeave={handleMouseUp}
        onWheel={handleWheel}
        onClick={handleClickWrapped}
        style={{ display: "block" }}
      />
      {/* 左上角统计 */}
      <div style={{
        position: "absolute",
        top: 4,
        left: 8,
        fontSize: 10,
        color: "var(--text-secondary, #5c6370)",
        pointerEvents: "none",
      }}>
        {graph.nodes.length.toLocaleString()} nodes / {graph.edges.length.toLocaleString()} edges
      </div>
    </div>
  );
}
