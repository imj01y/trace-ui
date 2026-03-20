import React, { useRef, useEffect, useState, useCallback } from "react";
import type { TraceLine } from "../types/trace";
import type { ResolvedRow } from "../hooks/useFoldState";
import { getSharedColors, getMinimapColors } from "../utils/canvasColors";
import { useThemeId } from "../stores/themeStore";

const MINIMAP_WIDTH = 70;
const MINIMAP_ROW_HEIGHT = 2;
const MINIMAP_CHAR_WIDTH = 1.2;
const MINIMAP_COL_START = 4;

// 色块不透明度：token 压暗到远景感，仅暗示代码结构
const MM_TOKEN_ALPHA = 0.35;

// 合并共用颜色和 Minimap 特有颜色——每次调用动态获取当前主题
function getMM_COLORS() {
  const s = getSharedColors();
  const m = getMinimapColors();
  return {
    bg: s.bgPrimary,
    border: s.borderColor,
    mnemonic: s.asmMnemonic,
    register: s.asmRegister,
    address: s.textAddress,
    immediate: s.asmImmediate,
    memory: s.asmMemory,
    changes: s.textChanges,
    text: s.textSecondary,
    ...m,
  };
}
let MM_COLORS = getMM_COLORS();

import { REG_RE, SHIFT_RE, IMM_RE, BRACKET_RE, TOKEN_RE } from "../utils/arm64Tokens";

function mmTokenColor(token: string, isFirst: boolean): string {
  if (isFirst) return MM_COLORS.mnemonic;
  if (BRACKET_RE.test(token)) return MM_COLORS.memory;
  if (IMM_RE.test(token)) return MM_COLORS.immediate;
  if (REG_RE.test(token)) return MM_COLORS.register;
  if (SHIFT_RE.test(token)) return MM_COLORS.changes;
  return MM_COLORS.text;
}

interface MinimapProps {
  virtualTotalRows: number;
  visibleRows: number;
  currentRow: number;
  maxRow: number;
  height: number;
  onScroll: (row: number) => void;
  resolveVirtualIndex: (vi: number) => ResolvedRow;
  getLines: (seqs: number[]) => Promise<TraceLine[]>;
  selectedSeq: number | null;
  rightOffset?: number;
  showSoName: boolean;
  showAbsAddress: boolean;
}

export { MINIMAP_WIDTH };

export default function Minimap({
  virtualTotalRows, visibleRows, currentRow, maxRow, height,
  onScroll, resolveVirtualIndex, getLines, selectedSeq, rightOffset,
  showSoName, showAbsAddress,
}: MinimapProps) {
  const _themeId = useThemeId(); // 触发主题切换时的重绘
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [isDragging, setIsDragging] = useState(false);
  const [isHovered, setIsHovered] = useState(false);
  const minimapLinesRef = useRef<Map<number, TraceLine>>(new Map());
  const dirtyRef = useRef(true);

  const totalMinimapRows = Math.floor(height / MINIMAP_ROW_HEIGHT);
  const viewportHeight = Math.max(10, (visibleRows / Math.max(1, virtualTotalRows)) * height);
  const viewportTop = maxRow > 0 ? (currentRow / maxRow) * (height - viewportHeight) : 0;

  // HiDPI Canvas
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas || height === 0) return;
    const dpr = window.devicePixelRatio || 1;
    canvas.width = MINIMAP_WIDTH * dpr;
    canvas.height = height * dpr;
    canvas.style.width = MINIMAP_WIDTH + "px";
    canvas.style.height = height + "px";
    dirtyRef.current = true;
  }, [height]);

  // 数据采样获取
  useEffect(() => {
    if (virtualTotalRows === 0 || totalMinimapRows === 0) return;
    const seqs: number[] = [];
    const seqSet = new Set<number>();
    for (let i = 0; i < totalMinimapRows; i++) {
      const vi = Math.round(i * virtualTotalRows / totalMinimapRows);
      if (vi >= virtualTotalRows) break;
      const resolved = resolveVirtualIndex(vi);
      if (resolved.type === "line" && !seqSet.has(resolved.seq)) {
        seqSet.add(resolved.seq);
        if (!minimapLinesRef.current.has(resolved.seq)) {
          seqs.push(resolved.seq);
        }
      }
    }
    if (seqs.length === 0) { dirtyRef.current = true; return; }
    const batchSize = 200;
    let idx = 0;
    const fetchNext = () => {
      if (idx >= seqs.length) { dirtyRef.current = true; return; }
      const batch = seqs.slice(idx, idx + batchSize);
      idx += batchSize;
      getLines(batch).then(lines => {
        for (const line of lines) minimapLinesRef.current.set(line.seq, line);
        if (minimapLinesRef.current.size > 5000) {
          const entries = Array.from(minimapLinesRef.current.entries());
          minimapLinesRef.current = new Map(entries.slice(-3000));
        }
        dirtyRef.current = true;
        fetchNext();
      });
    };
    fetchNext();
  }, [virtualTotalRows, totalMinimapRows, resolveVirtualIndex, getLines]);

  // 绘制
  const drawMinimap = useCallback(() => {
    MM_COLORS = getMM_COLORS(); // 刷新当前主题颜色
    const canvas = canvasRef.current;
    if (!canvas || height === 0) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    const dpr = window.devicePixelRatio || 1;
    ctx.save();
    ctx.scale(dpr, dpr);

    ctx.fillStyle = MM_COLORS.bg;
    ctx.fillRect(0, 0, MINIMAP_WIDTH, height);
    ctx.fillStyle = MM_COLORS.border;
    ctx.fillRect(0, 0, 1, height);

    if (virtualTotalRows > 0 && totalMinimapRows > 0) {
      ctx.globalAlpha = MM_TOKEN_ALPHA;
      for (let i = 0; i < totalMinimapRows; i++) {
        const vi = Math.round(i * virtualTotalRows / totalMinimapRows);
        if (vi >= virtualTotalRows) break;
        const resolved = resolveVirtualIndex(vi);
        const y = i * MINIMAP_ROW_HEIGHT;

        if (resolved.type === "summary") {
          ctx.fillStyle = MM_COLORS.summaryBg;
          ctx.fillRect(MINIMAP_COL_START, y, MINIMAP_WIDTH - MINIMAP_COL_START - 4, MINIMAP_ROW_HEIGHT);
          continue;
        }

        if (resolved.type === "hidden-summary") {
          ctx.fillStyle = MM_COLORS.hiddenBg;
          ctx.fillRect(MINIMAP_COL_START, y, MINIMAP_WIDTH - MINIMAP_COL_START - 4, MINIMAP_ROW_HEIGHT);
          continue;
        }

        const seq = resolved.seq;
        if (seq === selectedSeq) {
          // 选中行背景用独立 alpha，不受 token alpha 影响
          ctx.globalAlpha = 1;
          ctx.fillStyle = MM_COLORS.selected;
          ctx.fillRect(0, y, MINIMAP_WIDTH, MINIMAP_ROW_HEIGHT);
          ctx.globalAlpha = MM_TOKEN_ALPHA;
        }

        const line = minimapLinesRef.current.get(seq);
        if (!line) continue;
        let curX = MINIMAP_COL_START;

        if (line.address || line.so_offset) {
          let addrText = line.so_offset || line.address;
          if (showSoName && line.so_name) {
            const prefix = `[${line.so_name}] `;
            const addrPart = (showAbsAddress && line.address)
              ? `${line.address}!${line.so_offset}`
              : line.so_offset;
            addrText = prefix + addrPart;
          }
          ctx.fillStyle = MM_COLORS.address;
          const w = (addrText?.length ?? 0) * MINIMAP_CHAR_WIDTH;
          ctx.fillRect(curX, y, w, MINIMAP_ROW_HEIGHT);
          curX += w + 2;
        }

        if (line.disasm) {
          TOKEN_RE.lastIndex = 0;
          let isFirst = true;
          let match: RegExpExecArray | null;
          while ((match = TOKEN_RE.exec(line.disasm)) !== null) {
            const token = match[0];
            const color = mmTokenColor(token, isFirst);
            const w = token.length * MINIMAP_CHAR_WIDTH;
            ctx.fillStyle = color;
            ctx.fillRect(curX, y, Math.max(1, w), MINIMAP_ROW_HEIGHT);
            curX += w + 0.5;
            isFirst = false;
            if (curX > MINIMAP_WIDTH - 4) break;
          }
        }

        if (line.changes) {
          const remainX = Math.max(curX + 3, MINIMAP_WIDTH * 0.6);
          const w = Math.min(line.changes.length * MINIMAP_CHAR_WIDTH, MINIMAP_WIDTH - remainX - 4);
          if (w > 0) {
            ctx.fillStyle = MM_COLORS.changes;
            ctx.fillRect(remainX, y, w, MINIMAP_ROW_HEIGHT);
          }
        }
      }
      ctx.globalAlpha = 1;
    }

    const vpColor = isDragging ? MM_COLORS.viewportDrag : isHovered ? MM_COLORS.viewportHover : MM_COLORS.viewportBg;
    ctx.fillStyle = vpColor;
    ctx.fillRect(0, viewportTop, MINIMAP_WIDTH, viewportHeight);
    ctx.strokeStyle = MM_COLORS.viewportBorder;
    ctx.lineWidth = 1;
    ctx.strokeRect(0.5, viewportTop + 0.5, MINIMAP_WIDTH - 1, viewportHeight - 1);
    ctx.restore();
  }, [height, virtualTotalRows, totalMinimapRows, resolveVirtualIndex,
      selectedSeq, viewportTop, viewportHeight, isDragging, isHovered, _themeId]);

  useEffect(() => { dirtyRef.current = true; }, [
    currentRow, selectedSeq, height, virtualTotalRows, isDragging, isHovered, _themeId,
  ]);

  useEffect(() => {
    let running = true;
    const loop = () => {
      if (!running) return;
      if (dirtyRef.current) { dirtyRef.current = false; drawMinimap(); }
      requestAnimationFrame(loop);
    };
    requestAnimationFrame(loop);
    return () => { running = false; };
  }, [drawMinimap]);

  const handleMouseDown = useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    setIsDragging(true);
    const canvas = canvasRef.current;
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();

    // 立即跳转到点击位置
    const clickY = e.clientY - rect.top;
    const targetRow = Math.round((clickY / height) * virtualTotalRows - visibleRows / 2);
    onScroll(Math.max(0, Math.min(maxRow, targetRow)));

    const onMove = (ev: MouseEvent) => {
      const y = ev.clientY - rect.top;
      const tr = Math.round((y / height) * virtualTotalRows - visibleRows / 2);
      onScroll(Math.max(0, Math.min(maxRow, tr)));
    };
    const onUp = () => {
      setIsDragging(false);
      document.removeEventListener("mousemove", onMove);
      document.removeEventListener("mouseup", onUp);
    };
    document.addEventListener("mousemove", onMove);
    document.addEventListener("mouseup", onUp);
  }, [height, virtualTotalRows, visibleRows, maxRow, onScroll]);

  if (virtualTotalRows <= visibleRows) return null;

  return (
    <canvas
      ref={canvasRef}
      onMouseDown={handleMouseDown}
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => { if (!isDragging) setIsHovered(false); }}
      style={{
        position: "absolute",
        top: 0,
        right: rightOffset !== undefined ? rightOffset : 12,
        width: MINIMAP_WIDTH,
        height,
        zIndex: 5,
        cursor: "pointer",
      }}
    />
  );
}
