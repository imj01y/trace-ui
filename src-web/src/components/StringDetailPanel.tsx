import React, { useState, useEffect, useCallback } from "react";
import { emit, listen } from "@tauri-apps/api/event";
import { getCurrentWindow } from "@tauri-apps/api/window";
import type { StringRecordDto } from "../types/trace";

export default function StringDetailPanel() {
  const [record, setRecord] = useState<StringRecordDto | null>(null);

  // 事件方案：先注册数据监听，再发送 ready 信号
  useEffect(() => {
    const unlisten = listen<StringRecordDto>("string-detail:init-data", (e) => {
      setRecord(e.payload);
    });
    const winLabel = getCurrentWindow().label;
    emit(`string-detail:ready:${winLabel}`);
    return () => { unlisten.then(fn => fn()); };
  }, []);
  const [mode, setMode] = useState<"text" | "hex">("hex");
  const [highlight, setHighlight] = useState<Set<number>>(new Set());
  const [selecting, setSelecting] = useState(false);
  const [selStart, setSelStart] = useState<number | null>(null);
  const [selZone, setSelZone] = useState<"hex" | "ascii" | null>(null);

  // 从事件目标解析 data-byte-idx 和 data-zone
  const parseByteTarget = useCallback((e: React.MouseEvent): { idx: number; zone: "hex" | "ascii" } | null => {
    const el = (e.target as HTMLElement).closest<HTMLElement>("[data-byte-idx]");
    if (!el) return null;
    const idx = Number(el.dataset.byteIdx);
    const zone = el.dataset.zone as "hex" | "ascii";
    if (isNaN(idx) || (zone !== "hex" && zone !== "ascii")) return null;
    return { idx, zone };
  }, []);

  // 拖选结束
  useEffect(() => {
    if (!selecting) return;
    const onUp = () => setSelecting(false);
    window.addEventListener("mouseup", onUp);
    return () => window.removeEventListener("mouseup", onUp);
  }, [selecting]);

  // 容器级 mouseDown：开始拖选，始终阻止浏览器原生文本选择
  const handleContainerMouseDown = useCallback((e: React.MouseEvent) => {
    e.preventDefault(); // 始终阻止浏览器原生拖选，防止跨区域选中
    const target = parseByteTarget(e);
    if (!target) return;
    setSelecting(true);
    setSelStart(target.idx);
    setSelZone(target.zone);
    setHighlight(new Set([target.idx]));
  }, [parseByteTarget]);

  // 容器级 mouseMove：拖选过程中更新选区，只响应同区域
  const handleContainerMouseMove = useCallback((e: React.MouseEvent) => {
    if (!selecting || selStart === null) return;
    const target = parseByteTarget(e);
    if (!target || target.zone !== selZone) return;
    const lo = Math.min(selStart, target.idx);
    const hi = Math.max(selStart, target.idx);
    const s = new Set<number>();
    for (let i = lo; i <= hi; i++) s.add(i);
    setHighlight(s);
  }, [selecting, selStart, selZone, parseByteTarget]);

  // Ctrl/Cmd+C 复制选中内容
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "c" && highlight.size > 0 && record) {
        e.preventDefault();
        const enc = new TextEncoder();
        const allBytes = Array.from(enc.encode(record.content));
        const base = parseInt(record.addr, 16) || 0;
        const sorted = Array.from(highlight).sort((a, b) => a - b);
        if (selZone === "hex") {
          const hex = sorted.map(i => allBytes[i - base]?.toString(16).padStart(2, "0").toUpperCase() ?? "").join("");
          navigator.clipboard.writeText(hex);
        } else {
          const text = sorted.map(i => {
            const b = allBytes[i - base];
            return b !== undefined && b >= 0x20 && b <= 0x7E ? String.fromCharCode(b) : ".";
          }).join("");
          navigator.clipboard.writeText(text);
        }
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [highlight, selZone, record]);

  if (!record) {
    return (
      <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center" }}>
        <span style={{ color: "var(--text-secondary)", fontSize: 12 }}>Loading...</span>
      </div>
    );
  }

  const encoder = new TextEncoder();
  const bytes = Array.from(encoder.encode(record.content));
  const baseAddr = parseInt(record.addr, 16) || 0;
  const hexLines: { offset: number; bytes: number[] }[] = [];
  for (let i = 0; i < bytes.length; i += 16) {
    hexLines.push({ offset: baseAddr + i, bytes: bytes.slice(i, i + 16) });
  }

  return (
    <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
      {/* 信息字段 — 紧凑两列布局 */}
      <div style={{
        display: "flex", flexWrap: "wrap", gap: "2px 16px",
        padding: "6px 12px", fontSize: 11, fontFamily: "var(--font-mono)", flexShrink: 0,
        borderBottom: "1px solid var(--border-color)",
      }}>
        {[
          { label: "Addr", value: record.addr },
          { label: "Seq", value: String(record.seq + 1) },
          { label: "Enc", value: record.encoding },
          { label: "Len", value: String(record.byte_len) },
          { label: "XRefs", value: String(record.xref_count) },
        ].map(item => (
          <span key={item.label}>
            <span style={{ color: "var(--text-secondary)" }}>{item.label}: </span>
            <span style={{ color: "var(--text-primary)" }}>{item.value}</span>
          </span>
        ))}
      </div>

      {/* 选项卡 */}
      <div style={{
        display: "flex", flexShrink: 0,
        borderBottom: "1px solid var(--border-color)",
      }}>
        {(["hex", "text"] as const).map(m => (
          <button
            key={m}
            onClick={() => { setMode(m); setHighlight(new Set()); }}
            style={{
              padding: "4px 16px", fontSize: 11, cursor: "pointer",
              background: "transparent",
              color: mode === m ? "var(--text-primary)" : "var(--text-secondary)",
              border: "none",
              borderBottom: mode === m ? "2px solid var(--btn-primary)" : "2px solid transparent",
              fontWeight: mode === m ? 600 : 400,
            }}
          >{m === "text" ? "Text" : "Hex"}</button>
        ))}
        {mode === "hex" && highlight.size > 0 && (
          <span style={{ marginLeft: 8, fontSize: 11, color: "var(--text-secondary)", alignSelf: "center" }}>
            {highlight.size} byte{highlight.size > 1 ? "s" : ""} selected
          </span>
        )}
      </div>

      {/* 内容区 */}
      <div style={{ flex: 1, overflow: "hidden", display: "flex", flexDirection: "column", padding: 12 }}>
        {mode === "text" ? (
          <div style={{
            flex: 1, padding: "8px 10px", background: "var(--bg-secondary)", borderRadius: 4,
            border: "1px solid var(--border-color)", color: "var(--syntax-string)",
            whiteSpace: "pre-wrap", wordBreak: "break-all", overflow: "auto",
            userSelect: "text", lineHeight: 1.5, fontSize: 12, fontFamily: "var(--font-mono)",
          }}>
            {record.content}
          </div>
        ) : (
          <div
            onMouseDown={handleContainerMouseDown}
            onMouseMove={handleContainerMouseMove}
            style={{
              flex: 1, background: "var(--bg-secondary)", borderRadius: 4,
              border: "1px solid var(--border-color)", overflow: "auto",
              fontFamily: "var(--font-mono)", fontSize: 13, lineHeight: "20px",
              userSelect: "none",
            }}
          >
            {/* Hexdump 表头 */}
            <div style={{
              display: "flex", padding: "2px 8px", whiteSpace: "pre",
              borderBottom: "1px solid var(--border-color)",
              color: "var(--text-secondary)", fontWeight: 600,
            }}>
              <span style={{ marginRight: 8 }}>{"Offset  "}</span>
              <span style={{ marginRight: 6 }}>
                {Array.from({ length: 16 }, (_, i) =>
                  i.toString(16).toUpperCase().padStart(2, "0")
                ).reduce<React.ReactNode[]>((acc, s, i) => {
                  if (i > 0) acc.push(<span key={`hs${i}`} style={{ width: i === 8 ? 6 : 2, display: "inline-block" }} />);
                  acc.push(<span key={i} style={{ padding: "0 1px" }}>{s}</span>);
                  return acc;
                }, [])}
              </span>
              <span style={{ marginRight: 6 }}>|</span>
              <span>{"0123456789ABCDEF"}</span>
              <span>|</span>
            </div>
            {hexLines.map(line => (
              <div key={line.offset} style={{ display: "flex", padding: "0 8px", whiteSpace: "pre" }}>
                {/* 偏移 */}
                <span style={{ color: "var(--text-secondary)", marginRight: 8 }}>
                  {line.offset.toString(16).padStart(8, "0")}
                </span>
                {/* Hex 区 */}
                <span style={{ marginRight: 6 }}>
                  {line.bytes.map((b, i) => {
                    const idx = line.offset + i;
                    const hl = highlight.has(idx);
                    return (
                      <span
                        key={i}
                        data-byte-idx={idx}
                        data-zone="hex"
                        style={{
                          cursor: "pointer",
                          padding: "0 1px",
                          background: hl ? (selZone === "hex" ? "var(--bg-selected)" : "rgba(255,200,0,0.25)") : "transparent",
                          borderRadius: hl ? 2 : 0,
                          color: hl ? "var(--text-primary)" : "var(--syntax-number)",
                        }}
                      >{b.toString(16).padStart(2, "0").toUpperCase()}</span>
                    );
                  }).reduce<React.ReactNode[]>((acc, el, i) => {
                    if (i > 0) acc.push(<span key={`s${i}`} style={{ width: i === 8 ? 6 : 2, display: "inline-block" }} />);
                    acc.push(el);
                    return acc;
                  }, [])}
                  {line.bytes.length < 16 && Array.from({ length: 16 - line.bytes.length }, (_, i) => {
                    const pos = line.bytes.length + i;
                    return (
                      <React.Fragment key={`pad${i}`}>
                        {pos > 0 && <span style={{ width: pos === 8 ? 6 : 2, display: "inline-block" }} />}
                        <span style={{ padding: "0 1px", visibility: "hidden" }}>{"00"}</span>
                      </React.Fragment>
                    );
                  })}
                </span>
                {/* 分隔 */}
                <span style={{ color: "var(--border-color)", marginRight: 6 }}>|</span>
                {/* ASCII 区 */}
                <span>
                  {line.bytes.map((b, i) => {
                    const idx = line.offset + i;
                    const hl = highlight.has(idx);
                    const ch = b >= 0x20 && b <= 0x7E ? String.fromCharCode(b) : ".";
                    return (
                      <span
                        key={i}
                        data-byte-idx={idx}
                        data-zone="ascii"
                        style={{
                          cursor: "pointer",
                          background: hl ? (selZone === "ascii" ? "var(--bg-selected)" : "rgba(255,200,0,0.25)") : "transparent",
                          borderRadius: hl ? 2 : 0,
                          color: hl ? "var(--syntax-string)" : (b >= 0x20 && b <= 0x7E ? "var(--text-primary)" : "var(--text-secondary)"),
                        }}
                      >{ch}</span>
                    );
                  })}
                  {line.bytes.length < 16 && (
                    <span style={{ visibility: "hidden" }}>{"X".repeat(16 - line.bytes.length)}</span>
                  )}
                </span>
                <span style={{ color: "var(--border-color)", marginLeft: 6 }}>|</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
