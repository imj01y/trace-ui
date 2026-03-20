import { useState, useEffect, useRef, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import TraceTable from "./components/TraceTable";
import FloatingWindowFrame from "./components/FloatingWindowFrame";
import { MenuDropdown, MenuItem, MenuSeparator } from "./components/MenuDropdown";
import { useFoldState } from "./hooks/useFoldState";
import { useLineCache } from "./hooks/useLineCache";
import { usePreferences } from "./hooks/usePreferences";
import type { CallTreeNodeDto, SliceResult } from "./types/trace";

const PAGE_SIZE = 256;

interface Props {
  sessionId: string;
  totalLines: number;
  fileName: string;
  filePath: string;
  initialTaintActive?: boolean;
  initialTaintFilterMode?: "highlight" | "filter-only";
  initialTaintSourceSeq?: number;
}

export default function FloatingSession({
  sessionId, totalLines: initialTotalLines, fileName, filePath,
  initialTaintActive = false, initialTaintFilterMode = "filter-only", initialTaintSourceSeq,
}: Props) {
  const { preferences, updatePreferences } = usePreferences();
  const [totalLines, setTotalLines] = useState(initialTotalLines);
  const [selectedSeq, setSelectedSeq] = useState<number | null>(null);
  const [isPhase2Ready, setIsPhase2Ready] = useState(false);
  const scrollAlignRef = useRef<"center" | "auto" | "end">("center");
  const [scrollTrigger, setScrollTrigger] = useState(0);

  // 行缓存
  const { getLines } = useLineCache(sessionId);

  // CallTree + FoldState
  const LAZY_THRESHOLD = 100_000;
  const [callTreeNodeMap, setCallTreeNodeMap] = useState<Map<number, CallTreeNodeDto>>(new Map());

  // 加载 call tree：初始挂载时尝试加载（检测 phase2 是否已完成），
  // isPhase2Ready 变为 true 时重新加载以获取最新数据
  useEffect(() => {
    if (!sessionId) return;
    invoke<number>("get_call_tree_node_count", { sessionId })
      .then(count => {
        if (count === 0) return;
        if (!isPhase2Ready) setIsPhase2Ready(true);
        if (count <= LAZY_THRESHOLD) {
          return invoke<CallTreeNodeDto[]>("get_call_tree", { sessionId })
            .then(nodes => {
              const map = new Map<number, CallTreeNodeDto>();
              for (const n of nodes) map.set(n.id, n);
              setCallTreeNodeMap(map);
            });
        } else {
          return invoke<CallTreeNodeDto[]>("get_call_tree_children", {
            sessionId, nodeId: 0, includeSelf: true,
          }).then(nodes => {
            const map = new Map<number, CallTreeNodeDto>();
            for (const n of nodes) map.set(n.id, n);
            setCallTreeNodeMap(map);
          });
        }
      })
      .catch(() => {});
  }, [sessionId, isPhase2Ready]);

  const foldState = useFoldState(callTreeNodeMap, totalLines);

  // 监听 index-progress 事件
  useEffect(() => {
    const unlisteners: Promise<() => void>[] = [];
    unlisteners.push(listen<{ sessionId: string; progress: number; done: boolean }>(
      "index-progress", (e) => {
        if (e.payload.sessionId === sessionId && e.payload.done) {
          setIsPhase2Ready(true);
        }
      }
    ));
    return () => { unlisteners.forEach(p => p.then(fn => fn())); };
  }, [sessionId]);

  // === 独立的 Taint 状态管理 ===
  const [sliceActive, setSliceActive] = useState(initialTaintActive);
  const [sliceFilterMode, setSliceFilterMode] = useState<"highlight" | "filter-only">(initialTaintFilterMode);
  const [sliceInfo, setSliceInfo] = useState<SliceResult | null>(null);
  const [taintedSeqs, setTaintedSeqs] = useState<number[]>([]);
  const [sliceSourceSeq] = useState<number | undefined>(initialTaintSourceSeq);
  const sliceCacheRef = useRef<Map<number, boolean[]>>(new Map());

  // 初始化：从后端加载 taint 数据
  useEffect(() => {
    if (!initialTaintActive || !sessionId) return;
    invoke<number[]>("get_tainted_seqs", { sessionId })
      .then(seqs => {
        if (seqs.length > 0) {
          setTaintedSeqs(seqs);
          setSliceActive(true);
          setSliceInfo({
            markedCount: seqs.length,
            totalLines: initialTotalLines,
            percentage: initialTotalLines > 0 ? (seqs.length / initialTotalLines) * 100 : 0,
          });
        }
      })
      .catch(console.error);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sessionId]);

  const getSliceStatus = useCallback(async (startSeq: number, count: number): Promise<boolean[]> => {
    if (!sliceActive) return new Array(count).fill(false);

    const cache = sliceCacheRef.current;
    const startPage = Math.floor(startSeq / PAGE_SIZE);
    const endPage = Math.floor((startSeq + count - 1) / PAGE_SIZE);

    for (let page = startPage; page <= endPage; page++) {
      if (!cache.has(page)) {
        const pageStart = page * PAGE_SIZE;
        const statuses = await invoke<boolean[]>("get_slice_status", {
          sessionId,
          startSeq: pageStart,
          count: PAGE_SIZE,
        });
        cache.set(page, statuses);
      }
    }

    const result: boolean[] = [];
    for (let i = 0; i < count; i++) {
      const seq = startSeq + i;
      const page = Math.floor(seq / PAGE_SIZE);
      const offset = seq % PAGE_SIZE;
      const cached = cache.get(page);
      result.push(cached ? cached[offset] ?? false : false);
    }

    return result;
  }, [sessionId, sliceActive]);

  const handleClearSlice = useCallback(() => {
    // 先同步更新 UI 状态，再 fire-and-forget 发送 IPC（避免写锁饿死卡顿）
    sliceCacheRef.current.clear();
    setSliceActive(false);
    setSliceInfo(null);
    setTaintedSeqs([]);
    invoke("clear_slice", { sessionId }).catch(console.error);
  }, [sessionId]);

  const handleFilterModeChange = useCallback((mode: "highlight" | "filter-only") => {
    setSliceFilterMode(mode);
    if (selectedSeq !== null) {
      requestAnimationFrame(() => {
        scrollAlignRef.current = "auto";
        setScrollTrigger(c => c + 1);
      });
    }
  }, [selectedSeq]);

  const handleGoToSource = useCallback(() => {
    if (sliceSourceSeq !== undefined) {
      foldState.ensureSeqVisible(sliceSourceSeq);
      scrollAlignRef.current = "end";
      setScrollTrigger(c => c + 1);
      setSelectedSeq(sliceSourceSeq);
    }
  }, [sliceSourceSeq, foldState]);

  // === Taint 下拉菜单（标题栏内） ===
  const taintDropdown = sliceActive ? (
    <MenuDropdown label="Taint" minWidth={180} labelStyle={{ background: "rgba(80, 200, 120, 0.25)" }}>
      <MenuItem
        label="Tainted Only"
        checked={sliceFilterMode === "filter-only"}
        onClick={() => handleFilterModeChange("filter-only")}
      />
      <MenuItem
        label="Show All (Dimmed)"
        checked={sliceFilterMode === "highlight"}
        onClick={() => handleFilterModeChange("highlight")}
      />
      <MenuSeparator />
      <MenuItem label="Go to Source" onClick={handleGoToSource} />
      <MenuSeparator />
      <MenuItem label="Clear" onClick={handleClearSlice} />
    </MenuDropdown>
  ) : null;

  const titleNode = (
    <span title={filePath}>
      {fileName} — {totalLines.toLocaleString()} lines
    </span>
  );

  return (
    <FloatingWindowFrame title={titleNode} titleBarExtra={taintDropdown}>
      <div style={{ flex: 1, overflow: "hidden" }}>
        <TraceTable
          totalLines={totalLines}
          isLoaded={totalLines > 0}
          selectedSeq={selectedSeq}
          onSelectSeq={setSelectedSeq}
          getLines={getLines}
          savedScrollSeq={null}
          foldState={foldState}
          sessionId={sessionId}
          scrollAlignRef={scrollAlignRef}
          scrollTrigger={scrollTrigger}
          sliceActive={sliceActive}
          sliceFilterMode={sliceFilterMode}
          taintedSeqs={taintedSeqs}
          sliceSourceSeq={sliceSourceSeq}
          getSliceStatus={getSliceStatus}
          preferences={preferences}
          updatePreferences={updatePreferences}
        />
      </div>

      {/* 状态栏 */}
      <div style={{
        padding: "2px 12px", height: 22, flexShrink: 0,
        background: "var(--bg-secondary)", borderTop: "1px solid var(--border-color)",
        fontSize: 11, color: "var(--text-secondary)",
        display: "flex", alignItems: "center", justifyContent: "space-between",
      }}>
        <span>{totalLines.toLocaleString()} lines</span>
        <span>
          {sliceActive && sliceInfo
            ? `taint: ${sliceInfo.markedCount.toLocaleString()}/${sliceInfo.totalLines.toLocaleString()} (${sliceInfo.percentage.toFixed(1)}%)`
            : ""}
          {selectedSeq !== null ? ` | selected: #${selectedSeq + 1}` : ""}
        </span>
      </div>
    </FloatingWindowFrame>
  );
}
