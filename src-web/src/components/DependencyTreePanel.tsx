import { useState, useEffect } from "react";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { useFloatingWindowInit } from "../hooks/useFloatingWindowInit";
import type { DependencyNode } from "../types/trace";
import ExpressionTreeView from "./dep-tree/ExpressionTreeView";
import DagGraphView from "./dep-tree/DagGraphView";

interface DepTreeData {
  tree: DependencyNode;
  sessionId: string;
}

function countNodes(node: DependencyNode, seen = new Set<number>()): number {
  if (seen.has(node.seq)) return 0;
  seen.add(node.seq);
  let count = 1;
  for (const child of node.children) {
    count += countNodes(child, seen);
  }
  return count;
}

type TabKey = "tree" | "dag";

export default function DependencyTreePanel() {
  const data = useFloatingWindowInit<DepTreeData>("dep-tree");
  const [activeTab, setActiveTab] = useState<TabKey>("tree");

  // Esc to close
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        getCurrentWindow().close();
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, []);

  if (!data) {
    return (
      <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center" }}>
        <span style={{ color: "var(--text-secondary)", fontSize: 12 }}>Loading...</span>
      </div>
    );
  }

  const { tree, sessionId } = data;
  const nodeCount = countNodes(tree);

  const tabs: { key: TabKey; label: string }[] = [
    { key: "tree", label: "\u8868\u8FBE\u5F0F\u6811" },
    { key: "dag", label: "\u8BA1\u7B97\u56FE" },
  ];

  return (
    <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
      {/* Tab bar */}
      <div style={{
        display: "flex",
        alignItems: "center",
        borderBottom: "1px solid var(--border-color)",
        flexShrink: 0,
        background: "var(--bg-secondary)",
        padding: "0 8px",
        gap: 0,
      }}>
        {tabs.map((tab) => (
          <button
            key={tab.key}
            onClick={() => setActiveTab(tab.key)}
            style={{
              padding: "6px 14px",
              fontSize: 12,
              fontFamily: '"JetBrains Mono", "Fira Code", monospace',
              background: "transparent",
              border: "none",
              borderBottom: activeTab === tab.key ? "2px solid #61afef" : "2px solid transparent",
              color: activeTab === tab.key ? "var(--text-primary, #abb2bf)" : "var(--text-secondary, #5c6370)",
              cursor: "pointer",
            }}
          >
            {tab.label}
          </button>
        ))}
        <span style={{
          marginLeft: "auto",
          fontSize: 10,
          color: "var(--text-secondary, #5c6370)",
          padding: "0 8px",
        }}>
          {nodeCount} nodes
        </span>
      </div>

      {/* Content */}
      {activeTab === "tree" ? (
        <ExpressionTreeView tree={tree} sessionId={sessionId} />
      ) : (
        <DagGraphView tree={tree} sessionId={sessionId} />
      )}
    </div>
  );
}
