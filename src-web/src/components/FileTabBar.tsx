import { useCallback } from "react";
import { useDragToFloat } from "../hooks/useDragToFloat";

interface FileTab {
  sessionId: string;
  fileName: string;
  filePath: string;
  isPhase2Ready: boolean;
  traceFormat: string | null;
}

interface Props {
  tabs: FileTab[];
  activeSessionId: string | null;
  onActivate: (sessionId: string) => void;
  onClose: (sessionId: string) => void;
  onFloat: (sessionId: string, position?: { x: number; y: number }) => void;
}

export default function FileTabBar({
  tabs,
  activeSessionId,
  onActivate,
  onClose,
  onFloat,
}: Props) {
  const handleClose = useCallback(
    (e: React.MouseEvent, sessionId: string) => {
      e.stopPropagation();
      onClose(sessionId);
    },
    [onClose],
  );

  const startDrag = useDragToFloat({ onFloat, onActivate });

  if (tabs.length === 0) return null;

  return (
    <div
      style={{
        display: "flex",
        alignItems: "stretch",
        height: 30,
        flexShrink: 0,
        background: "var(--bg-secondary)",
        borderBottom: "1px solid var(--border-color)",
        overflowX: "auto",
        overflowY: "hidden",
        fontSize: "var(--font-size-sm)",
      }}
    >
      {tabs.map((tab) => {
        const isActive = tab.sessionId === activeSessionId;
        return (
          <div
            key={tab.sessionId}
            title={tab.filePath}
            onMouseDown={(e) => {
              if ((e.target as HTMLElement).closest("[data-close-btn]")) return;
              startDrag(tab.sessionId, tab.fileName, e);
            }}
            style={{
              display: "flex",
              alignItems: "center",
              gap: 6,
              padding: "0 12px",
              cursor: "grab",
              whiteSpace: "nowrap",
              background: isActive ? "var(--bg-primary)" : "transparent",
              color: isActive ? "var(--text-primary)" : "var(--text-secondary)",
              borderBottom: isActive
                ? "2px solid var(--btn-primary)"
                : "2px solid transparent",
              userSelect: "none",
            }}
          >
            <span
              style={{
                display: "inline-block",
                width: 7,
                height: 7,
                borderRadius: "50%",
                flexShrink: 0,
                background: tab.isPhase2Ready ? "#4caf50" : "#ff9800",
              }}
            />
            <span
              style={{
                overflow: "hidden",
                textOverflow: "ellipsis",
                maxWidth: 160,
              }}
            >
              {tab.fileName}
            </span>
            {tab.traceFormat && (
              <span
                style={{
                  fontSize: 9,
                  padding: "0 4px",
                  borderRadius: 3,
                  background: "var(--bg-selected)",
                  color: "var(--text-secondary)",
                  flexShrink: 0,
                  lineHeight: "16px",
                  textTransform: "uppercase",
                }}
              >
                {tab.traceFormat}
              </span>
            )}
            <span
              data-close-btn
              onClick={(e) => handleClose(e, tab.sessionId)}
              style={{
                display: "inline-flex",
                alignItems: "center",
                justifyContent: "center",
                width: 16,
                height: 16,
                borderRadius: 3,
                flexShrink: 0,
                fontSize: 12,
                lineHeight: 1,
                color: "var(--text-secondary)",
                cursor: "pointer",
              }}
              onMouseEnter={(e) => {
                (e.currentTarget as HTMLElement).style.background =
                  "var(--bg-selected)";
              }}
              onMouseLeave={(e) => {
                (e.currentTarget as HTMLElement).style.background =
                  "transparent";
              }}
            >
              ×
            </span>
          </div>
        );
      })}
    </div>
  );
}
