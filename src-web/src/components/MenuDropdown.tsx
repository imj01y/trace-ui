import { useRef, useEffect, useState, useCallback, type ReactNode } from "react";

// 全局菜单栏状态：追踪当前是否有菜单打开，实现悬停自动切换
let activeMenuSetter: ((open: boolean) => void) | null = null;

// --- MenuItem: 通用菜单项 ---
export function MenuItem({ label, disabled, onClick, shortcut, checked, children }: {
  label?: ReactNode;
  disabled?: boolean;
  onClick?: () => void;
  shortcut?: string;
  checked?: boolean;
  children?: ReactNode;
}) {
  if (children) return <>{children}</>;
  return (
    <div
      onClick={() => { if (!disabled && onClick) onClick(); }}
      onMouseEnter={(e) => { if (!disabled) (e.currentTarget as HTMLElement).style.background = "var(--bg-selected)"; }}
      onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.background = "transparent"; }}
      style={{
        display: "flex", alignItems: "center", padding: "6px 24px 6px 12px", fontSize: 12,
        color: disabled ? "var(--text-secondary)" : "var(--text-primary)",
        cursor: disabled ? "default" : "pointer", whiteSpace: "nowrap",
      }}
    >
      {checked !== undefined && <span style={{ width: 16, flexShrink: 0, fontSize: 11 }}>{checked ? "✓" : ""}</span>}
      <span style={{ flex: 1 }}>{label}</span>
      {shortcut && <span style={{ marginLeft: 24, fontSize: 11, color: "var(--text-secondary)" }}>{shortcut}</span>}
    </div>
  );
}

// --- MenuSeparator ---
export function MenuSeparator() {
  return <div style={{ height: 1, background: "var(--border-color)", margin: "4px 0" }} />;
}

// --- MenuDropdown: 通用下拉菜单容器 ---
export function MenuDropdown({ label, children, minWidth = 200, labelStyle, closeOnSelect = true }: {
  label: string;
  children: ReactNode;
  minWidth?: number;
  labelStyle?: React.CSSProperties;
  closeOnSelect?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [hover, setHover] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  // labelStyle.background 作为默认底色（如 taint 激活时的绿色）
  const baseBackground = (labelStyle?.background as string | undefined) ?? "transparent";

  useEffect(() => {
    if (!open) return;
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [open]);

  // 注册/注销为当前活跃菜单
  useEffect(() => {
    if (open) {
      activeMenuSetter = setOpen;
    } else if (activeMenuSetter === setOpen) {
      activeMenuSetter = null;
    }
  }, [open]);

  const handleMouseEnter = useCallback(() => {
    // 只有当菜单栏已激活（某个菜单已打开）时，悬停才自动切换
    if (activeMenuSetter && activeMenuSetter !== setOpen) {
      activeMenuSetter(false);
      setOpen(true);
    }
  }, []);

  // background 完全由 React state 控制，避免 DOM 直接修改与 React reconciliation 冲突
  const btnBackground = baseBackground !== "transparent"
    ? baseBackground  // 有自定义底色（如绿色）时始终保持
    : (open || hover) ? "var(--bg-input)" : "transparent";

  return (
    <div ref={ref} style={{ position: "relative" }} onMouseEnter={handleMouseEnter}>
      <button
        onClick={() => setOpen(v => !v)}
        onMouseEnter={() => setHover(true)}
        onMouseLeave={() => setHover(false)}
        style={{
          padding: labelStyle?.padding ?? "4px 10px",
          background: btnBackground,
          color: labelStyle?.color ?? "var(--text-primary)",
          border: "none",
          borderRadius: 4,
          cursor: "pointer",
          fontSize: labelStyle?.fontSize ?? "var(--font-size-sm)",
        }}
      >
        {label} ▾
      </button>
      {open && (
        <div
          onClick={closeOnSelect ? () => setOpen(false) : undefined}
          style={{
            position: "absolute", top: "100%", left: 0, marginTop: 2,
            background: "var(--bg-dialog)", border: "1px solid var(--border-color)",
            borderRadius: 6, boxShadow: "0 4px 16px rgba(0,0,0,0.4)",
            zIndex: 1000, minWidth: Math.min(minWidth, window.innerWidth - 40), padding: "4px 0",
          }}
        >
          {children}
        </div>
      )}
    </div>
  );
}
