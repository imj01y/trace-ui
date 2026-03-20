import { useState, useCallback } from "react";
import type { ThemeId } from "../theme/themes";

const PREFS_KEY = "trace-ui-preferences";
const SESSION_SNAPSHOT_KEY = "trace-ui-session-snapshot";

export interface Preferences {
  reopenLastFile: boolean;
  showAllHidden: boolean;
  showHiddenIndicators: boolean;
  cacheDir: string; // empty string = use default path
  scanStringsOnBuild: boolean;
  theme: ThemeId;
  confirmTaintRestore: boolean;
  showSoName: boolean;
  showAbsAddress: boolean;
  addrColorHighlight: boolean;
}

export interface TaintConfig {
  fromSpecs: string[];
  startSeq?: number;
  endSeq?: number;
  sourceSeq?: number;
  dataOnly?: boolean;
  filterMode: "highlight" | "filter-only";
}

export interface FileSnapshot {
  filePath: string;
  selectedSeq: number | null;
  taintConfig?: TaintConfig;
}

export interface SessionSnapshot {
  files: FileSnapshot[];
  activeFilePath: string | null;
}

const DEFAULTS: Preferences = {
  reopenLastFile: false,
  showAllHidden: false,
  showHiddenIndicators: true,
  cacheDir: "",
  scanStringsOnBuild: true,
  theme: "dark",
  confirmTaintRestore: true,
  showSoName: false,
  showAbsAddress: false,
  addrColorHighlight: false,
};

function load(): Preferences {
  try {
    const raw = localStorage.getItem(PREFS_KEY);
    if (!raw) return DEFAULTS;
    return { ...DEFAULTS, ...JSON.parse(raw) };
  } catch {
    return DEFAULTS;
  }
}

function save(prefs: Preferences) {
  localStorage.setItem(PREFS_KEY, JSON.stringify(prefs));
}

export function saveSessionSnapshot(snapshot: SessionSnapshot) {
  localStorage.setItem(SESSION_SNAPSHOT_KEY, JSON.stringify(snapshot));
}

export function loadSessionSnapshot(): SessionSnapshot | null {
  try {
    const raw = localStorage.getItem(SESSION_SNAPSHOT_KEY);
    if (!raw) return null;
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

export function usePreferences() {
  const [preferences, setPreferences] = useState<Preferences>(load);

  const updatePreferences = useCallback((updates: Partial<Preferences>) => {
    setPreferences(prev => {
      const next = { ...prev, ...updates };
      save(next);
      return next;
    });
  }, []);

  return { preferences, updatePreferences };
}
