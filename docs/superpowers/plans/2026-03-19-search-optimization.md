# 搜索交互优化实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 将搜索交互优化为 VSCode 风格，支持大小写敏感/全词匹配/正则表达式 toggle，上下导航按钮，Ctrl+F 切换 tab 行为，ESC 还原。

**Architecture:** 抽取共享 SearchBar 组件供 TabPanel 和 FloatingPanel 复用；后端 search_trace 命令新增 case_sensitive/use_regex 参数；Ctrl+F 改为优先切换 Search tab，仅浮窗已打开时聚焦浮窗。

**Tech Stack:** React + TypeScript（前端）、Rust + Tauri（后端）、Tauri Event 系统（跨窗口通信）

---

### Task 1: 后端 search_trace 新增 case_sensitive / use_regex 参数

**Files:**
- Modify: `src/commands/search.rs`

- [ ] **Step 1: 修改 SearchRequest 结构体，新增可选字段**

替换 `src/commands/search.rs` 第 7-11 行的 `SearchRequest`：

```rust
#[derive(Deserialize)]
pub struct SearchRequest {
    pub query: String,
    #[serde(default = "default_max_results")]
    pub max_results: u32,
    #[serde(default)]
    pub case_sensitive: bool,
    #[serde(default)]
    pub use_regex: bool,
}
```

- [ ] **Step 2: 拆分 SearchMode enum + 更新 parse_search_mode + 所有匹配函数**

将 `SearchMode` enum（第 36-40 行）替换为：

```rust
enum SearchMode {
    /// ASCII 大小写不敏感子串搜索（needle 已 lowercase）
    TextInsensitive(Vec<u8>),
    /// 大小写敏感子串搜索
    TextSensitive(Vec<u8>),
    Regex(regex::bytes::Regex),
}
```

将 `parse_search_mode`（第 42-51 行）替换为：

```rust
fn parse_search_mode(query: &str, case_sensitive: bool, use_regex: bool) -> Result<SearchMode, String> {
    // 兼容旧的 /regex/ 语法
    if query.starts_with('/') && query.ends_with('/') && query.len() > 2 {
        let pattern = &query[1..query.len() - 1];
        let re = regex::bytes::Regex::new(pattern)
            .map_err(|e| format!("正则表达式错误: {}", e))?;
        return Ok(SearchMode::Regex(re));
    }

    if use_regex {
        let pattern = if case_sensitive {
            query.to_string()
        } else {
            format!("(?i){}", query)
        };
        let re = regex::bytes::Regex::new(&pattern)
            .map_err(|e| format!("正则表达式错误: {}", e))?;
        Ok(SearchMode::Regex(re))
    } else if case_sensitive {
        Ok(SearchMode::TextSensitive(query.as_bytes().to_vec()))
    } else {
        Ok(SearchMode::TextInsensitive(query.to_lowercase().into_bytes()))
    }
}
```

在 `ascii_contains` 函数（第 55 行）后面新增 `ascii_contains_sensitive`：

```rust
#[inline]
fn ascii_contains_sensitive(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() { return true; }
    if needle.len() > haystack.len() { return false; }
    haystack.windows(needle.len()).any(|window| window == needle)
}
```

将 `matches_line`（第 69-85 行）替换为：

```rust
#[inline]
fn matches_line(mode: &SearchMode, line: &[u8], call_text: Option<&[u8]>) -> bool {
    let line_match = match mode {
        SearchMode::TextInsensitive(needle) => ascii_contains(line, needle),
        SearchMode::TextSensitive(needle) => ascii_contains_sensitive(line, needle),
        SearchMode::Regex(re) => re.is_match(line),
    };
    if line_match {
        return true;
    }
    if let Some(text) = call_text {
        match mode {
            SearchMode::TextInsensitive(needle) => ascii_contains(text, needle),
            SearchMode::TextSensitive(needle) => ascii_contains_sensitive(text, needle),
            SearchMode::Regex(re) => re.is_match(text),
        }
    } else {
        false
    }
}
```

将 `matches_mode_bytes`（第 173-178 行）替换为：

```rust
fn matches_mode_bytes(mode: &SearchMode, text: &[u8]) -> bool {
    match mode {
        SearchMode::TextInsensitive(needle) => ascii_contains(text, needle),
        SearchMode::TextSensitive(needle) => ascii_contains_sensitive(text, needle),
        SearchMode::Regex(re) => re.is_match(text),
    }
}
```

- [ ] **Step 3: 更新 search_trace 中的 parse_search_mode 调用**

将第 225 行的 `let mode = parse_search_mode(&request.query)?;` 替换为：

```rust
let mode = parse_search_mode(&request.query, request.case_sensitive, request.use_regex)?;
```

- [ ] **Step 4: 编译验证**

Run: `cargo build 2>&1 | head -30`
Expected: 编译成功，无错误

- [ ] **Step 5: Commit**

```bash
git add src/commands/search.rs
git commit -m "feat(search): add case_sensitive and use_regex parameters to search_trace"
```

---

### Task 2: 创建 SearchBar 组件

**Files:**
- Create: `src-web/src/components/SearchBar.tsx`

- [ ] **Step 1: 创建 SearchBar 组件文件**

```tsx
import React, { useState, useCallback, useRef } from "react";

export interface SearchOptions {
  caseSensitive: boolean;
  wholeWord: boolean;
  useRegex: boolean;
}

interface SearchBarProps {
  query: string;
  onQueryChange: (q: string) => void;
  onSearch: (query: string, options: SearchOptions) => void;
  onPrevMatch: () => void;
  onNextMatch: () => void;
  matchInfo?: string;
  inputRef?: React.RefObject<HTMLInputElement | null>;
  /** 初始 toggle 状态（浮窗打开时从主窗口继承） */
  initialOptions?: SearchOptions;
  /** toggle 状态变化时回调（用于同步状态） */
  onOptionsChange?: (options: SearchOptions) => void;
}

// VSCode 风格 toggle 按钮
function ToggleButton({
  active, onClick, title, children,
}: {
  active: boolean; onClick: () => void; title: string; children: React.ReactNode;
}) {
  const [hovered, setHovered] = useState(false);
  return (
    <button
      onClick={onClick}
      title={title}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        width: 22, height: 22,
        display: "flex", alignItems: "center", justifyContent: "center",
        background: active ? "rgba(255,255,255,0.12)" : hovered ? "rgba(255,255,255,0.06)" : "transparent",
        color: active ? "var(--text-primary)" : "var(--text-secondary)",
        border: "none", borderRadius: 3, cursor: "pointer",
        padding: 0, position: "relative",
        fontSize: 12, fontFamily: "var(--font-mono)",
      }}
    >
      {children}
      {active && (
        <span style={{
          position: "absolute", bottom: 0, left: 3, right: 3, height: 2,
          background: "var(--btn-primary)", borderRadius: 1,
        }} />
      )}
    </button>
  );
}

// 小型图标按钮（上下导航、选项）
function IconButton({
  onClick, title, disabled, children,
}: {
  onClick: () => void; title: string; disabled?: boolean; children: React.ReactNode;
}) {
  const [hovered, setHovered] = useState(false);
  return (
    <button
      onClick={onClick}
      title={title}
      disabled={disabled}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        width: 22, height: 22,
        display: "flex", alignItems: "center", justifyContent: "center",
        background: hovered && !disabled ? "rgba(255,255,255,0.08)" : "transparent",
        color: disabled ? "var(--text-disabled, #555)" : "var(--text-secondary)",
        border: "none", borderRadius: 3,
        cursor: disabled ? "default" : "pointer", padding: 0,
      }}
    >
      {children}
    </button>
  );
}

export default function SearchBar({
  query, onQueryChange, onSearch, onPrevMatch, onNextMatch, matchInfo,
  inputRef: externalRef, initialOptions, onOptionsChange,
}: SearchBarProps) {
  const [caseSensitive, setCaseSensitive] = useState(initialOptions?.caseSensitive ?? false);
  const [wholeWord, setWholeWord] = useState(initialOptions?.wholeWord ?? false);
  const [useRegex, setUseRegex] = useState(initialOptions?.useRegex ?? false);
  const internalRef = useRef<HTMLInputElement>(null);
  const ref = externalRef || internalRef;

  const getOptions = useCallback((): SearchOptions => ({
    caseSensitive, wholeWord, useRegex,
  }), [caseSensitive, wholeWord, useRegex]);

  // toggle 变化时通知父组件
  const toggleCaseSensitive = useCallback(() => {
    setCaseSensitive(v => {
      const next = !v;
      onOptionsChange?.({ caseSensitive: next, wholeWord, useRegex });
      return next;
    });
  }, [wholeWord, useRegex, onOptionsChange]);

  const toggleWholeWord = useCallback(() => {
    setWholeWord(v => {
      const next = !v;
      onOptionsChange?.({ caseSensitive, wholeWord: next, useRegex });
      return next;
    });
  }, [caseSensitive, useRegex, onOptionsChange]);

  const toggleUseRegex = useCallback(() => {
    setUseRegex(v => {
      const next = !v;
      onOptionsChange?.({ caseSensitive, wholeWord, useRegex: next });
      return next;
    });
  }, [caseSensitive, wholeWord, onOptionsChange]);

  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key === "Enter") {
      e.preventDefault();
      if (e.shiftKey) {
        onPrevMatch();
      } else {
        onSearch(query, getOptions());
        onNextMatch();
      }
    }
  }, [query, onSearch, onPrevMatch, onNextMatch, getOptions]);

  return (
    <div style={{
      display: "flex", gap: 2, padding: "6px 8px",
      borderBottom: "1px solid var(--border-color)", flexShrink: 0,
      alignItems: "center",
    }}>
      {/* 搜索输入框 + 内嵌 toggle */}
      <div style={{
        flex: 1, display: "flex", alignItems: "center",
        background: "var(--bg-input)", border: "1px solid var(--border-color)",
        borderRadius: 3, overflow: "hidden",
      }}>
        <input
          ref={ref}
          type="text"
          placeholder="Search text or /regex/"
          value={query}
          onChange={(e) => onQueryChange(e.target.value)}
          onKeyDown={handleKeyDown}
          style={{
            flex: 1, padding: "3px 8px",
            background: "transparent", color: "var(--text-primary)",
            border: "none", outline: "none",
            fontFamily: "var(--font-mono)", fontSize: "var(--font-size-sm)",
            minWidth: 0,
          }}
        />
        <div style={{ display: "flex", gap: 1, paddingRight: 4, flexShrink: 0 }}>
          <ToggleButton
            active={caseSensitive}
            onClick={toggleCaseSensitive}
            title="Match Case (Alt+C)"
          >
            <span style={{ fontSize: 13, fontFamily: "serif", fontWeight: 600 }}>Aa</span>
          </ToggleButton>
          <ToggleButton
            active={wholeWord}
            onClick={toggleWholeWord}
            title="Match Whole Word (Alt+W)"
          >
            <span style={{
              fontSize: 10, fontWeight: 700,
              border: "1.2px solid currentColor", borderRadius: 2,
              padding: "0 2px", lineHeight: "14px",
            }}>ab</span>
          </ToggleButton>
          <ToggleButton
            active={useRegex}
            onClick={toggleUseRegex}
            title="Use Regular Expression (Alt+R)"
          >
            <span style={{ fontSize: 12 }}>.*</span>
          </ToggleButton>
        </div>
      </div>

      {/* matchInfo 显示 */}
      {matchInfo && (
        <span style={{
          fontSize: 11, color: "var(--text-secondary)",
          whiteSpace: "nowrap", padding: "0 4px", flexShrink: 0,
        }}>
          {matchInfo}
        </span>
      )}

      {/* 上下导航 + 选项 */}
      <div style={{ display: "flex", gap: 1, alignItems: "center", flexShrink: 0 }}>
        <IconButton onClick={onPrevMatch} title="Previous Match (Shift+Enter)">
          <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor">
            <path d="M8 3.5L3 8.5h3v4h4v-4h3L8 3.5z" />
          </svg>
        </IconButton>
        <IconButton onClick={onNextMatch} title="Next Match (Enter)">
          <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor">
            <path d="M8 12.5L13 7.5h-3v-4H6v4H3L8 12.5z" />
          </svg>
        </IconButton>
        <IconButton onClick={() => {}} title="Search Options" disabled>
          <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor">
            <path d="M1 3h14v1H1zm2 3h10v1H3zm2 3h6v1H5zm2 3h2v1H7z" />
          </svg>
        </IconButton>
      </div>
    </div>
  );
}
```

- [ ] **Step 2: 验证编译**

Run: `cd src-web && npx tsc --noEmit 2>&1 | head -20`
Expected: 无错误

- [ ] **Step 3: Commit**

```bash
git add src-web/src/components/SearchBar.tsx
git commit -m "feat(ui): create VSCode-style SearchBar component"
```

---

### Task 3: SearchBar 集成到 TabPanel（Search tab 内新增搜索框）

**Files:**
- Modify: `src-web/src/components/TabPanel.tsx`

- [ ] **Step 1: 更新 imports**

将第 1 行：

```tsx
import React, { useState, useCallback, useEffect, useMemo } from "react";
```

替换为：

```tsx
import React, { useState, useCallback, useEffect, useMemo, useRef } from "react";
```

在 imports 区域新增：

```tsx
import SearchBar, { SearchOptions } from "./SearchBar";
```

- [ ] **Step 2: 更新 Props 接口和组件参数**

在 `Props` 接口（第 20-39 行）中新增：

```tsx
onSearch: (query: string, options: SearchOptions) => void;
```

在组件参数解构（第 42-48 行）中新增 `onSearch`。

- [ ] **Step 3: 添加搜索框内部状态和上下导航逻辑**

在组件内部 `searchBadge` 定义之后（约第 91 行后）添加：

```tsx
const searchInputRef = useRef<HTMLInputElement>(null);
const [localSearchQuery, setLocalSearchQuery] = useState(searchQuery);
const [selectedSearchIdx, setSelectedSearchIdx] = useState(0);
const [searchOptions, setSearchOptions] = useState<SearchOptions>({ caseSensitive: false, wholeWord: false, useRegex: false });

// 同步外部 searchQuery 变化
useEffect(() => { setLocalSearchQuery(searchQuery); }, [searchQuery]);

// 监听浮窗 ESC 还原时同步的 query 和 toggle 状态
useEffect(() => {
  const unlistenQuery = listen<{ query: string }>("sync:search-query-back", (e) => {
    setLocalSearchQuery(e.payload.query);
  });
  const unlistenOptions = listen<SearchOptions>("sync:search-options", (e) => {
    setSearchOptions(e.payload);
  });
  return () => {
    unlistenQuery.then(fn => fn());
    unlistenOptions.then(fn => fn());
  };
}, []);

// 搜索结果变化时重置选中索引
useEffect(() => { setSelectedSearchIdx(0); }, [searchResults]);

// 监听 action:activate-search-tab 事件
useEffect(() => {
  const unlisten = listen("action:activate-search-tab", () => {
    if (!floatedPanels.has("search")) {
      setActive("Search");
    }
  });
  return () => { unlisten.then(fn => fn()); };
}, [floatedPanels]);

// 监听 search:focus-input 事件（Ctrl+F 时聚焦搜索框）
useEffect(() => {
  const unlisten = listen("search:focus-input", () => {
    if (!floatedPanels.has("search")) {
      searchInputRef.current?.focus();
      searchInputRef.current?.select();
    }
  });
  return () => { unlisten.then(fn => fn()); };
}, [floatedPanels]);

const handlePrevMatch = useCallback(() => {
  if (searchResults.length === 0) return;
  setSelectedSearchIdx(prev =>
    (prev - 1 + searchResults.length) % searchResults.length
  );
}, [searchResults.length]);

const handleNextMatch = useCallback(() => {
  if (searchResults.length === 0) return;
  setSelectedSearchIdx(prev =>
    (prev + 1) % searchResults.length
  );
}, [searchResults.length]);

const searchMatchInfo = isSearching
  ? "Searching..."
  : searchResults.length === 0
    ? (searchQuery ? "No results" : "")
    : `${selectedSearchIdx + 1}/${searchTotalMatches.toLocaleString()}`;
```

- [ ] **Step 4: 替换 Search tab 内容区域**

将 TabPanel.tsx 第 155-183 行的 `<div style={tabStyle("Search")}>` 整个块替换为：

```tsx
<div style={tabStyle("Search")}>
  <SearchBar
    query={localSearchQuery}
    onQueryChange={setLocalSearchQuery}
    onSearch={onSearch}
    onPrevMatch={handlePrevMatch}
    onNextMatch={handleNextMatch}
    matchInfo={searchMatchInfo}
    inputRef={searchInputRef}
    initialOptions={searchOptions}
    onOptionsChange={setSearchOptions}
  />
  {isSearching ? (
    <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center" }}>
      <span style={{ color: "var(--text-secondary)", fontSize: 12 }}>Searching...</span>
    </div>
  ) : searchResults.length === 0 ? (
    <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center" }}>
      <span style={{ color: "var(--text-secondary)", fontSize: 12 }}>
        {searchQuery ? `No results found for "${searchQuery}"` : "Enter search query and press Enter"}
      </span>
    </div>
  ) : (
    <>
      <SearchResultList
        results={searchResults}
        selectedSeq={searchResults[selectedSearchIdx]?.seq ?? null}
        onJumpToSeq={onJumpToSeq}
        onJumpToMatch={onJumpToSearchMatch}
      />
      {searchStatus && (
        <div style={{
          padding: "3px 8px", flexShrink: 0,
          borderTop: "1px solid var(--border-color)",
          background: "var(--bg-secondary)",
          fontSize: 11, color: "var(--text-secondary)",
        }}>
          {searchStatus}
        </div>
      )}
    </>
  )}
</div>
```

- [ ] **Step 5: 验证编译**

Run: `cd src-web && npx tsc --noEmit 2>&1 | head -20`
Expected: 可能有 App.tsx 缺少 onSearch prop 的错误（Task 5 修复）

- [ ] **Step 6: Commit**

```bash
git add src-web/src/components/TabPanel.tsx
git commit -m "feat(ui): integrate SearchBar into TabPanel Search tab"
```

---

### Task 4: SearchBar 集成到 FloatingPanel（替换旧搜索框 + ESC 还原）

**Files:**
- Modify: `src-web/src/FloatingPanel.tsx`

- [ ] **Step 1: 新增 import**

在 FloatingPanel.tsx 顶部新增：

```tsx
import SearchBar, { SearchOptions } from "./components/SearchBar";
```

- [ ] **Step 2: 更新 handleSearch 支持 SearchOptions**

替换 FloatingPanel.tsx 中的 `handleSearch` 回调（约第 85 行，`const handleSearch = useCallback(async (query: string) => {`）为：

```tsx
const handleSearch = useCallback(async (query: string, options?: SearchOptions) => {
  if (!syncState.sessionId) return;
  setSearchQuery(query);
  setIsSearching(true);
  setSearchResults([]);
  setSearchTotalMatches(0);
  setSearchStatus("Searching...");
  try {
    // wholeWord 处理：先 escape 再加 \b
    let finalQuery = query;
    let finalUseRegex = options?.useRegex ?? false;
    if (options?.wholeWord && query.trim()) {
      const escaped = finalUseRegex ? query : query.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      finalQuery = `\\b${escaped}\\b`;
      finalUseRegex = true;
    }

    const result = await invoke<SearchResult>("search_trace", {
      sessionId: syncState.sessionId,
      request: {
        query: finalQuery,
        max_results: 10000,
        case_sensitive: options?.caseSensitive ?? false,
        use_regex: finalUseRegex,
      },
    });
    setSearchResults(result.matches);
    setSearchTotalMatches(result.total_matches);
    setSearchStatus(result.total_matches === 0
      ? `No results found for "${query}"`
      : `${result.total_matches.toLocaleString()} results`);
    // 同步结果回主窗口
    emit("sync:search-results-back", {
      results: result.matches,
      query,
      status: result.total_matches === 0
        ? `No results found for "${query}"`
        : `${result.total_matches.toLocaleString()} results`,
      totalMatches: result.total_matches,
    });
  } catch (e) {
    setSearchStatus(`Search failed: ${e}`);
    setSearchResults([]);
  } finally {
    setIsSearching(false);
  }
}, [syncState.sessionId]);
```

- [ ] **Step 3: 更新 action:trigger-search 事件监听**

将第 124 行的事件监听：

```tsx
const unlisten = listen<{ query: string }>("action:trigger-search", (e) => {
  handleSearch(e.payload.query);
});
```

替换为：

```tsx
const unlisten = listen<{ query: string; options?: SearchOptions }>("action:trigger-search", (e) => {
  handleSearch(e.payload.query, e.payload.options);
});
```

- [ ] **Step 4: 修改 ESC 处理逻辑（还原到 Search tab）**

将 FloatingPanel.tsx 第 143-154 行的 ESC handler 替换为：

注意：ESC handler 需要访问 FloatingSearchContent 中的 `localQuery` 和搜索选项。由于 ESC handler 位于 `FloatingPanelContent`（外层组件）中，而 query/options 在 `FloatingSearchContent`（内层）中，需要通过 state 提升或事件来传递。最简洁的方式是将 ESC handler 移入 `FloatingSearchContent` 内部（删除外层的 ESC handler，在 FloatingSearchContent 中添加）。

在 **Step 5 的 FloatingSearchContent** 内部，添加 ESC handler（紧接在 `useEffect` 区域之后）：

```tsx
// ESC 关闭浮窗并同步状态回主窗口
useEffect(() => {
  const handler = async (e: KeyboardEvent) => {
    if (e.key === "Escape") {
      e.preventDefault();
      await emit("action:activate-search-tab");
      await emit("sync:search-query-back", { query: localQuery });
      // 获取当前 toggle 状态（通过 SearchBar 的 onOptionsChange 已同步到 currentOptions ref）
      await emit("sync:search-options", currentOptionsRef.current);
      getCurrentWindow().close();
    }
  };
  window.addEventListener("keydown", handler);
  return () => window.removeEventListener("keydown", handler);
}, [localQuery]);
```

同时在外层 `FloatingPanelContent` 中**删除**原有的 search ESC handler（第 143-154 行）。

在 FloatingSearchContent 中添加 options ref 用于 ESC 同步：

```tsx
const currentOptionsRef = useRef<SearchOptions>({ caseSensitive: false, wholeWord: false, useRegex: false });

const handleOptionsChange = useCallback((opts: SearchOptions) => {
  currentOptionsRef.current = opts;
}, []);
```

并将 `onOptionsChange={handleOptionsChange}` 传递给 SearchBar。
```

- [ ] **Step 5: 重写 FloatingSearchContent 使用 SearchBar**

替换整个 `FloatingSearchContent` 函数（第 231-346 行）为：

```tsx
function FloatingSearchContent({
  searchResults, searchQuery, isSearching, searchStatus, searchTotalMatches,
  onJumpToSeq, onJumpToMatch, onSearch,
}: {
  searchResults: SearchMatch[];
  searchQuery: string;
  isSearching: boolean;
  searchStatus: string;
  searchTotalMatches: number;
  onJumpToSeq: (seq: number) => void;
  onJumpToMatch: (match: SearchMatch) => void;
  onSearch: (query: string, options: SearchOptions) => void;
}) {
  const [localQuery, setLocalQuery] = useState(searchQuery);
  const [selectedIdx, setSelectedIdx] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const currentOptionsRef = useRef<SearchOptions>({ caseSensitive: false, wholeWord: false, useRegex: false });

  const handleOptionsChange = useCallback((opts: SearchOptions) => {
    currentOptionsRef.current = opts;
  }, []);

  useEffect(() => {
    setTimeout(() => inputRef.current?.focus(), 100);
  }, []);

  useEffect(() => {
    const unlisten = listen("search:focus-input", () => {
      inputRef.current?.focus();
      inputRef.current?.select();
    });
    return () => { unlisten.then(fn => fn()); };
  }, []);

  // ESC 关闭浮窗并同步状态回主窗口
  useEffect(() => {
    const handler = async (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        await emit("action:activate-search-tab");
        await emit("sync:search-query-back", { query: localQuery });
        await emit("sync:search-options", currentOptionsRef.current);
        getCurrentWindow().close();
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [localQuery]);

  useEffect(() => { setLocalQuery(searchQuery); }, [searchQuery]);
  useEffect(() => { setSelectedIdx(0); }, [searchResults]);

  const handlePrevMatch = useCallback(() => {
    if (searchResults.length === 0) return;
    setSelectedIdx(prev => (prev - 1 + searchResults.length) % searchResults.length);
  }, [searchResults.length]);

  const handleNextMatch = useCallback(() => {
    if (searchResults.length === 0) return;
    setSelectedIdx(prev => (prev + 1) % searchResults.length);
  }, [searchResults.length]);

  const matchInfo = isSearching
    ? "Searching..."
    : searchResults.length === 0
      ? (searchQuery ? "No results" : "")
      : `${selectedIdx + 1}/${searchTotalMatches.toLocaleString()}`;

  return (
    <div style={{ height: "100%", display: "flex", flexDirection: "column" }}>
      <SearchBar
        query={localQuery}
        onQueryChange={setLocalQuery}
        onSearch={onSearch}
        onPrevMatch={handlePrevMatch}
        onNextMatch={handleNextMatch}
        matchInfo={matchInfo}
        inputRef={inputRef}
        onOptionsChange={handleOptionsChange}
      />

      {isSearching ? (
        <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center" }}>
          <span style={{ color: "var(--text-secondary)", fontSize: 12 }}>Searching...</span>
        </div>
      ) : searchResults.length === 0 ? (
        <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center" }}>
          <span style={{ color: "var(--text-secondary)", fontSize: 12 }}>
            {searchQuery ? `No results found for "${searchQuery}"` : "Enter search query and press Enter"}
          </span>
        </div>
      ) : (
        <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
          <SearchResultList
            results={searchResults}
            selectedSeq={searchResults[selectedIdx]?.seq ?? null}
            onJumpToSeq={onJumpToSeq}
            onJumpToMatch={onJumpToMatch}
          />
        </div>
      )}

      {searchStatus && (
        <div style={{
          padding: "3px 8px", flexShrink: 0,
          borderTop: "1px solid var(--border-color)",
          background: "var(--bg-secondary)",
          fontSize: 11, color: "var(--text-secondary)",
        }}>
          {searchStatus}
        </div>
      )}
    </div>
  );
}
```

- [ ] **Step 6: 更新 FloatingSearchContent 的渲染调用**

找到渲染 `FloatingSearchContent` 的位置，新增 `searchTotalMatches` prop：

```tsx
<FloatingSearchContent
  searchResults={searchResults}
  searchQuery={searchQuery}
  isSearching={isSearching}
  searchStatus={searchStatus}
  searchTotalMatches={searchTotalMatches}
  onJumpToSeq={handleJumpToSeq}
  onJumpToMatch={handleJumpToMatch}
  onSearch={handleSearch}
/>
```

- [ ] **Step 7: 验证编译**

Run: `cd src-web && npx tsc --noEmit 2>&1 | head -20`
Expected: 可能有 App.tsx 相关错误（Task 5 修复）

- [ ] **Step 8: Commit**

```bash
git add src-web/src/FloatingPanel.tsx
git commit -m "feat(ui): integrate SearchBar into FloatingPanel, add ESC restore logic"
```

---

### Task 5: App.tsx Ctrl+F 行为改动 + onSearch/searchTrace 适配

**Files:**
- Modify: `src-web/src/App.tsx`
- Modify: `src-web/src/hooks/useTraceStore.ts`

- [ ] **Step 1: 更新 useTraceStore 的 searchTrace 签名**

修改 `src-web/src/hooks/useTraceStore.ts` 中的 `searchTrace`（约第 300 行），新增参数：

```tsx
const searchTrace = useCallback(async (
  query: string,
  caseSensitive: boolean = false,
  useRegex: boolean = false,
): Promise<number> => {
  const sid = activeSessionIdRef.current;
  if (!sid || !query.trim()) {
    setSearchResults([]);
    setSearchQuery("");
    setSearchStatus("");
    return 0;
  }
  setIsSearching(true);
  setSearchQuery(query);
  setSearchStatus("Searching...");
  try {
    const result = await invoke<SearchResult>("search_trace", {
      sessionId: sid,
      request: { query, max_results: 10000, case_sensitive: caseSensitive, use_regex: useRegex },
    });
    setSearchResults(result.matches);
    setSearchTotalMatches(result.total_matches);
    setSearchStatus(result.total_matches === 0
      ? `No results found for "${query}"`
      : `${result.total_matches.toLocaleString()} results`);
    return result.total_matches;
  } catch (e) {
    setSearchStatus(`Search failed: ${e}`);
    setSearchResults([]);
    return 0;
  } finally {
    setIsSearching(false);
  }
}, []);
```

- [ ] **Step 2: 改造 App.tsx handleSearch 支持 SearchOptions**

在 App.tsx 顶部新增 import：

```tsx
import type { SearchOptions } from "./components/SearchBar";
```

替换 `handleSearch`（约第 540 行）为：

```tsx
const handleSearch = useCallback(async (query: string, options?: SearchOptions) => {
  if (floatedPanels.has("search")) {
    emit("action:trigger-search", { query, options });
  } else {
    // wholeWord 处理：先 escape 再加 \b
    let finalQuery = query;
    let finalUseRegex = options?.useRegex ?? false;
    if (options?.wholeWord && query.trim()) {
      const escaped = finalUseRegex ? query : query.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      finalQuery = `\\b${escaped}\\b`;
      finalUseRegex = true;
    }

    const count = await searchTrace(finalQuery, options?.caseSensitive ?? false, finalUseRegex);
    if (query.trim() && count === 0) {
      showToast(`No results found for "${query}"`, { type: "info" });
    }
  }
}, [searchTrace, floatedPanels, showToast]);
```

- [ ] **Step 3: 修改 Ctrl+F handler**

替换 App.tsx 第 807-841 行的 Ctrl+F 分支 `else` 块（浮窗未打开的情况，第 825-841 行）为：

```tsx
} else {
  // 搜索浮窗未打开 → 切换到 Search tab 并聚焦搜索框
  emit("action:activate-search-tab");
  setTimeout(() => emit("search:focus-input"), 100);
}
```

保留 `if (floatedPanels.has("search"))` 分支不变。

- [ ] **Step 4: 传递 onSearch prop 到 TabPanel**

在 App.tsx 中 TabPanel 的渲染处新增 `onSearch` prop：

```tsx
onSearch={handleSearch}
```

- [ ] **Step 5: 验证编译**

Run: `cd src-web && npx tsc --noEmit 2>&1 | head -20`
Expected: 无错误

- [ ] **Step 6: 全量编译验证**

Run: `cargo build 2>&1 | tail -5`
Expected: 编译成功

- [ ] **Step 7: Commit**

```bash
git add src-web/src/App.tsx src-web/src/hooks/useTraceStore.ts
git commit -m "feat: update Ctrl+F to switch Search tab, wire SearchOptions through stack"
```

---

### Task 6: SearchResultList 自动滚动到选中项

**Files:**
- Modify: `src-web/src/components/SearchResultList.tsx`

- [ ] **Step 1: 在 SearchResultList 中添加自动滚动逻辑**

当 `selectedSeq` 变化时，自动将对应行滚动到可见区域。在 SearchResultList 组件中，找到 `selectedSeq` 的 `useEffect`（约第 106-112 行），替换为：

```tsx
useEffect(() => {
  if (selectedSeq == null) return;
  const idx = seqToIndex.get(selectedSeq);
  if (idx != null) {
    setSelectedIdx(idx);
    // 自动滚动到选中项可见位置
    const container = parentRef.current;
    if (container && rowOffsets[idx] !== undefined) {
      const rowTop = rowOffsets[idx];
      const rowHeight = getRowHeight(results[idx]);
      const scrollTop = container.scrollTop;
      const viewHeight = container.clientHeight;
      if (rowTop < scrollTop) {
        container.scrollTop = rowTop;
      } else if (rowTop + rowHeight > scrollTop + viewHeight) {
        container.scrollTop = rowTop + rowHeight - viewHeight;
      }
    }
  }
}, [selectedSeq, seqToIndex, rowOffsets, results]);
```

- [ ] **Step 2: 验证编译**

Run: `cd src-web && npx tsc --noEmit 2>&1 | head -20`
Expected: 无错误

- [ ] **Step 3: Commit**

```bash
git add src-web/src/components/SearchResultList.tsx
git commit -m "feat(ui): auto-scroll SearchResultList to selected match"
```

---

### Task 7: 端到端验证和清理

**Files:**
- All modified files

- [ ] **Step 1: 全量编译**

Run: `cargo build 2>&1 | tail -10`
Expected: 编译成功

- [ ] **Step 2: 前端类型检查**

Run: `cd src-web && npx tsc --noEmit 2>&1 | head -30`
Expected: 无类型错误

- [ ] **Step 3: 验证无遗留的旧搜索按钮代码**

确认 FloatingSearchContent 中不再有独立的 `<button>Search</button>` 元素。

- [ ] **Step 4: Commit（仅在有清理改动时）**

```bash
git add src-web/src/components/SearchBar.tsx src-web/src/components/TabPanel.tsx src-web/src/FloatingPanel.tsx src-web/src/App.tsx src-web/src/hooks/useTraceStore.ts src-web/src/components/SearchResultList.tsx src/commands/search.rs
git commit -m "chore: cleanup and verify search optimization integration"
```
