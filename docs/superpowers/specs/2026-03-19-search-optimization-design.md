# 搜索交互优化设计

## 概述

优化搜索交互，使其更接近 VSCode 的搜索体验：
1. Ctrl+F 在搜索浮窗未打开时切换到 Search tab 并聚焦搜索框
2. 搜索框采用 VSCode 风格（输入框内嵌 toggle 按钮 + 外部导航/选项按钮）
3. ESC 关闭浮窗时还原到 Search tab

## 1. SearchBar 共享组件

**新文件：** `src-web/src/components/SearchBar.tsx`

### Props 接口

```ts
interface SearchOptions {
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
  matchInfo?: string;           // 如 "3/120"
  inputRef?: React.RefObject<HTMLInputElement>;
}
```

### 内部状态

- `caseSensitive: boolean`（默认 false）
- `wholeWord: boolean`（默认 false）
- `useRegex: boolean`（默认 false）

### 布局

```
┌─────────────────────────────────────┐ ┌──┐┌──┐┌──┐
│ [输入文本]              [Aa][ab][.*]│ │↑ ││↓ ││☰ │
└─────────────────────────────────────┘ └──┘└──┘└──┘
  输入框（含内嵌 toggle）                 外部按钮组
```

### 交互行为

- Enter → 触发 `onSearch`，调用 `onNextMatch`
- Shift+Enter → 调用 `onPrevMatch`
- Toggle 按钮点击 → 切换状态，激活时高亮（VSCode 风格：`rgba(255,255,255,0.1)` 背景 + 底部 accent 色条）
- 选项图标（☰）→ 暂不响应（占位）

### 复用位置

- `TabPanel.tsx` — Search 标签内容顶部
- `FloatingPanel.tsx` — FloatingSearchContent 顶部（替换现有搜索框 + Search 按钮）

## 2. Ctrl+F 行为改动

**文件：** `App.tsx`

### 新逻辑

| 条件 | 行为 |
|------|------|
| 搜索浮窗已打开 | 保持现有行为：置顶浮窗、聚焦输入框 |
| 搜索浮窗未打开 | 发送 `action:activate-search-tab` 切换到 Search tab，发送 `search:focus-input` 聚焦搜索框 |

### TabPanel 改动

- 监听 `action:activate-search-tab` → `setActive("Search")`
- Search 标签顶部新增 `<SearchBar />` 组件

## 3. ESC 还原逻辑

**文件：** `FloatingPanel.tsx`

### 搜索浮窗 ESC 行为

1. `emit("action:activate-search-tab")` — 通知主窗口切换到 Search tab
2. `emit("sync:search-query-back", localQuery)` — 同步搜索文本
3. `getCurrentWindow().close()` — 关闭浮窗

### 数据同步

- 搜索结果：复用现有 `sync:search-results-back` 事件
- 搜索选项：新增 `sync:search-options` 事件同步 toggle 状态（caseSensitive、wholeWord、useRegex），仅浮窗→主窗口方向（ESC 还原时）；浮窗打开时继承主窗口当前 toggle 状态（通过 init-data 传入）

## 4. 后端搜索能力适配

**文件：** `src/commands/search.rs`

### 参数变更

```rust
// 当前
fn search(query: String, max_results: Option<usize>)

// 改为
fn search(query: String, max_results: Option<usize>,
          case_sensitive: Option<bool>,   // 默认 false
          use_regex: Option<bool>)        // 默认 false
```

### 各 toggle 对应的行为

| Toggle | 实现方式 |
|--------|---------|
| caseSensitive | 后端新增参数控制，true 时使用精确大小写匹配 |
| wholeWord | 前端先对 query 做 regex escape，再前后加 `\b`，自动转为 regex 模式 |
| useRegex | 后端新增参数，true 时将 query 作为正则表达式（不再依赖 `/` 包裹语法，但兼容保留） |

### 兼容性

使用 `Option` 类型 + 默认值，TitleBar 搜索框的现有调用不受影响。

## 5. 上下导航按钮

### 选中索引管理

父组件（TabPanel / FloatingSearchContent）维护 `selectedIndex: number`：
- ↓ 按钮 / Enter：`selectedIndex = (selectedIndex + 1) % results.length`
- ↑ 按钮 / Shift+Enter：`selectedIndex = (selectedIndex - 1 + results.length) % results.length`
- 循环到头/尾时自动绕回
- SearchResultList 自动滚动到选中项可见位置
- 搜索结果更新时（重新搜索或 toggle 变化），`selectedIndex` 重置为 0

### matchInfo 显示

- 有结果时：`"3/120"` 格式（当前选中索引 / 总匹配数）
- 无结果时：`"No results"`
- 搜索中时：`"Searching..."`

## 涉及文件清单

| 文件 | 操作 |
|------|------|
| `src-web/src/components/SearchBar.tsx` | 新建 |
| `src-web/src/components/TabPanel.tsx` | 修改（添加 SearchBar、监听事件） |
| `src-web/src/FloatingPanel.tsx` | 修改（替换搜索框、ESC 还原逻辑） |
| `src-web/src/App.tsx` | 修改（Ctrl+F 行为分支） |
| `src/commands/search.rs` | 修改（新增参数） |
