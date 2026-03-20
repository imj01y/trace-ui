# 函数列表面板设计文档

## 概述

在左侧面板新增"函数列表"Tab，集中展示当前 trace 日志中所有的函数调用（系统调用 + JNI 函数调用），类似 IDA 的函数列表。支持分类筛选、函数名搜索、折叠展开和点击跳转。

## 需求

- 左侧面板新增 Tab，与现有"调用树"（FunctionTree）并列切换
- 默认展示所有函数调用，可筛选为仅系统调用或仅 JNI 调用
- 同名函数合并为一行，显示调用次数，可展开查看每次调用实例
- 每行显示：函数名 + 类型标记（系统调用/JNI）+ 首次出现行号 + 摘要
- 支持按函数名搜索过滤
- 点击具体调用实例跳转到 TraceTable 对应 seq
- 默认按首次出现顺序排列

## 后端设计

### 新增 Tauri 命令 `get_function_calls`

**位置**：新建 `src/commands/functions.rs`（需在 `src/commands/mod.rs` 增加 `pub mod functions;`，在 `src/main.rs` 的 `generate_handler!` 宏中注册命令）

**格式限制**：此功能仅对 **gumtrace 格式**的 trace 文件有效。Unidbg 格式的 `call_annotations` 始终为空，前端需优雅降级（显示空状态提示或隐藏 Tab）。

**数据源**：`SessionState.call_annotations: HashMap<u32, CallAnnotation>`

**DTO 定义**：

```rust
#[derive(serde::Serialize)]
pub struct FunctionCallOccurrence {
    pub seq: u32,
    pub summary: String,  // 来自 CallAnnotation::summary()，含函数名前缀，前端展示子项时需截取避免重复
}

#[derive(serde::Serialize)]
pub struct FunctionCallEntry {
    pub func_name: String,
    pub is_jni: bool,
    pub occurrences: Vec<FunctionCallOccurrence>,
}

#[derive(serde::Serialize)]
pub struct FunctionCallsResult {
    pub functions: Vec<FunctionCallEntry>,
    pub total_calls: usize,
}
```

**聚合逻辑**：

1. 遍历 `call_annotations`，按 `func_name` 分组
2. 每组内的 `occurrences` 按 `seq` 升序排列
3. 组与组之间按各组最小 `seq` 升序排列（首次出现顺序）
4. `total_calls` = 所有 occurrences 的总数

**命令签名**：

```rust
#[tauri::command]
pub fn get_function_calls(
    session_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<FunctionCallsResult, String>
```

## 前端设计

### 新增 TypeScript 类型

**位置**：`src-web/src/types/trace.ts`

```typescript
export interface FunctionCallOccurrence {
  seq: number;
  summary: string;
}

export interface FunctionCallEntry {
  func_name: string;
  is_jni: boolean;
  occurrences: FunctionCallOccurrence[];
}

export interface FunctionCallsResult {
  functions: FunctionCallEntry[];
  total_calls: number;
}
```

### 新增组件 `FunctionListPanel`

**位置**：`src-web/src/components/FunctionListPanel.tsx`

**布局**：

```
┌─────────────────────────────────┐
│ [🔍 搜索函数名...]              │  搜索框
│ [全部] [系统调用] [JNI]         │  筛选按钮组
├─────────────────────────────────┤
│ ▶ strlen (3次调用)              │  折叠行
│ ▼ Java_com_xxx_func (2次调用)   │  展开状态
│   ├ #1024 func("abc") → 0x3    │  子项（点击跳转）
│   └ #2048 func("def") → 0x3    │  子项（点击跳转）
│ ▶ malloc (15次调用)             │
│ ...                             │
├─────────────────────────────────┤
│ 共 20 个函数，42 次调用          │  状态栏
└─────────────────────────────────┘
```

**Props**：

```typescript
interface Props {
  sessionId: string | null;
  onJumpToSeq: (seq: number) => void;
  isGumtraceFormat: boolean;  // 控制是否显示内容，Unidbg 格式下显示空状态
}
```

**状态管理**：

- `data: FunctionCallsResult | null` — 后端返回的原始数据
- `filter: "all" | "syscall" | "jni"` — 当前筛选类型
- `search: string` — 搜索关键词
- `expanded: Set<string>` — 已展开的函数名集合

**数据获取**：

- `sessionId` 变化时调用 `invoke("get_function_calls", { sessionId })`
- 结果缓存在组件内部 state

**过滤逻辑**（前端本地执行）：

1. 先按 `filter` 过滤 `is_jni` 字段
2. 再按 `search` 关键词过滤 `func_name`（大小写不敏感）

**虚拟滚动**：

使用现有 `useVirtualizerNoSync` hook，将折叠/展开后的行扁平化为虚拟列表。

### 左侧面板 Tab 集成

**位置**：`src-web/src/App.tsx`

在左侧面板内部垂直分组的**上半区 Panel**（`App.tsx:941` 的 `<Panel defaultSize={65} minSize={20}>`，即 FunctionTree 所在位置）内部加 Tab 容器：

```tsx
{/* 这是左侧面板内部上半区的 Panel，不是最外层的左侧 Panel */}
<Panel defaultSize={65} minSize={20}>
  <div style={{ height: "100%", display: "flex", flexDirection: "column" }}>
    <div className="left-tab-bar">
      <button className={leftTab === "tree" ? "active" : ""} onClick={() => setLeftTab("tree")}>
        调用树
      </button>
      <button className={leftTab === "list" ? "active" : ""} onClick={() => setLeftTab("list")}>
        函数列表
      </button>
    </div>
    <div style={{ flex: 1, overflow: "hidden" }}>
      {leftTab === "tree" ? <FunctionTree ... /> : <FunctionListPanel ... />}
    </div>
  </div>
</Panel>
```

Tab 状态：`const [leftTab, setLeftTab] = useState<"tree" | "list">("tree")`，管理在 App 组件中。

Tab 栏样式参考 `FileTabBar` 的视觉风格，紧凑设计，不占用过多垂直空间。

## 数据流

```
用户打开文件
  → scan_unified 解析 trace，构建 call_annotations
  → 用户切换到"函数列表" Tab
  → 前端 invoke("get_function_calls", { sessionId })
  → 后端从 call_annotations 聚合数据返回
  → FunctionListPanel 渲染列表
  → 用户搜索/筛选 → 前端本地过滤
  → 用户点击子调用项 → onJumpToSeq(seq) → TraceTable 定位
```

## 不做的事情

- 不做实时增量更新（数据在文件加载时一次性构建完毕）
- 不做排序切换功能（固定首次出现顺序）
- 不弹出 CallInfo 浮动窗口（点击只跳转）
- 不新增 Zustand store（组件内部 state 足够）
