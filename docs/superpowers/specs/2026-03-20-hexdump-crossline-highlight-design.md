# Hexdump 跨行搜索高亮设计

## 概述

在搜索结果的 hidden_content（tooltip/hexdump 区域）中，支持 hex 和 ASCII 的跨行匹配与跨行高亮。同时支持三种搜索格式：带空格 hex、无空格紧凑 hex、ASCII 文本。

## 1. 搜索 query 格式支持

| 输入格式 | 示例 | 检测规则 | 归一化处理 |
|---------|------|---------|-----------|
| 带空格 hex | `"da 48 7d 00 00 00 29"` | 匹配 `/^[0-9a-f]{2}( [0-9a-f]{2})+$/i` | 直接在 hex 流中匹配 |
| 无空格紧凑 hex | `"da487d00000029"` | 全部 `[0-9a-fA-F]`，偶数长度，≥4 字符 | 插入空格归一化为 `"da 48 7d 00 00 00 29"` 后在 hex 流中匹配 |
| ASCII 文本 | `"HttpRequest"` | 不满足以上两种 | 在 ASCII 流中匹配；非 hexdump 行走普通 `highlightText` |

## 2. 后端改动

**文件：** `src/taint/gumtrace_parser.rs`

### searchable_text() 追加无空格 hex

在 `searchable_text()` 方法中，除了现有的带空格 hex 字符串外，额外追加一行无空格版本：

```rust
pub fn searchable_text(&self) -> String {
    let mut text = format!("{}\n{}", self.summary(), self.tooltip());
    let (hex_str, raw_bytes) = self.merged_hexdump();
    if !hex_str.is_empty() {
        text.push('\n');
        text.push_str(&hex_str);          // 带空格: "da 48 7d ..."
        text.push('\n');
        text.push_str(&hex_str.replace(" ", "")); // 无空格: "da487d..."
        let ascii: String = raw_bytes.iter().map(|&b| {
            if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' }
        }).collect();
        text.push('\n');
        text.push_str(&ascii);
    }
    text
}
```

这样后端搜索 `"da487d00000029"`（紧凑）和 `"da 48 7d 00 00 00 29"`（带空格）都能命中。

## 3. 前端 highlightHexdump 函数

**文件：** `src-web/src/utils/highlightText.tsx`

### 签名

```ts
export function highlightHexdump(
  text: string,           // hidden_content 原始文本（含换行、多行 hexdump）
  query: string,          // 搜索关键词
  caseSensitive: boolean, // 大小写敏感
  fuzzy: boolean,         // 模糊匹配
): React.ReactNode
```

### 算法

**Step 1: 按行拆分，分类识别**

将 `text` 按 `\n` 拆分。hexdump 数据行匹配正则 `/^[0-9a-fA-F]+:\s/`（地址 + 冒号 + 空格）。非 hexdump 行单独记录。

**Step 2: 提取两条连续流 + 位置映射**

遍历所有 hexdump 数据行：
- **hex 流**：提取冒号后到 `|` 之前的 hex 字节，拼成连续带空格字符串。同时建立 `byteIndex → { lineIndex, hexCharStart, hexCharEnd }` 映射（每个字节在原始行中的字符位置）。
- **ASCII 流**：提取 `|...|` 内的字符拼接。同时建立 `charIndex → { lineIndex, asciiCharPos }` 映射。

**Step 3: 判断 query 类型并匹配**

```
isSpacedHex = /^[0-9a-f]{2}( [0-9a-f]{2})+$/i.test(query)
isCompactHex = /^[0-9a-fA-F]{4,}$/.test(query) && query.length % 2 === 0
```

- `isSpacedHex` → 直接在 hex 流中匹配 query
- `isCompactHex` → 归一化为带空格形式（每 2 字符插空格），在 hex 流中匹配
- 其他 → 在 ASCII 流中匹配 query

匹配得到：命中的字节范围列表（如字节 10-16）。

**Step 4: 映射回原始行**

根据 Step 2 的映射表，将字节范围转换为每行的具体字符高亮范围：
- hex 流匹配 → 每行 hex 区域中对应字节的字符位置
- ASCII 流匹配 → 每行 ASCII 区域中对应字符的位置

**Step 5: 逐行渲染**

- hexdump 行：地址前缀原样输出，hex 区域和 ASCII 区域中匹配的字符用 `<mark>` 包裹
- 非 hexdump 行：调用现有 `highlightText()` 做普通高亮

### 示例

搜索 `"da487d00000029"`，归一化为 `"da 48 7d 00 00 00 29"`。

原始文本：
```
7b98de36c0: 1f e0 da 48 7d 00 00 00 27 e0 da 48 7d 00 00 00 |...H}...'..H}...|
7b98de36d0: 29 e0 da 48 7d 00 00 00 0e e3 da 48 7d 00 00 00 |)..H}......H}...|
```

hex 流（合并）：`"1f e0 da 48 7d 00 00 00 27 e0 da 48 7d 00 00 00 29 e0 ..."`

匹配 `"da 48 7d 00 00 00 29"` → 字节索引 10-16（1 处跨行匹配）

匹配（字节 10-16）：
- 第 1 行 hex 区域：`da 48 7d 00 00 00` 高亮（字节 10-15）
- 第 2 行 hex 区域：`29` 高亮（字节 16）

注：字节 2-7 是 `da 48 7d 00 00 00`，但第 8 字节是 `27` 不是 `29`，不匹配。

**已知限制：** `isCompactHex` 检测（全 hex 字符、偶数长度、≥4）可能将纯十六进制的 ASCII 词（如 `"deadbeef"`）误判为紧凑 hex。在逆向工程场景中此类误判概率低，作为已知边界情况接受。

## 4. SearchResultList 调用改动

**文件：** `src-web/src/components/SearchResultList.tsx`

将 hidden_content 的渲染从：
```tsx
{hl(match.hidden_content)}
```
改为：
```tsx
{match.hidden_content
  ? highlightHexdump(match.hidden_content, searchQuery ?? "", caseSensitive ?? false, fuzzy ?? false)
  : ""}
```

仅改动这一个调用点。`highlightHexdump` 内部对非 hexdump 行自动 fallback 到 `highlightText`。

## 涉及文件清单

| 文件 | 操作 |
|------|------|
| `src/taint/gumtrace_parser.rs` | 修改 `searchable_text()`，追加无空格 hex 行 |
| `src-web/src/utils/highlightText.tsx` | 新增 `highlightHexdump` 函数 |
| `src-web/src/components/SearchResultList.tsx` | hidden_content 改用 `highlightHexdump` |
