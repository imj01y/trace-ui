# Q 寄存器（128-bit SIMD）Hexdump 显示修复

**日期**: 2026-03-19
**范围**: Tier 1 — `ldr q` / `str q` / `ldp q` / `stp q`

## 问题

ARM64 q 寄存器为 128-bit，但 `MemAccessRecord.data` 是 `u64`（64-bit），且 `parse_hex_u64` 无法解析超过 16 位十六进制的值（溢出返回 None）。

当前行为：对于 `ldr q0, [x0]`，`elem_width=16`，`value=None`（parser 中 `elem_width <= 8` 守卫跳过），导致记录创建时 `data = mem_op.value.unwrap_or(0) = 0`，`size = 16`。产生一条 `size=16, data=0` 的错误记录。hexdump 恢复算法 `check_offset 0..=7` 只能覆盖前 8 字节（均为 0x00），后 8 字节无记录显示 `??`。

## 方案

将每个 128-bit 值拆成两条 `size=8` 的 `MemAccessRecord`（low 64 @ abs, high 64 @ abs+8）。不修改 `MemAccessRecord` 结构体，零持久内存开销。

## 修改文件与内容

### 1. `src/taint/parser.rs` — u128 解析

新增：

- `parse_hex_u128(bytes: &[u8]) -> Option<u128>`：与 `parse_hex_u64` 相同逻辑，返回 u128。
- `find_reg_hex_bytes<'a>(bytes, reg_name, start_pos) -> Option<&'a [u8]>`：从 `find_reg_value` 中提取共享搜索逻辑（找 `reg_name=0x` 模式，返回 HEX 部分的原始字节切片）。
- `find_reg_value_u128(bytes, reg_name, start_pos) -> Option<u128>`：基于 `find_reg_hex_bytes` + `parse_hex_u128`。
- 重构 `find_reg_value` 为 `find_reg_hex_bytes` + `parse_hex_u64`。

在 `parse_line_inner` 中，value 提取增加 128-bit 分支：

```
elem_width <= 8  → 现有 scalar 路径（value: Option<u64>）
elem_width == 16 → find_reg_value_u128 → split: value_lo = val as u64, value_hi = (val >> 64) as u64
```

pair 的 value2 路径同理，受 `is_pair_mnemonic` 守卫。

### 2. `src/taint/gumtrace_parser.rs` — 同样的 128-bit 提取

在 `find_gumtrace_mem_op` 中添加与 parser.rs 相同的 128-bit 分支，复用 `parser::find_reg_value_u128`、`parser::is_pair_mnemonic`、`parser::second_data_reg_name`。

### 3. `src/taint/types.rs` — MemOp 结构体扩展

```rust
pub struct MemOp {
    pub is_write: bool,
    pub abs: u64,
    pub elem_width: u8,
    pub value: Option<u64>,       // scalar（elem_width <= 8），128-bit 时保持 None
    pub value2: Option<u64>,      // pair scalar，128-bit 时保持 None
    pub value_lo: Option<u64>,    // 128-bit 第一个寄存器 low 64
    pub value_hi: Option<u64>,    // 128-bit 第一个寄存器 high 64
    pub value2_lo: Option<u64>,   // 128-bit pair 第二个寄存器 low 64
    pub value2_hi: Option<u64>,   // 128-bit pair 第二个寄存器 high 64
}
```

关键约束：
- `value`/`value2` 对 128-bit 保持 None，避免 taint 剪枝逻辑（scanner.rs:700-708 pass-through 剪枝）误用部分值。
- `value_lo`/`value_hi` 与 `value` 完全正交：128-bit 时 `value=None, value_lo=Some`；scalar 时 `value=Some, value_lo=None`。
- `MemOp` 只在两处构造（parser.rs 和 gumtrace_parser.rs），新增字段在非 128-bit 路径初始化为 `None`。
- 注意：scanner.rs 的 `memLastDef` 更新（第 835-856 行）直接操作 `MemOp` 字段而非 `MemAccessRecord`，不受记录拆分影响。128-bit STORE 的 `value` 为 None → `masked_val=0`，memLastDef 标记正确但值为 0（无法做 pass-through 优化，可接受）。

### 4. `src/phase2.rs`、`src/taint/mod.rs`、`src/taint/chunk_scan.rs` — 记录创建

三处统一改为按 `elem_width` 分支：

```rust
if mem_op.elem_width <= 8 {
    // 现有 scalar 路径（1 条记录）
    // + 现有 ldp fix：value2 → 第 2 条记录
} else if mem_op.elem_width == 16 {
    // 128-bit 路径：
    // value_lo  → record @ abs,      size=8
    // value_hi  → record @ abs+8,    size=8
    // value2_lo → record @ abs+16,   size=8
    // value2_hi → record @ abs+24,   size=8
}
```

现有 ldp fix 的 `value2` 逻辑限定在 `elem_width <= 8` 分支内。

## 不修改的文件

- `src/commands/memory.rs`：hexdump 恢复算法 `check_offset 0..=7` 天然适配 size=8 记录，无需改动。
- `src/taint/insn_class.rs`：指令分类不变。
- `MemAccessRecord` 结构体：不变，缓存格式兼容。

## 验证示例

输入 trace 行：
```
[libsscronet.so] 0x7a39cae2e8!0x2ad2e8 ldp q0, q1, [x2]; q0=0x798484e150000000798484e1b0 q1=0xffffff80ffffffc8000000798484e110 x2=0x798484e170 mem_r=0x798484e170 -> q0=0x798484e150000000798484e1b0 q1=0xffffff80ffffffc8000000798484e110
```

期望结果：4 条 MemAccessRecord

| 地址 | data | size |
|------|------|------|
| 0x798484e170 | 0x798484e1b0 (q0 low) | 8 |
| 0x798484e178 | 0x798484e150 (q0 high) | 8 |
| 0x798484e180 | 0x798484e110 (q1 low) | 8 |
| 0x798484e188 | 0xffffff80ffffffc8 (q1 high) | 8 |

Hexdump 在 0x798484e170 处显示 32 字节全部 known（无 `??`）。

## 不在范围内

- Tier 2: `ld1`/`st1` 多寄存器 SIMD（需要 MemOp 结构性调整支持 3-4 个寄存器值）
- Tier 3: lane load（需要修复 `determine_elem_width` 对 ld1 的错误返回值 + lane 位提取逻辑）
