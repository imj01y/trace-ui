# SIMD 寄存器 2-Lane 污点追踪精度修复

**日期**: 2026-03-19
**范围**: 将每个 v 寄存器拆分为 lo/hi 两个 64-bit lane，精确追踪 lane 级部分写入操作的依赖

## 问题

当前系统将 `s0/d0/q0/b0/h0` 全部归一化到同一个 `RegId::V0`，每个 v 寄存器只有一个 `reg_last_def` 条目。当 lane 级操作（`ins v0.d[1]`、`fmov v0.d[1]`、`ld1 {v0.s}[3]`）仅修改寄存器的一部分时，系统将其视为整个寄存器的 DEF，切断了未修改部分的旧依赖链。

**具体场景**：
```asm
ldr q0, [x1]        ; line 0: 加载 128-bit → DEF V0
ins v0.d[1], x8     ; line 1: 仅写高 64-bit → 当前: DEF V0（错误地覆盖整个寄存器的 last_def）
mov x9, v0.d[0]     ; line 2: 读低 64-bit → 当前: 依赖 line 1（错误，应该依赖 line 0）
```

**重要澄清**：ARM64 ISA 规定所有 SIMD 标量 load（`ldr s/d/q`）都会将未写入的高位清零到 128 位，因此 `ldr s0` 和 `ldr q0` 在污点追踪层面都是完整的 128-bit DEF。此修复主要针对 **lane 级部分写入操作**（`ins`、`fmov v.d[1]`、`ld1 lane` 等），这类操作在密码学代码（AES/SHA）中频繁出现。

## 方案

将每个 v 寄存器拆分为 2 个 sub-lane RegId（lo 64-bit / hi 64-bit），在 DEF/USE 分析阶段根据操作类型精确展开到对应的 lane。

## 修改文件与内容

### 1. `src/taint/types.rs` — RegId 扩展

**当前**：
- `RegId(0..30)` = x0..x30
- `RegId(31)` = sp
- `RegId(32)` = xzr
- `RegId(33..64)` = v0..v31（统一 128-bit）
- `RegId(65)` = nzcv
- `COUNT = 66`

**改为**：
- `RegId(33..64)` 重新定义为 **v0_lo..v31_lo**（低 64-bit lane）
- 新增 `RegId(66..97)` = **v0_hi..v31_hi**（高 64-bit lane）
- `COUNT = 98`

新增辅助方法：
```rust
impl RegId {
    /// v0_lo(33) → v0_hi(66)，仅对 SIMD lo-lane 有效
    pub fn simd_hi(self) -> Option<RegId> {
        if self.0 >= 33 && self.0 <= 64 {
            Some(RegId(self.0 + 33))
        } else {
            None
        }
    }

    /// 判断是否为 SIMD lo-lane
    pub fn is_simd_lo(self) -> bool { self.0 >= 33 && self.0 <= 64 }

    /// 判断是否为 SIMD hi-lane
    pub fn is_simd_hi(self) -> bool { self.0 >= 66 && self.0 <= 97 }

    /// 判断是否为 SIMD（lo 或 hi）
    pub fn is_simd(self) -> bool { self.is_simd_lo() || self.is_simd_hi() }
}
```

更新 `Display` 实现，66-97 范围显示为 `v{N}_hi`。

`parse_reg` 不变：所有 SIMD 寄存器名（s/d/q/b/h/v）仍 parse 到 lo-lane RegId。宽度区分在 DEF/USE 阶段处理。

### 2. `src/taint/parser.rs` — 扩展 lane 元素宽度提取

当前 `ParsedLine.lane_index` 只存储 lane 索引（`[N]` 中的 N），丢弃了排列标识符（`.s`/`.d`）。`simd_lane_reg()` 需要 `elem_width` 才能将 `lane_index` 映射到 lo/hi。

**新增字段**：`ParsedLine.lane_elem_width: Option<u8>`

- 对于内存 lane 操作（`ld1 {v0.s}[N]`）：可从 `MemOp.elem_width` 获取，无需额外解析
- 对于非内存 lane 操作（`ins v0.s[2], w8`）：从源操作数寄存器前缀推断：
  - `ins Vd.d[N], Xn` → `lane_elem_width = 8`（d-lane = 64-bit）
  - `ins Vd.s[N], Wn` → `lane_elem_width = 4`（s-lane = 32-bit）
  - `ins Vd.h[N], Wn` → `lane_elem_width = 2`
  - `ins Vd.b[N], Wn` → `lane_elem_width = 1`
  - `fmov Vd.d[1], Xn` → `lane_elem_width = 8`
- 在 `extract_lane_index` 中同时提取排列标识符宽度并存储

### 3. `src/taint/scanner.rs` — RegLastDef 扩展

`RegLastDef` 内部数组从 `[u32; 66]` 扩展为 `[u32; 98]`。

`big_array` serde 模块需适配新大小（或用 `serde_big_array` 宏重新生成）。

前向扫描中 Step 4（reg_last_def 更新）的 SIMD DEF 写入逻辑：

- **完整 128-bit DEF**（大部分 SIMD 指令、所有 SIMD load/store）：同时更新 `reg_last_def[v_lo]` 和 `reg_last_def[v_hi]`
- **仅 lo-lane DEF**（lane 操作 byte_offset < 8）：仅更新 `reg_last_def[v_lo]`
- **仅 hi-lane DEF**（lane 操作 byte_offset >= 8）：仅更新 `reg_last_def[v_hi]`

**LoadPair/StorePair 的 SIMD 展开**（`ldp q0, q1, [x0]` 等）：

当前 LoadPair 的 reg_last_def 更新为 2 条（defs[0] 无标记，defs[1] | PAIR_HALF2_BIT）。拆分后，如果 defs 是 SIMD 寄存器，需要展开为 4 条：

```
ldp q0, q1, [x0]:
  reg_last_def[v0_lo] = i              // half1
  reg_last_def[v0_hi] = i              // half1
  reg_last_def[v1_lo] = i | HALF2_BIT  // half2
  reg_last_def[v1_hi] = i | HALF2_BIT  // half2
```

StorePair 的 USE 展开同理：读 q0 时 USE v0_lo + v0_hi，读 q1 时 USE v1_lo + v1_hi。

PairSplitDeps 的 half1/half2/shared 三分结构不变，但 half1_deps 和 half2_deps 中的内存依赖边需要考虑每个寄存器覆盖 16 字节（两个 lane 各 8 字节）。

### 4. `src/taint/def_use.rs` — DEF/USE 展开

核心变更：`determine_def_use()` 返回的 defs/uses 中，SIMD RegId 需要按操作类型展开。

新增辅助函数：
```rust
/// 将 SIMD lo-lane RegId 展开为 lo+hi 两个 RegId（128-bit 完整操作）
fn expand_simd_full(reg: RegId) -> SmallVec<[RegId; 2]> {
    if let Some(hi) = reg.simd_hi() {
        smallvec![reg, hi]
    } else {
        smallvec![reg]
    }
}

/// 根据 lane_index 和 elem_width 判断属于 lo 还是 hi lane
fn simd_lane_reg(reg: RegId, lane_index: u8, elem_width: u8) -> RegId {
    let byte_offset = lane_index as u32 * elem_width as u32;
    if byte_offset >= 8 {
        reg.simd_hi().unwrap_or(reg)
    } else {
        reg  // lo lane
    }
}
```

**各 InsnClass 的展开规则**：

| InsnClass | DEF 展开 | USE 展开 |
|-----------|---------|---------|
| SimdArith / SimdMisc / SimdMove | lo+hi（128-bit 完整写入） | lo+hi（保守） |
| SimdRMW（`lane_index.is_none()`） | lo+hi（128-bit RMW） | lo+hi（读旧值 + 源操作数） |
| SimdRMW（`lane_index.is_some()`） | 仅目标 lane 的 lo 或 hi | 旧值的目标 lane + 源操作数 |
| SimdLoad（非 lane） | lo+hi（scalar load 清零高位） | 不变（base 寄存器是 x-reg） |
| SimdStore（非 lane） | 不变（writeback base 是 x-reg） | lo+hi（读完整寄存器写入内存） |
| SimdLaneLoad | 仅目标 lane 的 lo 或 hi | 旧值的目标 lane + base |
| LoadPair（SIMD 寄存器） | 两个寄存器各 lo+hi | 不变（base 是 x-reg） |
| StorePair（SIMD 寄存器） | 不变（writeback base 是 x-reg） | 两个寄存器各 lo+hi |

**SimdRMW 内部区分**：在 `def_use.rs` 的 `SimdRMW` 分支中，通过 `line.lane_index.is_some()` 判断是 lane 操作还是 128-bit 完整 RMW。lane 操作时，使用 `simd_lane_reg(rd, lane_index, lane_elem_width)` 精确映射到 lo 或 hi。

**非内存 SIMD 指令的 USE**：当前 `ParsedLine` 不存储 arrangement specifier（`.4s` vs `.2s`），无法区分 64-bit 和 128-bit 操作。**保守策略：默认 USE lo+hi（128-bit）**，安全的过近似（多追踪，不会漏追踪）。DEF 无此问题（ARM64 64-bit SIMD op 清零高位 = 完整 DEF）。

### 5. `src/taint/insn_class.rs` — Lane 操作识别

确保以下指令被正确分类为 lane 操作：

- `ins v0.d[1], x8` / `ins v0.s[2], w8` — 已有 SimdRMW
- `fmov v0.d[1], x8` — 需确认分类为 SimdRMW
- `ld1 {v0.s}[N], [x1]` — 已有 SimdLaneLoad
- `ext v0.16b, v1.16b, v2.16b, #N` — 128-bit 完整操作，不是 lane op

### 6. `src/taint/chunk_scan.rs` — 并行扫描分块处理

包含与 scanner.rs 几乎完全相同的 reg_last_def 更新逻辑。**所有 scanner.rs 中的 SIMD lo/hi 展开变更必须在此文件中同步应用**，包括：

- SIMD DEF 写入时的 lo+hi 展开
- LoadPair/StorePair 中 SIMD 寄存器的 4 条 reg_last_def 更新
- lane 操作的精确 lo/hi 映射

### 7. `src/taint/merge.rs` — 块合并逻辑

包含 `resolve_unresolved_pair_load`、`resolve_partial_pair_load`、`resolve_unresolved_reg_uses` 等函数，以及 `for r in 0..RegId::COUNT` 循环。

- `COUNT` 变化会自动扩展循环范围
- `resolve_unresolved_reg_uses` 中的 SIMD 寄存器 reg_last_def 查找需要同时处理 lo 和 hi lane
- pair load 的 resolve 函数需要适配 SIMD 寄存器展开后的 4 条 DEF

### 8. `src/taint/mod.rs` — 并行扫描入口

包含 reg_last_def 更新逻辑和 PairSplitDeps 处理，是并行扫描的前端入口。需要与 scanner.rs 同步适配 SIMD lo/hi 展开。

### 9. `src/taint/parallel_types.rs` — 并行扫描类型

包含 `final_reg_values: [u64; RegId::COUNT]`，数组大小自动跟随 COUNT 变化。新增的 hi-lane 槽位初始化为 0（与现有 lo-lane 一致）。

### 10. `src/phase2.rs` — Phase2 寄存器值追踪

包含多处 `[u64; RegId::COUNT]` 数组用于寄存器值快照。`update_reg_values` 函数解析 `=>` 箭头后的寄存器值：

- `parse_reg` 返回 lo-lane RegId，标量值（x/w/s/d）直接写入 lo 槽位
- q-register 的 128-bit 值：低 64-bit 写入 lo 槽位，高 64-bit 写入 hi 槽位（复用已有的 `value_lo`/`value_hi` 拆分逻辑）

### 11. `src/taint/reg_checkpoint.rs` — 寄存器快照

`RegSnapshot` 使用 `[u64; RegId::COUNT]`，大小自动跟随 COUNT。serde 反序列化已被缓存 MAGIC 版本保护，旧格式自动失效。

### 12. `src/cache.rs` — 缓存兼容性

`MAGIC` 从 `b"TCACHE02"` 升级为 `b"TCACHE03"`。旧缓存自动失效，首次加载时重建。三种缓存类型（Phase2、ScanState、LineIndex）均受 MAGIC 保护。

### 13. `src/taint/slicer.rs` — 后向切片

**无需修改**。lo/hi 拆分后，依赖边自然区分两个 lane。BFS 遍历的是 deps 数组中的行号，不涉及 RegId 解释。

### 14. 前端展示

`resolve_taint_*` 系列函数返回的寄存器变化信息中，如果涉及 SIMD hi-lane RegId，需要在显示时合并回完整寄存器名（如 `v0_hi` → 显示为 `v0` 的一部分）。具体影响取决于前端如何使用 RegId 显示名称，可能需要小幅调整。

## Lane 映射规则

```
128-bit register: |  hi (64-bit)  |  lo (64-bit)  |
                  | s[3] | s[2]   | s[1] | s[0]   |
                  |    d[1]       |    d[0]        |
                  |           q (full)              |

lane_index + elem_width → byte_offset → lo or hi:
  d[0] → offset 0  → lo
  d[1] → offset 8  → hi
  s[0] → offset 0  → lo
  s[1] → offset 4  → lo
  s[2] → offset 8  → hi
  s[3] → offset 12 → hi
  b[0..7]  → lo
  b[8..15] → hi
  h[0..3]  → lo
  h[4..7]  → hi
```

## 性能影响

- `RegLastDef`：264B → 392B（+128B），仍在 L1 缓存内
- `[u64; RegId::COUNT]` 数组（RegSnapshot 等）：528B → 784B（+256B），每个 checkpoint 增加 256B
- 每条 SIMD 指令的 DEF/USE 最多多 1 个 RegId → deps 数组约增长 10-20%（SIMD 密集 trace）
- 前向扫描：约 5-10% 慢
- 后向 BFS：约 10% 慢
- 整体用户感知：极小

## 测试策略

- **单元测试**：`simd_lane_reg` 的每种 elem_width / lane_index 组合（d[0]/d[1]、s[0..3]、b[0..15]、h[0..7]）
- **集成测试**：验证核心场景 `ldr q0 / ins v0.d[1] / mov x9, v0.d[0]` 的依赖追踪正确性
- **回归测试**：确保纯 128-bit SIMD 指令（如 `eor v0.16b, v1.16b, v2.16b`）的行为不变
- **LoadPair 测试**：`ldp q0, q1, [x0]` 后分别读 v0_lo、v0_hi、v1_lo、v1_hi 的依赖正确性

## 不在范围内

- 4-lane（32-bit 粒度）拆分 — 未来可升级
- 非内存 SIMD 指令的 arrangement specifier 解析 — 当前保守处理为 128-bit
- w/x 寄存器宽度区分 — ARM64 w 写入零扩展到 x，当前行为已正确
