# SIMD 2-Lane Taint Tracking Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Split each ARM64 v-register into lo/hi 64-bit lanes in the taint tracker so that lane-level partial writes (ins, fmov v.d[1], ld1 lane) don't incorrectly cut off unmodified lane dependencies.

**Architecture:** Extend RegId space from 66 to 98 entries (adding 32 hi-lane IDs). Modify DEF/USE analysis to expand SIMD registers to lo+hi based on instruction type. Scanner and chunk_scan update both lanes for full-width ops, single lane for lane ops.

**Tech Stack:** Rust, ARM64 ISA semantics, serde (cache format)

**Spec:** `docs/superpowers/specs/2026-03-19-simd-2lane-taint-design.md`

---

### Task 1: Extend RegId with hi-lane constants and helpers

**Files:**
- Modify: `src/taint/types.rs:17-111`

- [ ] **Step 1: Add hi-lane constants and update COUNT**

In `src/taint/types.rs`, after `NZCV` (line 91) and before `COUNT` (line 93):

```rust
    // SIMD hi-lanes (high 64-bit of v0-v31)
    pub const V0_HI: Self = Self(66);
    pub const V1_HI: Self = Self(67);
    // ... V2_HI(68) through V31_HI(97)
    pub const V31_HI: Self = Self(97);

    /// Total number of distinct RegId values (0..=97).
    pub const COUNT: usize = 98;
```

Add helper methods after `is_zero()` (line 97):

```rust
    /// For a SIMD lo-lane RegId (33..=64), return the corresponding hi-lane.
    pub fn simd_hi(self) -> Option<RegId> {
        if self.0 >= 33 && self.0 <= 64 {
            Some(RegId(self.0 + 33))
        } else {
            None
        }
    }

    /// True if this is a SIMD lo-lane (v0..v31, IDs 33-64).
    pub fn is_simd_lo(self) -> bool { self.0 >= 33 && self.0 <= 64 }

    /// True if this is a SIMD hi-lane (v0_hi..v31_hi, IDs 66-97).
    pub fn is_simd_hi(self) -> bool { self.0 >= 66 && self.0 <= 97 }

    /// True if this is any SIMD register (lo or hi lane).
    pub fn is_simd(self) -> bool { self.is_simd_lo() || self.is_simd_hi() }
```

- [ ] **Step 2: Update Debug/Display impl**

Update the Debug impl (line 100-111) to handle hi-lane range:

```rust
impl fmt::Debug for RegId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::SP => write!(f, "sp"),
            Self::XZR => write!(f, "xzr"),
            Self::NZCV => write!(f, "nzcv"),
            r if r.0 <= 30 => write!(f, "x{}", r.0),
            r if (33..=64).contains(&r.0) => write!(f, "v{}", r.0 - 33),
            r if (66..=97).contains(&r.0) => write!(f, "v{}_hi", r.0 - 66),
            _ => write!(f, "reg({})", self.0),
        }
    }
}
```

- [ ] **Step 3: Update doc comment**

Update the doc comment on RegId (line 17-20) to reflect the new layout:

```rust
/// ARM64 寄存器标识符。
///
/// 使用 `u8` 编码：x0-x28=0-28, x29(fp)=29, x30(lr)=30, sp=31, xzr=32,
/// v0_lo-v31_lo=33-64, nzcv=65, v0_hi-v31_hi=66-97。总共 98 个寄存器。
```

- [ ] **Step 4: Verify compilation**

Run: `cargo check 2>&1 | head -20`
Expected: Compiles (COUNT change propagates automatically to all `[T; RegId::COUNT]` arrays)

- [ ] **Step 5: Commit**

```bash
git add src/taint/types.rs
git commit -m "feat(taint): extend RegId with SIMD hi-lane IDs (66-97)"
```

---

### Task 2: Add lane_elem_width to ParsedLine and parser

**Files:**
- Modify: `src/taint/types.rs:284-305` (ParsedLine struct)
- Modify: `src/taint/parser.rs:396-413` (extract_lane_index)

- [ ] **Step 1: Add lane_elem_width field to ParsedLine**

In `src/taint/types.rs`, after `lane_index` field (line 300):

```rust
    /// SIMD lane 索引（如 `{v0.s}[1]` 中的 1）。
    pub lane_index: Option<u8>,
    /// SIMD lane 元素宽度（字节），从排列标识符推断：s=4, d=8, h=2, b=1。
    pub lane_elem_width: Option<u8>,
```

- [ ] **Step 2: Modify extract_lane_index to return elem_width**

In `src/taint/parser.rs`, change `extract_lane_index` (line 398-413) to return a triple:

```rust
/// Extract lane index and element width from token like "v0.s[1]".
/// Returns (token without lane bracket, optional lane index, optional elem width in bytes).
fn extract_lane_index(token: &str) -> (&str, Option<u8>, Option<u8>) {
    if let Some(dot_pos) = token.find('.') {
        if let Some(bracket_start) = token[dot_pos..].find('[') {
            let abs_bracket = dot_pos + bracket_start;
            if let Some(bracket_end) = token[abs_bracket..].find(']') {
                let idx_str = &token[abs_bracket + 1..abs_bracket + bracket_end];
                if let Ok(idx) = idx_str.parse::<u8>() {
                    // Extract element width from arrangement specifier between '.' and '['
                    let arrangement = &token[dot_pos + 1..abs_bracket];
                    let elem_width = match arrangement.as_bytes().first() {
                        Some(b'b') => Some(1u8),
                        Some(b'h') => Some(2u8),
                        Some(b's') => Some(4u8),
                        Some(b'd') | Some(b'D') => Some(8u8),
                        _ => None,
                    };
                    return (&token[..abs_bracket], Some(idx), elem_width);
                }
            }
        }
    }
    (token, None, None)
}
```

- [ ] **Step 3: Update caller in parse_operands_into**

In `src/taint/parser.rs`, update the call site (line 329-332):

```rust
        // Extract lane index if present (e.g., "v0.s[1]" → "v0.s", Some(1), Some(4))
        let (token, extracted_lane, extracted_elem_width) = extract_lane_index(token);
        if extracted_lane.is_some() {
            out.lane_index = extracted_lane;
            out.lane_elem_width = extracted_elem_width;
        }
```

- [ ] **Step 4: Verify compilation**

Run: `cargo check 2>&1 | head -20`
Expected: Compiles. Any `ParsedLine { ... }` construction sites will need `lane_elem_width: None` added if they use struct literal syntax. Check for compilation errors and fix.

- [ ] **Step 5: Commit**

```bash
git add src/taint/types.rs src/taint/parser.rs
git commit -m "feat(taint): add lane_elem_width to ParsedLine for SIMD lane mapping"
```

---

### Task 3: Add SIMD expansion helpers to def_use.rs

**Files:**
- Modify: `src/taint/def_use.rs`

- [ ] **Step 1: Add helper functions**

Add before `determine_def_use` (line 12):

```rust
/// Expand a SIMD lo-lane RegId to both lo+hi lanes (128-bit full operation).
/// Non-SIMD registers pass through unchanged.
fn expand_simd_full(defs: &mut SmallVec<[RegId; 4]>, reg: RegId) {
    defs.push(reg);
    if let Some(hi) = reg.simd_hi() {
        defs.push(hi);
    }
}

/// Determine which lane (lo or hi) a lane_index maps to given elem_width.
/// byte_offset = lane_index * elem_width; >= 8 means hi lane.
fn simd_lane_reg(reg: RegId, lane_index: u8, elem_width: u8) -> RegId {
    let byte_offset = lane_index as u32 * elem_width as u32;
    if byte_offset >= 8 {
        reg.simd_hi().unwrap_or(reg)
    } else {
        reg
    }
}
```

- [ ] **Step 2: Verify compilation**

Run: `cargo check 2>&1 | head -5`
Expected: Compiles (helpers unused yet, may get dead_code warning — OK)

- [ ] **Step 3: Commit**

```bash
git add src/taint/def_use.rs
git commit -m "feat(taint): add SIMD lo/hi expansion helpers in def_use"
```

---

### Task 4: Expand SIMD DEF/USE in determine_def_use

**Files:**
- Modify: `src/taint/def_use.rs:20-388`

This is the core change. Each SIMD InsnClass branch needs to expand register DEFs/USEs to lo+hi.

- [ ] **Step 1: Expand SimdArith/SimdMisc/SimdMove (lines 34-41)**

Current code:
```rust
        | InsnClass::SimdArith
        | InsnClass::SimdMisc
        | InsnClass::SimdMove => {
            if let Some(rd) = first_reg_non_zero(ops) {
                defs.push(rd);
            }
            collect_uses_from(ops, 1, &mut uses);
        }
```

These are grouped with scalar pure-write instructions. Need to split SIMD out:

```rust
        | InsnClass::SimdArith
        | InsnClass::SimdMisc
        | InsnClass::SimdMove => {
            if let Some(rd) = first_reg_non_zero(ops) {
                expand_simd_full(&mut defs, rd);
            }
            // USE: expand SIMD source operands to lo+hi
            for op in ops.iter().skip(1) {
                if let Some(r) = op.as_reg().filter(|r| !r.is_zero()) {
                    expand_simd_full(&mut uses, r);
                }
            }
        }
```

Note: This means SimdArith/SimdMisc/SimdMove can no longer share the arm with the scalar pure-write instructions (AluReg, etc.). Split them into a separate match arm.

- [ ] **Step 2: Expand SimdRMW (lines 105-111)**

Current code handles ScalarRMW and SimdRMW together. Split them:

```rust
        InsnClass::ScalarRMW => {
            if let Some(rd) = first_reg_non_zero(ops) {
                defs.push(rd);
                uses.push(rd);
            }
            collect_uses_from(ops, 1, &mut uses);
        }

        InsnClass::SimdRMW => {
            if let Some(rd) = first_reg_non_zero(ops) {
                if let (Some(lane_idx), Some(ew)) = (line.lane_index, line.lane_elem_width) {
                    // Lane operation (ins, fmov v.d[1]): only target lane
                    let target = simd_lane_reg(rd, lane_idx, ew);
                    defs.push(target);
                    uses.push(target); // old value of target lane
                } else {
                    // Full 128-bit RMW (bsl, aese, sha256h, mla, etc.)
                    expand_simd_full(&mut defs, rd);
                    expand_simd_full(&mut uses, rd);
                }
            }
            // Source operands: conservatively expand SIMD to lo+hi
            for op in ops.iter().skip(1) {
                if let Some(r) = op.as_reg().filter(|r| !r.is_zero()) {
                    if r.is_simd_lo() {
                        expand_simd_full(&mut uses, r);
                    } else {
                        uses.push(r);
                    }
                }
            }
        }
```

- [ ] **Step 3: Expand SimdLoad (lines 340-367)**

```rust
        InsnClass::SimdLoad => {
            if let Some(base) = line.base_reg {
                for op in ops.iter() {
                    if let Some(r) = op.as_reg() {
                        if r == base {
                            break;
                        }
                        // All SIMD loads (ldr s/d/q) zero upper bits → full DEF
                        expand_simd_full(&mut defs, r);
                    }
                }
                uses.push(base);
            } else {
                if let Some(vt) = ops.first().and_then(|o| o.as_reg()) {
                    expand_simd_full(&mut defs, vt);
                }
                // Non-SIMD source operands (base registers)
                collect_uses_from(ops, 1, &mut uses);
            }
            if line.writeback {
                if let Some(base) = line.base_reg {
                    defs.push(base);
                }
            }
        }
```

- [ ] **Step 4: Expand SimdLaneLoad (lines 373-384)**

Note: Do NOT use `mem_op.elem_width` as fallback — it represents the total memory access width (e.g., 16 for full vector), not the per-lane element width. Only `lane_elem_width` is correct here.

```rust
        InsnClass::SimdLaneLoad => {
            if let Some(vt) = ops.first().and_then(|o| o.as_reg()) {
                if let (Some(lane_idx), Some(ew)) = (line.lane_index, line.lane_elem_width) {
                    let target = simd_lane_reg(vt, lane_idx, ew);
                    defs.push(target);
                    uses.push(target); // old value of target lane (RMW)
                } else {
                    // Fallback: no lane_elem_width → conservative full register RMW
                    expand_simd_full(&mut defs, vt);
                    expand_simd_full(&mut uses, vt);
                }
            }
            collect_uses_from(ops, 1, &mut uses);
            if line.writeback {
                if let Some(base) = line.base_reg {
                    defs.push(base);
                }
            }
        }
```

- [ ] **Step 5: Split StoreReg/StorePair/SimdStore into 3 separate arms (lines 154-161)**

Currently these 3 share one arm. Split into 3 in one step to avoid intermediate compilation failures:

```rust
        InsnClass::StoreReg => {
            collect_uses_from(ops, 0, &mut uses);
            if line.writeback {
                if let Some(base) = line.base_reg {
                    defs.push(base);
                }
            }
        }

        InsnClass::StorePair => {
            // Data operands may be SIMD → expand lo+hi
            for op in ops.iter() {
                if let Some(r) = op.as_reg().filter(|r| !r.is_zero()) {
                    if r.is_simd_lo() {
                        expand_simd_full(&mut uses, r);
                    } else {
                        uses.push(r);
                    }
                }
            }
            if line.writeback {
                if let Some(base) = line.base_reg {
                    defs.push(base);
                }
            }
        }

        InsnClass::SimdStore => {
            // USE: expand SIMD data registers to lo+hi
            for op in ops.iter() {
                if let Some(r) = op.as_reg().filter(|r| !r.is_zero()) {
                    if r.is_simd_lo() {
                        expand_simd_full(&mut uses, r);
                    } else {
                        uses.push(r);
                    }
                }
            }
            if line.writeback {
                if let Some(base) = line.base_reg {
                    defs.push(base);
                }
            }
        }
```

- [ ] **Step 6: Expand LoadPair for SIMD registers (lines 133-146)**

```rust
        InsnClass::LoadPair => {
            for op in ops.iter().take(2) {
                if let Some(r) = op.as_reg().filter(|r| !r.is_zero()) {
                    if r.is_simd_lo() {
                        expand_simd_full(&mut defs, r);
                    } else {
                        defs.push(r);
                    }
                }
            }
            collect_uses_from(ops, 2, &mut uses);
            if line.writeback {
                if let Some(base) = line.base_reg {
                    defs.push(base);
                }
            }
        }
```

- [ ] **Step 7: Verify compilation**

Run: `cargo check 2>&1 | head -20`
Expected: Compiles

- [ ] **Step 8: Commit**

```bash
git add src/taint/def_use.rs
git commit -m "feat(taint): expand SIMD DEF/USE to lo+hi lanes in def_use"
```

---

### Task 5: Update scanner.rs reg_last_def for SIMD LoadPair

**Files:**
- Modify: `src/taint/scanner.rs:812-832`

- [ ] **Step 1: Update LoadPair reg_last_def update**

The LoadPair branch (line 813-822) now receives expanded defs from def_use (e.g., for `ldp q0, q1`: defs = [v0_lo, v0_hi, v1_lo, v1_hi, maybe base]). The existing logic tags defs[0] as half1 and defs[1] as half2, but with expansion we have 4+ SIMD defs.

Rewrite the LoadPair branch to handle expanded SIMD defs:

```rust
        if class == InsnClass::LoadPair {
            // LoadPair defs: after expansion, SIMD pairs have 4 data defs + optional base.
            // Original order from def_use: [rt1_lo, rt1_hi?, rt2_lo, rt2_hi?, base?]
            // Tag: rt1 lanes as half1 (no tag), rt2 lanes as half2, base as shared.
            let has_base_wb = line.writeback && line.base_reg.is_some();
            let data_defs = if has_base_wb { &defs[..defs.len() - 1] } else { &defs[..] };
            let mid = data_defs.len() / 2; // split point between rt1 and rt2

            for r in &data_defs[..mid] {
                state.reg_last_def.insert(*r, i); // half1: no tag
            }
            for r in &data_defs[mid..] {
                state.reg_last_def.insert(*r, i | PAIR_HALF2_BIT); // half2
            }
            if has_base_wb {
                state.reg_last_def.insert(*defs.last().unwrap(), i | PAIR_SHARED_BIT);
            }
```

- [ ] **Step 2: Verify compilation**

Run: `cargo check 2>&1 | head -10`
Expected: Compiles

- [ ] **Step 3: Commit**

```bash
git add src/taint/scanner.rs
git commit -m "feat(taint): update scanner LoadPair reg_last_def for SIMD hi-lanes"
```

---

### Task 6: Mirror changes in chunk_scan.rs

**Files:**
- Modify: `src/taint/chunk_scan.rs:524-541`

- [ ] **Step 1: Apply identical LoadPair reg_last_def update**

The code at lines 524-541 in chunk_scan.rs mirrors scanner.rs. Apply the exact same LoadPair rewrite from Task 5.

- [ ] **Step 2: Verify compilation**

Run: `cargo check 2>&1 | head -10`
Expected: Compiles

- [ ] **Step 3: Commit**

```bash
git add src/taint/chunk_scan.rs
git commit -m "feat(taint): mirror scanner SIMD hi-lane changes in chunk_scan"
```

---

### Task 6b: Mirror changes in mod.rs

**Files:**
- Modify: `src/taint/mod.rs` (LoadPair/StorePair reg_last_def updates, ~lines 370-446)

- [ ] **Step 1: Apply identical LoadPair reg_last_def update**

`mod.rs` contains a mirror of the LoadPair/StorePair reg_last_def update logic from scanner.rs. Apply the exact same LoadPair rewrite from Task 5.

Also check StorePair PairSplitDeps construction: when querying `reg_last_def.get(&r)` for SIMD operands, the `uses` now contain both lo and hi RegIds (from def_use expansion), so the existing `for r in &uses` loop will naturally query both lo and hi lanes. Verify this is correct.

- [ ] **Step 2: Verify compilation**

Run: `cargo check 2>&1 | head -10`
Expected: Compiles

- [ ] **Step 3: Commit**

```bash
git add src/taint/mod.rs
git commit -m "feat(taint): mirror scanner SIMD hi-lane changes in mod.rs"
```

---

### Task 6c: Verify insn_class.rs SIMD lane classification

**Files:**
- Review: `src/taint/insn_class.rs`

- [ ] **Step 1: Verify fmov v.d[1] classification**

Run: `grep -n 'fmov.*SimdRMW\|SimdRMW.*fmov\|fmov.*lane\|fmov.*D\[1\]' src/taint/insn_class.rs`

Confirm that `fmov v0.d[1], x8` is classified as `SimdRMW` (not `SimdMove`). If not, add it to the SimdRMW list.

- [ ] **Step 2: Verify ins classification**

Run: `grep -n '"ins"' src/taint/insn_class.rs`

Confirm `ins` is classified as SimdRMW.

- [ ] **Step 3: Commit if changes needed**

```bash
git add src/taint/insn_class.rs
git commit -m "fix(taint): ensure fmov lane ops classified as SimdRMW"
```

---

### Task 7: Update cache MAGIC version

**Files:**
- Modify: `src/cache.rs:8`

- [ ] **Step 1: Bump MAGIC**

```rust
const MAGIC: &[u8; 8] = b"TCACHE03";
```

- [ ] **Step 2: Update scanner.rs doc comment**

Update the RegLastDef doc comment (line 13-17) to reflect 98 entries:

```rust
/// Flat array mapping RegId → last DEF line index.
///
/// Uses `u32::MAX` as sentinel for "no definition seen". Provides the same
/// `.get()` / `.insert()` API as HashMap for drop-in replacement.
/// 98 entries × 4 bytes = 392 bytes — fits in a few cache lines.
```

- [ ] **Step 3: Verify compilation**

Run: `cargo check 2>&1 | head -5`
Expected: Compiles

- [ ] **Step 4: Commit**

```bash
git add src/cache.rs src/taint/scanner.rs
git commit -m "chore: bump cache MAGIC to TCACHE03 for RegId expansion"
```

---

### Task 8: Verify merge.rs and parallel_types.rs compatibility

**Files:**
- Review: `src/taint/merge.rs`, `src/taint/parallel_types.rs`, `src/taint/reg_checkpoint.rs`, `src/phase2.rs`

- [ ] **Step 1: Check merge.rs for r in 0..RegId::COUNT loops**

These loops automatically scale to 0..98. Verify no hardcoded `66` exists:

Run: `grep -n '66\|0\.\.66\|0..66' src/taint/merge.rs src/taint/parallel_types.rs src/taint/reg_checkpoint.rs src/phase2.rs`
Expected: No matches (all use RegId::COUNT)

- [ ] **Step 2: Check for any hardcoded SIMD range checks**

Run: `grep -n '33\.\.\|\.\.64\|33..=64\|>= 33\|<= 64' src/taint/merge.rs src/taint/parallel_types.rs src/taint/reg_checkpoint.rs src/phase2.rs src/taint/mod.rs`
Expected: Either no matches, or matches that are in parse_reg (types.rs) which we already handle.

- [ ] **Step 3: Fix phase2.rs register value population for 128-bit**

In phase2.rs, `update_reg_values_at` parses register values with `u64::from_str_radix`. For q-register 128-bit values (e.g., `q0=0x0123456789abcdef0123456789abcdef`), `u64` overflows and parsing fails silently.

Fix: For SIMD registers, attempt `u128` parsing first. If successful, split into lo/hi:

```rust
// In update_reg_values_at, when setting SIMD register values:
if reg.is_simd_lo() {
    // Try u128 parse first for q-register values
    if let Ok(val128) = u128::from_str_radix(hex_str, 16) {
        reg_values[reg.0 as usize] = val128 as u64;           // lo 64 bits
        if let Some(hi) = reg.simd_hi() {
            reg_values[hi.0 as usize] = (val128 >> 64) as u64; // hi 64 bits
        }
    } else if let Ok(val64) = u64::from_str_radix(hex_str, 16) {
        reg_values[reg.0 as usize] = val64;
        // hi lane stays at u64::MAX (no data)
    }
} else {
    // Non-SIMD: existing u64 parse path
}
```

Note: This also fixes a pre-existing bug where q-register values were silently lost.

- [ ] **Step 4: Commit**

```bash
git add src/phase2.rs && git commit -m "fix(taint): populate SIMD hi-lane values in phase2 register snapshots"
```

---

### Task 9: Full build and integration test

**Files:**
- All modified files

- [ ] **Step 1: Full build**

Run: `cargo build 2>&1 | tail -5`
Expected: Build succeeds

- [ ] **Step 2: Run existing tests**

Run: `cargo test 2>&1 | tail -20`
Expected: All existing tests pass (no regressions)

- [ ] **Step 3: Manual test with a trace file**

Open the application and load a trace file containing SIMD lane operations. Verify:
1. File loads successfully (cache rebuilds with new MAGIC)
2. Taint tracking works (selecting a line shows dependencies)
3. No crashes or panics in the console

- [ ] **Step 4: Commit all remaining changes**

```bash
git add -A && git commit -m "feat(taint): SIMD 2-lane taint tracking precision fix

Split each ARM64 v-register into lo/hi 64-bit lanes (RegId 33-64 for lo,
66-97 for hi). Lane-level operations (ins, fmov v.d[1], ld1 lane) now
correctly track dependencies per-lane instead of per-register.

Closes: SIMD taint precision issue with mixed-width lane operations."
```
