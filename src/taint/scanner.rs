use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use memchr::memchr;
use rustc_hash::FxHashMap;
use smallvec::SmallVec;

use super::def_use;
use crate::taint::insn_class::{self, InsnClass};
use super::parser;
use crate::taint::types::*;

/// Flat array mapping RegId → last DEF line index.
///
/// Uses `u32::MAX` as sentinel for "no definition seen". Provides the same
/// `.get()` / `.insert()` API as HashMap for drop-in replacement.
/// 66 entries × 4 bytes = 264 bytes — fits in a few cache lines.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct RegLastDef(#[serde(with = "big_array")] [u32; RegId::COUNT]);

mod big_array {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use crate::taint::types::RegId;

    pub fn serialize<S: Serializer>(arr: &[u32; RegId::COUNT], s: S) -> Result<S::Ok, S::Error> {
        arr.as_slice().serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u32; RegId::COUNT], D::Error> {
        let v = Vec::<u32>::deserialize(d)?;
        v.try_into().map_err(|v: Vec<u32>| {
            serde::de::Error::custom(format!("expected {} elements, got {}", RegId::COUNT, v.len()))
        })
    }
}

impl Default for RegLastDef {
    fn default() -> Self {
        Self::new()
    }
}

impl RegLastDef {
    const NO_DEF: u32 = u32::MAX;

    pub fn new() -> Self {
        Self([Self::NO_DEF; RegId::COUNT])
    }

    pub fn get(&self, reg: &RegId) -> Option<&u32> {
        let val = &self.0[reg.0 as usize];
        if *val != Self::NO_DEF {
            Some(val)
        } else {
            None
        }
    }

    pub fn insert(&mut self, reg: RegId, line: u32) {
        self.0[reg.0 as usize] = line;
    }
}

/// State accumulated during Pass 1 forward scan.
///
/// Tracks:
/// - `reg_last_def`: line index of the last DEF for each register
/// - `mem_last_def`: line index of the last DEF for each memory byte address
/// - `last_cond_branch`: line index of the most recent conditional branch
/// - `deps`: per-line dependency edges (line indices this line depends on)
/// - `line_count`: total number of lines processed
/// Bit 标记：dep 行号的高位表示 pair 指令的到达路径。
/// 24M 行远不到 2^30，所以 bit 30-31 可以安全复用。
///
/// - PAIR_HALF2_BIT (bit 31): 到达 pair 指令的第二半区（half2 数据）
/// - PAIR_SHARED_BIT (bit 30): 到达 pair 指令的共享路径（writeback base）
/// - 无标记: 到达 pair 指令的第一半区（half1 数据）
pub const PAIR_HALF2_BIT: u32 = 0x80000000;
pub const PAIR_SHARED_BIT: u32 = 0x40000000;
pub const LINE_MASK: u32 = 0x3FFFFFFF;

/// Pair 指令（ldp/stp）的分半依赖。
/// 将内存依赖和源寄存器依赖按半区拆分，以提高切片精度。
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct PairSplitDeps {
    /// 共享依赖（base reg、control dep）
    pub shared: SmallVec<[u32; 2]>,
    /// 第一个寄存器的专属依赖（mem 半区1 或 source reg1）
    pub half1_deps: SmallVec<[u32; 4]>,
    /// 第二个寄存器的专属依赖（mem 半区2 或 source reg2）
    pub half2_deps: SmallVec<[u32; 4]>,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct ScanState {
    pub reg_last_def: RegLastDef,
    pub mem_last_def: FxHashMap<u64, (u32, u64)>,
    pub last_cond_branch: Option<u32>,
    pub deps: Vec<SmallVec<[u32; 4]>>,
    pub line_count: u32,
    /// 成功解析的指令行数（parse_line 返回 Some 的次数）
    pub parsed_count: u32,
    /// Maps (@LINE, target) → resolved line index (may differ from original if fallback occurred).
    pub resolved_targets: FxHashMap<(u32, LineTarget), u32>,
    /// 未知助记符统计：助记符 → (首次出现行号 0-based, 出现次数)
    pub unknown_mnemonics: FxHashMap<String, (u32, u32)>,
    /// 标记从初始内存（trace 前状态）加载的行。
    pub init_mem_loads: bitvec::prelude::BitVec,
    /// Pair 指令的分半依赖（仅 LoadPair/StorePair 行有条目）。
    pub pair_split: FxHashMap<u32, PairSplitDeps>,
}

/// Push `val` into a SmallVec only if not already present (dedup).
pub fn push_unique<A: smallvec::Array<Item = u32>>(deps: &mut SmallVec<A>, val: u32) {
    if !deps.contains(&val) {
        deps.push(val);
    }
}

/// Scan from an in-memory string (for testing).
#[allow(dead_code)]
pub fn scan_from_string(trace: &str, data_only: bool) -> Result<ScanState> {
    scan_from_string_with_targets(trace, data_only, 0, None, &Default::default())
}

/// Scan from an in-memory string with range limiting.
#[allow(dead_code)]
pub fn scan_from_string_with_range(
    trace: &str,
    data_only: bool,
    start_seq: u32,
    end_seq: Option<u32>,
) -> Result<ScanState> {
    scan_from_string_with_targets(trace, data_only, start_seq, end_seq, &Default::default())
}

/// Scan from an in-memory string with full options (range + @LINE targets).
#[allow(dead_code)]
pub fn scan_from_string_with_targets(
    trace: &str,
    data_only: bool,
    start_seq: u32,
    end_seq: Option<u32>,
    line_targets: &std::collections::HashMap<u32, Vec<LineTarget>>,
) -> Result<ScanState> {
    scan_pass1_bytes(
        trace.as_bytes(),
        data_only,
        start_seq,
        end_seq,
        line_targets,
        false,
        false,
    )
}

/// Core Pass 1: forward scan building the dependency graph.
///
/// Operates directly on a byte slice (from mmap or string) using memchr to
/// find newlines. No read_line syscalls, no UTF-8 validation, no buffer copies.
///
/// For each line:
/// 1. Parse the trace line
/// 2. Classify the instruction
/// 3. Determine DEF/USE sets
/// 4. Record data dependencies (register + memory) and control dependencies
/// 5. Update regLastDef, memLastDef, lastCondBranch
///
/// `start_seq` and `end_seq` limit the range of lines that are actually
/// parsed/classified. Lines outside `[start_seq, end_seq]` still get an
/// empty deps entry to maintain index alignment.
///
/// Use this directly when the caller already has the mmap and wants to reuse it later.
#[allow(dead_code)]
pub fn scan_pass1_bytes(
    data: &[u8],
    data_only: bool,
    start_seq: u32,
    end_seq: Option<u32>,
    line_targets: &std::collections::HashMap<u32, Vec<LineTarget>>,
    profile: bool,
    no_prune: bool,
) -> Result<ScanState> {
    scan_pass1_bytes_with_progress(data, data_only, start_seq, end_seq, line_targets, profile, no_prune, None)
}

pub fn scan_pass1_bytes_with_progress(
    data: &[u8],
    data_only: bool,
    start_seq: u32,
    end_seq: Option<u32>,
    line_targets: &std::collections::HashMap<u32, Vec<LineTarget>>,
    profile: bool,
    no_prune: bool,
    progress_fn: Option<&dyn Fn(usize, usize)>,
) -> Result<ScanState> {
    // Pre-count lines for capacity pre-allocation.
    // This memchr scan (~0.3s for 2.88GB) also pre-faults all mmap pages into
    // physical memory, warming the page cache for the main loop. Removing this
    // causes ~5s regression on Windows due to cold page faults during parsing.
    let line_count_est = memchr::memchr_iter(b'\n', data).count()
        + if !data.is_empty() && data.last() != Some(&b'\n') {
            1
        } else {
            0
        };

    let mut state = ScanState {
        reg_last_def: RegLastDef::new(),
        mem_last_def: FxHashMap::with_capacity_and_hasher(
            line_count_est / 4, // heuristic: ~25% of lines have mem ops
            Default::default(),
        ),
        last_cond_branch: None,
        deps: Vec::with_capacity(line_count_est),
        line_count: 0,
        parsed_count: 0,
        resolved_targets: FxHashMap::default(),
        unknown_mnemonics: FxHashMap::default(),
        init_mem_loads: bitvec::prelude::BitVec::repeat(false, line_count_est),
        pair_split: FxHashMap::default(),
    };

    // Profiling accumulators
    let mut t_io = Duration::ZERO;
    let mut t_parse = Duration::ZERO;
    let mut t_classify = Duration::ZERO;
    let mut t_deps = Duration::ZERO;
    let mut t_update = Duration::ZERO;
    let mut pruned_count = 0u64;

    let mut pos = 0usize;
    let len = data.len();
    let progress_interval = len / 100 + 1;
    let mut last_progress_pos = 0usize;

    while pos < len {
        // 进度报告
        if let Some(cb) = &progress_fn {
            if pos - last_progress_pos >= progress_interval {
                cb(pos, len);
                last_progress_pos = pos;
            }
        }

        let t0 = profile.then(Instant::now);

        // Find next newline (or end of data)
        let line_end = match memchr(b'\n', &data[pos..]) {
            Some(p) => pos + p,
            None => len,
        };

        // Trim trailing \r (Windows CRLF)
        let end = if line_end > pos && data[line_end - 1] == b'\r' {
            line_end - 1
        } else {
            line_end
        };

        // SAFETY: trace lines are ASCII (ARM64 disassembly text from unidbg)
        let raw_line = unsafe { std::str::from_utf8_unchecked(&data[pos..end]) };
        pos = if line_end < len { line_end + 1 } else { len };

        if let Some(t) = t0 {
            t_io += t.elapsed();
        }

        let i = state.line_count;
        state.deps.push(SmallVec::new());

        // Range limiting: skip lines outside [start_seq, end_seq]
        if i < start_seq || end_seq.is_some_and(|end| i > end) {
            state.line_count += 1;
            continue;
        }

        // Parse; unparseable lines get an empty dep set
        let t1 = profile.then(Instant::now);

        let Some(line) = parser::parse_line(raw_line) else {
            if let Some(t) = t1 {
                t_parse += t.elapsed();
            }
            state.line_count += 1;
            continue;
        };

        if let Some(t) = t1 {
            t_parse += t.elapsed();
        }

        // Classify instruction + Determine DEF/USE
        let t2 = profile.then(Instant::now);

        let class = insn_class::classify_and_refine(&line);

        // 收集未知助记符（classify 回退到 Nop 但不属于已知 NOP 指令）
        if class == InsnClass::Nop && !insn_class::is_known_nop(line.mnemonic.as_str()) {
            let entry = state
                .unknown_mnemonics
                .entry(line.mnemonic.as_str().to_string())
                .or_insert((i, 0));
            entry.1 += 1;
        }

        let (defs, uses) = def_use::determine_def_use(class, &line);

        if let Some(t) = t2 {
            t_classify += t.elapsed();
        }

        // --- @LINE target resolution (with fallback) ---
        if let Some(targets) = line_targets.get(&i) {
            for target in targets {
                match target {
                    LineTarget::Reg(reg) => {
                        if defs.contains(reg) {
                            state.resolved_targets.insert((i, target.clone()), i);
                        } else if let Some(&prev) = state.reg_last_def.get(reg) {
                            eprintln!("[info] reg {:?} not DEF'd at line {}, resolved to last DEF at line {}", reg, i + 1, prev + 1);
                            state.resolved_targets.insert((i, target.clone()), prev);
                        } else {
                            bail!(
                                "line {} does not DEF register {:?} and no prior DEF exists",
                                i + 1,
                                reg
                            );
                        }
                    }
                    LineTarget::Mem(addr) => {
                        let is_store = line.mem_op.as_ref().is_some_and(|m| {
                            if !m.is_write {
                                return false;
                            }
                            let width = mem_access_width(class, m.elem_width, &line);
                            (0..width as u64).any(|off| m.abs + off == *addr)
                        });
                        if is_store {
                            state.resolved_targets.insert((i, target.clone()), i);
                        } else if let Some(&(prev, _)) = state.mem_last_def.get(addr) {
                            eprintln!("[info] mem 0x{:x} not STORE'd at line {}, resolved to last STORE at line {}", addr, i + 1, prev + 1);
                            state.resolved_targets.insert((i, target.clone()), prev);
                        } else {
                            bail!("line {} does not STORE to address 0x{:x} and no prior STORE exists", i + 1, addr);
                        }
                    }
                }
            }
        }

        // --- Dependency tracking ---
        let t3 = profile.then(Instant::now);
        let is_pair = class == InsnClass::LoadPair || class == InsnClass::StorePair;

        // For non-pair LOAD: do mem deps (3b) first to determine pass-through,
        // then conditionally skip register deps (3a).
        let is_non_pair_load = !is_pair
            && line.mem_op.as_ref().is_some_and(|m| !m.is_write);
        let mut is_pass_through = false;

        if is_non_pair_load && !no_prune {
            let mem = line.mem_op.as_ref().unwrap();
            let width = mem_access_width(class, mem.elem_width, &line);
            let mut has_init_mem = false;
            let mut all_same_store = true;
            let mut first_store_raw: Option<u32> = None;
            let mut store_val: Option<u64> = None;

            for offset in 0..width as u64 {
                if let Some(&(def_line, def_val)) = state.mem_last_def.get(&(mem.abs + offset)) {
                    push_unique(&mut state.deps[i as usize], def_line);
                    match first_store_raw {
                        None => {
                            first_store_raw = Some(def_line);
                            store_val = Some(def_val);
                        }
                        Some(first) if first != def_line => {
                            all_same_store = false;
                        }
                        _ => {}
                    }
                } else {
                    has_init_mem = true;
                    all_same_store = false;
                }
            }
            if has_init_mem {
                state.init_mem_loads.set(i as usize, true);
            }

            // Pass-through: all bytes from same STORE, both values extracted, values equal
            if all_same_store
                && store_val.is_some()
                && mem.value.is_some()
                && store_val.unwrap() == mem.value.unwrap()
            {
                is_pass_through = true;
                pruned_count += 1;
            }
        }

        // Step 3a: Register data dependencies
        // Skip for pair (handled in 3d) and for pass-through LOADs (address deps pruned)
        if !is_pair && !is_pass_through {
            for r in &uses {
                if let Some(&def_line) = state.reg_last_def.get(r) {
                    push_unique(&mut state.deps[i as usize], def_line);
                }
            }
        }

        // Step 3b: Memory data dependencies
        // Non-pair LOADs with pruning enabled are already handled above;
        // handle: pair LOADs, non-pair LOADs with pruning disabled
        if let Some(ref mem) = line.mem_op {
            if !mem.is_write && !(is_non_pair_load && !no_prune) {
                let width = mem_access_width(class, mem.elem_width, &line);
                let mut has_init_mem = false;
                for offset in 0..width as u64 {
                    if let Some(&(def_line, _)) = state.mem_last_def.get(&(mem.abs + offset)) {
                        if !is_pair {
                            push_unique(&mut state.deps[i as usize], def_line);
                        }
                    } else {
                        has_init_mem = true;
                    }
                }
                if has_init_mem {
                    state.init_mem_loads.set(i as usize, true);
                }
            }
        }

        // Step 3c: Control dependencies (skip for pair — handled in 3d)
        if !is_pair && !data_only {
            if let Some(cb) = state.last_cond_branch {
                push_unique(&mut state.deps[i as usize], cb);
            }
        }

        // Step 3d: Pair-specific split tracking (LoadPair/StorePair)
        if class == InsnClass::LoadPair || class == InsnClass::StorePair {
            if let Some(ref mem) = line.mem_op {
                let ew = mem.elem_width;
                let mut split = PairSplitDeps::default();

                match class {
                    InsnClass::LoadPair => {
                        // half1 mem deps (first elem_width bytes)
                        for offset in 0..ew as u64 {
                            if let Some(&(raw, _)) = state.mem_last_def.get(&(mem.abs + offset)) {
                                push_unique(&mut split.half1_deps, raw);
                            }
                        }
                        // half2 mem deps (second elem_width bytes)
                        for offset in ew as u64..2 * ew as u64 {
                            if let Some(&(raw, _)) = state.mem_last_def.get(&(mem.abs + offset)) {
                                push_unique(&mut split.half2_deps, raw);
                            }
                        }
                    }
                    InsnClass::StorePair => {
                        // half1: first source register dep
                        if let Some(r) = line.operands.first().and_then(|op| op.as_reg()) {
                            if let Some(&raw) = state.reg_last_def.get(&r) {
                                push_unique(&mut split.half1_deps, raw);
                            }
                        }
                        // half2: second source register dep
                        if let Some(r) = line.operands.get(1).and_then(|op| op.as_reg()) {
                            if let Some(&raw) = state.reg_last_def.get(&r) {
                                push_unique(&mut split.half2_deps, raw);
                            }
                        }
                    }
                    _ => unreachable!(),
                }

                // shared: base reg dep
                if let Some(base) = line.base_reg {
                    if let Some(&raw) = state.reg_last_def.get(&base) {
                        push_unique(&mut split.shared, raw);
                    }
                }
                // shared: control dep
                if !data_only {
                    if let Some(cb) = state.last_cond_branch {
                        push_unique(&mut split.shared, cb);
                    }
                }

                state.pair_split.insert(i, split);
            }
        }

        if let Some(t) = t3 {
            t_deps += t.elapsed();
        }

        // --- State update ---
        let t4 = profile.then(Instant::now);

        // Step 4: Update regLastDef
        if class == InsnClass::LoadPair {
            // LoadPair: tag half1 (no tag), half2 (PAIR_HALF2_BIT), writeback base (PAIR_SHARED_BIT)
            if defs.len() >= 2 {
                state.reg_last_def.insert(defs[0], i);
                state.reg_last_def.insert(defs[1], i | PAIR_HALF2_BIT);
            }
            // writeback base is the 3rd DEF (if present)
            if defs.len() >= 3 {
                state.reg_last_def.insert(defs[2], i | PAIR_SHARED_BIT);
            }
        } else if class == InsnClass::StorePair {
            // StorePair: writeback base is the only DEF (if present)
            for r in &defs {
                state.reg_last_def.insert(*r, i | PAIR_SHARED_BIT);
            }
        } else {
            for r in &defs {
                state.reg_last_def.insert(*r, i);
            }
        }

        // Step 5: Update memLastDef (byte granularity, with masked value for pruning)
        if let Some(ref mem) = line.mem_op {
            if mem.is_write {
                let masked_val = mem.value.unwrap_or(0);
                if class == InsnClass::StorePair {
                    // StorePair: tag second half bytes with PAIR_HALF2_BIT
                    // value=0 for pair (value extraction skipped, won't match in pruning)
                    let ew = mem.elem_width;
                    for offset in 0..ew as u64 {
                        state.mem_last_def.insert(mem.abs + offset, (i, masked_val));
                    }
                    for offset in ew as u64..2 * ew as u64 {
                        state
                            .mem_last_def
                            .insert(mem.abs + offset, (i | PAIR_HALF2_BIT, 0));
                    }
                } else {
                    let width = mem_access_width(class, mem.elem_width, &line);
                    for offset in 0..width as u64 {
                        state.mem_last_def.insert(mem.abs + offset, (i, masked_val));
                    }
                }
            }
        }

        // Step 6: Update lastCondBranch
        match class {
            InsnClass::CondBranchNzcv | InsnClass::CondBranchReg => {
                state.last_cond_branch = Some(i);
            }
            _ => {}
        }

        if let Some(t) = t4 {
            t_update += t.elapsed();
        }

        state.parsed_count += 1;
        state.line_count += 1;
    }

    // Print profiling results
    if profile {
        let total = t_io + t_parse + t_classify + t_deps + t_update;
        let total_s = total.as_secs_f64();
        let pct = |d: Duration| {
            if total_s > 0.0 {
                d.as_secs_f64() / total_s * 100.0
            } else {
                0.0
            }
        };
        eprintln!("\n[profile] ─── 扫描阶段内部耗时分解 ───");
        eprintln!(
            "[profile] I/O (mmap+memchr): {:7.2}s ({:5.1}%)",
            t_io.as_secs_f64(),
            pct(t_io)
        );
        eprintln!(
            "[profile] 解析 (parse_line): {:7.2}s ({:5.1}%)",
            t_parse.as_secs_f64(),
            pct(t_parse)
        );
        eprintln!(
            "[profile] 分类+DEF/USE     : {:7.2}s ({:5.1}%)",
            t_classify.as_secs_f64(),
            pct(t_classify)
        );
        eprintln!(
            "[profile] 依赖追踪         : {:7.2}s ({:5.1}%)",
            t_deps.as_secs_f64(),
            pct(t_deps)
        );
        eprintln!(
            "[profile] 状态更新         : {:7.2}s ({:5.1}%)",
            t_update.as_secs_f64(),
            pct(t_update)
        );
        eprintln!("[profile] 合计 (含计时开销): {:7.2}s", total_s);
        eprintln!("[profile] 已解析行数       : {}", state.parsed_count);
        eprintln!("[profile] 总行数           : {}", state.line_count);
        eprintln!("[profile] mem_last_def 条目: {}", state.mem_last_def.len());
        eprintln!(
            "[profile] deps 总边数      : {}",
            state.deps.iter().map(|d| d.len()).sum::<usize>()
        );
        eprintln!("[profile] pass-through 剪枝: {} loads", pruned_count);
        eprintln!("[profile] ──────────────────────────────");
    }

    // Check for line targets that were never reached
    for (&line_num, targets) in line_targets {
        if line_num >= state.line_count {
            if let Some(target) = targets.first() {
                match target {
                    LineTarget::Reg(reg) => bail!(
                        "line {} out of range (trace has {} lines), target: {:?}",
                        line_num + 1,
                        state.line_count,
                        reg
                    ),
                    LineTarget::Mem(addr) => bail!(
                        "line {} out of range (trace has {} lines), target: 0x{:x}",
                        line_num + 1,
                        state.line_count,
                        addr
                    ),
                }
            }
        }
    }

    Ok(state)
}

/// 计算内存访问的总宽度（字节）。
///
/// - 配对指令 (ldp/stp): `elem_width * 2`
/// - SIMD 多寄存器 (ld1 {v0,v1,...}): `elem_width * 数据寄存器数`
/// - 其它: `elem_width`
pub fn mem_access_width(class: InsnClass, elem_width: u8, line: &super::types::ParsedLine) -> u8 {
    match class {
        InsnClass::LoadPair | InsnClass::StorePair => elem_width.saturating_mul(2),
        InsnClass::SimdLoad | InsnClass::SimdStore => {
            // 统计 base_reg 之前的寄存器操作数数量（即数据寄存器）
            let data_reg_count = line.base_reg.map_or(1u8, |base| {
                line.operands
                    .iter()
                    .take_while(|op: &&super::types::Operand| op.as_reg() != Some(base))
                    .filter(|op: &&super::types::Operand| op.as_reg().is_some())
                    .count() as u8
            });
            elem_width.saturating_mul(data_reg_count.max(1))
        }
        _ => elem_width,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::taint::types::RegId;

    // =========================================================================
    // Test trace line builders
    // =========================================================================

    fn mov_line(rd: &str, val: u64) -> String {
        format!(
            r#"[00:00:00 001][lib.so 0x100] [d2800000] 0x40000100: "mov {rd}, #{val}" => {rd}=0x{val:x}"#,
        )
    }

    fn add_line(rd: &str, rn: &str, rm: &str) -> String {
        format!(
            r#"[00:00:00 001][lib.so 0x108] [8b000000] 0x40000108: "add {rd}, {rn}, {rm}" {rn}=0x1 {rm}=0x2 => {rd}=0x3"#,
        )
    }

    fn str_line(rt: &str, base: &str, abs: u64) -> String {
        format!(
            r#"[00:00:00 001][lib.so 0x10c] [f9000000] 0x4000010c: "str {rt}, [{base}, #0x10]" ; mem[WRITE] abs=0x{abs:x} {rt}=0x3 {base}=0x{:x} => {rt}=0x3"#,
            abs - 0x10,
        )
    }

    fn ldr_line(rt: &str, base: &str, abs: u64) -> String {
        format!(
            r#"[00:00:00 001][lib.so 0x110] [f9400000] 0x40000110: "ldr {rt}, [{base}, #0x10]" ; mem[READ] abs=0x{abs:x} {base}=0x{:x} => {rt}=0x3"#,
            abs - 0x10,
        )
    }

    // =========================================================================
    // Test: simple register chain
    // =========================================================================

    #[test]
    fn test_simple_register_chain() {
        let lines = vec![
            mov_line("x8", 5),
            mov_line("x9", 10),
            add_line("x0", "x8", "x9"),
        ];
        let trace = lines.join("\n");
        let state = scan_from_string(&trace, false).unwrap();

        assert_eq!(state.line_count, 3);
        // add x0 should have last def at line 2
        assert_eq!(state.reg_last_def.get(&RegId::X0), Some(&2));
        // add x0, x8, x9 depends on mov x8 (line 0) and mov x9 (line 1)
        assert!(state.deps[2].contains(&0), "add should depend on mov x8");
        assert!(state.deps[2].contains(&1), "add should depend on mov x9");
    }

    // =========================================================================
    // Test: memory dependency (store -> load)
    // =========================================================================

    #[test]
    fn test_memory_dependency() {
        let lines = vec![
            mov_line("x8", 42),
            str_line("x8", "sp", 0xbffff010),
            ldr_line("x0", "sp", 0xbffff010),
        ];
        let trace = lines.join("\n");
        let state = scan_from_string(&trace, false).unwrap();

        // ldr (line 2) depends on str (line 1) via memory
        assert!(
            state.deps[2].contains(&1),
            "ldr should depend on str via memory"
        );
        // str (line 1) depends on mov x8 (line 0) via register
        assert!(
            state.deps[1].contains(&0),
            "str should depend on mov x8 via register"
        );
    }

    // =========================================================================
    // Test: control dependency (cmp -> b.eq -> next instruction)
    // =========================================================================

    #[test]
    fn test_control_dependency() {
        let lines = vec![
            r#"[00:00:00 001][lib.so 0x300] [6b09011f] 0x40000300: "cmp x8, x9" x8=0x5 x9=0xa => nzcv=0x80000000"#.to_string(),
            r#"[00:00:00 001][lib.so 0x304] [54000040] 0x40000304: "b.eq #0x4000030c" nzcv=0x40000000"#.to_string(),
            mov_line("x0", 1),
        ];
        let trace = lines.join("\n");
        let state = scan_from_string(&trace, false).unwrap();

        // b.eq (line 1) is a conditional branch -> sets lastCondBranch
        // mov x0 (line 2) should have control dep on b.eq (line 1)
        assert!(
            state.deps[2].contains(&1),
            "mov after b.eq should have control dep"
        );
    }

    // =========================================================================
    // Test: data_only mode disables control deps
    // =========================================================================

    #[test]
    fn test_data_only_no_control_dep() {
        let lines = vec![
            r#"[00:00:00 001][lib.so 0x300] [6b09011f] 0x40000300: "cmp x8, x9" x8=0x5 x9=0xa => nzcv=0x80000000"#.to_string(),
            r#"[00:00:00 001][lib.so 0x304] [54000040] 0x40000304: "b.eq #0x4000030c" nzcv=0x40000000"#.to_string(),
            mov_line("x0", 1),
        ];
        let trace = lines.join("\n");
        let state = scan_from_string(&trace, true).unwrap();

        // In data_only mode, no control dependency edge from b.eq to mov
        assert!(
            !state.deps[2].contains(&1),
            "data_only should suppress control deps"
        );
    }

    // =========================================================================
    // Test: b.eq itself depends on cmp via nzcv register
    // =========================================================================

    #[test]
    fn test_cond_branch_depends_on_flag_setter() {
        let lines = vec![
            r#"[00:00:00 001][lib.so 0x300] [6b09011f] 0x40000300: "cmp x8, x9" x8=0x5 x9=0xa => nzcv=0x80000000"#.to_string(),
            r#"[00:00:00 001][lib.so 0x304] [54000040] 0x40000304: "b.eq #0x4000030c" nzcv=0x40000000"#.to_string(),
        ];
        let trace = lines.join("\n");
        let state = scan_from_string(&trace, false).unwrap();

        // b.eq (line 1) USEs nzcv, which was DEF'd by cmp (line 0)
        assert!(
            state.deps[1].contains(&0),
            "b.eq should depend on cmp via nzcv"
        );
    }

    // =========================================================================
    // Test: regLastDef is updated correctly
    // =========================================================================

    #[test]
    fn test_reg_last_def_updated() {
        let lines = vec![
            mov_line("x8", 1),
            mov_line("x8", 2), // overwrites x8
            mov_line("x0", 3),
        ];
        let trace = lines.join("\n");
        let state = scan_from_string(&trace, false).unwrap();

        // x8 last def should be line 1 (second mov)
        assert_eq!(state.reg_last_def.get(&RegId::X8), Some(&1));
        // x0 last def should be line 2
        assert_eq!(state.reg_last_def.get(&RegId::X0), Some(&2));
    }

    // =========================================================================
    // Test: unparseable lines are skipped
    // =========================================================================

    #[test]
    fn test_unparseable_lines_skipped() {
        let lines = vec![
            "random log line that doesn't match".to_string(),
            mov_line("x0", 42),
        ];
        let trace = lines.join("\n");
        let state = scan_from_string(&trace, false).unwrap();

        assert_eq!(state.line_count, 2);
        // The unparseable line has empty deps
        assert!(state.deps[0].is_empty());
        // mov x0 at line 1 has no deps (no prior defs)
        assert!(state.deps[1].is_empty());
        assert_eq!(state.reg_last_def.get(&RegId::X0), Some(&1));
    }

    // =========================================================================
    // Test: push_unique deduplication
    // =========================================================================

    #[test]
    fn test_push_unique_dedup() {
        let mut sv: SmallVec<[u32; 4]> = SmallVec::new();
        push_unique(&mut sv, 5);
        push_unique(&mut sv, 5);
        push_unique(&mut sv, 3);
        push_unique(&mut sv, 5);
        assert_eq!(sv.as_slice(), &[5, 3]);
    }

    // =========================================================================
    // Test: SimdLaneLoad refinement (ld1 lane → read-modify-write)
    // =========================================================================

    #[test]
    fn test_simd_lane_load_refinement() {
        let lines = vec![
            r#"[00:00:00 001][lib.so 0x100] [4f000400] 0x40000100: "movi v0.4s, #0" => q0=0x0"#.to_string(),
            r#"[00:00:00 001][lib.so 0x104] [0d401de0] 0x40000104: "ld1 {v0.s}[1], [x15]" ; mem[READ] abs=0x40500000 q0=0x0 x15=0x40500000 => q0=0x100"#.to_string(),
        ];
        let trace = lines.join("\n");
        let state = scan_from_string(&trace, true).unwrap();

        // ld1 lane (line 1) should depend on movi (line 0) via v0 old value (read-modify-write)
        assert!(
            state.deps[1].contains(&0),
            "ld1 lane should depend on prior v0 def (read-modify-write)"
        );
    }

    // =========================================================================
    // Test: SysRegNzcvRead refinement (mrs x0, nzcv → USE=nzcv)
    // =========================================================================

    #[test]
    fn test_sysreg_nzcv_read_refinement() {
        let lines = vec![
            r#"[00:00:00 001][lib.so 0x300] [6b09011f] 0x40000300: "cmp x8, x9" x8=0x5 x9=0xa => nzcv=0x80000000"#.to_string(),
            r#"[00:00:00 001][lib.so 0x304] [d53b4200] 0x40000304: "mrs x0, nzcv" nzcv=0x80000000 => x0=0x80000000"#.to_string(),
        ];
        let trace = lines.join("\n");
        let state = scan_from_string(&trace, true).unwrap();

        // mrs nzcv (line 1) should depend on cmp (line 0) via nzcv
        assert!(
            state.deps[1].contains(&0),
            "mrs x0, nzcv should depend on cmp via nzcv register"
        );
    }

    // =========================================================================
    // Test: scan_with_range — start_seq only
    // =========================================================================

    #[test]
    fn test_scan_with_start_seq() {
        let lines = vec![
            mov_line("x8", 5),
            mov_line("x9", 10),
            add_line("x0", "x8", "x9"),
        ];
        let trace = lines.join("\n");
        let state = scan_from_string_with_range(&trace, false, 2, None).unwrap();

        assert_eq!(state.line_count, 3);
        assert!(state.deps[0].is_empty());
        assert!(state.deps[1].is_empty());
        assert!(state.deps[2].is_empty()); // no prior defs in range
        assert_eq!(state.reg_last_def.get(&RegId::X0), Some(&2));
        assert_eq!(state.reg_last_def.get(&RegId::X8), None);
    }

    // =========================================================================
    // Test: scan_with_range — end_seq only
    // =========================================================================

    #[test]
    fn test_scan_with_end_seq() {
        let lines = vec![
            mov_line("x8", 5),
            mov_line("x9", 10),
            add_line("x0", "x8", "x9"),
        ];
        let trace = lines.join("\n");
        let state = scan_from_string_with_range(&trace, false, 0, Some(1)).unwrap();

        assert_eq!(state.line_count, 3);
        assert_eq!(state.reg_last_def.get(&RegId::X8), Some(&0));
        assert_eq!(state.reg_last_def.get(&RegId::X9), Some(&1));
        assert_eq!(state.reg_last_def.get(&RegId::X0), None);
        assert!(state.deps[2].is_empty());
    }

    // =========================================================================
    // Test: @LINE target validation — register DEF valid
    // =========================================================================

    #[test]
    fn test_scan_reg_at_line_valid() {
        use crate::taint::types::LineTarget;
        use std::collections::HashMap;

        let lines = vec![mov_line("x8", 5)];
        let trace = lines.join("\n");
        let mut targets = HashMap::new();
        targets.insert(0u32, vec![LineTarget::Reg(RegId::X8)]);

        let state = scan_from_string_with_targets(&trace, false, 0, None, &targets).unwrap();
        assert_eq!(
            state.resolved_targets.get(&(0, LineTarget::Reg(RegId::X8))),
            Some(&0),
            "should resolve to same line when DEF is present"
        );
    }

    // =========================================================================
    // Test: @LINE target validation — register DEF invalid
    // =========================================================================

    #[test]
    fn test_scan_reg_at_line_invalid() {
        use crate::taint::types::LineTarget;
        use std::collections::HashMap;

        let lines = vec![mov_line("x8", 5)];
        let trace = lines.join("\n");
        let mut targets = HashMap::new();
        targets.insert(0u32, vec![LineTarget::Reg(RegId::X0)]);

        let result = scan_from_string_with_targets(&trace, false, 0, None, &targets);
        assert!(result.is_err(), "should fail: line 0 does not DEF x0");
    }

    // =========================================================================
    // Test: @LINE target validation — memory STORE valid
    // =========================================================================

    #[test]
    fn test_scan_mem_at_line_valid() {
        use crate::taint::types::LineTarget;
        use std::collections::HashMap;

        let lines = vec![str_line("x8", "sp", 0xbffff010)];
        let trace = lines.join("\n");
        let mut targets = HashMap::new();
        targets.insert(0u32, vec![LineTarget::Mem(0xbffff010)]);

        let state = scan_from_string_with_targets(&trace, false, 0, None, &targets).unwrap();
        assert_eq!(
            state
                .resolved_targets
                .get(&(0, LineTarget::Mem(0xbffff010))),
            Some(&0),
            "should resolve to same line when STORE is present"
        );
    }

    // =========================================================================
    // Test: @LINE target validation — memory STORE invalid
    // =========================================================================

    #[test]
    fn test_scan_mem_at_line_invalid() {
        use crate::taint::types::LineTarget;
        use std::collections::HashMap;

        let lines = vec![str_line("x8", "sp", 0xbffff010)];
        let trace = lines.join("\n");
        let mut targets = HashMap::new();
        targets.insert(0u32, vec![LineTarget::Mem(0xdeadbeef)]);

        let result = scan_from_string_with_targets(&trace, false, 0, None, &targets);
        assert!(
            result.is_err(),
            "should fail: line 0 does not STORE to 0xdeadbeef"
        );
    }

    // =========================================================================
    // Test: @LINE target validation — line out of range
    // =========================================================================

    #[test]
    fn test_scan_line_target_out_of_range() {
        use crate::taint::types::LineTarget;
        use std::collections::HashMap;

        let lines = vec![mov_line("x8", 5)];
        let trace = lines.join("\n");
        let mut targets = HashMap::new();
        targets.insert(999u32, vec![LineTarget::Reg(RegId::X8)]);

        let result = scan_from_string_with_targets(&trace, false, 0, None, &targets);
        assert!(result.is_err(), "should fail: line 999 out of range");
    }

    // =========================================================================
    // Test: @LINE fallback — register DEF not at target line, resolves to prior
    // =========================================================================

    #[test]
    fn test_scan_reg_at_line_fallback() {
        use crate::taint::types::LineTarget;
        use std::collections::HashMap;

        // line 0: mov x8 (DEFs x8), line 1: str x8 (USEs x8)
        let lines = vec![mov_line("x8", 5), str_line("x8", "sp", 0x100)];
        let trace = lines.join("\n");
        let mut targets = HashMap::new();
        targets.insert(1u32, vec![LineTarget::Reg(RegId::X8)]);

        let state = scan_from_string_with_targets(&trace, true, 0, None, &targets).unwrap();
        let resolved = state.resolved_targets.get(&(1, LineTarget::Reg(RegId::X8)));
        assert_eq!(resolved, Some(&0));
    }

    // =========================================================================
    // Test: @LINE fallback — memory STORE not at target line, resolves to prior
    // =========================================================================

    #[test]
    fn test_scan_mem_at_line_fallback() {
        use crate::taint::types::LineTarget;
        use std::collections::HashMap;

        // line 0: str x8 to 0x100, line 1: mov x9 (no mem op)
        let lines = vec![str_line("x8", "sp", 0x100), mov_line("x9", 10)];
        let trace = lines.join("\n");
        let mut targets = HashMap::new();
        targets.insert(1u32, vec![LineTarget::Mem(0x100)]);

        let state = scan_from_string_with_targets(&trace, true, 0, None, &targets).unwrap();
        let resolved = state.resolved_targets.get(&(1, LineTarget::Mem(0x100)));
        assert_eq!(resolved, Some(&0));
    }

    // =========================================================================
    // Test: @LINE fallback — no prior DEF exists, should error
    // =========================================================================

    #[test]
    fn test_scan_reg_at_line_no_prior_def() {
        use crate::taint::types::LineTarget;
        use std::collections::HashMap;

        let lines = vec![mov_line("x9", 5)];
        let trace = lines.join("\n");
        let mut targets = HashMap::new();
        targets.insert(0u32, vec![LineTarget::Reg(RegId::X8)]);

        let result = scan_from_string_with_targets(&trace, true, 0, None, &targets);
        assert!(result.is_err());
    }

    // =========================================================================
    // Test: scan_with_range — start_seq and end_seq
    // =========================================================================

    #[test]
    fn test_scan_with_start_and_end_seq() {
        let lines = vec![
            mov_line("x8", 5),
            mov_line("x9", 10),
            add_line("x0", "x8", "x9"),
        ];
        let trace = lines.join("\n");
        let state = scan_from_string_with_range(&trace, false, 1, Some(1)).unwrap();

        assert_eq!(state.line_count, 3);
        assert_eq!(state.reg_last_def.get(&RegId::X9), Some(&1));
        assert_eq!(state.reg_last_def.get(&RegId::X8), None);
        assert_eq!(state.reg_last_def.get(&RegId::X0), None);
    }

    #[test]
    fn test_scan_empty_trace() {
        let state = scan_from_string("", false).unwrap();
        assert_eq!(state.line_count, 0);
        assert!(state.deps.is_empty());
    }

    #[test]
    fn test_scan_blank_lines_only() {
        let trace = "\n\n\n";
        let state = scan_from_string(trace, false).unwrap();
        assert_eq!(state.line_count, 3);
    }

    #[test]
    fn test_scan_unparseable_lines() {
        let trace = "this is not a valid trace line\nanother bad line";
        let state = scan_from_string(trace, false).unwrap();
        assert_eq!(state.line_count, 2);
        assert!(state.deps[0].is_empty());
        assert!(state.deps[1].is_empty());
    }

    #[test]
    fn test_mem_access_width_simd_multi_reg() {
        use crate::taint::types::{Mnemonic, Operand, ParsedLine};

        /// 构建一个含寄存器操作数和 base_reg 的最小 ParsedLine
        fn make_line(mnemonic: &str, regs: &[RegId], base: RegId) -> ParsedLine {
            ParsedLine {
                mnemonic: Mnemonic::new(mnemonic),
                operands: regs.iter().map(|&r| Operand::Reg(r)).collect(),
                base_reg: Some(base),
                ..Default::default()
            }
        }

        // ld1 {v0, v1}, [x0] — 2 个数据寄存器 × 16 = 32
        let line = make_line("ld1", &[RegId::V0, RegId::V1, RegId::X0], RegId::X0);
        assert_eq!(mem_access_width(InsnClass::SimdLoad, 16, &line), 32);

        // ld1 {v0, v1, v2, v3}, [x0] — 4 个数据寄存器 × 16 = 64
        let line = make_line(
            "ld1",
            &[RegId::V0, RegId::V1, RegId::V2, RegId::V3, RegId::X0],
            RegId::X0,
        );
        assert_eq!(mem_access_width(InsnClass::SimdLoad, 16, &line), 64);

        // ldr q0, [x0] — 单寄存器，不触发多寄存器扩展
        let line = make_line("ldr", &[RegId::V0, RegId::X0], RegId::X0);
        assert_eq!(mem_access_width(InsnClass::SimdLoad, 16, &line), 16);

        // ldp x0, x1, [x2] — 配对指令，8 × 2 = 16
        let line = make_line("ldp", &[RegId::X0, RegId(1), RegId(2)], RegId(2));
        assert_eq!(mem_access_width(InsnClass::LoadPair, 8, &line), 16);

        // ldr x0, [x1] — 普通标量加载，宽度不变
        let line = make_line("ldr", &[RegId::X0, RegId(1)], RegId(1));
        assert_eq!(mem_access_width(InsnClass::LoadReg, 8, &line), 8);
    }

    #[test]
    fn test_unknown_mnemonic_collected() {
        let trace = r#"[00:00:00 001][lib.so 0x100] [d2800000] 0x40000100: "xyzzy v0, v1, v2" => v0=0x0"#;
        let state = scan_from_string(trace, true).unwrap();
        assert_eq!(state.unknown_mnemonics.len(), 1);
        let (first_line, count) = state.unknown_mnemonics.get("xyzzy").unwrap();
        assert_eq!(*first_line, 0);
        assert_eq!(*count, 1);
    }

    #[test]
    fn test_known_nop_not_collected() {
        let trace = r#"[00:00:00 001][lib.so 0x100] [d5033f9f] 0x40000100: "dmb ish""#;
        let state = scan_from_string(trace, true).unwrap();
        assert!(state.unknown_mnemonics.is_empty());
    }

    // =========================================================================
    // Test: init_mem_loads — load from never-stored address is marked
    // =========================================================================

    #[test]
    fn test_init_mem_load_marked() {
        let trace = r#"[00:00:00 001][lib.so 0x100] [f9400be0] 0x40000100: "ldr x0, [sp, #0x10]" ; mem[READ] abs=0xbffff010 sp=0xbffff000 => x0=0x2a"#;
        let state = scan_from_string(trace, true).unwrap();
        assert!(state.init_mem_loads[0], "load from never-stored address should be marked");
    }

    // =========================================================================
    // Test: init_mem_loads — load from previously-stored address is NOT marked
    // =========================================================================

    #[test]
    fn test_stored_mem_load_not_marked() {
        let trace = [
            r#"[00:00:00 001][lib.so 0x100] [d2800548] 0x40000100: "mov x8, #42" => x8=0x2a"#,
            r#"[00:00:00 001][lib.so 0x104] [f9000be8] 0x40000104: "str x8, [sp, #0x10]" ; mem[WRITE] abs=0xbffff010 x8=0x2a sp=0xbffff000 => x8=0x2a"#,
            r#"[00:00:00 001][lib.so 0x108] [f9400be0] 0x40000108: "ldr x0, [sp, #0x10]" ; mem[READ] abs=0xbffff010 sp=0xbffff000 => x0=0x2a"#,
        ].join("\n");
        let state = scan_from_string(&trace, true).unwrap();
        assert!(!state.init_mem_loads[2], "load from previously-stored address should NOT be marked");
    }
}
