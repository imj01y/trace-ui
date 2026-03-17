pub mod types;
pub mod parser;
pub mod gumtrace_parser;
pub mod insn_class;
pub mod def_use;
pub mod scanner;
pub mod slicer;
pub mod call_tree;
pub mod mem_access;
pub mod reg_checkpoint;
pub mod strings;

use memchr::memchr;
use rustc_hash::FxHashMap;

use crate::line_index::LineIndexBuilder;
use crate::phase2;
use crate::state::Phase2State;
use call_tree::CallTreeBuilder;
use insn_class::InsnClass;
use mem_access::{MemAccessIndex, MemAccessRecord, MemRw};
use reg_checkpoint::RegCheckpoints;
use crate::taint::strings::StringBuilder;
use scanner::{
    mem_access_width, push_unique, PairSplitDeps, RegLastDef, ScanState, PAIR_HALF2_BIT,
    PAIR_SHARED_BIT,
};
use types::RegId;

pub type ProgressFn = Box<dyn Fn(usize, usize) + Send>;

const CHECKPOINT_INTERVAL: u32 = 1000;

/// scan_unified 的返回结果
pub struct ScanResult {
    pub scan_state: ScanState,
    pub phase2: Phase2State,
    pub line_index: crate::line_index::LineIndex,
    pub format: types::TraceFormat,
    pub call_annotations: std::collections::HashMap<u32, gumtrace_parser::CallAnnotation>,
    pub consumed_seqs: Vec<u32>,
}

/// 统一扫描：单次文件遍历同时构建 ScanState（依赖图）、Phase2State（CallTree/MemAccess/RegCheckpoints）
/// 和 LineIndex（采样行偏移索引）。
///
/// 合并了 scanner::scan_pass1_bytes、phase2::build_phase2 和 LineIndex::build 的逻辑，
/// 避免重复解析和多次遍历。
pub fn scan_unified(
    data: &[u8],
    data_only: bool,
    no_prune: bool,
    skip_strings: bool,
    progress_fn: Option<ProgressFn>,
) -> anyhow::Result<ScanResult> {
    // ── 格式检测 ──
    let format = gumtrace_parser::detect_format(data);

    // ── ScanState 初始化（来自 scanner.rs） ──
    // 用文件大小估算行数（平均每行 ~110 字节），避免预扫描整个文件
    let line_count_est = data.len() / 110 + 1;

    let mut state = ScanState {
        reg_last_def: RegLastDef::new(),
        mem_last_def: scanner::MemLastDef::default(),
        last_cond_branch: None,
        deps: scanner::CompactDeps::with_capacity(line_count_est, line_count_est * 2),
        line_count: 0,
        parsed_count: 0,
        mem_op_count: 0,
        resolved_targets: FxHashMap::default(),
        unknown_mnemonics: FxHashMap::default(),
        init_mem_loads: bitvec::prelude::BitVec::with_capacity(line_count_est),
        pair_split: FxHashMap::default(),
    };

    // ── Phase2 初始化（来自 phase2.rs） ──
    let mut ct_builder = CallTreeBuilder::new();
    let mut mem_idx = MemAccessIndex::new();
    let mut string_builder = if skip_strings { None } else { Some(StringBuilder::new()) };
    let mut reg_ckpts = RegCheckpoints::new(CHECKPOINT_INTERVAL);
    let mut reg_values = [u64::MAX; RegId::COUNT];

    // 保存初始检查点
    reg_ckpts.save_checkpoint(&reg_values);

    // ── Gumtrace 状态变量 ──
    let mut call_annotations: std::collections::HashMap<u32, gumtrace_parser::CallAnnotation> = std::collections::HashMap::new();
    let mut consumed_seqs: Vec<u32> = Vec::new();
    let mut pending_call_seq: Option<u32> = None;
    let mut current_annotation: Option<(u32, gumtrace_parser::CallAnnotation)> = None;

    // BLR 后需要检测：如果下一行地址 = BLR的PC+4，说明是 unidbg 拦截调用（无函数体）
    let mut blr_pending_pc: Option<u64> = None;

    // ── LineIndex builder ──
    let mut li_builder = LineIndexBuilder::with_capacity_hint(line_count_est);

    let mut pos = 0usize;
    let len = data.len();
    let progress_interval = len / 100 + 1;
    let mut last_report = 0usize;

    // ── 主循环 ──
    while pos < len {
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

        // LineIndex: 记录行偏移
        li_builder.add_line(pos as u64);

        pos = if line_end < len { line_end + 1 } else { len };

        // ── Gumtrace special line early interception (before deps.start_row) ──
        if format == types::TraceFormat::Gumtrace && gumtrace_parser::is_special_line(raw_line) {
            let i = state.line_count;
            // Special lines still occupy a row in deps (keep indices aligned)
            state.deps.start_row();
            state.init_mem_loads.push(false);

            if let Some(special) = gumtrace_parser::parse_special_line(raw_line) {
                consumed_seqs.push(i);
                match special {
                    gumtrace_parser::SpecialLine::CallFunc { name, is_jni, .. } => {
                        // Flush previous unfinished annotation
                        if let Some((bl_seq, ann)) = current_annotation.take() {
                            ct_builder.set_func_name_by_entry_seq(bl_seq, &ann.func_name);
                            call_annotations.insert(bl_seq, ann);
                        }
                        if let Some(bl_seq) = pending_call_seq.take() {
                            current_annotation = Some((bl_seq, gumtrace_parser::CallAnnotation {
                                func_name: name.to_string(),
                                is_jni,
                                args: Vec::new(),
                                ret_value: None,
                                raw_lines: vec![raw_line.to_string()],
                            }));
                        }
                    }
                    gumtrace_parser::SpecialLine::Arg { index, value } => {
                        if let Some((_, ref mut ann)) = current_annotation {
                            ann.args.push((index.to_string(), value.to_string()));
                            ann.raw_lines.push(raw_line.to_string());
                        }
                    }
                    gumtrace_parser::SpecialLine::Ret { value } => {
                        if let Some((bl_seq, mut ann)) = current_annotation.take() {
                            ann.ret_value = Some(value.to_string());
                            ann.raw_lines.push(raw_line.to_string());
                            ct_builder.set_func_name_by_entry_seq(bl_seq, &ann.func_name);
                            call_annotations.insert(bl_seq, ann);
                        }
                    }
                    gumtrace_parser::SpecialLine::HexDump(_) => {
                        // consumed_seqs already pushed above
                        if let Some((_, ref mut ann)) = current_annotation {
                            ann.raw_lines.push(raw_line.to_string());
                        }
                    }
                }
            }

            state.line_count += 1;
            if state.line_count % CHECKPOINT_INTERVAL == 0 {
                reg_ckpts.save_checkpoint(&reg_values);
            }
            if let Some(ref cb) = progress_fn {
                if pos - last_report >= progress_interval {
                    cb(pos, len);
                    last_report = pos;
                }
            }
            continue;
        }

        let i = state.line_count;
        state.deps.start_row();
        state.init_mem_loads.push(false);

        // ── Phase2: BLR pending 检测（必须在 parse_line 之前，非指令行也需检查） ──
        if let Some(blr_pc) = blr_pending_pc.take() {
            let next_addr = phase2::extract_insn_addr(raw_line);
            if next_addr != 0 {
                // 始终用下一行的实际指令地址更新 func_addr
                ct_builder.update_current_func_addr(next_addr);
                if next_addr == blr_pc + 4 {
                    // 下一行地址 = BLR的PC+4 → unidbg 拦截调用，无函数体
                    ct_builder.on_ret(i.saturating_sub(1));
                }
            } else {
                // 当前行无法提取指令地址（非指令行），保留到下一行再检查
                blr_pending_pc = Some(blr_pc);
            }
        }

        // Parse; unparseable lines get an empty dep set
        let parsed = match format {
            types::TraceFormat::Unidbg => parser::parse_line(raw_line),
            types::TraceFormat::Gumtrace => gumtrace_parser::parse_line_gumtrace(raw_line),
        };
        let Some(line) = parsed else {
            state.line_count += 1;
            // Checkpoint 保存
            if state.line_count % CHECKPOINT_INTERVAL == 0 {
                reg_ckpts.save_checkpoint(&reg_values);
            }
            // 进度报告
            if let Some(ref cb) = progress_fn {
                if pos - last_report >= progress_interval {
                    cb(pos, len);
                    last_report = pos;
                }
            }
            continue;
        };

        // ── 分类 + DEF/USE（scanner 逻辑） ──
        let class = insn_class::classify_and_refine(&line);

        // 收集未知助记符
        if class == InsnClass::Nop && !insn_class::is_known_nop(line.mnemonic.as_str()) {
            let entry = state
                .unknown_mnemonics
                .entry(line.mnemonic.as_str().to_string())
                .or_insert((i, 0));
            entry.1 += 1;
        }

        let (defs, uses) = def_use::determine_def_use(class, &line);

        // ── Scanner: 依赖追踪 ──
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
                if let Some((def_line, def_val)) = state.mem_last_def.get(&(mem.abs + offset)) {
                    state.deps.push_unique(def_line);
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
            }
        }

        // Step 3a: Register data dependencies
        // Skip for pair (handled in 3d) and for pass-through LOADs (address deps pruned)
        if !is_pair && !is_pass_through {
            for r in &uses {
                if let Some(&def_line) = state.reg_last_def.get(r) {
                    state.deps.push_unique(def_line);
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
                    if let Some((def_line, _)) = state.mem_last_def.get(&(mem.abs + offset)) {
                        if !is_pair {
                            state.deps.push_unique(def_line);
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
                state.deps.push_unique(cb | scanner::CONTROL_DEP_BIT);
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
                            if let Some((raw, _)) = state.mem_last_def.get(&(mem.abs + offset)) {
                                push_unique(&mut split.half1_deps, raw);
                            }
                        }
                        // half2 mem deps (second elem_width bytes)
                        for offset in ew as u64..2 * ew as u64 {
                            if let Some((raw, _)) = state.mem_last_def.get(&(mem.abs + offset)) {
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
                        push_unique(&mut split.shared, cb | scanner::CONTROL_DEP_BIT);
                    }
                }

                state.pair_split.insert(i, split);
            }
        }

        // ── Scanner: 状态更新 ──

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

        // ── Phase2: CallTree 逻辑 ──
        match class {
            InsnClass::BranchLink => {
                // BL: 目标地址是立即数操作数
                let target = line
                    .operands
                    .first()
                    .and_then(|op| match op {
                        types::Operand::Imm(val) => Some(*val as u64),
                        _ => None,
                    })
                    .unwrap_or(0);
                ct_builder.on_call(i, target);
                if format == types::TraceFormat::Gumtrace {
                    pending_call_seq = Some(i);
                }
            }
            InsnClass::BranchLinkReg => {
                // BLR: 记录 PC 地址，下一行判断是否为 unidbg 拦截调用
                let target = phase2::extract_blr_target(&line, raw_line);
                let blr_pc = phase2::extract_insn_addr(raw_line);
                ct_builder.on_call(i, target);
                blr_pending_pc = Some(blr_pc);
                if format == types::TraceFormat::Gumtrace {
                    pending_call_seq = Some(i);
                }
            }
            InsnClass::Return => {
                ct_builder.on_ret(i);
            }
            _ => {}
        }

        // ── Phase2: MemAccess 逻辑 ──
        if let Some(ref mem_op) = line.mem_op {
            state.mem_op_count += 1;
            let rw = if mem_op.is_write {
                MemRw::Write
            } else {
                MemRw::Read
            };
            let insn_addr = phase2::extract_insn_addr(raw_line);
            mem_idx.add(
                mem_op.abs,
                MemAccessRecord {
                    seq: i,
                    insn_addr,
                    rw,
                    data: mem_op.value.unwrap_or(0),
                    size: mem_op.elem_width,
                },
            );

            // ── Phase2: 字符串提取 ──
            if let Some(ref mut sb) = string_builder {
                if mem_op.is_write && mem_op.elem_width <= 8 {
                    if let Some(value) = mem_op.value {
                        sb.process_write(mem_op.abs, value, mem_op.elem_width, i);
                    }
                }
            }
        }

        // ── Phase2: RegCheckpoints 逻辑 ──
        if let Some(arrow_pos) = line.arrow_pos {
            phase2::update_reg_values_at(&mut reg_values, raw_line, arrow_pos);
        }

        state.parsed_count += 1;
        state.line_count += 1;

        // Checkpoint 保存（每 CHECKPOINT_INTERVAL 行）
        if state.line_count % CHECKPOINT_INTERVAL == 0 {
            reg_ckpts.save_checkpoint(&reg_values);
        }

        // 进度报告
        if let Some(ref cb) = progress_fn {
            if pos - last_report >= progress_interval {
                cb(pos, len);
                last_report = pos;
            }
        }
    }

    // ── 结束 ──
    // Flush any unfinished CallAnnotation (log truncated or function doesn't return)
    if let Some((bl_seq, ann)) = current_annotation.take() {
        ct_builder.set_func_name_by_entry_seq(bl_seq, &ann.func_name);
        call_annotations.insert(bl_seq, ann);
    }

    let call_tree = ct_builder.finish(state.line_count);
    let string_index = match string_builder {
        Some(sb) => {
            let mut si = sb.finish();
            StringBuilder::fill_xref_counts(&mut si, &mem_idx);
            si
        }
        None => Default::default(),
    };
    let phase2_state = Phase2State {
        call_tree,
        mem_accesses: mem_idx,
        reg_checkpoints: reg_ckpts,
        string_index,
    };
    let line_index = li_builder.finish();

    Ok(ScanResult {
        scan_state: state,
        phase2: phase2_state,
        line_index,
        format,
        call_annotations,
        consumed_seqs,
    })
}
