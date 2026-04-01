use serde::Serialize;
use std::collections::{HashMap, HashSet, VecDeque};

use crate::flat::line_index::LineIndexView;
use crate::flat::scan_view::ScanView;
use crate::scanner::{CONTROL_DEP_BIT, LINE_MASK, PAIR_HALF2_BIT, PAIR_SHARED_BIT};
use trace_parser::gumtrace as gumtrace_parser;
use trace_parser::insn_class;
use trace_parser::insn_class::InsnClass;
use trace_parser::parser;
use trace_parser::types::{Operand, ParsedLine, TraceFormat};
use trace_parser::qbdi as qbdi_parser;
use rustc_hash::FxHashMap;

/// 扁平 DAG：节点数组 + 边列表，无递归嵌套
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DependencyGraph {
    pub nodes: Vec<NodeInfo>,
    pub edges: Vec<[u32; 2]>,   // [parent_seq, child_seq]
    pub root_seq: u32,
    pub total_reachable: u32,   // BFS 可达的总节点数
    pub truncated: bool,        // 是否因超出 max_nodes 而截断
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeInfo {
    pub seq: u32,
    pub expression: String,
    pub asm: String,           // 新增：原始汇编文本
    pub operation: String,
    pub is_leaf: bool,
    pub value: Option<String>,
    pub depth: u32, // BFS 最短深度
}

/// 构建扁平依赖图：BFS 遍历依赖关系，输出去重的节点数组和边列表。
/// `max_nodes` 限制收集的节点数量，超出后仅计数不再收集。
pub fn build_graph(view: &ScanView, start_index: u32, data_only: bool, max_nodes: u32) -> DependencyGraph {
    let n = view.line_count as usize;
    let mut visited = bitvec::prelude::bitvec![0; n];
    let mut pair_visited: FxHashMap<u32, u8> = FxHashMap::default();
    let mut queue: VecDeque<u32> = VecDeque::new();

    // BFS 产出：节点集合（保留发现顺序）+ 去重边列表
    let mut node_seqs: Vec<u32> = Vec::new();
    let mut node_set: HashSet<u32> = HashSet::new();
    let mut edges: Vec<[u32; 2]> = Vec::new();
    let mut edge_set: HashSet<u64> = HashSet::new();
    let mut depth_map: HashMap<u32, u32> = HashMap::new();
    let mut children_exist: HashSet<u32> = HashSet::new();
    let mut collecting = true; // 是否仍在收集节点（未超限）

    let root_line = start_index & LINE_MASK;
    if (root_line as usize) >= n {
        return DependencyGraph {
            nodes: vec![],
            edges: vec![],
            root_seq: root_line,
            total_reachable: 0,
            truncated: false,
        };
    }

    visited.set(root_line as usize, true);
    queue.push_back(start_index);
    node_seqs.push(root_line);
    node_set.insert(root_line);
    depth_map.insert(root_line, 0);
    let mut total_reachable: u32 = 1;

    while let Some(raw) = queue.pop_front() {
        let parent_line = raw & LINE_MASK;
        let parent_depth = if collecting { depth_map.get(&parent_line).copied().unwrap_or(0) } else { 0 };
        let deps = collect_deps(raw, view, data_only);

        for dep_raw in deps {
            let dep_line = dep_raw & LINE_MASK;
            if (dep_line as usize) >= n {
                continue;
            }

            // 收集阶段：记录边（去重），仅对已收集的节点间的边
            if collecting && node_set.contains(&parent_line) {
                let edge_key = ((parent_line as u64) << 32) | (dep_line as u64);
                if edge_set.insert(edge_key) {
                    // 只保留两端都在收集范围内的边（dep_line 可能超限）
                    if node_set.contains(&dep_line) || total_reachable < max_nodes {
                        edges.push([parent_line, dep_line]);
                        children_exist.insert(parent_line);
                    }
                }
            }

            // BFS 入队（只对首次访问的节点入队）
            if view.pair_split.contains_key(&dep_line) {
                let visit_bit = if (dep_raw & PAIR_SHARED_BIT) != 0 {
                    4u8
                } else if (dep_raw & PAIR_HALF2_BIT) != 0 {
                    2u8
                } else {
                    1u8
                };
                let v = pair_visited.entry(dep_line).or_insert(0);
                if *v & visit_bit != 0 {
                    continue;
                }
                *v |= visit_bit;
            } else if visited[dep_line as usize] {
                continue;
            }

            visited.set(dep_line as usize, true);
            total_reachable += 1;

            if collecting {
                if node_set.insert(dep_line) {
                    node_seqs.push(dep_line);
                }
                depth_map.insert(dep_line, parent_depth + 1);
                // 检查是否达到上限
                if node_seqs.len() as u32 >= max_nodes {
                    collecting = false;
                    // 清理收集阶段的数据结构，释放内存
                    node_set.clear();
                    edge_set.clear();
                    depth_map.shrink_to_fit();
                }
            }

            queue.push_back(dep_raw);
        }
    }

    // 重建 node_set 用于 is_leaf 判断
    let node_set_final: HashSet<u32> = node_seqs.iter().copied().collect();
    // 过滤边：只保留两端都在节点集内的
    edges.retain(|[p, c]| node_set_final.contains(p) && node_set_final.contains(c));

    let nodes: Vec<NodeInfo> = node_seqs
        .iter()
        .map(|&seq| NodeInfo {
            seq,
            expression: String::new(),
            asm: String::new(),
            operation: String::new(),
            is_leaf: !children_exist.contains(&seq),
            value: None,
            depth: depth_map.get(&seq).copied().unwrap_or(0),
        })
        .collect();

    let truncated = total_reachable > nodes.len() as u32;

    DependencyGraph {
        nodes,
        edges,
        root_seq: root_line,
        total_reachable,
        truncated,
    }
}

/// 填充所有节点的 expression / operation / value 字段
pub fn populate_graph_info(
    graph: &mut DependencyGraph,
    mmap: &[u8],
    line_index: &LineIndexView,
    format: TraceFormat,
) {
    for node in &mut graph.nodes {
        fill_node_info(node, mmap, line_index, format);
    }
}

fn fill_node_info(
    node: &mut NodeInfo,
    mmap: &[u8],
    line_index: &LineIndexView,
    format: TraceFormat,
) {
    if let Some(raw_line) = line_index.get_line(mmap, node.seq) {
        if let Ok(line_str) = std::str::from_utf8(raw_line) {
            let parsed = match format {
                TraceFormat::Unidbg => parser::parse_line(line_str),
                TraceFormat::Gumtrace => gumtrace_parser::parse_line_gumtrace(line_str),
                TraceFormat::Qbdi => qbdi_parser::parse_line_qbdi(line_str),
            };
            if let Some(ref p) = parsed {
                let cls = insn_class::classify_and_refine(p);
                node.operation = p.mnemonic.to_string();
                node.expression = to_c_expr(cls, p);
                node.asm = extract_asm(line_str, format);

                let changes = extract_changes(line_str);
                if node.is_leaf && !changes.is_empty() {
                    node.value = Some(changes);
                }
            } else {
                node.expression = line_str.trim().to_string();
                node.asm = line_str.trim().to_string();
                node.operation = "unknown".to_string();
            }
        }
    }
}

fn collect_deps(raw: u32, view: &ScanView, data_only: bool) -> Vec<u32> {
    let line = raw & LINE_MASK;
    let mut deps = Vec::new();

    if let Some(split) = view.pair_split.get(&line) {
        if (raw & PAIR_SHARED_BIT) != 0 {
            for &dep in split.shared {
                if data_only && (dep & CONTROL_DEP_BIT) != 0 {
                    continue;
                }
                deps.push(dep);
            }
        } else {
            for &dep in split.shared {
                if data_only && (dep & CONTROL_DEP_BIT) != 0 {
                    continue;
                }
                deps.push(dep);
            }
            let half_deps = if (raw & PAIR_HALF2_BIT) != 0 {
                split.half2_deps
            } else {
                split.half1_deps
            };
            for &dep in half_deps {
                deps.push(dep);
            }
        }
    } else {
        for &dep in view
            .deps
            .row(line as usize)
            .iter()
            .chain(view.deps.patch_row(line as usize).iter())
        {
            if data_only && (dep & CONTROL_DEP_BIT) != 0 {
                continue;
            }
            deps.push(dep);
        }
    }

    deps
}

/// 从 trace 原始行中提取汇编文本（mnemonic + operands）。
fn extract_asm(line_str: &str, format: TraceFormat) -> String {
    match format {
        TraceFormat::Unidbg => {
            // Unidbg 格式: ... "mnemonic operands" ... => ...
            // 提取双引号之间的内容
            if let Some(start) = line_str.find('"') {
                if let Some(end) = line_str[start + 1..].find('"') {
                    return line_str[start + 1..start + 1 + end].trim().to_string();
                }
            }
            String::new()
        }
        TraceFormat::Gumtrace => {
            // Gumtrace 格式: [module] 0xABS!0xOFFSET mnemonic operands ; ...
            let rest = if let Some(pos) = line_str.find("] ") {
                &line_str[pos + 2..]
            } else {
                return String::new();
            };
            let insn_start = rest.find('!')
                .and_then(|bang| rest[bang + 1..].find(' ').map(|p| bang + 1 + p + 1))
                .unwrap_or(0);
            if insn_start == 0 || insn_start >= rest.len() {
                return String::new();
            }
            let insn_end = rest[insn_start..].find(';')
                .map(|p| insn_start + p)
                .unwrap_or(rest.len());
            rest[insn_start..insn_end].trim().to_string()
        }
        TraceFormat::Qbdi => {
            // QBDI 格式: 0xADDR[ module+0xOFF]: mnemonic operands; ...
            if !line_str.starts_with("0x") {
                return String::new();
            }
            let colon_space = line_str.find(": ");
            let insn_start = colon_space.map(|p| p + 2).unwrap_or(0);
            if insn_start == 0 || insn_start >= line_str.len() {
                return String::new();
            }
            let insn_end = line_str[insn_start..].find(';')
                .map(|p| insn_start + p)
                .unwrap_or(line_str.len());
            line_str[insn_start..insn_end].trim().to_string()
        }
    }
}

fn extract_changes(line: &str) -> String {
    if let Some(pos) = line.rfind("=> ") {
        line[pos + 3..].trim().to_string()
    } else {
        String::new()
    }
}

// ─── C 伪代码生成辅助函数 ───────────────────────────────────────────────────

/// 将操作数格式化为字符串（寄存器名或立即数）。
fn fmt_operand(op: &Operand) -> String {
    match op {
        Operand::Reg(r) => format!("{:?}", r),
        Operand::RegLane(r, lane) => format!("{:?}[{}]", r, lane),
        Operand::Imm(v) => {
            if *v < 0 {
                format!("-0x{:x}", -v)
            } else {
                format!("0x{:x}", v)
            }
        }
    }
}

fn op(ops: &[Operand], idx: usize) -> String {
    ops.get(idx).map_or("?".to_string(), fmt_operand)
}

fn mnemonic_to_c_op(m: &str) -> &str {
    match m {
        "add" | "adds" | "adc" | "adcs" | "cmn" => "+",
        "sub" | "subs" | "sbc" | "sbcs" | "cmp" | "neg" | "negs" => "-",
        "and" | "ands" | "tst" => "&",
        "orr" => "|",
        "eor" => "^",
        "orn" => "|~",
        "eon" => "^~",
        "bic" | "bics" => "&~",
        "lsl" | "lslv" => "<<",
        "lsr" | "lsrv" => ">>",
        "asr" | "asrv" => ">>",
        "ror" | "rorv" => "ror",
        "mul" => "*",
        _ => m,
    }
}

fn fallback_expr(m: &str, ops: &[Operand]) -> String {
    if ops.is_empty() {
        return m.to_string();
    }
    if ops.len() == 1 {
        return format!("{}({})", m, fmt_operand(&ops[0]));
    }
    format!(
        "{} = {}({})",
        fmt_operand(&ops[0]),
        m,
        ops[1..].iter().map(fmt_operand).collect::<Vec<_>>().join(", ")
    )
}

fn mem_type_str(m: &str, elem_width: u8) -> &'static str {
    if m.starts_with("ldrsw") {
        return "(int64_t)*(int32_t*)";
    }
    if m.starts_with("ldrsh") {
        return if elem_width == 8 {
            "(int64_t)*(int16_t*)"
        } else {
            "(int32_t)*(int16_t*)"
        };
    }
    if m.starts_with("ldrsb") {
        return if elem_width == 8 {
            "(int64_t)*(int8_t*)"
        } else {
            "(int32_t)*(int8_t*)"
        };
    }
    match elem_width {
        1 => "uint8_t",
        2 => "uint16_t",
        4 => "uint32_t",
        8 => "uint64_t",
        16 => "uint128_t",
        _ => "uint64_t",
    }
}

fn fmt_addr(addr: u64) -> String {
    format!("0x{:x}", addr)
}

// ─── 主函数：ARM64 指令 → C 伪代码字符串 ────────────────────────────────────

fn to_c_expr(class: InsnClass, p: &ParsedLine) -> String {
    let ops = &p.operands;
    let m = p.mnemonic.as_str();

    match class {
        // ALU
        InsnClass::AluReg | InsnClass::AluImm | InsnClass::AluShift => {
            let c_op = mnemonic_to_c_op(m);
            if c_op == "ror" {
                format!("{} = ror({}, {})", op(ops, 0), op(ops, 1), op(ops, 2))
            } else if c_op == "|~" || c_op == "^~" || c_op == "&~" {
                let base_op = &c_op[..1];
                format!(
                    "{} = {} {} ~{}",
                    op(ops, 0),
                    op(ops, 1),
                    base_op,
                    op(ops, 2)
                )
            } else if m == "neg" || m == "negs" {
                format!("{} = -{}", op(ops, 0), op(ops, 1))
            } else if m == "mvn" {
                format!("{} = ~{}", op(ops, 0), op(ops, 1))
            } else if ops.len() >= 3 {
                format!(
                    "{} = {} {} {}",
                    op(ops, 0),
                    op(ops, 1),
                    c_op,
                    op(ops, 2)
                )
            } else if ops.len() == 2 {
                format!("{} = {} {}", op(ops, 0), c_op, op(ops, 1))
            } else {
                fallback_expr(m, ops)
            }
        }

        // Multiply
        InsnClass::Multiply => match m {
            "mul" => format!("{} = {} * {}", op(ops, 0), op(ops, 1), op(ops, 2)),
            "madd" => format!(
                "{} = {} * {} + {}",
                op(ops, 0),
                op(ops, 1),
                op(ops, 2),
                op(ops, 3)
            ),
            "msub" => format!(
                "{} = {} - {} * {}",
                op(ops, 0),
                op(ops, 3),
                op(ops, 1),
                op(ops, 2)
            ),
            "mneg" => format!("{} = -({} * {})", op(ops, 0), op(ops, 1), op(ops, 2)),
            "smull" | "umull" => format!(
                "{} = ({}){} * ({}){} ",
                op(ops, 0),
                if m == "smull" { "int64_t" } else { "uint64_t" },
                op(ops, 1),
                if m == "smull" { "int32_t" } else { "uint32_t" },
                op(ops, 2)
            ),
            "smaddl" | "umaddl" => format!(
                "{} = {} * {} + {}",
                op(ops, 0),
                op(ops, 1),
                op(ops, 2),
                op(ops, 3)
            ),
            "smsubl" | "umsubl" => format!(
                "{} = {} - {} * {}",
                op(ops, 0),
                op(ops, 3),
                op(ops, 1),
                op(ops, 2)
            ),
            "smulh" | "umulh" => {
                format!("{} = mulhi({}, {})", op(ops, 0), op(ops, 1), op(ops, 2))
            }
            _ => fallback_expr(m, ops),
        },

        // Move
        InsnClass::Move => {
            format!("{} = {}", op(ops, 0), op(ops, 1))
        }

        // ScalarRMW
        InsnClass::ScalarRMW => fallback_expr(m, ops),

        // FlagSet
        InsnClass::FlagSet => {
            let c_op = mnemonic_to_c_op(m);
            if m == "tst" {
                format!("nzcv = {} & {}", op(ops, 0), op(ops, 1))
            } else {
                format!("nzcv = {} {} {}", op(ops, 0), c_op, op(ops, 1))
            }
        }

        // CondFlagSet
        InsnClass::CondFlagSet => {
            let c_op = if m.starts_with("ccmn") { "+" } else { "-" };
            format!("if (cond) nzcv = {} {} {}", op(ops, 0), c_op, op(ops, 1))
        }

        // AluFlags
        InsnClass::AluFlags => {
            let c_op = mnemonic_to_c_op(m);
            if m == "neg" || m == "negs" {
                format!("{} = -{}; nzcv = ...", op(ops, 0), op(ops, 1))
            } else {
                format!(
                    "{} = {} {} {}; nzcv = ...",
                    op(ops, 0),
                    op(ops, 1),
                    c_op,
                    op(ops, 2)
                )
            }
        }

        // FlagUse
        InsnClass::FlagUse => match m {
            "csel" | "fcsel" => format!(
                "{} = (cond) ? {} : {}",
                op(ops, 0),
                op(ops, 1),
                op(ops, 2)
            ),
            "cset" => format!("{} = (cond) ? 1 : 0", op(ops, 0)),
            "csetm" => format!("{} = (cond) ? -1 : 0", op(ops, 0)),
            "csinc" => format!(
                "{} = (cond) ? {} : {} + 1",
                op(ops, 0),
                op(ops, 1),
                op(ops, 2)
            ),
            "csinv" => format!(
                "{} = (cond) ? {} : ~{}",
                op(ops, 0),
                op(ops, 1),
                op(ops, 2)
            ),
            "csneg" => format!(
                "{} = (cond) ? {} : -{}",
                op(ops, 0),
                op(ops, 1),
                op(ops, 2)
            ),
            "cinc" => format!(
                "{} = (cond) ? {} + 1 : {}",
                op(ops, 0),
                op(ops, 1),
                op(ops, 1)
            ),
            "cinv" => format!(
                "{} = (cond) ? ~{} : {}",
                op(ops, 0),
                op(ops, 1),
                op(ops, 1)
            ),
            "cneg" => format!(
                "{} = (cond) ? -{} : {}",
                op(ops, 0),
                op(ops, 1),
                op(ops, 1)
            ),
            _ => fallback_expr(m, ops),
        },

        // AluCarry
        InsnClass::AluCarry => {
            let c_op = mnemonic_to_c_op(m);
            format!(
                "{} = {} {} {} {} C",
                op(ops, 0),
                op(ops, 1),
                c_op,
                op(ops, 2),
                c_op
            )
        }

        // AluCarryFlags
        InsnClass::AluCarryFlags => {
            let c_op = mnemonic_to_c_op(m);
            format!(
                "{} = {} {} {} {} C; nzcv = ...",
                op(ops, 0),
                op(ops, 1),
                c_op,
                op(ops, 2),
                c_op
            )
        }

        // LoadReg
        InsnClass::LoadReg => {
            if let Some(ref mem) = p.mem_op {
                let ty = mem_type_str(m, mem.elem_width);
                let addr = fmt_addr(mem.abs);
                if ty.starts_with('(') {
                    format!("{} = {}{}", op(ops, 0), ty, addr)
                } else {
                    format!("{} = *({}*){}", op(ops, 0), ty, addr)
                }
            } else {
                fallback_expr(m, ops)
            }
        }

        // LoadPair
        InsnClass::LoadPair => {
            if let Some(ref mem) = p.mem_op {
                let addr = fmt_addr(mem.abs);
                format!("{{{}, {}}} = *(uint128_t*){}", op(ops, 0), op(ops, 1), addr)
            } else {
                fallback_expr(m, ops)
            }
        }

        // StoreReg
        InsnClass::StoreReg => {
            if let Some(ref mem) = p.mem_op {
                let ty = mem_type_str(m, mem.elem_width);
                let addr = fmt_addr(mem.abs);
                format!("*({}*){} = {}", ty, addr, op(ops, 0))
            } else {
                fallback_expr(m, ops)
            }
        }

        // StorePair
        InsnClass::StorePair => {
            if let Some(ref mem) = p.mem_op {
                let addr = fmt_addr(mem.abs);
                format!("*(uint128_t*){} = {{{}, {}}}", addr, op(ops, 0), op(ops, 1))
            } else {
                fallback_expr(m, ops)
            }
        }

        // StoreExcl
        InsnClass::StoreExcl => {
            if let Some(ref mem) = p.mem_op {
                format!(
                    "{} = stxr({}, {})",
                    op(ops, 0),
                    fmt_addr(mem.abs),
                    op(ops, 1)
                )
            } else {
                fallback_expr(m, ops)
            }
        }

        // AtomicLoadOp
        InsnClass::AtomicLoadOp => {
            let atomic_op = if m.contains("add") {
                "atomic_add"
            } else if m.contains("clr") {
                "atomic_clr"
            } else if m.contains("set") {
                "atomic_set"
            } else if m.contains("eor") {
                "atomic_eor"
            } else if m.starts_with("swp") {
                "atomic_swap"
            } else {
                "atomic_op"
            };
            if let Some(ref mem) = p.mem_op {
                format!(
                    "{} = {}({}, {})",
                    op(ops, 1),
                    atomic_op,
                    fmt_addr(mem.abs),
                    op(ops, 0)
                )
            } else {
                fallback_expr(m, ops)
            }
        }

        // CompareAndSwap
        InsnClass::CompareAndSwap => {
            if let Some(ref mem) = p.mem_op {
                format!(
                    "{} = cas({}, {}, {})",
                    op(ops, 0),
                    fmt_addr(mem.abs),
                    op(ops, 0),
                    op(ops, 1)
                )
            } else {
                fallback_expr(m, ops)
            }
        }

        // Branch variants（依赖树中少见）
        InsnClass::CondBranchNzcv
        | InsnClass::CondBranchReg
        | InsnClass::Branch
        | InsnClass::BranchLink
        | InsnClass::BranchReg
        | InsnClass::BranchLinkReg
        | InsnClass::Return => fallback_expr(m, ops),

        // Nop/Svc
        InsnClass::Nop | InsnClass::Svc => fallback_expr(m, ops),

        // SysReg
        InsnClass::SysRegRead => format!("{} = mrs(sysreg)", op(ops, 0)),
        InsnClass::SysRegNzcvRead => format!("{} = nzcv", op(ops, 0)),
        InsnClass::SysRegWrite => format!("msr(sysreg) = {}", op(ops, 0)),
        InsnClass::SysRegNzcvWrite => format!("nzcv = {}", op(ops, 0)),

        // SIMD
        InsnClass::SimdArith
        | InsnClass::SimdRMW
        | InsnClass::SimdMove
        | InsnClass::SimdMisc
        | InsnClass::SimdLaneLoad => fallback_expr(m, ops),
        InsnClass::SimdLoad => {
            if let Some(ref mem) = p.mem_op {
                format!("{} = *(uint128_t*){}", op(ops, 0), fmt_addr(mem.abs))
            } else {
                fallback_expr(m, ops)
            }
        }
        InsnClass::SimdStore => {
            if let Some(ref mem) = p.mem_op {
                format!("*(uint128_t*){} = {}", fmt_addr(mem.abs), op(ops, 0))
            } else {
                fallback_expr(m, ops)
            }
        }

        // Float
        InsnClass::FloatArith => {
            let stripped = m.trim_start_matches('f');
            let c_op = mnemonic_to_c_op(stripped);
            if c_op != stripped && ops.len() >= 3 {
                format!(
                    "{} = {} {} {}",
                    op(ops, 0),
                    op(ops, 1),
                    c_op,
                    op(ops, 2)
                )
            } else if m == "fneg" {
                format!("{} = -{}", op(ops, 0), op(ops, 1))
            } else if m == "fabs" {
                format!("{} = fabs({})", op(ops, 0), op(ops, 1))
            } else if m == "fsqrt" {
                format!("{} = sqrt({})", op(ops, 0), op(ops, 1))
            } else if m == "fmadd" {
                format!(
                    "{} = {} * {} + {}",
                    op(ops, 0),
                    op(ops, 1),
                    op(ops, 2),
                    op(ops, 3)
                )
            } else if m == "fmsub" {
                format!(
                    "{} = {} - {} * {}",
                    op(ops, 0),
                    op(ops, 3),
                    op(ops, 1),
                    op(ops, 2)
                )
            } else if m == "fcmp" || m == "fcmpe" {
                format!("nzcv = {} - {}", op(ops, 0), op(ops, 1))
            } else {
                fallback_expr(m, ops)
            }
        }

        // Bitfield
        InsnClass::Bitfield => match m {
            "ubfx" | "ubfiz" => {
                if let (Some(Operand::Imm(lsb)), Some(Operand::Imm(width))) =
                    (ops.get(2), ops.get(3))
                {
                    let w = (*width).clamp(1, 63) as u64;
                    let mask = (1u64 << w) - 1;
                    if m == "ubfx" {
                        format!(
                            "{} = ({} >> {}) & 0x{:x}",
                            op(ops, 0),
                            op(ops, 1),
                            lsb,
                            mask
                        )
                    } else {
                        format!(
                            "{} = ({} & 0x{:x}) << {}",
                            op(ops, 0),
                            op(ops, 1),
                            mask,
                            lsb
                        )
                    }
                } else {
                    fallback_expr(m, ops)
                }
            }
            "sbfx" => {
                if let (Some(Operand::Imm(lsb)), Some(Operand::Imm(width))) =
                    (ops.get(2), ops.get(3))
                {
                    let w = (*width).clamp(1, 63) as u64;
                    format!(
                        "{} = sign_ext(({} >> {}) & 0x{:x}, {})",
                        op(ops, 0),
                        op(ops, 1),
                        lsb,
                        (1u64 << w) - 1,
                        width
                    )
                } else {
                    fallback_expr(m, ops)
                }
            }
            _ => fallback_expr(m, ops),
        },

        // Extend
        InsnClass::Extend => match m {
            "sxtw" => format!("{} = (int64_t)(int32_t){}", op(ops, 0), op(ops, 1)),
            "sxth" => format!("{} = (int64_t)(int16_t){}", op(ops, 0), op(ops, 1)),
            "sxtb" => format!("{} = (int64_t)(int8_t){}", op(ops, 0), op(ops, 1)),
            "uxtw" => format!("{} = (uint32_t){}", op(ops, 0), op(ops, 1)),
            "uxth" => format!("{} = (uint16_t){}", op(ops, 0), op(ops, 1)),
            "uxtb" => format!("{} = (uint8_t){}", op(ops, 0), op(ops, 1)),
            _ => fallback_expr(m, ops),
        },
    }
}
