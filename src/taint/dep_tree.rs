use serde::Serialize;
use std::collections::{HashMap, HashSet, VecDeque};

use crate::flat::line_index::LineIndexView;
use crate::flat::scan_view::ScanView;
use crate::taint::def_use::determine_def_use;
use crate::taint::gumtrace_parser;
use crate::taint::insn_class;
use crate::taint::parser;
use crate::taint::scanner::{CONTROL_DEP_BIT, LINE_MASK, PAIR_HALF2_BIT, PAIR_SHARED_BIT};
use crate::taint::types::TraceFormat;
use rustc_hash::FxHashMap;

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DependencyNode {
    pub seq: u32,
    pub expression: String,
    pub operation: String,
    pub children: Vec<DependencyNode>,
    pub is_leaf: bool,
    pub is_ref: bool,
    pub value: Option<String>,
    pub depth: u32,
}

pub fn build_tree(view: &ScanView, start_index: u32, data_only: bool) -> DependencyNode {
    let n = view.line_count as usize;
    let mut children_map: HashMap<u32, Vec<u32>> = HashMap::new();
    let mut visited = bitvec::prelude::bitvec![0; n];
    let mut pair_visited: FxHashMap<u32, u8> = FxHashMap::default();
    let mut queue: VecDeque<u32> = VecDeque::new();

    let root_line = start_index & LINE_MASK;
    if (root_line as usize) < n {
        visited.set(root_line as usize, true);
        queue.push_back(start_index);
        children_map.entry(root_line).or_default();
    }

    while let Some(raw) = queue.pop_front() {
        let parent_line = raw & LINE_MASK;
        let deps = collect_deps(raw, view, data_only);

        for dep_raw in deps {
            let dep_line = dep_raw & LINE_MASK;
            if (dep_line as usize) >= n {
                continue;
            }

            children_map
                .entry(parent_line)
                .or_default()
                .push(dep_line);

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
            children_map.entry(dep_line).or_default();
            queue.push_back(dep_raw);
        }
    }

    build_node_iterative(root_line, &children_map)
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

/// 迭代式 DFS 构建依赖树，避免栈溢出
fn build_node_iterative(
    root_line: u32,
    children_map: &HashMap<u32, Vec<u32>>,
) -> DependencyNode {
    // 每个栈帧：当前节点信息 + 待处理的子节点 + 已构建的子节点
    struct Frame {
        line: u32,
        depth: u32,
        children: Vec<u32>, // 待处理的子节点列表
        cursor: usize,      // 下一个待处理的子节点索引
        built_children: Vec<DependencyNode>,
    }

    let mut expanded: HashSet<u32> = HashSet::new();
    let mut ancestors: HashSet<u32> = HashSet::new();

    // 初始化根节点
    expanded.insert(root_line);
    ancestors.insert(root_line);
    let root_children: Vec<u32> = children_map
        .get(&root_line)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|c| !ancestors.contains(c))
        .collect();

    let mut stack = vec![Frame {
        line: root_line,
        depth: 0,
        children: root_children,
        cursor: 0,
        built_children: Vec::new(),
    }];

    loop {
        // 取栈顶帧，检查是否还有子节点需要处理
        let has_next_child = {
            let frame = stack.last().unwrap();
            frame.cursor < frame.children.len()
        };

        if has_next_child {
            let (child_line, parent_depth) = {
                let frame = stack.last_mut().unwrap();
                let child_line = frame.children[frame.cursor];
                frame.cursor += 1;
                (child_line, frame.depth)
            };

            let child_depth = parent_depth + 1;

            if expanded.contains(&child_line) {
                // 已在其他分支展开过 → 引用占位符
                let ref_node = DependencyNode {
                    seq: child_line,
                    expression: String::new(),
                    operation: String::new(),
                    children: vec![],
                    is_leaf: false,
                    is_ref: true,
                    value: None,
                    depth: child_depth,
                };
                stack.last_mut().unwrap().built_children.push(ref_node);
            } else {
                // 首次展开：压入新栈帧
                expanded.insert(child_line);
                ancestors.insert(child_line);
                let grandchildren: Vec<u32> = children_map
                    .get(&child_line)
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|c| !ancestors.contains(c))
                    .collect();

                stack.push(Frame {
                    line: child_line,
                    depth: child_depth,
                    children: grandchildren,
                    cursor: 0,
                    built_children: Vec::new(),
                });
            }
        } else {
            // 所有子节点已处理完毕 → 构建当前节点并弹出
            let frame = stack.pop().unwrap();
            ancestors.remove(&frame.line);

            let is_leaf = frame.built_children.is_empty();
            let node = DependencyNode {
                seq: frame.line,
                expression: String::new(),
                operation: String::new(),
                children: frame.built_children,
                is_leaf,
                is_ref: false,
                value: None,
                depth: frame.depth,
            };

            if stack.is_empty() {
                return node; // 根节点，返回完整树
            } else {
                stack.last_mut().unwrap().built_children.push(node);
            }
        }
    }
}

/// 迭代式填充所有节点的 expression / operation / value 字段
pub fn populate_node_info(
    root: &mut DependencyNode,
    mmap: &[u8],
    line_index: &LineIndexView,
    format: TraceFormat,
) {
    // 使用显式栈代替递归，避免深层树导致栈溢出。
    // 使用裸指针遍历树：每个节点只访问一次且互不重叠，安全性由树结构保证。
    let mut stack: Vec<*mut DependencyNode> = vec![root as *mut _];
    while let Some(ptr) = stack.pop() {
        // SAFETY: 树结构保证每个节点只被访问一次，不存在别名
        let node = unsafe { &mut *ptr };
        fill_single_node(node, mmap, line_index, format);
        for child in node.children.iter_mut() {
            stack.push(child as *mut _);
        }
    }
}

fn fill_single_node(
    node: &mut DependencyNode,
    mmap: &[u8],
    line_index: &LineIndexView,
    format: TraceFormat,
) {
    if let Some(raw_line) = line_index.get_line(mmap, node.seq) {
        if let Ok(line_str) = std::str::from_utf8(raw_line) {
            let parsed = match format {
                TraceFormat::Unidbg => parser::parse_line(line_str),
                TraceFormat::Gumtrace => gumtrace_parser::parse_line_gumtrace(line_str),
            };
            if let Some(ref p) = parsed {
                let cls = insn_class::classify_and_refine(p);
                let (defs, uses) = determine_def_use(cls, p);
                node.operation = p.mnemonic.to_string();

                let def_str = defs
                    .iter()
                    .map(|r| format!("{:?}", r))
                    .collect::<Vec<_>>()
                    .join(", ");
                let use_str = uses
                    .iter()
                    .map(|r| format!("{:?}", r))
                    .collect::<Vec<_>>()
                    .join(", ");
                let changes = extract_changes(line_str);

                if p.mem_op.is_some() {
                    let mem = p.mem_op.as_ref().unwrap();
                    if mem.is_write {
                        node.expression = format!("mem[0x{:x}] = {}", mem.abs, use_str);
                    } else {
                        node.expression = format!("{} = mem[0x{:x}]", def_str, mem.abs);
                    }
                } else if !def_str.is_empty() {
                    node.expression = format!("{} = {} {}", def_str, p.mnemonic, use_str);
                } else {
                    node.expression = format!("{} {}", p.mnemonic, use_str);
                }

                if node.is_leaf && !changes.is_empty() {
                    node.value = Some(changes);
                }
            } else {
                node.expression = line_str.trim().to_string();
                node.operation = "unknown".to_string();
            }
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
