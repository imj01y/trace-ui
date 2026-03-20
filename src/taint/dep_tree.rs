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

    let mut ancestors = HashSet::new();
    build_node(root_line, &children_map, 0, &mut ancestors)
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

fn build_node(
    line: u32,
    children_map: &HashMap<u32, Vec<u32>>,
    depth: u32,
    ancestors: &mut HashSet<u32>,
) -> DependencyNode {
    let child_lines = children_map.get(&line).cloned().unwrap_or_default();

    ancestors.insert(line);
    let valid_children: Vec<u32> = child_lines
        .iter()
        .copied()
        .filter(|child_line| !ancestors.contains(child_line))
        .collect();
    let children: Vec<DependencyNode> = valid_children
        .iter()
        .map(|&child_line| build_node(child_line, children_map, depth + 1, ancestors))
        .collect();
    ancestors.remove(&line);

    let is_leaf = children.is_empty();

    DependencyNode {
        seq: line,
        expression: String::new(),
        operation: String::new(),
        children,
        is_leaf,
        value: None,
        depth,
    }
}

pub fn populate_node_info(
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

                let def_str = defs.iter().map(|r| format!("{:?}", r)).collect::<Vec<_>>().join(", ");
                let use_str = uses.iter().map(|r| format!("{:?}", r)).collect::<Vec<_>>().join(", ");
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
    for child in &mut node.children {
        populate_node_info(child, mmap, line_index, format);
    }
}

fn extract_changes(line: &str) -> String {
    if let Some(pos) = line.rfind("=> ") {
        line[pos + 3..].trim().to_string()
    } else {
        String::new()
    }
}
