#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct CallTreeNode {
    pub id: u32,
    pub func_addr: u64,
    #[serde(default)]
    pub func_name: Option<String>,
    pub entry_seq: u32,
    pub exit_seq: u32,
    pub parent_id: Option<u32>,
    pub children_ids: Vec<u32>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct CallTree {
    pub nodes: Vec<CallTreeNode>,
}

pub struct CallTreeBuilder {
    nodes: Vec<CallTreeNode>,
    call_stack: Vec<u32>,
    next_id: u32,
    current_id: u32,
}

impl CallTreeBuilder {
    pub fn new() -> Self {
        let root = CallTreeNode {
            id: 0,
            func_addr: 0,
            func_name: None,
            entry_seq: 0,
            exit_seq: u32::MAX,
            parent_id: None,
            children_ids: Vec::new(),
        };
        Self {
            nodes: vec![root],
            call_stack: Vec::new(),
            next_id: 1,
            current_id: 0,
        }
    }

    /// 设置根节点的地址（用 trace 第一行的实际指令地址）
    pub fn set_root_addr(&mut self, addr: u64) {
        self.nodes[0].func_addr = addr;
    }

    pub fn on_call(&mut self, seq: u32, target_addr: u64) {
        let child_id = self.next_id;
        self.next_id += 1;
        let child = CallTreeNode {
            id: child_id,
            func_addr: target_addr,
            func_name: None,
            entry_seq: seq,
            exit_seq: u32::MAX,
            parent_id: Some(self.current_id),
            children_ids: Vec::new(),
        };
        self.nodes.push(child);
        self.nodes[self.current_id as usize].children_ids.push(child_id);
        self.call_stack.push(self.current_id);
        self.current_id = child_id;
    }

    /// 根据 entry_seq 查找节点并设置 func_name
    pub fn set_func_name_by_entry_seq(&mut self, entry_seq: u32, name: &str) {
        for node in self.nodes.iter_mut().rev() {
            if node.entry_seq == entry_seq {
                node.func_name = Some(name.to_string());
                return;
            }
        }
    }

    /// 更新当前节点的 func_addr（用于 BLR 后从下一行获取实际目标地址）
    pub fn update_current_func_addr(&mut self, addr: u64) {
        if self.current_id != 0 {
            self.nodes[self.current_id as usize].func_addr = addr;
        }
    }

    pub fn on_ret(&mut self, seq: u32) {
        if let Some(parent_id) = self.call_stack.pop() {
            self.nodes[self.current_id as usize].exit_seq = seq;
            self.current_id = parent_id;
        }
    }

    pub fn finish(mut self, total_lines: u32) -> CallTree {
        self.nodes[0].exit_seq = total_lines.saturating_sub(1);
        while let Some(parent_id) = self.call_stack.pop() {
            self.nodes[self.current_id as usize].exit_seq = total_lines.saturating_sub(1);
            self.current_id = parent_id;
        }
        CallTree { nodes: self.nodes }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_call_tree() {
        let mut b = CallTreeBuilder::new();
        b.on_call(5, 0x1000);
        b.on_ret(10);
        b.on_call(15, 0x2000);
        b.on_call(20, 0x3000);
        b.on_ret(25);
        b.on_ret(30);
        let tree = b.finish(35);
        assert_eq!(tree.nodes.len(), 4);
        assert_eq!(tree.nodes[0].children_ids, vec![1, 2]);
        assert_eq!(tree.nodes[1].func_addr, 0x1000);
        assert_eq!(tree.nodes[1].exit_seq, 10);
        assert_eq!(tree.nodes[2].children_ids, vec![3]);
    }

    #[test]
    fn test_unbalanced_rets() {
        let mut b = CallTreeBuilder::new();
        b.on_ret(5); // extra ret, should be ignored
        b.on_call(10, 0x1000);
        b.on_ret(15);
        let tree = b.finish(20);
        assert_eq!(tree.nodes.len(), 2);
    }

    #[test]
    fn test_unclosed_calls() {
        let mut b = CallTreeBuilder::new();
        b.on_call(5, 0x1000);
        b.on_call(10, 0x2000);
        // no rets
        let tree = b.finish(20);
        assert_eq!(tree.nodes.len(), 3);
        assert_eq!(tree.nodes[1].exit_seq, 19);
        assert_eq!(tree.nodes[2].exit_seq, 19);
    }
}
