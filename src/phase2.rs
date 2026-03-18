use crate::taint::call_tree::CallTreeBuilder;
use crate::taint::insn_class::{self, InsnClass};
use crate::taint::mem_access::{MemAccessIndex, MemAccessRecord, MemRw};
use crate::taint::parser;
use crate::taint::reg_checkpoint::RegCheckpoints;
use crate::taint::types::{parse_reg, Operand, RegId};

use crate::state::Phase2State;

const CHECKPOINT_INTERVAL: u32 = 1000;

/// 执行 Phase 2 扫描：构建 CallTree, MemAccessIndex, RegCheckpoints
#[allow(dead_code)]
pub fn build_phase2(data: &[u8], progress_fn: Option<Box<dyn Fn(usize, usize) + Send>>) -> Phase2State {
    let mut ct_builder = CallTreeBuilder::new();
    let mut mem_idx = MemAccessIndex::new();
    let mut reg_ckpts = RegCheckpoints::new(CHECKPOINT_INTERVAL);
    let mut reg_values = [u64::MAX; RegId::COUNT];

    // 保存初始检查点
    reg_ckpts.save_checkpoint(&reg_values);

    let data_len = data.len();
    let mut last_report = 0usize;

    let mut pos = 0usize;
    let mut seq: u32 = 0;
    // BLR 后需要检测：如果下一行地址 = BLR的PC+4，说明是 unidbg 拦截调用（无函数体）
    let mut blr_pending_pc: Option<u64> = None; // Some(BLR指令的PC地址)
    let mut root_addr_set = false;

    while pos < data.len() {
        // 找行尾
        let end = memchr::memchr(b'\n', &data[pos..])
            .map(|i| pos + i)
            .unwrap_or(data.len());
        let line_bytes = &data[pos..end];

        if let Ok(line_str) = std::str::from_utf8(line_bytes) {
            // 用第一条有效指令的地址作为根节点地址
            if !root_addr_set {
                let addr = extract_insn_addr(line_str);
                if addr != 0 {
                    ct_builder.set_root_addr(addr);
                    root_addr_set = true;
                }
            }

            // BLR 后处理：必须在 parse_line 之外，避免被不可解析的中间行（日志等）阻断
            if let Some(blr_pc) = blr_pending_pc.take() {
                let next_addr = extract_insn_addr(line_str);
                if next_addr != 0 {
                    // 始终用下一行的实际指令地址更新 func_addr
                    ct_builder.update_current_func_addr(next_addr);
                    if next_addr == blr_pc + 4 {
                        // 下一行地址 = BLR的PC+4 → unidbg 拦截调用，无函数体
                        ct_builder.on_ret(seq.saturating_sub(1));
                    }
                } else {
                    // 当前行无法提取指令地址（非指令行），保留到下一行再检查
                    blr_pending_pc = Some(blr_pc);
                }
            }

            if let Some(parsed) = parser::parse_line(line_str) {
                let first_reg = parsed.operands.first().and_then(|op| op.as_reg());
                let cls = insn_class::classify(parsed.mnemonic.as_str(), first_reg);

                // CallTree: BL/BLR → on_call, RET → on_ret
                match cls {
                    InsnClass::BranchLink => {
                        // BL: 目标地址是立即数操作数
                        let target = parsed
                            .operands
                            .first()
                            .and_then(|op| match op {
                                Operand::Imm(val) => Some(*val as u64),
                                _ => None,
                            })
                            .unwrap_or(0);
                        ct_builder.on_call(seq, target);
                    }
                    InsnClass::BranchLinkReg => {
                        // BLR: 记录 PC 地址，下一行判断是否为 unidbg 拦截调用
                        let target = extract_blr_target(&parsed, line_str);
                        let blr_pc = extract_insn_addr(line_str);
                        ct_builder.on_call(seq, target);
                        blr_pending_pc = Some(blr_pc);
                    }
                    InsnClass::Return => {
                        ct_builder.on_ret(seq);
                    }
                    _ => {}
                }

                // MemAccess: 从 parsed.mem_op 提取
                if let Some(ref mem_op) = parsed.mem_op {
                    let rw = if mem_op.is_write {
                        MemRw::Write
                    } else {
                        MemRw::Read
                    };
                    let insn_addr = extract_insn_addr(line_str);

                    if mem_op.elem_width <= 8 {
                        // Scalar 路径
                        mem_idx.add(
                            mem_op.abs,
                            MemAccessRecord {
                                seq,
                                insn_addr,
                                rw,
                                data: mem_op.value.unwrap_or(0),
                                size: mem_op.elem_width,
                            },
                        );

                        // Pair 指令：在 abs + elem_width 处创建第二条记录
                        if let Some(val2) = mem_op.value2 {
                            mem_idx.add(
                                mem_op.abs + mem_op.elem_width as u64,
                                MemAccessRecord {
                                    seq,
                                    insn_addr,
                                    rw,
                                    data: val2,
                                    size: mem_op.elem_width,
                                },
                            );
                        }
                    } else if mem_op.elem_width == 16 {
                        // 128-bit: 拆为两条 size=8 的记录
                        if let Some(lo) = mem_op.value_lo {
                            mem_idx.add(mem_op.abs, MemAccessRecord {
                                seq, insn_addr, rw, data: lo, size: 8,
                            });
                        }
                        if let Some(hi) = mem_op.value_hi {
                            mem_idx.add(mem_op.abs + 8, MemAccessRecord {
                                seq, insn_addr, rw, data: hi, size: 8,
                            });
                        }
                        // Pair 128-bit: 第二个寄存器
                        if let Some(lo2) = mem_op.value2_lo {
                            mem_idx.add(mem_op.abs + 16, MemAccessRecord {
                                seq, insn_addr, rw, data: lo2, size: 8,
                            });
                        }
                        if let Some(hi2) = mem_op.value2_hi {
                            mem_idx.add(mem_op.abs + 24, MemAccessRecord {
                                seq, insn_addr, rw, data: hi2, size: 8,
                            });
                        }
                    }
                }

                // RegCheckpoints: 从 "=>" 之后提取寄存器变更值
                update_reg_values(&mut reg_values, line_str);
            }
        }

        seq += 1;
        if seq % CHECKPOINT_INTERVAL == 0 {
            reg_ckpts.save_checkpoint(&reg_values);
        }

        pos = end + 1;

        // 每处理约 10MB 报告一次进度
        if let Some(ref cb) = progress_fn {
            if pos - last_report > 10 * 1024 * 1024 {
                cb(pos, data_len);
                last_report = pos;
            }
        }
    }

    let call_tree = ct_builder.finish(seq);

    Phase2State {
        call_tree,
        mem_accesses: mem_idx,
        reg_checkpoints: reg_ckpts,
        string_index: Default::default(),
    }
}

/// 从 BLR 指令行中提取目标地址（从行文本中找寄存器值）
pub fn extract_blr_target(parsed: &crate::taint::types::ParsedLine, line_str: &str) -> u64 {
    // BLR 的第一个操作数是寄存器（如 x6）
    if let Some(Operand::Reg(reg)) = parsed.operands.first() {
        // 在 "=>" 之前的部分查找 "xN=0x..." 格式
        let reg_name = format!("{:?}", reg); // "x6", "x30" 等
        let search_area = if let Some(arrow_pos) = line_str.find(" => ").or_else(|| line_str.find(" -> ")) {
            &line_str[..arrow_pos]
        } else {
            line_str
        };
        // 查找 "x6=0x" 模式
        let pattern = format!("{}=0x", reg_name);
        if let Some(eq_pos) = search_area.find(&pattern) {
            let val_start = eq_pos + pattern.len();
            let val_end = search_area[val_start..]
                .find(|c: char| !c.is_ascii_hexdigit())
                .map(|p| val_start + p)
                .unwrap_or(search_area.len());
            if let Ok(val) = u64::from_str_radix(&search_area[val_start..val_end], 16) {
                return val;
            }
        }
    }
    0
}

/// 从 trace 行提取指令绝对地址
pub fn extract_insn_addr(line: &str) -> u64 {
    // 格式: ... ] 0xADDR: "mnemonic ..." (unidbg)
    //   或: ... ] 0xADDR!0xOFFSET ... (gumtrace)
    if let Some(pos) = line.find("] 0x") {
        let rest = &line[pos + 4..]; // 跳过 "] 0x"
        // gumtrace: 0xADDR!0xOFFSET
        if let Some(bang) = rest.find('!') {
            if let Ok(addr) = u64::from_str_radix(&rest[..bang], 16) {
                return addr;
            }
        }
        // unidbg: 0xADDR:
        if let Some(colon) = rest.find(':') {
            if let Ok(addr) = u64::from_str_radix(&rest[..colon], 16) {
                return addr;
            }
        }
    }
    0
}

/// 从 trace 行提取偏移地址
/// gumtrace: `0xADDR!0xOFFSET` → OFFSET
/// unidbg:   `[libtiny.so 0x174250]` → 0x174250
pub fn extract_insn_offset(line: &str) -> u64 {
    // gumtrace: ...] 0xADDR!0xOFFSET ...
    if let Some(bracket_end) = line.find("] 0x") {
        let rest = &line[bracket_end + 4..];
        if let Some(bang) = rest.find('!') {
            let after = &rest[bang + 3..]; // skip "!0x"
            let end = after.find(|c: char| !c.is_ascii_hexdigit()).unwrap_or(after.len());
            if end > 0 {
                if let Ok(v) = u64::from_str_radix(&after[..end], 16) {
                    return v;
                }
            }
        }
    }
    // unidbg: [timestamp][libtiny.so 0x174250] [encoding] ...
    if let Some(pos) = line.find("] [") {
        let before = &line[..pos];
        if let Some(bracket_start) = before.rfind('[') {
            let module_info = &line[bracket_start + 1..pos];
            // module_info = "libtiny.so 0x174250"
            if let Some(space_pos) = module_info.rfind(" 0x") {
                let hex_str = &module_info[space_pos + 3..];
                if let Ok(v) = u64::from_str_radix(hex_str, 16) {
                    return v;
                }
            }
        }
    }
    0
}

/// 从 "=> " 之后提取寄存器变更并更新状态
pub fn update_reg_values(values: &mut [u64; RegId::COUNT], line: &str) {
    if let Some(arrow_pos) = line.find(" => ").or_else(|| line.find(" -> ")) {
        update_reg_values_at(values, line, arrow_pos);
    }
    // gumtrace: "msr nzcv, xN" 不会在 -> 后输出 nzcv=，需要从源寄存器值推断
    infer_nzcv_from_msr(values, line);
}

/// 检测 "msr nzcv, xN" 指令，从分号后的寄存器值区域提取源寄存器值来推断 nzcv
fn infer_nzcv_from_msr(values: &mut [u64; RegId::COUNT], line: &str) {
    // 快速检查：行中必须包含 "msr nzcv"
    let msr_pos = match line.find("msr nzcv, ") {
        Some(p) => p,
        None => return,
    };
    // 提取源寄存器名：msr nzcv, xN
    let after_comma = &line[msr_pos + 10..]; // skip "msr nzcv, "
    let reg_end = after_comma.find(|c: char| !c.is_ascii_alphanumeric())
        .unwrap_or(after_comma.len());
    let src_reg_name = &after_comma[..reg_end];
    if let Some(src_reg) = parse_reg(src_reg_name) {
        // 从分号后的标注区域查找 "xN=0x..." 值
        if let Some(semi_pos) = line.find(';') {
            let annot = &line[semi_pos..];
            let pattern = format!("{}=0x", src_reg_name);
            if let Some(val_pos) = annot.find(&pattern) {
                let hex_start = val_pos + pattern.len();
                let hex_end = annot[hex_start..].find(|c: char| !c.is_ascii_hexdigit())
                    .map(|p| hex_start + p)
                    .unwrap_or(annot.len());
                if let Ok(val) = u64::from_str_radix(&annot[hex_start..hex_end], 16) {
                    values[RegId::NZCV.0 as usize] = val;
                    return;
                }
            }
        }
        // 回退：如果源寄存器已有已知值，直接使用
        let src_val = values[src_reg.0 as usize];
        if src_val != u64::MAX {
            values[RegId::NZCV.0 as usize] = src_val;
        }
    }
}

/// 从已知的箭头位置提取寄存器变更（避免重复搜索 " => "）
pub fn update_reg_values_at(values: &mut [u64; RegId::COUNT], line: &str, arrow_pos: usize) {
    let changes = &line[arrow_pos + 4..];
    for part in changes.split_whitespace() {
        if let Some(eq_pos) = part.find('=') {
            let reg_name = &part[..eq_pos];
            let val_str = &part[eq_pos + 1..];
            if let Some(reg) = parse_reg(reg_name) {
                let val_str = val_str.trim_start_matches("0x");
                if let Ok(val) = u64::from_str_radix(val_str, 16) {
                    values[reg.0 as usize] = val;
                }
            }
        }
    }
}
