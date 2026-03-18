use std::collections::HashMap;
use tauri::State;
use crate::taint::def_use::determine_def_use;
use crate::taint::insn_class;
use crate::taint::parser;
use crate::taint::types::RegId;
use crate::state::AppState;

fn reg_id_to_name(r: RegId) -> Option<&'static str> {
    match r.0 {
        0 => Some("X0"), 1 => Some("X1"), 2 => Some("X2"), 3 => Some("X3"),
        4 => Some("X4"), 5 => Some("X5"), 6 => Some("X6"), 7 => Some("X7"),
        8 => Some("X8"), 9 => Some("X9"), 10 => Some("X10"), 11 => Some("X11"),
        12 => Some("X12"), 13 => Some("X13"), 14 => Some("X14"), 15 => Some("X15"),
        16 => Some("X16"), 17 => Some("X17"), 18 => Some("X18"), 19 => Some("X19"),
        20 => Some("X20"), 21 => Some("X21"), 22 => Some("X22"), 23 => Some("X23"),
        24 => Some("X24"), 25 => Some("X25"), 26 => Some("X26"), 27 => Some("X27"),
        28 => Some("X28"), 29 => Some("X29"), 30 => Some("X30"),
        31 => Some("SP"),
        65 => Some("NZCV"),
        _ => None,
    }
}

const REG_NAMES: &[(&str, u8)] = &[
    ("X0", 0), ("X1", 1), ("X2", 2), ("X3", 3), ("X4", 4),
    ("X5", 5), ("X6", 6), ("X7", 7), ("X8", 8), ("X9", 9),
    ("X10", 10), ("X11", 11), ("X12", 12), ("X13", 13), ("X14", 14),
    ("X15", 15), ("X16", 16), ("X17", 17), ("X18", 18), ("X19", 19),
    ("X20", 20), ("X21", 21), ("X22", 22), ("X23", 23), ("X24", 24),
    ("X25", 25), ("X26", 26), ("X27", 27), ("X28", 28),
    ("X29", 29), ("X30", 30), ("SP", 31), ("NZCV", 65),
];

#[tauri::command]
pub fn get_registers_at(session_id: String, seq: u32, state: State<'_, AppState>) -> Result<HashMap<String, String>, String> {
    let sessions = state.sessions.read().map_err(|e| e.to_string())?;
    let session = sessions.get(&session_id).ok_or_else(|| format!("Session {} 不存在", session_id))?;
    let reg_view = session.reg_checkpoints_view().ok_or("无可用检查点")?;
    let line_index = session.line_index.as_ref().ok_or_else(|| "索引尚未构建完成".to_string())?;

    // 找最近检查点
    let (ckpt_seq, snapshot) = reg_view
        .nearest_before(seq)
        .ok_or("无可用检查点")?;

    let mut values = *snapshot;

    // 从检查点重放到目标 seq
    for replay_seq in ckpt_seq..=seq {
        if let Some(raw) = line_index.get_line(&session.mmap, replay_seq) {
            if let Ok(line_str) = std::str::from_utf8(raw) {
                crate::phase2::update_reg_values(&mut values, line_str);
            }
        }
    }

    // 构建返回结果
    let mut result = HashMap::new();
    for &(name, idx) in REG_NAMES {
        let val = values[idx as usize];
        if val != u64::MAX {
            result.insert(name.to_string(), format!("0x{:016x}", val));
        } else {
            result.insert(name.to_string(), "?".to_string());
        }
    }

    // PC = 当前行的指令地址 + 提取当前行被修改的寄存器名
    let format = session.trace_format;
    if let Some(raw) = line_index.get_line(&session.mmap, seq) {
        let parsed = match format {
            crate::taint::types::TraceFormat::Unidbg => crate::commands::browse::parse_trace_line(seq, raw),
            crate::taint::types::TraceFormat::Gumtrace => crate::commands::browse::parse_trace_line_gumtrace(seq, raw),
        };
        if let Some(parsed) = parsed {
            let pc_display = if let Some(hex_str) = parsed.address.strip_prefix("0x")
                .or_else(|| parsed.address.strip_prefix("0X"))
            {
                if let Ok(addr) = u64::from_str_radix(hex_str, 16) {
                    format!("0x{:016x}", addr)
                } else {
                    parsed.address
                }
            } else {
                parsed.address
            };
            result.insert("PC".to_string(), pc_display);
        }
        if let Ok(line_str) = std::str::from_utf8(raw) {
            let mut changed = Vec::new();
            if let Some(arrow_pos) = line_str.find(" => ").or_else(|| line_str.find(" -> ")) {
                let changes = &line_str[arrow_pos + 4..];
                for part in changes.split_whitespace() {
                    if let Some(eq_pos) = part.find('=') {
                        let reg_name = &part[..eq_pos];
                        // 统一为大写以匹配前端 REG_NAMES
                        changed.push(reg_name.to_uppercase());
                    }
                }
            }
            if !changed.is_empty() {
                result.insert("__changed".to_string(), changed.join(","));
            }

            // 提取 USE（读取）寄存器
            if let Some(parsed) = parser::parse_line(line_str) {
                let first_reg = parsed.operands.first().and_then(|op| op.as_reg());
                let cls = insn_class::classify(parsed.mnemonic.as_str(), first_reg);
                let (_, uses) = determine_def_use(cls, &parsed);
                let read_names: Vec<&str> = uses.iter()
                    .filter_map(|r| reg_id_to_name(*r))
                    .collect();
                if !read_names.is_empty() {
                    result.insert("__read".to_string(), read_names.join(","));
                }
            }
        }
    }

    Ok(result)
}
