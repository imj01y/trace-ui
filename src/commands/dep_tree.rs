use tauri::{AppHandle, Manager, State};
use crate::state::AppState;
use crate::taint::dep_tree::{self, DependencyNode};
use crate::taint::types::TraceFormat;
use crate::taint::parser;
use crate::taint::gumtrace_parser;
use crate::taint::insn_class;
use crate::taint::def_use::determine_def_use;

#[tauri::command]
pub async fn build_dependency_tree(
    session_id: String, seq: u32, target: String,
    data_only: Option<bool>, app: AppHandle,
) -> Result<DependencyNode, String> {
    let data_only = data_only.unwrap_or(false);
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<AppState>();
        build_tree_inner(&session_id, seq, &target, data_only, &state)
    }).await.map_err(|e| format!("Task execution failed: {}", e))?
}

#[tauri::command]
pub async fn build_dependency_tree_from_slice(
    session_id: String, app: AppHandle,
) -> Result<DependencyNode, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<AppState>();
        let sessions = state.sessions.read().map_err(|e| e.to_string())?;
        let session = sessions.get(&session_id)
            .ok_or_else(|| format!("Session {} 不存在", session_id))?;
        let origin = session.slice_origin.as_ref()
            .ok_or("没有活跃的污点分析结果，请先执行污点追踪")?;
        let spec = origin.from_specs.first()
            .ok_or("SliceOrigin 中没有 from_specs")?;
        let data_only = origin.data_only;

        let reg_last_def = session.reg_last_def.as_ref().ok_or("索引尚未构建完成")?;
        let mem_last_def = session.mem_last_def_view().ok_or("索引尚未构建完成")?;
        let lidx_view = session.line_index_view().ok_or("索引尚未构建完成")?;
        let format = session.trace_format;

        let start_idx = crate::commands::slice::resolve_start_index(
            spec, reg_last_def, &mem_last_def, &session.mmap, &lidx_view, format)?;
        let scan_view = session.scan_view().ok_or("索引尚未构建完成")?;

        let mut tree = dep_tree::build_tree(&scan_view, start_idx, data_only);
        dep_tree::populate_node_info(&mut tree, &session.mmap, &lidx_view, format);
        Ok(tree)
    }).await.map_err(|e| format!("Task execution failed: {}", e))?
}

#[tauri::command]
pub fn get_line_def_registers(
    session_id: String, seq: u32, state: State<'_, AppState>,
) -> Result<Vec<String>, String> {
    let sessions = state.sessions.read().map_err(|e| e.to_string())?;
    let session = sessions.get(&session_id)
        .ok_or_else(|| format!("Session {} 不存在", session_id))?;
    let lidx_view = session.line_index_view().ok_or("索引尚未构建完成")?;
    let format = session.trace_format;

    if let Some(raw) = lidx_view.get_line(&session.mmap, seq) {
        if let Ok(line_str) = std::str::from_utf8(raw) {
            let parsed = match format {
                TraceFormat::Unidbg => parser::parse_line(line_str),
                TraceFormat::Gumtrace => gumtrace_parser::parse_line_gumtrace(line_str),
            };
            if let Some(ref p) = parsed {
                let cls = insn_class::classify_and_refine(p);
                let (defs, _) = determine_def_use(cls, p);
                return Ok(defs.iter().map(|r| format!("{:?}", r)).collect());
            }
        }
    }
    Ok(vec![])
}

fn build_tree_inner(
    session_id: &str, seq: u32, target: &str, data_only: bool, state: &AppState,
) -> Result<DependencyNode, String> {
    let sessions = state.sessions.read().map_err(|e| e.to_string())?;
    let session = sessions.get(session_id)
        .ok_or_else(|| format!("Session {} 不存在", session_id))?;
    let format = session.trace_format;
    let lidx_view = session.line_index_view().ok_or("索引尚未构建完成")?;

    let spec = if target.starts_with("mem:") {
        format!("{}@{}", target, seq + 1)
    } else {
        let reg_name = target.strip_prefix("reg:").unwrap_or(target);
        format!("reg:{}@{}", reg_name, seq + 1)
    };

    let reg_last_def = session.reg_last_def.as_ref().ok_or("索引尚未构建完成")?;
    let mem_last_def = session.mem_last_def_view().ok_or("索引尚未构建完成")?;

    let start_idx = crate::commands::slice::resolve_start_index(
        &spec, reg_last_def, &mem_last_def, &session.mmap, &lidx_view, format)?;
    let scan_view = session.scan_view().ok_or("索引尚未构建完成")?;

    let mut tree = dep_tree::build_tree(&scan_view, start_idx, data_only);
    dep_tree::populate_node_info(&mut tree, &session.mmap, &lidx_view, format);
    Ok(tree)
}
