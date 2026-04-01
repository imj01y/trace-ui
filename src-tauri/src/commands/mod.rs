use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, State};
use trace_core::{TraceEngine, BuildOptions, Progress, SearchOptions, SliceOptions,
    StringQueryOptions, DepTreeOptions, ExportConfig, parse_hex_addr};

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Session Management
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// 前端期望的返回结构（保持兼容）
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateSessionResult {
    session_id: String,
    total_lines: u32,
    file_size: u64,
    trace_format: Option<String>,
}

#[tauri::command]
pub async fn create_session(
    path: String,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<CreateSessionResult, String> {
    let engine = engine.inner().clone();
    let info = tauri::async_runtime::spawn_blocking(move || {
        engine.create_session(&path)
    })
    .await
    .map_err(|e| format!("Task execution failed: {}", e))?
    .map_err(|e| e.to_string())?;

    Ok(CreateSessionResult {
        session_id: info.session_id,
        total_lines: info.total_lines,
        file_size: info.file_size,
        trace_format: info.trace_format.map(|f| format!("{:?}", f)),
    })
}

#[tauri::command]
pub fn close_session(
    session_id: String,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<(), String> {
    engine.close_session(&session_id).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn delete_file_cache(
    path: String,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<(), String> {
    engine.delete_file_cache(&path);
    Ok(())
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Index Build (模板 2: async + 进度事件)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[tauri::command]
pub async fn build_index(
    session_id: String,
    app: AppHandle,
    engine: State<'_, Arc<TraceEngine>>,
    force: Option<bool>,
    skip_strings: Option<bool>,
) -> Result<(), String> {
    let engine = engine.inner().clone();
    let sid = session_id.clone();

    // 进度回调 → Tauri 事件
    let app_clone = app.clone();
    let sid_clone = sid.clone();
    let on_progress: Box<dyn Fn(Progress) + Send + Sync> = Box::new(move |p: Progress| {
        let _ = app_clone.emit("index-progress", serde_json::json!({
            "sessionId": sid_clone,
            "progress": p.fraction,
            "done": false,
        }));
    });

    let result = tauri::async_runtime::spawn_blocking(move || {
        engine.build_index(
            &sid,
            BuildOptions {
                force_rebuild: force.unwrap_or(false),
                skip_strings: skip_strings.unwrap_or(false),
            },
            Some(on_progress),
        )
    })
    .await
    .map_err(|e| format!("Task execution failed: {}", e))?;

    // 完成事件（成功或失败都发送，防止前端永远卡在 loading）
    match &result {
        Ok(r) => {
            let _ = app.emit("index-progress", serde_json::json!({
                "sessionId": session_id,
                "progress": 1.0,
                "done": true,
                "totalLines": r.total_lines,
                "hasStringIndex": r.has_string_index,
            }));
        }
        Err(e) => {
            let _ = app.emit("index-progress", serde_json::json!({
                "sessionId": session_id,
                "progress": 1.0,
                "done": true,
                "error": e.to_string(),
            }));
        }
    }

    result.map(|_| ()).map_err(|e| e.to_string())
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Browse (模板 1: 同步查询)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[tauri::command]
pub fn get_lines(
    session_id: String,
    seqs: Vec<u32>,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<Vec<trace_core::TraceLine>, String> {
    engine.get_lines(&session_id, &seqs).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn get_consumed_seqs(
    session_id: String,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<Vec<u32>, String> {
    engine.get_consumed_seqs(&session_id).map_err(|e| e.to_string())
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Search (模板 2: async)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Deserialize)]
pub struct SearchRequest {
    pub query: String,
    #[serde(default)]
    pub max_results: Option<u32>,
    #[serde(default)]
    pub case_sensitive: bool,
    #[serde(default)]
    pub use_regex: bool,
    #[serde(default)]
    pub fuzzy: bool,
}

#[tauri::command]
pub async fn search_trace(
    session_id: String,
    request: SearchRequest,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<trace_core::SearchResultLite, String> {
    let engine = engine.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        engine.search(
            &session_id,
            &request.query,
            SearchOptions {
                case_sensitive: request.case_sensitive,
                use_regex: request.use_regex,
                fuzzy: request.fuzzy,
                max_results: request.max_results,
            },
        ).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("Task execution failed: {}", e))?
}

#[derive(Serialize)]
pub struct SearchPageResult {
    pub generation: u64,
    pub seqs: Vec<u32>,
}

#[tauri::command]
pub fn fetch_search_page(
    session_id: String,
    offset: u32,
    count: u32,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<SearchPageResult, String> {
    let (gen, seqs) = engine.fetch_search_page(&session_id, offset, count)
        .map_err(|e| e.to_string())?;
    Ok(SearchPageResult { generation: gen, seqs })
}

#[derive(Deserialize)]
pub struct GetSearchMatchesRequest {
    pub seqs: Vec<u32>,
    pub query: String,
    #[serde(default)]
    pub case_sensitive: bool,
    #[serde(default)]
    pub use_regex: bool,
    #[serde(default)]
    pub fuzzy: bool,
}

#[tauri::command]
pub async fn get_search_matches(
    session_id: String,
    request: GetSearchMatchesRequest,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<Vec<trace_core::SearchMatch>, String> {
    let engine = engine.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        engine.get_search_matches(
            &session_id,
            &request.query,
            &request.seqs,
            request.case_sensitive,
            request.use_regex,
            request.fuzzy,
        ).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("Task execution failed: {}", e))?
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Slice (模板 2: async / 模板 1: sync)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[tauri::command]
pub async fn run_slice(
    session_id: String,
    from_specs: Vec<String>,
    start_seq: Option<u32>,
    end_seq: Option<u32>,
    data_only: Option<bool>,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<trace_core::SliceResult, String> {
    let engine = engine.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        engine.run_slice(
            &session_id,
            &from_specs,
            SliceOptions {
                start_seq,
                end_seq,
                data_only: data_only.unwrap_or(false),
            },
        ).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("Task execution failed: {}", e))?
}

#[tauri::command]
pub fn get_slice_status(
    session_id: String,
    start_seq: u32,
    count: u32,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<Vec<bool>, String> {
    engine.get_slice_status(&session_id, start_seq, count).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn clear_slice(
    session_id: String,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<(), String> {
    engine.clear_slice(&session_id).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn get_tainted_seqs(
    session_id: String,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<Vec<u32>, String> {
    engine.get_tainted_seqs(&session_id).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn export_taint_results(
    session_id: String,
    output_path: String,
    format: String,
    config: ExportConfig,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<(), String> {
    let engine = engine.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        engine.export_taint_results(&session_id, &output_path, &format, config)
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("Task execution failed: {}", e))?
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Memory (模板 1: 同步查询, 需要地址转换)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[tauri::command]
pub fn get_memory_at(
    session_id: String,
    seq: u32,
    addr: String,
    length: u32,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<trace_core::MemorySnapshot, String> {
    let addr_u64 = parse_hex_addr(&addr)?;
    engine.get_memory_at(&session_id, addr_u64, seq, length).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn get_mem_history_meta(
    session_id: String,
    addr: String,
    center_seq: u32,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<trace_core::MemHistoryMeta, String> {
    let addr_u64 = parse_hex_addr(&addr)?;
    engine.get_mem_history_meta(&session_id, addr_u64, center_seq).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn get_mem_history_range(
    session_id: String,
    addr: String,
    start_index: usize,
    limit: usize,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<Vec<trace_core::MemHistoryRecord>, String> {
    let addr_u64 = parse_hex_addr(&addr)?;
    engine.get_mem_history_range(&session_id, addr_u64, start_index, limit).map_err(|e| e.to_string())
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Registers (模板 1: 同步查询)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[tauri::command]
pub fn get_registers_at(
    session_id: String,
    seq: u32,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<std::collections::HashMap<String, String>, String> {
    engine.get_registers_at(&session_id, seq).map_err(|e| e.to_string())
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Call Tree (模板 1: 同步查询)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[tauri::command]
pub fn get_call_tree(
    session_id: String,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<Vec<trace_core::CallTreeNodeDto>, String> {
    engine.get_call_tree(&session_id).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn get_call_tree_node_count(
    session_id: String,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<u32, String> {
    engine.get_call_tree_node_count(&session_id).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn get_call_tree_children(
    session_id: String,
    node_id: u32,
    include_self: bool,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<Vec<trace_core::CallTreeNodeDto>, String> {
    engine.get_call_tree_children(&session_id, node_id, include_self).map_err(|e| e.to_string())
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Strings (模板 1/2/3)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[tauri::command]
pub fn get_strings(
    session_id: String,
    min_len: u32,
    offset: u32,
    limit: u32,
    search: Option<String>,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<trace_core::StringsResult, String> {
    engine.get_strings(
        &session_id,
        StringQueryOptions { min_len, offset, limit, search },
    ).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn get_string_xrefs(
    session_id: String,
    addr: String,
    byte_len: u32,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<Vec<trace_core::StringXRef>, String> {
    let addr_u64 = parse_hex_addr(&addr)?;
    engine.get_string_xrefs(&session_id, addr_u64, byte_len).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn scan_strings(
    session_id: String,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<(), String> {
    let engine = engine.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        engine.scan_strings(&session_id).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("Task execution failed: {}", e))?
}

#[tauri::command]
pub fn cancel_scan_strings(
    session_id: String,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<(), String> {
    engine.cancel_scan_strings(&session_id);
    Ok(())
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Functions (模板 1: 同步查询)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[tauri::command]
pub fn get_function_calls(
    session_id: String,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<trace_core::FunctionCallsResult, String> {
    engine.get_function_calls(&session_id).map_err(|e| e.to_string())
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Dep Tree (模板 2: async)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[tauri::command]
pub async fn build_dependency_tree(
    session_id: String,
    seq: u32,
    target: String,
    data_only: Option<bool>,
    max_nodes: Option<u32>,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<trace_core::query::dep_tree::DependencyGraph, String> {
    let engine = engine.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        engine.build_dep_tree(
            &session_id,
            seq,
            &target,
            DepTreeOptions {
                data_only: data_only.unwrap_or(false),
                max_nodes,
            },
        ).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("Task execution failed: {}", e))?
}

#[tauri::command]
pub async fn build_dependency_tree_from_slice(
    session_id: String,
    max_nodes: Option<u32>,
    data_only: Option<bool>,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<trace_core::query::dep_tree::DependencyGraph, String> {
    let engine = engine.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        engine.build_dep_tree_from_slice(
            &session_id,
            DepTreeOptions {
                data_only: data_only.unwrap_or(false),
                max_nodes,
            },
        ).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("Task execution failed: {}", e))?
}

#[tauri::command]
pub fn get_line_def_registers(
    session_id: String,
    seq: u32,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<Vec<String>, String> {
    engine.get_line_def_registers(&session_id, seq).map_err(|e| e.to_string())
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  DEF/USE (模板 1: 同步查询)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[tauri::command]
pub fn get_reg_def_use_chain(
    session_id: String,
    seq: u32,
    reg_name: String,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<trace_core::DefUseChain, String> {
    engine.get_def_use_chain(&session_id, seq, &reg_name).map_err(|e| e.to_string())
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Crypto (模板 2: async / 模板 1: sync)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[tauri::command]
pub async fn scan_crypto(
    session_id: String,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<trace_core::query::crypto::CryptoScanResult, String> {
    let engine = engine.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        engine.scan_crypto(&session_id).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("Task execution failed: {}", e))?
}

#[tauri::command]
pub fn load_crypto_cache(
    session_id: String,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<Option<trace_core::query::crypto::CryptoScanResult>, String> {
    engine.load_crypto_cache(&session_id).map_err(|e| e.to_string())
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Cache Management (模板 1: 同步查询)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[tauri::command]
pub fn get_cache_dir(
    engine: State<'_, Arc<TraceEngine>>,
) -> trace_core::CacheInfo {
    engine.get_cache_dir()
}

#[tauri::command]
pub fn set_cache_dir(
    path: Option<String>,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<(), String> {
    engine.set_cache_dir(path).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn clear_all_cache(
    engine: State<'_, Arc<TraceEngine>>,
) -> trace_core::ClearResult {
    engine.clear_all_cache()
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  MCP Server Management
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[tauri::command]
pub async fn start_mcp(
    port: Option<u16>,
    controller: State<'_, crate::mcp::McpController>,
) -> Result<crate::mcp::McpStatusInfo, String> {
    controller.start(port).await
}

/// 同步命令（有意为之）：仅做 lock + cancel + emit，无需 await。
#[tauri::command]
pub fn stop_mcp(
    controller: State<'_, crate::mcp::McpController>,
) -> crate::mcp::McpStatusInfo {
    controller.stop()
}

#[tauri::command]
pub fn get_mcp_status(
    controller: State<'_, crate::mcp::McpController>,
) -> crate::mcp::McpStatusInfo {
    controller.status()
}
