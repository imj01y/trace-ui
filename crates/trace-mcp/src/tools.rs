use std::sync::Arc;

use rmcp::{
    ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{ServerCapabilities, ServerInfo},
    tool, tool_handler, tool_router,
};

use trace_core::{TraceEngine, BuildOptions, SearchOptions, SliceOptions, StringQueryOptions, DepTreeOptions, ExportConfig, parse_hex_addr, api_types::TraceLine};
use crate::types::*;

// ── 截断常量 ──
// NOTE: 修改这些值时，需同步更新对应 #[tool] 描述中的硬编码数字。

// Referenced in: get_trace_lines description ("up to 100 lines per call")
const MAX_LINES: u32 = 100;
// Referenced in: search_instructions description ("up to 200 results")
const MAX_SEARCH: u32 = 200;
// Referenced in: get_memory_history description ("up to 200 records")
const MAX_HISTORY: usize = 200;
// Referenced in: get_dependency_tree, build_dep_tree_from_slice descriptions ("up to 200 nodes")
const MAX_DEP_NODES: u32 = 200;
const DEFAULT_SEARCH: u32 = 30;

fn json(val: &impl serde::Serialize) -> String {
    serde_json::to_string(val).unwrap_or_else(|e| format!("{{\"error\": \"serialization failed: {}\"}}", e))
}

/// Run a blocking closure on the tokio blocking thread pool to avoid starving
/// the async runtime. Used for heavy TraceEngine operations.
async fn blocking<F, T>(f: F) -> Result<T, String>
where
    F: FnOnce() -> Result<T, String> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| format!("Task panicked: {}", e))?
}

/// Compact 模式下裁剪 TraceLine 为精简 JSON
fn compact_line(line: &TraceLine) -> serde_json::Value {
    let mut obj = serde_json::json!({
        "seq": line.seq,
        "address": line.address,
    });
    if !line.so_offset.is_empty() {
        obj["so_offset"] = serde_json::json!(line.so_offset);
    }
    obj["disasm"] = serde_json::json!(line.disasm);
    if !line.changes.is_empty() {
        obj["changes"] = serde_json::json!(line.changes);
    }
    if let Some(ref rw) = line.mem_rw {
        obj["mem_rw"] = serde_json::json!(rw);
    }
    if let Some(ref addr) = line.mem_addr {
        obj["mem_addr"] = serde_json::json!(addr);
    }
    if let Some(ref name) = line.so_name {
        obj["so_name"] = serde_json::json!(name);
    }
    if let Some(ref info) = line.call_info {
        if !info.func_name.is_empty() {
            obj["func_name"] = serde_json::json!(info.func_name);
        }
    }
    obj
}

fn format_lines(lines: &[TraceLine], full: bool) -> Vec<serde_json::Value> {
    if full {
        lines.iter().map(|l| serde_json::to_value(l)
            .unwrap_or_else(|e| serde_json::json!({"error": e.to_string()}))
        ).collect()
    } else {
        lines.iter().map(|l| compact_line(l)).collect()
    }
}

/// 检查 changes 字段是否仅包含栈/帧指针寄存器变化
fn is_stack_only_change(changes: &str) -> bool {
    if changes.is_empty() { return false; }
    let mut has_any = false;
    for token in changes.split_whitespace() {
        if let Some(eq_pos) = token.find('=') {
            let reg = &token[..eq_pos];
            has_any = true;
            match reg {
                "sp" | "x29" | "fp" | "wsp" | "w29" => {}
                _ => return false,
            }
        }
    }
    has_any
}

/// Parse address range string like "0x246F00-0x249800"
fn parse_addr_range(range: &str) -> Result<(u64, u64), String> {
    let parts: Vec<&str> = range.split('-').collect();
    if parts.len() != 2 {
        return Err(format!(
            "Invalid addr_range format '{}'. Expected: '0x246F00-0x249800'", range
        ));
    }
    let start = parse_hex_addr(parts[0].trim())?;
    let end = parse_hex_addr(parts[1].trim())?;
    if start > end {
        return Err(format!("Invalid addr_range: start (0x{:x}) > end (0x{:x})", start, end));
    }
    Ok((start, end))
}

/// Parse seq range string like "3000-6000"
fn parse_seq_range(range: &str) -> Result<(u32, u32), String> {
    let parts: Vec<&str> = range.split('-').collect();
    if parts.len() != 2 {
        return Err(format!(
            "Invalid seq_range format '{}'. Expected: '3000-6000'", range
        ));
    }
    let start: u32 = parts[0].trim().parse()
        .map_err(|_| format!("Invalid start seq: '{}'", parts[0].trim()))?;
    let end: u32 = parts[1].trim().parse()
        .map_err(|_| format!("Invalid end seq: '{}'", parts[1].trim()))?;
    if start > end {
        return Err(format!("Invalid seq_range: start ({}) > end ({})", start, end));
    }
    Ok((start, end))
}

/// Check if TraceLine's SO offset falls within an address range
fn line_in_addr_range(line: &TraceLine, start: u64, end: u64) -> bool {
    parse_hex_addr(&line.so_offset)
        .map(|offset| offset >= start && offset <= end)
        .unwrap_or(false)
}

#[derive(Clone)]
pub struct TraceToolHandler {
    engine: Arc<TraceEngine>,
    tool_router: ToolRouter<Self>,
}

impl std::fmt::Debug for TraceToolHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TraceToolHandler").finish()
    }
}

#[tool_router]
impl TraceToolHandler {
    pub fn new(engine: Arc<TraceEngine>) -> Self {
        Self {
            engine,
            tool_router: Self::tool_router(),
        }
    }

    /// Implicit session resolution: auto-resolve when only one session is open
    fn resolve_session(&self, session_id: Option<String>) -> Result<String, String> {
        match session_id {
            Some(id) => Ok(id),
            None => {
                let sessions = self.engine.list_sessions();
                match sessions.len() {
                    0 => Err("No active session. Call open_trace first.".into()),
                    1 => Ok(sessions[0].session_id.clone()),
                    n => Err(format!(
                        "Multiple sessions active ({}). Please specify session_id. \
                         Use list_sessions to see all sessions.", n
                    )),
                }
            }
        }
    }

    // ━━━━━━━━━━━━━━━━━━━━━━ 会话管理 ━━━━━━━━━━━━━━━━━━━━━━

    #[tool(
        name = "open_trace",
        description = "Open a trace file and build its index. This is the first step before any analysis. \
            Returns session info including session_id, module_name, entry_address, trace_format, \
            function_count, and other metadata needed for all subsequent operations. \
            Building the index may take a few seconds for large files."
    )]
    async fn open_trace(&self, Parameters(req): Parameters<OpenTraceRequest>) -> Result<String, String> {
        let engine = self.engine.clone();
        blocking(move || {
            let session = engine.create_session(&req.file_path)
                .map_err(|e| format!("Failed to open trace: {}", e))?;

            let session_id = session.session_id.clone();
            let options = BuildOptions {
                force_rebuild: req.force_rebuild,
                skip_strings: req.skip_strings,
            };

            match engine.build_index(&session_id, options, None) {
                Ok(build) => {
                    // Extract additional info (graceful fallback on failure)
                    let module_name = engine.get_lines(&session_id, &[0])
                        .ok()
                        .and_then(|lines| lines.first().and_then(|l| l.so_name.clone()));

                    let entry_address = engine.get_call_tree_children(&session_id, 0, true)
                        .ok()
                        .and_then(|nodes| nodes.first().map(|n| n.func_addr.clone()));

                    let trace_format = engine.get_session_info(&session_id)
                        .ok()
                        .and_then(|info| info.trace_format.map(|f| format!("{:?}", f)));

                    let function_count = engine.get_call_tree_node_count(&session_id).ok();

                    Ok(json(&serde_json::json!({
                        "session_id": session_id,
                        "file_path": session.file_path,
                        "file_size": session.file_size,
                        "total_lines": build.total_lines,
                        "has_string_index": build.has_string_index,
                        "from_cache": build.from_cache,
                        "module_name": module_name,
                        "entry_address": entry_address,
                        "trace_format": trace_format,
                        "function_count": function_count,
                    })))
                },
                Err(e) => {
                    let _ = engine.close_session(&session_id);
                    Err(format!("Failed to build index: {}", e))
                }
            }
        }).await
    }

    #[tool(
        name = "close_trace",
        description = "Close a trace session and free its resources. \
            Call this when you're done analyzing a trace file."
    )]
    fn close_trace(&self, Parameters(req): Parameters<CloseTraceRequest>) -> Result<String, String> {
        self.engine.close_session(&req.session_id)
            .map(|()| "Session closed.".to_string())
            .map_err(|e| e.to_string())
    }

    #[tool(
        name = "list_sessions",
        description = "List all currently open trace sessions with their status."
    )]
    fn list_sessions(&self) -> String {
        json(&self.engine.list_sessions())
    }

    #[tool(
        name = "get_session_info",
        description = "Get detailed status of a trace session, including whether the index is ready, \
            total line count, and whether taint analysis results exist."
    )]
    fn get_session_info(&self, Parameters(req): Parameters<GetSessionInfoRequest>) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        self.engine.get_session_info(&sid)
            .map(|info| json(&info))
            .map_err(|e| e.to_string())
    }

    // ━━━━━━━━━━━━━━━━━━━━━━ 数据查看 ━━━━━━━━━━━━━━━━━━━━━━

    #[tool(
        name = "get_trace_lines",
        description = "Retrieve instruction lines from the trace. Each line contains: \
            address, disassembly, register changes, and memory access info. \
            Lines are identified by 0-based sequence numbers. \
            Returns up to 100 lines per call."
    )]
    fn get_trace_lines(&self, Parameters(req): Parameters<GetTraceLinesRequest>) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        let count = req.count.min(MAX_LINES);
        let end = req.start_seq.saturating_add(count);
        let seqs: Vec<u32> = (req.start_seq..end).collect();
        let lines = self.engine.get_lines(&sid, &seqs)
            .map_err(|e| e.to_string())?;
        Ok(json(&serde_json::json!({
            "lines": format_lines(&lines, req.full),
            "count": lines.len(),
            "start_seq": req.start_seq,
            "requested": count,
        })))
    }

    #[tool(
        name = "get_registers",
        description = "Get the complete register snapshot at a specific instruction line. \
            Shows all ARM64 registers (X0-X30, SP, PC, NZCV) with their values, \
            which registers were modified by this instruction, and which were read."
    )]
    fn get_registers(&self, Parameters(req): Parameters<GetRegistersRequest>) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        self.engine.get_registers_at(&sid, req.seq)
            .map(|regs| json(&regs))
            .map_err(|e| e.to_string())
    }

    #[tool(
        name = "get_memory",
        description = "Read memory contents at a specific address and instruction line. \
            Shows the byte values as they were at that point in execution. \
            Unknown bytes (never written) are marked in the 'known' array."
    )]
    fn get_memory(&self, Parameters(req): Parameters<GetMemoryRequest>) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        let addr = parse_hex_addr(&req.address)?;
        let length = req.length.min(256);
        self.engine.get_memory_at(&sid, addr, req.seq, length)
            .map(|snap| json(&snap))
            .map_err(|e| e.to_string())
    }

    #[tool(
        name = "get_memory_history",
        description = "Get the read/write access history for a memory address. \
            Returns records showing every time this address was read or written, \
            with the instruction that did it and the data value. \
            Supports pagination with offset/limit."
    )]
    fn get_memory_history(&self, Parameters(req): Parameters<GetMemoryHistoryRequest>) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        let addr = parse_hex_addr(&req.address)?;
        let limit = req.limit.min(MAX_HISTORY);

        let meta = self.engine.get_mem_history_meta(&sid, addr, req.center_seq)
            .map_err(|e| e.to_string())?;

        let records = self.engine.get_mem_history_range(&sid, addr, req.offset, limit)
            .map_err(|e| e.to_string())?;

        Ok(json(&serde_json::json!({
            "total": meta.total,
            "center_index": meta.center_index,
            "offset": req.offset,
            "records": records,
            "has_more": req.offset + records.len() < meta.total,
        })))
    }

    // ━━━━━━━━━━━━━━━━━━━━━━ 搜索与分析 ━━━━━━━━━━━━━━━━━━━━━━

    #[tool(
        name = "search_instructions",
        description = "Search for instructions matching a text or regex pattern in the trace. \
            Returns matching line numbers and a preview of each match. \
            Use regex for complex patterns like 'bl.*0x[0-9a-f]+' to find specific branch targets. \
            Wrap pattern in /slashes/ for auto-regex detection. \
            Supports optional seq_range ('3000-6000') and addr_range ('0x246F00-0x249800') filters \
            to narrow results to a specific execution window or code region."
    )]
    async fn search_instructions(&self, Parameters(req): Parameters<SearchInstructionsRequest>) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        let engine = self.engine.clone();
        blocking(move || {
            let max = req.max_results.unwrap_or(DEFAULT_SEARCH).min(MAX_SEARCH);
            let options = SearchOptions {
                case_sensitive: req.case_sensitive,
                use_regex: req.use_regex,
                fuzzy: false,
                max_results: Some(max),
            };
            let result = engine.search(&sid, &req.query, options)
                .map_err(|e| e.to_string())?;

            // seq range filter
            let filtered_seqs: Vec<u32> = if let Some(ref range) = req.seq_range {
                let (start, end) = parse_seq_range(range)?;
                result.match_seqs.iter()
                    .copied()
                    .filter(|&seq| seq >= start && seq <= end)
                    .collect()
            } else {
                result.match_seqs.clone()
            };

            let total_after_seq_filter = filtered_seqs.len();

            // Load lines (take more than needed to handle addr_range filtering)
            let load_count = if req.addr_range.is_some() { (max as usize) * 3 } else { max as usize };
            let preview_seqs: Vec<u32> = filtered_seqs.iter().copied().take(load_count).collect();
            let lines = engine.get_lines(&sid, &preview_seqs)
                .map_err(|e| e.to_string())?;

            // addr_range filter
            let final_lines: Vec<&TraceLine> = if let Some(ref range) = req.addr_range {
                let (start, end) = parse_addr_range(range)?;
                lines.iter()
                    .filter(|l| line_in_addr_range(l, start, end))
                    .take(max as usize)
                    .collect()
            } else {
                lines.iter().take(max as usize).collect()
            };

            let matches: Vec<serde_json::Value> = if req.full {
                final_lines.iter().map(|l| serde_json::to_value(l)
                    .unwrap_or_else(|e| serde_json::json!({"error": e.to_string()}))
                ).collect()
            } else {
                final_lines.iter().map(|l| compact_line(l)).collect()
            };

            let effective_total = if req.seq_range.is_some() || req.addr_range.is_some() {
                total_after_seq_filter
            } else {
                result.total_matches as usize
            };

            Ok(json(&serde_json::json!({
                "matches": matches,
                "total_matches": effective_total,
                "total_scanned": result.total_scanned,
                "truncated": result.truncated || final_lines.len() < total_after_seq_filter,
            })))
        }).await
    }

    #[tool(
        name = "run_taint_analysis",
        description = "Perform backward taint analysis (data dependency tracking) \
            from a register or memory address at a specific instruction. \
            Returns which instructions contributed to the tainted value. \
            Use this to trace where a value came from. \
            Register names are case-insensitive. \
            Example from_specs: ['reg:X0@1234'] traces X0 at line 1234, \
            ['mem:0xbffff000@last'] traces the last write to that address."
    )]
    async fn run_taint_analysis(&self, Parameters(req): Parameters<RunTaintAnalysisRequest>) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        let engine = self.engine.clone();
        blocking(move || {
            let options = SliceOptions {
                start_seq: req.start_seq,
                end_seq: req.end_seq,
                data_only: req.data_only,
            };
            let result = engine.run_slice(&sid, &req.from_specs, options)
                .map_err(|e| e.to_string())?;
            Ok(json(&serde_json::json!({
                "marked_count": result.marked_count,
                "total_lines": result.total_lines,
                "percentage": format!("{:.2}%", result.percentage),
                "hint": "Use get_tainted_lines to retrieve the actual tainted instructions.",
            })))
        }).await
    }

    #[tool(
        name = "get_tainted_lines",
        description = "Retrieve the instructions marked as tainted by the last run_taint_analysis. \
            Returns full line content with disassembly for each tainted instruction. \
            Supports pagination with offset/limit. \
            By default, filters out lines that only modify stack/frame pointer registers."
    )]
    fn get_tainted_lines(&self, Parameters(req): Parameters<GetTaintedLinesRequest>) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        let limit = req.limit.min(200);

        let all_seqs = self.engine.get_tainted_seqs(&sid)
            .map_err(|e| e.to_string())?;

        let total_tainted = all_seqs.len() as u32;

        // 栈操作过滤 + 分页
        let (lines, total_after_filter, stack_ops_filtered) = if req.ignore_stack_ops && !all_seqs.is_empty() {
            // 需要加载全部污点行以判断 is_stack_only_change
            let all_lines = self.engine.get_lines(&sid, &all_seqs)
                .map_err(|e| e.to_string())?;
            // 先过滤，再分页，复用已加载的行数据
            let kept: Vec<TraceLine> = all_lines.into_iter()
                .filter(|line| !is_stack_only_change(&line.changes))
                .collect();
            let filtered_count = total_tainted - kept.len() as u32;
            let after_filter = kept.len() as u32;
            let page_lines: Vec<TraceLine> = kept.into_iter()
                .skip(req.offset as usize)
                .take(limit as usize)
                .collect();
            (page_lines, after_filter, filtered_count)
        } else {
            // 无过滤：只加载分页所需的行
            let page_seqs: Vec<u32> = all_seqs.iter()
                .skip(req.offset as usize)
                .take(limit as usize)
                .copied()
                .collect();
            let page_lines = self.engine.get_lines(&sid, &page_seqs)
                .map_err(|e| e.to_string())?;
            (page_lines, total_tainted, 0u32)
        };

        // 上下文摘要
        let context = self.engine.get_slice_origin(&sid)
            .ok()
            .flatten()
            .map(|o| {
                let mut ctx = format!("taint from {}, data_only={}",
                    o.from_specs.join(", "), o.data_only);
                if let Some(s) = o.start_seq {
                    ctx.push_str(&format!(", start_seq={}", s));
                }
                if let Some(e) = o.end_seq {
                    ctx.push_str(&format!(", end_seq={}", e));
                }
                ctx
            });

        Ok(json(&serde_json::json!({
            "context": context,
            "lines": format_lines(&lines, req.full),
            "total_tainted": total_tainted,
            "total_after_filter": total_after_filter,
            "stack_ops_filtered": stack_ops_filtered,
            "offset": req.offset,
            "count": lines.len(),
            "has_more": (req.offset as usize + lines.len()) < total_after_filter as usize,
        })))
    }

    #[tool(
        name = "clear_taint",
        description = "Clear the current taint analysis results. \
            Call this before running a new taint analysis if you want fresh results."
    )]
    fn clear_taint(&self, Parameters(req): Parameters<ClearTaintRequest>) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        self.engine.clear_slice(&sid)
            .map(|()| "Taint results cleared.".to_string())
            .map_err(|e| e.to_string())
    }

    #[tool(
        name = "get_dependency_tree",
        description = "Build a dependency graph showing how a value at a specific instruction \
            was computed. Returns a DAG of instructions connected by data/control dependencies. \
            Useful for understanding the full computation chain of a value. \
            Target format: 'reg:X0' for a register (case-insensitive), 'mem:0xaddr' for a memory address."
    )]
    async fn get_dependency_tree(&self, Parameters(req): Parameters<GetDependencyTreeRequest>) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        let engine = self.engine.clone();
        blocking(move || {
            let max_nodes = req.max_nodes.unwrap_or(MAX_DEP_NODES).min(MAX_DEP_NODES);
            let options = DepTreeOptions {
                data_only: req.data_only,
                max_nodes: Some(max_nodes),
            };
            engine.build_dep_tree(&sid, req.seq, &req.target, options)
                .map(|graph| json(&graph))
                .map_err(|e| e.to_string())
        }).await
    }

    #[tool(
        name = "get_def_use_chain",
        description = "Get the definition-use chain for a register at a specific instruction. \
            If the register is USED at this line, returns the upstream DEF (where it was last written). \
            If the register is DEFined at this line, returns all downstream USEs until it's redefined. \
            Register names are case-insensitive. \
            Useful for tracking register value propagation."
    )]
    fn get_def_use_chain(&self, Parameters(req): Parameters<GetDefUseChainRequest>) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        self.engine.get_def_use_chain(&sid, req.seq, &req.register.to_lowercase())
            .map(|chain| json(&chain))
            .map_err(|e| e.to_string())
    }

    // ━━━━━━━━━━━━━━━━━━━━━━ 结构信息 ━━━━━━━━━━━━━━━━━━━━━━

    #[tool(
        name = "get_call_tree",
        description = "Get the function call tree rooted at a specific node. \
            Returns the node itself plus its direct children (lazy loading). \
            Use node_id=0 to start from the root. Each node contains: \
            function address, name, entry/exit line numbers, and child node IDs."
    )]
    fn get_call_tree(&self, Parameters(req): Parameters<GetCallTreeRequest>) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        self.engine.get_call_tree_children(&sid, req.node_id, true)
            .map(|nodes| json(&nodes))
            .map_err(|e| e.to_string())
    }

    #[tool(
        name = "get_function_info",
        description = "Get detailed information about a specific function call in the call tree. \
            Returns the function's address, name, entry/exit lines, line count, and child calls."
    )]
    fn get_function_info(&self, Parameters(req): Parameters<GetFunctionInfoRequest>) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        let nodes = self.engine.get_call_tree_children(&sid, req.node_id, true)
            .map_err(|e| e.to_string())?;
        match nodes.first() {
            Some(node) => Ok(json(node)),
            None => Err(format!("Node {} not found", req.node_id)),
        }
    }

    #[tool(
        name = "get_function_list",
        description = "Get an aggregated list of all function calls found in the trace. \
            Groups calls by function name, showing each occurrence with its line number. \
            Useful for finding where specific functions are called."
    )]
    fn get_function_list(&self, Parameters(req): Parameters<GetFunctionListRequest>) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        self.engine.get_function_calls(&sid)
            .map(|result| json(&result))
            .map_err(|e| e.to_string())
    }

    #[tool(
        name = "get_strings",
        description = "List runtime strings found in the trace. \
            These are strings observed in memory during execution. \
            Supports filtering by minimum length and search query. \
            Each string includes its memory address, content, encoding, and access type."
    )]
    fn get_strings(&self, Parameters(req): Parameters<GetStringsRequest>) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        let limit = req.limit.min(200);
        let options = StringQueryOptions {
            min_len: req.min_len,
            offset: req.offset,
            limit,
            search: req.search,
        };
        let result = self.engine.get_strings(&sid, options)
            .map_err(|e| e.to_string())?;
        Ok(json(&serde_json::json!({
            "strings": result.strings,
            "total": result.total,
            "offset": req.offset,
            "has_more": (req.offset + result.strings.len() as u32) < result.total,
        })))
    }

    #[tool(
        name = "get_string_xrefs",
        description = "Get cross-references for a specific string: all instructions that \
            read or write the string's memory address. Each xref includes the instruction \
            address, disassembly, and read/write type."
    )]
    fn get_string_xrefs(&self, Parameters(req): Parameters<GetStringXRefsRequest>) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        let addr = parse_hex_addr(&req.address)?;
        self.engine.get_string_xrefs(&sid, addr, req.byte_len)
            .map(|xrefs| json(&xrefs))
            .map_err(|e| e.to_string())
    }

    #[tool(
        name = "scan_crypto_patterns",
        description = "Scan the trace for known cryptographic algorithm signatures \
            (AES, SHA256, MD5, etc.) by detecting magic number constants in register values. \
            Returns matched algorithms and the instructions where they appear."
    )]
    async fn scan_crypto_patterns(&self, Parameters(req): Parameters<ScanCryptoPatternsRequest>) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        let engine = self.engine.clone();
        blocking(move || {
            if let Ok(Some(cached)) = engine.load_crypto_cache(&sid) {
                return Ok(json(&cached));
            }
            engine.scan_crypto(&sid)
                .map(|result| json(&result))
                .map_err(|e| e.to_string())
        }).await
    }

    // ━━━━━━━━━━━━━━━━━━━━━━ 扩展工具 ━━━━━━━━━━━━━━━━━━━━━━

    #[tool(
        name = "export_taint_results",
        description = "Export the current taint analysis results to a file. \
            Requires a prior run_taint_analysis call. \
            Supports 'json' (structured with metadata) and 'txt' (raw tainted lines) formats."
    )]
    async fn export_taint_results(&self, Parameters(req): Parameters<ExportTaintResultsRequest>) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        let engine = self.engine.clone();
        blocking(move || {
            // ExportConfig requires from_specs — retrieve from session's stored slice_origin
            // For MCP export, we pass empty config since the slice is already computed
            let config = ExportConfig {
                from_specs: vec![],
                start_seq: None,
                end_seq: None,
            };
            engine.export_taint_results(&sid, &req.output_path, &req.format, config)
                .map(|()| json(&serde_json::json!({
                    "exported": true,
                    "path": req.output_path,
                    "format": req.format,
                })))
                .map_err(|e| e.to_string())
        }).await
    }

    #[tool(
        name = "build_dep_tree_from_slice",
        description = "Build a dependency graph from the current taint analysis results. \
            Requires a prior run_taint_analysis call. \
            This is more convenient than get_dependency_tree when you already have taint results, \
            as it automatically uses the tainted instructions as the starting points."
    )]
    async fn build_dep_tree_from_slice(&self, Parameters(req): Parameters<BuildDepTreeFromSliceRequest>) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        let engine = self.engine.clone();
        blocking(move || {
            let max_nodes = req.max_nodes.unwrap_or(MAX_DEP_NODES).min(MAX_DEP_NODES);
            let options = DepTreeOptions {
                data_only: req.data_only,
                max_nodes: Some(max_nodes),
            };
            engine.build_dep_tree_from_slice(&sid, options)
                .map(|graph| json(&graph))
                .map_err(|e| e.to_string())
        }).await
    }

    #[tool(
        name = "get_line_def_registers",
        description = "Get the list of registers defined (written) by a specific instruction. \
            Useful before calling get_def_use_chain to know which registers are available. \
            Returns register names like ['X0', 'X1']."
    )]
    fn get_line_def_registers(&self, Parameters(req): Parameters<GetLineDefRegistersRequest>) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        self.engine.get_line_def_registers(&sid, req.seq)
            .map(|regs| json(&regs))
            .map_err(|e| e.to_string())
    }

    #[tool(
        name = "get_call_tree_node_count",
        description = "Get the total number of nodes in the function call tree. \
            Useful for understanding the scale of the call tree before exploring it."
    )]
    fn get_call_tree_node_count(&self, Parameters(req): Parameters<GetCallTreeNodeCountRequest>) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        self.engine.get_call_tree_node_count(&sid)
            .map(|count| json(&serde_json::json!({ "node_count": count })))
            .map_err(|e| e.to_string())
    }

    #[tool(
        name = "scan_strings",
        description = "Scan the trace for runtime strings. Only needed if open_trace was called \
            with skip_strings=true. After this completes, get_strings and get_string_xrefs \
            will have data. This may take a while for large traces."
    )]
    async fn scan_strings(&self, Parameters(req): Parameters<ScanStringsRequest>) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        let engine = self.engine.clone();
        blocking(move || {
            engine.scan_strings(&sid)
                .map(|()| json(&serde_json::json!({
                    "status": "String scanning completed.",
                })))
                .map_err(|e| e.to_string())
        }).await
    }
}

#[tool_handler]
impl ServerHandler for TraceToolHandler {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(
            ServerCapabilities::builder()
                .enable_tools()
                .build(),
        )
        .with_instructions(
            "Trace UI MCP Server — analyze ARM64 execution traces. \
             Start by calling open_trace with a file path, then use the returned \
             session_id for all analysis operations. Available analyses: \
             instruction browsing, register/memory inspection, taint analysis, \
             dependency trees, function call trees, string extraction, and \
             cryptographic pattern detection.".to_string(),
        )
    }
}
