use std::sync::Arc;

use rmcp::{
    ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{ServerCapabilities, ServerInfo},
    tool, tool_handler, tool_router,
};

use trace_core::{TraceEngine, BuildOptions, SearchOptions, SliceOptions, StringQueryOptions, parse_hex_addr, api_types::TraceLine};
use crate::types::*;

// ── 截断常量 ──
// NOTE: 修改这些值时，需同步更新对应 #[tool] 描述中的硬编码数字。

// Referenced in: get_trace_lines description ("up to 100 lines per call")
const MAX_LINES: u32 = 100;
// Referenced in: search_instructions description ("up to 200 results")
const MAX_SEARCH: u32 = 200;
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
        name = "get_memory",
        description = "Read memory contents at a specific address and instruction line. \
            Shows the byte values as they were at that point in execution. \
            Unknown bytes (never written) are marked in the 'known' array."
    )]
    fn get_memory(&self, Parameters(req): Parameters<GetMemoryRequest>) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        let addr = parse_hex_addr(&req.address)?;
        let length = req.length.min(256);
        let seq = match req.seq {
            Some(s) => s,
            None => {
                let info = self.engine.get_session_info(&sid).map_err(|e| e.to_string())?;
                info.total_lines.saturating_sub(1)
            }
        };
        self.engine.get_memory_at(&sid, addr, seq, length)
            .map(|snap| json(&snap))
            .map_err(|e| e.to_string())
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
        name = "get_tainted_lines",
        description = "Retrieve the instructions marked as tainted by the last run_taint_analysis or taint_analysis. \
            Returns full line content with disassembly for each tainted instruction. \
            Supports pagination with offset/limit. \
            By default, filters out lines that only modify stack/frame pointer registers. \
            Supports addr_range filter and context_lines to show surrounding non-tainted lines."
    )]
    fn get_tainted_lines(&self, Parameters(req): Parameters<GetTaintedLinesRequest>) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        let limit = req.limit.min(200);
        let ctx_lines = req.context_lines.min(5);

        let all_seqs = self.engine.get_tainted_seqs(&sid)
            .map_err(|e| e.to_string())?;

        let total_tainted = all_seqs.len() as u32;

        // 栈操作过滤
        let (after_stack_filter, stack_ops_filtered) = if req.ignore_stack_ops && !all_seqs.is_empty() {
            let all_lines = self.engine.get_lines(&sid, &all_seqs)
                .map_err(|e| e.to_string())?;
            let kept: Vec<TraceLine> = all_lines.into_iter()
                .filter(|line| !is_stack_only_change(&line.changes))
                .collect();
            let filtered_count = total_tainted - kept.len() as u32;
            (kept, filtered_count)
        } else {
            let all_lines = self.engine.get_lines(&sid, &all_seqs)
                .map_err(|e| e.to_string())?;
            (all_lines, 0u32)
        };

        // 地址范围过滤
        let after_addr_filter: Vec<TraceLine> = if let Some(ref range) = req.addr_range {
            let (start, end) = parse_addr_range(range)?;
            after_stack_filter.into_iter()
                .filter(|l| line_in_addr_range(l, start, end))
                .collect()
        } else {
            after_stack_filter
        };

        let total_after_filter = after_addr_filter.len() as u32;

        // 分页
        let page_lines: Vec<TraceLine> = after_addr_filter.into_iter()
            .skip(req.offset as usize)
            .take(limit as usize)
            .collect();

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

        // 上下文行展开
        if ctx_lines > 0 && !page_lines.is_empty() {
            let tainted_seqs: std::collections::HashSet<u32> = page_lines.iter().map(|l| l.seq).collect();
            let mut expanded_seqs = std::collections::BTreeSet::new();
            for line in &page_lines {
                let start = line.seq.saturating_sub(ctx_lines);
                let end = line.seq.saturating_add(ctx_lines);
                for s in start..=end {
                    expanded_seqs.insert(s);
                }
            }
            let extra_seqs: Vec<u32> = expanded_seqs.iter().copied()
                .filter(|s| !tainted_seqs.contains(s))
                .collect();
            let extra_lines = self.engine.get_lines(&sid, &extra_seqs)
                .unwrap_or_default();
            let extra_map: std::collections::HashMap<u32, &TraceLine> = extra_lines.iter()
                .map(|l| (l.seq, l))
                .collect();

            let mut output_lines: Vec<serde_json::Value> = Vec::new();
            for seq in expanded_seqs {
                if let Some(tl) = page_lines.iter().find(|l| l.seq == seq) {
                    let mut obj = if req.full {
                        serde_json::to_value(tl).unwrap_or_else(|e| serde_json::json!({"error": e.to_string()}))
                    } else {
                        compact_line(tl)
                    };
                    obj.as_object_mut().map(|o| o.insert("tainted".to_string(), serde_json::json!(true)));
                    output_lines.push(obj);
                } else if let Some(el) = extra_map.get(&seq) {
                    let mut obj = if req.full {
                        serde_json::to_value(*el).unwrap_or_else(|e| serde_json::json!({"error": e.to_string()}))
                    } else {
                        compact_line(el)
                    };
                    obj.as_object_mut().map(|o| o.insert("tainted".to_string(), serde_json::json!(false)));
                    output_lines.push(obj);
                }
            }

            return Ok(json(&serde_json::json!({
                "context": context,
                "lines": output_lines,
                "total_tainted": total_tainted,
                "total_after_filter": total_after_filter,
                "stack_ops_filtered": stack_ops_filtered,
                "offset": req.offset,
                "count": page_lines.len(),
                "context_lines": ctx_lines,
                "has_more": (req.offset as usize + page_lines.len()) < total_after_filter as usize,
            })));
        }

        Ok(json(&serde_json::json!({
            "context": context,
            "lines": format_lines(&page_lines, req.full),
            "total_tainted": total_tainted,
            "total_after_filter": total_after_filter,
            "stack_ops_filtered": stack_ops_filtered,
            "offset": req.offset,
            "count": page_lines.len(),
            "has_more": (req.offset as usize + page_lines.len()) < total_after_filter as usize,
        })))
    }


    // ━━━━━━━━━━━━━━━━━━━━━━ 结构信息 ━━━━━━━━━━━━━━━━━━━━━━

    fn collect_tree_to_depth(
        &self,
        session_id: &str,
        node_id: u32,
        depth: u32,
        max_nodes: u32,
    ) -> Result<Vec<serde_json::Value>, String> {
        let nodes = self.engine.get_call_tree_children(session_id, node_id, true)
            .map_err(|e| e.to_string())?;
        if nodes.is_empty() {
            return Ok(vec![]);
        }
        let mut result: Vec<serde_json::Value> = vec![serde_json::to_value(&nodes[0])
            .map_err(|e| e.to_string())?];
        if depth <= 1 {
            for child in &nodes[1..] {
                if result.len() as u32 >= max_nodes { break; }
                result.push(serde_json::to_value(child).map_err(|e| e.to_string())?);
            }
        } else {
            for child in &nodes[1..] {
                if result.len() as u32 >= max_nodes { break; }
                let remaining = max_nodes - result.len() as u32;
                let sub = self.collect_tree_to_depth(session_id, child.id, depth - 1, remaining)?;
                result.extend(sub);
            }
        }
        Ok(result)
    }

    #[tool(
        name = "get_call_tree",
        description = "Get the function call tree rooted at a specific node. \
            Use node_id=0 to start from the root. depth controls expansion levels (1-3). \
            Returns nodes array, count, total_node_count (full tree size), and depth used. \
            Each node contains: function address, name, entry/exit line numbers, and child node IDs."
    )]
    fn get_call_tree(&self, Parameters(req): Parameters<GetCallTreeRequest>) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        let depth = req.depth.min(3).max(1);
        let max_nodes: u32 = 500;
        let nodes = self.collect_tree_to_depth(&sid, req.node_id, depth, max_nodes)?;
        let total_count = self.engine.get_call_tree_node_count(&sid).unwrap_or(0);
        Ok(json(&serde_json::json!({
            "nodes": nodes,
            "count": nodes.len(),
            "total_node_count": total_count,
            "depth": depth,
            "hint": "Use analyze_function with node_id for detailed analysis including entry arguments.",
        })))
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
        let has_results = !result.strings.is_empty();
        let mut response = serde_json::json!({
            "strings": result.strings,
            "total": result.total,
            "offset": req.offset,
            "has_more": (req.offset + result.strings.len() as u32) < result.total,
        });
        if has_results {
            response["hint"] = serde_json::json!("Use get_string_xrefs with address and byte_len to find which instructions access a string.");
        }
        Ok(json(&response))
    }

    // ━━━━━━━━━━━━━━━━━━━━━━ Batch 2: 组合工具 ━━━━━━━━━━━━━━━━━━━━━━

    #[tool(
        name = "taint_analysis",
        description = "Run backward taint analysis and return results in one call. \
            Traces where a value came from by following data/control dependencies. \
            Returns analysis stats plus the first page of tainted instructions. \
            Use get_tainted_lines to paginate if has_more is true."
    )]
    async fn taint_analysis(&self, Parameters(req): Parameters<TaintAnalysisRequest>) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        let engine = self.engine.clone();
        blocking(move || {
            // 1. 执行污点分析
            let options = SliceOptions {
                start_seq: req.start_seq,
                end_seq: req.end_seq,
                data_only: req.data_only,
            };
            let result = engine.run_slice(&sid, &req.from_specs, options)
                .map_err(|e| e.to_string())?;

            // 2. 仅返回统计信息
            let include = req.include_lines.min(200);
            if include == 0 {
                return Ok(json(&serde_json::json!({
                    "marked_count": result.marked_count,
                    "total_lines": result.total_lines,
                    "percentage": format!("{:.2}%", result.percentage),
                    "lines": [],
                    "total_after_filter": result.marked_count,
                    "stack_ops_filtered": 0,
                    "count": 0,
                    "has_more": result.marked_count > 0,
                    "hint": "Use get_tainted_lines to retrieve tainted instructions.",
                })));
            }

            // 3. 获取污点行
            let all_seqs = engine.get_tainted_seqs(&sid)
                .map_err(|e| e.to_string())?;

            if all_seqs.is_empty() {
                return Ok(json(&serde_json::json!({
                    "marked_count": result.marked_count,
                    "total_lines": result.total_lines,
                    "percentage": format!("{:.2}%", result.percentage),
                    "lines": [],
                    "total_after_filter": 0,
                    "stack_ops_filtered": 0,
                    "count": 0,
                    "has_more": false,
                })));
            }

            let all_lines = engine.get_lines(&sid, &all_seqs)
                .map_err(|e| e.to_string())?;

            // 4. 栈操作过滤
            let (kept, stack_filtered) = if req.ignore_stack_ops {
                let before = all_lines.len();
                let filtered: Vec<TraceLine> = all_lines.into_iter()
                    .filter(|l| !is_stack_only_change(&l.changes))
                    .collect();
                let diff = before - filtered.len();
                (filtered, diff as u32)
            } else {
                (all_lines, 0u32)
            };

            // 5. 地址范围过滤
            let after_addr: Vec<TraceLine> = if let Some(ref range) = req.addr_range {
                let (start, end) = parse_addr_range(range)?;
                kept.into_iter()
                    .filter(|l| line_in_addr_range(l, start, end))
                    .collect()
            } else {
                kept
            };

            let total_after_filter = after_addr.len();

            // 6. 取前 include 行
            let page: Vec<&TraceLine> = after_addr.iter().take(include as usize).collect();
            let count = page.len();
            let lines: Vec<serde_json::Value> = page.iter().map(|l| compact_line(l)).collect();

            Ok(json(&serde_json::json!({
                "marked_count": result.marked_count,
                "total_lines": result.total_lines,
                "percentage": format!("{:.2}%", result.percentage),
                "lines": lines,
                "total_after_filter": total_after_filter,
                "stack_ops_filtered": stack_filtered,
                "count": count,
                "has_more": count < total_after_filter,
                "hint": if count < total_after_filter {
                    "Use get_tainted_lines with offset to see more results."
                } else {
                    "All tainted lines included."
                },
            })))
        }).await
    }

    #[tool(
        name = "analyze_function",
        description = "Analyze functions. Three modes: \
            (1) node_id: detailed analysis of one call with entry args (X0-X7) and return value (X0). \
            (2) func_name: find all calls matching a name (partial, case-insensitive). \
            (3) No arguments: list all functions with pagination (use offset/limit)."
    )]
    fn analyze_function(&self, Parameters(req): Parameters<AnalyzeFunctionRequest>) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;

        if let Some(node_id) = req.node_id {
            // Mode 1: 按 node_id 分析函数调用详情
            let nodes = self.engine.get_call_tree_children(&sid, node_id, true)
                .map_err(|e| e.to_string())?;
            let node = nodes.first()
                .ok_or_else(|| format!("Node {} not found", node_id))?;

            // 获取入口参数 X0-X7
            let entry_regs = self.engine.get_registers_at(&sid, node.entry_seq)
                .unwrap_or_default();
            let mut args = serde_json::Map::new();
            for i in 0..=7 {
                let reg_name = format!("X{}", i);
                if let Some(val) = entry_regs.get(&reg_name) {
                    args.insert(reg_name, serde_json::json!(val));
                }
            }

            // 获取返回值
            let return_value = if node.exit_seq > node.entry_seq {
                self.engine.get_registers_at(&sid, node.exit_seq)
                    .ok()
                    .and_then(|regs| regs.get("X0").cloned())
            } else {
                None
            };

            // 子调用
            let children = nodes.iter().skip(1).collect::<Vec<_>>();
            let sub_calls: Vec<serde_json::Value> = children.iter().map(|c| {
                serde_json::json!({
                    "node_id": c.id,
                    "func_name": c.func_name,
                    "func_addr": c.func_addr,
                    "entry_seq": c.entry_seq,
                    "exit_seq": c.exit_seq,
                    "line_count": c.line_count,
                })
            }).collect();

            Ok(json(&serde_json::json!({
                "node_id": node.id,
                "func_name": node.func_name,
                "func_addr": node.func_addr,
                "entry_seq": node.entry_seq,
                "exit_seq": node.exit_seq,
                "line_count": node.line_count,
                "args": args,
                "return_value": return_value,
                "sub_calls": sub_calls,
                "sub_call_count": sub_calls.len(),
            })))

        } else if let Some(ref func_name) = req.func_name {
            // Mode 2: 按名称搜索函数
            let result = self.engine.get_function_calls(&sid)
                .map_err(|e| e.to_string())?;

            let query_lower = func_name.to_lowercase();
            let matched: Vec<serde_json::Value> = result.functions.iter()
                .filter(|f| f.func_name.to_lowercase().contains(&query_lower))
                .map(|f| {
                    let occs: Vec<serde_json::Value> = f.occurrences.iter()
                        .take(50)
                        .map(|o| serde_json::json!({
                            "seq": o.seq,
                            "summary": o.summary,
                        }))
                        .collect();
                    let total_occs = f.occurrences.len();
                    serde_json::json!({
                        "func_name": f.func_name,
                        "call_count": total_occs,
                        "is_jni": f.is_jni,
                        "occurrences": occs,
                        "occurrences_truncated": total_occs > 50,
                    })
                })
                .collect();

            Ok(json(&serde_json::json!({
                "query": func_name,
                "matched_functions": matched.len(),
                "functions": matched,
                "hint": if matched.is_empty() {
                    "No functions matched. Try a broader search term or use analyze_function with no arguments to list all functions."
                } else {
                    "Use analyze_function with node_id from get_call_tree to inspect a specific call's arguments and return value."
                },
            })))

        } else {
            // Mode 3: list all functions with pagination
            let result = self.engine.get_function_calls(&sid)
                .map_err(|e| e.to_string())?;

            let limit = req.limit.min(100) as usize;
            let total = result.functions.len();
            let page: Vec<serde_json::Value> = result.functions.iter()
                .skip(req.offset as usize)
                .take(limit)
                .map(|f| serde_json::json!({
                    "func_name": f.func_name,
                    "call_count": f.occurrences.len(),
                    "is_jni": f.is_jni,
                }))
                .collect();

            Ok(json(&serde_json::json!({
                "functions": page,
                "total": total,
                "total_calls": result.total_calls,
                "offset": req.offset,
                "has_more": (req.offset as usize + page.len()) < total,
                "hint": "Use analyze_function with func_name to search, or node_id for detailed analysis with entry arguments.",
            })))
        }
    }

    #[tool(
        name = "analyze_crypto",
        description = "Detect cryptographic algorithms in the trace with surrounding code context. \
            Scans for magic constants of known algorithms (AES, SHA256, MD5, DES, etc.). \
            Returns each detection with context instructions. \
            Use taint_analysis on detection points to trace key/data sources."
    )]
    async fn analyze_crypto(&self, Parameters(req): Parameters<AnalyzeCryptoRequest>) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        let engine = self.engine.clone();
        blocking(move || {
            let ctx_count = req.context_lines.min(10);

            // 1. 尝试缓存，否则扫描
            let scan_result = if let Ok(Some(cached)) = engine.load_crypto_cache(&sid) {
                cached
            } else {
                engine.scan_crypto(&sid)
                    .map_err(|e| e.to_string())?
            };

            // 2. 为每个匹配收集上下文行
            let mut matches_output: Vec<serde_json::Value> = Vec::new();
            for m in &scan_result.matches {
                let start = m.seq.saturating_sub(ctx_count);
                let end = m.seq.saturating_add(ctx_count);
                let ctx_seqs: Vec<u32> = (start..=end).collect();
                let ctx_lines = engine.get_lines(&sid, &ctx_seqs)
                    .unwrap_or_default();

                let context: Vec<serde_json::Value> = ctx_lines.iter().map(|l| {
                    let mut obj = compact_line(l);
                    obj.as_object_mut().map(|o| {
                        o.insert("is_match".to_string(), serde_json::json!(l.seq == m.seq));
                    });
                    obj
                }).collect();

                matches_output.push(serde_json::json!({
                    "algorithm": m.algorithm,
                    "magic_hex": m.magic_hex,
                    "seq": m.seq,
                    "address": m.address,
                    "disasm": m.disasm,
                    "context": context,
                }));
            }

            Ok(json(&serde_json::json!({
                "algorithms_found": scan_result.algorithms_found,
                "match_count": scan_result.matches.len(),
                "matches": matches_output,
                "total_lines_scanned": scan_result.total_lines_scanned,
                "hint": "Use taint_analysis with 'reg:X0@<seq>' on a match's seq to trace the key/data source.",
            })))
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
            "Trace UI MCP Server — analyze ARM64 execution traces.\n\n\
             Workflow:\n\
             1. Start: open_trace with file path → get session overview\n\
             2. Overview: analyze_function (no args) to list functions, analyze_crypto to detect algorithms\n\
             3. Locate: search_instructions (supports seq_range/addr_range filtering)\n\
             4. Trace: taint_analysis to track data flow (returns stats + first page of results)\n\
             5. Deep dive: get_dependency_tree or get_def_use_chain on specific instructions\n\
             6. Extract: get_memory / get_registers at key points\n\n\
             Tips:\n\
             - session_id is optional when only one trace is open\n\
             - Use data_only=true in taint_analysis to reduce noise\n\
             - analyze_function with node_id shows entry args (X0-X7) and return value\n\
             - Use addr_range to focus search/taint on a specific address range".to_string(),
        )
    }
}
