use serde::Deserialize;
use schemars::JsonSchema;

// ── 会话管理 ──

#[derive(Debug, Deserialize, JsonSchema)]
pub struct OpenTraceRequest {
    #[schemars(description = "Absolute path to the trace file to open")]
    pub file_path: String,
    #[schemars(description = "Force rebuild the index even if cache exists")]
    #[serde(default)]
    pub force_rebuild: bool,
    #[schemars(description = "Skip building string index to speed up opening (default: false)")]
    #[serde(default)]
    pub skip_strings: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CloseTraceRequest {
    #[schemars(description = "Session ID returned by open_trace")]
    pub session_id: String,
}

// ── 数据查看 ──

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetTraceLinesRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(description = "Starting line number (0-based sequence number)")]
    pub start_seq: u32,
    #[schemars(description = "Number of lines to retrieve (default: 20, max: 100)")]
    #[serde(default = "default_line_count")]
    pub count: u32,
    #[schemars(description = "Return full TraceLine fields including raw, reg_before, so_offset, mem_size (default: false)")]
    #[serde(default)]
    pub full: bool,
}

fn default_line_count() -> u32 { 20 }

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetRegistersRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(description = "Line number (0-based) to inspect registers at")]
    pub seq: u32,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetMemoryRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(description = "Memory address in hex (e.g. '0xbffff000')")]
    pub address: String,
    #[schemars(description = "Line number to read memory at (default: last line of trace)")]
    pub seq: Option<u32>,
    #[schemars(description = "Number of bytes to read (default: 64, max: 256)")]
    #[serde(default = "default_mem_length")]
    pub length: u32,
}

fn default_mem_length() -> u32 { 64 }

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetMemoryHistoryRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(description = "Memory address in hex (e.g. '0xbffff000')")]
    pub address: String,
    #[schemars(description = "Center the history view around this line number")]
    pub center_seq: u32,
    #[schemars(description = "Starting index in history records (for pagination, default: 0)")]
    #[serde(default)]
    pub offset: usize,
    #[schemars(description = "Max records to return (default: 30, max: 200)")]
    #[serde(default = "default_history_limit")]
    pub limit: usize,
}

fn default_history_limit() -> usize { 30 }

// ── 搜索与分析 ──

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SearchInstructionsRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(description = "Search query. Plain text or regex (wrap in /pattern/ for auto-regex). Use regex for complex patterns like 'bl.*0x[0-9a-f]+'")]
    pub query: String,
    #[schemars(description = "Use regex matching")]
    #[serde(default)]
    pub use_regex: bool,
    #[schemars(description = "Case-sensitive matching")]
    #[serde(default)]
    pub case_sensitive: bool,
    #[schemars(description = "Max results to return (default: 30, max: 200)")]
    pub max_results: Option<u32>,
    #[schemars(description = "Return full TraceLine fields including raw, reg_before, so_offset, mem_size (default: false)")]
    #[serde(default)]
    pub full: bool,
    #[schemars(description = "Limit search to seq range, e.g. '3000-6000'")]
    pub seq_range: Option<String>,
    #[schemars(description = "Filter results by SO offset address range, e.g. '0x246F00-0x249800'")]
    pub addr_range: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetTaintedLinesRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(description = "Pagination offset (default: 0)")]
    #[serde(default)]
    pub offset: u32,
    #[schemars(description = "Max lines to return (default: 50, max: 200)")]
    #[serde(default = "default_taint_limit")]
    pub limit: u32,
    #[schemars(description = "Return full TraceLine fields including raw, reg_before, so_offset, mem_size (default: false)")]
    #[serde(default)]
    pub full: bool,
    #[schemars(description = "Filter out lines that only modify stack/frame pointer registers (sp, x29). Default: true")]
    #[serde(default = "default_true")]
    pub ignore_stack_ops: bool,
    #[schemars(description = "Filter by SO offset address range, e.g. '0x246F00-0x249800'")]
    pub addr_range: Option<String>,
    #[schemars(description = "Include N non-tainted context lines before/after each tainted line (default: 0, max: 5)")]
    #[serde(default)]
    pub context_lines: u32,
}

fn default_taint_limit() -> u32 { 50 }
fn default_true() -> bool { true }

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetDependencyTreeRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(description = "Line number (0-based) to build dependency tree from")]
    pub seq: u32,
    #[schemars(description = "Target: 'reg:X0' for register (case-insensitive), 'mem:0xaddr' for memory address")]
    pub target: String,
    #[schemars(description = "Only data dependencies (no control flow)")]
    #[serde(default)]
    pub data_only: bool,
    #[schemars(description = "Max nodes in the graph (default: 200)")]
    pub max_nodes: Option<u32>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetDefUseChainRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(description = "Line number (0-based)")]
    pub seq: u32,
    #[schemars(description = "Register name, case-insensitive (e.g. 'X0', 'SP', 'x29')")]
    pub register: String,
}

// ── 结构信息 ──

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetCallTreeRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(description = "Node ID to get children for (0 = root). Use this for lazy loading of large call trees")]
    pub node_id: u32,
    #[schemars(description = "Number of levels to expand (default: 1, max: 3). depth=1 returns node + direct children")]
    #[serde(default = "default_depth")]
    pub depth: u32,
}

fn default_depth() -> u32 { 1 }

fn default_func_list_limit() -> u32 { 30 }

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetStringsRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(description = "Minimum string length to include (default: 4)")]
    #[serde(default = "default_min_str_len")]
    pub min_len: u32,
    #[schemars(description = "Filter strings containing this substring")]
    pub search: Option<String>,
    #[schemars(description = "Pagination offset (default: 0)")]
    #[serde(default)]
    pub offset: u32,
    #[schemars(description = "Max strings to return (default: 50, max: 200)")]
    #[serde(default = "default_strings_limit")]
    pub limit: u32,
}

fn default_min_str_len() -> u32 { 4 }
fn default_strings_limit() -> u32 { 50 }

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetStringXRefsRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(description = "Memory address of the string in hex (e.g. '0xbffff000'), obtained from get_strings result")]
    pub address: String,
    #[schemars(description = "Byte length of the string (from get_strings result's byte_len field)")]
    pub byte_len: u32,
    #[schemars(description = "Pagination offset (default: 0)")]
    #[serde(default)]
    pub offset: u32,
    #[schemars(description = "Max xrefs to return (default: 30, max: 100)")]
    #[serde(default = "default_xref_limit")]
    pub limit: u32,
}

fn default_xref_limit() -> u32 { 30 }

// ── Batch 2 新增工具请求类型 ──

#[derive(Debug, Deserialize, JsonSchema)]
pub struct TaintAnalysisRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(description = "Taint sources (case-insensitive register names): \
        'reg:X0@1234' (register at line), 'mem:0xbffff000@1234' (memory at line), \
        '@last' for last definition. Examples: ['reg:X0@last'], ['mem:0xbffff000@5930']")]
    pub from_specs: Vec<String>,
    #[schemars(description = "Only track data dependencies, ignore control flow (recommended for reducing noise)")]
    #[serde(default)]
    pub data_only: bool,
    #[schemars(description = "Restrict analysis to lines >= this seq")]
    pub start_seq: Option<u32>,
    #[schemars(description = "Restrict analysis to lines <= this seq")]
    pub end_seq: Option<u32>,
    #[schemars(description = "Number of tainted lines to include in result (default: 30, 0=stats only, max: 200)")]
    #[serde(default = "default_inline_lines")]
    pub include_lines: u32,
    #[schemars(description = "Filter results by SO offset address range, e.g. '0x246F00-0x249800'")]
    pub addr_range: Option<String>,
    #[schemars(description = "Filter out lines that only modify stack/frame pointer registers (default: true)")]
    #[serde(default = "default_true")]
    pub ignore_stack_ops: bool,
}

fn default_inline_lines() -> u32 { 30 }

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AnalyzeFunctionRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(description = "Call tree node ID for detailed analysis of a specific function call (from get_call_tree)")]
    pub node_id: Option<u32>,
    #[schemars(description = "Search for all calls to functions matching this name (partial, case-insensitive). \
        Omit both node_id and func_name to list all functions.")]
    pub func_name: Option<String>,
    #[schemars(description = "Pagination offset when listing functions (default: 0)")]
    #[serde(default)]
    pub offset: u32,
    #[schemars(description = "Max functions to return when listing (default: 30, max: 100)")]
    #[serde(default = "default_func_list_limit")]
    pub limit: u32,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AnalyzeCryptoRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(description = "Number of context lines around each crypto match (default: 3, max: 10)")]
    #[serde(default = "default_crypto_context")]
    pub context_lines: u32,
}

fn default_crypto_context() -> u32 { 3 }
