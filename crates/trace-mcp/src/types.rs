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

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetSessionInfoRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
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
    #[schemars(description = "Line number (0-based) at which to read memory state")]
    pub seq: u32,
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
pub struct RunTaintAnalysisRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(description = "Taint sources (case-insensitive register names): \
        'reg:X0@1234' (register X0 at line 1234), \
        'mem:0xbffff000@1234' (memory address at line), \
        use '@last' for last definition")]
    pub from_specs: Vec<String>,
    #[schemars(description = "Only track data dependencies (ignore control flow)")]
    #[serde(default)]
    pub data_only: bool,
    #[schemars(description = "Restrict analysis to lines >= this seq")]
    pub start_seq: Option<u32>,
    #[schemars(description = "Restrict analysis to lines <= this seq")]
    pub end_seq: Option<u32>,
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
}

fn default_taint_limit() -> u32 { 50 }
fn default_true() -> bool { true }

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ClearTaintRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
}

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
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetFunctionInfoRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(description = "Call tree node ID to get detailed info for")]
    pub node_id: u32,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetFunctionListRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
}

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
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ScanCryptoPatternsRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
}

// ── 新增工具请求类型 ──

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ExportTaintResultsRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(description = "Output file path to save the results")]
    pub output_path: String,
    #[schemars(description = "Export format: 'json' or 'txt' (default: 'json')")]
    #[serde(default = "default_export_format")]
    pub format: String,
}

fn default_export_format() -> String { "json".to_string() }

#[derive(Debug, Deserialize, JsonSchema)]
pub struct BuildDepTreeFromSliceRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(description = "Only data dependencies (no control flow)")]
    #[serde(default)]
    pub data_only: bool,
    #[schemars(description = "Max nodes in the graph (default: 200)")]
    pub max_nodes: Option<u32>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetLineDefRegistersRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(description = "Line number (0-based) to query defined registers at")]
    pub seq: u32,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetCallTreeNodeCountRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ScanStringsRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
}
