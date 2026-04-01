export interface CallInfoDto {
  func_name: string;
  is_jni: boolean;
  summary: string;
  tooltip: string;
}

export interface TraceLine {
  seq: number;
  address: string;
  so_offset: string;
  so_name: string | null;
  disasm: string;
  changes: string;
  reg_before: string;
  mem_rw: string | null;
  mem_addr: string | null;
  mem_size: number | null;
  raw: string;
  call_info: CallInfoDto | null;
}

export interface MemorySnapshot {
  base_addr: string;
  bytes: number[];
  known: boolean[];
  length: number;
}

export interface CreateSessionResult {
  sessionId: string;
  totalLines: number;
  fileSize: number;
  traceFormat: string | null;
}

export interface SessionData {
  sessionId: string;
  filePath: string;
  fileName: string;
  totalLines: number;
  fileSize: number;
  traceFormat: string | null;
  isLoaded: boolean;
  isPhase2Ready: boolean;
  indexProgress: number;
}

export interface SearchMatch {
  seq: number;
  address: string;
  so_offset: string;
  so_name: string | null;
  disasm: string;
  changes: string;
  reg_before: string;
  mem_rw: string | null;
  call_info: CallInfoDto | null;
  hidden_content: string | null;
}

export interface SearchResult {
  /** 首页匹配序列号（非全量，通过 fetch_search_page 分页拉取剩余） */
  match_seqs: number[];
  total_scanned: number;
  total_matches: number;
  truncated: boolean;
}

export interface DefUseChain {
  defSeq: number | null;
  useSeqs: number[];
  redefinedSeq: number | null;
}

export interface CallTreeNodeDto {
  id: number;
  func_addr: string;
  func_name: string | null;
  entry_seq: number;
  exit_seq: number;
  parent_id: number | null;
  children_ids: number[];
  line_count: number;
}

export interface SliceResult {
  markedCount: number;
  totalLines: number;
  percentage: number;
}

export interface StringRecordDto {
  idx: number;
  addr: string;
  content: string;
  encoding: string;
  byte_len: number;
  seq: number;
  xref_count: number;
  rw: string;
}

export interface StringsResult {
  strings: StringRecordDto[];
  total: number;
}

export interface StringXRef {
  seq: number;
  rw: string;
  insn_addr: string;
  disasm: string;
}

export interface FunctionCallOccurrence {
  seq: number;
  summary: string;
}

export interface FunctionCallEntry {
  func_name: string;
  is_jni: boolean;
  occurrences: FunctionCallOccurrence[];
}

export interface FunctionCallsResult {
  functions: FunctionCallEntry[];
  total_calls: number;
}

export interface NodeInfo {
  seq: number;
  expression: string;
  asm: string; // 新增
  operation: string;
  isLeaf: boolean;
  value: string | null;
  depth: number;
}

export interface DependencyGraph {
  nodes: NodeInfo[];
  edges: [number, number][]; // [parent_seq, child_seq]
  rootSeq: number;
  totalReachable: number;
  truncated: boolean;
}

export interface CryptoMatch {
  algorithm: string;
  magic_hex: string;
  seq: number;
  address: string;
  disasm: string;
  changes: string;
}

export interface CryptoScanResult {
  matches: CryptoMatch[];
  algorithms_found: string[];
  total_lines_scanned: number;
  scan_duration_ms: number;
}
