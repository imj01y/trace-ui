use tauri::{AppHandle, Emitter, Manager, State};
use crate::cache;
use crate::line_index::LineIndex;
use crate::state::AppState;
use crate::taint;
use crate::taint::types::TraceFormat;
use crate::taint::mem_access::{MemAccessIndex, MemAccessRecord, MemRw};

#[tauri::command]
pub async fn build_index(
    session_id: String,
    app: AppHandle,
    state: State<'_, AppState>,
    force: Option<bool>,
    skip_strings: Option<bool>,
) -> Result<(), String> {
    let result = build_index_inner(&session_id, &app, &state, force.unwrap_or(false), skip_strings.unwrap_or(false)).await;

    // 无论成功或失败，都发送 done 事件，防止前端永远卡在 loading
    let (error, total_lines, has_string_index) = {
        let sessions = state.sessions.read().map_err(|e| e.to_string())?;
        let s = sessions.get(&*session_id);
        (
            result.as_ref().err().cloned(),
            s.map(|s| s.total_lines).unwrap_or(0),
            s.and_then(|s| s.phase2.as_ref())
                .map(|p| !p.string_index.strings.is_empty())
                .unwrap_or(false),
        )
    };
    let _ = app.emit("index-progress", serde_json::json!({
        "sessionId": session_id,
        "progress": 1.0,
        "done": true,
        "error": error,
        "totalLines": total_lines,
        "hasStringIndex": has_string_index,
    }));

    // Spawn background MemAccessIndex build if parallel scan was used (it skips MemAccessIndex)
    {
        let sessions_read = state.sessions.read().map_err(|e| e.to_string())?;
        let needs_build = sessions_read.get(&*session_id)
            .and_then(|s| s.phase2.as_ref())
            .map(|p| p.mem_accesses.total_addresses() == 0)
            .unwrap_or(false);

        if needs_build {
            let mmap_clone = sessions_read.get(&*session_id).unwrap().mmap.clone();
            let trace_format = sessions_read.get(&*session_id).unwrap().trace_format;
            drop(sessions_read);

            let sid = session_id.clone();
            let app2 = app.clone();

            // Emit initial progress
            let _ = app2.emit("mem-index-progress", serde_json::json!({
                "sessionId": sid,
                "progress": 0.0,
            }));

            tauri::async_runtime::spawn(async move {
                let mmap_for_build = mmap_clone.clone();
                let app_for_progress = app2.clone();
                let sid_for_progress = sid.clone();
                let build_result = tauri::async_runtime::spawn_blocking(move || {
                    build_mem_access_index_from_data(&mmap_for_build, trace_format, Some(&move |frac: f64| {
                        let _ = app_for_progress.emit("mem-index-progress", serde_json::json!({
                            "sessionId": sid_for_progress,
                            "progress": frac,
                        }));
                    }))
                }).await;

                if let Ok(mem_idx) = build_result {
                    // 先存 MemAccessIndex，发送 mem-index-ready
                    let state = app2.state::<AppState>();
                    if let Ok(mut sessions) = state.sessions.write() {
                        if let Some(session) = sessions.get_mut(&*sid) {
                            if let Some(ref mut phase2) = session.phase2 {
                                phase2.mem_accesses = mem_idx;
                            }
                        }
                    }
                    let _ = app2.emit("mem-index-ready", serde_json::json!({
                        "sessionId": sid,
                    }));

                    // 用路径 1 从 MemAccessIndex 精确构建字符串索引（带进度上报）
                    let _ = app2.emit("string-index-progress", serde_json::json!({
                        "sessionId": sid,
                        "progress": 0.0,
                    }));

                    let app_for_str = app2.clone();
                    let sid_for_str = sid.clone();
                    let str_result = tauri::async_runtime::spawn_blocking(move || {
                        use crate::taint::mem_access::MemRw;

                        let state = app_for_str.state::<AppState>();
                        let sessions = state.sessions.read().unwrap();
                        let session = sessions.get(&*sid_for_str).unwrap();
                        let phase2 = session.phase2.as_ref().unwrap();

                        // 1. 收集 Write 记录
                        let mut writes: Vec<(u64, u64, u8, u32)> = Vec::new();
                        for (addr, rec) in phase2.mem_accesses.iter_all() {
                            if rec.rw == MemRw::Write && rec.size <= 8 {
                                writes.push((addr, rec.data, rec.size, rec.seq));
                            }
                        }
                        writes.sort_unstable_by_key(|w| w.3);

                        let _ = app_for_str.emit("string-index-progress", serde_json::json!({
                            "sessionId": sid_for_str,
                            "progress": 0.1,
                        }));

                        // 2. StringBuilder（最慢的部分，占 10%-90%）
                        let total_writes = writes.len();
                        let report_interval = (total_writes / 100).max(1);
                        let mut sb = crate::taint::strings::StringBuilder::new();
                        for (i, &(addr, data, size, seq)) in writes.iter().enumerate() {
                            sb.process_write(addr, data, size, seq);
                            if i % report_interval == 0 {
                                let frac = 0.1 + 0.8 * (i as f64 / total_writes as f64);
                                let _ = app_for_str.emit("string-index-progress", serde_json::json!({
                                    "sessionId": sid_for_str,
                                    "progress": frac,
                                }));
                            }
                        }

                        let _ = app_for_str.emit("string-index-progress", serde_json::json!({
                            "sessionId": sid_for_str,
                            "progress": 0.9,
                        }));

                        // 3. finish + xref counts
                        let mut si = sb.finish();
                        crate::taint::strings::StringBuilder::fill_xref_counts(&mut si, &phase2.mem_accesses);

                        drop(sessions); // 释放读锁
                        si
                    }).await;

                    if let Ok(string_index) = str_result {
                        let state = app2.state::<AppState>();
                        if let Ok(mut sessions) = state.sessions.write() {
                            if let Some(session) = sessions.get_mut(&*sid) {
                                if let Some(ref mut phase2) = session.phase2 {
                                    phase2.string_index = string_index;
                                }
                            }
                        }
                        let _ = app2.emit("string-index-progress", serde_json::json!({
                            "sessionId": sid,
                            "progress": 1.0,
                            "done": true,
                        }));
                    }
                }
            });
        }
    }

    result
}

async fn build_index_inner(
    session_id: &str,
    app: &AppHandle,
    state: &State<'_, AppState>,
    force: bool,
    skip_strings: bool,
) -> Result<(), String> {
    let (mmap_arc, file_path) = {
        let sessions = state.sessions.read().map_err(|e| e.to_string())?;
        let session = sessions.get(session_id)
            .ok_or_else(|| format!("Session {} 不存在", session_id))?;
        (session.mmap.clone(), session.file_path.clone())
    };

    let app_clone = app.clone();
    let session_id_clone = session_id.to_string();
    let progress_fn: taint::ProgressFn = Box::new(move |processed, total| {
        let progress = processed as f64 / total as f64;
        let _ = app_clone.emit("index-progress", serde_json::json!({
            "sessionId": session_id_clone,
            "progress": progress,
            "done": false,
        }));
    });

    let app_for_init = app.clone();
    let sid_for_init = session_id.to_string();

    let result = tauri::async_runtime::spawn_blocking(move || {
        let data: &[u8] = &mmap_arc;

        // 辅助：加载或构建 LineIndex
        let load_or_build_line_index = |fp: &str, d: &[u8]| -> LineIndex {
            if let Some(cached) = cache::load_line_index_cache(fp, d) {
                return cached;
            }
            let li = LineIndex::build(d);
            cache::save_line_index_cache(fp, d, &li);
            li
        };

        // 检测格式（在缓存逻辑之前，确保后续路径都使用正确的格式）
        let detected_format = taint::gumtrace_parser::detect_format(data);

        // 尝试从缓存加载
        // 注意：gumtrace 格式的 call_annotations/consumed_seqs 不在缓存中，
        // 需要强制全量扫描以构建这些数据
        if !force && detected_format == crate::taint::types::TraceFormat::Unidbg {
            if let Some(cached_phase2) = cache::load_cache(&file_path, data) {
                // Phase2 命中，尝试加载 ScanState 缓存
                if let Some(cached_scan) = cache::load_scan_cache(&file_path, data) {
                    // 双缓存命中，加载或构建 LineIndex
                    let line_index = load_or_build_line_index(&file_path, data);
                    return Ok(taint::ScanResult {
                        scan_state: cached_scan,
                        phase2: cached_phase2,
                        line_index,
                        format: detected_format,
                        call_annotations: std::collections::HashMap::new(),
                        consumed_seqs: Vec::new(),
                    });
                }
                // 仅 Phase2 命中，需要重建 ScanState — 发送初始进度
                let _ = app_for_init.emit("index-progress", serde_json::json!({
                    "sessionId": sid_for_init,
                    "progress": 0.0,
                    "done": false,
                }));
                let mut scan_state = taint::scanner::scan_pass1_bytes_with_progress(
                    data, false, 0, None, &Default::default(), false, false,
                    Some(&*progress_fn),
                ).map_err(|e| format!("Scanner 失败: {}", e))?;
                scan_state.compact();
                cache::save_scan_cache(&file_path, data, &scan_state);
                let line_index = load_or_build_line_index(&file_path, data);
                return Ok(taint::ScanResult {
                    scan_state,
                    phase2: cached_phase2,
                    line_index,
                    format: detected_format,
                    call_annotations: std::collections::HashMap::new(),
                    consumed_seqs: Vec::new(),
                });
            }
        }

        // 无缓存: 统一扫描 — 发送初始进度
        let _ = app_for_init.emit("index-progress", serde_json::json!({
            "sessionId": sid_for_init,
            "progress": 0.0,
            "done": false,
        }));
        // Determine number of parallel chunks based on available CPU cores
        let num_cpus = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);
        let mut scan_result = taint::parallel::scan_unified_parallel(
            data, false, false, skip_strings, Some(progress_fn), num_cpus,
        ).map_err(|e| format!("统一扫描失败: {}", e))?;

        // 格式检查：如果没有任何行被成功解析，说明不是有效的 trace 文件
        if scan_result.scan_state.parsed_count == 0 && scan_result.scan_state.line_count > 0 {
            return Err("文件格式不正确：未检测到有效的 ARM64 trace 指令行".to_string());
        }

        // 格式检查：有指令行但没有内存操作注解（仅 unidbg 格式需要检查）
        if scan_result.scan_state.parsed_count > 0
            && scan_result.scan_state.mem_op_count == 0
            && scan_result.format == crate::taint::types::TraceFormat::Unidbg
        {
            return Err(
                "Trace 日志缺少内存访问注解（mem[WRITE]/mem[READ] 和 abs= 字段）。\n\n\
                 trace-ui 需要定制化的 unidbg 日志格式，标准 unidbg 输出不包含这些字段。\n\
                 请参考项目文档中的 unidbg 定制说明，启用内存读写打印后重新生成 trace 日志。"
                    .to_string(),
            );
        }

        // 压缩
        eprintln!("[index] scan complete, compacting...");
        scan_result.scan_state.compact();
        eprintln!("[index] compact done");

        // 保存缓存（大文件跳过：序列化 6GB+ 数据会导致内存压力过大 + 产生巨大缓存文件）
        const CACHE_SIZE_LIMIT: usize = 2 * 1024 * 1024 * 1024; // 2GB
        if data.len() <= CACHE_SIZE_LIMIT {
            eprintln!("[index] saving cache...");
            cache::save_cache(&file_path, data, &scan_result.phase2);
            eprintln!("[index] phase2 cache saved");
            cache::save_scan_cache(&file_path, data, &scan_result.scan_state);
            eprintln!("[index] scan cache saved");
            cache::save_line_index_cache(&file_path, data, &scan_result.line_index);
            eprintln!("[index] line index cache saved");
        } else {
            eprintln!("[index] skipping cache (file size {} > {})", data.len(), CACHE_SIZE_LIMIT);
        }

        eprintln!("[index] returning scan_result from spawn_blocking");
        Ok::<_, String>(scan_result)
    })
    .await
    .map_err(|e| format!("扫描线程 panic: {}", e))??;

    eprintln!("[index] spawn_blocking returned, writing to session...");
    // 写入结果
    {
        let scan_result = result;
        let mut sessions = state.sessions.write().map_err(|e| e.to_string())?;
        if let Some(session) = sessions.get_mut(session_id) {
            session.total_lines = scan_result.line_index.total_lines();
            session.trace_format = scan_result.format;
            session.call_annotations = scan_result.call_annotations;
            session.consumed_seqs = scan_result.consumed_seqs;
            session.scan_state = Some(scan_result.scan_state);
            session.phase2 = Some(scan_result.phase2);
            session.line_index = Some(scan_result.line_index);
        }
    }

    Ok(())
}

/// Build MemAccessIndex by scanning the mmap data for memory operations (parallel).
/// Uses rayon to split the file into chunks, build per-chunk indices, then merge.
fn build_mem_access_index_from_data(
    data: &[u8],
    format: TraceFormat,
    progress_fn: Option<&(dyn Fn(f64) + Send + Sync)>,
) -> MemAccessIndex {
    use memchr::memchr;
    use rayon::prelude::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use crate::taint::{parser, gumtrace_parser};
    use crate::taint::parallel::split_into_chunks;
    use crate::phase2;

    let num_cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    let chunks = split_into_chunks(data, num_cpus);
    let data_len = data.len();
    let global_bytes_done = AtomicUsize::new(0);

    // Phase 1: parallel — each chunk builds its own MemAccessIndex (0%-80%)
    let chunk_indices: Vec<MemAccessIndex> = chunks
        .par_iter()
        .map(|meta| {
            let mut mem_idx = MemAccessIndex::new();
            let mut pos = meta.start_byte;
            let end_byte = meta.end_byte;
            let mut seq = meta.start_line;

            while pos < end_byte {
                let search_end = end_byte.min(data.len());
                let line_end = match memchr(b'\n', &data[pos..search_end]) {
                    Some(p) => pos + p,
                    None => search_end,
                };
                let end = if line_end > pos && data[line_end - 1] == b'\r' {
                    line_end - 1
                } else {
                    line_end
                };

                if let Ok(raw_line) = std::str::from_utf8(&data[pos..end]) {
                    if format == TraceFormat::Gumtrace && gumtrace_parser::is_special_line(raw_line) {
                        seq += 1;
                        pos = if line_end < search_end { line_end + 1 } else { search_end };
                        continue;
                    }

                    let parsed = match format {
                        TraceFormat::Unidbg => parser::parse_line(raw_line),
                        TraceFormat::Gumtrace => gumtrace_parser::parse_line_gumtrace(raw_line),
                    };

                    if let Some(line) = parsed {
                        if let Some(ref mem_op) = line.mem_op {
                            let rw = if mem_op.is_write { MemRw::Write } else { MemRw::Read };
                            let insn_addr = phase2::extract_insn_addr(raw_line);
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
                        }
                    }
                }

                seq += 1;
                pos = if line_end < search_end { line_end + 1 } else { search_end };
            }

            // Report per-chunk progress (Phase 1 = 0%-80%)
            if let Some(ref cb) = progress_fn {
                let done = global_bytes_done.fetch_add(meta.end_byte - meta.start_byte, Ordering::Relaxed)
                    + (meta.end_byte - meta.start_byte);
                cb(done as f64 / data_len as f64 * 0.8);
            }

            mem_idx
        })
        .collect();

    if let Some(ref cb) = progress_fn { cb(0.8); }

    // Phase 2: sequential merge — records in chunk order = correct seq order (80%-100%)
    let total_chunks = chunk_indices.len();
    let mut merged = MemAccessIndex::new();
    for (i, idx) in chunk_indices.into_iter().enumerate() {
        for (addr, record) in idx.iter_all() {
            merged.add(addr, record.clone());
        }
        if let Some(ref cb) = progress_fn {
            cb(0.8 + 0.2 * (i + 1) as f64 / total_chunks as f64);
        }
    }

    if let Some(ref cb) = progress_fn { cb(1.0); }
    merged
}
