use tauri::{AppHandle, Emitter, State};
use crate::cache;
use crate::line_index::LineIndex;
use crate::state::AppState;
use crate::taint;

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
        scan_result.scan_state.compact();

        // 保存缓存（大文件跳过：序列化 6GB+ 数据会导致内存压力过大 + 产生巨大缓存文件）
        const CACHE_SIZE_LIMIT: usize = 2 * 1024 * 1024 * 1024; // 2GB
        if data.len() <= CACHE_SIZE_LIMIT {
            cache::save_cache(&file_path, data, &scan_result.phase2);
            cache::save_scan_cache(&file_path, data, &scan_result.scan_state);
            cache::save_line_index_cache(&file_path, data, &scan_result.line_index);
        }

        Ok::<_, String>(scan_result)
    })
    .await
    .map_err(|e| format!("扫描线程 panic: {}", e))??;

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
