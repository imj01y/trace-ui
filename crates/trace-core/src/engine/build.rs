use std::sync::atomic::Ordering;
use std::collections::HashMap;

use crate::cache;
use crate::flat::archives::{CachedStore, Phase2Archive, ScanArchive};
use crate::flat::convert;
use crate::flat::line_index::LineIndexArchive;
use crate::scan_unified::{ScanResult, ProgressFn};
use crate::parallel::scan_unified_parallel;
use crate::api_types::{BuildOptions, BuildResult, ProgressCallback, Progress, Phase};
use crate::error::{TraceError, Result};

/// 内部枚举：区分缓存命中 vs 新鲜扫描结果
enum IndexResult {
    CacheHit {
        phase2_store: CachedStore<Phase2Archive>,
        call_tree: crate::query::call_tree::CallTree,
        string_index: Option<crate::query::strings::StringIndex>,
        scan_store: CachedStore<ScanArchive>,
        reg_last_def: crate::scanner::RegLastDef,
        lidx_store: CachedStore<LineIndexArchive>,
        total_lines: u32,
        format: trace_parser::types::TraceFormat,
        call_annotations: HashMap<u32, trace_parser::gumtrace::CallAnnotation>,
        consumed_seqs: Vec<u32>,
    },
    ScanResult(ScanResult),
}

impl super::TraceEngine {
    pub fn build_index(
        &self,
        session_id: &str,
        options: BuildOptions,
        on_progress: Option<ProgressCallback>,
    ) -> Result<BuildResult> {
        let handle = self.get_handle(session_id)?;

        // 防止重复构建：CAS false -> true
        handle
            .building
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| TraceError::OperationInProgress("build_index".to_string()))?;

        // 重置取消标志
        handle.build_cancel.store(false, Ordering::SeqCst);

        let result = self.build_index_inner(session_id, &handle, options, on_progress);

        // 无论成功或失败，都重置 building 标志
        handle.building.store(false, Ordering::SeqCst);

        result
    }

    fn build_index_inner(
        &self,
        session_id: &str,
        handle: &crate::session::SessionHandle,
        options: BuildOptions,
        on_progress: Option<ProgressCallback>,
    ) -> Result<BuildResult> {
        let (mmap_arc, file_path) = {
            let state = handle.state.read()
                .map_err(|e| TraceError::Internal(e.to_string()))?;
            (state.mmap.clone(), state.file_path.clone())
        };

        let data: &[u8] = &mmap_arc;
        let force = options.force_rebuild;
        let skip_strings = options.skip_strings;

        // 检测格式
        let detected_format = trace_parser::gumtrace::detect_format(data);
        eprintln!(
            "[index] detected_format={:?}, force={}, file_path={}",
            detected_format, force, file_path
        );

        // 尝试从缓存加载（三个核心缓存全部命中时使用）
        if !force {
            if let (Some(p2_mmap), Some(scan_mmap), Some(lidx_mmap)) = (
                cache::load_phase2_cache(&file_path, data),
                cache::load_scan_cache(&file_path, data),
                cache::load_lidx_cache(&file_path, data),
            ) {
                // 通知进度：缓存加载
                if let Some(ref cb) = on_progress {
                    cb(Progress {
                        session_id: session_id.to_string(),
                        phase: Phase::LoadingCache,
                        fraction: 0.5,
                        message: None,
                    });
                }

                let string_index = cache::load_string_cache(&file_path, data);

                let (call_annotations, consumed_seqs) =
                    if detected_format == trace_parser::types::TraceFormat::Gumtrace {
                        cache::load_gumtrace_extra(&file_path, data)
                            .unwrap_or_else(|| (HashMap::new(), Vec::new()))
                    } else {
                        (HashMap::new(), Vec::new())
                    };

                let phase2_store = CachedStore::Mapped(p2_mmap);
                let call_tree = phase2_store.deserialize_call_tree();

                let scan_store = CachedStore::Mapped(scan_mmap);
                let reg_last_def = scan_store.deserialize_reg_last_def();

                let lidx_store = CachedStore::Mapped(lidx_mmap);
                let total_lines = lidx_store.total_lines();

                eprintln!(
                    "[index] section cache hit: total_lines={}, format={:?}",
                    total_lines, detected_format
                );

                let result = IndexResult::CacheHit {
                    phase2_store,
                    call_tree,
                    string_index,
                    scan_store,
                    reg_last_def,
                    lidx_store,
                    total_lines,
                    format: detected_format,
                    call_annotations,
                    consumed_seqs,
                };

                return self.apply_index_result(session_id, handle, result, true);
            }
        }

        // 无缓存：发送初始进度
        if let Some(ref cb) = on_progress {
            cb(Progress {
                session_id: session_id.to_string(),
                phase: Phase::Scanning,
                fraction: 0.0,
                message: None,
            });
        }

        // 构造 ProgressFn（包装 on_progress 回调）
        // ProgressCallback 已是 Box<dyn Fn(Progress) + Send + Sync + 'static>，
        // 将其包在 Arc 里即可跨线程共享、并满足 ProgressFn 的 'static 约束。
        let sid = session_id.to_string();
        let progress_fn: Option<ProgressFn> = on_progress.map(|cb| {
            let cb_arc: std::sync::Arc<dyn Fn(Progress) + Send + Sync> =
                std::sync::Arc::from(cb);
            let progress_box: ProgressFn = Box::new(move |processed: usize, total: usize| {
                let fraction = if total == 0 { 0.0 } else { processed as f64 / total as f64 };
                cb_arc(Progress {
                    session_id: sid.clone(),
                    phase: Phase::Scanning,
                    fraction,
                    message: None,
                });
            });
            progress_box
        });

        let num_cpus = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);

        let mut scan_result = scan_unified_parallel(
            data,
            false,
            false,
            skip_strings,
            progress_fn,
            num_cpus,
        )
        .map_err(|e| TraceError::Internal(format!("统一扫描失败: {}", e)))?;

        // 格式检查：没有有效行
        if scan_result.scan_state.parsed_count == 0 && scan_result.scan_state.line_count > 0 {
            return Err(TraceError::ParseError {
                line: None,
                detail: "文件格式不正确：未检测到有效的 ARM64 trace 指令行".to_string(),
            });
        }

        // 格式检查：unidbg 缺少内存注解
        if scan_result.scan_state.parsed_count > 0
            && scan_result.scan_state.mem_op_count == 0
            && scan_result.format == trace_parser::types::TraceFormat::Unidbg
        {
            return Err(TraceError::ParseError {
                line: None,
                detail: "Trace 日志缺少内存访问注解（mem[WRITE]/mem[READ] 和 abs= 字段）。\n\n\
                         trace-ui 需要定制化的 unidbg 日志格式，标准 unidbg 输出不包含这些字段。\n\
                         请参考项目文档中的 unidbg 定制说明，启用内存读写打印后重新生成 trace 日志。"
                    .to_string(),
            });
        }

        // Compact
        eprintln!("[index] scan complete, compacting...");
        scan_result.scan_state.compact();
        eprintln!("[index] compact done");

        self.apply_index_result(session_id, handle, IndexResult::ScanResult(scan_result), false)
    }

    fn apply_index_result(
        &self,
        _session_id: &str,
        handle: &crate::session::SessionHandle,
        result: IndexResult,
        _from_cache: bool,
    ) -> Result<BuildResult> {
        match result {
            IndexResult::CacheHit {
                phase2_store,
                call_tree,
                string_index,
                scan_store,
                reg_last_def,
                lidx_store,
                total_lines,
                format,
                call_annotations,
                consumed_seqs,
            } => {
                let mut state = handle.state.write()
                    .map_err(|e| TraceError::Internal(e.to_string()))?;
                let has_string_index = string_index.as_ref()
                    .map(|si| !si.strings.is_empty())
                    .unwrap_or(false);

                state.total_lines = total_lines;
                state.trace_format = format;
                state.call_annotations = call_annotations;
                state.consumed_seqs = consumed_seqs;
                state.rebuild_call_search_texts();

                state.call_tree = Some(call_tree);
                state.string_index = string_index;
                state.reg_last_def = Some(reg_last_def);
                state.phase2_store = Some(phase2_store);
                state.scan_store = Some(scan_store);
                state.lidx_store = Some(lidx_store);

                eprintln!("[index] session populated from section cache");

                Ok(BuildResult {
                    total_lines,
                    has_string_index,
                    from_cache: true,
                })
            }

            IndexResult::ScanResult(scan_result) => {
                // 1. 在 write lock 外构建 archives
                let phase2 = scan_result.phase2;
                let call_tree = phase2.call_tree.clone();
                let string_index = phase2.string_index;

                let phase2_archive = Phase2Archive {
                    mem_accesses: convert::mem_access_to_flat(&phase2.mem_accesses),
                    reg_checkpoints: convert::reg_checkpoints_to_flat(&phase2.reg_checkpoints),
                    call_tree: phase2.call_tree,
                };

                // fill_xref_counts：Phase2Archive 构建完成后，使用 flat view 计算 xref
                // 此时使用 flat 数据而非原始 MemAccessIndex，内存更友好
                let mut string_index = string_index;
                if !string_index.strings.is_empty() {
                    let mem_view = phase2_archive.mem_accesses.view();
                    eprintln!("[index] computing xref counts from flat view...");
                    let t_xref = std::time::Instant::now();
                    crate::query::strings::StringBuilder::fill_xref_counts_view(&mut string_index, &mem_view);
                    eprintln!("[index] xref counts done: {:?}", t_xref.elapsed());
                }

                let scan_state = &scan_result.scan_state;
                let scan_archive = ScanArchive {
                    deps: convert::deps_to_flat(&scan_state.deps),
                    mem_last_def: convert::mem_last_def_to_flat(&scan_state.mem_last_def),
                    pair_split: convert::pair_split_to_flat(&scan_state.pair_split),
                    init_mem_loads: convert::bitvec_to_flat(&scan_state.init_mem_loads),
                    reg_last_def_inner: scan_state.reg_last_def.inner().to_vec(),
                    line_count: scan_state.line_count,
                    parsed_count: scan_state.parsed_count,
                    mem_op_count: scan_state.mem_op_count,
                };
                let reg_last_def = scan_state.reg_last_def.clone();

                let lidx_archive = convert::line_index_to_archive(&scan_result.line_index);

                // 2. 序列化为 bytes
                eprintln!("[index] serializing archives to cache bytes...");
                let p2_bytes = phase2_archive.to_sections();
                let scan_bytes = scan_archive.to_sections();
                let lidx_bytes = lidx_archive.to_sections();
                let si_bytes = bincode::serialize(&string_index).ok();
                eprintln!(
                    "[index] serialization done: p2={}B scan={}B lidx={}B",
                    p2_bytes.len(),
                    scan_bytes.len(),
                    lidx_bytes.len()
                );

                // 3. write lock：仅存储数据到 session
                let (fp, mmap_arc, gum_extra, total_lines, has_string_index) = {
                    let mut state = handle.state.write()
                        .map_err(|e| TraceError::Internal(e.to_string()))?;

                    let total_lines = scan_result.line_index.total_lines();
                    let has_string_index = !string_index.strings.is_empty();

                    state.total_lines = total_lines;
                    state.trace_format = scan_result.format;

                    state.call_tree = Some(call_tree);
                    state.string_index = Some(string_index);
                    state.reg_last_def = Some(reg_last_def);
                    state.phase2_store = Some(CachedStore::Owned(phase2_archive));
                    state.scan_store = Some(CachedStore::Owned(scan_archive));
                    state.lidx_store = Some(CachedStore::Owned(lidx_archive));

                    state.call_annotations = scan_result.call_annotations;
                    state.consumed_seqs = scan_result.consumed_seqs;
                    state.rebuild_call_search_texts();

                    let gum_extra = if state.trace_format == trace_parser::types::TraceFormat::Gumtrace
                        && !state.call_annotations.is_empty()
                    {
                        Some((state.call_annotations.clone(), state.consumed_seqs.clone()))
                    } else {
                        None
                    };

                    (
                        state.file_path.clone(),
                        state.mmap.clone(),
                        gum_extra,
                        total_lines,
                        has_string_index,
                    )
                };
                // write lock 已释放

                // 4. 同步写缓存
                eprintln!("[index] writing cache files...");
                let data_for_cache: &[u8] = &mmap_arc;
                cache::save_sections_raw(&fp, data_for_cache, ".p2.cache", &p2_bytes);
                cache::save_sections_raw(&fp, data_for_cache, ".scan.cache", &scan_bytes);
                cache::save_sections_raw(&fp, data_for_cache, ".lidx.cache", &lidx_bytes);
                if let Some(ref si_b) = si_bytes {
                    cache::save_bincode_raw(&fp, data_for_cache, ".strings", si_b);
                }
                if let Some((ref anns, ref seqs)) = gum_extra {
                    cache::save_gumtrace_extra(&fp, data_for_cache, anns, seqs);
                }
                eprintln!("[index] cache save complete");

                Ok(BuildResult {
                    total_lines,
                    has_string_index,
                    from_cache: false,
                })
            }
        }
    }

    pub fn cancel_build(&self, session_id: &str) {
        if let Ok(handle) = self.get_handle(session_id) {
            handle.build_cancel.store(true, Ordering::SeqCst);
        }
        // 静默忽略 session 不存在的情况
    }
}
