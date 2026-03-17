use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use serde::Serialize;
use tauri::{AppHandle, State};
use crate::state::{AppState, SessionState};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateSessionResult {
    pub session_id: String,
    pub total_lines: u32,
    pub file_size: u64,
}

#[tauri::command]
pub async fn create_session(
    path: String,
    _app: AppHandle,
    state: State<'_, AppState>,
) -> Result<CreateSessionResult, String> {
    let path_clone = path.clone();

    let (mmap, file_size) = tauri::async_runtime::spawn_blocking(move || {
        let file = std::fs::File::open(&path_clone).map_err(|e| format!("无法打开文件: {}", e))?;
        let metadata = file.metadata().map_err(|e| format!("无法读取文件信息: {}", e))?;
        let file_size = metadata.len();
        let mmap = unsafe { memmap2::Mmap::map(&file) }.map_err(|e| format!("mmap 失败: {}", e))?;
        Ok::<_, String>((mmap, file_size))
    })
    .await
    .map_err(|e| format!("线程 panic: {}", e))??;

    // 估算行数（平均 ~110 字节/行），build_index 完成后会更新为精确值
    let total_lines_estimate = (file_size / 110).max(1) as u32;
    let session_id = uuid::Uuid::new_v4().to_string();

    {
        let mut sessions = state.sessions.write().map_err(|e| format!("锁获取失败: {}", e))?;
        sessions.insert(session_id.clone(), SessionState {
            mmap: Arc::new(mmap),
            line_index: None,
            file_path: path,
            total_lines: total_lines_estimate,
            file_size,
            phase2: None,
            scan_state: None,
            slice_result: None,
            scan_strings_cancelled: Arc::new(AtomicBool::new(false)),
        });
    }

    Ok(CreateSessionResult { session_id, total_lines: total_lines_estimate, file_size })
}

#[tauri::command]
pub fn close_session(session_id: String, state: State<'_, AppState>) -> Result<(), String> {
    let removed = {
        let mut sessions = state.sessions.write().map_err(|e| format!("锁获取失败: {}", e))?;
        sessions.remove(&session_id)
    };
    // 大数据结构的 Drop 在后台线程执行，避免阻塞主线程
    if let Some(session) = removed {
        std::thread::spawn(move || drop(session));
    }
    Ok(())
}

#[tauri::command]
pub fn delete_file_cache(path: String) -> Result<(), String> {
    crate::cache::delete_cache(&path);
    Ok(())
}
