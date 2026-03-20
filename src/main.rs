#![windows_subsystem = "windows"]

mod cache;
mod commands;
mod flat;
mod taint;
mod line_index;
mod phase2;
mod state;

use state::AppState;
use tauri::Manager;

#[tauri::command]
fn toggle_devtools(window: tauri::WebviewWindow) {
    if window.is_devtools_open() {
        window.close_devtools();
    } else {
        window.open_devtools();
    }
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .manage(AppState::new())
        .setup(|app| {
            let _window = app.get_webview_window("main").unwrap();

            // Windows 不支持 titleBarStyle: "Overlay"，需要手动关闭原生装饰
            #[cfg(target_os = "windows")]
            let _ = _window.set_decorations(false);

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            toggle_devtools,
            commands::file::create_session,
            commands::file::close_session,
            commands::file::delete_file_cache,
            commands::browse::get_lines,
            commands::index::build_index,
            commands::registers::get_registers_at,
            commands::call_tree::get_call_tree,
            commands::call_tree::get_call_tree_node_count,
            commands::call_tree::get_call_tree_children,
            commands::search::search_trace,
            commands::memory::get_memory_at,
            commands::memory::get_mem_history,
            commands::def_use::get_reg_def_use_chain,
            commands::slice::run_slice,
            commands::slice::get_slice_status,
            commands::slice::clear_slice,
            commands::slice::get_tainted_seqs,
            commands::slice::export_taint_results,
            commands::cache::get_cache_dir,
            commands::cache::set_cache_dir,
            commands::cache::clear_all_cache,
            commands::strings::get_strings,
            commands::strings::get_string_xrefs,
            commands::strings::scan_strings,
            commands::strings::cancel_scan_strings,
            commands::browse::get_consumed_seqs,
            commands::functions::get_function_calls,
            commands::dep_tree::build_dependency_tree,
            commands::dep_tree::build_dependency_tree_from_slice,
            commands::dep_tree::get_line_def_registers,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
