// Zero-Knowledge Vault — Tauri Backend (Rust)
//
// Native Rust backend for desktop-specific operations:
//   - Clipboard management (secure copy/paste with auto-clear)
//   - Keychain integration (OS-level credential storage)
//   - Local encryption helpers (Argon2id, AES-256-GCM)
//   - Auto-lock timer (inactivity-based session lock)

use tauri::Manager;

mod crypto;
mod keychain;
mod lock;

#[tauri::command]
fn greet(name: &str) -> String {
    format!("Hello, {}! ZK Vault is ready.", name)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_store::Builder::default().build())
        .invoke_handler(tauri::generate_handler![greet])
        .setup(|app| {
            #[cfg(debug_assertions)]
            {
                let window = app.get_webview_window("main").unwrap();
                window.open_devtools();
            }
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
