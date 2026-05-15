// SCP Desktop — Tauri 2.x entry point.
// Phase 3: reference client shell around the Rust core.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    tauri::Builder::default()
        // TODO Phase 3: register Tauri commands for identity / vitality / transport
        .run(tauri::generate_context!())
        .expect("SCP desktop failed to start");
}
