//! Quick Access (global shortcut, `Ctrl+Shift+Space` by default; shortcuts.rs): a small search window over every
//! unlocked vault. It searches with the `search` command and copies with `copy_field`, so the secrets never pass
//! through its webview and a copy is cleared after 45 s like any other (clipboard.rs). Like every Passyble window it
//! is kept out of screenshots and screen sharing (popups.rs).
//!
//! Locked (also soft-locked), it asks to unlock first, the way auto-type does: Windows Hello when it is on, else the
//! master password in the main window. It closes when it loses the focus.

use std::sync::Arc;
use std::thread;

use serde_json::json;
use tauri::{AppHandle, Emitter, Manager};

use crate::popups;
use crate::state::AppState;

pub fn open(app: &AppHandle) {
    let app = app.clone();
    let _ = thread::Builder::new()
        .name("pass-quick-access".into())
        .spawn(move || {
            let state = app.state::<Arc<AppState>>().inner().clone();
            let Some(agent) = state.agent() else {
                // No vault yet: the main window has the onboarding.
                popups::show_main(&app);
                return;
            };
            if agent.is_locked() && !pass_agent::Ui::request_unlock(state.ui.as_ref()) {
                return;
            }
            crate::webview_memory::wake(&app, "quickaccess");
            let _ = app.emit_to("quickaccess", "quickaccess", ());
            popups::show_quick_access(&app);
        });
}

#[tauri::command]
pub fn quick_access_open(app: AppHandle, id: String) {
    popups::hide(&app, "quickaccess");
    let _ = app.emit_to("main", "show-item", json!({ "id": id }));
    popups::open_main(&app);
}
