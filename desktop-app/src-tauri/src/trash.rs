//! The trash (vault view → ⋯ → Trash, Settings → This vault → Trash). Deleting an item moves it here (`Vault::delete`);
//! it stays for 30 days (`pass_core::TRASH_RETENTION_MS`, purged by the core when the vault is saved or unlocked) and
//! syncs like any edit. The view lists the trashed items without secrets, restores them, deletes them for good, or
//! empties the trash (after a confirmation in the window: that can't be undone). Everything here needs the vault
//! unlocked; the list a soft lock keeps has no trash.

use serde_json::{json, Value};
use tauri::{Emitter, State};

use crate::commands::{pass_err, ItemSummary};
use crate::state::AppState;

type Res<T> = Result<T, String>;
type AppState_<'a> = State<'a, std::sync::Arc<AppState>>;

/// The items in the trash, most recently trashed first, with `trashed_at` and the time they are
/// purged (`purge_at`, Unix ms).
#[tauri::command]
pub fn trash_list(state: AppState_<'_>) -> Res<Value> {
    let vault = state.vault()?;
    let items: Vec<ItemSummary> = vault
        .trash_summaries()
        .iter()
        .map(ItemSummary::trashed)
        .collect();
    Ok(json!({
        "items": items,
        "retention_ms": pass_core::TRASH_RETENTION_MS,
    }))
}

#[tauri::command]
pub fn trash_restore(app: tauri::AppHandle, state: AppState_<'_>, ids: Vec<String>) -> Res<Value> {
    let vault = state.vault()?;
    let mut restored = 0;
    for id in ids {
        match vault.restore(id) {
            Ok(_) => restored += 1,
            Err(pass_core::PassError::NotFound(_)) => {}
            Err(e) => return Err(pass_err(e)),
        }
    }
    if restored > 0 {
        state.require_agent()?.save().map_err(pass_err)?;
        let _ = app.emit("vault-changed", ());
    }
    Ok(json!({ "restored": restored }))
}

/// Deletes items in the trash for good (one save; a deletion that syncs). Returns how many.
#[tauri::command]
pub fn trash_delete(state: AppState_<'_>, ids: Vec<String>) -> Res<Value> {
    let vault = state.vault()?;
    let mut deleted = 0;
    for id in ids {
        match vault.purge(id) {
            Ok(()) => deleted += 1,
            Err(pass_core::PassError::NotFound(_)) => {}
            Err(e) => return Err(pass_err(e)),
        }
    }
    if deleted > 0 {
        state.require_agent()?.save().map_err(pass_err)?;
    }
    Ok(json!({ "deleted": deleted }))
}

#[tauri::command]
pub fn trash_empty(state: AppState_<'_>) -> Res<Value> {
    let vault = state.vault()?;
    let deleted = vault.empty_trash();
    if deleted > 0 {
        state.require_agent()?.save().map_err(pass_err)?;
    }
    Ok(json!({ "deleted": deleted }))
}
