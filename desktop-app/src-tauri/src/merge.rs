//! Merging two items (the vault list's Merge, "Merge with…" and the authenticator suggestions): the merge sheet asks
//! `merge_preview` for the two items, how their fields compare and the merged result after every pick, then
//! `merge_pair` merges them (the primary item keeps its id, the other is deleted). The toast's Undo (`undo_merge`)
//! puts both back within a minute (`undo.rs`). Every command needs the unlocked vault ([`VAULT_LOCKED`] otherwise: the
//! window unlocks and tries again). Passkey private keys never reach the window (`ItemDto`).
//!
//! [`VAULT_LOCKED`]: crate::state::VAULT_LOCKED

use std::sync::Arc;

use pass_core::MergePicks;
use serde_json::{json, Value};
use tauri::{AppHandle, Emitter, State};

use crate::commands::{pass_err, ItemDto};
use crate::i18n::tr;
use crate::state::AppState;
use crate::vaults;

type Res<T> = Result<T, String>;

/// The two items, how each field compares (`plan`), the picks in effect (the user's and the
/// defaults) and the merged item, as the merge sheet shows them.
#[tauri::command]
pub fn merge_preview(
    state: State<'_, Arc<AppState>>,
    a: String,
    b: String,
    picks: Option<MergePicks>,
) -> Res<Value> {
    let vault = state.vault()?;
    let a = vault.get(a).ok_or_else(|| tr!("errors.item_not_found"))?;
    let b = vault.get(b).ok_or_else(|| tr!("errors.item_not_found"))?;
    let preview = pass_core::merge_preview(a.clone(), b.clone(), picks.unwrap_or_default())
        .map_err(pass_err)?;
    Ok(json!({
        "plan": preview.plan,
        "picks": preview.picks,
        "history_added": preview.history_added,
        "totp_noted": preview.totp_noted,
        "a": ItemDto::from(a),
        "b": ItemDto::from(b),
        "result": ItemDto::from(preview.item),
    }))
}

/// Merges items `a` and `b` as `picks` says, saves, and keeps the undo for a minute.
/// `{ item, removed_id, undo_secs }`.
#[tauri::command]
pub fn merge_pair(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
    a: String,
    b: String,
    picks: Option<MergePicks>,
) -> Res<Value> {
    let vault = state.vault()?;
    let out = pass_core::merge_pair(vault, a, b, picks.unwrap_or_default()).map_err(pass_err)?;
    state.require_agent()?.save().map_err(pass_err)?;
    crate::undo::item_merged(&vaults::active_id(&state)?, out.undo.clone());
    let _ = app.emit("vault-changed", ());
    Ok(json!({
        "item": ItemDto::from(out.item),
        "removed_id": out.removed_id,
        "undo_secs": crate::undo::ITEM_UNDO_WINDOW.as_secs(),
    }))
}

#[tauri::command]
pub fn undo_merge(app: AppHandle, state: State<'_, Arc<AppState>>, id: String) -> Res<ItemDto> {
    let vault = state.vault()?;
    let undo = crate::undo::take_merge(&vaults::active_id(&state)?, &id)
        .ok_or_else(|| tr!("errors.too_late_undo"))?;
    let restored = undo.restore(vault).map_err(pass_err)?;
    state.require_agent()?.save().map_err(pass_err)?;
    let _ = app.emit("vault-changed", ());
    Ok(restored.into())
}

/// Authenticator entries (2FA only) that look like they belong to a login. No secrets.
#[tauri::command]
pub fn merge_suggestions(state: State<'_, Arc<AppState>>) -> Res<Value> {
    let vault = state.vault()?;
    Ok(json!({ "suggestions": pass_core::merge_suggestions(vault) }))
}

/// The items "Merge with…" offers for item `id`, likeliest first (`{ id, score }`; score 0: no sign
/// they are the same account).
#[tauri::command]
pub fn merge_candidates(state: State<'_, Arc<AppState>>, id: String) -> Res<Value> {
    let vault = state.vault()?;
    Ok(json!({ "candidates": pass_core::merge_candidates(vault, id) }))
}
