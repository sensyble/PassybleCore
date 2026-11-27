//! The vault list: pointing the single agent at one of the known vaults, and the list's own
//! commands (rename, remove, show in folder). Only the active vault can be unlocked; the browser
//! extension, auto-type and the Windows passkey provider always work against it.

use std::path::Path;
use std::sync::Arc;

use pass_agent::Agent;
use serde_json::{json, Value};
use tauri::{AppHandle, Manager, State};

use crate::i18n::tr;
use crate::settings::{self, Settings};
use crate::state::{lock as guard, AppState, SyncStatus};
use crate::{hello, passkey_provider, setup_guide, tray, undo};

fn not_listed() -> String {
    crate::i18n::tr!("errors.vault_not_listed")
}

fn app_state(app: &AppHandle) -> Arc<AppState> {
    app.state::<Arc<AppState>>().inner().clone()
}

/// Writes `vault` (just downloaded and unlocked) to its cache file at `path`, merging in what a file already there
/// holds (unsynced changes of an earlier session). If it can't be merged (another key, a damaged file), that file is
/// moved beside the vault as `<name>-unsaved-<ms>.vault` instead of overwritten; the agent merges it in at the next
/// unlock when it can. The write itself is the agent's (temp file, flush, rename), so a crash never leaves half a vault.
pub(crate) fn write_vault_file(path: &Path, vault: &pass_core::Vault) -> Result<(), String> {
    if let Ok(old) = std::fs::read(path) {
        if vault.merge_remote(old).is_err() {
            let stem = path
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| "pass".into());
            let aside = path.with_file_name(format!("{stem}-unsaved-{}.vault", now_ms().max(0)));
            std::fs::rename(path, &aside).map_err(crate::errors::file_not_saved)?;
        }
    }
    let bytes = vault.serialize().map_err(crate::commands::pass_err)?;
    pass_agent::store::write_file_atomically(path, &bytes).map_err(crate::errors::file_not_saved)
}

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Makes `id` the active vault and points the agent at it (creating it on first use). Switching away from an
/// unlocked vault saves and locks it first (`Agent::reconfigure`).
pub fn activate(app: &AppHandle, id: &str) -> Result<Arc<Agent>, String> {
    let state = app_state(app);
    let switched = state.update_settings(|s| {
        let switched = s.active_vault.as_deref() != Some(id);
        s.set_active(id)?;
        Ok(switched)
    })?;
    let agent = match state.agent() {
        Some(agent) => {
            // Also picks up a changed WebDAV account when the vault was already active.
            state.reconfigure_agent();
            agent
        }
        None => state.ensure_agent(app),
    };
    if switched {
        after_switch(&state);
    }
    Ok(agent)
}

pub(crate) fn after_switch(state: &AppState) {
    *guard(&state.sync) = SyncStatus::default();
    passkey_provider::vault_switched();
}

pub fn active_id(state: &AppState) -> Result<String, String> {
    state
        .settings()
        .active_vault
        .ok_or_else(|| tr!("errors.no_vault_set_up"))
}

/// Records a successful unlock (the list shows when each vault was last opened) and the vault id
/// of the active vault's file (the pins name vaults by it).
pub fn mark_opened(state: &AppState, id: &str) {
    let vault_id = state
        .agent()
        .and_then(|a| a.peek_vault())
        .map(|v| v.vault_id());
    let _ = state.update_settings(|s| {
        let vault_id = vault_id.filter(|_| s.active_vault.as_deref() == Some(id));
        s.touch(id, now_ms(), vault_id);
        Ok(())
    });
}

pub fn list_json(settings: &Settings) -> Vec<Value> {
    let roots = setup_guide::cloud_roots();
    let now = now_ms();
    settings
        .vaults
        .iter()
        .map(|v| {
            let local_only = setup_guide::is_local_only(v, &roots);
            let hello = if v.windows_hello {
                hello::readiness(&v.id, &v.hello_policy)
            } else {
                hello::Readiness::default()
            };
            json!({
                "id": v.id,
                "vault_id": v.vault_id,
                "name": v.name,
                "path": v.path,
                "location": v.location(),
                "managed": v.path.parent() == Some(settings::local_dir().join("vaults").as_path()),
                "webdav_host": v.webdav.as_ref().map(|w| w.host()),
                "google_email": v.google_account(),
                "last_opened_ms": v.last_opened_ms,
                "exists": v.path.exists(),
                "hello_enabled": v.windows_hello,
                "hello_enrolled": hello.enrolled,
                // Windows Hello can unlock it now (blob present, master password not due).
                "hello_ready": hello.ready,
                "hello_note": hello.note,
                "active": settings.active_vault.as_deref() == Some(v.id.as_str()),
                // No sync and no backup (`is_local_only`), and whether the "only on this device" reminder is due
                // (30 days after "Not now").
                "local_only": local_only,
                "local_reminder": v.local_reminder_due(local_only, now),
                // Linked to a Passyble account (opens with the Passyble password), as last seen here.
                "linked_account": v.linked_account,
                // In the signed-in account on Passyble Cloud, and whether "Delete vault from your account" may
                // delete it (not the home vault).
                "account_vault": crate::account_vaults::account_key(v, settings),
                "account_deletable": crate::account_vaults::deletable_key(v, settings).is_some(),
            })
        })
        .collect()
}

#[tauri::command]
pub fn rename_vault(
    state: State<'_, Arc<AppState>>,
    id: String,
    name: String,
) -> Result<(), String> {
    state.update_settings(|s| s.rename_vault(&id, &name))
}

/// The pinned vaults of the open vault, in pin order (`Vault::pinned_vaults`): `{ pins, max }`.
#[tauri::command]
pub fn vault_pins(state: State<'_, Arc<AppState>>) -> Result<Value, String> {
    let pins = state
        .require_agent()?
        .pinned_vaults()
        .map_err(crate::commands::pass_err)?;
    Ok(json!({ "pins": pins, "max": pass_core::MAX_PINNED_VAULTS }))
}

/// Saves the pins in this order (`Agent::set_pinned_vaults`: ids of vaults the user can't see
/// are dropped) and syncs them like an edit: `{ pins, max }`.
#[tauri::command]
pub fn set_vault_pins(state: State<'_, Arc<AppState>>, ids: Vec<String>) -> Result<Value, String> {
    let pins = state
        .require_agent()?
        .set_pinned_vaults(ids)
        .map_err(crate::commands::pass_err)?;
    Ok(json!({ "pins": pins, "max": pass_core::MAX_PINNED_VAULTS }))
}

/// "Not now" on the "This vault is only on this device" reminder: it stays away from these vaults
/// for 30 days (`settings::LOCAL_REMINDER_SNOOZE_MS`). Ids that aren't listed are skipped.
#[tauri::command]
pub fn local_reminder_dismiss(
    state: State<'_, Arc<AppState>>,
    ids: Vec<String>,
) -> Result<(), String> {
    let now = now_ms();
    state.update_settings(|s| {
        dismiss_local_reminder(s, &ids, now);
        Ok(())
    })
}

fn dismiss_local_reminder(settings: &mut Settings, ids: &[String], now_ms: i64) {
    for id in ids {
        if let Some(v) = settings.vault_mut(id) {
            v.local_reminder_dismissed_ms = Some(now_ms);
        }
    }
}

/// Takes a vault off the list. The file is kept; its WebDAV password on this PC is deleted (a copy stays in memory
/// for Undo) and its Windows Hello blob after the undo window ([`crate::undo`]). Removing the active vault locks it
/// and activates the most recently opened remaining one. `{ "undo_secs": n }`: how long `undo_remove_vault` works.
#[tauri::command]
pub async fn remove_vault(app: AppHandle, id: String) -> Result<Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let state = app_state(&app);
        let was_active = state.settings().active_vault.as_deref() == Some(id.as_str());
        if was_active {
            // Nothing of a vault taken off the list stays on screen.
            tray::lock_completely(&app);
        }
        let index = state
            .settings()
            .vaults
            .iter()
            .position(|v| v.id == id)
            .ok_or_else(not_listed)?;
        let removed = state.update_settings(|s| s.remove_vault(&id).ok_or_else(not_listed))?;
        // Its list kept for the next start goes at once (Undo brings it back at the next unlock).
        settings::remove_kept_list(&removed.id);
        // Its Windows Hello data goes after the undo window, or at the next start if Pass exits first.
        hello::mark_removed(&removed.id);
        let secret = removed
            .webdav
            .as_ref()
            .and_then(|w| settings::webdav_password(&removed.id, w));
        if let Some(webdav) = &removed.webdav {
            settings::delete_webdav_password(&removed.id, webdav, false);
        }
        if was_active {
            state.reconfigure_agent();
            after_switch(&state);
        }
        if let Some(previous) = undo::vault_removed(removed, index, was_active, secret) {
            forget(&app, &previous.entry);
        }
        let expiring = id.clone();
        let expiry_app = app.clone();
        std::thread::spawn(move || {
            std::thread::sleep(undo::VAULT_UNDO_WINDOW);
            if let Some(gone) = undo::expire_vault(&expiring) {
                forget(&expiry_app, &gone.entry);
            }
        });
        Ok(json!({ "undo_secs": undo::VAULT_UNDO_WINDOW.as_secs() }))
    })
    .await
    .map_err(|e| crate::errors::internal("background task", e))?
}

/// After the undo window of a removed vault: its Windows Hello data, and its Google account's
/// sign-in on this PC if no other vault uses it.
fn forget(app: &AppHandle, entry: &settings::VaultEntry) {
    hello::remove(&entry.id);
    crate::gdrive::forget_removed(app, entry);
}

/// Undo of `remove_vault`: puts the vault back where it was in the list, with its WebDAV password
/// and Windows Hello unlock (and makes it active again if it was).
#[tauri::command]
pub async fn undo_remove_vault(app: AppHandle, id: String) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || {
        let state = app_state(&app);
        let removed = undo::take_vault(&id).ok_or_else(|| tr!("errors.too_late_undo_vault"))?;
        let entry = removed.entry.clone();
        state.update_settings(|s| {
            s.restore_vault(entry.clone(), removed.index);
            if removed.was_active || s.active().is_none() {
                s.set_active(&entry.id)?;
            }
            Ok(())
        })?;
        hello::unmark_removed(&entry.id);
        if let (Some(webdav), Some(secret)) = (&entry.webdav, &removed.secret) {
            settings::set_webdav_password(&entry.id, webdav, secret)?;
        }
        if removed.was_active {
            state.reconfigure_agent();
            after_switch(&state);
        }
        Ok(())
    })
    .await
    .map_err(|e| crate::errors::internal("background task", e))?
}

#[tauri::command]
pub fn reveal_vault(state: State<'_, Arc<AppState>>, id: String) -> Result<(), String> {
    let path = state
        .settings()
        .vault(&id)
        .map(|v| v.path.clone())
        .ok_or_else(not_listed)?;
    reveal(&path)
}

#[cfg(windows)]
fn reveal(path: &Path) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    let mut cmd = std::process::Command::new("explorer.exe");
    if path.is_file() {
        // Explorer wants `/select,"C:\a b\c.vault"`, which normal argument quoting doesn't produce.
        cmd.raw_arg(format!("/select,\"{}\"", path.display()));
    } else if let Some(dir) = path.parent().filter(|d| d.is_dir()) {
        cmd.arg(dir);
    } else {
        return Err(tr!("errors.path_missing", path = path.display()));
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| crate::errors::logged(tr!("errors.open_folder_failed"), "explorer", e))?;
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(())
}

#[cfg(target_os = "macos")]
fn reveal(path: &Path) -> Result<(), String> {
    let target = if path.is_file() {
        path
    } else {
        match path.parent().filter(|d| d.is_dir()) {
            Some(dir) => dir,
            None => return Err(tr!("errors.path_missing", path = path.display())),
        }
    };
    pass_macos::finder::reveal(target)
        .map_err(|e| crate::errors::logged(tr!("errors.open_folder_failed"), "Finder", e))
}

/// Linux: the file manager with the vault file selected (FileManager1 `ShowItems`), or its folder
/// if the file is missing (`xdg-open`).
#[cfg(target_os = "linux")]
fn reveal(path: &Path) -> Result<(), String> {
    let target = if path.is_file() {
        path
    } else {
        match path.parent().filter(|d| d.is_dir()) {
            Some(dir) => dir,
            None => return Err(tr!("errors.path_missing", path = path.display())),
        }
    };
    pass_linux::files::reveal(target)
        .map_err(|e| crate::errors::logged(tr!("errors.open_folder_failed"), "file manager", e))
}

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
fn reveal(path: &Path) -> Result<(), String> {
    Err(tr!("errors.reveal_windows_only", path = path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::VaultEntry;

    #[test]
    fn not_now_dismisses_each_listed_vault() {
        let mut s = Settings::default();
        for id in ["a", "b", "c"] {
            s.vaults.push(VaultEntry {
                id: id.into(),
                ..Default::default()
            });
        }
        dismiss_local_reminder(&mut s, &["a".into(), "c".into(), "gone".into()], 42);
        let at: Vec<_> = s
            .vaults
            .iter()
            .map(|v| v.local_reminder_dismissed_ms)
            .collect();
        assert_eq!(at, [Some(42), None, Some(42)]);
        assert!(!s.vaults[0].local_reminder_due(true, 43));
        assert!(s.vaults[1].local_reminder_due(true, 43));
    }
}
