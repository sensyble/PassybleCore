//! Import from other password managers and authenticator apps (Settings → Import…).
//!
//! The export is parsed here; parsed items (with secrets) stay on the Rust side until `import_commit`. The webview
//! only gets the preview. The pending import targets the vault unlocked when it was previewed and is dropped when
//! the vault locks.
//!
//! Entries that clash with a vault item (or each other) come as groups; the window sends a decision per group
//! (merge / keep both / skip) with `import_commit`. `find_duplicates` / `merge_duplicates` do the same for
//! duplicates already in the vault.
//!
//! A password-protected export is recognised (`pass_core::import_encryption`): the preview answers
//! `{ needs_password: true, kind, key_file }`, the file stays here, and the window asks for the password
//! (`import_with_password`). A KeePass database can also use a key file (`import_key_file`; its bytes stay here
//! too). A wrong password can be retried. Neither the password nor the decrypted file is kept or logged.

use std::sync::{Arc, Mutex, MutexGuard};

use pass_core::{
    ImportBatch, ImportDecision, ImportGroupDecision, ImportPreview, MAX_IMPORT_BYTES,
};
use serde::Deserialize;
use serde_json::{json, Value};
use tauri::{AppHandle, Emitter, Manager};
use tauri_plugin_dialog::DialogExt;

use crate::i18n::tr;
use crate::state::AppState;

type Res<T> = Result<T, String>;

/// Most preview rows sent to the webview; the counts always cover everything.
const MAX_PREVIEW_ROWS: usize = 2000;

struct Pending {
    batch: ImportBatch,
    vault_id: String,
}

static PENDING: Mutex<Option<Pending>> = Mutex::new(None);

static ENCRYPTED: Mutex<Option<(Vec<u8>, String)>> = Mutex::new(None);

fn encrypted() -> MutexGuard<'static, Option<(Vec<u8>, String)>> {
    ENCRYPTED.lock().unwrap_or_else(|p| p.into_inner())
}

static KEY_FILE: Mutex<Option<zeroize::Zeroizing<Vec<u8>>>> = Mutex::new(None);

fn key_file() -> MutexGuard<'static, Option<zeroize::Zeroizing<Vec<u8>>>> {
    KEY_FILE.lock().unwrap_or_else(|p| p.into_inner())
}

/// Largest key file read (KeePass key files are a few hundred bytes; any file can be one).
const MAX_KEY_FILE_BYTES: u64 = 10 * 1024 * 1024;

/// The file last dropped on the main window, until `import_dropped` asks for it, so the webview never names a path.
static DROPPED: Mutex<Option<std::path::PathBuf>> = Mutex::new(None);

pub fn dropped(app: &AppHandle, paths: &[std::path::PathBuf]) {
    let Some(path) = paths.iter().find(|p| p.is_file()) else {
        return;
    };
    *DROPPED.lock().unwrap_or_else(|p| p.into_inner()) = Some(path.clone());
    let _ = app.emit_to("main", "import-dropped", ());
}

/// Google Authenticator export links read from the screen (screen_qr.rs) until the main window asks for their
/// preview. They hold secrets: memory only, wiped when they go.
static SCANNED: Mutex<Option<zeroize::Zeroizing<String>>> = Mutex::new(None);

fn scanned_text() -> MutexGuard<'static, Option<zeroize::Zeroizing<String>>> {
    SCANNED.lock().unwrap_or_else(|p| p.into_inner())
}

pub fn scanned(app: &AppHandle, links: zeroize::Zeroizing<String>) {
    *scanned_text() = Some(links);
    let _ = app.emit_to("main", "import-dropped", ());
}

fn pending() -> MutexGuard<'static, Option<Pending>> {
    PENDING.lock().unwrap_or_else(|p| p.into_inner())
}

pub fn clear() {
    *pending() = None;
    *encrypted() = None;
    *key_file() = None;
}

pub fn clear_all() {
    clear();
    *scanned_text() = None;
}

fn app_state(app: &AppHandle) -> Arc<AppState> {
    app.state::<Arc<AppState>>().inner().clone()
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Res<T> + Send + 'static) -> Res<T> {
    tauri::async_runtime::spawn_blocking(f)
        .await
        .map_err(|e| crate::errors::internal("background task", e))?
}

fn preview_json(source: &str, mut preview: ImportPreview) -> Value {
    let total = preview.entries.len();
    preview.entries.truncate(MAX_PREVIEW_ROWS);
    let groups = preview.groups.len();
    preview.groups.truncate(MAX_PREVIEW_ROWS);
    json!({
        "source": source,
        "preview": preview,
        "hidden_rows": total.saturating_sub(MAX_PREVIEW_ROWS),
        "hidden_groups": groups.saturating_sub(MAX_PREVIEW_ROWS),
    })
}

fn stage(app: &AppHandle, data: &[u8], source: &str) -> Res<Value> {
    app_state(app).vault()?;
    clear();
    if let Some(enc) = pass_core::import_encryption(data.to_vec(), source.to_string()) {
        *encrypted() = Some((data.to_vec(), source.to_string()));
        return Ok(json!({
            "needs_password": true,
            "source": source,
            // "Passyble (JSON)", "Bitwarden (JSON)", "KeePass (KDBX)", "Aegis", "ZIP", …
            "kind": enc.source,
            "passyble": enc.format == Some(pass_core::ImportFormat::PassybleJson),
            "key_file": enc.key_file,
        }));
    }
    let report = pass_core::parse_import(data, source, None).map_err(parse_error)?;
    stage_batch(app, ImportBatch::new(report), source)
}

fn parse_error(e: pass_core::PassError) -> String {
    match e {
        pass_core::PassError::InvalidInput(m) => capitalize(&m),
        other => other.to_string(),
    }
}

fn stage_batch(app: &AppHandle, batch: ImportBatch, source: &str) -> Res<Value> {
    let vault = app_state(app).vault()?;
    let preview = batch.preview(vault.clone());
    *pending() = Some(Pending {
        batch,
        vault_id: vault.vault_id(),
    });
    Ok(preview_json(source, preview))
}

fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

#[tauri::command]
pub async fn import_file(app: AppHandle) -> Res<Option<Value>> {
    blocking(move || {
        app_state(&app).vault()?;
        let mut dialog = app
            .dialog()
            .file()
            .set_title(tr!("dialog.import_title"))
            .add_filter(
                tr!("dialog.exports_filter"),
                &[
                    "csv", "json", "zip", "1pux", "2fas", "kdbx", "kdb", "pgp", "asc", "txt",
                    "png", "jpg", "jpeg",
                ],
            )
            .add_filter(tr!("dialog.all_files"), &["*"]);
        if let Some(main) = app.get_webview_window("main") {
            dialog = dialog.set_parent(&main);
        }
        let Some(path) = dialog.blocking_pick_file().and_then(|p| p.into_path().ok()) else {
            return Ok(None);
        };
        stage_file(&app, &path).map(Some)
    })
    .await
}

fn stage_file(app: &AppHandle, path: &std::path::Path) -> Res<Value> {
    let size = std::fs::metadata(path)
        .map_err(crate::errors::file_not_read)?
        .len();
    if size > MAX_IMPORT_BYTES as u64 {
        return Err(tr!(
            "errors.import_too_large",
            size = MAX_IMPORT_BYTES / (1024 * 1024)
        ));
    }
    let data = std::fs::read(path).map_err(crate::errors::file_not_read)?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    stage(app, &data, &name)
}

/// Opens the password-protected export (with the picked key file, if any) and previews it. A wrong password keeps
/// the file for another try.
#[tauri::command]
pub async fn import_with_password(app: AppHandle, password: String) -> Res<Value> {
    blocking(move || {
        let password = zeroize::Zeroizing::new(password);
        app_state(&app).vault()?;
        let (data, source) = encrypted()
            .clone()
            .ok_or_else(|| tr!("errors.nothing_to_import"))?;
        let key = key_file().as_ref().map(|k| k.to_vec());
        if password.is_empty() && key.is_none() {
            return Err(tr!("errors.enter_export_password"));
        }
        let with_key = key.is_some();
        let batch =
            pass_core::import_parse_with_key_file(data, source.clone(), password.to_string(), key)
                .map_err(|e| match e {
                    pass_core::PassError::InvalidPassword if with_key => {
                        tr!("errors.wrong_export_password_or_key_file")
                    }
                    pass_core::PassError::InvalidPassword => tr!("errors.wrong_export_password"),
                    other => parse_error(other),
                })?;
        *encrypted() = None;
        *key_file() = None;
        stage_batch(&app, ImportBatch::new(batch.report().clone()), &source)
    })
    .await
}

/// Picks a key file for the KeePass database waiting for its password. The file's bytes stay here.
#[tauri::command]
pub async fn import_key_file(app: AppHandle) -> Res<Option<String>> {
    blocking(move || {
        app_state(&app).vault()?;
        if encrypted().is_none() {
            return Err(tr!("errors.nothing_to_import"));
        }
        let mut dialog = app
            .dialog()
            .file()
            .set_title(tr!("dialog.key_file_title"))
            .add_filter(tr!("dialog.key_files_filter"), &["keyx", "key"])
            .add_filter(tr!("dialog.all_files"), &["*"]);
        if let Some(main) = app.get_webview_window("main") {
            dialog = dialog.set_parent(&main);
        }
        let Some(path) = dialog.blocking_pick_file().and_then(|p| p.into_path().ok()) else {
            return Ok(None);
        };
        let size = std::fs::metadata(&path)
            .map_err(crate::errors::file_not_read)?
            .len();
        if size > MAX_KEY_FILE_BYTES {
            return Err(tr!("errors.key_file_too_large"));
        }
        let data = std::fs::read(&path).map_err(crate::errors::file_not_read)?;
        *key_file() = Some(zeroize::Zeroizing::new(data));
        Ok(Some(
            path.file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
        ))
    })
    .await
}

#[tauri::command]
pub fn import_key_file_clear() {
    *key_file() = None;
}

#[tauri::command]
pub async fn import_dropped(app: AppHandle) -> Res<Option<Value>> {
    blocking(move || {
        // An export scanned from the screen first (it is what the user just chose to import).
        let scanned = scanned_text().take();
        if let Some(links) = scanned {
            app_state(&app).vault()?;
            return stage(&app, links.as_bytes(), "").map(Some);
        }
        let Some(path) = DROPPED.lock().unwrap_or_else(|p| p.into_inner()).take() else {
            return Ok(None);
        };
        app_state(&app).vault()?;
        stage_file(&app, &path).map(Some)
    })
    .await
}

#[tauri::command]
pub async fn import_text(app: AppHandle, text: String) -> Res<Value> {
    blocking(move || {
        if text.trim().is_empty() {
            return Err(tr!("errors.paste_links_first"));
        }
        stage(&app, text.as_bytes(), "")
    })
    .await
}

/// Adds the previewed import to the vault, saves and syncs. `decisions`: per clash group (`{ group_id, decision: {
/// type: "merge" | "keep_both" | "skip", password_from?, … } }`); groups without one get their default, or Keep
/// both when `rest_keep_both`.
#[tauri::command]
pub async fn import_commit(
    app: AppHandle,
    decisions: Option<Vec<ImportGroupDecision>>,
    rest_keep_both: Option<bool>,
) -> Res<Value> {
    blocking(move || {
        let state = app_state(&app);
        let vault = state.vault()?;
        let Some(p) = pending().take() else {
            return Err(tr!("errors.nothing_to_import"));
        };
        if p.vault_id != vault.vault_id() {
            return Err(tr!("errors.different_vault_open"));
        }
        let mut decisions = decisions.unwrap_or_default();
        if rest_keep_both == Some(true) {
            let listed: std::collections::HashSet<String> =
                decisions.iter().map(|d| d.group_id.clone()).collect();
            let rest: Vec<ImportGroupDecision> = p
                .batch
                .preview(vault.clone())
                .groups
                .into_iter()
                .filter(|g| !listed.contains(&g.id))
                .map(|g| ImportGroupDecision {
                    group_id: g.id,
                    decision: ImportDecision::KeepBoth,
                })
                .collect();
            decisions.extend(rest);
        }
        let result = p
            .batch
            .commit_with(vault, decisions)
            .map_err(crate::errors::friendly)?;
        state
            .require_agent()?
            .save()
            .map_err(crate::errors::friendly)?;
        state.kick_sync();
        let _ = app.emit("vault-changed", ());
        Ok(json!(result))
    })
    .await
}

#[tauri::command]
pub fn import_cancel() {
    clear();
}

#[tauri::command]
pub async fn find_duplicates(app: AppHandle) -> Res<Value> {
    blocking(move || {
        let vault = app_state(&app).vault()?;
        Ok(json!({ "groups": pass_core::find_duplicates(vault) }))
    })
    .await
}

#[derive(Deserialize)]
pub struct DuplicateMerge {
    /// The group's `item_ids`; the first one is kept.
    ids: Vec<String>,
    decision: ImportDecision,
}

/// Merges groups of duplicates (each into its first item; the others are deleted), saves and syncs.
#[tauri::command]
pub async fn merge_duplicates(app: AppHandle, merges: Vec<DuplicateMerge>) -> Res<Value> {
    blocking(move || {
        let state = app_state(&app);
        let vault = state.vault()?;
        let (mut merged, mut removed) = (0u32, 0usize);
        let mut failed = None;
        for m in merges {
            let count = m.ids.len();
            match pass_core::merge_items(vault.clone(), m.ids, m.decision) {
                Ok(Some(_)) => {
                    merged += 1;
                    removed += count.saturating_sub(1);
                }
                Ok(None) => {}
                Err(e) => failed = Some(crate::errors::friendly(e)),
            }
        }
        if merged > 0 {
            state
                .require_agent()?
                .save()
                .map_err(crate::errors::friendly)?;
            state.kick_sync();
            let _ = app.emit("vault-changed", ());
        }
        if let (0, Some(e)) = (merged, failed) {
            return Err(e);
        }
        Ok(json!({ "merged": merged, "removed": removed }))
    })
    .await
}
