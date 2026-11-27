//! Google Drive backup on Windows (docs/GOOGLE_DRIVE.md), with the same choices as Android: back up
//! at vault creation, restore from Drive, and the Settings → Sync actions.
//!
//! Sign-in is `google_oauth.rs`. A finished sign-in is pending in memory until a vault uses the
//! account; then its refresh token goes to Credential Manager. Every Drive call gets a current access
//! token, refreshed once when Drive refuses it. When Google refuses the refresh token too, the
//! account's vaults are marked "Sign in to Google again" and background sync skips them.
//!
//! Google only ever gets the encrypted vault file (plus its random id and display name).

use serde_json::{json, Value};
use tauri::AppHandle;

use crate::settings::{Settings, VaultEntry};

type Res<T> = Result<T, String>;

pub fn sign_in_again() -> String {
    crate::i18n::tr!("errors.google_sign_in_again")
}

pub fn available(settings: &Settings) -> bool {
    #[cfg(feature = "gdrive")]
    {
        crate::google_oauth::Client::configured(settings).is_some()
    }
    #[cfg(not(feature = "gdrive"))]
    {
        let _ = settings;
        false
    }
}

/// The active vault's backup for `status` and `get_settings`: `{email, sign_in_needed}`.
pub fn active_json(settings: &Settings) -> Value {
    settings
        .active()
        .and_then(|v| v.google_drive.as_ref())
        .map_or(
            Value::Null,
            |g| json!({ "email": g.account_email, "sign_in_needed": g.sign_in_needed }),
        )
}

/// "Sign in to Google again" is pending for the active vault. Never in a build without Google
/// sign-in ([`available`]), where signing in can't help.
pub fn sign_in_needed(settings: &Settings) -> bool {
    available(settings)
        && settings
            .active()
            .and_then(|v| v.google_drive.as_ref())
            .is_some_and(|g| g.sign_in_needed)
}

/// Opens Google's consent page and waits (up to 5 minutes). `email`: sign in to that account again.
/// `null` when cancelled, else `{email}` (kept in memory until a vault uses it).
#[tauri::command]
pub async fn google_sign_in(app: AppHandle, email: Option<String>) -> Res<Option<Value>> {
    crate::commands::blocking(move || imp::sign_in(&app, email)).await
}

#[tauri::command]
pub fn google_sign_in_cancel() {
    imp::cancel();
}

#[tauri::command]
pub async fn google_drive_vaults(app: AppHandle, email: String) -> Res<Vec<Value>> {
    crate::commands::blocking(move || imp::list(&app, &email)).await
}

#[tauri::command]
pub async fn setup_google_drive_restore(
    app: AppHandle,
    email: String,
    file_id: String,
    password: String,
    name: Option<String>,
) -> Res<Value> {
    crate::commands::blocking(move || imp::restore(&app, &email, &file_id, &password, name)).await
}

/// "Back up to Google Drive…" for the unlocked active vault: syncs first (uploads, or merges a copy
/// already there), then saves the account for the vault.
#[tauri::command]
pub async fn google_drive_enable(app: AppHandle, email: String) -> Res<Value> {
    crate::commands::blocking(move || imp::enable(&app, &email)).await
}

#[tauri::command]
pub async fn google_drive_disable(app: AppHandle, delete_copy: bool) -> Res<Value> {
    crate::commands::blocking(move || imp::disable(&app, delete_copy)).await
}

/// "Delete old versions" for the unlocked active vault: `{removed, kept, unfinished}`.
#[tauri::command]
pub async fn google_drive_delete_old_versions(app: AppHandle) -> Res<Value> {
    crate::commands::blocking(move || imp::delete_old_versions(&app)).await
}

/// "Remove vault from Google Drive": deletes the vault's copy from the app's Drive folder and turns
/// the backup off here. `confirm_name` is checked by [`name_confirmed`].
#[tauri::command]
pub async fn google_drive_remove(app: AppHandle, confirm_name: String) -> Res<Value> {
    crate::commands::blocking(move || imp::remove(&app, &confirm_name)).await
}

/// Whether `typed` is the vault's name: spaces and letter case don't matter, an empty name never matches.
#[cfg_attr(not(feature = "gdrive"), allow(dead_code))]
pub fn name_confirmed(typed: &str, name: &str) -> bool {
    let (typed, name) = (typed.trim(), name.trim());
    !name.is_empty() && typed.to_lowercase() == name.to_lowercase()
}

/// A vault just created with the backup on: upload it. A failed upload is a warning (background sync retries).
pub fn after_create(app: &AppHandle, email: &str) -> Option<String> {
    imp::after_create(app, email)
}

/// The Drive vaults of `email` that open with `password` after it was changed on another device;
/// returns the one this PC's copy `local` merges into.
pub fn open_with_password(
    app: &AppHandle,
    email: &str,
    password: &str,
    local: Option<&[u8]>,
) -> Option<std::sync::Arc<pass_core::Vault>> {
    imp::open_with_password(app, email, password, local)
}

/// A vault left the list for good: forget its Google sign-in on this PC if no other vault uses it.
pub fn forget_removed(app: &AppHandle, entry: &VaultEntry) {
    if let Some(email) = entry.google_account() {
        imp::release_if_unused(app, email, false);
    }
}

/// Set when the last background sync was refused for the rate (403 `rateLimitExceeded`, 429).
#[cfg_attr(not(feature = "gdrive"), allow(dead_code))]
static RATE_LIMITED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Whether the last [`sync`] was rate-limited (clears it), for the scheduler's backoff.
#[cfg_attr(not(feature = "gdrive"), allow(dead_code))]
pub fn take_rate_limited() -> bool {
    RATE_LIMITED.swap(false, std::sync::atomic::Ordering::Relaxed)
}

/// Background sync of the active vault. `Ok(None)` when it isn't backed up to Drive or is locked.
#[cfg(feature = "gdrive")]
pub fn sync(
    app: &AppHandle,
    agent: &pass_agent::Agent,
) -> Result<Option<pass_core::SyncResult>, String> {
    imp::sync(app, agent)
}

#[cfg(feature = "gdrive")]
mod imp {
    use crate::i18n::tr;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    use pass_core::{GDriveConfig, PassError, Vault};
    use serde_json::{json, Value};
    use tauri::{AppHandle, Emitter};

    use super::Res;
    use crate::commands::{after_password_unlock, app_state, pass_err};
    use crate::google_oauth::{self as oauth, AuthError, Client, Endpoints};
    use crate::settings::{self, GoogleDriveSettings};
    use crate::state::{lock, AppState};
    use crate::{popups, vaults};

    fn not_set_up() -> String {
        crate::i18n::tr!("errors.google_not_set_up")
    }
    fn not_listed() -> String {
        crate::i18n::tr!("errors.vault_not_listed")
    }

    static CURRENT: Mutex<Option<Arc<AtomicBool>>> = Mutex::new(None);

    fn client(app: &AppHandle) -> Res<Client> {
        Client::configured(&app_state(app).settings()).ok_or_else(not_set_up)
    }

    fn normalize(email: &str) -> Res<String> {
        let email = email.trim().to_lowercase();
        if email.is_empty() || !email.contains('@') {
            return Err(tr!("errors.google_sign_in_first"));
        }
        Ok(email)
    }

    pub fn sign_in(app: &AppHandle, hint: Option<String>) -> Res<Option<Value>> {
        let client = client(app)?;
        let cancel = Arc::new(AtomicBool::new(false));
        if let Some(previous) = lock(&CURRENT).replace(cancel.clone()) {
            previous.store(true, Ordering::Relaxed);
        }
        let result = oauth::sign_in_with(
            &Endpoints::google(),
            &client,
            hint.as_deref(),
            oauth::SIGN_IN_TIMEOUT,
            &cancel,
            oauth::open_browser,
        );
        {
            let mut current = lock(&CURRENT);
            if current.as_ref().is_some_and(|c| Arc::ptr_eq(c, &cancel)) {
                *current = None;
            }
        }
        let tokens = match result {
            Ok(tokens) => tokens,
            Err(AuthError::Cancelled) => return Ok(None),
            Err(e) => {
                popups::show_main(app);
                return Err(e.message());
            }
        };
        popups::show_main(app);
        let account = pass_core::gdrive_account(tokens.access_token.to_string())
            .map_err(|e| drive_failure(e).text())?;
        let email = account.email.trim().to_lowercase();
        if email.is_empty() {
            return Err(tr!("errors.google_no_account"));
        }
        oauth::store_pending(&email, &tokens);
        Ok(Some(
            json!({ "email": email, "name": account.display_name }),
        ))
    }

    pub fn cancel() {
        if let Some(flag) = lock(&CURRENT).take() {
            flag.store(true, Ordering::Relaxed);
        }
    }

    pub enum Failure {
        SignInAgain(String),
        /// Drive refused for the rate: the scheduler backs off for a while.
        RateLimited(String),
        /// The vault was removed from Drive on another device: the backup is turned off here.
        Removed(String),
        Other(String),
    }

    impl Failure {
        pub fn text(self) -> String {
            match self {
                Failure::SignInAgain(m)
                | Failure::RateLimited(m)
                | Failure::Removed(m)
                | Failure::Other(m) => m,
            }
        }
    }

    fn auth_failure(e: AuthError) -> Failure {
        match e {
            AuthError::SignInAgain => Failure::SignInAgain(oauth::sign_in_again()),
            other => Failure::Other(other.message()),
        }
    }

    fn drive_failure(e: PassError) -> Failure {
        match e {
            PassError::AuthRequired(m)
                if crate::errors::core_says(&m, "gdrive.app_folder_denied") =>
            {
                Failure::SignInAgain(tr!("errors.google_folder_permission"))
            }
            PassError::AuthRequired(_) => Failure::SignInAgain(oauth::sign_in_again()),
            PassError::Network(m) if crate::errors::core_says(&m, "gdrive.busy") => {
                Failure::RateLimited(pass_err(PassError::Network(m)))
            }
            PassError::NotFound(m) if crate::errors::core_says(&m, "gdrive.vault_removed") => {
                Failure::Removed(tr!("errors.google_removed_elsewhere"))
            }
            PassError::Crypto(_) | PassError::InvalidPassword => {
                Failure::Other(tr!("errors.google_different_vault"))
            }
            other => Failure::Other(pass_err(other)),
        }
    }

    /// Drive refused a token Google had just issued. Only a missing permission (app folder unticked)
    /// needs a new sign-in; a plain 401 is a hiccup and the sync tries again later.
    pub(super) fn refused_fresh_token(e: PassError) -> Failure {
        match e {
            PassError::AuthRequired(m)
                if !crate::errors::core_says(&m, "gdrive.app_folder_denied") =>
            {
                oauth::note("gdrive: drive refused a fresh token (401, sign-in kept)");
                Failure::Other(tr!("errors.google_refused"))
            }
            other => drive_failure(other),
        }
    }

    /// Runs a Drive call with a current access token; when refused, once more with a refreshed one.
    fn with_drive<T>(
        app: &AppHandle,
        email: &str,
        call: impl Fn(String) -> pass_core::Result<T>,
    ) -> Result<T, Failure> {
        let client = client(app).map_err(Failure::Other)?;
        let endpoints = Endpoints::google();
        let token = oauth::access_token(&endpoints, &client, email, false).map_err(auth_failure)?;
        match call(token.to_string()) {
            Err(PassError::AuthRequired(_)) => {
                oauth::note("gdrive: drive refused the access token (refreshing)");
                oauth::forget_access(email);
                let token =
                    oauth::access_token(&endpoints, &client, email, true).map_err(auth_failure)?;
                call(token.to_string()).map_err(refused_fresh_token)
            }
            other => other.map_err(drive_failure),
        }
    }

    pub fn list(app: &AppHandle, email: &str) -> Res<Vec<Value>> {
        let email = normalize(email)?;
        let vaults =
            with_drive(app, &email, pass_core::gdrive_list_vaults).map_err(Failure::text)?;
        let settings = app_state(app).settings();
        Ok(vaults
            .into_iter()
            .map(|v| {
                let here = settings
                    .find_by_path(&settings::cache_vault_path(&v.vault_id))
                    .is_some();
                json!({
                    "file_id": v.file_id,
                    "vault_id": v.vault_id,
                    "name": v.name,
                    "modified": v.modified,
                    "size": v.size,
                    "on_this_pc": here,
                })
            })
            .collect())
    }

    fn google(email: &str) -> Option<GoogleDriveSettings> {
        Some(GoogleDriveSettings {
            account_email: email.to_string(),
            sign_in_needed: false,
        })
    }

    pub fn open_with_password(
        app: &AppHandle,
        email: &str,
        password: &str,
        local: Option<&[u8]>,
    ) -> Option<Arc<Vault>> {
        let local = local?;
        let email = normalize(email).ok()?;
        let device_id = app_state(app).settings().device_id;
        let vaults = with_drive(app, &email, pass_core::gdrive_list_vaults).ok()?;
        vaults.into_iter().find_map(|v| {
            let bytes = with_drive(app, &email, |token| {
                pass_core::gdrive_download(token, v.file_id.clone())
            })
            .ok()?;
            let vault = Vault::unlock(bytes, password.to_string(), device_id.clone()).ok()?;
            vault.merge_remote(local.to_vec()).ok().map(|_| vault)
        })
    }

    pub fn restore(
        app: &AppHandle,
        email: &str,
        file_id: &str,
        password: &str,
        name: Option<String>,
    ) -> Res<Value> {
        let email = normalize(email)?;
        if file_id.trim().is_empty() {
            return Err(tr!("errors.choose_restore_vault"));
        }
        let state = app_state(app);
        let bytes = with_drive(app, &email, |token| {
            pass_core::gdrive_download(token, file_id.to_string())
        })
        .map_err(Failure::text)?;
        let vault = Vault::unlock(bytes, password.to_string(), state.settings().device_id)
            .map_err(pass_err)?;
        let path = settings::cache_vault_path(&vault.vault_id());
        if let Some(other) = state
            .settings()
            .find_by_path(&path)
            .filter(|v| v.webdav.is_some())
        {
            return Err(crate::i18n::tr!(
                "errors.vault_already_here",
                vault = other.name,
                location = other.location()
            ));
        }
        crate::vaults::write_vault_file(&path, &vault)?;
        oauth::commit(&email)?;
        let name = name.map(|n| n.trim().to_string()).filter(|n| !n.is_empty());
        let id = state.update_settings(|s| {
            let id = match s.find_by_path(&path).map(|v| v.id.clone()) {
                Some(id) => {
                    if let Some(name) = &name {
                        s.rename_vault(&id, name)?;
                    }
                    id
                }
                None => {
                    let name =
                        settings::unique_name(name.as_deref().unwrap_or("Personal"), &s.vaults);
                    s.add_vault(path.clone(), Some(&name), None)
                }
            };
            s.vault_mut(&id).ok_or_else(not_listed)?.google_drive = google(&email);
            s.set_google_sign_in_needed(&email, false);
            Ok(id)
        })?;
        let agent = vaults::activate(app, &id)?;
        agent
            .unlock_with_key(vault.export_vault_key())
            .map_err(pass_err)?;
        crate::health::note_master_password_unlock(&state, &id, password);
        let mut result = after_password_unlock(&state, &agent, &id);
        state.kick_sync();
        result["step"] = json!("done");
        Ok(result)
    }

    fn target(email: &str, vault_name: &str) -> Option<pass_agent::GDriveTarget> {
        Some(pass_agent::GDriveTarget {
            account: email.to_string(),
            vault_name: vault_name.to_string(),
        })
    }

    fn emit_synced(app: &AppHandle, state: &AppState, result: &pass_core::SyncResult) {
        let status = {
            let mut sync = lock(&state.sync);
            sync.record_success(vaults::now_ms(), result.remote_bytes);
            sync.running = false;
            sync.sign_in_needed = false;
            sync.pending = false;
            sync.clone()
        };
        let _ = app.emit("sync-status", status);
        let stats = &result.stats;
        if stats.added + stats.updated + stats.deleted > 0 {
            let _ = app.emit("vault-changed", ());
        }
    }

    pub fn enable(app: &AppHandle, email: &str) -> Res<Value> {
        let email = normalize(email)?;
        let state = app_state(app);
        let agent = state.require_agent()?;
        let vault = state.vault()?;
        let id = vaults::active_id(&state)?;
        let entry = state
            .settings()
            .vault(&id)
            .cloned()
            .ok_or_else(not_listed)?;
        if entry.webdav.as_ref().is_some_and(|w| w.is_pass_server()) {
            return Err(tr!("errors.google_server_vault"));
        }
        agent.save().map_err(pass_err)?;
        if entry.google_account() == Some(email.as_str()) {
            // A new sign-in for an account this vault already uses: kept and the pause lifted before the
            // sync, so a failing sync is retried in the background instead of asking again.
            oauth::commit(&email)?;
            state.update_settings(|s| {
                s.set_google_sign_in_needed(&email, false);
                Ok(())
            })?;
            lock(&state.sync).sign_in_needed = false;
        }
        let result = with_drive(app, &email, |token| {
            pass_core::gdrive_sync(
                vault.clone(),
                GDriveConfig {
                    access_token: token,
                    vault_name: entry.name.clone(),
                    start_again: true,
                },
            )
        })
        .map_err(Failure::text)?;
        agent.save().map_err(pass_err)?;
        oauth::commit(&email)?;
        state.update_settings(|s| {
            let v = s.vault_mut(&id).ok_or_else(not_listed)?;
            v.webdav = None;
            v.google_drive = google(&email);
            s.set_google_sign_in_needed(&email, false);
            Ok(())
        })?;
        if let Some(webdav) = &entry.webdav {
            settings::delete_webdav_password(&id, webdav, true);
        }
        agent.set_webdav(None);
        agent.set_gdrive(target(&email, &entry.name));
        if let Some(previous) = entry.google_account().filter(|p| *p != email) {
            release_if_unused(app, previous, true);
        }
        emit_synced(app, &state, &result);
        let stats = &result.stats;
        Ok(json!({
            "email": email,
            "created_remote": result.created_remote,
            "uploaded": result.uploaded,
            "added": stats.added,
            "updated": stats.updated,
            "deleted": stats.deleted,
        }))
    }

    pub fn after_create(app: &AppHandle, email: &str) -> Option<String> {
        let not_yet =
            |why: String| Some(tr!("warnings.google_not_backed_up", error = why.trim_end()));
        let email = match normalize(email) {
            Ok(e) => e,
            Err(e) => return not_yet(e),
        };
        let state = app_state(app);
        let (Some(agent), Ok(id)) = (state.agent(), vaults::active_id(&state)) else {
            return None;
        };
        if let Err(e) = oauth::commit(&email) {
            return Some(e);
        }
        let name = state
            .settings()
            .vault(&id)
            .map(|v| v.name.clone())
            .unwrap_or_default();
        if let Err(e) = state.update_settings(|s| {
            s.vault_mut(&id).ok_or_else(not_listed)?.google_drive = google(&email);
            s.set_google_sign_in_needed(&email, false);
            Ok(())
        }) {
            return Some(e);
        }
        agent.set_gdrive(target(&email, &name));
        match crate::background::sync_now(app) {
            Ok(_) => None,
            Err(e) => not_yet(e),
        }
    }

    pub fn disable(app: &AppHandle, delete_copy: bool) -> Res<Value> {
        let state = app_state(app);
        let id = vaults::active_id(&state)?;
        let entry = state
            .settings()
            .vault(&id)
            .cloned()
            .ok_or_else(not_listed)?;
        let email = entry
            .google_account()
            .ok_or_else(|| tr!("errors.not_google_vault"))?
            .to_string();
        let mut deleted = 0;
        if delete_copy {
            if super::sign_in_needed(&state.settings()) {
                return Err(oauth::sign_in_again());
            }
            let vault_id = state.vault()?.vault_id();
            // Every file of this vault (a twin too), and a marker so other devices stop syncing it.
            deleted = with_drive(app, &email, |token| {
                pass_core::gdrive_remove_vault(token, vault_id.clone())
            })
            .map_err(|f| {
                if let Failure::SignInAgain(_) = f {
                    pause_for_sign_in(app, &email);
                }
                tr!("errors.google_delete_failed", error = f.text())
            })?;
        }
        turn_off(app, &id, &email, true)?;
        Ok(json!({ "deleted": deleted }))
    }

    /// The backup of vault `id` is off on this PC: settings, agent, sync status, and the account's
    /// sign-in when no other vault uses it (`revoke`: also at Google).
    fn turn_off(app: &AppHandle, id: &str, email: &str, revoke: bool) -> Res<()> {
        let state = app_state(app);
        state.update_settings(|s| {
            s.vault_mut(id).ok_or_else(not_listed)?.google_drive = None;
            Ok(())
        })?;
        if let Some(agent) = state.agent() {
            agent.set_gdrive(None);
        }
        let status = {
            let mut sync = lock(&state.sync);
            *sync = Default::default();
            sync.clone()
        };
        let _ = app.emit("sync-status", status);
        release_if_unused(app, email, revoke);
        Ok(())
    }

    fn active_google(app: &AppHandle) -> Res<(String, settings::VaultEntry, String)> {
        let state = app_state(app);
        let id = vaults::active_id(&state)?;
        let entry = state
            .settings()
            .vault(&id)
            .cloned()
            .ok_or_else(not_listed)?;
        let email = entry
            .google_account()
            .ok_or_else(|| tr!("errors.not_google_vault"))?
            .to_string();
        Ok((id, entry, email))
    }

    pub fn delete_old_versions(app: &AppHandle) -> Res<Value> {
        let state = app_state(app);
        let agent = state.require_agent()?;
        let vault = state.vault()?;
        let (id, entry, email) = active_google(app)?;
        if super::sign_in_needed(&state.settings()) {
            return Err(oauth::sign_in_again());
        }
        agent.save().map_err(pass_err)?;
        let result = with_drive(app, &email, |token| {
            pass_core::gdrive_delete_old_versions(
                vault.clone(),
                GDriveConfig {
                    access_token: token,
                    vault_name: entry.name.clone(),
                    start_again: false,
                },
            )
        });
        // It syncs first: what it merged and its sync state are kept, whatever happened next.
        agent.save().map_err(pass_err)?;
        match result {
            Ok(r) => {
                let _ = app.emit("vault-changed", ());
                Ok(json!({ "removed": r.removed, "kept": r.kept, "unfinished": r.unfinished }))
            }
            Err(Failure::SignInAgain(message)) => {
                pause_for_sign_in(app, &email);
                Err(message)
            }
            Err(Failure::RateLimited(message)) => {
                super::RATE_LIMITED.store(true, Ordering::Relaxed);
                Err(message)
            }
            Err(Failure::Removed(message)) => {
                turn_off(app, &id, &email, false)?;
                Err(message)
            }
            Err(Failure::Other(message)) => Err(message),
        }
    }

    pub fn remove(app: &AppHandle, confirm_name: &str) -> Res<Value> {
        let (_, entry, _) = active_google(app)?;
        if !super::name_confirmed(confirm_name, &entry.name) {
            return Err(tr!("errors.google_remove_name", vault = entry.name));
        }
        disable(app, true)
    }

    /// Deletes the account's sign-in when no listed vault uses it (`revoke`: also at Google).
    pub fn release_if_unused(app: &AppHandle, email: &str, revoke: bool) {
        if app_state(app)
            .settings()
            .google_users(email)
            .next()
            .is_some()
        {
            return;
        }
        oauth::release(email, revoke.then(Endpoints::google));
    }

    fn pause_for_sign_in(app: &AppHandle, email: &str) {
        mark_sign_in_needed(app, email);
        let state = app_state(app);
        let status = lock(&state.sync).clone();
        let _ = app.emit("sync-status", status);
    }

    fn mark_sign_in_needed(app: &AppHandle, email: &str) {
        oauth::note("gdrive: vault paused (sign in to Google again)");
        let state = app_state(app);
        let _ = state.update_settings(|s| {
            s.set_google_sign_in_needed(email, true);
            Ok(())
        });
        lock(&state.sync).sign_in_needed = true;
    }

    pub fn sync(
        app: &AppHandle,
        agent: &pass_agent::Agent,
    ) -> Result<Option<pass_core::SyncResult>, String> {
        let Some(target) = agent.config().gdrive else {
            return Ok(None);
        };
        if agent.is_locked() {
            return Ok(None);
        }
        if super::sign_in_needed(&app_state(app).settings()) {
            return Err(oauth::sign_in_again());
        }
        match with_drive(app, &target.account, |token| {
            agent.sync_gdrive(&target.account, &token)
        }) {
            Ok(result) => Ok(result),
            Err(Failure::SignInAgain(message)) => {
                mark_sign_in_needed(app, &target.account);
                Err(message)
            }
            Err(Failure::RateLimited(message)) => {
                super::RATE_LIMITED.store(true, Ordering::Relaxed);
                Err(message)
            }
            Err(Failure::Removed(message)) => {
                // Removed on another device: stop here too (the vault stays on this PC), and say so.
                oauth::note("gdrive: vault removed from Drive on another device (backup off here)");
                let id = vaults::active_id(&app_state(app))?;
                turn_off(app, &id, &target.account, false)?;
                let _ = app.emit("toast", message);
                Ok(None)
            }
            Err(Failure::Other(message)) => Err(message),
        }
    }
}

#[cfg(not(feature = "gdrive"))]
mod imp {
    use serde_json::Value;
    use tauri::AppHandle;

    use super::Res;

    fn no_gdrive() -> String {
        crate::i18n::tr!("errors.no_gdrive_build")
    }

    pub fn sign_in(_app: &AppHandle, _hint: Option<String>) -> Res<Option<Value>> {
        Err(no_gdrive())
    }
    pub fn cancel() {}
    pub fn list(_app: &AppHandle, _email: &str) -> Res<Vec<Value>> {
        Err(no_gdrive())
    }
    pub fn restore(
        _app: &AppHandle,
        _email: &str,
        _file_id: &str,
        _password: &str,
        _name: Option<String>,
    ) -> Res<Value> {
        Err(no_gdrive())
    }
    pub fn enable(_app: &AppHandle, _email: &str) -> Res<Value> {
        Err(no_gdrive())
    }
    pub fn disable(_app: &AppHandle, _delete_copy: bool) -> Res<Value> {
        Err(no_gdrive())
    }
    pub fn delete_old_versions(_app: &AppHandle) -> Res<Value> {
        Err(no_gdrive())
    }
    pub fn remove(_app: &AppHandle, _confirm_name: &str) -> Res<Value> {
        Err(no_gdrive())
    }
    pub fn after_create(_app: &AppHandle, _email: &str) -> Option<String> {
        Some(no_gdrive())
    }
    pub fn release_if_unused(_app: &AppHandle, _email: &str, _revoke: bool) {}
    pub fn open_with_password(
        _app: &AppHandle,
        _email: &str,
        _password: &str,
        _local: Option<&[u8]>,
    ) -> Option<std::sync::Arc<pass_core::Vault>> {
        None
    }
}

#[cfg(all(test, feature = "gdrive"))]
mod tests {
    use super::imp::{refused_fresh_token, Failure};
    use pass_core::PassError;

    #[test]
    fn a_fresh_token_refused_by_drive_keeps_the_sign_in() {
        let plain = PassError::AuthRequired(
            "Google Drive: the sign-in expired or was revoked; sign in to Google again".into(),
        );
        assert!(matches!(refused_fresh_token(plain), Failure::Other(_)));
        // The user unticked the app folder: only a new sign-in can fix that.
        let denied = PassError::AuthRequired(
            "Google Drive: Passyble wasn't allowed to use its app folder; sign in to Google again and allow it"
                .into(),
        );
        assert!(matches!(
            refused_fresh_token(denied),
            Failure::SignInAgain(_)
        ));
        assert!(matches!(
            refused_fresh_token(PassError::Network("offline".into())),
            Failure::Other(_)
        ));
    }

    #[test]
    fn a_removal_on_another_device_is_told_apart() {
        let removed = PassError::NotFound(
            "this vault was removed from Google Drive on another device; the copy on this device stays"
                .into(),
        );
        assert!(matches!(refused_fresh_token(removed), Failure::Removed(_)));
        let gone = PassError::NotFound("that vault is no longer on Google Drive".into());
        assert!(matches!(refused_fresh_token(gone), Failure::Other(_)));
    }

    #[test]
    fn removing_from_drive_asks_for_the_vault_name() {
        use super::name_confirmed;
        assert!(name_confirmed("Personal", "Personal"));
        assert!(name_confirmed("  personal ", "Personal"));
        assert!(name_confirmed("ÉQUIPE", "équipe"));
        assert!(!name_confirmed("Persona", "Personal"));
        assert!(!name_confirmed("", "Personal"));
        assert!(!name_confirmed("", ""));
        assert!(!name_confirmed("Work", "Personal"));
    }

    #[test]
    fn a_rate_limit_is_told_apart_from_other_failures() {
        let busy = PassError::Network(
            "Check: Google Drive is busy (too many requests); try again in a few minutes".into(),
        );
        assert!(matches!(refused_fresh_token(busy), Failure::RateLimited(_)));
        assert!(!super::take_rate_limited());
    }
}
