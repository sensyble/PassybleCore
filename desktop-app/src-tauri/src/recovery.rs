//! Recovery code for a forgotten master password (`pass_core::Vault::create_recovery_code`). The code is shown
//! once and never stored by Passyble; the vault file keeps the vault key wrapped by a key derived from it.
//!
//! * Settings: `recovery_code_create` / `recovery_code_remove` ask for the master password first.
//! * Onboarding: `setup_create` leaves a short-lived [`grant`] so the first `recovery_code_create` needs no
//!   password (it was just chosen). Choosing a new password after a recovery leaves one too.
//! * Unlock: `recovery_unlock` opens the vault with the code (for a server vault whose local copy doesn't know it
//!   yet, the server's copy) and unlocks the agent. The window then requires a new master password
//!   (`recovery_set_password`, no old one, allowed for [`RECOVERED_FOR`]) and offers a new code.
//! * Passyble Server vaults use the account's password as the master password, so a vault-only password would be
//!   undone by the next sign-in elsewhere: `recovery_set_password` refuses and the window offers the server's
//!   password reset (`recovery_server_reset`), which re-encrypts the vault with the new password.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use pass_core::PassError;
use serde_json::{json, Value};
use tauri::{AppHandle, Manager};
use tauri_plugin_dialog::DialogExt;

use crate::commands::{
    after_password_unlock, app_state, blocking, pass_err, unlock_target,
};
use crate::i18n::tr;
use crate::vaults;

type Res<T> = Result<T, String>;

/// How long after creating a vault (or a new password after a recovery) a code can be made without the password.
const GRANT_FOR: Duration = Duration::from_secs(10 * 60);
/// How long after a recovery unlock the new master password can be set without the old one.
const RECOVERED_FOR: Duration = Duration::from_secs(30 * 60);

/// (vault list id, since): "Create a recovery code" without the password, once.
static GRANT: Mutex<Option<(String, Instant)>> = Mutex::new(None);
/// (vault list id, since): unlocked with a recovery code, new master password not set yet.
static RECOVERED: Mutex<Option<(String, Instant)>> = Mutex::new(None);

fn slot(
    m: &'static Mutex<Option<(String, Instant)>>,
) -> std::sync::MutexGuard<'static, Option<(String, Instant)>> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

fn take_fresh(m: &'static Mutex<Option<(String, Instant)>>, vault: &str, ttl: Duration) -> bool {
    let mut slot = slot(m);
    let fresh = slot
        .as_ref()
        .is_some_and(|(id, at)| id == vault && at.elapsed() < ttl);
    if fresh {
        *slot = None;
    }
    fresh
}

/// Lets the window make one recovery code for `vault` without the master password for a few minutes.
pub(crate) fn grant(vault: &str) {
    *slot(&GRANT) = Some((vault.to_string(), Instant::now()));
}

pub(crate) fn status_json(vault: &pass_core::Vault) -> Value {
    json!({
        "exists": vault.has_recovery_code(),
        "created_at": vault.recovery_code_created_at(),
    })
}

/// The active vault's list entry is a Passyble Server vault: its account `(host, user)`.
fn pass_server_account(app: &AppHandle, id: &str) -> Option<(String, String)> {
    app_state(app)
        .settings()
        .vault(id)
        .and_then(|v| v.webdav.clone())
        .filter(|w| w.is_pass_server())
        .map(|w| (w.host(), w.username))
}

fn save_and_sync(app: &AppHandle, agent: &pass_agent::Agent, what: &str) -> Res<Option<String>> {
    agent
        .save()
        .map_err(|e| tr!("warnings.done_not_saved", what = what, error = pass_err(e)))?;
    Ok(crate::background::sync_now(app)
        .err()
        .map(|e| tr!("warnings.done_not_uploaded", what = what, error = e)))
}

/// A new recovery code for the unlocked vault. `password` may be left out only right after the vault was
/// created or got a new password ([`grant`]). Returns `{code, created_at, warning}`.
#[tauri::command]
pub async fn recovery_code_create(app: AppHandle, password: Option<String>) -> Res<Value> {
    blocking(move || {
        let state = app_state(&app);
        let agent = state.require_agent()?;
        let vault = state.vault()?;
        let id = vaults::active_id(&state)?;
        match password.filter(|p| !p.is_empty()) {
            Some(p) => {
                if !vault.check_password(p).map_err(pass_err)? {
                    return Err(tr!("errors.master_password_wrong"));
                }
            }
            None if take_fresh(&GRANT, &id, GRANT_FOR) => {}
            None => return Err(tr!("errors.enter_master_password")),
        }
        let code = vault.create_recovery_code().map_err(pass_err)?;
        let warning = save_and_sync(&app, &agent, &tr!("recovery.done_made"))?;
        Ok(json!({
            "code": code,
            "created_at": vault.recovery_code_created_at(),
            "warning": warning,
        }))
    })
    .await
}

#[tauri::command]
pub async fn recovery_code_remove(app: AppHandle, password: String) -> Res<Value> {
    blocking(move || {
        let state = app_state(&app);
        let agent = state.require_agent()?;
        let vault = state.vault()?;
        if !vault.check_password(password).map_err(pass_err)? {
            return Err(tr!("errors.master_password_wrong"));
        }
        vault.remove_recovery_code().map_err(pass_err)?;
        let warning = save_and_sync(&app, &agent, &tr!("recovery.done_removed"))?;
        Ok(json!({ "warning": warning }))
    })
    .await
}

fn file_name_part(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_control() || r#"<>:"/\|?*"#.contains(c) {
                '-'
            } else {
                c
            }
        })
        .collect();
    let cleaned = cleaned.trim().trim_matches('.').to_string();
    if cleaned.is_empty() {
        "vault".into()
    } else {
        cleaned.chars().take(60).collect()
    }
}

fn code_file_text(vault_name: &str, code: &str, date: &str) -> String {
    let lines = [
        tr!("recovery.print_title"),
        tr!("recovery.print_vault", vault = vault_name),
        tr!("recovery.print_made", date = date),
        String::new(),
        code.to_string(),
        String::new(),
        tr!("recovery.file_text"),
    ];
    // Windows line ends, also inside the (wrapped) paragraph.
    format!(
        "{}\r\n",
        lines.join("\n").replace("\r\n", "\n").replace('\n', "\r\n")
    )
}

#[tauri::command]
pub async fn recovery_code_save(app: AppHandle, code: String) -> Res<Option<String>> {
    blocking(move || {
        if !pass_core::recovery_code_valid_format(code.clone()) {
            return Err(tr!("errors.not_recovery_code"));
        }
        let state = app_state(&app);
        let name = state
            .settings()
            .active()
            .map(|v| v.name.clone())
            .unwrap_or_default();
        let mut dialog = app
            .dialog()
            .file()
            .set_title(tr!("recovery.save_title"))
            .set_file_name(format!(
                "passyble-recovery-code-{}.txt",
                file_name_part(&name)
            ))
            .add_filter(tr!("dialog.text_filter"), &["txt"]);
        if let Some(main) = app.get_webview_window("main") {
            dialog = dialog.set_parent(&main);
        }
        let Some(path) = dialog.blocking_save_file().and_then(|p| p.into_path().ok()) else {
            return Ok(None);
        };
        let text = code_file_text(&name, code.trim(), &crate::export::today());
        std::fs::write(&path, text).map_err(crate::errors::file_not_saved)?;
        Ok(Some(path.to_string_lossy().into_owned()))
    })
    .await
}

fn unlock_err(e: PassError) -> String {
    match e {
        PassError::InvalidPassword => tr!("errors.recovery_wrong_code"),
        PassError::NotFound(_) => tr!("errors.recovery_none"),
        other => pass_err(other),
    }
}

/// The vault opened with `code` from this vault's sync account (WebDAV or Passyble Server), for a
/// local copy that doesn't know the code yet (made on another device since the last sync).
#[cfg(feature = "webdav")]
fn from_sync_account(
    app: &AppHandle,
    code: &str,
    device_id: &str,
) -> Option<std::sync::Arc<pass_core::Vault>> {
    let config = crate::state::webdav_config(&app_state(app).settings())?;
    let bytes = pass_core::webdav_download(config).ok()?;
    pass_core::Vault::unlock_with_recovery_code(bytes, code.to_string(), device_id.to_string()).ok()
}

#[cfg(not(feature = "webdav"))]
fn from_sync_account(_: &AppHandle, _: &str, _: &str) -> Option<std::sync::Arc<pass_core::Vault>> {
    None
}

/// Unlocks vault `vault_id` (the active one without it) with `code`. Returns `{server: {host, username} | null}`:
/// a Passyble Server vault gets its new password through the server's reset, any other through `recovery_set_password`.
#[tauri::command]
pub async fn recovery_unlock(app: AppHandle, code: String, vault_id: Option<String>) -> Res<Value> {
    blocking(move || {
        // A typo is reported before anything is read or activated.
        if let Err(e @ PassError::InvalidInput(_)) =
            pass_core::Vault::unlock_with_recovery_code(Vec::new(), code.clone(), String::new())
        {
            return Err(pass_err(e));
        }
        let state = app_state(&app);
        let (agent, id) = unlock_target(&app, vault_id)?;
        let device_id = state.settings().device_id;
        let path = agent.config().vault_path;
        let bytes = std::fs::read(&path)
            .map_err(|e| crate::errors::logged(tr!("errors.vault_not_read"), "read vault", e))?;
        let vault = match pass_core::Vault::unlock_with_recovery_code(
            bytes,
            code.clone(),
            device_id.clone(),
        ) {
            Ok(vault) => vault,
            Err(e @ (PassError::NotFound(_) | PassError::InvalidPassword)) => {
                let remote =
                    from_sync_account(&app, &code, &device_id).ok_or_else(|| unlock_err(e))?;
                if let Ok(local) = std::fs::read(&path) {
                    // Unsynced changes of this PC's copy.
                    let _ = remote.merge_remote(local);
                }
                let bytes = remote.serialize().map_err(pass_err)?;
                std::fs::write(&path, bytes).map_err(crate::errors::file_not_saved)?;
                remote
            }
            Err(e) => return Err(unlock_err(e)),
        };
        agent
            .unlock_with_key(vault.export_vault_key())
            .map_err(pass_err)?;
        vaults::mark_opened(&state, &id);
        *slot(&RECOVERED) = Some((id.clone(), Instant::now()));
        let server = pass_server_account(&app, &id)
            .map(|(host, username)| json!({ "host": host, "username": username }));
        Ok(json!({ "server": server }))
    })
    .await
}

/// After `recovery_unlock`: the new master password (no old one needed). Windows Hello is then set up or kept as
/// after a password unlock. Returns `{warning}`.
#[tauri::command]
pub async fn recovery_set_password(app: AppHandle, new_password: String) -> Res<Value> {
    blocking(move || {
        let state = app_state(&app);
        crate::commands::check_new_master_password(&state, &new_password, &[], true)?;
        let agent = state.require_agent()?;
        let vault = state.vault()?;
        let id = vaults::active_id(&state)?;
        if pass_server_account(&app, &id).is_some() {
            return Err(tr!("errors.reset_server_password_instead"));
        }
        if !take_fresh(&RECOVERED, &id, RECOVERED_FOR) {
            return Err(tr!("errors.recovery_unlock_again"));
        }
        // A new key with the new password: the code just used wrapped the old one, so the window offers a new one.
        let before = crate::password_change::before(&vault);
        if let Err(e) = vault.change_master_password(new_password) {
            // Still recovering: let the user try again.
            *slot(&RECOVERED) = Some((id, Instant::now()));
            return Err(pass_err(e));
        }
        let saved = save_and_sync(&app, &agent, &tr!("recovery.done_password"));
        crate::health::note_master_password_changed(&state, &id);
        let mut result = after_password_unlock(&state, &agent, &id);
        // The password is changed either way; a failed save is retried by the agent.
        if let Some(warning) = saved.unwrap_or_else(Some) {
            result["warning"] = json!(warning);
        }
        crate::password_change::after_change(&app, &agent, &id, &before, &mut result);
        Ok(result)
    })
    .await
}

/// A Passyble Server vault opened with its recovery code: asks the server to e-mail a password reset link
/// (`{sent: true}`).
#[tauri::command]
pub async fn recovery_server_reset(app: AppHandle) -> Res<Value> {
    blocking(move || {
        #[cfg(feature = "webdav")]
        {
            let state = app_state(&app);
            let id = vaults::active_id(&state)?;
            let webdav = state
                .settings()
                .vault(&id)
                .and_then(|v| v.webdav.clone())
                .filter(|w| w.is_pass_server())
                .ok_or_else(|| tr!("errors.not_server_vault"))?;
            let base = crate::signin::server_base(&webdav.url)
                .ok_or_else(|| tr!("errors.unexpected_server_address"))?;
            match pass_core::server_request_reset(base, webdav.username.clone(), webdav.pins) {
                Ok(()) => Ok(json!({ "sent": true })),
                // The server's own explanation (no e-mail configured, rate limit).
                Err(PassError::Network(m)) if !m.contains("://") => {
                    Err(crate::errors::sentence(&m))
                }
                Err(e) => Err(pass_err(e)),
            }
        }
        #[cfg(not(feature = "webdav"))]
        {
            let _ = app;
            Err(tr!("errors.no_sync_build"))
        }
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grants_are_for_one_vault_once_and_expire() {
        grant("a");
        assert!(!take_fresh(&GRANT, "b", GRANT_FOR));
        assert!(!take_fresh(&GRANT, "a", Duration::ZERO));
        assert!(take_fresh(&GRANT, "a", GRANT_FOR));
        assert!(!take_fresh(&GRANT, "a", GRANT_FOR));
    }

    #[test]
    fn file_names_and_text() {
        assert_eq!(
            file_name_part("alice@pass.example.com"),
            "alice@pass.example.com"
        );
        assert_eq!(file_name_part("Work: \"A/B\""), "Work- -A-B-");
        assert_eq!(file_name_part(" .. "), "vault");
        let text = code_file_text("Personal", "AAAAA-BBBBB", "2026-10-14");
        assert!(text.contains("Vault: Personal\r\n"));
        assert!(text.contains("\r\nAAAAA-BBBBB\r\n"));
        assert!(!text.contains("\n\n"), "CRLF line ends only");
    }

    #[test]
    fn recovery_errors_in_plain_words() {
        assert!(unlock_err(PassError::InvalidPassword).contains("doesn't open this vault"));
        assert!(unlock_err(PassError::NotFound("x".into())).contains("no recovery code"));
    }
}
