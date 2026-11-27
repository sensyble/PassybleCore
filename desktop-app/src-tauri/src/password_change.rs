//! What follows a vault's master password change. Every change gives the vault a new key and re-encrypts it
//! (pass-core), so a copy kept somewhere with the old password (a server's old versions, Drive revisions, WebDAV
//! history) never opens what is written from now on. This module does the rest on this PC:
//!
//! * Old copies: on a Passyble Server, once the re-encrypted file is uploaded the old versions are dropped
//!   (`pass_core::server_purge_versions`, owner only); a server too old for it keeps them until they expire.
//!   Google Drive and WebDAV have no such call: the window says their old copies still open with the old password.
//! * What wrapped the old key: the recovery code is gone (a new one is offered without the password again);
//!   emergency grants are renewed; admin recovery enrolments are stale and the member is asked to join again (never
//!   enrolled on its own); the Windows Hello copy of the old key is replaced.
//!
//! Other devices still on the old key get "password was changed on another device" on sync; unlocking there with
//! the new password opens the synced copy and merges theirs in ([`refresh_from_sync`]).

use pass_agent::Agent;
use pass_core::{PassError, Vault};
use serde_json::{json, Value};
use tauri::AppHandle;

use crate::commands::{app_state, pass_err};
use crate::i18n::tr;
use crate::state::AppState;

#[derive(Debug, Default)]
pub struct Before {
    had_recovery_code: bool,
    /// Organisations whose admin recovery held this vault's key.
    recovery_orgs: Vec<String>,
}

pub fn before(vault: &Vault) -> Before {
    Before {
        had_recovery_code: vault.has_recovery_code(),
        recovery_orgs: vault
            .admin_recovery_enrollments()
            .into_iter()
            .map(|e| e.org)
            .collect(),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OldCopies {
    /// A Passyble Server: its old versions are dropped after the upload.
    Server,
    /// Google Drive keeps revisions; nothing drops them from here.
    GoogleDrive,
    /// A WebDAV service may keep versions; nothing drops them from here.
    WebDav,
    None,
}

pub fn old_copies(state: &AppState, vault_id: &str) -> OldCopies {
    let settings = state.settings();
    let Some(entry) = settings.vault(vault_id) else {
        return OldCopies::None;
    };
    match (&entry.webdav, entry.google_account()) {
        (Some(w), _) if w.is_pass_server() => OldCopies::Server,
        (Some(w), _) if !w.url.trim().is_empty() => OldCopies::WebDav,
        (_, Some(_)) => OldCopies::GoogleDrive,
        _ => OldCopies::None,
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Purge {
    /// The re-encrypted file isn't uploaded yet: the old versions are not touched, since they may
    /// be the only copy with the latest items until the upload goes through.
    NotUploaded,
    Dropped(u64),
    /// A server too old for the call: its old versions stay until they expire.
    TooOld,
    NotOwner,
    Failed(String),
}

pub fn purge_after_upload(
    uploaded: bool,
    call: impl FnOnce() -> pass_core::Result<Option<u64>>,
) -> Purge {
    if !uploaded {
        return Purge::NotUploaded;
    }
    match call() {
        Ok(Some(n)) => Purge::Dropped(n),
        Ok(None) => Purge::TooOld,
        Err(PassError::InvalidInput(m))
            if crate::errors::core_says(&m, "server.not_vault_owner") =>
        {
            Purge::NotOwner
        }
        Err(e) => Purge::Failed(pass_err(e)),
    }
}

pub fn purge_json(purge: &Purge) -> Value {
    match purge {
        Purge::NotUploaded => json!({ "state": "not_uploaded" }),
        Purge::Dropped(n) => json!({ "state": "dropped", "count": n }),
        Purge::TooOld => json!({ "state": "kept_until_expiry" }),
        Purge::NotOwner => json!({ "state": "not_owner" }),
        Purge::Failed(e) => json!({ "state": "failed", "error": e }),
    }
}

#[cfg(feature = "webdav")]
pub fn server_purge(
    base: &str,
    webdav: &crate::settings::WebDavSettings,
    token: &str,
) -> pass_core::Result<Option<u64>> {
    pass_core::server_purge_versions(
        base.to_string(),
        webdav.username.clone(),
        token.to_string(),
        webdav.url.clone(),
        webdav.pins.clone(),
    )
}

/// After the password of listed vault `id` changed (unlocked in `agent`): re-offers a recovery code, renews
/// emergency grants and remakes the Windows Hello copy. Adds to `result` `new_recovery_code`,
/// `rejoin_admin_recovery` (`[{ org, name }]`) and `old_copies` (`server`, `google_drive`, `webdav` or null); a
/// Windows Hello problem goes to `warning` when there is none yet.
pub fn after_change(app: &AppHandle, agent: &Agent, id: &str, before: &Before, result: &mut Value) {
    let state = app_state(app);
    crate::recovery::grant(id);
    crate::teams_send::renew_soon(app);
    result["new_recovery_code"] = json!(before.had_recovery_code);
    let orgs = state.settings().teams.map(|t| t.orgs).unwrap_or_default();
    let rejoin: Vec<Value> = before
        .recovery_orgs
        .iter()
        .map(|org| {
            let name = orgs.iter().find(|o| &o.id == org).map(|o| o.name.clone());
            json!({ "org": org, "name": name.unwrap_or_else(|| org.clone()) })
        })
        .collect();
    result["rejoin_admin_recovery"] = json!(rejoin);
    result["old_copies"] = match old_copies(&state, id) {
        OldCopies::Server => json!("server"),
        OldCopies::GoogleDrive => json!("google_drive"),
        OldCopies::WebDav => json!("webdav"),
        OldCopies::None => Value::Null,
    };
    if let Some(warning) = renew_hello(&state, agent, id) {
        if result.get("warning").is_none_or(Value::is_null) {
            result["warning"] = json!(warning);
        }
    }
}

/// The Windows Hello copy of the old vault key opens nothing now: made again for the new key
/// (Windows Hello shows). If that fails, the old copy is removed so Hello asks to be set up again.
/// Also after this PC took a copy another device gave a new key (an unlock with the new password).
pub fn renew_hello(state: &AppState, agent: &Agent, id: &str) -> Option<String> {
    let on = state.settings().vault(id).is_some_and(|v| v.windows_hello);
    if !on || !crate::hello::enrolled(id) {
        return None;
    }
    let _hello = state.ui.hello_lock();
    match crate::hello::enroll(agent, id, state.ui.main_owner()) {
        Ok(note) => note,
        Err(e) => {
            crate::hello::remove(id);
            Some(tr!("warnings.hello_set_up_again", error = e))
        }
    }
}

/// Unlock of a WebDAV or Google Drive vault whose password was changed on another device: the local copy (old
/// key) rejects the new `password`, but the synced copy opens with it. It is downloaded, this PC's copy merged in,
/// written, and the vault unlocked. `Ok(false)`: nothing to try here (no sync account, or the synced copy
/// doesn't open either).
pub fn refresh_from_sync(app: &AppHandle, agent: &Agent, id: &str, password: &str) -> Result<bool, String> {
    let state = app_state(app);
    let path = agent.config().vault_path;
    let device_id = state.settings().device_id;
    let remote = match old_copies(&state, id) {
        OldCopies::WebDav => {
            let Some(bytes) = webdav_copy(&state) else {
                return Ok(false);
            };
            match Vault::unlock(bytes, password.to_string(), device_id) {
                Ok(v) => v,
                Err(_) => return Ok(false),
            }
        }
        OldCopies::GoogleDrive => {
            let Some(email) = state.settings().vault(id).and_then(|v| v.google_account().map(str::to_string)) else {
                return Ok(false);
            };
            let local = std::fs::read(&path).ok();
            match crate::gdrive::open_with_password(app, &email, password, local.as_deref()) {
                Some(v) => v,
                None => return Ok(false),
            }
        }
        _ => return Ok(false),
    };
    merge_local_into(&remote, std::fs::read(&path).ok())?;
    crate::vaults::write_vault_file(&path, &remote)?;
    agent.unlock_with_key(remote.export_vault_key()).map_err(pass_err)?;
    renew_hello(&state, agent, id);
    state.kick_sync();
    Ok(true)
}

#[cfg(feature = "webdav")]
fn webdav_copy(state: &AppState) -> Option<Vec<u8>> {
    pass_core::webdav_download(crate::state::webdav_config(&state.settings())?).ok()
}

#[cfg(not(feature = "webdav"))]
fn webdav_copy(_: &AppState) -> Option<Vec<u8>> {
    None
}

/// Merges this PC's copy `local` (if any) into `remote`. It must be the same vault: a copy that
/// isn't (another vault, or a key the remote never had) is refused, so nothing is overwritten.
fn merge_local_into(remote: &Vault, local: Option<Vec<u8>>) -> Result<(), String> {
    match local {
        Some(bytes) => remote.merge_remote(bytes).map(|_| ()).map_err(pass_err),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kdf() -> pass_core::KdfParams {
        pass_core::KdfParams {
            m_kib: 64,
            t: 1,
            p: 1,
            ..Default::default()
        }
    }

    #[test]
    fn old_versions_are_dropped_only_after_the_upload() {
        let mut asked = false;
        assert_eq!(
            purge_after_upload(false, || {
                asked = true;
                Ok(Some(3))
            }),
            Purge::NotUploaded
        );
        assert!(!asked, "never before the new file is on the server");
        assert_eq!(purge_after_upload(true, || Ok(Some(3))), Purge::Dropped(3));
        assert_eq!(purge_after_upload(true, || Ok(None)), Purge::TooOld);
        assert_eq!(purge_json(&Purge::Dropped(3))["count"], 3);
        assert_eq!(purge_json(&Purge::TooOld)["state"], "kept_until_expiry");
        assert!(matches!(
            purge_after_upload(true, || Err(PassError::Network("offline".into()))),
            Purge::Failed(_)
        ));
    }

    /// A copy the server (or Google Drive) kept from before the change, opened with the old
    /// password, reads nothing written after it: the key changed with the password.
    #[test]
    fn attack_an_old_copy_opened_with_the_old_password_misses_new_items() {
        let vault = Vault::create_with_kdf("old demo password", "pc", kdf()).unwrap();
        let old_copy = vault.serialize().unwrap();
        vault.change_master_password("new demo password 2026".into()).unwrap();
        let id = vault
            .upsert(pass_core::Item {
                title: "After the change".into(),
                password: "secret-after".into(),
                ..Default::default()
            })
            .unwrap()
            .id;
        let new_copy = vault.serialize().unwrap();
        let old = Vault::unlock(old_copy.clone(), "old demo password".into(), "attacker".into()).unwrap();
        assert!(old.get(id.clone()).is_none(), "the old copy has no such item");
        // The old password doesn't open the new copy, and the old key doesn't read it either.
        assert!(Vault::unlock(new_copy.clone(), "old demo password".into(), "attacker".into()).is_err());
        assert!(old.merge_remote(new_copy).is_err(), "the old key can't read the new copy");
        // This PC's own copy from before the change still merges into the new vault.
        let other_pc = Vault::unlock(new_copy_of(&vault), "new demo password 2026".into(), "pc2".into()).unwrap();
        assert!(merge_local_into(&other_pc, Some(old_copy)).is_ok());
    }

    fn new_copy_of(vault: &Vault) -> Vec<u8> {
        vault.serialize().unwrap()
    }

    #[test]
    fn another_vaults_copy_is_never_merged_in() {
        let a = Vault::create_with_kdf("demo password one", "pc", kdf()).unwrap();
        let b = Vault::create_with_kdf("demo password two", "pc", kdf()).unwrap();
        assert!(merge_local_into(&a, Some(b.serialize().unwrap())).is_err());
        assert!(merge_local_into(&a, None).is_ok());
    }

    #[test]
    fn before_remembers_what_wrapped_the_old_key() {
        let vault = Vault::create_with_kdf("demo password", "pc", kdf()).unwrap();
        assert!(!before(&vault).had_recovery_code);
        vault.create_recovery_code().unwrap();
        let b = before(&vault);
        assert!(b.had_recovery_code);
        assert!(b.recovery_orgs.is_empty());
        // The change drops the code that wrapped the old key: the window offers a new one.
        vault.change_master_password("another demo password".into()).unwrap();
        assert!(!vault.has_recovery_code());
    }
}
