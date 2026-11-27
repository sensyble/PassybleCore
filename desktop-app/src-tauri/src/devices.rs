//! Settings → Signed-in devices (Passyble Server vaults): the account's devices, each with "Sign out"
//! (`pass_core::server_list_devices` / `server_revoke_device`), and the "signed out" sync state.
//!
//! A password change signs out the account's other devices, and any device can sign out another from this list. Such a
//! device's next request is refused ("authentication failed … signed out"): sync then stops retrying (`background.rs`),
//! the vault view shows **Signed out · Sign in again**, and the user signs in again with the account password
//! (`server_adopt_password` in signin.rs, which also re-wraps the vault if the password changed). Signing out this
//! device from the list forgets its token right away and shows the same state.

use pass_core::PassError;
use serde_json::Value;
use tauri::{AppHandle, Emitter};

use crate::commands::{app_state, blocking};
use crate::state::lock;

type Res<T> = Result<T, String>;

pub fn signed_out_text() -> String {
    crate::i18n::tr!("errors.signed_out")
}

/// The server refused this device's token (Passyble Server's account API: 401 "…signed out"; its
/// WebDAV: 401/403 "authentication failed").
pub fn is_signed_out(e: &PassError) -> bool {
    matches!(e, PassError::Network(m) if crate::errors::is_auth_failure(m))
}

/// Puts the sync status into the "signed out" state and tells the windows. The vault's list kept
/// on disk for the next start is deleted (`Agent::forget_kept_list`): a device signed out from
/// another one may be lost or stolen.
pub fn mark_signed_out(app: &AppHandle) {
    let state = app_state(app);
    if let Some(agent) = state.agent() {
        agent.forget_kept_list();
    }
    let status = {
        let mut status = lock(&state.sync);
        status.signed_out = true;
        status.running = false;
        status.last_error = Some(signed_out_text());
        status.clone()
    };
    let _ = app.emit("sync-status", status);
}

pub fn clear_signed_out(app: &AppHandle) {
    let state = app_state(app);
    let status = {
        let mut status = lock(&state.sync);
        if !status.signed_out {
            return;
        }
        status.signed_out = false;
        if status.last_error.as_deref() == Some(signed_out_text().as_str()) {
            status.last_error = None;
        }
        status.clone()
    };
    let _ = app.emit("sync-status", status);
}

/// The active Passyble Server vault's account devices: `{ signed_out: false, devices: [{ id, name,
/// created_at, last_used_at, current, limited }] }` (times in unix ms, `last_used_at` may be
/// null), or `{ signed_out: true }` when this device is signed out.
#[tauri::command]
pub async fn server_devices(app: AppHandle) -> Res<Value> {
    blocking(move || imp::list(&app)).await
}

/// Signs out one of the account's devices. `{ current: true }` when it was this one: its token
/// is forgotten and the window asks to sign in again.
#[tauri::command]
pub async fn server_sign_out_device(app: AppHandle, device_id: String) -> Res<Value> {
    blocking(move || imp::sign_out(&app, device_id)).await
}

#[cfg(feature = "webdav")]
mod imp {
    use crate::i18n::tr;
    use pass_core::PassError;
    use serde_json::{json, Value};
    use tauri::AppHandle;

    use super::{clear_signed_out, is_signed_out, mark_signed_out, signed_out_text, Res};
    use crate::commands::app_state;
    use crate::settings;
    use crate::signin::imp::{active_server, err};

    /// Errors as the user should read them. The server's own sentences (a device that must
    /// still choose its own password, a server without the device list) are shown as they are.
    fn message(e: PassError) -> String {
        match e {
            PassError::Network(m) if crate::errors::password_change_required(&m).is_some() => {
                crate::errors::password_change_required(&m).unwrap_or(m)
            }
            PassError::Network(m) if crate::errors::core_says(&m, "server.no_devices_api") => {
                crate::errors::sentence(&m)
            }
            PassError::NotFound(_) => tr!("errors.device_already_signed_out"),
            other => err(other),
        }
    }

    pub fn list(app: &AppHandle) -> Res<Value> {
        let (_, webdav, token, base) = active_server(app)?;
        let Some(token) = token else {
            mark_signed_out(app);
            return Ok(json!({ "signed_out": true }));
        };
        match pass_core::server_list_devices(base, webdav.username, token, webdav.pins) {
            Ok(devices) => {
                clear_signed_out(app);
                let devices: Vec<Value> = devices
                    .into_iter()
                    .map(|d| {
                        json!({
                            "id": d.id,
                            "name": d.name,
                            "created_at": d.created_at,
                            "last_used_at": d.last_used_at,
                            "current": d.current,
                            "limited": d.limited,
                        })
                    })
                    .collect();
                Ok(json!({ "signed_out": false, "devices": devices }))
            }
            Err(e) if is_signed_out(&e) => {
                mark_signed_out(app);
                Ok(json!({ "signed_out": true }))
            }
            Err(e) => Err(message(e)),
        }
    }

    pub fn sign_out(app: &AppHandle, device_id: String) -> Res<Value> {
        let (id, webdav, token, base) = active_server(app)?;
        let token = token.ok_or_else(signed_out_text)?;
        let refused = |e: PassError| {
            if is_signed_out(&e) {
                mark_signed_out(app);
                signed_out_text()
            } else {
                message(e)
            }
        };
        // Which device this is (the list's `current`), from the server rather than the window.
        let this = pass_core::server_account(
            base.clone(),
            webdav.username.clone(),
            token.clone(),
            webdav.pins.clone(),
        )
        .map_err(refused)?;
        pass_core::server_revoke_device(
            base,
            webdav.username.clone(),
            token,
            device_id.clone(),
            webdav.pins.clone(),
        )
        .map_err(refused)?;
        let current = this.device_id == device_id.trim();
        if current {
            // The token is dead: forget it (the account stays, for signing in again).
            settings::delete_webdav_password(&id, &webdav, true);
            let state = app_state(app);
            if let Some(agent) = state.agent() {
                agent.set_webdav(crate::state::webdav_config(&state.settings()));
            }
            mark_signed_out(app);
        }
        Ok(json!({ "current": current }))
    }
}

#[cfg(not(feature = "webdav"))]
mod imp {
    use serde_json::Value;
    use tauri::AppHandle;

    use super::Res;

    fn no_webdav() -> String {
        crate::i18n::tr!("errors.no_sync_build")
    }

    pub fn list(_: &AppHandle) -> Res<Value> {
        Err(no_webdav())
    }
    pub fn sign_out(_: &AppHandle, _: String) -> Res<Value> {
        Err(no_webdav())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refused_tokens_are_signed_out() {
        // Core/core/src/server.rs (account API) and Core/core/src/webdav.rs (vault file).
        assert!(is_signed_out(&PassError::Network(
            "devices: authentication failed (the device was revoked or signed out)".into()
        )));
        assert!(is_signed_out(&PassError::Network(
            "sync: authentication failed".into()
        )));
        assert!(!is_signed_out(&PassError::InvalidPassword));
        assert!(!is_signed_out(&PassError::Network(
            "sync: https://h/dav/a/p.vault: Connection Failed: timed out".into()
        )));
    }
}
