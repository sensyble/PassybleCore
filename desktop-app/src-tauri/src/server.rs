//! "Connect to Passyble Server": a `pass+server://` pairing link (pasted, read from a QR code image or the clipboard,
//! or handed over by the browser extension's `server.pair`) becomes a vault's sync account.
//!
//! * `server_link_check` parses the link and tests the connection (HEAD on the vault file, with the link's certificate
//!   pin) so the user sees the server, certificate status and whether the vault exists before anything is saved.
//! * `setup_server_connect` downloads an existing vault or creates and uploads a new one; `server_use_for_vault` syncs
//!   the unlocked vault with the server (uploading it if the server has none) and keeps that account.
//!
//! The token is stored like a WebDAV password (Windows Credential Manager, per vault); the pins and the device name go
//! to `settings.json` with the vault's WebDAV account.

use pass_core::{parse_pairing_link, PairingLink};
use serde_json::{json, Value};
use tauri::{AppHandle, Manager};
use tauri_plugin_dialog::DialogExt;

use crate::commands::{app_state, blocking};
use crate::i18n::tr;
use crate::state::lock;

type Res<T> = Result<T, String>;

fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

fn parse(link: &str) -> Res<PairingLink> {
    let link = link.trim();
    if link.is_empty() {
        return Err(tr!("errors.paste_pairing_link"));
    }
    parse_pairing_link(link).map_err(|e| match e {
        pass_core::PassError::InvalidInput(m) => format!("{}.", capitalize(&m)),
        other => other.to_string(),
    })
}

/// What the dialog shows about a link. Never includes the token.
fn describe(link: &PairingLink) -> Value {
    json!({
        "host": link.host,
        "url": link.url,
        "username": link.username,
        "device_name": link.device_name,
        "https": link.https,
        "pinned": !link.pins.is_empty(),
        "pins": link.pins,
    })
}

fn pick_link(texts: Vec<String>) -> Res<String> {
    texts
        .into_iter()
        .map(|t| t.trim().to_string())
        .find(|t| t.starts_with("pass+server://"))
        .ok_or_else(|| tr!("errors.not_pairing_qr"))
}

fn qr_error(e: pass_core::PassError) -> String {
    match e {
        pass_core::PassError::InvalidInput(m) => format!("{}.", capitalize(&m)),
        other => other.to_string(),
    }
}

/// Parses the link and tests the connection. Returns the link's details plus `exists` (whether
/// the server has the vault file) and `error` (why the connection failed, `null` if it worked).
#[tauri::command]
pub async fn server_link_check(link: String) -> Res<Value> {
    blocking(move || {
        let parsed = parse(&link)?;
        let mut info = describe(&parsed);
        match imp::exists(&parsed) {
            Ok(exists) => {
                info["exists"] = json!(exists);
                info["error"] = Value::Null;
            }
            Err(e) => {
                info["exists"] = Value::Null;
                info["error"] = json!(e);
            }
        }
        Ok(info)
    })
    .await
}

/// Opens an image (a screenshot or photo of the pairing QR code) and returns the link in it, `None` if cancelled.
#[tauri::command]
pub async fn server_qr_from_file(app: AppHandle) -> Res<Option<String>> {
    blocking(move || {
        let mut dialog = app
            .dialog()
            .file()
            .set_title(tr!("dialog.qr_picture_title"))
            .add_filter(tr!("dialog.images_filter"), &["png", "jpg", "jpeg"]);
        if let Some(main) = app.get_webview_window("main") {
            dialog = dialog.set_parent(&main);
        }
        let Some(path) = dialog.blocking_pick_file().and_then(|p| p.into_path().ok()) else {
            return Ok(None);
        };
        let size = std::fs::metadata(&path)
            .map_err(crate::errors::file_not_read)?
            .len();
        if size > 50 * 1024 * 1024 {
            return Err(tr!("errors.image_too_large"));
        }
        let data = std::fs::read(&path).map_err(crate::errors::file_not_read)?;
        pick_link(pass_core::qr_decode_image(&data).map_err(qr_error)?).map(Some)
    })
    .await
}

/// Reads the pairing QR code from an image on the clipboard (e.g. a Win+Shift+S snip).
#[tauri::command]
pub async fn server_qr_from_clipboard() -> Res<String> {
    blocking(move || {
        let image = arboard::Clipboard::new()
            .and_then(|mut c| c.get_image())
            .map_err(|_| tr!("errors.no_clipboard_picture"))?;
        let (w, h) = (image.width as u32, image.height as u32);
        pick_link(pass_core::qr_decode_rgba(w, h, &image.bytes).map_err(qr_error)?)
    })
    .await
}

/// Vault list → Add existing vault → From Passyble Server. With `create`, the server must not have
/// the vault yet: a new vault is created at `path` and uploaded. Otherwise the server's vault is
/// downloaded to `path` and unlocked with `password` (its master password).
#[tauri::command]
pub async fn setup_server_connect(
    app: AppHandle,
    link: String,
    create: bool,
    path: String,
    password: String,
    name: Option<String>,
) -> Res<Value> {
    blocking(move || imp::setup(&app, &parse(&link)?, create, &path, &password, name)).await
}

/// Settings → This vault → Use Passyble Server: syncs the unlocked vault with the server and keeps the
/// account. `{ "connected": true, ... }`, or `{ "different_vault": true }` (nothing saved) when the
/// server holds another vault, which the user can add from the vault list instead.
#[tauri::command]
pub async fn server_use_for_vault(app: AppHandle, link: String) -> Res<Value> {
    blocking(move || imp::use_for_vault(&app, &parse(&link)?)).await
}

/// The link the browser extension sent with `server.pair`, if any (taken once).
#[tauri::command]
pub fn server_pair_take(app: AppHandle) -> Option<String> {
    lock(&app_state(&app).server_pair).take()
}

#[cfg(feature = "webdav")]
mod imp {
    use crate::i18n::tr;
    use pass_core::{PairingLink, PassError};
    use serde_json::{json, Value};
    use tauri::{AppHandle, Emitter};

    use super::Res;
    use crate::commands::{
        after_password_unlock, app_state, check_new_master_password, normalize_vault_path, pass_err,
        prepare_agent, restore_from_remote,
    };
    use crate::settings::{self, WebDavSettings};
    use crate::state::{lock, webdav_config};
    use crate::vaults;

    fn settings_for(link: &PairingLink) -> WebDavSettings {
        WebDavSettings {
            url: link.url.clone(),
            username: link.username.clone(),
            pins: link.pins.clone(),
            server_device: Some(link.device_name.clone().unwrap_or_default()),
        }
    }

    fn connect_err(e: PassError) -> String {
        match e {
            PassError::CertificateChanged(_) => tr!("errors.certificate_pairing_mismatch"),
            PassError::Network(m) if crate::errors::is_auth_failure(&m) => {
                tr!("errors.token_rejected")
            }
            other => pass_err(other),
        }
    }

    pub fn exists(link: &PairingLink) -> Res<bool> {
        pass_core::webdav_exists(link.webdav_config()).map_err(connect_err)
    }

    pub fn setup(
        app: &AppHandle,
        link: &PairingLink,
        create: bool,
        path: &str,
        password: &str,
        name: Option<String>,
    ) -> Res<Value> {
        let exists = exists(link)?;
        let webdav = settings_for(link);
        if exists {
            if create {
                return Err(tr!("errors.server_has_vault_now"));
            }
            return restore_from_remote(app, webdav, link.token.clone(), path, password, name);
        }
        if !create {
            return Err(tr!("errors.server_no_vault_yet"));
        }
        let names = [name.clone().unwrap_or_default(), link.username.clone()];
        check_new_master_password(&app_state(app), password, &names, false)?;
        let path = normalize_vault_path(path)?;
        if path.exists() {
            return Err(tr!("errors.file_exists_choose"));
        }
        let (agent, id) = prepare_agent(app, path, name, Some((webdav, link.token.clone())))?;
        agent.create_vault(password).map_err(pass_err)?;
        let mut result = after_password_unlock(&app_state(app), &agent, &id);
        // Upload now, so a failure shows up here rather than in the background sync.
        if let Err(e) = agent.sync() {
            result["warning"] = json!(tr!("warnings.not_uploaded_yet", error = connect_err(e)));
        }
        Ok(result)
    }

    pub fn use_for_vault(app: &AppHandle, link: &PairingLink) -> Res<Value> {
        let state = app_state(app);
        let agent = state.require_agent()?;
        let vault = state.vault()?;
        let id = vaults::active_id(&state)?;
        agent.save().map_err(pass_err)?;
        let result = match pass_core::webdav_sync(vault, link.webdav_config()) {
            Ok(r) => r,
            Err(PassError::Conflict(m))
                if crate::errors::core_says(&m, "vault.different_vault") =>
            {
                return Ok(json!({ "different_vault": true }))
            }
            Err(PassError::Crypto(_)) => return Ok(json!({ "different_vault": true })),
            Err(e) => return Err(connect_err(e)),
        };
        agent.save().map_err(pass_err)?;

        let webdav = settings_for(link);
        let previous = state.settings().vault(&id).and_then(|v| v.webdav.clone());
        // The old account's password first: the credential is named after URL and user, so
        // pairing the same account again (new token) reuses the entry.
        if let Some(previous) = previous.as_ref().filter(|w| **w != webdav) {
            settings::delete_webdav_password(&id, previous, true);
        }
        settings::set_webdav_password(&id, &webdav, &link.token)?;
        state.update_settings(|s| {
            s.vault_mut(&id)
                .ok_or_else(|| tr!("errors.vault_not_listed"))?
                .webdav = Some(webdav.clone());
            Ok(())
        })?;
        agent.set_webdav(webdav_config(&state.settings()));
        let status = {
            let mut sync = lock(&state.sync);
            sync.record_success(vaults::now_ms(), result.remote_bytes);
            sync.running = false;
            sync.clone()
        };
        let _ = app.emit("sync-status", status);
        let stats = result.stats;
        if stats.added + stats.updated + stats.deleted > 0 {
            let _ = app.emit("vault-changed", ());
        }
        Ok(json!({
            "connected": true,
            "created_remote": result.created_remote,
            "uploaded": result.uploaded,
            "added": stats.added,
            "updated": stats.updated,
            "deleted": stats.deleted,
        }))
    }
}

#[cfg(not(feature = "webdav"))]
mod imp {
    use pass_core::PairingLink;
    use serde_json::Value;
    use tauri::AppHandle;

    use super::Res;

    fn no_webdav() -> String {
        crate::i18n::tr!("errors.no_sync_build")
    }

    pub fn exists(_link: &PairingLink) -> Res<bool> {
        Err(no_webdav())
    }

    pub fn setup(
        _app: &AppHandle,
        _link: &PairingLink,
        _create: bool,
        _path: &str,
        _password: &str,
        _name: Option<String>,
    ) -> Res<Value> {
        Err(no_webdav())
    }

    pub fn use_for_vault(_app: &AppHandle, _link: &PairingLink) -> Res<Value> {
        Err(no_webdav())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn links_and_qr_texts() {
        let link = parse(
            "  pass+server://h:8443/dav/a/p.vault?v=1&user=a&token=pst_t&name=PC&pin=sha256:x \n",
        )
        .unwrap();
        let info = describe(&link);
        assert_eq!(info["host"], "h:8443");
        assert_eq!(info["device_name"], "PC");
        assert_eq!(info["pinned"], true);
        assert!(!info.to_string().contains("pst_t"));
        assert!(parse("").is_err());
        assert_eq!(
            parse("https://h/x").unwrap_err(),
            "This isn't a Passyble Server link."
        );
        assert_eq!(
            pick_link(vec!["otpauth://x".into(), " pass+server://h/x ".into()]).unwrap(),
            "pass+server://h/x"
        );
        assert!(pick_link(vec!["https://example.com".into()]).is_err());
    }
}
