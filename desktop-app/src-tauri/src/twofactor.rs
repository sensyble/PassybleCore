//! Settings → Passyble Server (`ui/views/twofactor.js`): two-factor sign-in for the account and its recent security
//! activity.
//!
//! * **Turn on**: the account password → `server_2fa_setup` returns the authenticator secret, its `otpauth://` URI and
//!   that URI as a QR code (drawn here with the `qrcode` crate as one SVG path, so the URI never goes to a web service)
//!   → the first code → `server_2fa_confirm` turns it on and returns the 10 recovery codes, shown once. Nothing of this
//!   is stored on the PC.
//! * **Turn off** (`server_2fa_disable`): the account password and a current code (or a recovery code).
//!
//! Every call uses this device's token for the active Passyble Server vault; a refused token puts the vault into the
//! "signed out" state (`devices.rs`).

use serde_json::Value;
use tauri::AppHandle;

use crate::commands::blocking;
use crate::i18n::tr;

type Res<T> = Result<T, String>;

/// `{ signed_out: true }`, or `{ enabled, pending, enabled_at, recovery_codes_left, available }`.
#[tauri::command]
pub async fn server_2fa_status(app: AppHandle) -> Res<Value> {
    blocking(move || imp::status(&app)).await
}

/// Starts turning on two-factor sign-in with the account `password`: `{ secret, secret_groups,
/// otpauth_uri, issuer, account, digits, period, qr: { size, path } }`.
#[tauri::command]
pub async fn server_2fa_setup(app: AppHandle, password: String) -> Res<Value> {
    blocking(move || imp::setup(&app, password)).await
}

/// Turns it on with the first `code` from the authenticator: `{ recovery_codes: [10 codes] }`.
#[tauri::command]
pub async fn server_2fa_confirm(app: AppHandle, code: String) -> Res<Value> {
    blocking(move || imp::confirm(&app, code)).await
}

#[tauri::command]
pub async fn server_2fa_disable(app: AppHandle, password: String, code: String) -> Res<()> {
    blocking(move || imp::disable(&app, password, code)).await
}

/// Saves the recovery codes the window just showed to a text file the user picks. `None` if the
/// dialog was cancelled, else the path.
#[tauri::command]
pub async fn server_2fa_save_codes(app: AppHandle, codes: Vec<String>) -> Res<Option<String>> {
    blocking(move || imp::save_codes(&app, codes)).await
}

/// The account's newest security events (at most `limit`, newest first): `{ signed_out: true }`
/// or `{ events: [{ at, event, actor, device_id, device_name, ip, detail, count, current }] }`.
#[tauri::command]
pub async fn server_security_events(app: AppHandle, limit: Option<u32>) -> Res<Value> {
    blocking(move || imp::events(&app, limit.unwrap_or(50))).await
}

/// The app's language for Passyble Server, sent as `Accept-Language` with every request (e-mails and pages of new
/// accounts, invite and reset links use it). `account_too` (the user just changed it): also stored for the active
/// account, in the background; errors are ignored (older servers don't have it).
pub fn server_language(app: &AppHandle, language: &str, account_too: bool) {
    imp::server_language(app, language, account_too);
}

/// The QR code of `text` as a module grid: `(side, path)`, where `path` draws every dark module as a unit square
/// (SVG path data) inside a 4-module quiet zone, for a `viewBox="0 0 side side"`.
pub fn qr_path(text: &str) -> Res<(usize, String)> {
    let code = qrcode::QrCode::with_error_correction_level(text.as_bytes(), qrcode::EcLevel::M)
        .map_err(|e| crate::errors::logged(tr!("errors.qr_code"), "QR code", e))?;
    let width = code.width();
    let quiet = 4;
    let mut path = String::new();
    for (i, c) in code.to_colors().iter().enumerate() {
        if *c == qrcode::Color::Dark {
            let (x, y) = (i % width + quiet, i / width + quiet);
            path.push_str(&format!("M{x} {y}h1v1h-1z"));
        }
    }
    Ok((width + 2 * quiet, path))
}

pub fn groups_of_four(secret: &str) -> String {
    let clean: Vec<char> = secret.chars().filter(|c| !c.is_whitespace()).collect();
    clean
        .chunks(4)
        .map(|c| c.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(feature = "webdav")]
mod imp {
    use crate::i18n::tr;
    use pass_core::PassError;
    use serde_json::{json, Value};
    use tauri::{AppHandle, Manager};
    use tauri_plugin_dialog::DialogExt;

    use super::{groups_of_four, qr_path, Res};
    use crate::devices::{clear_signed_out, is_signed_out, mark_signed_out, signed_out_text};
    use crate::signin::imp::{active_server, err};

    struct Account {
        user: String,
        token: String,
        base: String,
        pins: Vec<String>,
    }

    fn account(app: &AppHandle) -> Res<Option<Account>> {
        let (_, webdav, token, base) = active_server(app)?;
        let Some(token) = token else {
            mark_signed_out(app);
            return Ok(None);
        };
        Ok(Some(Account {
            user: webdav.username.clone(),
            token,
            base,
            pins: webdav.pins.clone(),
        }))
    }

    fn require(app: &AppHandle) -> Res<Account> {
        account(app)?.ok_or_else(signed_out_text)
    }

    pub fn server_language(app: &AppHandle, language: &str, account_too: bool) {
        pass_core::set_server_language(Some(language.to_string()));
        if !account_too {
            return;
        }
        let app = app.clone();
        let language = language.to_string();
        std::thread::spawn(move || {
            // Not a Passyble Server vault, or signed out: nothing to tell.
            let Ok((_, webdav, Some(token), base)) = active_server(&app) else {
                return;
            };
            if let Err(e) = pass_core::server_set_language(
                base,
                webdav.username.clone(),
                token,
                Some(language),
                webdav.pins.clone(),
            ) {
                crate::applog::plog!("server language: {e}");
            }
        });
    }

    fn message(app: &AppHandle, e: PassError) -> String {
        if is_signed_out(&e) {
            mark_signed_out(app);
            return signed_out_text();
        }
        match e {
            PassError::InvalidPassword => tr!("errors.not_server_password_caps"),
            PassError::Conflict(m) => crate::errors::sentence(&m),
            // The core's own "update Passyble Server" and "choose a new password" texts (any
            // language; see `errors::core_says`).
            PassError::Network(m)
                if crate::errors::core_says(&m, "server.unsupported.two_factor")
                    || crate::errors::core_says(&m, "server.no_security_events") =>
            {
                crate::errors::sentence(&m)
            }
            PassError::Network(m) if crate::errors::password_change_required(&m).is_some() => {
                crate::errors::password_change_required(&m).unwrap_or(m)
            }
            other => err(other),
        }
    }

    pub fn status(app: &AppHandle) -> Res<Value> {
        let Some(a) = account(app)? else {
            return Ok(json!({ "signed_out": true }));
        };
        let s = pass_core::server_two_factor_status(a.base, a.user, a.token, a.pins)
            .map_err(|e| message(app, e))?;
        clear_signed_out(app);
        Ok(json!({
            "signed_out": false,
            "enabled": s.enabled,
            "pending": s.pending,
            "enabled_at": s.enabled_at,
            "recovery_codes_left": s.recovery_codes_left,
            "available": s.available,
        }))
    }

    pub fn setup(app: &AppHandle, password: String) -> Res<Value> {
        if password.is_empty() {
            return Err(tr!("errors.enter_server_password"));
        }
        let a = require(app)?;
        let s = pass_core::server_two_factor_setup(a.base, a.user, a.token, password, a.pins)
            .map_err(|e| message(app, e))?;
        let (size, path) = qr_path(&s.otpauth_uri)?;
        Ok(json!({
            "secret": s.secret,
            "secret_groups": groups_of_four(&s.secret),
            "otpauth_uri": s.otpauth_uri,
            "issuer": s.issuer,
            "account": s.account,
            "digits": s.digits,
            "period": s.period,
            "qr": { "size": size, "path": path },
        }))
    }

    pub fn confirm(app: &AppHandle, code: String) -> Res<Value> {
        let a = require(app)?;
        let codes = pass_core::server_two_factor_confirm(a.base, a.user, a.token, code, a.pins)
            .map_err(|e| message(app, e))?;
        Ok(json!({ "recovery_codes": codes }))
    }

    pub fn disable(app: &AppHandle, password: String, code: String) -> Res<()> {
        if password.is_empty() {
            return Err(tr!("errors.enter_server_password"));
        }
        let a = require(app)?;
        pass_core::server_two_factor_disable(a.base, a.user, a.token, password, code, a.pins)
            .map_err(|e| message(app, e))
    }

    pub fn save_codes(app: &AppHandle, codes: Vec<String>) -> Res<Option<String>> {
        let codes: Vec<String> = codes
            .iter()
            .map(|c| c.trim().to_string())
            .filter(|c| !c.is_empty())
            .collect();
        if codes.is_empty() {
            return Err(tr!("errors.no_codes_to_save"));
        }
        let (_, webdav, _, _) = active_server(app)?;
        let host = webdav.host();
        let mut dialog = app
            .dialog()
            .file()
            .set_title(tr!("twofactor.codes_title"))
            .set_file_name(format!("passyble-recovery-codes-{host}.txt").replace(':', "-"))
            .add_filter(tr!("dialog.text_filter"), &["txt"]);
        if let Some(main) = app.get_webview_window("main") {
            dialog = dialog.set_parent(&main);
        }
        let Some(path) = dialog.blocking_save_file().and_then(|p| p.into_path().ok()) else {
            return Ok(None);
        };
        let text = format!(
            "{}\r\n{}\r\n{}\r\n\r\n{}\r\n\r\n{}\r\n",
            tr!("twofactor.file_title"),
            tr!(
                "twofactor.file_account",
                user = webdav.username,
                host = host
            ),
            tr!("twofactor.file_saved", date = crate::export::today()),
            tr!("twofactor.file_text"),
            codes.join("\r\n"),
        );
        std::fs::write(&path, text).map_err(crate::errors::file_not_saved)?;
        Ok(Some(path.to_string_lossy().into_owned()))
    }

    pub fn events(app: &AppHandle, limit: u32) -> Res<Value> {
        let Some(a) = account(app)? else {
            return Ok(json!({ "signed_out": true }));
        };
        let events =
            pass_core::server_security_events(a.base, a.user, a.token, limit.min(200), a.pins)
                .map_err(|e| message(app, e))?;
        clear_signed_out(app);
        Ok(json!({
            "signed_out": false,
            "events": events
                .into_iter()
                .map(|e| json!({
                    "at": e.at,
                    "event": e.event,
                    "actor": e.actor,
                    "device_id": e.device_id,
                    "device_name": e.device_name,
                    "ip": e.ip,
                    "detail": e.detail,
                    "count": e.count,
                    "current": e.current,
                }))
                .collect::<Vec<_>>(),
        }))
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

    pub fn status(_: &AppHandle) -> Res<Value> {
        Err(no_webdav())
    }
    pub fn setup(_: &AppHandle, _: String) -> Res<Value> {
        Err(no_webdav())
    }
    pub fn confirm(_: &AppHandle, _: String) -> Res<Value> {
        Err(no_webdav())
    }
    pub fn disable(_: &AppHandle, _: String, _: String) -> Res<()> {
        Err(no_webdav())
    }
    pub fn save_codes(_: &AppHandle, _: Vec<String>) -> Res<Option<String>> {
        Err(no_webdav())
    }
    pub fn events(_: &AppHandle, _: u32) -> Res<Value> {
        Err(no_webdav())
    }
    pub fn server_language(_: &AppHandle, _: &str, _: bool) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qr_codes_are_square_grids_with_a_quiet_zone() {
        let (size, path) =
            qr_path("otpauth://totp/Passyble:alice?secret=JBSWY3DPEHPK3PXP&issuer=Passyble")
                .unwrap();
        // Version 4+ at level M for this length: 33+ modules, plus 2 × 4 quiet modules.
        assert!(size >= 33 + 8, "{size}");
        assert!(path.starts_with('M') && path.ends_with('z'));
        // Nothing is drawn in the quiet zone: the top-left finder starts at (4, 4).
        assert!(path.starts_with("M4 4h1v1h-1z"));
        assert!(!path.contains("M0 ") && !path.contains("M3 "));
    }

    #[test]
    fn secrets_in_groups_of_four() {
        assert_eq!(groups_of_four("JBSWY3DPEHPK3PXP"), "JBSW Y3DP EHPK 3PXP");
        assert_eq!(groups_of_four("ABCDEF"), "ABCD EF");
        assert_eq!(groups_of_four(""), "");
    }
}
