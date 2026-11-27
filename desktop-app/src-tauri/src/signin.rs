//! "Sign in to Passyble Server": one password for the server account and the vault
//! (docs/PROTOCOL.md §3.4). The local copy of a server vault is a cache at
//! `%LOCALAPPDATA%\Pass\vaults\<vault id>.vault`, listed as `<user>@<host>`.
//!
//! Each step is a command, so the UI can ask for more between them; the device token stays in Rust,
//! in [`PENDING`], until the vault is set up.
//!
//! A password change goes to the server first, then re-wraps the vault: if the upload fails
//! afterwards, another device signing in is asked for the previous vault password and repairs it,
//! whereas a vault re-wrapped before a failed server change would match no password the server
//! accepts.
//!
//! Invite and reset links (docs/PROTOCOL.md §3.5) set the password with a one-time code. The server
//! can't re-encrypt the vault, so after a reset this PC re-wraps an unlocked or Windows Hello copy,
//! else asks for the previous password, else replaces the vault with a new empty one (the server
//! keeps the old file as a version; local copies stay as plain local vaults).
//!
//! Two-factor sign-in (docs/PROTOCOL.md §3.7): commands that need a code take an optional `otp` and
//! answer `{step: "two_factor", invalid}` until it is right.

use std::sync::Mutex;

use pass_core::ServerSession;
use serde_json::{json, Value};
use tauri::AppHandle;

use crate::commands::blocking;
use crate::i18n::tr;

type Res<T> = Result<T, String>;

/// The signed-in session between the steps of the sign-in flow.
static PENDING: Mutex<Option<ServerSession>> = Mutex::new(None);

fn pending() -> std::sync::MutexGuard<'static, Option<ServerSession>> {
    PENDING.lock().unwrap_or_else(|p| p.into_inner())
}

/// The server's base URL from a vault file URL (`https://h:8443/dav/alice/personal.vault` →
/// `https://h:8443`), keeping a reverse-proxy prefix.
pub fn server_base(vault_url: &str) -> Option<String> {
    vault_url.rfind("/dav/").map(|i| vault_url[..i].to_string())
}

/// "Pass on <computer name>".
fn device_name() -> String {
    match std::env::var("COMPUTERNAME") {
        Ok(name) if !name.trim().is_empty() => tr!("signin.device_name", computer = name.trim()),
        _ => tr!("signin.device_name_default"),
    }
}

/// What the sign-in form needs from a pasted or scanned `pass+server://` link. Pairing links (with
/// a token) are reported as such: the form hands them to the pairing flow.
#[tauri::command]
pub fn server_signin_link(link: String) -> Res<Value> {
    let link = link.trim();
    let parsed = pass_core::parse_server_link(link).map_err(|e| match e {
        pass_core::PassError::InvalidInput(m) => {
            let mut chars = m.chars();
            match chars.next() {
                Some(c) => format!("{}{}.", c.to_uppercase(), chars.as_str()),
                None => m,
            }
        }
        other => other.to_string(),
    })?;
    // The code itself stays in the link (the UI passes the link back), not in this answer.
    Ok(json!({
        "server_url": parsed.server_url,
        "host": parsed.host,
        "username": parsed.username,
        "pins": parsed.pins,
        "pinned": !parsed.pins.is_empty(),
        "https": parsed.https,
        "pairing": parsed.pairing.is_some(),
        "code_kind": parsed.code_kind,
    }))
}

/// Registers the `pass+server` and `passyble` URL schemes for development runs (installers do it for
/// release builds) and forwards links to the main window. A link only fills in a form; nothing
/// changes until the user confirms there.
pub fn setup_deep_links(app: &AppHandle) {
    use tauri_plugin_deep_link::DeepLinkExt;
    // Linux registers at every start, release builds too: the .deb's and .rpm's own menu entry
    // starts `Pass` without the link (no `%u`), and an AppImage has no installer at all. The
    // plugin writes ~/.local/share/applications/Pass-handler.desktop with the running executable
    // (the `.AppImage` file for an AppImage) and makes it the default, only rewriting what changed.
    #[cfg(any(all(debug_assertions, windows), target_os = "linux"))]
    if let Err(e) = app.deep_link().register_all() {
        crate::applog::plog!("registering the pass+server:// and passyble:// schemes: {e}");
    }
    // Linux: when Passyble already opens otpauth links (the user claimed them in Settings), point
    // the handler at this executable again, so a moved AppImage keeps working.
    #[cfg(target_os = "linux")]
    crate::otpauth_handler::refresh(app);
    let handle = app.clone();
    app.deep_link().on_open_url(move |event| {
        for url in event.urls() {
            open_link(&handle, url.as_str());
        }
    });
    if let Ok(Some(urls)) = app.deep_link().get_current() {
        for url in urls {
            open_link(app, url.as_str());
        }
    }
}

/// Hands a `pass+server://` link to the main window, like a link from the browser extension, and a
/// `passyble://support` link to Help and support (support.rs).
fn open_link(app: &AppHandle, link: &str) {
    use tauri::Emitter;
    if crate::support::open_link(app, link) {
        return;
    }
    if !link.starts_with("pass+server://") {
        return;
    }
    *crate::state::lock(&crate::commands::app_state(app).server_pair) = Some(link.to_string());
    let _ = app.emit_to("main", "server-pair-requested", ());
    crate::popups::show_main(app);
}

/// An invite or reset link: sets `new_password` with its one-time code, signs in and sets up the
/// vault. `{step: "done" | "previous_password" | "unlock_local", ...}`.
#[tauri::command]
pub async fn server_code_set_password(
    app: AppHandle,
    link: String,
    new_password: String,
    otp: Option<String>,
) -> Res<Value> {
    blocking(move || imp::code_set_password(&app, link, new_password, otp)).await
}

/// After `server_code_set_password` set the password but the sign-in needs a (new) two-factor
/// code: signs in with `password` and `otp`, then sets up the vault as that command would have.
#[tauri::command]
pub async fn server_code_signin(
    app: AppHandle,
    link: String,
    password: String,
    otp: Option<String>,
) -> Res<Value> {
    blocking(move || imp::code_signin(&app, link, password, otp)).await
}

/// After a reset: unlock this PC's copy of the vault with Windows Hello and re-wrap it with the
/// new password.
#[tauri::command]
pub async fn server_reset_hello(app: AppHandle, vault_id: String, password: String) -> Res<Value> {
    blocking(move || imp::reset_hello(&app, vault_id, password)).await
}

/// After a reset, when the old vault can't be decrypted: a new empty vault replaces it on the
/// server (which keeps the old one as a version).
#[tauri::command]
pub async fn server_signin_new_vault(app: AppHandle, password: String) -> Res<Value> {
    blocking(move || imp::new_vault(&app, password)).await
}

/// "Forgot password?" on the sign-in form: asks the server to e-mail a reset link. `{ sent: true }`,
/// or `{ step: "trust", ... }` like `server_signin` for a server whose certificate isn't trusted.
#[tauri::command]
pub async fn server_request_reset(
    server_url: String,
    user_or_email: String,
    pins: Vec<String>,
) -> Res<Value> {
    blocking(move || imp::request_reset(server_url, user_or_email, pins)).await
}

/// Step 1. `{step: "choose_password" | "previous_password" | "done", ...}`, or
/// `{step: "trust", server_url, host, pin}` when the server's certificate isn't publicly trusted
/// and no pin was given: the UI shows the fingerprint ("Trust this server?") and signs in again
/// with `pins: [pin]` once the user confirms (trust on first use, docs/PROTOCOL.md §3.2).
#[tauri::command]
pub async fn server_signin(
    app: AppHandle,
    server_url: String,
    username: String,
    password: String,
    pins: Vec<String>,
    otp: Option<String>,
) -> Res<Value> {
    blocking(move || imp::signin(&app, server_url, username, password, pins, otp)).await
}

/// Step 2: replaces the admin-set password, then sets up the vault with the new one.
#[tauri::command]
pub async fn server_signin_set_password(
    app: AppHandle,
    current: String,
    new_password: String,
    otp: Option<String>,
) -> Res<Value> {
    blocking(move || imp::set_password(&app, current, new_password, otp)).await
}

/// Step 3b: the vault still uses `previous`: unlock with it, re-wrap with `password`, upload.
#[tauri::command]
pub async fn server_signin_previous(
    app: AppHandle,
    previous: String,
    password: String,
) -> Res<Value> {
    blocking(move || imp::previous(&app, previous, password)).await
}

/// Leaves the sign-in flow. The device stays registered on the server (revoke it there).
#[tauri::command]
pub fn server_signin_cancel() {
    *pending() = None;
}

/// Settings → This vault → Change password (a Passyble Server vault, unlocked).
#[tauri::command]
pub async fn server_change_password(
    app: AppHandle,
    current: String,
    new_password: String,
    otp: Option<String>,
) -> Res<Value> {
    blocking(move || imp::change_password(&app, current, new_password, otp)).await
}

/// Settings → This vault → "Changed on another device?": re-wraps the unlocked vault with the
/// account's current password after the server confirms it.
#[tauri::command]
pub async fn server_adopt_password(
    app: AppHandle,
    password: String,
    otp: Option<String>,
) -> Res<Value> {
    blocking(move || imp::adopt_password(&app, password, otp)).await
}

/// Called by `unlock` when the local copy rejects the password: for a Passyble Server vault, tries the
/// server's copy (the password may have been changed on another device). `true` if the vault is
/// now unlocked.
pub fn refresh_from_server(
    app: &AppHandle,
    agent: &pass_agent::Agent,
    vault_id: &str,
    password: &str,
) -> bool {
    imp::refresh_from_server(app, agent, vault_id, password).unwrap_or(false)
}

#[cfg(feature = "webdav")]
pub(crate) mod imp {
    use crate::i18n::tr;
    use std::path::PathBuf;

    use pass_core::{PassError, ServerSession, Vault};
    use serde_json::{json, Value};
    use tauri::AppHandle;

    use super::{device_name, pending, server_base, Res};
    use crate::commands::{
        after_password_unlock, app_state, check_master_password, check_new_master_password,
        pass_err, prepare_agent,
    };
    use crate::devices::{clear_signed_out, is_signed_out, mark_signed_out};
    use crate::errors;
    use crate::settings::{self, WebDavSettings};
    use crate::vaults;

    /// A two-factor answer of the server: `Some(false)` when a code is needed, `Some(true)` when
    /// the code was wrong or already used.
    pub(crate) fn two_factor(e: &PassError) -> Option<bool> {
        match e {
            PassError::InvalidInput(m) if m.starts_with(pass_core::TWO_FACTOR_REQUIRED) => {
                Some(false)
            }
            PassError::InvalidInput(m) if m.starts_with(pass_core::TWO_FACTOR_INVALID) => {
                Some(true)
            }
            _ => None,
        }
    }

    /// What the window gets instead of a two-factor error: ask for the code, call again with it.
    pub(crate) fn two_factor_step(invalid: bool) -> Value {
        json!({ "step": "two_factor", "invalid": invalid })
    }

    pub(crate) fn err(e: PassError) -> String {
        match e {
            PassError::InvalidPassword => tr!("errors.wrong_sign_in"),
            PassError::CertificateChanged(_) => tr!("errors.certificate_link_mismatch"),
            PassError::Crypto(m) if crate::errors::core_says(&m, "server.unsafe_parameters") => {
                tr!("errors.unsafe_parameters", detail = m)
            }
            other => pass_err(other),
        }
    }

    /// The certificate isn't publicly trusted and the user gave no pin (no invite link): the
    /// server's pin, fetched without trusting it, for the "Trust this server?" dialog.
    fn trust_step(server_url: &str) -> Res<Value> {
        let base = pass_core::normalize_server_url(server_url.to_string()).map_err(err)?;
        let pin = pass_core::fetch_server_pin(base.clone()).map_err(err)?;
        let host = WebDavSettings {
            url: base.clone(),
            ..Default::default()
        }
        .host();
        Ok(json!({ "step": "trust", "server_url": base, "host": host, "pin": pin }))
    }

    fn untrusted(e: &PassError, pins: &[String]) -> bool {
        pins.iter().all(|p| p.trim().is_empty())
            && matches!(e, PassError::Network(m) if errors::is_untrusted_certificate(m))
    }

    fn session() -> Res<ServerSession> {
        pending()
            .clone()
            .ok_or_else(|| tr!("errors.sign_in_session_expired"))
    }

    fn webdav_of(s: &ServerSession) -> Res<WebDavSettings> {
        Ok(WebDavSettings {
            url: s.vault_url.clone().ok_or_else(no_vault)?,
            username: s.username.clone(),
            pins: s.pins.clone(),
            server_device: Some(s.device_name.clone()),
        })
    }

    fn no_vault() -> String {
        tr!("errors.no_server_vault")
    }

    /// `%LOCALAPPDATA%\Pass\vaults\<vault id>.vault`.
    fn cache_path(vault_id: &str) -> PathBuf {
        settings::cache_vault_path(vault_id)
    }

    /// `alice@pass.example.com`.
    fn list_name(s: &ServerSession) -> String {
        let host = WebDavSettings {
            url: s.server_url.clone(),
            ..Default::default()
        }
        .host();
        format!("{}@{host}", s.username)
    }

    /// Makes `vault` (already unlocked) a listed vault with the session's account: writes the cache
    /// file, points the agent at it, unlocks and syncs. `password`: the master password the user typed.
    fn install(
        app: &AppHandle,
        s: &ServerSession,
        vault: &Vault,
        upload: bool,
        password: &str,
    ) -> Res<Value> {
        let path = cache_path(&vault.vault_id());
        // Unsynced changes of an earlier sign-in on this PC (same vault) are kept.
        crate::vaults::write_vault_file(&path, vault)?;
        let webdav = webdav_of(s)?;
        let (agent, id) = prepare_agent(
            app,
            path,
            Some(list_name(s)),
            Some((webdav, s.token.clone())),
        )?;
        agent
            .unlock_with_key(vault.export_vault_key())
            .map_err(pass_err)?;
        crate::health::note_master_password_unlock(&app_state(app), &id, password);
        let mut result = after_password_unlock(&app_state(app), &agent, &id);
        *pending() = None;
        // The sign-in form starts with this server and user next time.
        let _ = app_state(app).update_settings(|st| {
            st.last_server_url = Some(s.server_url.clone());
            st.last_server_user = Some(s.username.clone());
            st.last_server_pins = s.pins.clone();
            Ok(())
        });
        if upload {
            // Upload now, so a failure shows up here rather than only in the background sync.
            match agent.sync() {
                Ok(_) => result["uploaded"] = json!(true),
                Err(e) => {
                    result["warning"] = json!(tr!("warnings.ready_not_uploaded", error = err(e)));
                }
            }
        } else {
            app_state(app).kick_sync();
        }
        result["step"] = json!("done");
        Ok(result)
    }

    /// Step 3: create, or download and unlock, the vault with `password`.
    fn vault_step(app: &AppHandle, s: &ServerSession, password: &str) -> Res<Value> {
        let config = s.webdav_config().map_err(|_| no_vault())?;
        let device_id = app_state(app).settings().device_id;
        if !s.vault_exists {
            // A vault created on another device in the meantime is downloaded instead.
            if !pass_core::webdav_exists(config.clone()).map_err(err)? {
                // The account's existing password, just used to sign in: only the old minimum
                // (the master password rule applies where a password is chosen).
                check_master_password(password)?;
                let vault = Vault::create(password.to_string(), device_id).map_err(pass_err)?;
                return install(app, s, &vault, true, password);
            }
        }
        let bytes = pass_core::webdav_download(config).map_err(err)?;
        match Vault::unlock(bytes, password.to_string(), device_id) {
            Ok(vault) => install(app, s, &vault, false, password),
            Err(PassError::InvalidPassword) => Ok(json!({ "step": "previous_password" })),
            Err(e) => Err(pass_err(e)),
        }
    }

    pub fn signin(
        app: &AppHandle,
        server_url: String,
        username: String,
        password: String,
        pins: Vec<String>,
        otp: Option<String>,
    ) -> Res<Value> {
        let s = match pass_core::server_login_2fa(
            server_url.clone(),
            username,
            password.clone(),
            device_name(),
            otp,
            pins.clone(),
        ) {
            Ok(s) => s,
            Err(e) if untrusted(&e, &pins) => return trust_step(&server_url),
            Err(e) => match two_factor(&e) {
                Some(invalid) => return Ok(two_factor_step(invalid)),
                None => return Err(err(e)),
            },
        };
        if s.vault_url.is_none() {
            return Err(no_vault());
        }
        *pending() = Some(s.clone());
        if s.must_change_password {
            return Ok(json!({
                "step": "choose_password",
                "username": s.username,
                "vault_exists": s.vault_exists,
            }));
        }
        vault_step(app, &s, &password)
    }

    pub fn set_password(
        app: &AppHandle,
        current: String,
        new_password: String,
        otp: Option<String>,
    ) -> Res<Value> {
        let mut s = session()?;
        check_new_master_password(&app_state(app), &new_password, &[s.username.clone()], false)?;
        if new_password == current {
            return Err(tr!("errors.choose_different_password"));
        }
        match pass_core::server_change_password_2fa(
            s.server_url.clone(),
            s.username.clone(),
            s.token.clone(),
            current,
            new_password.clone(),
            otp,
            s.pins.clone(),
        ) {
            Ok(()) => {}
            Err(e) => match two_factor(&e) {
                Some(invalid) => return Ok(two_factor_step(invalid)),
                None if matches!(e, PassError::InvalidPassword) => {
                    return Err(tr!("errors.current_password_wrong"))
                }
                None => return Err(err(e)),
            },
        }
        s.must_change_password = false;
        s.password_admin_known = false;
        *pending() = Some(s.clone());
        vault_step(app, &s, &new_password)
    }

    pub fn previous(app: &AppHandle, previous: String, password: String) -> Res<Value> {
        let s = session()?;
        let config = s.webdav_config().map_err(|_| no_vault())?;
        let bytes = pass_core::webdav_download(config).map_err(err)?;
        let device_id = app_state(app).settings().device_id;
        let vault = Vault::unlock(bytes, previous.clone(), device_id).map_err(|e| match e {
            PassError::InvalidPassword => tr!("errors.not_previous_password"),
            other => pass_err(other),
        })?;
        // Every password change gives the vault a new key.
        let password = zeroize::Zeroizing::new(password);
        let before = crate::password_change::before(&vault);
        vault
            .change_password(previous, (*password).clone())
            .map_err(pass_err)?;
        let mut result = install(app, &s, &vault, true, &password)?;
        let uploaded = result["uploaded"] == true;
        let purge = crate::password_change::purge_after_upload(uploaded, || {
            pass_core::server_purge_versions(
                s.server_url.clone(),
                s.username.clone(),
                s.token.clone(),
                s.webdav_config()?.url,
                s.pins.clone(),
            )
        });
        result["purge"] = crate::password_change::purge_json(&purge);
        let state = app_state(app);
        if let (Some(agent), Ok(id)) = (state.agent(), vaults::active_id(&state)) {
            crate::password_change::after_change(app, &agent, &id, &before, &mut result);
        }
        Ok(result)
    }

    /// The active Passyble Server vault's account: (list id, settings, token, server base URL).
    fn active_account(app: &AppHandle) -> Res<(String, WebDavSettings, String, String)> {
        let (id, webdav, token, base) = active_server(app)?;
        let token = token.ok_or_else(|| tr!("errors.token_missing"))?;
        Ok((id, webdav, token, base))
    }

    /// Like [`active_account`], with `None` for a missing token (this device was signed out).
    pub(crate) fn active_server(
        app: &AppHandle,
    ) -> Res<(String, WebDavSettings, Option<String>, String)> {
        let state = app_state(app);
        let id = vaults::active_id(&state)?;
        let webdav = state
            .settings()
            .vault(&id)
            .and_then(|v| v.webdav.clone())
            .filter(|w| w.is_pass_server())
            .ok_or_else(|| tr!("errors.not_server_vault"))?;
        let token = settings::webdav_password(&id, &webdav).filter(|t| !t.is_empty());
        let base =
            server_base(&webdav.url).ok_or_else(|| tr!("errors.unexpected_server_address"))?;
        Ok((id, webdav, token, base))
    }

    /// Keeps `webdav` and its device `token` as the sync account of the listed vault `id` (a new
    /// sign-in): settings, Credential Manager (the old entry goes if its name changes), the agent
    /// if `id` is the active vault, and the sync status leaves "signed out".
    fn keep_account(app: &AppHandle, id: &str, webdav: &WebDavSettings, token: &str) -> Res<()> {
        let state = app_state(app);
        let old = state.settings().vault(id).and_then(|v| v.webdav.clone());
        state.update_settings(|st| {
            st.vault_mut(id)
                .ok_or_else(|| tr!("errors.vault_not_listed"))?
                .webdav = Some(webdav.clone());
            Ok(())
        })?;
        settings::set_webdav_password(id, webdav, token)?;
        if let Some(old) = old.filter(|o| o.url != webdav.url || o.username != webdav.username) {
            settings::delete_webdav_password(id, &old, false);
        }
        let settings = state.settings();
        if settings.active_vault.as_deref() == Some(id) {
            if let Some(agent) = state.agent() {
                agent.set_webdav(crate::state::webdav_config(&settings));
            }
        }
        clear_signed_out(app);
        Ok(())
    }

    pub fn change_password(
        app: &AppHandle,
        current: String,
        new_password: String,
        otp: Option<String>,
    ) -> Res<Value> {
        let state = app_state(app);
        check_new_master_password(&state, &new_password, &[], true)?;
        let agent = state.require_agent()?;
        let vault = state.vault()?;
        let (id, webdav, token, base) = active_account(app)?;
        // 1. The current password must open this vault (nothing changes otherwise).
        if !vault.check_password(current.clone()).map_err(pass_err)? {
            return Err(tr!("errors.current_password_wrong"));
        }
        let account = pass_core::server_account(
            base.clone(),
            webdav.username.clone(),
            token.clone(),
            webdav.pins.clone(),
        )
        .map_err(|e| {
            if is_signed_out(&e) {
                mark_signed_out(app);
            }
            err(e)
        })?;
        // 2. The server sign-in (an account without a password yet sets its first one). With
        //    two-factor sign-in on, the window asks for a code and calls again.
        let changed = pass_core::server_change_password_2fa(
            base.clone(),
            webdav.username.clone(),
            token.clone(),
            if account.has_password {
                current.clone()
            } else {
                String::new()
            },
            new_password.clone(),
            otp,
            webdav.pins.clone(),
        );
        if let Err(e) = changed {
            if let Some(invalid) = two_factor(&e) {
                return Ok(two_factor_step(invalid));
            }
            return Err(match e {
                PassError::InvalidPassword => tr!("errors.server_rejected_current"),
                other => err(other),
            });
        }
        // 3. The vault: a new key under the new password, every item re-encrypted, so the server's old
        //    versions, encrypted under the old key, can go.
        let before = crate::password_change::before(&vault);
        vault
            .change_password(current, new_password)
            .map_err(pass_err)?;
        agent.save().map_err(pass_err)?;
        crate::health::note_master_password_changed(&state, &id);
        let mut result = json!({ "warning": null });
        // Changing an existing password signs out the account's other devices (the server's
        // default; setting the first password of a token-only account signs out nobody).
        result["others_signed_out"] = json!(account.has_password);
        let uploaded = match agent.sync() {
            Ok(_) => true,
            Err(e) => {
                result["warning"] = json!(tr!(
                    "warnings.server_password_changed_not_uploaded",
                    error = err(e)
                ));
                false
            }
        };
        // 4. Only once the new file is there: the server's old versions are dropped.
        let purge = crate::password_change::purge_after_upload(uploaded, || {
            crate::password_change::server_purge(&base, &webdav, &token)
        });
        result["purge"] = crate::password_change::purge_json(&purge);
        crate::password_change::after_change(app, &agent, &id, &before, &mut result);
        Ok(result)
    }

    pub fn adopt_password(app: &AppHandle, password: String, otp: Option<String>) -> Res<Value> {
        let state = app_state(app);
        let agent = state.require_agent()?;
        let vault = state.vault()?;
        let (id, webdav, token, base) = active_server(app)?;
        let wrong = || tr!("errors.not_server_password");
        // The server decides whether it is the account's password. A password change elsewhere
        // signed this device out (or it was signed out from a device list, or its token is gone):
        // then signing in with the password both proves it and gives this device a new token.
        let verified = match token {
            Some(token) => match pass_core::server_verify_password(
                base.clone(),
                webdav.username.clone(),
                token,
                password.clone(),
                webdav.pins.clone(),
            ) {
                Ok(ok) => Some(ok),
                Err(e) if is_signed_out(&e) => None,
                Err(e) => return Err(err(e)),
            },
            None => None,
        };
        let signed_in = match verified {
            Some(true) => false,
            Some(false) => return Err(wrong()),
            None => {
                let s = match pass_core::server_login_2fa(
                    base,
                    webdav.username.clone(),
                    password.clone(),
                    device_name(),
                    otp,
                    webdav.pins.clone(),
                ) {
                    Ok(s) => s,
                    Err(e) => match two_factor(&e) {
                        Some(invalid) => return Ok(two_factor_step(invalid)),
                        None if matches!(e, PassError::InvalidPassword) => return Err(wrong()),
                        None => return Err(err(e)),
                    },
                };
                if s.must_change_password {
                    // An admin-set password: the vault must not be re-wrapped with it.
                    return Err(tr!("errors.temporary_password"));
                }
                // Same vault file; the account's real name and this sign-in's device name.
                let account = WebDavSettings {
                    username: s.username.clone(),
                    server_device: Some(s.device_name.clone()),
                    ..webdav.clone()
                };
                keep_account(app, &id, &account, &s.token)?;
                true
            }
        };
        let unchanged = vault.check_password(password.clone()).map_err(pass_err)?;
        // The account's password, typed here and accepted by the server: the vault's master
        // password from now on (Password health's master password tip).
        crate::health::note_master_password_unlock(&state, &id, &password);
        if unchanged && !signed_in {
            // The server accepted the token, so this device isn't signed out (any more).
            clear_signed_out(app);
            return Ok(json!({ "unchanged": true }));
        }
        // Changed on another device: that device gave the vault a new key, so the server's copy
        // opens with the password and this PC's copy is merged into it. Only when it doesn't (the
        // server's copy still has the old password) is the vault given a new key here.
        let mut refreshed = false;
        let mut before = None;
        if !unchanged {
            agent.save().map_err(pass_err)?;
            refreshed = refresh_from_server(app, &agent, &id, &password).unwrap_or(false);
            if !refreshed {
                before = Some(crate::password_change::before(&vault));
                vault.change_master_password(password).map_err(pass_err)?;
                agent.save().map_err(pass_err)?;
            }
        }
        let mut result = json!({ "warning": null, "unchanged": unchanged, "signed_in": signed_in, "refreshed": refreshed });
        // Through the scheduler's sync, so the vault view's sync state follows.
        let synced = crate::background::sync_now(app);
        if let Err(e) = &synced {
            result["warning"] = json!(if unchanged {
                tr!("warnings.signed_in_not_synced", error = e)
            } else {
                tr!("warnings.new_password_not_uploaded", error = e)
            });
        }
        if let Some(before) = before {
            // The vault got a new key here: the server's old versions go once it is uploaded.
            let purge = crate::password_change::purge_after_upload(synced.is_ok(), || {
                let (_, webdav, token, base) = active_account(app).map_err(PassError::Network)?;
                crate::password_change::server_purge(&base, &webdav, &token)
            });
            result["purge"] = crate::password_change::purge_json(&purge);
            crate::password_change::after_change(app, &agent, &id, &before, &mut result);
        }
        Ok(result)
    }

    fn expired_link() -> String {
        tr!("errors.link_expired")
    }

    pub fn code_set_password(
        app: &AppHandle,
        link: String,
        new_password: String,
        otp: Option<String>,
    ) -> Res<Value> {
        let parsed = pass_core::parse_server_link(link.trim()).map_err(err)?;
        let (Some(code), Some(_)) = (parsed.code.clone(), parsed.code_kind.clone()) else {
            return Err(tr!("errors.link_no_code"));
        };
        check_new_master_password(&app_state(app), &new_password, &[parsed.username.clone()], false)?;
        // With two-factor sign-in on, the link alone isn't enough: a code too (the link's own
        // code is only used up when this succeeds).
        if let Err(e) = pass_core::server_set_password_with_code_2fa(
            parsed.server_url.clone(),
            parsed.username.clone(),
            code,
            new_password.clone(),
            otp,
            parsed.pins.clone(),
        ) {
            if let Some(invalid) = two_factor(&e) {
                return Ok(two_factor_step(invalid));
            }
            return Err(match e {
                PassError::InvalidPassword => expired_link(),
                other => err(other),
            });
        }
        // A reset signed out every device, this one included: sign in with the new password.
        // The code above is used up, so an account with two-factor sign-in needs the next one.
        code_signin(app, link, new_password, None)
    }

    /// Signs in after a link's password was set, then sets up the vault (invite) or re-wraps it
    /// (reset). `{step: "two_factor", password_set: true}` while a two-factor code is needed.
    pub fn code_signin(
        app: &AppHandle,
        link: String,
        new_password: String,
        otp: Option<String>,
    ) -> Res<Value> {
        let parsed = pass_core::parse_server_link(link.trim()).map_err(err)?;
        let Some(kind) = parsed.code_kind.clone() else {
            return Err(tr!("errors.link_no_code"));
        };
        let s = match pass_core::server_login_2fa(
            parsed.server_url,
            parsed.username,
            new_password.clone(),
            device_name(),
            otp,
            parsed.pins,
        ) {
            Ok(s) => s,
            Err(e) => match two_factor(&e) {
                Some(invalid) => {
                    let mut step = two_factor_step(invalid);
                    step["password_set"] = json!(true);
                    return Ok(step);
                }
                None => return Err(err(e)),
            },
        };
        if s.vault_url.is_none() {
            return Err(tr!("errors.password_set_no_vault", reason = no_vault()));
        }
        *pending() = Some(s.clone());
        if kind == "reset" {
            reset_vault_step(app, &s, &new_password)
        } else {
            vault_step(app, &s, &new_password)
        }
    }

    /// The vault list entries that sync with the session's account and vault.
    fn local_entries(app: &AppHandle, s: &ServerSession) -> Vec<settings::VaultEntry> {
        let url = s.vault_url.as_deref();
        app_state(app)
            .settings()
            .vaults
            .into_iter()
            .filter(|v| {
                v.webdav
                    .as_ref()
                    .is_some_and(|w| Some(w.url.as_str()) == url && w.username == s.username)
            })
            .collect()
    }

    /// After a reset: re-wrap a local copy (unlocked here, or with Windows Hello), else the
    /// server's copy.
    fn reset_vault_step(app: &AppHandle, s: &ServerSession, password: &str) -> Res<Value> {
        let state = app_state(app);
        let entries = local_entries(app, s);
        let active = state.settings().active_vault;
        let unlocked = state.agent().is_some_and(|a| !a.is_locked());
        if let Some(entry) = entries
            .iter()
            .find(|e| unlocked && active.as_deref() == Some(e.id.as_str()))
        {
            return rewrap_local(app, s, &entry.id, password);
        }
        if let Some(entry) = entries
            .iter()
            .find(|e| e.windows_hello && crate::hello::enrolled(&e.id))
        {
            return Ok(json!({
                "step": "unlock_local",
                "vault_id": entry.id,
                "vault_name": entry.name,
                "hello": true,
            }));
        }
        let mut result = vault_step(app, s, password)?;
        result["reset"] = json!(true);
        Ok(result)
    }

    /// The account's vault is unlocked here (the active vault): re-wrap it with the new password
    /// (no old password needed), keep the new device token, save and upload.
    fn rewrap_local(app: &AppHandle, s: &ServerSession, id: &str, password: &str) -> Res<Value> {
        let state = app_state(app);
        let agent = state.require_agent()?;
        let vault = agent.vault().ok_or(crate::state::VAULT_LOCKED)?;
        let before = crate::password_change::before(&vault);
        vault
            .change_master_password(password.to_string())
            .map_err(pass_err)?;
        keep_account(app, id, &webdav_of(s)?, &s.token)?;
        agent.save().map_err(pass_err)?;
        // Changed here; the tip still follows the password itself, which came with the link.
        crate::health::note_master_password_changed(&state, id);
        crate::health::note_master_password_unlock(&state, id, password);
        *pending() = None;
        let mut result = json!({ "step": "done", "warning": null, "rewrapped": true });
        let uploaded = match agent.sync() {
            Ok(_) => true,
            Err(e) => {
                result["warning"] = json!(tr!(
                    "warnings.your_new_password_not_uploaded",
                    error = err(e)
                ));
                false
            }
        };
        // The vault has a new key now: the server's old versions go once it is uploaded.
        let purge = crate::password_change::purge_after_upload(uploaded, || {
            pass_core::server_purge_versions(
                s.server_url.clone(),
                s.username.clone(),
                s.token.clone(),
                s.webdav_config()?.url,
                s.pins.clone(),
            )
        });
        result["purge"] = crate::password_change::purge_json(&purge);
        crate::password_change::after_change(app, &agent, id, &before, &mut result);
        Ok(result)
    }

    pub fn reset_hello(app: &AppHandle, vault_id: String, password: String) -> Res<Value> {
        let s = session()?;
        let state = app_state(app);
        let entry = state
            .settings()
            .vault(&vault_id)
            .cloned()
            .ok_or_else(|| tr!("errors.vault_not_listed"))?;
        let agent = vaults::activate(app, &vault_id)?;
        if agent.is_locked() {
            let _hello = state.ui.hello_lock();
            crate::hello::unlock(
                &agent,
                &vault_id,
                state.ui.main_owner(),
                &entry.hello_policy,
            )?;
        }
        vaults::mark_opened(&state, &vault_id);
        rewrap_local(app, &s, &vault_id, &password)
    }

    pub fn new_vault(app: &AppHandle, password: String) -> Res<Value> {
        let s = session()?;
        // The account's password (set with the reset link, which applied the master password
        // rule): only the old minimum here.
        check_master_password(&password)?;
        let config = s.webdav_config().map_err(|_| no_vault())?;
        let old = local_entries(app, &s);
        let device_id = app_state(app).settings().device_id;
        let password = zeroize::Zeroizing::new(password);
        let vault = Vault::create((*password).clone(), device_id).map_err(pass_err)?;
        pass_core::webdav_replace(config, vault.clone()).map_err(err)?;
        let mut result = install(app, &s, &vault, false, &password)?;
        // This PC's copies of the old vault stay, as plain local vaults (no sync): they open
        // again if the old password turns up.
        let state = app_state(app);
        let suffix = tr!("signin.before_reset_suffix");
        for entry in old {
            if let Some(webdav) = &entry.webdav {
                settings::delete_webdav_password(&entry.id, webdav, false);
            }
            let _ = state.update_settings(|st| {
                if let Some(e) = st.vault_mut(&entry.id) {
                    e.webdav = None;
                    // The name is only shown; copies marked by older builds carry the English suffix.
                    if !e.name.ends_with(suffix.as_str()) && !e.name.ends_with("(before reset)") {
                        e.name = format!("{} {suffix}", e.name);
                    }
                }
                Ok(())
            });
        }
        result["new_vault"] = json!(true);
        Ok(result)
    }

    pub fn request_reset(
        server_url: String,
        user_or_email: String,
        pins: Vec<String>,
    ) -> Res<Value> {
        match pass_core::server_request_reset(server_url.clone(), user_or_email, pins.clone()) {
            Ok(()) => Ok(json!({ "sent": true })),
            Err(e) if untrusted(&e, &pins) => trust_step(&server_url),
            Err(PassError::Network(m)) if !m.contains("://") && !m.contains("too many") => {
                // The server's own explanation (no e-mail configured, rate limit).
                let mut c = m.chars();
                Err(match c.next() {
                    Some(f) => format!("{}{}.", f.to_uppercase(), c.as_str()),
                    None => m,
                })
            }
            Err(e) => Err(err(e)),
        }
    }

    pub fn refresh_from_server(
        app: &AppHandle,
        agent: &pass_agent::Agent,
        vault_id: &str,
        password: &str,
    ) -> Res<bool> {
        let state = app_state(app);
        let Some(webdav) = state
            .settings()
            .vault(vault_id)
            .and_then(|v| v.webdav.clone())
            .filter(|w| w.is_pass_server())
        else {
            return Ok(false);
        };
        let token = settings::webdav_password(vault_id, &webdav)
            .ok_or_else(|| tr!("errors.token_missing"))?;
        let config = pass_core::WebDavConfig {
            url: webdav.url.clone(),
            username: webdav.username.clone(),
            password: token,
            pins: webdav.pins.clone(),
        };
        let bytes = pass_core::webdav_download(config).map_err(pass_err)?;
        let vault = Vault::unlock(bytes, password.to_string(), state.settings().device_id)
            .map_err(pass_err)?;
        let path = agent.config().vault_path;
        // Unsynced local changes are kept: same key, or an older key the server's copy
        // remembers; a file it can't merge is kept beside it.
        crate::vaults::write_vault_file(&path, &vault)?;
        agent
            .unlock_with_key(vault.export_vault_key())
            .map_err(pass_err)?;
        // Another device gave the vault a new key with its new password: Windows Hello's copy of
        // the old one opens nothing now.
        crate::password_change::renew_hello(&state, agent, vault_id);
        state.kick_sync();
        Ok(true)
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

    pub fn signin(
        _: &AppHandle,
        _: String,
        _: String,
        _: String,
        _: Vec<String>,
        _: Option<String>,
    ) -> Res<Value> {
        Err(no_webdav())
    }
    pub fn set_password(_: &AppHandle, _: String, _: String, _: Option<String>) -> Res<Value> {
        Err(no_webdav())
    }
    pub fn previous(_: &AppHandle, _: String, _: String) -> Res<Value> {
        Err(no_webdav())
    }
    pub fn change_password(_: &AppHandle, _: String, _: String, _: Option<String>) -> Res<Value> {
        Err(no_webdav())
    }
    pub fn adopt_password(_: &AppHandle, _: String, _: Option<String>) -> Res<Value> {
        Err(no_webdav())
    }
    pub fn code_set_password(_: &AppHandle, _: String, _: String, _: Option<String>) -> Res<Value> {
        Err(no_webdav())
    }
    pub fn code_signin(_: &AppHandle, _: String, _: String, _: Option<String>) -> Res<Value> {
        Err(no_webdav())
    }
    pub fn reset_hello(_: &AppHandle, _: String, _: String) -> Res<Value> {
        Err(no_webdav())
    }
    pub fn new_vault(_: &AppHandle, _: String) -> Res<Value> {
        Err(no_webdav())
    }
    pub fn request_reset(_: String, _: String, _: Vec<String>) -> Res<Value> {
        Err(no_webdav())
    }
    pub fn refresh_from_server(
        _: &AppHandle,
        _: &pass_agent::Agent,
        _: &str,
        _: &str,
    ) -> Res<bool> {
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_urls_and_links() {
        assert_eq!(
            server_base("https://h:8443/dav/alice/personal.vault").as_deref(),
            Some("https://h:8443")
        );
        assert_eq!(
            server_base("https://h/pass/dav/a/b.vault").as_deref(),
            Some("https://h/pass")
        );
        assert_eq!(server_base("https://cloud/remote.php/x.vault"), None);
        let info = server_signin_link(" pass+server://h:8443/?v=1&user=alice&pin=sha256:x ".into())
            .unwrap();
        assert_eq!(info["server_url"], "https://h:8443");
        assert_eq!(info["username"], "alice");
        assert_eq!(info["pairing"], false);
        assert_eq!(info["pinned"], true);
        assert!(info["code_kind"].is_null());
        let reset =
            server_signin_link("pass+server://h/?v=1&user=alice&reset=psc_secret".into()).unwrap();
        assert_eq!(reset["code_kind"], "reset");
        assert!(!reset.to_string().contains("psc_secret"));
        let pairing =
            server_signin_link("pass+server://h/dav/a/p.vault?v=1&user=a&token=pst_t".into())
                .unwrap();
        assert_eq!(pairing["pairing"], true);
        assert!(!pairing.to_string().contains("pst_t"));
        assert_eq!(
            server_signin_link("https://h".into()).unwrap_err(),
            "This isn't a Passyble Server link."
        );
        assert!(!device_name().is_empty());
    }
}
