//! Pass as a system-wide passkey provider on Windows 11 (opt-in, off by default).
//!
//! Windows 11 (24H2/25H2 with the November 2025 update, builds 26100.6725 / 26200.6725 and later) lets
//! third-party apps act as passkey managers through the `webauthn.dll` *plugin authenticator* API
//! (`webauthnplugin.h`, `pluginauthenticator.idl` in the Windows SDK). With the "Use Passyble as
//! Windows passkey provider" setting off, nothing is registered and no COM server runs.
//!
//! 1. **Package identity.** The plugin API only works for packaged processes, so Passyble registers a
//!    *package with external location* (sparse package) against the install folder (`package.rs`).
//!    Identity is fixed at process start, so Passyble restarts once afterwards.
//! 2. **Registration** (at start, with identity): `WebAuthNPluginAddAuthenticator` with the name, an SVG
//!    logo, the CLSID and an `authenticatorGetInfo` blob carrying `pass_core::AAGUID`
//!    (`ctap::authenticator_info`). Windows keeps the details it was given, so a later start whose
//!    [`Details`] differ hands them over with `WebAuthNPluginUpdateAuthenticatorDetails`, once; the
//!    user's switch in Windows Settings stays. Turning the setting off removes the credentials and the
//!    authenticator and unregisters the package (deferred until exit); the uninstallers do the same
//!    with `Pass.exe --passkey-setup remove` ([`cli`]).
//! 3. **COM server**: `Pass.exe` registers a class factory (`CoRegisterClassObject`,
//!    `CLSCTX_LOCAL_SERVER`, `REGCLS_MULTIPLEUSE`, on an MTA thread) for `IPluginAuthenticator`
//!    (`win.rs`). If Pass isn't running, COM starts it with `--passkey-provider` (tray only).
//!    * `MakeCredential` / `GetAssertion`: the request signature is verified with the operation-signing
//!      key from `WebAuthNPluginGetOperationSigningPublicKey` (SHA-256, ECDSA or RSA-PSS through CNG)
//!      and unsigned requests are refused, because any local process could activate the class. Then
//!      the CTAP2 CBOR request is decoded (`ctap.rs`) and handed to the agent. Windows has already
//!      checked the RP ID against the caller.
//!    * A locked vault is unlocked with Windows Hello shown over Windows' passkey dialog
//!      (`AppUi::passkey_unlock`), which also counts as the request's user verification. Otherwise
//!      user verification is `WebAuthNPluginPerformUserVerification`, falling back to
//!      `UserConsentVerifier` (`platform::hello_verify`).
//!    * `CancelOperation` cancels the pending prompt (a cancel that arrives before its operation is
//!      kept for it). One operation runs at a time: a new request cancels one still winding down and
//!      waits a few seconds for it (Windows shows one passkey dialog at a time).
//!    * Each operation logs one line (which, HRESULT, duration, lock state, list lengths, ending
//!      step), never the site, the user or key data.
//! 4. **Credential metadata** (`WebAuthNPluginAuthenticatorAddCredentials`): Windows keeps an autofill
//!    cache of rp id, rp name, user handle, user name and credential id (never keys). A background
//!    thread compares the vault's passkeys with what was last pushed every few seconds while the
//!    vault is unlocked and replaces the cache when they differ. The check doesn't count as vault
//!    activity, so it never keeps the vault from auto-locking. Switching vaults empties the cache at
//!    once; it is refilled when the new vault is unlocked.
//!
//! Without the setting (or on other OSes), native-app passkeys go through hybrid (QR) to Pass on
//! Android, and browsers use the extension.

pub mod ctap;
#[cfg(windows)]
mod package;
#[cfg(windows)]
mod win;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex, OnceLock};
use std::time::Duration;

use pass_agent::{Agent, PasskeyMetadata};
use serde_json::{json, Value};
use tauri::{AppHandle, Manager};

use crate::state::{lock, AppState};

/// The COM class id (`PASSYBLE_PASSKEY_CLSID` at build time, see build.rs). Test builds use another one so they can be registered next to an installed Passyble.
pub const CLSID: &str = env!("PASSYBLE_PASSKEY_CLSID");
/// The CLSID of normal builds, as in `Windows/installer/packaging/AppxManifest.xml`.
#[cfg_attr(not(test), allow(dead_code))]
pub const DEFAULT_CLSID: &str = "2ced63f3-59c6-4471-88dd-ee8d8822ad81";
#[cfg_attr(not(windows), allow(dead_code))]
pub const PACKAGE_NAME: &str = env!("PASSYBLE_PACKAGE_NAME");
#[cfg_attr(not(windows), allow(dead_code))]
pub const PACKAGE_PUBLISHER: &str = env!("PASSYBLE_PACKAGE_PUBLISHER");
pub const SETUP_ARG: &str = "--passkey-setup";
/// Windows Settings → Accounts → Passkeys → Advanced options (where plugins are switched on).
const PASSKEY_SETTINGS_URI: &str = "ms-settings:passkeys-advancedoptions";
/// Windows Settings → System → For developers (Developer Mode).
const DEVELOPER_SETTINGS_URI: &str = "ms-settings:developers";
pub const LAUNCH_ARG: &str = "--passkey-provider";
const SYNC_EVERY: Duration = Duration::from_secs(10);
const AUTHENTICATOR_NAME: &str = "Passyble";
/// The mark next to the name (written by make-icons.mjs), readable on the light and the dark passkey dialog.
const LOGO_SVG: &str = include_str!("passkey_provider/logo.svg");

static APP: OnceLock<AppHandle> = OnceLock::new();
static ENABLED: AtomicBool = AtomicBool::new(false);
static LAST_ERROR: Mutex<Option<String>> = Mutex::new(None);
static SYNC_KICK: Mutex<Option<mpsc::Sender<()>>> = Mutex::new(None);
static SYNCED: Mutex<Option<(Vec<u8>, usize)>> = Mutex::new(None);
/// Set by [`vault_switched`]: empty Windows' cache even though the vault is locked.
static CLEAR_PENDING: AtomicBool = AtomicBool::new(false);

/// The last failure of [`sync_once`], so a failure repeated every few seconds is logged once.
static SYNC_FAILURE: Mutex<Option<String>> = Mutex::new(None);

fn set_error(error: Option<String>) {
    let mut last = lock(&LAST_ERROR);
    if let Some(e) = error.as_ref().filter(|e| last.as_ref() != Some(*e)) {
        crate::applog::plog!("passkey provider: {e}");
    }
    *last = error;
}

fn new_failure(last: &mut Option<String>, failure: &str) -> bool {
    if last.as_deref() == Some(failure) {
        return false;
    }
    *last = Some(failure.to_string());
    true
}

#[cfg_attr(not(windows), allow(dead_code))]
fn agent() -> Option<Arc<Agent>> {
    APP.get()?.state::<Arc<AppState>>().agent()
}

/// Pass was unlocked moments ago for this very request (Windows Hello or master password): that
/// counts as its user verification, so Windows Hello isn't shown a second time. One-shot.
#[cfg_attr(not(windows), allow(dead_code))]
fn take_unlock_credit() -> bool {
    APP.get()
        .is_some_and(|app| app.state::<Arc<AppState>>().ui.take_unlock_credit())
}

pub struct Request {
    pub window: Option<isize>,
}

#[cfg(windows)]
pub fn current_request() -> Option<Request> {
    win::serving().map(|window| Request { window })
}

#[cfg(not(windows))]
pub fn current_request() -> Option<Request> {
    None
}

#[cfg(windows)]
pub fn request_cancelled() -> bool {
    win::serving_cancelled()
}

#[cfg(not(windows))]
pub fn request_cancelled() -> bool {
    false
}

/// A new request from Windows' passkey dialog: the user just chose Passyble there, so a Cancel in
/// an earlier unlock prompt (which makes unlock requests right behind it give up) doesn't count.
#[cfg_attr(not(windows), allow(dead_code))]
fn forget_hello_cancel() {
    if let Some(app) = APP.get() {
        app.state::<Arc<AppState>>().ui.forget_hello_cancel();
    }
}

#[cfg_attr(not(windows), allow(dead_code))]
fn cancel_prompts() {
    if let Some(app) = APP.get() {
        let state = app.state::<Arc<AppState>>();
        state.prompts.cancel_all(app);
        state.resolve_unlock_waiters(false);
    }
}

/// Another vault became active: Windows' cache still lists the previous vault's passkeys, so it is emptied (even while the new vault is locked) and refilled once unlocked.
pub fn vault_switched() {
    *lock(&SYNCED) = None;
    CLEAR_PENDING.store(true, Ordering::SeqCst);
    kick_sync();
}

pub fn kick_sync() {
    if let Some(tx) = lock(&SYNC_KICK).as_ref() {
        let _ = tx.send(());
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Enabled {
    Active,
    #[cfg_attr(not(windows), allow(dead_code))]
    RestartNeeded,
}

/// Set after turning the setting on registered the package, so the next start (the one with
/// identity) opens Windows' passkey settings for the last step.
fn finish_marker() -> PathBuf {
    crate::settings::local_dir().join(".passkey-provider-finish")
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(windows), allow(dead_code))]
pub struct Details {
    pub name: String,
    pub light_logo: String,
    pub dark_logo: String,
    pub info: Vec<u8>,
}

#[cfg_attr(not(windows), allow(dead_code))]
impl Details {
    pub fn current() -> Details {
        let logo =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, LOGO_SVG.trim());
        Details {
            name: AUTHENTICATOR_NAME.into(),
            light_logo: logo.clone(),
            dark_logo: logo,
            info: ctap::authenticator_info(&pass_core::AAGUID),
        }
    }

    /// Hex SHA-256 over every field, each length-prefixed so field boundaries count.
    pub fn digest(&self) -> String {
        let mut data = Vec::new();
        for field in [
            self.name.as_bytes(),
            self.light_logo.as_bytes(),
            self.dark_logo.as_bytes(),
            &self.info[..],
        ] {
            data.extend_from_slice(&(field.len() as u32).to_le_bytes());
            data.extend_from_slice(field);
        }
        pass_core::sha256(data)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
}

/// The [`Details::digest`] Windows last took, per CLSID, in `%LOCALAPPDATA%\Pass` (the registration belongs to this PC).
fn details_marker() -> PathBuf {
    crate::settings::local_dir().join(format!(".passkey-provider-details-{CLSID}"))
}

/// Whether Windows may hold other details than the ones with `digest`. Nothing recorded counts
/// as changed: a registration from before the details were recorded has the logo of its time.
fn details_changed_in(marker: &Path, digest: &str) -> bool {
    std::fs::read_to_string(marker).map_or(true, |stored| stored.trim() != digest)
}

fn remember_details_in(marker: &Path, digest: &str) -> std::io::Result<()> {
    if let Some(dir) = marker.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(marker, digest)
}

#[cfg_attr(not(windows), allow(dead_code))]
fn details_changed(digest: &str) -> bool {
    details_changed_in(&details_marker(), digest)
}

/// Records that Windows took the details with `digest`. If this fails the next start updates them again, which is harmless.
#[cfg_attr(not(windows), allow(dead_code))]
fn remember_details(digest: &str) {
    if let Err(e) = remember_details_in(&details_marker(), digest) {
        crate::applog::plog!("passkey provider: could not record the registered details: {e}");
    }
}

pub fn start(app: &AppHandle, enabled: bool) {
    let _ = APP.set(app.clone());
    if !enabled {
        let _ = std::fs::remove_file(finish_marker());
        return;
    }
    let app = app.clone();
    let _ = std::thread::Builder::new()
        .name("pass-passkey-start".into())
        .spawn(move || {
            let finishing = finish_marker().exists();
            match enable_inner(&app, finishing, true) {
                Ok(Enabled::Active) => {
                    let _ = std::fs::remove_file(finish_marker());
                    crate::applog::plog!(
                        "passkey provider: ready{}",
                        if started_by_windows() {
                            " (started by Windows for a passkey request)"
                        } else {
                            ""
                        }
                    );
                }
                Ok(Enabled::RestartNeeded) => {}
                Err(e) => set_error(Some(e)),
            }
        });
}

fn started_by_windows() -> bool {
    std::env::args_os().any(|a| a == LAUNCH_ARG)
}

/// A second `Pass.exe` started with [`LAUNCH_ARG`] handed over to this one and exits. COM only starts one when no Passyble had the passkey class registered; logged, and the server is restarted if the setting is on.
pub fn handed_over(app: &AppHandle) {
    let wanted = app.state::<Arc<AppState>>().settings().passkey_provider;
    let active = ENABLED.load(Ordering::SeqCst);
    crate::applog::plog!(
        "passkey provider: Windows started a second Pass.exe for a request (setting {}, server {}{})",
        if wanted { "on" } else { "off" },
        if active { "running" } else { "not running" },
        lock(&LAST_ERROR)
            .as_deref()
            .map(|e| format!(", last error: {e}"))
            .unwrap_or_default()
    );
    if wanted && !active {
        start(app, true);
    }
}

/// The setting was turned on: registers the package (then Passyble must restart once), or, with identity, starts the COM server, registers with Windows and opens its passkey settings.
pub fn enable(app: &AppHandle) -> Result<Enabled, String> {
    enable_inner(app, true, false)
}

/// `at_start`: the setting is on already (start-up, or a passkey request handed over).
fn enable_inner(
    app: &AppHandle,
    open_windows_settings: bool,
    at_start: bool,
) -> Result<Enabled, String> {
    let _ = APP.set(app.clone());
    let outcome = platform_enable(at_start)?;
    set_error(None);
    if outcome == Enabled::RestartNeeded {
        let marker = finish_marker();
        if let Some(dir) = marker.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let _ = std::fs::write(marker, b"");
        return Ok(outcome);
    }
    ENABLED.store(true, Ordering::SeqCst);
    start_sync_thread();
    kick_sync();
    if open_windows_settings && !status()["enabled_in_windows"].as_bool().unwrap_or(false) {
        let _ = crate::platform::open_browser(PASSKEY_SETTINGS_URI);
    }
    Ok(outcome)
}

pub fn disable() -> Result<(), String> {
    ENABLED.store(false, Ordering::SeqCst);
    *lock(&SYNCED) = None;
    let _ = std::fs::remove_file(finish_marker());
    // Turning it on again adds a new registration, with this build's details.
    let _ = std::fs::remove_file(details_marker());
    let result = platform_disable();
    set_error(result.as_ref().err().cloned());
    result
}

#[cfg(windows)]
static REMOVAL_PENDING: AtomicBool = AtomicBool::new(false);

#[cfg(windows)]
fn platform_enable(at_start: bool) -> Result<Enabled, String> {
    if !win::supported() {
        return Err(crate::i18n::tr!("errors.pp_unsupported_short"));
    }
    if !win::has_package_identity() {
        if package::registered_here()?.is_none() {
            package::register()?;
        }
        return Ok(Enabled::RestartNeeded);
    }
    if REMOVAL_PENDING.load(Ordering::SeqCst) {
        return Err(crate::i18n::tr!("errors.pp_removal_pending"));
    }
    win::start_com_server().map_err(|e| {
        crate::errors::logged(
            crate::i18n::tr!("errors.pp_start_failed"),
            "passkey provider",
            e,
        )
    })?;
    if let Err(e) = win::register() {
        // With the setting on, a failed registration check keeps the COM server: Windows may
        // still have Passyble registered from an earlier start and send it requests, and COM
        // can't start a second Passyble for them (it hands over to this one and exits).
        if !at_start {
            win::stop_com_server();
        }
        return Err(e);
    }
    Ok(Enabled::Active)
}

#[cfg(windows)]
fn platform_disable() -> Result<(), String> {
    win::stop_com_server();
    let identity = win::has_package_identity();
    let mut errors = Vec::new();
    if win::supported() && identity {
        if let Err(e) = win::unregister() {
            errors.push(e);
        }
    }
    match package::unregister() {
        Ok(removed) => {
            if removed && identity {
                REMOVAL_PENDING.store(true, Ordering::SeqCst);
            }
        }
        Err(e) => errors.push(e),
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join(" "))
    }
}

#[cfg(not(windows))]
fn platform_enable(_at_start: bool) -> Result<Enabled, String> {
    Err(crate::i18n::tr!("errors.pp_windows_only"))
}

#[cfg(not(windows))]
fn platform_disable() -> Result<(), String> {
    Ok(())
}

#[tauri::command]
pub fn passkey_provider_open(page: String) -> Result<(), String> {
    let uri = match page.as_str() {
        "passkeys" => PASSKEY_SETTINGS_URI,
        "developers" => DEVELOPER_SETTINGS_URI,
        _ => return Err(crate::i18n::tr!("errors.pp_unknown_page")),
    };
    crate::platform::open_browser(uri)
}

/// `Pass.exe --passkey-setup <action>` (support, tests, uninstallers): handled at the start of `main`,
/// before Tauri (no window, no single-instance hand-over), prints JSON and returns the exit code.
/// `None` when the arguments aren't a setup call. Actions: `status`, `register-package`,
/// `add-authenticator` (needs identity), `remove` (what the uninstallers run), and `hello-key
/// <vault-id>` (whether this process sees that vault's Hello key; identity changes which keys an app
/// sees; never creates or uses one).
pub fn cli() -> Option<i32> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) != Some(SETUP_ARG) {
        return None;
    }
    let action = args.get(1).map(String::as_str).unwrap_or("status");
    let (code, out) = match platform_cli(action, &args[2.min(args.len())..]) {
        Ok(value) => (0, value),
        Err(e) => (1, json!({ "action": action, "error": e })),
    };
    println!("{out:#}");
    Some(code)
}

#[cfg(windows)]
fn platform_cli(action: &str, rest: &[String]) -> Result<Value, String> {
    match action {
        "status" => Ok(status()),
        "register-package" => {
            let method = package::register()?;
            Ok(json!({ "action": action, "method": format!("{method:?}"), "status": status() }))
        }
        "add-authenticator" => {
            if !win::has_package_identity() {
                return Err("this process has no package identity (register the package, then run this again)".into());
            }
            win::register()?;
            Ok(json!({ "action": action, "status": status() }))
        }
        "remove" => {
            let mut errors = Vec::new();
            let identity = win::has_package_identity();
            if win::supported() && identity {
                if let Err(e) = win::unregister() {
                    errors.push(e);
                }
            }
            let removed = package::unregister().map_err(|e| errors.push(e)).ok();
            if errors.is_empty() {
                Ok(json!({ "action": action, "authenticator_removed": identity, "package_removed": removed }))
            } else {
                Err(errors.join(" "))
            }
        }
        "hello-key" => {
            let vault = rest.first().ok_or("hello-key needs a vault id")?;
            let name = crate::hello::key_name(vault);
            Ok(json!({
                "action": action,
                "key": name,
                "found": crate::platform::hello_key_public(&name).is_some(),
                "package_identity": win::package_full_name(),
            }))
        }
        _ => Err(format!("unknown action {action:?} (status, register-package, add-authenticator, remove, hello-key)")),
    }
}

#[cfg(not(windows))]
fn platform_cli(_action: &str, _rest: &[String]) -> Result<Value, String> {
    Err("the passkey provider is only available on Windows".into())
}

fn fingerprint(list: &[PasskeyMetadata]) -> Vec<u8> {
    let mut data = Vec::new();
    for m in list {
        for field in [
            &m.credential_id[..],
            m.rp_id.as_bytes(),
            m.rp_name.as_bytes(),
            &m.user_handle[..],
            m.user_name.as_bytes(),
            m.user_display_name.as_bytes(),
        ] {
            data.extend_from_slice(&(field.len() as u32).to_le_bytes());
            data.extend_from_slice(field);
        }
    }
    pass_core::sha256(data)
}

fn start_sync_thread() {
    let mut kick = lock(&SYNC_KICK);
    if kick.is_some() {
        return;
    }
    let (tx, rx) = mpsc::channel::<()>();
    *kick = Some(tx);
    let _ = std::thread::Builder::new()
        .name("pass-passkey-sync".into())
        .spawn(move || loop {
            match rx.recv_timeout(SYNC_EVERY) {
                Ok(()) | Err(mpsc::RecvTimeoutError::Timeout) => sync_once(),
                Err(mpsc::RecvTimeoutError::Disconnected) => return,
            }
        });
}

fn sync_once() {
    if !ENABLED.load(Ordering::SeqCst) || !windows_uses_list() {
        return;
    }
    // Locked: keep whatever Windows has cached (it only holds metadata), unless it belongs to a
    // vault that is no longer the active one.
    let list = match agent().and_then(|a| a.passkey_metadata()) {
        Some(list) => {
            CLEAR_PENDING.store(false, Ordering::SeqCst);
            list
        }
        None if CLEAR_PENDING.swap(false, Ordering::SeqCst) => Vec::new(),
        None => return,
    };
    let print = fingerprint(&list);
    if lock(&SYNCED).as_ref().is_some_and(|(p, _)| *p == print) {
        return;
    }
    match push(&list) {
        Ok(()) => {
            *lock(&SYNCED) = Some((print, list.len()));
            *lock(&SYNC_FAILURE) = None;
            set_error(None);
        }
        Err(e) => {
            if new_failure(&mut lock(&SYNC_FAILURE), &e) {
                crate::applog::plog!("passkey provider: {e}");
            }
            set_error(Some(crate::i18n::tr!("errors.pp_sync_failed")));
        }
    }
}

/// Whether Windows uses Passyble's passkey list: not while Passyble isn't registered or is switched off in
/// Windows' passkey settings. When the state can't be read, the push is tried anyway.
#[cfg(windows)]
fn windows_uses_list() -> bool {
    !matches!(win::authenticator_state(), Ok(None) | Ok(Some(false)))
}

#[cfg(not(windows))]
fn windows_uses_list() -> bool {
    true
}

#[cfg(windows)]
fn push(list: &[PasskeyMetadata]) -> Result<(), String> {
    win::sync_credentials(list)
}

#[cfg(not(windows))]
fn push(_list: &[PasskeyMetadata]) -> Result<(), String> {
    Err("not supported on this platform".into())
}

/// For Settings (and `--passkey-setup status`): what works and what doesn't.
///
/// * `supported`: Windows has the plugin API
/// * `packaged`: this process runs with the package identity (`package_identity`: its full name)
/// * `package_registered`: the package is registered with this Pass.exe's folder as its external
///   location (`package_elsewhere`: registered for another folder instead)
/// * `restart_needed`: registered, but this process started before that (no identity yet)
/// * `package_files` / `signed_package` / `developer_mode` / `can_register`: whether turning the
///   setting on can register the package (`package_error`: why the shipped files can't be used)
/// * `registered` / `enabled_in_windows`: the plugin authenticator (`WebAuthNPluginGetAuthenticatorState`)
pub fn status() -> Value {
    #[cfg(windows)]
    {
        let supported = win::supported();
        let identity = win::package_full_name();
        let packaged = identity.is_some();
        let state = if supported && packaged {
            win::authenticator_state().ok().flatten()
        } else {
            None
        };
        let files = package::files();
        let developer_mode = package::developer_mode();
        let (here, elsewhere, package_query_error) = match package::find() {
            Ok(found) => {
                let dir = package::exe_dir().ok();
                let (here, other): (Vec<_>, Vec<_>) = found.into_iter().partition(|r| {
                    r.external
                        .as_deref()
                        .zip(dir.as_deref())
                        .is_some_and(|(e, d)| package::same_dir(e, d))
                });
                (
                    here.into_iter().next(),
                    other.into_iter().next().and_then(|r| r.external),
                    None,
                )
            }
            Err(e) => (None, None, Some(e)),
        };
        let can_register = files.manifest && (files.signed || developer_mode);
        json!({
            "supported": supported,
            "packaged": packaged,
            "package_identity": identity,
            "package_name": PACKAGE_NAME,
            "package_publisher": PACKAGE_PUBLISHER,
            "package_registered": here.is_some(),
            "package_version": here.as_ref().map(|r| r.version.clone()),
            "package_development_mode": here.as_ref().map(|r| r.development_mode),
            "package_elsewhere": elsewhere,
            "restart_needed": here.is_some() && !packaged,
            "package_files": files.manifest,
            "signed_package": files.signed,
            "package_error": files.error.or(package_query_error),
            "developer_mode": developer_mode,
            "can_register": can_register,
            "active": ENABLED.load(Ordering::SeqCst),
            "registered": state.is_some(),
            "enabled_in_windows": state.unwrap_or(false),
            "synced_passkeys": lock(&SYNCED).as_ref().map(|(_, n)| *n),
            "error": lock(&LAST_ERROR).clone(),
            "clsid": CLSID,
        })
    }
    #[cfg(not(windows))]
    json!({
        "supported": false,
        "packaged": false,
        "package_registered": false,
        "restart_needed": false,
        "can_register": false,
        "active": ENABLED.load(Ordering::SeqCst),
        "registered": false,
        "enabled_in_windows": false,
        "synced_passkeys": lock(&SYNCED).as_ref().map(|(_, n)| *n),
        "error": lock(&LAST_ERROR).clone(),
        "clsid": CLSID,
    })
}
#[cfg(test)]
mod tests {
    use super::*;

    fn meta(id: u8, user: &str) -> PasskeyMetadata {
        PasskeyMetadata {
            credential_id: vec![id],
            rp_id: "example.com".into(),
            rp_name: "Example".into(),
            user_handle: vec![id, id],
            user_name: user.into(),
            user_display_name: user.into(),
        }
    }

    #[test]
    fn fingerprint_tracks_every_field() {
        let a = vec![meta(1, "alice"), meta(2, "bob")];
        assert_eq!(fingerprint(&a), fingerprint(&a.clone()));
        assert_ne!(fingerprint(&a), fingerprint(&a[..1]));
        let mut renamed = a.clone();
        renamed[1].user_display_name = "Bob".into();
        assert_ne!(fingerprint(&a), fingerprint(&renamed));
        let mut x = meta(1, "ab");
        x.user_display_name = "c".into();
        let mut y = meta(1, "a");
        y.user_display_name = "bc".into();
        assert_ne!(fingerprint(&[x]), fingerprint(&[y]));
    }

    #[test]
    fn a_repeated_sync_failure_is_new_once() {
        let mut last = None;
        assert!(new_failure(&mut last, "AddCredentials: E_FAIL"));
        assert!(!new_failure(&mut last, "AddCredentials: E_FAIL"));
        assert!(new_failure(&mut last, "RemoveAllCredentials: E_FAIL"));
        last = None;
        assert!(new_failure(&mut last, "RemoveAllCredentials: E_FAIL"));
    }

    #[test]
    fn clsid_matches_the_com_class() {
        #[cfg(windows)]
        assert_eq!(win::CLSID, windows::core::GUID::try_from(CLSID).unwrap());
        assert_eq!(CLSID.len(), 36);
    }

    #[test]
    fn packaging_manifest_uses_the_same_clsid() {
        let manifest = include_str!("../../../../Windows/installer/packaging/AppxManifest.xml");
        assert!(manifest.contains(&format!("Id=\"{DEFAULT_CLSID}\"")));
        assert!(manifest.contains(&format!("Arguments=\"{LAUNCH_ARG}\"")));
        assert!(manifest.contains("Application Id=\"Pass\" Executable=\"Pass.exe\""));
    }

    /// build.rs (Pass.exe's manifest, these constants) and the staging script must agree on the
    /// default identity, or the staged package would not give Pass.exe identity.
    #[test]
    fn identity_defaults_agree() {
        let build = include_str!("../build.rs");
        let script =
            include_str!("../../../../Windows/installer/packaging/build-sparse-package.ps1");
        let manifest = include_str!("../../../../Windows/installer/packaging/AppxManifest.xml");
        for (var, default) in [
            ("PASSYBLE_PACKAGE_NAME", "Sensyble.Passyble"),
            ("PASSYBLE_PACKAGE_PUBLISHER", "CN=Sensyble"),
            ("PASSYBLE_PASSKEY_CLSID", DEFAULT_CLSID),
        ] {
            assert!(build.contains(&format!("\"{default}\"")), "build.rs {var}");
            assert!(
                script.contains(&format!("\"{var}\" \"{default}\"")),
                "build-sparse-package.ps1 {var}"
            );
        }
        assert!(manifest.contains("Name=\"Sensyble.Passyble\""));
        assert!(manifest.contains("Publisher=\"CN=Sensyble\""));
        assert!(build.contains("applicationId=\"Pass\""));
    }

    #[test]
    fn details_digest_tracks_every_field() {
        let details = Details::current();
        assert_eq!(details.digest(), Details::current().digest());
        assert_eq!(details.digest().len(), 64);
        let changed = |edit: fn(&mut Details)| {
            let mut other = details.clone();
            edit(&mut other);
            other.digest() != details.digest()
        };
        assert!(changed(|d| d.name = "Pass".into()));
        assert!(changed(|d| d.light_logo.push('A')));
        assert!(changed(|d| d.dark_logo.push('A')));
        assert!(changed(|d| d.info.push(0)));
        let mut x = details.clone();
        x.name = "Passyble".into();
        x.light_logo = "Q".into();
        let mut y = details.clone();
        y.name = "PassybleQ".into();
        y.light_logo = String::new();
        assert_ne!(x.digest(), y.digest());
    }

    #[test]
    fn both_logos_are_the_lime_key_on_transparent() {
        let details = Details::current();
        assert_eq!(details.name, "Passyble");
        for logo in [&details.light_logo, &details.dark_logo] {
            let svg = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, logo)
                .map(String::from_utf8)
                .unwrap()
                .unwrap();
            assert!(svg.starts_with("<svg") && svg.ends_with("</svg>"));
            assert!(svg.contains("fill=\"#c6f432\""));
            assert!(svg.contains("stroke=\"#4f6b00\""));
            assert!(!svg.contains("#ffffff") && !svg.contains("#cfcfcf"));
            assert!(!svg.contains("<rect"));
        }
        assert_eq!(
            details.info,
            ctap::authenticator_info(&pass_core::AAGUID),
            "the AAGUID Windows shows"
        );
    }

    #[test]
    fn details_are_updated_once_after_they_change() {
        let dir = std::env::temp_dir().join(format!("pass-pp-details-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let marker = dir.join("nested").join(".passkey-provider-details");
        let digest = Details::current().digest();
        assert!(details_changed_in(&marker, &digest));
        remember_details_in(&marker, &digest).unwrap();
        assert!(!details_changed_in(&marker, &digest));
        assert!(!details_changed_in(&marker, &digest));
        assert!(details_changed_in(&marker, &"0".repeat(64)));
        std::fs::write(&marker, format!("{digest}\r\n")).unwrap();
        assert!(!details_changed_in(&marker, &digest));
        let _ = std::fs::remove_dir_all(&dir);
        let real = details_marker();
        assert!(real.starts_with(crate::settings::local_dir()));
        assert!(real.to_string_lossy().ends_with(CLSID));
    }

    #[test]
    fn setup_actions_need_the_flag() {
        assert_eq!(cli(), None);
    }
}
