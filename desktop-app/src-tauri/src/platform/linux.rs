//! Linux: the platform API (the same functions as `win32.rs`, `macos.rs` and `stub.rs`) mapped onto
//! the `pass-linux` crate in `Linux/platform/`. Keep this file a thin adapter.
//!
//! Names stay those of the Windows API (`dpapi_*`, `hello_*`) so callers need no change: "DPAPI" is the
//! device key in the Secret Service. Unlocking is by master password only (fprintd and polkit hold no
//! key). Auto-type is unavailable (Wayland has no synthetic input for other apps).

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

use pass_linux::{connector, secret, session, tray, Error};

use super::{HelloKeyError, Key, Target};

pub fn foreground_window() -> Option<Target> {
    None
}

pub fn focus(_target: &Target) -> bool {
    false
}

pub fn window_unchanged(_target: &Target, _same_title: bool) -> bool {
    false
}

pub fn wait_modifiers_released() {}

pub fn type_text(_target: &Target, _text: &str) -> bool {
    false
}

pub fn press(_target: &Target, _key: Key) -> bool {
    false
}

pub fn show_without_activation(window: &tauri::WebviewWindow) {
    let _ = window.show();
}

pub fn bring_to_front(window: &tauri::WebviewWindow) {
    let _ = window.set_focus();
}

pub fn hide_without_activation(window: &tauri::WebviewWindow) {
    let _ = window.hide();
}

pub fn watch_session_lock(on_lock: Box<dyn Fn() + Send + Sync>) {
    session::watch_lock(on_lock);
}

pub fn dpapi_protect(data: &[u8]) -> Result<Vec<u8>, String> {
    secret::seal(data).map_err(|e| secret_failed("Secret Service seal", e))
}

pub fn dpapi_unprotect(data: &[u8]) -> Result<Vec<u8>, String> {
    secret::open(data)
        .map(|plain| plain.to_vec())
        .map_err(|e| secret_failed("Secret Service open", e))
}

fn secret_failed(context: &str, e: Error) -> String {
    crate::errors::logged(crate::i18n::tr!("linux.secret_service_failed"), context, e)
}

pub fn hello_available() -> bool {
    false
}

pub fn hello_verify(_owner: Option<isize>, _message: &str) -> Result<bool, String> {
    Err(crate::i18n::tr!("errors.hello_keys_unavailable"))
}

pub fn window_handle(_window: &tauri::WebviewWindow) -> Option<isize> {
    None
}

pub fn browser_window(_client_pid: u32) -> Option<isize> {
    None
}

pub fn hello_key_supported() -> bool {
    false
}

pub fn hello_key_ensure(_name: &str, _owner: Option<isize>) -> Result<(), HelloKeyError> {
    Err(HelloKeyError::Unsupported)
}

pub fn hello_key_sign(
    _name: &str,
    _data: &[u8],
    _owner: Option<isize>,
) -> Result<Vec<u8>, HelloKeyError> {
    Err(HelloKeyError::Unsupported)
}

pub fn hello_key_public(_name: &str) -> Option<Vec<u8>> {
    None
}

pub fn hello_key_delete(_name: &str) {}

/// Whether a tray exists (a StatusNotifierWatcher on the session bus). GNOME without the AppIndicator
/// extension has none, so the main window minimizes instead of hiding (main.rs).
pub fn tray_host_present() -> bool {
    tray::host_present()
}

/// Runs from an AppImage (`$APPIMAGE` an absolute file path, this executable inside `$APPDIR`): the
/// in-app updater may replace that file. A .deb or .rpm install is updated by the package manager.
pub fn running_from_appimage() -> bool {
    connector::appimage().is_some()
}

/// AppImage only: the `pass-native-host` copy staged in `~/.local/share/Passyble/bin/`, where the
/// browsers' manifests point (an AppImage's own folder changes every run). Allowed to connect only
/// while its SHA-256 matches the host inside this AppImage; otherwise restaged, else left out.
pub fn staged_native_host() -> Option<PathBuf> {
    connector::appimage()?;
    let dirs = connector::Dirs::from_env()?;
    let bundled = std::env::current_exe()
        .ok()?
        .with_file_name(connector::HOST_FILE);
    connector::verified_staged_host(&dirs, &bundled)
        .map_err(|e| crate::applog::plog!("AppImage: the staged native host is not allowed: {e}"))
        .ok()
}

/// The kept item list's sealer (`pass_agent::KeptSealer`): the Secret Service device key. Without a
/// Secret Service the list is just not kept on disk (logged once).
pub struct KeptSecretService;

static SEAL_FAILURE_LOGGED: AtomicBool = AtomicBool::new(false);

impl pass_agent::KeptSealer for KeptSecretService {
    fn seal(&self, plain: &[u8]) -> Option<Vec<u8>> {
        secret::seal(plain)
            .map_err(|e| {
                if !SEAL_FAILURE_LOGGED.swap(true, Ordering::Relaxed) {
                    crate::applog::plog!("kept list: Secret Service seal: {e}");
                }
            })
            .ok()
    }

    fn open(&self, sealed: &[u8]) -> Option<Vec<u8>> {
        secret::open(sealed).map(|plain| plain.to_vec()).ok()
    }
}

/// Time since the last input, for the sync schedule: unknown here (Wayland has no portable idle time).
pub fn user_idle_for() -> Option<std::time::Duration> {
    None
}
