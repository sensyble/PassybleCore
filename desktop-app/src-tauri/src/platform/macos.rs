//! macOS: the platform API (the same functions as `win32.rs` and `stub.rs`) mapped onto the
//! `pass-macos` crate in `macOS/platform/`. Keep this file a thin adapter.
//!
//! Names stay those of the Windows API (`dpapi_*`, `hello_*`) so callers need no change: "DPAPI" is the
//! Keychain device key, "Windows Hello" is Touch ID or the Mac password. Window handles (`isize`) are
//! `NSWindow` pointers; an auto-type [`Target`]'s `hwnd` is the app's process ID and `exe` its bundle ID.

use pass_macos::{
    autotype, keychain, secure_enclave, session, touchid, window as mac_window, Error,
};

use super::{HelloKeyError, Key, Target};

fn frontmost_of(target: &Target) -> autotype::Frontmost {
    autotype::Frontmost {
        pid: target.hwnd as i32,
        title: target.title.clone(),
        app: String::new(),
        bundle_id: target.exe.clone(),
    }
}

pub fn foreground_window() -> Option<Target> {
    autotype::frontmost().map(|app| Target {
        hwnd: app.pid as isize,
        title: app.title,
        exe: app.bundle_id,
    })
}

pub fn app_name(target: &Target) -> Option<String> {
    autotype::app_name(target.hwnd as i32).filter(|name| !name.trim().is_empty())
}

/// The Accessibility permission auto-type needs; without it macOS shows its own dialog (once).
pub fn autotype_permission() -> Result<(), String> {
    if autotype::trusted(true) {
        Ok(())
    } else {
        Err(crate::i18n::tr!("macos.accessibility_needed"))
    }
}

pub fn autotype_ready(target: &Target) -> Result<(), String> {
    match autotype::ready(&frontmost_of(target)) {
        Ok(()) => Ok(()),
        Err(Error::NotPermitted) => {
            autotype::trusted(true);
            Err(crate::i18n::tr!("macos.accessibility_needed"))
        }
        Err(Error::SecureInput) => {
            crate::applog::plog!("auto-type: another app holds Secure Input");
            Err(crate::i18n::tr!("macos.secure_input"))
        }
        Err(e) => Err(crate::errors::logged(
            crate::i18n::tr!("autotype.stopped"),
            "auto-type",
            e,
        )),
    }
}

pub fn focus(target: &Target) -> bool {
    autotype::focus(&frontmost_of(target))
}

pub fn window_unchanged(target: &Target, same_title: bool) -> bool {
    autotype::unchanged(&frontmost_of(target), same_title)
}

pub fn wait_modifiers_released() {
    autotype::wait_modifiers_released();
}

pub fn type_text(target: &Target, text: &str) -> bool {
    autotype::type_text(&frontmost_of(target), text).is_ok()
}

pub fn press(target: &Target, key: Key) -> bool {
    let key = match key {
        Key::Tab => autotype::Key::Tab,
        Key::Enter => autotype::Key::Return,
    };
    autotype::press(&frontmost_of(target), key).is_ok()
}

pub fn show_without_activation(window: &tauri::WebviewWindow) {
    let shown = window_handle(window).is_some_and(mac_window::show_without_activation);
    if !shown {
        let _ = window.show();
    }
}

pub fn bring_to_front(window: &tauri::WebviewWindow) {
    if !window_handle(window).is_some_and(mac_window::bring_to_front) {
        let _ = window.set_focus();
    }
}

pub fn hide_without_activation(window: &tauri::WebviewWindow) {
    let _ = window.hide();
}

pub fn watch_session_lock(on_lock: Box<dyn Fn() + Send + Sync>) {
    session::watch_lock(on_lock);
}

pub fn dpapi_protect(data: &[u8]) -> Result<Vec<u8>, String> {
    keychain::seal(data).map_err(|e| keychain_failed("Keychain seal", e))
}

pub fn dpapi_unprotect(data: &[u8]) -> Result<Vec<u8>, String> {
    keychain::open(data)
        .map(|plain| plain.to_vec())
        .map_err(|e| keychain_failed("Keychain open", e))
}

fn keychain_failed(context: &str, e: Error) -> String {
    crate::errors::logged(crate::i18n::tr!("macos.keychain_failed"), context, e)
}

pub fn hello_available() -> bool {
    touchid::available()
}

/// The Touch ID (or Mac password) prompt. `Ok(false)` when not verified or cancelled.
pub fn hello_verify(_owner: Option<isize>, message: &str) -> Result<bool, String> {
    match touchid::verify(message) {
        Ok(verified) => Ok(verified),
        Err(Error::Cancelled) => Ok(false),
        Err(e) => Err(crate::errors::logged(
            crate::i18n::tr!("errors.hello_failed"),
            "Touch ID",
            e,
        )),
    }
}

pub fn window_handle(window: &tauri::WebviewWindow) -> Option<isize> {
    window
        .ns_window()
        .ok()
        .filter(|ptr| !ptr.is_null())
        .map(|ptr| ptr as isize)
}

pub fn browser_window(_client_pid: u32) -> Option<isize> {
    None
}

// The Windows Hello key signs keywrap's challenge; the Secure Enclave key answers with
// ECDH(key, hash_to_curve(challenge)) instead, which is just as deterministic and only exists after
// the Touch ID prompt (pass_macos::secure_enclave). With no public key to check against, keywrap
// asks twice at enrollment and compares; pass-macos answers the second request without a prompt.

fn key_error(e: Error) -> HelloKeyError {
    match e {
        Error::Cancelled => HelloKeyError::Cancelled,
        Error::NotFound => HelloKeyError::NotFound,
        Error::Unsupported => HelloKeyError::Unsupported,
        e => HelloKeyError::Failed(crate::errors::logged(
            crate::i18n::tr!("errors.hello_failed"),
            "Touch ID key",
            e,
        )),
    }
}

pub fn hello_key_supported() -> bool {
    secure_enclave::supported()
}

pub fn hello_key_ensure(name: &str, _owner: Option<isize>) -> Result<(), HelloKeyError> {
    secure_enclave::ensure(name, secure_enclave::Protection::Presence).map_err(key_error)
}

pub fn hello_key_sign(
    name: &str,
    data: &[u8],
    _owner: Option<isize>,
) -> Result<Vec<u8>, HelloKeyError> {
    let unlock = crate::i18n::tr!("macos.touchid_key_reason");
    let enroll = crate::i18n::tr!("macos.touchid_enroll_reason");
    let reasons = secure_enclave::Reasons {
        unlock: &unlock,
        enroll: &enroll,
    };
    secure_enclave::secret_for(name, data, reasons)
        .map(|secret| secret.to_vec())
        .map_err(key_error)
}

/// `None`: keywrap's check is for RSA signatures; it then compares two answers instead.
pub fn hello_key_public(_name: &str) -> Option<Vec<u8>> {
    None
}

pub fn hello_key_delete(name: &str) {
    secure_enclave::delete(name);
}

/// The kept item list's sealer (`pass_agent::KeptSealer`): the Keychain device key.
pub struct KeptKeychain;

impl pass_agent::KeptSealer for KeptKeychain {
    fn seal(&self, plain: &[u8]) -> Option<Vec<u8>> {
        keychain::seal(plain)
            .map_err(|e| crate::applog::plog!("kept list: Keychain seal: {e}"))
            .ok()
    }

    fn open(&self, sealed: &[u8]) -> Option<Vec<u8>> {
        keychain::open(sealed).map(|plain| plain.to_vec()).ok()
    }
}

/// Time since the last keyboard or mouse input (CoreGraphics), for the sync schedule; `None` if unknown.
pub fn user_idle_for() -> Option<std::time::Duration> {
    #[link(name = "CoreGraphics", kind = "framework")]
    unsafe extern "C" {
        fn CGEventSourceSecondsSinceLastEventType(state_id: i32, event_type: u32) -> f64;
    }
    // kCGEventSourceStateCombinedSessionState = 0, kCGAnyInputEventType = ~0.
    // SAFETY: a plain query with constant arguments.
    let seconds = unsafe { CGEventSourceSecondsSinceLastEventType(0, u32::MAX) };
    (seconds.is_finite() && seconds >= 0.0).then(|| std::time::Duration::from_secs_f64(seconds))
}
