//! Non-Windows fallbacks. Auto-type, Hello and DPAPI are unavailable; windows are shown normally.

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

pub fn bring_to_front(_window: &tauri::WebviewWindow) {}

pub fn hide_without_activation(window: &tauri::WebviewWindow) {
    let _ = window.hide();
}

pub fn watch_session_lock(_on_lock: Box<dyn Fn() + Send + Sync>) {}

pub fn dpapi_protect(_data: &[u8]) -> Result<Vec<u8>, String> {
    Err("DPAPI is only available on Windows".into())
}

pub fn dpapi_unprotect(_data: &[u8]) -> Result<Vec<u8>, String> {
    Err("DPAPI is only available on Windows".into())
}

pub fn hello_available() -> bool {
    false
}

pub fn hello_verify(_hwnd: Option<isize>, _message: &str) -> Result<bool, String> {
    Err("Windows Hello is only available on Windows".into())
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

pub fn user_idle_for() -> Option<std::time::Duration> {
    None
}
