//! Showing, hiding and placing the app's windows. All windows are declared in tauri.conf.json
//! and created hidden at start-up, so nothing here creates a window at runtime (window creation
//! from a command can deadlock on Windows, and a new webview is far slower to open than a warm
//! one). A hidden window's webview gives its memory back instead (webview_memory.rs): every show
//! goes through [`webview_memory::shown`], every hide through [`webview_memory::hidden`].

use std::sync::Arc;
use std::time::Instant;

use tauri::{AppHandle, Emitter, Manager, PhysicalPosition};

use crate::i18n::tr;
use crate::platform;
use crate::state::{lock, AppState};
use crate::webview_memory;

/// Every Passyble window is kept out of screenshots, screen recordings, screen sharing and the taskbar / Alt+Tab
/// previews, like Android's FLAG_SECURE: always, with no setting. Windows: `SetWindowDisplayAffinity
/// (WDA_EXCLUDEFROMCAPTURE)` (black before Windows 10 2004). macOS: `NSWindow.sharingType = .none`. Linux has no
/// equivalent: X11 lets any program read the screen, and Wayland leaves capture to the compositor's portal.
/// main.rs builds every window with it.
pub const CAPTURE_PROTECTED: bool = true;

/// The titles of the popup windows (taskbar, Alt+Tab) in the active language.
pub fn set_titles(app: &AppHandle) {
    for (label, title) in [
        ("totp", tr!("window.totp_title")),
        ("quickpick", tr!("window.quickpick_title")),
        ("quickaccess", tr!("window.quickaccess_title")),
        ("qrscan", tr!("window.qrscan_title")),
    ] {
        if let Some(window) = app.get_webview_window(label) {
            let _ = window.set_title(&title);
        }
    }
}

/// The user opened the main window (tray icon, Open, Start menu, a second launch, a start without `--background`,
/// "Open in Passyble"): shows it, and its unlock screen may start Windows Hello once (`main-opened`,
/// [`take_auto_hello`]). Anything else that brings the window up uses [`show_main`], which grants nothing.
pub fn open_main(app: &AppHandle) {
    // On screen first: an unlock screen that asks in between gets `false` without using the grant,
    // and asks again on `main-opened`.
    show_main(app);
    if let Some(state) = app.try_state::<Arc<AppState>>() {
        lock(&state.auto_hello).grant(Instant::now());
    }
    let _ = app.emit_to("main", "main-opened", ());
}

/// Whether the main window is on screen: shown and not minimized. Windows Hello is only ever
/// started from it then (its hidden webview reports itself visible, startup.rs).
pub fn main_on_screen(app: &AppHandle) -> bool {
    app.get_webview_window("main")
        .is_some_and(|w| w.is_visible().unwrap_or(false) && !w.is_minimized().unwrap_or(false))
}

/// The unlock screen asks whether it may start Windows Hello by itself: `true` once after the
/// user opened the window ([`open_main`]) while it is on screen; never for a window nobody opened
/// (a start with Windows, sign-in, resume, a lock).
#[tauri::command]
pub fn take_auto_hello(app: AppHandle) -> bool {
    let state = app.state::<Arc<AppState>>();
    let granted = lock(&state.auto_hello).take(Instant::now());
    granted && main_on_screen(&app)
}

pub fn show_main(app: &AppHandle) {
    set_dock_icon(app, true);
    if let Some(window) = app.get_webview_window("main") {
        let shown = window.clone();
        webview_memory::shown(&window, move || {
            let _ = shown.unminimize();
            let _ = shown.show();
            let _ = shown.set_focus();
            platform::bring_to_front(&shown);
        });
    }
}

pub fn hide(app: &AppHandle, label: &str) {
    if label == "main" {
        if let Some(state) = app.try_state::<Arc<AppState>>() {
            lock(&state.auto_hello).clear();
        }
    }
    if label == "main" {
        set_dock_icon(app, false);
    }
    if let Some(window) = app.get_webview_window(label) {
        if label == "totp" {
            // Shown natively without activation; hide it the same way.
            platform::hide_without_activation(&window);
        } else {
            let _ = window.hide();
        }
        webview_memory::hidden(app, label);
    }
}

/// macOS: Passyble is in the Dock (and the app switcher) only while its main window is open;
/// otherwise only the menu bar item is left, like the Windows tray.
#[cfg(target_os = "macos")]
pub fn set_dock_icon(app: &AppHandle, visible: bool) {
    let policy = if visible {
        tauri::ActivationPolicy::Regular
    } else {
        tauri::ActivationPolicy::Accessory
    };
    if let Err(e) = app.set_activation_policy(policy) {
        crate::applog::plog!("Dock icon: {e}");
    }
}

#[cfg(not(target_os = "macos"))]
pub fn set_dock_icon(_app: &AppHandle, _visible: bool) {}

pub fn show_prompt(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("prompt") {
        let shown = window.clone();
        webview_memory::shown(&window, move || {
            let _ = shown.center();
            let _ = shown.show();
            let _ = shown.set_always_on_top(true);
            let _ = shown.set_focus();
            platform::bring_to_front(&shown);
        });
    }
}

pub fn show_totp_popup(app: &AppHandle) {
    let Some(window) = app.get_webview_window("totp") else {
        return;
    };
    let monitor = app
        .cursor_position()
        .ok()
        .and_then(|p| window.monitor_from_point(p.x, p.y).ok().flatten())
        .or_else(|| window.primary_monitor().ok().flatten());
    if let (Some(monitor), Ok(size)) = (monitor, window.outer_size()) {
        let area = monitor.work_area();
        let margin = (12.0 * monitor.scale_factor()) as i32;
        let x = area.position.x + area.size.width as i32 - size.width as i32 - margin;
        let y = area.position.y + area.size.height as i32 - size.height as i32 - margin;
        let _ = window.set_position(PhysicalPosition::new(x, y));
    }
    let shown = window.clone();
    webview_memory::shown(&window, move || platform::show_without_activation(&shown));
}

pub fn show_quickpick(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("quickpick") {
        let shown = window.clone();
        webview_memory::shown(&window, move || {
            let _ = shown.center();
            let _ = shown.show();
            let _ = shown.set_focus();
        });
    }
}

/// Shows window `label`, focused, on the monitor under the cursor (where the user is looking when
/// they press a shortcut): centred across, its top at `from_top` of the monitor's work area.
fn show_on_cursor_monitor(app: &AppHandle, label: &str, from_top: f64) {
    let Some(window) = app.get_webview_window(label) else {
        return;
    };
    let monitor = app
        .cursor_position()
        .ok()
        .and_then(|p| window.monitor_from_point(p.x, p.y).ok().flatten())
        .or_else(|| window.primary_monitor().ok().flatten());
    if let (Some(monitor), Ok(size)) = (monitor, window.outer_size()) {
        let area = monitor.work_area();
        let x = area.position.x + (area.size.width as i32 - size.width as i32) / 2;
        let room = (area.size.height as i32 - size.height as i32).max(0);
        let y = area.position.y + (f64::from(room) * from_top) as i32;
        let _ = window.set_position(PhysicalPosition::new(x, y));
    }
    let shown = window.clone();
    webview_memory::shown(&window, move || {
        let _ = shown.show();
        let _ = shown.set_focus();
        platform::bring_to_front(&shown);
    });
}

pub fn show_quick_access(app: &AppHandle) {
    show_on_cursor_monitor(app, "quickaccess", 0.25);
}

pub fn show_qrscan(app: &AppHandle) {
    show_on_cursor_monitor(app, "qrscan", 0.4);
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    /// main.rs builds every window so the screen-capture protection reaches it: none may be created by Tauri on its
    /// own (`"create": true`). The config says `contentProtected` too, so a window built from it elsewhere is protected.
    #[test]
    fn every_window_is_built_by_the_app_and_kept_out_of_captures() {
        const { assert!(super::CAPTURE_PROTECTED) };
        let config: Value = serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        let windows = config["app"]["windows"].as_array().unwrap();
        let labels: Vec<&str> = windows.iter().filter_map(|w| w["label"].as_str()).collect();
        assert_eq!(
            labels,
            [
                "main",
                "prompt",
                "totp",
                "quickpick",
                "quickaccess",
                "qrscan"
            ]
        );
        for window in windows {
            assert_eq!(window["create"], Value::Bool(false), "{window}");
            assert_eq!(window["contentProtected"], Value::Bool(true), "{window}");
        }
    }

    /// Windows are hidden, never closed or destroyed (Quit lives in the tray): a warm window opens at once. Every show
    /// resumes the webview first and every hide lets it rest (webview_memory.rs); nothing else shows or hides a window.
    #[test]
    fn every_show_and_hide_goes_through_the_webview_memory() {
        let source = include_str!("popups.rs");
        let code = &source[..source.find("#[cfg(test)]").unwrap()];
        assert_eq!(code.matches("webview_memory::shown(&window").count(), 5);
        assert_eq!(
            code.matches("webview_memory::hidden(app, label)").count(),
            1
        );
        assert!(!code.contains("    let _ = window.show();"));
        let main = include_str!("main.rs");
        assert!(main.contains("api.prevent_close();"));
        assert!(main.contains("popups::hide(app, window.label());"));
        assert!(main.contains("webview_memory::built(&handle);"));
        for (name, file) in [
            ("main.rs", main),
            ("ui.rs", include_str!("ui.rs")),
            ("state.rs", include_str!("state.rs")),
            ("autotype.rs", include_str!("autotype.rs")),
            ("commands.rs", include_str!("commands.rs")),
            ("tray.rs", include_str!("tray.rs")),
            ("shortcuts.rs", include_str!("shortcuts.rs")),
            ("quick_access.rs", include_str!("quick_access.rs")),
            ("screen_qr.rs", include_str!("screen_qr.rs")),
        ] {
            for call in [".show()", ".hide()", ".close()", ".destroy()"] {
                assert!(!file.contains(call), "{name} calls {call} on a window");
            }
        }
    }

    /// An event that fills a popup wakes its webview first (a suspended page might not run it).
    #[test]
    fn popup_events_wake_the_webview_first() {
        for (file, label, event) in [
            (include_str!("state.rs"), "prompt", "prompts-changed"),
            (include_str!("autotype.rs"), "quickpick", "quickpick"),
            (include_str!("ui.rs"), "totp", "totp-popup"),
            (
                include_str!("quick_access.rs"),
                "quickaccess",
                "quickaccess",
            ),
            (include_str!("screen_qr.rs"), "qrscan", "qrscan"),
        ] {
            let emit = format!("emit_to(\"{label}\", \"{event}\"");
            let emits = file.matches(&emit).count();
            assert!(emits > 0, "{label}");
            for (at, _) in file.match_indices(&emit) {
                let line_start = file[..at].rfind('\n').unwrap();
                let prev_start = file[..line_start].rfind('\n').unwrap_or(0);
                let previous = &file[prev_start..line_start];
                assert!(
                    previous.contains("webview_memory::wake(") && previous.contains(label),
                    "{label}: {previous}"
                );
            }
        }
    }
}
