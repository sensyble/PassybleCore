//! The webviews' memory while their windows are hidden (in the tray), without making them slower to open: every
//! window stays built and warm (a new WebView2 takes far longer than the ~150 ms an open may take), but a hidden
//! one gives memory back.
//!
//! * A hidden popup, and the main window while the vault is locked, is **suspended** (WebView2 `TrySuspend`, which
//!   also sets the memory target to low). It is resumed before it is shown ([`shown`]) and before an event that
//!   fills it is sent ([`wake`]), so it paints new content on the first frame.
//! * The main window while unlocked is only **trimmed** (scripts keep running): it must hear `lock-state` at once
//!   to drop the list and any revealed secret. If the vault locks while it is hidden, it is suspended too
//!   ([`set_locked`]).
//!
//! The controller's `IsVisible` follows the window so a hidden page knows it is hidden, which WebView2 needs before
//! it suspends. macOS and Linux have no such API: there the windows only stay warm.
//!
//! `PASSYBLE_PERF=1` logs how long each window takes from the show to its first painted frame (`perf:` lines in
//! pass.log).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{LazyLock, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use tauri::{AppHandle, Manager, WebviewWindow};

use crate::state::lock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rest {
    Trim,
    Suspend,
}

/// How a hidden window rests: the main window keeps running while the vault is unlocked (it clears
/// itself on `lock-state`); everything else is suspended.
pub fn rest_for(label: &str, locked: bool) -> Rest {
    if label == "main" && !locked {
        Rest::Trim
    } else {
        Rest::Suspend
    }
}

/// How long a window hidden just now keeps running before it is suspended: its script finishes
/// what the hide started (an answer sent, the list cleared on a lock).
pub const SUSPEND_AFTER: Duration = Duration::from_secs(2);
pub const REST_AFTER_START: Duration = Duration::from_secs(10);

static LOCKED: AtomicBool = AtomicBool::new(true);

/// Per window, how many times it was shown or hidden: a suspend scheduled for one hide is dropped
/// when the window was shown (or hidden again) meanwhile.
#[derive(Default)]
struct Generations(HashMap<String, u64>);

impl Generations {
    fn bump(&mut self, label: &str) -> u64 {
        let g = self.0.entry(label.to_string()).or_insert(0);
        *g += 1;
        *g
    }

    fn current(&self, label: &str) -> u64 {
        self.0.get(label).copied().unwrap_or(0)
    }
}

static GENERATIONS: LazyLock<Mutex<Generations>> = LazyLock::new(Default::default);

static PERF: LazyLock<bool> =
    LazyLock::new(|| std::env::var("PASSYBLE_PERF").is_ok_and(|v| v.trim() == "1"));
static SHOWN_AT: LazyLock<Mutex<HashMap<String, Instant>>> = LazyLock::new(Default::default);

pub fn perf_enabled() -> bool {
    *PERF
}

/// The window is about to be shown: resumes its webview and makes it visible, then runs `show` (on Windows on the
/// UI thread right after, so the window never shows an empty frame).
pub fn shown(window: &WebviewWindow, show: impl FnOnce() + Send + 'static) {
    let label = window.label().to_string();
    lock(&GENERATIONS).bump(&label);
    if perf_enabled() {
        lock(&SHOWN_AT).insert(label, Instant::now());
    }
    imp::wake(window, true, Box::new(show));
}

pub fn hidden(app: &AppHandle, label: &str) {
    rest_later(app, label, SUSPEND_AFTER);
}

pub fn built(app: &AppHandle) {
    for window in app.webview_windows().into_values() {
        rest_later(app, window.label(), REST_AFTER_START);
    }
}

/// Resumes a hidden window's webview before an event that fills it is sent; it rests again if it stays hidden.
pub fn wake(app: &AppHandle, label: &str) {
    let Some(window) = app.get_webview_window(label) else {
        return;
    };
    imp::wake(&window, false, Box::new(|| {}));
    if !window.is_visible().unwrap_or(false) {
        rest_later(app, label, SUSPEND_AFTER);
    }
}

/// The vault locked or unlocked. A main window hidden while it locks is suspended once its page has cleared.
pub fn set_locked(app: &AppHandle, locked: bool) {
    let was = LOCKED.swap(locked, Ordering::Relaxed);
    if locked && !was {
        if let Some(main) = app.get_webview_window("main") {
            if !main.is_visible().unwrap_or(true) {
                rest_later(app, "main", SUSPEND_AFTER);
            }
        }
    }
}

fn rest_later(app: &AppHandle, label: &str, delay: Duration) {
    let Some(window) = app.get_webview_window(label) else {
        return;
    };
    let generation = lock(&GENERATIONS).bump(label);
    let rest = rest_for(label, LOCKED.load(Ordering::Relaxed));
    // Hidden pages stop painting at once; the memory goes after the delay.
    imp::hide(
        &window,
        if rest == Rest::Trim {
            Some(Rest::Trim)
        } else {
            None
        },
    );
    if rest == Rest::Suspend {
        let label = label.to_string();
        thread::spawn(move || {
            thread::sleep(delay);
            if lock(&GENERATIONS).current(&label) != generation
                || window.is_visible().unwrap_or(true)
            {
                return;
            }
            // Locked state may have changed meanwhile (an unlock from the prompt).
            if rest_for(&label, LOCKED.load(Ordering::Relaxed)) == Rest::Suspend {
                imp::hide(&window, Some(Rest::Suspend));
            } else {
                imp::hide(&window, Some(Rest::Trim));
            }
        });
    }
}

#[tauri::command]
pub fn perf_painted(window: WebviewWindow) {
    if !perf_enabled() {
        return;
    }
    let label = window.label().to_string();
    if let Some(at) = lock(&SHOWN_AT).remove(&label) {
        crate::applog::plog!(
            "perf: {label} painted {} ms after show",
            at.elapsed().as_millis()
        );
    }
}

pub fn perf_note(what: &str) {
    if perf_enabled() {
        crate::applog::plog!("perf: {what}");
    }
}

#[cfg(windows)]
mod imp {
    use std::sync::Mutex;

    use tauri::WebviewWindow;
    use webview2_com::Microsoft::Web::WebView2::Win32::{
        ICoreWebView2Controller, ICoreWebView2_19, ICoreWebView2_3,
        COREWEBVIEW2_MEMORY_USAGE_TARGET_LEVEL_LOW, COREWEBVIEW2_MEMORY_USAGE_TARGET_LEVEL_NORMAL,
    };
    use webview2_com::TrySuspendCompletedHandler;
    use windows_core::{Interface, BOOL};

    use super::Rest;

    type Then = Box<dyn FnOnce() + Send>;

    fn with_controller(
        window: &WebviewWindow,
        f: impl FnOnce(&ICoreWebView2Controller) + Send + 'static,
        fallback: Option<Then>,
    ) {
        // Shared so a webview that can't be reached still shows its window.
        let then = std::sync::Arc::new(Mutex::new(fallback));
        let after = then.clone();
        let reached = window.with_webview(move |webview| {
            f(&webview.controller());
            if let Some(show) = after.lock().unwrap_or_else(|e| e.into_inner()).take() {
                show();
            }
        });
        if reached.is_err() {
            if let Some(show) = then.lock().unwrap_or_else(|e| e.into_inner()).take() {
                show();
            }
        }
    }

    pub fn wake(window: &WebviewWindow, visible: bool, then: Then) {
        with_controller(
            window,
            move |controller| unsafe {
                let Ok(core) = controller.CoreWebView2() else {
                    return;
                };
                let mut suspended = BOOL::default();
                let core3 = core.cast::<ICoreWebView2_3>().ok();
                if let Some(core3) = &core3 {
                    let _ = core3.IsSuspended(&mut suspended);
                    if suspended.as_bool() {
                        // Also sets the memory target back to normal.
                        let _ = core3.Resume();
                    }
                }
                if !suspended.as_bool() {
                    if let Ok(core19) = core.cast::<ICoreWebView2_19>() {
                        let _ = core19.SetMemoryUsageTargetLevel(
                            COREWEBVIEW2_MEMORY_USAGE_TARGET_LEVEL_NORMAL,
                        );
                    }
                }
                if visible {
                    let _ = controller.SetIsVisible(true);
                }
            },
            Some(then),
        );
    }

    pub fn hide(window: &WebviewWindow, rest: Option<Rest>) {
        with_controller(
            window,
            move |controller| unsafe {
                let _ = controller.SetIsVisible(false);
                let Ok(core) = controller.CoreWebView2() else {
                    return;
                };
                match rest {
                    None => {}
                    Some(Rest::Trim) => {
                        if let Ok(core19) = core.cast::<ICoreWebView2_19>() {
                            let _ = core19.SetMemoryUsageTargetLevel(
                                COREWEBVIEW2_MEMORY_USAGE_TARGET_LEVEL_LOW,
                            );
                        }
                    }
                    Some(Rest::Suspend) => {
                        if let Ok(core3) = core.cast::<ICoreWebView2_3>() {
                            let handler =
                                TrySuspendCompletedHandler::create(Box::new(|_, _| Ok(())));
                            let _ = core3.TrySuspend(&handler);
                        }
                    }
                }
            },
            None,
        );
    }
}

#[cfg(not(windows))]
mod imp {
    use tauri::WebviewWindow;

    use super::Rest;

    pub fn wake(_window: &WebviewWindow, _visible: bool, then: Box<dyn FnOnce() + Send>) {
        then();
    }

    pub fn hide(_window: &WebviewWindow, _rest: Option<Rest>) {}
}

/// WebView2's start-up arguments, shared by every window (one browser process, so they must agree): wry's
/// defaults, with all windows in one renderer process (they are all Passyble's own pages, one origin).
#[cfg(windows)]
pub const BROWSER_ARGS: &str =
    "--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection --renderer-process-limit=1";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hidden_popups_are_suspended_and_main_only_while_locked() {
        for label in ["prompt", "totp", "quickpick"] {
            assert_eq!(rest_for(label, false), Rest::Suspend, "{label}");
            assert_eq!(rest_for(label, true), Rest::Suspend, "{label}");
        }
        // Unlocked, the main window must keep running to clear itself on `lock-state`.
        assert_eq!(rest_for("main", false), Rest::Trim);
        assert_eq!(rest_for("main", true), Rest::Suspend);
    }

    #[test]
    fn a_show_or_new_hide_cancels_a_pending_suspend() {
        let mut g = Generations::default();
        let hide = g.bump("prompt");
        assert_eq!(g.current("prompt"), hide);
        // Shown again before the delay ran out: the scheduled suspend sees another generation.
        g.bump("prompt");
        assert_ne!(g.current("prompt"), hide);
        // Other windows count on their own.
        assert_eq!(g.current("totp"), 0);
    }

    #[test]
    fn suspend_waits_for_the_page_to_finish() {
        assert!(SUSPEND_AFTER >= Duration::from_secs(1));
        assert!(REST_AFTER_START > SUSPEND_AFTER);
    }

    #[cfg(windows)]
    #[test]
    fn browser_args_keep_wrys_defaults() {
        assert!(BROWSER_ARGS
            .starts_with("--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection"));
        assert!(BROWSER_ARGS.contains("--renderer-process-limit=1"));
    }
}
