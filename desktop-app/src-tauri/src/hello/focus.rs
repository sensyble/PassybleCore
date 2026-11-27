//! Keeping Windows' Hello dialog in front: finding it among the top-level windows, the timing of
//! the foreground attempts, and the registry of Hello prompts in progress. Pure logic;
//! `platform::win32` does the Win32 calls.
//!
//! Windows behaviour (checked on Windows 11 build 26300):
//! * The dialog is a top-level `Credential Dialog Xaml Host` window of `CredentialUIBroker.exe`. With
//!   an owner window (`Request*ForWindowAsync`) it is owned by it (modal, no taskbar button);
//!   without one it is a separate window with its own taskbar button.
//! * It does not take the foreground by itself when the app isn't in front. Once the owner is the
//!   foreground window, `SetForegroundWindow` on the dialog works within ~0.3 s.
//! * `IAsyncOperation::Cancel` completes the operation at once but the dialog stays on screen until
//!   the user closes it, so cancel is a last resort.

#![cfg_attr(not(windows), allow(dead_code))]

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Serialize;

pub const DIALOG_CLASS: &str = "Credential Dialog Xaml Host";
pub const BROKER_EXE: &str = "CredentialUIBroker.exe";

/// How long the dialog may stay out of the foreground (or not show up) before the prompt window offers other choices.
pub const FOCUS_TIMEOUT: Duration = Duration::from_secs(2);
/// After this long without the foreground, one attempt with the ALT-key fallback.
pub const HARD_AFTER: Duration = Duration::from_millis(1000);
const FORCE_EVERY: Duration = Duration::from_millis(150);

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TopWindow {
    pub hwnd: isize,
    pub class: String,
    /// Executable file name of the owning process (only needed for [`DIALOG_CLASS`] windows).
    pub exe: String,
    pub owner: isize,
    pub visible: bool,
}

pub trait WindowSource {
    fn top_windows(&self) -> Vec<TopWindow>;
}

fn is_hello_dialog(w: &TopWindow) -> bool {
    w.visible && w.class == DIALOG_CLASS && w.exe.eq_ignore_ascii_case(BROKER_EXE)
}

/// Hello dialogs on screen now (taken before a request, so they aren't mistaken for ours).
pub fn hello_dialogs(source: &dyn WindowSource) -> Vec<isize> {
    source
        .top_windows()
        .iter()
        .filter(|w| is_hello_dialog(w))
        .map(|w| w.hwnd)
        .collect()
}

/// The Hello dialog of our request: one owned by `owner`, else the first new one (not in `ignore`).
/// Windows sets the owner only once the dialog has loaded, so a new unowned one counts too.
pub fn find_dialog(windows: &[TopWindow], owner: Option<isize>, ignore: &[isize]) -> Option<isize> {
    let candidates = || windows.iter().filter(|w| is_hello_dialog(w));
    if let Some(owner) = owner.filter(|o| *o != 0) {
        if let Some(w) = candidates().find(|w| w.owner == owner) {
            return Some(w.hwnd);
        }
    }
    candidates()
        .find(|w| !ignore.contains(&w.hwnd) && (w.owner == 0 || Some(w.owner) == owner))
        .map(|w| w.hwnd)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HelloFocus {
    Starting,
    Shown,
    /// The dialog has the foreground (and with it the keyboard: PIN field, face, fingerprint).
    Focused,
    Unfocused,
    /// No dialog appeared within [`FOCUS_TIMEOUT`].
    NotShown,
}

impl HelloFocus {
    pub fn stalled(self) -> bool {
        matches!(self, Self::Unfocused | Self::NotShown)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FocusAction {
    None,
    Force(isize),
    ForceHard(isize),
}

/// The timing of the foreground attempts, fed every ~50 ms with what is on screen.
#[derive(Debug)]
pub struct FocusWatch {
    started: Instant,
    shown: Option<(isize, Instant)>,
    last_force: Option<Instant>,
    hard_done: bool,
    state: HelloFocus,
}

impl FocusWatch {
    pub fn new(now: Instant) -> Self {
        Self {
            started: now,
            shown: None,
            last_force: None,
            hard_done: false,
            state: HelloFocus::Starting,
        }
    }

    pub fn state(&self) -> HelloFocus {
        self.state
    }

    pub fn tick(
        &mut self,
        now: Instant,
        dialog: Option<isize>,
        foreground: Option<isize>,
    ) -> FocusAction {
        if self.state == HelloFocus::Focused {
            return FocusAction::None;
        }
        let Some(dialog) = dialog else {
            // Gone again (answered: the operation completes) or not there yet.
            if self.shown.is_none() && now.duration_since(self.started) >= FOCUS_TIMEOUT {
                self.state = HelloFocus::NotShown;
            }
            return FocusAction::None;
        };
        let since = match self.shown {
            Some((hwnd, since)) if hwnd == dialog => since,
            _ => {
                self.shown = Some((dialog, now));
                self.hard_done = false;
                self.last_force = None;
                self.state = HelloFocus::Shown;
                now
            }
        };
        if foreground == Some(dialog) {
            self.state = HelloFocus::Focused;
            return FocusAction::None;
        }
        let shown_for = now.duration_since(since);
        if shown_for >= FOCUS_TIMEOUT {
            // Stop pushing; the user can still click it (it stays above its owner).
            self.state = HelloFocus::Unfocused;
            return FocusAction::None;
        }
        if self
            .last_force
            .is_some_and(|t| now.duration_since(t) < FORCE_EVERY)
        {
            return FocusAction::None;
        }
        self.last_force = Some(now);
        if shown_for >= HARD_AFTER && !self.hard_done {
            self.hard_done = true;
            FocusAction::ForceHard(dialog)
        } else {
            FocusAction::Force(dialog)
        }
    }
}

/// One Windows Hello prompt in progress. The platform code polls [`Attempt::cancelled`] and publishes [`HelloFocus`] changes.
#[derive(Debug)]
pub struct Attempt {
    id: u64,
    owner: Option<isize>,
    cancel: AtomicBool,
    state: Mutex<HelloFocus>,
}

impl Attempt {
    pub fn cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }

    pub fn set_state(&self, state: HelloFocus) {
        *self.state.lock().unwrap_or_else(|p| p.into_inner()) = state;
    }

    pub fn state(&self) -> HelloFocus {
        *self.state.lock().unwrap_or_else(|p| p.into_inner())
    }
}

static ACTIVE: Mutex<Vec<Arc<Attempt>>> = Mutex::new(Vec::new());
static NEXT: AtomicU64 = AtomicU64::new(1);

fn active() -> std::sync::MutexGuard<'static, Vec<Arc<Attempt>>> {
    ACTIVE.lock().unwrap_or_else(|p| p.into_inner())
}

pub fn begin(owner: Option<isize>) -> AttemptGuard {
    let attempt = Arc::new(Attempt {
        id: NEXT.fetch_add(1, Ordering::Relaxed),
        owner,
        cancel: AtomicBool::new(false),
        state: Mutex::new(HelloFocus::Starting),
    });
    active().push(attempt.clone());
    AttemptGuard(attempt)
}

pub struct AttemptGuard(Arc<Attempt>);

impl AttemptGuard {
    /// The attempt, for a thread that follows its dialog (it may outlive the guard).
    pub fn shared(&self) -> Arc<Attempt> {
        self.0.clone()
    }
}

impl std::ops::Deref for AttemptGuard {
    type Target = Attempt;
    fn deref(&self) -> &Attempt {
        &self.0
    }
}

impl Drop for AttemptGuard {
    fn drop(&mut self) {
        let id = self.0.id;
        active().retain(|a| a.id != id);
    }
}

pub fn cancel(owner: Option<isize>) -> bool {
    let mut any = false;
    for attempt in active().iter().filter(|a| a.owner == owner) {
        attempt.cancel.store(true, Ordering::Relaxed);
        any = true;
    }
    any
}

pub fn status(owner: Option<isize>) -> Option<HelloFocus> {
    active()
        .iter()
        .rev()
        .find(|a| a.owner == owner)
        .map(|a| a.state())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dialog(hwnd: isize, owner: isize) -> TopWindow {
        TopWindow {
            hwnd,
            class: DIALOG_CLASS.into(),
            exe: "credentialuibroker.exe".into(),
            owner,
            visible: true,
        }
    }

    struct Fake(Vec<TopWindow>);

    impl WindowSource for Fake {
        fn top_windows(&self) -> Vec<TopWindow> {
            self.0.clone()
        }
    }

    #[test]
    fn finds_our_dialog() {
        let browser = TopWindow {
            hwnd: 1,
            class: "Chrome_WidgetWin_1".into(),
            exe: "brave.exe".into(),
            visible: true,
            ..Default::default()
        };
        let impostor = TopWindow {
            exe: "evil.exe".into(),
            ..dialog(2, 0)
        };
        let hidden = TopWindow {
            visible: false,
            ..dialog(3, 0)
        };
        let old = dialog(4, 0);
        let source = Fake(vec![
            browser.clone(),
            impostor.clone(),
            hidden.clone(),
            old.clone(),
        ]);
        let before = hello_dialogs(&source);
        assert_eq!(before, vec![4]);

        assert_eq!(find_dialog(&source.top_windows(), Some(77), &before), None);
        let mut windows = source.top_windows();
        windows.push(dialog(5, 0));
        assert_eq!(find_dialog(&windows, Some(77), &before), Some(5));
        let other = vec![browser.clone(), dialog(6, 99)];
        assert_eq!(find_dialog(&other, Some(77), &[]), None);
        let owned = vec![old, dialog(7, 0), dialog(8, 77)];
        assert_eq!(find_dialog(&owned, Some(77), &[8]), Some(8));
        assert_eq!(find_dialog(&owned, None, &[4]), Some(7));
        assert_eq!(find_dialog(&[browser, impostor, hidden], None, &[]), None);
    }

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn focus_watch_forces_then_stops_once_focused() {
        let t = Instant::now();
        let mut w = FocusWatch::new(t);
        assert_eq!(w.tick(t, None, Some(1)), FocusAction::None);
        assert_eq!(w.state(), HelloFocus::Starting);
        assert_eq!(w.tick(t + ms(100), Some(9), Some(1)), FocusAction::Force(9));
        assert_eq!(w.state(), HelloFocus::Shown);
        assert_eq!(w.tick(t + ms(150), Some(9), Some(1)), FocusAction::None);
        assert_eq!(w.tick(t + ms(260), Some(9), Some(1)), FocusAction::Force(9));
        assert_eq!(w.tick(t + ms(400), Some(9), Some(9)), FocusAction::None);
        assert_eq!(w.state(), HelloFocus::Focused);
        assert_eq!(w.tick(t + ms(500), Some(9), Some(1)), FocusAction::None);
        assert_eq!(w.state(), HelloFocus::Focused);
    }

    #[test]
    fn focus_watch_alt_fallback_then_unfocused() {
        let t = Instant::now();
        let mut w = FocusWatch::new(t);
        let mut hard = 0;
        let mut step = 0;
        while step <= 1900 {
            match w.tick(t + ms(step), Some(9), Some(1)) {
                FocusAction::ForceHard(9) => {
                    hard += 1;
                    assert!(ms(step) >= HARD_AFTER);
                }
                FocusAction::Force(9) | FocusAction::None => {}
                other => panic!("{other:?}"),
            }
            step += 50;
        }
        assert_eq!(hard, 1, "the ALT fallback is tried once");
        assert_eq!(w.state(), HelloFocus::Shown);
        assert_eq!(w.tick(t + ms(2000), Some(9), Some(1)), FocusAction::None);
        assert_eq!(w.state(), HelloFocus::Unfocused);
        assert!(w.state().stalled());
        assert_eq!(w.tick(t + ms(5000), Some(9), Some(9)), FocusAction::None);
        assert_eq!(w.state(), HelloFocus::Focused);
    }

    #[test]
    fn focus_watch_reports_missing_dialog_and_recovers() {
        let t = Instant::now();
        let mut w = FocusWatch::new(t);
        assert_eq!(w.tick(t + ms(1999), None, None), FocusAction::None);
        assert_eq!(w.state(), HelloFocus::Starting);
        assert_eq!(w.tick(t + ms(2000), None, None), FocusAction::None);
        assert_eq!(w.state(), HelloFocus::NotShown);
        assert!(w.state().stalled());
        assert_eq!(w.tick(t + ms(3000), Some(5), None), FocusAction::Force(5));
        assert_eq!(w.state(), HelloFocus::Shown);
        assert_eq!(
            w.tick(t + ms(4900), Some(5), None),
            FocusAction::ForceHard(5)
        );
        assert_eq!(w.tick(t + ms(5000), Some(5), None), FocusAction::None);
        assert_eq!(w.state(), HelloFocus::Unfocused);
        assert_eq!(w.tick(t + ms(5100), Some(6), None), FocusAction::Force(6));
        assert_eq!(w.state(), HelloFocus::Shown);
    }

    #[test]
    fn attempts_are_cancelled_per_owner() {
        let a = begin(Some(1001));
        let b = begin(Some(1002));
        assert_eq!(status(Some(1001)), Some(HelloFocus::Starting));
        a.set_state(HelloFocus::Unfocused);
        assert_eq!(status(Some(1001)), Some(HelloFocus::Unfocused));
        assert!(cancel(Some(1001)));
        assert!(a.cancelled() && !b.cancelled());
        drop(a);
        assert_eq!(status(Some(1001)), None);
        assert!(!cancel(Some(1001)));
        assert_eq!(status(Some(1002)), Some(HelloFocus::Starting));
    }
}
