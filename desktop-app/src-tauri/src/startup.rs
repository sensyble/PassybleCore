//! Who opened the main window, and with it whether its unlock screen may start Windows Hello by itself.
//!
//! Windows Hello never shows unless the user just asked for something that needs it. Passyble starts with Windows as
//! `Pass.exe --background` (tray only) with its main window already created, hidden; the webview inside reports itself
//! visible even then (wry), so the page can't tell. Instead the unlock screen starts Windows Hello only with a one-time
//! grant ([`AutoHello`]) that `popups::open_main` gives when the user opens the window (tray icon, Start menu, a second
//! launch, a start without `--background`, a restart or update the user chose, "Open in Passyble"). A start with
//! Windows, sign-in, resume, a lock and Windows Hello turning available later (`hello-available`) give none.

use std::time::{Duration, Instant};

/// `--background` (the Run key entry, the native messaging host) and `--passkey-provider` (COM,
/// for a Windows passkey request) start Passyble in the tray, without its window.
pub fn tray_only<S: AsRef<str>>(args: impl IntoIterator<Item = S>) -> bool {
    args.into_iter().any(|a| {
        let a = a.as_ref();
        a == "--background" || a == crate::passkey_provider::LAUNCH_ARG
    })
}

/// How long the "show the window on the next start" marker of a restart or update counts: the relaunch follows within
/// seconds (an update's installer within a minute or two). An older one was left behind and is ignored, so a later
/// start with Windows stays in the tray.
pub const RESTART_MARKER_TTL: Duration = Duration::from_secs(5 * 60);

/// Whether the main window opens at start-up. `tray_only`: started with `--background` or
/// `--passkey-provider`; `start_minimized`: the "Start in the tray" setting; `restart_marker`:
/// the age of the marker a restart or an update the user chose left (`None`: there is none).
pub fn window_at_start(
    tray_only: bool,
    start_minimized: bool,
    restart_marker: Option<Duration>,
) -> bool {
    if restart_marker.is_some_and(|age| age <= RESTART_MARKER_TTL) {
        return true;
    }
    !(tray_only || start_minimized)
}

/// How long the grant of a window the user opened stays good when Windows Hello isn't ready yet: right after Windows
/// sign-in it can take half a minute to report itself available (`main.rs`, `HELLO_CHECKS`).
pub const AUTO_HELLO_TTL: Duration = Duration::from_secs(90);

/// The one-time permission for the main window's unlock screen to start Windows Hello by itself: given when the
/// user opens the window ([`AutoHello::grant`]), taken by the unlock screen (`take_auto_hello`), and dropped when the
/// window hides, the vault locks or unlocks (a lock is never the user asking), and after [`AUTO_HELLO_TTL`].
#[derive(Debug, Default)]
pub struct AutoHello {
    granted: Option<Instant>,
}

impl AutoHello {
    pub fn grant(&mut self, now: Instant) {
        self.granted = Some(now);
    }

    pub fn clear(&mut self) {
        self.granted = None;
    }

    pub fn take(&mut self, now: Instant) -> bool {
        self.granted
            .take()
            .is_some_and(|at| now.saturating_duration_since(at) <= AUTO_HELLO_TTL)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tray_only_for_background_and_passkey_starts() {
        assert!(tray_only(["Pass.exe", "--background"]));
        assert!(tray_only(["Pass.exe", crate::passkey_provider::LAUNCH_ARG]));
        assert!(!tray_only(["Pass.exe"]));
        assert!(!tray_only(["Pass.exe", "pass+server://example.com"]));
        assert!(!tray_only(Vec::<String>::new()));
    }

    #[test]
    fn a_start_with_windows_keeps_the_window_hidden() {
        assert!(!window_at_start(true, false, None));
        assert!(!window_at_start(true, true, None));
        assert!(!window_at_start(false, true, None));
        assert!(window_at_start(false, false, None));
    }

    #[test]
    fn a_restart_the_user_chose_shows_the_window_but_a_stale_marker_does_not() {
        assert!(window_at_start(true, false, Some(Duration::from_secs(3))));
        assert!(window_at_start(true, true, Some(RESTART_MARKER_TTL)));
        assert!(!window_at_start(
            true,
            false,
            Some(RESTART_MARKER_TTL + Duration::from_secs(1))
        ));
        assert!(window_at_start(
            false,
            false,
            Some(Duration::from_secs(86_400))
        ));
    }

    #[test]
    fn no_grant_no_windows_hello() {
        let mut auto = AutoHello::default();
        assert!(!auto.take(Instant::now()));
    }

    #[test]
    fn a_grant_is_taken_once() {
        let mut auto = AutoHello::default();
        let now = Instant::now();
        auto.grant(now);
        assert!(auto.take(now + Duration::from_secs(1)));
        assert!(!auto.take(now + Duration::from_secs(2)));
    }

    #[test]
    fn a_grant_waits_for_windows_hello_for_a_while_only() {
        let now = Instant::now();
        let mut auto = AutoHello::default();
        auto.grant(now);
        assert!(auto.take(now + Duration::from_secs(30)));
        auto.grant(now);
        assert!(!auto.take(now + AUTO_HELLO_TTL + Duration::from_secs(1)));
    }

    #[test]
    fn hiding_or_a_lock_drops_the_grant() {
        let now = Instant::now();
        let mut auto = AutoHello::default();
        auto.grant(now);
        auto.clear();
        assert!(!auto.take(now));
    }
}
