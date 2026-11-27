//! When the sync thread (background.rs) talks to the sync server: the check interval for what the
//! user is doing, the jitter, and the backoff after failures. Pure: every function takes the time
//! (`now`) and the random numbers it needs, so the tests run it with a fake clock.
//!
//! Google Drive: a check of an unchanged vault is one small metadata request and the file is
//! downloaded only when its version changed, so checks can be frequent: every 20 s while a Pass
//! window has focus or the vault was used in the last 2 min, every 2 min while the user is active
//! on the PC (last 15 min), every 15 min when idle. Plus a check right away on unlock, window focus,
//! wake from sleep and the extension asking for logins, each skipped when the last check is under
//! 20 s old. Every interval gets +-20 % jitter so devices that woke together don't stay in step.
//! Rate limits (403 `rateLimitExceeded` / `userRateLimitExceeded`, or 429): exponential backoff
//! with jitter (30 s doubling, at most 15 min), and for the next hour the focused interval is 2 min.
//!
//! Passyble Cloud on a live plan (a conditional `GET` answered `304` when nothing changed): 60 s
//! while focused or active, 5 min when idle and for an hour after a 429; the same right-away
//! checks, skipped when the last check is under 15 s old; backoff 30 s doubling, at most 10 min.
//!
//! WebDAV and Passyble Server have a calmer schedule (a check every 30 min while the vault is in
//! use, a focus check when the last one is over 5 min old, backoff up to 1 h); an edit goes up
//! after the same [`EDIT_DEBOUNCE`].

use std::time::{Duration, Instant};

/// How long edits must have stopped before they are uploaded (a burst of edits is one upload).
pub const EDIT_DEBOUNCE: Duration = Duration::from_secs(2);

pub const DRIVE_FOCUSED: Duration = Duration::from_secs(20);
pub const DRIVE_ACTIVE: Duration = Duration::from_secs(2 * 60);
pub const DRIVE_IDLE: Duration = Duration::from_secs(15 * 60);
pub const DRIVE_FOCUSED_THROTTLED: Duration = Duration::from_secs(2 * 60);
pub const THROTTLE_FOR: Duration = Duration::from_secs(60 * 60);
/// Google Drive: focus, wake-up and extension checks are skipped when the last check is this recent.
pub const DRIVE_NUDGE_GAP: Duration = Duration::from_secs(20);

/// "In use": the vault was used (an action in a window, a browser fill) this recently.
pub const IN_USE: Duration = Duration::from_secs(2 * 60);
pub const USER_ACTIVE: Duration = Duration::from_secs(15 * 60);

/// WebDAV and Passyble Server: the periodic check, only while the vault was used within
/// [`OTHER_IN_USE`].
pub const OTHER_CHECK: Duration = Duration::from_secs(30 * 60);
pub const OTHER_IN_USE: Duration = Duration::from_secs(30 * 60);
/// WebDAV and Passyble Server: focus and wake-up checks are skipped when the server was asked
/// this recently.
pub const OTHER_NUDGE_GAP: Duration = Duration::from_secs(5 * 60);

pub const CLOUD_CHECK: Duration = Duration::from_secs(60);
pub const CLOUD_IDLE: Duration = Duration::from_secs(5 * 60);
pub const CLOUD_CHECK_THROTTLED: Duration = Duration::from_secs(5 * 60);
pub const CLOUD_NUDGE_GAP: Duration = Duration::from_secs(15);

pub const BACKOFF_START: Duration = Duration::from_secs(30);
pub const DRIVE_BACKOFF_MAX: Duration = Duration::from_secs(15 * 60);
pub const OTHER_BACKOFF_MAX: Duration = Duration::from_secs(60 * 60);
pub const CLOUD_BACKOFF_MAX: Duration = Duration::from_secs(10 * 60);

/// Every interval and backoff is scaled by a random factor in `1 +- JITTER`.
pub const JITTER: f64 = 0.2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Backend {
    GoogleDrive,
    Cloud,
    /// WebDAV, Passyble Server, or Passyble Cloud without a live plan: the calmer schedule.
    Other,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Activity {
    Focused,
    Active,
    Idle,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Signals {
    pub window_focused: bool,
    pub vault_idle: Duration,
    /// Time since the last keyboard or mouse input, if the platform tells; otherwise the vault's own use stands in.
    pub user_idle: Option<Duration>,
}

pub fn activity(s: Signals) -> Activity {
    if s.window_focused || s.vault_idle < IN_USE {
        Activity::Focused
    } else if s.user_idle.unwrap_or(s.vault_idle) < USER_ACTIVE {
        Activity::Active
    } else {
        Activity::Idle
    }
}

/// The periodic check's interval before jitter; `None`: no periodic check now.
pub fn check_interval(
    backend: Backend,
    activity: Activity,
    throttled: bool,
    vault_idle: Duration,
) -> Option<Duration> {
    match backend {
        Backend::GoogleDrive => Some(match activity {
            Activity::Focused if throttled => DRIVE_FOCUSED_THROTTLED,
            Activity::Focused => DRIVE_FOCUSED,
            Activity::Active => DRIVE_ACTIVE,
            Activity::Idle => DRIVE_IDLE,
        }),
        Backend::Cloud => Some(match activity {
            Activity::Idle => CLOUD_IDLE,
            _ if throttled => CLOUD_CHECK_THROTTLED,
            _ => CLOUD_CHECK,
        }),
        Backend::Other => (vault_idle < OTHER_IN_USE).then_some(OTHER_CHECK),
    }
}

pub fn nudge_gap(backend: Backend) -> Duration {
    match backend {
        Backend::GoogleDrive => DRIVE_NUDGE_GAP,
        Backend::Cloud => CLOUD_NUDGE_GAP,
        Backend::Other => OTHER_NUDGE_GAP,
    }
}

/// `base` scaled by a factor in `[1 - JITTER, 1 + JITTER]`; `unit` is a random number in `[0, 1]`.
pub fn jitter(base: Duration, unit: f64) -> Duration {
    let unit = if unit.is_finite() {
        unit.clamp(0.0, 1.0)
    } else {
        0.5
    };
    base.mul_f64(1.0 - JITTER + 2.0 * JITTER * unit)
}

/// The wait after the `failures`-th failure in a row: [`BACKOFF_START`] doubling, jittered, never
/// above the backend's maximum (15 min for Google Drive, 10 min for Passyble Cloud).
pub fn backoff(backend: Backend, failures: u32, unit: f64) -> Duration {
    let max = match backend {
        Backend::GoogleDrive => DRIVE_BACKOFF_MAX,
        Backend::Cloud => CLOUD_BACKOFF_MAX,
        Backend::Other => OTHER_BACKOFF_MAX,
    };
    let doubled = BACKOFF_START.saturating_mul(1 << failures.saturating_sub(1).min(16));
    jitter(doubled.min(max), unit).min(max)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Ok,
    Failed,
    /// Google Drive refused for the rate (403 `rateLimitExceeded` / `userRateLimitExceeded`, 429),
    /// or Passyble Cloud answered 429.
    RateLimited,
}

#[derive(Clone, Copy, Debug)]
pub struct Schedule {
    pub last_ok: Option<Instant>,
    pub failures: u32,
    pub retry_at: Option<Instant>,
    /// A rate limit widens the focused interval until then.
    pub throttled_until: Option<Instant>,
    /// Rate limits since the app started (for support: logged, never anything secret).
    pub rate_limits: u32,
    /// The random factor of the interval until the next periodic check (`[0, 1]`, see [`jitter`]),
    /// drawn after each sync.
    pub jitter_unit: f64,
}

impl Schedule {
    pub const fn new() -> Self {
        Self {
            last_ok: None,
            failures: 0,
            retry_at: None,
            throttled_until: None,
            rate_limits: 0,
            jitter_unit: 0.5,
        }
    }

    pub fn backed_off(&self, now: Instant) -> bool {
        self.retry_at.is_some_and(|t| now < t)
    }

    pub fn throttled(&self, now: Instant) -> bool {
        self.throttled_until.is_some_and(|t| now < t)
    }

    pub fn since_ok(&self, now: Instant, gap: Duration) -> bool {
        self.last_ok
            .is_none_or(|t| now.saturating_duration_since(t) >= gap)
    }

    /// The periodic check is due: `interval` (before jitter) has passed since the last successful sync.
    pub fn check_due(&self, now: Instant, interval: Option<Duration>) -> bool {
        interval.is_some_and(|i| self.since_ok(now, jitter(i, self.jitter_unit)))
    }

    /// Notes how a sync ended. `units`: two random numbers in `[0, 1]` (backoff jitter, next interval). Returns the backoff on failure.
    pub fn record(
        &mut self,
        now: Instant,
        backend: Backend,
        outcome: Outcome,
        units: (f64, f64),
    ) -> Option<Duration> {
        self.jitter_unit = units.1;
        if outcome == Outcome::Ok {
            self.last_ok = Some(now);
            self.failures = 0;
            self.retry_at = None;
            return None;
        }
        self.failures = self.failures.saturating_add(1);
        if outcome == Outcome::RateLimited {
            self.rate_limits = self.rate_limits.saturating_add(1);
            self.throttled_until = Some(now + THROTTLE_FOR);
        }
        let delay = backoff(backend, self.failures, units.0);
        self.retry_at = Some(now + delay);
        Some(delay)
    }
}

/// A random number in `[0, 1]` for the jitter (not for anything secret).
pub fn random_unit() -> f64 {
    rand::random::<f64>()
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: Duration = Duration::from_secs(1);
    const MIN: Duration = Duration::from_secs(60);

    fn signals(window_focused: bool, vault_idle: Duration, user_idle: Option<Duration>) -> Signals {
        Signals {
            window_focused,
            vault_idle,
            user_idle,
        }
    }

    #[test]
    fn activity_follows_the_window_the_vault_and_the_user() {
        let long = 3 * 60 * MIN;
        assert_eq!(activity(signals(true, long, Some(long))), Activity::Focused);
        // A fill from the browser extension a minute ago, window in the background.
        assert_eq!(activity(signals(false, MIN, Some(long))), Activity::Focused);
        assert_eq!(
            activity(signals(false, 5 * MIN, Some(10 * S))),
            Activity::Active
        );
        assert_eq!(
            activity(signals(false, 5 * MIN, Some(20 * MIN))),
            Activity::Idle
        );
        // No input timer on this platform: the vault's own use stands in.
        assert_eq!(activity(signals(false, 5 * MIN, None)), Activity::Active);
        assert_eq!(activity(signals(false, 20 * MIN, None)), Activity::Idle);
    }

    #[test]
    fn google_drive_intervals_per_state() {
        let d = |a, throttled| check_interval(Backend::GoogleDrive, a, throttled, 99 * MIN);
        assert_eq!(d(Activity::Focused, false), Some(20 * S));
        assert_eq!(d(Activity::Active, false), Some(2 * MIN));
        assert_eq!(d(Activity::Idle, false), Some(15 * MIN));
        // After a rate limit, only the focused interval widens.
        assert_eq!(d(Activity::Focused, true), Some(2 * MIN));
        assert_eq!(d(Activity::Idle, true), Some(15 * MIN));
        assert_eq!(nudge_gap(Backend::GoogleDrive), 20 * S);
    }

    #[test]
    fn other_backends_keep_their_calm_schedule() {
        let o = |vault_idle| check_interval(Backend::Other, Activity::Focused, false, vault_idle);
        assert_eq!(o(10 * MIN), Some(30 * MIN));
        assert_eq!(o(31 * MIN), None);
        assert_eq!(nudge_gap(Backend::Other), 5 * MIN);
        assert_eq!(backoff(Backend::Other, 30, 1.0), 60 * MIN);
    }

    #[test]
    fn passyble_cloud_checks_every_minute_while_in_use_and_every_five_when_idle() {
        let c = |a, throttled| check_interval(Backend::Cloud, a, throttled, 99 * MIN);
        assert_eq!(c(Activity::Focused, false), Some(60 * S));
        assert_eq!(c(Activity::Active, false), Some(60 * S));
        assert_eq!(c(Activity::Idle, false), Some(5 * MIN));
        // After a rate limit the minute becomes 5 min.
        assert_eq!(c(Activity::Focused, true), Some(5 * MIN));
        assert_eq!(c(Activity::Active, true), Some(5 * MIN));
        assert_eq!(c(Activity::Idle, true), Some(5 * MIN));
        // Unlike Other, an unused vault keeps its checks.
        assert_eq!(
            check_interval(Backend::Cloud, Activity::Idle, false, 3 * 60 * MIN),
            Some(5 * MIN)
        );
        assert_eq!(nudge_gap(Backend::Cloud), 15 * S);
    }

    #[test]
    fn the_other_backends_keep_their_numbers() {
        let d = |a| check_interval(Backend::GoogleDrive, a, false, 99 * MIN);
        assert_eq!(d(Activity::Focused), Some(20 * S));
        assert_eq!(d(Activity::Active), Some(2 * MIN));
        assert_eq!(d(Activity::Idle), Some(15 * MIN));
        let o = |a, vault_idle| check_interval(Backend::Other, a, false, vault_idle);
        assert_eq!(o(Activity::Focused, MIN), Some(30 * MIN));
        assert_eq!(o(Activity::Idle, 29 * MIN), Some(30 * MIN));
        assert_eq!(o(Activity::Focused, 30 * MIN), None);
        assert_eq!(nudge_gap(Backend::GoogleDrive), 20 * S);
        assert_eq!(nudge_gap(Backend::Other), 5 * MIN);
        assert_eq!(backoff(Backend::GoogleDrive, 40, 1.0), 15 * MIN);
        assert_eq!(backoff(Backend::Other, 40, 1.0), 60 * MIN);
        assert_eq!(EDIT_DEBOUNCE, 2 * S);
    }

    #[test]
    fn passyble_cloud_backoff_doubles_up_to_ten_minutes() {
        let b = |n, unit| backoff(Backend::Cloud, n, unit);
        assert_eq!(b(1, 0.5), 30 * S);
        assert_eq!(b(2, 0.5), 60 * S);
        assert_eq!(b(3, 0.5), 2 * MIN);
        assert_eq!(b(4, 0.5), 4 * MIN);
        assert_eq!(b(5, 0.5), 8 * MIN);
        assert_eq!(b(6, 0.5), 10 * MIN);
        assert_eq!(b(1, 0.0), 24 * S);
        assert_eq!(b(1, 1.0), 36 * S);
        for n in 6..40 {
            assert!(b(n, 1.0) <= 10 * MIN);
            assert!(b(n, 0.0) >= 8 * MIN);
        }
        assert_eq!(b(u32::MAX, 1.0), 10 * MIN);
    }

    #[test]
    fn a_passyble_cloud_rate_limit_slows_its_checks_to_five_minutes_for_an_hour() {
        let t0 = Instant::now();
        let mut s = Schedule::new();
        assert_eq!(
            s.record(t0, Backend::Cloud, Outcome::RateLimited, (0.5, 0.5)),
            Some(30 * S)
        );
        let t1 = t0 + 30 * S;
        assert_eq!(s.record(t1, Backend::Cloud, Outcome::Ok, (0.5, 0.5)), None);
        let due = |s: &Schedule, now| {
            let throttled = s.throttled(now);
            let interval =
                check_interval(Backend::Cloud, Activity::Focused, throttled, Duration::ZERO);
            s.check_due(now, interval)
        };
        assert!(!due(&s, t1 + 2 * MIN));
        assert!(due(&s, t1 + 5 * MIN));
        // An hour after the rate limit: every minute again.
        let later = t0 + 61 * MIN;
        s.record(later, Backend::Cloud, Outcome::Ok, (0.5, 0.5));
        assert!(!s.throttled(later));
        assert!(!due(&s, later + 59 * S));
        assert!(due(&s, later + 60 * S));
    }

    #[test]
    fn jitter_stays_within_twenty_percent() {
        let base = 20 * S;
        assert_eq!(jitter(base, 0.0), 16 * S);
        assert_eq!(jitter(base, 1.0), 24 * S);
        assert_eq!(jitter(base, 0.5), base);
        // Out-of-range or broken numbers never leave the bounds.
        assert_eq!(jitter(base, 7.0), 24 * S);
        assert_eq!(jitter(base, -1.0), 16 * S);
        assert_eq!(jitter(base, f64::NAN), base);
        for _ in 0..1000 {
            let j = jitter(base, random_unit());
            assert!((16 * S..=24 * S).contains(&j), "{j:?}");
        }
    }

    #[test]
    fn backoff_doubles_with_jitter_up_to_fifteen_minutes() {
        let b = |n, unit| backoff(Backend::GoogleDrive, n, unit);
        assert_eq!(b(1, 0.5), 30 * S);
        assert_eq!(b(2, 0.5), 60 * S);
        assert_eq!(b(3, 0.5), 2 * MIN);
        assert_eq!(b(1, 0.0), 24 * S);
        assert_eq!(b(1, 1.0), 36 * S);
        for n in 6..40 {
            assert!(b(n, 1.0) <= 15 * MIN);
            assert!(b(n, 0.0) >= 12 * MIN);
        }
        assert_eq!(b(u32::MAX, 1.0), 15 * MIN);
    }

    #[test]
    fn a_rate_limit_backs_off_and_widens_the_focused_interval_for_an_hour() {
        let t0 = Instant::now();
        let mut s = Schedule::new();
        let delay = s.record(t0, Backend::GoogleDrive, Outcome::RateLimited, (0.5, 0.5));
        assert_eq!(delay, Some(30 * S));
        assert!(s.backed_off(t0 + 29 * S));
        assert!(!s.backed_off(t0 + 30 * S));
        assert!(s.throttled(t0 + 59 * MIN));
        assert!(!s.throttled(t0 + 60 * MIN));
        assert_eq!(s.rate_limits, 1);
        // A second one in a row waits twice as long; never a tight loop.
        let t1 = t0 + 30 * S;
        assert_eq!(
            s.record(t1, Backend::GoogleDrive, Outcome::RateLimited, (0.5, 0.5)),
            Some(60 * S)
        );
        assert_eq!(s.rate_limits, 2);
        // Success clears the backoff but not the hour of wider checks.
        let t2 = t1 + 60 * S;
        assert_eq!(
            s.record(t2, Backend::GoogleDrive, Outcome::Ok, (0.5, 0.5)),
            None
        );
        assert!(!s.backed_off(t2) && s.failures == 0);
        assert!(s.throttled(t2));
        let interval = check_interval(
            Backend::GoogleDrive,
            Activity::Focused,
            s.throttled(t2),
            Duration::ZERO,
        );
        assert!(!s.check_due(t2 + 30 * S, interval));
        assert!(s.check_due(t2 + 2 * MIN, interval));
        // A plain failure (offline) backs off without throttling.
        let mut plain = Schedule::new();
        plain.record(t0, Backend::GoogleDrive, Outcome::Failed, (0.5, 0.5));
        assert!(plain.backed_off(t0) && !plain.throttled(t0));
        assert_eq!(plain.rate_limits, 0);
    }

    #[test]
    fn the_periodic_check_waits_for_its_jittered_interval() {
        let t0 = Instant::now();
        let mut s = Schedule::new();
        // Never synced: due at once.
        assert!(s.check_due(t0, Some(20 * S)));
        // Drawn the longest interval (24 s for 20 s).
        s.record(t0, Backend::GoogleDrive, Outcome::Ok, (0.5, 1.0));
        assert!(!s.check_due(t0 + 23 * S, Some(20 * S)));
        assert!(s.check_due(t0 + 24 * S, Some(20 * S)));
        // Drawn the shortest (16 s).
        s.record(t0, Backend::GoogleDrive, Outcome::Ok, (0.5, 0.0));
        assert!(!s.check_due(t0 + 15 * S, Some(20 * S)));
        assert!(s.check_due(t0 + 16 * S, Some(20 * S)));
        assert!(!s.check_due(t0 + 60 * MIN, None));
        // The interval follows the state at once: idle now, so 15 min (+-20 %).
        assert!(!s.check_due(t0 + 11 * MIN, Some(DRIVE_IDLE)));
        assert!(s.check_due(t0 + 12 * MIN, Some(DRIVE_IDLE)));
    }
}
