//! Per-vault Windows Hello policy: how often the master password is still required, and the
//! optional "Require Windows Hello before each fill" gate with its grace period. Pure logic, so
//! the timing rules are unit-tested without Windows.

use std::collections::BTreeSet;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

const DAY_MS: i64 = 24 * 60 * 60 * 1000;

/// After a Hello or master-password unlock, the first fill within this window doesn't ask again (it is
/// the request that triggered the unlock). With a grace of 0 only the fill of the login the unlock was asked for counts.
pub const UNLOCK_CREDIT: Duration = Duration::from_secs(30);

/// "Every time": the 2FA codes of a login whose fill was just confirmed are filled without asking again
/// for this long (a wrong or expired code picked again); its password and other logins still ask.
pub const OTP_AFTER_FILL: Duration = Duration::from_secs(120);

pub const MAX_GRACE_MINUTES: u32 = 60;

/// "Ask for master password every ...", stored as a short string (`"14d"`, `"restart"`); unknown reads as the default.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "String", into = "String")]
pub enum PasswordInterval {
    Never,
    OneDay,
    SevenDays,
    FourteenDays,
    #[default]
    ThirtyDays,
    /// Once per run of Pass: the first unlock after starting Pass needs the master password.
    AfterRestart,
}

impl PasswordInterval {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Never => "never",
            Self::OneDay => "1d",
            Self::SevenDays => "7d",
            Self::FourteenDays => "14d",
            Self::ThirtyDays => "30d",
            Self::AfterRestart => "restart",
        }
    }

    fn days(self) -> Option<i64> {
        match self {
            Self::OneDay => Some(1),
            Self::SevenDays => Some(7),
            Self::FourteenDays => Some(14),
            Self::ThirtyDays => Some(30),
            Self::Never | Self::AfterRestart => None,
        }
    }

    /// For the "password due" message. `None` for `Never`, which is never due.
    pub fn describe(self) -> Option<String> {
        use crate::i18n::tr;
        Some(match self {
            Self::Never => return None,
            Self::OneDay => tr!("hello.interval_1d"),
            Self::SevenDays => tr!("hello.interval_7d"),
            Self::FourteenDays => tr!("hello.interval_14d"),
            Self::ThirtyDays => tr!("hello.interval_30d"),
            Self::AfterRestart => tr!("hello.interval_restart"),
        })
    }
}

impl From<String> for PasswordInterval {
    fn from(s: String) -> Self {
        match s.as_str() {
            "never" => Self::Never,
            "1d" => Self::OneDay,
            "7d" => Self::SevenDays,
            "14d" => Self::FourteenDays,
            "30d" => Self::ThirtyDays,
            "restart" => Self::AfterRestart,
            _ => Self::default(),
        }
    }
}

impl From<PasswordInterval> for String {
    fn from(i: PasswordInterval) -> Self {
        i.as_str().to_string()
    }
}

/// Settings → This vault → Unlock (stored per vault in settings.json as `hello_policy`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct HelloPolicy {
    pub password_interval: PasswordInterval,
    /// Ask for Windows Hello before each extension fill, auto-type and passkey use, even while
    /// the vault is unlocked.
    pub verify_each_fill: bool,
    /// After a successful per-fill verification, further fills within this many minutes don't
    /// ask again. 0 = ask every time.
    pub fill_grace_minutes: u32,
}

impl Default for HelloPolicy {
    fn default() -> Self {
        Self {
            password_interval: PasswordInterval::default(),
            verify_each_fill: false,
            fill_grace_minutes: 1,
        }
    }
}

impl HelloPolicy {
    pub fn normalized(mut self) -> Self {
        self.fill_grace_minutes = self.fill_grace_minutes.min(MAX_GRACE_MINUTES);
        self
    }

    pub fn grace(&self) -> Duration {
        Duration::from_secs(u64::from(self.fill_grace_minutes.min(MAX_GRACE_MINUTES)) * 60)
    }
}

/// Whether the master password is due before Windows Hello may unlock again. A `None` `last_password_ms`
/// counts as due for every interval but "never"; `password_this_run`: master-password unlock since start.
/// A clock that went backwards by more than a day also counts as due, so turning the clock back can't
/// stretch the interval.
pub fn password_required(
    interval: PasswordInterval,
    last_password_ms: Option<i64>,
    now_ms: i64,
    password_this_run: bool,
) -> bool {
    match interval {
        PasswordInterval::Never => false,
        PasswordInterval::AfterRestart => !password_this_run,
        other => {
            let Some(last) = last_password_ms else {
                return true;
            };
            let days = other.days().unwrap_or(30);
            let elapsed = now_ms.saturating_sub(last);
            elapsed < -DAY_MS || elapsed >= days.saturating_mul(DAY_MS)
        }
    }
}

static PASSWORD_THIS_RUN: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());

pub fn mark_password_unlock(vault: &str) {
    PASSWORD_THIS_RUN
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(vault.to_string());
}

pub fn password_this_run(vault: &str) -> bool {
    PASSWORD_THIS_RUN
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .contains(vault)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gated<'a> {
    Password(&'a str),
    Code(&'a str),
    Passkey(&'a str),
    Other,
}

/// Bookkeeping for "Require Windows Hello before each fill". Cleared when the vault locks.
#[derive(Debug, Default)]
pub struct FillGate {
    last_verified: Option<Instant>,
    unlock_credit: Option<(Instant, Option<String>)>,
    confirmed_fill: Option<(String, Instant)>,
}

impl FillGate {
    /// The vault was just unlocked by the user: the fill that asked for the unlock shouldn't ask again.
    /// `for_item` is the login the browser asked the unlock for; with "Every time" only that login's fill counts it.
    pub fn unlocked(&mut self, now: Instant, for_item: Option<String>) {
        self.unlock_credit = Some((now, for_item));
        self.last_verified = Some(now);
    }

    pub fn verified(&mut self, now: Instant) {
        self.last_verified = Some(now);
    }

    /// The password of login `item` was just let out: its 2FA codes follow without asking for [`OTP_AFTER_FILL`],
    /// also with "Every time".
    pub fn filled(&mut self, now: Instant, item: &str) {
        self.confirmed_fill = Some((item.to_string(), now));
    }
    /// Whether `what` may proceed without Windows Hello. With a grace period see [`FillGate::without_prompt`];
    /// with none ("Every time"):
    /// * a login's password: only by the unlock asked for that login, once (one prompt for the
    ///   one-step fill, never a free fill after an unrelated unlock such as the main window's);
    /// * a login's 2FA code: within [`OTP_AFTER_FILL`] of a confirmed fill of that same login
    ///   (allowed, as often as needed), or by the unlock asked for that login;
    /// * a passkey sign-in: by the unlock asked for that login, or for nothing in particular (a
    ///   page's passkey request on a locked vault, which can't name its login before the unlock),
    ///   once; never by the unlock another login's fill asked for;
    /// * anything else: the unlock moments ago, once.
    pub fn without_prompt_for(
        &mut self,
        now: Instant,
        grace: Duration,
        what: Gated<'_>,
    ) -> Option<bool> {
        let outcome = if !grace.is_zero() {
            self.without_prompt(now, grace)
        } else {
            match what {
                Gated::Other => self.take_unlock_credit(now).then_some(true),
                Gated::Password(item) => self.take_unlock_credit_for(now, item).then_some(true),
                Gated::Code(item) if self.code_follows_fill(now, item) => Some(false),
                Gated::Code(item) => self.take_unlock_credit_for(now, item).then_some(true),
                Gated::Passkey(item) => (self.take_unlock_credit_for(now, item)
                    || self.take_unnamed_unlock_credit(now))
                .then_some(true),
            }
        };
        if let (Some(_), Gated::Password(item)) = (outcome, what) {
            self.filled(now, item);
        }
        outcome
    }

    fn code_follows_fill(&self, now: Instant, item: &str) -> bool {
        self.confirmed_fill.as_ref().is_some_and(|(filled, at)| {
            filled == item && now.saturating_duration_since(*at) <= OTP_AFTER_FILL
        })
    }

    /// Takes the unlock's one-shot credit if it is recent and was asked for the fill of `item`.
    /// A credit for anything else stays (for the request it was for).
    fn take_unlock_credit_for(&mut self, now: Instant, item: &str) -> bool {
        let for_this = self.unlock_credit.as_ref().is_some_and(|(at, for_item)| {
            for_item.as_deref() == Some(item) && now.saturating_duration_since(*at) <= UNLOCK_CREDIT
        });
        if for_this {
            self.unlock_credit = None;
        }
        for_this
    }

    /// Takes the unlock's one-shot credit if it is recent and was asked for no login in
    /// particular. A credit for a login stays (for that login's fill).
    fn take_unnamed_unlock_credit(&mut self, now: Instant) -> bool {
        let unnamed = self.unlock_credit.as_ref().is_some_and(|(at, for_item)| {
            for_item.is_none() && now.saturating_duration_since(*at) <= UNLOCK_CREDIT
        });
        if unnamed {
            self.unlock_credit = None;
        }
        unnamed
    }

    /// A credential was just used: while the grace period is still running it restarts from `now`, but never
    /// runs longer than `grace` after the last use. Once run out (or with grace 0) nothing changes.
    pub fn used(&mut self, now: Instant, grace: Duration) {
        if let Some(t) = self.last_verified {
            if !grace.is_zero() && now.saturating_duration_since(t) <= grace {
                self.last_verified = Some(now);
            }
        }
    }

    pub fn reset(&mut self) {
        *self = Self::default();
    }

    pub fn take_unlock_credit(&mut self, now: Instant) -> bool {
        self.unlock_credit
            .take()
            .is_some_and(|(t, _)| now.saturating_duration_since(t) <= UNLOCK_CREDIT)
    }

    /// A fill now without Windows Hello: `Some(true)` verified for real (the unlock moments ago, one-shot),
    /// `Some(false)` within the grace period, `None` must ask.
    pub fn without_prompt(&mut self, now: Instant, grace: Duration) -> Option<bool> {
        if self.take_unlock_credit(now) {
            Some(true)
        } else if !self.needs_prompt(now, grace) {
            Some(false)
        } else {
            None
        }
    }

    pub fn needs_prompt(&mut self, now: Instant, grace: Duration) -> bool {
        if self.take_unlock_credit(now) {
            return false;
        }
        match self.last_verified {
            Some(t) if !grace.is_zero() => now.saturating_duration_since(t) > grace,
            _ => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000_000;

    #[test]
    fn interval_round_trips_and_defaults() {
        for i in [
            PasswordInterval::Never,
            PasswordInterval::OneDay,
            PasswordInterval::SevenDays,
            PasswordInterval::FourteenDays,
            PasswordInterval::ThirtyDays,
            PasswordInterval::AfterRestart,
        ] {
            let json = serde_json::to_string(&i).unwrap();
            assert_eq!(serde_json::from_str::<PasswordInterval>(&json).unwrap(), i);
        }
        assert_eq!(
            serde_json::from_str::<PasswordInterval>("\"weekly\"").unwrap(),
            PasswordInterval::ThirtyDays
        );
        let policy: HelloPolicy = serde_json::from_str("{}").unwrap();
        assert_eq!(policy, HelloPolicy::default());
        assert_eq!(policy.password_interval, PasswordInterval::ThirtyDays);
        assert!(!policy.verify_each_fill);
        let policy: HelloPolicy =
            serde_json::from_str(r#"{"password_interval":"restart","fill_grace_minutes":500}"#)
                .unwrap();
        assert_eq!(policy.password_interval, PasswordInterval::AfterRestart);
        assert_eq!(policy.normalized().fill_grace_minutes, MAX_GRACE_MINUTES);
    }

    #[test]
    fn password_interval_timing() {
        let days = |d: i64| NOW - d * DAY_MS;
        let i14 = PasswordInterval::FourteenDays;
        assert!(!password_required(i14, Some(days(13)), NOW, false));
        assert!(!password_required(
            i14,
            Some(NOW - (14 * DAY_MS - 1)),
            NOW,
            false
        ));
        assert!(password_required(i14, Some(days(14)), NOW, false));
        assert!(password_required(i14, None, NOW, true));
        assert!(password_required(
            PasswordInterval::OneDay,
            Some(days(1)),
            NOW,
            true
        ));
        assert!(!password_required(
            PasswordInterval::SevenDays,
            Some(days(6)),
            NOW,
            false
        ));
        assert!(!password_required(
            PasswordInterval::ThirtyDays,
            Some(days(29)),
            NOW,
            false
        ));
        assert!(password_required(
            PasswordInterval::ThirtyDays,
            Some(days(31)),
            NOW,
            false
        ));
        assert!(password_required(i14, Some(NOW + 2 * DAY_MS), NOW, false));
        assert!(!password_required(i14, Some(NOW + 1000), NOW, false));
        assert!(!password_required(
            PasswordInterval::Never,
            None,
            NOW,
            false
        ));
        assert!(password_required(
            PasswordInterval::AfterRestart,
            Some(NOW),
            NOW,
            false
        ));
        assert!(!password_required(
            PasswordInterval::AfterRestart,
            None,
            NOW,
            true
        ));
    }

    #[test]
    fn password_this_run_is_per_vault() {
        mark_password_unlock("vault-a-test");
        assert!(password_this_run("vault-a-test"));
        assert!(!password_this_run("vault-b-test"));
    }

    #[test]
    fn fill_gate_grace_and_unlock_credit() {
        let t0 = Instant::now();
        let s = Duration::from_secs;
        let mut gate = FillGate::default();
        assert!(gate.needs_prompt(t0, s(60)));
        gate.verified(t0);
        assert!(!gate.needs_prompt(t0 + s(30), s(60)));
        assert!(gate.needs_prompt(t0 + s(61), s(60)));
        assert!(gate.needs_prompt(t0 + s(1), Duration::ZERO));

        let mut gate = FillGate::default();
        gate.unlocked(t0, None);
        assert!(!gate.needs_prompt(t0 + s(5), Duration::ZERO));
        assert!(gate.needs_prompt(t0 + s(6), Duration::ZERO));
        let mut gate = FillGate::default();
        gate.unlocked(t0, None);
        assert!(gate.needs_prompt(t0 + UNLOCK_CREDIT + s(1), Duration::ZERO));
        let mut gate = FillGate::default();
        gate.unlocked(t0, None);
        assert!(!gate.needs_prompt(t0 + s(2), s(300)));
        assert!(!gate.needs_prompt(t0 + s(200), s(300)));
        assert!(gate.needs_prompt(t0 + s(301), s(300)));
        gate.verified(t0 + s(301));
        gate.reset();
        assert!(gate.needs_prompt(t0 + s(302), s(300)));
        let mut gate = FillGate::default();
        gate.unlocked(t0, None);
        assert!(gate.take_unlock_credit(t0 + s(1)));
        assert!(!gate.take_unlock_credit(t0 + s(2)));
    }

    #[test]
    fn the_fill_right_after_an_unlock_does_not_ask_again() {
        let t0 = Instant::now();
        let ms = Duration::from_millis;
        let s = Duration::from_secs;
        // "Ask every time" (grace 0): the fill the extension sends as the unlock it asked for
        // answers is verified by that unlock, once; the next fill asks.
        let mut gate = FillGate::default();
        gate.unlocked(t0, Some("a".into()));
        assert_eq!(
            gate.without_prompt_for(t0 + ms(30), Duration::ZERO, Gated::Password("a")),
            Some(true)
        );
        assert_eq!(
            gate.without_prompt_for(t0 + ms(60), Duration::ZERO, Gated::Password("a")),
            None
        );
        // A grace period: verified by the unlock (whoever asked for it), then allowed until the
        // grace runs out.
        let mut gate = FillGate::default();
        gate.unlocked(t0, None);
        assert_eq!(
            gate.without_prompt_for(t0 + ms(30), s(300), Gated::Password("a")),
            Some(true)
        );
        assert_eq!(
            gate.without_prompt_for(t0 + s(10), s(300), Gated::Password("b")),
            Some(false)
        );
        assert_eq!(gate.without_prompt(t0 + s(301), s(300)), None);
        let mut gate = FillGate::default();
        gate.unlocked(t0, None);
        assert_eq!(
            gate.without_prompt(t0 + UNLOCK_CREDIT + s(1), Duration::ZERO),
            None
        );
        let mut gate = FillGate::default();
        gate.unlocked(t0, None);
        gate.reset();
        assert_eq!(gate.without_prompt(t0 + ms(30), s(300)), None);
    }

    #[test]
    fn fill_gate_grace_slides_with_use_up_to_the_setting() {
        let t0 = Instant::now();
        let s = Duration::from_secs;
        let grace = s(60);
        let mut gate = FillGate::default();
        gate.verified(t0);
        gate.used(t0 + s(50), grace);
        assert!(!gate.needs_prompt(t0 + s(100), grace));
        gate.used(t0 + s(100), grace);
        assert!(!gate.needs_prompt(t0 + s(160), grace));
        assert!(gate.needs_prompt(t0 + s(161), grace));

        let mut gate = FillGate::default();
        gate.verified(t0);
        for i in 1..=10 {
            gate.used(t0 + s(i), grace);
        }
        assert!(!gate.needs_prompt(t0 + s(70), grace));
        assert!(gate.needs_prompt(t0 + s(71), grace));

        let mut gate = FillGate::default();
        gate.verified(t0);
        gate.used(t0 + s(61), grace);
        assert!(gate.needs_prompt(t0 + s(62), grace));

        let mut gate = FillGate::default();
        gate.used(t0, grace);
        assert!(gate.needs_prompt(t0 + s(1), grace));

        let mut gate = FillGate::default();
        gate.verified(t0);
        gate.used(t0, Duration::ZERO);
        assert!(gate.needs_prompt(t0, Duration::ZERO));

        let mut gate = FillGate::default();
        gate.unlocked(t0, None);
        assert!(!gate.needs_prompt(t0 + s(1), grace));
        gate.used(t0 + s(1), grace);
        gate.used(t0 + s(55), grace);
        assert!(!gate.needs_prompt(t0 + s(110), grace));
        gate.reset();
        gate.used(t0 + s(111), grace);
        assert!(gate.needs_prompt(t0 + s(112), grace));
    }

    const EVERY_TIME: Duration = Duration::ZERO;

    #[test]
    fn every_time_a_main_window_unlock_is_no_fill_check() {
        let t0 = Instant::now();
        let s = Duration::from_secs;
        let mut gate = FillGate::default();
        gate.unlocked(t0, None);
        assert_eq!(
            gate.without_prompt_for(t0 + s(1), EVERY_TIME, Gated::Password("a")),
            None
        );
        assert_eq!(
            gate.without_prompt_for(t0 + s(1), EVERY_TIME, Gated::Code("a")),
            None
        );
        // An unlock asked for another login's fill doesn't let this one through either, and stays
        // for the login it was asked for.
        let mut gate = FillGate::default();
        gate.unlocked(t0, Some("b".into()));
        assert_eq!(
            gate.without_prompt_for(t0 + s(1), EVERY_TIME, Gated::Password("a")),
            None
        );
        assert_eq!(
            gate.without_prompt_for(t0 + s(2), EVERY_TIME, Gated::Password("b")),
            Some(true)
        );
    }

    #[test]
    fn every_time_the_one_step_fill_asks_once() {
        let t0 = Instant::now();
        let s = Duration::from_secs;
        let mut gate = FillGate::default();
        gate.unlocked(t0, Some("a".into()));
        assert_eq!(
            gate.without_prompt_for(t0 + s(1), EVERY_TIME, Gated::Password("a")),
            Some(true)
        );
        assert_eq!(
            gate.without_prompt_for(t0 + s(2), EVERY_TIME, Gated::Password("a")),
            None
        );
        let mut gate = FillGate::default();
        gate.unlocked(t0, Some("a".into()));
        assert_eq!(
            gate.without_prompt_for(t0 + UNLOCK_CREDIT + s(1), EVERY_TIME, Gated::Password("a")),
            None
        );
    }

    #[test]
    fn every_time_the_codes_of_the_confirmed_login_follow_for_a_while() {
        let t0 = Instant::now();
        let s = Duration::from_secs;
        let mut gate = FillGate::default();
        gate.verified(t0);
        gate.filled(t0, "a");
        for at in [s(5), s(60), OTP_AFTER_FILL] {
            assert_eq!(
                gate.without_prompt_for(t0 + at, EVERY_TIME, Gated::Code("a")),
                Some(false)
            );
        }
        assert_eq!(
            gate.without_prompt_for(t0 + s(10), EVERY_TIME, Gated::Code("b")),
            None
        );
        assert_eq!(
            gate.without_prompt_for(t0 + s(10), EVERY_TIME, Gated::Password("b")),
            None
        );
        assert_eq!(
            gate.without_prompt_for(t0 + s(10), EVERY_TIME, Gated::Password("a")),
            None
        );
        assert_eq!(
            gate.without_prompt_for(t0 + OTP_AFTER_FILL + s(1), EVERY_TIME, Gated::Code("a")),
            None
        );
        let mut gate = FillGate::default();
        gate.unlocked(t0, Some("a".into()));
        assert_eq!(
            gate.without_prompt_for(t0 + s(1), EVERY_TIME, Gated::Password("a")),
            Some(true)
        );
        assert_eq!(
            gate.without_prompt_for(t0 + s(30), EVERY_TIME, Gated::Code("a")),
            Some(false)
        );
        gate.filled(t0 + s(40), "b");
        assert_eq!(
            gate.without_prompt_for(t0 + s(41), EVERY_TIME, Gated::Code("a")),
            None
        );
        gate.reset();
        assert_eq!(
            gate.without_prompt_for(t0 + s(42), EVERY_TIME, Gated::Code("b")),
            None
        );
    }

    #[test]
    fn every_time_other_requests_keep_the_unlock_credit_as_before() {
        let t0 = Instant::now();
        let s = Duration::from_secs;
        let mut gate = FillGate::default();
        gate.unlocked(t0, None);
        assert_eq!(
            gate.without_prompt_for(t0 + s(1), EVERY_TIME, Gated::Other),
            Some(true)
        );
        assert_eq!(
            gate.without_prompt_for(t0 + s(2), EVERY_TIME, Gated::Other),
            None
        );
    }

    #[test]
    fn every_time_a_passkey_sign_in_takes_only_its_own_unlock() {
        let t0 = Instant::now();
        let s = Duration::from_secs;
        let mut gate = FillGate::default();
        gate.unlocked(t0, Some("a".into()));
        assert_eq!(
            gate.without_prompt_for(t0 + s(1), EVERY_TIME, Gated::Passkey("a")),
            Some(true)
        );
        assert_eq!(
            gate.without_prompt_for(t0 + s(2), EVERY_TIME, Gated::Passkey("a")),
            None
        );
        let mut gate = FillGate::default();
        gate.unlocked(t0, None);
        assert_eq!(
            gate.without_prompt_for(t0 + s(1), EVERY_TIME, Gated::Passkey("a")),
            Some(true)
        );
        assert_eq!(
            gate.without_prompt_for(t0 + s(2), EVERY_TIME, Gated::Passkey("a")),
            None
        );
        // An unlock asked for another login's fill is that fill's: the passkey asks, and the
        // credit stays for the fill.
        let mut gate = FillGate::default();
        gate.unlocked(t0, Some("b".into()));
        assert_eq!(
            gate.without_prompt_for(t0 + s(1), EVERY_TIME, Gated::Passkey("a")),
            None
        );
        assert_eq!(
            gate.without_prompt_for(t0 + s(2), EVERY_TIME, Gated::Password("b")),
            Some(true)
        );
        let mut gate = FillGate::default();
        gate.unlocked(t0, Some("a".into()));
        assert_eq!(
            gate.without_prompt_for(t0 + UNLOCK_CREDIT + s(1), EVERY_TIME, Gated::Passkey("a")),
            None
        );
        let mut gate = FillGate::default();
        gate.unlocked(t0, Some("a".into()));
        assert_eq!(
            gate.without_prompt_for(t0 + s(1), EVERY_TIME, Gated::Passkey("a")),
            Some(true)
        );
        assert_eq!(
            gate.without_prompt_for(t0 + s(2), EVERY_TIME, Gated::Code("a")),
            None
        );
    }

    #[test]
    fn a_passkey_sign_in_keeps_the_grace_period_rules() {
        let t0 = Instant::now();
        let s = Duration::from_secs;
        let grace = s(60);
        let mut gate = FillGate::default();
        gate.verified(t0);
        assert_eq!(
            gate.without_prompt_for(t0 + s(30), grace, Gated::Passkey("a")),
            Some(false)
        );
        assert_eq!(
            gate.without_prompt_for(t0 + s(61), grace, Gated::Passkey("a")),
            None
        );
    }
}
