//! How often the vault locks by itself (Settings → Unlock → Auto-lock):
//!
//! * [`AutoLock::Restart`]: only when Passyble or the computer restarts (and on Lock); the vault stays unlocked while
//!   the computer is on, also while its screen is locked. The default of a new setup.
//! * [`AutoLock::System`]: when the computer locks or sleeps (Win+L, closing the lid, a Mac's screen lock), and on
//!   restart.
//! * [`AutoLock::Idle`]: after `auto_lock_minutes` without use, and when the computer locks or sleeps. The only mode
//!   older versions had, so a settings file without the choice keeps it.
//!
//! A Team or Family policy with a maximum auto-lock (teams.rs) wins: the vault then locks after that time at the
//! latest, and when the computer locks or sleeps, whatever was chosen here.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::settings::Settings;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutoLock {
    Restart,
    System,
    #[default]
    Idle,
}

/// The idle time (minutes) after which the vault locks: the one chosen (`minutes`, for
/// [`AutoLock::Idle`]), shortened to a policy's maximum `cap`. `None`: it never locks for being
/// idle.
pub fn idle_minutes(mode: AutoLock, minutes: u32, cap: Option<u32>) -> Option<u32> {
    let chosen = (mode == AutoLock::Idle).then(|| minutes.max(1));
    match (chosen, cap) {
        (Some(m), Some(c)) => Some(m.min(c)),
        (None, Some(c)) => Some(c),
        (m, None) => m,
    }
}

pub fn locks_with_computer(mode: AutoLock, cap: Option<u32>) -> bool {
    mode != AutoLock::Restart || cap.is_some()
}

pub fn idle_limit(settings: &Settings) -> Option<u32> {
    idle_minutes(
        settings.auto_lock,
        settings.auto_lock_minutes,
        crate::teams::settings_cap(settings),
    )
}

pub fn agent_timeout(settings: &Settings) -> Duration {
    idle_limit(settings)
        .map(|m| Duration::from_secs(u64::from(m) * 60))
        .unwrap_or(Duration::MAX)
}

pub fn on_computer_lock(settings: &Settings) -> bool {
    locks_with_computer(settings.auto_lock, crate::teams::settings_cap(settings))
}

/// The idle time the user chose, without a policy: `None` for "never" (what a policy's check of
/// this PC compares with its maximum, teams.rs `violations`).
pub fn chosen_idle_secs(settings: &Settings) -> Option<u64> {
    idle_minutes(settings.auto_lock, settings.auto_lock_minutes, None).map(|m| u64::from(m) * 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn on_every_restart_never_locks_by_itself() {
        assert_eq!(idle_minutes(AutoLock::Restart, 15, None), None);
        assert!(!locks_with_computer(AutoLock::Restart, None));
        assert_eq!(idle_minutes(AutoLock::System, 15, None), None);
        assert!(locks_with_computer(AutoLock::System, None));
        assert_eq!(idle_minutes(AutoLock::Idle, 5, None), Some(5));
        assert!(locks_with_computer(AutoLock::Idle, None));
        // Zero minutes can't come from the window, but never means "at once".
        assert_eq!(idle_minutes(AutoLock::Idle, 0, None), Some(1));
    }

    #[test]
    fn a_policy_maximum_wins_over_every_choice() {
        assert_eq!(idle_minutes(AutoLock::Restart, 15, Some(10)), Some(10));
        assert_eq!(idle_minutes(AutoLock::System, 15, Some(10)), Some(10));
        assert_eq!(idle_minutes(AutoLock::Idle, 60, Some(10)), Some(10));
        assert_eq!(idle_minutes(AutoLock::Idle, 5, Some(10)), Some(5));
        assert!(locks_with_computer(AutoLock::Restart, Some(10)));
    }

    #[test]
    fn new_setups_lock_on_restart_and_older_files_keep_their_timer() {
        let new = Settings::default();
        assert_eq!(new.auto_lock, AutoLock::Restart);
        assert_eq!(agent_timeout(&new), Duration::MAX);
        assert!(!on_computer_lock(&new));
        assert_eq!(chosen_idle_secs(&new), None);

        // A file written before the choice existed (it always has the minutes): the timer it had.
        let old: Settings = serde_json::from_str(r#"{"auto_lock_minutes":30}"#).unwrap();
        assert_eq!(old.auto_lock, AutoLock::Idle);
        assert_eq!(agent_timeout(&old), Duration::from_secs(30 * 60));
        assert!(on_computer_lock(&old));
        assert_eq!(chosen_idle_secs(&old), Some(1800));

        for mode in [AutoLock::Restart, AutoLock::System, AutoLock::Idle] {
            let s = Settings {
                auto_lock: mode,
                ..Default::default()
            };
            let back: Settings = serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
            assert_eq!(back.auto_lock, mode);
        }
        assert_eq!(
            serde_json::to_value(AutoLock::Restart).unwrap(),
            serde_json::json!("restart")
        );
    }
}
