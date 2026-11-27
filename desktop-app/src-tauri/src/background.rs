//! Background threads: the auto-lock tick and the sync scheduler (WebDAV / Passyble Server or Google
//! Drive, whichever the active vault uses).
//!
//! The server is contacted only when there is a reason (the intervals are in `sync_schedule.rs`),
//! and a sync of an unchanged vault is one small request (WebDAV: a conditional `GET` answered
//! `304`; Google Drive: `files.get` with a few fields). Reasons: unlock and "Sync now"; a local edit
//! once it has settled; a periodic check whose interval depends on window focus and user activity;
//! window focus, wake from sleep and the extension asking for logins (if the last check is old
//! enough). Usage counts alone never trigger a sync. Never while locked. Failures back off
//! exponentially with jitter, but kicks don't wait for the backoff. No retry loop for a Google
//! Drive vault marked "Sign in to Google again" or a Passyble Server device that was signed out
//! ("Sync now" still tries once).
//!
//! Shared vaults (Teams, Family) go along with the home vault's sync; a quiet check takes them
//! along at most every 5 min, and a quiet Passyble Cloud check takes them along every time.

use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use tauri::{AppHandle, Emitter, Manager};

use crate::state::{lock, AppState};
use crate::sync_schedule::{self as policy, Backend, Outcome, Schedule, Signals};

/// The sync thread looks at the vault this often (cheap: a few locks).
const TICK: Duration = Duration::from_secs(1);
const SLOW_TICKS: u32 = 5;
const LOCK_TICK: Duration = Duration::from_secs(5);
/// Every 30 s (6 auto-lock ticks), pick up changes a cloud-folder client wrote to the vault file.
const RELOAD_EVERY_TICKS: u32 = 6;
/// A wall-clock jump this much larger than the tick means the PC slept.
const SLEEP_GAP: Duration = Duration::from_secs(60);

static NUDGE: AtomicU8 = AtomicU8::new(NUDGE_NONE);
const NUDGE_NONE: u8 = 0;
const NUDGE_FOCUS: u8 = 1;
const NUDGE_EXTENSION: u8 = 2;
static WINDOW_FOCUSED: AtomicBool = AtomicBool::new(false);

static SCHEDULE: Mutex<Schedule> = Mutex::new(Schedule::new());
static LINKED_SYNCED: Mutex<Option<Instant>> = Mutex::new(None);

fn schedule() -> std::sync::MutexGuard<'static, Schedule> {
    lock(&SCHEDULE)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Wake {
    Kick,
    /// A window got focus, the PC woke up, or (Google Drive) the extension asked for logins.
    Focus,
    Tick,
}

#[derive(Clone, Copy, Default)]
struct Reasons {
    backed_off: bool,
    /// The vault has content changes the server hasn't seen (recorded uses don't count).
    pending: bool,
    edits_settled: bool,
    nudge_gap_passed: bool,
    check_due: bool,
    /// Usage counts have waited 6 hours, and the server wasn't asked in the last [`policy::OTHER_NUDGE_GAP`].
    usage_due: bool,
}

/// Whether to sync now (the policy in the module docs).
fn sync_due(wake: Wake, r: Reasons) -> bool {
    match wake {
        Wake::Kick => true,
        _ if r.backed_off => false,
        Wake::Focus => r.pending || r.nudge_gap_passed,
        Wake::Tick => (r.pending && r.edits_settled) || r.check_due || r.usage_due,
    }
}

/// The wake-up a kick stands for. The extension asking for logins is a reason to check only for
/// Google Drive and Passyble Cloud (WebDAV keeps its calmer schedule).
fn wake_for(nudge: u8, backend: Backend) -> Wake {
    match nudge {
        NUDGE_FOCUS => Wake::Focus,
        NUDGE_EXTENSION if backend != Backend::Other => Wake::Focus,
        NUDGE_EXTENSION => Wake::Tick,
        _ => Wake::Kick,
    }
}

/// The active vault's sync backend. Cheap: settings and the cached `whoami`, no request.
fn backend_of(state: &AppState, agent: &pass_agent::Agent) -> Backend {
    #[cfg(feature = "gdrive")]
    if agent.config().gdrive.is_some() {
        return Backend::GoogleDrive;
    }
    let _ = agent;
    let webdav = lock(&state.settings)
        .active()
        .and_then(|v| v.webdav.clone());
    if cloud_plan_live(webdav.as_ref(), &crate::teams::cache().whoami) {
        Backend::Cloud
    } else {
        Backend::Other
    }
}

fn server_vault(webdav: &crate::settings::WebDavSettings) -> Option<(&str, &str)> {
    if !webdav.is_pass_server() {
        return None;
    }
    let url = webdav.url.trim();
    let i = url.rfind("/dav/")?;
    let (base, rest) = (&url[..i], &url[i + "/dav/".len()..]);
    let (user, file) = rest.split_once('/')?;
    (!user.is_empty() && !file.is_empty()).then(|| (base.trim_end_matches('/'), user))
}

fn same_base(a: &str, b: &str) -> bool {
    a.trim_end_matches('/')
        .eq_ignore_ascii_case(b.trim_end_matches('/'))
}

/// Whether `webdav` is a Passyble Cloud vault whose account's plan is live (the server's last
/// `whoami` for the user says `cloud.state` "active"). False for no `whoami`, `read_only`,
/// `suspended` or a self-hosted server.
fn cloud_plan_live(
    webdav: Option<&crate::settings::WebDavSettings>,
    whoami: &[(crate::teams::Backend, crate::teams_api::Whoami)],
) -> bool {
    let Some((base, user)) = webdav.and_then(server_vault) else {
        return false;
    };
    whoami.iter().any(|(b, w)| {
        same_base(b.base(), base)
            && w.user == user
            && w.cloud.as_ref().is_some_and(|c| c.state == "active")
    })
}

/// The plan ended: the cached state stops saying "active", so the vault is back on the calmer
/// schedule before the next `whoami`.
#[cfg_attr(not(feature = "webdav"), allow(dead_code))]
fn note_plan_lapsed(
    webdav: Option<&crate::settings::WebDavSettings>,
    whoami: &mut [(crate::teams::Backend, crate::teams_api::Whoami)],
) {
    let Some((base, user)) = webdav.and_then(server_vault) else {
        return;
    };
    for (b, w) in whoami.iter_mut() {
        if same_base(b.base(), base) && w.user == user {
            if let Some(c) = w.cloud.as_mut().filter(|c| c.state == "active") {
                c.state = "read_only".into();
            }
        }
    }
}

pub fn start(app: &AppHandle) {
    let tick_app = app.clone();
    let _ = thread::Builder::new()
        .name("pass-tick".into())
        .spawn(move || {
            let mut n = 0u32;
            loop {
                thread::sleep(LOCK_TICK);
                let Some(agent) = tick_app.state::<Arc<AppState>>().agent() else {
                    continue;
                };
                agent.tick();
                n = n.wrapping_add(1);
                if n.is_multiple_of(RELOAD_EVERY_TICKS) && !agent.is_locked() {
                    let _ = agent.save();
                }
            }
        });

    let (tx, rx) = mpsc::channel::<()>();
    *lock(&app.state::<Arc<AppState>>().sync_kick) = Some(tx);
    let sync_app = app.clone();
    let _ = thread::Builder::new()
        .name("pass-sync".into())
        .spawn(move || {
            let mut last_revision: Option<u64> = None;
            let mut last_edit = Instant::now();
            let mut last_wall = SystemTime::now();
            let mut ticks = 0u32;
            loop {
                let (kicked, nudge) = match rx.recv_timeout(TICK) {
                    Ok(()) => (true, NUDGE.swap(NUDGE_NONE, Ordering::Relaxed)),
                    Err(mpsc::RecvTimeoutError::Timeout) => (false, NUDGE_NONE),
                    Err(mpsc::RecvTimeoutError::Disconnected) => return,
                };
                let wall = SystemTime::now();
                let slept = wall
                    .duration_since(last_wall)
                    .is_ok_and(|gap| gap > TICK + SLEEP_GAP);
                last_wall = wall;
                let slow_tick = !kicked && {
                    ticks = ticks.wrapping_add(1);
                    ticks.is_multiple_of(SLOW_TICKS)
                };

                let state = sync_app.state::<Arc<AppState>>();
                let Some(agent) = state.agent() else {
                    continue;
                };
                // Teams and Family: a change in a shared vault goes up within seconds.
                if slow_tick && !agent.is_locked() {
                    crate::teams_vaults::sync_pending(&sync_app);
                }
                let sign_in = crate::gdrive::sign_in_needed(&lock(&state.settings));
                let signed_out = lock(&state.sync).signed_out;
                let configured =
                    cfg!(feature = "webdav") && agent.has_sync_account() && !sign_in && !signed_out;
                let Some((pending, revision)) = agent.sync_pending().filter(|_| configured) else {
                    // Locked, no account, or waiting for a Google or Passyble Server sign-in: nothing to do.
                    last_revision = None;
                    set_flags(&sync_app, false, sign_in && !agent.is_locked());
                    continue;
                };
                if last_revision != Some(revision) {
                    last_revision = Some(revision);
                    last_edit = Instant::now();
                }
                set_flags(&sync_app, pending, false);

                let backend = backend_of(&state, &agent);
                let mut wake = if kicked {
                    wake_for(nudge, backend)
                } else {
                    Wake::Tick
                };
                if slept && wake == Wake::Tick {
                    wake = Wake::Focus;
                }
                let usage_due = slow_tick && agent.usage_sync_due();
                let now = Instant::now();
                let vault_idle = agent.idle_for();
                let activity = policy::activity(Signals {
                    window_focused: WINDOW_FOCUSED.load(Ordering::Relaxed),
                    vault_idle,
                    user_idle: crate::platform::user_idle_for(),
                });
                let reasons = {
                    let s = schedule();
                    let interval =
                        policy::check_interval(backend, activity, s.throttled(now), vault_idle);
                    Reasons {
                        backed_off: s.backed_off(now),
                        pending,
                        edits_settled: last_edit.elapsed() >= policy::EDIT_DEBOUNCE,
                        nudge_gap_passed: s.since_ok(now, policy::nudge_gap(backend)),
                        check_due: s.check_due(now, interval),
                        usage_due: usage_due && s.since_ok(now, policy::OTHER_NUDGE_GAP),
                    }
                };
                if sync_due(wake, reasons) {
                    let quiet = wake != Wake::Kick && !pending;
                    let _ = sync_with(&sync_app, quiet);
                }
            }
        });
}

/// `WindowEvent::Focused`: whether a Pass window has focus now. Gaining focus checks for other
/// devices' changes unless the server was asked recently, or uploads pending changes.
pub fn window_focused(app: &AppHandle, focused: bool) {
    WINDOW_FOCUSED.store(focused, Ordering::Relaxed);
    if focused {
        NUDGE.store(NUDGE_FOCUS, Ordering::Relaxed);
        app.state::<Arc<AppState>>().kick_sync();
    }
}

/// The browser extension asked for logins: a Google Drive or Passyble Cloud vault checks for other
/// devices' changes if the last check is old. Returns at once.
pub fn logins_requested(app: &AppHandle) {
    // A focus nudge waiting already covers it.
    let _ = NUDGE.compare_exchange(
        NUDGE_NONE,
        NUDGE_EXTENSION,
        Ordering::Relaxed,
        Ordering::Relaxed,
    );
    app.state::<Arc<AppState>>().kick_sync();
}

/// Updates the "changes pending" and "sign in to Google again" flags, telling the windows on change.
fn set_flags(app: &AppHandle, pending: bool, sign_in_needed: bool) {
    let state = app.state::<Arc<AppState>>();
    let changed = {
        let mut status = lock(&state.sync);
        let changed = status.pending != pending || status.sign_in_needed != sign_in_needed;
        status.pending = pending;
        status.sign_in_needed = sign_in_needed;
        if sign_in_needed {
            status.last_error = Some(crate::gdrive::sign_in_again());
        }
        changed.then(|| status.clone())
    };
    if let Some(status) = changed {
        let _ = app.emit("sync-status", status);
    }
}

/// Runs one sync if the vault is unlocked and has a sync account. Blocking.
pub fn sync_now(app: &AppHandle) -> Result<Option<serde_json::Value>, String> {
    sync_with(app, false)
}

#[cfg(feature = "webdav")]
type LinkedResults = Vec<(
    String,
    Result<Option<pass_core::SyncResult>, pass_core::PassError>,
)>;

/// [`sync_now`]; `quiet`: a background check with nothing to upload, which doesn't show "Syncing..."
/// and takes the shared vaults along at most every [`policy::OTHER_NUDGE_GAP`].
#[cfg(feature = "webdav")]
fn sync_with(app: &AppHandle, quiet: bool) -> Result<Option<serde_json::Value>, String> {
    sync_with_linked(app, quiet, &mut None)
}

#[cfg(feature = "webdav")]
fn sync_with_linked(
    app: &AppHandle,
    quiet: bool,
    linked: &mut Option<LinkedResults>,
) -> Result<Option<serde_json::Value>, String> {
    let state = app.state::<Arc<AppState>>();
    let Some(agent) = state.agent() else {
        return Ok(None);
    };
    // Read-only mode (update required): no sync.
    if agent.is_locked() || !agent.has_sync_account() || agent.update_required() {
        return Ok(None);
    }
    let backend = backend_of(&state, &agent);
    if !quiet {
        let snapshot = {
            let mut status = lock(&state.sync);
            status.running = true;
            status.clone()
        };
        let _ = app.emit("sync-status", snapshot);
    }
    // Passyble Server refused this device's token: signed out, not a retry loop.
    let webdav = lock(&state.settings)
        .active()
        .and_then(|v| v.webdav.clone());
    let pass_server = webdav.as_ref().is_some_and(|w| w.is_pass_server());
    let mut signed_out = false;
    let mut busy = false;
    let mut lapsed = false;
    let mut webdav_sync = || {
        agent.sync().map_err(|e| {
            if pass_server && crate::account_vaults::is_vault_gone(&e) {
                crate::account_vaults::check_deleted_soon(app);
            }
            crate::support::note_error(crate::support::sync_error_code(&e));
            if let pass_core::PassError::Network(m) = &e {
                busy = crate::errors::core_says(m, "net.busy");
                lapsed = crate::errors::core_says(m, "server.subscription_inactive")
                    || crate::errors::core_says(m, "server.account_suspended");
            }
            if pass_server && crate::devices::is_signed_out(&e) {
                signed_out = true;
                crate::devices::signed_out_text()
            } else {
                crate::errors::friendly(e)
            }
        })
    };
    #[cfg(feature = "gdrive")]
    let (result, rate_limited) = if backend == Backend::GoogleDrive {
        let result = crate::gdrive::sync(app, &agent);
        (result, crate::gdrive::take_rate_limited())
    } else {
        (webdav_sync(), false)
    };
    #[cfg(not(feature = "gdrive"))]
    let (result, rate_limited) = (webdav_sync(), false);
    let rate_limited = rate_limited || (backend == Backend::Cloud && busy);
    if backend == Backend::Cloud && lapsed {
        note_plan_lapsed(webdav.as_ref(), &mut crate::teams::cache().whoami);
    }
    // Shared vaults go along with the home vault's sync; their errors show on each vault. A quiet
    // check takes them along at most every few minutes, except those on Passyble Cloud.
    let configs = agent.linked_configs();
    if !configs.is_empty() && linked_due(quiet) {
        *linked = Some(agent.sync_linked());
        crate::teams::emit_changed(app);
    } else if backend == Backend::Cloud {
        let base = webdav.as_ref().and_then(server_vault).map(|(b, _)| b);
        let on_cloud: Vec<&str> = configs
            .iter()
            .filter(|c| {
                let url = c.webdav.as_ref().map(|w| w.url.as_str());
                let linked_base = url.and_then(crate::signin::server_base);
                linked_base.zip(base).is_some_and(|(l, h)| same_base(&l, h))
            })
            .map(|c| c.key.as_str())
            .collect();
        for key in &on_cloud {
            if let Err(e) = agent.sync_shared(key) {
                crate::applog::plog!("teams: sync of {key} failed: {e}");
            }
        }
        if !on_cloud.is_empty() {
            crate::teams::emit_changed(app);
        }
    }
    let ended = match &result {
        Ok(_) => Outcome::Ok,
        Err(_) if rate_limited => Outcome::RateLimited,
        Err(_) => Outcome::Failed,
    };
    let (delay, rate_limits) = {
        let mut s = schedule();
        let units = (policy::random_unit(), policy::random_unit());
        let delay = s.record(Instant::now(), backend, ended, units);
        (delay, s.rate_limits)
    };
    if ended == Outcome::RateLimited {
        // For "Report this problem" and the log: a count and the wait, nothing about the vault.
        let (code, name, focused) = if backend == Backend::Cloud {
            (
                "sync.cloud_rate_limited",
                "Passyble Cloud",
                policy::CLOUD_CHECK_THROTTLED,
            )
        } else {
            (
                "sync.gdrive_rate_limited",
                "Google Drive",
                policy::DRIVE_FOCUSED_THROTTLED,
            )
        };
        crate::support::note_error(code);
        crate::applog::write(&format!(
            "sync: {name} rate limit #{rate_limits} since start; next try in {} s, checks \
             while focused every {} s for {} min",
            delay.unwrap_or_default().as_secs(),
            focused.as_secs(),
            policy::THROTTLE_FOR.as_secs() / 60,
        ));
    }
    if signed_out {
        agent.forget_kept_list();
    }
    let sign_in_needed = crate::gdrive::sign_in_needed(&lock(&state.settings));
    let mut status = lock(&state.sync);
    status.running = false;
    status.sign_in_needed = sign_in_needed;
    // Another failure (offline, say) doesn't tell whether the token works again.
    status.signed_out = signed_out || (status.signed_out && result.is_err());
    status.pending = agent.sync_pending().is_some_and(|(p, _)| p);
    let outcome = match result {
        Ok(Some(r)) => {
            status.record_success(now_ms(), r.remote_bytes);
            let changed = r.stats.added + r.stats.updated + r.stats.deleted > 0;
            if changed {
                let _ = app.emit("vault-changed", ());
            }
            Ok(Some(serde_json::json!({
                "added": r.stats.added, "updated": r.stats.updated, "deleted": r.stats.deleted,
                "uploaded": r.uploaded, "created_remote": r.created_remote,
            })))
        }
        Ok(None) => Ok(None),
        Err(message) => {
            status.last_error = Some(message.clone());
            Err(message)
        }
    };
    let _ = app.emit("sync-status", status.clone());
    outcome
}

#[cfg(not(feature = "webdav"))]
fn sync_with(_app: &AppHandle, _quiet: bool) -> Result<Option<serde_json::Value>, String> {
    Ok(None)
}

/// "Sync now" from the vault screen, the tray, its shortcut and the extension: every open vault
/// with sync set up, including shared vaults. Also the home vault's changes when it synced. Blocking;
/// the caller checked that the vault is unlocked.
#[cfg(feature = "webdav")]
pub fn sync_all(app: &AppHandle) -> (pass_agent::SyncReport, Option<serde_json::Value>) {
    use pass_agent::{SyncFailure, SyncReport};
    let state = app.state::<Arc<AppState>>();
    let mut report = SyncReport::default();
    let Some(agent) = state.agent() else {
        report.no_sync = true;
        return (report, None);
    };
    let settings = state.settings();
    let configs = agent.linked_configs();
    let home = agent.has_sync_account();
    if !home && configs.is_empty() {
        report.no_sync = true;
        return (report, None);
    }
    let home_name = settings
        .active()
        .map(|v| v.name.clone())
        .unwrap_or_default();
    let mut linked = None;
    let mut changes = None;
    if home {
        if crate::gdrive::sign_in_needed(&settings) {
            report.failed.push(SyncFailure {
                vault: home_name,
                reason: crate::gdrive::sign_in_again(),
            });
        } else {
            match sync_with_linked(app, false, &mut linked) {
                Ok(Some(stats)) => {
                    report.synced += 1;
                    changes = Some(stats);
                }
                Ok(None) => {}
                Err(reason) => report.failed.push(SyncFailure {
                    vault: home_name,
                    reason,
                }),
            }
        }
    }
    let linked = match linked {
        Some(results) => results,
        None if !configs.is_empty() => {
            let results = agent.sync_linked();
            crate::teams::emit_changed(app);
            results
        }
        None => Vec::new(),
    };
    add_linked(&mut report, &configs, linked);
    (report, changes)
}

#[cfg(not(feature = "webdav"))]
pub fn sync_all(_app: &AppHandle) -> (pass_agent::SyncReport, Option<serde_json::Value>) {
    let report = pass_agent::SyncReport {
        no_sync: true,
        ..Default::default()
    };
    (report, None)
}

#[cfg(feature = "webdav")]
fn add_linked(
    report: &mut pass_agent::SyncReport,
    configs: &[pass_agent::LinkedVaultConfig],
    linked: LinkedResults,
) {
    for (key, result) in linked {
        let vault = configs
            .iter()
            .find(|c| c.key == key)
            .map(|c| c.name.clone())
            .unwrap_or(key);
        match result {
            Ok(Some(_)) => report.synced += 1,
            Ok(None) => {}
            Err(e) => report.failed.push(pass_agent::SyncFailure {
                vault,
                reason: crate::errors::friendly(e),
            }),
        }
    }
}

/// What a "Sync now" outside the main window says: synced, the first failure, or no sync set up.
pub fn report_text(report: &pass_agent::SyncReport) -> String {
    if report.no_sync {
        return crate::i18n::tr!("sync.not_set_up");
    }
    match report.failed.first() {
        Some(f) if f.vault.trim().is_empty() => f.reason.clone(),
        Some(f) => crate::i18n::tr!("sync.failed_one", vault = f.vault, reason = f.reason),
        None => crate::i18n::tr!("sync.done"),
    }
}

/// Whether this sync takes the shared vaults along: except a quiet check within [`policy::OTHER_NUDGE_GAP`] of the last. Notes the time.
#[cfg_attr(not(feature = "webdav"), allow(dead_code))]
fn linked_due(quiet: bool) -> bool {
    let mut last = lock(&LINKED_SYNCED);
    let now = Instant::now();
    let due =
        !quiet || last.is_none_or(|t| now.saturating_duration_since(t) >= policy::OTHER_NUDGE_GAP);
    if due {
        *last = Some(now);
    }
    due
}

#[cfg_attr(not(feature = "webdav"), allow(dead_code))]
fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_now_says_what_happened() {
        use pass_agent::{SyncFailure, SyncReport};
        let none = SyncReport {
            no_sync: true,
            ..Default::default()
        };
        assert!(
            report_text(&none).contains("Set up sync"),
            "{}",
            report_text(&none)
        );
        let ok = SyncReport {
            synced: 2,
            ..Default::default()
        };
        assert_eq!(report_text(&ok), "Synced just now");
        let failed = SyncReport {
            synced: 1,
            failed: vec![SyncFailure {
                vault: "Family".into(),
                reason: "Can't reach the server.".into(),
            }],
            no_sync: false,
        };
        assert_eq!(
            report_text(&failed),
            "Couldn't sync Family: Can't reach the server."
        );
    }

    #[cfg(feature = "webdav")]
    #[test]
    fn shared_vaults_count_once_synced_and_say_why_they_failed() {
        let mut report = pass_agent::SyncReport::default();
        add_linked(
            &mut report,
            &[],
            vec![
                ("acme/shared".into(), Ok(None)),
                (
                    "other/x".into(),
                    Err(pass_core::PassError::Network("offline".into())),
                ),
            ],
        );
        assert_eq!(report.synced, 0);
        assert_eq!(report.failed.len(), 1);
        assert_eq!(report.failed[0].vault, "other/x");
        assert!(!report.failed[0].reason.is_empty());
    }

    #[test]
    fn usage_due_syncs_on_a_tick() {
        let r = Reasons {
            usage_due: true,
            ..Reasons::default()
        };
        assert!(sync_due(Wake::Tick, r));
        // Backed off after a failure: wait, as for any other reason.
        assert!(!sync_due(
            Wake::Tick,
            Reasons {
                backed_off: true,
                ..r
            }
        ));
    }

    #[test]
    fn usage_alone_is_not_an_edit() {
        // Recorded uses leave `pending` false, so nothing waits on the edit debounce.
        let r = Reasons {
            edits_settled: true,
            ..Reasons::default()
        };
        assert!(!sync_due(Wake::Tick, r));
        assert!(!sync_due(Wake::Focus, r));
        // A content edit does sync once it has settled.
        assert!(sync_due(Wake::Tick, Reasons { pending: true, ..r }));
        assert!(!sync_due(
            Wake::Tick,
            Reasons {
                pending: true,
                edits_settled: false,
                ..r
            }
        ));
    }

    #[test]
    fn kicks_ignore_the_backoff() {
        let r = Reasons {
            backed_off: true,
            ..Reasons::default()
        };
        assert!(sync_due(Wake::Kick, r));
        assert!(!sync_due(
            Wake::Focus,
            Reasons {
                nudge_gap_passed: true,
                ..r
            }
        ));
    }

    #[test]
    fn focus_checks_only_after_the_gap_or_with_changes_to_upload() {
        let r = Reasons::default();
        assert!(!sync_due(Wake::Focus, r));
        assert!(sync_due(
            Wake::Focus,
            Reasons {
                nudge_gap_passed: true,
                ..r
            }
        ));
        // Pending edits go up on focus even inside the debounce.
        assert!(sync_due(Wake::Focus, Reasons { pending: true, ..r }));
        // The periodic check on a tick.
        assert!(sync_due(
            Wake::Tick,
            Reasons {
                check_due: true,
                ..r
            }
        ));
    }

    #[test]
    fn the_extension_asking_for_logins_checks_google_drive_and_passyble_cloud() {
        assert_eq!(wake_for(NUDGE_EXTENSION, Backend::GoogleDrive), Wake::Focus);
        assert_eq!(wake_for(NUDGE_EXTENSION, Backend::Cloud), Wake::Focus);
        assert_eq!(wake_for(NUDGE_EXTENSION, Backend::Other), Wake::Tick);
        assert_eq!(wake_for(NUDGE_FOCUS, Backend::Other), Wake::Focus);
        assert_eq!(wake_for(NUDGE_FOCUS, Backend::Cloud), Wake::Focus);
        assert_eq!(wake_for(NUDGE_NONE, Backend::GoogleDrive), Wake::Kick);
        assert_eq!(wake_for(NUDGE_NONE, Backend::Cloud), Wake::Kick);
    }

    fn server_vault_at(url: &str) -> crate::settings::WebDavSettings {
        crate::settings::WebDavSettings {
            url: url.into(),
            username: "u-abc".into(),
            server_device: Some("Laptop".into()),
            ..Default::default()
        }
    }

    fn cloud_whoami(
        base: &str,
        user: &str,
        state: Option<&str>,
    ) -> (crate::teams::Backend, crate::teams_api::Whoami) {
        let backend = crate::teams::Backend::Cloud {
            base: base.into(),
            user: user.into(),
            token: "demo-token".into(),
            account: "acc_demo".into(),
        };
        let whoami = crate::teams_api::Whoami {
            user: user.into(),
            cloud: state.map(|s| crate::teams_api::CloudState {
                state: s.into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        (backend, whoami)
    }

    #[test]
    fn only_a_passyble_cloud_vault_on_a_live_plan_gets_the_cloud_schedule() {
        let cloud = server_vault_at("https://cloud.passyble.example/dav/u-abc/personal.vault");
        let live = [cloud_whoami(
            "https://cloud.passyble.example",
            "u-abc",
            Some("active"),
        )];
        assert!(cloud_plan_live(Some(&cloud), &live));
        // Case and a trailing slash don't matter; a v-* vault of the same account counts too.
        let other_case = [cloud_whoami(
            "https://Cloud.Passyble.example/",
            "u-abc",
            Some("active"),
        )];
        assert!(cloud_plan_live(Some(&cloud), &other_case));
        let v = server_vault_at("https://cloud.passyble.example/dav/u-abc/v-2.vault");
        assert!(cloud_plan_live(Some(&v), &live));
        // No `whoami` yet, or the plan isn't live: the calmer schedule.
        assert!(!cloud_plan_live(Some(&cloud), &[]));
        for state in ["read_only", "suspended", ""] {
            let lapsed = [cloud_whoami(
                "https://cloud.passyble.example",
                "u-abc",
                Some(state),
            )];
            assert!(!cloud_plan_live(Some(&cloud), &lapsed), "{state}");
        }
        // A self-hosted Passyble Server (no `cloud` in its `whoami`).
        let own = server_vault_at("https://pass.home.example:8443/dav/u-abc/personal.vault");
        let own_whoami = [cloud_whoami(
            "https://pass.home.example:8443",
            "u-abc",
            None,
        )];
        assert!(!cloud_plan_live(Some(&own), &own_whoami));
        // Another server's or another user's live plan doesn't count.
        assert!(!cloud_plan_live(Some(&own), &live));
        let bob = [cloud_whoami(
            "https://cloud.passyble.example",
            "bob",
            Some("active"),
        )];
        assert!(!cloud_plan_live(Some(&cloud), &bob));
        // Plain WebDAV at the same address (no pairing), or no account at all.
        let plain = crate::settings::WebDavSettings {
            server_device: None,
            ..cloud.clone()
        };
        assert!(!cloud_plan_live(Some(&plain), &live));
        assert!(!cloud_plan_live(None, &live));
        let no_file = server_vault_at("https://cloud.passyble.example/dav/u-abc/");
        assert!(!cloud_plan_live(Some(&no_file), &live));
    }

    #[test]
    fn a_plan_that_ended_puts_the_vault_back_on_the_calm_schedule() {
        let cloud = server_vault_at("https://cloud.passyble.example/dav/u-abc/personal.vault");
        let mut whoami = vec![
            cloud_whoami("https://cloud.passyble.example", "u-abc", Some("active")),
            cloud_whoami("https://cloud.passyble.example", "bob", Some("active")),
        ];
        note_plan_lapsed(Some(&cloud), &mut whoami);
        assert!(!cloud_plan_live(Some(&cloud), &whoami));
        assert_eq!(whoami[0].1.cloud.as_ref().unwrap().state, "read_only");
        assert_eq!(whoami[1].1.cloud.as_ref().unwrap().state, "active");
    }

    #[test]
    fn quiet_checks_take_the_shared_vaults_along_every_few_minutes() {
        // The first one does; another quiet check right after doesn't; a kick always does.
        *lock(&LINKED_SYNCED) = None;
        assert!(linked_due(true));
        assert!(!linked_due(true));
        assert!(linked_due(false));
        *lock(&LINKED_SYNCED) = Instant::now().checked_sub(policy::OTHER_NUDGE_GAP);
        assert!(linked_due(true));
    }
}
