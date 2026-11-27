//! Password health (`ui/views/health.js`): the checks of `pass_core::password_health` over the open
//! vault, computed here. The window gets titles, usernames, domains, scores and addresses, never a
//! password. The two-factor and passkey checks use the core's bundled site directories (nothing is
//! looked up online), and their links come from that data, never from the window.
//!
//! **Check for breaches** is optional and only runs when the user clicks it. Every distinct
//! password is hashed up front and dropped; `pass_core::hibp_range` then asks Have I Been Pwned's
//! range API once per distinct 5-character SHA-1 prefix, one request at a time, so only that prefix
//! leaves the PC, never the password or its full hash.
//!
//! The check is a job of the app ([`BreachJob`]), not of the window: closing the window never stops
//! it. Only Cancel, the vault locking ([`on_lock`], which also drops results) or quitting does.
//! Nothing is stored, so no hash outlives the unlocked vault.
//!
//! **Master password tip**: a master password from before the current rule still unlocks. Each
//! unlock with the typed password records whether it is below the rule (a yes or no in the vault's
//! list entry on this PC), and the report says `master_password_tip` until Dismissed.

use std::collections::HashMap;
use std::sync::Mutex;

use serde_json::{json, Value};
use tauri::{AppHandle, Emitter, State};
use zeroize::Zeroizing;

use crate::commands::{app_state, blocking, pass_err};
use crate::i18n::{tr, trn};
use crate::state::AppState;

type Res<T> = Result<T, String>;

fn item_json(i: &pass_core::HealthItem) -> Value {
    json!({
        "id": i.item_id,
        "kind": "login",
        "title": i.title,
        "username": i.username,
        "domain": i.domain,
        "site": (!i.domain.is_empty()).then(|| i.domain.clone()),
        "score": i.score,
        "password_changed_at": i.password_changed_at,
        "reuse_count": i.reuse_count,
    })
}

fn items_json(list: &[pass_core::HealthItem]) -> Vec<Value> {
    list.iter().map(item_json).collect()
}

fn site_json(s: &pass_core::SiteItem) -> Value {
    let mut v = item_json(&s.item);
    v["methods"] = json!(s.methods);
    v["docs_url"] = json!(s.docs_url);
    v
}

/// The health report of the unlocked vault. `master_password_tip` shows the master password tip;
/// `master_password_server`: the vault is on Passyble Server, so its Change password is the account's.
#[tauri::command]
pub fn password_health(state: State<'_, std::sync::Arc<AppState>>) -> Res<Value> {
    let vault = state.vault()?;
    let report = pass_core::password_health(vault);
    let settings = state.settings();
    let active = settings.active();
    Ok(json!({
        "master_password_tip": active.is_some_and(|v| v.master_password_tip_due()),
        "master_password_server": active
            .and_then(|v| v.webdav.as_ref())
            .is_some_and(|w| w.is_pass_server()),
        "breach_check": cfg!(feature = "webdav"),
        // "Don't show this again" on the notice before a breach check (this PC).
        "breach_notice_hidden": settings.breach_notice_hidden,
        "checked": report.checked,
        "healthy": report.healthy,
        "weak": items_json(&report.weak),
        "reused": report.reused.iter().map(|g| items_json(&g.items)).collect::<Vec<_>>(),
        "old": items_json(&report.old),
        "old_after_ms": pass_core::OLD_PASSWORD_MS,
        "contains_name": items_json(&report.contains_name),
        "insecure": report
            .insecure
            .iter()
            .map(|i| {
                let mut v = item_json(&i.item);
                v["urls"] = json!(i.urls);
                v["can_use_https"] = json!(i.can_use_https);
                v
            })
            .collect::<Vec<_>>(),
        "no_two_factor": report.no_two_factor.iter().map(site_json).collect::<Vec<_>>(),
        "passkeys": report.passkeys.iter().map(site_json).collect::<Vec<_>>(),
        "no_password": items_json(&report.no_password),
        "duplicates": report.duplicates.iter().map(|g| items_json(&g.items)).collect::<Vec<_>>(),
    }))
}

/// The item editor's live check of the password being typed: `pass_core::password_issues` against
/// the open vault. All on this PC; the password is not kept or logged, and the answer has no secrets.
/// Locked: only the password itself (`vault_checked: false`).
#[tauri::command]
pub fn password_check(
    state: State<'_, std::sync::Arc<AppState>>,
    password: String,
    username: Option<String>,
    urls: Option<Vec<String>>,
    title: Option<String>,
    id: Option<String>,
) -> Res<Value> {
    // Core looks at the first 4096 characters only and zeroizes its copy.
    let mut password = Zeroizing::new(password);
    let context = pass_core::PasswordContext {
        username: username.unwrap_or_default(),
        urls: urls.unwrap_or_default().into_iter().take(32).collect(),
        android_apps: vec![],
        title: title.unwrap_or_default(),
        item_id: id.unwrap_or_default(),
    };
    // A live check while typing in the editor: not activity (the save is).
    let vault = state.agent().and_then(|a| a.peek_vault());
    let check = pass_core::password_issues(vault, std::mem::take(&mut *password), context);
    Ok(pass_agent::password_check_json(&check))
}

/// The live check of a new master password as it is typed (`pass_core::master_password_check`).
/// `names`: the names the form knows; `active_vault`: also the open vault's name, server user and
/// Google account. No secrets in the answer; the commands that set the password check the rule again.
#[tauri::command]
pub fn master_password_check(
    state: State<'_, std::sync::Arc<AppState>>,
    password: String,
    names: Option<Vec<String>>,
    active_vault: Option<bool>,
) -> Value {
    let mut password = Zeroizing::new(password);
    let context = crate::commands::master_password_context(
        &state,
        &names.unwrap_or_default(),
        active_vault.unwrap_or(false),
    );
    let check = pass_core::master_password_check(std::mem::take(&mut *password), context);
    master_check_json(&check)
}

pub(crate) fn master_check_json(check: &pass_core::MasterPasswordCheck) -> Value {
    json!({
        "ok": check.ok,
        "score": check.score,
        "label": check.label,
        "entropy_bits": check.entropy_bits,
        "issues": check.issues.iter().map(|i| i.as_str()).collect::<Vec<_>>(),
        "name": check.name,
        "min_length": check.min_length,
    })
}

// Password health suggests changing a master password below the rule (it predates the rule).
// The password is only known right after unlock, so each unlock records a yes or no in the vault's
// list entry (`VaultEntry::master_password_weak`, this PC only).

/// Whether `password` is below the master password rule with the names in `context`.
fn below_master_password_rule(password: &str, context: &pass_core::MasterPasswordContext) -> bool {
    !pass_core::check_master_password(password, context).ok
}

/// Whether the master password just typed to unlock list entry `vault` is below the rule, counting
/// the names this PC knows for it. `None` for a vault that isn't listed. The password is only borrowed.
fn master_password_weak_for(state: &AppState, vault: &str, password: &str) -> Option<bool> {
    let entry = state.settings().vault(vault).cloned()?;
    let names = crate::commands::vault_entry_names(&entry);
    let context = crate::commands::master_password_context(state, &names, false);
    Some(below_master_password_rule(password, &context))
}

/// Records the result of [`master_password_weak_for`] for `vault`. Best effort: a failed save only leaves the tip one unlock behind.
fn record_master_password_unlock(state: &AppState, vault: &str, weak: Option<bool>) {
    if let Some(weak) = weak {
        update_tip(state, vault, |v| v.note_master_password_unlock(weak));
    }
}

/// A successful unlock of `vault` with the typed master password: the tip follows whether it is
/// below the rule. Windows Hello and recovery code unlocks don't call this.
pub(crate) fn note_master_password_unlock(state: &AppState, vault: &str, password: &str) {
    let weak = master_password_weak_for(state, vault, password);
    record_master_password_unlock(state, vault, weak);
}

/// The master password of `vault` was changed here: no tip, and its "Dismiss" is forgotten.
pub(crate) fn note_master_password_changed(state: &AppState, vault: &str) {
    update_tip(state, vault, |v| v.note_master_password_changed());
}

fn update_tip(state: &AppState, vault: &str, f: impl FnOnce(&mut crate::settings::VaultEntry)) {
    let saved = state.update_settings(|s| {
        if let Some(v) = s.vault_mut(vault) {
            f(v);
        }
        Ok(())
    });
    if let Err(e) = saved {
        crate::applog::plog!("master password tip: not saved: {e}");
    }
}

/// "Dismiss" on the master password tip: hidden for the active vault on this PC until its master password is changed here.
#[tauri::command]
pub fn master_password_tip_dismiss(state: State<'_, std::sync::Arc<AppState>>) -> Res<()> {
    let id = crate::vaults::active_id(&state)?;
    state.update_settings(|s| {
        if let Some(v) = s.vault_mut(&id) {
            v.master_password_tip_dismissed = true;
        }
        Ok(())
    })
}

/// "Change to https": rewrites the item's safe `http://` addresses, then saves. `{ changed }`.
#[tauri::command]
pub fn health_use_https(state: State<'_, std::sync::Arc<AppState>>, id: String) -> Res<Value> {
    let vault = state.vault()?;
    let changed = pass_core::health_use_https(vault, id).map_err(pass_err)?;
    if changed > 0 {
        state.require_agent()?.save().map_err(pass_err)?;
    }
    Ok(json!({ "changed": changed }))
}

/// Opens the bundled directory's link for item `id`'s site (`kind`: `two_factor` or `passkey`).
#[tauri::command]
pub fn health_open_guide(
    state: State<'_, std::sync::Arc<AppState>>,
    id: String,
    kind: String,
) -> Res<()> {
    let item = state
        .vault()?
        .get(id)
        .ok_or_else(|| tr!("errors.item_not_found"))?;
    let url = item
        .urls
        .iter()
        .filter_map(|u| pass_core::site_security(u.clone()))
        .map(|s| {
            if kind == "passkey" {
                s.passkey_docs
            } else {
                s.two_factor_docs
            }
        })
        .find(|d| d.starts_with("https://") || d.starts_with("http://"))
        .ok_or_else(|| tr!("errors.no_guide"))?;
    crate::platform::open_browser(&url)
}

/// The breach check, one at a time, independent of the window.
static JOB: BreachJob = BreachJob::new();

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StopReason {
    Cancelled,
    Locked,
}

impl StopReason {
    fn key(self) -> &'static str {
        match self {
            StopReason::Cancelled => "cancelled",
            StopReason::Locked => "locked",
        }
    }
}

/// Where the check is. Only item ids and counts: no password, no hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum JobState {
    Idle,
    Running {
        done: usize,
        total: usize,
    },
    Done {
        results: Vec<(String, u64)>,
        checked: usize,
        total: usize,
        failed: usize,
    },
    Stopped {
        reason: StopReason,
        done: usize,
        total: usize,
    },
    Failed {
        error: String,
    },
}

/// One request: the distinct passwords whose SHA-1 starts with `prefix`, as their other 35 characters and item ids. Memory only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PrefixGroup {
    pub prefix: String,
    pub entries: Vec<(String, Vec<String>)>,
}

/// The vault's distinct passwords grouped by SHA-1 prefix, in vault order, and how many there are.
pub(crate) fn prefix_groups<'a>(
    items: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> (Vec<PrefixGroup>, usize) {
    let mut groups: Vec<PrefixGroup> = Vec::new();
    let mut by_prefix: HashMap<String, usize> = HashMap::new();
    let mut by_hash: HashMap<(usize, String), usize> = HashMap::new();
    let mut total = 0;
    for (id, password) in items {
        if password.is_empty() {
            continue;
        }
        let query = pass_core::hibp_prefix(password.to_string());
        let g = *by_prefix.entry(query.prefix.clone()).or_insert_with(|| {
            groups.push(PrefixGroup {
                prefix: query.prefix.clone(),
                entries: Vec::new(),
            });
            groups.len() - 1
        });
        let entries = &mut groups[g].entries;
        let e = *by_hash.entry((g, query.suffix.clone())).or_insert_with(|| {
            entries.push((query.suffix.clone(), Vec::new()));
            total += 1;
            entries.len() - 1
        });
        entries[e].1.push(id.to_string());
    }
    (groups, total)
}

/// The job's state and generation (bumped by every start, cancel and lock, so a stopped run can't write over what came after it).
pub(crate) struct BreachJob {
    inner: Mutex<(JobState, u64)>,
}

impl BreachJob {
    pub(crate) const fn new() -> Self {
        Self {
            inner: Mutex::new((JobState::Idle, 0)),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, (JobState, u64)> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub(crate) fn state(&self) -> JobState {
        self.lock().0.clone()
    }

    pub(crate) fn begin(&self, total: usize) -> Res<u64> {
        let mut s = self.lock();
        if matches!(s.0, JobState::Running { .. }) {
            return Err(tr!("errors.breach_check_running"));
        }
        s.1 += 1;
        s.0 = JobState::Running { done: 0, total };
        Ok(s.1)
    }

    fn is_current(&self, generation: u64) -> bool {
        let s = self.lock();
        s.1 == generation && matches!(s.0, JobState::Running { .. })
    }

    fn set(&self, generation: u64, state: JobState) -> bool {
        let mut s = self.lock();
        if s.1 != generation || !matches!(s.0, JobState::Running { .. }) {
            return false;
        }
        s.0 = state;
        true
    }

    pub(crate) fn cancel(&self, reason: StopReason) -> bool {
        let mut s = self.lock();
        let JobState::Running { done, total } = s.0 else {
            return false;
        };
        s.1 += 1;
        s.0 = JobState::Stopped {
            reason,
            done,
            total,
        };
        true
    }

    pub(crate) fn on_lock(&self) -> bool {
        if self.cancel(StopReason::Locked) {
            return true;
        }
        let mut s = self.lock();
        if matches!(s.0, JobState::Done { .. }) {
            s.1 += 1;
            s.0 = JobState::Idle;
            return true;
        }
        false
    }
}

/// Runs `generation` of `job`: asks `fetch` for each prefix in turn (only the 5 characters ever reach
/// it) and tells `announce` each step. Stops when cancelled or `locked()` says the vault locked
/// (checked before each request; not activity, so a long check never blocks auto-lock).
pub(crate) fn run(
    job: &BreachJob,
    generation: u64,
    groups: Vec<PrefixGroup>,
    total: usize,
    mut fetch: impl FnMut(&str) -> Res<String>,
    locked: impl Fn() -> bool,
    mut announce: impl FnMut(&JobState),
) {
    let mut results = Vec::new();
    let (mut done, mut failed) = (0usize, 0usize);
    let mut last_error = None;
    for group in groups {
        if locked() && job.cancel(StopReason::Locked) {
            announce(&job.state());
        }
        if !job.is_current(generation) {
            return;
        }
        match fetch(&group.prefix) {
            Ok(body) => {
                for (suffix, ids) in &group.entries {
                    let count = pass_core::hibp_match(body.clone(), suffix.clone());
                    results.extend(ids.iter().map(|id| (id.clone(), count)));
                }
            }
            Err(e) => {
                failed += group.entries.len();
                last_error = Some(e);
            }
        }
        done += group.entries.len();
        let step = JobState::Running { done, total };
        if !job.set(generation, step.clone()) {
            return;
        }
        announce(&step);
    }
    let end = if done > 0 && failed == done {
        JobState::Failed {
            error: last_error.unwrap_or_else(|| tr!("errors.breach_check_failed")),
        }
    } else {
        JobState::Done {
            results,
            checked: done - failed,
            total,
            failed,
        }
    };
    if job.set(generation, end.clone()) {
        announce(&end);
    }
}

/// What the window gets (`health_breach_status`, `health-breach` events).
pub(crate) fn status_json(state: &JobState) -> Value {
    match state {
        JobState::Idle => json!({ "state": "idle" }),
        JobState::Running { done, total } => {
            json!({ "state": "running", "done": done, "total": total })
        }
        JobState::Done {
            results,
            checked,
            total,
            failed,
        } => json!({
            "state": "done",
            "results": results.iter().map(|(id, count)| json!({ "id": id, "count": count })).collect::<Vec<_>>(),
            "checked": checked,
            "total": total,
            "failed": failed,
        }),
        JobState::Stopped {
            reason,
            done,
            total,
        } => {
            json!({ "state": "stopped", "reason": reason.key(), "done": done, "total": total })
        }
        JobState::Failed { error } => json!({ "state": "failed", "error": error }),
    }
}

pub(crate) fn running_text() -> Option<String> {
    match JOB.state() {
        JobState::Running { done, total } => Some(trn!("health.progress", total, done = done)),
        _ => None,
    }
}

/// "Check for breaches": starts the check in the background and answers at once. Only the first 5 characters of each SHA-1 are sent.
#[tauri::command]
pub async fn health_breach_check(app: AppHandle) -> Res<Value> {
    if !cfg!(feature = "webdav") {
        return Err(tr!("errors.no_network_build"));
    }
    let prep = app.clone();
    // Off the UI thread: reading the items and hashing every password.
    let (groups, total) = blocking(move || {
        let vault = app_state(&prep).vault()?;
        // The passwords are hashed here and dropped with the items: the job keeps only the hashes.
        let items = vault.items();
        Ok(prefix_groups(
            items.iter().map(|i| (i.id.as_str(), i.password.as_str())),
        ))
    })
    .await?;
    let generation = JOB.begin(total)?;
    let now = JOB.state();
    announce(&app, &now);
    let handle = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let watch = handle.clone();
        run(
            &JOB,
            generation,
            groups,
            total,
            range,
            || app_state(&watch).quiet_vault().is_err(),
            |s| announce(&handle, s),
        );
    });
    Ok(status_json(&now))
}

/// The check's state, for Password health when it opens.
#[tauri::command]
pub fn health_breach_status() -> Value {
    status_json(&JOB.state())
}

#[tauri::command]
pub fn health_breach_cancel(app: AppHandle) {
    cancel(&app);
}

pub(crate) fn cancel(app: &AppHandle) {
    if JOB.cancel(StopReason::Cancelled) {
        announce(app, &JOB.state());
    }
}

#[tauri::command]
pub fn health_breach_notice(state: State<'_, std::sync::Arc<AppState>>, hidden: bool) -> Res<()> {
    state.update_settings(|s| {
        s.breach_notice_hidden = hidden;
        Ok(())
    })
}

pub(crate) fn on_lock(app: &AppHandle) {
    if JOB.on_lock() {
        announce(app, &JOB.state());
    }
}

/// Tells the windows (`health-breach`) and the tray about progress and the end.
fn announce(app: &AppHandle, state: &JobState) {
    let _ = app.emit("health-breach", status_json(state));
    match state {
        JobState::Running { done, total } => {
            crate::tray::breach_progress(app, Some(trn!("health.progress", *total, done = *done)));
        }
        JobState::Done { results, .. } => {
            crate::tray::breach_progress(app, None);
            let breached = results.iter().filter(|(_, n)| *n > 0).count();
            let text = if breached == 0 {
                tr!("health.breach_done_none")
            } else {
                trn!("health.breach_done_found", breached)
            };
            crate::tray::notify(app, &text);
        }
        _ => crate::tray::breach_progress(app, None),
    }
}

#[cfg(feature = "webdav")]
fn range(prefix: &str) -> Res<String> {
    pass_core::hibp_range(prefix).map_err(|e| match e {
        pass_core::PassError::Network(m) => crate::errors::network(&m),
        other => crate::errors::friendly(other),
    })
}

#[cfg(not(feature = "webdav"))]
fn range(_: &str) -> Res<String> {
    Err(tr!("errors.no_network_build"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::{GoogleDriveSettings, VaultEntry, WebDavSettings};

    fn context(entry: &VaultEntry) -> pass_core::MasterPasswordContext {
        pass_core::MasterPasswordContext {
            names: crate::commands::vault_entry_names(entry),
        }
    }

    #[test]
    fn the_tip_judges_the_typed_password_by_the_master_password_rule() {
        let plain = VaultEntry::default();
        // Older, guessable master passwords (they still unlock).
        for weak in ["Password1234!", "aaaaaaaaaaaaaaaa", "qwerty123"] {
            assert!(below_master_password_rule(weak, &context(&plain)), "{weak}");
        }
        // A random password and a passphrase pass, as they would for a new master password.
        for strong in ["T7#qL9v!mZ2@wR4k", "orbit-candle-meadow-violin-harbor"] {
            assert!(
                !below_master_password_rule(strong, &context(&plain)),
                "{strong}"
            );
        }
    }

    #[test]
    fn the_tip_counts_the_names_this_pc_knows_for_the_vault() {
        let entry = VaultEntry {
            name: "Alexander".into(),
            webdav: Some(WebDavSettings {
                username: "alex.smith".into(),
                ..Default::default()
            }),
            google_drive: Some(GoogleDriveSettings {
                account_email: "alex.smith@example.com".into(),
                sign_in_needed: false,
            }),
            ..Default::default()
        };
        let names = crate::commands::vault_entry_names(&entry);
        assert_eq!(names, ["Alexander", "alex.smith", "alex.smith@example.com"]);
        let built_from_names = "alex.smith@example.com2024";
        assert!(below_master_password_rule(
            built_from_names,
            &context(&entry)
        ));
    }

    fn fake_range(prefix: &str, breached: &[(&str, u64)]) -> String {
        let mut lines = vec!["0000000000000000000000000000000000A:0".to_string()];
        for (password, count) in breached {
            let q = pass_core::hibp_prefix(password.to_string());
            if q.prefix == prefix {
                lines.push(format!("{}:{count}", q.suffix));
            }
        }
        lines.join("\r\n")
    }

    fn same_prefix_pair() -> (String, String) {
        let mut seen = HashMap::new();
        for i in 0.. {
            let p = format!("demo-{i}");
            let prefix = pass_core::hibp_prefix(p.clone()).prefix;
            if let Some(other) = seen.insert(prefix, p.clone()) {
                return (other, p);
            }
        }
        unreachable!()
    }

    #[test]
    fn passwords_are_grouped_by_prefix_and_each_distinct_one_counted_once() {
        let (a, b) = same_prefix_pair();
        let items = [
            ("1", a.as_str()),
            ("2", b.as_str()),
            ("3", a.as_str()),
            ("4", ""),
            ("5", "another demo"),
        ];
        let (groups, total) = prefix_groups(items);
        assert_eq!(total, 3);
        assert_eq!(groups.len(), 2, "one request per prefix");
        assert!(groups
            .iter()
            .all(|g| g.prefix.len() == 5 && g.prefix.bytes().all(|c| c.is_ascii_hexdigit())));
        let shared = &groups[0];
        assert_eq!(shared.entries.len(), 2);
        assert_eq!(shared.entries[0].1, ["1", "3"]);
        assert_eq!(shared.entries[1].1, ["2"]);
        // Only the 35-character rest of each hash is kept, never the password.
        assert!(groups
            .iter()
            .flat_map(|g| &g.entries)
            .all(|(suffix, _)| suffix.len() == 35));
    }

    #[test]
    fn the_job_finishes_with_every_item_and_its_count() {
        let job = BreachJob::new();
        let breached = [("password", 9_000_000u64)];
        let (groups, total) = prefix_groups([
            ("a", "password"),
            ("b", "kT9#vQ2!wLp7@zR"),
            ("c", "password"),
        ]);
        let generation = job.begin(total).unwrap();
        let mut asked = Vec::new();
        let mut seen = Vec::new();
        run(
            &job,
            generation,
            groups,
            total,
            |prefix| {
                asked.push(prefix.to_string());
                Ok(fake_range(prefix, &breached))
            },
            || false,
            |s| seen.push(s.clone()),
        );
        assert_eq!(asked.len(), 2);
        assert!(asked.iter().all(|p| p.len() == 5));
        let JobState::Done {
            mut results,
            checked,
            total,
            failed,
        } = job.state()
        else {
            panic!("{:?}", job.state())
        };
        results.sort();
        assert_eq!(
            results,
            [
                ("a".to_string(), 9_000_000),
                ("b".to_string(), 0),
                ("c".to_string(), 9_000_000)
            ]
        );
        assert_eq!((checked, total, failed), (2, 2, 0));
        // Progress for each request, then the end.
        assert_eq!(seen.len(), 3);
        assert!(matches!(seen[0], JobState::Running { done: 1, total: 2 }));
        assert!(matches!(seen[2], JobState::Done { .. }));
        let status = status_json(&job.state());
        assert_eq!(status["state"], "done");
        assert_eq!(status["checked"], 2);
    }

    #[test]
    fn cancel_stops_the_job_and_a_late_answer_changes_nothing() {
        let job = BreachJob::new();
        let (groups, total) = prefix_groups([
            ("a", "first demo"),
            ("b", "second demo"),
            ("c", "third demo"),
        ]);
        let generation = job.begin(total).unwrap();
        let mut asked = 0;
        run(
            &job,
            generation,
            groups,
            total,
            |prefix| {
                asked += 1;
                // Cancel arrives while the first request is under way.
                assert!(job.cancel(StopReason::Cancelled));
                Ok(fake_range(prefix, &[]))
            },
            || false,
            |_| {},
        );
        assert_eq!(asked, 1, "no request after Cancel");
        assert_eq!(
            job.state(),
            JobState::Stopped {
                reason: StopReason::Cancelled,
                done: 0,
                total: 3
            }
        );
        assert_eq!(status_json(&job.state())["reason"], "cancelled");
        // A new check can start; the old run can't write over it.
        let next = job.begin(1).unwrap();
        assert!(!job.set(generation, JobState::Idle));
        assert!(job.is_current(next));
    }

    #[test]
    fn locking_the_vault_stops_the_job() {
        let job = BreachJob::new();
        let (groups, total) = prefix_groups([("a", "first demo"), ("b", "second demo")]);
        let generation = job.begin(total).unwrap();
        let locked = std::cell::Cell::new(false);
        run(
            &job,
            generation,
            groups,
            total,
            |prefix| {
                // The vault locks after the first answer.
                locked.set(true);
                Ok(fake_range(prefix, &[]))
            },
            || locked.get(),
            |_| {},
        );
        assert_eq!(
            job.state(),
            JobState::Stopped {
                reason: StopReason::Locked,
                done: 1,
                total: 2
            }
        );
        assert_eq!(status_json(&job.state())["reason"], "locked");
    }

    #[test]
    fn the_lock_hook_stops_a_running_job_and_drops_finished_results() {
        let job = BreachJob::new();
        job.begin(4).unwrap();
        assert!(job.on_lock());
        assert!(matches!(
            job.state(),
            JobState::Stopped {
                reason: StopReason::Locked,
                ..
            }
        ));

        let (groups, total) = prefix_groups([("a", "password")]);
        let generation = job.begin(total).unwrap();
        run(
            &job,
            generation,
            groups,
            total,
            |p| Ok(fake_range(p, &[("password", 3)])),
            || false,
            |_| {},
        );
        assert!(matches!(job.state(), JobState::Done { .. }));
        assert!(job.on_lock());
        assert_eq!(job.state(), JobState::Idle);
        assert!(!job.on_lock(), "nothing left to drop");
    }

    #[test]
    fn one_check_at_a_time() {
        let job = BreachJob::new();
        job.begin(2).unwrap();
        assert!(matches!(job.state(), JobState::Running { .. }));
        assert!(job.begin(2).is_err());
        assert!(job.cancel(StopReason::Cancelled));
        assert!(!job.cancel(StopReason::Cancelled), "nothing runs any more");
        assert!(job.begin(2).is_ok());
    }

    #[test]
    fn a_check_where_every_request_failed_ends_with_the_error() {
        let job = BreachJob::new();
        let (groups, total) = prefix_groups([("a", "first demo"), ("b", "second demo")]);
        let generation = job.begin(total).unwrap();
        run(
            &job,
            generation,
            groups,
            total,
            |_| Err("offline".to_string()),
            || false,
            |_| {},
        );
        assert_eq!(
            job.state(),
            JobState::Failed {
                error: "offline".into()
            }
        );
        assert_eq!(status_json(&job.state())["state"], "failed");
    }

    #[test]
    fn an_empty_vault_finishes_at_once() {
        let job = BreachJob::new();
        let (groups, total) = prefix_groups([("a", "")]);
        let generation = job.begin(total).unwrap();
        run(
            &job,
            generation,
            groups,
            total,
            |_| panic!("nothing to ask"),
            || false,
            |_| {},
        );
        assert!(matches!(
            job.state(),
            JobState::Done {
                checked: 0,
                total: 0,
                ..
            }
        ));
    }

    #[test]
    fn the_notice_flag_is_off_by_default_and_kept_only_when_on() {
        let settings = crate::settings::Settings::default();
        assert!(!settings.breach_notice_hidden);
        let written = serde_json::to_value(&settings).unwrap();
        assert!(written.get("breach_notice_hidden").is_none());
        let hidden = crate::settings::Settings {
            breach_notice_hidden: true,
            ..Default::default()
        };
        let back: crate::settings::Settings =
            serde_json::from_value(serde_json::to_value(&hidden).unwrap()).unwrap();
        assert!(back.breach_notice_hidden);
        let old: crate::settings::Settings = serde_json::from_str("{}").unwrap();
        assert!(
            !old.breach_notice_hidden,
            "settings files from before the notice show it"
        );
    }
}
