//! Teams and Family (docs/ARCHITECTURE.md §15 to §17): the parts that don't touch the open
//! vaults. What the services said last, the backends this PC talks to, the effective policy and its
//! enforcement, the words for members notices, and the tray notifications. `teams_vaults.rs` links the
//! shared vaults and has the member commands, `teams_admin.rs` the admin and family manager ones,
//! `teams_send.rs` secure send, emergency access and admin-assisted recovery.
//!
//! **Backends.** A shared vault lives on a Passyble Server, and the account id is the backend's:
//! * self-hosted: the active vault's Passyble Server account (`signin.rs`); the account id is the
//!   server user name;
//! * Passyble Cloud: the Passyble account (`account.rs`) and its Cloud device (`POST
//!   /v1/cloud/devices`, made once per app session); the account id is the `acc_` id.
//!
//! **Visibility.** Nothing shows for a user without a Passyble account and without a shared vault on
//! the active vault's server ([`visible`]).
//!
//! **Policies** (§17): the strictest of every organisation's policy. Enforced here: a strong enough new
//! master password, the auto-lock cap (also applied to the agent) and export of shared vaults. The last
//! policy seen is kept in `settings.json` so it holds offline. A Team's password mode is apart
//! (`password_mode.rs`).

use std::collections::BTreeSet;
use std::sync::Mutex;

use pass_core::{MemberChange, MemberRole, MembersNotice, OrgPolicy, PolicyRule};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tauri::{AppHandle, Emitter};

use crate::commands::app_state;
use crate::i18n::tr;
use crate::teams_api::{OrgSummary, ServerNotifications, Whoami};

type Res<T> = Result<T, String>;

/// What `settings.json` keeps for Teams and Family (no secret, no item data).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TeamsSettings {
    /// `since` for the next `GET /api/v1/notifications` (the server's `now`).
    pub notifications_since: i64,
    /// Keys (`<owner>/<vault>`) of the shared vaults seen so far: a new one is "shared with you",
    /// a missing one "removed" (Passyble Cloud has no notifications route for apps).
    pub seen_vaults: Vec<String>,
    /// People already notified as "confirm this person" (`<vault>|<account>|<fingerprint>`).
    pub seen_confirm: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub orgs: Vec<CachedOrg>,
    #[serde(skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub labels: std::collections::BTreeMap<String, String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CachedOrg {
    pub id: String,
    pub kind: String,
    pub name: String,
    pub role: String,
    pub policy: String,
    pub sign_in_ok: bool,
    pub sharing_blocked: bool,
}

#[derive(Default)]
pub struct Cache {
    pub whoami: Vec<(Backend, Whoami)>,
    pub labels: Vec<(String, String, Option<String>)>,
    pub notifications: Notifications,
    pub notices: Vec<Value>,
    pub invites: Vec<Value>,
    pub password_score: Option<u32>,
    pub last_error: Option<String>,
    pub refreshed_ms: Option<i64>,
    pub device_waiting: Option<Value>,
    /// Shared vaults held until this device signs in as the organisation requires: `{ name, reason }`.
    pub held: Vec<Value>,
}

pub static CACHE: Mutex<Cache> = Mutex::new(Cache {
    whoami: Vec::new(),
    labels: Vec::new(),
    notifications: Notifications {
        shared_with_you: Vec::new(),
        removed: Vec::new(),
        waiting_for_confirmation: Vec::new(),
        confirm: Vec::new(),
    },
    notices: Vec::new(),
    invites: Vec::new(),
    password_score: None,
    last_error: None,
    refreshed_ms: None,
    device_waiting: None,
    held: Vec::new(),
});

pub fn cache() -> std::sync::MutexGuard<'static, Cache> {
    CACHE.lock().unwrap_or_else(|p| p.into_inner())
}

#[derive(Clone, PartialEq, Eq)]
pub enum Backend {
    Server {
        base: String,
        user: String,
        token: String,
        pins: Vec<String>,
    },
    Cloud {
        base: String,
        user: String,
        token: String,
        account: String,
    },
}

impl std::fmt::Debug for Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.kind())?;
        f.write_str(":")?;
        f.write_str(self.base())
    }
}

impl Backend {
    pub fn kind(&self) -> &'static str {
        match self {
            Backend::Server { .. } => "server",
            Backend::Cloud { .. } => "cloud",
        }
    }

    pub fn base(&self) -> &str {
        match self {
            Backend::Server { base, .. } | Backend::Cloud { base, .. } => base,
        }
    }

    pub fn account_id(&self) -> &str {
        match self {
            Backend::Server { user, .. } => user,
            Backend::Cloud { account, .. } => account,
        }
    }

    /// HTTP Basic user name and device token (a secret: never logged).
    pub fn credentials(&self) -> (&str, &str) {
        match self {
            Backend::Server { user, token, .. } | Backend::Cloud { user, token, .. } => {
                (user, token)
            }
        }
    }

    pub fn pins(&self) -> &[String] {
        match self {
            Backend::Server { pins, .. } => pins,
            Backend::Cloud { .. } => &[],
        }
    }

    pub fn api(&self) -> crate::teams_api::ServerApi<'static> {
        let (user, token) = match self {
            Backend::Server { user, token, .. } | Backend::Cloud { user, token, .. } => {
                (user, token)
            }
        };
        crate::teams_api::ServerApi::new(
            self.base(),
            user,
            token,
            self.pins(),
            crate::teams_api::transport(),
        )
    }
}

pub fn server_backend(app: &AppHandle) -> Option<Backend> {
    let state = app_state(app);
    let settings = state.settings();
    let vault = settings.active()?;
    let webdav = vault.webdav.as_ref().filter(|w| w.is_pass_server())?;
    let token = crate::settings::webdav_password(&vault.id, webdav).filter(|t| !t.is_empty())?;
    let base = crate::signin::server_base(&webdav.url)?;
    Some(Backend::Server {
        base,
        user: webdav.username.clone(),
        token,
        pins: webdav.pins.clone(),
    })
}

pub fn cloud_backend(app: &AppHandle) -> Option<Backend> {
    let account = crate::account::signed_in(app)?;
    let cloud = account.cloud.as_ref()?;
    let token = crate::account::store().get(&crate::account::cloud_token_name(&account.id))?;
    Some(Backend::Cloud {
        base: cloud.server_url.trim_end_matches('/').to_string(),
        user: cloud.user.clone(),
        token: token.to_string(),
        account: account.id.clone(),
    })
}

/// A policy as the services send it, in the core's key names (the account service and the hints
/// pass-server relays use `min_password_score`, `share_outside`, `sign_in`).
pub fn normalize_policy(v: &Value) -> Value {
    let Some(obj) = v.as_object() else {
        return json!({});
    };
    let mut out = serde_json::Map::new();
    for (k, val) in obj {
        match k.as_str() {
            "min_password_score" | "min_master_password_score" => {
                out.insert("master_password_min_strength".into(), val.clone());
            }
            "share_outside" => {
                out.insert("sharing_outside_allowed".into(), val.clone());
            }
            "sign_in" => {
                let strong = val.as_str().is_some_and(|s| s != "any");
                out.insert("require_two_step".into(), json!(strong));
            }
            // 0 clears the maximum.
            "max_auto_lock_minutes" if val.as_u64() == Some(0) => {}
            _ => {
                out.entry(k.clone()).or_insert_with(|| val.clone());
            }
        }
    }
    Value::Object(out)
}

pub fn parse_policy(v: &Value) -> Option<OrgPolicy> {
    pass_core::policy_parse(&normalize_policy(v).to_string()).ok()
}

pub fn strictest(policies: &[Value]) -> Option<OrgPolicy> {
    let parsed: Vec<OrgPolicy> = policies.iter().filter_map(parse_policy).collect();
    (!policies.is_empty()).then(|| pass_core::policy_strictest(parsed))
}

pub fn effective_policy(app: &AppHandle) -> Option<OrgPolicy> {
    let json = app_state(app).settings().teams.and_then(|t| t.policy)?;
    pass_core::policy_parse(&json).ok()
}

pub fn policy_json(p: &OrgPolicy) -> Value {
    json!({
        "master_password_min_strength": p.min_master_password_score,
        "max_auto_lock_minutes": p.max_auto_lock_secs.map(|s| s.div_ceil(60).max(1)),
        "export_allowed": p.export_allowed,
        "sharing_outside_allowed": p.sharing_outside_allowed,
        "require_two_step": p.require_two_step,
    })
}

fn policy_file(p: &OrgPolicy) -> String {
    json!({
        "master_password_min_strength": p.min_master_password_score,
        "max_auto_lock_minutes": p.max_auto_lock_secs.map(|s| s / 60),
        "export_allowed": p.export_allowed,
        "sharing_outside_allowed": p.sharing_outside_allowed,
        "require_two_step": p.require_two_step,
    })
    .to_string()
}

pub fn auto_lock_cap(policy: Option<&OrgPolicy>) -> Option<u32> {
    policy
        .and_then(|p| p.max_auto_lock_secs)
        .map(|s| u32::try_from(s / 60).unwrap_or(u32::MAX).max(1))
}

pub fn clamp_auto_lock(minutes: u32, policy: Option<&OrgPolicy>) -> u32 {
    match auto_lock_cap(policy) {
        Some(max) => minutes.min(max),
        None => minutes,
    }
}

fn settings_policy(settings: &crate::settings::Settings) -> Option<OrgPolicy> {
    settings
        .teams
        .as_ref()
        .and_then(|t| t.policy.as_deref())
        .and_then(|j| pass_core::policy_parse(j).ok())
}

pub fn settings_cap(settings: &crate::settings::Settings) -> Option<u32> {
    auto_lock_cap(settings_policy(settings).as_ref())
}

pub fn auto_lock_minutes(settings: &crate::settings::Settings) -> u32 {
    clamp_auto_lock(settings.auto_lock_minutes, settings_policy(settings).as_ref())
}

pub fn password_refusal(policy: Option<&OrgPolicy>, password: &str) -> Option<String> {
    let policy = policy?.clone();
    pass_core::policy_check_master_password(policy, password.to_string()).map(|v| v.message)
}

pub fn check_master_password(app: &AppHandle, password: &str) -> Res<()> {
    match password_refusal(effective_policy(app).as_ref(), password) {
        Some(message) => Err(message),
        None => Ok(()),
    }
}

/// Whether the shared vaults may be exported (a personal vault always may).
pub fn export_allowed(app: &AppHandle) -> bool {
    pass_core::policy_allows_export(effective_policy(app))
}

pub fn violations(app: &AppHandle, policy: &OrgPolicy) -> Vec<Value> {
    let settings = app_state(app).settings();
    let two_step_ok = settings
        .teams
        .as_ref()
        .map(|t| t.orgs.iter().all(|o| o.sign_in_ok))
        .unwrap_or(true);
    let local = pass_core::LocalSecurity {
        master_password_score: cache().password_score,
        // "On every restart" and "When the computer locks" never lock for being idle.
        auto_lock_secs: crate::auto_lock::chosen_idle_secs(&settings),
        two_step_enabled: two_step_ok,
    };
    pass_core::policy_violations(policy.clone(), local)
        .into_iter()
        .map(|v| {
            json!({
                "rule": match v.rule {
                    PolicyRule::MasterPasswordStrength => "master_password_strength",
                    PolicyRule::AutoLock => "auto_lock",
                    PolicyRule::TwoStep => "two_step",
                },
                "message": v.message,
            })
        })
        .collect()
}

/// Remembers the policy and the organisations from a refresh, applying a shorter auto-lock at
/// once. `orgs`: `None` when the account service wasn't asked (no account, or offline: keep them).
pub fn remember(app: &AppHandle, orgs: Option<&[OrgSummary]>, hints: &[Value]) {
    let state = app_state(app);
    let mut policies: Vec<Value> = hints.to_vec();
    let previous = state.settings().teams.unwrap_or_default();
    match orgs {
        Some(orgs) => policies.extend(orgs.iter().map(|o| o.policy.clone())),
        None => policies.extend(
            previous
                .orgs
                .iter()
                .filter_map(|o| serde_json::from_str::<Value>(&o.policy).ok()),
        ),
    }
    let policy = strictest(&policies).map(|p| policy_file(&p));
    let cached: Option<Vec<CachedOrg>> = orgs.map(|orgs| {
        orgs.iter()
            .map(|o| CachedOrg {
                id: o.id.clone(),
                kind: o.kind.clone(),
                name: o.name.clone(),
                role: o.role.clone(),
                policy: o.policy.to_string(),
                sign_in_ok: o.sign_in_ok,
                sharing_blocked: o.sharing_blocked,
            })
            .collect()
    });
    let old_cap = crate::auto_lock::idle_limit(&state.settings());
    let _ = state.update_settings(|s| {
        let t = s.teams.get_or_insert_with(Default::default);
        t.policy = policy.clone();
        if let Some(orgs) = cached.clone() {
            t.orgs = orgs;
        }
        Ok(())
    });
    if crate::auto_lock::idle_limit(&state.settings()) != old_cap {
        state.reconfigure_agent();
    }
}

pub fn cached_orgs(app: &AppHandle) -> Value {
    let orgs = app_state(app)
        .settings()
        .teams
        .map(|t| t.orgs)
        .unwrap_or_default();
    Value::Array(
        orgs.iter()
            .map(|o| {
                let policy = serde_json::from_str::<Value>(&o.policy)
                    .ok()
                    .and_then(|p| parse_policy(&p))
                    .unwrap_or_default();
                let mut policy = policy_json(&policy);
                policy["password_mode"] = json!(crate::password_mode::org_mode(o).as_str());
                json!({
                    "id": o.id, "kind": o.kind, "name": o.name, "role": o.role,
                    "policy": policy, "sign_in_ok": o.sign_in_ok,
                })
            })
            .collect(),
    )
}

pub fn cached_org(app: &AppHandle, org: &str) -> Option<CachedOrg> {
    app_state(app)
        .settings()
        .teams?
        .orgs
        .into_iter()
        .find(|o| o.id == org)
}

pub fn visible(signed_in: bool, orgs: usize, shared_vaults: usize) -> bool {
    (signed_in && orgs > 0) || shared_vaults > 0
}

/// The Passyble account changed (signed in, out, or the service signed it out): forget what the
/// services said, refresh in the background, tell the windows.
pub fn account_changed(app: &AppHandle) {
    {
        let mut c = cache();
        c.whoami.retain(|(b, _)| b.kind() == "server");
        c.labels.clear();
        c.invites.clear();
    }
    crate::password_mode::forget_report();
    if crate::account::signed_in(app).is_none() {
        let state = app_state(app);
        let _ = state.update_settings(|s| {
            if let Some(t) = s.teams.as_mut() {
                t.orgs.clear();
            }
            Ok(())
        });
    }
    let app = app.clone();
    let _ = std::thread::Builder::new()
        .name("pass-teams-refresh".into())
        .spawn(move || {
            let _ = crate::teams_vaults::refresh(&app);
        });
}

pub fn summary(app: &AppHandle) -> Option<pass_agent::TeamsSummary> {
    let signed_in = crate::account::signed_in(app).is_some();
    let orgs = app_state(app)
        .settings()
        .teams
        .map(|t| t.orgs.len())
        .unwrap_or(0);
    let shared = app_state(app)
        .agent()
        .map(|a| a.linked_configs().len())
        .unwrap_or(0);
    if !visible(signed_in, orgs, shared) {
        return None;
    }
    let c = cache();
    Some(pass_agent::TeamsSummary {
        invites: c.invites.len() as u32,
        to_confirm: c.notifications.confirm.len() as u32,
        notices: (c.notices.len()
            + c.notifications.shared_with_you.len()
            + c.notifications.removed.len()) as u32,
    })
}

pub fn emit_changed(app: &AppHandle) {
    let _ = app.emit("teams-changed", ());
}

pub fn role_word(role: MemberRole) -> String {
    match role {
        MemberRole::Manage => tr!("teams_rs.role_manage"),
        MemberRole::Edit => tr!("teams_rs.role_edit"),
        MemberRole::View => tr!("teams_rs.role_view"),
        MemberRole::Fill => tr!("teams_rs.role_fill"),
    }
}

pub fn change_words(change: &MemberChange) -> String {
    match change {
        MemberChange::Add { keys, role, .. } => {
            tr!(
                "teams_rs.change_add",
                account = keys.account,
                role = role_word(*role)
            )
        }
        MemberChange::SetRole { account, role } => {
            tr!(
                "teams_rs.change_role",
                account = account,
                role = role_word(*role)
            )
        }
        MemberChange::SetGroup { account, group } => match group {
            Some(group) => tr!("teams_rs.change_group", account = account, group = group),
            None => tr!("teams_rs.change_group_none", account = account),
        },
        MemberChange::ReplaceKeys { keys } => {
            tr!("teams_rs.change_keys", account = keys.account)
        }
        MemberChange::Remove { account } => tr!("teams_rs.change_remove", account = account),
    }
}

pub fn notice_json(vault_id: &str, name: &str, notice: &MembersNotice) -> Value {
    json!({
        "vault_id": vault_id,
        "name": name,
        "reapplied": notice.reapplied.iter().map(change_words).collect::<Vec<_>>(),
        "dropped": notice.dropped.iter().map(change_words).collect::<Vec<_>>(),
        "rotated_after_leave": notice.rotated_after_leave,
        "summary": notice_summary(name, notice),
    })
}

pub fn notice_summary(name: &str, notice: &MembersNotice) -> String {
    let mut parts = Vec::new();
    if !notice.reapplied.is_empty() {
        parts.push(crate::i18n::trn!(
            "teams_rs.notice_reapplied",
            notice.reapplied.len() as i64,
            vault = name
        ));
    }
    if !notice.dropped.is_empty() {
        parts.push(crate::i18n::trn!(
            "teams_rs.notice_dropped",
            notice.dropped.len() as i64,
            vault = name
        ));
    }
    if notice.rotated_after_leave {
        parts.push(tr!("teams_rs.notice_rotated", vault = name));
    }
    parts.join(" ")
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct Notifications {
    pub shared_with_you: Vec<Value>,
    pub removed: Vec<Value>,
    pub waiting_for_confirmation: Vec<Value>,
    pub confirm: Vec<Value>,
}

impl Notifications {
    pub fn is_empty(&self) -> bool {
        self.shared_with_you.is_empty()
            && self.removed.is_empty()
            && self.waiting_for_confirmation.is_empty()
            && self.confirm.is_empty()
    }

    pub fn absorb(&mut self, other: Notifications) {
        self.shared_with_you.extend(other.shared_with_you);
        self.removed.extend(other.removed);
        self.waiting_for_confirmation
            .extend(other.waiting_for_confirmation);
        self.confirm.extend(other.confirm);
    }
}

fn s(v: &Value, k: &str) -> String {
    v.get(k)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

pub fn from_server(n: &ServerNotifications) -> Notifications {
    Notifications {
        shared_with_you: n
            .shared_with_you
            .iter()
            .map(|v| {
                json!({ "key": s(v, "vault"), "name": vault_name(&s(v, "vault")), "by": s(v, "added_by"),
                        "at": v.get("added_at"), "role": s(v, "role") })
            })
            .collect(),
        removed: n
            .removed
            .iter()
            .map(|v| json!({ "key": s(v, "vault"), "name": vault_name(&s(v, "vault")), "by": s(v, "by"), "at": v.get("at") }))
            .collect(),
        waiting_for_confirmation: n
            .waiting_for_confirmation
            .iter()
            .map(|v| json!({ "key": s(v, "vault"), "name": vault_name(&s(v, "vault")), "since": v.get("since") }))
            .collect(),
        confirm: n
            .confirm
            .iter()
            .map(|v| {
                json!({ "key": s(v, "vault"), "vault_name": vault_name(&s(v, "vault")),
                        "account": s(v, "user"), "fingerprint": s(v, "fingerprint"),
                        "since": v.get("since"), "org": null })
            })
            .collect(),
    }
}

pub fn vault_name(key: &str) -> String {
    key.rsplit('/').next().unwrap_or(key).to_string()
}

/// Passyble Cloud has no notifications route for apps: "shared with you" and "removed" are the
/// shared vaults that appeared or went since the last look. `(shared, removed)` keys.
pub fn vault_changes(seen: &[String], now: &[String]) -> (Vec<String>, Vec<String>) {
    let seen_set: BTreeSet<&String> = seen.iter().collect();
    let now_set: BTreeSet<&String> = now.iter().collect();
    (
        now.iter()
            .filter(|k| !seen_set.contains(k))
            .cloned()
            .collect(),
        seen.iter()
            .filter(|k| !now_set.contains(k))
            .cloned()
            .collect(),
    )
}

/// The tray notifications for what is new: one per kind (shared with you, confirm this person,
/// removed), `None` when there is nothing new of that kind. `first`: the very first look on this
/// PC, which notifies nothing (everything would be "new").
pub fn tray_texts(
    first: bool,
    shared: &[String],
    removed: &[String],
    new_confirm: usize,
) -> Vec<String> {
    if first {
        return Vec::new();
    }
    let mut out = Vec::new();
    match shared {
        [] => {}
        [one] => out.push(tr!("teams_rs.notify_shared_one", vault = one)),
        many => out.push(crate::i18n::trn!(
            "teams_rs.notify_shared",
            many.len() as i64
        )),
    }
    if new_confirm > 0 {
        out.push(crate::i18n::trn!(
            "teams_rs.notify_confirm",
            new_confirm as i64
        ));
    }
    match removed {
        [] => {}
        [one] => out.push(tr!("teams_rs.notify_removed_one", vault = one)),
        many => out.push(crate::i18n::trn!(
            "teams_rs.notify_removed",
            many.len() as i64
        )),
    }
    out
}

pub fn note_seen(
    app: &AppHandle,
    vault_keys: &[String],
    names: &dyn Fn(&str) -> String,
    confirm_ids: &[String],
    since: Option<i64>,
) -> Vec<String> {
    let state = app_state(app);
    let previous = state.settings().teams.unwrap_or_default();
    let first = previous.seen_vaults.is_empty() && previous.notifications_since == 0;
    let (shared, removed) = vault_changes(&previous.seen_vaults, vault_keys);
    let new_confirm = confirm_ids
        .iter()
        .filter(|c| !previous.seen_confirm.contains(c))
        .count();
    let shared_names: Vec<String> = shared.iter().map(|k| names(k)).collect();
    let removed_names: Vec<String> = removed.iter().map(|k| vault_name(k)).collect();
    let texts = tray_texts(first, &shared_names, &removed_names, new_confirm);
    let mut keys = vault_keys.to_vec();
    keys.sort();
    let _ = state.update_settings(|s| {
        let t = s.teams.get_or_insert_with(Default::default);
        t.seen_vaults = keys.clone();
        t.seen_confirm = confirm_ids.to_vec();
        if let Some(since) = since {
            t.notifications_since = since;
        } else if t.notifications_since == 0 {
            t.notifications_since = 1;
        }
        Ok(())
    });
    texts
}

#[tauri::command]
pub fn policy_status(app: AppHandle) -> Value {
    let policy = effective_policy(&app);
    let settings = app_state(&app).settings();
    json!({
        "effective": policy.as_ref().map(policy_json),
        "violations": policy.as_ref().map(|p| violations(&app, p)).unwrap_or_default(),
        "auto_lock_max_minutes": auto_lock_cap(policy.as_ref()),
        "auto_lock_minutes": auto_lock_minutes(&settings),
        "export_allowed": pass_core::policy_allows_export(policy),
    })
}

#[tauri::command]
pub fn teams_notifications_seen(app: AppHandle) -> Value {
    cache().notifications = Notifications::default();
    emit_changed(&app);
    json!({})
}

#[tauri::command]
pub fn teams_notices_dismiss(app: AppHandle) -> Value {
    cache().notices.clear();
    emit_changed(&app);
    json!({})
}

pub fn note_master_password(password: &str) {
    let score = pass_core::password_strength(password.to_string()).score;
    cache().password_score = Some(score);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_policies_are_read_in_the_core_names() {
        let p = parse_policy(&json!({
            "min_password_score": 3, "sign_in": "passkey", "max_auto_lock_minutes": 10,
            "export_allowed": false, "share_outside": false, "send_allowed": true
        }))
        .unwrap();
        assert_eq!(p.min_master_password_score, 3);
        assert!(p.require_two_step);
        assert_eq!(p.max_auto_lock_secs, Some(600));
        assert!(!p.export_allowed && !p.sharing_outside_allowed);
        // 0 clears the maximum; `any` sign-in requires nothing.
        let p = parse_policy(&json!({ "max_auto_lock_minutes": 0, "sign_in": "any" })).unwrap();
        assert_eq!(p.max_auto_lock_secs, None);
        assert!(!p.require_two_step);
        let p = parse_policy(&json!({ "master_password_min_strength": "good" })).unwrap();
        assert_eq!(p.min_master_password_score, 3);
    }

    #[test]
    fn the_strictest_policy_wins_and_none_without_orgs() {
        assert_eq!(strictest(&[]), None);
        let p = strictest(&[
            json!({ "min_password_score": 2, "max_auto_lock_minutes": 30 }),
            json!({ "min_password_score": 4, "max_auto_lock_minutes": 60, "export_allowed": false }),
        ])
        .unwrap();
        assert_eq!(p.min_master_password_score, 4);
        assert_eq!(p.max_auto_lock_secs, Some(1800));
        assert!(!p.export_allowed);
        let file = policy_file(&p);
        assert_eq!(pass_core::policy_parse(&file).unwrap(), p);
    }

    #[test]
    fn the_auto_lock_is_clamped_to_the_policy() {
        let p = parse_policy(&json!({ "max_auto_lock_minutes": 15 })).unwrap();
        assert_eq!(auto_lock_cap(Some(&p)), Some(15));
        assert_eq!(clamp_auto_lock(60, Some(&p)), 15);
        assert_eq!(clamp_auto_lock(5, Some(&p)), 5);
        assert_eq!(clamp_auto_lock(60, None), 60);
        let mut settings = crate::settings::Settings {
            auto_lock_minutes: 240,
            ..Default::default()
        };
        assert_eq!(auto_lock_minutes(&settings), 240);
        settings.teams = Some(TeamsSettings {
            policy: Some(policy_file(&p)),
            ..Default::default()
        });
        assert_eq!(auto_lock_minutes(&settings), 15);
    }

    #[test]
    fn a_weak_master_password_is_refused_by_a_strict_policy() {
        let p = parse_policy(&json!({ "min_password_score": 4 })).unwrap();
        assert!(password_refusal(Some(&p), "password1").is_some());
        assert!(password_refusal(Some(&p), "correct-Horse-battery-staple-91-quokka").is_none());
        assert!(password_refusal(None, "a").is_none());
        let lenient = parse_policy(&json!({})).unwrap();
        assert!(password_refusal(Some(&lenient), "a").is_none());
    }

    #[test]
    fn visibility_needs_an_org_or_a_shared_vault() {
        assert!(!visible(false, 0, 0));
        assert!(!visible(true, 0, 0));
        assert!(visible(true, 1, 0));
        assert!(visible(false, 0, 1));
        // Organisations from an old sign-in don't count once signed out.
        assert!(!visible(false, 2, 0));
    }

    #[test]
    fn vault_changes_and_tray_texts() {
        let seen = vec!["o/a".to_string(), "o/b".to_string()];
        let now = vec!["o/b".to_string(), "o/c".to_string()];
        assert_eq!(
            vault_changes(&seen, &now),
            (vec!["o/c".to_string()], vec!["o/a".to_string()])
        );
        assert!(tray_texts(true, &["c".into()], &[], 3).is_empty());
        let texts = tray_texts(false, &["Engineering".into()], &["a".into(), "b".into()], 1);
        assert_eq!(texts.len(), 3);
        assert!(texts[0].contains("Engineering"));
        assert!(tray_texts(false, &[], &[], 0).is_empty());
    }

    #[test]
    fn members_notices_are_worded() {
        let keys = pass_core::PublicKeys {
            account: "bob".into(),
            enc_pub: String::new(),
            sig_pub: String::new(),
            created_at: 0,
            sig: String::new(),
        };
        let notice = MembersNotice {
            reapplied: vec![MemberChange::Add {
                keys,
                role: MemberRole::View,
                group: None,
            }],
            dropped: vec![MemberChange::Remove {
                account: "carol".into(),
            }],
            rotated_after_leave: true,
        };
        let j = notice_json("v1", "Engineering", &notice);
        assert_eq!(j["reapplied"][0], change_words(&notice.reapplied[0]));
        assert!(j["reapplied"][0].as_str().unwrap().contains("bob"));
        assert!(j["dropped"][0].as_str().unwrap().contains("carol"));
        assert_eq!(j["rotated_after_leave"], true);
        assert!(j["summary"].as_str().unwrap().contains("Engineering"));
    }

    #[test]
    fn server_notifications_take_the_contract_shape() {
        let n: ServerNotifications = serde_json::from_value(json!({
            "now": 5,
            "shared_with_you": [ { "vault": "alice/family", "path": "/dav/alice/family.vault",
                "owner": "alice", "role": "view", "added_at": 3, "added_by": "alice" } ],
            "removed": [ { "vault": "o/x", "role": "edit", "at": 4, "by": "admin" } ],
            "waiting_for_confirmation": [ { "vault": "o/y", "since": 2, "reason": "added" } ],
            "confirm": [ { "vault": "alice/family", "user": "bob", "fingerprint": "F",
                "keys_published": true, "reason": "added", "since": 1, "added_by": "alice" } ]
        }))
        .unwrap();
        let c = from_server(&n);
        assert_eq!(c.shared_with_you[0]["name"], "family");
        assert_eq!(c.shared_with_you[0]["by"], "alice");
        assert_eq!(c.removed[0]["key"], "o/x");
        assert_eq!(c.confirm[0]["account"], "bob");
        assert_eq!(c.confirm[0]["fingerprint"], "F");
    }
}
