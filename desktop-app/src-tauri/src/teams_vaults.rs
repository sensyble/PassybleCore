//! Teams and Family: the shared vaults beside the home vault (docs/PROTOCOL.md §2, "Linked
//! vaults"), and the member commands of the Teams and Family screen.
//!
//! **Linking** ([`refresh`]): after an unlock, a sign-in and on "Refresh", for every backend
//! (`teams.rs` [`Backend`]) the app reads `whoami` `vaults[]`, makes sure the home vault holds this
//! account's keyset and that its public keys are published, hands the agent the list of shared vaults
//! ([`pass_agent::LinkedVaultConfig`], local copy in `%LOCALAPPDATA%\Pass\shared\<hash>.vault`) and
//! lets the agent sync them (ETag, download-only for view and fill members).
//!
//! **Roles** are the agent's (`VaultRef::can_edit`, `can_reveal`); the item commands refuse edits in
//! vaults the user can't change and never hand out a fill-only member's password. A Team's password
//! mode (`password_mode.rs`) can make its vaults read-only here and turns sharing into them off.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use pass_agent::{Agent, LinkedVaultConfig, VaultRef};
use pass_core::{MemberChange, MemberRole, PassError, SharedKind, Vault};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Emitter};

use crate::commands::{app_state, blocking, pass_err};
use crate::contact_pins::{self, ToCompare};
use crate::i18n::tr;
use crate::teams::{self, cache, Backend};
use crate::teams_api::{ApiError, WhoamiVault};

type Res<T> = Result<T, String>;

static REFRESHING: Mutex<()> = Mutex::new(());

/// The fingerprints whose keys this session published, per backend (`<kind>:<base>`), so a
/// refresh doesn't upload the same keys again.
static PUBLISHED: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());

/// The emergency access vaults opened in this session (view or full access, one per granted vault
/// of an owner), kept in memory only.
static EMERGENCY: Mutex<Vec<(String, Arc<Vault>)>> = Mutex::new(Vec::new());

fn guard<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

fn api_err(e: ApiError) -> String {
    e.message()
}

/// `%LOCALAPPDATA%\Pass\shared\<first 32 hex of SHA-256(backend | key)>.vault`: the local copy
/// of a shared vault, apart for each backend (the same `<owner>/<vault>` can exist on two).
pub fn shared_path(backend_base: &str, key: &str) -> PathBuf {
    let digest = Sha256::digest(format!("{}|{key}", backend_base.trim_end_matches('/')).as_bytes());
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    crate::settings::local_dir()
        .join("shared")
        .join(format!("{}.vault", &hex[..32]))
}

pub fn key_of_path(path: &str) -> String {
    path.trim_start_matches('/')
        .trim_start_matches("dav/")
        .trim_end_matches(".vault")
        .to_string()
}

pub fn configs_for(
    backend: &Backend,
    vaults: &[WhoamiVault],
    labels: &dyn Fn(&str) -> Option<String>,
) -> Vec<LinkedVaultConfig> {
    vaults
        .iter()
        .filter(|v| v.shared && !v.path.is_empty())
        .map(|v| {
            let key = if v.vault.is_empty() {
                key_of_path(&v.path)
            } else {
                v.vault.clone()
            };
            let name = labels(&key)
                .filter(|l| !l.trim().is_empty())
                .unwrap_or_else(|| teams::vault_name(&key));
            let (user, token) = backend.credentials();
            LinkedVaultConfig {
                path: shared_path(backend.base(), &key),
                name,
                account: backend.account_id().to_string(),
                webdav: Some(pass_core::WebDavConfig {
                    url: format!("{}{}", backend.base(), v.path),
                    username: user.to_string(),
                    password: token.to_string(),
                    pins: backend.pins().to_vec(),
                }),
                // A manager or editor uploads; the server refuses viewers' and fill members' copies.
                writable: v.writable,
                org: None,
                key,
            }
        })
        .collect()
}

fn label_of(key: &str) -> Option<String> {
    let c = cache();
    c.labels
        .iter()
        .find(|(k, _, _)| k == key)
        .map(|(_, label, _)| label.clone())
}

fn org_of(key: &str) -> Option<String> {
    cache()
        .labels
        .iter()
        .find(|(k, _, _)| k == key)
        .and_then(|(_, _, org)| org.clone())
}

fn backends(app: &AppHandle) -> Vec<Backend> {
    let mut out = Vec::new();
    if let Some(b) = teams::server_backend(app) {
        out.push(b);
    }
    if let Some(b) = teams::cloud_backend(app) {
        out.push(b);
    }
    out
}

/// The Passyble Cloud device of the signed-in account, made once when the account is in an
/// organisation (its token goes to Credential Manager, never to settings.json).
fn ensure_cloud_device(app: &AppHandle) -> Option<Backend> {
    cloud_device(app).ok()
}

pub(crate) fn cloud_device(app: &AppHandle) -> Res<Backend> {
    if let Some(b) = teams::cloud_backend(app) {
        return Ok(b);
    }
    let account = crate::account::signed_in(app).ok_or_else(|| tr!("errors.teams_sign_in_first"))?;
    // A device that waits for one of the account's other devices to approve it (§16.5) gets no
    // token yet: the Teams screen shows the waiting card.
    let answer = crate::account::with_api(app, |api, _| {
        match api.cloud_device_or_approval(&crate::account::device_name()) {
            Ok(device) => Ok(Ok(device)),
            Err(Ok(approval)) => Ok(Err(approval)),
            Err(Err(e)) => Err(e),
        }
    })?;
    let device = match answer {
        Ok(device) => {
            cache().device_waiting = None;
            device
        }
        Err(approval) => {
            cache().device_waiting = Some(approval);
            return Err(tr!("errors.account_vault_approval"));
        }
    };
    if device.token.is_empty() || device.server_url.is_empty() {
        return Err(tr!("errors.account_vault_no_cloud"));
    }
    cache().held = device
        .shared
        .iter()
        .filter(|s| s.held)
        .map(|s| json!({ "name": s.label, "reason": s.hold_reason }))
        .collect();
    crate::account::store()
        .set(
            &crate::account::cloud_token_name(&account.id),
            &device.token,
        )
        .map_err(|e| crate::errors::internal("cloud device token", e))?;
    let labels: Vec<(String, String, Option<String>)> = device
        .shared
        .iter()
        .filter_map(|s| {
            let key = key_of_path(s.vault_path.as_deref()?);
            Some((key, s.label.clone(), s.org.clone()))
        })
        .collect();
    cache().labels.extend(labels);
    let state = app_state(app);
    let _ = state.update_settings(|s| {
        if let Some(a) = s.passyble_account.as_mut() {
            a.cloud = Some(crate::account::CloudDeviceSettings {
                server_url: device.server_url.clone(),
                user: device.user.clone(),
                device_id: device.device_id.clone(),
            });
        }
        Ok(())
    });
    teams::cloud_backend(app).ok_or_else(|| tr!("errors.account_vault_no_cloud"))
}

fn publish_keys(app: &AppHandle, agent: &Agent, backend: &Backend) -> Res<String> {
    let home = agent
        .peek_vault()
        .ok_or_else(|| tr!("errors.teams_unlock_first"))?;
    let keys = home
        .publish_keys_for(backend.account_id())
        .map_err(pass_err)?;
    if home.is_dirty() {
        agent.save().map_err(pass_err)?;
    }
    let fingerprint = pass_core::public_keys_fingerprint(keys.clone());
    let tag = format!("{}:{}:{fingerprint}", backend.kind(), backend.base());
    if guard(&PUBLISHED).contains(&tag) {
        return Ok(fingerprint);
    }
    match backend {
        Backend::Server { .. } => {
            backend.api().put_keys(&keys).map_err(api_err)?;
        }
        Backend::Cloud { .. } => {
            crate::account::with_api(app, |api, _| api.put_keys(&keys))?;
        }
    }
    guard(&PUBLISHED).insert(tag);
    Ok(fingerprint)
}

/// Reads the services, links the shared vaults to the agent and syncs them. Works locked too.
pub fn refresh(app: &AppHandle) -> Res<Value> {
    let _one = guard(&REFRESHING);
    let state = app_state(app);
    let agent = state.agent();
    let signed_in = crate::account::signed_in(app).is_some();
    let mut hints: Vec<Value> = Vec::new();
    let mut last_error: Option<String> = None;
    let orgs = if signed_in {
        match crate::account::with_api(app, |api, _| api.orgs()) {
            Ok(orgs) => Some(orgs.organisations),
            Err(e) => {
                last_error = Some(e);
                None
            }
        }
    } else {
        None
    };
    if orgs.as_ref().is_some_and(|o| !o.is_empty()) {
        ensure_cloud_device(app);
        if let Ok(invites) = crate::account::with_api(app, |api, _| api.my_invites()) {
            let list = invites
                .get("invites")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            cache().invites = list;
        }
    }
    let mut configs: Vec<LinkedVaultConfig> = Vec::new();
    let mut seen_keys: Vec<String> = Vec::new();
    let mut notifications = teams::Notifications::default();
    let mut whoamis = Vec::new();
    let mut confirm_ids: Vec<String> = Vec::new();
    let mut since: Option<i64> = None;
    for backend in backends(app) {
        let api = backend.api();
        let whoami = match api.whoami() {
            Ok(w) => w,
            Err(e) => {
                last_error = Some(e.message());
                continue;
            }
        };
        hints.extend(whoami.policies.iter().map(|p| p.policy.clone()));
        let shared: Vec<WhoamiVault> = whoami.vaults.iter().filter(|v| v.shared).cloned().collect();
        if let (Some(agent), false) = (agent.as_ref(), shared.is_empty() && orgs.is_none()) {
            if !agent.is_locked() {
                if let Err(e) = publish_keys(app, agent, &backend) {
                    last_error = Some(e);
                }
            }
        }
        let own_labels = state.settings().teams.map(|t| t.labels).unwrap_or_default();
        let labels = |key: &str| own_labels.get(key).cloned().or_else(|| label_of(key));
        let mut list = configs_for(&backend, &whoami.vaults, &labels);
        for c in &mut list {
            c.org = org_of(&c.key);
            seen_keys.push(c.key.clone());
        }
        configs.extend(list);
        if let Backend::Server { .. } = backend {
            let previous = state
                .settings()
                .teams
                .map(|t| t.notifications_since)
                .unwrap_or(0);
            if let Ok(n) = api.notifications(previous) {
                since = Some(n.now);
                confirm_ids.extend(n.confirm.iter().map(|c| {
                    format!(
                        "{}|{}|{}",
                        c.get("vault").and_then(Value::as_str).unwrap_or_default(),
                        c.get("user").and_then(Value::as_str).unwrap_or_default(),
                        c.get("fingerprint")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                    )
                }));
                notifications.absorb(teams::from_server(&n));
            }
        }
        whoamis.push((backend, whoami));
    }
    teams::remember(app, orgs.as_deref(), &hints);
    let rule = crate::password_mode::rule(app);
    if let Some(agent) = agent.as_ref() {
        // Twice: the vaults opened by the list tell which Team they belong to.
        rule.limit_writes(agent, &mut configs);
        agent.set_linked_vaults(configs.clone());
        if rule.limit_writes(agent, &mut configs) {
            agent.set_linked_vaults(configs.clone());
        }
        if !agent.is_locked() {
            for (key, result) in agent.sync_linked() {
                if let Err(e) = result {
                    crate::applog::plog!("teams: sync of {key} failed: {e}");
                }
            }
            if rule.limit_writes(agent, &mut configs) {
                agent.set_linked_vaults(configs.clone());
            }
            let notices: Vec<Value> = agent
                .take_linked_notices()
                .iter()
                .map(|n| teams::notice_json(&n.vault_id, &n.name, &n.notice))
                .collect();
            cache().notices.extend(notices);
        }
    }
    let names: Vec<(String, String)> = configs
        .iter()
        .map(|c| (c.key.clone(), c.name.clone()))
        .collect();
    let name_of = |key: &str| {
        names
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, n)| n.clone())
            .unwrap_or_else(|| teams::vault_name(key))
    };
    let texts = teams::note_seen(app, &seen_keys, &name_of, &confirm_ids, since);
    for text in &texts {
        crate::tray::notify(app, text);
    }
    {
        let mut c = cache();
        c.whoami = whoamis;
        if !notifications.is_empty() {
            c.notifications.absorb(notifications);
        }
        c.last_error = last_error;
        c.refreshed_ms = Some(now_ms());
    }
    crate::password_mode::report(app);
    teams::emit_changed(app);
    crate::tray::teams_visible(app, overview_visible(app));
    Ok(overview(app))
}

pub fn refresh_soon(app: &AppHandle) {
    if crate::account::signed_in(app).is_none() && teams::server_backend(app).is_none() {
        return;
    }
    let app = app.clone();
    let _ = std::thread::Builder::new()
        .name("pass-teams-refresh".into())
        .spawn(move || {
            if let Err(e) = refresh(&app) {
                crate::applog::plog!("teams: refresh failed: {e}");
            }
        });
}

pub fn sync_pending(app: &AppHandle) {
    let Some(agent) = app_state(app).agent() else {
        return;
    };
    if agent.is_locked() || !agent.linked_sync_pending() {
        return;
    }
    let _ = agent.sync_linked();
    let notices: Vec<Value> = agent
        .take_linked_notices()
        .iter()
        .map(|n| teams::notice_json(&n.vault_id, &n.name, &n.notice))
        .collect();
    if !notices.is_empty() {
        cache().notices.extend(notices);
    }
    teams::emit_changed(app);
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn overview_visible(app: &AppHandle) -> bool {
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
    teams::visible(signed_in, orgs, shared)
}

fn role_str(role: Option<MemberRole>) -> Value {
    role.map(|r| json!(r.as_str())).unwrap_or(Value::Null)
}

pub fn overview(app: &AppHandle) -> Value {
    let state = app_state(app);
    let agent = state.agent();
    let account = crate::account::signed_in(app);
    let backend = backends(app).into_iter().next();
    let vaults: Vec<Value> = agent
        .as_ref()
        .map(|a| {
            a.linked_status()
                .into_iter()
                .map(|s| {
                    let info = s
                        .vault
                        .as_ref()
                        .and_then(|r| a.shared_vault(&r.id))
                        .and_then(|v| v.shared_info());
                    let mut v = serde_json::to_value(&s).unwrap_or(Value::Null);
                    v["members_count"] = json!(info.as_ref().map(|i| i.members.len()));
                    v["my_role"] = role_str(s.vault.as_ref().and_then(|r| r.role));
                    v["kind"] = json!(s.vault.as_ref().map(|r| r.kind));
                    v["anchored"] = json!(info.as_ref().map(|i| i.anchored));
                    v["signer"] = json!(info.as_ref().map(|i| i.signed_by.clone()));
                    v["signer_fingerprint"] =
                        json!(info.as_ref().and_then(|i| i.signer_fingerprint.clone()));
                    let signer = s
                        .vault
                        .as_ref()
                        .and_then(|r| Some((a.peek_vault()?, a.shared_vault(&r.id)?)))
                        .and_then(|(home, shared)| home.shared_signer_status(&shared));
                    put_signer_status(&mut v, signer.as_ref());
                    v
                })
                .collect()
        })
        .unwrap_or_default();
    let keys = agent
        .as_ref()
        .and_then(|a| a.peek_vault())
        .zip(backend.as_ref())
        .and_then(|(home, b)| home.user_keyset(b.account_id()).ok().flatten().zip(Some(b)))
        .map(|(keyset, b)| {
            let fingerprint = keyset.fingerprint();
            let published = guard(&PUBLISHED).iter().any(|t| {
                t.starts_with(&format!("{}:{}:", b.kind(), b.base())) && t.ends_with(&fingerprint)
            });
            json!({ "fingerprint": fingerprint, "published": published })
        });
    let policy = teams::effective_policy(app);
    let direct_org = state
        .settings()
        .teams
        .and_then(|t| t.orgs.first().map(|o| o.id.clone()));
    let password_policy = crate::password_mode::overview_json(
        app,
        &crate::password_mode::rule(app),
        direct_org.as_deref(),
    );
    let c = cache();
    json!({
        "visible": overview_visible(app),
        "backend": backend.as_ref().map(|b| b.kind()),
        "account_id": backend.as_ref().map(|b| b.account_id().to_string()),
        "account": account.as_ref().map(|a| json!({ "id": a.id, "email": a.email })),
        "keys": keys,
        "vaults": vaults,
        "invites": c.invites,
        "notifications": c.notifications,
        "notices": c.notices,
        "orgs": teams::cached_orgs(app),
        "policy": {
            "effective": policy.as_ref().map(teams::policy_json),
            "violations": policy.as_ref().map(|p| teams::violations(app, p)).unwrap_or_default(),
        },
        "password_policy": password_policy,
        "last_error": c.last_error,
        "refreshed_at": c.refreshed_ms,
        "device_waiting": c.device_waiting,
        "held": c.held,
        "locked": agent.as_ref().map(|a| a.is_locked()).unwrap_or(true),
    })
}

/// `signer_status` (`pinned`, `not_verified`, `changed`; none for a signer no longer in the
/// list) and `signer_pinned_fingerprint` (changed) of a shared vault row: whether the manager who
/// signed its members list is someone this user verified. A changed one is a loud warning.
fn put_signer_status(v: &mut Value, status: Option<&pass_core::PinStatus>) {
    let (words, pinned) = match status {
        Some(s) => {
            let (w, p) = contact_pins::status_words(s);
            (Some(w), p)
        }
        None => (None, None),
    };
    v["signer_status"] = json!(words);
    v["signer_pinned_fingerprint"] = json!(pinned);
}

/// A person's keys from the backend a shared vault lives on (Passyble Cloud's key directory of
/// the vault's organisation, or the self-hosted server's), verified. Not trusted on their own:
/// callers check them against a fingerprint the user compared.
fn backend_keys(
    app: &AppHandle,
    config: &LinkedVaultConfig,
    org: Option<&str>,
    account: &str,
) -> Res<pass_core::PublicKeys> {
    let keys = match backend_of(app, config) {
        Some(b @ Backend::Server { .. }) => b.api().user_keys(account).map_err(api_err)?.keys,
        _ => {
            let org = config
                .org
                .as_deref()
                .or(org)
                .ok_or_else(|| tr!("errors.teams_bad_keys"))?;
            crate::account::with_api(app, |api, _| api.keys_of(org, account))?.keys
        }
    };
    keys.verify().map_err(|_| tr!("errors.teams_bad_keys"))?;
    if keys.account != account {
        return Err(tr!("errors.teams_bad_keys"));
    }
    Ok(keys)
}

fn agent_of(app: &AppHandle) -> Res<Arc<Agent>> {
    let agent = app_state(app).require_agent()?;
    if agent.is_locked() {
        return Err(tr!("errors.teams_unlock_first"));
    }
    Ok(agent)
}

fn open_shared(agent: &Agent, vault_id: &str) -> Res<(Arc<Vault>, LinkedVaultConfig, VaultRef)> {
    let vault = agent
        .shared_vault(vault_id)
        .ok_or_else(|| tr!("errors.teams_vault_not_open"))?;
    let (vault_ref, _) = agent
        .open_vaults()
        .into_iter()
        .find(|(r, _)| r.id == vault_id)
        .ok_or_else(|| tr!("errors.teams_vault_not_open"))?;
    let status = agent
        .linked_status()
        .into_iter()
        .find(|s| s.vault.as_ref().is_some_and(|r| r.id == vault_id))
        .ok_or_else(|| tr!("errors.teams_vault_not_open"))?;
    let config = agent
        .linked_configs()
        .into_iter()
        .find(|c| c.key == status.key)
        .ok_or_else(|| tr!("errors.teams_vault_not_open"))?;
    Ok((vault, config, vault_ref))
}

fn backend_of(app: &AppHandle, config: &LinkedVaultConfig) -> Option<Backend> {
    let url = config.webdav.as_ref()?.url.clone();
    backends(app)
        .into_iter()
        .find(|b| url.starts_with(b.base()))
}

/// Saves a changed shared vault and uploads it right away (members changes must reach the
/// others); an upload that fails is retried by the scheduler.
pub fn save_and_upload(agent: &Agent, vault_id: &str, key: &str) -> Res<()> {
    agent.save_shared(vault_id).map_err(pass_err)?;
    if let Err(e) = agent.sync_shared(key) {
        return Err(pass_err(e));
    }
    Ok(())
}

#[tauri::command]
pub async fn teams_overview(app: AppHandle) -> Res<Value> {
    blocking(move || Ok(overview(&app))).await
}

#[tauri::command]
pub async fn teams_refresh(app: AppHandle) -> Res<Value> {
    blocking(move || refresh(&app)).await
}

#[tauri::command]
pub async fn teams_publish_keys(app: AppHandle) -> Res<Value> {
    blocking(move || {
        let agent = agent_of(&app)?;
        guard(&PUBLISHED).clear();
        let mut fingerprint = None;
        for backend in backends(&app) {
            fingerprint = Some(publish_keys(&app, &agent, &backend)?);
        }
        let fingerprint = fingerprint.ok_or_else(|| tr!("errors.teams_sign_in_first"))?;
        teams::emit_changed(&app);
        Ok(json!({ "fingerprint": fingerprint, "published": true }))
    })
    .await
}

#[tauri::command]
pub async fn teams_invite_answer(
    app: AppHandle,
    org: String,
    invite_id: String,
    accept: bool,
) -> Res<Value> {
    blocking(move || {
        let _ = org;
        crate::account::with_api(&app, |api, _| api.answer_invite(&invite_id, accept))?;
        cache().invites.retain(|i| {
            i.get("invite_id").and_then(Value::as_str) != Some(invite_id.as_str())
                && i.get("id").and_then(Value::as_str) != Some(invite_id.as_str())
        });
        refresh_soon(&app);
        Ok(json!({}))
    })
    .await
}

#[tauri::command]
pub async fn shared_vault_info(app: AppHandle, vault_id: String) -> Res<Value> {
    blocking(move || {
        let agent = agent_of(&app)?;
        let (vault, config, vault_ref) = open_shared(&agent, &vault_id)?;
        let info = vault
            .shared_info()
            .ok_or_else(|| tr!("errors.teams_vault_not_open"))?;
        let can_manage = info.role == MemberRole::Manage;
        let pending = if can_manage {
            backend_of(&app, &config)
                .and_then(|b| match &b {
                    Backend::Server { .. } => b.api().confirmations(&config.key).ok(),
                    Backend::Cloud { .. } => None,
                })
                .and_then(|v| v.get("pending").cloned())
                .unwrap_or_else(|| json!([]))
        } else {
            json!([])
        };
        let mut answer = json!({
            "vault": vault_ref,
            "info": serde_json::to_value(&info).unwrap_or(Value::Null),
            "pending": pending,
            "can_manage": can_manage,
            "key": config.key,
        });
        let signer = agent
            .peek_vault()
            .and_then(|home| home.shared_signer_status(&vault));
        put_signer_status(&mut answer, signer.as_ref());
        Ok(answer)
    })
    .await
}

#[tauri::command]
pub async fn shared_vault_rename(app: AppHandle, vault_id: String, label: String) -> Res<Value> {
    blocking(move || {
        let label = label.trim().to_string();
        if label.chars().count() > 80 || label.chars().any(char::is_control) {
            return Err(tr!("errors.teams_bad_label"));
        }
        let agent = agent_of(&app)?;
        let (vault, config, _) = open_shared(&agent, &vault_id)?;
        if let (Some(org), Some(MemberRole::Manage)) = (config.org.clone(), vault.shared_role()) {
            if crate::password_mode::rule(&app)
                .read_only_refusal(Some(&org))
                .is_none()
            {
                let _ = crate::account::with_api(&app, |api, _| {
                    api.rename_vault(&org, &vault_id, &label)
                });
            }
        }
        let state = app_state(&app);
        state.update_settings(|s| {
            let t = s.teams.get_or_insert_with(Default::default);
            if label.is_empty() {
                t.labels.remove(&config.key);
            } else {
                t.labels.insert(config.key.clone(), label.clone());
            }
            Ok(())
        })?;
        let mut configs = agent.linked_configs();
        for c in &mut configs {
            if c.key == config.key && !label.is_empty() {
                c.name = label.clone();
            }
        }
        agent.set_linked_vaults(configs);
        teams::emit_changed(&app);
        Ok(json!({}))
    })
    .await
}

/// Leaves a shared vault: a manager (while another manager remains) signs a list without
/// themselves and uploads it; anyone else leaves through the server's members API. The local
/// copy goes either way.
#[tauri::command]
pub async fn shared_vault_leave(app: AppHandle, vault_id: String) -> Res<Value> {
    blocking(move || {
        let agent = agent_of(&app)?;
        let (vault, config, _) = open_shared(&agent, &vault_id)?;
        let info = vault
            .shared_info()
            .ok_or_else(|| tr!("errors.teams_vault_not_open"))?;
        let managers = info
            .members
            .iter()
            .filter(|m| m.role == MemberRole::Manage)
            .count();
        if info.role == MemberRole::Manage {
            if managers < 2 {
                return Err(tr!("errors.teams_last_manager"));
            }
            let org = info.org.clone().or_else(|| config.org.clone());
            if let Some(reason) = crate::password_mode::rule(&app).read_only_refusal(org.as_deref())
            {
                return Err(reason);
            }
            vault.leave_shared().map_err(pass_err)?;
            save_and_upload(&agent, &vault_id, &config.key)?;
        }
        match backend_of(&app, &config) {
            Some(b @ Backend::Server { .. }) => {
                b.api()
                    .remove_member(&config.key, b.account_id())
                    .map_err(api_err)?;
            }
            // Passyble Cloud: a vault given directly is left through the service (one through a
            // department or everyone can't be left alone: `bad_state`).
            Some(Backend::Cloud { .. }) => match config.org.as_deref().or(info.org.as_deref()) {
                Some(org) => {
                    crate::account::with_api(&app, |api, _| api.leave_vault(org, &vault_id))?;
                }
                None if info.role != MemberRole::Manage => {
                    return Err(tr!("errors.teams_leave_ask_manager"));
                }
                None => {}
            },
            None if info.role != MemberRole::Manage => {
                return Err(tr!("errors.teams_leave_ask_manager"));
            }
            None => {}
        }
        agent.remove_shared(&config.key, true);
        teams::emit_changed(&app);
        Ok(json!({}))
    })
    .await
}

/// The user compared the manager's fingerprint of a members list this device couldn't check and
/// trusts it: the home vault forgets what it remembered and the vault opens again as on a first open.
#[tauri::command]
pub async fn shared_trust_confirm(app: AppHandle, vault_id: String) -> Res<Value> {
    blocking(move || {
        let agent = agent_of(&app)?;
        let home = agent
            .peek_vault()
            .ok_or_else(|| tr!("errors.teams_unlock_first"))?;
        home.forget_share_trust(&vault_id).map_err(pass_err)?;
        agent.save().map_err(pass_err)?;
        // Opening again happens when the list is set (closed vaults are opened).
        let configs = agent.linked_configs();
        agent.set_linked_vaults(Vec::new());
        agent.set_linked_vaults(configs);
        teams::emit_changed(&app);
        Ok(json!({}))
    })
    .await
}

/// The user compared the fingerprint of the manager who signed a shared vault's members list: their
/// keys are pinned in the home vault, so the vault shows them as verified and a later key change
/// warns. The keys come from the vault's backend and must be the ones that signed the list.
#[tauri::command]
pub async fn shared_signer_pin(app: AppHandle, vault_id: String, fingerprint: String) -> Res<Value> {
    blocking(move || {
        let agent = agent_of(&app)?;
        let (vault, config, _) = open_shared(&agent, &vault_id)?;
        let info = vault
            .shared_info()
            .ok_or_else(|| tr!("errors.teams_vault_not_open"))?;
        let signed_with = info
            .signer_fingerprint
            .clone()
            .ok_or_else(|| tr!("errors.teams_bad_keys"))?;
        let keys = backend_keys(&app, &config, info.org.as_deref(), &info.signed_by)?;
        if !contact_pins::same_fingerprint(
            &pass_core::public_keys_fingerprint(keys.clone()),
            &signed_with,
        ) {
            return Err(tr!("errors.teams_bad_keys"));
        }
        let home = agent
            .peek_vault()
            .ok_or_else(|| tr!("errors.teams_unlock_first"))?;
        home.pin_contact(keys, pass_core::PERSONAL_SCOPE, &fingerprint)
            .map_err(pass_err)?;
        agent.save().map_err(pass_err)?;
        teams::emit_changed(&app);
        Ok(json!({}))
    })
    .await
}

/// Moves or copies an item into another open vault (`mode`: `move` or `copy`); never into a Team's
/// vault this account can't share into (`password_mode.rs`).
#[tauri::command]
pub async fn item_share(
    app: AppHandle,
    item_id: String,
    target_vault_id: String,
    mode: String,
) -> Res<Value> {
    blocking(move || {
        let agent = agent_of(&app)?;
        let remove = match mode.as_str() {
            "move" => true,
            "copy" => false,
            _ => return Err(tr!("errors.teams_bad_mode")),
        };
        if let Some(org) = crate::password_mode::vault_org(&agent, &target_vault_id) {
            if let Some(reason) = crate::password_mode::rule(&app).share_refusal(&org) {
                return Err(reason);
            }
        }
        let source = agent.vault_of_item(&item_id).map(|(r, _)| r);
        let item = agent
            .transfer_item(&item_id, &target_vault_id, remove)
            .map_err(item_err)?;
        let target = agent
            .open_vaults()
            .into_iter()
            .find(|(r, _)| r.id == target_vault_id)
            .map(|(r, _)| r);
        // Upload the shared vaults that changed (in the background: the move is saved already).
        let keys: Vec<String> = agent
            .linked_status()
            .into_iter()
            .filter(|s| {
                s.vault.as_ref().is_some_and(|r| {
                    r.id == target_vault_id || source.as_ref().is_some_and(|src| src.id == r.id)
                })
            })
            .map(|s| s.key)
            .collect();
        let a = agent.clone();
        std::thread::spawn(move || {
            for key in keys {
                let _ = a.sync_shared(&key);
            }
        });
        Ok(json!({ "item_id": item.id, "vault": target }))
    })
    .await
}

fn item_err(e: PassError) -> String {
    let words = match &e {
        PassError::InvalidInput(t) => t.clone(),
        _ => String::new(),
    };
    if pass_core::core_message_is(words.clone(), "share.fill_only".into()) {
        return tr!("errors.teams_fill_only");
    }
    if pass_core::core_message_is(words, "share.read_only".into()) {
        return tr!("errors.teams_read_only");
    }
    pass_err(e)
}

/// Starts a direct share with one person: a new shared vault of kind `direct`, registered with the
/// account service, with the person added in `role` and the chosen items copied in. Compare first,
/// then wrap: unless this user pinned their keys before, nothing is made and the answer is
/// `{ needs_compare }` (`changed` when the keys differ from those compared before). Called again with
/// `fingerprint` the keys are pinned and the share is made.
#[tauri::command]
pub async fn direct_share_start(
    app: AppHandle,
    person: String,
    role: String,
    item_ids: Vec<String>,
    fingerprint: Option<String>,
) -> Res<Value> {
    blocking(move || {
        let agent = agent_of(&app)?;
        let role = parse_role(&role)?;
        let person = person.trim().to_string();
        if person.is_empty() || person.len() > 320 {
            return Err(tr!("errors.teams_bad_person"));
        }
        let orgs = app_state(&app)
            .settings()
            .teams
            .map(|t| t.orgs)
            .unwrap_or_default();
        // No Passyble Cloud organisation, but a self-hosted Passyble Server that lets accounts
        // create vaults: the vault is made there.
        if orgs.is_empty() {
            if let Some(server) = teams::server_backend(&app) {
                let label = tr!("teams_rs.direct_label", person = person);
                let compared: Vec<(String, String)> = fingerprint
                    .iter()
                    .map(|f| (person.clone(), f.clone()))
                    .collect();
                let vault = match create_server_vault(
                    &app,
                    &agent,
                    &server,
                    &label,
                    "direct",
                    &[(person.clone(), role)],
                    &compared,
                )? {
                    Made::Vault(vault) => vault,
                    Made::Compare(list) => return Ok(json!({ "needs_compare": list.first() })),
                };
                for id in &item_ids {
                    agent
                        .transfer_item(id, &vault.vault_id(), false)
                        .map_err(item_err)?;
                }
                let key = key_of_vault(&agent, &vault.vault_id())?;
                save_and_upload(&agent, &vault.vault_id(), &key)?;
                teams::emit_changed(&app);
                return Ok(json!({
                    "vault": vault_ref_of(&agent, &vault.vault_id()),
                    "waiting_for_confirmation": true,
                }));
            }
        }
        let backend =
            ensure_cloud_device(&app).ok_or_else(|| tr!("errors.teams_direct_needs_cloud"))?;
        let org = orgs
            .first()
            .ok_or_else(|| tr!("errors.teams_direct_needs_cloud"))?
            .id
            .clone();
        if !pass_core::policy_allows_share(teams::effective_policy(&app), true) {
            return Err(pass_core::policy_blocked_message(
                pass_core::PolicyBlock::SharingOutside,
            ));
        }
        if let Some(reason) = crate::password_mode::rule(&app).share_refusal(&org) {
            return Err(reason);
        }
        let keys = crate::account::with_api(&app, |api, _| api.keys_of(&org, &person))?;
        keys.keys
            .verify()
            .map_err(|_| tr!("errors.teams_bad_keys"))?;
        let home = agent
            .peek_vault()
            .ok_or_else(|| tr!("errors.teams_unlock_first"))?;
        let mut pinned = false;
        let compare = contact_pins::check(&home, &keys.keys, fingerprint.as_deref(), &mut pinned)?;
        if pinned {
            agent.save().map_err(pass_err)?;
        }
        if let Some(mut c) = compare {
            c.person = Some(person.clone()).filter(|p| *p != c.account);
            return Ok(json!({ "needs_compare": c }));
        }
        let keyset = home
            .ensure_user_keyset(backend.account_id())
            .map_err(pass_err)?;
        let device = app_state(&app).settings().device_id;
        let vault = Vault::create_shared(&keyset, SharedKind::Direct, Some(org.clone()), &device)
            .map_err(pass_err)?;
        vault
            .add_member(keys.keys.clone(), role, None, &home)
            .map_err(pass_err)?;
        let label = tr!("teams_rs.direct_label", person = person);
        let registered = crate::account::with_api(&app, |api, _| {
            api.register_vault(
                &org,
                &vault.vault_id(),
                &label,
                "direct",
                &[json!({ "account": keys.keys.account, "role": role.as_str() })],
            )
        })?;
        let path = registered
            .get("vault_path")
            .and_then(Value::as_str)
            .ok_or_else(|| tr!("errors.teams_unexpected_answer"))?
            .to_string();
        let key = key_of_path(&path);
        let (user, token) = backend.credentials();
        let config = LinkedVaultConfig {
            path: shared_path(backend.base(), &key),
            name: label,
            account: backend.account_id().to_string(),
            webdav: Some(pass_core::WebDavConfig {
                url: format!("{}{path}", backend.base()),
                username: user.to_string(),
                password: token.to_string(),
                pins: Vec::new(),
            }),
            writable: true,
            org: Some(org),
            key: key.clone(),
        };
        agent.add_shared(config, vault.clone()).map_err(pass_err)?;
        for id in &item_ids {
            agent
                .transfer_item(id, &vault.vault_id(), false)
                .map_err(item_err)?;
        }
        save_and_upload(&agent, &vault.vault_id(), &key)?;
        let vault_ref = agent
            .open_vaults()
            .into_iter()
            .find(|(r, _)| r.id == vault.vault_id())
            .map(|(r, _)| r);
        teams::emit_changed(&app);
        Ok(json!({ "vault": vault_ref, "waiting_for_confirmation": true }))
    })
    .await
}

fn key_of_vault(agent: &Agent, vault_id: &str) -> Res<String> {
    agent
        .linked_status()
        .into_iter()
        .find(|s| s.vault.as_ref().is_some_and(|r| r.id == vault_id))
        .map(|s| s.key)
        .ok_or_else(|| tr!("errors.teams_vault_not_open"))
}

/// A vault name for a self-hosted server from a label: lowercase letters, digits and `-`, at most
/// 64 characters, with a short random part so two vaults of the same label don't clash.
pub fn server_vault_name(label: &str) -> String {
    let mut slug: String = label
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    while slug.contains("--") {
        slug = slug.replace("--", "-");
    }
    let slug: String = slug.trim_matches('-').chars().take(52).collect();
    let slug = slug.trim_end_matches('-').to_string();
    let tail = uuid::Uuid::new_v4().simple().to_string();
    let base = if slug.is_empty() {
        "shared".to_string()
    } else {
        slug
    };
    format!("{base}-{}", &tail[..8])
}

enum Made {
    Vault(Arc<Vault>),
    Compare(Vec<ToCompare>),
}

/// Makes a shared vault on a self-hosted Passyble Server (`POST /api/v1/vaults`): the server's entry
/// with `members`, the vault file with them in its members list, its local copy and the agent's list
/// entry. Compare first, then wrap: `compared` holds the fingerprints the user just compared (per user
/// name), pinned in the home vault first; while any member's keys aren't pinned nothing is made and
/// they come back as [`Made::Compare`].
fn create_server_vault(
    app: &AppHandle,
    agent: &Agent,
    server: &Backend,
    label: &str,
    kind: &str,
    members: &[(String, MemberRole)],
    compared: &[(String, String)],
) -> Res<Made> {
    let api = server.api();
    let features = api.features().map_err(api_err)?;
    if features.get("create_vault").and_then(Value::as_bool) != Some(true) {
        return Err(tr!("errors.teams_server_no_create"));
    }
    let home = agent
        .peek_vault()
        .ok_or_else(|| tr!("errors.teams_unlock_first"))?;
    let keyset = home
        .ensure_user_keyset(server.account_id())
        .map_err(pass_err)?;
    let mut changes = Vec::new();
    let mut to_compare = Vec::new();
    let mut pinned = false;
    for (user, role) in members {
        let stored = api.user_keys(user).map_err(api_err)?;
        stored
            .keys
            .verify()
            .map_err(|_| tr!("errors.teams_bad_keys"))?;
        let typed = compared
            .iter()
            .find(|(u, _)| u == user)
            .map(|(_, f)| f.as_str());
        if let Some(mut c) = contact_pins::check(&home, &stored.keys, typed, &mut pinned)? {
            c.person = Some(user.clone());
            to_compare.push(c);
        }
        changes.push(MemberChange::Add {
            keys: stored.keys,
            role: *role,
            group: None,
        });
    }
    if pinned {
        agent.save().map_err(pass_err)?;
    }
    if !to_compare.is_empty() {
        return Ok(Made::Compare(to_compare));
    }
    let name = server_vault_name(label);
    let listed: Vec<Value> = members
        .iter()
        .map(|(user, role)| json!({ "user": user, "role": role.as_str() }))
        .collect();
    api.create_vault(&name, kind, &listed).map_err(api_err)?;
    let device = app_state(app).settings().device_id;
    let shared_kind = if kind == "direct" {
        SharedKind::Direct
    } else {
        SharedKind::Org
    };
    let vault = Vault::create_shared(&keyset, shared_kind, None, &device).map_err(pass_err)?;
    if !changes.is_empty() {
        vault
            .change_members_pinned(changes, &home)
            .map_err(pass_err)?;
    }
    let key = format!("{}/{name}", server.account_id());
    let (user, token) = server.credentials();
    let config = LinkedVaultConfig {
        path: shared_path(server.base(), &key),
        name: label.to_string(),
        account: server.account_id().to_string(),
        webdav: Some(pass_core::WebDavConfig {
            url: format!("{}/dav/{key}.vault", server.base().trim_end_matches('/')),
            username: user.to_string(),
            password: token.to_string(),
            pins: server.pins().to_vec(),
        }),
        writable: true,
        org: None,
        key: key.clone(),
    };
    agent.add_shared(config, vault.clone()).map_err(pass_err)?;
    app_state(app).update_settings(|s| {
        s.teams
            .get_or_insert_with(Default::default)
            .labels
            .insert(key.clone(), label.to_string());
        Ok(())
    })?;
    Ok(Made::Vault(vault))
}

fn vault_ref_of(agent: &Agent, vault_id: &str) -> Option<VaultRef> {
    agent
        .open_vaults()
        .into_iter()
        .find(|(r, _)| r.id == vault_id)
        .map(|(r, _)| r)
}

#[tauri::command]
pub async fn server_vault_features(app: AppHandle) -> Res<Value> {
    blocking(move || {
        let Some(server) = teams::server_backend(&app) else {
            return Ok(json!({ "available": false }));
        };
        let features = server.api().features().map_err(api_err)?;
        Ok(json!({
            "available": features.get("create_vault").and_then(Value::as_bool) == Some(true),
            "max_owned_vaults": features.get("max_owned_vaults"),
        }))
    })
    .await
}

/// A new shared vault on the active vault's self-hosted Passyble Server, with `members`
/// (`[{ user, role, fingerprint? }]`), uploaded. Answers `{ needs_compare }` (nothing made) while a
/// member's keys aren't pinned; call again with each compared `fingerprint`.
#[tauri::command]
pub async fn server_vault_create(app: AppHandle, label: String, members: Vec<Value>) -> Res<Value> {
    blocking(move || {
        let agent = agent_of(&app)?;
        let label = label.trim().to_string();
        if label.is_empty() || label.chars().count() > 80 || label.chars().any(char::is_control) {
            return Err(tr!("errors.teams_bad_label"));
        }
        let server =
            teams::server_backend(&app).ok_or_else(|| tr!("errors.teams_server_no_create"))?;
        let mut list = Vec::new();
        let mut compared = Vec::new();
        for m in &members {
            let user = m
                .get("user")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .trim()
                .to_string();
            if user.is_empty() {
                continue;
            }
            let role = parse_role(m.get("role").and_then(Value::as_str).unwrap_or("edit"))?;
            if let Some(f) = m.get("fingerprint").and_then(Value::as_str) {
                compared.push((user.clone(), f.to_string()));
            }
            list.push((user, role));
        }
        let vault = match create_server_vault(
            &app,
            &agent,
            &server,
            &label,
            "department",
            &list,
            &compared,
        )? {
            Made::Vault(vault) => vault,
            Made::Compare(list) => return Ok(json!({ "needs_compare": list })),
        };
        let key = key_of_vault(&agent, &vault.vault_id())?;
        save_and_upload(&agent, &vault.vault_id(), &key)?;
        teams::emit_changed(&app);
        Ok(json!({ "vault": vault_ref_of(&agent, &vault.vault_id()) }))
    })
    .await
}

/// Deletes a shared vault this account owns on its self-hosted Passyble Server, for everyone
/// (the server moves the file aside, where its admin can still recover it).
#[tauri::command]
pub async fn server_vault_delete(app: AppHandle, vault_id: String) -> Res<Value> {
    blocking(move || {
        let agent = agent_of(&app)?;
        let (_, config, _) = open_shared(&agent, &vault_id)?;
        let server = backend_of(&app, &config)
            .filter(|b| matches!(b, Backend::Server { .. }))
            .ok_or_else(|| tr!("errors.teams_not_allowed"))?;
        if config.key.split('/').next() != Some(server.account_id()) {
            return Err(tr!("errors.teams_not_allowed"));
        }
        server.api().delete_vault(&config.key).map_err(api_err)?;
        agent.remove_shared(&config.key, true);
        teams::emit_changed(&app);
        Ok(json!({}))
    })
    .await
}

#[tauri::command]
pub async fn device_approvals(app: AppHandle) -> Res<Value> {
    blocking(move || {
        let mut answer = crate::account::with_api(&app, |api, _| api.device_approvals())?;
        if let Some(map) = answer.as_object_mut() {
            map.insert(
                "waiting".into(),
                cache().device_waiting.clone().unwrap_or(Value::Null),
            );
        }
        Ok(answer)
    })
    .await
}

#[tauri::command]
pub async fn device_approval_answer(app: AppHandle, id: String, approve: bool) -> Res<Value> {
    blocking(move || {
        crate::account::with_api(&app, |api, _| {
            if approve {
                api.device_approve(&id)
            } else {
                api.device_deny(&id)
            }
        })?;
        teams::emit_changed(&app);
        Ok(json!({}))
    })
    .await
}

/// This device waits for approval and no other device is at hand: the e-mail fallback (a link;
/// every device can still deny it for 24 hours). A refresh then tries again.
#[tauri::command]
pub async fn device_approval_email(app: AppHandle) -> Res<Value> {
    blocking(move || {
        crate::account::with_api(&app, |api, _| api.device_approval_email())?;
        Ok(json!({}))
    })
    .await
}

pub fn parse_role(role: &str) -> Res<MemberRole> {
    match role {
        "manage" => Ok(MemberRole::Manage),
        "edit" => Ok(MemberRole::Edit),
        "view" => Ok(MemberRole::View),
        "fill" => Ok(MemberRole::Fill),
        _ => Err(tr!("errors.teams_bad_role")),
    }
}

#[tauri::command]
pub fn vault_items_vaults(app: AppHandle) -> Value {
    let vaults: Vec<VaultRef> = app_state(&app)
        .agent()
        .map(|a| a.open_vaults().into_iter().map(|(r, _)| r).collect())
        .unwrap_or_default();
    json!(vaults)
}

/// Shows an opened emergency access vault in the vault view beside the others, until the next
/// lock (memory only): read-only with view access; with full access too, but its items can be
/// copied into the user's own vault.
pub fn add_emergency_vault(app: &AppHandle, owner: &str, vault: Arc<Vault>) -> Res<()> {
    let agent = app_state(app).require_agent()?;
    let name = tr!("teams_rs.emergency_label", owner = owner);
    agent
        .add_session_vault(&name, vault.clone())
        .map_err(pass_err)?;
    {
        let mut opened = guard(&EMERGENCY);
        let id = vault.vault_id();
        opened.retain(|(_, v)| v.vault_id() != id);
        opened.push((owner.to_string(), vault));
    }
    teams::emit_changed(app);
    let _ = app.emit("vault-changed", ());
    Ok(())
}

pub fn emergency_vault(vault_id: &str) -> Option<(String, Arc<Vault>)> {
    guard(&EMERGENCY).iter().find(|(_, v)| v.vault_id() == vault_id).cloned()
}

#[tauri::command]
pub fn emergency_items(_app: AppHandle) -> Value {
    match guard(&EMERGENCY).last() {
        Some((owner, vault)) => {
            let items: Vec<Value> = vault
                .summaries()
                .into_iter()
                .map(|s| json!({ "id": s.id, "title": s.title, "username": s.username, "domain": s.domain }))
                .collect();
            json!({ "owner": owner, "vault_id": vault.vault_id(), "read_only": vault.is_read_only(), "items": items })
        }
        None => Value::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn backend() -> Backend {
        Backend::Server {
            base: "https://pass.example.com".into(),
            user: "bob".into(),
            token: "pst_demo".into(),
            pins: vec!["sha256:demo".into()],
        }
    }

    fn whoami_vault(vault: &str, shared: bool, role: &str, writable: bool) -> WhoamiVault {
        WhoamiVault {
            vault: vault.into(),
            path: format!("/dav/{vault}.vault"),
            owner: vault.split('/').next().unwrap().into(),
            role: role.into(),
            shared,
            writable,
            ..Default::default()
        }
    }

    #[test]
    fn whoami_vaults_become_linked_vaults() {
        let vaults = [
            whoami_vault("bob/personal", false, "owner", true),
            whoami_vault("acme/eng", true, "edit", true),
            whoami_vault("acme/support", true, "view", false),
        ];
        let labels = |key: &str| (key == "acme/eng").then(|| "Engineering".to_string());
        let configs = configs_for(&backend(), &vaults, &labels);
        assert_eq!(configs.len(), 2, "the personal vault is no linked vault");
        assert_eq!(configs[0].key, "acme/eng");
        assert_eq!(configs[0].name, "Engineering");
        assert_eq!(configs[1].name, "support");
        assert_eq!(configs[0].account, "bob");
        assert!(configs[0].writable && !configs[1].writable);
        let webdav = configs[0].webdav.as_ref().unwrap();
        assert_eq!(webdav.url, "https://pass.example.com/dav/acme/eng.vault");
        assert_eq!(webdav.username, "bob");
        assert_eq!(webdav.pins, ["sha256:demo"]);
        assert_ne!(configs[0].path, configs[1].path);
        assert!(configs[0].path.to_string_lossy().ends_with(".vault"));
    }

    #[test]
    fn local_copies_are_apart_per_backend() {
        assert_ne!(
            shared_path("https://a.example", "acme/eng"),
            shared_path("https://b.example", "acme/eng")
        );
        assert_eq!(
            shared_path("https://a.example/", "acme/eng"),
            shared_path("https://a.example", "acme/eng")
        );
        assert_eq!(key_of_path("/dav/o-acme/v-eng.vault"), "o-acme/v-eng");
    }

    #[test]
    fn roles_parse() {
        assert_eq!(parse_role("fill").unwrap(), MemberRole::Fill);
        assert!(parse_role("owner").is_err());
    }

    #[test]
    fn a_vault_row_says_whether_its_signer_is_verified() {
        let mut v = json!({});
        put_signer_status(&mut v, Some(&pass_core::PinStatus::Pinned));
        assert_eq!(v["signer_status"], "pinned");
        assert!(v["signer_pinned_fingerprint"].is_null());
        put_signer_status(
            &mut v,
            Some(&pass_core::PinStatus::Changed {
                pinned_fingerprint: "7K3QD".into(),
            }),
        );
        assert_eq!(v["signer_status"], "changed");
        assert_eq!(v["signer_pinned_fingerprint"], "7K3QD");
        put_signer_status(&mut v, None);
        assert!(v["signer_status"].is_null());
    }

    /// A breached service hands the member a vault whose members list is signed by keys it made
    /// under the manager's account: the member pinned the manager's real keys, so the vault shows
    /// as changed (the loud warning), not as shared by the manager.
    #[test]
    fn attack_a_list_signed_with_swapped_manager_keys_shows_changed() {
        use pass_core::{PinStatus, UserKeyset};
        let home = contact_pins::tests::home();
        let alice = UserKeyset::generate("acc_alice").unwrap();
        let real = Vault::create_shared(&alice, SharedKind::Direct, None, "alice").unwrap();
        assert_eq!(home.shared_signer_status(&real), Some(PinStatus::NotPinned));
        contact_pins::tests::pin(&home, &alice.public_keys());
        assert_eq!(home.shared_signer_status(&real), Some(PinStatus::Pinned));
        let fake = UserKeyset::generate("acc_alice").unwrap();
        let planted = Vault::create_shared(&fake, SharedKind::Direct, None, "alice").unwrap();
        assert_eq!(
            home.shared_signer_status(&planted),
            Some(PinStatus::Changed {
                pinned_fingerprint: alice.fingerprint()
            })
        );
    }

    /// Direct share, compare first: a recipient nobody compared gets nothing wrapped; the
    /// fingerprint the user compared pins them, and only then the vault takes them.
    #[test]
    fn a_direct_share_wraps_only_after_the_compare() {
        use pass_core::UserKeyset;
        let home = contact_pins::tests::home();
        let me = home.ensure_user_keyset("acc_me").unwrap();
        let bob = UserKeyset::generate("acc_bob").unwrap().public_keys();
        let vault = Vault::create_shared(&me, SharedKind::Direct, None, "me").unwrap();
        let mut pinned = false;
        let c = contact_pins::check(&home, &bob, None, &mut pinned)
            .unwrap()
            .unwrap();
        assert_eq!(c.status, contact_pins::NOT_VERIFIED);
        assert!(vault
            .add_member(bob.clone(), MemberRole::Edit, None, &home)
            .is_err());
        let fp = pass_core::public_keys_fingerprint(bob.clone());
        assert!(contact_pins::check(&home, &bob, Some(&fp), &mut pinned)
            .unwrap()
            .is_none());
        assert!(pinned);
        vault
            .add_member(bob, MemberRole::Edit, None, &home)
            .unwrap();
        // The service later offers other keys for Bob: changed, never wrapped.
        let swapped = UserKeyset::generate("acc_bob").unwrap().public_keys();
        let c = contact_pins::check(&home, &swapped, None, &mut pinned)
            .unwrap()
            .unwrap();
        assert_eq!(c.status, contact_pins::CHANGED);
        let other = Vault::create_shared(&me, SharedKind::Direct, None, "me").unwrap();
        assert!(other
            .add_member(swapped, MemberRole::Edit, None, &home)
            .is_err());
    }
}
