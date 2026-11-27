//! Secure send, emergency access and admin-assisted recovery (docs/ARCHITECTURE.md §15.12, §15.13,
//! §16) on the Passyble account. The cryptography is the core's; the service stores only what it
//! must (the sealed send without its key, the grant and its release secret, the recovery key and
//! enrolments). The routes are in `teams_api.rs`.
//!
//! * **Secure send**: sealed here (`send_seal`, at most 10 MiB, 30 days); the key stays in the link's
//!   fragment, never sent to the service.
//! * **Emergency access**: the grant goes to the service with its release secret, which the service
//!   hands to the contact only after the wait and if the owner didn't refuse.
//! * **Admin-assisted recovery** (Teams, opt-in): enrolment wraps the home vault key to the
//!   organisation's recovery key; a request keeps its one-time secret in Credential Manager until an
//!   admin approves it.

use pass_core::{EmergencyAccess, OrgKind, PublicKeys, SendContent, SendKind, SendOptions};
use serde_json::{json, Value};
use tauri::AppHandle;

use crate::account::with_api;
use crate::commands::{
    after_password_unlock, app_state, blocking, check_new_master_password, pass_err,
};
use crate::i18n::tr;

type Res<T> = Result<T, String>;

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

const DAY_MS: i64 = 24 * 60 * 60 * 1000;

fn send_base(app: &AppHandle, answer: &Value) -> String {
    answer
        .get("link_base")
        .and_then(Value::as_str)
        .filter(|b| b.starts_with("https://"))
        .map(|b| b.trim_end_matches('/').to_string())
        .unwrap_or_else(|| {
            format!(
                "{}/send",
                crate::account::base_url(&app_state(app).settings())
            )
        })
}

fn send_content(text: Option<String>, file_path: Option<String>) -> Res<SendContent> {
    if let Some(path) = file_path.filter(|p| !p.trim().is_empty()) {
        let path = std::path::PathBuf::from(path);
        let size = std::fs::metadata(&path)
            .map_err(crate::errors::file_not_read)?
            .len();
        if size > pass_core::SEND_MAX_BYTES {
            return Err(tr!("errors.send_too_large"));
        }
        let data = std::fs::read(&path).map_err(crate::errors::file_not_read)?;
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        return Ok(SendContent {
            kind: SendKind::File,
            name,
            mime: "application/octet-stream".into(),
            data,
        });
    }
    let text = text.unwrap_or_default();
    if text.trim().is_empty() {
        return Err(tr!("errors.send_empty"));
    }
    Ok(SendContent {
        kind: SendKind::Text,
        name: String::new(),
        mime: "text/plain; charset=utf-8".into(),
        data: text.into_bytes(),
    })
}

pub fn send_options(
    now: i64,
    expires_days: u32,
    max_views: u32,
    password: Option<String>,
) -> SendOptions {
    let days = expires_days.clamp(1, pass_core::SEND_MAX_DAYS);
    SendOptions {
        expires_at: now + i64::from(days) * DAY_MS,
        max_views: max_views.min(1000),
        password: password.filter(|p| !p.is_empty()),
    }
}

/// Seals a text or file and stores it. The link carries the key in its fragment; the service never
/// sees the key.
#[tauri::command]
pub async fn send_create(
    app: AppHandle,
    text: Option<String>,
    file_path: Option<String>,
    expires_days: u32,
    max_views: u32,
    password: Option<String>,
) -> Res<Value> {
    blocking(move || {
        let content = send_content(text, file_path)?;
        let options = send_options(now_ms(), expires_days, max_views, password);
        let expires_at = options.expires_at;
        let views = options.max_views;
        let sealed = pass_core::send_seal(content, options).map_err(pass_err)?;
        let answer = with_api(&app, |api, _| api.send_create(&sealed))?;
        let id = answer
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| tr!("errors.teams_unexpected_answer"))?
            .to_string();
        let link = pass_core::send_link(&send_base(&app, &answer), &id, &sealed.key).map_err(pass_err)?;
        Ok(json!({
            "id": id, "link": link,
            "expires_at": answer.get("expires_at").cloned().unwrap_or(json!(expires_at)),
            "max_views": views,
            "views_left": answer.get("views_left").cloned().unwrap_or(if views == 0 { Value::Null } else { json!(views) }),
        }))
    })
    .await
}

#[tauri::command]
pub async fn send_list(app: AppHandle) -> Res<Value> {
    blocking(move || {
        let answer = with_api(&app, |api, _| api.send_list())?;
        Ok(answer.get("sends").cloned().unwrap_or(answer))
    })
    .await
}

#[tauri::command]
pub async fn send_revoke(app: AppHandle, id: String) -> Res<Value> {
    blocking(move || with_api(&app, |api, _| api.send_revoke(&id)).map(|_| json!({}))).await
}

#[tauri::command]
pub async fn send_pick_file(app: AppHandle) -> Res<Option<String>> {
    use tauri::Manager;
    use tauri_plugin_dialog::DialogExt;
    blocking(move || {
        let mut dialog = app.dialog().file().set_title(tr!("dialog.send_file_title"));
        if let Some(main) = app.get_webview_window("main") {
            dialog = dialog.set_parent(&main);
        }
        Ok(dialog
            .blocking_pick_file()
            .and_then(|p| p.into_path().ok())
            .map(|p| p.to_string_lossy().into_owned()))
    })
    .await
}

#[tauri::command]
pub async fn emergency_status(app: AppHandle) -> Res<Value> {
    blocking(move || {
        let answer = with_api(&app, |api, _| api.emergency())?;
        let rows = |key: &str| {
            Value::Array(
                answer
                    .get(key)
                    .and_then(Value::as_array)
                    .map(|rows| rows.iter().map(emergency_row).collect())
                    .unwrap_or_default(),
            )
        };
        Ok(json!({
            "allowed": answer.get("allowed").cloned().unwrap_or(Value::Null),
            "contacts": rows("as_owner"),
            "as_contact": rows("as_contact"),
            "pending": emergency_pending(&app),
        }))
    })
    .await
}

/// One emergency contact row as the screen reads it (`released` shows as `available`). Times stay as
/// the service sends them (Unix milliseconds).
pub fn emergency_row(row: &Value) -> Value {
    let mut out = row.clone();
    let Some(map) = out.as_object_mut() else {
        return out;
    };
    let text = |k: &str| row.get(k).and_then(Value::as_str).map(str::to_string);
    if !map.contains_key("grant_id") {
        if let Some(id) = row.get("id").cloned() {
            map.insert("grant_id".into(), id);
        }
    }
    if let Some(status) = text("status") {
        let state = if status == "released" {
            "available".to_string()
        } else {
            status
        };
        map.insert("state".into(), json!(state));
    }
    for (field, email) in [("contact", "contact_email"), ("owner", "owner_email")] {
        if let Some(v) = text(email).or_else(|| text(field)) {
            map.insert(field.into(), json!(v));
        }
    }
    out
}

#[tauri::command]
pub async fn emergency_add(
    app: AppHandle,
    contact: String,
    access: String,
    wait_hours: u32,
) -> Res<Value> {
    blocking(move || {
        let email = contact.trim().to_string();
        if !email.contains('@') || email.len() > 254 {
            return Err(tr!("errors.teams_bad_email"));
        }
        let access = if access == "full" { "full" } else { "view" };
        let wait = wait_hours.clamp(1, pass_core::EMERGENCY_MAX_WAIT_HOURS);
        with_api(&app, |api, _| api.emergency_invite(&email, access, wait))
    })
    .await
}

#[tauri::command]
pub async fn emergency_accept(app: AppHandle, token: String) -> Res<Value> {
    blocking(move || with_api(&app, |api, _| api.emergency_accept(token.trim()))).await
}

#[tauri::command]
pub async fn emergency_contact_keys(app: AppHandle, id: String) -> Res<Value> {
    blocking(move || {
        let stored = with_api(&app, |api, _| api.emergency_keys(&id))?;
        stored
            .keys
            .verify()
            .map_err(|_| tr!("errors.teams_bad_keys"))?;
        Ok(json!({ "fingerprint": stored.keys.fingerprint(), "account": stored.keys.account }))
    })
    .await
}

type GrantTarget = (std::sync::Arc<pass_core::Vault>, Option<String>, String);

type Released = (String, pass_core::EmergencyGrant, zeroize::Zeroizing<String>, bool);

/// The vaults one emergency access record covers: every vault linked to the account on this PC, plus
/// the open personal vault when it is linked, or when it has a separate password and the owner
/// ticked it (`include_open`).
fn grant_targets(
    app: &AppHandle,
    account: &str,
    include_open: bool,
    password: Option<&str>,
) -> Res<Vec<GrantTarget>> {
    let state = app_state(app);
    let settings = state.settings();
    let mut out = Vec::new();
    let active = settings.active().cloned();
    let open = state
        .agent()
        .filter(|a| !a.is_locked())
        .and_then(|a| a.peek_vault())
        .filter(|v| !v.is_shared());
    let mut open_id = None;
    if let (Some(vault), Some(entry)) = (open, active.as_ref()) {
        let linked = vault.account_link().is_some_and(|l| l.account == account);
        if linked || include_open {
            open_id = Some(vault.vault_id());
            out.push((vault, cloud_name(entry), entry.path.to_string_lossy().into_owned()));
        }
    }
    let linked = crate::account_keys::reset::local_vaults(&state, account);
    let others: Vec<_> = linked
        .iter()
        .filter(|v| active.as_ref().is_none_or(|a| a.id != v.id))
        .collect();
    if others.is_empty() {
        return Ok(out);
    }
    let ak = crate::account_keys::key_now(app, account, password)?;
    for v in others.into_iter().filter(|v| v.ak_id == ak.ak_id()) {
        let Ok(bytes) = std::fs::read(&v.path) else { continue };
        let Ok(vault) = pass_core::Vault::unlock_with_account_key(bytes, &ak, settings.device_id.clone()) else {
            continue;
        };
        if open_id.as_deref() == Some(vault.vault_id().as_str()) {
            continue;
        }
        let entry = settings.vault(&v.id);
        out.push((vault, entry.and_then(cloud_name), v.path.to_string_lossy().into_owned()));
    }
    Ok(out)
}

/// A vault's name on Passyble Cloud (`personal` or a `v-` name); `None` for a vault kept elsewhere.
pub fn cloud_name(entry: &crate::settings::VaultEntry) -> Option<String> {
    let w = entry.webdav.as_ref().filter(|w| w.is_pass_server())?;
    let last = w.url.trim_end_matches('/').rsplit('/').next()?;
    let stem = last.strip_suffix(".vault")?;
    (stem == "personal" || stem.starts_with("v-")).then(|| stem.to_string())
}

fn keep_grant(account: &str, record: &str, grant: &pass_core::EmergencyGrant, path: &str) {
    let kept = crate::account_keys::device::KeptGrant {
        record: record.to_string(),
        vault_id: grant.vault_id.clone(),
        grant: serde_json::to_value(grant).unwrap_or_default(),
        path: path.to_string(),
    };
    let _ = crate::account_keys::device::update(account, |c| {
        c.emergency.retain(|k| !(k.record == kept.record && k.vault_id == kept.vault_id));
        c.emergency.push(kept);
    });
}

fn same_fingerprint(a: &str, b: &str) -> bool {
    let norm = |f: &str| -> String {
        f.chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .map(|c| c.to_ascii_uppercase())
            .collect()
    };
    !a.is_empty() && norm(a) == norm(b)
}

/// After the owner compared `fingerprint`: one core grant per covered vault, with its release secret,
/// to the service. The account key is needed for linked vaults that aren't open (`password`, else
/// `account_password_needed`).
#[tauri::command]
pub async fn emergency_grant(
    app: AppHandle,
    id: String,
    fingerprint: String,
    access: String,
    wait_hours: u32,
    include_open: Option<bool>,
    password: Option<String>,
) -> Res<Value> {
    let password = password.map(zeroize::Zeroizing::new);
    blocking(move || {
        let me =
            crate::account::signed_in(&app).ok_or_else(|| tr!("errors.teams_sign_in_first"))?;
        let stored = with_api(&app, |api, _| api.emergency_keys(&id))?;
        let keys = stored.keys;
        keys.verify().map_err(|_| tr!("errors.teams_bad_keys"))?;
        if !same_fingerprint(&keys.fingerprint(), &fingerprint) {
            return Err(tr!("errors.teams_fingerprint_mismatch"));
        }
        let access = match access.as_str() {
            "full" => EmergencyAccess::Full,
            _ => EmergencyAccess::View,
        };
        let wait = wait_hours.clamp(1, pass_core::EMERGENCY_MAX_WAIT_HOURS);
        let targets = grant_targets(&app, &me.id, include_open.unwrap_or(true), password.as_deref().map(|p| p.as_str()))?;
        if targets.is_empty() {
            return Err(tr!("emergency.no_vault_open"));
        }
        let mut granted = 0;
        for (vault, cloud, path) in &targets {
            let created = vault
                .emergency_grant(&me.id, keys.clone(), access, wait)
                .map_err(pass_err)?;
            with_api(&app, |api, _| api.emergency_grant(&id, &created, cloud.as_deref()))?;
            keep_grant(&me.id, &id, &created.grant, path);
            granted += 1;
        }
        crate::account_keys::device::update(&me.id, |c| c.emergency_pending = false)?;
        Ok(json!({ "grant_id": id, "vaults": granted }))
    })
    .await
}

/// What the next open of `vault` does for one of the owner's records: `Renew` when the record covers
/// the vault and its grant is missing or stale, `Keep` otherwise.
#[derive(Debug, PartialEq, Eq)]
pub enum GrantStep {
    Keep,
    Renew,
}

pub fn grant_step(linked: bool, granted: bool, kept_current: Option<bool>) -> GrantStep {
    if !linked && !granted {
        return GrantStep::Keep;
    }
    match kept_current {
        Some(true) => GrantStep::Keep,
        Some(false) => GrantStep::Renew,
        // No grant made here: renew only a vault the record doesn't cover yet.
        None if granted => GrantStep::Keep,
        None => GrantStep::Renew,
    }
}

/// After a vault opened: renews missing or stale emergency grants and drops grants of vaults that are
/// gone. In the background; a renewal the service refuses (it wants a fresh sign-in) is left for
/// Emergency access ("Update now", `emergency_pending`).
pub fn renew_soon(app: &AppHandle) {
    let app = app.clone();
    let _ = std::thread::Builder::new()
        .name("pass-emergency-renew".into())
        .spawn(move || {
            if let Err(e) = renew(&app) {
                crate::applog::plog!("emergency access: grants not renewed: {e}");
            }
        });
}

#[tauri::command]
pub async fn emergency_renew_now(app: AppHandle) -> Res<Value> {
    blocking(move || {
        renew(&app)?;
        if emergency_pending(&app) {
            return Err("reauth_required".into());
        }
        Ok(json!({}))
    })
    .await
}

fn emergency_pending(app: &AppHandle) -> bool {
    crate::account::signed_in(app).is_some_and(|me| crate::account_keys::device::load(&me.id).emergency_pending)
}

fn file_vault_id(path: &std::path::Path) -> Option<String> {
    #[derive(serde::Deserialize)]
    struct Head {
        vault_id: String,
    }
    serde_json::from_slice::<Head>(&std::fs::read(path).ok()?).ok().map(|h| h.vault_id)
}

fn renew(app: &AppHandle) -> Res<()> {
    use crate::account_keys::device::{self, KeptGrant};
    let Some(me) = crate::account::signed_in(app) else {
        return Ok(());
    };
    let state = app_state(app);
    let Some(vault) = state
        .agent()
        .filter(|a| !a.is_locked())
        .and_then(|a| a.peek_vault())
        .filter(|v| !v.is_shared() && !v.is_read_only())
    else {
        return Ok(());
    };
    let answer = with_api(app, |api, _| api.emergency())?;
    let rows: Vec<Value> = answer
        .get("as_owner")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let vault_id = vault.vault_id();
    let linked = vault.account_link().is_some_and(|l| l.account == me.id);
    let settings = state.settings();
    let path = settings
        .active()
        .map(|e| e.path.to_string_lossy().into_owned())
        .unwrap_or_default();
    let cloud = settings.active().and_then(cloud_name);
    // The vaults of the list, by the vault id their files name (a moved file keeps its id).
    let listed: Vec<String> = settings.vaults.iter().filter_map(|v| file_vault_id(&v.path)).collect();
    let cache = device::load(&me.id);
    let mut added: Vec<KeptGrant> = Vec::new();
    let mut dropped: Vec<(String, String)> = Vec::new();
    let mut pending = false;
    for row in rows.iter().filter(|r| r.get("status").and_then(Value::as_str) == Some("ready")) {
        let Some(record) = row.get("id").and_then(Value::as_str) else { continue };
        let granted_ids: Vec<&str> = row
            .get("vault_ids")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        let mine: Vec<&KeptGrant> = cache.emergency.iter().filter(|k| k.record == record).collect();
        // Vaults this PC granted that are gone from it (no vault of the list has their id, and the
        // file they had is gone too): their grants go.
        for k in &mine {
            let gone = k.vault_id != vault_id
                && !listed.contains(&k.vault_id)
                && !k.path.is_empty()
                && !std::path::Path::new(&k.path).exists();
            if gone && with_api(app, |api, _| api.emergency_grant_remove(record, &k.vault_id)).is_ok() {
                dropped.push((record.to_string(), k.vault_id.clone()));
            }
        }
        let parsed = |k: &KeptGrant| serde_json::from_value::<pass_core::EmergencyGrant>(k.grant.clone()).ok();
        let kept = mine.iter().find(|k| k.vault_id == vault_id).and_then(|k| parsed(k));
        let current = kept.as_ref().map(|g| vault.emergency_grant_current(g.clone()));
        if grant_step(linked, granted_ids.contains(&vault_id.as_str()), current) == GrantStep::Keep {
            continue;
        }
        // The contact the owner confirmed: the fingerprint of any grant of this record made here.
        let Some(confirmed) = mine.iter().filter_map(|k| parsed(k)).map(|g| g.contact_fingerprint).next() else {
            // Set up on another device: that device (or a new setup here) grants it.
            crate::applog::plog!("emergency access: a record set up elsewhere was not renewed here");
            continue;
        };
        let Ok(stored) = with_api(app, |api, _| api.emergency_keys(record)) else { continue };
        if stored.keys.verify().is_err() || !same_fingerprint(&stored.keys.fingerprint(), &confirmed) {
            // The contact's keys changed: the owner confirms them again before any new grant.
            crate::applog::plog!("emergency access: the contact's keys changed; not renewed");
            continue;
        }
        let access = if row.get("access").and_then(Value::as_str) == Some("full") {
            EmergencyAccess::Full
        } else {
            EmergencyAccess::View
        };
        let wait = row
            .get("wait_hours")
            .and_then(Value::as_u64)
            .map(|w| w as u32)
            .unwrap_or(168)
            .clamp(1, pass_core::EMERGENCY_MAX_WAIT_HOURS);
        let Ok(created) = vault.emergency_grant(&me.id, stored.keys, access, wait) else { continue };
        match with_api(app, |api, _| api.emergency_grant(record, &created, cloud.as_deref())) {
            Ok(_) => added.push(KeptGrant {
                record: record.to_string(),
                vault_id: vault_id.clone(),
                grant: serde_json::to_value(&created.grant).unwrap_or_default(),
                path: path.clone(),
            }),
            Err(_) => pending = true,
        }
    }
    device::update(&me.id, |c| {
        c.emergency.retain(|k| !dropped.iter().any(|(r, v)| *r == k.record && *v == k.vault_id));
        for a in &added {
            c.emergency.retain(|k| !(k.record == a.record && k.vault_id == a.vault_id));
            c.emergency.push(a.clone());
        }
        // This vault's file now (it may have moved since it was granted).
        for k in c.emergency.iter_mut().filter(|k| k.vault_id == vault_id) {
            k.path = path.clone();
        }
        c.emergency_pending = pending;
    })?;
    Ok(())
}

#[tauri::command]
pub async fn emergency_remove(app: AppHandle, grant_id: String) -> Res<Value> {
    blocking(move || with_api(&app, |api, _| api.emergency_remove(&grant_id)).map(|_| json!({})))
        .await
}

#[tauri::command]
pub async fn emergency_request(app: AppHandle, grant_id: String) -> Res<Value> {
    blocking(move || with_api(&app, |api, _| api.emergency_request(&grant_id)).map(|_| json!({})))
        .await
}

#[tauri::command]
pub async fn emergency_answer(app: AppHandle, grant_id: String, approve: bool) -> Res<Value> {
    blocking(move || {
        with_api(&app, |api, _| api.emergency_answer(&grant_id, approve)).map(|_| json!({}))
    })
    .await
}

/// The released grants of a record: `grants` (one per vault), else the single grant older services
/// send. `(vault_id, grant, release_secret, on_cloud)`.
fn released_grants(release: &Value) -> Res<Vec<Released>> {
    let one = |g: &Value, secret: Option<&Value>, cloud: bool| -> Option<Released> {
        let grant: pass_core::EmergencyGrant = serde_json::from_value(g.clone()).ok()?;
        let secret = zeroize::Zeroizing::new(secret?.as_str()?.to_string());
        Some((grant.vault_id.clone(), grant, secret, cloud))
    };
    let mut out = Vec::new();
    if let Some(list) = release.get("grants").and_then(Value::as_array).filter(|l| !l.is_empty()) {
        for g in list {
            let cloud = g.get("download").is_some_and(|d| !d.is_null());
            if let Some(x) = g.get("grant").and_then(|grant| one(grant, g.get("release_secret"), cloud)) {
                out.push(x);
            }
        }
    } else if let Some(x) = release.get("grant").and_then(|g| one(g, release.get("release_secret"), true)) {
        out.push(x);
    }
    if out.is_empty() {
        return Err(tr!("errors.emergency_not_released"));
    }
    Ok(out)
}

/// As a contact, once released: opens every granted Passyble Cloud vault of the owner, memory only
/// (gone at the next lock). View access is read-only; full may edit, copy out or keep it
/// ([`emergency_keep`]). Vaults kept elsewhere open from a handed-over copy ([`emergency_open_file`]).
#[tauri::command]
pub async fn emergency_open(app: AppHandle, grant_id: String) -> Res<Value> {
    blocking(move || {
        let state = app_state(&app);
        let home = state.vault()?;
        let me =
            crate::account::signed_in(&app).ok_or_else(|| tr!("errors.teams_sign_in_first"))?;
        let release = with_api(&app, |api, _| api.emergency_release(&grant_id))?;
        let grants = released_grants(&release)?;
        let keyset = home
            .user_keyset(&me.id)
            .map_err(pass_err)?
            .ok_or_else(|| tr!("errors.teams_keys_missing"))?;
        let several = release.get("grants").and_then(Value::as_array).is_some_and(|g| !g.is_empty());
        let mut opened = 0;
        let mut opened_ids: Vec<String> = Vec::new();
        let mut read_only = true;
        let mut elsewhere = 0;
        let mut last_error = None;
        for (vault_id, grant, secret, on_cloud) in grants {
            if !on_cloud {
                elsewhere += 1;
                continue;
            }
            let file = if several {
                with_api(&app, |api, _| api.emergency_vault_of(&grant_id, &vault_id))
            } else {
                with_api(&app, |api, _| api.emergency_vault(&grant_id))
            };
            let file = match file {
                Ok(f) => f,
                Err(e) => {
                    last_error = Some(e);
                    continue;
                }
            };
            match pass_core::Vault::open_emergency(file, grant.clone(), &secret, &keyset, &state.settings().device_id) {
                Ok(vault) => {
                    read_only &= vault.is_read_only();
                    let owner = release
                        .pointer("/vault/owner")
                        .and_then(Value::as_str)
                        .unwrap_or(&grant.owner)
                        .to_string();
                    opened_ids.push(vault.vault_id());
                    crate::teams_vaults::add_emergency_vault(&app, &owner, vault)?;
                    opened += 1;
                }
                Err(e) => last_error = Some(pass_err(e)),
            }
        }
        if opened == 0 && elsewhere == 0 {
            return Err(last_error.unwrap_or_else(|| tr!("errors.emergency_not_released")));
        }
        Ok(json!({ "opened": opened, "vault_ids": opened_ids, "read_only": read_only, "elsewhere": elsewhere }))
    })
    .await
}

#[tauri::command]
pub async fn emergency_open_file(app: AppHandle, grant_id: String) -> Res<Value> {
    use tauri::Manager;
    use tauri_plugin_dialog::DialogExt;
    blocking(move || {
        let state = app_state(&app);
        let home = state.vault()?;
        let me =
            crate::account::signed_in(&app).ok_or_else(|| tr!("errors.teams_sign_in_first"))?;
        let mut dialog = app.dialog().file().set_title(tr!("emergency.open_copy_title")).add_filter("Passyble", &["vault"]);
        if let Some(main) = app.get_webview_window("main") {
            dialog = dialog.set_parent(&main);
        }
        let Some(path) = dialog.blocking_pick_file().and_then(|p| p.into_path().ok()) else {
            return Ok(json!({ "opened": 0 }));
        };
        let file = std::fs::read(&path).map_err(crate::errors::file_not_read)?;
        let release = with_api(&app, |api, _| api.emergency_release(&grant_id))?;
        let keyset = home
            .user_keyset(&me.id)
            .map_err(pass_err)?
            .ok_or_else(|| tr!("errors.teams_keys_missing"))?;
        let mut last = tr!("emergency.copy_not_granted");
        for (_, grant, secret, _) in released_grants(&release)? {
            match pass_core::Vault::open_emergency(file.clone(), grant.clone(), &secret, &keyset, &state.settings().device_id) {
                Ok(vault) => {
                    let read_only = vault.is_read_only();
                    let id = vault.vault_id();
                    crate::teams_vaults::add_emergency_vault(&app, &grant.owner, vault)?;
                    return Ok(json!({ "opened": 1, "vault_ids": [id], "read_only": read_only }));
                }
                Err(pass_core::PassError::InvalidInput(_)) => {}
                Err(e) => last = pass_err(e),
            }
        }
        Err(last)
    })
    .await
}

/// As a contact with full access: keeps an opened vault of the owner as a vault of the contact's own,
/// linked to the contact's Passyble password. The owner's account key is never involved; the
/// contact's own key must be open (`password`, else `account_password_needed`).
#[tauri::command]
pub async fn emergency_keep(app: AppHandle, vault_id: String, password: Option<String>) -> Res<Value> {
    use tauri::Manager;
    use tauri_plugin_dialog::DialogExt;
    let password = password.map(zeroize::Zeroizing::new);
    blocking(move || {
        let me =
            crate::account::signed_in(&app).ok_or_else(|| tr!("errors.teams_sign_in_first"))?;
        let (owner, vault) = crate::teams_vaults::emergency_vault(&vault_id).ok_or_else(|| tr!("errors.emergency_not_released"))?;
        if vault.is_read_only() {
            return Err(tr!("emergency.keep_view_only"));
        }
        let ak = crate::account_keys::key_now(&app, &me.id, password.as_deref().map(|p| p.as_str()))?;
        let mut dialog = app
            .dialog()
            .file()
            .set_title(tr!("emergency.keep_title"))
            .set_file_name(format!("{}.vault", tr!("emergency.keep_file_name", owner = owner)))
            .add_filter("Passyble", &["vault"]);
        if let Some(main) = app.get_webview_window("main") {
            dialog = dialog.set_parent(&main);
        }
        let Some(path) = dialog.blocking_save_file().and_then(|p| p.into_path().ok()) else {
            return Ok(json!({ "kept": false }));
        };
        let path = crate::commands::normalize_vault_path(&path.to_string_lossy())?;
        vault.link_to_account(&ak).map_err(pass_err)?;
        if let Some(copy) = crate::account_keys::device::load(&me.id).recovery {
            let _ = vault.set_account_recovery(copy.rec_id, copy.wrap);
        }
        crate::vaults::write_vault_file(&path, &vault)?;
        let name = tr!("teams_rs.emergency_label", owner = owner);
        let (agent, id) = crate::commands::prepare_agent(&app, path, Some(name), None)?;
        agent.unlock_with_account_key(&ak).map_err(pass_err)?;
        let state = app_state(&app);
        state.update_settings(|s| {
            if let Some(v) = s.vaults.iter_mut().find(|v| v.id == id) {
                v.linked_account = Some(me.id.clone());
            }
            Ok(())
        })?;
        crate::vaults::mark_opened(&state, &id);
        Ok(json!({ "kept": true, "id": id }))
    })
    .await
}

fn is_team(app: &AppHandle, org: &str) -> Res<()> {
    match crate::teams::cached_org(app, org) {
        Some(o) if o.kind == "team" => Ok(()),
        Some(_) => Err(tr!("errors.admin_recovery_teams_only")),
        None => Err(tr!("errors.teams_not_in_org")),
    }
}

/// A Team, or a Family (a Family member opts in to admin recovery of the account key).
fn is_team_or_family(app: &AppHandle, org: &str) -> Res<()> {
    match crate::teams::cached_org(app, org) {
        Some(o) if o.kind == "team" || o.kind == "family" => Ok(()),
        Some(_) => Err(tr!("errors.admin_recovery_teams_only")),
        None => Err(tr!("errors.teams_not_in_org")),
    }
}

pub(crate) fn org_keys(app: &AppHandle, org: &str, account: &str) -> Res<PublicKeys> {
    let stored = with_api(app, |api, _| api.keys_of(org, account))?;
    stored
        .keys
        .verify()
        .map_err(|_| tr!("errors.teams_bad_keys"))?;
    if stored.keys.account != account {
        return Err(tr!("errors.teams_bad_keys"));
    }
    Ok(stored.keys)
}

fn recovery_key(
    app: &AppHandle,
    org: &str,
    info: &Value,
) -> Res<(pass_core::OrgRecoveryKey, PublicKeys)> {
    let key: pass_core::OrgRecoveryKey =
        serde_json::from_value(info.get("key").cloned().unwrap_or_default())
            .map_err(|_| tr!("errors.admin_recovery_not_offered"))?;
    let creator = org_keys(app, org, &key.created_by)?;
    Ok((key, creator))
}

#[tauri::command]
pub async fn admin_recovery_status(app: AppHandle) -> Res<Value> {
    blocking(move || {
        let state = app_state(&app);
        let enrolled = state
            .quiet_vault()
            .map(|v| v.admin_recovery_enrollments())
            .unwrap_or_default();
        let orgs = state.settings().teams.map(|t| t.orgs).unwrap_or_default();
        let mut out = Vec::new();
        for org in orgs.iter().filter(|o| o.kind == "team") {
            let mine = enrolled.iter().find(|e| e.org == org.id);
            let info = with_api(&app, |api, _| api.recovery(&org.id)).unwrap_or_default();
            out.push(json!({
                "org": org.id, "name": org.name,
                "enrolled": mine.is_some(),
                "enrolled_at": mine.map(|e| e.enrolled_at),
                "available": info.get("enabled").and_then(Value::as_bool).unwrap_or(false)
                    && info.get("key").is_some_and(|k| !k.is_null()),
                "requests": info.get("requests").cloned().unwrap_or(json!([])),
            }));
        }
        let log = state
            .quiet_vault()
            .map(|v| v.admin_recovery_log())
            .unwrap_or_default();
        Ok(json!({ "orgs": out, "log": serde_json::to_value(log).unwrap_or_default() }))
    })
    .await
}

/// Opts the home vault in to the Team's admin-assisted recovery. Compare first: the admin who
/// made the Team's recovery key must be pinned in the home vault; until then the answer is `{
/// needs_compare }` with their fingerprint, and nothing is wrapped. Called again with
/// `fingerprint` (what the member compared with that admin) they are pinned, then enrolled.
#[tauri::command]
pub async fn admin_recovery_enroll(
    app: AppHandle,
    org: String,
    fingerprint: Option<String>,
) -> Res<Value> {
    blocking(move || {
        is_team(&app, &org)?;
        let state = app_state(&app);
        let vault = state.vault()?;
        let me =
            crate::account::signed_in(&app).ok_or_else(|| tr!("errors.teams_sign_in_first"))?;
        let info = with_api(&app, |api, _| api.recovery(&org))?;
        let (key, creator) = recovery_key(&app, &org, &info)?;
        let mut pinned = false;
        let compare =
            crate::contact_pins::check(&vault, &creator, fingerprint.as_deref(), &mut pinned)?;
        if pinned {
            state.require_agent()?.save().map_err(pass_err)?;
        }
        if let Some(c) = compare {
            return Ok(json!({ "needs_compare": c }));
        }
        let enrollment = vault
            .admin_recovery_enroll(key, creator, &me.id, OrgKind::Team)
            .map_err(pass_err)?;
        with_api(&app, |api, _| api.recovery_enroll(&org, &enrollment))?;
        state.require_agent()?.save().map_err(pass_err)?;
        Ok(json!({}))
    })
    .await
}

#[tauri::command]
pub async fn admin_recovery_withdraw(app: AppHandle, org: String) -> Res<Value> {
    blocking(move || {
        let state = app_state(&app);
        let vault = state.vault()?;
        vault.admin_recovery_withdraw(&org).map_err(pass_err)?;
        state.require_agent()?.save().map_err(pass_err)?;
        // The vault no longer holds the wrap; the service's copy goes too (best effort).
        if with_api(&app, |api, _| api.recovery_withdraw(&org)).is_err() {
            crate::applog::plog!("admin recovery: the withdrawal was not sent to the service");
        }
        Ok(json!({}))
    })
    .await
}

/// `Pass/AdminRecovery/<request id>`: the request's one-time secret until it is used.
pub(crate) fn secret_name(request_id: &str) -> String {
    format!(
        "Pass/AdminRecovery/{}",
        crate::teams_api::segment(request_id)
    )
}

/// Forgot the master password (works locked): asks the Team's admins to approve a recovery of the
/// active vault. The one-time secret stays on this PC. `code` is the request's comparison code
/// ([`pass_core::recovery_request_code`], from the request made here, never from the service), which
/// the member reads out to an admin on a call; the admin types it to approve.
#[tauri::command]
pub async fn admin_recovery_request(
    app: AppHandle,
    org: String,
    account: Option<String>,
) -> Res<Value> {
    blocking(move || {
        is_team(&app, &org)?;
        let me =
            crate::account::signed_in(&app).ok_or_else(|| tr!("errors.teams_sign_in_first"))?;
        let account = account.filter(|a| !a.trim().is_empty()).unwrap_or(me.id);
        let info = with_api(&app, |api, _| api.recovery(&org))?;
        let vault_id = info
            .pointer("/enrollment/vault_id")
            .and_then(Value::as_str)
            .ok_or_else(|| tr!("errors.admin_recovery_not_enrolled"))?
            .to_string();
        let request =
            pass_core::admin_recovery_request(&org, &account, &vault_id).map_err(pass_err)?;
        crate::account::store().set(&secret_name(&request.request.request_id), &request.secret)?;
        if let Err(e) = with_api(&app, |api, _| api.recovery_request(&org, &request.request)) {
            crate::account::store().delete(&secret_name(&request.request.request_id));
            return Err(e);
        }
        let code = pass_core::recovery_request_code(request.request.clone()).map_err(pass_err)?;
        Ok(json!({ "request_id": request.request.request_id, "code": code }))
    })
    .await
}

#[tauri::command]
pub async fn admin_recovery_finish(
    app: AppHandle,
    org: String,
    request_id: String,
    new_password: String,
) -> Res<Value> {
    blocking(move || {
        let state = app_state(&app);
        check_new_master_password(&state, &new_password, &[], true)?;
        crate::teams::check_master_password(&app, &new_password)?;
        let status = with_api(&app, |api, _| {
            api.recovery_request_status(&org, &request_id)
        })?;
        let approval: pass_core::RecoveryApproval =
            match status.get("approval").filter(|a| !a.is_null()) {
                Some(a) => serde_json::from_value(a.clone())
                    .map_err(|_| tr!("errors.teams_unexpected_answer"))?,
                None => return Err(tr!("errors.admin_recovery_waiting")),
            };
        let approver = org_keys(&app, &org, &approval.approved_by)?;
        let secret = crate::account::store()
            .get(&secret_name(&request_id))
            .ok_or_else(|| tr!("errors.admin_recovery_other_pc"))?;
        let agent = state.require_agent()?;
        let id = crate::vaults::active_id(&state)?;
        let path = agent.config().vault_path;
        let bytes = std::fs::read(&path)
            .map_err(|e| crate::errors::logged(tr!("errors.vault_not_read"), "read vault", e))?;
        let vault = pass_core::Vault::unlock_with_admin_recovery(
            bytes,
            approval.clone(),
            &secret,
            approver.clone(),
            &state.settings().device_id,
        )
        .map_err(pass_err)?;
        // The new password gives the vault a new key: the enrolment just used, the recovery code and the
        // emergency grants held the old one.
        let before = crate::password_change::before(&vault);
        vault
            .change_master_password(new_password.clone())
            .map_err(pass_err)?;
        let file = vault.serialize().map_err(pass_err)?;
        std::fs::write(&path, file).map_err(crate::errors::file_not_saved)?;
        agent
            .unlock_with_key(vault.export_vault_key())
            .map_err(pass_err)?;
        crate::account::store().delete(&secret_name(&request_id));
        if with_api(&app, |api, _| api.recovery_complete(&org, &request_id)).is_err() {
            crate::applog::plog!("admin recovery: the completion was not sent to the service");
        }
        crate::teams::note_master_password(&new_password);
        let mut result = after_password_unlock(&state, &agent, &id);
        let _ = crate::background::sync_now(&app);
        crate::password_change::after_change(&app, &agent, &id, &before, &mut result);
        result["unlocked"] = json!(true);
        result["approved_by"] = json!(approval.approved_by);
        result["approver_fingerprint"] = json!(approver.fingerprint());
        Ok(result)
    })
    .await
}

#[tauri::command]
pub async fn org_admin_recovery_requests(app: AppHandle, org: String) -> Res<Value> {
    blocking(move || {
        is_team_or_family(&app, &org)?;
        let answer = with_api(&app, |api, _| api.recovery(&org))?;
        Ok(answer.get("pending").cloned().unwrap_or(json!([])))
    })
    .await
}

/// Approves the waiting request `pending` by `admin`, with `code`: what the member read out from their
/// screen. The core checks it against the request it approves, so a request whose key the service
/// swapped is refused (`recovery.code_mismatch`). The code is never worked out for the admin.
fn approve_pending(
    key: pass_core::OrgRecoveryKey,
    admin: &pass_core::UserKeyset,
    pending: &Value,
    code: &str,
) -> Res<pass_core::RecoveryApproval> {
    if code.trim().is_empty() {
        return Err(tr!("errors.admin_recovery_code_needed"));
    }
    let request: pass_core::RecoveryRequestPublic =
        serde_json::from_value(pending.get("request").cloned().unwrap_or_default())
            .map_err(|_| tr!("errors.teams_unexpected_answer"))?;
    let enrollment: pass_core::RecoveryEnrollment =
        serde_json::from_value(pending.get("enrollment").cloned().unwrap_or_default())
            .map_err(|_| tr!("errors.teams_unexpected_answer"))?;
    pass_core::admin_recovery_approve(key, admin, enrollment, request, code).map_err(pass_err)
}

#[tauri::command]
pub async fn org_admin_recovery_approve(
    app: AppHandle,
    org: String,
    request_id: String,
    approve: Option<bool>,
    code: Option<String>,
) -> Res<Value> {
    blocking(move || {
        is_team_or_family(&app, &org)?;
        if approve == Some(false) {
            with_api(&app, |api, _| api.recovery_deny(&org, &request_id))?;
            return Ok(json!({}));
        }
        let state = app_state(&app);
        let home = state.vault()?;
        let me =
            crate::account::signed_in(&app).ok_or_else(|| tr!("errors.teams_sign_in_first"))?;
        let keyset = home
            .user_keyset(&me.id)
            .map_err(pass_err)?
            .ok_or_else(|| tr!("errors.teams_keys_missing"))?;
        let info = with_api(&app, |api, _| api.recovery(&org))?;
        let key: pass_core::OrgRecoveryKey =
            serde_json::from_value(info.get("key").cloned().unwrap_or_default())
                .map_err(|_| tr!("errors.admin_recovery_not_offered"))?;
        let pending = info
            .get("pending")
            .and_then(Value::as_array)
            .and_then(|list| {
                list.iter()
                    .find(|p| p.get("id").and_then(Value::as_str) == Some(request_id.as_str()))
            })
            .cloned()
            .ok_or_else(|| tr!("errors.item_not_found"))?;
        let approval = approve_pending(key, &keyset, &pending, code.as_deref().unwrap_or(""))?;
        with_api(&app, |api, _| {
            api.recovery_approve(&org, &request_id, &approval)
        })?;
        Ok(json!({}))
    })
    .await
}

#[cfg(test)]
mod tests {
    #[test]
    fn emergency_rows_keep_the_services_millisecond_times() {
        let row = json!({
            "id": "em_1", "status": "requested", "owner_email": "owner@example.com",
            "contact_email": "contact@example.com", "wait_hours": 48,
            "requested_at": 1_700_000_000_000_i64, "release_at": 1_700_172_800_000_i64,
        });
        let out = emergency_row(&row);
        assert_eq!(out["release_at"], 1_700_172_800_000_i64);
        assert_eq!(out["requested_at"], 1_700_000_000_000_i64);
        assert!(out.get("available_at").is_none());
        assert_eq!(out["grant_id"], "em_1");
        assert_eq!(out["state"], "requested");
        assert_eq!(emergency_row(&json!({ "status": "released" }))["state"], "available");
    }

    use super::*;

    /// A Team with a recovery key by Alice, and Mia's account key enrolled with it (Mia compared
    /// Alice's fingerprint). Demo keys only.
    fn recovery_org() -> (
        pass_core::UserKeyset,
        pass_core::OrgRecoveryKey,
        std::sync::Arc<pass_core::AccountKey>,
        pass_core::RecoveryEnrollment,
    ) {
        let alice = pass_core::UserKeyset::generate("acc_alice").unwrap();
        let admins_home = crate::contact_pins::tests::home();
        let key =
            pass_core::org_recovery_create(&alice, "org_acme", OrgKind::Team, vec![], &admins_home)
                .unwrap();
        let mia_home = crate::contact_pins::tests::home();
        crate::contact_pins::tests::pin(&mia_home, &alice.public_keys());
        let ak = pass_core::AccountKey::generate("acc_mia".into()).unwrap();
        let enrollment = ak
            .admin_recovery_enroll(key.clone(), alice.public_keys(), OrgKind::Team, &mia_home)
            .unwrap();
        (alice, key, ak, enrollment)
    }

    fn pending_of(request: &pass_core::RecoveryRequestPublic, e: &pass_core::RecoveryEnrollment) -> Value {
        json!({ "id": request.request_id, "request": request, "enrollment": e })
    }

    #[test]
    fn the_admin_approves_with_the_code_the_member_reads_out() {
        let (alice, key, ak, enrollment) = recovery_org();
        let req =
            pass_core::admin_recovery_request("org_acme", "acc_mia", &enrollment.vault_id).unwrap();
        let code = pass_core::recovery_request_code(req.request.clone()).unwrap();
        let pending = pending_of(&req.request, &enrollment);
        // No code, or another one: nothing is approved.
        assert!(approve_pending(key.clone(), &alice, &pending, "  ").is_err());
        assert!(approve_pending(key.clone(), &alice, &pending, "AAAA-BBBB-CCCC-DDDD").is_err());
        // The code as read out (case and dashes don't matter): approved, and Mia opens it.
        let typed = code.replace('-', " ").to_lowercase();
        let approval = approve_pending(key, &alice, &pending, &typed).unwrap();
        let opened =
            pass_core::account_key_from_admin_recovery(approval, req.secret.to_string(), alice.public_keys())
                .unwrap();
        assert_eq!(opened.ak_id(), ak.ak_id());
    }

    /// A breached service swaps the one-time key in Mia's request for its own before the admin
    /// sees it: the code Mia reads out doesn't match the request the admin would approve, so
    /// nothing is sealed to the service's key.
    #[test]
    fn attack_a_swapped_request_key_is_not_approved() {
        let (alice, key, _ak, enrollment) = recovery_org();
        let mine =
            pass_core::admin_recovery_request("org_acme", "acc_mia", &enrollment.vault_id).unwrap();
        let read_out = pass_core::recovery_request_code(mine.request.clone()).unwrap();
        let theirs =
            pass_core::admin_recovery_request("org_acme", "acc_mia", &enrollment.vault_id).unwrap();
        let mut swapped = mine.request.clone();
        swapped.enc_pub = theirs.request.enc_pub.clone();
        let err = approve_pending(key.clone(), &alice, &pending_of(&swapped, &enrollment), &read_out)
            .unwrap_err();
        let core = pass_core::admin_recovery_approve(key, &alice, enrollment, swapped, &read_out)
            .unwrap_err();
        match &core {
            pass_core::PassError::Crypto(m) => {
                assert!(pass_core::core_message_is(m.clone(), "recovery.code_mismatch".into()))
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(err, pass_err(core));
    }

    #[test]
    fn a_vault_open_renews_missing_and_stale_grants_only() {
        // A linked vault the record doesn't cover yet (linked later): granted.
        assert_eq!(grant_step(true, false, None), GrantStep::Renew);
        // Covered, and the grant made here still holds its key: nothing to do.
        assert_eq!(grant_step(true, true, Some(true)), GrantStep::Keep);
        // A new vault key (a separate password, a rotation): renewed.
        assert_eq!(grant_step(true, true, Some(false)), GrantStep::Renew);
        assert_eq!(grant_step(false, true, Some(false)), GrantStep::Renew);
        // Covered by a grant another device made: left as it is.
        assert_eq!(grant_step(true, true, None), GrantStep::Keep);
        // A separate-password vault the owner didn't tick: never granted by itself.
        assert_eq!(grant_step(false, false, None), GrantStep::Keep);
        assert!(same_fingerprint("ab-cd 12", "ABCD12"));
        assert!(!same_fingerprint("", ""));
    }

    #[test]
    fn a_grant_names_the_vaults_passyble_cloud_file() {
        let entry = |url: &str, pins: bool| crate::settings::VaultEntry {
            webdav: Some(crate::settings::WebDavSettings {
                url: url.into(),
                username: "acc".into(),
                pins: if pins { vec!["sha256:x".into()] } else { Vec::new() },
                server_device: None,
            }),
            ..Default::default()
        };
        assert_eq!(cloud_name(&entry("https://cloud.example/dav/u1/personal.vault", true)).as_deref(), Some("personal"));
        assert_eq!(cloud_name(&entry("https://cloud.example/dav/u1/v-abc.vault", true)).as_deref(), Some("v-abc"));
        assert_eq!(cloud_name(&entry("https://cloud.example/dav/u1/other.vault", true)), None);
        assert_eq!(cloud_name(&entry("https://dav.example/files/personal.vault", false)), None, "plain WebDAV is no Cloud");
        assert_eq!(cloud_name(&crate::settings::VaultEntry::default()), None);
    }

    #[test]
    fn released_grants_read_every_vault_or_the_single_grant() {
        let grant = |v: &str| {
            serde_json::to_value(pass_core::EmergencyGrant {
                grant_id: format!("g-{v}"),
                vault_id: v.into(),
                owner: "acc_o".into(),
                contact: "acc_c".into(),
                contact_fingerprint: "F".into(),
                access: EmergencyAccess::View,
                wait_hours: 1,
                created_at: 1,
                key_check: "k".into(),
                blob: "b".into(),
            })
            .unwrap()
        };
        let release = json!({ "grants": [
            { "vault_id": "v1", "grant": grant("v1"), "release_secret": "s1", "download": "/x" },
            { "vault_id": "v2", "grant": grant("v2"), "release_secret": "s2", "download": null },
        ] });
        let list = released_grants(&release).unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[1].0, "v2");
        assert!(list[0].3 && !list[1].3, "only the first is on Passyble Cloud");
        // An older service: the single grant.
        let old = json!({ "grant": grant("v9"), "release_secret": "s9" });
        assert_eq!(released_grants(&old).unwrap()[0].0, "v9");
        assert!(released_grants(&json!({})).is_err());
    }

    #[test]
    fn send_options_are_clamped() {
        let o = send_options(1000, 90, 5000, Some(String::new()));
        assert_eq!(o.expires_at, 1000 + 30 * DAY_MS);
        assert_eq!(o.max_views, 1000);
        assert_eq!(o.password, None);
        let o = send_options(0, 0, 0, Some("pw".into()));
        assert_eq!(o.expires_at, DAY_MS);
        assert_eq!(o.max_views, 0);
        assert!(o.password.is_some());
    }

    #[test]
    fn an_empty_text_is_not_sent() {
        assert!(send_content(Some("  ".into()), None).is_err());
        let c = send_content(Some("hello".into()), None).unwrap();
        assert_eq!(c.kind, SendKind::Text);
        assert_eq!(c.data, b"hello");
    }

    #[test]
    fn a_sealed_send_opens_with_the_key_from_its_link() {
        let sealed = pass_core::send_seal(
            send_content(Some("the wifi password".into()), None).unwrap(),
            send_options(now_ms(), 1, 1, None),
        )
        .unwrap();
        let link =
            pass_core::send_link("https://account.example.com/s", "snd_1", &sealed.key).unwrap();
        let parsed = pass_core::send_parse_link(&link).unwrap();
        assert_eq!(parsed.send_id, "snd_1");
        let opened = pass_core::send_open(
            sealed.ciphertext.clone(),
            sealed.meta.clone(),
            parsed.key,
            None,
        )
        .unwrap();
        assert_eq!(opened.data, b"the wifi password");
        // The key travels in the fragment only, never in what the service gets.
        assert!(!sealed.meta.contains(&sealed.key));
    }
}
