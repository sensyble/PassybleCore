//! The e-mail reset and the vaults it leaves locked.
//!
//! * **Start fresh**: a fresh sign-in starts a 72-hour wait that every device and address is told
//!   about; any device holding the account key (or the recovery code) can cancel it. After the wait
//!   this PC makes a whole new key set.
//! * **Locked, from before your reset**: the old key set is locked on the service, never deleted. A
//!   vault linked to it opens with the old password and Secret Key, the old recovery code, or the
//!   old key this PC still keeps, and is then relinked under the current key.
//! * **Your account key changed**: when the key id changes without a step on this PC (a reset
//!   elsewhere, or a service faking one), this PC warns and keeps the old key set and its vaults.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use pass_core::{AccountKey, AccountPassword, PassError, SecretKey};
use serde_json::{json, Value};
use tauri::{AppHandle, Emitter};
use zeroize::Zeroizing;

use super::api::{self, CancelBy, KeyBlobs, KeyStatus, LockedSet};
use super::device::{self, Cache, OldKeySet, RecoveryCopy};
use super::{
    check_new_password, forget_held, held, hello_available, hold, keep_on_device, key_err, key_now, kit_json,
    parse_secret_key, signed_in, unlock_with, with_api, wrong_code, Res, SECRET_KEY_NEEDED,
};
use crate::commands::{app_state, blocking, pass_err};
use crate::hello;
use crate::i18n::tr;
use crate::state::AppState;
use crate::vaults::now_ms;

/// The event the windows show a key notice for (`{ kind, at?, release_at? }`).
pub const NOTICE_EVENT: &str = "account-key-notice";

fn status(app: &AppHandle) -> Res<KeyStatus> {
    with_api(app, |api, _| api::status(api))
}

/// A waiting reset as the windows read it.
pub(super) fn reset_json(cache: &Cache, s: &KeyStatus, now: i64) -> Value {
    let waiting = s.reset_waiting();
    json!({
        "waiting": waiting,
        "started_at": s.reset_started_at,
        "release_at": s.reset_release_at,
        "due": waiting && s.reset_release_at.is_some_and(|r| r <= now),
        "started_here": waiting && cache.reset_started_here.is_some() && cache.reset_started_here == s.reset_started_at,
    })
}

/// "Your account key changed on <date>": the newest key set replaced without a step here whose
/// warning wasn't dismissed.
pub(super) fn key_changed_json(cache: &Cache) -> Value {
    cache
        .old_keys
        .iter()
        .rev()
        .find(|o| !o.here && !o.dismissed)
        .map(|o| json!({ "ak_id": o.ak_id, "at": o.replaced_at }))
        .unwrap_or(Value::Null)
}

/// Where a waiting reset stands, for "Forgot your password?" and Settings.
#[tauri::command]
pub async fn account_reset_status(app: AppHandle) -> Res<Value> {
    blocking(move || {
        let state = app_state(&app);
        let me = signed_in(&app)?;
        let s = status(&app)?;
        let cache = device::load(&me.id);
        let mut out = reset_json(&cache, &s, now_ms());
        let current = s.ak_id.clone().unwrap_or_default();
        let key_here = !current.is_empty()
            && (held(&state, &me.id).is_some_and(|k| k.ak_id() == current)
                || (cache.ak_id == current && (cache.offline_ready() || hello::account_kept(&me.id).is_some())));
        out["key_here"] = json!(key_here);
        out["set"] = json!(s.set);
        Ok(out)
    })
    .await
}

/// "Start fresh": the 72-hour wait starts; every device and address is told. Needs a sign-in within
/// 10 minutes ([`super::REAUTH`]).
#[tauri::command]
pub async fn account_reset_start(app: AppHandle) -> Res<Value> {
    blocking(move || {
        let me = signed_in(&app)?;
        let (s, started_now) = match with_api(&app, |api, _| api::reset_start(api)) {
            Ok(s) => (s, true),
            // Already waiting (started here or elsewhere): show where it stands, never as this PC's own.
            Err(e) if e == tr!("account_keys.reset_already") => (status(&app)?, false),
            Err(e) => return Err(e),
        };
        let cache = device::update(&me.id, |c| c.after_reset_start(s.reset_started_at, started_now))?;
        Ok(reset_json(&cache, &s, now_ms()))
    })
    .await
}

/// "Cancel the reset": this PC's account key signs it (opened with Windows Hello or `password`,
/// [`super::PASSWORD_NEEDED`] asks for it), or the recovery code (`code`) does.
#[tauri::command]
pub async fn account_reset_cancel(app: AppHandle, password: Option<String>, code: Option<String>) -> Res<Value> {
    let password = password.map(Zeroizing::new);
    let code = code.map(Zeroizing::new);
    blocking(move || {
        let me = signed_in(&app)?;
        let answer = match code.as_deref().map(|c| c.trim()).filter(|c| !c.is_empty()) {
            Some(code) => {
                if !pass_core::recovery_code_valid_format(code.to_string()) {
                    return Err(tr!("account_keys.recovery_code_typo"));
                }
                with_api(&app, |api, _| {
                    let ch = api::recovery_challenge(api)?;
                    let sig = pass_core::account_recovery_sign(code.to_string(), me.id.clone(), ch.rec_id.clone(), ch.challenge.clone())
                        .map_err(|e| crate::teams_api::ApiError::Unexpected(pass_err(e)))?;
                    api::reset_cancel(api, CancelBy::Recovery { challenge: &ch.challenge, sig: &sig })
                })?
            }
            None => {
                let ak = key_now(&app, &me.id, password.as_deref().map(|p| p.as_str()))?;
                with_api(&app, |api, _| api::reset_cancel(api, CancelBy::Device(&ak)))?
            }
        };
        device::update(&me.id, |c| {
            c.reset_started_here = None;
            c.reset_seen = None;
        })?;
        Ok(json!({ "signed_out": answer.get("signed_out").cloned().unwrap_or(Value::Null) }))
    })
    .await
}

/// After the wait: a whole new key set made here, uploaded signed with the new key. The old set is
/// locked on the service and kept on this PC for its vaults. Returns the new Emergency Kit, with
/// `locked_ak_id` and `rejoin` (organisations to ask about admin recovery again; nothing is enrolled
/// on its own). Needs a sign-in within 10 minutes.
#[tauri::command]
pub async fn account_reset_complete(app: AppHandle, password: String) -> Res<Value> {
    let password = Zeroizing::new(password);
    blocking(move || {
        let me = signed_in(&app)?;
        check_new_password(&app, &me.email, &password)?;
        let ak = AccountKey::generate(me.id.clone()).map_err(key_err)?;
        let sk = SecretKey::generate();
        let derived = AccountPassword::with_new_salt(password.to_string(), &sk, None).map_err(key_err)?;
        let pw_wrap = ak.password_wrap(&derived).map_err(key_err)?;
        let sk_wrap = ak.secret_key_wrap(&sk).map_err(key_err)?;
        let recovery = ak.new_recovery().map_err(key_err)?;
        let body = api::setup_body(&ak, &derived, &sk_wrap, &pw_wrap, &recovery);
        // Kept before the upload (staged under the new key's id): should its answer get lost, the
        // key watch finds it once the service names the new key.
        device::keep_old_secret_key(&me.id, &ak.ak_id(), &sk)?;
        let refused = std::cell::Cell::new(false);
        let answer = match with_api(&app, |api, _| {
            api::reset_complete(api, &ak, &body).inspect_err(|e| {
                refused.set(matches!(e, crate::teams_api::ApiError::Refused { status, .. } if (400..500).contains(status)));
            })
        }) {
            Ok(a) => a,
            Err(e) => {
                // A refusal by the service (a 4xx, not a lost answer) kept the old set: the staged key opens nothing.
                if refused.get() {
                    device::forget_old_secret_key(&me.id, &ak.ak_id());
                }
                return Err(e);
            }
        };
        device::forget_old_secret_key(&me.id, &ak.ak_id());
        let old_ak_id = answer
            .pointer("/locked_key_set/ak_id")
            .and_then(Value::as_str)
            .map(str::to_string);
        let locked_at = answer
            .pointer("/locked_key_set/locked_at")
            .and_then(Value::as_i64)
            .unwrap_or_else(now_ms);
        // The Secret Key this PC had belongs to the old set: kept under its name for the old vaults.
        let cached = device::load(&me.id).ak_id;
        let old_for_sk = Some(cached).filter(|a| !a.is_empty()).or(old_ak_id.clone());
        if let Some(old) = &old_for_sk {
            device::retire_secret_key(&me.id, old);
        }
        device::update(&me.id, |c| {
            c.retire(locked_at, true);
            if let Some(old) = &old_ak_id {
                if c.old_key(old).is_none() {
                    c.old_keys.push(OldKeySet {
                        ak_id: old.clone(),
                        replaced_at: locked_at,
                        here: true,
                        dismissed: true,
                        ..Default::default()
                    });
                }
            }
            c.email = me.email.clone();
            c.take_blobs(&KeyBlobs {
                ak_id: ak.ak_id(),
                salt: derived.salt(),
                kdf: Some(derived.kdf()),
                pw_wrap: Some(pw_wrap.clone()),
                sk_wrap: Some(sk_wrap.clone()),
            });
            c.recovery = Some(RecoveryCopy {
                rec_id: recovery.rec_id.clone(),
                wrap: recovery.wrap.clone(),
            });
            c.reset_started_here = None;
            c.reset_seen = None;
        })?;
        device::keep_secret_key(&me.id, &sk)?;
        hello::account_password_used(&me.id);
        forget_held();
        hold(ak.clone());
        // The old key's Windows Hello blob moves aside now, even if the new key can't be kept.
        hello::account_set_aside(&me.id, &hello::account_binding(&me.id, &ak.ak_id()));
        let mut kit = kit_json(&me.email, &me.id, &sk, Some(recovery.code.clone()))?;
        kit["warning"] = json!(keep_on_device(&app, &ak, false));
        kit["locked_ak_id"] = json!(old_ak_id);
        // Never enrolled again on its own: the window asks the member per organisation.
        kit["rejoin"] = json!(super::admin::rejoin_asks(&app, &ak));
        Ok(kit)
    })
    .await
}

/// A linked vault of the list, as its file says: list id, name, path, key id, recovery copy.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct LocalVault {
    pub id: String,
    pub name: String,
    pub path: std::path::PathBuf,
    pub ak_id: String,
    pub recovery_copy: bool,
}

/// The vaults of the list linked to `account` (read from their files).
pub(crate) fn local_vaults(state: &AppState, account: &str) -> Vec<LocalVault> {
    let settings = state.settings();
    settings
        .vaults
        .iter()
        .filter(|v| v.linked_account.as_deref().is_none_or(|a| a == account))
        .filter_map(|v| {
            let access = pass_core::vault_file_access(std::fs::read(&v.path).ok()?).ok()?;
            (access.kind == "account" && access.account.as_deref() == Some(account)).then(|| LocalVault {
                id: v.id.clone(),
                name: v.name.clone(),
                path: v.path.clone(),
                ak_id: access.ak_id.unwrap_or_default(),
                recovery_copy: access.account_recovery,
            })
        })
        .collect()
}

/// The locked key sets as the window lists them: the service's, this PC's old keys and the key
/// ids of local vaults that aren't the current key, merged by key id (never the current one).
pub(super) fn merge_sets(
    server: &[LockedSet],
    cache: &Cache,
    vaults: &[LocalVault],
    current: Option<&str>,
    kept_here: &[String],
    secret_key_here: &dyn Fn(&str) -> bool,
) -> Vec<Value> {
    let mut ids: Vec<String> = Vec::new();
    let mut add = |id: &str| {
        if !id.is_empty() && current != Some(id) && !ids.iter().any(|i| i == id) {
            ids.push(id.to_string());
        }
    };
    server.iter().for_each(|s| add(&s.ak_id));
    cache.old_keys.iter().for_each(|o| add(&o.ak_id));
    if let Some(current) = current.filter(|c| !c.is_empty()) {
        vaults.iter().filter(|v| v.ak_id != current).for_each(|v| add(&v.ak_id));
    }
    ids.iter()
        .map(|ak_id| {
            let s = server.iter().find(|s| s.ak_id == *ak_id);
            let o = cache.old_key(ak_id);
            let mine: Vec<&LocalVault> = vaults.iter().filter(|v| v.ak_id == *ak_id).collect();
            json!({
                "id": s.map(|s| s.id.clone()),
                "ak_id": ak_id,
                "fingerprint": super::fingerprint_of(ak_id),
                "locked_at": s.map(|s| s.locked_at).or(o.map(|o| o.replaced_at)),
                "ways": {
                    "password": s.is_some_and(|s| s.password) || o.is_some_and(|o| o.pw_wrap.is_some()),
                    "recovery": s.is_some_and(|s| s.recovery.is_some())
                        || o.is_some_and(|o| o.recovery.is_some())
                        || mine.iter().any(|v| v.recovery_copy),
                    "device": kept_here.iter().any(|k| k == ak_id),
                    "secret_key_here": secret_key_here(ak_id),
                    "admins": s.map(|s| s.admin_recovery.clone()).unwrap_or_default(),
                },
                "vaults": mine.iter().map(|v| json!({ "id": v.id, "name": v.name })).collect::<Vec<_>>(),
                "can_delete": mine.is_empty(),
            })
        })
        .collect()
}

/// "Locked, from before your reset": the locked key sets with the ways each opens and the
/// vaults on this PC that need it. `offline`: the service couldn't be asked.
#[tauri::command]
pub async fn account_locked_list(app: AppHandle) -> Res<Value> {
    blocking(move || {
        let state = app_state(&app);
        let me = signed_in(&app)?;
        let cache = device::load(&me.id);
        let online = status(&app).ok();
        let server = online
            .as_ref()
            .and_then(|_| with_api(&app, |api, _| api::locked_list(api)).ok());
        let current = online
            .as_ref()
            .and_then(|s| s.ak_id.clone())
            .or(Some(cache.ak_id.clone()))
            .filter(|a| !a.is_empty());
        let vaults = local_vaults(&state, &me.id);
        let kept = hello::account_old_kept(&me.id);
        let sk_here = |ak_id: &str| device::old_secret_key(&me.id, ak_id).is_some();
        let sets = merge_sets(server.as_deref().unwrap_or_default(), &cache, &vaults, current.as_deref(), &kept, &sk_here);
        Ok(json!({ "sets": sets, "offline": server.is_none(), "hello_available": hello_available(&state) }))
    })
    .await
}

/// The service's id of the locked set of key `ak_id`.
fn locked_set_id(app: &AppHandle, ak_id: &str) -> Res<String> {
    with_api(app, |api, _| api::locked_list(api))?
        .into_iter()
        .find(|s| s.ak_id == ak_id)
        .map(|s| s.id)
        .ok_or_else(|| tr!("account_keys.locked_gone"))
}

/// The old key with its password and Secret Key: this PC's cache of that set first (offline),
/// else the service's wraps after a signature by the old sign-in key over a fresh nonce.
fn old_by_password(app: &AppHandle, account: &str, email: &str, ak_id: &str, password: &str, typed_sk: Option<&str>) -> Res<Arc<AccountKey>> {
    let sk = match typed_sk.map(str::trim).filter(|t| !t.is_empty()) {
        Some(text) => parse_secret_key(text)?,
        None => device::old_secret_key(account, ak_id)
            .and_then(|t| SecretKey::parse(t.to_string()).ok())
            .ok_or_else(|| SECRET_KEY_NEEDED.to_string())?,
    };
    let cache = device::load(account);
    if let Some(old) = cache.old_key(ak_id).filter(|o| !o.salt.is_empty() && o.kdf.is_some()) {
        if let Some(wrap) = old.pw_wrap.clone() {
            let derived = AccountPassword::new(password.to_string(), &sk, old.salt.clone(), old.kdf.clone().unwrap_or_default())
                .map_err(key_err)?;
            match derived.open_account_key(account.into(), ak_id.into(), wrap) {
                Ok(ak) => return Ok(ak),
                // The service may know better (a password changed before the reset).
                Err(PassError::InvalidPassword) => {}
                Err(e) => return Err(key_err(e)),
            }
        }
    }
    let set = locked_set_id(app, ak_id)?;
    let email = api::normalize_email(email);
    let opened = with_api(app, |api, _| {
        let n = api::locked_nonce(api, &set)?;
        let derived = AccountPassword::new(password.to_string(), &sk, n.salt.clone(), n.kdf.clone().unwrap_or_default())
            .map_err(|e| crate::teams_api::ApiError::Unexpected(key_err(e)))?;
        let sig = derived
            .sign_in(email.clone(), n.nonce.clone(), String::new(), String::new())
            .map_err(|e| crate::teams_api::ApiError::Unexpected(key_err(e)))?;
        api::locked_open(api, &set, "password", &n.nonce, &sig).map(|o| (o, derived))
    });
    let (opened, derived) = opened?;
    let wrap = opened.pw_wrap.ok_or_else(|| tr!("errors.teams_unexpected_answer"))?;
    let ak = derived.open_account_key(account.into(), ak_id.into(), wrap).map_err(key_err)?;
    // The old Secret Key was right: kept for the other vaults of that set.
    if typed_sk.is_some() {
        let _ = device::keep_old_secret_key(account, ak_id, &sk);
    }
    Ok(ak)
}

/// The old key with its recovery code: a vault of that set on this PC (its header's copy), this
/// PC's cached copy, else the service's wrap after the code signed a fresh nonce.
fn old_by_recovery(app: &AppHandle, account: &str, ak_id: &str, code: &str, vaults: &[LocalVault]) -> Res<Arc<AccountKey>> {
    if !pass_core::recovery_code_valid_format(code.to_string()) {
        return Err(tr!("account_keys.recovery_code_typo"));
    }
    for v in vaults.iter().filter(|v| v.ak_id == ak_id && v.recovery_copy) {
        let Ok(bytes) = std::fs::read(&v.path) else { continue };
        if let Ok(ak) = pass_core::account_key_from_vault_file(bytes, code.to_string()) {
            if ak.ak_id() == ak_id && ak.account() == account {
                return Ok(ak);
            }
        }
    }
    if let Some(copy) = device::load(account).old_key(ak_id).and_then(|o| o.recovery.clone()) {
        if let Ok(ak) = pass_core::account_key_open_recovery(account.into(), ak_id.into(), code.to_string(), copy.rec_id, copy.wrap) {
            return Ok(ak);
        }
    }
    let set = locked_set_id(app, ak_id)?;
    let (opened, rec_id) = with_api(app, |api, _| {
        let n = api::locked_nonce(api, &set)?;
        let rec_id = n
            .rec_id
            .clone()
            .ok_or_else(|| crate::teams_api::ApiError::Unexpected(tr!("account_keys.no_recovery_code")))?;
        let sig = pass_core::account_recovery_sign(code.to_string(), account.into(), rec_id.clone(), n.nonce.clone())
            .map_err(|e| crate::teams_api::ApiError::Unexpected(pass_err(e)))?;
        api::locked_open(api, &set, "recovery", &n.nonce, &sig).map(|o| (o, rec_id))
    })?;
    let wrap = opened.wrap.ok_or_else(|| tr!("errors.teams_unexpected_answer"))?;
    pass_core::account_key_open_recovery(account.into(), ak_id.into(), code.to_string(), opened.rec_id.unwrap_or(rec_id), wrap)
        .map_err(wrong_code)
}

/// The old key this PC still keeps, after Windows Hello.
pub(super) fn old_by_device(state: &AppState, account: &str, ak_id: &str) -> Res<Arc<AccountKey>> {
    let _one = state.ui.hello_lock();
    let raw = hello::account_open_old(account, ak_id, state.ui.main_owner()).map_err(|f| f.message)?;
    AccountKey::from_bytes(account.into(), raw.to_vec(), ak_id.into()).map_err(key_err)
}

/// Relinks every vault of the list linked to `old` under `current` (with the current recovery
/// copy): the unlocked active vault through the agent, the others' files directly. A locked
/// active vault among them opens. Returns how many were relinked and the names of those that
/// didn't open with `old`.
pub(super) fn relink(app: &AppHandle, old: &AccountKey, current: &Arc<AccountKey>) -> (usize, Vec<String>) {
    let state = app_state(app);
    let account = current.account();
    let copy = device::load(&account).recovery;
    let device_id = state.settings().device_id;
    let active = state.settings().active_vault.clone();
    let mut done = 0;
    let mut failed = Vec::new();
    let mut open_active = None;
    for v in local_vaults(&state, &account).into_iter().filter(|v| v.ak_id == old.ak_id()) {
        let is_active = active.as_deref() == Some(v.id.as_str());
        let agent = state.agent().filter(|a| is_active && !a.is_locked());
        let result = match agent.as_ref().and_then(|a| a.peek_vault().map(|vault| (a.clone(), vault))) {
            Some((agent, vault)) => vault
                .link_to_account(current)
                .and_then(|_| {
                    if let Some(c) = &copy {
                        let _ = vault.set_account_recovery(c.rec_id.clone(), c.wrap.clone());
                    }
                    agent.save()
                })
                .map_err(pass_err),
            None => std::fs::read(&v.path)
                .map_err(crate::errors::file_not_read)
                .and_then(|bytes| pass_core::Vault::unlock_with_account_key(bytes, old, device_id.clone()).map_err(pass_err))
                .and_then(|vault| {
                    vault.link_to_account(current).map_err(pass_err)?;
                    if let Some(c) = &copy {
                        let _ = vault.set_account_recovery(c.rec_id.clone(), c.wrap.clone());
                    }
                    crate::vaults::write_vault_file(&v.path, &vault)
                }),
        };
        match result {
            Ok(()) => {
                done += 1;
                if is_active && state.agent().is_some_and(|a| a.is_locked()) {
                    open_active = Some(v.id.clone());
                }
            }
            Err(e) => {
                crate::applog::plog!("account keys: a locked vault was not relinked: {e}");
                failed.push(v.name.clone());
            }
        }
    }
    if let Some(id) = open_active {
        let _ = unlock_with(app, &id, current);
    }
    (done, failed)
}

/// "Unlock" a locked key set (`ak_id`): opens the old key `by` its `password`, its `recovery` code or
/// this PC's kept key (`device`), then relinks every vault of that set on this PC under the current
/// key. `{ relinked, failed, can_delete }`.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn account_locked_unlock(
    app: AppHandle,
    ak_id: String,
    by: String,
    old_password: Option<String>,
    old_secret_key: Option<String>,
    code: Option<String>,
    password: Option<String>,
) -> Res<Value> {
    let old_password = old_password.map(Zeroizing::new);
    let old_secret_key = old_secret_key.map(Zeroizing::new);
    let code = code.map(Zeroizing::new);
    let password = password.map(Zeroizing::new);
    blocking(move || {
        let state = app_state(&app);
        let me = signed_in(&app)?;
        // The current key first: relinking needs it, and asking for it after the old secrets
        // would make the user type those twice.
        let current = key_now(&app, &me.id, password.as_deref().map(|p| p.as_str()))?;
        if current.ak_id() == ak_id {
            return Err(tr!("account_keys.locked_is_current"));
        }
        let vaults = local_vaults(&state, &me.id);
        let old = match by.as_str() {
            "password" => {
                let pw = old_password.as_deref().map(|p| p.as_str()).filter(|p| !p.is_empty());
                let pw = pw.ok_or_else(|| tr!("unlock.enter_password"))?;
                old_by_password(&app, &me.id, &me.email, &ak_id, pw, old_secret_key.as_deref().map(|s| s.as_str()))?
            }
            "recovery" => {
                let code = code.as_deref().map(|c| c.trim()).filter(|c| !c.is_empty());
                old_by_recovery(&app, &me.id, &ak_id, code.ok_or_else(|| tr!("account_keys.enter_recovery_code"))?, &vaults)?
            }
            _ => old_by_device(&state, &me.id, &ak_id)?,
        };
        if old.ak_id() != ak_id {
            return Err(tr!("account_keys.other_key"));
        }
        let (relinked, failed) = relink(&app, &old, &current);
        let left = local_vaults(&state, &me.id).iter().filter(|v| v.ak_id == ak_id).count();
        Ok(json!({ "relinked": relinked, "failed": failed, "can_delete": left == 0 }))
    })
    .await
}

/// Deletes a locked key set the user is done with: on the service (signed with the current key)
/// and on this PC (its cache, Secret Key and Windows Hello blob). Refused while a vault on this PC
/// still needs it.
#[tauri::command]
pub async fn account_locked_delete(app: AppHandle, ak_id: String, password: Option<String>) -> Res<Value> {
    let password = password.map(Zeroizing::new);
    blocking(move || {
        let state = app_state(&app);
        let me = signed_in(&app)?;
        let needed = local_vaults(&state, &me.id).iter().filter(|v| v.ak_id == ak_id).count();
        if needed > 0 {
            return Err(crate::i18n::trn!("account_keys.locked_still_needed", needed));
        }
        let server = with_api(&app, |api, _| api::locked_list(api))?;
        if let Some(set) = server.iter().find(|s| s.ak_id == ak_id) {
            let current = key_now(&app, &me.id, password.as_deref().map(|p| p.as_str()))?;
            with_api(&app, |api, _| api::locked_delete(api, &current, &set.id))?;
        }
        hello::account_forget_old(&me.id, &ak_id);
        device::forget_old_secret_key(&me.id, &ak_id);
        device::update(&me.id, |c| c.old_keys.retain(|o| o.ak_id != ak_id))?;
        Ok(json!({}))
    })
    .await
}

/// "Got it" on "Your account key changed on <date>".
#[tauri::command]
pub async fn account_key_notice_dismiss(app: AppHandle, ak_id: String) -> Res<Value> {
    blocking(move || {
        let me = signed_in(&app)?;
        device::update(&me.id, |c| {
            for o in c.old_keys.iter_mut().filter(|o| o.ak_id == ak_id) {
                o.dismissed = true;
            }
        })?;
        Ok(json!({}))
    })
    .await
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Notice {
    /// An e-mail reset another device started is waiting (release time).
    ResetStarted(Option<i64>),
    /// The reset this PC warned about was cancelled.
    ResetCancelled,
    /// The account's key changed without a step here (the old key id).
    KeyChanged(String),
}

/// The notices for this PC's `cache` and the service's `status` (pure, tested).
pub fn notices(cache: &Cache, status: &KeyStatus) -> Vec<Notice> {
    let mut out = Vec::new();
    if !status.set {
        return out;
    }
    let current = status.ak_id.as_deref().unwrap_or_default();
    if !cache.ak_id.is_empty() && !current.is_empty() && current != cache.ak_id {
        out.push(Notice::KeyChanged(cache.ak_id.clone()));
    }
    if status.reset_waiting() {
        let started = status.reset_started_at;
        if cache.reset_seen != started && (cache.reset_started_here.is_none() || cache.reset_started_here != started) {
            out.push(Notice::ResetStarted(status.reset_release_at));
        }
    } else if cache.reset_seen.is_some() && out.is_empty() {
        out.push(Notice::ResetCancelled);
    }
    out
}

/// The push texts, as the tray and the windows show them.
fn push_text(what: &str) -> String {
    let body = match what {
        "started" => tr!("account_keys.push_account_key_reset_started_body"),
        "cancelled" => tr!("account_keys.push_account_key_reset_cancelled_body"),
        _ => tr!("account_keys.push_account_key_reset_done_body"),
    };
    format!("{}: {body}", tr!("account_keys.push_account_key_reset_title"))
}

static LAST_WATCH: Mutex<Option<Instant>> = Mutex::new(None);

/// Asks the service about the account's key in the background (after an unlock), at most once a
/// minute: warns about a reset another device started, a cancelled one, or a changed key.
pub fn watch_soon(app: &AppHandle) {
    {
        let mut last = LAST_WATCH.lock().unwrap_or_else(|p| p.into_inner());
        if last.is_some_and(|t| t.elapsed() < Duration::from_secs(60)) {
            return;
        }
        *last = Some(Instant::now());
    }
    let app = app.clone();
    let _ = std::thread::Builder::new()
        .name("pass-account-key-watch".into())
        .spawn(move || {
            if let Err(e) = watch(&app) {
                crate::applog::plog!("account keys: the key check didn't run: {e}");
            }
        });
}

fn watch(app: &AppHandle) -> Res<()> {
    let Some(me) = crate::account::signed_in(app) else {
        return Ok(());
    };
    let s = status(app)?;
    let cache = device::load(&me.id);
    let current = s.ak_id.clone().unwrap_or_default();
    let found = notices(&cache, &s);
    // The date of a changed key: when the service locked the old set.
    let changed_at = found.iter().find_map(|n| match n {
        Notice::KeyChanged(old) => Some(
            with_api(app, |api, _| api::locked_list(api))
                .ok()
                .and_then(|l| l.into_iter().find(|l| l.ak_id == *old).map(|l| l.locked_at))
                .unwrap_or_else(now_ms),
        ),
        _ => None,
    });
    let mut staged_from: Option<String> = None;
    for notice in &found {
        if let Notice::KeyChanged(old) = notice {
            device::retire_secret_key(&me.id, old);
            // A reset finished here whose answer got lost: its Secret Key was staged under the new id.
            if device::promote_staged_secret_key(&me.id, &current) {
                staged_from = Some(old.clone());
            }
            hello::account_set_aside(&me.id, &hello::account_binding(&me.id, &current));
            // The key in memory is the old one: Settings steps must not sign with it.
            forget_held();
        }
    }
    // Applied to the cache as it is now (another thread may have changed it meanwhile).
    if !found.is_empty() {
        device::update(&me.id, |c| {
            for notice in &found {
                match notice {
                    Notice::ResetStarted(_) => c.reset_seen = s.reset_started_at,
                    Notice::ResetCancelled => {
                        c.reset_seen = None;
                        c.reset_started_here = None;
                    }
                    Notice::KeyChanged(old) => {
                        if c.ak_id == *old {
                            c.retire(changed_at.unwrap_or_else(now_ms), false);
                        }
                        c.reset_seen = None;
                        c.reset_started_here = None;
                        if staged_from.as_deref() == Some(old.as_str()) {
                            c.after_staged_reset(old);
                        }
                    }
                }
            }
        })?;
    }
    for notice in found {
        match notice {
            Notice::ResetStarted(release_at) => {
                crate::tray::notify(app, &push_text("started"));
                let _ = app.emit(NOTICE_EVENT, json!({ "kind": "reset_started", "release_at": release_at }));
            }
            Notice::ResetCancelled => crate::tray::notify(app, &push_text("cancelled")),
            Notice::KeyChanged(old) => {
                crate::tray::notify(app, &push_text("done"));
                let _ = app.emit(
                    NOTICE_EVENT,
                    json!({ "kind": "key_changed", "at": changed_at, "ak_id": old }),
                );
            }
        }
    }
    super::admin::check_required(app);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(ak_id: &str, state: &str, started: Option<i64>) -> KeyStatus {
        KeyStatus {
            set: true,
            ak_id: Some(ak_id.into()),
            state: Some(state.into()),
            reset_started_at: started,
            reset_release_at: started.map(|s| s + 72 * 3_600_000),
            ..Default::default()
        }
    }

    fn cache(ak_id: &str) -> Cache {
        Cache {
            account: "acc_demo".into(),
            ak_id: ak_id.into(),
            ..Default::default()
        }
    }

    #[test]
    fn a_reset_started_elsewhere_warns_once_and_its_cancel_is_told() {
        let mut c = cache("AK1");
        assert!(notices(&c, &status("AK1", "active", None)).is_empty());
        let waiting = status("AK1", "reset_waiting", Some(100));
        assert_eq!(notices(&c, &waiting), [Notice::ResetStarted(Some(100 + 72 * 3_600_000))]);
        c.reset_seen = Some(100);
        assert!(notices(&c, &waiting).is_empty(), "told once");
        assert_eq!(notices(&c, &status("AK1", "active", None)), [Notice::ResetCancelled]);
        // The reset this PC started needs no warning.
        let mut mine = cache("AK1");
        mine.reset_started_here = Some(100);
        assert!(notices(&mine, &waiting).is_empty());
    }

    #[test]
    fn a_key_changed_without_a_step_here_is_a_notice() {
        let c = cache("OLD");
        assert_eq!(notices(&c, &status("NEW", "active", None)), [Notice::KeyChanged("OLD".into())]);
        // A PC that never had the key, or an account without keys, says nothing.
        assert!(notices(&cache(""), &status("NEW", "active", None)).is_empty());
        let unset = KeyStatus::default();
        assert!(notices(&c, &unset).is_empty());
        // A finished reset this PC had warned about is a key change, not a cancel.
        let mut seen = cache("OLD");
        seen.reset_seen = Some(5);
        assert_eq!(notices(&seen, &status("NEW", "active", None)), [Notice::KeyChanged("OLD".into())]);
    }

    #[test]
    fn locked_sets_merge_the_service_this_pc_and_the_vaults_by_key() {
        let mut c = cache("NEW");
        c.old_keys.push(OldKeySet { ak_id: "OLD".into(), replaced_at: 7, ..Default::default() });
        let server = vec![LockedSet {
            id: "lks_1".into(),
            ak_id: "OLD".into(),
            locked_at: 5,
            password: true,
            admin_recovery: vec!["g1".into()],
            ..Default::default()
        }];
        let vault = |id: &str, ak: &str| LocalVault {
            id: id.into(),
            name: format!("Vault {id}"),
            path: std::path::PathBuf::from(format!("{id}.vault")),
            ak_id: ak.into(),
            recovery_copy: true,
        };
        let vaults = vec![vault("v1", "OLD"), vault("v2", "NEW"), vault("v3", "OLDER")];
        let sk = |ak: &str| ak == "OLD";
        let sets = merge_sets(&server, &c, &vaults, Some("NEW"), &["OLDER".to_string()], &sk);
        assert_eq!(sets.len(), 2, "never the current key");
        assert_eq!(sets[0]["id"], "lks_1");
        assert_eq!(sets[0]["locked_at"], 5, "the service's time wins");
        assert_eq!(sets[0]["ways"]["password"], true);
        assert_eq!(sets[0]["ways"]["secret_key_here"], true);
        assert_eq!(sets[0]["ways"]["admins"][0], "g1");
        assert_eq!(sets[0]["vaults"][0]["id"], "v1");
        assert_eq!(sets[0]["can_delete"], false);
        assert_eq!(sets[1]["ak_id"], "OLDER");
        assert!(sets[1]["id"].is_null());
        assert_eq!(sets[1]["ways"]["device"], true);
        assert_eq!(sets[1]["ways"]["recovery"], true, "the vault's header copy");
        // Without the current key known, the vaults alone say nothing.
        assert_eq!(merge_sets(&[], &cache(""), &vaults, None, &[], &sk).len(), 0);
    }

    #[test]
    fn the_reset_and_key_change_read_for_the_windows() {
        let mut c = cache("AK1");
        let s = status("AK1", "reset_waiting", Some(100));
        let r = reset_json(&c, &s, 100);
        assert_eq!(r["waiting"], true);
        assert_eq!(r["due"], false);
        assert_eq!(r["started_here"], false);
        c.reset_started_here = Some(100);
        assert_eq!(reset_json(&c, &s, 100 + 72 * 3_600_000)["due"], true);
        assert_eq!(reset_json(&c, &s, 0)["started_here"], true);
        assert!(key_changed_json(&c).is_null());
        c.old_keys.push(OldKeySet { ak_id: "A0".into(), replaced_at: 9, ..Default::default() });
        assert_eq!(key_changed_json(&c)["at"], 9);
        c.old_keys[0].dismissed = true;
        assert!(key_changed_json(&c).is_null());
    }

    #[test]
    fn push_texts_name_the_step() {
        assert!(push_text("started").contains(&tr!("account_keys.push_account_key_reset_started_body")));
        assert!(push_text("done").starts_with(&tr!("account_keys.push_account_key_reset_title")));
    }

    #[test]
    fn a_reset_already_waiting_is_never_marked_as_this_pcs_own() {
        let waiting = status("AK1", "reset_waiting", Some(100));
        let mut other = cache("AK1");
        other.after_reset_start(Some(100), false);
        assert_eq!(other.reset_started_here, None);
        assert_eq!(reset_json(&other, &waiting, 0)["started_here"], false);
        assert_eq!(notices(&other, &waiting).len(), 1, "the warning stays");
        let mut mine = cache("AK1");
        mine.after_reset_start(Some(100), true);
        assert_eq!(mine.reset_started_here, Some(100));
        assert_eq!(reset_json(&mine, &waiting, 0)["started_here"], true);
        assert!(notices(&mine, &waiting).is_empty());
        // Another start time than the recorded one is not this PC's.
        assert_eq!(reset_json(&mine, &status("AK1", "reset_waiting", Some(200)), 0)["started_here"], false);
    }

    #[test]
    fn a_staged_secret_key_of_a_lost_reset_answer_becomes_the_current_one() {
        let account = "acc_staged_demo";
        let sk = SecretKey::generate();
        let old = SecretKey::generate();
        device::keep_secret_key(account, &old).unwrap();
        device::retire_secret_key(account, "AK1");
        device::keep_old_secret_key(account, "AK2", &sk).unwrap(); // staged before the upload
        assert!(device::promote_staged_secret_key(account, "AK2"));
        assert_eq!(device::secret_key(account).unwrap().to_string(), sk.text());
        assert!(device::old_secret_key(account, "AK2").is_none());
        assert_eq!(device::old_secret_key(account, "AK1").unwrap().to_string(), old.text());
        assert!(!device::promote_staged_secret_key(account, "AK3"), "nothing staged");
        let mut c = cache("AK1");
        c.retire(5, false);
        c.after_staged_reset("AK1");
        let o = c.old_key("AK1").unwrap();
        assert!(o.here && o.dismissed);
    }
}
