//! Admin recovery of the account key: a member of a Team or a Family seals the **account key** (not a
//! vault key) to the organisation's recovery key, enrolment `vault_id = "ak:" + ak_id`.
//!
//! * **Opt in**: every admin can then open every linked vault. A Team may require it, and then it
//!   can't be withdrawn.
//! * **Forgot the password**: the request's one-time secret stays in Credential Manager until an
//!   admin approved; the approval opens the account key here, and the member picks a new password
//!   and gets a new Secret Key (the admin never learns either). A request answers a `code` the
//!   member reads out to the admin, who types it to approve.
//! * **After the key changed**: never enrolled again on its own; the member is asked per
//!   organisation ([`rejoin_asks`]).
//! * **Compare first**: the account key is wrapped only to a recovery key made by an admin the
//!   member compared and pinned in the home vault (docs/ARCHITECTURE.md §15.16).

use pass_core::{AccountKey, OrgKind, SecretKey};
use serde_json::{json, Value};
use tauri::{AppHandle, Emitter};
use zeroize::Zeroizing;

use super::api;
use super::device;
use crate::contact_pins::{self, ToCompare};
use super::{
    check_new_password, hold, keep_on_device, key_now, kit_json, open_active_if_linked, put_password, signed_in,
    with_api, Res,
};
use crate::commands::{app_state, blocking, pass_err};
use crate::i18n::tr;

/// The `vault_id` of an account key enrolment.
pub fn enrolment_id(ak_id: &str) -> String {
    format!("ak:{ak_id}")
}

/// The account key id an enrolment's `vault_id` names.
pub fn enrolled_ak_id(vault_id: &str) -> Option<&str> {
    vault_id.strip_prefix("ak:").filter(|a| !a.is_empty())
}

/// The Teams and Families of the signed-in account: `(id, name, kind)`.
fn orgs(app: &AppHandle) -> Vec<(String, String, String)> {
    app_state(app)
        .settings()
        .teams
        .map(|t| t.orgs)
        .unwrap_or_default()
        .into_iter()
        .filter(|o| o.kind == "team" || o.kind == "family")
        .map(|o| (o.id, o.name, o.kind))
        .collect()
}

fn org_kind(app: &AppHandle, org: &str) -> Res<OrgKind> {
    match orgs(app).into_iter().find(|(id, _, _)| id == org) {
        Some((_, _, kind)) if kind == "family" => Ok(OrgKind::Family),
        Some(_) => Ok(OrgKind::Team),
        None => Err(tr!("errors.teams_not_in_org")),
    }
}

/// The account's current key id: the service's, else this PC's cache.
fn current_ak_id(app: &AppHandle, account: &str) -> String {
    with_api(app, |api, _| api::status(api))
        .ok()
        .and_then(|s| s.ak_id)
        .unwrap_or_else(|| device::load(account).ak_id)
}

/// What one organisation's recovery overview says about this member's account key.
pub fn org_row(org: &str, name: &str, kind: &str, info: &Value, current: &str) -> Value {
    let enrolled = info
        .pointer("/enrollment/vault_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let mine = !current.is_empty() && enrolled == enrolment_id(current);
    let locked: Vec<Value> = info
        .get("locked_enrollments")
        .and_then(Value::as_array)
        .map(|l| {
            l.iter()
                .map(|e| json!({ "vault_id": e.get("vault_id"), "ak_id": e.get("ak_id"), "locked_at": e.get("locked_at") }))
                .collect()
        })
        .unwrap_or_default();
    json!({
        "org": org,
        "name": name,
        "kind": kind,
        "available": info.get("enabled").and_then(Value::as_bool).unwrap_or(false)
            && info.get("key").is_some_and(|k| !k.is_null()),
        "required": info.get("required").and_then(Value::as_bool).unwrap_or(false),
        "enrolled": mine,
        "enrolled_at": if mine { info.pointer("/enrollment/created_at").cloned() } else { None },
        // Enrolled with a vault key or another account key: enrol the current key again.
        "enrol_again": !enrolled.is_empty() && !mine,
        "enrolment": Some(enrolled).filter(|e| !e.is_empty()),
        "locked": locked,
        "requests": info.get("requests").cloned().unwrap_or(json!([])),
    })
}

/// Per Team and Family: whether the account key is enrolled for admin recovery, may be, must be, or
/// was enrolled with an older key, and the admin who made the recovery key.
#[tauri::command]
pub async fn account_admin_recovery_status(app: AppHandle) -> Res<Value> {
    blocking(move || {
        let me = signed_in(&app)?;
        let current = current_ak_id(&app, &me.id);
        let rows: Vec<Value> = orgs(&app)
            .into_iter()
            .map(|(id, name, kind)| {
                let info = crate::account::with_api(&app, |api, _| api.recovery(&id)).unwrap_or_default();
                let mut row = org_row(&id, &name, &kind, &info, &current);
                if row["available"] == true {
                    if let Ok(admin) = admin_of(&app, &id, &info) {
                        put_admin(&mut row, &admin);
                    }
                }
                row
            })
            .collect();
        Ok(json!({ "has_keys": !current.is_empty(), "ak_id": current, "orgs": rows }))
    })
    .await
}

/// The admin who made `org`'s recovery key (`info`: its recovery overview): account, fingerprint
/// of their published keys, and what the pins in the home vault say (none while locked).
struct Admin {
    account: String,
    fingerprint: String,
    pin: Option<&'static str>,
}

fn admin_of(app: &AppHandle, org: &str, info: &Value) -> Res<Admin> {
    let (key, creator) = recovery_key(app, org, info)?;
    let pin = app_state(app)
        .quiet_vault()
        .ok()
        .map(|home| contact_pins::status_words(&contact_pins::status_of(&home, &creator)).0);
    Ok(Admin {
        account: key.created_by,
        fingerprint: pass_core::public_keys_fingerprint(creator),
        pin,
    })
}

fn put_admin(row: &mut Value, admin: &Admin) {
    row["admin"] = json!(admin.account);
    row["admin_fingerprint"] = json!(admin.fingerprint);
    row["admin_pin"] = json!(admin.pin);
}

/// Whether, after the account key changed, `row` ([`org_row`] for the new key) is an
/// organisation to ask the member about: recovery offered, the new key not enrolled, and the old
/// key (or a vault) was enrolled or the Team requires it.
pub fn rejoin_wanted(row: &Value) -> bool {
    let had = row["enrol_again"] == true || row["locked"].as_array().is_some_and(|l| !l.is_empty());
    row["available"] == true && row["enrolled"] != true && (had || row["required"] == true)
}

/// The organisation's current recovery key, checked against its creator's published keys.
fn recovery_key(app: &AppHandle, org: &str, info: &Value) -> Res<(pass_core::OrgRecoveryKey, pass_core::PublicKeys)> {
    let key: pass_core::OrgRecoveryKey = serde_json::from_value(info.get("key").cloned().unwrap_or_default())
        .map_err(|_| tr!("errors.admin_recovery_not_offered"))?;
    let creator = crate::teams_send::org_keys(app, org, &key.created_by)?;
    Ok((key, creator))
}

/// An enrolment with a creator the member pinned, ready to wrap the account key.
struct Ready {
    kind: OrgKind,
    key: pass_core::OrgRecoveryKey,
    creator: pass_core::PublicKeys,
    home: std::sync::Arc<pass_core::Vault>,
}

/// `org`'s recovery key and its creator, once the member pinned the creator in the home vault
/// (`compared`: the fingerprint the member just compared with that admin, pinned first and
/// saved). `Err` of the outer result: something failed; `Ok(Err)`: the admin to compare first.
fn ready(app: &AppHandle, org: &str, compared: Option<&str>) -> Res<Result<Ready, ToCompare>> {
    let kind = org_kind(app, org)?;
    let info = with_api(app, |api, _| api.recovery(org))?;
    let (key, creator) = recovery_key(app, org, &info)?;
    let state = app_state(app);
    let home = state.quiet_vault()?;
    let mut pinned = false;
    let compare = contact_pins::check(&home, &creator, compared, &mut pinned)?;
    if pinned {
        state.require_agent()?.save().map_err(pass_err)?;
    }
    Ok(match compare {
        Some(c) => Err(c),
        None => Ok(Ready { kind, key, creator, home }),
    })
}

/// Enrols `ak` with the recovery key of `ready` (the core checks the creator's signature and
/// pin again).
fn enrol(app: &AppHandle, org: &str, ak: &AccountKey, ready: Ready) -> Res<()> {
    let enrollment = ak
        .admin_recovery_enroll(ready.key, ready.creator, ready.kind, &ready.home)
        .map_err(pass_err)?;
    with_api(app, |api, _| api.recovery_enroll(org, &enrollment))?;
    Ok(())
}

/// Opts the account key in to `org`'s admin recovery (after the window's warning), or enrols the
/// current key again. First the admin who made the recovery key must be pinned: `{
/// needs_compare }` (their fingerprint) until the member compared it with them and calls again
/// with `fingerprint`. Then needs the key ([`super::PASSWORD_NEEDED`]) and a fresh sign-in
/// ([`super::REAUTH`]).
#[tauri::command]
pub async fn account_admin_recovery_enroll(
    app: AppHandle,
    org: String,
    password: Option<String>,
    fingerprint: Option<String>,
) -> Res<Value> {
    let password = password.map(Zeroizing::new);
    blocking(move || {
        let me = signed_in(&app)?;
        let ready = match ready(&app, &org, fingerprint.as_deref())? {
            Ok(r) => r,
            Err(c) => return Ok(json!({ "needs_compare": c })),
        };
        let ak = key_now(&app, &me.id, password.as_deref().map(|p| p.as_str()))?;
        enrol(&app, &org, &ak, ready)?;
        Ok(json!({}))
    })
    .await
}

/// Withdraws the account key's enrolment (or, with `vault_id`, one locked enrolment the member is
/// done with). A Team that requires it refuses the current one.
#[tauri::command]
pub async fn account_admin_recovery_withdraw(app: AppHandle, org: String, vault_id: Option<String>) -> Res<Value> {
    blocking(move || {
        with_api(&app, |api, _| api.recovery_withdraw_one(&org, vault_id.as_deref()))?;
        Ok(json!({}))
    })
    .await
}

/// "Ask your admin" (works while locked): a request naming the account key's enrolment with
/// `org` (`vault_id`: a locked key's enrolment, else the current one). The one-time secret stays
/// in Credential Manager until the approval is used.
#[tauri::command]
pub async fn account_admin_recovery_request(app: AppHandle, org: String, vault_id: Option<String>) -> Res<Value> {
    blocking(move || {
        let me = signed_in(&app)?;
        let enrolment = match vault_id.filter(|v| enrolled_ak_id(v).is_some()) {
            Some(v) => v,
            None => {
                let info = with_api(&app, |api, _| api.recovery(&org))?;
                info.pointer("/enrollment/vault_id")
                    .and_then(Value::as_str)
                    .filter(|v| enrolled_ak_id(v).is_some())
                    .ok_or_else(|| tr!("errors.admin_recovery_not_enrolled"))?
                    .to_string()
            }
        };
        let request = pass_core::admin_recovery_request(&org, &me.id, &enrolment).map_err(pass_err)?;
        let name = crate::teams_send::secret_name(&request.request.request_id);
        crate::account::store().set(&name, &request.secret)?;
        if let Err(e) = with_api(&app, |api, _| api.recovery_request(&org, &request.request)) {
            crate::account::store().delete(&name);
            return Err(e);
        }
        // The code the member reads out to the admin: from the request made here.
        let code = pass_core::recovery_request_code(request.request.clone()).map_err(pass_err)?;
        Ok(json!({ "request_id": request.request.request_id, "org": org, "vault_id": enrolment, "code": code }))
    })
    .await
}

/// What to do with an account key opened from an admin's approval, by the member's check against
/// the fingerprint in Settings on another device (a service that sealed its own key shows another).
#[derive(Debug, PartialEq, Eq)]
enum KeyCheck {
    /// Not checked yet: show this fingerprint.
    Ask(String),
    /// The member said it doesn't match, or the key isn't the one they checked: never used.
    Drop,
    /// The member checked this very key.
    Go,
}

fn key_check(opened: &str, confirmed: Option<&str>, matches: Option<bool>) -> KeyCheck {
    match (matches, confirmed) {
        (Some(false), _) => KeyCheck::Drop,
        (Some(true), Some(c)) if contact_pins::same_fingerprint(c, opened) => KeyCheck::Go,
        (Some(true), Some(_)) => KeyCheck::Drop,
        _ => KeyCheck::Ask(opened.to_string()),
    }
}

/// After an admin approved: the account key from the approval. First `{ state: "check",
/// fingerprint }` and nothing done: the member compares it with another device and calls again with
/// `fingerprint` and `matches` (false drops the key and the request's secret). Then the current key
/// gets `new_password` and a new Secret Key, or a locked key's vaults are relinked.
#[tauri::command]
pub async fn account_admin_recovery_finish(
    app: AppHandle,
    org: String,
    request_id: String,
    new_password: Option<String>,
    password: Option<String>,
    fingerprint: Option<String>,
    matches: Option<bool>,
) -> Res<Value> {
    let new_password = new_password.map(Zeroizing::new);
    let password = password.map(Zeroizing::new);
    blocking(move || {
        let me = signed_in(&app)?;
        let status = with_api(&app, |api, _| api.recovery_request_status(&org, &request_id))?;
        let approval: pass_core::RecoveryApproval = match status.get("approval").filter(|a| !a.is_null()) {
            Some(a) => serde_json::from_value(a.clone()).map_err(|_| tr!("errors.teams_unexpected_answer"))?,
            None => return Err(tr!("errors.admin_recovery_waiting")),
        };
        let approver = crate::teams_send::org_keys(&app, &org, &approval.approved_by)?;
        let secret_name = crate::teams_send::secret_name(&request_id);
        let secret = crate::account::store()
            .get(&secret_name)
            .ok_or_else(|| tr!("errors.admin_recovery_other_pc"))?;
        let ak = pass_core::account_key_from_admin_recovery(approval.clone(), secret.to_string(), approver.clone())
            .map_err(pass_err)?;
        if ak.account() != me.id {
            return Err(tr!("account_keys.other_account"));
        }
        match key_check(&ak.fingerprint(), fingerprint.as_deref(), matches) {
            KeyCheck::Ask(fingerprint) => return Ok(json!({ "state": "check", "fingerprint": fingerprint })),
            KeyCheck::Drop => {
                crate::account::store().delete(&secret_name);
                crate::applog::plog!("admin recovery: the key's fingerprint didn't match, dropped");
                return Ok(json!({ "state": "dropped" }));
            }
            KeyCheck::Go => {}
        }
        let current = current_ak_id(&app, &me.id);
        let mut out = if ak.ak_id() == current {
            let new_password = new_password
                .as_deref()
                .map(|p| p.as_str())
                .filter(|p| !p.is_empty())
                .ok_or_else(|| tr!("account_keys.new_password_needed"))?;
            check_new_password(&app, &me.email, new_password)?;
            // Someone who needed an admin has usually lost the Emergency Kit too.
            let new_sk = SecretKey::generate();
            put_password(&app, &me, &ak, new_password, Some(&new_sk), &new_sk, None, true)?;
            hold(ak.clone());
            let warning = keep_on_device(&app, &ak, false);
            let unlocked = open_active_if_linked(&app, &ak);
            let mut kit = kit_json(&me.email, &me.id, &new_sk, None)?;
            kit["kind"] = json!("current");
            kit["warning"] = json!(warning);
            kit["unlocked"] = json!(unlocked);
            kit
        } else {
            // Relinking writes the vaults: not while Passyble is read-only (update required).
            if crate::app_versions::blocked() {
                return Err(crate::read_only::refused_text());
            }
            let now = key_now(&app, &me.id, password.as_deref().map(|p| p.as_str()))?;
            let (relinked, failed) = super::reset::relink(&app, &ak, &now);
            json!({ "kind": "locked", "relinked": relinked, "failed": failed })
        };
        crate::account::store().delete(&secret_name);
        if with_api(&app, |api, _| api.recovery_complete(&org, &request_id)).is_err() {
            crate::applog::plog!("admin recovery: the completion was not sent to the service");
        }
        out["approved_by"] = json!(approval.approved_by);
        out["approver_fingerprint"] = json!(approver.fingerprint());
        Ok(out)
    })
    .await
}

/// After the account key changed here: the organisations to ask the member about
/// ([`rejoin_wanted`]). Nothing is enrolled here, even with the admin pinned: a breached service
/// could have set the flags.
pub fn rejoin_asks(app: &AppHandle, ak: &AccountKey) -> Vec<Value> {
    let mut asks = Vec::new();
    for (id, name, _) in orgs(app) {
        let Ok(info) = with_api(app, |api, _| api.recovery(&id)) else { continue };
        let row = org_row(&id, &name, "", &info, &ak.ak_id());
        if !rejoin_wanted(&row) {
            continue;
        }
        match admin_of(app, &id, &info) {
            Ok(admin) => {
                let mut ask = json!({ "org": id, "name": name });
                put_admin(&mut ask, &admin);
                asks.push(ask);
            }
            Err(e) => crate::applog::plog!("admin recovery: the admin's keys were not read: {e}"),
        }
    }
    asks
}

/// After an unlock: tells the windows about each Team that requires admin recovery of the
/// account key while it isn't enrolled ("enrol at join / when required").
pub fn check_required(app: &AppHandle) {
    let Some(me) = crate::account::signed_in(app) else { return };
    let cache = device::load(&me.id);
    if cache.ak_id.is_empty() {
        return;
    }
    for (id, name, kind) in orgs(app).into_iter().filter(|(_, _, k)| k == "team") {
        let Ok(info) = crate::account::with_api(app, |api, _| api.recovery(&id)) else { continue };
        let row = org_row(&id, &name, &kind, &info, &cache.ak_id);
        if row["required"] == true && row["available"] == true && row["enrolled"] != true {
            let _ = app.emit(
                super::reset::NOTICE_EVENT,
                json!({ "kind": "admin_recovery_required", "org": id, "name": name }),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enrolment_ids_name_the_account_key() {
        assert_eq!(enrolment_id("AK1"), "ak:AK1");
        assert_eq!(enrolled_ak_id("ak:AK1"), Some("AK1"));
        assert_eq!(enrolled_ak_id("vault-1"), None);
        assert_eq!(enrolled_ak_id("ak:"), None);
    }

    #[test]
    fn an_org_row_says_enrolled_enrol_again_and_required() {
        let info = json!({
            "enabled": true, "required": true, "key": { "key_id": "k" },
            "enrollment": { "vault_id": "ak:NEW", "created_at": 5 },
            "locked_enrollments": [{ "vault_id": "ak:OLD", "ak_id": "OLD", "locked_at": 3 }],
        });
        let row = org_row("g1", "Acme", "team", &info, "NEW");
        assert_eq!(row["enrolled"], true);
        assert_eq!(row["enrolled_at"], 5);
        assert_eq!(row["enrol_again"], false);
        assert_eq!(row["required"], true);
        assert_eq!(row["available"], true);
        assert_eq!(row["locked"][0]["ak_id"], "OLD");
        // Enrolled with the home vault's key, or an older account key: enrol again.
        let vault = json!({ "enabled": true, "key": {}, "enrollment": { "vault_id": "v-home" } });
        let row = org_row("g1", "Acme", "team", &vault, "NEW");
        assert_eq!(row["enrolled"], false);
        assert_eq!(row["enrol_again"], true);
        // Nothing offered.
        let none = org_row("g2", "Home", "family", &json!({}), "NEW");
        assert!(!rejoin_wanted(&none));
        assert_eq!(none["available"], false);
        assert_eq!(none["enrol_again"], false);
        assert!(none["enrolment"].is_null());
    }

    #[test]
    fn a_recovered_key_is_used_only_after_its_fingerprint_was_checked() {
        let real = AccountKey::generate("acc_mia".into()).unwrap().fingerprint();
        assert_eq!(key_check(&real, None, None), KeyCheck::Ask(real.clone()));
        assert_eq!(key_check(&real, Some(&real), None), KeyCheck::Ask(real.clone()));
        assert_eq!(key_check(&real, Some(&real.to_lowercase().replace('-', "")), Some(true)), KeyCheck::Go);
        assert_eq!(key_check(&real, Some(&real), Some(false)), KeyCheck::Drop);
    }

    /// A breached service hands the member an approval sealed to its own account key: its
    /// fingerprint isn't the one in Settings, so the member says it doesn't match and it's dropped;
    /// and a key swapped between the check and the use is dropped too.
    #[test]
    fn attack_a_key_the_service_sealed_is_never_used() {
        let real = AccountKey::generate("acc_mia".into()).unwrap().fingerprint();
        let fake = AccountKey::generate("acc_mia".into()).unwrap().fingerprint();
        assert_ne!(real, fake);
        assert_eq!(key_check(&fake, None, Some(false)), KeyCheck::Drop);
        // Checked the real key, then the service swapped the approval: not used.
        assert_eq!(key_check(&fake, Some(&real), Some(true)), KeyCheck::Drop);
    }

    /// After an e-mail reset: who to ask about joining again. Only asked, never enrolled here.
    #[test]
    fn after_a_reset_the_member_is_asked_where_the_old_key_was_enrolled() {
        let old = json!({
            "enabled": true, "key": { "key_id": "k" },
            "enrollment": { "vault_id": "ak:OLD" },
        });
        assert!(rejoin_wanted(&org_row("g1", "Acme", "team", &old, "NEW")));
        let locked = json!({
            "enabled": true, "key": {},
            "locked_enrollments": [{ "vault_id": "ak:OLD", "ak_id": "OLD" }],
        });
        assert!(rejoin_wanted(&org_row("g1", "Acme", "team", &locked, "NEW")));
        let required = json!({ "enabled": true, "required": true, "key": {} });
        assert!(rejoin_wanted(&org_row("g1", "Acme", "team", &required, "NEW")));
        // Never enrolled anywhere and not required: nothing to ask.
        let fresh = json!({ "enabled": true, "key": {} });
        assert!(!rejoin_wanted(&org_row("g1", "Acme", "team", &fresh, "NEW")));
        // Already enrolled with the new key: nothing to ask.
        let done = json!({ "enabled": true, "required": true, "key": {}, "enrollment": { "vault_id": "ak:NEW" } });
        assert!(!rejoin_wanted(&org_row("g1", "Acme", "team", &done, "NEW")));
        // Not offered any more: nothing to ask.
        let off = json!({ "enabled": false, "required": true, "key": {}, "enrollment": { "vault_id": "ak:OLD" } });
        assert!(!rejoin_wanted(&org_row("g1", "Acme", "team", &off, "NEW")));
    }

    #[test]
    fn a_row_carries_the_admin_who_made_the_recovery_key() {
        let mut row = json!({});
        put_admin(&mut row, &Admin { account: "acc_alice".into(), fingerprint: "7K3QD".into(), pin: Some("not_verified") });
        assert_eq!(row["admin"], "acc_alice");
        assert_eq!(row["admin_fingerprint"], "7K3QD");
        assert_eq!(row["admin_pin"], "not_verified");
    }

    /// A breached service publishes a recovery key made by keys it controls under the admin's
    /// account: the member pinned the real admin, so the planted key's creator shows as changed
    /// and the account key is never wrapped to it; with no pin at all nothing is enrolled either.
    #[test]
    fn attack_a_planted_recovery_key_is_never_enrolled() {
        let home = crate::contact_pins::tests::home();
        let admin = pass_core::UserKeyset::generate("acc_alice").unwrap();
        let fake = pass_core::UserKeyset::generate("acc_alice").unwrap();
        let ak = AccountKey::generate("acc_mia".into()).unwrap();
        let planted =
            pass_core::org_recovery_create(&fake, "org_acme", OrgKind::Team, vec![], &home).unwrap();
        let mut pinned = false;
        let c = contact_pins::check(&home, &fake.public_keys(), None, &mut pinned).unwrap().unwrap();
        assert_eq!(c.status, contact_pins::NOT_VERIFIED);
        assert!(ak
            .admin_recovery_enroll(planted.clone(), fake.public_keys(), OrgKind::Team, &home)
            .is_err());
        crate::contact_pins::tests::pin(&home, &admin.public_keys());
        let c = contact_pins::check(&home, &fake.public_keys(), None, &mut pinned).unwrap().unwrap();
        assert_eq!(c.status, contact_pins::CHANGED);
        assert!(ak
            .admin_recovery_enroll(planted, fake.public_keys(), OrgKind::Team, &home)
            .is_err());
        // The real admin's key, compared: enrolled.
        let real =
            pass_core::org_recovery_create(&admin, "org_acme", OrgKind::Team, vec![], &home).unwrap();
        assert!(contact_pins::check(&home, &admin.public_keys(), None, &mut pinned).unwrap().is_none());
        assert!(ak
            .admin_recovery_enroll(real, admin.public_keys(), OrgKind::Team, &home)
            .is_ok());
    }
}
