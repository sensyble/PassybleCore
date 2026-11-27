//! Teams and Family: the admin and family manager commands.
//!
//! The account service keeps who is in the organisation, the departments and who may open which
//! shared vault; the app does the cryptography it can't. Only people whose keys are pinned in this
//! user's home vault (`contact_pins.rs`) are added or re-keyed in shared vaults
//! (`Vault::change_members_pinned`, signed by this manager); the service's "confirmed" flag counts for
//! nothing, and everyone else comes back as `needs_compare`. Removing someone rotates the key of every
//! vault they could open. While the Team requires a second password this PC doesn't have yet, nothing
//! that changes members or access runs here (`password_mode.rs`).

use std::sync::Arc;

use pass_agent::Agent;
use pass_core::{MemberChange, MemberRole, PublicKeys, SharedKind, Vault};
use serde_json::{json, Value};
use tauri::AppHandle;

use crate::account::with_api;
use crate::commands::{app_state, blocking, pass_err};
use crate::contact_pins::{self, ToCompare};
use crate::i18n::tr;
use crate::teams;
use crate::teams_vaults::{key_of_path, parse_role, save_and_upload, shared_path};

type Res<T> = Result<T, String>;

fn agent_of(app: &AppHandle) -> Res<Arc<Agent>> {
    let agent = app_state(app).require_agent()?;
    if agent.is_locked() {
        return Err(tr!("errors.teams_unlock_first"));
    }
    Ok(agent)
}

fn is_admin(app: &AppHandle, org: &str) -> Res<teams::CachedOrg> {
    let cached = teams::cached_org(app, org).ok_or_else(|| tr!("errors.teams_not_in_org"))?;
    if cached.role != "owner" && cached.role != "admin" {
        return Err(tr!("errors.teams_not_admin"));
    }
    Ok(cached)
}

fn vaults_changeable(app: &AppHandle, org: &str) -> Res<()> {
    match crate::password_mode::rule(app).read_only_refusal(Some(org)) {
        Some(reason) => Err(reason),
        None => Ok(()),
    }
}

fn rank(role: MemberRole) -> u8 {
    match role {
        MemberRole::Manage => 4,
        MemberRole::Edit => 3,
        MemberRole::View => 2,
        MemberRole::Fill => 1,
    }
}

fn role_of(v: &Value) -> Option<MemberRole> {
    parse_role(v.get("role")?.as_str()?).ok()
}

/// The role `account` (in `departments`) gets from a vault's `access` grants: the highest of the
/// grants naming the account, one of its departments, or everyone.
pub fn effective_role(
    account: &str,
    departments: &[String],
    access: &[Value],
) -> Option<MemberRole> {
    access
        .iter()
        .filter(|g| {
            g.get("account").and_then(Value::as_str) == Some(account)
                || g.get("department")
                    .and_then(Value::as_str)
                    .is_some_and(|d| departments.iter().any(|x| x == d))
                || g.get("everyone").and_then(Value::as_bool) == Some(true)
        })
        .filter_map(role_of)
        .max_by_key(|r| rank(*r))
}

pub fn departments_of(members: &Value, account: &str) -> Vec<String> {
    members
        .get("members")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find(|m| m.get("account_id").and_then(Value::as_str) == Some(account))
        .and_then(|m| m.get("departments"))
        .and_then(Value::as_array)
        .map(|d| {
            d.iter()
                .filter_map(|x| {
                    x.as_str()
                        .map(str::to_string)
                        .or_else(|| x.get("id").and_then(Value::as_str).map(str::to_string))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The changes that bring `account` in a vault's members list in line with `role` and `keys`:
/// added, its role set, its keys replaced (a rotation), or removed (no role: a rotation).
pub fn changes_for(
    info: &pass_core::SharedInfo,
    keys: Option<&PublicKeys>,
    account: &str,
    role: Option<MemberRole>,
) -> Vec<MemberChange> {
    let current = info.members.iter().find(|m| m.account == account);
    match (current, role, keys) {
        (None, Some(role), Some(keys)) => vec![MemberChange::Add {
            keys: keys.clone(),
            role,
            group: None,
        }],
        (Some(m), Some(role), keys) => {
            let mut out = Vec::new();
            if let Some(keys) = keys {
                let fingerprint = pass_core::public_keys_fingerprint(keys.clone());
                if fingerprint != m.fingerprint {
                    out.push(MemberChange::ReplaceKeys { keys: keys.clone() });
                }
            }
            if m.role != role {
                out.push(MemberChange::SetRole {
                    account: account.to_string(),
                    role,
                });
            }
            out
        }
        (Some(_), None, _) if account != info.account => vec![MemberChange::Remove {
            account: account.to_string(),
        }],
        _ => Vec::new(),
    }
}

fn registry(app: &AppHandle, org: &str) -> Res<Vec<Value>> {
    let answer = with_api(app, |api, _| api.vaults(org))?;
    Ok(answer
        .get("vaults")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default())
}

fn access_of(vault: &Value) -> Vec<Value> {
    vault
        .get("access")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

/// Applies the registry's access of every open vault of `org` this user manages to `accounts`: role
/// changes and removals, and the adds and key replacements whose keys are pinned in the home vault
/// ([`contact_pins::split_pinned`]). Saves and uploads each changed vault. Returns the number of vaults
/// changed and the people left out until this user compared their keys.
fn apply_access(
    app: &AppHandle,
    agent: &Agent,
    org: &str,
    accounts: &[(String, Option<PublicKeys>)],
    only_vault: Option<&str>,
) -> Res<(usize, Vec<ToCompare>)> {
    let home = agent
        .peek_vault()
        .ok_or_else(|| tr!("errors.teams_unlock_first"))?;
    let vaults = registry(app, org)?;
    let members = with_api(app, |api, _| api.members(org))?;
    let mut changed = 0;
    let mut to_compare = Vec::new();
    for entry in vaults {
        let Some(vault_id) = entry.get("vault_id").and_then(Value::as_str) else {
            continue;
        };
        if only_vault.is_some_and(|v| v != vault_id) {
            continue;
        }
        let Some(vault) = agent.shared_vault(vault_id) else {
            continue;
        };
        let Some(info) = vault.shared_info() else {
            continue;
        };
        if info.role != MemberRole::Manage {
            continue;
        }
        let access = access_of(&entry);
        let mut changes = Vec::new();
        for (account, keys) in accounts {
            let role = effective_role(account, &departments_of(&members, account), &access);
            changes.extend(changes_for(&info, keys.as_ref(), account, role));
        }
        let (changes, left_out) = contact_pins::split_pinned(&home, &info, changes);
        contact_pins::merge(&mut to_compare, left_out);
        if changes.is_empty() {
            continue;
        }
        vault
            .change_members_pinned(changes, &home)
            .map_err(pass_err)?;
        let key = agent
            .linked_status()
            .into_iter()
            .find(|s| s.vault.as_ref().is_some_and(|r| r.id == vault_id))
            .map(|s| s.key)
            .ok_or_else(|| tr!("errors.teams_vault_not_open"))?;
        save_and_upload(agent, vault_id, &key)?;
        changed += 1;
    }
    Ok((changed, to_compare))
}

fn verified_keys(app: &AppHandle, org: &str, account: &str, fingerprint: &str) -> Res<PublicKeys> {
    let stored = with_api(app, |api, _| api.keys_of(org, account))?;
    stored
        .keys
        .verify()
        .map_err(|_| tr!("errors.teams_bad_keys"))?;
    if stored.keys.account != account {
        return Err(tr!("errors.teams_bad_keys"));
    }
    let norm = |f: &str| -> String {
        f.chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .map(|c| c.to_ascii_uppercase())
            .collect()
    };
    let actual = pass_core::public_keys_fingerprint(stored.keys.clone());
    if norm(&actual) != norm(fingerprint) {
        return Err(tr!("errors.teams_fingerprint_mismatch"));
    }
    Ok(stored.keys)
}

#[tauri::command]
pub async fn org_overview(app: AppHandle, org: String) -> Res<Value> {
    blocking(move || {
        let cached = teams::cached_org(&app, &org).ok_or_else(|| tr!("errors.teams_not_in_org"))?;
        let mut overview = with_api(&app, |api, _| api.overview(&org))?;
        overview["org"] = json!({
            "id": cached.id, "kind": cached.kind, "name": cached.name, "role": cached.role,
        });
        Ok(overview)
    })
    .await
}

/// The service's members list with `pin` (`pinned`, `not_verified`, `changed`) and `pinned_fingerprint`
/// for each member, so the window offers to compare where the service's "confirmed" isn't enough.
#[tauri::command]
pub async fn org_members(app: AppHandle, org: String) -> Res<Value> {
    blocking(move || {
        let mut answer = with_api(&app, |api, _| api.members(&org))?;
        if let Some(home) = app_state(&app).agent().and_then(|a| a.peek_vault()) {
            mark_pins(&home, &mut answer);
        }
        Ok(answer)
    })
    .await
}

fn mark_pins(home: &Vault, answer: &mut Value) {
    let Some(members) = answer.get_mut("members").and_then(Value::as_array_mut) else {
        return;
    };
    for m in members {
        let account = m.get("account_id").and_then(Value::as_str).map(str::to_string);
        let fingerprint = m
            .pointer("/keys/fingerprint")
            .and_then(Value::as_str)
            .map(str::to_string);
        if let (Some(account), Some(fingerprint)) = (account, fingerprint) {
            let (pin, pinned) = contact_pins::member_pin(home, &account, &fingerprint);
            m["pin"] = json!(pin);
            if let Some(pinned) = pinned {
                m["pinned_fingerprint"] = json!(pinned);
            }
        }
    }
}

#[tauri::command]
pub async fn org_invite(
    app: AppHandle,
    org: String,
    email: String,
    role: String,
    departments: Vec<String>,
) -> Res<Value> {
    blocking(move || {
        let cached = is_admin(&app, &org)?;
        let email = email.trim().to_string();
        if !email.contains('@') || email.len() > 254 {
            return Err(tr!("errors.teams_bad_email"));
        }
        if role != "member" && role != "admin" {
            return Err(tr!("errors.teams_bad_role"));
        }
        let team = cached.kind == "team";
        with_api(&app, |api, _| {
            api.invite(&org, &email, &role, &departments, team)
        })
    })
    .await
}

#[tauri::command]
pub async fn org_invite_csv(app: AppHandle, org: String, csv: String, dry_run: bool) -> Res<Value> {
    blocking(move || {
        is_admin(&app, &org)?;
        if csv.len() > 48 * 1024 {
            return Err(tr!("errors.teams_csv_too_large"));
        }
        with_api(&app, |api, _| api.bulk_invite(&org, &csv, dry_run))
    })
    .await
}

#[tauri::command]
pub async fn org_invite_resend(app: AppHandle, org: String, invite_id: String) -> Res<Value> {
    blocking(move || {
        with_api(&app, |api, _| api.resend_invite(&org, &invite_id)).map(|_| json!({}))
    })
    .await
}

#[tauri::command]
pub async fn org_invite_cancel(app: AppHandle, org: String, invite_id: String) -> Res<Value> {
    blocking(move || {
        with_api(&app, |api, _| api.cancel_invite(&org, &invite_id)).map(|_| json!({}))
    })
    .await
}

/// Confirms a person's keys after the admin compared the fingerprint: they are pinned in this user's
/// home vault, the service records it, and the person is added (or updated) in every shared vault of
/// the organisation they should be in and this user manages. `{ vaults_updated, needs_compare }`.
#[tauri::command]
pub async fn org_confirm(
    app: AppHandle,
    org: String,
    account_id: String,
    fingerprint: String,
) -> Res<Value> {
    blocking(move || {
        vaults_changeable(&app, &org)?;
        let agent = agent_of(&app)?;
        let keys = verified_keys(&app, &org, &account_id, &fingerprint)?;
        let home = agent
            .peek_vault()
            .ok_or_else(|| tr!("errors.teams_unlock_first"))?;
        home.pin_contact(keys.clone(), pass_core::PERSONAL_SCOPE, &fingerprint)
            .map_err(pass_err)?;
        agent.save().map_err(pass_err)?;
        let actual = pass_core::public_keys_fingerprint(keys.clone());
        with_api(&app, |api, _| api.confirm(&org, &account_id, &actual))?;
        let (changed, needs_compare) = apply_access(
            &app,
            &agent,
            &org,
            &[(account_id.clone(), Some(keys))],
            None,
        )?;
        teams::emit_changed(&app);
        Ok(json!({ "vaults_updated": changed, "needs_compare": needs_compare }))
    })
    .await
}

/// `member`: the `member_id` of `org_members` (the service looks members up by it, not by account).
#[tauri::command]
pub async fn org_set_role(
    app: AppHandle,
    org: String,
    member: String,
    role: String,
) -> Res<Value> {
    blocking(move || {
        is_admin(&app, &org)?;
        if !matches!(role.as_str(), "member" | "admin") {
            return Err(tr!("errors.teams_bad_role"));
        }
        with_api(&app, |api, _| api.set_role(&org, &member, &role)).map(|_| json!({}))
    })
    .await
}

/// Removes someone from the organisation (to a successor if given): every shared vault they could
/// open and this user manages gets a new key, and those vaults' logins are listed so their passwords
/// can be changed. `member`: the `member_id` of `org_members`; `account_id`: the same person's account.
#[tauri::command]
pub async fn org_offboard(
    app: AppHandle,
    org: String,
    member: String,
    account_id: String,
    transfer_to: Option<String>,
) -> Res<Value> {
    blocking(move || {
        is_admin(&app, &org)?;
        vaults_changeable(&app, &org)?;
        let agent = agent_of(&app)?;
        let answer = with_api(&app, |api, _| {
            api.offboard(&org, &member, transfer_to.as_deref())
        })?;
        let mut rotated = Vec::new();
        let mut change_passwords = Vec::new();
        for (vault_ref, vault) in agent.open_vaults() {
            let Some(info) = vault.shared_info() else {
                continue;
            };
            if info.org.as_deref() != Some(org.as_str())
                || !info.members.iter().any(|m| m.account == account_id)
            {
                continue;
            }
            for item in vault.summaries() {
                if item.trashed_at.is_none() && item.kind == pass_core::ItemKind::Login {
                    change_passwords.push(json!({
                        "vault": vault_ref.name, "vault_id": vault_ref.id, "item_id": item.id,
                        "title": item.title, "username": item.username,
                    }));
                }
            }
            if info.role != MemberRole::Manage {
                continue;
            }
            vault.remove_member(&account_id).map_err(pass_err)?;
            if let Some(status) = agent
                .linked_status()
                .into_iter()
                .find(|s| s.vault.as_ref().is_some_and(|r| r.id == vault_ref.id))
            {
                save_and_upload(&agent, &vault_ref.id, &status.key)?;
            }
            let _ = with_api(&app, |api, _| api.rotated(&org, &vault_ref.id));
            rotated.push(vault_ref.name.clone());
        }
        teams::emit_changed(&app);
        Ok(json!({
            "rotated": rotated,
            "change_passwords": change_passwords,
            "transfers": answer.get("transfers").cloned().unwrap_or(json!([])),
            "service": answer,
        }))
    })
    .await
}

#[tauri::command]
pub async fn org_departments(app: AppHandle, org: String) -> Res<Value> {
    blocking(move || with_api(&app, |api, _| api.departments(&org))).await
}

#[tauri::command]
pub async fn org_department_create(app: AppHandle, org: String, name: String) -> Res<Value> {
    blocking(move || {
        let name = name.trim().to_string();
        if name.is_empty() || name.chars().count() > 80 {
            return Err(tr!("errors.teams_bad_label"));
        }
        with_api(&app, |api, _| api.create_department(&org, &name))
    })
    .await
}

#[tauri::command]
pub async fn org_department_rename(
    app: AppHandle,
    org: String,
    id: String,
    name: String,
) -> Res<Value> {
    blocking(move || {
        let name = name.trim().to_string();
        if name.is_empty() || name.chars().count() > 80 {
            return Err(tr!("errors.teams_bad_label"));
        }
        with_api(&app, |api, _| api.rename_department(&org, &id, &name))
    })
    .await
}

#[tauri::command]
pub async fn org_department_delete(app: AppHandle, org: String, id: String) -> Res<Value> {
    blocking(move || with_api(&app, |api, _| api.delete_department(&org, &id)).map(|_| json!({})))
        .await
}

/// Adds someone to a department (or takes them out): the vaults the department reaches follow
/// when this user pinned the person's keys. `{ needs_compare }`: left out until compared.
#[tauri::command]
pub async fn org_department_member(
    app: AppHandle,
    org: String,
    id: String,
    account_id: String,
    add: bool,
) -> Res<Value> {
    blocking(move || {
        vaults_changeable(&app, &org)?;
        with_api(&app, |api, _| {
            api.department_member(&org, &id, &account_id, add)
        })?;
        let mut needs_compare = Vec::new();
        if let Ok(agent) = agent_of(&app) {
            let keys = service_keys(&app, &org, &account_id);
            if let Ok((_, left_out)) =
                apply_access(&app, &agent, &org, &[(account_id.clone(), keys)], None)
            {
                needs_compare = left_out;
            }
        }
        Ok(json!({ "needs_compare": needs_compare }))
    })
    .await
}

/// The keys the service hands out for `account` in `org`, if they verify and name that account.
/// Not trusted: [`apply_access`] wraps only to keys pinned here.
fn service_keys(app: &AppHandle, org: &str, account: &str) -> Option<PublicKeys> {
    with_api(app, |api, _| api.keys_of(org, account))
        .ok()
        .map(|k| k.keys)
        .filter(|k| k.verify().is_ok() && k.account == account)
}

/// The accounts of an `org_members` answer an access change looks at: the ones the service says
/// are confirmed, and the ones `pinned` says this user compared. The service's word only puts
/// someone on the list; access needs a pin ([`apply_access`]).
fn candidates(members: &Value, pinned: impl Fn(&str) -> bool) -> Vec<String> {
    members
        .get("members")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|m| {
            let account = m.get("account_id").and_then(Value::as_str)?;
            let confirmed = m.pointer("/keys/confirmed").and_then(Value::as_bool) == Some(true);
            (confirmed || pinned(account)).then(|| account.to_string())
        })
        .collect()
}

fn org_people(app: &AppHandle, agent: &Agent, org: &str) -> Vec<(String, Option<PublicKeys>)> {
    let members = with_api(app, |api, _| api.members(org)).unwrap_or_default();
    let home = agent.peek_vault();
    let pinned = |account: &str| {
        home.as_ref()
            .is_some_and(|h| h.contact_pin(account, pass_core::PERSONAL_SCOPE).is_some())
    };
    candidates(&members, pinned)
        .into_iter()
        .map(|account| {
            let keys = service_keys(app, org, &account);
            (account, keys)
        })
        .collect()
}

#[tauri::command]
pub async fn org_vault_create(
    app: AppHandle,
    org: String,
    label: String,
    access: Vec<Value>,
) -> Res<Value> {
    blocking(move || {
        vaults_changeable(&app, &org)?;
        let agent = agent_of(&app)?;
        let label = label.trim().to_string();
        if label.is_empty() || label.chars().count() > 80 {
            return Err(tr!("errors.teams_bad_label"));
        }
        let backend =
            teams::cloud_backend(&app).ok_or_else(|| tr!("errors.teams_direct_needs_cloud"))?;
        let home = agent
            .peek_vault()
            .ok_or_else(|| tr!("errors.teams_unlock_first"))?;
        let keyset = home
            .ensure_user_keyset(backend.account_id())
            .map_err(pass_err)?;
        let device = app_state(&app).settings().device_id;
        let vault = Vault::create_shared(&keyset, SharedKind::Org, Some(org.clone()), &device)
            .map_err(pass_err)?;
        let mut access = access;
        if !access
            .iter()
            .any(|g| g.get("account").and_then(Value::as_str) == Some(backend.account_id()))
        {
            access.push(json!({ "account": backend.account_id(), "role": "manage" }));
        }
        let registered = with_api(&app, |api, _| {
            api.register_vault(&org, &vault.vault_id(), &label, "department", &access)
        })?;
        let path = registered
            .get("vault_path")
            .and_then(Value::as_str)
            .ok_or_else(|| tr!("errors.teams_unexpected_answer"))?
            .to_string();
        let key = key_of_path(&path);
        let (user, token) = backend.credentials();
        let config = pass_agent::LinkedVaultConfig {
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
            org: Some(org.clone()),
            key: key.clone(),
        };
        agent.add_shared(config, vault.clone()).map_err(pass_err)?;
        save_and_upload(&agent, &vault.vault_id(), &key)?;
        let people = org_people(&app, &agent, &org);
        let needs_compare = apply_access(&app, &agent, &org, &people, Some(&vault.vault_id()))
            .map(|(_, left_out)| left_out)
            .unwrap_or_default();
        let vault_ref = agent
            .open_vaults()
            .into_iter()
            .find(|(r, _)| r.id == vault.vault_id())
            .map(|(r, _)| r);
        teams::emit_changed(&app);
        Ok(json!({ "vault": vault_ref, "needs_compare": needs_compare }))
    })
    .await
}

#[tauri::command]
pub async fn org_vault_access(
    app: AppHandle,
    org: String,
    vault_id: String,
    access: Vec<Value>,
) -> Res<Value> {
    blocking(move || {
        vaults_changeable(&app, &org)?;
        with_api(&app, |api, _| api.set_access(&org, &vault_id, &access))?;
        let agent = agent_of(&app)?;
        let mut people = org_people(&app, &agent, &org);
        if let Some(info) = agent.shared_vault(&vault_id).and_then(|v| v.shared_info()) {
            for m in info.members {
                if !people.iter().any(|(a, _)| *a == m.account) {
                    people.push((m.account, None));
                }
            }
        }
        let (changed, needs_compare) =
            apply_access(&app, &agent, &org, &people, Some(&vault_id))?;
        teams::emit_changed(&app);
        Ok(json!({ "vaults_updated": changed, "needs_compare": needs_compare }))
    })
    .await
}

#[tauri::command]
pub async fn org_vault_delete(app: AppHandle, org: String, vault_id: String) -> Res<Value> {
    blocking(move || {
        vaults_changeable(&app, &org)?;
        with_api(&app, |api, _| api.delete_vault(&org, &vault_id))?;
        if let Ok(agent) = agent_of(&app) {
            if let Some(status) = agent
                .linked_status()
                .into_iter()
                .find(|s| s.vault.as_ref().is_some_and(|r| r.id == vault_id))
            {
                agent.remove_shared(&status.key, true);
            }
        }
        teams::emit_changed(&app);
        Ok(json!({}))
    })
    .await
}

#[tauri::command]
pub async fn org_leave(app: AppHandle, org: String) -> Res<Value> {
    blocking(move || {
        let cached = teams::cached_org(&app, &org).ok_or_else(|| tr!("errors.teams_not_in_org"))?;
        if cached.role == "owner" {
            return Err(tr!("errors.teams_owner_cannot_leave"));
        }
        with_api(&app, |api, _| api.leave_org(&org))?;
        crate::teams_vaults::refresh_soon(&app);
        Ok(json!({}))
    })
    .await
}

#[tauri::command]
pub async fn org_transfer_owner(app: AppHandle, org: String, account_id: String) -> Res<Value> {
    blocking(move || {
        let cached = teams::cached_org(&app, &org).ok_or_else(|| tr!("errors.teams_not_in_org"))?;
        if cached.role != "owner" {
            return Err(tr!("errors.teams_not_owner"));
        }
        with_api(&app, |api, _| api.transfer_owner(&org, &account_id))?;
        crate::teams_vaults::refresh_soon(&app);
        Ok(json!({}))
    })
    .await
}

#[tauri::command]
pub async fn org_policies(app: AppHandle, org: String) -> Res<Value> {
    blocking(move || with_api(&app, |api, _| api.policies(&org))).await
}

#[tauri::command]
pub async fn org_policies_set(app: AppHandle, org: String, change: Value) -> Res<Value> {
    blocking(move || {
        is_admin(&app, &org)?;
        let answer = with_api(&app, |api, _| api.set_policies(&org, &change))?;
        crate::teams_vaults::refresh_soon(&app);
        Ok(answer)
    })
    .await
}

/// A Team member's own password mode (`mode`: `choice`, `second_password`, `one_password`; none:
/// the team's rule). `member`: the `member_id` of `org_members`. `{ mode, effective }`.
#[tauri::command]
pub async fn org_member_password_mode(
    app: AppHandle,
    org: String,
    member: String,
    mode: Option<String>,
) -> Res<Value> {
    blocking(move || {
        let cached = is_admin(&app, &org)?;
        if cached.kind != "team" {
            return Err(tr!("password_mode.team_only"));
        }
        let mode = mode.filter(|m| !m.is_empty());
        if mode
            .as_deref()
            .is_some_and(|m| crate::password_mode::Mode::parse(Some(m)).as_str() != m)
        {
            return Err(tr!("password_mode.bad_mode"));
        }
        let answer = with_api(&app, |api, _| {
            api.set_member_password_mode(&org, &member, mode.as_deref())
        })?;
        crate::teams_vaults::refresh_soon(&app);
        Ok(answer)
    })
    .await
}

#[tauri::command]
pub async fn org_activity(app: AppHandle, org: String, before: Option<i64>) -> Res<Value> {
    blocking(move || with_api(&app, |api, _| api.activity(&org, 100, before))).await
}

#[tauri::command]
pub fn org_billing_open(app: AppHandle, org: String) -> Res<Value> {
    let base = crate::account::base_url(&app_state(&app).settings());
    let kind = teams::cached_org(&app, &org)
        .map(|o| o.kind)
        .unwrap_or_default();
    let url = if kind == "family" {
        format!("{base}/family")
    } else {
        format!("{base}/org/{}", crate::teams_api::segment(&org))
    };
    crate::platform::open_browser(&url)?;
    Ok(json!({}))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(account: &str) -> (pass_core::UserKeyset, PublicKeys) {
        let k = pass_core::UserKeyset::generate(account).unwrap();
        let p = k.public_keys();
        (k, p)
    }

    #[test]
    fn the_highest_grant_wins() {
        let access = vec![
            json!({ "department": "dep_eng", "role": "view" }),
            json!({ "account": "acc_bob", "role": "edit" }),
            json!({ "everyone": true, "role": "fill" }),
        ];
        let eng = vec!["dep_eng".to_string()];
        assert_eq!(
            effective_role("acc_bob", &[], &access),
            Some(MemberRole::Edit)
        );
        assert_eq!(
            effective_role("acc_dan", &eng, &access),
            Some(MemberRole::View)
        );
        assert_eq!(
            effective_role("acc_eve", &[], &access),
            Some(MemberRole::Fill)
        );
        assert_eq!(effective_role("acc_eve", &[], &access[..2]), None);
    }

    #[test]
    fn departments_are_read_from_the_members_answer() {
        let members = json!({ "members": [
            { "account_id": "acc_bob", "departments": ["dep_a", { "id": "dep_b" }] },
        ] });
        assert_eq!(departments_of(&members, "acc_bob"), ["dep_a", "dep_b"]);
        assert!(departments_of(&members, "acc_x").is_empty());
    }

    #[test]
    fn member_changes_follow_the_access() {
        let (alice, _) = keys("acc_alice");
        let (_, bob) = keys("acc_bob");
        let vault = Vault::create_shared(&alice, SharedKind::Org, None, "alice").unwrap();
        let info = vault.shared_info().unwrap();
        let add = changes_for(&info, Some(&bob), "acc_bob", Some(MemberRole::View));
        assert!(matches!(
            &add[..],
            [MemberChange::Add {
                role: MemberRole::View,
                ..
            }]
        ));
        let home = crate::contact_pins::tests::home();
        crate::contact_pins::tests::pin(&home, &bob);
        let info = vault.change_members_pinned(add, &home).unwrap();
        assert!(changes_for(&info, Some(&bob), "acc_bob", Some(MemberRole::View)).is_empty());
        assert!(matches!(
            &changes_for(&info, Some(&bob), "acc_bob", Some(MemberRole::Edit))[..],
            [MemberChange::SetRole { .. }]
        ));
        let (_, bob2) = keys("acc_bob");
        assert!(matches!(
            &changes_for(&info, Some(&bob2), "acc_bob", Some(MemberRole::View))[..],
            [MemberChange::ReplaceKeys { .. }]
        ));
        assert!(matches!(
            &changes_for(&info, None, "acc_bob", None)[..],
            [MemberChange::Remove { .. }]
        ));
        assert!(changes_for(&info, None, "acc_alice", None).is_empty());
    }

    fn plan(
        home: &Vault,
        info: &pass_core::SharedInfo,
        people: &[(&str, &PublicKeys)],
        role: MemberRole,
    ) -> (Vec<MemberChange>, Vec<ToCompare>) {
        let mut changes = Vec::new();
        for (account, keys) in people {
            changes.extend(changes_for(info, Some(keys), account, Some(role)));
        }
        contact_pins::split_pinned(home, info, changes)
    }

    /// A breached account service marks an account it controls "confirmed" in the members list:
    /// it becomes a candidate, but the admin never compared its keys, so it is not added; it comes
    /// back to the window to compare.
    #[test]
    fn attack_the_service_adds_a_confirmed_member() {
        let members = json!({ "members": [
            { "account_id": "acc_bob", "keys": { "confirmed": true } },
            { "account_id": "acc_mallory", "keys": { "confirmed": true } },
            { "account_id": "acc_carol", "keys": { "confirmed": false } },
            { "account_id": "acc_dan" },
        ] });
        // Bob and Mallory because the service says so; Dan because the admin pinned him.
        let listed = candidates(&members, |a| a == "acc_dan");
        assert_eq!(listed, ["acc_bob", "acc_mallory", "acc_dan"]);

        let (alice, _) = keys("acc_alice");
        let vault = Vault::create_shared(&alice, SharedKind::Org, None, "alice").unwrap();
        let home = crate::contact_pins::tests::home();
        let (_, bob) = keys("acc_bob");
        let (_, mallory) = keys("acc_mallory");
        crate::contact_pins::tests::pin(&home, &bob);
        let info = vault.shared_info().unwrap();
        let (apply, compare) = plan(
            &home,
            &info,
            &[("acc_bob", &bob), ("acc_mallory", &mallory)],
            MemberRole::Edit,
        );
        assert_eq!(apply.len(), 1);
        assert_eq!(compare.len(), 1);
        assert_eq!(compare[0].account, "acc_mallory");
        assert_eq!(compare[0].status, contact_pins::NOT_VERIFIED);
        let info = vault.change_members_pinned(apply, &home).unwrap();
        let accounts: Vec<&str> = info.members.iter().map(|m| m.account.as_str()).collect();
        assert_eq!(accounts, ["acc_alice", "acc_bob"]);
    }

    /// A breached service hands out its own keys under a pinned member's account: the vault
    /// would re-key Bob to them (`ReplaceKeys`); that change is left out and shown as changed,
    /// while Bob's role change still goes ahead with his real keys.
    #[test]
    fn attack_the_service_swaps_a_pinned_members_keys() {
        let (alice, _) = keys("acc_alice");
        let vault = Vault::create_shared(&alice, SharedKind::Org, None, "alice").unwrap();
        let home = crate::contact_pins::tests::home();
        let (_, bob) = keys("acc_bob");
        crate::contact_pins::tests::pin(&home, &bob);
        let info = vault.shared_info().unwrap();
        let (apply, _) = plan(&home, &info, &[("acc_bob", &bob)], MemberRole::View);
        let info = vault.change_members_pinned(apply, &home).unwrap();
        let key_epoch = info.key_epoch;

        let (_, fake) = keys("acc_bob");
        let (apply, compare) = plan(&home, &info, &[("acc_bob", &fake)], MemberRole::Edit);
        assert!(matches!(&apply[..], [MemberChange::SetRole { .. }]));
        assert_eq!(compare.len(), 1);
        assert_eq!(compare[0].status, contact_pins::CHANGED);
        assert_eq!(
            compare[0].pinned_fingerprint.as_deref(),
            Some(pass_core::public_keys_fingerprint(bob.clone()).as_str())
        );
        let info = vault.change_members_pinned(apply, &home).unwrap();
        let in_vault = info.members.iter().find(|m| m.account == "acc_bob").unwrap();
        assert_eq!(in_vault.role, MemberRole::Edit);
        assert_eq!(in_vault.fingerprint, pass_core::public_keys_fingerprint(bob));
        // No rotation to the fake keys happened.
        assert_eq!(info.key_epoch, key_epoch);
    }

    #[test]
    fn member_rows_carry_what_the_pins_say() {
        let home = crate::contact_pins::tests::home();
        let (_, bob) = keys("acc_bob");
        let (_, carol) = keys("acc_carol");
        crate::contact_pins::tests::pin(&home, &bob);
        let (_, fake_bob) = keys("acc_bob");
        let mut answer = json!({ "members": [
            { "account_id": "acc_bob", "keys": { "fingerprint": pass_core::public_keys_fingerprint(bob.clone()), "confirmed": true } },
            { "account_id": "acc_carol", "keys": { "fingerprint": pass_core::public_keys_fingerprint(carol), "confirmed": true } },
            { "account_id": "acc_eve" },
        ] });
        mark_pins(&home, &mut answer);
        assert_eq!(answer["members"][0]["pin"], "pinned");
        assert_eq!(answer["members"][1]["pin"], "not_verified");
        assert!(answer["members"][2].get("pin").is_none());
        answer["members"][0]["keys"]["fingerprint"] =
            json!(pass_core::public_keys_fingerprint(fake_bob));
        mark_pins(&home, &mut answer);
        assert_eq!(answer["members"][0]["pin"], "changed");
        assert_eq!(
            answer["members"][0]["pinned_fingerprint"],
            json!(pass_core::public_keys_fingerprint(bob))
        );
    }
}
