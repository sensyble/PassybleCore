//! Adding a device: the account key and the Secret Key travel sealed (HPKE, Core
//! `AccountKey::approve_device` / `approve_invitation`) from a device that has them to a new one.
//!
//! * **This PC approves**: an invitation QR for a phone (the MAC in the phone's answer proves it saw
//!   the QR), or number matching for devices without a camera: the user types the six digits the
//!   new device shows and the core seals only for those. This PC never works the digits out itself,
//!   so a tap on a request nobody started can't approve it.
//! * **This PC is the new device**: the sealed keys are kept only after the user checked their
//!   fingerprint against the other device's Settings (a service that sealed its own account key
//!   shows another fingerprint), else dropped.
//!
//! The keys of a pending exchange live in memory only; a restart ends it.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use pass_core::{DeviceApprovalKeys, DeviceInvitation, SealedAccountKey};
use serde_json::{json, Value};
use tauri::AppHandle;
use zeroize::Zeroizing;

use super::{api, device, guard, hold, key_err, keep_on_device, key_now, open_active_if_linked, secret_key_here, signed_in, with_api, Res};
use crate::account;
use crate::commands::{app_state, blocking};
use crate::i18n::tr;
use crate::vaults::now_ms;

/// Invitations this PC showed (id → the invitation's MAC key).
static INVITATIONS: Mutex<Option<HashMap<String, Arc<DeviceInvitation>>>> = Mutex::new(None);
/// Requests this PC accepted for the code (id → its `r_a`).
static ACCEPTED: Mutex<Option<HashMap<String, String>>> = Mutex::new(None);

struct NewDevice {
    id: String,
    poll_token: Zeroizing<String>,
    keys: Arc<DeviceApprovalKeys>,
    base: String,
    revealed: bool,
    expires_at: i64,
}

/// This PC's own request, while it waits.
static NEW_DEVICE: Mutex<Option<NewDevice>> = Mutex::new(None);

/// Keys that arrived for this PC, held in memory until the user checked their fingerprint.
struct Checking {
    approved: Arc<pass_core::ApprovedKeys>,
    status: api::KeyStatus,
}

static CHECKING: Mutex<Option<Checking>> = Mutex::new(None);

fn qr_json(text: &str) -> Res<Value> {
    let (size, path) = crate::twofactor::qr_path(text)?;
    Ok(json!({ "size": size, "path": path }))
}

/// "Add a device": an invitation QR for a phone to scan (2 minutes, once). The phone's join then
/// shows in [`account_device_requests`].
#[tauri::command]
pub async fn account_invite_device(app: AppHandle) -> Res<Value> {
    blocking(move || {
        signed_in(&app)?;
        let invitation = DeviceInvitation::new();
        let made = with_api(&app, |a, _| api::invitation_create(a, &invitation.token()))?;
        let qr = qr_json(&invitation.qr(made.id.clone()))?;
        guard(&INVITATIONS).get_or_insert_with(HashMap::new).insert(made.id.clone(), invitation);
        Ok(json!({ "id": made.id, "qr": qr, "expires_at": made.expires_at }))
    })
    .await
}

/// The open requests of other devices: name, platform, kind (`request`, `invitation`), state.
/// `ready`: it can be approved now (a request this PC accepted whose new device shows its digits:
/// the user types them, they are never sent to the window). `mismatch`: the new device's revealed
/// value doesn't match its commitment.
#[tauri::command]
pub async fn account_device_requests(app: AppHandle) -> Res<Value> {
    blocking(move || {
        let me = signed_in(&app)?;
        let list = with_api(&app, |a, _| api::requests(a))?;
        let accepted = guard(&ACCEPTED).clone().unwrap_or_default();
        let invited = guard(&INVITATIONS).clone().unwrap_or_default();
        let out: Vec<Value> = list
            .iter()
            .map(|r| {
                let s = |k: &str| r[k].as_str().unwrap_or_default().to_string();
                let (id, kind, state) = (s("id"), s("kind"), s("state"));
                let mut revealed = false;
                let mut mismatch = false;
                if kind == "request" && state == "revealed" {
                    if let Some(r_a) = accepted.get(&id) {
                        // Only the commitment check: the digits themselves stay off this screen.
                        match pass_core::device_approval_code(id.clone(), me.id.clone(), s("enc_pub"), s("commitment"), s("r_n"), r_a.clone()) {
                            Ok(_) => revealed = true,
                            Err(_) => mismatch = true,
                        }
                    }
                }
                let ready = match kind.as_str() {
                    "invitation" => state == "waiting" && invited.contains_key(&id),
                    _ => revealed,
                };
                json!({
                    "id": id,
                    "kind": kind,
                    "state": state,
                    "device_name": s("device_name"),
                    "platform": s("platform"),
                    "created_at": r["created_at"],
                    "expires_at": r["expires_at"],
                    "accepted_here": accepted.contains_key(&id),
                    "mismatch": mismatch,
                    "ready": ready,
                })
            })
            .collect();
        Ok(json!({ "requests": out }))
    })
    .await
}

/// "Add this device?" yes, by the code: sends this PC's random value; the new device then reveals
/// its own and both show the six digits.
#[tauri::command]
pub async fn account_device_accept(app: AppHandle, id: String) -> Res<Value> {
    blocking(move || {
        signed_in(&app)?;
        let r_a = pass_core::device_approval_nonce();
        with_api(&app, |a, _| api::request_step(a, &id, "accept", json!({ "r_a": r_a })))?;
        guard(&ACCEPTED).get_or_insert_with(HashMap::new).insert(id.clone(), r_a);
        Ok(json!({}))
    })
    .await
}

/// The seal for a request (not an invitation) `r` this PC accepted with `r_a`: `typed` is what the
/// user typed after reading the new device's screen. Only those digits seal ([`AccountKey::
/// approve_device`]); an empty or other code is refused, so is a request whose answer doesn't match.
fn seal_request(
    ak: &pass_core::AccountKey,
    sk: &pass_core::SecretKey,
    id: &str,
    r: &Value,
    r_a: &str,
    typed: &str,
) -> Res<SealedAccountKey> {
    if !typed.chars().any(|c| c.is_ascii_digit()) {
        return Err(tr!("account_keys.approval_code_needed"));
    }
    let s = |k: &str| r[k].as_str().unwrap_or_default().to_string();
    ak.approve_device(sk, id.to_string(), s("enc_pub"), s("commitment"), s("r_n"), r_a.to_string(), typed.to_string())
        .map_err(|e| match &e {
            pass_core::PassError::Crypto(m) if pass_core::core_message_is(m.clone(), "account_key.approval_code_mismatch".into()) => {
                crate::commands::pass_err(e)
            }
            _ => tr!("account_keys.approval_mismatch"),
        })
}

/// Approves request `id`: a phone joined this PC's invitation, or (`code`) the user typed the six
/// digits the new device shows. The key must be open here, else `password`. Returns this PC's
/// account key fingerprint, which the new device should show before it keeps the keys.
#[tauri::command]
pub async fn account_device_approve(app: AppHandle, id: String, password: Option<String>, code: Option<String>) -> Res<Value> {
    let password = password.map(Zeroizing::new);
    blocking(move || {
        let me = signed_in(&app)?;
        let ak = key_now(&app, &me.id, password.as_deref().map(|p| p.as_str()))?;
        let sk = secret_key_here(&me.id, &ak)?;
        let list = with_api(&app, |a, _| api::requests(a))?;
        let r = list
            .iter()
            .find(|r| r["id"].as_str() == Some(id.as_str()))
            .ok_or_else(|| tr!("account_keys.request_gone"))?;
        let s = |k: &str| r[k].as_str().unwrap_or_default().to_string();
        let (sealed, r_a): (SealedAccountKey, Option<String>) = if s("kind") == "invitation" {
            let invitation = guard(&INVITATIONS)
                .as_ref()
                .and_then(|m| m.get(&id).cloned())
                .ok_or_else(|| tr!("account_keys.request_gone"))?;
            let sealed = ak
                .approve_invitation(&sk, &invitation, id.clone(), s("enc_pub"), s("mac"))
                .map_err(|_| tr!("account_keys.approval_mismatch"))?;
            (sealed, None)
        } else {
            let r_a = guard(&ACCEPTED)
                .as_ref()
                .and_then(|m| m.get(&id).cloned())
                .ok_or_else(|| tr!("account_keys.request_gone"))?;
            let sealed = seal_request(&ak, &sk, &id, r, &r_a, code.as_deref().unwrap_or(""))?;
            (sealed, Some(r_a))
        };
        let mut body = json!({ "enc": sealed.enc, "ct": sealed.ct });
        if let Some(r_a) = r_a {
            body["r_a"] = json!(r_a);
        }
        with_api(&app, |a, _| api::request_step(a, &id, "seal", body.clone()))?;
        forget_request(&id);
        Ok(json!({ "fingerprint": ak.fingerprint() }))
    })
    .await
}

/// "Not me", or the codes differ: the request ends (a new device that had a session is signed out).
#[tauri::command]
pub async fn account_device_deny(app: AppHandle, id: String) -> Res<Value> {
    blocking(move || {
        signed_in(&app)?;
        let answer = with_api(&app, |a, _| api::request_step(a, &id, "deny", json!({})));
        forget_request(&id);
        answer.map(|_| json!({}))
    })
    .await
}

fn forget_request(id: &str) {
    if let Some(m) = guard(&ACCEPTED).as_mut() {
        m.remove(id);
    }
    if let Some(m) = guard(&INVITATIONS).as_mut() {
        m.remove(id);
    }
}

/// "Approve from another device" (before any sign-in): asks the account of `email` for its keys
/// with a one-time key. Returns the request's QR for a phone to scan; the six digits follow once
/// another device accepted ([`account_device_request_poll`]). The same answer for every address.
#[tauri::command]
pub async fn account_device_request_start(app: AppHandle, email: String) -> Res<Value> {
    blocking(move || {
        let email = api::normalize_email(&email);
        if !email.contains('@') {
            return Err(tr!("account_keys.email_needed"));
        }
        let state = app_state(&app);
        let base = account::Endpoints::for_base(&account::base_url(&state.settings())).base;
        let keys = DeviceApprovalKeys::new();
        let made = api::request_without_session(
            crate::teams_api::transport(),
            &base,
            &email,
            &keys.enc_pub(),
            &keys.commitment(),
            &api::device_name(),
        )
        .map_err(super::api_err)?;
        let poll_token = made.poll_token.clone().ok_or_else(|| tr!("errors.teams_unexpected_answer"))?;
        let qr = qr_json(&keys.approval_qr(made.id.clone()))?;
        let expires_at = made.expires_at.unwrap_or(now_ms() + 10 * 60 * 1000);
        *guard(&NEW_DEVICE) = Some(NewDevice {
            id: made.id.clone(),
            poll_token: Zeroizing::new(poll_token),
            keys,
            base,
            revealed: false,
            expires_at,
        });
        Ok(json!({ "id": made.id, "qr": qr, "expires_at": expires_at }))
    })
    .await
}

/// How this PC's request goes: `waiting`, `code` (with the six digits to read out to the other
/// device), `check` (the keys arrived: `fingerprint` to compare with the other device's Settings,
/// then [`account_device_request_confirm`]), `denied` or `expired`.
#[tauri::command]
pub async fn account_device_request_poll(app: AppHandle) -> Res<Value> {
    blocking(move || {
        let (id, token, base, keys, revealed, expires_at) = {
            let slot = guard(&NEW_DEVICE);
            let n = slot.as_ref().ok_or_else(|| tr!("account_keys.request_gone"))?;
            (n.id.clone(), n.poll_token.clone(), n.base.clone(), n.keys.clone(), n.revealed, n.expires_at)
        };
        if now_ms() > expires_at {
            guard(&NEW_DEVICE).take();
            return Ok(json!({ "state": "expired" }));
        }
        let t = crate::teams_api::transport();
        let v = match api::request_poll(t, &base, &id, &token) {
            Ok(v) => v,
            Err(e) if e.status() == 404 => {
                guard(&NEW_DEVICE).take();
                return Ok(json!({ "state": "expired" }));
            }
            Err(e) => return Err(super::api_err(e)),
        };
        let account_id = v["account"].as_str().unwrap_or_default().to_string();
        let r_a = v["r_a"].as_str().unwrap_or_default().to_string();
        match v["state"].as_str().unwrap_or_default() {
            "accepted" | "revealed" if !r_a.is_empty() && !account_id.is_empty() => {
                if !revealed {
                    api::request_reveal(t, &base, &id, &token, &keys.reveal()).map_err(super::api_err)?;
                    if let Some(n) = guard(&NEW_DEVICE).as_mut() {
                        n.revealed = true;
                    }
                }
                let code = keys.code(id.clone(), account_id, r_a).map_err(key_err)?;
                Ok(json!({ "state": "code", "code": code }))
            }
            "sealed" => {
                let opened = open_keys(&app, &id, &keys, &v);
                guard(&NEW_DEVICE).take();
                let checking = opened?;
                let fingerprint = checking.approved.fingerprint();
                *guard(&CHECKING) = Some(checking);
                Ok(json!({ "state": "check", "fingerprint": fingerprint }))
            }
            "denied" => {
                guard(&NEW_DEVICE).take();
                Ok(json!({ "state": "denied" }))
            }
            _ => Ok(json!({ "state": "waiting" })),
        }
    })
    .await
}

/// The keys arrived: keep the session and open the account key and the Secret Key (checked against
/// the account's `ak_id`). Nothing is kept yet: the user first checks the fingerprint.
fn open_keys(app: &AppHandle, id: &str, keys: &DeviceApprovalKeys, v: &Value) -> Res<Checking> {
    let state = app_state(app);
    let ep = account::Endpoints::for_base(&account::base_url(&state.settings()));
    let account_id = v["account"].as_str().unwrap_or_default().to_string();
    if let Some(session) = v.get("session").filter(|s| s.is_object()) {
        let answer = crate::teams_api::Answer {
            status: 200,
            error_code: None,
            body: session.to_string(),
        };
        let tokens = account::parse_tokens(&answer).map_err(|e| e.message())?;
        account::signed_in_with(app, &ep, &tokens)?;
    }
    let me = signed_in(app)?;
    if me.id != account_id {
        return Err(tr!("account_keys.other_account"));
    }
    let status = with_api(app, |a, _| api::status(a))?;
    let ak_id = status.ak_id.clone().ok_or_else(|| tr!("account_keys.not_set_up"))?;
    let sealed: SealedAccountKey = serde_json::from_value(v["sealed"].clone()).map_err(|_| tr!("account_keys.request_gone"))?;
    let r_a = v["r_a"].as_str().unwrap_or_default().to_string();
    let approved = keys
        .open(id.to_string(), account_id.clone(), ak_id, r_a, sealed)
        .map_err(|_| tr!("account_keys.approval_mismatch"))?;
    Ok(Checking { approved, status })
}

/// What the user's answer to "does your other device show this fingerprint?" does with the keys
/// held for it: `Ok(Some)` to keep them, `Ok(None)` to drop them (they don't match: maybe not the
/// account's own key), `Err` when nothing waits.
fn decide(held: Option<Checking>, matches: bool) -> Res<Option<Checking>> {
    let held = held.ok_or_else(|| tr!("account_keys.request_gone"))?;
    Ok(matches.then_some(held))
}

/// The user compared the fingerprint with the other device's Settings: `matches` keeps the keys
/// (`done`), otherwise they are dropped and never stored (`dropped`).
#[tauri::command]
pub async fn account_device_request_confirm(app: AppHandle, matches: bool) -> Res<Value> {
    blocking(move || {
        let held = guard(&CHECKING).take();
        match decide(held, matches)? {
            Some(checking) => keep_keys(&app, checking),
            None => {
                crate::applog::plog!("device approval: the keys' fingerprint didn't match, dropped");
                Ok(json!({ "state": "dropped" }))
            }
        }
    })
    .await
}

fn keep_keys(app: &AppHandle, checking: Checking) -> Res<Value> {
    let Checking { approved, status } = checking;
    let me = signed_in(app)?;
    let ak_id = status.ak_id.clone().ok_or_else(|| tr!("account_keys.not_set_up"))?;
    let ak = approved.account_key();
    // A key set an e-mail reset replaced stays on this PC for its vaults: its Secret Key and cache move
    // apart before the new ones are kept.
    let before = device::load(&me.id).ak_id;
    if !before.is_empty() && before != ak_id {
        device::retire_secret_key(&me.id, &before);
    }
    device::keep_secret_key(&me.id, &approved.secret_key())?;
    device::update(&me.id, |c| {
        c.email = me.email.clone();
        if c.ak_id != ak_id {
            c.retire(now_ms(), false);
            c.recovery = None;
            c.pw_wrap = None;
        }
        c.ak_id = ak_id.clone();
        c.salt = status.salt.clone().unwrap_or_default();
        c.kdf = status.kdf.clone();
        if let Ok(wrap) = ak.secret_key_wrap(&approved.secret_key()) {
            c.sk_wrap = Some(wrap);
        }
    })?;
    hold(ak.clone());
    let warning = keep_on_device(app, &ak, false);
    let unlocked = open_active_if_linked(app, &ak);
    Ok(json!({ "state": "done", "email": me.email, "unlocked": unlocked, "warning": warning }))
}

/// Ends this PC's request (and drops keys still waiting for the fingerprint check).
#[tauri::command]
pub fn account_device_request_cancel() -> Value {
    guard(&NEW_DEVICE).take();
    guard(&CHECKING).take();
    json!({})
}

#[cfg(test)]
mod tests {
    use super::*;
    use pass_core::{AccountKey, SecretKey};

    /// A request as the service lists it for the approving device: the new device's key,
    /// commitment and revealed value.
    fn listed(n: &DeviceApprovalKeys) -> Value {
        json!({ "enc_pub": n.enc_pub(), "commitment": n.commitment(), "r_n": n.reveal() })
    }

    #[test]
    fn a_request_is_approved_only_with_the_digits_typed_from_the_new_device() {
        let ak = AccountKey::generate("acc_1".into()).unwrap();
        let sk = SecretKey::generate();
        let n = DeviceApprovalKeys::new();
        let r_a = pass_core::device_approval_nonce();
        let shown = n.code("req-1".into(), "acc_1".into(), r_a.clone()).unwrap();
        let r = listed(&n);
        // A tap (nothing typed) never approves.
        assert_eq!(seal_request(&ak, &sk, "req-1", &r, &r_a, "").unwrap_err(), tr!("account_keys.approval_code_needed"));
        // Other digits are refused.
        let wrong = format!("{:06}", (shown.parse::<u32>().unwrap() + 1) % 1_000_000);
        assert!(seal_request(&ak, &sk, "req-1", &r, &r_a, &wrong).is_err());
        // The digits on the new device's screen, as typed: sealed, and they open there.
        let typed = format!("{} {}", &shown[..3], &shown[3..]);
        let sealed = seal_request(&ak, &sk, "req-1", &r, &r_a, &typed).unwrap();
        let got = n.open("req-1".into(), "acc_1".into(), ak.ak_id(), r_a, sealed).unwrap();
        assert_eq!(got.fingerprint(), ak.fingerprint());
    }

    /// A breached service plays the approving device and seals its own account key (with the
    /// account's `ak_id` on its side too): the new device shows that key's fingerprint, which is
    /// not the one in the real device's Settings, and the user's "doesn't match" drops the keys.
    #[test]
    fn attack_the_service_seals_its_own_account_key_and_it_is_dropped() {
        let real = AccountKey::generate("acc_1".into()).unwrap();
        let fake = AccountKey::generate("acc_1".into()).unwrap();
        let n = DeviceApprovalKeys::new();
        let r_a = pass_core::device_approval_nonce();
        let code = n.code("req-1".into(), "acc_1".into(), r_a.clone()).unwrap();
        let sealed = seal_request(&fake, &SecretKey::generate(), "req-1", &listed(&n), &r_a, &code).unwrap();
        let approved = n.open("req-1".into(), "acc_1".into(), fake.ak_id(), r_a, sealed).unwrap();
        assert_ne!(approved.fingerprint(), real.fingerprint());
        let held = Checking { approved, status: api::KeyStatus::default() };
        assert!(decide(Some(held), false).unwrap().is_none(), "dropped, never kept");
        assert!(decide(None, true).is_err(), "nothing waits after a drop");
    }

    #[test]
    fn matching_keys_are_kept() {
        let ak = AccountKey::generate("acc_1".into()).unwrap();
        let n = DeviceApprovalKeys::new();
        let r_a = pass_core::device_approval_nonce();
        let code = n.code("req-1".into(), "acc_1".into(), r_a.clone()).unwrap();
        let sealed = seal_request(&ak, &SecretKey::generate(), "req-1", &listed(&n), &r_a, &code).unwrap();
        let approved = n.open("req-1".into(), "acc_1".into(), ak.ak_id(), r_a, sealed).unwrap();
        let kept = decide(Some(Checking { approved, status: api::KeyStatus::default() }), true).unwrap().unwrap();
        assert_eq!(kept.approved.fingerprint(), ak.fingerprint());
    }
}
