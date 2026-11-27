//! The Passyble password (Core docs/ARCHITECTURE.md §18): the account's password and a Secret Key
//! held by each device open every vault linked to the account. Setting up, unlocking, linking,
//! password and key changes live here; adding a device is in [`approval`].
//!
//! The service never receives the password, the Secret Key, the account key or a vault key. Every
//! cryptographic step is Core's (`pass_core::AccountKey`, `AccountPassword`, `SecretKey`, ...).

pub mod admin;
pub mod api;
pub mod approval;
pub mod device;
pub mod reset;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use pass_core::{AccountKey, AccountPassword, PassError, SecretKey};
use serde_json::{json, Value};
use tauri::AppHandle;
use zeroize::Zeroizing;

use self::api::KeyBlobs;
use self::device::{DeviceKey, RecoveryCopy};
use crate::account::{self, AccountSettings};
use crate::commands::{app_state, blocking, pass_err};
use crate::i18n::tr;
use crate::state::AppState;
use crate::teams_api::{AccountApi, ApiError};
use crate::{hello, vaults};

type Res<T> = Result<T, String>;

/// Answers the windows act on instead of showing. The Secret Key isn't on this PC: ask for it once.
pub const SECRET_KEY_NEEDED: &str = "secret_key_needed";
/// The account key isn't open here: ask for the Passyble password.
pub const PASSWORD_NEEDED: &str = "account_password_needed";
/// Not signed in and no address known: ask for the account's e-mail address.
pub const EMAIL_NEEDED: &str = "account_email_needed";
/// The service wants a sign-in within the last 10 minutes: sign in again, then repeat.
pub const REAUTH: &str = "reauth_required";
/// The vault is linked to a key an e-mail reset replaced: "Locked, from before your reset".
pub const LOCKED: &str = "account_key_locked";

/// How long an account key opened while no vault is unlocked (a setup, an approval, a reset)
/// stays usable for the next step.
const LOOSE_KEY: Duration = Duration::from_secs(120);

struct Held {
    ak: Arc<AccountKey>,
    since: Instant,
}

/// The account key while a vault is unlocked (or for [`LOOSE_KEY`] after it was opened).
static HELD: Mutex<Option<Held>> = Mutex::new(None);

fn guard<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

fn hold(ak: Arc<AccountKey>) {
    *guard(&HELD) = Some(Held {
        ak,
        since: Instant::now(),
    });
}

/// Every lock (soft, full, auto-lock, Win+L, sleep, a switch) drops the account key.
pub fn forget_held() {
    guard(&HELD).take();
}

fn held(state: &AppState, account: &str) -> Option<Arc<AccountKey>> {
    let unlocked = state.agent().is_some_and(|a| !a.is_locked());
    let mut slot = guard(&HELD);
    let usable = slot
        .as_ref()
        .map(|h| (h.ak.account() == account, unlocked || h.since.elapsed() < LOOSE_KEY));
    match usable {
        Some((true, true)) => slot.as_ref().map(|h| h.ak.clone()),
        Some((_, false)) => {
            slot.take();
            None
        }
        _ => None,
    }
}

fn signed_in(app: &AppHandle) -> Res<AccountSettings> {
    account::signed_in(app).ok_or_else(|| tr!("errors.teams_sign_in_first"))
}

fn api_err(e: ApiError) -> String {
    match e.code() {
        "reauth_required" => REAUTH.into(),
        "account_keys_off" => tr!("account_keys.off"),
        "wrong_password" => tr!("account_keys.wrong_password"),
        "password_limited" => tr!("errors.too_many_attempts"),
        "wrong_recovery_code" => tr!("account_keys.wrong_recovery_code"),
        "no_recovery_code" => tr!("account_keys.no_recovery_code"),
        "already_set" => tr!("account_keys.already_set"),
        "no_password" => tr!("account_keys.not_set_up"),
        "other_account_key" | "changed_meanwhile" => tr!("account_keys.changed_meanwhile"),
        "bad_key_signature" | "key_signature_required" => tr!("account_keys.bad_signature"),
        "invitation_gone" | "bad_state" | "not_found" => tr!("account_keys.request_gone"),
        "reset_waiting" => tr!("account_keys.reset_already"),
        "no_reset" => tr!("account_keys.reset_none"),
        "reset_not_due" => tr!("account_keys.reset_not_due"),
        "reset_proof_required" => tr!("account_keys.reset_proof_required"),
        "locked_set_gone" => tr!("account_keys.locked_gone"),
        "invalid_challenge" => tr!("account_keys.try_again"),
        "recovery_required" => tr!("recoveryadmin.required_stays"),
        _ => e.message(),
    }
}

/// Runs `f` with the signed-in account's API; a `401` refreshes the access token once.
fn with_api<T>(app: &AppHandle, f: impl Fn(&AccountApi<'_>, &AccountSettings) -> Result<T, ApiError>) -> Res<T> {
    let (api, account) = account::api(app)?;
    match f(&api, &account) {
        Err(e) if e.is_auth() => {
            account::drop_access_token();
            let (api, account) = account::api(app)?;
            f(&api, &account).map_err(api_err)
        }
        other => other.map_err(api_err),
    }
}

fn key_err(e: PassError) -> String {
    match e {
        PassError::InvalidPassword => tr!("account_keys.wrong_password"),
        other => pass_err(other),
    }
}

fn wrong_code(e: PassError) -> String {
    match e {
        PassError::InvalidPassword => tr!("account_keys.wrong_recovery_code"),
        other => key_err(other),
    }
}

fn hello_available(state: &AppState) -> bool {
    state.hello_available.load(std::sync::atomic::Ordering::Relaxed)
}

fn parse_secret_key(text: &str) -> Res<Arc<SecretKey>> {
    SecretKey::parse(text.to_string()).map_err(|e| match e {
        PassError::InvalidInput(m) => m,
        other => pass_err(other),
    })
}

/// The Secret Key the user typed (or pasted), else this PC's. [`SECRET_KEY_NEEDED`] without one.
fn secret_key_for(account: &str, typed: Option<&str>) -> Res<Arc<SecretKey>> {
    if let Some(text) = typed.map(str::trim).filter(|t| !t.is_empty()) {
        return parse_secret_key(text);
    }
    let kept = device::secret_key(account).ok_or_else(|| SECRET_KEY_NEEDED.to_string())?;
    SecretKey::parse(kept.to_string()).map_err(|_| SECRET_KEY_NEEDED.to_string())
}

/// This PC's Secret Key, else the cached `sk_wrap` opened with `ak`.
fn secret_key_here(account: &str, ak: &AccountKey) -> Res<Arc<SecretKey>> {
    match secret_key_for(account, None) {
        Ok(sk) => Ok(sk),
        Err(e) => {
            let wrap = device::load(account).sk_wrap.ok_or(e)?;
            ak.open_secret_key(wrap).map_err(key_err)
        }
    }
}

/// Opens the account key with the Passyble password: the cached wrap first (offline), else the
/// service's after a sign-in signature. `expected_ak_id`: the key a vault is linked to.
fn open_with_password(
    app: &AppHandle,
    account: &str,
    expected_ak_id: Option<&str>,
    password: &str,
    typed_secret_key: Option<&str>,
    email: Option<&str>,
) -> Res<(Arc<AccountKey>, Option<String>)> {
    let sk = secret_key_for(account, typed_secret_key)?;
    let mut cache = device::load(account);
    let mut wrong = false;
    let cached = cache.offline_ready() && expected_ak_id.is_none_or(|id| id == cache.ak_id);
    let mut opened = None;
    let known_email = Some(cache.email.clone()).filter(|e| !e.is_empty());
    if let Some(wrap) = cache.pw_wrap.clone().filter(|_| cached) {
        let derived = AccountPassword::new(
            password.to_string(),
            &sk,
            cache.salt.clone(),
            cache.kdf.clone().unwrap_or_default(),
        )
        .map_err(key_err)?;
        match derived.open_account_key(account.into(), cache.ak_id.clone(), wrap) {
            Ok(ak) => opened = Some(ak),
            // Maybe the password changed on another device: ask the service.
            Err(PassError::InvalidPassword) => wrong = true,
            Err(e) => return Err(key_err(e)),
        }
    }
    let ak = match opened {
        Some(ak) => ak,
        None => match online_open(app, account, password, &sk, email.or(known_email.as_deref())) {
            Ok((ak, blobs, address)) => {
                // The account's key changed (an e-mail reset elsewhere): the Secret Key kept here
                // was the old set's when another one had to be typed; kept apart for its vaults.
                if typed_secret_key.is_some() && !cache.ak_id.is_empty() && cache.ak_id != blobs.ak_id {
                    device::retire_secret_key(account, &cache.ak_id);
                }
                cache.take_blobs(&blobs);
                if let Some(address) = address {
                    cache.email = address;
                }
                ak
            }
            // The cached wrap said no and the service can't be asked (offline, not signed in):
            // it was the password.
            Err(e) if wrong && e != tr!("errors.too_many_attempts") => {
                if e != tr!("account_keys.wrong_password") {
                    crate::applog::plog!("account keys: no online check after a wrong offline try");
                }
                return Err(tr!("account_keys.wrong_password"));
            }
            Err(e) => return Err(e),
        },
    };
    if typed_secret_key.is_some() {
        device::keep_secret_key(account, &sk)?;
    }
    if let Some(me) = account::signed_in(app).filter(|a| a.id == account) {
        cache.email = me.email;
    }
    device::save(&cache)?;
    hello::account_password_used(account);
    let note = keep_on_device(app, &ak, false);
    Ok((ak, note))
}

/// The online half of [`open_with_password`].
fn online_open(
    app: &AppHandle,
    account: &str,
    password: &str,
    sk: &SecretKey,
    email: Option<&str>,
) -> Res<(Arc<AccountKey>, KeyBlobs, Option<String>)> {
    let device_name = api::device_name();
    if let Some(me) = account::signed_in(app).filter(|a| a.id == account) {
        let status = with_api(app, |api, _| api::status(api))?;
        if !status.set {
            return Err(tr!("account_keys.not_set_up"));
        }
        let derived = AccountPassword::new(
            password.to_string(),
            sk,
            status.salt.unwrap_or_default(),
            status.kdf.unwrap_or_default(),
        )
        .map_err(key_err)?;
        let blobs = with_api(app, |api, _| {
            let nonce = api::nonce(api, "unlock")?;
            let sig = derived
                .sign_in(me.email.clone(), nonce.clone(), device_name.clone(), api::platform())
                .map_err(|e| ApiError::Unexpected(pass_err(e)))?;
            api::unlock(api, &nonce, &sig, &device_name)
        })?;
        let ak = open_blobs(&derived, account, &blobs)?;
        return Ok((ak, blobs, None));
    }
    // Not signed in here: a sign-in with the password (it also gives this PC a session).
    let email = email
        .map(api::normalize_email)
        .filter(|e| e.contains('@'))
        .ok_or_else(|| EMAIL_NEEDED.to_string())?;
    let email = email.as_str();
    let state = app_state(app);
    let ep = account::Endpoints::for_base(&account::base_url(&state.settings()));
    let t = crate::teams_api::transport();
    let pre = api::prelogin(t, &ep.base, email).map_err(api_err)?;
    let derived = AccountPassword::new(password.to_string(), sk, pre.salt, pre.kdf).map_err(key_err)?;
    let sig = derived
        .sign_in(email.to_string(), pre.nonce.clone(), device_name.clone(), api::platform())
        .map_err(key_err)?;
    let (tokens, blobs) =
        api::session_password(t, &ep.base, email, &pre.nonce, &sig, &device_name).map_err(api_err)?;
    if tokens.account_id != account {
        return Err(tr!("account_keys.other_account"));
    }
    account::signed_in_with(app, &ep, &tokens)?;
    let ak = open_blobs(&derived, account, &blobs)?;
    Ok((ak, blobs, Some(tokens.email.clone())))
}

fn open_blobs(derived: &AccountPassword, account: &str, blobs: &KeyBlobs) -> Res<Arc<AccountKey>> {
    let wrap = blobs.pw_wrap.clone().ok_or_else(|| tr!("errors.teams_unexpected_answer"))?;
    derived
        .open_account_key(account.into(), blobs.ak_id.clone(), wrap)
        .map_err(key_err)
}

/// Keeps `ak` on this PC as Settings says: under Windows Hello or DPAPI only. `force`: also when it
/// is kept already. Returns a note for the user when it couldn't be kept.
fn keep_on_device(app: &AppHandle, ak: &AccountKey, force: bool) -> Option<String> {
    let state = app_state(app);
    let account = ak.account();
    let binding = hello::account_binding(&account, &ak.ak_id());
    let mode = device::load(&account).device_key;
    let kept = hello::account_kept(&account);
    let want_hello = match mode {
        DeviceKey::Off => {
            if kept.is_some() {
                hello::account_forget(&account);
            }
            return None;
        }
        DeviceKey::Hello => true,
        DeviceKey::Remember => false,
    };
    if !force && kept.as_ref().is_some_and(|(h, b)| *h == want_hello && *b == binding) {
        return None;
    }
    if want_hello && !hello_available(&state) {
        return None;
    }
    let _one = state.ui.hello_lock();
    let raw = Zeroizing::new(ak.to_bytes());
    match hello::account_store(&account, &raw, &binding, state.ui.main_owner(), !want_hello) {
        Ok(()) => None,
        Err(e) => Some(crate::errors::logged(tr!("account_keys.not_kept"), "account key on this PC", e)),
    }
}

/// The account key for a step in Settings: in memory (a vault is unlocked), else with `password`,
/// else after the Windows Hello prompt when it is kept here. [`PASSWORD_NEEDED`] otherwise.
pub(crate) fn key_now(app: &AppHandle, account: &str, password: Option<&str>) -> Res<Arc<AccountKey>> {
    let state = app_state(app);
    if let Some(ak) = held(&state, account) {
        return Ok(ak);
    }
    if let Some(pw) = password.filter(|p| !p.is_empty()) {
        let (ak, _) = open_with_password(app, account, None, pw, None, None)?;
        hold(ak.clone());
        return Ok(ak);
    }
    let cache = device::load(account);
    if !cache.ak_id.is_empty() && hello::account_kept(account).is_some() {
        let ak = open_kept(&state, account, &cache.ak_id)?;
        hold(ak.clone());
        return Ok(ak);
    }
    Err(PASSWORD_NEEDED.into())
}

fn open_kept(state: &AppState, account: &str, ak_id: &str) -> Res<Arc<AccountKey>> {
    let _one = state.ui.hello_lock();
    let policy = hello::HelloPolicy::default();
    let raw = hello::account_open(account, &hello::account_binding(account, ak_id), state.ui.main_owner(), &policy)
        .map_err(|f| f.message)?;
    AccountKey::from_bytes(account.into(), raw.to_vec(), ak_id.into()).map_err(key_err)
}

/// Whether `password` is in Pwned Passwords, via the account service's prefix proxy. `None` when
/// that can't be asked (fail open).
fn breached(app: &AppHandle, password: &str) -> Option<bool> {
    let q = pass_core::hibp_prefix(password.to_string());
    let range = with_api(app, |api, _| api::pwned(api, &q.prefix)).ok()?;
    Some(pass_core::hibp_match(range, q.suffix) > 0)
}

/// The rules for a new Passyble password on this PC: the master password rule (12+ characters,
/// strength 3, not built from the address) and the breach check.
fn check_new_password(app: &AppHandle, email: &str, password: &str) -> Res<()> {
    let context = pass_core::MasterPasswordContext {
        names: vec![email.to_string()],
    };
    pass_core::require_master_password(password, &context).map_err(pass_err)?;
    if breached(app, password) == Some(true) {
        return Err(tr!("account_keys.password_breached"));
    }
    Ok(())
}

/// Refuses the Passyble password as a vault's own password (Core's
/// `AccountKey::require_second_password`): a vault with its own password has no Secret Key, so a
/// copy of its file must not be a way to guess the Passyble password. Checked against this PC's
/// copy of the account's password wrap with the open account key; without them it can't be told.
fn refuse_account_password(state: &AppState, account: &str, password: &str) -> Res<()> {
    let Some(ak) = held(state, account) else {
        return Ok(());
    };
    let cache = device::load(account);
    if cache.ak_id != ak.ak_id() {
        return Ok(());
    }
    let (Some(kdf), Some(pw_wrap), Some(sk_wrap)) = (cache.kdf, cache.pw_wrap, cache.sk_wrap) else {
        return Ok(());
    };
    ak.require_second_password(
        password.to_string(),
        pass_core::MasterPasswordContext::default(),
        cache.salt,
        kdf,
        pw_wrap,
        sk_wrap,
    )
    .map_err(pass_err)
}

/// The fingerprint Settings shows for an account key id (Core's `AccountKey::fingerprint`: the
/// first 8 bytes of `ak_id` as 4 groups of 4 hex digits).
pub fn fingerprint_of(ak_id: &str) -> Option<String> {
    let raw = pass_core::b64url_decode(ak_id.to_string()).ok()?;
    if raw.len() < 8 {
        return None;
    }
    let hex: String = raw[..8].iter().map(|b| format!("{b:02X}")).collect();
    Some(
        hex.as_bytes()
            .chunks(4)
            .map(|c| String::from_utf8_lossy(c).into_owned())
            .collect::<Vec<_>>()
            .join("-"),
    )
}

fn device_key_str(k: DeviceKey) -> &'static str {
    match k {
        DeviceKey::Hello => "hello",
        DeviceKey::Remember => "remember",
        DeviceKey::Off => "off",
    }
}

/// The active vault's link, read from its file (`None`: not linked or not readable).
fn active_link(state: &AppState) -> Option<pass_core::VaultAccess> {
    let agent = state.agent()?;
    if let Some(v) = agent.peek_vault() {
        return v.account_link().map(|l| pass_core::VaultAccess {
            kind: "account".into(),
            account: Some(l.account),
            ak_id: Some(l.ak_id),
            account_recovery: l.recovery_id.is_some(),
        });
    }
    let access = pass_core::vault_file_access(agent.vault_file_bytes()?).ok()?;
    (access.kind == "account").then_some(access)
}

/// Settings → Passyble account → Passyble password: the account key's state here and the active
/// vault's link.
#[tauri::command]
pub async fn account_keys_status(app: AppHandle) -> Res<Value> {
    blocking(move || {
        let state = app_state(&app);
        let Some(me) = account::signed_in(&app) else {
            return Ok(json!({ "signed_in": false }));
        };
        let cache = device::load(&me.id);
        let online = with_api(&app, |api, _| api::status(api));
        let (feature_off, set, ak_id, recovery_at, offline) = match &online {
            Ok(s) => (false, Some(s.set), s.ak_id.clone(), s.recovery.as_ref().and_then(|r| r.created_at), false),
            Err(e) if *e == tr!("account_keys.off") => (true, Some(false), None, None, false),
            Err(_) => (false, (!cache.ak_id.is_empty()).then_some(true), Some(cache.ak_id.clone()).filter(|a| !a.is_empty()), None, true),
        };
        let ak_id = ak_id.unwrap_or_default();
        let link = active_link(&state);
        let active = state.settings().active().cloned();
        let home = state.agent().and_then(|a| a.peek_vault()).is_some_and(|v| v.holds_sharing_keys());
        let rule = crate::password_mode::rule(&app);
        let active_id = active.as_ref().map(|v| v.id.clone()).unwrap_or_default();
        let linked_here = link.as_ref().and_then(|l| l.account.clone());
        let unlocked = state.agent().is_some_and(|a| !a.is_locked());
        let reset = online.as_ref().ok().map(|s| reset::reset_json(&cache, s, vaults::now_ms()));
        let locked = online
            .as_ref()
            .ok()
            .and_then(|s| s.locked_key_sets)
            .unwrap_or(0)
            .max(cache.old_keys.len() as u32);
        let offer = set == Some(true)
            && unlocked
            && linked_here.is_none()
            && rule.link_refusal(&active_id).is_none()
            && active.as_ref().is_some_and(|v| !cache.link_declined.contains(&v.id));
        Ok(json!({
            "signed_in": true,
            "account": me.id,
            "email": me.email,
            "feature_off": feature_off,
            "offline": offline,
            "set": set,
            "fingerprint": fingerprint_of(&ak_id),
            "recovery_created_at": recovery_at,
            "secret_key_here": device::secret_key(&me.id).is_some(),
            "device_key": device_key_str(cache.device_key),
            "kept": hello::account_kept(&me.id).map(|(h, _)| if h { "hello" } else { "remember" }),
            "hello_available": hello_available(&state),
            "key_open": held(&state, &me.id).is_some(),
            "reset": reset,
            "key_changed": reset::key_changed_json(&cache),
            "locked": locked,
            "active_vault": active.as_ref().map(|v| json!({
                "id": v.id,
                "name": v.name,
                "linked": linked_here.as_deref() == Some(me.id.as_str()),
                "linked_other": linked_here.as_ref().is_some_and(|a| *a != me.id),
                "home": home,
                "offer_link": offer,
                // A Team's password mode: whether "Use a separate password" and the link are offered.
                "unlink": rule.unlink_refusal(&active_id, home).is_none(),
                "link": rule.link_refusal(&active_id).is_none(),
                "password_mode": rule.mode.as_str(),
            })),
        }))
    })
    .await
}

/// The Emergency Kit as the window lays it out; the recovery code only at setup or with a new code.
fn kit_json(email: &str, account: &str, sk: &SecretKey, recovery_code: Option<String>) -> Res<Value> {
    let kit = pass_core::emergency_kit(email.into(), account.into(), sk, recovery_code);
    let (size, path) = crate::twofactor::qr_path(&kit.setup_qr)?;
    Ok(json!({
        "email": kit.email,
        "sign_in_url": kit.sign_in_url,
        "account": kit.account,
        "secret_key": kit.secret_key,
        "setup_qr": { "size": size, "path": path },
        "recovery_code": kit.recovery_code,
    }))
}

/// Sets up the Passyble password of the signed-in account: makes the account key, the Secret Key
/// and the recovery code here and uploads only public keys and wraps. Returns the Emergency Kit.
#[tauri::command]
pub async fn account_keys_setup(app: AppHandle, password: String) -> Res<Value> {
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
        with_api(&app, |api, _| api::signed(api, &ak, "POST", "/account-key", &body))?;
        device::keep_secret_key(&me.id, &sk)?;
        device::update(&me.id, |c| {
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
        })?;
        hello::account_password_used(&me.id);
        hold(ak.clone());
        let mut kit = kit_json(&me.email, &me.id, &sk, Some(recovery.code.clone()))?;
        kit["warning"] = json!(keep_on_device(&app, &ak, false));
        Ok(kit)
    })
    .await
}

/// The Emergency Kit again (Settings), without the recovery code (it isn't kept anywhere): after
/// Windows Hello or the Passyble password.
#[tauri::command]
pub async fn account_kit(app: AppHandle, password: Option<String>) -> Res<Value> {
    let password = password.map(Zeroizing::new);
    blocking(move || {
        let me = signed_in(&app)?;
        let ak = key_now(&app, &me.id, password.as_deref().map(|p| p.as_str()))?;
        let sk = match device::secret_key(&me.id) {
            Some(text) => SecretKey::parse(text.to_string()).map_err(key_err)?,
            None => {
                let wrap = device::load(&me.id).sk_wrap.ok_or_else(|| SECRET_KEY_NEEDED.to_string())?;
                ak.open_secret_key(wrap).map_err(key_err)?
            }
        };
        kit_json(&me.email, &me.id, &sk, None)
    })
    .await
}

/// What the unlock form needs to know about list entry `vault_id`, read from its file: how it opens
/// and, for a linked vault, what this PC keeps for it. Records the link in the list.
#[tauri::command]
pub async fn vault_access(app: AppHandle, vault_id: String) -> Res<Value> {
    blocking(move || {
        let state = app_state(&app);
        let entry = state.settings().vault(&vault_id).cloned().ok_or_else(|| tr!("errors.vault_not_listed"))?;
        let Ok(bytes) = std::fs::read(&entry.path) else {
            return Ok(json!({ "kind": "missing" }));
        };
        let access = pass_core::vault_file_access(bytes).map_err(pass_err)?;
        let linked = (access.kind == "account").then(|| access.account.clone()).flatten();
        if entry.linked_account != linked {
            let _ = state.update_settings(|s| {
                if let Some(v) = s.vaults.iter_mut().find(|v| v.id == vault_id) {
                    v.linked_account = linked.clone();
                }
                Ok(())
            });
        }
        let Some(account) = linked else {
            return Ok(json!({ "kind": access.kind }));
        };
        Ok(account_access_json(&state, &account, access.ak_id.as_deref().unwrap_or_default(), access.account_recovery))
    })
    .await
}

fn account_access_json(state: &AppState, account: &str, ak_id: &str, recovery_copy: bool) -> Value {
    let cache = device::load(account);
    let kept = hello::account_kept(account);
    let binding = hello::account_binding(account, ak_id);
    let kept_for_this = kept.as_ref().filter(|(_, b)| *b == binding);
    let readiness = hello::account_readiness(account, &hello::HelloPolicy::default());
    let locked_kept = hello::account_old_kept(account).iter().any(|k| k == ak_id);
    let me = state.settings().passyble_account.filter(|a| a.id == account);
    json!({
        "kind": "account",
        "account": account,
        "email": me.as_ref().map(|a| a.email.clone()).or(Some(cache.email.clone()).filter(|e| !e.is_empty())),
        "signed_in": me.is_some(),
        "secret_key_here": device::secret_key(account).is_some(),
        "offline_ready": cache.offline_ready() && cache.ak_id == ak_id,
        // The old key of a locked vault, still kept here, opens it like the current one.
        "kept": kept_for_this.map(|(h, _)| if *h { "hello" } else { "remember" }).or(locked_kept.then_some("hello")),
        "kept_ready": (kept_for_this.is_some() && readiness.ready) || locked_kept,
        "kept_note": readiness.note,
        "key_open": held(state, account).is_some_and(|ak| ak.ak_id() == ak_id),
        "recovery_copy": recovery_copy,
        // Linked to a key an e-mail reset replaced (this PC knows it, or still keeps that key).
        "locked": cache.old_key(ak_id).is_some() || locked_kept,
        "locked_kept": locked_kept,
        "ak_id": ak_id,
    })
}

fn linked_target(state: &AppState, vault_id: Option<&str>) -> Res<(String, String, String)> {
    let settings = state.settings();
    let id = match vault_id.filter(|v| !v.is_empty()) {
        Some(v) => v.to_string(),
        None => vaults::active_id(state)?,
    };
    let entry = settings.vault(&id).ok_or_else(|| tr!("errors.vault_not_listed"))?;
    let bytes = std::fs::read(&entry.path).map_err(|_| tr!("unlock.missing_file"))?;
    let access = pass_core::vault_file_access(bytes).map_err(pass_err)?;
    match (access.kind.as_str(), access.account, access.ak_id) {
        ("account", Some(account), Some(ak_id)) => Ok((id, account, ak_id)),
        _ => Err(tr!("account_keys.not_linked")),
    }
}

/// Opens linked vault `vault_id` (the active one without it) with the Passyble password. Without
/// `password`: the account key in memory, else [`PASSWORD_NEEDED`].
#[tauri::command]
pub async fn unlock_account(
    app: AppHandle,
    vault_id: Option<String>,
    password: Option<String>,
    secret_key: Option<String>,
    email: Option<String>,
) -> Res<Value> {
    let password = password.map(Zeroizing::new);
    let secret_key = secret_key.map(Zeroizing::new);
    blocking(move || {
        let state = app_state(&app);
        let (id, account, ak_id) = linked_target(&state, vault_id.as_deref())?;
        // A key set an e-mail reset replaced: the password asked online would be the new one.
        if password.as_deref().is_some_and(|p| !p.is_empty()) && device::load(&account).old_key(&ak_id).is_some() {
            return Err(LOCKED.into());
        }
        let (ak, note) = match password.as_deref().map(|p| p.as_str()).filter(|p| !p.is_empty()) {
            None => (
                held(&state, &account)
                    .filter(|k| k.ak_id() == ak_id)
                    .ok_or_else(|| PASSWORD_NEEDED.to_string())?,
                None,
            ),
            Some(pw) => open_with_password(
                &app,
                &account,
                Some(&ak_id),
                pw,
                secret_key.as_deref().map(|s| s.as_str()),
                email.as_deref(),
            )?,
        };
        if ak.ak_id() != ak_id {
            // The account's key now is another one: this vault is from before a reset.
            return Err(LOCKED.into());
        }
        unlock_with(&app, &id, &ak)?;
        Ok(json!({ "warning": note }))
    })
    .await
}

/// Opens linked vault `vault_id` (or the active one) with the account key kept on this PC, after
/// Windows Hello ("Remember on this PC": no prompt).
#[tauri::command]
pub async fn unlock_account_hello(app: AppHandle, vault_id: Option<String>) -> Res<Value> {
    blocking(move || {
        let state = app_state(&app);
        let (id, account, ak_id) = linked_target(&state, vault_id.as_deref())?;
        if !crate::popups::main_on_screen(&app) {
            return Err(tr!("errors.hello_cancelled"));
        }
        // A vault from before an e-mail reset opens with the old key this PC still keeps; relinking is a
        // separate step.
        if hello::account_old_kept(&account).contains(&ak_id) {
            let old = reset::old_by_device(&state, &account, &ak_id)?;
            unlock_with(&app, &id, &old)?;
            // Settings steps must never sign with the old key.
            forget_held();
            return Ok(json!({ "warning": null, "locked": true }));
        }
        let ak = open_kept(&state, &account, &ak_id)?;
        unlock_with(&app, &id, &ak)?;
        Ok(json!({ "warning": null }))
    })
    .await
}

/// Points the agent at list entry `id` and opens it with `ak`; then the key stays in memory for
/// the other linked vaults, and the vault's recovery copy is brought up to date in the background.
fn unlock_with(app: &AppHandle, id: &str, ak: &Arc<AccountKey>) -> Res<()> {
    let state = app_state(app);
    let (agent, id) = crate::commands::unlock_target(app, Some(id.to_string()))?;
    agent.unlock_with_account_key(ak).map_err(pass_err)?;
    hold(ak.clone());
    vaults::mark_opened(&state, &id);
    let account = ak.account();
    let _ = state.update_settings(|s| {
        if let Some(v) = s.vaults.iter_mut().find(|v| v.id == id) {
            v.linked_account = Some(account.clone());
        }
        Ok(())
    });
    sync_recovery_soon(app, &account);
    Ok(())
}

/// Brings the open vault's recovery copy and this PC's cache in line with the account's current
/// recovery code, as the service names it (in the background; nothing when offline).
fn sync_recovery_soon(app: &AppHandle, account: &str) {
    let app = app.clone();
    let account = account.to_string();
    let _ = std::thread::Builder::new()
        .name("pass-account-recovery-copy".into())
        .spawn(move || {
            if account::signed_in(&app).is_none_or(|a| a.id != account) {
                return;
            }
            let Ok(status) = with_api(&app, |api, _| api::status(api)) else {
                return;
            };
            let current_key = status.ak_id.clone().unwrap_or_default();
            let Some(current) = status.recovery.map(|r| r.rec_id) else {
                return;
            };
            let state = app_state(&app);
            let Some(agent) = state.agent() else { return };
            let Some(vault) = agent.peek_vault() else { return };
            // Only a vault of the current key: one from before a reset keeps its old copy (the old
            // recovery code opens it offline).
            let Some(link) = vault
                .account_link()
                .filter(|l| l.account == account && l.ak_id == current_key)
            else {
                return;
            };
            let cache = device::load(&account);
            let cached = cache.recovery.clone().filter(|r| r.rec_id == current);
            match (cached, link.recovery_id.as_deref() == Some(current.as_str())) {
                (Some(copy), false) => {
                    if vault.set_account_recovery(copy.rec_id, copy.wrap).is_ok() {
                        let _ = agent.save();
                    }
                }
                (None, true) => {
                    if let Some(copy) = vault.account_recovery_copy() {
                        let _ = device::update(&account, |c| {
                            c.recovery = Some(RecoveryCopy {
                                rec_id: copy.rec_id,
                                wrap: copy.wrap,
                            })
                        });
                    }
                }
                _ => {}
            }
        });
}

/// Links the active, unlocked vault to the signed-in account after its master password was typed
/// once. The account's recovery copy goes into the header.
#[tauri::command]
pub async fn vault_link(app: AppHandle, master_password: String, password: Option<String>) -> Res<Value> {
    let master_password = Zeroizing::new(master_password);
    let password = password.map(Zeroizing::new);
    blocking(move || {
        let state = app_state(&app);
        let me = signed_in(&app)?;
        let agent = state.require_agent()?;
        let vault = agent.vault().ok_or_else(|| crate::state::VAULT_LOCKED.to_string())?;
        if vault.account_link().is_some() {
            return Err(tr!("account_keys.already_linked"));
        }
        let id = vaults::active_id(&state)?;
        if let Some(reason) = crate::password_mode::rule(&app).link_refusal(&id) {
            return Err(reason);
        }
        let bytes = agent.vault_file_bytes().ok_or_else(|| tr!("unlock.missing_file"))?;
        let device_id = state.settings().device_id;
        pass_core::Vault::unlock(bytes, master_password.to_string(), device_id).map_err(pass_err)?;
        let ak = key_now(&app, &me.id, password.as_deref().map(|p| p.as_str()))?;
        vault.link_to_account(&ak).map_err(pass_err)?;
        if let Some(copy) = device::load(&me.id).recovery {
            let _ = vault.set_account_recovery(copy.rec_id, copy.wrap);
        }
        agent.save().map_err(pass_err)?;
        hold(ak);
        state.update_settings(|s| {
            if let Some(v) = s.vaults.iter_mut().find(|v| v.id == id) {
                v.linked_account = Some(me.id.clone());
                v.windows_hello = false;
            }
            Ok(())
        })?;
        // Its own Windows Hello blob held the vault key for the master password: the account's
        // key opens it now.
        hello::remove(&id);
        crate::teams_vaults::refresh_soon(&app);
        Ok(json!({}))
    })
    .await
}

/// "Not now" on the link offer for the active vault.
#[tauri::command]
pub async fn vault_link_decline(app: AppHandle) -> Res<Value> {
    blocking(move || {
        let state = app_state(&app);
        let me = signed_in(&app)?;
        let id = vaults::active_id(&state)?;
        device::update(&me.id, |c| {
            if !c.link_declined.contains(&id) {
                c.link_declined.push(id.clone());
            }
        })?;
        Ok(json!({}))
    })
    .await
}

/// "Use a separate password" for the active linked vault: back to its own master password with a
/// new vault key, cut off from the account. A Team's password mode can refuse it
/// ([`crate::password_mode::Rule::unlink_refusal`]).
#[tauri::command]
pub async fn vault_unlink(app: AppHandle, new_password: String) -> Res<Value> {
    let new_password = Zeroizing::new(new_password);
    blocking(move || {
        let state = app_state(&app);
        let agent = state.require_agent()?;
        let vault = agent.vault().ok_or_else(|| crate::state::VAULT_LOCKED.to_string())?;
        if vault.account_link().is_none() {
            return Err(tr!("account_keys.not_linked"));
        }
        let id = vaults::active_id(&state)?;
        if let Some(reason) = crate::password_mode::rule(&app).unlink_refusal(&id, vault.holds_sharing_keys()) {
            return Err(reason);
        }
        crate::commands::check_new_master_password(&state, &new_password, &[], true)?;
        crate::teams::check_master_password(&app, &new_password)?;
        if let Some(link) = vault.account_link() {
            refuse_account_password(&state, &link.account, &new_password)?;
        }
        vault.unlink_from_account(new_password.to_string()).map_err(pass_err)?;
        agent.save().map_err(pass_err)?;
        state.update_settings(|s| {
            if let Some(v) = s.vaults.iter_mut().find(|v| v.id == id) {
                v.linked_account = None;
                v.note_master_password_changed();
            }
            Ok(())
        })?;
        crate::recovery::grant(&id);
        // Its emergency grants held the old vault key: renew them with the new one.
        crate::teams_send::renew_soon(&app);
        crate::teams_vaults::refresh_soon(&app);
        // Windows Hello's copy of the old vault key opens nothing now.
        let warning = crate::password_change::renew_hello(&state, &agent, &id);
        Ok(json!({ "warning": warning }))
    })
    .await
}

/// A new vault linked to the signed-in account from the start (the account key must be open:
/// the window asks for the Passyble password first, [`PASSWORD_NEEDED`]).
#[tauri::command]
pub async fn setup_create_linked(app: AppHandle, path: String, name: Option<String>, password: Option<String>) -> Res<Value> {
    let password = password.map(Zeroizing::new);
    blocking(move || {
        let path = crate::commands::normalize_vault_path(&path)?;
        create_linked(&app, path, name, password.as_deref().map(|p| p.as_str()), None)?;
        Ok(json!({ "warning": null }))
    })
    .await
}

/// Creates a vault at `path` that opens with the signed-in account's Passyble password, syncing
/// with `webdav` (and its token) when given: its agent and list id.
pub(crate) fn create_linked(
    app: &AppHandle,
    path: std::path::PathBuf,
    name: Option<String>,
    password: Option<&str>,
    webdav: Option<(crate::settings::WebDavSettings, String)>,
) -> Res<(Arc<pass_agent::Agent>, String)> {
    let me = signed_in(app)?;
    let ak = key_now(app, &me.id, password)?;
    if path.exists() {
        return Err(tr!("errors.file_exists"));
    }
    let (agent, id) = crate::commands::prepare_agent(app, path, name, webdav)?;
    agent.create_vault_for_account(&ak).map_err(pass_err)?;
    if let Some(copy) = device::load(&me.id).recovery {
        if let Some(v) = agent.vault() {
            if v.set_account_recovery(copy.rec_id, copy.wrap).is_ok() {
                let _ = agent.save();
            }
        }
    }
    hold(ak);
    let state = app_state(app);
    state.update_settings(|s| {
        if let Some(v) = s.vaults.iter_mut().find(|v| v.id == id) {
            v.linked_account = Some(me.id.clone());
        }
        Ok(())
    })?;
    vaults::mark_opened(&state, &id);
    Ok((agent, id))
}

/// A new password (and with `new_secret_key` a new Secret Key) for the same account key: the body
/// of `PUT /v1/account-key/password`. `old`: the current password's sign-in signature over an
/// `unlock` nonce (empty device name and platform), else the session must be fresh.
fn change_body(ak: &AccountKey, derived: &AccountPassword, new_sk: Option<&SecretKey>, old: Option<(String, String)>, sign_out_others: bool) -> Res<Value> {
    let mut body = json!({
        "ak_id": ak.ak_id(),
        "salt": derived.salt(),
        "kdf": derived.kdf(),
        "auth_pub": derived.auth_pub(),
        "pw_wrap": ak.password_wrap(derived).map_err(key_err)?,
        "sign_out_others": sign_out_others,
    });
    if let Some(sk) = new_sk {
        body["sk_wrap"] = json!(ak.secret_key_wrap(sk).map_err(key_err)?);
    }
    if let Some((nonce, sig)) = old {
        body["old_nonce"] = json!(nonce);
        body["old_sig"] = json!(sig);
    }
    Ok(body)
}

/// The current password's proof for a change: its sign-in signature over a fresh `unlock` nonce.
fn old_password_proof(app: &AppHandle, me: &AccountSettings, password: &str, sk: &SecretKey) -> Res<(String, String)> {
    let status = with_api(app, |api, _| api::status(api))?;
    let current = AccountPassword::new(password.to_string(), sk, status.salt.unwrap_or_default(), status.kdf.unwrap_or_default())
        .map_err(key_err)?;
    let nonce = with_api(app, |api, _| api::nonce(api, "unlock"))?;
    let sig = current
        .sign_in(me.email.clone(), nonce.clone(), String::new(), String::new())
        .map_err(key_err)?;
    Ok((nonce, sig))
}

#[allow(clippy::too_many_arguments)]
fn put_password(
    app: &AppHandle,
    me: &AccountSettings,
    ak: &AccountKey,
    new_password: &str,
    new_sk: Option<&SecretKey>,
    current_sk: &SecretKey,
    old: Option<(String, String)>,
    sign_out_others: bool,
) -> Res<Value> {
    let sk = new_sk.unwrap_or(current_sk);
    let derived = AccountPassword::with_new_salt(new_password.to_string(), sk, None).map_err(key_err)?;
    let body = change_body(ak, &derived, new_sk, old, sign_out_others)?;
    let answer = with_api(app, |api, _| api::signed(api, ak, "PUT", "/account-key/password", &body))?;
    if let Some(sk) = new_sk {
        device::keep_secret_key(&me.id, sk)?;
    }
    device::update(&me.id, |c| {
        c.email = me.email.clone();
        c.take_blobs(&KeyBlobs {
            ak_id: ak.ak_id(),
            salt: derived.salt(),
            kdf: Some(derived.kdf()),
            pw_wrap: serde_json::from_value(body["pw_wrap"].clone()).ok(),
            sk_wrap: serde_json::from_value(body["sk_wrap"].clone()).ok(),
        });
    })?;
    hello::account_password_used(&me.id);
    Ok(answer)
}

/// Change the Passyble password: the old password proves it and opens the key. No vault changes;
/// other devices keep their account key.
#[tauri::command]
pub async fn account_password_change(app: AppHandle, old_password: String, new_password: String, sign_out_others: Option<bool>) -> Res<Value> {
    let old_password = Zeroizing::new(old_password);
    let new_password = Zeroizing::new(new_password);
    blocking(move || {
        let me = signed_in(&app)?;
        check_new_password(&app, &me.email, &new_password)?;
        let sk = secret_key_for(&me.id, None)?;
        let (ak, _) = open_with_password(&app, &me.id, None, &old_password, None, None)?;
        let proof = old_password_proof(&app, &me, &old_password, &sk)?;
        let answer = put_password(&app, &me, &ak, &new_password, None, &sk, Some(proof), sign_out_others.unwrap_or(true))?;
        hold(ak);
        Ok(json!({ "signed_out": answer["signed_out"] }))
    })
    .await
}

/// "New Secret Key": the same password with a new Secret Key (and a new salt), a new `sk_wrap`, and
/// a new Emergency Kit to save (other devices pick the key up through their account key).
#[tauri::command]
pub async fn account_secret_key_replace(app: AppHandle, password: String) -> Res<Value> {
    let password = Zeroizing::new(password);
    blocking(move || {
        let me = signed_in(&app)?;
        let sk = secret_key_for(&me.id, None)?;
        let (ak, _) = open_with_password(&app, &me.id, None, &password, None, None)?;
        let proof = old_password_proof(&app, &me, &password, &sk)?;
        let new_sk = SecretKey::generate();
        put_password(&app, &me, &ak, &password, Some(&new_sk), &sk, Some(proof), false)?;
        hold(ak);
        kit_json(&me.email, &me.id, &new_sk, None)
    })
    .await
}

/// Puts the account's new recovery copy into every linked vault of this account on this PC: the
/// open one through the agent, the others' local files directly. Returns how many were updated.
fn update_recovery_copies(app: &AppHandle, ak: &AccountKey, copy: &RecoveryCopy) -> usize {
    let state = app_state(app);
    let settings = state.settings();
    let account = ak.account();
    let mut updated = 0;
    let active = settings.active_vault.clone();
    if let Some(agent) = state.agent() {
        let ak_id = ak.ak_id();
        if let Some(v) = agent
            .peek_vault()
            .filter(|v| v.account_link().is_some_and(|l| l.account == account && l.ak_id == ak_id))
        {
            if v.set_account_recovery(copy.rec_id.clone(), copy.wrap.clone()).is_ok() && agent.save().is_ok() {
                updated += 1;
            }
        }
    }
    for entry in settings.vaults.iter().filter(|v| v.linked_account.as_deref() == Some(account.as_str())) {
        if active.as_deref() == Some(entry.id.as_str()) && state.agent().is_some_and(|a| !a.is_locked()) {
            continue;
        }
        let Ok(bytes) = std::fs::read(&entry.path) else { continue };
        let Ok(v) = pass_core::Vault::unlock_with_account_key(bytes, ak, settings.device_id.clone()) else {
            continue;
        };
        if v.set_account_recovery(copy.rec_id.clone(), copy.wrap.clone()).is_ok()
            && vaults::write_vault_file(&entry.path, &v).is_ok()
        {
            updated += 1;
        }
    }
    updated
}

/// "New recovery code": a new code for the account key (the old one stops working), uploaded
/// signed, and the headers of the linked vaults this PC reaches updated. The code is shown once.
#[tauri::command]
pub async fn account_recovery_replace(app: AppHandle, password: Option<String>) -> Res<Value> {
    let password = password.map(Zeroizing::new);
    blocking(move || {
        let me = signed_in(&app)?;
        let ak = key_now(&app, &me.id, password.as_deref().map(|p| p.as_str()))?;
        let recovery = ak.new_recovery().map_err(key_err)?;
        let body = json!({ "recovery": api::recovery_json(&recovery) });
        with_api(&app, |api, _| api::signed(api, &ak, "PUT", "/account-key/recovery", &body))?;
        let copy = RecoveryCopy {
            rec_id: recovery.rec_id.clone(),
            wrap: recovery.wrap.clone(),
        };
        device::update(&me.id, |c| c.recovery = Some(copy.clone()))?;
        let updated = update_recovery_copies(&app, &ak, &copy);
        Ok(json!({ "code": recovery.code, "updated": updated }))
    })
    .await
}

/// After the account key was opened another way (the recovery code, this PC's kept key): the active
/// vault opens too when it is linked to this key and locked.
fn open_active_if_linked(app: &AppHandle, ak: &Arc<AccountKey>) -> bool {
    let state = app_state(app);
    if state.agent().is_some_and(|a| !a.is_locked()) {
        return false;
    }
    match linked_target(&state, None) {
        Ok((id, account, ak_id)) if account == ak.account() && ak_id == ak.ak_id() => unlock_with(app, &id, ak).is_ok(),
        _ => false,
    }
}

/// "Forgot your password?" with the recovery code: a fresh sign-in and the code sign the service's
/// challenge, the recovery wrap gives the account key here, and the new password is uploaded signed.
#[tauri::command]
pub async fn account_recovery_reset(app: AppHandle, code: String, new_password: String) -> Res<Value> {
    let code = Zeroizing::new(code);
    let new_password = Zeroizing::new(new_password);
    blocking(move || {
        let me = signed_in(&app)?;
        if !pass_core::recovery_code_valid_format(code.to_string()) {
            return Err(tr!("account_keys.recovery_code_typo"));
        }
        check_new_password(&app, &me.email, &new_password)?;
        let challenge = with_api(&app, |api, _| api::recovery_challenge(api))?;
        let sig = pass_core::account_recovery_sign(code.to_string(), me.id.clone(), challenge.rec_id.clone(), challenge.challenge.clone())
            .map_err(key_err)?;
        let opened = with_api(&app, |api, _| api::recovery_open(api, &challenge.challenge, &sig))?;
        let ak = pass_core::account_key_open_recovery(me.id.clone(), opened.ak_id.clone(), code.to_string(), opened.rec_id.clone(), opened.wrap.clone())
            .map_err(wrong_code)?;
        let sk = ak.open_secret_key(opened.sk_wrap.clone()).map_err(key_err)?;
        put_password(&app, &me, &ak, &new_password, None, &sk, None, true)?;
        device::keep_secret_key(&me.id, &sk)?;
        device::update(&me.id, |c| {
            c.sk_wrap = Some(opened.sk_wrap.clone());
            c.recovery = Some(RecoveryCopy { rec_id: opened.rec_id.clone(), wrap: opened.wrap.clone() });
        })?;
        hold(ak.clone());
        let warning = keep_on_device(&app, &ak, false);
        let unlocked = open_active_if_linked(&app, &ak);
        Ok(json!({ "unlocked": unlocked, "warning": warning }))
    })
    .await
}

/// "Forgot your password?" on a PC that keeps the account key: Windows Hello opens it, a fresh
/// sign-in authorizes the change, and the new password is uploaded signed. The Secret Key stays.
#[tauri::command]
pub async fn account_reset_from_device(app: AppHandle, new_password: String) -> Res<Value> {
    let new_password = Zeroizing::new(new_password);
    blocking(move || {
        let state = app_state(&app);
        let me = signed_in(&app)?;
        check_new_password(&app, &me.email, &new_password)?;
        let cache = device::load(&me.id);
        if cache.ak_id.is_empty() || hello::account_kept(&me.id).is_none() {
            return Err(tr!("account_keys.not_kept_here"));
        }
        let ak = open_kept(&state, &me.id, &cache.ak_id)?;
        let sk = secret_key_here(&me.id, &ak)?;
        put_password(&app, &me, &ak, &new_password, None, &sk, None, true)?;
        hold(ak.clone());
        let unlocked = open_active_if_linked(&app, &ak);
        Ok(json!({ "unlocked": unlocked }))
    })
    .await
}

/// How this PC keeps the account key: `hello` (Windows Hello, the default), `remember` (DPAPI
/// only, no gesture) or `off`. Turning one on keeps the key now (it must be open, or `password`).
#[tauri::command]
pub async fn account_device_key_set(app: AppHandle, mode: String, password: Option<String>) -> Res<Value> {
    let password = password.map(Zeroizing::new);
    blocking(move || {
        let me = signed_in(&app)?;
        let mode = match mode.as_str() {
            "hello" => DeviceKey::Hello,
            "remember" => DeviceKey::Remember,
            _ => DeviceKey::Off,
        };
        if mode == DeviceKey::Off {
            device::update(&me.id, |c| c.device_key = mode)?;
            hello::account_forget(&me.id);
            return Ok(json!({ "warning": null }));
        }
        let ak = key_now(&app, &me.id, password.as_deref().map(|p| p.as_str()))?;
        device::update(&me.id, |c| c.device_key = mode)?;
        let warning = keep_on_device(&app, &ak, true);
        Ok(json!({ "warning": warning }))
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_fingerprint_matches_the_core() {
        let ak = AccountKey::generate("acc_demo".into()).unwrap();
        assert_eq!(fingerprint_of(&ak.ak_id()).unwrap(), ak.fingerprint());
        assert_eq!(fingerprint_of("short"), None);
    }

    #[test]
    fn a_new_password_needs_a_new_salt_and_opens_the_same_key() {
        // The body of a password change: the same AK, a wrap the new password opens.
        let ak = AccountKey::generate("acc_demo".into()).unwrap();
        let sk = SecretKey::generate();
        let fast = pass_core::AccountKdf::default();
        let derived = AccountPassword::with_new_salt("a new demo passphrase 42".into(), &sk, Some(fast.clone())).unwrap();
        let body = change_body(&ak, &derived, None, Some(("n".into(), "s".into())), true).unwrap();
        assert_eq!(body["ak_id"], ak.ak_id());
        assert_eq!(body["old_nonce"], "n");
        assert!(body.get("sk_wrap").is_none());
        let wrap: pass_core::AccountWrap = serde_json::from_value(body["pw_wrap"].clone()).unwrap();
        let again = AccountPassword::new("a new demo passphrase 42".into(), &sk, body["salt"].as_str().unwrap().into(), fast).unwrap();
        let opened = again.open_account_key("acc_demo".into(), ak.ak_id(), wrap).unwrap();
        assert_eq!(opened.to_bytes(), ak.to_bytes());
        // With a new Secret Key the body carries its wrap under the same AK.
        let new_sk = SecretKey::generate();
        let body = change_body(&ak, &derived, Some(&new_sk), None, false).unwrap();
        let sk_wrap: pass_core::AccountWrap = serde_json::from_value(body["sk_wrap"].clone()).unwrap();
        assert_eq!(ak.open_secret_key(sk_wrap).unwrap().text(), new_sk.text());
        assert!(body.get("old_sig").is_none());
    }

    #[test]
    fn errors_the_windows_act_on_keep_their_codes() {
        let refused = |code: &str| ApiError::Refused {
            status: 403,
            code: code.into(),
            message: String::new(),
            limit: None,
        };
        assert_eq!(api_err(refused("reauth_required")), REAUTH);
        assert_eq!(api_err(refused("wrong_password")), tr!("account_keys.wrong_password"));
        assert_eq!(key_err(PassError::InvalidPassword), tr!("account_keys.wrong_password"));
    }
}
