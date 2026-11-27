//! The account service's routes for the Passyble password,
//! as plain functions over [`Transport`] so tests answer with fixed JSON.
//!
//! Every request that adds or replaces a key blob is signed with the account key's `ak_sign`
//! over a fresh nonce, the method, the path and the exact body bytes ([`signed`]); the signature
//! goes in `X-Pass-Key-Nonce` and `X-Pass-Key-Sig`. A new device without a session sends its poll
//! token in `X-Pass-Request-Token`.

use pass_core::{AccountKdf, AccountKey, AccountRecovery, AccountWrap};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::account::{self, Tokens};
use crate::teams_api::{parse_answer, segment, AccountApi, ApiError, Request, Transport};

pub const NONCE_HEADER: &str = "X-Pass-Key-Nonce";
pub const SIG_HEADER: &str = "X-Pass-Key-Sig";
pub const REQUEST_TOKEN_HEADER: &str = "X-Pass-Request-Token";

/// The platform a sign-in signs (`windows`, `macos`, `linux`).
pub fn platform() -> String {
    std::env::consts::OS.to_string()
}

/// The device name as the service reads it before checking a sign-in signature (trimmed, no
/// control characters, at most 64 characters, "Passyble" when empty): the signed name must be the
/// same.
pub fn device_name() -> String {
    let name: String = crate::account::device_name()
        .trim()
        .chars()
        .filter(|c| !c.is_control())
        .take(64)
        .collect();
    if name.is_empty() {
        "Passyble".into()
    } else {
        name
    }
}

/// An e-mail address as the service keeps it (trimmed, lower case): what a sign-in signs.
pub fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

fn typed<T: serde::de::DeserializeOwned>(v: Value) -> Result<T, ApiError> {
    serde_json::from_value(v)
        .map_err(|_| ApiError::Unexpected(crate::i18n::tr!("errors.teams_unexpected_answer")))
}

/// A request to the service without a session (prelogin, a password sign-in, a new device).
fn anon(
    t: &dyn Transport,
    base: &str,
    method: &'static str,
    path: &str,
    body: Option<Value>,
    headers: Vec<(&'static str, Zeroizing<String>)>,
) -> Result<Value, ApiError> {
    let answer = t.send(&Request {
        method,
        url: format!("{}/v1{path}", base.trim_end_matches('/')),
        auth: None,
        body: body.map(|b| ("application/json", b.to_string().into_bytes())),
        pins: Vec::new(),
        headers,
    })?;
    parse_answer(&answer)
}

/// The salt and parameters of an account's password, and a single-use sign-in nonce.
#[derive(Clone, Debug, Deserialize)]
pub struct Prelogin {
    pub salt: String,
    pub kdf: AccountKdf,
    pub nonce: String,
}

/// `POST /v1/prelogin { email }` (the same answer for every address).
pub fn prelogin(t: &dyn Transport, base: &str, email: &str) -> Result<Prelogin, ApiError> {
    typed(anon(t, base, "POST", "/prelogin", Some(json!({ "email": email })), Vec::new())?)
}

/// The account key's blobs as the service hands them to a device that proved the password:
/// `account_key { ak_id, salt, kdf, pw_wrap, sk_wrap }`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct KeyBlobs {
    pub ak_id: String,
    pub salt: String,
    pub kdf: Option<AccountKdf>,
    pub pw_wrap: Option<AccountWrap>,
    pub sk_wrap: Option<AccountWrap>,
}

/// `POST /v1/session/password`: a new app session (the token answer) and the account's key
/// blobs. `wrong_password` for a wrong address, password or Secret Key alike.
pub fn session_password(
    t: &dyn Transport,
    base: &str,
    email: &str,
    nonce: &str,
    sig: &str,
    device_name: &str,
) -> Result<(Tokens, KeyBlobs), ApiError> {
    let body = json!({
        "client_id": account::CLIENT_ID,
        "email": email,
        "nonce": nonce,
        "sig": sig,
        "device_name": device_name,
        "platform": platform(),
    });
    let v = anon(t, base, "POST", "/session/password", Some(body), Vec::new())?;
    let blobs: KeyBlobs = typed(v.get("account_key").cloned().unwrap_or(Value::Null))?;
    let answer = crate::teams_api::Answer {
        status: 200,
        error_code: None,
        body: v.to_string(),
    };
    let tokens = account::parse_tokens(&answer).map_err(|e| ApiError::Unexpected(e.message()))?;
    Ok((tokens, blobs))
}

/// What `GET /v1/account-key` says is set up (never a blob).
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct KeyStatus {
    pub set: bool,
    pub ak_id: Option<String>,
    pub salt: Option<String>,
    pub kdf: Option<AccountKdf>,
    pub state: Option<String>,
    pub recovery: Option<RecoveryStatus>,
    /// An e-mail reset is waiting (`state = reset_waiting`): when it started and when the new
    /// keys may be set.
    pub reset_started_at: Option<i64>,
    pub reset_release_at: Option<i64>,
    /// How many key sets an e-mail reset locked.
    pub locked_key_sets: Option<u32>,
}

impl KeyStatus {
    pub fn reset_waiting(&self) -> bool {
        self.state.as_deref() == Some("reset_waiting")
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct RecoveryStatus {
    pub rec_id: String,
    pub created_at: Option<i64>,
}

pub fn status(api: &AccountApi<'_>) -> Result<KeyStatus, ApiError> {
    typed(api.call("GET", "/account-key", None)?)
}

/// `POST /v1/account-key/nonce { purpose }`: `key_change` (for [`signed`]) or `unlock` (a
/// sign-in signature from a signed-in app).
pub fn nonce(api: &AccountApi<'_>, purpose: &str) -> Result<String, ApiError> {
    let v = api.call("POST", "/account-key/nonce", Some(json!({ "purpose": purpose })))?;
    v["nonce"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| ApiError::Unexpected(crate::i18n::tr!("errors.teams_unexpected_answer")))
}

/// A key change signed with the account key: a fresh `key_change` nonce, then the signature over
/// it, the method, the path (`/v1...`) and these exact body bytes.
pub fn signed(
    api: &AccountApi<'_>,
    ak: &AccountKey,
    method: &'static str,
    path: &str,
    body: &Value,
) -> Result<Value, ApiError> {
    signed_bytes(api, ak, method, path, body.to_string().into_bytes())
}

/// [`signed`] over raw body bytes; an empty body is sent as none (a signed `DELETE`).
pub fn signed_bytes(
    api: &AccountApi<'_>,
    ak: &AccountKey,
    method: &'static str,
    path: &str,
    bytes: Vec<u8>,
) -> Result<Value, ApiError> {
    let n = nonce(api, "key_change")?;
    let sig = ak
        .sign_request(n.clone(), method.into(), format!("/v1{path}"), bytes.clone())
        .map_err(|e| ApiError::Unexpected(crate::commands::pass_err(e)))?;
    api.call_bytes(
        method,
        path,
        (!bytes.is_empty()).then_some(bytes),
        vec![
            (NONCE_HEADER, Zeroizing::new(n)),
            (SIG_HEADER, Zeroizing::new(sig)),
        ],
    )
}

/// The recovery part of a setup or a new code: `{ rec_id, verify_pub, wrap }` (never the code).
pub fn recovery_json(r: &AccountRecovery) -> Value {
    json!({ "rec_id": r.rec_id, "verify_pub": r.verify_pub, "wrap": r.wrap })
}

/// The body of `POST /v1/account-key` (the first Passyble password and keys).
pub fn setup_body(
    ak: &AccountKey,
    password: &pass_core::AccountPassword,
    sk_wrap: &AccountWrap,
    pw_wrap: &AccountWrap,
    recovery: &AccountRecovery,
) -> Value {
    json!({
        "ak_id": ak.ak_id(),
        "ak_sign_pub": ak.ak_sign_pub(),
        "salt": password.salt(),
        "kdf": password.kdf(),
        "auth_pub": password.auth_pub(),
        "pw_wrap": pw_wrap,
        "sk_wrap": sk_wrap,
        "recovery": recovery_json(recovery),
    })
}

/// `POST /v1/account-key/unlock { nonce, sig, device_name, platform }`: the blobs again for a
/// signed-in app that proved the password (a changed password, a lost cache).
pub fn unlock(
    api: &AccountApi<'_>,
    nonce: &str,
    sig: &str,
    device_name: &str,
) -> Result<KeyBlobs, ApiError> {
    let v = api.call(
        "POST",
        "/account-key/unlock",
        Some(json!({ "nonce": nonce, "sig": sig, "device_name": device_name, "platform": platform() })),
    )?;
    typed(v.get("account_key").cloned().unwrap_or(Value::Null))
}

#[derive(Clone, Debug, Deserialize)]
pub struct Challenge {
    pub challenge: String,
    pub rec_id: String,
}

/// `POST /v1/account-key/recovery/challenge` (a fresh app session).
pub fn recovery_challenge(api: &AccountApi<'_>) -> Result<Challenge, ApiError> {
    typed(api.call("POST", "/account-key/recovery/challenge", Some(json!({})))?)
}

#[derive(Clone, Debug, Deserialize)]
pub struct RecoveryOpened {
    pub rec_id: String,
    pub ak_id: String,
    pub wrap: AccountWrap,
    pub sk_wrap: AccountWrap,
}

/// `POST /v1/account-key/recovery/open { challenge, sig }`: the recovery wrap and `sk_wrap`.
pub fn recovery_open(
    api: &AccountApi<'_>,
    challenge: &str,
    sig: &str,
) -> Result<RecoveryOpened, ApiError> {
    typed(api.call(
        "POST",
        "/account-key/recovery/open",
        Some(json!({ "challenge": challenge, "sig": sig })),
    )?)
}

/// `GET /v1/pwned/<prefix>`: the padded Pwned Passwords range (only the 5-character prefix leaves
/// this PC).
pub fn pwned(api: &AccountApi<'_>, prefix: &str) -> Result<String, ApiError> {
    api.get_text(&format!("/pwned/{}", segment(prefix)))
}

/// `POST /v1/account-key/reset` (an app session signed in within 10 minutes): the 72-hour wait
/// starts. `{ state, reset_started_at, reset_release_at }`.
pub fn reset_start(api: &AccountApi<'_>) -> Result<KeyStatus, ApiError> {
    typed(api.call("POST", "/account-key/reset", None)?)
}

/// How a waiting reset is cancelled: this PC's account key (`device`, signed with `ak_sign`), or
/// the recovery code's signature over a challenge (`recovery`).
pub enum CancelBy<'a> {
    Device(&'a AccountKey),
    Recovery { challenge: &'a str, sig: &'a str },
}

/// `POST /v1/account-key/reset/cancel { by, challenge?, sig? }` -> `{ state: "active", by,
/// signed_out }`.
pub fn reset_cancel(api: &AccountApi<'_>, by: CancelBy<'_>) -> Result<Value, ApiError> {
    const PATH: &str = "/account-key/reset/cancel";
    match by {
        CancelBy::Device(ak) => signed(api, ak, "POST", PATH, &json!({ "by": "device" })),
        CancelBy::Recovery { challenge, sig } => api.call(
            "POST",
            PATH,
            Some(json!({ "by": "recovery", "challenge": challenge, "sig": sig })),
        ),
    }
}

/// `POST /v1/account-key/reset/complete` after the wait: the whole new key set ([`setup_body`]),
/// signed with the new key's `ak_sign`. `{ ak_id, locked_key_set: { id, ak_id, locked_at },
/// signed_out }`.
pub fn reset_complete(api: &AccountApi<'_>, new_ak: &AccountKey, body: &Value) -> Result<Value, ApiError> {
    signed(api, new_ak, "POST", "/account-key/reset/complete", body)
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct RecoveryRef {
    pub rec_id: String,
}

/// A locked key set as `GET /v1/account-key/locked` lists it (never a blob).
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct LockedSet {
    pub id: String,
    pub ak_id: String,
    pub locked_at: i64,
    pub password: bool,
    pub recovery: Option<RecoveryRef>,
    pub passkeys: u32,
    /// The organisations whose admin recovery enrolment names this key.
    pub admin_recovery: Vec<String>,
}

pub fn locked_list(api: &AccountApi<'_>) -> Result<Vec<LockedSet>, ApiError> {
    let v = api.call("GET", "/account-key/locked", None)?;
    typed(v.get("locked").cloned().unwrap_or(json!([])))
}

/// `POST /v1/account-key/locked/<id>/nonce`: a nonce for this set (2 minutes) and what the old
/// password needs (its salt and parameters) or the old recovery code signs (`rec_id`).
#[derive(Clone, Debug, Deserialize)]
pub struct LockedNonce {
    pub nonce: String,
    #[serde(default)]
    pub salt: String,
    #[serde(default)]
    pub kdf: Option<AccountKdf>,
    #[serde(default)]
    pub rec_id: Option<String>,
}

pub fn locked_nonce(api: &AccountApi<'_>, id: &str) -> Result<LockedNonce, ApiError> {
    typed(api.call("POST", &format!("/account-key/locked/{}/nonce", segment(id)), None)?)
}

/// What `.../locked/<id>/open` hands out: with the old password `pw_wrap` (and `sk_wrap`), with
/// the old recovery code `rec_id` and `wrap`.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct LockedOpened {
    pub ak_id: String,
    pub pw_wrap: Option<AccountWrap>,
    pub sk_wrap: Option<AccountWrap>,
    pub rec_id: Option<String>,
    pub wrap: Option<AccountWrap>,
}

/// `POST /v1/account-key/locked/<id>/open { by: password | recovery, nonce, sig }`.
pub fn locked_open(api: &AccountApi<'_>, id: &str, by: &str, nonce: &str, sig: &str) -> Result<LockedOpened, ApiError> {
    typed(api.call(
        "POST",
        &format!("/account-key/locked/{}/open", segment(id)),
        Some(json!({ "by": by, "nonce": nonce, "sig": sig })),
    )?)
}

/// `DELETE /v1/account-key/locked/<id>`, signed with the current account key (an empty body).
pub fn locked_delete(api: &AccountApi<'_>, current: &AccountKey, id: &str) -> Result<Value, ApiError> {
    signed_bytes(api, current, "DELETE", &format!("/account-key/locked/{}", segment(id)), Vec::new())
}

/// A new device's request: its id and, without a session, the poll token.
#[derive(Clone, Debug, Deserialize)]
pub struct NewRequest {
    pub id: String,
    #[serde(default)]
    pub poll_token: Option<String>,
    #[serde(default)]
    pub expires_at: Option<i64>,
}

/// `POST /v1/account-key/requests` before any sign-in ("Approve from another device").
pub fn request_without_session(
    t: &dyn Transport,
    base: &str,
    email: &str,
    enc_pub: &str,
    commitment: &str,
    device_name: &str,
) -> Result<NewRequest, ApiError> {
    let body = json!({
        "enc_pub": enc_pub,
        "commitment": commitment,
        "email": email,
        "client_id": account::CLIENT_ID,
        "device_name": device_name,
        "platform": platform(),
    });
    typed(anon(t, base, "POST", "/account-key/requests", Some(body), Vec::new())?)
}

/// `GET /v1/account-key/requests/<id>` by the new device with its poll token: the state, `r_a`,
/// once sealed the keys and (it had no session) `session`, its new app session's tokens.
pub fn request_poll(t: &dyn Transport, base: &str, id: &str, poll_token: &str) -> Result<Value, ApiError> {
    anon(
        t,
        base,
        "GET",
        &format!("/account-key/requests/{}", segment(id)),
        None,
        vec![(REQUEST_TOKEN_HEADER, Zeroizing::new(poll_token.to_string()))],
    )
}

/// `POST /v1/account-key/requests/<id>/reveal { r_n }` (the code variant, after `r_a` came).
pub fn request_reveal(
    t: &dyn Transport,
    base: &str,
    id: &str,
    poll_token: &str,
    r_n: &str,
) -> Result<Value, ApiError> {
    anon(
        t,
        base,
        "POST",
        &format!("/account-key/requests/{}/reveal", segment(id)),
        Some(json!({ "r_n": r_n })),
        vec![(REQUEST_TOKEN_HEADER, Zeroizing::new(poll_token.to_string()))],
    )
}

/// The account's open requests and joined invitations (an existing device).
pub fn requests(api: &AccountApi<'_>) -> Result<Vec<Value>, ApiError> {
    let v = api.call("GET", "/account-key/requests", None)?;
    Ok(v["requests"].as_array().cloned().unwrap_or_default())
}

pub fn request_step(api: &AccountApi<'_>, id: &str, step: &str, body: Value) -> Result<Value, ApiError> {
    api.call(
        "POST",
        &format!("/account-key/requests/{}/{step}", segment(id)),
        Some(body),
    )
}

/// `POST /v1/account-key/invitations { token }`: the invitation's id (2 minutes).
pub fn invitation_create(api: &AccountApi<'_>, token: &str) -> Result<NewRequest, ApiError> {
    typed(api.call("POST", "/account-key/invitations", Some(json!({ "token": token })))?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::teams_api::tests::Fake;

    #[test]
    fn signed_changes_carry_the_nonce_and_a_signature_over_the_exact_body() {
        let ak = AccountKey::generate("acc_demo".into()).unwrap();
        let fake = Fake::with(vec![
            (200, r#"{"nonce":"n_1","expires_at":1}"#),
            (200, r#"{"rec_id":"r_2"}"#),
        ]);
        let api = AccountApi::new("https://account.example", "pat_demo", &fake);
        let body = json!({ "recovery": { "rec_id": "r_2" } });
        signed(&api, &ak, "PUT", "/account-key/recovery", &body).unwrap();
        let seen = fake.requests();
        assert_eq!(seen[0].url, "https://account.example/v1/account-key/nonce");
        assert_eq!(seen[0].json()["purpose"], "key_change");
        let put = &seen[1];
        assert_eq!(put.method, "PUT");
        assert_eq!(put.url, "https://account.example/v1/account-key/recovery");
        let bytes = put.body.clone().unwrap().1;
        let header = |n: &str| {
            put.headers
                .iter()
                .find(|(k, _)| *k == n)
                .map(|(_, v)| v.to_string())
                .unwrap()
        };
        assert_eq!(header(NONCE_HEADER), "n_1");
        assert!(pass_core::account_request_verify(
            &ak.ak_sign_pub(),
            "acc_demo",
            "n_1",
            "PUT",
            "/v1/account-key/recovery",
            &bytes,
            &header(SIG_HEADER),
        ));
    }

    #[test]
    fn a_password_sign_in_gives_tokens_and_the_key_blobs() {
        let fake = Fake::with(vec![(
            200,
            r#"{ "access_token": "pat_1", "expires_in": 900, "refresh_token": "prt_1",
                 "account": { "id": "acc_1", "email": "demo@example.com" },
                 "account_key": { "ak_id": "AK", "salt": "S", "kdf": { "alg": "argon2id", "m_kib": 65536, "t": 3, "p": 1 },
                                  "pw_wrap": { "nonce": "N", "ct": "C" }, "sk_wrap": { "nonce": "N2", "ct": "C2" } } }"#,
        )]);
        let (tokens, blobs) =
            session_password(&fake, "https://a.example", "demo@example.com", "n", "sig", "Passyble on PC").unwrap();
        assert_eq!(tokens.account_id, "acc_1");
        assert_eq!(blobs.ak_id, "AK");
        assert_eq!(blobs.kdf.unwrap().m_kib, 65536);
        let body = fake.requests()[0].json();
        assert_eq!(body["client_id"], account::CLIENT_ID);
        assert_eq!(body["platform"], platform());
        assert_eq!(fake.requests()[0].url, "https://a.example/v1/session/password");
        assert!(fake.requests()[0].auth.is_none());

        let refused = Fake::with(vec![(403, r#"{"error":"wrong_password"}"#)]);
        let e = session_password(&refused, "https://a.example", "x@example.com", "n", "s", "d").err().unwrap();
        assert_eq!(e.code(), "wrong_password");
    }

    #[test]
    fn signed_values_match_what_the_service_checks() {
        assert_eq!(normalize_email("  Demo@Example.COM "), "demo@example.com");
        let name = device_name();
        assert!(!name.is_empty() && name.chars().count() <= 64);
        assert_eq!(name, name.trim());
    }

    #[test]
    fn a_reset_is_cancelled_by_this_pcs_key_and_locked_sets_are_deleted_signed() {
        let ak = AccountKey::generate("acc_demo".into()).unwrap();
        let fake = Fake::with(vec![
            (200, r#"{"nonce":"n_1"}"#),
            (200, r#"{"state":"active","by":"device","signed_out":true}"#),
            (200, r#"{"nonce":"n_2"}"#),
            (204, ""),
        ]);
        let api = AccountApi::new("https://a.example", "pat_demo", &fake);
        let v = reset_cancel(&api, CancelBy::Device(&ak)).unwrap();
        assert_eq!(v["state"], "active");
        locked_delete(&api, &ak, "lks 1").unwrap();
        let seen = fake.requests();
        assert_eq!(seen[1].url, "https://a.example/v1/account-key/reset/cancel");
        assert_eq!(seen[1].json()["by"], "device");
        let del = &seen[3];
        assert_eq!(del.method, "DELETE");
        assert_eq!(del.url, "https://a.example/v1/account-key/locked/lks%201");
        assert!(del.body.is_none(), "a signed DELETE sends no body");
        let sig = del.headers.iter().find(|(k, _)| *k == SIG_HEADER).map(|(_, v)| v.to_string()).unwrap();
        assert!(pass_core::account_request_verify(
            &ak.ak_sign_pub(),
            "acc_demo",
            "n_2",
            "DELETE",
            "/v1/account-key/locked/lks%201",
            b"",
            &sig,
        ));
    }

    #[test]
    fn the_status_and_locked_sets_read_the_reset_fields() {
        let s: KeyStatus = serde_json::from_str(
            r#"{"set":true,"ak_id":"A","state":"reset_waiting","reset_started_at":5,"reset_release_at":9,"locked_key_sets":1}"#,
        )
        .unwrap();
        assert!(s.reset_waiting());
        assert_eq!(s.reset_release_at, Some(9));
        let fake = Fake::with(vec![(
            200,
            r#"{"locked":[{"id":"lks_1","ak_id":"OLD","locked_at":7,"password":true,"recovery":{"rec_id":"r"},"passkeys":0,"admin_recovery":["g1"]}]}"#,
        )]);
        let api = AccountApi::new("https://a.example", "pat_demo", &fake);
        let list = locked_list(&api).unwrap();
        assert_eq!(list[0].ak_id, "OLD");
        assert_eq!(list[0].recovery.as_ref().unwrap().rec_id, "r");
        assert_eq!(list[0].admin_recovery, ["g1"]);
    }

    #[test]
    fn a_new_device_polls_with_its_token_header() {
        let fake = Fake::with(vec![(200, r#"{"id":"akq_1","state":"waiting"}"#)]);
        request_poll(&fake, "https://a.example/", "akq_1", "akp_secret").unwrap();
        let r = &fake.requests()[0];
        assert_eq!(r.url, "https://a.example/v1/account-key/requests/akq_1");
        assert_eq!(r.headers[0].0, REQUEST_TOKEN_HEADER);
        assert_eq!(r.headers[0].1.as_str(), "akp_secret");
    }
}
