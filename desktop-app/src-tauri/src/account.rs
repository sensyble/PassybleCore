//! Passyble account sign-in (docs/PROTOCOL.md §4.2): OAuth 2.0 authorization code with PKCE, a
//! loopback redirect and issuer identification (`iss`, RFC 9207), client `passyble-windows`.
//!
//! The refresh token goes to Credential Manager (`Pass/PassybleAccount/<host>`) before the access
//! token is used; the access token stays in memory. Refreshes run one at a time (a second refresh of a
//! rotated token signs the session out). Neither token is ever logged.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Emitter};
use zeroize::Zeroizing;

use crate::commands::{app_state, blocking};
use crate::i18n::tr;
use crate::teams_api::{self, AccountApi, Answer, ApiError, Request, Transport};

type Res<T> = Result<T, String>;

pub const CLIENT_ID: &str = "passyble-windows";
/// How long the browser sign-in may take.
pub const SIGN_IN_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const REFRESH_MARGIN: Duration = Duration::from_secs(60);
const KEYRING_SERVICE: &str = "com.sensyble.pass.account";
const MAX_REQUEST: usize = 16 * 1024;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AccountSettings {
    pub id: String,
    pub email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloud: Option<CloudDeviceSettings>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CloudDeviceSettings {
    pub server_url: String,
    pub user: String,
    pub device_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthError {
    Cancelled,
    SignInAgain,
    Failed(String),
}

impl AuthError {
    pub fn message(&self) -> String {
        match self {
            AuthError::Cancelled => "cancelled".into(),
            AuthError::SignInAgain => tr!("errors.teams_sign_in_again"),
            AuthError::Failed(m) => m.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoints {
    pub base: String,
    pub authorize: String,
    pub token: String,
    pub revoke: String,
    pub issuer: String,
}

impl Endpoints {
    pub fn for_base(base: &str) -> Self {
        let base = base.trim().trim_end_matches('/').to_string();
        Self {
            authorize: format!("{base}/oauth/authorize"),
            token: format!("{base}/oauth/token"),
            revoke: format!("{base}/oauth/revoke"),
            issuer: origin(&base),
            base,
        }
    }
}

pub fn base_url(settings: &crate::settings::Settings) -> String {
    settings
        .account_url
        .as_deref()
        .map(str::trim)
        .filter(|u| u.starts_with("https://") || u.starts_with("http://127.0.0.1"))
        .unwrap_or(teams_api::DEFAULT_ACCOUNT_URL)
        .trim_end_matches('/')
        .to_string()
}

fn origin(url: &str) -> String {
    let (scheme, rest) = url.split_once("://").unwrap_or(("https", url));
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    format!("{scheme}://{authority}").to_ascii_lowercase()
}

fn random_b64(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    pass_core::b64url_encode(buf)
}

pub fn pkce() -> (Zeroizing<String>, String) {
    let verifier = Zeroizing::new(random_b64(32));
    let challenge = challenge_for(&verifier);
    (verifier, challenge)
}

pub fn challenge_for(verifier: &str) -> String {
    pass_core::b64url_encode(Sha256::digest(verifier.as_bytes()).to_vec())
}

pub fn encode(s: &str) -> String {
    teams_api::segment(s).replace('@', "%40")
}

pub fn authorize_url(
    ep: &Endpoints,
    redirect_uri: &str,
    challenge: &str,
    state: &str,
    device_name: &str,
) -> String {
    let params = [
        ("client_id", CLIENT_ID),
        ("redirect_uri", redirect_uri),
        ("response_type", "code"),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256"),
        ("state", state),
        ("device_name", device_name),
    ];
    let query: Vec<String> = params
        .iter()
        .map(|(k, v)| format!("{k}={}", encode(v)))
        .collect();
    format!("{}?{}", ep.authorize, query.join("&"))
}

#[derive(Debug, PartialEq, Eq)]
pub enum Callback {
    Code {
        code: String,
        state: String,
        iss: String,
    },
    Error {
        error: String,
        state: String,
        iss: String,
    },
    Other,
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => {
                match std::str::from_utf8(&bytes[i + 1..i + 3])
                    .ok()
                    .and_then(|h| u8::from_str_radix(h, 16).ok())
                {
                    Some(b) => {
                        out.push(b);
                        i += 2;
                    }
                    None => out.push(b'%'),
                }
            }
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub(crate) fn query_param(query: &str, name: &str) -> String {
    query
        .split('&')
        .filter_map(|pair| pair.split_once('=').or(Some((pair, ""))))
        .find(|(k, _)| percent_decode(k) == name)
        .map(|(_, v)| percent_decode(v))
        .unwrap_or_default()
}

pub fn parse_callback(head: &str) -> Callback {
    let line = head.lines().next().unwrap_or_default();
    let mut parts = line.split_whitespace();
    let (Some("GET"), Some(target)) = (parts.next(), parts.next()) else {
        return Callback::Other;
    };
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    if path != "/" {
        return Callback::Other;
    }
    let state = query_param(query, "state");
    let iss = query_param(query, "iss");
    let code = query_param(query, "code");
    if !code.is_empty() {
        return Callback::Code { code, state, iss };
    }
    let error = query_param(query, "error");
    if !error.is_empty() {
        return Callback::Error { error, state, iss };
    }
    Callback::Other
}

/// Constant-time comparison (the state is a secret).
fn same(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

pub fn ours(state: &str, iss: &str, expected_state: &str, issuer: &str) -> bool {
    same(state, expected_state) && origin(iss) == issuer
}

fn page(title: &str, text: &str) -> String {
    let escape = |t: &str| {
        t.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
    };
    format!(
        "<!doctype html><html lang=\"{}\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" \
content=\"width=device-width, initial-scale=1\"><title>Passyble</title><style>:root{{color-scheme:light dark}}\
body{{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;\
font:15px/1.5 system-ui,sans-serif}}main{{max-width:420px;margin:24px;padding:28px 30px;\
border:1px solid #8884;border-radius:14px}}h1{{font-size:20px;margin:0 0 8px}}p{{margin:0}}</style>\
</head><body><main><h1>{}</h1><p>{}</p></main></body></html>",
        crate::i18n::locale(),
        escape(title),
        escape(text)
    )
}

fn respond(stream: &mut TcpStream, status: &str, body: &str) {
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n\
Cache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

fn read_head(stream: &mut TcpStream) -> String {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let mut buf = Vec::new();
    let mut chunk = [0u8; 2048];
    while buf.len() < MAX_REQUEST && !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

struct Loopback {
    listener: TcpListener,
    port: u16,
}

impl Loopback {
    fn bind() -> Result<Self, AuthError> {
        let fail = |e: std::io::Error| {
            AuthError::Failed(crate::errors::logged(
                tr!("errors.account_cant_start"),
                "account sign-in",
                e,
            ))
        };
        let listener = TcpListener::bind(("127.0.0.1", 0)).map_err(fail)?;
        listener.set_nonblocking(true).map_err(fail)?;
        let port = listener.local_addr().map_err(fail)?.port();
        Ok(Self { listener, port })
    }

    fn redirect_uri(&self) -> String {
        format!("http://127.0.0.1:{}/", self.port)
    }

    fn wait_for_code(
        &self,
        state: &str,
        issuer: &str,
        timeout: Duration,
        cancel: &AtomicBool,
    ) -> Result<Zeroizing<String>, AuthError> {
        let deadline = Instant::now() + timeout;
        loop {
            if cancel.load(Ordering::Relaxed) {
                return Err(AuthError::Cancelled);
            }
            if Instant::now() >= deadline {
                return Err(AuthError::Failed(tr!("errors.account_too_long")));
            }
            let mut stream = match self.listener.accept() {
                Ok((stream, _)) => stream,
                Err(_) => {
                    std::thread::sleep(Duration::from_millis(100));
                    continue;
                }
            };
            let head = read_head(&mut stream);
            match parse_callback(&head) {
                Callback::Code {
                    code,
                    state: s,
                    iss,
                } if ours(&s, &iss, state, issuer) => {
                    respond(
                        &mut stream,
                        "200 OK",
                        &page(&tr!("google.page_signed_in"), &tr!("google.page_close_tab")),
                    );
                    return Ok(Zeroizing::new(code));
                }
                Callback::Error {
                    error,
                    state: s,
                    iss,
                } if ours(&s, &iss, state, issuer) => {
                    let cancelled = error == "access_denied";
                    respond(
                        &mut stream,
                        "200 OK",
                        &page(
                            &if cancelled {
                                tr!("google.page_cancelled")
                            } else {
                                tr!("google.page_failed")
                            },
                            &tr!("google.page_close_tab"),
                        ),
                    );
                    return Err(if cancelled {
                        AuthError::Cancelled
                    } else {
                        AuthError::Failed(crate::errors::logged(
                            tr!("errors.account_failed"),
                            "account sign-in",
                            teams_api::segment(&error),
                        ))
                    });
                }
                Callback::Code { .. } | Callback::Error { .. } => respond(
                    &mut stream,
                    "400 Bad Request",
                    &page(
                        &tr!("google.page_out_of_date"),
                        &tr!("google.page_start_again"),
                    ),
                ),
                Callback::Other => respond(&mut stream, "404 Not Found", ""),
            }
        }
    }
}

pub struct Tokens {
    pub access_token: Zeroizing<String>,
    pub expires_in: Duration,
    pub refresh_token: Zeroizing<String>,
    pub account_id: String,
    pub email: String,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct TokenAnswer {
    access_token: Option<String>,
    expires_in: Option<u64>,
    refresh_token: Option<String>,
    account: Option<AccountJson>,
    error: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct AccountJson {
    id: String,
    email: String,
}

pub fn parse_tokens(answer: &Answer) -> Result<Tokens, AuthError> {
    let t: TokenAnswer = serde_json::from_str(&answer.body).unwrap_or_default();
    if !(200..300).contains(&answer.status) {
        let code = answer.error_code.clone().or(t.error).unwrap_or_default();
        return Err(match code.as_str() {
            "invalid_grant" => AuthError::SignInAgain,
            "too_many_requests" => AuthError::Failed(tr!("errors.too_many_attempts")),
            _ => AuthError::Failed(crate::errors::logged(
                tr!("errors.account_failed"),
                "account token endpoint",
                format!("HTTP {} {}", answer.status, teams_api::segment(&code)),
            )),
        });
    }
    let access = t.access_token.filter(|a| !a.is_empty());
    let refresh = t.refresh_token.filter(|r| !r.is_empty());
    let (Some(access), Some(refresh)) = (access, refresh) else {
        return Err(AuthError::Failed(tr!("errors.account_failed")));
    };
    let account = t.account.unwrap_or_default();
    Ok(Tokens {
        access_token: Zeroizing::new(access),
        expires_in: Duration::from_secs(t.expires_in.unwrap_or(900).max(60)),
        refresh_token: Zeroizing::new(refresh),
        account_id: account.id,
        email: account.email,
    })
}

fn form(pairs: &[(&str, &str)]) -> Option<(&'static str, Vec<u8>)> {
    let body: Vec<String> = pairs
        .iter()
        .map(|(k, v)| format!("{k}={}", encode(v)))
        .collect();
    Some((
        "application/x-www-form-urlencoded",
        body.join("&").into_bytes(),
    ))
}

fn post_form(t: &dyn Transport, url: &str, pairs: &[(&str, &str)]) -> Result<Answer, AuthError> {
    t.send(&Request {
        method: "POST",
        url: url.to_string(),
        auth: None,
        body: form(pairs),
        pins: Vec::new(),
        headers: Vec::new(),
    })
    .map_err(|e| AuthError::Failed(e.message()))
}

pub fn exchange_code(
    t: &dyn Transport,
    ep: &Endpoints,
    code: &str,
    verifier: &str,
    redirect_uri: &str,
) -> Result<Tokens, AuthError> {
    let answer = post_form(
        t,
        &ep.token,
        &[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("code_verifier", verifier),
            ("client_id", CLIENT_ID),
            ("redirect_uri", redirect_uri),
        ],
    )?;
    match parse_tokens(&answer) {
        // A code is single use and lives 60 s: start again, not "signed out".
        Err(AuthError::SignInAgain) => Err(AuthError::Failed(tr!("errors.account_code_expired"))),
        other => other,
    }
}

pub fn refresh(
    t: &dyn Transport,
    ep: &Endpoints,
    refresh_token: &str,
) -> Result<Tokens, AuthError> {
    let answer = post_form(
        t,
        &ep.token,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", CLIENT_ID),
        ],
    )?;
    parse_tokens(&answer)
}

pub fn revoke(t: &dyn Transport, ep: &Endpoints, token: &str) {
    let _ = post_form(t, &ep.revoke, &[("token", token), ("client_id", CLIENT_ID)]);
}

pub(crate) trait Store: Send + Sync {
    fn get(&self, name: &str) -> Option<Zeroizing<String>>;
    fn set(&self, name: &str, secret: &str) -> Result<(), String>;
    fn delete(&self, name: &str);
}

#[cfg_attr(test, allow(dead_code))]
struct CredentialManager;

#[cfg_attr(test, allow(dead_code))]
fn entry(name: &str) -> Option<keyring::Entry> {
    crate::platform::keyring_entry(name, KEYRING_SERVICE, name).ok()
}

impl Store for CredentialManager {
    fn get(&self, name: &str) -> Option<Zeroizing<String>> {
        entry(name)?.get_password().ok().map(Zeroizing::new)
    }

    fn set(&self, name: &str, secret: &str) -> Result<(), String> {
        entry(name)
            .ok_or_else(|| tr!("errors.account_not_stored"))?
            .set_password(secret)
            .map_err(|e| {
                crate::errors::logged(tr!("errors.account_not_stored"), "Credential Manager", e)
            })
    }

    fn delete(&self, name: &str) {
        if let Some(e) = entry(name) {
            let _ = e.delete_credential();
        }
    }
}

#[cfg(not(test))]
pub(crate) fn store() -> &'static dyn Store {
    &CredentialManager
}

#[cfg(test)]
pub(crate) fn store() -> &'static dyn Store {
    tests::fake_store()
}

fn refresh_name(ep: &Endpoints) -> String {
    format!(
        "Pass/PassybleAccount/{}",
        ep.issuer.split("://").nth(1).unwrap_or_default()
    )
}

/// `Pass/PassybleCloud/<account id>`: the Passyble Cloud device token.
pub fn cloud_token_name(account_id: &str) -> String {
    format!("Pass/PassybleCloud/{account_id}")
}

struct Access {
    token: Zeroizing<String>,
    until: Instant,
}

static ACCESS: Mutex<Option<Access>> = Mutex::new(None);
static REFRESHING: Mutex<()> = Mutex::new(());
static CANCEL: Mutex<Option<std::sync::Arc<AtomicBool>>> = Mutex::new(None);

fn guard<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

fn keep(ep: &Endpoints, tokens: &Tokens) -> Result<(), String> {
    // The new refresh token first: the old one is dead now.
    store().set(&refresh_name(ep), &tokens.refresh_token)?;
    *guard(&ACCESS) = Some(Access {
        token: tokens.access_token.clone(),
        until: Instant::now() + tokens.expires_in.saturating_sub(REFRESH_MARGIN),
    });
    Ok(())
}

fn forget(ep: &Endpoints, account_id: &str) {
    *guard(&ACCESS) = None;
    store().delete(&refresh_name(ep));
    if !account_id.is_empty() {
        store().delete(&cloud_token_name(account_id));
    }
}

/// A current access token, refreshed if needed. `SignInAgain` when there is no sign-in or the
/// service refused the refresh token (everything is then forgotten).
pub fn access_token_with(
    t: &dyn Transport,
    ep: &Endpoints,
) -> Result<Zeroizing<String>, AuthError> {
    if let Some(a) = guard(&ACCESS).as_ref().filter(|a| Instant::now() < a.until) {
        return Ok(a.token.clone());
    }
    let _one = guard(&REFRESHING);
    if let Some(a) = guard(&ACCESS).as_ref().filter(|a| Instant::now() < a.until) {
        return Ok(a.token.clone());
    }
    let stored = store()
        .get(&refresh_name(ep))
        .ok_or(AuthError::SignInAgain)?;
    match refresh(t, ep, &stored) {
        Ok(tokens) => {
            keep(ep, &tokens).map_err(AuthError::Failed)?;
            Ok(tokens.access_token)
        }
        Err(AuthError::SignInAgain) => {
            forget(ep, "");
            Err(AuthError::SignInAgain)
        }
        Err(e) => Err(e),
    }
}

/// After a `401 invalid_token`: the cached access token is no good.
pub fn drop_access_token() {
    *guard(&ACCESS) = None;
}

pub fn signed_in(app: &AppHandle) -> Option<AccountSettings> {
    app_state(app)
        .settings()
        .passyble_account
        .filter(|a| !a.id.is_empty())
}

/// An [`AccountApi`] for the signed-in account. `invalid_grant` signs the app out.
pub fn api(app: &AppHandle) -> Res<(AccountApi<'static>, AccountSettings)> {
    let account = signed_in(app).ok_or_else(|| tr!("errors.teams_sign_in_first"))?;
    let ep = Endpoints::for_base(&base_url(&app_state(app).settings()));
    match access_token_with(teams_api::transport(), &ep) {
        Ok(token) => Ok((
            AccountApi::new(&ep.base, &token, teams_api::transport()),
            account,
        )),
        Err(AuthError::SignInAgain) => {
            signed_out_here(app, &account.id);
            Err(tr!("errors.teams_sign_in_again"))
        }
        Err(e) => Err(e.message()),
    }
}

/// Runs `f` with the account API; one `401` drops the access token and tries once more.
pub fn with_api<T>(
    app: &AppHandle,
    f: impl Fn(&AccountApi<'_>, &AccountSettings) -> Result<T, ApiError>,
) -> Res<T> {
    let (api, account) = api(app)?;
    match f(&api, &account) {
        Err(e) if e.is_auth() => {
            drop_access_token();
            let (api, account) = api_again(app)?;
            f(&api, &account).map_err(|e| e.message())
        }
        other => other.map_err(|e| e.message()),
    }
}

fn api_again(app: &AppHandle) -> Res<(AccountApi<'static>, AccountSettings)> {
    api(app)
}

fn signed_out_here(app: &AppHandle, account_id: &str) {
    let state = app_state(app);
    let ep = Endpoints::for_base(&base_url(&state.settings()));
    forget(&ep, account_id);
    let _ = state.update_settings(|s| {
        s.passyble_account = None;
        Ok(())
    });
    crate::teams::account_changed(app);
}

/// The Passyble account status, from the last refresh so it works locked and offline.
#[tauri::command]
pub fn account_status(app: AppHandle) -> Value {
    let extension = handoff_settings(&app).extension_recent(crate::vaults::now_ms());
    status_value(signed_in(&app), crate::teams::cached_orgs(&app), extension)
}

/// Reads `settings.json` only (never the OS credential store), so nothing stored means signed out, not an error.
fn status_value(account: Option<AccountSettings>, orgs: Value, extension: bool) -> Value {
    json!({
        "signed_in": account.is_some(),
        "account": account.as_ref().map(|a| json!({ "id": a.id, "email": a.email })),
        "orgs": orgs,
        "cloud": account.as_ref().is_some_and(|a| a.cloud.is_some()),
        "extension_recent": extension,
    })
}

#[tauri::command]
pub async fn account_sign_in(app: AppHandle) -> Res<Value> {
    blocking(move || sign_in_now(&app)).await
}

fn sign_in_now(app: &AppHandle) -> Res<Value> {
    let cancel = std::sync::Arc::new(AtomicBool::new(false));
    if let Some(previous) = guard(&CANCEL).replace(cancel.clone()) {
        previous.store(true, Ordering::Relaxed);
    }
    let state = app_state(app);
    let ep = Endpoints::for_base(&base_url(&state.settings()));
    let result = sign_in_with(
        teams_api::transport(),
        &ep,
        &cancel,
        crate::platform::open_browser,
    );
    {
        // Ours only: a sign-in that replaced this one keeps its Cancel.
        let mut slot = guard(&CANCEL);
        if slot
            .as_ref()
            .is_some_and(|c| std::sync::Arc::ptr_eq(c, &cancel))
        {
            slot.take();
        }
    }
    let tokens = match result {
        Ok(t) => t,
        Err(AuthError::Cancelled) => return Err("cancelled".into()),
        Err(e) => return Err(e.message()),
    };
    signed_in_with(app, &ep, &tokens)
}

/// Keeps a new app session's tokens as this PC's sign-in. A sign-in ends what the last sign-out chose
/// for the browser extension ([`HandoffSettings::signed_in`]).
pub(crate) fn signed_in_with(app: &AppHandle, ep: &Endpoints, tokens: &Tokens) -> Res<Value> {
    let state = app_state(app);
    keep(ep, tokens)?;
    let previous = state.settings().passyble_account;
    state.update_settings(|s| {
        let cloud = previous
            .as_ref()
            .filter(|p| p.id == tokens.account_id)
            .and_then(|p| p.cloud.clone());
        s.passyble_account = Some(AccountSettings {
            id: tokens.account_id.clone(),
            email: tokens.email.clone(),
            cloud,
        });
        HandoffSettings::update(&mut s.account_handoff, HandoffSettings::signed_in);
        Ok(())
    })?;
    if let Some(p) = previous.filter(|p| p.id != tokens.account_id) {
        store().delete(&cloud_token_name(&p.id));
    }
    crate::teams::account_changed(app);
    Ok(json!({
        "signed_in": true,
        "account": { "id": tokens.account_id, "email": tokens.email },
    }))
}

/// `app.show_account` from the browser extension: Sign out opens Settings on the account row to
/// confirm; Sign in runs the sign-in on its own thread, so it works locked too.
pub fn show_from_extension(app: &AppHandle, sign_in: bool) {
    if !sign_in {
        let _ = app.emit_to("main", "show-account", json!({}));
        crate::popups::open_main(app);
        return;
    }
    // The window without an automatic Windows Hello prompt: the browser comes up over it.
    crate::popups::show_main(app);
    let app = app.clone();
    let _ = std::thread::Builder::new()
        .name("pass-account-sign-in".into())
        .spawn(move || {
            let message = match sign_in_now(&app) {
                Ok(answer) => tr!(
                    "account.signed_in",
                    email = answer["account"]["email"].as_str().unwrap_or_default()
                )
                .trim()
                .to_string(),
                Err(e) if e == "cancelled" => return,
                Err(e) => e,
            };
            let _ = app.emit("toast", message);
        });
}

pub fn sign_in_with(
    t: &dyn Transport,
    ep: &Endpoints,
    cancel: &AtomicBool,
    open: impl FnOnce(&str) -> Result<(), String>,
) -> Result<Tokens, AuthError> {
    let loopback = Loopback::bind()?;
    let redirect_uri = loopback.redirect_uri();
    let (verifier, challenge) = pkce();
    let state = random_b64(32);
    let url = authorize_url(ep, &redirect_uri, &challenge, &state, &device_name());
    open(&url).map_err(AuthError::Failed)?;
    let code = loopback.wait_for_code(&state, &ep.issuer, SIGN_IN_TIMEOUT, cancel)?;
    drop(loopback);
    if cancel.load(Ordering::Relaxed) {
        return Err(AuthError::Cancelled);
    }
    exchange_code(t, ep, &code, &verifier, &redirect_uri)
}

pub fn device_name() -> String {
    match std::env::var("COMPUTERNAME") {
        Ok(name) if !name.trim().is_empty() => {
            tr!("signin.device_name", computer = name.trim())
        }
        _ => tr!("signin.device_name_default"),
    }
}

#[tauri::command]
pub fn account_sign_in_cancel() -> Value {
    if let Some(cancel) = guard(&CANCEL).take() {
        cancel.store(true, Ordering::Relaxed);
    }
    json!({})
}

/// Signs this PC out: revokes the refresh token, forgets the tokens and the Passyble Cloud device,
/// and closes the shared vaults that came through it. `sign_out_extension` is the confirmation's
/// "Also sign out of the browser extension" box (missing: ticked).
#[tauri::command]
pub async fn account_sign_out(app: AppHandle, sign_out_extension: Option<bool>) -> Res<Value> {
    let choice = if sign_out_extension.unwrap_or(true) {
        SignOutChoice::AlsoExtension
    } else {
        SignOutChoice::KeepExtension
    };
    blocking(move || sign_out_now(&app, choice).map(|_| json!({}))).await
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignOutChoice {
    /// Ask the extension to sign out of that address too.
    AlsoExtension,
    /// The extension stays signed in and doesn't sign the app in until the user signs in here.
    KeepExtension,
    /// The extension is signing out itself: nothing to ask it.
    FromExtension,
}

fn sign_out_now(app: &AppHandle, choice: SignOutChoice) -> Res<bool> {
    let state = app_state(app);
    let ep = Endpoints::for_base(&base_url(&state.settings()));
    let account = signed_in(app);
    if let Some(token) = store().get(&refresh_name(&ep)) {
        revoke(teams_api::transport(), &ep, &token);
    }
    forget(&ep, account.as_ref().map_or("", |a| a.id.as_str()));
    let email = account
        .as_ref()
        .map(|a| a.email.clone())
        .unwrap_or_default();
    let now = crate::vaults::now_ms();
    state.update_settings(|s| {
        s.passyble_account = None;
        HandoffSettings::update(&mut s.account_handoff, |h| {
            h.signed_out(choice, &email, now)
        });
        Ok(())
    })?;
    crate::teams::account_changed(app);
    Ok(account.is_some())
}

// The browser extension and this app sign each other in (docs/PROTOCOL.md, "The Passyble account in
// browser mode"). The signed-in side asks the service for a sign-in code (`POST /v1/session/handoff`)
// bound to the S256 challenge of a verifier only the receiving side holds. Each side gets its own
// revocable session; no token or account key is copied. Neither code nor verifier is logged.

pub const EXTENSION_CLIENT_ID: &str = "passyble-extension";
/// The redirect URI a handoff code is bound to (never a browser sign-in's).
pub const HANDOFF_REDIRECT: &str = "urn:passyble:handoff";
const HANDOFF_TTL: Duration = Duration::from_secs(60);
const DAY_MS: i64 = 24 * 60 * 60 * 1000;
const SIGN_OUT_EXTENSION_MS: i64 = 7 * DAY_MS;
const EXTENSION_RECENT_MS: i64 = 30 * DAY_MS;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct HandoffSettings {
    /// Ticked: the extension signs out of this address too, for 7 days at most or until it did or
    /// the user signed in here again.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sign_out_extension: Option<SignOutRequest>,
    /// Unticked: the extension stays signed in and doesn't sign this app in until the user signs in here.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub keep_extension: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extension_seen_ms: Option<i64>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SignOutRequest {
    pub email: String,
    pub at_ms: i64,
}

impl HandoffSettings {
    pub fn update(slot: &mut Option<HandoffSettings>, f: impl FnOnce(&mut HandoffSettings)) {
        let mut h = slot.take().unwrap_or_default();
        f(&mut h);
        *slot = (h != HandoffSettings::default()).then_some(h);
    }

    /// A sign-in here: the extension may sign this app in again and no earlier sign-out is followed.
    pub fn signed_in(&mut self) {
        self.sign_out_extension = None;
        self.keep_extension = false;
    }

    pub fn signed_out(&mut self, choice: SignOutChoice, email: &str, now: i64) {
        match choice {
            SignOutChoice::AlsoExtension => {
                self.sign_out_extension = (!email.is_empty()).then(|| SignOutRequest {
                    email: email.to_string(),
                    at_ms: now,
                });
                self.keep_extension = false;
            }
            SignOutChoice::KeepExtension => {
                self.sign_out_extension = None;
                self.keep_extension = true;
            }
            SignOutChoice::FromExtension => self.sign_out_extension = None,
        }
    }

    fn live_sign_out(&self, now: i64) -> Option<&SignOutRequest> {
        self.sign_out_extension
            .as_ref()
            .filter(|r| (0..SIGN_OUT_EXTENSION_MS).contains(&(now - r.at_ms)))
    }

    pub fn extension_recent(&self, now: i64) -> bool {
        self.extension_seen_ms
            .is_some_and(|at| (0..EXTENSION_RECENT_MS).contains(&(now - at)))
    }

    pub fn seen(&mut self, now: i64) -> bool {
        if self
            .extension_seen_ms
            .is_some_and(|at| (0..DAY_MS).contains(&(now - at)))
        {
            return false;
        }
        self.extension_seen_ms = Some(now);
        true
    }

    pub fn peer(&self, account: Option<&AccountSettings>, now: i64) -> pass_agent::AccountPeer {
        if let Some(a) = account {
            return pass_agent::AccountPeer {
                signed_in: true,
                email: Some(a.email.clone()).filter(|e| !e.is_empty()),
                accepts_handoff: true,
                sign_out_extension: false,
            };
        }
        let sign_out = self.live_sign_out(now);
        pass_agent::AccountPeer {
            signed_in: false,
            email: sign_out.map(|r| r.email.clone()),
            // While the extension is asked to sign out, it doesn't sign this app in again either
            // (an extension signed in to another address would otherwise do just that).
            accepts_handoff: !self.keep_extension && sign_out.is_none(),
            sign_out_extension: sign_out.is_some(),
        }
    }
}

/// A verifier of `account.handoff_begin`: memory only, single use, replaced by a new begin, zeroized on drop.
pub struct PendingHandoff {
    slot: Mutex<Option<(Zeroizing<String>, Instant)>>,
    ttl: Duration,
}

impl PendingHandoff {
    pub const fn new(ttl: Duration) -> Self {
        Self {
            slot: Mutex::new(None),
            ttl,
        }
    }

    pub fn begin(&self) -> String {
        let (verifier, challenge) = pkce();
        *guard(&self.slot) = Some((verifier, Instant::now()));
        challenge
    }

    pub fn take(&self) -> Option<Zeroizing<String>> {
        let (verifier, at) = guard(&self.slot).take()?;
        (at.elapsed() < self.ttl).then_some(verifier)
    }
}

static PENDING_HANDOFF: PendingHandoff = PendingHandoff::new(HANDOFF_TTL);

#[derive(Deserialize, Default)]
#[serde(default)]
struct HandoffAnswer {
    code: String,
}

/// `POST /v1/session/handoff`: a sign-in code for the browser extension, bound to `code_challenge`.
pub fn handoff_code(
    api: &AccountApi<'_>,
    code_challenge: &str,
    device_name: &str,
) -> Result<Zeroizing<String>, ApiError> {
    let answer = api.call(
        "POST",
        "/session/handoff",
        Some(json!({
            "client_id": EXTENSION_CLIENT_ID,
            "code_challenge": code_challenge,
            "device_name": device_name,
        })),
    )?;
    let answer: HandoffAnswer = serde_json::from_value(answer).unwrap_or_default();
    if answer.code.is_empty() {
        return Err(ApiError::Unexpected(tr!("errors.teams_unexpected_answer")));
    }
    Ok(Zeroizing::new(answer.code))
}

fn handoff_settings(app: &AppHandle) -> HandoffSettings {
    app_state(app)
        .settings()
        .account_handoff
        .unwrap_or_default()
}

fn not_now(message: &str) -> pass_agent::AccountError {
    pass_agent::AccountError::InvalidState(message.into())
}

/// `account.peer`: this app's account for the extension, which asks at most every half minute.
pub fn peer_for_extension(app: &AppHandle) -> pass_agent::AccountPeer {
    let now = crate::vaults::now_ms();
    let mut handoff = handoff_settings(app);
    if handoff.seen(now) {
        let _ = app_state(app).update_settings(|s| {
            HandoffSettings::update(&mut s.account_handoff, |h| {
                h.seen(now);
            });
            Ok(())
        });
    }
    handoff.peer(signed_in(app).as_ref(), now)
}

/// `account.handoff_to_extension`: a sign-in code for the extension (this app is signed in).
pub fn hand_to_extension(
    app: &AppHandle,
    code_challenge: &str,
    device_name: &str,
) -> Result<pass_agent::HandoffCode, pass_agent::AccountError> {
    if signed_in(app).is_none() {
        return Err(not_now("the Passyble app is not signed in"));
    }
    let (code, email) = with_api(app, |api, account| {
        Ok((
            handoff_code(api, code_challenge, device_name)?,
            account.email.clone(),
        ))
    })
    .map_err(pass_agent::AccountError::Failed)?;
    let _ = app.emit(
        "toast",
        tr!("account.handoff_to_extension", email = email.as_str()),
    );
    Ok(pass_agent::HandoffCode {
        code: code.as_str().to_owned(),
        email,
    })
}

pub fn begin_from_extension(
    app: &AppHandle,
) -> Result<pass_agent::HandoffRequest, pass_agent::AccountError> {
    if signed_in(app).is_some() {
        return Err(not_now("the Passyble app is signed in already"));
    }
    let peer = handoff_settings(app).peer(None, crate::vaults::now_ms());
    if !peer.accepts_handoff {
        return Err(not_now(
            "the Passyble app takes no sign-in from the extension now",
        ));
    }
    Ok(pass_agent::HandoffRequest {
        code_challenge: PENDING_HANDOFF.begin(),
        device_name: device_name(),
    })
}

/// `account.handoff_finish`: redeems the extension's code with the waiting verifier.
pub fn finish_from_extension(
    app: &AppHandle,
    code: &str,
) -> Result<String, pass_agent::AccountError> {
    // Taken first: single use whatever happens next.
    let verifier = PENDING_HANDOFF
        .take()
        .ok_or_else(|| not_now("no sign-in from the extension is waiting"))?;
    if signed_in(app).is_some() {
        return Err(not_now("the Passyble app is signed in already"));
    }
    let ep = Endpoints::for_base(&base_url(&app_state(app).settings()));
    let tokens = exchange_code(
        teams_api::transport(),
        &ep,
        code,
        &verifier,
        HANDOFF_REDIRECT,
    )
    .map_err(|e| pass_agent::AccountError::Failed(e.message()))?;
    signed_in_with(app, &ep, &tokens).map_err(pass_agent::AccountError::Failed)?;
    let _ = app.emit(
        "toast",
        tr!(
            "account.handoff_from_extension",
            email = tokens.email.as_str()
        ),
    );
    Ok(tokens.email.clone())
}

/// `account.sign_out`: the extension's own sign-out; signs out here without asking it to follow.
pub fn sign_out_from_extension(app: &AppHandle) -> Result<(), pass_agent::AccountError> {
    if signed_in(app).is_none() {
        return Ok(());
    }
    sign_out_now(app, SignOutChoice::FromExtension).map_err(pass_agent::AccountError::Failed)?;
    let _ = app.emit("toast", tr!("account.signed_out_by_extension"));
    Ok(())
}

pub fn extension_signed_out(app: &AppHandle) -> Result<(), pass_agent::AccountError> {
    app_state(app)
        .update_settings(|s| {
            HandoffSettings::update(&mut s.account_handoff, |h| h.sign_out_extension = None);
            Ok(())
        })
        .map_err(pass_agent::AccountError::Failed)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn status_with_nothing_stored_is_signed_out() {
        let v = status_value(None, Value::Array(vec![]), false);
        assert_eq!(v["signed_in"], false);
        assert!(v["account"].is_null());
        assert_eq!(v["cloud"], false);
        assert_eq!(v["orgs"], json!([]));
        assert_eq!(v["extension_recent"], false);
    }

    fn ada() -> AccountSettings {
        AccountSettings {
            id: "acc_1".into(),
            email: "ada@example.com".into(),
            cloud: None,
        }
    }

    #[test]
    fn the_sign_out_choice_is_what_the_extension_sees() {
        let now = 1_800_000_000_000;
        let mut h = HandoffSettings::default();
        let peer = h.peer(Some(&ada()), now);
        assert!(peer.signed_in && peer.accepts_handoff && !peer.sign_out_extension);
        assert_eq!(peer.email.as_deref(), Some("ada@example.com"));
        let peer = h.peer(None, now);
        assert!(!peer.signed_in && peer.accepts_handoff && !peer.sign_out_extension);
        assert_eq!(peer.email, None);

        h.signed_out(SignOutChoice::AlsoExtension, "ada@example.com", now);
        let peer = h.peer(None, now + 1000);
        assert!(peer.sign_out_extension && !peer.accepts_handoff);
        assert_eq!(peer.email.as_deref(), Some("ada@example.com"));
        // For 7 days at most (and never for a clock set back).
        assert!(
            h.peer(None, now + SIGN_OUT_EXTENSION_MS - 1)
                .sign_out_extension
        );
        let late = h.peer(None, now + SIGN_OUT_EXTENSION_MS);
        assert!(!late.sign_out_extension && late.accepts_handoff && late.email.is_none());
        assert!(!h.peer(None, now - 1).sign_out_extension);
        let mut done = h.clone();
        done.sign_out_extension = None;
        assert!(done.peer(None, now).accepts_handoff);

        h.signed_out(SignOutChoice::KeepExtension, "ada@example.com", now);
        let peer = h.peer(None, now);
        assert!(!peer.accepts_handoff && !peer.sign_out_extension && peer.email.is_none());
        h.signed_in();
        assert_eq!(h, HandoffSettings::default());
        assert!(h.peer(None, now).accepts_handoff);

        h.signed_out(SignOutChoice::FromExtension, "ada@example.com", now);
        let peer = h.peer(None, now);
        assert!(peer.accepts_handoff && !peer.sign_out_extension);
        h.signed_out(SignOutChoice::AlsoExtension, "ada@example.com", now);
        h.signed_in();
        assert!(!h.peer(None, now).sign_out_extension);
    }

    #[test]
    fn handoff_settings_are_saved_only_when_they_say_something() {
        let mut slot = None;
        HandoffSettings::update(&mut slot, HandoffSettings::signed_in);
        assert_eq!(slot, None);
        HandoffSettings::update(&mut slot, |h| {
            h.signed_out(SignOutChoice::KeepExtension, "ada@example.com", 5)
        });
        assert!(slot.as_ref().is_some_and(|h| h.keep_extension));
        let saved = serde_json::to_value(slot.as_ref().unwrap()).unwrap();
        assert_eq!(saved, json!({ "keep_extension": true }));
        HandoffSettings::update(&mut slot, HandoffSettings::signed_in);
        assert_eq!(slot, None);

        let now = 1_800_000_000_000;
        let mut h = HandoffSettings::default();
        assert!(!h.extension_recent(now));
        assert!(h.seen(now));
        assert!(!h.seen(now + DAY_MS - 1));
        assert!(h.seen(now + DAY_MS));
        assert!(h.extension_recent(now + DAY_MS + EXTENSION_RECENT_MS - 1));
        assert!(!h.extension_recent(now + DAY_MS + EXTENSION_RECENT_MS));
    }

    #[test]
    fn a_handoff_verifier_is_single_use_and_short_lived() {
        let pending = PendingHandoff::new(Duration::from_secs(60));
        assert!(pending.take().is_none());
        let first = pending.begin();
        let second = pending.begin();
        assert_ne!(first, second);
        let verifier = pending.take().unwrap();
        assert_eq!(verifier.len(), 43);
        assert_eq!(challenge_for(&verifier), second);
        assert!(pending.take().is_none(), "single use");

        let expired = PendingHandoff::new(Duration::ZERO);
        expired.begin();
        assert!(expired.take().is_none());
        assert!(expired.take().is_none(), "gone after the try");
    }

    #[test]
    fn a_code_for_the_extension_comes_from_the_service() {
        let fake = Fake::with(vec![(
            200,
            r#"{ "code": "pac_x", "redirect_uri": "urn:passyble:handoff", "expires_in": 60 }"#,
        )]);
        let api = AccountApi::new("https://a.example", "pat_1", &fake);
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        let code = handoff_code(&api, challenge, "Chrome on PC").unwrap();
        assert_eq!(code.as_str(), "pac_x");
        let r = &fake.requests()[0];
        assert_eq!(r.method, "POST");
        assert_eq!(r.url, "https://a.example/v1/session/handoff");
        assert_eq!(r.auth.as_deref().map(String::as_str), Some("Bearer pat_1"));
        assert_eq!(
            r.json(),
            json!({
                "client_id": "passyble-extension",
                "code_challenge": challenge,
                "device_name": "Chrome on PC",
            })
        );
        let fake = Fake::with(vec![(403, r#"{ "error": "handoff_client" }"#)]);
        let api = AccountApi::new("https://a.example", "pat_1", &fake);
        let refused = handoff_code(&api, challenge, "").unwrap_err();
        assert_eq!(refused.code(), "handoff_client");
        let fake = Fake::with(vec![(200, r#"{ "code": "" }"#)]);
        let api = AccountApi::new("https://a.example", "pat_1", &fake);
        assert!(matches!(
            handoff_code(&api, challenge, ""),
            Err(ApiError::Unexpected(_))
        ));
    }

    #[test]
    fn a_code_from_the_extension_is_redeemed_with_the_handoff_redirect() {
        let fake = Fake::with(vec![(
            200,
            r#"{ "access_token": "pat_1", "expires_in": 900, "refresh_token": "prt_1",
                 "account": { "id": "acc_1", "email": "ada@example.com" } }"#,
        )]);
        let ep = Endpoints::for_base("https://a.example");
        let t = exchange_code(&fake, &ep, "pac_x", "verifier", HANDOFF_REDIRECT).unwrap();
        assert_eq!(t.email, "ada@example.com");
        let body = String::from_utf8(fake.requests()[0].body.clone().unwrap().1).unwrap();
        assert_eq!(
            body,
            "grant_type=authorization_code&code=pac_x&code_verifier=verifier&client_id=passyble-windows&redirect_uri=urn%3Apassyble%3Ahandoff"
        );
    }
    use crate::teams_api::tests::Fake;
    use std::collections::HashMap;
    use std::sync::OnceLock;

    #[derive(Default)]
    pub(crate) struct FakeStore(Mutex<HashMap<String, String>>);

    impl Store for FakeStore {
        fn get(&self, name: &str) -> Option<Zeroizing<String>> {
            guard(&self.0).get(name).cloned().map(Zeroizing::new)
        }
        fn set(&self, name: &str, secret: &str) -> Result<(), String> {
            guard(&self.0).insert(name.into(), secret.into());
            Ok(())
        }
        fn delete(&self, name: &str) {
            guard(&self.0).remove(name);
        }
    }

    pub(crate) fn fake_store() -> &'static FakeStore {
        static STORE: OnceLock<FakeStore> = OnceLock::new();
        STORE.get_or_init(FakeStore::default)
    }

    /// The token tests share the in-memory access token: one at a time.
    static SERIAL: Mutex<()> = Mutex::new(());

    #[test]
    fn the_authorize_url_has_pkce_state_and_the_client() {
        let ep = Endpoints::for_base("https://account.example.com/");
        assert_eq!(ep.issuer, "https://account.example.com");
        let url = authorize_url(
            &ep,
            "http://127.0.0.1:53682/",
            "CH",
            "ST",
            "Passyble on PC 1",
        );
        assert!(url.starts_with(
            "https://account.example.com/oauth/authorize?client_id=passyble-windows&"
        ));
        assert!(url.contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A53682%2F"));
        assert!(url.contains("code_challenge=CH&code_challenge_method=S256&state=ST"));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("device_name=Passyble%20on%20PC%201"));
        let (verifier, challenge) = pkce();
        assert_eq!(verifier.len(), 43);
        assert_eq!(challenge.len(), 43);
        assert_eq!(challenge, challenge_for(&verifier));
        // RFC 7636 appendix B.
        assert_eq!(
            challenge_for("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn the_redirect_must_carry_our_state_and_issuer() {
        let head =
            "GET /?code=pac_abc&state=S1&iss=https%3A%2F%2Faccount.example.com HTTP/1.1\r\n\r\n";
        let Callback::Code { code, state, iss } = parse_callback(head) else {
            panic!("a code");
        };
        assert_eq!(code, "pac_abc");
        assert!(ours(&state, &iss, "S1", "https://account.example.com"));
        assert!(!ours(&state, &iss, "S2", "https://account.example.com"));
        assert!(!ours(
            &state,
            "https://evil.example",
            "S1",
            "https://account.example.com"
        ));
        assert!(!ours(&state, "", "S1", "https://account.example.com"));
        assert_eq!(
            parse_callback("GET /?error=access_denied&state=S1&iss=x HTTP/1.1"),
            Callback::Error {
                error: "access_denied".into(),
                state: "S1".into(),
                iss: "x".into()
            }
        );
        assert_eq!(parse_callback("GET /favicon.ico HTTP/1.1"), Callback::Other);
    }

    #[test]
    fn the_code_exchange_sends_the_form() {
        let fake = Fake::with(vec![(
            200,
            r#"{ "access_token": "pat_1", "token_type": "Bearer", "expires_in": 900,
                 "refresh_token": "prt_1", "session_id": "aps_1",
                 "account": { "id": "acc_1", "email": "alex@example.com" } }"#,
        )]);
        let ep = Endpoints::for_base("https://a.example");
        let t = exchange_code(&fake, &ep, "pac_x", "verifier", "http://127.0.0.1:5/").unwrap();
        assert_eq!(t.account_id, "acc_1");
        assert_eq!(t.refresh_token.as_str(), "prt_1");
        let r = &fake.requests()[0];
        assert_eq!(r.url, "https://a.example/oauth/token");
        let (kind, body) = r.body.clone().unwrap();
        assert_eq!(kind, "application/x-www-form-urlencoded");
        assert_eq!(
            String::from_utf8(body).unwrap(),
            "grant_type=authorization_code&code=pac_x&code_verifier=verifier&client_id=passyble-windows&redirect_uri=http%3A%2F%2F127.0.0.1%3A5%2F"
        );
        let fake = Fake::with(vec![(400, r#"{"error":"invalid_grant"}"#)]);
        assert!(matches!(
            exchange_code(&fake, &ep, "c", "v", "r"),
            Err(AuthError::Failed(_))
        ));
    }

    #[test]
    fn refreshes_store_the_new_token_first_and_invalid_grant_signs_out() {
        let _one = guard(&SERIAL);
        let ep = Endpoints::for_base("https://refresh.example");
        drop_access_token();
        assert_eq!(
            access_token_with(&Fake::default(), &ep).unwrap_err(),
            AuthError::SignInAgain
        );
        store().set(&refresh_name(&ep), "prt_old").unwrap();
        let fake = Fake::with(vec![(
            200,
            r#"{"access_token":"pat_2","expires_in":900,"refresh_token":"prt_new"}"#,
        )]);
        assert_eq!(access_token_with(&fake, &ep).unwrap().as_str(), "pat_2");
        assert_eq!(store().get(&refresh_name(&ep)).unwrap().as_str(), "prt_new");
        let body = String::from_utf8(fake.requests()[0].body.clone().unwrap().1).unwrap();
        assert_eq!(
            body,
            "grant_type=refresh_token&refresh_token=prt_old&client_id=passyble-windows"
        );
        assert_eq!(access_token_with(&fake, &ep).unwrap().as_str(), "pat_2");
        assert_eq!(fake.requests().len(), 1);
        drop_access_token();
        let refused = Fake::with(vec![(400, r#"{"error":"invalid_grant"}"#)]);
        assert_eq!(
            access_token_with(&refused, &ep).unwrap_err(),
            AuthError::SignInAgain
        );
        assert!(store().get(&refresh_name(&ep)).is_none());
        store().set(&refresh_name(&ep), "prt_keep").unwrap();
        assert!(matches!(
            access_token_with(&Fake::default(), &ep),
            Err(AuthError::Failed(_))
        ));
        assert!(store().get(&refresh_name(&ep)).is_some());
        drop_access_token();
    }

    #[test]
    fn only_https_or_loopback_service_urls_are_taken_from_settings() {
        let mut s = crate::settings::Settings::default();
        assert_eq!(base_url(&s), "https://account.passyble.com");
        s.account_url = Some("http://evil.example".into());
        assert_eq!(base_url(&s), "https://account.passyble.com");
        s.account_url = Some("https://staging.account.example/".into());
        assert_eq!(base_url(&s), "https://staging.account.example");
        s.account_url = Some("http://127.0.0.1:8090".into());
        assert_eq!(base_url(&s), "http://127.0.0.1:8090");
    }
}
