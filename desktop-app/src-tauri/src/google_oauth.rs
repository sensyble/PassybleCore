//! Google sign-in for Drive backup: OAuth 2.0 for installed apps
//! (<https://developers.google.com/identity/protocols/oauth2/native-app>).
//!
//! The system browser (Google refuses embedded web views) opens the consent page with a PKCE `S256`
//! challenge, a random `state` and scope `drive.appdata` only. A one-shot listener on
//! `127.0.0.1:<ephemeral port>` is the redirect URI: it checks `state`, reads `code` or `error` and
//! closes. The code (+ verifier) is exchanged at the token endpoint, and the granted `scope` must
//! include `drive.appdata` (the user can untick it).
//!
//! The refresh token goes to the OS credential store (`Pass/GoogleDrive/<e-mail>`) once a vault
//! uses the account ([`commit`]); until then it is only in memory. Access tokens never leave
//! memory. Neither is logged or written to `settings.json`. Only a refresh answered `invalid_grant`
//! deletes the credential ([`AuthError::SignInAgain`]); a network error, a Google outage or an
//! unreadable store keeps the sign-in for the next try.
//!
//! The Desktop client's "secret" is not confidential for installed apps (Google says so); it is
//! compiled in like the client ID (`PASS_GOOGLE_CLIENT_ID` / `PASS_GOOGLE_CLIENT_SECRET`, build.rs)
//! or set in `settings.json` (`google_oauth`) for development.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use rand::RngCore;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::i18n::tr;
use crate::settings::Settings;

/// Pass's only scope: its own hidden app folder. The e-mail comes from Drive's `about.get`, so no `openid email`.
pub const SCOPE: &str = "https://www.googleapis.com/auth/drive.appdata";
pub const SIGN_IN_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const REFRESH_MARGIN: Duration = Duration::from_secs(120);
const KEYRING_SERVICE: &str = "com.sensyble.pass.google";
const MAX_REQUEST: usize = 16 * 1024;
const MAX_RESPONSE: u64 = 64 * 1024;

fn missing_scope() -> String {
    tr!("errors.google_missing_scope")
}
pub use crate::gdrive::sign_in_again;

/// Why a sign-in or token request didn't give Pass a token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthError {
    Cancelled,
    SignInAgain,
    Failed(String),
}

impl AuthError {
    pub fn message(&self) -> String {
        match self {
            AuthError::Cancelled => tr!("errors.google_cancelled"),
            AuthError::SignInAgain => sign_in_again(),
            AuthError::Failed(m) => m.clone(),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Client {
    pub id: String,
    pub secret: String,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl Client {
    /// `settings.json` → `google_oauth`, else the compiled-in client. `None`: this build has no Google option.
    pub fn configured(settings: &Settings) -> Option<Client> {
        if let Some(c) = settings
            .google_oauth
            .as_ref()
            .filter(|c| !c.client_id.trim().is_empty())
        {
            return Some(Client {
                id: c.client_id.trim().to_string(),
                secret: c.client_secret.trim().to_string(),
            });
        }
        let id = option_env!("PASS_GOOGLE_CLIENT_ID").unwrap_or("").trim();
        (!id.is_empty()).then(|| Client {
            id: id.to_string(),
            secret: option_env!("PASS_GOOGLE_CLIENT_SECRET")
                .unwrap_or("")
                .trim()
                .to_string(),
        })
    }
}

/// Google's endpoints; tests point them at a local fake.
#[derive(Clone, Debug)]
pub struct Endpoints {
    pub auth: String,
    pub token: String,
    pub revoke: String,
}

impl Endpoints {
    pub fn google() -> Self {
        Self {
            auth: "https://accounts.google.com/o/oauth2/v2/auth".into(),
            token: "https://oauth2.googleapis.com/token".into(),
            revoke: "https://oauth2.googleapis.com/revoke".into(),
        }
    }
}

fn random_b64(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    pass_core::b64url_encode(buf)
}

/// RFC 7636 proof key: a 64-character verifier and its `S256` challenge.
pub struct Pkce {
    pub verifier: Zeroizing<String>,
    pub challenge: String,
}

pub fn pkce() -> Pkce {
    let verifier = Zeroizing::new(random_b64(48));
    let challenge = challenge_for(&verifier);
    Pkce {
        verifier,
        challenge,
    }
}

pub fn challenge_for(verifier: &str) -> String {
    pass_core::b64url_encode(Sha256::digest(verifier.as_bytes()).to_vec())
}

/// A random `state` (anti-CSRF: the redirect must carry it back).
pub fn random_state() -> String {
    random_b64(24)
}

fn encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Google's consent page. Without `login_hint` Google shows its account picker.
pub fn auth_url(
    endpoints: &Endpoints,
    client_id: &str,
    redirect_uri: &str,
    challenge: &str,
    state: &str,
    login_hint: Option<&str>,
) -> String {
    let hint = login_hint.map(str::trim).filter(|h| !h.is_empty());
    let mut params = vec![
        ("client_id", client_id),
        ("redirect_uri", redirect_uri),
        ("response_type", "code"),
        ("scope", SCOPE),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256"),
        ("state", state),
        // A refresh token, every time.
        ("access_type", "offline"),
        (
            "prompt",
            if hint.is_some() {
                "consent"
            } else {
                "select_account consent"
            },
        ),
    ];
    if let Some(hint) = hint {
        params.push(("login_hint", hint));
    }
    let query: Vec<String> = params
        .iter()
        .map(|(k, v)| format!("{k}={}", encode(v)))
        .collect();
    format!("{}?{}", endpoints.auth, query.join("&"))
}

#[derive(Debug, PartialEq, Eq)]
pub enum Callback {
    Code {
        code: String,
        state: String,
    },
    Error {
        error: String,
        state: String,
    },
    /// Not Google's redirect (another path, a favicon, a probe): answered 404, the wait goes on.
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
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3])
                    .ok()
                    .and_then(|h| u8::from_str_radix(h, 16).ok());
                match hex {
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

fn query_param(query: &str, name: &str) -> Option<String> {
    query
        .split('&')
        .filter_map(|pair| pair.split_once('=').or(Some((pair, ""))))
        .find(|(k, _)| percent_decode(k) == name)
        .map(|(_, v)| percent_decode(v))
}

/// Parses the request head the browser sent to the loopback listener.
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
    let state = query_param(query, "state").unwrap_or_default();
    if let Some(code) = query_param(query, "code").filter(|c| !c.is_empty()) {
        return Callback::Code { code, state };
    }
    if let Some(error) = query_param(query, "error").filter(|e| !e.is_empty()) {
        return Callback::Error { error, state };
    }
    Callback::Other
}

/// Constant-time comparison (the state is a secret of this sign-in).
fn same(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

fn page(title: &str, text: &str) -> String {
    // The texts come from the catalogs: no markup in them.
    let escape = |t: &str| {
        t.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
    };
    let (title, text) = (escape(title), escape(text));
    format!(
        "<!doctype html><html lang=\"{lang}\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>Passyble</title>\
<style>:root{{color-scheme:light dark;--bg:#f6f6f6;--card:#fff;--border:#e4e4e4;--text:#111;--muted:#555;--accent:#111}}\
@media (prefers-color-scheme:dark){{:root{{--bg:#0f0f10;--card:#18181a;--border:#2a2a2d;--text:#ededed;--muted:#b4b4b8;--accent:#ededed}}}}\
body{{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:var(--bg);\
color:var(--text);font:15px/1.5 \"Space Grotesk\",system-ui,sans-serif}}\
main{{max-width:420px;margin:24px;padding:28px 30px;background:var(--card);border:1px solid var(--border);border-radius:14px;\
box-shadow:0 8px 24px rgba(0,0,0,.10),0 1px 2px rgba(0,0,0,.06)}}\
h1{{font-size:20px;font-weight:700;letter-spacing:-.02em;margin:0 0 8px}}p{{margin:0;color:var(--muted)}}\
.mark{{width:36px;height:36px;margin-bottom:12px;color:var(--accent)}}</style></head><body><main>\
<svg class=\"mark\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" \
stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\"><path d=\"M20 13c0 5-3.5 7.5-7.66 \
8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 \
3.81 17 5 19 5a1 1 0 0 1 1 1z\"/><path d=\"m9 12 2 2 4-4\"/></svg><h1>{title}</h1><p>{text}</p></main>\
</body></html>",
        lang = crate::i18n::locale(),
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

pub struct Loopback {
    listener: TcpListener,
    port: u16,
}

impl Loopback {
    pub fn bind() -> Result<Self, AuthError> {
        let fail = |e: std::io::Error| {
            AuthError::Failed(crate::errors::logged(
                tr!("errors.google_cant_start"),
                "Google sign-in",
                e,
            ))
        };
        let listener = TcpListener::bind(("127.0.0.1", 0)).map_err(fail)?;
        listener.set_nonblocking(true).map_err(fail)?;
        let port = listener.local_addr().map_err(fail)?.port();
        Ok(Self { listener, port })
    }

    /// `http://127.0.0.1:<port>/`, identical in the consent URL and the code exchange.
    pub fn redirect_uri(&self) -> String {
        format!("http://127.0.0.1:{}/", self.port)
    }

    /// Waits for Google's redirect carrying `state`. Other requests (favicon, a stale tab, a wrong `state`) are answered and ignored.
    pub fn wait_for_code(
        &self,
        state: &str,
        timeout: Duration,
        cancel: &AtomicBool,
    ) -> Result<Zeroizing<String>, AuthError> {
        let deadline = Instant::now() + timeout;
        loop {
            if cancel.load(Ordering::Relaxed) {
                return Err(AuthError::Cancelled);
            }
            if Instant::now() >= deadline {
                return Err(AuthError::Failed(tr!("errors.google_too_long")));
            }
            let mut stream = match self.listener.accept() {
                Ok((stream, _)) => stream,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(100));
                    continue;
                }
                Err(_) => {
                    std::thread::sleep(Duration::from_millis(100));
                    continue;
                }
            };
            let head = read_head(&mut stream);
            match parse_callback(&head) {
                Callback::Code { code, state: got } if same(&got, state) => {
                    respond(
                        &mut stream,
                        "200 OK",
                        &page(&tr!("google.page_signed_in"), &tr!("google.page_close_tab")),
                    );
                    return Ok(Zeroizing::new(code));
                }
                Callback::Error { error, state: got } if same(&got, state) => {
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
                    return Err(AuthError::Failed(if cancelled {
                        tr!("errors.google_cancelled_browser")
                    } else {
                        crate::errors::logged(tr!("errors.google_failed"), "Google sign-in", error)
                    }));
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

// Opens `url` in the default browser.
pub use crate::platform::open_browser;

pub struct Tokens {
    pub access_token: Zeroizing<String>,
    pub expires_in: Duration,
    pub refresh_token: Option<Zeroizing<String>>,
}

impl std::fmt::Debug for Tokens {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tokens")
            .field("expires_in", &self.expires_in)
            .field("refresh_token", &self.refresh_token.is_some())
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct TokenResponse {
    access_token: Option<String>,
    expires_in: Option<u64>,
    refresh_token: Option<String>,
    scope: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

pub fn parse_token_response(status: u16, body: &str) -> Result<Tokens, AuthError> {
    let r: TokenResponse = serde_json::from_str(body).unwrap_or_default();
    if let Some(error) = r.error.as_deref().filter(|e| !e.is_empty()) {
        return Err(match error {
            // Revoked, expired (Testing: 7 days), evicted, or a code already used.
            "invalid_grant" => AuthError::SignInAgain,
            "invalid_client" | "unauthorized_client" => AuthError::Failed(crate::errors::logged(
                tr!("errors.google_client_rejected"),
                "Google token endpoint",
                error,
            )),
            "invalid_scope" => AuthError::Failed(missing_scope()),
            other => {
                let detail = r
                    .error_description
                    .as_deref()
                    .map(|d| format!(": {}", d.trim_end_matches('.')))
                    .unwrap_or_default();
                AuthError::Failed(crate::errors::logged(
                    tr!("errors.google_failed"),
                    "Google token endpoint",
                    format!("{other}{detail}"),
                ))
            }
        });
    }
    if !(200..300).contains(&status) {
        return Err(AuthError::Failed(crate::errors::logged(
            tr!("errors.google_http"),
            "Google token endpoint",
            format!("HTTP {status}"),
        )));
    }
    let access = r
        .access_token
        .filter(|t| !t.is_empty())
        .ok_or_else(|| AuthError::Failed(tr!("errors.google_no_access")))?;
    if let Some(scope) = r.scope.as_deref() {
        if !scope.split_whitespace().any(|s| s == SCOPE) {
            return Err(AuthError::Failed(missing_scope()));
        }
    }
    Ok(Tokens {
        access_token: Zeroizing::new(access),
        expires_in: Duration::from_secs(r.expires_in.unwrap_or(3600)),
        refresh_token: r
            .refresh_token
            .filter(|t| !t.is_empty())
            .map(Zeroizing::new),
    })
}

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .build()
}

fn post_form(url: &str, form: &[(&str, &str)]) -> Result<(u16, String), AuthError> {
    let response = match agent().post(url).send_form(form) {
        Ok(r) => r,
        Err(ureq::Error::Status(_, r)) => r,
        Err(e) => {
            return Err(AuthError::Failed(crate::errors::network(&format!(
                "{url}: {e}"
            ))))
        }
    };
    let status = response.status();
    let mut body = String::new();
    let _ = response
        .into_reader()
        .take(MAX_RESPONSE)
        .read_to_string(&mut body);
    Ok((status, body))
}

pub fn exchange_code(
    endpoints: &Endpoints,
    client: &Client,
    code: &str,
    verifier: &str,
    redirect_uri: &str,
) -> Result<Tokens, AuthError> {
    let mut form = vec![
        ("client_id", client.id.as_str()),
        ("code", code),
        ("code_verifier", verifier),
        ("grant_type", "authorization_code"),
        ("redirect_uri", redirect_uri),
    ];
    if !client.secret.is_empty() {
        form.push(("client_secret", client.secret.as_str()));
    }
    let (status, body) = post_form(&endpoints.token, &form)?;
    let tokens = match parse_token_response(status, &body) {
        // A code is single-use and short-lived: "start again", not "sign in again".
        Err(AuthError::SignInAgain) => {
            return Err(AuthError::Failed(tr!("errors.google_code_expired")))
        }
        other => other?,
    };
    if tokens.refresh_token.is_none() {
        return Err(AuthError::Failed(tr!("errors.google_no_refresh")));
    }
    Ok(tokens)
}

/// A new access token for a refresh token. `invalid_grant` is [`AuthError::SignInAgain`].
pub fn refresh(
    endpoints: &Endpoints,
    client: &Client,
    refresh_token: &str,
) -> Result<Tokens, AuthError> {
    let mut form = vec![
        ("client_id", client.id.as_str()),
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
    ];
    if !client.secret.is_empty() {
        form.push(("client_secret", client.secret.as_str()));
    }
    let answer = post_form(&endpoints.token, &form);
    note(&refresh_step(&answer));
    let (status, body) = answer?;
    if let Some(description) = refused_description(&body) {
        // Google's fixed refusal text for pass.log, never the token.
        crate::applog::plog!("Google token endpoint: invalid_grant: {description}");
    }
    parse_token_response(status, &body)
}

/// Revokes the grant behind a (refresh) token. A token that is already invalid counts as done.
pub fn revoke(endpoints: &Endpoints, token: &str) -> Result<(), AuthError> {
    let (status, body) = post_form(&endpoints.revoke, &[("token", token)])?;
    if (200..300).contains(&status) || body.contains("invalid_token") {
        Ok(())
    } else {
        Err(AuthError::Failed(crate::errors::logged(
            tr!("errors.google_revoke"),
            "Google revoke",
            format!("HTTP {status}"),
        )))
    }
}

/// The whole browser sign-in. `open` shows the URL (the system browser; tests play the browser).
pub fn sign_in_with(
    endpoints: &Endpoints,
    client: &Client,
    login_hint: Option<&str>,
    timeout: Duration,
    cancel: &AtomicBool,
    open: impl FnOnce(&str) -> Result<(), String>,
) -> Result<Tokens, AuthError> {
    let loopback = Loopback::bind()?;
    let redirect_uri = loopback.redirect_uri();
    let pkce = pkce();
    let state = random_state();
    let url = auth_url(
        endpoints,
        &client.id,
        &redirect_uri,
        &pkce.challenge,
        &state,
        login_hint,
    );
    open(&url).map_err(AuthError::Failed)?;
    let code = loopback.wait_for_code(&state, timeout, cancel)?;
    drop(loopback);
    if cancel.load(Ordering::Relaxed) {
        return Err(AuthError::Cancelled);
    }
    exchange_code(endpoints, client, &code, &pkce.verifier, &redirect_uri)
}

/// One line in the timing log: a fixed text with codes only, never a token, an e-mail or a message from Google.
pub(crate) fn note(step: &str) {
    if pass_agent::timing::enabled() {
        pass_agent::timing::Trace::begin(step);
    }
}

pub fn refresh_step(answer: &Result<(u16, String), AuthError>) -> String {
    let (status, body) = match answer {
        Ok(answer) => answer,
        Err(_) => return "gdrive: refresh failed (network)".into(),
    };
    let r: TokenResponse = serde_json::from_str(body).unwrap_or_default();
    match r.error.as_deref().filter(|e| !e.is_empty()) {
        Some("invalid_grant") => "gdrive: signed out (invalid_grant)".into(),
        Some(code) => format!(
            "gdrive: refresh failed ({})",
            pass_agent::timing::safe_code(code)
        ),
        None if !(200..300).contains(status) => format!("gdrive: refresh failed (http {status})"),
        None if r.access_token.as_deref().is_none_or(str::is_empty) => {
            "gdrive: refresh failed (no_access_token)".into()
        }
        None => "gdrive: token refreshed".into(),
    }
}

fn refused_description(body: &str) -> Option<String> {
    let r: TokenResponse = serde_json::from_str(body).ok()?;
    if r.error.as_deref() != Some("invalid_grant") {
        return None;
    }
    let description: String = r
        .error_description
        .unwrap_or_default()
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(120)
        .collect();
    Some(if description.is_empty() {
        "(no description)".into()
    } else {
        description
    })
}

struct Cached {
    email: String,
    token: Zeroizing<String>,
    expires: Instant,
}

static ACCESS: Mutex<Vec<Cached>> = Mutex::new(Vec::new());
static PENDING: Mutex<Option<(String, Zeroizing<String>)>> = Mutex::new(None);

fn guard<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

fn key(email: &str) -> String {
    email.trim().to_lowercase()
}

/// Where the refresh tokens of the accounts in use are kept ([`CredentialManager`]; tests use an
/// in-memory fake). Errors are short codes for the logs; "nothing stored" is `Ok(None)`.
pub(crate) trait Store: Send + Sync {
    fn get(&self, account: &str) -> Result<Option<Zeroizing<String>>, &'static str>;
    fn set(&self, account: &str, token: &str) -> Result<(), &'static str>;
    fn delete(&self, account: &str);
}

/// Generic credentials `Pass/GoogleDrive/<e-mail>` (the `keyring` crate; the same target name for every build and install path).
#[cfg_attr(test, allow(dead_code))]
struct CredentialManager;

#[cfg_attr(test, allow(dead_code))]
fn keyring_code(e: &keyring::Error) -> &'static str {
    match e {
        keyring::Error::PlatformFailure(_) => "platform",
        keyring::Error::NoStorageAccess(_) => "no_storage_access",
        keyring::Error::NoEntry => "no_entry",
        keyring::Error::BadEncoding(_) => "bad_encoding",
        keyring::Error::TooLong(..) => "too_long",
        keyring::Error::Invalid(..) => "invalid",
        keyring::Error::Ambiguous(_) => "ambiguous",
        _ => "other",
    }
}

#[cfg_attr(test, allow(dead_code))]
impl CredentialManager {
    fn entry(account: &str) -> Result<keyring::Entry, &'static str> {
        crate::platform::keyring_entry(
            &format!("Pass/GoogleDrive/{account}"),
            KEYRING_SERVICE,
            account,
        )
        .map_err(|e| Self::failed("open", &e))
    }

    fn failed(what: &str, e: &keyring::Error) -> &'static str {
        crate::applog::plog!("Credential Manager: Google sign-in {what}: {e}");
        keyring_code(e)
    }
}

impl Store for CredentialManager {
    fn get(&self, account: &str) -> Result<Option<Zeroizing<String>>, &'static str> {
        match Self::entry(account)?.get_password() {
            Ok(token) => Ok(Some(Zeroizing::new(token))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(Self::failed("read", &e)),
        }
    }

    fn set(&self, account: &str, token: &str) -> Result<(), &'static str> {
        Self::entry(account)?
            .set_password(token)
            .map_err(|e| Self::failed("write", &e))
    }

    fn delete(&self, account: &str) {
        if let Ok(entry) = Self::entry(account) {
            match entry.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry) => {}
                Err(e) => {
                    Self::failed("delete", &e);
                }
            }
        }
    }
}

#[cfg(not(test))]
fn store() -> &'static dyn Store {
    &CredentialManager
}

#[cfg(test)]
fn store() -> &'static dyn Store {
    tests::fake_store()
}

fn cache_access(email: &str, tokens: &Tokens) {
    let email = key(email);
    let mut cache = guard(&ACCESS);
    cache.retain(|c| c.email != email);
    cache.push(Cached {
        email,
        token: tokens.access_token.clone(),
        expires: Instant::now() + tokens.expires_in,
    });
}

pub fn store_pending(email: &str, tokens: &Tokens) {
    cache_access(email, tokens);
    if let Some(refresh) = &tokens.refresh_token {
        *guard(&PENDING) = Some((key(email), refresh.clone()));
    }
    note("gdrive: signed in (kept in memory until a vault uses it)");
}

pub fn forget_access(email: &str) {
    let email = key(email);
    guard(&ACCESS).retain(|c| c.email != email);
}

/// The refresh token for `email`: the pending sign-in's, else the stored one. `Err` (unreadable
/// right now) is not a sign-out: the next try reads it again.
fn stored_refresh_token(email: &str) -> Result<Option<Zeroizing<String>>, AuthError> {
    if let Some((pending, token)) = guard(&PENDING).as_ref() {
        if *pending == key(email) {
            return Ok(Some(token.clone()));
        }
    }
    store().get(&key(email)).map_err(|code| {
        note(&format!("gdrive: credential read failed ({code})"));
        AuthError::Failed(tr!("errors.google_store_read"))
    })
}

/// Google refused `used` (`invalid_grant`). Forgets it, but only where they still hold that very
/// token: a newer sign-in that arrived meanwhile is kept and returned for one more try.
fn forget_refused(email: &str, used: &str) -> Option<Zeroizing<String>> {
    {
        let mut pending = guard(&PENDING);
        match pending.as_ref() {
            Some((e, t)) if *e == key(email) && t.as_str() == used => *pending = None,
            Some((e, t)) if *e == key(email) => return Some(t.clone()),
            _ => {}
        }
    }
    match store().get(&key(email)) {
        Ok(Some(stored)) if stored.as_str() != used => Some(stored),
        Ok(Some(_)) => {
            store().delete(&key(email));
            None
        }
        // Nothing stored, or unreadable right now: nothing newer to try.
        _ => None,
    }
}

/// A current access token for `email`: the cached one, or a refreshed one (`force`: after Drive
/// refused the cached one). Blocking. Only `invalid_grant` or no sign-in is [`AuthError::SignInAgain`];
/// other errors are [`AuthError::Failed`] and keep the sign-in.
pub fn access_token(
    endpoints: &Endpoints,
    client: &Client,
    email: &str,
    force: bool,
) -> Result<Zeroizing<String>, AuthError> {
    if !force {
        let cache = guard(&ACCESS);
        if let Some(c) = cache
            .iter()
            .find(|c| c.email == key(email) && c.expires > Instant::now() + REFRESH_MARGIN)
        {
            return Ok(c.token.clone());
        }
    }
    let Some(mut refresh_token) = stored_refresh_token(email)? else {
        note("gdrive: signed out (no stored sign-in)");
        forget_access(email);
        return Err(AuthError::SignInAgain);
    };
    // A second round only when a newer sign-in replaced the refused token meanwhile.
    for _ in 0..2 {
        match refresh(endpoints, client, &refresh_token) {
            Ok(tokens) => {
                cache_access(email, &tokens);
                return Ok(tokens.access_token);
            }
            Err(AuthError::SignInAgain) => match forget_refused(email, &refresh_token) {
                Some(newer) => refresh_token = newer,
                None => break,
            },
            Err(e) => return Err(e),
        }
    }
    // Useless from now on, and forgotten (forget_refused).
    forget_access(email);
    Err(AuthError::SignInAgain)
}

/// A vault now uses `email`: the pending refresh token goes to the credential store and is read
/// back, so a write that didn't stick fails now, not an hour later. Without a pending sign-in the
/// account must be stored already.
pub fn commit(email: &str) -> Result<(), String> {
    let store_failed = |code: &str| {
        note(&format!("gdrive: store failed ({code})"));
        tr!("errors.google_store")
    };
    let pending = guard(&PENDING)
        .as_ref()
        .filter(|(e, _)| *e == key(email))
        .map(|(_, t)| t.clone());
    let Some(token) = pending else {
        return match store().get(&key(email)) {
            Ok(Some(_)) => Ok(()),
            Ok(None) => {
                note("gdrive: store failed (no sign-in to store)");
                Err(tr!("errors.google_sign_in_first"))
            }
            Err(code) => Err(store_failed(code)),
        };
    };
    store().set(&key(email), &token).map_err(store_failed)?;
    match store().get(&key(email)) {
        Ok(Some(back)) if back.as_str() == token.as_str() => {}
        Ok(_) => return Err(store_failed("not_read_back")),
        Err(code) => return Err(store_failed(code)),
    }
    // Stored: the pending copy goes, unless a newer sign-in replaced it meanwhile.
    {
        let mut pending = guard(&PENDING);
        if pending
            .as_ref()
            .is_some_and(|(e, t)| *e == key(email) && t.as_str() == token.as_str())
        {
            *pending = None;
        }
    }
    note("gdrive: token stored");
    Ok(())
}

/// No vault uses `email` any more: deletes its credential and, with `revoke_with`, revokes the grant
/// at Google (best effort, in the background), which also ends access on other devices.
pub fn release(email: &str, revoke_with: Option<Endpoints>) {
    forget_access(email);
    let token = stored_refresh_token(email).ok().flatten();
    {
        let mut pending = guard(&PENDING);
        if pending.as_ref().is_some_and(|(e, _)| *e == key(email)) {
            *pending = None;
        }
    }
    store().delete(&key(email));
    note(if revoke_with.is_some() {
        "gdrive: sign-in removed (turned off, revoking at Google)"
    } else {
        "gdrive: sign-in removed (no vault uses it)"
    });
    if let (Some(endpoints), Some(token)) = (revoke_with, token) {
        std::thread::spawn(move || {
            note(match revoke(&endpoints, &token) {
                Ok(()) => "gdrive: access revoked",
                Err(_) => "gdrive: revoke failed",
            });
        });
    }
}

#[cfg(test)]
mod tests;
