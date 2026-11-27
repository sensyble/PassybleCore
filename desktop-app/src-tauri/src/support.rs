//! Help and support in the app: the same tickets, rules and staff queue as the web form at
//! `help.passyble.com/support`, without a browser.
//!
//! * **Signed in**: the account's tickets through the app session (`/v1/support/tickets`).
//! * **No account** (Google Drive, a local file, WebDAV, a self-hosted server): guest tickets. The
//!   address is required; the service keeps the ticket unconfirmed and e-mails a confirmation link with
//!   a one-time code. The app keeps the `claim` it got in the credential store
//!   (`Pass/PassybleSupport/<host>/<reference>/claim`), polls `guest/status`, and exchanges claim and
//!   code for the `spt_` ticket token (same store, `.../token`). The code arrives through the app link
//!   (`passyble://support/app?r=&c=`, or the e-mailed `https://help.passyble.com/support/app?r=&c=`
//!   pasted in) or typed in. Removing a guest ticket revokes its token.
//! * **Diagnostics**: optional, built here from [`DIAGNOSTIC_FIELDS`] only, shown in full before
//!   sending, and filtered again ([`clean_diagnostics`]) whatever the window sends. Never vault data,
//!   names, addresses, URLs or paths: a value is letters, digits, spaces and `. _ - + ( ) ,` only,
//!   under 64 characters.
//! * **Replies**: the desktop has no push channel, so a background poll (every 15 minutes, only while
//!   there are tickets to follow) looks for staff replies and says so in the tray and the main window.
//!
//! No ticket text, claim, code or token is ever logged.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use tauri::{AppHandle, Emitter};
use zeroize::Zeroizing;

use crate::account::{self, Store};
use crate::commands::{app_state, blocking};
use crate::i18n::{tr, trn};
use crate::teams_api::{self, AccountApi, ApiError, Request, Transport};

type Res<T> = Result<T, String>;

pub const DIAGNOSTIC_FIELDS: [&str; 7] = [
    "app",
    "app_version",
    "platform",
    "os_version",
    "sync",
    "errors",
    "locale",
];
pub const VALUE_MAX: usize = 63;
pub const ERRORS_MAX: usize = 10;
pub const ERROR_MAX: usize = 40;
pub const MAX_GUESTS: usize = 10;
pub const SUBJECT_MAX: usize = 150;
pub const BODY_MAX: usize = 5000;
pub const NAME_MAX: usize = 100;
pub const CODE_LEN: usize = 8;
const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const KEY_PREFIX: &str = "Pass/PassybleSupport";
/// The URL scheme of the app links (tauri.conf.json `plugins.deep-link`).
pub const SCHEME: &str = "passyble://";

const FIRST_POLL: Duration = Duration::from_secs(2 * 60);
const POLL_EVERY: Duration = Duration::from_secs(15 * 60);

fn guard<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct GuestTicket {
    pub reference: String,
    /// The address the confirmation went to.
    pub email: String,
    pub subject: String,
    pub category: String,
    pub created_at: i64,
    /// Until when the e-mailed code works (ms), while unclaimed.
    pub confirm_by: i64,
    pub claimed: bool,
    pub status: String,
    pub unread: i64,
    pub last_message_at: i64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SupportSettings {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub guests: Vec<GuestTicket>,
    /// Per ticket, the `last_message_at` whose staff reply was already announced.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub notified: BTreeMap<String, i64>,
}

/// A diagnostics value: 1 to [`VALUE_MAX`] letters, digits, spaces and `. _ - + ( ) ,` (so no
/// `/ : @ = ? #`: no URL, address, path or key-value secret).
pub fn value_ok(v: &str) -> bool {
    let n = v.chars().count();
    (1..=VALUE_MAX).contains(&n)
        && v.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, ' ' | '.' | '_' | '-' | '+' | '(' | ')' | ',')
        })
}

pub fn error_ok(v: &str) -> bool {
    (1..=ERROR_MAX).contains(&v.len())
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

pub fn squeeze(s: &str) -> String {
    let mapped: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+' | '(' | ')' | ',') {
                c
            } else {
                ' '
            }
        })
        .collect();
    let joined = mapped.split_whitespace().collect::<Vec<_>>().join(" ");
    joined
        .chars()
        .take(VALUE_MAX)
        .collect::<String>()
        .trim()
        .to_string()
}

pub fn clean_diagnostics(v: &Value) -> Option<Value> {
    let obj = v.as_object()?;
    let mut out = Map::new();
    for field in DIAGNOSTIC_FIELDS {
        match (field, obj.get(field)) {
            ("errors", Some(Value::Array(items))) => {
                let mut codes: Vec<&str> = Vec::new();
                for code in items.iter().filter_map(Value::as_str).map(str::trim) {
                    if error_ok(code) && !codes.contains(&code) && codes.len() < ERRORS_MAX {
                        codes.push(code);
                    }
                }
                if !codes.is_empty() {
                    out.insert(field.into(), json!(codes));
                }
            }
            ("errors", _) => {}
            (_, Some(Value::String(s))) if value_ok(s.trim()) => {
                out.insert(field.into(), json!(s.trim()));
            }
            _ => {}
        }
    }
    (!out.is_empty()).then_some(Value::Object(out))
}

static ERRORS: Mutex<Vec<String>> = Mutex::new(Vec::new());

pub fn note_error(code: &str) {
    let code: String = code
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
        .take(ERROR_MAX)
        .collect();
    if code.is_empty() {
        return;
    }
    push_error(&mut guard(&ERRORS), code);
}

fn push_error(errors: &mut Vec<String>, code: String) {
    errors.retain(|c| *c != code);
    errors.insert(0, code);
    errors.truncate(ERRORS_MAX);
}

pub fn recent_errors() -> Vec<String> {
    guard(&ERRORS).clone()
}

pub fn sync_error_code(e: &pass_core::PassError) -> &'static str {
    use pass_core::PassError::*;
    match e {
        InvalidPassword => "sync.invalid_password",
        Corrupt(_) => "sync.corrupt",
        Crypto(_) => "sync.crypto",
        InvalidInput(_) => "sync.invalid_input",
        NotFound(_) => "sync.not_found",
        Network(_) => "sync.network",
        Conflict(_) => "sync.conflict",
        CertificateChanged(_) => "sync.certificate_changed",
        AuthRequired(_) => "sync.auth_required",
    }
}

pub fn sync_kind(s: &crate::settings::Settings) -> &'static str {
    let Some(v) = s.active() else {
        return "none";
    };
    if v.google_drive.is_some() {
        return "google_drive";
    }
    match &v.webdav {
        Some(w) if w.is_pass_server() => {
            let cloud_host = s
                .passyble_account
                .as_ref()
                .and_then(|a| a.cloud.as_ref())
                .map(|c| crate::settings::WebDavSettings {
                    url: c.server_url.clone(),
                    ..Default::default()
                })
                .map(|c| c.host());
            if cloud_host.is_some_and(|h| !h.is_empty() && h == w.host()) {
                "passyble_cloud"
            } else {
                "passyble_server"
            }
        }
        Some(_) => "webdav",
        None => "local",
    }
}

pub fn os_version() -> String {
    squeeze(&os_version_text())
}

#[cfg(windows)]
fn os_version_text() -> String {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    let Ok(key) = winreg::RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion")
    else {
        return "Windows".into();
    };
    let build: String = key.get_value("CurrentBuildNumber").unwrap_or_default();
    let ubr: Option<u32> = key.get_value("UBR").ok();
    let display: String = key.get_value("DisplayVersion").unwrap_or_default();
    // ProductName still says "Windows 10" on Windows 11: the build tells them apart.
    let name = if build.parse::<u32>().is_ok_and(|b| b >= 22000) {
        "Windows 11"
    } else {
        "Windows 10"
    };
    let build = match ubr {
        Some(u) if !build.is_empty() => format!("{build}.{u}"),
        _ => build,
    };
    format!("{name} {display} (build {build})")
}

#[cfg(target_os = "macos")]
fn os_version_text() -> String {
    let plist = std::fs::read_to_string("/System/Library/CoreServices/SystemVersion.plist")
        .unwrap_or_default();
    let version = plist
        .split("<key>ProductVersion</key>")
        .nth(1)
        .and_then(|r| r.split("<string>").nth(1))
        .and_then(|r| r.split("</string>").next())
        .unwrap_or_default();
    format!("macOS {version}")
}

#[cfg(target_os = "linux")]
fn os_version_text() -> String {
    let release = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
    let pretty = release
        .lines()
        .find_map(|l| l.strip_prefix("PRETTY_NAME="))
        .map(|v| v.trim().trim_matches('"').to_string())
        .unwrap_or_else(|| "Linux".into());
    format!("Linux {pretty}")
}

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
fn os_version_text() -> String {
    std::env::consts::OS.to_string()
}

pub fn build_diagnostics(settings: &crate::settings::Settings) -> Option<Value> {
    clean_diagnostics(&json!({
        "app": "Passyble desktop",
        "app_version": env!("CARGO_PKG_VERSION"),
        "platform": crate::app_versions::PLATFORM,
        "os_version": os_version(),
        "sync": sync_kind(settings),
        "errors": recent_errors(),
        "locale": crate::i18n::locale(),
    }))
}

pub fn parse_reference(s: &str) -> Option<String> {
    let s = s.trim().to_ascii_uppercase();
    let tail = s.strip_prefix("PS-")?;
    (tail.len() == 6 && tail.bytes().all(|b| ALPHABET.contains(&b))).then_some(s)
}

pub fn normalize_code(s: &str) -> Option<String> {
    let c: String = s
        .chars()
        .filter(|c| !matches!(c, ' ' | '-'))
        .map(|c| c.to_ascii_uppercase())
        .collect();
    (c.len() == CODE_LEN && c.bytes().all(|b| ALPHABET.contains(&b))).then_some(c)
}

#[derive(Debug, PartialEq, Eq)]
pub enum SupportLink {
    Open,
    Claim { reference: String, code: String },
}

/// The host of the support pages; the e-mailed links of older mails carry the account host instead.
const HELP_HOST: &str = "help.passyble.com";

/// `passyble://support[/...]`, `passyble://support/app?r=&c=`, or the e-mailed
/// `https://help.passyble.com/support/app?r=&c=` or `https://<account host>/...` (`account_host`: the
/// service's `host[:port]`).
pub fn parse_link(link: &str, account_host: &str) -> Option<SupportLink> {
    let link = link.trim();
    let lower = link.to_ascii_lowercase();
    let (rest, app_scheme) = if lower.starts_with(SCHEME) {
        (&link[SCHEME.len()..], true)
    } else if let Some(r) = lower.strip_prefix("https://") {
        let host = r.split(['/', '?', '#']).next().unwrap_or_default();
        if !(host == HELP_HOST
            || (!account_host.is_empty() && host == account_host.to_ascii_lowercase()))
        {
            return None;
        }
        (&link["https://".len() + host.len()..], false)
    } else {
        return None;
    };
    let rest = rest.trim_start_matches('/');
    let (path, query) = rest.split_once('?').unwrap_or((rest, ""));
    let path = path
        .split('#')
        .next()
        .unwrap_or_default()
        .trim_end_matches('/');
    let path = path.to_ascii_lowercase();
    if path == "support/app" {
        let query = query.split('#').next().unwrap_or_default();
        let reference = parse_reference(&account::query_param(query, "r"));
        let code = normalize_code(&account::query_param(query, "c"));
        if let (Some(reference), Some(code)) = (reference, code) {
            return Some(SupportLink::Claim { reference, code });
        }
        return app_scheme.then_some(SupportLink::Open);
    }
    (app_scheme && (path == "support" || path.starts_with("support/"))).then_some(SupportLink::Open)
}

pub fn parse_code_input(text: &str, account_host: &str) -> Option<(Option<String>, String)> {
    if let Some(SupportLink::Claim { reference, code }) = parse_link(text, account_host) {
        return Some((Some(reference), code));
    }
    normalize_code(text).map(|c| (None, c))
}

pub fn valid_email(email: &str) -> bool {
    let e = email.trim();
    let Some((local, domain)) = e.split_once('@') else {
        return false;
    };
    e.len() <= 254
        && !local.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !e
            .chars()
            .any(|c| c.is_whitespace() || c == '<' || c == '>' || c == ',')
        && !domain.contains('@')
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct NewTicket {
    pub subject: String,
    pub body: String,
    pub category: String,
    pub diagnostics: Option<Value>,
    pub email: Option<String>,
    pub name: Option<String>,
}

impl NewTicket {
    pub fn check(&self, guest: bool) -> Res<()> {
        let subject = self.subject.trim().chars().count();
        if subject == 0 || subject > SUBJECT_MAX {
            return Err(tr!("support.err_subject"));
        }
        let body = self.body.trim().chars().count();
        if body == 0 || body > BODY_MAX {
            return Err(tr!("support.err_body"));
        }
        if self.category.trim().is_empty() {
            return Err(tr!("support.err_topic"));
        }
        if self
            .name
            .as_deref()
            .unwrap_or_default()
            .trim()
            .chars()
            .count()
            > NAME_MAX
        {
            return Err(tr!("support.err_name"));
        }
        if guest && !valid_email(self.email.as_deref().unwrap_or_default()) {
            return Err(tr!("support.err_email"));
        }
        Ok(())
    }

    pub fn json(&self, email: Option<&str>) -> Value {
        let mut body = json!({
            "subject": self.subject.trim(),
            "body": self.body.trim(),
            "category": self.category.trim(),
        });
        if let Some(d) = self.diagnostics.as_ref().and_then(clean_diagnostics) {
            body["diagnostics"] = d;
        }
        if let Some(name) = self
            .name
            .as_deref()
            .map(str::trim)
            .filter(|n| !n.is_empty())
        {
            body["name"] = json!(name);
        }
        if let Some(email) = email {
            body["email"] = json!(email.trim());
        }
        body
    }
}

pub struct SupportApi<'a> {
    base: String,
    transport: &'a dyn Transport,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct GuestCreated {
    pub reference: String,
    pub claim: String,
    pub confirm_by: i64,
}

impl<'a> SupportApi<'a> {
    pub fn new(base: &str, transport: &'a dyn Transport) -> Self {
        Self {
            base: base.trim().trim_end_matches('/').to_string(),
            transport,
        }
    }

    pub fn host(&self) -> String {
        self.base
            .split("://")
            .nth(1)
            .and_then(|r| r.split('/').next())
            .unwrap_or_default()
            .to_ascii_lowercase()
    }

    fn call(
        &self,
        method: &'static str,
        path: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> Result<Value, ApiError> {
        let request = Request {
            method,
            url: format!("{}/v1/support{path}", self.base),
            auth: token.map(|t| Zeroizing::new(format!("Bearer {t}"))),
            body: body.map(|b| ("application/json", b.to_string().into_bytes())),
            pins: Vec::new(),
            headers: Vec::new(),
        };
        teams_api::parse_answer(&self.transport.send(&request)?)
    }

    pub fn meta(&self) -> Result<Value, ApiError> {
        self.call("GET", "/meta", None, None)
    }

    pub fn guest_create(&self, t: &NewTicket, email: &str) -> Result<GuestCreated, ApiError> {
        let v = self.call("POST", "/guest/tickets", None, Some(t.json(Some(email))))?;
        let created: GuestCreated = serde_json::from_value(v).unwrap_or_default();
        if parse_reference(&created.reference).is_none() || created.claim.len() < 32 {
            return Err(ApiError::Unexpected(tr!("errors.teams_unexpected_answer")));
        }
        Ok(created)
    }

    pub fn guest_status(&self, reference: &str, claim: &str) -> Result<bool, ApiError> {
        let v = self.call(
            "POST",
            "/guest/status",
            None,
            Some(json!({ "reference": reference, "claim": claim })),
        )?;
        Ok(v["confirmed"].as_bool().unwrap_or(false))
    }

    pub fn guest_claim(
        &self,
        reference: &str,
        claim: &str,
        code: &str,
    ) -> Result<(Zeroizing<String>, Value), ApiError> {
        let mut v = self.call(
            "POST",
            "/guest/claim",
            None,
            Some(json!({ "reference": reference, "claim": claim, "code": code })),
        )?;
        let token = v
            .get("token")
            .and_then(Value::as_str)
            .filter(|t| t.starts_with("spt_"))
            .map(|t| Zeroizing::new(t.to_string()))
            .ok_or_else(|| ApiError::Unexpected(tr!("errors.teams_unexpected_answer")))?;
        if let Some(obj) = v.as_object_mut() {
            obj.remove("token");
        }
        Ok((token, v))
    }

    pub fn guest_thread(&self, token: &str) -> Result<Value, ApiError> {
        self.call("GET", "/guest/ticket", Some(token), None)
    }

    pub fn guest_reply(&self, token: &str, body: &str) -> Result<Value, ApiError> {
        self.call(
            "POST",
            "/guest/ticket/reply",
            Some(token),
            Some(json!({ "body": body })),
        )
    }

    pub fn guest_close(&self, token: &str) -> Result<Value, ApiError> {
        self.call("POST", "/guest/ticket/close", Some(token), None)
    }

    pub fn guest_read(&self, token: &str, up_to: Option<i64>) -> Result<Value, ApiError> {
        self.call(
            "POST",
            "/guest/ticket/read",
            Some(token),
            Some(read_body(up_to)),
        )
    }

    pub fn guest_revoke(&self, token: &str) -> Result<Value, ApiError> {
        self.call("DELETE", "/guest/token", Some(token), None)
    }
}

fn read_body(up_to: Option<i64>) -> Value {
    match up_to {
        Some(id) => json!({ "up_to": id }),
        None => json!({}),
    }
}

pub mod mine {
    use super::*;

    fn path(reference: &str, action: &str) -> String {
        format!("/support/tickets/{}{action}", teams_api::segment(reference))
    }

    pub fn list(api: &AccountApi<'_>) -> Result<Value, ApiError> {
        api.call("GET", "/support/tickets", None)
    }

    pub fn create(api: &AccountApi<'_>, t: &NewTicket) -> Result<Value, ApiError> {
        api.call("POST", "/support/tickets", Some(t.json(None)))
    }

    pub fn thread(api: &AccountApi<'_>, reference: &str) -> Result<Value, ApiError> {
        api.call("GET", &path(reference, ""), None)
    }

    pub fn reply(api: &AccountApi<'_>, reference: &str, body: &str) -> Result<Value, ApiError> {
        api.call(
            "POST",
            &path(reference, "/reply"),
            Some(json!({ "body": body })),
        )
    }

    pub fn close(api: &AccountApi<'_>, reference: &str) -> Result<Value, ApiError> {
        api.call("POST", &path(reference, "/close"), None)
    }

    pub fn read(
        api: &AccountApi<'_>,
        reference: &str,
        up_to: Option<i64>,
    ) -> Result<Value, ApiError> {
        api.call("POST", &path(reference, "/read"), Some(read_body(up_to)))
    }
}

fn secret_name(host: &str, reference: &str, kind: &str) -> String {
    format!("{KEY_PREFIX}/{host}/{reference}/{kind}")
}

pub fn last_message_id(thread: &Value) -> Option<i64> {
    thread["messages"]
        .as_array()
        .and_then(|m| m.iter().filter_map(|m| m["id"].as_i64()).max())
}

fn update_guest(g: &mut GuestTicket, thread: &Value) {
    let t = &thread["ticket"];
    if let Some(status) = t["status"].as_str() {
        g.status = status.to_string();
    }
    g.unread = t["unread"].as_i64().unwrap_or(0);
    g.last_message_at = t["last_message_at"].as_i64().unwrap_or(g.last_message_at);
    if let Some(subject) = t["subject"].as_str().filter(|s| !s.is_empty()) {
        g.subject = subject.to_string();
    }
}

/// A guest ticket's token no longer works: deleted with its ticket (unconfirmed for 48 hours, a
/// year without messages) or revoked.
fn token_gone(e: &ApiError) -> bool {
    e.status() == 401 || e.status() == 404 || e.code() == "invalid_token"
}

pub(crate) fn create_guest(
    api: &SupportApi<'_>,
    store: &dyn Store,
    s: &mut SupportSettings,
    t: &NewTicket,
    now: i64,
) -> Res<GuestTicket> {
    t.check(true)?;
    if s.guests.len() >= MAX_GUESTS {
        return Err(tr!("support.err_too_many_guests", count = MAX_GUESTS));
    }
    let email = t.email.as_deref().unwrap_or_default().trim().to_string();
    let created = api.guest_create(t, &email).map_err(|e| e.message())?;
    store.set(
        &secret_name(&api.host(), &created.reference, "claim"),
        &created.claim,
    )?;
    let guest = GuestTicket {
        reference: created.reference,
        email,
        subject: t.subject.trim().to_string(),
        category: t.category.trim().to_string(),
        created_at: now,
        confirm_by: created.confirm_by,
        claimed: false,
        status: "unconfirmed".into(),
        unread: 0,
        last_message_at: now,
    };
    s.guests.retain(|g| g.reference != guest.reference);
    s.guests.insert(0, guest.clone());
    Ok(guest)
}

pub(crate) fn check_guest(api: &SupportApi<'_>, store: &dyn Store, reference: &str) -> Res<bool> {
    let claim = store
        .get(&secret_name(&api.host(), reference, "claim"))
        .ok_or_else(|| tr!("support.err_no_claim"))?;
    api.guest_status(reference, &claim).map_err(|e| e.message())
}

pub(crate) fn claim_guest(
    api: &SupportApi<'_>,
    store: &dyn Store,
    s: &mut SupportSettings,
    reference: &str,
    code: &str,
) -> Res<Value> {
    claim_guest_final(api, store, s, reference, code).map_err(|(message, _)| message)
}

/// Whether the service's refusal is its last word on a code (wrong, used up, expired), so asking
/// again can't help. Offline, timeouts, rate limits and server errors may pass.
fn claim_refused_for_good(e: &ApiError) -> bool {
    matches!(e, ApiError::Refused { status, .. } if (400..500).contains(status) && *status != 408 && *status != 429)
}

fn claim_guest_final(
    api: &SupportApi<'_>,
    store: &dyn Store,
    s: &mut SupportSettings,
    reference: &str,
    code: &str,
) -> Result<Value, (String, bool)> {
    let host = api.host();
    let (link_reference, code) =
        parse_code_input(code, &host).ok_or_else(|| (tr!("support.err_code_shape"), true))?;
    let reference = link_reference.unwrap_or_else(|| reference.to_string());
    let Some(index) = s.guests.iter().position(|g| g.reference == reference) else {
        return Err((tr!("support.err_link_elsewhere"), true));
    };
    let claim = store
        .get(&secret_name(&host, &reference, "claim"))
        .ok_or_else(|| (tr!("support.err_no_claim"), true))?;
    let (token, thread) = api
        .guest_claim(&reference, &claim, &code)
        .map_err(|e| (e.message(), claim_refused_for_good(&e)))?;
    store
        .set(&secret_name(&host, &reference, "token"), &token)
        .map_err(|e| (e, false))?;
    store.delete(&secret_name(&host, &reference, "claim"));
    let g = &mut s.guests[index];
    g.claimed = true;
    g.confirm_by = 0;
    update_guest(g, &thread);
    Ok(with_guest(thread, true))
}

type PendingLink = Mutex<Option<(String, Zeroizing<String>)>>;

/// Claims the pending app link's ticket. The code stays until the claim succeeds or the service
/// refuses it for good, so a failed try (offline, server error) can be confirmed again; a second
/// call while one is under way does nothing.
fn claim_pending(
    pending: &PendingLink,
    busy: &AtomicBool,
    run: impl FnOnce(&str, &str) -> Result<Value, (String, bool)>,
) -> Res<Value> {
    let Some((reference, code)) = guard(pending).clone() else {
        return Ok(Value::Null);
    };
    if busy.swap(true, Ordering::AcqRel) {
        return Ok(Value::Null);
    }
    let result = run(&reference, &code);
    if matches!(&result, Ok(_) | Err((_, true))) {
        *guard(pending) = None;
    }
    busy.store(false, Ordering::Release);
    result.map_err(|(message, _)| message)
}

fn guest_token(api: &SupportApi<'_>, store: &dyn Store, reference: &str) -> Res<Zeroizing<String>> {
    store
        .get(&secret_name(&api.host(), reference, "token"))
        .ok_or_else(|| tr!("support.err_not_claimed"))
}

/// Forgets a guest ticket on this PC and revokes its token (the ticket stays with the service and
/// its e-mailed links keep working).
pub(crate) fn remove_guest(
    api: &SupportApi<'_>,
    store: &dyn Store,
    s: &mut SupportSettings,
    reference: &str,
) {
    let host = api.host();
    if let Some(token) = store.get(&secret_name(&host, reference, "token")) {
        let _ = api.guest_revoke(&token);
    }
    store.delete(&secret_name(&host, reference, "token"));
    store.delete(&secret_name(&host, reference, "claim"));
    s.guests.retain(|g| g.reference != reference);
    s.notified.remove(reference);
}

fn with_guest(mut thread: Value, guest: bool) -> Value {
    if let Some(t) = thread.get_mut("ticket").and_then(Value::as_object_mut) {
        t.insert("guest".into(), json!(guest));
    }
    thread
}

fn guest_list_entry(g: &GuestTicket, now: i64) -> Value {
    let status = if g.claimed {
        g.status.clone()
    } else if g.confirm_by > 0 && now > g.confirm_by {
        "expired".into()
    } else {
        "unconfirmed".into()
    };
    json!({
        "reference": g.reference,
        "subject": g.subject,
        "category": g.category,
        "status": status,
        "unread": g.unread,
        "created_at": g.created_at,
        "last_message_at": g.last_message_at,
        "confirm_by": g.confirm_by,
        "email": g.email,
        "guest": true,
        "claimed": g.claimed,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Seen {
    pub reference: String,
    pub unread: i64,
    pub last_message_at: i64,
}

impl Seen {
    fn of(ticket: &Value) -> Option<Self> {
        Some(Self {
            reference: ticket["reference"].as_str()?.to_string(),
            unread: ticket["unread"].as_i64().unwrap_or(0),
            last_message_at: ticket["last_message_at"].as_i64().unwrap_or(0),
        })
    }
}

pub fn new_replies(seen: &[Seen], notified: &mut BTreeMap<String, i64>) -> Vec<String> {
    let mut out = Vec::new();
    for s in seen {
        let last = notified.get(&s.reference).copied().unwrap_or(0);
        if s.unread > 0 && s.last_message_at > last {
            out.push(s.reference.clone());
            notified.insert(s.reference.clone(), s.last_message_at);
        }
    }
    notified.retain(|r, _| seen.iter().any(|s| &s.reference == r));
    out
}

fn base(app: &AppHandle) -> String {
    account::base_url(&app_state(app).settings())
}

fn support_api(app: &AppHandle) -> SupportApi<'static> {
    SupportApi::new(&base(app), teams_api::transport())
}

fn settings_of(app: &AppHandle) -> SupportSettings {
    app_state(app).settings().support.unwrap_or_default()
}

fn update<T>(app: &AppHandle, f: impl FnOnce(&mut SupportSettings) -> Res<T>) -> Res<T> {
    app_state(app).update_settings(|s| {
        let mut support = s.support.take().unwrap_or_default();
        let out = f(&mut support);
        s.support = (support != SupportSettings::default()).then_some(support);
        out
    })
}

/// Runs `f` (network calls included) on a copy of the support settings, then keeps the copy:
/// settings.json stays unlocked while the service answers.
fn edit<T>(app: &AppHandle, f: impl FnOnce(&mut SupportSettings) -> Res<T>) -> Res<T> {
    let mut copy = settings_of(app);
    let out = f(&mut copy);
    update(app, |kept| {
        *kept = copy;
        Ok(())
    })?;
    out
}

fn is_guest(app: &AppHandle, reference: &str) -> bool {
    settings_of(app)
        .guests
        .iter()
        .any(|g| g.reference == reference)
}

static FOLLOW_ACCOUNT: AtomicBool = AtomicBool::new(true);
static UNREAD: Mutex<i64> = Mutex::new(0);
static PENDING: PendingLink = Mutex::new(None);
static CLAIMING: AtomicBool = AtomicBool::new(false);
static META: Mutex<Option<Value>> = Mutex::new(None);

fn note_open(tickets: &[Value]) {
    if tickets
        .iter()
        .any(|t| t["status"].as_str() != Some("closed"))
    {
        FOLLOW_ACCOUNT.store(true, Ordering::Relaxed);
    }
}

pub fn open_link(app: &AppHandle, link: &str) -> bool {
    let host = support_api(app).host();
    let Some(parsed) = parse_link(link, &host) else {
        return false;
    };
    let claim = match parsed {
        SupportLink::Claim { reference, code } => {
            *guard(&PENDING) = Some((reference, Zeroizing::new(code)));
            true
        }
        SupportLink::Open => false,
    };
    let _ = app.emit_to("main", "show-support", json!({ "claim": claim }));
    crate::popups::show_main(app);
    true
}

#[tauri::command]
pub fn support_status(app: AppHandle) -> Value {
    let account = account::signed_in(&app);
    let now = crate::vaults::now_ms();
    let guests: Vec<Value> = settings_of(&app)
        .guests
        .iter()
        .map(|g| guest_list_entry(g, now))
        .collect();
    json!({
        "signed_in": account.is_some(),
        "email": account.map(|a| a.email),
        "guests": guests,
        "unread": *guard(&UNREAD),
        "web_url": format!("{}/support", base(&app)),
        "link_pending": guard(&PENDING).is_some(),
        // The ticket reference only; the code stays here until the person confirms (`support_link_claim`).
        "link_reference": guard(&PENDING).as_ref().map(|(r, _)| r.clone()),
    })
}

#[tauri::command]
pub async fn support_meta(app: AppHandle) -> Res<Value> {
    blocking(move || {
        if let Some(meta) = guard(&META).clone() {
            return Ok(meta);
        }
        match support_api(&app).meta() {
            Ok(meta) if meta["categories"].is_array() => {
                *guard(&META) = Some(meta.clone());
                Ok(meta)
            }
            _ => {
                let topics: Vec<Value> = [
                    "account", "sync", "autofill", "passkeys", "teams", "billing", "other",
                ]
                .iter()
                .map(|id| json!({ "id": id }))
                .collect();
                Ok(json!({ "categories": topics, "offline": true }))
            }
        }
    })
    .await
}

#[tauri::command]
pub fn support_diagnostics(app: AppHandle) -> Value {
    build_diagnostics(&app_state(&app).settings()).unwrap_or(Value::Null)
}

#[tauri::command]
pub async fn support_tickets(app: AppHandle) -> Res<Value> {
    blocking(move || {
        let mut tickets: Vec<Value> = Vec::new();
        let mut errors: Vec<String> = Vec::new();
        if account::signed_in(&app).is_some() {
            match account::with_api(&app, |api, _| mine::list(api)) {
                Ok(v) => {
                    let list = v["tickets"].as_array().cloned().unwrap_or_default();
                    note_open(&list);
                    tickets.extend(list.into_iter().map(|mut t| {
                        t["guest"] = json!(false);
                        t
                    }));
                }
                Err(e) => errors.push(e),
            }
        }
        let api = support_api(&app);
        let store = account::store();
        let now = crate::vaults::now_ms();
        let mut guests = settings_of(&app).guests;
        for g in guests
            .iter_mut()
            .filter(|g| g.claimed && g.status != "gone")
        {
            let Some(token) = store.get(&secret_name(&api.host(), &g.reference, "token")) else {
                g.status = "gone".into();
                continue;
            };
            match api.guest_thread(&token) {
                Ok(thread) => update_guest(g, &thread),
                Err(e) if token_gone(&e) => g.status = "gone".into(),
                Err(e) => {
                    let m = e.message();
                    if !errors.contains(&m) {
                        errors.push(m);
                    }
                }
            }
        }
        update(&app, |s| {
            for g in &guests {
                if let Some(kept) = s.guests.iter_mut().find(|k| k.reference == g.reference) {
                    *kept = g.clone();
                }
            }
            Ok(())
        })?;
        tickets.extend(guests.iter().map(|g| guest_list_entry(g, now)));
        tickets.sort_by_key(|t| std::cmp::Reverse(t["last_message_at"].as_i64().unwrap_or(0)));
        let unread: i64 = tickets.iter().filter_map(|t| t["unread"].as_i64()).sum();
        *guard(&UNREAD) = unread;
        Ok(json!({ "tickets": tickets, "unread": unread, "errors": errors }))
    })
    .await
}

#[tauri::command]
pub async fn support_create(app: AppHandle, ticket: NewTicket) -> Res<Value> {
    blocking(move || {
        if account::signed_in(&app).is_some() {
            ticket.check(false)?;
            let thread = account::with_api(&app, |api, _| mine::create(api, &ticket))?;
            FOLLOW_ACCOUNT.store(true, Ordering::Relaxed);
            return Ok(json!({ "thread": with_guest(thread, false) }));
        }
        let api = support_api(&app);
        let now = crate::vaults::now_ms();
        let guest = edit(&app, |s| {
            create_guest(&api, account::store(), s, &ticket, now)
        })?;
        Ok(json!({ "guest": guest_list_entry(&guest, now) }))
    })
    .await
}

#[tauri::command]
pub async fn support_ticket(app: AppHandle, reference: String) -> Res<Value> {
    blocking(move || {
        if is_guest(&app, &reference) {
            let api = support_api(&app);
            let token = guest_token(&api, account::store(), &reference)?;
            let thread = api.guest_thread(&token).map_err(|e| e.message())?;
            if let Some(id) =
                last_message_id(&thread).filter(|_| thread["ticket"]["unread"].as_i64() > Some(0))
            {
                let _ = api.guest_read(&token, Some(id));
            }
            update(&app, |s| {
                if let Some(g) = s.guests.iter_mut().find(|g| g.reference == reference) {
                    update_guest(g, &thread);
                    g.unread = 0;
                }
                Ok(())
            })?;
            return Ok(with_guest(thread, true));
        }
        let thread = account::with_api(&app, |api, _| mine::thread(api, &reference))?;
        if let Some(id) =
            last_message_id(&thread).filter(|_| thread["ticket"]["unread"].as_i64() > Some(0))
        {
            let _ = account::with_api(&app, |api, _| mine::read(api, &reference, Some(id)));
        }
        Ok(with_guest(thread, false))
    })
    .await
}

#[tauri::command]
pub async fn support_reply(app: AppHandle, reference: String, body: String) -> Res<Value> {
    blocking(move || {
        let body = body.trim().to_string();
        if body.is_empty() || body.chars().count() > BODY_MAX {
            return Err(tr!("support.err_body"));
        }
        if is_guest(&app, &reference) {
            let api = support_api(&app);
            let token = guest_token(&api, account::store(), &reference)?;
            let thread = api.guest_reply(&token, &body).map_err(|e| e.message())?;
            update(&app, |s| {
                if let Some(g) = s.guests.iter_mut().find(|g| g.reference == reference) {
                    update_guest(g, &thread);
                }
                Ok(())
            })?;
            return Ok(with_guest(thread, true));
        }
        let thread = account::with_api(&app, |api, _| mine::reply(api, &reference, &body))?;
        FOLLOW_ACCOUNT.store(true, Ordering::Relaxed);
        Ok(with_guest(thread, false))
    })
    .await
}

#[tauri::command]
pub async fn support_close(app: AppHandle, reference: String) -> Res<Value> {
    blocking(move || {
        if is_guest(&app, &reference) {
            let api = support_api(&app);
            let token = guest_token(&api, account::store(), &reference)?;
            let thread = api.guest_close(&token).map_err(|e| e.message())?;
            update(&app, |s| {
                if let Some(g) = s.guests.iter_mut().find(|g| g.reference == reference) {
                    update_guest(g, &thread);
                }
                Ok(())
            })?;
            return Ok(with_guest(thread, true));
        }
        let thread = account::with_api(&app, |api, _| mine::close(api, &reference))?;
        Ok(with_guest(thread, false))
    })
    .await
}

#[tauri::command]
pub async fn support_guest_check(app: AppHandle, reference: String) -> Res<Value> {
    blocking(move || {
        let confirmed = check_guest(&support_api(&app), account::store(), &reference)?;
        Ok(json!({ "confirmed": confirmed }))
    })
    .await
}

#[tauri::command]
pub async fn support_guest_claim(app: AppHandle, reference: String, code: String) -> Res<Value> {
    blocking(move || {
        let api = support_api(&app);
        edit(&app, |s| {
            claim_guest(&api, account::store(), s, &reference, &code)
        })
    })
    .await
}

#[tauri::command]
pub async fn support_link_claim(app: AppHandle) -> Res<Value> {
    blocking(move || {
        let api = support_api(&app);
        let for_good = std::cell::Cell::new(false);
        claim_pending(&PENDING, &CLAIMING, |reference, code| {
            edit(&app, |s| {
                claim_guest_final(&api, account::store(), s, reference, code).map_err(|(m, f)| {
                    for_good.set(f);
                    m
                })
            })
            .map_err(|m| (m, for_good.get()))
        })
    })
    .await
}

#[tauri::command]
pub async fn support_guest_remove(app: AppHandle, reference: String) -> Res<Value> {
    blocking(move || {
        let api = support_api(&app);
        edit(&app, |s| {
            remove_guest(&api, account::store(), s, &reference);
            Ok(json!({}))
        })
    })
    .await
}

#[tauri::command]
pub fn support_open_web(app: AppHandle) -> Res<Value> {
    // The production support pages live on help.passyble.com; another service (a test one) keeps its own.
    let base = base(&app);
    let base = base.replace("://account.passyble.com", "://help.passyble.com");
    crate::platform::open_browser(&format!("{base}/support"))?;
    Ok(json!({}))
}

pub fn start(app: &AppHandle) {
    let app = app.clone();
    let _ = std::thread::Builder::new()
        .name("pass-support-poll".into())
        .spawn(move || {
            std::thread::sleep(FIRST_POLL);
            loop {
                poll(&app);
                std::thread::sleep(POLL_EVERY);
            }
        });
}

fn poll(app: &AppHandle) {
    let mut seen: Vec<Seen> = Vec::new();
    let mut complete = true;
    if account::signed_in(app).is_some() && FOLLOW_ACCOUNT.load(Ordering::Relaxed) {
        match account::with_api(app, |api, _| mine::list(api)) {
            Ok(v) => {
                let list = v["tickets"].as_array().cloned().unwrap_or_default();
                let open = list.iter().any(|t| t["status"].as_str() != Some("closed"));
                FOLLOW_ACCOUNT.store(open, Ordering::Relaxed);
                seen.extend(list.iter().filter_map(Seen::of));
            }
            Err(_) => complete = false,
        }
    }
    let api = support_api(app);
    let store = account::store();
    let mut guests = settings_of(app).guests;
    for g in guests
        .iter_mut()
        .filter(|g| g.claimed && g.status != "gone")
    {
        let Some(token) = store.get(&secret_name(&api.host(), &g.reference, "token")) else {
            continue;
        };
        match api.guest_thread(&token) {
            Ok(thread) => {
                update_guest(g, &thread);
                seen.extend(Seen::of(&thread["ticket"]));
            }
            Err(e) if token_gone(&e) => g.status = "gone".into(),
            Err(_) => complete = false,
        }
    }
    let mut fresh = Vec::new();
    let _ = update(app, |s| {
        for g in &guests {
            if let Some(kept) = s.guests.iter_mut().find(|k| k.reference == g.reference) {
                *kept = g.clone();
            }
        }
        // An incomplete look keeps what it didn't see.
        let mut notified = s.notified.clone();
        if !complete {
            for r in notified.keys() {
                if !seen.iter().any(|x| &x.reference == r) {
                    seen.push(Seen {
                        reference: r.clone(),
                        unread: 0,
                        last_message_at: 0,
                    });
                }
            }
        }
        fresh = new_replies(&seen, &mut notified);
        s.notified = notified;
        Ok(())
    });
    let unread: i64 = seen.iter().map(|s| s.unread).sum();
    *guard(&UNREAD) = unread;
    let _ = app.emit_to("main", "support-changed", json!({ "unread": unread }));
    if fresh.is_empty() {
        return;
    }
    let text = match fresh.as_slice() {
        [one] => tr!("support.notify_reply", reference = one),
        many => trn!("support.notify_replies", many.len() as i64),
    };
    crate::tray::notice(app, &text);
    let _ = app.emit_to(
        "main",
        "support-reply",
        json!({ "text": text, "reference": fresh[0] }),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::teams_api::tests::Fake;

    #[test]
    fn diagnostics_keep_only_the_allowed_fields_and_values() {
        let d = clean_diagnostics(&json!({
            "app": "Passyble desktop",
            "app_version": "1.2.3",
            "platform": "windows",
            "os_version": "Windows 11 24H2 (build 26100.2894)",
            "sync": "https://cloud.example.com/dav",
            "errors": ["sync.network", "api.too_many", "bad code!", "sync.network", "x".repeat(41)],
            "locale": "zh-CN",
            "vault": "Personal",
            "email": "alice@example.com",
        }))
        .unwrap();
        assert_eq!(
            d,
            json!({
                "app": "Passyble desktop",
                "app_version": "1.2.3",
                "platform": "windows",
                "os_version": "Windows 11 24H2 (build 26100.2894)",
                "errors": ["sync.network", "api.too_many"],
                "locale": "zh-CN",
            })
        );
        for bad in [
            "alice@example.com",
            "C:/Users/alice",
            "key=value",
            "a:b",
            "/home",
            "",
            &"x".repeat(64),
        ] {
            assert!(!value_ok(bad), "{bad}");
        }
        assert!(value_ok(&"x".repeat(63)));
        assert_eq!(clean_diagnostics(&json!({ "vault": "x" })), None);
        assert_eq!(clean_diagnostics(&json!("text")), None);
        let many: Vec<String> = (0..15).map(|i| format!("e{i}")).collect();
        let d = clean_diagnostics(&json!({ "errors": many })).unwrap();
        assert_eq!(d["errors"].as_array().unwrap().len(), ERRORS_MAX);
    }

    #[test]
    fn squeezed_text_and_noted_errors_fit_the_rules() {
        assert_eq!(
            squeeze("Debian GNU/Linux 12 (bookworm)"),
            "Debian GNU Linux 12 (bookworm)"
        );
        assert!(value_ok(&squeeze(&"Ubuntu: ".repeat(30))));
        assert!(value_ok(&os_version()), "{}", os_version());
        let mut errors = Vec::new();
        push_error(&mut errors, "a.first".into());
        push_error(&mut errors, "a.second".into());
        push_error(&mut errors, "a.first".into());
        assert_eq!(errors, ["a.first", "a.second"]);
        for i in 0..20 {
            push_error(&mut errors, format!("e{i}"));
        }
        assert_eq!(errors.len(), ERRORS_MAX);
        assert_eq!(errors[0], "e19");
        // What note_error keeps passes the filter (other tests note codes at the same time).
        note_error("test second/with=junk");
        assert!(recent_errors().iter().all(|e| error_ok(e)));
        let built = build_diagnostics(&crate::settings::Settings::default()).unwrap();
        assert_eq!(clean_diagnostics(&built), Some(built.clone()));
        assert_eq!(built["sync"], "none");
        assert_eq!(built["app_version"], env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn app_links_codes_and_references_are_read() {
        let host = "account.passyble.com";
        assert_eq!(
            parse_link("passyble://support", host),
            Some(SupportLink::Open)
        );
        assert_eq!(
            parse_link("passyble://support/", host),
            Some(SupportLink::Open)
        );
        assert_eq!(
            parse_link("passyble://support/app?r=ps-abcdef&c=WXYZ-2345", host),
            Some(SupportLink::Claim {
                reference: "PS-ABCDEF".into(),
                code: "WXYZ2345".into()
            })
        );
        assert_eq!(
            parse_link(
                " https://account.passyble.com/support/app?r=PS-ABCDEF&c=wxyz2345 ",
                host
            ),
            Some(SupportLink::Claim {
                reference: "PS-ABCDEF".into(),
                code: "WXYZ2345".into()
            })
        );
        // A bad code in an app link still opens the screen; another site never counts.
        assert_eq!(
            parse_link("passyble://support/app?r=PS-ABCDEF&c=0000", host),
            Some(SupportLink::Open)
        );
        assert_eq!(
            parse_link(
                "https://evil.example/support/app?r=PS-ABCDEF&c=WXYZ2345",
                host
            ),
            None
        );
        assert_eq!(
            parse_link(
                "https://HELP.passyble.com/support/app?r=PS-ABCDEF&c=WXYZ2345",
                host
            ),
            Some(SupportLink::Claim {
                reference: "PS-ABCDEF".into(),
                code: "WXYZ2345".into()
            })
        );
        assert_eq!(
            parse_link(
                "https://help.passyble.com.evil.example/support/app?r=PS-ABCDEF&c=WXYZ2345",
                host
            ),
            None
        );
        assert_eq!(
            parse_link("https://account.passyble.com/support/app?r=PS-ABCDEF", host),
            None
        );
        assert_eq!(parse_link("pass+server://x", host), None);
        assert_eq!(parse_link("passyble://vault", host), None);
        assert_eq!(normalize_code("abcd efgh"), Some("ABCDEFGH".into()));
        assert_eq!(
            normalize_code("ABCD-EFG0"),
            None,
            "0 is not in the alphabet"
        );
        assert_eq!(parse_reference("PS-ABC123"), None);
        assert_eq!(
            parse_code_input("WXYZ-2345", host),
            Some((None, "WXYZ2345".into()))
        );
        assert_eq!(
            parse_code_input(
                "https://account.passyble.com/support/app?r=PS-BCDEFG&c=WXYZ2345",
                host
            ),
            Some((Some("PS-BCDEFG".into()), "WXYZ2345".into()))
        );
        assert!(valid_email("alice@example.com"));
        for bad in [
            "alice",
            "alice@",
            "@example.com",
            "a b@example.com",
            "alice@example",
            "a@b@c.com",
        ] {
            assert!(!valid_email(bad), "{bad}");
        }
    }

    fn ticket() -> NewTicket {
        NewTicket {
            subject: " Sync stopped ".into(),
            body: "It says offline.".into(),
            category: "sync".into(),
            diagnostics: Some(
                json!({ "app": "Passyble desktop", "sync": "webdav", "path": "C:/x" }),
            ),
            email: Some("alice@example.com".into()),
            name: Some(" ".into()),
        }
    }

    #[test]
    fn a_new_ticket_is_checked_and_sends_only_clean_diagnostics() {
        let t = ticket();
        assert!(t.check(true).is_ok());
        let body = t.json(None);
        assert_eq!(body["subject"], "Sync stopped");
        assert_eq!(
            body["diagnostics"],
            json!({ "app": "Passyble desktop", "sync": "webdav" })
        );
        assert!(body.get("name").is_none() && body.get("email").is_none());
        let mut bad = t.clone();
        bad.email = Some("nope".into());
        assert!(bad.check(true).is_err());
        assert!(bad.check(false).is_ok(), "signed in: the account's address");
        bad.subject = "  ".into();
        assert!(bad.check(false).is_err());
        let mut none = t.clone();
        none.diagnostics = None;
        assert!(none.json(None).get("diagnostics").is_none());
    }

    #[test]
    fn the_guest_flow_keeps_the_claim_then_the_token() {
        let store = account::tests::fake_store();
        let claim = "c".repeat(43);
        let created = json!({ "reference": "PS-GUESTA", "status": "unconfirmed", "claim": claim, "confirm_by": 99 });
        let thread = r#"{ "token": "spt_secret", "ticket": { "reference": "PS-GUESTA", "subject": "Sync stopped",
            "status": "waiting_on_us", "unread": 0, "last_message_at": 7 }, "messages": [ { "id": 1, "author": "customer", "body": "x" } ] }"#;
        let fake = Fake::with(vec![
            (202, &created.to_string()),
            (200, r#"{ "reference": "PS-GUESTA", "confirmed": true }"#),
            (
                400,
                r#"{ "error": "bad_code", "message": "That code is not right." }"#,
            ),
            (200, thread),
            (204, ""),
        ]);
        let api = SupportApi::new("https://account.example.com/", &fake);
        let mut s = SupportSettings::default();
        let g = create_guest(&api, store, &mut s, &ticket(), 5).unwrap();
        assert_eq!(g.reference, "PS-GUESTA");
        assert_eq!(s.guests.len(), 1);
        let claim_name = secret_name("account.example.com", "PS-GUESTA", "claim");
        assert_eq!(
            store.get(&claim_name).as_deref().map(String::as_str),
            Some(claim.as_str())
        );
        assert!(check_guest(&api, store, "PS-GUESTA").unwrap());
        // A code of the wrong shape never reaches the service; a wrong one is the service's word.
        assert!(claim_guest(&api, store, &mut s, "PS-GUESTA", "123").is_err());
        assert_eq!(
            claim_guest(&api, store, &mut s, "PS-GUESTA", "WXYZ-2345").unwrap_err(),
            "That code is not right."
        );
        let out = claim_guest(
            &api,
            store,
            &mut s,
            "PS-GUESTA",
            "passyble://support/app?r=PS-GUESTA&c=WXYZ2345",
        )
        .unwrap();
        assert!(out.get("token").is_none(), "the token stays in Rust");
        assert_eq!(out["ticket"]["guest"], true);
        assert!(s.guests[0].claimed);
        assert_eq!(s.guests[0].status, "waiting_on_us");
        assert!(store.get(&claim_name).is_none(), "the claim is spent");
        let token_name = secret_name("account.example.com", "PS-GUESTA", "token");
        assert_eq!(
            store.get(&token_name).as_deref().map(String::as_str),
            Some("spt_secret")
        );
        // A link for a ticket this PC didn't open.
        assert_eq!(
            claim_guest(
                &api,
                store,
                &mut s,
                "PS-GUESTA",
                "passyble://support/app?r=PS-ZZZZZZ&c=WXYZ2345"
            )
            .unwrap_err(),
            tr!("support.err_link_elsewhere")
        );
        remove_guest(&api, store, &mut s, "PS-GUESTA");
        assert!(s.guests.is_empty() && store.get(&token_name).is_none());
        let seen = fake.requests();
        let urls: Vec<String> = seen
            .iter()
            .map(|r| format!("{} {}", r.method, r.url))
            .collect();
        assert_eq!(
            urls,
            [
                "POST https://account.example.com/v1/support/guest/tickets",
                "POST https://account.example.com/v1/support/guest/status",
                "POST https://account.example.com/v1/support/guest/claim",
                "POST https://account.example.com/v1/support/guest/claim",
                "DELETE https://account.example.com/v1/support/guest/token",
            ]
        );
        assert_eq!(seen[0].json()["email"], "alice@example.com");
        assert_eq!(
            seen[0].json()["diagnostics"],
            json!({ "app": "Passyble desktop", "sync": "webdav" })
        );
        assert!(seen[0].auth.is_none());
        assert_eq!(seen[3].json()["code"], "WXYZ2345");
        assert_eq!(seen[3].json()["claim"], claim);
        assert_eq!(
            seen[4].auth.as_deref().map(String::as_str),
            Some("Bearer spt_secret")
        );
    }

    fn pending(reference: &str, code: &str) -> PendingLink {
        Mutex::new(Some((reference.to_string(), Zeroizing::new(code.to_string()))))
    }

    fn link_claim(
        fake: &Fake,
        store: &dyn Store,
        s: &mut SupportSettings,
        pending: &PendingLink,
    ) -> Res<Value> {
        let api = SupportApi::new("https://account.example.com", fake);
        claim_pending(pending, &AtomicBool::new(false), |reference, code| {
            claim_guest_final(&api, store, s, reference, code)
        })
    }

    fn guest_awaiting_claim(store: &dyn Store) -> SupportSettings {
        store.set(&secret_name("account.example.com", "PS-LINKAA", "claim"), &"c".repeat(43)).unwrap();
        SupportSettings {
            guests: vec![GuestTicket { reference: "PS-LINKAA".into(), ..Default::default() }],
            ..Default::default()
        }
    }

    #[test]
    fn a_failed_link_claim_keeps_the_code_and_a_good_one_clears_it() {
        let store = account::tests::fake_store();
        let mut s = guest_awaiting_claim(store);
        let thread = r#"{ "token": "spt_secret", "ticket": { "reference": "PS-LINKAA", "subject": "x",
            "status": "waiting_on_us", "unread": 0, "last_message_at": 7 }, "messages": [] }"#;
        let fake = Fake::with(vec![
            (503, r#"{ "error": "unavailable", "message": "Try later." }"#),
            (429, r#"{ "error": "rate_limited", "message": "Slow down." }"#),
            (200, thread),
        ]);
        let link = pending("PS-LINKAA", "WXYZ2345");
        assert_eq!(link_claim(&fake, store, &mut s, &link).unwrap_err(), "Try later.");
        assert!(link.lock().unwrap().is_some(), "a server error keeps the code");
        assert!(link_claim(&fake, store, &mut s, &link).is_err());
        assert!(link.lock().unwrap().is_some(), "a rate limit keeps the code");
        let out = link_claim(&fake, store, &mut s, &link).unwrap();
        assert_eq!(out["ticket"]["guest"], true);
        assert!(link.lock().unwrap().is_none(), "a good claim spends the code");
        assert_eq!(link_claim(&fake, store, &mut s, &link).unwrap(), Value::Null);
        let seen = fake.requests();
        assert_eq!(seen.len(), 3);
        assert!(seen.iter().all(|r| r.json()["code"] == "WXYZ2345"));
    }

    #[test]
    fn a_refused_link_code_is_dropped() {
        for (status, body) in [
            (400, r#"{ "error": "bad_code", "message": "That code is not right." }"#),
            (410, r#"{ "error": "code_expired", "message": "That code expired." }"#),
        ] {
            let store = account::tests::fake_store();
            let mut s = guest_awaiting_claim(store);
            let fake = Fake::with(vec![(status, body)]);
            let link = pending("PS-LINKAA", "WXYZ2345");
            assert!(link_claim(&fake, store, &mut s, &link).is_err());
            assert!(link.lock().unwrap().is_none(), "{status} ends the code");
        }
        let store = account::tests::fake_store();
        let mut s = SupportSettings::default();
        let link = pending("PS-OTHER1", "WXYZ2345");
        assert!(link_claim(&Fake::with(vec![]), store, &mut s, &link).is_err());
        assert!(link.lock().unwrap().is_none(), "a link for another PC's ticket is dropped");
    }

    #[test]
    fn a_second_link_claim_while_one_runs_sends_nothing() {
        let link = pending("PS-LINKAA", "WXYZ2345");
        let busy = AtomicBool::new(true);
        let out = claim_pending(&link, &busy, |_, _| panic!("must not run"));
        assert_eq!(out.unwrap(), Value::Null);
        assert!(link.lock().unwrap().is_some());
    }

    #[test]
    fn too_many_guest_tickets_are_refused_before_sending() {
        let fake = Fake::with(vec![]);
        let api = SupportApi::new("https://account.example.com", &fake);
        let mut s = SupportSettings {
            guests: (0..MAX_GUESTS)
                .map(|i| GuestTicket {
                    reference: format!("PS-AAAAA{}", (b'A' + i as u8) as char),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        };
        assert!(create_guest(&api, account::tests::fake_store(), &mut s, &ticket(), 1).is_err());
        assert!(fake.requests().is_empty());
    }

    #[test]
    fn account_routes_and_guest_token_routes() {
        let fake = Fake::with(vec![(200, "{}"); 6]);
        let api = AccountApi::new("https://account.example.com", "at_1", &fake);
        mine::list(&api).unwrap();
        mine::thread(&api, "PS-ABCDEF").unwrap();
        mine::reply(&api, "PS-ABCDEF", "Thanks").unwrap();
        mine::close(&api, "PS-ABCDEF").unwrap();
        mine::read(&api, "PS-ABCDEF", Some(4)).unwrap();
        mine::create(&api, &ticket()).unwrap();
        let seen = fake.requests();
        let urls: Vec<String> = seen
            .iter()
            .map(|r| format!("{} {}", r.method, r.url))
            .collect();
        assert_eq!(
            urls,
            [
                "GET https://account.example.com/v1/support/tickets",
                "GET https://account.example.com/v1/support/tickets/PS-ABCDEF",
                "POST https://account.example.com/v1/support/tickets/PS-ABCDEF/reply",
                "POST https://account.example.com/v1/support/tickets/PS-ABCDEF/close",
                "POST https://account.example.com/v1/support/tickets/PS-ABCDEF/read",
                "POST https://account.example.com/v1/support/tickets",
            ]
        );
        assert_eq!(seen[4].json(), json!({ "up_to": 4 }));
        assert!(seen[5].json().get("email").is_none());
        let fake = Fake::with(vec![(200, "{}"); 3]);
        let guest = SupportApi::new("https://account.example.com", &fake);
        guest.guest_thread("spt_t").unwrap();
        guest.guest_reply("spt_t", "More").unwrap();
        guest.guest_read("spt_t", None).unwrap();
        let seen = fake.requests();
        assert_eq!(
            seen[0].url,
            "https://account.example.com/v1/support/guest/ticket"
        );
        assert_eq!(
            seen[1].url,
            "https://account.example.com/v1/support/guest/ticket/reply"
        );
        assert_eq!(seen[2].json(), json!({}));
        assert!(seen
            .iter()
            .all(|r| r.auth.as_deref().map(String::as_str) == Some("Bearer spt_t")));
        assert!(token_gone(&ApiError::Refused {
            status: 401,
            code: "invalid_token".into(),
            message: String::new(),
            limit: None,
        }));
        assert!(!token_gone(&ApiError::Network("offline".into())));
    }

    #[test]
    fn a_staff_reply_is_announced_once() {
        let mut notified = BTreeMap::new();
        let seen = |unread, at| {
            vec![Seen {
                reference: "PS-ABCDEF".into(),
                unread,
                last_message_at: at,
            }]
        };
        assert!(new_replies(&seen(0, 5), &mut notified).is_empty());
        assert_eq!(new_replies(&seen(1, 6), &mut notified), ["PS-ABCDEF"]);
        assert!(new_replies(&seen(1, 6), &mut notified).is_empty());
        assert_eq!(new_replies(&seen(2, 9), &mut notified), ["PS-ABCDEF"]);
        assert!(new_replies(&[], &mut notified).is_empty());
        assert!(
            notified.is_empty(),
            "tickets no longer followed are forgotten"
        );
        let thread = json!({ "messages": [ { "id": 3 }, { "id": 9 }, { "id": 4 } ] });
        assert_eq!(last_message_id(&thread), Some(9));
    }
}
