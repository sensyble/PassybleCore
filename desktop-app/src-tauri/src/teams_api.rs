//! Service APIs behind Teams and Family (docs/PROTOCOL.md §4): [`ServerApi`] for a Passyble Server
//! (HTTP Basic device credentials, certificate pins that replace CA validation when set) and
//! [`AccountApi`] for the account service (bearer access token).
//!
//! Requests go through a [`Transport`], so every request and answer is handled without a network.
//! No token, password or private key is ever logged; errors carry the service's code and message.

#[cfg(feature = "webdav")]
use std::time::Duration;

use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use zeroize::Zeroizing;

/// Answers are small JSON documents; a vault file never comes through here.
const MAX_ANSWER: u64 = 4 * 1024 * 1024;

/// One request. `auth` holds the `Authorization` header value (a secret: never logged).
#[derive(Clone)]
pub struct Request {
    pub method: &'static str,
    pub url: String,
    pub auth: Option<Zeroizing<String>>,
    pub body: Option<(&'static str, Vec<u8>)>,
    pub pins: Vec<String>,
    /// Extra headers: key-change signature (`X-Pass-Key-Nonce`, `X-Pass-Key-Sig`) and a new device's
    /// poll token (`X-Pass-Request-Token`, a secret: never logged).
    pub headers: Vec<(&'static str, Zeroizing<String>)>,
}

impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Request")
            .field("method", &self.method)
            .field("url", &self.url)
            .finish_non_exhaustive()
    }
}

impl Request {
    #[cfg(test)]
    pub fn json(&self) -> Value {
        self.body
            .as_ref()
            .and_then(|(_, b)| serde_json::from_slice(b).ok())
            .unwrap_or(Value::Null)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Answer {
    pub status: u16,
    pub error_code: Option<String>,
    pub body: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApiError {
    Network(String),
    /// The service refused: its code (`X-Pass-Error` or JSON `error`) and its message (translated
    /// by the service; may be empty).
    Refused {
        status: u16,
        code: String,
        message: String,
        /// The `limit` of a `vault_limit` refusal (how many vaults the plan hosts), when sent.
        limit: Option<u64>,
    },
    Unexpected(String),
}

impl ApiError {
    pub fn code(&self) -> &str {
        match self {
            ApiError::Refused { code, .. } => code,
            ApiError::Network(_) => "network",
            ApiError::Unexpected(_) => "internal",
        }
    }

    pub fn status(&self) -> u16 {
        match self {
            ApiError::Refused { status, .. } => *status,
            _ => 0,
        }
    }

    pub fn is_auth(&self) -> bool {
        matches!(self, ApiError::Refused { status: 401, .. })
    }

    pub fn message(&self) -> String {
        use crate::i18n::tr;
        match self {
            ApiError::Network(m) => m.clone(),
            ApiError::Unexpected(m) => m.clone(),
            ApiError::Refused { code, limit, .. } if code == "vault_limit" => match limit {
                Some(n) => tr!("errors.teams_vault_limit_n", limit = n),
                None => tr!("errors.teams_vault_limit"),
            },
            ApiError::Refused { code, message, .. } => match known_code_text(code) {
                Some(text) => text,
                None => {
                    let line: String = message
                        .lines()
                        .next()
                        .unwrap_or_default()
                        .chars()
                        .filter(|c| !c.is_control())
                        .take(300)
                        .collect();
                    if line.trim().is_empty() {
                        tr!("errors.teams_service_refused", code = code)
                    } else {
                        line.trim().to_string()
                    }
                }
            },
        }
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message())
    }
}

fn known_code_text(code: &str) -> Option<String> {
    use crate::i18n::tr;
    Some(match code {
        "read_only_member" => tr!("errors.teams_read_only_member"),
        "subscription_inactive" => tr!("errors.teams_subscription_inactive"),
        "account_suspended" => tr!("errors.teams_account_suspended"),
        "cloud_managed" => tr!("errors.teams_cloud_managed"),
        "sign_in_policy" => tr!("errors.teams_sign_in_policy"),
        "reauth_required" => tr!("errors.teams_reauth_required"),
        "fingerprint_mismatch" => tr!("errors.teams_fingerprint_mismatch"),
        "seats_needed" => tr!("errors.teams_seats_needed"),
        "transfer_required" => tr!("errors.teams_transfer_required"),
        "no_cloud_plan" => tr!("errors.teams_no_cloud_plan"),
        "not_vault_manager" | "not_allowed" | "not_admin" => tr!("errors.teams_not_allowed"),
        "outside_sharing" => tr!("errors.teams_outside_sharing"),
        "no_manager" => tr!("errors.teams_no_manager"),
        "keys_missing" | "no_keys" => tr!("errors.teams_keys_missing"),
        "invalid_token" | "sign_in_required" | "unauthorized" => {
            tr!("errors.teams_sign_in_again")
        }
        "too_many_requests" => tr!("errors.too_many_attempts"),
        _ => return None,
    })
}

pub fn parse_answer(answer: &Answer) -> Result<Value, ApiError> {
    if (200..300).contains(&answer.status) {
        if answer.body.trim().is_empty() {
            return Ok(Value::Null);
        }
        return serde_json::from_str(&answer.body)
            .map_err(|_| ApiError::Unexpected(crate::i18n::tr!("errors.teams_unexpected_answer")));
    }
    let json: Option<Value> = serde_json::from_str(&answer.body).ok();
    let field = |name: &str| {
        json.as_ref()
            .and_then(|j| j.get(name))
            .and_then(Value::as_str)
            .map(str::to_string)
    };
    let code = answer
        .error_code
        .clone()
        .filter(|c| !c.trim().is_empty())
        .or_else(|| field("error"))
        .unwrap_or_default();
    // JSON `{error, message}` (account service, cloud internal codes), else the server's
    // text/plain sentence.
    let message = field("message")
        .or_else(|| field("error_description"))
        .unwrap_or_else(|| {
            if json.is_none() {
                answer.body.clone()
            } else {
                String::new()
            }
        });
    let limit = json
        .as_ref()
        .and_then(|j| j.get("limit"))
        .and_then(Value::as_u64);
    let code = safe_code(&code);
    // For the support diagnostics: the code only, never the message.
    crate::support::note_error(&if code.is_empty() {
        format!("api.http_{}", answer.status)
    } else {
        format!("api.{code}")
    });
    Err(ApiError::Refused {
        status: answer.status,
        code,
        message,
        limit,
    })
}

/// A service error code as it may be shown or matched: lower-case letters, digits and `_` only.
fn safe_code(code: &str) -> String {
    code.trim()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
        .take(64)
        .collect::<String>()
        .to_ascii_lowercase()
}

/// One path segment, percent-encoded (ids, vault names and e-mail addresses go into paths).
pub fn segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'@' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn trim_base(base: &str) -> String {
    base.trim().trim_end_matches('/').to_string()
}

pub trait Transport: Send + Sync {
    fn send(&self, request: &Request) -> Result<Answer, ApiError>;
}

/// ureq 2 + rustls. With pins only the pinned server keys are accepted (`pass_core::spki_pin` of the
/// leaf certificate; the handshake signature is still verified against it).
#[cfg(feature = "webdav")]
pub struct UreqTransport;

#[cfg(feature = "webdav")]
mod pinned {
    use std::sync::Arc;

    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{CertificateError, DigitallySignedStruct, Error, SignatureScheme};

    #[derive(Debug)]
    pub struct PinVerifier {
        pins: Vec<String>,
        provider: Arc<CryptoProvider>,
    }

    impl ServerCertVerifier for PinVerifier {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            let pin = pass_core::spki_pin(end_entity)
                .ok_or(Error::InvalidCertificate(CertificateError::BadEncoding))?;
            if self.pins.iter().any(|p| p.trim() == pin) {
                Ok(ServerCertVerified::assertion())
            } else {
                Err(Error::InvalidCertificate(
                    CertificateError::ApplicationVerificationFailure,
                ))
            }
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            verify_tls12_signature(
                message,
                cert,
                dss,
                &self.provider.signature_verification_algorithms,
            )
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            verify_tls13_signature(
                message,
                cert,
                dss,
                &self.provider.signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.provider
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    pub fn config(pins: &[String]) -> Option<Arc<rustls::ClientConfig>> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = Arc::new(PinVerifier {
            pins: pins.to_vec(),
            provider: provider.clone(),
        });
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .ok()?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        Some(Arc::new(config))
    }
}

#[cfg(feature = "webdav")]
impl Transport for UreqTransport {
    fn send(&self, request: &Request) -> Result<Answer, ApiError> {
        use std::io::Read;
        let mut builder = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(10))
            .timeout(Duration::from_secs(30));
        let pins: Vec<String> = request
            .pins
            .iter()
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty())
            .collect();
        if !pins.is_empty() {
            let config = pinned::config(&pins)
                .ok_or_else(|| ApiError::Network(crate::i18n::tr!("errors.teams_tls_setup")))?;
            builder = builder.tls_config(config);
        }
        let agent = builder.build();
        let mut call = agent
            .request(request.method, &request.url)
            .set("Accept", "application/json")
            // The service words its errors (and support e-mails) in the app's language.
            .set("Accept-Language", crate::i18n::locale());
        if let Some(auth) = &request.auth {
            call = call.set("Authorization", auth);
        }
        for (name, value) in &request.headers {
            call = call.set(name, value);
        }
        let result = match &request.body {
            Some((content_type, body)) => call.set("Content-Type", content_type).send_bytes(body),
            None => call.call(),
        };
        let response = match result {
            Ok(r) => r,
            Err(ureq::Error::Status(_, r)) => r,
            Err(ureq::Error::Transport(t)) => {
                // The host only, never the query (the paths carry no secrets either).
                let host = request
                    .url
                    .split("://")
                    .nth(1)
                    .and_then(|r| r.split('/').next())
                    .unwrap_or_default()
                    .to_string();
                crate::applog::plog!("teams api: {} {host}: {t}", request.method);
                crate::support::note_error("api.network");
                return Err(ApiError::Network(crate::errors::network(&format!(
                    "{host}: {t}"
                ))));
            }
        };
        let status = response.status();
        let error_code = response.header("X-Pass-Error").map(str::to_string);
        let mut body = String::new();
        let _ = response
            .into_reader()
            .take(MAX_ANSWER)
            .read_to_string(&mut body);
        Ok(Answer {
            status,
            error_code,
            body,
        })
    }
}

pub fn transport() -> &'static dyn Transport {
    #[cfg(feature = "webdav")]
    {
        &UreqTransport
    }
    #[cfg(not(feature = "webdav"))]
    {
        struct NoNetwork;
        impl Transport for NoNetwork {
            fn send(&self, _: &Request) -> Result<Answer, ApiError> {
                Err(ApiError::Network(crate::i18n::tr!(
                    "errors.teams_no_network"
                )))
            }
        }
        &NoNetwork
    }
}

fn json_body(v: &Value) -> Option<(&'static str, Vec<u8>)> {
    Some(("application/json", v.to_string().into_bytes()))
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default)]
pub struct WhoamiVault {
    pub vault: String,
    pub path: String,
    pub owner: String,
    /// `owner`, `manage`, `edit`, `view`, `fill`.
    pub role: String,
    pub shared: bool,
    pub kind: Option<String>,
    pub writable: bool,
    pub manage: bool,
    pub group: Option<String>,
    pub waiting_for_confirmation: bool,
    pub to_confirm: u32,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default)]
pub struct CloudState {
    pub state: String,
    pub quota_bytes: u64,
    pub org: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(default)]
pub struct PolicyHint {
    pub org: String,
    pub policy: Value,
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(default)]
pub struct Whoami {
    pub user: String,
    pub device_id: String,
    pub vaults: Vec<WhoamiVault>,
    pub cloud: Option<CloudState>,
    pub policies: Vec<PolicyHint>,
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(default)]
pub struct ServerNotifications {
    pub now: i64,
    pub keys: Option<Value>,
    pub shared_with_you: Vec<Value>,
    pub removed: Vec<Value>,
    pub waiting_for_confirmation: Vec<Value>,
    pub confirm: Vec<Value>,
}

/// A stored key directory entry (`GET .../keys`); both services' shapes have `keys` and `fingerprint`.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct StoredKeys {
    pub keys: pass_core::PublicKeys,
    #[serde(default)]
    pub fingerprint: String,
}

#[derive(Clone)]
pub struct ServerApi<'a> {
    base: String,
    user: String,
    token: Zeroizing<String>,
    pins: Vec<String>,
    transport: &'a dyn Transport,
}

impl<'a> ServerApi<'a> {
    /// `base`: the server's base URL (`https://pass.example.com:8443`, before `/dav/`).
    pub fn new(
        base: &str,
        user: &str,
        token: &str,
        pins: &[String],
        transport: &'a dyn Transport,
    ) -> Self {
        Self {
            base: trim_base(base),
            user: user.to_string(),
            token: Zeroizing::new(token.to_string()),
            pins: pins.to_vec(),
            transport,
        }
    }

    fn request(&self, method: &'static str, path: &str, body: Option<Value>) -> Request {
        let basic = base64::engine::general_purpose::STANDARD.encode(format!(
            "{}:{}",
            self.user,
            self.token.as_str()
        ));
        Request {
            method,
            url: format!("{}{path}", self.base),
            auth: Some(Zeroizing::new(format!("Basic {basic}"))),
            body: body.as_ref().and_then(json_body),
            pins: self.pins.clone(),
            headers: Vec::new(),
        }
    }

    fn call(
        &self,
        method: &'static str,
        path: &str,
        body: Option<Value>,
    ) -> Result<Value, ApiError> {
        parse_answer(&self.transport.send(&self.request(method, path, body))?)
    }

    fn vault_path(owner_vault: &str) -> String {
        let (owner, vault) = owner_vault.split_once('/').unwrap_or((owner_vault, ""));
        format!("/api/v1/vaults/{}/{}", segment(owner), segment(vault))
    }

    pub fn whoami(&self) -> Result<Whoami, ApiError> {
        typed(self.call("GET", "/api/v1/whoami", None)?)
    }

    /// `GET /api/v1/info` `features` (`create_vault`, `max_owned_vaults`, ...).
    pub fn features(&self) -> Result<Value, ApiError> {
        Ok(self
            .call("GET", "/api/v1/info", None)?
            .get("features")
            .cloned()
            .unwrap_or(Value::Null))
    }

    /// A new vault owned by this account, `<user>/<name>`: `kind` `department` or
    /// `direct`, `members` `[{ user, role }]` (each waits for key confirmation).
    pub fn create_vault(
        &self,
        name: &str,
        kind: &str,
        members: &[Value],
    ) -> Result<Value, ApiError> {
        self.call(
            "POST",
            "/api/v1/vaults",
            Some(json!({ "name": name, "kind": kind, "members": members })),
        )
    }

    /// Passyble Cloud: another vault of this account's own, `<user>/<name>` (`403 vault_limit` once the
    /// plan's vaults are used up).
    pub fn create_personal_vault(&self, name: &str) -> Result<Value, ApiError> {
        self.call("POST", "/api/v1/vaults", Some(json!({ "name": name })))
    }

    pub fn delete_vault(&self, owner_vault: &str) -> Result<Value, ApiError> {
        self.call("DELETE", &Self::vault_path(owner_vault), None)
    }

    pub fn notifications(&self, since: i64) -> Result<ServerNotifications, ApiError> {
        typed(self.call(
            "GET",
            &format!("/api/v1/notifications?since={}", since.max(0)),
            None,
        )?)
    }

    pub fn user_keys(&self, user: &str) -> Result<StoredKeys, ApiError> {
        typed(self.call(
            "GET",
            &format!("/api/v1/users/{}/keys", segment(user)),
            None,
        )?)
    }

    /// Publishes this account's keys (`account` must be the server user name).
    pub fn put_keys(&self, keys: &pass_core::PublicKeys) -> Result<Value, ApiError> {
        self.call(
            "PUT",
            &format!("/api/v1/users/{}/keys", segment(&self.user)),
            Some(serde_json::to_value(keys).unwrap_or_default()),
        )
    }

    pub fn confirmations(&self, owner_vault: &str) -> Result<Value, ApiError> {
        self.call(
            "GET",
            &format!("{}/confirmations", Self::vault_path(owner_vault)),
            None,
        )
    }

    pub fn remove_member(&self, owner_vault: &str, user: &str) -> Result<Value, ApiError> {
        self.call(
            "DELETE",
            &format!(
                "{}/members/{}",
                Self::vault_path(owner_vault),
                segment(user)
            ),
            None,
        )
    }
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(default)]
pub struct OrgSummary {
    pub id: String,
    pub kind: String,
    pub name: String,
    pub role: String,
    /// The caller's view: `password_mode` is their own (an override, else the team's).
    pub policy: Value,
    pub sign_in_ok: bool,
    pub keys: String,
    /// A Team that refuses this account's shares (second_password mode, or one of its app sessions
    /// reported a second password).
    pub sharing_blocked: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(default)]
pub struct Orgs {
    pub organisations: Vec<OrgSummary>,
    pub sharing_keys: Option<Value>,
}

/// `POST /v1/cloud/devices` (the token is a secret: kept in Credential Manager only).
#[derive(Clone, Default, Deserialize)]
#[serde(default)]
pub struct CloudDevice {
    pub server_url: String,
    pub user: String,
    pub token: String,
    pub device_id: String,
    pub vault_path: Option<String>,
    pub shared: Vec<CloudShared>,
}

impl std::fmt::Debug for CloudDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudDevice")
            .field("server_url", &self.server_url)
            .field("user", &self.user)
            .field("shared", &self.shared)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default)]
pub struct CloudShared {
    pub org: Option<String>,
    pub id: String,
    pub vault_id: String,
    pub label: String,
    pub kind: Option<String>,
    pub role: Option<String>,
    pub owner: Option<String>,
    pub vault_path: Option<String>,
    /// Left out of the access lists until this device meets the organisation's sign-in rules
    /// (`hold_reason` `sign_in_policy` or `sso_required`).
    pub held: bool,
    pub hold_reason: Option<String>,
}

#[derive(Clone)]
pub struct AccountApi<'a> {
    base: String,
    token: Zeroizing<String>,
    transport: &'a dyn Transport,
}

impl<'a> AccountApi<'a> {
    pub fn new(base: &str, token: &str, transport: &'a dyn Transport) -> Self {
        Self {
            base: trim_base(base),
            token: Zeroizing::new(token.to_string()),
            transport,
        }
    }

    fn request(&self, method: &'static str, path: &str, body: Option<Value>) -> Request {
        Request {
            method,
            url: format!("{}/v1{path}", self.base),
            auth: Some(Zeroizing::new(format!("Bearer {}", self.token.as_str()))),
            body: body.as_ref().and_then(json_body),
            pins: Vec::new(),
            headers: Vec::new(),
        }
    }

    /// A JSON request whose body goes exactly as given (`body` bytes), with extra headers: the
    /// key changes signed with the account key sign these very bytes (account_keys.rs).
    pub fn call_bytes(
        &self,
        method: &'static str,
        path: &str,
        body: Option<Vec<u8>>,
        headers: Vec<(&'static str, Zeroizing<String>)>,
    ) -> Result<Value, ApiError> {
        let mut request = self.request(method, path, None);
        request.body = body.map(|b| ("application/json", b));
        request.headers = headers;
        parse_answer(&self.transport.send(&request)?)
    }

    /// A `GET` whose answer is text, not JSON (the Pwned Passwords range, `GET /v1/pwned/<prefix>`).
    pub fn get_text(&self, path: &str) -> Result<String, ApiError> {
        let answer = self.transport.send(&self.request("GET", path, None))?;
        if (200..300).contains(&answer.status) {
            Ok(answer.body)
        } else {
            parse_answer(&answer).map(|_| String::new())
        }
    }

    pub fn call(
        &self,
        method: &'static str,
        path: &str,
        body: Option<Value>,
    ) -> Result<Value, ApiError> {
        parse_answer(&self.transport.send(&self.request(method, path, body))?)
    }

    fn org(g: &str) -> String {
        format!("/orgs/{}", segment(g))
    }

    pub fn orgs(&self) -> Result<Orgs, ApiError> {
        typed(self.call("GET", "/orgs", None)?)
    }

    pub fn put_keys(&self, keys: &pass_core::PublicKeys) -> Result<Value, ApiError> {
        self.call(
            "PUT",
            "/keys",
            Some(serde_json::to_value(keys).unwrap_or_default()),
        )
    }

    pub fn overview(&self, g: &str) -> Result<Value, ApiError> {
        self.call("GET", &Self::org(g), None)
    }

    pub fn members(&self, g: &str) -> Result<Value, ApiError> {
        self.call("GET", &format!("{}/members", Self::org(g)), None)
    }

    pub fn keys_of(&self, g: &str, account: &str) -> Result<StoredKeys, ApiError> {
        typed(self.call(
            "GET",
            &format!("{}/keys/{}", Self::org(g), segment(account)),
            None,
        )?)
    }

    pub fn confirm(&self, g: &str, account: &str, fingerprint: &str) -> Result<Value, ApiError> {
        self.call(
            "POST",
            &format!("{}/confirmations", Self::org(g)),
            Some(json!({ "account_id": account, "fingerprint": fingerprint })),
        )
    }

    pub fn departments(&self, g: &str) -> Result<Value, ApiError> {
        self.call("GET", &format!("{}/departments", Self::org(g)), None)
    }

    pub fn create_department(&self, g: &str, name: &str) -> Result<Value, ApiError> {
        self.call(
            "POST",
            &format!("{}/departments", Self::org(g)),
            Some(json!({ "name": name })),
        )
    }

    pub fn rename_department(&self, g: &str, d: &str, name: &str) -> Result<Value, ApiError> {
        self.call(
            "PATCH",
            &format!("{}/departments/{}", Self::org(g), segment(d)),
            Some(json!({ "name": name })),
        )
    }

    pub fn delete_department(&self, g: &str, d: &str) -> Result<Value, ApiError> {
        self.call(
            "DELETE",
            &format!("{}/departments/{}", Self::org(g), segment(d)),
            None,
        )
    }

    pub fn department_member(
        &self,
        g: &str,
        d: &str,
        account: &str,
        add: bool,
    ) -> Result<Value, ApiError> {
        if add {
            self.call(
                "POST",
                &format!("{}/departments/{}/members", Self::org(g), segment(d)),
                Some(json!({ "account_id": account })),
            )
        } else {
            self.call(
                "DELETE",
                &format!(
                    "{}/departments/{}/members/{}",
                    Self::org(g),
                    segment(d),
                    segment(account)
                ),
                None,
            )
        }
    }

    pub fn vaults(&self, g: &str) -> Result<Value, ApiError> {
        self.call("GET", &format!("{}/vaults", Self::org(g)), None)
    }

    pub fn register_vault(
        &self,
        g: &str,
        vault_id: &str,
        label: &str,
        kind: &str,
        access: &[Value],
    ) -> Result<Value, ApiError> {
        self.call(
            "POST",
            &format!("{}/vaults", Self::org(g)),
            Some(json!({ "vault_id": vault_id, "label": label, "kind": kind, "access": access })),
        )
    }

    pub fn rename_vault(&self, g: &str, v: &str, label: &str) -> Result<Value, ApiError> {
        self.call(
            "PATCH",
            &format!("{}/vaults/{}", Self::org(g), segment(v)),
            Some(json!({ "label": label })),
        )
    }

    pub fn delete_vault(&self, g: &str, v: &str) -> Result<Value, ApiError> {
        self.call(
            "DELETE",
            &format!("{}/vaults/{}", Self::org(g), segment(v)),
            None,
        )
    }

    pub fn set_access(&self, g: &str, v: &str, access: &[Value]) -> Result<Value, ApiError> {
        self.call(
            "PUT",
            &format!("{}/vaults/{}/access", Self::org(g), segment(v)),
            Some(json!({ "access": access })),
        )
    }

    pub fn rotated(&self, g: &str, v: &str) -> Result<Value, ApiError> {
        self.call(
            "POST",
            &format!("{}/vaults/{}/rotated", Self::org(g), segment(v)),
            None,
        )
    }

    pub fn policies(&self, g: &str) -> Result<Value, ApiError> {
        self.call("GET", &format!("{}/policies", Self::org(g)), None)
    }

    pub fn set_policies(&self, g: &str, change: &Value) -> Result<Value, ApiError> {
        self.call(
            "PUT",
            &format!("{}/policies", Self::org(g)),
            Some(change.clone()),
        )
    }

    /// A member's own password mode in a Team (`mode`: `choice`, `second_password`,
    /// `one_password`; `None` follows the team's): `{ mode, effective }`.
    pub fn set_member_password_mode(
        &self,
        g: &str,
        member: &str,
        mode: Option<&str>,
    ) -> Result<Value, ApiError> {
        self.call(
            "PUT",
            &format!("{}/members/{}/password-mode", Self::org(g), segment(member)),
            Some(json!({ "mode": mode })),
        )
    }

    pub fn report_second_password(&self, second_password: bool) -> Result<Value, ApiError> {
        self.call(
            "PUT",
            "/me/second-password",
            Some(json!({ "second_password": second_password })),
        )
    }

    pub fn activity(&self, g: &str, limit: u32, before: Option<i64>) -> Result<Value, ApiError> {
        let mut path = format!("{}/activity?limit={}", Self::org(g), limit.clamp(1, 1000));
        if let Some(before) = before {
            path.push_str(&format!("&before={before}"));
        }
        self.call("GET", &path, None)
    }

    pub fn bulk_invite(&self, g: &str, csv: &str, dry_run: bool) -> Result<Value, ApiError> {
        self.call(
            "POST",
            &format!("{}/invites/bulk", Self::org(g)),
            Some(json!({ "csv": csv, "dry_run": dry_run })),
        )
    }

    /// One invitation (owners and admins): `POST /orgs/<g>/invites { email }`. A Team's role other
    /// than member, or departments, go through the bulk route with one line (the service's only
    /// way to set them on an invitation).
    pub fn invite(
        &self,
        g: &str,
        email: &str,
        role: &str,
        departments: &[String],
        team: bool,
    ) -> Result<Value, ApiError> {
        if team && (role != "member" || !departments.is_empty()) {
            return self.bulk_invite(g, &invite_csv_line(email, role, departments), false);
        }
        self.call(
            "POST",
            &format!("{}/invites", Self::org(g)),
            Some(json!({ "email": email })),
        )
    }

    pub fn resend_invite(&self, g: &str, member: &str) -> Result<Value, ApiError> {
        self.call(
            "POST",
            &format!("{}/invites/{}/resend", Self::org(g), segment(member)),
            None,
        )
    }

    pub fn cancel_invite(&self, g: &str, member: &str) -> Result<Value, ApiError> {
        self.call(
            "DELETE",
            &format!("{}/invites/{}", Self::org(g), segment(member)),
            None,
        )
    }

    pub fn set_role(&self, g: &str, member: &str, role: &str) -> Result<Value, ApiError> {
        self.call(
            "PATCH",
            &format!("{}/members/{}", Self::org(g), segment(member)),
            Some(json!({ "role": role })),
        )
    }

    pub fn leave_org(&self, g: &str) -> Result<Value, ApiError> {
        self.call("POST", &format!("{}/leave", Self::org(g)), None)
    }

    /// The caller leaves one shared vault given to them directly (`409 bad_state` through a
    /// department or everyone, `400 no_manager` for the last manager).
    pub fn leave_vault(&self, g: &str, v: &str) -> Result<Value, ApiError> {
        self.call(
            "POST",
            &format!("{}/vaults/{}/leave", Self::org(g), segment(v)),
            None,
        )
    }

    pub fn transfer_owner(&self, g: &str, account: &str) -> Result<Value, ApiError> {
        self.call(
            "POST",
            &format!("{}/owner", Self::org(g)),
            Some(json!({ "account_id": account })),
        )
    }

    pub fn my_invites(&self) -> Result<Value, ApiError> {
        self.call("GET", "/invites", None)
    }

    pub fn answer_invite(&self, invite: &str, accept: bool) -> Result<Value, ApiError> {
        self.call(
            "POST",
            &format!(
                "/invites/{}/{}",
                segment(invite),
                if accept { "accept" } else { "decline" }
            ),
            None,
        )
    }

    pub fn offboard(
        &self,
        g: &str,
        member: &str,
        transfer_to: Option<&str>,
    ) -> Result<Value, ApiError> {
        let mut body = json!({});
        if let Some(t) = transfer_to.filter(|t| !t.trim().is_empty()) {
            body["transfer_to"] = json!(t);
        }
        self.call(
            "POST",
            &format!("{}/members/{}/offboard", Self::org(g), segment(member)),
            Some(body),
        )
    }

    /// `POST /cloud/devices`: this app session's Passyble Cloud device, with a device approval that is still waiting as
    /// `Err(Ok(approval))` (the waiting card shows it), any other refusal as `Err(Err(_))`.
    pub fn cloud_device_or_approval(
        &self,
        device_name: &str,
    ) -> Result<CloudDevice, Result<Value, ApiError>> {
        let answer = self
            .transport
            .send(&self.request(
                "POST",
                "/cloud/devices",
                Some(json!({ "device_name": device_name })),
            ))
            .map_err(Err)?;
        match parse_answer(&answer) {
            Ok(v) => typed(v).map_err(Err),
            Err(e) if e.code() == "device_approval_required" => {
                let body: Value = serde_json::from_str(&answer.body).unwrap_or(Value::Null);
                Err(Ok(body.get("approval").cloned().unwrap_or(Value::Null)))
            }
            Err(e) => Err(Err(e)),
        }
    }

    pub fn device_approvals(&self) -> Result<Value, ApiError> {
        self.call("GET", "/device-approvals", None)
    }

    pub fn device_approve(&self, id: &str) -> Result<Value, ApiError> {
        self.call(
            "POST",
            &format!("/device-approvals/{}/approve", segment(id)),
            None,
        )
    }

    pub fn device_deny(&self, id: &str) -> Result<Value, ApiError> {
        self.call(
            "POST",
            &format!("/device-approvals/{}/deny", segment(id)),
            None,
        )
    }

    pub fn device_approval_email(&self) -> Result<Value, ApiError> {
        self.call("POST", "/device-approvals/email", None)
    }

    /// `POST /sends { meta, ciphertext (base64), password_auth? }` → `{ id, link_base, expires_at,
    /// max_views }`. `meta` is the core's metadata exactly as it made it (a JSON string).
    pub fn send_create(&self, sealed: &pass_core::SealedSend) -> Result<Value, ApiError> {
        let mut body = json!({
            "meta": sealed.meta,
            "ciphertext": base64::engine::general_purpose::STANDARD.encode(&sealed.ciphertext),
        });
        if let Some(auth) = &sealed.password_auth {
            body["password_auth"] = json!(auth);
        }
        self.call("POST", "/sends", Some(body))
    }

    pub fn send_list(&self) -> Result<Value, ApiError> {
        self.call("GET", "/sends", None)
    }

    pub fn send_revoke(&self, id: &str) -> Result<Value, ApiError> {
        self.call("DELETE", &format!("/sends/{}", segment(id)), None)
    }

    pub fn emergency(&self) -> Result<Value, ApiError> {
        self.call("GET", "/emergency", None)
    }

    pub fn emergency_invite(
        &self,
        email: &str,
        access: &str,
        wait_hours: u32,
    ) -> Result<Value, ApiError> {
        self.call(
            "POST",
            "/emergency/contacts",
            Some(json!({ "email": email, "access": access, "wait_hours": wait_hours })),
        )
    }

    pub fn emergency_accept(&self, token: &str) -> Result<Value, ApiError> {
        self.call("POST", "/emergency/accept", Some(json!({ "token": token })))
    }

    pub fn emergency_keys(&self, id: &str) -> Result<StoredKeys, ApiError> {
        typed(self.call("GET", &format!("/emergency/{}/keys", segment(id)), None)?)
    }

    /// Adds or renews one vault's grant (core's grant plus release secret, kept apart by the service) and
    /// keeps the record's others. `cloud_vault`: the Passyble Cloud name, `None` for a vault kept elsewhere.
    pub fn emergency_grant(
        &self,
        id: &str,
        created: &pass_core::EmergencyGrantCreated,
        cloud_vault: Option<&str>,
    ) -> Result<Value, ApiError> {
        self.call(
            "PUT",
            &format!("/emergency/{}/grant", segment(id)),
            Some(json!({
                "grant": serde_json::to_value(&created.grant).unwrap_or_default(),
                "release_secret": created.release_secret,
                "vault_id": created.grant.vault_id,
                "cloud_vault": cloud_vault,
            })),
        )
    }

    pub fn emergency_grant_remove(&self, id: &str, vault_id: &str) -> Result<Value, ApiError> {
        self.call(
            "DELETE",
            &format!("/emergency/{}/grants/{}", segment(id), segment(vault_id)),
            None,
        )
    }

    pub fn emergency_vault_of(&self, id: &str, vault_id: &str) -> Result<Vec<u8>, ApiError> {
        self.download(&format!(
            "/emergency/{}/vault?vault_id={}",
            segment(id),
            segment(vault_id)
        ))
    }

    pub fn emergency_remove(&self, id: &str) -> Result<Value, ApiError> {
        self.call("DELETE", &format!("/emergency/{}", segment(id)), None)
    }

    pub fn emergency_request(&self, id: &str) -> Result<Value, ApiError> {
        self.call("POST", &format!("/emergency/{}/request", segment(id)), None)
    }

    pub fn emergency_answer(&self, id: &str, approve: bool) -> Result<Value, ApiError> {
        self.call(
            "POST",
            &format!(
                "/emergency/{}/{}",
                segment(id),
                if approve { "approve" } else { "refuse" }
            ),
            None,
        )
    }

    pub fn emergency_release(&self, id: &str) -> Result<Value, ApiError> {
        self.call("GET", &format!("/emergency/{}/release", segment(id)), None)
    }

    pub fn emergency_vault(&self, id: &str) -> Result<Vec<u8>, ApiError> {
        self.download(&format!("/emergency/{}/vault", segment(id)))
    }

    /// A binary answer of the service (at most 64 MiB), with the bearer token.
    #[cfg(feature = "webdav")]
    fn download(&self, path: &str) -> Result<Vec<u8>, ApiError> {
        use std::io::Read;
        let url = format!("{}/v1{path}", self.base);
        let response = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(10))
            .timeout(Duration::from_secs(120))
            .build()
            .get(&url)
            .set("Authorization", &format!("Bearer {}", self.token.as_str()))
            .call();
        match response {
            Ok(r) => {
                let mut bytes = Vec::new();
                r.into_reader()
                    .take(64 * 1024 * 1024)
                    .read_to_end(&mut bytes)
                    .map_err(|e| ApiError::Network(crate::errors::network(&e.to_string())))?;
                Ok(bytes)
            }
            Err(ureq::Error::Status(status, r)) => {
                let code = r.header("X-Pass-Error").unwrap_or_default().to_string();
                Err(ApiError::Refused {
                    status,
                    code,
                    message: String::new(),
                    limit: None,
                })
            }
            Err(ureq::Error::Transport(t)) => {
                Err(ApiError::Network(crate::errors::network(&t.to_string())))
            }
        }
    }

    #[cfg(not(feature = "webdav"))]
    fn download(&self, _path: &str) -> Result<Vec<u8>, ApiError> {
        Err(ApiError::Network(crate::i18n::tr!(
            "errors.teams_no_network"
        )))
    }

    pub fn recovery(&self, g: &str) -> Result<Value, ApiError> {
        self.call("GET", &format!("{}/recovery", Self::org(g)), None)
    }

    pub fn recovery_enroll(
        &self,
        g: &str,
        enrollment: &pass_core::RecoveryEnrollment,
    ) -> Result<Value, ApiError> {
        self.call(
            "PUT",
            &format!("{}/recovery/enrollment", Self::org(g)),
            Some(json!({ "enrollment": serde_json::to_value(enrollment).unwrap_or_default() })),
        )
    }

    pub fn recovery_withdraw(&self, g: &str) -> Result<Value, ApiError> {
        self.call(
            "DELETE",
            &format!("{}/recovery/enrollment", Self::org(g)),
            None,
        )
    }

    /// `DELETE .../recovery/enrollment?vault_id=`: one enrolment (a locked one), or without
    /// `vault_id` all of the member's.
    pub fn recovery_withdraw_one(&self, g: &str, vault_id: Option<&str>) -> Result<Value, ApiError> {
        let query = vault_id
            .map(|v| format!("?vault_id={}", segment(v)))
            .unwrap_or_default();
        self.call(
            "DELETE",
            &format!("{}/recovery/enrollment{query}", Self::org(g)),
            None,
        )
    }

    pub fn recovery_request(
        &self,
        g: &str,
        request: &pass_core::RecoveryRequestPublic,
    ) -> Result<Value, ApiError> {
        self.call(
            "POST",
            &format!("{}/recovery/requests", Self::org(g)),
            Some(json!({ "request": serde_json::to_value(request).unwrap_or_default() })),
        )
    }

    pub fn recovery_request_status(&self, g: &str, id: &str) -> Result<Value, ApiError> {
        self.call(
            "GET",
            &format!("{}/recovery/requests/{}", Self::org(g), segment(id)),
            None,
        )
    }

    pub fn recovery_approve(
        &self,
        g: &str,
        id: &str,
        approval: &pass_core::RecoveryApproval,
    ) -> Result<Value, ApiError> {
        self.call(
            "POST",
            &format!("{}/recovery/requests/{}/approve", Self::org(g), segment(id)),
            Some(json!({ "approval": serde_json::to_value(approval).unwrap_or_default() })),
        )
    }

    pub fn recovery_deny(&self, g: &str, id: &str) -> Result<Value, ApiError> {
        self.call(
            "POST",
            &format!("{}/recovery/requests/{}/deny", Self::org(g), segment(id)),
            None,
        )
    }

    pub fn recovery_complete(&self, g: &str, id: &str) -> Result<Value, ApiError> {
        self.call(
            "POST",
            &format!(
                "{}/recovery/requests/{}/complete",
                Self::org(g),
                segment(id)
            ),
            None,
        )
    }
}

/// One line of the bulk invitation CSV (`email,role,departments` with `;` between departments).
/// Commas, semicolons, quotes and line breaks are dropped from the parts so one invitation can't
/// become several.
pub fn invite_csv_line(email: &str, role: &str, departments: &[String]) -> String {
    let clean = |s: &str| {
        s.chars()
            .filter(|c| !matches!(c, ',' | ';' | '|' | '"' | '\r' | '\n'))
            .collect::<String>()
            .trim()
            .to_string()
    };
    let deps: Vec<String> = departments
        .iter()
        .map(|d| clean(d))
        .filter(|d| !d.is_empty())
        .collect();
    format!("{},{},{}", clean(email), clean(role), deps.join(";"))
}

fn typed<T: serde::de::DeserializeOwned>(value: Value) -> Result<T, ApiError> {
    serde_json::from_value(value)
        .map_err(|_| ApiError::Unexpected(crate::i18n::tr!("errors.teams_unexpected_answer")))
}

/// `settings.json` `account_url` overrides it.
pub const DEFAULT_ACCOUNT_URL: &str = "https://account.passyble.com";

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Answers each request with the next fixed answer and keeps the requests.
    #[derive(Default)]
    pub(crate) struct Fake {
        pub answers: Mutex<Vec<Answer>>,
        pub seen: Mutex<Vec<Request>>,
    }

    impl Fake {
        pub(crate) fn with(answers: Vec<(u16, &str)>) -> Self {
            Self {
                answers: Mutex::new(
                    answers
                        .into_iter()
                        .rev()
                        .map(|(status, body)| Answer {
                            status,
                            error_code: None,
                            body: body.to_string(),
                        })
                        .collect(),
                ),
                seen: Mutex::new(Vec::new()),
            }
        }

        pub(crate) fn requests(&self) -> Vec<Request> {
            self.seen.lock().unwrap().clone()
        }
    }

    impl Transport for Fake {
        fn send(&self, request: &Request) -> Result<Answer, ApiError> {
            self.seen.lock().unwrap().push(request.clone());
            self.answers
                .lock()
                .unwrap()
                .pop()
                .ok_or_else(|| ApiError::Network("offline".into()))
        }
    }

    const WHOAMI: &str = r#"{ "user": "bob", "device_id": "d_1", "vaults": [
        { "vault": "bob/personal", "path": "/dav/bob/personal.vault", "owner": "bob",
          "role": "owner", "shared": false, "kind": null, "writable": true, "manage": true },
        { "vault": "o-acme/eng", "path": "/dav/o-acme/eng.vault", "owner": "o-acme",
          "role": "view", "shared": true, "kind": "department", "writable": false, "manage": false,
          "group": "eng", "waiting_for_confirmation": true, "to_confirm": 0, "later_field": 1 } ],
      "vault_path": "/dav/bob/personal.vault", "vault_exists": true,
      "cloud": { "state": "active", "quota_bytes": 1073741824, "org": "o-acme" },
      "policies": [ { "org": "o-acme", "policy": { "min_password_score": 3 } } ] }"#;

    #[test]
    fn whoami_is_read_with_basic_auth_and_pins() {
        let fake = Fake::with(vec![(200, WHOAMI)]);
        let pins = vec!["sha256:abc".to_string()];
        let api = ServerApi::new("https://pass.example.com:8443/", "bob", "tok", &pins, &fake);
        let who = api.whoami().unwrap();
        assert_eq!(who.user, "bob");
        assert_eq!(who.vaults.len(), 2);
        let eng = &who.vaults[1];
        assert!(eng.shared && !eng.writable && eng.waiting_for_confirmation);
        assert_eq!(eng.kind.as_deref(), Some("department"));
        assert_eq!(who.cloud.as_ref().unwrap().org.as_deref(), Some("o-acme"));
        assert_eq!(who.policies[0].policy["min_password_score"], 3);
        let req = &fake.requests()[0];
        assert_eq!(req.method, "GET");
        assert_eq!(req.url, "https://pass.example.com:8443/api/v1/whoami");
        assert_eq!(req.pins, pins);
        // base64("bob:tok")
        assert_eq!(
            req.auth.as_deref().map(String::as_str),
            Some("Basic Ym9iOnRvaw==")
        );
    }

    #[test]
    fn server_requests_are_built_with_encoded_paths() {
        let fake = Fake::with(vec![(204, ""), (200, "{}")]);
        let api = ServerApi::new("https://h", "alice", "t", &[], &fake);
        api.remove_member("alice/family vault", "bob").unwrap();
        api.notifications(-5).unwrap();
        let r = fake.requests();
        assert_eq!(r[0].method, "DELETE");
        assert_eq!(
            r[0].url,
            "https://h/api/v1/vaults/alice/family%20vault/members/bob"
        );
        assert_eq!(r[1].url, "https://h/api/v1/notifications?since=0");
    }

    #[test]
    fn errors_carry_the_code_from_the_header_or_the_body() {
        let text = Answer {
            status: 403,
            error_code: Some("read_only_member".into()),
            body: "Dieses Mitglied darf nicht hochladen".into(),
        };
        let e = parse_answer(&text).unwrap_err();
        assert_eq!(e.code(), "read_only_member");
        assert_eq!(e.status(), 403);
        assert_eq!(
            e.message(),
            crate::i18n::tr!("errors.teams_read_only_member")
        );
        let json = Answer {
            status: 409,
            error_code: None,
            body: r#"{"error":"vault_exists","message":"That vault is already registered."}"#
                .into(),
        };
        let e = parse_answer(&json).unwrap_err();
        assert_eq!(e.code(), "vault_exists");
        assert_eq!(e.message(), "That vault is already registered.");
        let auth = Answer {
            status: 401,
            error_code: Some("invalid_token".into()),
            body: String::new(),
        };
        assert!(parse_answer(&auth).unwrap_err().is_auth());
        assert_eq!(
            parse_answer(&Answer {
                status: 204,
                ..Answer::default()
            }),
            Ok(Value::Null)
        );
        // A strange code can't inject anything into a text.
        let odd = Answer {
            status: 400,
            error_code: Some("Bad<Code> \n".into()),
            body: String::new(),
        };
        assert_eq!(parse_answer(&odd).unwrap_err().code(), "badcode");
        // The plan's vault limit: its number when the service sends it, plain words without.
        let with = Answer {
            status: 403,
            error_code: Some("vault_limit".into()),
            body: r#"{"error":"vault_limit","message":"x","limit":10,"scope":"shared"}"#.into(),
        };
        let e = parse_answer(&with).unwrap_err();
        assert_eq!(e.code(), "vault_limit");
        assert!(e.message().contains("up to 10 shared vaults"), "{}", e.message());
        let without = Answer {
            status: 403,
            error_code: Some("vault_limit".into()),
            body: "Too many vaults".into(),
        };
        let m = parse_answer(&without).unwrap_err().message();
        assert!(m.contains("hosts no more vaults"), "{m}");
        assert!(!m.contains("Too many"), "{m}");
    }

    #[test]
    fn account_requests_use_the_bearer_token() {
        let orgs = r#"{ "organisations": [ { "id": "g1", "kind": "team", "name": "Acme",
            "role": "admin", "policy": { "min_password_score": 2, "share_outside": false },
            "sign_in_ok": true, "keys": "confirmed" } ], "sharing_keys": null }"#;
        let fake = Fake::with(vec![
            (200, orgs),
            (204, ""),
            (200, r#"{"fingerprint":"F","replaced":false}"#),
        ]);
        let api = AccountApi::new("https://account.example.com/", "pat_x", &fake);
        let o = api.orgs().unwrap();
        assert_eq!(o.organisations[0].kind, "team");
        assert_eq!(o.organisations[0].policy["share_outside"], false);
        api.confirm("g1", "acc_2", "FP").unwrap();
        let keys = pass_core::PublicKeys {
            account: "acc_1".into(),
            enc_pub: "e".into(),
            sig_pub: "s".into(),
            created_at: 5,
            sig: "g".into(),
        };
        api.put_keys(&keys).unwrap();
        let r = fake.requests();
        assert_eq!(r[0].url, "https://account.example.com/v1/orgs");
        assert_eq!(
            r[0].auth.as_deref().map(String::as_str),
            Some("Bearer pat_x")
        );
        assert_eq!(
            r[1].url,
            "https://account.example.com/v1/orgs/g1/confirmations"
        );
        assert_eq!(
            r[1].json(),
            json!({ "account_id": "acc_2", "fingerprint": "FP" })
        );
        assert_eq!(r[2].method, "PUT");
        assert_eq!(r[2].json()["account"], "acc_1");
        assert_eq!(r[2].json()["created_at"], 5);
    }

    #[test]
    fn a_team_invitation_with_a_role_or_departments_goes_through_the_bulk_route() {
        let fake = Fake::with(vec![(200, r#"{"preview":{},"invited":1}"#)]);
        let api = AccountApi::new("https://a", "t", &fake);
        let answer = api
            .invite(
                "g1",
                "dana@example.com",
                "member",
                &["Sales, EU".into()],
                true,
            )
            .unwrap();
        assert_eq!(answer["invited"], 1);
        let r = fake.requests();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].url, "https://a/v1/orgs/g1/invites/bulk");
        assert_eq!(
            r[0].json(),
            json!({ "csv": "dana@example.com,member,Sales EU", "dry_run": false })
        );
        // A plain member (and any Family invitation): `POST .../invites { email }`.
        let fake = Fake::with(vec![(201, r#"{"member_id":"m1"}"#)]);
        let api = AccountApi::new("https://a", "t", &fake);
        api.invite("g2", "x@example.com", "member", &[], false)
            .unwrap();
        let r = fake.requests();
        assert_eq!(r[0].url, "https://a/v1/orgs/g2/invites");
        assert_eq!(r[0].json(), json!({ "email": "x@example.com" }));
    }

    #[test]
    fn a_csv_line_cannot_smuggle_more_rows() {
        assert_eq!(
            invite_csv_line("a@b.c\n,evil@x.y", "admin", &["Eng".into(), "Ops|x".into()]),
            "a@b.cevil@x.y,admin,Eng;Opsx"
        );
    }

    #[test]
    fn cloud_device_keeps_its_token_out_of_debug_output() {
        let fake = Fake::with(vec![(
            200,
            r#"{ "server_url": "https://cloud.passyble.com", "user": "u-abc", "token": "pst_secret",
                 "device_id": "d_9", "vault_path": "/dav/u-abc/personal.vault",
                 "shared": [ { "org": "g1", "id": "v1", "vault_id": "uuid-1", "label": "Engineering",
                   "kind": "department", "role": "edit", "owner": "o-acme",
                   "vault_path": "/dav/o-acme/v-1.vault" } ] }"#,
        )]);
        let api = AccountApi::new("https://a", "t", &fake);
        let Ok(device) = api.cloud_device_or_approval("Laptop") else {
            panic!("no device");
        };
        assert_eq!(device.token.as_str(), "pst_secret");
        assert_eq!(device.shared[0].label, "Engineering");
        assert!(!format!("{device:?}").contains("pst_secret"));
        assert_eq!(
            fake.requests()[0].json(),
            json!({ "device_name": "Laptop" })
        );
    }

    #[test]
    fn activity_paging_and_the_member_routes() {
        let fake = Fake::with(vec![
            (200, r#"{"events":[]}"#),
            (200, "{}"),
            (204, ""),
            (204, ""),
            (201, r#"{"member_id":"m1"}"#),
            (200, "{}"),
        ]);
        let api = AccountApi::new("https://a", "t", &fake);
        api.activity("g1", 5000, Some(17)).unwrap();
        api.emergency_answer("gr 1", false).unwrap();
        api.leave_vault("g1", "v 1").unwrap();
        api.leave_org("g1").unwrap();
        api.invite("g1", "kim@example.com", "member", &[], true)
            .unwrap();
        api.invite("g1", "ada@example.com", "admin", &[], true)
            .unwrap();
        let r = fake.requests();
        assert_eq!(
            r[0].url,
            "https://a/v1/orgs/g1/activity?limit=1000&before=17"
        );
        assert_eq!(r[1].url, "https://a/v1/emergency/gr%201/refuse");
        assert_eq!(r[2].url, "https://a/v1/orgs/g1/vaults/v%201/leave");
        assert_eq!(r[3].url, "https://a/v1/orgs/g1/leave");
        assert_eq!(r[4].url, "https://a/v1/orgs/g1/invites");
        assert_eq!(r[4].json(), json!({ "email": "kim@example.com" }));
        // An admin invitation (a role the single route can't set) goes through the bulk route.
        assert_eq!(r[5].url, "https://a/v1/orgs/g1/invites/bulk");
    }

    #[test]
    fn role_and_offboard_routes_use_the_member_id() {
        let fake = Fake::with(vec![(204, ""), (200, r#"{"offboarding":"off_1"}"#)]);
        let api = AccountApi::new("https://a", "t", &fake);
        api.set_role("g1", "gm_7", "admin").unwrap();
        api.offboard("g1", "gm_7", Some("acc_2")).unwrap();
        let r = fake.requests();
        assert_eq!(r[0].method, "PATCH");
        assert_eq!(r[0].url, "https://a/v1/orgs/g1/members/gm_7");
        assert_eq!(r[0].json(), json!({ "role": "admin" }));
        assert_eq!(r[1].method, "POST");
        assert_eq!(r[1].url, "https://a/v1/orgs/g1/members/gm_7/offboard");
        assert_eq!(r[1].json(), json!({ "transfer_to": "acc_2" }));
    }

    #[test]
    fn the_password_mode_routes() {
        let fake = Fake::with(vec![
            (200, r#"{"mode":"one_password","effective":"one_password"}"#),
            (200, r#"{"mode":null,"effective":"choice"}"#),
            (204, ""),
        ]);
        let api = AccountApi::new("https://a", "t", &fake);
        let set = api
            .set_member_password_mode("g1", "gm_1", Some("one_password"))
            .unwrap();
        assert_eq!(set["effective"], "one_password");
        api.set_member_password_mode("g1", "gm_1", None).unwrap();
        assert_eq!(api.report_second_password(true).unwrap(), Value::Null);
        let r = fake.requests();
        assert_eq!(r[0].method, "PUT");
        assert_eq!(r[0].url, "https://a/v1/orgs/g1/members/gm_1/password-mode");
        assert_eq!(r[0].json(), json!({ "mode": "one_password" }));
        assert_eq!(r[1].json(), json!({ "mode": null }));
        assert_eq!(r[2].url, "https://a/v1/me/second-password");
        assert_eq!(r[2].json(), json!({ "second_password": true }));
        let orgs: Orgs = serde_json::from_value(json!({ "organisations": [
            { "id": "g1", "kind": "team", "policy": { "password_mode": "second_password" },
              "sharing_blocked": true },
            { "id": "g2", "kind": "family" },
        ] }))
        .unwrap();
        assert!(orgs.organisations[0].sharing_blocked);
        assert!(!orgs.organisations[1].sharing_blocked, "older services leave it out");
    }

    #[test]
    fn a_device_waiting_for_approval_is_told_apart() {
        let fake = Fake {
            answers: Mutex::new(vec![Answer {
                status: 403,
                error_code: Some("device_approval_required".into()),
                body: r#"{"error":"device_approval_required","message":"","approval":{"id":"da_1","status":"pending"}}"#.into(),
            }]),
            ..Default::default()
        };
        let api = AccountApi::new("https://a", "t", &fake);
        match api.cloud_device_or_approval("Laptop") {
            Err(Ok(approval)) => assert_eq!(approval["id"], "da_1"),
            other => panic!("{:?}", other.map(|_| ()).map_err(|e| e.map(|_| ()))),
        }
    }

    #[test]
    fn a_send_carries_the_cores_metadata_as_is() {
        let fake = Fake::with(vec![(
            201,
            r#"{"id":"s1","link_base":"https://account.passyble.com/send/"}"#,
        )]);
        let api = AccountApi::new("https://a", "t", &fake);
        let sealed = pass_core::SealedSend {
            ciphertext: vec![1, 2, 3],
            meta: r#"{"v":1}"#.into(),
            key: "k".into(),
            password_auth: None,
        };
        api.send_create(&sealed).unwrap();
        let body = fake.requests()[0].json();
        assert_eq!(body["meta"], r#"{"v":1}"#);
        assert_eq!(body["ciphertext"], "AQID");
        assert!(body.get("password_auth").is_none());
    }

    #[test]
    fn the_request_debug_output_has_no_credentials() {
        let api_fake = Fake::default();
        let api = ServerApi::new("https://h", "bob", "very-secret", &[], &api_fake);
        let request = api.request("GET", "/api/v1/whoami", None);
        assert!(!format!("{request:?}").contains("very-secret"));
        assert!(!format!("{request:?}").contains("Basic"));
    }
}
