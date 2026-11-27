//! PKCE, state, the loopback redirect and the token endpoint, against a local fake of Google's
//! token endpoint (the real endpoints are never contacted).

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use super::*;

/// A fake HTTP server answering each connection with the next canned response; records requests.
struct Fake {
    base: String,
    requests: Arc<Mutex<Vec<String>>>,
}

impl Fake {
    fn start(responses: Vec<(u16, &'static str)>) -> Fake {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let seen = requests.clone();
        thread::spawn(move || {
            for (status, body) in responses {
                let Ok((mut stream, _)) = listener.accept() else {
                    return;
                };
                let request = read_request(&mut stream);
                seen.lock().unwrap().push(request);
                let response = format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        Fake { base, requests }
    }

    fn endpoints(&self) -> Endpoints {
        Endpoints {
            auth: "https://accounts.example.test/o/oauth2/v2/auth".into(),
            token: format!("{}/token", self.base),
            revoke: format!("{}/revoke", self.base),
        }
    }

    fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }
}

fn read_request(stream: &mut TcpStream) -> String {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..end]).to_lowercase();
            let length = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .and_then(|v| v.trim().parse::<usize>().ok())
                .unwrap_or(0);
            if buf.len() >= end + 4 + length {
                break;
            }
        }
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

fn client() -> Client {
    Client {
        id: "123-abc.apps.googleusercontent.com".into(),
        secret: "GOCSPX-not-secret".into(),
    }
}

fn form(request: &str) -> Vec<(String, String)> {
    let body = request.split("\r\n\r\n").nth(1).unwrap_or_default();
    body.split('&')
        .filter_map(|p| p.split_once('='))
        .map(|(k, v)| (percent_decode(k), percent_decode(v)))
        .collect()
}

fn field<'a>(form: &'a [(String, String)], name: &str) -> Option<&'a str> {
    form.iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

fn query(url: &str) -> Vec<(String, String)> {
    let q = url.split_once('?').unwrap().1;
    q.split('&')
        .filter_map(|p| p.split_once('='))
        .map(|(k, v)| (percent_decode(k), percent_decode(v)))
        .collect()
}

const OK_TOKENS: &str = r#"{"access_token":"ya29.access","expires_in":3599,"refresh_token":"1//refresh","scope":"https://www.googleapis.com/auth/drive.appdata","token_type":"Bearer"}"#;

#[test]
fn pkce_matches_rfc_7636_and_is_random() {
    // RFC 7636, appendix B.
    assert_eq!(
        challenge_for("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    );
    let a = pkce();
    let b = pkce();
    assert_eq!(a.verifier.len(), 64);
    assert!((43..=128).contains(&a.verifier.len()));
    assert!(a
        .verifier
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    assert_eq!(a.challenge, challenge_for(&a.verifier));
    assert_ne!(*a.verifier, *b.verifier);
    let s = random_state();
    assert_eq!(s.len(), 32);
    assert_ne!(s, random_state());
}

#[test]
fn consent_url_has_every_parameter() {
    let ep = Endpoints::google();
    let url = auth_url(
        &ep,
        "id.apps",
        "http://127.0.0.1:5555/",
        "chal",
        "st/ate",
        None,
    );
    assert!(url.starts_with("https://accounts.google.com/o/oauth2/v2/auth?"));
    let q = query(&url);
    let get = |k: &str| field(&q, k).map(str::to_string);
    assert_eq!(get("client_id").as_deref(), Some("id.apps"));
    assert_eq!(
        get("redirect_uri").as_deref(),
        Some("http://127.0.0.1:5555/")
    );
    assert_eq!(get("response_type").as_deref(), Some("code"));
    assert_eq!(get("scope").as_deref(), Some(SCOPE));
    assert_eq!(get("code_challenge").as_deref(), Some("chal"));
    assert_eq!(get("code_challenge_method").as_deref(), Some("S256"));
    assert_eq!(get("state").as_deref(), Some("st/ate"));
    assert_eq!(get("access_type").as_deref(), Some("offline"));
    assert_eq!(get("prompt").as_deref(), Some("select_account consent"));
    assert!(get("login_hint").is_none());
    assert!(url.contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A5555%2F"));
    assert!(url.contains("state=st%2Fate"));

    let again = auth_url(
        &ep,
        "id",
        "http://127.0.0.1:1/",
        "c",
        "s",
        Some(" a+b@gmail.com "),
    );
    let q = query(&again);
    assert_eq!(field(&q, "login_hint"), Some("a+b@gmail.com"));
    assert_eq!(field(&q, "prompt"), Some("consent"));
}

#[test]
fn callback_parsing() {
    assert_eq!(
        parse_callback("GET /?state=abc&code=4%2F0AVG-x_y&scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fdrive.appdata HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"),
        Callback::Code { code: "4/0AVG-x_y".into(), state: "abc".into() }
    );
    assert_eq!(
        parse_callback("GET /?error=access_denied&state=abc HTTP/1.1\r\n\r\n"),
        Callback::Error {
            error: "access_denied".into(),
            state: "abc".into()
        }
    );
    assert_eq!(
        parse_callback("GET /favicon.ico HTTP/1.1\r\n\r\n"),
        Callback::Other
    );
    assert_eq!(
        parse_callback("GET /?state=abc HTTP/1.1\r\n\r\n"),
        Callback::Other
    );
    assert_eq!(
        parse_callback("POST /?code=x&state=abc HTTP/1.1\r\n\r\n"),
        Callback::Other
    );
    assert_eq!(
        parse_callback("GET /other?code=x&state=abc HTTP/1.1\r\n\r\n"),
        Callback::Other
    );
    assert_eq!(parse_callback(""), Callback::Other);
    assert_eq!(percent_decode("a%2"), "a%2");
    assert_eq!(percent_decode("a%zz+b"), "a%zz b");
}

fn browse(redirect_uri: &str, target: &str) -> String {
    let addr = redirect_uri
        .trim_start_matches("http://")
        .trim_end_matches('/')
        .to_string();
    let mut stream = TcpStream::connect(addr).unwrap();
    write!(
        stream,
        "GET {target} HTTP/1.1\r\nHost: 127.0.0.1\r\nAccept: text/html\r\n\r\n"
    )
    .unwrap();
    let mut response = String::new();
    let _ = stream.read_to_string(&mut response);
    response
}

#[test]
fn loopback_takes_the_redirect_with_the_right_state_only() {
    let loopback = Loopback::bind().unwrap();
    let uri = loopback.redirect_uri();
    assert!(uri.starts_with("http://127.0.0.1:") && uri.ends_with('/'));
    let browser = {
        let uri = uri.clone();
        thread::spawn(move || {
            let favicon = browse(&uri, "/favicon.ico");
            let forged = browse(&uri, "/?state=wrong&code=evil");
            let real = browse(&uri, "/?state=s3cret&code=4%2Fgood");
            (favicon, forged, real)
        })
    };
    let code = loopback
        .wait_for_code("s3cret", Duration::from_secs(10), &AtomicBool::new(false))
        .unwrap();
    assert_eq!(*code, "4/good");
    let (favicon, forged, real) = browser.join().unwrap();
    assert!(favicon.starts_with("HTTP/1.1 404"));
    assert!(forged.starts_with("HTTP/1.1 400"));
    assert!(real.starts_with("HTTP/1.1 200"));
    assert!(real.contains("You can close this tab and return to Passyble."));
    assert!(real.contains("Cache-Control: no-store"));
}

#[test]
fn loopback_reports_a_refusal() {
    let loopback = Loopback::bind().unwrap();
    let uri = loopback.redirect_uri();
    let browser = thread::spawn(move || browse(&uri, "/?error=access_denied&state=st"));
    let err = loopback
        .wait_for_code("st", Duration::from_secs(10), &AtomicBool::new(false))
        .unwrap_err();
    assert!(matches!(&err, AuthError::Failed(m) if m.contains("cancelled in the browser")));
    assert!(browser.join().unwrap().contains("Sign-in cancelled"));
}

#[test]
fn loopback_can_be_cancelled_and_times_out() {
    let loopback = Loopback::bind().unwrap();
    let cancel = Arc::new(AtomicBool::new(false));
    let flag = cancel.clone();
    thread::spawn(move || {
        thread::sleep(Duration::from_millis(200));
        flag.store(true, Ordering::Relaxed);
    });
    assert_eq!(
        loopback
            .wait_for_code("s", Duration::from_secs(10), &cancel)
            .unwrap_err(),
        AuthError::Cancelled
    );
    let err = loopback
        .wait_for_code("s", Duration::from_millis(250), &AtomicBool::new(false))
        .unwrap_err();
    assert!(matches!(err, AuthError::Failed(m) if m.contains("took too long")));
}

#[test]
fn token_responses() {
    let t = parse_token_response(200, OK_TOKENS).unwrap();
    assert_eq!(*t.access_token, "ya29.access");
    assert_eq!(t.expires_in, Duration::from_secs(3599));
    assert_eq!(
        t.refresh_token.as_deref().map(|s| s.as_str()),
        Some("1//refresh")
    );
    assert!(!format!("{t:?}").contains("ya29"));

    // The user unticked the Drive permission.
    let no_scope = r#"{"access_token":"a","expires_in":10,"scope":"openid"}"#;
    assert!(
        matches!(parse_token_response(200, no_scope), Err(AuthError::Failed(m)) if m.contains("its own folder"))
    );
    let t = parse_token_response(200, r#"{"access_token":"b"}"#).unwrap();
    assert!(t.refresh_token.is_none());
    assert_eq!(t.expires_in, Duration::from_secs(3600));

    assert_eq!(
        parse_token_response(
            400,
            r#"{"error":"invalid_grant","error_description":"Token has been expired or revoked."}"#
        )
        .unwrap_err(),
        AuthError::SignInAgain
    );
    assert!(matches!(
        parse_token_response(401, r#"{"error":"invalid_client","error_description":"Unauthorized"}"#),
        Err(AuthError::Failed(m)) if m == "Google sign-in isn't working in Passyble right now. Try again later, or back up your vault another way."
    ));
    assert!(matches!(
        parse_token_response(400, r#"{"error":"invalid_request","error_description":"Missing code verifier."}"#),
        Err(AuthError::Failed(m)) if m == "Google sign-in didn't work. Try again."
    ));
    assert!(
        matches!(parse_token_response(502, "<html>bad gateway</html>"), Err(AuthError::Failed(m)) if m == "Google sign-in didn't work. Try again in a moment.")
    );
    assert!(matches!(
        parse_token_response(200, "{}"),
        Err(AuthError::Failed(_))
    ));
}

#[test]
fn code_exchange_sends_the_verifier_and_secret() {
    let fake = Fake::start(vec![(200, OK_TOKENS)]);
    let tokens = exchange_code(
        &fake.endpoints(),
        &client(),
        "4/code",
        "verifier-123",
        "http://127.0.0.1:4242/",
    )
    .unwrap();
    assert_eq!(*tokens.access_token, "ya29.access");
    let requests = fake.requests();
    assert!(requests[0].starts_with("POST /token "));
    assert!(requests[0]
        .to_lowercase()
        .contains("content-type: application/x-www-form-urlencoded"));
    let f = form(&requests[0]);
    assert_eq!(field(&f, "grant_type"), Some("authorization_code"));
    assert_eq!(field(&f, "code"), Some("4/code"));
    assert_eq!(field(&f, "code_verifier"), Some("verifier-123"));
    assert_eq!(field(&f, "redirect_uri"), Some("http://127.0.0.1:4242/"));
    assert_eq!(
        field(&f, "client_id"),
        Some("123-abc.apps.googleusercontent.com")
    );
    assert_eq!(field(&f, "client_secret"), Some("GOCSPX-not-secret"));
}

#[test]
fn code_exchange_needs_a_refresh_token_and_a_fresh_code() {
    let fake = Fake::start(vec![
        (
            200,
            r#"{"access_token":"a","expires_in":3599,"scope":"https://www.googleapis.com/auth/drive.appdata"}"#,
        ),
        (
            400,
            r#"{"error":"invalid_grant","error_description":"Bad Request"}"#,
        ),
    ]);
    let no_secret = Client {
        secret: String::new(),
        ..client()
    };
    let err = exchange_code(
        &fake.endpoints(),
        &no_secret,
        "c",
        "v",
        "http://127.0.0.1:1/",
    )
    .unwrap_err();
    assert!(matches!(err, AuthError::Failed(m) if m.contains("lasting access")));
    assert!(field(&form(&fake.requests()[0]), "client_secret").is_none());
    let err = exchange_code(
        &fake.endpoints(),
        &client(),
        "c",
        "v",
        "http://127.0.0.1:1/",
    )
    .unwrap_err();
    assert!(matches!(err, AuthError::Failed(m) if m.contains("expired before it finished")));
}

#[test]
fn refresh_and_revoke() {
    let fake = Fake::start(vec![
        (
            200,
            r#"{"access_token":"ya29.new","expires_in":3599,"scope":"https://www.googleapis.com/auth/drive.appdata","token_type":"Bearer"}"#,
        ),
        (
            400,
            r#"{"error":"invalid_grant","error_description":"Token has been expired or revoked."}"#,
        ),
        (200, ""),
        (
            400,
            r#"{"error":"invalid_token","error_description":"Token expired or revoked"}"#,
        ),
    ]);
    let ep = fake.endpoints();
    assert_eq!(
        *refresh(&ep, &client(), "1//r").unwrap().access_token,
        "ya29.new"
    );
    assert_eq!(
        refresh(&ep, &client(), "1//r").unwrap_err(),
        AuthError::SignInAgain
    );
    revoke(&ep, "1//r").unwrap();
    revoke(&ep, "1//r").unwrap();
    let requests = fake.requests();
    let f = form(&requests[0]);
    assert_eq!(field(&f, "grant_type"), Some("refresh_token"));
    assert_eq!(field(&f, "refresh_token"), Some("1//r"));
    assert!(requests[2].starts_with("POST /revoke "));
    assert_eq!(field(&form(&requests[2]), "token"), Some("1//r"));
}

#[test]
fn unreachable_token_endpoint_is_plain_language() {
    // Nothing listens on this port (bound, then closed).
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let ep = Endpoints {
        auth: String::new(),
        token: format!("http://127.0.0.1:{port}/token"),
        revoke: String::new(),
    };
    let err = refresh(&ep, &client(), "r").unwrap_err();
    assert!(
        matches!(&err, AuthError::Failed(m) if m.starts_with("Can't reach 127.0.0.1:")),
        "{err:?}"
    );
}

#[test]
fn whole_sign_in_against_a_fake_google() {
    let fake = Fake::start(vec![(200, OK_TOKENS)]);
    let ep = fake.endpoints();
    let seen_url = Arc::new(Mutex::new(String::new()));
    let seen = seen_url.clone();
    let tokens = sign_in_with(
        &ep,
        &client(),
        None,
        Duration::from_secs(10),
        &AtomicBool::new(false),
        |url| {
            *seen.lock().unwrap() = url.to_string();
            let q = query(url);
            let redirect = field(&q, "redirect_uri").unwrap().to_string();
            let state = field(&q, "state").unwrap().to_string();
            thread::spawn(move || {
                browse(
                    &redirect,
                    &format!(
                        "/?state={}&code=4%2Fconsented&scope={}",
                        encode(&state),
                        encode(SCOPE)
                    ),
                )
            });
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(
        tokens.refresh_token.as_deref().map(|s| s.as_str()),
        Some("1//refresh")
    );
    let url = seen_url.lock().unwrap().clone();
    let q = query(&url);
    let f = form(&fake.requests()[0]);
    assert_eq!(field(&f, "code"), Some("4/consented"));
    assert_eq!(field(&f, "redirect_uri"), field(&q, "redirect_uri"));
    // The verifier sent to the token endpoint belongs to the challenge in the consent URL.
    assert_eq!(
        challenge_for(field(&f, "code_verifier").unwrap()),
        field(&q, "code_challenge").unwrap()
    );
}

#[test]
fn browser_that_cannot_open_ends_the_sign_in() {
    let fake = Fake::start(vec![]);
    let err = sign_in_with(
        &fake.endpoints(),
        &client(),
        None,
        Duration::from_secs(10),
        &AtomicBool::new(false),
        |_| Err("Passyble couldn't open your browser (x).".into()),
    )
    .unwrap_err();
    assert_eq!(
        err,
        AuthError::Failed("Passyble couldn't open your browser (x).".into())
    );
}

/// The pending sign-in is one slot: tests that use it take turns.
static PENDING_TESTS: Mutex<()> = Mutex::new(());

#[test]
fn pending_sign_in_tokens_are_cached_and_refreshed() {
    let _turn = PENDING_TESTS.lock().unwrap_or_else(|p| p.into_inner());
    let email = "Pending.Test@example.invalid";
    let fake = Fake::start(vec![
        (200, r#"{"access_token":"ya29.second","expires_in":3599}"#),
        (400, r#"{"error":"invalid_grant"}"#),
    ]);
    let ep = fake.endpoints();
    let first = parse_token_response(200, OK_TOKENS).unwrap();
    store_pending(email, &first);
    assert_eq!(
        *access_token(&ep, &client(), "pending.test@example.invalid", false).unwrap(),
        "ya29.access"
    );
    assert!(fake.requests().is_empty());
    // Drive refused it: refresh with the pending refresh token.
    assert_eq!(
        *access_token(&ep, &client(), email, true).unwrap(),
        "ya29.second"
    );
    assert_eq!(
        field(&form(&fake.requests()[0]), "refresh_token"),
        Some("1//refresh")
    );
    assert_eq!(
        *access_token(&ep, &client(), email, false).unwrap(),
        "ya29.second"
    );
    assert_eq!(
        access_token(&ep, &client(), email, true).unwrap_err(),
        AuthError::SignInAgain
    );
    assert!(guard(&PENDING)
        .as_ref()
        .is_none_or(|(e, _)| e != "pending.test@example.invalid"));
    forget_access(email);
}

#[test]
fn short_lived_access_tokens_are_refreshed_early() {
    let _turn = PENDING_TESTS.lock().unwrap_or_else(|p| p.into_inner());
    let email = "short.lived@example.invalid";
    let fake = Fake::start(vec![(
        200,
        r#"{"access_token":"ya29.fresh","expires_in":3599}"#,
    )]);
    let soon = parse_token_response(
        200,
        r#"{"access_token":"ya29.old","expires_in":30,"refresh_token":"1//x"}"#,
    )
    .unwrap();
    store_pending(email, &soon);
    assert_eq!(
        *access_token(&fake.endpoints(), &client(), email, false).unwrap(),
        "ya29.fresh"
    );
    *guard(&PENDING) = None;
    forget_access(email);
}

#[test]
fn errors_read_well() {
    assert_eq!(AuthError::SignInAgain.message(), sign_in_again());
    assert_eq!(
        AuthError::Cancelled.message(),
        "Google sign-in was cancelled."
    );
    let c = client();
    assert!(!format!("{c:?}").contains("GOCSPX"));
}

/// The tests' stand-in for Windows Credential Manager, with failures to inject per account.
#[derive(Default)]
pub(super) struct FakeStore {
    tokens: Mutex<std::collections::HashMap<String, String>>,
    failing_reads: Mutex<Vec<String>>,
    failing_writes: Mutex<Vec<String>>,
    lost_writes: Mutex<Vec<String>>,
}

impl FakeStore {
    fn put(&self, account: &str, token: &str) {
        self.tokens
            .lock()
            .unwrap()
            .insert(account.into(), token.into());
    }

    fn peek(&self, account: &str) -> Option<String> {
        self.tokens.lock().unwrap().get(account).cloned()
    }

    fn fail_reads(&self, account: &str, fail: bool) {
        let mut list = self.failing_reads.lock().unwrap();
        list.retain(|a| a != account);
        if fail {
            list.push(account.into());
        }
    }
}

impl Store for FakeStore {
    fn get(&self, account: &str) -> Result<Option<Zeroizing<String>>, &'static str> {
        if self
            .failing_reads
            .lock()
            .unwrap()
            .iter()
            .any(|a| a == account)
        {
            return Err("platform");
        }
        Ok(self.peek(account).map(Zeroizing::new))
    }

    fn set(&self, account: &str, token: &str) -> Result<(), &'static str> {
        if self
            .failing_writes
            .lock()
            .unwrap()
            .iter()
            .any(|a| a == account)
        {
            return Err("platform");
        }
        if !self
            .lost_writes
            .lock()
            .unwrap()
            .iter()
            .any(|a| a == account)
        {
            self.put(account, token);
        }
        Ok(())
    }

    fn delete(&self, account: &str) {
        self.tokens.lock().unwrap().remove(account);
    }
}

pub(super) fn fake_store() -> &'static FakeStore {
    static STORE: std::sync::OnceLock<FakeStore> = std::sync::OnceLock::new();
    STORE.get_or_init(FakeStore::default)
}

const REFRESHED: &str = r#"{"access_token":"ya29.refreshed","expires_in":3599,"scope":"https://www.googleapis.com/auth/drive.appdata","token_type":"Bearer"}"#;

fn unreachable() -> Endpoints {
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    Endpoints {
        auth: String::new(),
        token: format!("http://127.0.0.1:{port}/token"),
        revoke: String::new(),
    }
}

#[test]
fn a_committed_sign_in_outlives_the_access_token_and_a_restart() {
    let _turn = PENDING_TESTS.lock().unwrap_or_else(|p| p.into_inner());
    let email = "restart@example.invalid";
    store_pending(email, &parse_token_response(200, OK_TOKENS).unwrap());
    commit(email).unwrap();
    assert_eq!(fake_store().peek(email).as_deref(), Some("1//refresh"));
    assert!(guard(&PENDING).as_ref().is_none_or(|(e, _)| e != email));
    // A restart (or the hour of the access token running out): only Credential Manager is left.
    forget_access(email);
    let fake = Fake::start(vec![(200, REFRESHED)]);
    assert_eq!(
        *access_token(&fake.endpoints(), &client(), email, false).unwrap(),
        "ya29.refreshed"
    );
    assert_eq!(
        field(&form(&fake.requests()[0]), "refresh_token"),
        Some("1//refresh")
    );
    commit(email).unwrap();
    forget_access(email);
    fake_store().delete(email);
}

#[test]
fn an_unreadable_credential_manager_is_not_a_sign_out() {
    let email = "busy.store@example.invalid";
    fake_store().put(email, "1//kept");
    fake_store().fail_reads(email, true);
    let fake = Fake::start(vec![(200, REFRESHED)]);
    let err = access_token(&fake.endpoints(), &client(), email, true).unwrap_err();
    assert!(
        matches!(&err, AuthError::Failed(m) if m.contains("couldn't read the Google sign-in")),
        "{err:?}"
    );
    assert!(
        fake.requests().is_empty(),
        "Google isn't asked without a token"
    );
    // The next try, once Credential Manager answers again, just works.
    fake_store().fail_reads(email, false);
    assert_eq!(fake_store().peek(email).as_deref(), Some("1//kept"));
    assert_eq!(
        *access_token(&fake.endpoints(), &client(), email, true).unwrap(),
        "ya29.refreshed"
    );
    forget_access(email);
    fake_store().delete(email);
}

#[test]
fn refresh_failures_other_than_invalid_grant_keep_the_sign_in() {
    let email = "flaky.network@example.invalid";
    fake_store().put(email, "1//kept");
    let err = access_token(&unreachable(), &client(), email, true).unwrap_err();
    assert!(matches!(err, AuthError::Failed(_)), "{err:?}");
    // Google's outage, with and without its JSON error.
    let fake = Fake::start(vec![
        (503, "<html>Service Unavailable</html>"),
        (500, r#"{"error":"internal_failure"}"#),
        (200, REFRESHED),
    ]);
    for _ in 0..2 {
        let err = access_token(&fake.endpoints(), &client(), email, true).unwrap_err();
        assert!(matches!(err, AuthError::Failed(_)), "{err:?}");
        assert_eq!(fake_store().peek(email).as_deref(), Some("1//kept"));
    }
    assert_eq!(
        *access_token(&fake.endpoints(), &client(), email, true).unwrap(),
        "ya29.refreshed"
    );
    forget_access(email);
    fake_store().delete(email);
}

#[test]
fn invalid_grant_signs_out_and_forgets_the_stored_token() {
    let email = "revoked@example.invalid";
    fake_store().put(email, "1//revoked");
    let fake = Fake::start(vec![(
        400,
        r#"{"error":"invalid_grant","error_description":"Token has been expired or revoked."}"#,
    )]);
    assert_eq!(
        access_token(&fake.endpoints(), &client(), email, true).unwrap_err(),
        AuthError::SignInAgain
    );
    assert_eq!(fake_store().peek(email), None);
    // Nothing on this PC any more: "Sign in to Google again", without asking Google.
    let fake = Fake::start(vec![]);
    assert_eq!(
        access_token(&fake.endpoints(), &client(), email, true).unwrap_err(),
        AuthError::SignInAgain
    );
    assert!(fake.requests().is_empty());
}

#[test]
fn a_new_sign_in_survives_the_refusal_of_the_old_token() {
    // A background sync refreshes the old token while "Sign in to Google again" stores a new one.
    let email = "race@example.invalid";
    fake_store().put(email, "1//old");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let server = thread::spawn(move || {
        let mut seen = Vec::new();
        for (status, body) in [(400, r#"{"error":"invalid_grant"}"#), (200, REFRESHED)] {
            let (mut stream, _) = listener.accept().unwrap();
            seen.push(read_request(&mut stream));
            if seen.len() == 1 {
                // The new sign-in lands while Google answers the old token's refresh.
                fake_store().put("race@example.invalid", "1//new");
            }
            let response = format!(
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).unwrap();
        }
        seen
    });
    let ep = Endpoints {
        auth: String::new(),
        token: format!("{base}/token"),
        revoke: String::new(),
    };
    assert_eq!(
        *access_token(&ep, &client(), email, true).unwrap(),
        "ya29.refreshed"
    );
    let seen = server.join().unwrap();
    assert_eq!(field(&form(&seen[0]), "refresh_token"), Some("1//old"));
    assert_eq!(field(&form(&seen[1]), "refresh_token"), Some("1//new"));
    assert_eq!(fake_store().peek(email).as_deref(), Some("1//new"));
    forget_access(email);
    fake_store().delete(email);
}

#[test]
fn commit_fails_loudly_when_the_token_did_not_stick() {
    let _turn = PENDING_TESTS.lock().unwrap_or_else(|p| p.into_inner());
    let tokens = parse_token_response(200, OK_TOKENS).unwrap();
    let refused = "write.refused@example.invalid";
    fake_store()
        .failing_writes
        .lock()
        .unwrap()
        .push(refused.into());
    store_pending(refused, &tokens);
    let err = commit(refused).unwrap_err();
    assert!(err.contains("couldn't save the Google sign-in"), "{err}");
    // The sign-in stays pending in memory, so trying again can still store it.
    assert!(guard(&PENDING).as_ref().is_some_and(|(e, _)| e == refused));
    // A write that "succeeded" but stored nothing is caught by the read-back.
    let lost = "write.lost@example.invalid";
    fake_store().lost_writes.lock().unwrap().push(lost.into());
    store_pending(lost, &tokens);
    assert!(commit(lost).is_err());
    assert_eq!(fake_store().peek(lost), None);
    // No sign-in at all for that account: the vault isn't set up without one.
    *guard(&PENDING) = None;
    let err = commit("never.signed.in@example.invalid").unwrap_err();
    assert_eq!(err, "Sign in with Google first.");
    forget_access(refused);
    forget_access(lost);
}

#[test]
fn release_deletes_the_stored_sign_in() {
    let _turn = PENDING_TESTS.lock().unwrap_or_else(|p| p.into_inner());
    let email = "released@example.invalid";
    fake_store().put(email, "1//gone");
    release(email, None);
    assert_eq!(fake_store().peek(email), None);
}

#[test]
fn refresh_outcomes_are_logged_as_codes() {
    let ok = Ok((200, REFRESHED.to_string()));
    assert_eq!(refresh_step(&ok), "gdrive: token refreshed");
    assert_eq!(
        refresh_step(&Err(AuthError::Failed(
            "Can't reach oauth2.googleapis.com".into()
        ))),
        "gdrive: refresh failed (network)"
    );
    let revoked = Ok((
        400,
        r#"{"error":"invalid_grant","error_description":"Token has been expired or revoked."}"#
            .to_string(),
    ));
    assert_eq!(refresh_step(&revoked), "gdrive: signed out (invalid_grant)");
    assert_eq!(
        refresh_step(&Ok((503, "<html>down</html>".into()))),
        "gdrive: refresh failed (http 503)"
    );
    assert_eq!(
        refresh_step(&Ok((401, r#"{"error":"unauthorized_client"}"#.into()))),
        "gdrive: refresh failed (unauthorized_client)"
    );
    // Free text from the endpoint never reaches the timing log.
    assert_eq!(
        refresh_step(&Ok((400, r#"{"error":"Weird Error <x>"}"#.into()))),
        "gdrive: refresh failed (other)"
    );
    assert_eq!(
        refresh_step(&Ok((200, "{}".into()))),
        "gdrive: refresh failed (no_access_token)"
    );
    // pass.log gets Google's reason for a refusal, cut short, and nothing else.
    assert_eq!(
        refused_description(
            r#"{"error":"invalid_grant","error_description":"Token has been expired or revoked."}"#
        )
        .as_deref(),
        Some("Token has been expired or revoked.")
    );
    assert_eq!(
        refused_description(r#"{"error":"invalid_grant"}"#).as_deref(),
        Some("(no description)")
    );
    assert_eq!(refused_description(r#"{"error":"invalid_client"}"#), None);
    assert_eq!(refused_description(REFRESHED), None);
}
