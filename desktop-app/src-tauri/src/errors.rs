//! Plain-language error messages with a next action, for every error that reaches the window.
//! Core errors carry technical detail (`network error: sign in: Connection Failed: …`); the user
//! should read what happened and what to do. The UI's `friendlyError` (ui/lib.js) applies the same
//! rules to the few texts that don't come through here.

use pass_core::PassError;

use crate::i18n::{tr, trn};

fn capitalize(s: &str) -> String {
    let mut chars = s.trim().chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

/// `message` for the user, with the technical `detail` (an OS, library or service error) written to
/// the log only: what the user reads says what happened and what to do, never the raw text.
pub(crate) fn logged(message: String, context: &str, detail: impl std::fmt::Display) -> String {
    crate::applog::plog!("{context}: {detail}");
    message
}

pub(crate) fn file_not_read(detail: impl std::fmt::Display) -> String {
    logged(tr!("errors.file_not_read"), "read file", detail)
}

pub(crate) fn file_not_saved(detail: impl std::fmt::Display) -> String {
    logged(tr!("errors.file_not_saved"), "save file", detail)
}

/// Something that shouldn't fail did: the generic "Something went wrong" for the user, the detail in the log.
pub(crate) fn internal(context: &str, detail: impl std::fmt::Display) -> String {
    logged(tr!("errors.generic"), context, detail)
}

/// The prefix the desktop agent gives its vault file read and write errors (`pass-agent`
/// `io_err`): the file is missing, locked by another program or on a drive that is gone.
const AGENT_FILE_ERROR: &str = "vault file: ";

pub(crate) fn sentence(s: &str) -> String {
    let s = capitalize(s);
    // Core texts come in the app's language: Chinese, Japanese and Hindi end sentences differently.
    if s.ends_with(['.', '!', '?', '。', '！', '？', '।']) {
        s
    } else {
        format!("{s}.")
    }
}

/// The host in a network error text (`https://h:8443/…`), for "Can't reach h:8443".
fn host_in(message: &str) -> Option<String> {
    let start = message.find("://")? + 3;
    let rest = &message[start..];
    let host: String = rest
        .chars()
        .take_while(|c| !matches!(c, '/' | ' ' | '\'' | '"' | ')' | ','))
        .collect();
    (!host.is_empty()).then_some(host)
}

/// Whether `message` is pass-core's text `key`, in whatever language the core wrote it: core messages are
/// translated (`pass_core::set_language`), so their English words can't be matched. A key ending in `*` stands for
/// every key it starts.
pub(crate) fn core_says(message: &str, key: &str) -> bool {
    pass_core::core_message_is(message.to_string(), key.to_string())
}

fn core_arg(message: &str, key: &str, name: &str) -> Option<String> {
    pass_core::core_message_arg(message.to_string(), key.to_string(), name.to_string())
}

/// The server or WebDAV refused this device's token: pass-core's "authentication failed" (Passyble Server's 401
/// "…signed out"; WebDAV 401/403), or a server's own text with those words.
pub(crate) fn is_auth_failure(message: &str) -> bool {
    core_says(message, "server.auth_failed")
        || core_says(message, "webdav.auth_failed")
        || message
            .to_ascii_lowercase()
            .contains("authentication failed")
}

/// Passyble Server's `password_change_required` (a device signed in with an admin-set password
/// may only change it), as pass-core words it (`server.password_change_required`, any language).
/// Older servers send no code: their English sentence after the core's action prefix.
pub(crate) fn password_change_required(message: &str) -> Option<String> {
    if !core_says(message, "server.password_change_required") {
        return None;
    }
    let at = message.find("choose a new password").unwrap_or(0);
    Some(sentence(&message[at..]))
}

fn minutes_in(message: &str) -> Option<u64> {
    let tail = &message[message.find("try again in ")? + "try again in ".len()..];
    tail.split_whitespace().next()?.parse().ok()
}

/// The certificate isn't publicly trusted (self-signed Passyble Server without a pin yet).
pub fn is_untrusted_certificate(message: &str) -> bool {
    if core_says(message, "net.untrusted_certificate") {
        return true;
    }
    // Texts of this app's own HTTPS calls (Google sign-in) and of older cores.
    let m = message.to_ascii_lowercase();
    m.contains("invalid peer certificate")
        || m.contains("unknownissuer")
        || m.contains("unknown issuer")
        || m.contains("self-signed")
        || m.contains("self signed")
        || m.contains("certificate not valid")
        || m.contains("notvalidforname")
}

pub fn network(message: &str) -> String {
    let m = message.to_ascii_lowercase();
    // pass-core's texts by their catalog key (any language), see `core_says`.
    // E-mail alias services (Core/core/src/alias.rs): already a sentence naming the service.
    if core_says(message, "alias.*") {
        return sentence(message);
    }
    if core_says(message, "server.too_many_attempts") {
        let minutes = core_arg(message, "server.too_many_attempts", "count")
            .and_then(|n| n.trim().parse().ok())
            .or_else(|| minutes_in(message));
        return match minutes {
            Some(1) => tr!("errors.too_many_attempts_minute"),
            Some(n) => trn!("errors.too_many_attempts_minutes", n),
            None => tr!("errors.too_many_attempts"),
        };
    }
    if core_says(message, "server.unsupported.sign_in") {
        return tr!("errors.server_too_old");
    }
    if is_auth_failure(message) {
        return tr!("errors.device_signed_out");
    }
    if is_untrusted_certificate(message) {
        return tr!("errors.certificate_untrusted");
    }
    // Passyble Server's per-account quota (`<action>: storage quota reached[: <server message>]`).
    if let Some(detail) = core_arg(message, "webdav.quota_reached_detail", "detail") {
        let detail = detail.trim();
        if !detail.is_empty() {
            return tr!(
                "errors.storage_full_detail",
                detail = detail.trim_end_matches('.')
            );
        }
    }
    if core_says(message, "webdav.quota_reached") {
        return tr!("errors.storage_full");
    }
    // Google Drive (Core/core/src/gdrive.rs `fail`).
    if core_says(message, "gdrive.storage_full") {
        return tr!("errors.google_storage_full");
    }
    if core_says(message, "gdrive.busy") {
        return tr!("errors.google_busy");
    }
    if core_says(message, "gdrive.api_disabled") {
        return tr!("errors.google_api_disabled");
    }
    if core_says(message, "gdrive.refused") {
        return tr!("errors.google_refused");
    }
    if m.contains("expired") && m.contains("certificate") && !core_says(message, "net.*") {
        return tr!("errors.certificate_expired");
    }
    let unreachable = [
        "dns failed",
        "no such host",
        "failed to lookup",
        "connection failed",
        "connection refused",
        "actively refused",
        "timed out",
        "timeout",
        "unreachable",
        "can't connect",
        "connection reset",
        "network is",
    ];
    // `fetch_server_pin` couldn't connect (Core/core/src/pinning.rs).
    if let Some(host) = core_arg(message, "pinning.cant_connect", "host") {
        return tr!("errors.cant_reach_host", host = host);
    }
    // The core's other network texts are already plain and in the app's language: shown without
    // their action label ("upload: ").
    if let Some(text) = core_plain(message) {
        return text;
    }
    if unreachable.iter().any(|p| m.contains(p)) {
        return match host_in(message) {
            Some(host) => tr!("errors.cant_reach_host", host = host),
            None => tr!("errors.cant_reach_server"),
        };
    }
    logged(tr!("errors.server_problem"), "network", message.trim())
}

/// Families of pass-core texts that are plain sentences already (Core/core/locales/en.json).
const CORE_PLAIN: &[&str] = &["net.*", "gdrive.*", "webdav.*", "server.*", "pinning.*"];

/// A pass-core network text as a sentence without its `{action}: ` label, or `None` if `message`
/// isn't one of the core's plain texts.
fn core_plain(message: &str) -> Option<String> {
    let family = CORE_PLAIN.iter().find(|f| core_says(message, f))?;
    let message = message.trim();
    let text = core_arg(message, family, "action")
        .and_then(|action| message.strip_prefix(action.as_str()))
        .and_then(|rest| rest.strip_prefix(':'))
        .unwrap_or(message);
    Some(sentence(text))
}

/// Passyble Server's two-factor answers (`pass_core::TWO_FACTOR_REQUIRED` / `TWO_FACTOR_INVALID` at the start of an
/// `InvalidInput` message) in plain words. The sign-in flows turn these into a code field first (`signin.rs`); this
/// covers the rest (turning two-factor sign-in on or off with a wrong code).
pub fn two_factor(message: &str) -> Option<String> {
    let m = message.trim_start();
    if m.starts_with("2fa_required") {
        Some(tr!("errors.two_factor_required"))
    } else if m.starts_with("2fa_invalid") {
        Some(tr!("errors.two_factor_invalid"))
    } else {
        None
    }
}

pub fn friendly(e: PassError) -> String {
    match e {
        PassError::InvalidPassword => tr!("errors.wrong_master_password"),
        PassError::Network(m) => network(&m),
        PassError::CertificateChanged(_) => tr!("errors.certificate_changed"),
        PassError::InvalidInput(m) => two_factor(&m).unwrap_or_else(|| sentence(&m)),
        PassError::NotFound(m) => sentence(&m),
        PassError::Conflict(m) => sentence(&m),
        PassError::Corrupt(m) => match m.strip_prefix(AGENT_FILE_ERROR) {
            Some(detail) => logged(tr!("errors.vault_file_unavailable"), "vault file", detail),
            None => sentence(&m),
        },
        // A sync of a vault whose password was changed on another device: that change gave it a new key;
        // unlocking with the new password takes the synced copy.
        PassError::Crypto(m) if core_says(&m, "vault.different_key") => {
            tr!("errors.password_changed_elsewhere")
        }
        PassError::Crypto(m) => sentence(&m),
        PassError::AuthRequired(_) => tr!("errors.sign_in_expired"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_vault_rekeyed_on_another_device_says_to_unlock_with_the_new_password() {
        let synced = PassError::Crypto("remote vault uses a different key".into());
        assert_eq!(friendly(synced), tr!("errors.password_changed_elsewhere"));
    }

    #[test]
    fn plain_messages() {
        assert_eq!(
            friendly(PassError::InvalidPassword),
            "Wrong master password. Check Caps Lock and try again."
        );
        assert_eq!(
            friendly(PassError::Network(
                "sign in: too many failed attempts; try again in 15 minutes".into()
            )),
            "Too many attempts. Wait 15 minutes, then try again."
        );
        assert_eq!(
            friendly(PassError::Network(
                "sign in: https://pass.example.com:8443/api/v1/login: Dns Failed: resolve dns name 'pass.example.com:8443': No such host is known.".into()
            )),
            "Can't reach pass.example.com:8443. Check the address and your internet connection, then try again."
        );
        let untrusted = "sign in: https://h/api/v1/login: Connection Failed: tls connection init failed: invalid peer certificate: UnknownIssuer";
        assert!(is_untrusted_certificate(untrusted));
        assert!(network(untrusted).contains("isn't trusted"));
        assert!(friendly(PassError::Network(
            "sign in: this server doesn't support password sign-in (update Passyble Server, or use a pairing link)".into()
        ))
        .contains("too old"));
        assert!(friendly(PassError::CertificateChanged("x".into())).contains("changed"));
        assert_eq!(
            friendly(PassError::InvalidInput("enter the server address".into())),
            "Enter the server address."
        );
        assert!(friendly(PassError::Network("sync: HTTP 500".into())).contains("Try again"));
        assert!(friendly(PassError::InvalidInput(
            "2fa_required: two-factor sign-in is on; enter the code".into()
        ))
        .starts_with("Enter the 6-digit code"));
        let wrong = friendly(PassError::InvalidInput(
            "2fa_invalid: wrong or already used code".into(),
        ));
        assert!(wrong.contains("wrong or was already used"), "{wrong}");
        assert!(!wrong.contains("2fa_"));
        assert_eq!(
            friendly(PassError::Network("upload: storage quota reached".into())),
            "Your Passyble Server storage is full. Ask the server admin to raise the limit, or delete old items/versions."
        );
        assert_eq!(
            friendly(PassError::Network(
                "upload: storage quota reached: 80 MB of 100 MB used.".into()
            )),
            "Your Passyble Server storage is full: 80 MB of 100 MB used. Ask the server admin to raise the limit, or delete old items/versions."
        );
        assert!(friendly(PassError::Network(
            "upload: your Google storage is full; free up space and try again".into()
        ))
        .starts_with("Your Google storage is full."));
        assert_eq!(
            friendly(PassError::Network(
                "check: Google Drive isn't available right now. Try again later".into()
            )),
            "Google Drive isn't available right now. Try again later."
        );
        assert_eq!(
            friendly(PassError::Network(
                "check: https://www.googleapis.com/drive/v3/files/x: Dns Failed: no such host"
                    .into()
            )),
            "Can't reach www.googleapis.com. Check the address and your internet connection, then try again."
        );
    }

    /// Words that only a developer understands, which no message for the user may contain.
    const TECHNICAL: &[&str] = &[
        "HTTP",
        "os error",
        "0x8",
        "ureq",
        "serde",
        "Connection Failed",
        "UnknownIssuer",
        "docs/",
        "this build",
        "OAuth",
        "pass-server",
        "Access is denied",
    ];

    fn assert_plain(text: &str) {
        for word in TECHNICAL {
            assert!(!text.contains(word), "{text:?} contains {word:?}");
        }
    }

    #[test]
    fn unknown_network_errors_never_show_their_text() {
        for raw in [
            "sync: https://h/x: Status code 418: I'm a teapot",
            "upload: unexpected serde error at line 1 column 2",
            "sign in: Access is denied. (os error 5)",
        ] {
            let text = friendly(PassError::Network(raw.into()));
            assert_plain(&text);
            assert!(!text.contains("teapot"), "{text}");
        }
    }

    #[test]
    fn core_network_texts_lose_their_action_label() {
        assert_eq!(
            friendly(PassError::Network(
                "upload: the server is busy. Try again in a few minutes".into()
            )),
            "The server is busy. Try again in a few minutes."
        );
        let untrusted =
            "sign-in: this device doesn't trust the server's certificate (it may be self-signed)";
        assert!(is_untrusted_certificate(untrusted));
        assert!(network(untrusted).contains("isn't trusted"));
        assert_eq!(
            friendly(PassError::Network(
                "connect: can't connect to h.example:8443. Check your internet connection and the server address, then try again".into()
            )),
            "Can't reach h.example:8443. Check the address and your internet connection, then try again."
        );
    }

    #[test]
    fn vault_file_errors_say_what_to_check() {
        let text = friendly(PassError::Corrupt(
            "vault file: The process cannot access the file because it is being used by another process. (os error 32)".into(),
        ));
        assert_plain(&text);
        assert!(text.contains("no other program is using it"), "{text}");
        assert_eq!(
            friendly(PassError::Corrupt(
                "this vault was made by a newer version of Passyble. Update Passyble to open it"
                    .into()
            )),
            "This vault was made by a newer version of Passyble. Update Passyble to open it."
        );
    }
}
