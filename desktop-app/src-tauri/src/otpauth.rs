//! `otpauth://` links opened from outside: a scanner app, a web page, another app (the URL protocol,
//! `otpauth_handler.rs`). `Pass.exe "otpauth://..."` starts Passyble, or a second launch hands its arguments to the
//! running instance.
//!
//! The link is untrusted input from any web page, and it carries a secret:
//!
//! * [`Inbox`] holds it in memory only, for [`LINK_TTL`]. The window gets what the confirmation shows
//!   ([`confirmation`]) and answers with the id of what it showed, so a newer link can't be slipped under an open
//!   dialog. Never logged or written to disk.
//! * [`pass_core::otpauth_parse_link`] validates it on arrival.
//! * Nothing happens without the user: the window unlocks if needed (no automatic Windows Hello), shows the
//!   details and adds only on `otpauth_commit`.
//!
//! A link Windows started Passyble with also stays in the process' command line: [`scrub_command_line`] wipes it
//! once read.

use std::sync::Arc;
use std::time::{Duration, Instant};

use pass_core::{otpauth_matches, otpauth_parse_link, OtpauthLink};
use serde_json::{json, Value};
use tauri::{AppHandle, Emitter, Manager};
use zeroize::{Zeroize, Zeroizing};

use crate::commands::pass_err;
use crate::i18n::tr;
use crate::popups;
use crate::state::{lock, AppState};

type Res<T> = Result<T, String>;
type AppState_<'a> = tauri::State<'a, Arc<AppState>>;

const SCHEME: &str = "otpauth:";

const LINK_TTL: Duration = Duration::from_secs(10 * 60);

/// The link a launch carries: the first argument after the program (`Pass.exe "%1"`). Everything after it belongs
/// to the link: an unencoded `"` makes more arguments of it, and the single-instance plugin splits what it hands
/// over on `|`, which a link may contain. The strict parser decides, and no part is read as an option
/// ([`crate::startup::tray_only`] isn't asked for such a launch). `otpauth-migration:` is another scheme.
pub fn link_argument<S: AsRef<str>>(args: &[S]) -> Option<Zeroizing<String>> {
    let first = args.get(1)?.as_ref();
    if !first
        .get(..SCHEME.len())
        .is_some_and(|s| s.eq_ignore_ascii_case(SCHEME))
    {
        return None;
    }
    let parts: Vec<&str> = args[1..].iter().map(AsRef::as_ref).collect();
    Some(Zeroizing::new(parts.join("|")))
}

/// A link arrived: it waits in the [`Inbox`], the main window comes up and asks for it (no automatic Windows Hello).
pub fn open(app: &AppHandle, link: &str) {
    let Some(state) = app.try_state::<Arc<AppState>>() else {
        return;
    };
    lock(&state.otpauth).accept(link, Instant::now());
    let _ = app.emit_to("main", "otpauth-requested", ());
    popups::show_main(app);
}

struct Held(OtpauthLink);

impl Drop for Held {
    fn drop(&mut self) {
        self.0.uri.zeroize();
    }
}

enum Waiting {
    Link {
        id: u64,
        at: Instant,
        link: Held,
    },
    Rejected(String),
}

#[derive(Default)]
pub struct Inbox {
    last_id: u64,
    waiting: Option<Waiting>,
}

impl Inbox {
    fn accept(&mut self, link: &str, now: Instant) {
        self.waiting = Some(match otpauth_parse_link(link.to_string()) {
            Ok(link) => {
                self.last_id += 1;
                Waiting::Link {
                    id: self.last_id,
                    at: now,
                    link: Held(link),
                }
            }
            Err(e) => Waiting::Rejected(pass_err(e)),
        });
    }

    fn drop_expired(&mut self, now: Instant) {
        if let Some(Waiting::Link { at, .. }) = &self.waiting {
            if now.saturating_duration_since(*at) > LINK_TTL {
                self.waiting = None;
            }
        }
    }

    /// What the window shows next: the confirmation data, or `{ rejected }` once. Never the secret.
    fn pending(&mut self, now: Instant) -> Option<Value> {
        self.drop_expired(now);
        if let Some(Waiting::Link { id, link, .. }) = &self.waiting {
            return Some(confirmation(*id, &link.0));
        }
        match self.waiting.take()? {
            Waiting::Rejected(message) => Some(json!({ "rejected": message })),
            Waiting::Link { .. } => None,
        }
    }

    fn link(&mut self, id: u64, now: Instant) -> Res<&OtpauthLink> {
        self.drop_expired(now);
        match &self.waiting {
            Some(Waiting::Link {
                id: waiting, link, ..
            }) if *waiting == id => Ok(&link.0),
            _ => Err(tr!("otpauth.expired")),
        }
    }

    fn finish(&mut self, id: u64) {
        if matches!(&self.waiting, Some(Waiting::Link { id: waiting, .. }) if *waiting == id) {
            self.waiting = None;
        }
    }
}

/// What the confirmation shows. Issuer and account come from the link: the window shows them as plain text.
fn confirmation(id: u64, link: &OtpauthLink) -> Value {
    json!({
        "id": id,
        "issuer": link.issuer,
        "account": link.account,
        "algorithm": link.algorithm.uri_name(),
        "digits": link.digits,
        "period": link.period,
    })
}

#[tauri::command]
pub fn otpauth_pending(state: AppState_<'_>) -> Option<Value> {
    lock(&state.otpauth).pending(Instant::now())
}

#[tauri::command]
pub fn otpauth_review(state: AppState_<'_>, id: u64) -> Res<Value> {
    let vault = state.vault()?;
    let (issuer, account) = {
        let mut inbox = lock(&state.otpauth);
        let link = inbox.link(id, Instant::now())?;
        (link.issuer.clone(), link.account.clone())
    };
    let matches: Vec<Value> = otpauth_matches(issuer, account, vault.summaries())
        .into_iter()
        .map(|m| {
            json!({
                "id": m.id,
                "title": m.title,
                "username": m.username,
                "has_totp": m.has_totp,
                "account_matches": m.account_matches,
                "suggested": m.suggested,
            })
        })
        .collect();
    let settings = state.settings();
    Ok(json!({
        "vault_name": settings.active().map(|v| v.name.clone()),
        "matches": matches,
    }))
}

/// The user confirmed link `id`: adds it to the login `target`, or a new login. `replace`: they chose to replace an existing 2FA code.
#[tauri::command]
pub fn otpauth_commit(
    state: AppState_<'_>,
    id: u64,
    target: Option<String>,
    replace: bool,
) -> Res<Value> {
    let vault = state.vault()?;
    let link = Held(lock(&state.otpauth).link(id, Instant::now())?.clone());
    let fallback_title = tr!("otpauth.default_title");
    let item = vault
        .add_otpauth_link(link.0.clone(), target, replace, fallback_title)
        .map_err(pass_err)?;
    state.require_agent()?.save().map_err(pass_err)?;
    lock(&state.otpauth).finish(id);
    Ok(json!({ "id": item.id, "title": item.title }))
}

#[tauri::command]
pub fn otpauth_cancel(state: AppState_<'_>, id: u64) {
    lock(&state.otpauth).finish(id);
}

/// Wipes a link from this process' command line. Windows keeps that text for the life of the
/// process, and any program of the user can read it (Task Manager's "Command line" column).
#[cfg(windows)]
pub fn scrub_command_line() {
    use windows::Win32::System::Environment::GetCommandLineW;
    // SAFETY: the pointer is the process' own NUL-terminated, writable command line, valid for its
    // whole life; nothing else writes it, and this runs once, at start-up on the main thread.
    unsafe {
        let line = GetCommandLineW();
        if !line.is_null() {
            let len = line.as_wide().len();
            scrub_link(std::slice::from_raw_parts_mut(line.0.cast_mut(), len));
        }
    }
}

/// Linux: the same for `/proc/<pid>/cmdline`, which other users can read by default. pass-linux overwrites the
/// argv area from the `otpauth:` argument on. Same-user tracing is left to Yama's ptrace_scope, as for every other
/// secret in memory.
#[cfg(target_os = "linux")]
pub fn scrub_command_line() {
    pass_linux::process::scrub_command_line(SCHEME);
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn scrub_command_line() {}

#[cfg_attr(not(windows), allow(dead_code))]
fn scrub_link(line: &mut [u16]) {
    let scheme: Vec<u16> = SCHEME.encode_utf16().collect();
    let found = line.windows(scheme.len()).position(|w| {
        w.iter().zip(&scheme).all(|(a, b)| {
            char::from_u32(u32::from(*a))
                .is_some_and(|c| c.to_ascii_lowercase() as u32 == u32::from(*b))
        })
    });
    if let Some(mut start) = found {
        if start > 0 && line[start - 1] == u16::from(b'"') {
            start -= 1;
        }
        line[start..].fill(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LINK: &str = "otpauth://totp/Demo:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Demo";

    fn accepted(link: &str) -> (Inbox, Instant) {
        let now = Instant::now();
        let mut inbox = Inbox::default();
        inbox.accept(link, now);
        (inbox, now)
    }

    #[test]
    fn a_link_launch_is_the_first_argument() {
        assert_eq!(
            link_argument(&["Pass.exe", LINK])
                .as_deref()
                .map(String::as_str),
            Some(LINK)
        );
        assert!(link_argument(&["Pass.exe", "OTPAUTH://totp/x"]).is_some());
        assert!(link_argument(&["Pass.exe"]).is_none());
        assert!(link_argument::<&str>(&[]).is_none());
        assert!(link_argument(&["Pass.exe", "--background"]).is_none());
        assert!(link_argument(&["Pass.exe", "pass+server://h/x"]).is_none());
        // Not this scheme, and not a link anywhere else on the command line.
        assert!(link_argument(&["Pass.exe", "otpauth-migration://offline?data=x"]).is_none());
        assert!(link_argument(&["Pass.exe", "--background", LINK]).is_none());
        assert!(link_argument(&["Pass.exe", "otpé"]).is_none());
    }

    #[test]
    fn the_second_instance_gets_a_link_with_a_bar_back_whole() {
        // The single-instance plugin joins the arguments with `|` and splits on it.
        let link = "otpauth://totp/A|B:alice?secret=JBSWY3DPEHPK3PXP";
        let argv: Vec<&str> = format!("Pass.exe|{link}").leak().split('|').collect();
        assert_eq!(argv.len(), 3);
        assert_eq!(
            link_argument(&argv).as_deref().map(String::as_str),
            Some(link)
        );
    }

    #[test]
    fn options_after_a_link_are_part_of_it_and_it_is_refused() {
        // `otpauth://...secret=X" --background`: a quote that wasn't encoded, in the command line.
        let argv = [
            "Pass.exe",
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP",
            "--background",
        ];
        let link = link_argument(&argv).unwrap();
        let (mut inbox, now) = accepted(&link);
        assert!(inbox.pending(now).unwrap().get("rejected").is_some());
    }

    #[test]
    fn the_confirmation_shows_the_details_and_never_the_secret() {
        let (mut inbox, now) = accepted(LINK);
        let shown = inbox.pending(now).unwrap();
        assert_eq!(shown["issuer"], "Demo");
        assert_eq!(shown["account"], "alice@example.com");
        assert_eq!(shown["algorithm"], "SHA1");
        assert_eq!(shown["digits"], 6);
        assert_eq!(shown["period"], 30);
        let text = shown.to_string();
        assert!(!text.contains("JBSWY3DPEHPK3PXP"), "{text}");
        assert!(!text.contains("otpauth"), "{text}");
        // It keeps waiting until the user answers.
        assert_eq!(inbox.pending(now).unwrap(), shown);
    }

    #[test]
    fn labels_reach_the_window_as_the_text_they_are() {
        let (mut inbox, now) =
            accepted("otpauth://totp/%3Cimg%20src%3Dx%3E:%E2%80%AEbob?secret=JBSWY3DPEHPK3PXP");
        let shown = inbox.pending(now).unwrap();
        assert_eq!(shown["issuer"], "<img src=x>");
        assert_eq!(shown["account"], "bob");
    }

    #[test]
    fn a_bad_link_is_a_plain_message_once() {
        for bad in [
            "otpauth://totp/Demo?secret=not-base-32!",
            "otpauth://hotp/Demo?secret=JBSWY3DPEHPK3PXP&counter=1",
            "otpauth://totp/Demo",
            "otpauth:nonsense",
        ] {
            let (mut inbox, now) = accepted(bad);
            let shown = inbox.pending(now).unwrap();
            let message = shown["rejected"].as_str().unwrap();
            assert!(!message.is_empty(), "{bad}");
            assert!(!message.contains("not-base-32"), "{message}");
            assert_eq!(inbox.pending(now), None, "{bad}");
        }
        let (mut inbox, now) = accepted(&format!(
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&x={}",
            "a".repeat(5000)
        ));
        assert!(inbox.pending(now).unwrap().get("rejected").is_some());
    }

    #[test]
    fn a_newer_link_replaces_the_one_on_screen_and_the_old_answer_counts_for_nothing() {
        let (mut inbox, now) = accepted(LINK);
        let first = inbox.pending(now).unwrap()["id"].as_u64().unwrap();
        inbox.accept("otpauth://totp/Other:mallory?secret=GEZDGNBVGY3TQOJQ", now);
        let shown = inbox.pending(now).unwrap();
        let second = shown["id"].as_u64().unwrap();
        assert_ne!(first, second);
        assert_eq!(shown["issuer"], "Other");
        assert!(inbox.link(first, now).is_err());
        inbox.finish(first);
        assert_eq!(
            inbox.link(second, now).unwrap().issuer.as_deref(),
            Some("Other")
        );
    }

    #[test]
    fn cancel_leaves_nothing() {
        let (mut inbox, now) = accepted(LINK);
        let id = inbox.pending(now).unwrap()["id"].as_u64().unwrap();
        inbox.finish(id);
        assert_eq!(inbox.pending(now), None);
        assert!(inbox.link(id, now).is_err());
    }

    #[test]
    fn a_link_nobody_answers_goes_away() {
        let (mut inbox, now) = accepted(LINK);
        let id = inbox.pending(now).unwrap()["id"].as_u64().unwrap();
        let later = now + LINK_TTL + Duration::from_secs(1);
        assert!(inbox.link(id, now + LINK_TTL).is_ok());
        assert!(inbox.link(id, later).is_err());
        assert_eq!(inbox.pending(later), None);
    }

    fn scrubbed(line: &str) -> String {
        let mut wide: Vec<u16> = line.encode_utf16().collect();
        scrub_link(&mut wide);
        let end = wide.iter().position(|c| *c == 0).unwrap_or(wide.len());
        String::from_utf16(&wide[..end]).unwrap()
    }

    #[test]
    fn the_command_line_keeps_nothing_of_the_link() {
        assert_eq!(
            scrubbed(&format!(r#""C:\Passyble\Pass.exe" "{LINK}""#)),
            r#""C:\Passyble\Pass.exe" "#
        );
        assert_eq!(scrubbed("Pass.exe OTPAUTH://totp/x?secret=A"), "Pass.exe ");
        assert_eq!(scrubbed("Pass.exe --background"), "Pass.exe --background");
    }
}
