//! Global hotkey auto-type for native desktop apps (KeePass-style), on Windows and macOS.
//!
//! Hotkey → foreground window (title + exe; on macOS the bundle ID) → `Agent::match_window`:
//! * exactly one login, pinned to the app or named in the window title: type `username ⇥ password ↵`, then show
//!   the TOTP popup if it has a 2FA secret;
//! * none, several, or one that only matched by a site name in the title (a chat mentioning "github" is not
//!   GitHub's sign-in): open the quick-pick; Enter types the selected login into the original window.
//!
//! Typing stops as soon as another window gets focus, and only goes to the window the hotkey was pressed in while
//! it still has the same title (after an unlock or the quick-pick the browser may have moved to another tab).
//!
//! The quick-pick also offers "Generate new password": [`type_generated`] saves a new login for the app, copies
//! the password and types it into the focused field (no Tab, no Enter: usually a sign-up form).
//!
//! On macOS typing needs the Accessibility permission and is refused while another app holds Secure Input; both
//! say so in a toast (`not_ready`).

use std::sync::Arc;
use std::thread;
use std::time::Duration;

use pass_agent::{Verification, WindowMatch};
use pass_core::{generate_password, Item, ItemKind, PasswordOptions};
use tauri::{AppHandle, Emitter, Manager};

use crate::clipboard;
use crate::i18n::tr;
use crate::platform::{self, Key, Target};
use crate::popups;
use crate::state::{lock, AppState, QuickPick};

pub fn on_hotkey(app: &AppHandle) {
    // Capture the target now, while it still has focus.
    let target = platform::foreground_window();
    let app = app.clone();
    let _ = thread::Builder::new()
        .name("pass-autotype".into())
        .spawn(move || run(&app, target));
}

fn run(app: &AppHandle, target: Option<Target>) {
    let state = app.state::<Arc<AppState>>().inner().clone();
    let Some(agent) = state.agent() else {
        popups::show_main(app);
        return;
    };
    // Read-only mode (update required): auto-type is a fill.
    if agent.update_required() {
        toast(app, &crate::read_only::refused_text());
        return;
    }
    if agent.is_locked() && !pass_agent::Ui::request_unlock(state.ui.as_ref()) {
        return;
    }
    let Some(target) = target else {
        // Pressed while Pass itself (or the desktop) had focus: nothing to type into.
        popups::show_main(app);
        return;
    };
    #[cfg(target_os = "macos")]
    if let Err(message) = platform::autotype_permission() {
        // Without it the window title can't be read either.
        toast(app, &message);
        return;
    }
    let matches = agent.match_window(&target.title, &target.exe);
    if matches.len() == 1 && matches[0].0 >= WindowMatch::Title {
        type_login(app, &target, &matches[0].1);
    } else {
        *lock(&state.quickpick) = Some(QuickPick {
            target,
            item_ids: matches.into_iter().map(|(_, i)| i.id).collect(),
        });
        crate::webview_memory::wake(app, "quickpick");
        let _ = app.emit_to("quickpick", "quickpick", ());
        popups::show_quickpick(app);
    }
}

/// Types the login into `target`; refuses if it can't be brought to the foreground, so a password never lands in
/// the wrong window. Windows Hello comes first when the fill policy requires it. Blocking.
pub fn type_login(app: &AppHandle, target: &Target, item: &Item) {
    if refused(app) {
        return;
    }
    let state = app.state::<Arc<AppState>>().inner().clone();
    let reason = tr!("autotype.reason_login", title = item.title);
    if state.ui.verify(&reason) == Verification::Refused {
        toast(app, &tr!("autotype.cancelled_hello"));
        return;
    }
    if !platform::window_unchanged(target, true) {
        toast(app, &tr!("autotype.cancelled_changed"));
        return;
    }
    if !platform::focus(target) {
        toast(app, &tr!("autotype.cancelled_focus"));
        return;
    }
    if let Some(message) = not_ready(target) {
        toast(app, &message);
        return;
    }
    platform::wait_modifiers_released();
    let typed = (item.username.is_empty()
        || platform::type_text(target, &item.username) && platform::press(target, Key::Tab))
        && platform::type_text(target, &item.password)
        && platform::press(target, Key::Enter);
    if !typed {
        toast(app, &tr!("autotype.stopped"));
        return;
    }
    // A use, for "most used first" (saved, never a reason to sync).
    if let Some(agent) = state.agent() {
        agent.record_use(&item.id);
    }
    if item.has_totp() {
        // Let the app move to its 2FA screen before the popup appears.
        thread::sleep(Duration::from_millis(300));
        state
            .ui
            .show_totp_popup_for(&item.id, &item.title, Some(target.clone()));
    }
}

/// "Generate new password": saves a generated password right away as a new login for the app (so it is never
/// lost), copies it (cleared after 45 s) and types it into the focused field of `target`, without Tab or Enter.
/// Typing is refused like [`type_login`]; the login and the copy stay either way. Blocking.
pub fn type_generated(app: &AppHandle, target: &Target) {
    if refused(app) {
        return;
    }
    let state = app.state::<Arc<AppState>>().inner().clone();
    let reason = tr!("autotype.reason_generate", app = app_label(target));
    if state.ui.verify(&reason) == Verification::Refused {
        toast(app, &tr!("autotype.cancelled_hello_short"));
        return;
    }
    let password = match generate_password(PasswordOptions::default()) {
        Ok(p) => zeroize::Zeroizing::new(p),
        Err(e) => {
            toast(
                app,
                &crate::errors::logged(tr!("tray.generate_failed"), "generate password", e),
            );
            return;
        }
    };
    let saved = save_generated(&state, target, &password);
    if saved.is_ok() {
        pass_agent::Ui::vault_changed(state.ui.as_ref());
    }
    let copied = clipboard::copy_secret(&password).is_ok();
    let mut blocked = None;
    let typed = platform::window_unchanged(target, true) && platform::focus(target) && {
        blocked = not_ready(target);
        blocked.is_none() && {
            platform::wait_modifiers_released();
            platform::type_text(target, &password)
        }
    };
    let message = generated_message(&saved, copied, typed);
    // Why it was not typed (no Accessibility permission, Secure Input), then what happened.
    toast(
        app,
        &blocked.map_or_else(|| message.clone(), |why| format!("{why} {message}")),
    );
}

/// macOS: why typing into `target` can't start now (no Accessibility permission, or Secure Input), as toast text.
fn not_ready(target: &Target) -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        platform::autotype_ready(target).err()
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = target;
        None
    }
}

fn save_generated(state: &AppState, target: &Target, password: &str) -> Result<String, String> {
    let agent = state.require_agent()?;
    let vault = state.vault()?;
    // A window without a title: the app's name (on macOS `exe` is the bundle ID).
    let title = if target.title.trim().is_empty() {
        app_label(target)
    } else {
        target.title.clone()
    };
    let saved = vault
        .upsert(generated_login(&title, &target.exe, password))
        .map_err(crate::errors::friendly)?;
    agent.save().map_err(crate::errors::friendly)?;
    Ok(saved.title)
}

/// The URL entry prefix that pins a login to an app: `windows:<exe>` or `macos:<bundle id>`.
pub(crate) const PIN_PREFIX: &str = if cfg!(target_os = "macos") {
    "macos:"
} else {
    "windows:"
};

pub(crate) fn pin_entry(exe: &str) -> String {
    format!("{PIN_PREFIX}{}", exe.trim())
}

/// The target app's name for messages (`putty` for `putty.exe`; on macOS the app's own name).
pub(crate) fn app_label(target: &Target) -> String {
    #[cfg(target_os = "macos")]
    if let Some(name) = platform::app_name(target) {
        return name;
    }
    app_name(&target.exe).to_string()
}

/// Browsers: their windows show any website, so a login is never pinned to the browser (the
/// extension saves website logins). Windows executables and macOS bundle IDs.
const BROWSERS: &[&str] = &[
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
    "brave.exe",
    "opera.exe",
    "vivaldi.exe",
    "chromium.exe",
    "iexplore.exe",
    "librewolf.exe",
    "waterfox.exe",
    "floorp.exe",
    "zen.exe",
    "arc.exe",
    "com.apple.Safari",
    "com.apple.SafariTechnologyPreview",
    "com.google.Chrome",
    "com.google.Chrome.beta",
    "com.google.Chrome.canary",
    "com.microsoft.edgemac",
    "com.microsoft.edgemac.Beta",
    "org.mozilla.firefox",
    "org.mozilla.firefoxdeveloperedition",
    "org.mozilla.nightly",
    "com.brave.Browser",
    "com.operasoftware.Opera",
    "com.vivaldi.Vivaldi",
    "org.chromium.Chromium",
    "company.thebrowser.Browser",
    "app.zen-browser.zen",
    "org.librewolf.librewolf",
    "net.waterfox.waterfox",
    "one.ablaze.floorp",
];

fn is_browser(exe: &str) -> bool {
    BROWSERS.iter().any(|b| b.eq_ignore_ascii_case(exe.trim()))
}

fn app_name(exe: &str) -> &str {
    let exe = exe.trim();
    match exe.len().checked_sub(4) {
        Some(n) if exe.is_char_boundary(n) && exe[n..].eq_ignore_ascii_case(".exe") => &exe[..n],
        _ => exe,
    }
}

/// Longest title a generated login gets from its window (window titles can be long).
const MAX_TITLE_CHARS: usize = 80;

/// The login "Generate new password" saves: titled after the window (or the app), pinned to the app with
/// [`pin_entry`] (not for browsers) so the next hotkey press finds it, no username.
pub(crate) fn generated_login(window_title: &str, exe: &str, password: &str) -> Item {
    let title = window_title.trim();
    let title = if title.is_empty() {
        app_name(exe).to_string()
    } else {
        title.chars().take(MAX_TITLE_CHARS).collect()
    };
    let urls = if exe.trim().is_empty() || is_browser(exe) {
        Vec::new()
    } else {
        vec![pin_entry(exe)]
    };
    Item {
        kind: ItemKind::Login,
        title: if title.is_empty() {
            tr!("editor.new_login")
        } else {
            title
        },
        password: password.to_string(),
        urls,
        notes: tr!("autotype.generated_notes"),
        ..Item::default()
    }
}

pub(crate) fn generated_message(
    saved: &Result<String, String>,
    copied: bool,
    typed: bool,
) -> String {
    let what = match (typed, copied) {
        (true, true) => tr!("autotype.typed_copied"),
        (true, false) => tr!("autotype.typed"),
        (false, true) => tr!("autotype.copied_not_typed"),
        (false, false) => tr!("autotype.not_typed_copied"),
    };
    match saved {
        Ok(title) => tr!("autotype.saved_as", title = title, what = what),
        // Not typed, copied or saved: one plain sentence ("couldn't …, but not saved" contradicts).
        Err(e) if !typed && !copied => tr!("autotype.nothing_done", error = e),
        Err(e) => tr!("autotype.not_saved", what = what, error = e),
    }
}

/// Types a single string (a TOTP code) into `target`. Its title may have changed (the app moved on to its 2FA
/// screen), but it must still be the same app's window.
pub fn type_into(app: &AppHandle, target: &Target, text: &str) -> bool {
    if refused(app) {
        return false;
    }
    if !platform::window_unchanged(target, false) || !platform::focus(target) {
        toast(app, &tr!("autotype.code_focus"));
        return false;
    }
    if let Some(message) = not_ready(target) {
        toast(app, &message);
        return false;
    }
    platform::wait_modifiers_released();
    if !platform::type_text(target, text) {
        toast(app, &tr!("autotype.stopped"));
        return false;
    }
    true
}

fn refused(app: &AppHandle) -> bool {
    let blocked = crate::app_versions::blocked();
    if blocked {
        toast(app, &crate::read_only::refused_text());
    }
    blocked
}

fn toast(app: &AppHandle, message: &str) {
    let _ = app.emit("toast", message);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_login_is_pinned_to_the_app() {
        let item = generated_login("  Create account – Contoso  ", "Contoso.exe", "pw");
        assert_eq!(item.kind, ItemKind::Login);
        assert_eq!(item.title, "Create account – Contoso");
        assert_eq!(item.urls, vec![format!("{PIN_PREFIX}Contoso.exe")]);
        assert_eq!(item.password, "pw");
        assert!(item.username.is_empty());
        assert!(item.id.is_empty());
        assert!(item.notes.contains("generator"));
    }

    #[test]
    fn untitled_window_uses_the_app_name() {
        assert_eq!(generated_login("", "putty.EXE", "pw").title, "putty");
        assert_eq!(generated_login(" ", "", "pw").title, "New login");
        assert!(generated_login("x", "", "pw").urls.is_empty());
    }

    #[test]
    fn long_titles_are_shortened() {
        let long = "é".repeat(200);
        assert_eq!(
            generated_login(&long, "a.exe", "pw").title.chars().count(),
            MAX_TITLE_CHARS
        );
    }

    #[test]
    fn browsers_are_never_pinned() {
        assert!(
            generated_login("Sign up - Google Chrome", "chrome.exe", "pw")
                .urls
                .is_empty()
        );
        assert!(generated_login("x", "MSEdge.exe", "pw").urls.is_empty());
        // macOS bundle IDs: exactly, in any case, never by prefix.
        assert!(generated_login("x", "com.apple.safari", "pw")
            .urls
            .is_empty());
        assert!(generated_login("x", "org.mozilla.firefox", "pw")
            .urls
            .is_empty());
        assert_eq!(
            generated_login("x", "com.apple.SafariFoo", "pw").urls,
            vec![format!("{PIN_PREFIX}com.apple.SafariFoo")]
        );
        assert!(!generated_login("x", "chromex.exe", "pw").urls.is_empty());
    }

    #[test]
    fn pins_name_the_app_for_this_os() {
        assert_eq!(pin_entry(" putty.exe "), format!("{PIN_PREFIX}putty.exe"));
        let expected = if cfg!(target_os = "macos") {
            "macos:"
        } else {
            "windows:"
        };
        assert_eq!(PIN_PREFIX, expected);
        assert!(pass_core::app_pin(&pin_entry("com.apple.Terminal")).is_some());
    }

    #[test]
    fn app_name_strips_exe() {
        assert_eq!(app_name("putty.exe"), "putty");
        assert_eq!(app_name("Tool.Exe "), "Tool");
        assert_eq!(app_name("exe"), "exe");
        assert_eq!(app_name("notes"), "notes");
        assert_eq!(app_name("ö.exe"), "ö");
    }

    #[test]
    fn messages_say_what_happened() {
        let saved: Result<String, String> = Ok("Contoso".into());
        assert_eq!(
            generated_message(&saved, true, true),
            "Saved to Passyble as \"Contoso\". Password typed and copied (clears in 45 s)."
        );
        assert!(generated_message(&saved, true, false).contains("copied"));
        let failed: Result<String, String> = Err("The vault is locked".into());
        let m = generated_message(&failed, false, true);
        assert!(m.starts_with("Password typed, but it was not saved"));
        assert!(m.ends_with("The vault is locked"));
        assert_eq!(
            generated_message(&failed, false, false),
            "Couldn't type, copy or save the new password: The vault is locked"
        );
    }
}
