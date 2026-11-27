//! Global keyboard shortcuts (Settings → Keyboard shortcuts). Each action is registered on its own with
//! the global shortcut plugin, so changing one never touches the others.
//!
//! | Action | Default | On a Mac |
//! |---|---|---|
//! | Quick Access: search every unlocked vault, copy (`quick_access.rs`) | `Ctrl+Shift+Space` | `Cmd+Shift+Space` |
//! | Scan a QR code on screen for a 2FA code (`screen_qr.rs`, Windows) | `Ctrl+Alt+Shift+Q` | the same |
//! | Auto-type (`autotype.rs`, not on Linux) | `Ctrl+Alt+P` (`Settings::hotkey`) | `Ctrl+Cmd+P` |
//! | Show Passyble, Lock now, Sync now, Generate password and copy, New secure note | none | none |
//! A Mac uses Cmd where Windows uses Ctrl, except where macOS has the key: the QR scan keeps
//! Control+Option+Shift+Q (Cmd+Option+Shift+Q logs out at once) and auto-type takes Control+Cmd+P
//! (Cmd+Option+P is Finder's Show Path Bar). Files a Mac wrote with the Windows defaults move once
//! ([`Settings::migrate_defaults`]).
//!
//! The auto-type shortcut stays in `Settings::hotkey`, the others in `Settings::shortcuts` by action id.
//! A missing action has its default; `""` means the user cleared it.
//!
//! A shortcut needs Ctrl, Alt or Win (Shift alone would take a capital letter from every app), and two
//! actions can't share one. Windows refuses a shortcut another app registered first: that action keeps
//! no shortcut and Settings shows why ([`error`]).

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use serde::Deserialize;
use serde_json::{json, Value};
use tauri::{AppHandle, Manager};
use tauri_plugin_global_shortcut::{GlobalShortcutExt, Modifiers, Shortcut, ShortcutState};

use crate::i18n::tr;
use crate::settings::{default_hotkey, Settings, DEFAULT_HOTKEY};
use crate::state::{lock, AppState};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Action {
    QuickAccess,
    ScanQr,
    AutoType,
    ShowApp,
    Lock,
    SyncNow,
    GeneratePassword,
    NewNote,
}

impl Action {
    pub const ALL: [Action; 8] = [
        Action::QuickAccess,
        Action::ScanQr,
        Action::AutoType,
        Action::ShowApp,
        Action::Lock,
        Action::SyncNow,
        Action::GeneratePassword,
        Action::NewNote,
    ];

    pub fn id(self) -> &'static str {
        match self {
            Action::QuickAccess => "quick_access",
            Action::ScanQr => "scan_qr",
            Action::AutoType => "auto_type",
            Action::ShowApp => "show_app",
            Action::Lock => "lock",
            Action::SyncNow => "sync_now",
            Action::GeneratePassword => "generate_password",
            Action::NewNote => "new_note",
        }
    }

    pub fn from_id(id: &str) -> Option<Action> {
        Action::ALL.into_iter().find(|a| a.id() == id)
    }

    pub fn default_keys(self) -> Option<&'static str> {
        self.default_keys_on(cfg!(target_os = "macos"))
    }

    /// The QR scan takes all three modifiers: Ctrl+Alt+Shift+Q is used by no common Windows app and
    /// types nothing on AltGr keyboards; on a Mac, Control+Option+Shift+Q is free while Cmd+Shift+Q logs out.
    pub fn default_keys_on(self, mac: bool) -> Option<&'static str> {
        match self {
            Action::QuickAccess if mac => Some("Cmd+Shift+Space"),
            Action::QuickAccess => Some("Ctrl+Shift+Space"),
            Action::ScanQr => Some("Ctrl+Alt+Shift+Q"),
            Action::AutoType => Some(default_hotkey(mac)),
            _ => None,
        }
    }

    pub fn label(self) -> String {
        match self {
            Action::QuickAccess => tr!("shortcuts.quick_access"),
            Action::ScanQr => tr!("shortcuts.scan_qr"),
            Action::AutoType => tr!("shortcuts.auto_type"),
            Action::ShowApp => tr!("shortcuts.show_app"),
            Action::Lock => tr!("shortcuts.lock"),
            Action::SyncNow => tr!("shortcuts.sync_now"),
            Action::GeneratePassword => tr!("shortcuts.generate_password"),
            Action::NewNote => tr!("shortcuts.new_note"),
        }
    }

    /// Whether this copy can do it: reading the screen is Windows only, and Linux has no auto-type.
    pub fn supported(self) -> bool {
        match self {
            Action::ScanQr => crate::screen_qr::SUPPORTED,
            Action::AutoType => !cfg!(target_os = "linux"),
            _ => true,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Choice {
    Default,
    Off,
    Keys(String),
}

pub fn keys(settings: &Settings, action: Action) -> Option<String> {
    let stored = match action {
        Action::AutoType => Some(settings.hotkey.as_str()),
        _ => settings.shortcuts.get(action.id()).map(String::as_str),
    };
    match stored {
        Some(keys) => Some(keys.trim())
            .filter(|k| !k.is_empty())
            .map(str::to_string),
        None => action.default_keys().map(str::to_string),
    }
}

pub fn store(settings: &mut Settings, action: Action, choice: &Choice) {
    if action == Action::AutoType {
        settings.hotkey = match choice {
            Choice::Default => DEFAULT_HOTKEY.to_string(),
            Choice::Off => String::new(),
            Choice::Keys(keys) => keys.trim().to_string(),
        };
        return;
    }
    let id = action.id().to_string();
    match choice {
        Choice::Default => {
            settings.shortcuts.remove(&id);
        }
        Choice::Off => {
            settings.shortcuts.insert(id, String::new());
        }
        Choice::Keys(keys) => {
            settings.shortcuts.insert(id, keys.trim().to_string());
        }
    }
}

pub fn parse(keys: &str) -> Result<Shortcut, String> {
    let keys = keys.trim();
    let shortcut: Shortcut = keys.parse().map_err(|e| {
        crate::errors::logged(tr!("errors.hotkey_invalid", hotkey = keys), "shortcut", e)
    })?;
    let modifier = Modifiers::CONTROL | Modifiers::ALT | Modifiers::SUPER;
    if !shortcut.mods.intersects(modifier) {
        return Err(tr!("errors.shortcut_needs_modifier", hotkey = keys));
    }
    Ok(shortcut)
}

/// Another action that already has `shortcut` (actions this copy can't do don't count).
pub fn conflict(settings: &Settings, action: Action, shortcut: &Shortcut) -> Option<Action> {
    Action::ALL.into_iter().find(|other| {
        *other != action
            && other.supported()
            && keys(settings, *other)
                .and_then(|k| k.parse::<Shortcut>().ok())
                .is_some_and(|s| s.id() == shortcut.id())
    })
}

/// Checks `choice` for `action`: the shortcut it gives (`None`: none), or why it can't be used.
pub fn validate(
    settings: &Settings,
    action: Action,
    choice: &Choice,
) -> Result<Option<Shortcut>, String> {
    let mut next = settings.clone();
    store(&mut next, action, choice);
    let Some(keys) = keys(&next, action) else {
        return Ok(None);
    };
    let shortcut = parse(&keys)?;
    if let Some(other) = conflict(&next, action, &shortcut) {
        return Err(tr!(
            "errors.shortcut_taken_here",
            hotkey = keys,
            action = other.label()
        ));
    }
    Ok(Some(shortcut))
}

#[derive(Default)]
struct Registry {
    registered: BTreeMap<Action, Shortcut>,
    errors: BTreeMap<Action, String>,
}

static REGISTRY: Mutex<Option<Registry>> = Mutex::new(None);
/// Held while shortcuts are registered or let go of, so they never interleave. Never taken on the main thread.
static CHANGE: Mutex<()> = Mutex::new(());

fn with_registry<T>(f: impl FnOnce(&mut Registry) -> T) -> T {
    let mut guard = lock(&REGISTRY);
    f(guard.get_or_insert_with(Registry::default))
}

pub fn error(action: Action) -> Option<String> {
    with_registry(|r| r.errors.get(&action).cloned())
}

fn register_one(
    app: &AppHandle,
    action: Action,
    shortcut: Shortcut,
    keys: &str,
) -> Result<(), String> {
    app.global_shortcut()
        .on_shortcut(shortcut, move |app, _shortcut, event| {
            if event.state == ShortcutState::Pressed {
                run(app, action);
            }
        })
        .map_err(|e| {
            crate::errors::logged(tr!("errors.hotkey_register", hotkey = keys), "shortcut", e)
        })
}

fn unregister_one(app: &AppHandle, shortcut: Shortcut) {
    if let Err(e) = app.global_shortcut().unregister(shortcut) {
        crate::applog::plog!("shortcut: unregister failed: {e}");
    }
}

/// While Settings records a shortcut, Passyble's own are let go of so pressing one reaches the window.
static PAUSED: AtomicBool = AtomicBool::new(false);
/// Which pause is current, so the safety timer of an earlier one doesn't end a later one.
static PAUSE_GENERATION: AtomicU64 = AtomicU64::new(0);
/// A pause the window never ended (it crashed, or was closed mid-recording) ends by itself.
const PAUSE_LIMIT: Duration = Duration::from_secs(60);

fn pause(app: &AppHandle) {
    let _changing = lock(&CHANGE);
    if PAUSED.swap(true, Ordering::SeqCst) {
        return;
    }
    let generation = PAUSE_GENERATION.fetch_add(1, Ordering::SeqCst) + 1;
    for shortcut in with_registry(|r| r.registered.values().copied().collect::<Vec<_>>()) {
        unregister_one(app, shortcut);
    }
    let app = app.clone();
    let _ = std::thread::Builder::new()
        .name("pass-shortcut-pause".into())
        .spawn(move || {
            std::thread::sleep(PAUSE_LIMIT);
            if PAUSE_GENERATION.load(Ordering::SeqCst) == generation {
                resume(&app);
            }
        });
}

fn resume(app: &AppHandle) {
    let _changing = lock(&CHANGE);
    if !PAUSED.swap(false, Ordering::SeqCst) {
        return;
    }
    PAUSE_GENERATION.fetch_add(1, Ordering::SeqCst);
    let registered = with_registry(|r| r.registered.clone());
    for (action, shortcut) in registered {
        if let Err(e) = register_one(app, action, shortcut, &shortcut.to_string()) {
            // Another app took it while Settings was recording.
            with_registry(|r| {
                r.registered.remove(&action);
                r.errors.insert(action, e);
            });
        }
    }
}

/// The recorder got (`on`) or lost the focus. Off the main thread (registering waits for it).
#[tauri::command]
pub async fn shortcuts_recording(app: AppHandle, on: bool) {
    let _ = tauri::async_runtime::spawn_blocking(move || {
        if on {
            pause(&app);
        } else {
            resume(&app);
        }
    })
    .await;
}

/// At start-up: every action's shortcut. One that can't be registered is noted and the others still work.
pub fn register_all(app: &AppHandle, settings: &Settings) {
    for action in Action::ALL {
        if !action.supported() {
            continue;
        }
        let Some(keys) = keys(settings, action) else {
            continue;
        };
        let result = parse(&keys).and_then(|shortcut| {
            if let Some(other) = conflict(settings, action, &shortcut).filter(|o| *o < action) {
                // A hand-edited file: the first action keeps it.
                return Err(tr!(
                    "errors.shortcut_taken_here",
                    hotkey = keys,
                    action = other.label()
                ));
            }
            register_one(app, action, shortcut, &keys).map(|()| shortcut)
        });
        with_registry(|r| match result {
            Ok(shortcut) => {
                r.registered.insert(action, shortcut);
                r.errors.remove(&action);
            }
            Err(e) => {
                crate::applog::plog!("shortcut {}: {e}", action.id());
                r.errors.insert(action, e);
            }
        });
    }
}

/// Applies the user's choice at once: the old shortcut goes, the new one is registered and saved; if it
/// can't be registered (another app has it), the old one is restored and nothing is saved.
pub fn apply(app: &AppHandle, action: Action, choice: Choice) -> Result<(), String> {
    let state = app.state::<std::sync::Arc<AppState>>().inner().clone();
    let settings = state.settings();
    let wanted = validate(&settings, action, &choice)?;
    let changing = lock(&CHANGE);
    if action.supported() {
        let old = with_registry(|r| r.registered.get(&action).copied());
        // Paused (Settings is recording): the new shortcut is still tried so one another app holds is
        // refused at once, then let go of until the recording ends.
        let paused = PAUSED.load(Ordering::SeqCst);
        if old.map(|s| s.id()) != wanted.map(|s| s.id()) {
            if let Some(old) = old {
                if !paused {
                    unregister_one(app, old);
                }
                with_registry(|r| r.registered.remove(&action));
            }
            if let Some(new) = wanted {
                let mut next = settings.clone();
                store(&mut next, action, &choice);
                let keys = keys(&next, action).unwrap_or_default();
                if let Err(e) = register_one(app, action, new, &keys) {
                    if let Some(old) = old {
                        if paused || register_one(app, action, old, "").is_ok() {
                            with_registry(|r| r.registered.insert(action, old));
                        }
                    }
                    return Err(e);
                }
                if paused {
                    unregister_one(app, new);
                }
                with_registry(|r| r.registered.insert(action, new));
            }
        }
        with_registry(|r| r.errors.remove(&action));
    }
    drop(changing);
    state.update_settings(|s| {
        store(s, action, &choice);
        Ok(())
    })
}

/// Runs `action` on the main thread: anything that may wait (an unlock, the screen capture) runs on its own thread.
fn run(app: &AppHandle, action: Action) {
    match action {
        Action::QuickAccess => crate::quick_access::open(app),
        Action::ScanQr => crate::screen_qr::on_shortcut(app),
        Action::AutoType => crate::autotype::on_hotkey(app),
        Action::ShowApp => crate::popups::open_main(app),
        Action::Lock => {
            crate::popups::hide(app, "quickaccess");
            crate::tray::lock_now(app);
        }
        Action::SyncNow => crate::tray::sync_now(app),
        Action::GeneratePassword => crate::tray::generate_and_copy(app),
        Action::NewNote => {
            let _ = tauri::Emitter::emit_to(app, "main", "new-item", json!({ "kind": "note" }));
            crate::popups::open_main(app);
        }
    }
}

pub fn keys_json(settings: &Settings) -> Value {
    Action::ALL
        .into_iter()
        .filter(|a| a.supported())
        .map(|a| (a.id().to_string(), json!(keys(settings, a))))
        .collect::<serde_json::Map<String, Value>>()
        .into()
}

fn action_json(settings: &Settings, action: Action) -> Value {
    json!({
        "id": action.id(),
        "keys": keys(settings, action),
        "default": action.default_keys(),
        "supported": action.supported(),
        "error": error(action),
    })
}

#[tauri::command]
pub fn shortcuts_state(app: AppHandle) -> Value {
    let settings = app.state::<std::sync::Arc<AppState>>().settings();
    json!({
        "actions": Action::ALL.into_iter().map(|a| action_json(&settings, a)).collect::<Vec<_>>(),
    })
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub struct ShortcutChange {
    action: String,
    keys: Option<String>,
    clear: bool,
    reset: bool,
}

#[tauri::command]
pub async fn set_shortcut(app: AppHandle, change: ShortcutChange) -> Result<Value, String> {
    let action = Action::from_id(&change.action).ok_or_else(|| tr!("errors.shortcut_unknown"))?;
    let choice = if change.reset {
        Choice::Default
    } else if change.clear {
        Choice::Off
    } else {
        Choice::Keys(
            change
                .keys
                .map(|k| k.trim().to_string())
                .filter(|k| !k.is_empty())
                .ok_or_else(|| tr!("errors.shortcut_unknown"))?,
        )
    };
    let handle = app.clone();
    tauri::async_runtime::spawn_blocking(move || apply(&handle, action, choice))
        .await
        .map_err(|e| crate::errors::internal("background task", e))??;
    Ok(shortcuts_state(app))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(json: &str) -> Settings {
        Settings::from_json(json.as_bytes(), |_| false)
            .expect("valid")
            .0
    }

    #[test]
    fn a_file_without_shortcuts_has_the_defaults() {
        let s = settings("{}");
        for action in [Action::QuickAccess, Action::ScanQr, Action::AutoType] {
            assert_eq!(keys(&s, action).as_deref(), action.default_keys(), "{action:?}");
        }
        for action in [
            Action::ShowApp,
            Action::Lock,
            Action::SyncNow,
            Action::GeneratePassword,
            Action::NewNote,
        ] {
            assert_eq!(keys(&s, action), None, "{action:?}");
        }
        for action in Action::ALL {
            if let Some(default) = action.default_keys() {
                let shortcut = parse(default).unwrap();
                assert_eq!(conflict(&s, action, &shortcut), None, "{action:?}");
            }
        }
    }

    #[test]
    fn the_old_hotkey_stays_the_auto_type_shortcut() {
        let s = settings(r#"{"hotkey":"Ctrl+Shift+L"}"#);
        assert_eq!(keys(&s, Action::AutoType).as_deref(), Some("Ctrl+Shift+L"));
        assert_eq!(
            keys(&s, Action::QuickAccess).as_deref(),
            Action::QuickAccess.default_keys()
        );
    }

    #[test]
    fn windows_keeps_its_defaults_and_a_mac_uses_cmd() {
        assert_eq!(Action::QuickAccess.default_keys_on(false), Some("Ctrl+Shift+Space"));
        assert_eq!(Action::ScanQr.default_keys_on(false), Some("Ctrl+Alt+Shift+Q"));
        assert_eq!(Action::AutoType.default_keys_on(false), Some("Ctrl+Alt+P"));
        assert_eq!(Action::QuickAccess.default_keys_on(true), Some("Cmd+Shift+Space"));
        assert_eq!(Action::AutoType.default_keys_on(true), Some("Ctrl+Cmd+P"));
        let taken = ["Cmd+Space", "Cmd+Shift+Q", "Cmd+Alt+Shift+Q", "Ctrl+Cmd+Q", "Cmd+Alt+P", "Ctrl+Cmd+Space"]
            .map(|k| parse(k).unwrap().id());
        for mac in [false, true] {
            let defaults: Vec<Shortcut> = Action::ALL
                .into_iter()
                .filter_map(|a| a.default_keys_on(mac))
                .map(|k| parse(k).unwrap())
                .collect();
            for (i, a) in defaults.iter().enumerate() {
                assert!(defaults[i + 1..].iter().all(|b| b.id() != a.id()), "{a} twice");
                if mac {
                    assert!(!taken.contains(&a.id()), "{a} is the system's");
                }
            }
        }
        let mac = cfg!(target_os = "macos");
        for action in Action::ALL {
            assert_eq!(action.default_keys(), action.default_keys_on(mac), "{action:?}");
        }
        assert_eq!(Settings::default().hotkey, default_hotkey(mac));
    }

    #[test]
    fn choices_are_stored_and_read_back() {
        let mut s = settings("{}");
        store(
            &mut s,
            Action::QuickAccess,
            &Choice::Keys(" Ctrl+Alt+K ".into()),
        );
        store(&mut s, Action::Lock, &Choice::Keys("Ctrl+Alt+L".into()));
        store(&mut s, Action::ScanQr, &Choice::Off);
        store(&mut s, Action::AutoType, &Choice::Off);
        assert_eq!(keys(&s, Action::QuickAccess).as_deref(), Some("Ctrl+Alt+K"));
        assert_eq!(keys(&s, Action::Lock).as_deref(), Some("Ctrl+Alt+L"));
        assert_eq!(keys(&s, Action::ScanQr), None);
        assert_eq!(keys(&s, Action::AutoType), None);
        assert_eq!(s.hotkey, "");
        let back = settings(&s.to_json().to_string());
        assert_eq!(back, s);
        assert_eq!(keys(&back, Action::ScanQr), None);
        assert_eq!(keys(&back, Action::AutoType), None);
        let mut s = back;
        store(&mut s, Action::ScanQr, &Choice::Default);
        store(&mut s, Action::AutoType, &Choice::Default);
        store(&mut s, Action::Lock, &Choice::Default);
        assert_eq!(
            keys(&s, Action::ScanQr).as_deref(),
            Some("Ctrl+Alt+Shift+Q")
        );
        assert_eq!(keys(&s, Action::AutoType).as_deref(), Some(DEFAULT_HOTKEY));
        assert_eq!(keys(&s, Action::Lock), None);
        assert!(!s.shortcuts.contains_key("lock"));
    }

    #[test]
    fn a_shortcut_needs_ctrl_alt_or_win() {
        assert!(parse("Ctrl+Alt+P").is_ok());
        assert!(parse("Alt+F4").is_ok());
        assert!(parse("Super+Space").is_ok());
        assert!(parse("ctrl+shift+space").is_ok());
        let modifiers = if cfg!(target_os = "macos") {
            "Ctrl, Option or Cmd"
        } else if cfg!(target_os = "linux") {
            "Ctrl, Alt or Super"
        } else {
            "Ctrl, Alt or Win"
        };
        for bad in ["P", "Shift+P", "F5", "Shift+Space"] {
            let e = parse(bad).unwrap_err();
            assert!(e.contains(modifiers), "{bad}: {e}");
        }
        for unreadable in ["", "Ctrl+", "Ctrl+Nope", "Ctrl+P+Q"] {
            assert!(parse(unreadable).is_err(), "{unreadable}");
        }
    }

    #[test]
    fn two_actions_cannot_share_a_shortcut() {
        let s = settings("{}");
        let auto_type = DEFAULT_HOTKEY;
        let quick_access = Action::QuickAccess.default_keys().unwrap();
        // Auto-type's default for Quick Access, in another spelling (free on Linux: no auto-type).
        let taken = validate(&s, Action::QuickAccess, &Choice::Keys(auto_type.to_lowercase()));
        if Action::AutoType.supported() {
            let e = taken.unwrap_err();
            assert!(e.contains("Auto-type"), "{e}");
        } else {
            assert!(taken.is_ok());
        }
        let e = validate(&s, Action::Lock, &Choice::Keys(quick_access.into())).unwrap_err();
        assert!(e.contains("Quick Access"), "{e}");
        assert!(validate(
            &s,
            Action::QuickAccess,
            &Choice::Keys(quick_access.into())
        )
        .unwrap()
        .is_some());
        assert!(
            validate(&s, Action::Lock, &Choice::Keys("Ctrl+Alt+L".into()))
                .unwrap()
                .is_some()
        );
        assert!(validate(&s, Action::QuickAccess, &Choice::Off)
            .unwrap()
            .is_none());
        let mut s = s;
        store(&mut s, Action::AutoType, &Choice::Off);
        assert!(validate(&s, Action::QuickAccess, &Choice::Keys(auto_type.into())).is_ok());
        // Reset to a default another action took meanwhile: refused too.
        store(
            &mut s,
            Action::Lock,
            &Choice::Keys("Ctrl+Alt+Shift+Q".into()),
        );
        store(&mut s, Action::ScanQr, &Choice::Off);
        let e = validate(&s, Action::ScanQr, &Choice::Default);
        if Action::ScanQr.supported() {
            assert!(e.unwrap_err().contains("Lock"));
        }
    }

    #[test]
    fn action_ids_round_trip() {
        for action in Action::ALL {
            assert_eq!(Action::from_id(action.id()), Some(action));
        }
        assert_eq!(Action::from_id("nope"), None);
    }
}
