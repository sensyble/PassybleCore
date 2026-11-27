//! The macOS menu bar. Windows and Linux have none: the main window draws its own bar there (titlebar.rs).
//!
//! Without an Edit menu, Cmd+C, Cmd+V, Cmd+X, Cmd+A and Cmd+Z do nothing in a web view's text fields. The menu's
//! commands do what the window's keys do: New Item, Search, Settings, Close Window, Help and Keyboard Shortcuts go to
//! the main window as `menu-command` (ui/main.js); Lock and Lock Completely go there while the window is on screen (so
//! an unsaved edit asks first), else they are the tray's; Quit is the tray's; the rest are macOS's own.
//!
//! The page sees a key before the menu does and cancels the keys it runs, so a key acts once. Close Window on another
//! window closes it as its close button does (main.rs hides it). Texts are the catalogs' (`menu.*`), relabelled after
//! Settings → Language ([`relabel`]).

use serde_json::json;
use tauri::menu::{
    AboutMetadata, IsMenuItem, Menu, MenuItem, PredefinedMenuItem, Submenu, HELP_SUBMENU_ID,
    WINDOW_SUBMENU_ID,
};
use tauri::{AppHandle, Emitter, Manager, Runtime};

use crate::i18n::tr;
use crate::{popups, tray};

const EVENT: &str = "menu-command";

/// One of the menu's own commands: its id (`menu.` plus the window's command name; menu events reach every listener,
/// the tray's too, so the ids must differ from the tray's), the catalog key of its text, and its key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Command {
    id: &'static str,
    label: &'static str,
    keys: Option<&'static str>,
}

const SETTINGS: Command = Command {
    id: "menu.settings",
    label: "menu.settings",
    keys: Some("Cmd+,"),
};
const QUIT: Command = Command {
    id: "menu.quit",
    label: "tray.quit",
    keys: Some("Cmd+Q"),
};
const NEW: Command = Command {
    id: "menu.new",
    label: "menu.new_item",
    keys: Some("Cmd+N"),
};
const LOCK: Command = Command {
    id: "menu.lock",
    label: "tray.lock",
    keys: Some("Cmd+L"),
};
const LOCK_FULL: Command = Command {
    id: "menu.lock_full",
    label: "tray.lock_completely",
    keys: Some("Cmd+Shift+L"),
};
const CLOSE: Command = Command {
    id: "menu.close",
    label: "menu.close_window",
    keys: Some("Cmd+W"),
};
const SEARCH: Command = Command {
    id: "menu.search",
    label: "common.search",
    keys: Some("Cmd+F"),
};
const HELP: Command = Command {
    id: "menu.help",
    label: "menu.help_item",
    keys: None,
};
const SHORTCUTS: Command = Command {
    id: "menu.shortcuts",
    label: "help.keys_title",
    keys: None,
};

const COMMANDS: [Command; 9] = [
    SETTINGS, QUIT, NEW, LOCK, LOCK_FULL, CLOSE, SEARCH, HELP, SHORTCUTS,
];

#[derive(Debug, PartialEq, Eq)]
enum Route {
    Window(&'static str),
    Lock,
    LockFull,
    Quit,
    /// Closes the window in front (the main window decides itself: `Window("close")`).
    CloseOther,
}

/// What menu item `id` does; `main_in_front`: the main window has the focus, `main_on_screen`: it
/// is shown and not minimized. None for an id that isn't the menu's.
fn route(id: &str, main_in_front: bool, main_on_screen: bool) -> Option<Route> {
    let command = COMMANDS.iter().find(|c| c.id == id)?;
    let name = command.id.strip_prefix("menu.")?;
    Some(match *command {
        QUIT => Route::Quit,
        CLOSE if !main_in_front => Route::CloseOther,
        LOCK if !main_on_screen => Route::Lock,
        LOCK_FULL if !main_on_screen => Route::LockFull,
        _ => Route::Window(name),
    })
}

fn item<R: Runtime>(app: &AppHandle<R>, command: Command) -> tauri::Result<MenuItem<R>> {
    MenuItem::with_id(app, command.id, tr!(command.label), true, command.keys)
}

fn build<R: Runtime>(app: &AppHandle<R>) -> tauri::Result<Menu<R>> {
    let info = app.package_info();
    let about = AboutMetadata {
        name: Some(info.name.clone()),
        version: Some(info.version.to_string()),
        copyright: app.config().bundle.copyright.clone(),
        ..Default::default()
    };
    let separator = || PredefinedMenuItem::separator(app);

    let app_menu = Submenu::with_items(
        app,
        &info.name,
        true,
        &[
            &PredefinedMenuItem::about(app, Some(tr!("menu.about").as_str()), Some(about))?,
            &separator()?,
            &item(app, SETTINGS)?,
            &separator()?,
            &PredefinedMenuItem::services(app, Some(tr!("menu.services").as_str()))?,
            &separator()?,
            &PredefinedMenuItem::hide(app, Some(tr!("menu.hide").as_str()))?,
            &PredefinedMenuItem::hide_others(app, Some(tr!("menu.hide_others").as_str()))?,
            &PredefinedMenuItem::show_all(app, Some(tr!("menu.show_all").as_str()))?,
            &separator()?,
            &item(app, QUIT)?,
        ],
    )?;
    let file = Submenu::with_items(
        app,
        tr!("menu.file"),
        true,
        &[
            &item(app, NEW)?,
            &separator()?,
            &item(app, LOCK)?,
            &item(app, LOCK_FULL)?,
            &separator()?,
            &item(app, CLOSE)?,
        ],
    )?;
    let edit = Submenu::with_items(
        app,
        tr!("menu.edit"),
        true,
        &[
            &PredefinedMenuItem::undo(app, Some(tr!("menu.undo").as_str()))?,
            &PredefinedMenuItem::redo(app, Some(tr!("menu.redo").as_str()))?,
            &separator()?,
            &PredefinedMenuItem::cut(app, Some(tr!("menu.cut").as_str()))?,
            &PredefinedMenuItem::copy(app, Some(tr!("menu.copy").as_str()))?,
            &PredefinedMenuItem::paste(app, Some(tr!("menu.paste").as_str()))?,
            &PredefinedMenuItem::select_all(app, Some(tr!("menu.select_all").as_str()))?,
        ],
    )?;
    let view = Submenu::with_items(
        app,
        tr!("menu.view"),
        true,
        &[
            &item(app, SEARCH)?,
            &separator()?,
            &PredefinedMenuItem::fullscreen(app, Some(tr!("menu.full_screen").as_str()))?,
        ],
    )?;
    // These ids make them macOS's Window menu (its list of windows) and Help menu (its search).
    let window = Submenu::with_id_and_items(
        app,
        WINDOW_SUBMENU_ID,
        tr!("menu.window"),
        true,
        &[
            &PredefinedMenuItem::minimize(app, Some(tr!("menu.minimize").as_str()))?,
            &PredefinedMenuItem::maximize(app, Some(tr!("menu.zoom").as_str()))?,
            &separator()?,
            &PredefinedMenuItem::bring_all_to_front(
                app,
                Some(tr!("menu.bring_all_to_front").as_str()),
            )?,
        ],
    )?;
    let help = Submenu::with_id_and_items(
        app,
        HELP_SUBMENU_ID,
        tr!("help.title"),
        true,
        &[&item(app, HELP)?, &item(app, SHORTCUTS)?],
    )?;
    let menus: [&dyn IsMenuItem<R>; 6] = [&app_menu, &file, &edit, &view, &window, &help];
    Menu::with_items(app, &menus)
}

pub fn install(app: &AppHandle) {
    if !cfg!(target_os = "macos") {
        return;
    }
    set(app);
    app.on_menu_event(|app, event| run(app, event.id().as_ref()));
}

pub fn relabel(app: &AppHandle) {
    if cfg!(target_os = "macos") {
        set(app);
    }
}

fn set(app: &AppHandle) {
    match build(app).and_then(|menu| app.set_menu(menu)) {
        Ok(_) => {}
        // macOS's own Edit keys then come from Tauri's default menu, kept until now.
        Err(e) => crate::applog::plog!("menu bar: {e}"),
    }
}

fn run(app: &AppHandle, id: &str) {
    let main = app.get_webview_window("main");
    let main_in_front = main
        .as_ref()
        .is_some_and(|w| w.is_focused().unwrap_or(false));
    match route(id, main_in_front, popups::main_on_screen(app)) {
        Some(Route::Window(command)) => {
            if !popups::main_on_screen(app) {
                popups::show_main(app);
            }
            let _ = app.emit_to("main", EVENT, json!({ "command": command }));
        }
        Some(Route::Lock) => tray::lock_now(app),
        Some(Route::LockFull) => tray::lock_and_forget_list(app),
        Some(Route::Quit) => tray::quit(app),
        Some(Route::CloseOther) => {
            let front = app
                .webview_windows()
                .into_values()
                .find(|w| w.is_focused().unwrap_or(false));
            if let Some(window) = front {
                let _ = window.close();
            }
        }
        None => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_command_has_its_own_id_a_text_and_a_mac_key() {
        let mut ids: Vec<&str> = COMMANDS.iter().map(|c| c.id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), COMMANDS.len(), "ids are unique");
        // The tray's ids (tray.rs) never collide: every menu event reaches its handler too.
        for tray_id in [
            "open",
            "teams",
            "lock",
            "lock_full",
            "generate",
            "sync",
            "breach_cancel",
            "quit",
        ] {
            assert!(!ids.contains(&tray_id), "{tray_id}");
        }
        // The other texts are literal `tr!` keys, which ui/test/i18n.test.mjs checks.
        for command in COMMANDS {
            assert!(command.id.starts_with("menu."), "{}", command.id);
            assert_ne!(
                tr!(command.label),
                command.label,
                "{} has a text",
                command.label
            );
            if let Some(keys) = command.keys {
                assert!(keys.starts_with("Cmd+"), "{}: {keys}", command.id);
            }
        }
    }

    /// The window's keys on a Mac (ui/views/app-keys.js, whose test reads these too) and the
    /// Mac's own Close Window and Quit.
    #[test]
    fn the_keys_are_the_windows_and_the_macs_own() {
        let keys = |command: Command| command.keys;
        assert_eq!(keys(NEW), Some("Cmd+N"));
        assert_eq!(keys(SEARCH), Some("Cmd+F"));
        assert_eq!(keys(SETTINGS), Some("Cmd+,"));
        assert_eq!(keys(LOCK), Some("Cmd+L"));
        assert_eq!(keys(LOCK_FULL), Some("Cmd+Shift+L"));
        assert_eq!(keys(CLOSE), Some("Cmd+W"));
        assert_eq!(keys(QUIT), Some("Cmd+Q"));
        assert_eq!(keys(HELP), None);
    }

    #[test]
    fn commands_go_where_their_keys_go() {
        let window = |name| Some(Route::Window(name));
        for (command, name) in [
            (NEW, "new"),
            (SEARCH, "search"),
            (SETTINGS, "settings"),
            (HELP, "help"),
            (SHORTCUTS, "shortcuts"),
        ] {
            assert_eq!(route(command.id, true, true), window(name));
            // Hidden: the window opens for it.
            assert_eq!(route(command.id, false, false), window(name));
        }
        // Lock asks the window while it is on screen (an unsaved edit), else locks at once.
        assert_eq!(route(LOCK.id, true, true), window("lock"));
        assert_eq!(route(LOCK.id, false, false), Some(Route::Lock));
        assert_eq!(route(LOCK_FULL.id, false, true), window("lock_full"));
        assert_eq!(route(LOCK_FULL.id, false, false), Some(Route::LockFull));
        // Close Window: the main window closes what is open in it; another window just closes.
        assert_eq!(route(CLOSE.id, true, true), window("close"));
        assert_eq!(route(CLOSE.id, false, true), Some(Route::CloseOther));
        assert_eq!(route(QUIT.id, true, true), Some(Route::Quit));
        // Not the menu's (the tray's, macOS's own items).
        assert_eq!(route("lock", true, true), None);
        assert_eq!(route("quit", true, true), None);
    }
}
