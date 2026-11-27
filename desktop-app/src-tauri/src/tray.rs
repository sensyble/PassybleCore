//! System tray: Open, Lock, Lock completely, Generate password (copies), Quit; while a breach check runs, its
//! progress and "Cancel breach check" (`health.rs`).
//!
//! Every ordinary lock is soft: it keeps the list of items on screen without secrets while "Keep list visible when
//! locked" is on (`LockKind::Soft`), and quitting, restarting and updating keep it on disk so the next start is
//! soft-locked. Only "Lock completely" drops the list too, also the copy on disk (`Agent::forget_kept_list`).

use std::sync::{Arc, Mutex};

use pass_agent::LockKind;
use pass_core::{generate_password, PasswordOptions};
use tauri::menu::{IsMenuItem, Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, Wry};

use crate::i18n::tr;
use crate::state::AppState;
use crate::{clipboard, popups};

const TRAY_ID: &str = "pass";

fn menu(app: &AppHandle) -> tauri::Result<Menu<Wry>> {
    let open = MenuItem::with_id(app, "open", tr!("tray.open"), true, None::<&str>)?;
    let lock = MenuItem::with_id(app, "lock", tr!("tray.lock"), true, None::<&str>)?;
    let lock_full = MenuItem::with_id(
        app,
        "lock_full",
        tr!("tray.lock_completely"),
        true,
        None::<&str>,
    )?;
    let generate = MenuItem::with_id(app, "generate", tr!("tray.generate"), true, None::<&str>)?;
    let sync = MenuItem::with_id(app, "sync", tr!("tray.sync_now"), true, None::<&str>)?;
    let quit_item = MenuItem::with_id(app, "quit", tr!("tray.quit"), true, None::<&str>)?;
    let separator = PredefinedMenuItem::separator(app)?;
    let breach_separator = PredefinedMenuItem::separator(app)?;
    // "Teams and Family" only for an account in a Team or Family or with a shared vault.
    let teams = if *TEAMS_VISIBLE.lock().unwrap_or_else(|e| e.into_inner()) {
        Some(MenuItem::with_id(
            app,
            "teams",
            tr!("tray.teams"),
            true,
            None::<&str>,
        )?)
    } else {
        None
    };
    // While a breach check runs: "Checking N of M passwords" (not clickable) and its Cancel.
    let breach = match crate::health::running_text() {
        Some(text) => {
            let progress = MenuItem::with_id(app, "breach_progress", text, false, None::<&str>)?;
            let cancel = MenuItem::with_id(
                app,
                "breach_cancel",
                tr!("tray.breach_cancel"),
                true,
                None::<&str>,
            )?;
            Some((progress, cancel))
        }
        None => None,
    };
    *BREACH_ITEM.lock().unwrap_or_else(|e| e.into_inner()) =
        breach.as_ref().map(|(p, _)| p.clone());
    let mut items: Vec<&dyn IsMenuItem<Wry>> = vec![&open];
    if let Some(teams) = &teams {
        items.push(teams);
    }
    items.extend([&lock as &dyn IsMenuItem<Wry>, &lock_full, &sync, &generate]);
    if let Some((progress, cancel)) = &breach {
        items.extend([&breach_separator as &dyn IsMenuItem<Wry>, progress, cancel]);
    }
    items.extend([&separator as &dyn IsMenuItem<Wry>, &quit_item]);
    Menu::with_items(app, &items)
}

static BREACH_ITEM: Mutex<Option<MenuItem<Wry>>> = Mutex::new(None);

/// The breach check moved on or ended (`None`): the menu gets or loses its progress line and "Cancel breach
/// check" when that changes, else only the line's text. Never waits (the main thread does it).
pub fn breach_progress(app: &AppHandle, text: Option<String>) {
    let handle = app.clone();
    let _ = app.run_on_main_thread(move || {
        let item = BREACH_ITEM
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        match (item, text) {
            (Some(item), Some(text)) => {
                let _ = item.set_text(text);
            }
            (None, None) => {}
            _ => relabel(&handle),
        }
    });
}

static TEAMS_VISIBLE: Mutex<bool> = Mutex::new(false);

pub fn teams_visible(app: &AppHandle, visible: bool) {
    let changed = {
        let mut v = TEAMS_VISIBLE.lock().unwrap_or_else(|e| e.into_inner());
        let changed = *v != visible;
        *v = visible;
        changed
    };
    if changed {
        let handle = app.clone();
        let _ = app.run_on_main_thread(move || relabel(&handle));
    }
}

/// A Teams and Family notification: the tray tooltip says it until the next lock change, and open windows toast it.
pub fn notify(app: &AppHandle, text: &str) {
    let _ = app.emit("toast", text);
    notice(app, text);
}

/// A notice in the tray tooltip until the next lock change.
pub fn notice(app: &AppHandle, text: &str) {
    let handle = app.clone();
    let text = text.to_string();
    let _ = app.run_on_main_thread(move || {
        if let Some(tray) = handle.tray_by_id(TRAY_ID) {
            let _ = tray.set_tooltip(Some(format!("Passyble: {text}")));
        }
    });
}

pub fn show_teams(app: &AppHandle, section: &str) {
    let _ = app.emit_to(
        "main",
        "show-teams",
        serde_json::json!({ "section": section }),
    );
    popups::open_main(app);
}

static LOCK_STATE: Mutex<(bool, bool)> = Mutex::new((true, false));

pub fn create(app: &AppHandle) -> tauri::Result<()> {
    let menu = menu(app)?;

    let mut builder = TrayIconBuilder::with_id(TRAY_ID)
        .tooltip(tooltip(true, false))
        .menu(&menu)
        // A menu bar item opens its menu on a click (macOS); the Windows tray icon opens the
        // window and keeps the menu for a right click.
        .show_menu_on_left_click(cfg!(target_os = "macos"))
        .on_menu_event(|app, event| match event.id().as_ref() {
            "open" => popups::open_main(app),
            "teams" => show_teams(app, ""),
            "lock" => lock_now(app),
            "lock_full" => lock_and_forget_list(app),
            "generate" => generate_and_copy(app),
            "sync" => sync_now(app),
            "breach_cancel" => crate::health::cancel(app),
            "quit" => quit(app),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                if cfg!(target_os = "macos") {
                    return;
                }
                popups::open_main(tray.app_handle());
            }
        });
    // macOS: the bare key as a template image, which the menu bar tints for light and dark
    // (pass-macos embeds it as raw RGBA). Elsewhere the app icon.
    #[cfg(target_os = "macos")]
    {
        let size = pass_macos::MENU_BAR_ICON_SIZE;
        let icon = tauri::image::Image::new(pass_macos::menu_bar_icon(), size, size);
        builder = builder.icon(icon).icon_as_template(true);
    }
    #[cfg(not(target_os = "macos"))]
    if let Some(icon) = app.default_window_icon() {
        builder = builder.icon(icon.clone());
    }
    builder.build(app)?;
    Ok(())
}

/// "Sync now" (tray or global shortcut): every open vault with sync, after an unlock if needed. Reports in the
/// windows, and in the tray tooltip while the main window isn't on screen.
pub fn sync_now(app: &AppHandle) {
    let app = app.clone();
    let _ = std::thread::Builder::new()
        .name("pass-sync-now".into())
        .spawn(move || {
            if crate::app_versions::blocked() {
                let _ = app.emit("toast", crate::read_only::refused_text());
                return;
            }
            let state = app.state::<Arc<AppState>>().inner().clone();
            let Some(agent) = state.agent() else {
                popups::show_main(&app);
                return;
            };
            if agent.is_locked() && !pass_agent::Ui::request_unlock(state.ui.as_ref()) {
                return;
            }
            let (report, _) = crate::background::sync_all(&app);
            let message = crate::background::report_text(&report);
            let _ = app.emit("toast", &message);
            if report.no_sync {
                let _ = app.emit_to(
                    "main",
                    "show-settings",
                    serde_json::json!({ "section": "sync" }),
                );
                popups::show_main(&app);
            } else if !popups::main_on_screen(&app) {
                notice(&app, &message);
            }
        });
}

/// "Generate password" (tray or global shortcut): a new password, copied and cleared after 45 s. The windows say
/// so, and the tray tooltip while the main window isn't on screen.
pub fn generate_and_copy(app: &AppHandle) {
    let message = match generate_password(PasswordOptions::default())
        .map(zeroize::Zeroizing::new)
        .map_err(|e| e.to_string())
        .and_then(|p| clipboard::copy_secret(&p))
    {
        Ok(()) => tr!("tray.generated_copied"),
        Err(e) => crate::errors::logged(tr!("tray.generate_failed"), "generate password", e),
    };
    let _ = app.emit("toast", &message);
    if !popups::main_on_screen(app) {
        notice(app, &message);
    }
}

pub(crate) fn tooltip(locked: bool, soft: bool) -> String {
    match (locked, soft) {
        (false, _) => tr!("tray.tooltip_unlocked"),
        (true, true) => tr!("tray.tooltip_locked_list"),
        (true, false) => tr!("tray.tooltip_locked"),
    }
}

/// Keeps the tray tooltip in step with the lock state. Never waits: the main thread sets it from the latest state,
/// so a lock right after an unlock still ends up right.
pub fn update(app: &AppHandle, locked: bool, soft: bool) {
    *LOCK_STATE.lock().unwrap_or_else(|e| e.into_inner()) = (locked, soft);
    let handle = app.clone();
    let _ = app.run_on_main_thread(move || {
        let (locked, soft) = *LOCK_STATE.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(tray) = handle.tray_by_id(TRAY_ID) {
            let _ = tray.set_tooltip(Some(tooltip(locked, soft)));
        }
    });
}

pub fn relabel(app: &AppHandle) {
    let (locked, soft) = *LOCK_STATE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(tray) = app.tray_by_id(TRAY_ID) {
        if let Ok(menu) = menu(app) {
            let _ = tray.set_menu(Some(menu));
        }
        let _ = tray.set_tooltip(Some(tooltip(locked, soft)));
    }
}

/// Saves and locks. Keeps the list without secrets while "Keep list visible when locked" is on. If the vault file
/// can't be written, the agent keeps the edits in a copy beside it that the next unlock merges in; only if even that
/// fails are they lost (logged and shown).
pub fn lock_now(app: &AppHandle) {
    lock_as(app, None);
}

/// A full lock: like [`lock_now`], and the list is dropped from memory too. Used before removing the active vault,
/// switching vaults, quitting, restarting and updating; the list kept on disk for the next start stays.
pub fn lock_completely(app: &AppHandle) {
    lock_as(app, Some(LockKind::Full));
}

/// "Lock completely" chosen by the user: [`lock_completely`], and the list kept on disk is deleted too, so nothing
/// shows until the next unlock, even after a restart.
pub fn lock_and_forget_list(app: &AppHandle) {
    lock_completely(app);
    if let Some(agent) = app.state::<Arc<AppState>>().agent() {
        agent.forget_kept_list();
    }
}

fn lock_as(app: &AppHandle, kind: Option<LockKind>) {
    if let Some(agent) = app.state::<Arc<AppState>>().agent() {
        let saved = match kind {
            Some(kind) => agent.save_and_lock_as(kind),
            None => agent.save_and_lock(),
        };
        if let Err(e) = saved {
            crate::applog::plog!("lock: the vault could not be saved: {e}");
            let _ = app.emit("toast", tr!("tray.lock_save_failed"));
        }
    }
}

pub fn quit(app: &AppHandle) {
    let state = app.state::<Arc<AppState>>();
    state.prompts.cancel_all(app);
    state.resolve_unlock_waiters(false);
    lock_completely(app);
    // The 45 s clear timer dies with the process: don't leave a copied secret behind.
    clipboard::clear_now();
    app.exit(0);
}

#[cfg(test)]
mod tests {
    use super::tooltip;

    #[test]
    fn tooltip_tells_the_lock_states_apart() {
        assert_eq!(tooltip(false, false), "Passyble (unlocked)");
        // `soft` only means something while locked.
        assert_eq!(tooltip(false, true), "Passyble (unlocked)");
        assert_eq!(tooltip(true, true), "Passyble (locked, list visible)");
        assert_eq!(tooltip(true, false), "Passyble (locked)");
    }
}
