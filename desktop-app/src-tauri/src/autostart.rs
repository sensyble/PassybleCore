//! "Start with Windows" (Settings → Startup & updates): the `Pass` value under
//! `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, starting `Pass.exe --background` (tray
//! only). The registry value is the setting; the uninstaller deletes it. macOS uses a LaunchAgent
//! instead (see [`set`]).

#[cfg(windows)]
const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
#[cfg(windows)]
const VALUE: &str = "Pass";

#[cfg(windows)]
pub fn enabled() -> bool {
    use winreg::enums::HKEY_CURRENT_USER;
    winreg::RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey(RUN_KEY)
        .and_then(|k| k.get_value::<String, _>(VALUE))
        .is_ok_and(|v| !v.trim().is_empty())
}

#[cfg(windows)]
pub fn set(on: bool) -> Result<(), String> {
    use winreg::enums::{HKEY_CURRENT_USER, KEY_SET_VALUE};
    let hkcu = winreg::RegKey::predef(HKEY_CURRENT_USER);
    if on {
        let failed = |e: std::io::Error| {
            crate::errors::logged(
                crate::i18n::tr!("errors.autostart_on_failed"),
                "start with Windows",
                e,
            )
        };
        let exe = std::env::current_exe().map_err(failed)?;
        let (key, _) = hkcu.create_subkey(RUN_KEY).map_err(failed)?;
        key.set_value(VALUE, &format!("\"{}\" --background", exe.display()))
            .map_err(failed)
    } else {
        match hkcu.open_subkey_with_flags(RUN_KEY, KEY_SET_VALUE) {
            Ok(key) => match key.delete_value(VALUE) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(crate::errors::logged(
                    crate::i18n::tr!("errors.autostart_off_failed"),
                    "start with Windows",
                    e,
                )),
                _ => Ok(()),
            },
            Err(_) => Ok(()),
        }
    }
}

/// macOS: "Open at login" is the LaunchAgent `~/Library/LaunchAgents/com.sensyble.pass.plist`
/// (`pass_macos::login_item`), starting this executable with `--background` (menu bar only).
#[cfg(target_os = "macos")]
pub fn enabled() -> bool {
    pass_macos::login_item::home_dir().is_some_and(|home| pass_macos::login_item::enabled(&home))
}

#[cfg(target_os = "macos")]
pub fn set(on: bool) -> Result<(), String> {
    let failed = |e: String| {
        let message = if on {
            crate::i18n::tr!("errors.autostart_on_failed")
        } else {
            crate::i18n::tr!("errors.autostart_off_failed")
        };
        crate::errors::logged(message, "open at login", e)
    };
    let home = pass_macos::login_item::home_dir().ok_or_else(|| failed("no home folder".into()))?;
    let exe = std::env::current_exe().map_err(|e| failed(e.to_string()))?;
    pass_macos::login_item::set(&home, &exe, on).map_err(|e| failed(e.to_string()))
}

/// At start: an existing login item points at this executable again (the app may have moved).
#[cfg(target_os = "macos")]
pub fn refresh() {
    let (Some(home), Ok(exe)) = (pass_macos::login_item::home_dir(), std::env::current_exe())
    else {
        return;
    };
    // A translocated copy's path changes with every start; keep the agent as it is.
    if pass_macos::apps::is_translocated(&exe) {
        return;
    }
    if let Err(e) = pass_macos::login_item::refresh(&home, &exe) {
        crate::applog::plog!("refreshing the login item: {e}");
    }
}

/// Linux: "Start at login" is the XDG autostart entry `~/.config/autostart/com.sensyble.pass.desktop`
/// (`pass_linux::login_item`), starting this executable (an AppImage: the `.AppImage` file) with
/// `--background` (tray only).
#[cfg(target_os = "linux")]
pub fn enabled() -> bool {
    pass_linux::login_item::config_dir().is_some_and(|dir| pass_linux::login_item::enabled(&dir))
}

#[cfg(target_os = "linux")]
pub fn set(on: bool) -> Result<(), String> {
    let failed = |e: String| {
        let message = if on {
            crate::i18n::tr!("errors.autostart_on_failed")
        } else {
            crate::i18n::tr!("errors.autostart_off_failed")
        };
        crate::errors::logged(message, "start at login", e)
    };
    let dir = pass_linux::login_item::config_dir().ok_or_else(|| failed("no home folder".into()))?;
    let launch =
        pass_linux::login_item::launch_path().ok_or_else(|| failed("no executable path".into()))?;
    pass_linux::login_item::set(&dir, &launch, on).map_err(|e| failed(e.to_string()))
}

/// At start: an existing autostart entry points at this executable again (the AppImage may have
/// moved).
#[cfg(target_os = "linux")]
pub fn refresh() {
    let (Some(dir), Some(launch)) = (
        pass_linux::login_item::config_dir(),
        pass_linux::login_item::launch_path(),
    ) else {
        return;
    };
    if let Err(e) = pass_linux::login_item::refresh(&dir, &launch) {
        crate::applog::plog!("refreshing the autostart entry: {e}");
    }
}

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
pub fn enabled() -> bool {
    false
}

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
pub fn set(_on: bool) -> Result<(), String> {
    Err(crate::i18n::tr!("errors.autostart_windows_only"))
}
