//! The main window's own title bar (ui/titlebar.js) and how its window is framed.
//!
//! * Windows: no system frame; the window draws its own bar. Dragging and double-clicking the bar is Tauri's
//!   (`data-tauri-drag-region`), and so is resizing at the edges. The shadow gives the window its 1 px border and, on
//!   Windows 11, its rounded corners.
//! * macOS: an overlay title bar with a hidden title: the traffic lights stay, centred in the window's own 44 px bar.
//! * Linux: the system's title bar stays; the window's bar is just its first row.
//!
//! Snap layouts (Windows 11): the system shows them when the pointer rests on a Maximize button it finds by asking the
//! window (`WM_NCHITTEST` answering `HTMAXBUTTON`). The webview covers the window and answers for it, so Windows never
//! asks. Instead, the bar's Maximize asks for them after the pointer rests on it ([`window_snap_layouts`]): Passyble
//! presses Win+Z, unless the user turned the hover off in Settings → System → Multitasking.

use tauri::WebviewWindowBuilder;

#[cfg(target_os = "macos")]
const BAR_HEIGHT: f64 = 44.0;
#[cfg(target_os = "macos")]
const TRAFFIC_LIGHT_HEIGHT: f64 = 16.0;

pub fn frame<'a, R: tauri::Runtime, M: tauri::Manager<R>>(
    label: &str,
    builder: WebviewWindowBuilder<'a, R, M>,
) -> WebviewWindowBuilder<'a, R, M> {
    if label != "main" {
        return builder;
    }
    #[cfg(windows)]
    let builder = builder.decorations(false).shadow(true);
    #[cfg(target_os = "macos")]
    let builder = builder
        .title_bar_style(tauri::TitleBarStyle::Overlay)
        .hidden_title(true)
        .traffic_light_position(tauri::LogicalPosition::new(
            16.0,
            (BAR_HEIGHT - TRAFFIC_LIGHT_HEIGHT) / 2.0,
        ));
    builder
}

/// The pointer rests on the bar's Maximize (Windows 11): its snap layouts, as over a system
/// Maximize. Nothing elsewhere, nor when the window isn't in front, a key or mouse button is held
/// or the user turned the hover off.
#[tauri::command]
pub fn window_snap_layouts(window: tauri::WebviewWindow) {
    #[cfg(windows)]
    win::snap_layouts(&window);
    #[cfg(not(windows))]
    let _ = window;
}

#[cfg(windows)]
mod win {
    use windows::Win32::UI::Input::KeyboardAndMouse::{
        GetAsyncKeyState, SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT,
        KEYBD_EVENT_FLAGS, KEYEVENTF_KEYUP, VIRTUAL_KEY, VK_CONTROL, VK_LBUTTON, VK_LWIN,
        VK_MBUTTON, VK_MENU, VK_RBUTTON, VK_RWIN, VK_SHIFT, VK_Z,
    };
    use windows::Win32::UI::WindowsAndMessaging::GetForegroundWindow;

    /// The first Windows 11 build: Windows 10 has no snap layouts (Win+Z does nothing there).
    const WINDOWS_11: u32 = 22000;

    pub fn snap_layouts(window: &tauri::WebviewWindow) {
        let Ok(hwnd) = window.hwnd() else {
            return;
        };
        let foreground = unsafe { GetForegroundWindow() };
        if foreground.0 as isize != hwnd.0 as isize || held() || !windows_11() || !hover_on() {
            return;
        }
        let key = |vk: VIRTUAL_KEY, flags: KEYBD_EVENT_FLAGS| INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: vk,
                    wScan: 0,
                    dwFlags: flags,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        };
        let none = KEYBD_EVENT_FLAGS(0);
        let inputs = [
            key(VK_LWIN, none),
            key(VK_Z, none),
            key(VK_Z, KEYEVENTF_KEYUP),
            key(VK_LWIN, KEYEVENTF_KEYUP),
        ];
        let sent = unsafe { SendInput(&inputs, std::mem::size_of::<INPUT>() as i32) };
        if sent as usize != inputs.len() {
            crate::applog::plog!("snap layouts: Windows took {sent} of {} keys", inputs.len());
        }
    }

    /// A modifier or a mouse button is down: Win+Z would become another shortcut, or the user is
    /// dragging.
    fn held() -> bool {
        [VK_CONTROL, VK_MENU, VK_SHIFT, VK_LWIN, VK_RWIN, VK_LBUTTON, VK_RBUTTON, VK_MBUTTON]
            .iter()
            .any(|vk| (unsafe { GetAsyncKeyState(vk.0 as i32) } as u16) & 0x8000 != 0)
    }

    fn windows_11() -> bool {
        use winreg::enums::HKEY_LOCAL_MACHINE;
        winreg::RegKey::predef(HKEY_LOCAL_MACHINE)
            .open_subkey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion")
            .and_then(|key| key.get_value::<String, _>("CurrentBuildNumber"))
            .ok()
            .and_then(|build| build.parse::<u32>().ok())
            .is_some_and(|build| build >= WINDOWS_11)
    }

    /// Settings → System → Multitasking → "Show snap layouts when I hover over a window's maximize
    /// button" (on unless turned off).
    fn hover_on() -> bool {
        use winreg::enums::HKEY_CURRENT_USER;
        winreg::RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced")
            .and_then(|key| key.get_value::<u32, _>("EnableSnapAssistFlyout"))
            .map_or(true, |on| on != 0)
    }
}
