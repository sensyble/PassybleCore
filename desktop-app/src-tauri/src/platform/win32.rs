//! Windows: maps the platform API onto the `pass-windows` crate (Win32 / WinRT calls). What stays here
//! needs the app itself: Tauri windows, localized error texts, the log, and running a Windows Hello
//! prompt in front of the right window ([`crate::hello::focus`]).

use std::thread;
use std::time::{Duration, Instant};

use pass_windows::hello::{self as win_hello, KeyError, WindowId};
use pass_windows::{dpapi, input, process, session, window};
use windows_core::RuntimeType;
use windows_future::{AsyncStatus, IAsyncOperation};

use super::{HelloKeyError, Key, Target};
use crate::hello::focus::{self, FocusAction, FocusWatch, TopWindow, WindowSource, DIALOG_CLASS};

pub fn foreground_window() -> Option<Target> {
    window::foreground().map(|w| Target {
        hwnd: w.hwnd,
        title: w.title,
        exe: w.exe,
    })
}

/// Whether `target` still is the window captured at the hotkey: the HWND exists, belongs to the same
/// executable (HWNDs are reused) and, with `same_title`, still shows the same title.
pub fn window_unchanged(target: &Target, same_title: bool) -> bool {
    window::unchanged(
        target.hwnd,
        &target.exe,
        same_title.then_some(target.title.as_str()),
    )
}

/// Brings `target` back to the foreground and confirms it is there, so a secret is never typed into
/// another window. Allowed because Pass just received the hotkey or owns the foreground window.
pub fn focus(target: &Target) -> bool {
    window::focus(target.hwnd)
}

/// The hotkey is still held when its handler runs; waits until Ctrl, Alt, Shift and Win are released.
pub fn wait_modifiers_released() {
    input::wait_modifiers_released()
}

pub fn type_text(target: &Target, text: &str) -> bool {
    input::type_text(target.hwnd, text)
}

pub fn press(target: &Target, key: Key) -> bool {
    input::press(
        target.hwnd,
        match key {
            Key::Tab => input::Key::Tab,
            Key::Enter => input::Key::Enter,
        },
    )
}

pub fn window_handle(window: &tauri::WebviewWindow) -> Option<isize> {
    window.hwnd().ok().map(|h| h.0 as isize)
}

/// The browser window a request from the extension came from, as owner of the Hello dialog: the
/// foreground window's root owner if visible, not Pass's own, and started by `client_pid` (the native
/// host; Chrome and Edge start it through `cmd.exe`, Firefox directly). `None` otherwise.
pub fn browser_window(client_pid: u32) -> Option<isize> {
    let (root, pid) = window::foreground_root()?;
    static KNOWN: std::sync::Mutex<super::HostBrowsers> =
        std::sync::Mutex::new(super::HostBrowsers(Vec::new()));
    let known = || KNOWN.lock().unwrap_or_else(|p| p.into_inner());
    if known().known(client_pid, pid) {
        return Some(root);
    }
    let parents: std::collections::HashMap<u32, u32> = process::all()
        .into_iter()
        .map(|(pid, parent, _)| (pid, parent))
        .collect();
    let started = super::started_by(&parents, client_pid, pid, super::BROWSER_PARENT_LEVELS);
    if started {
        known().remember(client_pid, pid);
    }
    started.then_some(root)
}

pub fn show_without_activation(window: &tauri::WebviewWindow) {
    match window_handle(window) {
        Some(raw) => window::show_without_activation(raw),
        None => {
            let _ = window.show();
        }
    }
}

/// Moves a window Pass just showed to the foreground, also while Pass is a background process (see
/// `pass_windows::window::force_foreground`).
pub fn bring_to_front(window: &tauri::WebviewWindow) {
    if let Some(raw) = window_handle(window) {
        window::force_foreground(raw, true);
    }
}

/// Hides a window shown with [`show_without_activation`]; both bypass tao, whose cached visibility
/// flag would make a later `hide()` a no-op.
pub fn hide_without_activation(window: &tauri::WebviewWindow) {
    match window_handle(window) {
        Some(raw) => window::hide(raw),
        None => {
            let _ = window.hide();
        }
    }
}

pub fn watch_session_lock(on_lock: Box<dyn Fn() + Send + Sync>) {
    session::watch_lock(on_lock)
}

pub fn dpapi_protect(data: &[u8]) -> Result<Vec<u8>, String> {
    dpapi::protect(data)
}

pub fn dpapi_unprotect(data: &[u8]) -> Result<Vec<u8>, String> {
    dpapi::unprotect(data)
}

/// Whether Windows Hello is set up. Blocks briefly; don't call on the UI thread.
pub fn hello_available() -> bool {
    win_hello::available()
}

struct Desktop;

impl WindowSource for Desktop {
    fn top_windows(&self) -> Vec<TopWindow> {
        window::of_class(DIALOG_CLASS)
            .into_iter()
            .map(|w| TopWindow {
                hwnd: w.hwnd,
                class: w.class,
                exe: w.exe,
                owner: w.owner,
                visible: w.visible,
            })
            .collect()
    }
}

enum PromptError {
    Cancelled,
    Failed(windows::core::Error),
}

impl From<windows::core::Error> for PromptError {
    fn from(e: windows::core::Error) -> Self {
        Self::Failed(e)
    }
}

/// Runs one Windows Hello operation in front of `owner`: keeps its dialog in the foreground
/// ([`FocusWatch`]), publishes where it stands ([`focus::status`]) and cancels on [`focus::cancel`].
/// Blocks; call from a background thread.
fn run_prompt<T: RuntimeType + 'static>(
    owner: Option<isize>,
    start: impl FnOnce(Option<WindowId>) -> windows::core::Result<IAsyncOperation<T>>,
) -> Result<T, PromptError> {
    let owner = owner.filter(|raw| window::is_window(*raw));
    let attempt = focus::begin(owner);
    if let Some(raw) = owner.filter(|raw| window::own_window(*raw)) {
        window::force_foreground(raw, true);
    }
    let window_id = owner.and_then(win_hello::window_id);
    let before = focus::hello_dialogs(&Desktop);
    let op = start(window_id)?;
    pass_agent::timing::mark("hello: dialog requested");
    // Wakes the loop the moment the operation completes, not at the next 50 ms tick.
    let (completed, done) = std::sync::mpsc::channel::<()>();
    let woken = op
        .SetCompleted(&windows_future::AsyncOperationCompletedHandler::new(
            move |_, _| {
                let _ = completed.send(());
                Ok(())
            },
        ))
        .is_ok();
    // A thread of its own keeps the dialog in front: `force_foreground` can take a few 20 ms sleeps,
    // which must not delay the answer.
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let follower = {
        let stop = stop.clone();
        let attempt = attempt.shared();
        let trace = pass_agent::timing::current();
        thread::Builder::new()
            .name("pass-hello-focus".into())
            .spawn(move || {
                let _entered = pass_agent::timing::enter(trace);
                follow_dialog(owner, &before, &attempt, &stop);
            })
    };
    if follower.is_err() {
        crate::applog::plog!("Windows Hello: no thread to bring the dialog to the front");
    }
    let finished = loop {
        let status = op.Status();
        if !matches!(status, Ok(AsyncStatus::Started)) {
            break status;
        }
        if attempt.cancelled() {
            stop.store(true, std::sync::atomic::Ordering::Relaxed);
            // Windows may leave its dialog up until the user closes it (checked on build 26300), so this
            // is only done on request.
            let _ = op.Cancel();
            return Err(PromptError::Cancelled);
        }
        if woken {
            let _ = done.recv_timeout(Duration::from_millis(50));
        } else {
            thread::sleep(Duration::from_millis(50));
        }
    };
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    pass_agent::timing::mark("hello: dialog answered");
    match finished? {
        AsyncStatus::Canceled => Err(PromptError::Cancelled),
        _ => Ok(op.GetResults()?),
    }
}

/// Keeps the Hello dialog of `attempt` in front and publishes where it stands, every 50 ms until `stop`.
fn follow_dialog(
    owner: Option<isize>,
    before: &[isize],
    attempt: &focus::Attempt,
    stop: &std::sync::atomic::AtomicBool,
) {
    let mut watch = FocusWatch::new(Instant::now());
    while !stop.load(std::sync::atomic::Ordering::Relaxed) {
        let dialog = focus::find_dialog(&Desktop.top_windows(), owner, before);
        let foreground = window::foreground_handle();
        // Answered meanwhile: the closing dialog isn't pushed to the front again.
        if stop.load(std::sync::atomic::Ordering::Relaxed) {
            return;
        }
        match watch.tick(Instant::now(), dialog, foreground) {
            FocusAction::Force(d) => {
                window::force_foreground(d, false);
            }
            FocusAction::ForceHard(d) => {
                window::force_foreground(d, true);
            }
            FocusAction::None => {}
        }
        let state = watch.state();
        if state != attempt.state() {
            if stop.load(std::sync::atomic::Ordering::Relaxed) {
                return;
            }
            match state {
                focus::HelloFocus::Shown => pass_agent::timing::mark("hello: dialog shown"),
                focus::HelloFocus::Focused => pass_agent::timing::mark("hello: dialog focused"),
                stalled if stalled.stalled() => {
                    crate::applog::plog!("Windows Hello: {stalled:?} after 2 s");
                }
                _ => {}
            }
            attempt.set_state(state);
        }
        thread::sleep(Duration::from_millis(50));
    }
}

/// Shows the Windows Hello prompt, owned by `owner` so it appears in front of Pass. `Ok(false)` when
/// not verified or cancelled. Blocks; call from a background thread.
pub fn hello_verify(owner: Option<isize>, message: &str) -> Result<bool, String> {
    let owner = owner.filter(|raw| window::is_window(*raw));
    match run_prompt(owner, |_| win_hello::start_verify(owner, message)) {
        Ok(result) => Ok(win_hello::verified(result)),
        Err(PromptError::Cancelled) => Ok(false),
        Err(PromptError::Failed(e)) => Err(crate::errors::logged(
            crate::i18n::tr!("errors.hello_failed"),
            "Windows Hello",
            e,
        )),
    }
}

fn key_error(e: KeyError) -> HelloKeyError {
    match e {
        KeyError::Cancelled => HelloKeyError::Cancelled,
        KeyError::NotFound => HelloKeyError::NotFound,
        KeyError::DeviceLocked => HelloKeyError::Failed(crate::i18n::tr!("errors.tpm_locked")),
        KeyError::Status(status) => HelloKeyError::Failed(crate::errors::logged(
            crate::i18n::tr!("errors.hello_failed"),
            "Windows Hello key",
            format!("KeyCredential status {status}"),
        )),
        KeyError::Os(e) => winrt_error(e),
    }
}

fn winrt_error(e: windows::core::Error) -> HelloKeyError {
    HelloKeyError::Failed(crate::errors::logged(
        crate::i18n::tr!("errors.hello_failed"),
        "Windows Hello key",
        e,
    ))
}

fn prompt_error(e: PromptError) -> HelloKeyError {
    match e {
        PromptError::Cancelled => HelloKeyError::Cancelled,
        PromptError::Failed(e) => winrt_error(e),
    }
}

pub fn hello_key_supported() -> bool {
    win_hello::key_supported()
}

/// Opens the Windows Hello key `name`, creating it if missing. Blocks; call from a background thread.
pub fn hello_key_ensure(name: &str, owner: Option<isize>) -> Result<(), HelloKeyError> {
    match win_hello::open_key(name) {
        Ok(_) => return Ok(()),
        Err(KeyError::NotFound) => {}
        Err(e) => return Err(key_error(e)),
    }
    let result =
        run_prompt(owner, |window| win_hello::start_create(window, name)).map_err(prompt_error)?;
    win_hello::created(&result).map_err(key_error)
}

/// Signs `data` with the Hello key `name` (RSA 2048, RSASSA-PKCS1-v1_5 / SHA-256), after a prompt owned
/// by `owner`. Blocks; call from a background thread.
pub fn hello_key_sign(
    name: &str,
    data: &[u8],
    owner: Option<isize>,
) -> Result<Vec<u8>, HelloKeyError> {
    let credential = win_hello::open_key(name).map_err(key_error)?;
    pass_agent::timing::mark("hello: key opened");
    let buffer = win_hello::buffer(data).map_err(winrt_error)?;
    let result = run_prompt(owner, |window| {
        win_hello::start_sign(&credential, window, &buffer)
    })
    .map_err(prompt_error)?;
    win_hello::signature(&result).map_err(key_error)
}

pub fn hello_key_public(name: &str) -> Option<Vec<u8>> {
    win_hello::key_public(name)
}

pub fn hello_key_delete(name: &str) {
    win_hello::key_delete(name)
}

/// Time since the last keyboard or mouse input (`GetLastInputInfo`), for the sync schedule.
pub fn user_idle_for() -> Option<Duration> {
    use windows::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetTickCount() -> u32;
    }
    let mut info = LASTINPUTINFO {
        cbSize: std::mem::size_of::<LASTINPUTINFO>() as u32,
        dwTime: 0,
    };
    // SAFETY: `info` is a properly sized LASTINPUTINFO; GetTickCount has no preconditions.
    let (ok, now) = unsafe { (GetLastInputInfo(&mut info).as_bool(), GetTickCount()) };
    // Both are milliseconds since boot and wrap after 49.7 days together.
    ok.then(|| Duration::from_millis(u64::from(now.wrapping_sub(info.dwTime))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::core::{w, PCWSTR};
    use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DefWindowProcW, DispatchMessageW, FindWindowW, GetForegroundWindow,
        GetMessageW, GetWindowLongW, PostMessageW, PostQuitMessage, RegisterClassW,
        SetForegroundWindow, TranslateMessage, GWL_EXSTYLE, MSG, WINDOW_EX_STYLE, WM_CLOSE,
        WM_DESTROY, WNDCLASSW, WS_EX_APPWINDOW, WS_OVERLAPPEDWINDOW, WS_VISIBLE,
    };

    fn hwnd(raw: isize) -> HWND {
        HWND(raw as *mut std::ffi::c_void)
    }

    const TEST_KEY: &str = "PassybleFocusTest";

    unsafe extern "system" fn test_wndproc(
        window: HWND,
        msg: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        if msg == WM_DESTROY {
            unsafe { PostQuitMessage(0) };
        }
        unsafe { DefWindowProcW(window, msg, wparam, lparam) }
    }

    fn owner_window() -> isize {
        let (tx, rx) = std::sync::mpsc::channel();
        thread::spawn(move || unsafe {
            let module = GetModuleHandleW(PCWSTR::null()).unwrap();
            let class = w!("PassHelloFocusTestOwner");
            let wc = WNDCLASSW {
                lpfnWndProc: Some(test_wndproc),
                hInstance: module.into(),
                lpszClassName: class,
                ..Default::default()
            };
            RegisterClassW(&wc);
            let window = CreateWindowExW(
                WINDOW_EX_STYLE(0),
                class,
                w!("Passyble Hello focus test"),
                WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                200,
                200,
                460,
                260,
                None,
                None,
                Some(module.into()),
                None,
            )
            .unwrap();
            tx.send(window.0 as isize).unwrap();
            let mut msg = MSG::default();
            while GetMessageW(&mut msg, None, 0, 0).as_bool() {
                let _ = TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        });
        rx.recv().unwrap()
    }

    /// `EndTask`, test clean-up only: `IAsyncOperation::Cancel` leaves the dialog on screen.
    fn end_task(window: isize) {
        unsafe {
            let module = windows::Win32::System::LibraryLoader::LoadLibraryW(w!("user32.dll"));
            let Ok(module) = module else { return };
            let Some(address) = windows::Win32::System::LibraryLoader::GetProcAddress(
                module,
                windows::core::s!("EndTask"),
            ) else {
                return;
            };
            let end_task: unsafe extern "system" fn(HWND, i32, i32) -> i32 =
                std::mem::transmute(address);
            end_task(hwnd(window), 0, 1);
        }
    }

    /// Manual check on a PC with Windows Hello (shows a real Hello dialog, then cancels it):
    ///
    /// ```text
    /// set HELLO_FOCUS_BLOCKER=<an exe that opens a window of class PassybleFocusTestBlocker>
    /// set HELLO_FOCUS_KIND=verify   (or create: KeyCredentialManager, throwaway key PassybleFocusTest)
    /// cargo test -p pass-desktop -- --ignored --nocapture hello_dialog_comes_to_front
    /// ```
    ///
    /// With another process's window in front, the dialog must still be owned by our window and come to the front.
    #[test]
    #[ignore = "shows a real Windows Hello dialog"]
    fn hello_dialog_comes_to_front() {
        let owner = owner_window();
        let blocker = std::env::var("HELLO_FOCUS_BLOCKER")
            .ok()
            .and_then(|exe| std::process::Command::new(exe).arg("blocker").spawn().ok());
        if blocker.is_some() {
            let deadline = Instant::now() + Duration::from_secs(8);
            while Instant::now() < deadline {
                let found = unsafe { FindWindowW(w!("PassybleFocusTestBlocker"), PCWSTR::null()) };
                if found.is_ok_and(|w| unsafe { GetForegroundWindow() } == w) {
                    break;
                }
                thread::sleep(Duration::from_millis(100));
            }
            thread::sleep(Duration::from_millis(500));
            unsafe {
                let _ = SetForegroundWindow(hwnd(owner));
            }
            thread::sleep(Duration::from_millis(100));
            println!(
                "this process can take the foreground by itself: {}",
                unsafe { GetForegroundWindow() } == hwnd(owner)
            );
        }
        let kind = std::env::var("HELLO_FOCUS_KIND").unwrap_or_else(|_| "verify".into());
        let started = Instant::now();
        let worker = {
            let kind = kind.clone();
            thread::spawn(move || match kind.as_str() {
                "create" => format!("{:?}", hello_key_ensure(TEST_KEY, Some(owner))),
                _ => format!("{:?}", hello_verify(Some(owner), "Passyble focus test")),
            })
        };
        let mut seen = None;
        let mut owned = false;
        let mut taskbar_button = true;
        let deadline = Instant::now() + Duration::from_secs(6);
        while Instant::now() < deadline {
            if let Some(dialog) = focus::find_dialog(&Desktop.top_windows(), Some(owner), &[]) {
                seen.get_or_insert(started.elapsed());
                owned = window::owner(dialog) == Some(owner);
                let ex = unsafe { GetWindowLongW(hwnd(dialog), GWL_EXSTYLE) } as u32;
                taskbar_button = !owned || ex & WS_EX_APPWINDOW.0 != 0;
                if owned && focus::status(Some(owner)) == Some(focus::HelloFocus::Focused) {
                    break;
                }
            }
            thread::sleep(Duration::from_millis(50));
        }
        let status = focus::status(Some(owner));
        let foreground = window::foreground_handle();
        let dialog = focus::find_dialog(&Desktop.top_windows(), Some(owner), &[]);
        println!(
            "{kind}: dialog seen after {seen:?}, status {status:?} after {:?}, owned by our window {owned}, own taskbar button {taskbar_button}, foreground is the dialog {}",
            started.elapsed(),
            dialog.is_some_and(|d| Some(d) == foreground)
        );
        assert!(focus::cancel(Some(owner)));
        let result = worker.join().unwrap();
        println!("result after cancel: {result}");
        for _ in 0..20 {
            match focus::find_dialog(&Desktop.top_windows(), Some(owner), &[]) {
                Some(d) => end_task(d),
                None => break,
            }
            thread::sleep(Duration::from_millis(1500));
        }
        if kind == "create" {
            hello_key_delete(TEST_KEY);
        }
        unsafe {
            let _ = PostMessageW(Some(hwnd(owner)), WM_CLOSE, WPARAM(0), LPARAM(0));
            if let Ok(b) = FindWindowW(w!("PassybleFocusTestBlocker"), PCWSTR::null()) {
                let _ = PostMessageW(Some(b), WM_CLOSE, WPARAM(0), LPARAM(0));
            }
        }
        assert_eq!(status, Some(focus::HelloFocus::Focused));
        assert!(owned && !taskbar_button);
        assert!(
            result.contains("Cancelled") || result == "Ok(false)",
            "{result}"
        );
    }
}
