//! Copying secrets: cleared after 45 s (only if the clipboard still holds our value), and on
//! Windows flagged so clipboard history, cloud clipboard and clipboard managers skip them
//! (`pass_windows::clipboard`). On macOS a copy stays on this Mac (no Universal Clipboard) and
//! is marked concealed (`pass_macos::clipboard`).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

use zeroize::Zeroizing;

pub const CLEAR_AFTER: Duration = Duration::from_secs(45);

static GENERATION: AtomicU64 = AtomicU64::new(0);
static LAST: Mutex<Option<(u64, Zeroizing<String>)>> = Mutex::new(None);

fn last() -> std::sync::MutexGuard<'static, Option<(u64, Zeroizing<String>)>> {
    LAST.lock().unwrap_or_else(|p| p.into_inner())
}

/// Clears the clipboard now if it still holds the secret Pass copied last (Pass is quitting, so
/// the timer won't run).
pub fn clear_now() {
    let Some((_, copied)) = last().take() else {
        return;
    };
    if let Ok(mut clipboard) = arboard::Clipboard::new() {
        if clipboard.get_text().ok().as_deref() == Some(copied.as_str()) {
            let _ = clipboard.clear();
        }
    }
}

pub fn copy_secret(text: &str) -> Result<(), String> {
    fn failed(e: impl std::fmt::Display) -> String {
        crate::errors::logged(crate::i18n::tr!("errors.copy_failed"), "clipboard", e)
    }
    #[cfg(windows)]
    {
        let mut clipboard = arboard::Clipboard::new().map_err(failed)?;
        pass_windows::clipboard::set_secret_text(&mut clipboard, text.to_string())
            .map_err(failed)?;
    }
    // This Mac only (no Universal Clipboard), concealed and transient (pass_macos::clipboard).
    #[cfg(target_os = "macos")]
    pass_macos::clipboard::set_secret(text).map_err(failed)?;
    // Linux: marked secret for clipboard managers (`x-kde-passwordManagerHint`), on X11 and on
    // Wayland (pass_linux::clipboard).
    #[cfg(target_os = "linux")]
    pass_linux::clipboard::set_secret(text).map_err(failed)?;
    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    arboard::Clipboard::new()
        .and_then(|mut clipboard| clipboard.set_text(text.to_string()))
        .map_err(failed)?;

    let generation = GENERATION.fetch_add(1, Ordering::SeqCst) + 1;
    *last() = Some((generation, Zeroizing::new(text.to_string())));
    let copied = Zeroizing::new(text.to_string());
    let _ = thread::Builder::new()
        .name("pass-clipboard-clear".into())
        .spawn(move || {
            thread::sleep(CLEAR_AFTER);
            // A newer copy has its own timer.
            if GENERATION.load(Ordering::SeqCst) != generation {
                return;
            }
            {
                let mut last = last();
                if last.as_ref().is_some_and(|(g, _)| *g == generation) {
                    *last = None;
                }
            }
            if let Ok(mut clipboard) = arboard::Clipboard::new() {
                if clipboard.get_text().ok().as_deref() == Some(copied.as_str()) {
                    let _ = clipboard.clear();
                }
            }
        });
    Ok(())
}
