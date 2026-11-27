//! A small rolling log file, `%LOCALAPPDATA%\Pass\logs\pass.log`.
//!
//! `Pass.exe` is a Windows GUI program (no console): [`plog!`] writes one line to the log file and, when Pass has a
//! stderr (started from a terminal), there too. What goes in: start-up, errors from background work, panics. Never
//! vault contents, passwords, tokens, keys or server responses: callers log fixed texts and error messages only.
//!
//! The file is capped at [`MAX_BYTES`]; when full it becomes `pass.old.log` (replacing the previous one).

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

pub const MAX_BYTES: u64 = 512 * 1024;

/// Serialises writers (threads) so lines don't interleave and rotation happens once.
static WRITE: Mutex<()> = Mutex::new(());

macro_rules! plog {
    ($($arg:tt)*) => {
        $crate::applog::write(&format!($($arg)*))
    };
}
pub(crate) use plog;

pub fn dir() -> PathBuf {
    crate::settings::local_dir().join("logs")
}

pub fn init() {
    write(&format!(
        "Passyble {} started (pid {}{})",
        env!("CARGO_PKG_VERSION"),
        std::process::id(),
        if cfg!(debug_assertions) {
            ", debug build"
        } else {
            ""
        }
    ));
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let location = info
            .location()
            .map(|l| format!(" at {}:{}", l.file(), l.line()))
            .unwrap_or_default();
        let message = info
            .payload()
            .downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| info.payload().downcast_ref::<String>().cloned())
            .unwrap_or_default();
        write(&format!("panic{location}: {message}"));
        default_hook(info);
    }));
}

/// Appends `message` as one line. Never fails: logging problems are ignored.
pub fn write(message: &str) {
    // One line per call: a message with line breaks can't fake other entries.
    let message = message.replace(['\r', '\n'], " ");
    eprintln!("pass: {message}");
    if cfg!(test) {
        return; // unit tests don't write to the user's log
    }
    let line = format!("{} {message}\n", timestamp(SystemTime::now()));
    let _guard = WRITE.lock().unwrap_or_else(|p| p.into_inner());
    let _ = append(&dir(), &line);
}

fn append(dir: &std::path::Path, line: &str) -> std::io::Result<()> {
    fs::create_dir_all(dir)?;
    let file = dir.join("pass.log");
    if fs::metadata(&file).is_ok_and(|m| m.len() + line.len() as u64 > MAX_BYTES) {
        let _ = fs::rename(&file, dir.join("pass.old.log"));
    }
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(&file)?
        .write_all(line.as_bytes())
}

/// `2026-10-10T08:15:30Z` (UTC, no dependency on a date crate).
fn timestamp(t: SystemTime) -> String {
    let secs = t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs()) as i64;
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

#[tauri::command]
pub fn open_log_folder() -> Result<(), String> {
    let dir = dir();
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    #[cfg(windows)]
    {
        let mut child = std::process::Command::new("explorer.exe")
            .arg(&dir)
            .spawn()
            .map_err(|e| e.to_string())?;
        std::thread::spawn(move || {
            let _ = child.wait();
        });
        Ok(())
    }
    #[cfg(target_os = "macos")]
    {
        pass_macos::finder::reveal(&dir).map_err(|e| e.to_string())
    }
    #[cfg(target_os = "linux")]
    {
        pass_linux::files::open(&dir).map_err(|e| e.to_string())
    }
    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    {
        Err(crate::i18n::tr!(
            "errors.log_location",
            path = dir.display()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn timestamps_are_utc_iso() {
        assert_eq!(timestamp(UNIX_EPOCH), "1970-01-01T00:00:00Z");
        let t = UNIX_EPOCH + Duration::from_secs(1_791_571_932);
        assert_eq!(timestamp(t), "2026-10-09T18:52:12Z");
        let leap = UNIX_EPOCH + Duration::from_secs(951_782_400); // 2000-02-29
        assert_eq!(timestamp(leap), "2000-02-29T00:00:00Z");
    }

    #[test]
    fn the_file_rotates_at_the_cap() {
        let dir = std::env::temp_dir().join(format!("pass-log-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let line = format!("{}\n", "x".repeat(1023));
        for _ in 0..(MAX_BYTES / 1024) {
            append(&dir, &line).unwrap();
        }
        assert!(!dir.join("pass.old.log").exists());
        append(&dir, &line).unwrap();
        assert!(dir.join("pass.old.log").exists());
        assert_eq!(fs::metadata(dir.join("pass.log")).unwrap().len(), 1024);
        assert!(fs::metadata(dir.join("pass.old.log")).unwrap().len() <= MAX_BYTES);
        let _ = fs::remove_dir_all(&dir);
    }
}
