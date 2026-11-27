//! OS integration: foreground window, auto-type, session-lock notifications, DPAPI and Windows
//! Hello. Windows has the real implementation, macOS maps the API onto `pass-macos`, Linux onto
//! `pass-linux`, other platforms get stubs so the crate still compiles.

#[cfg(windows)]
mod win32;
#[cfg(windows)]
pub use win32::*;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::*;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
mod stub;
#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
pub use stub::*;

#[derive(Clone, Debug, Default)]
pub struct Target {
    /// The HWND as an integer (HWND itself isn't `Send`).
    #[cfg_attr(not(windows), allow(dead_code))]
    pub hwnd: isize,
    pub title: String,
    pub exe: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HelloKeyError {
    Cancelled,
    #[cfg_attr(target_os = "linux", allow(dead_code))]
    NotFound,
    /// Windows Hello keys can't be used on this PC (the non-Windows stubs).
    #[cfg_attr(windows, allow(dead_code))]
    Unsupported,
    Failed(String),
}

impl std::fmt::Display for HelloKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cancelled => f.write_str(&crate::i18n::tr!("errors.hello_cancelled")),
            Self::NotFound => f.write_str(&crate::i18n::tr!("errors.hello_key_gone")),
            Self::Unsupported => f.write_str(&crate::i18n::tr!("errors.hello_keys_unavailable")),
            // Already words for the user (the detail went to the log).
            Self::Failed(message) => f.write_str(message),
        }
    }
}

/// How many parent processes [`started_by`] follows up from the native messaging host: Chrome and
/// Edge start it through `cmd.exe` (2 levels), Firefox directly (1).
#[cfg_attr(target_os = "linux", allow(dead_code))]
pub const BROWSER_PARENT_LEVELS: usize = 4;

/// Whether process `ancestor` started `child`, directly or through at most `levels - 1` processes in
/// between, per `parents` (a ToolHelp snapshot). Process ID 0 never matches; a loop ends the walk.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn started_by(
    parents: &std::collections::HashMap<u32, u32>,
    child: u32,
    ancestor: u32,
    levels: usize,
) -> bool {
    if ancestor == 0 || ancestor == child {
        return false;
    }
    let mut pid = child;
    for _ in 0..levels {
        match parents.get(&pid) {
            Some(&parent) if parent != 0 && parent != pid => {
                if parent == ancestor {
                    return true;
                }
                pid = parent;
            }
            _ => return false,
        }
    }
    false
}

/// The (native messaging host, browser) pairs [`started_by`] already confirmed, so the next Windows
/// Hello dialog for that host needs no process snapshot (about 10 ms). Only decides which window the
/// dialog is shown over.
#[derive(Debug, Default)]
#[cfg_attr(not(windows), allow(dead_code))]
pub struct HostBrowsers(Vec<(u32, u32)>);

#[cfg_attr(not(windows), allow(dead_code))]
impl HostBrowsers {
    const MAX: usize = 16;

    pub fn known(&self, host: u32, browser: u32) -> bool {
        self.0.contains(&(host, browser))
    }

    pub fn remember(&mut self, host: u32, browser: u32) {
        if self.known(host, browser) {
            return;
        }
        if self.0.len() >= Self::MAX {
            self.0.remove(0);
        }
        self.0.push((host, browser));
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Key {
    Tab,
    Enter,
}

/// A keychain entry for `service` + `user`. On Windows `target` names the Credential Manager entry.
/// macOS and Linux take no free-form target (the Mac keychain accepts only a domain name, Secret
/// Service a collection), so there the entry is `service` + `user` alone. On macOS entries live in
/// one sealed file, not the Keychain (`pass_macos::secrets`, set up in main.rs).
pub fn keyring_entry(target: &str, service: &str, user: &str) -> keyring::Result<keyring::Entry> {
    #[cfg(windows)]
    {
        keyring::Entry::new_with_target(target, service, user)
    }
    #[cfg(not(windows))]
    {
        let _ = target;
        keyring::Entry::new(service, user)
    }
}

pub fn open_browser(url: &str) -> Result<(), String> {
    #[cfg(windows)]
    let mut cmd = {
        // `url.dll` hands the URL to the default browser without a console or cmd.exe parsing.
        let mut c = std::process::Command::new("rundll32.exe");
        c.arg("url.dll,FileProtocolHandler").arg(url);
        c
    };
    #[cfg(target_os = "macos")]
    let mut cmd = {
        let mut c = std::process::Command::new("open");
        c.arg(url);
        c
    };
    #[cfg(all(not(windows), not(target_os = "macos")))]
    let mut cmd = {
        let mut c = std::process::Command::new("xdg-open");
        c.arg(url);
        c
    };
    let mut child = cmd.spawn().map_err(|e| {
        crate::errors::logged(crate::i18n::tr!("errors.browser_open"), "open browser", e)
    })?;
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{started_by, HostBrowsers, BROWSER_PARENT_LEVELS};
    use std::collections::HashMap;

    #[test]
    fn host_browser_pairs_are_remembered_exactly() {
        let mut pairs = HostBrowsers::default();
        assert!(!pairs.known(30, 10));
        pairs.remember(30, 10);
        pairs.remember(30, 10);
        assert!(pairs.known(30, 10));
        // Another browser in front, or another host: checked again.
        assert!(!pairs.known(30, 40));
        assert!(!pairs.known(31, 10));
        for host in 100..100 + HostBrowsers::MAX as u32 {
            pairs.remember(host, 10);
        }
        assert!(!pairs.known(30, 10));
        assert!(pairs.known(100 + HostBrowsers::MAX as u32 - 1, 10));
    }

    #[test]
    fn browser_started_the_native_host() {
        // chrome.exe (10) -> cmd.exe (20) -> pass-native-host.exe (30); firefox.exe (40) -> host (50).
        let parents: HashMap<u32, u32> = [
            (10, 4),
            (20, 10),
            (30, 20),
            (40, 4),
            (50, 40),
            (60, 60),
            (70, 0),
        ]
        .into();
        let ok = |child, ancestor| started_by(&parents, child, ancestor, BROWSER_PARENT_LEVELS);
        assert!(ok(30, 10), "Chrome / Edge through cmd.exe");
        assert!(ok(50, 40), "Firefox directly");
        assert!(ok(30, 20));
        assert!(!ok(30, 40));
        assert!(!ok(30, 30));
        assert!(!ok(10, 30));
        assert!(!ok(70, 0));
        assert!(!ok(60, 10));
        assert!(!ok(99, 10));
        assert!(started_by(&parents, 30, 4, 3));
        assert!(!started_by(&parents, 30, 4, 2));
    }

    /// The Mac keychain refuses a free-form target ("not User, System, Common, or Dynamic"), and
    /// the entry then can't be saved.
    #[test]
    fn a_named_entry_opens_on_every_platform() {
        assert!(super::keyring_entry(
            "Pass/GoogleDrive/someone@example.com",
            "com.sensyble.pass.google",
            "someone@example.com",
        )
        .is_ok());
    }
}
