//! Registers `pass-native-host.exe` (installed beside `Pass.exe`) as the browser Native
//! Messaging host `com.sensyble.pass` for Chrome, Edge, Brave, Chromium, Opera, Opera GX and
//! Firefox, per user (HKCU; each Chromium browser reads only its own key, and Opera and Opera GX
//! read Chrome's: Chromium looks in `Software\Google\Chrome` unless a browser changes that, and
//! Opera doesn't). Runs at every start and only rewrites what changed, so moving the install
//! folder heals itself. On macOS and Linux the manifests go into each installed browser's own
//! folder instead, and for Opera also into Chrome's (see [`register`]).

use serde::Serialize;

#[cfg_attr(not(windows), allow(dead_code))]
pub const HOST_NAME: &str = "com.sensyble.pass";
#[cfg_attr(not(windows), allow(dead_code))]
pub const FIREFOX_EXTENSION_ID: &str = "pass@sensyble.com";

/// `allowed_origins` for Chromium browsers: the ID pinned by the `key` in `Extension/manifest.json`
/// (unpacked loads in Chrome and Edge). `Extension/test/manifest.test.js` recomputes it from the key
/// and fails if they drift. Other IDs can be added in settings.json (`extra_extension_ids`).
pub const CHROMIUM_EXTENSION_IDS: &[&str] = &["bmjmlhhgfbpcbfbkbndlmmockkbdcaoo"];

/// The ID the Chrome Web Store assigns (32 letters a to p). Opera also installs from there.
pub const CHROME_STORE_EXTENSION_IDS: &[&str] = &[];

/// The ID Edge Add-ons assigns (32 letters a to p).
pub const EDGE_STORE_EXTENSION_IDS: &[&str] = &[];

/// The ID Opera Add-ons (addons.opera.com) assigns, for Opera and Opera GX (32 letters a to p).
pub const OPERA_STORE_EXTENSION_IDS: &[&str] = &["elckicaofoomkdcfbkkbnjdljhbbmkch"];

/// Every extension ID that may call the native host, from the lists above.
fn all_store_ids() -> impl Iterator<Item = &'static &'static str> {
    CHROMIUM_EXTENSION_IDS
        .iter()
        .chain(CHROME_STORE_EXTENSION_IDS)
        .chain(EDGE_STORE_EXTENSION_IDS)
        .chain(OPERA_STORE_EXTENSION_IDS)
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Status {
    pub supported: bool,
    pub host_path: String,
    pub host_exists: bool,
    pub manifest_path: String,
    pub chrome: bool,
    pub edge: bool,
    pub brave: bool,
    pub chromium: bool,
    pub opera: bool,
    pub opera_gx: bool,
    pub firefox: bool,
    pub error: Option<String>,
}

#[cfg_attr(not(windows), allow(dead_code))]
fn chromium_origins(extra: &[String]) -> Vec<String> {
    all_store_ids()
        .map(|s| s.to_string())
        .chain(extra.iter().map(|s| s.trim().to_string()))
        .filter(|id| !id.is_empty())
        .map(|id| {
            if id.starts_with("chrome-extension://") {
                id
            } else {
                format!("chrome-extension://{id}/")
            }
        })
        .collect()
}

#[cfg(windows)]
pub fn register(extra_ids: &[String]) -> Status {
    match win::register(extra_ids) {
        Ok(status) => status,
        Err(e) => Status {
            supported: true,
            error: Some(crate::errors::logged(
                crate::i18n::tr!("errors.native_register_failed"),
                "browser registration",
                e,
            )),
            ..Default::default()
        },
    }
}

/// macOS: a manifest in each installed browser's own `NativeMessagingHosts` folder under
/// `~/Library/Application Support` (`pass_macos::connector`). Browsers that are not installed get
/// nothing; the next start picks up one installed since.
#[cfg(target_os = "macos")]
pub fn register(extra_ids: &[String]) -> Status {
    mac::register(extra_ids)
}

/// Linux: a manifest in each installed browser's own `NativeMessagingHosts` folder under
/// `~/.config` (Firefox: `~/.mozilla/native-messaging-hosts`), `pass_linux::connector`. An
/// AppImage first stages the host in `~/.local/share/Passyble/bin/` (its own folder changes at
/// every run) and the manifests point there.
#[cfg(target_os = "linux")]
pub fn register(extra_ids: &[String]) -> Status {
    linux::register(extra_ids)
}

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
pub fn register(_extra_ids: &[String]) -> Status {
    Status {
        supported: false,
        error: Some(crate::i18n::tr!("errors.native_windows_only")),
        ..Default::default()
    }
}

#[cfg(windows)]
mod win {
    use std::fs;
    use std::path::{Path, PathBuf};

    use serde_json::json;
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;

    use super::*;

    const CHROME_KEY: &str = r"Software\Google\Chrome\NativeMessagingHosts\com.sensyble.pass";
    const EDGE_KEY: &str = r"Software\Microsoft\Edge\NativeMessagingHosts\com.sensyble.pass";
    const BRAVE_KEY: &str =
        r"Software\BraveSoftware\Brave-Browser\NativeMessagingHosts\com.sensyble.pass";
    const CHROMIUM_KEY: &str = r"Software\Chromium\NativeMessagingHosts\com.sensyble.pass";
    const FIREFOX_KEY: &str = r"Software\Mozilla\NativeMessagingHosts\com.sensyble.pass";

    fn write_if_changed(path: &Path, contents: &str) -> std::io::Result<()> {
        if fs::read_to_string(path).ok().as_deref() == Some(contents) {
            return Ok(());
        }
        fs::write(path, contents)
    }

    /// Next to the exe when writable (per-user install), else `%LOCALAPPDATA%\Pass`.
    fn manifest_dir(exe_dir: &Path) -> PathBuf {
        let probe = exe_dir.join(".pass-write-test");
        if fs::write(&probe, b"").is_ok() {
            let _ = fs::remove_file(&probe);
            return exe_dir.to_path_buf();
        }
        crate::settings::local_dir().join("native-messaging")
    }

    fn set_default(key: &str, value: &str) -> Result<bool, String> {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let (k, _) = hkcu.create_subkey(key).map_err(|e| format!("{key}: {e}"))?;
        let current: Option<String> = k.get_value("").ok();
        if current.as_deref() != Some(value) {
            k.set_value("", &value.to_string())
                .map_err(|e| format!("{key}: {e}"))?;
        }
        Ok(true)
    }

    pub fn register(extra_ids: &[String]) -> Result<Status, String> {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let exe_dir = exe
            .parent()
            .ok_or_else(|| crate::i18n::tr!("errors.pp_no_folder"))?
            .to_path_buf();
        let host = exe_dir.join("pass-native-host.exe");
        let dir = manifest_dir(&exe_dir);
        fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let host_str = host.to_string_lossy().to_string();

        let chromium_manifest = dir.join(format!("{HOST_NAME}.json"));
        let chromium = json!({
            "name": HOST_NAME,
            "description": "Passyble password manager",
            "path": host_str,
            "type": "stdio",
            "allowed_origins": chromium_origins(extra_ids),
        });
        write_if_changed(
            &chromium_manifest,
            &serde_json::to_string_pretty(&chromium).unwrap_or_default(),
        )
        .map_err(|e| e.to_string())?;

        let firefox_manifest = dir.join(format!("{HOST_NAME}.firefox.json"));
        let firefox = json!({
            "name": HOST_NAME,
            "description": "Passyble password manager",
            "path": host_str,
            "type": "stdio",
            "allowed_extensions": [FIREFOX_EXTENSION_ID],
        });
        write_if_changed(
            &firefox_manifest,
            &serde_json::to_string_pretty(&firefox).unwrap_or_default(),
        )
        .map_err(|e| e.to_string())?;

        let chromium_path = chromium_manifest.to_string_lossy().to_string();
        let firefox_path = firefox_manifest.to_string_lossy().to_string();
        let mut errors = Vec::new();
        let mut ok = |key: &str, value: &str| match set_default(key, value) {
            Ok(v) => v,
            Err(e) => {
                errors.push(e);
                false
            }
        };
        let chrome = ok(CHROME_KEY, &chromium_path);
        let edge = ok(EDGE_KEY, &chromium_path);
        let brave = ok(BRAVE_KEY, &chromium_path);
        let chromium = ok(CHROMIUM_KEY, &chromium_path);
        let firefox = ok(FIREFOX_KEY, &firefox_path);
        Ok(Status {
            supported: true,
            host_exists: host.exists(),
            host_path: host_str,
            manifest_path: chromium_path,
            chrome,
            edge,
            brave,
            chromium,
            // Opera and Opera GX read Chrome's key (module docs).
            opera: chrome,
            opera_gx: chrome,
            firefox,
            error: (!errors.is_empty()).then(|| {
                crate::errors::logged(
                    crate::i18n::tr!("errors.native_register_failed"),
                    "browser registration",
                    errors.join("; "),
                )
            }),
        })
    }
}

#[cfg(target_os = "macos")]
mod mac {
    use pass_macos::connector::{self, Browser};

    use super::*;

    fn failed(detail: String) -> Status {
        Status {
            supported: true,
            error: Some(crate::errors::logged(
                crate::i18n::tr!("errors.native_register_failed"),
                "browser registration",
                detail,
            )),
            ..Default::default()
        }
    }

    pub fn register(extra_ids: &[String]) -> Status {
        let exe = match std::env::current_exe() {
            Ok(exe) => exe,
            Err(e) => return failed(e.to_string()),
        };
        // A downloaded app that was never moved runs from a random read-only copy (App
        // Translocation): a manifest pointing there breaks with the next start.
        if pass_macos::apps::is_translocated(&exe) {
            return Status {
                supported: true,
                error: Some(crate::errors::logged(
                    crate::i18n::tr!("macos.move_to_applications"),
                    "browser registration",
                    format!("the app is translocated ({})", exe.display()),
                )),
                ..Default::default()
            };
        }
        let (Some(app_support), Some(host)) =
            (connector::app_support_dir(), connector::host_path(&exe))
        else {
            return failed("no home folder".into());
        };
        let registrations = connector::install(
            &app_support,
            &Browser::ALL,
            &host,
            &chromium_origins(extra_ids),
            &[FIREFOX_EXTENSION_ID.to_string()],
        );
        let done = |browser: Browser| {
            registrations
                .iter()
                .any(|r| r.browser == browser && matches!(r.result, Ok(true)))
        };
        let errors: Vec<String> = registrations
            .iter()
            .filter_map(|r| r.result.as_ref().err().cloned())
            .collect();
        let manifest_path = registrations
            .iter()
            .find(|r| matches!(r.result, Ok(true)))
            .map(|r| r.manifest.to_string_lossy().into_owned())
            .unwrap_or_default();
        Status {
            supported: true,
            host_exists: host.exists(),
            host_path: host.to_string_lossy().into_owned(),
            manifest_path,
            chrome: done(Browser::Chrome),
            edge: done(Browser::Edge),
            brave: done(Browser::Brave),
            chromium: done(Browser::Chromium),
            opera: done(Browser::Opera),
            opera_gx: done(Browser::OperaGx),
            firefox: done(Browser::Firefox),
            error: (!errors.is_empty()).then(|| {
                crate::errors::logged(
                    crate::i18n::tr!("errors.native_register_failed"),
                    "browser registration",
                    errors.join("; "),
                )
            }),
        }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use pass_linux::connector::{self, Browser, Dirs};

    use super::*;

    fn failed(detail: String) -> Status {
        Status {
            supported: true,
            error: Some(crate::errors::logged(
                crate::i18n::tr!("errors.native_register_failed"),
                "browser registration",
                detail,
            )),
            ..Default::default()
        }
    }

    pub fn register(extra_ids: &[String]) -> Status {
        let exe = match std::env::current_exe() {
            Ok(exe) => exe,
            Err(e) => return failed(e.to_string()),
        };
        let (Some(dirs), Some(bundled)) = (Dirs::from_env(), connector::host_path(&exe)) else {
            return failed("no home folder".into());
        };
        // AppImage: the manifests point at a staged copy, with the AppImage and this executable
        // recorded beside it for the host (`pass-app`).
        let host = match connector::appimage() {
            Some(appimage) => match connector::stage_host(&dirs, &bundled, &appimage, &exe) {
                Ok(staged) => staged,
                Err(e) => return failed(format!("staging the native host: {e}")),
            },
            None => bundled,
        };
        let registrations = connector::install(
            &dirs,
            &Browser::ALL,
            &host,
            &chromium_origins(extra_ids),
            &[FIREFOX_EXTENSION_ID.to_string()],
        );
        let done = |browser: Browser| {
            registrations
                .iter()
                .any(|r| r.browser == browser && matches!(r.result, Ok(true)))
        };
        let errors: Vec<String> = registrations
            .iter()
            .filter_map(|r| r.result.as_ref().err().cloned())
            .collect();
        let manifest_path = registrations
            .iter()
            .find(|r| matches!(r.result, Ok(true)))
            .map(|r| r.manifest.to_string_lossy().into_owned())
            .unwrap_or_default();
        Status {
            supported: true,
            host_exists: host.exists(),
            host_path: host.to_string_lossy().into_owned(),
            manifest_path,
            chrome: done(Browser::Chrome),
            edge: done(Browser::Edge),
            brave: done(Browser::Brave),
            chromium: done(Browser::Chromium),
            opera: done(Browser::Opera),
            // Opera GX has no Linux version.
            opera_gx: false,
            firefox: done(Browser::Firefox),
            error: (!errors.is_empty()).then(|| {
                crate::errors::logged(
                    crate::i18n::tr!("errors.native_register_failed"),
                    "browser registration",
                    errors.join("; "),
                )
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origins_are_normalized() {
        let origins = chromium_origins(&[
            " abcdefghijklmnopabcdefghijklmnop ".into(),
            "chrome-extension://ponmlkjihgfedcbaponmlkjihgfedcba/".into(),
            "".into(),
        ]);
        assert!(
            origins.contains(&"chrome-extension://abcdefghijklmnopabcdefghijklmnop/".to_string())
        );
        assert!(
            origins.contains(&"chrome-extension://ponmlkjihgfedcbaponmlkjihgfedcba/".to_string())
        );
        assert_eq!(
            origins.len(),
            all_store_ids().count() + 2
        );
    }

    #[test]
    fn store_ids_are_allowed_and_well_formed() {
        let origins = chromium_origins(&[]);
        for id in all_store_ids() {
            assert!(
                id.len() == 32 && id.bytes().all(|b| (b'a'..=b'p').contains(&b)),
                "not an extension ID: {id}"
            );
            assert!(origins.contains(&format!("chrome-extension://{id}/")));
        }
    }

    #[test]
    fn dev_and_opera_store_ids_are_allowed() {
        let origins = chromium_origins(&[]);
        for id in ["bmjmlhhgfbpcbfbkbndlmmockkbdcaoo", "elckicaofoomkdcfbkkbnjdljhbbmkch"] {
            assert!(origins.contains(&format!("chrome-extension://{id}/")), "{id}");
        }
    }

    #[test]
    fn firefox_gecko_id_is_unchanged() {
        assert_eq!(FIREFOX_EXTENSION_ID, "pass@sensyble.com");
    }
}
