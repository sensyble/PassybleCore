//! First-run help: the "Get started" checklist and the browser extension setup guide.
//!
//! The extension isn't in every store yet, so the guide loads it unpacked (Chromium) or as a
//! temporary add-on (Firefox) from the copy the installer ships. "Connected" is detected by finding
//! `pass-native-host.exe` in a process snapshot and walking up its parent chain to the browser, so
//! it works with every extension version.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde_json::{json, Value};
use tauri::{AppHandle, State};

use crate::i18n::tr;
use crate::settings::VaultEntry;
use crate::state::AppState;
use crate::{native_messaging, vaults};

type Res<T> = Result<T, String>;
type AppState_<'a> = State<'a, Arc<AppState>>;

/// A browser the guide knows: where its extensions page is and how Windows names it.
#[derive(Debug)]
pub struct Browser {
    pub id: &'static str,
    pub name: &'static str,
    pub exe: &'static str,
    /// The page where extensions are loaded. Chromium browsers don't open their own pages from
    /// the command line, so the guide copies the address too.
    pub page: &'static str,
    pub prog_id: &'static str,
    /// Install folders under Program Files / LocalAppData when App Paths has no entry.
    #[cfg_attr(target_os = "linux", allow(dead_code))]
    pub dirs: &'static [&'static str],
    pub mac_exe: &'static str,
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub mac_bundle: &'static str,
    pub store: &'static str,
}

// Store pages: searches until a listing is published, then the listing.
const CHROME_WEB_STORE: &str = "https://chromewebstore.google.com/search/Passyble";
const EDGE_ADD_ONS: &str = "https://microsoftedge.microsoft.com/addons/search/Passyble";
const OPERA_ADD_ONS: &str = "https://addons.opera.com/en/search/?query=Passyble";
const FIREFOX_ADD_ONS: &str = "https://addons.mozilla.org/firefox/addon/passyble/";

pub const BROWSERS: &[Browser] = &[
    Browser {
        id: "chrome",
        name: "Chrome",
        exe: "chrome.exe",
        page: "chrome://extensions",
        prog_id: "ChromeHTML",
        dirs: &[r"Google\Chrome\Application"],
        mac_exe: "Google Chrome",
        mac_bundle: "com.google.Chrome",
        store: CHROME_WEB_STORE,
    },
    Browser {
        id: "edge",
        name: "Edge",
        exe: "msedge.exe",
        page: "edge://extensions",
        prog_id: "MSEdgeHTM",
        dirs: &[r"Microsoft\Edge\Application"],
        mac_exe: "Microsoft Edge",
        mac_bundle: "com.microsoft.edgemac",
        store: EDGE_ADD_ONS,
    },
    Browser {
        id: "brave",
        name: "Brave",
        exe: "brave.exe",
        page: "brave://extensions",
        prog_id: "BraveHTML",
        dirs: &[r"BraveSoftware\Brave-Browser\Application"],
        mac_exe: "Brave Browser",
        mac_bundle: "com.brave.Browser",
        store: CHROME_WEB_STORE,
    },
    // Runs `chrome.exe` like Chrome; a host it starts on Windows shows up as Chrome's.
    Browser {
        id: "chromium",
        name: "Chromium",
        exe: "chrome.exe",
        page: "chrome://extensions",
        prog_id: "ChromiumHTM",
        dirs: &[r"Chromium\Application"],
        mac_exe: "Chromium",
        mac_bundle: "org.chromium.Chromium",
        store: CHROME_WEB_STORE,
    },
    // Opera and Opera GX both run `opera.exe`, from their own folders.
    Browser {
        id: "opera",
        name: "Opera",
        exe: "opera.exe",
        page: "opera://extensions",
        prog_id: "OperaStable",
        dirs: &[r"Programs\Opera", "Opera"],
        mac_exe: "Opera",
        mac_bundle: "com.operasoftware.Opera",
        store: OPERA_ADD_ONS,
    },
    Browser {
        id: "opera-gx",
        name: "Opera GX",
        exe: "opera.exe",
        page: "opera://extensions",
        prog_id: "OperaGXStable",
        dirs: &[r"Programs\Opera GX", "Opera GX"],
        mac_exe: "Opera GX",
        mac_bundle: "com.operasoftware.OperaGX",
        store: OPERA_ADD_ONS,
    },
    Browser {
        id: "firefox",
        name: "Firefox",
        exe: "firefox.exe",
        page: "about:debugging#/runtime/this-firefox",
        prog_id: "FirefoxURL",
        dirs: &["Mozilla Firefox"],
        mac_exe: "firefox",
        mac_bundle: "org.mozilla.firefox",
        store: FIREFOX_ADD_ONS,
    },
];

pub fn browser(id: &str) -> Option<&'static Browser> {
    BROWSERS.iter().find(|b| b.id == id)
}

/// The browser whose https ProgId this is.
pub fn browser_for_prog_id(prog_id: &str) -> Option<&'static Browser> {
    let lower = prog_id.trim().to_ascii_lowercase();
    BROWSERS
        .iter()
        .find(|b| lower.starts_with(&b.prog_id.to_ascii_lowercase()))
}

/// Whether `exe` sits in one of `browser`'s install folders: `...\Programs\Opera GX\opera.exe` is not Opera's.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn in_browser_dir(exe: &Path, browser: &Browser) -> bool {
    // As text, so a Windows path reads the same on every OS (and in the tests).
    let path = exe.to_string_lossy().replace('/', "\\").to_lowercase();
    let folder = path
        .rsplit_once('\\')
        .map(|(dir, _)| dir)
        .unwrap_or_default();
    browser.dirs.iter().any(|d| {
        let d = d.replace('/', "\\").to_lowercase();
        folder == d || folder.ends_with(&format!("\\{d}"))
    })
}

const HOST_EXE: &str = "pass-native-host.exe";
const HOST_EXE_MAC: &str = "pass-native-host";

/// Which browser runs a native host, from `(pid, parent pid, exe name)` rows: the first known
/// browser up the parent chain (Chrome starts the host through `cmd.exe`). `Some("other")` for an
/// unknown browser, `None` when no host runs.
pub fn host_browser(procs: &[(u32, u32, String)]) -> Option<&'static str> {
    let mut found = None;
    for (_, parent, _) in procs.iter().filter(|(_, _, name)| {
        name.eq_ignore_ascii_case(HOST_EXE) || name.eq_ignore_ascii_case(HOST_EXE_MAC)
    }) {
        let mut pid = *parent;
        for _ in 0..4 {
            let Some((_, next, name)) = procs.iter().find(|(p, _, _)| *p == pid) else {
                break;
            };
            if let Some(b) = BROWSERS
                .iter()
                .find(|b| name.eq_ignore_ascii_case(b.exe) || name.eq_ignore_ascii_case(b.mac_exe))
            {
                return Some(b.id);
            }
            if *next == pid {
                break;
            }
            pid = *next;
        }
        found = Some("other");
    }
    found
}

/// A file in a folder a sync client keeps (OneDrive, Dropbox, Google Drive, iCloud, Syncthing): one
/// of `roots`, or a path component naming one. On macOS these live under `~/Library/CloudStorage`
/// and `~/Library/Mobile Documents` (iCloud).
pub fn in_synced_folder(path: &Path, roots: &[PathBuf]) -> bool {
    let norm = |p: &Path| p.to_string_lossy().replace('/', "\\").to_lowercase();
    let file = norm(path);
    if roots.iter().any(|r| {
        let root = norm(r);
        let root = root.trim_end_matches('\\');
        !root.is_empty() && file.starts_with(&format!("{root}\\"))
    }) {
        return true;
    }
    let names: Vec<String> = path
        .parent()
        .map(|dir| {
            dir.components()
                .map(|c| c.as_os_str().to_string_lossy().to_lowercase())
                .collect()
        })
        .unwrap_or_default();
    if names.windows(2).any(|pair| {
        pair[0] == "library" && (pair[1] == "cloudstorage" || pair[1] == "mobile documents")
    }) {
        return true;
    }
    path.parent().is_some_and(|dir| {
        dir.components().any(|c| {
            let name = c.as_os_str().to_string_lossy().to_lowercase();
            name.starts_with("onedrive")
                || name == "dropbox"
                || name == "google drive"
                || name == "my drive"
                || name == "icloud drive"
                || name == "iclouddrive"
                || name == "syncthing"
        })
    })
}

/// How a vault leaves this device: "server", "webdav", "google", "folder" (its file is in a sync
/// client's folder, [`in_synced_folder`]), or `None` (only on this device). `roots`: [`cloud_roots`].
pub fn sync_kind(vault: &VaultEntry, roots: &[PathBuf]) -> Option<&'static str> {
    match (&vault.webdav, vault.google_account()) {
        (Some(w), _) if w.is_pass_server() => Some("server"),
        (Some(_), _) => Some("webdav"),
        (_, Some(_)) => Some("google"),
        _ if in_synced_folder(&vault.path, roots) => Some("folder"),
        _ => None,
    }
}

/// No sync and no backup: losing this device loses the vault.
pub fn is_local_only(vault: &VaultEntry, roots: &[PathBuf]) -> bool {
    sync_kind(vault, roots).is_none()
}

/// Whether a sync client keeps the folder of `path` (a location picked in the create form).
#[tauri::command]
pub fn vault_path_synced(path: String) -> bool {
    in_synced_folder(Path::new(path.trim()), &cloud_roots())
}

/// The OneDrive folders (environment) and `%USERPROFILE%\Dropbox`.
pub fn cloud_roots() -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = ["OneDrive", "OneDriveConsumer", "OneDriveCommercial"]
        .iter()
        .filter_map(std::env::var_os)
        .map(PathBuf::from)
        .collect();
    if let Some(home) = dirs::home_dir() {
        roots.push(home.join("Dropbox"));
    }
    // Linux: Dropbox, Nextcloud and ownCloud (their configured folders too), Insync, and GVFS
    // Google Drive mounts (pass_linux::synced).
    #[cfg(target_os = "linux")]
    if let Some(dirs) = pass_linux::connector::Dirs::from_env() {
        let runtime = pass_linux::synced::runtime_dir();
        roots.extend(pass_linux::synced::roots(
            &dirs.home,
            &dirs.config,
            runtime.as_deref(),
        ));
    }
    roots
}

fn exe_dir() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()?
        .parent()
        .map(Path::to_path_buf)
}

/// The app's bundle resources (`bundle.resources`): next to `Pass.exe` on Windows,
/// `Passyble.app/Contents/Resources` on macOS, `/usr/lib/Passyble` for .deb and .rpm and
/// `$APPDIR/usr/lib/Passyble` in the AppImage on Linux. Tauri knows each layout.
pub fn resources(app: &AppHandle) -> Option<PathBuf> {
    use tauri::Manager;
    app.path().resource_dir().ok()
}

/// Looks for an extension file `name` in the bundle resources, then next to the exe (dev run).
fn candidates(resources: Option<&Path>, exe_dir: Option<&Path>, name: &str) -> Vec<PathBuf> {
    [resources, exe_dir]
        .into_iter()
        .flatten()
        .map(|dir| dir.join(name))
        .collect()
}

/// The repo's `Extension/` folder in a debug build (no installer staged a copy).
#[cfg(debug_assertions)]
fn repo_extension() -> Option<PathBuf> {
    Some(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../Extension"))
}

#[cfg(not(debug_assertions))]
fn repo_extension() -> Option<PathBuf> {
    None
}

/// Without `\\?\` (Explorer and the browsers' folder pickers don't take it).
fn plain(path: PathBuf) -> PathBuf {
    let path = std::fs::canonicalize(&path).unwrap_or(path);
    let text = path.to_string_lossy();
    match text.strip_prefix(r"\\?\") {
        Some(rest) if !rest.starts_with("UNC\\") => PathBuf::from(rest),
        _ => path,
    }
}

pub fn extension_dir(resources: Option<&Path>) -> Option<PathBuf> {
    candidates(resources, exe_dir().as_deref(), "extension")
        .into_iter()
        .chain(repo_extension())
        .find(|d| d.join("manifest.json").is_file())
        .map(plain)
}

/// The Firefox package for a temporary add-on (debug builds: `Extension/dist/pass-firefox.zip`).
pub fn firefox_package(resources: Option<&Path>) -> Option<PathBuf> {
    candidates(resources, exe_dir().as_deref(), "extension-firefox.zip")
        .into_iter()
        .chain(repo_extension().map(|d| d.join("dist").join("pass-firefox.zip")))
        .find(|f| f.is_file())
        .map(plain)
}

/// `processes` is also how `platform::browser_window` finds the browser that started the
/// native messaging host.
#[cfg(windows)]
pub(crate) mod win {
    use std::path::PathBuf;

    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
    use winreg::RegKey;

    use super::Browser;

    pub fn processes() -> Vec<(u32, u32, String)> {
        pass_windows::process::all()
    }

    fn app_path(exe: &str) -> Option<PathBuf> {
        let key = format!(r"Software\Microsoft\Windows\CurrentVersion\App Paths\{exe}");
        let wow = format!(r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\{exe}");
        let found = [
            (HKEY_CURRENT_USER, key.as_str()),
            (HKEY_LOCAL_MACHINE, key.as_str()),
            (HKEY_LOCAL_MACHINE, wow.as_str()),
        ]
        .into_iter()
        .filter_map(|(root, key)| RegKey::predef(root).open_subkey(key).ok())
        .filter_map(|k| k.get_value::<String, _>("").ok())
        .map(|v| PathBuf::from(v.trim().trim_matches('"')))
        .find(|p| p.is_file());
        found
    }

    /// The browser's executable: App Paths, else its usual install folders. A name two browsers share
    /// (`opera.exe`) counts only when it points into the browser's own folder.
    pub fn installed(browser: &Browser) -> Option<PathBuf> {
        let shared = super::BROWSERS
            .iter()
            .filter(|b| b.exe.eq_ignore_ascii_case(browser.exe))
            .count()
            > 1;
        app_path(browser.exe)
            .filter(|p| !shared || super::in_browser_dir(p, browser))
            .or_else(|| {
                ["ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"]
                    .iter()
                    .filter_map(std::env::var_os)
                    .flat_map(|base| {
                        browser
                            .dirs
                            .iter()
                            .map(move |d| PathBuf::from(&base).join(d).join(browser.exe))
                    })
                    .find(|p| p.is_file())
            })
    }

    pub fn default_prog_id() -> Option<String> {
        let base = r"Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https";
        ["UserChoiceLatest", "UserChoice"]
            .iter()
            .filter_map(|k| {
                RegKey::predef(HKEY_CURRENT_USER)
                    .open_subkey(format!(r"{base}\{k}"))
                    .ok()
            })
            .find_map(|k| k.get_value::<String, _>("ProgId").ok())
    }
}

/// macOS: libproc's process list, bundle IDs and Launch Services (`pass_macos`).
/// Keeps the Windows module name so callers stay the same.
#[cfg(target_os = "macos")]
pub(crate) mod win {
    use std::path::PathBuf;

    use super::{Browser, BROWSERS};

    pub fn processes() -> Vec<(u32, u32, String)> {
        pass_macos::process::all()
    }

    pub fn installed(browser: &Browser) -> Option<PathBuf> {
        let exe = pass_macos::apps::app_path(browser.mac_bundle)?
            .join("Contents")
            .join("MacOS")
            .join(browser.mac_exe);
        exe.is_file().then_some(exe)
    }

    pub fn default_prog_id() -> Option<String> {
        let id = pass_macos::apps::default_browser()?;
        BROWSERS
            .iter()
            .find(|b| b.mac_bundle.eq_ignore_ascii_case(&id))
            .map(|b| b.prog_id.to_string())
    }
}

/// Linux: `/proc`, browsers found on `PATH` and the default from `xdg-settings` (`pass_linux::apps`).
/// Keeps the Windows module name so callers stay the same.
#[cfg(target_os = "linux")]
pub(crate) mod win {
    use std::path::PathBuf;

    use super::{Browser, BROWSERS};

    pub fn processes() -> Vec<(u32, u32, String)> {
        pass_linux::apps::processes()
    }

    pub fn installed(browser: &Browser) -> Option<PathBuf> {
        pass_linux::apps::find_browser(browser.id)
    }

    pub fn default_prog_id() -> Option<String> {
        let id = pass_linux::apps::default_browser()?;
        BROWSERS
            .iter()
            .find(|b| b.id == id)
            .map(|b| b.prog_id.to_string())
    }
}

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
mod win {
    use std::path::PathBuf;

    use super::Browser;

    pub fn processes() -> Vec<(u32, u32, String)> {
        Vec::new()
    }

    pub fn installed(_browser: &Browser) -> Option<PathBuf> {
        None
    }

    pub fn default_prog_id() -> Option<String> {
        None
    }
}

/// The browser whose extension is connected now (`"other"` if unknown); remembered in `Settings::extension_connected`.
fn connected_now(state: &AppState) -> Option<&'static str> {
    let browser = host_browser(&win::processes());
    if browser.is_some() && !state.settings().extension_connected {
        let _ = state.update_settings(|s| {
            s.extension_connected = true;
            Ok(())
        });
    }
    browser
}

/// The Get started checklist state. Async: the process snapshot must stay off the main thread.
#[tauri::command]
pub async fn get_started(app: AppHandle) -> Value {
    tauri::async_runtime::spawn_blocking(move || get_started_now(&crate::commands::app_state(&app)))
        .await
        .unwrap_or_else(|_| json!({ "show": false }))
}

fn get_started_now(state: &AppState) -> Value {
    let connected = connected_now(state);
    let settings = state.settings();
    let Some(vault) = settings.active() else {
        return json!({ "show": false });
    };
    let agent = state.agent();
    let sync = sync_kind(vault, &cloud_roots());
    json!({
        "show": vault.get_started,
        "browser": settings.extension_connected || connected.is_some(),
        // Unknown (null) while locked.
        "items": agent.as_ref().and_then(|a| a.item_count()),
        "recovery": agent
            .as_ref()
            // Not activity: the windows ask for this on their own.
            .and_then(|a| a.peek_vault())
            .map(|v| crate::recovery::status_json(&v)["exists"].as_bool().unwrap_or(false)),
        "sync": sync,
        // The step-by-step setup isn't finished: the card offers to continue it.
        "setup": settings.setup,
    })
}

/// Records setup progress: `step`, `paused` ("Finish later") or `done` (forgotten so it doesn't reopen).
#[tauri::command]
pub fn setup_progress(
    state: AppState_<'_>,
    step: Option<String>,
    paused: Option<bool>,
    done: Option<bool>,
) -> Res<()> {
    state.update_settings(|s| {
        s.setup = if done == Some(true) {
            None
        } else {
            let old = s.setup.clone().unwrap_or_default();
            Some(crate::settings::SetupProgress::at(
                step.as_deref().unwrap_or(&old.step),
                paused.unwrap_or(false),
            ))
        };
        Ok(())
    })
}

/// Shows (Settings → Help) or hides the checklist. `browser_done`: "I've done it" in the guide.
#[tauri::command]
pub fn get_started_show(
    state: AppState_<'_>,
    show: Option<bool>,
    browser_done: Option<bool>,
) -> Res<()> {
    let id = vaults::active_id(&state)?;
    state.update_settings(|s| {
        if let Some(show) = show {
            if let Some(v) = s.vault_mut(&id) {
                v.get_started = show;
            }
        }
        if browser_done == Some(true) {
            s.extension_connected = true;
        }
        Ok(())
    })
}

#[tauri::command]
pub fn extension_setup(app: AppHandle, state: AppState_<'_>) -> Value {
    let settings = state.settings();
    let nh = native_messaging::register(&settings.extra_extension_ids);
    let default = win::default_prog_id()
        .as_deref()
        .and_then(browser_for_prog_id)
        .map(|b| b.id);
    let browsers: Vec<Value> = BROWSERS
        .iter()
        .map(|b| {
            json!({
                "id": b.id,
                "name": b.name,
                "page": b.page,
                "installed": win::installed(b).is_some(),
                "default": default == Some(b.id),
                "registered": match b.id {
                    "chrome" => nh.chrome,
                    "edge" => nh.edge,
                    "brave" => nh.brave,
                    "chromium" => nh.chromium,
                    "opera" => nh.opera,
                    "opera-gx" => nh.opera_gx,
                    _ => nh.firefox,
                },
            })
        })
        .collect();
    json!({
        "browsers": browsers,
        "folder": extension_dir(resources(&app).as_deref()),
        "firefox_package": firefox_package(resources(&app).as_deref()),
        "host_exists": nh.host_exists,
        "native_error": nh.error,
        "connected": connected_now(&state),
    })
}

/// Polled while the guide is open: the connected browser's id, or null. Async, like [`get_started`].
#[tauri::command]
pub async fn extension_connected(app: AppHandle) -> Option<&'static str> {
    tauri::async_runtime::spawn_blocking(move || connected_now(&crate::commands::app_state(&app)))
        .await
        .ok()
        .flatten()
}

/// Starts `browser` with its extensions page. Chromium ignores internal pages on the command line,
/// so the guide copies the address. Only these fixed addresses are ever passed.
#[tauri::command]
pub fn extension_open_browser(browser: String) -> Res<()> {
    let b = self::browser(&browser).ok_or_else(|| tr!("errors.browser_unknown"))?;
    let exe = win::installed(b).ok_or_else(|| tr!("errors.browser_not_found", browser = b.name))?;
    launch(exe, b.page)
}

/// Opens `browser`'s store page, or the default browser's if it isn't found. Fixed addresses only.
#[tauri::command]
pub fn extension_open_store(browser: String) -> Res<()> {
    let b = self::browser(&browser).ok_or_else(|| tr!("errors.browser_unknown"))?;
    match win::installed(b) {
        Some(exe) => launch(exe, b.store),
        None => crate::platform::open_browser(b.store),
    }
}

fn launch(exe: PathBuf, arg: &str) -> Res<()> {
    let mut child = std::process::Command::new(exe)
        .arg(arg)
        .spawn()
        .map_err(|e| crate::errors::logged(tr!("errors.browser_open"), "open browser", e))?;
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(())
}

fn target(what: &str, browser: Option<&str>, resources: Option<&Path>) -> Res<String> {
    let missing = || tr!("errors.extension_files_missing");
    match what {
        "folder" => extension_dir(resources)
            .map(|p| p.display().to_string())
            .ok_or_else(missing),
        "firefox" => firefox_package(resources)
            .map(|p| p.display().to_string())
            .ok_or_else(missing),
        "page" => browser
            .and_then(self::browser)
            .map(|b| b.page.to_string())
            .ok_or_else(|| tr!("errors.browser_unknown")),
        _ => Err(tr!("errors.browser_unknown")),
    }
}

/// Copies a path or extensions page address (no secret, not cleared).
#[tauri::command]
pub fn extension_copy(app: AppHandle, what: String, browser: Option<String>) -> Res<()> {
    let text = target(&what, browser.as_deref(), resources(&app).as_deref())?;
    arboard::Clipboard::new()
        .and_then(|mut c| c.set_text(text))
        .map_err(|e| crate::errors::logged(tr!("errors.copy_failed"), "clipboard", e))
}

#[tauri::command]
pub fn extension_show(app: AppHandle, what: String) -> Res<()> {
    if what != "folder" && what != "firefox" {
        return Err(tr!("errors.browser_unknown"));
    }
    let path = PathBuf::from(target(&what, None, resources(&app).as_deref())?);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let mut cmd = std::process::Command::new("explorer.exe");
        if path.is_file() {
            cmd.raw_arg(format!("/select,\"{}\"", path.display()));
        } else {
            cmd.arg(&path);
        }
        let mut child = cmd
            .spawn()
            .map_err(|e| crate::errors::logged(tr!("errors.open_folder_failed"), "explorer", e))?;
        std::thread::spawn(move || {
            let _ = child.wait();
        });
        Ok(())
    }
    #[cfg(target_os = "macos")]
    {
        pass_macos::finder::reveal(&path)
            .map_err(|e| crate::errors::logged(tr!("errors.open_folder_failed"), "Finder", e))
    }
    #[cfg(target_os = "linux")]
    {
        pass_linux::files::reveal(&path)
            .map_err(|e| crate::errors::logged(tr!("errors.open_folder_failed"), "file manager", e))
    }
    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    {
        Err(tr!("errors.path_missing", path = path.display()))
    }
}

/// The public downloads page (the Windows setup and release notes): Settings → Help.
pub const RELEASES_URL: &str = "https://github.com/sensyble/pass-releases/releases/latest";

#[tauri::command]
pub fn open_releases_page() -> Res<()> {
    crate::platform::open_browser(RELEASES_URL)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(pid: u32, parent: u32, name: &str) -> (u32, u32, String) {
        (pid, parent, name.to_string())
    }

    #[test]
    fn opera_and_opera_gx_share_opera_exe_but_not_a_folder() {
        let opera = browser("opera").unwrap();
        let gx = browser("opera-gx").unwrap();
        assert_eq!(opera.exe, gx.exe);
        let in_gx = Path::new(r"C:\Users\me\AppData\Local\Programs\Opera GX\opera.exe");
        let in_opera = Path::new(r"C:\Users\me\AppData\Local\Programs\Opera\opera.exe");
        let system = Path::new(r"C:\Program Files\Opera\opera.exe");
        assert!(in_browser_dir(in_gx, gx) && !in_browser_dir(in_gx, opera));
        assert!(in_browser_dir(in_opera, opera) && !in_browser_dir(in_opera, gx));
        assert!(in_browser_dir(system, opera));
        assert!(!in_browser_dir(Path::new(r"C:\Tools\opera.exe"), opera));
        let gx_host = [p(70, 1, "opera.exe"), p(71, 70, "pass-native-host.exe")];
        assert_eq!(host_browser(&gx_host), Some("opera"));
        let mac = [p(80, 1, "Opera GX"), p(81, 80, "pass-native-host")];
        assert_eq!(host_browser(&mac), Some("opera-gx"));
    }

    #[test]
    fn host_browser_walks_up_to_the_browser() {
        assert_eq!(host_browser(&[p(1, 0, "chrome.exe")]), None);
        // Chrome: chrome.exe → cmd.exe → pass-native-host.exe.
        let chrome = [
            p(10, 1, "chrome.exe"),
            p(11, 10, "cmd.exe"),
            p(12, 11, "Pass-Native-Host.exe"),
        ];
        assert_eq!(host_browser(&chrome), Some("chrome"));
        let firefox = [p(20, 1, "firefox.exe"), p(21, 20, "pass-native-host.exe")];
        assert_eq!(host_browser(&firefox), Some("firefox"));
        // A parent that is gone, or a loop: some browser we can't name.
        assert_eq!(
            host_browser(&[p(30, 99, "pass-native-host.exe")]),
            Some("other")
        );
        assert_eq!(
            host_browser(&[p(40, 40, "cmd.exe"), p(41, 40, "pass-native-host.exe")]),
            Some("other")
        );
        // Two hosts: the one with a known browser wins.
        let both = [
            p(50, 99, "pass-native-host.exe"),
            p(60, 1, "msedge.exe"),
            p(61, 60, "pass-native-host.exe"),
        ];
        assert_eq!(host_browser(&both), Some("edge"));
        // macOS: the browser starts the host itself, both named without .exe.
        let mac = [
            p(70, 1, "Google Chrome"),
            p(71, 70, "Google Chrome Helper"),
            p(72, 70, "pass-native-host"),
        ];
        assert_eq!(host_browser(&mac), Some("chrome"));
        let brave = [p(80, 1, "Brave Browser"), p(81, 80, "pass-native-host")];
        assert_eq!(host_browser(&brave), Some("brave"));
    }

    #[test]
    fn extension_files_come_from_the_bundle_first() {
        let resources = Path::new("res");
        let exe = Path::new("bin");
        assert_eq!(
            candidates(Some(resources), Some(exe), "extension"),
            [resources.join("extension"), exe.join("extension")]
        );
        assert_eq!(
            candidates(None, Some(exe), "extension-firefox.zip"),
            [exe.join("extension-firefox.zip")]
        );
        assert!(candidates(None, None, "extension").is_empty());

        // The bundle's copy wins over one beside the exe.
        let dir = std::env::temp_dir().join(format!("pass-guide-test-{}", std::process::id()));
        let bundle = dir.join("Resources");
        let beside = dir.join("MacOS");
        for root in [&bundle, &beside] {
            std::fs::create_dir_all(root.join("extension")).unwrap();
            std::fs::write(root.join("extension").join("manifest.json"), "{}").unwrap();
        }
        let found = candidates(Some(&bundle), Some(&beside), "extension")
            .into_iter()
            .find(|d| d.join("manifest.json").is_file());
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(found, Some(bundle.join("extension")));
    }

    #[test]
    fn mac_cloud_folders_are_synced() {
        let synced = |p: &str| in_synced_folder(Path::new(p), &[]);
        assert!(synced(
            "/Users/me/Library/CloudStorage/GoogleDrive-me@example.com/My Drive/pass.vault"
        ));
        assert!(synced("/Users/me/Library/CloudStorage/Box-Box/pass.vault"));
        assert!(synced(
            "/Users/me/Library/Mobile Documents/com~apple~CloudDocs/Pass/pass.vault"
        ));
        assert!(!synced(
            "/Users/me/Library/Application Support/Pass/pass.vault"
        ));
        assert!(!synced("/Users/me/Documents/CloudStorage/pass.vault"));
    }

    #[test]
    fn prog_ids_and_browsers() {
        assert_eq!(
            browser_for_prog_id("ChromeHTML").map(|b| b.id),
            Some("chrome")
        );
        assert_eq!(browser_for_prog_id("MSEdgeHTM").map(|b| b.id), Some("edge"));
        assert_eq!(
            browser_for_prog_id("BraveHTML").map(|b| b.id),
            Some("brave")
        );
        assert_eq!(
            browser_for_prog_id("FirefoxURL-308046B0AF4A39CB").map(|b| b.id),
            Some("firefox")
        );
        assert_eq!(
            browser_for_prog_id("OperaStable").map(|b| b.id),
            Some("opera")
        );
        assert_eq!(
            browser_for_prog_id("OperaGXStable").map(|b| b.id),
            Some("opera-gx")
        );
        assert!(browser_for_prog_id("VivaldiHTM").is_none());
        assert!(browser("chrome").is_some());
        assert!(browser("chrome://extensions").is_none());
        // Only fixed browser pages, never a web address (Opera GX uses Opera's pages, Chromium
        // Chrome's).
        for b in BROWSERS {
            let scheme = match b.id {
                "chromium" => "chrome",
                id => id.split('-').next().unwrap_or(id),
            };
            assert!(b.page.starts_with(&format!("{scheme}://")) || b.page.starts_with("about:"));
        }
        assert_eq!(
            browser_for_prog_id("ChromiumHTM").map(|b| b.id),
            Some("chromium")
        );
    }

    #[test]
    fn synced_folders() {
        let roots = [
            PathBuf::from(r"C:\Users\Me\OneDrive"),
            PathBuf::from(r"C:\Users\Me\Dropbox"),
        ];
        let yes = |p: &str| in_synced_folder(Path::new(p), &roots);
        assert!(yes(r"C:\Users\Me\OneDrive\Pass\pass.vault"));
        assert!(yes(r"c:/users/me/dropbox/pass.vault"));
        assert!(!yes(r"C:\Users\Me\OneDriveX.vault"));
        assert!(!yes(r"C:\Users\Me\AppData\Roaming\Pass\pass.vault"));
        // Folder names are path components: `\` separates them only on Windows.
        #[cfg(windows)]
        {
            assert!(yes(r"D:\OneDrive - Contoso\pass.vault"));
            assert!(yes(r"G:\My Drive\Pass\pass.vault"));
            // Without the environment's roots, a folder named like a sync client still counts.
            assert!(in_synced_folder(Path::new(r"E:\Dropbox\pass.vault"), &[]));
        }
        #[cfg(unix)]
        {
            assert!(yes("/media/me/OneDrive - Contoso/pass.vault"));
            assert!(yes("/home/me/My Drive/Pass/pass.vault"));
            assert!(in_synced_folder(
                Path::new("/home/me/Dropbox/pass.vault"),
                &[]
            ));
        }
    }

    #[test]
    fn local_only_means_no_sync_and_no_backup() {
        use crate::settings::{GoogleDriveSettings, WebDavSettings};
        let roots = [PathBuf::from(r"C:\Users\Me\OneDrive")];
        let vault = |path: &str| VaultEntry {
            id: "v".into(),
            path: PathBuf::from(path),
            ..Default::default()
        };
        // The default location in the app's folder, or any other folder no sync client keeps.
        let plain = vault(r"C:\Users\Me\AppData\Roaming\Pass\pass.vault");
        assert_eq!(sync_kind(&plain, &roots), None);
        assert!(is_local_only(&plain, &roots));
        assert!(is_local_only(
            &vault(r"C:\Users\Me\Documents\pass.vault"),
            &roots
        ));

        let folder = vault(r"C:\Users\Me\OneDrive\Pass\pass.vault");
        assert_eq!(sync_kind(&folder, &roots), Some("folder"));
        assert!(!is_local_only(&folder, &roots));

        let mut webdav = plain.clone();
        webdav.webdav = Some(WebDavSettings {
            url: "https://cloud.example.com/dav/pass.vault".into(),
            username: "me".into(),
            ..Default::default()
        });
        assert_eq!(sync_kind(&webdav, &roots), Some("webdav"));
        assert!(!is_local_only(&webdav, &roots));
        let mut server = webdav.clone();
        server.webdav.as_mut().unwrap().server_device = Some("This PC".into());
        assert_eq!(sync_kind(&server, &roots), Some("server"));
        assert!(!is_local_only(&server, &roots));
        let mut google = plain.clone();
        google.google_drive = Some(GoogleDriveSettings {
            account_email: "me@example.com".into(),
            sign_in_needed: false,
        });
        assert_eq!(sync_kind(&google, &roots), Some("google"));
        assert!(!is_local_only(&google, &roots));
        // Still backed up while Google asks to sign in again (sync is only paused).
        google.google_drive.as_mut().unwrap().sign_in_needed = true;
        assert!(!is_local_only(&google, &roots));
        google.google_drive.as_mut().unwrap().account_email = " ".into();
        assert!(is_local_only(&google, &roots));
    }

    /// Linux: the roots of Nextcloud, Insync and GVFS Google Drive count (pass_linux::synced).
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_synced_roots() {
        let roots = [
            PathBuf::from("/home/me/Nextcloud"),
            PathBuf::from("/run/user/1000/gvfs/google-drive:host=gmail.com,user=me"),
        ];
        let yes = |p: &str| in_synced_folder(Path::new(p), &roots);
        assert!(yes("/home/me/Nextcloud/Pass/pass.vault"));
        assert!(yes(
            "/run/user/1000/gvfs/google-drive:host=gmail.com,user=me/0AbC/pass.vault"
        ));
        assert!(!yes("/home/me/NextcloudX/pass.vault"));
        assert!(!yes("/home/me/Documents/pass.vault"));
    }

    #[test]
    fn every_browser_opens_its_own_store() {
        let store = |id: &str| browser(id).unwrap().store;
        for id in ["chrome", "brave", "chromium"] {
            assert_eq!(store(id), "https://chromewebstore.google.com/search/Passyble");
        }
        assert!(store("edge").starts_with("https://microsoftedge.microsoft.com/addons/"));
        assert!(store("opera").starts_with("https://addons.opera.com/"));
        assert_eq!(store("opera-gx"), store("opera"));
        assert_eq!(store("firefox"), "https://addons.mozilla.org/firefox/addon/passyble/");
        assert!(BROWSERS.iter().all(|b| b.store.starts_with("https://")));
    }

    #[test]
    fn chromium_shares_chrome_exe_but_not_its_folder() {
        let chrome = browser("chrome").unwrap();
        let chromium = browser("chromium").unwrap();
        assert_eq!(chrome.exe, chromium.exe);
        let own = Path::new(r"C:\Users\me\AppData\Local\Chromium\Application\chrome.exe");
        let google = Path::new(r"C:\Program Files\Google\Chrome\Application\chrome.exe");
        assert!(in_browser_dir(own, chromium) && !in_browser_dir(own, chrome));
        assert!(in_browser_dir(google, chrome) && !in_browser_dir(google, chromium));
        // A host Chromium starts is Chrome's on Windows (both run chrome.exe), Chromium's on a Mac.
        assert_eq!(
            host_browser(&[p(1, 0, "chrome.exe"), p(2, 1, "pass-native-host.exe")]),
            Some("chrome")
        );
        assert_eq!(
            host_browser(&[p(1, 0, "Chromium"), p(2, 1, "pass-native-host")]),
            Some("chromium")
        );
    }

    #[test]
    fn copy_targets_are_fixed() {
        assert_eq!(
            target("page", Some("edge"), None).unwrap(),
            "edge://extensions"
        );
        assert!(target("page", Some("https://example.com"), None).is_err());
        assert!(target("page", None, None).is_err());
        assert!(target("C:\\Windows", None, None).is_err());
    }
}
