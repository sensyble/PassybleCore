//! Forced and recommended updates: the owner sets a minimum and a recommended version per platform in the admin console;
//! `GET https://account.passyble.com/api/app-versions` serves them and this app reads its platform's entry.
//!
//! * The request is anonymous (no cookies, account, device or vault data, no version) and follows Settings → Startup &
//!   updates → "Check for updates automatically". Release builds ask at start and every 6 hours (30 minutes after a
//!   failure); debug builds only when `app_versions_endpoint` points at a test server.
//! * The last good answer is cached in `%LOCALAPPDATA%\Pass\app-versions.json`. With nothing ever fetched, nothing is
//!   blocked. A malformed value counts as no requirement.
//! * Below the minimum: read-only mode (`Agent::set_update_required`) and the "Update required" screen, whose Update
//!   button uses the in-app updater when possible, else opens [`DOWNLOAD_PAGE`]. Below the recommended version: the
//!   "Update available" banner, closed per version.

use std::path::PathBuf;
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, SystemTime};

use pass_agent::app_versions::{Cache, Requirement, ENDPOINT};
use serde_json::{json, Value};
use tauri::{AppHandle, Emitter};

use crate::applog::plog;
use crate::commands::app_state;
use crate::state::lock;

pub const PLATFORM: &str = if cfg!(target_os = "macos") {
    "macos"
} else if cfg!(target_os = "linux") {
    "linux"
} else {
    "windows"
};

/// Where the Update button goes when this copy can't install an update itself (a managed MSI install, a build
/// without the updater, a .deb or .rpm, macOS until its updater is on; see `updates::UpdateWay`).
pub const DOWNLOAD_PAGE: &str = "https://www.passyble.com/download";

const CHECK_EVERY: Duration = Duration::from_secs(6 * 60 * 60);
const RETRY_AFTER: Duration = Duration::from_secs(30 * 60);
/// How often the checker looks at the clock (wall time, so sleep and hibernation count).
const POLL: Duration = Duration::from_secs(5 * 60);
#[cfg_attr(not(feature = "webdav"), allow(dead_code))]
const TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Default)]
struct State {
    cache: Cache,
    requirement: Option<Requirement>,
}

static STATE: Mutex<Option<State>> = Mutex::new(None);

fn with_state<T>(f: impl FnOnce(&mut State) -> T) -> T {
    let mut guard = lock(&STATE);
    f(guard.get_or_insert_with(State::default))
}

fn cache_path() -> PathBuf {
    crate::settings::local_dir().join("app-versions.json")
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64)
}

fn current(app: &AppHandle) -> String {
    app.package_info().version.to_string()
}

/// Reads the cached answer and applies it, before the agent exists (so a blocked app starts
/// read-only, offline too).
pub fn init(app: &AppHandle) {
    let cache = Cache::load(&cache_path());
    let requirement = cache.requirement(&current(app), PLATFORM);
    if requirement.is_required() {
        plog!("app versions: below the minimum version (cached answer): read-only");
    }
    with_state(|s| {
        s.cache = cache;
        s.requirement = Some(requirement);
    });
}

pub fn blocked() -> bool {
    with_state(|s| s.requirement.as_ref().is_some_and(Requirement::is_required))
}

pub fn status(app: &AppHandle) -> Value {
    let (requirement, dismissed) = with_state(|s| {
        let requirement = s.requirement.clone().unwrap_or(Requirement::None);
        let dismissed = match &requirement {
            Requirement::Recommended { version, .. } => s.cache.is_dismissed(version),
            _ => false,
        };
        (requirement, dismissed)
    });
    let mut value = serde_json::to_value(&requirement).unwrap_or_else(|_| json!({}));
    value["current"] = json!(current(app));
    value["dismissed"] = json!(dismissed);
    value["self_update"] = json!(crate::updates::can_self_update(app));
    value
}

fn apply(app: &AppHandle) {
    let blocked = blocked();
    if let Some(agent) = app_state(app).agent() {
        agent.set_update_required(blocked);
    }
    let _ = app.emit("app-versions", status(app));
}

/// `app_versions_endpoint` from settings.json when it is an http(s) URL, else [`ENDPOINT`].
fn endpoint(app: &AppHandle) -> String {
    app_state(app)
        .settings()
        .app_versions_endpoint
        .map(|e| e.trim().to_string())
        .filter(|e| e.starts_with("https://") || e.starts_with("http://"))
        .unwrap_or_else(|| ENDPOINT.to_string())
}

#[cfg(feature = "webdav")]
fn fetch(url: &str) -> Option<String> {
    use std::io::Read;
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(TIMEOUT)
        .timeout(TIMEOUT)
        .redirects(0)
        .build();
    let response = match agent
        .get(url)
        .set("Accept", "application/json")
        .set("User-Agent", "Passyble")
        .call()
    {
        Ok(r) => r,
        Err(e) => {
            plog!("app versions: no answer: {e}");
            return None;
        }
    };
    if response.status() != 200 {
        return None;
    }
    let mut body = String::new();
    let limit = pass_agent::app_versions::MAX_BODY as u64 + 1;
    response
        .into_reader()
        .take(limit)
        .read_to_string(&mut body)
        .ok()?;
    Some(body)
}

#[cfg(not(feature = "webdav"))]
fn fetch(_url: &str) -> Option<String> {
    None
}

/// Asks the server once (blocking) and applies the answer, or the cached one; `true` if a good answer came.
pub fn refresh(app: &AppHandle) -> bool {
    let body = fetch(&endpoint(app));
    let current = current(app);
    let (fresh, was, now) = with_state(|s| {
        let fresh = s.cache.record(body.as_deref(), now_ms());
        if fresh {
            if let Err(e) = s.cache.save(&cache_path()) {
                plog!("app versions: couldn't keep the answer: {e}");
            }
        }
        let was = s.requirement.as_ref().is_some_and(Requirement::is_required);
        let requirement = s.cache.requirement(&current, PLATFORM);
        let now = requirement.is_required();
        s.requirement = Some(requirement);
        (fresh, was, now)
    });
    if was != now {
        plog!(
            "app versions: {}",
            if now {
                "below the minimum version: read-only"
            } else {
                "the minimum version is met"
            }
        );
    }
    apply(app);
    fresh
}

pub fn refresh_soon(app: &AppHandle) {
    let app = app.clone();
    let _ = thread::Builder::new()
        .name("pass-app-versions-now".into())
        .spawn(move || {
            refresh(&app);
        });
}

/// Automatic checks: the setting on, in release builds or with a test endpoint.
fn automatic_checks_allowed(app: &AppHandle) -> bool {
    let settings = app_state(app).settings();
    settings.update_auto_check && (!cfg!(debug_assertions) || settings.app_versions_endpoint.is_some())
}

pub fn start(app: &AppHandle) {
    let app = app.clone();
    let _ = thread::Builder::new()
        .name("pass-app-versions".into())
        .spawn(move || {
            let mut next = SystemTime::now();
            loop {
                if SystemTime::now() >= next && automatic_checks_allowed(&app) {
                    let ok = refresh(&app);
                    next = SystemTime::now() + if ok { CHECK_EVERY } else { RETRY_AFTER };
                }
                thread::sleep(POLL);
            }
        });
}

#[tauri::command]
pub fn app_versions_status(app: AppHandle) -> Value {
    status(&app)
}

/// Closes "Update available" for recommended `version` (it shows again for a higher one).
#[tauri::command]
pub fn app_versions_dismiss(app: AppHandle, version: String) -> Value {
    with_state(|s| {
        if matches!(&s.requirement, Some(Requirement::Recommended { version: v, .. }) if *v == version)
        {
            s.cache.dismissed = Some(version);
            if let Err(e) = s.cache.save(&cache_path()) {
                plog!("app versions: couldn't keep the dismissal: {e}");
            }
        }
    });
    let status = status(&app);
    let _ = app.emit("app-versions", status.clone());
    status
}

/// The Update button: the in-app updater when this copy can update itself and a newer version
/// is out (download, install, restart), else the download page in the browser.
#[tauri::command]
pub async fn app_versions_update(app: AppHandle) -> Result<Value, String> {
    if crate::updates::can_self_update(&app) {
        if !crate::updates::update_found() {
            let _ = crate::updates::check(&app).await;
        }
        if crate::updates::update_found() {
            crate::updates::update_install(app).await?;
            return Ok(json!({ "installing": true }));
        }
    }
    crate::platform::open_browser(DOWNLOAD_PAGE)?;
    Ok(json!({ "opened": DOWNLOAD_PAGE }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_platform_key_is_this_os() {
        let expected = if cfg!(windows) {
            "windows"
        } else if cfg!(target_os = "linux") {
            "linux"
        } else {
            "macos"
        };
        assert_eq!(PLATFORM, expected);
    }

    #[test]
    fn the_update_destination_is_built_in() {
        assert_eq!(DOWNLOAD_PAGE, "https://www.passyble.com/download");
        assert_eq!(ENDPOINT, "https://account.passyble.com/api/app-versions");
    }

    #[test]
    fn this_platform_reads_its_own_entry() {
        let mut cache = Cache::default();
        let doc = serde_json::json!({ "v": 1, "platforms": {
            PLATFORM: { "minimum": "99.0.0", "message": "Security fix" },
            "android": { "minimum": "0.0.1" },
        }})
        .to_string();
        assert!(cache.record(Some(&doc), 1));
        assert!(cache.requirement("0.1.0", PLATFORM).is_required());
        let other = if PLATFORM == "linux" { "windows" } else { "linux" };
        assert_eq!(cache.requirement("0.1.0", other), Requirement::None);
    }
}
