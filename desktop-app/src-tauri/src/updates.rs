//! In-app updates (Settings → Startup & updates).
//!
//! * The release publishes installers, their minisign signatures and one `latest.json` for every
//!   platform. Pass asks `…/releases/latest/download/latest.json` (`plugins.updater.endpoints`, or
//!   `update_endpoints` in settings.json for testing) and only installs a download whose signature
//!   matches the compiled-in public key and whose signed version (`requireSignedVersion`) is the one
//!   the manifest announced, so a tampered `latest.json` can't pass off an older signed release.
//! * Fail closed: without a well-formed public key, or with a `dangerous…` / `allowDowngrades`
//!   switch on or `requireSignedVersion` off, updates are off altogether ([`config_problem`]).
//! * Checks run about a minute after start, then daily while "Check automatically" is on, and on
//!   "Check for updates". A found update only sets a quiet badge, never a dialog.
//! * "Update and restart": download, save and lock the vault (a vault that can't be saved stops the
//!   update), run the installer in passive mode and exit; an AppImage replaces its file instead.
//! * Only the per-user NSIS install on Windows and an AppImage on Linux update themselves
//!   ([`install_kind`], [`UpdateWay`]); a Mac only with the `macos-updater` feature, which stays off
//!   until releases are notarized. The .deb and .rpm show "Version X available" with a link.
//! * Managed installs (the per-machine MSI) never install in-app ([`managed_install`]): no automatic
//!   checks, and Settings says to update with the new MSI.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use serde_json::{json, Value};
use tauri::utils::{config::BundleType, platform::bundle_type};
use tauri::{AppHandle, Emitter, Url};
use tauri_plugin_updater::{Update, UpdaterExt};

use crate::applog::plog;
use crate::commands::app_state;
use crate::i18n::tr;
use crate::state::lock;

const FIRST_CHECK_DELAY: Duration = Duration::from_secs(60);
const CHECK_EVERY: Duration = Duration::from_secs(24 * 60 * 60);
const RETRY_AFTER: Duration = Duration::from_secs(60 * 60);
const POLL: Duration = Duration::from_secs(10 * 60);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const NOTES_MAX: usize = 280;

#[derive(Default)]
struct UpdateState {
    checking: bool,
    last_check_ms: Option<i64>,
    error: Option<String>,
    /// A newer version was found; installing it needs no second check.
    update: Option<Update>,
    notes_url: Option<String>,
    up_to_date: bool,
    progress: Option<(u64, Option<u64>)>,
    installing: bool,
}

static STATE: Mutex<Option<UpdateState>> = Mutex::new(None);

fn with_state<T>(f: impl FnOnce(&mut UpdateState) -> T) -> T {
    let mut guard = lock(&STATE);
    f(guard.get_or_insert_with(UpdateState::default))
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64)
}

fn base64_decode(text: &str) -> Option<Vec<u8>> {
    fn value(c: u8) -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32)
    }
    let bytes = text.as_bytes();
    if bytes.is_empty() || !bytes.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for (i, quad) in bytes.chunks(4).enumerate() {
        let last = i == bytes.len() / 4 - 1;
        let pad = quad.iter().rev().take_while(|&&c| c == b'=').count();
        if pad > 2 || (pad > 0 && !last) {
            return None;
        }
        let mut n = 0u32;
        for &c in &quad[..4 - pad] {
            n = (n << 6) | value(c)?;
        }
        n <<= 6 * pad as u32;
        out.extend_from_slice(&n.to_be_bytes()[1..4 - pad]);
    }
    Some(out)
}

/// The key id of a minisign Ed25519 public key as `cargo tauri signer generate` writes it
/// (`plugins.updater.pubkey`); none for an empty, placeholder or malformed value.
fn pubkey_id(pubkey: &str) -> Option<[u8; 8]> {
    let text = String::from_utf8(base64_decode(pubkey.trim())?).ok()?;
    let mut lines = text.lines();
    if !lines.next()?.starts_with("untrusted comment:") {
        return None;
    }
    let raw = base64_decode(lines.next()?.trim())?;
    if raw.len() != 42 || &raw[..2] != b"Ed" || raw[10..].iter().all(|&b| b == 0) {
        return None;
    }
    raw[2..10].try_into().ok()
}

/// Why this build must not update itself: no real public key, or a relaxed check. Fail closed.
fn config_problem(updater: Option<&Value>) -> Option<&'static str> {
    let Some(updater) = updater else {
        return Some("no updater configuration");
    };
    if updater["pubkey"].as_str().and_then(pubkey_id).is_none() {
        return Some("no valid update signing public key (plugins.updater.pubkey)");
    }
    if updater["requireSignedVersion"] != Value::Bool(true) {
        return Some("plugins.updater.requireSignedVersion is not on");
    }
    let relaxed = [
        "allowDowngrades",
        "dangerousInsecureTransportProtocol",
        "dangerousAcceptInvalidCerts",
        "dangerousAcceptInvalidHostnames",
    ];
    if relaxed
        .iter()
        .any(|key| !matches!(updater.get(*key), None | Some(Value::Bool(false))))
    {
        return Some("a plugins.updater safety check is turned off");
    }
    None
}

fn is_under(exe: &Path, roots: &[PathBuf]) -> bool {
    let norm = |p: &Path| p.to_string_lossy().replace('/', "\\").to_lowercase();
    let exe = norm(exe);
    roots.iter().any(|root| {
        let root = norm(root);
        let root = root.trim_end_matches('\\');
        !root.is_empty() && exe.starts_with(&format!("{root}\\"))
    })
}

/// How this copy of Passyble was installed, which decides what "update" means for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstallKind {
    Nsis,
    /// Windows, per machine: the MSI, or running from Program Files (the per-user NSIS update would not replace it).
    Msi,
    AppImage,
    /// Linux .deb or .rpm (or any non-AppImage copy), and any other OS: the package manager owns the files.
    LinuxPackage,
    Mac,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpdateWay {
    InApp,
    DownloadPage,
    Managed,
}

impl UpdateWay {
    fn name(self) -> &'static str {
        match self {
            UpdateWay::InApp => "in_app",
            UpdateWay::DownloadPage => "download",
            UpdateWay::Managed => "managed",
        }
    }
}

/// Built with the `macos-updater` feature: Mac releases are signed with a Developer ID and notarized.
const MAC_UPDATER: bool = cfg!(feature = "macos-updater");

/// [`InstallKind`] from what the running copy knows about itself: `os` is `std::env::consts::OS`,
/// `bundle` Tauri's `bundle_type()`, `appimage` whether it runs from an AppImage, `in_program_files`
/// whether the executable is under Program Files.
fn install_kind_for(
    os: &str,
    bundle: Option<BundleType>,
    appimage: bool,
    in_program_files: bool,
) -> InstallKind {
    match os {
        "windows" if in_program_files || matches!(bundle, Some(BundleType::Msi)) => {
            InstallKind::Msi
        }
        "windows" => InstallKind::Nsis,
        "macos" => InstallKind::Mac,
        // A .deb or .rpm build started from an AppImage's environment is still the package.
        "linux" if appimage && !matches!(bundle, Some(BundleType::Deb | BundleType::Rpm)) => {
            InstallKind::AppImage
        }
        // Linux packages, and any other OS: never installs updates itself.
        _ => InstallKind::LinuxPackage,
    }
}

fn update_way(kind: InstallKind, mac_updater: bool) -> UpdateWay {
    match kind {
        InstallKind::Nsis | InstallKind::AppImage => UpdateWay::InApp,
        InstallKind::Mac if mac_updater => UpdateWay::InApp,
        InstallKind::Mac | InstallKind::LinuxPackage => UpdateWay::DownloadPage,
        InstallKind::Msi => UpdateWay::Managed,
    }
}

/// Whether an install of `kind` asks `latest.json` at all. A Mac doesn't until the macOS updater
/// is on (it would only get "no update for this Mac"); App versions tells it about new versions.
fn reads_feed(kind: InstallKind, mac_updater: bool) -> bool {
    kind != InstallKind::Mac || mac_updater
}

#[cfg(target_os = "linux")]
fn running_from_appimage() -> bool {
    crate::platform::running_from_appimage()
}

#[cfg(not(target_os = "linux"))]
fn running_from_appimage() -> bool {
    false
}

pub fn install_kind() -> InstallKind {
    static KIND: OnceLock<InstallKind> = OnceLock::new();
    *KIND.get_or_init(|| {
        let roots: Vec<PathBuf> = ["ProgramFiles", "ProgramW6432", "ProgramFiles(x86)"]
            .iter()
            .filter_map(std::env::var_os)
            .map(PathBuf::from)
            .collect();
        let in_program_files =
            cfg!(windows) && std::env::current_exe().is_ok_and(|exe| is_under(&exe, &roots));
        install_kind_for(
            std::env::consts::OS,
            bundle_type(),
            running_from_appimage(),
            in_program_files,
        )
    })
}

fn way() -> UpdateWay {
    update_way(install_kind(), MAC_UPDATER)
}

/// Installed per machine from the MSI; the administrator deploys a newer MSI.
pub fn managed_install() -> bool {
    install_kind() == InstallKind::Msi
}

fn disabled_reason(app: &AppHandle) -> Option<&'static str> {
    config_problem(app.config().plugins.0.get("updater"))
}

/// This copy asks the update feed ([`reads_feed`]).
fn feed_on(app: &AppHandle) -> bool {
    disabled_reason(app).is_none() && reads_feed(install_kind(), MAC_UPDATER)
}

/// This copy can install an update itself ([`UpdateWay::InApp`]); otherwise the "Update required"
/// screen opens the download page.
pub fn can_self_update(app: &AppHandle) -> bool {
    disabled_reason(app).is_none() && way() == UpdateWay::InApp
}

pub fn update_found() -> bool {
    with_state(|s| s.update.is_some())
}

pub fn status(app: &AppHandle) -> Value {
    let settings = app_state(app).settings();
    with_state(|s| {
        json!({
            "current": app.package_info().version.to_string(),
            "auto_check": settings.update_auto_check,
            "checking": s.checking,
            "last_check_ms": s.last_check_ms,
            "error": s.error,
            "up_to_date": s.up_to_date && s.update.is_none(),
            "available": s.update.as_ref().map(|u| json!({
                "version": u.version,
                "notes": u.body.as_deref().map(short_notes).filter(|n| !n.is_empty()),
                "notes_url": s.notes_url,
            })),
            "downloading": s.progress.map(|(done, total)| json!({ "done": done, "total": total })),
            "installing": s.installing,
            "managed": managed_install(),
            // What a found update leads to: "in_app", "download" (a link: .deb, .rpm, macOS without its updater) or "managed" (MSI).
            "way": way().name(),
            "self_update": can_self_update(app),
            "enabled": feed_on(app),
        })
    })
}

fn emit(app: &AppHandle) {
    let _ = app.emit_to("main", "update-state", status(app));
}

fn short_notes(body: &str) -> String {
    let text = body.split_whitespace().collect::<Vec<_>>().join(" ");
    if text.chars().count() <= NOTES_MAX {
        return text;
    }
    let cut: String = text.chars().take(NOTES_MAX).collect();
    let cut = cut.rsplit_once(' ').map_or(cut.as_str(), |(head, _)| head);
    format!("{cut}…")
}

/// `https://github.com/<owner>/<repo>/releases/tag/v<version>` for a manifest served from a
/// GitHub release (`…/releases/latest/download/latest.json`), else none.
fn release_page(endpoint: &str, version: &str) -> Option<String> {
    let rest = endpoint.strip_prefix("https://github.com/")?;
    let mut parts = rest.split('/');
    let (owner, repo) = (parts.next()?, parts.next()?);
    (parts.next()? == "releases" && !owner.is_empty() && !repo.is_empty())
        .then(|| format!("https://github.com/{owner}/{repo}/releases/tag/v{version}"))
}

fn custom_endpoints(app: &AppHandle) -> Vec<Url> {
    app_state(app)
        .settings()
        .update_endpoints
        .iter()
        .filter_map(|e| match Url::parse(e.trim()) {
            Ok(url) if matches!(url.scheme(), "https" | "http") => Some(url),
            _ => {
                plog!("updates: ignoring update endpoint {e:?} (not an http(s) URL)");
                None
            }
        })
        .collect()
}

fn first_endpoint(app: &AppHandle) -> Option<String> {
    custom_endpoints(app)
        .first()
        .map(|u| u.to_string())
        .or_else(|| {
            let config = app.config().plugins.0.get("updater")?;
            config["endpoints"].get(0)?.as_str().map(str::to_string)
        })
}

fn friendly(e: tauri_plugin_updater::Error) -> String {
    use tauri_plugin_updater::Error as E;
    match e {
        E::Reqwest(_) | E::Network(_) => tr!("errors.update_unreachable"),
        E::ReleaseNotFound => tr!("errors.update_no_info"),
        E::Minisign(_)
        | E::Base64(_)
        | E::SignatureUtf8(_)
        | E::SignedVersionMismatch { .. }
        | E::MissingSignedVersion => tr!("errors.update_signature"),
        E::TargetNotFound(_) | E::TargetsNotFound(_) => tr!("errors.update_no_target"),
        other => crate::errors::logged(tr!("errors.update_failed"), "updates", other),
    }
}

/// Asks the update server once. Does nothing while a check, download or install is running.
pub async fn check(app: &AppHandle) -> Result<(), String> {
    let busy = with_state(|s| {
        let busy = s.checking || s.progress.is_some() || s.installing;
        if !busy {
            s.checking = true;
            s.error = None;
        }
        busy
    });
    if busy {
        return Ok(());
    }
    if !reads_feed(install_kind(), MAC_UPDATER) {
        // A Mac without the macOS updater: the feed has nothing for it (see [`reads_feed`]).
        with_state(|s| s.checking = false);
        emit(app);
        return Ok(());
    }
    if let Some(reason) = disabled_reason(app) {
        plog!("updates: turned off in this build: {reason}");
        let message = tr!("errors.updates_off");
        with_state(|s| {
            s.checking = false;
            s.error = Some(message.clone());
        });
        emit(app);
        return Err(message);
    }
    emit(app);
    let result = async {
        let mut builder = app.updater_builder().timeout(REQUEST_TIMEOUT);
        let custom = custom_endpoints(app);
        if !custom.is_empty() {
            builder = builder.endpoints(custom).map_err(friendly)?;
        }
        builder
            .build()
            .map_err(friendly)?
            .check()
            .await
            .map_err(|e| {
                plog!("updates: check failed: {e}");
                friendly(e)
            })
    }
    .await;
    let notes_url = match &result {
        Ok(Some(update)) => first_endpoint(app).and_then(|e| release_page(&e, &update.version)),
        _ => None,
    };
    let outcome = with_state(|s| {
        s.checking = false;
        match result {
            Ok(update) => {
                if let Some(u) = &update {
                    if s.update.as_ref().map(|old| &old.version) != Some(&u.version) {
                        plog!("updates: version {} is available", u.version);
                    }
                }
                s.last_check_ms = Some(now_ms());
                s.up_to_date = update.is_none();
                s.update = update;
                s.notes_url = notes_url;
                Ok(())
            }
            Err(e) => {
                s.error = Some(e.clone());
                Err(e)
            }
        }
    });
    emit(app);
    outcome
}

fn automatic_checks_allowed(app: &AppHandle) -> bool {
    !cfg!(debug_assertions) || !app_state(app).settings().update_endpoints.is_empty()
}

pub fn start(app: &AppHandle) {
    if let Some(reason) = disabled_reason(app) {
        plog!("updates: turned off in this build: {reason}");
        return;
    }
    if managed_install() {
        plog!("updates: managed install (MSI): no automatic checks, nothing to install");
        return;
    }
    if !feed_on(app) {
        plog!(
            "updates: the macOS updater is off in this build: new versions show from App versions"
        );
        return;
    }
    if way() == UpdateWay::DownloadPage {
        plog!("updates: installed from a package: new versions link to the download page");
    }
    let app = app.clone();
    let _ = thread::Builder::new()
        .name("pass-updates".into())
        .spawn(move || {
            thread::sleep(FIRST_CHECK_DELAY);
            let mut next = SystemTime::now();
            loop {
                let state = app_state(&app);
                if SystemTime::now() >= next
                    && state.settings().update_auto_check
                    && automatic_checks_allowed(&app)
                {
                    let ok = tauri::async_runtime::block_on(check(&app)).is_ok();
                    next = SystemTime::now() + if ok { CHECK_EVERY } else { RETRY_AFTER };
                }
                thread::sleep(POLL);
            }
        });
}

#[tauri::command]
pub fn update_status(app: AppHandle) -> Value {
    status(&app)
}

/// "Check for updates". Also refreshes the version requirements (app_versions.rs).
#[tauri::command]
pub async fn update_check(app: AppHandle) -> Result<Value, String> {
    crate::app_versions::refresh_soon(&app);
    check(&app).await?;
    Ok(status(&app))
}

/// "Update and restart": download with progress, save and lock the vault, run the installer (passive) and exit.
#[tauri::command]
pub async fn update_install(app: AppHandle) -> Result<(), String> {
    match way() {
        UpdateWay::Managed => return Err(tr!("updates.managed")),
        UpdateWay::DownloadPage => return Err(tr!("updates.download_page")),
        UpdateWay::InApp => {}
    }
    let update = with_state(|s| {
        if s.progress.is_some() || s.installing {
            return Err(tr!("errors.update_installing"));
        }
        let update = s
            .update
            .clone()
            .ok_or_else(|| tr!("errors.update_not_found"))?;
        s.progress = Some((0, None));
        s.error = None;
        Ok(update)
    })?;
    emit(&app);
    plog!("updates: downloading version {}", update.version);
    let mut done = 0u64;
    let mut last_emit = Instant::now();
    let downloaded = update
        .download(
            |chunk, total| {
                done += chunk as u64;
                with_state(|s| s.progress = Some((done, total)));
                if last_emit.elapsed() >= Duration::from_millis(150) {
                    last_emit = Instant::now();
                    emit(&app);
                }
            },
            || {},
        )
        .await;
    let bytes = match downloaded {
        Ok(bytes) => bytes,
        Err(e) => {
            plog!("updates: download failed: {e}");
            let message = friendly(e);
            with_state(|s| {
                s.progress = None;
                s.error = Some(message.clone());
            });
            emit(&app);
            return Err(message);
        }
    };
    with_state(|s| {
        s.progress = None;
        s.installing = true;
    });
    emit(&app);
    // The installer ends this process: unsaved vault changes must be on disk first. A vault that can't
    // be saved (disk full, file locked by a sync client) stops the update.
    if let Some(agent) = app_state(&app).agent() {
        if let Err(e) = agent.save() {
            plog!("updates: not installing, the vault couldn't be saved: {e}");
            let message = tr!("errors.update_save_failed");
            with_state(|s| {
                s.installing = false;
                s.error = Some(message.clone());
            });
            emit(&app);
            return Err(message);
        }
    }
    plog!("updates: installing version {}", update.version);
    // The new Pass opens its window even if this one was started in the tray.
    let marker = crate::show_on_start_marker();
    if let Some(dir) = marker.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(&marker, b"");
    // The installer replaces Pass.exe and, on Windows, `install` exits without the usual exit path
    // (RunEvent::Exit never runs): lock the vault and clear the clipboard first.
    crate::tray::lock_completely(&app);
    crate::clipboard::clear_now();
    match update.install(bytes) {
        Ok(()) => {
            // Platforms where installing doesn't exit (not Windows): start the new version.
            app.restart();
        }
        Err(e) => {
            plog!("updates: install failed: {e}");
            let _ = std::fs::remove_file(&marker);
            let message = friendly(e);
            with_state(|s| {
                s.installing = false;
                s.error = Some(message.clone());
            });
            emit(&app);
            Err(message)
        }
    }
}

#[tauri::command]
pub fn update_open_notes() -> Result<(), String> {
    let url = with_state(|s| s.notes_url.clone()).ok_or_else(|| tr!("errors.no_release_notes"))?;
    crate::platform::open_browser(&url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_pages_come_from_github_endpoints_only() {
        assert_eq!(
            release_page(
                "https://github.com/sensyble/pass-releases/releases/latest/download/latest.json",
                "0.2.0"
            )
            .as_deref(),
            Some("https://github.com/sensyble/pass-releases/releases/tag/v0.2.0")
        );
        assert_eq!(
            release_page("http://127.0.0.1:8080/latest.json", "0.2.0"),
            None
        );
        assert_eq!(
            release_page("https://github.com/sensyble/pass-releases", "1.0.0"),
            None
        );
    }

    const PUBKEY: &str = "dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXk6IDMyRTg4RTI1MUZDOTI1OTcKUldTWEpja2ZKWTdvTXZUN0luU3dDTFZoK1BsZ2M1SnJaZWdkaXVncmpiRTIzY0lPZmp5TmkyQnEK";

    #[test]
    fn base64_is_strict() {
        assert_eq!(base64_decode("TWFu").as_deref(), Some(&b"Man"[..]));
        assert_eq!(base64_decode("TWE=").as_deref(), Some(&b"Ma"[..]));
        assert_eq!(base64_decode("TQ==").as_deref(), Some(&b"M"[..]));
        for bad in ["", "TWF", "TQ==TWFu", "T===", "TW-u", "TWFu\n"] {
            assert_eq!(base64_decode(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn only_real_public_keys_enable_updates() {
        assert_eq!(
            pubkey_id(PUBKEY),
            Some([0x97, 0x25, 0xc9, 0x1f, 0x25, 0x8e, 0xe8, 0x32])
        );
        for placeholder in ["", "REPLACE_ME", "dW50cnVzdGVkIGNvbW1lbnQ6IAo="] {
            assert_eq!(pubkey_id(placeholder), None, "{placeholder:?}");
        }

        let config = |extra: Value| {
            let mut c = json!({ "pubkey": PUBKEY, "requireSignedVersion": true });
            c.as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            c
        };
        assert_eq!(config_problem(Some(&config(json!({})))), None);
        assert_eq!(
            config_problem(Some(&config(json!({ "allowDowngrades": false })))),
            None
        );
        assert!(config_problem(None).is_some());
        assert!(config_problem(Some(&config(json!({ "pubkey": "" })))).is_some());
        assert!(config_problem(Some(&config(json!({ "requireSignedVersion": false })))).is_some());
        for relaxed in [
            "allowDowngrades",
            "dangerousInsecureTransportProtocol",
            "dangerousAcceptInvalidCerts",
            "dangerousAcceptInvalidHostnames",
        ] {
            assert!(
                config_problem(Some(&config(json!({ relaxed: true })))).is_some(),
                "{relaxed}"
            );
        }
    }

    #[test]
    fn the_shipped_config_enables_updates() {
        let conf: Value =
            serde_json::from_str(include_str!("../tauri.conf.json")).expect("tauri.conf.json");
        assert_eq!(config_problem(conf["plugins"].get("updater")), None);
        assert_eq!(conf["plugins"]["updater"]["pubkey"], PUBKEY);
    }

    #[test]
    fn install_kinds_come_from_the_bundle_and_the_environment() {
        use BundleType as B;
        use InstallKind as K;
        let kind = install_kind_for;
        // Windows: the NSIS setup (or no bundle: a dev build) updates itself; the MSI, or any copy
        // in Program Files, is managed.
        assert_eq!(kind("windows", Some(B::Nsis), false, false), K::Nsis);
        assert_eq!(kind("windows", None, false, false), K::Nsis);
        assert_eq!(kind("windows", Some(B::Msi), false, false), K::Msi);
        assert_eq!(kind("windows", Some(B::Nsis), false, true), K::Msi);
        assert_eq!(kind("windows", None, false, true), K::Msi);
        // `$APPIMAGE` means nothing on Windows.
        assert_eq!(kind("windows", Some(B::Nsis), true, false), K::Nsis);
        // Linux: only a copy running from an AppImage is one.
        assert_eq!(kind("linux", Some(B::AppImage), true, false), K::AppImage);
        assert_eq!(kind("linux", None, true, false), K::AppImage);
        assert_eq!(
            kind("linux", Some(B::AppImage), false, false),
            K::LinuxPackage
        );
        assert_eq!(kind("linux", Some(B::Deb), false, false), K::LinuxPackage);
        assert_eq!(kind("linux", Some(B::Rpm), false, false), K::LinuxPackage);
        assert_eq!(kind("linux", None, false, false), K::LinuxPackage);
        // A .deb or .rpm started with an AppImage's environment is still the package.
        assert_eq!(kind("linux", Some(B::Deb), true, false), K::LinuxPackage);
        assert_eq!(kind("linux", Some(B::Rpm), true, false), K::LinuxPackage);
        // macOS: the .app, whatever else is set.
        assert_eq!(kind("macos", Some(B::App), false, false), K::Mac);
        assert_eq!(kind("macos", None, true, true), K::Mac);
        // Anything else never installs updates itself.
        assert_eq!(kind("freebsd", None, true, false), K::LinuxPackage);
    }

    #[test]
    fn only_nsis_appimage_and_a_mac_with_its_updater_install_updates() {
        use InstallKind as K;
        use UpdateWay as W;
        for mac_updater in [false, true] {
            assert_eq!(update_way(K::Nsis, mac_updater), W::InApp);
            assert_eq!(update_way(K::AppImage, mac_updater), W::InApp);
            assert_eq!(update_way(K::LinuxPackage, mac_updater), W::DownloadPage);
            assert_eq!(update_way(K::Msi, mac_updater), W::Managed);
        }
        assert_eq!(update_way(K::Mac, false), W::DownloadPage);
        assert_eq!(update_way(K::Mac, true), W::InApp);
        // Every install asks the feed but a Mac without its updater (the feed has no Mac entry).
        for k in [K::Nsis, K::Msi, K::AppImage, K::LinuxPackage] {
            assert!(reads_feed(k, false), "{k:?}");
        }
        assert!(!reads_feed(K::Mac, false));
        assert!(reads_feed(K::Mac, true));
        // Installing in the app always goes with asking the feed.
        for k in [K::Nsis, K::Msi, K::AppImage, K::LinuxPackage, K::Mac] {
            for m in [false, true] {
                assert!(
                    update_way(k, m) != W::InApp || reads_feed(k, m),
                    "{k:?} {m}"
                );
            }
        }
        assert_eq!(
            [W::InApp, W::DownloadPage, W::Managed].map(W::name),
            ["in_app", "download", "managed"]
        );
    }

    #[test]
    fn the_macos_updater_is_off_by_default() {
        assert_eq!(MAC_UPDATER, cfg!(feature = "macos-updater"));
        if cfg!(target_os = "macos") && !MAC_UPDATER {
            assert_eq!(way(), UpdateWay::DownloadPage);
        }
        let manifest = include_str!("../Cargo.toml");
        assert!(manifest.contains("\nmacos-updater = []"));
        let default = manifest
            .lines()
            .find(|l| l.starts_with("default = "))
            .expect("default features");
        assert!(!default.contains("macos-updater"), "{default}");
    }

    #[test]
    fn program_files_installs_are_managed() {
        let roots = [
            PathBuf::from(r"C:\Program Files"),
            PathBuf::from(r"C:\Program Files (x86)\"),
        ];
        assert!(is_under(
            Path::new(r"C:\Program Files\Passyble\Pass.exe"),
            &roots
        ));
        assert!(is_under(
            Path::new("c:/program files/Passyble/Pass.exe"),
            &roots
        ));
        assert!(is_under(
            Path::new(r"C:\Program Files (x86)\Passyble\Pass.exe"),
            &roots
        ));
        assert!(!is_under(
            Path::new(r"C:\Users\me\AppData\Local\Programs\Passyble\Pass.exe"),
            &roots
        ));
        assert!(!is_under(Path::new(r"C:\Program FilesX\Pass.exe"), &roots));
        assert!(!is_under(
            Path::new(r"C:\Program Files\Pass.exe"),
            &[PathBuf::new()]
        ));
    }

    #[test]
    fn notes_are_one_short_line() {
        assert_eq!(
            short_notes("Fixes.\n\n* faster sync  "),
            "Fixes. * faster sync"
        );
        let long = "word ".repeat(200);
        let short = short_notes(&long);
        assert!(short.chars().count() <= NOTES_MAX + 1);
        assert!(short.ends_with("word…"));
    }
}
