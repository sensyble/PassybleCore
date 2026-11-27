//! "Scan QR code on screen": turns a two-factor QR code shown by another app or web page into a 2FA
//! code, from the global shortcut or the item editor's two-factor field. Windows only ([`SUPPORTED`]).
//!
//! * Every monitor is captured in memory, its QR codes read and the pixels wiped right away: a screenshot
//!   is never written to disk, logged or sent. Passyble's own windows are kept out of captures.
//! * Only `otpauth://totp/...` links count, parsed as strictly as one opened from outside: a QR code on
//!   screen is untrusted input. Google Authenticator exports go to the import preview; others are ignored.
//! * The links stay in [`Session`]; the window only gets issuer, account and digits. Nothing is added until
//!   the user picks a login. Logins in vaults the user may not edit are never offered.
//! * The session goes when the window closes, the vault locks, or after [`SESSION_TTL`].

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use pass_core::{otpauth_matches, otpauth_parse_link, OtpauthLink};
use serde_json::{json, Value};
use tauri::{AppHandle, Emitter, Manager};
use zeroize::{Zeroize, Zeroizing};

use crate::i18n::tr;
use crate::popups;
use crate::state::{lock, AppState};

type Res<T> = Result<T, String>;

pub const SUPPORTED: bool = cfg!(windows);

const SESSION_TTL: Duration = Duration::from_secs(10 * 60);

struct Held(OtpauthLink);

impl Drop for Held {
    fn drop(&mut self) {
        self.0.uri.zeroize();
    }
}

#[derive(Default)]
pub struct Found {
    links: Vec<Held>,
    migration: Option<Zeroizing<String>>,
    /// Why an `otpauth://` QR code was refused (the first one), if any.
    rejected: Option<String>,
    other: usize,
}

const OTPAUTH: &str = "otpauth://";
const MIGRATION: &str = "otpauth-migration://";

fn starts_with_ci(text: &str, prefix: &str) -> bool {
    text.get(..prefix.len())
        .is_some_and(|s| s.eq_ignore_ascii_case(prefix))
}

pub fn classify(texts: Vec<String>) -> Found {
    let mut found = Found::default();
    for mut text in texts {
        let trimmed = text.trim();
        if starts_with_ci(trimmed, MIGRATION) {
            let lines = found
                .migration
                .get_or_insert_with(|| Zeroizing::new(String::new()));
            if !lines.contains(trimmed) {
                if !lines.is_empty() {
                    lines.push('\n');
                }
                lines.push_str(trimmed);
            }
        } else if starts_with_ci(trimmed, OTPAUTH) {
            match otpauth_parse_link(trimmed.to_string()) {
                Ok(link) => {
                    if found.links.iter().any(|h| h.0.uri == link.uri) {
                        drop(Held(link));
                    } else {
                        found.links.push(Held(link));
                    }
                }
                Err(e) => {
                    found
                        .rejected
                        .get_or_insert_with(|| crate::commands::pass_err(e));
                }
            }
        } else {
            found.other += 1;
        }
        text.zeroize();
    }
    found
}

pub fn decode(width: u32, height: u32, rgba: &[u8]) -> Vec<String> {
    pass_core::qr_decode_rgba(width, height, rgba).unwrap_or_default()
}

/// Captures every monitor and reads its QR codes, wiping the pixels after each.
pub fn scan(app: &AppHandle) -> Res<Found> {
    let mut texts = Vec::new();
    for area in monitors(app) {
        let pixels = capture::area(area)?;
        texts.extend(decode(pixels.width, pixels.height, &pixels.rgba));
        // `Zeroizing`: wiped here, before the next monitor is captured.
        drop(pixels);
    }
    Ok(classify(texts))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Area {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
}

fn monitors(app: &AppHandle) -> Vec<Area> {
    let listed = app
        .get_webview_window("main")
        .and_then(|w| w.available_monitors().ok())
        .unwrap_or_default();
    let mut areas: Vec<Area> = listed
        .iter()
        .map(|m| Area {
            x: m.position().x,
            y: m.position().y,
            width: m.size().width,
            height: m.size().height,
        })
        .filter(|a| a.width > 0 && a.height > 0)
        .collect();
    areas.dedup();
    if areas.is_empty() {
        areas.extend(capture::virtual_screen());
    }
    areas
}

/// One monitor's pixels, wiped when dropped.
pub struct Pixels {
    pub width: u32,
    pub height: u32,
    pub rgba: Zeroizing<Vec<u8>>,
}

#[cfg(windows)]
mod capture {
    use windows::Win32::Graphics::Gdi::{
        BitBlt, CreateCompatibleBitmap, CreateCompatibleDC, DeleteDC, DeleteObject, GetDC,
        GetDIBits, ReleaseDC, SelectObject, BITMAPINFO, BITMAPINFOHEADER, BI_RGB, CAPTUREBLT,
        DIB_RGB_COLORS, SRCCOPY,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        GetSystemMetrics, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN,
        SM_YVIRTUALSCREEN,
    };
    use zeroize::Zeroizing;

    use super::{Area, Pixels};
    use crate::i18n::tr;

    /// The whole virtual screen, when the monitors can't be listed.
    pub fn virtual_screen() -> Option<Area> {
        // SAFETY: plain metric queries.
        let (x, y, w, h) = unsafe {
            (
                GetSystemMetrics(SM_XVIRTUALSCREEN),
                GetSystemMetrics(SM_YVIRTUALSCREEN),
                GetSystemMetrics(SM_CXVIRTUALSCREEN),
                GetSystemMetrics(SM_CYVIRTUALSCREEN),
            )
        };
        (w > 0 && h > 0).then(|| Area {
            x,
            y,
            width: w as u32,
            height: h as u32,
        })
    }

    fn failed(step: &str) -> String {
        crate::errors::logged(tr!("errors.screen_capture_failed"), "screen capture", step)
    }

    /// Copies `area` of the screen into memory, without windows that keep themselves out of captures.
    pub fn area(area: Area) -> Result<Pixels, String> {
        let (w, h) = (area.width as i32, area.height as i32);
        if w <= 0 || h <= 0 || area.width > 16_384 || area.height > 16_384 {
            return Err(failed("monitor size"));
        }
        // SAFETY: every handle is checked before use and released on every path below; the buffer
        // holds exactly `height` top-down rows of `width` 32-bit pixels, as `info` describes.
        unsafe {
            let screen = GetDC(None);
            if screen.is_invalid() {
                return Err(failed("GetDC"));
            }
            let memory = CreateCompatibleDC(Some(screen));
            let bitmap = CreateCompatibleBitmap(screen, w, h);
            let mut out = Err(failed("CreateCompatibleBitmap"));
            if !memory.is_invalid() && !bitmap.is_invalid() {
                let previous = SelectObject(memory, bitmap.into());
                let copied = BitBlt(
                    memory,
                    0,
                    0,
                    w,
                    h,
                    Some(screen),
                    area.x,
                    area.y,
                    SRCCOPY | CAPTUREBLT,
                );
                // GetDIBits wants the bitmap out of the DC.
                SelectObject(memory, previous);
                out = match copied {
                    Err(_) => Err(failed("BitBlt")),
                    Ok(()) => {
                        let mut info = BITMAPINFO {
                            bmiHeader: BITMAPINFOHEADER {
                                biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                                biWidth: w,
                                // Negative: top-down rows.
                                biHeight: -h,
                                biPlanes: 1,
                                biBitCount: 32,
                                biCompression: BI_RGB.0,
                                ..Default::default()
                            },
                            ..Default::default()
                        };
                        let mut pixels =
                            Zeroizing::new(vec![
                                0u8;
                                area.width as usize * area.height as usize * 4
                            ]);
                        let lines = GetDIBits(
                            memory,
                            bitmap,
                            0,
                            area.height,
                            Some(pixels.as_mut_ptr().cast()),
                            &mut info,
                            DIB_RGB_COLORS,
                        );
                        if lines == h {
                            // BGRX to RGBA: GDI leaves the fourth byte 0, which would read as
                            // transparent.
                            for px in pixels.chunks_exact_mut(4) {
                                px.swap(0, 2);
                                px[3] = 255;
                            }
                            Ok(Pixels {
                                width: area.width,
                                height: area.height,
                                rgba: pixels,
                            })
                        } else {
                            Err(failed("GetDIBits"))
                        }
                    }
                };
            }
            if !bitmap.is_invalid() {
                let _ = DeleteObject(bitmap.into());
            }
            if !memory.is_invalid() {
                let _ = DeleteDC(memory);
            }
            ReleaseDC(None, screen);
            out
        }
    }
}

#[cfg(not(windows))]
mod capture {
    use super::{Area, Pixels};
    use crate::i18n::tr;

    pub fn virtual_screen() -> Option<Area> {
        None
    }

    pub fn area(_area: Area) -> Result<Pixels, String> {
        Err(tr!("errors.screen_scan_unsupported"))
    }
}

struct Session {
    id: u64,
    at: Instant,
    found: Found,
}

static SESSION: Mutex<Option<Session>> = Mutex::new(None);
static LAST_ID: Mutex<u64> = Mutex::new(0);
/// A scan is running (the shortcut pressed again meanwhile does nothing).
static SCANNING: AtomicBool = AtomicBool::new(false);

fn session() -> std::sync::MutexGuard<'static, Option<Session>> {
    lock(&SESSION)
}

fn start_session(found: Found) -> u64 {
    let id = {
        let mut last = lock(&LAST_ID);
        *last += 1;
        *last
    };
    *session() = Some(Session {
        id,
        at: Instant::now(),
        found,
    });
    id
}

pub fn clear() {
    *session() = None;
}

fn with_session<T>(id: u64, f: impl FnOnce(&mut Found) -> Res<T>) -> Res<T> {
    let mut guard = session();
    if guard.as_ref().is_some_and(|s| s.at.elapsed() > SESSION_TTL) {
        *guard = None;
    }
    match guard.as_mut() {
        Some(s) if s.id == id => f(&mut s.found),
        _ => Err(tr!("qrscan.expired")),
    }
}

/// The shortcut was pressed: capture first (before anything moves), unlock if a code was found, then show the window.
pub fn on_shortcut(app: &AppHandle) {
    if SCANNING.swap(true, Ordering::SeqCst) {
        return;
    }
    let app = app.clone();
    let spawned = thread::Builder::new()
        .name("pass-screen-qr".into())
        .spawn(move || {
            let result = scan(&app);
            SCANNING.store(false, Ordering::SeqCst);
            let found = match result {
                Ok(found) => found,
                Err(e) => {
                    show_window(&app, Some(e));
                    return;
                }
            };
            let codes = !found.links.is_empty() || found.migration.is_some();
            start_session(found);
            if codes && !unlocked(&app) {
                // Cancelled: nothing stays.
                clear();
                return;
            }
            show_window(&app, None);
        });
    if spawned.is_err() {
        SCANNING.store(false, Ordering::SeqCst);
    }
}

fn unlocked(app: &AppHandle) -> bool {
    let state = app.state::<Arc<AppState>>().inner().clone();
    match state.agent() {
        None => true,
        Some(agent) => !agent.is_locked() || pass_agent::Ui::request_unlock(state.ui.as_ref()),
    }
}

static SCAN_ERROR: Mutex<Option<String>> = Mutex::new(None);

fn show_window(app: &AppHandle, error: Option<String>) {
    if error.is_some() {
        clear();
    }
    *lock(&SCAN_ERROR) = error;
    crate::webview_memory::wake(app, "qrscan");
    let _ = app.emit_to("qrscan", "qrscan", ());
    popups::show_qrscan(app);
}

/// What the window shows of one code: never its secret.
fn code_json(index: usize, link: &OtpauthLink) -> Value {
    json!({
        "index": index,
        "issuer": link.issuer,
        "account": link.account,
        "algorithm": link.algorithm.uri_name(),
        "digits": link.digits,
        "period": link.period,
    })
}

#[tauri::command]
pub fn qrscan_state(app: AppHandle) -> Value {
    let error = lock(&SCAN_ERROR).clone();
    let state = app.state::<Arc<AppState>>();
    let vault = state.agent().is_some();
    let locked = state.agent().is_none_or(|a| a.is_locked());
    let guard = session();
    let Some(s) = guard.as_ref().filter(|s| s.at.elapsed() <= SESSION_TTL) else {
        return json!({ "error": error, "codes": [], "vault": vault, "locked": locked });
    };
    json!({
        "id": s.id,
        "error": error,
        "codes": s.found.links.iter().enumerate().map(|(i, h)| code_json(i, &h.0)).collect::<Vec<_>>(),
        "migration": s.found.migration.is_some(),
        "rejected": s.found.rejected,
        "other": s.found.other,
        "vault": vault,
        "locked": locked,
    })
}

#[derive(Clone, Debug)]
pub struct VaultChoice {
    pub name: String,
    pub home: bool,
    pub can_edit: bool,
}

/// Logins of the open vaults the code could be added to, best match first. Read-only vaults are left out.
pub fn matches(
    vaults: Vec<(VaultChoice, Vec<pass_core::ItemSummary>)>,
    issuer: Option<String>,
    account: Option<String>,
) -> Vec<Value> {
    let editable: Vec<(VaultChoice, Vec<pass_core::ItemSummary>)> =
        vaults.into_iter().filter(|(v, _)| v.can_edit).collect();
    let several = editable.len() > 1;
    let all: Vec<pass_core::ItemSummary> = editable
        .iter()
        .flat_map(|(_, items)| items.iter().cloned())
        .collect();
    otpauth_matches(issuer, account, all)
        .into_iter()
        .map(|m| {
            let vault = editable
                .iter()
                .find(|(_, items)| items.iter().any(|i| i.id == m.id))
                .map(|(v, _)| v);
            json!({
                "id": m.id,
                "title": m.title,
                "username": m.username,
                "has_totp": m.has_totp,
                "account_matches": m.account_matches,
                "suggested": m.suggested,
                "vault_name": vault.filter(|v| several && !v.home).map(|v| v.name.clone()),
            })
        })
        .collect()
}

fn open_vaults(state: &AppState) -> Res<Vec<(VaultChoice, Vec<pass_core::ItemSummary>)>> {
    let agent = state.require_agent()?;
    state.vault()?;
    Ok(agent
        .open_vaults()
        .into_iter()
        .map(|(r, v)| {
            (
                VaultChoice {
                    name: r.name.clone(),
                    home: r.home,
                    can_edit: r.can_edit,
                },
                v.summaries(),
            )
        })
        .collect())
}

#[tauri::command]
pub fn qrscan_review(app: AppHandle, id: u64, index: usize) -> Res<Value> {
    let state = app.state::<Arc<AppState>>().inner().clone();
    let vaults = open_vaults(&state)?;
    let (issuer, account) = with_session(id, |found| {
        let link = found
            .links
            .get(index)
            .ok_or_else(|| tr!("qrscan.expired"))?;
        Ok((link.0.issuer.clone(), link.0.account.clone()))
    })?;
    let home = vaults
        .iter()
        .find(|(v, _)| v.home)
        .map(|(v, _)| v.name.clone());
    Ok(json!({
        "matches": matches(vaults, issuer, account),
        "vault_name": home.or_else(|| state.settings().active().map(|v| v.name.clone())),
    }))
}

/// Adds code `index` of session `id` to login `target`, or to a new login in the home vault. `replace`: the user
/// confirmed replacing an existing 2FA code.
#[tauri::command]
pub fn qrscan_commit(
    app: AppHandle,
    id: u64,
    index: usize,
    target: Option<String>,
    replace: bool,
) -> Res<Value> {
    let state = app.state::<Arc<AppState>>().inner().clone();
    let agent = state.require_agent()?;
    let home = state.vault()?;
    let link = with_session(id, |found| {
        let held = found
            .links
            .get(index)
            .ok_or_else(|| tr!("qrscan.expired"))?;
        Ok(Held(held.0.clone()))
    })?;
    let target = target.filter(|t| !t.is_empty());
    let vault = match &target {
        Some(item) => {
            let (r, vault) = agent
                .vault_of_item(item)
                .ok_or_else(|| tr!("errors.item_not_found"))?;
            if !r.can_edit {
                return Err(tr!("errors.teams_read_only"));
            }
            vault
        }
        None => home,
    };
    let item = vault
        .add_otpauth_link(
            link.0.clone(),
            target,
            replace,
            tr!("otpauth.default_title"),
        )
        .map_err(crate::commands::pass_err)?;
    agent.save().map_err(crate::commands::pass_err)?;
    pass_agent::Ui::vault_changed(state.ui.as_ref());
    let left = with_session(id, |found| {
        if index < found.links.len() {
            found.links.remove(index);
        }
        Ok(found.links.len())
    })
    .unwrap_or(0);
    Ok(json!({ "id": item.id, "title": item.title, "left": left }))
}

#[tauri::command]
pub async fn qrscan_again(app: AppHandle) -> Res<Value> {
    let handle = app.clone();
    let found = tauri::async_runtime::spawn_blocking(move || scan(&handle))
        .await
        .map_err(|e| crate::errors::internal("background task", e))?;
    *lock(&SCAN_ERROR) = None;
    match found {
        Ok(found) => {
            start_session(found);
        }
        Err(e) => {
            clear();
            *lock(&SCAN_ERROR) = Some(e);
        }
    }
    let state = app.state::<Arc<AppState>>().inner().clone();
    if state.agent().is_some_and(|a| a.is_locked()) {
        // Found while locked (the vault locked meanwhile): unlock before showing anything.
        let has_codes = session()
            .as_ref()
            .is_some_and(|s| !s.found.links.is_empty() || s.found.migration.is_some());
        if has_codes {
            let ui = state.ui.clone();
            let unlocked = tauri::async_runtime::spawn_blocking(move || {
                pass_agent::Ui::request_unlock(ui.as_ref())
            })
            .await
            .unwrap_or(false);
            if !unlocked {
                clear();
            }
        }
    }
    Ok(qrscan_state(app))
}

#[tauri::command]
pub fn qrscan_import(app: AppHandle, id: u64) -> Res<()> {
    let state = app.state::<Arc<AppState>>().inner().clone();
    state.vault()?;
    let links = with_session(id, |found| {
        found.migration.take().ok_or_else(|| tr!("qrscan.expired"))
    })?;
    clear();
    popups::hide(&app, "qrscan");
    crate::import::scanned(&app, links);
    popups::show_main(&app);
    Ok(())
}

/// The editor's scan: the links on screen for its own field. Nothing is kept here.
#[tauri::command]
pub async fn qr_scan_screen(app: AppHandle) -> Res<Value> {
    let found = tauri::async_runtime::spawn_blocking(move || scan(&app))
        .await
        .map_err(|e| crate::errors::internal("background task", e))??;
    if found.links.is_empty() {
        return Err(if found.migration.is_some() {
            tr!("qrscan.migration_in_editor")
        } else if let Some(rejected) = &found.rejected {
            rejected.clone()
        } else {
            tr!("qrscan.none_found")
        });
    }
    Ok(json!({
        "codes": found.links.iter().map(|h| json!({
            "issuer": h.0.issuer,
            "account": h.0.account,
            "uri": h.0.uri,
        })).collect::<Vec<_>>(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const LINK: &str =
        "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example";

    /// A "screen" of white RGBA pixels with `text` drawn as a QR code at (`x`, `y`), `scale` pixels per module.
    fn screen_with_qr(text: &str, width: u32, height: u32, x: u32, y: u32, scale: u32) -> Vec<u8> {
        let code = qrcode::QrCode::new(text.as_bytes()).unwrap();
        let modules = code.width() as u32;
        let colors = code.to_colors();
        let mut rgba = vec![255u8; (width * height * 4) as usize];
        for my in 0..modules {
            for mx in 0..modules {
                if colors[(my * modules + mx) as usize] != qrcode::Color::Dark {
                    continue;
                }
                for dy in 0..scale {
                    for dx in 0..scale {
                        let (px, py) = (x + mx * scale + dx, y + my * scale + dy);
                        let i = ((py * width + px) * 4) as usize;
                        rgba[i..i + 3].copy_from_slice(&[0, 0, 0]);
                    }
                }
            }
        }
        rgba
    }

    #[test]
    fn a_qr_code_on_screen_is_read() {
        let rgba = screen_with_qr(LINK, 1280, 720, 700, 200, 6);
        let texts = decode(1280, 720, &rgba);
        assert_eq!(texts, vec![LINK.to_string()]);
        let found = classify(texts);
        assert_eq!(found.links.len(), 1);
        let link = &found.links[0].0;
        assert_eq!(link.issuer.as_deref(), Some("Example"));
        assert_eq!(link.account.as_deref(), Some("alice@example.com"));
        assert_eq!(link.digits, 6);
        assert!(found.migration.is_none());
        assert_eq!(found.other, 0);
    }

    #[test]
    fn a_screen_without_a_qr_code_reads_nothing() {
        let rgba = vec![200u8; 640 * 480 * 4];
        assert!(decode(640, 480, &rgba).is_empty());
        assert!(classify(Vec::new()).links.is_empty());
    }

    #[test]
    fn only_two_factor_links_count() {
        let found = classify(vec![
            "https://example.com".into(),
            LINK.into(),
            format!("  {LINK}  "),
            "OTPAUTH://totp/Other:bob?secret=GEZDGNBVGY3TQOJQ&issuer=Other".into(),
            "otpauth-migration://offline?data=CjEKCkhlbGxvId6tvu8SGEV4YW1wbGU".into(),
            "otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=1".into(),
            "WIFI:S:home;T:WPA;P:secret;;".into(),
        ]);
        // The same link twice counts once; screen order is kept.
        assert_eq!(found.links.len(), 2);
        assert_eq!(found.links[0].0.issuer.as_deref(), Some("Example"));
        assert_eq!(found.links[1].0.issuer.as_deref(), Some("Other"));
        assert!(found
            .migration
            .as_deref()
            .unwrap()
            .starts_with("otpauth-migration://"));
        assert!(
            found.rejected.is_some(),
            "the HOTP link is refused with a reason"
        );
        assert_eq!(found.other, 2);
    }

    #[test]
    fn what_the_window_sees_has_no_secret() {
        let found = classify(vec![LINK.into()]);
        let shown = code_json(0, &found.links[0].0).to_string();
        assert!(!shown.contains("JBSWY3DPEHPK3PXP"), "{shown}");
        assert!(!shown.contains("otpauth"), "{shown}");
        assert!(shown.contains("alice@example.com"));
    }

    fn summary(
        id: &str,
        title: &str,
        username: &str,
        url: &str,
        has_totp: bool,
    ) -> pass_core::ItemSummary {
        pass_core::ItemSummary {
            id: id.into(),
            kind: pass_core::ItemKind::Login,
            title: title.into(),
            username: username.into(),
            urls: if url.is_empty() {
                Vec::new()
            } else {
                vec![url.into()]
            },
            has_totp,
            ..Default::default()
        }
    }

    fn vault(id: &str, home: bool, can_edit: bool) -> VaultChoice {
        VaultChoice {
            name: format!("Vault {id}"),
            home,
            can_edit,
        }
    }

    #[test]
    fn the_best_login_is_suggested_and_read_only_vaults_are_left_out() {
        let vaults = vec![
            (
                vault("home", true, true),
                vec![
                    summary(
                        "a",
                        "Example",
                        "alice@example.com",
                        "https://example.com/login",
                        false,
                    ),
                    summary(
                        "b",
                        "Other site",
                        "alice@example.com",
                        "https://other.test",
                        false,
                    ),
                ],
            ),
            (
                vault("team", false, true),
                vec![summary(
                    "c",
                    "Example (work)",
                    "alice@corp.test",
                    "https://www.example.com",
                    false,
                )],
            ),
            (
                vault("viewer", false, false),
                vec![summary(
                    "d",
                    "Example",
                    "alice@example.com",
                    "https://example.com",
                    false,
                )],
            ),
        ];
        let found = matches(
            vaults,
            Some("Example".into()),
            Some("alice@example.com".into()),
        );
        let ids: Vec<&str> = found.iter().map(|m| m["id"].as_str().unwrap()).collect();
        // The website and the account match best; the view-only vault's login never shows.
        assert_eq!(ids.first(), Some(&"a"));
        assert!(ids.contains(&"c"));
        assert!(!ids.contains(&"d"));
        assert!(!ids.contains(&"b"));
        assert_eq!(found[0]["suggested"], true);
        assert_eq!(found.iter().filter(|m| m["suggested"] == true).count(), 1);
        // Several vaults: a shared vault's login says where it is; the home vault's doesn't.
        assert!(found[0]["vault_name"].is_null());
        let c = found.iter().find(|m| m["id"] == "c").unwrap();
        assert_eq!(c["vault_name"], "Vault team");
    }

    #[test]
    fn a_login_with_a_code_is_listed_but_never_suggested() {
        let vaults = vec![(
            vault("home", true, true),
            vec![summary("a", "GitHub", "alice", "https://github.com", true)],
        )];
        let found = matches(vaults, Some("GitHub".into()), Some("alice".into()));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0]["has_totp"], true);
        assert_eq!(found[0]["suggested"], false);
        assert!(found[0]["vault_name"].is_null());
    }

    #[test]
    fn codes_wait_in_a_session_that_a_newer_scan_replaces() {
        let first = start_session(classify(vec![LINK.into()]));
        assert!(with_session(first, |f| Ok(f.links.len())).unwrap() == 1);
        let second = start_session(Found::default());
        assert_ne!(first, second);
        assert!(with_session(first, |_| Ok(())).is_err());
        clear();
        assert!(with_session(second, |_| Ok(())).is_err());
    }
}
