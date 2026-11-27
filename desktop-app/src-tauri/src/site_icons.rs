//! Website icons on item avatars (feature `icons`): the "Show website icons" setting (per device, on by default),
//! the cache in `%LOCALAPPDATA%\Pass\icons` and the background fetches.
//!
//! Windows ask for icons with [`site_icons`], batched per frame. Cached icons come back at once; the rest go to a
//! queue worked by at most [`MAX_WORKERS`] threads, each result announced as `site-icon` (`{ domain, icon }`).
//! A domain is tried at most once per [`RETRY_AFTER`], only while the vault is unlocked and the setting is on:
//! locking empties the queue; turning the setting off also deletes the cached icons and tells the agent to stop
//! serving them to the browser extension.
//!
//! Soft-locked, windows still get cached icons but nothing new is fetched. A full lock shows none.
//!
//! Only the item's host name ever leaves the device.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use pass_core::{Item, ItemKind};
use serde::Serialize;
use serde_json::json;
use tauri::{AppHandle, Emitter};

use crate::commands::{app_state, blocking};
use crate::settings::{self, Settings};
use crate::state::{lock, AppState};

pub const MAX_WORKERS: usize = 4;
/// A domain isn't queued again for this long after a fetch started, whatever the cache says
/// (so a cache that can't be written doesn't turn into a fetch loop).
pub const RETRY_AFTER: Duration = Duration::from_secs(6 * 60 * 60);
const MAX_PER_CALL: usize = 500;

/// `%LOCALAPPDATA%\Pass\icons`: device-bound, never synced, cleared with the setting.
pub fn cache_dir() -> PathBuf {
    settings::local_dir().join("icons")
}

pub fn agent_dir(settings: &Settings) -> Option<PathBuf> {
    (cfg!(feature = "icons") && settings.show_site_icons).then(cache_dir)
}

/// The domain whose icon a login shows: its first URL that names a public website. `None` for notes, app links,
/// IP addresses and intranet names, which keep the letter and fetch nothing.
pub fn item_site(item: &Item) -> Option<String> {
    site_of(item.kind, &item.urls)
}

pub fn summary_site(item: &pass_core::ItemSummary) -> Option<String> {
    site_of(item.kind, &item.urls)
}

fn site_of(kind: ItemKind, urls: &[String]) -> Option<String> {
    if kind != ItemKind::Login {
        return None;
    }
    urls.iter().find_map(|u| domain_of(u))
}

pub fn host_site(host: &str) -> Option<String> {
    domain_of(host)
}

#[cfg(feature = "icons")]
fn domain_of(url: &str) -> Option<String> {
    let url = url.trim();
    (!url.is_empty())
        .then(|| pass_core::site_icon_domain(url.to_string()))
        .flatten()
}

#[cfg(not(feature = "icons"))]
fn domain_of(_url: &str) -> Option<String> {
    None
}

/// `data:image/png;base64,…` for an `<img src>` (the CSP allows `data:` images).
pub fn data_url(png: &[u8]) -> String {
    use base64::Engine as _;
    format!(
        "data:image/png;base64,{}",
        base64::engine::general_purpose::STANDARD.encode(png)
    )
}

/// Icons may be fetched: the setting is on and the vault unlocked. Takes the settings and agent
/// locks: never call it with the queue locked.
fn active(state: &AppState) -> bool {
    cfg!(feature = "icons")
        && lock(&state.settings).show_site_icons
        && state.agent().is_some_and(|a| !a.is_locked())
}

/// Cached icons may be shown: the setting is on and the list is on screen (unlocked, or soft-locked).
fn showing(state: &AppState) -> bool {
    cfg!(feature = "icons")
        && lock(&state.settings).show_site_icons
        && state
            .agent()
            .is_some_and(|a| list_on_screen(a.is_locked(), a.is_soft_locked()))
}

pub(crate) fn list_on_screen(locked: bool, soft_locked: bool) -> bool {
    !locked || soft_locked
}

#[derive(Default)]
struct Queue {
    pending: VecDeque<String>,
    busy: HashSet<String>,
    attempted: HashMap<String, Instant>,
    workers: usize,
}

impl Queue {
    fn push(&mut self, domain: &str, now: Instant) -> bool {
        let recent = self
            .attempted
            .get(domain)
            .is_some_and(|t| now.saturating_duration_since(*t) < RETRY_AFTER);
        if recent || !self.busy.insert(domain.to_string()) {
            return false;
        }
        self.pending.push_back(domain.to_string());
        true
    }

    fn take(&mut self, now: Instant) -> Option<String> {
        let domain = self.pending.pop_front()?;
        self.attempted.insert(domain.clone(), now);
        Some(domain)
    }

    fn done(&mut self, domain: &str) {
        self.busy.remove(domain);
    }

    fn clear_pending(&mut self) {
        for domain in self.pending.drain(..) {
            self.busy.remove(&domain);
        }
    }

    fn workers_wanted(&self) -> usize {
        MAX_WORKERS
            .saturating_sub(self.workers)
            .min(self.pending.len())
    }
}

#[derive(Default)]
pub struct SiteIcons {
    queue: Mutex<Queue>,
}

impl SiteIcons {
    fn enqueue(&self, app: &AppHandle, domains: Vec<String>) {
        let now = Instant::now();
        let start = {
            let mut q = lock(&self.queue);
            for domain in &domains {
                q.push(domain, now);
            }
            let n = q.workers_wanted();
            q.workers += n;
            n
        };
        for _ in 0..start {
            let app = app.clone();
            let spawned = thread::Builder::new()
                .name("pass-site-icon".into())
                .spawn(move || work(app));
            if spawned.is_err() {
                lock(&self.queue).workers -= 1;
            }
        }
    }
}

fn work(app: AppHandle) {
    let state = app_state(&app);
    let dir = cache_dir();
    loop {
        let go = active(&state);
        let domain = {
            let mut q = lock(&state.site_icons.queue);
            let next = if go {
                q.take(Instant::now())
            } else {
                q.clear_pending();
                None
            };
            match next {
                Some(domain) => domain,
                None => {
                    q.workers -= 1;
                    return;
                }
            }
        };
        let png = refresh(&dir, &domain);
        lock(&state.site_icons.queue).done(&domain);
        if !lock(&state.settings).show_site_icons {
            // Turned off during the fetch: the cache was cleared before this file was written.
            forget(&dir, &domain);
            continue;
        }
        if showing(&state) {
            let icon = png.as_deref().map(data_url);
            let _ = app.emit("site-icon", json!({ "domain": domain, "icon": icon }));
        }
    }
}

#[cfg(feature = "icons")]
fn read(dir: &std::path::Path, domain: &str) -> Option<(Option<Vec<u8>>, bool)> {
    pass_core::site_icon_cache_read(dir.to_string_lossy().into_owned(), domain.to_string())
        .map(|c| (c.png, c.needs_refresh))
}

#[cfg(not(feature = "icons"))]
fn read(_dir: &std::path::Path, _domain: &str) -> Option<(Option<Vec<u8>>, bool)> {
    None
}

#[cfg(feature = "icons")]
fn refresh(dir: &std::path::Path, domain: &str) -> Option<Vec<u8>> {
    pass_core::site_icon_cache_refresh(dir.to_string_lossy().into_owned(), domain.to_string())
        .unwrap_or_else(|e| {
            crate::applog::plog!("website icon: {e}");
            None
        })
}

#[cfg(not(feature = "icons"))]
fn refresh(_dir: &std::path::Path, _domain: &str) -> Option<Vec<u8>> {
    None
}

#[cfg(feature = "icons")]
fn forget(dir: &std::path::Path, domain: &str) {
    let _ =
        std::fs::remove_file(dir.join(pass_core::site_icon_cache_file_name(domain.to_string())));
}

#[cfg(not(feature = "icons"))]
fn forget(_dir: &std::path::Path, _domain: &str) {}

fn clear_cache() {
    #[cfg(feature = "icons")]
    match pass_core::site_icon_cache_clear(cache_dir().to_string_lossy().into_owned()) {
        Ok(n) if n > 0 => crate::applog::plog!("website icons: deleted {n} cached icons"),
        Ok(_) => {}
        Err(e) => crate::applog::plog!("website icons: {e}"),
    }
}

/// The vault locked: nothing more is fetched until the next unlock (running fetches finish and are cached).
pub fn on_lock(state: &AppState) {
    lock(&state.site_icons.queue).clear_pending();
}

/// "Show website icons" was changed. Off: stops the queue, deletes the cached icons and turns the agent's
/// `icons.get` off. On: points the agent at the cache. The windows hear `site-icons-enabled` either way.
pub fn setting_changed(app: &AppHandle, state: &Arc<AppState>, enabled: bool) {
    if let Some(agent) = state.agent() {
        agent.set_icon_cache_dir(enabled.then(cache_dir));
    }
    if !enabled {
        {
            let mut q = lock(&state.site_icons.queue);
            q.clear_pending();
            // Turned on again later: fetch everything anew.
            q.attempted.clear();
        }
        clear_cache();
    }
    let _ = app.emit("site-icons-enabled", json!({ "enabled": enabled }));
}

#[derive(Serialize)]
pub struct SiteIconDto {
    domain: String,
    icon: Option<String>,
}

/// The cached icons of `domains`, queueing fetches for the rest (only while unlocked). All `null` while fully
/// locked or the setting is off; soft-locked, only what is cached.
#[tauri::command]
pub async fn site_icons(app: AppHandle, domains: Vec<String>) -> Result<Vec<SiteIconDto>, String> {
    blocking(move || {
        let state = app_state(&app);
        let mut seen = HashSet::new();
        let domains: Vec<String> = domains
            .into_iter()
            .filter(|d| seen.insert(d.clone()))
            .take(MAX_PER_CALL)
            .collect();
        if !showing(&state) {
            return Ok(domains
                .into_iter()
                .map(|domain| SiteIconDto { domain, icon: None })
                .collect());
        }
        let dir = cache_dir();
        let mut fetch = Vec::new();
        let icons = domains
            .into_iter()
            .map(|domain| {
                // Only host names as `item_site` gives them, never a URL.
                if domain_of(&domain).as_deref() != Some(domain.as_str()) {
                    return SiteIconDto { domain, icon: None };
                }
                let icon = match read(&dir, &domain) {
                    None => {
                        fetch.push(domain.clone());
                        None
                    }
                    Some((png, needs_refresh)) => {
                        if needs_refresh {
                            fetch.push(domain.clone());
                        }
                        png.as_deref().map(data_url)
                    }
                };
                SiteIconDto { domain, icon }
            })
            .collect();
        if !fetch.is_empty() && active(&state) {
            state.site_icons.enqueue(&app, fetch);
        }
        Ok(icons)
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_dedups_and_waits_before_trying_again() {
        let t0 = Instant::now();
        let mut q = Queue::default();
        assert!(q.push("example.com", t0));
        assert!(!q.push("example.com", t0), "already waiting");
        assert!(q.push("github.com", t0));
        assert_eq!(q.take(t0).as_deref(), Some("example.com"));
        assert!(!q.push("example.com", t0), "being fetched");
        q.done("example.com");
        assert!(!q.push("example.com", t0), "tried just now");
        assert!(q.push("example.com", t0 + RETRY_AFTER));
        assert_eq!(q.take(t0).as_deref(), Some("github.com"));
        assert_eq!(q.take(t0).as_deref(), Some("example.com"));
        assert_eq!(q.take(t0), None);
    }

    #[test]
    fn clearing_drops_what_waits_but_remembers_attempts() {
        let t0 = Instant::now();
        let mut q = Queue::default();
        q.push("a.com", t0);
        q.push("b.com", t0);
        assert_eq!(q.take(t0).as_deref(), Some("a.com"));
        q.clear_pending();
        assert_eq!(q.take(t0), None);
        assert!(q.push("b.com", t0), "never tried: may wait again");
        assert!(!q.push("a.com", t0), "still being fetched");
        q.done("a.com");
        assert!(!q.push("a.com", t0), "tried just now");
    }

    #[test]
    fn at_most_four_workers() {
        let t0 = Instant::now();
        let mut q = Queue::default();
        assert_eq!(q.workers_wanted(), 0);
        for i in 0..10 {
            q.push(&format!("site{i}.com"), t0);
        }
        assert_eq!(q.workers_wanted(), MAX_WORKERS);
        q.workers = 3;
        assert_eq!(q.workers_wanted(), 1);
        q.workers = MAX_WORKERS;
        assert_eq!(q.workers_wanted(), 0);
        q.workers = 0;
        q.clear_pending();
        q.push("one.com", t0);
        assert_eq!(q.workers_wanted(), 1);
    }

    #[test]
    fn icons_show_while_the_list_is_on_screen() {
        assert!(list_on_screen(false, false), "unlocked");
        assert!(list_on_screen(true, true), "soft-locked");
        assert!(!list_on_screen(true, false), "fully locked");
    }

    #[cfg(feature = "icons")]
    #[test]
    fn summaries_get_the_same_site_as_items() {
        let item = Item {
            kind: ItemKind::Login,
            urls: vec![
                "windows:putty.exe".into(),
                "https://accounts.google.com/x".into(),
            ],
            password: "secret".into(),
            ..Default::default()
        };
        let summary = pass_core::ItemSummary::of(&item);
        assert_eq!(summary_site(&summary), item_site(&item));
        assert!(summary_site(&summary).is_some());
        let note = pass_core::ItemSummary {
            kind: ItemKind::Note,
            urls: vec!["https://example.com".into()],
            ..Default::default()
        };
        assert_eq!(summary_site(&note), None);
    }

    #[test]
    fn data_url_is_standard_base64() {
        assert_eq!(data_url(&[0xfb, 0xff, 0x00]), "data:image/png;base64,+/8A");
    }

    #[cfg(feature = "icons")]
    #[test]
    fn only_logins_with_a_website_get_a_site() {
        let login = |urls: &[&str]| Item {
            kind: ItemKind::Login,
            urls: urls.iter().map(|u| u.to_string()).collect(),
            ..Default::default()
        };
        assert_eq!(
            item_site(&login(&[
                "windows:notepad.exe",
                "https://www.GitHub.com:443/login"
            ])),
            Some("github.com".into())
        );
        assert_eq!(
            item_site(&login(&["https://192.168.1.1", "android://com.example"])),
            None
        );
        assert_eq!(item_site(&login(&[])), None);
        let note = Item {
            kind: ItemKind::Note,
            urls: vec!["https://example.com".into()],
            ..Default::default()
        };
        assert_eq!(item_site(&note), None);
    }
}
