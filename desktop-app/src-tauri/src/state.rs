//! Shared app state, the agent's lifecycle and the prompt registry that lets blocking agent
//! callbacks wait for an answer from a window.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::thread;
use std::time::Duration;

use pass_agent::{ipc, Agent, AgentConfig};
use serde_json::{json, Value};
use tauri::{AppHandle, Emitter, Manager};

use crate::i18n::tr;
use crate::platform::Target;
use crate::popups;
use crate::settings::Settings;
use crate::ui::AppUi;

/// What a command that needs the unlocked vault answers while it is locked. The main window matches this
/// exact text (`isLockedError` in ui/lib.js): it asks to unlock and runs the action again.
pub const VAULT_LOCKED: &str = "The vault is locked";

pub fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

#[derive(Clone, Debug)]
pub struct TotpPopup {
    pub item_id: String,
    pub title: String,
    pub target: Option<Target>,
}

#[derive(Clone, Debug)]
pub struct QuickPick {
    pub target: Target,
    pub item_ids: Vec<String>,
}

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct SyncStatus {
    pub last_sync_ms: Option<i64>,
    pub last_error: Option<String>,
    pub running: bool,
    pub pending: bool,
    /// Google Drive refused the stored sign-in; sync is paused until "Sign in to Google again".
    pub sign_in_needed: bool,
    /// The server no longer accepts this device's token; background sync waits for "Sign in again".
    pub signed_out: bool,
    /// Size of the remote copy after the last sync that knew it, and as text ("84 KB"); kept across
    /// syncs that learn nothing new (a `304`), never fetched just to show it.
    pub remote_bytes: Option<u64>,
    pub remote_size: Option<String>,
}

impl SyncStatus {
    pub fn record_success(&mut self, now_ms: i64, remote_bytes: Option<u64>) {
        self.last_sync_ms = Some(now_ms);
        self.last_error = None;
        if let Some(bytes) = remote_bytes {
            self.remote_bytes = Some(bytes);
            self.remote_size = Some(crate::sizes::format_size(bytes));
        }
    }
}

pub struct AppState {
    pub settings: Mutex<Settings>,
    /// Held while the settings are changed and saved; readers only take `settings`, briefly.
    settings_write: Mutex<()>,
    agent: OnceLock<Arc<Agent>>,
    pub server: OnceLock<Arc<ipc::Server>>,
    pub ipc_error: Mutex<Option<String>>,
    pub ui: Arc<AppUi>,
    pub prompts: Prompts,
    pub unlock_waiters: Mutex<Vec<mpsc::Sender<bool>>>,
    pub totp_popup: Mutex<Option<TotpPopup>>,
    pub quickpick: Mutex<Option<QuickPick>>,
    pub sync: Mutex<SyncStatus>,
    pub sync_kick: Mutex<Option<mpsc::Sender<()>>>,
    pub hello_available: AtomicBool,
    /// The user opened the main window: its unlock screen may start Windows Hello once.
    pub auto_hello: Mutex<crate::startup::AutoHello>,
    pub server_pair: Mutex<Option<String>>,
    pub otpauth: Mutex<crate::otpauth::Inbox>,
    pub site_icons: crate::site_icons::SiteIcons,
}

impl AppState {
    pub fn new(app: AppHandle, settings: Settings) -> Self {
        Self {
            settings: Mutex::new(settings),
            settings_write: Mutex::new(()),
            agent: OnceLock::new(),
            server: OnceLock::new(),
            ipc_error: Mutex::new(None),
            ui: Arc::new(AppUi::new(app)),
            prompts: Prompts::default(),
            unlock_waiters: Mutex::new(Vec::new()),
            totp_popup: Mutex::new(None),
            quickpick: Mutex::new(None),
            sync: Mutex::new(SyncStatus::default()),
            sync_kick: Mutex::new(None),
            hello_available: AtomicBool::new(false),
            auto_hello: Mutex::new(Default::default()),
            server_pair: Mutex::new(None),
            otpauth: Default::default(),
            site_icons: Default::default(),
        }
    }

    pub fn settings(&self) -> Settings {
        lock(&self.settings).clone()
    }

    /// Changes the settings and saves them if anything changed; nothing is kept if `f` or the save
    /// fails. Readers don't wait for the disk: they see the old settings until the file is written.
    pub fn update_settings<T>(
        &self,
        f: impl FnOnce(&mut Settings) -> Result<T, String>,
    ) -> Result<T, String> {
        let _writing = lock(&self.settings_write);
        let current = self.settings();
        let mut next = current.clone();
        let out = f(&mut next)?;
        if next != current {
            next.save()?;
            *lock(&self.settings) = next;
        }
        Ok(out)
    }

    /// Saves `next` and makes it the settings (Settings → Save), one change at a time.
    pub fn replace_settings(&self, next: &Settings) -> Result<(), String> {
        let _writing = lock(&self.settings_write);
        next.save()?;
        *lock(&self.settings) = next.clone();
        Ok(())
    }

    /// The agent, once a vault location has been chosen; created at most once per process.
    pub fn agent(&self) -> Option<Arc<Agent>> {
        self.agent.get().cloned()
    }

    pub fn require_agent(&self) -> Result<Arc<Agent>, String> {
        self.agent().ok_or_else(|| tr!("errors.no_vault_set_up"))
    }

    pub fn vault(&self) -> Result<Arc<pass_core::Vault>, String> {
        self.require_agent()?
            .vault()
            .ok_or_else(|| VAULT_LOCKED.to_string())
    }

    /// [`AppState::vault`] without counting as activity (`Agent::peek_vault`), for background checks.
    pub fn quiet_vault(&self) -> Result<Arc<pass_core::Vault>, String> {
        self.require_agent()?
            .peek_vault()
            .ok_or_else(|| VAULT_LOCKED.to_string())
    }

    /// Creates the agent for the current settings and starts the IPC server. Idempotent.
    pub fn ensure_agent(&self, app: &AppHandle) -> Arc<Agent> {
        let mut created = false;
        let agent = self
            .agent
            .get_or_init(|| {
                created = true;
                let agent = Agent::new(self.agent_config(), self.ui.clone());
                let settings = self.settings();
                agent.set_keep_list(settings.keep_list_when_locked);
                if !settings.keep_list_when_locked {
                    crate::settings::remove_kept_lists();
                }
                agent.set_icon_cache_dir(crate::site_icons::agent_dir(&settings));
                agent.set_otp_history_file(Some(
                    crate::settings::local_dir().join("otp-history.json"),
                ));
                agent.set_update_required(crate::app_versions::blocked());
                start_ipc(app.clone(), agent.clone());
                agent
            })
            .clone();
        if created && agent.keeps_list() {
            // Start soft-locked with the list kept from the last run, so the extension lists logins before
            // the first unlock. Off the main thread: it reads the vault header, which may sit in a cloud
            // folder that downloads it first. After `get_or_init`, so the lock-state event finds the agent.
            let restoring = agent.clone();
            let _ = thread::Builder::new()
                .name("pass-kept-list".into())
                .spawn(move || restoring.restore_kept_list());
        }
        agent
    }

    pub fn agent_config(&self) -> AgentConfig {
        agent_config(&self.settings())
    }

    /// Applies the current settings to the running agent. A new vault file or sync account locks the
    /// vault; returns `true` if it was locked.
    pub fn reconfigure_agent(&self) -> bool {
        match self.agent() {
            Some(agent) => agent.reconfigure(self.agent_config()),
            None => false,
        }
    }

    pub fn resolve_unlock_waiters(&self, unlocked: bool) {
        for waiter in lock(&self.unlock_waiters).drain(..) {
            let _ = waiter.send(unlocked);
        }
    }

    pub fn unlock_requested(&self) -> bool {
        !lock(&self.unlock_waiters).is_empty()
    }

    pub fn kick_sync(&self) {
        if let Some(tx) = lock(&self.sync_kick).as_ref() {
            let _ = tx.send(());
        }
    }
}

/// The agent's configuration: the active vault (an empty path when the list is empty) plus device id and auto-lock time.
pub fn agent_config(settings: &Settings) -> AgentConfig {
    AgentConfig {
        vault_path: settings
            .active()
            .map(|v| v.path.clone())
            .unwrap_or_default(),
        device_id: settings.device_id.clone(),
        // Never for "On every restart" and "When the computer locks" (auto_lock.rs).
        auto_lock: crate::auto_lock::agent_timeout(settings),
        #[cfg(feature = "webdav")]
        webdav: webdav_config(settings),
        #[cfg(feature = "gdrive")]
        gdrive: gdrive_target(settings),
        kept_list: settings
            .active()
            .map(|v| crate::settings::kept_list_path(&v.id)),
    }
}

#[cfg(feature = "gdrive")]
pub fn gdrive_target(settings: &Settings) -> Option<pass_agent::GDriveTarget> {
    let vault = settings.active()?;
    Some(pass_agent::GDriveTarget {
        account: vault.google_account()?.to_string(),
        vault_name: vault.name.clone(),
    })
}

#[cfg(feature = "webdav")]
pub fn webdav_config(settings: &Settings) -> Option<pass_core::WebDavConfig> {
    let vault = settings.active()?;
    let webdav = vault.webdav.as_ref().filter(|w| !w.url.trim().is_empty())?;
    Some(pass_core::WebDavConfig {
        url: webdav.url.clone(),
        username: webdav.username.clone(),
        password: crate::settings::webdav_password(&vault.id, webdav).unwrap_or_default(),
        pins: webdav.pins.clone(),
    })
}

/// The processes the agent's pipe accepts for the browser protocol: the native messaging host beside
/// `Pass.exe` and Pass itself. The AI tools connector (`ai_tools::connector_path`) is accepted for `ai.*` only.
fn allowed_ipc_clients() -> Vec<PathBuf> {
    let Ok(exe) = std::env::current_exe() else {
        return Vec::new();
    };
    let host = if cfg!(windows) {
        "pass-native-host.exe"
    } else {
        "pass-native-host"
    };
    #[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
    let mut clients = vec![exe.with_file_name(host), exe];
    // Linux AppImage: also the host staged in ~/.local/share/Passyble/bin/ (exactly that path,
    // only while it matches the host in this AppImage), where the browsers' manifests point.
    #[cfg(target_os = "linux")]
    clients.extend(crate::platform::staged_native_host());
    clients
}

fn start_ipc(app: AppHandle, agent: Arc<Agent>) {
    let _ = thread::Builder::new()
        .name("pass-ipc-start".into())
        .spawn(move || {
            let state = app.state::<Arc<AppState>>();
            let mut last_error = String::new();
            for _ in 0..40 {
                match ipc::Server::start_restricted_with_ai(
                    agent.clone(),
                    allowed_ipc_clients(),
                    crate::ai_tools::connector_path().into_iter().collect(),
                ) {
                    Ok(server) => {
                        let _ = state.server.set(server);
                        *lock(&state.ipc_error) = None;
                        return;
                    }
                    Err(e) => last_error = e.to_string(),
                }
                thread::sleep(Duration::from_millis(250));
            }
            *lock(&state.ipc_error) = Some(crate::errors::logged(
                tr!("errors.ipc"),
                "agent pipe",
                last_error,
            ));
        });
}

struct Pending {
    payload: Value,
    answer: mpsc::Sender<Value>,
    /// Opened with [`Prompts::open`]: stays listed after an answer until [`Prompts::close`].
    keep: bool,
}

#[derive(Default)]
pub struct Prompts {
    next: AtomicU64,
    pending: Mutex<BTreeMap<u64, Pending>>,
}

impl Prompts {
    pub fn ask(
        &self,
        app: &AppHandle,
        kind: &str,
        data: Value,
        timeout: Duration,
    ) -> Option<Value> {
        let (id, rx) = self.insert(app, kind, data, false);
        let answer = rx.recv_timeout(timeout).ok();
        self.close(app, id);
        answer
    }

    fn insert(
        &self,
        app: &AppHandle,
        kind: &str,
        data: Value,
        keep: bool,
    ) -> (u64, mpsc::Receiver<Value>) {
        let id = self.next.fetch_add(1, Ordering::Relaxed) + 1;
        let (tx, rx) = mpsc::channel();
        lock(&self.pending).insert(
            id,
            Pending {
                payload: json!({ "request_id": id, "kind": kind, "data": data }),
                answer: tx,
                keep,
            },
        );
        crate::webview_memory::wake(app, "prompt");
        let _ = app.emit_to("prompt", "prompts-changed", ());
        popups::show_prompt(app);
        (id, rx)
    }

    /// Shows a prompt that stays up until [`Prompts::close`]; answers arrive on the receiver.
    pub fn open(&self, app: &AppHandle, kind: &str, data: Value) -> (u64, mpsc::Receiver<Value>) {
        self.insert(app, kind, data, true)
    }

    pub fn update(&self, app: &AppHandle, request_id: u64, data: Value) -> bool {
        let found = match lock(&self.pending).get_mut(&request_id) {
            Some(p) => {
                p.payload["data"] = data;
                true
            }
            None => false,
        };
        crate::webview_memory::wake(app, "prompt");
        let _ = app.emit_to("prompt", "prompts-changed", ());
        found
    }

    pub fn close(&self, app: &AppHandle, request_id: u64) {
        lock(&self.pending).remove(&request_id);
        self.after_change(app);
    }

    pub fn answer(&self, app: &AppHandle, request_id: u64, answer: Value) -> bool {
        let found = {
            let mut pending = lock(&self.pending);
            match pending.get(&request_id).map(|p| p.keep) {
                Some(true) => pending
                    .get(&request_id)
                    .is_some_and(|p| p.answer.send(answer).is_ok()),
                Some(false) => pending
                    .remove(&request_id)
                    .is_some_and(|p| p.answer.send(answer).is_ok()),
                None => false,
            }
        };
        self.after_change(app);
        found
    }

    pub fn cancel_all(&self, app: &AppHandle) {
        lock(&self.pending).clear();
        self.after_change(app);
    }

    pub fn list(&self) -> Vec<Value> {
        lock(&self.pending)
            .values()
            .map(|p| p.payload.clone())
            .collect()
    }

    fn after_change(&self, app: &AppHandle) {
        crate::webview_memory::wake(app, "prompt");
        let _ = app.emit_to("prompt", "prompts-changed", ());
        if lock(&self.pending).is_empty() {
            popups::hide(app, "prompt");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sync_records_the_remote_size() {
        let mut status = SyncStatus {
            last_error: Some("offline".into()),
            ..SyncStatus::default()
        };
        status.record_success(1_000, Some(84 * 1024));
        assert_eq!(status.last_sync_ms, Some(1_000));
        assert_eq!(status.last_error, None);
        assert_eq!(status.remote_bytes, Some(84 * 1024));
        assert_eq!(status.remote_size.as_deref(), Some("84 KB"));
    }

    #[test]
    fn a_sync_that_learns_no_size_keeps_the_last_one() {
        let mut status = SyncStatus::default();
        status.record_success(1_000, Some(2048));
        status.record_success(2_000, None);
        assert_eq!(status.last_sync_ms, Some(2_000));
        assert_eq!(status.remote_bytes, Some(2048));
        assert_eq!(status.remote_size.as_deref(), Some("2 KB"));
        status.record_success(3_000, Some(3 * 1024 * 1024));
        assert_eq!(status.remote_size.as_deref(), Some("3 MB"));
    }
}
