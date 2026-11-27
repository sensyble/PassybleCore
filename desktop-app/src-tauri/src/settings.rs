//! `%APPDATA%\Pass\settings.json` plus the WebDAV passwords in Windows Credential Manager
//! (Google Drive refresh tokens are there too: `google_oauth.rs`).
//!
//! Pass keeps a list of vaults and one active vault, the one the agent points at. The file
//! location, sync account and Windows Hello switch are per vault; everything else is global.
//!
//! Older single-vault files (`vault_path` / `webdav` / `windows_hello`) are migrated into the list
//! ([`migrate_legacy`]). Saving mirrors the active vault back into those keys so an older build
//! on the same profile still opens it.

use std::fs;
use std::path::{Path, PathBuf};

use crate::i18n::tr;
use serde::{Deserialize, Serialize};

const KEYRING_SERVICE: &str = "com.sensyble.pass.webdav";
pub const DEFAULT_HOTKEY: &str = default_hotkey(cfg!(target_os = "macos"));
/// Version of the defaults this file was migrated to ([`Settings::migrate_defaults`]).
/// 1: Windows Hello master-password interval 30 days (was 14). 2: a Mac's shortcuts use Cmd.
pub const DEFAULTS_VERSION: u32 = 2;

/// The auto-type hotkey of a new install: Ctrl+Alt+P, on a Mac Control+Cmd+P (Cmd+Option+P is
/// Finder's Show Path Bar).
pub const fn default_hotkey(mac: bool) -> &'static str {
    if mac {
        "Ctrl+Cmd+P"
    } else {
        "Ctrl+Alt+P"
    }
}
/// "Not now" on the "This vault is only on this device" reminder hides it this long, per vault.
pub const LOCAL_REMINDER_SNOOZE_MS: i64 = 30 * 24 * 60 * 60 * 1000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct WebDavSettings {
    /// Full URL of the vault file, e.g. `https://cloud.example.com/remote.php/dav/files/me/pass.vault`.
    pub url: String,
    pub username: String,
    /// Certificate pins of a Passyble Server with its self-signed certificate (`sha256:...`, from the
    /// pairing link). Empty: the certificate must be publicly trusted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pins: Vec<String>,
    /// Set when the account came from a Passyble Server pairing link: this PC's device name there.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_device: Option<String>,
}

impl WebDavSettings {
    pub fn host(&self) -> String {
        let rest = self
            .url
            .trim()
            .split_once("://")
            .map_or(self.url.trim(), |(_, r)| r);
        let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
        let host = authority.rsplit('@').next().unwrap_or_default();
        let host = match host.strip_prefix('[') {
            Some(v6) => v6.split(']').next().unwrap_or_default(),
            None => host.split(':').next().unwrap_or_default(),
        };
        host.to_string()
    }

    /// `scheme://authority` in lower case, to tell whether an edited URL still points at the
    /// same server (and its certificate pins still apply).
    pub fn origin(&self) -> String {
        let url = self.url.trim();
        let (scheme, rest) = url.split_once("://").unwrap_or(("", url));
        let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
        format!("{scheme}://{authority}").to_ascii_lowercase()
    }

    pub fn is_pass_server(&self) -> bool {
        self.server_device.is_some() || !self.pins.is_empty()
    }
}

/// Google Drive backup of one vault. The refresh token is in Credential Manager (`google_oauth.rs`),
/// shared by every vault on that account. Never set together with `webdav`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct GoogleDriveSettings {
    /// The Google account (from Drive `about.get`), shown as "Google Drive · <e-mail>".
    pub account_email: String,
    /// Google refused the stored sign-in (revoked, expired in Testing mode, evicted): background
    /// sync skips the vault until "Sign in to Google again".
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub sign_in_needed: bool,
}

/// A Desktop OAuth client set in `settings.json` instead of at build time (development).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct GoogleOAuthClient {
    pub client_id: String,
    /// Google's "client secret" of a Desktop client; not confidential (docs/GOOGLE_DRIVE.md).
    pub client_secret: String,
}

/// One vault Pass knows about. Removing it from the list never touches the file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct VaultEntry {
    /// Random id, also used to name this vault's Windows Hello blob and Credential Manager entry.
    pub id: String,
    pub name: String,
    pub path: PathBuf,
    /// WebDAV sync target. The password is kept in the OS credential store, never here.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webdav: Option<WebDavSettings>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub google_drive: Option<GoogleDriveSettings>,
    /// Windows Hello quick unlock for this vault (see `hello.rs` for the threat model).
    pub windows_hello: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_opened_ms: Option<i64>,
    /// Settings → Unlock: master password interval and per-fill Windows Hello (`hello/policy.rs`).
    pub hello_policy: crate::hello::HelloPolicy,
    /// "Not now" on the "Unlock with Windows Hello next time?" card: don't offer it again.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub hello_offer_dismissed: bool,
    /// The "Get started" checklist (`ui/views/getstarted.js`): set for vaults added by this version,
    /// cleared by its Hide button or once every step is done.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub get_started: bool,
    /// "Not now" on the local-only reminder (`ui/views/local-reminder.js`), Unix milliseconds: it
    /// stays away for [`LOCAL_REMINDER_SNOOZE_MS`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_reminder_dismissed_ms: Option<i64>,
    /// The master password typed at the last unlock is below the master password rule
    /// (`pass_core::check_master_password`). Only this flag is kept, never the password or its
    /// strength. Set by each master password unlock, cleared when it is changed here; Windows Hello
    /// and recovery code unlocks leave it.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub master_password_weak: bool,
    /// "Dismiss" on that tip. Cleared with the flag above when the master password is changed here.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub master_password_tip_dismissed: bool,
    /// The Passyble account this vault is linked to (file version 3, `account_keys.rs`). The file
    /// itself is authoritative (`vault_access`); this only picks the unlock screen before it is read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub linked_account: Option<String>,
    /// The vault id inside the file, recorded at each unlock: pinned vaults name vaults by it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vault_id: Option<String>,
    /// `<owner>/<vault>` on Passyble Cloud when created in the Passyble account here (account_vaults.rs).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_vault: Option<String>,
}

impl VaultEntry {
    /// A master password unlock records whether the password is weak. A password changed on another
    /// device clears the flag at its first unlock here; "Dismiss" is kept.
    pub fn note_master_password_unlock(&mut self, weak: bool) {
        self.master_password_weak = weak;
    }

    /// The master password was changed in this app (the new one passed the rule): no tip, and a
    /// later weak one (changed on another device) is suggested again.
    pub fn note_master_password_changed(&mut self) {
        self.master_password_weak = false;
        self.master_password_tip_dismissed = false;
    }

    pub fn master_password_tip_due(&self) -> bool {
        self.master_password_weak && !self.master_password_tip_dismissed
    }
    pub fn location(&self) -> String {
        match (&self.webdav, self.google_account()) {
            (Some(w), _) if !w.host().is_empty() => w.host(),
            (_, Some(email)) => tr!("vaults.google_location", email = email),
            _ => self.path.display().to_string(),
        }
    }

    pub fn google_account(&self) -> Option<&str> {
        self.google_drive
            .as_ref()
            .map(|g| g.account_email.as_str())
            .filter(|e| !e.trim().is_empty())
    }

    /// Whether the local-only reminder is due at `now_ms`: local only and not dismissed in the last 30
    /// days. A dismiss time in the future (clock set back, hand-edited file) doesn't count.
    pub fn local_reminder_due(&self, local_only: bool, now_ms: i64) -> bool {
        local_only
            && self
                .local_reminder_dismissed_ms
                .is_none_or(|at| at > now_ms || now_ms - at >= LOCAL_REMINDER_SNOOZE_MS)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub vaults: Vec<VaultEntry>,
    pub active_vault: Option<String>,
    /// Auto-lock: on restart, when the computer locks or sleeps, or after `auto_lock_minutes` idle
    /// (auto_lock.rs). Files written before the choice existed keep `idle`; new setups start with `restart`.
    #[serde(default)]
    pub auto_lock: crate::auto_lock::AutoLock,
    pub auto_lock_minutes: u32,
    /// Global auto-type hotkey, e.g. `Ctrl+Alt+P`; `""` when the user cleared it (Settings →
    /// Keyboard shortcuts). The other global shortcuts are in `shortcuts` (shortcuts.rs).
    pub hotkey: String,
    /// Other global shortcuts by action id (`quick_access`, `lock`, ...; shortcuts.rs): the keys, or
    /// `""` for none. A missing action has its default.
    #[serde(skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub shortcuts: std::collections::BTreeMap<String, String>,
    pub start_minimized: bool,
    /// Generated once; identifies this device in vault merges.
    pub device_id: String,
    /// Extra browser extension IDs allowed to talk to the native host (e.g. an unpacked dev build),
    /// in addition to the store IDs compiled into `native_messaging.rs`.
    pub extra_extension_ids: Vec<String>,
    /// Windows 11 system passkey provider (`passkey_provider.rs`). Off by default.
    pub passkey_provider: bool,
    /// [`DEFAULTS_VERSION`] this file was migrated to; missing in older files (0).
    #[serde(default)]
    pub defaults_version: u32,
    /// The Passyble Server address and user name of the last sign-in, to prefill the form.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_server_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_server_user: Option<String>,
    /// Certificate pins of that server (from its invite link or trusted on first use).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub last_server_pins: Vec<String>,
    /// Overrides the Google OAuth client compiled in (`PASS_GOOGLE_CLIENT_ID`), for development.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub google_oauth: Option<GoogleOAuthClient>,
    /// Check for updates automatically: about a minute after start, then daily.
    pub update_auto_check: bool,
    /// Update manifests (`latest.json`) to ask instead of the one in tauri.conf.json, for testing
    /// a release channel or a local server. Empty: the built-in endpoint.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub update_endpoints: Vec<String>,
    /// The version requirements document to ask instead of
    /// `https://account.passyble.com/api/app-versions` (app_versions.rs), for testing a local
    /// server; it also turns on automatic checks in debug builds. Not in the Settings window.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_versions_endpoint: Option<String>,
    /// Show website icons: fetched in the background and cached in `%LOCALAPPDATA%\Pass\icons`
    /// (`site_icons.rs`). On by default.
    pub show_site_icons: bool,
    /// Keep the item list visible when locked (titles, usernames, websites; no secrets). Any
    /// password, 2FA code, note or edit asks to unlock first (`pass_agent::LockKind::Soft`). On by
    /// default, also for older files.
    pub keep_list_when_locked: bool,
    /// "Don't show this again" on the notice before a breach check (`health_breach_notice`).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub breach_notice_hidden: bool,
    /// A catalog in `ui/i18n` (`de`, `zh-CN`), or `None` for Windows' display language (`i18n.rs`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    /// A browser extension connected to this PC (`setup_guide.rs`), or the user marked that step done.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub extension_connected: bool,
    /// The signed-in Passyble account (`account.rs`); tokens are in Credential Manager.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub passyble_account: Option<crate::account::AccountSettings>,
    /// Sign-in handoff with the browser extension on this PC (`account.rs`): no token, no code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_handoff: Option<crate::account::HandoffSettings>,
    /// The account service to use instead of account.passyble.com (`https://`, or
    /// `http://127.0.0.1:<port>` for a local test server). Not in the Settings window.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub teams: Option<crate::teams::TeamsSettings>,
    /// Guest support tickets followed here and replies already announced (`support.rs`); no claim or token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub support: Option<crate::support::SupportSettings>,
    /// The step-by-step setup (`ui/views/setup.js`) while unfinished: set when the first vault is
    /// added on this PC, cleared once its last step is done.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub setup: Option<SetupProgress>,
}

/// Where the step-by-step setup stands (`Settings::setup`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SetupProgress {
    /// The step it opens at next (an id of `ui/views/setup-model.js`, or a legacy id that
    /// `resumeStep` maps); empty: the first step.
    pub step: String,
    /// "Finish later" closed it: it waits for the Get started card or Settings → Help instead of
    /// opening by itself after an unlock.
    pub paused: bool,
}

impl SetupProgress {
    pub const MAX_STEP: usize = 32;

    /// Progress at `step`, kept as a plain id (ASCII letters, digits and `_`).
    pub fn at(step: &str, paused: bool) -> Self {
        let step = step
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
            .take(Self::MAX_STEP)
            .collect();
        Self { step, paused }
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            vaults: Vec::new(),
            active_vault: None,
            // A new setup: the vault stays unlocked until Passyble or the computer restarts.
            auto_lock: crate::auto_lock::AutoLock::Restart,
            auto_lock_minutes: 15,
            hotkey: DEFAULT_HOTKEY.into(),
            shortcuts: std::collections::BTreeMap::new(),
            start_minimized: false,
            device_id: String::new(),
            extra_extension_ids: Vec::new(),
            passkey_provider: false,
            defaults_version: DEFAULTS_VERSION,
            last_server_url: None,
            last_server_user: None,
            last_server_pins: Vec::new(),
            google_oauth: None,
            update_auto_check: true,
            update_endpoints: Vec::new(),
            app_versions_endpoint: None,
            show_site_icons: true,
            keep_list_when_locked: true,
            breach_notice_hidden: false,
            language: None,
            extension_connected: false,
            passyble_account: None,
            account_handoff: None,
            account_url: None,
            teams: None,
            support: None,
            setup: None,
        }
    }
}

/// The single-vault keys of settings files written before multi-vault support.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct LegacyVault {
    pub vault_path: Option<PathBuf>,
    pub webdav: Option<WebDavSettings>,
    pub windows_hello: bool,
}

/// `%APPDATA%\Pass` (roaming) on Windows, `~/.config/Pass` elsewhere.
pub fn data_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("Pass")
}

/// `%LOCALAPPDATA%\Pass`: device-bound data that must not roam (the DPAPI blobs).
pub fn local_dir() -> PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("Pass")
}

pub fn settings_path() -> PathBuf {
    data_dir().join("settings.json")
}

pub fn default_vault_path() -> PathBuf {
    data_dir().join("pass.vault")
}

/// `%LOCALAPPDATA%\Pass\vaults\<vault id>.vault`: the local copy of a vault whose home is a
/// server or Google Drive (no file location to choose).
pub fn cache_vault_path(vault_id: &str) -> PathBuf {
    let safe: String = vault_id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .collect();
    local_dir().join("vaults").join(format!("{safe}.vault"))
}

/// `%LOCALAPPDATA%\Pass\kept-lists`: the soft-lock list of each vault kept between runs
/// (`pass_agent` kept_list.rs: DPAPI-sealed, no secrets).
fn kept_lists_dir() -> PathBuf {
    local_dir().join("kept-lists")
}

pub fn kept_list_path(vault_id: &str) -> PathBuf {
    let safe: String = vault_id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    kept_lists_dir().join(format!("{safe}.bin"))
}

pub fn remove_kept_list(vault_id: &str) {
    let path = kept_list_path(vault_id);
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(path.with_extension("tmp"));
}

pub fn remove_kept_lists() {
    let _ = std::fs::remove_dir_all(kept_lists_dir());
}

pub fn new_vault_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Ids name files and credentials, so only `[A-Za-z0-9_-]` is accepted.
fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

pub fn same_path(a: &Path, b: &Path) -> bool {
    if cfg!(windows) {
        let norm = |p: &Path| p.to_string_lossy().replace('/', "\\").to_lowercase();
        norm(a) == norm(b)
    } else {
        a == b
    }
}

fn name_taken(vaults: &[VaultEntry], name: &str) -> bool {
    vaults
        .iter()
        .any(|v| v.name.trim().eq_ignore_ascii_case(name.trim()))
}

pub fn unique_name(base: &str, vaults: &[VaultEntry]) -> String {
    if !name_taken(vaults, base) {
        return base.to_string();
    }
    (2..)
        .map(|n| format!("{base} {n}"))
        .find(|name| !name_taken(vaults, name))
        .unwrap_or_else(|| base.to_string())
}

/// A name for a vault added without one: the file name (`work.vault` -> "Work"), or "Personal"
/// for the default `pass.vault`, made unique within the list.
pub fn default_name(path: &Path, vaults: &[VaultEntry]) -> String {
    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().trim().to_string())
        .unwrap_or_default();
    // `pass.vault`, and the numbered `pass-2.vault` the location picker suggests next to it.
    let generic = {
        let lower = stem.to_ascii_lowercase();
        lower == "pass"
            || lower
                .strip_prefix("pass-")
                .is_some_and(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()))
    };
    let base = if stem.is_empty() || generic {
        "Personal".to_string()
    } else {
        let mut chars = stem.chars();
        match chars.next() {
            Some(first) => first.to_uppercase().chain(chars).collect(),
            None => stem,
        }
    };
    unique_name(&base, vaults)
}

/// Turns the single vault of an old settings file into the first list entry (unless the list
/// already has entries or the old file only held the never-created default). Returns its id.
pub fn migrate_legacy(
    settings: &mut Settings,
    legacy: LegacyVault,
    exists: impl Fn(&Path) -> bool,
) -> Option<String> {
    if !settings.vaults.is_empty() {
        return None;
    }
    let path = legacy.vault_path.filter(|p| !p.as_os_str().is_empty())?;
    let webdav = legacy.webdav.filter(|w| !w.url.trim().is_empty());
    // Old builds wrote the default path before onboarding finished; that isn't a vault yet.
    if !exists(&path) && same_path(&path, &default_vault_path()) && webdav.is_none() {
        return None;
    }
    let id = new_vault_id();
    let name = default_name(&path, &settings.vaults);
    settings.vaults.push(VaultEntry {
        id: id.clone(),
        name,
        path,
        webdav,
        google_drive: None,
        windows_hello: legacy.windows_hello,
        last_opened_ms: None,
        hello_policy: Default::default(),
        hello_offer_dismissed: false,
        // Already in use before this version: no Get started checklist.
        get_started: false,
        local_reminder_dismissed_ms: None,
        master_password_weak: false,
        master_password_tip_dismissed: false,
        linked_account: None,
        vault_id: None,
        account_vault: None,
    });
    settings.active_vault = Some(id.clone());
    Some(id)
}

impl Settings {
    pub fn from_json(
        bytes: &[u8],
        exists: impl Fn(&Path) -> bool,
    ) -> Option<(Self, Option<String>)> {
        let mut settings: Settings = serde_json::from_slice(bytes).ok()?;
        let legacy: LegacyVault = serde_json::from_slice(bytes).unwrap_or_default();
        let migrated = migrate_legacy(&mut settings, legacy, exists);
        settings.migrate_defaults();
        settings.normalize();
        Some((settings, migrated))
    }

    /// Loads the settings, creating the file (with a fresh device id) on first run.
    /// The flag is `true` when a settings file already existed.
    pub fn load() -> (Settings, bool) {
        let path = settings_path();
        let original = fs::read(&path).ok();
        let existing = original
            .as_deref()
            .and_then(|bytes| Settings::from_json(bytes, Path::exists));
        let existed = existing.is_some();
        if let (Some(bytes), false) = (&original, existed) {
            // Unreadable (cut short by a crash, edited by hand): the defaults below would replace
            // the vault list for good. Keep the file for the user (and the log) first.
            let backup =
                path.with_extension(format!("json.unreadable-{}", crate::vaults::now_ms()));
            let _ = fs::write(&backup, bytes);
            crate::applog::plog!(
                "settings.json could not be read; starting with defaults, the old file is {}",
                backup.display()
            );
        }
        let (mut settings, migrated) = existing.unwrap_or_default();
        let mut dirty = !existed || migrated.is_some();
        if let Some(id) = &migrated {
            crate::hello::adopt_legacy(id);
        }
        if settings.device_id.trim().is_empty() {
            settings.device_id = uuid::Uuid::new_v4().to_string();
            dirty = true;
        }
        if settings.auto_lock_minutes == 0 {
            settings.auto_lock_minutes = 15;
            dirty = true;
        }
        if migrated.is_some() {
            // Keep the pre-migration file next to the new one, once.
            let backup = path.with_extension("json.pre-vaults");
            if let (Some(bytes), false) = (&original, backup.exists()) {
                let _ = fs::write(backup, bytes);
            }
        }
        if dirty || existed && settings.needed_normalizing(original.as_deref()) {
            let _ = settings.save();
        }
        (settings, existed)
    }

    fn needed_normalizing(&self, original: Option<&[u8]>) -> bool {
        let Some(on_disk) = original.and_then(|b| serde_json::from_slice::<Settings>(b).ok())
        else {
            return false;
        };
        on_disk.vaults != self.vaults
            || on_disk.active_vault != self.active_vault
            || on_disk.defaults_version != self.defaults_version
    }

    /// Moves files written with older defaults to the current ones, once. Version 1: the Windows
    /// Hello master-password interval goes from 14 to 30 days. The per-vault policy briefly wrote
    /// 14 days as a default, so a stored "14d" can't be told from a choice: all move to 30.
    pub fn migrate_defaults(&mut self) {
        use crate::hello::policy::PasswordInterval;
        if self.defaults_version < 1 {
            for vault in &mut self.vaults {
                if vault.hello_policy.password_interval == PasswordInterval::FourteenDays {
                    vault.hello_policy.password_interval = PasswordInterval::ThirtyDays;
                }
            }
        }
        if self.defaults_version < 2 {
            self.mac_shortcut_defaults(cfg!(target_os = "macos"));
        }
        self.defaults_version = self.defaults_version.max(DEFAULTS_VERSION);
    }

    /// Version 2: a Mac's global shortcuts use Cmd. A Mac used to write Windows' defaults; those
    /// still on Windows' default keys take the Mac's, a shortcut the user picked stays. No change on
    /// Windows and Linux (`mac` false).
    fn mac_shortcut_defaults(&mut self, mac: bool) {
        use crate::shortcuts::Action;
        if !mac {
            return;
        }
        let same = |a: &str, b: &str| {
            use tauri_plugin_global_shortcut::Shortcut;
            match (a.trim().parse::<Shortcut>(), b.parse::<Shortcut>()) {
                (Ok(a), Ok(b)) => a.id() == b.id(),
                _ => false,
            }
        };
        let windows = Action::AutoType.default_keys_on(false).unwrap_or_default();
        if same(&self.hotkey, windows) {
            self.hotkey = default_hotkey(true).to_string();
        }
        for action in Action::ALL {
            let Some(windows) = action.default_keys_on(false) else {
                continue;
            };
            if self.shortcuts.get(action.id()).is_some_and(|keys| same(keys, windows)) {
                // Without an entry the action has its (Mac) default.
                self.shortcuts.remove(action.id());
            }
        }
    }

    /// Repairs hand-edited files: missing or duplicate ids, an unlisted active id, a vault with two
    /// sync accounts (WebDAV wins), or a Google Drive entry without an account.
    pub fn normalize(&mut self) {
        let mut seen: Vec<String> = Vec::new();
        for vault in &mut self.vaults {
            if !valid_id(&vault.id) || seen.contains(&vault.id) {
                vault.id = new_vault_id();
            }
            seen.push(vault.id.clone());
            if let Some(g) = &mut vault.google_drive {
                g.account_email = g.account_email.trim().to_lowercase();
            }
            if vault.webdav.is_some() || vault.google_account().is_none() {
                vault.google_drive = None;
            }
        }
        for i in 0..self.vaults.len() {
            if self.vaults[i].name.trim().is_empty() {
                let (before, rest) = self.vaults.split_at(i);
                let name = default_name(&rest[0].path, before);
                self.vaults[i].name = name;
            }
        }
        if self.active().is_none() {
            self.active_vault = self.most_recent().map(|v| v.id.clone());
        }
    }

    fn most_recent(&self) -> Option<&VaultEntry> {
        self.vaults
            .iter()
            .enumerate()
            .max_by_key(|(i, v)| (v.last_opened_ms.unwrap_or(i64::MIN), std::cmp::Reverse(*i)))
            .map(|(_, v)| v)
    }

    pub fn save(&self) -> Result<(), String> {
        let path = settings_path();
        let failed = |e: std::io::Error| {
            crate::errors::logged(tr!("errors.settings_not_saved"), "save settings", e)
        };
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir).map_err(failed)?;
        }
        let json = serde_json::to_vec_pretty(&self.to_json()).map_err(|e| {
            crate::errors::logged(tr!("errors.settings_not_saved"), "save settings", e)
        })?;
        let tmp = path.with_extension("json.tmp");
        {
            // Flushed before the rename, so a crash or power cut can't leave an empty file.
            use std::io::Write;
            let mut file = fs::File::create(&tmp).map_err(failed)?;
            file.write_all(&json).map_err(failed)?;
            file.sync_all().map_err(failed)?;
        }
        fs::rename(&tmp, &path).map_err(failed)
    }

    pub fn to_json(&self) -> serde_json::Value {
        let mut value = serde_json::to_value(self).unwrap_or_default();
        if let (Some(obj), Some(active)) = (value.as_object_mut(), self.active()) {
            obj.insert("vault_path".into(), serde_json::json!(active.path));
            if let Some(webdav) = &active.webdav {
                obj.insert("webdav".into(), serde_json::json!(webdav));
            }
            obj.insert("windows_hello".into(), active.windows_hello.into());
        }
        value
    }

    pub fn active(&self) -> Option<&VaultEntry> {
        self.vault(self.active_vault.as_deref()?)
    }

    pub fn vault(&self, id: &str) -> Option<&VaultEntry> {
        self.vaults.iter().find(|v| v.id == id)
    }

    pub fn vault_mut(&mut self, id: &str) -> Option<&mut VaultEntry> {
        self.vaults.iter_mut().find(|v| v.id == id)
    }

    pub fn find_by_path(&self, path: &Path) -> Option<&VaultEntry> {
        self.vaults.iter().find(|v| same_path(&v.path, path))
    }

    /// Adds a vault (not made active) and returns its id. A path that is already listed keeps its
    /// entry; a given name or WebDAV account replaces the old one.
    pub fn add_vault(
        &mut self,
        path: PathBuf,
        name: Option<&str>,
        webdav: Option<WebDavSettings>,
    ) -> String {
        let name = name.map(str::trim).filter(|n| !n.is_empty());
        if let Some(id) = self.find_by_path(&path).map(|v| v.id.clone()) {
            let entry = self.vault_mut(&id).expect("listed");
            if let Some(name) = name {
                entry.name = name.to_string();
            }
            if webdav.is_some() {
                entry.webdav = webdav;
            }
            return id;
        }
        // The first vault on this PC: the step-by-step setup goes on from here.
        if self.vaults.is_empty() && self.setup.is_none() {
            self.setup = Some(SetupProgress::default());
        }
        let id = new_vault_id();
        let name = match name {
            Some(n) => n.to_string(),
            None => default_name(&path, &self.vaults),
        };
        self.vaults.push(VaultEntry {
            id: id.clone(),
            name,
            path,
            webdav,
            google_drive: None,
            windows_hello: false,
            last_opened_ms: None,
            hello_policy: Default::default(),
            hello_offer_dismissed: false,
            // New on this PC: the vault view shows the Get started checklist.
            get_started: true,
            local_reminder_dismissed_ms: None,
            master_password_weak: false,
            master_password_tip_dismissed: false,
            linked_account: None,
            vault_id: None,
            account_vault: None,
        });
        id
    }

    pub fn rename_vault(&mut self, id: &str, name: &str) -> Result<(), String> {
        let name = name.trim();
        if name.is_empty() {
            return Err(tr!("errors.vault_needs_name"));
        }
        if name.chars().count() > 80 {
            return Err(tr!("errors.name_too_long"));
        }
        let entry = self
            .vault_mut(id)
            .ok_or_else(|| tr!("errors.vault_not_listed"))?;
        entry.name = name.to_string();
        Ok(())
    }

    /// Takes a vault off the list (the file stays); the most recently opened one becomes active.
    pub fn remove_vault(&mut self, id: &str) -> Option<VaultEntry> {
        let index = self.vaults.iter().position(|v| v.id == id)?;
        let removed = self.vaults.remove(index);
        if self.active_vault.as_deref() == Some(id) {
            self.active_vault = self.most_recent().map(|v| v.id.clone());
        }
        Some(removed)
    }

    pub fn restore_vault(&mut self, entry: VaultEntry, index: usize) {
        if self.vault(&entry.id).is_some() || self.find_by_path(&entry.path).is_some() {
            return;
        }
        let index = index.min(self.vaults.len());
        self.vaults.insert(index, entry);
    }

    pub fn set_active(&mut self, id: &str) -> Result<(), String> {
        if self.vault(id).is_none() {
            return Err(tr!("errors.vault_not_listed"));
        }
        self.active_vault = Some(id.to_string());
        Ok(())
    }

    #[cfg_attr(not(feature = "gdrive"), allow(dead_code))]
    pub fn google_users<'a>(&'a self, email: &'a str) -> impl Iterator<Item = &'a VaultEntry> + 'a {
        self.vaults.iter().filter(move |v| {
            v.google_account()
                .is_some_and(|e| e.eq_ignore_ascii_case(email))
        })
    }

    /// Marks (or clears) "Sign in to Google again" on every vault backed up to `email`: they
    /// share its refresh token.
    #[cfg_attr(not(feature = "gdrive"), allow(dead_code))]
    pub fn set_google_sign_in_needed(&mut self, email: &str, needed: bool) {
        for vault in &mut self.vaults {
            if let Some(g) = vault.google_drive.as_mut() {
                if g.account_email.eq_ignore_ascii_case(email) {
                    g.sign_in_needed = needed;
                }
            }
        }
    }

    pub fn touch(&mut self, id: &str, now_ms: i64, vault_id: Option<String>) {
        if let Some(entry) = self.vault_mut(id) {
            entry.last_opened_ms = Some(now_ms);
            if vault_id.is_some() {
                entry.vault_id = vault_id;
            }
        }
    }

    pub fn free_vault_path(&self, path: &Path) -> PathBuf {
        let taken = |p: &Path| p.exists() || self.find_by_path(p).is_some();
        if !taken(path) {
            return path.to_path_buf();
        }
        let stem = path
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "pass".into());
        let ext = path
            .extension()
            .map(|e| e.to_string_lossy().to_string())
            .unwrap_or_else(|| "vault".into());
        (2..1000)
            .map(|n| path.with_file_name(format!("{stem}-{n}.{ext}")))
            .find(|p| !taken(p))
            .unwrap_or_else(|| path.to_path_buf())
    }
}

fn keyring_entry(user: &str) -> Result<keyring::Entry, String> {
    keyring::Entry::new(KEYRING_SERVICE, user)
        .map_err(|e| crate::errors::internal("Credential Manager", e))
}

/// One credential per vault, account and server, so switching servers doesn't reuse a password
/// and removing one vault doesn't affect another.
fn keyring_user(vault_id: &str, webdav: &WebDavSettings) -> String {
    format!("{vault_id}:{}@{}", webdav.username, webdav.url)
}

/// Legacy credential name (one per account and server).
fn legacy_keyring_user(webdav: &WebDavSettings) -> String {
    format!("{}@{}", webdav.username, webdav.url)
}

/// Reads the vault's WebDAV password from Credential Manager, copying a legacy entry to the
/// vault's own (and leaving it for older builds).
pub fn webdav_password(vault_id: &str, webdav: &WebDavSettings) -> Option<String> {
    if let Some(password) = keyring_entry(&keyring_user(vault_id, webdav))
        .ok()
        .and_then(|e| e.get_password().ok())
    {
        return Some(password);
    }
    let legacy = keyring_entry(&legacy_keyring_user(webdav))
        .ok()?
        .get_password()
        .ok()?;
    let _ = set_webdav_password(vault_id, webdav, &legacy);
    Some(legacy)
}

pub fn set_webdav_password(
    vault_id: &str,
    webdav: &WebDavSettings,
    password: &str,
) -> Result<(), String> {
    keyring_entry(&keyring_user(vault_id, webdav))?
        .set_password(password)
        .map_err(|e| {
            crate::errors::logged(
                tr!("errors.webdav_password_not_stored"),
                "Credential Manager",
                e,
            )
        })
}

/// Deletes the vault's WebDAV password; with `legacy`, also the older builds' copy.
pub fn delete_webdav_password(vault_id: &str, webdav: &WebDavSettings, legacy: bool) {
    if let Ok(entry) = keyring_entry(&keyring_user(vault_id, webdav)) {
        let _ = entry.delete_credential();
    }
    if legacy {
        if let Ok(entry) = keyring_entry(&legacy_keyring_user(webdav)) {
            let _ = entry.delete_credential();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_vault(name: &str) -> PathBuf {
        std::env::temp_dir().join("pass-settings-tests").join(name)
    }

    fn parse(json: &str, exists: bool) -> (Settings, Option<String>) {
        Settings::from_json(json.as_bytes(), |_| exists).expect("valid settings")
    }

    #[test]
    fn missing_fields_take_defaults() {
        let (s, migrated) = parse(r#"{"hotkey":"Ctrl+Shift+L"}"#, false);
        assert_eq!(s.hotkey, "Ctrl+Shift+L");
        assert_eq!(s.auto_lock_minutes, 15);
        assert!(s.vaults.is_empty());
        assert!(s.active_vault.is_none());
        assert!(migrated.is_none());
        assert!(!s.passkey_provider);
        assert!(
            s.update_auto_check,
            "update checks are on unless turned off"
        );
        assert!(s.update_endpoints.is_empty());
        assert!(s.app_versions_endpoint.is_none());
        assert!(s.show_site_icons, "website icons are on unless turned off");
        assert!(
            s.keep_list_when_locked,
            "the list stays visible when locked unless turned off"
        );
    }

    #[test]
    fn shortcuts_are_kept_and_older_files_get_none() {
        // A file from before the keyboard shortcuts: the auto-type hotkey as it was, no others.
        let (s, _) = parse(r#"{"hotkey":"Ctrl+Alt+K"}"#, false);
        assert_eq!(s.hotkey, "Ctrl+Alt+K");
        assert!(s.shortcuts.is_empty());
        // Written only when set, so the usual file stays unchanged for older builds.
        assert!(s.to_json().get("shortcuts").is_none());
        let (s, _) = parse(
            r#"{"hotkey":"","shortcuts":{"quick_access":"Ctrl+Alt+Space","lock":"","later_action":"Ctrl+F9"}}"#,
            false,
        );
        assert_eq!(s.hotkey, "");
        assert_eq!(s.shortcuts["quick_access"], "Ctrl+Alt+Space");
        assert_eq!(s.shortcuts["lock"], "");
        // An action a newer version added survives a save by this one.
        assert_eq!(s.shortcuts["later_action"], "Ctrl+F9");
        let (back, _) = parse(&s.to_json().to_string(), false);
        assert_eq!(back, s);
    }

    #[test]
    fn keep_list_setting_round_trips() {
        let (mut s, _) = parse(r#"{"keep_list_when_locked":false}"#, false);
        assert!(!s.keep_list_when_locked);
        let (back, _) = parse(&s.to_json().to_string(), false);
        assert_eq!(back, s);
        s.keep_list_when_locked = true;
        assert_eq!(s.to_json()["keep_list_when_locked"], true);
    }

    #[test]
    fn local_reminder_dismiss_round_trips_and_older_files_load() {
        // Written before the reminder existed: no dismiss time, the reminder is due.
        let (mut s, _) = parse(
            r#"{"vaults":[{"id":"aaaaaaaaaaaaaaaa","name":"Personal","path":"C:/Vaults/v.vault"}]}"#,
            false,
        );
        assert_eq!(s.vaults[0].local_reminder_dismissed_ms, None);
        assert!(s.vaults[0].local_reminder_due(true, 1_000));
        // Not written until "Not now", so the usual file stays as older builds wrote it.
        assert!(s.to_json()["vaults"][0]
            .get("local_reminder_dismissed_ms")
            .is_none());
        s.vaults[0].local_reminder_dismissed_ms = Some(1_700_000_000_000);
        let (back, _) = parse(&s.to_json().to_string(), false);
        assert_eq!(back, s);
        assert_eq!(
            back.vaults[0].local_reminder_dismissed_ms,
            Some(1_700_000_000_000)
        );
    }

    #[test]
    fn master_password_tip_follows_unlocks_changes_and_dismiss() {
        let mut v = VaultEntry::default();
        assert!(!v.master_password_tip_due(), "nothing known before an unlock");
        v.note_master_password_unlock(true);
        assert!(v.master_password_weak);
        assert!(v.master_password_tip_due());
        v.master_password_tip_dismissed = true;
        assert!(!v.master_password_tip_due());
        v.note_master_password_unlock(true);
        assert!(!v.master_password_tip_due());
        v.note_master_password_unlock(false);
        assert!(!v.master_password_weak);
        assert!(!v.master_password_tip_due());
        v.note_master_password_unlock(true);
        v.note_master_password_changed();
        assert!(!v.master_password_weak && !v.master_password_tip_dismissed);
        v.note_master_password_unlock(true);
        assert!(v.master_password_tip_due());
    }

    #[test]
    fn master_password_tip_flags_round_trip_and_older_files_load() {
        let (mut s, _) = parse(
            r#"{"vaults":[{"id":"aaaaaaaaaaaaaaaa","name":"Personal","path":"C:/Vaults/v.vault"}]}"#,
            false,
        );
        assert!(!s.vaults[0].master_password_weak);
        assert!(!s.vaults[0].master_password_tip_dismissed);
        // Not written while false, so the usual file stays as older builds wrote it.
        let json = s.to_json();
        assert!(json["vaults"][0].get("master_password_weak").is_none());
        assert!(json["vaults"][0].get("master_password_tip_dismissed").is_none());
        s.vaults[0].note_master_password_unlock(true);
        s.vaults[0].master_password_tip_dismissed = true;
        let (back, _) = parse(&s.to_json().to_string(), false);
        assert_eq!(back, s);
        assert!(back.vaults[0].master_password_weak);
        assert!(back.vaults[0].master_password_tip_dismissed);
    }

    #[test]
    fn local_reminder_stays_away_30_days_after_not_now() {
        const DAY: i64 = 24 * 60 * 60 * 1000;
        let at = 1_700_000_000_000;
        let mut v = VaultEntry::default();
        assert!(v.local_reminder_due(true, at));
        assert!(!v.local_reminder_due(false, at));
        v.local_reminder_dismissed_ms = Some(at);
        assert!(!v.local_reminder_due(true, at));
        assert!(!v.local_reminder_due(true, at + DAY));
        assert!(!v.local_reminder_due(true, at + 30 * DAY - 1));
        assert!(v.local_reminder_due(true, at + 30 * DAY));
        assert!(v.local_reminder_due(true, at + 90 * DAY));
        assert!(!v.local_reminder_due(false, at + 90 * DAY));
        assert!(v.local_reminder_due(true, at - DAY));
        assert_eq!(LOCAL_REMINDER_SNOOZE_MS, 30 * DAY);
    }

    #[test]
    fn update_settings_round_trip() {
        let (mut s, _) = parse(r#"{"update_auto_check":false}"#, false);
        assert!(!s.update_auto_check);
        // Written only when set, so the usual file stays unchanged for older builds.
        assert!(s.to_json().get("update_endpoints").is_none());
        s.update_endpoints = vec!["http://127.0.0.1:8080/latest.json".into()];
        assert!(s.to_json().get("app_versions_endpoint").is_none());
        s.app_versions_endpoint = Some("http://127.0.0.1:8080/api/app-versions".into());
        let (back, _) = parse(&s.to_json().to_string(), false);
        assert_eq!(back, s);
    }

    #[test]
    fn legacy_single_vault_becomes_first_entry() {
        let path = tmp_vault("OneDrive/Pass/pass.vault");
        let json = serde_json::json!({
            "vault_path": path,
            "auto_lock_minutes": 30,
            "webdav": { "url": "https://cloud.example.com/dav/pass.vault", "username": "me" },
            "hotkey": "Ctrl+Alt+P",
            "device_id": "dev-1",
            "windows_hello": true,
            "passkey_provider": true,
        })
        .to_string();
        let (s, migrated) = parse(&json, true);
        let id = migrated.expect("migrated");
        assert_eq!(s.vaults.len(), 1);
        let v = &s.vaults[0];
        assert_eq!(v.id, id);
        assert_eq!(v.name, "Personal");
        assert_eq!(v.path, path);
        assert_eq!(v.webdav.as_ref().unwrap().username, "me");
        assert!(v.windows_hello);
        assert_eq!(s.active_vault.as_deref(), Some(id.as_str()));
        assert_eq!(s.device_id, "dev-1");
        assert_eq!(s.auto_lock_minutes, 30);
        assert!(s.passkey_provider);
        assert_eq!(v.location(), "cloud.example.com");
    }

    #[test]
    fn legacy_name_comes_from_the_file_stem() {
        let path = tmp_vault("work.vault");
        let json = serde_json::json!({ "vault_path": path }).to_string();
        let (s, migrated) = parse(&json, true);
        assert!(migrated.is_some());
        assert_eq!(s.vaults[0].name, "Work");
        assert!(!s.vaults[0].windows_hello);
        assert!(s.vaults[0].webdav.is_none());
    }

    #[test]
    fn legacy_default_path_without_a_file_is_not_a_vault() {
        let json = serde_json::json!({ "vault_path": default_vault_path() }).to_string();
        let (s, migrated) = parse(&json, false);
        assert!(migrated.is_none());
        assert!(s.vaults.is_empty());
        let json = serde_json::json!({ "vault_path": tmp_vault("x/pass.vault") }).to_string();
        let (s, migrated) = parse(&json, false);
        assert!(migrated.is_some());
        assert_eq!(s.vaults.len(), 1);
    }

    #[test]
    fn new_format_ignores_the_mirrored_legacy_keys() {
        let mut s = Settings::default();
        let a = s.add_vault(tmp_vault("a.vault"), Some("A"), None);
        let b = s.add_vault(tmp_vault("b.vault"), Some("B"), None);
        s.set_active(&b).unwrap();
        s.vault_mut(&b).unwrap().windows_hello = true;
        let json = s.to_json();
        assert_eq!(json["vault_path"], serde_json::json!(tmp_vault("b.vault")));
        assert_eq!(json["windows_hello"], serde_json::json!(true));
        let (back, migrated) = parse(&json.to_string(), true);
        assert!(migrated.is_none());
        assert_eq!(back, s);
        assert_eq!(back.vault(&a).unwrap().name, "A");
    }

    #[test]
    fn saved_settings_round_trip() {
        let (s, _) = parse(
            &serde_json::json!({ "vault_path": tmp_vault("pass.vault"), "device_id": "d" })
                .to_string(),
            true,
        );
        let (again, migrated) = parse(&s.to_json().to_string(), true);
        assert!(migrated.is_none());
        assert_eq!(again, s);
    }

    #[test]
    fn get_started_only_for_vaults_added_here() {
        // A vault listed by an older version (no key) and a migrated single-vault file: no checklist.
        let (s, _) = parse(
            &serde_json::json!({ "vaults": [{ "id": "old", "name": "Old", "path": tmp_vault("old.vault") }] })
                .to_string(),
            true,
        );
        assert!(!s.vaults[0].get_started);
        assert!(!s.extension_connected);
        let (s, migrated) = parse(
            &serde_json::json!({ "vault_path": tmp_vault("legacy.vault") }).to_string(),
            true,
        );
        assert!(!s.vault(&migrated.unwrap()).unwrap().get_started);

        let mut s = Settings::default();
        let id = s.add_vault(tmp_vault("new.vault"), None, None);
        assert!(s.vault(&id).unwrap().get_started);
        assert_eq!(s.to_json()["vaults"][0]["get_started"], true);
        s.vault_mut(&id).unwrap().get_started = false;
        assert!(s.to_json()["vaults"][0].get("get_started").is_none());
        s.add_vault(tmp_vault("new.vault"), Some("Renamed"), None);
        assert!(!s.vault(&id).unwrap().get_started);
    }

    #[test]
    fn the_step_by_step_setup_starts_with_the_first_vault_only() {
        // Settings files from before it (and every later vault) don't get it.
        let (s, _) = parse(
            &serde_json::json!({ "vaults": [{ "id": "old", "name": "Old", "path": tmp_vault("old.vault") }] })
                .to_string(),
            true,
        );
        assert!(s.setup.is_none());
        let mut s = Settings::default();
        assert!(s.setup.is_none());
        assert!(s.to_json().get("setup").is_none());
        s.add_vault(tmp_vault("first.vault"), None, None);
        assert_eq!(s.setup, Some(SetupProgress::default()));
        s.setup = Some(SetupProgress::at("browser", true));
        s.add_vault(tmp_vault("second.vault"), None, None);
        assert_eq!(s.setup, Some(SetupProgress::at("browser", true)));
        let (back, _) = parse(&s.to_json().to_string(), true);
        assert_eq!(back.setup, s.setup);
        s.setup = None;
        s.add_vault(tmp_vault("third.vault"), None, None);
        assert!(s.setup.is_none());
        assert_eq!(SetupProgress::at("auto_lock\"; x", false).step, "auto_lockx");
        assert_eq!(SetupProgress::at(&"a".repeat(99), false).step.len(), SetupProgress::MAX_STEP);
    }

    #[test]
    fn add_rename_remove() {
        let mut s = Settings::default();
        let first = s.add_vault(tmp_vault("pass.vault"), None, None);
        let second = s.add_vault(tmp_vault("other/pass.vault"), None, None);
        let third = s.add_vault(tmp_vault("team.vault"), Some("  Team  "), None);
        assert_eq!(s.vault(&first).unwrap().name, "Personal");
        assert_eq!(s.vault(&second).unwrap().name, "Personal 2");
        assert_eq!(s.vault(&third).unwrap().name, "Team");
        assert_ne!(first, second);
        assert_eq!(
            default_name(&tmp_vault("pass-2.vault"), &s.vaults),
            "Personal 3"
        );
        assert_eq!(
            default_name(&tmp_vault("pass-x.vault"), &s.vaults),
            "Pass-x"
        );

        let again = s.add_vault(tmp_vault("pass.vault"), None, None);
        assert_eq!(again, first);
        assert_eq!(s.vaults.len(), 3);
        let webdav = WebDavSettings {
            url: "https://dav.example.org/p.vault".into(),
            username: "u".into(),
            ..Default::default()
        };
        s.add_vault(tmp_vault("pass.vault"), Some("Home"), Some(webdav.clone()));
        assert_eq!(s.vault(&first).unwrap().name, "Home");
        assert_eq!(s.vault(&first).unwrap().webdav, Some(webdav));

        assert!(s.rename_vault(&second, "   ").is_err());
        assert!(s.rename_vault("nope", "x").is_err());
        s.rename_vault(&second, " Laptop ").unwrap();
        assert_eq!(s.vault(&second).unwrap().name, "Laptop");

        s.set_active(&second).unwrap();
        assert!(s.set_active("nope").is_err());
        s.touch(&third, 2_000, Some("vault-3".into()));
        s.touch(&first, 1_000, None);
        assert_eq!(
            s.vault(&third).unwrap().vault_id.as_deref(),
            Some("vault-3")
        );
        s.touch(&third, 3_000, None);
        assert_eq!(
            s.vault(&third).unwrap().vault_id.as_deref(),
            Some("vault-3")
        );
        let removed = s.remove_vault(&second).unwrap();
        assert_eq!(removed.id, second);
        assert_eq!(s.active_vault.as_deref(), Some(third.as_str()));
        assert!(s.remove_vault(&second).is_none());
        s.remove_vault(&first).unwrap();
        assert_eq!(s.active_vault.as_deref(), Some(third.as_str()));
        s.remove_vault(&third).unwrap();
        assert!(s.active_vault.is_none());
        assert!(s.active().is_none());
    }

    #[test]
    fn removing_an_inactive_vault_keeps_the_active_one() {
        let mut s = Settings::default();
        let a = s.add_vault(tmp_vault("a.vault"), None, None);
        let b = s.add_vault(tmp_vault("b.vault"), None, None);
        s.set_active(&a).unwrap();
        s.remove_vault(&b).unwrap();
        assert_eq!(s.active_vault.as_deref(), Some(a.as_str()));
    }

    #[cfg(windows)]
    #[test]
    fn paths_compare_like_windows() {
        let mut s = Settings::default();
        let id = s.add_vault(PathBuf::from(r"C:\Users\Me\Pass\pass.vault"), None, None);
        let same = s.add_vault(PathBuf::from("c:/users/me/pass/PASS.vault"), None, None);
        assert_eq!(id, same);
    }

    #[test]
    fn normalize_repairs_ids_and_active() {
        let json = serde_json::json!({
            "vaults": [
                { "id": "../evil", "name": "", "path": tmp_vault("a.vault") },
                { "id": "same", "name": "B", "path": tmp_vault("b.vault"), "last_opened_ms": 5 },
                { "id": "same", "name": "C", "path": tmp_vault("c.vault") },
            ],
            "active_vault": "missing",
        })
        .to_string();
        let (s, migrated) = parse(&json, true);
        assert!(migrated.is_none());
        assert!(s.vaults.iter().all(|v| valid_id(&v.id)));
        assert_ne!(s.vaults[0].id, "../evil");
        assert_eq!(s.vaults[1].id, "same");
        assert_ne!(s.vaults[2].id, "same");
        assert_eq!(s.vaults[0].name, "A");
        assert_eq!(s.active_vault.as_deref(), Some("same"));
    }

    #[test]
    fn old_default_interval_moves_to_30_days_once() {
        use crate::hello::policy::PasswordInterval;
        let json = serde_json::json!({
            "vaults": [
                { "id": "a", "name": "A", "path": tmp_vault("a.vault"),
                  "hello_policy": { "password_interval": "14d" } },
                { "id": "b", "name": "B", "path": tmp_vault("b.vault"),
                  "hello_policy": { "password_interval": "7d" } },
            ],
        })
        .to_string();
        let (s, _) = parse(&json, true);
        assert_eq!(
            s.vaults[0].hello_policy.password_interval,
            PasswordInterval::ThirtyDays
        );
        assert_eq!(
            s.vaults[1].hello_policy.password_interval,
            PasswordInterval::SevenDays
        );
        assert_eq!(s.defaults_version, DEFAULTS_VERSION);
        let mut s = s;
        s.vaults[0].hello_policy.password_interval = PasswordInterval::FourteenDays;
        let (again, _) = parse(&s.to_json().to_string(), true);
        assert_eq!(
            again.vaults[0].hello_policy.password_interval,
            PasswordInterval::FourteenDays
        );
        assert_eq!(Settings::default().defaults_version, DEFAULTS_VERSION);
    }

    #[test]
    fn a_mac_file_with_the_windows_shortcuts_moves_to_the_mac_ones_once() {
        let json = serde_json::json!({
            "defaults_version": 1,
            "hotkey": "Ctrl+Alt+P",
            "shortcuts": {
                "quick_access": "ctrl+shift+space",
                "scan_qr": "Ctrl+Alt+Shift+Q",
                "lock": "Ctrl+Alt+L",
                "show_app": "",
            },
        })
        .to_string();
        let file: Settings = serde_json::from_str(&json).unwrap();
        // A Mac: the Windows defaults go, the user's own choices (and a cleared one) stay.
        let mut mac = file.clone();
        mac.mac_shortcut_defaults(true);
        assert_eq!(mac.hotkey, "Ctrl+Cmd+P");
        assert!(!mac.shortcuts.contains_key("quick_access"));
        assert!(!mac.shortcuts.contains_key("scan_qr"));
        assert_eq!(mac.shortcuts["lock"], "Ctrl+Alt+L");
        assert_eq!(mac.shortcuts["show_app"], "");
        for own in ["Ctrl+Alt+K", ""] {
            let mut picked = file.clone();
            picked.hotkey = own.into();
            picked.mac_shortcut_defaults(true);
            assert_eq!(picked.hotkey, own);
        }
        let mut windows = file.clone();
        windows.mac_shortcut_defaults(false);
        assert_eq!(windows, file);
        // Once: the file records version 2, so a later "Ctrl+Alt+P" is the user's.
        let (s, _) = parse(&json, true);
        assert_eq!(s.defaults_version, DEFAULTS_VERSION);
        assert!(DEFAULTS_VERSION >= 2);
        if !cfg!(target_os = "macos") {
            assert_eq!(s.hotkey, "Ctrl+Alt+P");
            assert_eq!(s.shortcuts["quick_access"], "ctrl+shift+space");
        }
    }

    #[test]
    fn removed_vault_can_be_restored_in_place() {
        let mut s = Settings::default();
        let a = s.add_vault(tmp_vault("a.vault"), Some("A"), None);
        let b = s.add_vault(tmp_vault("b.vault"), Some("B"), None);
        let c = s.add_vault(tmp_vault("c.vault"), Some("C"), None);
        let removed = s.remove_vault(&b).unwrap();
        s.restore_vault(removed.clone(), 1);
        let ids: Vec<_> = s.vaults.iter().map(|v| v.id.clone()).collect();
        assert_eq!(ids, [a, b, c]);
        s.restore_vault(removed, 1);
        assert_eq!(s.vaults.len(), 3);
    }

    #[test]
    fn free_path_skips_listed_files() {
        let mut s = Settings::default();
        let base = tmp_vault("free/pass.vault");
        assert_eq!(s.free_vault_path(&base), base);
        s.add_vault(base.clone(), None, None);
        assert_eq!(s.free_vault_path(&base), tmp_vault("free/pass-2.vault"));
    }

    #[test]
    fn webdav_host() {
        let host = |url: &str| {
            WebDavSettings {
                url: url.into(),
                ..Default::default()
            }
            .host()
        };
        assert_eq!(
            host("https://cloud.example.com/remote.php/dav/x.vault"),
            "cloud.example.com"
        );
        assert_eq!(host("https://me:pw@nas.local:8443/dav"), "nas.local");
        assert_eq!(host("http://[::1]:8080/v"), "::1");
        assert_eq!(host("cloud.example.com/x"), "cloud.example.com");
    }

    #[test]
    fn google_drive_vaults_round_trip_and_older_files_load() {
        // A file from before Google Drive support: no `google_drive` anywhere.
        let old = serde_json::json!({
            "vaults": [
                { "id": "a", "name": "A", "path": tmp_vault("a.vault"),
                  "webdav": { "url": "https://dav.example.org/a.vault", "username": "u" } },
                { "id": "b", "name": "B", "path": tmp_vault("b.vault") },
            ],
            "active_vault": "b",
        })
        .to_string();
        let (mut s, migrated) = parse(&old, true);
        assert!(migrated.is_none());
        assert!(s.vaults.iter().all(|v| v.google_drive.is_none()));
        assert!(s.google_oauth.is_none());
        // Written without the new keys while unused, so older builds see what they wrote.
        let json = s.to_json();
        assert!(json["vaults"][1].get("google_drive").is_none());
        assert!(json.get("google_oauth").is_none());

        s.vault_mut("b").unwrap().google_drive = Some(GoogleDriveSettings {
            account_email: "alice@gmail.com".into(),
            sign_in_needed: false,
        });
        let json = s.to_json();
        assert_eq!(
            json["vaults"][1]["google_drive"],
            serde_json::json!({ "account_email": "alice@gmail.com" })
        );
        assert!(json.get("webdav").is_none());
        let (back, _) = parse(&json.to_string(), true);
        assert_eq!(back, s);
        let b = back.vault("b").unwrap();
        assert_eq!(b.location(), "Google Drive · alice@gmail.com");
        assert_eq!(b.google_account(), Some("alice@gmail.com"));
        assert_eq!(back.google_users("ALICE@gmail.com").count(), 1);

        s.set_google_sign_in_needed("Alice@Gmail.com", true);
        let json = s.to_json();
        assert_eq!(json["vaults"][1]["google_drive"]["sign_in_needed"], true);
        let (back, _) = parse(&json.to_string(), true);
        assert!(back.vaults[1].google_drive.as_ref().unwrap().sign_in_needed);
    }

    #[test]
    fn hand_edited_google_drive_entries_are_repaired() {
        let json = serde_json::json!({
            "vaults": [
                // Two sync accounts: WebDAV stays (one sync account per vault).
                { "id": "a", "name": "A", "path": tmp_vault("a.vault"),
                  "webdav": { "url": "https://dav.example.org/a.vault", "username": "u" },
                  "google_drive": { "account_email": "a@example.com" } },
                { "id": "b", "name": "B", "path": tmp_vault("b.vault"),
                  "google_drive": { "account_email": "  " } },
                { "id": "c", "name": "C", "path": tmp_vault("c.vault"),
                  "google_drive": { "account_email": " Bob@Example.COM " } },
            ],
            "google_oauth": { "client_id": "id.apps.googleusercontent.com", "client_secret": "s" },
        })
        .to_string();
        let (s, _) = parse(&json, true);
        assert!(s.vaults[0].google_drive.is_none());
        assert!(s.vaults[0].webdav.is_some());
        assert!(s.vaults[1].google_drive.is_none());
        assert_eq!(s.vaults[2].google_account(), Some("bob@example.com"));
        assert_eq!(
            s.google_oauth.as_ref().unwrap().client_id,
            "id.apps.googleusercontent.com"
        );
    }

    #[test]
    fn cache_paths_stay_in_the_vaults_folder() {
        let p = cache_vault_path("../../evil\\x");
        assert_eq!(p.parent().unwrap(), local_dir().join("vaults"));
        assert_eq!(p.file_name().unwrap(), "evilx.vault");
    }

    #[test]
    fn pass_server_account_round_trips() {
        let mut s = Settings::default();
        let webdav = WebDavSettings {
            url: "https://203.0.113.7:8443/dav/alice/personal.vault".into(),
            username: "alice".into(),
            pins: vec!["sha256:novcWsacBi2IRLwBIN7QCQVpLOAGPBXRFHKFijjSE-g".into()],
            server_device: Some("Laptop".into()),
        };
        let id = s.add_vault(tmp_vault("srv.vault"), None, Some(webdav.clone()));
        s.set_active(&id).unwrap();
        let (back, _) = parse(&s.to_json().to_string(), true);
        assert_eq!(back.vault(&id).unwrap().webdav, Some(webdav.clone()));
        assert!(webdav.is_pass_server());
        assert_eq!(webdav.origin(), "https://203.0.113.7:8443");
        // Plain WebDAV accounts are written without the new keys (older builds read them).
        let plain = WebDavSettings {
            url: "https://Cloud.Example.com/dav/x.vault".into(),
            username: "me".into(),
            ..Default::default()
        };
        let json = serde_json::to_value(&plain).unwrap();
        assert_eq!(
            json,
            serde_json::json!({ "url": plain.url, "username": "me" })
        );
        assert!(!plain.is_pass_server());
        assert_eq!(plain.origin(), "https://cloud.example.com");
    }
}
