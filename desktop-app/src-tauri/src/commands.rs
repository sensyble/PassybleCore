//! Tauri commands for the windows. Each window may only call the commands its capability grants
//! (`capabilities/default.json`; permissions are generated in build.rs).
//!
//! Passkey private keys never reach the webview: items cross the bridge as [`ItemDto`], whose passkeys
//! carry metadata only. A card's number, security code and PIN and hidden custom field values don't
//! travel with the item either (`get_item`): the detail view asks for one when shown (`item_secret`)
//! and copies in Rust (`copy_field`). Only the editor gets them (`get_item_for_edit`).
//!
//! Soft lock (`pass_agent::LockKind::Soft`): the vault is locked but the agent keeps a list without
//! secrets (`Agent::summaries`). `list_items`, `search`, `get_item` and copying a username answer from
//! it (marked `locked`); anything needing a secret or changing the vault answers [`VAULT_LOCKED`], and
//! the main window asks to unlock and reruns the action.

use std::path::PathBuf;
use std::sync::Arc;
use std::thread;

use pass_core::{
    b64url_encode, card_brand, card_brand_name, card_number_valid, generate_passphrase,
    generate_password as core_generate_password, totp_generate, totp_parse, CardData, CustomField,
    FieldKind, IdentityData, Item, ItemKind, PassError, PasswordOptions, UrlRule,
    PASSPHRASE_DEFAULT_WORDS,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tauri::{AppHandle, Emitter, Manager, State, WebviewWindow};
use tauri_plugin_dialog::DialogExt;

use crate::i18n::tr;
use crate::settings::{self, Settings, WebDavSettings};
use crate::state::{lock as guard, AppState, SyncStatus, VAULT_LOCKED};
use crate::{
    autotype, background, clipboard, hello, native_messaging, platform, popups, tray, vaults,
};

type Res<T> = Result<T, String>;
type AppState_<'a> = State<'a, Arc<AppState>>;

/// Runs blocking work (Argon2, file IO, network, Windows Hello) off the main thread.
pub(crate) async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Res<T> + Send + 'static,
) -> Res<T> {
    tauri::async_runtime::spawn_blocking(f)
        .await
        .map_err(|e| crate::errors::internal("background task", e))?
}

pub(crate) fn app_state(app: &AppHandle) -> Arc<AppState> {
    app.state::<Arc<AppState>>().inner().clone()
}

pub(crate) fn pass_err(e: PassError) -> String {
    crate::errors::friendly(e)
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[derive(Serialize)]
pub struct ItemSummary {
    id: String,
    kind: ItemKind,
    title: String,
    username: String,
    url: Option<String>,
    favorite: bool,
    has_password: bool,
    has_totp: bool,
    has_passkey: bool,
    /// The domain whose website icon the avatar shows (`site_icons.rs`), if any.
    site: Option<String>,
    locked: bool,
    /// Uses on every device (fills, auto-type, copied passwords and 2FA codes, passkey sign-ins).
    use_count: u64,
    last_used: i64,
    /// "Most used" sort key (`pass_core::ItemUsage::rank`): higher first, 0 if never used.
    rank: i64,
    tags: Vec<String>,
    /// A card's public part (brand, last four digits, expiry), never the number or codes.
    card: Option<CardSummaryDto>,
    identity: Option<IdentitySummaryDto>,
    has_fields: bool,
    trashed_at: Option<i64>,
    /// The vault the item is in when several are open: id, name, kind and what the user may do there.
    #[serde(skip_serializing_if = "Option::is_none")]
    vault_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    vault: Option<pass_agent::VaultRef>,
}

#[derive(Serialize, Default, Clone)]
pub struct CardSummaryDto {
    cardholder_name: String,
    brand: String,
    brand_name: String,
    last4: String,
    expiry_month: u32,
    expiry_year: u32,
}

impl From<&pass_core::CardSummary> for CardSummaryDto {
    fn from(c: &pass_core::CardSummary) -> Self {
        Self {
            cardholder_name: c.cardholder_name.clone(),
            brand: c.brand.clone(),
            brand_name: card_brand_name(c.brand.clone()),
            last4: c.last4.clone(),
            expiry_month: c.expiry_month,
            expiry_year: c.expiry_year,
        }
    }
}

#[derive(Serialize, Default, Clone)]
pub struct IdentitySummaryDto {
    full_name: String,
    email: String,
    company: String,
}

impl From<&pass_core::IdentitySummary> for IdentitySummaryDto {
    fn from(i: &pass_core::IdentitySummary) -> Self {
        Self {
            full_name: i.full_name.clone(),
            email: i.email.clone(),
            company: i.company.clone(),
        }
    }
}

impl ItemSummary {
    fn in_vault(mut self, vault: &pass_agent::VaultRef) -> Self {
        self.vault_id = Some(vault.id.clone());
        self.vault = Some(vault.clone());
        self
    }

    fn with_usage(mut self, usage: pass_core::ItemUsage) -> Self {
        self.use_count = usage.count;
        self.last_used = usage.last_used;
        self.rank = usage.rank;
        self
    }

    fn of(vault: &pass_core::Vault, item: &Item) -> Self {
        Self::from(item).with_usage(vault.usage(item.id.clone()))
    }

    pub(crate) fn trashed(s: &pass_core::ItemSummary) -> Self {
        Self {
            locked: false,
            ..Self::from(s)
        }
    }
}

fn first_url(urls: &[String]) -> Option<String> {
    urls.iter().find(|u| !u.trim().is_empty()).cloned()
}

impl From<&Item> for ItemSummary {
    fn from(i: &Item) -> Self {
        Self {
            locked: false,
            ..Self::from(&pass_core::ItemSummary::of(i))
        }
    }
}

impl From<&pass_core::ItemSummary> for ItemSummary {
    fn from(s: &pass_core::ItemSummary) -> Self {
        Self {
            id: s.id.clone(),
            kind: s.kind,
            title: s.title.clone(),
            username: s.username.clone(),
            url: first_url(&s.urls),
            favorite: s.favorite,
            has_password: s.has_password,
            has_totp: s.has_totp,
            has_passkey: !s.passkeys.is_empty(),
            site: crate::site_icons::summary_site(s),
            locked: true,
            use_count: s.use_count,
            last_used: s.last_used,
            rank: s.rank,
            tags: s.tags.clone(),
            card: s.card.as_ref().map(CardSummaryDto::from),
            identity: s.identity.as_ref().map(IdentitySummaryDto::from),
            vault_id: None,
            vault: None,
            has_fields: s.has_fields,
            trashed_at: s.trashed_at,
        }
    }
}

#[derive(Serialize, Deserialize, Default)]
#[serde(default)]
pub struct PasskeyInfo {
    credential_id: String,
    rp_id: String,
    rp_name: Option<String>,
    user_name: String,
    user_display_name: String,
    created_at: i64,
}

/// A card as the UI sees it. `number`, `security_code` and `pin` are empty in the detail view's
/// copy (`has_*` say which are set; `last4` shows); the editor's copy carries them.
#[derive(Serialize, Deserialize, Default, Clone)]
#[serde(default)]
pub struct CardDto {
    cardholder_name: String,
    number: String,
    expiry_month: u32,
    expiry_year: u32,
    security_code: String,
    pin: String,
    brand: String,
    #[serde(skip_deserializing)]
    brand_name: String,
    #[serde(skip_deserializing)]
    last4: String,
    #[serde(skip_deserializing)]
    has_number: bool,
    #[serde(skip_deserializing)]
    has_security_code: bool,
    #[serde(skip_deserializing)]
    has_pin: bool,
}

impl CardDto {
    fn hide_secrets(&mut self) {
        self.number = String::new();
        self.security_code = String::new();
        self.pin = String::new();
    }

    fn of(c: &CardData, with_secrets: bool) -> Self {
        Self {
            cardholder_name: c.cardholder_name.clone(),
            number: if with_secrets {
                c.number.clone()
            } else {
                String::new()
            },
            expiry_month: c.expiry_month,
            expiry_year: c.expiry_year,
            security_code: if with_secrets {
                c.security_code.clone()
            } else {
                String::new()
            },
            pin: if with_secrets {
                c.pin.clone()
            } else {
                String::new()
            },
            brand: c.brand.clone(),
            brand_name: card_brand_name(c.brand.clone()),
            last4: c.last4(),
            has_number: !c.number.is_empty(),
            has_security_code: !c.security_code.is_empty(),
            has_pin: !c.pin.is_empty(),
        }
    }

    fn locked(c: &pass_core::CardSummary) -> Self {
        Self {
            cardholder_name: c.cardholder_name.clone(),
            expiry_month: c.expiry_month,
            expiry_year: c.expiry_year,
            brand: c.brand.clone(),
            brand_name: card_brand_name(c.brand.clone()),
            last4: c.last4.clone(),
            has_number: !c.last4.is_empty(),
            ..Default::default()
        }
    }

    fn into_card(self) -> CardData {
        CardData {
            cardholder_name: self.cardholder_name.trim().to_string(),
            number: self.number.trim().to_string(),
            expiry_month: self.expiry_month,
            expiry_year: self.expiry_year,
            security_code: self.security_code.trim().to_string(),
            pin: self.pin.trim().to_string(),
            brand: self.brand,
        }
    }
}

/// A custom field as the UI sees it. A hidden field's `value` is empty in the detail view's copy
/// (`has_value` says whether it has one); the editor's copy carries it.
#[derive(Serialize, Deserialize, Default, Clone)]
#[serde(default)]
pub struct FieldDto {
    name: String,
    value: String,
    kind: FieldKind,
    #[serde(skip_deserializing)]
    has_value: bool,
}

impl FieldDto {
    fn of(f: &CustomField, with_secrets: bool) -> Self {
        let hide = f.kind == FieldKind::Hidden && !with_secrets;
        Self {
            name: f.name.clone(),
            value: if hide { String::new() } else { f.value.clone() },
            kind: f.kind,
            has_value: !f.value.is_empty(),
        }
    }
}

#[derive(Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ItemDto {
    id: String,
    kind: ItemKind,
    title: String,
    username: String,
    password: String,
    urls: Vec<String>,
    /// How the website entries match pages (`pass_core::Item::url_rules`): only the entries whose
    /// rule is not the default, each `url` exactly as in `urls`.
    url_rules: Vec<UrlRule>,
    totp: Option<String>,
    notes: String,
    favorite: bool,
    /// On save, passkeys missing from this list are deleted; nothing else about them changes.
    passkeys: Vec<PasskeyInfo>,
    android_apps: Vec<String>,
    /// The packages of `android_apps` the user hid ("Never show"); the only part of them a save
    /// changes.
    android_never_show: Vec<String>,
    created_at: i64,
    updated_at: i64,
    card: Option<CardDto>,
    identity: Option<IdentityData>,
    fields: Vec<FieldDto>,
    tags: Vec<String>,
    /// "Available to AI tools": `ask` (Ask every time), `allow` (Allow without asking) or `None` (not
    /// shared). Stored as a custom field (`pass_core::AI_ACCESS_FIELD`) that `fields` leaves out: the editor
    /// shows a switch.
    ai_access: Option<String>,
    #[serde(skip_deserializing)]
    site: Option<String>,
    /// Read-only: from the list a soft lock keeps, so `password`, `totp` and `notes` are empty (`has_*`
    /// say which exist). Sent back only so [`save_item`] can refuse it: saving would wipe them.
    locked: bool,
    /// Read-only: the detail view's copy, without card number, codes and hidden field values. Sent back
    /// only so [`save_item`] can refuse it; the editor uses [`get_item_for_edit`].
    partial: bool,
    #[serde(skip_deserializing)]
    has_password: bool,
    #[serde(skip_deserializing)]
    has_totp: bool,
    #[serde(skip_deserializing)]
    has_notes: bool,
    #[serde(skip_deserializing)]
    has_fields: bool,
    /// Read-only: how many earlier passwords are kept and when each was replaced (Unix ms, newest first).
    /// The passwords themselves are fetched one at a time ([`password_history_entry`],
    /// [`copy_history_password`]).
    #[serde(skip_deserializing)]
    password_history_at: Vec<i64>,
    #[serde(skip_deserializing)]
    password_changed_at: i64,
    /// The vault the item is in (Teams and Family). For a new item, the window sends the vault to
    /// save it in (`vault_id`); `vault` is read-only.
    #[serde(skip_serializing_if = "Option::is_none")]
    vault_id: Option<String>,
    #[serde(skip_deserializing, skip_serializing_if = "Option::is_none")]
    vault: Option<Value>,
    /// Read-only: a fill-only member's login. Its password, password history and hidden field
    /// values are left out; it is only ever filled (browser extension, auto-type).
    #[serde(skip_deserializing)]
    password_hidden: bool,
}

impl ItemDto {
    fn in_vault(mut self, vault: Option<&pass_agent::VaultRef>) -> Self {
        let Some(vault) = vault else {
            return self;
        };
        self.vault_id = Some(vault.id.clone());
        self.vault = serde_json::to_value(vault).ok();
        if !vault.can_reveal {
            self.password_hidden = !self.password.is_empty() || self.has_password;
            self.password = String::new();
            self.password_history_at.clear();
            for f in &mut self.fields {
                if f.kind == FieldKind::Hidden {
                    f.value = String::new();
                }
            }
            if let Some(card) = self.card.as_mut() {
                card.hide_secrets();
            }
        }
        self
    }
}

impl ItemDto {
    fn locked(s: &pass_core::ItemSummary) -> Self {
        Self {
            id: s.id.clone(),
            kind: s.kind,
            title: s.title.clone(),
            username: s.username.clone(),
            urls: s.urls.clone(),
            url_rules: s.url_rules.clone(),
            favorite: s.favorite,
            passkeys: s
                .passkeys
                .iter()
                .map(|p| PasskeyInfo {
                    credential_id: b64url_encode(p.credential_id.clone()),
                    rp_id: p.rp_id.clone(),
                    user_name: p.user_name.clone(),
                    user_display_name: p.user_display_name.clone(),
                    ..Default::default()
                })
                .collect(),
            android_apps: s.android_apps.iter().map(|a| a.package.clone()).collect(),
            android_never_show: never_shown(&s.android_apps),
            created_at: s.created_at,
            updated_at: s.updated_at,
            card: s.card.as_ref().map(CardDto::locked),
            // The kept list has the whole name in one string: shown as the first name, the
            // detail view joins the parts anyway.
            identity: s.identity.as_ref().map(|i| IdentityData {
                first_name: i.full_name.clone(),
                email: i.email.clone(),
                company: i.company.clone(),
                ..Default::default()
            }),
            tags: s.tags.clone(),
            site: crate::site_icons::summary_site(s),
            locked: true,
            partial: true,
            has_password: s.has_password,
            has_totp: s.has_totp,
            has_notes: s.has_notes,
            has_fields: s.has_fields,
            ..Default::default()
        }
    }

    pub(crate) fn for_edit(i: Item) -> Self {
        Self::build(i, true)
    }

    fn build(i: Item, with_secrets: bool) -> Self {
        Self {
            site: crate::site_icons::item_site(&i),
            locked: false,
            partial: !with_secrets,
            has_password: !i.password.is_empty(),
            has_totp: i.has_totp(),
            has_notes: !i.notes.trim().is_empty(),
            has_fields: i.fields.iter().any(|f| !pass_core::is_ai_access_field(f)),
            ai_access: i.ai_access().map(|a| a.as_str().to_string()),
            password_history_at: i.password_history.iter().map(|h| h.replaced_at).collect(),
            password_changed_at: i.password_changed_at,
            vault_id: None,
            vault: None,
            password_hidden: false,
            passkeys: i
                .passkeys
                .iter()
                .map(|p| PasskeyInfo {
                    credential_id: b64url_encode(p.credential_id.clone()),
                    rp_id: p.rp_id.clone(),
                    rp_name: p.rp_name.clone(),
                    user_name: p.user_name.clone(),
                    user_display_name: p.user_display_name.clone(),
                    created_at: p.created_at,
                })
                .collect(),
            android_apps: i.android_apps.iter().map(|a| a.package.clone()).collect(),
            android_never_show: never_shown(&i.android_apps),
            card: i.card.as_ref().map(|c| CardDto::of(c, with_secrets)),
            fields: i
                .fields
                .iter()
                .filter(|f| !pass_core::is_ai_access_field(f))
                .map(|f| FieldDto::of(f, with_secrets))
                .collect(),
            identity: i.identity,
            tags: i.tags,
            id: i.id,
            kind: i.kind,
            title: i.title,
            username: i.username,
            password: i.password,
            urls: i.urls,
            url_rules: i.url_rules,
            totp: i.totp,
            notes: i.notes,
            favorite: i.favorite,
            created_at: i.created_at,
            updated_at: i.updated_at,
        }
    }
}

fn never_shown(apps: &[pass_core::AndroidApp]) -> Vec<String> {
    apps.iter()
        .filter(|a| a.never_show)
        .map(|a| a.package.clone())
        .collect()
}

/// The editor's match rules onto `target`, whose `urls` are already the saved ones: each rule's
/// `url` trimmed as the entries are (`Vault::upsert` drops rules for entries that are gone), and
/// "Never show" on the linked Android apps the window lists.
fn apply_match_rules(target: &mut Item, url_rules: Vec<UrlRule>, never_show: &[String]) {
    target.url_rules = url_rules
        .into_iter()
        .map(|r| UrlRule {
            url: r.url.trim().to_string(),
            rule: r.rule,
        })
        .collect();
    for app in &mut target.android_apps {
        app.never_show = never_show.contains(&app.package);
    }
}

impl From<Item> for ItemDto {
    fn from(i: Item) -> Self {
        Self::build(i, false)
    }
}

#[tauri::command]
pub fn status(state: AppState_<'_>) -> Value {
    let settings = state.settings();
    let agent = state.agent();
    let active = settings.active();
    let vault_path = active
        .map(|v| v.path.clone())
        .unwrap_or_else(settings::default_vault_path);
    let locked = agent.as_ref().is_none_or(|a| a.is_locked());
    // Locked with the list kept: the main window keeps showing the vault (without secrets).
    let soft_locked = locked && agent.as_ref().is_some_and(|a| a.is_soft_locked());
    let hello_available = state
        .hello_available
        .load(std::sync::atomic::Ordering::Relaxed);
    let mut out = json!({
        "setup": !settings.vaults.is_empty(),
        "locked": locked,
        "soft_locked": soft_locked,
        "keep_list": settings.keep_list_when_locked,
        "vaults": vaults::list_json(&settings),
        "active_vault": settings.active_vault,
        "active_vault_name": active.map(|v| v.name.clone()),
        "vault_path": vault_path,
        "vault_exists": vault_path.exists(),
        "hello_enabled": active.is_some_and(|v| v.windows_hello),
        "hello_enrolled": active.is_some_and(|v| hello::enrolled(&v.id)),
        "hello_available": hello_available,
        // Offer "Unlock with Windows Hello next time?" after a master-password unlock or creating / signing in
        // to a vault (the guided setup has no Hello step) of a vault without Windows Hello.
        "offer_hello": !locked
            && hello_available
            && active.is_some_and(|v| {
                !v.windows_hello
                    && !v.hello_offer_dismissed
                    && hello::policy::password_this_run(&v.id)
            }),
        "get_started": active.is_some_and(|v| v.get_started),
        "last_server_url": settings.last_server_url,
        "last_server_user": settings.last_server_user,
        "last_server_pins": settings.last_server_pins,
        "sync": guard(&state.sync).clone(),
        // The user picked "Use master password instead" for a pending unlock: don't start
        // Windows Hello by itself.
        "prefer_password": state.ui.prefer_password(),
        "unlock_requested": state.unlock_requested(),
        "webdav_supported": cfg!(feature = "webdav"),
        "webdav_configured": active.is_some_and(|v| v.webdav.is_some()),
        "google_available": crate::gdrive::available(&settings),
        "google_drive": crate::gdrive::active_json(&settings),
        "sync_configured": active.is_some_and(|v| v.webdav.is_some() || v.google_account().is_some()),
        "shared_sync": state.agent().is_some_and(|a| !a.linked_configs().is_empty()),
        "hotkey": settings.hotkey,
        "shortcuts": crate::shortcuts::keys_json(&settings),
        "ipc_error": guard(&state.ipc_error).clone(),
        "version": env!("CARGO_PKG_VERSION"),
        "platform": std::env::consts::OS,
    });
    // The step-by-step setup isn't finished (`{ step, paused }`): the vault view opens it after an
    // unlock unless "Finish later" paused it. Set apart: one more key overflows `json!`'s
    // recursion limit.
    out["setup_progress"] = json!(settings.setup);
    out
}

/// Default location plus cloud folders found on this PC. Taken paths get a numbered name
/// (`pass-2.vault`). `synced`: a sync client keeps the folder (setup_guide.rs); the form warns otherwise.
#[tauri::command]
pub fn vault_suggestions(state: AppState_<'_>) -> Vec<Value> {
    let settings = state.settings();
    let roots = crate::setup_guide::cloud_roots();
    let mut out = vault_suggestions_raw();
    for entry in &mut out {
        if let Some(path) = entry["path"].as_str().map(PathBuf::from) {
            let path = settings.free_vault_path(&path);
            entry["synced"] = json!(crate::setup_guide::in_synced_folder(&path, &roots));
            entry["path"] = json!(path);
        }
    }
    out
}

fn vault_suggestions_raw() -> Vec<Value> {
    let mut out = vec![json!({
        "label": tr!("onboarding.this_pc_only"),
        "path": settings::default_vault_path(),
    })];
    let mut seen = Vec::new();
    for (var, label) in [
        ("OneDrive", "OneDrive"),
        ("OneDriveConsumer", "OneDrive (personal)"),
        ("OneDriveCommercial", "OneDrive (work)"),
    ] {
        let label = match var {
            "OneDriveConsumer" => tr!("onboarding.onedrive_personal"),
            "OneDriveCommercial" => tr!("onboarding.onedrive_work"),
            _ => label.to_string(),
        };
        if let Some(dir) = std::env::var_os(var).map(PathBuf::from) {
            if dir.is_dir() && !seen.contains(&dir) {
                out.push(json!({ "label": label, "path": dir.join("Pass").join("pass.vault") }));
                seen.push(dir);
            }
        }
    }
    if let Some(dropbox) = dirs::home_dir().map(|h| h.join("Dropbox")) {
        if dropbox.is_dir() {
            out.push(
                json!({ "label": "Dropbox", "path": dropbox.join("Pass").join("pass.vault") }),
            );
        }
    }
    if let Some(icloud) = icloud_drive_dir() {
        out.push(
            json!({ "label": "iCloud Drive", "path": icloud.join("Pass").join("pass.vault") }),
        );
    }
    out
}

/// iCloud Drive, when it is turned on: on macOS `~/Library/Mobile Documents/com~apple~CloudDocs`
/// (pass-macos), on Windows the `iCloudDrive` folder of iCloud for Windows.
fn icloud_drive_dir() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        pass_macos::icloud::drive_dir()
    }
    #[cfg(not(target_os = "macos"))]
    {
        dirs::home_dir()
            .map(|home| home.join("iCloudDrive"))
            .filter(|dir| cfg!(windows) && dir.is_dir())
    }
}

#[tauri::command]
pub async fn pick_vault_file(app: AppHandle) -> Res<Option<String>> {
    blocking(move || {
        let mut dialog = app
            .dialog()
            .file()
            .set_title(tr!("dialog.open_vault_title"))
            .add_filter(tr!("dialog.vault_filter"), &["vault"]);
        if let Some(main) = app.get_webview_window("main") {
            dialog = dialog.set_parent(&main);
        }
        Ok(dialog
            .blocking_pick_file()
            .and_then(|p| p.into_path().ok())
            .map(|p| p.to_string_lossy().into_owned()))
    })
    .await
}

#[tauri::command]
pub async fn pick_vault_save(app: AppHandle) -> Res<Option<String>> {
    blocking(move || {
        let mut dialog = app
            .dialog()
            .file()
            .set_title(tr!("dialog.save_vault_title"))
            .set_file_name("pass.vault")
            .add_filter(tr!("dialog.vault_filter"), &["vault"]);
        if let Some(main) = app.get_webview_window("main") {
            dialog = dialog.set_parent(&main);
        }
        Ok(dialog
            .blocking_save_file()
            .and_then(|p| p.into_path().ok())
            .map(|p| p.to_string_lossy().into_owned()))
    })
    .await
}

pub(crate) fn normalize_vault_path(path: &str) -> Res<PathBuf> {
    let mut path = PathBuf::from(path.trim());
    if path.as_os_str().is_empty() || !path.is_absolute() {
        return Err(tr!("errors.full_path_needed"));
    }
    if path.is_dir() {
        path = path.join("pass.vault");
    }
    if path.extension().is_none() {
        path.set_extension("vault");
    }
    Ok(path)
}

/// The old 8-character minimum, for a password that already exists and isn't being chosen now: a
/// Passyble Server account's password, which also becomes the vault's. Refusing it would lock the user
/// out, so the master password rule ([`check_new_master_password`]) isn't applied there.
pub(crate) fn check_master_password(password: &str) -> Res<()> {
    if password.chars().count() < 8 {
        return Err(tr!("errors.password_too_short"));
    }
    Ok(())
}

/// What a new master password must not be built from: `names` and, with `active_vault`, the open
/// vault's name, Passyble Server user and Google account.
pub(crate) fn master_password_context(
    state: &AppState,
    names: &[String],
    active_vault: bool,
) -> pass_core::MasterPasswordContext {
    let mut all: Vec<String> = names.iter().take(16).cloned().collect();
    if active_vault {
        if let Some(entry) = state.settings().active() {
            all.extend(vault_entry_names(entry));
        }
    }
    all.retain(|n| !n.trim().is_empty());
    pass_core::MasterPasswordContext { names: all }
}

pub(crate) fn vault_entry_names(entry: &settings::VaultEntry) -> Vec<String> {
    let mut names = vec![entry.name.clone()];
    if let Some(w) = &entry.webdav {
        names.push(w.username.clone());
    }
    if let Some(g) = &entry.google_drive {
        names.push(g.account_email.clone());
    }
    names
}

/// The master password rule (`pass_core::require_master_password`) for a password the user is choosing
/// now. The window already showed the reasons while typing (`master_password_check`); this is the same
/// check on the way in.
pub(crate) fn check_new_master_password(
    state: &AppState,
    password: &str,
    names: &[String],
    active_vault: bool,
) -> Res<()> {
    let context = master_password_context(state, names, active_vault);
    pass_core::require_master_password(password, &context).map_err(pass_err)
}

/// Adds `path` to the vault list (or finds it), stores the WebDAV password, makes it active and points
/// the agent at it. Returns the agent and the vault's list id.
pub(crate) fn prepare_agent(
    app: &AppHandle,
    path: PathBuf,
    name: Option<String>,
    webdav: Option<(WebDavSettings, String)>,
) -> Res<(Arc<pass_agent::Agent>, String)> {
    let state = app_state(app);
    let id = state.update_settings(|s| {
        Ok(s.add_vault(
            path,
            name.as_deref(),
            webdav.as_ref().map(|(w, _)| w.clone()),
        ))
    })?;
    if let Some((webdav, password)) = &webdav {
        settings::set_webdav_password(&id, webdav, password)?;
    }
    // Switching locks the vault that was active (it is saved to its own file first).
    let agent = vaults::activate(app, &id)?;
    Ok((agent, id))
}

/// After a master-password unlock of list entry `vault`: record it for the Windows Hello policy, set up
/// (or migrate) its Hello unlock and remember when it was opened. First-time setup shows Hello's prompt.
pub(crate) fn after_password_unlock(
    state: &AppState,
    agent: &pass_agent::Agent,
    vault: &str,
) -> Value {
    let mut warning = None;
    hello::policy::mark_password_unlock(vault);
    if state
        .settings()
        .vault(vault)
        .is_some_and(|v| v.windows_hello)
    {
        let _hello = state.ui.hello_lock();
        match hello::after_password_unlock(agent, vault, state.ui.main_owner()) {
            Ok(note) => warning = note,
            Err(e) => {
                warning = Some(crate::errors::logged(
                    tr!("warnings.hello_setup_failed"),
                    "Windows Hello setup",
                    e,
                ))
            }
        }
    }
    vaults::mark_opened(state, vault);
    json!({ "warning": warning })
}

/// "Use on this PC": a new vault. `google_email`: the user signed in to Google for "Back up to Google
/// Drive" (`google_sign_in`): backup is turned on and the vault uploaded (a failed upload is a warning).
#[tauri::command]
pub async fn setup_create(
    app: AppHandle,
    path: String,
    password: String,
    name: Option<String>,
    google_email: Option<String>,
) -> Res<Value> {
    blocking(move || {
        let names = [name.clone().unwrap_or_default(), google_email.clone().unwrap_or_default()];
        check_new_master_password(&app_state(&app), &password, &names, false)?;
        let path = normalize_vault_path(&path)?;
        if path.exists() {
            return Err(tr!("errors.file_exists"));
        }
        let (agent, id) = prepare_agent(&app, path, name, None)?;
        agent.create_vault(&password).map_err(pass_err)?;
        // The window offers a recovery code next, without asking for this password again.
        crate::recovery::grant(&id);
        let mut result = after_password_unlock(&app_state(&app), &agent, &id);
        if let Some(email) = google_email.filter(|e| !e.trim().is_empty()) {
            if let Some(warning) = crate::gdrive::after_create(&app, &email) {
                result["warning"] = json!(warning);
            }
        }
        Ok(result)
    })
    .await
}

#[tauri::command]
pub async fn setup_open(
    app: AppHandle,
    path: String,
    password: String,
    name: Option<String>,
) -> Res<Value> {
    blocking(move || {
        let path = normalize_vault_path(&path)?;
        if !path.is_file() {
            return Err(tr!("errors.no_vault_file"));
        }
        // A vault linked to a Passyble account opens with the Passyble password: it joins the
        // list and the window shows its unlock form (account_keys.rs).
        let linked = std::fs::read(&path)
            .ok()
            .and_then(|b| pass_core::vault_file_access(b).ok())
            .filter(|a| a.kind == "account")
            .and_then(|a| a.account);
        if let Some(account) = linked {
            let (_, id) = prepare_agent(&app, path, name, None)?;
            app_state(&app).update_settings(|s| {
                if let Some(v) = s.vaults.iter_mut().find(|v| v.id == id) {
                    v.linked_account = Some(account.clone());
                }
                Ok(())
            })?;
            return Ok(json!({ "linked": true, "vault_id": id }));
        }
        let (agent, id) = prepare_agent(&app, path, name, None)?;
        agent.unlock(&password).map_err(pass_err)?;
        crate::health::note_master_password_unlock(&app_state(&app), &id, &password);
        Ok(after_password_unlock(&app_state(&app), &agent, &id))
    })
    .await
}

#[tauri::command]
pub async fn setup_webdav_restore(
    app: AppHandle,
    url: String,
    username: String,
    webdav_password: String,
    path: String,
    password: String,
    name: Option<String>,
) -> Res<Value> {
    #[cfg(feature = "webdav")]
    {
        blocking(move || {
            let webdav = WebDavSettings {
                url: url.trim().to_string(),
                username: username.trim().to_string(),
                ..Default::default()
            };
            restore_from_remote(&app, webdav, webdav_password, &path, &password, name)
        })
        .await
    }
    #[cfg(not(feature = "webdav"))]
    {
        let _ = (app, url, username, webdav_password, path, password, name);
        Err(tr!("errors.no_webdav_build"))
    }
}

/// Downloads the vault from a WebDAV account (or Passyble Server), checks the master password before
/// writing anything, keeps a local copy at `path`, adds it to the list and unlocks it.
#[cfg(feature = "webdav")]
pub(crate) fn restore_from_remote(
    app: &AppHandle,
    webdav: WebDavSettings,
    secret: String,
    path: &str,
    password: &str,
    name: Option<String>,
) -> Res<Value> {
    let path = normalize_vault_path(path)?;
    if path.exists() {
        return Err(tr!("errors.local_file_exists"));
    }
    let config = pass_core::WebDavConfig {
        url: webdav.url.clone(),
        username: webdav.username.clone(),
        password: secret.clone(),
        pins: webdav.pins.clone(),
    };
    let bytes = pass_core::webdav_download(config).map_err(pass_err)?;
    let device_id = app_state(app).settings().device_id;
    pass_core::Vault::unlock(bytes.clone(), password.to_string(), device_id).map_err(pass_err)?;
    // Temporary file, flush, rename (it creates the folder): a crash can't leave half a vault.
    pass_agent::store::write_file_atomically(&path, &bytes)
        .map_err(crate::errors::file_not_saved)?;
    let (agent, id) = prepare_agent(app, path, name, Some((webdav, secret)))?;
    agent.unlock(password).map_err(pass_err)?;
    crate::health::note_master_password_unlock(&app_state(app), &id, password);
    Ok(after_password_unlock(&app_state(app), &agent, &id))
}

pub(crate) fn unlock_target(
    app: &AppHandle,
    vault_id: Option<String>,
) -> Res<(Arc<pass_agent::Agent>, String)> {
    let state = app_state(app);
    match vault_id.filter(|id| !id.is_empty()) {
        Some(id) => Ok((vaults::activate(app, &id)?, id)),
        None => Ok((state.require_agent()?, vaults::active_id(&state)?)),
    }
}

/// Switching to another vault: checks the master password against its file before anything is locked,
/// so a wrong password leaves the open vault as it was. Skipped when nothing is unlocked, for the active
/// vault, or when the file can't be read (the normal unlock reports that). A server vault whose password
/// changed on another device may open from the server's copy, so that error is left to the normal unlock.
fn check_switch_password(app: &AppHandle, vault_id: Option<&str>, password: &str) -> Res<()> {
    let Some(id) = vault_id.filter(|id| !id.is_empty()) else {
        return Ok(());
    };
    let state = app_state(app);
    let settings = state.settings();
    if settings.active_vault.as_deref() == Some(id) || state.agent().is_none_or(|a| a.is_locked()) {
        return Ok(());
    }
    let Some(entry) = settings.vault(id) else {
        return Ok(());
    };
    if entry.webdav.is_some() {
        return Ok(());
    }
    let Ok(bytes) = std::fs::read(&entry.path) else {
        return Ok(());
    };
    match pass_core::Vault::unlock(bytes, password.to_string(), settings.device_id.clone()) {
        Err(PassError::InvalidPassword) => Err(pass_err(PassError::InvalidPassword)),
        _ => Ok(()),
    }
}

#[tauri::command]
pub async fn unlock(app: AppHandle, password: String, vault_id: Option<String>) -> Res<Value> {
    // Wiped when the unlock is done, not left in a freed heap block.
    let password = zeroize::Zeroizing::new(password);
    blocking(move || {
        let state = app_state(&app);
        check_switch_password(&app, vault_id.as_deref(), &password)?;
        let (agent, id) = unlock_target(&app, vault_id)?;
        match agent.unlock(&password) {
            Ok(()) => crate::teams::note_master_password(&password),
            // A Passyble Server vault whose password was changed on another device: the server's
            // copy opens with the new password (see `signin::refresh_from_server`).
            Err(PassError::InvalidPassword)
                if crate::signin::refresh_from_server(&app, &agent, &id, &password) => {}
            // The same for a WebDAV or Google Drive vault: the synced copy has the new key.
            Err(PassError::InvalidPassword)
                if crate::password_change::refresh_from_sync(&app, &agent, &id, &password)
                    .unwrap_or(false) => {}
            Err(e) => return Err(pass_err(e)),
        }
        crate::health::note_master_password_unlock(&state, &id, &password);
        Ok(after_password_unlock(&state, &agent, &id))
    })
    .await
}

#[tauri::command]
pub async fn unlock_hello(app: AppHandle, vault_id: Option<String>) -> Res<Value> {
    blocking(move || {
        let state = app_state(&app);
        let (agent, id) = unlock_target(&app, vault_id)?;
        let Some(entry) = state.settings().vault(&id).cloned() else {
            return Err(tr!("errors.vault_not_listed"));
        };
        if !entry.windows_hello {
            return Err(tr!("errors.hello_off_for_vault"));
        }
        // Never from a window that isn't on screen (the hidden window of a start with Windows):
        // Windows Hello shows only for something the user asked for in front of them.
        if !popups::main_on_screen(&app) {
            return Err(tr!("errors.hello_cancelled"));
        }
        let _hello = state.ui.hello_lock();
        if !agent.is_locked() {
            return Ok(json!({ "warning": null }));
        }
        let owner = app
            .get_webview_window("main")
            .and_then(|w| platform::window_handle(&w));
        let note = hello::unlock(&agent, &id, owner, &entry.hello_policy)?;
        vaults::mark_opened(&state, &id);
        Ok(json!({ "warning": note }))
    })
    .await
}

/// "Use master password instead" (or typing it) in the main window's unlock form while its Hello is
/// pending: cancels that Hello operation so `unlock_hello` answers at once. `true` if one was pending.
/// Windows may leave an already shown dialog up until the user closes it.
#[tauri::command]
pub fn cancel_hello_unlock(app: AppHandle) -> bool {
    let owner = app
        .get_webview_window("main")
        .and_then(|w| platform::window_handle(&w));
    hello::focus::cancel(owner)
}

#[tauri::command]
pub fn cancel_unlock(state: AppState_<'_>) {
    state.resolve_unlock_waiters(false);
}

/// Ctrl+L / the lock button (soft while "Keep list visible when locked" is on, never a full lock, and
/// not while already soft-locked); `full`: "Lock completely", "Switch vault" and adding a server vault,
/// which drop the list from memory too. `forget`: the list kept on disk goes as well.
#[tauri::command]
pub fn lock(app: AppHandle, full: Option<bool>, forget: Option<bool>) {
    if forget == Some(true) {
        tray::lock_and_forget_list(&app);
    } else if full == Some(true) {
        tray::lock_completely(&app);
    } else {
        tray::lock_now(&app);
    }
}

enum Listing {
    Unlocked(Vec<(pass_agent::VaultRef, Arc<pass_core::Vault>)>),
    Locked(Vec<(pass_agent::VaultRef, Arc<Vec<pass_core::ItemSummary>>)>),
}

impl Listing {
    fn several(&self) -> bool {
        match self {
            Listing::Unlocked(v) => v.len() > 1,
            Listing::Locked(v) => v.len() > 1,
        }
    }

    fn kept(
        list: &[(pass_agent::VaultRef, Arc<Vec<pass_core::ItemSummary>>)],
    ) -> Vec<pass_core::ItemSummary> {
        list.iter().flat_map(|(_, l)| l.iter().cloned()).collect()
    }

    fn summary(&self, id: &str) -> Option<(pass_agent::VaultRef, pass_core::ItemSummary)> {
        match self {
            Listing::Unlocked(vaults) => vaults.iter().find_map(|(r, v)| {
                v.get(id.to_string())
                    .map(|i| (r.clone(), pass_core::ItemSummary::of(&i)))
            }),
            Listing::Locked(lists) => lists.iter().find_map(|(r, l)| {
                l.iter()
                    .find(|s| s.id == id)
                    .map(|s| (r.clone(), s.clone()))
            }),
        }
    }
}

/// The open vault holding item `id` (the home vault or a shared one) and what the user may do
/// there; activity for the auto-lock unless `quiet`. Locked: [`VAULT_LOCKED`].
fn vault_of(
    state: &AppState,
    id: &str,
    quiet: bool,
) -> Res<(pass_agent::VaultRef, Arc<pass_core::Vault>)> {
    let agent = state.require_agent()?;
    if quiet {
        agent.peek_vault().ok_or_else(|| VAULT_LOCKED.to_string())?;
    } else {
        agent.vault().ok_or_else(|| VAULT_LOCKED.to_string())?;
    }
    agent
        .vault_of_item(id)
        .ok_or_else(|| tr!("errors.item_not_found"))
}

fn editable(vault: &pass_agent::VaultRef) -> Res<()> {
    if vault.can_edit {
        Ok(())
    } else {
        Err(tr!("errors.teams_read_only"))
    }
}

/// A secret of a fill-only member's login (its password, history, hidden fields, card number):
/// never shown or copied.
fn revealable(vault: &pass_agent::VaultRef) -> Res<()> {
    if vault.can_reveal {
        Ok(())
    } else {
        Err(tr!("errors.teams_fill_only"))
    }
}

/// The unlocked vault or else the kept list. [`VAULT_LOCKED`] when fully locked. Reading it is activity
/// for the auto-lock unless `quiet`: the window passes that when it reloads on its own (a sync or the
/// extension changed the vault), so a sync never keeps the vault unlocked.
fn listing(state: &AppState, quiet: bool) -> Res<Listing> {
    let agent = state.require_agent()?;
    let vault = if quiet {
        agent.peek_vault()
    } else {
        agent.vault()
    };
    if vault.is_some() {
        let open = agent.open_vaults();
        if !open.is_empty() {
            return Ok(Listing::Unlocked(open));
        }
    }
    agent
        .all_summaries()
        .map(Listing::Locked)
        .ok_or_else(|| VAULT_LOCKED.to_string())
}

#[tauri::command]
pub fn list_items(state: AppState_<'_>, quiet: Option<bool>) -> Res<Vec<ItemSummary>> {
    let listing = listing(&state, quiet.unwrap_or(false))?;
    let several = listing.several();
    let tag = |s: ItemSummary, r: &pass_agent::VaultRef| if several { s.in_vault(r) } else { s };
    Ok(match listing {
        Listing::Unlocked(vaults) => vaults
            .iter()
            .flat_map(|(r, vault)| {
                vault
                    .items()
                    .iter()
                    .map(|i| tag(ItemSummary::of(vault, i), r))
                    .collect::<Vec<_>>()
            })
            .collect(),
        Listing::Locked(lists) => lists
            .iter()
            .flat_map(|(r, list)| {
                list.iter()
                    .map(|s| tag(ItemSummary::from(s), r))
                    .collect::<Vec<_>>()
            })
            .collect(),
    })
}

#[tauri::command]
pub fn search(state: AppState_<'_>, query: String, quiet: Option<bool>) -> Res<Vec<ItemSummary>> {
    let listing = listing(&state, quiet.unwrap_or(false))?;
    let several = listing.several();
    Ok(match &listing {
        Listing::Unlocked(vaults) if !several => {
            let vault = &vaults[0].1;
            vault
                .search(query)
                .iter()
                .map(|i| ItemSummary::of(vault, i))
                .collect()
        }
        Listing::Unlocked(vaults) => {
            let groups: Vec<pass_core::VaultSummaries> =
                vaults.iter().map(|(_, v)| v.vault_summaries()).collect();
            pass_core::multi_search(groups, query)
                .into_iter()
                .filter_map(|hit| {
                    let (r, vault) = vaults.iter().find(|(r, _)| r.id == hit.vault_id)?;
                    let item = vault.get(hit.summary.id.clone())?;
                    Some(ItemSummary::of(vault, &item).in_vault(r))
                })
                .collect()
        }
        Listing::Locked(lists) => pass_core::summaries_search(Listing::kept(lists), query)
            .iter()
            .map(|s| {
                let row = ItemSummary::from(s);
                match listing.summary(&s.id) {
                    Some((r, _)) if several => row.in_vault(&r),
                    _ => row,
                }
            })
            .collect(),
    })
}

#[tauri::command]
pub fn get_item(state: AppState_<'_>, id: String, quiet: Option<bool>) -> Res<ItemDto> {
    let listing = listing(&state, quiet.unwrap_or(false))?;
    let several = listing.several();
    let found = match &listing {
        Listing::Unlocked(vaults) => vaults
            .iter()
            .find_map(|(r, v)| v.get(id.clone()).map(|i| (r.clone(), ItemDto::from(i)))),
        Listing::Locked(_) => listing.summary(&id).map(|(r, s)| (r, ItemDto::locked(&s))),
    };
    let (vault, dto) = found.ok_or_else(|| tr!("errors.item_not_found"))?;
    Ok(if several || !vault.can_reveal {
        dto.in_vault(Some(&vault))
    } else {
        dto
    })
}

#[tauri::command]
pub fn get_item_for_edit(state: AppState_<'_>, id: String) -> Res<ItemDto> {
    let (vault_ref, vault) = vault_of(&state, &id, false)?;
    // The editor changes the item and shows its secrets: neither for view and fill members.
    editable(&vault_ref)?;
    revealable(&vault_ref)?;
    vault
        .get(id)
        .map(|i| ItemDto::for_edit(i).in_vault(Some(&vault_ref)))
        .ok_or_else(|| tr!("errors.item_not_found"))
}

/// One secret of an item for "Show" in the detail view, only while unlocked: `card_number`,
/// `card_code`, `card_pin` or `field.<index>` (a custom field's value).
#[tauri::command]
pub fn item_secret(state: AppState_<'_>, id: String, field: String) -> Res<String> {
    let (vault_ref, vault) = vault_of(&state, &id, false)?;
    revealable(&vault_ref)?;
    let item = vault.get(id).ok_or_else(|| tr!("errors.item_not_found"))?;
    secret_of(&item, &field)?.ok_or_else(|| tr!("errors.unknown_field"))
}

/// The value `copy_field` / `item_secret` mean by `field`, beyond the username, password and 2FA
/// code: a card's parts, an identity's details (`identity.<name>`), a custom field
/// (`field.<index>`). `Ok(None)`: not such a field.
fn secret_of(item: &Item, field: &str) -> Res<Option<String>> {
    let card = || item.card.clone().unwrap_or_default();
    Ok(Some(match field {
        "card_number" => card().number,
        "card_code" => card().security_code,
        "card_pin" => card().pin,
        "card_holder" => card().cardholder_name,
        "card_expiry" => {
            let c = card();
            expiry_text(c.expiry_month, c.expiry_year)
        }
        _ => {
            if let Some(name) = field.strip_prefix("identity.") {
                let identity = item.identity.clone().unwrap_or_default();
                let value = serde_json::to_value(&identity).map_err(|e| e.to_string())?;
                match name {
                    "full_name" => identity.full_name(),
                    "address" => address_text(&identity),
                    _ => value
                        .get(name)
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                }
            } else if let Some(index) = field.strip_prefix("field.") {
                let index: usize = index.parse().map_err(|_| tr!("errors.unknown_field"))?;
                item.fields
                    .get(index)
                    .map(|f| f.value.clone())
                    .ok_or_else(|| tr!("errors.fields_changed"))?
            } else {
                return Ok(None);
            }
        }
    }))
}

fn expiry_text(month: u32, year: u32) -> String {
    match (month, year) {
        (0, 0) => String::new(),
        (m, 0) => format!("{m:02}"),
        (0, y) => format!("{y}"),
        (m, y) => format!("{m:02}/{:02}", y % 100),
    }
}

fn address_text(i: &IdentityData) -> String {
    let city = [i.postal_code.trim(), i.city.trim()]
        .iter()
        .filter(|s| !s.is_empty())
        .copied()
        .collect::<Vec<_>>()
        .join(" ");
    [
        i.address1.trim(),
        i.address2.trim(),
        i.address3.trim(),
        city.as_str(),
        i.region.trim(),
        i.country.trim(),
    ]
    .iter()
    .filter(|s| !s.is_empty())
    .copied()
    .collect::<Vec<_>>()
    .join("\n")
}

/// Opens one of an item's web addresses in the default browser: `url.<index>` (also while soft-locked)
/// or `field.<index>` (a "Web address" custom field). Only `http(s)`, a bare host gets `https://`.
#[tauri::command]
pub fn open_item_url(state: AppState_<'_>, id: String, field: String) -> Res<()> {
    let url = if let Some(index) = field.strip_prefix("url.") {
        let index: usize = index.parse().map_err(|_| tr!("errors.unknown_field"))?;
        match listing(&state, false)? {
            l @ (Listing::Unlocked(_) | Listing::Locked(_)) => l.summary(&id).map(|(_, s)| s.urls),
        }
        .ok_or_else(|| tr!("errors.item_not_found"))?
        .get(index)
        .cloned()
        .ok_or_else(|| tr!("errors.websites_changed"))?
    } else if field.starts_with("field.") {
        let item = state
            .vault()?
            .get(id)
            .ok_or_else(|| tr!("errors.item_not_found"))?;
        secret_of(&item, &field)?.ok_or_else(|| tr!("errors.unknown_field"))?
    } else {
        return Err(tr!("errors.unknown_field"));
    };
    let url = web_address(&url).ok_or_else(|| tr!("errors.not_web_address"))?;
    platform::open_browser(&url)
}

/// `value` as an `http(s)` address to open, `None` for anything else (other schemes, app links,
/// spaces, quotes or control characters).
fn web_address(value: &str) -> Option<String> {
    let v = value.trim();
    if v.is_empty()
        || v.chars().any(|c| {
            c.is_whitespace()
                || c.is_control()
                || matches!(c, '"' | '<' | '>' | '`' | '^' | '|' | '\\')
        })
    {
        return None;
    }
    let lower = v.to_ascii_lowercase();
    let url = if lower.starts_with("https://") || lower.starts_with("http://") {
        v.to_string()
    } else if !v.contains("://") && !v.contains(':') && v.contains('.') && !v.starts_with('.') {
        format!("https://{v}")
    } else {
        return None;
    };
    let host = url.split("://").nth(1)?.split(['/', '?', '#']).next()?;
    (!host.is_empty() && !host.starts_with('-')).then_some(url)
}

#[tauri::command]
pub fn card_info(number: String) -> Value {
    let digits = number.chars().filter(char::is_ascii_digit).count();
    let brand = card_brand(number.clone());
    json!({
        "brand": brand,
        "brand_name": card_brand_name(brand.clone()),
        "digits": digits,
        "valid": card_number_valid(number),
    })
}

/// The editor's website row: a site on shared hosting (`alice.github.io`) is best matched on its
/// own host, so the row's menu suggests "Same host only". Only a suggestion; nothing is stored.
#[tauri::command]
pub fn url_suggests_host_only(url: String) -> bool {
    pass_core::url_suggests_host_only(url)
}

#[tauri::command]
pub fn site_suggestions(query: String, limit: u32) -> Vec<pass_core::SiteSuggestion> {
    pass_core::site_suggestions(query, limit)
}

#[tauri::command]
pub fn site_name_for(url: String) -> Option<String> {
    pass_core::site_for_domain(url)
}

#[tauri::command]
pub fn vault_tags(state: AppState_<'_>) -> Res<Vec<Value>> {
    let tags = match listing(&state, false)? {
        Listing::Unlocked(vaults) if vaults.len() == 1 => vaults[0].1.tags(),
        Listing::Unlocked(vaults) => {
            pass_core::summaries_tags(vaults.iter().flat_map(|(_, v)| v.summaries()).collect())
        }
        Listing::Locked(lists) => pass_core::summaries_tags(Listing::kept(&lists)),
    };
    Ok(tags
        .into_iter()
        .map(|t| json!({ "tag": t.tag, "count": t.count }))
        .collect())
}

#[tauri::command]
pub fn save_item(state: AppState_<'_>, item: ItemDto) -> Res<ItemDto> {
    // Teams and Family: an existing item stays in its vault; a new one goes into the vault the
    // window chose (`vault_id`), else the home vault. Never a vault the user may only use.
    let (vault_ref, vault) = if item.id.is_empty() {
        let agent = state.require_agent()?;
        state.vault()?;
        let open = agent.open_vaults();
        let wanted = item.vault_id.clone().filter(|v| !v.is_empty());
        match wanted {
            Some(id) => open
                .into_iter()
                .find(|(r, _)| r.id == id)
                .ok_or_else(|| tr!("errors.teams_vault_not_open"))?,
            None => open
                .into_iter()
                .next()
                .ok_or_else(|| VAULT_LOCKED.to_string())?,
        }
    } else {
        vault_of(&state, &item.id, false)?
    };
    editable(&vault_ref)?;
    // A copy from the soft-lock list (no password, 2FA secret or notes in it), e.g. read just before
    // an unlock: saving it would erase them. The window unlocks / re-reads the item and tries again.
    if item.locked {
        return Err(VAULT_LOCKED.into());
    }
    if item.partial {
        return Err(tr!("errors.item_partial"));
    }
    let mut target = if item.id.is_empty() {
        Item::default()
    } else {
        vault
            .get(item.id.clone())
            .ok_or_else(|| tr!("errors.item_not_found"))?
    };
    // Every field comes from the window's copy, so saving a copy that is older than the vault's
    // (a sync merged a new password, the extension added a passkey) would silently undo that
    // change everywhere. `updated_at` is the version the window loaded.
    if !item.id.is_empty() && item.updated_at != target.updated_at {
        return Err(tr!("errors.item_changed"));
    }
    let totp = item
        .totp
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty());
    if let Some(secret) = &totp {
        totp_parse(secret.clone()).map_err(pass_err)?;
    }
    let mut title = item.title.trim().to_string();
    if title.is_empty() && item.kind == ItemKind::Identity {
        title = item
            .identity
            .as_ref()
            .map(IdentityData::full_name)
            .unwrap_or_default();
    }
    let card_titled = item.kind == ItemKind::Card
        && item
            .card
            .as_ref()
            .is_some_and(|c| c.number.chars().any(|ch| ch.is_ascii_digit()) || !c.brand.is_empty());
    if title.is_empty() && !card_titled {
        return Err(tr!("editor.needs_title"));
    }
    target.kind = item.kind;
    target.title = title;
    target.username = item.username;
    target.password = item.password;
    target.urls = item
        .urls
        .into_iter()
        .map(|u| u.trim().to_string())
        .filter(|u| !u.is_empty())
        .collect();
    apply_match_rules(&mut target, item.url_rules, &item.android_never_show);
    target.totp = totp;
    target.notes = item.notes;
    target.favorite = item.favorite;
    target.card = match item.kind {
        ItemKind::Card => Some(item.card.unwrap_or_default().into_card()),
        _ => None,
    };
    target.identity = match item.kind {
        ItemKind::Identity => Some(trim_identity(item.identity.unwrap_or_default())),
        _ => None,
    };
    target.fields = item
        .fields
        .into_iter()
        .filter(|f| !(f.name.trim().is_empty() && f.value.is_empty()))
        .map(|f| CustomField {
            name: f.name.trim().to_string(),
            value: f.value,
            kind: f.kind,
        })
        .collect();
    // The switch decides; a field typed with the mark's name is replaced by it.
    target.set_ai_access(match item.ai_access.as_deref() {
        Some("allow") => Some(pass_core::AiAccess::Allow),
        Some("ask") => Some(pass_core::AiAccess::Ask),
        _ => None,
    });
    target.tags = item.tags;
    let keep: Vec<&str> = item
        .passkeys
        .iter()
        .map(|p| p.credential_id.as_str())
        .collect();
    target
        .passkeys
        .retain(|p| keep.contains(&b64url_encode(p.credential_id.clone()).as_str()));
    let saved = vault.upsert(target).map_err(pass_err)?;
    let agent = state.require_agent()?;
    agent.save().map_err(pass_err)?;
    let several = agent.open_vaults().len() > 1;
    Ok(ItemDto::from(saved).in_vault(several.then_some(&vault_ref)))
}

fn trim_identity(mut i: IdentityData) -> IdentityData {
    for v in [
        &mut i.honorific,
        &mut i.first_name,
        &mut i.middle_name,
        &mut i.last_name,
        &mut i.email,
        &mut i.phone,
        &mut i.address1,
        &mut i.address2,
        &mut i.address3,
        &mut i.city,
        &mut i.region,
        &mut i.postal_code,
        &mut i.country,
        &mut i.company,
        &mut i.birth_date,
    ] {
        *v = v.trim().to_string();
    }
    i
}

/// Moves an item to the trash (`Vault::delete`). A copy stays in memory for a minute (until the vault
/// locks) so the toast's Undo (`restore_item`) works even if the trash was emptied on another device.
#[tauri::command]
pub fn delete_item(state: AppState_<'_>, id: String) -> Res<Value> {
    let (vault_ref, vault) = vault_of(&state, &id, false)?;
    editable(&vault_ref)?;
    let item = vault
        .get(id.clone())
        .ok_or_else(|| tr!("errors.item_not_found"))?;
    vault.delete(id).map_err(pass_err)?;
    state.require_agent()?.save().map_err(pass_err)?;
    crate::undo::item_deleted(&vault.vault_id(), item);
    Ok(json!({ "undo_secs": crate::undo::ITEM_UNDO_WINDOW.as_secs() }))
}

#[tauri::command]
pub fn restore_item(state: AppState_<'_>, id: String) -> Res<ItemDto> {
    let (vault_ref, vault) = match vault_of(&state, &id, false) {
        Ok(found) => found,
        Err(_) => {
            let home = state.vault()?;
            let r = state
                .require_agent()?
                .home_ref()
                .ok_or_else(|| VAULT_LOCKED.to_string())?;
            (r, home)
        }
    };
    editable(&vault_ref)?;
    let restored =
        restore_one(&vault, &vault.vault_id(), &id)?.ok_or_else(|| tr!("errors.too_late_undo"))?;
    state.require_agent()?.save().map_err(pass_err)?;
    Ok(restored.into())
}

fn restore_one(vault: &pass_core::Vault, vault_id: &str, id: &str) -> Res<Option<Item>> {
    let copy = crate::undo::take_item(vault_id, id);
    match vault.restore(id.to_string()) {
        Ok(item) => Ok(Some(item)),
        Err(PassError::NotFound(_)) => match copy {
            Some(mut item) => {
                item.trashed_at = None;
                Ok(Some(vault.upsert(item).map_err(pass_err)?))
            }
            None => Ok(None),
        },
        Err(e) => Err(pass_err(e)),
    }
}

#[tauri::command]
pub fn delete_items(state: AppState_<'_>, ids: Vec<String>) -> Res<Value> {
    state.vault()?;
    let agent = state.require_agent()?;
    let mut deleted: Vec<(String, Item)> = Vec::new();
    for id in ids {
        let Some((vault_ref, vault)) = agent.vault_of_item(&id) else {
            continue;
        };
        let Some(item) = vault.get(id.clone()).filter(|_| vault_ref.can_edit) else {
            continue;
        };
        vault.delete(id).map_err(pass_err)?;
        deleted.push((vault.vault_id(), item));
    }
    let count = deleted.len();
    if count > 0 {
        agent.save().map_err(pass_err)?;
        let mut by_vault: std::collections::BTreeMap<String, Vec<Item>> = Default::default();
        for (vault_id, item) in deleted {
            by_vault.entry(vault_id).or_default().push(item);
        }
        for (vault_id, items) in by_vault {
            crate::undo::items_deleted(&vault_id, items);
        }
    }
    Ok(json!({ "deleted": count, "undo_secs": crate::undo::ITEM_UNDO_WINDOW.as_secs() }))
}

#[tauri::command]
pub fn restore_items(state: AppState_<'_>, ids: Vec<String>) -> Res<Vec<ItemDto>> {
    let home = state.vault()?;
    let agent = state.require_agent()?;
    let mut restored = Vec::new();
    for id in ids {
        let vault = match agent.vault_of_item(&id) {
            Some((r, v)) if r.can_edit => v,
            Some(_) => continue,
            None => home.clone(),
        };
        if let Some(item) = restore_one(&vault, &vault.vault_id(), &id)? {
            restored.push(item);
        }
    }
    if restored.is_empty() {
        return Err(tr!("errors.too_late_undo"));
    }
    state.require_agent()?.save().map_err(pass_err)?;
    Ok(restored.into_iter().map(ItemDto::from).collect())
}

/// Stars (or unstars) several items with one save, reading each from the unlocked vault so a copy
/// without secrets is never written back. Returns how many changed.
#[tauri::command]
pub fn set_favorites(state: AppState_<'_>, ids: Vec<String>, favorite: bool) -> Res<Value> {
    state.vault()?;
    let agent = state.require_agent()?;
    let mut changed = 0;
    for id in ids {
        let Some((vault_ref, vault)) = agent.vault_of_item(&id) else {
            continue;
        };
        if !vault_ref.can_edit {
            continue;
        }
        let Some(mut item) = vault.get(id) else {
            continue;
        };
        if item.favorite == favorite {
            continue;
        }
        item.favorite = favorite;
        vault.upsert(item).map_err(pass_err)?;
        changed += 1;
    }
    if changed > 0 {
        state.require_agent()?.save().map_err(pass_err)?;
    }
    Ok(json!({ "changed": changed }))
}

#[tauri::command]
pub async fn enable_hello(app: AppHandle) -> Res<Value> {
    blocking(move || {
        let state = app_state(&app);
        if !state
            .hello_available
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            return Err(tr!("errors.hello_not_set_up"));
        }
        let agent = state.require_agent()?;
        if agent.is_locked() {
            return Err(tr!("errors.unlock_first"));
        }
        let id = vaults::active_id(&state)?;
        let note = {
            let _hello = state.ui.hello_lock();
            hello::enroll(&agent, &id, state.ui.main_owner())?
        };
        state.update_settings(|s| {
            let v = s
                .vault_mut(&id)
                .ok_or_else(|| tr!("errors.vault_not_listed"))?;
            v.windows_hello = true;
            Ok(())
        })?;
        hello::policy::mark_password_unlock(&id);
        Ok(json!({ "warning": note }))
    })
    .await
}

#[tauri::command]
pub fn dismiss_hello_offer(state: AppState_<'_>) -> Res<()> {
    let id = vaults::active_id(&state)?;
    state.update_settings(|s| {
        if let Some(v) = s.vault_mut(&id) {
            v.hello_offer_dismissed = true;
        }
        Ok(())
    })
}

fn totp_for(state: &AppState, id: &str) -> Res<Value> {
    totp_of(state, id, false)
}

/// [`totp_for`]; `quiet`: not activity (a code shown again when its period ends, in the TOTP popup
/// or the merge view, which refresh on their own).
fn totp_of(state: &AppState, id: &str, quiet: bool) -> Res<Value> {
    let (_, vault) = vault_of(state, id, quiet)?;
    let item = vault
        .get(id.to_string())
        .ok_or_else(|| tr!("errors.item_not_found"))?;
    let secret = item
        .totp
        .filter(|t| !t.trim().is_empty())
        .ok_or_else(|| tr!("errors.no_totp_secret"))?;
    let code = totp_generate(secret, now_secs()).map_err(pass_err)?;
    Ok(json!({ "code": code.code, "period": code.period, "remaining_secs": code.remaining_secs }))
}

#[tauri::command]
pub fn totp(state: AppState_<'_>, id: String, quiet: Option<bool>) -> Res<Value> {
    totp_of(&state, &id, quiet.unwrap_or(false))
}

#[tauri::command]
pub fn totp_check(input: String) -> Value {
    match totp_parse(input.clone()) {
        Ok(config) => {
            let code = totp_generate(input, now_secs()).ok();
            json!({
                "valid": true,
                "issuer": config.issuer,
                "account": config.account,
                "digits": config.digits,
                "period": config.period,
                "code": code.map(|c| c.code),
            })
        }
        Err(e) => json!({ "valid": false, "error": e.to_string() }),
    }
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub struct GenerateOptions {
    length: Option<u32>,
    lowercase: Option<bool>,
    uppercase: Option<bool>,
    digits: Option<bool>,
    symbols: Option<bool>,
    avoid_ambiguous: Option<bool>,
    passphrase: bool,
    words: Option<u32>,
    separator: Option<String>,
}

#[tauri::command]
pub fn generate_password(options: Option<GenerateOptions>) -> Res<String> {
    let o = options.unwrap_or_default();
    if o.passphrase {
        return Ok(generate_passphrase(
            o.words.unwrap_or(PASSPHRASE_DEFAULT_WORDS),
            o.separator.unwrap_or_else(|| "-".into()),
        ));
    }
    let d = PasswordOptions::default();
    core_generate_password(PasswordOptions {
        length: o.length.unwrap_or(d.length).clamp(4, 128),
        lowercase: o.lowercase.unwrap_or(d.lowercase),
        uppercase: o.uppercase.unwrap_or(d.uppercase),
        digits: o.digits.unwrap_or(d.digits),
        symbols: o.symbols.unwrap_or(d.symbols),
        avoid_ambiguous: o.avoid_ambiguous.unwrap_or(d.avoid_ambiguous),
    })
    .map_err(pass_err)
}

#[tauri::command]
pub fn copy_secret(text: String) -> Res<()> {
    clipboard::copy_secret(&text)
}

/// Copies a field without the value passing through the webview: `username`, `password`, `totp`, or
/// what [`secret_of`] names. While soft-locked only what the kept list holds (username, a card's holder,
/// an identity's name, e-mail and company); the rest needs the vault unlocked.
#[tauri::command]
pub fn copy_field(state: AppState_<'_>, id: String, field: String) -> Res<()> {
    if let Some(value) = public_field(&state, &id, &field)? {
        if value.is_empty() {
            return Err(tr!("errors.nothing_to_copy"));
        }
        clipboard::copy_secret(&value)?;
        note_use(&state);
        return Ok(());
    }
    let (vault_ref, vault) = vault_of(&state, &id, false)?;
    // A fill-only member copies the 2FA code, never the password or a hidden value.
    if field != "totp" {
        revealable(&vault_ref)?;
    }
    let item = vault
        .get(id.clone())
        .ok_or_else(|| tr!("errors.item_not_found"))?;
    let value = match field.as_str() {
        "password" => item.password,
        "totp" => totp_for(&state, &id)?["code"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        other => secret_of(&item, other)?.ok_or_else(|| tr!("errors.unknown_field"))?,
    };
    if value.is_empty() {
        return Err(tr!("errors.nothing_to_copy"));
    }
    clipboard::copy_secret(&value)?;
    // A copied password or 2FA code is a use ("most used first"); a username is not. Any copy
    // is a use for the auto-lock and the per-fill grace period.
    if field == "password" || field == "totp" {
        record_use(&state, &id);
    } else {
        note_use(&state);
    }
    Ok(())
}

fn public_field(state: &AppState, id: &str, field: &str) -> Res<Option<String>> {
    if !matches!(
        field,
        "username" | "card_holder" | "identity.full_name" | "identity.email" | "identity.company"
    ) {
        return Ok(None);
    }
    // Quiet: the copy counts once it went through (`note_use`).
    let summary = listing(state, true)?
        .summary(id)
        .map(|(_, s)| s)
        .ok_or_else(|| tr!("errors.item_not_found"))?;
    let card = summary.card.unwrap_or_default();
    let identity = summary.identity.unwrap_or_default();
    Ok(Some(match field {
        "username" => summary.username,
        "card_holder" => card.cardholder_name,
        "identity.full_name" => identity.full_name,
        "identity.email" => identity.email,
        _ => identity.company,
    }))
}

/// The earlier password `index` of item `id` (newest first), after checking the window's copy of the
/// history is still the vault's (`replaced_at`; a sync or edit in between would shift the indexes).
fn history_password(state: &AppState, id: &str, index: usize, replaced_at: i64) -> Res<String> {
    let (vault_ref, vault) = vault_of(state, id, false)?;
    revealable(&vault_ref)?;
    let item = vault
        .get(id.to_string())
        .ok_or_else(|| tr!("errors.item_not_found"))?;
    let entry = item
        .password_history
        .get(index)
        .filter(|e| e.replaced_at == replaced_at)
        .ok_or_else(|| tr!("errors.history_changed"))?;
    if entry.password.is_empty() {
        return Err(tr!("errors.nothing_to_copy"));
    }
    Ok(entry.password.clone())
}

#[tauri::command]
pub fn password_history_entry(
    state: AppState_<'_>,
    id: String,
    index: usize,
    replaced_at: i64,
) -> Res<String> {
    history_password(&state, &id, index, replaced_at)
}

/// Copies one earlier password of an item (cleared after 45 s) without it passing through the
/// webview. Not a "use" of the item.
#[tauri::command]
pub fn copy_history_password(
    state: AppState_<'_>,
    id: String,
    index: usize,
    replaced_at: i64,
) -> Res<()> {
    let value = history_password(&state, &id, index, replaced_at)?;
    clipboard::copy_secret(&value)
}

/// Settings → This vault → Change password, for a vault not on Passyble Server: checks `current`,
/// gives the vault a new key under `new_password` and re-encrypts it (a copy kept with the old password
/// never opens what is saved from now on), saves and syncs. Then what wrapped the old key follows
/// (`password_change::after_change`: recovery code, emergency grants, admin recovery, Windows Hello,
/// old copies). Other devices need the new password at their next unlock after syncing.
#[tauri::command]
pub async fn change_master_password(
    app: AppHandle,
    current: String,
    new_password: String,
) -> Res<Value> {
    blocking(move || {
        let state = app_state(&app);
        let on_server = state
            .settings()
            .active()
            .and_then(|v| v.webdav.as_ref())
            .is_some_and(|w| w.is_pass_server());
        if on_server {
            return Err(tr!("errors.server_password_change_elsewhere"));
        }
        check_new_master_password(&state, &new_password, &[], true)?;
        crate::teams::check_master_password(&app, &new_password)?;
        let agent = state.require_agent()?;
        let vault = state.vault()?;
        if !vault.check_password(current.clone()).map_err(pass_err)? {
            return Err(tr!("errors.current_password_wrong"));
        }
        if current == new_password {
            return Err(tr!("errors.same_password"));
        }
        let before = crate::password_change::before(&vault);
        vault
            .change_master_password(new_password)
            .map_err(pass_err)?;
        // The file now; the vault stays dirty if this fails, so the next save retries.
        agent
            .save()
            .map_err(|e| tr!("errors.password_changed_not_saved", error = pass_err(e)))?;
        if let Ok(id) = vaults::active_id(&state) {
            crate::health::note_master_password_changed(&state, &id);
        }
        let mut result = json!({ "warning": null, "synced": false });
        // Through the scheduler's sync, so the vault view's sync state follows. `None`: no sync
        // account (nothing to upload).
        match crate::background::sync_now(&app) {
            Ok(Some(_)) => result["synced"] = json!(true),
            Ok(None) => {}
            Err(e) => {
                result["warning"] = json!(tr!("warnings.password_changed_not_uploaded", error = e));
            }
        }
        if let Ok(id) = vaults::active_id(&state) {
            crate::password_change::after_change(&app, &agent, &id, &before, &mut result);
        }
        Ok(result)
    })
    .await
}

fn record_use(state: &AppState, id: &str) {
    if let Some(agent) = state.agent() {
        agent.record_use(id);
    }
}

fn note_use(state: &AppState) {
    if let Some(agent) = state.agent() {
        agent.note_use();
    }
}

/// Where "Created for the community by Sensyble" leads. The only address `open_sensyble_site`
/// opens, so the page can't ask for any other.
pub const SENSYBLE_URL: &str = "https://www.sensyble.net";

#[tauri::command]
pub fn open_sensyble_site() -> Result<(), String> {
    crate::platform::open_browser(SENSYBLE_URL)
}

#[tauri::command]
pub fn get_settings(state: AppState_<'_>) -> Value {
    let s = state.settings();
    let vault = s.active().cloned().unwrap_or_default();
    let webdav = vault.webdav.clone().unwrap_or_default();
    // Settings → This vault → Vault file: the file's size on disk (also while soft-locked) and
    // the item count (the unlocked vault's, or the kept list's; unknown when locked completely).
    let vault_bytes = crate::sizes::file_bytes(&vault.path);
    let vault_items = state.agent().and_then(|a| a.item_count());
    let mut out = json!({
        "vault_id": vault.id,
        "vault_name": vault.name,
        "vault_path": vault.path,
        "vault_location": vault.location(),
        "vault_bytes": vault_bytes,
        "vault_items": vault_items,
        "vault_file_text": crate::sizes::vault_file_text(vault_bytes, vault_items),
        "vault_count": s.vaults.len(),
        "auto_lock_minutes": s.auto_lock_minutes,
        "webdav_url": webdav.url,
        "webdav_username": webdav.username,
        "webdav_has_password": vault
            .webdav
            .as_ref()
            .and_then(|w| settings::webdav_password(&vault.id, w))
            .is_some(),
        "pass_server": vault.webdav.as_ref().filter(|w| w.is_pass_server()).map(|w| json!({
            "host": w.host(),
            "device_name": w.server_device,
            "pinned": !w.pins.is_empty(),
        })),
        "webdav_supported": cfg!(feature = "webdav"),
        "google_available": crate::gdrive::available(&s),
        "google_drive": crate::gdrive::active_json(&s),
        "hotkey": s.hotkey,
        "start_minimized": s.start_minimized,
        "start_with_windows": crate::autostart::enabled(),
        "update_auto_check": s.update_auto_check,
        "show_site_icons": s.show_site_icons,
        "keep_list_when_locked": s.keep_list_when_locked,
        "language": s.language,
        "locale": crate::i18n::locale(),
        "site_icons_supported": cfg!(feature = "icons"),
        "version": env!("CARGO_PKG_VERSION"),
        "log_dir": crate::applog::dir(),
        "windows_hello": vault.windows_hello,
        "hello_available": state.hello_available.load(std::sync::atomic::Ordering::Relaxed),
        "hello_enrolled": !vault.id.is_empty() && hello::enrolled(&vault.id),
        // Settings → Unlock: the policy, and whether the key is bound to a Windows Hello key
        // (`false`: DPAPI only, `hello_note` says why) or what Hello is waiting for.
        "hello_policy": vault.hello_policy,
        "hello_status": (!vault.id.is_empty()).then(|| hello::readiness(&vault.id, &vault.hello_policy)),
        "device_id": s.device_id,
        "extra_extension_ids": s.extra_extension_ids,
        "native_host": native_messaging::register(&s.extra_extension_ids),
        "hotkey_error": crate::shortcuts::error(crate::shortcuts::Action::AutoType),
        "ipc_error": guard(&state.ipc_error).clone(),
        "sync": guard(&state.sync).clone(),
        "passkey_provider": s.passkey_provider,
        "passkey_provider_status": crate::passkey_provider::status(),
        "recovery_code": state
            .agent()
            .and_then(|a| a.vault())
            .map(|v| crate::recovery::status_json(&v)),
    });
    // Opens with the Passyble password (account_keys.rs): no master password or vault recovery
    // code of its own.
    out["linked_account"] = json!(vault.linked_account);
    // Settings → Help → Get started checklist: on for this vault (setup_guide.rs). Set apart
    // because one more key overflows `json!`'s recursion limit.
    out["get_started"] = json!(vault.get_started);
    out["auto_lock"] = json!(s.auto_lock);
    // Settings → Autofill → Developer options (extra extension IDs, helper paths, Developer Mode
    // for Windows passkeys): debug builds, or once extension IDs were added by hand.
    out["developer_options"] = json!(cfg!(debug_assertions) || !s.extra_extension_ids.is_empty());
    out
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub struct SettingsUpdate {
    vault_name: Option<String>,
    vault_path: Option<String>,
    auto_lock: Option<crate::auto_lock::AutoLock>,
    auto_lock_minutes: Option<u32>,
    webdav_url: Option<String>,
    webdav_username: Option<String>,
    /// Only stored when non-empty.
    webdav_password: Option<String>,
    hotkey: Option<String>,
    start_minimized: Option<bool>,
    start_with_windows: Option<bool>,
    update_auto_check: Option<bool>,
    windows_hello: Option<bool>,
    hello_policy: Option<hello::HelloPolicy>,
    extra_extension_ids: Option<Vec<String>>,
    passkey_provider: Option<bool>,
    show_site_icons: Option<bool>,
    keep_list_when_locked: Option<bool>,
    language: Option<String>,
}

fn webdav_eq(a: &pass_agent::AgentConfig, b: &pass_agent::AgentConfig) -> bool {
    #[cfg(feature = "webdav")]
    {
        a.webdav == b.webdav
    }
    #[cfg(not(feature = "webdav"))]
    {
        let _ = (a, b);
        true
    }
}

#[tauri::command]
pub async fn set_settings(app: AppHandle, update: SettingsUpdate) -> Res<Value> {
    blocking(move || {
        let state = app_state(&app);
        let old = state.settings();
        let mut new = old.clone();
        let mut notes: Vec<String> = Vec::new();

        if let Some(minutes) = update.auto_lock_minutes {
            new.auto_lock_minutes = minutes.clamp(1, 24 * 60);
            new.auto_lock = crate::auto_lock::AutoLock::Idle;
        }
        if let Some(mode) = update.auto_lock {
            new.auto_lock = mode;
        }
        if let Some(start_minimized) = update.start_minimized {
            new.start_minimized = start_minimized;
        }
        if let Some(auto) = update.update_auto_check {
            new.update_auto_check = auto;
        }
        if let Some(on) = update.show_site_icons {
            new.show_site_icons = on;
        }
        if let Some(on) = update.keep_list_when_locked {
            new.keep_list_when_locked = on;
        }
        if let Some(language) = update.language {
            let language = language.trim();
            new.language = crate::i18n::match_tag(language).map(str::to_string);
        }
        if let Some(on) = update
            .start_with_windows
            .filter(|on| *on != crate::autostart::enabled())
        {
            crate::autostart::set(on)?;
        }
        if let Some(ids) = update.extra_extension_ids {
            new.extra_extension_ids = ids
                .into_iter()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }

        // Settings → Keyboard shortcuts changes the auto-type hotkey at once (shortcuts.rs); older
        // windows send it with the other settings.
        if let Some(hotkey) = update.hotkey.map(|h| h.trim().to_string()) {
            if hotkey != old.hotkey {
                let choice = if hotkey.is_empty() {
                    crate::shortcuts::Choice::Off
                } else {
                    crate::shortcuts::Choice::Keys(hotkey.clone())
                };
                crate::shortcuts::apply(&app, crate::shortcuts::Action::AutoType, choice)?;
                new.hotkey = hotkey;
            }
        }

        let old_vault = old.active().cloned();
        let vault_id = || {
            old_vault
                .as_ref()
                .map(|v| v.id.clone())
                .ok_or_else(|| tr!("errors.no_vault_open"))
        };
        fn vault_mut<'a>(s: &'a mut Settings, id: &str) -> Res<&'a mut settings::VaultEntry> {
            s.vault_mut(id)
                .ok_or_else(|| tr!("errors.vault_not_listed"))
        }

        if let Some(name) = update.vault_name {
            new.rename_vault(&vault_id()?, &name)?;
        }

        if let Some(url) = update.webdav_url {
            let id = vault_id()?;
            let previous = old_vault.as_ref().and_then(|v| v.webdav.clone());
            let url = url.trim().to_string();
            if url.is_empty() {
                if let Some(w) = &previous {
                    settings::delete_webdav_password(&id, w, true);
                }
                vault_mut(&mut new, &id)?.webdav = None;
            } else {
                if !url.starts_with("https://") && !url.starts_with("http://") {
                    return Err(tr!("errors.webdav_https"));
                }
                // Plain http:// only on this device or a private network (the core's one rule,
                // as on Android and for Passyble Server addresses).
                #[cfg(feature = "webdav")]
                pass_core::check_plain_http(&url).map_err(pass_err)?;
                if old_vault.as_ref().is_some_and(|v| v.google_drive.is_some()) {
                    return Err(tr!("errors.google_and_webdav"));
                }
                let mut webdav = WebDavSettings {
                    url,
                    username: update
                        .webdav_username
                        .unwrap_or_default()
                        .trim()
                        .to_string(),
                    ..Default::default()
                };
                if let Some(p) = previous.as_ref().filter(|p| p.origin() == webdav.origin()) {
                    webdav.pins = p.pins.clone();
                    webdav.server_device = p.server_device.clone();
                }
                let password = update
                    .webdav_password
                    .filter(|p| !p.is_empty())
                    .or_else(|| {
                        previous
                            .as_ref()
                            .and_then(|w| settings::webdav_password(&id, w))
                    });
                if let Some(password) = password {
                    settings::set_webdav_password(&id, &webdav, &password)?;
                }
                if let Some(previous) = previous.as_ref().filter(|w| **w != webdav) {
                    settings::delete_webdav_password(&id, previous, true);
                }
                vault_mut(&mut new, &id)?.webdav = Some(webdav);
            }
        }

        if let Some(path) = update.vault_path {
            let id = vault_id()?;
            let old_path = old_vault
                .as_ref()
                .map(|v| v.path.clone())
                .unwrap_or_default();
            let path = normalize_vault_path(&path)?;
            if !settings::same_path(&path, &old_path) {
                if let Some(other) = new.find_by_path(&path).filter(|v| v.id != id) {
                    return Err(tr!("errors.file_already_listed", vault = other.name));
                }
                if !path.exists() && old_path.exists() {
                    if let Some(agent) = state.agent() {
                        agent.save().map_err(pass_err)?;
                    }
                    if let Some(dir) = path.parent() {
                        std::fs::create_dir_all(dir).map_err(crate::errors::file_not_saved)?;
                    }
                    std::fs::copy(&old_path, &path).map_err(crate::errors::file_not_saved)?;
                    notes.push(tr!(
                        "settings.note_copied",
                        path = path.display(),
                        old = old_path.display()
                    ));
                }
                vault_mut(&mut new, &id)?.path = path;
            }
        }

        if let Some(enabled) = update.windows_hello {
            let id = vault_id()?;
            if enabled
                && !state
                    .hello_available
                    .load(std::sync::atomic::Ordering::Relaxed)
            {
                return Err(tr!("errors.hello_not_set_up_short"));
            }
            vault_mut(&mut new, &id)?.windows_hello = enabled;
            let was_enabled = old_vault.as_ref().is_some_and(|v| v.windows_hello);
            if !enabled {
                hello::remove(&id);
            } else if was_enabled && hello::enrolled(&id) {
                // Unchanged: nothing to set up (and no Windows Hello prompt on every save).
            } else if let Some(agent) = state.agent().filter(|a| !a.is_locked()) {
                let _hello = state.ui.hello_lock();
                if let Some(note) = hello::enroll(&agent, &id, state.ui.main_owner())? {
                    notes.push(note);
                }
            } else {
                notes.push(tr!("settings.note_hello_next_unlock"));
            }
        }

        if let Some(policy) = update.hello_policy {
            let id = vault_id()?;
            vault_mut(&mut new, &id)?.hello_policy = policy.normalized();
        }

        if let Some(enabled) = update
            .passkey_provider
            .filter(|e| *e != old.passkey_provider)
        {
            if enabled {
                notes.push(match crate::passkey_provider::enable(&app)? {
                    crate::passkey_provider::Enabled::Active => tr!("settings.note_pp_active"),
                    crate::passkey_provider::Enabled::RestartNeeded => {
                        tr!("settings.note_pp_restart")
                    }
                });
            } else if let Err(e) = crate::passkey_provider::disable() {
                notes.push(crate::errors::logged(
                    tr!("settings.note_pp_unregister_failed"),
                    "passkey provider",
                    e,
                ));
            }
            new.passkey_provider = enabled;
        }

        state.replace_settings(&new)?;
        if new.language != old.language {
            let before = crate::i18n::locale();
            if crate::i18n::apply_preference(new.language.as_deref()) != before {
                tray::relabel(&app);
                crate::app_menu::relabel(&app);
                crate::popups::set_titles(&app);
            }
            pass_core::set_language(Some(crate::i18n::locale().to_string()));
            // Every window reloads with the new catalog (ui/i18n.js), also for the same language
            // (the Settings choice shown changed).
            let _ = app.emit("locale-changed", crate::i18n::locale());
            crate::twofactor::server_language(&app, crate::i18n::locale(), true);
        }
        if new.extra_extension_ids != old.extra_extension_ids {
            native_messaging::register(&new.extra_extension_ids);
        }
        if new.show_site_icons != old.show_site_icons {
            crate::site_icons::setting_changed(&app, &state, new.show_site_icons);
        }
        if let Some(agent) = state.agent() {
            agent.set_keep_list(new.keep_list_when_locked);
        }
        if !new.keep_list_when_locked {
            settings::remove_kept_lists();
        }

        // Vault path, WebDAV account and auto-lock time apply live. A new vault file or WebDAV
        // account locks the vault (it was saved to the old place first).
        let webdav_changed = state
            .agent()
            .is_some_and(|agent| !webdav_eq(&agent.config(), &state.agent_config()));
        let locked = state.reconfigure_agent();
        if webdav_changed {
            *guard(&state.sync) = SyncStatus::default();
        }
        if locked {
            notes.push(tr!("settings.note_locked"));
        }
        Ok(json!({ "restart_required": false, "locked": locked, "notes": notes }))
    })
    .await
}

/// Restarts the app (relaunching with the main window shown).
#[tauri::command]
pub fn restart_app(app: AppHandle) {
    let marker = crate::show_on_start_marker();
    if let Some(dir) = marker.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(marker, b"");
    tray::lock_completely(&app);
    // Goes through the normal exit path (which releases the single-instance lock) and relaunches;
    // the new process retries binding the IPC pipe until this one is gone.
    app.request_restart();
}

/// Sync now (the pill, Settings → Sync). A failure is `{ message, signed_out }`: `signed_out` is
/// the sync status' flag (Passyble Server no longer accepts this device's token), so the windows
/// don't need to recognise the message, which is in the user's language.
#[tauri::command]
pub async fn sync_now(app: AppHandle) -> Result<Value, Value> {
    let handle = app.clone();
    sync_now_inner(app).await.map_err(|message| {
        let signed_out = guard(&app_state(&handle).sync).signed_out;
        json!({ "message": message, "signed_out": signed_out })
    })
}

async fn sync_now_inner(app: AppHandle) -> Res<Value> {
    blocking(move || {
        let state = app_state(&app);
        let settings = state.settings();
        if settings
            .active()
            .is_none_or(|v| v.webdav.is_none() && v.google_drive.is_none())
        {
            return Err(tr!("errors.sync_not_set_up"));
        }
        if crate::gdrive::sign_in_needed(&settings) {
            return Err(crate::gdrive::sign_in_again());
        }
        background::sync_now(&app)?.ok_or_else(|| tr!("errors.unlock_to_sync"))
    })
    .await
}

/// The vault screen's Sync button: every open vault with sync set up (`background::sync_all`).
/// `{ synced, failed: [{ vault, reason }], no_sync, changes }`; `changes`: the home vault's `{ added,
/// updated, deleted, ... }` when it synced.
#[tauri::command]
pub async fn sync_all(app: AppHandle) -> Res<Value> {
    blocking(move || {
        let state = app_state(&app);
        if state.require_agent()?.is_locked() {
            return Err(tr!("errors.unlock_to_sync"));
        }
        let (report, changes) = background::sync_all(&app);
        let mut out = serde_json::to_value(&report).map_err(|e| crate::errors::internal("sync report", e))?;
        out["changes"] = changes.unwrap_or(Value::Null);
        Ok(out)
    })
    .await
}

#[tauri::command]
pub fn pending_prompts(state: AppState_<'_>) -> Vec<Value> {
    state.prompts.list()
}

#[tauri::command]
pub fn answer_prompt(app: AppHandle, request_id: u64, answer: Value) -> bool {
    app_state(&app).prompts.answer(&app, request_id, answer)
}

#[tauri::command]
pub fn totp_popup_state(state: AppState_<'_>) -> Option<Value> {
    guard(&state.totp_popup).as_ref().map(|p| {
        json!({
            "item_id": p.item_id,
            "title": p.title,
            "can_type": p.target.is_some() && cfg!(windows),
        })
    })
}

#[tauri::command]
pub fn totp_popup_copy(state: AppState_<'_>) -> Res<()> {
    let id = guard(&state.totp_popup)
        .as_ref()
        .map(|p| p.item_id.clone())
        .ok_or_else(|| tr!("errors.no_code_to_copy"))?;
    let code = totp_for(&state, &id)?;
    clipboard::copy_secret(code["code"].as_str().unwrap_or_default())?;
    record_use(&state, &id);
    Ok(())
}

#[tauri::command]
pub fn totp_popup_type(app: AppHandle) -> Res<()> {
    let state = app_state(&app);
    let popup = guard(&state.totp_popup)
        .take()
        .ok_or_else(|| tr!("errors.no_code_to_type"))?;
    let target = popup.target.ok_or_else(|| tr!("errors.no_window"))?;
    let code = totp_for(&state, &popup.item_id)?["code"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    popups::hide(&app, "totp");
    thread::spawn(move || {
        if autotype::type_into(&app, &target, &code) {
            record_use(&app_state(&app), &popup.item_id);
        }
    });
    Ok(())
}

#[tauri::command]
pub fn quickpick_state(state: AppState_<'_>) -> Res<Value> {
    let pick = guard(&state.quickpick)
        .clone()
        .ok_or_else(|| tr!("errors.nothing_to_type_into"))?;
    let vault = state.quiet_vault()?;
    let matches: Vec<ItemSummary> = pick
        .item_ids
        .iter()
        .filter_map(|id| vault.get(id.clone()))
        .map(|i| ItemSummary::of(&vault, &i))
        .collect();
    // `pin`: the entry that pins a login to this app (`windows:<exe>`, `macos:<bundle id>`);
    // `app`: its name for the window's words (on macOS `exe` is the bundle ID).
    let pin = (!pick.target.exe.trim().is_empty()).then(|| autotype::pin_entry(&pick.target.exe));
    Ok(json!({
        "window_title": pick.target.title,
        "exe": pick.target.exe,
        "app": autotype::app_label(&pick.target),
        "pin": pin,
        "matches": matches,
    }))
}

#[tauri::command]
pub fn quickpick_choose(app: AppHandle, id: String) -> Res<()> {
    let state = app_state(&app);
    let pick = guard(&state.quickpick)
        .take()
        .ok_or_else(|| tr!("errors.nothing_to_type_into"))?;
    let item = state
        .vault()?
        .get(id)
        .ok_or_else(|| tr!("errors.item_not_found"))?;
    popups::hide(&app, "quickpick");
    thread::spawn(move || autotype::type_login(&app, &pick.target, &item));
    Ok(())
}

/// "Generate new password": saves a new login for the quick-pick's window, copies the password
/// and types it there (`autotype::type_generated`). The password never reaches the webview.
#[tauri::command]
pub fn quickpick_generate(app: AppHandle) -> Res<()> {
    let state = app_state(&app);
    state.vault()?;
    let pick = guard(&state.quickpick)
        .take()
        .ok_or_else(|| tr!("errors.nothing_to_type_into"))?;
    popups::hide(&app, "quickpick");
    thread::spawn(move || autotype::type_generated(&app, &pick.target));
    Ok(())
}

#[tauri::command]
pub fn hide_window(app: AppHandle, window: WebviewWindow) {
    let state = app_state(&app);
    match window.label() {
        "prompt" => state.prompts.cancel_all(&app),
        "quickpick" => *guard(&state.quickpick) = None,
        "totp" => *guard(&state.totp_popup) = None,
        "qrscan" => crate::screen_qr::clear(),
        _ => {}
    }
    popups::hide(&app, window.label());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_footer_link_is_the_https_sensyble_site() {
        assert_eq!(SENSYBLE_URL, "https://www.sensyble.net");
    }

    fn secret_login() -> Item {
        Item {
            id: "id-1".into(),
            kind: ItemKind::Login,
            title: "GitHub".into(),
            username: "octo".into(),
            password: "hunter2-secret".into(),
            urls: vec!["".into(), "https://github.com/login".into()],
            totp: Some("JBSWY3DPEHPK3PXP".into()),
            notes: "recovery codes: 1234-5678".into(),
            favorite: true,
            ..Default::default()
        }
    }

    #[test]
    fn a_locked_item_carries_no_secrets() {
        let item = secret_login();
        let dto = ItemDto::locked(&pass_core::ItemSummary::of(&item));
        let json = serde_json::to_value(&dto).unwrap();
        assert_eq!(json["locked"], true);
        assert_eq!(json["password"], "");
        assert_eq!(json["totp"], Value::Null);
        assert_eq!(json["notes"], "");
        assert_eq!(json["has_password"], true);
        assert_eq!(json["has_totp"], true);
        assert_eq!(json["has_notes"], true);
        assert_eq!(json["title"], "GitHub");
        assert_eq!(json["username"], "octo");
        assert_eq!(json["favorite"], true);
        let text = json.to_string();
        for secret in ["hunter2", "JBSWY3DP", "recovery"] {
            assert!(!text.contains(secret), "{secret} leaked: {text}");
        }
    }

    #[test]
    fn an_unlocked_item_says_what_it_has() {
        let json = serde_json::to_value(ItemDto::from(secret_login())).unwrap();
        assert_eq!(json["locked"], false);
        assert_eq!(json["password"], "hunter2-secret");
        assert_eq!(json["has_password"], true);
        assert_eq!(json["has_totp"], true);
        assert_eq!(json["has_notes"], true);
        let empty = serde_json::to_value(ItemDto::from(Item::default())).unwrap();
        assert_eq!(empty["has_password"], false);
        assert_eq!(empty["has_totp"], false);
        assert_eq!(empty["has_notes"], false);
    }

    #[test]
    fn locked_passkeys_keep_their_metadata() {
        let mut item = secret_login();
        item.passkeys.push(pass_core::Passkey {
            credential_id: vec![1, 2, 3],
            rp_id: "github.com".into(),
            user_name: "octo".into(),
            ..Default::default()
        });
        let dto = ItemDto::locked(&pass_core::ItemSummary::of(&item));
        let json = serde_json::to_value(&dto).unwrap();
        assert_eq!(json["passkeys"][0]["rp_id"], "github.com");
        assert_eq!(json["passkeys"][0]["user_name"], "octo");
        assert_eq!(
            json["passkeys"][0]["credential_id"],
            b64url_encode(vec![1, 2, 3])
        );
    }

    #[test]
    fn list_rows_match_whether_locked_or_not() {
        let item = secret_login();
        let open = serde_json::to_value(ItemSummary::from(&item)).unwrap();
        let locked =
            serde_json::to_value(ItemSummary::from(&pass_core::ItemSummary::of(&item))).unwrap();
        assert_eq!(open["locked"], false);
        assert_eq!(locked["locked"], true);
        for key in [
            "id",
            "kind",
            "title",
            "username",
            "url",
            "favorite",
            "has_password",
            "has_totp",
            "has_passkey",
            "site",
            "use_count",
            "last_used",
            "rank",
        ] {
            assert_eq!(open[key], locked[key], "{key}");
        }
        assert_eq!(locked["url"], "https://github.com/login");
    }

    #[test]
    fn list_rows_carry_usage() {
        let row = ItemSummary::from(&secret_login()).with_usage(pass_core::ItemUsage {
            count: 3,
            last_used: 1_700_000_000_000,
            rank: 42,
        });
        let json = serde_json::to_value(row).unwrap();
        assert_eq!(json["use_count"], 3);
        assert_eq!(json["last_used"], 1_700_000_000_000i64);
        assert_eq!(json["rank"], 42);
    }

    fn card_item() -> Item {
        Item {
            id: "card-1".into(),
            kind: ItemKind::Card,
            title: "Visa •••• 1111".into(),
            card: Some(CardData {
                cardholder_name: "Ada Lovelace".into(),
                number: "4111111111111111".into(),
                expiry_month: 3,
                expiry_year: 2031,
                security_code: "7373".into(),
                pin: "9876".into(),
                brand: "visa".into(),
            }),
            fields: vec![
                CustomField {
                    name: "Customer no.".into(),
                    value: "C-1001".into(),
                    kind: FieldKind::Text,
                },
                CustomField {
                    name: "Online banking PIN".into(),
                    value: "hidden-field-secret".into(),
                    kind: FieldKind::Hidden,
                },
            ],
            tags: vec!["Finance/Cards".into()],
            ..Default::default()
        }
    }

    #[test]
    fn the_detail_copy_of_a_card_holds_no_number_codes_or_hidden_fields() {
        let json = serde_json::to_value(ItemDto::from(card_item())).unwrap();
        assert_eq!(json["partial"], true);
        assert_eq!(json["card"]["last4"], "1111");
        assert_eq!(json["card"]["brand_name"], "Visa");
        assert_eq!(json["card"]["has_number"], true);
        assert_eq!(json["card"]["has_security_code"], true);
        assert_eq!(json["card"]["has_pin"], true);
        assert_eq!(json["card"]["expiry_month"], 3);
        assert_eq!(json["fields"][0]["value"], "C-1001");
        assert_eq!(json["fields"][1]["value"], "");
        assert_eq!(json["fields"][1]["has_value"], true);
        assert_eq!(json["fields"][1]["kind"], "hidden");
        assert_eq!(json["tags"][0], "Finance/Cards");
        let text = json.to_string();
        for secret in ["4111111111111111", "7373", "9876", "hidden-field-secret"] {
            assert!(!text.contains(secret), "{secret} leaked: {text}");
        }
        let edit = serde_json::to_value(ItemDto::for_edit(card_item())).unwrap();
        assert_eq!(edit["partial"], false);
        assert_eq!(edit["card"]["number"], "4111111111111111");
        assert_eq!(edit["card"]["security_code"], "7373");
        assert_eq!(edit["fields"][1]["value"], "hidden-field-secret");
        let back: ItemDto = serde_json::from_value(json).unwrap();
        assert!(back.partial);
    }

    #[test]
    fn secrets_on_demand() {
        let item = card_item();
        let get = |f: &str| secret_of(&item, f).unwrap();
        assert_eq!(get("card_number").as_deref(), Some("4111111111111111"));
        assert_eq!(get("card_code").as_deref(), Some("7373"));
        assert_eq!(get("card_pin").as_deref(), Some("9876"));
        assert_eq!(get("card_expiry").as_deref(), Some("03/31"));
        assert_eq!(get("field.1").as_deref(), Some("hidden-field-secret"));
        assert!(secret_of(&item, "field.9").is_err());
        assert_eq!(get("password"), None);
        let identity = Item {
            kind: ItemKind::Identity,
            identity: Some(IdentityData {
                first_name: "Ada".into(),
                last_name: "Lovelace".into(),
                email: "ada@example.com".into(),
                address1: "12 Example Street".into(),
                postal_code: "NW1".into(),
                city: "London".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let get = |f: &str| secret_of(&identity, f).unwrap().unwrap();
        assert_eq!(get("identity.full_name"), "Ada Lovelace");
        assert_eq!(get("identity.email"), "ada@example.com");
        assert_eq!(get("identity.phone"), "");
        assert_eq!(get("identity.address"), "12 Example Street\nNW1 London");
        assert_eq!(expiry_text(0, 0), "");
        assert_eq!(expiry_text(12, 2031), "12/31");
    }

    #[test]
    fn only_web_addresses_open() {
        assert_eq!(
            web_address(" https://github.com/login ").as_deref(),
            Some("https://github.com/login")
        );
        assert_eq!(
            web_address("github.com").as_deref(),
            Some("https://github.com")
        );
        assert_eq!(
            web_address("HTTP://intranet/x").as_deref(),
            Some("HTTP://intranet/x")
        );
        for bad in [
            "",
            "windows:putty.exe",
            "android://com.example",
            "file:///C:/Windows/System32/calc.exe",
            "C:\\Windows\\calc.exe",
            "javascript:alert(1)",
            "https://a.com/\"&calc",
            "https://",
            "http:// space.com",
            "localhost",
        ] {
            assert_eq!(web_address(bad), None, "{bad}");
        }
    }

    #[test]
    fn list_rows_show_cards_and_identities_without_secrets() {
        let row = serde_json::to_value(ItemSummary::from(&card_item())).unwrap();
        assert_eq!(row["card"]["last4"], "1111");
        assert_eq!(row["card"]["brand_name"], "Visa");
        assert_eq!(row["has_fields"], true);
        assert_eq!(row["tags"][0], "Finance/Cards");
        assert!(!row.to_string().contains("4111111111111111"));
        let locked = ItemDto::locked(&pass_core::ItemSummary::of(&card_item()));
        let locked = serde_json::to_value(locked).unwrap();
        assert_eq!(locked["card"]["last4"], "1111");
        assert_eq!(locked["card"]["number"], "");
        assert_eq!(locked["has_fields"], true);
        assert!(locked["fields"].as_array().unwrap().is_empty());
        let info = card_info("4111 1111 1111 1111".into());
        assert_eq!(info["brand"], "visa");
        assert_eq!(info["valid"], true);
        assert_eq!(card_info("4111 1111 1111 1112".into())["valid"], false);
    }

    #[test]
    fn the_ai_tools_mark_is_a_switch_not_a_field() {
        let mut item = card_item();
        assert!(item.fields.iter().all(|f| !pass_core::is_ai_access_field(f)));
        let plain = serde_json::to_value(ItemDto::for_edit(item.clone())).unwrap();
        assert_eq!(plain["ai_access"], Value::Null);
        let fields = item.fields.len();
        item.set_ai_access(Some(pass_core::AiAccess::Allow));
        let dto = serde_json::to_value(ItemDto::for_edit(item.clone())).unwrap();
        assert_eq!(dto["ai_access"], "allow");
        assert_eq!(dto["fields"].as_array().unwrap().len(), fields);
        assert!(!dto.to_string().contains(pass_core::AI_ACCESS_FIELD));
        item.fields.retain(pass_core::is_ai_access_field);
        let dto = serde_json::to_value(ItemDto::for_edit(item)).unwrap();
        assert_eq!(dto["has_fields"], false);
        let back: ItemDto = serde_json::from_value(dto).unwrap();
        assert_eq!(back.ai_access.as_deref(), Some("allow"));
    }

    #[test]
    fn match_rules_go_both_ways() {
        let mut item = secret_login();
        item.url_rules = vec![UrlRule {
            url: "https://github.com/login".into(),
            rule: pass_core::UrlMatch::Host,
        }];
        item.android_apps = vec![
            pass_core::AndroidApp {
                package: "com.github.android".into(),
                never_show: true,
                ..Default::default()
            },
            pass_core::AndroidApp {
                package: "com.example".into(),
                ..Default::default()
            },
        ];
        for json in [
            serde_json::to_value(ItemDto::for_edit(item.clone())).unwrap(),
            serde_json::to_value(ItemDto::locked(&pass_core::ItemSummary::of(&item))).unwrap(),
        ] {
            assert_eq!(json["url_rules"][0]["url"], "https://github.com/login");
            assert_eq!(json["url_rules"][0]["rule"], "host");
            assert_eq!(json["android_never_show"], json!(["com.github.android"]));
        }
        let back: ItemDto = serde_json::from_value(json!({
            "urls": [" https://github.com/login "],
            "url_rules": [{ "url": " https://github.com/login ", "rule": "never" }],
            "android_never_show": ["com.example"],
        }))
        .unwrap();
        apply_match_rules(&mut item, back.url_rules, &back.android_never_show);
        assert_eq!(item.url_rule("https://github.com/login"), pass_core::UrlMatch::Never);
        assert!(!item.android_apps[0].never_show);
        assert!(item.android_apps[1].never_show);
    }

    #[test]
    fn shared_hosting_suggests_the_same_host_only() {
        assert!(url_suggests_host_only("https://alice.github.io/blog".into()));
        assert!(!url_suggests_host_only("https://github.com".into()));
    }

    #[test]
    fn popular_sites_name_a_new_login_and_its_website() {
        let found = serde_json::to_value(site_suggestions("github".into(), 3)).unwrap();
        assert_eq!(found[0]["name"], "GitHub");
        assert_eq!(found[0]["domain"], "github.com");
        assert!(found.as_array().unwrap().len() <= 3);
        assert_eq!(site_name_for("https://github.com/login".into()).as_deref(), Some("GitHub"));
        assert_eq!(site_name_for("https://not-a-known-site.example".into()), None);
    }

    #[test]
    fn the_window_cannot_set_read_only_fields() {
        let dto: ItemDto = serde_json::from_value(json!({
            "id": "x",
            "title": "T",
            "locked": true,
            "has_password": true,
            "site": "evil.example",
        }))
        .unwrap();
        // `locked` does come back (save_item refuses such a copy); the flags don't.
        assert!(dto.locked);
        assert!(!dto.has_password);
        assert!(dto.site.is_none());
        assert_eq!(dto.title, "T");
    }
}
