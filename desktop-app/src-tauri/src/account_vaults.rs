//! Vaults kept in the signed-in Passyble account on Passyble Cloud (cloud-mode `POST` and `DELETE /api/v1/vaults`).
//!
//! * `account_vault_create`: the account's Cloud device, then the empty home slot (`<u>/personal`) or a new vault
//!   (`<u>/v-…`, within the plan's vault limit), a local copy in `%LOCALAPPDATA%\Pass\vaults` and the first upload.
//! * `account_vault_delete`: the owner deletes it on the server for every device (never the home vault or a shared
//!   vault), then it goes from this PC too.
//! * [`check_deleted`]: another device deleted it; the sync here is refused, so it goes from the list (the file stays).

use serde_json::{json, Value};
use tauri::{AppHandle, Emitter};

use crate::commands::{app_state, blocking};
use crate::i18n::tr;
use crate::settings::{self, Settings, VaultEntry, WebDavSettings};
use crate::teams_api::{ApiError, ServerApi};

type Res<T> = Result<T, String>;

const HOME: &str = "personal";

/// `(base, "<owner>/<vault>")` of a Passyble Server vault URL `<base>/dav/<owner>/<vault>.vault`.
pub fn cloud_key(url: &str) -> Option<(String, String)> {
    let url = url.trim();
    let i = url.rfind("/dav/")?;
    let rest = url[i + "/dav/".len()..].strip_suffix(".vault")?;
    let (owner, name) = rest.split_once('/')?;
    if owner.is_empty() || name.is_empty() || name.contains('/') {
        return None;
    }
    Some((url[..i].trim_end_matches('/').to_string(), format!("{owner}/{name}")))
}

/// `<owner>/<vault>` of a vault in the signed-in account on Passyble Cloud: made here, or a
/// Passyble Server vault of the account's Cloud user on its Cloud server.
pub fn account_key(entry: &VaultEntry, settings: &Settings) -> Option<String> {
    let webdav = entry.webdav.as_ref().filter(|w| w.is_pass_server())?;
    let (base, key) = cloud_key(&webdav.url)?;
    if entry.account_vault.as_deref() == Some(key.as_str()) {
        return Some(key);
    }
    let cloud = settings.passyble_account.as_ref()?.cloud.as_ref()?;
    let same_server = base.eq_ignore_ascii_case(cloud.server_url.trim_end_matches('/'));
    let owner = key.split('/').next().unwrap_or_default();
    (same_server && owner == cloud.user).then_some(key)
}

pub fn deletable_key(entry: &VaultEntry, settings: &Settings) -> Option<String> {
    account_key(entry, settings).filter(|k| k.rsplit('/').next() != Some(HOME))
}

pub fn name_confirmed(typed: &str, name: &str) -> bool {
    let name = name.trim();
    !name.is_empty() && typed.trim().to_lowercase() == name.to_lowercase()
}

/// A new vault name on Passyble Cloud: `v-` and 12 random hex digits (the name is only an id; the
/// vault's own name stays on the devices).
fn new_server_name() -> String {
    let id = uuid::Uuid::new_v4().simple().to_string();
    format!("v-{}", &id[..12])
}

fn limit_text(e: &ApiError) -> String {
    match e {
        ApiError::Refused { code, limit, .. } if code == "vault_limit" => match limit {
            Some(n) => tr!("errors.account_vault_limit_n", limit = n),
            None => tr!("errors.account_vault_limit"),
        },
        other => other.message(),
    }
}

/// "Create a vault in your Passyble account": `name` for the list, `password` the Passyble password (`linked`, the
/// account has one) or the new vault's own master password. `{ warning, vault }`.
#[tauri::command]
pub async fn account_vault_create(
    app: AppHandle,
    name: String,
    password: String,
    linked: bool,
) -> Res<Value> {
    let password = zeroize::Zeroizing::new(password);
    blocking(move || imp::create(&app, name.trim(), &password, linked)).await
}

/// "Delete vault from your account": deletes vault `id` (listed here) on Passyble Cloud for every
/// device once `confirm_name` is its name, then takes it and its local copy off this PC.
#[tauri::command]
pub async fn account_vault_delete(app: AppHandle, id: String, confirm_name: String) -> Res<Value> {
    blocking(move || {
        let state = app_state(&app);
        let settings = state.settings();
        let entry = settings
            .vault(&id)
            .cloned()
            .ok_or_else(|| tr!("errors.vault_not_listed"))?;
        if !name_confirmed(&confirm_name, &entry.name) {
            return Err(tr!("errors.account_vault_delete_name", vault = entry.name));
        }
        let key = deletable_key(&entry, &settings)
            .ok_or_else(|| tr!("errors.account_vault_not_deletable"))?;
        let api = vault_api(&entry).ok_or_else(|| tr!("errors.account_vault_signed_out"))?;
        match api.delete_vault(&key) {
            Ok(_) => {}
            Err(e) if e.status() == 404 => {}
            Err(e) => return Err(e.message()),
        }
        forget_here(&app, &entry, true)?;
        Ok(json!({ "deleted": key }))
    })
    .await
}

fn vault_api(entry: &VaultEntry) -> Option<ServerApi<'static>> {
    let webdav = entry.webdav.as_ref().filter(|w| w.is_pass_server())?;
    let token = settings::webdav_password(&entry.id, webdav).filter(|t| !t.is_empty())?;
    let base = crate::signin::server_base(&webdav.url)?;
    Some(ServerApi::new(
        &base,
        &webdav.username,
        &token,
        &webdav.pins,
        crate::teams_api::transport(),
    ))
}

/// Takes `entry` off this PC: locked completely first when it is open, its Windows Hello data and
/// server token deleted, and with `delete_file` its local copy too.
fn forget_here(app: &AppHandle, entry: &VaultEntry, delete_file: bool) -> Res<()> {
    let state = app_state(app);
    let was_active = state.settings().active_vault.as_deref() == Some(entry.id.as_str());
    if was_active {
        crate::tray::lock_completely(app);
    }
    state.update_settings(|s| {
        s.remove_vault(&entry.id)
            .map(|_| ())
            .ok_or_else(|| tr!("errors.vault_not_listed"))
    })?;
    settings::remove_kept_list(&entry.id);
    crate::hello::remove(&entry.id);
    if let Some(webdav) = &entry.webdav {
        settings::delete_webdav_password(&entry.id, webdav, false);
    }
    if was_active {
        state.reconfigure_agent();
        crate::vaults::after_switch(&state);
    }
    if delete_file && entry.path.is_file() {
        let _ = std::fs::remove_file(&entry.path);
    }
    let _ = app.emit("vaults-changed", ());
    Ok(())
}

pub fn is_vault_gone(e: &pass_core::PassError) -> bool {
    matches!(e, pass_core::PassError::Network(m) if crate::errors::core_says(m, "server.no_vault_access"))
}

pub fn check_deleted_soon(app: &AppHandle) {
    let app = app.clone();
    std::thread::spawn(move || check_deleted(&app));
}

/// The open vault's Passyble Server refused its sync as if it had no such vault: when the server's list of the
/// account's vaults no longer has it, it was deleted on another device. It goes from the list (its file stays).
pub fn check_deleted(app: &AppHandle) {
    let state = app_state(app);
    let Some(entry) = state.settings().active().cloned() else {
        return;
    };
    let Some(path) = entry
        .webdav
        .as_ref()
        .and_then(|w| w.url.rfind("/dav/").map(|i| w.url[i..].to_string()))
    else {
        return;
    };
    let Some(api) = vault_api(&entry) else {
        return;
    };
    let Ok(whoami) = api.whoami() else {
        return;
    };
    if whoami.vaults.iter().any(|v| v.path == path) {
        return;
    }
    crate::applog::plog!("account vault: {} is no longer on its server, taken off the list", entry.id);
    if forget_here(app, &entry, false).is_ok() {
        let _ = app.emit(
            "toast",
            tr!("vaults.deleted_elsewhere", vault = entry.name),
        );
    }
}

#[cfg(feature = "webdav")]
mod imp {
    use super::*;
    use crate::commands::{after_password_unlock, check_new_master_password, pass_err, prepare_agent};

    pub fn create(app: &AppHandle, name: &str, password: &str, linked: bool) -> Res<Value> {
        if name.is_empty() {
            return Err(tr!("errors.vault_needs_name"));
        }
        if password.is_empty() {
            return Err(tr!("unlock.enter_password"));
        }
        let state = app_state(app);
        if !linked {
            check_new_master_password(&state, password, &[name.to_string()], false)?;
        }
        let backend = crate::teams_vaults::cloud_device(app)?;
        let (user, token) = backend.credentials();
        let (user, token) = (user.to_string(), token.to_string());
        let base = backend.base().to_string();
        let api = backend.api();
        let listed = |key: &str| {
            state.settings().vaults.iter().any(|v| {
                v.webdav
                    .as_ref()
                    .and_then(|w| cloud_key(&w.url))
                    .is_some_and(|(b, k)| k == key && b.eq_ignore_ascii_case(&base))
            })
        };
        let home = format!("{user}/{HOME}");
        let home_url = format!("{base}/dav/{home}.vault");
        let home_free = !listed(&home)
            && !pass_core::webdav_exists(pass_core::WebDavConfig {
                url: home_url.clone(),
                username: user.clone(),
                password: token.clone(),
                pins: Vec::new(),
            })
            .map_err(crate::errors::friendly)?;
        let (key, url) = if home_free {
            (home, home_url)
        } else {
            let made = api
                .create_personal_vault(&new_server_name())
                .map_err(|e| limit_text(&e))?;
            let key = made["vault"].as_str().unwrap_or_default().to_string();
            let path = made["path"].as_str().unwrap_or_default().to_string();
            if key.is_empty() || !path.starts_with("/dav/") {
                return Err(tr!("errors.generic"));
            }
            (key, format!("{base}{path}"))
        };
        let webdav = WebDavSettings {
            url,
            username: user,
            pins: Vec::new(),
            server_device: Some(crate::account::device_name()),
        };
        let path = settings::cache_vault_path(&key.replace('/', "-"));
        if path.exists() {
            return Err(tr!("errors.file_exists"));
        }
        let (agent, id, mut result) = if linked {
            let (agent, id) = crate::account_keys::create_linked(
                app,
                path,
                Some(name.to_string()),
                Some(password),
                Some((webdav, token)),
            )?;
            (agent, id, json!({ "warning": null }))
        } else {
            let (agent, id) = prepare_agent(app, path, Some(name.to_string()), Some((webdav, token)))?;
            agent.create_vault(password).map_err(pass_err)?;
            let result = after_password_unlock(&state, &agent, &id);
            (agent, id, result)
        };
        state.update_settings(|s| {
            if let Some(v) = s.vault_mut(&id) {
                v.account_vault = Some(key.clone());
            }
            Ok(())
        })?;
        if let Err(e) = agent.sync() {
            result["warning"] = json!(tr!(
                "warnings.not_uploaded_yet",
                error = crate::errors::friendly(e)
            ));
        }
        result["vault"] = json!(key);
        Ok(result)
    }
}

#[cfg(not(feature = "webdav"))]
mod imp {
    use super::*;

    pub fn create(_app: &AppHandle, _name: &str, _password: &str, _linked: bool) -> Res<Value> {
        Err(tr!("errors.no_sync_build"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::{AccountSettings, CloudDeviceSettings};

    fn entry(url: &str, account_vault: Option<&str>) -> VaultEntry {
        VaultEntry {
            id: "a".into(),
            name: "Work".into(),
            webdav: Some(WebDavSettings {
                url: url.into(),
                username: "u-abc".into(),
                pins: Vec::new(),
                server_device: Some("PC".into()),
            }),
            account_vault: account_vault.map(str::to_string),
            ..Default::default()
        }
    }

    fn signed_in() -> Settings {
        Settings {
            passyble_account: Some(AccountSettings {
                cloud: Some(CloudDeviceSettings {
                    server_url: "https://cloud.passyble.com/".into(),
                    user: "u-abc".into(),
                    device_id: "d1".into(),
                }),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn keys_of_cloud_urls() {
        assert_eq!(
            cloud_key("https://cloud.passyble.com/dav/u-abc/v-1234.vault"),
            Some(("https://cloud.passyble.com".into(), "u-abc/v-1234".into()))
        );
        assert_eq!(cloud_key("https://x/dav/u-abc.vault"), None);
        assert_eq!(cloud_key("https://x/dav/u-abc/a/b.vault"), None);
        assert_eq!(cloud_key("https://x/files/pass.vault"), None);
    }

    #[test]
    fn only_the_accounts_own_vaults_other_than_home_can_be_deleted() {
        let cloud = signed_in();
        let made_here = entry("https://cloud.passyble.com/dav/u-abc/v-1234.vault", Some("u-abc/v-1234"));
        assert_eq!(deletable_key(&made_here, &Settings::default()).as_deref(), Some("u-abc/v-1234"));
        let elsewhere = entry("https://cloud.passyble.com/dav/u-abc/v-9999.vault", None);
        assert_eq!(deletable_key(&elsewhere, &cloud).as_deref(), Some("u-abc/v-9999"));
        assert_eq!(deletable_key(&elsewhere, &Settings::default()), None);
        let home = entry("https://cloud.passyble.com/dav/u-abc/personal.vault", Some("u-abc/personal"));
        assert_eq!(account_key(&home, &cloud).as_deref(), Some("u-abc/personal"));
        assert_eq!(deletable_key(&home, &cloud), None);
        let other_user = entry("https://cloud.passyble.com/dav/u-zzz/v-1.vault", None);
        assert_eq!(deletable_key(&other_user, &cloud), None);
        let self_hosted = entry("https://pass.example.com/dav/u-abc/v-1.vault", None);
        assert_eq!(deletable_key(&self_hosted, &cloud), None);
        let mut plain = entry("https://cloud.passyble.com/dav/u-abc/v-1.vault", None);
        plain.webdav.as_mut().unwrap().server_device = None;
        assert_eq!(deletable_key(&plain, &cloud), None);
    }

    #[test]
    fn the_name_confirms_the_delete() {
        assert!(name_confirmed(" work ", "Work"));
        assert!(!name_confirmed("Wor", "Work"));
        assert!(!name_confirmed("", " "));
    }

    #[test]
    fn new_server_names_are_valid_vault_names() {
        let a = new_server_name();
        assert!(a.starts_with("v-") && a.len() == 14, "{a}");
        assert!(a.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'));
        assert_ne!(a, new_server_name());
    }
}
