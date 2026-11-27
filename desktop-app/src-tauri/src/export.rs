//! Settings → This vault → Export… (`ui/views/export.js`): the open vault as a file, written here after Windows' save
//! dialog, so the export never passes through the webview.
//!
//! Formats (`pass_core::export_*`; items in the trash are left out): `encrypted` (recommended; Argon2id +
//! XChaCha20-Poly1305 with a password chosen for the export), `json` (everything, passkeys with their private keys,
//! unencrypted) and `csv` (Bitwarden's columns, unencrypted; no passkeys or password history).
//!
//! A shared vault is exported on its own, and only when the user's role may see its passwords (not a fill member) and
//! the organisations' policy allows exports (`pass_core::policy_allows_export`). The home vault always may be exported.
//!
//! An unencrypted export needs the master password typed again (`Vault::check_password`, which changes nothing), so a
//! moment at an unlocked PC isn't enough to take every password away in a readable file.

use serde_json::{json, Value};
use tauri::{AppHandle, Manager};
use tauri_plugin_dialog::DialogExt;
use zeroize::Zeroizing;

use crate::commands::{app_state, blocking, check_master_password, pass_err};
use crate::i18n::tr;

type Res<T> = Result<T, String>;

fn date_of(days: i64) -> String {
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    format!("{:04}-{m:02}-{d:02}", if m <= 2 { y + 1 } else { y })
}

pub(crate) fn today() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    date_of(secs.div_euclid(86_400))
}

fn file_of(format: &str) -> Res<(String, String, &'static [&'static str])> {
    let date = today();
    Ok(match format {
        "encrypted" => (
            format!("passyble-export-{date}-encrypted.json"),
            tr!("export.filter_encrypted"),
            &["json"],
        ),
        "json" => (
            format!("passyble-export-{date}.json"),
            tr!("export.filter_json"),
            &["json"],
        ),
        "csv" => (
            format!("passyble-export-{date}.csv"),
            "CSV".into(),
            &["csv"],
        ),
        _ => return Err(tr!("errors.choose_format")),
    })
}

fn export_refusal(app: &AppHandle, vault_ref: &pass_agent::VaultRef) -> Option<String> {
    if vault_ref.home {
        return None;
    }
    if vault_ref.kind == pass_agent::VaultKind::Emergency || !vault_ref.can_reveal {
        return Some(tr!("errors.export_role"));
    }
    if !crate::teams::export_allowed(app) {
        return Some(pass_core::policy_blocked_message(
            pass_core::PolicyBlock::Export,
        ));
    }
    None
}

/// The open vaults and whether each may be exported: `[{ id, name, home, kind, allowed,
/// reason }]` (`reason` the words when not).
#[tauri::command]
pub async fn export_choices(app: AppHandle) -> Res<Value> {
    blocking(move || {
        let agent = app_state(&app).require_agent()?;
        let list: Vec<Value> = agent
            .open_vaults()
            .into_iter()
            .map(|(r, _)| {
                let reason = export_refusal(&app, &r);
                json!({
                    "id": r.id, "name": r.name, "home": r.home, "kind": r.kind,
                    "allowed": reason.is_none(), "reason": reason,
                })
            })
            .collect();
        Ok(Value::Array(list))
    })
    .await
}

/// Exports the unlocked vault, or (`vault_id`) one open shared vault. `password`: the export's own password (`encrypted`, at least 8
/// characters); `master_password`: the vault's master password, needed for `json` and `csv`.
/// Opens the save dialog; `None` if it was cancelled. `{ path, items }` once written.
#[tauri::command]
pub async fn export_vault(
    app: AppHandle,
    format: String,
    password: Option<String>,
    master_password: Option<String>,
    vault_id: Option<String>,
) -> Res<Option<Value>> {
    blocking(move || {
        let state = app_state(&app);
        let vault = state.vault()?;
        let pick = |vault_id: &str| -> Res<std::sync::Arc<pass_core::Vault>> {
            let (vault_ref, chosen) = state
                .require_agent()?
                .open_vaults()
                .into_iter()
                .find(|(r, _)| r.id == vault_id)
                .ok_or_else(|| tr!("errors.teams_vault_not_open"))?;
            match export_refusal(&app, &vault_ref) {
                Some(reason) => Err(reason),
                None => Ok(chosen),
            }
        };
        if let Some(id) = vault_id.as_deref() {
            pick(id)?;
        }
        let (name, filter, extensions) = file_of(&format)?;
        let password = Zeroizing::new(password.unwrap_or_default());
        if format == "encrypted" {
            check_master_password(&password).map_err(|_| tr!("errors.export_password_short"))?;
        } else {
            let master = Zeroizing::new(master_password.unwrap_or_default());
            if master.is_empty() {
                return Err(tr!("export.need_master"));
            }
            if !vault.check_password(master.to_string()).map_err(pass_err)? {
                return Err(tr!("errors.wrong_master_password"));
            }
        }
        let mut dialog = app
            .dialog()
            .file()
            .set_title(tr!("export.title"))
            .set_file_name(&name)
            .add_filter(filter, extensions);
        if let Some(main) = app.get_webview_window("main") {
            dialog = dialog.set_parent(&main);
        }
        let Some(path) = dialog.blocking_save_file().and_then(|p| p.into_path().ok()) else {
            return Ok(None);
        };
        // The vault may have locked while the dialog was open.
        let home = state.vault()?;
        let vault = match vault_id.as_deref() {
            Some(id) => pick(id)?,
            None => home,
        };
        let items = vault.items().len();
        let data: Zeroizing<Vec<u8>> = Zeroizing::new(match format.as_str() {
            "encrypted" => {
                pass_core::export_encrypted_json(vault, password.to_string()).map_err(pass_err)?
            }
            "json" => pass_core::export_json(vault).into_bytes(),
            _ => pass_core::export_csv(vault).into_bytes(),
        });
        std::fs::write(&path, data.as_slice())
            .map_err(|e| crate::errors::logged(tr!("errors.export_not_saved"), "export", e))?;
        Ok(Some(json!({
            "path": path.to_string_lossy(),
            "items": items,
            "encrypted": format == "encrypted",
        })))
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates() {
        assert_eq!(date_of(0), "1970-01-01");
        assert_eq!(date_of(20_740), "2026-10-14");
        assert_eq!(date_of(11_016), "2000-02-29");
        assert_eq!(date_of(-1), "1969-12-31");
    }

    #[test]
    fn file_names() {
        let (name, _, ext) = file_of("encrypted").unwrap();
        assert!(name.starts_with("passyble-export-") && name.ends_with("-encrypted.json"));
        assert_eq!(ext, ["json"]);
        assert!(file_of("csv").unwrap().0.ends_with(".csv"));
        assert!(file_of("xml").is_err());
    }
}
