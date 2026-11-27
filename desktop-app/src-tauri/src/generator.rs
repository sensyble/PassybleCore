//! Username and e-mail generator (`ui/views/generator.js`, `ui/views/settings.js`), on pass-core.
//!
//! * Usernames, plus addresses and catch-all addresses are made locally.
//! * E-mail aliases come from the user's own account at an alias service (SimpleLogin, addy.io, Firefox Relay,
//!   DuckDuckGo, Fastmail, Forward Email), only when the user asks for one or tests a token, off the UI thread. The
//!   website goes along only when the window passes it (the user ticked "Mention the website").
//! * The services' API tokens and the user's own address and domain are kept encrypted in the vault, never in
//!   `settings.json`. The window never gets a token back: only whether one is saved.

use pass_core::{
    alias_check, generate_email as core_generate_email,
    generate_username as core_generate_username, AliasConfig, AliasService, EmailGeneratorSettings,
    EmailKind, EmailOptions, UsernameKind, UsernameOptions,
};
use serde::Deserialize;
use serde_json::{json, Value};
use tauri::State;
use zeroize::Zeroizing;

use crate::commands::{blocking, pass_err};
use crate::i18n::tr;
use crate::state::AppState;

type Res<T> = Result<T, String>;
type AppState_<'a> = State<'a, std::sync::Arc<AppState>>;

#[derive(Deserialize, Default)]
#[serde(default)]
pub struct UsernameDto {
    /// `words` (default), `word_number`, `characters`.
    kind: Option<String>,
    capitalize: Option<bool>,
    include_number: Option<bool>,
    separator: Option<String>,
    length: Option<u32>,
}

fn username_options(o: UsernameDto) -> Res<UsernameOptions> {
    let d = UsernameOptions::default();
    let kind = match o.kind.as_deref().unwrap_or("words") {
        "words" => UsernameKind::Words,
        "word_number" => UsernameKind::WordNumber,
        "characters" => UsernameKind::Characters,
        _ => return Err(tr!("errors.generator_kind")),
    };
    Ok(UsernameOptions {
        kind,
        capitalize: o.capitalize.unwrap_or(d.capitalize),
        include_number: o.include_number.unwrap_or(d.include_number),
        separator: o.separator.unwrap_or(d.separator),
        length: o.length.unwrap_or(d.length).clamp(4, 64),
    })
}

#[tauri::command]
pub fn generate_username(options: Option<UsernameDto>) -> Res<String> {
    core_generate_username(username_options(options.unwrap_or_default())?).map_err(pass_err)
}

/// A plus address (`kind: "plus"`) or catch-all address (`"catch_all"`) from the addresses in
/// the vault's settings. `website`: name the tag after it (local only).
#[tauri::command]
pub fn generate_email(state: AppState_<'_>, kind: String, website: Option<String>) -> Res<String> {
    let saved = state.vault()?.email_generator_settings();
    let (kind, missing) = match kind.as_str() {
        "plus" => (EmailKind::PlusAddress, saved.address.is_empty()),
        "catch_all" => (EmailKind::CatchAll, saved.domain.is_empty()),
        _ => return Err(tr!("errors.generator_kind")),
    };
    if missing {
        return Err(tr!("errors.email_generator_not_set_up"));
    }
    core_generate_email(EmailOptions {
        kind,
        address: saved.address,
        domain: saved.domain,
        website: website.filter(|w| !w.trim().is_empty()),
    })
    .map_err(pass_err)
}

fn service(id: &str) -> Res<AliasService> {
    AliasService::from_id(id).ok_or_else(|| tr!("errors.alias_unknown_service"))
}

/// A new alias at the user's alias service (`None`: the default one). Network; `website` is sent
/// as the alias's note, so the window passes it only when the user asked.
#[tauri::command]
pub async fn generate_alias(
    state: AppState_<'_>,
    service_id: Option<String>,
    website: Option<String>,
) -> Res<String> {
    let vault = state.vault()?;
    let service = service_id.as_deref().map(service).transpose()?;
    let website = website.filter(|w| !w.trim().is_empty());
    blocking(move || vault.generate_alias(service, website).map_err(pass_err)).await
}

/// What the generator and Settings → Generator show: the e-mail generator's addresses and every
/// alias service (set up or not) with its non-secret settings. Never a token.
#[tauri::command]
pub fn generator_settings(state: AppState_<'_>) -> Res<Value> {
    let vault = state.vault()?;
    let email = vault.email_generator_settings();
    let default = vault.alias_default_service();
    let services: Vec<Value> = AliasService::ALL
        .into_iter()
        .map(|s| {
            let config = vault.alias_config(s);
            json!({
                "id": s.id(),
                "name": s.name(),
                "configured": config.is_some(),
                "default": Some(s) == default,
                "base_url": config.as_ref().map(|c| c.base_url.clone()).unwrap_or_default(),
                "domain": config.as_ref().map(|c| c.domain.clone()).unwrap_or_default(),
                "self_hostable": s.self_hostable(),
                "uses_domain": s.uses_domain(),
                "default_base_url": s.default_base_url(),
            })
        })
        .collect();
    Ok(json!({
        "address": email.address,
        "domain": email.domain,
        "default": default.map(|s| s.id()),
        "services": services,
    }))
}

fn save(state: &AppState) -> Res<()> {
    state.require_agent()?.save().map_err(pass_err)
}

#[tauri::command]
pub fn set_email_generator(state: AppState_<'_>, address: String, domain: String) -> Res<()> {
    state
        .vault()?
        .set_email_generator_settings(EmailGeneratorSettings { address, domain })
        .map_err(pass_err)?;
    save(&state)
}

#[derive(Deserialize)]
pub struct AliasServiceDto {
    service: String,
    /// `None` or `""`: keep the saved token (the window never has it).
    #[serde(default)]
    token: Option<String>,
    #[serde(default)]
    base_url: String,
    #[serde(default)]
    domain: String,
}

fn config_of(vault: &pass_core::Vault, dto: AliasServiceDto) -> Res<AliasConfig> {
    let service = service(&dto.service)?;
    let typed = Zeroizing::new(dto.token.unwrap_or_default());
    let token = if typed.trim().is_empty() {
        vault
            .alias_config(service)
            .map(|c| c.token)
            .unwrap_or_default()
    } else {
        typed.trim().to_string()
    };
    Ok(AliasConfig {
        service,
        token,
        base_url: dto.base_url,
        domain: dto.domain,
    })
}

#[tauri::command]
pub fn set_alias_service(state: AppState_<'_>, config: AliasServiceDto) -> Res<()> {
    let vault = state.vault()?;
    let config = config_of(&vault, config)?;
    vault.set_alias_config(config).map_err(pass_err)?;
    save(&state)
}

#[tauri::command]
pub fn remove_alias_service(state: AppState_<'_>, service_id: String) -> Res<()> {
    state
        .vault()?
        .remove_alias_config(service(&service_id)?)
        .map_err(pass_err)?;
    save(&state)
}

#[tauri::command]
pub fn set_default_alias_service(state: AppState_<'_>, service_id: String) -> Res<()> {
    state
        .vault()?
        .set_alias_default_service(Some(service(&service_id)?))
        .map_err(pass_err)?;
    save(&state)
}

/// Settings → Generator → Test: checks the token as typed (or the saved one) without saving it.
/// `{ "address": null }`, or for DuckDuckGo (no check without making one) the test alias.
#[tauri::command]
pub async fn test_alias_service(state: AppState_<'_>, config: AliasServiceDto) -> Res<Value> {
    let vault = state.vault()?;
    let config = config_of(&vault, config)?;
    let address = blocking(move || alias_check(config).map_err(pass_err)).await?;
    Ok(json!({ "address": address }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn username_options_map_and_clamp() {
        let o = username_options(UsernameDto {
            kind: Some("characters".into()),
            length: Some(500),
            ..Default::default()
        })
        .unwrap();
        assert_eq!((o.kind, o.length), (UsernameKind::Characters, 64));
        let d = username_options(UsernameDto::default()).unwrap();
        assert_eq!(d, UsernameOptions::default());
        assert!(username_options(UsernameDto {
            kind: Some("x".into()),
            ..Default::default()
        })
        .is_err());
        assert_eq!(
            generate_username(Some(UsernameDto {
                kind: Some("characters".into()),
                length: Some(8),
                ..Default::default()
            }))
            .unwrap()
            .len(),
            8
        );
    }
}
