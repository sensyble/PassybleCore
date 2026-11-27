//! Settings → AI tools: the Passyble connector for AI tools (`passyble-mcp`, installed beside `Pass.exe`), the items
//! shared with AI tools, the standing permissions ("Allow until the vault locks", with Revoke), the log of recent
//! requests, and how to add the connector to MCP clients (with the real install path).
//!
//! Also the approval prompts the agent asks for (`Ui::confirm_ai_run`, `Ui::confirm_ai_reveal`): what they show and how
//! their answers read, and which shared vaults AI tools may use at all ([`vault_allowed`]).

use std::path::{Path, PathBuf};

use pass_agent::{AiDecision, AiRevealRequest, AiRunRequest, VaultKind, VaultRef};
use serde_json::{json, Value};
use tauri::{AppHandle, State};

use crate::i18n::tr;
use crate::state::AppState;

type Res<T> = Result<T, String>;
type AppState_<'a> = State<'a, std::sync::Arc<AppState>>;

pub const CONNECTOR_EXE: &str = if cfg!(windows) {
    "passyble-mcp.exe"
} else {
    "passyble-mcp"
};

pub fn connector_path() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .map(|exe| exe.with_file_name(CONNECTOR_EXE))
}

/// The setup snippets for `path` (the connector): the Claude Code command, the Codex
/// `config.toml` block and the JSON of Claude Desktop and other MCP clients.
pub fn setup_snippets(path: &Path) -> Value {
    let path = path.to_string_lossy();
    // TOML basic strings and JSON strings escape `\` and `"` the same way.
    let escaped = path.replace('\\', "\\\\").replace('"', "\\\"");
    let claude = format!("claude mcp add --scope user passyble -- \"{path}\"");
    let codex = format!(
        "[mcp_servers.passyble]\ncommand = \"{escaped}\"\n# Leave time for the approval prompt (up to 2 minutes) and the command.\ntool_timeout_sec = 720"
    );
    let json_config = serde_json::to_string_pretty(&json!({
        "mcpServers": { "passyble": { "command": path, "args": [] } }
    }))
    .unwrap_or_default();
    json!({ "claude_code": claude, "codex": codex, "json": json_config })
}

/// Whether AI tools may use the marked items of `vault` at all, with the words why not: the home
/// vault always may; a vault opened through emergency access never; a shared vault not while the
/// organisations' policy keeps their vaults' data in the app (`export_allowed: false`, the rule
/// that hides Export: a secret given to an AI tool leaves Passyble as an export does).
pub fn vault_refusal(allowed_export: bool, vault: &VaultRef) -> Option<&'static str> {
    if vault.home {
        None
    } else if vault.kind == VaultKind::Emergency {
        Some("emergency")
    } else if !allowed_export {
        Some("policy")
    } else {
        None
    }
}

pub fn vault_allowed(app: &AppHandle, vault: &VaultRef) -> bool {
    vault.home || vault_refusal(crate::teams::export_allowed(app), vault).is_none()
}

/// The items marked "Available to AI tools" in every open vault, as the AI tools page lists them: how a use is
/// approved (always asking in a shared vault), the vault, and why AI tools can't see the item (`blocked`: `policy`,
/// `emergency`), if they can't.
pub fn shared_items(vaults: &[(VaultRef, std::sync::Arc<pass_core::Vault>)], allowed_export: bool) -> Vec<Value> {
    let several = vaults.len() > 1;
    vaults
        .iter()
        .flat_map(|(r, v)| {
            let blocked = vault_refusal(allowed_export, r);
            v.items().into_iter().filter_map(move |i| {
                let access = i.ai_access()?;
                let access = if r.home { access } else { pass_core::AiAccess::Ask };
                Some(json!({
                    "id": i.id,
                    "title": i.title,
                    "kind": i.kind.as_str(),
                    "access": access.as_str(),
                    "vault": if several { Some(r.name.clone()) } else { None },
                    "fill_only": !r.can_reveal,
                    "blocked": blocked,
                }))
            })
        })
        .collect()
}

/// Everything the AI tools page shows. The shared items and grants need the unlocked vault;
/// locked, the page says so and shows the setup and the log.
#[tauri::command]
pub fn ai_tools_state(app: AppHandle, state: AppState_<'_>) -> Res<Value> {
    let path = connector_path();
    let installed = path.as_ref().is_some_and(|p| p.is_file());
    let agent = state.agent();
    let vaults = agent
        .as_ref()
        .map(|a| a.open_vaults())
        .filter(|v| !v.is_empty());
    let shared: Vec<Value> = vaults
        .as_deref()
        .map(|v| shared_items(v, crate::teams::export_allowed(&app)))
        .unwrap_or_default();
    let grants = agent.as_ref().map(|a| a.ai_grants()).unwrap_or_default();
    let log = agent.as_ref().map(|a| a.ai_log()).unwrap_or_default();
    Ok(json!({
        "locked": vaults.is_none(),
        "installed": installed,
        "path": path.as_ref().map(|p| p.to_string_lossy().to_string()),
        // An AppImage runs from a new folder every time: no fixed path to give an MCP client yet.
        "appimage": cfg!(target_os = "linux") && std::env::var_os("APPIMAGE").is_some(),
        "setup": path.as_deref().map(setup_snippets),
        "shared": shared,
        "grants": grants,
        "log": log,
    }))
}

#[tauri::command]
pub fn ai_tools_revoke(state: AppState_<'_>, item_id: String, client_key: String) -> Res<bool> {
    Ok(state.require_agent()?.ai_revoke(&item_id, &client_key))
}

#[tauri::command]
pub fn ai_tools_clear_log(state: AppState_<'_>) -> Res<()> {
    state.require_agent()?.ai_clear_log();
    Ok(())
}

#[tauri::command]
pub fn ai_tools_copy(what: String) -> Res<()> {
    let path = connector_path().ok_or_else(|| tr!("errors.generic"))?;
    let text = if what == "path" {
        path.to_string_lossy().to_string()
    } else {
        setup_snippets(&path)
            .get(&what)
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| tr!("errors.generic"))?
    };
    arboard::Clipboard::new()
        .and_then(|mut c| c.set_text(text))
        .map_err(|e| crate::errors::logged(tr!("errors.copy_failed"), "clipboard", e))
}

/// The "ai-run" prompt's data: the client, each secret (item, field, variable, whether it asks),
/// the exact command line and working directory.
pub fn run_prompt_data(request: &AiRunRequest) -> Value {
    json!({
        "client": request.client.label(),
        "client_version": request.client.version,
        "secrets": request.secrets,
        "command_line": request.command_line(),
        "command": request.command,
        "cwd": request.cwd,
        "timeout_secs": request.timeout_secs,
    })
}

pub fn reveal_prompt_data(request: &AiRevealRequest) -> Value {
    json!({
        "client": request.client.label(),
        "item_title": request.item_title,
        "field": request.field,
        "reason": request.reason,
        "vault": request.vault,
    })
}

/// The "ai-run" prompt's answer (`{ decision: "once" | "until_lock" | "deny" }`); closed, timed
/// out or anything else is a denial.
pub fn run_decision(answer: Option<&Value>) -> AiDecision {
    match answer
        .and_then(|a| a.get("decision"))
        .and_then(Value::as_str)
    {
        Some("once") => AiDecision::Once,
        Some("until_lock") => AiDecision::UntilLock,
        _ => AiDecision::Deny,
    }
}

pub fn reveal_approved(answer: Option<&Value>) -> bool {
    answer
        .and_then(|a| a.get("reveal"))
        .and_then(Value::as_bool)
        == Some(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pass_agent::{AiClient, AiSecretUse};

    #[test]
    fn snippets_quote_the_path() {
        let s = setup_snippets(Path::new(
            r"C:\Users\Ann Lee\AppData\Local\Passyble\passyble-mcp.exe",
        ));
        assert_eq!(
            s["claude_code"],
            r#"claude mcp add --scope user passyble -- "C:\Users\Ann Lee\AppData\Local\Passyble\passyble-mcp.exe""#
        );
        let codex = s["codex"].as_str().unwrap();
        assert!(codex.starts_with("[mcp_servers.passyble]\ncommand = \"C:\\\\Users\\\\Ann Lee\\\\"));
        assert!(codex.contains("tool_timeout_sec = 720"));
        let json: Value = serde_json::from_str(s["json"].as_str().unwrap()).unwrap();
        assert_eq!(
            json["mcpServers"]["passyble"]["command"],
            r"C:\Users\Ann Lee\AppData\Local\Passyble\passyble-mcp.exe"
        );
    }

    #[test]
    fn answers_default_to_no() {
        assert_eq!(run_decision(None), AiDecision::Deny);
        assert_eq!(
            run_decision(Some(&json!({ "decision": "once" }))),
            AiDecision::Once
        );
        assert_eq!(
            run_decision(Some(&json!({ "decision": "until_lock" }))),
            AiDecision::UntilLock
        );
        assert_eq!(
            run_decision(Some(&json!({ "decision": "always" }))),
            AiDecision::Deny
        );
        assert!(!reveal_approved(None));
        assert!(!reveal_approved(Some(&json!({ "reveal": "yes" }))));
        assert!(reveal_approved(Some(&json!({ "reveal": true }))));
    }

    #[test]
    fn the_run_prompt_shows_the_exact_command() {
        let request = AiRunRequest {
            client: AiClient {
                name: "claude-code".into(),
                process: "claude.exe".into(),
                ..Default::default()
            },
            secrets: vec![AiSecretUse {
                item_id: "1".into(),
                item_title: "GitHub".into(),
                field: "password".into(),
                env: "GH_TOKEN".into(),
                asks: true,
                vault: Some("Team".into()),
            }],
            command: "gh".into(),
            program: r"C:\Program Files\GitHub CLI\gh.exe".into(),
            args: vec!["api".into(), "user".into()],
            cwd: r"C:\work".into(),
            timeout_secs: 60,
        };
        let data = run_prompt_data(&request);
        assert_eq!(data["client"], "Claude Code (claude.exe)");
        assert_eq!(
            data["command_line"],
            r#""C:\Program Files\GitHub CLI\gh.exe" api user"#
        );
        assert_eq!(data["cwd"], r"C:\work");
        assert_eq!(data["secrets"][0]["env"], "GH_TOKEN");
        assert_eq!(data["secrets"][0]["asks"], true);
        assert_eq!(data["secrets"][0]["vault"], "Team");
    }

    fn vault_ref(home: bool, kind: VaultKind, can_reveal: bool) -> VaultRef {
        VaultRef {
            id: format!("{kind:?}"),
            name: format!("{kind:?}"),
            home,
            kind,
            role: None,
            can_edit: home,
            can_reveal,
        }
    }

    /// The home vault always; emergency access never; shared vaults unless the policy keeps their
    /// data in the app.
    #[test]
    fn which_vaults_ai_tools_may_use() {
        let home = vault_ref(true, VaultKind::Personal, true);
        let org = vault_ref(false, VaultKind::Org, true);
        let direct = vault_ref(false, VaultKind::Direct, false);
        let emergency = vault_ref(false, VaultKind::Emergency, true);
        assert_eq!(vault_refusal(true, &home), None);
        assert_eq!(vault_refusal(false, &home), None);
        assert_eq!(vault_refusal(true, &org), None);
        assert_eq!(vault_refusal(true, &direct), None);
        assert_eq!(vault_refusal(false, &org), Some("policy"));
        assert_eq!(vault_refusal(false, &direct), Some("policy"));
        assert_eq!(vault_refusal(true, &emergency), Some("emergency"));
    }

    #[test]
    fn the_page_lists_shared_vaults_items_as_asking() {
        let mark = |vault: &pass_core::Vault, title: &str, access| {
            let mut item = pass_core::Item {
                title: title.into(),
                password: "pw".into(),
                ..Default::default()
            };
            item.set_ai_access(Some(access));
            vault.upsert(item).unwrap();
        };
        let open = |name: &str| {
            let kdf = pass_core::KdfParams {
                m_kib: 64,
                t: 1,
                p: 1,
                ..Default::default()
            };
            pass_core::Vault::create_with_kdf("pw", name, kdf).unwrap()
        };
        let home = open("home");
        let team = open("team");
        mark(&home, "Mine", pass_core::AiAccess::Allow);
        mark(&team, "Theirs", pass_core::AiAccess::Allow);
        let vaults = vec![
            (vault_ref(true, VaultKind::Personal, true), home),
            (vault_ref(false, VaultKind::Org, false), team),
        ];
        let list = shared_items(&vaults, true);
        assert_eq!(list.len(), 2);
        assert_eq!(list[0]["access"], "allow");
        assert_eq!(list[0]["blocked"], Value::Null);
        assert_eq!(list[1]["access"], "ask");
        assert_eq!(list[1]["vault"], "Org");
        assert_eq!(list[1]["fill_only"], true);
        assert_eq!(shared_items(&vaults, false)[1]["blocked"], "policy");
    }
}
