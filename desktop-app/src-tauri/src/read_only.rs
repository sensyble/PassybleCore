//! Read-only mode for the windows (this app is below the minimum version).
//!
//! The agent refuses the browser's fills, saves and edits, the passkey provider, auto-type and sync itself. This
//! gate does the same for the windows' own commands: every command runs through [`gate`], and while read-only only
//! those in [`ALLOWED`] go through; every other one, a command added later and not listed included, answers
//! "Passyble is read-only until you update." A test checks that every registered command is in exactly one of
//! [`ALLOWED`] and [`BLOCKED`].

use tauri::ipc::Invoke;
use tauri::Wry;

use crate::i18n::tr;

pub const ALLOWED: &[&str] = &[
    "status",
    "vault_suggestions",
    "pick_vault_file",
    "pick_vault_save",
    "setup_open",
    "unlock",
    "unlock_hello",
    "cancel_unlock",
    "cancel_hello_unlock",
    "take_auto_hello",
    "lock",
    "enable_hello",
    "dismiss_hello_offer",
    "recovery_unlock",
    // Finishing an unlock with the recovery code needs a new master password: nobody is locked out.
    "recovery_set_password",
    // Its live check of the new password (changes nothing).
    "master_password_check",
    "recovery_server_reset",
    "recovery_code_save",
    // A 2FA link from outside: looked at and cancelled, never added.
    "otpauth_pending",
    "otpauth_review",
    "otpauth_cancel",
    "otpauth_handler_status",
    "otpauth_handler_claim",
    "otpauth_handler_open_settings",
    "list_items",
    "search",
    "get_item",
    "totp",
    "totp_check",
    "copy_secret",
    "copy_field",
    "password_history_entry",
    "copy_history_password",
    "item_secret",
    "card_info",
    "url_suggests_host_only",
    "site_suggestions",
    "site_name_for",
    "vault_tags",
    "open_item_url",
    "site_icons",
    "trash_list",
    "find_duplicates",
    "merge_preview",
    "merge_suggestions",
    "merge_candidates",
    "password_health",
    "password_check",
    "health_breach_check",
    "health_breach_cancel",
    "health_breach_status",
    // "Don't show this again" on the breach check notice: a UI setting on this PC.
    "health_breach_notice",
    "health_open_guide",
    // Password health's master password tip: Dismiss is a UI setting on this PC (as the Windows
    // Hello offer's "Not now"), not a vault change.
    "master_password_tip_dismiss",
    "totp_popup_state",
    "totp_popup_copy",
    "quickpick_state",
    "hide_window",
    "pending_prompts",
    "answer_prompt",
    "generate_password",
    "generate_username",
    "generate_email",
    "generator_settings",
    "test_alias_service",
    "export_vault",
    "export_choices",
    "import_cancel",
    "import_key_file_clear",
    "get_settings",
    "set_settings",
    "open_sensyble_site",
    "restart_app",
    "rename_vault",
    "remove_vault",
    "undo_remove_vault",
    "reveal_vault",
    "local_reminder_dismiss",
    "vault_pins",
    "open_log_folder",
    "passkey_provider_open",
    "i18n_state",
    "perf_painted",
    "window_snap_layouts",
    "get_started",
    "get_started_show",
    "vault_path_synced",
    "extension_setup",
    "extension_connected",
    "extension_open_browser",
    "extension_open_store",
    "extension_copy",
    "extension_show",
    "open_releases_page",
    "setup_progress",
    // Settings > AI tools: the page, its copy buttons, Revoke and Clear (no vault changes). The
    // agent itself refuses the connector's commands and reveals while read-only.
    "ai_tools_state",
    "ai_tools_copy",
    "ai_tools_revoke",
    "ai_tools_clear_log",
    // Passyble Server account security and links (no vault changes, no sync).
    "server_link_check",
    "server_qr_from_file",
    "server_qr_from_clipboard",
    "server_pair_take",
    "server_signin_link",
    "server_signin_previous",
    "server_signin_cancel",
    "server_devices",
    "server_sign_out_device",
    "server_2fa_status",
    "server_2fa_setup",
    "server_2fa_confirm",
    "server_2fa_disable",
    "server_2fa_save_codes",
    "server_security_events",
    "google_sign_in_cancel",
    "google_drive_vaults",
    // Turning sync off is fine, also with the copy on Drive deleted.
    "google_drive_disable",
    "google_drive_remove",
    "update_status",
    "update_check",
    "update_install",
    "update_open_notes",
    "app_versions_status",
    "app_versions_dismiss",
    "app_versions_update",
    // Teams and Family: reading, signing in, opening the website.
    "account_status",
    // The Passyble password: its unlock screen, the checks that change nothing, and the ways back in
    // (a recovery code, a reset from this PC, another device's approval).
    "vault_access",
    "unlock_account",
    "unlock_account_hello",
    "account_keys_status",
    "account_kit",
    "account_recovery_reset",
    "account_reset_from_device",
    "account_device_request_start",
    "account_device_request_poll",
    "account_device_request_confirm",
    "account_device_request_cancel",
    // The e-mail reset and admin recovery are ways back in too (no vault changes); the list of
    // locked key sets only reads.
    "account_reset_status",
    "account_reset_start",
    "account_reset_cancel",
    "account_reset_complete",
    "account_locked_list",
    "account_key_notice_dismiss",
    "account_admin_recovery_status",
    "account_admin_recovery_request",
    "account_admin_recovery_finish",
    "account_sign_in",
    "account_sign_in_cancel",
    "account_sign_out",
    // Help and support: no vault involved, and read-only is when people need it.
    "support_status",
    "support_meta",
    "support_diagnostics",
    "support_tickets",
    "support_create",
    "support_ticket",
    "support_reply",
    "support_close",
    "support_guest_check",
    "support_guest_claim",
    "support_link_claim",
    "support_guest_remove",
    "support_open_web",
    "policy_status",
    "teams_notifications_seen",
    "teams_notices_dismiss",
    "send_list",
    "send_pick_file",
    "emergency_status",
    "admin_recovery_status",
    "admin_recovery_request",
    "admin_recovery_finish",
    "org_admin_recovery_requests",
    "teams_overview",
    "teams_refresh",
    "shared_vault_info",
    "vault_items_vaults",
    "emergency_items",
    "org_overview",
    "emergency_contact_keys",
    "server_vault_features",
    "device_approvals",
    "org_members",
    "org_departments",
    "org_policies",
    "org_activity",
    "org_billing_open",
    // Settings → Keyboard shortcuts (a setting on this PC), and Quick Access (search and copy).
    "shortcuts_state",
    "set_shortcut",
    "shortcuts_recording",
    "quick_access_open",
    // A QR code read from the screen: looked at, never added (the editor's field can't be saved).
    "qrscan_state",
    "qrscan_review",
    "qrscan_again",
    "qr_scan_screen",
];

/// Refused in read-only mode: edits, deletes, imports, merges, 2FA changes, sync and sync set-up, a new vault,
/// auto-type, vault settings kept in the vault and recovery codes. [`refuses`] only needs [`ALLOWED`].
#[cfg_attr(not(test), allow(dead_code))]
pub const BLOCKED: &[&str] = &[
    "account_keys_setup",
    "vault_link",
    "vault_link_decline",
    "vault_unlink",
    "setup_create_linked",
    "account_vault_create",
    "account_vault_delete",
    "account_password_change",
    "account_secret_key_replace",
    "account_recovery_replace",
    "account_device_key_set",
    "account_invite_device",
    "account_device_requests",
    "account_device_accept",
    "account_device_approve",
    "account_device_deny",
    // Relinking old vaults writes them; deleting a locked set and enrolment change the account.
    "account_locked_unlock",
    "account_locked_delete",
    "account_admin_recovery_enroll",
    "account_admin_recovery_withdraw",
    "setup_create",
    "setup_webdav_restore",
    "otpauth_commit",
    "save_item",
    "delete_item",
    "restore_item",
    "delete_items",
    "restore_items",
    "set_favorites",
    "get_item_for_edit",
    "change_master_password",
    "sync_now",
    "totp_popup_type",
    "quickpick_choose",
    "quickpick_generate",
    "generate_alias",
    "set_email_generator",
    "set_alias_service",
    "remove_alias_service",
    "set_default_alias_service",
    "set_vault_pins",
    "import_file",
    "import_text",
    "import_commit",
    "import_dropped",
    "import_with_password",
    "import_key_file",
    "merge_duplicates",
    "merge_pair",
    "undo_merge",
    "setup_server_connect",
    "server_use_for_vault",
    "server_signin",
    "server_signin_set_password",
    "server_change_password",
    "server_adopt_password",
    "server_code_set_password",
    "server_reset_hello",
    "server_signin_new_vault",
    "server_request_reset",
    "server_code_signin",
    "google_sign_in",
    "setup_google_drive_restore",
    "google_drive_enable",
    // Syncs (may upload) before it deletes.
    "google_drive_delete_old_versions",
    "trash_restore",
    "trash_delete",
    "trash_empty",
    "health_use_https",
    "recovery_code_create",
    "recovery_code_remove",
    "send_create",
    "send_revoke",
    "emergency_add",
    "emergency_remove",
    "emergency_request",
    "emergency_answer",
    "emergency_open",
    "emergency_open_file",
    "emergency_keep",
    "emergency_renew_now",
    "admin_recovery_enroll",
    "admin_recovery_withdraw",
    "org_admin_recovery_approve",
    "teams_publish_keys",
    "teams_invite_answer",
    "shared_vault_rename",
    "shared_vault_leave",
    "shared_trust_confirm",
    "shared_signer_pin",
    "item_share",
    "direct_share_start",
    "org_invite",
    "org_invite_csv",
    "org_invite_resend",
    "org_invite_cancel",
    "org_confirm",
    "org_set_role",
    "org_offboard",
    "emergency_accept",
    "emergency_grant",
    "server_vault_create",
    "server_vault_delete",
    "device_approval_answer",
    "device_approval_email",
    "org_leave",
    "org_transfer_owner",
    "org_department_create",
    "org_department_rename",
    "org_department_delete",
    "org_department_member",
    "org_vault_create",
    "org_vault_access",
    "org_vault_delete",
    "org_policies_set",
    "org_member_password_mode",
    // A 2FA code from a QR code on screen, or its Google Authenticator export (an import).
    "qrscan_commit",
    "qrscan_import",
    // Sync now from the vault screen (every vault with sync, as `sync_now`).
    "sync_all",
];

pub fn refuses(command: &str) -> bool {
    !ALLOWED.contains(&command)
}

pub fn refused_text() -> String {
    tr!("app_versions.read_only_refused")
}

pub fn gate<F>(handler: F) -> impl Fn(Invoke<Wry>) -> bool + Send + Sync + 'static
where
    F: Fn(Invoke<Wry>) -> bool + Send + Sync + 'static,
{
    move |invoke: Invoke<Wry>| {
        let command = invoke.message.command();
        if refuses(command) && crate::app_versions::blocked() {
            crate::applog::plog!("read-only: refused {command}");
            invoke.resolver.reject(refused_text());
            return true;
        }
        handler(invoke)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The command names registered in main.rs (`tauri::generate_handler![...]`).
    fn registered() -> Vec<String> {
        let main = include_str!("main.rs");
        let start = main.find("generate_handler![").expect("generate_handler") + 18;
        let end = start + main[start..].find(']').expect("end of the list");
        main[start..end]
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with("//") && !l.starts_with('#'))
            .flat_map(|l| l.split(','))
            .map(str::trim)
            .filter(|c| !c.is_empty())
            .map(|c| c.rsplit("::").next().unwrap_or(c).to_string())
            .collect()
    }

    #[test]
    fn every_command_is_allowed_or_blocked() {
        let commands = registered();
        assert!(commands.len() > 150, "{}", commands.len());
        for command in &commands {
            let allowed = ALLOWED.contains(&command.as_str());
            let blocked = BLOCKED.contains(&command.as_str());
            assert!(
                allowed != blocked,
                "{command}: in {} lists (add it to ALLOWED or BLOCKED)",
                if allowed { "both" } else { "neither of the" }
            );
        }
        for listed in ALLOWED.iter().chain(BLOCKED) {
            assert!(
                commands.iter().any(|c| c == listed),
                "{listed} is listed but not registered"
            );
        }
    }

    #[test]
    fn edits_imports_deletes_sync_and_auto_type_are_refused() {
        for command in [
            "save_item",
            "delete_item",
            "delete_items",
            "restore_item",
            "trash_empty",
            "import_commit",
            "import_file",
            "sync_now",
            "sync_all",
            "setup_server_connect",
            "google_drive_enable",
            "quickpick_choose",
            "totp_popup_type",
            "otpauth_commit",
            "qrscan_commit",
            "qrscan_import",
            "change_master_password",
            "a_command_added_later",
        ] {
            assert!(refuses(command), "{command}");
        }
        for command in [
            "unlock",
            "lock",
            "list_items",
            "get_item",
            "copy_secret",
            "totp",
            "export_vault",
            "update_install",
            "app_versions_update",
        ] {
            assert!(!refuses(command), "{command}");
        }
    }
}
