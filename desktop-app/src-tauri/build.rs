// Generates `allow-<command>` permissions for every app command, so each window's capability
// (capabilities/default.json) can grant exactly the commands it needs.
const COMMANDS: &[&str] = &[
    "status",
    "perf_painted",
    "ai_tools_state",
    "ai_tools_revoke",
    "ai_tools_clear_log",
    "ai_tools_copy",
    "vault_suggestions",
    "pick_vault_file",
    "pick_vault_save",
    "setup_create",
    "setup_open",
    "setup_webdav_restore",
    "unlock",
    "unlock_hello",
    "cancel_hello_unlock",
    "take_auto_hello",
    "cancel_unlock",
    "lock",
    "otpauth_pending",
    "otpauth_review",
    "otpauth_commit",
    "otpauth_cancel",
    "otpauth_handler_status",
    "otpauth_handler_claim",
    "otpauth_handler_open_settings",
    "list_items",
    "search",
    "get_item",
    "save_item",
    "delete_item",
    "restore_item",
    "delete_items",
    "restore_items",
    "set_favorites",
    "enable_hello",
    "dismiss_hello_offer",
    "totp",
    "totp_check",
    "generate_password",
    "generate_username",
    "generate_email",
    "generate_alias",
    "generator_settings",
    "set_email_generator",
    "set_alias_service",
    "remove_alias_service",
    "set_default_alias_service",
    "test_alias_service",
    "copy_secret",
    "copy_field",
    "password_history_entry",
    "copy_history_password",
    "change_master_password",
    "get_settings",
    "open_sensyble_site",
    "set_settings",
    "restart_app",
    "sync_now",
    "pending_prompts",
    "answer_prompt",
    "totp_popup_state",
    "totp_popup_copy",
    "totp_popup_type",
    "quickpick_state",
    "quickpick_choose",
    "quickpick_generate",
    "hide_window",
    "import_file",
    "import_text",
    "import_commit",
    "import_cancel",
    "import_dropped",
    "find_duplicates",
    "merge_duplicates",
    "merge_preview",
    "merge_pair",
    "undo_merge",
    "merge_suggestions",
    "merge_candidates",
    "rename_vault",
    "remove_vault",
    "account_vault_create",
    "account_vault_delete",
    "undo_remove_vault",
    "reveal_vault",
    "local_reminder_dismiss",
    "vault_pins",
    "set_vault_pins",
    "server_link_check",
    "server_qr_from_file",
    "server_qr_from_clipboard",
    "setup_server_connect",
    "server_use_for_vault",
    "server_pair_take",
    "server_signin_link",
    "server_signin",
    "server_signin_set_password",
    "server_signin_previous",
    "server_signin_cancel",
    "server_change_password",
    "server_adopt_password",
    "server_code_set_password",
    "server_reset_hello",
    "server_signin_new_vault",
    "server_request_reset",
    "server_devices",
    "server_sign_out_device",
    "google_sign_in",
    "google_sign_in_cancel",
    "google_drive_vaults",
    "setup_google_drive_restore",
    "google_drive_enable",
    "google_drive_disable",
    "google_drive_delete_old_versions",
    "google_drive_remove",
    "update_status",
    "update_check",
    "update_install",
    "update_open_notes",
    "app_versions_status",
    "app_versions_dismiss",
    "app_versions_update",
    "open_log_folder",
    "site_icons",
    "passkey_provider_open",
    "get_item_for_edit",
    "item_secret",
    "card_info",
    "url_suggests_host_only",
    "site_suggestions",
    "site_name_for",
    "vault_tags",
    "open_item_url",
    "trash_list",
    "trash_restore",
    "trash_delete",
    "trash_empty",
    "export_vault",
    "export_choices",
    "password_health",
    "password_check",
    "master_password_check",
    "master_password_tip_dismiss",
    "health_breach_check",
    "health_breach_cancel",
    "health_breach_status",
    "health_breach_notice",
    "health_use_https",
    "health_open_guide",
    "server_code_signin",
    "import_with_password",
    "import_key_file",
    "import_key_file_clear",
    "server_2fa_status",
    "server_2fa_setup",
    "server_2fa_confirm",
    "server_2fa_disable",
    "server_2fa_save_codes",
    "server_security_events",
    "recovery_code_create",
    "recovery_code_remove",
    "recovery_code_save",
    "recovery_unlock",
    "recovery_set_password",
    "recovery_server_reset",
    "i18n_state",
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
    "account_status",
    "account_sign_in",
    "account_sign_in_cancel",
    "account_sign_out",
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
    "account_keys_setup",
    "vault_link",
    "vault_link_decline",
    "vault_unlink",
    "setup_create_linked",
    "account_password_change",
    "account_secret_key_replace",
    "account_recovery_replace",
    "account_device_key_set",
    "account_invite_device",
    "account_device_requests",
    "account_device_accept",
    "account_device_approve",
    "account_device_deny",
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
    "send_create",
    "send_list",
    "send_revoke",
    "send_pick_file",
    "emergency_status",
    "emergency_add",
    "emergency_remove",
    "emergency_request",
    "emergency_answer",
    "emergency_open",
    "admin_recovery_status",
    "admin_recovery_enroll",
    "admin_recovery_withdraw",
    "admin_recovery_request",
    "admin_recovery_finish",
    "org_admin_recovery_requests",
    "org_admin_recovery_approve",
    "teams_overview",
    "teams_refresh",
    "teams_publish_keys",
    "teams_invite_answer",
    "shared_vault_info",
    "shared_vault_rename",
    "shared_vault_leave",
    "shared_trust_confirm",
    "shared_signer_pin",
    "item_share",
    "direct_share_start",
    "vault_items_vaults",
    "emergency_items",
    "org_overview",
    "org_members",
    "org_invite",
    "org_invite_csv",
    "org_invite_resend",
    "org_invite_cancel",
    "org_confirm",
    "org_set_role",
    "org_offboard",
    "emergency_accept",
    "emergency_contact_keys",
    "emergency_grant",
    "server_vault_features",
    "server_vault_create",
    "server_vault_delete",
    "device_approvals",
    "device_approval_answer",
    "device_approval_email",
    "org_leave",
    "org_transfer_owner",
    "org_departments",
    "org_department_create",
    "org_department_rename",
    "org_department_delete",
    "org_department_member",
    "org_vault_create",
    "org_vault_access",
    "org_vault_delete",
    "org_policies",
    "org_policies_set",
    "org_member_password_mode",
    "org_activity",
    "org_billing_open",
    "shortcuts_state",
    "set_shortcut",
    "shortcuts_recording",
    "quick_access_open",
    "qrscan_state",
    "qrscan_review",
    "qrscan_commit",
    "qrscan_again",
    "qrscan_import",
    "qr_scan_screen",
    "sync_all",
    "window_snap_layouts",
];

/// The Google OAuth Desktop client for Drive backup, read by `google_oauth.rs` with `option_env!`. From the
/// environment, or from the git-ignored `google-oauth.env` next to this file (`PASS_GOOGLE_CLIENT_ID=…` /
/// `PASS_GOOGLE_CLIENT_SECRET=…` lines). Without a client ID the app shows no Google option. A Desktop
/// client's secret is not confidential.
const GOOGLE_VARS: &[&str] = &["PASS_GOOGLE_CLIENT_ID", "PASS_GOOGLE_CLIENT_SECRET"];
const GOOGLE_FILE: &str = "google-oauth.env";

fn google_oauth_client() {
    println!("cargo:rerun-if-changed={GOOGLE_FILE}");
    let file = std::fs::read_to_string(GOOGLE_FILE).unwrap_or_default();
    for var in GOOGLE_VARS {
        println!("cargo:rerun-if-env-changed={var}");
        if std::env::var(var).is_ok_and(|v| !v.trim().is_empty()) {
            continue; // option_env! sees it directly
        }
        let from_file = file
            .lines()
            .filter_map(|l| l.trim().split_once('='))
            .find(|(k, _)| k.trim() == *var)
            .map(|(_, v)| v.trim().trim_matches('"').to_string())
            .filter(|v| !v.is_empty());
        if let Some(value) = from_file {
            println!("cargo:rustc-env={var}={value}");
        }
    }
}

/// Package identity for the Windows passkey provider (`passkey_provider.rs`): every Pass.exe carries an `<msix>`
/// manifest element naming the sparse package registered when the passkey provider is turned on; until then
/// Windows ignores it. The values are also compiled in (`env!`) and read by the packaging script. Defaults are the
/// development identity; releases set `PASSYBLE_PACKAGE_PUBLISHER` to the code-signing subject, and test builds
/// override the name and CLSID so they can be registered next to an installed Passyble.
const PACKAGE_VARS: &[(&str, &str)] = &[
    ("PASSYBLE_PACKAGE_NAME", "Sensyble.Passyble"),
    ("PASSYBLE_PACKAGE_PUBLISHER", "CN=Sensyble"),
    (
        "PASSYBLE_PASSKEY_CLSID",
        "2ced63f3-59c6-4471-88dd-ee8d8822ad81",
    ),
];

const WINDOWS_MANIFEST: &str = r#"<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <dependency>
    <dependentAssembly>
      <assemblyIdentity
        type="win32"
        name="Microsoft.Windows.Common-Controls"
        version="6.0.0.0"
        processorArchitecture="*"
        publicKeyToken="6595b64144ccf1df"
        language="*"
      />
    </dependentAssembly>
  </dependency>
  <msix xmlns="urn:schemas-microsoft-com:msix.v1"
        publisher="{publisher}"
        packageName="{name}"
        applicationId="Pass" />
</assembly>
"#;

fn xml_attr(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn package_identity() -> String {
    let mut values = Vec::new();
    for (var, default) in PACKAGE_VARS {
        println!("cargo:rerun-if-env-changed={var}");
        let value = std::env::var(var)
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| default.to_string());
        println!("cargo:rustc-env={var}={value}");
        values.push(value);
    }
    let (name, publisher, clsid) = (&values[0], &values[1], &values[2]);
    let name_ok = (3..=50).contains(&name.len())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-');
    assert!(
        name_ok,
        "PASSYBLE_PACKAGE_NAME {name:?} is not a valid package name"
    );
    let clsid_ok = clsid.len() == 36
        && clsid.char_indices().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => c == '-',
            _ => c.is_ascii_hexdigit(),
        });
    assert!(
        clsid_ok,
        "PASSYBLE_PASSKEY_CLSID {clsid:?} is not a GUID (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)"
    );
    // Windows refuses to start an exe whose msix publisher it considers invalid (side-by-side
    // error), and its check rejects the OID.2.25... marker of unsigned packages.
    assert!(
        publisher.contains("CN=") && !publisher.contains("OID."),
        "PASSYBLE_PACKAGE_PUBLISHER {publisher:?} must be a certificate subject (CN=...) without OIDs"
    );
    WINDOWS_MANIFEST
        .replace("{publisher}", &xml_attr(publisher))
        .replace("{name}", &xml_attr(name))
}

/// `path` relative to this package (`../ui/i18n/en.json`), with `/`. Relative on purpose: Cargo gives every
/// checkout that shares a target folder the same build output folder, so an absolute path would embed another
/// checkout's catalogs.
fn package_relative(path: &std::path::Path) -> String {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn json_files(dir: &std::path::Path) -> Vec<(String, std::path::PathBuf)> {
    println!("cargo:rerun-if-changed={}", package_relative(dir));
    let mut entries: Vec<(String, std::path::PathBuf)> = std::fs::read_dir(dir)
        .map(|d| {
            d.filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|x| x == "json"))
                .filter_map(|p| Some((p.file_stem()?.to_str()?.to_string(), p)))
                .collect()
        })
        .unwrap_or_default();
    entries.sort();
    entries
}

fn json_table(name: &str, entries: &[(String, std::path::PathBuf)]) -> String {
    let mut out = format!(
        "const {name}: &[(&str, &str)] = &[
"
    );
    for (code, path) in entries {
        let rel = package_relative(path);
        println!("cargo:rerun-if-changed={rel}");
        out.push_str(&format!(
            "    ({code:?}, include_str!(concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/{rel}\"))),
"
        ));
    }
    out.push_str(
        "];
",
    );
    out
}

/// The UI text catalogs (`ui/i18n/<locale>.json`) for `i18n.rs`: `OUT_DIR/i18n_catalogs.rs` defines `CATALOGS`,
/// (locale, JSON text) per file, embedded with `include_str!`. Also `OVERLAYS` in the same shape: on macOS and
/// Linux the platform wording of `macOS/i18n/` and `Linux/i18n/`, merged over the catalogs; empty elsewhere.
fn i18n_catalogs() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let entries = json_files(&root.join("../ui/i18n"));
    assert!(
        entries.iter().any(|(code, _)| code == "en"),
        "ui/i18n/en.json (the source catalog) is missing"
    );
    let target_os = std::env::var("CARGO_CFG_TARGET_OS");
    let overlays = if target_os.as_deref() == Ok("macos") {
        json_files(&root.join("../../../macOS/i18n"))
    } else if target_os.as_deref() == Ok("linux") {
        json_files(&root.join("../../../Linux/i18n"))
    } else {
        Vec::new()
    };
    let out = json_table("CATALOGS", &entries) + &json_table("OVERLAYS", &overlays);
    let target =
        std::path::Path::new(&std::env::var("OUT_DIR").expect("OUT_DIR")).join("i18n_catalogs.rs");
    std::fs::write(target, out).expect("write i18n_catalogs.rs");
}

fn main() {
    google_oauth_client();
    i18n_catalogs();
    let manifest = package_identity();
    tauri_build::try_build(
        tauri_build::Attributes::new()
            .app_manifest(tauri_build::AppManifest::new().commands(COMMANDS))
            .windows_attributes(tauri_build::WindowsAttributes::new().app_manifest(manifest)),
    )
    .expect("failed to run tauri-build");
}
