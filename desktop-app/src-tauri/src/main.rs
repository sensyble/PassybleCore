//! Pass for Windows: the GUI shell around `pass_agent`: the vault UI, passkey consent, TOTP popup and
//! auto-type quick-pick windows, tray and close-to-tray, `--background` start (used by the native host),
//! single instance, the `pass+server://` and `otpauth://` links, the agent's IPC server for the browser
//! extension, auto-lock, sync, global shortcuts, Windows Hello unlock, signed updates and read-only mode
//! below the minimum version.

// A GUI program in every build: no console window, also for `target\debug\Pass.exe`. Diagnostics go to
// %LOCALAPPDATA%\Pass\logs\pass.log (and stderr when there is one). The native host stays a console
// program: it talks to the browser over stdio.
#![windows_subsystem = "windows"]

mod account;
mod account_keys;
mod account_vaults;
mod ai_tools;
mod app_menu;
mod applog;
mod app_versions;
mod auto_lock;
mod autostart;
mod autotype;
mod background;
mod clipboard;
mod commands;
mod contact_pins;
mod devices;
mod errors;
mod export;
mod gdrive;
mod generator;
#[cfg(feature = "gdrive")]
mod google_oauth;
mod health;
mod hello;
mod i18n;
mod import;
mod merge;
mod native_messaging;
mod otpauth;
mod otpauth_handler;
mod passkey_provider;
mod password_change;
mod password_mode;
mod platform;
mod popups;
mod quick_access;
mod read_only;
mod recovery;
mod screen_qr;
mod server;
mod settings;
mod shortcuts;
mod setup_guide;
mod signin;
mod site_icons;
mod sizes;
mod startup;
mod state;
mod teams;
mod support;
mod sync_schedule;
mod teams_admin;
mod teams_api;
mod teams_send;
mod teams_vaults;
mod titlebar;
mod trash;
mod tray;
mod twofactor;
mod ui;
mod undo;
mod updates;
mod vaults;
mod webview_memory;

use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use tauri::{Emitter, Manager, RunEvent, WindowEvent};

use crate::settings::Settings;
use crate::state::{lock, AppState};

/// How often, and how far apart, start-up asks whether Windows Hello is available (it can say no for a
/// while right after signing in to Windows).
const HELLO_CHECKS: u32 = 10;
const HELLO_RECHECK: Duration = Duration::from_secs(3);

/// Written before a settings-triggered restart so the relaunched app opens its window even after `--background`.
pub fn show_on_start_marker() -> PathBuf {
    settings::local_dir().join(".show-on-start")
}

fn main() {
    // Before any secret is in memory: no crash dumps, and (Windows, macOS) other programs can't read
    // this process' memory or attach a debugger (pass_agent::harden; release builds, or PASSYBLE_HARDEN=1).
    pass_agent::harden::harden_process();
    // `--passkey-setup <action>`: passkey provider registration from the command line; exits before anything else.
    if let Some(code) = passkey_provider::cli() {
        std::process::exit(code);
    }
    // `--background` and `--passkey-provider` (started by COM for a passkey request): tray only.
    let args: Vec<String> = std::env::args_os()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    // Started for an otpauth:// link: always the window. The link's text never counts as options.
    let start_link = otpauth::link_argument(&args);
    let background = start_link.is_none() && startup::tray_only(&args);
    drop(args);
    // The kept item list is sealed with the Keychain device key (DPAPI's place on Windows), and a vault
    // in iCloud Drive that macOS 12 or 13 evicted is downloaded before it is read. Keyring secrets go
    // into one file sealed with that same key, so macOS asks at most once (pass_macos::secrets). All set
    // once, before any agent or keyring entry exists.
    #[cfg(target_os = "macos")]
    {
        keyring::set_default_credential_builder(pass_macos::secrets::keyring_store());
        let sealer = std::sync::Arc::new(platform::KeptKeychain);
        let sealer = pass_agent::set_default_kept_sealer(sealer);
        let fetch = pass_macos::icloud::fetch_missing;
        let fetcher = pass_agent::store::set_missing_file_fetcher(fetch);
        if sealer.is_err() || fetcher.is_err() {
            applog::plog!("start: an agent hook was already set");
        }
    }
    #[cfg(target_os = "linux")]
    {
        let sealer = std::sync::Arc::new(platform::KeptSecretService);
        if pass_agent::set_default_kept_sealer(sealer).is_err() {
            applog::plog!("start: an agent hook was already set");
        }
    }

    let app = tauri::Builder::default()
        // Must be the first plugin: a second launch hands its arguments over and exits.
        // Started again from the Start menu or a shortcut: the user opens the window. A `--background` start stays in the tray.
        .plugin(tauri_plugin_single_instance::init(|app, argv, _cwd| {
            if argv.iter().any(|a| a == passkey_provider::LAUNCH_ARG) {
                passkey_provider::handed_over(app);
            }
            if let Some(link) = otpauth::link_argument(&argv) {
                otpauth::open(app, &link);
            } else if !startup::tray_only(&argv) {
                popups::open_main(app);
            }
        }))
        .plugin(tauri_plugin_deep_link::init())
        .plugin(tauri_plugin_global_shortcut::Builder::new().build())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .setup(move |app| {
            applog::init();
            if let Some(hardening) = pass_agent::harden::last() {
                applog::plog!("start: {hardening}");
            }
            // The cached version requirements first: below the minimum, the agent starts read-only.
            app_versions::init(app.handle());
            if start_link.is_some() {
                otpauth::scrub_command_line();
            }
            let handle = app.handle().clone();
            let (settings, _existed) = Settings::load();
            let locale = i18n::apply_preference(settings.language.as_deref());
            pass_core::set_language(Some(locale.to_string()));
            twofactor::server_language(&handle, locale, false);
            let listed: Vec<String> = settings.vaults.iter().map(|v| v.id.clone()).collect();
            thread::spawn(move || undo::sweep_removed_hello(&listed));
            let state = Arc::new(AppState::new(handle.clone(), settings.clone()));
            app.manage(state.clone());

            // The windows are `"create": false` in tauri.conf.json and built here, after `manage`, so their
            // scripts can't call a command before the state exists. All are kept out of screenshots and
            // screen sharing (popups::CAPTURE_PROTECTED), whatever the config says, and stay built so a warm
            // window opens at once (webview_memory.rs).
            for window in app.config().app.windows.clone() {
                let builder = tauri::WebviewWindowBuilder::from_config(&handle, &window)?
                    .content_protected(popups::CAPTURE_PROTECTED);
                let builder = titlebar::frame(&window.label, builder);
                #[cfg(windows)]
                let builder = builder.additional_browser_args(webview_memory::BROWSER_ARGS);
                builder.build()?;
            }
            popups::set_titles(&handle);
            webview_memory::built(&handle);
            webview_memory::perf_note("windows built");

            // The agent (and the IPC pipe) is created only once there is a vault in the list; until then
            // the main window shows onboarding, which creates it.
            if settings.active().is_some() {
                state.ensure_agent(&handle);
            }

            signin::setup_deep_links(&handle);
            popups::set_dock_icon(&handle, false);
            #[cfg(target_os = "macos")]
            autostart::refresh();
            #[cfg(target_os = "linux")]
            autostart::refresh();
            tray::create(&handle)?;
            app_menu::install(&handle);
            shortcuts::register_all(&handle, &settings);
            background::start(&handle);
            updates::start(&handle);
            support::start(&handle);
            app_versions::start(&handle);
            passkey_provider::start(&handle, settings.passkey_provider);

            // Win+L, sleep, a Mac's screen lock: locks unless the vault stays unlocked until a restart (auto_lock.rs).
            let lock_handle = handle.clone();
            platform::watch_session_lock(Box::new(move || {
                let settings = lock_handle.state::<Arc<AppState>>().settings();
                if auto_lock::on_computer_lock(&settings) {
                    tray::lock_now(&lock_handle);
                }
            }));

            let extra_ids = settings.extra_extension_ids.clone();
            thread::spawn(move || {
                let status = native_messaging::register(&extra_ids);
                if let Some(e) = status.error.filter(|_| status.supported) {
                    crate::applog::plog!("native messaging registration: {e}");
                }
            });
            // The unlock screen may already be up: it refreshes on `hello-available`. Right after signing
            // in to Windows, Hello can report itself unavailable for a while, so a "no" is asked again. The
            // event only offers Hello; it starts by itself only on a window the user opened (startup.rs).
            let hello_state = state.clone();
            let hello_handle = handle.clone();
            thread::spawn(move || {
                for attempt in 0..HELLO_CHECKS {
                    if attempt > 0 {
                        thread::sleep(HELLO_RECHECK);
                    }
                    if platform::hello_available() {
                        hello_state.hello_available.store(true, Ordering::Relaxed);
                        let _ = hello_handle.emit("hello-available", ());
                        return;
                    }
                }
            });

            // Started with Windows or by the browser: tray only, the vault stays locked and nothing asks for Hello.
            let marker = show_on_start_marker();
            let marker_age = marker.exists().then(|| {
                std::fs::metadata(&marker)
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|t| t.elapsed().ok())
                    .unwrap_or_default()
            });
            let _ = std::fs::remove_file(&marker);
            let restarted = marker_age.is_some_and(|age| age <= startup::RESTART_MARKER_TTL);
            match start_link.filter(|_| !restarted) {
                Some(link) => otpauth::open(&handle, &link),
                None => {
                    if startup::window_at_start(background, settings.start_minimized, marker_age) {
                        popups::open_main(&handle);
                    } else {
                        // Linux without a tray (GNOME without the AppIndicator extension): a tray-only start
                        // would leave no window and no icon, so the main window opens minimized.
                        #[cfg(target_os = "linux")]
                        if !platform::tray_host_present() {
                            popups::open_main(&handle);
                            if let Some(main) = handle.get_webview_window("main") {
                                let _ = main.minimize();
                            }
                        }
                    }
                }
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::DragDrop(tauri::DragDropEvent::Drop { paths, .. }) = event {
                if window.label() == "main" {
                    import::dropped(window.app_handle(), paths);
                }
            }
            if let WindowEvent::Focused(focused) = event {
                background::window_focused(window.app_handle(), *focused);
            }
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let app = window.app_handle();
                // Linux without a tray: the main window minimizes instead, so Passyble stays in the dock.
                #[cfg(target_os = "linux")]
                let minimize = window.label() == "main" && !platform::tray_host_present();
                #[cfg(not(target_os = "linux"))]
                let minimize = false;
                if minimize {
                    let _ = window.minimize();
                } else {
                    popups::hide(app, window.label());
                }
                let state = app.state::<Arc<AppState>>();
                match window.label() {
                    "main" => state.resolve_unlock_waiters(false),
                    "prompt" => state.prompts.cancel_all(app),
                    "quickpick" => *lock(&state.quickpick) = None,
                    "qrscan" => screen_qr::clear(),
                    "totp" => *lock(&state.totp_popup) = None,
                    _ => {}
                }
            }
        })
        .invoke_handler(read_only::gate(tauri::generate_handler![
            commands::status,
            webview_memory::perf_painted,
            commands::vault_suggestions,
            commands::pick_vault_file,
            commands::pick_vault_save,
            commands::setup_create,
            commands::setup_open,
            commands::setup_webdav_restore,
            commands::unlock,
            commands::unlock_hello,
            commands::cancel_unlock,
            commands::cancel_hello_unlock,
            popups::take_auto_hello,
            commands::lock,
            otpauth::otpauth_pending,
            otpauth::otpauth_review,
            otpauth::otpauth_commit,
            otpauth::otpauth_cancel,
            otpauth_handler::otpauth_handler_status,
            otpauth_handler::otpauth_handler_claim,
            otpauth_handler::otpauth_handler_open_settings,
            commands::list_items,
            commands::search,
            commands::get_item,
            commands::save_item,
            commands::delete_item,
            commands::restore_item,
            commands::delete_items,
            commands::restore_items,
            commands::set_favorites,
            commands::enable_hello,
            commands::dismiss_hello_offer,
            commands::totp,
            commands::totp_check,
            commands::generate_password,
            generator::generate_username,
            generator::generate_email,
            generator::generate_alias,
            generator::generator_settings,
            generator::set_email_generator,
            generator::set_alias_service,
            generator::remove_alias_service,
            generator::set_default_alias_service,
            generator::test_alias_service,
            commands::copy_secret,
            commands::copy_field,
            commands::password_history_entry,
            commands::copy_history_password,
            commands::change_master_password,
            commands::get_settings,
            commands::open_sensyble_site,
            commands::set_settings,
            commands::restart_app,
            commands::sync_now,
            commands::pending_prompts,
            commands::answer_prompt,
            commands::totp_popup_state,
            commands::totp_popup_copy,
            commands::totp_popup_type,
            commands::quickpick_state,
            commands::quickpick_choose,
            commands::quickpick_generate,
            commands::hide_window,
            import::import_file,
            import::import_text,
            import::import_commit,
            import::import_cancel,
            import::import_dropped,
            import::find_duplicates,
            import::merge_duplicates,
            merge::merge_preview,
            merge::merge_pair,
            merge::undo_merge,
            merge::merge_suggestions,
            merge::merge_candidates,
            vaults::rename_vault,
            vaults::remove_vault,
            vaults::undo_remove_vault,
            vaults::reveal_vault,
            vaults::local_reminder_dismiss,
            vaults::vault_pins,
            vaults::set_vault_pins,
            server::server_link_check,
            server::server_qr_from_file,
            server::server_qr_from_clipboard,
            server::setup_server_connect,
            server::server_use_for_vault,
            server::server_pair_take,
            signin::server_signin_link,
            signin::server_signin,
            signin::server_signin_set_password,
            signin::server_signin_previous,
            signin::server_signin_cancel,
            signin::server_change_password,
            signin::server_adopt_password,
            signin::server_code_set_password,
            signin::server_reset_hello,
            signin::server_signin_new_vault,
            signin::server_request_reset,
            devices::server_devices,
            devices::server_sign_out_device,
            gdrive::google_sign_in,
            gdrive::google_sign_in_cancel,
            gdrive::google_drive_vaults,
            gdrive::setup_google_drive_restore,
            gdrive::google_drive_enable,
            gdrive::google_drive_disable,
            gdrive::google_drive_delete_old_versions,
            gdrive::google_drive_remove,
            updates::update_status,
            updates::update_check,
            updates::update_install,
            updates::update_open_notes,
            app_versions::app_versions_status,
            app_versions::app_versions_dismiss,
            app_versions::app_versions_update,
            applog::open_log_folder,
            site_icons::site_icons,
            passkey_provider::passkey_provider_open,
            commands::get_item_for_edit,
            commands::item_secret,
            commands::card_info,
            commands::url_suggests_host_only,
            commands::site_suggestions,
            commands::site_name_for,
            commands::vault_tags,
            commands::open_item_url,
            trash::trash_list,
            trash::trash_restore,
            trash::trash_delete,
            trash::trash_empty,
            export::export_vault,
            export::export_choices,
            health::password_health,
            health::password_check,
            health::master_password_check,
            health::master_password_tip_dismiss,
            health::health_breach_check,
            health::health_breach_cancel,
            health::health_breach_status,
            health::health_breach_notice,
            health::health_use_https,
            health::health_open_guide,
            signin::server_code_signin,
            import::import_with_password,
            import::import_key_file,
            import::import_key_file_clear,
            twofactor::server_2fa_status,
            twofactor::server_2fa_setup,
            twofactor::server_2fa_confirm,
            twofactor::server_2fa_disable,
            twofactor::server_2fa_save_codes,
            twofactor::server_security_events,
            recovery::recovery_code_create,
            recovery::recovery_code_remove,
            recovery::recovery_code_save,
            recovery::recovery_unlock,
            recovery::recovery_set_password,
            recovery::recovery_server_reset,
            i18n::i18n_state,
            setup_guide::get_started,
            setup_guide::get_started_show,
            setup_guide::vault_path_synced,
            setup_guide::extension_setup,
            setup_guide::extension_connected,
            setup_guide::extension_open_browser,
            setup_guide::extension_copy,
            setup_guide::extension_show,
            setup_guide::open_releases_page,
            setup_guide::setup_progress,
            setup_guide::extension_open_store,
            account::account_status,
            account::account_sign_in,
            account::account_sign_in_cancel,
            account::account_sign_out,
            account_keys::vault_access,
            account_keys::unlock_account,
            account_keys::unlock_account_hello,
            account_keys::account_keys_status,
            account_keys::account_kit,
            account_keys::account_recovery_reset,
            account_keys::account_reset_from_device,
            account_keys::approval::account_device_request_start,
            account_keys::approval::account_device_request_poll,
            account_keys::approval::account_device_request_confirm,
            account_keys::approval::account_device_request_cancel,
            account_keys::account_keys_setup,
            account_keys::vault_link,
            account_keys::vault_link_decline,
            account_keys::vault_unlink,
            account_keys::setup_create_linked,
            account_vaults::account_vault_create,
            account_vaults::account_vault_delete,
            account_keys::account_password_change,
            account_keys::account_secret_key_replace,
            account_keys::account_recovery_replace,
            account_keys::account_device_key_set,
            account_keys::approval::account_invite_device,
            account_keys::approval::account_device_requests,
            account_keys::approval::account_device_accept,
            account_keys::approval::account_device_approve,
            account_keys::approval::account_device_deny,
            account_keys::reset::account_reset_status,
            account_keys::reset::account_reset_start,
            account_keys::reset::account_reset_cancel,
            account_keys::reset::account_reset_complete,
            account_keys::reset::account_locked_list,
            account_keys::reset::account_locked_unlock,
            account_keys::reset::account_locked_delete,
            account_keys::reset::account_key_notice_dismiss,
            account_keys::admin::account_admin_recovery_status,
            account_keys::admin::account_admin_recovery_enroll,
            account_keys::admin::account_admin_recovery_withdraw,
            account_keys::admin::account_admin_recovery_request,
            account_keys::admin::account_admin_recovery_finish,
            support::support_status,
            support::support_meta,
            support::support_diagnostics,
            support::support_tickets,
            support::support_create,
            support::support_ticket,
            support::support_reply,
            support::support_close,
            support::support_guest_check,
            support::support_guest_claim,
            support::support_link_claim,
            support::support_guest_remove,
            support::support_open_web,
            teams::policy_status,
            teams::teams_notifications_seen,
            teams::teams_notices_dismiss,
            teams_send::send_create,
            teams_send::send_list,
            teams_send::send_revoke,
            teams_send::send_pick_file,
            teams_send::emergency_status,
            teams_send::emergency_add,
            teams_send::emergency_remove,
            teams_send::emergency_request,
            teams_send::emergency_answer,
            teams_send::emergency_open,
            teams_send::emergency_open_file,
            teams_send::emergency_keep,
            teams_send::emergency_renew_now,
            teams_send::admin_recovery_status,
            teams_send::admin_recovery_enroll,
            teams_send::admin_recovery_withdraw,
            teams_send::admin_recovery_request,
            teams_send::admin_recovery_finish,
            teams_send::org_admin_recovery_requests,
            teams_send::org_admin_recovery_approve,
            teams_vaults::teams_overview,
            teams_vaults::teams_refresh,
            teams_vaults::teams_publish_keys,
            teams_vaults::teams_invite_answer,
            teams_vaults::shared_vault_info,
            teams_vaults::shared_vault_rename,
            teams_vaults::shared_vault_leave,
            teams_vaults::shared_trust_confirm,
            teams_vaults::shared_signer_pin,
            teams_vaults::item_share,
            teams_vaults::direct_share_start,
            teams_vaults::vault_items_vaults,
            teams_vaults::emergency_items,
            teams_admin::org_overview,
            teams_admin::org_members,
            teams_admin::org_invite,
            teams_admin::org_invite_csv,
            teams_admin::org_invite_resend,
            teams_admin::org_invite_cancel,
            teams_admin::org_confirm,
            teams_admin::org_set_role,
            teams_admin::org_offboard,
            teams_send::emergency_accept,
            teams_send::emergency_contact_keys,
            teams_send::emergency_grant,
            teams_vaults::server_vault_features,
            teams_vaults::server_vault_create,
            teams_vaults::server_vault_delete,
            teams_vaults::device_approvals,
            teams_vaults::device_approval_answer,
            teams_vaults::device_approval_email,
            teams_admin::org_leave,
            teams_admin::org_transfer_owner,
            teams_admin::org_departments,
            teams_admin::org_department_create,
            teams_admin::org_department_rename,
            teams_admin::org_department_delete,
            teams_admin::org_department_member,
            teams_admin::org_vault_create,
            teams_admin::org_vault_access,
            teams_admin::org_vault_delete,
            teams_admin::org_policies,
            teams_admin::org_policies_set,
            teams_admin::org_member_password_mode,
            teams_admin::org_activity,
            teams_admin::org_billing_open,
            ai_tools::ai_tools_state,
            ai_tools::ai_tools_revoke,
            ai_tools::ai_tools_clear_log,
            ai_tools::ai_tools_copy,
            shortcuts::shortcuts_state,
            shortcuts::set_shortcut,
            shortcuts::shortcuts_recording,
            quick_access::quick_access_open,
            screen_qr::qrscan_state,
            screen_qr::qrscan_review,
            screen_qr::qrscan_commit,
            screen_qr::qrscan_again,
            screen_qr::qrscan_import,
            screen_qr::qr_scan_screen,
            commands::sync_all,
            titlebar::window_snap_layouts,
        ]))
        .build(tauri::generate_context!())
        .expect("error while building Passyble");

    app.run(|app, event| {
        match event {
            RunEvent::ExitRequested {
                code: None, api, ..
            } => api.prevent_exit(),
            RunEvent::Exit => {
                tray::lock_completely(app);
                clipboard::clear_now();
                // Linux X11: let go of the clipboard only after the secret is cleared.
                #[cfg(target_os = "linux")]
                pass_linux::clipboard::release();
            }
            #[cfg(target_os = "macos")]
            RunEvent::Reopen { .. } => popups::open_main(app),
            _ => {}
        }
    });
}
