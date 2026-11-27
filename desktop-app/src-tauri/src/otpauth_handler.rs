//! Who opens `otpauth:` links on this PC: the per-user URL protocol, no administrator rights.
//!
//! The NSIS installer writes `HKCU\Software\Classes\otpauth` only when no app handles these links yet, and removes it
//! on uninstall when it still points at that install. It is deliberately not in `plugins.deep-link`: the Tauri template
//! would overwrite another authenticator's handler without asking. Settings → Startup "Open otpauth links with
//! Passyble" claims it later ([`claim`]), the user's explicit choice.
//!
//! Windows' default-app choice can override the key (`UrlAssociations\otpauth\UserChoice`, which apps can't write):
//! then only the user can change it ([`Handler`] stays [`Handler::OtherApp`] after a claim). All of it goes through
//! [`Registry`]: the tests use a fake and never touch the real keys.

use serde_json::{json, Value};

use crate::i18n::tr;

/// The scheme is also the name of its class key (the "ProgId" Windows reports for it).
const SCHEME: &str = "otpauth";

/// The values of the class key under `HKCU\Software\Classes\otpauth`: (subkey, name, data).
fn class_values(exe: &str) -> [(&'static str, &'static str, String); 4] {
    [
        ("", "", "URL:otpauth".to_string()),
        ("", "URL Protocol", String::new()),
        ("DefaultIcon", "", format!("\"{exe}\",0")),
        (r"shell\open\command", "", open_command(exe)),
    ]
}

/// What Windows runs for a link (the installer writes the same string).
fn open_command(exe: &str) -> String {
    format!("\"{exe}\" \"%1\"")
}

trait Registry {
    fn open_command(&self) -> Option<String>;
    fn user_choice(&self) -> Option<String>;
    fn write_class(&mut self, values: &[(&str, &str, String)]) -> Result<(), String>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Handler {
    ThisApp,
    Nobody,
    OtherApp,
}

impl Handler {
    fn name(self) -> &'static str {
        match self {
            Handler::ThisApp => "this",
            Handler::Nobody => "none",
            Handler::OtherApp => "other",
        }
    }
}

fn handler(registry: &impl Registry, exe: &str) -> Handler {
    let chosen = registry.user_choice();
    if chosen.is_some_and(|app| !app.eq_ignore_ascii_case(SCHEME)) {
        return Handler::OtherApp;
    }
    match registry.open_command() {
        None => Handler::Nobody,
        Some(command) if command.trim().is_empty() => Handler::Nobody,
        Some(command) if command.eq_ignore_ascii_case(&open_command(exe)) => Handler::ThisApp,
        Some(_) => Handler::OtherApp,
    }
}

/// Makes this `Pass.exe` the handler and says who opens the links now (Windows' own choice can
/// still say another app).
fn claim(registry: &mut impl Registry, exe: &str) -> Result<Handler, String> {
    registry.write_class(&class_values(exe))?;
    Ok(handler(registry, exe))
}

#[cfg(windows)]
mod real {
    use winreg::enums::{HKEY_CLASSES_ROOT, HKEY_CURRENT_USER};
    use winreg::RegKey;

    const CLASS_KEY: &str = r"Software\Classes\otpauth";
    const ASSOCIATIONS: &str =
        r"Software\Microsoft\Windows\Shell\Associations\UrlAssociations\otpauth";

    pub struct Hkcu;

    impl super::Registry for Hkcu {
        fn open_command(&self) -> Option<String> {
            RegKey::predef(HKEY_CLASSES_ROOT)
                .open_subkey(r"otpauth\shell\open\command")
                .and_then(|key| key.get_value::<String, _>(""))
                .ok()
        }

        fn user_choice(&self) -> Option<String> {
            let hkcu = RegKey::predef(HKEY_CURRENT_USER);
            // Windows 11's newer key first; both hold the app's ProgId.
            ["UserChoiceLatest", "UserChoice"]
                .iter()
                .find_map(|choice| {
                    hkcu.open_subkey(format!(r"{ASSOCIATIONS}\{choice}"))
                        .and_then(|key| key.get_value::<String, _>("ProgId"))
                        .ok()
                        .filter(|app| !app.trim().is_empty())
                })
        }

        fn write_class(&mut self, values: &[(&str, &str, String)]) -> Result<(), String> {
            let hkcu = RegKey::predef(HKEY_CURRENT_USER);
            for (subkey, name, data) in values {
                let path = if subkey.is_empty() {
                    CLASS_KEY.to_string()
                } else {
                    format!(r"{CLASS_KEY}\{subkey}")
                };
                let (key, _) = hkcu.create_subkey(path).map_err(failed)?;
                key.set_value(name, data).map_err(failed)?;
            }
            Ok(())
        }
    }

    fn failed(e: std::io::Error) -> String {
        crate::errors::logged(
            crate::i18n::tr!("errors.otpauth_handler_failed"),
            "otpauth link handler",
            e,
        )
    }
}

fn this_exe() -> Result<String, String> {
    std::env::current_exe()
        .map(|exe| exe.display().to_string())
        .map_err(|e| crate::errors::logged(tr!("errors.otpauth_handler_failed"), "current exe", e))
}

/// `{ supported, handler: "this" | "none" | "other" }` for the Settings row.
#[tauri::command]
pub fn otpauth_handler_status(app: tauri::AppHandle) -> Value {
    #[cfg(target_os = "linux")]
    {
        json!({ "supported": true, "handler": linux::state(&app) })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = app;
        #[cfg(windows)]
        {
            if let Ok(exe) = this_exe() {
                return json!({ "supported": true, "handler": handler(&real::Hkcu, &exe).name() });
            }
        }
        json!({ "supported": false })
    }
}

#[tauri::command]
pub fn otpauth_handler_claim(app: tauri::AppHandle) -> Result<Value, String> {
    #[cfg(windows)]
    {
        let _ = app;
        let found = claim(&mut real::Hkcu, &this_exe()?)?;
        Ok(json!({ "handler": found.name() }))
    }
    #[cfg(target_os = "linux")]
    {
        linux::claim(&app)?;
        Ok(json!({ "handler": linux::state(&app) }))
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        let _ = app;
        Err(tr!("errors.otpauth_handler_failed"))
    }
}

/// Windows settings' default apps, where the user can pick the app when Windows' own choice wins. Linux has no
/// such page to open (it differs per desktop); the Settings row hides the button there.
#[tauri::command]
pub fn otpauth_handler_open_settings() -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        Err(tr!("errors.otpauth_handler_failed"))
    }
    #[cfg(not(target_os = "linux"))]
    {
        crate::platform::open_browser("ms-settings:defaultapps")
    }
}

/// Linux, at start: when Passyble already opens otpauth links, register them again, so the
/// handler follows this executable (an AppImage that was moved). Nothing is claimed otherwise.
#[cfg(target_os = "linux")]
pub fn refresh(app: &tauri::AppHandle) {
    use tauri_plugin_deep_link::DeepLinkExt;
    if app.deep_link().is_registered(SCHEME).unwrap_or(false) {
        if let Err(e) = app.deep_link().register(SCHEME) {
            crate::applog::plog!("refreshing the otpauth handler: {e}");
        }
    }
}

/// Linux: the desktop's URL handlers through xdg-mime. Claiming uses the deep-link plugin's `register`, which adds
/// `x-scheme-handler/otpauth` to `Pass-handler.desktop` and makes it the default. otpauth stays out of
/// `plugins.deep-link`, so only the user's choice claims it, as on Windows; the link arrives on the command line
/// and goes through [`crate::otpauth`].
#[cfg(target_os = "linux")]
mod linux {
    use tauri::AppHandle;
    use tauri_plugin_deep_link::DeepLinkExt;

    use super::SCHEME;
    use crate::i18n::tr;

    pub fn state(app: &AppHandle) -> &'static str {
        let ours = app.deep_link().is_registered(SCHEME).unwrap_or(false);
        let default = if ours {
            None
        } else {
            pass_linux::url_handler::default_handler(SCHEME)
        };
        pass_linux::url_handler::handler_state(default.as_deref(), ours)
    }

    pub fn claim(app: &AppHandle) -> Result<(), String> {
        app.deep_link().register(SCHEME).map_err(|e| {
            crate::errors::logged(tr!("errors.otpauth_handler_failed"), "otpauth handler", e)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    const EXE: &str = r"C:\Users\demo\AppData\Local\Programs\Passyble\Pass.exe";
    const OTHER: &str = r#""C:\Other\Auth.exe" "%1""#;

    #[derive(Default)]
    struct Fake {
        machine: Option<String>,
        choice: Option<String>,
        user: BTreeMap<(String, String), String>,
    }

    impl Registry for Fake {
        fn open_command(&self) -> Option<String> {
            // Like HKEY_CLASSES_ROOT: the user's key wins over the machine's.
            let user = (r"shell\open\command".to_string(), String::new());
            self.user.get(&user).cloned().or(self.machine.clone())
        }

        fn user_choice(&self) -> Option<String> {
            self.choice.clone()
        }

        fn write_class(&mut self, values: &[(&str, &str, String)]) -> Result<(), String> {
            for (subkey, name, data) in values {
                self.user
                    .insert((subkey.to_string(), name.to_string()), data.clone());
            }
            Ok(())
        }
    }

    #[test]
    fn says_who_opens_the_links() {
        let mut fake = Fake::default();
        assert_eq!(handler(&fake, EXE), Handler::Nobody);
        fake.machine = Some(OTHER.into());
        assert_eq!(handler(&fake, EXE), Handler::OtherApp);
        fake.machine = Some(format!("\"{}\" \"%1\"", EXE.to_uppercase()));
        assert_eq!(handler(&fake, EXE), Handler::ThisApp, "paths ignore case");
        fake.machine = Some("  ".into());
        assert_eq!(handler(&fake, EXE), Handler::Nobody);
    }

    #[test]
    fn claiming_writes_the_protocol_keys() {
        let mut fake = Fake {
            machine: Some(OTHER.into()),
            ..Default::default()
        };
        assert_eq!(claim(&mut fake, EXE), Ok(Handler::ThisApp));
        let value = |subkey: &str, name: &str| {
            fake.user
                .get(&(subkey.to_string(), name.to_string()))
                .cloned()
        };
        assert_eq!(value("", "").as_deref(), Some("URL:otpauth"));
        assert_eq!(value("", "URL Protocol").as_deref(), Some(""));
        assert_eq!(
            value(r"shell\open\command", "").unwrap(),
            format!("\"{EXE}\" \"%1\"")
        );
        assert_eq!(value("DefaultIcon", "").unwrap(), format!("\"{EXE}\",0"));
    }

    #[test]
    fn windows_own_choice_wins_and_only_the_user_can_change_it() {
        let mut fake = Fake {
            choice: Some("AppXOtherAuthenticator".into()),
            ..Default::default()
        };
        assert_eq!(handler(&fake, EXE), Handler::OtherApp);
        // Claimed, and Windows still says the other app: the row sends the user to its settings.
        assert_eq!(claim(&mut fake, EXE), Ok(Handler::OtherApp));
        fake.choice = Some("OTPAUTH".into());
        assert_eq!(handler(&fake, EXE), Handler::ThisApp);
    }

    /// The installer writes the same thing `claim` does, and only when nothing handles the links.
    #[test]
    fn the_installer_keeps_other_handlers_and_cleans_up_after_itself() {
        let hooks =
            include_str!("../../../../Windows/installer/installer-hooks.nsh").replace("\r\n", "\n");
        let register = hooks
            .split("!macro PASS_REGISTER_OTPAUTH")
            .nth(1)
            .and_then(|rest| rest.split("!macroend").next())
            .expect("the install macro");
        assert!(register.contains(r#"ReadRegStr $R7 HKCR "otpauth\shell\open\command" """#));
        assert!(register.contains(r#"${If} $R7 == """#));
        let exe = r"$INSTDIR\${MAINBINARYNAME}.exe";
        assert!(register.contains(&format!(
            r#"WriteRegStr HKCU "Software\Classes\otpauth\shell\open\command" "" '{}'"#,
            open_command(exe)
        )));
        assert!(
            register.contains(r#"WriteRegStr HKCU "Software\Classes\otpauth" "URL Protocol" """#)
        );
        let post_install = hooks.split("!macro NSIS_HOOK_POSTINSTALL").nth(1).unwrap();
        assert!(post_install
            .split("!macroend")
            .next()
            .unwrap()
            .contains("PASS_REGISTER_OTPAUTH"));
        let post_uninstall = hooks
            .split("!macro NSIS_HOOK_POSTUNINSTALL")
            .nth(1)
            .unwrap();
        let cleanup = post_uninstall.split("!macroend").next().unwrap();
        assert!(cleanup.contains(&format!(r#"${{If}} $R7 == '{}'"#, open_command(exe))));
        assert!(cleanup.contains(r#"DeleteRegKey HKCU "Software\Classes\otpauth""#));
    }

    /// In `plugins.deep-link` the Tauri template would overwrite another app's handler.
    #[test]
    fn the_scheme_is_not_a_deep_link_of_the_template() {
        let config: Value = serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        let schemes = config["plugins"]["deep-link"]["desktop"]["schemes"]
            .as_array()
            .unwrap();
        assert!(!schemes.iter().any(|s| s == "otpauth"), "{schemes:?}");
    }
}
