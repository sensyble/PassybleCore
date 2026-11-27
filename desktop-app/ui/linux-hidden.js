// What the Linux build leaves out of the UI: Windows-only features. Each entry is the i18n key of the
// row, line or tip it hides; views check `hiddenOn(platform, key)`. Pure (no DOM, no Tauri) so node
// can test it. macOS hides only the Windows passkey provider (MACOS_HIDDEN); Windows hides nothing.

export const LINUX_HIDDEN = Object.freeze([
  // Settings → Unlock: Windows Hello and the rows that only exist for it.
  "settings.windows_hello",
  "settings.ask_master",
  "settings.more_security",
  // Settings → Autofill: Windows passkeys and the auto-type hotkey.
  "settings.windows_passkeys",
  "settings.hotkey",
  "settings.otpauth_open_windows",
  // Help: auto-type, Windows app keys, the Windows 11 passkeys step.
  "help.autotype_title",
  "help.keys_windows",
  "help.passkeys_4",
  "editor.urls_pin_hint",
]);

// macOS: no Passyble passkey provider yet (the browser extension's passkeys still work).
export const MACOS_HIDDEN = Object.freeze([
  "settings.windows_passkeys",
  "help.passkeys_4",
]);

/** True when `platform` ("windows", "macos", "linux", as `status` says) leaves out `key`. */
export function hiddenOn(platform, key) {
  if (platform === "linux") return LINUX_HIDDEN.includes(key);
  if (platform === "macos") return MACOS_HIDDEN.includes(key);
  return false;
}
