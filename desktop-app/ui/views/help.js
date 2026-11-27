// Settings → Help: short built-in tutorials, each a dialog with numbered steps and, where it helps, a button
// to the setting or flow it is about. Texts name the app's own labels through placeholders (`t("settings.sync")`),
// so each tutorial matches the screen in every language. What a tutorial offers depends on the build and the vault.
// `ctx` (from Settings or the Get started checklist): `hotkey`, `google`, `webdav` and the actions
// `openSettings(section)`, `openImport()`, `openGuide()`, `openRecovery()`; a missing action leaves its button out.

import { h, icon, invoke, keyLabel, modal, mount, t, toast, errorText } from "../lib.js";
import { hidden, isMac } from "../platform.js";
import { appKeys, commandLabel } from "./app-keys.js";

const path = (...labels) => labels.join(" → ");

/** Every tutorial, in the order Settings → Help lists them: `[id, icon, title]`. */
const ALL_TUTORIALS = [
  ["fill", "globe", t("help.fill_title")],
  ["autotype", "keyboard", t("help.autotype_title")],
  ["totp", "clock", t("help.totp_title")],
  ["passkeys", "key", t("help.passkeys_title")],
  ["sync", "sync", t("help.sync_title")],
  ["import", "download", t("help.import_title")],
  ["recovery", "shield", t("help.recovery_title")],
  ["keys", "keyboard", t("help.keys_title")],
];

/** The tutorials this OS has: Linux has no auto-type (linux-hidden.js). */
export function tutorials() {
  return ALL_TUTORIALS.filter(([id]) => !(id === "autotype" && hidden("help.autotype_title")));
}

/** Opens the public downloads page (setup_guide.rs allows that one address). */
export function openDownloads() {
  invoke("open_releases_page").catch((e) => toast(errorText(e), "error"));
}

function keyTable(title, rows) {
  return h("div", { class: "col" },
    h("h3", { class: "set-head", text: title }),
    h("dl", { class: "keys guide-keys" }, rows.map(([keys, what]) => [h("dt", {}, h("kbd", { text: keys })), h("dd", { text: what })])));
}

function globalKeys(ctx, hotkey) {
  const keys = ctx.shortcuts || {};
  const rows = [];
  if (keys.quick_access) rows.push([keyLabel(keys.quick_access), t("shortcuts.quick_access")]);
  if (keys.scan_qr) rows.push([keyLabel(keys.scan_qr), t("shortcuts.scan_qr")]);
  if (!hidden("help.keys_windows") && (keys.auto_type || !ctx.shortcuts)) rows.push([hotkey, t("vault.auto_type_any")]);
  for (const [id, label] of [["show_app", t("shortcuts.show_app")], ["lock", t("shortcuts.lock")], ["sync_now", t("shortcuts.sync_now")], ["generate_password", t("shortcuts.generate_password")], ["new_note", t("shortcuts.new_note")]]) {
    if (keys[id]) rows.push([keyLabel(keys[id]), label]);
  }
  return rows;
}

function content(id, ctx) {
  const hotkey = keyLabel(ctx.hotkey || "Ctrl+Alt+P");
  const settings = t("settings.title");
  const autofill = path(settings, t("settings.autofill"));
  switch (id) {
    case "fill":
      return {
        steps: [
          t("help.fill_1"),
          t("help.fill_2"),
          t("help.fill_3", { keys: keyLabel("Mod+Shift+L") }),
          t("help.fill_4"),
        ],
        note: t("help.fill_note"),
        actions: [["globe", t("extsetup.title"), ctx.openGuide, true]],
      };
    case "autotype":
      return {
        steps: [
          t("help.autotype_1"),
          t("help.autotype_2", { hotkey }),
          t("help.autotype_3"),
          t("help.autotype_4"),
          t("help.autotype_5", { type_it: t("totp.type") }),
        ],
        note: t("help.autotype_note", { path: path(settings, t("settings.shortcuts"), t("shortcuts.auto_type")) }),
        actions: [["gear", t("help.open_shortcuts"), ctx.openSettings && (() => ctx.openSettings("shortcuts"))]],
      };
    case "totp":
      return {
        steps: [
          t("help.totp_1"),
          t("help.totp_2", { field: t("editor.totp") }),
          t("help.totp_3"),
          t("help.totp_4"),
          t("help.totp_5"),
        ],
        note: t("help.totp_note"),
        actions: [["download", t("help.open_import"), ctx.openImport]],
      };
    case "passkeys":
      return {
        steps: [
          t("help.passkeys_1"),
          t("help.passkeys_2"),
          t("help.passkeys_3"),
          hidden("help.passkeys_4") ? null : t("help.passkeys_4", { path: path(autofill, t("settings.windows_passkeys")) }),
        ],
        note: t("help.passkeys_note"),
        actions: [["gear", t("help.open_autofill"), ctx.openSettings && (() => ctx.openSettings("autofill"))]],
      };
    case "sync":
      return {
        intro: t("help.sync_intro"),
        steps: [
          ctx.webdav ? t("help.sync_server", { path: path(settings, t("settings.sync"), "Passyble Server", t("settings.connect")), signin: t("vaults.sign_in_server") }) : null,
          ctx.google
            ? t("help.sync_google", { path: path(settings, t("settings.sync"), t("onboarding.google_backup")), restore: t("onboarding.google_restore") })
            : null,
          t("help.sync_folder", { path: path(settings, t("settings.this_vault"), t("settings.file"), t("settings.move")), open: t("onboarding.open_existing_file") }),
          ctx.webdav
            ? t("help.sync_webdav", { path: path(settings, t("settings.sync"), "WebDAV"), restore: t("onboarding.webdav"), more: t("onboarding.more_options") })
            : null,
          ctx.webdav ? t("help.sync_phone") : null,
          t("help.sync_install"),
        ],
        note: t("help.sync_note"),
        actions: [
          ["sync", t("help.open_sync"), ctx.openSettings && (() => ctx.openSettings("sync")), true],
          ["external", t("help.downloads_open"), openDownloads],
        ],
      };
    case "import":
      return {
        steps: [t("help.import_1"), t("help.import_2"), t("help.import_3"), t("help.import_4")],
        actions: [["download", t("help.open_import"), ctx.openImport, true]],
      };
    case "recovery":
      return {
        steps: [
          t("help.recovery_1"),
          t("help.recovery_2", { path: path(settings, t("settings.this_vault"), t("recovery.title")) }),
          t("help.recovery_3", { forgot: t("unlock.forgot") }),
          ctx.webdav ? t("help.recovery_4", { forgot: t("signin.forgot") }) : null,
        ],
        note: t("help.recovery_note"),
        actions: [["key", t("help.make_recovery"), ctx.openRecovery, true]],
      };
    case "keys":
      return {
        body: h("div", { class: "col" },
          // This OS's keys (app-keys.js): Cmd on a Mac, plus its Close Window and Quit.
          keyTable(t("help.keys_app"), [
            ...appKeys(isMac()).filter(([id]) => id !== "cancel").map(([id, keys]) => [keyLabel(keys), commandLabel(id)]),
            ["↑ ↓", t("help.key_list")],
            [keyLabel("Esc"), commandLabel("cancel")],
          ]),
          keyTable(t("help.keys_anywhere"), globalKeys(ctx, hotkey)),
          // The browser extension's own keys: a Mac's are its "mac" ones.
          keyTable(t("help.keys_browser"), [
            [keyLabel("Mod+Shift+L"), t("help.key_fill")],
            [keyLabel(isMac() ? "Ctrl+Shift+P" : "Alt+Shift+P"), t("help.key_popup")],
            [keyLabel(isMac() ? "Cmd+Shift+K" : "Alt+Shift+K"), t("help.key_otp")],
          ])),
        note: t("help.keys_note", { page: "chrome://extensions/shortcuts" }),
      };
    default:
      return null;
  }
}

export function openTutorial(id, ctx = {}) {
  const entry = tutorials().find(([key]) => key === id);
  const c = entry && content(id, ctx);
  if (!c) return;
  const [, iconName, title] = entry;
  const m = modal({ label: title, cls: "guide" });
  const actions = (c.actions || [])
    .filter(([, , run]) => typeof run === "function")
    .map(([name, label, run, primary]) => h("button", {
      class: `btn${primary ? " primary" : ""}`,
      type: "button",
      on: { click: () => { m.close(); run(); } },
    }, icon(name), label));
  const close = h("button", { class: "btn", type: "button", text: t("common.close"), on: { click: () => m.close() } });
  mount(m.box,
    h("div", { class: "row" }, h("span", { class: "modal-icon" }, icon(iconName)), h("h2", { class: "grow", text: title })),
    c.intro ? h("p", { text: c.intro }) : null,
    c.body || h("ol", { class: "guide-steps" }, c.steps.filter(Boolean).map((text) => h("li", { text }))),
    c.note ? h("p", { class: "muted", text: c.note }) : null,
    h("div", { class: "row modal-actions wrap" }, actions, h("span", { class: "spacer" }), close));
  (actions[0] || close).focus();
}
