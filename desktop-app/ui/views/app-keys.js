// The main window's own keys (main.js runs them, Help lists them): the pure part, tested in
// ui/test/shortcuts-model.test.mjs. "Mod" is Cmd on a Mac and Ctrl elsewhere (shortcuts-model.js `withMod`).
// A Mac also has these in its menu bar (src-tauri/src/app_menu.rs) plus Cmd+W/Q/H/M. Windows and Linux have no
// Cmd+W or Cmd+Q: the window's Close button hides it and the tray quits.

import { t } from "../i18n.js";
import { comboParts, hasMod } from "./shortcuts-model.js";

/**
 * Every key in Help's order: `[command, keys]`, `keys` the same on every OS or `{ mac, other }` (null: none).
 * "save" is the editor's, "cancel" every view's own Esc, "quit" the Mac's menu bar; the window runs the rest
 * (`WINDOW_COMMANDS`).
 */
const KEYS = [
  ["search", "Mod+F"],
  ["new", "Mod+N"],
  ["edit", "Mod+E"],
  ["save", "Mod+S"],
  ["settings", "Mod+,"],
  ["lock", "Mod+L"],
  ["lock_full", "Mod+Shift+L"],
  // A Mac keyboard's Delete is Backspace; Finder's Move to Trash is Cmd+Backspace.
  ["trash", { mac: "Mod+Backspace", other: "Delete" }],
  ["close", { mac: "Mod+W", other: null }],
  ["quit", { mac: "Mod+Q", other: null }],
  ["cancel", "Esc"],
];

export const WINDOW_COMMANDS = ["search", "new", "edit", "settings", "lock", "lock_full", "trash", "close"];

export function commandKeys(command, mac) {
  const entry = KEYS.find(([id]) => id === command);
  if (!entry) return null;
  const keys = entry[1];
  return typeof keys === "string" ? keys : (mac ? keys.mac : keys.other) || null;
}

export function appKeys(mac) {
  return KEYS.map(([id]) => [id, commandKeys(id, mac)]).filter(([, keys]) => keys);
}

export function commandLabel(command) {
  return {
    search: t("common.search"),
    new: t("editor.new_item"),
    edit: t("common.edit"),
    save: t("common.save"),
    settings: t("settings.title"),
    lock: t("tray.lock"),
    lock_full: t("tray.lock_completely"),
    trash: t("vault.move_to_trash"),
    close: t("menu.close_window"),
    quit: t("tray.quit"),
    cancel: t("help.key_esc"),
  }[command] || command;
}

/**
 * The key of a keydown as the shortcut strings name it, lower case ("f", ",", "backspace"). A
 * letter by its character, so Dvorak and AZERTY keep their own letters, else by its place on the
 * keyboard (Cyrillic, Greek or Hebrew letters: Ctrl+F is still Ctrl+F).
 */
function keyOf(e) {
  const key = String(e.key || "");
  if (/^[a-z0-9,]$/i.test(key)) return key.toLowerCase();
  const code = String(e.code || "");
  if (/^Key[A-Z]$/.test(code)) return code.slice(3).toLowerCase();
  if (code === "Comma") return ",";
  return key.toLowerCase();
}

/** Whether keydown `e` is `combo` on this OS: its modifiers exactly (never Alt: AltGr and Option type letters). */
function pressed(e, combo, mac) {
  const parts = comboParts(combo).map((part) => part.toLowerCase());
  const key = parts[parts.length - 1];
  if (e.altKey) return false;
  if (parts.includes("mod") ? !hasMod(e, mac) : e.ctrlKey || e.metaKey) return false;
  if (!!e.shiftKey !== parts.includes("shift")) return false;
  return keyOf(e) === (key === "esc" ? "escape" : key);
}

export function isCommandKey(e, command, mac) {
  if (!e || e.isComposing) return false;
  const combo = commandKeys(command, mac);
  return !!combo && pressed(e, combo, mac);
}

export function appKeyCommand(e, mac) {
  return WINDOW_COMMANDS.find((id) => isCommandKey(e, id, mac)) || null;
}
