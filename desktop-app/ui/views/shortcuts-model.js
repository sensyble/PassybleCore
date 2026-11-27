// Settings → Keyboard shortcuts (src-tauri/src/shortcuts.rs is the authority): the pure part, tested in
// ui/test/shortcuts-model.test.mjs. The recorder turns key presses into the English shortcut strings Rust
// parses ("Ctrl+Alt+P"); keyLabel (lib.js) shows them with the key names of the user's language.

import { t } from "../i18n.js";

/** The actions, in the order Settings lists them (shortcuts.rs `Action::ALL`). */
export const ACTIONS = ["quick_access", "scan_qr", "auto_type", "show_app", "lock", "sync_now", "generate_password", "new_note"];

export function actionLabel(id) {
  return {
    quick_access: t("shortcuts.quick_access"),
    scan_qr: t("shortcuts.scan_qr"),
    auto_type: t("shortcuts.auto_type"),
    show_app: t("shortcuts.show_app"),
    lock: t("shortcuts.lock"),
    sync_now: t("shortcuts.sync_now"),
    generate_password: t("shortcuts.generate_password"),
    new_note: t("shortcuts.new_note"),
  }[id] || id;
}

export function actionInfo(id) {
  return {
    quick_access: t("shortcuts.quick_access_info"),
    scan_qr: t("shortcuts.scan_qr_info"),
    auto_type: t("settings.hotkey_info"),
    generate_password: t("shortcuts.generate_password_info"),
    sync_now: t("shortcuts.sync_now_info"),
  }[id] || null;
}

const MODIFIER_KEYS = new Set(["Control", "Alt", "Shift", "Meta", "OS", "AltGraph"]);
const NAMED_CODES = new Set(["Space", "Insert", "Home", "End", "PageUp", "PageDown", "Backquote", "Backslash"]);

/** The key of a keydown as the Rust parser names it ("P", "7", "F5", "Space"), or null. */
function keyName(code) {
  if (/^Key[A-Z]$/.test(code)) return code.slice(3);
  if (/^Digit\d$/.test(code)) return code.slice(5);
  if (/^F\d{1,2}$/.test(code)) return code;
  if (NAMED_CODES.has(code)) return code;
  return null;
}

/** Ctrl, Alt or Win in a shortcut string (Shift alone doesn't count: it types capitals). */
export function hasModifier(combo) {
  return String(combo || "").split("+").some((part) => /^(ctrl|control|alt|option|super|win|cmd|command|meta)$/i.test(part.trim()));
}

/**
 * What a keydown in the recorder means: `{ pending: true }` while only modifiers are held,
 * `{ ignored: true }` for a key shortcuts can't use, `{ combo }` for a shortcut, or
 * `{ combo, error }` when it lacks Ctrl, Alt or Win.
 */
export function recordKey(e) {
  if (MODIFIER_KEYS.has(e.key)) return { pending: true };
  const key = keyName(e.code || "");
  if (!key) return { ignored: true };
  const mods = [];
  if (e.ctrlKey) mods.push("Ctrl");
  if (e.altKey) mods.push("Alt");
  if (e.shiftKey) mods.push("Shift");
  if (e.metaKey) mods.push("Super");
  const combo = [...mods, key].join("+");
  return hasModifier(combo) ? { combo } : { combo, error: t("shortcuts.needs_modifier") };
}

export function comboParts(combo) {
  return String(combo || "").split(/\+(?!$)/).map((part) => part.trim()).filter(Boolean);
}

// What each modifier spelling is: Control, Option (Alt), Shift or Command (Super, Win, Meta). "Mod"
// is the app's own shortcuts' main modifier: Cmd on a Mac, Ctrl elsewhere (`withMod`).
const MODIFIER_ROLES = { ctrl: "ctrl", control: "ctrl", alt: "alt", option: "alt", shift: "shift", super: "cmd", win: "cmd", cmd: "cmd", command: "cmd", meta: "cmd" };
const MAC_MODIFIERS = [["ctrl", "⌃"], ["alt", "⌥"], ["shift", "⇧"], ["cmd", "⌘"]];
// The keys a Mac's menus show as symbols: Delete (Backspace elsewhere) and Forward Delete.
const MAC_KEYS = { Backspace: "⌫", Delete: "⌦" };

export function withMod(combo, mac) {
  return comboParts(combo).map((part) => (part.toLowerCase() === "mod" ? (mac ? "Cmd" : "Ctrl") : part)).join("+");
}

/** A shortcut as a Mac shows it ("Mod+Shift+L" is ⇧⌘L); `name` gives a named key's word in the user's language. */
export function macKeyLabel(combo, name = (key) => key) {
  const mods = new Set();
  const keys = [];
  for (const part of comboParts(withMod(combo, true))) {
    const role = MODIFIER_ROLES[part.toLowerCase()];
    if (role) mods.add(role);
    else keys.push(Object.hasOwn(MAC_KEYS, part) ? MAC_KEYS[part] : name(part));
  }
  return MAC_MODIFIERS.filter(([role]) => mods.has(role)).map(([, symbol]) => symbol).join("") + keys.join(" ");
}

export function hasMod(e, mac) {
  return mac ? !!e.metaKey && !e.ctrlKey : !!e.ctrlKey && !e.metaKey;
}

/** A shortcut's identity, whatever the spelling or order: "alt+ctrl+P" and "Ctrl+Alt+p" are one. */
export function comboKey(combo) {
  const parts = String(combo || "").split("+").map((p) => p.trim()).filter(Boolean);
  if (!parts.length) return "";
  const names = { ctrl: "ctrl", control: "ctrl", alt: "alt", option: "alt", shift: "shift", super: "super", win: "super", cmd: "super", command: "super", meta: "super" };
  const mods = new Set();
  let key = "";
  for (const part of parts) {
    const mod = names[part.toLowerCase()];
    if (mod) mods.add(mod);
    else key = part.toUpperCase().replace(/^KEY([A-Z])$/, "$1").replace(/^DIGIT(\d)$/, "$1");
  }
  return [...[...mods].sort(), key].join("+");
}

/**
 * Why `combo` can't be the shortcut of action `id`, or null. `actions`: `shortcuts_state`'s list
 * (`{ id, keys, supported }`). Rust checks again (and whether Windows lets Passyble have it).
 */
export function shortcutProblem(actions, id, combo) {
  if (!hasModifier(combo)) return t("shortcuts.needs_modifier");
  const wanted = comboKey(combo);
  const other = (actions || []).find((a) => a.id !== id && a.supported !== false && a.keys && comboKey(a.keys) === wanted);
  return other ? t("shortcuts.duplicate", { action: actionLabel(other.id) }) : null;
}

export function canReset(action) {
  return comboKey(action.keys || "") !== comboKey(action.default || "");
}
