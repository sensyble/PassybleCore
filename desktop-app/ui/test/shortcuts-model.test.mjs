// node --test Core/desktop-app/ui/test/*.test.mjs (Node 22 or later)
// Settings → Keyboard shortcuts, the main window's own keys and a Mac's menu bar, Quick Access and
// the screen QR scan's window.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { appKeyCommand, appKeys, commandKeys, commandLabel, WINDOW_COMMANDS } from "../views/app-keys.js";
import { ACTIONS, actionLabel, canReset, comboKey, comboParts, hasMod, hasModifier, macKeyLabel, recordKey, shortcutProblem, withMod } from "../views/shortcuts-model.js";
import { MAX_ROWS, quickAccessKey, quickAccessRows } from "../views/quickaccess-model.js";
import { codeRows, firstStep, pickableLogins, qrscanTitle } from "../views/qrscan-model.js";

const key = (code, mods = {}, keyName = "x") => ({ code, key: keyName, ctrlKey: false, altKey: false, shiftKey: false, metaKey: false, ...mods });

test("the recorder turns key presses into shortcut strings", () => {
  assert.deepEqual(recordKey(key("KeyP", { ctrlKey: true, altKey: true })), { combo: "Ctrl+Alt+P" });
  assert.deepEqual(recordKey(key("Space", { ctrlKey: true, shiftKey: true })), { combo: "Ctrl+Shift+Space" });
  assert.deepEqual(recordKey(key("Digit7", { metaKey: true })), { combo: "Super+7" });
  assert.deepEqual(recordKey(key("F9", { altKey: true })), { combo: "Alt+F9" });
  assert.deepEqual(recordKey(key("ControlLeft", { ctrlKey: true }, "Control")), { pending: true });
  assert.deepEqual(recordKey(key("ArrowUp", { ctrlKey: true })), { ignored: true });
  // No Ctrl, Alt or Win: refused with a reason.
  for (const e of [key("KeyP"), key("KeyP", { shiftKey: true }), key("F5")]) {
    const r = recordKey(e);
    assert.ok(r.error, JSON.stringify(r));
  }
});

test("a shortcut needs Ctrl, Alt or Win, and its spelling doesn't matter", () => {
  assert.ok(hasModifier("Ctrl+P"));
  assert.ok(hasModifier("Super+Space"));
  assert.ok(!hasModifier("Shift+P"));
  assert.ok(!hasModifier("P"));
  assert.equal(comboKey("alt+ctrl+p"), comboKey("Ctrl+Alt+P"));
  assert.equal(comboKey("Control+Shift+Space"), comboKey("Ctrl+Shift+Space"));
  assert.notEqual(comboKey("Ctrl+Alt+P"), comboKey("Ctrl+Shift+P"));
  assert.equal(comboKey(""), "");
});

test("the app's own shortcuts use Cmd on a Mac and Ctrl elsewhere", () => {
  assert.equal(withMod("Mod+F", false), "Ctrl+F");
  assert.equal(withMod("Mod+Shift+L", true), "Cmd+Shift+L");
  assert.equal(withMod("Ctrl+Alt+P", true), "Ctrl+Alt+P");
  assert.deepEqual(comboParts("Ctrl++"), ["Ctrl", "+"]);
  // Keydowns: Cmd on a Mac (Control there is its own key), Ctrl elsewhere.
  assert.ok(hasMod(key("KeyF", { metaKey: true }), true));
  assert.ok(!hasMod(key("KeyF", { ctrlKey: true }), true));
  assert.ok(hasMod(key("KeyF", { ctrlKey: true }), false));
  assert.ok(!hasMod(key("KeyF", { metaKey: true }), false));
  assert.ok(!hasMod(key("KeyF", { ctrlKey: true, metaKey: true }), true));
});

test("a Mac shows shortcuts with Apple's symbols, in Apple's order", () => {
  assert.equal(macKeyLabel("Mod+F"), "⌘F");
  assert.equal(macKeyLabel("Mod+Shift+L"), "⇧⌘L");
  assert.equal(macKeyLabel("Cmd+Shift+Space", (k) => (k === "Space" ? "Space" : k)), "⇧⌘Space");
  // Every spelling of each modifier, in any order.
  assert.equal(macKeyLabel("Shift+Super+Alt+Ctrl+Q"), "⌃⌥⇧⌘Q");
  assert.equal(macKeyLabel("Ctrl+Cmd+P"), "⌃⌘P");
  assert.equal(macKeyLabel("Control+Option+Shift+Q"), "⌃⌥⇧Q");
  assert.equal(macKeyLabel("Win+Meta+Command+K"), "⌘K");
  assert.equal(macKeyLabel("Mod+,"), "⌘,");
  assert.equal(macKeyLabel("Esc", () => "Esc"), "Esc");
});

test("two actions can't share a shortcut", () => {
  const actions = [
    { id: "quick_access", keys: "Ctrl+Shift+Space", default: "Ctrl+Shift+Space", supported: true },
    { id: "scan_qr", keys: "Ctrl+Alt+Shift+Q", default: "Ctrl+Alt+Shift+Q", supported: false },
    { id: "auto_type", keys: "Ctrl+Alt+P", default: "Ctrl+Alt+P", supported: true },
    { id: "lock", keys: null, default: null, supported: true },
  ];
  assert.match(shortcutProblem(actions, "lock", "Alt+Ctrl+P"), new RegExp(actionLabel("auto_type")));
  assert.equal(shortcutProblem(actions, "quick_access", "Ctrl+Shift+Space"), null);
  assert.equal(shortcutProblem(actions, "lock", "Ctrl+Alt+L"), null);
  assert.equal(shortcutProblem(actions, "lock", "Ctrl+Alt+Shift+Q"), null);
  assert.ok(shortcutProblem(actions, "lock", "Shift+L"));
  assert.ok(canReset({ keys: "Ctrl+Alt+K", default: "Ctrl+Alt+P" }));
  assert.ok(!canReset({ keys: "alt+ctrl+p", default: "Ctrl+Alt+P" }));
  assert.ok(!canReset({ keys: null, default: null }));
  assert.ok(canReset({ keys: null, default: "Ctrl+Alt+P" }));
});

test("every action has a name", () => {
  for (const id of ACTIONS) assert.notEqual(actionLabel(id), id, id);
});

test("Quick Access keys", () => {
  assert.equal(quickAccessKey(key("Enter", {}, "Enter")), "enter");
  assert.equal(quickAccessKey(key("Enter", { shiftKey: true }, "Enter")), "open");
  assert.equal(quickAccessKey(key("KeyO", { ctrlKey: true }, "o")), "open");
  assert.equal(quickAccessKey(key("KeyC", { ctrlKey: true }, "c")), "username");
  assert.equal(quickAccessKey(key("KeyC", { ctrlKey: true, shiftKey: true }, "C")), "code");
  // AltGr (Ctrl+Alt) types a letter on some layouts: never a copy.
  assert.equal(quickAccessKey(key("KeyC", { ctrlKey: true, altKey: true }, "ć")), null);
  assert.equal(quickAccessKey(key("ArrowDown", {}, "ArrowDown")), "down");
  assert.equal(quickAccessKey(key("ArrowUp", {}, "ArrowUp")), "up");
  assert.equal(quickAccessKey(key("KeyC", {}, "c")), null);
  assert.equal(quickAccessKey(key("KeyC", { metaKey: true }, "c")), null);
});

test("Quick Access keys on a Mac use Cmd", () => {
  const mac = (e) => quickAccessKey(e, true);
  assert.equal(mac(key("KeyC", { metaKey: true }, "c")), "username");
  assert.equal(mac(key("KeyC", { metaKey: true, shiftKey: true }, "C")), "code");
  assert.equal(mac(key("KeyO", { metaKey: true }, "o")), "open");
  assert.equal(mac(key("Enter", { metaKey: true }, "Enter")), "open");
  // Control+C on a Mac is not Copy.
  assert.equal(mac(key("KeyC", { ctrlKey: true }, "c")), null);
  assert.equal(mac(key("KeyC", { metaKey: true, altKey: true }, "ç")), null);
});

const press = (code, mods = {}, name) => key(code, mods, name ?? (code.startsWith("Key") ? code.slice(3).toLowerCase() : code));

test("the window's keys on Windows and Linux: Ctrl", () => {
  const win = (e) => appKeyCommand(e, false);
  assert.equal(win(press("KeyF", { ctrlKey: true })), "search");
  assert.equal(win(press("KeyN", { ctrlKey: true })), "new");
  assert.equal(win(press("KeyE", { ctrlKey: true })), "edit");
  assert.equal(win(press("Comma", { ctrlKey: true }, ",")), "settings");
  assert.equal(win(press("KeyL", { ctrlKey: true })), "lock");
  assert.equal(win(press("KeyL", { ctrlKey: true, shiftKey: true }, "L")), "lock_full");
  assert.equal(win(press("Delete", {}, "Delete")), "trash");
  // Cmd (Win) is Windows' own, and Close Window is a Mac's.
  assert.equal(win(press("KeyF", { metaKey: true })), null);
  assert.equal(win(press("KeyW", { ctrlKey: true })), null);
  assert.equal(win(press("Backspace", { ctrlKey: true }, "Backspace")), null);
  // Modifiers must match: AltGr (Ctrl+Alt) types letters, Ctrl+Shift+F is something else.
  assert.equal(win(press("KeyF", { ctrlKey: true, altKey: true })), null);
  assert.equal(win(press("KeyF", { ctrlKey: true, shiftKey: true }, "F")), null);
  assert.equal(win(press("KeyF")), null);
  assert.equal(win(press("Delete", { shiftKey: true }, "Delete")), null);
  assert.equal(win(press("KeyS", { ctrlKey: true })), null);
  assert.equal(win(press("Escape", {}, "Escape")), null);
});

test("the window's keys on a Mac: Cmd, Control stays Control", () => {
  const mac = (e) => appKeyCommand(e, true);
  assert.equal(mac(press("KeyF", { metaKey: true })), "search");
  assert.equal(mac(press("KeyN", { metaKey: true })), "new");
  assert.equal(mac(press("KeyE", { metaKey: true })), "edit");
  assert.equal(mac(press("Comma", { metaKey: true }, ",")), "settings");
  assert.equal(mac(press("KeyL", { metaKey: true })), "lock");
  assert.equal(mac(press("KeyL", { metaKey: true, shiftKey: true }, "L")), "lock_full");
  assert.equal(mac(press("Backspace", { metaKey: true }, "Backspace")), "trash");
  assert.equal(mac(press("KeyW", { metaKey: true })), "close");
  // Control+F, Control+N are not the app's on a Mac (Control+N moves down in a text field).
  assert.equal(mac(press("KeyF", { ctrlKey: true })), null);
  assert.equal(mac(press("KeyN", { ctrlKey: true })), null);
  assert.equal(mac(press("KeyF", { ctrlKey: true, metaKey: true })), null);
  // Backspace alone deletes a character; Forward Delete isn't Move to Trash here.
  assert.equal(mac(press("Backspace", {}, "Backspace")), null);
  assert.equal(mac(press("Delete", {}, "Delete")), null);
  assert.equal(mac(press("KeyQ", { metaKey: true })), null);
  assert.equal(mac(press("KeyH", { metaKey: true })), null);
  assert.equal(mac(press("KeyM", { metaKey: true })), null);
  assert.equal(mac(press("KeyF", { metaKey: true, altKey: true }, "ƒ")), null);
  // Typing in an input method (Japanese, Chinese) is never a shortcut.
  assert.equal(mac({ ...press("KeyF", { metaKey: true }), isComposing: true }), null);
});

test("the window's keys work with other keyboard layouts", () => {
  assert.equal(appKeyCommand(press("KeyF", { ctrlKey: true }, "а"), false), "search");
  assert.equal(appKeyCommand(press("KeyL", { metaKey: true, shiftKey: true }, "Д"), true), "lock_full");
  // Dvorak: the letter, not the place (Dvorak's F is on QWERTY's Y).
  assert.equal(appKeyCommand(press("KeyY", { ctrlKey: true }, "f"), false), "search");
  assert.equal(appKeyCommand(press("KeyF", { ctrlKey: true }, "u"), false), null);
});

test("Help lists each OS's keys", () => {
  const win = new Map(appKeys(false));
  const mac = new Map(appKeys(true));
  assert.equal(win.get("search"), "Mod+F");
  assert.equal(win.get("trash"), "Delete");
  assert.equal(win.has("close"), false);
  assert.equal(win.has("quit"), false);
  assert.equal(mac.get("trash"), "Mod+Backspace");
  assert.equal(mac.get("close"), "Mod+W");
  assert.equal(mac.get("quit"), "Mod+Q");
  assert.equal(mac.get("save"), "Mod+S");
  assert.equal(macKeyLabel(mac.get("trash")), "⌘⌫");
  assert.equal(macKeyLabel("Mod+Shift+L"), "⇧⌘L");
  for (const [id] of appKeys(true)) assert.notEqual(commandLabel(id), id, id);
  for (const id of WINDOW_COMMANDS) assert.ok(win.has(id) || mac.has(id), id);
});

test("a Mac's menu bar has the window's keys (src-tauri/src/app_menu.rs)", () => {
  const rust = readFileSync(new URL("../../src-tauri/src/app_menu.rs", import.meta.url), "utf8");
  const commands = [...rust.matchAll(/Command \{\s*id: "menu\.([a-z_]+)",\s*label: "[a-z_.]+",\s*keys: (?:Some\("([^"]+)"\)|None),?\s*\}/g)];
  assert.ok(commands.length >= 9, "the menu's commands");
  for (const [, id, keys] of commands) {
    const window = commandKeys(id, true);
    assert.equal(keys ? keys : null, window ? withMod(window, true) : null, id);
  }
});

test("Quick Access lists the most used first while the box is empty", () => {
  const items = [
    { id: "a", title: "Beta", rank: 0 },
    { id: "b", title: "Alpha", rank: 0 },
    { id: "c", title: "Zed", rank: 9 },
    { id: "d", title: "Gone", rank: 99, trashed_at: 1 },
  ];
  assert.deepEqual(quickAccessRows(items, "").map((i) => i.id), ["c", "b", "a"]);
  assert.deepEqual(quickAccessRows(items, "x").map((i) => i.id), ["a", "b", "c"]);
  const many = Array.from({ length: 80 }, (_, i) => ({ id: String(i), title: String(i) }));
  assert.equal(quickAccessRows(many, "").length, MAX_ROWS);
});

test("the QR scan window says what it found", () => {
  assert.match(qrscanTitle({ issuer: "GitHub", account: "alice" }), /GitHub \(alice\)/);
  assert.match(qrscanTitle({ issuer: null, account: "alice" }), /alice/);
  assert.ok(qrscanTitle({}).length > 0);
  const one = { index: 0, issuer: "GitHub", account: "alice" };
  assert.equal(firstStep({ error: "x", codes: [] }), "error");
  assert.equal(firstStep({ codes: [], vault: true }), "none");
  assert.equal(firstStep({ codes: [one], vault: false }), "no_vault");
  assert.equal(firstStep({ codes: [one], vault: true }), "review");
  assert.equal(firstStep({ codes: [one, { ...one, index: 1 }], vault: true }), "pick");
  assert.equal(firstStep({ codes: [], migration: true, vault: true }), "migration");
  assert.equal(firstStep(null), "none");
  const rows = codeRows([one, { index: 1, issuer: null, account: "bob" }]);
  assert.deepEqual(rows[0], { index: 0, title: "GitHub", detail: "alice" });
  assert.deepEqual(rows[1], { index: 1, title: "bob", detail: "" });
});

test("only logins the user may change can take a scanned code", () => {
  const items = [
    { id: "a", kind: "login" },
    { id: "b", kind: "note" },
    { id: "c", kind: "login", vault: { can_edit: false } },
    { id: "d", kind: "login", vault: { can_edit: true } },
    { id: "e", kind: "login" },
  ];
  assert.deepEqual(pickableLogins(items, ["e"]).map((i) => i.id), ["a", "d"]);
});
