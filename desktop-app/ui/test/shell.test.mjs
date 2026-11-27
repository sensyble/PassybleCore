// node --test Core/desktop-app/ui/test/*.test.mjs (Node 22 or later)
// The window shell: the top bar with the vault's search and New, and the rail. The views need a
// DOM, so these read their source.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const read = (path) => readFileSync(new URL(path, import.meta.url), "utf8");
const vault = read("../views/vault.js");
const titlebar = read("../titlebar.js");
const rail = read("../views/rail.js");
const main = read("../main.js");
const css = read("../styles.css");
const caps = JSON.parse(read("../../src-tauri/capabilities/default.json"));

test("the top bar is over every screen, and the vault puts its search and New in it", () => {
  assert.match(main, /startTitlebar\(\);/);
  assert.match(titlebar, /"data-tauri-drag-region": "deep"/);
  assert.match(vault, /setTitlebarTools\(this\.searchBox, this\.newBtn\);/);
  assert.match(vault, /destroy\(\) \{[\s\S]*?setTitlebarTools\(\);/);
  assert.doesNotMatch(vault, /sidebar-bottom|fitBottomBar|bottomBar/);
});

test("Windows gets the window buttons, a Mac room for its traffic lights", () => {
  assert.match(titlebar, /os === "windows" \? windowButtons\(\) : null/);
  assert.match(titlebar, /os === "macos" \? h\("div", \{ class: "tb-traffic"/);
  for (const glyph of ["\\uE921", "\\uE922", "\\uE923", "\\uE8BB"]) assert.ok(titlebar.includes(glyph), glyph);
  assert.match(css, /\.tb-btn \{[^}]*width: 46px;/);
  assert.match(css, /\.tb-btn\.tb-close:hover \{ background: #c42b1c;/);
  assert.match(css, /:root\.fullscreen \.tb-traffic \{ display: none; \}/);
});

test("the rail has every section, and Lock at its end", () => {
  for (const key of ["home", "favorites", "generator", "health", "trash", "teams", "more", "help", "settings", "sync", "lock"]) {
    assert.match(vault, new RegExp(`\\["${key}", (railButton|this\\.)`), key);
  }
  const order = ["\"home\"", "\"favorites\"", "\"generator\"", "\"health\"", "\"trash\"", "\"teams\"", "\"more\"", "\"help\"", "\"settings\"", "\"sync\"", "\"lock\""]
    .map((k) => vault.search(new RegExp(`\\[${k}, (railButton|this\\.)`)));
  assert.deepEqual([...order].sort((a, b) => a - b), order);
  // Keyboard: one Tab stop, arrows move; the current page is marked for screen readers.
  assert.match(rail, /ArrowDown: i \+ 1, ArrowUp: i - 1, Home: 0, End: shown\.length - 1/);
  assert.match(rail, /setAttribute\("aria-current", "page"\)/);
  assert.match(rail, /role: "tooltip"/);
});

test("the main window may move, resize, minimize, maximize and close itself", () => {
  const main = caps.capabilities.find((c) => c.identifier === "main");
  for (const p of [
    "core:window:allow-start-dragging",
    "core:window:allow-internal-toggle-maximize",
    "core:window:allow-minimize",
    "core:window:allow-toggle-maximize",
    "core:window:allow-close",
    "core:window:allow-is-maximized",
    "core:window:allow-is-fullscreen",
    "allow-window-snap-layouts",
  ]) assert.ok(main.permissions.includes(p), p);
});

test("the app's own shortcuts are written once, with Mod (Cmd on a Mac)", () => {
  for (const file of ["../views/vault.js", "../views/help.js", "../views/editor.js", "../quickaccess.js", "../views/vaults.js"]) {
    const src = read(file).replace(/^\s*\/\/.*$/gm, "");
    assert.doesNotMatch(src, /keyLabel\("Ctrl\+[A-Z,]"\)|withShortcut\([^)]*"Ctrl\+/, file);
    // Ctrl alone is the main modifier on Windows only (modKey / hasMod pick Cmd on a Mac).
    assert.doesNotMatch(src, /e\.ctrlKey \|\| e\.metaKey/, file);
  }
  assert.match(main, /appKeyCommand\(e, isMac\(\)\)/);
  assert.match(main, /listen\("menu-command"/);
  assert.match(vault, /^  command\(name, e = null\) \{/m);
  assert.doesNotMatch(vault, /document\.addEventListener\("keydown", this\.keyHandler\)/);
});
