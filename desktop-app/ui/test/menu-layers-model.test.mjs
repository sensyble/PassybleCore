// node --test Core/desktop-app/ui/test/*.test.mjs
// The vault switcher's row menu opens over the switcher: what a press or Escape closes.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { escapeCloses, pressCloses } from "../views/menu-layers-model.js";

test("a press outside both menus closes both; with no row menu it closes the switcher", () => {
  assert.equal(pressCloses({ inMenu: false, inSub: false, hasSub: true }), "all");
  assert.equal(pressCloses({ inMenu: false, inSub: false, hasSub: false }), "menu");
});

test("a press inside the row menu closes nothing", () => {
  assert.equal(pressCloses({ inMenu: false, inSub: true, hasSub: true }), "none");
});

test("a press on the switcher closes only the row menu above it", () => {
  assert.equal(pressCloses({ inMenu: true, inSub: false, hasSub: true }), "sub");
  assert.equal(pressCloses({ inMenu: true, inSub: false, hasSub: false }), "none");
});

test("Escape closes the row menu first, then the switcher", () => {
  assert.equal(escapeCloses(true), "sub");
  assert.equal(escapeCloses(false), "menu");
});

test("a vault's row menu opens as a layer over the switcher instead of replacing it", () => {
  const src = readFileSync(new URL("../views/vault.js", import.meta.url), "utf8");
  assert.match(src, /\{ sub: true, opener \}/);
  assert.match(src, /if \(sub\) this\.closeSubMenu\(\); else this\.closeItemMenu\(false\);/);
});
