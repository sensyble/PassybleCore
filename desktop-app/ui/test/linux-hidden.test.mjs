// node --test Core/desktop-app/ui/test/*.test.mjs (Node 22 or later)
// What the Linux and macOS builds leave out of the UI, and the otpauth Settings row there.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { hiddenOn, LINUX_HIDDEN, MACOS_HIDDEN } from "../linux-hidden.js";
import { handlerRow } from "../views/otpauth-model.js";

const en = JSON.parse(readFileSync(new URL("../i18n/en.json", import.meta.url), "utf8"));

test("Linux hides exactly this list", () => {
  assert.deepEqual([...LINUX_HIDDEN], [
    "settings.windows_hello",
    "settings.ask_master",
    "settings.more_security",
    "settings.windows_passkeys",
    "settings.hotkey",
    "settings.otpauth_open_windows",
    "help.autotype_title",
    "help.keys_windows",
    "help.passkeys_4",
    "editor.urls_pin_hint",
  ]);
  assert.ok(Object.isFrozen(LINUX_HIDDEN));
  for (const key of LINUX_HIDDEN) {
    assert.ok(key in en, `${key} is not in en.json`);
    assert.equal(hiddenOn("linux", key), true);
  }
});

test("Windows and an unknown platform hide nothing", () => {
  for (const platform of ["windows", "", undefined, null]) {
    for (const key of [...LINUX_HIDDEN, ...MACOS_HIDDEN]) assert.equal(hiddenOn(platform, key), false, `${platform}: ${key}`);
  }
});

test("macOS hides only the Windows passkey provider", () => {
  assert.deepEqual([...MACOS_HIDDEN], ["settings.windows_passkeys", "help.passkeys_4"]);
  assert.ok(Object.isFrozen(MACOS_HIDDEN));
  for (const key of LINUX_HIDDEN) {
    assert.equal(hiddenOn("macos", key), MACOS_HIDDEN.includes(key), key);
  }
  for (const key of MACOS_HIDDEN) assert.ok(key in en, `${key} is not in en.json`);
});

test("Linux keeps the rows that work there", () => {
  for (const key of ["settings.auto_lock", "settings.keep_list", "settings.extension", "aitools.title", "settings.otpauth_title", "support.title", "help.passkeys_3", "editor.add_website"]) {
    assert.equal(hiddenOn("linux", key), false, key);
  }
});

test("the otpauth row never offers Windows settings on Linux", () => {
  for (const handler of ["this", "none", "other"]) {
    for (const claimed of [false, true]) assert.notEqual(handlerRow(handler, claimed, "linux").action, "windows");
  }
  // Another app still wins after a claim: the claim is offered again, with no Windows wording.
  const row = handlerRow("other", true, "linux");
  assert.equal(row.action, "claim");
  assert.equal(row.value, handlerRow("other", false, "linux").value);
  assert.equal(handlerRow("this", true, "linux").action, null);
});

test("the otpauth row on Windows and macOS is unchanged", () => {
  for (const platform of ["windows", "macos", ""]) {
    assert.equal(handlerRow("other", true, platform).action, "windows");
    assert.deepEqual(handlerRow("other", true, platform), handlerRow("other", true));
    assert.deepEqual(handlerRow("none", false, platform), handlerRow("none"));
  }
});
