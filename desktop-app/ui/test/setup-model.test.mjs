// node --test Core/desktop-app/ui/test/*.test.mjs (Node 22 or later)
// The guided setup: which steps a computer gets and in what order, Continue, Skip for now and Back,
// resuming, what counts as done, and how the start page, the vault view's Windows Hello offer and
// Settings' auto-lock row are wired in.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  browserRows,
  browserToAdd,
  connectedHere,
  DONE,
  EXTRAS,
  firstStep,
  nextStep,
  previousStep,
  recoveryAction,
  resumeStep,
  setupExtras,
  setupSteps,
  stepDone,
  stepLabel,
  stepPosition,
  STEPS,
  syncAction,
  syncChoices,
} from "../views/setup-model.js";

const read = (path) => readFileSync(new URL(path, import.meta.url), "utf8");
const newVault = { sync: true, synced: false, account: false };
const windows11 = { platform: "windows", passkeys: true, shortcuts: true };

test("three steps at most: browser, sync, recovery", () => {
  assert.deepEqual(STEPS, ["browser", "sync", "recovery"]);
  assert.deepEqual(setupSteps(newVault), STEPS);
  assert.deepEqual(setupSteps({}), STEPS);
  for (const dropped of ["vault", "password", "unlock", "auto_lock", "passkeys", "shortcuts", "import"]) {
    assert.ok(!STEPS.includes(dropped), dropped);
  }
});

test("sync is left out when it doesn't apply, and the others are renumbered", () => {
  assert.deepEqual(setupSteps({ ...newVault, synced: true }), ["browser", "recovery"]);
  assert.deepEqual(setupSteps({ ...newVault, account: true }), ["browser", "recovery"]);
  assert.deepEqual(setupSteps({ ...newVault, sync: false }), ["browser", "recovery"]);
  const two = setupSteps({ ...newVault, account: true });
  assert.deepEqual(stepPosition(two, "browser"), { number: 1, total: 2 });
  assert.deepEqual(stepPosition(two, "recovery"), { number: 2, total: 2 });
});

test("the start page and You're set aren't steps: not counted, no indicator", () => {
  const steps = setupSteps(newVault);
  assert.deepEqual(stepPosition(steps, "browser"), { number: 1, total: 3 });
  assert.deepEqual(stepPosition(steps, "sync"), { number: 2, total: 3 });
  assert.deepEqual(stepPosition(steps, "recovery"), { number: 3, total: 3 });
  assert.equal(stepPosition(steps, DONE), null);
  assert.equal(stepPosition(steps, "extra:import"), null);
  for (const id of STEPS) assert.ok(stepLabel(id), id);
  assert.equal(stepLabel("recovery"), "Recovery");
  const setup = read("../views/setup.js");
  assert.match(setup, /const position = stepPosition\(steps, current\);\s+if \(!position\) return null;/);
  assert.doesNotMatch(read("../views/onboarding.js"), /stepIndicator|indicator\(/);
});

test("Continue and Skip for now go to the next step, then You're set; Back never leaves the steps", () => {
  const steps = setupSteps(newVault);
  assert.equal(firstStep(steps), "browser");
  assert.equal(nextStep(steps, "browser"), "sync");
  assert.equal(nextStep(steps, "recovery"), DONE);
  assert.equal(nextStep(steps, DONE), null);
  assert.equal(nextStep(steps, "nope"), null);
  assert.equal(previousStep(steps, "sync"), "browser");
  assert.equal(previousStep(steps, "browser"), null);
  assert.equal(previousStep(steps, DONE), "recovery");
  // No step applies: straight to You're set.
  assert.equal(firstStep([]), DONE);
  assert.equal(previousStep([], DONE), null);
  const seen = [];
  for (let at = firstStep(steps); at; at = nextStep(steps, at)) seen.push(at);
  assert.deepEqual(seen, [...steps, DONE]);
});

test("a saved setup resumes where it stopped", () => {
  const steps = setupSteps(newVault);
  assert.equal(resumeStep(steps, "sync"), "sync");
  assert.equal(resumeStep(steps, DONE), DONE);
  // Nothing saved yet (the first vault was just added) or an unknown id: the first step.
  for (const saved of [null, undefined, "", "nope"]) assert.equal(resumeStep(steps, saved), "browser", String(saved));
  assert.equal(resumeStep(setupSteps({ ...newVault, synced: true }), "sync"), "recovery");
});

test("a setup saved by the 11-step version goes on at the next step there is", () => {
  const steps = setupSteps(newVault);
  const moved = {
    vault: "browser",
    password: "browser",
    unlock: "browser",
    auto_lock: "browser",
    browser: "browser",
    passkeys: "sync",
    shortcuts: "sync",
    sync: "sync",
    import: "recovery",
    recovery: "recovery",
    done: DONE,
  };
  for (const [saved, to] of Object.entries(moved)) assert.equal(resumeStep(steps, saved), to, saved);
  const noSync = setupSteps({ ...newVault, account: true });
  assert.equal(resumeStep(noSync, "passkeys"), "recovery");
  assert.equal(resumeStep(noSync, "sync"), "recovery");
  assert.match(read("../../src-tauri/src/settings.rs"), /pub fn at\(step: &str, paused: bool\) -> Self/);
});

test("You're set offers import, Windows passkeys (Windows 11) and the shortcut as links, not steps", () => {
  assert.deepEqual(EXTRAS, ["import", "passkeys", "shortcuts"]);
  assert.deepEqual(setupExtras(windows11), ["import", "passkeys", "shortcuts"]);
  // A Mac, Windows 10 and Linux have no Windows passkey provider.
  assert.deepEqual(setupExtras({ ...windows11, platform: "macos" }), ["import", "shortcuts"]);
  assert.deepEqual(setupExtras({ ...windows11, passkeys: false }), ["import", "shortcuts"]);
  assert.deepEqual(setupExtras({ platform: "linux", shortcuts: false }), ["import"]);
  const setup = read("../views/setup.js");
  // A link isn't saved as progress: closing it there resumes at You're set.
  assert.match(setup, /this\.step = `extra:\$\{id\}`;/);
  assert.match(setup, /const step = this\.step\.startsWith\("extra:"\) \? DONE : this\.step;/);
});

test("what counts as done", () => {
  const none = {};
  assert.ok(!stepDone("browser", none) && !stepDone("sync", none) && !stepDone("recovery", none));
  assert.ok(!stepDone("recovery", { recovery: false }));
  assert.ok(stepDone("browser", { browser: true }));
  assert.ok(stepDone("sync", { sync: "google" }));
  assert.ok(stepDone("recovery", { recovery: true }));
  assert.ok(!stepDone(DONE, none));
});

test("the browser step lists the browsers here, the default one first", () => {
  const browsers = [
    { id: "chrome", installed: true },
    { id: "edge", installed: true, default: true },
    { id: "brave", installed: false },
    { id: "firefox", installed: true },
  ];
  assert.deepEqual(browserRows(browsers).map((b) => b.id), ["edge", "chrome", "firefox"]);
  // None found: the main three, to open their store pages anyway.
  assert.deepEqual(browserRows(browsers.map((b) => ({ ...b, installed: false, default: false }))).map((b) => b.id), ["chrome", "edge", "firefox"]);
  assert.deepEqual(browserRows(), []);
  // Windows sees Opera GX as Opera and Chromium as Chrome (the same program).
  assert.ok(connectedHere("edge", "edge"));
  assert.ok(!connectedHere("edge", "chrome"));
  assert.ok(!connectedHere("edge", null));
  assert.ok(connectedHere("opera-gx", "opera", ["opera-gx"]));
  assert.ok(!connectedHere("opera-gx", "opera", ["opera", "opera-gx"]));
  assert.ok(connectedHere("chromium", "chrome", ["chromium"]));
});

test("the main button does what it says: add to the default browser, until one is connected", () => {
  const rows = browserRows([
    { id: "chrome", name: "Google Chrome", installed: true },
    { id: "edge", name: "Microsoft Edge", installed: true, default: true },
  ]);
  assert.equal(browserToAdd(rows, null).id, "edge");
  assert.equal(browserToAdd(rows, "chrome"), null);
  assert.equal(browserToAdd([], null), null);
  const setup = read("../views/setup.js");
  assert.match(setup, /this\.setAction\(add \? \{ text: t\("setup\.browser_add", \{ browser: add\.name \}\), run: \(\) => store\(add\) \} : null\);/);
  // Skip for now stays the second button: the main one is Continue once nothing is left to do.
  assert.match(setup, /on: \{ click: \(\) => \(this\.action \? this\.action\.run\(\) : this\.next\(\)\) \}/);
});

test("sync: Google Drive recommended and chosen where it can be set up, the rare ways under More options", () => {
  assert.deepEqual(syncChoices({ google: true, server: true }), {
    shown: ["google", "local"], more: ["account", "server", "webdav"], selected: "google", recommended: "google",
  });
  // No Google Drive here: every way in a row, "Only on this device" chosen, nothing recommended.
  assert.deepEqual(syncChoices({ google: false, server: true }), {
    shown: ["local", "account", "server", "webdav"], more: [], selected: "local", recommended: null,
  });
  // No Passyble Server or WebDAV in this build.
  assert.deepEqual(syncChoices({ google: true, server: false }).more, ["account"]);
  const en = JSON.parse(read("../i18n/en.json"));
  const said = Object.fromEntries(["google", "account", "server", "webdav", "local"].map((id) => [id, en[syncAction(id)]]));
  assert.deepEqual(said, { google: "Turn on sync", account: "Sign in", server: "Connect", webdav: "Open Settings", local: "Keep on this device" });
});

test("recovery: the main button saves the code or the kit until there is one", () => {
  assert.equal(recoveryAction({ made: false }), "code");
  assert.equal(recoveryAction({ made: true }), null);
  assert.equal(recoveryAction({ linked: true }), "kit");
  assert.equal(recoveryAction({ linked: true, kitShown: true }), null);
  const en = JSON.parse(read("../i18n/en.json"));
  assert.equal(en["setup.recovery_action"], "Save recovery code");
  assert.equal(en["setup.kit_action"], "Save Emergency Kit");
});

test("short copy: a short title and at most one short line per screen, short hints", () => {
  const en = JSON.parse(read("../i18n/en.json"));
  const titles = ["onboarding.welcome", "onboarding.tile_create", "onboarding.tile_open", "onboarding.tile_account", "onboarding.choose_password",
    "start.browser", "setup.sync_title", "start.recovery", "setup.kit_title", "setup.done_title"];
  for (const key of titles) assert.ok(en[key].split(" ").length <= 5, key);
  const lines = ["onboarding.welcome_text", "onboarding.open_text", "onboarding.choose_password_text", "start.browser_text", "setup.sync_text",
    "start.recovery_text", "setup.kit_text", "setup.done_text"];
  const hints = ["onboarding.tile_create_text", "onboarding.tile_open_text", "onboarding.tile_account_text", "onboarding.open_file_text",
    "onboarding.server_text", "onboarding.google_restore_text", "onboarding.webdav_text", "onboarding.pairing_text", "onboarding.account_browser_text",
    "onboarding.account_device_text", "onboarding.create_linked_text", "onboarding.google_backup_hint", "onboarding.password_hint",
    "local_reminder.create_notice", "setup.browser_hint", "setup.sync_local_hint", "setup.sync_account_hint", "setup.sync_server_hint",
    "setup.import_hint", "setup.passkeys_link_text", "setup.shortcuts_link_text"];
  for (const key of lines) assert.ok(en[key].length <= 60, `${key}: ${en[key].length}`);
  for (const key of hints) assert.ok(en[key].length <= 48, `${key}: ${en[key].length}`);
  // The explanations are behind "Why?", not on the screen.
  assert.match(read("../views/onboarding.js"), /whyNote\(t\("onboarding\.icons_line"\), t\("onboarding\.icons_why", \{ path: iconsPath \}\)\)/);
});

test("recovery: the vault's recovery code, or the Emergency Kit for a vault on the Passyble password", () => {
  const setup = read("../views/setup.js");
  assert.match(setup, /if \(this\.s\.linked_account\) \{/);
  assert.match(setup, /withAccountKey\(\(password\) => invoke\("account_kit", \{ password \}\)\)/);
  assert.match(setup, /openCreateRecoveryDialog\(\{\s+askPassword: false,/);
});

test("the start page: create, open, or sign in with the Passyble account", () => {
  const onboarding = read("../views/onboarding.js");
  assert.match(onboarding, /big\("plus", t\("onboarding\.tile_create"\)/);
  assert.match(onboarding, /big\("folder", t\("onboarding\.tile_open"\), t\("onboarding\.tile_open_text"\), \(\) => this\.openChoices\(\)\)/);
  assert.match(onboarding, /big\("user", t\("onboarding\.tile_account"\), t\("onboarding\.tile_account_text"\), \(\) => this\.account\(\)\)/);
  // Open: a file, Passyble Server, Google Drive; WebDAV and a pairing link under More options.
  for (const flow of ["this.open()", "this.signin()", "this.googleRestore()", "this.webdav()", "this.server()"]) {
    assert.ok(onboarding.includes(`() => ${flow})`), flow);
  }
  // The account: the existing sign-in (browser) and device approval with six digits; no new auth.
  assert.match(onboarding, /await invoke\("account_sign_in"\)/);
  assert.match(onboarding, /openNewDeviceDialog\(\{ onDone: \(\) => this\.account\(\) \}\)/);
  assert.match(onboarding, /invoke\("account_keys_status"\)/);
  // The vault password is part of Create: the core's live rule, blocked until it passes,
  // repeated, a passphrase suggestion and a strength bar.
  assert.match(onboarding, /masterPasswordMeter\(pw\.input, \{ names: \(\) => \[name\.value\(\)\], onResult: showStrength \}\)/);
  assert.match(onboarding, /await rule\.ensure\(\);\s+if \(pw\.input\.value !== pw2\.input\.value\)/);
  assert.match(onboarding, /passphrase: true, words: 6, separator: " "/);
  // The first vault gets its recovery code in the setup, not right after creating it.
  assert.match(onboarding, /if \(this\.firstRun\) return;\s+\/\/ Skippable[^\n]*\n[^\n]*\n\s+offerRecoveryCode/);
});

test("Windows Hello and auto-lock aren't steps: the vault view's offer and Settings' row", () => {
  // The "next time?" offer comes after the first vault is created or opened too.
  const commands = read("../../src-tauri/src/commands.rs");
  const offer = commands.slice(commands.indexOf('"offer_hello"'), commands.indexOf('"get_started"'));
  assert.ok(offer.includes("password_this_run") && !offer.includes("get_started"));
  // The Get started checklist has no Windows Hello step of its own.
  assert.doesNotMatch(read("../views/getstarted.js"), /enable_hello|start\.hello/);
  // Settings' auto-lock row says what "On every restart" means while it is the choice.
  const settings = read("../views/settings.js");
  assert.match(settings, /this\.autoLock\.value === "restart" \? t\("settings\.auto_lock_restart_note"\)/);
  assert.match(settings, /this\.autoLock\.addEventListener\("change", lockNote\);/);
  const en = JSON.parse(read("../i18n/en.json"));
  assert.equal(en["settings.auto_lock_restart_note"], "Anyone using this computer while it's on can open Passyble. Choose a shorter time if others use it.");
  for (const gone of ["setup.autolock_note", "setup.unlock_on", "setup.step_auto_lock", "start.hello"]) assert.ok(!(gone in en), gone);
});

test("the setup is wired in: opening, pausing, resuming", () => {
  const main = read("../main.js");
  assert.match(main, /closeOtpauthDialog\(\);\s+closeSetup\(\);/);
  assert.match(main, /maybeOpenSetup\(status\);/);
  const setup = read("../views/setup.js");
  // Every step saves where it is; Finish later pauses; the last button forgets it.
  assert.match(setup, /invoke\("setup_progress", \{ step \}\)/);
  assert.match(setup, /invoke\("setup_progress", \{ step, paused: true \}\)/);
  assert.match(setup, /invoke\("setup_progress", \{ done: true \}\)/);
  assert.match(setup, /if \(!progress \|\| progress\.paused \|\| status\.locked \|\| open\) return;/);
  // Continued from the Get started card and Settings → Help.
  assert.match(read("../views/getstarted.js"), /t\("setup\.continue_setup"\), on: \{ click: \(\) => openSetup\(\) \}/);
  assert.match(read("../views/settings.js"), /rowButton\(null, t\("setup\.open"\), \(\) => openSetup\(\)\)/);
  const caps = JSON.parse(read("../../src-tauri/capabilities/default.json")).capabilities.find((c) => c.identifier === "main");
  for (const p of ["allow-setup-progress", "allow-extension-open-store", "allow-get-started", "allow-set-settings", "allow-set-shortcut", "allow-account-sign-in", "allow-account-kit", "allow-account-device-request-start"]) {
    assert.ok(caps.permissions.includes(p), p);
  }
});
