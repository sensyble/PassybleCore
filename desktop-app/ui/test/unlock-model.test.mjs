// node --test Core/desktop-app/ui/test/*.test.mjs (Node 22 or later)
// When the unlock form starts Windows Hello by itself: only for something the user just did, never
// for a hidden window (a start with Windows), a lock, a resume from sleep or Hello turning available
// after Windows sign-in.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { autoHelloMode } from "../views/unlock-model.js";

const form = (extra = {}) => ({ auto: undefined, ready: true, active: true, usePassword: false, typed: false, ...extra });

test("the window's unlock screen waits for the user to open the window", () => {
  assert.equal(autoHelloMode(form()), "if-opened");
});

test("the vault view's unlock dialog for a secret the user asked for starts at once", () => {
  assert.equal(autoHelloMode(form({ auto: true })), "now");
});

test("never when Windows Hello can't unlock now, for another vault, or after the user chose the password", () => {
  assert.equal(autoHelloMode(form({ auto: false })), "never");
  assert.equal(autoHelloMode(form({ ready: false })), "never");
  assert.equal(autoHelloMode(form({ ready: false, auto: true })), "never");
  assert.equal(autoHelloMode(form({ active: false })), "never");
  assert.equal(autoHelloMode(form({ usePassword: true })), "never");
  assert.equal(autoHelloMode(form({ typed: true })), "never");
});

const unlockSource = readFileSync(new URL("../views/unlock.js", import.meta.url), "utf8");

test("the form never decides on its own that the window is on screen", () => {
  // A hidden Tauri window's webview reports itself visible: no visibility checks, the app's
  // one-time grant decides.
  assert.doesNotMatch(unlockSource, /visibilityState|visibilitychange/);
  assert.match(unlockSource, /invoke\("take_auto_hello"\)/);
  assert.match(unlockSource, /listen\("main-opened"/);
});

test("a lock no longer arms Windows Hello", () => {
  assert.doesNotMatch(unlockSource, /listen\("lock-state"/);
});

test("hello-available only refreshes the form; it starts nothing without the grant", () => {
  const main = readFileSync(new URL("../main.js", import.meta.url), "utf8");
  assert.match(main, /listen\("hello-available", refresh\)/);
  // A form that turns ready asks for the grant like any other (maybeAutoHello), nothing more.
  assert.match(unlockSource, /if \(ready && this\.wasReady === false\) this\.maybeAutoHello\(\);/);
});
