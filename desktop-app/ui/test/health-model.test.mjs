// node --test Core/desktop-app/ui/test/*.test.mjs (Node 22 or later)
// The pure part of Password health: the checks in order, their counts, "look fine" after a breach
// check, what "Change to https" saves, when the master password tip shows.
import assert from "node:assert/strict";
import test from "node:test";

import { CHECKS, healthChecks, healthyCount, httpsChanges, masterTipDialog, methodText, methodTexts, problemIds, showMasterTip, toFixCount } from "../views/health-model.js";

const item = (id, extra = {}) => ({ id, title: id, username: "", domain: "", score: 3, reuse_count: 1, ...extra });

function report(extra = {}) {
  return {
    checked: 6,
    healthy: 2,
    weak: [item("weak", { score: 0 })],
    reused: [[item("r1", { reuse_count: 2 }), item("r2", { reuse_count: 2 })]],
    old: [],
    contains_name: [],
    insecure: [item("http", { urls: ["http://shop.example"], can_use_https: true })],
    no_two_factor: [item("fine1", { methods: ["totp", "sms"], docs_url: "https://example.com/2fa" })],
    passkeys: [],
    no_password: [item("empty")],
    duplicates: [[item("d1"), item("d2"), item("d3")]],
    ...extra,
  };
}

test("checks: the order, the counts, password problems first", () => {
  assert.deepEqual(CHECKS.map((c) => c.id), [
    "breached", "weak", "reused", "insecure", "contains_name", "old",
    "no_two_factor", "no_password", "duplicates", "passkeys",
  ]);
  assert.ok(CHECKS.slice(0, 6).every((c) => c.problem));
  assert.ok(CHECKS.slice(6).every((c) => !c.problem));

  const before = healthChecks(report());
  assert.equal(before.find((c) => c.id === "breached"), undefined, "no breach check yet");
  const count = Object.fromEntries(before.map((c) => [c.id, c.count]));
  assert.deepEqual(count, {
    weak: 1, reused: 2, insecure: 1, contains_name: 0, old: 0,
    no_two_factor: 1, no_password: 1, duplicates: 1, passkeys: 0,
  });

  const after = healthChecks(report(), [item("fine2")]);
  assert.equal(after[0].id, "breached");
  assert.equal(after[0].count, 1);

  const legacy = healthChecks({ checked: 1, healthy: 1, weak: [], reused: [], old: [] });
  assert.deepEqual(legacy.map((c) => c.count), [0, 0, 0, 0, 0, 0, 0, 0, 0]);
});

test("look fine: breached items that looked fine no longer do", () => {
  const r = report();
  assert.deepEqual([...problemIds(r)].sort(), ["http", "r1", "r2", "weak"]);
  assert.equal(healthyCount(r, null), 2);
  assert.equal(toFixCount(r, null), 4);
  // "fine1" lacks 2FA (no problem); its breach makes it one more to fix. "weak" was already one.
  const breaches = new Map([["fine1", 12], ["weak", 3], ["fine2", 0]]);
  assert.equal(healthyCount(r, breaches), 1);
  assert.equal(toFixCount(r, breaches), 5);
  assert.equal(healthyCount({ ...r, healthy: 0 }, breaches), 0, "never below 0");
});

test("two-factor methods: names, known ones only, at most three", () => {
  assert.equal(methodText("totp"), "Authenticator app");
  assert.equal(methodText("security_key"), "Security key");
  assert.equal(methodText("sms"), "Text message");
  assert.equal(methodText("nope"), "");
  assert.equal(methodText("toString"), "");
  assert.deepEqual(methodTexts(["totp", "nope", "sms", "email", "call"]), ["Authenticator app", "Text message", "Email"]);
  assert.deepEqual(methodTexts(undefined), []);
});

test("change to https: only http:// addresses, the rest kept", () => {
  assert.deepEqual(httpsChanges(["http://shop.example/login?a=1", " HTTP://Shop.example ", "https://x.example", "ftp://y"]), [
    { from: "http://shop.example/login?a=1", to: "https://shop.example/login?a=1" },
    { from: "HTTP://Shop.example", to: "https://Shop.example" },
  ]);
  assert.deepEqual(httpsChanges(null), []);
});

test("master password tip: only while Rust says so and until Dismiss", () => {
  assert.equal(showMasterTip(report({ master_password_tip: true })), true);
  assert.equal(showMasterTip(report({ master_password_tip: false })), false);
  assert.equal(showMasterTip(report()), false);
  assert.equal(showMasterTip(null), false);
  // Dismiss in this view hides it at once, before the next report says so too.
  assert.equal(showMasterTip(report({ master_password_tip: true }), true), false);
  assert.equal(showMasterTip(report({ master_password_tip: "yes" })), false);
});

test("master password tip: the change dialog of the vault or of the Passyble Server account", () => {
  assert.equal(masterTipDialog(report({ master_password_tip: true })), "vault");
  assert.equal(masterTipDialog(report({ master_password_tip: true, master_password_server: true })), "server");
  assert.equal(masterTipDialog(null), "vault");
});
