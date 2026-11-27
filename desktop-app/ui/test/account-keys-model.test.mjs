// node --test Core/desktop-app/ui/test/*.test.mjs (Node 22 or later)
// The Passyble password screens' pure decisions.
import assert from "node:assert/strict";
import test from "node:test";
import { friendlyError } from "../errors.js";
import { t } from "../i18n.js";
import {
  adminKeyRow,
  codeText,
  confirmsCode,
  errorCode,
  lastGroup,
  linkedForm,
  lockedWays,
  looksLikeSecretKey,
  namesKey,
  opensWithAccount,
  requestView,
  resetStep,
  securityRows,
} from "../views/account-keys-model.js";

test("the Emergency Kit is confirmed by the recovery code's last group", () => {
  const code = "ABCDE-FGH12-34567-89JKM-NPQRS-T0V1W";
  assert.equal(lastGroup(code), "T0V1W");
  assert.ok(confirmsCode(code, "t0v1w"));
  assert.ok(confirmsCode(code, " TOV1W "), "O reads as 0");
  assert.ok(confirmsCode(code, "T0VIW"), "I reads as 1");
  assert.ok(!confirmsCode(code, "NPQRS"));
  assert.ok(!confirmsCode(code, ""));
  assert.ok(!confirmsCode("", ""));
});

test("Secret Keys are told from other text", () => {
  assert.ok(looksLikeSecretKey("P1-ABCDE-FGH12-34567-89JKM-NPQRS-T0V1W"));
  assert.ok(looksLikeSecretKey(" p1-abcde-fgh12-34567-89jkm-npqrs-t0v1w "));
  assert.ok(!looksLikeSecretKey("ABCDE-FGH12-34567-89JKM-NPQRS-T0V1W"), "a recovery code is not a Secret Key");
  assert.ok(!looksLikeSecretKey("P1-ABCDE"));
});

test("the linked unlock form asks only for what this PC lacks", () => {
  assert.deepEqual(linkedForm({ kept: "hello", kept_ready: true, secret_key_here: true, signed_in: true }, true), {
    hello: true,
    remembered: false,
    secretKey: false,
    email: false,
  });
  assert.equal(linkedForm({ kept: "hello", kept_ready: true }, false).hello, false);
  assert.equal(linkedForm({ kept: "remember", kept_ready: true }, false).remembered, true);
  assert.deepEqual(linkedForm({ secret_key_here: false, signed_in: false }, true), {
    hello: false,
    remembered: false,
    secretKey: true,
    email: true,
  });
  assert.equal(linkedForm({ secret_key_here: true, signed_in: false, offline_ready: true }, true).email, false);
  assert.equal(linkedForm({ signed_in: false, email: "demo@example.com" }, true).email, false);
});

test("Settings shows the rows the account's state allows", () => {
  assert.deepEqual(securityRows({ signed_in: false }), []);
  assert.deepEqual(securityRows({ signed_in: true, feature_off: true, set: false }), []);
  assert.deepEqual(securityRows({ signed_in: true, set: false }), ["setup"]);
  assert.deepEqual(securityRows({ signed_in: true, set: null }), [], "unknown while offline without a cache");
  const base = ["password", "kit", "recovery", "device_key", "fingerprint", "devices"];
  assert.deepEqual(securityRows({ signed_in: true, set: true }), base);
  assert.deepEqual(securityRows({ signed_in: true, set: true, active_vault: { linked: false } }), [...base, "link"]);
  assert.deepEqual(securityRows({ signed_in: true, set: true, active_vault: { linked: true, unlink: true } }), [...base, "unlink"]);
  assert.deepEqual(securityRows({ signed_in: true, set: true, active_vault: { linked: true, home: true, unlink: false } }), base, "the home vault keeps its link");
  assert.deepEqual(securityRows({ signed_in: true, set: true, active_vault: { linked: true, home: true, unlink: true, password_mode: "second_password" } }),
    [...base, "unlink"], "unless its Team requires a second password");
  assert.deepEqual(securityRows({ signed_in: true, set: true, active_vault: { linked: false, linked_other: true } }), base);
  assert.deepEqual(securityRows({ signed_in: true, set: true, active_vault: { linked: false, home: true, link: false } }), base, "a required second password stays");
  // A waiting reset, a changed key and locked key sets come first, in that order.
  assert.deepEqual(
    securityRows({ signed_in: true, set: true, reset: { waiting: true }, key_changed: { at: 1 }, locked: 2 }),
    ["reset", "key_changed", "locked", ...base],
  );
  assert.deepEqual(securityRows({ signed_in: true, set: true, reset: { waiting: false }, key_changed: null, locked: 0 }), base);
});

test("an e-mail reset waits 72 hours, then the new keys are due", () => {
  assert.deepEqual(resetStep(null), { step: "none", releaseAt: null });
  assert.deepEqual(resetStep({ waiting: false }), { step: "none", releaseAt: null });
  assert.deepEqual(resetStep({ waiting: true, release_at: 1000 }, 999), { step: "waiting", releaseAt: 1000 });
  assert.equal(resetStep({ waiting: true, release_at: 1000 }, 1000).step, "due");
  assert.equal(resetStep({ waiting: true, release_at: 5000, due: true }, 0).step, "due", "the service's word wins");
});

test("a locked key set offers this PC, the old password, the old code and admins", () => {
  assert.deepEqual(lockedWays({ ways: {} }), ["password", "recovery"]);
  assert.deepEqual(lockedWays({ ways: { device: true, recovery: false, admins: ["g1"] } }), ["device", "password", "admin"]);
  assert.deepEqual(lockedWays(null), ["password", "recovery"]);
});

test("admin recovery of the account key: enrolled, required, enrol again", () => {
  assert.deepEqual(adminKeyRow({ available: true, enrolled: true }), { state: "enrolled", actions: ["withdraw"] });
  assert.deepEqual(adminKeyRow({ available: true, enrolled: true, required: true }).actions, [], "a required enrolment stays");
  assert.deepEqual(adminKeyRow({ available: true, required: true }), { state: "required", actions: ["enrol"] });
  assert.equal(adminKeyRow({ available: true, enrol_again: true }).state, "again");
  assert.equal(adminKeyRow({ available: true }).state, "offered");
  assert.equal(adminKeyRow({ available: false }).state, "hidden");
  assert.ok(namesKey("ak:AK1", "AK1"));
  assert.ok(!namesKey("ak:AK0", "AK1"));
  assert.ok(!namesKey("ak:", ""));
});

test("device requests move from new to compare to approve", () => {
  assert.deepEqual(requestView({ kind: "request", state: "waiting" }).actions, ["accept", "deny"]);
  assert.equal(requestView({ kind: "request", accepted_here: true }).step, "accepted");
  // Number matching: the window never gets the new device's digits.
  assert.deepEqual(requestView({ kind: "request", accepted_here: true, ready: true }).actions, ["approve", "deny"]);
  assert.equal(requestView({ kind: "request", accepted_here: true, ready: true }).step, "compare");
  assert.equal(requestView({ kind: "request", accepted_here: true, code: "123456" }).step, "accepted", "a code alone doesn't make it approvable");
  assert.deepEqual(requestView({ kind: "request", mismatch: true }).actions, ["deny"]);
  assert.equal(requestView({ kind: "invitation", ready: false }).step, "waiting");
  assert.deepEqual(requestView({ kind: "invitation", ready: true }).actions, ["approve", "deny"]);
  assert.equal(codeText("123456"), "123 456");
});

test("answers the windows act on are read from strings and errors", () => {
  assert.equal(errorCode("secret_key_needed"), "secret_key_needed");
  assert.equal(errorCode(new Error(" reauth_required ")), "reauth_required");
  assert.equal(errorCode(null), "");
  assert.ok(opensWithAccount("This vault opens with your Passyble password"));
  assert.ok(!opensWithAccount("Wrong master password"));
});

test("a code that reaches the screen still reads as a sentence", () => {
  assert.equal(friendlyError("secret_key_needed"), t("account_keys.secret_key_needed"));
  assert.equal(friendlyError(new Error("reauth_required")), t("account_keys.sign_in_again"));
  assert.notEqual(t("account_keys.secret_key_needed"), "account_keys.secret_key_needed");
});
