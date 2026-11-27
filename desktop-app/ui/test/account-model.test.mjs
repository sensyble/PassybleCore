// node --test Core/desktop-app/ui/test/*.test.mjs (Node 22 or later)
// The Passyble account row: always there, signed out, failed check, signed in.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { accountState, offersExtensionSignOut } from "../views/account-model.js";

const en = JSON.parse(readFileSync(new URL("../i18n/en.json", import.meta.url), "utf8"));

test("signed out: a sign in button, no error", () => {
  for (const status of [null, {}, { signed_in: false }, { signed_in: true }]) {
    const v = accountState({ status });
    assert.equal(v.state, "signed_out");
    assert.deepEqual(v.actions, ["sign_in"]);
    assert.deepEqual(v.text, { key: "account.signed_out" });
  }
});

test("a failed check keeps the row: calm line, Retry and Sign in", () => {
  const v = accountState({ failed: true });
  assert.equal(v.state, "error");
  assert.deepEqual(v.actions, ["retry", "sign_in"]);
  assert.equal(en[v.text.key], "Couldn't check your account. Try again.");
  assert.ok(en["account.retry"]);
});

test("signed in: the e-mail and the organisations, and Sign out", () => {
  const v = accountState({
    status: { signed_in: true, account: { email: "a@b.c" }, orgs: [{ name: "Acme", role: "owner", kind: "team" }] },
    orgLabel: (o) => o.role,
  });
  assert.equal(v.state, "signed_in");
  assert.deepEqual(v.actions, ["sign_out"]);
  assert.equal(v.text.plain, "a@b.c · Acme (owner)");
});

test("the row is never hidden by the code", () => {
  const src = readFileSync(new URL("../views/account.js", import.meta.url), "utf8");
  assert.ok(!/row\.hidden/.test(src));
});

test("sign out offers the browser extension only when one talked to the app lately", () => {
  assert.equal(offersExtensionSignOut(null), false);
  assert.equal(offersExtensionSignOut({ signed_in: true, account: { email: "a@b.c" } }), false);
  assert.equal(offersExtensionSignOut({ signed_in: true, extension_recent: false }), false);
  assert.equal(offersExtensionSignOut({ signed_in: false, extension_recent: true }), false);
  assert.equal(offersExtensionSignOut({ signed_in: true, extension_recent: true }), true);
  assert.equal(en["account.sign_out_extension"], "Also sign out of the browser extension on this computer");
});
