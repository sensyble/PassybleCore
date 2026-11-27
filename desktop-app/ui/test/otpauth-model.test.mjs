// node --test Core/desktop-app/ui/test/*.test.mjs (Node 22 or later)
// The confirmation for an otpauth:// link opened from outside and the Settings row.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  NEW_LOGIN,
  addLabel,
  detailRows,
  handlerRow,
  initialChoice,
  matchDetail,
  newLoginTitle,
  replaces,
  unlockNotice,
} from "../views/otpauth-model.js";

const link = { id: 1, issuer: "Demo", account: "alice@example.com", algorithm: "SHA1", digits: 6, period: 30 };

test("the details show what the link says, and a gap plainly", () => {
  const rows = detailRows(link).map((r) => r.value);
  assert.equal(rows[0], "Demo");
  assert.equal(rows[1], "alice@example.com");
  assert.match(rows[2], /6/);
  assert.match(rows[2], /30/);
  assert.match(rows[2], /SHA1/);
  const empty = detailRows({ ...link, issuer: null, account: null }).map((r) => r.value);
  assert.equal(empty[0], empty[1]);
  assert.ok(empty[0].length > 0);
});

test("the core's suggestion is preselected, a login with a code never is", () => {
  const free = { id: "a", suggested: true, has_totp: false };
  const other = { id: "b", suggested: false, has_totp: false };
  assert.equal(initialChoice([other, free]), "a");
  assert.equal(initialChoice([other]), NEW_LOGIN);
  assert.equal(initialChoice([]), NEW_LOGIN);
  assert.equal(initialChoice([{ id: "c", suggested: true, has_totp: true }]), NEW_LOGIN);
});

test("choosing a login with a code says it replaces it", () => {
  const matches = [
    { id: "code", has_totp: true },
    { id: "free", has_totp: false },
  ];
  assert.equal(replaces(matches, "code"), true);
  assert.equal(replaces(matches, "free"), false);
  assert.equal(replaces(matches, NEW_LOGIN), false);
  assert.notEqual(addLabel(matches, "code"), addLabel(matches, "free"));
  assert.equal(addLabel(matches, "free"), addLabel(matches, NEW_LOGIN));
  assert.ok(matchDetail({ username: "alice", has_totp: true }).startsWith("alice · "));
  assert.equal(matchDetail({ username: "alice", has_totp: false }), "alice");
  assert.equal(matchDetail({ username: "", has_totp: false }), "");
});

test("a new login is named after the issuer, the account, or plainly", () => {
  assert.equal(newLoginTitle(link), "Demo");
  assert.equal(newLoginTitle({ ...link, issuer: null }), "alice@example.com");
  assert.ok(newLoginTitle({ ...link, issuer: null, account: null }).length > 0);
});

test("the unlock line names the service when the link does", () => {
  assert.match(unlockNotice(link), /Demo/);
  assert.ok(unlockNotice({ ...link, issuer: null, account: null }).length > 0);
});

test("the Settings row: nothing to do, claim, or Windows settings after a claim that didn't win", () => {
  assert.equal(handlerRow("this").action, null);
  assert.equal(handlerRow("none").action, "claim");
  assert.equal(handlerRow("other").action, "claim");
  assert.equal(handlerRow("other", true).action, "windows");
  assert.equal(handlerRow("this", true).action, null);
});

test("the dialog never renders a link's text as markup", () => {
  const source = readFileSync(new URL("../views/otpauth.js", import.meta.url), "utf8");
  assert.doesNotMatch(source, /innerHTML|insertAdjacentHTML|outerHTML/);
});
