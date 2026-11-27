// node --test Core/desktop-app/ui/test/*.test.mjs (Node 22 or later)
// The pure part of the live master password check: the text for each reason the core's rule gives,
// what shows for an answer, and the names it gets.
import assert from "node:assert/strict";
import test from "node:test";

import { MASTER_MIN_LENGTH, masterFeedback, masterIssueText, masterNames } from "../views/master-password-model.js";

const refused = (issues, extra = {}) => ({ ok: false, score: 1, label: "weak", entropy_bits: 30, issues, name: "", min_length: 12, ...extra });

test("masterIssueText: one plain sentence per reason", () => {
  assert.equal(masterIssueText("too_short", { min_length: 12 }), "Use at least 12 characters.");
  assert.equal(masterIssueText("too_short", { min_length: 14 }), "Use at least 14 characters.");
  assert.equal(masterIssueText("too_short"), `Use at least ${MASTER_MIN_LENGTH} characters.`, "the core's minimum when left out");
  assert.equal(masterIssueText("common"), "This is one of the most common passwords. Choose something else.");
  assert.equal(masterIssueText("contains_name"), "Leave out your email address, username and the vault's name.");
  assert.match(masterIssueText("pattern"), /repeated characters, sequences like abcd or 1234 and keyboard rows like qwerty/);
  assert.match(masterIssueText("guessable"), /^Too easy to guess\. Add more words or random characters/);
  assert.equal(masterIssueText("something_newer"), "");
});

test("masterFeedback: the reasons in the core's order while refused", () => {
  const f = masterFeedback(refused(["too_short", "pattern", "guessable"]), "aaaa");
  assert.equal(f.ok, false);
  assert.equal(f.okText, "");
  assert.deepEqual(f.reasons, [masterIssueText("too_short"), masterIssueText("pattern"), masterIssueText("guessable")]);
  assert.deepEqual(masterFeedback(refused(["newer"]), "x").reasons, [masterIssueText("guessable")]);
  assert.deepEqual(masterFeedback(refused(["newer", "common"]), "x").reasons, [masterIssueText("common")]);
});

test("masterFeedback: strength and 'strong enough' once it passes", () => {
  const good = masterFeedback({ ok: true, score: 3, label: "good", issues: [], min_length: 12 }, "x7#Rq!9vLm@2");
  assert.deepEqual(good, { ok: true, reasons: [], okText: "Good: strong enough for a master password." });
  assert.equal(masterFeedback({ ok: true, label: "strong", issues: [] }, "p").okText, "Strong: strong enough for a master password.");
  assert.equal(masterFeedback({ ok: true, label: "odd", issues: [] }, "p").okText, "Good: strong enough for a master password.");
  // Only `ok: true` passes, whatever the score says.
  assert.equal(masterFeedback({ ok: "yes", score: 4, issues: [] }, "p").ok, false);
});

test("masterFeedback: nothing before typing or without an answer", () => {
  const none = { ok: false, reasons: [], okText: "" };
  assert.deepEqual(masterFeedback(refused(["guessable"]), ""), none);
  assert.deepEqual(masterFeedback(null, "something"), none);
  assert.deepEqual(masterFeedback("oops", "something"), none);
});

test("masterNames: trimmed strings only, at most 16", () => {
  assert.deepEqual(masterNames(" Family vault ", null, "", ["alex@example.com", 7, undefined]), ["Family vault", "alex@example.com"]);
  assert.equal(masterNames(Array.from({ length: 30 }, (_, i) => `name${i}`)).length, 16);
  assert.deepEqual(masterNames(), []);
});
