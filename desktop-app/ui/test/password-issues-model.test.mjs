// node --test Core/desktop-app/ui/test/*.test.mjs (Node 22 or later)
// The pure part of the editor's live password check: the text for each issue, what shows for an
// answer (issues, "Strong", the one-tap fix), and the context password_check gets.
import assert from "node:assert/strict";
import test from "node:test";

import { checkContext, issueText, passwordFeedback } from "../views/password-issues-model.js";

const answer = (issues, score = 1) => ({ score, label: "weak", entropy_bits: 20, vault_checked: true, issues });

test("issueText: one plain sentence per code", () => {
  assert.equal(issueText({ code: "common", severity: "high" }), "This is one of the most common passwords.");
  assert.equal(issueText({ code: "weak", severity: "high" }), "This password is easy to guess.");
  assert.equal(issueText({ code: "reused", severity: "high", count: 1 }), "You use this password for 1 other login.");
  assert.equal(issueText({ code: "reused", severity: "high", count: 3 }), "You use this password for 3 other logins.");
  assert.equal(issueText({ code: "reused", severity: "high" }), "You use this password for 1 other login.", "a missing count reads as one");
  assert.equal(issueText({ code: "used_before", severity: "medium" }), "You used this password before for this login.");
  assert.equal(issueText({ code: "contains_username", severity: "medium", name: "alex" }), "This password contains your username.");
  assert.equal(issueText({ code: "contains_site", severity: "medium", name: "github" }), "This password contains the site's name.");
  assert.equal(issueText({ code: "short", severity: "low", min_length: 12 }), "Short: use at least 12 characters.");
  assert.equal(issueText({ code: "short", severity: "low", min_length: 16 }), "Short: use at least 16 characters.");
  assert.equal(issueText({ code: "short", severity: "low" }), "Short: use at least 12 characters.");
  assert.equal(issueText({ code: "something_new", severity: "high" }), "", "a code from a newer core is left out");
  assert.equal(issueText(null), "");
});

test("passwordFeedback: issues in the core's order, the fix for high and medium ones", () => {
  const fb = passwordFeedback(answer([
    { code: "common", severity: "high" },
    { code: "reused", severity: "high", count: 2 },
    { code: "future", severity: "high" },
    { code: "short", severity: "low", min_length: 12 },
  ]), "password1");
  assert.deepEqual(fb.issues.map((i) => [i.code, i.severity]), [["common", "high"], ["reused", "high"], ["short", "low"]]);
  assert.equal(fb.issues[1].text, "You use this password for 2 other logins.");
  assert.equal(fb.strong, "");
  assert.equal(fb.fix, true);

  assert.equal(passwordFeedback(answer([{ code: "contains_site", severity: "medium" }], 3), "x").fix, true);
  const low = passwordFeedback(answer([{ code: "short", severity: "low" }], 4), "Tr0ub4dor&3x");
  assert.equal(low.fix, false, "only low ones: no fix offered");
  assert.equal(low.strong, "", "no \"Strong\" next to an issue");
  assert.equal(passwordFeedback(answer([{ code: "weak", severity: "odd" }]), "x").issues[0].severity, "low", "unknown severity shows as low");
});

test("passwordFeedback: Strong only without issues and with a score of 3 or more", () => {
  assert.equal(passwordFeedback(answer([], 4), "x").strong, "Strong");
  assert.equal(passwordFeedback(answer([], 3), "x").strong, "Strong");
  assert.equal(passwordFeedback(answer([], 2), "x").strong, "");
  assert.equal(passwordFeedback(answer([{ code: "nope", severity: "high" }], 4), "x").strong, "", "not next to an issue this window can't word");
});

test("passwordFeedback: nothing for an empty password or a failed check", () => {
  const none = { issues: [], strong: "", fix: false };
  assert.deepEqual(passwordFeedback(answer([{ code: "weak", severity: "high" }], 0), ""), none);
  assert.deepEqual(passwordFeedback(null, "x"), none);
  assert.deepEqual(passwordFeedback(undefined, "x"), none);
  assert.deepEqual(passwordFeedback({ score: 4 }, "x"), { issues: [], strong: "Strong", fix: false }, "an answer without issues");
});

test("checkContext: the editor's username, websites (one per line), title and item id", () => {
  assert.deepEqual(checkContext({ username: "alex", urls: " https://github.com \r\n\nwindows:putty.exe\n", title: "GitHub", id: "abc" }), {
    username: "alex",
    urls: ["https://github.com", "windows:putty.exe"],
    title: "GitHub",
    id: "abc",
  });
  assert.deepEqual(checkContext({ username: "", urls: "", title: "", id: "" }), { username: "", urls: [], title: "" }, "a new item has no id");
  assert.deepEqual(checkContext(), { username: "", urls: [], title: "" });
});
