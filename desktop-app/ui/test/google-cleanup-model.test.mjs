// node --test Core/desktop-app/ui/test/*.test.mjs (Node 22 or later)
// What "Delete old versions from Google Drive" and "Remove vault from Google Drive" tell the user.
// Demo data only.
import assert from "node:assert/strict";
import test from "node:test";

import { nameConfirmed, oldVersionsText } from "../views/google-cleanup-model.js";

test("deleting old versions says how many went, what stayed and when to try again", () => {
  const done = oldVersionsText({ removed: 3, kept: 0, unfinished: false });
  assert.match(done, /3/);
  assert.notEqual(oldVersionsText({ removed: 1 }), done, "one and many read differently");

  const none = oldVersionsText({ removed: 0, kept: 0, unfinished: false });
  assert.ok(none && !/\d/.test(none), "nothing to delete is said plainly");

  const kept = oldVersionsText({ removed: 2, kept: 1, unfinished: false });
  assert.match(kept, /2/);
  assert.ok(kept.length > oldVersionsText({ removed: 2 }).length, "what stayed is added");
  assert.ok(!oldVersionsText({ removed: 0, kept: 2 }).includes(none), "kept ones aren't 'nothing to delete'");

  const partly = oldVersionsText({ removed: 1, kept: 0, unfinished: true });
  assert.ok(partly.length > oldVersionsText({ removed: 1 }).length, "an unfinished run says to try again");
  assert.ok(!oldVersionsText({ removed: 0, unfinished: true }).includes(none));

  assert.equal(oldVersionsText(null), none);
  assert.equal(oldVersionsText({ removed: -4, kept: "x" }), none);
});

test("removing from Google Drive needs the vault's name, case and outer spaces aside", () => {
  assert.equal(nameConfirmed("Personal", "Personal"), true);
  assert.equal(nameConfirmed("  personal ", "Personal"), true);
  assert.equal(nameConfirmed("ÉQUIPE", "équipe"), true);
  assert.equal(nameConfirmed("Persona", "Personal"), false);
  assert.equal(nameConfirmed("Work", "Personal"), false);
  assert.equal(nameConfirmed("", "Personal"), false);
  assert.equal(nameConfirmed("", ""), false, "an empty name never matches");
  assert.equal(nameConfirmed(undefined, "Personal"), false);
});
