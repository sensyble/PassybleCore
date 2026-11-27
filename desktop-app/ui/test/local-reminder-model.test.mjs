// node --test Core/desktop-app/ui/test/*.test.mjs (Node 22 or later)
// "This vault is only on this device": the card shows while a vault is local only and not hidden by
// "Not now", never while locked; "Set up sync" points at the open vault first. The create form warns
// unless the new vault gets Google Drive backup or goes into a synced folder.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { createNoticeShown, reminderVaults, reminderView } from "../views/local-reminder-model.js";

const vault = (id, extra = {}) => ({ id, name: id, active: false, local_only: true, local_reminder: true, ...extra });
const unlocked = (vaults, extra = {}) => ({ locked: false, google_available: true, vaults, ...extra });

test("only vaults Rust marks as due count", () => {
  const vaults = [
    vault("a"),
    vault("synced", { local_only: false, local_reminder: false }),
    vault("snoozed", { local_reminder: false }),
    vault("b"),
  ];
  assert.deepEqual(reminderVaults(vaults).map((v) => v.id), ["a", "b"]);
  assert.deepEqual(reminderVaults(null), []);
  assert.deepEqual(reminderVaults([null, { local_reminder: true }]), []);
});

test("nothing while every vault syncs or was put off", () => {
  assert.equal(reminderView(unlocked([vault("a", { local_only: false, local_reminder: false })])), null);
  assert.equal(reminderView(unlocked([vault("a", { local_reminder: false })])), null);
  assert.equal(reminderView(unlocked([])), null);
  assert.equal(reminderView(null), null);
});

test("never while locked: not on the unlock screen, nor over a soft-locked list", () => {
  assert.equal(reminderView(unlocked([vault("a", { active: true })], { locked: true })), null);
  assert.equal(reminderView(unlocked([vault("a", { active: true })], { locked: true, soft_locked: true })), null);
});

test("one local-only vault: the open one, named only when there are others", () => {
  const view = reminderView(unlocked([vault("a", { active: true })]));
  assert.equal(view.count, 1);
  assert.equal(view.target.id, "a");
  assert.deepEqual(view.ids, ["a"]);
  assert.equal(view.named, false);
  const two = reminderView(unlocked([vault("a", { active: true }), vault("s", { local_only: false, local_reminder: false })]));
  assert.equal(two.count, 1);
  assert.equal(two.named, true);
});

test("several: Set up sync opens the open vault first, else the first one; Not now hides them all", () => {
  const view = reminderView(unlocked([vault("a"), vault("b", { active: true }), vault("c")]));
  assert.equal(view.count, 3);
  assert.equal(view.target.id, "b");
  assert.deepEqual(view.ids, ["a", "b", "c"]);
  const other = reminderView(unlocked([vault("s", { active: true, local_only: false, local_reminder: false }), vault("x"), vault("y")]));
  assert.equal(other.target.id, "x");
  assert.deepEqual(other.ids, ["x", "y"]);
});

test("without Google sign-in in this build it still shows, with the text for the other options", () => {
  const view = reminderView(unlocked([vault("a", { active: true })], { google_available: false }));
  assert.ok(view);
  assert.equal(view.google, false);
  assert.equal(reminderView(unlocked([vault("a", { active: true })])).google, true);
});

test("create form: the notice shows unless Google Drive backup is on or the folder syncs", () => {
  assert.equal(createNoticeShown({ googleBackup: false, synced: false }), true);
  assert.equal(createNoticeShown({ googleBackup: true, synced: false }), false);
  assert.equal(createNoticeShown({ googleBackup: false, synced: true }), false);
  assert.equal(createNoticeShown({ googleBackup: false, synced: null }), true);
});

test("the card's wording follows the shared contract", () => {
  const en = JSON.parse(readFileSync(new URL("../i18n/en.json", import.meta.url), "utf8"));
  assert.equal(en["local_reminder.title"].one, "This vault is only on this device");
  assert.equal(en["local_reminder.title"].other, "{count} vaults are only on this device");
  assert.equal(
    en["local_reminder.body"].one,
    "If this device is lost, stolen, broken or reset, the passwords in this vault are gone for good. Turn on sync or backup (Google Drive is free), or export a backup copy regularly.",
  );
  // The create form's notice is one short line.
  assert.equal(en["local_reminder.create_notice"], "Only on this device: no backup");
  assert.equal(en["local_reminder.set_up_sync"], "Set up sync");
  assert.equal(en["common.not_now"], "Not now");
});

test("Not now goes to Rust; Set up sync opens Settings at Sync", () => {
  const card = readFileSync(new URL("../views/local-reminder.js", import.meta.url), "utf8");
  assert.match(card, /invoke\("local_reminder_dismiss", \{ ids \}\)/);
  const view = readFileSync(new URL("../views/vault.js", import.meta.url), "utf8");
  assert.match(view, /this\.showSettings\(\{ section: "sync" \}\)/);
  assert.match(view, /this\.switchTo\(vault, \{ settings: \{ section: "sync" \} \}\)/);
});
