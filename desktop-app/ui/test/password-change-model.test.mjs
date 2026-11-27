// node --test Core/desktop-app/ui/test/*.test.mjs (Node 22 or later)
// What a vault's master password change tells the user afterwards: the server's old versions, old
// copies other services keep, a new recovery code, and admin recovery to join again. Demo data only.
import assert from "node:assert/strict";
import test from "node:test";

import { followUps, oldCopiesText, purgeText } from "../views/password-change-model.js";

test("the server's answer to dropping old versions is put in words", () => {
  assert.ok(purgeText({ state: "dropped", count: 3 }));
  assert.notEqual(purgeText({ state: "dropped", count: 0 }), purgeText({ state: "dropped", count: 3 }));
  assert.ok(purgeText({ state: "kept_until_expiry" }));
  assert.ok(purgeText({ state: "not_owner" }));
  assert.ok(purgeText({ state: "not_uploaded" }));
  assert.ok(purgeText({ state: "failed", error: "offline" }));
  assert.equal(purgeText(null), null);
  assert.equal(purgeText({ state: "later_state" }), null);
});

test("Google Drive and WebDAV vaults are told their old copies still open with the old password", () => {
  assert.ok(oldCopiesText({ old_copies: "google_drive" }));
  assert.ok(oldCopiesText({ old_copies: "webdav" }));
  assert.notEqual(oldCopiesText({ old_copies: "google_drive" }), oldCopiesText({ old_copies: "webdav" }));
  assert.equal(oldCopiesText({ old_copies: "server" }), null, "the server's purge says it");
  assert.equal(oldCopiesText({ old_copies: null }), null);
});

test("after a change: a new recovery code is offered when the old one was dropped, admin recovery is only asked", () => {
  const f = followUps({
    purge: { state: "dropped", count: 2 },
    old_copies: "server",
    new_recovery_code: true,
    rejoin_admin_recovery: [{ org: "org_acme", name: "Acme" }, { name: "no id" }],
  });
  assert.equal(f.notes.length, 1);
  assert.equal(f.newCode, true);
  assert.deepEqual(f.rejoin.map((o) => o.org), ["org_acme"]);
  const none = followUps({ new_recovery_code: false });
  assert.deepEqual(none, { notes: [], newCode: false, rejoin: [], cleanDrive: false });
  assert.deepEqual(followUps(null), { notes: [], newCode: false, rejoin: [], cleanDrive: false });
});

test("a Google Drive vault is offered to delete its old versions there instead of a note", () => {
  const drive = followUps({ old_copies: "google_drive", new_recovery_code: false });
  assert.equal(drive.cleanDrive, true);
  assert.deepEqual(drive.notes, [], "the offer says it");
  const webdav = followUps({ old_copies: "webdav" });
  assert.equal(webdav.cleanDrive, false);
  assert.equal(webdav.notes.length, 1, "WebDAV services keep their note");
  assert.equal(followUps({ old_copies: "server" }).cleanDrive, false);
});
