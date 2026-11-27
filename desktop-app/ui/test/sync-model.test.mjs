// node --test Core/desktop-app/ui/test/*.test.mjs (Node 22 or later)
// The vault screen's Sync button.
import assert from "node:assert/strict";
import test from "node:test";

import { DEBOUNCE_MS, acceptClick, syncButton, syncToast } from "../views/sync-model.js";

test("the button offers Set up sync when no vault has sync", () => {
  const b = syncButton(false, { running: true });
  assert.equal(b.action, "setup");
  assert.equal(b.busy, false);
  assert.match(b.title, /Set up sync/);
});

test("the button turns while syncing, warns after a failure, says when it last synced", () => {
  assert.deepEqual(syncButton(true, { running: true }).busy, true);
  const failed = syncButton(true, { last_error: "Can't reach the server." });
  assert.equal(failed.warn, true);
  assert.match(failed.title, /Can't reach the server/);
  const synced = syncButton(true, { last_sync_ms: 1000 }, () => "just now");
  assert.match(synced.title, /Synced just now/);
  assert.equal(synced.action, "sync");
  assert.equal(syncButton(true, {}).title, "Sync now");
});

test("a double click is one sync", () => {
  assert.ok(acceptClick(0, false, 10_000));
  assert.ok(!acceptClick(10_000, false, 10_000 + DEBOUNCE_MS - 1));
  assert.ok(acceptClick(10_000, false, 10_000 + DEBOUNCE_MS));
  assert.ok(!acceptClick(0, true, 10_000));
});

test("the toast says what the sync did", () => {
  assert.equal(syncToast({ no_sync: true }), null);
  assert.equal(syncToast({ synced: 1, failed: [] }).text, "Synced just now");
  const failed = syncToast({ synced: 1, failed: [{ vault: "Family", reason: "Offline." }] });
  assert.equal(failed.kind, "error");
  assert.match(failed.text, /Family/);
  assert.match(failed.text, /Offline/);
  const changed = syncToast({ synced: 1, failed: [], changes: { added: 2, updated: 0, deleted: 1 } });
  assert.equal(changed.kind, "");
  assert.match(changed.text, /2/);
});
