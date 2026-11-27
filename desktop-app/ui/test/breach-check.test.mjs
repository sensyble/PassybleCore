// node --test Core/desktop-app/ui/test/*.test.mjs (Node 22 or later)
// The breach check belongs to the app, not to the Password health pane: a pane that opens shows
// where the check is, closing the pane never cancels it, and the notice before a check shows until
// "Don't show this again".
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { breachCard, breachNoticeNeeded } from "../views/health-model.js";

test("breach card: a pane that opens during a check shows its live progress", () => {
  assert.deepEqual(breachCard({ state: "running", done: 3, total: 12 }), { mode: "running", done: 3, total: 12, pct: 25 });
  assert.deepEqual(breachCard({ state: "running", done: 0, total: 0 }), { mode: "running", done: 0, total: 0, pct: 0 });
  assert.equal(breachCard({ state: "running", done: 12, total: 12 }).pct, 100);
});

test("breach card: a check that finished while the pane was closed shows its results", () => {
  const card = breachCard({
    state: "done",
    results: [{ id: "a", count: 9000 }, { id: "b", count: 0 }],
    checked: 2,
    total: 2,
    failed: 0,
  });
  assert.equal(card.mode, "done");
  assert.equal(card.breaches.get("a"), 9000);
  assert.equal(card.breaches.get("b"), 0);
  assert.equal(card.checked, 2);
  assert.equal(card.failed, 0);
});

test("breach card: Check stopped, with the reason", () => {
  assert.deepEqual(breachCard({ state: "stopped", reason: "locked", done: 1, total: 4 }), { mode: "stopped", reason: "locked" });
  assert.deepEqual(breachCard({ state: "stopped", reason: "cancelled" }), { mode: "stopped", reason: "cancelled" });
  assert.deepEqual(breachCard({ state: "failed", error: "Couldn't reach Have I Been Pwned" }), { mode: "failed", error: "Couldn't reach Have I Been Pwned" });
});

test("breach card: nothing checked yet", () => {
  for (const s of [null, undefined, {}, { state: "idle" }, { state: "something new" }]) {
    assert.deepEqual(breachCard(s), { mode: "idle" });
  }
});

test("breach notice: shown until Don't show this again", () => {
  assert.equal(breachNoticeNeeded(null), true);
  assert.equal(breachNoticeNeeded({}), true);
  assert.equal(breachNoticeNeeded({ breach_notice_hidden: false }), true);
  assert.equal(breachNoticeNeeded({ breach_notice_hidden: true }), false);
});

test("the pane reattaches to the app's check and never cancels it when it closes", () => {
  const src = readFileSync(new URL("../views/health.js", import.meta.url), "utf8");
  assert.match(src, /invoke\("health_breach_status"\)/);
  assert.match(src, /listen\("health-breach"/);
  // destroy() only drops the listener.
  const destroy = src.slice(src.indexOf("  destroy() {"), src.indexOf("  async load() {"));
  assert.ok(destroy.length > 0);
  assert.doesNotMatch(destroy, /health_breach_cancel/);
  // Cancel is a button (and the tray's menu item), nothing else.
  assert.equal(src.match(/health_breach_cancel/g).length, 1);
});
