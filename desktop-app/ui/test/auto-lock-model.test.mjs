// node --test Core/desktop-app/ui/test/*.test.mjs (Node 22 or later)
// How often the vault locks by itself: Settings' choices, how a choice maps onto the settings,
// existing users keeping theirs, and an organisation's maximum.
import assert from "node:assert/strict";
import test from "node:test";

import {
  autoLockAllowed,
  autoLockLabel,
  autoLockUpdate,
  autoLockValue,
  choicesWith,
  locksWithComputer,
  SETTINGS_CHOICES,
} from "../views/auto-lock-model.js";

test("Settings lists on every restart, with the computer, and times without use", () => {
  assert.deepEqual(SETTINGS_CHOICES, ["restart", "system", "1", "5", "10", "15", "30", "60", "240"]);
  assert.equal(autoLockLabel("restart"), "On every restart");
  assert.equal(autoLockLabel("system"), "When the computer locks or sleeps");
  assert.equal(autoLockLabel("60"), "1 hour");
});

test("auto-lock choices map onto the settings, and existing users keep theirs", () => {
  assert.deepEqual(autoLockUpdate("restart"), { auto_lock: "restart" });
  assert.deepEqual(autoLockUpdate("system"), { auto_lock: "system" });
  assert.deepEqual(autoLockUpdate("5"), { auto_lock: "idle", auto_lock_minutes: 5 });
  assert.equal(autoLockValue({ auto_lock: "restart", auto_lock_minutes: 15 }), "restart");
  assert.equal(autoLockValue({ auto_lock: "system", auto_lock_minutes: 15 }), "system");
  assert.equal(autoLockValue({ auto_lock: "idle", auto_lock_minutes: 30 }), "30");
  assert.equal(autoLockValue({ auto_lock_minutes: 10 }), "10");
  assert.equal(autoLockValue({}), "15");
  // A time no list has (an older version's, a hand-edited file) stays a choice, in order.
  assert.deepEqual(choicesWith(SETTINGS_CHOICES, "45"), ["restart", "system", "1", "5", "10", "15", "30", "45", "60", "240"]);
  assert.deepEqual(choicesWith(SETTINGS_CHOICES, "480"), [...SETTINGS_CHOICES, "480"]);
  assert.deepEqual(choicesWith(SETTINGS_CHOICES, "restart"), SETTINGS_CHOICES);
  assert.ok(!locksWithComputer("restart") && locksWithComputer("system") && locksWithComputer("15"));
});

test("an organisation's maximum rules out the choices that lock later or never", () => {
  assert.ok(autoLockAllowed("restart", null) && autoLockAllowed("240", null));
  assert.ok(!autoLockAllowed("restart", 15) && !autoLockAllowed("system", 15));
  assert.ok(autoLockAllowed("15", 15) && !autoLockAllowed("60", 15));
});
