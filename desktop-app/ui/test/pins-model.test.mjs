// node --test Core/desktop-app/ui/test/*.test.mjs
// Pinned vaults: their order in every vault list, pinning at most five, and the pins the locked
// vault list remembers.
import assert from "node:assert/strict";
import test from "node:test";

import { MAX_PINS, lastPins, pinnedFirst, rememberPins, togglePin } from "../views/pins-model.js";

const vaults = [{ id: "home" }, { id: "eng" }, { id: "family" }, { id: "support" }];
const ids = (list) => list.map((v) => v.id);

test("pinned vaults come first, in pin order, the others as they were", () => {
  assert.deepEqual(ids(pinnedFirst(vaults, ["support", "gone", "eng"])), ["support", "eng", "home", "family"]);
  assert.deepEqual(ids(pinnedFirst(vaults, [])), ids(vaults));
  assert.deepEqual(pinnedFirst(null, ["eng"]), []);
});

test("the active vault comes before the pinned ones, pinned or not", () => {
  const active = (v) => v.id === "family";
  assert.deepEqual(ids(pinnedFirst(vaults, ["support", "eng"], undefined, active)), ["family", "support", "eng", "home"]);
  assert.deepEqual(ids(pinnedFirst(vaults, ["eng", "family"], undefined, active)), ["family", "eng", "home", "support"]);
  assert.deepEqual(ids(pinnedFirst(vaults, [], undefined, active)), ["family", "home", "eng", "support"]);
});

test("vaults on this PC are matched by the vault id inside their file", () => {
  const local = [{ id: "a", vault_id: "v1", active: false }, { id: "b", vault_id: null, active: true }, { id: "c", vault_id: "v3", active: false }];
  assert.deepEqual(ids(pinnedFirst(local, ["v3"], (v) => v.vault_id)), ["c", "a", "b"]);
  assert.deepEqual(ids(pinnedFirst(local, ["v3"], (v) => v.vault_id, (v) => v.active)), ["b", "c", "a"]);
});

test("a new pin goes last; unpinning keeps the rest and the pins this PC doesn't show", () => {
  assert.deepEqual(togglePin(["gone", "eng"], "home", true, ids(vaults)), { pins: ["gone", "eng", "home"] });
  assert.deepEqual(togglePin(["gone", "eng", "home"], "eng", false, ids(vaults)), { pins: ["gone", "home"] });
  assert.deepEqual(togglePin(["eng"], "eng", true, ids(vaults)), { pins: ["eng"] });
  assert.deepEqual(togglePin([], "eng", false, ids(vaults)), { pins: [] });
});

test("a sixth pin is refused; pins of vaults not shown here don't count", () => {
  const five = ["a", "b", "c", "d", "e"];
  assert.equal(MAX_PINS, 5);
  assert.deepEqual(togglePin(five, "f", true, [...five, "f"]), { full: true });
  assert.deepEqual(togglePin(["gone", "a", "b", "c", "d"], "e", true, five), { pins: ["gone", "a", "b", "c", "d", "e"] });
});

test("the locked list gets the pins of the vault that was open last, and only that one's", () => {
  const data = new Map();
  const storage = { getItem: (k) => (data.has(k) ? data.get(k) : null), setItem: (k, v) => data.set(k, String(v)) };
  assert.deepEqual(lastPins("v-personal", storage), []);
  rememberPins("v-personal", ["sv-eng", "v-side"], storage);
  assert.deepEqual(lastPins("v-personal", storage), ["sv-eng", "v-side"]);
  assert.deepEqual(lastPins("v-side", storage), []);
  data.set("passyble.pins.last", "not json");
  assert.deepEqual(lastPins("v-personal", storage), []);
  // No storage at all (a test, a private window): nothing remembered, nothing thrown.
  rememberPins("v-personal", ["sv-eng"], null);
  assert.deepEqual(lastPins("v-personal", null), []);
});
