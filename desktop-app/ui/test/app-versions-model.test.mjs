// node --test Core/desktop-app/ui/test/*.test.mjs (Node 22 or later)
// What the main window shows for the version requirements: "Update required" and a read-only bar
// below the minimum, "Update available" below the recommended version, nothing otherwise.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { appVersionsView, messageText } from "../views/app-versions-model.js";

const required = { state: "required", current: "0.1.0", minimum: "0.2.0", message: "Security fix", self_update: true };

test("below the minimum: the screen first, then the read-only bar after View my passwords", () => {
  const view = appVersionsView(required);
  assert.equal(view.screen, true);
  assert.equal(view.bar, true);
  assert.equal(view.banner, null);
  assert.equal(view.minimum, "0.2.0");
  assert.equal(view.current, "0.1.0");
  assert.equal(view.message, "Security fix");
  const viewing = appVersionsView(required, true);
  assert.equal(viewing.screen, false);
  assert.equal(viewing.bar, true, "the bar stays while the vault is read-only");
});

test("below the recommended version: a bar until it is closed for that version", () => {
  const status = { state: "recommended", version: "0.3.0", message: null, dismissed: false };
  assert.deepEqual(appVersionsView(status), { screen: false, bar: false, banner: { version: "0.3.0", message: "" } });
  assert.deepEqual(appVersionsView({ ...status, dismissed: true }), { screen: false, bar: false, banner: null });
});

test("no requirement, no data or anything malformed shows nothing", () => {
  const none = { screen: false, bar: false, banner: null };
  for (const status of [null, undefined, "required", 5, {}, { state: "none" }, { state: "blocked" }, { state: "recommended" }]) {
    assert.deepEqual(appVersionsView(status), none, JSON.stringify(status));
  }
});

test("the admin's message is plain text cut to 280 characters", () => {
  assert.equal(messageText("  Update\n\tnow "), "Update now");
  assert.equal(messageText(null), "");
  assert.equal(messageText(42), "");
  assert.equal([...messageText("é".repeat(400))].length, 280);
  assert.equal(messageText("<img src=x onerror=alert(1)>"), "<img src=x onerror=alert(1)>");
});

test("the view never puts the message in as markup", () => {
  const src = readFileSync(new URL("../views/app-versions.js", import.meta.url), "utf8");
  assert.doesNotMatch(src, /innerHTML|insertAdjacentHTML|outerHTML/);
  assert.match(src, /text: view\.message/);
});
