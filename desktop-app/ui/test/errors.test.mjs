// node --test Core/desktop-app/ui/test/*.test.mjs (Node 22 or later)
// What the windows show for an error: own sentences as they are, known core texts mapped, and
// nothing technical (exceptions, transport errors, OS errors, HRESULTs) ever on screen.
import assert from "node:assert/strict";
import test from "node:test";

import { friendlyError, isHelloCancelled, LOCKED_ERROR } from "../errors.js";
import { t } from "../i18n.js";

const GENERIC = t("errors.generic");

// The detail goes to the console; keep the test output quiet.
console.warn = () => {};

test("sentences from Rust and the windows are shown as they are", () => {
  assert.equal(friendlyError(t("errors.file_not_saved")), t("errors.file_not_saved"));
  assert.equal(friendlyError(new Error(t("errors.password_too_short"))), t("errors.password_too_short"));
  const missing = t("errors.path_missing", { path: "C:\\Users\\me\\Documents\\pass.vault" });
  assert.equal(friendlyError(missing), missing);
  assert.equal(friendlyError(t("errors.cant_reach_host", { host: "[::1]:8443" })), t("errors.cant_reach_host", { host: "[::1]:8443" }));
});

test("known core and agent texts are mapped", () => {
  assert.equal(friendlyError(LOCKED_ERROR), t("errors.vault_locked"));
  assert.equal(friendlyError("wrong master password"), t("errors.wrong_master_password"));
  assert.equal(
    friendlyError("network error: sign in: https://pass.example.com/api: Dns Failed"),
    t("errors.cant_reach_host", { host: "pass.example.com" }),
  );
});

test("technical text never reaches the screen", () => {
  for (const raw of [
    new TypeError("Cannot read properties of undefined (reading 'id')"),
    new ReferenceError("foo is not defined"),
    "invalid args `email` for command `google_sign_in`: command google_sign_in missing required key email",
    "command google_drive_vaults not found",
    "Access is denied. (os error 5)",
    "WebAuthNPluginAddAuthenticator: The parameter is incorrect. (0x80070057)",
    "called `Option::unwrap()` on a `None` value",
    "serde_json::Error: expected value at line 1 column 1",
    "failed to deserialize: std::io::Error",
    undefined,
    null,
    {},
    "",
  ]) {
    assert.equal(friendlyError(raw), GENERIC, String(raw && raw.message ? raw.message : raw));
  }
});

test("a cancelled Windows Hello is told apart from a real failure", () => {
  assert.equal(isHelloCancelled(t("errors.hello_cancelled")), true);
  assert.equal(isHelloCancelled(new Error(t("errors.hello_verification_cancelled"))), true);
  assert.equal(isHelloCancelled(t("errors.hello_failed")), false);
  assert.equal(isHelloCancelled(t("errors.hello_invalidated")), false);
  assert.equal(isHelloCancelled("wrong master password"), false);
  assert.equal(isHelloCancelled(""), false);
  assert.equal(isHelloCancelled(null), false);
});
