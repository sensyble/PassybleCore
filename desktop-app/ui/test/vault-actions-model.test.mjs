// node --test Core/desktop-app/ui/test/*.test.mjs
// A vault's own menu and the typed name that confirms "Delete vault from your account".
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { canExportFirst, deleteNameConfirmed, vaultActionKeys } from "../views/vault-actions-model.js";

test("every vault can be renamed, shown and removed; only account vaults can be deleted", () => {
  assert.deepEqual(vaultActionKeys({ id: "a", name: "Personal" }), ["rename", "reveal", "remove"]);
  assert.deepEqual(vaultActionKeys({ id: "a", account_vault: "u-abc/personal", account_deletable: false }), ["rename", "reveal", "remove"]);
  assert.deepEqual(vaultActionKeys({ id: "b", account_vault: "u-abc/v-1", account_deletable: true }), ["rename", "reveal", "remove", "delete_account"]);
  assert.deepEqual(vaultActionKeys(null), []);
});

test("the vault's name confirms the delete, ignoring case and spaces around it", () => {
  assert.equal(deleteNameConfirmed(" work ", "Work"), true);
  assert.equal(deleteNameConfirmed("Wor", "Work"), false);
  assert.equal(deleteNameConfirmed("", ""), false);
  assert.equal(deleteNameConfirmed(undefined, "Work"), false);
});

test("Export first only for the open, unlocked vault", () => {
  assert.equal(canExportFirst({ active: true }, false), true);
  assert.equal(canExportFirst({ active: true }, true), false);
  assert.equal(canExportFirst({ active: false }, false), false);
});

test("the vault switcher always ends with Add vault and no list-only page is left", () => {
  const vault = readFileSync(new URL("../views/vault.js", import.meta.url), "utf8");
  const main = readFileSync(new URL("../main.js", import.meta.url), "utf8");
  assert.match(vault, /t\("vault\.add_vault"\), \(\) => this\.addVault\(\)/);
  assert.doesNotMatch(vault, /manage_vaults|pass-switch-vault/);
  assert.doesNotMatch(main, /showList|pass-switch-vault/);
  assert.match(main, /"pass-add-vault"/);
});
