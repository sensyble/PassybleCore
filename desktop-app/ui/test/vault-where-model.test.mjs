// node --test Core/desktop-app/ui/test/*.test.mjs
// The caption under a vault's name: plain words, never a path or UUID.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { folderLabel, vaultWhere } from "../views/vault-where-model.js";

const uuid = "C:/Users/a/AppData/Local/Pass/vaults/e06be1c1-c3a4-416a-86a9-b2fa835eb159.vault";

test("a Passyble Server on this PC", () => {
  for (const host of ["127.0.0.1", "::1", "localhost", "pass.localhost"]) {
    assert.deepEqual(vaultWhere({ webdav_host: host, path: uuid, managed: true }), { key: "vaultwhere.server_this_pc", params: {} });
  }
});

test("a server on the home or office network", () => {
  for (const host of ["192.168.1.20", "10.0.0.5", "172.16.4.1", "172.31.0.1", "nas", "box.local", "pass.lan", "x.home.arpa", "169.254.1.1"]) {
    assert.deepEqual(vaultWhere({ webdav_host: host }), { key: "vaultwhere.network", params: { host } }, host);
  }
});

test("a public host is shown by name alone", () => {
  for (const host of ["pass.example.com", "172.32.0.1", "8.8.8.8"]) {
    assert.deepEqual(vaultWhere({ webdav_host: host }), { key: "vaultwhere.host", params: { host } }, host);
  }
});

test("Google Drive keeps the account", () => {
  assert.deepEqual(vaultWhere({ google_email: "a@b.c", path: uuid, managed: true }), { key: "unlock.google_backup", params: { email: "a@b.c" } });
});

test("a vault in the app's own storage", () => {
  assert.deepEqual(vaultWhere({ path: uuid, managed: true }), { key: "vaultwhere.this_pc", params: {} });
});

test("a vault in a folder the user chose", () => {
  assert.deepEqual(vaultWhere({ path: "C:/Users/a/OneDrive - Work/Pass/pass.vault" }), { key: "vaultwhere.folder", params: { folder: "OneDrive" } });
  assert.equal(folderLabel("C:/Users/a/Dropbox/x/pass.vault"), "Dropbox");
  assert.equal(folderLabel("/home/a/Syncthing/pass.vault"), "Syncthing");
  assert.equal(folderLabel("E:/Backups/Keys/pass.vault"), "Keys");
  assert.equal(folderLabel("E:/pass.vault"), "E:");
  const w = vaultWhere({ path: "E:/Backups/Keys/pass.vault" });
  assert.ok(!JSON.stringify(w).includes("pass.vault"));
});

test("the views use the helper and the keys exist in every catalog", () => {
  const unlock = readFileSync(new URL("../views/unlock.js", import.meta.url), "utf8");
  assert.ok(unlock.includes("whereText(vault, t)"));
  for (const loc of ["en", "de", "es", "fr", "hi", "id", "ja", "ko", "zh-CN"]) {
    const c = JSON.parse(readFileSync(new URL(`../i18n/${loc}.json`, import.meta.url), "utf8"));
    for (const k of ["server_this_pc", "network", "host", "this_pc", "folder"]) assert.ok(c[`vaultwhere.${k}`], `${loc} ${k}`);
    assert.equal(c["unlock.synced_with"], undefined);
  }
});
