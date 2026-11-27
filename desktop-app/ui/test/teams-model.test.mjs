// node --test Core/desktop-app/ui/test/*.test.mjs (Node 22 or later)
// The pure part of Teams and Family: what roles allow, the vault filter and the "Save in" choice,
// fingerprints compared by eye, CSV invites, the access matrix. Demo data only.
import assert from "node:assert/strict";
import test from "node:test";

import {
  compareFingerprints, defaultSaveVault, filterByVault, fingerprintGroups, fingerprintsMatch, itemCaps,
  saveVaultChoices, shareTargets, showVaultNames, validVaultFilter,
} from "../views/teams-model.js";
import { changedAccess, csvInviteRows, csvPreview, grantRole, parseCsv, setGrant, ssoReady, validEmail } from "../views/admin-model.js";

const HOME = { id: "home", name: "Personal", home: true, kind: "personal", role: null, can_edit: true, can_reveal: true };
const ENG = { id: "eng", name: "Engineering", home: false, kind: "org", role: "edit", can_edit: true, can_reveal: true };
const VIEW = { id: "sup", name: "Support", home: false, kind: "org", role: "view", can_edit: false, can_reveal: true };
const FILL = { id: "dep", name: "Deploy", home: false, kind: "org", role: "fill", can_edit: false, can_reveal: false };

test("roles decide what an item allows", () => {
  assert.deepEqual(itemCaps({ vault: ENG }), { edit: true, reveal: true, readOnly: false, fillOnly: false, role: "edit" });
  assert.deepEqual(itemCaps({ vault: VIEW }), { edit: false, reveal: true, readOnly: true, fillOnly: false, role: "view" });
  assert.deepEqual(itemCaps({ vault: FILL }), { edit: false, reveal: false, readOnly: true, fillOnly: true, role: "fill" });
  // The backend hid the password: fill only, whatever the vault says.
  assert.equal(itemCaps({ vault: ENG, password_hidden: true }).fillOnly, true);
  assert.equal(itemCaps({ id: "x" }).edit, true);
});

test("the list's vault filter and the Save in choice", () => {
  const vaults = [ENG, HOME, VIEW, FILL];
  assert.equal(showVaultNames([HOME]), false);
  assert.equal(showVaultNames(vaults), true);
  const items = [{ id: "1", vault_id: "eng" }, { id: "2", vault_id: "home" }];
  assert.deepEqual(filterByVault(items, "eng").map((i) => i.id), ["1"]);
  assert.equal(filterByVault(items, null).length, 2);
  assert.equal(validVaultFilter("gone", vaults), null);
  assert.deepEqual(saveVaultChoices(vaults).map((v) => v.id), ["home", "eng"]);
  assert.equal(defaultSaveVault(vaults), "home");
  assert.equal(defaultSaveVault(vaults, "eng"), "eng");
  assert.equal(defaultSaveVault(vaults, "sup"), "home", "a view vault takes nothing");
});

test("move and copy targets follow the roles", () => {
  const vaults = [HOME, ENG, VIEW, FILL];
  assert.deepEqual(shareTargets({ vault_id: "home", vault: HOME }, vaults, "move").map((v) => v.id), ["eng"]);
  assert.deepEqual(shareTargets({ vault_id: "sup", vault: VIEW }, vaults, "move"), [], "a viewer can't move");
  assert.deepEqual(shareTargets({ vault_id: "sup", vault: VIEW }, vaults, "copy").map((v) => v.id), ["home", "eng"]);
  assert.deepEqual(shareTargets({ vault_id: "dep", vault: FILL }, vaults, "copy"), [], "fill only never leaves");
});

test("fingerprints compared by eye, in the apps' groups of five", () => {
  const fp = "7K3QD-M2XPA-9TRWE-4HB7N-QZ2KC-81V5S";
  assert.deepEqual(fingerprintGroups(fp), ["7K3QD", "M2XPA", "9TRWE", "4HB7N", "QZ2KC", "81V5S"]);
  assert.equal(fingerprintsMatch(fp, "7k3qd m2xpa 9trwe 4hb7n qz2kc 81v5s"), true);
  assert.equal(fingerprintsMatch("", ""), false);
  const partial = compareFingerprints(fp, "7K3QD M2XPA");
  assert.deepEqual([partial.complete, partial.match], [false, false]);
  const wrong = compareFingerprints(fp, "7K3QD M2XPA 9TRWE 4HB7N QZ2KC 81V5T");
  assert.deepEqual([wrong.complete, wrong.match, wrong.groups[5].match], [true, false, false]);
  assert.equal(compareFingerprints(fp, fp).match, true);
});

test("CSV invites: header, separators, problems, the service's preview", () => {
  assert.deepEqual(parseCsv('a;b\n"x;y";z\r\n'), [["a", "b"], ["x;y", "z"]]);
  const rows = csvInviteRows("email,role,departments\nkim@example.com,admin,dep_a|dep_b\nnot-an-address\nKIM@example.com\n");
  assert.deepEqual(rows.map((r) => [r.line, r.email, r.role, r.problem]), [
    [2, "kim@example.com", "admin", ""], [3, "not-an-address", "member", "invalid_email"], [4, "KIM@example.com", "member", "duplicate"],
  ]);
  assert.deepEqual(rows[0].departments, ["dep_a", "dep_b"]);
  const preview = csvPreview(rows, { rows: [{ email: "kim@example.com", state: "over_seats" }] });
  assert.deepEqual(preview.rows.map((r) => r.state), ["over_seats", "invalid_email", "duplicate"]);
  assert.equal(preview.invite, 0);
  assert.equal(validEmail(" a@b.co "), true);
});

test("the access matrix: grants set, removed and compared", () => {
  let grants = [{ everyone: true, role: "view" }];
  grants = setGrant(grants, "department:dep_eng", "edit");
  grants = setGrant(grants, "account:acc_bob", "fill");
  assert.equal(grantRole(grants, "department:dep_eng"), "edit");
  grants = setGrant(grants, "everyone", null);
  assert.equal(grantRole(grants, "everyone"), null);
  const changed = changedAccess({ v1: [{ account: "acc_bob", role: "fill" }], v2: [] }, { v1: [{ account: "acc_bob", role: "fill" }], v2: grants });
  assert.deepEqual(changed.map((c) => c.vaultId), ["v2"]);
});

test("policies are edited under the service's stored names", async () => {
  const { policyChange, policyFields, policyForm } = await import("../views/admin-model.js");
  assert.deepEqual(policyFields("family"), ["strong_master_password", "share_outside"]);
  assert.ok(policyFields("team").includes("sso_required") && policyFields("team").includes("admin_recovery"));
  const stored = { min_password_score: 3, sign_in: "strong", max_auto_lock_minutes: 15, export_allowed: true, share_outside: false };
  const form = policyForm(stored, "team");
  assert.equal(form.sign_in, "strong");
  assert.equal(form.send_allowed, true, "on unless turned off");
  assert.equal(form.device_approval, false);
  assert.deepEqual(policyChange(stored, form, "team"), {});
  assert.deepEqual(policyChange(stored, { ...form, max_auto_lock_minutes: null, sso_required: true }, "team"),
    { max_auto_lock_minutes: 0, sso_required: true });
  assert.equal(policyForm({ min_password_score: 3 }, "family").strong_master_password, true);
  assert.deepEqual(policyChange({ min_password_score: 3 }, { strong_master_password: false, share_outside: false }, "family"),
    { strong_master_password: false });
});

test("the owner can hand the organisation to an active admin", async () => {
  const { memberActions } = await import("../views/admin-model.js");
  const admin = { account_id: "acc_b", role: "admin", status: "active", keys: { fingerprint: "x" } };
  assert.ok(memberActions(admin, { me: "acc_a", myRole: "owner" }).includes("make_owner"));
  assert.ok(!memberActions(admin, { me: "acc_c", myRole: "admin" }).includes("make_owner"));
  assert.ok(!memberActions({ ...admin, role: "member" }, { me: "acc_a", myRole: "owner" }).includes("make_owner"));
});

test("emergency access: the owner sets up an accepted contact, an invited contact accepts", async () => {
  const { emergencyState } = await import("../views/teams-model.js");
  assert.ok(emergencyState({ state: "accepted" }, "owner").actions.includes("setup"));
  assert.ok(emergencyState({ state: "invited" }, "contact").actions.includes("accept"));
  assert.ok(emergencyState({ state: "available" }, "contact").actions.includes("open"));
});

test("the SSO switch shows only when the service says single sign-on is ready", () => {
  assert.equal(ssoReady({ sso: { ready: true, protocol: "oidc" } }), true);
  assert.equal(ssoReady({ sso: { ready: false, protocol: null } }), false);
  assert.equal(ssoReady(null, { sso: { ready: true, protocol: "saml" } }), true);
  assert.equal(ssoReady({ policy: {} }, {}), false);
  assert.equal(ssoReady(), false);
});

test("emergency access: a requested grant opens at release_at (milliseconds)", async () => {
  const { emergencyState } = await import("../views/teams-model.js");
  const now = 1_700_000_000_000;
  const open = emergencyState({ state: "requested", release_at: now - 1000 }, "contact", now);
  assert.ok(open.actions.includes("open"));
  const waiting = emergencyState({ state: "requested", release_at: now + 86_400_000 }, "contact", now);
  assert.ok(!waiting.actions.includes("open"));
});

test("a Team's password rules leave its vaults out of sharing and say what to do", async () => {
  const { attentionCount, directShareAllowed, passwordNotices, policyLines } = await import("../views/teams-model.js");
  const vaults = [HOME, ENG];
  const item = { vault_id: "home", vault: HOME };
  assert.deepEqual(shareTargets(item, vaults, "copy", ["eng"]), [], "the Team's vault is left out");
  assert.deepEqual(shareTargets(item, vaults, "copy", []).map((v) => v.id), ["eng"]);
  assert.equal(directShareAllowed(null), true, "no Team");
  assert.equal(directShareAllowed({ direct_share: false }), false);
  const second = { mode: "second_password", action_needed: true, title: "Required", message: "Give Personal its own password.", home: { id: "home", name: "Personal" } };
  assert.deepEqual(passwordNotices(second).map((n) => [n.kind, n.text, n.vault.id]), [["second", "Give Personal its own password.", "home"]]);
  assert.deepEqual(passwordNotices({ ...second, action_needed: false }), [], "met: nothing to do");
  const one = { mode: "one_password", action_needed: true, own_password: [{ id: "v1", name: "Old" }, { id: "v2", name: "Older" }] };
  assert.deepEqual(passwordNotices(one).map((n) => n.vault.id), ["v1", "v2"]);
  assert.deepEqual(passwordNotices({ mode: "choice", action_needed: false }), []);
  assert.equal(attentionCount({ visible: true, password_policy: one }), 2);
  assert.equal(policyLines({ password_mode: "second_password" }, "team").length, 1);
  assert.deepEqual(policyLines({ password_mode: "choice" }, "team"), []);
  assert.deepEqual(policyLines({ password_mode: "one_password" }, "family"), [], "a Family has no password rules");
});

test("admins set a Team's password mode and one per member", async () => {
  const { memberActions, memberPasswordChoices, policyChange, policyFields, policyForm } = await import("../views/admin-model.js");
  assert.ok(policyFields("team").includes("password_mode"));
  assert.ok(!policyFields("family").includes("password_mode"));
  assert.equal(policyForm({}, "team").password_mode, "choice", "a missing key is the member's choice");
  assert.equal(policyForm({ password_mode: "later_mode" }, "team").password_mode, "choice");
  const stored = { password_mode: "choice" };
  assert.deepEqual(policyChange(stored, { ...policyForm(stored, "team"), password_mode: "one_password" }, "team"), { password_mode: "one_password" });
  const label = (m) => `<${m}>`;
  assert.deepEqual(memberPasswordChoices("second_password", label).map(([v]) => v), [null, "choice", "second_password", "one_password"]);
  assert.ok(memberPasswordChoices("second_password", label)[0][1].includes("<second_password>"));
  const member = { account_id: "acc_b", role: "member", status: "active" };
  assert.ok(memberActions(member, { me: "acc_a", myRole: "admin" }).includes("passwords"));
  assert.ok(!memberActions(member, { me: "acc_a", myRole: "admin", kind: "family" }).includes("passwords"));
  assert.ok(!memberActions({ ...member, status: "invited" }, { me: "acc_a", myRole: "owner" }).includes("passwords"));
  assert.ok(!memberActions({ ...member, role: "owner" }, { me: "acc_a", myRole: "admin" }).includes("passwords"), "only the owner sets the owner's");
  assert.ok(memberActions({ ...member, account_id: "acc_a", role: "owner" }, { me: "acc_a", myRole: "owner" }).includes("passwords"));
});

test("pinned contact keys: the service's confirmed flag alone doesn't make a member confirmed here", async () => {
  const { keyState, memberActions } = await import("../views/admin-model.js");
  const fp = "7K3QD-M2XPA-0000A";
  const member = { account_id: "acc_bob", role: "member", status: "active", keys: { fingerprint: fp, confirmed: true } };
  // Compared on this device (or the pins say nothing): confirmed.
  assert.equal(keyState({ ...member, pin: "pinned" }), "confirmed");
  assert.equal(keyState(member), "confirmed");
  // The service says confirmed, this admin never compared: compare first, nobody gets access from here.
  assert.equal(keyState({ ...member, pin: "not_verified" }), "to_compare");
  assert.ok(memberActions({ ...member, pin: "not_verified" }, { me: "acc_a", myRole: "admin" }).includes("confirm"));
  // The service hands out other keys than the ones compared: changed, whatever it says.
  assert.equal(keyState({ ...member, pin: "changed", pinned_fingerprint: "OLD" }), "changed");
  assert.ok(memberActions({ ...member, pin: "changed" }, { me: "acc_a", myRole: "owner" }).includes("confirm"));
  assert.ok(!memberActions({ ...member, pin: "pinned" }, { me: "acc_a", myRole: "owner" }).includes("confirm"));
  assert.equal(keyState({ account_id: "acc_c", keys: { fingerprint: fp } }), "to_confirm");
});

test("pinned contact keys: who to compare, changed keys first, and what the vault's signer is", async () => {
  const { attentionCount, compareList, signerState } = await import("../views/teams-model.js");
  const list = compareList([
    { account: "acc_bob", fingerprint: "A", status: "not_verified" },
    { account: "acc_eve", fingerprint: "B", status: "changed", pinned_fingerprint: "C" },
    { account: "", fingerprint: "D" },
  ]);
  assert.deepEqual(list.map((c) => c.account), ["acc_eve", "acc_bob"]);
  assert.deepEqual(compareList({ account: "acc_bob", fingerprint: "A" }).map((c) => c.account), ["acc_bob"]);
  assert.deepEqual(compareList(null), []);
  assert.equal(signerState({ signer_status: "pinned" }).state, "verified");
  assert.equal(signerState({ signer_status: "not_verified" }).state, "not_verified");
  assert.equal(signerState({ signer_status: "changed" }).state, "changed");
  assert.match(signerState({ signer_status: "changed" }).cls, /danger/);
  assert.equal(signerState({}).state, null);
  // A vault signed with keys other than the ones compared needs the user.
  const overview = { visible: true, vaults: [{ signer_status: "changed" }, { signer_status: "pinned" }] };
  assert.equal(attentionCount(overview), 1);
});
