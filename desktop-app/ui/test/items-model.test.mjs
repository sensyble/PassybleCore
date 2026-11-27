// node --test Core/desktop-app/ui/test/*.test.mjs (Node 22 or later)
// The pure part of cards, identities, tags, trash, password health and security activity.
import assert from "node:assert/strict";
import test from "node:test";

import {
  ageText,
  breachText,
  cardExpired,
  cardLabel,
  eventText,
  expiryText,
  hasTag,
  identityName,
  initials,
  matchesFilter,
  purgeText,
  rowSubtitle,
  strengthText,
  tagKey,
  tagTree,
} from "../views/items-model.js";

const DAY = 24 * 60 * 60 * 1000;

test("cards: expiry, label, expired", () => {
  assert.equal(expiryText(3, 2031), "03/31");
  assert.equal(expiryText(12, 2000), "12/00");
  assert.equal(expiryText(0, 0), "");
  assert.equal(expiryText(7, 0), "07");
  assert.equal(cardLabel({ brand_name: "Visa", last4: "1111" }), "Visa •••• 1111");
  assert.equal(cardLabel({ brand_name: "", last4: "1111" }), "Card •••• 1111");
  assert.equal(cardLabel({ brand_name: "Mastercard", last4: "" }), "Mastercard");
  assert.equal(cardLabel(null), "Card");
  const now = new Date(2026, 9, 14); // October 2026
  assert.equal(cardExpired(9, 2026, now), true);
  assert.equal(cardExpired(10, 2026, now), false);
  assert.equal(cardExpired(1, 2027, now), false);
  assert.equal(cardExpired(12, 2025, now), true);
  assert.equal(cardExpired(0, 2020, now), false);
});

test("identities: names and initials", () => {
  assert.equal(initials("Ada King Lovelace"), "AL");
  assert.equal(initials("ada"), "A");
  assert.equal(initials("  "), "");
  assert.equal(identityName({ first_name: "Ada", middle_name: "", last_name: "Lovelace" }), "Ada Lovelace");
  assert.equal(identityName({ full_name: "Ada Lovelace", first_name: "x" }), "Ada Lovelace");
  assert.equal(identityName(null), "");
});

test("tags nest with / and match case-insensitively", () => {
  assert.equal(tagKey(" /Work / Clients/ "), "work/clients");
  assert.equal(hasTag(["Work/Clients"], "work"), true);
  assert.equal(hasTag(["Work/Clients"], "WORK/clients"), true);
  assert.equal(hasTag(["Workshop"], "work"), false);
  assert.equal(hasTag(["Work"], "work/clients"), false);
  assert.equal(hasTag([], "work"), false);
  assert.equal(hasTag(["Work"], ""), false);
});

test("the tag tree lists parents, children indented after them, with counts", () => {
  const items = [
    { tags: ["Work/Clients"] },
    { tags: ["work"] },
    { tags: ["Work/Admin", "Personal"] },
    { tags: [] },
    { tags: ["Personal/Health"] },
  ];
  const tree = tagTree(items);
  assert.deepEqual(tree.map((n) => [n.tag, n.depth, n.count]), [
    ["Personal", 0, 2],
    ["Personal/Health", 1, 1],
    ["Work", 0, 3],
    ["Work/Admin", 1, 1],
    ["Work/Clients", 1, 1],
  ]);
  assert.equal(tree.find((n) => n.tag === "Work/Clients").name, "Clients");
  assert.deepEqual(tagTree([]), []);
});

test("quick filters and row subtitles", () => {
  const card = { kind: "card", title: "Visa •••• 1111", card: { brand_name: "Visa", last4: "1111", expiry_month: 3, expiry_year: 2031 } };
  const person = { kind: "identity", title: "Me", identity: { full_name: "Ada Lovelace", email: "ada@example.com" } };
  const named = { kind: "identity", title: "Ada Lovelace", identity: { full_name: "Ada Lovelace", email: "ada@example.com" } };
  assert.equal(rowSubtitle(card), "Visa •••• 1111 · 03/31");
  assert.equal(rowSubtitle(person), "Ada Lovelace");
  assert.equal(rowSubtitle(named), "ada@example.com");
  assert.equal(rowSubtitle({ kind: "note" }), "Secure note");
  assert.equal(rowSubtitle({ kind: "login", username: "octo", url: "https://x" }), "octo");
  assert.equal(matchesFilter(card, "cards"), true);
  assert.equal(matchesFilter(card, "identities"), false);
  assert.equal(matchesFilter(person, "identities"), true);
  assert.equal(matchesFilter(card, "all"), true);
  assert.equal(matchesFilter({ kind: "login", has_totp: true }, "totp"), true);
});

test("trash and health texts", () => {
  const now = 1_800_000_000_000;
  const thirty = 30 * DAY;
  assert.equal(purgeText(now, thirty, now), "Removed for good in 30 days");
  assert.equal(purgeText(now - 29 * DAY, thirty, now), "Removed for good tomorrow");
  assert.equal(purgeText(now - 30 * DAY, thirty, now), "Removed for good today");
  assert.equal(purgeText(null, thirty, now), "");
  assert.equal(strengthText(0), "Very weak");
  assert.equal(strengthText(4), "Strong");
  assert.equal(strengthText(9), "Strong");
  assert.equal(ageText(now - 3 * DAY, now), "3 days ago");
  assert.equal(ageText(now - 400 * DAY, now), "13 months ago");
  assert.equal(ageText(now - 1000 * DAY, now), "2 years ago");
  assert.equal(breachText(0), "Not found in known breaches");
  assert.equal(breachText(1), "Found 1 time in data breaches");
  assert.equal(breachText(30210), "Found 30,210 times in data breaches");
});

test("security events in plain words", () => {
  assert.deepEqual(eventText({ event: "sign_in", actor: "user", detail: "totp" }), {
    title: "Signed in", detail: "with an authenticator code", warn: false, admin: false,
  });
  const failed = eventText({ event: "sign_in_failed", actor: "anonymous", detail: "2fa" });
  assert.equal(failed.title, "Failed sign-in");
  assert.equal(failed.detail, "wrong two-factor code");
  assert.equal(failed.warn, true);
  const changed = eventText({ event: "password_changed", actor: "user", detail: "old_password", count: 2 });
  assert.equal(changed.detail, "with the old password · 2 other devices signed out");
  const admin = eventText({ event: "admin_password_reset", actor: "admin", count: 1 });
  assert.equal(admin.admin, true);
  assert.equal(admin.detail, "1 other device signed out");
  assert.equal(eventText({ event: "2fa_recovery_code_used", actor: "user", count: 3 }).detail, "3 recovery codes left");
  assert.equal(eventText({ event: "brand_new_thing", actor: "server" }).title, "Brand new thing");
});
