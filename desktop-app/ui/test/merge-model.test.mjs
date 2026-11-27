// node --test Core/desktop-app/ui/test/*.test.mjs (Node 22 or later)
// The pure part of the merge sheet, the list's multi-select and the suggestions.
import assert from "node:assert/strict";
import test from "node:test";

import {
  APP_PIN,
  deletedText,
  favoriteLabel,
  favoritesText,
  favoriteTarget,
  fieldRows,
  hintText,
  mergePicks,
  pairKey,
  pickedTitle,
  pendingSuggestions,
  pickerRows,
  pruneSelected,
  restoredText,
  selectRange,
  toggleSelected,
  unionRows,
} from "../views/merge-model.js";

/** A `merge_preview` answer for a login (A) and an authenticator entry (B). */
function preview(overrides = {}) {
  return {
    plan: {
      fields: [
        { field: "title", state: "same" },
        { field: "username", state: "differs" },
        { field: "password", state: "only_a" },
        { field: "totp", state: "only_b" },
        { field: "notes", state: "differs" },
      ],
      default_primary: "a",
      urls: 2,
      android_apps: 0,
      passkeys: 1,
    },
    picks: { primary: "a", title: "a", username: "b", password: "a", totp: "b", notes: "both" },
    history_added: 0,
    totp_noted: false,
    a: { id: "1", title: "GitHub", urls: ["https://github.com"], passkeys: [], android_apps: [] },
    b: {
      id: "2",
      title: "GitHub 2FA",
      urls: ["https://gist.github.com"],
      passkeys: [{ user_name: "me", rp_id: "github.com" }],
      android_apps: [],
    },
    result: { urls: ["https://github.com", "https://gist.github.com"], passkeys: [{}], android_apps: [] },
    ...overrides,
  };
}

test("field rows follow the plan and the picks", () => {
  const rows = fieldRows(preview());
  assert.deepEqual(rows.map((r) => r.field), ["title", "username", "password", "totp", "notes"]);
  const by = Object.fromEntries(rows.map((r) => [r.field, r]));
  assert.equal(by.title.same, true);
  assert.equal(by.title.choosable, false);
  assert.equal(by.username.choosable, true);
  assert.equal(by.username.pick, "b");
  assert.equal(by.password.kept, "a");
  assert.equal(by.password.secret, true);
  assert.equal(by.totp.kept, "b");
  assert.equal(by.notes.both, true);
  assert.equal(by.notes.pick, "both");
  assert.equal(by.username.both, false);
  assert.equal(by.title.renamable, true);
  assert.equal(by.username.renamable, false);
});

test("the title row always shows, with a Custom pick while the custom title is on", () => {
  const p = preview();
  p.plan.fields[0] = { field: "title", state: "empty" };
  const title = (rows) => rows.find((r) => r.field === "title");
  assert.equal(title(fieldRows(p)).renamable, true);
  assert.equal(title(fieldRows(p)).choosable, false);
  p.plan.fields[0] = { field: "title", state: "differs" };
  assert.equal(title(fieldRows(p)).choosable, true);
  assert.equal(title(fieldRows(p)).pick, "a");
  assert.equal(title(fieldRows(p, {}, { on: false })).pick, "a");
  assert.equal(title(fieldRows(p, { title: "b" }, { on: false })).pick, "b");
  assert.equal(title(fieldRows(p, { title: "b" }, { on: true })).pick, "custom");
  const user = fieldRows(p, {}, { on: true }).find((r) => r.field === "username");
  assert.equal(user.pick, "b", "only the title row is affected");
});

test("the custom title starts as the picked title, or the other when that is blank", () => {
  const p = preview();
  assert.equal(pickedTitle(p), "GitHub");
  assert.equal(pickedTitle(p, { title: "b" }), "GitHub 2FA");
  p.a.title = "  ";
  assert.equal(pickedTitle(p), "GitHub 2FA");
  p.picks.title = "b";
  p.b.title = "";
  assert.equal(pickedTitle(p), "");
});

test("merge picks carry the custom title only while it is on and has text", () => {
  const chosen = { username: "a", title: "b" };
  assert.deepEqual(mergePicks(chosen), chosen);
  assert.deepEqual(mergePicks(chosen, { on: false, text: "Mine" }), chosen);
  assert.deepEqual(mergePicks(chosen, { on: true, text: "   " }), chosen);
  assert.deepEqual(mergePicks(chosen, { on: true, text: "" }), chosen);
  assert.deepEqual(mergePicks(chosen, { on: true, text: "  Mine  " }), { ...chosen, custom_title: "Mine" });
  assert.deepEqual(chosen, { username: "a", title: "b" }, "the picks are not changed");
});

test("fields neither item has are left out", () => {
  const p = preview();
  p.plan.fields[4] = { field: "notes", state: "empty" };
  assert.ok(!fieldRows(p).some((r) => r.field === "notes"));
});

test("union rows list each side and the total", () => {
  const rows = unionRows(preview());
  assert.deepEqual(rows.map((r) => r.key), ["urls", "passkeys"]);
  assert.deepEqual(rows[0].a, ["https://github.com"]);
  assert.deepEqual(rows[1].b, ["me · github.com"]);
  assert.equal(rows[0].total, 2);
});

test("app pins show as desktop apps, websites as they are", () => {
  const p = preview();
  p.a.urls = ["windows:putty.exe", "macos:com.apple.Terminal", "MacOS:com.example.App", "macos.example.com"];
  const rows = unionRows(p);
  assert.deepEqual(rows[0].a, ["Desktop app putty.exe", "Desktop app com.apple.Terminal", "Desktop app com.example.App", "macos.example.com"]);
  assert.ok(!APP_PIN.test("https://example.com"));
  assert.ok(!APP_PIN.test("androidapp://com.example"));
});

test("the user's picks override the core's defaults, per field", () => {
  const rows = fieldRows(preview(), { username: "a", notes: "b", title: "b" });
  const by = Object.fromEntries(rows.map((r) => [r.field, r]));
  assert.equal(by.username.pick, "a");
  assert.equal(by.notes.pick, "b");
  assert.equal(by.title.pick, "b");
  assert.equal(by.password.pick, "a", "untouched fields keep the default");
  assert.equal(fieldRows(preview()).find((r) => r.field === "username").pick, "b");
});

test("a title that differs is a choice like any other field", () => {
  const p = preview();
  p.plan.fields[0] = { field: "title", state: "differs" };
  const title = fieldRows(p).find((r) => r.field === "title");
  assert.equal(title.choosable, true);
  assert.equal(title.both, false);
  assert.equal(title.same, false);
});

test("shift+click selects a range in list order, ctrl+click toggles", () => {
  const ids = ["a", "b", "c", "d"];
  assert.deepEqual(selectRange(ids, "b", "d"), ["b", "c", "d"]);
  assert.deepEqual(selectRange(ids, "d", "b"), ["b", "c", "d"]);
  assert.deepEqual(selectRange(ids, null, "c"), ["c"]);
  assert.deepEqual(selectRange(ids, "b", "zz"), []);
  let sel = toggleSelected(new Set(), "c", "a");
  assert.deepEqual([...sel], ["a", "c"], "the open item joins first");
  sel = toggleSelected(sel, "a");
  assert.deepEqual([...sel], ["c"]);
  sel = toggleSelected(new Set(), "c", "c");
  assert.deepEqual([...sel], ["c"]);
  assert.deepEqual([...pruneSelected(new Set(["a", "x"]), ids)], ["a"]);
});

test("dismissed suggestions stay quiet, new ones show", () => {
  const s1 = { login_id: "l1", otp_id: "o1" };
  const s2 = { login_id: "l2", otp_id: "o2" };
  assert.equal(pairKey(s1), "l1|o1");
  assert.deepEqual(pendingSuggestions([s1, s2], ["l1|o1"]), [s2]);
  assert.deepEqual(pendingSuggestions([s1], null), [s1]);
  assert.deepEqual(pendingSuggestions(undefined, []), []);
  assert.equal(hintText(1), "1 authenticator code can be added to its login.");
  assert.equal(hintText(3), "3 authenticator codes can be added to your logins.");
});

test("the picker keeps the core's order and splits likely matches", () => {
  const summaries = [
    { id: "x", title: "Amazon", username: "me" },
    { id: "y", title: "GitHub", username: "me", url: "https://github.com" },
    { id: "z", title: "Gist" },
  ];
  const candidates = [{ id: "y", score: 5 }, { id: "z", score: 3 }, { id: "x", score: 0 }, { id: "gone", score: 9 }];
  const { likely, rest } = pickerRows(candidates, summaries);
  assert.deepEqual(likely.map((s) => s.id), ["y", "z"]);
  assert.deepEqual(rest.map((s) => s.id), ["x"]);
  const found = pickerRows(candidates, summaries, "github.com");
  assert.deepEqual(found.likely.map((s) => s.id), ["y"]);
  assert.deepEqual(found.rest, []);
});
test("the selection's star stars them all unless all are favorites", () => {
  assert.equal(favoriteTarget([false, false]), true);
  assert.equal(favoriteTarget([true, false, true]), true, "one is not yet");
  assert.equal(favoriteTarget([true, true]), false, "all are: unstar them all");
  assert.equal(favoriteTarget([true]), false);
  assert.equal(favoriteTarget([]), true);
  assert.equal(favoriteLabel(true), "Add to favorites");
  assert.equal(favoriteLabel(false), "Remove from favorites");
});

test("the selection's toasts", () => {
  assert.equal(favoritesText(1, true), "Added to favorites");
  assert.equal(favoritesText(3, true), "Added 3 items to favorites");
  assert.equal(favoritesText(2, false), "Removed 2 items from favorites");
  assert.equal(deletedText(1), "Moved 1 item to Trash");
  assert.equal(deletedText(4), "Moved 4 items to Trash");
  assert.equal(restoredText(1), "The item is back.");
  assert.equal(restoredText(4), "4 items are back.");
});
