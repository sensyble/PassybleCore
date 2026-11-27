// node --test Core/desktop-app/ui/test/*.test.mjs (Node 22 or later)
// The pure part of the item editor.
import assert from "node:assert/strict";
import test from "node:test";

import { readFileSync } from "node:fs";

import { appRows, cancelStep, detailsOpen, editorKey, effectiveRule, hiddenApps, isAppPin, NOTES_MAX, notesCounter, notesMaxLength, ruleBadge, ruleOf, ruleOptions, savedUrls, siteQuery, siteUrl, takeEscape, titleForSite, urlRows } from "../views/editor-model.js";

const key = (k, extra = {}) => ({ key: k, code: "", ctrlKey: false, metaKey: false, altKey: false, shiftKey: false, defaultPrevented: false, isComposing: false, ...extra });
const ctrl = (k, extra = {}) => key(k, { ctrlKey: true, ...extra });
const cmd = (k, extra = {}) => key(k, { metaKey: true, ...extra });

test("Esc cancels and Mod+S saves, also with the focus on the window's body", () => {
  for (const where of ["editor", "page"]) {
    assert.equal(editorKey(key("Escape", { code: "Escape" }), { where }), "cancel");
    assert.equal(editorKey(ctrl("s", { code: "KeyS" }), { where }), "save");
    assert.equal(editorKey(cmd("s", { code: "KeyS" }), { where, mac: true }), "save");
  }
  assert.equal(editorKey(key("s"), {}), null);
  assert.equal(editorKey(key("Enter"), {}), null);
});

test("Mod+S follows the window's key table: any layout, exact modifiers, Cmd on a Mac", () => {
  assert.equal(editorKey(ctrl("ы", { code: "KeyS" }), {}), "save");
  assert.equal(editorKey(cmd("σ", { code: "KeyS" }), { mac: true }), "save");
  assert.equal(editorKey(cmd("ß", { code: "KeyS", altKey: true }), { mac: true }), null);
  assert.equal(editorKey(ctrl("s", { code: "KeyS", altKey: true }), {}), null);
  assert.equal(editorKey(ctrl("S", { code: "KeyS", shiftKey: true }), {}), null);
  // Control is not Cmd on a Mac, and Win is not Ctrl elsewhere.
  assert.equal(editorKey(ctrl("s", { code: "KeyS" }), { mac: true }), null);
  assert.equal(editorKey(cmd("s", { code: "KeyS" }), {}), null);
  assert.equal(editorKey(ctrl("s", { code: "Semicolon" }), {}), "save");
  assert.equal(editorKey(key("Escape", { shiftKey: true }), {}), null);
});

test("a dialog takes every key", () => {
  assert.equal(editorKey(key("Escape"), { dialog: true }), null);
  assert.equal(editorKey(ctrl("s"), { dialog: true }), null);
});

test("keys another part of the window handled, or typed elsewhere, are left alone", () => {
  assert.equal(editorKey(key("Escape", { defaultPrevented: true }), {}), null);
  assert.equal(editorKey(key("Escape", { isComposing: true }), {}), null);
  assert.equal(editorKey(key("Escape"), { where: "other" }), null);
  assert.equal(editorKey(ctrl("s"), { where: "other" }), null);
  assert.equal(editorKey(null, {}), null);
});

test("Esc, Cancel and Cmd+W close an open menu or suggestion list before the editor", () => {
  assert.equal(cancelStep({ popup: true, list: true, dirty: true }), "popup");
  assert.equal(cancelStep({ list: true, dirty: true }), "list");
  assert.equal(cancelStep({ dirty: true }), "ask");
  assert.equal(cancelStep({}), "close");
});

test("Esc in the editor's menus and lists is marked handled, other keys are left alone", () => {
  const event = (k) => ({ key: k, prevented: false, stopped: false, preventDefault() { this.prevented = true; }, stopPropagation() { this.stopped = true; } });
  let closed = 0;
  const esc = event("Escape");
  assert.equal(takeEscape(esc, () => { closed += 1; }), true);
  assert.deepEqual([esc.prevented, esc.stopped, closed], [true, true, 1]);
  const down = event("ArrowDown");
  assert.equal(takeEscape(down, () => { closed += 1; }), false);
  assert.deepEqual([down.prevented, down.stopped, closed], [false, false, 1]);
  // Every Esc goes through takeEscape (or editorKey), so none reaches the pane or Cmd+W unmarked.
  const source = readFileSync(new URL("../views/editor.js", import.meta.url), "utf8");
  assert.doesNotMatch(source, /["']Escape["']/);
  assert.ok((source.match(/takeEscape\(e,/g) || []).length >= 3);
});

test("websites become rows with their rule, the default when they have none", () => {
  const rules = [{ url: "https://alice.github.io", rule: "host" }, { url: "windows:putty.exe", rule: "never" }, { url: "x", rule: "newer" }];
  assert.deepEqual(urlRows(["https://github.com", "https://alice.github.io", "windows:putty.exe", "x"], rules), [
    { url: "https://github.com", rule: "subdomains" },
    { url: "https://alice.github.io", rule: "host" },
    { url: "windows:putty.exe", rule: "never" },
    { url: "x", rule: "subdomains" },
  ]);
  assert.deepEqual(urlRows(undefined, undefined), []);
  assert.equal(ruleOf(null, "a"), "subdomains");
});

test("a save sends the entries and only the rules other than the default, same text", () => {
  const rows = [
    { url: " https://github.com ", rule: "subdomains" },
    { url: "", rule: "never" },
    { url: "https://alice.github.io/", rule: "host" },
    { url: "  ", rule: "subdomains" },
    { url: "windows:putty.exe", rule: "never" },
    // Typed into a pin after "Same host only" was chosen: a pin has no host, it just matches.
    { url: "macos:com.apple.Terminal", rule: "host" },
  ];
  assert.deepEqual(savedUrls(rows), {
    urls: ["https://github.com", "https://alice.github.io/", "windows:putty.exe", "macos:com.apple.Terminal"],
    url_rules: [{ url: "https://alice.github.io/", rule: "host" }, { url: "windows:putty.exe", rule: "never" }],
  });
  assert.deepEqual(savedUrls([]), { urls: [], url_rules: [] });
});

test("app pins and Android apps only match or are hidden", () => {
  assert.ok(isAppPin("windows:putty.exe"));
  assert.ok(isAppPin(" MacOS:com.apple.Terminal"));
  assert.ok(!isAppPin("https://windows.com"));
  assert.equal(effectiveRule("windows:putty.exe", "host"), "subdomains");
  assert.equal(effectiveRule("https://a.example", "host"), "host");
  assert.deepEqual(ruleOptions({ app: true }).map((o) => o.rule), ["subdomains", "never"]);
  const rows = appRows(["com.github.android", "com.example"], ["com.example", "com.gone"]);
  assert.deepEqual(rows, [{ package: "com.github.android", rule: "subdomains" }, { package: "com.example", rule: "never" }]);
  rows[0].rule = "never";
  rows[1].rule = "subdomains";
  assert.deepEqual(hiddenApps(rows), ["com.github.android"]);
});

test("the menu explains each rule, and shared hosting suggests the same host only", () => {
  const plain = ruleOptions();
  assert.deepEqual(plain.map((o) => o.rule), ["subdomains", "host", "never"]);
  assert.ok(plain.every((o) => o.label && o.hint && !o.suggested));
  const shared = ruleOptions({ suggestHost: true });
  assert.deepEqual(shared.filter((o) => o.suggested).map((o) => o.rule), ["host"]);
  assert.notEqual(shared[1].hint, plain[1].hint);
});

test("only a rule other than the default has a badge", () => {
  assert.equal(ruleBadge("subdomains"), null);
  assert.equal(ruleBadge(undefined), null);
  assert.equal(ruleBadge("host"), "Same host");
  assert.equal(ruleBadge("never"), "Hidden");
});

test("a website row asks the site suggestions for its host as typed", () => {
  assert.equal(siteQuery("https://www.Git"), "git");
  assert.equal(siteQuery("  github.com/login?x=1 "), "github.com");
  assert.equal(siteQuery("http://shop.example#top"), "shop.example");
  assert.equal(siteQuery("windows:putty.exe"), "");
  assert.equal(siteQuery(""), "");
  assert.equal(siteUrl("github.com"), "https://github.com");
});

test("a website names a new login only while the Name is empty or was named that way", () => {
  assert.deepEqual(titleForSite("", false, "GitHub"), { title: "GitHub", auto: true });
  // Another site replaces a name it filled; none empties it again.
  assert.deepEqual(titleForSite("GitHub", true, "GitLab"), { title: "GitLab", auto: true });
  assert.deepEqual(titleForSite("GitHub", true, null), { title: "", auto: false });
  assert.deepEqual(titleForSite("My work account", false, "GitHub"), { title: "My work account", auto: false });
  assert.deepEqual(titleForSite("  ", false, null), { title: "  ", auto: false });
});

test("More details starts open only for an item that already has some", () => {
  const login = (extra = {}) => ({ id: "it-1", kind: "login", title: "Netflix", username: "alex", password: "pw", urls: ["https://netflix.com"], url_rules: [], totp: null, notes: "", passkeys: [], fields: [], tags: [], favorite: false, ...extra });
  // A new item starts closed, whatever it was opened with (a tag filter's tags, the vault chosen).
  assert.equal(detailsOpen(null), false);
  assert.equal(detailsOpen(login({ id: "", tags: ["Work"] })), false);
  assert.equal(detailsOpen(login()), false);
  assert.equal(detailsOpen(login({ urls: [], url_rules: undefined, totp: "  ", notes: " \n" })), false);
  assert.equal(detailsOpen(login({ urls: ["https://netflix.com", "  "] })), false);
  assert.equal(detailsOpen(login({ urls: ["https://netflix.com", "https://netflix.co.uk"] })), true);
  assert.equal(detailsOpen(login({ url_rules: [{ url: "https://netflix.com", rule: "host" }] })), true);
  assert.equal(detailsOpen(login({ android_apps: ["com.netflix.mediaclient"] })), true);
  assert.equal(detailsOpen(login({ totp: "JBSWY3DPEHPK3PXP" })), false);
  assert.equal(detailsOpen(login({ passkeys: [{ credential_id: "c1" }] })), true);
  assert.equal(detailsOpen(login({ notes: "Family plan" })), false);
  assert.equal(detailsOpen(login({ fields: [{ name: "PIN", value: "1234", kind: "hidden" }] })), true);
  assert.equal(detailsOpen(login({ tags: ["Streaming"] })), true);
  assert.equal(detailsOpen(login({ favorite: true })), true);
  assert.equal(detailsOpen(login({ ai_access: "ask" })), true);
  assert.equal(detailsOpen(login({ url_rules: [{ url: "https://netflix.com", rule: "subdomains" }] })), false);
  // A note's text is its main content; a card or an identity has no websites or 2FA up there.
  assert.equal(detailsOpen({ id: "it-2", kind: "note", notes: "Wi-Fi: demo" }), false);
  assert.equal(detailsOpen({ id: "it-2", kind: "note", notes: "Wi-Fi: demo", tags: ["Home"] }), true);
  assert.equal(detailsOpen({ id: "it-3", kind: "card", card: { number: "4242424242424242" }, notes: "" }), false);
  assert.equal(detailsOpen({ id: "it-3", kind: "card", notes: "Travel card" }), true);
  assert.equal(detailsOpen({ id: "it-4", kind: "identity", urls: ["https://a.example", "https://b.example"], totp: "x" }), false);
});

test("the notes counter shows from 90% of the cap, and a note over it can shrink, not grow", () => {
  assert.equal(NOTES_MAX, 20000);
  assert.equal(notesCounter(17999), null);
  assert.deepEqual(notesCounter(18000), { count: 18000, max: 20000, full: false });
  assert.deepEqual(notesCounter(20000), { count: 20000, max: 20000, full: true });
  assert.equal(notesMaxLength(0), 20000);
  assert.equal(notesMaxLength(25000), 25000);
});
