// node --test Core/desktop-app/ui/test/*.test.mjs (Node 22 or later)
// The (i) explanation tooltip (used by infoTip and whyNote), on a small fake DOM.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { attachTooltip, placeTooltip } from "../tooltip.js";

class FakeEl extends EventTarget {
  constructor(doc, tag) {
    super();
    this.ownerDocument = doc;
    this.tagName = tag.toUpperCase();
    this.parent = null;
    this.children = [];
    this.attrs = {};
    this.style = {};
    this.dataset = {};
    this.hidden = false;
    this.textContent = "";
    this.rect = { left: 100, top: 100, right: 118, bottom: 118, width: 18, height: 18 };
    const set = new Set();
    this.classList = { add: (c) => set.add(c), remove: (c) => set.delete(c), contains: (c) => set.has(c) };
  }
  set id(v) { this.attrs.id = v; }
  get id() { return this.attrs.id || ""; }
  set className(v) { this.attrs.class = v; }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; }
  append(child) { child.parent = this; this.children.push(child); }
  contains(node) { for (let n = node; n; n = n.parent) if (n === this) return true; return false; }
  get isConnected() { return true; }
  getBoundingClientRect() { return this.rect; }
  get offsetWidth() { return 200; }
  get offsetHeight() { return 40; }
}

function setup({ hoverNone = false } = {}) {
  const view = new EventTarget();
  Object.assign(view, { innerWidth: 800, innerHeight: 600, setTimeout, clearTimeout, matchMedia: (q) => ({ matches: hoverNone && q === "(hover: none)" }) });
  const doc = new EventTarget();
  doc.defaultView = view;
  doc.createElement = (tag) => new FakeEl(doc, tag);
  const btn = new FakeEl(doc, "button");
  btn.setAttribute("aria-label", "About Auto-lock");
  const tip = attachTooltip(btn, "Locks the vault after a while.");
  const fire = (target, type, init = {}) => {
    const e = new Event(type, { cancelable: true });
    for (const [k, v] of Object.entries(init)) Object.defineProperty(e, k, { value: v });
    target.dispatchEvent(e);
    return e;
  };
  return { view, doc, btn, tip, fire };
}
const wait = (ms) => new Promise((r) => setTimeout(r, ms));

test("tooltip: role and id, linked with aria-describedby, inside its named button, hidden at first", () => {
  const { btn, tip } = setup();
  assert.equal(tip.el.getAttribute("role"), "tooltip");
  assert.equal(btn.getAttribute("aria-describedby"), tip.el.id);
  assert.equal(tip.el.parent, btn);
  assert.equal(tip.el.textContent, "Locks the vault after a while.");
  assert.equal(btn.getAttribute("aria-label"), "About Auto-lock");
  assert.equal(tip.el.hidden, true);
});

test("tooltip: hover shows it, a short trip onto the bubble keeps it, leaving hides it", async () => {
  const { btn, tip, fire } = setup();
  fire(btn, "pointerenter", { pointerType: "mouse" });
  assert.equal(tip.el.hidden, false);
  assert.ok(btn.classList.contains("open"));
  fire(btn, "pointerleave", { pointerType: "mouse" });
  fire(btn, "pointerenter", { pointerType: "mouse" }); // the bubble is inside the button
  await wait(200);
  assert.equal(tip.el.hidden, false);
  fire(btn, "pointerleave", { pointerType: "mouse" });
  await wait(200);
  assert.equal(tip.el.hidden, true);
});

test("tooltip: it does not vanish on its own", async () => {
  const { btn, tip, fire } = setup();
  fire(btn, "pointerenter", { pointerType: "mouse" });
  await wait(300);
  assert.equal(tip.el.hidden, false);
});

test("tooltip: keyboard focus shows it and keeps it while the pointer leaves; blur hides it", async () => {
  const { btn, tip, fire } = setup();
  fire(btn, "focus");
  assert.equal(tip.el.hidden, false);
  fire(btn, "pointerleave", { pointerType: "mouse" });
  await wait(200);
  assert.equal(tip.el.hidden, false);
  fire(btn, "blur");
  assert.equal(tip.el.hidden, true);
});

test("tooltip: Esc hides it first, on the window, so a dialog behind it stays open", () => {
  const { view, btn, tip, fire } = setup();
  fire(btn, "focus");
  const esc = fire(view, "keydown", { key: "Escape" });
  assert.equal(tip.el.hidden, true);
  assert.equal(esc.defaultPrevented, true);
  assert.equal(esc.cancelBubble, true, "stopped before the document's listeners");
  const again = fire(view, "keydown", { key: "Escape" });
  assert.equal(again.defaultPrevented, false, "closed: Esc is the page's again");
});

test("tooltip: without hover a tap toggles it and a tap outside closes it", () => {
  const { doc, btn, tip, fire } = setup({ hoverNone: true });
  fire(btn, "pointerenter", { pointerType: "touch" });
  assert.equal(tip.el.hidden, true);
  const tap = () => { fire(btn, "pointerdown", { pointerType: "touch" }); fire(btn, "focus"); fire(btn, "click"); };
  tap();
  assert.equal(tip.el.hidden, false);
  tap();
  assert.equal(tip.el.hidden, true);
  tap();
  fire(doc, "pointerdown", { pointerType: "touch" });
  assert.equal(tip.el.hidden, true);
});

test("tooltip: a mouse click keeps it open and does not reach the row or label", () => {
  const { btn, tip, fire } = setup();
  fire(btn, "pointerenter", { pointerType: "mouse" });
  fire(btn, "pointerdown", { pointerType: "mouse" });
  const click = fire(btn, "click");
  assert.equal(tip.el.hidden, false);
  assert.equal(click.defaultPrevented, true);
});

test("tooltip: placed below, flipped above near the bottom, shifted inside the window", () => {
  const { btn, tip } = setup();
  btn.rect = { left: 780, top: 20, right: 798, bottom: 38, width: 18, height: 18 };
  placeTooltip(btn, tip.el);
  assert.equal(tip.el.dataset.side, "below");
  assert.equal(tip.el.style.top, "44px");
  assert.equal(tip.el.style.left, "592px");
  btn.rect = { left: 2, top: 570, right: 20, bottom: 588, width: 18, height: 18 };
  placeTooltip(btn, tip.el);
  assert.equal(tip.el.dataset.side, "above");
  assert.equal(tip.el.style.top, "524px");
  assert.equal(tip.el.style.left, "8px");
});

test("infoTip and whyNote use the tooltip; the (i) is named About <label>, not by its text", () => {
  const lib = readFileSync(new URL("../lib.js", import.meta.url), "utf8");
  const css = readFileSync(new URL("../styles.css", import.meta.url), "utf8");
  assert.match(lib, /export function infoTip\(text, label = null\) \{[\s\S]*?t\("common\.about", \{ name: label \}\)[\s\S]*?attachTooltip\(tip, text\);/);
  assert.match(lib, /export function whyNote\(lead, text\) \{[\s\S]*?attachTooltip\(why, text\);/);
  assert.doesNotMatch(lib, /"data-tip"/);
  assert.match(css, /\.tooltip \{[^}]*max-width: min\(280px, calc\(100vw - 16px\)\)/);
  assert.match(css, /\.tooltip \{[^}]*background: var\(--surface-raised\)/);
  const reminder = readFileSync(new URL("../views/local-reminder.js", import.meta.url), "utf8");
  assert.match(reminder, /attachTooltip\(info, body\);/);
  assert.doesNotMatch(reminder, /aria-expanded/);
});
