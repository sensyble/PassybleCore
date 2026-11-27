// The vault view's rail: one column of icon buttons at the window's left edge. Home, Favorites, the
// generator, Password health, Trash, Teams and Family on top; More, Help, Account, Sync and Lock below.
//
// * Where the user is: the button of the open page is filled and has aria-current="page".
// * Names: a tooltip on hover or keyboard focus (a button's `title` is moved into it).
// * Keyboard: one Tab stop (the current button); Up, Down, Home and End move between buttons.

import { h, icon, t } from "../lib.js";

/** A rail button: icon only, named by `label` ("Lock (Ctrl+L)": the shortcut shows in its tooltip). */
export function railButton(iconName, label, onClick, cls = "") {
  return h("button", {
    class: `rail-btn ${cls}`.trim(),
    type: "button",
    title: label,
    "aria-label": label.replace(/\s*[(（][^()（）]*[)）]$/, ""),
    tabindex: "-1",
    on: { click: onClick },
  }, icon(iconName));
}

export class Rail {
  /** `groups`: lists of `[key, button]`, top to bottom; `null` pushes the groups after it down. */
  constructor(groups) {
    this.buttons = new Map();
    this.active = null;
    this.tip = h("div", { class: "rail-tip", role: "tooltip", hidden: true });
    this.el = h("nav", { class: "rail", "aria-label": t("rail.label") },
      groups.map((group) => {
        if (!group) return h("div", { class: "rail-fill" });
        return h("div", { class: "rail-group" }, group.map(([key, button]) => {
          this.buttons.set(key, button);
          button.dataset.rail = key;
          return button;
        }));
      }));
    this.el.addEventListener("keydown", (e) => this.keys(e));
    this.el.addEventListener("pointerover", (e) => this.showTip(e.target.closest(".rail-btn")));
    this.el.addEventListener("pointerleave", () => this.hideTip());
    this.el.addEventListener("focusin", (e) => {
      // A click focuses too: the tooltip is for the pointer's hover and for the keyboard.
      if (!document.documentElement.classList.contains("mouse")) this.showTip(e.target.closest(".rail-btn"));
    });
    this.el.addEventListener("focusout", () => this.hideTip());
    this.el.addEventListener("click", () => this.hideTip());
    document.body.append(this.tip);
    this.refresh();
  }

  shown() {
    return [...this.buttons.values()].filter((b) => !b.hidden);
  }

  setActive(key) {
    this.active = key;
    for (const [name, button] of this.buttons) {
      const on = name === key;
      button.classList.toggle("active", on);
      if (on) button.setAttribute("aria-current", "page");
      else button.removeAttribute("aria-current");
    }
    this.refresh();
  }

  /** One Tab stop: the current button, else the first one shown. */
  refresh() {
    const shown = this.shown();
    const current = shown.find((b) => b.dataset.rail === this.active) || shown[0];
    for (const button of this.buttons.values()) button.tabIndex = button === current ? 0 : -1;
  }

  keys(e) {
    const shown = this.shown();
    const i = shown.indexOf(document.activeElement);
    if (i < 0) return;
    const to = { ArrowDown: i + 1, ArrowUp: i - 1, Home: 0, End: shown.length - 1 }[e.key];
    if (to === undefined) return;
    e.preventDefault();
    const next = shown[(to + shown.length) % shown.length];
    for (const b of shown) b.tabIndex = b === next ? 0 : -1;
    next.focus();
  }

  showTip(button) {
    if (!button || button.hidden) return this.hideTip();
    if (button.title) {
      button.dataset.tip = button.title;
      button.removeAttribute("title");
    }
    this.tip.textContent = button.dataset.tip || button.getAttribute("aria-label") || "";
    this.tip.hidden = false;
    const r = button.getBoundingClientRect();
    const tip = this.tip.getBoundingClientRect();
    this.tip.style.left = `${Math.round(r.right + 8)}px`;
    this.tip.style.top = `${Math.round(Math.max(4, Math.min(window.innerHeight - tip.height - 4, r.top + (r.height - tip.height) / 2)))}px`;
  }

  hideTip() {
    this.tip.hidden = true;
  }

  destroy() {
    this.tip.remove();
  }
}
