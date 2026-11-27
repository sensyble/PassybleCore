// Shared helpers for every window: Tauri bridge, DOM building (no innerHTML with data), icons,
// errors, toasts, password fields, dialogs and the TOTP ring.

import { friendlyError } from "./errors.js";
import { formatDate, t, tn, tx } from "./i18n.js";
import { ICONS } from "./icons.js";
import { isMac } from "./platform.js";
import { attachTooltip } from "./tooltip.js";
import { comboParts, hasMod, macKeyLabel, withMod } from "./views/shortcuts-model.js";

export { formatDate, formatDateTime, formatNumber, formatTime, inSentence, t, tn, tx } from "./i18n.js";

export { cardExpired, cardLabel, expiryText, hasTag, identityName, initials, tagKey } from "./views/items-model.js";

const tauri = window.__TAURI__;

/** Calls a Rust command. Argument names are camelCase (Tauri maps them to snake_case). */
export function invoke(cmd, args) {
  return tauri.core.invoke(cmd, args);
}

export function listen(event, handler) {
  return tauri.event.listen(event, (e) => handler(e.payload));
}

/**
 * Runs `fn` each time this window comes back on screen. A window hidden in the tray is suspended or
 * trimmed, so an event sent meanwhile may only run now: views with live state refresh here.
 */
export function onShown(fn) {
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) fn();
  });
}

// Open latency: first frame painted after the window came on screen (logged only with PASSYBLE_PERF=1).
if (tauri && typeof document !== "undefined") {
  onShown(() => requestAnimationFrame(() => requestAnimationFrame(() => {
    tauri.core.invoke("perf_painted").catch(() => {});
  })));
}

export { friendlyError, isHelloCancelled, isLockedError, LOCKED_ERROR, looksTechnical } from "./errors.js";

export const errorText = friendlyError;

/** Creates an element. `props`: attributes, `class`, `text`, `on: {event: fn}`, `dataset`, `value`. */
export function h(tag, props = {}, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(props || {})) {
    if (value === undefined || value === null || value === false) continue;
    if (key === "class") el.className = value;
    else if (key === "text") el.textContent = value;
    else if (key === "on") for (const [ev, fn] of Object.entries(value)) el.addEventListener(ev, fn);
    else if (key === "dataset") Object.assign(el.dataset, value);
    else if (key === "value") el.value = value;
    else if (key === "checked") el.checked = Boolean(value);
    else if (value === true) el.setAttribute(key, "");
    else el.setAttribute(key, String(value));
  }
  append(el, children);
  return el;
}

function append(el, children) {
  for (const child of children.flat(Infinity)) {
    if (child === null || child === undefined || child === false) continue;
    el.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
}

export function mount(el, ...children) {
  el.replaceChildren();
  append(el, children);
}

const SVG_NS = "http://www.w3.org/2000/svg";

/** A Lucide icon as an <svg>. Unknown names fall back to "key". */
export function icon(name, cls) {
  const svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "2");
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("stroke-linejoin", "round");
  svg.setAttribute("aria-hidden", "true");
  svg.setAttribute("class", cls ? `icon ${cls}` : "icon");
  for (const [tag, attrs] of ICONS[name] || ICONS.key) {
    const el = document.createElementNS(SVG_NS, tag);
    for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
    svg.append(el);
  }
  return svg;
}

export function iconButton(name, title, onClick, cls = "ghost") {
  return h("button", { class: `btn icon ${cls}`, title, "aria-label": title.replace(/\s*[(（][^()（）]*[)）]$/, ""), type: "button", on: { click: onClick } }, icon(name));
}

/** A small (i) button with `text` as its tooltip. Inside a <label> it doesn't toggle the control. */
export function infoTip(text, label = null) {
  const name = typeof label === "string" && label ? t("common.about", { name: label }) : t("common.more_info");
  const tip = h("button", { class: "tip", type: "button", "aria-label": name }, icon("info"));
  attachTooltip(tip, text);
  return tip;
}

/** A short line (`lead`, optional) and a small "Why?" with `text` as its tooltip. */
export function whyNote(lead, text) {
  const why = h("button", { class: "why-toggle", type: "button", text: t("common.why") });
  attachTooltip(why, text);
  return h("p", { class: "why" }, lead ? h("span", { text: `${lead} ` }) : null, why);
}

/** A settings group: a title with an optional (i), then a card holding `rows`. */
export function settingsGroup(title, rows, { info = null, cls = "", sub = null } = {}) {
  return h(
    "section",
    { class: `set-group ${cls}`.trim() },
    h("h3", { class: "set-head" }, h("span", { text: title }), info ? infoTip(info, title) : null),
    sub ? h("p", { class: "set-intro", text: sub }) : null,
    h("div", { class: "card set-card" }, rows),
  );
}

/**
 * One settings row: icon, `title`, an optional `value` line showing state (`valueClass` "warn" or
 * "ok"), an optional (i) `info`, and a `control` at the end. A checkbox `control` is drawn as a
 * switch and the whole row toggles it; `id` labels another control. `onClick` makes the row a
 * button with a chevron. The row keeps `valueEl` and `controlEl` for later updates.
 */
export function settingsRow(iconName, title, { value = null, valueClass = "", info = null, control = null, onClick = null, id = null, cls = "", valueTitle = null } = {}) {
  const isSwitch = control && control.tagName === "INPUT" && control.type === "checkbox";
  const valueEl = h("span", { class: `set-sub ${valueClass}`.trim(), title: valueTitle || (typeof value === "string" ? value : null) }, value);
  const label = id && !isSwitch && typeof title === "string" ? h("label", { for: id, text: title }) : h("span", { class: "set-title" }, title);
  const controlEl = h("span", { class: "set-control" }, isSwitch ? h("span", { class: "switch" }, control) : control);
  const row = h(
    isSwitch ? "label" : "div",
    { class: `set-row${onClick ? " set-link" : ""} ${cls}`.trim() },
    icon(iconName, "set-ico"),
    h("span", { class: "set-text" }, h("span", { class: "set-label" }, label, info ? infoTip(info, title) : null), valueEl),
    controlEl,
    onClick ? icon("chevronRight", "set-chev") : null,
  );
  if (onClick) {
    row.setAttribute("role", "button");
    row.setAttribute("tabindex", "0");
    row.addEventListener("click", (e) => {
      if (!e.target.closest(".set-control button, .set-control input, .set-control select")) onClick();
    });
    row.addEventListener("keydown", (e) => {
      if ((e.key === "Enter" || e.key === " ") && e.target === row) {
        e.preventDefault();
        onClick();
      }
    });
  }
  row.valueEl = valueEl;
  row.controlEl = controlEl;
  return row;
}

export function agoText(ms, now = Date.now()) {
  const diff = Math.max(0, now - ms);
  const min = Math.round(diff / 60000);
  if (min < 1) return t("time.just_now");
  if (min < 60) return tn("time.minutes_ago", min);
  const hours = Math.round(min / 60);
  if (hours < 24) return tn("time.hours_ago", hours);
  const days = Math.round(hours / 24);
  if (days === 1) return t("time.yesterday");
  if (days < 7) return tn("time.days_ago", days);
  return formatDate(ms);
}

/**
 * A shortcut as the user's language names its keys ("Ctrl+Shift+L" is "Strg+Umschalt+L" in German).
 * Display only: hotkey strings and key handling stay English. "Mod" is Ctrl, or Cmd on a Mac, where
 * shortcuts show as Apple symbols.
 */
export function keyLabel(combo) {
  if (!combo) return "";
  if (isMac()) return macKeyLabel(combo, (key) => (Object.hasOwn(NAMED_KEYS, key) ? t(NAMED_KEYS[key]) : key));
  const names = {
    Ctrl: t("keys.ctrl"),
    Control: t("keys.ctrl"),
    Alt: t("keys.alt"),
    Shift: t("keys.shift"),
    Super: t("keys.win"),
    Win: t("keys.win"),
    Meta: t("keys.win"),
    Space: t("keys.space"),
    Insert: t("keys.insert"),
    Delete: t("keys.delete"),
    Backspace: t("keys.backspace"),
    Home: t("keys.home"),
    End: t("keys.end"),
    PageUp: t("keys.page_up"),
    PageDown: t("keys.page_down"),
    Enter: t("keys.enter"),
    Esc: t("keys.esc"),
    Escape: t("keys.esc"),
  };
  return comboParts(withMod(combo, false))
    .map((key) => (Object.hasOwn(names, key) ? names[key] : key))
    .join("+");
}

// The named keys a Mac still spells out after the modifier symbols ("⌘ Space" reads "⌘Space").
const NAMED_KEYS = {
  Space: "keys.space",
  Insert: "keys.insert",
  Home: "keys.home",
  End: "keys.end",
  PageUp: "keys.page_up",
  PageDown: "keys.page_down",
  Enter: "keys.enter",
  Esc: "keys.esc",
  Escape: "keys.esc",
};

export function modKey(e) {
  return hasMod(e, isMac());
}

export function withShortcut(label, shortcut) {
  return shortcut ? t("common.with_shortcut", { label, shortcut: keyLabel(shortcut) }) : label;
}

let toastHost;
let problemReporter = null;
/** Error toasts offer the main window's "Report this problem" through this. */
export function setProblemReporter(fn) {
  problemReporter = typeof fn === "function" ? fn : null;
}

/**
 * A short message at the bottom of the window. `options.action`: `{ label, icon?, onClick }` adds a
 * button (e.g. Undo); such toasts stay longer. An error toast without one offers "Report this
 * problem" (`options.report: false` leaves it out). Returns `{ close() }`.
 */
export function toast(message, kind = "", ms = 0, options = {}) {
  if (!toastHost) {
    toastHost = h("div", { id: "toasts", role: "status", "aria-live": "polite" });
    document.body.append(toastHost);
  }
  const reporter = problemReporter;
  const action = options.action
    || (kind === "error" && reporter && options.report !== false
      ? { label: t("support.report"), icon: "lifeBuoy", onClick: () => reporter(String(message)) }
      : null);
  const duration = ms || (action ? 8000 : kind === "error" ? 6000 : 2600);
  const el = h("div", { class: `toast ${kind}${action ? " has-action" : ""}` }, h("span", { class: "grow", text: message }));
  let timer = null;
  const close = () => {
    clearTimeout(timer);
    el.remove();
  };
  if (action) {
    el.append(
      h(
        "button",
        {
          class: "btn small toast-action",
          type: "button",
          on: {
            click: () => {
              close();
              action.onClick();
            },
          },
        },
        action.icon ? icon(action.icon) : null,
        action.label,
      ),
      h("button", { class: "btn icon ghost small", type: "button", title: t("common.dismiss"), "aria-label": t("common.dismiss"), on: { click: close } }, icon("close")),
    );
  }
  toastHost.append(el);
  timer = setTimeout(close, duration);
  return { close };
}

/** A password input with a show/hide toggle and a Caps Lock warning. `props` go to the <input>. */
export function passwordField(props = {}) {
  const input = h("input", { class: "input", type: "password", spellcheck: "false", autocomplete: "current-password", ...props });
  const caps = h("div", { class: "caps-warning", role: "status", hidden: true }, icon("alert"), t("password.caps_lock"));
  const toggle = h(
    "button",
    {
      class: "btn icon ghost reveal",
      type: "button",
      title: t("password.show"),
      "aria-label": t("password.show"),
      "aria-pressed": "false",
      tabindex: "-1",
      on: {
        click: () => {
          const show = input.type === "password";
          input.type = show ? "text" : "password";
          toggle.title = show ? t("password.hide") : t("password.show");
          toggle.setAttribute("aria-label", toggle.title);
          toggle.setAttribute("aria-pressed", String(show));
          mount(toggle, icon(show ? "eyeOff" : "eye"));
          input.focus();
        },
      },
    },
    icon("eye"),
  );
  const capsCheck = (e) => {
    if (e.getModifierState) caps.hidden = !e.getModifierState("CapsLock");
  };
  input.addEventListener("keydown", capsCheck);
  input.addEventListener("keyup", capsCheck);
  input.addEventListener("blur", () => { caps.hidden = true; });
  const el = h("div", { class: "password-field" }, h("div", { class: "input-wrap" }, input, toggle), caps);
  return {
    el,
    input,
    focus: (options) => input.focus(options),
    reset() {
      input.value = "";
      input.type = "password";
      toggle.title = t("password.show");
      toggle.setAttribute("aria-label", toggle.title);
      toggle.setAttribute("aria-pressed", "false");
      mount(toggle, icon("eye"));
    },
  };
}

/** `sha256:<base64url>` as groups of four characters, for comparing by eye. */
export function fingerprint(pin) {
  const body = String(pin || "").replace(/^sha256:/, "");
  return (body.match(/.{1,4}/g) || []).join(" ");
}

/** "Trust this server?" (trust on first use) for a certificate that isn't publicly trusted. Resolves `true` if trusted. */
export function trustDialog({ host, pin }) {
  return new Promise((resolve) => {
    const done = (ok) => {
      document.removeEventListener("keydown", keys, true);
      backdrop.remove();
      resolve(ok);
    };
    const keys = (e) => {
      if (e.key === "Escape") {
        e.preventDefault();
        e.stopPropagation();
        done(false);
      }
    };
    const trust = h("button", { class: "btn primary", type: "button", on: { click: () => done(true) } }, icon("shield"), t("trust.confirm"));
    const backdrop = h(
      "div",
      { class: "modal-backdrop" },
      h(
        "div",
        { class: "modal trust", role: "dialog", "aria-modal": "true", "aria-label": t("trust.title") },
        h("div", { class: "row" }, h("span", { class: "modal-icon warn" }, icon("shieldAlert")), h("h2", { class: "grow", text: t("trust.title") })),
        h("p", {}, tx("trust.body", { host: h("strong", { class: "selectable", text: host }) })),
        h(
          "div",
          { class: "fingerprint" },
          h("div", { class: "label", text: t("trust.fingerprint") }),
          h("div", { class: "fp selectable mono", text: fingerprint(pin) }),
        ),
        h("p", { class: "muted", text: t("trust.compare") }),
        h(
          "div",
          { class: "row modal-actions" },
          h("span", { class: "spacer" }),
          h("button", { class: "btn", type: "button", text: t("common.cancel"), on: { click: () => done(false) } }),
          trust,
        ),
      ),
    );
    document.addEventListener("keydown", keys, true);
    document.body.append(backdrop);
    trust.focus();
  });
}

export function formatCode(code) {
  if (!code) return "";
  if (code.length === 6) return `${code.slice(0, 3)} ${code.slice(3)}`;
  if (code.length === 8) return `${code.slice(0, 4)} ${code.slice(4)}`;
  return code;
}

export function maskCode(code) {
  return code ? formatCode(code).replace(/\S/g, "•") : "••• •••";
}

/**
 * A 2FA code shown as dots until revealed (eye button, hover, or press and hold). The digits are
 * only in the DOM while visible. Returns `{ el, eye, set(code), setText(text) }`; `setText` shows a
 * message (an error) instead.
 */
export function maskedCode({ revealed = false, onToggle = null, cls = "code" } = {}) {
  let code = null;
  let message = null;
  let pinned = !!revealed;
  let hover = false;
  let press = false;
  const el = h("span", { class: `${cls} masked-code` });
  const eye = h("button", { class: "btn icon ghost", type: "button" });
  const render = () => {
    const show = !!code && (pinned || hover || press);
    el.textContent = message || (show ? formatCode(code) : maskCode(code));
    el.classList.toggle("masked", !message && !show);
    el.classList.toggle("selectable", show);
    const label = pinned ? t("code.hide") : t("code.show");
    eye.title = label;
    eye.setAttribute("aria-label", label);
    eye.setAttribute("aria-pressed", String(pinned));
    mount(eye, icon(pinned ? "eyeOff" : "eye"));
  };
  eye.addEventListener("click", () => {
    pinned = !pinned;
    render();
    if (onToggle) onToggle(pinned);
  });
  el.addEventListener("pointerenter", () => { hover = true; render(); });
  el.addEventListener("pointerleave", () => { hover = false; press = false; render(); });
  el.addEventListener("pointerdown", () => { press = true; render(); });
  for (const ev of ["pointerup", "pointercancel"]) el.addEventListener(ev, () => { press = false; render(); });
  render();
  return {
    el,
    eye,
    set(next) {
      message = null;
      code = next || null;
      render();
    },
    setText(text) {
      message = text || null;
      render();
    },
  };
}

const RING_R = 11;
const RING_C = 2 * Math.PI * RING_R;

export function ring() {
  const svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("viewBox", "0 0 28 28");
  svg.setAttribute("class", "ring");
  const track = document.createElementNS(SVG_NS, "circle");
  const bar = document.createElementNS(SVG_NS, "circle");
  for (const c of [track, bar]) {
    c.setAttribute("cx", "14");
    c.setAttribute("cy", "14");
    c.setAttribute("r", String(RING_R));
  }
  track.setAttribute("class", "track");
  bar.setAttribute("class", "bar");
  bar.setAttribute("stroke-dasharray", String(RING_C));
  svg.append(track, bar);
  return {
    el: svg,
    set(remaining, period) {
      // A short arc stays visible at the very end of the period.
      const fraction = Math.max(0.04, Math.min(1, remaining / (period || 30)));
      bar.setAttribute("stroke-dashoffset", String(RING_C * (1 - fraction)));
      svg.classList.toggle("low", remaining <= 5);
    },
  };
}

/** `fetchCode()` must resolve `{code, period, remaining_secs}`. */
export function liveTotp(fetchCode, { onCode, onError, shouldRefresh = () => true } = {}) {
  let remaining = 0;
  let period = 30;
  let timer = null;
  let stopped = false;
  let fetching = false;

  async function refresh() {
    if (fetching) return;
    fetching = true;
    try {
      const c = await fetchCode();
      remaining = c.remaining_secs;
      period = c.period;
      onCode && onCode(c.code, remaining, period);
    } catch (e) {
      onError && onError(errorText(e));
    } finally {
      fetching = false;
    }
  }

  function tick() {
    if (stopped) return;
    remaining -= 1;
    if (remaining <= 0) {
      if (shouldRefresh()) refresh();
      else onCode && onCode(null, 0, period);
    } else {
      onCode && onCode(undefined, remaining, period);
    }
  }

  refresh();
  timer = setInterval(tick, 1000);
  return {
    refresh,
    stop() {
      stopped = true;
      clearInterval(timer);
    },
  };
}

/** The letter avatar for a title. `kind`: a note or card shows its icon; `letters` replaces the first letter. */
export function avatar(title, kind, letters = null) {
  const text = (title || "?").trim();
  const el = h("div", { class: `avatar${kind === "card" ? " card-avatar" : ""}`, "aria-hidden": "true" });
  if (kind === "note") el.append(icon("note"));
  else if (kind === "card") el.append(icon("creditCard"));
  else if (letters) el.textContent = letters;
  else el.textContent = (Array.from(text)[0] || "?").toUpperCase();
  return el;
}

/**
 * A dialog over the window; put the content in `box`. Esc closes it unless `escape` is false, or a
 * function that answers false right now (a step that must be finished).
 */
export function modal({ label, cls = "", onClose = null, escape = true } = {}) {
  const box = h("div", { class: `modal ${cls}`.trim(), role: "dialog", "aria-modal": "true", "aria-label": label || "" });
  const backdrop = h("div", { class: "modal-backdrop" }, box);
  let open = true;
  const keys = (e) => {
    if (e.key !== "Escape" || !(typeof escape === "function" ? escape() : escape)) return;
    // A dialog opened over this one handles its own Esc.
    const backdrops = document.querySelectorAll(".modal-backdrop");
    if (backdrops[backdrops.length - 1] !== backdrop) return;
    e.preventDefault();
    e.stopPropagation();
    close();
  };
  const close = () => {
    if (!open) return;
    open = false;
    document.removeEventListener("keydown", keys, true);
    backdrop.remove();
    if (onClose) onClose();
  };
  document.addEventListener("keydown", keys, true);
  document.body.append(backdrop);
  return { box, close, isOpen: () => open };
}

/** "Are you sure?" for what can't be undone. Resolves `true` to go ahead. */
export function confirmDialog({ title, text, confirm = t("common.ok"), iconName = "alert", danger = false }) {
  return new Promise((resolve) => {
    let answer = false;
    const m = modal({ label: title, cls: "narrow", onClose: () => resolve(answer) });
    const go = h("button", {
      class: `btn ${danger ? "primary danger-fill" : "primary"}`,
      type: "button",
      on: { click: () => { answer = true; m.close(); } },
    }, icon(iconName), confirm);
    mount(m.box,
      h("div", { class: "row" }, h("span", { class: `modal-icon${danger ? " danger" : ""}` }, icon(iconName)), h("h2", { class: "grow", text: title })),
      typeof text === "string" ? h("p", { text }) : text,
      h("div", { class: "row modal-actions" },
        h("span", { class: "spacer" }),
        h("button", { class: "btn", type: "button", text: t("common.cancel"), on: { click: () => m.close() } }),
        go));
    go.focus();
  });
}

/** A QR code from Rust's module grid (`{ size, path }`, quiet zone included): black on white in both themes so phones can scan it. */
export function qrCode({ size, path }, label = t("common.qr_code")) {
  const svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("viewBox", `0 0 ${size} ${size}`);
  svg.setAttribute("class", "qr");
  svg.setAttribute("shape-rendering", "crispEdges");
  svg.setAttribute("role", "img");
  svg.setAttribute("aria-label", label);
  const bg = document.createElementNS(SVG_NS, "rect");
  bg.setAttribute("width", String(size));
  bg.setAttribute("height", String(size));
  bg.setAttribute("fill", "#fff");
  const fg = document.createElementNS(SVG_NS, "path");
  fg.setAttribute("fill", "#000");
  fg.setAttribute("d", path);
  svg.append(bg, fg);
  return svg;
}

/** A small link to sensyble.net. Rust opens the site (`open_sensyble_site` allows that one address only). */
export function sensybleCredit() {
  return h("button", {
    class: "link sensyble-credit",
    type: "button",
    text: t("about.credit"),
    title: "www.sensyble.net",
    on: { click: () => invoke("open_sensyble_site").catch((e) => toast(friendlyError(e), "error")) },
  });
}

// The wordmark's key mark: the app icon's, the same in both themes.
const WORDMARK_Y = "M18.677 9.033L17.92 9.436L16.808 8.77L15.956 9.223L17.068 9.889L16.31 10.292L13.727 8.73L13.727 9.151C13.728 11.475 13.677 12.383 12.229 13.708L11.219 12.691C12.285 11.696 12.185 10.858 12.152 9.01L12.084 5.135L13.756 4.245L13.769 6.118ZM6.582 16.971C5.728 15.364 6.337 13.37 7.944 12.516C9.55 11.661 11.545 12.271 12.399 13.878C13.253 15.484 12.643 17.479 11.037 18.333C9.43 19.187 7.436 18.577 6.582 16.971ZM7.658 16.398C8.196 17.41 9.453 17.795 10.465 17.256C11.477 16.718 11.861 15.462 11.323 14.45C10.785 13.438 9.528 13.054 8.516 13.592C7.504 14.13 7.12 15.386 7.658 16.398Z";

export function wordmark() {
  const svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("viewBox", "4.705 3.160 14.935 17.171");
  svg.setAttribute("aria-hidden", "true");
  for (const [fill, stroke] of [["#4f6b00", true], ["#c6f432", false]]) {
    const path = document.createElementNS(SVG_NS, "path");
    path.setAttribute("d", WORDMARK_Y);
    path.setAttribute("fill", fill);
    if (stroke) {
      path.setAttribute("stroke", fill);
      path.setAttribute("stroke-width", "1.771");
      path.setAttribute("stroke-linejoin", "round");
    }
    svg.append(path);
  }
  return h("div", { class: "wordmark", role: "img", "aria-label": "Passyble" }, "Pass", svg, "ble");
}

export function escapeHides(extra) {
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      e.preventDefault();
      if (extra) extra();
      invoke("hide_window");
    }
  });
}

/** Esc pressed at `target` (Close Window on a Mac does what Esc does). True when something took it. */
export function pressEscape(target) {
  const e = new KeyboardEvent("keydown", { key: "Escape", code: "Escape", bubbles: true, cancelable: true });
  (target || document.body).dispatchEvent(e);
  return e.defaultPrevented;
}

// The focus ring is for the keyboard: <html> gets "mouse" on a pointer press and loses it on any key.
document.addEventListener("pointerdown", () => document.documentElement.classList.add("mouse"), true);
document.addEventListener("keydown", (e) => {
  if (e && e.key) document.documentElement.classList.remove("mouse");
}, true);

// Web-page shortcuts that make no sense in an app window.
document.addEventListener("contextmenu", (e) => {
  if (!e.target.closest("input, textarea, .selectable")) e.preventDefault();
});
document.addEventListener("keydown", (e) => {
  if ((e.key === "F5") || (modKey(e) && (e.key === "r" || e.key === "p" || e.key === "R"))) e.preventDefault();
});
