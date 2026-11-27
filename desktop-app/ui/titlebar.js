// The main window's top bar: wordmark, the vault view's search and New, and on Windows the window
// buttons.
//
// * Windows: the window has no system frame, so this bar is the title bar (drag, double-click to
//   maximize, caption buttons sized as Windows 11 draws them).
// * macOS: the traffic lights sit over this bar (overlay title bar); it leaves them room, except in
//   full screen.
// * Linux: the system title bar stays; this is just the first row.

import { h, invoke, mount, t, wordmark } from "./lib.js";
import { platformGuess } from "./platform.js";

let bar = null;
let tools = null;

function appWindow() {
  const api = window.__TAURI__ && window.__TAURI__.window;
  return api && api.getCurrentWindow ? api.getCurrentWindow() : null;
}

export function startTitlebar() {
  if (bar) return;
  const os = platformGuess() || "other";
  document.documentElement.dataset.os = os;
  tools = h("div", { class: "tb-tools" });
  bar = h(
    "header",
    { class: "titlebar", "data-tauri-drag-region": "deep" },
    h("div", { class: "tb-start" },
      os === "macos" ? h("div", { class: "tb-traffic", "aria-hidden": "true" }) : null,
      h("div", { class: "tb-brand" }, wordmark())),
    tools,
    h("div", { class: "tb-end" }, os === "windows" ? windowButtons() : null),
  );
  document.body.prepend(bar);
  document.body.classList.add("has-titlebar");
  watchWindow(os);
}

/** Puts `nodes` in the middle of the bar; none clears it. */
export function setTitlebarTools(...nodes) {
  if (tools) mount(tools, ...nodes);
}

/** Windows 11 caption buttons, drawn with its own glyphs. */
function windowButtons() {
  const win = appWindow();
  const button = (cls, label, glyph, onClick) => h(
    "button",
    { class: `tb-btn ${cls}`, type: "button", title: label, "aria-label": label, on: { click: onClick } },
    h("span", { class: "tb-glyph", "aria-hidden": "true", text: glyph }),
  );
  const maximize = button("tb-max", t("window.maximize"), "\uE922", () => win && win.toggleMaximize().catch(() => {}));
  // Windows 11 shows its snap layouts when the pointer rests on Maximize.
  let snapTimer = 0;
  const cancelSnap = () => {
    clearTimeout(snapTimer);
    snapTimer = 0;
  };
  maximize.addEventListener("pointerenter", (e) => {
    if (e.pointerType !== "mouse" || e.buttons) return;
    cancelSnap();
    snapTimer = setTimeout(() => {
      snapTimer = 0;
      if (maximize.matches(":hover")) invoke("window_snap_layouts").catch(() => {});
    }, 450);
  });
  maximize.addEventListener("pointerleave", cancelSnap);
  maximize.addEventListener("pointerdown", cancelSnap);
  return h(
    "div",
    { class: "tb-buttons" },
    button("tb-min", t("window.minimize"), "\uE921", () => win && win.minimize().catch(() => {})),
    maximize,
    // Close hides the window; Passyble stays in the tray.
    button("tb-close", t("common.close"), "\uE8BB", () => win && win.close().catch(() => {})),
  );
}

function watchWindow(os) {
  const win = appWindow();
  const setActive = () => bar.classList.toggle("inactive", !document.hasFocus());
  window.addEventListener("focus", setActive);
  window.addEventListener("blur", setActive);
  setActive();
  if (!win) return;
  const refresh = async () => {
    if (os === "windows") {
      const maximized = await win.isMaximized().catch(() => false);
      const max = bar.querySelector(".tb-max");
      if (max) {
        const label = maximized ? t("window.restore") : t("window.maximize");
        max.title = label;
        max.setAttribute("aria-label", label);
        max.firstChild.textContent = maximized ? "\uE923" : "\uE922";
      }
      document.documentElement.classList.toggle("maximized", maximized);
    } else if (os === "macos") {
      const full = await win.isFullscreen().catch(() => false);
      document.documentElement.classList.toggle("fullscreen", full);
    }
  };
  if (win.onResized) win.onResized(refresh).catch(() => {});
  refresh();
}
