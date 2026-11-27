// TOTP popup: a small always-on-top card near the tray with the live code, Copy and "Type it".
// Shown by the agent when a code can't be filled (native apps, custom 2FA widgets).
// The code shows as dots until revealed (eye button, hover, or press and hold); Copy and "Type it"
// work without revealing it. Each new popup starts hidden again.

import { escapeHides, h, icon, invoke, listen, liveTotp, maskedCode, mount, ring, toast, errorText, t } from "./lib.js";

const AUTO_HIDE_MS = 3 * 60 * 1000;
const root = document.getElementById("root");
let live = null;
let hideTimer = null;

function close() {
  if (live) live.stop();
  live = null;
  invoke("hide_window");
}

async function show() {
  if (live) live.stop();
  clearTimeout(hideTimer);
  const popup = await invoke("totp_popup_state").catch(() => null);
  if (!popup) {
    mount(root);
    return;
  }
  const code = maskedCode();
  const countdown = ring();
  const typeBtn = h(
    "button",
    {
      class: "btn primary",
      type: "button",
      title: t("totp.type_title"),
      on: {
        click: () => invoke("totp_popup_type").catch((e) => toast(errorText(e), "error")),
      },
    },
    icon("keyboard"),
    t("totp.type"),
  );
  typeBtn.hidden = !popup.can_type;
  const copyBtn = h(
    "button",
    {
      class: "btn",
      type: "button",
      on: {
        click: () =>
          invoke("totp_popup_copy")
            .then(() => toast(t("common.copied_clears")))
            .catch((e) => toast(errorText(e), "error")),
      },
    },
    icon("copy"),
    t("common.copy"),
  );
  mount(
    root,
    h(
      "div",
      { class: "drag", "data-tauri-drag-region": true },
      h("span", { class: "title ellipsis grow", "data-tauri-drag-region": true, text: popup.title }),
      h("button", { class: "btn icon ghost", type: "button", title: t("common.close"), "aria-label": t("common.close"), on: { click: close } }, icon("close")),
    ),
    h(
      "div",
      { class: "body" },
      h("div", { class: "totp" }, countdown.el, code.el, h("span", { class: "spacer" }), code.eye),
      h("div", { class: "btns" }, copyBtn, typeBtn),
    ),
  );
  // Showing the code each period doesn't count as activity for the auto-lock; Copy and Type it do.
  live = liveTotp(() => invoke("totp", { id: popup.item_id, quiet: true }), {
    onCode(value, remaining, period) {
      if (value) code.set(value);
      countdown.set(remaining, period);
    },
    onError(message) {
      code.setText("-");
      toast(message, "error");
    },
  });
  hideTimer = setTimeout(close, AUTO_HIDE_MS);
}

escapeHides(() => live && live.stop());
listen("totp-popup", show);
listen("lock-state", (s) => {
  if (s && s.locked) {
    if (live) live.stop();
    live = null;
    mount(root);
  }
});
show();
