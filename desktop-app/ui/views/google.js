// Google Drive backup: the browser sign-in with its "finish in your browser" banner and Cancel, the
// zero-knowledge note under every Google choice, the restore list's details and the "Stop backing up" dialog.

import { formatDateTime, formatNumber, h, icon, invoke, t, toast } from "../lib.js";

/** Shown under every Google Drive choice (same text as on Android). */
export const ZERO_KNOWLEDGE_NOTE = t("google.zero_knowledge");

export function googleNote() {
  return h("p", { class: "hint google-note" }, icon("shield"), h("span", { text: ZERO_KNOWLEDGE_NOTE }));
}

/**
 * Google sign-in in the system browser (Rust: loopback + PKCE, up to 5 minutes). `host` (or a toast) says to
 * finish in the browser and offers Cancel. `email`: sign in to that account again. Resolves `{email}`, or
 * `null` when cancelled; rejects with a plain-language error.
 */
export async function googleSignIn({ host = null, email = null } = {}) {
  const cancel = () => invoke("google_sign_in_cancel").catch(() => {});
  const text = t("google.finish_in_browser");
  let waiting;
  if (host) {
    const box = h(
      "div",
      { class: "banner google-wait", role: "status" },
      icon("sync", "spin"),
      h("span", { class: "grow", text }),
      h("button", { class: "btn small", type: "button", text: t("common.cancel"), on: { click: cancel } }),
    );
    host.replaceChildren(box);
    waiting = { close: () => box.remove() };
  } else {
    waiting = toast(text, "", 5 * 60 * 1000 + 5000, { action: { label: t("common.cancel"), icon: "close", onClick: cancel } });
  }
  try {
    return await invoke("google_sign_in", { email });
  } finally {
    waiting.close();
  }
}

export function driveVaultDetails(v) {
  const parts = [v.modified ? t("google.backed_up_at", { date: formatDateTime(v.modified) }) : t("google.backed_up")];
  if (v.size) parts.push(t("common.size_kb", { size: formatNumber(Math.max(1, Math.round(v.size / 1024))) }));
  if (v.on_this_pc) parts.push(t("google.already_on_pc"));
  return parts.join(" · ");
}

/** "Stop backing up to Google Drive?" with "Also delete the copy" (only when `canDelete`). Resolves `{ deleteCopy }`, or `null` when cancelled. */
export function stopBackupDialog({ canDelete = true } = {}) {
  return new Promise((resolve) => {
    const check = h("input", { type: "checkbox", id: "g-delete" });
    const done = (value) => {
      document.removeEventListener("keydown", keys, true);
      backdrop.remove();
      resolve(value);
    };
    const keys = (e) => {
      if (e.key === "Escape") {
        e.preventDefault();
        e.stopPropagation();
        done(null);
      }
    };
    const stop = h("button", { class: "btn primary", type: "button", on: { click: () => done({ deleteCopy: check.checked }) } }, icon("cloudOff"), t("common.turn_off"));
    const backdrop = h(
      "div",
      { class: "modal-backdrop" },
      h(
        "div",
        { class: "modal narrow", role: "dialog", "aria-modal": "true", "aria-label": t("google.stop_title") },
        h("div", { class: "row" }, h("span", { class: "modal-icon" }, icon("cloudOff")), h("h2", { class: "grow", text: t("google.stop_title") })),
        h("p", { text: t("google.stop_body") }),
        canDelete
          ? h("label", { class: "switch" }, check, h("span", {}, t("google.stop_delete_copy"),
              h("div", { class: "hint", text: t("google.stop_delete_hint") })))
          : null,
        h("div", { class: "row modal-actions" },
          h("span", { class: "spacer" }),
          h("button", { class: "btn", type: "button", text: t("common.cancel"), on: { click: () => done(null) } }),
          stop),
      ),
    );
    document.addEventListener("keydown", keys, true);
    document.body.append(backdrop);
    stop.focus();
  });
}
