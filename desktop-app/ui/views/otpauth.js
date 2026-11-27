// "Add 2FA code": the confirmation for an otpauth:// link opened from outside. The link stays in
// Rust: this window gets the details to show, never the secret. Issuer and account come from
// whoever made the link, so they are plain text only. Nothing is added until Add.

import { errorText, h, icon, invoke, modal, mount, t, toast } from "../lib.js";
import { NEW_LOGIN, addLabel, detailRows, initialChoice, matchDetail, newLoginTitle, replaces } from "./otpauth-model.js";

let current = null;

/** The vault locked (or a newer link came): the dialog goes, the link keeps waiting. */
export function closeOtpauthDialog() {
  if (!current) return;
  const open = current;
  current = null;
  if (open.dialog) {
    open.keep = true;
    open.dialog.close();
  }
}

/** Shows the confirmation for `link` (`otpauth_pending`), unless it is up already. `onAdded(item)`. */
export async function openOtpauthDialog(link, { onAdded }) {
  if (current && current.id === link.id) return;
  closeOtpauthDialog();
  const entry = { id: link.id, keep: false, dialog: null };
  current = entry;
  let review;
  try {
    review = await invoke("otpauth_review", { id: link.id });
  } catch (e) {
    if (current === entry) current = null;
    toast(errorText(e), "error");
    return;
  }
  if (current !== entry) return;

  const matches = review.matches || [];
  let choice = initialChoice(matches);
  let added = false;
  const dialog = modal({
    label: t("otpauth.title"),
    onClose: () => {
      if (current === entry) current = null;
      if (!added && !entry.keep) invoke("otpauth_cancel", { id: link.id }).catch(() => {});
    },
  });
  entry.dialog = dialog;

  const warning = h("div", { class: "banner warn", text: t("otpauth.replace_warning") });
  const error = h("div", { class: "error-text", role: "alert" });
  const addBtn = h("button", { class: "btn primary", type: "button", on: { click: () => add() } });
  const show = () => {
    addBtn.textContent = addLabel(matches, choice);
    warning.hidden = !replaces(matches, choice);
  };

  const row = (value, title, detail, suggested) => {
    const input = h("input", {
      type: "radio",
      name: "otpauth-target",
      value,
      checked: value === choice,
      on: { change: () => { choice = value; show(); } },
    });
    return h(
      "label",
      { class: "otpauth-choice" },
      input,
      h(
        "span",
        { class: "otpauth-choice-text" },
        h("span", { class: "otpauth-choice-title" }, h("span", { text: title }), suggested ? h("span", { class: "pill", text: t("otpauth.best_match") }) : null),
        detail ? h("span", { class: "faint", text: detail }) : null,
      ),
    );
  };

  async function add() {
    addBtn.disabled = true;
    error.textContent = "";
    try {
      const item = await invoke("otpauth_commit", {
        id: link.id,
        target: choice === NEW_LOGIN ? null : choice,
        replace: replaces(matches, choice),
      });
      added = true;
      dialog.close();
      toast(t("otpauth.added", { title: item.title }));
      onAdded(item);
    } catch (e) {
      addBtn.disabled = false;
      error.textContent = errorText(e);
    }
  }

  mount(
    dialog.box,
    h("div", { class: "row" }, h("span", { class: "modal-icon" }, icon("shield")), h("h2", { class: "grow", text: t("otpauth.title") })),
    h("p", { class: "muted", text: t("otpauth.intro") }),
    h(
      "dl",
      { class: "otpauth-details" },
      detailRows(link).flatMap((d) => [h("dt", { text: d.label }), h("dd", { text: d.value })]),
      review.vault_name ? [h("dt", { text: t("otpauth.vault") }), h("dd", { text: review.vault_name })] : null,
    ),
    h("h3", { class: "otpauth-head", text: t("otpauth.add_to") }),
    h(
      "div",
      { class: "col otpauth-choices" },
      matches.map((m) => row(m.id, m.title, matchDetail(m), m.suggested)),
      row(NEW_LOGIN, t("otpauth.new_login"), newLoginTitle(link), false),
    ),
    warning,
    error,
    h(
      "div",
      { class: "row modal-actions" },
      h("span", { class: "spacer" }),
      h("button", { class: "btn", type: "button", text: t("common.cancel"), on: { click: () => dialog.close() } }),
      addBtn,
    ),
  );
  show();
}
