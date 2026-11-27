// Export… (export.rs): the open vault as a file. Encrypted (recommended; a password for the file),
// Passyble JSON and CSV, both unencrypted, which need the master password again and an explicit
// "I understand". Rust writes the file after the save dialog; nothing passes through the window.

import { errorText, h, icon, invoke, isLockedError, listen, modal, mount, passwordField, t, tn, toast } from "../lib.js";
import { newPasswordFields } from "./signin.js";
import { exportAllowed } from "./teams-model.js";

const FORMATS = [
  ["encrypted", t("export.encrypted"), t("export.encrypted_text")],
  ["json", t("export.json"), t("export.json_text")],
  ["csv", t("export.csv"), t("export.csv_text")],
];

let uid = 0;

/** Opens the export dialog. `options.onError(e, retry)`: a "vault is locked" answer unlocks and retries. */
export function openExportDialog(options = {}) {
  let format = "encrypted";
  let offLock = null;
  const m = modal({
    label: t("export.title"),
    onClose: () => Promise.resolve(offLock).then((off) => off && off()).catch(() => {}),
  });
  offLock = listen("lock-state", (p) => { if (p && p.locked) m.close(); });

  const choices = h("div", { class: "export-formats", role: "radiogroup", "aria-label": t("export.format") });
  const detail = h("div", { class: "col" });
  const error = h("div", { class: "error-text", role: "alert" });
  const submit = h("button", { class: "btn primary", type: "submit" }, icon("upload"), t("export.submit"));

  // Shared vaults: the organisation's policy may keep them out of an export; the dialog says so up front.
  const policyNote = h("div", { hidden: true });
  invoke("policy_status")
    .then((s) => {
      if (!s || exportAllowed(s)) return;
      mount(policyNote, h("div", { class: "banner" }, icon("shield"), h("span", { class: "grow", text: t("policy.export_shared_off") })));
      policyNote.hidden = false;
    })
    .catch(() => {});

  // Which vault: the home vault, or one shared vault the role and policy allow (`export_choices`).
  let vaultId = null;
  const vaultPick = h("div", { hidden: true });
  invoke("export_choices")
    .then((list) => {
      const vaults = Array.isArray(list) ? list : [];
      if (vaults.length < 2) return;
      const sel = h("select", { class: "input", id: `ex-${++uid}` }, vaults.map((v) => h("option", {
        value: v.home ? "" : v.id,
        disabled: !v.allowed,
        text: v.home ? (v.name ? t("export.vault_home_named", { name: v.name }) : t("export.vault_home")) : v.allowed ? v.name : t("export.vault_not_allowed", { name: v.name }),
      })));
      const hint = h("span", { class: "hint", text: t("export.vault_hint") });
      sel.addEventListener("change", () => { vaultId = sel.value || null; });
      mount(vaultPick, h("div", { class: "field" }, h("label", { for: sel.id, text: t("export.vault") }), sel, hint));
      vaultPick.hidden = false;
    })
    .catch(() => {});

  let fields = null;
  const renderChoices = () => mount(choices, FORMATS.map(([key, label, text]) => {
    const on = key === format;
    return h("button", {
      class: `export-format${on ? " on" : ""}`,
      type: "button",
      role: "radio",
      "aria-checked": String(on),
      on: { click: () => { format = key; renderChoices(); renderDetail(); } },
    }, h("span", { class: "merge-radio", "aria-hidden": "true" }, on ? icon("check") : null),
      h("span", { class: "col grow" }, h("span", { class: "t", text: label }), h("span", { class: "faint", text })));
  }));

  const renderDetail = () => {
    error.textContent = "";
    if (format === "encrypted") {
      // The file's own password, not a master password: the plain hint and minimum.
      const pw = newPasswordFields(t("export.password_label"), { master: false });
      fields = { kind: "encrypted", pw };
      mount(detail,
        ...pw.els,
        h("p", { class: "faint", text: t("export.password_note") }));
    } else {
      const master = passwordField({ autocomplete: "current-password" });
      const id = `ex-${++uid}`;
      master.input.id = id;
      const agree = h("input", { type: "checkbox" });
      fields = { kind: "plain", master, agree };
      mount(detail,
        h("div", { class: "banner warn" }, icon("alert"), h("span", { class: "grow", text: t("export.plain_warning") })),
        h("div", { class: "field" }, h("label", { for: id, text: t("export.master_password") }), master.el),
        h("label", { class: "check" }, agree, t("export.understand")));
    }
  };

  const form = h("form", {
    class: "col",
    on: {
      submit: async (e) => {
        e.preventDefault();
        error.textContent = "";
        const args = { format, password: null, masterPassword: null, vaultId };
        try {
          if (fields.kind === "encrypted") {
            args.password = fields.pw.check();
          } else {
            if (!fields.master.input.value) throw new Error(t("export.need_master"));
            if (!fields.agree.checked) throw new Error(t("export.need_agree"));
            args.masterPassword = fields.master.input.value;
          }
        } catch (err) {
          error.textContent = errorText(err);
          return;
        }
        submit.disabled = true;
        try {
          const r = await invoke("export_vault", args);
          if (!r) return; // the save dialog was cancelled
          m.close();
          toast(tn("export.done", r.items, { path: r.path }), "", 9000);
          if (!r.encrypted) toast(t("export.delete_reminder"), "", 9000);
        } catch (err) {
          error.textContent = errorText(err);
          if (options.onError && isLockedError(err)) {
            m.close();
            options.onError(err, () => openExportDialog(options));
          }
        } finally {
          submit.disabled = false;
        }
      },
    },
  },
  h("p", { class: "note-line" }, icon("info"), h("span", { class: "grow", text: t("export.intro") })),
  policyNote,
  vaultPick,
  choices,
  detail,
  error,
  h("div", { class: "row modal-actions" },
    h("span", { class: "spacer" }),
    h("button", { class: "btn", type: "button", text: t("common.cancel"), on: { click: () => m.close() } }),
    submit));

  mount(m.box, h("div", { class: "row" }, h("span", { class: "modal-icon" }, icon("upload")), h("h2", { class: "grow", text: t("export.title") })), form);
  renderChoices();
  renderDetail();
  const first = choices.querySelector(".export-format.on");
  if (first) first.focus();
}
