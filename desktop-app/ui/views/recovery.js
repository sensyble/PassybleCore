// Recovery code for a forgotten master password (recovery.rs). The code is made and checked in Rust; the
// window shows it once (Copy, Save, Print) and never keeps it. Used from Settings → This vault, onboarding
// and Unlock → "Forgot password?". A Passyble Server vault shares its password with the server account,
// so its new password comes from the server's password reset, not from here.

import { errorText, formatDate, h, icon, invoke, modal, mount, passwordField, settingsRow, t, toast } from "../lib.js";
import { newPasswordFields, openLinkDialog } from "./signin.js";
import { afterPasswordChange } from "./password-change.js";
import { adminRecoveryLink } from "./teams-recovery.js";

const dateText = (ms) => formatDate(ms);
const CODE_PLACEHOLDER = "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX";
const WHAT_IT_IS = t("recovery.what_it_is");
const KEEP_IT = t("recovery.keep_it");

let uid = 0;
function field(label, input, hint) {
  const id = `rc-${++uid}`;
  (input.input || input).id = id;
  return h("div", { class: "field" }, h("label", { for: id, text: label }), input.el || input, hint ? h("span", { class: "hint", text: hint }) : null);
}

function rowButton(iconName, label, onClick, cls = "") {
  return h("button", { class: `btn small ${cls}`.trim(), type: "button", on: { click: onClick } }, iconName ? icon(iconName) : null, label);
}

function formOf(onSubmit, submitLabel, children, buttons = []) {
  const error = h("div", { class: "error-text", role: "alert" });
  const submit = h("button", { class: "btn primary", type: "submit", text: submitLabel });
  return h("form", {
    class: "col",
    on: {
      submit: async (e) => {
        e.preventDefault();
        error.textContent = "";
        submit.disabled = true;
        submit.textContent = t("common.working");
        try {
          await onSubmit();
        } catch (err) {
          error.textContent = errorText(err);
        } finally {
          submit.disabled = false;
          submit.textContent = submitLabel;
        }
      },
    },
  }, children, error, h("div", { class: "row modal-actions" }, h("span", { class: "spacer" }), buttons, submit));
}

/** Prints the code on a sheet of its own (everything else is hidden while printing). */
function printCode(code, vaultName) {
  const sheet = h("div", { class: "print-sheet" },
    h("h1", { text: t("recovery.print_title") }),
    vaultName ? h("p", { text: t("recovery.print_vault", { vault: vaultName }) }) : null,
    h("p", { text: t("recovery.print_made", { date: dateText(Date.now()) }) }),
    h("div", { class: "print-code", text: code }),
    h("p", { text: t("recovery.print_how") }),
    h("p", { text: t("recovery.print_keep") }));
  document.body.append(sheet);
  document.body.classList.add("printing");
  const done = () => {
    window.removeEventListener("afterprint", done);
    document.body.classList.remove("printing");
    sheet.remove();
  };
  window.addEventListener("afterprint", done);
  try {
    window.print();
  } catch (e) {
    done();
    toast(errorText(e), "error");
  }
}

/** The code, shown once, with Copy / Save / Print and "I saved it", which enables `done`. Returns `{ els, done }`. */
function codeStep({ code, vaultName, doneLabel = t("common.done"), onDone }) {
  const saved = h("input", { type: "checkbox" });
  const done = h("button", { class: "btn primary", type: "button", disabled: true, text: doneLabel, on: { click: () => onDone() } });
  saved.addEventListener("change", () => { done.disabled = !saved.checked; });
  const els = [
    h("p", { text: t("recovery.shown_once") }),
    h("div", { class: "fingerprint recovery-code" }, h("div", { class: "fp selectable mono", text: code })),
    h("div", { class: "row wrap" },
      rowButton("copy", t("common.copy"), () => invoke("copy_secret", { text: code }).then(() => toast(t("recovery.copied"))).catch((e) => toast(errorText(e), "error"))),
      rowButton("download", t("recovery.save_text"), async () => {
        try {
          const path = await invoke("recovery_code_save", { code });
          if (path) toast(t("common.saved_to", { path }), "", 7000);
        } catch (e) {
          toast(errorText(e), "error");
        }
      }),
      rowButton("fileText", t("recovery.print"), () => printCode(code, vaultName))),
    h("p", { class: "muted", text: KEEP_IT }),
    h("label", { class: "check" }, saved, t("recovery.saved_check")),
    h("div", { class: "row modal-actions" }, h("span", { class: "spacer" }), done),
  ];
  return { els, focus: () => saved.focus() };
}

/**
 * Create or replace the unlocked vault's code. `askPassword` is false right after the vault was created
 * or got a new password (Rust allows one code without it then).
 */
export function openCreateRecoveryDialog({ askPassword = true, replacing = false, vaultName = "", intro = null, skipLabel = t("common.cancel"), onDone = null } = {}) {
  let created = false;
  let showing = false;
  // The code must be acknowledged: Esc closes the dialog only before it shows.
  const m = modal({ label: t("recovery.title"), escape: () => !showing, onClose: () => onDone && onDone(created) });
  const title = h("h2", { class: "grow", text: replacing ? t("recovery.replace_title") : t("recovery.create_title") });
  const body = h("div", { class: "col" });
  mount(m.box, h("div", { class: "row" }, title), body);
  const intro_ = [
    h("p", { text: intro || WHAT_IT_IS }),
    replacing ? h("p", { class: "muted", text: t("recovery.replace_note") }) : null,
  ];
  const render = (ask) => {
    const pw = ask ? passwordField({ autocomplete: "current-password" }) : null;
    mount(body,
      intro_,
      formOf(async () => {
        let r;
        try {
          r = await invoke("recovery_code_create", { password: pw ? pw.input.value : null });
        } catch (e) {
          // The few minutes without the password are over: ask for it.
          if (!pw && errorText(e).toLowerCase() === t("errors.enter_master_password").toLowerCase()) {
            render(true);
            return;
          }
          throw e;
        }
        if (pw) pw.reset();
        created = true;
        showing = true;
        if (r.warning) toast(r.warning, "", 9000);
        title.textContent = t("recovery.save_title");
        const step = codeStep({ code: r.code, vaultName, onDone: () => { showing = false; m.close(); toast(t("recovery.saved")); } });
        mount(body, step.els);
        step.focus();
      }, replacing ? t("recovery.replace_code") : t("recovery.create_code"), pw ? [field(t("unlock.master_password"), pw)] : [], [
        h("button", { class: "btn", type: "button", text: skipLabel, on: { click: () => m.close() } }),
      ]));
    // Opening the dialog doesn't scroll the page under it.
    if (pw) pw.focus({ preventScroll: true });
    else body.querySelector("button[type=submit]").focus();
  };
  render(askPassword);
}

export function openRemoveRecoveryDialog({ onDone = null } = {}) {
  let removed = false;
  const m = modal({ label: t("recovery.remove_label"), cls: "narrow", onClose: () => onDone && onDone(removed) });
  const pw = passwordField({ autocomplete: "current-password" });
  mount(m.box,
    h("div", { class: "row" }, h("span", { class: "modal-icon danger" }, icon("alert")), h("h2", { class: "grow", text: t("recovery.remove_title") })),
    h("p", { text: t("recovery.remove_text") }),
    h("p", { class: "muted", text: t("recovery.remove_note") }),
    formOf(async () => {
      const r = await invoke("recovery_code_remove", { password: pw.input.value });
      pw.reset();
      removed = true;
      m.close();
      toast(t("recovery.removed"));
      if (r && r.warning) toast(r.warning, "", 9000);
    }, t("common.remove"), [field(t("unlock.master_password"), pw)], [
      h("button", { class: "btn", type: "button", text: t("common.cancel"), on: { click: () => m.close() } }),
    ]));
  pw.focus();
}

export function recoveryRow(rc, { vaultName = "", onChanged = () => {} } = {}) {
  const info = `${WHAT_IT_IS}\n\n${KEEP_IT}`;
  if (!rc) {
    return settingsRow("shield", t("recovery.title"), { value: t("recovery.unlock_to_see"), info });
  }
  if (!rc.exists) {
    return settingsRow("shield", t("recovery.title"), {
      value: t("recovery.none"),
      valueClass: "warn",
      info,
      control: rowButton(null, t("recovery.create_ellipsis"), () => openCreateRecoveryDialog({ vaultName, onDone: (c) => c && onChanged() }), "tonal"),
    });
  }
  return settingsRow("shield", t("recovery.title"), {
    value: rc.created_at ? t("recovery.made_on", { date: dateText(rc.created_at) }) : t("recovery.set_up"),
    valueClass: "ok",
    info,
    control: [
      rowButton(null, t("recovery.replace_ellipsis"), () => openCreateRecoveryDialog({ replacing: true, vaultName, onDone: (c) => c && onChanged() })),
      rowButton(null, t("recovery.remove_ellipsis"), () => openRemoveRecoveryDialog({ onDone: (r) => r && onChanged() })),
    ],
  });
}

export function offerRecoveryCode({ vaultName = "", onDone = null } = {}) {
  openCreateRecoveryDialog({
    askPassword: false,
    vaultName,
    intro: t("recovery.offer_intro", { what: WHAT_IT_IS }),
    skipLabel: t("common.skip"),
    onDone,
  });
}

/** Unlock → "Forgot password?" for `vault`. `onUnlocked()` once it is open; the dialog stays until a new master password is set. */
export function openRecoveryUnlockDialog(vault, { onUnlocked = () => {} } = {}) {
  let step = "code";
  // Once unlocked, the new password must be chosen (or the vault locked again).
  const m = modal({ label: t("recovery.use_title"), escape: () => step === "code" });
  const title = h("h2", { class: "grow" });
  const body = h("div", { class: "col" });
  mount(m.box, h("div", { class: "row" }, h("span", { class: "modal-icon" }, icon("key")), title), body);

  const lockAgain = () => h("button", {
    class: "btn",
    type: "button",
    text: t("recovery.lock_vault"),
    on: { click: async () => { await invoke("lock", { full: true }).catch(() => {}); m.close(); } },
  });

  const codeStepForm = () => {
    title.textContent = t("recovery.use_title");
    const input = h("input", { class: "input mono otp-input recovery-input", spellcheck: "false", autocomplete: "off", placeholder: CODE_PLACEHOLDER, maxlength: "60" });
    mount(body,
      h("p", { text: t("recovery.enter_for", { vault: vault.name }) }),
      formOf(async () => {
        const code = input.value.trim();
        if (!code) {
          input.focus();
          throw new Error(t("recovery.enter_code"));
        }
        const r = await invoke("recovery_unlock", { code, vaultId: vault.id });
        input.value = "";
        onUnlocked();
        if (r && r.server) serverStep(r.server);
        else passwordStep();
      }, t("unlock.unlock"), [field(t("recovery.title"), input)], [
        h("button", { class: "btn", type: "button", text: t("common.cancel"), on: { click: () => m.close() } }),
      ]),
      // A Team member enrolled in admin-assisted recovery can ask an admin instead (teams-recovery.js).
      h("div", { class: "center-links" }, adminRecoveryLink({ onOpen: () => m.close(), onUnlocked })));
    input.focus();
  };

  const passwordStep = () => {
    step = "password";
    title.textContent = t("recovery.new_password_title");
    const fields = newPasswordFields(t("recovery.new_password"), { activeVault: true });
    mount(body,
      h("div", { class: "banner ok-banner" }, icon("check"), h("span", { class: "grow", text: t("recovery.unlocked") })),
      h("p", { text: t("recovery.new_password_text") }),
      formOf(async () => {
        const next = await fields.checkPolicy();
        const r = await invoke("recovery_set_password", { newPassword: next });
        fields.clear();
        toast(t("recovery.password_set"));
        if (r && r.warning) toast(r.warning, "", 9000);
        // The new password gave the vault a new key: the code just used works no more.
        afterPasswordChange(r, { offerCode: false });
        newCodeStep(r);
      }, t("recovery.set_password"), fields.els, [lockAgain()]));
    fields.first.focus();
  };

  const newCodeStep = (r) => {
    step = "offer";
    const dropped = !!(r && r.new_recovery_code);
    title.textContent = t("recovery.new_code_title");
    mount(body,
      h("p", { text: dropped ? t("password_change.code_dropped") : t("recovery.new_code_text") }),
      h("div", { class: "row modal-actions" },
        h("span", { class: "spacer" }),
        h("button", { class: "btn", type: "button", text: dropped ? t("common.not_now") : t("recovery.keep_old"), on: { click: () => m.close() } }),
        h("button", {
          class: "btn primary",
          type: "button",
          text: t("recovery.make_new"),
          on: { click: () => { m.close(); openCreateRecoveryDialog({ askPassword: false, replacing: true, vaultName: vault.name, skipLabel: t("common.not_now") }); } },
        })));
    body.querySelector(".btn.primary").focus();
  };

  // A Passyble Server vault: one password for the server account and the vault.
  const serverStep = (server) => {
    step = "server";
    title.textContent = t("recovery.server_title");
    const sent = h("div", { class: "col" });
    const linkInput = h("input", { class: "input", spellcheck: "false", autocomplete: "off", placeholder: "pass+server://…&reset=…" });
    mount(body,
      h("div", { class: "banner ok-banner" }, icon("check"), h("span", { class: "grow", text: t("recovery.unlocked") })),
      h("p", { text: t("recovery.server_text", { username: server.username, host: server.host }) }),
      h("p", { text: t("recovery.server_how") }),
      h("div", { class: "row wrap" },
        rowButton("mail", t("recovery.email_link"), async (e) => {
          const btn = e.currentTarget;
          btn.disabled = true;
          try {
            await invoke("recovery_server_reset");
            mount(sent, h("div", { class: "banner" }, icon("mail"), h("span", { class: "grow", text: t("recovery.link_sent") })));
          } catch (err) {
            mount(sent, h("div", { class: "banner error", text: errorText(err) }));
          } finally {
            btn.disabled = false;
          }
        }, "primary")),
      sent,
      h("p", { class: "muted", text: t("recovery.no_email") }),
      formOf(async () => {
        const link = linkInput.value.trim();
        if (!link) {
          linkInput.focus();
          throw new Error(t("recovery.paste_link"));
        }
        m.close();
        openLinkDialog(link, () => {
          openCreateRecoveryDialog({ replacing: true, vaultName: `${server.username}@${server.host}`, skipLabel: t("common.not_now"), intro: t("recovery.after_reset_intro", { what: WHAT_IT_IS }) });
        });
      }, t("recovery.use_link"), [field(t("recovery.reset_link"), linkInput)], [
        h("button", { class: "btn", type: "button", text: t("common.later"), on: { click: () => m.close() } }),
      ]));
  };

  codeStepForm();
}
