// The Passyble password (account_keys.rs): one password and a Secret Key on each device open every
// vault linked to the account. Holds the Settings rows (`passwordSection`) and the dialogs the unlock
// form uses for a linked vault. Rust answers a few codes instead of errors (account-keys-model.js);
// the dialogs ask for what is missing and try again.

import { confirmDialog, errorText, formatDate, formatDateTime, h, icon, invoke, modal, mount, passwordField, qrCode, settingsRow, t, tn, toast } from "../lib.js";
import {
  codeText,
  confirmsCode,
  errorCode,
  PASSWORD_NEEDED,
  REAUTH,
  requestView,
  resetStep,
  securityRows,
} from "./account-keys-model.js";
import { openAdminKeyDialog, openCancelResetDialog, openKeyNotice, openLockedListDialog, openStartFreshDialog } from "./account-reset.js";
import { openCreateRecoveryDialog } from "./recovery.js";
import { newPasswordFields } from "./signin.js";

let uid = 0;
export function field(label, input, hint) {
  const id = `ak-${++uid}`;
  (input.input || input).id = id;
  return h("div", { class: "field" }, h("label", { for: id, text: label }), input.el || input, hint ? h("span", { class: "hint", text: hint }) : null);
}

export function button(label, onClick, cls = "") {
  return h("button", { class: `btn small ${cls}`.trim(), type: "button", on: { click: onClick } }, label);
}

export function cancelButton(m) {
  return h("button", { class: "btn", type: "button", text: t("common.cancel"), on: { click: () => m.close() } });
}

/** One way to go on in a dialog: an icon, a title and a line under it. */
export function choice(iconName, title, text, onClick) {
  return h("button", { class: "btn choice", type: "button", on: { click: onClick } },
    icon(iconName), h("div", { class: "grow" }, h("div", { class: "t", text: title }), h("div", { class: "muted small", text })));
}

export function codeInput() {
  return h("input", { class: "input recovery-input", type: "text", autocomplete: "off", spellcheck: "false", placeholder: "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX" });
}

/** "Type the last group of the recovery code": `onChange(confirmed)` on every keystroke. */
function confirmCodeField(code, onChange) {
  const input = h("input", { class: "input recovery-input", type: "text", autocomplete: "off", spellcheck: "false", maxlength: "7" });
  input.addEventListener("input", () => onChange(confirmsCode(code, input.value)));
  return field(t("account_keys.kit_confirm"), input, t("account_keys.kit_confirm_hint"));
}

/** A form with an error line and a row of buttons; `onSubmit` runs with the button disabled. */
export function formOf(onSubmit, submitLabel, children, buttons = []) {
  const error = h("div", { class: "error-text", role: "alert" });
  const submit = h("button", { class: "btn primary", type: "submit", text: submitLabel });
  const form = h("form", {
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
  return form;
}

/** Runs `step()`; if the service wants a sign-in within the last 10 minutes, the browser sign-in comes first. */
export async function withFreshSignIn(step) {
  try {
    return await step();
  } catch (e) {
    if (errorCode(e) !== REAUTH) throw e;
    toast(t("account_keys.sign_in_again"), "", 7000);
    await invoke("account_sign_in");
    return step();
  }
}

/** Runs `step(password)` with no password first; if the account key isn't open here, asks for the password and retries. */
export async function withAccountKey(step) {
  try {
    return await step(null);
  } catch (e) {
    if (errorCode(e) !== PASSWORD_NEEDED) throw e;
    const password = await askPassword();
    if (password === null) return null;
    return step(password);
  }
}

function askPassword() {
  return new Promise((resolve) => {
    let answer = null;
    const m = modal({ label: t("account_keys.password"), cls: "narrow", onClose: () => resolve(answer) });
    const pw = passwordField({ autocomplete: "current-password" });
    mount(m.box,
      h("h2", { text: t("account_keys.enter_password") }),
      formOf(async () => {
        if (!pw.input.value) throw new Error(t("unlock.enter_password"));
        answer = pw.input.value;
        m.close();
      }, t("common.continue"), [field(t("account_keys.password"), pw)], [cancelButton(m)]));
    pw.input.focus();
  });
}

function kitCard(kit) {
  const line = (label, value, cls = "") => h("div", { class: "kit-line" }, h("div", { class: "kit-label", text: label }), h("div", { class: `kit-value selectable ${cls}`.trim(), text: value }));
  return h("div", { class: "kit" },
    h("div", { class: "kit-main" },
      h("div", { class: "kit-fields" },
        line(t("account_keys.kit_email"), kit.email),
        line(t("account_keys.kit_sign_in"), kit.sign_in_url),
        line(t("account_keys.kit_secret_key"), kit.secret_key, "mono kit-secret"),
        h("div", { class: "kit-line" }, h("div", { class: "kit-label", text: t("account_keys.kit_password") }), h("div", { class: "kit-blank" }))),
      h("div", { class: "kit-qr" }, qrCode(kit.setup_qr, t("account_keys.kit_qr")), h("div", { class: "hint", text: t("account_keys.kit_qr_hint") }))),
    kit.recovery_code
      ? h("div", { class: "kit-box" }, h("div", { class: "kit-label", text: t("account_keys.kit_recovery") }), h("div", { class: "kit-code mono selectable", text: kit.recovery_code }), h("div", { class: "hint", text: t("account_keys.kit_recovery_hint") }))
      : null);
}

function printKit(kit) {
  const sheet = h("div", { class: "print-sheet" },
    h("h1", { text: t("account_keys.kit_title") }),
    h("p", { text: t("account_keys.kit_print_made", { date: formatDate(Date.now()) }) }),
    kitCard(kit),
    h("p", { text: t("account_keys.kit_print_keep") }));
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

export function openKitDialog(kit, { intro = null, onDone = null } = {}) {
  let confirmed = false;
  const m = modal({ label: t("account_keys.kit_title"), escape: () => confirmed, onClose: () => onDone && onDone() });
  const done = h("button", { class: "btn primary", type: "button", disabled: true, text: t("common.done"), on: { click: () => m.close() } });
  const confirm = kit.recovery_code
    ? confirmCodeField(kit.recovery_code, (ok) => {
        confirmed = ok;
        done.disabled = !confirmed;
      })
    : (() => {
        const saved = h("input", { type: "checkbox" });
        saved.addEventListener("change", () => {
          confirmed = saved.checked;
          done.disabled = !confirmed;
        });
        return h("label", { class: "check" }, saved, t("account_keys.kit_saved"));
      })();
  mount(m.box,
    h("div", { class: "row" }, h("span", { class: "modal-icon" }, icon("fileText")), h("h2", { class: "grow", text: t("account_keys.kit_title") })),
    h("p", { text: intro || t("account_keys.kit_intro") }),
    kitCard(kit),
    h("div", { class: "row wrap" },
      button(t("account_keys.kit_print"), () => printKit(kit), "tonal"),
      button(t("account_keys.copy_secret_key"), () => invoke("copy_secret", { text: kit.secret_key }).then(() => toast(t("account_keys.secret_key_copied"))).catch((e) => toast(errorText(e), "error")))),
    h("p", { class: "muted", text: t("account_keys.kit_keep") }),
    confirm,
    h("div", { class: "row modal-actions" }, h("span", { class: "spacer" }), done));
}

function openSetupDialog({ email = "", onDone = null } = {}) {
  const m = modal({ label: t("account_keys.setup_title") });
  const fields = newPasswordFields(t("account_keys.password"), { names: () => [email] });
  mount(m.box,
    h("div", { class: "row" }, h("span", { class: "modal-icon" }, icon("lock")), h("h2", { class: "grow", text: t("account_keys.setup_title") })),
    h("p", { text: t("account_keys.setup_intro") }),
    h("p", { class: "muted", text: t("account_keys.setup_secret_key") }),
    formOf(async () => {
      const password = await fields.check();
      const kit = await withFreshSignIn(() => invoke("account_keys_setup", { password }));
      m.close();
      if (kit && kit.warning) toast(kit.warning, "", 9000);
      openKitDialog(kit, { intro: t("account_keys.kit_intro_new"), onDone });
    }, t("account_keys.setup_button"), fields.els,
    [h("button", { class: "btn", type: "button", text: t("common.not_now"), on: { click: () => m.close() } })]));
  fields.first.focus();
}

function openChangeDialog({ email = "", onDone = null } = {}) {
  const m = modal({ label: t("account_keys.change_title") });
  const old = passwordField({ autocomplete: "current-password" });
  const fields = newPasswordFields(t("account_keys.new_password"), { names: () => [email] });
  const others = h("input", { type: "checkbox", checked: true });
  mount(m.box,
    h("h2", { text: t("account_keys.change_title") }),
    h("p", { class: "muted", text: t("account_keys.change_intro") }),
    formOf(async () => {
      if (!old.input.value) throw new Error(t("unlock.enter_password"));
      const password = await fields.check();
      await invoke("account_password_change", { oldPassword: old.input.value, newPassword: password, signOutOthers: others.checked });
      m.close();
      toast(t("account_keys.changed"));
      if (onDone) onDone();
    }, t("account_keys.change_button"), [
      field(t("account_keys.current_password"), old),
      ...fields.els,
      h("label", { class: "check" }, others, t("account_keys.sign_out_others")),
    ], [cancelButton(m)]));
  old.input.focus();
}

function openSecretKeyDialog({ onDone = null } = {}) {
  const m = modal({ label: t("account_keys.new_secret_key_title") });
  const pw = passwordField({ autocomplete: "current-password" });
  mount(m.box,
    h("h2", { text: t("account_keys.new_secret_key_title") }),
    h("p", { text: t("account_keys.new_secret_key_intro") }),
    formOf(async () => {
      if (!pw.input.value) throw new Error(t("unlock.enter_password"));
      const kit = await invoke("account_secret_key_replace", { password: pw.input.value });
      m.close();
      openKitDialog(kit, { intro: t("account_keys.kit_intro_new_secret_key"), onDone });
    }, t("account_keys.new_secret_key_button"), [field(t("account_keys.password"), pw)], [cancelButton(m)]));
  pw.input.focus();
}

async function newRecoveryCode({ onDone = null } = {}) {
  const ok = await confirmDialog({ title: t("account_keys.new_recovery_title"), text: t("account_keys.new_recovery_text"), confirm: t("account_keys.new_recovery_button"), iconName: "key" });
  if (!ok) return;
  try {
    const r = await withAccountKey((password) => invoke("account_recovery_replace", { password }));
    if (!r) return;
    let confirmed = false;
    const m = modal({ label: t("account_keys.new_recovery_title"), escape: () => confirmed, onClose: () => onDone && onDone() });
    const done = h("button", { class: "btn primary", type: "button", disabled: true, text: t("common.done"), on: { click: () => m.close() } });
    const confirm = confirmCodeField(r.code, (ok) => {
      confirmed = ok;
      done.disabled = !confirmed;
    });
    mount(m.box,
      h("h2", { text: t("account_keys.new_recovery_title") }),
      h("p", { text: t("account_keys.new_recovery_shown_once") }),
      h("div", { class: "fingerprint recovery-code" }, h("div", { class: "fp selectable mono", text: r.code })),
      h("p", { class: "muted", text: tn("account_keys.new_recovery_vaults", r.updated) }),
      confirm,
      h("div", { class: "row modal-actions" }, h("span", { class: "spacer" }), done));
    confirm.querySelector("input").focus();
  } catch (e) {
    toast(errorText(e), "error");
  }
}

/** "Forgot your password?": with this PC's kept account key or the recovery code; both set a new password. */
export function openForgotDialog({ email = "", kept = false, onUnlocked = null } = {}) {
  const m = modal({ label: t("account_keys.forgot_title") });
  const body = h("div", { class: "col" });
  mount(m.box, h("h2", { text: t("account_keys.forgot_title") }), body);
  const finish = (r) => {
    m.close();
    toast(t("account_keys.reset_done"));
    if (r && r.warning) toast(r.warning, "", 9000);
    if (r && r.unlocked && onUnlocked) onUnlocked();
  };
  const withCode = () => {
    const code = codeInput();
    const fields = newPasswordFields(t("account_keys.new_password"), { names: () => [email] });
    mount(body,
      h("p", { text: t("account_keys.forgot_code_intro") }),
      formOf(async () => {
        if (!code.value.trim()) throw new Error(t("account_keys.enter_recovery_code"));
        const password = await fields.check();
        const r = await withFreshSignIn(() => invoke("account_recovery_reset", { code: code.value.trim(), newPassword: password }));
        finish(r);
      }, t("account_keys.reset_button"), [field(t("account_keys.recovery_code"), code), ...fields.els], [cancelButton(m)]));
    code.focus();
  };
  const withDevice = () => {
    const fields = newPasswordFields(t("account_keys.new_password"), { names: () => [email] });
    mount(body,
      h("p", { text: t("account_keys.forgot_device_intro") }),
      formOf(async () => {
        const password = await fields.check();
        const r = await withFreshSignIn(() => invoke("account_reset_from_device", { newPassword: password }));
        finish(r);
      }, t("account_keys.reset_button"), fields.els, [cancelButton(m)]));
    fields.first.focus();
  };
  const admin = choice("lifeBuoy", t("account_admin.forgot_admin"), t("account_admin.forgot_admin_text"), () => {
    m.close();
    openAdminKeyDialog({ email, onDone: onUnlocked });
  });
  admin.hidden = true;
  invoke("account_admin_recovery_status")
    .then((s) => { admin.hidden = !((s && s.orgs) || []).some((o) => o.enrolled); })
    .catch(() => {});
  mount(body,
    h("p", { text: t("account_keys.forgot_intro") }),
    kept ? choice("hello", t("account_keys.forgot_device"), t("account_keys.forgot_device_text"), withDevice) : null,
    choice("key", t("account_keys.forgot_code"), t("account_keys.forgot_code_text"), withCode),
    admin,
    // The last way, after all the others: new keys after 72 hours, old vaults locked.
    choice("alert", t("account_reset.forgot_fresh"), t("account_reset.forgot_fresh_text"), () => {
      m.close();
      openStartFreshDialog({ email });
    }),
    h("div", { class: "row modal-actions" }, h("span", { class: "spacer" }), cancelButton(m)));
}

export function openLinkDialog({ vaultName = "", onDone = null } = {}) {
  const m = modal({ label: t("account_keys.link_title") });
  const master = passwordField({ autocomplete: "current-password" });
  mount(m.box,
    h("div", { class: "row" }, h("span", { class: "modal-icon" }, icon("link")), h("h2", { class: "grow", text: t("account_keys.link_title") })),
    h("p", { text: t("account_keys.link_intro", { vault: vaultName }) }),
    h("p", { class: "muted", text: t("account_keys.link_copies") }),
    formOf(async () => {
      if (!master.input.value) throw new Error(t("unlock.enter_password"));
      const r = await withAccountKey((password) => invoke("vault_link", { masterPassword: master.input.value, password }));
      if (r === null) return;
      m.close();
      toast(t("account_keys.linked"));
      if (onDone) onDone();
    }, t("account_keys.link_button"), [field(t("account_keys.master_password"), master)],
    [h("button", { class: "btn", type: "button", text: t("common.not_now"), on: { click: async () => {
      m.close();
      await invoke("vault_link_decline").catch(() => {});
      if (onDone) onDone();
    } } })]));
  master.input.focus();
}

export function openUnlinkDialog({ vaultName = "", second = false, onDone = null } = {}) {
  const title = second ? t("password_mode.set_second_title", { vault: vaultName }) : t("account_keys.unlink_title");
  const m = modal({ label: title });
  const fields = newPasswordFields(t("signin.new_password"), { names: () => [vaultName], activeVault: true });
  mount(m.box,
    h("div", { class: "row" }, h("span", { class: "modal-icon danger" }, icon("alert")), h("h2", { class: "grow", text: title })),
    h("p", { text: t("account_keys.unlink_warning") }),
    formOf(async () => {
      const password = await fields.checkPolicy();
      const r = await invoke("vault_unlink", { newPassword: password });
      m.close();
      toast(t("account_keys.unlinked"));
      if (r && r.warning) toast(r.warning, "", 9000);
      openCreateRecoveryDialog({ askPassword: false, vaultName, intro: t("account_keys.unlink_recovery"), skipLabel: t("common.not_now"), onDone: () => onDone && onDone() });
    }, second ? t("password_mode.set_second") : t("account_keys.unlink_button"), fields.els, [cancelButton(m)]));
  fields.first.focus();
}

const POLL_MS = 2000;

function keyFingerprintBox(label, fingerprint) {
  return h("div", { class: "fingerprint" },
    h("div", { class: "label", text: label }),
    h("div", { class: "fp selectable mono", text: fingerprint }));
}

/**
 * Resolves true (the fingerprint matches), false (it doesn't: the caller drops the keys) or null (closed).
 * A service that sealed its own account key shows another fingerprint.
 */
export function askFingerprintMatch(fingerprint) {
  return new Promise((resolve) => {
    let answer = null;
    const m = modal({ label: t("account_keys.check_fingerprint_title"), escape: false, onClose: () => resolve(answer) });
    const say = (value) => {
      answer = value;
      m.close();
    };
    mount(m.box,
      h("div", { class: "row" }, h("span", { class: "modal-icon" }, icon("shield")), h("h2", { class: "grow", text: t("account_keys.check_fingerprint_title") })),
      h("p", { text: t("account_keys.check_fingerprint_text") }),
      keyFingerprintBox(t("account_keys.fingerprint"), fingerprint),
      h("div", { class: "row modal-actions" }, h("span", { class: "spacer" }),
        h("button", { class: "btn danger", type: "button", text: t("account_keys.fingerprint_differs"), on: { click: () => say(false) } }),
        h("button", { class: "btn primary", type: "button", text: t("account_keys.fingerprint_matches"), on: { click: () => say(true) } })));
  });
}

export function showKeysDropped() {
  const m = modal({ label: t("account_keys.keys_dropped_title") });
  mount(m.box,
    h("div", { class: "row" }, h("span", { class: "modal-icon danger" }, icon("shieldAlert")), h("h2", { class: "grow", text: t("account_keys.keys_dropped_title") })),
    h("div", { class: "banner error", role: "alert" }, icon("shieldAlert"), h("span", { class: "grow", text: t("account_keys.keys_dropped_text") })),
    h("div", { class: "row modal-actions" }, h("span", { class: "spacer" }),
      h("button", { class: "btn primary", type: "button", text: t("common.ok"), on: { click: () => m.close() } })));
}

function showApprovedFingerprint(fingerprint) {
  if (!fingerprint) return;
  const m = modal({ label: t("account_keys.approved_title") });
  mount(m.box,
    h("div", { class: "row" }, h("span", { class: "modal-icon" }, icon("shield")), h("h2", { class: "grow", text: t("account_keys.approved_title") })),
    h("p", { text: t("account_keys.approved_fingerprint") }),
    keyFingerprintBox(t("account_keys.fingerprint"), fingerprint),
    h("div", { class: "row modal-actions" }, h("span", { class: "spacer" }),
      h("button", { class: "btn primary", type: "button", text: t("common.ok"), on: { click: () => m.close() } })));
}

/**
 * Number matching: the user types the six digits the new device shows; this PC never shows them.
 * Resolves `{ fingerprint }`, "denied" or null.
 */
function openTypeCodeDialog(r, name) {
  const code = h("input", { class: "input mono", inputmode: "numeric", autocomplete: "off", spellcheck: "false", maxlength: "9", placeholder: "000 000" });
  return new Promise((resolve) => {
    let answer = null;
    const m = modal({ label: t("account_keys.type_code_title", { device: name }), cls: "narrow", onClose: () => resolve(answer) });
    const deny = h("button", {
      class: "link danger",
      type: "button",
      text: t("account_keys.didnt_start"),
      on: {
        click: async () => {
          try {
            await invoke("account_device_deny", { id: r.id });
            answer = "denied";
          } catch (e) {
            toast(errorText(e), "error");
          }
          m.close();
        },
      },
    });
    mount(m.box,
      h("div", { class: "row" }, h("span", { class: "modal-icon" }, icon("shield")), h("h2", { class: "grow", text: t("account_keys.type_code_title", { device: name }) })),
      h("p", { text: t("account_keys.type_code_text", { device: name }) }),
      formOf(async () => {
        if (!/\d/.test(code.value)) {
          code.focus();
          throw new Error(t("account_keys.approval_code_needed"));
        }
        const done = await withAccountKey((password) => invoke("account_device_approve", { id: r.id, password, code: code.value }));
        if (done === null) return;
        answer = done || {};
        m.close();
      }, t("account_keys.add_this_device"), [field(t("account_keys.type_code_label"), code)], [deny, cancelButton(m)]));
    code.focus();
  });
}

function openAddDeviceDialog() {
  let timer = null;
  const m = modal({ label: t("account_keys.add_device_title"), onClose: () => clearTimeout(timer) });
  const qrBox = h("div", { class: "kit-qr" }, h("div", { class: "hint", text: t("common.loading") }));
  const list = h("div", { class: "col" });
  mount(m.box,
    h("div", { class: "row" }, h("span", { class: "modal-icon" }, icon("userPlus")), h("h2", { class: "grow", text: t("account_keys.add_device_title") })),
    h("p", { text: t("account_keys.add_device_intro") }),
    qrBox,
    h("h3", { text: t("account_keys.requests_title") }),
    h("p", { class: "muted", text: t("account_keys.requests_intro") }),
    list,
    h("div", { class: "row modal-actions" }, h("span", { class: "spacer" }),
      h("button", { class: "btn", type: "button", text: t("common.close"), on: { click: () => m.close() } })));

  const showQr = async () => {
    try {
      const inv = await invoke("account_invite_device");
      mount(qrBox, qrCode(inv.qr, t("account_keys.add_device_qr")), h("div", { class: "hint", text: t("account_keys.add_device_qr_hint") }),
        button(t("account_keys.new_qr"), showQr));
    } catch (e) {
      mount(qrBox, h("div", { class: "error-text", text: errorText(e) }));
    }
  };

  const act = async (fn) => {
    try {
      await fn();
    } catch (e) {
      toast(errorText(e), "error");
    }
    refresh();
  };
  const row = (r) => {
    const view = requestView(r);
    const name = r.device_name || t("account_keys.unknown_device");
    const lines = {
      new: t("account_keys.request_new", { device: name }),
      accepted: t("account_keys.request_accepted", { device: name }),
      compare: t("account_keys.request_type", { device: name }),
      joined: t("account_keys.request_joined", { device: name }),
      waiting: t("account_keys.request_waiting"),
      mismatch: t("account_keys.request_mismatch", { device: name }),
    };
    const actions = {
      accept: () => button(t("account_keys.add_this_device"), () => act(() => invoke("account_device_accept", { id: r.id })), "tonal"),
      approve: () => button(view.step === "compare" ? t("account_keys.enter_code") : t("account_keys.add_this_device"), () => act(async () => {
        const done = view.step === "compare"
          ? await openTypeCodeDialog(r, name)
          : await withAccountKey((password) => invoke("account_device_approve", { id: r.id, password }));
        if (!done || done === "denied") return;
        toast(t("account_keys.device_added", { device: name }));
        showApprovedFingerprint(done.fingerprint);
      }), "primary"),
      deny: () => button(t("account_keys.not_me"), () => act(() => invoke("account_device_deny", { id: r.id }))),
    };
    return h("div", { class: "set-row" },
      icon(r.platform === "android" || r.platform === "ios" ? "phone" : "monitor", "set-ico"),
      h("span", { class: "set-text" },
        h("span", { class: "set-title", text: lines[view.step] })),
      h("span", { class: "set-control row wrap" }, view.actions.map((a) => actions[a]())));
  };
  const refresh = async () => {
    clearTimeout(timer);
    if (!m.isOpen()) return;
    try {
      const r = await invoke("account_device_requests");
      const requests = (r && r.requests) || [];
      mount(list, requests.length ? requests.map(row) : h("p", { class: "muted", text: t("account_keys.no_requests") }));
    } catch (e) {
      mount(list, h("div", { class: "error-text", text: errorText(e) }));
    }
    if (m.isOpen()) timer = setTimeout(refresh, POLL_MS);
  };
  showQr();
  refresh();
}

/** This PC as a new device ("Approve from another device"). `onDone(result)` once the keys arrived. */
export function openNewDeviceDialog({ email = "", onDone = null } = {}) {
  let timer = null;
  let finished = false;
  const m = modal({
    label: t("account_keys.new_device_title"),
    onClose: () => {
      clearTimeout(timer);
      if (!finished) invoke("account_device_request_cancel").catch(() => {});
    },
  });
  const body = h("div", { class: "col" });
  mount(m.box,
    h("div", { class: "row" }, h("span", { class: "modal-icon" }, icon("phoneApp")), h("h2", { class: "grow", text: t("account_keys.new_device_title") })),
    body);
  const waiting = (start) => {
    const status = h("p", { class: "muted", role: "status", text: t("account_keys.new_device_waiting") });
    mount(body,
      h("p", { text: t("account_keys.new_device_how") }),
      h("div", { class: "kit-qr" }, qrCode(start.qr, t("account_keys.new_device_qr")), h("div", { class: "hint", text: t("account_keys.new_device_qr_hint") })),
      status,
      h("div", { class: "row modal-actions" }, h("span", { class: "spacer" }), cancelButton(m)));
    const poll = async () => {
      if (!m.isOpen()) return;
      try {
        const r = await invoke("account_device_request_poll");
        if (r.state === "code") {
          mount(status, h("span", { text: t("account_keys.new_device_read") }), h("span", { class: "kit-code mono", text: ` ${codeText(r.code)}` }));
        } else if (r.state === "check") {
          // The keys arrived: kept only once the user checked their fingerprint.
          finished = true;
          const ok = await askFingerprintMatch(r.fingerprint);
          const answer = await invoke("account_device_request_confirm", { matches: ok === true });
          m.close();
          if (answer.state !== "done") {
            showKeysDropped();
            return;
          }
          toast(t("account_keys.new_device_done"));
          if (answer.warning) toast(answer.warning, "", 9000);
          if (onDone) onDone(answer);
          return;
        } else if (r.state === "denied" || r.state === "expired") {
          finished = true;
          status.textContent = r.state === "denied" ? t("account_keys.new_device_denied") : t("account_keys.new_device_expired");
          status.classList.add("error-text");
          return;
        }
      } catch (e) {
        status.textContent = errorText(e);
        status.classList.add("error-text");
        return;
      }
      timer = setTimeout(poll, POLL_MS);
    };
    poll();
  };
  const address = h("input", { class: "input", type: "email", autocomplete: "email", value: email, spellcheck: "false" });
  mount(body,
    h("p", { text: t("account_keys.new_device_intro") }),
    formOf(async () => {
      const start = await invoke("account_device_request_start", { email: address.value.trim() });
      waiting(start);
    }, t("account_keys.new_device_button"), [field(t("account_keys.email"), address)], [cancelButton(m)]));
  address.focus();
}

/** The Passyble password rows for Settings. `el.reload({ offer: true })` after a sign-in offers the setup. */
export function passwordSection({ onChanged = () => {} } = {}) {
  const el = h("div", { class: "account-keys" });
  const load = async ({ offer = false } = {}) => {
    let s;
    try {
      s = await invoke("account_keys_status");
    } catch (e) {
      console.warn("account_keys_status failed:", e);
      mount(el);
      return;
    }
    const again = () => {
      load();
      onChanged();
    };
    const email = s.email || "";
    const v = s.active_vault || {};
    const reset = resetStep(s.reset);
    const rows = {
      reset: () => settingsRow("clock", t("account_reset.row"), {
        value: reset.step === "due"
          ? t("account_reset.row_due")
          : reset.releaseAt ? t("account_reset.waiting_until", { date: formatDateTime(reset.releaseAt) }) : t("account_reset.waiting"),
        valueClass: "warn",
        info: t("account_reset.row_info"),
        control: [
          s.reset && s.reset.started_here ? button(reset.step === "due" ? t("account_reset.set_keys") : t("account_reset.show"), () => openStartFreshDialog({ email, onDone: again }), "tonal") : null,
          button(t("account_reset.cancel_button"), () => openCancelResetDialog({ onDone: again }), s.reset && s.reset.started_here ? "" : "danger"),
        ],
      }),
      key_changed: () => settingsRow("shieldAlert", t("account_reset.key_changed_title", { date: formatDate(s.key_changed.at) }), {
        value: t("account_reset.key_changed_row"),
        valueClass: "warn",
        control: button(t("account_reset.details"), () => openKeyNotice({ kind: "key_changed", ...s.key_changed }, { onChanged: again })),
      }),
      locked: () => settingsRow("lock", t("account_reset.locked_title"), {
        value: tn("account_reset.locked_count", Number(s.locked) || 0),
        info: t("account_reset.locked_info"),
        control: button(t("account_keys.show"), () => openLockedListDialog({ onChanged: again })),
      }),
      setup: () => settingsRow("lock", t("account_keys.title"), {
        value: t("account_keys.not_set"),
        info: t("account_keys.info"),
        control: button(t("account_keys.setup_ellipsis"), () => openSetupDialog({ email, onDone: again }), "tonal"),
      }),
      password: () => settingsRow("lock", t("account_keys.title"), {
        value: s.offline ? t("account_keys.offline") : t("account_keys.set"),
        info: t("account_keys.info"),
        control: [button(t("settings.change"), () => openChangeDialog({ email, onDone: again })),
          button(t("account_keys.forgot_short"), () => openForgotDialog({ email, kept: !!s.kept, onUnlocked: again }))],
      }),
      kit: () => settingsRow("fileText", t("account_keys.kit_title"), {
        info: t("account_keys.kit_info"),
        control: [button(t("account_keys.show"), () => withAccountKey((password) => invoke("account_kit", { password }))
          .then((kit) => kit && openKitDialog(kit, { intro: t("account_keys.kit_intro_again") }))
          .catch((e) => toast(errorText(e), "error"))),
        button(t("account_keys.new_secret_key"), () => openSecretKeyDialog({ onDone: again }))],
      }),
      recovery: () => settingsRow("key", t("account_keys.recovery_code"), {
        value: s.recovery_created_at ? t("account_keys.recovery_made", { date: formatDate(s.recovery_created_at) }) : null,
        info: t("account_keys.recovery_info"),
        control: button(t("account_keys.new_code"), () => newRecoveryCode({ onDone: again })),
      }),
      device_key: () => {
        const select = h("select", { class: "input", id: "ak-device-key" },
          h("option", { value: "hello", text: t("account_keys.keep_hello") }),
          h("option", { value: "remember", text: t("account_keys.keep_remember") }),
          h("option", { value: "off", text: t("account_keys.keep_off") }));
        select.value = s.device_key || "hello";
        select.addEventListener("change", async () => {
          try {
            const r = await withAccountKey((password) => invoke("account_device_key_set", { mode: select.value, password }));
            if (r && r.warning) toast(r.warning, "", 9000);
          } catch (e) {
            toast(errorText(e), "error");
          }
          load();
        });
        const note = s.device_key === "hello" && !s.hello_available ? t("account_keys.hello_unavailable") : s.kept ? null : t("account_keys.not_kept_yet");
        return settingsRow("hello", t("account_keys.on_this_pc"), { id: "ak-device-key", value: note, info: t("account_keys.on_this_pc_info"), control: select });
      },
      fingerprint: () => settingsRow("shield", t("account_keys.fingerprint"), { value: s.fingerprint || "", valueClass: "mono selectable", info: t("account_keys.fingerprint_info") }),
      devices: () => settingsRow("userPlus", t("account_keys.add_device_title"), {
        info: t("account_keys.add_device_info"),
        control: button(t("account_keys.add_device_button"), () => openAddDeviceDialog()),
      }),
      link: () => settingsRow("link", v.password_mode === "one_password" ? t("password_mode.one_title") : t("account_keys.this_vault"), {
        value: v.password_mode === "one_password"
          ? t("password_mode.one_body", { vault: v.name || "" })
          : t("account_keys.vault_own_password", { vault: v.name || "" }),
        valueClass: v.password_mode === "one_password" ? "warn" : "",
        control: button(t("account_keys.link_short"), () => openLinkDialog({ vaultName: v.name || "", onDone: again }), "tonal"),
      }),
      unlink: () => {
        const second = v.home && v.password_mode === "second_password";
        return settingsRow("link", second ? t("password_mode.second_title") : t("account_keys.this_vault"), {
          value: second ? t("password_mode.second_body", { vault: v.name || "" }) : t("account_keys.vault_linked", { vault: v.name || "" }),
          valueClass: second ? "warn" : "",
          info: t("account_keys.unlink_info"),
          control: button(second ? t("password_mode.set_second") : t("account_keys.unlink_short"),
            () => openUnlinkDialog({ vaultName: v.name || "", second, onDone: again }), second ? "tonal" : ""),
        });
      },
    };
    mount(el, ...securityRows(s).map((r) => rows[r]()));
    if (offer && s.set === false && !s.feature_off) openSetupDialog({ email, onDone: again });
  };
  el.reload = load;
  load();
  return el;
}
