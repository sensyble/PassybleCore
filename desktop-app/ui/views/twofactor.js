// Settings → Passyble Server (twofactor.rs): two-factor sign-in (turn on / off, recovery codes left) and the
// account's recent security activity. The QR code of the authenticator secret is drawn from Rust's module grid,
// never by a web service. The 10 recovery codes are shown once; Done only after "I saved them".

import { agoText, errorText, formatDate, formatDateTime, h, icon, invoke, modal, mount, passwordField, qrCode, settingsRow, t, tn, toast } from "../lib.js";
import { eventText } from "./items-model.js";
import { twoFactorField } from "./signin.js";

const dateText = (ms) => formatDate(ms);

function rowButton(iconName, label, onClick, cls = "") {
  return h("button", { class: `btn small ${cls}`.trim(), type: "button", on: { click: onClick } }, iconName ? icon(iconName) : null, label);
}

let uid = 0;
function field(label, input, hint) {
  const id = `tf-${++uid}`;
  (input.input || input).id = id;
  return h("div", { class: "field" }, h("label", { for: id, text: label }), input.el || input, hint ? h("span", { class: "hint", text: hint }) : null);
}

export class TwoFactorSettings {
  /** `hooks`: `onActivity()` opens the activity page, `onSignIn()` for a signed-out device. */
  constructor(hooks = {}) {
    this.hooks = hooks;
    this.el = h("div", { class: "set-rows" });
    this.load();
  }

  async load() {
    mount(this.el, settingsRow("phoneApp", t("twofactor.title"), { value: t("server.checking") }), this.activityRow());
    let st;
    try {
      st = await invoke("server_2fa_status");
    } catch (e) {
      mount(this.el,
        settingsRow("phoneApp", t("twofactor.title"), {
          value: errorText(e),
          valueClass: "warn",
          control: rowButton("retry", t("common.try_again"), () => this.load()),
        }),
        this.activityRow());
      return;
    }
    this.render(st);
  }

  activityRow() {
    const row = settingsRow("history", t("twofactor.activity"), {
      value: t("twofactor.activity_value"),
      onClick: () => this.hooks.onActivity && this.hooks.onActivity(),
    });
    row.dataset.page = "activity";
    return row;
  }

  render(st) {
    const info = t("twofactor.info");
    let row;
    if (st.signed_out) {
      row = settingsRow("phoneApp", t("twofactor.title"), {
        value: t("twofactor.signed_out"),
        valueClass: "warn",
        control: this.hooks.onSignIn ? rowButton("logIn", t("common.sign_in_ellipsis"), () => this.hooks.onSignIn(), "primary") : null,
      });
    } else if (st.enabled) {
      row = settingsRow("phoneApp", t("twofactor.title"), {
        value: st.enabled_at ? t("twofactor.on_since", { date: dateText(st.enabled_at) }) : t("twofactor.on"),
        valueClass: "ok",
        info,
        control: rowButton(null, t("twofactor.turn_off_ellipsis"), () => openDisableDialog({ onDone: () => this.load() })),
      });
    } else if (!st.available) {
      row = settingsRow("phoneApp", t("twofactor.title"), {
        value: t("twofactor.not_offered"),
        info: `${info}\n\n${t("twofactor.admin_can_allow")}`,
      });
    } else {
      row = settingsRow("phoneApp", t("twofactor.title"), {
        value: st.pending ? t("twofactor.pending") : t("twofactor.off"),
        valueClass: st.pending ? "warn" : "",
        info,
        control: rowButton("shield", st.pending ? t("twofactor.finish") : t("twofactor.turn_on_ellipsis"), () => openEnableDialog({ onDone: () => this.load() }), "primary"),
      });
    }
    const rows = [row];
    if (st.enabled && !st.signed_out) {
      const left = st.recovery_codes_left || 0;
      rows.push(settingsRow("key", t("twofactor.recovery_codes"), {
        value: left <= 3
          ? tn("twofactor.codes_low", left)
          : tn("twofactor.codes_left", left),
        valueClass: left <= 3 ? "warn" : "",
        info: t("twofactor.codes_info"),
      }));
    }
    mount(this.el, rows, this.activityRow());
  }
}

export function openEnableDialog({ onDone } = {}) {
  let step = "password";
  // The recovery codes must be acknowledged: Esc closes the dialog only before they show.
  const m = modal({ label: t("twofactor.turn_on_title"), escape: () => step !== "codes", onClose: () => onDone && onDone() });
  const title = h("h2", { class: "grow" });
  const body = h("div", { class: "col" });
  mount(m.box, h("div", { class: "row" }, h("span", { class: "modal-icon" }, icon("phoneApp")), title), body);

  const formOf = (onSubmit, submitLabel, children, buttons = []) => {
    const error = h("div", { class: "error-text", role: "alert" });
    const submit = h("button", { class: "btn primary", type: "submit", text: submitLabel });
    return h("form", {
      class: "col",
      on: {
        submit: async (e) => {
          e.preventDefault();
          error.textContent = "";
          submit.disabled = true;
          try {
            await onSubmit();
          } catch (err) {
            error.textContent = errorText(err);
          } finally {
            submit.disabled = false;
          }
        },
      },
    }, children, error, h("div", { class: "row modal-actions" }, buttons, h("span", { class: "spacer" }), submit));
  };
  const cancel = () => h("button", { class: "btn", type: "button", text: t("common.cancel"), on: { click: () => m.close() } });

  const passwordStep = () => {
    step = "password";
    title.textContent = t("twofactor.turn_on_title");
    const pw = passwordField({ autocomplete: "current-password" });
    mount(body,
      h("p", { class: "muted", text: t("twofactor.turn_on_intro") }),
      formOf(async () => {
        const setup = await invoke("server_2fa_setup", { password: pw.input.value });
        pw.reset();
        scanStep(setup);
      }, t("common.continue"), [field(t("twofactor.server_password"), pw)], [cancel()]));
    pw.focus();
  };

  const scanStep = (setup) => {
    step = "scan";
    title.textContent = t("twofactor.scan_title");
    const code = twoFactorField();
    // Only the app's code here, not a recovery code (there are none yet).
    code.el.querySelector(".hint").remove();
    const copyKey = rowButton("copy", t("twofactor.copy_key"), () => invoke("copy_secret", { text: setup.secret }).then(() => toast(t("twofactor.key_copied"))).catch((e) => toast(errorText(e), "error")));
    mount(body,
      h("div", { class: "tf-scan" },
        h("div", { class: "qr-box" }, qrCode(setup.qr, t("twofactor.qr_label"))),
        h("div", { class: "col grow" },
          h("p", { text: t("twofactor.scan_step") }),
          h("p", { class: "muted", text: t("twofactor.cant_scan") }),
          h("div", { class: "fingerprint" },
            h("div", { class: "fp selectable mono", text: setup.secret_groups }),
            h("div", { class: "faint", text: [setup.issuer, setup.account, t("twofactor.digits_period", { digits: setup.digits || 6, period: setup.period || 30 })].filter(Boolean).join(" · ") })),
          h("div", { class: "row" }, copyKey))),
      formOf(async () => {
        const otp = code.value();
        if (!otp) throw new Error(t("twofactor.enter_code"));
        const r = await invoke("server_2fa_confirm", { code: otp });
        codesStep(r.recovery_codes || []);
      }, t("common.turn_on"), [h("p", { text: t("twofactor.code_step") }), code.el], [cancel()]));
    code.input.focus();
  };

  const codesStep = (codes) => {
    step = "codes";
    title.textContent = t("twofactor.codes_title");
    const saved = h("input", { type: "checkbox" });
    const done = h("button", { class: "btn primary", type: "button", disabled: true, text: t("common.done"), on: { click: () => { step = "done"; m.close(); toast(t("twofactor.is_on")); } } });
    saved.addEventListener("change", () => { done.disabled = !saved.checked; });
    mount(body,
      h("div", { class: "banner ok-banner" }, icon("check"), h("span", { class: "grow", text: t("twofactor.is_on_sentence") })),
      h("p", { text: t("twofactor.codes_text") }),
      h("div", { class: "recovery-codes selectable mono" }, codes.map((c) => h("span", { text: c }))),
      h("div", { class: "row" },
        rowButton("copy", t("common.copy"), () => invoke("copy_secret", { text: codes.join("\n") }).then(() => toast(t("twofactor.codes_copied"))).catch((e) => toast(errorText(e), "error"))),
        rowButton("download", t("common.save_to_file"), async () => {
          try {
            const path = await invoke("server_2fa_save_codes", { codes });
            if (path) toast(t("common.saved_to", { path }), "", 7000);
          } catch (e) {
            toast(errorText(e), "error");
          }
        })),
      h("label", { class: "check" }, saved, t("twofactor.saved_codes")),
      h("div", { class: "row modal-actions" }, h("span", { class: "spacer" }), done));
    saved.focus();
  };

  passwordStep();
}

export function openDisableDialog({ onDone } = {}) {
  const m = modal({ label: t("twofactor.turn_off_label"), cls: "narrow" });
  const pw = passwordField({ autocomplete: "current-password" });
  const code = twoFactorField();
  const error = h("div", { class: "error-text", role: "alert" });
  const submit = h("button", { class: "btn primary", type: "submit", text: t("common.turn_off") });
  mount(m.box,
    h("div", { class: "row" }, h("span", { class: "modal-icon warn" }, icon("shieldAlert")), h("h2", { class: "grow", text: t("twofactor.turn_off_title") })),
    h("p", { class: "muted", text: t("twofactor.turn_off_text") }),
    h("form", {
      class: "col",
      on: {
        submit: async (e) => {
          e.preventDefault();
          error.textContent = "";
          submit.disabled = true;
          try {
            if (!code.value()) throw new Error(t("twofactor.enter_code_or_recovery"));
            await invoke("server_2fa_disable", { password: pw.input.value, code: code.value() });
            m.close();
            toast(t("twofactor.is_off"));
            if (onDone) onDone();
          } catch (err) {
            error.textContent = errorText(err);
          } finally {
            submit.disabled = false;
          }
        },
      },
    },
    field(t("twofactor.server_password"), pw),
    code.el,
    error,
    h("div", { class: "row modal-actions" },
      h("span", { class: "spacer" }),
      h("button", { class: "btn", type: "button", text: t("common.cancel"), on: { click: () => m.close() } }),
      submit)));
  pw.focus();
}

const EVENT_ICONS = {
  sign_in: "logIn",
  sign_in_failed: "alert",
  account_slowed_down: "timer",
  device_added: "monitor",
  device_revoked: "monitor",
  password_changed: "key",
  password_reset_requested: "mail",
  admin_password_reset: "key",
  email_changed: "mail",
  invite_issued: "mail",
  reset_link_issued: "mail",
  signup: "user",
  user_added: "user",
};

export class SecurityActivity {
  constructor(hooks = {}) {
    this.hooks = hooks;
    this.el = h("div", { class: "set-rows" });
    this.loaded = false;
  }

  async load() {
    this.loaded = true;
    mount(this.el, settingsRow("clock", t("common.loading"), {}));
    let r;
    try {
      r = await invoke("server_security_events", { limit: 50 });
    } catch (e) {
      mount(this.el, settingsRow("alert", t("twofactor.activity_failed"), {
        value: errorText(e),
        valueClass: "warn",
        control: rowButton("retry", t("common.try_again"), () => this.load()),
      }));
      return;
    }
    if (r.signed_out) {
      mount(this.el, settingsRow("cloudOff", t("devices.signed_out_title"), {
        value: t("twofactor.activity_signed_out"),
        valueClass: "warn",
        control: this.hooks.onSignIn ? rowButton("logIn", t("common.sign_in_ellipsis"), () => this.hooks.onSignIn(), "primary") : null,
      }));
      return;
    }
    const events = r.events || [];
    if (!events.length) {
      mount(this.el, settingsRow("history", t("twofactor.activity_none"), {}));
      return;
    }
    mount(this.el, events.map((e) => this.row(e)));
  }

  row(e) {
    const ev = eventText(e);
    const when = e.at ? agoText(e.at) : "";
    const where = [e.device_name, e.ip ? t("twofactor.ip", { ip: e.ip }) : null, when].filter(Boolean).join(" · ");
    const row = settingsRow(ev.warn ? "alert" : EVENT_ICONS[e.event] || (String(e.event).startsWith("2fa") ? "phoneApp" : "history"), [
      h("span", { class: "ellipsis", text: ev.title, title: ev.title }),
      e.current ? h("span", { class: "chip", text: t("devices.this_device") }) : null,
      ev.admin ? h("span", { class: "chip warn", text: t("twofactor.admin"), title: t("twofactor.admin_title") }) : null,
    ], {
      value: [ev.detail, where].filter(Boolean).join(" · "),
      valueClass: ev.warn ? "warn" : "",
      valueTitle: e.at ? formatDateTime(e.at, { dateStyle: "medium", timeStyle: "medium" }) : null,
    });
    return row;
  }
}
