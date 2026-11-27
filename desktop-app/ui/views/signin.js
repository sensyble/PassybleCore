// "Sign in to Passyble Server": one field takes a server address or a pass+server:// link (sign-in, invite,
// password reset, or pairing, which goes to the pairing flow), pasted or read from a QR code image / the clipboard.
// A server without a publicly trusted certificate and without a pin from a link gets "Trust this server?" with
// its fingerprint (trust on first use). One password signs in and unlocks the vault; the server only sees a
// value derived from it.
//
// Also the "Change password" / "Sign in again" dialogs for Passyble Server vaults (Settings → This vault).
//
// Invite and reset links skip the form: "Choose your password" sets it with the one-time code. With two-factor on,
// requests answer `{step: "two_factor"}` and are sent again with the code (each code works once).

import { errorText, h, icon, iconButton, invoke, mount, passwordField, t, toast, trustDialog } from "../lib.js";
import { masterFeedback, masterIssueText, masterNames } from "./master-password-model.js";
import { afterPasswordChange } from "./password-change.js";
import { minStrength, strengthCheck } from "./teams-model.js";

export function strength(password) {
  let score = 0;
  if (password.length >= 12) score++;
  if (password.length >= 16) score++;
  if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score++;
  if (/\d/.test(password)) score++;
  if (/[^A-Za-z0-9]/.test(password)) score++;
  if (password.length < 8) return { text: t("signin.strength_short"), ok: false };
  return score >= 4
    ? { text: t("strength.strong"), ok: true }
    : score >= 2
      ? { text: t("signin.strength_ok"), ok: true }
      : { text: t("signin.strength_weak"), ok: true };
}

/** The first pass+server:// link in pasted text (surrounding text, quotes or <> allowed). */
export function extractLink(text) {
  const m = /pass\+server:\/\/[^\s<>"'`]+/i.exec(String(text || ""));
  return m ? m[0] : null;
}

export function plainAddress(text) {
  const v = String(text || "").trim().replace(/\/+$/, "");
  if (!v || /\s/.test(v) || extractLink(v)) return null;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(v) && !/^https?:\/\//i.test(v)) return null;
  return v;
}

let uid = 0;
function field(label, input, hint) {
  const id = `si-${++uid}`;
  const target = input.input || input;
  target.id = id;
  return h("div", { class: "field" }, h("label", { for: id, text: label }), input.el || input, hint ? h("span", { class: "hint", text: hint }) : null);
}

/**
 * Live check under a new master password (`input`): the core's rule (`master_password_check`), a moment after each
 * keystroke. `names()`: what it should not be built from; `activeVault`: also the open vault's names.
 * `onResult(answer)`: each answer, for a strength bar. Returns `{ el, ensure(), clear() }`; `ensure()` throws the
 * first reason if the password is refused.
 */
export function masterPasswordMeter(input, { names = () => [], activeVault = false, onResult = null } = {}) {
  const el = h("div", { class: "hint master-check", "aria-live": "polite" });
  let timer = 0;
  let seq = 0;
  const ask = () =>
    invoke("master_password_check", { password: input.value, names: masterNames(names()), activeVault }).catch(() => null);
  const render = (result) => {
    if (onResult) onResult(input.value ? result : null);
    const f = masterFeedback(result, input.value);
    if (f.ok) mount(el, h("span", { class: "ok-text", text: f.okText }));
    else if (f.reasons.length) mount(el, h("ul", { class: "pw-issues" }, f.reasons.map((r) => h("li", { class: "high", text: r }))));
    else mount(el);
  };
  const refresh = async () => {
    clearTimeout(timer);
    const n = ++seq;
    if (!input.value) {
      render(null);
      return;
    }
    const result = await ask();
    if (n === seq) render(result);
  };
  input.addEventListener("input", () => {
    clearTimeout(timer);
    if (!input.value) {
      seq++;
      render(null);
      return;
    }
    timer = setTimeout(refresh, MASTER_CHECK_DELAY_MS);
  });
  return {
    el,
    refresh,
    async ensure() {
      if (!input.value) throw new Error(masterIssueText("too_short"));
      clearTimeout(timer);
      const n = ++seq;
      const result = await ask();
      if (n === seq) render(result);
      // No answer (the check failed): the command that sets the password decides.
      if (result && result.ok !== true) throw new Error(masterFeedback(result, input.value).reasons[0]);
    },
    clear() {
      clearTimeout(timer);
      seq++;
      mount(el);
    },
  };
}

const MASTER_CHECK_DELAY_MS = 150;

/**
 * New password + repeat; returns {els, first, value(), check(), checkPolicy(), clear()}. A master password gets the
 * live rule (`options.names`, `options.activeVault`) and an async `check()`; `options.master: false` keeps the plain
 * hint, an 8-character minimum and a sync `check()`. `checkPolicy()` refuses a password below the organisation's
 * minimum strength.
 */
export function newPasswordFields(label = t("signin.new_password"), options = {}) {
  const master = options.master !== false;
  const pw = passwordField({ autocomplete: "new-password" });
  const pw2 = passwordField({ autocomplete: "new-password" });
  const meter = master
    ? masterPasswordMeter(pw.input, { names: options.names, activeVault: !!options.activeVault })
    : null;
  const hint = meter ? meter.el : h("div", { class: "hint" });
  if (!meter) {
    pw.input.addEventListener("input", () => {
      hint.textContent = pw.input.value ? strength(pw.input.value).text : "";
    });
  }
  const policyHint = master ? h("div", { class: "hint", "aria-live": "polite" }) : null;
  const policy = master ? invoke("policy_status").then((s) => (s && s.effective) || null).catch(() => null) : Promise.resolve(null);
  let policySeq = 0;
  const policyVerdict = async (password) => {
    const p = await policy;
    if (!minStrength(p) || !password) return { ok: true, text: "" };
    const r = await invoke("password_check", { password }).catch(() => null);
    return strengthCheck(r && Number.isFinite(r.score) ? r.score : null, p);
  };
  if (policyHint) {
    pw.input.addEventListener("input", async () => {
      const value = pw.input.value;
      const n = ++policySeq;
      policyHint.textContent = "";
      policyHint.classList.remove("error-text");
      if (!value) return;
      const verdict = await policyVerdict(value);
      if (n !== policySeq || !verdict.text) return;
      policyHint.textContent = verdict.text;
      policyHint.classList.toggle("error-text", !verdict.ok);
    });
  }
  const id = `si-${++uid}`;
  pw.input.id = id;
  const same = () => {
    if (pw.input.value !== pw2.input.value) throw new Error(t("onboarding.mismatch_again"));
    return pw.input.value;
  };
  return {
    first: pw.input,
    els: [
      h("div", { class: "field" }, h("label", { for: id, text: label }), pw.el, hint, policyHint),
      field(t("signin.repeat_it"), pw2),
    ],
    value: () => pw.input.value,
    check: meter
      ? async () => {
          await meter.ensure();
          return same();
        }
      : () => {
          if (pw.input.value.length < 8) throw new Error(t("signin.password_too_short"));
          return same();
        },
    /** `check()`, and the organisation's minimum strength for a master password (Rust checks again). */
    async checkPolicy() {
      const value = await this.check();
      const verdict = await policyVerdict(value);
      if (!verdict.ok) throw new Error(verdict.text);
      return value;
    },
    clear() {
      pw.reset();
      pw2.reset();
      if (meter) meter.clear();
      else hint.textContent = "";
      if (policyHint) {
        policySeq++;
        policyHint.textContent = "";
        policyHint.classList.remove("error-text");
      }
    },
  };
}

const TWO_FACTOR_INVALID = t("errors.two_factor_invalid");

/** The two-factor code field: 6 digits, or a recovery code (xxxx-xxxx-xxxx) after switching. Returns `{ el, input, value() }`. */
export function twoFactorField() {
  let recovery = false;
  const input = h("input", { class: "input mono otp-input", spellcheck: "false", autocomplete: "one-time-code" });
  const id = `si-${++uid}`;
  input.id = id;
  const label = h("label", { for: id });
  const toggle = h("button", { class: "link", type: "button" });
  const paint = () => {
    label.textContent = recovery ? t("recovery.title") : t("signin.app_code");
    input.inputMode = recovery ? "text" : "numeric";
    input.maxLength = recovery ? 24 : 8;
    input.placeholder = recovery ? "xxxx-xxxx-xxxx" : "123456";
    toggle.textContent = recovery ? t("signin.use_app") : t("signin.use_recovery");
  };
  toggle.addEventListener("click", () => {
    recovery = !recovery;
    input.value = "";
    paint();
    input.focus();
  });
  input.addEventListener("input", () => {
    // A 6-digit code is often pasted as "123 456".
    if (!recovery) input.value = input.value.replace(/[^\d]/g, "");
  });
  paint();
  return {
    el: h("div", { class: "field" }, label, input, h("span", { class: "hint" }, toggle)),
    input,
    value: () => input.value.trim(),
  };
}

/**
 * The two-factor step after `answer` (`{step: "two_factor", invalid, password_set}`). `retry(otp)` resends the request
 * with the code; another two-factor answer shows "wrong or already used"; anything else goes to `onDone(answer)`.
 * `buttons`: extra buttons for the left of the button row.
 */
export function twoFactorStep({ answer, retry, onDone, buttons = [], submitLabel = t("common.continue") }) {
  const code = twoFactorField();
  let passwordSet = !!(answer && answer.password_set);
  const intro = h("p", { class: "muted" });
  const paintIntro = () => {
    intro.textContent = passwordSet
      ? t("signin.two_factor_next")
      : t("signin.two_factor_intro");
  };
  paintIntro();
  const el = form(
    async () => {
      const otp = code.value();
      if (!otp) {
        code.input.focus();
        throw new Error(t("signin.enter_app_code"));
      }
      const r = await retry(otp);
      if (r && r.step === "two_factor") {
        code.input.value = "";
        code.input.focus();
        if (r.password_set && !passwordSet && !r.invalid) {
          passwordSet = true;
          paintIntro();
          return;
        }
        throw new Error(TWO_FACTOR_INVALID);
      }
      onDone(r);
    },
    submitLabel,
    [code.el],
    buttons,
  );
  if (answer && answer.invalid) el.querySelector(".error-text").textContent = TWO_FACTOR_INVALID;
  return { els: [h("div", { class: "row two-factor-head" }, icon("phoneApp"), h("span", { class: "grow t", text: t("twofactor.title") })), intro, el], focus: () => code.input.focus() };
}

function form(onSubmit, submitLabel, children, extraButtons = []) {
  const error = h("div", { class: "error-text", role: "alert" });
  const submit = h("button", { class: "btn primary", type: "submit", text: submitLabel });
  const el = h(
    "form",
    {
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
    },
    ...children,
    error,
    h("div", { class: "row" }, ...extraButtons, h("span", { class: "spacer" }), submit),
  );
  return el;
}

/** The server field: an address or a pass+server:// link, with QR buttons. `onLink(link)` runs for a pasted/scanned link. */
function serverField(onLink) {
  const input = h("input", {
    class: "input",
    spellcheck: "false",
    autocomplete: "url",
    placeholder: t("signin.server_placeholder"),
  });
  const error = h("div", { class: "error-text", role: "alert" });
  const check = () => {
    const link = extractLink(input.value);
    if (link) onLink(link);
  };
  input.addEventListener("change", check);
  input.addEventListener("paste", () => setTimeout(check, 0));
  const fromQr = async (cmd) => {
    error.textContent = "";
    try {
      const link = await invoke(cmd);
      if (!link) return;
      input.value = link;
      onLink(link);
    } catch (e) {
      error.textContent = errorText(e);
    }
  };
  const id = `si-${++uid}`;
  input.id = id;
  const el = h(
    "div",
    { class: "field" },
    h("label", { for: id, text: t("server.info_server") }),
    h(
      "div",
      { class: "server-input-row field-tools" },
      input,
      h("span", { class: "tools" },
        iconButton("image", t("signin.qr_picture"), () => fromQr("server_qr_from_file"), "ghost small"),
        iconButton("qr", t("signin.qr_clipboard"), () => fromQr("server_qr_from_clipboard"), "ghost small")),
    ),
    h("span", { class: "hint", text: t("signin.server_hint") }),
    error,
  );
  return { el, input, error, set: (v) => { input.value = v || ""; } };
}

/**
 * The sign-in flow, rendered into `root`. `options`: `link` (a link or server address to prefill from), `back()`
 * (a button for the left of the button row), `onDone(result)`, `onPairingLink(link)` for links that carry a device token.
 */
export class SignInFlow {
  constructor(root, options) {
    this.root = root;
    this.options = options;
    this.pins = [];
    // The server the pins belong to (from a link, the last sign-in, or trusted on first use).
    this.pinsFor = null;
    this.linkInfo = null;
    this.password = "";
    this.start();
  }

  frame(...children) {
    mount(this.root, ...children);
  }

  async applyLink(link) {
    this.server.error.textContent = "";
    if (!link.trim()) return;
    try {
      const info = await invoke("server_signin_link", { link });
      if (info.pairing) {
        if (this.options.onPairingLink) this.options.onPairingLink(link.trim());
        else this.server.error.textContent = t("signin.pairing_link");
        return;
      }
      if (info.code_kind) {
        this.codeFlow(link.trim(), info);
        return;
      }
      this.linkInfo = info;
      this.server.set(info.host);
      if (info.username) this.user.value = info.username;
      this.pins = info.pins || [];
      this.pinsFor = info.server_url;
      this.showTrust(info);
      (this.user.value ? this.pw.input : this.user).focus();
    } catch (e) {
      this.server.error.textContent = errorText(e);
    }
  }

  showTrust(info) {
    mount(
      this.trust,
      info.pinned
        ? h("div", { class: "banner" }, icon("shield"), h("span", { class: "grow", text: t("signin.pinned", { host: info.host }) }))
        : null,
      info.https ? null : h("div", { class: "banner warn" }, icon("alert"), h("span", { class: "grow", text: t("signin.plain_http") })),
    );
  }

  serverUrl() {
    const typed = this.server.input.value.trim();
    if (this.linkInfo && (typed === this.linkInfo.host || extractLink(typed))) return this.linkInfo.server_url;
    return plainAddress(typed) || typed;
  }

  pinsFor_(url) {
    const norm = (u) => String(u || "").trim().replace(/\/+$/, "").replace(/^https:\/\//i, "").toLowerCase();
    return this.pinsFor && norm(url) === norm(this.pinsFor) ? this.pins : [];
  }

  start(prefill = null) {
    this.server = serverField((link) => this.applyLink(link));
    this.user = h("input", { class: "input", spellcheck: "false", autocomplete: "username", placeholder: t("signin.user_placeholder") });
    this.pw = passwordField({ autocomplete: "current-password" });
    this.trust = h("div", { class: "col" });
    this.server.input.addEventListener("input", () => {
      // A link's details only apply while its server is in the field.
      if (this.linkInfo && this.server.input.value.trim() !== this.linkInfo.host) {
        this.linkInfo = null;
        mount(this.trust);
      }
    });
    this.frame(
      h("h2", { text: t("vaults.sign_in_server") }),
      h("p", {
        class: "muted",
        text: t("signin.intro"),
      }),
      form(
        () => this.signIn(),
        t("prompt.sign_in"),
        [
          this.server.el,
          field(t("signin.user"), this.user),
          h("div", { class: "field" }, field(t("field.password"), this.pw),
            h("button", { class: "link caption-link", type: "button", text: t("signin.forgot"), on: { click: () => this.forgot() } })),
          this.trust,
        ],
        [
          this.options.back(),
        ],
      ),
    );
    if (prefill) {
      this.server.set(prefill.server || "");
      this.user.value = prefill.user || "";
      if (prefill.info) this.showTrust(prefill.info);
      this.focusFirstEmpty();
    } else if (this.options.link && extractLink(this.options.link)) {
      this.server.set(this.options.link);
      this.applyLink(extractLink(this.options.link));
    } else if (this.options.link) {
      this.server.set(plainAddress(this.options.link) || this.options.link);
      this.rememberedUser().finally(() => this.focusFirstEmpty());
    } else {
      this.remembered().finally(() => this.focusFirstEmpty());
    }
  }

  focusFirstEmpty() {
    if (!this.server.input.value.trim()) this.server.input.focus();
    else if (!this.user.value.trim()) this.user.focus();
    else this.pw.focus();
  }

  async remembered() {
    const status = await invoke("status").catch(() => null);
    if (!status || !status.last_server_url || this.server.input.value.trim()) return;
    this.server.set(status.last_server_url.replace(/^https:\/\//i, ""));
    if (!this.user.value) this.user.value = status.last_server_user || "";
    this.pins = status.last_server_pins || [];
    this.pinsFor = status.last_server_url;
  }

  async rememberedUser() {
    const status = await invoke("status").catch(() => null);
    if (!status || !status.last_server_url) return;
    const norm = (u) => String(u || "").trim().replace(/\/+$/, "").replace(/^https:\/\//i, "").toLowerCase();
    if (norm(status.last_server_url) !== norm(this.server.input.value)) return;
    if (!this.user.value) this.user.value = status.last_server_user || "";
    this.pins = status.last_server_pins || [];
    this.pinsFor = status.last_server_url;
  }

  snapshot() {
    return { server: this.server.input.value, user: this.user.value };
  }

  /** Runs a server request that may answer `{step: "trust", server_url, host, pin}`: asks "Trust this server?" and reruns with the pin. */
  async withTrust(url, run) {
    let r = await run(this.pinsFor_(url));
    if (r && r.step === "trust") {
      const ok = await trustDialog({ host: r.host, pin: r.pin });
      if (!ok) throw new Error(t("signin.not_trusted"));
      this.pins = [r.pin];
      this.pinsFor = r.server_url;
      r = await run(this.pins);
    }
    return r;
  }

  forgot() {
    const back = this.snapshot();
    const server = serverField(() => {});
    const who = h("input", { class: "input", spellcheck: "false", autocomplete: "username" });
    server.set(back.server);
    who.value = back.user;
    const backButton = () => h("button", { class: "btn ghost", type: "button", text: t("common.back"), on: { click: () => this.start(back) } });
    this.frame(
      h("h2", { text: t("signin.reset_title") }),
      h("p", {
        class: "muted",
        text: t("signin.reset_intro"),
      }),
      form(
        async () => {
          const typed = server.input.value.trim();
          if (!typed) throw new Error(t("signin.enter_server"));
          if (!who.value.trim()) throw new Error(t("signin.enter_user"));
          const link = extractLink(typed);
          const serverUrl = link ? (await invoke("server_signin_link", { link })).server_url : plainAddress(typed) || typed;
          await this.withTrust(serverUrl, (pins) => invoke("server_request_reset", { serverUrl, userOrEmail: who.value.trim(), pins }));
          this.frame(
            h("h2", { text: t("signin.check_email") }),
            h("p", {
              text: t("signin.check_email_text", { user: who.value.trim() }),
            }),
            h("p", { class: "muted", text: t("signin.check_email_hint") }),
            h("div", { class: "row" }, h("span", { class: "spacer" }), h("button", { class: "btn primary", type: "button", text: t("signin.back_to_signin"), on: { click: () => this.start(back) } })),
          );
        },
        t("signin.send_reset"),
        [server.el, field(t("signin.user"), who)],
        [backButton()],
      ),
    );
    (server.input.value ? who : server.input).focus();
  }

  codeFlow(link, info) {
    const reset = info.code_kind === "reset";
    this.codeLink = link;
    const fields = newPasswordFields(reset ? t("signin.new_password") : t("signin.your_password"), { names: () => [info.username] });
    const trust = h("div", { class: "col" });
    this.trust = trust;
    this.showTrust(info);
    this.frame(
      h("h2", { text: reset ? t("signin.reset_title") : t("signin.choose_title") }),
      h("p", {
        class: "muted",
        text: reset
          ? t("signin.reset_text", { username: info.username, host: info.host })
          : t("signin.invite_text", { username: info.username, host: info.host }),
      }),
      reset
        ? h("div", { class: "banner warn", text: t("signin.reset_warning") })
        : null,
      trust,
      form(
        async () => {
          const next = await fields.check();
          const link = this.codeLink;
          // The link's code is used up once the password is set; signing in then asks for the next two-factor code.
          let passwordSet = false;
          const send = async (otp) => {
            const r = passwordSet
              ? await invoke("server_code_signin", { link, password: next, otp })
              : await invoke("server_code_set_password", { link, newPassword: next, otp });
            if (r.step !== "two_factor" || r.password_set) passwordSet = true;
            return r;
          };
          const res = await send(null);
          this.password = next;
          this.retry2fa = send;
          fields.clear();
          this.next(res);
        },
        reset ? t("signin.reset_password") : t("recovery.set_password"),
        fields.els,
        [this.cancelButton()],
      ),
    );
    fields.first.focus();
  }

  unlockLocal(r) {
    this.frame(
      h("h2", { text: t("signin.reencrypt_title") }),
      h("p", {
        class: "muted",
        text: t("signin.reencrypt_text", { vault: r.vault_name }),
      }),
      form(
        async () => {
          const res = await invoke("server_reset_hello", { vaultId: r.vault_id, password: this.password });
          this.next(res);
        },
        t("unlock.with_hello"),
        [],
        [
          this.cancelButton(),
          h("button", { class: "btn ghost", type: "button", text: t("signin.use_previous"), on: { click: () => this.previousPassword({ reset: true }) } }),
        ],
      ),
    );
  }

  newVaultConfirm() {
    const agree = h("input", { type: "checkbox" });
    this.frame(
      h("h2", { text: t("signin.new_vault_title") }),
      h("div", {
        class: "banner warn",
        text: t("signin.new_vault_warning"),
      }),
      h("p", {
        class: "muted",
        text: t("signin.new_vault_text", { suffix: t("signin.before_reset_suffix") }),
      }),
      form(
        async () => {
          if (!agree.checked) throw new Error(t("signin.new_vault_agree_needed"));
          const res = await invoke("server_signin_new_vault", { password: this.password });
          this.next(res);
        },
        t("signin.new_vault_start"),
        [h("label", { class: "check" }, agree, t("signin.new_vault_agree"))],
        [h("button", { class: "btn ghost", type: "button", text: t("common.back"), on: { click: () => this.previousPassword({ reset: true }) } })],
      ),
    );
  }

  async signIn() {
    const typed = this.server.input.value.trim();
    if (!typed) {
      this.server.input.focus();
      throw new Error(t("signin.enter_server_or_link"));
    }
    const link = extractLink(typed);
    if (link && !this.linkInfo) {
      await this.applyLink(link);
      return;
    }
    if (!this.user.value.trim()) {
      this.user.focus();
      throw new Error(t("signin.enter_user"));
    }
    if (!this.pw.input.value) {
      this.pw.focus();
      throw new Error(t("signin.enter_password"));
    }
    this.password = this.pw.input.value;
    const serverUrl = this.serverUrl();
    const username = this.user.value.trim();
    const r = await this.withTrust(serverUrl, (pins) =>
      invoke("server_signin", { serverUrl, username, password: this.password, pins, otp: null }),
    );
    this.retry2fa = (otp) => invoke("server_signin", { serverUrl, username, password: this.password, pins: this.pinsFor_(serverUrl), otp });
    this.pw.reset();
    this.next(r);
  }

  /** The two-factor code step; `this.retry2fa(otp)` repeats the request that asked for it. */
  twoFactor(r) {
    const retry = this.retry2fa;
    const step = twoFactorStep({ answer: r, retry, onDone: (res) => this.next(res), buttons: [this.cancelButton()] });
    this.frame(h("h2", { text: t("signin.enter_code") }), ...step.els);
    step.focus();
  }

  next(r) {
    if (r.step === "two_factor") this.twoFactor(r);
    else if (r.step === "choose_password") this.choosePassword(r);
    else if (r.step === "previous_password") this.previousPassword(r);
    else if (r.step === "unlock_local") this.unlockLocal(r);
    else this.done(r);
  }

  cancelButton() {
    return h("button", {
      class: "btn ghost",
      type: "button",
      text: t("common.cancel"),
      on: {
        click: () => {
          invoke("server_signin_cancel").catch(() => {});
          this.password = "";
          this.start();
        },
      },
    });
  }

  choosePassword(r) {
    const fields = newPasswordFields(t("signin.your_new_password"), { names: () => [r.username] });
    this.frame(
      h("h2", { text: t("signin.choose_own_title") }),
      h("p", {
        class: "muted",
        text: t("signin.choose_own_text", { username: r.username }),
      }),
      form(
        async () => {
          const next = await fields.check();
          const current = this.password;
          const send = async (otp) => {
            const r = await invoke("server_signin_set_password", { current, newPassword: next, otp });
            if (r.step !== "two_factor") this.password = next;
            return r;
          };
          const res = await send(null);
          this.retry2fa = send;
          fields.clear();
          this.next(res);
        },
        t("recovery.set_password"),
        fields.els,
        [this.cancelButton()],
      ),
    );
    fields.first.focus();
  }

  previousPassword(r = {}) {
    const prev = passwordField({ autocomplete: "current-password" });
    const extra = r.reset
      ? [h("button", { class: "btn ghost", type: "button", text: t("signin.new_vault_ellipsis"), on: { click: () => this.newVaultConfirm() } })]
      : [];
    this.frame(
      h("h2", { text: t("signin.unlock_title") }),
      h("p", {
        class: "muted",
        text: r.reset
          ? t("signin.previous_after_reset")
          : t("signin.previous_text"),
      }),
      form(
        async () => {
          const res = await invoke("server_signin_previous", { previous: prev.input.value, password: this.password });
          prev.reset();
          this.next(res);
        },
        t("signin.unlock_reencrypt"),
        [
          field(t("signin.previous_password"), prev,
            t("signin.previous_hint")),
        ],
        [this.cancelButton(), ...extra],
      ),
    );
    prev.focus();
  }

  done(r) {
    this.password = "";
    if (this.options.onDone) this.options.onDone(r);
    // A sign-in that re-encrypted the vault with a new key: follow-ups.
    if (r && r.purge) afterPasswordChange(r);
  }
}

/**
 * A pass+server:// link or server address opened while a vault is unlocked: the sign-in flow in a dialog, so nothing
 * is locked until it finishes. `onDone(result)` after the flow finished.
 */
export function openLinkDialog(link, onDone) {
  const body = h("div", { class: "col" });
  const keys = (e) => {
    if (e.key === "Escape" && !document.querySelector(".modal.trust")) {
      e.preventDefault();
      cancel();
    }
  };
  const close = () => {
    document.removeEventListener("keydown", keys);
    backdrop.remove();
  };
  const cancel = () => {
    invoke("server_signin_cancel").catch(() => {});
    close();
  };
  const backdrop = h(
    "div",
    { class: "modal-backdrop" },
    h("div", { class: "modal", role: "dialog", "aria-modal": "true", "aria-label": t("signin.dialog_label") }, body),
  );
  document.addEventListener("keydown", keys);
  document.body.append(backdrop);
  new SignInFlow(body, {
    link,
    back: () => h("button", { class: "btn", type: "button", text: t("common.close"), on: { click: cancel } }),
    onDone: (r) => {
      close();
      toast(r && r.rewrapped ? t("signin.reset_done") : t("signin.signed_in"));
      if (r && r.warning) toast(r.warning, "", 9000);
      if (onDone) onDone(r);
    },
  });
}

/**
 * Settings → This vault → Change password (Passyble Server vaults), with "Changed on another device?" to adopt a
 * password changed elsewhere. `options.signIn` opens it as "Sign in again" for a device that was signed out. Both use
 * `server_adopt_password`, which re-encrypts the unlocked vault if the password changed.
 */
export function openChangePasswordDialog(options = {}) {
  let mode = options.signIn ? "signin" : "change"; // change | adopt | signin
  const body = h("div", { class: "col" });
  const title = h("h2", { text: options.signIn ? t("vaults.sign_in_server") : t("signin.change_password") });
  const keys = (e) => {
    if (e.key === "Escape") {
      e.preventDefault();
      close();
    }
  };
  const close = () => {
    document.removeEventListener("keydown", keys);
    backdrop.remove();
  };
  const cancel = () => h("button", { class: "btn", type: "button", text: t("common.cancel"), on: { click: close } });
  const finish = (r, message, ...more) => {
    close();
    toast(message);
    for (const m of more) toast(m, "", 9000);
    if (r && r.warning) toast(r.warning, "", 9000);
    if (options.onDone) options.onDone();
  };
  const adopted = (r) =>
    r.signed_in
      ? r.unchanged
        ? t("signin.signed_in_again")
        : t("signin.signed_in_again_new")
      : r.unchanged
        ? options.signIn ? t("signin.signed_in") : t("signin.already_uses")
        : t("signin.now_uses_new");
  const codeStep = (answer, retry, onDone) => {
    const step = twoFactorStep({
      answer,
      retry,
      onDone,
      buttons: [h("button", { class: "btn ghost", type: "button", text: t("common.back"), on: { click: () => render() } }), cancel()],
    });
    mount(body, ...step.els);
    step.focus();
  };
  const render = () => {
    if (mode === "change") {
      title.textContent = t("signin.change_password");
      const current = passwordField({ autocomplete: "current-password" });
      const fields = newPasswordFields(undefined, { activeVault: true });
      mount(
        body,
        h("p", { class: "muted", text: t("signin.change_text") }),
        form(
          async () => {
            const next = await fields.checkPolicy();
            const old = current.input.value;
            const changed = (r) => {
              finish(r, t("signin.changed"), ...(r.others_signed_out ? [t("signin.others_signed_out")] : []));
              afterPasswordChange(r);
            };
            const send = (otp) => invoke("server_change_password", { current: old, newPassword: next, otp });
            const r = await send(null);
            if (r.step === "two_factor") codeStep(r, send, changed);
            else changed(r);
          },
          t("signin.change_password"),
          [field(t("signin.current_password"), current), ...fields.els],
          [
            h("button", { class: "btn ghost", type: "button", text: t("signin.changed_elsewhere"), on: { click: () => { mode = "adopt"; render(); } } }),
            cancel(),
          ],
        ),
      );
      current.focus();
    } else {
      const signIn = mode === "signin";
      title.textContent = signIn ? t("vaults.sign_in_server") : t("signin.change_password");
      const pw = passwordField({ autocomplete: "current-password" });
      mount(
        body,
        h("p", {
          class: "muted",
          text: signIn
            ? t("signin.signin_again_text")
            : t("signin.adopt_text"),
        }),
        form(
          async () => {
            const password = pw.input.value;
            const send = (otp) => invoke("server_adopt_password", { password, otp });
            const r = await send(null);
            const adoptedDone = (res) => {
              finish(res, adopted(res));
              afterPasswordChange(res);
            };
            if (r.step === "two_factor") codeStep(r, send, adoptedDone);
            else adoptedDone(r);
          },
          signIn ? t("prompt.sign_in") : t("signin.use_this_password"),
          [field(t("signin.current_server_password"), pw)],
          [
            signIn ? null : h("button", { class: "btn ghost", type: "button", text: t("common.back"), on: { click: () => { mode = "change"; render(); } } }),
            cancel(),
          ],
        ),
      );
      pw.focus();
    }
  };
  const dialog = h(
    "div",
    { class: "modal", role: "dialog", "aria-modal": "true", "aria-label": title.textContent },
    title,
    body,
  );
  const backdrop = h("div", { class: "modal-backdrop" }, dialog);
  document.addEventListener("keydown", keys);
  document.body.append(backdrop);
  render();
}

/**
 * Change password for a vault not on Passyble Server: current password, new password twice. `change_master_password`
 * re-encrypts the vault and syncs (Windows Hello is set up again); `afterPasswordChange` handles the follow-ups.
 */
export function openChangeMasterPasswordDialog(options = {}) {
  const keys = (e) => {
    if (e.key === "Escape") {
      e.preventDefault();
      close();
    }
  };
  const close = () => {
    document.removeEventListener("keydown", keys);
    backdrop.remove();
  };
  const current = passwordField({ autocomplete: "current-password" });
  const fields = newPasswordFields(undefined, { activeVault: true });
  const body = h(
    "div",
    { class: "col" },
    h("p", { class: "muted", text: t("signin.master_change_text") }),
    h("p", { class: "muted", text: t("password_change.note") }),
    form(
      async () => {
        const next = await fields.checkPolicy();
        const r = await invoke("change_master_password", { current: current.input.value, newPassword: next });
        close();
        toast(t("signin.master_changed"));
        if (r && r.warning) toast(r.warning, "", 9000);
        if (options.onDone) options.onDone(r);
        afterPasswordChange(r);
      },
      t("signin.change_password"),
      [field(t("signin.current_password"), current), ...fields.els],
      [h("button", { class: "btn", type: "button", text: t("common.cancel"), on: { click: close } })],
    ),
  );
  const backdrop = h(
    "div",
    { class: "modal-backdrop" },
    h("div", { class: "modal", role: "dialog", "aria-modal": "true", "aria-label": t("signin.change_master") }, h("h2", { text: t("signin.change_master") }), body),
  );
  document.addEventListener("keydown", keys);
  document.body.append(backdrop);
  current.focus();
}

export function openSignInAgainDialog(options = {}) {
  openChangePasswordDialog({ ...options, signIn: true });
}
