// First run and "Add vault": the start page (create, open, or sign in to a Passyble account) and the
// add chooser (`start: "choose"`). A link from the browser extension opens `start: "server"`.
// The first vault on this PC starts the guided setup (setup.js), so it is not offered a recovery
// code here. The "Only on this device" notice on the create form never blocks creating a vault.

import { errorText, h, icon, invoke, mount, passwordField, sensybleCredit, t, toast, whyNote, wordmark } from "../lib.js";
import { driveVaultDetails, googleNote, googleSignIn } from "./google.js";
import { createNoticeShown } from "./local-reminder-model.js";
import { setupChanged } from "./extension.js";
import { openNewDeviceDialog } from "./account-keys.js";
import { offerRecoveryCode } from "./recovery.js";
import { linkField, serverInfo } from "./server.js";
import { masterPasswordMeter, SignInFlow } from "./signin.js";

/** Not a pairing link (no device token): a sign-in / invite link or a plain server address. */
function isSignInLink(link) {
  return Boolean(link) && !/[?&]token=/.test(link);
}

/** "More options" disclosure. */
function more(label, ...children) {
  return h("details", { class: "more" }, h("summary", {}, label, icon("chevronDown")), h("div", { class: "col" }, ...children));
}

export class Onboarding {
  /** `options.start`: "choose", "server" (prefilled with `options.link`) or "signin". `options.onBack`
   * leaves for where the user came from. */
  constructor(root, status, onDone, options = {}) {
    this.root = root;
    this.status = status;
    this.onDone = onDone;
    this.options = options;
    this.suggestions = [];
    // The first vault on this PC: the guided setup follows over the vault view (setup.js).
    this.firstRun = !(status.vaults || []).length && !options.start;
    this.backTo = null;
    invoke("vault_suggestions")
      .then((s) => { this.suggestions = s; })
      .catch(() => {})
      .finally(() => {
        if (options.start === "choose") this.choose();
        else if (options.start === "signin" || (options.start === "server" && isSignInLink(options.link))) this.signin(options.link);
        else if (options.start === "server") this.server(options.link);
        else this.home();
      });
  }

  update(status) {
    this.status = status;
  }

  frame(...children) {
    this.frameWith("onboard", children);
  }

  frameWith(cls, children) {
    const welcome = cls.split(" ").includes("welcome");
    mount(this.root, h("div", { class: "center-screen first-run" },
      h("div", { class: "center-stack" }, wordmark(), h("div", { class: cls }, ...children),
        welcome ? h("div", { class: "center-links credit" }, sensybleCredit()) : null)));
  }

  passwordRow(id, label, autocomplete, extra = []) {
    const pw = passwordField({ id, autocomplete });
    return { pw, input: pw.input, el: h("div", { class: "field" }, h("label", { for: id, text: label }), pw.el, ...extra) };
  }

  back() {
    const out = ["server", "signin"].includes(this.options.start) && !this.backTo && this.options.onBack;
    const to = this.backTo || (() => this.home());
    return this.backButton(() => (out ? this.options.onBack() : to()));
  }

  nameField({ google = false } = {}) {
    const first = !(this.status.vaults || []).length;
    const input = h("input", {
      class: "input",
      id: "vname",
      maxlength: "80",
      spellcheck: "false",
      autocomplete: "off",
      placeholder: first ? t("onboarding.name_placeholder_first") : t("onboarding.name_placeholder"),
    });
    // A vault kept on Google Drive has its name stored there readable, so a new device can list it.
    const googleHint = h("span", { class: "hint", text: t("onboarding.name_google_hint") });
    googleHint.hidden = !google;
    return {
      input,
      googleHint,
      el: h("div", { class: "field" }, h("label", { for: "vname", text: t("vaults.name") }), input,
        h("span", { class: "hint", text: t("onboarding.name_hint") }), googleHint),
      value: () => input.value.trim() || null,
    };
  }

  choice(iconName, title, text, onClick) {
    return h(
      "button",
      { class: "btn choice", type: "button", on: { click: onClick } },
      icon(iconName),
      h("div", { class: "grow" }, h("div", { class: "t", text: title }), text ? h("div", { class: "muted small", text }) : null),
    );
  }

  backButton(to) {
    return h("button", { class: "btn back-btn", type: "button", on: { click: to } }, icon("back"), t("common.back"));
  }

  home() {
    this.backTo = null;
    const big = (iconName, title, text, onClick, tag = null) =>
      h(
        "button",
        { class: `btn choice big${tag ? " recommended" : ""}`, type: "button", on: { click: onClick } },
        icon(iconName),
        h("div", { class: "t", text: title }),
        h("div", { class: "choice-text", text }),
        h("span", { class: "choice-foot" }, tag ? h("span", { class: "choice-tag", text: tag }) : null, icon("forward", "choice-go")),
      );
    const iconsPath = [t("settings.title"), t("settings.display"), t("settings.site_icons")].join(" → ");
    this.frameWith("onboard wide welcome", [
      h("h1", { text: t("onboarding.welcome") }),
      h("p", { class: "muted", text: t("onboarding.welcome_text") }),
      h(
        "div",
        { class: "choices-big three" },
        big("plus", t("onboarding.tile_create"), t("onboarding.tile_create_text"), () => this.create(), t("onboarding.new_here")),
        big("folder", t("onboarding.tile_open"), t("onboarding.tile_open_text"), () => this.openChoices()),
        big("user", t("onboarding.tile_account"), t("onboarding.tile_account_text"), () => this.account()),
      ),
      whyNote(t("onboarding.icons_line"), t("onboarding.icons_why", { path: iconsPath })),
    ]);
  }

  openChoices() {
    this.backTo = () => this.openChoices();
    const advanced = this.status.webdav_supported
      ? more(
          t("onboarding.more_options"),
          this.choice("cloud", t("onboarding.webdav"), t("onboarding.webdav_text"), () => this.webdav()),
          this.choice("server", t("onboarding.pairing"), t("onboarding.pairing_text"), () => this.server()),
        )
      : null;
    this.frame(
      h("h2", { text: t("onboarding.tile_open") }),
      h("p", { class: "muted", text: t("onboarding.open_text") }),
      h(
        "div",
        { class: "col" },
        this.choice("folder", t("onboarding.open_file"), t("onboarding.open_file_text"), () => this.open()),
        this.status.webdav_supported
          ? this.choice("server", t("vaults.sign_in_server"), t("onboarding.server_text"), () => this.signin())
          : null,
        this.status.google_available
          ? this.choice("cloudDownload", t("onboarding.google_restore"), t("onboarding.google_restore_text"), () => this.googleRestore())
          : null,
      ),
      advanced,
      h("div", { class: "row" }, this.backButton(() => this.home())),
    );
  }

  choose() {
    this.backTo = () => this.choose();
    const tile = (iconName, title, text, onClick) =>
      h("button", { class: "btn choice", type: "button", on: { click: onClick } }, icon(iconName),
        h("div", { class: "grow" }, h("div", { class: "t", text: title }), h("div", { class: "muted small", text })),
        icon("forward", "choice-go"));
    const advanced = this.status.webdav_supported
      ? more(
          t("onboarding.more_options"),
          this.choice("cloud", t("onboarding.webdav"), t("onboarding.webdav_text"), () => this.webdav()),
          this.choice("server", t("onboarding.pairing"), t("onboarding.pairing_text"), () => this.server()),
        )
      : null;
    this.frame(
      h("h2", { text: t("onboarding.add_title") }),
      h("div", { class: "col add-choices" },
        tile("plus", t("onboarding.tile_create"), t("onboarding.add_create_text"), () => this.create()),
        this.status.webdav_supported
          ? tile("user", t("onboarding.account_vault"), t("onboarding.account_vault_text"), () => this.accountVault())
          : null,
        tile("folder", t("onboarding.open_file"), t("onboarding.open_file_text"), () => this.open()),
        this.status.google_available
          ? tile("cloudDownload", "Google Drive", t("onboarding.google_restore_text"), () => this.googleRestore())
          : null,
        this.status.webdav_supported
          ? tile("server", t("onboarding.server_tile"), t("onboarding.server_text"), () => this.signin())
          : null),
      advanced,
      this.options.onBack ? h("div", { class: "row" }, this.backButton(() => this.options.onBack())) : null,
    );
    const first = this.root.querySelector(".add-choices .choice");
    if (first) first.focus();
  }

  /** A Passyble Cloud vault of the signed-in account; the plan's vault limit shows as the error under the form. */
  async accountVault() {
    this.backTo = () => this.choose();
    const status = await invoke("account_status").catch(() => null);
    if (!(status && status.signed_in)) {
      this.accountVaultSignIn();
      return;
    }
    const keys = await invoke("account_keys_status").catch(() => null);
    const linked = Boolean(keys && keys.set === true && !keys.feature_off);
    const email = (status.account && status.account.email) || "";
    const nameInput = h("input", { class: "input", id: "avname", maxlength: "80", spellcheck: "false", autocomplete: "off", placeholder: t("onboarding.name_placeholder") });
    const pw = this.passwordRow("avpw", linked ? t("account_keys.password") : t("unlock.master_password"), linked ? "current-password" : "new-password",
      [h("span", { class: "hint", text: linked ? t("onboarding.account_vault_password_hint") : t("onboarding.password_hint") })]);
    const pw2 = linked ? null : this.passwordRow("avpw2", t("onboarding.repeat_password"), "new-password");
    const rule = linked ? null : masterPasswordMeter(pw.input, { names: () => [nameInput.value.trim()] });
    if (rule) pw.el.append(rule.el);
    this.frame(
      h("h2", { text: t("onboarding.account_vault") }),
      h("div", { class: "account-row" }, icon("user"), h("strong", { class: "grow selectable ellipsis", text: email })),
      h("p", { class: "muted", text: t("onboarding.account_vault_intro") }),
      this.form(
        async () => {
          const name = nameInput.value.trim();
          if (!name) throw new Error(t("errors.vault_needs_name"));
          if (!pw.input.value) throw new Error(t("unlock.enter_password"));
          if (rule) await rule.ensure();
          if (pw2 && pw.input.value !== pw2.input.value) throw new Error(t("onboarding.mismatch_again"));
          const result = await invoke("account_vault_create", { name, password: pw.input.value, linked });
          pw.pw.reset();
          if (pw2) pw2.pw.reset();
          this.finish(result);
        },
        h("div", { class: "field" }, h("label", { for: "avname", text: t("vaults.name") }), nameInput),
        pw.el,
        pw2 ? pw2.el : null,
        h("button", { class: "btn primary", type: "submit", text: t("onboarding.create_vault") }),
      ),
    );
    nameInput.focus();
  }

  accountVaultSignIn() {
    const status = h("div", { class: "muted small", role: "status", "aria-live": "polite" });
    const error = h("div", { class: "error-text", role: "alert" });
    const go = h("button", { class: "btn primary", type: "button", on: { click: async () => {
      error.textContent = "";
      go.disabled = true;
      mount(status, t("account.waiting"), " ",
        h("button", { class: "btn small", type: "button", text: t("common.cancel"), on: { click: () => invoke("account_sign_in_cancel").catch(() => {}) } }));
      try {
        await invoke("account_sign_in");
        this.accountVault();
      } catch (e) {
        const code = (e && e.code) || String((e && e.message) || e);
        if (code !== "cancelled") error.textContent = errorText(e);
      } finally {
        go.disabled = false;
        mount(status);
      }
    } } }, icon("logIn"), t("onboarding.account_browser"));
    this.frame(
      h("h2", { text: t("onboarding.account_vault") }),
      h("p", { class: "muted", text: t("onboarding.account_vault_sign_in") }),
      status,
      error,
      h("div", { class: "row" }, this.back(), h("span", { class: "spacer" }), go),
    );
    go.focus();
  }

  /** Sign in with the Passyble account in the browser, or approve from another device (account-keys.js). */
  account() {
    this.backTo = () => this.account();
    const box = h("div", { class: "col" });
    const status = h("div", { class: "muted small", role: "status", "aria-live": "polite" });
    const error = h("div", { class: "error-text", role: "alert" });
    const back = () => h("div", { class: "row" }, this.backButton(() => this.home()));
    const signedIn = async (email) => {
      const keys = await invoke("account_keys_status").catch(() => null);
      const withPassword = Boolean(keys && keys.set === true && !keys.feature_off);
      mount(box,
        h("div", { class: "account-row" }, icon("user"), h("strong", { class: "grow selectable ellipsis", text: email })),
        h("p", { class: "muted", text: withPassword ? t("onboarding.account_next_linked") : t("onboarding.account_next") }),
        this.choice("folder", t("onboarding.tile_open"), t("onboarding.tile_open_text"), () => this.openChoices()),
        this.choice("plus", t("onboarding.tile_create"), withPassword ? t("onboarding.create_linked_text") : t("onboarding.tile_create_text"), () => this.create()),
        back());
    };
    const signIn = async (button) => {
      error.textContent = "";
      button.disabled = true;
      mount(status, t("account.waiting"), " ",
        h("button", { class: "btn small", type: "button", text: t("common.cancel"), on: { click: () => invoke("account_sign_in_cancel").catch(() => {}) } }));
      try {
        const r = await invoke("account_sign_in");
        await signedIn((r && r.account && r.account.email) || "");
      } catch (e) {
        // Cancelled here or in the browser: no error, the choices as they were.
        const code = (e && e.code) || String((e && e.message) || e);
        if (code !== "cancelled") error.textContent = errorText(e);
      } finally {
        button.disabled = false;
        mount(status);
      }
    };
    const choices = () => {
      const browser = this.choice("logIn", t("onboarding.account_browser"), t("onboarding.account_browser_text"), () => signIn(browser));
      mount(box,
        browser,
        this.choice("phoneApp", t("account_keys.approve_from_device"), t("onboarding.account_device_text"), () => openNewDeviceDialog({ onDone: () => this.account() })),
        status,
        error,
        back());
    };
    this.frame(h("h2", { text: t("onboarding.tile_account") }), box);
    invoke("account_status")
      .then((a) => (a && a.signed_in ? signedIn((a.account && a.account.email) || "") : choices()))
      .catch(() => choices());
  }

  /** Radio list of locations; returns {el, value(), synced()}. `synced()` is null while a picked folder
   * is being checked. */
  locationPicker(defaultPath, onChange = null) {
    const name = `loc-${Math.random().toString(36).slice(2)}`;
    const box = h("div", { class: "locations", role: "radiogroup", "aria-label": t("onboarding.location") });
    let custom = null;
    const add = (label, path, checked, synced) => {
      const input = h("input", { type: "radio", name, value: path, checked, dataset: { synced: synced === true ? "1" : synced === false ? "0" : "" } });
      if (onChange) input.addEventListener("change", onChange);
      box.append(
        h(
          "label",
          { class: "location" },
          input,
          h("div", { class: "grow" }, h("div", { text: label }), h("div", { class: "p", text: path })),
        ),
      );
      return input;
    };
    const list = this.suggestions.length ? this.suggestions : [{ label: t("onboarding.this_pc_only"), path: defaultPath || "" }];
    list.forEach((s, i) => add(s.label, s.path, i === 0, s.synced === true));
    const choose = h(
      "button",
      {
        class: "btn",
        type: "button",
        on: {
          click: async () => {
            const path = await invoke("pick_vault_save").catch(() => null);
            if (!path) return;
            if (custom) custom.closest("label").remove();
            custom = add(t("onboarding.custom_location"), path, true, null);
            custom.checked = true;
            if (!onChange) return;
            const picked = custom;
            onChange();
            const synced = await invoke("vault_path_synced", { path }).catch(() => false);
            picked.dataset.synced = synced ? "1" : "0";
            onChange();
          },
        },
      },
      icon("folder"),
      t("onboarding.choose_location"),
    );
    return {
      el: h("div", { class: "col" }, box, h("div", {}, choose)),
      value: () => {
        const checked = box.querySelector("input:checked");
        return checked ? checked.value : "";
      },
      synced: () => {
        const checked = box.querySelector("input:checked");
        const known = checked ? checked.dataset.synced : "0";
        return known === "1" ? true : known === "0" ? false : null;
      },
    };
  }

  form(onSubmit, ...children) {
    const error = h("div", { class: "error-text", role: "alert" });
    const submit = children.find((c) => c && c.type === "submit");
    const form = h(
      "form",
      {
        class: "col",
        on: {
          submit: async (e) => {
            e.preventDefault();
            error.textContent = "";
            const label = submit.textContent;
            submit.disabled = true;
            submit.textContent = t("common.working");
            try {
              await onSubmit(error);
            } catch (err) {
              error.textContent = errorText(err);
            } finally {
              submit.disabled = false;
              submit.textContent = label;
            }
          },
        },
      },
      ...children.filter((c) => c !== submit),
      error,
      h("div", { class: "row" }, this.back(), h("span", { class: "spacer" }), submit),
    );
    return form;
  }

  finish(result) {
    if (result && result.warning) toast(result.warning, "", 9000);
    this.onDone();
  }

  create() {
    const hasVaults = (this.status.vaults || []).length > 0;
    const name = this.nameField();
    const google = !!this.status.google_available;
    const backup = h("input", { type: "checkbox", id: "gbackup" });
    const notice = h("div", { class: "banner warn local-notice", role: "status" }, icon("shieldAlert"),
      h("span", { class: "grow", text: t("local_reminder.create_notice") }));
    const showNotice = () => {
      notice.hidden = !createNoticeShown({ googleBackup: google && backup.checked, synced: loc.synced() });
    };
    const loc = this.locationPicker(this.status.vault_path, showNotice);
    const meter = h("div");
    const bar = h("div", { class: "pw-bar", "aria-hidden": "true" }, h("span"), h("span"), h("span"), h("span"));
    const showStrength = (result) => {
      const filled = result ? Math.max(1, Math.min(4, Number(result.score) || 0)) : 0;
      [...bar.children].forEach((segment, i) => segment.classList.toggle("on", i < filled));
      bar.classList.toggle("ok", Boolean(result && result.ok));
    };
    const suggestHint = h("span", { class: "hint", text: t("setup.passphrase_hint"), hidden: true });
    const suggest = h("button", { class: "link small", type: "button", text: t("setup.passphrase"), on: { click: () => this.suggestPassphrase(pw, pw2, suggestHint) } });
    const pw = this.passwordRow("pw1", t("unlock.master_password"), "new-password", [bar, meter, h("span", { class: "hint", text: t("onboarding.password_hint") }), h("div", {}, suggest), suggestHint]);
    const pw2 = this.passwordRow("pw2", t("onboarding.repeat_password"), "new-password");
    const rule = masterPasswordMeter(pw.input, { names: () => [name.value()], onResult: showStrength });
    meter.append(rule.el);
    // Signed in with a Passyble password: the new vault opens with it, so no master password is chosen.
    const linked = h("input", { type: "checkbox", id: "linked" });
    const linkedRow = h("label", { class: "switch", hidden: true }, linked, h("span", {}, t("account_keys.create_linked"),
      h("div", { class: "hint", text: t("account_keys.create_linked_hint") })));
    const pwLabel = pw.el.querySelector("label");
    const applyLinked = () => {
      const on = linked.checked;
      pw2.el.hidden = on;
      meter.hidden = on;
      bar.hidden = on;
      suggest.hidden = on;
      if (backupRow) backupRow.hidden = on;
      pwLabel.textContent = on ? t("account_keys.password") : t("unlock.master_password");
      pw.input.autocomplete = on ? "current-password" : "new-password";
    };
    linked.addEventListener("change", applyLinked);
    invoke("account_keys_status").then((st) => {
      if (st && st.set === true && !st.feature_off) {
        linkedRow.hidden = false;
        linked.checked = true;
        applyLinked();
      }
    }).catch(() => {});
    const location = h("div", { class: "field" }, h("span", { class: "label", text: t("onboarding.where") }), loc.el,
      h("span", { class: "hint", text: t("onboarding.where_hint") }));
    const note = googleNote();
    note.hidden = true;
    const wait = h("div", { class: "col" });
    const submit = h("button", { class: "btn primary", type: "submit", text: t("onboarding.create_vault") });
    backup.addEventListener("change", () => {
      note.hidden = !backup.checked;
      name.googleHint.hidden = !backup.checked;
      submit.textContent = backup.checked ? t("onboarding.google_create") : t("onboarding.create_vault");
      showNotice();
    });
    showNotice();
    const backupRow = google
      ? h("div", { class: "col" },
          h("label", { class: "switch" }, backup, h("span", {}, t("onboarding.google_backup"),
            h("div", { class: "hint", text: t("onboarding.google_backup_hint") }))),
          note,
          wait)
      : null;
    this.frame(
      h("h2", { text: hasVaults ? t("onboarding.create_title") : t("onboarding.choose_password") }),
      hasVaults ? null : h("p", { class: "muted", text: t("onboarding.choose_password_text") }),
      this.form(
        async () => {
          if (linked.checked) {
            if (!pw.input.value) throw new Error(t("unlock.enter_password"));
            const result = await invoke("setup_create_linked", { path: loc.value(), name: name.value(), password: pw.input.value });
            pw.pw.reset();
            this.finish(result);
            return;
          }
          await rule.ensure();
          if (pw.input.value !== pw2.input.value) throw new Error(t("onboarding.mismatch_again"));
          let googleEmail = null;
          if (google && backup.checked) {
            const account = await googleSignIn({ host: wait });
            if (!account) return;
            googleEmail = account.email;
          }
          const result = await invoke("setup_create", { path: loc.value(), password: pw.input.value, name: name.value(), googleEmail });
          pw.pw.reset();
          pw2.pw.reset();
          this.finish(result);
          // The first vault gets its recovery code in the setup's last steps (setup.js).
          if (this.firstRun) return;
          // Skippable; the dialog stays over the new vault's view, whose Get started checklist
          // ticks the recovery code once it closes.
          offerRecoveryCode({ vaultName: name.value(), onDone: setupChanged });
        },
        hasVaults ? name.el : null,
        linkedRow,
        pw.el,
        pw2.el,
        backupRow,
        notice,
        more(t("onboarding.more_options"), hasVaults ? null : name.el, location),
        submit,
      ),
    );
    if (hasVaults) name.input.focus();
    else pw.input.focus();
  }

  async suggestPassphrase(pw, pw2, hint) {
    try {
      const phrase = await invoke("generate_password", { options: { passphrase: true, words: 6, separator: " " } });
      for (const field of [pw, pw2]) {
        field.input.value = phrase;
        const reveal = field.el.querySelector("button.reveal");
        if (reveal && field.input.type === "password") reveal.click();
        field.input.dispatchEvent(new Event("input", { bubbles: true }));
      }
      hint.hidden = false;
      pw.input.focus();
      pw.input.select();
    } catch (e) {
      toast(errorText(e), "error");
    }
  }

  open() {
    const path = h("input", { class: "input", id: "path", placeholder: t("onboarding.path_placeholder"), spellcheck: "false" });
    const browse = h(
      "button",
      {
        class: "btn",
        type: "button",
        on: {
          click: async () => {
            const p = await invoke("pick_vault_file").catch(() => null);
            if (p) { path.value = p; pw.focus(); }
          },
        },
      },
      icon("folder"),
      t("onboarding.browse"),
    );
    const row = this.passwordRow("pw", t("unlock.master_password"), "current-password");
    const pw = row.input;
    const name = this.nameField();
    this.frame(
      h("h2", { text: t("onboarding.open_title") }),
      this.form(
        async () => {
          if (!path.value.trim()) throw new Error(t("onboarding.choose_file_first"));
          const result = await invoke("setup_open", { path: path.value.trim().replace(/^"(.*)"$/, "$1"), password: pw.value, name: name.value() });
          row.pw.reset();
          // A vault linked to a Passyble account joins the list locked (unlock.js).
          if (result && result.linked) toast(t("account_keys.opens_with_password"), "", 7000);
          this.finish(result);
        },
        h("div", { class: "field" }, h("label", { for: "path", text: t("onboarding.vault_file") }), h("div", { class: "input-group" }, path, browse)),
        row.el,
        more(t("onboarding.more_options"), name.el),
        h("button", { class: "btn primary", type: "submit", text: t("onboarding.open_vault") }),
      ),
    );
    browse.focus();
  }

  webdav() {
    const url = h("input", { class: "input", id: "url", type: "url", placeholder: "https://cloud.example.com/remote.php/dav/files/me/pass.vault", spellcheck: "false" });
    const user = h("input", { class: "input", id: "user", autocomplete: "username" });
    const davField = passwordField({ id: "davpw", autocomplete: "off" });
    const davpw = davField.input;
    const loc = this.locationPicker(this.status.vault_path);
    const mrow = this.passwordRow("mpw", t("unlock.master_password"), "current-password");
    const pw = mrow.input;
    const name = this.nameField();
    this.frame(
      h("h2", { text: t("onboarding.webdav") }),
      this.form(
        async () => {
          const result = await invoke("setup_webdav_restore", {
            url: url.value,
            username: user.value,
            webdavPassword: davpw.value,
            path: loc.value(),
            password: pw.value,
            name: name.value(),
          });
          pw.value = davpw.value = "";
          this.finish(result);
        },
        h("div", { class: "field" }, h("label", { for: "url", text: t("onboarding.webdav_url") }), url,
          h("span", { class: "hint", text: t("onboarding.webdav_url_hint") })),
        h("div", { class: "editor" }, h("div", { class: "two" },
          h("div", { class: "field" }, h("label", { for: "user", text: t("onboarding.webdav_user") }), user),
          h("div", { class: "field" }, h("label", { for: "davpw", text: t("onboarding.webdav_password") }), davField.el))),
        mrow.el,
        more(t("onboarding.more_options"), name.el, h("div", { class: "field" }, h("span", { class: "label", text: t("onboarding.local_copy") }), loc.el)),
        h("button", { class: "btn primary", type: "submit", text: t("onboarding.restore_vault") }),
      ),
    );
    url.focus();
  }

  /** Restore from Google Drive: the local copy goes to %LOCALAPPDATA%\Passaults and keeps syncing. */
  googleRestore() {
    const box = h("div", { class: "col" });
    const wait = h("div", { class: "col" });
    const error = h("div", { class: "error-text", role: "alert" });
    let account = null;
    let vaults = null;
    this.frame(
      h("h2", { text: t("onboarding.google_restore") }),
      h("p", { class: "muted", text: t("onboarding.google_restore_intro") }),
      googleNote(),
      box,
    );
    const signIn = async (button) => {
      error.textContent = "";
      button.disabled = true;
      try {
        const signedIn = await googleSignIn({ host: wait });
        if (!signedIn) return;
        account = signedIn;
        vaults = null;
        render();
        vaults = await invoke("google_drive_vaults", { email: account.email });
      } catch (e) {
        error.textContent = errorText(e);
      } finally {
        button.disabled = false;
      }
      render();
    };
    const render = () => {
      if (!account) {
        const start = h("button", { class: "btn primary", type: "button", on: { click: () => signIn(start) } }, t("onboarding.google_sign_in"));
        mount(box, wait, error, h("div", { class: "row" }, this.back(), h("span", { class: "spacer" }), start));
        start.focus();
        return;
      }
      const other = h("button", { class: "link", type: "button", text: t("onboarding.other_account"), on: { click: () => signIn(other) } });
      const head = h("div", { class: "account-row" }, icon("user"), h("strong", { class: "grow selectable ellipsis", text: account.email }), other);
      if (!vaults || !vaults.length) {
        mount(
          box,
          head,
          wait,
          vaults
            ? h("div", { class: "banner" }, icon("info"), h("span", { class: "grow", text: t("onboarding.google_no_vault") }))
            : error.textContent ? null : h("p", { class: "muted", text: t("onboarding.google_looking") }),
          error,
          h("div", { class: "row" }, this.back()),
        );
        return;
      }
      const group = `gv-${Math.random().toString(36).slice(2)}`;
      const list = h(
        "div",
        { class: "locations", role: "radiogroup", "aria-label": t("onboarding.google_vaults") },
        vaults.map((v, i) =>
          h(
            "label",
            { class: "location" },
            h("input", { type: "radio", name: group, value: v.file_id, checked: i === 0 }),
            h("div", { class: "grow" }, h("div", { text: v.name || t("onboarding.vault_id", { id: String(v.vault_id).slice(0, 8) }) }), h("div", { class: "p", text: driveVaultDetails(v) })),
          ),
        ),
      );
      const row = this.passwordRow("gpw", t("unlock.master_password"), "current-password");
      const name = this.nameField({ google: true });
      mount(
        box,
        head,
        wait,
        this.form(
          async () => {
            const checked = list.querySelector("input:checked");
            const chosen = checked && vaults.find((v) => v.file_id === checked.value);
            if (!chosen) throw new Error(t("onboarding.choose_restore"));
            const result = await invoke("setup_google_drive_restore", {
              email: account.email,
              fileId: chosen.file_id,
              password: row.input.value,
              name: name.value() || chosen.name || null,
            });
            row.pw.reset();
            this.finish(result);
          },
          h("div", { class: "field" }, h("span", { class: "label", text: vaults.length === 1 ? t("onboarding.vault") : t("onboarding.choose_vault") }), list),
          row.el,
          more(t("onboarding.more_options"), name.el),
          h("button", { class: "btn primary", type: "submit", text: t("onboarding.restore_vault") }),
        ),
      );
      row.input.focus();
    };
    render();
  }

  signin(link) {
    const box = h("div", { class: "col" });
    this.frame(box);
    new SignInFlow(box, {
      link,
      back: () => this.back(),
      onDone: (result) => this.finish(result),
      onPairingLink: (pairing) => this.server(pairing),
    });
  }

  server(initialLink) {
    let info = null;
    const area = h("div", { class: "col" });
    const link = linkField(initialLink, () => {
      if (info) beforeCheck();
    });
    const checkError = h("div", { class: "error-text", role: "alert" });
    const checkBtn = h("button", { class: "btn primary", type: "submit" }, t("server.check"));

    const runCheck = async () => {
      checkError.textContent = "";
      checkBtn.disabled = true;
      checkBtn.textContent = t("server.checking");
      try {
        info = await invoke("server_link_check", { link: link.value() });
        afterCheck();
      } catch (err) {
        checkError.textContent = errorText(err);
      } finally {
        checkBtn.disabled = false;
        checkBtn.textContent = t("server.check");
      }
    };

    const beforeCheck = () => {
      info = null;
      mount(
        area,
        h(
          "form",
          { class: "col", on: { submit: (e) => { e.preventDefault(); runCheck(); } } },
          checkError,
          h("div", { class: "row" }, this.back(), h("span", { class: "spacer" }), checkBtn),
        ),
      );
    };

    const afterCheck = () => {
      if (info.error) {
        mount(
          area,
          serverInfo(info),
          h("div", { class: "row" }, this.back(), h("span", { class: "spacer" }),
            h("button", { class: "btn primary", type: "button", text: t("health.check_again"), on: { click: () => { beforeCheck(); runCheck(); } } })),
        );
        return;
      }
      const create = !info.exists;
      const name = this.nameField();
      const loc = this.locationPicker(this.status.vault_path);
      const pwField = passwordField({ id: "spw", autocomplete: create ? "new-password" : "current-password" });
      const pw2Field = passwordField({ id: "spw2", autocomplete: "new-password" });
      const pw = pwField.input;
      const pw2 = pw2Field.input;
      const rule = create ? masterPasswordMeter(pw, { names: () => [name.value(), info.username] }) : null;
      const meter = rule ? rule.el : null;
      mount(
        area,
        serverInfo(info),
        h("p", {
          class: "muted",
          text: create
            ? t("onboarding.server_no_vault")
            : t("onboarding.server_has_vault"),
        }),
        this.form(
          async () => {
            if (create) {
              await rule.ensure();
              if (pw.value !== pw2.value) throw new Error(t("onboarding.mismatch"));
            }
            const result = await invoke("setup_server_connect", {
              link: link.value(),
              create,
              path: loc.value(),
              password: pw.value,
              name: name.value(),
            });
            pw.value = pw2.value = "";
            this.finish(result);
          },
          h("div", { class: "field" }, h("label", { for: "spw", text: t("unlock.master_password") }), pwField.el, create ? meter : null),
          create
            ? h("div", { class: "field" }, h("label", { for: "spw2", text: t("onboarding.repeat_password") }), pw2Field.el,
                h("span", { class: "hint", text: t("onboarding.no_recovery") }))
            : null,
          more(t("onboarding.more_options"), name.el, h("div", { class: "field" }, h("span", { class: "label", text: t("onboarding.local_copy") }), loc.el)),
          h("button", { class: "btn primary", type: "submit", text: create ? t("onboarding.create_on_server") : t("onboarding.download_vault") }),
        ),
      );
      pw.focus();
    };

    this.frame(
      h("h2", { text: t("server.title") }),
      h("p", {
        class: "muted",
        text: t("onboarding.server_intro"),
      }),
      link.el,
      area,
    );
    beforeCheck();
    if (initialLink) runCheck();
    else link.focus();
  }
}
