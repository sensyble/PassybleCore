// Unlock form for one vault: Windows Hello when it's ready for that vault, with "Use master password
// instead", or the master password. While Hello is up the password field shows too: typing into it (or
// Unlock) calls Hello off (`cancel_hello_unlock`).
//
// Hello starts by itself only for something the user just did: opening the window (the app's one-time
// grant, `take_auto_hello`) or asking the vault view for a secret (`options.autoHello`). Never in the
// hidden window of a start with Windows, after a lock, or only because Hello became available
// (`hello-available`): that just offers it.
//
// A vault linked to a Passyble account (`vault_access`) opens with the Passyble password instead
// (account_keys.rs): Hello opens the account key kept on this PC, else the password, with the Secret
// Key typed once when this PC has none. "Forgot" offers this PC's kept key or the account recovery
// code, and a new PC can ask another device ("Approve from another device").

import { errorText, h, icon, invoke, isHelloCancelled, listen, mount, passwordField, t, toast, wordmark } from "../lib.js";
import { openRecoveryUnlockDialog } from "./recovery.js";
import { openForgotDialog, openNewDeviceDialog } from "./account-keys.js";
import { EMAIL_NEEDED, errorCode, linkedForm, LOCKED, opensWithAccount, PASSWORD_NEEDED, SECRET_KEY_NEEDED } from "./account-keys-model.js";
import { openLockedUnlockDialog } from "./account-reset.js";
import { autoHelloMode } from "./unlock-model.js";
import { whereText } from "./vault-where-model.js";
import { openSupport } from "./support.js";

// The unlock forms on screen; the active one may start Windows Hello when the window is opened (`main-opened`).
const panels = new Set();
listen("main-opened", () => {
  for (const panel of panels) panel.maybeAutoHello();
}).catch(() => {});

export class UnlockPanel {
  /**
   * `vault` is an entry of `status.vaults`; unlocking it makes it the active vault and calls `onDone`.
   * Options: `onAdd()` (an "Add vault" link), `onCancel()` (a Cancel button), `autoHello` (`true` starts
   * Hello at once, `false` never; left out, only after the window was just opened), `reason` (a line
   * under the vault name), `onBusy(busy)`.
   */
  constructor(container, vault, status, onDone, options = {}) {
    this.container = container;
    this.vault = vault;
    this.onDone = onDone;
    this.options = options;
    this.busy = false;
    this.usePassword = !!status.prefer_password;
    // `helloRun` tells the pending Windows Hello answer (`unlock_hello`) apart from one the user called off.
    this.helloUp = false;
    this.helloRun = 0;
    this.helloPending = null;

    this.pw = passwordField({ id: "master", placeholder: t("unlock.master_password"), autocomplete: "current-password" });
    this.password = this.pw.input;
    this.error = h("div", { class: "error-text", role: "alert" });
    this.helloStatus = h("div", { class: "hint", role: "status", text: t("unlock.hello_or_password") });
    this.password.addEventListener("input", () => {
      if (this.helloUp && this.password.value) this.dropHello();
    });
    this.note = h("div", { class: "hint" });
    // A linked vault (`vault_access`): the Secret Key once, the account's address when this PC knows none.
    this.linked = vault.linked_account ? { kind: "account", account: vault.linked_account, secret_key_here: true, signed_in: true } : null;
    this.secretKey = h("input", { class: "input mono", type: "text", autocomplete: "off", spellcheck: "false", placeholder: "P1-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX" });
    this.secretKeyField = h("div", { class: "field" },
      h("label", { text: t("account_keys.secret_key") }), this.secretKey, h("span", { class: "hint", text: t("account_keys.secret_key_hint") }));
    this.email = h("input", { class: "input", type: "email", autocomplete: "email", spellcheck: "false", placeholder: t("account_keys.email") });
    this.emailField = h("div", { class: "field" }, h("label", { text: t("account_keys.email") }), this.email);
    this.accountNote = h("div", { class: "hint" });
    this.approveLink = h("button", { class: "link", type: "button", on: { click: () => this.approveFromDevice() } }, t("account_keys.approve_from_device"));
    this.submit = h("button", { class: "btn primary big", type: "submit", text: t("unlock.unlock") });
    this.helloBtn = h(
      "button",
      { class: "btn big", type: "button", on: { click: () => this.hello() } },
      icon("hello"),
      t("unlock.with_hello"),
    );
    this.passwordLink = h("button", {
      class: "btn ghost",
      type: "button",
      text: t("prompt.use_password"),
      on: { click: () => this.showPassword() },
    });
    this.forgotText = h("span", { text: t("unlock.forgot") });
    this.forgotLink = h("div", { class: "center-links forgot-link" },
      h("button", { class: "link", type: "button", on: { click: () => this.recover() } }, this.forgotText),
      this.approveLink,
      // Help and support works locked: people who can't get in need it most.
      h("button", { class: "link", type: "button", on: { click: () => openSupport() } }, t("support.title")));
    this.banner = h(
      "div",
      { class: "banner" },
      icon("globe"),
      h("span", { class: "grow", text: t("unlock.browser_waiting") }),
      h("button", {
        class: "btn ghost",
        type: "button",
        text: t("common.not_now"),
        on: { click: () => invoke("cancel_unlock").then(() => this.update({ ...this.status, unlock_requested: false })) },
      }),
    );
    this.missing = h("div", { class: "banner warn" });
    this.title = h("h1", { class: "ellipsis selectable" });
    this.location = h("div", { class: "faint selectable ellipsis" });
    this.reason = options.reason ? h("div", { class: "hint", text: options.reason }) : null;

    const form = h(
      "form",
      { on: { submit: (e) => { e.preventDefault(); this.unlock(); } } },
      this.helloStatus,
      this.accountNote,
      this.pw.el,
      this.secretKeyField,
      this.emailField,
      this.error,
      this.submit,
      this.helloBtn,
      this.passwordLink,
      this.forgotLink,
      this.note,
    );

    mount(
      container,
      h(
        "div",
        { class: "center-screen" },
        h(
          "div",
          { class: "center-stack" },
          // The wordmark frames a screen of its own, not the unlock dialog over the vault list (`onCancel`).
          options.onCancel ? null : wordmark(),
          h(
            "div",
            { class: "unlock" },
            this.title,
            this.location,
            this.reason,
            this.banner,
            this.missing,
            form,
            options.onCancel
              ? h("button", { class: "btn ghost", type: "button", text: t("common.cancel"), on: { click: () => options.onCancel() } })
              : null,
          ),
          options.onAdd
            ? h("div", { class: "center-links switch-link" },
                h("button", { class: "link", type: "button", on: { click: () => options.onAdd() } }, icon("plus"), t("vault.add_vault")))
            : null,
        ),
      ),
    );
    this.update(status, vault);
    panels.add(this);
    this.maybeAutoHello();
    this.loadAccess();
  }

  /** Reads how the vault's file opens (`vault_access`): a linked vault gets its own form. */
  async loadAccess() {
    if (!this.vault.exists) return;
    try {
      const access = await invoke("vault_access", { vaultId: this.vault.id });
      if (this.destroyed) return;
      this.linked = access && access.kind === "account" ? access : null;
      this.render();
      // Another linked vault of the account is open (switching vaults): its key opens this one.
      if (this.linked && this.linked.key_open) {
        this.unlockHeld();
        return;
      }
      this.maybeAutoHello();
    } catch (e) {
      console.warn("vault_access failed:", e);
    }
  }

  async unlockHeld() {
    if (this.busy) return;
    this.setBusy(true, t("unlock.unlocking"));
    try {
      await invoke("unlock_account", { vaultId: this.vault.id });
      if (!this.destroyed) this.onDone();
    } catch (e) {
      this.setBusy(false);
      if (errorCode(e) !== PASSWORD_NEEDED) this.showError(errorText(e));
    }
  }

  openLocked() {
    openLockedUnlockDialog({
      akId: (this.linked && this.linked.ak_id) || "",
      vaultName: this.vault.name,
      onDone: () => {
        if (!this.destroyed) this.loadAccess();
      },
    });
  }

  approveFromDevice() {
    openNewDeviceDialog({
      email: (this.linked && this.linked.email) || "",
      onDone: (r) => {
        if (r && r.unlocked) this.onDone();
        else this.loadAccess();
      },
    });
  }

  helloReady() {
    const v = this.vault;
    if (this.linked) {
      const form = linkedForm(this.linked, this.status.hello_available);
      return !!((form.hello || form.remembered) && v.exists);
    }
    return !!(v.hello_enabled && v.hello_enrolled && v.hello_ready && this.status.hello_available && v.exists);
  }

  update(status, vault = this.vault) {
    this.status = status;
    this.vault = vault;
    if (status.prefer_password) this.usePassword = true;
    this.title.textContent = vault.name;
    this.title.title = vault.name;
    this.password.setAttribute("aria-label", t("unlock.master_password_for", { vault: vault.name }));
    // Plain words, never the file path (a vault's file name is its id): the path is the tooltip.
    this.location.textContent = whereText(vault, t);
    this.location.title = vault.path || "";
    this.banner.hidden = !status.unlock_requested;
    this.missing.hidden = vault.exists;
    this.missing.textContent = vault.exists ? "" : t("unlock.missing_file");
    this.render();
    // Windows Hello became ready after the form was built (start-up checks it in the background):
    // it starts if the user opened the window moments ago (else it is just offered).
    const ready = this.helloReady();
    if (ready && this.wasReady === false) this.maybeAutoHello();
    this.wasReady = ready;
  }

  render() {
    const ready = this.helloReady();
    const helloFirst = ready && !this.usePassword && !this.helloUp;
    this.helloStatus.hidden = !this.helloUp;
    this.pw.el.hidden = helloFirst;
    this.submit.hidden = helloFirst;
    this.passwordLink.hidden = !helloFirst;
    this.forgotLink.hidden = helloFirst;
    this.helloBtn.hidden = !ready;
    this.helloBtn.classList.toggle("primary", helloFirst);
    const note = this.linked
      ? (this.linked.kept && !ready ? this.linked.kept_note : null)
      : this.vault.hello_enabled && this.status.hello_available && !ready ? this.vault.hello_note : null;
    this.note.textContent = note || "";
    this.note.hidden = !note;
    this.renderLinked(helloFirst);
  }

  renderLinked(helloFirst) {
    const linked = this.linked;
    const form = linked ? linkedForm(linked, this.status.hello_available) : null;
    this.password.placeholder = linked ? t("account_keys.password") : t("unlock.master_password");
    this.password.setAttribute("aria-label", linked ? t("account_keys.password_for", { vault: this.vault.name }) : t("unlock.master_password_for", { vault: this.vault.name }));
    this.accountNote.hidden = !linked;
    this.accountNote.textContent = linked
      ? linked.locked
        ? t("account_reset.locked_vault_note")
        : (linked.email ? t("account_keys.opens_with_email", { email: linked.email }) : t("account_keys.opens_with_password"))
      : "";
    this.secretKeyField.hidden = !linked || helloFirst || !(form.secretKey || this.needSecretKey);
    this.emailField.hidden = !linked || helloFirst || !(form.email || this.needEmail);
    this.approveLink.hidden = !linked || !form.secretKey;
    this.forgotText.textContent = linked ? (linked.locked ? t("account_reset.unlock_link") : t("account_keys.forgot_password")) : t("unlock.forgot");
    mount(this.helloBtn, form && form.remembered ? icon("lockOpen") : icon("hello"), form && form.remembered ? t("unlock.unlock") : t("unlock.with_hello"));
  }

  autoMode() {
    return autoHelloMode({
      auto: this.options.autoHello,
      ready: this.helloReady(),
      active: !!this.vault.active,
      usePassword: this.usePassword,
      typed: !!this.password.value,
    });
  }

  /** Starts Windows Hello by itself for something the user just did (see the header). */
  maybeAutoHello() {
    if (this.destroyed || this.busy || this.helloUp) return;
    const mode = this.autoMode();
    if (mode === "now") {
      this.hello();
      return;
    }
    if (mode !== "if-opened" || this.asking) return;
    this.asking = true;
    invoke("take_auto_hello").then((granted) => {
      this.asking = false;
      if (granted && !this.destroyed && !this.busy && !this.helloUp && this.autoMode() === "if-opened") this.hello();
    }, () => {
      this.asking = false;
    });
  }

  showPassword() {
    if (this.helloUp) this.dropHello();
    this.usePassword = true;
    this.error.textContent = "";
    this.render();
    this.password.focus();
  }

  focus() {
    if (this.helloReady() && !this.usePassword && !this.helloUp) this.helloBtn.focus();
    else this.password.focus();
  }

  setBusy(busy, label) {
    this.busy = busy;
    this.submit.disabled = busy;
    this.helloBtn.disabled = busy || this.helloUp;
    this.password.disabled = busy;
    this.submit.textContent = busy && label ? label : t("unlock.unlock");
    if (this.options.onBusy) this.options.onBusy(busy);
  }

  async unlock() {
    if (this.busy) return;
    const password = this.password.value;
    if (!password) {
      this.showError(t("unlock.enter_password"));
      this.password.focus();
      return;
    }
    if (this.helloUp) {
      const pending = this.helloPending;
      this.dropHello();
      this.setBusy(true, t("unlock.unlocking"));
      const unlocked = await (pending || Promise.reject()).then(() => true, () => false);
      this.setBusy(false);
      if (unlocked || this.destroyed) return;
    }
    this.error.textContent = "";
    this.setBusy(true, t("unlock.unlocking"));
    try {
      const result = this.linked
        ? await invoke("unlock_account", {
            vaultId: this.vault.id,
            password,
            secretKey: this.secretKey.value.trim() || null,
            email: this.email.value.trim() || null,
          })
        : await invoke("unlock", { password, vaultId: this.vault.id });
      this.pw.reset();
      this.secretKey.value = "";
      if (result && result.warning) toast(result.warning, "", 9000);
      this.onDone();
    } catch (e) {
      this.setBusy(false);
      const code = errorCode(e);
      if (code === SECRET_KEY_NEEDED) {
        this.needSecretKey = true;
        this.render();
        this.showError(t("account_keys.secret_key_needed"));
        this.secretKey.focus();
        return;
      }
      if (code === EMAIL_NEEDED) {
        this.needEmail = true;
        this.render();
        this.showError(t("account_keys.email_needed_unlock"));
        this.email.focus();
        return;
      }
      if (code === PASSWORD_NEEDED) {
        this.showError(t("unlock.enter_password"));
        this.password.focus();
        return;
      }
      if (code === LOCKED) {
        // From before an e-mail reset: opened with the old key, then relinked under the current one.
        this.pw.reset();
        this.showError(t("account_reset.locked_vault_note"));
        this.openLocked();
        return;
      }
      if (!this.linked && opensWithAccount(e)) {
        this.showError(t("account_keys.opens_with_password"));
        this.loadAccess();
        return;
      }
      this.showError(errorText(e));
      this.password.select();
    }
  }

  /** Shows `text` under the password; `calm` (the user cancelled Hello) uses muted text, red is for real failures. */
  showError(text, calm = false) {
    this.error.textContent = text;
    this.error.classList.toggle("calm", calm);
  }

  recover() {
    if (this.busy) return;
    this.error.textContent = "";
    if (this.linked && this.linked.locked) {
      this.openLocked();
      return;
    }
    if (this.linked) {
      openForgotDialog({ email: this.linked.email || "", kept: !!this.linked.kept, onUnlocked: () => this.onDone() });
      return;
    }
    openRecoveryUnlockDialog(this.vault, { onUnlocked: () => this.onDone() });
  }

  async hello() {
    if (this.busy || this.helloUp) return;
    const run = ++this.helloRun;
    this.error.textContent = "";
    this.helloUp = true;
    this.helloBtn.disabled = true;
    this.render();
    this.helloPending = invoke(this.linked ? "unlock_account_hello" : "unlock_hello", { vaultId: this.vault.id });
    try {
      const result = await this.helloPending;
      // Unlocked, even if the user had gone for the password meanwhile: nothing left to type.
      this.helloUp = false;
      if (this.destroyed) return;
      this.pw.reset();
      if (result && result.warning) toast(result.warning, "", 9000);
      if (result && result.locked) toast(t("account_reset.opened_old_key"), "", 9000);
      this.onDone();
    } catch (e) {
      if (run !== this.helloRun) return; // called off for the password: that form stays as it is
      this.helloUp = false;
      this.helloBtn.disabled = false;
      this.showError(errorText(e), isHelloCancelled(e));
      this.usePassword = true;
      this.render();
      this.password.focus();
      invoke("status").then((s) => {
        const v = (s.vaults || []).find((x) => x.id === this.vault.id);
        if (v && !this.destroyed) this.update(s, v);
      }).catch(() => {});
    } finally {
      if (run === this.helloRun) this.helloPending = null;
    }
  }

  dropHello() {
    this.helloRun++;
    this.helloUp = false;
    this.helloPending = null;
    this.usePassword = true;
    this.helloBtn.disabled = this.busy;
    this.error.textContent = "";
    this.render();
    invoke("cancel_hello_unlock").catch(() => {});
  }

  destroy() {
    this.destroyed = true;
    panels.delete(this);
    this.password.value = "";
    this.secretKey.value = "";
  }
}
