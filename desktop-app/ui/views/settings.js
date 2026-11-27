// Settings: sections (This vault, Unlock, Autofill, Sync, Import, Display, Startup, About) are listed in the
// window sidebar while open (vault.js `hooks.onSections`). Rows mirror Android's Rows.kt (lib.js settingsRow).
// Edits on the main page apply with "Save settings"; buttons inside a row (update, sync, sign-in, devices,
// two-factor, recovery code, export) and keyboard shortcuts apply at once.

import { agoText, errorText, formatNumber, h, icon, iconButton, infoTip, invoke, keyLabel, mount, passwordField, sensybleCredit, settingsGroup, settingsRow, t, tn, toast, withShortcut } from "../lib.js";
import { AiToolsPage } from "./aitools.js";
import { GeneratorSettings } from "./aliases.js";
import { DevicesList } from "./devices.js";
import { openExtensionGuide } from "./extension.js";
import { googleSignIn, stopBackupDialog, ZERO_KNOWLEDGE_NOTE } from "./google.js";
import { driveCleanupRows } from "./google-cleanup.js";
import { openDownloads, openTutorial, tutorials } from "./help.js";
import { openSupport, reportProblem } from "./support.js";
import { openCreateRecoveryDialog, recoveryRow } from "./recovery.js";
import { handlerRow } from "./otpauth-model.js";
import { openServerDialog } from "./server.js";
import { openChangeMasterPasswordDialog, openChangePasswordDialog, openSignInAgainDialog } from "./signin.js";
import { SecurityActivity, TwoFactorSettings } from "./twofactor.js";
import { availableLanguages, languagePreference } from "../i18n.js";
import { accountRow } from "./account.js";
import { openDeleteFromAccountDialog, removeVault, revealVault } from "./vault-actions.js";
import { passwordSection } from "./account-keys.js";
import { durationText } from "./teams-model.js";
import { autoLockAllowed, autoLockLabel, autoLockUpdate, autoLockValue, choicesWith, SETTINGS_CHOICES } from "./auto-lock-model.js";
import { openSetup } from "./setup.js";
import { hidden, platformReady } from "../platform.js";
import { actionInfo, actionLabel, canReset, recordKey, shortcutProblem } from "./shortcuts-model.js";

// Windows Hello policy (Settings → Unlock); values as `hello/policy.rs` stores them.
const HELLO_INTERVALS = [
  ["never", t("settings.hello_never")],
  ["1d", t("settings.hello_every_day")],
  ["7d", tn("settings.hello_every_days", 7)],
  ["14d", tn("settings.hello_every_days", 14)],
  ["30d", tn("settings.hello_every_days", 30)],
  ["restart", t("settings.hello_after_start")],
];
const HELLO_GRACE = [
  [0, t("settings.grace_every_time")],
  [1, tn("settings.grace_minutes", 1)],
  [5, tn("settings.grace_minutes", 5)],
];
const MANAGED_UPDATE = t("updates.managed");
/** Session storage key: Settings was open when the language changed (main.js reopens it). */
export const REOPEN_SETTINGS = "pass.reopen-settings";

/** A text-only button at the end of a settings row (`iconName` is unused). */
function rowButton(iconName, label, onClick, cls = "") {
  return h("button", { class: `btn small ${cls}`.trim(), type: "button", on: { click: onClick } }, label);
}

/** A status line with a coloured dot (Autofill → Browser extension). */
function statusChip(ok, label, title) {
  return h("span", { class: "status-chip", title: title || null }, h("span", { class: `status-dot ${ok ? "ok" : "bad"}` }), label);
}

const select = (id, options, value) => {
  const el = h("select", { class: "input", id }, options.map(([v, text]) => h("option", { value: String(v), text })));
  el.value = String(value);
  return el;
};

const bytes = (n) => (n >= 1048576
  ? t("common.size_mb", { size: formatNumber(n / 1048576, { minimumFractionDigits: 1, maximumFractionDigits: 1 }) })
  : t("common.size_kb", { size: formatNumber(Math.max(1, Math.round(n / 1024))) }));
const hostOf = (url) => { try { return new URL(url).host; } catch { return url; } };

export class SettingsView {
  /** `options.page`: page to open; `options.section`: main-page group to scroll to. */
  constructor(pane, hooks, options = {}) {
    this.pane = pane;
    this.hooks = hooks;
    this.update = null;
    this.page = options.page || "main";
    this.section = options.section || null;
    this.load();
  }

  async load() {
    try {
      // An older backend has no policy; the platform decides what this OS leaves out (linux-hidden.js).
      [this.s, this.update, this.policy, this.platform] = await Promise.all([
        invoke("get_settings"),
        invoke("update_status").catch(() => null),
        invoke("policy_status").catch(() => null),
        platformReady(),
      ]);
    } catch (e) {
      mount(this.pane, h("div", { class: "pane-inner" }, h("div", { class: "banner error row" },
        h("span", { class: "grow", text: errorText(e) }),
        h("button", { class: "btn small", type: "button", text: t("support.report"), on: { click: () => reportProblem(errorText(e)) } }))));
      return;
    }
    this.render();
  }

  render() {
    this.pendingVaultPath = null;
    this.dirty = false;
    this.message = h("div", { class: "col" });
    this.title = h("h2", { class: "grow ellipsis" });
    this.back = iconButton("back", withShortcut(t("common.back"), t("keys.esc")), () => this.showPage("main"));
    this.pages = {
      main: h("div", { class: "settings" },
        this.sectionOf("vault", this.vaultSection()),
        this.sectionOf("server", this.serverSection()),
        this.sectionOf("unlock", this.unlockSection()),
        this.autofillSection(),
        this.shortcutsSection(),
        this.syncSection(),
        this.sectionOf("import", this.importSection()),
        this.sectionOf("display", this.displaySection()),
        this.sectionOf("startup", this.startupSection()),
        this.sectionOf("help", this.helpAboutSection()),
        this.credit = h("div", { class: "set-credit" }, sensybleCredit())),
      security: h("div", { class: "settings" }, this.securityPage()),
      help: h("div", { class: "settings" }, this.helpPage()),
      devices: h("div", { class: "settings" }, this.devicesPage()),
      activity: h("div", { class: "settings" }, this.activityPage()),
      generator: h("div", { class: "settings" }, this.generatorPage()),
      ai: h("div", { class: "settings" }, (this.aiTools = new AiToolsPage()).el),
    };
    const intro = {
      [t("settings.this_vault")]: t("settings.this_vault_sub"),
      [t("settings.unlock")]: t("settings.unlock_sub"),
      [t("settings.autofill")]: t("settings.autofill_sub"),
      [t("settings.shortcuts")]: t("settings.shortcuts_sub"),
      [t("settings.sync")]: t("settings.sync_sub"),
      [t("settings.import_export")]: t("settings.import_export_sub"),
      [t("settings.display")]: t("settings.display_sub"),
      [t("settings.startup")]: t("settings.startup_sub"),
      [t("settings.help_about")]: t("settings.help_about_sub"),
    };
    // The account row heads the Sync group (or a group of its own without one); the Passyble password
    // (account-keys.js) follows it for a signed-in account.
    const passyblePassword = passwordSection({ onChanged: () => this.load() });
    const account = accountRow({
      onChanged: () => {
        passyblePassword.reload();
        if (this.hooks.onAccount) this.hooks.onAccount();
      },
      onSignedIn: () => passyblePassword.reload({ offer: true }),
    });
    const syncCard = this.pages.main.querySelector('[data-section="sync"] > .set-card');
    if (syncCard) syncCard.prepend(account);
    else this.pages.main.prepend(this.sectionOf("account", settingsGroup(t("account.title"), [account])));
    account.after(passyblePassword);
    for (const head of this.pages.main.querySelectorAll(":scope > .set-group > .set-head")) {
      const text = intro[head.textContent.trim()];
      if (text && !head.nextElementSibling.classList.contains("set-intro")) head.after(h("p", { class: "set-intro", text }));
    }
    // Save settings looks quiet until something changed.
    const saveBtn = h("button", { class: "btn primary is-clean", type: "button", title: t("settings.no_changes"), text: t("settings.save"), on: { click: () => this.save() } });
    const live = () => { saveBtn.classList.remove("is-clean"); saveBtn.removeAttribute("title"); };
    const touched = () => { this.dirty = true; live(); };
    this.pages.main.addEventListener("input", touched);
    this.pages.main.addEventListener("change", touched);
    for (const ev of ["input", "change"]) this.pages.security.addEventListener(ev, live);
    this.closeBtn = h("button", { class: "btn", type: "button", text: t("common.close"), on: { click: () => this.hooks.onClose() } });
    this.actions = h("div", { class: "row sticky-actions" }, h("span", { class: "spacer" }), this.closeBtn, saveBtn);
    const inner = h("div", { class: "pane-inner settings-view" },
      h("div", { class: "pane-header" }, this.back, this.title),
      this.message,
      Object.values(this.pages),
      this.actions);
    inner.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && this.page !== "main" && !e.defaultPrevented) {
        e.preventDefault();
        this.showPage("main");
      }
    });
    mount(this.pane, inner);
    this.renderUpdate();
    this.sections = [...this.pages.main.querySelectorAll(":scope > .set-group[data-section]")].map((group) => ({
      key: group.dataset.section,
      label: group.querySelector(".set-head > span").textContent.trim(),
    }));
    this.showSection(this.section, { quiet: true });
    this.showPage(this.pages[this.page] ? this.page : "main");
  }

  /** False (after asking) when the main page has edits that "Save settings" has not applied yet. */
  confirmLeave() {
    return !this.dirty || confirm(t("editor.discard"));
  }

  scrollTo(section) {
    this.showSection(section);
  }

  /** Shows one section of the main page (the first when `key` names none) and tells the sidebar. */
  showSection(key, { quiet = false } = {}) {
    const sections = this.sections || [];
    const current = sections.some((s) => s.key === key) ? key : sections.length ? sections[0].key : null;
    this.section = null;
    this.sectionKey = current;
    for (const group of this.pages.main.querySelectorAll(":scope > .set-group")) group.hidden = group.dataset.section !== current;
    this.credit.hidden = current !== "help";
    if (!quiet && this.page !== "main") this.showPage("main");
    this.pane.scrollTop = 0;
    if (this.hooks.onSections) this.hooks.onSections(sections, current);
  }

  sectionOf(section, group) {
    if (group) group.dataset.section = section;
    return group;
  }

  /** The Save / Close bar: visual only (Save works the same); hidden where buttons act at once. */
  syncActions() {
    const page = this.page;
    this.closeBtn.hidden = page !== "main";
    this.actions.hidden = page === "devices" || page === "activity" || page === "help" || page === "generator" || page === "ai"
      || (page === "security" && !(this.hello && this.hello.checked));
  }

  showPage(page) {
    if ((page === "devices" && !this.devices) || (page === "activity" && !this.activity)) page = "main";
    const from = this.page;
    this.page = page;
    for (const [name, el] of Object.entries(this.pages)) el.hidden = name !== page;
    this.title.textContent = { main: t("settings.title"), security: t("settings.more_security"), devices: t("settings.devices"), activity: t("twofactor.activity"), help: t("help.title"), generator: t("settings.generator"), ai: t("aitools.title") }[page];
    this.back.hidden = page === "main";
    // Devices, activity, help and the generator have no settings to save; their buttons act at once.
    this.syncActions();
    if (page === "activity" && from !== "activity") this.activity.load();
    if (page === "generator" && from !== "generator") this.generator.load();
    if (page === "ai" && from !== "ai") this.aiTools.load();
    if (this.hooks.onPage) this.hooks.onPage(page);
    const opener = page === "main" ? null : this.pages.main.querySelector(`[data-page="${page}"]`);
    const owner = opener && opener.closest(".set-group[data-section]");
    if (this.hooks.onSections && this.sections) this.hooks.onSections(this.sections, owner ? owner.dataset.section : this.sectionKey);
    this.pane.scrollTop = 0;
    if (page !== "main") this.back.focus();
    else if (from !== "main") {
      const row = this.pane.querySelector(`[data-page="${from}"]`);
      if (row) row.focus();
    }
  }

  vaultSection() {
    const s = this.s;
    const ps = s.pass_server;
    this.vaultName = h("input", { class: "input", id: "s-vname", value: s.vault_name, maxlength: "80", spellcheck: "false", autocomplete: "off" });
    const pick = (cmd) => async () => {
      const p = await invoke(cmd).catch(() => null);
      if (p) {
        this.pendingVaultPath = p;
        this.dirty = true;
        fileRow.valueEl.textContent = t("settings.after_saving", { path: p });
        fileRow.valueEl.title = p;
      }
    };
    const fileRow = settingsRow("folder", t("settings.file"), {
      value: s.vault_path,
      cls: "set-path",
      info: `${t("settings.file_info")}

${t("settings.vault_file_info")}`,
      control: [rowButton("folder", t("settings.move"), pick("pick_vault_save")), rowButton("search", t("settings.locate"), pick("pick_vault_file"))],
    });
    fileRow.valueEl.classList.add("selectable");
    // Size on disk and item count on a second line of the File row (count unknown while fully locked).
    const sizeText = s.vault_file_text ? (s.vault_file_text.match(/\(([^()]+)\)\s*$/) || [null, s.vault_file_text])[1] : t("settings.not_found");
    fileRow.querySelector(".set-text").append(h("span", { class: "set-sub set-size", text: sizeText }));
    const signedOut = !!(s.sync && s.sync.signed_out);
    return settingsGroup(t("settings.this_vault"), [
      settingsRow("edit", t("settings.name"), { id: "s-vname", control: this.vaultName }),
      fileRow,
      // Linked vaults have no master password or recovery code of their own (see the Passyble password rows).
      s.linked_account
        ? settingsRow("lock", t("account_keys.this_vault"), { value: t("account_keys.opens_with_password"), info: t("account_keys.unlink_info") })
      // Passyble Server vaults: one password for the server account and this vault.
      : ps
        ? settingsRow("lock", t("signin.change_password"), {
            value: ps.host,
            info: t("settings.change_password_server_info"),
            control: rowButton(null, t("settings.change"), () => openChangePasswordDialog({ onDone: () => this.load() })),
          })
        : settingsRow("lock", t("signin.change_password"), {
            info: t("settings.change_password_info"),
            control: rowButton(null, t("settings.change"), () => openChangeMasterPasswordDialog({ onDone: () => this.load() })),
          }),
      // Recovery code (recovery.js): applies at once, not with "Save settings".
      s.linked_account ? null : recoveryRow(s.recovery_code, { vaultName: s.vault_name, onChanged: () => this.load() }),
      ps
        ? this.pageRow(settingsRow("monitor", t("settings.devices"), {
            value: signedOut ? t("settings.signed_out") : null,
            valueClass: signedOut ? "warn" : "",
            onClick: () => this.showPage("devices"),
          }), "devices")
        : null,
      this.generatorRow = this.pageRow(settingsRow("user", t("settings.generator"), {
        info: t("settings.generator_info"),
        onClick: () => this.showPage("generator"),
      }), "generator"),
      this.pageRow(settingsRow("health", t("health.title"), {
        value: t("settings.health_value"),
        onClick: () => this.hooks.onHealth && this.hooks.onHealth(),
      }), "health"),
      this.pageRow(settingsRow("trash", t("trash.title"), {
        value: t("settings.trash_value"),
        onClick: () => this.hooks.onTrash && this.hooks.onTrash(),
      }), "trash"),
      settingsRow("swap", t("settings.switch_vault"), {
        value: s.vault_count > 1 ? tn("vaults.count", s.vault_count) : null,
        info: t("settings.switch_vault_info"),
        control: h("button", {
          class: "btn small", type: "button", title: t("settings.switch_vault_title"),
          on: { click: (e) => this.hooks.onSwitchVault && this.hooks.onSwitchVault(e.currentTarget) },
        }, t("settings.switch")),
      }),
      this.vaultActionRows(),
    ]);
  }

  /** The open vault's own actions (vault-actions.js). */
  vaultActionRows() {
    const vault = this.hooks.activeVault ? this.hooks.activeVault() : null;
    if (!vault) return [];
    const changed = () => this.hooks.onVaultChanged && this.hooks.onVaultChanged();
    return [
      settingsRow("folder", t("vaults.show_in_folder"), {
        control: rowButton(null, t("settings.vault_show"), () => revealVault(vault)),
      }),
      settingsRow("close", t("vaults.remove_here"), {
        value: t("settings.remove_here_value"),
        info: t("settings.remove_here_info"),
        control: rowButton(null, t("settings.vault_remove"), () => removeVault(vault, changed)),
      }),
      vault.account_deletable
        ? settingsRow("trash", t("vaults.delete_account"), {
            value: t("settings.delete_account_value"),
            info: t("settings.delete_account_info"),
            control: rowButton(null, t("settings.vault_delete"), () => openDeleteFromAccountDialog({ vault, onDeleted: changed }), "danger"),
          })
        : null,
    ];
  }

  /** Marks a chevron row with the page it opens (focus returns to it on Back). */
  pageRow(row, page) {
    row.dataset.page = page;
    return row;
  }

  unlockSection() {
    const s = this.s;
    const hp = s.hello_policy || {};
    const hs = s.hello_status || {};
    this.hello = h("input", { type: "checkbox", checked: s.windows_hello, disabled: !s.hello_available && !s.windows_hello });
    this.helloInterval = select("s-hello-pw", HELLO_INTERVALS, hp.password_interval || "30d");
    this.helloEachFill = h("input", { type: "checkbox", checked: !!hp.verify_each_fill });
    const grace = hp.fill_grace_minutes ?? 1;
    const graceChoices = HELLO_GRACE.some(([m]) => m === grace) ? HELLO_GRACE : [...HELLO_GRACE, [grace, tn("settings.grace_minutes", grace)]];
    this.helloGrace = select("s-hello-grace", graceChoices, grace);

    const helloState = !s.hello_available && !s.windows_hello
      ? { text: t("settings.hello_not_set_up"), tip: t("settings.hello_not_set_up_tip") }
      : !s.windows_hello
        ? { text: t("settings.hello_off") }
        : !hs.enrolled
          ? { text: t("settings.hello_pending") }
          : hs.bound
            ? { cls: "ok", text: t("settings.hello_bound"), tip: t("settings.hello_bound_tip") }
            : { cls: "warn", text: t("settings.hello_dpapi"), tip: hs.note || t("settings.hello_dpapi_tip") };
    const helloInfo = [
      t("settings.hello_info"),
      helloState.tip,
    ].filter(Boolean).join("\n\n");

    this.keepList = h("input", { type: "checkbox", checked: s.keep_list_when_locked !== false });
    const lockValue = autoLockValue(s);
    this.autoLock = select("s-lock", choicesWith(SETTINGS_CHOICES, lockValue).map((v) => [v, autoLockLabel(v)]), lockValue);
    // A policy may cap auto-lock: longer choices are disabled, with the reason.
    const lockMax = this.policy ? this.policy.auto_lock_max_minutes ?? (this.policy.effective && this.policy.effective.max_auto_lock_minutes) : null;
    let lockLimited = false;
    for (const option of this.autoLock.options) {
      if (autoLockAllowed(option.value, lockMax)) continue;
      option.disabled = true;
      option.textContent = t("policy.auto_lock_above", { time: option.textContent });
      lockLimited = true;
    }

    const lockRow = settingsRow("timer", t("settings.auto_lock"), {
      id: "s-lock",
      control: this.autoLock,
      info: lockLimited ? `${t("settings.auto_lock_info")}

${t("policy.auto_lock_limit_info")}` : t("settings.auto_lock_info"),
    });
    const lockNote = () => {
      const text = lockLimited
        ? t("policy.auto_lock_limit", { time: durationText(lockMax) })
        : this.autoLock.value === "restart" ? t("settings.auto_lock_restart_note") : "";
      lockRow.valueEl.textContent = text;
      lockRow.valueEl.title = text;
    };
    lockNote();
    this.autoLock.addEventListener("change", lockNote);

    const intervalRow = settingsRow("key", t("settings.ask_master"), {
      id: "s-hello-pw", control: this.helloInterval,
      info: t("settings.ask_master_info"),
    });
    this.moreSecurityRow = this.pageRow(settingsRow("shield", t("settings.more_security"), { onClick: () => this.showPage("security") }), "security");
    const sync = () => {
      const on = this.hello.checked;
      intervalRow.hidden = !on;
      this.helloEachFill.disabled = !on;
      this.helloGrace.disabled = !on || !this.helloEachFill.checked;
      this.graceRow.hidden = !this.helloEachFill.checked;
      this.eachFillRow.valueEl.textContent = on ? t("settings.asks_hello") : t("settings.needs_hello");
      if (this.helloLink) {
        // Windows Hello off: "Turn on Windows Hello" in place of the switch, which shows once it is on.
        this.helloLink.hidden = on || this.hello.disabled;
        this.eachFillRow.classList.toggle("set-row-off", !on);
      }
      if (this.actions) this.syncActions();
      this.moreSecurityRow.valueEl.textContent = on && this.helloEachFill.checked ? t("settings.confirm_each_fill") : "";
    };
    this.syncHello = sync;
    this.hello.addEventListener("change", sync);
    this.helloEachFill.addEventListener("change", sync);

    // Linux has no Windows Hello (linux-hidden.js): those rows are left out, values saved unchanged.
    return settingsGroup(t("settings.unlock"), [
      hidden("settings.windows_hello") ? null : settingsRow("hello", t("settings.windows_hello"), { control: this.hello, value: helloState.text, valueClass: helloState.cls || "", info: helloInfo }),
      hidden("settings.ask_master") ? null : intervalRow,
      lockRow,
      settingsRow("lock", t("settings.keep_list"), {
        control: this.keepList,
        value: t("settings.keep_list_value"),
        info: t("settings.keep_list_info"),
      }),
      hidden("settings.more_security") ? null : this.moreSecurityRow,
    ]);
  }

  securityPage() {
    this.eachFillRow = settingsRow("shield", t("settings.confirm_each_fill"), {
      control: this.helloEachFill,
      info: t("settings.confirm_each_fill_info"),
    });
    this.graceRow = settingsRow("timer", t("settings.after_confirming"), { id: "s-hello-grace", control: this.helloGrace, info: t("settings.after_confirming_info") });
    this.helloLink = h("button", {
      class: "btn small", type: "button", hidden: true, text: t("settings.turn_on_hello"),
      on: { click: (e) => { e.preventDefault(); this.showPage("main"); this.hello.scrollIntoView({ block: "center" }); this.hello.focus(); } },
    });
    this.eachFillRow.controlEl.prepend(this.helloLink);
    const group = settingsGroup(t("settings.filling"), [this.eachFillRow, this.graceRow], { sub: t("settings.more_security_intro") });
    this.syncHello();
    return group;
  }

  autofillSection() {
    const s = this.s;
    const nh = s.native_host || {};
    this.extIds = h("textarea", { class: "input mono", id: "s-ext", rows: "2", spellcheck: "false", placeholder: "abcdefghijklmnopabcdefghijklmnop" });
    this.extIds.value = (s.extra_extension_ids || []).join("\n");

    // Windows passkeys: three steps. 1. turning it on registers Passyble's Windows package
    // (Developer Mode or a signed build), 2. a restart gives Passyble the package identity and
    // registers the plugin, 3. the user switches Passyble on in Windows' passkey settings.
    const pp = s.passkey_provider_status || {};
    // Debug builds, or extension IDs added by hand (commands.rs `developer_options`): the helper
    // paths, the Developer Mode route for Windows passkeys and the extra extension IDs.
    const dev = !!s.developer_options;
    const ppPackaged = pp.packaged || pp.package_registered;
    const ppUsable = pp.supported && (ppPackaged || pp.can_register);
    this.passkeyProvider = h("input", { type: "checkbox", checked: s.passkey_provider, disabled: !s.passkey_provider && !ppUsable });
    const openPage = (page) => invoke("passkey_provider_open", { page }).catch((err) => toast(errorText(err), "error"));
    const ppValue = !pp.supported
      ? t("settings.pp_needs_win11")
      : s.passkey_provider
        ? h("span", { class: "status-chips" },
            statusChip(ppPackaged, t("settings.pp_package")),
            statusChip(pp.registered, t("settings.pp_plugin")),
            statusChip(pp.enabled_in_windows, t("settings.pp_on_in_windows"), t("settings.pp_windows_path")),
            pp.synced_passkeys != null ? h("span", { text: tn("settings.pp_listed", pp.synced_passkeys) }) : null)
        : !ppUsable
          ? (pp.package_files === false ? t("settings.pp_files_missing") : t("settings.pp_needs_dev_mode"))
          : t("settings.pp_value");
    const ppTip = !pp.supported
      ? t("settings.pp_tip_unsupported")
      : t("settings.pp_tip");
    let ppStep = null;
    if (pp.supported && s.passkey_provider && pp.restart_needed) {
      ppStep = settingsRow("retry", t("settings.pp_restart_title"), {
        value: t("settings.pp_restart_value"),
        control: rowButton("retry", t("settings.restart"), () => invoke("restart_app").catch((err) => toast(errorText(err), "error")), "tonal"),
      });
    } else if (pp.supported && s.passkey_provider && pp.registered && !pp.enabled_in_windows) {
      ppStep = settingsRow("external", t("settings.pp_switch_on"), {
        value: t("settings.pp_switch_on_value"),
        control: rowButton("external", t("common.open"), () => openPage("passkeys")),
      });
    } else if (dev && pp.supported && !s.passkey_provider && !ppUsable && pp.package_files !== false) {
      ppStep = settingsRow("external", t("settings.pp_dev_mode"), {
        value: t("settings.pp_dev_mode_value"),
        control: rowButton("external", t("common.open"), () => openPage("developers")),
      });
    }

    const banner = (text) => (text ? h("div", { class: "banner error", text }) : null);
    return this.sectionOf("autofill", settingsGroup(t("settings.autofill"), [
      nh.supported === false
        ? settingsRow("globe", t("settings.extension"), { value: nh.error || t("settings.extension_unsupported") })
        : settingsRow("globe", t("settings.extension"), {
            value: nh.host_exists
              ? h("span", { class: "status-chips" }, statusChip(nh.chrome, "Chrome"), statusChip(nh.edge, "Edge"), statusChip(nh.brave, "Brave"), statusChip(nh.opera || nh.opera_gx, "Opera"), statusChip(nh.firefox, "Firefox"))
              : t("settings.helper_missing"),
            valueClass: nh.host_exists ? "" : "warn",
            control: rowButton("play", t("extsetup.set_up"), () => openExtensionGuide()),
            info: [
              t("settings.extension_info"),
              nh.host_exists ? null : t("settings.helper_missing_info"),
              dev && nh.host_path ? t("settings.helper_path", { path: nh.host_path }) : null,
              dev && nh.manifest_path ? t("settings.manifest_path", { path: nh.manifest_path }) : null,
            ].filter(Boolean).join(" "),
          }),
      banner(nh.error),
      banner(s.ipc_error),
      // Linux has no passkey provider or auto-type, macOS no passkey provider (linux-hidden.js): rows left out, values saved unchanged.
      ...(hidden("settings.windows_passkeys") ? [] : [
        settingsRow("key", t("settings.windows_passkeys"), { control: this.passkeyProvider, value: ppValue, info: ppTip }),
        ppStep,
        banner(pp.error || (s.passkey_provider || ppUsable || !dev ? null : pp.package_error)),
      ]),
      this.pageRow(settingsRow("shield", t("aitools.title"), {
        value: t("settings.ai_tools_value"),
        info: t("aitools.how_it_works"),
        onClick: () => this.showPage("ai"),
      }), "ai"),
      dev
        ? h("details", { class: "more" },
            h("summary", {}, t("settings.developer"), icon("chevronDown")),
            h("div", { class: "col" },
              h("div", { class: "field" }, h("label", { for: "s-ext", text: t("settings.extension_ids") }), this.extIds)))
        : null,
    ]));
  }

  shortcutsSection() {
    const group = settingsGroup(t("settings.shortcuts"), [h("div", { class: "set-wait" })]);
    this.shortcutsCard = group.querySelector(".set-card");
    this.loadShortcuts();
    return this.sectionOf("shortcuts", group);
  }

  async loadShortcuts(state) {
    try {
      this.shortcuts = state || (await invoke("shortcuts_state"));
    } catch (e) {
      mount(this.shortcutsCard, h("div", { class: "banner error", text: errorText(e) }));
      return;
    }
    const actions = this.shortcuts.actions || [];
    const autoType = actions.find((a) => a.id === "auto_type");
    this.hotkeyValue = autoType ? autoType.keys || "" : this.s.hotkey;
    // Linux has no auto-type (linux-hidden.js); reading the screen is Windows only for now.
    const shown = actions.filter((a) => a.supported !== false && !(a.id === "auto_type" && hidden("settings.hotkey")));
    mount(this.shortcutsCard, shown.map((a) => this.shortcutRow(a)));
  }

  shortcutRow(action) {
    const icons = { quick_access: "search", scan_qr: "qr", auto_type: "keyboard", show_app: "monitor", lock: "lock", sync_now: "sync", generate_password: "dice", new_note: "note" };
    const label = actionLabel(action.id);
    const shownKeys = () => (action.keys ? keyLabel(action.keys) : "");
    const input = h("input", {
      class: "input hotkey-input",
      readonly: true,
      value: shownKeys(),
      placeholder: t("shortcuts.none"),
      title: t("settings.hotkey_title"),
      "aria-label": t("shortcuts.record_for", { action: label }),
    });
    const normal = action.default ? t("shortcuts.default", { keys: keyLabel(action.default) }) : t("shortcuts.no_default");
    const clear = h("button", { class: "btn small", type: "button", text: t("shortcuts.clear"), disabled: !action.keys, on: { click: () => this.changeShortcut({ action: action.id, clear: true }, problem) } });
    const reset = h("button", { class: "btn small", type: "button", text: t("shortcuts.reset"), title: normal, disabled: !canReset(action), on: { click: () => this.changeShortcut({ action: action.id, reset: true }, problem) } });
    const row = settingsRow(icons[action.id] || "keyboard", label, {
      value: action.error || normal,
      valueClass: action.error ? "warn" : "",
      info: actionInfo(action.id),
      control: h("span", { class: "shortcut-controls" }, input, clear, reset),
    });
    const problem = (text) => {
      row.valueEl.textContent = text;
      row.valueEl.className = "set-sub warn";
    };
    // While the recorder has the focus, Passyble lets go of its own shortcuts, so pressing one
    // reaches the recorder instead of running its action.
    input.addEventListener("focus", () => {
      input.classList.add("recording");
      input.placeholder = t("shortcuts.recording");
      invoke("shortcuts_recording", { on: true }).catch(() => {});
    });
    input.addEventListener("blur", () => {
      input.classList.remove("recording");
      input.placeholder = t("shortcuts.none");
      input.value = shownKeys();
      invoke("shortcuts_recording", { on: false }).catch(() => {});
    });
    input.addEventListener("keydown", (e) => {
      if (e.key === "Tab") return;
      e.preventDefault();
      if (e.key === "Escape" && !e.ctrlKey && !e.altKey && !e.metaKey) {
        input.blur();
        return;
      }
      const pressed = recordKey(e);
      if (pressed.pending || pressed.ignored) return;
      input.value = keyLabel(pressed.combo);
      const why = pressed.error || shortcutProblem(this.shortcuts.actions, action.id, pressed.combo);
      if (why) {
        problem(why);
        return;
      }
      input.blur();
      this.changeShortcut({ action: action.id, keys: pressed.combo }, problem);
    });
    return row;
  }

  async changeShortcut(change, problem) {
    try {
      const state = await invoke("set_shortcut", { change });
      toast(change.clear ? t("shortcuts.cleared") : t("shortcuts.saved"));
      await this.loadShortcuts(state);
    } catch (e) {
      problem(errorText(e));
    }
  }

  /**
   * Google Drive, or Passyble Server and WebDAV with "Back up to Google Drive" on top when this build has
   * Google sign-in (it replaces WebDAV for the vault; Passyble Server vaults don't offer it).
   */
  syncSection() {
    const s = this.s;
    const g = s.google_drive;
    const ps = s.pass_server;
    this.googleWait = h("div", { class: "set-wait" });
    this.syncRow = settingsRow("sync", t("settings.not_synced_yet"), {});
    this.syncRow.hidden = !(g || ps || s.webdav_url);
    this.backupRow = settingsRow("cloud", t("settings.backup"), {});
    this.backupRow.hidden = this.syncRow.hidden;
    this.syncStatus(s.sync || {});

    if (!s.webdav_supported && !g) {
      return this.sectionOf("sync", settingsGroup(t("settings.sync"), [
        settingsRow("cloudOff", t("settings.sync"), { value: t("common.not_in_this_version") }),
      ]));
    }

    // Backed up to Drive but this build has no Google sign-in: Turn off is the only action.
    if (g && !s.google_available) {
      this.syncRow.hidden = this.backupRow.hidden = true;
      return this.sectionOf("sync", settingsGroup(t("settings.sync"), [
        settingsRow("cloudOff", "Google Drive", {
          value: t("common.not_in_this_version"),
          valueClass: "warn",
          info: t("settings.google_unavailable_info"),
        }),
        settingsRow("cloudOff", t("settings.turn_off_backup"), { control: rowButton(null, t("twofactor.turn_off_ellipsis"), (e) => this.googleTurnOff(e.currentTarget)) }),
      ]));
    }

    if (g) {
      return this.sectionOf("sync", settingsGroup(t("settings.sync"), [
        settingsRow("cloud", "Google Drive", {
          value: g.sign_in_needed ? t("settings.google_paused") : g.email,
          valueClass: g.sign_in_needed ? "warn" : "",
          info: `${t("settings.google_info", { email: g.email })}\n\n${ZERO_KNOWLEDGE_NOTE}`,
        }),
        this.googleWait,
        this.syncRow,
        this.backupRow,
        ...driveCleanupRows({ vaultName: s.vault_name, onRemoved: () => this.load(), onError: (text) => mount(this.message, h("div", { class: "banner error", text })) }),
        settingsRow("cloudOff", t("settings.turn_off_backup"), { control: rowButton(null, t("twofactor.turn_off_ellipsis"), (e) => this.googleTurnOff(e.currentTarget)) }),
      ]));
    }

    this.davUrl = h("input", { class: "input mono", id: "s-davurl", value: s.webdav_url, placeholder: "https://cloud.example.com/…/pass.vault", spellcheck: "false" });
    this.davUser = h("input", { class: "input", id: "s-davuser", value: s.webdav_username, autocomplete: "off" });
    const davPass = passwordField({ id: "s-davpass", autocomplete: "off", placeholder: s.webdav_has_password ? t("settings.saved_placeholder") : "" });
    this.davPass = davPass.input;
    const panel = h("div", { class: "set-panel col", id: "s-davpanel" },
      h("div", { class: "field" },
        h("span", { class: "set-label" }, h("label", { for: "s-davurl", text: t("onboarding.webdav_url") }), infoTip(t("settings.webdav_url_info"), t("onboarding.webdav_url"))),
        this.davUrl),
      h("div", { class: "two" },
        h("div", { class: "field" }, h("label", { for: "s-davuser", text: t("settings.webdav_user") }), this.davUser),
        h("div", { class: "field" },
          h("span", { class: "set-label" }, h("label", { for: "s-davpass", text: t("settings.app_password") }), infoTip(t("settings.app_password_info"), t("settings.app_password"))),
          davPass.el)));
    const davOn = !!s.webdav_url && !ps;
    panel.hidden = !davOn;
    const toggle = h("button", { class: "btn icon ghost small expand", type: "button", "aria-expanded": String(davOn), "aria-controls": "s-davpanel", title: t("settings.webdav_show") }, icon("chevronDown"));
    const davRow = settingsRow("cloud", "WebDAV", {
      value: davOn ? hostOf(s.webdav_url) : ps ? t("settings.webdav_used_by_server") : t("settings.webdav_caption"),
      info: t("settings.webdav_info"),
      control: toggle,
    });
    davRow.classList.add("set-toggle");
    const flip = () => {
      panel.hidden = !panel.hidden;
      toggle.setAttribute("aria-expanded", String(!panel.hidden));
      if (!panel.hidden) this.davUrl.focus();
    };
    davRow.addEventListener("click", (e) => { if (!e.target.closest(".tip")) flip(); });

    const offerGoogle = s.google_available && !ps;
    const backupBtn = rowButton("cloudUpload", t("settings.back_up"), () => this.googleBackup(backupBtn, null));
    const serverBtn = rowButton("qr", ps ? t("settings.pair_again") : t("settings.connect"), () => this.useServer());
    serverBtn.disabled = !s.webdav_supported;

    return this.sectionOf("sync", settingsGroup(t("settings.sync"), [
      offerGoogle
        ? settingsRow("cloudUpload", t("onboarding.google_backup"), {
            value: s.webdav_url ? t("settings.replaces_webdav") : t("settings.google_encrypted"),
            info: `${t("settings.google_backup_info")}\n\n${ZERO_KNOWLEDGE_NOTE}`,
            control: backupBtn,
          })
        : null,
      offerGoogle ? this.googleWait : null,
      settingsRow("server", "Passyble Server", {
        value: ps ? [ps.host, ps.device_name].filter(Boolean).join(" · ") : t("settings.server_caption"),
        info: ps
          ? (ps.pinned ? t("settings.server_pinned") : t("settings.server_trusted"))
          : t("settings.server_info"),
        control: serverBtn,
      }),
      davRow,
      panel,
      this.syncRow,
      this.backupRow,
    ]));
  }

  syncStatus(status) {
    if (this.devices) this.devices.syncStatus(status);
    this.backupSize(status);
    const row = this.syncRow;
    if (!row) return;
    const g = this.s && this.s.google_drive;
    const label = row.querySelector(".set-title");
    let title;
    let value = "";
    let warn = false;
    let action = null;
    let problem = null;
    if (status.running) {
      title = t("settings.syncing");
    } else if (status.sign_in_needed && g) {
      [title, value, warn] = [t("settings.not_synced"), t("settings.google_paused"), true];
      action = ["logIn", t("common.sign_in_ellipsis"), (b) => this.googleBackup(b, g.email), true];
    } else if (status.signed_out) {
      [title, value, warn] = [t("settings.not_synced"), t("devices.signed_out_title"), true];
      action = ["logIn", t("common.sign_in_ellipsis"), () => openSignInAgainDialog({ onDone: () => { this.load(); this.hooks.onSynced && this.hooks.onSynced(); } }), true];
    } else if (status.last_error) {
      [title, value, warn] = [t("settings.not_synced"), t("settings.keeps_trying", { error: status.last_error }), true];
      action = ["retry", t("settings.retry"), () => this.syncNow()];
      problem = status.last_error;
    } else {
      title = status.pending ? t("settings.changes_pending") : status.last_sync_ms ? t("settings.synced_ago", { ago: agoText(status.last_sync_ms) }) : t("settings.not_synced_yet");
      action = ["sync", t("settings.sync_now"), () => this.syncNow()];
    }
    label.textContent = title;
    row.valueEl.textContent = value;
    row.valueEl.title = value;
    row.valueEl.className = `set-sub${warn ? " warn" : ""}`;
    row.querySelector(".set-ico").replaceWith(icon(warn ? "cloudOff" : "sync", `set-ico${status.running ? " spin" : ""}`));
    if (action) {
      const [iconName, text, run, primary] = action;
      const b = rowButton(iconName, text, () => run(b), primary ? "tonal" : "");
      mount(row.controlEl, b, problem ? rowButton("lifeBuoy", t("support.report"), () => reportProblem(problem)) : null);
    } else {
      mount(row.controlEl);
    }
  }

  backupSize(status) {
    const row = this.backupRow;
    const s = this.s;
    if (!row || !s) return;
    const where = s.google_drive ? "Google Drive" : s.pass_server ? "Passyble Server" : s.webdav_url ? "WebDAV" : null;
    row.hidden = !where;
    if (!where) return;
    row.querySelector(".set-title").textContent = t("settings.backup_on", { where });
    const size = status && status.remote_size;
    row.valueEl.textContent = size || t("settings.size_after_sync");
    row.valueEl.title = size || "";
  }

  devicesPage() {
    this.devices = null;
    if (!this.s.pass_server) return null;
    this.devices = new DevicesList({ onSignedIn: () => { this.load(); this.hooks.onSynced && this.hooks.onSynced(); } });
    // The sync state may already say "signed out" (the list then shows it too).
    if (this.s.sync && this.s.sync.signed_out) this.devices.showSignedOut();
    return settingsGroup(t("settings.devices_title"), this.devices.el, {
      cls: "devices",
      sub: t("settings.devices_host_sub", { host: this.s.pass_server.host }),
    });
  }

  serverSection() {
    this.twoFactor = null;
    const ps = this.s.pass_server;
    if (!ps) return null;
    const signIn = () => openSignInAgainDialog({ onDone: () => { this.load(); this.hooks.onSynced && this.hooks.onSynced(); } });
    this.twoFactor = new TwoFactorSettings({ onActivity: () => this.showPage("activity"), onSignIn: signIn });
    return settingsGroup("Passyble Server", this.twoFactor.el, {
      info: t("settings.server_section_info", { host: ps.host }),
    });
  }

  generatorPage() {
    this.generator = new GeneratorSettings({
      onClose: () => this.hooks.onClose(),
      onChanged: (summary) => {
        if (this.generatorRow) this.generatorRow.valueEl.textContent = summary;
      },
    });
    return this.generator.el;
  }

  activityPage() {
    this.activity = null;
    const ps = this.s.pass_server;
    if (!ps) return null;
    this.activity = new SecurityActivity({ onSignIn: () => openSignInAgainDialog({ onDone: () => this.activity.load() }) });
    return settingsGroup(ps.host, this.activity.el, {
      info: t("settings.activity_info"),
    });
  }

  importSection() {
    return settingsGroup(t("settings.import_export"), [
      settingsRow("download", t("settings.import"), {
        value: t("settings.import_value"),
        onClick: () => this.hooks.onImport && this.hooks.onImport(),
      }),
      settingsRow("merge", t("import.find_duplicates"), {
        value: t("settings.duplicates_value"),
        onClick: () => this.hooks.onImport && this.hooks.onImport({ duplicates: true }),
      }),
      settingsRow("upload", t("settings.export"), {
        value: t("settings.export_value"),
        info: t("settings.export_info"),
        control: rowButton("upload", t("export.submit"), () => this.hooks.onExport && this.hooks.onExport()),
      }),
    ]);
  }

  displaySection() {
    const s = this.s;
    this.siteIcons = h("input", { type: "checkbox", checked: s.show_site_icons !== false });
    const languages = availableLanguages();
    this.language = select("s-lang", [["", t("settings.language_system")], ...languages.map((l) => [l.code, l.native === l.name ? l.native : `${l.native} (${l.name})`])], s.language || languagePreference() || "");
    return settingsGroup(t("settings.display"), [
      settingsRow("globe", t("settings.language"), {
        id: "s-lang",
        control: this.language,
        info: t("settings.language_info"),
      }),
      s.site_icons_supported
        ? settingsRow("image", t("settings.site_icons"), {
            control: this.siteIcons,
            info: t("settings.site_icons_info"),
          })
        : null,
    ]);
  }

  startupSection() {
    const s = this.s;
    this.startWithWindows = h("input", { type: "checkbox", checked: !!s.start_with_windows });
    this.startMin = h("input", { type: "checkbox", checked: s.start_minimized });
    return settingsGroup(t("settings.startup"), [
      settingsRow("power", t("settings.start_with_windows"), { control: this.startWithWindows, info: t("settings.start_with_windows_info") }),
      settingsRow("monitor", t("settings.start_in_tray"), { control: this.startMin, value: t("settings.start_in_tray_value") }),
      this.otpauthHandlerRow(),
    ]);
  }

  otpauthHandlerRow() {
    const button = h("button", { class: "btn", type: "button", hidden: true });
    const row = settingsRow("qr", t("settings.otpauth_title"), { value: "", info: t("settings.otpauth_info"), control: button });
    row.hidden = true;
    let action = null;
    const show = (handler, claimed) => {
      const state = handlerRow(handler, claimed, this.platform);
      action = state.action;
      row.valueEl.textContent = state.value;
      row.valueEl.className = `set-sub ${state.valueClass}`.trim();
      button.textContent = state.label;
      button.hidden = !state.action;
    };
    button.addEventListener("click", async (e) => {
      e.preventDefault();
      button.disabled = true;
      try {
        if (action === "windows") await invoke("otpauth_handler_open_settings");
        else show((await invoke("otpauth_handler_claim")).handler, true);
      } catch (err) {
        toast(errorText(err), "error");
      }
      button.disabled = false;
    });
    invoke("otpauth_handler_status")
      .then((status) => {
        if (!status.supported) return;
        row.hidden = false;
        show(status.handler, false);
      })
      .catch(() => {});
    return row;
  }

  helpSection() {
    return settingsGroup(t("help.title"), [
      this.pageRow(settingsRow("play", t("help.row_title"), {
        value: t("help.row_value"),
        onClick: () => this.showPage("help"),
      }), "help"),
      settingsRow("lifeBuoy", t("support.title"), {
        value: t("support.row_value"),
        onClick: () => openSupport(),
      }),
    ]);
  }

  tutorialContext() {
    const s = this.s;
    return {
      hotkey: this.hotkeyValue || s.hotkey,
      shortcuts: this.shortcuts ? Object.fromEntries((this.shortcuts.actions || []).filter((a) => a.supported !== false).map((a) => [a.id, a.keys])) : null,
      google: !!s.google_available && !s.pass_server,
      webdav: !!s.webdav_supported,
      openSettings: (section) => this.scrollTo(section),
      openImport: () => this.hooks.onImport && this.hooks.onImport(),
      openGuide: () => openExtensionGuide(),
      openRecovery: () => openCreateRecoveryDialog({
        replacing: !!(s.recovery_code && s.recovery_code.exists),
        vaultName: s.vault_name,
        onDone: (created) => created && this.load(),
      }),
    };
  }

  helpPage() {
    const s = this.s;
    const showAgain = rowButton(null, t("help.show_again"), async () => {
      // The checklist is on the empty pane: leaving Settings drops unsaved edits of the main page.
      if (!this.confirmLeave()) return;
      try {
        await invoke("get_started_show", { show: true });
        if (this.hooks.onGetStarted) this.hooks.onGetStarted();
      } catch (e) {
        toast(errorText(e), "error");
      }
    });
    showAgain.disabled = !!s.get_started;
    const setup = rowButton(null, t("setup.open"), () => openSetup());
    invoke("get_started").then((g) => {
      if (g && g.setup) setup.textContent = t("setup.continue_setup");
    }).catch(() => {});
    return [
      settingsGroup(t("start.title"), [
        settingsRow("play", t("setup.title"), {
          value: t("setup.row_value"),
          control: setup,
        }),
        settingsRow("check", t("help.checklist"), {
          value: s.get_started ? t("help.checklist_on") : t("help.checklist_off"),
          info: t("help.checklist_info"),
          control: showAgain,
        }),
        settingsRow("globe", t("extsetup.title"), {
          value: t("help.extension_value"),
          onClick: () => openExtensionGuide(),
        }),
      ], { sub: t("help.get_started_sub") }),
      settingsGroup(t("help.how_to"), tutorials().map(([id, iconName, title]) =>
        settingsRow(iconName, title, { onClick: () => openTutorial(id, this.tutorialContext()) })), { sub: t("help.how_to_sub") }),
      settingsGroup(t("support.title"), [
        settingsRow("lifeBuoy", t("support.contact"), {
          value: t("support.row_value"),
          info: t("support.row_info"),
          onClick: () => openSupport(),
        }),
      ], { sub: t("support.help_sub") }),
      settingsGroup("Passyble", [
        settingsRow("download", t("help.downloads"), {
          value: t("help.downloads_value"),
          info: t("help.downloads_info"),
          control: rowButton("external", t("help.downloads_open"), openDownloads),
        }),
      ], { sub: t("help.passyble_sub") }),
    ];
  }

  helpAboutSection() {
    const help = this.helpSection();
    const about = this.aboutSection();
    about.querySelector(".set-card").prepend(...help.querySelector(".set-card").children);
    about.querySelector(".set-head > span").textContent = t("settings.help_about");
    return about;
  }

  aboutSection() {
    const s = this.s;
    this.autoUpdate = h("input", { type: "checkbox", checked: s.update_auto_check !== false });
    this.versionRow = settingsRow("info", "Passyble", {});
    this.versionRow.classList.add("set-version");
    this.updateProgress = h("div", { class: "progress", role: "progressbar", "aria-valuemin": "0", "aria-valuemax": "100", hidden: true }, h("div", { class: "progress-bar" }));
    this.versionRow.querySelector(".set-text").append(this.updateProgress);
    const device = settingsRow("idCard", t("settings.device_id"), { value: s.device_id, cls: "selectable" });
    device.valueEl.classList.add("mono");
    // A managed (MSI, per-machine) install is updated by deploying a newer MSI (updates.rs).
    const managed = !!(this.update && this.update.managed);
    return settingsGroup(t("settings.about"), [
      this.versionRow,
      (this.autoUpdateRow = managed ? null : settingsRow("update", t("settings.auto_update"), {
        control: this.autoUpdate,
        info: t("settings.auto_update_info"),
      })),
      settingsRow("fileText", t("settings.log_file"), {
        info: t("settings.log_file_info"),
        control: rowButton("folder", t("settings.open_folder"), () => invoke("open_log_folder").catch((e) => toast(errorText(e), "error"))),
      }),
      device,
    ]);
  }

  updateState(u) {
    this.update = u;
    this.renderUpdate();
  }

  renderUpdate() {
    const row = this.versionRow;
    if (!row) return;
    const u = this.update;
    const version = (u && u.current) || this.s.version || "";
    row.querySelector(".set-title").textContent = version ? t("settings.version", { version }) : "Passyble";
    const value = row.valueEl;
    value.className = "set-sub";
    value.title = "";
    this.updateProgress.hidden = true;
    if (!u) {
      mount(value);
      mount(row.controlEl);
      return;
    }
    // A copy of Passyble that doesn't ask the update feed (updates.rs `enabled`): no check, no
    // switch. A Mac without its updater still gets the download page (`way` "download").
    if (this.autoUpdateRow) this.autoUpdateRow.hidden = u.enabled === false;
    if (u.enabled === false) {
      const link = u.way === "download";
      mount(value, link ? t("updates.download_hint") : t("common.not_in_this_version"));
      mount(row.controlEl, link ? this.downloadButton() : null);
      return;
    }
    const check = rowButton("sync", u.checking ? t("server.checking") : t("settings.check_now"), () => this.checkUpdate());
    check.disabled = u.checking;
    if (u.checking) check.querySelector("svg").classList.add("spin");
    let action = check;
    if (u.installing) {
      mount(value, t("settings.installing"));
      action = null;
    } else if (u.downloading) {
      const { done, total } = u.downloading;
      const pct = total ? Math.min(100, Math.round((done / total) * 100)) : null;
      mount(value, pct != null
        ? (u.available ? t("settings.downloading_version", { version: u.available.version, percent: pct }) : t("settings.downloading_percent", { percent: pct }))
        : t("settings.downloading_bytes", { size: bytes(done) }));
      this.updateProgress.hidden = false;
      this.updateProgress.classList.toggle("busy", pct == null);
      if (pct != null) this.updateProgress.setAttribute("aria-valuenow", String(pct));
      this.updateProgress.firstChild.style.width = `${pct ?? 30}%`;
      action = null;
    } else if (u.available) {
      const a = u.available;
      value.classList.add("accent");
      value.title = a.notes || "";
      mount(value, t("settings.version_available", { version: a.version }),
        a.notes_url ? [" · ", h("button", { class: "link", type: "button", text: t("settings.whats_new"), on: { click: (e) => { e.stopPropagation(); invoke("update_open_notes").catch((err) => toast(errorText(err), "error")); } } })] : null,
        u.managed ? ` · ${MANAGED_UPDATE}` : null,
        u.way === "download" ? ` · ${t("updates.download_page")}` : null);
      // .deb, .rpm and macOS until its updater is on: a link, never an install from here.
      if (u.way === "download") action = this.downloadButton("tonal");
      else if (!u.managed) action = rowButton("download", t("settings.update_restart"), () => this.installUpdate(), "tonal");
    } else if (u.managed && !u.error && !u.up_to_date) {
      mount(value, MANAGED_UPDATE);
    } else if (u.error) {
      value.classList.add("warn");
      value.title = u.error;
      mount(value, u.error);
    } else if (u.up_to_date) {
      value.classList.add("ok");
      mount(value, u.last_check_ms ? t("settings.up_to_date_checked", { ago: agoText(u.last_check_ms) }) : t("settings.up_to_date"));
    } else {
      mount(value, t("settings.not_checked"));
    }
    mount(row.controlEl, action);
  }

  async checkUpdate() {
    try {
      this.updateState(await invoke("update_check"));
    } catch (e) {
      // The state (with the error) arrives as an event too.
      this.update = { ...(this.update || {}), checking: false, error: errorText(e) };
      this.renderUpdate();
    }
  }

  downloadButton(style) {
    return rowButton("download", t("updates.download_open"), () => invoke("app_versions_update").catch((e) => toast(errorText(e), "error")), style);
  }

  async installUpdate() {
    try {
      await invoke("update_install");
    } catch (e) {
      toast(errorText(e), "error");
    }
  }

  async googleBackup(button, email) {
    mount(this.message);
    button.disabled = true;
    try {
      const account = await googleSignIn({ host: this.googleWait, email });
      if (!account) return;
      mount(this.googleWait, h("div", { class: "hint", text: t("settings.backing_up") }));
      const r = await invoke("google_drive_enable", { email: account.email });
      toast(email
        ? t("settings.google_signed_in_again")
        : r.created_remote
          ? t("settings.google_backed_up", { email: r.email })
          : t("settings.google_backed_up_merged", { email: r.email }));
      this.s = await invoke("get_settings");
      this.render();
      this.hooks.onSynced && this.hooks.onSynced();
    } catch (e) {
      mount(this.googleWait);
      mount(this.message, h("div", { class: "banner error", text: errorText(e) }));
    } finally {
      button.disabled = false;
    }
  }

  async googleTurnOff(button) {
    const choice = await stopBackupDialog({ canDelete: !!this.s.google_available });
    if (!choice) return;
    mount(this.message);
    button.disabled = true;
    try {
      await invoke("google_drive_disable", { deleteCopy: choice.deleteCopy });
      toast(choice.deleteCopy ? t("settings.google_off_deleted") : t("settings.google_off"));
      this.s = await invoke("get_settings");
      this.render();
    } catch (e) {
      mount(this.message, h("div", { class: "banner error", text: errorText(e) }));
      button.disabled = false;
    }
  }

  useServer() {
    openServerDialog({
      vaultName: this.s.vault_name,
      onConnected: () => {
        this.load();
        this.hooks.onSynced && this.hooks.onSynced();
      },
      onAddSeparate: (link) => window.dispatchEvent(new CustomEvent("pass-server-add", { detail: link })),
    });
  }

  async syncNow() {
    this.syncStatus({ running: true });
    try {
      const r = await invoke("sync_now");
      this.syncStatus({ last_sync_ms: Date.now() });
      toast(t("settings.synced_toast", { added: formatNumber(r.added), updated: formatNumber(r.updated), deleted: formatNumber(r.deleted) }));
      this.hooks.onSynced && this.hooks.onSynced();
    } catch (e) {
      const text = errorText(e);
      // sync_now's error says whether this device is signed out (any language).
      this.syncStatus({ last_error: text, signed_out: !!(e && e.signed_out) });
    }
  }

  async save() {
    const renamed = this.vaultName.value.trim() !== this.s.vault_name;
    const google = !!this.s.google_drive;
    const update = {
      vault_name: renamed ? this.vaultName.value : null,
      ...autoLockUpdate(this.autoLock.value),
      windows_hello: this.hello.checked,
      hello_policy: {
        password_interval: this.helloInterval.value,
        verify_each_fill: this.helloEachFill.checked,
        fill_grace_minutes: Number(this.helloGrace.value),
      },
      // A Google Drive vault has no WebDAV fields on screen: leave the account alone.
      webdav_url: google ? null : this.davUrl.value,
      webdav_username: google ? null : this.davUser.value,
      webdav_password: google ? null : this.davPass.value || null,
      start_minimized: this.startMin.checked,
      start_with_windows: this.startWithWindows.checked,
      update_auto_check: this.autoUpdate.checked,
      passkey_provider: this.passkeyProvider.checked,
      show_site_icons: this.s.site_icons_supported ? this.siteIcons.checked : null,
      keep_list_when_locked: this.keepList.checked,
      extra_extension_ids: this.extIds.value.split(/\r?\n/).map((x) => x.trim()).filter(Boolean),
    };
    const language = this.language.value;
    const languageChanged = language !== (this.s.language || "");
    if (languageChanged) {
      update.language = language;
      // Every window reloads in the new language (`locale-changed`); main.js opens Settings again.
      try {
        sessionStorage.setItem(REOPEN_SETTINGS, "1");
      } catch {
        // No session storage: the window shows the vault list after reloading.
      }
    }
    if (this.pendingVaultPath) update.vault_path = this.pendingVaultPath;
    try {
      const result = await invoke("set_settings", { update });
      if (this.davPass) this.davPass.value = "";
      this.s = await invoke("get_settings");
      this.render();
      const notes = (result.notes || []).map((n) => h("div", { class: "banner", text: n }));
      mount(this.message, notes);
      toast(t("settings.saved"));
      if (renamed && !result.locked && this.hooks.onRenamed) this.hooks.onRenamed();
      // A new vault location or sync account locks the vault, which swaps this view for the
      // unlock screen: show the notes as toasts so they aren't lost.
      if (result.locked) (result.notes || []).forEach((n) => toast(n, "", 9000));
    } catch (e) {
      if (languageChanged) {
        try {
          sessionStorage.removeItem(REOPEN_SETTINGS);
        } catch {
          // Nothing stored.
        }
      }
      mount(this.message, h("div", { class: "banner error", text: errorText(e) }));
    }
  }
}
