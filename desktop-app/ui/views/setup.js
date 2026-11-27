// The guided setup over the vault view (setup-model.js has the steps and the rules): at most three
// steps (browser extension, sync, recovery), then "You're set" with optional links. Every choice is
// saved as it is made (the same commands as Settings), so Skip for now leaves the defaults and closing
// loses nothing.
//
// It opens by itself after the first vault on this PC is set up (Rust marks that: settings.rs
// `SetupProgress`), and again after an unlock until it is done, unless "Finish later" (or Esc) paused
// it. A lock closes it without pausing it (the steps need the vault open).

import { errorText, formatDate, h, icon, invoke, keyLabel, modal, mount, t, tn, toast } from "../lib.js";
import { hidden } from "../platform.js";
import { openKitDialog, withAccountKey } from "./account-keys.js";
import { openExtensionGuide, setupChanged } from "./extension.js";
import { googleSignIn } from "./google.js";
import { ImportView } from "./import.js";
import { openCreateRecoveryDialog } from "./recovery.js";
import { openServerDialog } from "./server.js";
import {
  browserRows,
  browserToAdd,
  connectedHere,
  DONE,
  nextStep,
  previousStep,
  recoveryAction,
  resumeStep,
  setupExtras,
  setupSteps,
  stepDone,
  stepLabel,
  stepPosition,
  syncAction,
  syncChoices,
} from "./setup-model.js";
import { canReset, recordKey, shortcutProblem } from "./shortcuts-model.js";

const POLL_MS = 2000;
const helpPath = () => [t("settings.title"), t("help.title")].join(" → ");

let host = null;
let open = null;

/** What the setup needs from the vault view: `vaultName()`, `reload()`, `openSettings(section)` and `reviewMerges(pairs, done)`. */
export function setSetupHost(next) {
  host = next;
}

export function closeSetup() {
  if (open) open.close({ pause: false });
}

export function maybeOpenSetup(status) {
  const progress = status && status.setup_progress;
  if (!progress || progress.paused || status.locked || open) return;
  openSetup({ step: progress.step });
}

/** What decides the steps and the links (setup-model.js), read from the app. Never fails. */
export async function setupContext() {
  const [status, s, keys, started, account] = await Promise.all([
    invoke("status").catch(() => ({})),
    invoke("get_settings").catch(() => ({})),
    invoke("shortcuts_state").catch(() => null),
    invoke("get_started").catch(() => null),
    invoke("account_status").catch(() => null),
  ]);
  const pp = (s && s.passkey_provider_status) || {};
  const quick = keys && (keys.actions || []).find((a) => a.id === "quick_access");
  return {
    platform: (status && status.platform) || "",
    sync: Boolean(s && (s.webdav_supported || s.google_available)),
    synced: Boolean(started && started.sync),
    account: Boolean(account && account.signed_in),
    passkeys: !hidden("settings.windows_passkeys") && pp.supported === true,
    shortcuts: Boolean(quick && quick.supported !== false),
    quickKeys: (quick && quick.keys) || "",
    saved: started && started.setup ? started.setup.step : null,
  };
}

/** The step indicator; nothing for a screen that isn't a step. */
export function stepIndicator(steps, current) {
  const position = stepPosition(steps, current);
  if (!position) return null;
  const index = position.number - 1;
  const text = `${t("setup.step_of", { n: position.number, total: position.total })} · ${stepLabel(current)}`;
  return h("div", { class: "setup-steps" },
    h("ol", { class: "setup-dots", "aria-hidden": "true" }, steps.map((_, i) =>
      h("li", { class: i === index ? "current" : i < index ? "done" : "" }))),
    h("span", { class: "setup-count", text }));
}

export async function openSetup({ step = null } = {}) {
  if (open) return;
  open = { close: () => {} };
  try {
    const ctx = await setupContext();
    const steps = setupSteps(ctx);
    open = new SetupWizard(steps, setupExtras(ctx), resumeStep(steps, step ?? ctx.saved), ctx.quickKeys);
  } catch (e) {
    open = null;
    toast(errorText(e), "error");
  }
}

function stateChip(ok, text) {
  return h("span", { class: "status-chip" }, h("span", { class: `status-dot ${ok ? "ok" : ""}` }), text);
}

function statusLine() {
  const el = h("div", { class: "setup-status small", role: "status", "aria-live": "polite" });
  return {
    el,
    ok(text = t("common.saved")) { mount(el, h("span", { text })); el.className = "setup-status small ok-text"; },
    error(e) { mount(el, h("span", { text: errorText(e) })); el.className = "setup-status small error-text"; },
    busy(text) { mount(el, h("span", { text })); el.className = "setup-status small muted"; },
    clear() { mount(el); },
  };
}

function option(iconName, title, text, run) {
  return h("button", { class: "btn choice", type: "button", on: { click: run } },
    icon(iconName), h("div", { class: "grow" }, h("div", { class: "t", text: title }), text ? h("div", { class: "muted small", text }) : null));
}

function more(...children) {
  return h("details", { class: "more" }, h("summary", {}, t("onboarding.more_options"), icon("chevronDown")), h("div", { class: "col setup-choices" }, ...children));
}

class SetupWizard {
  constructor(steps, extras, start, quickKeys = "") {
    this.steps = steps;
    this.extras = extras;
    this.quickKeys = quickKeys;
    // The main button does what it says: `{ text, run }` set by the step, or null for Continue.
    this.action = null;
    this.kitShown = false;
    this.facts = {};
    this.s = {};
    this.cleanup = null;
    this.pause = true;
    // Esc is "Finish later", except in the shortcut box, where it only leaves the box.
    this.recording = false;
    this.m = modal({ label: t("setup.title"), cls: "setup", escape: () => !this.recording, onClose: () => this.closed() });
    this.indicator = h("div", { class: "grow" });
    this.body = h("div", { class: "setup-body" });
    this.backBtn = h("button", { class: "btn", type: "button", on: { click: () => this.back() } }, icon("back"), t("common.back"));
    this.skipBtn = h("button", { class: "btn ghost", type: "button", text: t("setup.skip"), on: { click: () => this.go(nextStep(this.steps, this.step)) } });
    this.nextBtn = h("button", { class: "btn primary", type: "button", text: t("common.continue"), on: { click: () => (this.action ? this.action.run() : this.next()) } });
    this.foot = h("div", { class: "row setup-foot" }, this.backBtn, h("span", { class: "spacer" }), this.skipBtn, this.nextBtn);
    this.laterBtn = h("button", { class: "btn ghost small", type: "button", text: t("setup.later"), on: { click: () => this.close({ pause: true }) } });
    mount(this.m.box,
      h("div", { class: "row setup-head" }, this.indicator, this.laterBtn),
      this.body,
      this.foot);
    this.go(start);
  }

  async refresh() {
    const [s, g] = await Promise.all([invoke("get_settings").catch(() => ({})), invoke("get_started").catch(() => ({}))]);
    this.s = s || {};
    this.facts = {
      browser: g && g.browser,
      sync: g && g.sync,
      items: g && g.items,
      recovery: Boolean(this.s.recovery_code && this.s.recovery_code.exists),
    };
  }

  async go(step) {
    if (!step) {
      this.finish();
      return;
    }
    this.step = step;
    this.action = null;
    invoke("setup_progress", { step }).catch(() => {});
    await this.show(step, () => this[`render_${step}`]());
    if (this.step !== step) return;
    const last = step === DONE;
    this.backBtn.hidden = !previousStep(this.steps, step);
    this.skipBtn.hidden = last;
    this.nextBtn.hidden = false;
    this.nextBtn.textContent = last ? t("setup.done_button") : this.action ? this.action.text : t("common.continue");
  }

  setAction(action) {
    this.action = action;
    this.nextBtn.textContent = action ? action.text : t("common.continue");
  }

  /** One of the optional links of "You're set": its page in place, Back returns. Not saved as progress. */
  async extra(id) {
    this.step = `extra:${id}`;
    this.action = null;
    if (id === "shortcuts") this.shortcuts = await invoke("shortcuts_state").catch(() => null);
    await this.show(this.step, () => this[`extra_${id}`]());
    if (this.step !== `extra:${id}`) return;
    this.backBtn.hidden = false;
    this.skipBtn.hidden = true;
    this.nextBtn.hidden = true;
  }

  async show(at, render) {
    if (this.cleanup) this.cleanup();
    this.cleanup = null;
    await this.refresh();
    if (!this.m.isOpen() || this.step !== at) return;
    mount(this.indicator, stepIndicator(this.steps, at));
    this.foot.hidden = false;
    mount(this.body, render());
    this.body.scrollTop = 0;
    const heading = this.body.querySelector("h2");
    if (heading) {
      heading.tabIndex = -1;
      heading.focus({ preventScroll: true });
    }
  }

  next() {
    this.go(nextStep(this.steps, this.step));
  }

  back() {
    if (this.step.startsWith("extra:")) {
      this.go(DONE);
      return;
    }
    const to = previousStep(this.steps, this.step);
    if (to) this.go(to);
  }

  finish() {
    this.done = true;
    invoke("setup_progress", { done: true }).catch(() => {});
    this.m.close();
  }

  close({ pause }) {
    this.pause = pause;
    this.m.close();
  }

  closed() {
    if (this.cleanup) this.cleanup();
    open = null;
    setupChanged();
    if (this.done || !this.pause) return;
    const step = this.step.startsWith("extra:") ? DONE : this.step;
    invoke("setup_progress", { step, paused: true }).catch(() => {});
    toast(t("setup.later_toast", { path: helpPath() }), "", 7000);
  }

  head(title, text) {
    return [h("h2", { text: title }), text ? h("p", { class: "muted", text }) : null];
  }

  /** The browser extension: the main button adds it to the default browser until one is connected. */
  render_browser() {
    const rows = h("div", { class: "setup-list" });
    const note = h("div", { class: "col" });
    let info = null;
    let connected = null;
    const store = (b) => invoke("extension_open_store", { browser: b.id }).catch((e) => toast(errorText(e), "error"));
    const draw = () => {
      if (!info || this.step !== "browser") return;
      const shown = browserRows(info.browsers || []);
      const ids = shown.map((b) => b.id);
      const here = (b) => connectedHere(b.id, connected, ids);
      const add = browserToAdd(shown, connected);
      mount(rows, shown.map((b) => h("div", { class: "setup-row" },
        h("div", { class: "grow t", text: b.name }),
        here(b) ? stateChip(true, t("setup.browser_connected"))
          : b === add ? null
            : h("button", { class: "btn small", type: "button", text: t("setup.browser_add_short"), "aria-label": t("setup.browser_add", { browser: b.name }), on: { click: () => store(b) } }))));
      this.setAction(add ? { text: t("setup.browser_add", { browser: add.name }), run: () => store(add) } : null);
      const other = connected && !shown.some(here);
      mount(note,
        info.host_exists === false ? h("div", { class: "banner warn", text: t("settings.helper_missing") }) : null,
        !(info.browsers || []).some((b) => b.installed) ? h("p", { class: "muted small", text: t("setup.browser_none") }) : null,
        other ? h("div", { class: "banner" }, icon("check"), h("span", { class: "grow", text: t("extsetup.connected_other") })) : null);
    };
    invoke("extension_setup").then((r) => {
      info = r || {};
      connected = info.connected || null;
      draw();
    }).catch((e) => mount(note, h("div", { class: "banner error", text: errorText(e) })));
    const timer = setInterval(async () => {
      const now = await invoke("extension_connected").catch(() => null);
      if (now !== connected) {
        connected = now;
        if (now) toast(t("extsetup.connected_toast"));
        draw();
      }
    }, POLL_MS);
    this.cleanup = () => clearInterval(timer);
    return [
      this.head(t("start.browser"), t("start.browser_text")),
      rows,
      note,
      h("p", { class: "muted small" }, t("setup.browser_hint"), " ",
        h("button", { class: "link", type: "button", text: t("setup.browser_by_hand"), on: { click: () => openExtensionGuide({ onClose: () => this.step === "browser" && this.go("browser") }) } })),
    ];
  }

  /** Sync: one way chosen (Google Drive where it can be set up), the rarer ways under More options. */
  render_sync() {
    const s = this.s;
    const status = statusLine();
    const wait = h("div", { class: "col" });
    if (this.facts.sync) {
      const where = s.google_drive ? `Google Drive (${s.google_drive.email})`
        : s.pass_server ? `Passyble Server (${s.pass_server.host})`
          : s.webdav_url ? "WebDAV"
            : t("setup.sync_folder");
      return [this.head(t("setup.sync_title"), t("setup.sync_text")),
        h("div", { class: "setup-status ok-text" }, icon("check"), h("span", { text: t("setup.sync_on", { where }) }))];
    }
    const google = async () => {
      status.clear();
      try {
        const account = await googleSignIn({ host: wait });
        if (!account) return;
        status.busy(t("settings.backing_up"));
        const r = await invoke("google_drive_enable", { email: account.email });
        toast(r.created_remote ? t("settings.google_backed_up", { email: r.email }) : t("settings.google_backed_up_merged", { email: r.email }));
        this.go("sync");
      } catch (e) {
        status.error(e);
      }
    };
    const server = () => openServerDialog({
      vaultName: s.vault_name,
      onConnected: () => this.go("sync"),
      onAddSeparate: (link) => window.dispatchEvent(new CustomEvent("pass-server-add", { detail: link })),
    });
    const webdav = () => {
      // Its fields are in Settings → Sync: the setup waits there to be continued.
      this.close({ pause: true });
      if (host && host.openSettings) host.openSettings("sync");
    };
    const account = async () => {
      status.busy(t("account.waiting"));
      status.el.append(" ", h("button", { class: "btn small", type: "button", text: t("common.cancel"), on: { click: () => invoke("account_sign_in_cancel").catch(() => {}) } }));
      try {
        const r = await invoke("account_sign_in");
        status.ok(t("account.signed_in", { email: (r && r.account && r.account.email) || "" }).trim());
      } catch (e) {
        const code = (e && e.code) || String((e && e.message) || e);
        if (code === "cancelled") status.clear();
        else status.error(e);
      }
    };
    const ways = {
      google: { icon: "cloudUpload", title: "Google Drive", run: google },
      local: { icon: "monitor", title: t("setup.sync_local"), hint: t("setup.sync_local_hint"), run: () => this.next() },
      account: { icon: "user", title: t("account.title"), hint: t("setup.sync_account_hint"), run: account },
      server: { icon: "server", title: "Passyble Server", hint: t("setup.sync_server_hint"), run: server },
      webdav: { icon: "cloud", title: "WebDAV", hint: t("onboarding.webdav_text"), run: webdav },
    };
    const choices = syncChoices({ google: Boolean(s.google_available && !s.pass_server), server: Boolean(s.webdav_supported) });
    const group = `sync-${Math.random().toString(36).slice(2)}`;
    const choose = (id) => this.setAction({ text: t(syncAction(id)), run: () => ways[id].run() });
    const choice = (id) => {
      const way = ways[id];
      const input = h("input", { type: "radio", name: group, value: id, checked: id === choices.selected, on: { change: () => choose(id) } });
      return h("label", { class: "setup-choice" }, input, icon(way.icon),
        h("div", { class: "grow" },
          h("div", { class: "t" }, way.title, id === choices.recommended ? h("span", { class: "choice-tag", text: t("onboarding.new_here") }) : null),
          way.hint ? h("div", { class: "hint", text: way.hint }) : null));
    };
    choose(choices.selected);
    return [
      this.head(t("setup.sync_title"), t("setup.sync_text")),
      h("div", { class: "col setup-choices", role: "radiogroup", "aria-label": t("setup.sync_title") }, choices.shown.map(choice)),
      choices.more.length ? more(...choices.more.map(choice)) : null,
      wait,
      status.el,
    ];
  }

  /** Recovery: the vault's recovery code, or for a vault on the Passyble password, the Emergency Kit. */
  render_recovery() {
    const status = statusLine();
    if (this.s.linked_account) {
      const show = async () => {
        status.clear();
        try {
          const kit = await withAccountKey((password) => invoke("account_kit", { password }));
          if (!kit) return;
          openKitDialog(kit, { intro: t("account_keys.kit_intro_again") });
          this.kitShown = true;
          this.setAction(null);
        } catch (e) {
          status.error(e);
        }
      };
      if (recoveryAction({ linked: true, kitShown: this.kitShown })) this.setAction({ text: t("setup.kit_action"), run: show });
      return [this.head(t("setup.kit_title"), t("setup.kit_text")), status.el];
    }
    const rc = this.s.recovery_code;
    const made = Boolean(rc && rc.exists);
    const create = () => openCreateRecoveryDialog({
      askPassword: false,
      replacing: made,
      vaultName: (host && host.vaultName && host.vaultName()) || this.s.vault_name || "",
      onDone: (created) => created && this.go("recovery"),
    });
    if (recoveryAction({ made })) this.setAction({ text: t("setup.recovery_action"), run: create });
    return [
      this.head(t("start.recovery"), t("start.recovery_text")),
      made
        ? h("div", { class: "setup-status ok-text" }, icon("check"),
            h("span", { text: rc.created_at ? t("setup.recovery_saved_on", { date: formatDate(rc.created_at) }) : t("common.saved") }),
            h("button", { class: "link small", type: "button", text: t("recovery.replace_ellipsis"), on: { click: create } }))
        : null,
      status.el,
    ];
  }

  render_done() {
    const f = this.facts;
    const value = {
      browser: f.browser ? t("setup.browser_connected") : t("setup.state_not_yet"),
      sync: f.sync ? t("setup.state_on") : t("setup.sync_local"),
      recovery: this.s.linked_account ? t("account_keys.kit_title") : f.recovery ? t("common.saved") : t("setup.state_not_yet"),
    };
    const extra = (id, iconName, title, text) => option(iconName, title, text, () => this.extra(id));
    const links = {
      import: () => extra("import", "download", t("setup.import_action"), t("setup.import_hint")),
      passkeys: () => extra("passkeys", "key", t("setup.passkeys_title"), t("setup.passkeys_link_text")),
      shortcuts: () => extra("shortcuts", "keyboard", t("setup.shortcuts_title"), this.quickKeys ? keyLabel(this.quickKeys) : t("setup.shortcuts_link_text")),
    };
    const row = (id) => {
      const done = stepDone(id, f) || (id === "recovery" && this.kitShown);
      return h("li", {}, h("span", { class: "grow", text: stepLabel(id) }), stateChip(done, value[id]),
        done ? null : h("button", { class: "btn small", type: "button", text: t("setup.set_up"), on: { click: () => this.go(id) } }));
    };
    return [
      this.head(t("setup.done_title"), t("setup.done_text")),
      this.steps.length ? h("ul", { class: "setup-summary" }, this.steps.map(row)) : null,
      this.extras.length ? h("h3", { class: "setup-more", text: t("setup.more_title") }) : null,
      this.extras.length ? h("div", { class: "col setup-options" }, this.extras.map((id) => links[id]())) : null,
    ];
  }

  extra_import() {
    this.foot.hidden = true;
    const pane = h("div", { class: "setup-import" });
    const view = new ImportView(pane, {
      onClose: () => this.go(DONE),
      onImported: () => host && host.reload && host.reload(),
      onReviewMerges: host && host.reviewMerges ? (pairs, done) => host.reviewMerges(pairs, done) : null,
    });
    this.cleanup = () => view.destroy();
    return pane;
  }

  extra_passkeys() {
    const s = this.s;
    const pp = s.passkey_provider_status || {};
    const status = statusLine();
    const usable = pp.supported && (pp.packaged || pp.package_registered || pp.can_register);
    const button = (text, run, primary = false) => h("button", { class: `btn${primary ? " primary" : ""}`, type: "button", text, on: { click: run } });
    let state;
    if (s.passkey_provider && pp.enabled_in_windows) {
      state = h("div", { class: "setup-status small ok-text" }, h("span", { text: t("setup.passkeys_on") }));
    } else if (s.passkey_provider && pp.restart_needed) {
      state = h("div", { class: "setup-row" }, h("div", { class: "grow" }, h("div", { class: "t", text: t("settings.pp_restart_title") }),
        h("div", { class: "muted small", text: t("settings.pp_restart_value") })),
      button(t("settings.restart"), () => invoke("restart_app").catch((e) => status.error(e)), true));
    } else if (s.passkey_provider && pp.registered) {
      state = h("div", { class: "setup-row" }, h("div", { class: "grow" }, h("div", { class: "t", text: t("settings.pp_switch_on") }),
        h("div", { class: "muted small", text: t("settings.pp_switch_on_value") })),
      button(t("common.open"), () => invoke("passkey_provider_open", { page: "passkeys" }).catch((e) => status.error(e)), true));
    } else if (!usable) {
      state = h("p", { class: "muted", text: pp.package_files === false ? t("settings.pp_files_missing") : t("settings.pp_needs_dev_mode") });
    } else {
      state = h("div", {}, button(t("common.turn_on"), async () => {
        status.busy(t("common.working"));
        try {
          const r = await invoke("set_settings", { update: { passkey_provider: true } });
          (r && r.notes ? r.notes : []).forEach((n) => toast(n, "", 7000));
          this.extra("passkeys");
        } catch (e) {
          status.error(e);
        }
      }, true));
    }
    return [this.head(t("setup.passkeys_title"), t("setup.passkeys_text")), state, status.el];
  }

  extra_shortcuts() {
    const actions = (this.shortcuts && this.shortcuts.actions) || [];
    const action = actions.find((a) => a.id === "quick_access") || { id: "quick_access", keys: "" };
    const status = statusLine();
    const shown = () => (action.keys ? keyLabel(action.keys) : "");
    const input = h("input", {
      class: "input hotkey-input setup-keys",
      readonly: true,
      value: shown(),
      placeholder: t("shortcuts.none"),
      title: t("settings.hotkey_title"),
      "aria-label": t("shortcuts.record_for", { action: t("shortcuts.quick_access") }),
    });
    const change = async (change) => {
      try {
        this.shortcuts = await invoke("set_shortcut", { change });
        const fresh = (this.shortcuts.actions || []).find((a) => a.id === "quick_access");
        if (fresh) Object.assign(action, fresh);
        input.value = shown();
        reset.disabled = !canReset(action);
        status.ok(t("shortcuts.saved"));
      } catch (e) {
        status.error(e);
      }
    };
    const reset = h("button", { class: "btn small", type: "button", text: t("shortcuts.reset"), disabled: !canReset(action), on: { click: () => change({ action: action.id, reset: true }) } });
    // While the box has the focus, Passyble lets go of its own shortcuts so they reach it.
    input.addEventListener("focus", () => {
      this.recording = true;
      input.classList.add("recording");
      input.placeholder = t("shortcuts.recording");
      invoke("shortcuts_recording", { on: true }).catch(() => {});
    });
    input.addEventListener("blur", () => {
      this.recording = false;
      input.classList.remove("recording");
      input.placeholder = t("shortcuts.none");
      input.value = shown();
      invoke("shortcuts_recording", { on: false }).catch(() => {});
    });
    input.addEventListener("keydown", (e) => {
      if (e.key === "Tab") return;
      e.preventDefault();
      // Esc leaves the box (the dialog's own Esc waits while it records).
      if (e.key === "Escape" && !e.ctrlKey && !e.altKey && !e.metaKey) {
        input.blur();
        return;
      }
      const pressed = recordKey(e);
      if (pressed.pending || pressed.ignored) return;
      input.value = keyLabel(pressed.combo);
      const why = pressed.error || shortcutProblem(actions, action.id, pressed.combo);
      if (why) {
        status.error(why);
        return;
      }
      input.blur();
      change({ action: action.id, keys: pressed.combo });
    });
    this.cleanup = () => invoke("shortcuts_recording", { on: false }).catch(() => {});
    return [
      this.head(t("setup.shortcuts_title"), t("setup.shortcuts_text")),
      h("div", { class: "setup-row" },
        h("div", { class: "grow" }, h("div", { class: "t", text: t("shortcuts.quick_access") }),
          action.default ? h("div", { class: "muted small", text: t("shortcuts.default", { keys: keyLabel(action.default) }) }) : null),
        h("span", { class: "shortcut-controls" }, input, reset)),
      h("p", { class: "muted small", text: t("setup.shortcuts_hint") }),
      status.el,
    ];
  }
}
