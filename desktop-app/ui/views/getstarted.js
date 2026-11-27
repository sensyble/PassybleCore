// The "Get started" checklist above the vault view's empty pane, for a vault added on this PC (setup_guide.rs
// `get_started`). Each step opens the flow that does it and is ticked once Passyble can see it done:
//   * Connect your browser: the extension setup guide; done once an extension connected, or "Mark as done".
//   * Bring your passwords over: Import; done when the vault has items.
//   * Save a recovery code: recovery.js; done when the vault has one.
//   * Use on your phone and other PCs: the sync tutorial (help.js); done when the vault syncs.
// Windows Hello / Touch ID isn't a step: the sidebar offers it right after the vault is unlocked with its password.
// Hide hides it for this vault (Settings → Help shows it again). Once every step is done it hides itself, with
// a toast if that happened while it was on screen. "Continue setup" reopens setup.js where it stopped.

import { errorText, formatNumber, h, icon, invoke, mount, t, tn, toast } from "../lib.js";
import { openExtensionGuide } from "./extension.js";
import { openTutorial } from "./help.js";
import { openCreateRecoveryDialog } from "./recovery.js";
import { openSetup } from "./setup.js";

const helpPath = () => [t("settings.title"), t("help.title")].join(" → ");

export class GetStarted {
  /** `hooks`: `vaultName()`, `onImport()`, `tutorial()` (the context for help.js). */
  constructor(hooks) {
    this.hooks = hooks;
    this.shown = false;
    this.el = h("section", { class: "card checklist", role: "region", "aria-label": t("start.title"), hidden: true });
    this.refresh = () => this.load();
    window.addEventListener("pass-get-started", this.refresh);
  }

  destroy() {
    this.destroyed = true;
    window.removeEventListener("pass-get-started", this.refresh);
  }

  async load() {
    const seq = (this.seq = (this.seq || 0) + 1);
    const s = await invoke("get_started").catch(() => null);
    if (this.destroyed || seq !== this.seq) return;
    if (!s || !s.show) {
      this.el.hidden = true;
      return;
    }
    this.setup = s.setup || null;
    const steps = this.steps(s);
    const done = steps.filter((step) => step.done).length;
    if (done === steps.length) {
      this.el.hidden = true;
      invoke("get_started_show", { show: false }).catch(() => {});
      if (this.shown) toast(t("start.all_done", { path: helpPath() }), "", 6000);
      this.shown = false;
      return;
    }
    this.render(steps, done);
  }

  steps(s) {
    return [
      {
        icon: "globe",
        title: t("start.browser"),
        text: t("start.browser_text"),
        done: !!s.browser,
        action: t("start.browser_action"),
        run: () => openExtensionGuide(),
      },
      {
        icon: "download",
        title: t("start.import"),
        text: t("start.import_text"),
        done: (s.items || 0) > 0,
        action: t("start.import_action"),
        run: () => this.hooks.onImport(),
      },
      {
        icon: "key",
        title: t("start.recovery"),
        text: t("start.recovery_text"),
        done: s.recovery === true,
        action: t("start.recovery_action"),
        run: () => openCreateRecoveryDialog({ vaultName: this.hooks.vaultName(), onDone: () => this.load() }),
      },
      {
        icon: "sync",
        title: t("start.sync"),
        text: t("start.sync_text"),
        done: !!s.sync,
        action: t("start.sync_action"),
        run: () => openTutorial("sync", this.hooks.tutorial()),
      },
    ];
  }

  render(steps, done) {
    const total = steps.length;
    const bar = h("div", {
      class: "progress",
      role: "progressbar",
      "aria-label": t("start.title"),
      "aria-valuemin": "0",
      "aria-valuemax": String(total),
      "aria-valuenow": String(done),
    }, h("div", { class: "progress-bar" }));
    bar.firstChild.style.width = `${Math.round((done / total) * 100)}%`;
    const next = steps.findIndex((step) => !step.done);
    mount(this.el,
      h("div", { class: "row checklist-head" },
        h("div", { class: "grow" },
          h("h2", { text: t("start.title") }),
          h("div", { class: "muted small", text: tn("start.progress", done, { total: formatNumber(total) }) })),
        this.setup ? h("button", { class: "btn small tonal", type: "button", text: t("setup.continue_setup"), on: { click: () => openSetup() } }) : null,
        h("button", { class: "btn ghost small", type: "button", title: t("start.hide_title", { path: helpPath() }), on: { click: () => this.hide() } }, t("common.hide"))),
      bar,
      h("ol", { class: "start-steps" }, steps.map((step, i) => this.stepRow(step, i, i === next))));
    this.el.hidden = false;
    this.shown = true;
  }

  stepRow(step, index, next) {
    const message = h("div", { class: "hint", role: "status" });
    let button = null;
    if (!step.done) {
      button = h("button", {
        class: `btn small${next ? " primary" : ""}`,
        type: "button",
        on: { click: () => step.run(button, message) },
      }, step.action);
    }
    return h("li", { class: `start-step${step.done ? " done" : ""}` },
      h("span", { class: "start-mark", "aria-hidden": "true" }, step.done ? icon("check") : String(index + 1)),
      h("div", { class: "grow" },
        h("div", { class: "t" }, icon(step.icon, "start-ico"), step.title),
        step.done ? null : h("div", { class: "muted small", text: step.text }),
        message),
      step.done ? h("span", { class: "start-done ok-text", text: t("start.done") }) : button);
  }

  async hide() {
    this.el.hidden = true;
    this.shown = false;
    try {
      await invoke("get_started_show", { show: false });
      toast(t("start.hidden", { path: helpPath() }), "", 6000);
    } catch (e) {
      toast(errorText(e), "error");
    }
  }
}
