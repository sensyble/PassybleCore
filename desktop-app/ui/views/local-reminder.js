// "This vault is only on this device": a sidebar card while a vault has no sync and no backup
// (local-reminder-model.js says when). Never blocks anything, never shows while locked. "Not now"
// hides it for 30 days per vault (`local_reminder_dismiss`).

import { h, icon, invoke, mount, t, tn } from "../lib.js";
import { reminderView } from "./local-reminder-model.js";
import { attachTooltip } from "../tooltip.js";

export class LocalReminder {
  /** `hooks.onSetUp(vault)`: opens the sync setup of `vault` (an entry of `status.vaults`). */
  constructor(hooks) {
    this.hooks = hooks;
    this.el = h("div", { hidden: true });
    this.key = "";
    // Ids hidden by "Not now" in this window, until a status says so too.
    this.dismissed = new Set();
  }

  update(status) {
    // Once Rust reports a vault as not due, its "Not now" is on record there.
    for (const v of (status && status.vaults) || []) if (!v.local_reminder) this.dismissed.delete(v.id);
    const view = reminderView(status && {
      ...status,
      vaults: (status.vaults || []).filter((v) => !this.dismissed.has(v.id)),
    });
    const key = view ? [view.target.id, view.target.name, view.ids.join(","), view.named, view.google].join("|") : "";
    if (key === this.key) return;
    this.key = key;
    if (!view) {
      this.el.hidden = true;
      mount(this.el);
      return;
    }
    const setUp = h("button", { class: "btn primary small", type: "button", text: t("local_reminder.set_up_sync"), on: { click: () => this.hooks.onSetUp(view.target) } });
    const later = h("button", { class: "btn ghost small", type: "button", text: t("common.not_now"), on: { click: () => this.notNow(view.ids) } });
    const body = view.google ? tn("local_reminder.body", view.count) : tn("local_reminder.body_no_google", view.count);
    // Title only: the explanation is the tooltip of the (i) in the title row.
    const info = h("button", { class: "local-reminder-info", type: "button", "aria-label": t("local_reminder.what_this_means") }, icon("info"));
    attachTooltip(info, body);
    mount(
      this.el,
      h("div", { class: "offer local-reminder", role: "region", "aria-label": tn("local_reminder.title", view.count) },
        icon("shieldAlert"),
        h("div", { class: "grow" },
          h("div", { class: "local-reminder-head" }, h("div", { class: "t", text: tn("local_reminder.title", view.count) }), info),
          view.named ? h("div", { class: "hint ellipsis local-reminder-vault", text: view.target.name }) : null,
          h("div", { class: "row" }, setUp, later))),
    );
    this.el.hidden = false;
  }

  notNow(ids) {
    for (const id of ids) this.dismissed.add(id);
    this.key = "";
    this.el.hidden = true;
    mount(this.el);
    // Nothing to tell the user if this fails: the card just comes back next time.
    invoke("local_reminder_dismiss", { ids }).catch(() => {});
  }
}
