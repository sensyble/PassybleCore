// Password health (health.rs): every check of the core's report as a category with a count, an explanation,
// the items and an action (health-model.js decides which and in what order). The window gets titles,
// usernames, domains, addresses and scores, never a password. Checks with nothing to show come last.
//
// "Check for breaches" runs only when clicked, after a short notice of what is sent: Rust asks Have I Been
// Pwned once per distinct 5-character SHA-1 prefix (k-anonymity). The check belongs to the app, not this
// pane: closing the pane doesn't stop it, and the pane asks for its state when it opens
// (`health_breach_status`) and follows `health-breach` events. Only Cancel, a lock or quitting stop it.
//
// The master password tip: a note at the top while the master password typed at the last unlock on this PC
// is below the master password rule. "Dismiss" hides it for this vault on this PC (`master_password_tip_dismiss`).

import { confirmDialog, errorText, formatNumber, h, icon, iconButton, invoke, listen, mount, t, tn, toast, withShortcut } from "../lib.js";
import { itemAvatar, watchIcons } from "../siteicons.js";
import { breachCard, breachNoticeNeeded, healthChecks, healthyCount, httpsChanges, masterTipDialog, methodTexts, showMasterTip, toFixCount } from "./health-model.js";
import { ageText, breachText, strengthText } from "./items-model.js";
import { openChangeMasterPasswordDialog, openChangePasswordDialog } from "./signin.js";

const PRIVACY_NOTE = t("health.privacy_note");

const TEXT = {
  breached: { title: t("health.breached_section"), info: t("health.breached_info"), none: t("health.breached_none") },
  weak: { title: t("health.weak"), info: t("health.weak_info"), none: t("health.weak_none") },
  reused: { title: t("health.reused"), info: t("health.reused_info"), none: t("health.reused_none") },
  insecure: { title: t("health.insecure"), info: t("health.insecure_info"), none: t("health.insecure_none") },
  contains_name: { title: t("health.contains_name"), info: t("health.contains_name_info"), none: t("health.contains_name_none") },
  old: { title: t("health.old"), info: t("health.old_info"), none: t("health.old_none") },
  no_two_factor: { title: t("health.two_factor"), info: t("health.two_factor_info"), none: t("health.two_factor_none") },
  no_password: { title: t("health.no_password"), info: t("health.no_password_info"), none: t("health.no_password_none") },
  duplicates: { title: t("health.duplicates"), info: t("health.duplicates_info"), none: t("health.duplicates_none") },
  passkeys: { title: t("health.passkeys"), info: t("health.passkeys_info"), none: t("health.passkeys_none") },
};

export class HealthView {
  /** `hooks`: `onClose()`, `onEdit(id)`, `onFindDuplicates()`, `onError(e, retry)`. */
  constructor(pane, hooks) {
    this.pane = pane;
    this.hooks = hooks;
    this.report = null;
    // item id → breach count, after a check.
    this.breaches = null;
    this.card = { mode: "idle" };
    this.destroyed = false;
    // "Dismiss" on the master password tip in this view (Rust keeps it too).
    this.masterTipDismissed = false;
    this.body = h("div", { class: "col health-body" }, h("div", { class: "faint", text: t("health.checking") }));
    this.unlisten = listen("health-breach", (s) => this.onBreach(s));
    const inner = h("div", { class: "pane-inner health" },
      h("div", { class: "pane-header" },
        iconButton("back", withShortcut(t("common.back"), t("keys.esc")), () => this.hooks.onClose()),
        h("h2", { class: "grow", text: t("health.title") })),
      this.body);
    inner.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && !e.defaultPrevented) {
        e.preventDefault();
        this.hooks.onClose();
      }
    });
    mount(pane, inner);
    this.load();
  }

  destroy() {
    if (this.destroyed) return;
    this.destroyed = true;
    Promise.resolve(this.unlisten).then((off) => off && off()).catch(() => {});
  }

  async load() {
    try {
      this.report = await invoke("password_health");
    } catch (e) {
      if (!this.destroyed) mount(this.body, h("div", { class: "banner error", text: errorText(e) }));
      return;
    }
    const status = await invoke("health_breach_status").catch(() => null);
    if (this.destroyed) return;
    await this.onBreach(status, { quiet: true });
    if (!this.destroyed) this.render();
  }

  breachedItems() {
    if (!this.breaches) return null;
    return this.allItems().filter((i) => (this.breaches.get(i.id) || 0) > 0)
      .sort((a, b) => (this.breaches.get(b.id) || 0) - (this.breaches.get(a.id) || 0));
  }

  render() {
    const r = this.report;
    const healthy = healthyCount(r, this.breaches);
    const toFix = toFixCount(r, this.breaches);
    const checks = healthChecks(r, this.breachedItems());
    const found = checks.filter((c) => c.count > 0);
    const clean = checks.filter((c) => c.count === 0);
    const breached = this.breaches ? checks.find((c) => c.id === "breached").count : null;
    const tile = (label, n, cls = "") => h("div", { class: `import-stat ${cls}`.trim() }, h("div", { class: "n", text: formatNumber(n) }), h("div", { class: "faint", text: label }));

    mount(this.body,
      h("div", { class: "import-stats health-stats" },
        tile(t("health.checked"), r.checked),
        tile(t("health.look_fine"), healthy),
        tile(t("health.to_fix"), toFix, toFix ? "bad" : ""),
        breached === null
          ? tile(t("health.tips"), found.filter((c) => !c.problem).reduce((n, c) => n + c.count, 0))
          : tile(t("health.breached"), breached, breached ? "bad" : "")),
      // The figures above already say how many look fine.
      r.checked ? null : h("p", { class: "muted", text: t("health.no_logins") }),
      this.masterTip(),
      this.breachCard(),
      found.map((c) => this.section(c)),
      clean.length
        ? h("div", { class: "col" },
            h("div", { class: "section-title", text: t("health.all_good") }),
            h("div", { class: "col health-clean" }, clean.map((c) => this.allGood(TEXT[c.id].none))))
        : null);
    watchIcons(this.body);
  }

  allItems() {
    const seen = new Map();
    const r = this.report;
    const lists = [r.weak, r.reused.flat(), r.old, r.contains_name || [], r.insecure || [], r.no_two_factor || [], r.passkeys || []];
    for (const i of lists.flat()) if (!seen.has(i.id)) seen.set(i.id, i);
    // Breached items that are in none of the lists (strong, unique, recent) come from the check.
    for (const id of this.breaches ? this.breaches.keys() : []) {
      if (!seen.has(id) && this.extra && this.extra.has(id)) seen.set(id, this.extra.get(id));
    }
    return [...seen.values()];
  }

  section(check) {
    const text = TEXT[check.id];
    let content;
    let action = null;
    switch (check.id) {
      case "breached":
        content = this.rows(check.items, (i) => h("span", { class: "chip warn", text: breachText(this.breaches.get(i.id)) }));
        break;
      case "weak":
        content = this.rows(check.items, (i) => h("span", { class: `chip${i.score === 0 ? " warn" : ""}`, text: strengthText(i.score) }));
        break;
      case "reused":
        content = this.groups(check.items, (n) => tn("health.reused_group", n));
        break;
      case "insecure":
        content = this.rows(check.items, null, (i) => i.can_use_https
          ? h("button", { class: "btn small", type: "button", title: t("health.use_https_title"), on: { click: () => this.useHttps(i) } }, icon("lock"), t("health.use_https"))
          : null, (i) => (i.urls || [])[0]);
        break;
      case "old":
        content = this.rows(check.items, (i) => h("span", { class: "chip", text: t("health.changed_ago", { age: ageText(i.password_changed_at) }) }));
        break;
      case "no_two_factor":
        content = this.rows(check.items, (i) => methodTexts(i.methods, 2).map((m) => h("span", { class: "chip", text: m })),
          (i) => this.guideButton(i, "two_factor", t("health.two_factor_how")));
        break;
      case "passkeys":
        content = this.rows(check.items, null, (i) => this.guideButton(i, "passkey", t("health.passkeys_how")));
        break;
      case "duplicates":
        content = this.groups(check.items, (n) => tn("health.duplicates_group", n));
        if (this.hooks.onFindDuplicates) {
          action = h("button", { class: "btn small", type: "button", on: { click: () => this.hooks.onFindDuplicates() } }, icon("merge"), t("health.duplicates_merge"));
        }
        break;
      default:
        content = this.rows(check.items, null);
    }
    return h("div", { class: "col health-section", "data-check": check.id },
      h("div", { class: "row health-section-head" },
        h("div", { class: "section-title grow", text: t("health.section_count", { title: text.title, count: formatNumber(check.count) }) }),
        action),
      h("div", { class: "faint", text: text.info }),
      content);
  }

  rows(items, chip, extra, subtitle) {
    return h("div", { class: "fields" }, items.map((i) => this.row(i, chip ? chip(i) : null, extra ? extra(i) : null, subtitle ? subtitle(i) : null)));
  }

  groups(groups, head) {
    return h("div", { class: "col" }, groups.map((group) => h("div", { class: "fields reused-group" },
      h("div", { class: "reused-head faint", text: head(group.length) }),
      group.map((i) => this.row(i, null)))));
  }

  allGood(text) {
    return h("div", { class: "ok-line row" }, icon("check"), text);
  }

  row(i, chip, extra = null, subtitle = null) {
    const breach = this.breaches ? this.breaches.get(i.id) : undefined;
    const sub = subtitle || [i.username, i.domain].filter(Boolean).join(" · ");
    const chips = [chip].flat().filter(Boolean);
    return h("div", { class: "frow health-row" },
      itemAvatar(i),
      h("div", { class: "value" },
        h("div", { class: "ellipsis health-title", text: i.title || t("common.untitled") }),
        sub ? h("div", { class: "faint ellipsis", text: sub }) : null,
        // The chips go under the subtitle, so it keeps the width and they can wrap.
        h("div", { class: "health-chips" },
          chips,
          breach > 0 && !chips.length ? h("span", { class: "chip warn", text: t("health.breached") }) : null,
          i.reuse_count > 1 && chips.length ? h("span", { class: "chip", text: t("health.used_times", { count: formatNumber(i.reuse_count) }) }) : null)),
      h("div", { class: "actions" },
        extra,
        h("button", { class: "btn small", type: "button", title: t("health.edit_title", { title: i.title }), on: { click: () => this.hooks.onEdit(i.id) } }, icon("edit"), t("common.edit"))));
  }

  guideButton(i, kind, label) {
    if (!i.docs_url) return null;
    return h("button", {
      class: "btn small",
      type: "button",
      title: i.docs_url,
      on: { click: () => invoke("health_open_guide", { id: i.id, kind }).catch((e) => toast(errorText(e), "error")) },
    }, icon("external"), label);
  }

  async useHttps(i) {
    const changes = httpsChanges(i.urls);
    if (!changes.length) return;
    const ok = await confirmDialog({
      title: t("health.use_https_confirm_title"),
      text: h("div", { class: "col" },
        h("p", { text: t("health.use_https_confirm_text") }),
        changes.map((c) => h("div", { class: "mono ellipsis", text: c.to }))),
      confirm: t("health.use_https"),
      iconName: "lock",
    });
    if (!ok || this.destroyed) return;
    try {
      const r = await invoke("health_use_https", { id: i.id });
      toast(r.changed ? t("health.use_https_done", { title: i.title || t("common.untitled") }) : t("health.use_https_nothing"));
    } catch (e) {
      toast(errorText(e), "error");
      return;
    }
    if (this.destroyed) return;
    await this.load();
  }

  masterTip() {
    if (!showMasterTip(this.report, this.masterTipDismissed)) return null;
    const change = () => {
      const onDone = () => { if (!this.destroyed) this.load(); };
      if (masterTipDialog(this.report) === "server") openChangePasswordDialog({ onDone });
      else openChangeMasterPasswordDialog({ onDone });
    };
    return h("div", { class: "banner master-tip", role: "note", "data-tip": "master_password" },
      icon("info"),
      h("div", { class: "col grow" },
        h("div", { class: "t", text: t("unlock.master_password") }),
        h("div", { text: t("health.master_tip") }),
        h("div", { class: "row" },
          h("button", { class: "btn small", type: "button", text: t("signin.change_master"), on: { click: change } }),
          h("button", { class: "btn ghost small", type: "button", text: t("common.dismiss"), on: { click: () => this.dismissMasterTip() } }))));
  }

  dismissMasterTip() {
    this.masterTipDismissed = true;
    if (!this.destroyed && this.report) this.render();
    // Nothing to tell the user if this fails: the tip just comes back next time.
    invoke("master_password_tip_dismiss").catch(() => {});
  }

  breachCard() {
    // A copy of Passyble without the network code can't check for breaches: no card at all.
    if (this.report && this.report.breach_check === false) return null;
    const card = this.card;
    const running = card.mode === "running";
    this.progressBar = h("div", { class: "progress", role: "progressbar", "aria-valuemin": "0", "aria-valuemax": "100", hidden: !running }, h("div", { class: "progress-bar" }));
    this.progressText = h("span", { class: "faint" });
    let stopped = null;
    if (card.mode === "stopped" || card.mode === "failed") {
      const reason = card.mode === "failed"
        ? card.error
        : card.reason === "locked" ? t("health.breach_stopped_locked") : t("health.breach_stopped_cancelled");
      stopped = h("div", { class: "col grow" },
        h("strong", { text: t("health.breach_stopped") }),
        h("span", { class: card.mode === "failed" ? "error-text" : "faint", text: reason }));
    }
    const button = running
      ? h("button", { class: "btn", type: "button", on: { click: () => invoke("health_breach_cancel").catch(() => {}) } }, icon("close"), t("common.cancel"))
      : h("button", { class: "btn primary", type: "button", disabled: !this.report.checked, on: { click: () => this.checkBreaches() } }, icon("shield"),
        card.mode === "idle" ? t("health.check") : t("health.check_again"));
    const about = h("button", { class: "btn ghost small", type: "button", on: { click: () => this.aboutBreachCheck() } }, icon("info"), t("health.notice_title"));
    const section = h("div", { class: "col health-section breach-section" },
      h("div", { class: "row health-section-head" }, h("div", { class: "section-title grow", text: t("health.breached_passwords") }), about),
      h("div", { class: "faint", text: PRIVACY_NOTE }),
      h("div", { class: "card col breach-card" },
        h("div", { class: "row" }, stopped || this.progressText, h("span", { class: "spacer" }), button),
        this.progressBar));
    if (running) this.showProgress();
    return section;
  }

  showProgress() {
    const c = this.card;
    if (c.mode !== "running" || !this.progressBar) return;
    this.progressBar.hidden = false;
    this.progressBar.firstChild.style.width = `${c.pct}%`;
    this.progressBar.setAttribute("aria-valuenow", String(c.pct));
    this.progressText.textContent = tn("health.progress", c.total, { done: formatNumber(c.done) });
  }

  /** The app's breach check moved on (`health-breach`) or the pane just opened (`quiet`: no toast for a check that ended while it was closed). */
  async onBreach(status, { quiet = false } = {}) {
    if (this.destroyed) return;
    const was = this.card.mode;
    const card = breachCard(status);
    this.card = card;
    if (card.mode === "running" && was === "running" && this.progressBar && this.progressBar.isConnected) {
      this.showProgress();
      return;
    }
    // A new check, a stop or a lock: the earlier results are gone in the app too.
    this.breaches = null;
    this.extra = new Map();
    if (card.mode === "done") {
      this.breaches = card.breaches;
      const missing = [...this.breaches.entries()].filter(([, c]) => c > 0).map(([id]) => id);
      if (missing.length) {
        const all = await invoke("list_items").catch(() => []);
        for (const it of all) if (missing.includes(it.id)) this.extra.set(it.id, { id: it.id, kind: it.kind, title: it.title, username: it.username, domain: it.site || "", site: it.site, score: 4, reuse_count: 1 });
      }
      if (!quiet && was === "running" && card.failed) toast(tn("health.failed", card.failed), "error");
    }
    if (!this.destroyed && this.report) this.render();
  }

  /** The notice of what the check sends and never sends, with "Don't show this again". True for "Check passwords". */
  async breachNotice() {
    const box = h("input", { type: "checkbox", checked: !!(this.report && this.report.breach_notice_hidden) });
    const ok = await confirmDialog({
      title: t("health.notice_title"),
      text: h("div", { class: "col" },
        h("p", { text: t("health.notice_text") }),
        h("label", { class: "check" }, box, t("health.notice_dont_show"))),
      confirm: t("health.notice_check"),
      iconName: "shield",
    });
    const hidden = box.checked;
    if (this.report) this.report.breach_notice_hidden = hidden;
    invoke("health_breach_notice", { hidden }).catch(() => {});
    return ok;
  }

  async aboutBreachCheck() {
    if (await this.breachNotice() && !this.destroyed && this.card.mode !== "running") this.startBreachCheck();
  }

  async checkBreaches() {
    if (this.card.mode === "running") return;
    if (breachNoticeNeeded(this.report) && !(await this.breachNotice())) return;
    if (!this.destroyed) this.startBreachCheck();
  }

  async startBreachCheck() {
    try {
      await this.onBreach(await invoke("health_breach_check"));
    } catch (e) {
      if (!this.destroyed) toast(errorText(e), "error");
    }
  }
}
