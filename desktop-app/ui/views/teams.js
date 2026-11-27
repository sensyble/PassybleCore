// Teams and Family: only for an account in a Team or a Family, or with a vault shared with it
// (`teams_overview().visible`); nobody else sees any of it.
//
// The main page lists what needs the user first (notices, invitations, notifications), then "Shared with me",
// the organisations (admins open views/teams-admin.js), Secure send, Emergency access, admin-assisted recovery
// and the user's own key fingerprint. Shared vault, Secure send and Emergency access have pages of their own.
//
// Every action is a Tauri command; a failure shows as a toast (a "locked" answer unlocks first
// through `hooks.onError`). `teams-changed` (main.js → vault.js `teamsChanged`) reloads the page.

import { agoText, confirmDialog, errorText, formatDate, formatDateTime, h, icon, iconButton, invoke, mount, settingsGroup, settingsRow, t, tn, toast, withShortcut } from "../lib.js";
import { accountRow } from "./account.js";
import { openLinkDialog, openUnlinkDialog, withAccountKey, withFreshSignIn } from "./account-keys.js";
import { adminKeyRows, openKeyNotice } from "./account-reset.js";
import { pinnedFirst } from "./pins-model.js";
import { OrgAdminView } from "./teams-admin.js";
import {
  compareFirst,
  enrolComparing,
  fingerprintBox,
  formDialog,
  labelled,
  leaveOrg,
  openDirectShareDialog,
  openEmergencyAcceptDialog,
  openEmergencyAddDialog,
  openConfirmKeysDialog,
  openSendCreateDialog,
  openSendLinkDialog,
  openTrustDialog,
  roleSelect,
  setupEmergencyContact,
} from "./teams-dialogs.js";
import {
  directShareAllowed,
  emergencyAccessLabel,
  emergencyState,
  fingerprintText,
  isOrgManager,
  linkedState,
  needsTrust,
  noticeLines,
  notificationGroups,
  notificationText,
  orgKindLabel,
  orgRoleLabel,
  passwordNotices,
  policyLines,
  roleLabel,
  sendState,
  sharedVaultLine,
  signerState,
  vaultKindLabel,
  violationText,
  waitText,
} from "./teams-model.js";

const openedEmergency = new Map();

const ago = (ms) => agoText(ms);

function rowButton(label, onClick, cls = "") {
  return h("button", { class: `btn small ${cls}`.trim(), type: "button", on: { click: onClick } }, label);
}

function vaultIcon(v, orgs) {
  if (v.kind === "direct") return "user";
  const org = (orgs || []).find((o) => o.id === v.org);
  return org && org.kind === "family" ? "heart" : "building";
}

export class TeamsView {
  /**
   * `hooks`: `onClose()`, `onChanged()`, `onOpenItem(id)`, `onVaultSettings(id)`, `onError(e, retry)`, `pins()` and
   * `onPin(id, pin)`. `options.section`: "shared", "invites", "confirm", "notices", "members", "send", "emergency",
   * or an org id to open its admin page.
   */
  constructor(pane, hooks, options = {}) {
    this.pane = pane;
    this.hooks = hooks;
    this.page = "main";
    this.section = options.section || null;
    this.destroyed = false;
    this.overview = null;
    this.account = null;
    this.title = h("h2", { class: "grow ellipsis" });
    this.back = iconButton("back", withShortcut(t("common.back"), t("keys.esc")), () => this.goBack());
    this.refreshBtn = iconButton("sync", t("teams.refresh"), () => this.refresh());
    this.body = h("div", { class: "settings" }, settingsRow("clock", t("common.loading"), {}));
    const inner = h("div", { class: "pane-inner settings-view teams-view" },
      h("div", { class: "pane-header" }, this.back, this.title, this.refreshBtn),
      this.body);
    inner.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && !e.defaultPrevented) {
        e.preventDefault();
        this.goBack();
      }
    });
    mount(pane, inner);
    this.showTitle();
    this.load();
  }

  destroy() {
    this.destroyed = true;
    if (this.admin) this.admin.destroy();
    this.admin = null;
  }

  goBack() {
    if (this.page === "main") this.hooks.onClose();
    else this.showMain();
  }

  showTitle(text = t("teams.title")) {
    this.title.textContent = text;
    this.title.title = text;
    this.back.title = this.page === "main" ? withShortcut(t("common.close"), t("keys.esc")) : withShortcut(t("common.back"), t("keys.esc"));
    this.back.setAttribute("aria-label", this.page === "main" ? t("common.close") : t("common.back"));
    this.refreshBtn.hidden = this.page !== "main";
  }

  async load({ quiet = false } = {}) {
    try {
      const [overview, account] = await Promise.all([invoke("teams_overview"), invoke("account_status").catch(() => null)]);
      if (this.destroyed) return;
      this.overview = overview;
      this.account = account;
    } catch (e) {
      if (this.destroyed) return;
      if (!quiet) mount(this.body, h("div", { class: "banner error", text: errorText(e) }));
      return;
    }
    if (this.page === "main") this.renderMain();
    else if (this.page === "vault" && this.vaultRef) this.showVault(this.vaultRef, { quiet: true });
    if (this.section) {
      const section = this.section;
      this.section = null;
      this.openSection(section);
    }
  }

  changed() {
    if (this.admin) this.admin.reload({ quiet: true });
    this.load({ quiet: true });
  }

  pinsChanged() {
    if (this.page === "main") this.renderMain();
    else if (this.page === "vault" && this.vaultRef) this.showVault(this.vaultRef, { quiet: true });
  }

  pins() {
    return this.hooks.pins ? this.hooks.pins() : [];
  }

  async refresh() {
    this.refreshBtn.disabled = true;
    try {
      this.overview = await invoke("teams_refresh");
      this.renderMain();
      if (this.hooks.onChanged) this.hooks.onChanged();
      toast(t("teams.refreshed"));
    } catch (e) {
      this.failed(e, () => this.refresh());
    } finally {
      this.refreshBtn.disabled = false;
    }
  }

  failed(e, retry) {
    if (this.hooks.onError) this.hooks.onError(e, retry);
    else toast(errorText(e), "error");
  }

  openSection(section) {
    if (section === "send") return this.showSend();
    if (section === "emergency") return this.showEmergency();
    const orgs = (this.account && this.account.orgs) || [];
    const org = orgs.find((o) => o.id === section);
    if (org) return this.showOrg(org);
    if (section === "members" || section === "confirm") {
      const managed = orgs.find((o) => isOrgManager(o.role));
      if (section === "members" && managed) return this.showOrg(managed);
    }
    const target = this.body.querySelector(`[data-section="${section}"]`);
    if (target) target.scrollIntoView({ block: "start" });
    return undefined;
  }

  showMain() {
    if (this.admin) this.admin.destroy();
    this.admin = null;
    this.page = "main";
    this.vaultRef = null;
    this.showTitle();
    this.renderMain();
    this.back.focus();
  }

  renderMain() {
    const o = this.overview;
    if (!o) return;
    if (!o.visible) {
      mount(this.body, settingsGroup(t("teams.title"), [
        settingsRow("users", t("teams.not_available"), { value: t("teams.not_available_sub") }),
        accountRow({ onChanged: () => this.load && this.load() }),
      ]));
      return;
    }
    const orgs = (this.account && this.account.orgs) || [];
    mount(this.body,
      this.noticesGroup(o),
      this.approvalsGroup(),
      this.invitesGroup(o),
      this.notificationsGroup(o, orgs),
      this.sharedGroup(o, orgs),
      this.orgsGroup(orgs),
      this.moreGroup(orgs),
      this.keysGroup(o));
  }

  noticesGroup(o) {
    const rows = [];
    if (o.device_waiting) rows.push(this.deviceWaitingRow(o.device_waiting));
    for (const held of o.held || []) {
      rows.push(this.notice("shieldAlert", t("teams.held_title", { vault: held.name || "" }),
        held.reason === "sso_required" ? t("teams.held_sso") : t("teams.held_sign_in"), null));
    }
    if (o.keys && o.keys.published === false) {
      rows.push(this.notice("key", t("teams.keys_unpublished"), t("teams.keys_unpublished_sub"),
        rowButton(t("teams.keys_publish"), async (e) => {
          const btn = e.currentTarget;
          btn.disabled = true;
          try {
            await invoke("teams_publish_keys");
            toast(t("teams.keys_published"));
            this.load({ quiet: true });
          } catch (err) {
            btn.disabled = false;
            this.failed(err);
          }
        }, "tonal")));
    }
    for (const v of (o.vaults || []).filter(needsTrust)) {
      rows.push(this.notice("shieldAlert", t("teams.untrusted_title", { vault: v.name }), t("teams.untrusted_sub"),
        rowButton(t("teams.compare"), async () => {
          if (await openTrustDialog(this.vaultOf(v))) this.afterChange();
        }, "tonal")));
    }
    // The manager who signed a vault's members list has other keys than the ones compared.
    for (const v of (o.vaults || []).filter((x) => !needsTrust(x) && signerState(x).state === "changed")) {
      rows.push(this.notice("shieldAlert", t("contacts.signer_changed_title", { person: v.signer || "" }),
        t("contacts.signer_changed_sub", { vault: v.name, person: v.signer || "" }),
        rowButton(t("teams.compare"), () => this.pinSigner(this.vaultOf(v), { signed_by: v.signer, signer_fingerprint: v.signer_fingerprint }, true), "tonal")));
    }
    for (const n of o.notices || []) {
      const lines = noticeLines(n);
      rows.push(h("div", { class: "set-row teams-notice", role: "note" },
        icon(n.rotated_after_leave ? "key" : "history", "set-ico"),
        h("span", { class: "set-text" },
          h("span", { class: "set-title", text: t("teams.notice_title", { vault: n.name }) }),
          lines.map((l) => h("span", { class: `set-sub${l.kind === "dropped" ? " warn" : ""}`, text: l.text })))));
    }
    if ((o.notices || []).length) {
      rows.push(h("div", { class: "set-row set-actions-row" }, h("span", { class: "spacer" }),
        rowButton(t("teams.notices_dismiss"), async () => {
          try {
            await invoke("teams_notices_dismiss");
            this.load({ quiet: true });
          } catch (e) {
            this.failed(e);
          }
        })));
    }
    const policy = o.policy || {};
    for (const v of policy.violations || []) {
      rows.push(this.notice("shieldAlert", violationText(v), v.rule === "master_password_strength" ? t("policy.violation_strength_sub") : "", null));
    }
    rows.push(...this.passwordRuleRows(o.password_policy));
    if (!rows.length) return null;
    return this.mark("notices", settingsGroup(t("teams.notices"), rows, { cls: "teams-notices" }));
  }

  /** A Team's password rule not met here: "Set a second password" or "Use Passyble password" per vault. */
  passwordRuleRows(policy) {
    const activeId = policy && policy.home ? policy.home.id : null;
    return passwordNotices(policy).map((n) => {
      const name = (n.vault && n.vault.name) || "";
      const action = n.kind === "second"
        ? rowButton(t("password_mode.set_second"), () => openUnlinkDialog({ vaultName: name, second: true, onDone: () => this.afterChange() }), "tonal")
        : rowButton(t("account_keys.link_button"), () => {
            if (n.vault.id === activeId) openLinkDialog({ vaultName: name, onDone: () => this.afterChange() });
            else if (this.hooks.onVaultSettings) this.hooks.onVaultSettings(n.vault.id);
          }, "tonal");
      return this.notice("shieldAlert", n.title, n.text, action);
    });
  }

  deviceWaitingRow(approval) {
    const mailed = approval.email_sent_at || approval.email_confirmed_at;
    const releaseAt = Number(approval.release_at) || 0;
    const sub = releaseAt
      ? t("teams.device_waiting_release", { date: formatDateTime(releaseAt) })
      : mailed ? t("teams.device_waiting_mailed") : t("teams.device_waiting_sub");
    const email = rowButton(t("teams.device_waiting_email"), async (e) => {
      const btn = e.currentTarget;
      btn.disabled = true;
      try {
        await invoke("device_approval_email");
        toast(t("teams.device_waiting_email_sent"));
      } catch (err) {
        btn.disabled = false;
        this.failed(err);
      }
    });
    const again = rowButton(t("teams.device_waiting_check"), async (e) => {
      const btn = e.currentTarget;
      btn.disabled = true;
      try {
        await invoke("teams_refresh");
        this.load({ quiet: true });
      } catch (err) {
        btn.disabled = false;
        this.failed(err);
      }
    }, "tonal");
    return this.notice("monitor", t("teams.device_waiting"), sub, mailed ? [again] : [email, again]);
  }

  approvalsGroup() {
    const box = h("div", { class: "col" });
    invoke("device_approvals")
      .then((r) => {
        if (this.destroyed) return;
        const pending = (r && r.pending) || [];
        if (!pending.length) return;
        const answer = async (a, approve, btn) => {
          if (!approve) {
            const ok = await confirmDialog({ title: t("teams.approval_deny_title"), text: t("teams.approval_deny_text", { device: a.device_name || "" }), confirm: t("teams.approval_deny"), danger: true });
            if (!ok) return;
          }
          btn.disabled = true;
          try {
            await invoke("device_approval_answer", { id: a.id, approve });
            toast(approve ? t("teams.approval_approved", { device: a.device_name || "" }) : t("teams.approval_denied"));
            this.load({ quiet: true });
          } catch (e) {
            btn.disabled = false;
            this.failed(e);
          }
        };
        mount(box, settingsGroup(t("teams.approvals"), pending.map((a) => settingsRow("monitor", a.device_name || t("teams.approval_device"), {
          value: [a.platform || "", a.created_at ? t("teams.approval_asked", { ago: agoText(Number(a.created_at)) }) : ""].filter(Boolean).join(" · "),
          valueClass: "warn",
          control: [
            rowButton(t("teams.approval_deny"), (e) => answer(a, false, e.currentTarget)),
            rowButton(t("teams.approval_approve"), (e) => answer(a, true, e.currentTarget), "tonal"),
          ],
        })), { sub: t("teams.approvals_sub") }));
      })
      .catch(() => {});
    return box;
  }

  notice(iconName, title, sub, control) {
    return settingsRow(iconName, title, { value: sub || null, valueClass: "warn", control });
  }

  invitesGroup(o) {
    const invites = o.invites || [];
    if (!invites.length) return null;
    const answer = async (inv, accept, btn) => {
      btn.disabled = true;
      try {
        await invoke("teams_invite_answer", { org: inv.org, inviteId: inv.invite_id, accept });
        toast(accept ? t("teams.invite_accepted", { org: inv.org_name }) : t("teams.invite_declined", { org: inv.org_name }));
        this.afterChange();
        // The Team requires admin recovery of the account key (told before joining): enrol now.
        if (accept && inv.admin_recovery_required) openKeyNotice({ kind: "admin_recovery_required", org: inv.org, name: inv.org_name }, { onChanged: () => this.load({ quiet: true }) });
      } catch (e) {
        btn.disabled = false;
        this.failed(e, () => answer(inv, accept, btn));
      }
    };
    return this.mark("invites", settingsGroup(t("teams.invites"), invites.map((inv) => {
      const decline = rowButton(t("teams.decline"), (e) => answer(inv, false, e.currentTarget));
      const accept = rowButton(t("teams.accept"), (e) => answer(inv, true, e.currentTarget), "tonal");
      return settingsRow(inv.kind === "family" ? "heart" : "building", t("teams.invite_line", { org: inv.org_name }), {
        value: [orgKindLabel(inv.kind), inv.invited_by ? t("teams.invited_by", { person: inv.invited_by }) : "", orgRoleLabel(inv.role, inv.kind),
          inv.admin_recovery_required ? t("account_admin.invite_required") : ""].filter(Boolean).join(" · "),
        info: inv.admin_recovery_required ? t("account_admin.warning") : null,
        control: [decline, accept],
      });
    })));
  }

  notificationsGroup(o, orgs) {
    const groups = notificationGroups(o.notifications);
    if (!groups.length) return null;
    const rows = [];
    for (const g of groups) {
      rows.push(h("div", { class: "set-row set-subhead", role: "heading", "aria-level": "4" }, icon("bell", "set-ico"), h("span", { class: "set-title", text: g.title })));
      for (const entry of g.items) {
        const text = notificationText(g.kind, entry, (ms) => agoText(ms));
        let control = null;
        if (g.kind === "confirm") {
          const org = orgs.find((x) => x.id === entry.org);
          if (org && isOrgManager(org.role)) control = rowButton(t("teams.confirm_open"), () => this.showOrg(org, { confirm: entry.account }), "tonal");
        } else if (g.kind === "shared" && entry.vault_id) {
          control = rowButton(t("common.open"), () => this.showVault({ id: entry.vault_id, name: entry.name }));
        }
        rows.push(settingsRow(g.kind === "removed" ? "close" : g.kind === "waiting" ? "clock" : g.kind === "confirm" ? "shield" : "share", text.title, { value: text.sub || null, control }));
      }
    }
    rows.push(h("div", { class: "set-row set-actions-row" }, h("span", { class: "spacer" }),
      rowButton(t("teams.mark_seen"), async () => {
        try {
          await invoke("teams_notifications_seen");
          this.load({ quiet: true });
        } catch (e) {
          this.failed(e);
        }
      })));
    return this.mark("confirm", settingsGroup(t("teams.notifications"), rows));
  }

  sharedGroup(o, orgs) {
    const pins = this.pins();
    const vaults = pinnedFirst(o.vaults || [], pins, (v) => this.vaultOf(v).id);
    const rows = vaults.map((v) => {
      const line = sharedVaultLine(v, ago);
      const id = this.vaultOf(v).id;
      const pinned = pins.includes(id);
      return settingsRow(vaultIcon(v, orgs), [v.name, pinned ? h("span", { class: "visually-hidden", text: `, ${t("vault.pinned")}` }) : null], {
        value: line.text,
        valueClass: line.cls,
        onClick: () => this.showVault(this.vaultOf(v)),
        control: this.hooks.onPin ? this.pinButton(id, v.name, pinned) : null,
        cls: pinned ? "pinned" : "",
      });
    });
    if (!rows.length) rows.push(settingsRow("users", t("teams.nothing_shared"), { value: t("teams.nothing_shared_sub") }));
    // A Team's password rules may turn it off: the reason instead of the button.
    const sharing = directShareAllowed(o.password_policy);
    rows.push(settingsRow("userPlus", t("teams.share_person"), {
      value: sharing ? t("teams.share_person_sub") : o.password_policy.sharing_note,
      control: sharing ? rowButton(t("teams.share_start"), () => this.directShare()) : null,
    }));
    const group = this.mark("shared", settingsGroup(t("teams.shared_with_me"), rows, { sub: t("teams.shared_sub") }));
    if (o.backend === "server" && !orgs.length) {
      invoke("server_vault_features")
        .then((f) => {
          if (this.destroyed || !f || !f.available) return;
          const card = group.querySelector(".set-card");
          if (card) card.append(settingsRow("plus", t("teams.server_new"), {
            value: t("teams.server_new_sub"),
            control: rowButton(t("teams.server_new_start"), () => this.serverVaultCreate()),
          }));
        })
        .catch(() => {});
    }
    return group;
  }

  async serverVaultCreate() {
    const name = h("input", { class: "input", type: "text", maxlength: "80", autocomplete: "off", placeholder: t("teams.server_new_name_placeholder") });
    const people = h("textarea", { class: "input", rows: "3", spellcheck: "false", placeholder: t("teams.server_new_people_placeholder") });
    const role = roleSelect("edit");
    const r = await formDialog({
      title: t("teams.server_new_title"),
      iconName: "users",
      submit: t("teams.server_new_submit"),
      body: [
        labelled(t("teams.server_new_name"), name),
        labelled(t("teams.server_new_people"), people, t("teams.server_new_people_hint")),
        labelled(t("teams.server_new_role"), role),
      ],
      onSubmit: async () => {
        const label = name.value.trim();
        if (!label) {
          name.focus();
          throw new Error(t("teams.server_new_name_needed"));
        }
        const members = people.value.split(/[\s,;]+/).map((x) => x.trim()).filter(Boolean).map((user) => ({ user, role: role.value }));
        return { label, members, answer: await invoke("server_vault_create", { label, members }) };
      },
    });
    if (r && !(await this.compareMembers(r))) return;
    if (r) {
      toast(t("teams.server_new_done", { vault: name.value.trim() }));
      this.afterChange();
    }
  }

  /**
   * Compare first, then wrap: while `server_vault_create` answers `needs_compare`, the user compares each member's
   * fingerprint, then it runs again with the compared fingerprints. Resolves true once the vault was made.
   */
  async compareMembers({ label, members, answer }) {
    let r = answer;
    while (r && r.needs_compare && r.needs_compare.length) {
      for (const c of r.needs_compare) {
        const m = members.find((x) => x.user === (c.person || c.account));
        if (!m) return false;
        const fp = await compareFirst(c, async (fingerprint) => fingerprint, { name: m.user });
        if (!fp) return false;
        m.fingerprint = fp;
      }
      r = await invoke("server_vault_create", { label, members });
    }
    return true;
  }

  async serverVaultDelete(ref, name) {
    const ok = await confirmDialog({
      title: t("teams.server_delete_title", { vault: name }),
      text: t("teams.server_delete_text"),
      confirm: t("teams.server_delete"),
      iconName: "trash",
      danger: true,
    });
    if (!ok) return;
    try {
      await invoke("server_vault_delete", { vaultId: ref.id });
      toast(t("teams.server_deleted", { vault: name }));
      this.afterChange();
      this.showMain();
    } catch (e) {
      this.failed(e);
    }
  }

  orgsGroup(orgs) {
    if (!orgs.length) return null;
    return this.mark("members", settingsGroup(t("teams.orgs"), orgs.map((org) => {
      const lines = policyLines(org.policy, org.kind);
      const value = [orgKindLabel(org.kind), orgRoleLabel(org.role, org.kind), org.sign_in_ok === false ? t("teams.org_sign_in_needed") : ""].filter(Boolean).join(" · ");
      const info = lines.length ? `${t("teams.org_policies")}\n${lines.map((l) => `• ${l}`).join("\n")}` : null;
      return isOrgManager(org.role)
        ? settingsRow(org.kind === "family" ? "heart" : "building", org.name, {
            value: org.kind === "family" ? t("teams.manage_family", { role: value }) : t("teams.manage_team", { role: value }),
            valueClass: org.sign_in_ok === false ? "warn" : "",
            info,
            onClick: () => this.showOrg(org),
          })
        : settingsRow(org.kind === "family" ? "heart" : "building", org.name, {
            value,
            valueClass: org.sign_in_ok === false ? "warn" : "",
            info,
            control: org.role === "owner" ? null : rowButton(t("teams.leave_org"), () => leaveOrg(org, () => this.afterChange()).catch((e) => this.failed(e))),
          });
    })));
  }

  moreGroup(orgs) {
    const rows = [
      settingsRow("send", t("send.title"), { value: t("send.row_sub"), onClick: () => this.showSend() }),
      settingsRow("lifeBuoy", t("emergency.title"), { value: t("emergency.row_sub"), onClick: () => this.showEmergency() }),
    ];
    const group = settingsGroup(t("teams.more"), rows);
    // Admin-assisted recovery: opt-in, and the member sees whether they are enrolled.
    if (orgs.some((o) => o.kind === "team" || o.kind === "family")) this.recoveryRows(group.querySelector(".set-card"));
    return group;
  }

  async recoveryRows(card) {
    // An account with a Passyble password enrols its account key.
    const keyRows = await adminKeyRows(card, { reload: () => this.load({ quiet: true }), failed: (e) => this.failed(e) });
    if (keyRows || this.destroyed) return;
    if (!((this.account && this.account.orgs) || []).some((o) => o.kind === "team")) return;
    let list;
    try {
      list = await invoke("admin_recovery_status");
    } catch {
      return;
    }
    if (this.destroyed || !card.isConnected) return;
    const orgs = (this.account && this.account.orgs) || [];
    for (const r of (list || []).filter((x) => x.available || x.enrolled)) {
      const org = orgs.find((o) => o.id === r.org);
      const name = (org && org.name) || r.org;
      const btn = rowButton(r.enrolled ? t("recoveryadmin.withdraw") : t("recoveryadmin.enrol"), async () => {
        if (r.enrolled) {
          const ok = await confirmDialog({ title: t("recoveryadmin.withdraw_title", { org: name }), text: t("recoveryadmin.withdraw_text"), confirm: t("recoveryadmin.withdraw") });
          if (!ok) return;
        } else {
          const ok = await confirmDialog({ title: t("recoveryadmin.enrol_title", { org: name }), text: t("recoveryadmin.enrol_text", { org: name }), confirm: t("recoveryadmin.enrol"), iconName: "lifeBuoy" });
          if (!ok) return;
        }
        btn.disabled = true;
        try {
          if (r.enrolled) await invoke("admin_recovery_withdraw", { org: r.org });
          else if (!(await enrolComparing((fingerprint) => invoke("admin_recovery_enroll", { org: r.org, fingerprint })))) {
            btn.disabled = false;
            return;
          }
          toast(r.enrolled ? t("recoveryadmin.withdrawn") : t("recoveryadmin.enrolled_toast"));
          this.load({ quiet: true });
        } catch (e) {
          btn.disabled = false;
          this.failed(e);
        }
      }, r.enrolled ? "" : "tonal");
      card.append(settingsRow("lifeBuoy", t("recoveryadmin.row", { org: name }), {
        value: !r.enrolled
          ? t("recoveryadmin.not_enrolled")
          : r.enrolled_at ? t("recoveryadmin.enrolled_on", { date: formatDate(r.enrolled_at) }) : t("recoveryadmin.enrolled"),
        valueClass: r.enrolled ? "ok" : "",
        info: t("recoveryadmin.info"),
        control: btn,
      }));
    }
  }

  keysGroup(o) {
    const fp = o.keys && o.keys.fingerprint;
    if (!fp) return null;
    return settingsGroup(t("teams.your_keys"), [
      settingsRow("shield", t("teams.your_fingerprint"), {
        value: fingerprintText(fp),
        valueTitle: fingerprintText(fp),
        cls: "fp-row",
        info: t("teams.your_fingerprint_info"),
        control: rowButton(t("common.show"), () => this.showFingerprint(fp)),
      }),
    ]);
  }

  showFingerprint(fp) {
    formDialog({
      title: t("teams.your_fingerprint"),
      iconName: "shield",
      submit: t("common.done"),
      cancel: t("common.close"),
      body: [h("p", { class: "muted", text: t("teams.your_fingerprint_info") }), fingerprintBox(t("teams.your_fingerprint"), fp)],
      onSubmit: () => true,
    });
  }

  mark(section, group) {
    if (group) group.dataset.section = section;
    return group;
  }

  vaultOf(v) {
    return { id: (v.vault && v.vault.id) || v.vault_id || v.key, name: v.name, row: v };
  }

  afterChange() {
    this.load({ quiet: true });
    if (this.hooks.onChanged) this.hooks.onChanged();
  }

  async directShare() {
    const policy = this.overview && this.overview.policy ? this.overview.policy.effective : null;
    const r = await openDirectShareDialog({ policy });
    if (r) this.afterChange();
  }

  async showVault(ref, { quiet = false } = {}) {
    if (this.admin) this.admin.destroy();
    this.admin = null;
    this.page = "vault";
    this.vaultRef = ref;
    this.showTitle(ref.name || t("teams.shared_vault"));
    if (!quiet) mount(this.body, settingsRow("clock", t("common.loading"), {}));
    let info;
    try {
      info = await invoke("shared_vault_info", { vaultId: ref.id });
    } catch (e) {
      if (this.destroyed || this.page !== "vault") return;
      mount(this.body, h("div", { class: "banner error", text: errorText(e) }));
      return;
    }
    if (this.destroyed || this.page !== "vault" || this.vaultRef !== ref) return;
    const row = ref.row || ((this.overview && this.overview.vaults) || []).find((v) => (v.vault && v.vault.id) === ref.id) || {};
    const vault = info.vault || {};
    const name = vault.name || ref.name;
    this.showTitle(name);
    const orgs = (this.account && this.account.orgs) || [];
    const org = orgs.find((o) => o.id === row.org);
    const state = linkedState(row, ago);

    const label = h("input", { class: "input", value: name, maxlength: "80", spellcheck: "false", autocomplete: "off" });
    const rename = rowButton(t("teams.rename"), async () => {
      const text = label.value.trim();
      if (!text || text === name) return;
      rename.disabled = true;
      try {
        await invoke("shared_vault_rename", { vaultId: ref.id, label: text });
        toast(t("teams.renamed"));
        ref.name = text;
        this.afterChange();
        this.showVault(ref, { quiet: true });
      } catch (e) {
        rename.disabled = false;
        this.failed(e);
      }
    });
    label.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); rename.click(); } });
    label.id = "tv-label";

    const i = info.info || {};
    const members = i.members || [];
    const memberRows = members.map((m) => settingsRow(m.group ? "users" : "user", [
      h("span", { class: "ellipsis", text: m.account }),
      m.account === (this.overview && this.overview.account_id) ? h("span", { class: "chip", text: t("teams.you") }) : null,
    ], {
      value: [roleLabel(m.role), m.group ? t("teams.via_group", { group: m.group }) : "", m.added_by ? t("teams.added_by", { person: m.added_by }) : ""].filter(Boolean).join(" · "),
      valueTitle: m.added_at ? formatDateTime(m.added_at) : null,
      info: m.fingerprint ? t("teams.member_fingerprint", { fingerprint: fingerprintText(m.fingerprint) }) : null,
    }));
    const pending = (info.pending || []).map((p) => settingsRow("clock", p.account, {
      value: [p.reason || t("teams.pending_confirmation"), p.since ? agoText(p.since) : ""].filter(Boolean).join(" · "),
      valueClass: "warn",
    }));

    const signer = signerState(info);
    const signerChanged = signer.state === "changed" && !(needsTrust(row) || i.anchored === false)
      ? settingsRow("shieldAlert", t("contacts.signer_changed_title", { person: i.signed_by || "" }), {
          value: t("contacts.signer_changed_sub", { vault: name, person: i.signed_by || "" }),
          valueClass: "warn danger",
          control: rowButton(t("teams.compare"), () => this.pinSigner(ref, i, true), "tonal"),
        })
      : null;
    const trust = needsTrust(row) || i.anchored === false
      ? settingsRow("shieldAlert", t("teams.untrusted_title", { vault: name }), {
          value: t("teams.untrusted_sub"),
          valueClass: "warn",
          control: rowButton(t("teams.compare"), async () => {
            if (await openTrustDialog(ref, info)) {
              this.afterChange();
              this.showVault(ref, { quiet: true });
            }
          }, "tonal"),
        })
      : null;

    const ov = this.overview || {};
    const owned = ov.backend === "server" && row.key && ov.account_id && String(row.key).startsWith(`${ov.account_id}/`);
    const leave = owned
      ? h("button", { class: "btn danger", type: "button", on: { click: () => this.serverVaultDelete(ref, name) } }, icon("trash"), t("teams.server_delete"))
      : h("button", { class: "btn danger", type: "button", on: { click: () => this.leaveVault(ref, name) } }, icon("logOut"), t("teams.leave"));
    // A Team's vault while its password rule isn't met here.
    const ruleRows = ((ov.password_policy && ov.password_policy.blocked_vaults) || []).includes(ref.id)
      ? this.passwordRuleRows(ov.password_policy)
      : [];
    const noticeRows = [trust, signerChanged, ...ruleRows].filter(Boolean);
    mount(this.body,
      noticeRows.length ? settingsGroup(t("teams.notices"), noticeRows) : null,
      settingsGroup(t("teams.this_shared_vault"), [
        settingsRow("edit", t("teams.label"), { id: "tv-label", control: [label, rename], info: t("teams.label_info") }),
        settingsRow(vault.kind === "direct" ? "user" : org && org.kind === "family" ? "heart" : "building", vaultKindLabel(vault.kind || row.kind, org && org.kind), {
          value: [org ? org.name : "", roleLabel(vault.role || row.my_role) ? t("teams.your_role", { role: roleLabel(vault.role || row.my_role) }) : ""].filter(Boolean).join(" · "),
        }),
        settingsRow("sync", t("teams.sync_state"), { value: state.text, valueClass: state.cls }),
        this.hooks.onPin ? this.pinRow(ref) : null,
        i.signed_by ? settingsRow(signer.state === "changed" ? "shieldAlert" : "shield", t("teams.signed_by", { person: i.signed_by }), {
          value: [i.signer_fingerprint ? fingerprintText(i.signer_fingerprint) : "", signer.text].filter(Boolean).join(" · ") || null,
          valueClass: signer.cls,
          cls: "fp-row",
          info: t("teams.signed_by_info"),
          control: signer.state === "not_verified" && i.signer_fingerprint && i.signed_by !== ov.account_id
            ? rowButton(t("teams.compare"), () => this.pinSigner(ref, i, false), "tonal")
            : null,
        }) : null,
      ]),
      settingsGroup(t("teams.who_has_access"), memberRows.length ? memberRows : [settingsRow("users", t("teams.no_members"), {})], {
        sub: info.can_manage ? t("teams.access_manage_sub") : t("teams.access_sub"),
      }),
      pending.length ? settingsGroup(t("teams.waiting_confirmation"), pending) : null,
      h("div", { class: "row" }, h("span", { class: "spacer" }), leave));
  }

  /**
   * Compare the fingerprint of the manager who signed `ref`'s members list (`i`: its info); once it matches, their
   * keys are pinned (`shared_signer_pin`). `changed`: their keys changed since compared (the loud warning).
   */
  async pinSigner(ref, i, changed) {
    if (!i || !i.signer_fingerprint) return;
    const person = i.signed_by || t("teams.trust_manager");
    try {
      const r = await openConfirmKeysDialog({ account: person, name: person, fingerprint: i.signer_fingerprint, changed },
        (fingerprint) => invoke("shared_signer_pin", { vaultId: ref.id, fingerprint }));
      if (r === null) return;
      toast(t("contacts.signer_verified_toast", { person }));
      this.afterChange();
      if (this.page === "vault" && this.vaultRef === ref) this.showVault(ref, { quiet: true });
    } catch (e) {
      this.failed(e);
    }
  }

  pinButton(id, name, pinned) {
    const button = iconButton("pin", t(pinned ? "vault.unpin_named" : "vault.pin_named", { vault: name }), () => this.hooks.onPin(id, !pinned), "ghost row-pin");
    button.setAttribute("aria-pressed", String(pinned));
    return button;
  }

  pinRow(ref) {
    const pinned = this.pins().includes(ref.id);
    return settingsRow("pin", t(pinned ? "vault.pinned" : "vault.not_pinned"), {
      value: t("vault.pin_sub"),
      control: h("button", { class: "btn small", type: "button", on: { click: () => this.hooks.onPin(ref.id, !pinned) } },
        icon(pinned ? "pinOff" : "pin"), t(pinned ? "vault.unpin" : "vault.pin")),
    });
  }

  async leaveVault(ref, name) {
    const ok = await confirmDialog({
      title: t("teams.leave_title", { vault: name }),
      text: t("teams.leave_text"),
      confirm: t("teams.leave"),
      iconName: "logOut",
      danger: true,
    });
    if (!ok) return;
    try {
      await invoke("shared_vault_leave", { vaultId: ref.id });
      toast(t("teams.left", { vault: name }));
      this.afterChange();
      this.showMain();
    } catch (e) {
      this.failed(e, () => this.leaveVault(ref, name));
    }
  }

  async showSend() {
    if (this.admin) this.admin.destroy();
    this.admin = null;
    this.page = "send";
    this.showTitle(t("send.title"));
    mount(this.body, settingsRow("clock", t("common.loading"), {}));
    let sends;
    try {
      sends = await invoke("send_list");
    } catch (e) {
      if (!this.destroyed && this.page === "send") mount(this.body, h("div", { class: "banner error", text: errorText(e) }));
      return;
    }
    if (this.destroyed || this.page !== "send") return;
    const create = h("button", {
      class: "btn primary",
      type: "button",
      on: {
        click: async () => {
          const r = await openSendCreateDialog();
          if (r && r.link) openSendLinkDialog(r);
          if (r) this.showSend();
        },
      },
    }, icon("plus"), t("send.new"));
    const rows = (sends || []).map((s) => {
      const st = sendState(s);
      const revoke = rowButton(t("send.revoke"), async () => {
        const ok = await confirmDialog({ title: t("send.revoke_title", { name: s.name || t("send.unnamed") }), text: t("send.revoke_text"), confirm: t("send.revoke"), danger: true });
        if (!ok) return;
        try {
          await invoke("send_revoke", { id: s.id });
          toast(t("send.revoked"));
          this.showSend();
        } catch (e) {
          this.failed(e);
        }
      });
      return settingsRow(s.kind === "file" ? "fileText" : "note", s.name || t("send.unnamed"), {
        value: [s.created_at ? t("send.created_on", { date: formatDate(s.created_at) }) : "", st.text].filter(Boolean).join(" · "),
        valueClass: st.cls,
        control: st.live ? revoke : null,
      });
    });
    mount(this.body,
      h("p", { class: "page-lead muted", text: t("send.lead") }),
      settingsGroup(t("send.yours"), rows.length ? rows : [settingsRow("send", t("send.none"), { value: t("send.none_sub") })]),
      h("div", { class: "row" }, h("span", { class: "spacer" }), create));
  }

  async showEmergency() {
    if (this.admin) this.admin.destroy();
    this.admin = null;
    this.page = "emergency";
    this.showTitle(t("emergency.title"));
    mount(this.body, settingsRow("clock", t("common.loading"), {}));
    let s;
    try {
      s = await invoke("emergency_status");
    } catch (e) {
      if (!this.destroyed && this.page === "emergency") mount(this.body, h("div", { class: "banner error", text: errorText(e) }));
      return;
    }
    if (this.destroyed || this.page !== "emergency") return;
    const act = async (cmd, args, done) => {
      try {
        const r = await invoke(cmd, args);
        if (done) done(r);
        this.showEmergency();
      } catch (e) {
        this.failed(e);
      }
    };
    const contactRow = (g) => {
      const st = emergencyState(g, "owner");
      const controls = [];
      if (st.actions.includes("setup")) {
        controls.push(rowButton(t("emergency.setup"), async () => {
          try {
            if (await setupEmergencyContact(g)) this.showEmergency();
          } catch (e) {
            this.failed(e);
          }
        }, "tonal"));
      }
      if (st.actions.includes("refuse")) controls.push(rowButton(t("emergency.refuse"), () => act("emergency_answer", { grantId: g.grant_id, approve: false }, () => toast(t("emergency.refused")))));
      if (st.actions.includes("approve")) {
        controls.push(rowButton(t("emergency.approve"), async () => {
          const ok = await confirmDialog({ title: t("emergency.approve_title", { contact: g.contact }), text: g.access === "full" ? t("emergency.approve_full_text") : t("emergency.approve_view_text"), confirm: t("emergency.approve") });
          if (ok) act("emergency_answer", { grantId: g.grant_id, approve: true }, () => toast(t("emergency.approved")));
        }, "tonal"));
      }
      if (st.actions.includes("remove")) {
        controls.push(rowButton(t("common.remove"), async () => {
          const ok = await confirmDialog({ title: t("emergency.remove_title", { contact: g.contact }), text: t("emergency.remove_text"), confirm: t("common.remove"), danger: true });
          if (ok) act("emergency_remove", { grantId: g.grant_id }, () => toast(t("emergency.removed")));
        }));
      }
      return settingsRow("user", g.contact, {
        value: [emergencyAccessLabel(g.access), t("emergency.after_wait", { wait: waitText(g.wait_hours) }),
          Array.isArray(g.vault_ids) && g.vault_ids.length ? tn("emergency.vaults_covered", g.vault_ids.length) : "", st.text].filter(Boolean).join(" · "),
        valueClass: st.cls,
        info: g.fingerprint ? t("teams.member_fingerprint", { fingerprint: fingerprintText(g.fingerprint) }) : null,
        control: controls,
      });
    };
    const remember = (g, r) => {
      if (!r || !Array.isArray(r.vault_ids)) return;
      const ids = openedEmergency.get(g.grant_id) || [];
      openedEmergency.set(g.grant_id, [...new Set([...ids, ...r.vault_ids])]);
    };
    const trusterRow = (g) => {
      const st = emergencyState(g, "contact");
      const controls = [];
      if (st.actions.includes("accept")) {
        controls.push(rowButton(t("emergency.accept"), async () => {
          if (await openEmergencyAcceptDialog()) this.showEmergency();
        }, "tonal"));
      }
      if (st.actions.includes("request")) {
        controls.push(rowButton(t("emergency.request"), async () => {
          const ok = await confirmDialog({ title: t("emergency.request_title", { owner: g.owner }), text: t("emergency.request_text", { owner: g.owner, wait: waitText(g.wait_hours) }), confirm: t("emergency.request"), iconName: "lifeBuoy" });
          if (ok) act("emergency_request", { grantId: g.grant_id }, () => toast(t("emergency.requested")));
        }, "tonal"));
      }
      if (st.actions.includes("open")) {
        controls.push(rowButton(g.access === "full" ? t("emergency.take_over") : t("emergency.open_view"), () => act("emergency_open", { grantId: g.grant_id }, (r) => {
          remember(g, r);
          toast(r && r.read_only ? t("emergency.opened_view", { owner: g.owner }) : t("emergency.opened_full", { owner: g.owner }));
          if (r && r.elsewhere) toast(tn("emergency.elsewhere", r.elsewhere), "", 9000);
          if (this.hooks.onChanged) this.hooks.onChanged();
        }), "tonal"));
        // A vault the owner kept on Google Drive, WebDAV or in a folder: a copy handed over opens too.
        controls.push(rowButton(t("emergency.open_copy"), () => act("emergency_open_file", { grantId: g.grant_id }, (r) => {
          if (r && r.opened) {
            remember(g, r);
            toast(r.read_only ? t("emergency.opened_view", { owner: g.owner }) : t("emergency.opened_full", { owner: g.owner }));
            if (this.hooks.onChanged) this.hooks.onChanged();
          }
        })));
        if (g.access === "full") {
          controls.push(rowButton(t("emergency.keep"), async () => {
            const ids = openedEmergency.get(g.grant_id) || [];
            if (!ids.length) {
              toast(t("emergency.keep_open_first"), "error");
              return;
            }
            try {
              for (const vaultId of ids) {
                const r = await withAccountKey((password) => invoke("emergency_keep", { vaultId, password }));
                if (r && r.kept) toast(t("emergency.kept", { owner: g.owner }));
              }
              if (this.hooks.onChanged) this.hooks.onChanged();
            } catch (e) {
              this.failed(e);
            }
          }));
        }
      }
      return settingsRow("lifeBuoy", g.owner, {
        value: [emergencyAccessLabel(g.access), st.text].filter(Boolean).join(" · "),
        valueClass: st.cls,
        control: controls,
      });
    };
    const contacts = (s.contacts || []).map(contactRow);
    // A vault's grant couldn't be renewed at its open (the service wants a fresh sign-in).
    const pendingBanner = s.pending
      ? h("div", { class: "banner warn" }, icon("alert"), h("span", { class: "grow", text: t("emergency.pending") }),
        rowButton(t("emergency.update_now"), () => withFreshSignIn(() => invoke("emergency_renew_now"))
          .then(() => { toast(t("emergency.updated")); this.showEmergency(); })
          .catch((e) => this.failed(e)), "tonal"))
      : null;
    // Requests made to the user that the backend lists apart: answered like a contact's request.
    for (const r of s.requests || []) {
      if (!(s.contacts || []).some((c) => c.grant_id === r.grant_id)) contacts.push(contactRow({ ...r, state: r.state || "requested" }));
    }
    const add = h("button", {
      class: "btn primary",
      type: "button",
      on: { click: async () => { if (await openEmergencyAddDialog()) this.showEmergency(); } },
    }, icon("plus"), t("emergency.add"));
    const accept = h("button", {
      class: "btn",
      type: "button",
      on: { click: async () => { if (await openEmergencyAcceptDialog()) this.showEmergency(); } },
    }, t("emergency.accept_invitation"));
    mount(this.body,
      h("p", { class: "page-lead muted", text: t("emergency.lead") }),
      pendingBanner,
      settingsGroup(t("emergency.your_contacts"), contacts.length ? contacts : [settingsRow("user", t("emergency.no_contacts"), { value: t("emergency.no_contacts_sub") })], {
        sub: t("emergency.your_contacts_sub"),
      }),
      h("div", { class: "row" }, h("span", { class: "spacer" }), add),
      settingsGroup(t("emergency.trusting_you"), (s.as_contact || []).length
        ? s.as_contact.map(trusterRow)
        : [settingsRow("lifeBuoy", t("emergency.no_trusters"), {})], { sub: t("emergency.trusting_you_sub") }),
      h("div", { class: "row" }, h("span", { class: "spacer" }), accept));
  }

  showOrg(org, options = {}) {
    if (this.admin) this.admin.destroy();
    this.page = "org";
    this.showTitle(org.name);
    const holder = h("div", { class: "col" });
    mount(this.body, holder);
    this.admin = new OrgAdminView(holder, org, {
      me: this.overview && this.overview.account_id,
      onChanged: () => this.afterChange(),
      onOpenItem: (id) => this.hooks.onOpenItem && this.hooks.onOpenItem(id),
      onError: (e, retry) => this.failed(e, retry),
    }, options);
  }
}

export function teamsButtonLabel(count) {
  return count ? tn("teams.button_count", count) : t("teams.title");
}
