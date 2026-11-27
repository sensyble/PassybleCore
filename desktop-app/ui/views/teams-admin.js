// The admin screen of a Team and the family manager screen of a Family: seats and billing (on the website, no prices in
// the app), members (roles, key confirmation by comparing fingerprints, departments, offboarding), invitations (one,
// or a CSV with a preview), departments (Teams), shared vaults and the access matrix, policies, admin recovery
// approvals (Teams) and the activity log. Logic in admin-model.js.

import { agoText, confirmDialog, errorText, formatDateTime, h, icon, invoke, modal, mount, settingsGroup, settingsRow, t, tn, toast } from "../lib.js";
import {
  accessSummary,
  activityText,
  changedAccess,
  csvInviteRows,
  csvPreview,
  grantRole,
  keyState,
  matrixSubjects,
  MAX_AUTO_LOCK,
  memberActions,
  memberPasswordChoices,
  offboardSummary,
  orgRoleChoices,
  PASSWORD_MODES,
  policyChange,
  policyFields,
  policyForm,
  seatsFull,
  seatsText,
  setGrant,
  SIGN_IN_RULES,
  ssoReady,
  validEmail,
} from "./admin-model.js";
import { formDialog, labelled, leaveOrg, openConfirmKeysDialog, openNeedsCompareDialog, selectOf } from "./teams-dialogs.js";
import { durationText, fingerprintText, orgKindLabel, orgRoleLabel, passwordModeLabel, roleLabel, ROLES, strengthName } from "./teams-model.js";

function rowButton(label, onClick, cls = "") {
  return h("button", { class: `btn small ${cls}`.trim(), type: "button", on: { click: onClick } }, label);
}

const toggle = (checked) => h("input", { type: "checkbox", checked: !!checked });

const vaultId = (v) => v.vault_id || v.id;
const vaultName = (v) => v.label || v.name || vaultId(v);

export class OrgAdminView {
  /**
   * `org`: `account_status().orgs[]`. `hooks`: `me` (the user's account id), `onChanged()`, `onOpenItem(id)`,
   * `onError(e, retry)`. `options.confirm`: an account to open the confirmation for once loaded.
   */
  constructor(el, org, hooks, options = {}) {
    this.el = el;
    this.org = org;
    this.hooks = hooks;
    this.pendingConfirm = options.confirm || null;
    this.destroyed = false;
    this.events = [];
    this.next = null;
    mount(el, settingsRow("clock", t("common.loading"), {}));
    this.reload();
  }

  destroy() {
    this.destroyed = true;
  }

  get family() {
    return this.org.kind === "family";
  }

  failed(e, retry) {
    if (this.hooks.onError) this.hooks.onError(e, retry);
    else toast(errorText(e), "error");
  }

  async reload({ quiet = false } = {}) {
    const org = this.org.id;
    try {
      const [overview, members, policies] = await Promise.all([
        invoke("org_overview", { org }),
        invoke("org_members", { org }),
        invoke("org_policies", { org }).catch(() => null),
      ]);
      let departments = [];
      if (!this.family) departments = await invoke("org_departments", { org }).catch(() => overview.departments || []);
      if (this.destroyed) return;
      this.data = { overview, members: members.members || [], invites: members.invites || [], departments: departments || [], policies };
    } catch (e) {
      if (this.destroyed) return;
      if (!quiet) mount(this.el, h("div", { class: "banner error", text: errorText(e) }));
      return;
    }
    this.render();
    if (!this.events.length) this.loadActivity();
    if (this.pendingConfirm) {
      const who = this.pendingConfirm;
      this.pendingConfirm = null;
      const m = this.data.members.find((x) => x.account_id === who || x.email === who);
      if (m) this.confirm(m);
    }
  }

  changed() {
    this.reload({ quiet: true });
    if (this.hooks.onChanged) this.hooks.onChanged();
  }

  async run(cmd, args, done) {
    try {
      const r = await invoke(cmd, { org: this.org.id, ...args });
      if (done) done(r);
      this.changed();
      this.needsCompare(r && r.needs_compare);
      return r;
    } catch (e) {
      this.failed(e);
      return null;
    }
  }

  render() {
    const d = this.data;
    const features = (d.overview && d.overview.features) || {};
    mount(this.el,
      this.orgGroup(d.overview),
      this.membersGroup(d),
      this.invitesGroup(d.invites),
      this.family ? null : this.departmentsGroup(d),
      this.vaultsGroup(d),
      this.policiesGroup(d.policies),
      // A Family's members may opt in their account key; a Team needs its policy.
      this.family || features.admin_recovery !== false ? this.recoveryGroup() : null,
      this.transfersGroup(d.overview),
      this.activityGroup());
  }

  orgGroup(o) {
    const seats = (o && o.seats) || null;
    return settingsGroup(this.family ? t("admin.family_title") : t("admin.team_title"), [
      settingsRow(this.family ? "heart" : "building", this.org.name, {
        value: [orgKindLabel(this.org.kind), orgRoleLabel(this.org.role, this.org.kind)].join(" · "),
      }),
      seats ? settingsRow("users", t("admin.seats"), { value: seatsText(seats), valueClass: seatsFull(seats) ? "warn" : "" }) : null,
      this.org.role === "owner"
        ? settingsRow("external", t("admin.billing"), {
            value: t("admin.billing_sub"),
            control: rowButton(t("admin.billing_open"), () => invoke("org_billing_open", { org: this.org.id }).catch((e) => this.failed(e))),
          })
        : settingsRow("logOut", this.family ? t("teams.leave_family") : t("teams.leave_team"), {
            value: t("teams.leave_org_sub"),
            control: rowButton(t("teams.leave_org"), () => leaveOrg(this.org, () => { if (this.hooks.onChanged) this.hooks.onChanged(); }).catch((e) => this.failed(e))),
          }),
    ], { sub: this.family ? t("admin.family_sub") : t("admin.team_sub") });
  }

  membersGroup(d) {
    const deptName = (id) => (d.departments.find((x) => x.id === id) || {}).name || id;
    const rows = d.members.map((m) => {
      const actions = memberActions(m, { me: this.hooks.me, myRole: this.org.role, kind: this.org.kind });
      const ks = keyState(m);
      const controls = [];
      if (actions.includes("confirm")) controls.push(rowButton(t("admin.confirm"), () => this.confirm(m), "tonal"));
      const more = actions.filter((a) => a !== "confirm");
      if (more.length) {
        const btn = h("button", { class: "btn icon ghost small", type: "button", title: t("admin.member_options", { person: m.name || m.email }), "aria-label": t("admin.member_options", { person: m.name || m.email }), "aria-haspopup": "menu" }, icon("more"));
        btn.addEventListener("click", () => this.memberMenu(m, more, btn));
        controls.push(btn);
      }
      const value = [
        orgRoleLabel(m.role, this.org.kind),
        (m.departments || []).map(deptName).join(", "),
        ks === "to_confirm" ? t("admin.key_to_confirm")
          : ks === "to_compare" ? t("contacts.compare_row")
          : ks === "changed" ? t("contacts.changed_row")
          : ks === "no_keys" ? t("admin.key_none") : "",
        m.password_mode ? passwordModeLabel(m.password_mode) : "",
        m.second_password ? t("admin.member_second_password") : "",
      ].filter(Boolean).join(" · ");
      return settingsRow(m.role === "owner" || m.role === "admin" ? "shield" : "user", [
        h("span", { class: "ellipsis", text: m.name || m.email || m.account_id }),
        m.account_id === this.hooks.me ? h("span", { class: "chip", text: t("teams.you") }) : null,
      ], {
        value,
        valueClass: ks === "changed" ? "warn danger" : ks === "to_confirm" || ks === "to_compare" ? "warn" : "",
        valueTitle: m.email || null,
        info: m.keys && m.keys.fingerprint ? t("teams.member_fingerprint", { fingerprint: fingerprintText(m.keys.fingerprint) }) : null,
        control: controls,
      });
    });
    const seats = d.overview && d.overview.seats;
    const buttons = h("div", { class: "row wrap" }, h("span", { class: "spacer" }),
      rowButton(t("admin.invite_csv"), () => this.inviteCsv()),
      rowButton(t("admin.invite"), () => this.invite(), "tonal"));
    return h("div", { class: "col" },
      settingsGroup(this.family ? t("admin.family_members") : t("admin.members"), rows.length ? rows : [settingsRow("users", t("admin.no_members"), {})], {
        sub: seats && seatsFull(seats) ? t("admin.seats_full_sub") : null,
      }),
      buttons);
  }

  memberMenu(m, actions, anchor) {
    const entries = [];
    if (actions.includes("role")) entries.push(["shield", t("admin.change_role"), () => this.changeRole(m)]);
    if (actions.includes("departments")) entries.push(["users", t("admin.member_departments"), () => this.memberDepartments(m)]);
    if (actions.includes("passwords")) entries.push(["lock", t("admin.member_passwords"), () => this.memberPasswords(m)]);
    if (actions.includes("make_owner")) entries.push(["swap", t("admin.make_owner"), () => this.makeOwner(m)]);
    if (actions.includes("remove")) entries.push(["logOut", this.family ? t("admin.remove_family") : t("admin.remove"), () => this.offboard(m), "danger"]);
    popupMenu(entries, anchor, t("admin.member_options", { person: m.name || m.email }));
  }

  async makeOwner(m) {
    const person = m.name || m.email;
    const ok = await confirmDialog({
      title: t("admin.make_owner_title", { person }),
      text: this.family ? t("admin.make_owner_text_family", { person }) : t("admin.make_owner_text", { person }),
      confirm: t("admin.make_owner"),
      iconName: "swap",
    });
    if (!ok) return;
    await this.run("org_transfer_owner", { accountId: m.account_id }, () => toast(t("admin.owner_transferred", { person })));
  }

  confirm(m) {
    openConfirmKeysDialog({ account: m.account_id, name: m.name || m.email, fingerprint: m.keys && m.keys.fingerprint, changed: keyState(m) === "changed" },
      (fingerprint) => this.confirmKeys(m.account_id, m.name || m.email, fingerprint));
  }

  async confirmKeys(account, person, fingerprint) {
    const r = await invoke("org_confirm", { org: this.org.id, accountId: account, fingerprint });
    toast(tn("admin.confirmed", (r && r.vaults_updated) || 0, { person: person || account }));
    this.changed();
    return r;
  }

  /**
   * The people an access change left out (`needs_compare`): comparing each one confirms and pins them (`org_confirm`),
   * which gives them their access.
   */
  needsCompare(list) {
    if (!list || !list.length) return;
    const names = {};
    for (const m of (this.data && this.data.members) || []) names[m.account_id] = m.name || m.email || m.account_id;
    openNeedsCompareDialog(list, { names, onCompare: (c, fingerprint) => this.confirmKeys(c.account, names[c.account], fingerprint) });
  }

  changeRole(m) {
    const choices = orgRoleChoices(this.org.role);
    const role = selectOf(choices.map((r) => [r, orgRoleLabel(r, this.org.kind)]), m.role === "owner" ? "admin" : m.role);
    formDialog({
      title: t("admin.change_role_title", { person: m.name || m.email }),
      iconName: "shield",
      body: [labelled(t("admin.role"), role, this.family ? t("admin.role_hint_family") : t("admin.role_hint_team"))],
      onSubmit: async () => {
        await invoke("org_set_role", { org: this.org.id, member: m.member_id, role: role.value });
        toast(t("admin.role_changed", { person: m.name || m.email, role: orgRoleLabel(role.value, this.org.kind) }));
        this.changed();
      },
    });
  }

  memberDepartments(m) {
    const depts = this.data.departments;
    if (!depts.length) {
      toast(t("admin.no_departments_yet"));
      return;
    }
    const boxes = depts.map((d) => ({ d, box: h("input", { type: "checkbox", checked: (m.departments || []).includes(d.id) }) }));
    formDialog({
      title: t("admin.member_departments_title", { person: m.name || m.email }),
      iconName: "users",
      body: [h("div", { class: "col" }, boxes.map(({ d, box }) => h("label", { class: "check" }, box, d.name)))],
      onSubmit: async () => {
        const left = [];
        for (const { d, box } of boxes) {
          const was = (m.departments || []).includes(d.id);
          if (box.checked !== was) {
            const r = await invoke("org_department_member", { org: this.org.id, id: d.id, accountId: m.account_id, add: box.checked });
            left.push(...((r && r.needs_compare) || []));
          }
        }
        toast(t("common.saved"));
        this.changed();
        this.needsCompare(left);
      },
    });
  }

  memberPasswords(m) {
    const settings = (this.data.policies && (this.data.policies.policy_settings || this.data.policies.settings)) || {};
    const person = m.name || m.email;
    const mode = selectOf(memberPasswordChoices(settings.password_mode, passwordModeLabel), m.password_mode || null);
    formDialog({
      title: t("admin.member_passwords_title", { person }),
      iconName: "lock",
      body: [labelled(t("admin.policy_password_mode"), mode, t("admin.member_passwords_hint"))],
      onSubmit: async () => {
        await invoke("org_member_password_mode", { org: this.org.id, member: m.member_id, mode: mode.value || null });
        toast(t("admin.member_passwords_saved", { person }));
        this.changed();
      },
    });
  }

  async offboard(m) {
    const others = this.data.members.filter((x) => x.account_id !== m.account_id);
    const successor = selectOf([[null, t("admin.no_successor")], ...others.map((x) => [x.account_id, x.name || x.email])], null);
    const name = m.name || m.email;
    const result = await formDialog({
      title: this.family ? t("admin.remove_family_title", { person: name }) : t("admin.remove_title", { person: name }),
      iconName: "logOut",
      danger: true,
      submit: t("common.remove"),
      body: [
        h("p", { text: t("admin.remove_text") }),
        labelled(t("admin.successor"), successor, t("admin.successor_hint")),
      ],
      onSubmit: () => invoke("org_offboard", { org: this.org.id, member: m.member_id, accountId: m.account_id, transferTo: successor.value || null }),
    });
    if (!result) return;
    this.changed();
    this.showOffboardResult(name, result);
  }

  showOffboardResult(name, result) {
    const s = offboardSummary(result);
    const m = modal({ label: t("admin.removed_title", { person: name }) });
    const close = h("button", { class: "btn primary", type: "button", text: t("common.done"), on: { click: () => m.close() } });
    mount(m.box,
      h("div", { class: "row" }, h("span", { class: "modal-icon" }, icon("check")), h("h2", { class: "grow", text: t("admin.removed_title", { person: name }) })),
      s.rotated.length
        ? h("div", { class: "banner ok-banner" }, icon("key"), h("span", { class: "grow", text: tn("admin.rotated", s.rotated.length, { vaults: s.rotated.join(", ") }) }))
        : null,
      s.total
        ? h("div", { class: "col" },
            h("div", { class: "section-title", text: tn("admin.change_passwords", s.total) }),
            h("p", { class: "muted", text: t("admin.change_passwords_text", { person: name }) }),
            s.change.map((g) => h("div", { class: "col" },
              h("div", { class: "label", text: g.vault }),
              h("div", { class: "fields" }, g.items.map((it) => h("div", { class: "frow" },
                icon("key"),
                h("div", { class: "value" }, h("div", { text: it.title || t("common.untitled") }), it.username ? h("div", { class: "faint", text: it.username }) : null),
                it.item_id && this.hooks.onOpenItem
                  ? h("div", { class: "actions" }, rowButton(t("common.open"), () => { m.close(); this.hooks.onOpenItem(it.item_id); }))
                  : null))))))
        : h("p", { class: "muted", text: t("admin.change_passwords_none") }),
      s.transfers.length
        ? h("p", { class: "muted", text: tn("admin.transferred", s.transfers.length) })
        : null,
      h("div", { class: "row modal-actions" }, h("span", { class: "spacer" }), close));
    close.focus();
  }

  invite() {
    const email = h("input", { class: "input", type: "email", spellcheck: "false", autocomplete: "off", placeholder: t("admin.email_placeholder") });
    const role = selectOf(orgRoleChoices(this.org.role).map((r) => [r, orgRoleLabel(r, this.org.kind)]), "member");
    const boxes = this.data.departments.map((d) => ({ d, box: h("input", { type: "checkbox" }) }));
    const seats = this.data.overview && this.data.overview.seats;
    formDialog({
      title: this.family ? t("admin.invite_family_title") : t("admin.invite_title"),
      iconName: "userPlus",
      submit: t("admin.send_invite"),
      body: [
        h("p", { class: "muted", text: this.family ? t("admin.invite_family_text") : t("admin.invite_text") }),
        seats && seatsFull(seats) ? h("div", { class: "banner warn" }, icon("alert"), h("span", { class: "grow", text: t("admin.seats_full") })) : null,
        labelled(t("admin.email"), email),
        labelled(t("admin.role"), role),
        boxes.length ? h("div", { class: "field" }, h("span", { class: "label", text: t("admin.departments") }), h("div", { class: "col" }, boxes.map(({ d, box }) => h("label", { class: "check" }, box, d.name)))) : null,
      ],
      onSubmit: async () => {
        const to = email.value.trim();
        if (!validEmail(to)) {
          email.focus();
          throw new Error(t("admin.email_invalid"));
        }
        await invoke("org_invite", { org: this.org.id, email: to, role: role.value, departments: boxes.filter((b) => b.box.checked).map((b) => b.d.id) });
        toast(t("admin.invited", { email: to }));
        this.changed();
      },
    });
  }

  inviteCsv() {
    let csv = "";
    let preview = null;
    const file = h("input", { type: "file", accept: ".csv,text/csv,text/plain", class: "visually-hidden", tabindex: "-1" });
    const name = h("span", { class: "grow ellipsis muted", text: t("send.no_file") });
    const pick = rowButton(t("send.choose_file"), () => file.click());
    const table = h("div", { class: "col" });
    const summary = h("p", { class: "muted", role: "status", "aria-live": "polite" });
    file.addEventListener("change", async () => {
      const f = file.files && file.files[0];
      if (!f) return;
      name.textContent = f.name;
      try {
        csv = await f.text();
      } catch (e) {
        summary.textContent = errorText(e);
        return;
      }
      const rows = csvInviteRows(csv);
      let service = null;
      try {
        service = await invoke("org_invite_csv", { org: this.org.id, csv, dryRun: true });
      } catch (e) {
        summary.textContent = errorText(e);
      }
      preview = csvPreview(rows, service);
      summary.textContent = rows.length ? tn("admin.csv_will_invite", preview.invite, { total: String(rows.length) }) : t("admin.csv_empty");
      mount(table, rows.length
        ? h("div", { class: "teams-table-wrap" }, h("table", { class: "teams-table" },
            h("thead", {}, h("tr", {},
              h("th", { scope: "col", text: t("admin.csv_line") }),
              h("th", { scope: "col", text: t("admin.email") }),
              h("th", { scope: "col", text: t("admin.role") }),
              this.family ? null : h("th", { scope: "col", text: t("admin.departments") }),
              h("th", { scope: "col", text: t("admin.csv_state") }))),
            h("tbody", {}, preview.rows.map((r) => h("tr", { class: r.state === "invite" ? "" : "muted" },
              h("td", { text: String(r.line) }),
              h("td", { class: "selectable", text: r.email }),
              h("td", { text: orgRoleLabel(r.role, this.org.kind) }),
              this.family ? null : h("td", { text: r.departments.join(", ") }),
              h("td", { class: r.state === "invite" ? "" : "warn", text: r.text }))))))
        : null);
    });
    formDialog({
      title: t("admin.csv_title"),
      iconName: "fileText",
      cls: "wide",
      submit: t("admin.csv_submit"),
      body: [
        h("p", { class: "muted", text: this.family ? t("admin.csv_text_family") : t("admin.csv_text") }),
        h("div", { class: "field" }, h("span", { class: "label", text: t("admin.csv_file") }), h("div", { class: "row" }, name, pick, file)),
        summary,
        table,
      ],
      onSubmit: async () => {
        if (!preview || !preview.invite) throw new Error(t("admin.csv_nothing"));
        const r = await invoke("org_invite_csv", { org: this.org.id, csv, dryRun: false });
        const n = r && Number.isFinite(r.invited) ? r.invited : preview.invite;
        toast(tn("admin.csv_invited", n));
        this.changed();
      },
    });
  }

  invitesGroup(invites) {
    if (!invites.length) return null;
    return settingsGroup(t("admin.invites_sent"), invites.map((inv) => settingsRow("mail", inv.email, {
      value: [orgRoleLabel(inv.role, this.org.kind), inv.sent_at ? t("admin.sent_ago", { ago: agoText(inv.sent_at) }) : ""].filter(Boolean).join(" · "),
      control: [
        rowButton(t("admin.cancel_invite"), () => this.run("org_invite_cancel", { inviteId: inv.invite_id }, () => toast(t("admin.invite_cancelled", { email: inv.email })))),
        rowButton(t("admin.resend"), () => this.run("org_invite_resend", { inviteId: inv.invite_id }, () => toast(t("admin.invite_resent", { email: inv.email })))),
      ],
    })));
  }

  departmentsGroup(d) {
    const rows = d.departments.map((dep) => {
      const count = d.members.filter((m) => (m.departments || []).includes(dep.id)).length;
      return settingsRow("users", dep.name, {
        value: tn("teams.members_count", count),
        control: [
          rowButton(t("admin.dept_members"), () => this.departmentMembers(dep)),
          rowButton(t("admin.rename"), () => this.renameDepartment(dep)),
          rowButton(t("common.remove"), async () => {
            const ok = await confirmDialog({ title: t("admin.dept_delete_title", { name: dep.name }), text: t("admin.dept_delete_text"), confirm: t("common.remove"), danger: true });
            if (ok) this.run("org_department_delete", { id: dep.id }, () => toast(t("admin.dept_deleted", { name: dep.name })));
          }),
        ],
      });
    });
    return h("div", { class: "col" },
      settingsGroup(t("admin.departments"), rows.length ? rows : [settingsRow("users", t("admin.no_departments"), { value: t("admin.no_departments_sub") })], { sub: t("admin.departments_sub") }),
      h("div", { class: "row" }, h("span", { class: "spacer" }), rowButton(t("admin.dept_new"), () => this.newDepartment(), "tonal")));
  }

  newDepartment() {
    const name = h("input", { class: "input", maxlength: "80", autocomplete: "off" });
    formDialog({
      title: t("admin.dept_new_title"),
      iconName: "users",
      submit: t("admin.create"),
      body: [labelled(t("admin.dept_name"), name)],
      onSubmit: async () => {
        if (!name.value.trim()) throw new Error(t("admin.name_needed"));
        await invoke("org_department_create", { org: this.org.id, name: name.value.trim() });
        this.changed();
      },
    });
  }

  renameDepartment(dep) {
    const name = h("input", { class: "input", maxlength: "80", autocomplete: "off", value: dep.name });
    formDialog({
      title: t("admin.dept_rename_title", { name: dep.name }),
      iconName: "edit",
      body: [labelled(t("admin.dept_name"), name)],
      onSubmit: async () => {
        if (!name.value.trim()) throw new Error(t("admin.name_needed"));
        await invoke("org_department_rename", { org: this.org.id, id: dep.id, name: name.value.trim() });
        this.changed();
      },
    });
  }

  departmentMembers(dep) {
    const boxes = this.data.members.map((m) => ({ m, box: h("input", { type: "checkbox", checked: (m.departments || []).includes(dep.id) }) }));
    formDialog({
      title: t("admin.dept_members_title", { name: dep.name }),
      iconName: "users",
      body: [h("div", { class: "col teams-checks" }, boxes.map(({ m, box }) => h("label", { class: "check" }, box, m.name || m.email)))],
      onSubmit: async () => {
        const left = [];
        for (const { m, box } of boxes) {
          const was = (m.departments || []).includes(dep.id);
          if (box.checked !== was) {
            const r = await invoke("org_department_member", { org: this.org.id, id: dep.id, accountId: m.account_id, add: box.checked });
            left.push(...((r && r.needs_compare) || []));
          }
        }
        toast(t("common.saved"));
        this.changed();
        this.needsCompare(left);
      },
    });
  }

  vaultsGroup(d) {
    const vaults = (d.overview && d.overview.vaults) || [];
    const rows = vaults.map((v) => settingsRow("folder", vaultName(v), {
      value: accessSummary(v.access, this.org.kind),
      control: [
        rowButton(t("admin.access"), () => this.accessMatrix([v])),
        rowButton(t("common.remove"), async () => {
          const ok = await confirmDialog({ title: t("admin.vault_delete_title", { vault: vaultName(v) }), text: t("admin.vault_delete_text"), confirm: t("common.remove"), danger: true });
          if (ok) this.run("org_vault_delete", { vaultId: vaultId(v) }, () => toast(t("admin.vault_deleted", { vault: vaultName(v) })));
        }),
      ],
    }));
    const suggested = ((d.overview && d.overview.suggested_vaults) || []).filter((s) => !vaults.some((v) => vaultName(v) === (s.label || s.name || s)));
    for (const s of suggested) {
      const label = s.label || s.name || String(s);
      rows.push(settingsRow("plus", t("admin.suggested_vault", { vault: label }), {
        value: this.family ? t("admin.suggested_family_sub") : t("admin.suggested_sub"),
        control: rowButton(t("admin.create"), () => this.run("org_vault_create", { label, access: s.access || [{ everyone: true, role: "edit" }] }, () => toast(t("admin.vault_created", { vault: label }))), "tonal"),
      }));
    }
    return h("div", { class: "col" },
      settingsGroup(t("admin.shared_vaults"), rows.length ? rows : [settingsRow("folder", t("admin.no_vaults"), {})], { sub: this.family ? t("admin.shared_vaults_family_sub") : t("admin.shared_vaults_sub") }),
      h("div", { class: "row wrap" }, h("span", { class: "spacer" }),
        vaults.length > 1 ? rowButton(t("admin.access_matrix"), () => this.accessMatrix(vaults)) : null,
        rowButton(t("admin.vault_new"), () => this.newVault(), "tonal")));
  }

  matrixTable(columns, grants) {
    const subjects = matrixSubjects({ members: this.data.members, departments: this.data.departments, kind: this.org.kind });
    const selects = [];
    const table = h("table", { class: "teams-table matrix" },
      h("thead", {}, h("tr", {},
        h("th", { scope: "col", text: t("admin.matrix_who") }),
        columns.map((c) => h("th", { scope: "col", text: c.name })))),
      h("tbody", {}, subjects.map((s) => h("tr", {},
        h("th", { scope: "row" }, h("div", { text: s.label }), s.sub ? h("div", { class: "faint", text: s.sub }) : null),
        columns.map((c) => {
          const sel = h("select", { class: "input small-select", "aria-label": t("admin.matrix_cell", { who: s.label, vault: c.name }) },
            h("option", { value: "", text: t("admin.no_access") }),
            ROLES.map((r) => h("option", { value: r, text: roleLabel(r) })));
          sel.value = grantRole(grants[c.id], s.key) || "";
          selects.push({ sel, key: s.key, column: c.id });
          return h("td", {}, sel);
        })))));
    const read = () => {
      const out = {};
      for (const c of columns) out[c.id] = grants[c.id] || [];
      for (const { sel, key, column } of selects) out[column] = setGrant(out[column], key, sel.value || null);
      return out;
    };
    return { el: h("div", { class: "teams-table-wrap" }, table), read };
  }

  accessMatrix(vaults) {
    const columns = vaults.map((v) => ({ id: vaultId(v), name: vaultName(v) }));
    const before = {};
    for (const v of vaults) before[vaultId(v)] = v.access || [];
    const matrix = this.matrixTable(columns, before);
    formDialog({
      title: vaults.length === 1 ? t("admin.access_title", { vault: vaultName(vaults[0]) }) : t("admin.access_matrix"),
      iconName: "users",
      cls: "wide",
      body: [h("p", { class: "muted", text: t("admin.access_text") }), matrix.el, h("p", { class: "faint", text: t("admin.access_rotation_note") })],
      onSubmit: async () => {
        const changes = changedAccess(before, matrix.read());
        const left = [];
        for (const c of changes) {
          const r = await invoke("org_vault_access", { org: this.org.id, vaultId: c.vaultId, access: c.access });
          left.push(...((r && r.needs_compare) || []));
        }
        if (changes.length) toast(tn("admin.access_saved", changes.length));
        this.changed();
        this.needsCompare(left);
      },
    });
  }

  newVault() {
    const label = h("input", { class: "input", maxlength: "80", autocomplete: "off" });
    const matrix = this.matrixTable([{ id: "new", name: t("admin.vault_new_column") }], { new: [] });
    formDialog({
      title: t("admin.vault_new_title"),
      iconName: "folder",
      cls: "wide",
      submit: t("admin.create"),
      body: [labelled(t("admin.vault_label"), label), h("div", { class: "label", text: t("admin.vault_new_access") }), matrix.el],
      onSubmit: async () => {
        const name = label.value.trim();
        if (!name) {
          label.focus();
          throw new Error(t("admin.name_needed"));
        }
        const r = await invoke("org_vault_create", { org: this.org.id, label: name, access: matrix.read().new });
        toast(t("admin.vault_created", { vault: name }));
        this.changed();
        this.needsCompare(r && r.needs_compare);
      },
    });
  }

  policiesGroup(p) {
    // Edited under the service's stored names (`policy_settings`); `policy` is the core's view.
    const settings = (p && (p.policy_settings || p.settings)) || {};
    const kind = this.org.kind;
    const values = policyForm(settings, kind);
    const controls = {};
    const rows = [];
    const editable = this.org.role === "owner" || this.org.role === "admin";
    const switches = {
      strong_master_password: ["lock", t("admin.policy_strong_master"), t("admin.policy_strong_master_info")],
      export_allowed: ["upload", t("admin.policy_export"), t("admin.policy_export_info")],
      share_outside: this.family
        ? ["share", t("admin.policy_outside_family"), t("admin.policy_outside_family_info")]
        : ["share", t("admin.policy_outside"), t("admin.policy_outside_info")],
      sso_required: ["key", t("admin.policy_sso"), t("admin.policy_sso_info")],
      device_approval: ["monitor", t("admin.policy_device_approval"), t("admin.policy_device_approval_info")],
      send_allowed: ["send", t("admin.policy_send"), t("admin.policy_send_info")],
      emergency_allowed: ["lifeBuoy", t("admin.policy_emergency"), t("admin.policy_emergency_info")],
      admin_recovery: ["lifeBuoy", t("admin.policy_admin_recovery"), t("admin.policy_admin_recovery_info")],
    };
    const ssoOn = ssoReady(p, this.data && this.data.overview, this.org);
    for (const key of policyFields(kind)) {
      if (key === "sso_required" && !ssoOn) {
        // No working connection yet: no switch (it is left out of the saved change too).
        rows.push(settingsRow("key", t("admin.policy_sso_not_ready"), {}));
        continue;
      }
      if (key === "min_password_score") {
        const sel = selectOf([[0, t("admin.policy_strength_any")], [2, strengthName(2)], [3, strengthName(3)], [4, strengthName(4)]], values[key], { id: "pol-strength", disabled: !editable });
        controls[key] = () => Number(sel.value);
        rows.push(settingsRow("lock", t("admin.policy_strength"), { id: "pol-strength", control: sel, info: t("admin.policy_strength_info") }));
      } else if (key === "sign_in") {
        const names = { any: t("admin.policy_sign_in_any"), strong: t("admin.policy_sign_in_strong"), passkey: t("admin.policy_sign_in_passkey") };
        const sel = selectOf(SIGN_IN_RULES.map((r) => [r, names[r]]), values[key], { id: "pol-sign-in", disabled: !editable });
        controls[key] = () => sel.value;
        rows.push(settingsRow("shield", t("admin.policy_sign_in"), { id: "pol-sign-in", control: sel, info: t("admin.policy_sign_in_info") }));
      } else if (key === "max_auto_lock_minutes") {
        const sel = selectOf(MAX_AUTO_LOCK.map((m) => [m, m === null ? t("admin.policy_no_limit") : durationText(m)]), values[key], { id: "pol-lock", disabled: !editable });
        controls[key] = () => (sel.value ? Number(sel.value) : null);
        rows.push(settingsRow("timer", t("admin.policy_auto_lock"), { id: "pol-lock", control: sel, info: t("admin.policy_auto_lock_info") }));
      } else if (key === "password_mode") {
        const sel = selectOf(PASSWORD_MODES.map((m) => [m, passwordModeLabel(m)]), values[key], { id: "pol-passwords", disabled: !editable });
        controls[key] = () => sel.value;
        rows.push(settingsRow("key", t("admin.policy_password_mode"), { id: "pol-passwords", control: sel, info: t("admin.policy_password_mode_info") }));
      } else {
        const sw = toggle(!!values[key]);
        sw.disabled = !editable;
        controls[key] = () => sw.checked;
        const [iconName, title, info] = switches[key];
        rows.push(settingsRow(iconName, title, { control: sw, info }));
      }
    }
    const save = rowButton(t("admin.policy_save"), async () => {
      const form = {};
      for (const [key, read] of Object.entries(controls)) form[key] = read();
      const change = policyChange(settings, form, kind);
      if (!Object.keys(change).length) {
        toast(t("settings.no_changes"));
        return;
      }
      save.disabled = true;
      await this.run("org_policies_set", { change }, () => toast(t("admin.policy_saved")));
      save.disabled = false;
    }, "tonal");
    return h("div", { class: "col" },
      settingsGroup(t("admin.policies"), rows, { sub: this.family ? t("admin.policies_family_sub") : t("admin.policies_sub") }),
      editable ? h("div", { class: "row" }, h("span", { class: "spacer" }), save) : null);
  }

  recoveryGroup() {
    const card = h("div", { class: "set-rows" }, settingsRow("clock", t("common.loading"), {}));
    invoke("org_admin_recovery_requests", { org: this.org.id })
      .then((list) => {
        if (this.destroyed) return;
        const reqs = Array.isArray(list) ? list : (list && list.requests) || [];
        mount(card, reqs.length
          ? reqs.map((r) => settingsRow("lifeBuoy", r.name || r.email || r.account, {
              value: [r.at || r.created_at ? t("admin.recovery_asked", { ago: agoText(r.at || r.created_at) }) : "", r.fingerprint ? fingerprintText(r.fingerprint) : "",
                String((r.request && r.request.vault_id) || r.vault_id || "").startsWith("ak:") ? t("account_admin.request_account_key") : ""].filter(Boolean).join(" · "),
              control: rowButton(t("emergency.approve"), async () => {
                if (await this.approveRecovery(r)) this.changed();
              }, "tonal"),
            }))
          : settingsRow("lifeBuoy", t("admin.recovery_none"), {}));
      })
      .catch(() => mount(card, settingsRow("lifeBuoy", t("admin.recovery_none"), {})));
    return settingsGroup(t("admin.recovery"), card, { info: t("admin.recovery_info") });
  }

  /**
   * Approve a member's recovery request with the code they read out: the admin calls them and types it here. The code
   * is never worked out or filled in on this side: a service that swapped the request's key shows an admin a request
   * the member's code doesn't match, and nothing is approved. Resolves true once approved.
   */
  approveRecovery(r) {
    const person = r.name || r.email || r.account;
    const code = h("input", { class: "input mono", spellcheck: "false", autocomplete: "off", placeholder: t("teams.confirm_typed_placeholder") });
    return formDialog({
      title: t("admin.recovery_approve_title", { person }),
      iconName: "lifeBuoy",
      submit: t("emergency.approve"),
      body: [
        h("p", { text: t("admin.recovery_code_text", { person }) }),
        labelled(t("admin.recovery_code_label", { person }), code),
        h("p", { class: "muted", text: t("admin.recovery_approve_text") }),
      ],
      onSubmit: async () => {
        if (!code.value.trim()) {
          code.focus();
          throw new Error(t("errors.admin_recovery_code_needed"));
        }
        await invoke("org_admin_recovery_approve", { org: this.org.id, requestId: r.request_id || r.id, code: code.value });
        toast(t("admin.recovery_approved"));
        return true;
      },
    });
  }

  transfersGroup(o) {
    const list = (o && o.transfers) || [];
    if (!list.length) return null;
    return settingsGroup(t("admin.transfers"), list.map((x) => settingsRow("swap", x.title || x.vault || x.name || "", {
      value: [x.from ? t("admin.transfer_from", { person: x.from }) : "", x.to ? t("admin.transfer_to", { person: x.to }) : "", x.state || ""].filter(Boolean).join(" · "),
    })));
  }

  activityGroup() {
    this.activityCard = h("div", { class: "set-rows" });
    this.moreBtn = rowButton(t("admin.activity_more"), () => this.loadActivity(this.next));
    this.paintActivity();
    return h("div", { class: "col" },
      settingsGroup(t("admin.activity"), this.activityCard, { sub: t("admin.activity_sub") }),
      h("div", { class: "row" }, h("span", { class: "spacer" }), this.moreBtn));
  }

  paintActivity() {
    if (!this.activityCard) return;
    mount(this.activityCard, this.events.length
      ? this.events.map((e) => settingsRow("history", activityText(e), { value: e.at ? formatDateTime(e.at) : null }))
      : settingsRow("history", this.activityLoaded ? t("admin.activity_none") : t("common.loading"), {}));
    this.moreBtn.hidden = !this.next;
  }

  async loadActivity(before = null) {
    try {
      const r = await invoke("org_activity", { org: this.org.id, before });
      if (this.destroyed) return;
      this.events = before ? [...this.events, ...(r.events || [])] : r.events || [];
      this.next = r.next || null;
    } catch (e) {
      if (before) this.failed(e);
    }
    this.activityLoaded = true;
    this.paintActivity();
  }
}

export function popupMenu(entries, anchor, label) {
  const menu = h("div", { class: "menu", role: "menu", "aria-label": label });
  const close = () => {
    document.removeEventListener("mousedown", outside, true);
    menu.remove();
    if (anchor && anchor.isConnected) anchor.focus({ preventScroll: true });
  };
  const outside = (e) => { if (!menu.contains(e.target)) close(); };
  for (const [iconName, text, fn, cls] of entries) {
    menu.append(h("button", { class: `menu-item ${cls || ""}`.trim(), type: "button", role: "menuitem", on: { click: () => { close(); fn(); } } }, icon(iconName), text));
  }
  menu.addEventListener("keydown", (e) => {
    const items = [...menu.querySelectorAll(".menu-item")];
    const i = items.indexOf(document.activeElement);
    if (e.key === "ArrowDown") { e.preventDefault(); items[(i + 1) % items.length].focus(); }
    else if (e.key === "ArrowUp") { e.preventDefault(); items[(i - 1 + items.length) % items.length].focus(); }
    else if (e.key === "Escape" || e.key === "Tab") { e.preventDefault(); e.stopPropagation(); close(); }
  });
  document.body.append(menu);
  const r = anchor.getBoundingClientRect();
  const m = menu.getBoundingClientRect();
  menu.style.left = `${Math.max(8, Math.min(r.right - m.width, window.innerWidth - m.width - 8))}px`;
  menu.style.top = `${r.bottom + m.height + 8 > window.innerHeight ? Math.max(8, r.top - m.height - 4) : r.bottom + 4}px`;
  document.addEventListener("mousedown", outside, true);
  const first = menu.querySelector(".menu-item");
  if (first) first.focus();
}
