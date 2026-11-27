// The pure part of the admin and family manager screens (teams-admin.js). No DOM and no Tauri.
//
// `Grant`: `{ account, role }` | `{ department, role }` | `{ everyone: true, role }`, role "manage" |
// "edit" | "view" | "fill".

import { formatNumber, t, tn } from "../i18n.js";
import { ROLES } from "./teams-model.js";

export function seatsText(seats) {
  if (!seats) return "";
  const used = Number(seats.used) || 0;
  if (seats.total === null || seats.total === undefined) return tn("admin.seats_used", used);
  return t("admin.seats_of", { used: formatNumber(used), total: formatNumber(Number(seats.total) || 0) });
}

export function seatsFull(seats) {
  return !!seats && seats.total !== null && seats.total !== undefined && Number(seats.used) >= Number(seats.total);
}

/** The organisation roles `myRole` may give: an owner gives admin or member, an admin member or admin. */
export function orgRoleChoices(myRole) {
  if (myRole === "owner" || myRole === "admin") return ["admin", "member"];
  return [];
}

/**
 * A member's key state: "confirmed", "to_confirm" (an admin compares the fingerprint), "to_compare"
 * (confirmed by the service, not yet compared on this device), "changed" (other keys than the ones
 * compared: a loud warning) or "no_keys".
 */
export function keyState(member) {
  const k = (member && member.keys) || {};
  const pin = member && member.pin;
  if (pin === "changed") return "changed";
  if (k.confirmed) return pin === "not_verified" ? "to_compare" : "confirmed";
  if (k.published || k.fingerprint) return "to_confirm";
  return "no_keys";
}

export const COMPARE_STATES = ["to_confirm", "to_compare", "changed"];

/**
 * What the signed-in manager can do with `member`. Nobody removes or demotes themselves here, and an
 * admin can't change or remove the owner. A family has no departments or password rules.
 */
export function memberActions(member, { me, myRole, kind = "team" } = {}) {
  if (!member || (myRole !== "owner" && myRole !== "admin")) return [];
  const actions = [];
  const self = me && member.account_id === me;
  if (COMPARE_STATES.includes(keyState(member))) actions.push("confirm");
  const protectedOwner = member.role === "owner" && myRole !== "owner";
  if (!self && !protectedOwner && member.role !== "owner") actions.push("role");
  if (kind !== "family") actions.push("departments");
  if (kind !== "family" && !protectedOwner && (member.status || "active") === "active") actions.push("passwords");
  if (myRole === "owner" && !self && member.role === "admin" && (member.status || "active") === "active") actions.push("make_owner");
  if (!self && !protectedOwner) actions.push("remove");
  return actions;
}

export function validEmail(text) {
  return /^[^\s@,;<>"]+@[^\s@,;<>"]+\.[^\s@,;<>"]+$/.test(String(text || "").trim());
}

/** Splits CSV text into rows of cells: quotes, "" inside quotes, commas or semicolons, CRLF. */
export function parseCsv(text) {
  const src = String(text || "").replace(/^﻿/, "");
  // The separator: a semicolon when the first line has more of them than commas (European Excel).
  const firstLine = src.split(/\r?\n/, 1)[0] || "";
  const sep = (firstLine.match(/;/g) || []).length > (firstLine.match(/,/g) || []).length ? ";" : ",";
  const rows = [];
  let row = [];
  let cell = "";
  let quoted = false;
  for (let i = 0; i < src.length; i++) {
    const c = src[i];
    if (quoted) {
      if (c === '"' && src[i + 1] === '"') {
        cell += '"';
        i++;
      } else if (c === '"') {
        quoted = false;
      } else {
        cell += c;
      }
    } else if (c === '"' && cell === "") {
      quoted = true;
    } else if (c === sep) {
      row.push(cell.trim());
      cell = "";
    } else if (c === "\n" || c === "\r") {
      if (c === "\r" && src[i + 1] === "\n") i++;
      row.push(cell.trim());
      rows.push(row);
      row = [];
      cell = "";
    } else {
      cell += c;
    }
  }
  if (cell !== "" || row.length) {
    row.push(cell.trim());
    rows.push(row);
  }
  return rows.filter((r) => r.some((c) => c !== ""));
}

const HEADERS = {
  email: /^(e-?mail( address)?|mail|address)$/i,
  name: /^(name|full ?name|display ?name)$/i,
  role: /^(role|org ?role)$/i,
  departments: /^(departments?|groups?|teams?)$/i,
};

/** Reads invite rows from CSV text: a header row names the columns, else the first column holding an address is the e-mail. */
export function csvInviteRows(text) {
  const rows = parseCsv(text);
  if (!rows.length) return [];
  const header = rows[0].map((c) => c.trim());
  const cols = {};
  header.forEach((c, i) => {
    for (const [key, re] of Object.entries(HEADERS)) if (cols[key] === undefined && re.test(c)) cols[key] = i;
  });
  const hasHeader = cols.email !== undefined;
  const body = hasHeader ? rows.slice(1) : rows;
  if (!hasHeader) {
    const idx = rows[0].findIndex((c) => validEmail(c));
    cols.email = idx >= 0 ? idx : 0;
  }
  const seen = new Set();
  return body.map((r, i) => {
    const email = (r[cols.email] || "").trim();
    const roleRaw = cols.role !== undefined ? (r[cols.role] || "").trim().toLowerCase() : "";
    const departments = cols.departments !== undefined
      ? (r[cols.departments] || "").split(/[|,]/).map((d) => d.trim()).filter(Boolean)
      : [];
    const key = email.toLowerCase();
    let problem = "";
    if (!validEmail(email)) problem = "invalid_email";
    else if (seen.has(key)) problem = "duplicate";
    seen.add(key);
    return {
      line: i + 1 + (hasHeader ? 1 : 0),
      email,
      name: cols.name !== undefined ? (r[cols.name] || "").trim() : "",
      role: roleRaw === "admin" ? "admin" : "member",
      departments,
      problem,
    };
  });
}

/** The preview: the rows read here merged with the service's dry run (`org_invite_csv`). */
export function csvPreview(localRows, service = null) {
  const byEmail = new Map();
  for (const r of (service && service.rows) || []) byEmail.set(String(r.email || "").toLowerCase(), r);
  const rows = localRows.map((r) => {
    const s = byEmail.get(r.email.toLowerCase());
    const state = r.problem || (s && s.state) || "invite";
    return { ...r, state, text: (s && s.message) || csvStateText(state) };
  });
  return { rows, invite: rows.filter((r) => r.state === "invite").length };
}

export function csvStateText(state) {
  switch (state) {
    case "invite":
      return t("admin.csv_state_invite");
    case "exists":
      return t("admin.csv_state_exists");
    case "invited":
      return t("admin.csv_state_invited");
    case "invalid_email":
    case "invalid":
      return t("admin.csv_state_invalid");
    case "duplicate":
      return t("admin.csv_state_duplicate");
    case "over_seats":
      return t("admin.csv_state_over_seats");
    default:
      return String(state || "");
  }
}

/** A Grant's subject as a key: "account:<id>", "department:<id>", "everyone". */
export function grantKey(grant) {
  if (!grant) return "";
  if (grant.everyone) return "everyone";
  if (grant.department !== undefined && grant.department !== null) return `department:${grant.department}`;
  return `account:${grant.account}`;
}

/** The subject of a key, as a Grant without its role. */
export function subjectOf(key) {
  if (key === "everyone") return { everyone: true };
  const at = key.indexOf(":");
  const kind = key.slice(0, at);
  const id = key.slice(at + 1);
  return kind === "department" ? { department: id } : { account: id };
}

/** The role `key` has in `grants`, or null. */
export function grantRole(grants, key) {
  const g = (grants || []).find((x) => grantKey(x) === key);
  return g && ROLES.includes(g.role) ? g.role : null;
}

/** `grants` with `key` set to `role` (null removes it); the order of the others is kept. */
export function setGrant(grants, key, role) {
  const rest = (grants || []).filter((g) => grantKey(g) !== key);
  if (!role) return rest;
  const at = (grants || []).findIndex((g) => grantKey(g) === key);
  const next = { ...subjectOf(key), role };
  if (at < 0) return [...rest, next];
  const out = [...rest];
  out.splice(at, 0, next);
  return out;
}

export function matrixSubjects({ members = [], departments = [], kind = "team" } = {}) {
  const rows = [{ key: "everyone", label: kind === "family" ? t("admin.everyone_family") : t("admin.everyone_team"), sub: "" }];
  if (kind !== "family") {
    for (const d of departments) rows.push({ key: `department:${d.id}`, label: d.name, sub: t("admin.department") });
  }
  for (const m of members) rows.push({ key: `account:${m.account_id}`, label: m.name || m.email || m.account_id, sub: m.name ? m.email || "" : "" });
  return rows;
}

export function changedAccess(before, after) {
  const norm = (grants) => JSON.stringify([...(grants || [])].map((g) => `${grantKey(g)}=${g.role}`).sort());
  const out = [];
  for (const [vaultId, access] of Object.entries(after || {})) {
    if (norm((before || {})[vaultId]) !== norm(access)) out.push({ vaultId, access });
  }
  return out;
}

export function accessSummary(grants, kind = "team") {
  const list = grants || [];
  const everyone = list.find((g) => g.everyone);
  const people = list.filter((g) => !g.everyone && g.account !== undefined && g.department === undefined).length;
  const depts = list.filter((g) => g.department !== undefined && g.department !== null).length;
  const parts = [];
  if (everyone) parts.push(kind === "family" ? t("admin.access_everyone_family") : t("admin.access_everyone_team"));
  if (depts) parts.push(tn("admin.access_departments", depts));
  if (people) parts.push(tn("admin.access_members", people));
  return parts.length ? parts.join(", ") : t("admin.access_none");
}

/** The policy rules an organisation edits, under their `PUT .../policies` names: a Family has two, a Team all of them. */
export function policyFields(kind) {
  return kind === "family"
    ? ["strong_master_password", "share_outside"]
    : [
        "min_password_score",
        "sign_in",
        "max_auto_lock_minutes",
        "export_allowed",
        "share_outside",
        "sso_required",
        "device_approval",
        "send_allowed",
        "emergency_allowed",
        "admin_recovery",
        "password_mode",
      ];
}

export const PASSWORD_MODES = ["choice", "second_password", "one_password"];

/** The choices for one member's password mode: the team's rule (`null`) first, then the three modes. */
export function memberPasswordChoices(teamMode, label) {
  const team = PASSWORD_MODES.includes(teamMode) ? teamMode : "choice";
  return [[null, t("admin.password_mode_team", { mode: label(team) })], ...PASSWORD_MODES.map((m) => [m, label(m)])];
}

/** Whether the Team's single sign-on works; the first source that carries `sso` decides. */
export function ssoReady(...sources) {
  for (const src of sources) {
    if (src && typeof src === "object" && src.sso && typeof src.sso === "object") return src.sso.ready === true;
  }
  return false;
}

export const SIGN_IN_RULES = ["any", "strong", "passkey"];

const ON_BY_DEFAULT = new Set(["export_allowed", "send_allowed"]);

/** The form's values from the service's `policy_settings`; a Family's strong master password is a score of 3 or more. */
export function policyForm(settings, kind) {
  const s = settings || {};
  const form = {};
  for (const key of policyFields(kind)) {
    if (key === "strong_master_password") form[key] = (Number(s.min_password_score) || 0) >= 3;
    else if (key === "min_password_score") form[key] = Number(s[key]) || 0;
    else if (key === "sign_in") form[key] = SIGN_IN_RULES.includes(s[key]) ? s[key] : "any";
    else if (key === "max_auto_lock_minutes") form[key] = Number(s[key]) > 0 ? Number(s[key]) : null;
    else if (key === "password_mode") form[key] = PASSWORD_MODES.includes(s[key]) ? s[key] : "choice";
    else form[key] = key in s ? !!s[key] : ON_BY_DEFAULT.has(key);
  }
  return form;
}

/** What changed between the stored policy and the form, as `org_policies_set`'s `change` (a cleared auto-lock limit is 0). */
export function policyChange(settings, form, kind) {
  const before = policyForm(settings, kind);
  const change = {};
  for (const key of policyFields(kind)) {
    if (!(key in (form || {}))) continue;
    const after = form[key] ?? null;
    if ((before[key] ?? null) === after) continue;
    change[key] = key === "max_auto_lock_minutes" && after === null ? 0 : after;
  }
  return change;
}

export const MAX_AUTO_LOCK = [null, 5, 15, 30, 60, 240];

/** After removing someone: the "change the passwords they could see" items grouped by vault. */
export function offboardSummary(result) {
  const r = result || {};
  const groups = new Map();
  for (const item of r.change_passwords || []) {
    const vault = item.vault || "";
    if (!groups.has(vault)) groups.set(vault, []);
    groups.get(vault).push(item);
  }
  return {
    rotated: r.rotated || [],
    change: [...groups.entries()].map(([vault, items]) => ({ vault, items })),
    transfers: r.transfers || [],
    total: (r.change_passwords || []).length,
  };
}

/** An activity event as a sentence; unknown actions show their detail or the action name. */
export function activityText(e) {
  const actor = e.actor || t("admin.activity_someone");
  const target = e.target || "";
  switch (e.action) {
    case "member.invited":
      return t("admin.act_invited", { actor, target });
    case "member.joined":
      return t("admin.act_joined", { actor });
    case "member.confirmed":
      return t("admin.act_confirmed", { actor, target });
    case "member.removed":
      return t("admin.act_removed", { actor, target });
    case "member.left":
      return t("admin.act_left", { actor });
    case "member.role_changed":
      return t("admin.act_role_changed", { actor, target });
    case "vault.created":
      return t("admin.act_vault_created", { actor, target });
    case "vault.deleted":
      return t("admin.act_vault_deleted", { actor, target });
    case "vault.access_changed":
      return t("admin.act_access_changed", { actor, target });
    case "vault.rotated":
      return t("admin.act_rotated", { target });
    case "policy.changed":
      return t("admin.act_policy_changed", { actor });
    case "department.created":
      return t("admin.act_department_created", { actor, target });
    case "department.deleted":
      return t("admin.act_department_deleted", { actor, target });
    case "recovery.approved":
      return t("admin.act_recovery_approved", { actor, target });
    default:
      return e.detail || [actor, e.action, target].filter(Boolean).join(" ");
  }
}
