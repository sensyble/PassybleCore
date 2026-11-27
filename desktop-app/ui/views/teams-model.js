// Pure member-side logic for Teams and Family (views/teams.js, shared vaults in the vault view, Settings' policy
// rules): roles, an item's vault, sync states, notifications, fingerprints, policy checks, secure send and emergency
// access texts. No DOM and no Tauri (unit-tested in test/teams-model.test.mjs).
//
// Data shapes are the Tauri commands': `VaultRef` `{ id, name, home, kind: "personal" | "org" |
// "direct", role: "manage" | "edit" | "view" | "fill" | null, can_edit, can_reveal }`, items with `vault_id` and `vault`.

import { formatDate, t, tn } from "../i18n.js";

export const ROLES = ["manage", "edit", "view", "fill"];

export function roleLabel(role) {
  switch (role) {
    case "manage":
      return t("teams.role_manage");
    case "edit":
      return t("teams.role_edit");
    case "view":
      return t("teams.role_view");
    case "fill":
      return t("teams.role_fill");
    default:
      return "";
  }
}

export function roleHint(role) {
  switch (role) {
    case "manage":
      return t("teams.role_manage_hint");
    case "edit":
      return t("teams.role_edit_hint");
    case "view":
      return t("teams.role_view_hint");
    case "fill":
      return t("teams.role_fill_hint");
    default:
      return "";
  }
}

export function orgRoleLabel(role, kind = "team") {
  switch (role) {
    case "owner":
      return t("teams.org_role_owner");
    case "admin":
      return kind === "family" ? t("teams.org_role_manager") : t("teams.org_role_admin");
    case "member":
      return t("teams.org_role_member");
    default:
      return "";
  }
}

export function isOrgManager(role) {
  return role === "owner" || role === "admin";
}

export function orgKindLabel(kind) {
  return kind === "family" ? t("teams.kind_family") : t("teams.kind_team");
}

export function vaultKindLabel(kind, orgKind = null) {
  if (kind === "direct") return t("teams.vault_kind_direct");
  if (kind === "personal") return t("teams.vault_kind_personal");
  if (kind === "emergency") return t("teams.vault_kind_emergency");
  return orgKind === "family" ? t("teams.vault_kind_family") : t("teams.vault_kind_team");
}

export function itemVaultId(item) {
  if (!item) return null;
  if (item.vault_id) return item.vault_id;
  return item.vault && item.vault.id ? item.vault.id : null;
}

/**
 * What the user may do with an item: `edit`, `reveal` (show and copy secrets, history, copy to another vault),
 * `readOnly` (view and fill), `fillOnly` (filled, never shown). An item without a vault allows everything.
 */
export function itemCaps(item) {
  const vault = item && item.vault;
  const fillOnly = !!(item && item.password_hidden) || !!(vault && vault.can_reveal === false);
  const readOnly = fillOnly || !!(vault && vault.can_edit === false) || !!(item && item.read_only);
  return { edit: !readOnly, reveal: !fillOnly, readOnly, fillOnly, role: (vault && vault.role) || null };
}

export function itemRoleNote(item) {
  const caps = itemCaps(item);
  if (caps.fillOnly) return t("teams.item_fill_only");
  if (caps.readOnly) return t("teams.item_view_only");
  return "";
}

export function vaultRoleNote(vault) {
  const caps = itemCaps({ vault });
  if (caps.fillOnly) return t("teams.item_fill_only");
  return caps.readOnly ? t("teams.vault_view_only") : "";
}

export function showVaultNames(vaults) {
  return Array.isArray(vaults) && vaults.length > 1;
}

export function filterByVault(items, vaultId) {
  if (!vaultId) return items;
  return items.filter((i) => itemVaultId(i) === vaultId);
}

export function validVaultFilter(vaultId, vaults) {
  if (!vaultId) return null;
  return (vaults || []).some((v) => v.id === vaultId) ? vaultId : null;
}

export function saveVaultChoices(vaults) {
  const editable = (vaults || []).filter((v) => v && v.can_edit !== false);
  return [...editable.filter((v) => v.home), ...editable.filter((v) => !v.home)];
}

/** The "Save in" vault for a new item: the list's filter vault if editable, else the backend's default, else home, else the first editable. */
export function defaultSaveVault(vaults, filterId = null) {
  const choices = saveVaultChoices(vaults);
  if (!choices.length) return null;
  const filtered = filterId && choices.find((v) => v.id === filterId);
  if (filtered) return filtered.id;
  const marked = choices.find((v) => v.default);
  if (marked) return marked.id;
  return (choices.find((v) => v.home) || choices[0]).id;
}

/**
 * Where "Move to vault" / "Copy to vault" can put `item`: other editable vaults, except a Team's vaults while its password
 * rules turn sharing off (`blocked`). Moving needs the item's own vault editable, copying needs its secrets visible.
 * `[]`: the action isn't offered.
 */
export function shareTargets(item, vaults, mode = "move", blocked = []) {
  const caps = itemCaps(item);
  if (mode === "move" && !caps.edit) return [];
  if (!caps.reveal) return [];
  const from = itemVaultId(item);
  const off = new Set(blocked || []);
  return saveVaultChoices(vaults).filter((v) => v.id !== from && !off.has(v.id));
}

/** A message for a shared vault's status code (`teams_errors`), or the server's text. */
export function linkedErrorText(error) {
  if (!error) return "";
  switch (error.code) {
    case "no_keyset":
      return t("teams.error_no_keyset");
    case "not_a_member":
      return t("teams.error_not_a_member");
    case "keys_mismatch":
      return t("teams.error_keys_mismatch");
    case "untrusted":
      return t("teams.error_untrusted");
    case "rollback":
      return t("teams.error_rollback");
    case "read_only_member":
      return t("teams.error_read_only_member");
    case "subscription_inactive":
      return t("teams.error_subscription_inactive");
    case "account_suspended":
      return t("teams.error_account_suspended");
    case "network":
      return t("teams.error_network");
    default:
      return error.message || t("teams.error_internal");
  }
}

/** Codes that are a state the user can live with (the vault still opens), not a failure. */
const QUIET_ERRORS = new Set(["read_only_member", "subscription_inactive"]);

/** A shared vault's state: `{ text, cls }` with `cls` "warn" for a problem. `ago(ms)` words a time. */
export function linkedState(v, ago = (ms) => formatDate(ms)) {
  if (v && v.error && !QUIET_ERRORS.has(v.error.code)) return { text: linkedErrorText(v.error), cls: "warn" };
  if (v && v.error) return { text: linkedErrorText(v.error), cls: "" };
  if (!v || !v.open) return { text: t("teams.not_opened"), cls: "" };
  if (v.last_sync_ms) return { text: t("teams.synced_ago", { ago: ago(v.last_sync_ms) }), cls: "" };
  return { text: t("teams.not_synced_yet"), cls: "" };
}

export function sharedVaultLine(v, ago) {
  const parts = [];
  const role = roleLabel(v.my_role || (v.vault && v.vault.role));
  if (role) parts.push(role);
  if (Number.isFinite(v.members_count)) parts.push(tn("teams.members_count", v.members_count));
  const state = linkedState(v, ago);
  if (state.text) parts.push(state.text);
  return { text: parts.join(" · "), cls: state.cls };
}

export function needsTrust(v) {
  return !!(v && v.error && v.error.code === "untrusted");
}

/**
 * What the user's pinned contact keys say about the manager who signed a shared vault's members list:
 * `{ state, text, cls }`, `state` "verified", "not_verified", "changed" (loud warning) or null.
 */
export function signerState(v) {
  switch (v && v.signer_status) {
    case "pinned":
      return { state: "verified", text: t("contacts.verified"), cls: "ok" };
    case "not_verified":
      return { state: "not_verified", text: t("contacts.not_verified"), cls: "warn" };
    case "changed":
      return { state: "changed", text: t("contacts.changed_short"), cls: "warn danger" };
    default:
      return { state: null, text: "", cls: "" };
  }
}

/** The people a command left out until compared (`needs_compare`), changed keys first. */
export function compareList(needs) {
  const list = (Array.isArray(needs) ? needs : needs ? [needs] : []).filter((c) => c && c.account && c.fingerprint);
  return [...list].sort((a, b) => (b.status === "changed") - (a.status === "changed"));
}

/** The notifications in the order they need the user: `[{ kind, title, items }]`, empty groups left out. */
export function notificationGroups(n) {
  const src = n || {};
  const groups = [
    { kind: "confirm", title: t("teams.notif_confirm"), items: src.confirm || [] },
    { kind: "shared", title: t("teams.notif_shared"), items: src.shared_with_you || [] },
    { kind: "waiting", title: t("teams.notif_waiting"), items: src.waiting_for_confirmation || [] },
    { kind: "removed", title: t("teams.notif_removed"), items: src.removed || [] },
  ];
  return groups.filter((g) => g.items.length > 0);
}

export function notificationText(kind, entry, when = (ms) => formatDate(ms)) {
  const at = (ms) => (ms ? when(ms) : "");
  switch (kind) {
    case "confirm":
      return { title: t("teams.notif_confirm_line", { account: entry.account, vault: entry.vault_name }), sub: at(entry.since) };
    case "shared":
      return {
        title: t("teams.notif_shared_line", { name: entry.name, by: entry.by }),
        sub: [roleLabel(entry.role), at(entry.at)].filter(Boolean).join(" · "),
      };
    case "waiting":
      return { title: t("teams.notif_waiting_line", { name: entry.name }), sub: at(entry.since) };
    case "removed":
      return { title: t("teams.notif_removed_line", { name: entry.name, by: entry.by }), sub: at(entry.at) };
    default:
      return { title: "", sub: "" };
  }
}

export function attentionCount(overview) {
  if (!overview || !overview.visible) return 0;
  const n = overview.notifications || {};
  return (overview.invites || []).length
    + passwordNotices(overview.password_policy).length
    + (n.confirm || []).length
    + (n.shared_with_you || []).length
    + (n.removed || []).length
    + (overview.notices || []).length
    + (overview.vaults || []).filter(needsTrust).length
    + (overview.vaults || []).filter((v) => !needsTrust(v) && signerState(v).state === "changed").length
    + ((overview.policy && overview.policy.violations) || []).length
    + (overview.keys && overview.keys.published === false ? 1 : 0);
}

export function noticeLines(notice) {
  const lines = [];
  for (const text of notice.reapplied || []) lines.push({ kind: "reapplied", text: t("teams.notice_reapplied", { change: text }) });
  for (const text of notice.dropped || []) lines.push({ kind: "dropped", text: t("teams.notice_dropped", { change: text }) });
  if (notice.rotated_after_leave) lines.push({ kind: "rotated", text: t("teams.notice_rotated") });
  return lines;
}

export function normalizeFingerprint(fp) {
  return String(fp || "").trim().replace(/^sha256:/i, "").replace(/[\s:-]+/g, "").toUpperCase();
}

/** A fingerprint in groups of five characters ("7K3QD M2XPA ..."), as every Passyble app shows it, for reading aloud. */
export function fingerprintGroups(fp) {
  return normalizeFingerprint(fp).match(/.{1,5}/g) || [];
}

export function fingerprintText(fp, perLine = 0) {
  const groups = fingerprintGroups(fp);
  if (!perLine) return groups.join(" ");
  const lines = [];
  for (let i = 0; i < groups.length; i += perLine) lines.push(groups.slice(i, i + perLine).join(" "));
  return lines.join("\n");
}

export function fingerprintsMatch(a, b) {
  const x = normalizeFingerprint(a);
  return x.length > 0 && x === normalizeFingerprint(b);
}

/** Side by side, group by group: `{ groups: [{ expected, typed, match }], complete, match }` (`match`: complete and all equal). */
export function compareFingerprints(expected, typed) {
  const want = fingerprintGroups(expected);
  const got = fingerprintGroups(typed);
  const groups = want.map((g, i) => ({ expected: g, typed: got[i] || "", match: got[i] === g }));
  const complete = got.length >= want.length && want.length > 0;
  return { groups, complete, match: complete && got.length === want.length && groups.every((g) => g.match) };
}

export function strengthName(score) {
  switch (Number(score)) {
    case 0:
      return t("strength.very_weak");
    case 1:
      return t("strength.weak");
    case 2:
      return t("strength.fair");
    case 3:
      return t("strength.good");
    default:
      return t("strength.strong");
  }
}

export function minStrength(policy) {
  const n = Number(policy && policy.master_password_min_strength);
  return Number.isFinite(n) ? Math.max(0, Math.min(4, n)) : 0;
}

/** A new master password against the policy: `{ ok, text }`. `score` null (not known yet) is fine. */
export function strengthCheck(score, policy) {
  const min = minStrength(policy);
  if (score === null || score === undefined || !Number.isFinite(Number(score))) return { ok: true, text: "" };
  const have = strengthName(score);
  if (Number(score) >= min) return { ok: true, text: t("policy.strength_is", { strength: have }) };
  return { ok: false, text: t("policy.strength_too_weak", { strength: have, needed: strengthName(min) }) };
}

export function exportAllowed(status) {
  if (!status) return true;
  if (typeof status.export_allowed === "boolean") return status.export_allowed;
  const eff = status.effective;
  return !(eff && eff.export_allowed === false);
}

export function sharingOutsideAllowed(policy) {
  return !(policy && policy.sharing_outside_allowed === false);
}

export function violationText(v) {
  if (v && v.message) return v.message;
  switch (v && v.rule) {
    case "master_password_strength":
      return t("policy.violation_strength");
    case "auto_lock":
      return t("policy.violation_auto_lock");
    case "two_step":
      return t("policy.violation_two_step");
    default:
      return t("policy.violation_other");
  }
}

/** The rules of a policy as lines for the "Policies" notice: only rules that ask for something. */
export function policyLines(policy, kind = "team") {
  if (!policy) return [];
  const lines = [];
  const min = minStrength(policy);
  if (min > 0) lines.push(t("policy.line_strength", { strength: strengthName(min) }));
  if (kind !== "family") {
    if (policy.max_auto_lock_minutes) lines.push(t("policy.line_auto_lock", { time: durationText(policy.max_auto_lock_minutes) }));
    if (policy.export_allowed === false) lines.push(t("policy.line_no_export"));
    if (policy.require_two_step) lines.push(t("policy.line_two_step"));
    if (policy.sso_required) lines.push(t("policy.line_sso"));
    if (policy.device_approval_required) lines.push(t("policy.line_device_approval"));
  }
  if (policy.sharing_outside_allowed === false) {
    lines.push(kind === "family" ? t("policy.line_no_sharing_outside_family") : t("policy.line_no_sharing_outside"));
  }
  if (kind !== "family" && policy.password_mode === "second_password") lines.push(t("policy.line_second_password"));
  if (kind !== "family" && policy.password_mode === "one_password") lines.push(t("policy.line_one_password"));
  return lines;
}

export function passwordModeLabel(mode) {
  switch (mode) {
    case "second_password":
      return t("admin.password_mode_second");
    case "one_password":
      return t("admin.password_mode_one");
    default:
      return t("admin.password_mode_choice");
  }
}

/** The notices a Team's password rule asks for on this PC: `[{ kind, title, text, vault }]`. */
export function passwordNotices(policy) {
  const p = policy || {};
  if (!p.action_needed) return [];
  if (p.mode === "second_password") {
    return [{ kind: "second", title: p.title || t("password_mode.second_title"), text: p.message || "", vault: p.home || null }];
  }
  if (p.mode !== "one_password") return [];
  return (p.own_password || [])
    .map((v) => ({ kind: "one", title: t("password_mode.one_title"), text: t("password_mode.one_body", { vault: v.name }), vault: v }));
}

export function directShareAllowed(policy) {
  return !(policy && policy.direct_share === false);
}

export function durationText(minutes) {
  const m = Number(minutes) || 0;
  return m >= 60 && m % 60 === 0 ? tn("settings.hours", m / 60) : tn("settings.minutes", m);
}

/** How long a send stays available, in days. */
export const SEND_EXPIRY_DAYS = [1, 3, 7, 30];
export const SEND_VIEWS = [1, 2, 5, 10];

export function sendState(send, now = Date.now()) {
  const expires = Number(send.expires_at) || 0;
  if (expires && expires <= now) return { text: t("send.expired"), cls: "warn", live: false };
  if (send.views_left !== null && send.views_left !== undefined && Number(send.views_left) <= 0) {
    return { text: t("send.no_views_left"), cls: "warn", live: false };
  }
  const parts = [];
  if (expires) {
    const days = Math.ceil((expires - now) / 86400000);
    parts.push(days <= 1 ? t("send.expires_today") : tn("send.expires_in_days", days));
  }
  if (send.views_left !== null && send.views_left !== undefined) parts.push(tn("send.views_left", Number(send.views_left)));
  if (send.has_password) parts.push(t("send.has_password"));
  return { text: parts.join(" · "), cls: "", live: true };
}

/** Wait periods for emergency access, in hours. */
export const EMERGENCY_WAIT_HOURS = [24, 48, 72, 168, 336, 720];

export function waitText(hours) {
  const h = Number(hours) || 0;
  return h >= 24 && h % 24 === 0 ? tn("emergency.wait_days", h / 24) : tn("emergency.wait_hours", h);
}

export function emergencyAccessLabel(access) {
  return access === "full" ? t("emergency.access_full") : t("emergency.access_view");
}

/**
 * An emergency grant's state and what can be done now: `{ text, cls, actions }`, actions among "setup", "approve",
 * "refuse", "accept", "request", "open", "remove". `side`: "owner" (my trusted contacts) or "contact" (people who trust me).
 */
export function emergencyState(grant, side, now = Date.now()) {
  const state = grant.state;
  const actions = [];
  let text;
  let cls = "";
  switch (state) {
    case "invited":
      text = side === "owner" ? t("emergency.state_invited") : t("emergency.state_invited_you");
      if (side === "contact") actions.push("accept");
      break;
    case "accepted":
      text = side === "owner" ? t("emergency.state_accepted_owner") : t("emergency.state_accepted");
      if (side === "owner") {
        cls = "warn";
        actions.push("setup");
      }
      break;
    case "confirmed":
    case "ready":
      text = side === "owner" ? t("emergency.state_ready") : t("emergency.state_ready_contact");
      if (side === "contact") actions.push("request");
      break;
    case "requested": {
      const at = Number(grant.release_at) || 0;
      if (side === "owner") {
        text = at ? t("emergency.state_requested_until", { date: formatDate(at) }) : t("emergency.state_requested");
        cls = "warn";
        actions.push("approve", "refuse");
      } else if (at && at <= now) {
        text = t("emergency.state_available");
        actions.push("open");
      } else {
        text = at ? t("emergency.state_waiting_until", { date: formatDate(at) }) : t("emergency.state_waiting");
      }
      break;
    }
    case "approved":
    case "available":
      text = side === "owner" ? t("emergency.state_approved") : t("emergency.state_available");
      if (side === "contact") actions.push("open");
      break;
    case "refused":
    case "rejected":
      text = t("emergency.state_refused");
      if (side === "contact") actions.push("request");
      break;
    default:
      text = state ? String(state) : "";
  }
  if (side === "owner") actions.push("remove");
  return { text, cls, actions };
}
