// Pure helpers of the vault view (item kinds, tags, trash, health, security activity); no DOM, no Tauri.

import { formatNumber, t, tn } from "../i18n.js";

export function initials(name) {
  const words = String(name || "").trim().split(/\s+/).filter(Boolean);
  if (!words.length) return "";
  const first = Array.from(words[0])[0] || "";
  const last = words.length > 1 ? Array.from(words[words.length - 1])[0] || "" : "";
  return (first + last).toUpperCase();
}

export function expiryText(month, year) {
  const m = Number(month) || 0;
  const y = Number(year) || 0;
  if (!m && !y) return "";
  if (!y) return String(m).padStart(2, "0");
  if (!m) return String(y);
  return `${String(m).padStart(2, "0")}/${String(y % 100).padStart(2, "0")}`;
}

export function cardExpired(month, year, now = new Date()) {
  const m = Number(month) || 0;
  const y = Number(year) || 0;
  if (!m || !y) return false;
  return y < now.getFullYear() || (y === now.getFullYear() && m < now.getMonth() + 1);
}

export function cardLabel(card) {
  if (!card) return t("card.label");
  const brand = card.brand_name || t("card.label");
  return card.last4 ? `${brand} •••• ${card.last4}` : brand;
}

export function identityName(identity) {
  if (!identity) return "";
  if (identity.full_name) return identity.full_name;
  return [identity.first_name, identity.middle_name, identity.last_name].map((s) => (s || "").trim()).filter(Boolean).join(" ");
}

/** A tag as filters compare it: trimmed, lower case, no surrounding slashes or spaces around "/". */
export function tagKey(tag) {
  return String(tag || "").trim().replace(/^\/+|\/+$/g, "").replace(/\s*\/\s*/g, "/").toLowerCase();
}

/** Whether `tags` holds `wanted` or a tag nested under it (`work` matches `Work/Clients`, not `Workshop`). */
export function hasTag(tags, wanted) {
  const w = tagKey(wanted);
  if (!w) return false;
  return (tags || []).some((tag) => {
    const k = tagKey(tag);
    return k === w || k.startsWith(`${w}/`);
  });
}

/** The vault view's tag list: items' tags plus parents of nested ones, children after parent, with `depth`, `name` and `count`. Case-variants merge. */
export function tagTree(items) {
  const nodes = new Map();
  for (const item of items || []) {
    for (const tag of item.tags || []) {
      const parts = String(tag).split("/").map((p) => p.trim()).filter(Boolean);
      for (let i = 1; i <= parts.length; i++) {
        const path = parts.slice(0, i).join("/");
        const key = tagKey(path);
        if (!nodes.has(key)) nodes.set(key, { tag: path, name: parts[i - 1], depth: i - 1, count: 0, key });
      }
    }
  }
  for (const node of nodes.values()) {
    node.count = (items || []).filter((item) => hasTag(item.tags, node.key)).length;
  }
  return [...nodes.values()]
    .sort((a, b) => a.key.split("/").join("\u0000").localeCompare(b.key.split("/").join("\u0000")))
    .map(({ key: _key, ...rest }) => rest);
}

export function matchesFilter(item, filter) {
  switch (filter) {
    case "favorites": return !!item.favorite;
    case "used": return item.rank > 0;
    case "logins": return item.kind === "login";
    case "notes": return item.kind === "note";
    case "cards": return item.kind === "card";
    case "identities": return item.kind === "identity";
    case "totp": return !!item.has_totp;
    case "passkeys": return !!item.has_passkey;
    default: return true;
  }
}

export function rowSubtitle(item) {
  if (item.kind === "card") {
    const label = item.card ? cardLabel(item.card) : t("card.label");
    const exp = item.card ? expiryText(item.card.expiry_month, item.card.expiry_year) : "";
    return exp ? t("card.label_expiry", { label, expiry: exp }) : label;
  }
  if (item.kind === "identity") {
    const id = item.identity || {};
    const name = identityName(id);
    return [name !== item.title ? name : "", id.email, id.company].filter(Boolean)[0] || t("kind.identity");
  }
  if (item.kind === "note") return t("kind.note");
  return item.username || item.url || "";
}

const DAY = 24 * 60 * 60 * 1000;

export function purgeText(trashedAt, retentionMs, now = Date.now()) {
  if (!trashedAt) return "";
  const left = trashedAt + retentionMs - now;
  if (left <= DAY / 2) return t("trash.purge_today");
  const days = Math.round(left / DAY);
  return days <= 1 ? t("trash.purge_tomorrow") : tn("trash.purge_in_days", days);
}

const STRENGTH = [t("strength.very_weak"), t("strength.weak"), t("strength.fair"), t("strength.good"), t("strength.strong")];

export function strengthText(score) {
  return STRENGTH[Math.max(0, Math.min(4, Number(score) || 0))];
}

export function ageText(ms, now = Date.now()) {
  if (!ms) return t("age.long_ago");
  const days = Math.max(0, Math.floor((now - ms) / DAY));
  if (days < 60) return tn("age.days_ago", days);
  const months = Math.floor(days / 30.44);
  if (months < 24) return tn("age.months_ago", months);
  return tn("age.years_ago", Math.floor(days / 365.25));
}

export function breachText(count) {
  if (!count) return t("health.breach_none");
  return tn("health.breach_found", Number(count));
}

const EVENT_TEXT = {
  sign_in: t("security.event.sign_in"),
  sign_in_failed: t("security.event.sign_in_failed"),
  account_slowed_down: t("security.event.account_slowed_down"),
  device_added: t("security.event.device_added"),
  device_revoked: t("security.event.device_revoked"),
  password_changed: t("security.event.password_changed"),
  password_reset_requested: t("security.event.password_reset_requested"),
  "2fa_setup_started": t("security.event.2fa_setup_started"),
  "2fa_enabled": t("security.event.2fa_enabled"),
  "2fa_disabled": t("security.event.2fa_disabled"),
  "2fa_recovery_code_used": t("security.event.2fa_recovery_code_used"),
  "2fa_reset": t("security.event.2fa_reset"),
  invite_issued: t("security.event.invite_issued"),
  reset_link_issued: t("security.event.reset_link_issued"),
  signup: t("security.event.signup"),
  user_added: t("security.event.user_added"),
  email_changed: t("security.event.email_changed"),
  admin_password_reset: t("security.event.admin_password_reset"),
};

const DETAIL_TEXT = {
  sign_in: { totp: t("security.detail.sign_in.totp"), recovery_code: t("security.detail.sign_in.recovery_code") },
  sign_in_failed: { password: t("security.detail.sign_in_failed.password"), "2fa": t("security.detail.sign_in_failed.2fa") },
  password_changed: {
    old_password: t("security.detail.password_changed.old_password"),
    first_password: t("security.detail.password_changed.first_password"),
    reset_code: t("security.detail.password_changed.reset_code"),
    invite_code: t("security.detail.password_changed.invite_code"),
  },
  device_revoked: { self: t("security.detail.device_revoked.self"), user: t("security.detail.device_revoked.user"), admin: t("security.detail.device_revoked.admin") },
};

const WARN_EVENTS = new Set(["sign_in_failed", "account_slowed_down", "2fa_disabled", "2fa_reset", "admin_password_reset", "2fa_recovery_code_used", "password_reset_requested"]);

/** A security event (`server_security_events`) in plain words; unknown events read as their name with spaces. */
export function eventText(e) {
  const known = EVENT_TEXT[e.event];
  const title = known || `${String(e.event || t("security.event_unknown")).replace(/_/g, " ").replace(/^./, (c) => c.toUpperCase())}`;
  const parts = [];
  const detail = e.detail && DETAIL_TEXT[e.event] ? DETAIL_TEXT[e.event][e.detail] : null;
  if (detail) parts.push(detail);
  if (e.count != null) {
    if (e.event === "password_changed" || e.event === "admin_password_reset") {
      if (e.count > 0) parts.push(tn("security.devices_signed_out", e.count));
    } else if (e.event === "account_slowed_down") {
      parts.push(tn("security.failed_attempts", e.count));
    } else if (e.event === "2fa_recovery_code_used") {
      parts.push(tn("security.recovery_codes_left", e.count));
    }
  }
  return {
    title,
    detail: parts.join(" · "),
    warn: WARN_EVENTS.has(e.event),
    admin: e.actor === "admin",
  };
}
