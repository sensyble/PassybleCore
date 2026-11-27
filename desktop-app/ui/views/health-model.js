// The pure part of Password health (views/health.js): which checks found something, in which order, and the
// "look fine" count after a breach check. No DOM, no Tauri (test/health-model.test.mjs). Password problems
// count against "look fine"; the account checks (two-step sign-in, no password, duplicates, passkeys) are listed but don't.

import { t } from "../i18n.js";

/** Every check, in the order the view shows them. `problem`: counts against "look fine". */
export const CHECKS = [
  { id: "breached", problem: true },
  { id: "weak", problem: true },
  { id: "reused", problem: true },
  { id: "insecure", problem: true },
  { id: "contains_name", problem: true },
  { id: "old", problem: true },
  { id: "no_two_factor", problem: false },
  { id: "no_password", problem: false },
  { id: "duplicates", problem: false },
  { id: "passkeys", problem: false },
];

export function problemIds(report) {
  const ids = new Set();
  for (const list of [report.weak, report.reused.flat(), report.old, report.contains_name || [], report.insecure || []]) {
    for (const i of list) ids.add(i.id);
  }
  return ids;
}

/** The report's "look fine" count, less items a breach check found that the report counted as fine. `breaches`: item id → count (null before a check). */
export function healthyCount(report, breaches) {
  if (!breaches) return report.healthy;
  const flagged = problemIds(report);
  let n = report.healthy;
  for (const [id, count] of breaches) if (count > 0 && !flagged.has(id)) n -= 1;
  return Math.max(0, n);
}

/**
 * Each check with what it found: `{ id, problem, count, items }` in [CHECKS] order. `items` are items, or
 * groups for `reused` and `duplicates` (`count` then counts groups for `duplicates`). `breached` is left
 * out before a check.
 */
export function healthChecks(report, breachedItems = null) {
  const lists = {
    breached: breachedItems,
    weak: report.weak,
    reused: report.reused,
    insecure: report.insecure || [],
    contains_name: report.contains_name || [],
    old: report.old,
    no_two_factor: report.no_two_factor || [],
    no_password: report.no_password || [],
    duplicates: report.duplicates || [],
    passkeys: report.passkeys || [],
  };
  const out = [];
  for (const check of CHECKS) {
    const items = lists[check.id];
    if (!items) continue;
    const count = check.id === "reused" ? items.reduce((n, g) => n + g.length, 0) : items.length;
    out.push({ ...check, count, items });
  }
  return out;
}

export function toFixCount(report, breaches) {
  return Math.max(0, report.checked - healthyCount(report, breaches));
}

const METHOD = {
  totp: t("health.method.totp"),
  security_key: t("health.method.security_key"),
  sms: t("health.method.sms"),
  call: t("health.method.call"),
  email: t("health.method.email"),
  app: t("health.method.app"),
  device: t("health.method.device"),
};

export function methodText(code) {
  return Object.hasOwn(METHOD, code) ? METHOD[code] : "";
}

export function methodTexts(codes, max = 3) {
  return (codes || []).map(methodText).filter(Boolean).slice(0, max);
}

/** Whether the master password tip shows: Rust says so and it wasn't dismissed in this view since (`dismissed`). */
export function showMasterTip(report, dismissed = false) {
  return !dismissed && !!(report && report.master_password_tip === true);
}

export function masterTipDialog(report) {
  return report && report.master_password_server ? "server" : "vault";
}

/**
 * What the breach card shows for the app's breach check (it runs in the app, not the pane):
 * `{ mode: "idle" | "running" | "done" | "stopped" | "failed", ... }`; `breaches` (item id → count) only when done.
 */
export function breachCard(status) {
  const s = status || {};
  switch (s.state) {
    case "running": {
      const done = Number(s.done) || 0;
      const total = Number(s.total) || 0;
      return { mode: "running", done, total, pct: total ? Math.round((done / total) * 100) : 0 };
    }
    case "done":
      return {
        mode: "done",
        breaches: new Map((s.results || []).map((r) => [r.id, r.count])),
        checked: Number(s.checked) || 0,
        failed: Number(s.failed) || 0,
        total: Number(s.total) || 0,
      };
    case "stopped":
      return { mode: "stopped", reason: s.reason === "locked" ? "locked" : "cancelled" };
    case "failed":
      return { mode: "failed", error: String(s.error || "") };
    default:
      return { mode: "idle" };
  }
}

export function breachNoticeNeeded(report) {
  return !(report && report.breach_notice_hidden === true);
}

export function httpsChanges(urls) {
  return (urls || [])
    .map((u) => String(u).trim())
    .filter((u) => /^http:\/\//i.test(u))
    .map((from) => ({ from, to: `https://${from.slice("http://".length)}` }));
}
