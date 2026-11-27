// The pure part of the editor's live password check: what to show under the password field for an
// answer of `password_check`. The answer carries no secrets (a score, a label and `issues`, most
// important first), and the password itself never comes here.

import { t, tn } from "../i18n.js";

const SEVERITIES = new Set(["high", "medium", "low"]);

/** The core's default minimum length, when an answer leaves `min_length` out. */
const MIN_LENGTH = 12;

/** The sentence for one issue, "" for a code this window doesn't know (a newer core). */
export function issueText(issue) {
  switch (issue && issue.code) {
    case "common":
      return t("editor.pw_issue.common");
    case "weak":
      return t("editor.pw_issue.weak");
    case "reused":
      return tn("editor.pw_issue.reused", Math.max(1, Number(issue.count) || 1));
    case "used_before":
      return t("editor.pw_issue.used_before");
    case "contains_username":
      return t("editor.pw_issue.contains_username");
    case "contains_site":
      return t("editor.pw_issue.contains_site");
    case "short":
      return t("editor.pw_issue.short", { min: Number(issue.min_length) || MIN_LENGTH });
    default:
      return "";
  }
}

/**
 * What the editor shows: `{ issues: [{ code, severity, text }], strong, fix }`. Unknown codes are
 * left out; `strong` is the "Strong" text when the core found nothing and the score is 3 or more;
 * `fix` offers "Use a strong password instead" for a high or medium issue. Nothing for an empty
 * password or a failed check (`result` null).
 */
export function passwordFeedback(result, password = "") {
  const none = { issues: [], strong: "", fix: false };
  if (!password || !result || typeof result !== "object") return none;
  const found = Array.isArray(result.issues) ? result.issues : [];
  const issues = [];
  for (const issue of found) {
    const text = issueText(issue);
    if (!text) continue;
    issues.push({ code: issue.code, severity: SEVERITIES.has(issue.severity) ? issue.severity : "low", text });
  }
  const score = Number(result.score);
  return {
    issues,
    strong: !found.length && score >= 3 ? t("strength.strong") : "",
    fix: issues.some((i) => i.severity === "high" || i.severity === "medium"),
  };
}

/** What `password_check` gets besides the password: the editor's username, websites, title, item id. */
export function checkContext({ username = "", urls = "", title = "", id = "" } = {}) {
  const args = {
    username: String(username || ""),
    urls: String(urls || "").split(/\r?\n/).map((s) => s.trim()).filter(Boolean),
    title: String(title || ""),
  };
  if (id) args.id = String(id);
  return args;
}
