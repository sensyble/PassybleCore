// Wording for the live master password check (`master_password_check`). The rule lives only in the
// core; this file words its answer, `{ ok, score, label, entropy_bits, issues: [code], name,
// min_length }` with issues in display order. It carries no secrets, and the password never comes here.

import { t } from "../i18n.js";

/** The core's minimum length, when an answer leaves `min_length` out. */
export const MASTER_MIN_LENGTH = 12;

const LABELS = new Set(["very_weak", "weak", "fair", "good", "strong"]);

/** The sentence for one reason a master password is refused, "" for a code this window doesn't know. */
export function masterIssueText(code, result = {}) {
  switch (code) {
    case "too_short":
      return t("master_pw.too_short", { min: Number(result.min_length) || MASTER_MIN_LENGTH });
    case "common":
      return t("master_pw.common");
    case "contains_name":
      return t("master_pw.contains_name");
    case "pattern":
      return t("master_pw.pattern");
    case "guessable":
      return t("master_pw.guessable");
    default:
      return "";
  }
}

/**
 * What shows under the field: `{ ok, reasons: [text], okText }`. `ok` only when the core said so;
 * unknown codes are left out, and a refusal this window can't word gets the general "too easy to
 * guess". Nothing for an empty password or a failed check (`result` null).
 */
export function masterFeedback(result, password = "") {
  const none = { ok: false, reasons: [], okText: "" };
  if (!password || !result || typeof result !== "object") return none;
  if (result.ok === true) {
    const label = LABELS.has(result.label) ? result.label : "good";
    return { ok: true, reasons: [], okText: t("master_pw.ok", { strength: t(`strength.${label}`) }) };
  }
  const codes = Array.isArray(result.issues) ? result.issues : [];
  const reasons = codes.map((c) => masterIssueText(c, result)).filter(Boolean);
  if (!reasons.length) reasons.push(t("master_pw.guessable"));
  return { ok: false, reasons, okText: "" };
}

/** The names a new master password should not be built from, as `master_password_check` takes them. */
export function masterNames(...names) {
  return names
    .flat()
    .map((n) => (typeof n === "string" ? n.trim() : ""))
    .filter(Boolean)
    .slice(0, 16);
}
