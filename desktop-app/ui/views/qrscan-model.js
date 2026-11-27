// "Add two-factor code" after a screen scan: the pure part (no DOM, no Tauri). Issuer and account
// come from whoever made the QR code, so the window shows them as plain text only.

import { t } from "../i18n.js";

export function qrscanTitle(code) {
  const issuer = code && code.issuer;
  const account = code && code.account;
  if (issuer && account) return t("qrscan.title_for_both", { issuer, account });
  if (issuer || account) return t("qrscan.title_for", { name: issuer || account });
  return t("qrscan.title");
}

export function codeRows(codes) {
  return (codes || []).map((c) => ({
    index: c.index,
    title: c.issuer || c.account || t("otpauth.default_title"),
    detail: c.issuer ? c.account || "" : "",
  }));
}

/**
 * What the window shows first (`qrscan_state`): "error" (the scan failed), "no_vault", "none"
 * (nothing to add), "pick" (several codes), "review" (one code) or "migration" (only a Google
 * Authenticator export).
 */
export function firstStep(state) {
  if (!state) return "none";
  if (state.error) return "error";
  const codes = state.codes || [];
  if ((codes.length || state.migration) && !state.vault) return "no_vault";
  if (codes.length > 1) return "pick";
  if (codes.length === 1) return "review";
  return state.migration ? "migration" : "none";
}

/** Logins from a search that can take the code: logins only, in vaults the user may edit. */
export function pickableLogins(items, shown = []) {
  const skip = new Set(shown);
  return (items || []).filter((i) => i.kind === "login" && !(i.vault && i.vault.can_edit === false) && !skip.has(i.id));
}
