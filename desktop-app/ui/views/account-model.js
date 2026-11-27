// The Passyble account row's states (account.js), pure so it can be tested. The row is never hidden:
// a failed check shows the signed-out state with a calm line and a Retry.

/** `{ status }` is the answer of `account_status`; `{ failed: true }` when asking it threw.
 * Returns `{ state: "signed_out" | "signed_in" | "error", text, actions }` (`text` is the value line,
 * as `{ key }` for a catalog key or `{ plain }` for the e-mail and organisations). */
export function accountState({ status = null, failed = false, orgLabel = (o) => o.name } = {}) {
  if (failed) return { state: "error", text: { key: "account.check_failed" }, actions: ["retry", "sign_in"] };
  if (!status || !status.signed_in || !status.account) {
    return { state: "signed_out", text: { key: "account.signed_out" }, actions: ["sign_in"] };
  }
  const orgs = (status.orgs || []).map((o) => `${o.name} (${orgLabel(o)})`);
  return { state: "signed_in", text: { plain: [status.account.email, ...orgs].filter(Boolean).join(" · ") }, actions: ["sign_out"] };
}

/** Whether the Sign out confirmation offers to sign out the browser extension too (ticked by
 * default): only when one that signs in with this app talked to it in the last 30 days. */
export function offersExtensionSignOut(status) {
  return !!(status && status.signed_in && status.extension_recent);
}
