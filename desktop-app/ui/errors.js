// Errors as the user reads them, for every window. Rust words its own errors (src-tauri/src/errors.rs)
// and so do the windows; what is left is mapped here. Anything technical (a JavaScript exception, a
// Tauri transport error, raw OS or library text) becomes the generic "Something went wrong", with
// the detail in the console only.

import { t, tn } from "./i18n.js";

/** What a command needing the unlocked vault answers while locked (state.rs `VAULT_LOCKED`). */
export const LOCKED_ERROR = "The vault is locked";

/** `e` is the "vault is locked" answer of a command. */
export function isLockedError(e) {
  const text = typeof e === "string" ? e : e && typeof e.message === "string" ? e.message : "";
  return text.trim() === LOCKED_ERROR;
}

// Text no message for the user has: Tauri's own errors (a command or argument that doesn't
// exist), Rust and JavaScript internals, OS error codes and HRESULTs, library names. (Paths are
// fine: messages name the user's own files.)
const TECHNICAL = [
  /^(invalid args|command \S+ not found|unknown variant|missing field|invalid type|invalid value|expected )/i,
  /\b(os error|errno|hresult|panicked|unwrap|serde\w*|ureq|reqwest|rustls|tauri|webview2?|ipc|dpapi|stack trace)\b/i,
  /\b0x[0-9a-f]{8}\b/i,
  /\b(undefined|null) is not\b|\bis not a function\b|\bcannot read propert/i,
  /`[^`]*`/,
  // A Rust path (std::io), not an IPv6 address ([::1], fe80::1).
  /\b[a-z_]{2,}::[A-Za-z_]{2,}/,
];

/** Whether `e` says the user cancelled Windows Hello (their choice: shown muted, not as an error). */
export function isHelloCancelled(e) {
  const text = (typeof e === "string" ? e : e && typeof e.message === "string" ? e.message : "").trim();
  return text !== "" && (text === t("errors.hello_cancelled") || text === t("errors.hello_verification_cancelled"));
}

/** Whether `text` looks like a developer's text rather than a sentence for the user. */
export function looksTechnical(text) {
  return TECHNICAL.some((re) => re.test(text));
}

function generic(detail) {
  // For whoever debugs it (devtools in debug builds); the user sees plain words.
  console.warn("Passyble error:", detail);
  return t("errors.generic");
}

/** A rejected command (or any error) as plain language. Catches what Rust (errors.rs) did not word. */
export function friendlyError(e) {
  // A JavaScript exception (TypeError, a DOMException, ...): a bug, never something to show.
  if (e instanceof Error && e.name !== "Error") return generic(e);
  let text = typeof e === "string" ? e : e && typeof e.message === "string" ? e.message : String(e);
  text = text.trim();
  const lower = text.toLowerCase();
  if (!text || /^(undefined|null|\[object \w+\])$/.test(lower)) return generic(e);
  // Matched against the English texts of pass-core and the agent (they aren't translated).
  if (text === LOCKED_ERROR) return t("errors.vault_locked");
  // What the Passyble password's commands answer for a missing piece (account_keys.rs).
  const accountKeys = {
    secret_key_needed: "account_keys.secret_key_needed",
    account_password_needed: "account_keys.enter_password",
    account_email_needed: "account_keys.email_needed",
    reauth_required: "account_keys.sign_in_again",
  };
  if (accountKeys[text]) return t(accountKeys[text]);
  if (lower === "wrong master password" || lower.startsWith("wrong master password or vault key")) {
    return t("errors.wrong_master_password");
  }
  if (/too many failed attempts/.test(lower)) {
    const m = /try again in (\d+) minute/.exec(lower);
    return m ? tn("errors.too_many_attempts_minutes", Number(m[1])) : t("errors.too_many_attempts");
  }
  if (/^network error: /.test(lower) || /(dns failed|connection failed|timed out|connection refused)/.test(lower)) {
    const host = /:\/\/([^/\s'")]+)/.exec(text);
    return host ? t("errors.cant_reach_host", { host: host[1] }) : t("errors.cant_reach_server");
  }
  if (/^server certificate changed/.test(lower)) {
    return t("errors.certificate_changed_short");
  }
  if (/^invalid input: /.test(lower)) text = text.slice("invalid input: ".length);
  // Server two-factor codes, should one get here unworded (errors.rs words them).
  if (/^(invalid input: )?2fa_required/.test(lower)) return t("errors.two_factor_required");
  if (/^(invalid input: )?2fa_invalid/.test(lower)) return t("errors.two_factor_invalid");
  if (looksTechnical(text)) return generic(text);
  return text.charAt(0).toUpperCase() + text.slice(1);
}
