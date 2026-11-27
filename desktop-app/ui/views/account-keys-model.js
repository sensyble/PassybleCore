// The pure part of the Passyble password screens (account-keys.js, unlock.js).

/** What the Rust commands answer instead of an error the user reads (account_keys.rs). */
export const SECRET_KEY_NEEDED = "secret_key_needed";
export const PASSWORD_NEEDED = "account_password_needed";
export const EMAIL_NEEDED = "account_email_needed";
export const REAUTH = "reauth_required";
/** The vault is linked to a key an e-mail reset replaced ("Locked, from before your reset"). */
export const LOCKED = "account_key_locked";

export function errorCode(e) {
  if (typeof e === "string") return e.trim();
  if (e && typeof e.message === "string") return e.message.trim();
  return "";
}

/** Whether a master password unlock failed because the vault opens with the Passyble password. */
export function opensWithAccount(e) {
  return /opens with your passyble password/i.test(errorCode(e));
}

export function lastGroup(code) {
  const groups = String(code || "").trim().split("-").filter(Boolean);
  return groups.length ? groups[groups.length - 1].toUpperCase() : "";
}

/** Whether `typed` is the recovery code's last group: case and spaces don't matter, and O, I, L read as 0, 1, 1 (Crockford base32). */
export function confirmsCode(code, typed) {
  const norm = (s) => String(s || "").toUpperCase().replace(/[\s-]/g, "").replace(/O/g, "0").replace(/[IL]/g, "1");
  const want = norm(lastGroup(code));
  return want.length > 0 && norm(typed) === want;
}

export function looksLikeSecretKey(text) {
  const t = String(text || "").trim().toUpperCase().replace(/\s+/g, "");
  return /^P1-?([0-9A-Z]{5}-?){5}[0-9A-Z]{5}$/.test(t);
}

/**
 * What the linked vault's unlock form shows: `hello`, `remembered` (one Unlock button), `secretKey`
 * (ask for it once) or `email` (this PC isn't signed in and knows no address).
 */
export function linkedForm(access, helloAvailable) {
  const a = access || {};
  const remembered = a.kept === "remember" && !!a.kept_ready;
  const hello = a.kept === "hello" && !!a.kept_ready && !!helloAvailable;
  return {
    hello,
    remembered,
    secretKey: !a.secret_key_here,
    email: !a.signed_in && !a.email && !a.offline_ready,
  };
}

/**
 * The Settings rows of the Passyble password. `unlink` only where Rust offers it (never for the home
 * vault, unless its Team requires a second password, and never while a Team uses one password).
 */
export function securityRows(status) {
  const s = status || {};
  if (!s.signed_in || s.feature_off) return [];
  if (s.set === false) return ["setup"];
  if (s.set !== true) return [];
  const rows = [];
  // What needs the user first: a waiting e-mail reset, a key that changed, locked key sets.
  if (s.reset && s.reset.waiting) rows.push("reset");
  if (s.key_changed) rows.push("key_changed");
  if (Number(s.locked) > 0) rows.push("locked");
  rows.push("password", "kit", "recovery", "device_key", "fingerprint", "devices");
  const v = s.active_vault;
  if (v && v.linked && v.unlink) rows.push("unlink");
  if (v && !v.linked && !v.linked_other && v.link !== false) rows.push("link");
  return rows;
}

export function requestView(r) {
  const x = r || {};
  if (x.mismatch) return { step: "mismatch", actions: ["deny"] };
  if (x.kind === "invitation") return x.ready ? { step: "joined", actions: ["approve", "deny"] } : { step: "waiting", actions: [] };
  // The new device shows its six digits: the user types them here (never shown on this side).
  if (x.ready) return { step: "compare", actions: ["approve", "deny"] };
  if (x.accepted_here) return { step: "accepted", actions: ["deny"] };
  return { step: "new", actions: ["accept", "deny"] };
}

export function codeText(code) {
  const c = String(code || "").replace(/\D/g, "");
  return c.length === 6 ? `${c.slice(0, 3)} ${c.slice(3)}` : c;
}

/** Where an e-mail reset stands: `none`, `waiting` (the 72 hours run) or `due`. */
export function resetStep(reset, now = Date.now()) {
  const r = reset || {};
  if (!r.waiting) return { step: "none", releaseAt: null };
  const releaseAt = Number(r.release_at) || null;
  const due = !!r.due || (releaseAt !== null && releaseAt <= now);
  return { step: due ? "due" : "waiting", releaseAt };
}

/** The ways a locked key set opens, in the order the dialog offers them. */
export function lockedWays(set) {
  const w = (set && set.ways) || {};
  const out = [];
  if (w.device) out.push("device");
  // The old password always gets a try: the old Emergency Kit has the Secret Key.
  out.push("password");
  if (w.recovery !== false) out.push("recovery");
  if (Array.isArray(w.admins) && w.admins.length) out.push("admin");
  return out;
}

/** The admin recovery row of one organisation for the account key: `{ state, actions }`. */
export function adminKeyRow(row) {
  const r = row || {};
  if (r.enrolled) return { state: "enrolled", actions: r.required ? [] : ["withdraw"] };
  if (!r.available) return { state: "hidden", actions: [] };
  if (r.required) return { state: "required", actions: ["enrol"] };
  if (r.enrol_again) return { state: "again", actions: ["enrol"] };
  return { state: "offered", actions: ["enrol"] };
}

export function namesKey(vaultId, akId) {
  return !!akId && vaultId === `ak:${akId}`;
}
