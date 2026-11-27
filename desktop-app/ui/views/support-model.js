// Help and support (views/support.js): the pure part, tested under Node (test/support-model.test.mjs).
// The diagnostics filter (same rules as src-tauri/src/support.rs and the service), guest codes and app
// links, the new-ticket checks. No DOM, no Tauri.

export const DIAGNOSTIC_FIELDS = Object.freeze(["app", "app_version", "platform", "os_version", "sync", "errors", "locale"]);
/** A value stays under 64 characters (the service takes 64 at most). */
export const VALUE_MAX = 63;
export const ERRORS_MAX = 10;
export const ERROR_MAX = 40;
export const SUBJECT_MAX = 150;
export const BODY_MAX = 5000;
export const NAME_MAX = 100;
export const CODE_LEN = 8;
export const TOPICS = Object.freeze(["account", "sync", "autofill", "passkeys", "teams", "billing", "other"]);
export const ACCOUNT_HOST = "account.passyble.com";
/** Links in older e-mails still carry ACCOUNT_HOST. */
export const HELP_HOST = "help.passyble.com";

const ALPHABET = /^[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]+$/;

/** A diagnostics value: letters, digits, spaces and `. _ - + ( ) ,` only (no `/ : @ = ? #`). */
export function valueOk(v) {
  return typeof v === "string" && v.length >= 1 && v.length <= VALUE_MAX && /^[A-Za-z0-9 ._\-+(),]+$/.test(v);
}

/** An error code: `[A-Za-z0-9_.-]`, at most 40 characters. */
export function errorOk(v) {
  return typeof v === "string" && v.length >= 1 && v.length <= ERROR_MAX && /^[A-Za-z0-9_.-]+$/.test(v);
}

/** Only what may be sent: known fields that pass the checks, `null` when nothing is left. */
export function cleanDiagnostics(d) {
  if (!d || typeof d !== "object" || Array.isArray(d)) return null;
  const out = {};
  for (const field of DIAGNOSTIC_FIELDS) {
    const value = d[field];
    if (field === "errors") {
      if (!Array.isArray(value)) continue;
      const codes = [];
      for (const raw of value) {
        const code = typeof raw === "string" ? raw.trim() : "";
        if (errorOk(code) && !codes.includes(code) && codes.length < ERRORS_MAX) codes.push(code);
      }
      if (codes.length) out.errors = codes;
    } else if (typeof value === "string" && valueOk(value.trim())) {
      out[field] = value.trim();
    }
  }
  return Object.keys(out).length ? out : null;
}

export function diagnosticsLines(d) {
  const clean = cleanDiagnostics(d);
  if (!clean) return [];
  return DIAGNOSTIC_FIELDS.filter((f) => f in clean).map((f) => [f, f === "errors" ? clean.errors.join(", ") : clean[f]]);
}

export function parseReference(s) {
  const r = String(s ?? "").trim().toUpperCase();
  return /^PS-[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{6}$/.test(r) ? r : null;
}

export function normalizeCode(s) {
  const c = String(s ?? "").replace(/[\s-]/g, "").toUpperCase();
  return c.length === CODE_LEN && ALPHABET.test(c) ? c : null;
}

export function formatCode(code) {
  const c = normalizeCode(code);
  return c ? `${c.slice(0, 4)}-${c.slice(4)}` : String(code ?? "");
}

/** An app link (`passyble://support/app?r=&c=` or `https://<host>/support/app?r=&c=`): `{ reference, code }` or `null`. */
export function parseAppLink(text, host = ACCOUNT_HOST) {
  const s = String(text ?? "").trim();
  let url;
  try {
    url = new URL(s);
  } catch {
    return null;
  }
  const app = url.protocol === "passyble:";
  const path = app ? `${url.host}${url.pathname}` : url.pathname.replace(/^\//, "");
  if (!app && !(url.protocol === "https:" && [String(host).toLowerCase(), HELP_HOST].includes(url.host.toLowerCase()))) return null;
  if (path.replace(/\/$/, "").toLowerCase() !== "support/app") return null;
  const reference = parseReference(url.searchParams.get("r"));
  const code = normalizeCode(url.searchParams.get("c"));
  return reference && code ? { reference, code } : null;
}

export function parseCodeInput(text, host = ACCOUNT_HOST) {
  const link = parseAppLink(text, host);
  if (link) return link;
  const code = normalizeCode(text);
  return code ? { reference: null, code } : null;
}

export function validEmail(email) {
  const e = String(email ?? "").trim();
  return e.length <= 254 && /^[^\s@<>,]+@[^\s@<>,.][^\s@<>,]*\.[^\s@<>,]*[^\s@<>,.]$/.test(e);
}

/** The new-ticket form's problems: `{ field: reason }` (`missing`, `long`, `invalid`). */
export function ticketProblems({ subject = "", body = "", topic = "", email = "", name = "" } = {}, { guest = false } = {}) {
  const out = {};
  const s = String(subject).trim();
  const b = String(body).trim();
  if (!s) out.subject = "missing";
  else if (s.length > SUBJECT_MAX) out.subject = "long";
  if (!b) out.body = "missing";
  else if (b.length > BODY_MAX) out.body = "long";
  if (!String(topic).trim()) out.topic = "missing";
  if (String(name).trim().length > NAME_MAX) out.name = "long";
  if (guest) {
    if (!String(email).trim()) out.email = "missing";
    else if (!validEmail(email)) out.email = "invalid";
  }
  return out;
}

/** Where a ticket stands: `waiting`, `expired`, `gone`, `closed` or `open`. */
export function ticketStage(ticket, now = Date.now()) {
  if (!ticket) return "gone";
  if (ticket.guest && !ticket.claimed) {
    if (ticket.status === "expired" || (ticket.confirm_by && now > ticket.confirm_by)) return "expired";
    return "waiting";
  }
  if (ticket.status === "gone") return "gone";
  if (ticket.status === "closed") return "closed";
  return "open";
}

export function topicChoices(meta) {
  const list = Array.isArray(meta && meta.categories) ? meta.categories : [];
  const choices = list
    .filter((c) => c && typeof c.id === "string" && c.id)
    .map((c) => ({ id: c.id, label: typeof c.label === "string" && c.label.trim() ? c.label.trim() : null }));
  return choices.length ? choices : TOPICS.map((id) => ({ id, label: null }));
}

export function totalUnread(tickets) {
  return (tickets || []).reduce((n, t) => n + (Number(t && t.unread) > 0 ? Number(t.unread) : 0), 0);
}

export function sortTickets(tickets) {
  return [...(tickets || [])].sort((a, b) => (b.last_message_at || b.created_at || 0) - (a.last_message_at || a.created_at || 0));
}

/** The error a "Report this problem" ticket quotes (one line, 300 characters at most). */
export function problemMessage(message) {
  return String(message ?? "").replace(/\s+/g, " ").trim().slice(0, 300);
}

/**
 * An app link with a guest code only shows its ticket reference and waits for "Confirm": a web page
 * could fire links to use up the code's tries. `null`: no link.
 */
export function linkArrival(status) {
  const reference = status && typeof status.link_reference === "string" ? status.link_reference : "";
  return reference ? { step: "confirm", reference, submit: false } : null;
}
