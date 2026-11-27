// UI text catalogs: one JSON file per language in i18n/<locale>.json, en.json being the source.
// Keys are flat and dotted, placeholders named ({host}), plurals objects keyed by CLDR category
// (falling back to "other"). A key missing from the active catalog falls back to English, then to
// the key itself (with a console warning).
//
// Rust picks the language and hands the catalogs over (`i18n_state`) so windows, tray and errors
// agree. Loaded with a top-level await, so importers see the catalog already loaded (Node tests
// load en.json).

let locale = "en";
let catalog = {};
let source = {};
let languages = [];
let preference = null;
let pluralRules = null;
const warned = new Set();

/** Applies a catalog: `active` for `code`, `english` the source used for anything missing. */
export function setCatalog(code, active, english = active) {
  locale = code || "en";
  catalog = active || {};
  source = english || {};
  try {
    pluralRules = new Intl.PluralRules(locale);
  } catch {
    pluralRules = new Intl.PluralRules("en");
  }
}

/** The language chosen in Settings, or null for "System default". */
export function languagePreference() {
  return preference;
}

/** The languages there are catalogs for: `[{ code, name, native }]` (English and native names). */
export function availableLanguages() {
  return languages.slice();
}

export function textDirection() {
  return /^(ar|fa|he|ur|ps|sd|yi|dv|ug)(-|$)/i.test(locale) ? "rtl" : "ltr";
}

function warn(key) {
  if (warned.has(key)) return;
  warned.add(key);
  console.warn(`i18n: missing text for "${key}"`);
}

const isPlural = (v) => v && typeof v === "object" && typeof v.other === "string";

/** The catalog entry for `key`: the active language's, else English, else null. */
function entry(key, want) {
  const own = catalog[key];
  if (want === "string" ? typeof own === "string" : isPlural(own)) return own;
  const en = source[key];
  if (want === "string" ? typeof en === "string" : isPlural(en)) return en;
  // A plural used as a plain string (or the other way round): take what there is.
  if (typeof own === "string" || isPlural(own)) return own;
  if (typeof en === "string" || isPlural(en)) return en;
  return null;
}

function fill(text, params) {
  if (!params) return text;
  return text.replace(/\{([A-Za-z0-9_]+)\}/g, (m, name) => (params[name] === undefined || params[name] === null ? m : String(params[name])));
}

/** The text for `key` with `{name}` placeholders filled from `params`. */
export function t(key, params) {
  let v = entry(key, "string");
  if (v === null) {
    warn(key);
    return key;
  }
  if (typeof v !== "string") v = v.other;
  return fill(v, params);
}

/** The CLDR plural category of `count` in the active language ("one", "other", "many", ...). */
export function pluralCategory(count) {
  return pluralRules ? pluralRules.select(Number(count)) : Number(count) === 1 ? "one" : "other";
}

/** A plural text: the form for `count` ("other" if the catalog lacks it), placeholders filled. */
export function tn(key, count, params = {}) {
  let v = entry(key, "plural");
  if (v === null) {
    warn(key);
    return key;
  }
  if (typeof v !== "string") {
    const forms = v;
    v = forms[pluralCategory(count)];
    if (typeof v !== "string") v = forms.other;
  }
  return fill(v, { count: formatNumber(count), ...params });
}

/** Like `t`, but placeholders may be DOM nodes: returns strings and nodes to append. */
export function tx(key, params = {}) {
  const text = t(key);
  const parts = [];
  let last = 0;
  text.replace(/\{([A-Za-z0-9_]+)\}/g, (m, name, at) => {
    if (at > last) parts.push(text.slice(last, at));
    const value = params[name];
    parts.push(value === undefined || value === null ? m : value);
    last = at + m.length;
    return m;
  });
  if (last < text.length) parts.push(text.slice(last));
  return parts;
}

/** A label used inside a sentence: lower case, except in languages that capitalize nouns (German). */
export function inSentence(label) {
  const text = String(label || "");
  return /^de(-|$)/i.test(locale) ? text : text.toLocaleLowerCase(locale);
}

export function formatNumber(n, options) {
  const value = Number(n);
  if (!Number.isFinite(value)) return String(n);
  try {
    return new Intl.NumberFormat(locale, options).format(value);
  } catch {
    return String(n);
  }
}

function dateFormat(ms, options) {
  const d = ms instanceof Date ? ms : new Date(ms);
  if (Number.isNaN(d.getTime())) return "";
  try {
    return new Intl.DateTimeFormat(locale, options).format(d);
  } catch {
    return d.toISOString();
  }
}

export function formatDate(ms, options = { day: "numeric", month: "short", year: "numeric" }) {
  return dateFormat(ms, options);
}

export function formatDateTime(ms, options = { day: "numeric", month: "short", year: "numeric", hour: "numeric", minute: "2-digit" }) {
  return dateFormat(ms, options);
}

export function formatTime(ms, options = { hour: "numeric", minute: "2-digit" }) {
  return dateFormat(ms, options);
}

/**
 * Fills marked-up elements under `root`: `data-i18n="key"` sets the text, and
 * `data-i18n-attr="title:key; aria-label:key2"` sets attributes.
 */
export function applyI18n(root = document) {
  for (const el of root.querySelectorAll("[data-i18n]")) el.textContent = t(el.dataset.i18n);
  for (const el of root.querySelectorAll("[data-i18n-attr]")) {
    for (const pair of el.dataset.i18nAttr.split(";")) {
      const [attr, key] = pair.split(":").map((s) => s.trim());
      if (attr && key) el.setAttribute(attr, t(key));
    }
  }
}

function applyDocument() {
  if (typeof document === "undefined") return;
  document.documentElement.lang = locale;
  document.documentElement.dir = textDirection();
  applyI18n(document);
}

async function load() {
  const tauri = globalThis.window && window.__TAURI__;
  if (tauri) {
    try {
      const state = await tauri.core.invoke("i18n_state");
      languages = state.languages || [];
      preference = state.preference || null;
      // English comes once: `source` is null when English is the active catalog.
      setCatalog(state.locale, state.catalog, state.source || state.catalog);
    } catch (e) {
      console.error("i18n: could not load the catalogs", e);
    }
    applyDocument();
    // Another window (Settings) changed the language: start over with the new catalog.
    tauri.event.listen("locale-changed", () => window.location.reload()).catch(() => {});
    return;
  }
  if (typeof process !== "undefined" && process.versions && process.versions.node) {
    const { readFileSync } = await import("node:fs");
    const en = JSON.parse(readFileSync(new URL("./i18n/en.json", import.meta.url), "utf8"));
    setCatalog("en", en, en);
  }
}

await load();
