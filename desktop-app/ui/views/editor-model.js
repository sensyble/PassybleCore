// Pure part of the item editor and of the item view's website badges (no DOM, no Tauri, so node can test it).
// Rules are pass-core's `UrlMatch`: "subdomains" (default), "host" (exact host only) and "never". Only
// non-default rules are stored, keyed by the entry's text exactly as in `urls`.

import { t } from "../i18n.js";
import { isCommandKey } from "./app-keys.js";
import { APP_PIN } from "./merge-model.js";

export const DEFAULT_RULE = "subdomains";
const WEB_RULES = ["subdomains", "host", "never"];
// An app pin or an Android app has no host: it matches or is hidden.
const APP_RULES = ["subdomains", "never"];

export const isAppPin = (url) => APP_PIN.test(String(url || ""));

export const ruleChoices = (url) => (isAppPin(url) ? APP_RULES : WEB_RULES);

export const effectiveRule = (url, rule) => (ruleChoices(url).includes(rule) ? rule : DEFAULT_RULE);

export function ruleOf(rules, url) {
  const found = (rules || []).find((r) => r && r.url === url);
  return found && WEB_RULES.includes(found.rule) ? found.rule : DEFAULT_RULE;
}

export function urlRows(urls, rules) {
  return (urls || []).map((url) => ({ url, rule: ruleOf(rules, url) }));
}

/** What a save sends from the rows: `urls` (trimmed, empty rows dropped) and `url_rules` (non-default only). */
export function savedUrls(rows) {
  const kept = (rows || [])
    .map((r) => ({ url: String(r.url || "").trim(), rule: r.rule }))
    .filter((r) => r.url)
    .map((r) => ({ url: r.url, rule: effectiveRule(r.url, r.rule) }));
  return {
    urls: kept.map((r) => r.url),
    url_rules: kept.filter((r) => r.rule !== DEFAULT_RULE),
  };
}

export function appRows(packages, neverShow) {
  const hidden = new Set(neverShow || []);
  return (packages || []).map((pkg) => ({ package: pkg, rule: hidden.has(pkg) ? "never" : DEFAULT_RULE }));
}

export const hiddenApps = (rows) => (rows || []).filter((r) => r.rule === "never").map((r) => r.package);

/** The options of a row's menu. `suggestHost` marks "Same host only" as suggested (never chosen for the user). */
export function ruleOptions({ app = false, suggestHost = false } = {}) {
  if (app) {
    return [
      { rule: "subdomains", label: t("editor.rule_match_app"), hint: t("editor.rule_match_app_hint"), suggested: false },
      { rule: "never", label: t("editor.rule_never"), hint: t("editor.rule_never_app_hint"), suggested: false },
    ];
  }
  return [
    { rule: "subdomains", label: t("editor.rule_subdomains"), hint: t("editor.rule_subdomains_hint"), suggested: false },
    { rule: "host", label: t("editor.rule_host"), hint: t(suggestHost ? "editor.rule_host_hint_shared" : "editor.rule_host_hint"), suggested: suggestHost },
    { rule: "never", label: t("editor.rule_never"), hint: t("editor.rule_never_hint"), suggested: false },
  ];
}

export function ruleBadge(rule) {
  if (rule === "host") return t("editor.rule_badge_host");
  if (rule === "never") return t("editor.rule_badge_never");
  return null;
}

/** What a website row's text asks site suggestions for: the bare host as typed; "" for an app pin. */
export function siteQuery(text) {
  const value = String(text || "").trim();
  if (isAppPin(value)) return "";
  return value.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "").replace(/^www\./i, "").split(/[/?#]/)[0].toLowerCase();
}

export const siteUrl = (domain) => `https://${domain}`;

/** A new login's Name after the website changed: a site's name fills an empty or auto-filled Name, never a typed one. */
export function titleForSite(title, auto, name) {
  if (String(title || "").trim() && !auto) return { title, auto: false };
  if (name) return { title: name, auto: true };
  return { title: auto ? "" : title, auto: false };
}

/** Whether "More details" starts open: only for an existing item that already has something in there. */
export function detailsOpen(item) {
  if (!item || !item.id) return false;
  const some = (list) => Array.isArray(list) && list.length > 0;
  const filled = (text) => !!String(text || "").trim();
  const { urls, url_rules: rules } = savedUrls(urlRows(item.urls, item.url_rules));
  const login = item.kind === "login"
    && (urls.length > 1 || rules.length > 0 || some(item.android_apps) || some(item.passkeys));
  return login
    || (item.kind !== "note" && item.kind !== "login" && filled(item.notes))
    || some(item.fields) || some(item.tags) || !!item.favorite || !!item.ai_access;
}

/** What keydown `e` does in the editor: "cancel" (Esc), "save" (Mod+S) or null. `where`: "editor", "page" or "other"; `dialog`: a dialog is open and takes every key. */
export function editorKey(e, { mac = false, where = "editor", dialog = false } = {}) {
  if (!e || e.defaultPrevented || dialog || where === "other") return null;
  if (isCommandKey(e, "cancel", mac)) return "cancel";
  if (isCommandKey(e, "save", mac)) return "save";
  return null;
}

/** Esc in one of the editor's popups: marks it handled and runs `close()`. False for any other key. */
export function takeEscape(e, close) {
  if (!e || e.key !== "Escape") return false;
  e.preventDefault();
  e.stopPropagation();
  close();
  return true;
}

/** What cancelling does first: close a popup, else a suggestion list, else ask about unsaved changes, else close. */
export function cancelStep({ popup = false, list = false, dirty = false } = {}) {
  if (popup) return "popup";
  if (list) return "list";
  return dirty ? "ask" : "close";
}

export const NOTES_MAX = 20000;
export const FIELD_VALUE_MAX = 5000;
export const FIELD_NAME_MAX = 500;

/** The notes counter: null below 90% of `max`. A note already over the cap keeps its length as the limit. */
export function notesCounter(length, max = NOTES_MAX) {
  if (length < max * 0.9) return null;
  return { count: length, max, full: length >= max };
}

export const notesMaxLength = (length, max = NOTES_MAX) => Math.max(max, length);
