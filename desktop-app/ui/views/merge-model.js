// Merging two items: the pure part of the merge sheet, the list's multi-select and the suggestions (no DOM,
// no Tauri; tested in ui/test/merge-model.test.mjs). The merge itself is pass-core's.

import { t, tn } from "../i18n.js";

/** A URL entry that pins a login to a desktop app for auto-type: `windows:<exe>` or
 * `macos:<bundle id>` (pass-core `APP_PIN_PREFIXES`). The prefix, to strip for display. */
export const APP_PIN = /^\s*(windows|macos):/i;

export const FIELD_LABELS = {
  title: t("field.title"),
  username: t("field.username"),
  password: t("field.password"),
  totp: t("field.totp"),
  notes: t("field.notes"),
};

/**
 * The sheet's single-value rows from a `merge_preview` answer. `choosable`: both have different values;
 * `kept`: only one has it; `pick`: the user's pick (`chosen`) or else the core's default. The title row
 * always shows and also has `renamable` and, while `custom.on`, the pick "custom".
 */
export function fieldRows(preview, chosen = {}, custom = null) {
  const { plan } = preview;
  const picks = { ...preview.picks, ...chosen };
  return plan.fields
    .filter((f) => f.state !== "empty" || f.field === "title")
    .map((f) => ({
      field: f.field,
      label: FIELD_LABELS[f.field] || f.field,
      state: f.state,
      pick: f.field === "title" && custom && custom.on ? "custom" : picks[f.field],
      choosable: f.state === "differs",
      both: f.field === "notes" && f.state === "differs",
      renamable: f.field === "title",
      same: f.state === "same",
      kept: f.state === "only_a" ? "a" : f.state === "only_b" ? "b" : null,
      secret: f.field === "password" || f.field === "totp",
    }));
}

/** The title the merged item gets without a custom one (the other's when the picked one is blank, as the core does). */
export function pickedTitle(preview, chosen = {}) {
  const side = { ...preview.picks, ...chosen }.title === "b" ? "b" : "a";
  const title = (item) => ((item && item.title) || "").trim();
  return title(preview[side]) || title(preview[side === "a" ? "b" : "a"]);
}

/** The picks `merge_pair` gets: the user's plus `custom_title` while the custom choice is on and has text. */
export function mergePicks(chosen = {}, custom = null) {
  const picks = { ...chosen };
  const text = custom && custom.on ? (custom.text || "").trim() : "";
  if (text) picks.custom_title = text;
  return picks;
}

const passkeyText = (p) => t("merge.passkey_value", { user: p.user_name || p.user_display_name || t("merge.passkey"), site: p.rp_id });

/** The rows both items' values are kept for (websites, passkeys, Android apps), when either has some. */
export function unionRows(preview) {
  const { a, b, plan } = preview;
  const rows = [
    ["urls", t("field.websites"), (i) => (i.urls || []).map((u) => (APP_PIN.test(u) ? t("merge.desktop_app", { app: u.replace(APP_PIN, "") }) : u)), plan.urls],
    ["passkeys", t("field.passkeys"), (i) => (i.passkeys || []).map(passkeyText), plan.passkeys],
    ["android_apps", t("field.android_apps"), (i) => i.android_apps || [], plan.android_apps],
  ];
  return rows
    .map(([key, label, values, total]) => ({ key, label, a: values(a), b: values(b), total }))
    .filter((r) => r.a.length || r.b.length);
}

export function selectRange(ids, anchor, target) {
  const from = ids.indexOf(anchor);
  const to = ids.indexOf(target);
  if (to < 0) return [];
  if (from < 0) return [target];
  const [lo, hi] = from <= to ? [from, to] : [to, from];
  return ids.slice(lo, hi + 1);
}

export function toggleSelected(selected, id, current = null) {
  const next = new Set(selected);
  if (!next.size && current && current !== id) next.add(current);
  if (next.has(id)) next.delete(id);
  else next.add(id);
  return next;
}

export function pruneSelected(selected, ids) {
  const listed = new Set(ids);
  return new Set([...selected].filter((id) => listed.has(id)));
}

/** The selection's star target: `true` stars them all unless every one is already a favorite. */
export function favoriteTarget(favorites) {
  return !favorites.length || favorites.some((f) => !f);
}

export const favoriteLabel = (on) => (on ? t("favorites.add") : t("favorites.remove"));

export function favoritesText(n, on) {
  if (n === 1) return on ? t("favorites.added_one") : t("favorites.removed_one");
  return on ? tn("favorites.added_many", n) : tn("favorites.removed_many", n);
}

export const deletedText = (n) => tn("trash.moved_items", n);

export const restoredText = (n) => (n === 1 ? t("trash.restored_one") : tn("trash.restored_many", n));

export const pairKey = (s) => `${s.login_id}|${s.otp_id}`;

export function pendingSuggestions(list, dismissed) {
  const off = new Set(dismissed || []);
  return (list || []).filter((s) => !off.has(pairKey(s)));
}

export function hintText(n) {
  return tn("merge.hint", n);
}

/** The picker's rows: likely matches (core's order, score above 0) first, then the rest, filtered by `query`. */
export function pickerRows(candidates, summaries, query = "") {
  const byId = new Map(summaries.map((s) => [s.id, s]));
  const q = query.trim().toLowerCase();
  const hit = (s) => !q || [s.title, s.username, s.url].some((v) => v && v.toLowerCase().includes(q));
  const likely = [];
  const rest = [];
  for (const c of candidates) {
    const s = byId.get(c.id);
    if (!s || !hit(s)) continue;
    (c.score > 0 ? likely : rest).push(s);
  }
  return { likely, rest };
}
