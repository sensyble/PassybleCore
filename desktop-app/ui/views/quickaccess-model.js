// Quick Access: the pure part (no DOM, no Tauri).

import { hasMod } from "./shortcuts-model.js";

export const MAX_ROWS = 50;

/**
 * What a key in the search box does: "down", "up", "enter" (copy the password, or open a note,
 * card or identity), "username" (Ctrl+C), "code" (Ctrl+Shift+C), "open" (Ctrl+O or Shift+Enter),
 * or null (the box types it). `mac`: Cmd instead of Ctrl.
 */
export function quickAccessKey(e, mac = false) {
  const ctrl = hasMod(e, mac);
  if (e.key === "ArrowDown") return "down";
  if (e.key === "ArrowUp") return "up";
  if (e.key === "Enter") return e.shiftKey || ctrl ? "open" : "enter";
  // By the key's place, so it also works with other keyboard layouts; never with Alt (AltGr+C types
  // a letter on some layouts).
  if (ctrl && !e.altKey && e.code === "KeyC") return e.shiftKey ? "code" : "username";
  if (ctrl && !e.altKey && !e.shiftKey && e.code === "KeyO") return "open";
  return null;
}

/** The rows to list: the search's order for a query; with an empty box the most used items first, then A to Z. Trashed items never show. */
export function quickAccessRows(items, query) {
  const live = (items || []).filter((i) => !i.trashed_at);
  if (String(query || "").trim()) return live.slice(0, MAX_ROWS);
  return [...live]
    .sort((a, b) => (b.rank || 0) - (a.rank || 0) || String(a.title).localeCompare(String(b.title)))
    .slice(0, MAX_ROWS);
}
