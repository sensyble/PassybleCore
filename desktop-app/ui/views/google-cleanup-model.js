// What "Delete old versions from Google Drive" and "Remove vault from Google Drive" tell the user
// (google-cleanup.js, src-tauri/src/gdrive.rs). Pure: tested in test/google-cleanup-model.test.mjs.

import { t, tn } from "../i18n.js";

/** The result of deleting old versions (`{ removed, kept, unfinished }`) in a few plain sentences. */
export function oldVersionsText(result) {
  const r = result || {};
  const removed = Math.max(0, Number(r.removed) || 0);
  const kept = Math.max(0, Number(r.kept) || 0);
  const lines = [];
  if (removed > 0) lines.push(tn("google.old_versions_done", removed));
  else if (!kept && !r.unfinished) lines.push(t("google.old_versions_none"));
  if (kept > 0) lines.push(tn("google.old_versions_kept", kept));
  if (r.unfinished) lines.push(t("google.old_versions_unfinished"));
  return lines.join(" ");
}

/** Whether `typed` is the vault's name (same rule as gdrive.rs `name_confirmed`): spaces around it and letter case don't matter, an empty name never matches. */
export function nameConfirmed(typed, name) {
  const a = String(typed ?? "").trim();
  const b = String(name ?? "").trim();
  return b !== "" && a.toLowerCase() === b.toLowerCase();
}
