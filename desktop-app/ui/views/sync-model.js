// The vault screen's Sync button: the pure part (no DOM, no Tauri).

import { t } from "../i18n.js";

/** Clicks closer together than this count once (a double click is one sync). */
export const DEBOUNCE_MS = 1500;

/**
 * What the button shows. `available`: some open vault has sync set up (else it offers "Set up
 * sync"); `sync`: the sync status (`running`, `last_error`, `last_sync_ms`, `signed_out`,
 * `sign_in_needed`); `ago(ms)`: "just now", "5 min ago" (lib.js agoText).
 * `{ action: "sync" | "setup", busy, warn, title }`.
 */
export function syncButton(available, sync = {}, ago = () => "") {
  if (!available) return { action: "setup", busy: false, warn: false, title: t("local_reminder.set_up_sync") };
  if (sync.running) return { action: "sync", busy: true, warn: false, title: t("settings.syncing") };
  if (sync.last_error) return { action: "sync", busy: false, warn: true, title: t("sync.failed_title", { error: sync.last_error }) };
  if (sync.last_sync_ms) return { action: "sync", busy: false, warn: false, title: t("sync.synced_title", { ago: ago(sync.last_sync_ms) }) };
  return { action: "sync", busy: false, warn: false, title: t("settings.sync_now") };
}

/** Whether a click at `now` starts a sync: not while one runs, nor right after the last click. */
export function acceptClick(lastClick, running, now = Date.now()) {
  return !running && (!lastClick || now - lastClick >= DEBOUNCE_MS);
}

export function syncToast(result) {
  if (!result || result.no_sync) return null;
  const failed = result.failed || [];
  if (failed.length) {
    const f = failed[0];
    return { text: f.vault ? t("sync.failed_one", { vault: f.vault, reason: f.reason }) : f.reason, kind: "error" };
  }
  const c = result.changes;
  const changes = c ? (c.added || 0) + (c.updated || 0) + (c.deleted || 0) : 0;
  if (changes) return { text: t("settings.synced_toast", { added: c.added || 0, updated: c.updated || 0, deleted: c.deleted || 0 }), kind: "" };
  return { text: t("sync.done"), kind: "" };
}
