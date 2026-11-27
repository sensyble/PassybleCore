// The pure part of the "This vault is only on this device" reminder (local-reminder.js) and the
// create form's notice. Rust decides what is local only and when "Not now" has run out (30 days per
// vault); `status.vaults` carries both as `local_only` and `local_reminder`.

/** The vaults the reminder is about right now: local only, and not hidden by "Not now". */
export function reminderVaults(vaults) {
  return (Array.isArray(vaults) ? vaults : []).filter((v) => v && v.id && v.local_reminder === true);
}

/**
 * What the reminder shows for `status`, or null: never while locked, nor when no vault is due.
 * `target` is the vault "Set up sync" opens; `ids` the vaults "Not now" hides for 30 days.
 */
export function reminderView(status) {
  if (!status || status.locked) return null;
  const due = reminderVaults(status.vaults);
  if (!due.length) return null;
  const target = due.find((v) => v.active) || due[0];
  return {
    count: due.length,
    target,
    ids: due.map((v) => v.id),
    named: (status.vaults || []).length > 1,
    google: !!status.google_available,
  };
}

/**
 * The create form's "Only on this device" notice: unless the new vault gets Google Drive backup
 * (`googleBackup`) or goes into a synced folder (`synced`; unknown counts as not synced).
 */
export function createNoticeShown({ googleBackup, synced }) {
  return !googleBackup && synced !== true;
}
