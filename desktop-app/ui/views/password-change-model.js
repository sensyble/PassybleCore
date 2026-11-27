// What a master password change tells the user afterwards: every change gives the vault a new key,
// so old copies a service keeps, a recovery code and admin recovery enrolments held the old key. Pure.

import { t, tn } from "../i18n.js";

/** The words for what the Passyble Server did with its old versions (`purge` of the answer), or null. */
export function purgeText(purge) {
  if (!purge) return null;
  switch (purge.state) {
    case "dropped": {
      const n = Number(purge.count) || 0;
      return n > 0 ? tn("password_change.purged", n) : t("password_change.purged_none");
    }
    case "kept_until_expiry":
      return t("password_change.server_too_old");
    case "not_owner":
      return t("password_change.not_owner");
    case "not_uploaded":
      return t("password_change.not_uploaded");
    case "failed":
      return t("password_change.purge_failed", { error: purge.error || "" });
    default:
      return null;
  }
}

/** For a vault Google Drive or a WebDAV service keeps old copies of (`old_copies`): what that means. */
export function oldCopiesText(answer) {
  switch (answer && answer.old_copies) {
    case "google_drive":
      return t("password_change.drive_keeps");
    case "webdav":
      return t("password_change.webdav_keeps");
    default:
      return null;
  }
}

/**
 * Everything to do after a password change: `notes` (lines to show), `newCode` (offer a new recovery
 * code: the old one was dropped), `rejoin` (`[{ org, name }]`: ask about joining that organisation's
 * admin recovery again, only on yes) and `cleanDrive` (offer to delete old Google Drive versions;
 * they still open with the old password, and that offer says so, so there is no note).
 */
export function followUps(answer) {
  const a = answer || {};
  const cleanDrive = a.old_copies === "google_drive";
  return {
    notes: [purgeText(a.purge), cleanDrive ? null : oldCopiesText(a)].filter(Boolean),
    newCode: a.new_recovery_code === true,
    rejoin: (Array.isArray(a.rejoin_admin_recovery) ? a.rejoin_admin_recovery : []).filter((o) => o && o.org),
    cleanDrive,
  };
}
