// After a vault's master password change: what the old key leaves behind (password-change-model.js
// `followUps`). A new recovery code is offered right away; each organisation whose admin recovery
// held the old key asks to be joined again, only on yes; Google Drive offers deleting old versions.

import { invoke, t, toast } from "../lib.js";
import { askRejoin } from "./account-reset.js";
import { offerOldVersionsCleanup } from "./google-cleanup.js";
import { followUps } from "./password-change-model.js";
import { openCreateRecoveryDialog } from "./recovery.js";
import { enrolComparing } from "./teams-dialogs.js";

/**
 * The follow-ups of password change answer `answer`. `offerCode`: false where the caller offers the
 * new recovery code itself. Resolves when the user went through them.
 */
export async function afterPasswordChange(answer, { offerCode = true, vaultName = "" } = {}) {
  const f = followUps(answer);
  for (const note of f.notes) toast(note, "", 9000);
  if (offerCode && f.newCode) {
    await new Promise((resolve) => openCreateRecoveryDialog({
      askPassword: false,
      vaultName,
      intro: t("password_change.new_code_intro"),
      skipLabel: t("common.not_now"),
      onDone: resolve,
    }));
  }
  for (const o of f.rejoin) {
    await askRejoin(o, {
      warning: t("recoveryadmin.enrol_text", { org: o.name || o.org }),
      enrol: (org) => enrolComparing((fingerprint) => invoke("admin_recovery_enroll", { org, fingerprint })),
    });
  }
  if (f.cleanDrive) await offerOldVersionsCleanup();
}
