// Settings → Sync for a vault backed up to Google Drive (src-tauri/src/gdrive.rs): "Delete old versions"
// (earlier copies still open with the old password after a password change; also offered right after one) and
// "Remove vault from Google Drive" (deletes this vault's copy and turns the backup off here; other devices
// that sync through Drive keep their own copy).

import { confirmDialog, errorText, h, icon, invoke, modal, mount, settingsRow, t, toast } from "../lib.js";
import { openExportDialog } from "./export.js";
import { nameConfirmed, oldVersionsText } from "./google-cleanup-model.js";

function rowButton(label, onClick, cls = "") {
  return h("button", { class: `btn small ${cls}`.trim(), type: "button", on: { click: onClick } }, label);
}

/** Deletes the old versions with a progress toast, then reports (`onError(text)`, or a toast). A sign-in Google refused also shows in the Sync section (Rust sends `sync-status`). */
async function deleteOldVersions({ onError = null } = {}) {
  const working = toast(t("google.old_versions_working"), "", 10 * 60 * 1000);
  try {
    const r = await invoke("google_drive_delete_old_versions");
    working.close();
    toast(oldVersionsText(r), "", 9000);
  } catch (e) {
    working.close();
    if (onError) onError(errorText(e));
    else toast(errorText(e), "error");
  }
}

function confirmOldVersions({ title = t("google.old_versions_title"), text = t("google.old_versions_body"), confirm = t("google.old_versions_delete") } = {}) {
  return confirmDialog({ title, text, confirm, iconName: "history" });
}

/** Right after a password change of a Drive-synced vault: one tap deletes the old versions (they still open with the old password). */
export async function offerOldVersionsCleanup() {
  const yes = await confirmOldVersions({
    title: t("google.old_versions_title"),
    text: t("google.after_password_body"),
  });
  if (yes) await deleteOldVersions();
}

/** "Remove vault from Google Drive?": what goes and what stays, Export first, the vault's name typed to confirm. `onRemoved()` once the copy is gone. */
export function openRemoveDialog({ vaultName, onRemoved = null } = {}) {
  const m = modal({ label: t("google.remove_title"), cls: "narrow" });
  const input = h("input", { class: "input", id: "g-remove-name", autocomplete: "off", spellcheck: "false" });
  const error = h("div", { class: "error-text", role: "alert" });
  const status = h("div", { class: "hint", role: "status" });
  const go = h("button", { class: "btn primary danger-fill", type: "submit", disabled: true }, icon("cloudOff"), t("google.remove_confirm"));
  const cancel = h("button", { class: "btn", type: "button", text: t("common.cancel"), on: { click: () => m.close() } });
  input.addEventListener("input", () => {
    go.disabled = !nameConfirmed(input.value, vaultName);
  });
  const form = h(
    "form",
    {
      class: "col",
      on: {
        submit: async (e) => {
          e.preventDefault();
          if (!nameConfirmed(input.value, vaultName)) return;
          mount(error);
          go.disabled = cancel.disabled = input.disabled = true;
          mount(status, icon("sync", "spin"), " ", t("google.remove_working"));
          try {
            await invoke("google_drive_remove", { confirmName: input.value });
            m.close();
            toast(t("settings.google_removed"), "", 9000);
            if (onRemoved) onRemoved();
          } catch (err) {
            mount(status);
            mount(error, errorText(err));
            cancel.disabled = input.disabled = false;
            go.disabled = !nameConfirmed(input.value, vaultName);
          }
        },
      },
    },
    h("div", { class: "row" }, h("span", { class: "modal-icon danger" }, icon("cloudOff")), h("h2", { class: "grow", text: t("google.remove_title") })),
    h("p", { text: t("google.remove_body", { vault: vaultName }) }),
    h("div", { class: "banner" }, icon("alert"), h("span", { class: "grow", text: t("google.remove_other_devices") })),
    h("div", { class: "row" },
      h("span", { class: "grow hint", text: t("google.remove_export_hint") }),
      h("button", { class: "btn small", type: "button", on: { click: () => openExportDialog() } }, icon("upload"), t("google.remove_export"))),
    h("div", { class: "field" }, h("label", { for: "g-remove-name", text: t("google.remove_type_name", { vault: vaultName }) }), input),
    error,
    status,
    h("div", { class: "row modal-actions" }, h("span", { class: "spacer" }), cancel, go),
  );
  mount(m.box, form);
  input.focus();
}

/** The two Drive rows of Settings → Sync. `onRemoved()`: redraw Settings; `onError(text)`: deleting old versions failed. */
export function driveCleanupRows({ vaultName, onRemoved = null, onError = null }) {
  const oldButton = rowButton(t("google.old_versions_button"), async () => {
    if (!(await confirmOldVersions())) return;
    oldButton.disabled = true;
    try {
      await deleteOldVersions({ onError });
    } finally {
      oldButton.disabled = false;
    }
  });
  const removeButton = rowButton(t("google.remove_button"), () => openRemoveDialog({ vaultName, onRemoved }), "danger");
  return [
    settingsRow("history", t("settings.google_old_versions"), {
      value: t("settings.google_old_versions_value"),
      info: t("settings.google_old_versions_info"),
      control: oldButton,
    }),
    settingsRow("cloudOff", t("settings.google_remove"), {
      value: t("settings.google_remove_value"),
      info: t("settings.google_remove_info"),
      control: removeButton,
    }),
  ];
}
