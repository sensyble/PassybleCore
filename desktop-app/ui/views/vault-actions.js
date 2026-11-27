// A vault's own actions, shared by the vault switcher, the locked vault list and Settings: rename,
// show in folder, remove from this computer, and delete from the signed-in account.

import { errorText, h, icon, invoke, modal, mount, t, toast } from "../lib.js";
import { openExportDialog } from "./export.js";
import { canExportFirst, deleteNameConfirmed, vaultActionKeys } from "./vault-actions-model.js";

export function openRenameDialog(vault, onDone = null) {
  const m = modal({ label: t("vaults.rename_title"), cls: "narrow" });
  const input = h("input", { class: "input", id: "v-rename", value: vault.name, maxlength: "80", spellcheck: "false", autocomplete: "off" });
  const error = h("div", { class: "error-text", role: "alert" });
  const save = h("button", { class: "btn primary", type: "submit", text: t("common.save") });
  mount(m.box, h("form", {
    class: "col",
    on: {
      submit: async (e) => {
        e.preventDefault();
        const name = input.value.trim();
        if (name === vault.name) return m.close();
        save.disabled = true;
        try {
          await invoke("rename_vault", { id: vault.id, name });
          m.close();
          if (onDone) onDone();
        } catch (err) {
          mount(error, errorText(err));
          save.disabled = false;
        }
      },
    },
  },
  h("h2", { text: t("vaults.rename_title") }),
  h("div", { class: "field" }, h("label", { for: "v-rename", text: t("vaults.name") }), input),
  error,
  h("div", { class: "row modal-actions" }, h("span", { class: "spacer" }),
    h("button", { class: "btn", type: "button", text: t("common.cancel"), on: { click: () => m.close() } }), save)));
  input.focus();
  input.select();
}

export async function revealVault(vault) {
  try {
    await invoke("reveal_vault", { id: vault.id });
  } catch (e) {
    toast(errorText(e), "error");
  }
}

/** Takes the vault off this computer's list; the file stays, and the toast's Undo puts it back. */
export async function removeVault(vault, onDone = null) {
  try {
    await invoke("remove_vault", { id: vault.id });
    if (onDone) onDone(false);
    toast(t("vaults.removed", { vault: vault.name }), "", 0, {
      action: {
        label: t("common.undo"),
        icon: "undo",
        onClick: () =>
          invoke("undo_remove_vault", { id: vault.id })
            .then(() => onDone && onDone(true))
            .catch((e) => toast(errorText(e), "error")),
      },
    });
  } catch (e) {
    toast(errorText(e), "error");
  }
}

/**
 * Confirms "Delete vault from your account": the vault's name is typed, and Export is offered first
 * for the open vault (`locked`: it is soft-locked).
 */
export function openDeleteFromAccountDialog({ vault, locked = false, onDeleted = null }) {
  const m = modal({ label: t("vaults.delete_account_title"), cls: "narrow" });
  const input = h("input", { class: "input", id: "v-delete-name", autocomplete: "off", spellcheck: "false" });
  const error = h("div", { class: "error-text", role: "alert" });
  const status = h("div", { class: "hint", role: "status" });
  const go = h("button", { class: "btn primary danger-fill", type: "submit", disabled: true }, icon("trash"), t("vaults.delete_account_confirm"));
  const cancel = h("button", { class: "btn", type: "button", text: t("common.cancel"), on: { click: () => m.close() } });
  input.addEventListener("input", () => {
    go.disabled = !deleteNameConfirmed(input.value, vault.name);
  });
  const exportRow = canExportFirst(vault, locked)
    ? h("div", { class: "row" },
        h("span", { class: "grow hint", text: t("vaults.delete_account_export_hint") }),
        h("button", { class: "btn small", type: "button", on: { click: () => openExportDialog() } }, icon("upload"), t("google.remove_export")))
    : h("p", { class: "hint", text: t("vaults.delete_account_open_first") });
  mount(m.box, h("form", {
    class: "col",
    on: {
      submit: async (e) => {
        e.preventDefault();
        if (!deleteNameConfirmed(input.value, vault.name)) return;
        mount(error);
        go.disabled = cancel.disabled = input.disabled = true;
        mount(status, icon("sync", "spin"), " ", t("vaults.delete_account_working"));
        try {
          await invoke("account_vault_delete", { id: vault.id, confirmName: input.value });
          m.close();
          toast(t("vaults.delete_account_done", { vault: vault.name }), "", 9000);
          if (onDeleted) onDeleted();
        } catch (err) {
          mount(status);
          mount(error, errorText(err));
          cancel.disabled = input.disabled = false;
          go.disabled = !deleteNameConfirmed(input.value, vault.name);
        }
      },
    },
  },
  h("div", { class: "row" }, h("span", { class: "modal-icon danger" }, icon("trash")), h("h2", { class: "grow", text: t("vaults.delete_account_title") })),
  h("p", { text: t("vaults.delete_account_body", { vault: vault.name }) }),
  h("div", { class: "banner" }, icon("alert"), h("span", { class: "grow", text: t("vaults.delete_account_devices") })),
  exportRow,
  h("div", { class: "field" }, h("label", { for: "v-delete-name", text: t("google.remove_type_name", { vault: vault.name }) }), input),
  error,
  status,
  h("div", { class: "row modal-actions" }, h("span", { class: "spacer" }), cancel, go)));
  input.focus();
}

/**
 * Menu entries `[icon, label, run, cls]` for `vault`. `onChanged()`: draw the list again;
 * `onRename(vault)` replaces the dialog; `locked`: the open vault is soft-locked.
 */
export function vaultMenuActions(vault, { onChanged = null, onRename = null, locked = false } = {}) {
  const changed = () => onChanged && onChanged();
  const entries = {
    rename: ["edit", t("vaults.rename_ellipsis"), () => (onRename ? onRename(vault) : openRenameDialog(vault, changed))],
    reveal: ["folder", t("vaults.show_in_folder"), () => revealVault(vault)],
    remove: ["close", t("vaults.remove_here"), () => removeVault(vault, changed)],
    delete_account: ["trash", t("vaults.delete_account"), () => openDeleteFromAccountDialog({ vault, locked, onDeleted: changed }), "danger"],
  };
  return vaultActionKeys(vault).map((key) => entries[key]);
}
