// Settings → Sync → Passyble account: the optional account that Passyble Cloud, Teams and Family
// use. Signing out asks first (shared vaults close on this device, own vaults stay); when a browser
// extension signed in with this app recently, the confirmation also offers to sign it out (ticked).

import { confirmDialog, errorText, h, invoke, mount, settingsRow, t, toast } from "../lib.js";
import { accountState, offersExtensionSignOut } from "./account-model.js";
import { button, openNewDeviceDialog } from "./account-keys.js";
import { orgRoleLabel } from "./teams-model.js";

/**
 * The row; `onChanged()` after signing in or out, `onSignedIn()` after signing in. Signed out,
 * "Approve from another device" signs this PC in with another device's approval.
 */
export function accountRow({ onChanged = () => {}, onSignedIn = () => {} } = {}) {
  const row = settingsRow("user", t("account.title"), { value: t("common.loading"), info: t("account.info") });
  const set = (value, controls, cls = "") => {
    row.valueEl.textContent = value;
    row.valueEl.title = value;
    row.valueEl.className = `set-sub ${cls}`.trim();
    mount(row.controlEl, ...[].concat(controls));
  };

  const render = (view) => {
    const buttons = {
      sign_in: () => button(t("common.sign_in_ellipsis"), signIn, "tonal"),
      sign_out: () => button(t("account.sign_out"), signOut),
      retry: () => button(t("account.retry"), () => load()),
    };
    const text = view.text.key ? t(view.text.key) : view.text.plain;
    const controls = view.actions.map((a) => buttons[a]());
    if (view.state === "signed_out") {
      controls.push(button(t("account_keys.approve_from_device"), () => openNewDeviceDialog({
        onDone: () => {
          onChanged();
          load();
        },
      })));
    }
    set(text, controls, view.state === "error" ? "warn" : "");
  };

  let status = null;
  const load = async () => {
    try {
      status = await invoke("account_status");
      render(accountState({ status, orgLabel: (o) => orgRoleLabel(o.role, o.kind) }));
    } catch (e) {
      console.warn("account_status failed:", e);
      render(accountState({ failed: true }));
    }
  };

  let cancelled = false;
  const signIn = async () => {
    cancelled = false;
    set(t("account.waiting"), button(t("common.cancel"), () => {
      cancelled = true;
      invoke("account_sign_in_cancel").catch(() => {});
    }));
    try {
      const r = await invoke("account_sign_in");
      toast(t("account.signed_in", { email: (r && r.account && r.account.email) || "" }).trim());
      onChanged();
      onSignedIn();
    } catch (e) {
      const code = (e && e.code) || String((e && e.message) || e);
      if (!cancelled && code !== "cancelled") toast(errorText(e), "error");
    }
    load();
  };

  const signOut = async () => {
    // Hidden, it counts as ticked.
    const extension = h("input", { type: "checkbox", checked: true });
    const text = offersExtensionSignOut(status)
      ? h("div", {}, h("p", { text: t("account.sign_out_text") }), h("label", { class: "check" }, extension, t("account.sign_out_extension")))
      : t("account.sign_out_text");
    const ok = await confirmDialog({ title: t("account.sign_out_title"), text, confirm: t("account.sign_out"), iconName: "logOut" });
    if (!ok) return;
    try {
      await invoke("account_sign_out", { signOutExtension: extension.checked });
      toast(t("account.signed_out_toast"));
      onChanged();
    } catch (e) {
      toast(errorText(e), "error");
    }
    load();
  };

  load();
  return row;
}
