// Admin-assisted recovery (Teams only, opt-in): a member who enrolled and forgot the master password asks a Team
// admin from the unlock screen's recovery dialog. The request goes out (`admin_recovery_request`, works locked); once
// an admin approved it, the member sets a new master password here (`admin_recovery_finish`). The admin never sees the
// vault's passwords or the new master password. The request's code shows big: the member reads it to the admin on a
// call, and the admin types it to approve.

import { errorText, h, icon, invoke, modal, mount, t, toast } from "../lib.js";
import { newPasswordFields } from "./signin.js";
import { afterPasswordChange } from "./password-change.js";
import { requestCodeBox } from "./teams-dialogs.js";

// The request sent in this session (the dialog may be closed while waiting for the admin).
let pending = null;

/**
 * The link for the recovery dialog: hidden unless the signed-in account is in a Team.
 * `onUnlocked()` once the new password is set; `onOpen()` before the dialog opens (to close the other).
 */
export function adminRecoveryLink({ onUnlocked = () => {}, onOpen = () => {} } = {}) {
  const link = h("button", { class: "link", type: "button", hidden: true, text: t("recoveryadmin.ask_admin") });
  let status = null;
  invoke("account_status")
    .then((s) => {
      status = s;
      link.hidden = !(s && s.signed_in && s.account && (s.orgs || []).some((o) => o.kind === "team"));
    })
    .catch(() => {});
  link.addEventListener("click", () => {
    onOpen();
    openAdminRecoveryDialog(status, { onUnlocked });
  });
  return link;
}

export function openAdminRecoveryDialog(status, { onUnlocked = () => {} } = {}) {
  let step = pending ? "finish" : "request";
  const m = modal({ label: t("recoveryadmin.dialog_title"), escape: () => step !== "busy" });
  const body = h("div", { class: "col" });
  mount(m.box, h("div", { class: "row" }, h("span", { class: "modal-icon" }, icon("lifeBuoy")), h("h2", { class: "grow", text: t("recoveryadmin.dialog_title") })), body);
  const error = h("div", { class: "error-text", role: "alert" });
  const teams = ((status && status.orgs) || []).filter((o) => o.kind === "team");

  const requestStep = () => {
    step = "request";
    const org = h("select", { class: "input", id: "ar-org" }, teams.map((o) => h("option", { value: o.id, text: o.name })));
    const send = h("button", { class: "btn primary", type: "submit" }, t("recoveryadmin.send_request"));
    mount(body,
      h("p", { text: t("recoveryadmin.request_text") }),
      teams.length > 1 ? h("div", { class: "field" }, h("label", { for: "ar-org", text: t("recoveryadmin.which_team") }), org) : null,
      h("p", { class: "muted", text: t("recoveryadmin.request_note") }),
      error,
      h("form", {
        class: "row modal-actions",
        on: {
          submit: async (e) => {
            e.preventDefault();
            error.textContent = "";
            send.disabled = true;
            try {
              const orgId = org.value || (teams[0] && teams[0].id);
              const r = await invoke("admin_recovery_request", { org: orgId, account: status.account.id });
              pending = { requestId: r.request_id, org: orgId, code: r.code };
              finishStep();
            } catch (err) {
              error.textContent = errorText(err);
              send.disabled = false;
            }
          },
        },
      }, h("span", { class: "spacer" }), h("button", { class: "btn", type: "button", text: t("common.cancel"), on: { click: () => m.close() } }), send));
    send.focus();
  };

  const finishStep = () => {
    step = "finish";
    const fields = newPasswordFields(t("recovery.new_password"), { activeVault: true });
    const go = h("button", { class: "btn primary", type: "submit" }, t("recovery.set_password"));
    mount(body,
      h("div", { class: "banner" }, icon("clock"), h("span", { class: "grow", text: t("recoveryadmin.waiting") })),
      pending.code ? requestCodeBox(pending.code) : null,
      h("p", { text: t("recoveryadmin.finish_text") }),
      h("form", {
        class: "col",
        on: {
          submit: async (e) => {
            e.preventDefault();
            error.textContent = "";
            go.disabled = true;
            step = "busy";
            try {
              const next = await fields.checkPolicy();
              const r = await invoke("admin_recovery_finish", { org: pending.org, requestId: pending.requestId, newPassword: next });
              fields.clear();
              pending = null;
              m.close();
              toast(t("recovery.password_set"));
              onUnlocked();
              // The vault has a new key: a new recovery code, and joining admin recovery again.
              afterPasswordChange(r);
            } catch (err) {
              step = "finish";
              error.textContent = errorText(err);
              go.disabled = false;
            }
          },
        },
      },
      fields.els,
      error,
      h("div", { class: "row modal-actions" },
        h("button", { class: "link", type: "button", text: t("recoveryadmin.new_request"), on: { click: () => { pending = null; requestStep(); } } }),
        h("span", { class: "spacer" }),
        h("button", { class: "btn", type: "button", text: t("common.later"), on: { click: () => m.close() } }),
        go)));
    fields.first.focus();
  };

  if (step === "finish") finishStep();
  else requestStep();
}
