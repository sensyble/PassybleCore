// The e-mail reset, locked key sets, key notices and admin recovery of the account key
// (account_keys/reset.rs and admin.rs). "Start fresh" is the last way back in: a 72-hour wait, then
// new keys and a new Emergency Kit. Old vaults stay locked, not deleted.

import { confirmDialog, errorText, formatDate, formatDateTime, h, icon, invoke, modal, mount, passwordField, settingsRow, t, tn, toast } from "../lib.js";
import { adminKeyRow, errorCode, lockedWays, namesKey, resetStep, SECRET_KEY_NEEDED } from "./account-keys-model.js";
import { askFingerprintMatch, button, cancelButton, choice, codeInput, field, formOf, openKitDialog, showKeysDropped, withAccountKey, withFreshSignIn } from "./account-keys.js";
import { newPasswordFields } from "./signin.js";
import { enrolComparing, fingerprintBox, formDialog, requestCodeBox } from "./teams-dialogs.js";

/** "Start fresh": what happens, then the 72-hour wait, then a new password and Emergency Kit. */
export async function openStartFreshDialog({ email = "", onDone = null } = {}) {
  const m = modal({ label: t("account_reset.title") });
  const body = h("div", { class: "col" });
  mount(m.box, h("div", { class: "row" }, h("span", { class: "modal-icon danger" }, icon("alert")), h("h2", { class: "grow", text: t("account_reset.title") })), body);
  mount(body, h("p", { class: "muted", text: t("common.loading") }));

  const explain = () => {
    mount(body,
      h("p", { text: t("account_reset.intro") }),
      h("ul", {},
        h("li", { text: t("account_reset.what_wait") }),
        h("li", { text: t("account_reset.what_locked") }),
        h("li", { text: t("account_reset.what_told") }),
        h("li", { text: t("account_reset.what_after") })),
      h("p", { class: "muted", text: t("account_reset.other_ways") }),
      formOf(async () => {
        const r = await withFreshSignIn(() => invoke("account_reset_start"));
        waiting(r);
      }, t("account_reset.start_button"), [], [cancelButton(m)]));
  };

  const waiting = (r) => {
    const s = resetStep(r);
    if (s.step === "due") {
      due();
      return;
    }
    mount(body,
      h("div", { class: "banner" }, icon("clock"), h("span", { class: "grow", text: s.releaseAt ? t("account_reset.waiting_until", { date: formatDateTime(s.releaseAt) }) : t("account_reset.waiting") })),
      h("p", { text: t("account_reset.waiting_text") }),
      h("div", { class: "row modal-actions" },
        h("button", { class: "link", type: "button", text: t("account_reset.cancel_link"), on: { click: () => { m.close(); openCancelResetDialog(); } } }),
        h("span", { class: "spacer" }),
        h("button", { class: "btn primary", type: "button", text: t("common.close"), on: { click: () => m.close() } })));
  };

  const due = () => {
    const fields = newPasswordFields(t("account_keys.new_password"), { names: () => [email] });
    mount(body,
      h("p", { text: t("account_reset.due_text") }),
      formOf(async () => {
        const password = await fields.check();
        const kit = await withFreshSignIn(() => invoke("account_reset_complete", { password }));
        m.close();
        if (kit && kit.warning) toast(kit.warning, "", 9000);
        // Admin recovery is never joined again on its own: the member is asked per organisation.
        openKitDialog(kit, {
          intro: t("account_reset.kit_intro"),
          onDone: async () => {
            toast(t("account_reset.done"));
            await askRejoinAll(kit && kit.rejoin);
            if (onDone) onDone();
          },
        });
      }, t("account_reset.set_keys"), fields.els, [cancelButton(m)]));
    fields.first.focus();
  };

  try {
    const r = await invoke("account_reset_status");
    if (r && r.waiting) waiting(r);
    else explain();
  } catch (e) {
    mount(body, h("div", { class: "error-text", text: errorText(e) }), h("div", { class: "row modal-actions" }, h("span", { class: "spacer" }), cancelButton(m)));
  }
}

/** "Cancel the reset": with this PC's account key (Windows Hello or the password) or the recovery code. */
export function openCancelResetDialog({ onDone = null } = {}) {
  const m = modal({ label: t("account_reset.cancel_title") });
  const body = h("div", { class: "col" });
  mount(m.box, h("h2", { text: t("account_reset.cancel_title") }), body);
  const finish = () => {
    m.close();
    toast(t("account_keys.push_account_key_reset_cancelled_body"));
    if (onDone) onDone();
  };
  const withDevice = async () => {
    try {
      const r = await withAccountKey((password) => invoke("account_reset_cancel", { password }));
      if (r !== null) finish();
    } catch (e) {
      toast(errorText(e), "error");
    }
  };
  const withCode = () => {
    const code = codeInput();
    mount(body,
      h("p", { text: t("account_reset.cancel_code_intro") }),
      formOf(async () => {
        if (!code.value.trim()) throw new Error(t("account_keys.enter_recovery_code"));
        await invoke("account_reset_cancel", { code: code.value.trim() });
        finish();
      }, t("account_reset.cancel_button"), [field(t("account_keys.recovery_code"), code)], [cancelButton(m)]));
    code.focus();
  };
  mount(body,
    h("p", { text: t("account_reset.cancel_intro") }),
    choice("hello", t("account_reset.cancel_device"), t("account_reset.cancel_device_text"), withDevice),
    choice("key", t("account_keys.forgot_code"), t("account_reset.cancel_code_text"), withCode),
    h("div", { class: "row modal-actions" }, h("span", { class: "spacer" }), cancelButton(m)));
}

export function openLockedListDialog({ onChanged = null } = {}) {
  const m = modal({ label: t("account_reset.locked_title") });
  const list = h("div", { class: "col" });
  mount(m.box,
    h("div", { class: "row" }, h("span", { class: "modal-icon" }, icon("lock")), h("h2", { class: "grow", text: t("account_reset.locked_title") })),
    h("p", { text: t("account_reset.locked_intro") }),
    list,
    h("div", { class: "row modal-actions" }, h("span", { class: "spacer" }), h("button", { class: "btn", type: "button", text: t("common.close"), on: { click: () => m.close() } })));
  const changed = () => {
    load();
    if (onChanged) onChanged();
  };
  const row = (set) => {
    const names = (set.vaults || []).map((v) => v.name);
    const controls = [button(t("account_reset.unlock_short"), () => openLockedUnlockDialog({ set, onDone: changed }), "tonal")];
    if (set.can_delete) controls.push(button(t("account_reset.delete_button"), () => deleteLockedSet(set, changed)));
    return settingsRow("lock", set.fingerprint || set.ak_id, {
      value: [set.locked_at ? t("account_reset.locked_on", { date: formatDate(set.locked_at) }) : null,
        names.length ? t("account_reset.needed_by", { vaults: names.join(", ") }) : t("account_reset.needed_by_none")].filter(Boolean).join(" · "),
      control: controls,
    });
  };
  const load = async () => {
    try {
      const r = await invoke("account_locked_list");
      const sets = (r && r.sets) || [];
      mount(list,
        r && r.offline ? h("p", { class: "muted", text: t("account_reset.locked_offline") }) : null,
        sets.length ? h("div", { class: "set-card" }, sets.map(row)) : h("p", { class: "muted", text: t("account_reset.locked_none") }));
    } catch (e) {
      mount(list, h("div", { class: "error-text", text: errorText(e) }));
    }
  };
  load();
}

async function deleteLockedSet(set, done) {
  const ok = await confirmDialog({ title: t("account_reset.delete_title"), text: t("account_reset.delete_text"), confirm: t("account_reset.delete_button"), danger: true });
  if (!ok) return;
  try {
    const r = await withAccountKey((password) => invoke("account_locked_delete", { akId: set.ak_id, password }));
    if (r === null) return;
    toast(t("account_reset.deleted"));
    if (done) done();
  } catch (e) {
    toast(errorText(e), "error");
  }
}

/** "Unlock" a locked key set; every vault of that set on this PC is then relinked under the current key. */
export async function openLockedUnlockDialog({ set = null, akId = "", vaultName = "", onDone = null } = {}) {
  if (!set) {
    try {
      const r = await invoke("account_locked_list");
      set = ((r && r.sets) || []).find((s) => s.ak_id === akId) || { ak_id: akId, ways: {}, vaults: [] };
    } catch {
      set = { ak_id: akId, ways: {}, vaults: [] };
    }
  }
  const m = modal({ label: t("account_reset.unlock_title") });
  const body = h("div", { class: "col" });
  mount(m.box, h("div", { class: "row" }, h("span", { class: "modal-icon" }, icon("lockOpen")), h("h2", { class: "grow", text: t("account_reset.unlock_title") })), body);
  const names = (set.vaults || []).map((v) => v.name).join(", ") || vaultName;
  const run = async (args) => {
    const r = await withAccountKey((password) => invoke("account_locked_unlock", { akId: set.ak_id, password, ...args }));
    if (r === null) return;
    m.close();
    toast(tn("account_reset.relinked", r.relinked || 0));
    if (r.failed && r.failed.length) toast(t("account_reset.relink_failed", { vaults: r.failed.join(", ") }), "error", 9000);
    if (onDone) onDone();
    if (r.can_delete) {
      const ok = await confirmDialog({ title: t("account_reset.offer_delete_title"), text: t("account_reset.offer_delete_text"), confirm: t("account_reset.delete_button"), danger: true });
      if (ok) deleteLockedSet(set, onDone);
    }
  };
  const withPassword = () => {
    const pw = passwordField({ autocomplete: "off" });
    const sk = h("input", { class: "input mono", type: "text", autocomplete: "off", spellcheck: "false", placeholder: "P1-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX" });
    const skField = field(t("account_reset.old_secret_key"), sk, set.ways && set.ways.secret_key_here ? t("account_reset.old_secret_key_kept") : t("account_reset.old_secret_key_hint"));
    mount(body,
      h("p", { text: t("account_reset.by_password_intro") }),
      formOf(async () => {
        if (!pw.input.value) throw new Error(t("unlock.enter_password"));
        try {
          await run({ by: "password", oldPassword: pw.input.value, oldSecretKey: sk.value.trim() || null });
        } catch (e) {
          if (errorCode(e) === SECRET_KEY_NEEDED) {
            sk.focus();
            throw new Error(t("account_reset.old_secret_key_needed"));
          }
          throw e;
        }
      }, t("account_reset.unlock_button"), [field(t("account_reset.old_password"), pw), skField], [cancelButton(m)]));
    pw.input.focus();
  };
  const withCode = () => {
    const code = codeInput();
    mount(body,
      h("p", { text: t("account_reset.by_code_intro") }),
      formOf(async () => {
        if (!code.value.trim()) throw new Error(t("account_keys.enter_recovery_code"));
        await run({ by: "recovery", code: code.value.trim() });
      }, t("account_reset.unlock_button"), [field(t("account_reset.old_code"), code)], [cancelButton(m)]));
    code.focus();
  };
  const withDevice = async () => {
    try {
      await run({ by: "device" });
    } catch (e) {
      toast(errorText(e), "error");
    }
  };
  const ways = {
    device: () => choice("hello", t("account_reset.by_device"), t("account_reset.by_device_text"), withDevice),
    password: () => choice("lock", t("account_reset.by_password"), t("account_reset.by_password_text"), withPassword),
    recovery: () => choice("key", t("account_reset.by_code"), t("account_reset.by_code_text"), withCode),
    admin: () => choice("lifeBuoy", t("account_reset.by_admin"), t("account_reset.by_admin_text"), () => {
      m.close();
      openAdminKeyDialog({ vaultId: `ak:${set.ak_id}`, onDone });
    }),
  };
  mount(body,
    h("p", { text: names ? t("account_reset.unlock_intro_vaults", { vaults: names }) : t("account_reset.unlock_intro") }),
    lockedWays(set).map((w) => ways[w]()),
    h("div", { class: "row modal-actions" }, h("span", { class: "spacer" }), cancelButton(m)));
}

/** A key notice from Rust (`account-key-notice`): `reset_started`, `key_changed` or `admin_recovery_required`. */
export function openKeyNotice(notice, { onChanged = null } = {}) {
  const n = notice || {};
  if (n.kind === "admin_recovery_required") {
    openRequiredDialog(n, { onChanged });
    return;
  }
  const m = modal({ label: t("account_keys.push_account_key_reset_title") });
  if (n.kind === "reset_started") {
    mount(m.box,
      h("div", { class: "row" }, h("span", { class: "modal-icon danger" }, icon("shieldAlert")), h("h2", { class: "grow", text: t("account_reset.notice_started_title") })),
      h("p", { text: n.release_at ? t("account_reset.notice_started_text", { date: formatDateTime(n.release_at) }) : t("account_reset.notice_started_text_plain") }),
      h("div", { class: "row modal-actions" }, h("span", { class: "spacer" }),
        h("button", { class: "btn", type: "button", text: t("account_reset.it_was_me"), on: { click: () => m.close() } }),
        h("button", { class: "btn danger", type: "button", text: t("account_reset.cancel_button"), on: { click: () => { m.close(); openCancelResetDialog({ onDone: onChanged }); } } })));
    return;
  }
  const dismiss = () => invoke("account_key_notice_dismiss", { akId: n.ak_id || "" }).catch(() => {}).then(() => onChanged && onChanged());
  mount(m.box,
    h("div", { class: "row" }, h("span", { class: "modal-icon danger" }, icon("shieldAlert")), h("h2", { class: "grow", text: t("account_reset.key_changed_title", { date: formatDate(n.at || Date.now()) }) })),
    h("p", { text: t("account_reset.key_changed_text") }),
    h("p", { class: "muted", text: t("account_reset.key_changed_kept") }),
    h("div", { class: "row modal-actions" }, h("span", { class: "spacer" }),
      h("button", { class: "btn", type: "button", text: t("account_reset.locked_short"), on: { click: () => { m.close(); dismiss(); openLockedListDialog({ onChanged }); } } }),
      h("button", { class: "btn primary", type: "button", text: t("common.ok"), on: { click: () => { m.close(); dismiss(); } } })));
}

/**
 * Enrols the account key with `org`'s admin recovery: the admin's fingerprint is compared and pinned
 * before anything is wrapped. Resolves null when cancelled.
 */
function enrolAccountKey(org) {
  return enrolComparing((fingerprint) => withFreshSignIn(() => withAccountKey((password) => invoke("account_admin_recovery_enroll", { org, password, fingerprint }))));
}

/**
 * "Join <org>'s admin recovery again?" after the account key or a vault's key changed: never on its
 * own. `ask`: `{ org, name, admin?, admin_fingerprint? }`; the admin's fingerprint is compared first
 * when it isn't verified on this device. Resolves true once enrolled, null otherwise.
 */
export function askRejoin(ask, { enrol = enrolAccountKey, warning = t("account_admin.warning") } = {}) {
  const name = ask.name || ask.org;
  const admin = ask.admin || t("teams.trust_manager");
  return formDialog({
    title: t("contacts.rejoin_title", { org: name }),
    iconName: "lifeBuoy",
    submit: t("contacts.rejoin_yes"),
    cancel: t("common.not_now"),
    body: [
      h("p", { text: t("contacts.rejoin_text", { org: name }) }),
      ask.admin_fingerprint ? fingerprintBox(t("contacts.rejoin_fingerprint", { admin }), ask.admin_fingerprint) : null,
      h("p", { class: "muted", text: warning }),
    ],
    onSubmit: async () => {
      const r = await enrol(ask.org);
      if (r === null) return null;
      toast(t("account_admin.enrolled_toast", { org: name }));
      return true;
    },
  });
}

async function askRejoinAll(list) {
  for (const ask of Array.isArray(list) ? list : []) await askRejoin(ask);
}

function openRequiredDialog(n, { onChanged = null } = {}) {
  const m = modal({ label: t("account_admin.required_title", { org: n.name || "" }) });
  mount(m.box,
    h("div", { class: "row" }, h("span", { class: "modal-icon" }, icon("lifeBuoy")), h("h2", { class: "grow", text: t("account_admin.required_title", { org: n.name || "" }) })),
    h("p", { text: t("account_admin.required_text", { org: n.name || "" }) }),
    h("p", { class: "muted", text: t("account_admin.warning") }),
    formOf(async () => {
      const r = await enrolAccountKey(n.org);
      if (r === null) return;
      m.close();
      toast(t("account_admin.enrolled_toast", { org: n.name || "" }));
      if (onChanged) onChanged();
    }, t("account_admin.enrol"), [], [h("button", { class: "btn", type: "button", text: t("common.later"), on: { click: () => m.close() } })]));
}

// The request sent in this session (the dialog may be closed while waiting for the admin).
let pending = null;

/** "Ask your Team or Family admin": once approved, a new password and Emergency Kit, or the old vaults relinked. */
export async function openAdminKeyDialog({ email = "", vaultId = "", onDone = null } = {}) {
  const m = modal({ label: t("account_admin.dialog_title") });
  const body = h("div", { class: "col" });
  mount(m.box, h("div", { class: "row" }, h("span", { class: "modal-icon" }, icon("lifeBuoy")), h("h2", { class: "grow", text: t("account_admin.dialog_title") })), body);
  mount(body, h("p", { class: "muted", text: t("common.loading") }));
  let status;
  try {
    status = await invoke("account_admin_recovery_status");
  } catch (e) {
    mount(body, h("div", { class: "error-text", text: errorText(e) }), h("div", { class: "row modal-actions" }, h("span", { class: "spacer" }), cancelButton(m)));
    return;
  }
  const want = vaultId || (status.ak_id ? `ak:${status.ak_id}` : "");
  const orgs = (status.orgs || []).filter((o) => o.enrolment === want || (o.locked || []).some((l) => l.vault_id === want));

  const request = () => {
    if (!orgs.length) {
      mount(body, h("p", { text: t("account_admin.none") }), h("div", { class: "row modal-actions" }, h("span", { class: "spacer" }), cancelButton(m)));
      return;
    }
    const select = h("select", { class: "input" }, orgs.map((o) => h("option", { value: o.org, text: o.name })));
    mount(body,
      h("p", { text: t("account_admin.request_text") }),
      orgs.length > 1 ? field(t("recoveryadmin.which_team"), select) : null,
      h("p", { class: "muted", text: t("recoveryadmin.request_note") }),
      formOf(async () => {
        const org = select.value || orgs[0].org;
        const r = await invoke("account_admin_recovery_request", { org, vaultId: want });
        pending = { org, requestId: r.request_id, vaultId: r.vault_id, code: r.code };
        finish();
      }, t("recoveryadmin.send_request"), [], [cancelButton(m)]));
  };

  const finish = () => {
    const current = namesKey(pending.vaultId, status.ak_id);
    const fields = current ? newPasswordFields(t("account_keys.new_password"), { names: () => [email] }) : null;
    mount(body,
      h("div", { class: "banner" }, icon("clock"), h("span", { class: "grow", text: t("recoveryadmin.waiting") })),
      pending.code ? requestCodeBox(pending.code) : null,
      h("p", { text: current ? t("account_admin.finish_current") : t("account_admin.finish_locked") }),
      formOf(async () => {
        const newPassword = fields ? await fields.check() : null;
        const run = (check) => withFreshSignIn(() => withAccountKey((password) => invoke("account_admin_recovery_finish", { org: pending.org, requestId: pending.requestId, newPassword, password, ...check })));
        let r = await run({});
        if (r === null) return;
        // The key from the approval is used only once its fingerprint was checked.
        if (r.state === "check") {
          const ok = await askFingerprintMatch(r.fingerprint);
          if (ok === null) return;
          r = await run({ fingerprint: r.fingerprint, matches: ok });
          if (r === null) return;
        }
        pending = null;
        m.close();
        if (r.state === "dropped") {
          showKeysDropped();
          return;
        }
        if (r.kind === "current") {
          if (r.warning) toast(r.warning, "", 9000);
          openKitDialog(r, { intro: t("account_admin.kit_intro"), onDone: () => { toast(t("account_keys.reset_done")); if (onDone) onDone(); } });
        } else {
          toast(tn("account_reset.relinked", r.relinked || 0));
          if (onDone) onDone();
        }
      }, current ? t("account_keys.reset_button") : t("account_reset.unlock_button"), fields ? fields.els : [],
      [h("button", { class: "link", type: "button", text: t("recoveryadmin.new_request"), on: { click: () => { pending = null; request(); } } }),
        h("button", { class: "btn", type: "button", text: t("common.later"), on: { click: () => m.close() } })]));
    if (fields) fields.first.focus();
  };

  if (pending && pending.vaultId === want) finish();
  else request();
}

/**
 * The rows of Teams and Family, Admin-assisted recovery, for an account with a Passyble password.
 * Resolves `false` when the account has none (the caller shows the vault rows instead).
 */
export async function adminKeyRows(card, { reload = () => {}, failed = (e) => toast(errorText(e), "error") } = {}) {
  let s;
  try {
    s = await invoke("account_admin_recovery_status");
  } catch {
    return false;
  }
  if (!s || !s.has_keys) return false;
  if (!card.isConnected) return true;
  for (const r of s.orgs || []) {
    const view = adminKeyRow(r);
    if (view.state === "hidden") continue;
    const controls = view.actions.map((a) => a === "enrol"
      ? button(view.state === "again" ? t("account_admin.enrol_again") : t("account_admin.enrol"), async () => {
        if (view.state === "again") {
          // The member is asked with the admin's fingerprint.
          try {
            if (await askRejoin(r)) reload();
          } catch (e) {
            failed(e);
          }
          return;
        }
        const ok = await confirmDialog({ title: t("account_admin.enrol_title", { org: r.name }), text: t("account_admin.warning"), confirm: t("account_admin.enrol"), iconName: "lifeBuoy" });
        if (!ok) return;
        try {
          const done = await enrolAccountKey(r.org);
          if (done === null) return;
          toast(t("account_admin.enrolled_toast", { org: r.name }));
          reload();
        } catch (e) {
          failed(e);
        }
      }, "tonal")
      : button(t("recoveryadmin.withdraw"), async () => {
        const ok = await confirmDialog({ title: t("recoveryadmin.withdraw_title", { org: r.name }), text: t("recoveryadmin.withdraw_text"), confirm: t("recoveryadmin.withdraw") });
        if (!ok) return;
        try {
          await invoke("account_admin_recovery_withdraw", { org: r.org });
          toast(t("recoveryadmin.withdrawn"));
          reload();
        } catch (e) {
          failed(e);
        }
      }));
    const value = {
      enrolled: r.enrolled_at ? t("recoveryadmin.enrolled_on", { date: formatDate(r.enrolled_at) }) : t("recoveryadmin.enrolled"),
      required: t("account_admin.state_required"),
      again: t("account_admin.state_again"),
      offered: t("recoveryadmin.not_enrolled"),
    }[view.state];
    card.append(settingsRow("lifeBuoy", t("recoveryadmin.row", { org: r.name }), {
      value,
      valueClass: view.state === "enrolled" ? "ok" : view.state === "required" ? "warn" : "",
      info: t("account_admin.info"),
      control: controls,
    }));
  }
  return true;
}
