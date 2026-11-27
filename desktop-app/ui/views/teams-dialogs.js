// Dialogs of Teams and Family: comparing fingerprints, moving or copying an item to another vault, a direct share,
// a secure send, an emergency access contact. Each resolves when it closed.
// Nothing here ever shows a password or a key.
//
// Pinned contact keys: a key is wrapped only to people whose fingerprint this user compared (kept as pins in the
// home vault). A command that would wrap to someone not compared yet answers `needs_compare`; `compareFirst` and
// `openNeedsCompareDialog` show the comparison (a loud warning when their keys changed) and run the command again
// with the compared fingerprint, which pins them.

import { confirmDialog, errorText, h, icon, invoke, modal, mount, settingsRow, t, toast, tx } from "../lib.js";
import { withAccountKey } from "./account-keys.js";
import {
  compareFingerprints,
  compareList,
  EMERGENCY_WAIT_HOURS,
  emergencyAccessLabel,
  fingerprintText,
  itemVaultId,
  roleHint,
  roleLabel,
  SEND_EXPIRY_DAYS,
  SEND_VIEWS,
  shareTargets,
  sharingOutsideAllowed,
  waitText,
} from "./teams-model.js";

let uid = 0;
const nextId = (p) => `${p}-${++uid}`;

export function labelled(label, input, hint = null) {
  const id = input.id || nextId("tf");
  input.id = id;
  return h("div", { class: "field" }, h("label", { for: id, text: label }), input, hint ? h("span", { class: "hint", text: hint }) : null);
}

export function selectOf(options, value, props = {}) {
  const el = h("select", { class: "input", ...props }, options.map(([v, text, disabled]) => h("option", { value: v === null ? "" : String(v), text, disabled: !!disabled })));
  el.value = value === null || value === undefined ? "" : String(value);
  return el;
}

export function roleSelect(value = "edit", { roles = ["manage", "edit", "view", "fill"], none = null, props = {} } = {}) {
  const el = h("select", { class: "input", ...props },
    none ? h("option", { value: "", text: none }) : null,
    roles.map((r) => h("option", { value: r, text: roleLabel(r), title: roleHint(r) })));
  el.value = value || "";
  return el;
}

/** A form dialog. `onSubmit()` may throw (the message shows in the dialog). Resolves what it returned, or null when cancelled. */
export function formDialog({ title, iconName = "users", body = [], submit = t("common.save"), onSubmit, danger = false, cls = "narrow", cancel = t("common.cancel") }) {
  return new Promise((resolve) => {
    let result = null;
    const m = modal({ label: title, cls, onClose: () => resolve(result) });
    const error = h("div", { class: "error-text", role: "alert" });
    const go = h("button", { class: `btn primary${danger ? " danger-fill" : ""}`, type: "submit" }, submit);
    const form = h("form", {
      class: "col",
      on: {
        submit: async (e) => {
          e.preventDefault();
          error.textContent = "";
          go.disabled = true;
          try {
            result = await onSubmit();
            if (result === undefined) result = true;
            m.close();
          } catch (err) {
            error.textContent = errorText(err);
            go.disabled = false;
          }
        },
      },
    },
    body,
    error,
    h("div", { class: "row modal-actions" },
      h("span", { class: "spacer" }),
      h("button", { class: "btn", type: "button", text: cancel, on: { click: () => m.close() } }),
      go));
    mount(m.box,
      h("div", { class: "row" }, h("span", { class: `modal-icon${danger ? " danger" : ""}` }, icon(iconName)), h("h2", { class: "grow", text: title })),
      form);
    const first = form.querySelector("input:not([type=checkbox]):not([type=radio]), select, textarea");
    (first || go).focus();
  });
}

/**
 * The comparison code of the member's own recovery request, big, to read out to an admin on a call; the admin
 * types it to approve.
 */
export function requestCodeBox(code) {
  return h("div", { class: "col" },
    h("div", { class: "fingerprint recovery-code" },
      h("div", { class: "label", text: t("recoveryadmin.code_label") }),
      h("div", { class: "fp selectable mono", text: code })),
    h("p", { text: t("recoveryadmin.code_text") }));
}

export function fingerprintBox(label, fp) {
  return h("div", { class: "fingerprint" },
    h("div", { class: "label", text: label }),
    h("div", { class: "fp selectable mono", text: fingerprintText(fp, 4) }));
}

/** An unanchored members list: the manager who signed it and their fingerprint; "I compared it" trusts it (`shared_trust_confirm`). */
export async function openTrustDialog(vault, info = null) {
  let details = info;
  if (!details) details = await invoke("shared_vault_info", { vaultId: vault.id }).catch(() => null);
  const i = (details && details.info) || {};
  const signer = i.signed_by || t("teams.trust_manager");
  const fp = i.signer_fingerprint || "";
  const pin = details && details.signer_status;
  const ok = await formDialog({
    title: t("teams.trust_title", { vault: vault.name }),
    iconName: "shieldAlert",
    submit: t("teams.trust_confirm"),
    body: [
      pin === "changed" ? changedBanner(signer) : null,
      h("p", {}, tx("teams.trust_text", { manager: h("strong", { class: "selectable", text: signer }) })),
      fp ? fingerprintBox(t("teams.trust_fingerprint", { manager: signer }), fp) : h("div", { class: "banner warn", text: t("teams.trust_no_fingerprint") }),
      h("p", { class: "muted", text: t("teams.trust_how") }),
    ],
    onSubmit: async () => {
      // Compared: the manager's keys are pinned too (best effort: their keys may not be listed).
      if (fp && pin && pin !== "pinned") await invoke("shared_signer_pin", { vaultId: vault.id, fingerprint: fp }).catch(() => null);
      await invoke("shared_trust_confirm", { vaultId: vault.id });
      toast(t("teams.trust_done", { vault: vault.name }));
      return true;
    },
  });
  return !!ok;
}

/** The loud warning for keys that changed since this user compared them. */
function changedBanner(name) {
  return h("div", { class: "banner error", role: "alert" }, icon("shieldAlert"), h("span", { class: "grow", text: t("contacts.changed_warning", { person: name }) }));
}

/**
 * Confirm this person's keys: the fingerprint received next to what they read out (typed or pasted), group by group.
 * Confirm needs a match, or "We compared it" ticked. `person.changed`: other keys than compared before (loud warning
 * first). Resolves the result of `onConfirm(fingerprint)`, or null.
 */
export function openConfirmKeysDialog(person, onConfirm) {
  const typed = h("input", { class: "input mono", spellcheck: "false", autocomplete: "off", placeholder: t("teams.confirm_typed_placeholder") });
  const byEye = h("input", { type: "checkbox" });
  const grid = h("div", { class: "fp-compare", role: "group", "aria-label": t("teams.confirm_compare") });
  const state = h("div", { class: "hint", role: "status", "aria-live": "polite" });
  const paint = () => {
    const c = compareFingerprints(person.fingerprint, typed.value);
    mount(grid,
      h("div", { class: "fp-col" }, h("div", { class: "label", text: t("teams.confirm_received") }),
        h("div", { class: "fp-groups mono" }, c.groups.map((g) => h("span", { class: "fp-g", text: g.expected })))),
      h("div", { class: "fp-col" }, h("div", { class: "label", text: t("teams.confirm_they_read") }),
        h("div", { class: "fp-groups mono" }, c.groups.map((g) => h("span", {
          class: `fp-g${g.typed ? (g.match ? " ok" : " bad") : " empty"}`,
          text: g.typed || "····",
          "aria-label": g.typed ? (g.match ? t("teams.confirm_group_ok", { group: g.typed }) : t("teams.confirm_group_bad", { group: g.typed })) : null,
        })))));
    state.textContent = !typed.value.trim()
      ? ""
      : c.match ? t("teams.confirm_match") : c.complete ? t("teams.confirm_mismatch") : t("teams.confirm_partial");
    state.className = `hint${c.match ? " ok-text" : c.complete ? " error-text" : ""}`;
  };
  typed.addEventListener("input", paint);
  paint();
  const name = person.name || person.account;
  return formDialog({
    title: t("teams.confirm_title", { person: name }),
    iconName: "shield",
    cls: "",
    submit: t("teams.confirm_submit"),
    body: [
      person.changed ? changedBanner(name) : null,
      person.intro ? h("p", { class: "muted", text: person.intro }) : null,
      h("p", {}, tx("teams.confirm_text", { person: h("strong", { class: "selectable", text: name }) })),
      grid,
      labelled(t("teams.confirm_typed"), typed),
      state,
      h("label", { class: "check" }, byEye, t("teams.confirm_by_eye")),
      h("p", { class: "faint", text: t("teams.confirm_why") }),
    ],
    onSubmit: async () => {
      const c = compareFingerprints(person.fingerprint, typed.value);
      if (!c.match && !byEye.checked) throw new Error(typed.value.trim() && c.complete ? t("teams.confirm_mismatch") : t("teams.confirm_need_compare"));
      return onConfirm(person.fingerprint);
    },
  });
}

/**
 * A command answered `needs_compare` (one entry): the comparison dialog, then `run(fingerprint)` again, which pins
 * the keys. Resolves `run`'s result, or null when cancelled.
 */
export function compareFirst(needs, run, { name = "", intro = null } = {}) {
  const c = compareList(needs)[0];
  if (!c) return Promise.resolve(null);
  return openConfirmKeysDialog({
    account: c.account,
    name: name || c.person || c.account,
    fingerprint: c.fingerprint,
    changed: c.status === "changed",
    intro,
  }, run);
}

/**
 * An admin recovery enrolment, compare first: `run(fingerprint)` enrols (`null` the first time) and runs again with
 * the compared fingerprint while it answers `needs_compare`. Nothing is enrolled to an admin the member hasn't compared.
 */
export async function enrolComparing(run) {
  const r = await run(null);
  if (!r || !r.needs_compare) return r;
  return compareFirst(r.needs_compare, run, { intro: t("contacts.recovery_intro") });
}

/**
 * The people an access change left out (`needs_compare`): keys not verified, or changed (loud warning). Each row has
 * Compare; `onCompare(entry, fingerprint)` runs once they match. `names`: account id to a name.
 */
export function openNeedsCompareDialog(needs, { names = {}, onCompare }) {
  const entries = compareList(needs);
  if (!entries.length) return Promise.resolve(null);
  return new Promise((resolve) => {
    const m = modal({ label: t("contacts.needs_title"), onClose: () => resolve(true) });
    const card = h("div", { class: "set-card" });
    const done = new Set();
    const paint = () => mount(card, entries.map((c) => {
      const name = names[c.account] || c.person || c.account;
      const changed = c.status === "changed";
      const ok = done.has(c.account);
      const compare = h("button", {
        class: "btn small tonal",
        type: "button",
        text: t("teams.compare"),
        on: {
          click: async () => {
            const r = await openConfirmKeysDialog({ account: c.account, name, fingerprint: c.fingerprint, changed }, (fp) => onCompare(c, fp));
            if (r === null) return;
            done.add(c.account);
            paint();
          },
        },
      });
      return settingsRow(changed ? "shieldAlert" : "user", h("span", { class: "ellipsis selectable", text: name }), {
        value: ok ? t("contacts.verified") : changed ? t("contacts.changed_row") : t("contacts.compare_row"),
        valueClass: ok ? "ok" : changed ? "warn danger" : "warn",
        info: t("teams.member_fingerprint", { fingerprint: fingerprintText(c.fingerprint) }),
        control: ok ? null : compare,
      });
    }));
    paint();
    mount(m.box,
      h("div", { class: "row" }, h("span", { class: "modal-icon warn" }, icon("shield")), h("h2", { class: "grow", text: t("contacts.needs_title") })),
      h("p", { class: "muted", text: t("contacts.needs_text") }),
      card,
      h("div", { class: "row modal-actions" }, h("span", { class: "spacer" }),
        h("button", { class: "btn primary", type: "button", text: t("common.close"), on: { click: () => m.close() } })));
  });
}

/**
 * "Move to vault" / "Copy to vault" for `item` (`item_share`): target vaults (editable, not the item's own, not a
 * Team's vault while its password rules turn sharing off) and who will see it there. `policy`: `password_policy`
 * (`blocked_vaults`, `sharing_note`). Resolves `{ item_id, vault }` or null.
 */
export function openItemShareDialog(item, vaults, mode = "move", policy = null) {
  const blocked = (policy && policy.blocked_vaults) || [];
  let current = mode;
  const list = h("div", { class: "export-formats", role: "radiogroup", "aria-label": t("share.target") });
  let target = null;
  const segBtns = {};
  const seg = h("div", { class: "segmented", role: "radiogroup", "aria-label": t("share.mode") },
    ["move", "copy"].map((m) => (segBtns[m] = h("button", {
      type: "button",
      role: "radio",
      text: m === "move" ? t("share.move") : t("share.copy"),
      on: { click: () => { current = m; paint(); } },
    }))));
  const note = h("p", { class: "faint" });
  const paint = () => {
    for (const [m, b] of Object.entries(segBtns)) {
      b.classList.toggle("active", m === current);
      b.setAttribute("aria-checked", String(m === current));
    }
    const targets = shareTargets(item, vaults, current, blocked);
    if (!targets.some((v) => v.id === target)) target = targets.length ? targets[0].id : null;
    mount(list, targets.length
      ? targets.map((v) => {
          const on = v.id === target;
          return h("button", {
            class: `export-format${on ? " on" : ""}`,
            type: "button",
            role: "radio",
            "aria-checked": String(on),
            on: { click: () => { target = v.id; paint(); } },
          }, h("span", { class: "merge-radio", "aria-hidden": "true" }, on ? icon("check") : null),
          h("span", { class: "col grow" }, h("span", { class: "t", text: v.name }),
            h("span", { class: "faint", text: v.home ? t("share.home_vault") : [roleLabel(v.role), v.kind === "direct" ? t("teams.vault_kind_direct") : ""].filter(Boolean).join(" · ") })));
        })
      : h("div", { class: "banner", text: t("share.no_targets") }));
    const chosen = vaults.find((v) => v.id === target);
    note.textContent = chosen
      ? (chosen.home
          ? t("share.note_home")
          : current === "move" ? t("share.note_move", { vault: chosen.name }) : t("share.note_copy", { vault: chosen.name }))
      : "";
  };
  paint();
  const from = vaults.find((v) => v.id === itemVaultId(item));
  return formDialog({
    title: t("share.title", { title: item.title || t("common.untitled") }),
    iconName: "share",
    cls: "",
    submit: t("share.submit"),
    body: [
      from ? h("p", { class: "muted", text: t("share.from", { vault: from.name }) }) : null,
      seg,
      list,
      note,
      blocked.length > 0 && policy.sharing_note ? h("p", { class: "faint", text: policy.sharing_note }) : null,
    ],
    onSubmit: async () => {
      if (!target) throw new Error(t("share.no_targets"));
      const r = await invoke("item_share", { itemId: item.id, targetVaultId: target, mode: current });
      const name = (r && r.vault && r.vault.name) || (vaults.find((v) => v.id === target) || {}).name || "";
      toast(current === "move" ? t("share.moved", { vault: name }) : t("share.copied", { vault: name }));
      return r || { item_id: item.id };
    },
  });
}

/**
 * "Share with a person": a direct share (`direct_share_start`) of `items` (may be empty) with one person and a role.
 * Compare first, then wrap: the share is made only with the compared fingerprint. `policy`: sharing outside the
 * organisation may be off.
 */
export async function openDirectShareDialog({ items = [], itemTitle = "", policy = null } = {}) {
  const first = await directShareForm({ items, itemTitle, policy });
  if (!first || !first.answer.needs_compare) return first ? first.answer : null;
  const { who, role } = first;
  return compareFirst(first.answer.needs_compare, async (fingerprint) => {
    const r = (await invoke("direct_share_start", { person: who, role, itemIds: items, fingerprint })) || {};
    toast(directShareToast(r, who));
    return r;
  }, { name: who });
}

function directShareToast(r, who) {
  return r && r.waiting_for_confirmation ? t("share.direct_waiting", { person: who }) : t("share.direct_done", { person: who });
}

function directShareForm({ items, itemTitle, policy }) {
  const person = h("input", { class: "input", type: "text", spellcheck: "false", autocomplete: "off", placeholder: t("share.person_placeholder") });
  const role = roleSelect("view", { roles: ["edit", "view", "fill"] });
  const hint = h("span", { class: "hint", text: roleHint("view") });
  role.addEventListener("change", () => { hint.textContent = roleHint(role.value); });
  return formDialog({
    title: itemTitle ? t("share.direct_title_item", { title: itemTitle }) : t("share.direct_title"),
    iconName: "userPlus",
    submit: t("share.direct_submit"),
    body: [
      h("p", { class: "muted", text: t("share.direct_text") }),
      labelled(t("share.person"), person),
      h("div", { class: "field" }, h("label", { for: role.id = nextId("tf"), text: t("share.role") }), role, hint),
      sharingOutsideAllowed(policy) ? null : h("div", { class: "banner" }, icon("info"), h("span", { class: "grow", text: t("share.outside_off") })),
      h("p", { class: "faint", text: t("share.direct_confirm_note") }),
    ],
    onSubmit: async () => {
      const who = person.value.trim();
      if (!who) {
        person.focus();
        throw new Error(t("share.person_needed"));
      }
      const r = (await invoke("direct_share_start", { person: who, role: role.value, itemIds: items })) || {};
      if (!r.needs_compare) toast(directShareToast(r, who));
      return { who, role: role.value, answer: r };
    },
  });
}

/** A new secure send from text or a file (`send_create`). Resolves the new send (with its link) or null. */
export function openSendCreateDialog() {
  let kind = "text";
  let filePath = null;
  const text = h("textarea", { class: "input", rows: "4", spellcheck: "false", placeholder: t("send.text_placeholder") });
  const fileName = h("span", { class: "grow ellipsis muted", text: t("send.no_file") });
  const pick = h("button", {
    class: "btn small",
    type: "button",
    text: t("send.choose_file"),
    on: {
      click: async () => {
        try {
          const p = await invoke("send_pick_file");
          if (p) {
            filePath = p;
            fileName.textContent = String(p).split(/[\\/]/).pop();
            fileName.title = p;
          }
        } catch (e) {
          toast(errorText(e), "error");
        }
      },
    },
  });
  const textField = labelled(t("send.text"), text);
  const fileField = h("div", { class: "field" }, h("span", { class: "label", text: t("send.file") }), h("div", { class: "row" }, fileName, pick));
  const kindBtns = {};
  const seg = h("div", { class: "segmented", role: "radiogroup", "aria-label": t("send.kind") },
    ["text", "file"].map((k) => (kindBtns[k] = h("button", {
      type: "button",
      role: "radio",
      text: k === "text" ? t("send.kind_text") : t("send.kind_file"),
      on: { click: () => { kind = k; paintKind(); } },
    }))));
  const paintKind = () => {
    for (const [k, b] of Object.entries(kindBtns)) {
      b.classList.toggle("active", k === kind);
      b.setAttribute("aria-checked", String(k === kind));
    }
    textField.hidden = kind !== "text";
    fileField.hidden = kind !== "file";
  };
  paintKind();
  const expires = selectOf(SEND_EXPIRY_DAYS.map((d) => [d, waitText(d * 24)]), 7);
  const views = selectOf(SEND_VIEWS.map((n) => [n, String(n)]), 1);
  const password = h("input", { class: "input", type: "password", autocomplete: "new-password", spellcheck: "false" });
  return formDialog({
    title: t("send.new_title"),
    iconName: "send",
    cls: "",
    submit: t("send.create"),
    body: [
      h("p", { class: "muted", text: t("send.intro") }),
      seg,
      textField,
      fileField,
      h("div", { class: "two" }, labelled(t("send.expires"), expires), labelled(t("send.max_views"), views)),
      labelled(t("send.password"), password, t("send.password_hint")),
    ],
    onSubmit: async () => {
      if (kind === "text" && !text.value.trim()) {
        text.focus();
        throw new Error(t("send.need_text"));
      }
      if (kind === "file" && !filePath) throw new Error(t("send.need_file"));
      const r = await invoke("send_create", {
        text: kind === "text" ? text.value : null,
        filePath: kind === "file" ? filePath : null,
        expiresDays: Number(expires.value),
        maxViews: Number(views.value),
        password: password.value || null,
      });
      text.value = "";
      password.value = "";
      return r;
    },
  });
}

/** Shows a new send's link once, with Copy (the key is in the link: whoever has it can open it). */
export function openSendLinkDialog(send) {
  const m = modal({ label: t("send.link_title"), cls: "narrow" });
  const copy = h("button", {
    class: "btn primary",
    type: "button",
    on: {
      click: async () => {
        try {
          await navigator.clipboard.writeText(send.link);
          toast(t("send.link_copied"));
        } catch {
          toast(t("send.copy_failed"), "error");
        }
      },
    },
  }, icon("copy"), t("send.copy_link"));
  mount(m.box,
    h("div", { class: "row" }, h("span", { class: "modal-icon" }, icon("send")), h("h2", { class: "grow", text: t("send.link_title") })),
    h("p", { text: t("send.link_text") }),
    h("div", { class: "card notes selectable mono send-link", text: send.link }),
    h("p", { class: "faint", text: t("send.link_note") }),
    h("div", { class: "row modal-actions" }, h("span", { class: "spacer" }),
      h("button", { class: "btn", type: "button", text: t("common.done"), on: { click: () => m.close() } }), copy));
  copy.focus();
}

/** A trusted contact for emergency access (`emergency_add`): who, view or take over, how long to wait. */
export function openEmergencyAddDialog() {
  const contact = h("input", { class: "input", type: "text", spellcheck: "false", autocomplete: "off", placeholder: t("share.person_placeholder") });
  const access = selectOf([["view", emergencyAccessLabel("view")], ["full", emergencyAccessLabel("full")]], "view");
  const wait = selectOf(EMERGENCY_WAIT_HOURS.map((hrs) => [hrs, waitText(hrs)]), 168);
  const accessHint = h("span", { class: "hint", text: t("emergency.access_view_hint") });
  access.addEventListener("change", () => {
    accessHint.textContent = access.value === "full" ? t("emergency.access_full_hint") : t("emergency.access_view_hint");
  });
  return formDialog({
    title: t("emergency.add_title"),
    iconName: "lifeBuoy",
    submit: t("emergency.add_submit"),
    body: [
      h("p", { class: "muted", text: t("emergency.add_text") }),
      labelled(t("emergency.contact"), contact),
      h("div", { class: "field" }, h("label", { for: access.id = nextId("tf"), text: t("emergency.access") }), access, accessHint),
      labelled(t("emergency.wait"), wait, t("emergency.wait_hint")),
    ],
    onSubmit: async () => {
      const who = contact.value.trim();
      if (!who) {
        contact.focus();
        throw new Error(t("share.person_needed"));
      }
      const r = await invoke("emergency_add", { contact: who, access: access.value, waitHours: Number(wait.value) });
      toast(t("emergency.added", { contact: who }));
      return r || {};
    },
  });
}

/** The invited contact accepts emergency access: the e-mailed link (or the code in it) is pasted here. */
export function openEmergencyAcceptDialog() {
  const link = h("input", { class: "input", type: "text", spellcheck: "false", autocomplete: "off", placeholder: t("emergency.accept_placeholder") });
  return formDialog({
    title: t("emergency.accept_title"),
    iconName: "lifeBuoy",
    submit: t("emergency.accept"),
    body: [h("p", { class: "muted", text: t("emergency.accept_text") }), labelled(t("emergency.accept_link"), link)],
    onSubmit: async () => {
      const token = emergencyToken(link.value);
      if (!token) {
        link.focus();
        throw new Error(t("emergency.accept_needed"));
      }
      const r = await invoke("emergency_accept", { token });
      toast(t("emergency.accepted"));
      return r || {};
    },
  });
}

export function emergencyToken(text) {
  const raw = String(text || "").trim();
  if (!raw) return "";
  try {
    const url = new URL(raw);
    return (url.searchParams.get("t") || "").trim();
  } catch {
    return /^[A-Za-z0-9_-]{8,200}$/.test(raw) ? raw : "";
  }
}

/**
 * The owner finishes a contact's setup: compare the fingerprint, then grant (`ready`) every vault linked to the
 * Passyble password, and the open vault with a separate password when the owner ticks it.
 */
export async function setupEmergencyContact(grant) {
  const keys = await invoke("emergency_contact_keys", { id: grant.grant_id });
  const status = await invoke("account_keys_status").catch(() => null);
  const open = status && status.active_vault;
  let includeOpen = true;
  if (open && !open.linked && status.set) {
    includeOpen = await confirmDialog({
      title: t("emergency.include_open_title", { vault: open.name || "" }),
      text: t("emergency.include_open_text"),
      confirm: t("emergency.include_open"),
      iconName: "lifeBuoy",
    });
  }
  const r = await openConfirmKeysDialog({ account: keys.account, name: grant.contact, fingerprint: keys.fingerprint }, (fingerprint) =>
    withAccountKey((password) => invoke("emergency_grant", { id: grant.grant_id, fingerprint, access: grant.access || "view", waitHours: Number(grant.wait_hours) || 168, includeOpen, password })));
  if (r) toast(t("emergency.setup_done", { contact: grant.contact }));
  return !!r;
}

export async function leaveOrg(org, done) {
  const family = org.kind === "family";
  const ok = await confirmDialog({
    title: t(family ? "teams.leave_family_title" : "teams.leave_team_title", { name: org.name }),
    text: t(family ? "teams.leave_family_text" : "teams.leave_team_text", { name: org.name }),
    confirm: t("teams.leave_org"),
    iconName: "logOut",
    danger: true,
  });
  if (!ok) return false;
  await invoke("org_leave", { org: org.id });
  toast(t("teams.left_org", { name: org.name }));
  if (done) done();
  return true;
}
