// Merging two items into one (merge.rs, pass-core `merge_pair`), from the vault list (two items selected,
// "Merge with…") and from suggestions that pair an authenticator entry with its login.
// The sheet shows both items side by side: where they differ the user picks a side per field (the title can
// also be custom, notes can keep both); where only one has a value it is kept; websites, passkeys and
// Android apps of both are kept. The core picks which item's id stays. Secrets are dots until revealed.
// One `merge_preview` gives each field's state and the core's default pick, so the merge rules live in one place.

import { avatar, errorText, h, icon, iconButton, invoke, liveTotp, maskedCode, mount, t } from "../lib.js";
import { fieldRows, mergePicks, pickedTitle, pickerRows, unionRows } from "./merge-model.js";

const PASSWORD_MASK = "••••••••••••";

/** A modal over the window; `onClose` runs once however it closes. Returns `{ box, close() }`. */
function modal(cls, label, onClose) {
  const box = h("div", { class: `modal ${cls}`, role: "dialog", "aria-modal": "true", "aria-label": label });
  const backdrop = h("div", { class: "modal-backdrop" }, box);
  let open = true;
  const keys = (e) => {
    if (e.key !== "Escape") return;
    e.preventDefault();
    e.stopPropagation();
    close();
  };
  const close = () => {
    if (!open) return;
    open = false;
    document.removeEventListener("keydown", keys, true);
    backdrop.remove();
    onClose();
  };
  backdrop.addEventListener("mousedown", (e) => { if (e.target === backdrop) close(); });
  document.addEventListener("keydown", keys, true);
  document.body.append(backdrop);
  return { box, close };
}

/**
 * The merge sheet for items `a` and `b`. `step`: `{ index, total }` when reviewing several pairs;
 * `heading` titles that review. Hooks: `onMerged(result)`, `onSkip()`, `onClose()`, `onError(e)` (a failed
 * first preview, e.g. vault locked: the caller unlocks and reopens).
 */
export class MergeSheet {
  constructor(a, b, { step = null, heading = null, onMerged, onSkip, onClose, onError }) {
    this.ids = { a, b };
    this.step = step;
    this.heading = heading;
    this.hooks = { onMerged, onSkip, onClose, onError };
    this.picks = {};
    // The title row's "Custom" choice: `text` is what the user typed (`edited`: don't re-prefill it).
    this.custom = { on: false, text: "", edited: false };
    this.preview = null;
    this.reveal = { a: false, b: false };
    this.codes = { a: null, b: null };
    this.live = [];
    this.codeViews = [];
    this.busy = false;
    this.open();
  }

  async open() {
    let first;
    try {
      first = await invoke("merge_preview", { a: this.ids.a, b: this.ids.b, picks: null });
    } catch (e) {
      if (this.hooks.onError) this.hooks.onError(e);
      return;
    }
    if (this.closed) return;
    this.preview = first;
    this.dialog = modal("merge-modal", t("merge.title"), () => this.closed || this.finish());
    this.body = h("div", { class: "col merge-body" });
    this.error = h("div", { class: "col" });
    this.mergeBtn = h("button", { class: "btn primary", type: "button", on: { click: () => this.merge() } }, icon("merge"), t("merge.merge"));
    const head = h("div", { class: "row merge-head" },
      h("span", { class: "modal-icon" }, icon("merge")),
      h("h2", { class: "grow", text: this.heading || t("merge.title") }),
      this.step ? h("span", { class: "faint", text: t("common.n_of_total", { n: this.step.index, total: this.step.total }) }) : null,
      iconButton("close", t("common.close"), () => this.dialog.close()));
    mount(this.dialog.box,
      head,
      h("p", { class: "muted", text: t("merge.intro") }),
      this.error,
      this.body,
      h("div", { class: "row modal-actions" },
        h("span", { class: "spacer" }),
        this.step ? h("button", { class: "btn", type: "button", text: t("common.skip"), on: { click: () => this.skip() } }) : null,
        h("button", { class: "btn", type: "button", text: t("common.cancel"), on: { click: () => this.dialog.close() } }),
        this.mergeBtn));
    this.startCodes();
    this.render();
    this.mergeBtn.focus();
  }

  /** Live 2FA codes of both items (dots until revealed), for comparing with the phone. */
  startCodes() {
    for (const side of ["a", "b"]) {
      const item = this.preview[side];
      if (!item.totp) continue;
      // Codes shown again each period don't count as activity for the auto-lock (the merge does).
      this.live.push(liveTotp(() => invoke("totp", { id: item.id, quiet: true }), {
        onCode: (c) => {
          if (c === undefined) return;
          this.codes[side] = c || null;
          for (const m of this.codeViews.filter((v) => v.side === side)) m.view.set(this.codes[side]);
        },
        onError: () => {},
      }));
    }
  }

  stopCodes() {
    for (const l of this.live) l.stop();
    this.live = [];
  }

  finish() {
    this.closed = true;
    this.stopCodes();
    if (this.hooks.onClose) this.hooks.onClose();
  }

  close() {
    if (this.dialog) this.dialog.close();
    else this.finish();
  }

  skip() {
    const onSkip = this.hooks.onSkip;
    this.hooks.onClose = null;
    this.close();
    if (onSkip) onSkip();
  }

  /** A pick changed: only the user's picks are kept (the rest is the core's default when merging). */
  pick(field, value) {
    this.picks = { ...this.picks, [field]: value };
    if (field === "title") this.custom.on = false;
    mount(this.error);
    this.render();
  }

  chooseCustom() {
    if (!this.custom.edited) this.custom.text = pickedTitle(this.preview, this.picks);
    this.custom.on = true;
    mount(this.error);
    this.render();
    if (this.customInput) {
      this.customInput.focus();
      this.customInput.select();
    }
  }

  async merge() {
    if (this.busy) return;
    this.busy = true;
    this.mergeBtn.disabled = true;
    try {
      const result = await invoke("merge_pair", { a: this.ids.a, b: this.ids.b, picks: mergePicks(this.picks, this.custom) });
      const onMerged = this.hooks.onMerged;
      this.hooks.onClose = null;
      this.close();
      if (onMerged) onMerged(result);
    } catch (e) {
      mount(this.error, h("div", { class: "banner error", text: errorText(e) }));
      this.mergeBtn.disabled = false;
    } finally {
      this.busy = false;
    }
  }

  secretText(item, field, side) {
    if (field === "password") {
      const value = h("span", { class: "mono" });
      const eye = iconButton("eye", t("password.show"), (e) => {
        e.stopPropagation();
        this.reveal[side] = !this.reveal[side];
        paint();
      }, "ghost small");
      const paint = () => {
        const shown = this.reveal[side];
        value.textContent = shown ? item.password : PASSWORD_MASK;
        value.classList.toggle("masked", !shown);
        value.classList.toggle("selectable", shown);
        eye.title = shown ? t("password.hide") : t("password.show");
        eye.setAttribute("aria-label", eye.title);
        eye.setAttribute("aria-pressed", String(shown));
        mount(eye, icon(shown ? "eyeOff" : "eye"));
      };
      paint();
      return h("span", { class: "merge-secret" }, value, eye);
    }
    const view = maskedCode({ cls: "code merge-code" });
    view.set(this.codes[side]);
    this.codeViews.push({ side, view });
    view.eye.classList.add("small");
    view.eye.addEventListener("click", (e) => e.stopPropagation());
    return h("span", { class: "merge-secret" }, view.el, view.eye);
  }

  valueOf(item, field, side) {
    if (field === "password" || field === "totp") return this.secretText(item, field, side);
    const text = (item[field] || "").trim();
    return h("span", { class: `selectable${field === "notes" ? " merge-notes" : ""}`, text });
  }

  cell(row, side) {
    const item = this.preview[side];
    const has = row.field === "totp" ? !!item.totp : !!(item[row.field] || "").trim();
    if (!has) return h("div", { class: "merge-cell empty" }, h("span", { class: "faint", text: t("merge.none") }));
    const content = this.valueOf(item, row.field, side);
    if (!row.choosable) {
      return h("div", { class: "merge-cell kept" }, content, row.kept === side ? h("span", { class: "chip ok", text: t("merge.kept") }) : null);
    }
    const on = row.pick === side;
    const el = h("div", {
      class: `merge-cell choice${on ? " on" : ""}`,
      role: "radio",
      tabindex: "0",
      "aria-checked": String(on),
      "aria-label": t("merge.field_from", { field: row.label, title: item.title || t("common.untitled") }),
      on: {
        click: () => this.pick(row.field, side),
        keydown: (e) => { if (e.key === " " || e.key === "Enter") { e.preventDefault(); this.pick(row.field, side); } },
      },
    }, h("span", { class: "merge-radio" }, on ? icon("check") : null), h("span", { class: "grow" }, content));
    return el;
  }

  customChoice(row) {
    const on = row.pick === "custom";
    const button = h("button", {
      class: `merge-both${on ? " on" : ""}`,
      type: "button",
      role: "radio",
      "aria-checked": String(on),
      on: { click: () => this.chooseCustom() },
    }, h("span", { class: "merge-radio" }, on ? icon("check") : null), icon("edit"), t("merge.custom_title"));
    if (!on) return [button];
    const input = h("input", {
      class: "input merge-custom-input",
      type: "text",
      value: this.custom.text,
      placeholder: t("field.title"),
      "aria-label": t("merge.custom_title"),
      spellcheck: "false",
      autocomplete: "off",
      on: {
        input: () => { this.custom.text = input.value; this.custom.edited = true; },
        // Enter does nothing here (it never merges or closes the sheet).
        keydown: (e) => {
          if (e.key !== "Enter") return;
          e.preventDefault();
          e.stopPropagation();
        },
      },
    });
    this.customInput = input;
    return [button, input];
  }

  fieldRow(row) {
    const label = h("div", { class: "merge-label" }, h("span", { text: row.label }),
      row.same ? h("span", { class: "chip", text: t("merge.same") }) : null);
    const custom = row.renamable ? this.customChoice(row) : [];
    if (row.same) {
      const side = row.pick === "b" ? "b" : "a";
      return h("div", { class: "merge-row", role: row.renamable ? "radiogroup" : "group", "aria-label": row.label },
        label, h("div", { class: "merge-cell span" }, this.valueOf(this.preview[side], row.field, side)), ...custom);
    }
    const cells = [this.cell(row, "a"), this.cell(row, "b")];
    const both = row.both
      ? h("button", {
          class: `merge-both${row.pick === "both" ? " on" : ""}`,
          type: "button",
          role: "radio",
          "aria-checked": String(row.pick === "both"),
          on: { click: () => this.pick(row.field, "both") },
        }, h("span", { class: "merge-radio" }, row.pick === "both" ? icon("check") : null), t("merge.keep_both"))
      : null;
    return h("div", { class: "merge-row", role: row.choosable || row.renamable ? "radiogroup" : "group", "aria-label": row.label }, label, ...cells, both, ...custom);
  }

  unionRow(row) {
    const list = (values) => values.length
      ? h("div", { class: "merge-cell kept col" }, values.map((v) => h("span", { class: "selectable ellipsis", text: v, title: v })))
      : h("div", { class: "merge-cell empty" }, h("span", { class: "faint", text: t("merge.none") }));
    return h("div", { class: "merge-row" },
      h("div", { class: "merge-label" }, h("span", { text: row.label }), row.a.length && row.b.length ? h("span", { class: "chip ok", text: t("merge.both_kept") }) : null),
      list(row.a), list(row.b));
  }

  render() {
    this.codeViews = [];
    this.customInput = null;
    const p = this.preview;
    mount(this.body,
      h("div", { class: "merge-grid" },
        fieldRows(p, this.picks, this.custom).map((row) => this.fieldRow(row)),
        unionRows(p).map((row) => this.unionRow(row))));
  }
}

/** "Merge with…": pick the item to merge `item` with; likely matches (same website, title or issuer) come first. `onPick(id)`. */
export async function openMergePicker(item, summaries, { onPick, onClose, onError }) {
  let candidates;
  try {
    ({ candidates } = await invoke("merge_candidates", { id: item.id }));
  } catch (e) {
    if (onError) onError(e);
    return null;
  }
  const dialog = modal("narrow merge-picker", t("merge.picker_label", { title: item.title }), () => onClose && onClose());
  const search = h("input", { class: "input", type: "search", placeholder: t("common.search"), "aria-label": t("merge.search_items"), spellcheck: "false", autocomplete: "off" });
  const list = h("div", { class: "col merge-pick-list", role: "listbox", "aria-label": t("merge.items") });
  const row = (s) => h("button", {
    class: "merge-pick", type: "button", role: "option",
    on: { click: () => { dialog.close(); onPick(s.id); } },
  }, avatar(s.title, s.kind),
  h("span", { class: "grow" },
    h("span", { class: "ellipsis merge-item-title", text: s.title || t("common.untitled") }),
    h("span", { class: "faint ellipsis", text: s.username || s.url || (s.kind === "note" ? t("kind.note") : "") })));
  const paint = () => {
    const { likely, rest } = pickerRows(candidates, summaries, search.value);
    mount(list,
      likely.length ? [h("div", { class: "section-title", text: t("merge.likely") }), likely.map(row)] : null,
      rest.length ? [h("div", { class: "section-title", text: likely.length ? t("merge.other_items") : t("merge.items") }), rest.map(row)] : null,
      likely.length || rest.length ? null : h("div", { class: "empty", text: candidates.length ? t("merge.nothing_matches") : t("merge.no_other_items") }));
  };
  search.addEventListener("input", paint);
  search.addEventListener("keydown", (e) => {
    if (e.key === "ArrowDown") { e.preventDefault(); const first = list.querySelector(".merge-pick"); if (first) first.focus(); }
  });
  list.addEventListener("keydown", (e) => {
    const rows = [...list.querySelectorAll(".merge-pick")];
    const i = rows.indexOf(document.activeElement);
    if (e.key === "ArrowDown" && i >= 0) { e.preventDefault(); (rows[i + 1] || rows[i]).focus(); }
    else if (e.key === "ArrowUp" && i >= 0) { e.preventDefault(); (i ? rows[i - 1] : search).focus(); }
  });
  mount(dialog.box,
    h("div", { class: "row" },
      h("span", { class: "modal-icon" }, icon("merge")),
      h("h2", { class: "grow ellipsis", text: t("merge.picker_title", { title: item.title || t("common.untitled") }) }),
      iconButton("close", t("common.close"), () => dialog.close())),
    h("p", { class: "muted", text: t("merge.picker_intro") }),
    search,
    list);
  paint();
  search.focus();
  return dialog;
}

