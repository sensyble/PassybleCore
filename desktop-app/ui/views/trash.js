// Trash (trash.rs): items deleted in the last 30 days, without secrets. Restore returns an item on
// every device after sync; Delete for good and Empty trash ask first. The core removes items itself
// after 30 days.

import { confirmDialog, errorText, formatDate, h, icon, iconButton, invoke, mount, t, tn, toast, withShortcut } from "../lib.js";
import { itemAvatar, watchIcons } from "../siteicons.js";
import { purgeText, rowSubtitle } from "./items-model.js";

export class TrashView {
  /** `hooks`: `onClose()`, `onChanged()` (something was restored or deleted), `onError(e, retry)`. */
  constructor(pane, hooks) {
    this.pane = pane;
    this.hooks = hooks;
    this.items = [];
    this.retention = 30 * 24 * 60 * 60 * 1000;
    this.list = h("div", { class: "col" });
    this.emptyBtn = h("button", { class: "btn danger", type: "button", disabled: true, on: { click: () => this.emptyTrash() } }, icon("trash"), t("trash.empty"));
    const inner = h("div", { class: "pane-inner trash" },
      h("div", { class: "pane-header" },
        iconButton("back", withShortcut(t("common.back"), t("keys.esc")), () => this.hooks.onClose()),
        h("h2", { class: "grow", text: t("trash.title") }),
        this.emptyBtn),
      h("p", { class: "muted", text: t("trash.intro") }),
      this.list);
    inner.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && !e.defaultPrevented && !document.querySelector(".modal-backdrop")) {
        e.preventDefault();
        this.hooks.onClose();
      }
    });
    mount(pane, inner);
    this.load();
  }

  async load() {
    let r;
    try {
      r = await invoke("trash_list");
    } catch (e) {
      mount(this.list, h("div", { class: "banner error", text: errorText(e) }));
      return;
    }
    if (!this.pane.contains(this.list)) return;
    this.items = r.items || [];
    this.retention = r.retention_ms || this.retention;
    this.render();
  }

  render() {
    this.emptyBtn.disabled = !this.items.length;
    if (!this.items.length) {
      mount(this.list, h("div", { class: "center-screen trash-empty" },
        h("div", { class: "empty-state" },
          h("span", { class: "empty-icon" }, icon("trash")),
          h("p", { class: "t", text: t("trash.empty_title") }),
          h("p", { text: t("trash.empty_text") }))));
      return;
    }
    const now = Date.now();
    mount(this.list,
      h("div", { class: "faint", text: tn("common.items", this.items.length) }),
      h("div", { class: "fields trash-list" }, this.items.map((item) => {
        const restore = h("button", { class: "btn small", type: "button", title: t("trash.restore_title"), on: { click: () => this.restore(item, restore) } }, icon("undo"), t("trash.restore"));
        const del = iconButton("trash", t("trash.delete_for_good"), () => this.deleteForGood(item), "danger trash-del");
        const deleted = item.trashed_at ? t("trash.deleted_on", { date: formatDate(item.trashed_at, { dateStyle: "medium" }) }) : "";
        return h("div", { class: "frow trash-row" },
          itemAvatar(item),
          h("div", { class: "value" },
            h("div", { class: "ellipsis trash-title", text: item.title || t("common.untitled") }),
            h("div", { class: "faint ellipsis", text: [rowSubtitle(item), deleted, purgeText(item.trashed_at, this.retention, now)].filter(Boolean).join(" · ") })),
          h("div", { class: "actions" }, restore, del));
      })));
    watchIcons(this.list);
  }

  async restore(item, button) {
    button.disabled = true;
    try {
      await invoke("trash_restore", { ids: [item.id] });
      toast(t("trash.restored", { title: item.title }));
      this.hooks.onChanged();
      await this.load();
    } catch (e) {
      button.disabled = false;
      this.hooks.onError(e, () => this.restore(item, button));
    }
  }

  async deleteForGood(item) {
    const ok = await confirmDialog({
      title: t("trash.delete_confirm_title"),
      text: t("trash.delete_confirm_text", { title: item.title }),
      confirm: t("trash.delete_for_good"),
      iconName: "trash",
      danger: true,
    });
    if (!ok) return;
    try {
      await invoke("trash_delete", { ids: [item.id] });
      toast(t("trash.deleted_for_good", { title: item.title }));
      await this.load();
    } catch (e) {
      this.hooks.onError(e, () => this.deleteForGood(item));
    }
  }

  async emptyTrash() {
    const n = this.items.length;
    const ok = await confirmDialog({
      title: t("trash.empty_confirm_title"),
      text: n === 1 ? t("trash.empty_confirm_one") : tn("trash.empty_confirm_many", n),
      confirm: t("trash.empty"),
      iconName: "trash",
      danger: true,
    });
    if (!ok) return;
    try {
      const r = await invoke("trash_empty");
      toast(tn("trash.emptied", r.deleted));
      await this.load();
    } catch (e) {
      this.hooks.onError(e, () => this.emptyTrash());
    }
  }
}
