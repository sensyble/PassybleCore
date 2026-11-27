// Start screen while locked: the vaults added on this PC on the left, the unlock form for the selected
// one on the right, and "Add vault". Only one vault is unlocked at a time; unlocking another makes it
// the active vault (the browser extension, auto-type and Windows passkeys then use it).

import { avatar, errorText, formatDate, formatTime, h, icon, iconButton, invoke, mount, t, tn, toast, wordmark } from "../lib.js";
import { isMac } from "../platform.js";
import { appKeyCommand } from "./app-keys.js";
import { lastPins, pinnedFirst } from "./pins-model.js";
import { UnlockPanel } from "./unlock.js";
import { removeVault, vaultMenuActions } from "./vault-actions.js";
import { whereText } from "./vault-where-model.js";

const MINUTE = 60 * 1000;
const DAY = 24 * 60 * MINUTE;

function sameDay(a, b) {
  return a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() && a.getDate() === b.getDate();
}

export function lastOpenedText(ms, now = Date.now()) {
  if (!ms) return t("vaults.never_opened");
  const diff = now - ms;
  if (diff < MINUTE) return t("vaults.opened_now");
  if (diff < 60 * MINUTE) return tn("vaults.opened_minutes", Math.round(diff / MINUTE));
  const d = new Date(ms);
  const today = new Date(now);
  const time = formatTime(d, { hour: "numeric", minute: "2-digit" });
  if (sameDay(d, today)) return t("vaults.opened_today", { time });
  const yesterday = new Date(now);
  yesterday.setDate(today.getDate() - 1);
  if (sameDay(d, yesterday)) return t("vaults.opened_yesterday", { time });
  if (diff < 7 * DAY) return t("vaults.opened_on", { date: formatDate(d, { weekday: "long" }) });
  return t("vaults.opened_on", { date: formatDate(d) });
}

function initialSelection(status) {
  const vaults = status.vaults || [];
  if (vaults.some((v) => v.id === status.active_vault)) return status.active_vault;
  const recent = [...vaults].sort((a, b) => (b.last_opened_ms || 0) - (a.last_opened_ms || 0))[0];
  return recent ? recent.id : null;
}

export class VaultsView {
  constructor(root, status, onDone, hooks) {
    this.root = root;
    this.status = status;
    this.onDone = onDone;
    this.hooks = hooks;
    this.selectedId = initialSelection(status);
    this.panel = null;
    this.menu = null;
    this.renaming = false;

    this.list = h("ul", { class: "list vault-list", role: "listbox", "aria-label": t("vaults.title"), tabindex: "0" });
    this.count = h("span", { class: "faint" });
    this.pane = h("main", { class: "pane" });

    mount(
      root,
      h(
        "div",
        { class: "app start" },
        h(
          "aside",
          { class: "sidebar" },
          h(
            "div",
            { class: "sidebar-top start-head" },
            wordmark(),
            h("div", { class: "grow" }, h("h2", { text: t("vaults.title") }), this.count),
          ),
          this.list,
          h(
            "div",
            { class: "sidebar-bottom stack" },
            h("button", { class: "btn", type: "button", on: { click: () => this.hooks.onAdd() } }, icon("plus"), t("vault.add_vault")),
          ),
        ),
        this.pane,
      ),
    );

    this.list.addEventListener("keydown", (e) => this.listKeys(e));
    this.outside = (e) => {
      if (this.menu && !this.menu.contains(e.target)) this.closeMenu();
    };
    this.keys = (e) => {
      if (e.key === "Escape" && this.menu) {
        e.preventDefault();
        this.closeMenu();
      }
    };
    this.blur = () => this.closeMenu();
    document.addEventListener("mousedown", this.outside, true);
    document.addEventListener("keydown", this.keys);
    window.addEventListener("blur", this.blur);
    window.addEventListener("resize", this.blur);

    this.renderList();
    this.showPanel();
  }

  /** The active vault first, then the ones pinned when a vault was last open here, then the rest. */
  vaults() {
    return pinnedFirst(this.status.vaults || [], this.pins(), (v) => v.vault_id, (v) => v.active);
  }

  pins() {
    return lastPins(this.status.active_vault);
  }

  selected() {
    return this.vaults().find((v) => v.id === this.selectedId) || null;
  }

  update(status) {
    this.status = status;
    if (!this.selected()) {
      this.selectedId = initialSelection(status);
      this.showPanel();
    } else if (this.panel) {
      this.panel.update(status, this.selected());
    }
    if (!this.renaming) this.renderList();
  }

  destroy() {
    this.closeMenu();
    document.removeEventListener("mousedown", this.outside, true);
    document.removeEventListener("keydown", this.keys);
    window.removeEventListener("blur", this.blur);
    window.removeEventListener("resize", this.blur);
    if (this.panel) this.panel.destroy();
  }

  renderList() {
    const vaults = this.vaults();
    const pins = this.pins();
    this.count.textContent = tn("vaults.count", vaults.length);
    mount(
      this.list,
      vaults.map((v) => {
        const selected = v.id === this.selectedId;
        const pinned = !!v.vault_id && pins.includes(v.vault_id);
        const more = iconButton("more", t("vaults.options_for", { vault: v.name }), (e) => {
          e.stopPropagation();
          const r = more.getBoundingClientRect();
          this.openMenu(v, r.left, r.bottom + 2);
        }, "ghost more");
        return h(
          "li",
          {
            class: `list-item vault-row${selected ? " selected" : ""}`,
            role: "option",
            "aria-selected": String(selected),
            title: v.path,
            dataset: { id: v.id },
            on: {
              click: () => this.select(v.id),
              dblclick: () => this.panel && this.panel.focus(),
              contextmenu: (e) => {
                e.preventDefault();
                this.select(v.id);
                this.openMenu(v, e.clientX, e.clientY);
              },
            },
          },
          avatar(v.name),
          h(
            "div",
            { class: "grow" },
            h(
              "div",
              { class: "title vault-title" },
              h("span", { class: "ellipsis", text: v.name }),
              pinned ? h("span", { class: "row-pinned", title: t("vault.pinned") }, icon("pin"), h("span", { class: "visually-hidden", text: t("vault.pinned") })) : null,
            ),
            h("div", { class: "sub ellipsis row-location" }, icon(v.webdav_host || v.google_email ? "cloud" : "folder"), h("span", { class: "ellipsis", text: whereText(v, t) })),
            h("div", { class: `meta ellipsis${v.exists ? "" : " missing"}`, text: v.exists ? lastOpenedText(v.last_opened_ms) : t("vaults.file_not_found") }),
          ),
          more,
        );
      }),
    );
    const sel = this.list.querySelector(".selected");
    if (sel) sel.scrollIntoView({ block: "nearest" });
  }

  select(id) {
    if (id === this.selectedId) return;
    this.selectedId = id;
    this.renderList();
    this.showPanel();
  }

  listKeys(e) {
    const vaults = this.vaults();
    if (!vaults.length || this.renaming) return;
    const index = vaults.findIndex((v) => v.id === this.selectedId);
    if (e.key === "ArrowDown") {
      e.preventDefault();
      this.select(vaults[Math.min(vaults.length - 1, index + 1)].id);
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      this.select(vaults[Math.max(0, index - 1)].id);
    } else if (e.key === "Enter") {
      e.preventDefault();
      if (this.panel) this.panel.focus();
    } else if (e.key === "F2" && this.selected()) {
      e.preventDefault();
      this.rename(this.selected());
    } else if (appKeyCommand(e, isMac()) === "trash" && this.selected()) {
      // Delete, or Cmd+Backspace on a Mac: off the list (the toast's Undo puts it back).
      e.preventDefault();
      this.remove(this.selected());
    }
  }

  showPanel() {
    if (this.panel) this.panel.destroy();
    this.panel = null;
    const vault = this.selected();
    if (!vault) {
      mount(this.pane, h("div", { class: "center-screen" }, h("p", { class: "muted", text: t("vaults.choose") })));
      return;
    }
    this.panel = new UnlockPanel(this.pane, vault, this.status, this.onDone);
    this.panel.focus();
  }

  openMenu(vault, x, y) {
    this.closeMenu();
    const item = (iconName, label, fn, cls = "") =>
      h(
        "button",
        {
          class: `menu-item ${cls}`,
          type: "button",
          role: "menuitem",
          on: { click: () => { this.closeMenu(); fn(); } },
        },
        icon(iconName),
        label,
      );
    const actions = vaultMenuActions(vault, {
      onRename: (v) => this.rename(v),
      onChanged: () => this.onDone(),
    });
    this.menu = h(
      "div",
      { class: "menu", role: "menu", "aria-label": t("vaults.options_for", { vault: vault.name }) },
      actions.map(([iconName, label, fn, cls]) => item(iconName, label, fn, cls)),
    );
    document.body.append(this.menu);
    const r = this.menu.getBoundingClientRect();
    this.menu.style.left = `${Math.max(8, Math.min(x, window.innerWidth - r.width - 8))}px`;
    this.menu.style.top = `${y + r.height > window.innerHeight - 8 ? Math.max(8, y - r.height) : y}px`;
    this.menu.addEventListener("keydown", (e) => {
      const items = [...this.menu.querySelectorAll(".menu-item")];
      const i = items.indexOf(document.activeElement);
      if (e.key === "ArrowDown") { e.preventDefault(); items[(i + 1) % items.length].focus(); }
      else if (e.key === "ArrowUp") { e.preventDefault(); items[(i - 1 + items.length) % items.length].focus(); }
    });
    this.menu.querySelector(".menu-item").focus();
  }

  closeMenu() {
    if (this.menu) this.menu.remove();
    this.menu = null;
  }

  rename(vault) {
    const row = [...this.list.children].find((li) => li.dataset.id === vault.id);
    const title = row && row.querySelector(".title");
    if (!title) return;
    const input = h("input", { class: "input rename", value: vault.name, maxlength: "80", "aria-label": t("vaults.name"), spellcheck: "false" });
    let finished = false;
    const finish = async (save) => {
      if (finished) return;
      finished = true;
      this.renaming = false;
      const name = input.value.trim();
      if (save && name && name !== vault.name) {
        try {
          await invoke("rename_vault", { id: vault.id, name });
        } catch (e) {
          toast(errorText(e), "error");
        }
        this.onDone();
      } else {
        this.renderList();
      }
    };
    input.addEventListener("keydown", (e) => {
      e.stopPropagation();
      if (e.key === "Enter") { e.preventDefault(); finish(true); }
      else if (e.key === "Escape") { e.preventDefault(); finish(false); }
    });
    input.addEventListener("blur", () => finish(true));
    input.addEventListener("click", (e) => e.stopPropagation());
    input.addEventListener("dblclick", (e) => e.stopPropagation());
    this.renaming = true;
    title.replaceWith(input);
    input.focus();
    input.select();
  }

  remove(vault) {
    removeVault(vault, (undone) => {
      if (undone) this.selectedId = vault.id;
      else if (this.selectedId === vault.id) this.selectedId = null;
      this.onDone();
    });
  }
}
