// Unlocked vault: the rail at the window's left edge, the searchable list beside it, item detail,
// editor or settings on the right. On a Mac every Ctrl shortcut is Cmd.
//
// Soft lock ("Keep list visible when locked"): the view keeps the list from the agent (titles,
// usernames, websites, icons; no secrets) and shows secrets as dots. Anything needing a secret or
// changing the vault opens the unlock dialog first, then finishes the action. Locking drops every
// secret from the window (revealed values, the editor and an unsaved edit). Only "Lock completely"
// (Ctrl+Shift+L) drops the list too.
//
// Secrets (card number, codes, hidden fields, 2FA codes) show as dots; Show fetches one from Rust
// (`item_secret`) and Copy copies it in Rust (`copy_field`), so the value never needs to pass through
// the page. What is revealed resets when another item is opened.

import { agoText, avatar, cardExpired, cardLabel, errorText, expiryText, formatDate, formatDateTime, formatNumber, h, hasTag, icon, iconButton, identityName, inSentence, invoke, isLockedError, keyLabel, liveTotp, LOCKED_ERROR, maskedCode, modKey, mount, pressEscape, ring, t, tn, toast, tx, withShortcut } from "../lib.js";
import { itemAvatar, watchIcons } from "../siteicons.js";
import { Editor, IDENTITY_GROUPS, itemRuleBadge, KINDS } from "./editor.js";
import { generatorPanel } from "./generator.js";
import { openExportDialog } from "./export.js";
import { HealthView } from "./health.js";
import { matchesFilter, rowSubtitle, tagTree } from "./items-model.js";
import { TrashView } from "./trash.js";
import { ImportView } from "./import.js";
import { MergeSheet, openMergePicker } from "./merge.js";
import {
  APP_PIN,
  deletedText,
  favoriteLabel,
  favoritesText,
  favoriteTarget,
  hintText,
  pairKey,
  pendingSuggestions,
  pruneSelected,
  restoredText,
  selectRange,
  toggleSelected,
} from "./merge-model.js";
import { GetStarted } from "./getstarted.js";
import { openTutorial } from "./help.js";
import { Rail, railButton } from "./rail.js";
import { setTitlebarTools } from "../titlebar.js";
import { hidden as hiddenHere, isMac } from "../platform.js";
import { commandKeys } from "./app-keys.js";
import { acceptClick, syncButton, syncToast } from "./sync-model.js";
import { LocalReminder } from "./local-reminder.js";
import { googleSignIn } from "./google.js";
import { SettingsView } from "./settings.js";
import { openSignInAgainDialog } from "./signin.js";
import { UnlockPanel } from "./unlock.js";
import { openLinkDialog, openUnlinkDialog } from "./account-keys.js";
import { whereText } from "./vault-where-model.js";
import { vaultMenuActions } from "./vault-actions.js";
import { escapeCloses, pressCloses } from "./menu-layers-model.js";
import { MAX_PINS, pinnedFirst, rememberPins, togglePin } from "./pins-model.js";
import { teamsButtonLabel, TeamsView } from "./teams.js";
import { openDirectShareDialog, openItemShareDialog } from "./teams-dialogs.js";
import {
  attentionCount,
  defaultSaveVault,
  directShareAllowed,
  filterByVault,
  itemCaps,
  itemRoleNote,
  vaultRoleNote,
  itemVaultId,
  passwordNotices,
  shareTargets,
  showVaultNames,
  validVaultFilter,
} from "./teams-model.js";

const FILTERS = [
  ["all", t("vault.filter_all")],
  ["favorites", t("vault.filter_favorites")],
  ["logins", t("quickpick.logins")],
  ["totp", t("vault.filter_totp")],
  ["passkeys", t("field.passkeys")],
  ["cards", t("vault.filter_cards")],
  ["notes", t("field.notes")],
  ["identities", t("vault.filter_identities")],
  ["used", t("vault.filter_used")],
];

const TAGS_OPEN_KEY = "passyble.tags.open";

function tagsOpen() {
  try {
    return localStorage.getItem(TAGS_OPEN_KEY) !== "0";
  } catch {
    return true;
  }
}

function setTagsOpen(open) {
  try {
    localStorage.setItem(TAGS_OPEN_KEY, open ? "1" : "0");
  } catch {
  }
}

const PUBLIC_FIELDS = new Set(["username", "card_holder", "card_expiry", "identity.full_name", "identity.email", "identity.company"]);

const groupDigits = (text) => (/^[\d ]+$/.test(text) ? text.replace(/\s+/g, "").replace(/(.{4})(?=.)/g, "$1 ") : text);

// Codes refresh only while the window is in use, so an open detail view never blocks auto-lock.
const IDLE_MS = 2 * 60 * 1000;
let lastInput = Date.now();
for (const ev of ["keydown", "mousedown", "mousemove", "wheel"]) {
  window.addEventListener(ev, () => { lastInput = Date.now(); }, { passive: true });
}
const userActive = () => !document.hidden && Date.now() - lastInput < IDLE_MS;

const softLocked = (status) => !!(status && status.locked && status.soft_locked);

const PASSWORD_MASK = "••••••••••••";

/** Nothing revealed. `values`: secrets fetched for Show, by field name. */
const hidden = (id = null) => ({ id, password: false, totp: false, values: {} });

// "Not now" on the authenticator-codes hint: the shown pairs (item ids) stay quiet on this computer.
const HINT_KEY = "passyble.mergeHint.dismissed";

function hintDismissed() {
  try {
    const list = JSON.parse(localStorage.getItem(HINT_KEY) || "[]");
    return Array.isArray(list) ? list : [];
  } catch {
    return [];
  }
}

function dismissHint(pairs) {
  try {
    const keys = new Set([...hintDismissed(), ...pairs.map(pairKey)]);
    localStorage.setItem(HINT_KEY, JSON.stringify([...keys].slice(-500)));
  } catch {
  }
}

function rowBadges(item, vaultName = null) {
  const caps = itemCaps(item);
  return h(
    "span",
    { class: "badges" },
    item.has_totp ? h("span", { class: "badge-2fa", title: t("vault.has_totp"), text: t("import.has_totp") }) : null,
    item.has_passkey ? h("span", { class: "badge-key", title: t("vault.has_passkey") }, icon("key")) : null,
    vaultName
      ? h("span", { class: "badge-vault", title: t("teams.in_vault", { vault: vaultName }) }, caps.readOnly ? icon("lock") : null, h("span", { class: "ellipsis", text: vaultName }))
      : null,
  );
}

/** Soft lock: a "Locked" caption in place of a secret's show button; it still reveals after an unlock (`onClick`). */
function lockedCap(label, onClick) {
  return h("button", { class: "locked-cap", type: "button", title: label, "aria-label": `${t("vault.locked")}. ${label}`, on: { click: onClick } }, icon("lock"), t("vault.locked"));
}

const TAGS_SHOWN = 3;
export class VaultView {
  constructor(root, status, onLockChange) {
    this.root = root;
    this.status = status;
    this.onLockChange = onLockChange;
    this.items = [];
    this.known = new Map();
    this.filter = "all";
    this.tagFilter = null;
    this.allItems = [];
    this.selectedId = null;
    this.mode = "empty"; // empty | detail | edit | settings | import | trash | health | teams | generator
    this.editor = null;
    this.live = null;
    this.searchSeq = 0;
    this.reveal = hidden();
    this.locked = undefined;
    this.unlockDialog = null;

    this.search = h("input", {
      class: "input",
      type: "search",
      placeholder: withShortcut(t("common.search"), "Mod+F"),
      "aria-label": t("quickpick.search"),
      spellcheck: "false",
      autocomplete: "off",
    });
    this.searchBox = h("div", { class: "tb-search", role: "search" }, icon("search"), this.search);
    this.newBtn = h("button", {
      class: "btn primary new-item",
      type: "button",
      title: t("vault.new_title", { shortcut: keyLabel("Mod+N") }),
      "aria-label": t("vault.new"),
      "aria-haspopup": "menu",
      on: { click: () => this.openNewMenu() },
    }, icon("plus"), h("span", { class: "new-label", text: t("vault.new") }), icon("chevronDown", "btn-caret"));
    this.filterName = h("span", { class: "ellipsis" });
    this.filterBtn = h("button", {
      class: "btn ghost small filter-btn",
      type: "button",
      "aria-haspopup": "menu",
      "aria-expanded": "false",
      on: { click: () => this.openFilterMenu() },
    }, this.filterName, icon("chevronDown", "btn-caret"));
    this.filterClear = iconButton("close", t("vault.filter_clear"), () => { this.clearFilters(); this.filterBtn.focus(); }, "ghost small filter-clear");
    this.filters = h("div", { class: "filter-bar" }, this.filterBtn, this.filterClear);
    this.tagPanel = h("div", { class: "tag-panel", hidden: true });
    this.list = h("ul", { class: "list", role: "listbox", "aria-label": t("merge.items"), tabindex: "0" });
    this.listHead = h("div", { class: "list-head", "aria-hidden": "true" });
    this.tagsAll = false;
    this.pane = h("main", { class: "pane" });
    this.settingsNav = h("nav", { class: "settings-nav", "aria-label": t("settings.sections"), hidden: true });
    this.settingsNav.addEventListener("keydown", (e) => this.settingsNavKeys(e));
    this.syncBtn = railButton("sync", t("settings.sync_now"), () => this.syncClicked(), "sync-btn nav-sync");
    this.syncPill = h("button", { class: "pill", type: "button", hidden: true, on: { click: () => this.pillClicked() } });
    this.lockPill = h(
      "button",
      {
        class: "pill locked",
        type: "button",
        hidden: true,
        title: t("vault.locked_title"),
        on: { click: () => this.unlock({ hello: true }) },
      },
      icon("lock"),
      t("vault.locked"),
    );
    this.lockBtn = railButton("lock", withShortcut(t("tray.lock"), "Mod+L"), () => this.lockClicked(), "nav-lock");
    this.lockBtn.addEventListener("contextmenu", (e) => {
      e.preventDefault();
      this.openLockMenu();
    });
    this.signInNeeded = false;
    this.signedOut = false;
    this.offer = h("div", { hidden: true });
    this.linkOffer = h("div", { hidden: true });
    this.ruleCard = h("div", { hidden: true });
    this.localReminder = new LocalReminder({ onSetUp: (vault) => this.setUpSync(vault) });
    this.multi = new Set();
    this.selectBar = h("div", { class: "select-bar", role: "toolbar", "aria-label": t("vault.selected_items"), hidden: true });
    this.mergeHint = h("div", { hidden: true });
    this.suggestions = [];
    this.gearBtn = railButton("gear", withShortcut(t("rail.settings"), "Mod+,"), () => this.showSettings(), "nav-settings");
    this.gearBtn.classList.add("has-badge");
    this.gearBadge = h("span", { class: "badge-dot", hidden: true, "aria-hidden": "true" });
    this.gearBtn.append(this.gearBadge);
    // The list's foot: the open vault (opens the vault menu) and, while signed in, the Passyble account.
    this.vaultName = h("span", { class: "grow ellipsis" });
    this.switchBtn = h(
      "button",
      { class: "btn ghost vault-switch", type: "button", title: t("vault.switch_title"), "aria-haspopup": "menu", on: { click: () => this.openVaultMenu() } },
      icon("key"),
      this.vaultName,
      icon("chevronUp"),
    );
    this.accountBtn = h("button", { class: "btn ghost account-who", type: "button", on: { click: () => this.showSettings({ section: "sync" }) } });
    this.accountRow = h("div", { class: "sidebar-account", hidden: true },
      this.accountBtn,
      iconButton("gear", withShortcut(t("rail.settings"), "Mod+,"), () => this.showSettings(), "ghost small account-gear"));
    this.switchDialog = null;
    this.teams = null;
    this.openVaults = [];
    this.vaultFilter = null;
    // Pinned vault ids in pin order (some may name vaults this PC doesn't list).
    this.pins = [];
    this.teamsBtn = railButton("users", t("teams.title"), () => this.showTeams(), "nav-teams");
    this.teamsBtn.classList.add("has-badge");
    this.teamsBadge = h("span", { class: "badge-dot", hidden: true, "aria-hidden": "true" });
    this.teamsBtn.append(this.teamsBadge);
    this.teamsBtn.hidden = true;

    this.rail = new Rail([
      [
        ["home", railButton("home", t("rail.home"), () => this.goHome(), "nav-home")],
        ["favorites", railButton("star", t("vault.filter_favorites"), () => this.goHome("favorites"), "nav-favorites")],
      ],
      [
        ["generator", railButton("dice", t("rail.generator"), () => this.showGenerator(), "nav-generator")],
        ["health", railButton("health", t("health.title"), () => this.showHealth(), "nav-health")],
        ["trash", railButton("trash", t("trash.title"), () => this.showTrash(), "nav-trash")],
        ["teams", this.teamsBtn],
      ],
      null,
      [
        ["more", this.moreBtn = railButton("more", t("vault.more_title"), () => this.openMoreMenu(), "nav-more")],
        ["help", railButton("help", t("help.title"), () => this.showSettings({ page: "help" }), "nav-help")],
        ["settings", this.gearBtn],
      ],
      [
        ["sync", this.syncBtn],
        ["lock", this.lockBtn],
      ],
    ]);

    mount(
      root,
      h(
        "div",
        { class: "app has-rail" },
        this.rail.el,
        h(
          "aside",
          { class: "sidebar" },
          h("div", { class: "sidebar-top" }, this.filters, this.tagPanel),
          this.settingsNav,
          this.offer,
          this.ruleCard,
          this.linkOffer,
          this.localReminder.el,
          this.mergeHint,
          this.selectBar,
          this.listHead,
          this.list,
          h("div", { class: "sidebar-foot" }, h("div", { class: "vault-head" }, this.switchBtn, this.lockPill, this.syncPill), this.accountRow),
        ),
        this.pane,
      ),
    );
    this.app = root.querySelector(".app");
    setTitlebarTools(this.searchBox, this.newBtn);

    this.search.addEventListener("input", () => this.reload());
    this.search.addEventListener("keydown", (e) => this.listKeys(e));
    this.list.addEventListener("keydown", (e) => this.listKeys(e));
    this.list.addEventListener("keydown", (e) => this.listMenuKey(e));

    this.renderFilters();
    this.syncStatus(status.sync || {});
    invoke("update_status").then((u) => this.updateState(u)).catch(() => {});
    this.update(status);
    this.showEmpty();
    this.reload();
    this.loadTeams();
    this.loadAccount();
    this.search.focus();
  }

  async loadAccount() {
    if (this.destroyed) return;
    const seq = (this.accountSeq = (this.accountSeq || 0) + 1);
    const status = await invoke("account_status").catch(() => null);
    if (seq !== this.accountSeq || this.destroyed) return;
    const email = (status && status.signed_in && status.account && status.account.email) || "";
    this.accountRow.hidden = !email;
    if (!email) return;
    const label = t("account.signed_in", { email });
    this.accountBtn.title = label;
    this.accountBtn.setAttribute("aria-label", label);
    mount(this.accountBtn, avatar(email), h("span", { class: "grow ellipsis", text: email }));
  }

  /** The Teams and Family overview and open vaults, reloaded after an unlock and on `teams-changed`. */
  async loadTeams() {
    if (this.destroyed) return;
    const seq = (this.teamsSeq = (this.teamsSeq || 0) + 1);
    let overview = null;
    let vaults = [];
    let pins = null;
    if (!this.locked) {
      [overview, vaults, pins] = await Promise.all([
        invoke("teams_overview").catch(() => null),
        invoke("vault_items_vaults").catch(() => []),
        invoke("vault_pins").catch(() => null),
      ]);
    }
    if (seq !== this.teamsSeq || this.destroyed) return;
    // Soft-locked: keep what was known (the list keeps its vault names).
    if (this.locked && this.teams) return;
    this.teams = overview;
    this.openVaults = Array.isArray(vaults) ? vaults : [];
    if (pins) this.setPins(pins.pins);
    const filter = validVaultFilter(this.vaultFilter, this.openVaults);
    const filterChanged = filter !== this.vaultFilter;
    this.vaultFilter = filter;
    const visible = !!(overview && overview.visible);
    this.teamsBtn.hidden = !visible;
    this.rail.refresh();
    const count = attentionCount(overview);
    this.teamsBadge.hidden = !count;
    const label = teamsButtonLabel(count);
    this.teamsBtn.title = label;
    this.teamsBtn.setAttribute("aria-label", label);
    this.renderFilters();
    this.renderRuleCard();
    if (filterChanged || showVaultNames(this.openVaults)) this.renderList();
  }

  async loadPins() {
    if (this.destroyed || this.locked) return;
    const pins = await invoke("vault_pins").catch(() => null);
    if (!pins || this.destroyed) return;
    this.setPins(pins.pins);
    this.renderFilters();
    if (this.teamsView) this.teamsView.pinsChanged();
  }

  setPins(pins) {
    this.pins = pins || [];
    if (this.status && this.status.active_vault) rememberPins(this.status.active_vault, this.pins);
  }

  pinnableIds() {
    const local = ((this.status && this.status.vaults) || []).map((v) => v.vault_id).filter(Boolean);
    return [...new Set([...this.openVaults.map((v) => v.id), ...local])];
  }

  isPinned(id) {
    return !!id && this.pins.includes(id);
  }

  async setPinned(id, pin) {
    if (this.locked) return this.withUnlock(() => this.setPinned(id, pin));
    const next = togglePin(this.pins, id, pin, this.pinnableIds());
    if (next.full) {
      toast(t("vault.pins_full", { max: MAX_PINS }));
      return;
    }
    try {
      const saved = await invoke("set_vault_pins", { ids: next.pins });
      this.setPins(saved.pins);
    } catch (e) {
      toast(errorText(e), "error");
      return;
    }
    this.renderFilters();
    if (this.teamsView) this.teamsView.pinsChanged();
  }

  pinAction(id) {
    return id ? { pinned: this.isPinned(id), onToggle: () => this.setPinned(id, !this.isPinned(id)) } : null;
  }

  renderRuleCard() {
    const policy = this.teams && this.teams.password_policy;
    const notice = passwordNotices(policy).find((n) => n.kind === "second");
    if (!notice) {
      this.ruleCard.hidden = true;
      mount(this.ruleCard);
      return;
    }
    const name = (notice.vault && notice.vault.name) || "";
    const set = h("button", { class: "btn primary small", type: "button", text: t("password_mode.set_second"), on: { click: () => openUnlinkDialog({
      vaultName: name,
      second: true,
      onDone: () => this.loadTeams(),
    }) } });
    mount(this.ruleCard,
      h("div", { class: "offer", role: "region", "aria-label": notice.title },
        icon("shieldAlert"),
        h("div", { class: "grow" },
          h("div", { class: "t", text: notice.title }),
          h("div", { class: "hint", text: notice.text }),
          h("div", { class: "row" }, set))));
    this.ruleCard.hidden = false;
  }

  teamsChanged() {
    this.loadTeams();
    this.loadAccount();
    if (this.teamsView) this.teamsView.changed();
  }

  showTeams(section = null) {
    if (this.locked) {
      this.withUnlock(() => this.showTeams(section));
      return;
    }
    if (!this.confirmLeave()) return;
    this.leavePane();
    this.mode = "teams";
    this.teamsView = new TeamsView(this.pane, {
      onClose: () => { this.teamsView = null; this.showEmpty(); },
      onChanged: () => { this.reload(); this.loadTeams(); },
      onOpenItem: (id) => this.showItem(id),
      pins: () => this.pins,
      onPin: (id, pin) => this.setPinned(id, pin),
      onVaultSettings: (id) => {
        const vault = ((this.status && this.status.vaults) || []).find((v) => v.id === id);
        if (vault) this.setUpSync(vault);
      },
      onError: (e, retry) => this.failed(e, retry),
    }, { section });
  }

  vaultNameOf(item) {
    if (!showVaultNames(this.openVaults)) return null;
    const id = itemVaultId(item);
    const v = this.openVaults.find((x) => x.id === id) || (item && item.vault);
    return v ? v.name : null;
  }

  async shareItem(item, mode) {
    if (this.locked) return this.withUnlock(() => this.shareItem(item, mode));
    const r = await openItemShareDialog(item, this.openVaults, mode, this.teams && this.teams.password_policy);
    if (!r) return undefined;
    await this.reload();
    this.loadTeams();
    const id = r.item_id || item.id;
    if (this.items.some((i) => i.id === id)) this.select(id);
    return r;
  }

  async shareWithPerson(item) {
    if (this.locked) return this.withUnlock(() => this.shareWithPerson(item));
    const policy = this.teams && this.teams.policy ? this.teams.policy.effective : null;
    const r = await openDirectShareDialog({ items: [item.id], itemTitle: item.title, policy });
    if (r) {
      this.reload();
      this.loadTeams();
    }
    return r;
  }

  update(status) {
    const was = this.locked;
    const locked = softLocked(status);
    this.status = status;
    this.locked = locked;
    this.lockPill.hidden = !locked;
    this.app.classList.toggle("soft-locked", locked);
    this.lockBtn.title = locked ? t("vault.lock_completely_ellipsis") : withShortcut(t("tray.lock"), "Mod+L");
    this.lockBtn.setAttribute("aria-label", locked ? t("vault.lock_completely_ellipsis") : t("tray.lock"));
    if (locked) this.lockBtn.setAttribute("aria-haspopup", "menu");
    else this.lockBtn.removeAttribute("aria-haspopup");
    if (was !== undefined && was !== locked) {
      if (locked) this.onSoftLock();
      else this.onUnlocked();
    }
    if (locked && this.unlockDialog && this.unlockDialog.panel) {
      const vault = (status.vaults || []).find((v) => v.active);
      if (vault) this.unlockDialog.panel.update(status, vault);
    }
    // The browser or auto-type is waiting for an unlock: the master password, over the list.
    if (locked && status.unlock_requested && !this.unlockDialog) this.unlock();
    this.syncAvailable = !!(status.sync_configured ?? status.webdav_configured) || !!status.shared_sync;
    this.renderSyncBtn();
    this.renderVaultTitle(status);
    this.switchBtn.title = (status.vaults || []).length > 1
      ? t("vault.switch_named", { vault: status.active_vault_name || t("onboarding.vault") })
      : t("vault.switch_or_add");
    this.renderOffer(status);
    this.renderLinkOffer(status, locked);
    this.localReminder.update(status);
  }

  /** Offers to link the open personal vault to the signed-in account's password; "Not now" is kept (`vault_link_decline`). */
  renderLinkOffer(status, locked) {
    const active = (status.vaults || []).find((v) => v.active);
    if (locked || !active || active.linked_account) {
      this.linkOffer.hidden = true;
      return;
    }
    if (this.linkChecked === active.id) return;
    this.linkChecked = active.id;
    invoke("account_keys_status").then((s) => {
      const v = s && s.active_vault;
      if (!v || !v.offer_link || v.id !== active.id) return;
      const later = h("button", { class: "btn ghost small", type: "button", text: t("common.not_now"), on: { click: () => {
        this.linkOffer.hidden = true;
        invoke("vault_link_decline").catch(() => {});
      } } });
      const go = h("button", { class: "btn primary small", type: "button", text: t("account_keys.link_short"), on: { click: () => openLinkDialog({
        vaultName: v.name || "",
        onDone: () => {
          this.linkOffer.hidden = true;
          invoke("status").then((st) => this.update && this.update(st)).catch(() => {});
        },
      }) } });
      mount(this.linkOffer,
        h("div", { class: "offer", role: "region", "aria-label": t("account_keys.title") },
          icon("link"),
          h("div", { class: "grow" },
            h("div", { class: "t", text: t("account_keys.link_title") }),
            h("div", { class: "hint", text: t("account_keys.link_offer_text") }),
            h("div", { class: "row" }, go, later))));
      this.linkOffer.hidden = false;
    }).catch(() => {});
  }

  setUpSync(vault) {
    if (vault.active) this.showSettings({ section: "sync" });
    else this.switchTo(vault, { settings: { section: "sync" } });
  }

  renderOffer(status) {
    if (!status.offer_hello || this.offerDone) {
      this.offer.hidden = true;
      mount(this.offer);
      return;
    }
    if (!this.offer.hidden) return;
    const msg = h("div", { class: "hint", role: "status" });
    const on = h("button", { class: "btn primary small", type: "button" }, t("common.turn_on"));
    on.addEventListener("click", async () => {
      on.disabled = true;
      msg.textContent = t("vault.confirm_hello");
      try {
        const r = await invoke("enable_hello");
        this.offerDone = true;
        this.renderOffer(status);
        toast(r && r.warning ? r.warning : t("vault.hello_on"), "", r && r.warning ? 9000 : 0);
      } catch (e) {
        msg.textContent = errorText(e);
        on.disabled = false;
      }
    });
    const later = h("button", {
      class: "btn ghost small",
      type: "button",
      text: t("common.not_now"),
      on: {
        click: () => {
          this.offerDone = true;
          this.renderOffer(status);
          invoke("dismiss_hello_offer").catch(() => {});
        },
      },
    });
    mount(
      this.offer,
      h("div", { class: "offer", role: "region", "aria-label": t("settings.windows_hello") },
        icon("hello"),
        h("div", { class: "grow" },
          h("div", { class: "t", text: t("vault.hello_offer") }),
          h("div", { class: "hint", text: t("vault.hello_offer_text") }),
          h("div", { class: "row" }, on, later),
          msg)),
    );
    this.offer.hidden = false;
  }

  /** The "Switch vault" menu. Picking another vault asks for its unlock over this one, which stays open until then. */
  openVaultMenu(anchor = this.switchBtn) {
    if (this.skipAnchorClick === anchor && Date.now() - this.skipAnchorAt < 1000) {
      // This click only closed the menu (its mousedown did).
      this.skipAnchorClick = null;
      return;
    }
    const vaults = pinnedFirst((this.status && this.status.vaults) || [], this.pins, (v) => v.vault_id, (v) => v.active);
    const where = (v) => (v.google_email ? "cloud" : v.webdav_host ? "server" : "monitor");
    const pin = (v) => (this.locked ? null : this.pinAction(v.vault_id));
    const own = (v) => vaultMenuActions(v, { locked: this.locked, onChanged: () => this.onLockChange() });
    const actions = vaults.map((v) => v.active
      ? [where(v), v.name, () => {}, "current", whereText(v, t), pin(v), null, own(v)]
      : [where(v), v.name, () => this.switchTo(v), "", whereText(v, t), pin(v), null, own(v)]);
    if (actions.length) actions.push("sep");
    actions.push(["plus", t("vault.add_vault"), () => this.addVault()]);
    const r = anchor.getBoundingClientRect();
    this.openMenu(actions, r.left, r.bottom + 4, t("vault.switch_title"), { anchor });
    if (this.itemMenu) {
      this.itemMenu.classList.add("vault-menu");
      this.itemMenu.style.minWidth = `${Math.round(Math.max(r.width, 240))}px`;
      const m = this.itemMenu.getBoundingClientRect();
      this.itemMenu.style.left = `${Math.max(8, Math.min(r.left, window.innerWidth - m.width - 8))}px`;
      // No room under the button (the list's foot): the menu opens upward, clear of it.
      if (r.bottom + 4 + m.height > window.innerHeight - 8) this.itemMenu.style.top = `${Math.max(8, r.top - 4 - m.height)}px`;
      const current = this.itemMenu.querySelector(".menu-item.current");
      if (current) {
        current.setAttribute("aria-current", "true");
        current.append(icon("check", "menu-check"));
      }
    }
  }

  switchToId(id) {
    const vault = ((this.status && this.status.vaults) || []).find((v) => v.id === id);
    if (vault && !vault.active) this.switchTo(vault);
  }

  /** Another vault from the menu: its unlock form over this vault. Cancel, Esc or a wrong master password keeps this vault open. */
  switchTo(vault, options = {}) {
    if (this.unlockDialog || this.switchDialog || !this.confirmLeave()) return;
    const box = h("div", { class: "modal narrow unlock-modal", role: "dialog", "aria-modal": "true", "aria-label": t("prompt.unlock_title", { vault: vault.name }) });
    const backdrop = h("div", { class: "modal-backdrop" }, box);
    let panel = null;
    const dialog = {};
    const keys = (e) => {
      if (e.key !== "Escape" || (panel && panel.busy)) return;
      e.preventDefault();
      e.stopPropagation();
      dialog.close();
    };
    dialog.close = () => {
      if (this.switchDialog !== dialog) return;
      this.switchDialog = null;
      document.removeEventListener("keydown", keys, true);
      if (panel) panel.destroy();
      backdrop.remove();
      if (!this.destroyed) this.switchBtn.focus({ preventScroll: true });
    };
    this.switchDialog = dialog;
    document.body.append(backdrop);
    document.addEventListener("keydown", keys, true);
    const status = { ...this.status, unlock_requested: false };
    panel = new UnlockPanel(box, vault, status, () => {
      dialog.close();
      window.dispatchEvent(new CustomEvent("pass-vault-switched", { detail: options.settings || null }));
    }, {
      onCancel: () => dialog.close(),
      autoHello: false,
      reason: t("vault.switch_reason", { vault: this.status.active_vault_name || t("onboarding.vault") }),
      // While it unlocks, the vault being left locks first (main.js keeps this view meanwhile).
      onBusy: (busy) => {
        window.dispatchEvent(new CustomEvent("pass-vault-switching", { detail: busy }));
      },
    });
    panel.focus();
  }

  addVault() {
    if (!this.confirmLeave()) return;
    window.dispatchEvent(new CustomEvent("pass-add-vault"));
  }

  activeVault() {
    return ((this.status && this.status.vaults) || []).find((v) => v.active) || null;
  }

  lockClicked() {
    if (this.skipAnchorClick === this.lockBtn && Date.now() - this.skipAnchorAt < 1000) {
      // This click only closed the lock menu (its mousedown did).
      this.skipAnchorClick = null;
      return;
    }
    if (this.locked) this.openLockMenu();
    else invoke("lock");
  }

  openLockMenu() {
    const actions = [];
    if (!this.locked) {
      const keeps = !(this.status && this.status.keep_list === false);
      actions.push(["lock", t("tray.lock"), () => invoke("lock"), "", keeps ? t("vault.lock_keeps_list") : ""]);
    }
    actions.push(["lock", t("tray.lock_completely"), () => this.lockCompletely(), "", t("vault.lock_completely_hint")]);
    const r = this.lockBtn.getBoundingClientRect();
    this.openMenu(actions, r.left, r.top - 4, t("tray.lock"), { anchor: this.lockBtn });
  }

  /** "Lock completely" (Ctrl+Shift+L): also forgets the copy kept for the next start; no Windows Hello right away (the user locked on purpose). */
  lockCompletely() {
    if (!this.confirmLeave()) return;
    Promise.resolve(invoke("lock", { full: true, forget: true })).catch(() => {});
  }

  destroy() {
    this.destroyed = true;
    this.rail.destroy();
    setTitlebarTools();
    if (this.unlockDialog) this.unlockDialog.done(false);
    if (this.switchDialog) this.switchDialog.close();
    this.closeItemMenu(false);
    this.closeMergeUi();
    this.stopLive();
    this.current = null;
    mount(this.root);
  }

  /** Locked with the list kept: every secret leaves the window; the list, search and selection stay. An unsaved edit is lost. */
  onSoftLock() {
    this.closeItemMenu(false);
    this.closeMergeUi();
    this.suggestions = [];
    this.renderMergeHint();
    this.stopLive();
    this.reveal = hidden();
    const lostEdit = this.mode === "edit" && this.editor && this.editor.dirty;
    const id = (this.mode === "detail" || this.mode === "edit") && this.selectedId ? this.selectedId : null;
    if (this.importView && this.mode === "import") this.importView.destroy();
    this.editor = null;
    this.settingsView = null;
    this.importView = null;
    this.current = null;
    mount(this.pane);
    if (id) {
      this.mode = "detail";
      this.select(id);
    } else {
      this.showEmpty();
    }
    if (lostEdit) toast(t("vault.edit_discarded"), "", 6000);
    this.reload();
  }

  onUnlocked() {
    if (this.unlockDialog) this.unlockDialog.done(true);
    this.reload();
    this.loadTeams();
    if (this.mode === "empty" && !this.getStarted && this.status.get_started) this.showEmpty();
    if (this.mode === "detail" && this.current) {
      const id = this.current.id;
      invoke("get_item", { id })
        .then((fresh) => {
          if (!this.locked && this.mode === "detail" && this.current && this.current.id === id) this.showDetail(fresh);
        })
        .catch(() => {});
    }
  }

  /** Runs `action` with the vault unlocked, after the unlock dialog if needed; cancelled means nothing happens. */
  async withUnlock(action) {
    if (this.locked && !(await this.unlock({ hello: true }))) return undefined;
    if (this.destroyed) return undefined;
    return action();
  }

  /** A failed action. If the vault locked meanwhile: unlock and `retry` (rate limited so it can't loop); else a toast. */
  failed(e, retry) {
    const now = Date.now();
    if (isLockedError(e) && retry && !this.destroyed && now - (this.lastRetry || 0) > 2000) {
      this.lastRetry = now;
      this.unlock({ hello: true }).then((ok) => { if (ok && !this.destroyed) retry(); });
      return;
    }
    toast(errorText(e), "error");
  }

  /** The unlock dialog over the list. Resolves `true` once unlocked (here or elsewhere), `false` if cancelled or locked completely. `hello`: start Windows Hello at once (not for unlocks the browser or auto-type asked for). */
  unlock({ hello = false } = {}) {
    if (this.unlockDialog) return this.unlockDialog.promise;
    let resolve;
    const dialog = { promise: new Promise((r) => { resolve = r; }), panel: null, backdrop: null, keys: null };
    dialog.done = (ok) => {
      if (this.unlockDialog !== dialog) return;
      this.unlockDialog = null;
      if (dialog.keys) document.removeEventListener("keydown", dialog.keys, true);
      if (dialog.panel) dialog.panel.destroy();
      if (dialog.backdrop) dialog.backdrop.remove();
      resolve(!!ok);
    };
    this.unlockDialog = dialog;
    this.openUnlockDialog(dialog, hello);
    return dialog.promise;
  }

  async openUnlockDialog(dialog, hello) {
    const status = await invoke("status").catch(() => null);
    if (this.unlockDialog !== dialog) return;
    if (status && !status.locked) {
      this.update(status);
      dialog.done(true);
      return;
    }
    const vault = status && (status.vaults || []).find((v) => v.active);
    if (!softLocked(status) || !vault || this.destroyed) {
      dialog.done(false);
      return;
    }
    const cancel = () => {
      if ((this.status && this.status.unlock_requested) || status.unlock_requested) invoke("cancel_unlock").catch(() => {});
      dialog.done(false);
    };
    dialog.keys = (e) => {
      if (e.key !== "Escape") return;
      e.preventDefault();
      e.stopPropagation();
      cancel();
    };
    const box = h("div", { class: "modal narrow unlock-modal", role: "dialog", "aria-modal": "true", "aria-label": t("prompt.unlock_title", { vault: vault.name }) });
    dialog.backdrop = h("div", { class: "modal-backdrop" }, box);
    document.body.append(dialog.backdrop);
    document.addEventListener("keydown", dialog.keys, true);
    dialog.panel = new UnlockPanel(box, vault, status, async () => {
      const now = await invoke("status").catch(() => null);
      if (now) this.update(now);
      dialog.done(!!now && !now.locked);
    }, {
      onCancel: cancel,
      autoHello: hello && !status.unlock_requested,
      reason: t("vault.unlock_reason"),
    });
    dialog.panel.focus();
  }

  updateState(u) {
    if (this.settingsView) this.settingsView.updateState(u);
    // Managed (MSI) installs are updated by the administrator: no "ready to install" dot.
    const ready = !!(u && u.available && !u.managed);
    this.gearBadge.hidden = !ready;
    const label = !ready ? t("rail.settings")
      : u.way === "download" ? t("vault.update_available", { version: u.available.version })
      : t("vault.update_ready", { version: u.available.version });
    this.gearBtn.title = withShortcut(label, "Mod+,");
    this.gearBtn.setAttribute("aria-label", label);
  }

  renderSyncBtn() {
    const b = syncButton(this.syncAvailable, this.syncState || {}, agoText);
    this.syncBtn.title = b.title;
    this.syncBtn.setAttribute("aria-label", b.title);
    this.syncBtn.classList.toggle("busy", b.busy);
    this.syncBtn.classList.toggle("warn", b.warn);
  }

  syncClicked() {
    if (!acceptClick(this.lastSyncClick, this.syncRunning)) return;
    this.lastSyncClick = Date.now();
    if (!this.syncAvailable) this.setUpSync({ active: true });
    else this.syncAll();
  }

  async syncAll() {
    if (this.locked) return this.withUnlock(() => this.syncAll());
    this.syncRunning = true;
    this.syncStatus({ ...(this.syncState || {}), running: true });
    try {
      const r = await invoke("sync_all");
      if (r.no_sync) {
        this.syncAvailable = false;
        this.syncStatus({});
        this.setUpSync({ active: true });
        return;
      }
      const shown = syncToast(r);
      const failed = (r.failed || [])[0];
      this.syncStatus(failed ? { last_error: shown.text } : { last_sync_ms: Date.now() });
      toast(shown.text, shown.kind);
      this.reload();
    } catch (e) {
      this.syncStatus({ last_error: errorText(e) });
    } finally {
      this.syncRunning = false;
      this.renderSyncBtn();
    }
  }

  syncStatus(status) {
    if (this.settingsView) this.settingsView.syncStatus(status);
    this.syncState = status;
    if (this.syncBtn) this.renderSyncBtn();
    const pill = this.syncPill;
    this.signInNeeded = !!status.sign_in_needed;
    this.signedOut = !!status.signed_out;
    if (status.signed_out && !status.running) {
      pill.hidden = false;
      pill.className = "pill warn";
      pill.title = t("vault.pill_signed_out_title");
      mount(pill, icon("cloudOff"), t("vault.pill_signed_out"));
    } else if (status.sign_in_needed && !status.running) {
      pill.hidden = false;
      pill.className = "pill warn";
      pill.title = t("vault.pill_google_title");
      mount(pill, icon("cloudOff"), t("vault.pill_google"));
    } else if (status.running) {
      pill.hidden = false;
      pill.className = "pill busy";
      pill.title = t("vault.pill_syncing_title");
      mount(pill, icon("sync"), t("settings.syncing"));
    } else if (status.last_error) {
      pill.hidden = false;
      pill.className = "pill warn";
      pill.title = t("vault.pill_error_title", { error: status.last_error });
      mount(pill, icon("cloud"), t("vault.pill_error"));
    } else {
      pill.hidden = true;
    }
  }

  filterParts() {
    const vault = showVaultNames(this.openVaults) ? this.openVaults.find((v) => v.id === this.vaultFilter) : null;
    const kind = this.filter !== "all" ? FILTERS.find(([key]) => key === this.filter) : null;
    return [vault && vault.name, kind && kind[1], this.tagFilter && `#${this.tagFilter}`].filter(Boolean);
  }

  renderFilters() {
    const parts = this.filterParts();
    const text = parts.join(" · ");
    const label = parts.length ? t("vault.filter_showing", { filter: text }) : t("vault.filter");
    this.filterName.textContent = text || t("vault.filter");
    this.filterBtn.classList.toggle("active", parts.length > 0);
    this.filterBtn.title = label;
    this.filterBtn.setAttribute("aria-label", label);
    this.filterClear.hidden = !parts.length;
    this.paintRail();
  }

  clearFilters() {
    this.filter = "all";
    this.vaultFilter = null;
    this.tagFilter = null;
    this.renderFilters();
    this.renderTags();
    this.renderList();
  }

  openFilterMenu() {
    const anchor = this.filterBtn;
    if (this.skipAnchorClick === anchor && Date.now() - this.skipAnchorAt < 1000) {
      // This click only closed the menu (its mousedown did).
      this.skipAnchorClick = null;
      return;
    }
    const pickVault = (id) => () => { this.vaultFilter = id; this.renderFilters(); this.renderList(); };
    const pickKind = (key) => () => { this.filter = key; this.renderFilters(); this.renderList(); };
    const mark = (on) => (on ? "check" : null);
    const vaults = showVaultNames(this.openVaults)
      ? [
          { heading: t("teams.filter_vaults") },
          [mark(!this.vaultFilter), t("teams.all_vaults"), pickVault(null), "", "", null, !this.vaultFilter],
          ...pinnedFirst(this.openVaults, this.pins, undefined, (v) => v.home).map((v) =>
            [mark(v.id === this.vaultFilter), v.name, pickVault(v.id), "", v.home ? "" : vaultRoleNote(v), this.pinAction(v.id), v.id === this.vaultFilter]),
        ]
      : [];
    const actions = [
      ...vaults,
      { heading: t("vault.filter_show") },
      ...FILTERS.map(([key, label]) => [mark(this.filter === key), label, pickKind(key), "", "", null, this.filter === key]),
      ...(this.filterParts().length ? ["sep", ["close", t("vault.filter_clear"), () => this.clearFilters()]] : []),
    ];
    const r = anchor.getBoundingClientRect();
    this.openMenu(actions, r.left, r.bottom + 4, t("vault.filter"), { anchor });
    if (!this.itemMenu) return;
    this.itemMenu.classList.add("filter-menu");
    anchor.setAttribute("aria-expanded", "true");
  }

  setTagFilter(tag) {
    this.tagFilter = tag && this.tagFilter !== tag ? tag : null;
    this.renderFilters();
    this.renderTags();
    this.renderList();
  }

  renderTags() {
    const tree = tagTree(this.allItems);
    // A filter on a tag that is gone (renamed, last item deleted) is dropped.
    if (this.tagFilter && !tree.some((n) => n.tag.toLowerCase() === this.tagFilter.toLowerCase())) {
      this.tagFilter = null;
      this.renderFilters();
    }
    this.tagPanel.hidden = !tree.length;
    this.listHead.hidden = !!tree.length;
    if (!tree.length) {
      mount(this.tagPanel);
      return;
    }
    const open = tagsOpen();
    const head = h("button", {
      class: "tag-head",
      type: "button",
      "aria-expanded": String(open),
      on: { click: () => { setTagsOpen(!tagsOpen()); this.renderTags(); } },
    }, icon("tag"), h("span", { class: "grow" }, t("vault.tags_count", { count: formatNumber(tree.length) }),
      this.tagCount = h("span", { class: "tag-head-count", text: this.countText || "" })), icon(open ? "chevronUp" : "chevronDown"));
    const activeAt = this.tagFilter ? tree.findIndex((n) => n.tag.toLowerCase() === this.tagFilter.toLowerCase()) : -1;
    const shown = this.tagsAll || tree.length <= TAGS_SHOWN + 1 ? tree : tree.filter((n, i) => i < TAGS_SHOWN || i === activeAt);
    const more = open && shown.length < tree.length || this.tagsAll && tree.length > TAGS_SHOWN + 1
      ? h("button", {
          class: "tag-more",
          type: "button",
          text: this.tagsAll ? t("vault.tags_show_fewer") : t("vault.tags_show_all"),
          on: { click: () => { this.tagsAll = !this.tagsAll; this.renderTags(); } },
        })
      : null;
    const rows = open
      ? h("div", { class: "tag-list", role: "list" }, shown.map((n) => {
          const active = this.tagFilter && this.tagFilter.toLowerCase() === n.tag.toLowerCase();
          const row = h("button", {
            class: `tag-row${active ? " active" : ""}`,
            type: "button",
            role: "listitem",
            title: active ? t("vault.tag_active_title", { tag: n.tag }) : t("vault.tag_show", { tag: n.tag }),
            "aria-pressed": String(!!active),
            on: { click: () => this.setTagFilter(n.tag) },
          }, h("span", { class: "grow ellipsis", text: n.name }), h("span", { class: "tag-count", text: formatNumber(n.count) }));
          row.style.paddingLeft = `${8 + n.depth * 14}px`;
          return row;
        }), more)
      : null;
    mount(this.tagPanel, head, rows);
  }

  /** `quiet`: a reload the window does on its own (sync, browser extension); it doesn't count as use for auto-lock. */
  async reload({ quiet = false } = {}) {
    const seq = ++this.searchSeq;
    const query = this.search.value.trim();
    let items;
    try {
      items = query ? await invoke("search", { query, quiet }) : await invoke("list_items", { quiet });
    } catch (e) {
      if (seq === this.searchSeq) mount(this.list, h("li", { class: "empty", text: errorText(e) }));
      return;
    }
    if (seq !== this.searchSeq) return;
    this.items = items;
    for (const i of items) this.known.set(i.id, i);
    this.itemsQuery = query;
    if (!query) {
      this.allItems = items;
      this.renderTags();
    }
    // A search keeps the selection (pick one item, search for the other, Ctrl+click it).
    if (!query) this.multi = pruneSelected(this.multi, items.map((i) => i.id));
    this.renderList();
    if (!query) this.refreshMergeHint();
    if (this.mode === "detail" && this.selectedId && !items.some((i) => i.id === this.selectedId) && !query) {
      this.showEmpty();
    } else if (this.mode === "detail" && this.current && this.current.id === this.selectedId) {
      // A sync or the browser extension may have changed the item on show: never keep showing
      // (and toggling or editing) an old copy.
      const id = this.current.id;
      const fresh = await invoke("get_item", { id, quiet }).catch(() => null);
      if (fresh && this.mode === "detail" && this.current && this.current.id === id && fresh.updated_at !== this.current.updated_at) {
        this.showDetail(fresh);
      }
    }
  }

  renderVaultTitle(status = this.status) {
    const several = showVaultNames(this.openVaults);
    const filtered = several ? this.openVaults.find((v) => v.id === this.vaultFilter) : null;
    const name = filtered ? filtered.name : several ? t("teams.all_vaults") : status && status.active_vault_name;
    this.vaultName.textContent = name || t("onboarding.vault");
  }

  visibleItems() {
    const f = this.filter;
    const tag = this.tagFilter;
    const items = filterByVault(this.items, this.vaultFilter).filter((i) => matchesFilter(i, f) && (!tag || hasTag(i.tags, tag)));
    // "Most used": the items used on any device, most used (and most recently) first, then by
    // title. `rank` stays put over time, so the order only changes with a new use.
    if (f === "used") return [...items].sort((a, b) => b.rank - a.rank);
    if (this.itemsQuery) return items;
    return [...items.filter((i) => i.favorite), ...items.filter((i) => !i.favorite)];
  }

  renderList() {
    if (this.mode === "empty" && this.emptyFor !== this.items.length > 0) this.showEmpty();
    this.renderSelectBar();
    this.renderVaultTitle();
    const items = this.visibleItems();
    this.countText = items.length ? tn("common.items", items.length) : "";
    this.listHead.textContent = this.countText;
    if (this.tagCount) this.tagCount.textContent = this.countText;
    if (!items.length) {
      mount(this.list, h("li", { class: "empty", text: this.items.length ? t("merge.nothing_matches") : t("vault.empty_list") }));
      return;
    }
    mount(
      this.list,
      items.map((item) => {
        const more = iconButton("more", t("vaults.options_for", { vault: item.title }), (e) => {
          e.stopPropagation();
          const r = more.getBoundingClientRect();
          this.openItemMenu(item, r.right, r.bottom + 2);
        }, "ghost more");
        more.tabIndex = -1; // the keyboard opens the menu with Shift+F10 / the menu key
        const star = this.rowStar(item);
        return h(
          "li",
          {
            class: `list-item has-star${item.id === this.selectedId ? " selected" : ""}${item.id === this.menuFor ? " ctx" : ""}${this.multi.has(item.id) ? " multi" : ""}`,
            role: "option",
            "aria-selected": String(item.id === this.selectedId || this.multi.has(item.id)),
            tabindex: "-1",
            dataset: { id: item.id },
            on: {
              click: (e) => this.rowClicked(item.id, e),
              contextmenu: (e) => {
                e.preventDefault();
                this.openItemMenu(item, e.clientX, e.clientY);
              },
            },
          },
          itemAvatar(item),
          h(
            "div",
            { class: "grow" },
            h("div", { class: "title-line" }, h("span", { class: "title ellipsis", text: item.title }), rowBadges(item, this.vaultNameOf(item))),
            h("div", { class: "sub ellipsis", text: rowSubtitle(item) }),
          ),
          star,
          more,
        );
      }),
    );
    watchIcons(this.list);
    const sel = this.list.querySelector(".selected");
    if (sel) sel.scrollIntoView({ block: "nearest" });
  }

  rowStar(item) {
    const btn = h("button", {
      class: "row-star",
      type: "button",
      on: {
        click: (e) => { e.stopPropagation(); this.toggleFavorite(item.id, { inPlace: true }); },
        keydown: (e) => { if (e.key === "Enter" || e.key === " ") e.stopPropagation(); },
        dblclick: (e) => e.stopPropagation(),
      },
    });
    this.paintRowStar(btn, item.favorite);
    return btn;
  }

  paintRowStar(btn, on) {
    const label = on ? t("favorites.remove") : t("favorites.add");
    btn.classList.toggle("on", on);
    btn.title = label;
    btn.setAttribute("aria-label", label);
    btn.setAttribute("aria-pressed", String(on));
    mount(btn, icon(on ? "starFilled" : "star"));
  }

  updateRowFavorite(id, on) {
    const it = this.items.find((i) => i.id === id);
    if (it) it.favorite = on;
    if (this.filter === "favorites" && !on) {
      const li = [...this.list.querySelectorAll(".list-item")].find((el) => el.dataset.id === id);
      if (li && this.visibleItems().length) li.remove();
      else this.renderList();
      return;
    }
    const li = [...this.list.querySelectorAll(".list-item")].find((el) => el.dataset.id === id);
    const btn = li && li.querySelector(".row-star");
    if (btn) this.paintRowStar(btn, on);
    if (this.multi.has(id)) this.renderSelectBar();
  }

  listKeys(e) {
    const items = this.visibleItems();
    if (!items.length) return;
    const index = items.findIndex((i) => i.id === this.selectedId);
    if (e.key === "ArrowDown") {
      e.preventDefault();
      this.select(items[Math.min(items.length - 1, index + 1)].id);
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      this.select(items[Math.max(0, index - 1)].id);
    } else if (e.key === "Enter" && e.target === this.search) {
      e.preventDefault();
      this.select((items[index] || items[0]).id);
    } else if (e.key === "Escape" && e.target === this.search && this.search.value) {
      e.preventDefault();
      this.search.value = "";
      this.reload();
    } else if (e.key === "Escape" && this.multi.size) {
      e.preventDefault();
      this.clearSelection();
    }
  }

  /** Runs command `name` (a window key or a Mac menu-bar item, through main.js); true when it did something. */
  command(name, e = null) {
    if (name === "close") return this.closeCommand();
    if (this.unlockDialog || this.mergeSheet || this.mergePicker) return false;
    switch (name) {
      case "search": this.search.focus(); this.search.select(); return true;
      case "new": this.newItem("login"); return true;
      case "lock": if (!this.locked) invoke("lock"); return true;
      case "lock_full": this.lockCompletely(); return true;
      case "settings": this.showSettings(); return true;
      case "help": this.showSettings({ page: "help" }); return true;
      case "shortcuts": openTutorial("keys", this.tutorialContext()); return true;
      case "edit":
        if (this.mode !== "detail" || !this.current || !itemCaps(this.current).edit) return false;
        this.edit(this.current);
        return true;
      case "trash": return this.trashKey(e);
      default: return false;
    }
  }

  trashKey(e) {
    if (!e || !this.list.contains(e.target)) return false;
    if (this.multi.size > 1) {
      this.deleteSelected();
      return true;
    }
    const item = this.items.find((i) => i.id === this.selectedId);
    if (!item || !itemCaps(item).edit) return false;
    this.deleteFromList(item);
    return true;
  }

  /** Close Window (Cmd+W): closes an open menu or dialog, cancels the editor (asking about changes), goes back from a page, else hides the window. */
  closeCommand() {
    if (this.itemMenu) {
      this.closeItemMenu();
      return true;
    }
    if (document.querySelector(".modal-backdrop")) {
      pressEscape(document.activeElement);
      return true;
    }
    if (this.mode === "edit" && this.editor) {
      this.editor.cancel();
      return true;
    }
    if (this.mode !== "empty" && this.mode !== "detail") {
      const inside = this.pane.contains(document.activeElement) ? document.activeElement : this.pane.firstElementChild;
      if (!pressEscape(inside)) this.showEmpty();
      return true;
    }
    invoke("hide_window");
    return true;
  }

  confirmLeave() {
    return !(this.mode === "edit" && this.editor && this.editor.dirty) || confirm(t("editor.discard"));
  }

  stopLive() {
    if (this.live) this.live.stop();
    this.live = null;
    if (this.healthView) this.healthView.destroy();
    this.healthView = null;
    this.trashView = null;
    if (this.getStarted) this.getStarted.destroy();
    this.getStarted = null;
  }

  showEmpty() {
    this.stopLive();
    this.mode = "empty";
    this.emptyFor = this.items.length > 0;
    this.current = null;
    this.settingsView = null;
    if (this.status.get_started && !this.locked) {
      this.getStarted = new GetStarted({
        vaultName: () => this.status.active_vault_name || "",
        onImport: () => this.showImport(),
        tutorial: () => this.tutorialContext(),
      });
      this.getStarted.load();
    }
    // The global shortcuts in use (Settings → Keyboard shortcuts); an older status has only the hotkey.
    const keys = this.status.shortcuts || null;
    const quickKeys = keys ? keys.quick_access : null;
    const autoTypeKeys = hiddenHere("help.keys_windows") ? null : keys ? keys.auto_type : this.status.hotkey || "Ctrl+Alt+P";
    mount(
      this.pane,
      h("div", { class: "center-screen" },
        h("div", { class: "empty-wrap" },
        this.getStarted ? this.getStarted.el : null,
        h("div", { class: "empty-state" },
          h("span", { class: "empty-icon" }, icon(this.items.length ? "key" : "plus")),
          h("p", { class: "t", text: this.items.length ? t("vault.choose_item") : t("vault.add_first") }),
          h("dl", { class: "keys" },
            h("dt", {}, h("kbd", { text: keyLabel("Mod+F") })), h("dd", { text: t("common.search") }),
            h("dt", {}, h("kbd", { text: keyLabel("Mod+N") })), h("dd", { text: t("editor.new_item") }),
            h("dt", {}, h("kbd", { text: keyLabel("Mod+E") })), h("dd", { text: t("common.edit") }),
            h("dt", {}, h("kbd", { text: keyLabel("Mod+L") })), h("dd", { text: t("tray.lock") }),
            h("dt", {}, h("kbd", { text: keyLabel("Mod+Shift+L") })), h("dd", { text: t("tray.lock_completely") }),
            quickKeys ? [h("dt", {}, h("kbd", { text: keyLabel(quickKeys) })), h("dd", { text: t("shortcuts.quick_access") })] : null,
            autoTypeKeys ? [h("dt", {}, h("kbd", { text: keyLabel(autoTypeKeys) })), h("dd", { text: t("vault.auto_type_any") })] : null),
          h("p", { class: "faint", text: t("vault.drop_hint") })))),
    );
  }

  tutorialContext() {
    return {
      hotkey: this.status.hotkey,
      shortcuts: this.status.shortcuts || null,
      google: !!this.status.google_available,
      webdav: !!this.status.webdav_supported,
      openSettings: (section) => this.showSettings({ section }),
      openImport: () => this.showImport(),
    };
  }

  async select(id) {
    if (id !== this.selectedId && !this.confirmLeave()) return;
    this.selectedId = id;
    this.renderList();
    try {
      const item = await invoke("get_item", { id });
      if (this.selectedId === id) this.showDetail(item);
    } catch (e) {
      toast(errorText(e), "error");
    }
  }

  copy(field, label) {
    this.copyFor(this.current.id, field, label);
  }

  /** Copies in Rust. The username works while soft-locked; the password and 2FA code unlock first. */
  copyFor(id, field, label) {
    const run = () => invoke("copy_field", { id, field }).then(() => toast(t("vault.copied_label", { label })));
    Promise.resolve(PUBLIC_FIELDS.has(field) ? run() : this.withUnlock(run))
      .catch((e) => this.failed(e, () => this.copyFor(id, field, label)));
  }

  listMenuKey(e) {
    if (!(e.key === "ContextMenu" || (e.key === "F10" && e.shiftKey))) return;
    const row = (e.target.closest && e.target.closest(".list-item")) || this.list.querySelector(".list-item.selected");
    const item = row && this.items.find((i) => i.id === row.dataset.id);
    if (!item) return;
    e.preventDefault();
    const r = row.getBoundingClientRect();
    this.openItemMenu(item, r.left + 40, r.bottom - 4);
  }

  itemMenuActions(item) {
    const login = item.kind === "login";
    // A view or fill member's item: nothing that changes it; fill only: no password, card number or code either.
    const caps = itemCaps(item);
    const actions = [];
    if (login && item.username) actions.push(["user", t("vault.copy_username"), () => this.copyFor(item.id, "username", t("field.username"))]);
    if (login && item.has_password && caps.reveal) actions.push(["key", t("vault.copy_password"), () => this.copyFor(item.id, "password", t("field.password"))]);
    if (login && item.has_totp) actions.push(["timer", t("vault.copy_totp"), () => this.copyFor(item.id, "totp", t("vault.code"))]);
    if (caps.reveal && item.kind === "card" && item.card && item.card.last4) actions.push(["creditCard", t("vault.copy_card_number"), () => this.copyFor(item.id, "card_number", t("card.number"))]);
    if (caps.reveal && item.kind === "card") actions.push(["key", t("vault.copy_security_code"), () => this.copyFor(item.id, "card_code", t("vault.security_code"))]);
    if (item.kind === "identity" && item.identity && identityName(item.identity)) actions.push(["user", t("vault.copy_name"), () => this.copyFor(item.id, "identity.full_name", t("identity.group_name"))]);
    if (item.kind === "identity" && item.identity && item.identity.email) actions.push(["mail", t("vault.copy_email"), () => this.copyFor(item.id, "identity.email", t("identity.email"))]);
    if (actions.length) actions.push("sep");
    if (this.multi.size > 1 && this.multi.has(item.id)) return actions.concat(this.selectionMenuActions());
    if (caps.edit) {
      actions.push(["edit", t("common.edit"), () => this.editFromList(item.id)]);
      actions.push([item.favorite ? "star" : "starFilled", item.favorite ? t("favorites.remove") : t("favorites.add"), () => this.toggleFavorite(item.id)]);
    }
    if (caps.reveal) actions.push(["copy", t("vault.duplicate"), () => this.duplicateItem(item.id)]);
    if (caps.edit) actions.push(["merge", t("vault.merge_with"), () => this.mergeWith(item)]);
    const teamsActions = [];
    const policy = this.teams && this.teams.password_policy;
    const blocked = (policy && policy.blocked_vaults) || [];
    if (shareTargets(item, this.openVaults, "move", blocked).length) teamsActions.push(["share", t("share.move_to_vault"), () => this.shareItem(item, "move")]);
    if (shareTargets(item, this.openVaults, "copy", blocked).length) teamsActions.push(["copy", t("share.copy_to_vault"), () => this.shareItem(item, "copy")]);
    if (this.teams && this.teams.visible && caps.reveal && directShareAllowed(policy)) teamsActions.push(["userPlus", t("share.with_person"), () => this.shareWithPerson(item)]);
    const sep = () => { if (actions.length && actions[actions.length - 1] !== "sep") actions.push("sep"); };
    if (teamsActions.length) {
      sep();
      actions.push(...teamsActions);
    }
    if (caps.edit) {
      sep();
      actions.push(["trash", t("vault.move_to_trash"), () => this.deleteFromList(item), "danger", keyLabel(commandKeys("trash", isMac()))]);
    }
    if (actions[actions.length - 1] === "sep") actions.pop();
    return actions;
  }

  selectionMenuActions() {
    const n = this.multi.size;
    const on = favoriteTarget(this.selectedFavorites());
    const actions = [[on ? "starFilled" : "star", on ? tn("vault.selected_add_favorites", n) : tn("vault.selected_remove_favorites", n), () => this.favoriteSelected()]];
    if (n === 2) actions.push(["merge", t("vault.merge_two_selected"), () => this.mergeSelected()]);
    actions.push("sep");
    actions.push(["trash", tn("vault.selected_to_trash", n), () => this.deleteSelected(), "danger"]);
    return actions;
  }

  openItemMenu(item, x, y) {
    const actions = this.itemMenuActions(item);
    if (!actions.length) return;
    this.openMenu(actions, x, y, t("vaults.options_for", { vault: item.title }), { forId: item.id });
  }

  /**
   * Shows a menu of `actions` (`[icon, label, fn, cls?, hint?, pin?, checked?]`, `"sep"` or `{ heading }`) at `x`, `y`.
   * A boolean `checked` makes the row a radio item. `options.forId` / `options.anchor` get focus back on close.
   */
  openMenu(actions, x, y, label, options = {}) {
    const sub = !!options.sub;
    if (sub) this.closeSubMenu(); else this.closeItemMenu(false);
    if (!sub) {
      this.menuFor = options.forId || null;
      this.menuAnchor = options.anchor || null;
    }
    const row = !sub && this.menuFor && [...this.list.children].find((li) => li.dataset && li.dataset.id === this.menuFor);
    if (row) row.classList.add("ctx");
    // `pin` and `more` (a vault's row): buttons at the row's end, also reachable with ArrowRight and the context menu.
    const entry = (iconName, text, fn, cls = "", hint = "", pin = null, checked = null, more = null) => {
      const pinnedNote = pin && pin.pinned ? h("span", { class: "visually-hidden", text: `, ${t("vault.pinned")}` }) : null;
      const radio = typeof checked === "boolean";
      const item = h("button", {
        class: `menu-item ${cls}`,
        type: "button",
        role: radio ? "menuitemradio" : "menuitem",
        ...(radio ? { "aria-checked": String(checked) } : {}),
        on: { click: () => { this.closeItemMenu(); fn(); } },
      }, iconName ? icon(iconName) : h("span", { class: "menu-icon-space", "aria-hidden": "true" }), hint ? h("span", { class: "menu-text" }, h("span", { text }), h("span", { class: "menu-hint", text: hint })) : text, pinnedNote);
      if (!pin && !more) return item;
      const rowMenu = (x, y) => this.openMenu([
        ...(pin ? [[pin.pinned ? "pinOff" : "pin", t(pin.pinned ? "vault.unpin" : "vault.pin"), pin.onToggle]] : []),
        ...(pin && more && more.length ? ["sep"] : []),
        ...(more || []),
      ], x, y, t("vaults.options_for", { vault: text }), { sub: true, opener });
      let opener = item;
      item.addEventListener("contextmenu", (e) => {
        e.preventDefault();
        e.stopPropagation();
        const r = item.getBoundingClientRect();
        const [x, y] = e.clientX || e.clientY ? [e.clientX, e.clientY] : [r.left + 24, r.bottom];
        opener = moreBtn || item;
        rowMenu(x, y);
      });
      const pinTitle = pin ? t(pin.pinned ? "vault.unpin_named" : "vault.pin_named", { vault: text }) : "";
      const moreTitle = t("vaults.options_for", { vault: text });
      const moreBtn = more
        ? h("button", {
            class: "menu-pin menu-more",
            type: "button",
            tabindex: "-1",
            title: moreTitle,
            "aria-label": moreTitle,
            "aria-haspopup": "menu",
            on: { click: (e) => {
              e.stopPropagation();
              opener = e.currentTarget;
              const r = opener.getBoundingClientRect();
              rowMenu(r.left, r.bottom + 2);
            } },
          }, icon("more"))
        : null;
      return h("div", { class: `menu-row${pin && pin.pinned ? " pinned" : ""}` }, item,
        pin
          ? h("button", {
              class: "menu-pin",
              type: "button",
              tabindex: "-1",
              title: pinTitle,
              "aria-label": pinTitle,
              "aria-pressed": String(pin.pinned),
              on: { click: () => { this.closeItemMenu(false); pin.onToggle(); } },
            }, icon("pin"))
          : null,
        moreBtn);
    };
    const menu = h("div", { class: "menu", role: "menu", "aria-label": label });
    let group = null;
    for (const a of actions) {
      if (a === "sep") {
        group = null;
        menu.append(h("div", { class: "menu-sep", role: "separator" }));
      } else if (a.heading) {
        group = h("div", { class: "menu-group", role: "group", "aria-label": a.heading }, h("div", { class: "menu-heading", "aria-hidden": "true", text: a.heading }));
        menu.append(group);
      } else {
        (group || menu).append(entry(...a));
      }
    }
    if (sub) this.subMenu = menu; else this.itemMenu = menu;
    document.body.append(menu);
    const r = menu.getBoundingClientRect();
    menu.style.left = `${Math.max(8, Math.min(x, window.innerWidth - r.width - 8))}px`;
    menu.style.top = `${Math.max(8, y + r.height > window.innerHeight - 8 ? y - r.height : y)}px`;
    menu.addEventListener("keydown", (e) => {
      const items = [...menu.querySelectorAll(".menu-item")];
      const row = document.activeElement.closest(".menu-row");
      const i = items.indexOf(row ? row.querySelector(".menu-item") : document.activeElement);
      const extras = row ? [...row.querySelectorAll(".menu-pin")] : [];
      const j = extras.indexOf(document.activeElement);
      if (e.key === "ArrowRight" && extras.length && j < extras.length - 1) { e.preventDefault(); extras[j + 1].focus(); }
      else if (e.key === "ArrowLeft" && j >= 0) { e.preventDefault(); (j > 0 ? extras[j - 1] : items[i]).focus(); }
      else if (e.key === "ArrowDown") { e.preventDefault(); items[(i + 1) % items.length].focus(); }
      else if (e.key === "ArrowUp") { e.preventDefault(); items[(i - 1 + items.length) % items.length].focus(); }
      else if (e.key === "Home") { e.preventDefault(); items[0].focus(); }
      else if (e.key === "End") { e.preventDefault(); items[items.length - 1].focus(); }
      else if (e.key === "Escape" || e.key === "Tab") { e.preventDefault(); e.stopPropagation(); if (escapeCloses(sub) === "sub") this.closeSubMenu(true); else this.closeItemMenu(); }
    });
    const anchor = sub ? null : this.menuAnchor;
    const close = (e) => {
      const sa = this.subMenu;
      const inMenu = !!(e && e.target && e.target.nodeType && menu.contains(e.target));
      const inSub = !sub && !!(sa && e && e.target && e.target.nodeType && sa.contains(e.target));
      const what = sub ? (inMenu ? "none" : "sub") : pressCloses({ inMenu, inSub, hasSub: !!sa });
      if (what === "none") return;
      if (what === "sub") return this.closeSubMenu();
      // A press on the button that opened it just closes it (its click must not reopen it).
      this.skipAnchorClick = anchor && e && e.type === "mousedown" && anchor.contains(e.target) ? anchor : null;
      this.skipAnchorAt = Date.now();
      this.closeItemMenu(false);
    };
    const cleanup = () => {
      document.removeEventListener("mousedown", close, true);
      document.removeEventListener("wheel", close, true);
      this.list.removeEventListener("scroll", close);
      window.removeEventListener("blur", close);
      window.removeEventListener("resize", close);
    };
    if (sub) { this.subCleanup = cleanup; this.subOpener = options.opener || null; } else this.menuCleanup = cleanup;
    document.addEventListener("mousedown", close, true);
    document.addEventListener("wheel", close, true);
    this.list.addEventListener("scroll", close);
    window.addEventListener("blur", close);
    window.addEventListener("resize", close);
    menu.querySelector(".menu-item").focus();
  }

  closeSubMenu(restoreFocus = false) {
    if (this.subCleanup) this.subCleanup();
    this.subCleanup = null;
    if (this.subMenu) this.subMenu.remove();
    this.subMenu = null;
    const opener = this.subOpener;
    this.subOpener = null;
    if (restoreFocus && opener && opener.isConnected) opener.focus({ preventScroll: true });
  }

  closeItemMenu(restoreFocus = true) {
    this.closeSubMenu();
    if (this.menuCleanup) this.menuCleanup();
    this.menuCleanup = null;
    if (this.itemMenu) this.itemMenu.remove();
    this.itemMenu = null;
    const id = this.menuFor;
    const anchor = this.menuAnchor;
    this.menuFor = null;
    this.menuAnchor = null;
    if (anchor && anchor.hasAttribute("aria-expanded")) anchor.setAttribute("aria-expanded", "false");
    this.list.querySelectorAll(".list-item.ctx").forEach((li) => li.classList.remove("ctx"));
    if (restoreFocus && id) {
      const row = [...this.list.children].find((li) => li.dataset && li.dataset.id === id);
      if (row) row.focus({ preventScroll: true });
    } else if (restoreFocus && anchor && anchor.isConnected) anchor.focus({ preventScroll: true });
  }

  rowClicked(id, e) {
    if (e && modKey(e)) {
      this.multi = toggleSelected(this.multi, id, this.selectedId);
      this.anchorId = id;
      this.renderList();
      return;
    }
    if (e && e.shiftKey) {
      const ids = this.visibleItems().map((i) => i.id);
      this.multi = new Set(selectRange(ids, this.anchorId || this.selectedId, id));
      this.renderList();
      return;
    }
    if (this.multi.size) this.multi = new Set();
    this.anchorId = id;
    this.select(id);
  }

  clearSelection(render = true) {
    this.multi = new Set();
    if (render) this.renderList();
  }

  renderSelectBar() {
    const n = this.multi.size;
    this.selectBar.hidden = n < 1;
    if (n < 1) {
      mount(this.selectBar);
      return;
    }
    const on = favoriteTarget(this.selectedFavorites());
    const merge = h("button", {
      class: "btn primary small",
      type: "button",
      title: n === 2 ? t("vault.merge_these") : t("vault.select_two"),
      disabled: n !== 2,
      on: { click: () => this.mergeSelected() },
    }, icon("merge"), t("merge.merge"));
    mount(this.selectBar,
      h("span", { class: "grow", text: tn("vault.n_selected", n) }),
      iconButton(on ? "star" : "starFilled", favoriteLabel(on), () => this.favoriteSelected(), "ghost small"),
      iconButton("trash", n === 1 ? t("vault.selected_one_to_trash") : tn("vault.selected_to_trash", n), () => this.deleteSelected(), "ghost small"),
      merge,
      iconButton("close", withShortcut(t("vault.clear_selection"), t("keys.esc")), () => this.clearSelection(), "ghost small"));
  }

  selectedFavorites() {
    return [...this.multi].map((id) => this.known.get(id)).filter(Boolean).map((i) => !!i.favorite);
  }

  async favoriteSelected() {
    if (this.locked) return this.withUnlock(() => this.favoriteSelected());
    const ids = [...this.multi];
    if (!ids.length) return;
    const favorite = favoriteTarget(this.selectedFavorites());
    try {
      await invoke("set_favorites", { ids, favorite });
      await this.reload();
      toast(favoritesText(ids.length, favorite));
    } catch (e) {
      this.failed(e, () => this.favoriteSelected());
    }
  }

  async deleteSelected() {
    if (this.locked) return this.withUnlock(() => this.deleteSelected());
    const ids = [...this.multi];
    if (!ids.length) return;
    const open = (this.mode === "detail" || this.mode === "edit") && ids.includes(this.selectedId);
    if (open && !this.confirmLeave()) return;
    try {
      const { deleted } = await invoke("delete_items", { ids });
      this.multi = new Set();
      if (open) {
        this.selectedId = null;
        this.showEmpty();
      }
      await this.reload();
      toast(deletedText(deleted), "", 0, {
        action: { label: t("common.undo"), icon: "undo", onClick: () => this.restoreDeleted(ids) },
      });
    } catch (e) {
      this.failed(e, () => this.deleteSelected());
    }
  }

  async restoreDeleted(ids) {
    try {
      const restored = await invoke("restore_items", { ids });
      this.multi = new Set(restored.map((i) => i.id));
      await this.reload();
      toast(restoredText(restored.length));
    } catch (e) {
      toast(errorText(e), "error");
    }
  }

  mergeSelected() {
    if (this.multi.size !== 2) return;
    const [a, b] = [...this.multi];
    this.openMerge(a, b);
  }

  async mergeWith(item) {
    if (this.locked) return this.withUnlock(() => this.mergeWith(item));
    this.closeMergeUi();
    let all;
    try {
      all = await invoke("list_items");
    } catch (e) {
      this.failed(e, () => this.mergeWith(item));
      return;
    }
    const token = (this.pickerToken = {});
    const dialog = await openMergePicker(item, all, {
      onPick: (id) => this.openMerge(item.id, id),
      onClose: () => { if (this.pickerToken === token) this.mergePicker = null; },
      onError: (e) => this.failed(e, () => this.mergeWith(item)),
    });
    if (this.pickerToken === token && dialog) this.mergePicker = dialog;
  }

  /** The merge sheet for items `a` and `b`; `opts` carries the step/heading of a series and the onNext/onCancel/onError hooks. */
  openMerge(a, b, opts = {}) {
    if (this.locked) return this.withUnlock(() => this.openMerge(a, b, opts));
    if (!this.confirmLeave()) return undefined;
    this.closeMergeUi();
    const sheet = new MergeSheet(a, b, {
      step: opts.step,
      heading: opts.heading,
      onMerged: (result) => {
        if (this.mergeSheet === sheet) this.mergeSheet = null;
        this.merged(result);
        if (opts.onNext) opts.onNext();
      },
      onSkip: () => {
        if (this.mergeSheet === sheet) this.mergeSheet = null;
        if (opts.onNext) opts.onNext();
      },
      onClose: () => {
        if (this.mergeSheet === sheet) this.mergeSheet = null;
        if (opts.onCancel) opts.onCancel();
      },
      onError: (e) => {
        if (this.mergeSheet === sheet) this.mergeSheet = null;
        if (opts.onError) opts.onError(e);
        else this.failed(e, () => this.openMerge(a, b, opts));
      },
    });
    this.mergeSheet = sheet;
    return sheet;
  }

  closeMergeUi() {
    const sheet = this.mergeSheet;
    this.mergeSheet = null;
    if (sheet) {
      sheet.hooks.onClose = null;
      sheet.close();
    }
    const picker = this.mergePicker;
    this.mergePicker = null;
    this.pickerToken = null;
    if (picker) picker.close();
  }

  async merged(result) {
    const item = result.item;
    this.multi = new Set();
    await this.reload();
    this.selectedId = item.id;
    this.renderList();
    this.showDetail(item);
    toast(t("vault.merged_into", { title: item.title }), "", 0, {
      action: { label: t("common.undo"), icon: "undo", onClick: () => this.undoMerge(item.id) },
    });
  }

  async undoMerge(id) {
    try {
      const restored = await invoke("undo_merge", { id });
      await this.reload();
      this.selectedId = restored.id;
      this.renderList();
      this.showDetail(restored);
      toast(t("vault.merge_undone"));
    } catch (e) {
      toast(errorText(e), "error");
    }
  }

  reviewMerges(pairs, onDone) {
    let i = 0;
    const done = () => {
      this.refreshMergeHint();
      if (onDone) onDone();
    };
    const next = () => {
      if (this.destroyed) return;
      if (i >= pairs.length) {
        done();
        return;
      }
      const s = pairs[i];
      i += 1;
      this.openMerge(s.login_id, s.otp_id, {
        step: pairs.length > 1 ? { index: i, total: pairs.length } : null,
        heading: t("vault.add_totp_heading", { title: s.login_title || t("common.untitled") }),
        onNext: next,
        onCancel: done,
        // Locked meanwhile: unlock and show it again; gone (merged already): the next one.
        onError: (e) => {
          if (isLockedError(e)) {
            i -= 1;
            this.failed(e, next);
          } else {
            next();
          }
        },
      });
    };
    next();
  }

  async refreshMergeHint() {
    if (this.locked || this.destroyed) return;
    const seq = (this.hintSeq = (this.hintSeq || 0) + 1);
    let list = [];
    try {
      ({ suggestions: list } = await invoke("merge_suggestions"));
    } catch {
      list = [];
    }
    if (seq !== this.hintSeq || this.locked) return;
    this.suggestions = list || [];
    this.renderMergeHint();
  }

  renderMergeHint() {
    const pending = this.locked ? [] : pendingSuggestions(this.suggestions, hintDismissed());
    if (!pending.length) {
      this.mergeHint.hidden = true;
      mount(this.mergeHint);
      return;
    }
    mount(
      this.mergeHint,
      h("div", { class: "offer merge-offer", role: "region", "aria-label": t("vault.authenticator_codes") },
        icon("merge"),
        h("div", { class: "grow" },
          h("div", { class: "t", text: hintText(pending.length) }),
          h("div", { class: "hint", text: t("vault.hint_text") }),
          h("div", { class: "row" },
            h("button", { class: "btn primary small", type: "button", text: t("import.review"), on: { click: () => this.reviewMerges(pending) } }),
            h("button", {
              class: "btn ghost small",
              type: "button",
              text: t("common.not_now"),
              on: {
                click: () => {
                  dismissHint(pending);
                  this.renderMergeHint();
                },
              },
            })))),
    );
    this.mergeHint.hidden = false;
  }

  async editFromList(id) {
    if (id !== this.selectedId) await this.select(id);
    if (this.selectedId === id && this.mode === "detail" && this.current && this.current.id === id) this.edit(this.current);
  }

  async toggleFavorite(id, { inPlace = false } = {}) {
    if (this.locked) return this.withUnlock(() => this.toggleFavorite(id, { inPlace }));
    try {
      // Rust reads the current version and flips only the star, so the toggle can't write back
      // fields another device changed (nor a copy without secrets).
      const fresh = await invoke("get_item", { id });
      if (fresh.locked) {
        this.failed({ message: LOCKED_ERROR }, () => this.toggleFavorite(id, { inPlace }));
        return;
      }
      await invoke("set_favorites", { ids: [id], favorite: !fresh.favorite });
      const saved = await invoke("get_item", { id });
      if (this.mode === "detail" && this.current && this.current.id === id) this.showDetail(saved);
      if (inPlace) this.updateRowFavorite(id, !!saved.favorite);
      else this.reload();
      toast(saved.favorite ? t("favorites.added_one") : t("favorites.removed_one"));
    } catch (e) {
      this.failed(e, () => this.toggleFavorite(id, { inPlace }));
    }
  }

  async duplicateItem(id) {
    if (this.locked) return this.withUnlock(() => this.duplicateItem(id));
    if (!this.confirmLeave()) return;
    try {
      const fresh = await invoke("get_item_for_edit", { id });
      const saved = await invoke("save_item", { item: { ...fresh, id: "", title: t("vault.copy_title", { title: fresh.title }), passkeys: [] } });
      await this.reload();
      this.select(saved.id);
      toast(t("vault.duplicated", { title: saved.title }));
    } catch (e) {
      this.failed(e, () => this.duplicateItem(id));
    }
  }

  deleteFromList(item) {
    if (!this.confirmLeave()) return;
    return this.deleteItem(item);
  }

  async showItem(id) {
    if (this.mode === "edit" && this.selectedId === id) return;
    this.closeItemMenu(false);
    if (this.search.value || this.filter !== "all" || this.tagFilter || this.vaultFilter) {
      this.search.value = "";
      this.filter = "all";
      this.tagFilter = null;
      this.vaultFilter = null;
      this.renderFilters();
      this.renderTags();
    }
    await this.reload();
    if (!this.items.some((i) => i.id === id)) return;
    await this.select(id); // asks before discarding an unsaved edit
  }

  revealAfterUnlock(id, field) {
    this.withUnlock(async () => {
      if (this.selectedId !== id) return;
      const fresh = await invoke("get_item", { id });
      if (this.selectedId !== id || this.locked) return;
      const reveal = hidden(id);
      if (field === "password" || field === "totp") reveal[field] = true;
      else if (field !== "notes" && field !== "fields") reveal.values[field] = await invoke("item_secret", { id, field });
      if (this.selectedId !== id || this.locked) return;
      this.reveal = reveal;
      this.showDetail(fresh);
    }).catch((e) => this.failed(e, () => this.revealAfterUnlock(id, field)));
  }

  /** A secret shown as dots (`mask`) until Show fetches it (`item_secret`); Copy copies in Rust. Soft-locked: both unlock first. */
  secretRow(item, label, field, { mask, copyLabel, format = (text) => text, mono = true } = {}) {
    // A fill member's item: the secret is filled, never shown or copied.
    if (itemCaps(item).fillOnly) return this.fillOnlyRow(label, mask);
    const value = h("span", { class: `value${mono ? " mono" : ""}` });
    const eye = iconButton("eye", t("vault.show_field", { field: inSentence(label) }), () => toggle());
    const paint = () => {
      const text = this.reveal.id === item.id ? this.reveal.values[field] : undefined;
      const shown = typeof text === "string";
      value.textContent = shown ? format(text) : mask;
      value.classList.toggle("masked", !shown);
      value.classList.toggle("selectable", shown);
      eye.title = shown ? t("vault.hide_field", { field: inSentence(label) }) : t("vault.show_field", { field: inSentence(label) });
      eye.setAttribute("aria-label", eye.title);
      eye.setAttribute("aria-pressed", String(shown));
      mount(eye, icon(shown ? "eyeOff" : "eye"));
    };
    let busy = false;
    const toggle = async () => {
      if (typeof this.reveal.values[field] === "string" && this.reveal.id === item.id) {
        delete this.reveal.values[field];
        paint();
        return;
      }
      if (item.locked) {
        this.revealAfterUnlock(item.id, field);
        return;
      }
      if (busy) return;
      busy = true;
      try {
        const text = await invoke("item_secret", { id: item.id, field });
        if (!this.locked && this.mode === "detail" && this.current && this.current.id === item.id && value.isConnected) {
          this.reveal.values[field] = text;
          paint();
        }
      } catch (e) {
        this.failed(e, toggle);
      } finally {
        busy = false;
      }
    };
    paint();
    const copy = iconButton("copy", t("vault.copy_field", { field: inSentence(label) }), () => this.copyFor(item.id, field, copyLabel || label));
    return h("div", { class: "frow" }, h("span", { class: "label", text: label }), value,
      h("div", { class: "actions" }, item.locked ? lockedCap(eye.title, toggle) : eye, copy));
  }

  fillOnlyRow(label, mask = PASSWORD_MASK) {
    return h("div", { class: "frow fill-only" },
      h("span", { class: "label", text: label }),
      h("span", { class: "value mono masked", text: mask || PASSWORD_MASK, "aria-label": t("teams.fill_only_value", { field: label }) }),
      h("div", { class: "actions" }, h("span", { class: "locked-cap fill-cap", title: t("teams.fill_only_tip") }, icon("fill"), t("teams.fill_only_cap"))));
  }

  copyRow(item, label, field, text, { mono = false, multiline = false } = {}) {
    return h("div", { class: "frow" },
      h("span", { class: "label", text: label }),
      h("span", { class: `value selectable${mono ? " mono" : ""}${multiline ? " pre" : ""}`, text }),
      h("div", { class: "actions" }, iconButton("copy", t("vault.copy_field", { field: inSentence(label) }), () => this.copyFor(item.id, field, label))));
  }

  cardRows(item) {
    const c = item.card || {};
    const rows = [];
    if (c.cardholder_name) rows.push(this.copyRow(item, t("vault.cardholder"), "card_holder", c.cardholder_name));
    if (c.has_number || c.last4) {
      rows.push(this.secretRow(item, t("vault.number"), "card_number", { mask: c.last4 ? `•••• •••• •••• ${c.last4}` : "•••• •••• •••• ••••", copyLabel: t("card.number"), format: groupDigits }));
    }
    const exp = expiryText(c.expiry_month, c.expiry_year);
    if (exp) {
      const expired = cardExpired(c.expiry_month, c.expiry_year);
      rows.push(h("div", { class: "frow" },
        h("span", { class: "label", text: t("card.expires") }),
        h("span", { class: "value selectable" }, exp, expired ? h("span", { class: "chip warn inline-chip", text: t("vault.expired") }) : null),
        h("div", { class: "actions" }, iconButton("copy", t("vault.copy_expiry"), () => this.copyFor(item.id, "card_expiry", t("vault.expiry_date"))))));
    }
    if (c.has_security_code || (item.locked && c.has_number)) {
      rows.push(this.secretRow(item, t("vault.security_code"), "card_code", { mask: "•••", copyLabel: t("vault.security_code") }));
    }
    if (c.has_pin) rows.push(this.secretRow(item, t("card.pin"), "card_pin", { mask: "••••", copyLabel: t("card.pin") }));
    return rows;
  }

  identitySections(item) {
    const d = item.identity || {};
    const sections = [];
    const name = [d.honorific, identityName(d)].filter(Boolean).join(" ");
    for (const [group, fields] of IDENTITY_GROUPS) {
      const rows = [];
      const first = fields[0][0];
      if (first === "honorific") {
        if (name) rows.push(this.copyRow(item, t("identity.group_name"), "identity.full_name", name));
      } else if (first === "address1") {
        const city = [d.postal_code, d.city].filter(Boolean).join(" ");
        const lines = [d.address1, d.address2, d.address3, city, d.region, d.country].filter(Boolean);
        if (lines.length) rows.push(this.copyRow(item, t("identity.address1"), "identity.address", lines.join("\n"), { multiline: true }));
      } else {
        for (const [key, label] of fields) {
          if (!d[key]) continue;
          const text = key === "birth_date" && /^\d{4}-\d{2}-\d{2}$/.test(d[key])
            ? formatDate(new Date(`${d[key]}T00:00:00`), { dateStyle: "long" })
            : d[key];
          rows.push(this.copyRow(item, label, `identity.${key}`, text));
        }
      }
      if (rows.length) sections.push(h("div", { class: "col" }, h("div", { class: "section-title", text: group }), h("div", { class: "fields" }, rows)));
    }
    if (item.locked) {
      sections.push(h("div", { class: "faint", text: t("vault.identity_locked") }));
    }
    return sections;
  }

  customFields(item) {
    if (item.locked) {
      if (!item.has_fields) return null;
      return h("div", { class: "col" }, h("div", { class: "section-title", text: t("editor.custom_fields") }),
        h("div", { class: "card notes locked-secret" }, h("span", { class: "masked grow", text: "••••••••••••" }),
          lockedCap(t("vault.unlock_to_view"), () => this.revealAfterUnlock(item.id, "fields"))));
    }
    const fields = item.fields || [];
    if (!fields.length) return null;
    const rows = fields.map((f, i) => {
      const label = f.name || t("vault.field");
      const field = `field.${i}`;
      if (f.kind === "hidden") return this.secretRow(item, label, field, { mask: f.has_value ? "••••••••" : "", copyLabel: label });
      const copy = iconButton("copy", t("vault.copy_field", { field: inSentence(label) }), () => this.copyFor(item.id, field, label));
      if (f.kind === "url" && f.value) {
        const open = iconButton("external", t("vault.open_in_browser"), () => invoke("open_item_url", { id: item.id, field }).catch((e) => this.failed(e)));
        return h("div", { class: "frow" }, h("span", { class: "label", text: label }), h("span", { class: "value selectable link-text", text: f.value }), h("div", { class: "actions" }, open, copy));
      }
      return h("div", { class: "frow" }, h("span", { class: "label", text: label }), h("span", { class: "value selectable", text: f.value }), h("div", { class: "actions" }, copy));
    });
    return h("div", { class: "col" }, h("div", { class: "section-title", text: t("editor.custom_fields") }), h("div", { class: "fields" }, rows));
  }

  tagChips(item) {
    const tags = item.tags || [];
    if (!tags.length) return null;
    return h("div", { class: "tag-chips detail-tags", "aria-label": t("editor.tags") }, tags.map((tag) =>
      h("button", { class: "chip tag-chip", type: "button", title: t("vault.tag_show", { tag }), on: { click: () => this.setTagFilter(tag) } }, icon("tag"), tag)));
  }

  /** "Password history (N)": old passwords masked; one is fetched only when shown (`password_history_entry`) and leaves the page when hidden. */
  passwordHistory(item) {
    const dates = item.password_history_at || [];
    const entries = dates.map((at, index) => {
      const value = h("span", { class: "value mono masked", text: PASSWORD_MASK });
      let shown = false;
      let busy = false;
      const eye = iconButton("eye", t("password.show"), () => toggle());
      const paint = (text) => {
        shown = text !== null;
        value.textContent = shown ? text : PASSWORD_MASK;
        value.classList.toggle("masked", !shown);
        value.classList.toggle("selectable", shown);
        eye.title = shown ? t("password.hide") : t("password.show");
        eye.setAttribute("aria-label", eye.title);
        eye.setAttribute("aria-pressed", String(shown));
        mount(eye, icon(shown ? "eyeOff" : "eye"));
      };
      const toggle = async () => {
        if (shown) return paint(null);
        if (busy) return;
        busy = true;
        try {
          const text = await invoke("password_history_entry", { id: item.id, index, replacedAt: at });
          if (!this.locked && this.mode === "detail" && this.current && this.current.id === item.id) paint(text);
        } catch (e) {
          this.failed(e, toggle);
        } finally {
          busy = false;
        }
      };
      const copy = iconButton("copy", t("vault.copy_this_password"), () => {
        const run = () =>
          invoke("copy_history_password", { id: item.id, index, replacedAt: at })
            .then(() => toast(t("vault.copied_label", { label: t("field.password") })))
            .catch((e) => this.failed(e, run));
        run();
      });
      const when = at ? t("vault.replaced_on", { date: formatDate(at, { dateStyle: "medium" }) }) : t("vault.earlier");
      return h("div", { class: "frow" }, h("span", { class: "label", text: when, title: at ? formatDateTime(at, { dateStyle: "medium", timeStyle: "medium" }) : "" }), value, h("div", { class: "actions" }, eye, copy));
    });
    return h("details", { class: "more history" },
      h("summary", {}, t("vault.password_history", { count: formatNumber(dates.length) }), icon("chevronDown")),
      h("div", { class: "fields" }, entries));
  }

  /** The item pane; `item.locked` means no secrets in it (dots with "Unlock to view"). */
  showDetail(item) {
    this.stopLive();
    this.mode = "detail";
    this.current = item;
    this.settingsView = null;
    this.editor = null;
    if (this.reveal.id !== item.id) this.reveal = hidden(item.id);
    // A changed item (an edit, a sync): secrets fetched for the old version go.
    if (this.reveal.updated_at !== item.updated_at) this.reveal.values = {};
    this.reveal.updated_at = item.updated_at;
    const reveal = this.reveal;
    const locked = !!item.locked;
    const caps = itemCaps(item);

    const rows = [];
    const row = (label, value, ...actions) =>
      h("div", { class: "frow" }, h("span", { class: "label", text: label }), value, h("div", { class: "actions" }, ...actions));
    const unlockTo = (field, label) => lockedCap(label, () => this.revealAfterUnlock(item.id, field));

    if (item.kind === "login") {
      if (item.username) {
        rows.push(row(t("field.username"), h("span", { class: "value selectable", text: item.username }),
          iconButton("copy", t("vault.copy_username"), () => this.copy("username", t("field.username")))));
      }
      const copyPassword = iconButton("copy", t("vault.copy_password"), () => this.copy("password", t("field.password")));
      if (caps.fillOnly) {
        if (item.has_password || item.password_hidden) rows.push(this.fillOnlyRow(t("field.password")));
      } else if (locked && item.has_password) {
        rows.push(row(t("field.password"), h("span", { class: "value masked mono", text: PASSWORD_MASK }),
          unlockTo("password", t("vault.unlock_show_password")), copyPassword));
      } else if (item.password) {
        const value = h("span", { class: "value mono" });
        const eye = iconButton("eye", t("password.show"), () => {
          reveal.password = !reveal.password;
          paint();
        });
        // The password is only in the DOM while shown.
        const paint = () => {
          const shown = reveal.password;
          value.textContent = shown ? item.password : PASSWORD_MASK;
          value.classList.toggle("masked", !shown);
          value.classList.toggle("selectable", shown);
          eye.title = shown ? t("password.hide") : t("password.show");
          eye.setAttribute("aria-label", eye.title);
          eye.setAttribute("aria-pressed", String(shown));
          mount(eye, icon(shown ? "eyeOff" : "eye"));
        };
        paint();
        rows.push(row(t("field.password"), value, eye, copyPassword));
      }
      const copyCode = iconButton("copy", t("vault.copy_code"), () => this.copy("totp", t("vault.code")));
      if (locked && item.has_totp) {
        rows.push(row(t("field.totp"), h("div", { class: "value totp" }, h("span", { class: "code masked", text: "••• •••" })),
          unlockTo("totp", t("vault.unlock_show_code")), copyCode));
      } else if (item.totp) {
        const code = maskedCode({ revealed: reveal.totp, onToggle: (on) => { reveal.totp = on; } });
        const countdown = ring();
        const resume = h("button", { class: "btn small", type: "button", text: t("code.show"), hidden: true });
        const startLive = () => {
          resume.hidden = true;
          this.stopLive();
          this.live = liveTotp(() => invoke("totp", { id: item.id }), {
            shouldRefresh: userActive,
            onCode: (c, remaining, period) => {
              if (c === null) {
                code.set(null);
                resume.hidden = false;
                this.stopLive();
                return;
              }
              if (c) code.set(c);
              countdown.set(remaining, period);
            },
            onError: (msg) => { code.setText(msg); },
          });
        };
        resume.addEventListener("click", startLive);
        rows.push(row(t("field.totp"), h("div", { class: "value totp" }, countdown.el, code.el, resume), code.eye, copyCode));
        startLive();
      }
      if (item.urls && item.urls.length) {
        rows.push(row(t("field.websites"), h("div", { class: "value col" },
          item.urls.map((u, i) => APP_PIN.test(u)
            ? h("span", { class: "url-line" },
                h("span", { class: "selectable" }, tx("vault.desktop_app", { app: h("span", { class: "faint", text: t("vault.desktop_app_label") }), exe: u.replace(APP_PIN, "") })),
                itemRuleBadge(item, { url: u }))
            : h("span", { class: "url-line" },
                h("span", { class: "selectable grow", text: u }),
                itemRuleBadge(item, { url: u }),
                /^(https?:\/\/|[^:/\s]+\.[^:/\s]+)/i.test(u)
                  ? iconButton("external", t("vault.open_in_browser"), () => invoke("open_item_url", { id: item.id, field: `url.${i}` }).catch((e) => this.failed(e)), "ghost small")
                  : null)))));
      }
      if (item.android_apps && item.android_apps.length) {
        rows.push(row(t("field.android_apps"), h("div", { class: "value col faint" }, item.android_apps.map((a) => h("span", { class: "url-line" }, h("span", { text: a }), itemRuleBadge(item, { app: a }))))));
      }
    }

    if (item.kind === "card") rows.push(...this.cardRows(item));
    const identity = item.kind === "identity" ? this.identitySections(item) : null;

    const fav = caps.edit ? iconButton(item.favorite ? "starFilled" : "star", item.favorite ? t("favorites.remove") : t("favorites.add"), () => this.toggleFavorite(item.id)) : null;

    let notes = null;
    if (locked && item.has_notes) {
      notes = h("div", { class: "col" }, h("div", { class: "section-title", text: t("field.notes") }),
        h("div", { class: "card notes locked-secret" }, h("span", { class: "masked grow", text: PASSWORD_MASK }), unlockTo("notes", t("vault.unlock_show_notes"))));
    } else if (item.notes) {
      notes = h("div", { class: "col" }, h("div", { class: "section-title", text: t("field.notes") }), h("div", { class: "card notes selectable", text: item.notes }));
    }
    const lockedNote = locked
      ? h("div", { class: "locked-note", role: "note" },
          icon("lock"),
          h("span", { class: "grow", text: item.kind === "card"
            ? t("vault.locked_card")
            : t("vault.locked_item") }),
          h("button", { class: "btn primary", type: "button", on: { click: () => this.unlock({ hello: true }) } }, t("unlock.unlock")))
      : null;

    const del = caps.edit ? h("button", { class: "btn danger", type: "button", title: t("vault.delete_title"), on: { click: () => this.deleteItem(item) } }, icon("trash"), t("vault.delete")) : null;
    const vaultName = this.vaultNameOf(item);
    const roleNote = itemRoleNote(item);
    const updated = item.updated_at ? t("vault.updated_on", { date: formatDateTime(item.updated_at, { dateStyle: "medium", timeStyle: "short" }) }) : "";
    const kindText = item.kind === "card" ? cardLabel(item.card) : item.kind === "identity" ? t("kind.identity") : item.kind === "note" ? t("kind.note") : "";

    mount(
      this.pane,
      h("div", { class: "pane-inner" },
        h("div", { class: "pane-header" },
          itemAvatar(item),
          h("div", { class: "grow" }, h("h2", { class: "ellipsis selectable", text: item.title, title: item.title }),
            updated || kindText ? h("div", { class: "faint ellipsis", text: [kindText !== item.title ? kindText : "", updated].filter(Boolean).join(" · ") }) : null,
            vaultName ? h("div", { class: "faint ellipsis item-vault" }, icon("folder"), t("teams.in_vault", { vault: vaultName })) : null),
          fav,
          caps.edit ? h("button", { class: "btn", type: "button", title: withShortcut(t("common.edit"), "Mod+E"), on: { click: () => this.edit(item) } }, icon("edit"), t("common.edit")) : null),
        lockedNote,
        roleNote ? h("div", { class: "locked-note role-note", role: "note" }, icon(caps.fillOnly ? "fill" : "eye"), h("span", { class: "grow", text: roleNote })) : null,
        this.tagChips(item),
        rows.length ? h("div", { class: "fields" }, rows) : null,
        identity,
        this.customFields(item),
        notes,
        !locked && caps.reveal && item.password_history_at && item.password_history_at.length ? this.passwordHistory(item) : null,
        item.passkeys && item.passkeys.length
          ? h("div", { class: "col" },
              h("div", { class: "section-title", text: t("field.passkeys") }),
              h("div", { class: "fields" }, item.passkeys.map((pk) =>
                h("div", { class: "frow" }, icon("key"),
                  h("div", { class: "value" },
                    h("div", { text: pk.user_name || pk.user_display_name }),
                    h("div", { class: "faint", text: pk.created_at ? t("editor.passkey_created", { site: pk.rp_id, date: formatDate(pk.created_at, { dateStyle: "short" }) }) : pk.rp_id }))))))
          : null,
        del ? h("div", { class: "row" }, h("span", { class: "spacer" }), del) : null,
      ),
    );
    watchIcons(this.pane);
  }

  async deleteItem(item) {
    if (this.locked) return this.withUnlock(() => this.deleteItem(item));
    try {
      await invoke("delete_item", { id: item.id });
      this.selectedId = null;
      this.showEmpty();
      this.reload();
      toast(t("vault.moved_to_trash", { title: item.title }), "", 0, {
        action: {
          label: t("common.undo"),
          icon: "undo",
          onClick: async () => {
            try {
              const restored = await invoke("restore_item", { id: item.id });
              await this.reload();
              this.selectedId = restored.id;
              this.renderList();
              this.showDetail(restored);
            } catch (e) {
              toast(errorText(e), "error");
            }
          },
        },
      });
    } catch (e) {
      this.failed(e, () => this.deleteItem(item));
    }
  }

  async edit(item, kind = "login") {
    if (this.locked) return this.withUnlock(() => this.edit(item, kind));
    let shown = null;
    if (item && item.id) {
      // Edit the current version, whole (card number and codes, hidden fields), not the copy
      // shown when the item was opened. Locked meanwhile: this fails, unlocks and retries.
      const original = item;
      try {
        [item, shown] = await Promise.all([invoke("get_item_for_edit", { id: item.id }), invoke("get_item", { id: item.id })]);
      } catch (e) {
        this.failed(e, () => this.edit(original));
        return;
      }
    }
    this.stopLive();
    this.mode = "edit";
    this.settingsView = null;
    this.editor = new Editor(this.pane, item, {
      onSaved: (saved) => {
        this.selectedId = saved.id;
        this.editor = null;
        this.showDetail(saved);
        this.reload();
      },
      onCancel: () => {
        this.editor = null;
        // The detail view's copy, never the editor's (which holds the card number and codes).
        if (shown) this.showDetail(shown);
        else this.showEmpty();
      },
    }, {
      kind,
      tags: this.tagFilter ? [this.tagFilter] : [],
      vaults: this.openVaults,
      vault: defaultSaveVault(this.openVaults, this.vaultFilter),
    });
  }

  newItem(kind = "login") {
    if (this.locked) {
      this.withUnlock(() => this.newItem(kind));
      return;
    }
    if (!this.confirmLeave()) return;
    this.selectedId = null;
    this.renderList();
    this.edit(null, kind);
  }

  openNewMenu() {
    if (this.skipAnchorClick === this.newBtn && Date.now() - this.skipAnchorAt < 1000) {
      this.skipAnchorClick = null;
      return;
    }
    const r = this.newBtn.getBoundingClientRect();
    this.openMenu(KINDS.map(([kind, label, iconName]) => [iconName, label, () => this.newItem(kind), "", kind === "login" ? keyLabel("Mod+N") : ""]), r.left, r.bottom + 4, t("editor.new_item"), { anchor: this.newBtn });
  }

  openMoreMenu() {
    if (this.skipAnchorClick === this.moreBtn && Date.now() - this.skipAnchorAt < 1000) {
      this.skipAnchorClick = null;
      return;
    }
    const r = this.moreBtn.getBoundingClientRect();
    this.openMenu([
      ["download", t("vault.import_title"), () => this.showImport()],
      ["upload", t("export.submit"), () => this.exportVault(), "", t("vault.export_hint")],
      "sep",
      ["mail", t("settings.generator"), () => this.showSettings({ page: "generator" })],
      ["lock", t("tray.lock_completely"), () => this.lockCompletely(), "", keyLabel("Mod+Shift+L")],
    ], r.right + 6, r.top, t("vault.more"), { anchor: this.moreBtn });
  }

  goHome(filter = "all") {
    if (!["empty", "detail", "edit"].includes(this.mode)) {
      if (!this.confirmLeave()) return;
      this.showEmpty();
    }
    const searched = !!this.search.value;
    this.filter = filter;
    this.tagFilter = null;
    this.vaultFilter = null;
    this.search.value = "";
    this.renderFilters();
    this.renderTags();
    if (searched) this.reload();
    else this.renderList();
  }

  showGenerator() {
    if (!this.confirmLeave()) return;
    this.leavePane();
    this.mode = "generator";
    const close = () => this.showEmpty();
    const inner = h("div", { class: "pane-inner generator-page" },
      h("div", { class: "pane-header" },
        iconButton("back", withShortcut(t("common.back"), t("keys.esc")), close),
        h("h2", { class: "grow", text: t("rail.generator") })),
      h("p", { class: "muted", text: t("rail.generator_intro") }),
      generatorPanel(null),
      h("div", { class: "row" },
        h("button", { class: "btn", type: "button", on: { click: () => this.showSettings({ page: "generator" }) } }, icon("mail"), t("settings.generator"))));
    inner.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && !e.defaultPrevented && !document.querySelector(".modal-backdrop")) {
        e.preventDefault();
        close();
      }
    });
    mount(this.pane, inner);
  }

  railKey() {
    const mode = this.mode;
    if (mode === "settings") return this.settingsView && this.settingsView.page === "help" ? "help" : "settings";
    if (["generator", "health", "trash", "teams"].includes(mode)) return mode;
    if (mode === "import") return "more";
    return this.filter === "favorites" ? "favorites" : "home";
  }

  paintRail() {
    if (this.rail) this.rail.setActive(this.railKey());
  }

  get mode() {
    return this.currentMode;
  }

  set mode(mode) {
    this.currentMode = mode;
    if (this.app) this.app.classList.toggle("settings-open", mode === "settings");
    if (this.settingsNav) this.settingsNav.hidden = mode !== "settings";
    this.paintRail();
  }

  renderSettingsNav(sections, current) {
    const focused = this.settingsNav.contains(document.activeElement);
    mount(this.settingsNav, h("ul", { class: "settings-nav-list" }, sections.map(({ key, label }) => {
      const on = key === current;
      return h("li", {}, h("button", {
        class: `settings-nav-item${on ? " current" : ""}`,
        type: "button",
        tabindex: on ? "0" : "-1",
        "aria-current": on ? "page" : null,
        dataset: { section: key },
        on: { click: () => this.settingsView && this.settingsView.showSection(key) },
      }, label));
    })));
    if (focused) {
      const button = this.settingsNav.querySelector(".settings-nav-item.current");
      if (button) button.focus({ preventScroll: true });
    }
  }

  settingsNavKeys(e) {
    const buttons = [...this.settingsNav.querySelectorAll(".settings-nav-item")];
    const i = buttons.indexOf(document.activeElement);
    if (i < 0) return;
    const to = { ArrowDown: i + 1, ArrowUp: i - 1, Home: 0, End: buttons.length - 1 }[e.key];
    if (to === undefined) return;
    e.preventDefault();
    const next = buttons[(to + buttons.length) % buttons.length];
    for (const b of buttons) b.tabIndex = b === next ? 0 : -1;
    next.focus();
  }

  showTrash() {
    if (this.locked) {
      this.withUnlock(() => this.showTrash());
      return;
    }
    if (!this.confirmLeave()) return;
    this.leavePane();
    this.mode = "trash";
    this.trashView = new TrashView(this.pane, {
      onClose: () => { this.trashView = null; this.showEmpty(); },
      onChanged: () => this.reload(),
      onError: (e, retry) => this.failed(e, retry),
    });
  }

  showHealth() {
    if (this.locked) {
      this.withUnlock(() => this.showHealth());
      return;
    }
    if (!this.confirmLeave()) return;
    this.leavePane();
    this.mode = "health";
    this.healthView = new HealthView(this.pane, {
      onClose: () => { this.healthView = null; this.showEmpty(); },
      onEdit: (id) => this.editById(id),
      onFindDuplicates: () => this.showImport({ duplicates: true }),
      onError: (e, retry) => this.failed(e, retry),
    });
  }

  exportVault() {
    if (this.locked) {
      this.withUnlock(() => this.exportVault());
      return;
    }
    openExportDialog({ onError: (e, retry) => this.failed(e, retry) });
  }

  async editById(id) {
    this.stopLive();
    this.filter = "all";
    this.tagFilter = null;
    this.search.value = "";
    this.renderFilters();
    await this.reload();
    this.selectedId = id;
    this.renderList();
    this.edit({ id });
  }

  leavePane() {
    this.stopLive();
    this.editor = null;
    this.settingsView = null;
    this.current = null;
    this.selectedId = null;
    this.renderList();
  }

  showSettings(options = {}) {
    if (this.locked) {
      this.withUnlock(() => this.showSettings(options));
      return;
    }
    if (!this.confirmLeave()) return;
    this.stopLive();
    this.mode = "settings";
    this.editor = null;
    this.selectedId = null;
    this.renderList();
    this.settingsView = new SettingsView(this.pane, {
      onClose: () => this.showEmpty(),
      onPage: () => this.paintRail(),
      onSynced: () => {
        this.reload();
        this.onLockChange();
      },
      onSwitchVault: (anchor) => this.openVaultMenu(anchor),
      onSections: (sections, current) => this.renderSettingsNav(sections, current),
      activeVault: () => this.activeVault(),
      onVaultChanged: () => this.onLockChange(),
      onRenamed: () => this.onLockChange(),
      onAccount: () => { this.loadTeams(); this.loadAccount(); this.reload({ quiet: true }); },
      onImport: (options) => this.viaSettings(() => this.showImport(options)),
      onExport: () => this.exportVault(),
      onHealth: () => this.viaSettings(() => this.showHealth()),
      onTrash: () => this.viaSettings(() => this.showTrash()),
      onGetStarted: () => {
        this.status = { ...this.status, get_started: true };
        this.showEmpty();
      },
    }, options);
    this.paintRail();
  }

  async importDropped() {
    if (this.locked) return this.withUnlock(() => this.importDropped());
    if (!this.confirmLeave()) return;
    this.showImport({ dropped: true });
  }

  viaSettings(open) {
    open();
    const inner = this.pane.querySelector(":scope > .pane-inner");
    if (inner && this.mode !== "settings") inner.classList.add("via-settings");
  }

  showImport(options = {}) {
    if (this.locked) {
      this.withUnlock(() => this.showImport(options));
      return;
    }
    if (this.mode === "edit" && !options.dropped && !this.confirmLeave()) return;
    this.stopLive();
    this.mode = "import";
    this.editor = null;
    this.settingsView = null;
    this.selectedId = null;
    this.renderList();
    this.importView = new ImportView(this.pane, {
      onClose: () => { this.importView = null; this.showEmpty(); },
      onImported: () => this.reload(),
      onReviewMerges: (pairs, done) => this.reviewMerges(pairs, done),
    }, options);
  }

  pillClicked() {
    if (this.locked) {
      this.withUnlock(() => this.pillClicked());
      return;
    }
    if (this.signedOut) openSignInAgainDialog({ onDone: () => this.reload() });
    else if (this.signInNeeded) this.googleSignInAgain();
    else this.syncNow();
  }

  async googleSignInAgain() {
    const google = this.status && this.status.google_drive;
    try {
      const account = await googleSignIn({ email: google ? google.email : null });
      if (!account) return;
      this.syncStatus({ running: true });
      await invoke("google_drive_enable", { email: account.email });
      this.syncStatus({});
      toast(t("settings.google_signed_in_again"));
      this.reload();
    } catch (e) {
      toast(errorText(e), "error");
      this.syncStatus({ sign_in_needed: true });
    }
  }

  async syncNow() {
    if (this.locked) return this.withUnlock(() => this.syncNow());
    this.syncStatus({ running: true });
    try {
      const r = await invoke("sync_now");
      this.syncStatus({});
      const changes = r ? r.added + r.updated + r.deleted : 0;
      toast(changes ? t("settings.synced_toast", { added: formatNumber(r.added), updated: formatNumber(r.updated), deleted: formatNumber(r.deleted) }) : t("settings.up_to_date"));
      this.reload();
    } catch (e) {
      const text = errorText(e);
      // sync_now's error says whether this device is signed out (any language).
      this.syncStatus({ last_error: text, signed_out: !!(e && e.signed_out) });
    }
  }
}
