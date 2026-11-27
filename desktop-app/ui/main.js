// Main window: onboarding (no vaults yet) → unlock (one vault: its unlock form; several: the vault
// list) → vault (unlocked). "Add vault" opens the add chooser over whichever is up; the open vault
// stays open until the new one is set up. Re-renders when the lock state changes or the browser
// extension asks for an unlock.
//
// Soft lock (the default for auto-lock, Ctrl+L, tray "Lock", Win+L and sleep): the vault view stays,
// showing the list without secrets, and asks to unlock (in a dialog) only when a password, a 2FA
// code or an edit is wanted. A full lock ("Lock completely", "Switch vault") shows the unlock
// screen; so does start-up, unless the app starts soft-locked with the list kept from the last run.
//
// Passyble Server links and addresses (from the extension or the pass+server:// URL scheme) arrive
// here. A pairing link (with a device token) opens "Connect to Passyble Server". Any other link or
// address opens the sign-in: in a dialog while a vault is unlocked (nothing is locked until it
// finishes; a reset can re-encrypt the open vault), else as a form. Nothing is stored until the
// user confirms.
//
// An otpauth:// link (Rust keeps it): the vault unlocks first, then the confirmation. Without a
// vault: a message.

import { errorText, h, icon, invoke, listen, onShown, pressEscape, setProblemReporter, t, toast } from "./lib.js";
import { isMac, setPlatform } from "./platform.js";
import { appKeyCommand } from "./views/app-keys.js";
import { startTitlebar } from "./titlebar.js";
import { openKeyNotice } from "./views/account-reset.js";
import { startAppVersions } from "./views/app-versions.js";
import { reportProblem, startSupport } from "./views/support.js";
import { closeSetup, maybeOpenSetup, setSetupHost } from "./views/setup.js";
import { Onboarding } from "./views/onboarding.js";
import { closeOtpauthDialog, openOtpauthDialog } from "./views/otpauth.js";
import { unlockNotice } from "./views/otpauth-model.js";
import { closeServerDialog, openServerDialog } from "./views/server.js";
import { openLinkDialog } from "./views/signin.js";
import { UnlockPanel } from "./views/unlock.js";
import { VaultsView } from "./views/vaults.js";
import { VaultView } from "./views/vault.js";

const root = document.getElementById("root");
startTitlebar();
let view = null;
let viewName = "";
// "choose" while the add chooser or one of its forms is open, "server" for the Passyble Server form
// (prefilled with `serverLink`).
let adding = null;
let serverLink = null;
// Another vault from "Switch vault" is unlocking: the vault being left locks first, so the lock
// state changes twice; the vault view stays until done.
let switchingVault = false;
// "Open in Passyble" from the browser extension while locked: opened after unlock.
let pendingItem = null;
// Teams and Family asked for while no vault was open.
let pendingTeams = null;
// "New secure note" from its global shortcut while no vault was open.
let pendingNew = null;
// Settings at a section (`{ section }`) asked for while no vault was open.
let pendingSettings = null;
// Open Settings again once the vault view is up: after a language change reloaded the window, or
// (with options) after "Set up sync" switched vault.
let reopenSettings = false;
try {
  reopenSettings = sessionStorage.getItem("pass.reopen-settings") === "1";
  sessionStorage.removeItem("pass.reopen-settings");
} catch {
  // No session storage: nothing to reopen.
}

class SingleUnlock {
  constructor(status, onDone, onAdd) {
    this.panel = new UnlockPanel(root, status.vaults[0], status, onDone, { onAdd });
    this.panel.focus();
  }
  update(status) {
    if (status.vaults[0]) this.panel.update(status, status.vaults[0]);
  }
  destroy() {
    this.panel.destroy();
  }
}

async function refresh() {
  if (switchingVault) return;
  let status;
  try {
    status = await invoke("status");
  } catch (e) {
    toast(errorText(e), "error");
    return;
  }
  setPlatform(status.platform);
  const vaults = status.vaults || [];
  const hasVaults = vaults.length > 0;
  const listed = !status.locked || !!status.soft_locked;
  if (!hasVaults) adding = null;
  if (status.locked) {
    closeServerDialog();
    closeOtpauthDialog();
    closeSetup();
  }
  const name = !hasVaults
    ? "onboarding"
    : adding
      ? `onboarding-${adding}`
      : listed
        ? "vault"
        : vaults.length === 1
          ? "single"
          : "vaults";
  if (name === viewName && view) {
    view.update(status);
    flushPendingItem();
    otpauthFlush();
    if (name === "vault") maybeOpenSetup(status);
    return;
  }
  if (view && view.destroy) view.destroy();
  viewName = name;
  const done = () => refresh();
  const openFlow = (flow) => {
    adding = flow;
    serverLink = null;
    refresh();
  };
  if (name === "onboarding") view = new Onboarding(root, status, done);
  else if (name.startsWith("onboarding-")) {
    view = new Onboarding(root, status, () => openFlow(null), { start: adding, link: serverLink, onBack: () => openFlow(null) });
  } else if (name === "single") {
    view = new SingleUnlock(status, done, () => openFlow("choose"));
  } else if (name === "vaults") {
    view = new VaultsView(root, status, done, { onAdd: () => openFlow("choose") });
  } else {
    view = new VaultView(root, status, done);
    const vaultView = view;
    setSetupHost({
      vaultName: () => vaultView.status.active_vault_name || "",
      reload: () => vaultView.reload({ quiet: true }),
      openSettings: (section) => vaultView.showSettings({ section }),
      reviewMerges: (pairs, onDone) => vaultView.reviewMerges(pairs, onDone),
    });
    maybeOpenSetup(status);
  }
  flushPendingItem();
  otpauthFlush();
  if (reopenSettings && viewName === "vault" && view.showSettings) {
    const options = reopenSettings === true ? {} : reopenSettings;
    reopenSettings = false;
    view.showSettings(options);
  }
}

/** Opens what was asked for once the vault view is up (a request expires after 5 minutes). */
function flushPendingItem() {
  if (pendingSettings && viewName === "vault" && view && view.showSettings) {
    const { section, at } = pendingSettings;
    pendingSettings = null;
    if (Date.now() - at < 5 * 60 * 1000) view.showSettings({ section });
  }
  if (pendingNew && viewName === "vault" && view && view.newItem) {
    const { kind, at } = pendingNew;
    pendingNew = null;
    if (Date.now() - at < 5 * 60 * 1000) view.newItem(kind);
  }
  if (pendingTeams && viewName === "vault" && view && view.showTeams) {
    const { section, at } = pendingTeams;
    pendingTeams = null;
    if (Date.now() - at < 5 * 60 * 1000) view.showTeams(section);
  }
  if (!pendingItem) return;
  if (Date.now() - pendingItem.at > 5 * 60 * 1000) pendingItem = null;
  else if (viewName === "vault" && view && view.showItem) {
    const { id } = pendingItem;
    pendingItem = null;
    view.showItem(id);
  }
}

/** Locks the open vault completely and shows the Passyble Server form. */
async function addServerVault(link) {
  const status = await invoke("status").catch(() => null);
  if (status && (!status.locked || status.soft_locked)) await invoke("lock", { full: true }).catch(() => {});
  adding = "server";
  serverLink = link || null;
  viewName = ""; // rebuild even if the form is already open
  refresh();
}

const isPairingLink = (link) => /^\s*pass\+server:\/\//i.test(link) && /[?&]token=/.test(link);

async function serverPairRequested() {
  const link = await invoke("server_pair_take").catch(() => null);
  if (!link) return;
  const status = await invoke("status").catch(() => null);
  if (!status) return;
  const unlocked = !status.locked && (status.vaults || []).length > 0;
  if (unlocked && !isPairingLink(link)) {
    // Sign in without locking the open vault.
    openLinkDialog(link, () => {
      viewName = ""; // the active vault may have changed
      refresh();
    });
    return;
  }
  if (!unlocked) {
    addServerVault(link);
    return;
  }
  openServerDialog({
    link,
    vaultName: status.active_vault_name,
    onConnected: () => view && view.reload && view.reload(),
    onAddSeparate: addServerVault,
  });
}

let otpauthBanner = null;
// The link whose soft-lock unlock dialog is up.
let otpauthUnlocking = 0;

function showOtpauthBanner(link) {
  hideOtpauthBanner();
  otpauthBanner = h(
    "div",
    { class: "banner otpauth-banner", role: "status" },
    h("span", { class: "grow", text: unlockNotice(link) }),
    h("button", {
      class: "btn",
      type: "button",
      text: t("common.cancel"),
      on: {
        click: () => {
          invoke("otpauth_cancel", { id: link.id }).catch(() => {});
          hideOtpauthBanner();
        },
      },
    }),
  );
  document.body.append(otpauthBanner);
}

function hideOtpauthBanner() {
  if (otpauthBanner) otpauthBanner.remove();
  otpauthBanner = null;
}

async function otpauthFlush() {
  const link = await invoke("otpauth_pending").catch(() => null);
  if (!link) {
    hideOtpauthBanner();
    closeOtpauthDialog();
    return;
  }
  if (link.rejected) {
    toast(link.rejected, "error");
    return;
  }
  const status = await invoke("status").catch(() => null);
  if (!status) return;
  if (!(status.vaults || []).length) {
    toast(t("otpauth.no_vault"), "error");
    invoke("otpauth_cancel", { id: link.id }).catch(() => {});
    return;
  }
  if (!status.locked) {
    hideOtpauthBanner();
    openOtpauthDialog(link, {
      onAdded: (item) => {
        if (view && view.reload) view.reload({ quiet: true });
        if (view && view.showItem) view.showItem(item.id);
      },
    });
    return;
  }
  if (!status.soft_locked || viewName !== "vault" || !view.unlock) {
    showOtpauthBanner(link);
    return;
  }
  if (otpauthUnlocking === link.id) return;
  hideOtpauthBanner();
  otpauthUnlocking = link.id;
  // No automatic Windows Hello: a web page can open a link.
  const unlocked = await view.unlock({ hello: false });
  otpauthUnlocking = 0;
  if (unlocked) otpauthFlush();
  else invoke("otpauth_cancel", { id: link.id }).catch(() => {});
}

// An export file dropped on the window opens the import preview (Rust keeps the path).
let overlay = null;
function showDropOverlay(show) {
  if (show && !overlay) {
    overlay = h("div", { class: "drop-overlay", "aria-hidden": "true" }, icon("download"), h("div", { text: t("main.drop_title") }),
      h("div", { class: "faint", text: t("main.drop_sub") }));
    document.body.append(overlay);
  } else if (!show && overlay) {
    overlay.remove();
    overlay = null;
  }
}

listen("tauri://drag-enter", () => showDropOverlay(true)).catch(() => {});
listen("tauri://drag-leave", () => showDropOverlay(false)).catch(() => {});
listen("tauri://drag-drop", () => showDropOverlay(false)).catch(() => {});
listen("import-dropped", () => {
  showDropOverlay(false);
  if (view && view.importDropped) view.importDropped();
  else toast(t("main.drop_locked"));
});

window.addEventListener("pass-server-add", (e) => addServerVault(e.detail));
window.addEventListener("pass-add-vault", () => {
  adding = "choose";
  serverLink = null;
  refresh();
});
// Hold the vault view while "Switch vault" unlocks; afterwards rebuild it for the new vault, or
// catch up after a failed or cancelled unlock.
window.addEventListener("pass-vault-switching", (e) => {
  switchingVault = !!e.detail;
  if (!switchingVault) refresh();
});
window.addEventListener("pass-vault-switched", (e) => {
  switchingVault = false;
  if (e.detail) reopenSettings = e.detail;
  viewName = "";
  refresh();
});
listen("server-pair-requested", serverPairRequested);
listen("otpauth-requested", otpauthFlush);
listen("show-item", (p) => {
  if (!p || !p.id) return;
  pendingItem = { id: String(p.id), at: Date.now() };
  flushPendingItem();
});
listen("show-settings", (p) => {
  pendingSettings = { section: (p && p.section) || null, at: Date.now() };
  flushPendingItem();
});
listen("new-item", (p) => {
  const kind = p && ["login", "note", "card", "identity"].includes(p.kind) ? p.kind : "login";
  pendingNew = { kind, at: Date.now() };
  flushPendingItem();
});
listen("lock-state", refresh);
listen("vaults-changed", refresh);
// Hidden in the tray, the window may have slept through an unlock.
onShown(refresh);
listen("unlock-requested", refresh);
listen("hello-available", refresh);
// A sync or the browser extension changed the vault.
listen("vault-changed", () => {
  if (view && view.reload) view.reload({ quiet: true });
  if (view && view.loadPins) view.loadPins();
});
// The extension's vault switcher: unlocked, the other vault's unlock opens over this one; locked,
// the app already made it the active vault.
listen("switch-vault", (p) => {
  if (viewName === "vault" && view && !view.locked && view.switchToId) view.switchToId(p && p.id);
  else if (viewName === "vault" || viewName === "vaults") {
    viewName = "";
    refresh();
  }
});
listen("sync-status", (s) => view && view.syncStatus && view.syncStatus(s));
// Teams and Family: the overview changed, or the tray or extension asked for the screen (while
// locked it opens after the unlock).
listen("teams-changed", () => view && view.teamsChanged && view.teamsChanged());
listen("show-teams", (p) => {
  if (view && view.showTeams) view.showTeams((p && p.section) || null);
  else pendingTeams = { section: (p && p.section) || null, at: Date.now() };
});
// The extension's Sign out in app mode: Settings at the account row, where the user confirms.
listen("show-account", () => {
  if (viewName === "vault" && view && view.showSettings) view.showSettings({ section: "sync" });
  else pendingSettings = { section: "sync", at: Date.now() };
});
listen("update-state", (u) => view && view.updateState && view.updateState(u));

/**
 * Runs command `name` (`e`: its keydown, or null from the menu bar): the vault view's own. Outside
 * it: Close Window, and from the menu also Lock, New Item and Settings. True when it was done.
 */
function runCommand(name, e = null) {
  if (view && view.command) return view.command(name, e);
  if (name === "close") {
    if (!pressEscape(document.activeElement)) invoke("hide_window");
    return true;
  }
  if (e) return false;
  if (name === "lock" || name === "lock_full") invoke("lock", name === "lock" ? {} : { full: true, forget: true }).catch(() => {});
  else if (name === "new") pendingNew = { kind: "login", at: Date.now() };
  else if (name === "settings") pendingSettings = { section: null, at: Date.now() };
  else return false;
  return true;
}

document.addEventListener("keydown", (e) => {
  const name = appKeyCommand(e, isMac());
  if (name && runCommand(name, e)) e.preventDefault();
});
// A Mac's menu bar.
listen("menu-command", (p) => p && p.command && runCommand(String(p.command)));
listen("toast", (message) => toast(String(message)));
// Account key notices after an unlock: a reset another device started, a changed key, a Team that
// requires admin recovery.
listen("account-key-notice", (notice) => openKeyNotice(notice, { onChanged: () => view && view.reload && view.reload({ quiet: true }) }));

refresh();
serverPairRequested();
startAppVersions();
startSupport();
setProblemReporter(reportProblem);
