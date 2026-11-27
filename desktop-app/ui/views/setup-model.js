// The guided setup (setup.js): which steps this computer gets and in what order, where Continue, Skip
// for now and Back go, where it resumes, and which steps are done. Pure (no DOM, no Tauri). A step that
// doesn't apply is left out and the others are numbered without it. Rust keeps where it stands
// (settings.rs `SetupProgress`).

import { t } from "../i18n.js";

export const STEPS = ["browser", "sync", "recovery"];
export const DONE = "done";
export const EXTRAS = ["import", "passkeys", "shortcuts"];

/**
 * Every id the setup has saved, in the order of its first version. A setup saved by that version goes
 * on at the first step of today's at or after its own.
 */
const SAVED_ORDER = ["vault", "password", "unlock", "auto_lock", "browser", "passkeys", "shortcuts", "sync", "import", "recovery", DONE];

/**
 * The steps this computer gets. `ctx`: `sync` (this copy can sync), `synced` (the vault syncs
 * already), `account` (signed in to a Passyble account). Left out (undefined), `sync` counts as yes,
 * the others as no.
 */
export function setupSteps(ctx = {}) {
  return STEPS.filter((id) => id !== "sync" || (ctx.sync !== false && ctx.synced !== true && ctx.account !== true));
}

/** The optional links of the "You're set" screen; `passkeys` is Windows 11 only, `shortcuts` undefined counts as yes. */
export function setupExtras(ctx = {}) {
  return EXTRAS.filter((id) => {
    if (id === "passkeys") return ctx.platform === "windows" && ctx.passkeys === true;
    if (id === "shortcuts") return ctx.shortcuts !== false;
    return true;
  });
}

export function firstStep(steps) {
  return steps[0] || DONE;
}

export function nextStep(steps, id) {
  if (id === DONE) return null;
  const i = steps.indexOf(id);
  if (i < 0) return null;
  return steps[i + 1] || DONE;
}

export function previousStep(steps, id) {
  if (id === DONE) return steps[steps.length - 1] || null;
  const i = steps.indexOf(id);
  return i > 0 ? steps[i - 1] : null;
}

/** Where a saved setup goes on: its step, else the next one this computer has, else "You're set". */
export function resumeStep(steps, saved) {
  if (saved === DONE || steps.includes(saved)) return saved;
  const at = SAVED_ORDER.indexOf(saved);
  if (!saved || at < 0) return firstStep(steps);
  return SAVED_ORDER.slice(at).find((id) => steps.includes(id)) || DONE;
}

export function stepPosition(steps, id) {
  const i = steps.indexOf(id);
  return i < 0 ? null : { number: i + 1, total: steps.length };
}

export function stepLabel(id) {
  switch (id) {
    case "browser": return t("setup.step_browser");
    case "sync": return t("setup.step_sync");
    case "recovery": return t("setup.step_recovery");
    default: return "";
  }
}

export function stepDone(id, facts = {}) {
  switch (id) {
    case "browser": return Boolean(facts.browser);
    case "sync": return Boolean(facts.sync);
    case "recovery": return facts.recovery === true;
    default: return false;
  }
}

export function browserRows(browsers = []) {
  const found = browsers.filter((b) => b.installed);
  const rows = found.length ? found : browsers.filter((b) => ["chrome", "edge", "firefox"].includes(b.id));
  return rows.slice().sort((a, b) => Number(Boolean(b.default)) - Number(Boolean(a.default)));
}

export function browserToAdd(rows = [], connected = null) {
  return connected ? null : rows[0] || null;
}

/** The sync step's choices; with Google Drive it is preselected and recommended. */
export function syncChoices({ google = false, server = true } = {}) {
  const rare = ["account", ...(server ? ["server", "webdav"] : [])];
  if (google) return { shown: ["google", "local"], more: rare, selected: "google", recommended: "google" };
  return { shown: ["local", ...rare], more: [], selected: "local", recommended: null };
}

export function syncAction(id) {
  return {
    google: "setup.sync_turn_on",
    account: "setup.sync_sign_in",
    server: "setup.sync_connect",
    webdav: "setup.sync_open_settings",
  }[id] || "setup.sync_keep_local";
}

/** What the recovery step's main button does: "kit", "code" or null (Continue). */
export function recoveryAction({ linked = false, made = false, kitShown = false } = {}) {
  if (linked) return kitShown ? null : "kit";
  return made ? null : "code";
}

/** Whether the extension connected now (`connected`, a browser id from `extension_connected`) is
 * the one in the row of browser `id`. Windows can't tell Opera GX from Opera, nor Chromium from
 * Chrome (each pair runs the same program): the row that is shown takes it. */
export function connectedHere(id, connected, shownIds = []) {
  if (!connected) return false;
  if (id === connected) return true;
  const twin = { "opera-gx": "opera", chromium: "chrome" }[id];
  return twin === connected && !shownIds.includes(connected);
}
