// Forced and recommended updates in the main window (app_versions.rs). Below the minimum version
// Passyble is read-only (Rust refuses every fill, save, edit, import, delete and sync): a full-window
// "Update required" screen, with "View my passwords" leading to the vault under a bar that stays.
// Below the recommended version: an "Update available" bar, closed per version.

import { errorText, h, icon, invoke, listen, t, toast } from "../lib.js";
import { appVersionsView } from "./app-versions-model.js";

let status = null;
let viewing = false;
let screen = null;
let bar = null;
let busy = false;

async function update(note) {
  if (busy) return;
  busy = true;
  if (note) note.textContent = t("app_versions.updating");
  try {
    const result = await invoke("app_versions_update");
    if (result && result.opened) {
      if (note) note.textContent = t("app_versions.download_opened");
      else toast(t("app_versions.download_opened"));
    }
  } catch (e) {
    if (note) note.textContent = errorText(e);
    else toast(errorText(e), "error");
  } finally {
    busy = false;
  }
}

function buildScreen(view) {
  const note = h("p", { class: "faint update-required-note", role: "status" });
  const message = view.message ? h("p", { class: "update-required-message", text: view.message }) : null;
  return h(
    "div",
    { class: "update-required", role: "dialog", "aria-modal": "true", "aria-labelledby": "update-required-title" },
    h(
      "div",
      { class: "update-required-card" },
      h("span", { class: "modal-icon warn" }, icon("update")),
      h("h1", { id: "update-required-title", text: t("app_versions.required_title") }),
      h("p", { text: t("app_versions.required_body", { current: view.current, minimum: view.minimum }) }),
      message,
      h("p", { class: "faint", text: t("app_versions.required_safe") }),
      h(
        "div",
        { class: "update-required-actions" },
        h("button", { class: "btn primary big", type: "button", text: t("app_versions.update"), on: { click: () => update(note) } }),
        h("button", {
          class: "btn big",
          type: "button",
          text: t("app_versions.view"),
          on: {
            click: () => {
              viewing = true;
              render();
            },
          },
        }),
      ),
      note,
    ),
  );
}

function buildBar(view) {
  if (view.bar) {
    return h(
      "div",
      { class: "banner warn app-version-bar", role: "status" },
      icon("lock"),
      h("span", { class: "grow", text: t("app_versions.bar") }),
      h("button", {
        class: "btn small",
        type: "button",
        text: t("app_versions.bar_update"),
        on: {
          click: () => {
            viewing = false;
            render();
          },
        },
      }),
    );
  }
  const { version, message } = view.banner;
  return h(
    "div",
    { class: "banner app-version-bar", role: "status" },
    icon("update"),
    h("span", { class: "grow" }, t("app_versions.available", { version }), message ? ` ${message}` : ""),
    h("button", { class: "btn small", type: "button", text: t("app_versions.update"), on: { click: () => update(null) } }),
    h("button", {
      class: "btn ghost small",
      type: "button",
      text: t("app_versions.dismiss"),
      on: {
        click: () => {
          invoke("app_versions_dismiss", { version }).then(set, () => {});
        },
      },
    }),
  );
}

function render() {
  const view = appVersionsView(status, viewing);
  if (screen) screen.remove();
  if (bar) bar.remove();
  screen = view.screen ? buildScreen(view) : null;
  bar = view.bar || view.banner ? buildBar(view) : null;
  if (bar) document.body.prepend(bar);
  if (screen) document.body.append(screen);
  document.body.classList.toggle("has-version-bar", !!bar);
  document.body.classList.toggle("read-only", view.bar);
}

function set(next) {
  // A new requirement (or none) starts on its screen again.
  if (!next || next.state !== "required") viewing = false;
  status = next || null;
  render();
}

export function startAppVersions() {
  invoke("app_versions_status").then(set, () => {});
  listen("app-versions", set).catch(() => {});
}
