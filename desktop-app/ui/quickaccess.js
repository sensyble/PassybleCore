// Quick Access: opened by a global shortcut, searches every unlocked vault. Enter copies the
// password, Ctrl+C the username, Ctrl+Shift+C the one-time code (`copy_field`: the value never
// passes through this window), Ctrl+O opens the item in the main window (Cmd on a Mac). Other kinds
// open in the main window on Enter. Closes when it loses focus, like a launcher.

import { errorText, escapeHides, h, icon, invoke, keyLabel, listen, mount, t, tx } from "./lib.js";
import { isMac } from "./platform.js";
import { itemAvatar, watchIcons } from "./siteicons.js";
import { quickAccessKey, quickAccessRows } from "./views/quickaccess-model.js";

const root = document.getElementById("root");
let items = [];
let selected = 0;
let searchSeq = 0;
let closing = null;

const input = h("input", {
  class: "input",
  type: "search",
  placeholder: t("quickaccess.search"),
  "aria-label": t("quickaccess.search"),
  autocomplete: "off",
  spellcheck: "false",
});
const list = h("ul", { class: "list", role: "listbox", "aria-label": t("quickaccess.results") });
const status = h("div", { class: "qa-status", role: "status", "aria-live": "polite" });
const hint = (key, text) => h("span", {}, tx(text, { key: h("kbd", { text: keyLabel(key) }) }));
const foot = h("div", { class: "foot" },
  hint("Enter", "quickaccess.key_password"),
  hint("Mod+C", "quickaccess.key_username"),
  hint("Mod+Shift+C", "quickaccess.key_code"),
  hint("Mod+O", "quickaccess.key_open"),
  hint("Esc", "quickpick.key_close"));

mount(
  root,
  h(
    "div",
    { class: "drag", "data-tauri-drag-region": true },
    icon("search"),
    h("span", { class: "ellipsis grow small muted", "data-tauri-drag-region": true, text: t("shortcuts.quick_access") }),
    h("button", { class: "btn icon ghost", type: "button", title: t("common.close"), "aria-label": t("common.close"), on: { click: () => close() } }, icon("close")),
  ),
  h("div", { class: "search" }, input),
  list,
  status,
  foot,
);

function close() {
  clearTimeout(closing);
  closing = null;
  invoke("hide_window");
}

function say(text, kind = "") {
  status.className = `qa-status ${kind}`.trim();
  status.textContent = text || "";
}

function renderList() {
  selected = Math.max(0, Math.min(items.length - 1, selected));
  if (!items.length) {
    mount(list, h("li", { class: "empty small", role: "presentation", text: input.value.trim() ? t("quickpick.no_matches") : t("quickaccess.empty") }));
    return;
  }
  mount(
    list,
    items.map((item, i) =>
      h(
        "li",
        {
          class: `list-item${i === selected ? " selected" : ""}`,
          role: "option",
          "aria-selected": String(i === selected),
          on: { click: () => { selected = i; renderList(); input.focus(); }, dblclick: () => act(i, "enter") },
        },
        itemAvatar(item),
        h(
          "div",
          { class: "grow" },
          h("div", { class: "title ellipsis", text: item.title }),
          h("div", { class: "sub ellipsis", text: item.username || item.url || "" }),
        ),
        item.vault && !item.vault.home ? h("span", { class: "pill faint", text: item.vault.name }) : null,
        item.has_totp ? h("span", { class: "qa-badge", title: t("quickaccess.has_code"), "aria-label": t("quickaccess.has_code") }, icon("clock")) : null,
      ),
    ),
  );
  watchIcons(list);
  const el = list.querySelectorAll(".list-item")[selected];
  if (el) el.scrollIntoView({ block: "nearest" });
}

async function runSearch() {
  const seq = ++searchSeq;
  const query = input.value.trim();
  let result;
  try {
    result = query ? await invoke("search", { query }) : await invoke("list_items");
  } catch (e) {
    result = [];
    say(errorText(e), "error");
  }
  if (seq !== searchSeq) return;
  items = quickAccessRows(result, query);
  selected = 0;
  renderList();
}

async function copy(item, field, done) {
  try {
    await invoke("copy_field", { id: item.id, field });
  } catch (e) {
    say(errorText(e), "error");
    return;
  }
  say(done, "ok");
  // Long enough to read, short enough not to be in the way.
  clearTimeout(closing);
  closing = setTimeout(close, 700);
}

function open(item) {
  invoke("quick_access_open", { id: item.id }).catch((e) => say(errorText(e), "error"));
}

function act(i, what) {
  const item = items[i];
  if (!item) return;
  if (what === "open") return open(item);
  if (what === "username") {
    if (!item.username) return say(t("quickaccess.no_username"), "error");
    return copy(item, "username", t("quickaccess.copied_username"));
  }
  if (what === "code") {
    if (!item.has_totp) return say(t("quickaccess.no_code"), "error");
    return copy(item, "totp", t("quickaccess.copied_code"));
  }
  // Enter: a login's password; anything else opens.
  if (item.kind !== "login") return open(item);
  if (!item.has_password) return say(t("quickaccess.no_password"), "error");
  return copy(item, "password", t("quickaccess.copied_password"));
}

async function load() {
  clearTimeout(closing);
  closing = null;
  input.value = "";
  say("");
  items = [];
  renderList();
  input.focus();
  await runSearch();
  input.focus();
}

input.addEventListener("input", () => { say(""); runSearch(); });
input.addEventListener("keydown", (e) => {
  const what = quickAccessKey(e, isMac());
  if (!what) return;
  e.preventDefault();
  if (what === "down") { selected += 1; renderList(); }
  else if (what === "up") { selected -= 1; renderList(); }
  else act(selected, what);
});
window.addEventListener("blur", () => {
  setTimeout(() => { if (!document.hasFocus()) close(); }, 150);
});

escapeHides();
listen("quickaccess", load);
load();
