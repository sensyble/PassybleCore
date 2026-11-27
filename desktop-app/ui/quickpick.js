// Auto-type quick-pick: opened by the hotkey when the foreground window matched no login,
// several, or one only by a site name in its title. Enter types the selected login into that window.
// The last row, "Generate new password" (the only one, selected, when nothing matches), saves a new
// login for the app and types the new password into the window (quickpick_generate).

import { errorText, escapeHides, h, icon, invoke, listen, mount, t, toast, tx } from "./lib.js";
import { itemAvatar, watchIcons } from "./siteicons.js";

const root = document.getElementById("root");
let state = null;
let items = [];
let selected = 0;
let searchSeq = 0;

/** The "Generate new password" row, after the logins. */
const GENERATE = { action: "generate" };
const rows = () => [...items, GENERATE];

const input = h("input", {
  class: "input",
  type: "search",
  placeholder: t("quickpick.search"),
  "aria-label": t("quickpick.search"),
  autocomplete: "off",
  spellcheck: "false",
});
const list = h("ul", { class: "list", role: "listbox", "aria-label": t("quickpick.logins") });
const header = h("span", { class: "ellipsis grow small muted", "data-tauri-drag-region": true });
const foot = h("div", { class: "foot" });

mount(
  root,
  h(
    "div",
    { class: "drag", "data-tauri-drag-region": true },
    icon("keyboard"),
    header,
    h("button", { class: "btn icon ghost", type: "button", title: t("common.close"), "aria-label": t("common.close"), on: { click: () => invoke("hide_window") } }, icon("close")),
  ),
  h("div", { class: "search" }, input),
  list,
  foot,
);

function appName() {
  return (state && (state.app || (state.exe || "").replace(/\.exe$/i, ""))) || t("quickpick.this_app");
}

function generateRow(i) {
  return h(
    "li",
    {
      class: `list-item action${items.length ? "" : " prominent"}${i === selected ? " selected" : ""}`,
      role: "option",
      "aria-selected": String(i === selected),
      on: { click: () => { selected = i; renderList(); }, dblclick: () => choose(i) },
    },
    h("span", { class: "action-icon" }, icon("dice")),
    h(
      "div",
      { class: "grow" },
      h("div", { class: "title ellipsis", text: t("quickpick.generate") }),
      h("div", { class: "sub ellipsis", text: t("quickpick.generate_sub", { app: appName() }) }),
    ),
  );
}

function renderList() {
  // A search that found nothing selects nothing, so Enter doesn't generate by accident.
  const min = !items.length && input.value.trim() ? -1 : 0;
  selected = Math.max(min, Math.min(rows().length - 1, selected));
  if (!items.length) {
    mount(
      list,
      h("li", { class: "empty small", role: "presentation", text: input.value ? t("quickpick.no_matches") : t("quickpick.no_window_match") }),
      generateRow(0),
    );
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
          on: { click: () => { selected = i; renderList(); }, dblclick: () => choose(i) },
        },
        itemAvatar(item),
        h(
          "div",
          { class: "grow" },
          h("div", { class: "title ellipsis", text: item.title }),
          h("div", { class: "sub ellipsis", text: item.username || item.url || "" }),
        ),
      ),
    ),
    generateRow(items.length),
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
    result = query ? await invoke("search", { query }) : state ? state.matches : [];
  } catch (e) {
    result = [];
    toast(errorText(e), "error");
  }
  if (seq !== searchSeq) return;
  items = result.filter((i) => i.kind === "login");
  selected = items.length || !query ? 0 : -1;
  renderList();
}

function choose(i) {
  const row = rows()[i];
  if (!row) return;
  if (row === GENERATE) {
    invoke("quickpick_generate").catch((e) => toast(errorText(e), "error"));
    return;
  }
  invoke("quickpick_choose", { id: row.id }).catch((e) => toast(errorText(e), "error"));
}

async function load() {
  state = await invoke("quickpick_state").catch(() => null);
  input.value = "";
  if (state) {
    header.textContent = t("quickpick.type_into", { window: state.window_title || t("quickpick.untitled_window") });
    header.title = t("prompt.title_user", { title: state.window_title, username: state.app || state.exe });
    mount(
      foot,
      h("span", {}, tx("quickpick.key_type", { key: h("kbd", { text: t("keys.enter") }) })),
      h("span", {}, tx("quickpick.key_close", { key: h("kbd", { text: t("keys.esc") }) })),
      state.pin ? h("span", { class: "ellipsis grow" }, tx("quickpick.tip", { app: h("span", {}, state.app ? `${state.app} ` : null, h("code", { class: "selectable", text: state.pin })) })) : null,
    );
  }
  items = state ? state.matches.filter((i) => i.kind === "login") : [];
  selected = 0;
  renderList();
  input.focus();
}

input.addEventListener("input", runSearch);
input.addEventListener("keydown", (e) => {
  if (e.key === "ArrowDown") { e.preventDefault(); selected += 1; renderList(); }
  else if (e.key === "ArrowUp") { e.preventDefault(); selected -= 1; renderList(); }
  else if (e.key === "Enter") { e.preventDefault(); choose(selected); }
});
window.addEventListener("blur", () => {
  setTimeout(() => { if (!document.hasFocus()) invoke("hide_window"); }, 150);
});

escapeHides();
listen("quickpick", load);
load();
