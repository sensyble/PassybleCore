// "Add two-factor code": shown after the "Scan QR code on screen" shortcut reads the screen. The
// codes stay in Rust: this window gets their issuer, account and settings, never the secret, and
// answers with the session and code it showed. Nothing is added before "Add". This window is left
// out of the capture, so "Scan again" can run with it open. A Google Authenticator export opens the
// import preview in the main window.

import { errorText, escapeHides, h, icon, invoke, listen, mount, t, tn } from "./lib.js";
import { NEW_LOGIN, addLabel, detailRows, initialChoice, matchDetail, newLoginTitle, replaces } from "./views/otpauth-model.js";
import { codeRows, firstStep, pickableLogins, qrscanTitle } from "./views/qrscan-model.js";

const root = document.getElementById("root");
let state = null;
let closing = null;

const heading = h("span", { class: "ellipsis grow small muted", "data-tauri-drag-region": true, text: t("qrscan.title") });
const body = h("div", { class: "qr-body" });

mount(
  root,
  h(
    "div",
    { class: "drag", "data-tauri-drag-region": true },
    icon("qr"),
    heading,
    h("button", { class: "btn icon ghost", type: "button", title: t("common.close"), "aria-label": t("common.close"), on: { click: () => close() } }, icon("close")),
  ),
  body,
);

function close() {
  clearTimeout(closing);
  closing = null;
  invoke("hide_window");
}

const button = (text, onClick, cls = "") => h("button", { class: `btn ${cls}`.trim(), type: "button", text, on: { click: onClick } });

const actions = (...buttons) => h("div", { class: "row qr-actions" }, h("span", { class: "spacer" }), buttons);

async function scanAgain(btn) {
  if (btn) btn.disabled = true;
  mount(body, h("p", { class: "muted qr-wait", text: t("qrscan.scanning") }));
  try {
    state = await invoke("qrscan_again");
  } catch (e) {
    state = { error: errorText(e), codes: [] };
  }
  show();
}

function extras() {
  const lines = [];
  if (state.rejected) lines.push(h("div", { class: "banner warn", text: state.rejected }));
  if (state.other) lines.push(h("p", { class: "faint", text: tn("qrscan.other_codes", state.other) }));
  return lines;
}

function migrationRow() {
  if (!state.migration) return null;
  const btn = button(t("qrscan.migration_import"), async () => {
    btn.disabled = true;
    try {
      await invoke("qrscan_import", { id: state.id });
    } catch (e) {
      btn.disabled = false;
      mount(body, message(errorText(e), "error"));
    }
  }, "tonal");
  return h("div", { class: "banner qr-migration" }, h("span", { class: "grow", text: t("qrscan.migration_found") }), btn);
}

function message(text, kind = "") {
  return h("div", { class: "col" },
    h("div", { class: `qr-message ${kind}`.trim() }, h("span", { class: "modal-icon" }, icon(kind === "error" ? "alert" : "qr")), h("p", { text })),
    actions(button(t("common.close"), close), button(t("qrscan.scan_again"), (e) => scanAgain(e.currentTarget), "primary")));
}

function show() {
  clearTimeout(closing);
  closing = null;
  heading.textContent = t("qrscan.title");
  const step = firstStep(state);
  if (step === "error") {
    mount(body, message(state.error, "error"));
  } else if (step === "no_vault") {
    mount(body, h("div", { class: "col" },
      h("p", { text: t("qrscan.no_vault") }),
      actions(button(t("common.close"), close))));
  } else if (step === "none") {
    mount(body, h("div", { class: "col" },
      h("div", { class: "qr-message" }, h("span", { class: "modal-icon" }, icon("qr")),
        h("div", { class: "col" }, h("p", { class: "qr-strong", text: t("qrscan.none_found") }), h("p", { class: "muted", text: t("qrscan.none_hint") }))),
      extras(),
      actions(button(t("common.close"), close), button(t("qrscan.scan_again"), (e) => scanAgain(e.currentTarget), "primary"))));
  } else if (step === "migration") {
    mount(body, h("div", { class: "col" }, migrationRow(), extras(), actions(button(t("common.close"), close))));
  } else if (step === "pick") {
    pick();
  } else {
    review(state.codes[0], false);
  }
  const focus = body.querySelector(".btn.primary, input, .qr-pick");
  if (focus) focus.focus();
}

function pick() {
  const rows = codeRows(state.codes);
  mount(body, h("div", { class: "col" },
    h("p", { class: "muted", text: tn("qrscan.found_several", rows.length) }),
    h("div", { class: "col qr-codes" }, rows.map((r) =>
      h("button", { class: "qr-pick", type: "button", on: { click: () => review(state.codes.find((c) => c.index === r.index), true) } },
        h("span", { class: "otpauth-choice-text" }, h("span", { class: "otpauth-choice-title", text: r.title }), r.detail ? h("span", { class: "faint", text: r.detail }) : null),
        icon("chevronRight")))),
    migrationRow(),
    extras(),
    actions(button(t("common.close"), close))));
}

async function review(code, back) {
  if (!code) return show();
  heading.textContent = qrscanTitle(code);
  mount(body, h("p", { class: "muted qr-wait", text: t("common.loading") }));
  let found;
  try {
    found = await invoke("qrscan_review", { id: state.id, index: code.index });
  } catch (e) {
    mount(body, message(errorText(e), "error"));
    return;
  }
  const matches = (found.matches || []).slice();
  let choice = initialChoice(matches);
  const warning = h("div", { class: "banner warn", text: t("otpauth.replace_warning") });
  const error = h("div", { class: "error-text", role: "alert" });
  const addBtn = button("", () => add(), "primary");
  const update = () => {
    addBtn.textContent = addLabel(matches, choice);
    warning.hidden = !replaces(matches, choice);
    for (const input of choices.querySelectorAll("input[type=radio]")) input.checked = input.value === choice;
  };
  const row = (value, title, detail, suggested) => h(
    "label",
    { class: "otpauth-choice" },
    h("input", { type: "radio", name: "qr-target", value, checked: value === choice, on: { change: () => { choice = value; update(); } } }),
    h("span", { class: "otpauth-choice-text" },
      h("span", { class: "otpauth-choice-title" }, h("span", { text: title }), suggested ? h("span", { class: "pill", text: t("otpauth.best_match") }) : null),
      detail ? h("span", { class: "faint", text: detail }) : null),
  );
  const detailOf = (m) => [matchDetail(m), m.vault_name].filter(Boolean).join(" · ");
  const choices = h("div", { class: "col otpauth-choices" });
  const renderChoices = () => mount(choices,
    matches.map((m) => row(m.id, m.title, detailOf(m), m.suggested)),
    row(NEW_LOGIN, t("qrscan.new_login"), newLoginTitle(code), false));

  // "Another login": search over the logins the user may change.
  const results = h("div", { class: "col qr-results" });
  const search = h("input", { class: "input", type: "search", placeholder: t("qrscan.search_logins"), "aria-label": t("qrscan.search_logins"), autocomplete: "off", spellcheck: "false" });
  let seq = 0;
  search.addEventListener("input", async () => {
    const mine = ++seq;
    const query = search.value.trim();
    if (!query) return mount(results);
    let items = [];
    try {
      items = await invoke("search", { query });
    } catch (e) {
      if (mine === seq) mount(results, h("div", { class: "error-text", text: errorText(e) }));
      return;
    }
    if (mine !== seq) return;
    const logins = pickableLogins(items, matches.map((m) => m.id)).slice(0, 6);
    mount(results, logins.length
      ? logins.map((i) => h("button", { class: "qr-pick small", type: "button", on: { click: () => {
          matches.push({ id: i.id, title: i.title, username: i.username, has_totp: !!i.has_totp, suggested: false, vault_name: i.vault && !i.vault.home ? i.vault.name : null });
          choice = i.id;
          search.value = "";
          mount(results);
          renderChoices();
          update();
        } } },
        h("span", { class: "otpauth-choice-text" }, h("span", { class: "otpauth-choice-title", text: i.title }), i.username ? h("span", { class: "faint", text: i.username }) : null)))
      : h("p", { class: "faint", text: t("quickpick.no_matches") }));
  });
  const other = h("details", { class: "qr-other" }, h("summary", {}, t("qrscan.other_login")), search, results);
  other.addEventListener("toggle", () => { if (other.open) search.focus(); });

  async function add() {
    addBtn.disabled = true;
    error.textContent = "";
    try {
      const item = await invoke("qrscan_commit", {
        id: state.id,
        index: code.index,
        target: choice === NEW_LOGIN ? null : choice,
        replace: replaces(matches, choice),
      });
      const added = t("otpauth.added", { title: item.title });
      if (item.left > 0) {
        state = await invoke("qrscan_state");
        show();
        body.prepend(h("div", { class: "banner ok", text: added }));
        return;
      }
      heading.textContent = t("qrscan.title");
      mount(body, h("div", { class: "col" },
        h("div", { class: "qr-message ok" }, h("span", { class: "modal-icon" }, icon("check")), h("p", { class: "qr-strong", text: added })),
        actions(button(t("common.close"), close, "primary"))));
      closing = setTimeout(close, 2500);
    } catch (e) {
      addBtn.disabled = false;
      error.textContent = errorText(e);
    }
  }

  renderChoices();
  mount(body, h("div", { class: "col" },
    h("dl", { class: "otpauth-details" },
      detailRows(code).flatMap((d) => [h("dt", { text: d.label }), h("dd", { text: d.value })]),
      found.vault_name ? [h("dt", { text: t("otpauth.vault") }), h("dd", { text: found.vault_name })] : null),
    h("h3", { class: "otpauth-head", text: t("otpauth.add_to") }),
    choices,
    other,
    warning,
    error,
    actions(
      back ? button(t("common.back"), () => show()) : button(t("common.cancel"), close),
      addBtn)));
  update();
  addBtn.focus();
}

async function load() {
  mount(body, h("p", { class: "muted qr-wait", text: t("common.loading") }));
  state = await invoke("qrscan_state").catch((e) => ({ error: errorText(e), codes: [] }));
  show();
}

escapeHides();
listen("qrscan", load);
load();
