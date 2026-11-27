// Item editor for the four kinds (login, note, card, identity). It works on the item's full copy
// (`get_item_for_edit`, secrets included), which only lives while the editor is open.
// Up front only what the item is; the rest sits under "More details" (closed for a new item, see `detailsOpen`).
// A login's password is checked as typed (`password_check`, on this PC only); it only warns, saving is never blocked.

import { errorText, formatCode, formatDate, formatNumber, h, icon, iconButton, infoTip, invoke, keyLabel, mount, pressEscape, t, toast, tx } from "../lib.js";
import { generatorControls, generatorOptions, saveGeneratorOptions, usernamePanel } from "./generator.js";
import { siteOf } from "./generator-model.js";
import { appRows, cancelStep, detailsOpen, editorKey, effectiveRule, FIELD_NAME_MAX, FIELD_VALUE_MAX, hiddenApps, isAppPin, notesCounter, notesMaxLength, ruleBadge, ruleOf, ruleOptions, savedUrls, siteQuery, siteUrl, takeEscape, titleForSite, urlRows } from "./editor-model.js";
import { checkContext, passwordFeedback } from "./password-issues-model.js";
import { roleLabel, saveVaultChoices } from "./teams-model.js";
import { hidden, isMac, platformName } from "../platform.js";
import { itemAvatar, watchIcons } from "../siteicons.js";

const CHECK_DELAY_MS = 350;
const SITE_DELAY_MS = 150;
const SITE_LIMIT = 6;

// Editor styles are shared with the item view's website badges.
if (typeof document !== "undefined" && !document.getElementById("editor-css")) {
  document.head.append(h("link", { id: "editor-css", rel: "stylesheet", href: new URL("./editor.css", import.meta.url).href }));
}

export const KINDS = [
  ["login", t("kind.login"), "key"],
  ["note", t("kind.note"), "note"],
  ["card", t("card.label"), "creditCard"],
  ["identity", t("kind.identity"), "idCard"],
];

const KIND_SHORT = { login: t("kind.login"), note: t("kind.note_short"), card: t("card.label"), identity: t("kind.identity") };

// One text per kind, for languages with gendered nouns.
const HEADINGS = {
  edit: { login: t("editor.edit_login"), note: t("editor.edit_note"), card: t("editor.edit_card"), identity: t("editor.edit_identity"), item: t("editor.edit_item") },
  new: { login: t("editor.new_login"), note: t("editor.new_note"), card: t("editor.new_card"), identity: t("editor.new_identity"), item: t("editor.new_item") },
};

const FIELD_KINDS = [
  ["text", t("editor.field_text")],
  ["hidden", t("editor.field_hidden")],
  ["url", t("editor.field_url")],
];

export const IDENTITY_GROUPS = [
  [t("identity.group_name"), [
    ["honorific", t("identity.honorific"), { placeholder: t("identity.honorific_placeholder"), autocomplete: "off" }],
    ["first_name", t("identity.first_name"), {}],
    ["middle_name", t("identity.middle_name"), {}],
    ["last_name", t("identity.last_name"), {}],
  ]],
  [t("identity.group_contact"), [
    ["email", t("identity.email"), { type: "email" }],
    ["phone", t("identity.phone"), { type: "tel" }],
  ]],
  [t("identity.group_address"), [
    ["address1", t("identity.address1"), {}],
    ["address2", t("identity.address2"), {}],
    ["address3", t("identity.address3"), {}],
    ["city", t("identity.city"), {}],
    ["region", t("identity.region"), {}],
    ["postal_code", t("identity.postal_code"), {}],
    ["country", t("identity.country"), {}],
  ]],
  [t("identity.group_other"), [
    ["company", t("identity.company"), {}],
    ["birth_date", t("identity.birth_date"), { type: "date" }],
  ]],
];

function blank(kind) {
  return {
    id: "", kind, title: "", username: "", password: "", urls: [], totp: null, notes: "", favorite: false, passkeys: [],
    card: kind === "card" ? {} : null, identity: kind === "identity" ? {} : null, fields: [], tags: [],
  };
}

let uid = 0;
const nextId = (p) => `${p}-${++uid}`;

function secretInput(props, onInput) {
  const input = h("input", { class: "input mono", type: "password", spellcheck: "false", autocomplete: "off", ...props });
  input.addEventListener("input", onInput);
  const eye = iconButton("eye", t("common.show"), () => {
    const show = input.type === "password";
    input.type = show ? "text" : "password";
    eye.title = show ? t("common.hide") : t("common.show");
    eye.setAttribute("aria-label", eye.title);
    mount(eye, icon(show ? "eyeOff" : "eye"));
  }, "");
  return { input, el: h("div", { class: "input-group" }, input, eye) };
}

export function ruleBadgeEl(rule) {
  const badge = h("span", { class: "rule-badge" });
  paintBadge(badge, rule);
  return badge;
}

export function itemRuleBadge(item, { url = null, app = null }) {
  if (app !== null) return ruleBadgeEl((item.android_never_show || []).includes(app) ? "never" : null);
  return ruleBadgeEl(effectiveRule(url, ruleOf(item.url_rules, url)));
}

function paintBadge(badge, rule) {
  const text = ruleBadge(rule);
  badge.textContent = text || "";
  badge.hidden = !text;
}

/** Popular sites suggested under `input` as it is typed; `query(text)` is what to look up, `onPick({ name, domain })` gets the choice. Esc closes only the list. */
function siteSuggest(input, query, onPick) {
  let shown = [];
  let active = -1;
  let seq = 0;
  let timer = null;
  const list = h("div", { class: "tag-suggest site-suggest", id: nextId("e-sites"), role: "listbox", "aria-label": t("editor.site_suggestions"), hidden: true });
  input.setAttribute("role", "combobox");
  input.setAttribute("aria-autocomplete", "list");
  input.setAttribute("aria-controls", list.id);
  input.setAttribute("aria-expanded", "false");
  const close = () => {
    seq += 1;
    clearTimeout(timer);
    shown = [];
    active = -1;
    list.hidden = true;
    input.setAttribute("aria-expanded", "false");
  };
  const pick = (site) => {
    close();
    onPick(site);
  };
  const paint = () => {
    mount(list, shown.map((site, i) => h("button", {
      class: `tag-option${i === active ? " active" : ""}`,
      type: "button",
      role: "option",
      tabindex: "-1",
      "aria-selected": String(i === active),
      on: { mousedown: (e) => { e.preventDefault(); pick(site); } },
    }, itemAvatar({ title: site.name, kind: "login", site: site.domain }), h("span", { class: "grow", text: site.name }), h("span", { class: "faint", text: site.domain }))));
    list.hidden = !shown.length;
    input.setAttribute("aria-expanded", String(!list.hidden));
    if (shown.length) watchIcons(list);
  };
  const lookup = async () => {
    const n = ++seq;
    const q = query(input.value);
    const found = q ? await invoke("site_suggestions", { query: q, limit: SITE_LIMIT }).catch(() => []) : [];
    if (n !== seq || document.activeElement !== input) return;
    shown = Array.isArray(found) ? found : [];
    active = -1;
    paint();
  };
  input.addEventListener("input", () => {
    clearTimeout(timer);
    timer = setTimeout(lookup, SITE_DELAY_MS);
  });
  input.addEventListener("blur", close);
  input.addEventListener("keydown", (e) => {
    if (list.hidden || e.isComposing || takeEscape(e, close)) return;
    if (e.key === "ArrowDown") active = (active + 1) % shown.length;
    else if (e.key === "ArrowUp") active = active <= 0 ? shown.length - 1 : active - 1;
    else if (e.key === "Enter" && active >= 0) pick(shown[active]);
    else return;
    e.preventDefault();
    e.stopPropagation();
    if (!list.hidden) paint();
  });
  return h("div", { class: "site-field" }, input, list);
}

/** Shows `el` under `anchor` until Esc, an outside click, a scroll, window blur or `close()`. `tabCloses`: Tab closes it too (menus); a dropdown closes once focus leaves it. */
function popover(anchor, el, { tabCloses = false, onClose = null } = {}) {
  let open = true;
  const close = (restoreFocus = true) => {
    if (!open) return;
    open = false;
    document.removeEventListener("mousedown", outside, true);
    document.removeEventListener("scroll", scrolled, true);
    window.removeEventListener("blur", lost);
    window.removeEventListener("resize", lost);
    el.remove();
    anchor.setAttribute("aria-expanded", "false");
    if (onClose) onClose();
    if (restoreFocus && anchor.isConnected) anchor.focus({ preventScroll: true });
  };
  // A press on the anchor is left to its click, which closes the popover.
  const outside = (e) => { if (!el.contains(e.target) && !anchor.contains(e.target)) close(false); };
  const scrolled = (e) => { if (!el.contains(e.target)) close(false); };
  const lost = () => close(false);
  el.addEventListener("keydown", (e) => {
    if (takeEscape(e, close) || !(tabCloses && e.key === "Tab")) return;
    e.preventDefault();
    e.stopPropagation();
    close();
  });
  if (!tabCloses) el.addEventListener("focusout", (e) => { if (e.relatedTarget && !el.contains(e.relatedTarget) && e.relatedTarget !== anchor) close(false); });
  document.body.append(el);
  const r = anchor.getBoundingClientRect();
  const m = el.getBoundingClientRect();
  el.style.left = `${Math.max(8, Math.min(r.right - m.width, window.innerWidth - m.width - 8))}px`;
  el.style.top = `${r.bottom + m.height + 8 > window.innerHeight ? Math.max(8, r.top - m.height - 4) : r.bottom + 4}px`;
  anchor.setAttribute("aria-expanded", "true");
  document.addEventListener("mousedown", outside, true);
  document.addEventListener("scroll", scrolled, true);
  window.addEventListener("blur", lost);
  window.addEventListener("resize", lost);
  return { anchor, close };
}

/** Tag chips with suggestions from `vault_tags`. Enter, comma or Tab adds the typed text; Backspace in the empty box removes the last chip. */
export function tagEditor(initial, onChange) {
  let tags = [...(initial || [])];
  let known = [];
  let active = -1;
  let shown = [];
  const id = nextId("e-tags");
  const input = h("input", { class: "tag-input", id, spellcheck: "false", autocomplete: "off", placeholder: t("editor.add_tag"), "aria-autocomplete": "list" });
  const chips = h("div", { class: "tag-chips" });
  const menu = h("div", { class: "tag-suggest", role: "listbox", hidden: true });
  const box = h("div", { class: "tag-editor input", on: { click: (e) => { if (e.target === box || e.target === chips) input.focus(); } } }, chips, input);
  invoke("vault_tags").then((list) => { known = (list || []).map((x) => x.tag); }).catch(() => {});

  const same = (a, b) => a.trim().toLowerCase() === b.trim().toLowerCase();
  const changed = () => { renderChips(); if (onChange) onChange(); };
  const add = (text) => {
    const tag = String(text || "").trim().replace(/^\/+|\/+$/g, "").replace(/\s*\/\s*/g, "/");
    if (tag && !tags.some((x) => same(x, tag))) tags.push(tag);
    input.value = "";
    closeMenu();
    changed();
  };
  const remove = (tag) => {
    tags = tags.filter((x) => x !== tag);
    changed();
    input.focus();
  };
  const renderChips = () => mount(chips, tags.map((tag) => h("span", { class: "chip tag-chip" },
    icon("tag"), h("span", { text: tag }),
    h("button", { class: "chip-x", type: "button", title: t("editor.remove_tag", { tag }), "aria-label": t("editor.remove_tag", { tag }), on: { click: (e) => { e.stopPropagation(); remove(tag); } } }, icon("close")))));
  const closeMenu = () => { menu.hidden = true; active = -1; shown = []; };
  const openMenu = () => {
    const q = input.value.trim().toLowerCase();
    shown = known.filter((k) => !tags.some((x) => same(x, k)) && (!q || k.toLowerCase().includes(q))).slice(0, 8);
    if (!shown.length) return closeMenu();
    active = Math.min(active, shown.length - 1);
    mount(menu, shown.map((tag, i) => h("button", {
      class: `tag-option${i === active ? " active" : ""}`,
      type: "button",
      role: "option",
      "aria-selected": String(i === active),
      tabindex: "-1",
      on: { mousedown: (e) => { e.preventDefault(); add(tag); } },
    }, icon("tag"), tag)));
    menu.hidden = false;
  };
  input.addEventListener("input", () => { active = -1; openMenu(); });
  input.addEventListener("focus", openMenu);
  input.addEventListener("blur", () => { if (input.value.trim()) add(input.value); else closeMenu(); });
  input.addEventListener("keydown", (e) => {
    if (!menu.hidden && takeEscape(e, closeMenu)) return;
    if (e.key === "ArrowDown" && shown.length) { e.preventDefault(); active = (active + 1) % shown.length; openMenu(); }
    else if (e.key === "ArrowUp" && shown.length) { e.preventDefault(); active = (active - 1 + shown.length) % shown.length; openMenu(); }
    else if (e.key === "Enter" || e.key === ",") {
      if (active >= 0 && shown[active]) { e.preventDefault(); add(shown[active]); }
      else if (input.value.trim()) { e.preventDefault(); add(input.value); }
    } else if (e.key === "Tab" && input.value.trim()) { add(input.value); }
    else if (e.key === "Backspace" && !input.value && tags.length) { remove(tags[tags.length - 1]); }
  });
  renderChips();
  return {
    id,
    el: h("div", { class: "tag-field" }, box, menu),
    values: () => {
      if (input.value.trim()) add(input.value);
      return [...tags];
    },
  };
}

export class Editor {
  /**
   * @param {object|null} item the item's full copy (`get_item_for_edit`), or null for a new one
   * @param {{kind?: string, tags?: string[], vaults?: object[], vault?: string}} options a new item's kind and tags;
   * with shared vaults open, the vaults it can be saved in and the one chosen first
   */
  constructor(pane, item, hooks, options = {}) {
    this.pane = pane;
    this.hooks = hooks;
    this.item = item ? JSON.parse(JSON.stringify(item)) : blank(options.kind || "login");
    if (!item && options.tags) this.item.tags = [...options.tags];
    this.item.card = this.item.card || {};
    this.item.identity = this.item.identity || {};
    this.fieldRows = (this.item.fields || []).map((f) => ({ name: f.name || "", value: f.value || "", kind: f.kind || "text" }));
    // "Save in": new items only, and only with more than one editable vault.
    this.saveChoices = item ? [] : saveVaultChoices(options.vaults || []);
    this.saveVault = options.vault || (this.saveChoices[0] && this.saveChoices[0].id) || null;
    this.detailsShown = detailsOpen(this.item);
    this.dirty = false;
    this.pwSeq = 0;
    this.pwTimer = null;
    this.genSeq = 0;
    this.nameSeq = 0;
    this.nameTimer = null;
    this.render();
  }

  render() {
    const it = this.item;
    const mark = () => { this.dirty = true; };
    const input = (id, value, props = {}) => {
      const el = h("input", { class: "input", id, value: value || "", spellcheck: "false", ...props });
      el.addEventListener("input", mark);
      return el;
    };

    this.title = input("e-title", it.title, { autocomplete: "off" });
    // Popular sites are suggested for a new login's Name; the website fills it unless the user typed one (`autoTitle`).
    this.suggestSites = !it.id;
    this.autoTitle = false;
    this.title.addEventListener("input", () => { this.autoTitle = false; });
    const titleField = this.suggestSites
      ? siteSuggest(this.title, (text) => (this.item.kind === "login" ? text.trim() : ""), (site) => this.useSite(site))
      : this.title;
    this.username = input("e-user", it.username, { autocomplete: "off" });
    this.password = input("e-pass", it.password, { type: "password", autocomplete: "new-password", class: "input mono" });
    // One row per website or desktop-app pin, each with its match rule; Android apps only hide or show.
    this.urlRows = urlRows(it.urls, it.url_rules);
    if (!this.urlRows.length) this.urlRows.push({ url: "", rule: "subdomains" });
    this.urlFirst = h("div", { class: "url-rows", role: "group", "aria-labelledby": "e-url-label" });
    this.urlMore = h("div", { class: "url-rows", role: "group", "aria-labelledby": "e-urls-label" });
    this.renderUrlRows();
    this.appRows = appRows(it.android_apps, it.android_never_show);
    this.appList = h("div", { class: "url-rows", role: "group", "aria-labelledby": "e-apps-label" });
    this.renderAppRows();
    this.pwCheck = h("div", { class: "pw-check", role: "status", "aria-live": "polite", "aria-label": t("editor.pw_check") });
    this.password.addEventListener("input", () => this.schedulePasswordCheck());
    for (const el of [this.username, this.title]) el.addEventListener("input", () => this.schedulePasswordCheck());
    this.totp = input("e-totp", it.totp || "", { class: "input mono", placeholder: t("editor.totp_placeholder"), autocomplete: "off" });
    this.totpStatus = h("div", { class: "hint" });
    // Reading the screen is Windows only.
    this.totpScanBtn = h("button", { class: "btn small", type: "button", title: t("editor.scan_qr_tip"), on: { click: () => this.scanTotp() } }, icon("qr"), t("editor.scan_qr"));
    this.totpChoices = h("span", { class: "totp-scan" });
    this.totpScan = ["windows", ""].includes(platformName()) ? h("div", { class: "totp-scan" }, this.totpScanBtn, this.totpChoices) : null;
    this.notes = h("textarea", { class: "input", id: "e-notes", rows: "4", maxlength: String(notesMaxLength((it.notes || "").length)) });
    this.notes.value = it.notes || "";
    this.notesCount = h("div", { class: "hint notes-count", "aria-live": "polite" });
    const countNotes = () => {
      const c = notesCounter(this.notes.value.length);
      this.notesCount.hidden = !c;
      this.notesCount.textContent = c ? t("editor.notes_count", { count: formatNumber(c.count), max: formatNumber(c.max) }) : "";
      this.notesCount.classList.toggle("full", !!c?.full);
    };
    countNotes();
    this.notes.addEventListener("input", mark);
    this.notes.addEventListener("input", countNotes);
    // A note's text and a login's notes sit up front; a card's or identity's notes go under More details (showKind moves the field).
    this.notesField = h("div", { class: "field" }, h("label", { for: "e-notes", text: t("field.notes") }), this.notes, this.notesCount);
    this.notesMain = h("div", { class: "notes-slot" });
    this.notesMore = h("div", { class: "notes-slot" });
    this.favorite = h("input", { type: "checkbox", checked: it.favorite });
    this.aiShare = h("input", { type: "checkbox", id: "e-ai", checked: !!it.ai_access });
    this.aiMode = h("select", { class: "input", id: "e-ai-mode" },
      h("option", { value: "ask", text: t("editor.ai_ask") }),
      h("option", { value: "allow", text: t("editor.ai_allow") }));
    this.aiMode.value = it.ai_access === "allow" ? "allow" : "ask";
    // In a shared vault every use asks.
    const aiShared = !!(it.vault && !it.vault.home);
    if (aiShared) {
      this.aiMode.value = "ask";
      this.aiMode.disabled = true;
    }
    this.aiModeRow = h("div", { class: "field" },
      h("label", { for: "e-ai-mode", text: t("editor.ai_mode") }),
      this.aiMode,
      h("span", { class: "hint", text: t(aiShared ? "editor.ai_mode_shared" : "editor.ai_mode_hint") }));
    this.aiModeRow.hidden = !this.aiShare.checked;
    this.aiShare.addEventListener("change", () => { this.aiModeRow.hidden = !this.aiShare.checked; this.dirty = true; });
    this.aiMode.addEventListener("change", () => { this.dirty = true; });
    this.favorite.addEventListener("change", mark);
    this.error = h("div", { class: "error-text", role: "alert" });

    this.reveal = iconButton("eye", t("password.show"), () => this.showPassword(this.password.type === "password"), "");
    const genBtn = iconButton("dice", t("editor.generate"), () => this.generate(), "");
    const genOptions = iconButton("chevronDown", t("editor.generator_options"), () => this.openGenerator(genOptions), "gen-more");
    genOptions.setAttribute("aria-haspopup", "dialog");
    genOptions.setAttribute("aria-expanded", "false");

    // The login's site goes along only with "Mention the website".
    const userGenSlot = h("div");
    const userGenBtn = iconButton("dice", t("editor.generate_username"), () => {
      if (userGenSlot.firstChild) {
        mount(userGenSlot);
        return;
      }
      mount(userGenSlot, usernamePanel((value) => {
        this.username.value = value;
        this.dirty = true;
        mount(userGenSlot);
        this.username.focus();
        this.schedulePasswordCheck();
      }, { website: siteOf(this.urlText()) }));
    }, "");

    let totpTimer = null;
    this.totp.addEventListener("input", () => {
      clearTimeout(totpTimer);
      totpTimer = setTimeout(() => this.checkTotp(), 250);
    });

    this.kindButtons = KINDS.map(([kind, label, iconName]) =>
      h("button", { type: "button", class: it.kind === kind ? "active" : "", title: label, "aria-label": label, dataset: { kind }, on: { click: () => this.setKind(kind) } }, icon(iconName), h("span", { class: "seg-label", text: KIND_SHORT[kind] || label })));
    const kind = h("div", { class: "segmented kinds", role: "tablist", "aria-label": t("editor.item_type") }, this.kindButtons);

    this.loginMain = h(
      "div",
      { class: "col" },
      h("div", { class: "field" }, h("div", { class: "label", id: "e-url-label", text: t("editor.website") }), this.urlFirst),
      h("div", { class: "two" },
        h("div", { class: "field" }, h("label", { for: "e-user", text: t("editor.username") }),
          h("div", { class: "input-group" }, this.username, userGenBtn)),
        h("div", { class: "field" }, h("label", { for: "e-pass", text: t("field.password") }),
          h("div", { class: "input-group" }, this.password, this.reveal, genBtn, genOptions), this.pwCheck)),
      h("div", { class: "field" }, h("label", { for: "e-totp", text: t("editor.totp") }), this.totp, this.totpScan, this.totpStatus),
      userGenSlot,
    );
    this.loginMore = h(
      "div",
      { class: "col" },
      h("div", { class: "field" }, h("div", { class: "label", id: "e-urls-label", text: t("editor.more_websites") }), this.urlMore,
        // The auto-type pin is hidden on Linux (no auto-type there).
        h("div", { class: "row url-actions" },
          h("button", { class: "btn small", type: "button", on: { click: () => this.addUrl() } }, icon("plus"), t("editor.add_website")),
          hidden("editor.urls_pin_hint") ? null
            : infoTip(t("editor.urls_pin_hint", { app: t("editor.urls_hint_app_code"), example: t("editor.urls_hint_example_code") }), t("editor.more_websites")))),
      this.appRows.length
        ? h("div", { class: "field" }, h("div", { class: "label", id: "e-apps-label", text: t("field.android_apps") }), this.appList)
        : null,
    );
    this.cardFields = this.renderCard(mark);
    this.identityFields = this.renderIdentity(mark);

    this.vaultSelect = null;
    if (this.saveChoices.length > 1) {
      this.vaultSelect = h("select", { class: "input", id: "e-vault" }, this.saveChoices.map((v) =>
        h("option", { value: v.id, text: v.home ? v.name : t("editor.save_in_shared", { vault: v.name, role: roleLabel(v.role) || t("teams.vault_kind_team") }) })));
      this.vaultSelect.value = this.saveVault || this.saveChoices[0].id;
      this.vaultSelect.addEventListener("change", () => { this.saveVault = this.vaultSelect.value; mark(); });
    }

    this.passkeyList = h("div", { class: "fields" });
    this.renderPasskeys();

    this.fieldList = h("div", { class: "custom-fields" });
    this.renderFieldRows();
    this.tags = tagEditor(it.tags, mark);

    const detailsId = nextId("e-more");
    this.detailsToggle = h("button", {
      class: "more-toggle",
      type: "button",
      "aria-controls": detailsId,
      on: { click: () => this.showDetails(this.details.hidden) },
    }, h("span", { class: "grow", text: t("editor.more_details") }), icon("chevronDown"));

    const form = h(
      "form",
      { class: "editor", on: { submit: (e) => { e.preventDefault(); this.save(); } } },
      h("div", { class: "pane-header" },
        this.heading = h("h2", { class: "grow" }),
        kind),
      h("div", { class: "card editor-card" },
        h("div", { class: "field" }, h("label", { for: "e-title", text: t("field.title") }), titleField),
        this.loginMain,
        this.cardFields,
        this.identityFields,
        this.notesMain,
        this.detailsToggle),
      this.details = h("div", { class: "more-body", id: detailsId }, h("div", { class: "card editor-card" },
        this.vaultSelect
          ? h("div", { class: "field" }, h("label", { for: "e-vault", text: t("editor.save_in") }), this.vaultSelect,
              h("span", { class: "hint", text: t("editor.save_in_hint") }))
          : null,
        this.loginMore,
        this.notesMore,
        h("div", { class: "col" },
          h("div", { class: "label", text: t("editor.custom_fields") }),
          this.fieldList,
          h("div", { class: "row" },
            h("button", { class: "btn small", type: "button", on: { click: () => this.addField() } }, icon("plus"), t("editor.add_field")))),
        h("div", { class: "field" }, h("label", { for: this.tags.id, text: t("editor.tags") }), this.tags.el,
          h("span", { class: "hint", text: t("editor.tags_hint") })),
        h("label", { class: "check" }, this.favorite, t("editor.favorite")),
        h("div", { class: "col" },
          h("label", { class: "check" }, this.aiShare, t("editor.ai_share"),
            infoTip(t("editor.ai_share_info"), t("editor.ai_share"))),
          this.aiModeRow)),
      it.passkeys && it.passkeys.length ? (this.passkeySection = h("div", { class: "col" }, h("div", { class: "section-title", text: t("field.passkeys") }), this.passkeyList)) : null),
      this.error,
      h("div", { class: "row sticky-actions" },
        h("span", { class: "faint" }, tx("editor.shortcuts", { save: h("kbd", { text: keyLabel("Mod+S") }), cancel: h("kbd", { text: t("keys.esc") }) })),
        h("span", { class: "spacer" }),
        h("button", { class: "btn", type: "button", text: t("common.cancel"), on: { click: () => this.cancel() } }),
        h("button", { class: "btn primary", type: "submit", text: t("common.save") })),
    );
    // Keys are caught on the whole window: after a click on empty space the focus is on the body.
    this.detachKeys();
    this.keys = (e) => {
      if (!form.isConnected) {
        this.detachKeys();
        return;
      }
      const target = e.target;
      const where = this.pane.contains(target) ? "editor"
        : !target || target === document.body || target === document.documentElement ? "page" : "other";
      const action = editorKey(e, { mac: isMac(), where, dialog: !!document.querySelector(".modal-backdrop") });
      if (!action) return;
      e.preventDefault();
      e.stopPropagation();
      if (action === "cancel") this.cancel();
      else this.save();
    };
    document.addEventListener("keydown", this.keys);

    mount(this.pane, h("div", { class: "pane-inner" }, form));
    this.showDetails(this.detailsShown);
    this.showKind();
    if (it.totp) this.checkTotp();
    if (it.card && it.card.number) this.checkCard();
    if (it.password) this.checkPassword();
    this.title.focus();
  }

  renderCard(mark) {
    const c = this.item.card || {};
    this.cardHolder = h("input", { class: "input", id: "e-holder", value: c.cardholder_name || "", spellcheck: "false", autocomplete: "off" });
    this.cardHolder.addEventListener("input", mark);
    let timer = null;
    this.cardNumber = secretInput({ id: "e-cardno", value: c.number || "", inputmode: "numeric", placeholder: t("editor.card_number_placeholder") }, () => {
      mark();
      clearTimeout(timer);
      timer = setTimeout(() => this.checkCard(), 200);
    });
    this.cardStatus = h("div", { class: "hint" });
    const months = [["0", t("editor.month")], ...Array.from({ length: 12 }, (_, i) => [String(i + 1), String(i + 1).padStart(2, "0")])];
    this.cardMonth = h("select", { class: "input", id: "e-month", "aria-label": t("editor.expiry_month") }, months.map(([v, label]) => h("option", { value: v, text: label })));
    this.cardMonth.value = String(c.expiry_month || 0);
    this.cardMonth.addEventListener("change", mark);
    this.cardYear = h("input", { class: "input", id: "e-year", type: "number", min: "2000", max: "2099", placeholder: t("editor.year"), value: c.expiry_year ? String(c.expiry_year) : "", "aria-label": t("editor.expiry_year") });
    this.cardYear.addEventListener("input", mark);
    this.cardCode = secretInput({ id: "e-cvv", value: c.security_code || "", inputmode: "numeric", maxlength: "8" }, mark);
    this.cardPin = secretInput({ id: "e-pin", value: c.pin || "", inputmode: "numeric", maxlength: "12" }, mark);
    return h("div", { class: "col" },
      h("div", { class: "field" }, h("label", { for: "e-holder", text: t("card.holder") }), this.cardHolder),
      h("div", { class: "field" }, h("label", { for: "e-cardno", text: t("card.number") }), this.cardNumber.el, this.cardStatus),
      h("div", { class: "two" },
        h("div", { class: "field" }, h("label", { for: "e-month", text: t("card.expires") }),
          h("div", { class: "input-group" }, this.cardMonth, this.cardYear)),
        h("div", { class: "field" }, h("label", { for: "e-cvv", text: t("card.security_code") }), this.cardCode.el)),
      h("div", { class: "two" },
        h("div", { class: "field" }, h("label", { for: "e-pin", text: t("card.pin") }), this.cardPin.el),
        h("div")));
  }

  renderIdentity(mark) {
    const d = this.item.identity || {};
    this.identityInputs = {};
    return h("div", { class: "col identity-edit" }, IDENTITY_GROUPS.map(([group, fields]) =>
      h("div", { class: "col" },
        h("div", { class: "section-title", text: group }),
        h("div", { class: "two" }, fields.map(([key, label, props]) => {
          const id = `e-id-${key}`;
          const el = h("input", { class: "input", id, value: d[key] || "", spellcheck: "false", autocomplete: "off", ...props });
          el.addEventListener("input", mark);
          this.identityInputs[key] = el;
          return h("div", { class: `field${key.startsWith("address") ? " wide" : ""}` }, h("label", { for: id, text: label }), el);
        })))));
  }

  showKind() {
    const kind = this.item.kind;
    this.loginMain.hidden = kind !== "login";
    this.loginMore.hidden = kind !== "login";
    this.cardFields.hidden = kind !== "card";
    this.identityFields.hidden = kind !== "identity";
    if (this.passkeySection) this.passkeySection.hidden = kind !== "login";
    const notesAt = kind === "note" || kind === "login" ? this.notesMain : this.notesMore;
    if (this.notesField.parentElement !== notesAt) notesAt.append(this.notesField);
    for (const b of this.kindButtons) {
      const on = b.dataset.kind === kind;
      b.classList.toggle("active", on);
      b.setAttribute("aria-selected", String(on));
    }
    const headings = this.item.id ? HEADINGS.edit : HEADINGS.new;
    this.heading.textContent = headings[kind] || headings.item;
    this.title.placeholder = kind === "card"
      ? t("editor.title_placeholder_card")
      : kind === "identity"
        ? t("editor.title_placeholder_identity")
        : kind === "note" ? t("editor.title_placeholder_note") : t("editor.title_placeholder_login");
  }

  showDetails(open) {
    this.detailsShown = open;
    this.details.hidden = !open;
    this.detailsToggle.setAttribute("aria-expanded", String(open));
  }

  setKind(kind) {
    if (this.item.kind === kind) return;
    this.item.kind = kind;
    this.dirty = true;
    this.showKind();
  }

  async checkCard() {
    const number = this.cardNumber.input.value.trim();
    if (!number) {
      this.cardStatus.className = "hint";
      this.cardStatus.textContent = "";
      return;
    }
    const r = await invoke("card_info", { number }).catch(() => null);
    if (!r || this.cardNumber.input.value.trim() !== number) return;
    const brand = r.brand_name || t("card.label");
    if (r.valid) {
      this.cardStatus.className = "ok-text";
      this.cardStatus.textContent = t("editor.card_valid", { brand });
    } else if (r.digits < 12) {
      this.cardStatus.className = "hint";
      this.cardStatus.textContent = r.brand_name ? r.brand_name : "";
    } else {
      this.cardStatus.className = "error-text";
      this.cardStatus.textContent = t("editor.card_invalid", { brand });
    }
  }

  /** An answer still on its way is for an older text and is dropped. */
  schedulePasswordCheck() {
    clearTimeout(this.pwTimer);
    this.pwSeq += 1;
    if (!this.password.value) {
      mount(this.pwCheck);
      return;
    }
    this.pwTimer = setTimeout(() => this.checkPassword(), CHECK_DELAY_MS);
  }

  /** `password_check` with the editor's context; only the newest answer is shown and a failure shows nothing. */
  async checkPassword() {
    clearTimeout(this.pwTimer);
    const n = ++this.pwSeq;
    if (!this.password.isConnected) return;
    if (!this.password.value) {
      mount(this.pwCheck);
      return;
    }
    const context = checkContext({ username: this.username.value, urls: this.urlText(), title: this.title.value, id: this.item.id });
    const result = await invoke("password_check", { password: this.password.value, ...context }).catch(() => null);
    if (n !== this.pwSeq || !this.password.isConnected) return;
    const feedback = passwordFeedback(result, this.password.value);
    if (!feedback.issues.length) {
      mount(this.pwCheck, feedback.strong ? h("span", { class: "ok-text", text: feedback.strong }) : null);
      return;
    }
    mount(this.pwCheck,
      h("ul", { class: "pw-issues" }, feedback.issues.map((i) => h("li", { class: i.severity, text: i.text }))),
      feedback.fix ? h("button", { class: "btn small", type: "button", text: t("editor.pw_use_strong"), on: { click: () => this.generate({ focus: true }) } }) : null);
  }

  showPassword(show) {
    this.password.type = show ? "text" : "password";
    mount(this.reveal, icon(show ? "eyeOff" : "eye"));
  }

  /** Puts a new generated password into the field, shown. A reply overtaken by a newer click is dropped. */
  async generate({ options = generatorOptions(), focus = false } = {}) {
    const n = ++this.genSeq;
    let pw;
    try {
      pw = await invoke("generate_password", { options });
    } catch (e) {
      this.error.textContent = errorText(e);
      return;
    }
    if (n !== this.genSeq || !this.password.isConnected) return;
    this.password.value = pw;
    pw = "";
    this.showPassword(true);
    this.dirty = true;
    if (focus) this.password.focus();
    this.checkPassword();
  }

  /** The generator's options in a dropdown under `anchor`; every change is remembered and fills a new password. */
  openGenerator(anchor) {
    const reopen = !(this.popup && this.popup.anchor === anchor);
    this.closePopup();
    if (!reopen) return;
    const options = generatorOptions();
    const { kindSwitch, charOpts, wordOpts, sync } = generatorControls(options, () => {
      sync();
      saveGeneratorOptions(options);
      this.generate({ options });
    });
    const again = h("button", { class: "btn small", type: "button", title: t("generator.another"), on: { click: () => this.generate({ options }) } }, icon("retry"), t("generator.again"));
    const panel = h("div", { class: "menu generator gen-drop", role: "dialog", "aria-label": t("editor.generator_options") },
      h("div", { class: "row" }, kindSwitch, h("span", { class: "spacer" }), again), charOpts, wordOpts);
    this.popup = popover(anchor, panel, { onClose: () => { this.popup = null; } });
    kindSwitch.querySelector(".active").focus();
  }

  urlText() {
    return this.urlRows.map((r) => r.url).join("\n");
  }

  /** The website rows; the first up front, the others under More details. */
  renderUrlRows(focus = -1) {
    const rows = this.urlRows.map((row, i) => {
      const input = h("input", { class: "input", value: row.url, spellcheck: "false", autocomplete: "off", placeholder: "https://github.com", "aria-label": t("editor.website_n", { n: i + 1 }) });
      const badge = ruleBadgeEl(effectiveRule(row.url, row.rule));
      const paint = () => paintBadge(badge, effectiveRule(row.url, row.rule));
      input.addEventListener("input", () => {
        row.url = input.value;
        this.dirty = true;
        paint();
        this.schedulePasswordCheck();
        this.nameFromSite(row.url);
      });
      const gear = this.ruleButton(() => ({ url: row.url, app: isAppPin(row.url), rule: effectiveRule(row.url, row.rule) }), (rule) => {
        row.rule = rule;
        this.dirty = true;
        paint();
      });
      const remove = iconButton("close", t("editor.remove_website"), () => this.removeUrl(i));
      const field = this.suggestSites
        ? siteSuggest(input, siteQuery, (site) => {
            row.url = siteUrl(site.domain);
            input.value = row.url;
            this.dirty = true;
            paint();
            this.schedulePasswordCheck();
            this.setAutoTitle(site.name);
          })
        : input;
      return h("div", { class: "input-group url-row" }, field, badge, gear, remove);
    });
    mount(this.urlFirst, rows[0]);
    mount(this.urlMore, rows.slice(1));
    if (rows[focus]) rows[focus].querySelector("input").focus();
  }

  renderAppRows() {
    mount(this.appList, this.appRows.map((row) => {
      const badge = ruleBadgeEl(row.rule);
      const paint = () => paintBadge(badge, row.rule);
      const gear = this.ruleButton(() => ({ app: true, rule: row.rule }), (rule) => {
        row.rule = rule;
        this.dirty = true;
        paint();
      });
      return h("div", { class: "url-row app-row" }, icon("phoneApp"), h("span", { class: "grow selectable", text: row.package }), badge, gear);
    }));
  }

  useSite(site) {
    this.title.value = site.name;
    this.autoTitle = false;
    this.dirty = true;
    if (!this.urlRows[0].url.trim()) {
      this.urlRows[0].url = siteUrl(site.domain);
      this.renderUrlRows();
    }
    this.schedulePasswordCheck();
  }

  nameFromSite(url) {
    if (!this.suggestSites || (this.title.value.trim() && !this.autoTitle)) return;
    clearTimeout(this.nameTimer);
    const n = ++this.nameSeq;
    this.nameTimer = setTimeout(async () => {
      const site = siteQuery(url) ? url.trim() : "";
      const name = site ? await invoke("site_name_for", { url: site }).catch(() => null) : null;
      if (n === this.nameSeq && this.title.isConnected) this.setAutoTitle(typeof name === "string" ? name : null);
    }, SITE_DELAY_MS);
  }

  setAutoTitle(name) {
    const next = titleForSite(this.title.value, this.autoTitle, name);
    if (next.title === this.title.value && next.auto === this.autoTitle) return;
    this.title.value = next.title;
    this.autoTitle = next.auto;
    this.schedulePasswordCheck();
  }

  addUrl() {
    this.urlRows.push({ url: "", rule: "subdomains" });
    this.dirty = true;
    this.renderUrlRows(this.urlRows.length - 1);
  }

  removeUrl(i) {
    this.urlRows.splice(i, 1);
    if (!this.urlRows.length) this.urlRows.push({ url: "", rule: "subdomains" });
    this.dirty = true;
    this.renderUrlRows(Math.min(i, this.urlRows.length - 1));
    this.schedulePasswordCheck();
  }

  ruleButton(current, onPick) {
    const gear = iconButton("gear", t("editor.match_options"), () => this.openRuleMenu(gear, current(), onPick));
    gear.setAttribute("aria-haspopup", "menu");
    gear.setAttribute("aria-expanded", "false");
    return gear;
  }

  /** The rule menu under `anchor`: one radio item per rule; a shared-hosting site gets "Same host only" marked suggested, never chosen. */
  async openRuleMenu(anchor, { url = "", app = false, rule }, onPick) {
    const reopen = !(this.popup && this.popup.anchor === anchor);
    this.closePopup();
    if (!reopen) return;
    const site = url.trim();
    const suggestHost = !app && site ? await invoke("url_suggests_host_only", { url: site }).catch(() => false) : false;
    if (!anchor.isConnected || this.popup) return;
    const items = ruleOptions({ app, suggestHost }).map((o) => h("button", {
      class: "menu-item",
      type: "button",
      role: "menuitemradio",
      "aria-checked": String(o.rule === rule),
      on: { click: () => { this.closePopup(); onPick(o.rule); } },
    },
    h("span", { class: "menu-text" },
      h("span", { class: "rule-name" }, h("span", { text: o.label }), o.suggested ? h("span", { class: "rule-suggested", text: t("editor.rule_suggested") }) : null),
      h("span", { class: "menu-hint", text: o.hint })),
    o.rule === rule ? icon("check", "menu-check") : null));
    const menu = h("div", { class: "menu rule-menu", role: "menu", "aria-label": anchor.getAttribute("aria-label") }, items);
    menu.addEventListener("keydown", (e) => {
      const i = items.indexOf(document.activeElement);
      const to = { ArrowDown: (i + 1) % items.length, ArrowUp: (i - 1 + items.length) % items.length, Home: 0, End: items.length - 1 }[e.key];
      if (to === undefined) return;
      e.preventDefault();
      items[to].focus();
    });
    this.popup = popover(anchor, menu, { tabCloses: true, onClose: () => { this.popup = null; } });
    (items.find((b) => b.getAttribute("aria-checked") === "true") || items[0]).focus();
  }

  closePopup() {
    if (this.popup) this.popup.close();
  }

  addField() {
    this.fieldRows.push({ name: "", value: "", kind: "text" });
    this.dirty = true;
    this.renderFieldRows();
    const inputs = this.fieldList.querySelectorAll(".cf-name");
    if (inputs.length) inputs[inputs.length - 1].focus();
  }

  moveField(i, delta, focusSel) {
    const j = i + delta;
    if (j < 0 || j >= this.fieldRows.length) return;
    [this.fieldRows[i], this.fieldRows[j]] = [this.fieldRows[j], this.fieldRows[i]];
    this.dirty = true;
    this.renderFieldRows();
    const row = this.fieldList.children[j];
    const target = row && (row.querySelector(focusSel) || row.querySelector(".cf-name"));
    if (target && !target.disabled) target.focus();
    else if (row) row.querySelector(".cf-name").focus();
  }

  renderFieldRows() {
    const rows = this.fieldRows;
    mount(this.fieldList, rows.length ? rows.map((f, i) => {
      const name = h("input", { class: "input cf-name", value: f.name, placeholder: t("editor.field_name"), spellcheck: "false", autocomplete: "off", maxlength: String(Math.max(FIELD_NAME_MAX, f.name.length)), "aria-label": t("editor.field_name_label", { n: i + 1 }) });
      name.addEventListener("input", () => { f.name = name.value; this.dirty = true; });
      const props = { value: f.value, placeholder: f.kind === "url" ? "https://…" : t("editor.field_value"), "aria-label": t("editor.field_value_label", { n: i + 1 }), class: "input cf-value", maxlength: String(Math.max(FIELD_VALUE_MAX, f.value.length)) };
      let valueEl;
      if (f.kind === "hidden") {
        const secret = secretInput(props, () => { f.value = secret.input.value; this.dirty = true; });
        valueEl = secret.el;
      } else {
        const v = h("input", { ...props, type: f.kind === "url" ? "url" : "text", spellcheck: "false", autocomplete: "off" });
        v.addEventListener("input", () => { f.value = v.value; this.dirty = true; });
        valueEl = v;
      }
      const kind = h("select", { class: "input cf-kind", "aria-label": t("editor.field_type_label", { n: i + 1 }) }, FIELD_KINDS.map(([v, label]) => h("option", { value: v, text: label })));
      kind.value = f.kind;
      kind.addEventListener("change", () => { f.kind = kind.value; this.dirty = true; this.renderFieldRows(); });
      const up = iconButton("chevronUp", t("editor.move_up"), () => this.moveField(i, -1, ".cf-up"), "ghost small cf-up");
      const down = iconButton("chevronDown", t("editor.move_down"), () => this.moveField(i, 1, ".cf-down"), "ghost small cf-down");
      up.disabled = i === 0;
      down.disabled = i === rows.length - 1;
      const del = iconButton("trash", t("editor.remove_field"), () => {
        rows.splice(i, 1);
        this.dirty = true;
        this.renderFieldRows();
      }, "ghost small");
      return h("div", { class: "cf-row" }, name, valueEl, kind, h("div", { class: "cf-actions" }, up, down, del));
    }) : h("div", { class: "hint", text: t("editor.custom_fields_hint") }));
  }

  renderPasskeys() {
    const list = this.item.passkeys || [];
    mount(
      this.passkeyList,
      list.map((pk) =>
        h("div", { class: "frow" },
          icon("key"),
          h("div", { class: "value" },
            h("div", { text: pk.user_name || pk.user_display_name || t("editor.no_user_name") }),
            h("div", { class: "faint", text: pk.created_at ? t("editor.passkey_created", { site: pk.rp_id, date: formatDate(pk.created_at, { dateStyle: "short" }) }) : pk.rp_id })),
          iconButton("trash", t("editor.remove_passkey"), () => {
            this.item.passkeys = this.item.passkeys.filter((p) => p.credential_id !== pk.credential_id);
            this.dirty = true;
            this.renderPasskeys();
          })),
      ),
      list.length ? null : h("div", { class: "frow faint", text: t("editor.passkeys_removed") }),
    );
  }

  async checkTotp() {
    const value = this.totp.value.trim();
    if (!value) {
      this.totpStatus.className = "hint";
      this.totpStatus.textContent = t("editor.totp_hint");
      return;
    }
    const r = await invoke("totp_check", { input: value }).catch((e) => ({ valid: false, error: errorText(e) }));
    if (r.valid) {
      const who = [r.issuer, r.account].filter(Boolean).join(" · ");
      this.totpStatus.className = "ok-text";
      this.totpStatus.textContent = who ? t("editor.totp_valid_who", { who, code: formatCode(r.code || "") }) : t("editor.totp_valid", { code: formatCode(r.code || "") });
    } else {
      this.totpStatus.className = "error-text";
      this.totpStatus.textContent = r.error || t("editor.totp_invalid");
    }
  }

  async scanTotp() {
    this.totpScanBtn.disabled = true;
    mount(this.totpChoices);
    this.totpStatus.className = "hint";
    this.totpStatus.textContent = t("qrscan.scanning");
    let found;
    try {
      found = await invoke("qr_scan_screen");
    } catch (e) {
      this.totpScanBtn.disabled = false;
      this.totpStatus.className = "error-text";
      this.totpStatus.textContent = errorText(e);
      return;
    }
    this.totpScanBtn.disabled = false;
    const codes = found.codes || [];
    if (codes.length === 1) {
      this.useScanned(codes[0]);
      return;
    }
    this.totpStatus.className = "hint";
    this.totpStatus.textContent = t("editor.scan_pick");
    mount(this.totpChoices, codes.map((c) => h("button", {
      class: "btn small tonal",
      type: "button",
      text: [c.issuer, c.account].filter(Boolean).join(" · ") || t("otpauth.default_title"),
      on: { click: () => { mount(this.totpChoices); this.useScanned(c); } },
    })));
  }

  useScanned(code) {
    const current = this.totp.value.trim();
    if (current && current !== code.uri && !confirm(t("editor.scan_replace"))) {
      this.checkTotp();
      return;
    }
    this.totp.value = code.uri;
    if (!this.title.value.trim() && code.issuer) this.title.value = code.issuer;
    if (!this.username.value.trim() && code.account) this.username.value = code.account;
    this.dirty = true;
    this.checkTotp();
    toast(t("editor.scan_done"));
  }

  detachKeys() {
    if (this.keys) document.removeEventListener("keydown", this.keys);
    this.keys = null;
    this.closePopup();
  }

  /** Esc, Cancel and Cmd+W: an open popup or list closes first; then the editor closes, asking about unsaved changes. */
  cancel() {
    const list = this.pane.querySelector(".tag-suggest:not([hidden])");
    const step = cancelStep({ popup: !!this.popup, list: !!list, dirty: this.dirty });
    if (step === "popup") {
      this.closePopup();
      return;
    }
    if (step === "list") {
      pressEscape(list.parentElement.querySelector("input"));
      return;
    }
    if (step === "ask" && !confirm(t("editor.discard"))) return;
    this.detachKeys();
    this.hooks.onCancel();
  }

  async save() {
    const it = this.item;
    const kind = it.kind;
    const identity = {};
    for (const [key, el] of Object.entries(this.identityInputs)) identity[key] = el.value;
    const year = Number(this.cardYear.value) || 0;
    const dto = {
      ...it,
      title: this.title.value,
      username: this.username.value,
      password: this.password.value,
      ...savedUrls(this.urlRows),
      android_never_show: hiddenApps(this.appRows),
      totp: this.totp.value.trim() || null,
      notes: this.notes.value,
      favorite: this.favorite.checked,
      card: kind === "card"
        ? {
            cardholder_name: this.cardHolder.value,
            number: this.cardNumber.input.value,
            expiry_month: Number(this.cardMonth.value) || 0,
            expiry_year: year,
            security_code: this.cardCode.input.value,
            pin: this.cardPin.input.value,
            brand: (it.card && it.card.brand) || "",
          }
        : null,
      identity: kind === "identity" ? identity : null,
      fields: this.fieldRows
        .filter((f) => f.name.trim() || f.value)
        .map((f) => ({ name: f.name.trim(), value: f.value, kind: f.kind })),
      tags: this.tags.values(),
      ai_access: this.aiShare.checked ? this.aiMode.value : null,
    };
    const unnamed = this.fieldRows.findIndex((f) => !f.name.trim() && f.value);
    if (unnamed >= 0) {
      this.error.textContent = t("editor.field_needs_name");
      this.showDetails(true);
      const el = this.fieldList.children[unnamed];
      if (el) el.querySelector(".cf-name").focus();
      return;
    }
    if (kind === "card" && year && (year < 2000 || year > 2099) && !(year >= 0 && year < 100)) {
      this.error.textContent = t("editor.year_four_digits");
      this.cardYear.focus();
      return;
    }
    const titleOptional = (kind === "card" && dto.card.number.trim()) || (kind === "identity" && (identity.first_name || identity.last_name));
    if (!dto.title.trim() && !titleOptional) {
      this.error.textContent = t("editor.needs_title");
      this.title.focus();
      return;
    }
    try {
      const args = { item: dto };
      if (!it.id && this.vaultSelect && this.saveVault) args.vaultId = this.saveVault;
      const saved = await invoke("save_item", args);
      this.dirty = false;
      this.detachKeys();
      toast(t("common.saved"));
      this.hooks.onSaved(saved);
    } catch (e) {
      this.error.textContent = errorText(e);
    }
  }
}
