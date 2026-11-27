// The password generator (vault view page, the editor's Generate and options dropdown) and the username or
// e-mail panel next to the editor's username field (generator.rs). Usernames, plus and catch-all addresses are
// made locally; an alias is made at the user's service only on "Create alias", and the website goes along
// only with "Mention the website".

import { errorText, h, icon, invoke, mount, t, toast } from "../lib.js";
import { emailSources } from "./generator-model.js";

const STORE_KEY = "pass.generator";
const DEFAULTS = {
  length: 20,
  lowercase: true,
  uppercase: true,
  digits: true,
  symbols: true,
  avoid_ambiguous: true,
  passphrase: false,
  words: 6,
};

function loadOptions() {
  try {
    return { ...DEFAULTS, ...JSON.parse(localStorage.getItem(STORE_KEY) || "{}") };
  } catch {
    return { ...DEFAULTS };
  }
}

export function generatorOptions() {
  return loadOptions();
}

export function saveGeneratorOptions(options) {
  try {
    localStorage.setItem(STORE_KEY, JSON.stringify(options));
  } catch {
    // Storage unavailable: options just aren't remembered.
  }
}

/** The password options, changed in place; `onChange()` after each change, `sync()` shows `options` again. Returns `{ kindSwitch, charOpts, wordOpts, sync }`. */
export function generatorControls(options, onChange) {
  const lengthLabel = h("span", { class: "mono small value-pill" });
  const slider = h("input", { type: "range", min: "8", max: "64", value: String(options.length), "aria-label": t("generator.length") });
  const wordsSlider = h("input", { type: "range", min: "4", max: "10", value: String(options.words), "aria-label": t("generator.words") });

  const toggle = (key, label) => {
    const input = h("input", { type: "checkbox", checked: options[key] });
    input.addEventListener("change", () => {
      options[key] = input.checked;
      onChange();
    });
    return h("label", { class: "check" }, input, label);
  };

  const charOpts = h(
    "div",
    { class: "col" },
    h("div", { class: "row" }, h("span", { class: "label", text: t("generator.length") }), slider, lengthLabel),
    h(
      "div",
      { class: "opts" },
      toggle("lowercase", "a-z"),
      toggle("uppercase", "A-Z"),
      toggle("digits", "0-9"),
      toggle("symbols", "!@#"),
      toggle("avoid_ambiguous", t("generator.avoid_ambiguous")),
    ),
  );
  const wordsLabel = h("span", { class: "mono small value-pill" });
  const wordOpts = h("div", { class: "row" }, h("span", { class: "label", text: t("generator.words") }), wordsSlider, wordsLabel);

  const kindSwitch = h(
    "div",
    { class: "segmented", role: "tablist" },
    h("button", { type: "button", text: t("generator.characters"), on: { click: () => setKind(false) } }),
    h("button", { type: "button", text: t("generator.passphrase"), on: { click: () => setKind(true) } }),
  );

  function setKind(passphrase) {
    options.passphrase = passphrase;
    onChange();
  }

  function sync() {
    lengthLabel.textContent = String(options.length);
    wordsLabel.textContent = String(options.words);
    charOpts.hidden = options.passphrase;
    wordOpts.hidden = !options.passphrase;
    kindSwitch.children[0].classList.toggle("active", !options.passphrase);
    kindSwitch.children[1].classList.toggle("active", options.passphrase);
  }

  slider.addEventListener("input", () => {
    options.length = Number(slider.value);
    onChange();
  });
  wordsSlider.addEventListener("input", () => {
    options.words = Number(wordsSlider.value);
    onChange();
  });
  sync();
  return { kindSwitch, charOpts, wordOpts, sync };
}

export function generatorPanel() {
  const options = loadOptions();
  const preview = h("div", { class: "preview selectable", "aria-live": "polite" });
  const { kindSwitch, charOpts, wordOpts, sync } = generatorControls(options, () => generate());

  let seq = 0;
  async function generate() {
    const n = ++seq;
    sync();
    saveGeneratorOptions(options);
    try {
      const password = await invoke("generate_password", { options });
      if (n === seq) preview.textContent = password;
    } catch (e) {
      if (n === seq) preview.textContent = errorText(e);
    }
  }

  const panel = h(
    "div",
    { class: "generator" },
    h("div", { class: "row" }, kindSwitch, h("span", { class: "spacer" }),
      h("button", { class: "btn small", type: "button", title: t("generator.another"), on: { click: generate } }, icon("retry"), t("generator.again"))),
    preview,
    charOpts,
    wordOpts,
    h(
      "div",
      { class: "row" },
      h("span", { class: "spacer" }),
      h("button", {
        class: "btn",
        type: "button",
        on: { click: () => invoke("copy_secret", { text: preview.textContent }).then(() => toast(t("common.copied_clears"))) },
      }, icon("copy"), t("common.copy")),
    ),
  );
  generate();
  return panel;
}

const USER_STORE_KEY = "pass.generator.username";
const USER_DEFAULTS = {
  mode: "username",
  kind: "words",
  capitalize: true,
  include_number: false,
  separator: "-",
  length: 12,
  // "plus", "catch_all" or "alias:<service id>".
  email: "plus",
};
const SEPARATORS = ["-", "_", ".", ""];

function loadUserOptions() {
  try {
    return { ...USER_DEFAULTS, ...JSON.parse(localStorage.getItem(USER_STORE_KEY) || "{}") };
  } catch {
    return { ...USER_DEFAULTS };
  }
}

function saveUserOptions(options) {
  try {
    localStorage.setItem(USER_STORE_KEY, JSON.stringify(options));
  } catch {
    // Storage unavailable: options just aren't remembered.
  }
}

/** The username / e-mail panel. `onUse(value)` fills the username field. `website`: the login's host, offered for "Mention the website" (off by default, never remembered). */
export function usernamePanel(onUse, { website = "" } = {}) {
  const options = loadUserOptions();
  let sources = [];
  const preview = h("div", { class: "preview selectable", "aria-live": "polite" });
  const hint = h("div", { class: "hint" });
  const error = h("div", { class: "error-text", role: "alert" });

  const toggle = (key, label) => {
    const input = h("input", { type: "checkbox", checked: options[key] });
    input.addEventListener("change", () => {
      options[key] = input.checked;
      generate();
    });
    return h("label", { class: "check" }, input, label);
  };
  const kind = h("select", { class: "input", "aria-label": t("generator.username") },
    [["words", t("generator.kind_words")], ["word_number", t("generator.kind_word_number")], ["characters", t("generator.kind_characters")]]
      .map(([value, text]) => h("option", { value, text })));
  kind.value = options.kind;
  kind.addEventListener("change", () => { options.kind = kind.value; generate(); });
  const separator = h("select", { class: "input", "aria-label": t("generator.separator") },
    SEPARATORS.map((s) => h("option", { value: s, text: s || t("generator.separator_none") })));
  separator.value = SEPARATORS.includes(options.separator) ? options.separator : "-";
  separator.addEventListener("change", () => { options.separator = separator.value; generate(); });
  const lengthLabel = h("span", { class: "mono small value-pill" });
  const slider = h("input", { type: "range", min: "4", max: "32", value: String(options.length), "aria-label": t("generator.length") });
  slider.addEventListener("input", () => { options.length = Number(slider.value); generate(); });

  const capitalize = toggle("capitalize", t("generator.capitalize"));
  const number = toggle("include_number", t("generator.include_number"));
  const sepRow = h("div", { class: "row" }, h("span", { class: "label", text: t("generator.separator") }), separator);
  const lengthRow = h("div", { class: "row" }, h("span", { class: "label", text: t("generator.length") }), slider, lengthLabel);
  const userOpts = h("div", { class: "col" }, kind, h("div", { class: "opts" }, capitalize, number), sepRow, lengthRow);

  const source = h("select", { class: "input", "aria-label": t("generator.email") });
  source.addEventListener("change", () => { options.email = source.value; generate(); });
  const mention = h("input", { type: "checkbox" });
  mention.addEventListener("change", () => generate());
  const mentionRow = h("label", { class: "check" }, mention, t("generator.mention_website", { site: website }));
  mentionRow.hidden = !website;
  const emailOpts = h("div", { class: "col" }, source, mentionRow);

  const again = h("button", { class: "btn small", type: "button", title: t("generator.another"), on: { click: () => generate() } }, icon("retry"), t("generator.again"));
  const create = h("button", { class: "btn", type: "button", on: { click: () => createAlias() } }, icon("mail"), t("generator.create_alias"));
  const use = h("button", { class: "btn tonal", type: "button", on: { click: () => preview.textContent && onUse(preview.textContent) } });
  const copy = h("button", {
    class: "btn",
    type: "button",
    on: { click: () => preview.textContent && invoke("copy_secret", { text: preview.textContent }).then(() => toast(t("common.copied_clears"))) },
  }, icon("copy"), t("common.copy"));

  const modeSwitch = h(
    "div",
    { class: "segmented", role: "tablist" },
    h("button", { type: "button", text: t("generator.username"), on: { click: () => setMode("username") } }),
    h("button", { type: "button", text: t("generator.email"), on: { click: () => setMode("email") } }),
  );

  function setMode(mode) {
    options.mode = mode;
    generate();
  }

  const current = () => sources.find((s) => s.value === options.email) || sources[0] || null;

  function show(value) {
    preview.textContent = value;
    use.disabled = !value;
    copy.disabled = !value;
  }

  let seq = 0;
  async function generate() {
    const n = ++seq;
    const email = options.mode === "email";
    modeSwitch.children[0].classList.toggle("active", !email);
    modeSwitch.children[1].classList.toggle("active", email);
    userOpts.hidden = email;
    emailOpts.hidden = !email;
    sepRow.hidden = options.kind !== "words";
    number.hidden = options.kind !== "words";
    capitalize.hidden = options.kind === "characters";
    lengthRow.hidden = options.kind !== "characters";
    lengthLabel.textContent = String(options.length);
    use.textContent = email ? t("generator.use_email") : t("generator.use_username");
    error.textContent = "";
    hint.textContent = "";
    create.hidden = true;
    again.hidden = false;
    saveUserOptions(options);
    if (!email) {
      try {
        const name = await invoke("generate_username", { options });
        if (n === seq) show(name);
      } catch (e) {
        if (n === seq) { show(""); error.textContent = errorText(e); }
      }
      return;
    }
    const src = current();
    source.hidden = !src;
    mentionRow.hidden = !website || !src;
    if (!src) {
      show("");
      hint.textContent = t("generator.email_not_set_up");
      again.hidden = true;
      return;
    }
    source.value = src.value;
    // DuckDuckGo's API takes no note: nothing about the site can go there.
    const takesSite = !src.service || src.service.id !== "duckduckgo";
    mentionRow.hidden = !website || !takesSite;
    if (!takesSite) mention.checked = false;
    if (src.service) {
      // A new alias is an account change at the service: only on request.
      show("");
      again.hidden = true;
      create.hidden = false;
      hint.textContent = mention.checked
        ? t("generator.alias_hint_site", { service: src.service.name, site: website })
        : t("generator.alias_hint", { service: src.service.name });
      return;
    }
    try {
      const address = await invoke("generate_email", { kind: src.value, website: mention.checked ? website : null });
      if (n === seq) show(address);
    } catch (e) {
      if (n === seq) { show(""); error.textContent = errorText(e); }
    }
  }

  async function createAlias() {
    const src = current();
    if (!src || !src.service) return;
    const n = ++seq;
    create.disabled = true;
    mount(create, t("generator.creating"));
    error.textContent = "";
    try {
      const alias = await invoke("generate_alias", { serviceId: src.service.id, website: mention.checked ? website : null });
      if (n === seq) show(alias);
    } catch (e) {
      if (n === seq) error.textContent = errorText(e);
    } finally {
      create.disabled = false;
      mount(create, icon("mail"), t("generator.create_alias"));
    }
  }

  const panel = h(
    "div",
    { class: "generator" },
    h("div", { class: "row" }, modeSwitch, h("span", { class: "spacer" }), again),
    preview,
    userOpts,
    emailOpts,
    hint,
    error,
    h("div", { class: "row" }, create, h("span", { class: "spacer" }), copy, use),
  );
  show("");
  generate();
  // The addresses and services are in the (unlocked) vault: loaded once.
  invoke("generator_settings").then((s) => {
    sources = emailSources(s);
    mount(source, sources.map((src) => h("option", { value: src.value, text: src.label })));
    if (options.mode === "email") generate();
  }).catch(() => {
    if (options.mode === "email") generate();
  });
  return panel;
}
