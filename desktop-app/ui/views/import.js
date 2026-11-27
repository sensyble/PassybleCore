// Import from another password manager or authenticator app: choose a file, drop it on the main window or
// paste otpauth-migration:// links, check the preview, then import. The parsed export stays in Rust; this view
// only sees titles, usernames, websites and counts.
// Clashing entries (same site + username as a vault item, or several rows of the file for one account) are
// reviewed as groups with a "Merge" switch and, when passwords differ, which one to keep. Settings → Import →
// Find duplicates shows the same review for logins saved twice and for authenticator codes that belong to a login.

import { agoText, avatar, errorText, formatDate, formatNumber, h, icon, iconButton, invoke, mount, passwordField, settingsRow, t, tn, toast, withShortcut } from "../lib.js";

const HOW_TO = [
  ["Google Authenticator", t("import.howto.google_authenticator")],
  ["Chrome / Edge / Brave", t("import.howto.chromium")],
  ["Firefox", t("import.howto.firefox")],
  ["Apple Passwords / Safari", t("import.howto.apple")],
  ["Proton Pass", t("import.howto.proton")],
  ["1Password", t("import.howto.onepassword")],
  ["Bitwarden", t("import.howto.bitwarden")],
  ["KeePass / KeePassXC", t("import.howto.keepassxc")],
  ["LastPass", t("import.howto.lastpass")],
  ["Dashlane", t("import.howto.dashlane")],
  ["Aegis", t("import.howto.aegis")],
  ["2FAS", t("import.howto.twofas")],
];

const ACTION = {
  add: [t("import.action_new"), "add"],
  merge: [t("merge.merge"), "merge"],
  conflict: [t("import.action_kept_both"), "conflict"],
  duplicate: [t("import.action_already_there"), "dup"],
  skip: [t("import.action_skipped"), "dup"],
};

const DIFFERS = {
  title: t("field.title"),
  password: t("import.password_differs"),
  totp: t("import.totp_differs"),
  urls: t("field.websites"),
  notes: t("field.notes"),
  passkeys: t("field.passkeys"),
};

const PAGE = 100;

/** A titled group: a heading over a card, as in Settings (a leading hint goes under the heading). */
function group(title, ...children) {
  const first = children[0];
  const intro = first instanceof Element && first.classList.contains("hint") ? children.shift() : null;
  if (intro) intro.className = "set-intro";
  return h("section", { class: "set-group" }, h("h3", { class: "set-head", text: title }), intro, h("div", { class: "card" }, ...children));
}

function hostOf(url) {
  if (!url) return "";
  try {
    return new URL(url.includes("://") ? url : `https://${url}`).hostname.replace(/^www\./, "");
  } catch {
    return url;
  }
}

function dateText(ms) {
  return ms ? formatDate(ms) : "";
}

/** Button text for one "keep which" choice (core MergeChoice): where it is from, never values. */
function choiceLabel(c, all) {
  if (c.source === "existing") return t("import.choice_existing");
  if (c.source === "vault") return c.modified_at ? t("import.choice_vault", { title: c.label || t("common.untitled"), ago: agoText(c.modified_at) }) : c.label || t("common.untitled");
  const many = all.filter((x) => x.source === "import").length > 1;
  const base = many ? t("import.choice_import_named", { label: c.label }) : t("import.choice_import");
  return c.modified_at ? t("import.choice_dated", { choice: base, date: dateText(c.modified_at) }) : base;
}

/** The clash groups with a master "Merge duplicates" switch and one per group. `mode`: "import" | "vault". `onChange` on any change. */
class ClashReview {
  constructor(groups, { mode, hidden = 0, onChange }) {
    this.groups = groups;
    this.mode = mode;
    this.hidden = hidden;
    this.onChange = onChange;
    this.state = new Map(groups.map((g) => [g.id, { merge: true, password: null, totp: null }]));
    this.cards = new Map();
    this.shown = 0;
    /** The master switch as last set: groups not shown (over the preview cap) follow it. */
    this.masterOn = true;
  }

  element() {
    this.master = h("input", {
      type: "checkbox", checked: true,
      on: { change: () => this.setAll(this.master.checked) },
    });
    this.list = h("div", { class: "clash-list" });
    this.more = h("button", { class: "btn", type: "button", on: { click: () => this.showMore() } });
    const masterRow = settingsRow("merge", t("import.merge_duplicates"), {
      value: "",
      control: this.master,
      info: this.mode === "vault"
        ? t("import.merge_info_vault")
        : t("import.merge_info_import"),
    });
    this.masterValue = masterRow.valueEl;
    this.showMore();
    this.paintMaster();
    return h("div", { class: "col clash-review" },
      h("div", { class: "card set-card" }, masterRow),
      this.list,
      h("div", { class: "row" }, this.more),
      this.hidden ? h("div", { class: "faint", text: tn("import.more_clashes", this.hidden) }) : null);
  }

  showMore() {
    const next = this.groups.slice(this.shown, this.shown + PAGE);
    this.list.append(...next.map((g) => this.card(g)));
    this.shown += next.length;
    const left = this.groups.length - this.shown;
    this.more.textContent = tn("import.show_more", Math.min(left, PAGE));
    this.more.hidden = left <= 0;
  }

  setAll(on) {
    this.masterOn = on;
    for (const s of this.state.values()) s.merge = on;
    for (const g of this.groups.slice(0, this.shown)) this.refreshCard(g);
    this.paintMaster();
    this.onChange();
  }

  /** The master switch keeps its own setting (the default for every group); its line says how many merge. */
  paintMaster() {
    const on = [...this.state.values()].filter((s) => s.merge).length;
    const all = this.state.size;
    this.master.checked = this.masterOn;
    this.masterValue.textContent = on === all
      ? t("import.master_on")
      : on === 0
        ? (this.mode === "vault" ? t("import.master_off_vault") : t("import.master_off_import"))
        : tn("import.master_some", all, { on: formatNumber(on) });
  }

  context(g) {
    if (this.mode === "vault") return tn("import.copies", g.item_ids.length);
    if (g.kind === "in_file_duplicate") return tn("import.entries_in_file", g.entries.length);
    return g.entries.length > 1 ? tn("import.entries_match", g.entries.length, { title: g.existing_title }) : t("import.matches", { title: g.existing_title });
  }

  status(g, on) {
    const n = this.mode === "vault" ? g.item_ids.length : g.entries.length;
    if (this.mode === "vault") return on ? tn("import.status_merged_removed", n - 1) : t("import.status_left");
    if (g.kind === "identical") return on ? t("import.status_skipped") : (n > 1 ? tn("import.status_more_copies", n) : t("import.status_second_copy"));
    if (g.kind === "differs") return on ? t("import.status_merged_into", { title: g.existing_title }) : (n > 1 ? tn("import.status_separate_items", n) : t("import.status_separate_item"));
    return on ? t("import.status_merged_one") : tn("import.status_separate_items", n);
  }

  keepRow(g, field, label) {
    const choices = g[`${field}_choices`] || [];
    if (choices.length < 2) return null;
    const st = this.state.get(g.id);
    const seg = h("div", { class: "seg", role: "radiogroup", "aria-label": label });
    const paint = () => {
      const current = st[field] || (choices.find((c) => c.is_default) || choices[0]).id;
      for (const b of seg.children) {
        const on = b.dataset.id === current;
        b.classList.toggle("active", on);
        b.setAttribute("aria-checked", String(on));
      }
    };
    for (const c of choices) {
      seg.append(h("button", {
        type: "button", role: "radio", dataset: { id: c.id }, text: choiceLabel(c, choices),
        title: c.modified_at ? t("import.last_changed", { date: dateText(c.modified_at) }) : (c.source === "import" ? t("import.no_date") : null),
        on: { click: () => { st[field] = c.id; paint(); this.onChange(); } },
      }));
    }
    paint();
    return h("div", { class: "clash-keep" }, h("span", { text: label }), seg);
  }

  card(g) {
    const st = this.state.get(g.id);
    const sw = h("input", {
      type: "checkbox", checked: st.merge, "aria-label": t("import.merge_title", { title: g.title }),
      on: {
        change: () => {
          st.merge = sw.checked;
          this.refreshCard(g);
          this.paintMaster();
          this.onChange();
        },
      },
    });
    const chips = g.differs.length
      ? g.differs.map((f) => h("span", { class: `chip${f === "password" || f === "totp" ? " warn" : ""}`, text: DIFFERS[f] || f }))
      : [h("span", { class: "chip", text: t("import.identical") })];
    const keep = h("div", { class: "col clash-keeps" },
      this.keepRow(g, "password", t("import.keep_password")),
      this.keepRow(g, "totp", t("import.keep_totp")));
    const status = h("div", { class: "faint clash-status" });
    const sub = [g.username, hostOf(g.url), this.context(g)].filter(Boolean).join(" · ");
    const el = h("div", { class: "clash" },
      avatar(g.title),
      h("div", { class: "clash-main" },
        h("div", { class: "clash-title ellipsis", text: g.title || t("common.untitled"), title: g.title }),
        h("div", { class: "faint ellipsis", text: sub, title: sub }),
        h("div", { class: "clash-chips" }, chips),
        keep,
        status),
      h("label", { class: "switch clash-switch", title: t("merge.merge") }, h("span", { class: "faint", text: t("merge.merge") }), sw));
    this.cards.set(g.id, { el, sw, keep, status });
    this.refreshCard(g);
    return el;
  }

  refreshCard(g) {
    const c = this.cards.get(g.id);
    if (!c) return;
    const on = this.state.get(g.id).merge;
    c.sw.checked = on;
    c.keep.hidden = !on || !c.keep.childElementCount;
    c.status.textContent = this.status(g, on);
    c.el.classList.toggle("off", !on);
  }

  decision(g) {
    const st = this.state.get(g.id);
    if (!st.merge) return { type: this.mode === "vault" ? "skip" : "keep_both" };
    if (this.mode === "import" && g.kind === "identical") return { type: "skip" };
    return { type: "merge", password_from: st.password, totp_from: st.totp };
  }
}

export class ImportView {
  /** `options.dropped`: a file was dropped on the window (preview right away); `options.duplicates`: open on Find duplicates. */
  constructor(pane, hooks, options = {}) {
    this.pane = pane;
    this.hooks = hooks;
    this.busy = false;
    this.renderStart();
    if (options.dropped) this.previewDropped();
    else if (options.duplicates) this.findDuplicates();
  }

  previewDropped() {
    return this.run(async () => {
      const staged = await invoke("import_dropped");
      if (staged) this.staged(staged);
    });
  }

  destroy() {
    invoke("import_cancel").catch(() => {});
  }

  close() {
    this.destroy();
    this.hooks.onClose();
  }

  header(title) {
    return h("div", { class: "pane-header" },
      iconButton("back", withShortcut(t("common.back"), t("keys.esc")), () => this.close()),
      h("h2", { class: "grow", text: title }));
  }

  renderStart(error) {
    this.paste = h("textarea", {
      class: "input mono", rows: "4", spellcheck: "false", autocomplete: "off",
      placeholder: "otpauth-migration://offline?data=…\notpauth://totp/…",
      "aria-label": t("import.export_links"),
    });
    this.message = h("div", { class: "col" }, error ? h("div", { class: "banner error", text: error }) : null);
    mount(
      this.pane,
      h("div", { class: "pane-inner settings import" },
        this.header(t("import.title")),
        this.message,
        group(t("import.from_file"),
          h("p", { class: "hint", text: t("import.from_file_hint") }),
          h("div", { class: "row" },
            h("button", { class: "btn primary", type: "button", on: { click: () => this.pickFile() } }, icon("folder"), t("import.choose_file"))),
          h("p", { class: "note-line" }, icon("alert"), t("import.delete_exports"))),
        group(t("import.paste_links"),
          h("p", { class: "hint", text: t("import.paste_links_hint") }),
          this.paste,
          h("div", { class: "row" }, h("span", { class: "spacer" }),
            h("button", { class: "btn", type: "button", text: t("import.preview"), on: { click: () => this.previewText() } }))),
        group(t("import.duplicates"),
          h("p", { class: "hint", text: t("import.duplicates_hint") }),
          h("div", { class: "row" },
            h("button", { class: "btn", type: "button", on: { click: () => this.findDuplicates() } }, icon("merge"), t("import.find_duplicates")))),
        group(t("import.how_to"),
          h("div", { class: "howto-list" }, HOW_TO.map(([app, how]) =>
            h("div", { class: "howto" }, h("span", { class: "howto-app", text: app }), h("span", { class: "howto-path", text: how }))))),
      ),
    );
  }

  async run(fn) {
    if (this.busy) return;
    this.busy = true;
    try {
      await fn();
    } catch (e) {
      mount(this.message, h("div", { class: "banner error", text: errorText(e) }));
    } finally {
      this.busy = false;
    }
  }

  pickFile() {
    return this.run(async () => {
      const staged = await invoke("import_file");
      if (staged) this.staged(staged);
    });
  }

  previewText() {
    return this.run(async () => {
      this.staged(await invoke("import_text", { text: this.paste.value }));
      this.paste.value = "";
    });
  }

  staged(r) {
    if (r && r.needs_password) this.askPassword(r);
    else this.renderPreview(r);
  }

  /** A password-protected export: its password (and for KeePass an optional key file, read by Rust), then the preview. */
  askPassword({ source, kind, passyble = true, key_file: keyFile = false }) {
    const pw = passwordField({ autocomplete: "off", id: "imp-export-pw" });
    const error = h("div", { class: "error-text", role: "alert" });
    const submit = h("button", { class: "btn primary", type: "submit", text: t("common.open") });
    const back = () => { invoke("import_cancel").catch(() => {}); this.renderStart(); };
    // KeePass: a key file as well as (or instead of) the password. Only its name comes here.
    const keyName = h("span", { class: "grow ellipsis muted", text: t("import.no_key_file") });
    const removeKey = h("button", {
      class: "btn ghost", type: "button", hidden: true, text: t("import.remove_key_file"),
      on: { click: () => { invoke("import_key_file_clear").catch(() => {}); keyName.textContent = t("import.no_key_file"); removeKey.hidden = true; } },
    });
    const pickKey = h("button", {
      class: "btn", type: "button", text: t("import.choose_key_file"),
      on: {
        click: async () => {
          error.textContent = "";
          try {
            const name = await invoke("import_key_file");
            if (name != null) { keyName.textContent = name; removeKey.hidden = false; }
          } catch (err) {
            error.textContent = errorText(err);
          }
        },
      },
    });
    const keyRow = keyFile
      ? h("div", { class: "field" }, h("label", { text: t("import.key_file") }), h("div", { class: "row" }, icon("key"), keyName, removeKey, pickKey))
      : null;
    mount(
      this.pane,
      h("div", { class: "pane-inner settings import" },
        this.header(t("import.title")),
        group(passyble ? t("import.encrypted_export") : t("import.encrypted_other", { kind: kind || "" }),
          h("div", { class: "row" }, icon("lock"), h("span", { class: "grow ellipsis", text: source || t("import.export_file") })),
          h("p", { class: "hint", text: passyble ? t("import.encrypted_hint") : keyFile ? t("import.keepass_hint") : t("import.encrypted_other_hint") }),
          h("form", {
            class: "col",
            on: {
              submit: async (e) => {
                e.preventDefault();
                error.textContent = "";
                submit.disabled = true;
                try {
                  const r = await invoke("import_with_password", { password: pw.input.value });
                  pw.reset();
                  this.renderPreview(r);
                } catch (err) {
                  error.textContent = errorText(err);
                  pw.input.select();
                } finally {
                  submit.disabled = false;
                }
              },
            },
          },
          h("div", { class: "field" }, h("label", { for: "imp-export-pw", text: keyFile ? t("import.database_password") : t("import.export_password") }), pw.el),
          keyRow,
          error,
          h("div", { class: "row" },
            h("button", { class: "btn", type: "button", text: t("common.back"), on: { click: back } }),
            h("span", { class: "spacer" }),
            submit)))),
    );
    pw.focus();
  }

  renderPreview({ source, preview: p, hidden_rows: hidden, hidden_groups: hiddenGroups = 0 }) {
    const groups = p.groups || [];
    // New items that clash with nothing: under the defaults each in-file group adds one item too.
    const plainAdds = Math.max(0, p.to_add - groups.filter((g) => g.kind === "in_file_duplicate").length);
    const tile = (label) => {
      const n = h("div", { class: "n" });
      return { n, el: h("div", { class: "import-stat" }, n, h("div", { class: "faint", text: label })) };
    };
    const tiles = { added: tile(t("import.tile_new")), merged: tile(t("import.tile_merged")), skipped: tile(t("import.tile_skipped")), cant: tile(t("import.tile_cant")) };
    tiles.cant.n.textContent = formatNumber(p.skipped.length);
    const summary = h("span", { class: "import-summary" });
    const importBtn = h("button", { class: "btn primary", type: "button", on: { click: () => this.commit(importBtn) } });

    const review = groups.length
      ? new ClashReview(groups, { mode: "import", hidden: hiddenGroups, onChange: () => update() })
      : null;
    const update = () => {
      let added = plainAdds;
      let merged = 0;
      let skipped = 0;
      for (const g of groups) {
        const n = g.entries.length;
        if (!review.state.get(g.id).merge) added += n;
        else if (g.kind === "identical") skipped += n;
        else if (g.kind === "differs") merged += n;
        else { added += 1; merged += n - 1; }
      }
      tiles.added.n.textContent = formatNumber(added);
      tiles.merged.n.textContent = formatNumber(merged);
      tiles.skipped.n.textContent = formatNumber(skipped);
      summary.textContent = t("import.summary", { added: formatNumber(added), merged: formatNumber(merged), skipped: formatNumber(skipped) });
      importBtn.disabled = added + merged === 0;
      importBtn.textContent = added + merged ? t("import.import") : t("import.nothing");
    };
    this.review = review;

    const plain = p.entries.filter((e) => !e.group);
    const rows = plain.map((e) => {
      const [label, cls] = ACTION[e.action] || [e.action, ""];
      const what = [
        e.has_password ? t("import.has_password") : null,
        e.has_totp ? t("import.has_totp") : null,
        e.passkeys ? tn("import.has_passkeys", e.passkeys) : null,
        e.has_notes ? t("import.has_notes") : null,
      ].filter(Boolean).join(" · ");
      return h("div", { class: "frow" },
        h("div", { class: "grow" },
          h("div", { class: "ellipsis", text: e.title }),
          h("div", { class: "faint ellipsis", text: [e.username, e.url].filter(Boolean).join(" · ") || (e.kind === "note" ? t("kind.note") : "") }),
          what ? h("div", { class: "faint ellipsis", text: what, title: what }) : null),
        h("span", { class: `chip import-${cls}`, text: label }));
    });

    mount(
      this.pane,
      h("div", { class: "pane-inner settings import" },
        this.header(t("import.preview_title")),
        h("div", { class: "faint", text: [p.format_name, source].filter(Boolean).join(" · ") }),
        this.message = h("div", { class: "col" }),
        h("div", { class: "import-stats" }, tiles.added.el, tiles.merged.el, tiles.skipped.el, tiles.cant.el),
        p.warnings.map((w) => h("div", { class: "banner warn", text: w })),
        review
          ? h("section", { class: "set-group" },
              h("h3", { class: "set-head", text: t("import.review_clashes", { count: formatNumber(groups.length + hiddenGroups) }) }),
              h("p", { class: "hint", text: t("import.review_clashes_hint") }),
              review.element())
          : null,
        p.skipped.length
          ? h("details", { class: "card" },
              h("summary", { text: tn("import.cant_import", p.skipped.length) }),
              h("div", { class: "col" }, p.skipped.slice(0, 500).map((s) =>
                h("div", {}, h("strong", { text: s.entry }), h("span", { class: "muted", text: t("prompt.vault_suffix", { vault: s.reason }) })))))
          : null,
        rows.length
          ? h("section", { class: "set-group" },
              h("h3", { class: "set-head", text: tn("import.new_items", rows.length) }),
              h("div", { class: "fields import-list" }, rows))
          : null,
        hidden ? h("div", { class: "faint", text: tn("import.and_more", hidden) }) : null,
        h("div", { class: "row sticky-actions" }, summary, h("span", { class: "spacer" }),
          h("button", { class: "btn", type: "button", text: t("common.back"), on: { click: () => { invoke("import_cancel").catch(() => {}); this.renderStart(); } } }),
          importBtn),
      ),
    );
    if (review) update();
    else {
      tiles.added.n.textContent = formatNumber(p.to_add);
      tiles.merged.n.textContent = formatNumber(p.to_merge);
      tiles.skipped.n.textContent = formatNumber(p.duplicates);
      summary.textContent = t("import.summary", { added: formatNumber(p.to_add), merged: formatNumber(p.to_merge), skipped: formatNumber(p.duplicates) });
      const n = p.to_add + p.to_merge;
      importBtn.disabled = n === 0;
      importBtn.textContent = n ? t("import.import") : t("import.nothing");
    }
  }

  commit(button) {
    return this.run(async () => {
      button.disabled = true;
      try {
        const review = this.review;
        const args = review
          ? {
              decisions: review.groups.map((g) => ({ group_id: g.id, decision: review.decision(g) })),
              restKeepBoth: review.hidden > 0 && !review.masterOn,
            }
          : {};
        const r = await invoke("import_commit", args);
        const done = { added: formatNumber(r.added), merged: formatNumber(r.merged), skipped: formatNumber(r.skipped) };
        toast(r.skipped ? t("import.done_skipped", done) : t("import.done", done), "", 5000);
        this.hooks.onImported && this.hooks.onImported();
        this.hooks.onClose();
      } finally {
        button.disabled = false;
      }
    });
  }

  findDuplicates() {
    return this.run(async () => {
      this.renderDuplicates(...(await this.loadDuplicates()));
    });
  }

  async loadDuplicates() {
    const [{ groups }, more] = await Promise.all([
      invoke("find_duplicates"),
      invoke("merge_suggestions").catch(() => ({ suggestions: [] })),
    ]);
    return [groups, more.suggestions || []];
  }

  reviewMerges(pairs) {
    if (!this.hooks.onReviewMerges) return;
    this.hooks.onReviewMerges(pairs, () => this.findDuplicates());
  }

  suggestionsSection(suggestions) {
    const n = suggestions.length;
    return h("section", { class: "set-group" },
      h("h3", { class: "set-head", text: t("import.suggestions_title", { count: formatNumber(n) }) }),
      h("p", { class: "hint", text: t("import.suggestions_hint") }),
      h("div", { class: "clash-list" }, suggestions.map((s) => {
        const sub = [s.username, hostOf(s.url), t("import.totp_code", { title: s.otp_title || t("common.untitled") })].filter(Boolean).join(" · ");
        return h("div", { class: "clash" },
          avatar(s.login_title),
          h("div", { class: "clash-main" },
            h("div", { class: "clash-title ellipsis", text: s.login_title || t("common.untitled"), title: s.login_title }),
            h("div", { class: "faint ellipsis", text: sub, title: sub })),
          h("button", { class: "btn small", type: "button", on: { click: () => this.reviewMerges([s]) } }, icon("merge"), t("import.review")));
      })),
      n > 1
        ? h("div", { class: "row" },
            h("button", { class: "btn", type: "button", on: { click: () => this.reviewMerges(suggestions) } }, icon("merge"), t("import.review_all", { count: formatNumber(n) })))
        : null);
  }

  renderDuplicates(groups, suggestions = []) {
    const summary = h("span", { class: "import-summary" });
    const mergeBtn = h("button", { class: "btn primary", type: "button", on: { click: () => this.mergeDuplicates(review, mergeBtn) } });
    const review = groups.length ? new ClashReview(groups, { mode: "vault", onChange: () => update() }) : null;
    const update = () => {
      const on = groups.filter((g) => review.state.get(g.id).merge);
      const removed = on.reduce((n, g) => n + g.item_ids.length - 1, 0);
      summary.textContent = t("import.dup_summary", { merges: tn("import.merges", on.length), removed: tn("import.copies_removed", removed) });
      mergeBtn.disabled = on.length === 0;
      mergeBtn.textContent = on.length ? t("import.merge_n", { count: formatNumber(on.length) }) : t("import.nothing_to_merge");
    };
    mount(
      this.pane,
      h("div", { class: "pane-inner settings import" },
        this.header(t("import.duplicates")),
        this.message = h("div", { class: "col" }),
        suggestions.length ? this.suggestionsSection(suggestions) : null,
        review
          ? [
              h("p", { class: "hint", text: t("import.dup_hint") }),
              h("section", { class: "set-group" },
                h("h3", { class: "set-head", text: t("import.review_duplicates", { count: formatNumber(groups.length) }) }),
                review.element()),
              h("div", { class: "row sticky-actions" }, summary, h("span", { class: "spacer" }),
                h("button", { class: "btn", type: "button", text: t("common.back"), on: { click: () => this.renderStart() } }),
                mergeBtn),
            ]
          : suggestions.length
            ? h("div", { class: "row" }, h("button", { class: "btn", type: "button", text: t("common.back"), on: { click: () => this.renderStart() } }))
            : h("div", { class: "empty-state dup-empty" },
              h("div", { class: "empty-icon" }, icon("check")),
              h("strong", { text: t("import.no_duplicates") }),
              h("span", { text: t("import.no_duplicates_hint") }),
              h("button", { class: "btn", type: "button", text: t("common.back"), on: { click: () => this.renderStart() } })),
      ),
    );
    if (review) update();
  }

  mergeDuplicates(review, button) {
    return this.run(async () => {
      button.disabled = true;
      try {
        const merges = review.groups
          .filter((g) => review.state.get(g.id).merge)
          .map((g) => ({ ids: g.item_ids, decision: review.decision(g) }));
        const r = await invoke("merge_duplicates", { merges });
        toast(t("import.merged_toast", { logins: tn("import.logins", r.merged), removed: tn("import.copies_removed", r.removed) }), "", 5000);
        this.hooks.onImported && this.hooks.onImported();
        this.renderDuplicates(...(await this.loadDuplicates()));
      } finally {
        button.disabled = false;
      }
    });
  }
}
