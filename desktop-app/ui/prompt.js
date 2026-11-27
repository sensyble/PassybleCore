// Prompt window: passkey consent and choice, Windows Hello ("unlock", "verify"), "fill-cross" (a
// login filled into another site's page; Cancel is the default) and AI tool requests ("ai-run" to
// run a command with secrets, Deny is the default; "ai-reveal" to show a value, asked every time).
// Windows' Hello dialog is a modal window owned by this one; if it doesn't open or come to the
// front within 2 s the state turns "stalled" / "unfocused" and the buttons here cancel it. The
// agent blocks on these until answered; closing the window or Esc counts as "no".

import { h, icon, invoke, listen, mount, onShown, errorText, passwordField, t, tx } from "./lib.js";
import { itemAvatar, watchIcons } from "./siteicons.js";

const root = document.getElementById("root");
let prompts = [];
let current = null;

async function refresh() {
  try {
    prompts = await invoke("pending_prompts");
  } catch (e) {
    prompts = [];
  }
  const next = prompts[0] || null;
  if (!next) {
    current = null;
    mount(root);
    return;
  }
  // "unlock" prompts change in place (waiting → failed → waiting).
  if (!current || current.request_id !== next.request_id || JSON.stringify(current.data) !== JSON.stringify(next.data)) {
    current = next;
    render(next);
  } else {
    renderCounter();
  }
}

function answer(value) {
  if (!current) return;
  const id = current.request_id;
  current = null;
  invoke("answer_prompt", { requestId: id, answer: value }).catch(() => {}).finally(refresh);
}

function counter() {
  return h("span", { class: "faint", id: "counter" });
}

function renderCounter() {
  const el = document.getElementById("counter");
  if (el) el.textContent = prompts.length > 1 ? t("prompt.counter", { total: prompts.length }) : "";
}

/** Fits the window's height to the prompt (480 at most; longer lists scroll). Needs core:window:allow-set-size and allow-center. */
function fitWindow() {
  const win = window.__TAURI__ && window.__TAURI__.window;
  if (!win || !win.getCurrentWindow || !win.LogicalSize) return;
  requestAnimationFrame(() => {
    const was = root.style.height;
    root.style.height = "auto";
    const natural = Math.ceil(root.getBoundingClientRect().height);
    root.style.height = was;
    const height = Math.max(180, Math.min(480, natural));
    if (Math.abs(height - window.innerHeight) < 2) return;
    // 440 is the window's configured width.
    const current = win.getCurrentWindow();
    current.setSize(new win.LogicalSize(440, height)).then(() => current.center()).catch(() => {});
  });
}

function render(prompt) {
  root.onkeydown = null;
  if (prompt.kind === "passkey-create") renderCreate(prompt.data);
  else if (prompt.kind === "passkey-choose") renderChoose(prompt.data);
  else if (prompt.kind === "unlock") renderUnlock(prompt.data);
  else if (prompt.kind === "verify") renderVerify(prompt.data);
  else if (prompt.kind === "fill-cross") renderFillCross(prompt.data);
  else if (prompt.kind === "fill-card") renderFillCard(prompt.data);
  else if (prompt.kind === "ai-run") renderAiRun(prompt.data);
  else if (prompt.kind === "ai-reveal") renderAiReveal(prompt.data);
  else {
    console.warn("prompt: unknown kind", prompt.kind);
    mount(root, h("p", { text: t("prompt.unknown") }));
  }
  renderCounter();
  fitWindow();
}

function renderCreate(data) {
  const candidates = data.candidates || [];
  const select = h(
    "select",
    { class: "input", id: "attach" },
    candidates.map((c) =>
      h("option", { value: c.id, text: c.username ? t("prompt.title_user", { title: c.title, username: c.username }) : c.title }),
    ),
    h("option", { value: "", text: t("prompt.create_login") }),
  );
  const save = h("button", { class: "btn primary", type: "submit", text: t("prompt.save_passkey") });
  const cancel = h("button", {
    class: "btn",
    type: "button",
    text: t("common.cancel"),
    on: { click: () => answer({ approve: false }) },
  });
  const form = h(
    "form",
    {
      class: "col grow",
      on: {
        submit: (e) => {
          e.preventDefault();
          answer({ approve: true, item_id: select.value || null });
        },
      },
    },
    h(
      "div",
      { class: "head" },
      icon("key"),
      h(
        "div",
        { class: "col" },
        h("h2", {}, t("prompt.save_passkey_title")),
        h(
          "p",
          { class: "muted" },
          tx("prompt.save_passkey_body", {
            user: h("strong", { class: "selectable", text: data.user_name || t("prompt.this_account") }),
            site: h("strong", { class: "selectable", text: data.rp_id }),
          }),
        ),
      ),
    ),
    h(
      "div",
      { class: "field" },
      h("label", { for: "attach", text: t("prompt.keep_with") }),
      select,
      h("span", { class: "hint", text: t("prompt.passkey_syncs") }),
    ),
    h("div", { class: "actions" }, counter(), h("span", { class: "spacer" }), cancel, save),
  );
  mount(root, form);
  save.focus();
}

function renderChoose(data) {
  const options = data.options || [];
  let selected = 0;
  const items = options.map((o, i) =>
    h(
      "li",
      {
        class: "list-item",
        role: "option",
        tabindex: "-1",
        on: {
          click: () => select(i),
          dblclick: () => answer({ index: i }),
        },
      },
      data.site ? itemAvatar({ title: o.title, kind: "login", site: data.site }) : icon("key"),
      h(
        "div",
        { class: "grow" },
        h("div", { class: "title ellipsis", text: o.user_name || o.title }),
        h("div", { class: "sub ellipsis", text: o.title }),
      ),
    ),
  );
  function select(i) {
    selected = Math.max(0, Math.min(items.length - 1, i));
    items.forEach((el, n) => {
      el.classList.toggle("selected", n === selected);
      el.setAttribute("aria-selected", String(n === selected));
    });
    items[selected] && items[selected].scrollIntoView({ block: "nearest" });
  }
  const list = h("ul", { class: "list", role: "listbox", "aria-label": t("field.passkeys") }, items);
  const ok = h("button", {
    class: "btn primary",
    type: "button",
    text: t("prompt.sign_in"),
    on: { click: () => answer({ index: selected }) },
  });
  const cancel = h("button", { class: "btn", type: "button", text: t("common.cancel"), on: { click: () => answer(null) } });
  // A request from the browser: its own WebAuthn can take over (phone, security key).
  const elsewhere = data.elsewhere
    ? h("button", { class: "btn", type: "button", text: t("prompt.use_another_device"), on: { click: () => answer({ elsewhere: true }) } })
    : null;
  mount(
    root,
    h(
      "div",
      { class: "head" },
      icon("key"),
      h(
        "div",
        { class: "col" },
        h("h2", {}, t("prompt.choose_title")),
        h("p", { class: "muted" }, tx("prompt.choose_body", { site: h("strong", { text: data.rp_id }) })),
      ),
    ),
    list,
    h("div", { class: "actions" }, counter(), elsewhere, h("span", { class: "spacer" }), cancel, ok),
  );
  if (data.site) watchIcons(list);
  select(0);
  ok.focus();
  root.onkeydown = (e) => {
    if (!current || current.kind !== "passkey-choose") return;
    if (e.key === "ArrowDown") { e.preventDefault(); select(selected + 1); }
    else if (e.key === "ArrowUp") { e.preventDefault(); select(selected - 1); }
    else if (e.key === "Enter") { e.preventDefault(); answer({ index: selected }); }
  };
}

function helloStatus(data, waiting) {
  if (data.state === "failed") return data.error || t("prompt.hello_failed");
  if (data.state === "stalled") return t("prompt.hello_stalled");
  if (data.state === "unfocused") return t("prompt.hello_unfocused");
  return waiting;
}

function renderUnlock(data) {
  const failed = data.state === "failed";
  const stalled = failed || data.state === "stalled";
  const status = h("p", { class: "muted", role: "status" },
    helloStatus(data, t("prompt.hello_confirm")));
  const choose = (action) => {
    if (!current) return;
    const id = current.request_id;
    invoke("answer_prompt", { requestId: id, answer: { action } }).catch(() => {});
  };
  const password = h("button", {
    class: "btn",
    type: "button",
    text: t("prompt.use_password"),
    on: { click: () => choose("password") },
  });
  const cancel = h("button", { class: "btn", type: "button", text: t("common.cancel"), on: { click: () => choose("cancel") } });
  const retry = h("button", {
    class: "btn primary",
    type: "button",
    on: { click: () => choose("retry") },
  }, icon("hello"), failed ? t("common.try_again") : t("prompt.use_hello"));
  retry.hidden = !stalled;
  mount(
    root,
    h(
      "div",
      { class: "head" },
      icon(failed ? "lock" : "hello"),
      h(
        "div",
        { class: "col" },
        h("h2", { class: "ellipsis", text: t("prompt.unlock_title", { vault: data.vault_name || "Passyble" }) }),
        status,
      ),
    ),
    h("div", { class: "actions" }, counter(), password, h("span", { class: "spacer" }), cancel, retry),
  );
  (stalled ? retry : password).focus();
}

/**
 * Windows Hello before a fill. When Hello doesn't confirm (or the user picks the link) the state
 * turns "password": the master password is typed here and checked by the app (`verify_password`).
 */
function renderVerify(data) {
  const stalled = data.state === "stalled";
  const asking = data.state === "password";
  const choose = (action, extra = {}) => {
    if (!current) return;
    invoke("answer_prompt", { requestId: current.request_id, answer: { action, ...extra } }).catch(() => {});
  };
  const cancel = h("button", { class: "btn", type: "button", text: t("common.cancel"), on: { click: () => choose("cancel") } });
  const retry = h("button", {
    class: asking ? "btn" : "btn primary",
    type: "button",
    on: { click: () => choose("retry") },
  }, icon("hello"), t("prompt.use_hello"));
  retry.hidden = !stalled && !asking;
  // " from {vault}" continues a reason; after the generic sentence the vault goes on its own line.
  const vaultNote = !data.vault_name
    ? null
    : data.reason
      ? h("span", { text: t("prompt.from_vault", { vault: data.vault_name }) })
      : [h("br"), h("span", { text: t("recovery.print_vault", { vault: data.vault_name }) })];
  const reason = h("p", { class: "muted prompt-reason" }, data.reason || t("prompt.verify_reason"), vaultNote);
  const status = data.state === "stalled" || data.state === "unfocused"
    ? h("p", { class: "muted", role: "status", text: helloStatus(data, "") })
    : null;
  const usePassword = asking ? null : h("button", {
    class: "btn",
    type: "button",
    text: t("prompt.use_password"),
    on: { click: () => choose("password") },
  });
  let form = null;
  let pw = null;
  if (asking) {
    pw = passwordField({ id: "verify-master", placeholder: t("unlock.master_password"), autocomplete: "off",
      "aria-label": t("unlock.master_password") });
    const confirm = h("button", { class: "btn primary", type: "submit", text: t("prompt.confirm") });
    form = h(
      "form",
      {
        class: "col",
        on: {
          submit: (e) => {
            e.preventDefault();
            const password = pw.input.value;
            pw.input.value = "";
            if (!password) return;
            choose("verify_password", { password });
          },
        },
      },
      data.error ? h("p", { class: "error-text", role: "alert", text: data.error }) : null,
      h("div", { class: "field" }, h("label", { for: "verify-master", text: t("unlock.master_password") }), pw.el),
      h("div", { class: "actions" }, counter(), h("span", { class: "spacer" }), cancel, retry, confirm),
    );
  }
  mount(
    root,
    h(
      "div",
      { class: "head" },
      icon("hello"),
      h("div", { class: "col" }, h("h2", { text: t("prompt.verify_title") }), reason, status),
    ),
    form || h("div", { class: "actions" }, counter(), usePassword, h("span", { class: "spacer" }), cancel, retry),
  );
  if (asking) pw.input.focus();
  else (stalled ? retry : cancel).focus();
}

/** Phishing pages copy real sites, so Cancel is the default and "Fill once" covers this fill only. */
function renderFillCross(data) {
  const itemSite = data.item_domain || data.title || "";
  const pageHost = data.page_host || t("prompt.this_site");
  const cancel = h("button", {
    class: "btn",
    type: "button",
    text: t("common.cancel"),
    on: { click: () => answer({ approve: false }) },
  });
  const fill = h("button", {
    class: "btn primary",
    type: "button",
    text: t("prompt.fill_once"),
    on: { click: () => answer({ approve: true }) },
  });
  const head = h(
    "div",
    { class: "head" },
    data.site ? itemAvatar({ title: data.title || itemSite, kind: "login", site: data.site }) : icon("key"),
    h(
      "div",
      { class: "col" },
      h("h2", {}, t("prompt.cross_title")),
      h(
        "p",
        { class: "muted" },
        tx(itemSite
          ? (data.username ? "prompt.cross_body_user" : "prompt.cross_body")
          : (data.username ? "prompt.cross_body_this_user" : "prompt.cross_body_this"), {
          site: h("strong", { class: "selectable", text: itemSite }),
          username: data.username,
          host: h("strong", { class: "selectable", text: pageHost }),
        }),
      ),
    ),
  );
  // The page looks like the login's site without being it: say so instead of the general warning.
  const like = data.lookalike && data.lookalike.domain ? data.lookalike : null;
  mount(
    root,
    head,
    like
      ? h(
          "div",
          { class: "banner error", role: "alert" },
          icon("alert"),
          h(
            "span",
            {},
            tx("prompt.cross_lookalike", {
              host: h("strong", { class: "selectable", text: like.host || pageHost }),
              site: h("strong", { class: "selectable", text: like.domain }),
            }),
          ),
        )
      : h(
          "div",
          { class: "banner warn", role: "note" },
          icon("alert"),
          h(
            "span",
            {},
            t("prompt.cross_warning", { host: pageHost }),
          ),
        ),
    h("div", { class: "actions" }, counter(), h("span", { class: "spacer" }), cancel, fill),
  );
  if (data.site) watchIcons(head);
  cancel.focus();
}

/** Cancel is the default: a card is never filled without a click. `copy`: the popup copies the number or code. */
function renderFillCard(data) {
  const card = data.last4 ? t("prompt.card_number", { brand: data.brand_name || t("card.label"), last4: data.last4 }) : data.brand_name || t("prompt.card_lower");
  const label = data.title && data.title !== card ? t("prompt.title_user", { title: data.title, username: card }) : card;
  const pageHost = data.page_host || t("prompt.this_page");
  const cancel = h("button", { class: "btn", type: "button", text: t("common.cancel"), on: { click: () => answer({ approve: false }) } });
  const go = h("button", { class: "btn primary", type: "button", text: data.copy ? t("common.copy") : t("prompt.fill"), on: { click: () => answer({ approve: true }) } });
  const strong = (text) => h("strong", { class: "selectable", text });
  const body = data.copy
    ? tx("prompt.card_copy_body", { card: strong(label) })
    : tx(data.top_host ? "prompt.card_fill_body_framed" : "prompt.card_fill_body", { card: strong(label), host: strong(pageHost), top: data.top_host ? strong(data.top_host) : null });
  mount(
    root,
    h("div", { class: "head" },
      icon("creditCard"),
      h("div", { class: "col" },
        h("h2", {}, data.copy ? t("prompt.card_copy_title") : t("prompt.card_fill_title")),
        h("p", { class: "muted" }, body))),
    data.top_host && !data.copy
      ? h("div", { class: "banner", role: "note" }, icon("info"),
          h("span", {}, tx("prompt.card_framed_note", { top: h("strong", { text: data.top_host }) })))
      : null,
    h("div", { class: "actions" }, counter(), h("span", { class: "spacer" }), cancel, go),
  );
  cancel.focus();
}

/** Deny is the default; "Allow until the vault locks" covers this client and these items until the next lock. */
function renderAiRun(data) {
  const strong = (text) => h("strong", { class: "selectable", text });
  const secrets = (data.secrets || []).map((s) =>
    h("li", { class: "ai-secret" },
      h("code", { class: "mono selectable", text: s.env }),
      h("span", { text: s.vault
        ? t("prompt.ai_secret_from_vault", { item: s.item_title, field: s.field, vault: s.vault })
        : t("prompt.ai_secret_from", { item: s.item_title, field: s.field }) }),
      s.asks ? null : h("span", { class: "faint", text: t("prompt.ai_already_allowed") })));
  const deny = h("button", { class: "btn", type: "button", text: t("prompt.ai_deny"), on: { click: () => answer({ decision: "deny" }) } });
  const once = h("button", { class: "btn primary", type: "button", text: t("prompt.ai_allow_once"), on: { click: () => answer({ decision: "once" }) } });
  const untilLock = h("button", {
    class: "btn", type: "button", text: t("prompt.ai_allow_until_lock"), title: t("prompt.ai_allow_until_lock_title"),
    on: { click: () => answer({ decision: "until_lock" }) },
  });
  mount(
    root,
    h("div", { class: "head" },
      icon("shieldAlert"),
      h("div", { class: "col" },
        h("h2", {}, t("prompt.ai_run_title")),
        h("p", { class: "muted" }, tx("prompt.ai_run_body", { client: strong(data.client || "") })))),
    h("ul", { class: "ai-secrets" }, secrets),
    h("div", { class: "field" },
      h("span", { class: "label", text: t("prompt.ai_command") }),
      h("pre", { class: "ai-command mono selectable", text: data.command_line || "" })),
    h("div", { class: "field" },
      h("span", { class: "label", text: t("prompt.ai_cwd") }),
      h("pre", { class: "ai-command mono selectable", text: data.cwd || "" })),
    h("div", { class: "banner warn", role: "note" }, icon("alert"), h("span", {}, t("prompt.ai_run_warning"))),
    h("div", { class: "actions" }, counter(), h("span", { class: "spacer" }), deny, untilLock, once),
  );
  deny.focus();
}

/** Asked every time: the value goes to the AI provider, which the warning says. The reason is the AI's own text. */
function renderAiReveal(data) {
  const strong = (text) => h("strong", { class: "selectable", text });
  const cancel = h("button", { class: "btn", type: "button", text: t("common.cancel"), on: { click: () => answer({ reveal: false }) } });
  const reveal = h("button", { class: "btn danger", type: "button", text: t("prompt.ai_reveal_button"), on: { click: () => answer({ reveal: true }) } });
  mount(
    root,
    h("div", { class: "head" },
      icon("eye"),
      h("div", { class: "col" },
        h("h2", {}, t("prompt.ai_reveal_title")),
        h("p", { class: "muted" }, tx(data.vault ? "prompt.ai_reveal_body_vault" : "prompt.ai_reveal_body", {
          client: strong(data.client || ""), field: strong(data.field || ""), item: strong(data.item_title || ""),
          ...(data.vault ? { vault: strong(data.vault) } : {}),
        })))),
    data.reason
      ? h("div", { class: "field" },
          h("span", { class: "label", text: t("prompt.ai_says") }),
          h("p", { class: "ai-reason selectable", text: data.reason }))
      : null,
    h("div", { class: "banner error", role: "alert" }, icon("alert"), h("span", {}, t("prompt.ai_reveal_warning"))),
    h("div", { class: "actions" }, counter(), h("span", { class: "spacer" }), cancel, reveal),
  );
  cancel.focus();
}

document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && current) {
    e.preventDefault();
    // Hello prompts stay open until Rust closes them; Esc cancels the operation.
    if (current.kind === "unlock" || current.kind === "verify") {
      invoke("answer_prompt", { requestId: current.request_id, answer: { action: "cancel" } }).catch(() => {});
      return;
    }
    if (current.kind === "ai-run") { answer({ decision: "deny" }); return; }
    if (current.kind === "ai-reveal") { answer({ reveal: false }); return; }
    answer(current.kind === "passkey-create" || current.kind === "fill-cross" || current.kind === "fill-card" ? { approve: false } : null);
  }
});

listen("prompts-changed", refresh).catch((e) => console.error(errorText(e)));
onShown(refresh);
refresh();
