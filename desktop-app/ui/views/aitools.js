// Settings → AI tools: how to add the Passyble connector (passyble-mcp) to AI tools, the items shared
// with them, the standing permissions ("Allow until the vault locks") with Revoke, and the log of
// recent requests (memory only, never a secret).

import { agoText, errorText, formatDateTime, h, icon, invoke, listen, mount, settingsGroup, settingsRow, t, toast } from "../lib.js";

const rowButton = (iconName, label, onClick, cls = "") =>
  h("button", { class: `btn small ${cls}`.trim(), type: "button", on: { click: onClick } }, iconName ? icon(iconName) : null, label);

const ACTION = { list: "aitools.action_list", run: "aitools.action_run", reveal: "aitools.action_reveal" };
const APPROVAL = {
  once: "aitools.approval_once",
  until_lock: "aitools.approval_until_lock",
  grant: "aitools.approval_grant",
  without_asking: "aitools.approval_without_asking",
};

export function outcomeText(entry) {
  switch (entry.outcome) {
    case "listed": return t("aitools.outcome_listed");
    case "denied": return t("aitools.outcome_denied");
    case "locked": return t("aitools.outcome_locked");
    case "running": return t("aitools.outcome_running");
    case "finished": return entry.exit_code === null || entry.exit_code === undefined
      ? t("aitools.outcome_ended")
      : t("aitools.outcome_exit", { code: entry.exit_code });
    case "timed_out": return t("aitools.outcome_timed_out");
    case "cancelled": return t("aitools.outcome_cancelled");
    case "failed": return t("aitools.outcome_failed");
    case "revealed": return t("aitools.outcome_revealed");
    default: return entry.outcome || "";
  }
}

export class AiToolsPage {
  constructor() {
    this.el = h("div", { class: "col ai-tools" });
    this.unlisten = null;
  }

  async load() {
    if (!this.unlisten) {
      listen("ai-activity", () => { if (this.el.isConnected && !this.el.closest("[hidden]")) this.load(); })
        .then((u) => { this.unlisten = u; })
        .catch(() => {});
    }
    let s;
    try {
      s = await invoke("ai_tools_state");
    } catch (e) {
      mount(this.el, h("div", { class: "banner error", text: errorText(e) }));
      return;
    }
    mount(this.el, this.setupGroup(s), this.sharedGroup(s), this.grantsGroup(s), this.logGroup(s));
  }

  setupGroup(s) {
    const copy = (what) => invoke("ai_tools_copy", { what }).then(() => toast(t("aitools.copied"))).catch((e) => toast(errorText(e), "error"));
    const snippet = (title, what, text, note) => h("div", { class: "col ai-snippet" },
      h("div", { class: "row" }, h("span", { class: "label grow", text: title }), rowButton("copy", t("common.copy"), () => copy(what))),
      h("pre", { class: "mono selectable ai-code", text }),
      note ? h("span", { class: "hint", text: note }) : null);
    const rows = [
      settingsRow("fileText", t("aitools.connector"), {
        value: s.path || t("aitools.not_installed"),
        valueClass: s.installed ? "" : "warn",
        info: t("aitools.connector_info"),
        control: s.path ? rowButton("copy", t("aitools.copy_path"), () => copy("path")) : null,
      }),
    ];
    if (!s.installed) rows.push(h("div", { class: "banner warn", text: t("aitools.not_installed_info") }));
    if (s.appimage) rows.push(h("div", { class: "banner warn", text: t("aitools.appimage") }));
    if (s.setup) {
      rows.push(h("div", { class: "col ai-setup" },
        snippet(t("aitools.claude_code"), "claude_code", s.setup.claude_code, t("aitools.claude_code_note")),
        snippet(t("aitools.codex"), "codex", s.setup.codex, t("aitools.codex_note")),
        snippet(t("aitools.json"), "json", s.setup.json, t("aitools.json_note")),
        h("p", { class: "hint", text: t("aitools.running_note") })));
    }
    return settingsGroup(t("aitools.setup"), rows, { info: t("aitools.how_it_works") });
  }

  sharedGroup(s) {
    let rows;
    if (s.locked) rows = [settingsRow("lock", t("aitools.locked"), {})];
    else if (!s.shared.length) rows = [settingsRow("info", t("aitools.none_shared"), { value: t("aitools.none_shared_hint") })];
    else {
      // Shared vaults: every use asks; a fill-only member's items give no secrets; a vault the
      // organisation's policy or emergency access keeps from AI tools isn't there for them.
      const access = (i) => {
        if (i.blocked === "policy") return t("aitools.blocked_policy");
        if (i.blocked === "emergency") return t("aitools.blocked_emergency");
        const text = i.access === "allow" ? t("editor.ai_allow") : t("editor.ai_ask");
        return i.fill_only ? t("aitools.fill_only", { access: text }) : text;
      };
      rows = s.shared.map((i) => settingsRow(i.kind === "card" ? "creditCard" : i.kind === "note" ? "note" : "key", i.title || t("common.untitled"), {
        value: i.vault ? t("aitools.in_vault", { vault: i.vault, access: access(i) }) : access(i),
        valueClass: i.blocked ? "faint" : i.access === "allow" ? "warn" : "",
      }));
    }
    return settingsGroup(t("aitools.shared"), rows, { info: t("aitools.shared_info") });
  }

  grantsGroup(s) {
    const rows = s.grants.length
      ? s.grants.map((g) => settingsRow("lockOpen", g.item_title, {
          value: t("aitools.grant_value", { client: g.client, when: agoText(g.granted_at) }),
          control: rowButton(null, t("aitools.revoke"), () => invoke("ai_tools_revoke", { itemId: g.item_id, clientKey: g.client_key })
            .then(() => this.load())
            .catch((e) => toast(errorText(e), "error"))),
        }))
      : [settingsRow("shield", t("aitools.no_grants"), { value: t("aitools.no_grants_hint") })];
    return settingsGroup(t("aitools.grants"), rows, { info: t("aitools.grants_info") });
  }

  logGroup(s) {
    const entries = s.log || [];
    const rows = entries.length
      ? entries.map((e) => {
          const what = [t(ACTION[e.action] || "aitools.action_run"), e.items.join(", ")].filter(Boolean).join(": ");
          const outcome = [outcomeText(e), e.approval ? t(APPROVAL[e.approval] || "aitools.approval_once") : null].filter(Boolean).join(", ");
          const row = settingsRow(e.outcome === "denied" ? "close" : e.action === "reveal" ? "eye" : "history", what, {
            value: `${formatDateTime(e.at)} · ${e.client} · ${outcome}`,
            valueClass: e.outcome === "denied" || e.outcome === "failed" || e.outcome === "timed_out" ? "warn" : "",
          });
          if (e.command) {
            row.querySelector(".set-text").append(h("code", { class: "set-sub mono selectable ai-log-command", text: e.cwd ? `${e.command}  (${e.cwd})` : e.command }));
          }
          return row;
        })
      : [settingsRow("history", t("aitools.no_requests"), {})];
    const clear = entries.length
      ? h("div", { class: "row" }, h("span", { class: "spacer" }),
          rowButton("trash", t("aitools.clear_log"), () => invoke("ai_tools_clear_log").then(() => this.load()).catch((e) => toast(errorText(e), "error"))))
      : null;
    return settingsGroup(t("aitools.log"), [rows, clear], { info: t("aitools.log_info") });
  }
}
