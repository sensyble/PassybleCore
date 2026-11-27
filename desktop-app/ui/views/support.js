// Help and support (src-tauri/src/support.rs): one dialog over whatever the window shows, even locked,
// without a vault or read-only (people who can't get in need it most). Signed in: the account's tickets.
// Otherwise guest tickets, confirmed once by e-mail. The pure rules are in support-model.js.

import { agoText, confirmDialog, errorText, formatDate, formatDateTime, h, icon, invoke, listen, modal, mount, t, tn, toast } from "../lib.js";
import { accountRow } from "./account.js";
import {
  BODY_MAX, diagnosticsLines, formatCode, NAME_MAX, parseCodeInput, problemMessage, SUBJECT_MAX, sortTickets, ticketProblems,
  ticketStage, topicChoices, linkArrival,
} from "./support-model.js";

let uid = 0;
const nextId = (p) => `${p}-${++uid}`;
const CHECK_EVERY_MS = 10000;

/** A topic's name: the service's label, else the app's. */
function topicLabel(id, label) {
  if (label) return label;
  switch (id) {
    case "account": return t("support.topic_account");
    case "sync": return t("support.topic_sync");
    case "autofill": return t("support.topic_autofill");
    case "passkeys": return t("support.topic_passkeys");
    case "teams": return t("support.topic_teams");
    case "billing": return t("support.topic_billing");
    default: return t("support.topic_other");
  }
}

function statusLabel(ticket) {
  switch (ticketStage(ticket)) {
    case "waiting": return t("support.status_unconfirmed");
    case "expired": return t("support.status_expired");
    case "gone": return t("support.status_gone");
    case "closed": return t("support.status_closed");
    default:
      return ticket.status === "waiting_on_customer" ? t("support.status_waiting_on_you") : t("support.status_open");
  }
}

function fieldLabel(field) {
  switch (field) {
    case "app": return t("support.diag_app");
    case "app_version": return t("support.diag_app_version");
    case "platform": return t("support.diag_platform");
    case "os_version": return t("support.diag_os_version");
    case "sync": return t("support.diag_sync");
    case "errors": return t("support.diag_errors");
    default: return t("support.diag_locale");
  }
}

function field(label, input, hint = null) {
  const id = input.id || (input.id = nextId("sf"));
  return h("div", { class: "field" }, h("label", { for: id, text: label }), input, hint ? h("span", { class: "hint", text: hint }) : null);
}

const button = (label, onClick, cls = "", iconName = null) =>
  h("button", { class: `btn ${cls}`.trim(), type: "button", on: { click: onClick } }, iconName ? icon(iconName) : null, label);

let current = null;
// An app link is being claimed (the link event and the start-up check can both ask).
let claiming = false;

/** `options`: `claim` (an app link arrived), `reference` (open that thread), `problem` (an error text to quote). */
export function openSupport(options = {}) {
  if (options.claim && claiming) return;
  if (current && current.isOpen()) current.close();
  current = new SupportDialog(options);
}

export function startSupport() {
  listen("show-support", (p) => openSupport({ claim: !!(p && p.claim) })).catch(() => {});
  listen("support-reply", (p) => {
    if (!p || !p.text) return;
    if (current && current.isOpen()) current.refresh();
    toast(String(p.text), "", 0, { action: { label: t("common.open"), icon: "lifeBuoy", onClick: () => openSupport({ reference: p.reference }) } });
  }).catch(() => {});
  listen("support-changed", () => current && current.isOpen() && current.refresh()).catch(() => {});
  // An app link that started Passyble (or arrived before this window was ready).
  invoke("support_status").then((s) => s && s.link_pending && openSupport({ claim: true })).catch(() => {});
}

export function reportProblem(message) {
  openSupport({ problem: problemMessage(message) });
}

class SupportDialog {
  constructor(options) {
    this.m = modal({ label: t("support.title"), cls: "support-dialog", onClose: () => this.stopChecking() });
    this.status = null;
    this.tickets = null;
    this.meta = null;
    this.page = "list";
    this.checkTimer = null;
    this.start(options);
  }

  isOpen() {
    return this.m.isOpen();
  }

  close() {
    this.m.close();
  }

  async start(options) {
    this.loading();
    try {
      this.status = await invoke("support_status");
    } catch (e) {
      this.status = { signed_in: false, guests: [] };
      toast(errorText(e), "error");
    }
    if (options.claim) {
      // Never submitted by the link itself: a web page could fire links to use up the code's tries.
      // The person sees the reference and confirms.
      const arrival = linkArrival(this.status);
      if (arrival) return this.showLinkConfirm(arrival.reference);
    }
    if (options.reference) return this.openThread(options.reference);
    if (options.problem !== undefined && options.problem !== null) return this.showCompose({ problem: options.problem });
    this.showList();
  }

  showLinkConfirm(reference) {
    this.page = "link";
    this.stopChecking();
    const message = h("div", { class: "col", role: "alert" });
    const confirm = button(t("support.link_confirm"), async () => {
      confirm.disabled = true;
      mount(message);
      claiming = true;
      try {
        const thread = await invoke("support_link_claim");
        this.status = await invoke("support_status").catch(() => this.status);
        if (thread) return this.showThread(thread);
        this.showList();
      } catch (e) {
        confirm.disabled = false;
        mount(message, h("div", { class: "banner error", text: errorText(e) }));
      } finally {
        claiming = false;
      }
    }, "primary");
    mount(this.m.box,
      this.header(t("support.link_title"), true),
      h("p", { class: "muted", text: t("support.link_intro") }),
      h("p", { class: "mono", text: reference }),
      message,
      this.actions(button(t("common.back"), () => this.showList()), confirm));
  }

  loading() {
    mount(this.m.box, this.header(t("support.title")), h("p", { class: "muted", text: t("common.loading") }));
  }

  header(title, back = false) {
    return h("div", { class: "row" },
      back
        ? h("button", { class: "btn icon ghost", type: "button", title: t("common.back"), "aria-label": t("common.back"), on: { click: () => this.showList() } }, icon("back"))
        : h("span", { class: "modal-icon" }, icon("lifeBuoy")),
      h("h2", { class: "grow", text: title }));
  }

  actions(...buttons) {
    return h("div", { class: "row modal-actions wrap" }, buttons.filter(Boolean).slice(0, -1), h("span", { class: "spacer" }), buttons.filter(Boolean).slice(-1));
  }

  refresh() {
    if (this.page === "list") this.loadTickets();
  }

  showList() {
    this.page = "list";
    this.stopChecking();
    const s = this.status || {};
    this.listEl = h("div", { class: "col support-list", "aria-live": "polite" }, h("p", { class: "muted", text: t("common.loading") }));
    const intro = s.signed_in
      ? t("support.intro_signed_in", { email: s.email || "" })
      : t("support.intro_guest");
    const newBtn = button(t("support.new_ticket"), () => this.showCompose(), "primary", "plus");
    mount(this.m.box,
      this.header(t("support.title")),
      h("p", { text: intro }),
      // Not signed in: the way to the account's tickets (sign in, or retry after a failed check).
      s.signed_in ? null : h("div", { class: "card set-card" }, accountRow({ onChanged: () => this.start({}) })),
      h("h3", { class: "set-head", text: t("support.your_tickets") }),
      this.listEl,
      this.actions(
        button(t("support.web_form"), () => invoke("support_open_web").catch((e) => toast(errorText(e), "error")), "", "external"),
        button(t("common.close"), () => this.close()),
        newBtn));
    newBtn.focus();
    this.loadTickets();
  }

  async loadTickets() {
    let answer;
    try {
      answer = await invoke("support_tickets");
    } catch (e) {
      answer = { tickets: (this.status && this.status.guests) || [], errors: [errorText(e)] };
    }
    if (this.page !== "list" || !this.listEl) return;
    const tickets = sortTickets(answer.tickets);
    this.tickets = tickets;
    const errors = (answer.errors || []).map((e) => h("div", { class: "banner warn", text: errorText(e) }));
    if (!tickets.length) {
      mount(this.listEl, errors, h("p", { class: "muted", text: t("support.no_tickets") }));
      return;
    }
    mount(this.listEl, errors, h("div", { class: "card set-card" }, tickets.map((ticket) => this.ticketRow(ticket))));
  }

  ticketRow(ticket) {
    const unread = Number(ticket.unread) > 0 ? Number(ticket.unread) : 0;
    const when = ticket.last_message_at || ticket.created_at;
    const sub = [ticket.reference, statusLabel(ticket), when ? agoText(when) : null].filter(Boolean).join(" · ");
    const row = h("div", { class: "set-row set-link", role: "button", tabindex: "0" },
      icon(ticket.guest ? "mail" : "lifeBuoy", "set-ico"),
      h("span", { class: "set-text" },
        h("span", { class: "set-label" }, h("span", { class: "set-title", text: ticket.subject || ticket.reference })),
        h("span", { class: "set-sub", text: sub })),
      unread ? h("span", { class: "pill warn", "aria-label": tn("support.unread", unread), text: tn("support.unread", unread) }) : null,
      icon("chevronRight", "set-chev"));
    const open = () => this.openTicket(ticket);
    row.addEventListener("click", open);
    row.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        open();
      }
    });
    return row;
  }

  openTicket(ticket) {
    const stage = ticketStage(ticket);
    if (stage === "waiting" || stage === "expired" || stage === "gone" && ticket.guest && !ticket.claimed) return this.showWaiting(ticket);
    if (stage === "gone") return this.showGone(ticket);
    this.openThread(ticket.reference);
  }

  async showCompose({ problem = "" } = {}) {
    this.page = "compose";
    this.stopChecking();
    const guest = !(this.status && this.status.signed_in);
    if (!this.meta) this.meta = await invoke("support_meta").catch(() => null);
    const topic = h("select", { class: "input" },
      h("option", { value: "", text: t("support.topic_choose") }),
      topicChoices(this.meta).map((c) => h("option", { value: c.id, text: topicLabel(c.id, c.label) })));
    if (problem) topic.value = "other";
    const subject = h("input", { class: "input", type: "text", maxlength: String(SUBJECT_MAX), autocomplete: "off" });
    if (problem) subject.value = t("support.problem_subject");
    const body = h("textarea", { class: "input", rows: "6", maxlength: String(BODY_MAX) });
    if (problem) body.value = t("support.problem_body", { message: problem });
    const email = guest ? h("input", { class: "input", type: "email", autocomplete: "email", spellcheck: "false", maxlength: "254" }) : null;
    const name = guest ? h("input", { class: "input", type: "text", autocomplete: "name", maxlength: String(NAME_MAX) }) : null;
    // Diagnostics: off until the person turns them on, and then shown in full.
    const diagnostics = await invoke("support_diagnostics").catch(() => null);
    const lines = diagnosticsLines(diagnostics);
    const attach = h("input", { type: "checkbox", id: nextId("sd") });
    const preview = h("dl", { class: "support-diag", hidden: true },
      lines.map(([f, value]) => [h("dt", { text: fieldLabel(f) }), h("dd", { class: "mono", text: value })]));
    attach.addEventListener("change", () => { preview.hidden = !attach.checked; });
    const diagBlock = lines.length
      ? h("div", { class: "col" },
        h("label", { class: "row support-check", for: attach.id }, attach, h("span", { text: t("support.attach_diagnostics") })),
        h("p", { class: "hint", text: t("support.diagnostics_note") }),
        h("div", { class: "col", hidden: false }, preview))
      : null;
    const message = h("div", { class: "col", role: "alert" });
    const send = button(t("support.send"), () => this.send(), "primary", "send");
    this.form = { topic, subject, body, email, name, attach, diagnostics, message, send, guest };
    mount(this.m.box,
      this.header(t("support.new_ticket"), true),
      guest ? h("p", { class: "muted", text: t("support.guest_note") }) : null,
      field(t("support.topic"), topic),
      field(t("support.subject"), subject),
      field(t("support.message"), body, t("support.message_hint")),
      guest ? field(t("support.email"), email, t("support.email_hint")) : null,
      guest ? field(t("support.name"), name, t("support.name_hint")) : null,
      diagBlock,
      message,
      this.actions(button(t("common.cancel"), () => this.showList()), send));
    (problem ? body : topic).focus();
  }

  async send() {
    const f = this.form;
    const values = {
      topic: f.topic.value,
      subject: f.subject.value,
      body: f.body.value,
      email: f.email ? f.email.value : "",
      name: f.name ? f.name.value : "",
    };
    const problems = ticketProblems(values, { guest: f.guest });
    const first = Object.keys(problems)[0];
    if (first) {
      const text = {
        topic: t("support.err_topic"),
        subject: t("support.err_subject"),
        body: t("support.err_body"),
        email: t("support.err_email"),
        name: t("support.err_name"),
      }[first];
      mount(f.message, h("div", { class: "banner error", text }));
      ({ topic: f.topic, subject: f.subject, body: f.body, email: f.email, name: f.name })[first].focus();
      return;
    }
    f.send.disabled = true;
    mount(f.message);
    try {
      const out = await invoke("support_create", {
        ticket: {
          subject: values.subject,
          body: values.body,
          category: values.topic,
          diagnostics: f.attach.checked ? f.diagnostics : null,
          email: f.guest ? values.email : null,
          name: f.guest && values.name.trim() ? values.name : null,
        },
      });
      if (out.thread) {
        toast(t("support.sent"));
        this.showThread(out.thread);
      } else if (out.guest) {
        this.status = await invoke("support_status").catch(() => this.status);
        this.showWaiting(out.guest);
      }
    } catch (e) {
      f.send.disabled = false;
      mount(f.message, h("div", { class: "banner error", text: errorText(e) }));
    }
  }

  showWaiting(ticket) {
    this.page = "waiting";
    this.stopChecking();
    const expired = ticketStage(ticket) === "expired";
    const state = h("p", { class: "muted", role: "status", "aria-live": "polite", text: expired ? t("support.code_expired") : t("support.waiting_confirm") });
    const code = h("input", { class: "input mono", type: "text", autocomplete: "one-time-code", spellcheck: "false", placeholder: "ABCD-EFGH", maxlength: "300" });
    const message = h("div", { class: "col", role: "alert" });
    const go = button(t("support.code_continue"), async () => {
      const parsed = parseCodeInput(code.value);
      if (!parsed) {
        mount(message, h("div", { class: "banner error", text: t("support.err_code_shape") }));
        code.focus();
        return;
      }
      go.disabled = true;
      mount(message);
      try {
        const thread = await invoke("support_guest_claim", { reference: ticket.reference, code: code.value });
        this.status = await invoke("support_status").catch(() => this.status);
        this.showThread(thread);
      } catch (e) {
        go.disabled = false;
        mount(message, h("div", { class: "banner error", text: errorText(e) }));
      }
    }, "primary");
    code.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        go.click();
      }
    });
    code.addEventListener("blur", () => {
      const parsed = parseCodeInput(code.value);
      if (parsed && !parsed.reference) code.value = formatCode(parsed.code);
    });
    mount(this.m.box,
      this.header(t("support.check_email_title"), true),
      h("p", { class: "muted", text: `${ticket.reference} · ${ticket.subject || ""}` }),
      h("ol", { class: "guide-steps" },
        h("li", { text: t("support.check_email_1", { email: ticket.email || "" }) }),
        h("li", { text: t("support.check_email_2") }),
        h("li", { text: t("support.check_email_3") })),
      state,
      field(t("support.code"), code, ticket.confirm_by && !expired ? t("support.code_until", { date: formatDateTime(ticket.confirm_by) }) : t("support.code_hint")),
      message,
      this.actions(this.removeButton(ticket), go));
    code.focus();
    if (!expired) this.startChecking(ticket.reference, state);
  }

  startChecking(reference, state) {
    const check = async () => {
      if (this.page !== "waiting") return;
      try {
        const { confirmed } = await invoke("support_guest_check", { reference });
        if (this.page !== "waiting") return;
        state.textContent = confirmed ? t("support.confirmed_enter_code") : t("support.waiting_confirm");
        if (confirmed) return;
      } catch {
        // Offline for a moment: try again later.
      }
      this.checkTimer = setTimeout(check, CHECK_EVERY_MS);
    };
    this.checkTimer = setTimeout(check, 1500);
  }

  stopChecking() {
    clearTimeout(this.checkTimer);
    this.checkTimer = null;
  }

  removeButton(ticket) {
    return button(t("support.remove"), async () => {
      const ok = await confirmDialog({
        title: t("support.remove_title"),
        text: t("support.remove_text", { reference: ticket.reference }),
        confirm: t("support.remove"),
        iconName: "trash",
        danger: true,
      });
      if (!ok) return;
      try {
        await invoke("support_guest_remove", { reference: ticket.reference });
        this.status = await invoke("support_status").catch(() => this.status);
        this.showList();
      } catch (e) {
        toast(errorText(e), "error");
      }
    }, "", "trash");
  }

  showGone(ticket) {
    this.page = "gone";
    mount(this.m.box,
      this.header(ticket.subject || ticket.reference, true),
      h("p", { text: t("support.gone_text", { reference: ticket.reference }) }),
      this.actions(ticket.guest ? this.removeButton(ticket) : null, button(t("common.back"), () => this.showList(), "primary")));
  }

  async openThread(reference) {
    this.loading();
    try {
      this.showThread(await invoke("support_ticket", { reference }));
    } catch (e) {
      toast(errorText(e), "error");
      this.showList();
    }
  }

  showThread(thread) {
    this.page = "thread";
    this.stopChecking();
    const ticket = (thread && thread.ticket) || {};
    const messages = (thread && thread.messages) || [];
    const closed = ticket.status === "closed";
    const meta = [ticket.reference, topicLabel(ticket.category), statusLabel(ticket), ticket.created_at ? formatDate(ticket.created_at) : null].filter(Boolean).join(" · ");
    const list = h("ol", { class: "support-thread", "aria-label": t("support.messages") },
      messages.map((m) => h("li", { class: `support-msg ${m.author === "staff" ? "staff" : "me"}` },
        h("div", { class: "support-msg-head" },
          h("span", { class: "support-author", text: m.author === "staff" ? t("support.author_staff") : t("support.author_you") }),
          h("span", { class: "faint", text: m.created_at ? formatDateTime(m.created_at) : "" })),
        h("div", { class: "notes", text: m.body || "" }))));
    const reply = h("textarea", { class: "input", rows: "4", maxlength: String(BODY_MAX) });
    const message = h("div", { class: "col", role: "alert" });
    const sendReply = button(t("support.send_reply"), async () => {
      if (!reply.value.trim()) {
        mount(message, h("div", { class: "banner error", text: t("support.err_body") }));
        reply.focus();
        return;
      }
      sendReply.disabled = true;
      try {
        this.showThread(await invoke("support_reply", { reference: ticket.reference, body: reply.value }));
        toast(t("support.reply_sent"));
      } catch (e) {
        sendReply.disabled = false;
        mount(message, h("div", { class: "banner error", text: errorText(e) }));
      }
    }, "primary", "send");
    const closeTicket = closed ? null : button(t("support.close_ticket"), async () => {
      const ok = await confirmDialog({ title: t("support.close_title"), text: t("support.close_text"), confirm: t("support.close_ticket"), iconName: "check" });
      if (!ok) return;
      try {
        this.showThread(await invoke("support_close", { reference: ticket.reference }));
      } catch (e) {
        toast(errorText(e), "error");
      }
    }, "", "check");
    mount(this.m.box,
      this.header(ticket.subject || ticket.reference || t("support.title"), true),
      h("p", { class: "muted", text: meta }),
      ticket.diagnostics
        ? h("details", { class: "support-diag-sent" }, h("summary", { text: t("support.diagnostics_sent") }), h("pre", { class: "mono notes", text: String(ticket.diagnostics) }))
        : null,
      list,
      field(closed ? t("support.reply_reopens") : t("support.reply"), reply),
      message,
      this.actions(ticket.guest ? this.removeButton({ ...ticket, guest: true }) : null, closeTicket, sendReply));
    const last = list.lastElementChild;
    if (last) last.scrollIntoView({ block: "nearest" });
    reply.focus();
  }
}
