// "Connect to Passyble Server": the pairing link input (paste, or read a QR code), the connection
// check that shows what the link points at, and the dialog that connects the open vault.

import { errorText, h, icon, invoke, mount, t, toast } from "../lib.js";

export function linkField(initial, onChange) {
  const id = `link-${Math.random().toString(36).slice(2)}`;
  const area = h("textarea", {
    class: "input mono",
    id,
    rows: "3",
    spellcheck: "false",
    autocomplete: "off",
    placeholder: "pass+server://pass.example.com:8443/dav/you/personal.vault?v=1&user=…",
  });
  area.value = initial || "";
  const error = h("div", { class: "error-text", role: "alert" });
  const changed = () => onChange && onChange(area.value);
  // Pasted with surrounding text ("Link: <pass+server://…>"): keep just the link.
  area.addEventListener("paste", () => setTimeout(() => {
    const m = /pass\+server:\/\/[^\s<>"']+/i.exec(area.value);
    if (m && m[0] !== area.value.trim()) {
      area.value = m[0];
      changed();
    }
  }, 0));
  area.addEventListener("input", changed);
  const fromQr = async (cmd) => {
    error.textContent = "";
    try {
      const link = await invoke(cmd);
      if (!link) return;
      area.value = link;
      changed();
    } catch (e) {
      error.textContent = errorText(e);
    }
  };
  const el = h(
    "div",
    { class: "field" },
    h("label", { for: id, text: t("server.pairing_link") }),
    area,
    h("span", { class: "hint", text: t("server.pairing_hint") }),
    h(
      "div",
      { class: "row wrap" },
      h("button", { class: "btn", type: "button", on: { click: () => fromQr("server_qr_from_file") } }, icon("image"), t("server.qr_from_picture")),
      h("button", { class: "btn", type: "button", title: t("server.qr_from_clipboard_title"), on: { click: () => fromQr("server_qr_from_clipboard") } }, icon("qr"), t("server.qr_from_clipboard")),
    ),
    error,
  );
  return {
    el,
    value: () => area.value.trim(),
    set: (v) => { area.value = v || ""; },
    focus: () => area.focus(),
  };
}

export function serverInfo(info) {
  const row = (k, v, cls = "") => [h("div", { class: "k", text: k }), h("div", { class: `v ${cls}`, text: v })];
  const pin = (info.pins || [])[0] || "";
  return h(
    "div",
    { class: "col" },
    h(
      "div",
      { class: "server-info" },
      row(t("server.info_server"), info.host),
      row(t("server.info_account"), info.username),
      row(t("devices.this_device"), info.device_name || t("server.no_name")),
      row(
        t("server.info_certificate"),
        info.pinned
          ? t("server.cert_pinned", { pin: `${pin.slice(0, 19)}…` })
          : info.https
            ? t("server.cert_trusted")
            : t("server.cert_none"),
      ),
      row(
        t("server.info_vault"),
        info.error ? t("server.vault_unknown") : info.exists ? t("server.vault_found") : t("server.vault_none"),
      ),
    ),
    info.https ? null : h("div", { class: "banner warn", text: t("server.plain_http") }),
    info.error ? h("div", { class: "banner error", text: info.error }) : null,
  );
}

/**
 * Modal dialog for the unlocked vault. `options`: `link` (prefilled), `vaultName`, `onConnected()`,
 * and `onAddSeparate(link)` to add the server's vault to the list instead.
 */
export class ServerDialog {
  constructor(options) {
    this.options = options;
    this.info = null;
    this.link = linkField(options.link, () => this.reset());
    this.details = h("div", { class: "col" });
    this.error = h("div", { class: "error-text", role: "alert" });
    this.checkBtn = h("button", { class: "btn", type: "button", on: { click: () => this.check() } }, icon("sync"), t("server.check"));
    this.connectBtn = h("button", { class: "btn primary", type: "button", disabled: true, on: { click: () => this.connect() } }, t("server.connect"));
    this.separateBtn = h("button", {
      class: "btn", type: "button",
      title: t("server.add_separate_title"),
      on: { click: () => this.addSeparate() },
    }, t("server.add_separate"));
    this.dialog = h(
      "div",
      { class: "modal", role: "dialog", "aria-modal": "true", "aria-label": t("server.title") },
      h("h2", { text: t("server.title") }),
      h("p", { class: "muted", text: t("server.intro", { vault: options.vaultName || t("server.this_vault") }) }),
      this.link.el,
      this.details,
      this.error,
      h(
        "div",
        { class: "row" },
        this.separateBtn,
        h("span", { class: "spacer" }),
        h("button", { class: "btn", type: "button", text: t("common.cancel"), on: { click: () => this.close() } }),
        this.checkBtn,
        this.connectBtn,
      ),
    );
    this.backdrop = h("div", { class: "modal-backdrop" }, this.dialog);
    this.keys = (e) => {
      if (e.key === "Escape") {
        e.preventDefault();
        this.close();
      }
    };
    document.addEventListener("keydown", this.keys);
    document.body.append(this.backdrop);
    if (options.link) this.check();
    else this.link.focus();
  }

  reset() {
    this.info = null;
    this.connectBtn.disabled = true;
    mount(this.details);
    this.error.textContent = "";
  }

  async check() {
    this.reset();
    const label = this.checkBtn.lastChild.textContent;
    this.checkBtn.disabled = true;
    this.checkBtn.lastChild.textContent = t("server.checking");
    try {
      const info = await invoke("server_link_check", { link: this.link.value() });
      this.info = info;
      mount(
        this.details,
        serverInfo(info),
        info.error
          ? null
          : h("p", {
              class: "hint",
              text: info.exists
                ? t("server.exists_hint")
                : t("server.upload_hint"),
            }),
      );
      this.connectBtn.disabled = Boolean(info.error);
      if (!info.error) this.connectBtn.focus();
    } catch (e) {
      this.error.textContent = errorText(e);
    } finally {
      this.checkBtn.disabled = false;
      this.checkBtn.lastChild.textContent = label;
    }
  }

  async connect() {
    this.error.textContent = "";
    this.connectBtn.disabled = true;
    this.connectBtn.textContent = t("server.connecting");
    try {
      const r = await invoke("server_use_for_vault", { link: this.link.value() });
      if (r.different_vault) {
        mount(
          this.details,
          serverInfo(this.info),
          h("div", { class: "banner warn", text: t("server.different_vault") }),
        );
        this.separateBtn.classList.add("primary");
        return;
      }
      toast(r.created_remote ? t("server.connected_uploaded") : t("server.connected_synced"));
      this.close();
      if (this.options.onConnected) this.options.onConnected();
    } catch (e) {
      this.error.textContent = errorText(e);
    } finally {
      this.connectBtn.disabled = !this.info || Boolean(this.info.error);
      this.connectBtn.textContent = t("server.connect");
    }
  }

  addSeparate() {
    const link = this.link.value();
    this.close();
    if (this.options.onAddSeparate) this.options.onAddSeparate(link);
  }

  close() {
    document.removeEventListener("keydown", this.keys);
    this.backdrop.remove();
    if (current === this) current = null;
  }
}

let current = null;

export function openServerDialog(options) {
  if (current) current.close();
  current = new ServerDialog(options);
  return current;
}

export function closeServerDialog() {
  if (current) current.close();
}
