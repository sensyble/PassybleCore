// Settings → This vault → Username and e-mail generator (generator.rs): the user's own address (plus
// addressing), catch-all domain and e-mail alias services. Kept encrypted in the vault and applied at
// once. The window never gets a saved token back, only whether there is one.

import { errorText, h, icon, infoTip, invoke, isLockedError, modal, mount, passwordField, settingsGroup, settingsRow, t, toast } from "../lib.js";
import { aliasConfig, generatorSummary, serviceState } from "./generator-model.js";

const HELP = {
  simplelogin: () => t("settings.alias_help_simplelogin"),
  addy_io: () => t("settings.alias_help_addy_io"),
  firefox_relay: () => t("settings.alias_help_firefox_relay"),
  duckduckgo: () => t("settings.alias_help_duckduckgo"),
  fastmail: () => t("settings.alias_help_fastmail"),
  forwardemail: () => t("settings.alias_help_forwardemail"),
};

let uid = 0;
function field(label, input, hint) {
  const id = `al-${++uid}`;
  (input.input || input).id = id;
  return h("div", { class: "field" }, h("label", { for: id, text: label }), input.el || input, hint ? h("span", { class: "hint", text: hint }) : null);
}

/** A row's button: text only, as in Settings (`iconName` is not drawn). */
function rowButton(iconName, label, onClick, cls = "") {
  return h("button", { class: `btn small ${cls}`.trim(), type: "button", on: { click: onClick } }, label);
}

export class GeneratorSettings {
  constructor({ onChanged = null, onClose = null } = {}) {
    this.onChanged = onChanged;
    this.onClose = onClose;
    this.el = h("div", { class: "col" });
  }

  async load() {
    mount(this.el, h("div", { class: "hint", text: t("common.working") }));
    try {
      this.s = await invoke("generator_settings");
    } catch (e) {
      mount(this.el, h("div", { class: "banner", text: isLockedError(e) ? t("settings.generator_locked") : errorText(e) }));
      return;
    }
    this.render();
    if (this.onChanged) this.onChanged(generatorSummary(this.s));
  }

  render() {
    const s = this.s;
    const address = h("input", { class: "input", type: "email", value: s.address, spellcheck: "false", autocomplete: "off", placeholder: "alex@example.com", "aria-label": t("settings.generator_address") });
    const domain = h("input", { class: "input", value: s.domain, spellcheck: "false", autocomplete: "off", placeholder: "mydomain.com", "aria-label": t("settings.generator_domain") });
    const error = h("div", { class: "error-text", role: "alert" });
    // Save addresses: disabled until an address changed (Settings' footer: Close, then Save).
    const save = h("button", {
      class: "btn primary",
      type: "button",
      disabled: true,
      on: {
        click: async () => {
          error.textContent = "";
          save.disabled = true;
          try {
            await invoke("set_email_generator", { address: address.value, domain: domain.value });
            toast(t("settings.generator_saved"));
            await this.load();
          } catch (e) {
            error.textContent = errorText(e);
          } finally {
            save.disabled = false;
          }
        },
      },
    }, t("settings.generator_save_addresses"));

    const emailGroup = settingsGroup(t("settings.generator_email"), [
      settingsRow("mail", t("settings.generator_address"), { control: address, info: t("settings.generator_address_info") }),
      settingsRow("globe", t("settings.generator_domain"), { control: domain, info: t("settings.generator_domain_info") }),
    ], { sub: t("settings.generator_email_sub") });

    const rows = s.services.map((service) => settingsRow("mail", service.name, {
      value: serviceState(service),
      valueClass: service.configured ? "ok" : "",
      control: [
        service.configured && !service.default
          ? rowButton(null, t("settings.alias_make_default"), () => this.run(() => invoke("set_default_alias_service", { serviceId: service.id })))
          : null,
        rowButton(service.configured ? "edit" : "plus", service.configured ? t("settings.alias_edit") : t("settings.alias_set_up"), () => this.openService(service)),
      ],
    }));
    const aliasGroup = settingsGroup(t("settings.alias_services"), rows, { info: t("settings.alias_services_info"), sub: t("settings.alias_privacy") });

    // Save addresses sits at the foot of the page like Settings' own Save bar.
    for (const input of [address, domain]) input.addEventListener("input", () => { save.disabled = false; });
    mount(this.el, emailGroup, aliasGroup, h("div", { class: "row sticky-actions gen-save" }, error, h("span", { class: "spacer" }),
      this.onClose ? h("button", { class: "btn", type: "button", text: t("common.close"), on: { click: () => this.onClose() } }) : null,
      save));
  }

  async run(change) {
    try {
      await change();
      await this.load();
    } catch (e) {
      toast(errorText(e), "error");
    }
  }

  openService(service) {
    const m = modal({ label: service.name, cls: "narrow" });
    const token = passwordField({ autocomplete: "off", placeholder: service.configured ? t("settings.alias_token_saved") : "" });
    const server = h("input", { class: "input", value: service.base_url, spellcheck: "false", autocomplete: "off", placeholder: service.default_base_url });
    const domain = h("input", { class: "input", value: service.domain, spellcheck: "false", autocomplete: "off", placeholder: service.id === "addy_io" ? "anonaddy.me" : "mydomain.com" });
    const status = h("div", { class: "hint", role: "status" });
    const error = h("div", { class: "error-text", role: "alert" });
    const config = () => aliasConfig(service, { token: token.input.value, baseUrl: server.value, domain: domain.value });
    const busy = async (button, work) => {
      error.textContent = "";
      status.textContent = "";
      button.disabled = true;
      try {
        await work();
      } catch (e) {
        error.textContent = errorText(e);
      } finally {
        button.disabled = false;
      }
    };
    const test = h("button", {
      class: "btn",
      type: "button",
      on: {
        click: () => busy(test, async () => {
          status.textContent = t("settings.alias_testing", { service: service.name });
          const r = await invoke("test_alias_service", { config: config() });
          status.textContent = r && r.address
            ? t("settings.alias_test_made", { service: service.name, address: r.address })
            : t("settings.alias_test_ok", { service: service.name });
        }),
      },
    }, t("settings.alias_test"));
    const remove = service.configured
      ? h("button", {
          class: "btn danger",
          type: "button",
          on: {
            click: () => busy(remove, async () => {
              await invoke("remove_alias_service", { serviceId: service.id });
              m.close();
              await this.load();
            }),
          },
        }, icon("trash"), t("settings.alias_remove"))
      : null;
    const save = h("button", {
      class: "btn primary",
      type: "submit",
      text: t("settings.alias_save"),
    });
    const form = h("form", {
      class: "col",
      on: {
        submit: (e) => {
          e.preventDefault();
          busy(save, async () => {
            await invoke("set_alias_service", { config: config() });
            m.close();
            toast(t("settings.alias_saved", { service: service.name }));
            await this.load();
          });
        },
      },
    },
    h("p", { class: "muted", text: (HELP[service.id] || (() => ""))() }),
    field(t("settings.alias_token"), token),
    service.self_hostable ? field(t("settings.alias_server"), server, t("settings.alias_server_hint")) : null,
    service.uses_domain
      ? field(service.id === "addy_io" ? t("settings.alias_domain_addy") : t("settings.alias_domain_own"), domain,
        service.id === "addy_io" ? t("settings.alias_domain_addy_hint") : null)
      : null,
    status,
    error,
    h("div", { class: "row modal-actions" }, remove, test, h("span", { class: "spacer" }),
      h("button", { class: "btn", type: "button", text: t("common.cancel"), on: { click: () => m.close() } }),
      save));
    mount(m.box,
      h("div", { class: "row" }, h("span", { class: "modal-icon" }, icon("mail")), h("h2", { class: "grow", text: service.name }), infoTip(t("settings.alias_services_info"), service.name)),
      form);
    token.focus();
  }
}
