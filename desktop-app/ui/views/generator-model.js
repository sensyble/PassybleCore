// The pure part of the username / e-mail generator (views/generator.js) and of Settings →
// Username and e-mail generator (views/aliases.js), tested by test/generator-model.test.mjs.

import { t } from "../i18n.js";

/** The host of the first web address in the editor's URL list, "" if none (`windows:app.exe` and the like). */
export function siteOf(urls) {
  for (const line of String(urls || "").split(/\r?\n/)) {
    const u = line.trim();
    if (!u) continue;
    if (/^[a-z][a-z0-9+.-]*:/i.test(u) && !/^https?:/i.test(u)) continue;
    try {
      const host = new URL(/^https?:/i.test(u) ? u : `https://${u}`).hostname;
      if (host.includes(".")) return host;
    } catch {
    }
  }
  return "";
}

/** The e-mail sources the generator offers, from `generator_settings`, the default first. */
export function emailSources(settings) {
  const sources = [];
  if (settings && settings.address) sources.push({ value: "plus", label: t("generator.email_plus") });
  if (settings && settings.domain) sources.push({ value: "catch_all", label: t("generator.email_catch_all") });
  const services = ((settings && settings.services) || []).filter((s) => s.configured);
  services.sort((a, b) => Number(b.default) - Number(a.default));
  for (const s of services) sources.push({ value: `alias:${s.id}`, label: t("generator.email_alias", { service: s.name }), service: s });
  return sources;
}

export function serviceState(service) {
  if (!service.configured) return t("settings.alias_not_set_up");
  return service.default ? t("settings.alias_default_value") : t("settings.alias_set_up_value");
}

export function generatorSummary(settings) {
  const def = ((settings && settings.services) || []).find((s) => s.configured && s.default);
  if (def) return def.name;
  if (settings && (settings.address || settings.domain)) return t("settings.generator_email_only");
  return t("settings.alias_not_set_up");
}

/** What the alias dialog sends: the token only when one was typed (`null` keeps the saved one), server and domain only where the service uses them. */
export function aliasConfig(service, { token = "", baseUrl = "", domain = "" } = {}) {
  return {
    service: service.id,
    token: token.trim() ? token.trim() : null,
    base_url: service.self_hostable ? baseUrl.trim() : "",
    domain: service.uses_domain ? domain.trim() : "",
  };
}
