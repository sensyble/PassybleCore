// node --test Core/desktop-app/ui/test/*.test.mjs (Node 22 or later)
// The pure part of the username / e-mail generator and its settings.
import assert from "node:assert/strict";
import test from "node:test";

import { aliasConfig, emailSources, generatorSummary, serviceState, siteOf } from "../views/generator-model.js";

const service = (id, name, extra = {}) => ({ id, name, configured: false, default: false, self_hostable: false, uses_domain: false, ...extra });

test("siteOf: the first web address of the URL list", () => {
  assert.equal(siteOf("https://accounts.github.com/login\nhttps://example.com"), "accounts.github.com");
  assert.equal(siteOf("windows:putty.exe\n  example.org/path "), "example.org");
  assert.equal(siteOf("androidapp://com.example"), "");
  assert.equal(siteOf("localhost"), "");
  assert.equal(siteOf(""), "");
  assert.equal(siteOf(null), "");
});

test("emailSources: what is set up, the default alias service first", () => {
  assert.deepEqual(emailSources(null), []);
  assert.deepEqual(emailSources({ address: "", domain: "", services: [] }), []);
  const sources = emailSources({
    address: "alex@example.com",
    domain: "mydomain.com",
    services: [
      service("simplelogin", "SimpleLogin", { configured: true }),
      service("addy_io", "addy.io"),
      service("duckduckgo", "DuckDuckGo", { configured: true, default: true }),
    ],
  });
  assert.deepEqual(sources.map((s) => s.value), ["plus", "catch_all", "alias:duckduckgo", "alias:simplelogin"]);
  assert.equal(sources[2].label, "DuckDuckGo alias");
  assert.equal(sources[2].service.id, "duckduckgo");
  assert.equal(sources[0].service, undefined);
});

test("settings: row values", () => {
  assert.equal(serviceState(service("fastmail", "Fastmail")), "Not set up");
  assert.equal(serviceState(service("fastmail", "Fastmail", { configured: true })), "Set up");
  assert.equal(serviceState(service("fastmail", "Fastmail", { configured: true, default: true })), "Set up, used by default");
  assert.equal(generatorSummary({ services: [service("fastmail", "Fastmail", { configured: true, default: true })] }), "Fastmail");
  assert.equal(generatorSummary({ address: "a@b.c", services: [] }), "Email generator");
  assert.equal(generatorSummary({ services: [] }), "Not set up");
});

test("aliasConfig: the saved token stays unless one is typed; fields only where used", () => {
  const addy = service("addy_io", "addy.io", { self_hostable: true, uses_domain: true });
  assert.deepEqual(aliasConfig(addy, { token: "  ", baseUrl: " https://addy.example.org ", domain: " me.anonaddy.com " }), {
    service: "addy_io",
    token: null,
    base_url: "https://addy.example.org",
    domain: "me.anonaddy.com",
  });
  const ddg = service("duckduckgo", "DuckDuckGo");
  assert.deepEqual(aliasConfig(ddg, { token: " tok ", baseUrl: "https://x", domain: "y.com" }), {
    service: "duckduckgo",
    token: "tok",
    base_url: "",
    domain: "",
  });
});
