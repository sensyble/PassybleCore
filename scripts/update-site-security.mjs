#!/usr/bin/env node
// Refreshes the two offline site lists that Password health uses (core/src/sites.rs), so the app
// never asks the network which sites offer two-factor sign-in or passkeys (Node 20+, no
// dependencies):
//
//   node scripts/update-site-security.mjs              download, reduce, write both files
//   node scripts/update-site-security.mjs --from <dir> reduce local copies (all.json, supported.json)
//
// Sources (see THIRD_PARTY_NOTICES.md for the licences):
//   2FA Directory      https://api.2fa.directory/v4/all.json                 (MIT)
//   Passkeys Directory https://passkeys-api.2fa.directory/v1/supported.json  (CC BY 4.0)
//
// Output, one site per line, sorted by domain, tab-separated, "https://" left out of the links:
//   core/data/2fa-directory.tsv            domain  methods  documentation
//   core/data/passkeys-directory.tsv       domain  modes    documentation
// Methods (one letter each): t authenticator app (TOTP), s text message, c phone call, e email,
// u security key (FIDO U2F / WebAuthn), a the site's own app, h the site's own device.
// Modes: p sign in with a passkey instead of the password, m a passkey as the second step.
// Sites without two-factor sign-in (or without passkeys) are left out.
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const OUT = join(root, "core", "data");
const TFA_URL = "https://api.2fa.directory/v4/all.json";
const PASSKEYS_URL = "https://passkeys-api.2fa.directory/v1/supported.json";

const METHODS = {
  totp: "t",
  sms: "s",
  call: "c",
  email: "e",
  u2f: "u",
  "custom-software": "a",
  "custom-hardware": "h",
};
const ORDER = "tusceah";

async function load(url, file) {
  const from = process.argv.indexOf("--from");
  if (from > 0) return JSON.parse(readFileSync(join(process.argv[from + 1], file), "utf8"));
  const res = await fetch(url, { headers: { "User-Agent": "Passyble site list update" } });
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  return res.json();
}

/** A lower-case host name, or null for anything else. */
function domainOf(key) {
  const d = String(key).trim().toLowerCase().replace(/\.$/, "");
  return /^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(d) ? d : null;
}

/** A documentation link without "https://", ASCII only, no tabs or line breaks; "" if unusable. */
function linkOf(url) {
  if (typeof url !== "string") return "";
  let u;
  try {
    u = new URL(url.trim());
  } catch {
    return "";
  }
  if (u.protocol !== "https:" && u.protocol !== "http:") return "";
  const text = u.href; // percent-encodes anything outside ASCII
  if (/[^\x21-\x7e]/.test(text)) return "";
  return text.startsWith("https://") ? text.slice("https://".length) : text;
}

function write(file, header, rows) {
  rows.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  const body = rows.map((r) => r.join("\t")).join("\n");
  const text = header.map((l) => `# ${l}`.trimEnd()).join("\n") + "\n" + body + "\n";
  writeFileSync(join(OUT, file), text);
  console.log(`${file}: ${rows.length} sites, ${Buffer.byteLength(text)} bytes`);
}

const today = new Date().toISOString().slice(0, 10);
mkdirSync(OUT, { recursive: true });

const tfa = await load(TFA_URL, "all.json");
const tfaRows = [];
const seen = new Set();
for (const [key, entry] of Object.entries(tfa)) {
  const domain = domainOf(key);
  if (!domain || seen.has(domain) || !entry || !Array.isArray(entry.methods)) continue;
  const codes = new Set(entry.methods.map((m) => METHODS[m]).filter(Boolean));
  if (!codes.size) continue;
  seen.add(domain);
  tfaRows.push([domain, [...ORDER].filter((c) => codes.has(c)).join(""), linkOf(entry.documentation)]);
}
write("2fa-directory.tsv", [
  "Sites that offer two-factor sign-in, from the 2FA Directory (https://2fa.directory,",
  "https://github.com/2factorauth/twofactorauth). MIT License: Copyright (c) 2021 2factorauth and",
  "Contributors; Copyright (c) 2014-2020 Josh Davis. Full text in THIRD_PARTY_NOTICES.md.",
  `Reduced by scripts/update-site-security.mjs on ${today} from ${TFA_URL}.`,
  "domain<TAB>methods<TAB>documentation (\"https://\" left out). Methods: t authenticator app (TOTP),",
  "u security key, s text message, c phone call, e email, a the site's own app, h the site's own device.",
], tfaRows);

const passkeys = await load(PASSKEYS_URL, "supported.json");
const pkRows = [];
seen.clear();
for (const [key, entry] of Object.entries(passkeys)) {
  const domain = domainOf(key);
  if (!domain || seen.has(domain) || !entry) continue;
  const modes = (entry.passwordless ? "p" : "") + (entry.mfa ? "m" : "");
  if (!modes) continue;
  seen.add(domain);
  pkRows.push([domain, modes, linkOf(entry.documentation)]);
}
write("passkeys-directory.tsv", [
  "Sites that support passkeys, from the Passkeys Directory (https://passkeys.2fa.directory,",
  "https://github.com/2factorauth/passkeys) by 2factorauth and contributors, licensed under",
  "CC BY 4.0 (https://creativecommons.org/licenses/by/4.0/). Changed: reduced to the fields below.",
  `Reduced by scripts/update-site-security.mjs on ${today} from ${PASSKEYS_URL}.`,
  "domain<TAB>modes<TAB>documentation (\"https://\" left out). Modes: p sign in with a passkey",
  "instead of the password, m a passkey as the second step.",
], pkRows);
