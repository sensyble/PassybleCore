// node --test Core/desktop-app/ui/test/*.test.mjs (Node 22 or later)
// The UI text catalogs (ui/i18n/<locale>.json, en.json the source): every key the windows or Rust
// use is in en.json with the right shape and placeholders, and every other catalog matches it.
// Missing translations are reported, not failures (they fall back to English); so are unused keys.
import assert from "node:assert/strict";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const UI = fileURLToPath(new URL("..", import.meta.url));
const CATALOGS = join(UI, "i18n");
const RUST = join(UI, "..", "src-tauri", "src");
const CATEGORIES = new Set(["zero", "one", "two", "few", "many", "other"]);

const load = (file) => JSON.parse(readFileSync(join(CATALOGS, file), "utf8"));
const en = load("en.json");
// Mac-only Rust texts ("macos.*" keys) live in an overlay, checked when it sits beside this repo.
const MAC_EN = join(UI, "..", "..", "..", "macOS", "i18n", "en.json");
const macEn = existsSync(MAC_EN) ? JSON.parse(readFileSync(MAC_EN, "utf8")) : null;
// Same for the Linux-only texts ("linux.*" keys).
const LINUX_EN = join(UI, "..", "..", "..", "Linux", "i18n", "en.json");
const linuxEn = existsSync(LINUX_EN) ? JSON.parse(readFileSync(LINUX_EN, "utf8")) : null;

function files(dir, ext, skip = []) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (skip.includes(name)) continue;
    if (statSync(path).isDirectory()) out.push(...files(path, ext, skip));
    else if (ext.some((e) => name.endsWith(e))) out.push(path);
  }
  return out;
}

/** Source without comments (doc examples aren't uses). */
const code = (file) => readFileSync(file, "utf8").replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");

const isPlural = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const placeholders = (text) => new Set([...String(text).matchAll(/\{([A-Za-z0-9_]+)\}/g)].map((m) => m[1]));
/** The placeholders of an entry (all plural forms together; `{count}` of a plural is implied). */
function entryPlaceholders(value) {
  const set = new Set();
  for (const text of isPlural(value) ? Object.values(value) : [value]) for (const p of placeholders(text)) set.add(p);
  if (isPlural(value)) set.delete("count");
  return set;
}
const sorted = (set) => [...set].sort().join(", ");

function usedKeys() {
  const uses = [];
  const js = files(UI, [".js", ".mjs"], ["test", "i18n", "node_modules"]);
  for (const file of js) {
    const src = code(file);
    for (const m of src.matchAll(/\b(t|tn|tx)\(\s*(["'`])([^"'`$]+)\2\s*(,\s*([^{)]*?)?\{([^{}]*)\})?/g)) {
      const params = m[6] === undefined ? null : [...m[6].matchAll(/(?:^|,)\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?=[:,]|$)/g)].map((p) => p[1]);
      uses.push({ key: m[3], kind: { t: "text", tn: "plural", tx: "nodes" }[m[1]], params: m[1] === "tn" && m[5] === undefined ? null : params, file });
    }
  }
  for (const file of files(UI, [".html"], ["test"])) {
    const src = readFileSync(file, "utf8");
    for (const m of src.matchAll(/data-i18n="([^"]+)"/g)) uses.push({ key: m[1], kind: "text", params: [], file });
    for (const m of src.matchAll(/data-i18n-attr="([^"]+)"/g)) {
      for (const pair of m[1].split(";")) {
        const key = pair.split(":")[1];
        if (key && key.trim()) uses.push({ key: key.trim(), kind: "text", params: [], file });
      }
    }
  }
  for (const file of files(RUST, [".rs"])) {
    const src = code(file);
    for (const m of src.matchAll(/\b(tr|trn)!\(\s*"([^"]+)"/g)) {
      let depth = 1;
      let end = m.index + m[0].length;
      while (end < src.length && depth > 0) {
        const c = src[end++];
        if (c === "(" || c === "[" || c === "{") depth++;
        else if (c === ")" || c === "]" || c === "}") depth--;
      }
      // tr!("key", name = value, ...): the top-level names; trn! has a count first.
      let top = "";
      let level = 0;
      for (const c of src.slice(m.index + m[0].length, end - 1)) {
        if (c === "(" || c === "[" || c === "{") level++;
        else if (c === ")" || c === "]" || c === "}") level--;
        else if (level === 0) top += c;
      }
      const params = [...top.matchAll(/,\s*([a-z_][a-z0-9_]*)\s*=(?!=)/g)].map((p) => p[1]);
      uses.push({ key: m[2], kind: m[1] === "trn" ? "plural" : "text", params, file, rust: true });
    }
  }
  return uses;
}

test("en.json: _meta and well-formed entries", () => {
  assert.equal(typeof en._meta, "object", "_meta");
  assert.equal(typeof en._meta.name, "string", "_meta.name (English name)");
  assert.equal(typeof en._meta.native, "string", "_meta.native (name in the language)");
  for (const [key, value] of Object.entries(en)) {
    if (key === "_meta") continue;
    assert.match(key, /^[a-z0-9_]+(\.[a-z0-9_]+)+$/, `${key}: keys are dotted lower-case words`);
    if (isPlural(value)) {
      assert.equal(typeof value.other, "string", `${key}: a plural needs "other"`);
      assert.equal(typeof value.one, "string", `${key}: English plurals have "one"`);
      for (const [category, text] of Object.entries(value)) {
        assert.ok(CATEGORIES.has(category), `${key}: unknown plural category "${category}"`);
        assert.equal(typeof text, "string", `${key}.${category}`);
      }
    } else {
      assert.equal(typeof value, "string", `${key}: a text or a plural object`);
      assert.ok(value.length > 0, `${key}: empty`);
    }
  }
});

test("every key used in the code is in en.json, with its placeholders", () => {
  const problems = [];
  for (const use of usedKeys()) {
    const where = `${use.key} (${use.file.slice(UI.length - 3)})`;
    const mac = use.rust && use.key.startsWith("macos.");
    if (mac && !macEn) continue;
    const linux = use.rust && use.key.startsWith("linux.");
    if (linux && !linuxEn) continue;
    const value = mac ? macEn[use.key] : linux ? linuxEn[use.key] : en[use.key];
    if (value === undefined) {
      problems.push(`missing: ${where}`);
      continue;
    }
    if (use.kind === "plural" && !isPlural(value)) problems.push(`not a plural (tn/trn): ${where}`);
    if (use.kind !== "plural" && isPlural(value)) problems.push(`a plural used as text (use tn/trn): ${where}`);
    if (use.params) {
      const wanted = entryPlaceholders(value);
      const given = new Set(use.params);
      const missing = [...wanted].filter((p) => !given.has(p));
      if (missing.length) problems.push(`${where}: placeholders not filled: ${missing.join(", ")}`);
      // Rust fills only what it is given: an extra name is a typo.
      const extra = use.rust ? [...given].filter((p) => !wanted.has(p)) : [];
      if (extra.length) problems.push(`${where}: no such placeholder: ${extra.join(", ")}`);
    }
  }
  assert.deepEqual(problems, []);
});

test("unused keys (reported only)", () => {
  const sources = [
    ...files(UI, [".js", ".mjs", ".html"], ["test", "i18n", "node_modules"]),
    ...files(RUST, [".rs"]),
  ].map((f) => readFileSync(f, "utf8")).join("\n");
  const unused = Object.keys(en).filter((k) => k !== "_meta" && !sources.includes(`"${k}"`));
  if (unused.length) console.log(`i18n: ${unused.length} keys in en.json aren't used:\n  ${unused.join("\n  ")}`);
  assert.ok(true);
});

test("other catalogs match en.json", () => {
  const locales = readdirSync(CATALOGS).filter((f) => f.endsWith(".json") && f !== "en.json");
  const problems = [];
  for (const file of locales) {
    const code = file.slice(0, -5);
    let canonical = null;
    try {
      [canonical] = Intl.getCanonicalLocales(code);
    } catch {
      problems.push(`${file}: "${code}" isn't a language tag`);
      continue;
    }
    if (canonical !== code) problems.push(`${file}: name it ${canonical}.json`);
    let catalog;
    try {
      catalog = load(file);
    } catch (e) {
      problems.push(`${file}: not valid JSON (${e.message})`);
      continue;
    }
    if (!catalog._meta || typeof catalog._meta.name !== "string" || typeof catalog._meta.native !== "string") {
      problems.push(`${file}: _meta needs "name" (in English) and "native"`);
    }
    const needed = new Set(new Intl.PluralRules(code).resolvedOptions().pluralCategories);
    const missing = [];
    const thin = [];
    for (const key of Object.keys(en)) {
      if (key !== "_meta" && !(key in catalog)) missing.push(key);
    }
    for (const [key, value] of Object.entries(catalog)) {
      if (key === "_meta") continue;
      const source = en[key];
      if (source === undefined) {
        problems.push(`${file}: ${key} isn't in en.json (renamed or removed?)`);
        continue;
      }
      if (isPlural(source) !== isPlural(value)) {
        problems.push(`${file}: ${key} must be ${isPlural(source) ? "a plural object" : "a text"} as in en.json`);
        continue;
      }
      if (isPlural(value)) {
        if (typeof value.other !== "string") problems.push(`${file}: ${key} needs "other"`);
        for (const [category, text] of Object.entries(value)) {
          if (!CATEGORIES.has(category)) problems.push(`${file}: ${key}: unknown plural category "${category}"`);
          else if (typeof text !== "string") problems.push(`${file}: ${key}.${category} isn't a text`);
        }
        const lacking = [...needed].filter((c) => c !== "other" && !(c in value));
        if (lacking.length) thin.push(`${key} (${lacking.join(", ")}: "other" is used)`);
      } else if (typeof value !== "string") {
        problems.push(`${file}: ${key} isn't a text`);
        continue;
      }
      const want = entryPlaceholders(source);
      const have = entryPlaceholders(value);
      if (sorted(want) !== sorted(have)) problems.push(`${file}: ${key}: placeholders {${sorted(have)}} but en.json has {${sorted(want)}}`);
    }
    if (missing.length) console.log(`i18n: ${file} lacks ${missing.length} of ${Object.keys(en).length - 1} texts (English is shown):\n  ${missing.join("\n  ")}`);
    if (thin.length) console.log(`i18n: ${file}: plurals without every form ${code} uses:\n  ${thin.join("\n  ")}`);
  }
  assert.deepEqual(problems, []);
});

test("the runtime: fallback, placeholders, plurals", async () => {
  const i18n = await import("../i18n.js");
  i18n.setCatalog("fr", { "a.b": "Bonjour {name}", "p.q": { one: "{count} élément", other: "{count} éléments" } }, {
    "a.b": "Hello {name}",
    "a.c": "Only English",
    "p.q": { one: "{count} item", other: "{count} items" },
  });
  assert.equal(i18n.t("a.b", { name: "Ada" }), "Bonjour Ada");
  assert.equal(i18n.t("a.c"), "Only English");
  assert.equal(i18n.t("no.such.key"), "no.such.key");
  assert.equal(i18n.tn("p.q", 0), "0 élément"); // French: 0 is singular
  assert.equal(i18n.tn("p.q", 2), "2 éléments");
  // "many" (French millions) falls back to "other"; the number uses French grouping.
  assert.equal(i18n.tn("p.q", 1000000).replace(/\s/g, " "), "1 000 000 éléments");
  assert.deepEqual(i18n.tx("a.b", { name: { node: true } }), ["Bonjour ", { node: true }]);
  i18n.setCatalog("en", en, en);
  assert.equal(i18n.tn("trash.purge_in_days", 1), "Removed for good in 1 day");
  assert.equal(i18n.tn("trash.purge_in_days", 1234), "Removed for good in 1,234 days");
});
