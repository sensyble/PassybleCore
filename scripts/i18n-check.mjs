#!/usr/bin/env node
// Checks the translations of all four apps and of pass-core (the messages the Windows and Android
// apps get from the shared core) without building anything (Node 20+, no dependencies).
// Guide for translators: docs/TRANSLATING.md.
//
//   node scripts/i18n-check.mjs                 every app, every language
//   node scripts/i18n-check.mjs --lang de       one language (zh-CN, zh_CN, zh-rCN, id and in all work)
//   node scripts/i18n-check.mjs --app android   one app: windows, extension, android, server, core (comma list ok)
//   node scripts/i18n-check.mjs --strict        warnings (missing texts included) count as errors
//   node scripts/i18n-check.mjs --json          machine-readable output
//   node scripts/i18n-check.mjs --verbose       list every missing key even without --lang
//   node scripts/i18n-check.mjs --root <dir>    check another tree (the tests use fixtures)
//
// Errors (exit code 1) are things that break or mislead: unknown keys, wrong placeholders, invalid
// plural forms, empty texts, bad escaping, broken files. Warnings are things the apps survive:
// missing texts (English is shown instead), plural forms a language uses but a translation lacks
// (the "other" form is shown), and a few style hints. Exit code 2: bad command line.
//
// It mirrors the per-app tests (Core/desktop-app/ui/test/i18n.test.mjs, Extension/test/i18n.test.js,
// android .../UiStringsTest.kt and ServicesStringsTest.kt, Server/src/i18n.rs tests,
// Core/core/src/i18n_tests.rs) so problems show up before a build.
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export const APPS = ["windows", "extension", "android", "server", "core"];
const APP_ALIASES = {
  windows: "windows",
  desktop: "windows",
  win: "windows",
  extension: "extension",
  ext: "extension",
  browser: "extension",
  android: "android",
  server: "server",
  core: "core",
  "pass-core": "core",
};
const PATHS = {
  windows: "Core/desktop-app/ui/i18n",
  extension: "Extension/_locales",
  android: "Android/app/src/main/res",
  server: "Server/locales",
  // pass-core's messages, shown by the Windows and Android apps; same format as the Windows app's.
  core: "Core/core/locales",
};
const CATEGORIES = ["zero", "one", "two", "few", "many", "other"];
// The folder that holds the sibling repositories (Core, Extension, Android, Server, ...), the parent of
// this script's repository. Apps whose repository is not cloned there are skipped.
const DEFAULT_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

/** One tag for every spelling of a language: `zh_CN`, `zh-rCN`, `values-zh-rCN`, `b+zh+CN` → `zh-CN`; `in` → `id`. */
export function normalizeTag(input) {
  let tag = String(input).trim().replace(/^values-/, "");
  if (tag.startsWith("b+")) tag = tag.slice(2).replace(/\+/g, "-");
  tag = tag.replace(/_/g, "-").replace(/-r([A-Za-z]{2})$/, "-$1");
  if (/^in(-|$)/i.test(tag)) tag = "id" + tag.slice(2);
  try {
    return Intl.getCanonicalLocales(tag)[0];
  } catch {
    return tag;
  }
}

/** Android resource qualifier → BCP 47 (`zh-rCN` → `zh-CN`, `b+sr+Latn` → `sr-Latn`, `in` stays `in`). */
export function qualifierToTag(q) {
  return q.startsWith("b+") ? q.slice(2).replace(/\+/g, "-") : q.replace("-r", "-");
}

/** The CLDR categories a language has, e.g. `de` → one, other. */
export function pluralCategories(tag) {
  try {
    return new Intl.PluralRules(normalizeTag(tag)).resolvedOptions().pluralCategories;
  } catch {
    return ["other"];
  }
}

/** The categories a translation must give: the ones the language picks for 0…1000 (French "many" is for millions). */
export function neededCategories(tag) {
  const out = new Set();
  let rules;
  try {
    rules = new Intl.PluralRules(normalizeTag(tag));
  } catch {
    return ["other"];
  }
  for (let n = 0; n <= 1000; n++) out.add(rules.select(n));
  return CATEGORIES.filter((c) => out.has(c));
}

/** Passyble Server's own rule (Server/src/i18n.rs `plural_category`): one and other, or only other. */
export function serverCategories(tag) {
  const base = tag.toLowerCase().split(/[-_]/)[0];
  return ["zh", "ja", "ko", "id", "ms", "th", "vi", "lo", "km", "my", "yue"].includes(base) ? ["other"] : ["one", "other"];
}

class Report {
  constructor(root) {
    this.root = root;
    this.errors = [];
    this.warnings = [];
    this.coverage = [];
  }
  rel(file) {
    return file ? relative(this.root, file).split("\\").join("/") : "";
  }
  error(app, lang, file, message) {
    this.errors.push({ app, lang, file: this.rel(file), message });
  }
  /** `kind`: "missing" (a text or form English has), or "hint". */
  warn(app, lang, file, message, kind = "hint", keys = undefined) {
    this.warnings.push({ app, lang, file: this.rel(file), kind, message, ...(keys ? { keys } : {}) });
  }
  cover(app, lang, translated, total) {
    this.coverage.push({ app, lang, translated, total, missing: total - translated });
  }
}

const sortedList = (set) => [...set].sort().join(", ") || "none";
const sameSet = (a, b) => a.size === b.size && [...a].every((x) => b.has(x));
const isDir = (p) => existsSync(p) && statSync(p).isDirectory();
const isFile = (p) => existsSync(p) && statSync(p).isFile();
const readText = (p) => readFileSync(p, "utf8").replace(/^\uFEFF/, "");

function readJson(rep, app, lang, file) {
  try {
    return JSON.parse(readText(file));
  } catch (e) {
    rep.error(app, lang, file, `not valid JSON: ${e.message}`);
    return null;
  }
}

const isPlural = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const curlyPlaceholders = (text) => new Set([...String(text).matchAll(/\{([A-Za-z0-9_]+)\}/g)].map((m) => m[1]));
/** All placeholders of an entry (every plural form together); `{count}` of a plural is implied. */
function windowsPlaceholders(value) {
  const set = new Set();
  for (const text of isPlural(value) ? Object.values(value) : [value]) for (const p of curlyPlaceholders(text)) set.add(p);
  if (isPlural(value)) set.delete("count");
  return set;
}

const checkWindows = (root, rep, opts) => checkFlatJson("windows", root, rep, opts);
const checkCore = (root, rep, opts) => checkFlatJson("core", root, rep, opts);

/** The Windows app's catalog format (flat JSON, `{name}` placeholders, plural objects), also pass-core's. */
function checkFlatJson(app, root, rep, opts) {
  const dir = join(root, PATHS[app]);
  const enFile = join(dir, "en.json");
  if (!isFile(enFile)) return false;
  const en = readJson(rep, app, "en", enFile);
  if (!en) return true;
  // The source itself.
  if (!isPlural(en._meta) || typeof en._meta.name !== "string" || typeof en._meta.native !== "string") {
    rep.error(app, "en", enFile, `_meta needs "name" and "native"`);
  }
  for (const [key, value] of Object.entries(en)) {
    if (key === "_meta") continue;
    if (isPlural(value)) {
      if (typeof value.other !== "string") rep.error(app, "en", enFile, `${key}: a plural needs "other"`);
      for (const [c, text] of Object.entries(value)) {
        if (!CATEGORIES.includes(c)) rep.error(app, "en", enFile, `${key}: unknown plural category "${c}"`);
        else if (typeof text !== "string" || !text.trim()) rep.error(app, "en", enFile, `${key}.${c}: empty`);
      }
    } else if (typeof value !== "string" || !value.trim()) {
      rep.error(app, "en", enFile, `${key}: empty (or not a text)`);
    }
  }
  const keys = Object.keys(en).filter((k) => k !== "_meta");
  for (const name of readdirSync(dir).sort()) {
    if (!name.endsWith(".json") || name === "en.json") continue;
    const file = join(dir, name);
    const code = name.slice(0, -5);
    const lang = normalizeTag(code);
    if (!opts.wantLang(lang)) continue;
    let canonical = null;
    try {
      [canonical] = Intl.getCanonicalLocales(code);
    } catch {
      rep.error(app, lang, file, `"${code}" isn't a language tag`);
      continue;
    }
    if (canonical !== code) rep.error(app, lang, file, `name it ${canonical}.json`);
    const cat = readJson(rep, app, lang, file);
    if (!cat) continue;
    if (!isPlural(cat)) {
      rep.error(app, lang, file, "the file must be a JSON object");
      continue;
    }
    if (!isPlural(cat._meta) || typeof cat._meta.name !== "string" || !cat._meta.name.trim() || typeof cat._meta.native !== "string" || !cat._meta.native.trim()) {
      rep.error(app, lang, file, `_meta needs "name" (in English) and "native" (in the language), e.g. {"name": "German", "native": "Deutsch"}`);
    }
    const valid = pluralCategories(code);
    const needed = neededCategories(code);
    const thin = [];
    for (const [key, value] of Object.entries(cat)) {
      if (key === "_meta") continue;
      const source = en[key];
      if (source === undefined) {
        rep.error(app, lang, file, `${key}: not in en.json (renamed or removed? delete it)`);
        continue;
      }
      if (isPlural(source) !== isPlural(value)) {
        rep.error(app, lang, file, `${key}: must be ${isPlural(source) ? "a plural object" : "a text"} as in en.json`);
        continue;
      }
      if (isPlural(value)) {
        if (typeof value.other !== "string") rep.error(app, lang, file, `${key}: a plural needs "other"`);
        for (const [c, text] of Object.entries(value)) {
          if (!valid.includes(c)) rep.error(app, lang, file, `${key}: "${c}" is not a plural category of ${code} (${valid.join(", ")})`);
          else if (typeof text !== "string") rep.error(app, lang, file, `${key}.${c}: not a text`);
          else if (!text.trim()) rep.error(app, lang, file, `${key}.${c}: empty`);
        }
        const lacking = needed.filter((c) => c !== "other" && !(c in value));
        if (lacking.length) thin.push(`${key} (${lacking.join(", ")})`);
      } else if (typeof value !== "string") {
        rep.error(app, lang, file, `${key}: not a text`);
        continue;
      } else if (!value.trim()) {
        rep.error(app, lang, file, `${key}: empty (leave the key out to show English)`);
        continue;
      }
      const want = windowsPlaceholders(source);
      const have = windowsPlaceholders(value);
      if (!sameSet(want, have)) rep.error(app, lang, file, `${key}: placeholders {${sortedList(have)}}, en.json has {${sortedList(want)}}`);
    }
    if (thin.length) rep.warn(app, lang, file, `plurals without every form ${code} uses ("other" is shown)`, "missing", thin);
    const missing = keys.filter((k) => !(k in cat));
    if (missing.length) rep.warn(app, lang, file, `${missing.length} of ${keys.length} texts missing (English is shown)`, "missing", missing);
    rep.cover(app, lang, keys.length - missing.length, keys.length);
  }
  return true;
}

const EXT_PLURAL_RE = new RegExp(`^(.+)_(${CATEGORIES.join("|")})$`);
const EXT_REF_RE = /\$([A-Za-z0-9_@]+)\$/g;
const extPluralBase = (key) => EXT_PLURAL_RE.exec(key)?.[1] ?? null;
const extRefs = (message) => new Set([...String(message).matchAll(EXT_REF_RE)].map((m) => m[1].toLowerCase()));
const extPlaceholders = (entry) =>
  Object.entries(entry?.placeholders || {}).map(([n, p]) => `${n.toLowerCase()}=${p?.content}`).sort().join(", ") || "none";

function checkExtension(root, rep, opts) {
  const dir = join(root, PATHS.extension);
  const enFile = join(dir, "en", "messages.json");
  if (!isFile(enFile)) return false;
  const en = readJson(rep, "extension", "en", enFile);
  if (!en) return true;
  for (const [key, entry] of Object.entries(en)) {
    if (typeof entry?.message !== "string" || !entry.message.trim()) {
      rep.error("extension", "en", enFile, `${key}: empty message`);
      continue;
    }
    const defined = new Set(Object.keys(entry.placeholders || {}).map((n) => n.toLowerCase()));
    if (!sameSet(extRefs(entry.message), defined)) rep.error("extension", "en", enFile, `${key}: $NAME$ references and "placeholders" differ`);
  }
  const plainKeys = Object.keys(en).filter((k) => !extPluralBase(k));
  const bases = [...new Set(Object.keys(en).map(extPluralBase).filter(Boolean))];
  const total = plainKeys.length + bases.length;
  for (const folder of readdirSync(dir).sort()) {
    if (folder === "en" || !isDir(join(dir, folder))) continue;
    const tag = folder.replace("_", "-");
    const lang = normalizeTag(tag);
    if (!opts.wantLang(lang)) continue;
    const file = join(dir, folder, "messages.json");
    if (!/^[a-z]{2,3}(?:_[A-Z]{2})?$/.test(folder)) rep.error("extension", lang, join(dir, folder), `"${folder}" isn't a browser locale folder (de, zh_CN, pt_BR, ...)`);
    if (!isFile(file)) {
      rep.error("extension", lang, join(dir, folder), "no messages.json in this folder");
      continue;
    }
    const cat = readJson(rep, "extension", lang, file);
    if (!cat) continue;
    if (!isPlural(cat)) {
      rep.error("extension", lang, file, "the file must be a JSON object");
      continue;
    }
    const cl = cat.catalogLocale?.message;
    if (cl !== tag) rep.error("extension", lang, file, `catalogLocale must be "${tag}" (the folder name with "-"), is ${cl === undefined ? "missing" : `"${cl}"`}`);
    const seen = new Map();
    for (const key of Object.keys(cat)) {
      if (!/^[A-Za-z0-9_]+$/.test(key)) rep.error("extension", lang, file, `${key}: names may only use A-Z, a-z, 0-9 and _`);
      if (seen.has(key.toLowerCase())) rep.error("extension", lang, file, `${key} and ${seen.get(key.toLowerCase())} differ only in case`);
      seen.set(key.toLowerCase(), key);
    }
    for (const [key, entry] of Object.entries(cat)) {
      const base = extPluralBase(key);
      const ref = en[key] ?? (base && bases.includes(base) ? en[`${base}_other`] : null);
      if (!ref) {
        rep.error("extension", lang, file, `${key}: not an English message (renamed or removed? delete it)`);
        continue;
      }
      if (typeof entry?.message !== "string" || !entry.message.trim()) {
        rep.error("extension", lang, file, `${key}: empty message (leave the key out to show English)`);
        continue;
      }
      if (extPlaceholders(entry) !== extPlaceholders(ref)) {
        rep.error("extension", lang, file, `${key}: "placeholders" must be as in English (${extPlaceholders(ref)}), has ${extPlaceholders(entry)}`);
      }
      const refs = extRefs(entry.message);
      const defined = Object.keys(entry.placeholders || {}).map((n) => n.toLowerCase());
      for (const n of defined) if (!refs.has(n)) rep.error("extension", lang, file, `${key}: the message must use $${n.toUpperCase()}$`);
      for (const n of refs) if (!defined.includes(n)) rep.error("extension", lang, file, `${key}: $${n.toUpperCase()}$ is not defined in "placeholders"`);
    }
    const valid = pluralCategories(tag);
    const needed = neededCategories(tag);
    let translated = plainKeys.filter((k) => k in cat).length;
    const missing = plainKeys.filter((k) => !(k in cat));
    for (const base of bases) {
      const present = CATEGORIES.filter((c) => `${base}_${c}` in cat);
      if (!present.length) {
        missing.push(`${base}_*`);
        continue;
      }
      translated++;
      if (!present.includes("other")) rep.error("extension", lang, file, `${base}_other is required`);
      for (const c of present) if (!valid.includes(c)) rep.error("extension", lang, file, `${base}_${c}: "${c}" is not a plural category of ${tag} (${valid.join(", ")})`);
      for (const c of needed) if (!present.includes(c)) rep.error("extension", lang, file, `${base}_${c} is missing (${tag} uses ${needed.join(", ")})`);
    }
    for (const [key, max] of [["extName", 75], ["extDescription", 132], ["actionTitle", 75]]) {
      const text = cat[key]?.message;
      if (typeof text === "string" && [...text].length > max) rep.error("extension", lang, file, `${key}: ${[...text].length} characters, the stores allow ${max}`);
    }
    if (missing.length) rep.warn("extension", lang, file, `${missing.length} of ${total} messages missing (English is shown)`, "missing", missing);
    rep.cover("extension", lang, translated, total);
  }
  return true;
}

const XML_ENTITIES = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'" };

/**
 * Parses an XML document into `{ type: "element", name, attrs, children, line }` nodes (children:
 * elements, `{ type: "text", value }`, `{ type: "comment", value }`, `{ type: "cdata", value }`).
 * Handles the prolog, comments, CDATA, processing instructions, attributes and entities; no DTDs.
 * Throws an Error with a line number on malformed input.
 */
export function parseXml(text) {
  let i = 0;
  let seenPos = 0;
  let seenLine = 1;
  const lineAt = (pos) => {
    if (pos < seenPos) {
      seenPos = 0;
      seenLine = 1;
    }
    for (; seenPos < pos && seenPos < text.length; seenPos++) if (text.charCodeAt(seenPos) === 10) seenLine++;
    return seenLine;
  };
  const fail = (msg, pos = i) => {
    throw new Error(`line ${lineAt(pos)}: ${msg}`);
  };
  const decode = (s, pos) =>
    s.replace(/&([^;&\s]*);?/g, (m, name, offset) => {
      if (!m.endsWith(";")) fail(`"&" must be written &amp;`, pos + offset);
      if (name in XML_ENTITIES) return XML_ENTITIES[name];
      const num = /^#x([0-9a-fA-F]+)$/.exec(name) ?? /^#([0-9]+)$/.exec(name);
      if (num) return String.fromCodePoint(parseInt(num[1], name[1] === "x" ? 16 : 10));
      return fail(`unknown entity &${name};`, pos + offset);
    });
  const root = { type: "document", children: [] };
  const stack = [root];
  const top = () => stack[stack.length - 1];
  while (i < text.length) {
    if (text.startsWith("<!--", i)) {
      const end = text.indexOf("-->", i + 4);
      if (end < 0) fail("unterminated comment");
      top().children.push({ type: "comment", value: text.slice(i + 4, end) });
      i = end + 3;
    } else if (text.startsWith("<![CDATA[", i)) {
      const end = text.indexOf("]]>", i + 9);
      if (end < 0) fail("unterminated CDATA section");
      top().children.push({ type: "cdata", value: text.slice(i + 9, end) });
      i = end + 3;
    } else if (text.startsWith("<?", i)) {
      const end = text.indexOf("?>", i + 2);
      if (end < 0) fail("unterminated <? ... ?>");
      i = end + 2;
    } else if (text.startsWith("<!", i)) {
      fail("DOCTYPE and other declarations aren't supported");
    } else if (text.startsWith("</", i)) {
      const m = /^<\/([A-Za-z_][\w.:-]*)\s*>/.exec(text.slice(i, i + 200));
      if (!m) fail("malformed end tag");
      const open = top();
      if (open.type !== "element") fail(`</${m[1]}> without a start tag`);
      if (open.name !== m[1]) fail(`</${m[1]}> closes <${open.name}> (line ${open.line})`);
      stack.pop();
      i += m[0].length;
    } else if (text[i] === "<") {
      const start = i;
      const nm = /^<([A-Za-z_][\w.:-]*)/.exec(text.slice(i, i + 200));
      if (!nm) fail(`"<" must be written &lt;`);
      i += nm[0].length;
      const el = { type: "element", name: nm[1], attrs: {}, children: [], line: lineAt(start) };
      for (;;) {
        const ws = /^\s*/.exec(text.slice(i, i + 1000))[0];
        i += ws.length;
        if (text.startsWith("/>", i)) {
          i += 2;
          top().children.push(el);
          break;
        }
        if (text[i] === ">") {
          i += 1;
          top().children.push(el);
          stack.push(el);
          break;
        }
        if (!ws) fail(`malformed start tag <${el.name}>`);
        const am = /^([A-Za-z_][\w.:-]*)\s*=\s*("([^"]*)"|'([^']*)')/.exec(text.slice(i, i + 10000));
        if (!am) fail(`malformed attribute in <${el.name}>`);
        if (am[1] in el.attrs) fail(`attribute ${am[1]} given twice`);
        const raw = am[3] ?? am[4];
        if (raw.includes("<")) fail(`"<" in an attribute value`);
        el.attrs[am[1]] = decode(raw, i);
        i += am[0].length;
      }
      if (stack.length === 1 && root.children.filter((c) => c.type === "element").length > 1) fail("more than one root element", start);
    } else {
      const end = text.indexOf("<", i);
      const raw = text.slice(i, end < 0 ? text.length : end);
      if (stack.length === 1) {
        if (raw.trim()) fail("text outside the root element");
      } else {
        top().children.push({ type: "text", value: decode(raw, i) });
      }
      i += raw.length;
    }
  }
  if (stack.length > 1) fail(`<${top().name}> (line ${top().line}) is never closed`);
  const docEl = root.children.find((c) => c.type === "element");
  if (!docEl) fail("no root element");
  return docEl;
}

/** The text of a node and its descendants (CDATA included), like DOM textContent. */
export function textContent(node) {
  if (node.type === "text" || node.type === "cdata") return node.value;
  if (node.type === "comment") return "";
  return (node.children || []).map(textContent).join("");
}

const elements = (node) => (node.children || []).filter((c) => c.type === "element");
function countElements(node, name) {
  let n = 0;
  for (const c of elements(node)) n += (c.name === name ? 1 : 0) + countElements(c, name);
  return n;
}

const ANDROID_PLACEHOLDER = /%(?:(\d+)\$)?[-#+ 0,(<]*\d*(?:\.\d+)?([a-zA-Z%])/g;

/** Format specifiers of a text, `%n` left out: `["%1$s", "%%", "% d"]`. */
function androidSpecifiers(text) {
  return [...text.matchAll(ANDROID_PLACEHOLDER)].map((m) => m[0]).filter((p) => !p.endsWith("n"));
}
/** As a set of "1$s" keys, plus "%%" for a literal percent sign. */
function androidPlaceholderSet(text) {
  const out = new Set();
  for (const m of text.matchAll(ANDROID_PLACEHOLDER)) {
    if (m[2] === "n") continue;
    out.add(m[2] === "%" ? "%%" : `${m[1] || "?"}$${m[2]}`);
  }
  return out;
}
const showSet = (set) => `{${[...set].sort().map((p) => (p === "%%" ? p : `%${p}`)).join(", ")}}`;

/** aapt2: an unescaped ' or " is an error (or silently dropped); a leading @ or ? is a resource reference. */
export function androidEscapingProblem(text) {
  const t = text.trim();
  if (t.length >= 2 && t.startsWith('"') && t.endsWith('"')) return null;
  if (t.startsWith("@") || t.startsWith("?")) return `starts with ${t[0]} (write \\${t[0]})`;
  for (let i = 0; i < t.length; i++) {
    const c = t[i];
    if (c !== "'" && c !== '"') continue;
    let n = 0;
    for (let j = i - 1; j >= 0 && t[j] === "\\"; j--) n++;
    if (n % 2 === 0) return `unescaped ${c} (write \\${c}${c === "'" ? " or use ’" : ""})`;
  }
  return null;
}

/** `<string>`s and `<plurals>` of a resource file: name → { plural, translatable, texts: { quantity: { text, xliff } }, line }. */
function parseAndroid(rep, lang, file) {
  let docEl;
  try {
    docEl = parseXml(readText(file));
  } catch (e) {
    rep.error("android", lang, file, `not well-formed XML: ${e.message}`);
    return null;
  }
  if (docEl.name !== "resources") {
    rep.error("android", lang, file, `the root element must be <resources>, is <${docEl.name}>`);
    return null;
  }
  const out = new Map();
  for (const e of elements(docEl)) {
    if (e.name !== "string" && e.name !== "plurals") continue;
    const name = e.attrs.name;
    if (!name) {
      rep.error("android", lang, file, `line ${e.line}: <${e.name}> without a name`);
      continue;
    }
    const texts = {};
    if (e.name === "string") {
      texts[""] = { text: textContent(e), xliff: countElements(e, "xliff:g") };
    } else {
      for (const item of elements(e)) {
        if (item.name !== "item") continue;
        const q = item.attrs.quantity ?? "";
        if (q in texts) rep.error("android", lang, file, `${name}: quantity "${q}" given twice`);
        texts[q] = { text: textContent(item), xliff: countElements(item, "xliff:g") };
      }
    }
    if (out.has(name)) rep.error("android", lang, file, `${name} is defined twice`);
    out.set(name, { plural: e.name === "plurals", translatable: e.attrs.translatable !== "false", texts, line: e.line });
  }
  return out;
}

function checkAndroidText(rep, lang, file, where, text) {
  const esc = androidEscapingProblem(text);
  if (esc) rep.error("android", lang, file, `${where}: ${esc}`);
  for (const p of androidSpecifiers(text)) {
    if (p !== "%%" && !/^%\d+\$/.test(p)) rep.error("android", lang, file, `${where}: "${p}" is not a positional placeholder (use %1$s; write %% for a percent sign)`);
  }
}

function checkAndroid(root, rep, opts) {
  const res = join(root, PATHS.android);
  const values = join(res, "values");
  if (!isDir(values)) return false;
  const stringFiles = (dir) => readdirSync(dir).filter((f) => /^strings.*\.xml$/.test(f) && isFile(join(dir, f))).sort();
  const english = new Map(); // file name → entries
  const owner = new Map(); // resource name → English file name
  for (const name of stringFiles(values)) {
    const file = join(values, name);
    const entries = parseAndroid(rep, "en", file);
    if (!entries) continue;
    english.set(name, entries);
    for (const [key, e] of entries) {
      if (owner.has(key)) rep.error("android", "en", file, `${key} is also defined in values/${owner.get(key)}`);
      else owner.set(key, name);
      for (const [q, t] of Object.entries(e.texts)) checkAndroidText(rep, "en", file, e.plural ? `${key}[${q}]` : key, t.text);
      if (e.plural && !("other" in e.texts)) rep.error("android", "en", file, `${key}: plurals need an "other" item`);
    }
  }
  if (!english.size) return true;
  const translatable = [...english].flatMap(([f, entries]) => [...entries].filter(([, e]) => e.translatable).map(([k]) => [f, k]));
  const total = translatable.length;

  // The locales Android 13+ offers (res/xml/locales_config.xml).
  const configFile = join(res, "xml", "locales_config.xml");
  let listed = null;
  if (isFile(configFile)) {
    try {
      const cfg = parseXml(readText(configFile));
      listed = new Set(elements(cfg).filter((e) => e.name === "locale").map((e) => normalizeTag(e.attrs["android:name"] ?? "")));
    } catch (e) {
      rep.error("android", "", configFile, `not well-formed XML: ${e.message}`);
    }
  } else {
    rep.error("android", "", configFile, "res/xml/locales_config.xml is missing");
  }

  const langDirs = readdirSync(res)
    .filter((d) => /^values-(?:[a-z]{2,3}(?:-r[A-Z]{2})?|b\+[A-Za-z0-9+]+)$/.test(d) && isDir(join(res, d)) && stringFiles(join(res, d)).length)
    .sort();
  const seenLangs = new Set();
  for (const d of langDirs) {
    const q = d.slice("values-".length);
    const tag = qualifierToTag(q);
    const lang = normalizeTag(tag);
    seenLangs.add(lang);
    if (!opts.wantLang(lang)) continue;
    const dirPath = join(res, d);
    if (listed && !listed.has(lang)) {
      rep.error("android", lang, configFile, `${d}: add <locale android:name="${lang}" /> (Android 13+ only offers listed languages)`);
    }
    const valid = pluralCategories(lang);
    const needed = neededCategories(lang);
    const present = new Set(); // "file/name"
    const thin = [];
    for (const name of stringFiles(dirPath)) {
      const file = join(dirPath, name);
      const entries = parseAndroid(rep, lang, file);
      if (!entries) continue;
      const source = english.get(name);
      if (!source) rep.error("android", lang, file, `there is no values/${name}; put these strings in the file of the same name as English`);
      for (const [key, t] of entries) {
        const src = source?.get(key);
        if (!src) {
          const other = owner.get(key);
          rep.error("android", lang, file, other ? `${key}: belongs in ${d}/${other} (as in values/)` : `${key}: not in values/ (renamed or removed? delete it)`);
          continue;
        }
        if (!src.translatable) {
          rep.error("android", lang, file, `${key}: translatable="false" in English; don't copy it`);
          continue;
        }
        if (src.plural !== t.plural) {
          rep.error("android", lang, file, `${key}: must be a <${src.plural ? "plurals" : "string"}> as in English`);
          continue;
        }
        present.add(`${name}/${key}`);
        for (const [quantity, { text }] of Object.entries(t.texts)) {
          const where = t.plural ? `${key}[${quantity}]` : key;
          if (!text.trim()) rep.error("android", lang, file, `${where}: empty (leave it out to show English)`);
          checkAndroidText(rep, lang, file, where, text);
        }
        if (!t.plural) {
          const want = androidPlaceholderSet(src.texts[""].text);
          const got = androidPlaceholderSet(t.texts[""].text);
          if (!sameSet(want, got)) rep.error("android", lang, file, `${key}: placeholders ${showSet(got)}, English has ${showSet(want)}`);
          if (src.texts[""].xliff !== t.texts[""].xliff) {
            rep.warn("android", lang, file, `${key}: <xliff:g> elements: ${t.texts[""].xliff}, English has ${src.texts[""].xliff} (keep each placeholder and brand name in its <xliff:g>)`);
          }
          continue;
        }
        // Plurals: "other" has exactly the English placeholders; other items only English ones.
        const englishAll = new Set(Object.values(src.texts).flatMap((x) => [...androidPlaceholderSet(x.text)]));
        const englishOther = androidPlaceholderSet(src.texts.other?.text ?? "");
        for (const [quantity, { text }] of Object.entries(t.texts)) {
          if (!CATEGORIES.includes(quantity)) rep.error("android", lang, file, `${key}: unknown quantity "${quantity}"`);
          else if (!valid.includes(quantity)) rep.error("android", lang, file, `${key}: quantity "${quantity}" is not used by ${lang} (${valid.join(", ")})`);
          const got = androidPlaceholderSet(text);
          if (quantity !== "other" && ![...got].every((p) => englishAll.has(p))) rep.error("android", lang, file, `${key}[${quantity}]: placeholders ${showSet(got)}, English has ${showSet(englishAll)}`);
        }
        if (!("other" in t.texts)) {
          rep.error("android", lang, file, `${key}: plurals need an "other" item`);
        } else {
          const got = androidPlaceholderSet(t.texts.other.text);
          if (!sameSet(got, englishOther)) rep.error("android", lang, file, `${key}[other]: placeholders ${showSet(got)}, English has ${showSet(englishOther)}`);
          if (src.texts.other && t.texts.other.xliff !== src.texts.other.xliff) {
            rep.warn("android", lang, file, `${key}[other]: <xliff:g> elements: ${t.texts.other.xliff}, English has ${src.texts.other.xliff}`);
          }
        }
        const lacking = needed.filter((c) => c !== "other" && !(c in t.texts));
        if (lacking.length) thin.push(`${key} (${lacking.join(", ")})`);
      }
    }
    if (thin.length) rep.warn("android", lang, dirPath, `plurals without every quantity ${lang} uses ("other" is shown)`, "missing", thin);
    const byFile = new Map();
    for (const [f, k] of translatable) {
      if (present.has(`${f}/${k}`)) continue;
      if (!byFile.has(f)) byFile.set(f, []);
      byFile.get(f).push(k);
    }
    for (const [f, keys] of byFile) {
      const n = translatable.filter(([ff]) => ff === f).length;
      rep.warn("android", lang, join(dirPath, f), `${keys.length} of ${n} strings missing (English is shown)`, "missing", keys);
    }
    rep.cover("android", lang, present.size, total);
  }
  if (listed) {
    for (const lang of [...listed].sort()) {
      if (lang === "en" || seenLangs.has(lang) || !opts.wantLang(lang)) continue;
      rep.warn("android", lang, configFile, `"${lang}" is listed but has no values-* strings yet (Android offers it and shows English)`, "missing");
      rep.cover("android", lang, 0, total);
    }
  }
  return true;
}

/**
 * Parses the TOML subset strings.toml uses: comments, `[table]` / `[a.b]` headers, bare or quoted
 * keys (dotted too), and string values: basic "..." (with escapes), literal '...', and multi-line
 * """...""" / '''...'''. Returns nested plain objects. Throws an Error with a line number.
 */
export function parseToml(text) {
  const rootTable = {};
  let current = rootTable;
  const defined = new Set();
  let i = 0;
  let line = 1;
  const fail = (msg) => {
    throw new Error(`line ${line}: ${msg}`);
  };
  const peek = (s) => text.startsWith(s, i);
  const skipSpaces = () => {
    while (i < text.length && (text[i] === " " || text[i] === "\t")) i++;
  };
  const skipComment = () => {
    if (text[i] === "#") while (i < text.length && text[i] !== "\n") i++;
  };
  const endOfLine = () => {
    skipSpaces();
    skipComment();
    if (i < text.length && text[i] === "\r") i++;
    if (i < text.length && text[i] !== "\n") fail(`unexpected "${text[i]}"`);
  };
  const escape = () => {
    const c = text[i++];
    const simple = { b: "\b", t: "\t", n: "\n", f: "\f", r: "\r", '"': '"', "\\": "\\", e: "\x1b" };
    if (c in simple) return simple[c];
    if (c === "u" || c === "U") {
      const len = c === "u" ? 4 : 8;
      const hex = text.slice(i, i + len);
      if (!new RegExp(`^[0-9a-fA-F]{${len}}$`).test(hex)) fail(`bad \\${c} escape`);
      i += len;
      return String.fromCodePoint(parseInt(hex, 16));
    }
    return fail(`unknown escape \\${c}`);
  };
  const basicString = () => {
    i++;
    let out = "";
    for (;;) {
      if (i >= text.length || text[i] === "\n") fail("unterminated string");
      const c = text[i];
      if (c === '"') {
        i++;
        return out;
      }
      if (c === "\\") {
        i++;
        out += escape();
      } else {
        out += c;
        i++;
      }
    }
  };
  const literalString = () => {
    const end = text.indexOf("'", i + 1);
    const nl = text.indexOf("\n", i + 1);
    if (end < 0 || (nl >= 0 && nl < end)) fail("unterminated string");
    const s = text.slice(i + 1, end);
    i = end + 1;
    return s;
  };
  const multiline = (quote) => {
    i += 3;
    if (text[i] === "\r") i++;
    if (text[i] === "\n") {
      i++;
      line++;
    }
    let out = "";
    for (;;) {
      if (i >= text.length) fail("unterminated multi-line string");
      if (peek(quote.repeat(3))) {
        // Up to two quotes right before the closing ones belong to the string.
        let extra = 0;
        while (extra < 2 && text[i + 3 + extra] === quote) extra++;
        out += quote.repeat(extra);
        i += 3 + extra;
        return out;
      }
      const c = text[i];
      if (c === "\n") line++;
      if (quote === '"' && c === "\\") {
        i++;
        // Line-ending backslash: trim the newline and the whitespace after it.
        const m = /^[ \t]*\r?\n/.exec(text.slice(i, i + 200));
        if (m) {
          i += m[0].length;
          line++;
          while (i < text.length && /\s/.test(text[i])) {
            if (text[i] === "\n") line++;
            i++;
          }
        } else {
          out += escape();
        }
        continue;
      }
      out += c;
      i++;
    }
  };
  const key = () => {
    skipSpaces();
    if (text[i] === '"') return basicString();
    if (text[i] === "'") return literalString();
    const m = /^[A-Za-z0-9_-]+/.exec(text.slice(i, i + 200));
    if (!m) fail("expected a key");
    i += m[0].length;
    return m[0];
  };
  const dottedKey = () => {
    const parts = [key()];
    skipSpaces();
    while (text[i] === ".") {
      i++;
      parts.push(key());
      skipSpaces();
    }
    return parts;
  };
  const tableAt = (parts, from) => {
    let t = from;
    for (const p of parts) {
      if (!(p in t)) t[p] = {};
      else if (typeof t[p] !== "object") fail(`${p} is a value, not a table`);
      t = t[p];
    }
    return t;
  };
  while (i < text.length) {
    skipSpaces();
    if (text[i] === "\n") {
      i++;
      line++;
      continue;
    }
    if (text[i] === "\r" || text[i] === "#") {
      endOfLine();
      continue;
    }
    if (text[i] === "[") {
      if (peek("[[")) fail("arrays of tables aren't supported");
      i++;
      const parts = dottedKey();
      if (text[i] !== "]") fail('expected "]"');
      i++;
      const name = parts.join(".");
      if (defined.has(name)) fail(`table [${name}] defined twice`);
      defined.add(name);
      current = tableAt(parts, rootTable);
      endOfLine();
      continue;
    }
    const parts = dottedKey();
    if (text[i] !== "=") fail('expected "="');
    i++;
    skipSpaces();
    let value;
    if (peek('"""')) value = multiline('"');
    else if (peek("'''")) value = multiline("'");
    else if (text[i] === '"') value = basicString();
    else if (text[i] === "'") value = literalString();
    else fail("only string values are supported here");
    const t = tableAt(parts.slice(0, -1), current);
    const last = parts[parts.length - 1];
    if (last in t) fail(`${parts.join(".")} given twice`);
    t[last] = value;
    endOfLine();
  }
  return rootTable;
}

/** strings.toml flattened like Server/src/i18n.rs: "section.key" → { text } or { plural: { category: text } }. */
export function flattenStrings(table, prefix = "", out = new Map()) {
  for (const [k, v] of Object.entries(table)) {
    const name = prefix ? `${prefix}.${k}` : k;
    if (typeof v === "string") out.set(name, { text: v });
    else if (Object.keys(v).length && Object.entries(v).every(([c, x]) => CATEGORIES.includes(c) && typeof x === "string")) out.set(name, { plural: v });
    else flattenStrings(v, name, out);
  }
  return out;
}

/** The names in `{{name}}`, `{{#name}}` and `{{/name}}` (Server/src/i18n.rs `placeholders`). */
export function serverPlaceholders(template) {
  const out = new Set();
  let rest = String(template);
  for (;;) {
    const start = rest.indexOf("{{");
    if (start < 0) break;
    const after = rest.slice(start + 2);
    const end = after.indexOf("}}");
    if (end < 0) break;
    const tag = after.slice(0, end).trim().replace(/^[#/]+/, "").trim();
    if (tag) out.add(tag);
    rest = after.slice(end + 2);
  }
  return out;
}
const entryServerPlaceholders = (e) => new Set((e.plural ? Object.values(e.plural) : [e.text]).flatMap((t) => [...serverPlaceholders(t)]));
/** The HTML tags of a text in order, e.g. "<b> </b>". */
const htmlTags = (s) => [...String(s).matchAll(/<\/?[A-Za-z][A-Za-z0-9]*/g)].map((m) => `${m[0].toLowerCase()}>`);
const sameTags = (a, b) => [...a].sort().join(" ") === [...b].sort().join(" ");

function readStrings(rep, lang, file) {
  try {
    return flattenStrings(parseToml(readText(file)));
  } catch (e) {
    rep.error("server", lang, file, `not valid: ${e.message}`);
    return null;
  }
}

function checkServer(root, rep, opts) {
  const dir = join(root, PATHS.server);
  const enDir = join(dir, "en");
  if (!isDir(enDir)) return false;
  const localeFiles = (d) => readdirSync(d).filter((f) => /\.(txt|html|toml)$/.test(f) && isFile(join(d, f))).sort();
  const enFiles = localeFiles(enDir);
  const enStringsFile = join(enDir, "strings.toml");
  if (!enFiles.includes("strings.toml")) {
    rep.error("server", "en", enStringsFile, "missing");
    return true;
  }
  const en = readStrings(rep, "en", enStringsFile);
  if (!en) return true;
  for (const [key, e] of en) {
    if (e.plural && !("other" in e.plural)) rep.error("server", "en", enStringsFile, `${key}: a plural needs "other"`);
    for (const t of e.plural ? Object.values(e.plural) : [e.text]) if (!t.trim()) rep.error("server", "en", enStringsFile, `${key}: empty`);
  }
  const templates = enFiles.filter((f) => f !== "strings.toml");
  const total = templates.length + en.size;
  for (const tag of readdirSync(dir).sort()) {
    const tagDir = join(dir, tag);
    if (tag === "en" || !isDir(tagDir)) continue;
    const lang = normalizeTag(tag);
    if (!opts.wantLang(lang)) continue;
    if (!/^[A-Za-z0-9][A-Za-z0-9-]{0,34}$/.test(tag)) rep.error("server", lang, tagDir, `"${tag}": locale directories are named like en, de or zh-CN`);
    const files = localeFiles(tagDir);
    for (const f of files) if (!enFiles.includes(f)) rep.error("server", lang, join(tagDir, f), `en/ has no ${f} (the server needs the same file names as en/)`);
    const missingFiles = enFiles.filter((f) => !files.includes(f));
    let translated = 0;
    for (const name of templates) {
      if (!files.includes(name)) continue;
      translated++;
      const file = join(tagDir, name);
      const text = readText(file);
      if (!text.trim()) rep.error("server", lang, file, "empty");
      if (text.startsWith("Subject:")) rep.error("server", lang, file, "subjects go into strings.toml ([email] *_subject)");
      const want = serverPlaceholders(readText(join(enDir, name)));
      const got = serverPlaceholders(text);
      if (!sameSet(want, got)) rep.error("server", lang, file, `placeholders {{${sortedList(got)}}}, en/${name} has {{${sortedList(want)}}}`);
    }
    const missingKeys = [];
    if (files.includes("strings.toml")) {
      const file = join(tagDir, "strings.toml");
      const strings = readStrings(rep, lang, file);
      if (strings) {
        const used = serverCategories(tag);
        for (const [key, e] of strings) {
          const src = en.get(key);
          if (!src) {
            rep.error("server", lang, file, `${key}: not in en/strings.toml (renamed or removed? delete it)`);
            continue;
          }
          if (!!src.plural !== !!e.plural) {
            rep.error("server", lang, file, `${key}: must be ${src.plural ? "a plural table" : "a string"} as in English`);
            continue;
          }
          for (const t of e.plural ? Object.values(e.plural) : [e.text]) if (!t.trim()) rep.error("server", lang, file, `${key}: empty`);
          const want = entryServerPlaceholders(src);
          const got = entryServerPlaceholders(e);
          if (!sameSet(want, got)) rep.error("server", lang, file, `${key}: placeholders {{${sortedList(got)}}}, English has {{${sortedList(want)}}}`);
          if (e.plural) {
            if (!("other" in e.plural)) rep.error("server", lang, file, `${key}: a plural needs "other"`);
            const unused = Object.keys(e.plural).filter((c) => !used.includes(c));
            if (unused.length) rep.warn("server", lang, file, `${key}: ${unused.join(", ")} never used (the server picks ${used.join(" or ")} for ${tag}; see plural_category in Server/src/i18n.rs)`);
            const lacking = used.filter((c) => c !== "other" && !(c in e.plural));
            if (lacking.length) rep.warn("server", lang, file, `${key}: lacks ${lacking.join(", ")} ("other" is shown)`, "missing");
          }
          if (key === "meta.dir" && !["ltr", "rtl"].includes(e.text)) rep.error("server", lang, file, `meta.dir must be "ltr" or "rtl"`);
          if (key.startsWith("page.") && !e.plural && !sameTags(htmlTags(e.text), htmlTags(src.text))) {
            rep.warn("server", lang, file, `${key}: HTML tags ${htmlTags(e.text).join(" ") || "(none)"}, English has ${htmlTags(src.text).join(" ") || "(none)"}`);
          }
        }
        for (const key of en.keys()) if (!strings.has(key)) missingKeys.push(key);
        translated += en.size - missingKeys.length;
      }
    } else {
      missingKeys.push(...en.keys());
    }
    if (missingFiles.length) {
      rep.warn("server", lang, tagDir, `${missingFiles.length} of ${enFiles.length} files missing (English is used; cargo test -p pass-server needs them all)`, "missing", missingFiles);
    }
    if (missingKeys.length && files.includes("strings.toml")) {
      rep.warn("server", lang, join(tagDir, "strings.toml"), `${missingKeys.length} of ${en.size} strings missing (English is used; cargo test -p pass-server needs them all)`, "missing", missingKeys);
    }
    rep.cover("server", lang, translated, total);
  }
  return true;
}

const CHECKS = { windows: checkWindows, extension: checkExtension, android: checkAndroid, server: checkServer, core: checkCore };

/**
 * Runs the checks and returns `{ errors, warnings, coverage, apps, ok }`. Options: `root`, `langs`
 * (tags, any spelling), `apps`, `strict` (warnings become errors).
 */
export function check({ root = DEFAULT_ROOT, langs = [], apps = APPS, strict = false } = {}) {
  const rep = new Report(resolve(root));
  const wanted = new Set(langs.map(normalizeTag));
  const opts = { wantLang: (tag) => tag !== "en" && (!wanted.size || wanted.has(normalizeTag(tag))) };
  const checked = [];
  for (const app of apps) {
    if (CHECKS[app](rep.root, rep, opts)) checked.push(app);
    else if (apps.length < APPS.length) rep.error(app, "", join(rep.root, PATHS[app]), "English source not found");
  }
  if (strict) {
    rep.errors.push(...rep.warnings.map((w) => ({ ...w, message: `${w.message} (--strict)` })));
    rep.warnings = [];
  }
  return { root: rep.root, apps: checked, errors: rep.errors, warnings: rep.warnings, coverage: rep.coverage, ok: rep.errors.length === 0 };
}

function parseArgs(argv) {
  const out = { langs: [], apps: [], strict: false, json: false, verbose: false, root: DEFAULT_ROOT, help: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const [flag, inline] = a.startsWith("--") && a.includes("=") ? [a.slice(0, a.indexOf("=")), a.slice(a.indexOf("=") + 1)] : [a, undefined];
    const value = () => {
      const v = inline ?? argv[++i];
      if (v === undefined) throw new Error(`${flag} needs a value`);
      return v;
    };
    if (flag === "--lang") out.langs.push(...value().split(",").filter(Boolean));
    else if (flag === "--app") {
      for (const name of value().split(",").filter(Boolean)) {
        const app = APP_ALIASES[name.toLowerCase()];
        if (!app) throw new Error(`unknown app "${name}" (${APPS.join(", ")})`);
        out.apps.push(app);
      }
    } else if (flag === "--root") out.root = resolve(value());
    else if (flag === "--strict") out.strict = true;
    else if (flag === "--json") out.json = true;
    else if (flag === "--verbose" || flag === "-v") out.verbose = true;
    else if (flag === "--help" || flag === "-h") out.help = true;
    else throw new Error(`unknown option ${a}`);
  }
  if (!out.apps.length) out.apps = [...APPS];
  out.apps = APPS.filter((a) => out.apps.includes(a));
  return out;
}

/** The human-readable report. */
export function format(result, { verbose = false } = {}) {
  const lines = [];
  const langs = [...new Set(result.coverage.map((c) => c.lang))].sort();
  const cols = result.apps;
  const cell = (c) => (!c ? "-" : c.missing ? `${c.translated}/${c.total} -${c.missing}` : `${c.translated}/${c.total} ok`);
  if (langs.length) {
    const rows = [["lang", ...cols], ...langs.map((l) => [l, ...cols.map((a) => cell(result.coverage.find((c) => c.lang === l && c.app === a)))])];
    const widths = rows[0].map((_, k) => Math.max(...rows.map((r) => r[k].length)));
    lines.push("Coverage (translated/total, -missing):", "");
    rows.forEach((r, n) => {
      lines.push("  " + r.map((v, k) => (k === 0 ? v.padEnd(widths[k]) : v.padStart(widths[k]))).join("   "));
      if (n === 0) lines.push("  " + widths.map((w) => "-".repeat(w)).join("   "));
    });
    lines.push("");
  } else {
    lines.push("No translations to check (only English, or none match --lang); the English sources were checked.", "");
  }
  const where = (p) => `${p.lang ? `${p.lang}: ` : ""}${p.file || p.app}`;
  const group = (list) => {
    const byFile = new Map();
    for (const p of list) {
      const k = where(p);
      if (!byFile.has(k)) byFile.set(k, []);
      byFile.get(k).push(p);
    }
    return byFile;
  };
  const LIMIT = 8;
  const show = (title, list) => {
    if (!list.length) return;
    lines.push(`${title} (${list.length}):`);
    for (const [file, items] of group(list)) {
      lines.push(`  ${file}`);
      for (const p of items) {
        lines.push(`    ${p.message}`);
        if (p.keys) {
          const all = verbose || p.keys.length <= LIMIT;
          for (const k of all ? p.keys : p.keys.slice(0, LIMIT)) lines.push(`      ${k}`);
          if (!all) lines.push(`      ... and ${p.keys.length - LIMIT} more (--lang ${p.lang} or --verbose lists all)`);
        }
      }
    }
    lines.push("");
  };
  show("Errors", result.errors);
  show("Warnings", result.warnings);
  lines.push(
    result.ok
      ? `i18n-check: ok (${result.warnings.length} warning${result.warnings.length === 1 ? "" : "s"}; missing texts fall back to English)`
      : `i18n-check: ${result.errors.length} error${result.errors.length === 1 ? "" : "s"}. See docs/TRANSLATING.md.`,
  );
  return lines.join("\n");
}

const USAGE = `Usage: node scripts/i18n-check.mjs [--lang <tag>] [--app <name>] [--strict] [--json] [--verbose] [--root <dir>]

  --lang <tag>   only this language (repeat or comma-separate; de, zh-CN, zh_CN, zh-rCN, id, in ...)
  --app <name>   only this app: windows, extension, android, server, core (repeat or comma-separate)
  --strict       warnings (missing texts and plural forms included) count as errors
  --json         print the result as JSON
  --verbose      list every missing key (done anyway with --lang)
  --root <dir>   the folder with the repositories to check (default: the parent of this script's repository)

Exit code: 0 ok, 1 errors found, 2 bad command line. Guide: docs/TRANSLATING.md`;

function main(argv) {
  let args;
  try {
    args = parseArgs(argv);
  } catch (e) {
    console.error(`i18n-check: ${e.message}\n\n${USAGE}`);
    return 2;
  }
  if (args.help) {
    console.log(USAGE);
    return 0;
  }
  const result = check({ root: args.root, langs: args.langs, apps: args.apps, strict: args.strict });
  if (args.json) console.log(JSON.stringify(result, null, 2));
  else console.log(format(result, { verbose: args.verbose || args.langs.length > 0 }));
  return result.ok ? 0 : 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  process.exitCode = main(process.argv.slice(2));
}
