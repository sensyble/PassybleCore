// node --test scripts/test/*.test.mjs
// Tests scripts/i18n-check.mjs against small fixture trees: fixtures/good (German complete in every
// app and in pass-core, French and Indonesian partly translated) and fixtures/broken (one or more
// mistakes per format).
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  androidEscapingProblem,
  check,
  flattenStrings,
  format,
  neededCategories,
  normalizeTag,
  parseToml,
  parseXml,
  serverPlaceholders,
  textContent,
} from "../i18n-check.mjs";

const fixture = (name) => fileURLToPath(new URL(`fixtures/${name}`, import.meta.url));
const GOOD = fixture("good");
const BROKEN = fixture("broken");
const SCRIPT = fileURLToPath(new URL("../i18n-check.mjs", import.meta.url));
// The folder that holds the sibling repositories (this test needs Extension, Android and Server cloned there).
const REPO = fileURLToPath(new URL("../../..", import.meta.url));

const messages = (list, app, lang) => list.filter((p) => p.app === app && (!lang || p.lang === lang)).map((p) => p.message);
/** Every pattern matches one of the messages. */
function assertReports(list, patterns) {
  for (const re of patterns) assert.ok(list.some((m) => re.test(m)), `expected ${re} in:\n  ${list.join("\n  ")}`);
}
const run = (...args) => spawnSync(process.execPath, [SCRIPT, ...args], { encoding: "utf8" });

test("good tree: no errors; German is complete in every app", () => {
  const r = check({ root: GOOD });
  assert.deepEqual(r.errors, []);
  assert.equal(r.ok, true);
  assert.deepEqual(r.apps, ["windows", "extension", "android", "server", "core"]);
  for (const app of r.apps) {
    const de = r.coverage.find((c) => c.app === app && c.lang === "de");
    assert.ok(de, `${app}: de coverage`);
    assert.equal(de.missing, 0, `${app}: de complete`);
  }
  assert.deepEqual(check({ root: GOOD, langs: ["de"] }).warnings, []);
});

test("good tree: missing texts are warnings that list the keys; --strict makes them errors", () => {
  const r = check({ root: GOOD, langs: ["fr"] });
  assert.equal(r.ok, true);
  const missing = r.warnings.filter((w) => w.kind === "missing");
  assert.deepEqual(missing.find((w) => w.app === "windows").keys, ["app.title"]);
  assert.deepEqual(missing.find((w) => w.app === "extension").keys, ["popupLookUp"]);
  assert.deepEqual(missing.find((w) => w.app === "android").keys, ["app_name", "save_sync", "markup"]);
  assert.deepEqual(missing.find((w) => w.app === "server" && w.file.endsWith("strings.toml")).keys, ["page.note"]);
  assert.deepEqual(missing.find((w) => w.app === "server" && !w.file.endsWith("strings.toml")).keys, ["hello.html"]);
  assert.deepEqual(missing.find((w) => w.app === "core").keys, ["server.enter_address"]);
  assert.equal(missing.find((w) => w.app === "core").file, "Core/core/locales/fr.json");
  assert.deepEqual(r.coverage.find((c) => c.app === "windows"), { app: "windows", lang: "fr", translated: 3, total: 4, missing: 1 });

  const strict = check({ root: GOOD, langs: ["fr"], strict: true });
  assert.equal(strict.ok, false);
  assert.equal(strict.warnings.length, 0);
  assert.equal(strict.errors.length, r.warnings.length);
});

test("filters: --lang takes any spelling (in = id, values-in), --app limits the apps", () => {
  for (const spelling of ["id", "in", "values-in", "b+id"]) {
    const r = check({ root: GOOD, langs: [spelling], apps: ["android"] });
    assert.deepEqual(r.coverage.map((c) => `${c.app}/${c.lang}`), ["android/id"], spelling);
  }
  const r = check({ root: GOOD, apps: ["server"] });
  assert.deepEqual([...new Set(r.coverage.map((c) => c.app))], ["server"]);
  const core = check({ root: GOOD, apps: ["core"] });
  assert.deepEqual([...new Set(core.coverage.map((c) => c.app))], ["core"]);
  assert.deepEqual(core.coverage.map((c) => c.lang), ["de", "fr"]);
  assert.deepEqual(check({ root: GOOD, langs: ["xx"] }).coverage, [], "unknown language: nothing to check");
});

test("the human-readable report has a coverage table and the summary line", () => {
  const out = format(check({ root: GOOD }));
  assert.match(out, /lang\s+windows\s+extension\s+android\s+server/);
  assert.match(out, /de\s+4\/4 ok\s+4\/4 ok\s+5\/5 ok\s+8\/8 ok/);
  assert.match(out, /fr\s+3\/4 -1/);
  assert.match(out, /i18n-check: ok \(\d+ warnings/);
});

const broken = check({ root: BROKEN });

test("broken tree: errors, so the run fails", () => {
  assert.equal(broken.ok, false);
});

test("Windows app: _meta, unknown keys, placeholders, plural categories, shapes, empty texts", () => {
  assertReports(messages(broken.errors, "windows", "de"), [
    /_meta needs "name"/,
    /greet\.hello: placeholders \{nme\}, en\.json has \{name\}/,
    /greet\.bye: not in en\.json/,
    /items\.count: a plural needs "other"/,
    /items\.count: "few" is not a plural category of de/,
    /items\.in_folder: must be a plural object/,
    /app\.title: empty/,
  ]);
  assertReports(messages(broken.errors, "windows", "ja"), [/items\.count: "one" is not a plural category of ja/]);
});

test("extension: catalogLocale, placeholders and $NAME$ references, plural sets, unknown keys, folder names", () => {
  assertReports(messages(broken.errors, "extension", "de"), [
    /catalogLocale must be "de"/,
    /extName: empty message/,
    /popupLookUp: the message must use \$SITE\$/,
    /popupLookUp: \$SEITE\$ is not defined/,
    /popupUnknown: not an English message/,
    /badgeLogins_other is required/,
  ]);
  assertReports(messages(broken.errors, "extension", "ja"), [
    /popupLookUp: "placeholders" must be as in English \(site=\$1, user=\$2\), has site=\$1/,
    /badgeLogins_one: "one" is not a plural category of ja/,
  ]);
  assertReports(messages(broken.errors, "extension", "zh-CN"), [/isn't a browser locale folder/]);
});

test("Android: placeholders, escaping, translatable=false, quantities, locales_config, well-formedness", () => {
  assertReports(messages(broken.errors, "android", "de"), [
    /greet: unescaped '/,
    /greet: placeholders \{%1\$s\}, English has \{%%, %1\$s, %2\$d\}/,
    /charset: translatable="false"/,
    /save_sync: "%s" is not a positional placeholder/,
    /markup: starts with @/,
    /bye: not in values\//,
    /items: quantity "few" is not used by de/,
    /items\[other\]: placeholders \{%2\$d\}, English has \{%1\$d\}/,
  ]);
  assertReports(messages(broken.errors, "android", "ja"), [/values-ja: add <locale android:name="ja" \/>/, /items: quantity "one" is not used by ja/]);
  assertReports(messages(broken.errors, "android", "ko"), [/not well-formed XML: line 3: <\/strin> closes <string>/]);
  assertReports(messages(broken.warnings, "android", "de"), [/greet: <xliff:g> elements: 1, English has 2/]);
  assertReports(
    broken.warnings.filter((w) => w.app === "android" && w.lang === "de" && w.kind === "missing").flatMap((w) => w.keys),
    [/^items \(one\)$/],
  );
});

test("server: file set, template and string placeholders, plural tables, meta.dir, TOML errors", () => {
  assertReports(messages(broken.errors, "server", "de"), [
    /en\/ has no extra\.txt/,
    /^empty$/,
    /placeholders \{\{user\}\}, en\/hello\.txt has \{\{link, user\}\}/,
    /meta\.dir must be "ltr" or "rtl"/,
    /email\.hello_subject: placeholders \{\{usr\}\}, English has \{\{user\}\}/,
    /email\.bye_subject: not in en\/strings\.toml/,
    /time\.days: a plural needs "other"/,
    /page\.note: empty/,
  ]);
  assertReports(messages(broken.errors, "server", "ko"), [/not valid: line 3: only string values/]);
  assertReports(messages(broken.warnings, "server", "de"), [/page\.intro: HTML tags \(none\), English has <b> <\/b>/]);
  assertReports(messages(broken.warnings, "server", "ja"), [/time\.days: one never used/]);
  assertReports(messages(broken.warnings, "server", "ko"), [/2 of 3 files missing/]);
});

test("pass-core (Core/core/locales, the Windows format): _meta, unknown keys, placeholders, plurals, empty texts", () => {
  assertReports(messages(broken.errors, "core", "de"), [
    /_meta needs "name"/,
    /server\.enter_address: empty/,
    /webdav\.auth_failed: placeholders \{aktion\}, en\.json has \{action\}/,
    /webdav\.gone: not in en\.json/,
    /merge\.websites: must be a plural object/,
  ]);
  assertReports(messages(broken.errors, "core", "ja"), [/merge\.websites: "one" is not a plural category of ja/]);
  assert.ok(broken.errors.filter((e) => e.app === "core").every((e) => e.file.startsWith("Core/core/locales/")));
});

test("CLI: exit codes, --json, bad options", () => {
  const good = run("--root", GOOD);
  assert.equal(good.status, 0, good.stderr);
  assert.match(good.stdout, /Coverage/);
  const bad = run("--root", BROKEN, "--app", "windows");
  assert.equal(bad.status, 1);
  assert.match(bad.stdout, /Errors \(\d+\):/);
  const json = run("--root", BROKEN, "--json", "--lang=ja");
  assert.equal(json.status, 1);
  const parsed = JSON.parse(json.stdout);
  assert.equal(parsed.ok, false);
  assert.ok(parsed.errors.every((e) => e.lang === "ja"));
  assert.equal(run("--root", GOOD, "--lang", "fr", "--strict").status, 1);
  assert.equal(run("--app", "nope").status, 2);
  const coreOnly = run("--root", BROKEN, "--app", "core", "--json");
  assert.equal(coreOnly.status, 1);
  assert.deepEqual(JSON.parse(coreOnly.stdout).apps, ["core"]);
  assert.equal(run("--bogus").status, 2);
  assert.equal(run("--help").status, 0);
});

test("the repository's English sources pass (no translation checked)", () => {
  const r = check({ root: REPO, langs: ["xx-none"] });
  assert.deepEqual(r.errors, []);
  assert.deepEqual(r.apps, ["windows", "extension", "android", "server", "core"]);
});

test("normalizeTag and neededCategories", () => {
  assert.equal(normalizeTag("zh_CN"), "zh-CN");
  assert.equal(normalizeTag("zh-rCN"), "zh-CN");
  assert.equal(normalizeTag("values-zh-rCN"), "zh-CN");
  assert.equal(normalizeTag("b+sr+Latn"), "sr-Latn");
  assert.equal(normalizeTag("in"), "id");
  assert.equal(normalizeTag("de"), "de");
  assert.deepEqual(neededCategories("de"), ["one", "other"]);
  assert.deepEqual(neededCategories("fr"), ["one", "other"], "French many is for millions: optional");
  assert.deepEqual(neededCategories("ja"), ["other"]);
});

test("parseXml: elements, attributes, entities, CDATA, comments, errors with line numbers", () => {
  const doc = parseXml(`<?xml version="1.0"?>\n<!-- c -->\n<r a="1 &amp; 2"><s>x &lt;y&gt; &#65;&#x42;<![CDATA[<b>]]><g/></s></r>`);
  assert.equal(doc.name, "r");
  assert.equal(doc.attrs.a, "1 & 2");
  assert.equal(textContent(doc), "x <y> AB<b>");
  assert.throws(() => parseXml("<r>\n<s></t></r>"), /line 2: <\/t> closes <s>/);
  assert.throws(() => parseXml("<r>a & b</r>"), /&amp;/);
  assert.throws(() => parseXml("<r>"), /never closed/);
  assert.throws(() => parseXml("<r/><q/>"), /more than one root/);
});

test("androidEscapingProblem: aapt2's rules", () => {
  assert.equal(androidEscapingProblem("it\\'s \\\"ok\\\""), null);
  assert.equal(androidEscapingProblem("c’est"), null);
  assert.equal(androidEscapingProblem('"quoted \' whole"'), null);
  assert.match(androidEscapingProblem("it's"), /unescaped '/);
  assert.match(androidEscapingProblem('say "hi"'), /unescaped "/);
  assert.match(androidEscapingProblem("it\\\\'s"), /unescaped '/, "an escaped backslash doesn't escape the quote");
  assert.match(androidEscapingProblem("?attr"), /starts with \?/);
});

test("parseToml and flattenStrings: tables, strings of every kind, errors", () => {
  const t = parseToml(`# c\n[meta]\nname = "A \\"B\\" \\u00e9"\n[a.n]\none = '1'\nother = """\nmany\nlines"""\n[a]\n"q k" = "v" # c\n`);
  assert.deepEqual(t, { meta: { name: 'A "B" é' }, a: { n: { one: "1", other: "many\nlines" }, "q k": "v" } });
  const flat = flattenStrings(t);
  assert.deepEqual(flat.get("a.n"), { plural: { one: "1", other: "many\nlines" } });
  assert.deepEqual(flat.get("meta.name"), { text: 'A "B" é' });
  assert.throws(() => parseToml("a = 1"), /line 1: only string values/);
  assert.throws(() => parseToml('[a]\nb = "x"\n[a]\n'), /line 3: table \[a\] defined twice/);
  assert.throws(() => parseToml('a = "x'), /unterminated/);
});

test("serverPlaceholders: like Server/src/i18n.rs", () => {
  assert.deepEqual([...serverPlaceholders("{{a}} {{#b}}x{{/b}} {{ c }}")].sort(), ["a", "b", "c"]);
});
