// node --test scripts/test/*.test.mjs
// Tests scripts/release-feed.mjs: one latest.json for every desktop platform, each entry pointing at
// the file the app installs, signed by the app's key for this file and version. The signatures are
// real minisign signatures, made here with a test key (node:crypto, Ed25519 over the BLAKE2b-512 of
// the file, as the Tauri CLI signs).
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { addEntry, keyIdOf, publicKeyOf, signatureProblem, signingKeyOf } from "../release-feed.mjs";

const SCRIPT = fileURLToPath(new URL("../release-feed.mjs", import.meta.url));
const CONF = fileURLToPath(new URL("../../desktop-app/src-tauri/tauri.conf.json", import.meta.url));
const SIGNING = fileURLToPath(new URL("../updater-signing.json", import.meta.url));
const PUBKEY = JSON.parse(readFileSync(CONF, "utf8")).plugins.updater.pubkey;
const KEY_ID = "9725c91f258ee832";
/** The key the apps embedded before KEY_ID; it still signs the release that first ships KEY_ID. */
const PREVIOUS_KEY_ID = "24131b5df1065f8b";

/** A test minisign key pair: the private key, and the public key as `plugins.updater.pubkey` holds it. */
function keyPair(keyId = "0123456789abcdef") {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const raw = Buffer.from(publicKey.export({ format: "jwk" }).x, "base64url");
  const line = Buffer.concat([Buffer.from("Ed"), Buffer.from(keyId, "hex"), raw]).toString("base64");
  const file = `untrusted comment: minisign public key: ${keyId.toUpperCase()}\n${line}\n`;
  return { keyId, privateKey, pubkey: Buffer.from(file).toString("base64") };
}

/**
 * A `.sig` file as the Tauri CLI writes it (base64 of a minisign signature file), signing `data`
 * with `pair`. `keyId` puts another key id in it; `comment` replaces the trusted comment after
 * signing (a tampered file).
 */
function sig(pair, data, { file, version, keyId = pair.keyId, comment }) {
  const trusted = `timestamp:1790000000\tfile:${file}\tversion:${version}`;
  const signature = sign(null, createHash("blake2b512").update(data).digest(), pair.privateKey);
  const global = sign(null, Buffer.concat([signature, Buffer.from(trusted)]), pair.privateKey);
  const raw = Buffer.concat([Buffer.from("ED"), Buffer.from(keyId, "hex"), signature]).toString("base64");
  const text = `untrusted comment: signature from tauri secret key\n${raw}\ntrusted comment: ${comment ?? trusted}\n${global.toString("base64")}\n`;
  return Buffer.from(text).toString("base64");
}

test("the key id is the one the app trusts", () => {
  assert.equal(keyIdOf(PUBKEY), KEY_ID);
  assert.equal(publicKeyOf(PUBKEY).keyId, KEY_ID);
  assert.equal(keyIdOf(""), null);
  assert.equal(keyIdOf("REPLACE_ME"), null);
  const pair = keyPair();
  assert.equal(keyIdOf(pair.pubkey), pair.keyId);
});

test("signatures must be by the app's key, over these bytes, for this file and version", () => {
  const pair = keyPair();
  const other = keyPair("fedcba9876543210");
  const publicKey = publicKeyOf(pair.pubkey);
  const file = "Passyble_0.2.0_amd64.AppImage";
  const data = Buffer.from("the 0.2.0 AppImage");
  const want = { publicKey, file, version: "0.2.0", data };
  const good = sig(pair, data, { file, version: "0.2.0" });
  assert.equal(signatureProblem(good, want), null);
  // Other bytes: a rebuilt file, or the signature of another file.
  assert.match(signatureProblem(good, { ...want, data: Buffer.from("the 0.2.0 AppImage, rebuilt") }), /doesn't match the file/);
  // Stale: last release's signature, also with its comment edited to the new version.
  assert.match(signatureProblem(sig(pair, Buffer.from("the 0.1.9 AppImage"), { file, version: "0.1.9" }), want), /doesn't match the file/);
  assert.match(signatureProblem(sig(pair, data, { file, version: "0.1.9" }), want), /version 0\.2\.0/);
  const edited = sig(pair, data, { file, version: "0.1.9", comment: `timestamp:1790000000\tfile:${file}\tversion:0.2.0` });
  assert.match(signatureProblem(edited, want), /trusted comment was changed/);
  // Another key: its own id, or the app's id with another key's signature.
  assert.match(signatureProblem(sig(other, data, { file, version: "0.2.0" }), want), /another key/);
  assert.match(signatureProblem(sig(other, data, { file, version: "0.2.0", keyId: pair.keyId }), want), /doesn't match the file/);
  // The app's real key does not verify a test signature, even under its key id.
  const real = { ...want, publicKey: publicKeyOf(PUBKEY) };
  assert.match(signatureProblem(sig(pair, data, { file, version: "0.2.0", keyId: KEY_ID }), real), /doesn't match the file/);
  // The trusted comment must name the file too.
  assert.match(signatureProblem(sig(pair, data, { file: "Passyble_0.2.0_amd64.deb", version: "0.2.0" }), want), /doesn't name/);
  assert.match(signatureProblem("bm9wZQ==", want), /not a minisign signature/);
  assert.match(signatureProblem(good, { ...want, publicKey: null }), /no valid signing public key/);
});

test("updater-signing.json picks the key that signs the release", () => {
  const current = keyPair();
  const previous = keyPair("fedcba9876543210");
  const conf = { plugins: { updater: { pubkey: current.pubkey } } };
  assert.equal(signingKeyOf(conf, { signWith: "current" }).publicKey.keyId, current.keyId);
  const prev = signingKeyOf(conf, { signWith: "previous", previousPubkey: previous.pubkey });
  assert.equal(prev.which, "previous");
  assert.equal(prev.publicKey.keyId, previous.keyId);
  assert.throws(() => signingKeyOf(conf, {}), /signWith must be/);
  assert.throws(() => signingKeyOf(conf, { signWith: "old" }), /signWith must be/);
  assert.throws(() => signingKeyOf(conf, { signWith: "previous" }), /previousPubkey is not a valid/);
  assert.throws(() => signingKeyOf(conf, { signWith: "previous", previousPubkey: current.pubkey }), /set signWith to "current"/);
  assert.throws(() => signingKeyOf({}, { signWith: "current" }), /no valid plugins\.updater\.pubkey/);
});

test("the shipped updater-signing.json is valid and names a known key", () => {
  const signing = JSON.parse(readFileSync(SIGNING, "utf8"));
  const conf = JSON.parse(readFileSync(CONF, "utf8"));
  const { which, publicKey } = signingKeyOf(conf, signing);
  // "previous": the release that first embeds KEY_ID is signed with the key the installed apps trust.
  assert.equal(publicKey.keyId, which === "previous" ? PREVIOUS_KEY_ID : KEY_ID);
});

test("one feed carries every platform, each at its own file", () => {
  const now = new Date("2026-11-21T10:00:00.123Z");
  let feed = addEntry(null, { version: "0.2.0", platforms: ["windows-x86_64"], file: "Passyble_0.2.0_x64-setup.exe", signature: "w", notes: "Fixes.", now });
  feed = addEntry(feed, { version: "0.2.0", platforms: ["linux-x86_64"], file: "Passyble_0.2.0_amd64.AppImage", signature: "l" });
  feed = addEntry(feed, { version: "0.2.0", platforms: ["darwin-aarch64", "darwin-x86_64"], file: "Passyble.app.tar.gz", signature: "m" });
  assert.deepEqual(feed, {
    version: "0.2.0",
    notes: "Fixes.",
    pub_date: "2026-11-21T10:00:00Z",
    platforms: {
      "windows-x86_64": { signature: "w", url: "https://github.com/sensyble/pass-releases/releases/download/v0.2.0/Passyble_0.2.0_x64-setup.exe" },
      "linux-x86_64": { signature: "l", url: "https://github.com/sensyble/pass-releases/releases/download/v0.2.0/Passyble_0.2.0_amd64.AppImage" },
      "darwin-aarch64": { signature: "m", url: "https://github.com/sensyble/pass-releases/releases/download/v0.2.0/Passyble.app.tar.gz" },
      "darwin-x86_64": { signature: "m", url: "https://github.com/sensyble/pass-releases/releases/download/v0.2.0/Passyble.app.tar.gz" },
    },
  });
  // The same platform again replaces its entry.
  const again = addEntry(feed, { version: "0.2.0", platforms: ["linux-x86_64"], file: "Passyble_0.2.0_amd64.AppImage", signature: "l2" });
  assert.equal(again.platforms["linux-x86_64"].signature, "l2");
  assert.equal(Object.keys(again.platforms).length, 4);
});

test("entries that the apps would refuse are refused", () => {
  const entry = (over) => () => addEntry(null, { version: "0.2.0", platforms: ["linux-x86_64"], file: "Passyble_0.2.0_amd64.AppImage", signature: "s", ...over });
  assert.throws(entry({ file: "Passyble_0.2.0_amd64.deb" }), /linux-x86_64 must point at a \.AppImage file/);
  assert.throws(entry({ platforms: ["windows-x86_64"], file: "Passyble_0.2.0_x64_en-US.msi" }), /-setup\.exe/);
  assert.throws(entry({ platforms: ["darwin-aarch64"], file: "Passyble_0.2.0_aarch64.dmg" }), /\.app\.tar\.gz/);
  assert.throws(entry({ platforms: ["linux"] }), /unknown platform/);
  assert.throws(entry({ platforms: [] }), /no platform/);
  assert.throws(entry({ version: "0.2" }), /MAJOR\.MINOR\.PATCH/);
  const old = { version: "0.1.0", notes: "", pub_date: "", platforms: {} };
  assert.throws(() => addEntry(old, { version: "0.2.0", platforms: ["linux-x86_64"], file: "Passyble_0.2.0_amd64.AppImage", signature: "s" }), /start a new latest\.json/);
});

test("the command line verifies the signature and writes the feed", () => {
  const dir = mkdtempSync(join(tmpdir(), "release-feed-"));
  try {
    const pair = keyPair();
    const testConf = join(dir, "tauri.conf.json");
    writeFileSync(testConf, JSON.stringify({ plugins: { updater: { pubkey: pair.pubkey } } }));
    const testSigning = join(dir, "updater-signing.json");
    writeFileSync(testSigning, JSON.stringify({ signWith: "current" }));
    const name = "Passyble_0.2.0_amd64.AppImage";
    const file = join(dir, name);
    const feed = join(dir, "latest.json");
    const data = Buffer.from("appimage");
    writeFileSync(file, data);
    const run = (conf = testConf, signing = testSigning) =>
      spawnSync(process.execPath, [SCRIPT, "--feed", feed, "--version", "0.2.0", "--platform", "linux-x86_64", "--file", file, "--conf", conf, ...(signing ? ["--signing", signing] : [])], { encoding: "utf8" });
    assert.equal(run().status, 1, "no .sig yet");
    writeFileSync(`${file}.sig`, sig(pair, data, { file: name, version: "0.1.0" }));
    const wrong = run();
    assert.equal(wrong.status, 1);
    assert.match(wrong.stderr, /version 0\.2\.0/);
    // Signed, then the file changed: refused.
    writeFileSync(`${file}.sig`, sig(pair, Buffer.from("an older build"), { file: name, version: "0.2.0" }));
    const stale = run();
    assert.equal(stale.status, 1);
    assert.match(stale.stderr, /doesn't match the file/);
    writeFileSync(`${file}.sig`, sig(pair, data, { file: name, version: "0.2.0" }));
    // The app's real keys (the shipped tauri.conf.json and updater-signing.json) do not trust the test key.
    const real = run(CONF, null);
    assert.equal(real.status, 1);
    assert.match(real.stderr, /another key/);
    // While signWith is "previous", a signature by the new key (the one in tauri.conf.json) is refused.
    const previous = keyPair("fedcba9876543210");
    writeFileSync(testSigning, JSON.stringify({ signWith: "previous", previousPubkey: previous.pubkey }));
    const byNew = run();
    assert.equal(byNew.status, 1);
    assert.match(byNew.stderr, /another key/);
    assert.match(byNew.stderr, /signWith: previous/);
    assert.throws(() => readFileSync(feed), "nothing written so far");
    writeFileSync(`${file}.sig`, sig(previous, data, { file: name, version: "0.2.0" }));
    const byPrevious = run();
    assert.equal(byPrevious.status, 0, byPrevious.stderr);
    assert.match(byPrevious.stdout, /signed with the previous key/);
    rmSync(feed);
    writeFileSync(`${file}.sig`, sig(pair, data, { file: name, version: "0.2.0" }));
    writeFileSync(testSigning, JSON.stringify({ signWith: "current" }));
    const ok = run();
    assert.equal(ok.status, 0, ok.stderr);
    const written = JSON.parse(readFileSync(feed, "utf8"));
    assert.equal(written.version, "0.2.0");
    assert.match(written.platforms["linux-x86_64"].url, /\/v0\.2\.0\/Passyble_0\.2\.0_amd64\.AppImage$/);
    assert.equal(spawnSync(process.execPath, [SCRIPT, "--feed", feed], { encoding: "utf8" }).status, 2);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
