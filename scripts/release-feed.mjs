#!/usr/bin/env node
// Adds one platform's download to the release's update feed, `latest.json` (Node 20+, no
// dependencies). Every desktop platform reads the same file
// (https://github.com/sensyble/pass-releases/releases/latest/download/latest.json, the updater
// endpoint in desktop-app/src-tauri/tauri.conf.json), and each is built on its own machine, so each
// build adds its entry to the one file, which is then uploaded with the release:
//
//   node scripts/release-feed.mjs --feed <latest.json> --version 0.2.0 --platform windows-x86_64 \
//     --file <...>/bundle/nsis/Passyble_0.2.0_x64-setup.exe [--notes "Passyble 0.2.0."]
//   node scripts/release-feed.mjs --feed latest.json --version 0.2.0 --platform linux-x86_64 \
//     --file <...>/bundle/appimage/Passyble_0.2.0_amd64.AppImage
//   node scripts/release-feed.mjs --feed latest.json --version 0.2.0 \
//     --platform darwin-aarch64,darwin-x86_64 --file <...>/bundle/macos/Passyble.app.tar.gz
//
// * Platforms and what they must point at: windows-* the NSIS `-setup.exe` (never the MSI: MSI
//   installs don't update themselves), linux-* the `.AppImage` (.deb and .rpm installs link to the
//   download page instead), darwin-* the `.app.tar.gz` (only once the macOS updater is on:
//   macOS/README.md, "Updates"). A universal Mac build gives both darwin keys the same file.
// * The signature is `<file>.sig`, as the Tauri CLI writes it (tauri.release.conf.json). It is
//   verified here as the installed apps verify it (updates.rs, minisign): Ed25519 by the key that
//   signs this release over the BLAKE2b-512 of the file's bytes, and the global signature over that
//   signature and the trusted comment, which must name this file and this version. The apps refuse
//   anything else, so a wrong or stale entry is caught here, before it ships.
// * The key that signs this release is set in scripts/updater-signing.json (`signWith`): "current"
//   is the key in `plugins.updater.pubkey`; "previous" is `previousPubkey`, the key the installed
//   apps still trust while the first release that embeds a new public key goes out. That release
//   must be signed with the previous key, every later one with the current key.
// * The feed carries one version for every platform. A feed of another version is refused: start a
//   new file for each release. An entry for the same platform is replaced.
// * The download URL is the release asset on sensyble/pass-releases (`--base` for a test server).
//
// Exit code 1: a check failed (nothing written); 2: bad command line.
import { createHash, createPublicKey, verify } from "node:crypto";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const RELEASES = "https://github.com/sensyble/pass-releases/releases/download";
const CONF = join(dirname(fileURLToPath(import.meta.url)), "..", "desktop-app", "src-tauri", "tauri.conf.json");
const SIGNING = join(dirname(fileURLToPath(import.meta.url)), "updater-signing.json");

/** The updater targets the apps look up, and the file each must point at. */
export const PLATFORMS = {
  "windows-x86_64": /-setup\.exe$/,
  "windows-aarch64": /-setup\.exe$/,
  "linux-x86_64": /\.AppImage$/,
  "linux-aarch64": /\.AppImage$/,
  "darwin-aarch64": /\.app\.tar\.gz$/,
  "darwin-x86_64": /\.app\.tar\.gz$/,
};

const VERSION = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;

const b64 = (text) => Buffer.from(String(text).trim(), "base64");

/**
 * A minisign public key as `plugins.updater.pubkey` holds it (base64 of the key file: an untrusted
 * comment line, then base64 of "Ed", the 8-byte key id and the 32-byte Ed25519 key): its key id
 * (hex) and the key for node:crypto, or null.
 */
export function publicKeyOf(pubkey) {
  const lines = b64(pubkey).toString("utf8").split("\n");
  if (!lines[0].startsWith("untrusted comment:") || !lines[1]) return null;
  const raw = b64(lines[1]);
  if (raw.length !== 42 || raw.subarray(0, 2).toString() !== "Ed") return null;
  try {
    const key = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: raw.subarray(10).toString("base64url") }, format: "jwk" });
    return { keyId: raw.subarray(2, 10).toString("hex"), key };
  } catch {
    return null;
  }
}

/** The 8-byte key id (hex) of a minisign public key as `plugins.updater.pubkey` holds it. */
export function keyIdOf(pubkey) {
  return publicKeyOf(pubkey)?.keyId ?? null;
}

/**
 * The key that signs this release: `signing` is scripts/updater-signing.json, `conf` tauri.conf.json.
 * Returns `{ which, publicKey }` ("current" or "previous", and the key from [publicKeyOf]). Throws an
 * Error with a plain reason when the file is wrong, so a half-done key change can't ship.
 */
export function signingKeyOf(conf, signing) {
  const current = publicKeyOf(conf?.plugins?.updater?.pubkey || "");
  if (!current) throw new Error("no valid plugins.updater.pubkey in tauri.conf.json");
  const which = signing?.signWith;
  if (which === "current") return { which, publicKey: current };
  if (which !== "previous") throw new Error(`updater-signing.json: signWith must be "current" or "previous", not ${JSON.stringify(which)}`);
  const previous = publicKeyOf(signing.previousPubkey || "");
  if (!previous) throw new Error("updater-signing.json: signWith is \"previous\" but previousPubkey is not a valid public key");
  if (previous.keyId === current.keyId) {
    throw new Error("updater-signing.json: previousPubkey is the key in plugins.updater.pubkey; set signWith to \"current\"");
  }
  return { which, publicKey: previous };
}

const TRUSTED = "trusted comment: ";

/**
 * Why `sig` (the contents of a Tauri `.sig` file: base64 of a minisign signature file) can't go
 * into the feed for `data` (the file's bytes), or null. `publicKey` is the key that signs this
 * release, from [publicKeyOf] or [signingKeyOf].
 *
 * The minisign format (https://jedisct1.github.io/minisign/): an untrusted comment line; base64 of
 * the algorithm ("ED": the file is hashed with BLAKE2b-512 first, "Ed": signed as it is), the key
 * id and the 64-byte Ed25519 signature; the trusted comment line; base64 of the global signature,
 * Ed25519 over the signature and the trusted comment's text.
 */
export function signatureProblem(sig, { publicKey, file, version, data }) {
  if (!publicKey) return "no valid signing public key";
  const lines = b64(sig).toString("utf8").split("\n").map((l) => l.replace(/\r$/, ""));
  if (lines.length < 4 || !lines[0].startsWith("untrusted comment:") || !lines[2].startsWith(TRUSTED)) {
    return "not a minisign signature";
  }
  const raw = b64(lines[1]);
  const algorithm = raw.subarray(0, 2).toString("latin1");
  if (raw.length !== 74 || (algorithm !== "ED" && algorithm !== "Ed")) return "not a minisign signature";
  if (raw.subarray(2, 10).toString("hex") !== publicKey.keyId) return "signed with another key than the one that signs this release (scripts/updater-signing.json)";
  const signature = raw.subarray(10);
  const message = algorithm === "ED" ? createHash("blake2b512").update(data).digest() : Buffer.from(data);
  if (!verify(null, message, publicKey.key, signature)) {
    return "the signature doesn't match the file (another build, or not signed by the key that signs this release)";
  }
  const comment = lines[2].slice(TRUSTED.length);
  const global = b64(lines[3]);
  if (global.length !== 64 || !verify(null, Buffer.concat([signature, Buffer.from(comment, "utf8")]), publicKey.key, global)) {
    return "the trusted comment was changed after signing";
  }
  const fields = comment.split("\t");
  if (!fields.includes(`version:${version}`)) return `the signature doesn't name version ${version} (use the Tauri CLI 2.11.5 or later)`;
  if (!fields.includes(`file:${file}`)) return `the signature doesn't name ${file}`;
  return null;
}

/**
 * `feed` (the parsed latest.json, or null for a new one) with `platforms` pointing at `file`.
 * Throws an Error with a plain reason when an entry doesn't fit.
 */
export function addEntry(feed, { version, platforms, file, signature, notes, now = new Date(), base = RELEASES }) {
  if (!VERSION.test(version)) throw new Error(`the version is not MAJOR.MINOR.PATCH: ${version}`);
  if (feed && feed.version !== version) {
    throw new Error(`the feed is for version ${feed.version}, not ${version}: start a new latest.json for this release`);
  }
  if (!platforms.length) throw new Error("no platform");
  for (const p of platforms) {
    if (!PLATFORMS[p]) throw new Error(`unknown platform ${p} (one of ${Object.keys(PLATFORMS).join(", ")})`);
    if (!PLATFORMS[p].test(file)) throw new Error(`${p} must point at a ${PLATFORMS[p].source.replace(/\\|\$/g, "")} file, not ${file}`);
  }
  const out = feed
    ? { ...feed, platforms: { ...(feed.platforms || {}) } }
    : { version, notes: notes || `Passyble ${version}.`, pub_date: now.toISOString().replace(/\.\d{3}Z$/, "Z"), platforms: {} };
  if (notes) out.notes = notes;
  const url = `${base.replace(/\/+$/, "")}/v${version}/${encodeURIComponent(file)}`;
  for (const p of platforms) out.platforms[p] = { signature: String(signature).trim(), url };
  return out;
}

function main(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 2) {
    const [key, value] = [argv[i], argv[i + 1]];
    if (!key.startsWith("--") || value === undefined) return usage(`unexpected ${key}`);
    args[key.slice(2)] = value;
  }
  for (const need of ["feed", "version", "platform", "file"]) if (!args[need]) return usage(`--${need} is missing`);
  const file = basename(args.file);
  const sigPath = `${args.file}.sig`;
  if (!existsSync(args.file)) return fail(`no file ${args.file}`);
  if (!existsSync(sigPath)) return fail(`no signature ${sigPath} (build with --config tauri.release.conf.json)`);
  const conf = JSON.parse(readFileSync(args.conf || CONF, "utf8"));
  let key;
  try {
    key = signingKeyOf(conf, JSON.parse(readFileSync(args.signing || SIGNING, "utf8")));
  } catch (e) {
    return fail(e.message);
  }
  const { which, publicKey } = key;
  const signature = readFileSync(sigPath, "utf8").trim();
  const problem = signatureProblem(signature, { publicKey, file, version: args.version, data: readFileSync(args.file) });
  if (problem) return fail(`${sigPath}: ${problem} (signWith: ${which}, key id ${publicKey.keyId})`);
  const feed = existsSync(args.feed) ? JSON.parse(readFileSync(args.feed, "utf8")) : null;
  let out;
  try {
    out = addEntry(feed, { version: args.version, platforms: args.platform.split(","), file, signature, notes: args.notes, base: args.base });
  } catch (e) {
    return fail(e.message);
  }
  writeFileSync(args.feed, `${JSON.stringify(out, null, 2)}\n`);
  console.log(`${args.feed}: version ${out.version}, platforms ${Object.keys(out.platforms).sort().join(", ")} (signed with the ${which} key)`);
  return 0;
}

function usage(why) {
  console.error(`release-feed.mjs: ${why}\nusage: node scripts/release-feed.mjs --feed latest.json --version X.Y.Z --platform <key>[,<key>] --file <bundle> [--notes text] [--conf tauri.conf.json] [--signing updater-signing.json] [--base url]`);
  return 2;
}

function fail(why) {
  console.error(`release-feed.mjs: ${why}`);
  return 1;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) process.exitCode = main(process.argv.slice(2));
