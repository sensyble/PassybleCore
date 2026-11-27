#!/usr/bin/env node
// Stages the browser extension for the installer (run by before-bundle.ps1; shipped by the
// `bundle.resources` of tauri.bundle.conf.json, so it lands in <install>\extension\ and
// <install>\extension-firefox.zip; the extension setup guide, src-tauri/src/setup_guide.rs, points
// there):
//
//   src-tauri/extension/            the unpacked extension for "Load unpacked" in Chrome, Edge and
//                                   Brave: the repo's manifest.json WITH "key" (the ID the native
//                                   host allows) and the same files as
//                                   Extension/dist/pass-chromium-unpacked.zip
//   src-tauri/extension-firefox.zip the Firefox package (pass-firefox.zip) for a temporary add-on
//
// The file list comes from Extension/scripts/package.mjs (no tests, scripts, node_modules, dist or
// dotfiles), so the installer ships exactly what the store packages ship.
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { buildPackages } from "../../../Extension/scripts/package.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const extension = resolve(here, "../../../Extension");
const target = resolve(here, "../src-tauri");
const folder = join(target, "extension");

const pkg = await buildPackages(extension);
await rm(folder, { recursive: true, force: true });
for (const file of ["manifest.json", ...pkg.files]) {
  const dest = join(folder, ...file.split("/"));
  await mkdir(dirname(dest), { recursive: true });
  await writeFile(dest, await readFile(join(extension, ...file.split("/"))));
}
const manifest = JSON.parse(await readFile(join(folder, "manifest.json"), "utf8"));
if (!manifest.key) throw new Error("Extension/manifest.json has no \"key\": the native host would refuse the unpacked extension");
await writeFile(join(target, "extension-firefox.zip"), pkg.firefox);
console.log(`staged src-tauri/extension (${pkg.files.length + 1} files) and src-tauri/extension-firefox.zip (${pkg.firefox.length} bytes)`);
