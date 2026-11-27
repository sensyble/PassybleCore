// The OS the app runs on ("windows", "macos", "linux": `status`'s `platform`), kept from the last
// `status` main.js read, so views can leave out what this OS has no use for (linux-hidden.js).
// Unknown (an older backend, or before the first `status`): nothing is hidden, and the webview's
// user agent tells the title bar and the key names which OS this is (WebView2 says "Windows",
// WKWebView "Macintosh", WebKitGTK "Linux").

import { invoke } from "./lib.js";
import { hiddenOn } from "./linux-hidden.js";

let platform = "";

/** Keeps `status.platform` (main.js calls it with every status it reads). */
export function setPlatform(name) {
  if (typeof name === "string" && name) platform = name;
}

/** The platform, reading `status` once if nothing has set it yet. Never fails. */
export async function platformReady() {
  if (!platform) {
    const status = await invoke("status").catch(() => null);
    setPlatform(status && status.platform);
  }
  return platform;
}

/** The platform as `status` said ("windows", "macos", "linux"), or "" before the first `status`. */
export function platformName() {
  return platform;
}

/** The platform `status` named, else the one the user agent names ("" when it names none). */
export function platformGuess() {
  if (platform) return platform;
  const agent = typeof navigator === "undefined" ? "" : `${navigator.platform || ""} ${navigator.userAgent || ""}`;
  if (/Mac/i.test(agent)) return "macos";
  if (/Win/i.test(agent)) return "windows";
  if (/Linux|X11/i.test(agent)) return "linux";
  return "";
}

/** True on a Mac: shortcuts use Cmd where Windows and Linux use Ctrl, and show as ⌘ ⇧ ⌥ ⌃. */
export function isMac() {
  return platformGuess() === "macos";
}

/** True when this OS leaves out the row, line or tip named by i18n key `key` (linux-hidden.js). */
export function hidden(key) {
  return hiddenOn(platform, key);
}
