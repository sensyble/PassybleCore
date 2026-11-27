# A vault in the browser extension, without the Windows app (design)

Status: **design approved; Phase A built.** Written 2026-11-06 against branch `integrate/3l`,
with a throwaway feasibility probe (section 3.4) that is not part of the repository. The owner approved
every recommendation (section 11, now the decisions). Phase A is built on branch
`feature/extension-vault` (section 13, the API in section 14): steps 1 and 2, the Rust side (wasm-ready core,
the portable agent, the `pass-wasm` crate, the build script), and step 3, the JavaScript side (`LocalBackend`,
the modes, the setup, popup and Options UI, the translations, tests; section 13.8). **Phase B pulled forward for
Google Drive only** (2026-11-08, branch `feature/extension-drive`, section 15): a vault in the browser now always
lives in Google Drive (or the desktop app); the extension no longer creates a vault that lives only in this
browser. The rest of Phase B is next.

The owner's request: *"make the extension so that it can run without window app (unless the vault is in
windows app). even allow own vault in the extension".* Then, on 2026-11-08: *"let's not allow vaults to be
created in extension, as it is not safe. the vaults need desktop app or google drive login or account".*

Today the extension is a thin client of the desktop app: every request goes over native messaging to the
desktop agent (docs/PROTOCOL.md §2), which holds the vault, does the crypto, syncs, unlocks with Windows
Hello, copies to the clipboard and signs passkeys. This document designs a second mode in which the
extension holds its own vault, on any computer that runs Chrome, Edge or Brave (Windows, macOS, Linux,
ChromeOS) and later Firefox, while the existing mode stays exactly as it is for people who keep their vault
in the Windows app.

## 0. Summary

* **Two modes, one at a time per browser profile.** "Use the Passyble app on this PC" (today, unchanged)
  or the vault in the browser (new), which always comes from the user's Google Drive (built) or a Passyble
  account (Passyble Cloud, later); the browser keeps an encrypted copy. No vault lives only in the browser
  (2026-11-08). The first run picks for the user when the app is installed and asks when it is not.
  Options can switch later. The two vaults are never shown or saved to at the same time.
* **One protocol, two backends.** The background script keeps calling `agent(method, params)` with the
  PROTOCOL.md §2 methods. In app mode the call goes to the native host as today. In browser mode it goes
  to a **BrowserAgent inside the extension: the desktop agent's own request handlers (`pass-agent`) and
  pass-core, compiled to WebAssembly**. Content scripts, menus, banners, passkey cards and most of the
  popup need no change, and the policy rules (URL binding, pending 2FA window, save decisions, rate
  limits, passkey RP ID checks) are the same Rust code in both modes.
* **No JavaScript crypto.** The vault format, Argon2id, XChaCha20-Poly1305, merge, TOTP, generators,
  passkey signing, import and export all come from pass-core. The vault file the extension writes is
  byte-for-byte the format the apps write, so it syncs with them.
* **Feasibility, measured:** pass-core with every feature except networking compiles for
  `wasm32-unknown-unknown` unchanged (plus two randomness features). pass-agent compiles once its IPC
  module is gated out. Argon2id with the vault defaults (64 MiB, t = 3, p = 1) takes **114 ms in V8**
  (native: 94 ms, same output). A release build is about **3 MB, 0.9 MB gzipped**. The networking stack
  (ureq + rustls/ring) does not build and could not work in a browser anyway, so sync moves to `fetch`
  driven by a sans-IO version of the core's sync code.
* **Storage:** the encrypted vault file in the extension's IndexedDB (`unlimitedStorage`), never in
  `chrome.storage.sync`. Nothing secret is stored in the clear: device-local secrets (a WebDAV password,
  a server token) are sealed with the vault key.
* **The unlocked key** lives in `chrome.storage.session` (memory only, trusted contexts), so a service
  worker that the browser stops is rebuilt in milliseconds with `Vault::unlock_with_key`. Auto-lock by
  timer, on the computer locking (`chrome.idle`), and always on browser exit or extension update.
* **Unlock:** master password in extension pages only (popup, the in-page unlock frame, an unlock
  window). Quick unlock with a passkey through **WebAuthn PRF** (Windows Hello, Touch ID, a phone, a
  security key, wherever the browser and authenticator support PRF). No short PIN. Recovery code as in
  the apps.
* **Sync:** Google Drive (`chrome.identity.launchWebAuthFlow`, same Google Cloud project so the same
  hidden app folder as Android and Windows; built, section 15), WebDAV and Passyble Server over `fetch`
  (later). No cloud folder.
* **Reduced or app-only:** auto-type into native apps, the Windows passkey provider, Windows Hello as
  such (replaced by PRF), keeping copied secrets out of Windows clipboard history, cloud-folder sync,
  self-signed pinned servers.
* **Phases:** A (L) wasm core and portable agent, local vault, master password, autofill, save prompts,
  generator, 2FA, backup file. B (L) sync (Google Drive built first, section 15), passkeys, PRF quick
  unlock, recovery code, full vault page.
  C (M to L) import, export, health, icons, multiple vaults, Firefox, moving a vault between app and
  browser.

## 1. Goals, non-goals, invariants

Goals:

1. Passyble works in Chrome, Edge and Brave on any desktop OS with no other software installed.
2. A browser vault is a normal Passyble vault: same file format, same master password rules, opens in
   the Windows and Android apps, syncs with them through Google Drive, WebDAV or Passyble Server.
3. App mode stays exactly as it is: no new prompts, no vault data in the browser, no network requests
   from the extension.
4. One implementation of the security-relevant rules, shared with the desktop agent.

Non-goals (for now): Safari; mobile browsers (the Android app covers phones); acting as the operating
system's passkey provider for native apps; a JavaScript reimplementation of anything in pass-core.

Invariants (a change that breaks one is a bug):

1. Decrypted secrets never reach `chrome.storage.local`, `chrome.storage.sync`, IndexedDB, the page's DOM,
   a URL, a log line or a message to a content script other than the one value being filled.
2. Only the encrypted vault file and sealed blobs are written to disk. Only the encrypted vault file
   leaves the device (to the sync target the user chose).
3. The master password is typed only into extension pages, never into the page's DOM.
4. In app mode the extension behaves exactly as before this feature (it doesn't even load the wasm).
5. The extension loads no remote code. The wasm is part of the package and built from this repository.

## 2. Modes

### 2.1 The two modes

| | **Use the Passyble app on this PC** (`vaultMode: "app"`) | **The vault in Google Drive** (`vaultMode: "browser"`) |
|---|---|---|
| Where the vault is | The desktop app (today) | The user's Google Drive (the apps' hidden app folder), with an encrypted copy in the extension's IndexedDB. Later also Passyble Cloud |
| Backend of `agent()` | `NativeClient` → native host → agent | `LocalBackend` → wasm BrowserAgent |
| Unlock | Windows Hello, master password (app or in-page frame) | Master password (extension pages), passkey quick unlock (PRF, later) |
| Sync | The app's | The extension's own (Google Drive built; WebDAV, Server later) |
| Network requests by the extension | None (Sign in only opens the website in a tab) | `account.passyble.com` after the user clicks Sign in (13.8); Google (sign-in, Drive) for the vault; later opt-in HIBP range queries, website icons (if on), alias services (if set up) |
| Platforms | Windows with the app | Any desktop OS with a Chromium browser (Firefox later) |

`vaultMode` is a plain setting in `chrome.storage.local`. It is not a secret.

**No vault only in the browser (2026-11-08).** The owner: *"let's not allow vaults to be created in
extension, as it is not safe. the vaults need desktop app or google drive login or account".* A vault
kept only in IndexedDB is lost with the extension or the profile, so browser mode never creates or opens
one: a vault comes from the desktop app (app mode), the user's Google Drive, or a Passyble account
(Passyble Cloud, not ready server side yet). Section 15 is how it was built.

### 2.2 Detection and first run

The background already tells "host not installed" from "app not running" (`isHostMissing`, the error
"Specified native messaging host not found" on Chromium, its Firefox equivalent). On
`runtime.onInstalled` with `reason: "install"` (and whenever `vaultMode` is unset), the background sends
one `status` with a short timeout:

| result | what happens |
|---|---|
| The app answers | `vaultMode = "app"`, silently. The setup guide shows the app checklist and one line, "The Passyble app is installed on this computer, so Passyble uses it here." (no mode choice, §2.6). |
| The host is installed, the app isn't running (`agent_unavailable`) | `vaultMode = "app"` (the app is on this PC). The guide shows today's "Start Passyble" step, and the same line. |
| No native host | The setup guide asks (below). Nothing is created until the user picks. |

The choice screen (in `src/welcome/`, the page that already opens on install), titles only (as built,
2026-11-08):

1. **Continue with Google Drive**: Google's sign-in, then **Choose a vault** (the vaults in that
   account's app folder, by name and change date; a vault made in the Windows or Android app is there)
   and its master password. Or **Create a vault** (name, default "Personal", master password twice with
   the app's strength rules, the "can't reset" warning), created in Drive at once. Or **Upload a vault
   file** (a `.vault` file and its master password, put into Drive). An empty Drive goes straight to
   create.
2. **Sign in** (Passyble account): signs in, then one line "Passyble Cloud storage is coming soon." and a
   **Use Google Drive** button.
3. On Windows only: **Get the Windows app** (link to the download page).
4. In app mode with a browser vault kept here: **Use the vault in this browser**.

WebDAV and Passyble Server are not offered yet. There is no "Open a vault file" that keeps the vault only
here, and no backup step.

Updating users: an existing install with `vaultMode` unset and no browser vault is set to `"app"`
without asking, so nothing changes for them.

### 2.3 Both at once? No.

One backend per browser profile. Running both would mean two lists in every menu, a save prompt that has
to ask "which vault?", and two lock states, for little gain: someone with the app on this PC already has
their vault there, and someone who wants the same vault on another computer gets it through sync (the
same `vault_id` in both places). The phrase "unless the vault is in the Windows app" maps directly to app
mode.

### 2.4 Switching

Options → **Where your vault is** (a new first card):

* **Browser → app**: the browser vault is locked and kept, untouched and inactive. A Drive vault is
  already in Drive, so the app opens the same vault with "Restore from Google Drive". (As built: a Drive
  vault is never deleted from Options; **Sign out** of Google forgets its copy here. Only a legacy vault
  kept only in this browser has "Delete", guarded by a copy downloaded in the last hour and the master
  password.)
* **App → browser**: the same choice screen as the first run (Google Drive, Sign in). The app's vault is
  not copied over native messaging in Phase A or B; it gets into the browser through Google Drive.
* If the app appears later on a PC that uses browser mode, the extension switches to it on its own and offers
  to move the browser's items (§2.6, 2026-11-25; until then this was one dismissible tip and never a switch).
* App → browser is offered only while the app isn't installed on this computer (§2.6).

### 2.5 What the popup and options show

**Popup, browser mode.** The same header (logo, lock chip, Lock, ⋯), search and rows as today. Changes:

* The lock chip reads "Locked" / "Unlocked"; its tooltip names the vault ("Personal, in this browser").
* Locked: the master password field is the popup body (it already has one for `unlock.inline`), plus
  **Unlock with passkey** when quick unlock is set up, plus **Forgot master password?** (recovery code).
  No "Passyble isn't running", no **Start Passyble**.
* No vault yet ("No vault yet"): **Continue with Google Drive** and **Sign in**, which open the setup
  page in a tab.
* A chip at the bottom (as built): **Not synced** (changes not in Drive yet, or the last sync failed;
  opens Options' Vault part) or **Only in this browser** (a legacy vault; opens setup at Move to Google
  Drive). Nothing while synced.
* ⋯ menu: **Google Drive** (Options' Vault part; it replaced "Back up"), Settings, Setup guide, and the
  Sensyble link as today; **Open vault** (the full vault page) comes later. No "Add Passyble Server".

**Popup, app mode.** Unchanged.

**Options, browser mode.** Existing cards (Autofill, Sites without save prompts, Passkeys, Shortcuts,
About) stay. New cards: **Where your vault is** (2.4); **Vault** (name, change master password, recovery
code, quick unlock with a passkey, lock after N minutes of inactivity (1, 5, 15 default, 30, 60, only when
the browser closes), lock when the computer locks, download a copy); **Sync** (WebDAV, Passyble Server
later); **Import and export** (Phase C); **Password health** (Phase C). **Passyble Server** moves into Sync.

As built (2026-11-08), under the **Vault** heading: the mode row says **In Google Drive**; a **Google
Drive** row with the account and "Synced <time>", "Not synced", "Sign in to Google again" or "Syncing...",
with **Sync now** (or **Sign in again**) and **Sign out** (with pending changes: "Changes not in Google
Drive yet will be lost." and **Sign out anyway**); for a legacy vault an **Only in this browser** row with
**Move to Google Drive** and the guarded **Delete**; **Download a copy**; the lock settings.

**Options, app mode.** Unchanged, plus the **Where your vault is** card.

### 2.6 The Passyble app always wins (2026-11-25)

The owner: *"if there is desktop application, always sync with desktop application".* Whenever the Passyble app is
installed on this computer, the extension uses it.

**Installed** means the native host is registered for this browser: `connectNative` answers, or answers "the app isn't
running" (`agent_unavailable`, a timeout), rather than "host not found" (`isHostMissing`). One look has three outcomes
(Extension `src/shared/vault-mode.js`, `hostOutcome`): `connected`, `installed`, `missing`. `nextHostState` turns an
outcome into the stored state (`vaultMode`, `vaultHostSeen`, `vaultHostMisses`, `vaultAppGone`, all plain settings in
`storage.local`):

| outcome | before | after |
|---|---|---|
| `connected` or `installed` | anything | `vaultMode = "app"`, `vaultHostSeen = "present"`, misses and "gone" cleared. From browser mode: the switch, and the move offer below |
| `missing` | the app never seen here | `vaultHostSeen = "missing"` at once: browser mode allowed as before |
| `missing` | the app seen (`present`) | one miss counted, at most once per minute; still installed. Three counted misses in a row: `vaultHostSeen = "missing"`, `vaultAppGone = true` (in app mode), mode unchanged |

So the extension never leaves app mode because the app is closed or slow (installed is as good as connected), and one
failure, a burst of failures or a failure followed by an answer never counts as an uninstall.

**Where the looks come from.** In app mode every request to the native host tells (`agent()`); nothing extra is sent.
In browser mode (or before a mode is set) the background sends one `status` on a fresh port when the popup opens (at
most every 10 minutes), when the browser starts, after an update, and when Options or the setup guide opens (at most
every 15 s), and closes the port again. On Safari the extension ships inside the Passyble app: always app mode.
Firefox: the same as Chromium where native messaging exists; `browserVaultSupported` is unchanged.

**What the user sees.**

* *A fresh install with the app* (running or not): app mode at once. The setup guide skips the mode choice (whatever
  its `#hash`) and shows the app checklist with "The Passyble app is installed on this computer, so Passyble uses it
  here." Options shows that line instead of the mode switch. `vault.create`, `vault.open-file` and `vault.set-mode` to
  `browser` answer `invalid_state` while the app is installed.
* *The app closed*: app mode stays; the popup's "Passyble isn't running" with **Start Passyble** (the host starts it).
* *Browser mode, then the app is installed*: app mode on its own at the next look. The vault in this browser is locked
  and kept as it is. With items in it, the popup offers once: "Move 23 items from this browser into the Passyble app"
  (counted with the vault's `vaults.list` while it is open; locked: "Move the items in this browser into the Passyble
  app"). **Move** opens Options' move card; the close button is **Not now**. Either answer ends the popup's offer; the
  card stays in Options.
* *The app uninstalled* (three spaced misses): Options says "The Passyble app is no longer on this computer. You can
  keep a vault in this browser instead." with the switch, which opens the setup guide's choice (or uses a vault kept
  here). No vault is created on its own.

**The move** (Options, `vault.move`). The user types the browser vault's master password (the Passyble password for a
vault linked to an account) and, when the app has more than one vault it can edit, picks one (`vault.move-targets`,
from the app's `vaults.list`; default the home vault). The background:

1. checks the app: `status` answers and lists `items.import` (else "This needs a newer Passyble app");
2. opens a second BrowserAgent on the vault file with that password (`LocalBackend.exportForMove`): a wrong password
   stops here; the vault in this browser itself stays locked and no lock event fires;
3. sends the encrypted vault file and its vault key once, `items.import { file, key, vault? }` (PROTOCOL.md §2); the
   app is locked: its own unlock prompt (`unlock`), then once more. The master password never leaves the extension
   and is never kept; the key is zeroed once sent;
4. the agent opens the file in memory and adds every live item as a new item: logins with their 2FA secret, passkeys,
   notes, custom fields, tags and password history, secure notes, cards and identities. **Exact duplicates are
   skipped**: a login when the app has one with the same site (a host in common, `www.` and case ignored), the same
   username and the same password, and the incoming one brings nothing that one lacks (another 2FA secret, a passkey,
   other notes); any other item when one of the same kind has the same content. The answer: `total`, `added`,
   `skipped`, `failed_count` and the titles of what failed;
5. keeps the outcome (`vaultMove`): `moved`, or `partial` when something failed. Options then shows "Moved into the
   Passyble app" (added, already in the app) with **Delete the vault in this browser**, or "Some items could not move"
   with their titles and **Try again** (duplicates are skipped, so only what is missing moves). After a partial move
   nothing can be deleted.

**Delete after a move** (`vault.delete-moved`): only for the vault that was moved completely, and only after the
confirmation in Options ("Deletes the vault in this browser for good. Its items are in the Passyble app now.").
Declining the move ("Not now", or never answering) loses nothing: the vault in this browser stays, locked, and can
still be moved later.

## 3. Architecture and code sharing

### 3.1 One protocol, two backends

```
 content scripts, popup, options, unlock frame (unchanged message types)
                 │ runtime.sendMessage
                 ▼
 background.js ── agent(method, params) ──► backend()
                                              │
                ┌─────────────────────────────┴──────────────────────────────┐
                │ vaultMode "app"                                             │ vaultMode "browser"
                ▼                                                             ▼
   NativeClient (today)                                         LocalBackend (new, src/background/local/)
   connectNative("com.sensyble.pass")                            • loads pass_wasm (wasm-bindgen, target web)
                │                                                • BrowserAgent.handle(request line) → response
                ▼                                                • VaultStore: IndexedDB
   native host ⇄ desktop agent (pass-agent)                      • key: chrome.storage.session
                                                                 • timers: chrome.alarms, chrome.idle
                                                                 • effects: clipboard, lock_state events
                                                                 • sync driver: fetch + identity
                                                                              │
                                                       pass-agent (portable build) + pass-core in wasm
```

`LocalBackend` exposes the same surface as `NativeClient` (`request(method, params)`, `on(event, fn)`,
`connected`), so `agent()`, `withUnlock()`, the retry rules and every `popup.*` handler keep working. The
envelope is the native one (`{id, method, params}` → `{id, result}` / `{id, error: {code, message}}`), and
`BrowserAgent.handle` is `Agent::handle_line`, the function the native IPC server already calls. Error
codes are the same; browser mode never answers `agent_unavailable`, and adds `no_vault` (no browser vault
yet: the popup shows the setup buttons).

Vault management that has no PROTOCOL.md §2 method today (create, change master password, recovery code,
sync settings, backups, import, export) gets new **extension-internal** methods with a `vault.` and
`sync.` prefix, handled by `LocalBackend` and the wasm crate and reachable only from extension pages (the
same rule as the `popup.*` handlers: never from a content script). They are documented in PROTOCOL.md §2,
"Extension notes", not on the native wire.

### 3.2 What the Rust side looks like

*Phase A steps 1 and 2 built this; where the build differs from the plan below (a `Clock` trait next to
`web-time`, the store's methods, an Argon2id runner instead of a raw host import, the exports, `npm run
package` not building the WebAssembly itself), section 13 says how and why.*

**pass-core** (`Core/core/`), Phase A changes are small:

* `now_ms()` (`Core/core/src/lib.rs`) uses `std::time::SystemTime::now()`, which **panics** on
  `wasm32-unknown-unknown` (std has no clock there; `cargo check` can't see this). On wasm it reads
  `js_sys::Date::now()` (or the `web-time` crate). It is the only clock in the modules the extension uses
  (`icons`, which also uses `Instant`, stays off).
* `[target.'cfg(target_arch = "wasm32")'.dependencies]`: `getrandom 0.2` with `js` (rand's `OsRng`, used
  for keys, nonces, salts and generators: `crypto.getRandomValues`) and `uuid` with `js` (vault and item
  ids). Without them the build stops with a `compile_error!` (seen in the probe).
* A small public API for sealing device-local data with the vault key (section 4.3) and for wrapping the
  vault key with a quick-unlock secret (section 5.2), so the extension's JavaScript never does crypto.
* Phase B: the sans-IO sync (section 6.1; Google Drive built, section 15).
* A check: `cargo check --target wasm32-unknown-unknown -p pass-core --no-default-features --features
  import-kdbx,import-pgp,import-qr`, so the wasm build can't silently break.

**pass-agent** (`Core/agent/`), the "portable agent" (Phase A, M to L). Reusing the agent instead of
writing a second dispatcher keeps the ~40 methods and their policy identical, and its existing Rust tests
cover both builds. What it takes:

* A `native` feature (default on) that gates `ipc.rs` and the `interprocess` dependency (the only compile
  error in the probe), the DPAPI kept list (`kept_list.rs` is already `cfg(windows)` for DPAPI), the
  conflict-copy scan of a cloud folder, `platform_passkey.rs` (Windows passkey provider) and `timing.rs`
  file output.
* Clocks: 26 uses of `Instant::now()` / `SystemTime::now()` (agent.rs, otp_history.rs, protocol.rs,
  kept_list.rs, timing.rs) switch to `web_time::{Instant, SystemTime}`, a drop-in that re-exports std on
  native.
* Persistence: the 11 `std::fs` calls in agent.rs go behind a `VaultStore` trait (`load`, `save`,
  `changed_since`). Native: today's file code. Browser: a host callback that hands the serialized vault to
  JavaScript, which writes IndexedDB. There is one writer (the service worker), so `reload_if_changed`
  becomes a no-op in the browser.
* The save delay thread (`save_soon`, agent.rs:873) and the usage save delay run from `Agent::tick()` when
  threads aren't available (`std::thread::Builder::spawn` returns an error on wasm; the host calls `tick`
  from an alarm and after each request).
* A browser `Ui` (in the wasm crate). The `Ui` methods block in the desktop app; in the browser no call
  may wait for a person, so decisions travel with the request (section 3.3).
* `status.features` per host: browser mode drops `unlock.hello_browser`, `totp.from_image` unless the QR
  feature is in, and adds `vault.browser`.

**pass-wasm** (`Core/wasm/`, new crate, workspace member but not a default member):

* Depends on `pass-agent` (`default-features = false`) and `pass-core` (`default-features = false`,
  `import-kdbx`, `import-pgp`, later `import-qr`), `wasm-bindgen`, `js-sys`.
* Exports: `BrowserAgent { new(config_json), load(file, vault_key), handle(line) -> String, tick(now_ms),
  take_effects() -> String, lock(), session_snapshot() -> bytes, restore_session(bytes) }`, plus free
  functions for the `vault.*` and `sync.*` methods. JSON strings at the boundary, like the agent's own
  protocol, so the JS glue stays a few hundred lines and the Rust side is testable natively
  (`cargo test -p pass-wasm`).
* `Core/wasm/kdf/` (`pass-wasm-kdf`): a second, tiny module with only Argon2id and a raw C ABI
  export (no JS glue). The probe's equivalent is 52 KB. See section 3.5.
* Built by `Extension/scripts/build-wasm.mjs`: `cargo build --release --target wasm32-unknown-unknown`
  through `scripts\cargo-low.cmd` locally, then `wasm-bindgen --target web` (the CLI version pinned to
  the crate's) and `wasm-opt -Oz`, writing `Extension/src/wasm/` (git-ignored). `npm run package` requires
  it (`npm run release` builds, then packages; section 13.8); for "Load unpacked" during development, `npm run
  wasm` once. The size budget is 1.5 MB gzipped (the build fails above it).

Android keeps using pass-core through UniFFI; nothing there changes. The UniFFI and wasm-bindgen exports
stay separate (`cfg_attr(feature = "uniffi", ...)` in core, the wasm-bindgen surface only in pass-wasm),
so core gets no wasm-bindgen attributes.

### 3.3 UI decisions without blocking

Every `Ui` method of the desktop agent (lib.rs, 22 methods) gets a browser answer:

| desktop `Ui` method | browser |
|---|---|
| `request_unlock` (the app's unlock window) | Never reached: `LocalBackend` handles `unlock` itself by opening the popup (`action.openPopup()` where allowed, else a small extension window `src/unlock/window.html`) and resolving when the vault is open |
| `unlock_options`, `unlock_with_password`, `unlock_with_hello`, `cancel_unlock`, `hello_in_browser` | `unlock.options` answers `{ password: true, hello: false, passkey: bool }`; password unlock is section 5.1; no Windows Hello |
| `confirm_passkey_create`, `choose_passkey`, `choose_passkey_for_browser` | The extension's passkey cards already decide in the page and send `consent` and the chosen credential; a request without a browser decision is `cancelled` |
| `verify_user`, `verify_item` (per-fill verification) | Off by default: `Allowed`. With the policy on, the request first fails with a new code `verification_required`; `LocalBackend` runs the check (master password or a passkey assertion with user verification, in an extension page) and retries once with a short-lived grant that only it can attach |
| cross-site fill confirmation (`logins.fill_cross`) | The popup asks "Fill the login of example.com on other.com?" itself; the grant is attached only to popup-originated requests |
| card fill confirmation | An extension-origin confirmation frame in the in-page menu (like the unlock frame), never page DOM; or the popup pick itself |
| `show_totp_popup` | `not_supported`; the extension's OTP toast already covers this |
| `copy_to_clipboard` (`generate.copy`, `logins.copy`, card copies) | An effect drained with `take_effects()`; the extension copies and clears after 45 s (section 7) |
| `notify_lock_state` | An effect; `LocalBackend` emits the same `lock_state` event the native client does |

### 3.4 Feasibility probe (done)

A throwaway crate in a temporary folder (`wasm-probe`, not committed) depended on this branch's `Core/core/`
by path, with the lock file copied from the workspace; a second one (`kdf-bench`) held only the same
`argon2` and `chacha20poly1305` versions. Target `wasm32-unknown-unknown`, rustc 1.99.0, run in Node
26.2 (V8, the same engine as Chrome), on the owner's desktop CPU at idle priority.

| step | result |
|---|---|
| `pass-core`, `default-features = false` | First error: `uuid` needs a randomness source on wasm32 (`compile_error!`). With `uuid/js` and `getrandom 0.2/js`: **compiles** (3 dead-code warnings for sync-only helpers) |
| + `import-kdbx`, `import-pgp` (KeePass, rPGP) | compiles |
| + `import-qr` (image, rqrr) | compiles |
| + `webdav` (ureq, rustls with ring) | **fails**: ring's build script needs clang for wasm32. Even if it built, ureq opens TCP sockets, which a browser doesn't offer. Networking must move to `fetch` |
| `pass-agent`, `default-features = false` | **fails only in `interprocess`** ("target operating system is not supported") |
| a copy of `pass-agent` with `mod ipc` cfg'd out | **compiles** with no other change. Its runtime hazards (clocks, `std::fs`, threads, blocking `Ui`) are listed in 3.2 |
| release size: one export touching vault create/unlock/serialize/merge, URL matching, TOTP, passkey create, password check, health, CSV import, encrypted export, search (`opt-level = "z"`, LTO, no wasm-bindgen or wasm-opt yet) | **3.03 MB, 0.89 MB gzipped**. With KeePass and PGP import: 4.68 MB, 1.38 MB gzipped. Embedded data accounts for part of it (core text catalogs 304 KB, 2FA and passkey directories 190 KB, the Public Suffix List) |
| compiling the module (`new WebAssembly.Module`) | 4 ms (3 MB) and 6 ms (4.7 MB): V8 compiles lazily |
| Argon2id m = 19 MiB, t = 2, p = 1 | 18 ms in wasm, 19 ms native |
| **Argon2id m = 64 MiB, t = 3, p = 1 (vault default)** | **114 ms in wasm, 94 ms native, identical output.** The instance's memory grows to 84 MiB and never shrinks |
| same with p = 4 | 118 ms (no threads in wasm: lanes run one after another; same memory) |
| `+simd128` | no gain (112 ms) |
| XChaCha20-Poly1305, 1000 records of 1 KiB, seal and open | 4 ms |

Conclusions: the core and the agent's logic port without restructuring; networking is the one real piece
of work; the KDF is fast enough on desktops (expect roughly 5 to 8 times slower on a low-end Chromebook,
still under a second), but its 64 MiB should not stay in the long-lived instance.

What the probe did not test, and Phase A must: wasm-bindgen glue in a real MV3 service worker
(`import` of the generated module, `fetch` of the `.wasm` from the package), `getrandom` through
`crypto.getRandomValues` in a service worker, the size after wasm-bindgen and `wasm-opt`, and the time
to rebuild an unlocked vault from `storage.session` on a service-worker restart (estimated well under
50 ms for 1000 items from the AEAD figure above).

### 3.5 Where Argon2id runs

Argon2id runs for create, unlock, change master password, recovery code create and unlock, encrypted
export and import, and the Passyble Server sign-in key. Running it in the agent's long-lived instance
would keep 84 MiB of wasm memory for as long as the service worker lives (an active browsing session keeps
it alive for hours). Instead:

* On wasm, `crypto::derive_kek_bytes` calls a host import `pass_kdf(secret, salt, m_kib, t, p) -> key`.
  The host instantiates the 52 KB `pass-wasm-kdf` module afresh (synchronous instantiation is allowed
  outside a window's main thread), runs it, zeroes its memory and drops it; the garbage collector frees
  the 64 MiB. (Built as a runner the core calls, `pass_core::set_argon2id_runner`, which pass-wasm sets
  from JavaScript with `setKdf(fn)`; the module is 38 KiB. Section 13.)
* A unit test in pass-wasm checks that `pass_kdf` and core's native `derive_kek` give the same key for the
  same inputs, so the two can't drift (they are the same `argon2` crate from the same lock file).
* This works the same in a Chrome service worker (which can't start a dedicated `Worker`) and a Firefox
  event page, with no offscreen document.
* The service worker is busy for that ~0.1 s (up to ~1 s on slow devices). Unlocking is the only
  frequent case, and nothing else needs to run during it.

Fallback if this turns out awkward: run the KDF in the main instance and accept the memory until the
service worker is next stopped.

### 3.6 Manifest and CSP

```jsonc
"content_security_policy": {
  "extension_pages": "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'"
},
"permissions": [ /* today's */, "idle", "unlimitedStorage" ],   // "identity" added in Phase B
```

* `'wasm-unsafe-eval'` allows compiling wasm and nothing else (no `eval`, no remote script). Declare it
  explicitly for Chromium and Firefox alike.
* `idle` (lock when the computer locks), `unlimitedStorage` (vault storage that is never evicted) and
  `identity` (Google Drive sign-in) show no install warning in Chrome, so existing users are not asked to
  re-approve the extension.
* `nativeMessaging` stays required (decision 11).
* The `.wasm` files are loaded only by extension contexts, so they are not `web_accessible_resources`.

## 4. Storage and the key

### 4.1 What goes where

| data | where | protected by |
|---|---|---|
| The vault file (`Vault::serialize`, including the local-only `sync` state) | IndexedDB `passyble` → `vaults[vault_id].file` | The vault's own encryption (Argon2id-wrapped vault key, XChaCha20-Poly1305 items). Cleartext metadata exactly as in any synced copy (ids, timestamps, device ids, KDF parameters) |
| The previous good copy | `vaults[vault_id].prev` | same |
| Vault display name, created and last-backup times; as built also `source: "drive"`, the Drive account e-mail, `pending`, `syncedAt`, `syncError` | `vaults[vault_id]` | none needed (not secret; the same name is in clear on Drive) |
| Device-local secrets: WebDAV app password, Passyble Server device token | `local[vault_id]`, one blob | Sealed with the vault key (core, AAD `"pass/browser-local/v1:" + vault_id`). Readable only while unlocked, which is when sync runs |
| Quick unlock: credential id, PRF salt, vault key wrapped by the PRF secret | `quick[vault_id]` | The authenticator (section 5.2) |
| Website icon cache (Phase C) | `icons`, keyed by an HMAC of the domain under the vault key | Each icon sealed with the vault key, so a copied profile doesn't list the user's sites |
| Settings: `vaultMode`, auto-lock minutes, lock on computer lock, device id and name, the existing autofill toggles | `chrome.storage.local` | none needed (not secret) |
| The unlocked vault key, the agent's session snapshot, the soft-lock list | `chrome.storage.session` | Memory only, trusted contexts (4.2) |
| Google access token (1 hour) and its account e-mail (`passGoogleToken`) | `chrome.storage.session` | Memory only, trusted contexts |

Never used for anything vault-related: `chrome.storage.sync` (it is uploaded to the browser vendor's sync).

**Why IndexedDB, not `chrome.storage.local`:** the vault is binary and can grow past `storage.local`'s 10
MB quota without `unlimitedStorage`; IndexedDB stores `ArrayBuffer`s and has transactions (vault and
previous copy are replaced together); and content scripts can call `chrome.storage.local` but run in the
page's origin for IndexedDB, so they can't reach the extension's database at all. With `unlimitedStorage`
the extension's storage is not evicted under disk pressure; the setup page also calls
`navigator.storage.persist()`.

**Format.** `vaults[id].file` is the exact file the apps read. "Download a copy" saves it as
`Passyble-<name>-<yyyy-mm-dd>.vault`; the Windows app can open it as a vault file and Android can import
it.

### 4.2 Keeping the key while unlocked

A Manifest V3 service worker is stopped after about 30 s without events, which drops the wasm instance and
the decrypted vault with it. Options considered:

| option | verdict |
|---|---|
| **Vault key in `chrome.storage.session`**; on each service-worker start, read the vault file from IndexedDB and `Vault::unlock_with_key` (no Argon2) | **Recommended.** `storage.session` is held in memory, never written to disk, cleared when the browser exits and when the extension is reloaded, updated or disabled, and by default (asserted at startup with `setAccessLevel({ accessLevel: "TRUSTED_CONTEXTS" })`) not readable by content scripts. Chrome 102+, Firefox 115+, 10 MB quota |
| Hold the unlocked agent in an offscreen document | Chrome and Edge only, and an offscreen document kept open only to hold state doesn't match any allowed `reason` honestly. Not chosen |
| A non-extractable WebCrypto key in IndexedDB wrapping the vault key | The key material is on disk in the profile (no OS protection for IndexedDB), so a copied profile unlocks the vault. Rejected |
| Keeping the service worker alive artificially | Against the platform's rules and the store policies. Rejected |

The agent's volatile state (pending 2FA windows, the save prompt's pending decision, rate-limit counters,
edit grants, search hits, recently generated passwords) is small. After each request that changed it,
`session_snapshot()` returns it sealed with the vault key and `LocalBackend` stores it in
`storage.session`; `restore_session()` puts it back after a restart. So only the 32-byte vault key is raw
in `storage.session`.

The soft lock (ARCHITECTURE.md §12) maps naturally: a soft lock drops the key and keeps the list of items
without secrets in `storage.session`, so the inline menu still lists logins and asks to unlock; after a
browser restart the vault is fully locked (there is no DPAPI equivalent to keep the list on disk safely).

### 4.3 Locking

* **Inactivity** (default 15 min, sliding with credential uses as in ARCHITECTURE.md §7): the agent's own
  `tick()` decides, called from a `chrome.alarms` alarm every minute while unlocked (30 s is the platform
  minimum) and after each request. Background methods (`BACKGROUND_METHODS`) don't count as activity, as
  on the desktop.
* **The computer locks**: `chrome.idle.onStateChanged` → `"locked"` → soft lock (Windows, macOS,
  ChromeOS; on Linux it depends on the desktop environment, so the inactivity timer is the safety net).
* **Browser exit**: `storage.session` is cleared by the browser. If the browser keeps running in the
  background after its last window closes, `windows.onRemoved` for the last window locks.
* **Extension update, reload or disable**: `storage.session` is cleared; the vault is locked afterwards.
* **Lock button, "Lock completely"**: as today.
* On every lock: `BrowserAgent.lock()` (core zeroizes keys it holds in `Zeroizing`), the key and the
  session snapshot are removed from `storage.session`, the wasm instance is dropped, and `lock_state` is
  sent to tabs as today.

### 4.4 Quota and size

A vault with 1000 logins is around 1 to 2 MB (each item a sealed JSON record, base64). Passkeys add a few
hundred bytes each. IndexedDB with `unlimitedStorage` has no practical limit here.

### 4.5 Data loss: uninstalling deletes the vault

Uninstalling the extension deletes its IndexedDB. "Clear browsing data" and "Reset settings" don't touch
extension storage, but uninstalling, a profile deleted by the user, or a broken disk do.

The Phase A plan nudged (a backup step at the end of setup, a **Not backed up** chip, a delete guard).
**As built (2026-11-08), a new vault always lives in Google Drive** (2.1, the owner's request): it is
created in Drive at once, every change goes there within seconds, and IndexedDB holds only a copy. Losing
the browser's storage then loses nothing that reached Drive. Changes that didn't (offline) are marked
`pending` in the same IndexedDB write as the change and show as **Not synced** until they are in Drive;
**Sign out** with pending changes warns first. The backup step and the chip are gone; **Download a copy**
stays in Options.

**Legacy vaults.** Developer installs of Phase A may hold a vault kept only in this browser (never
shipped). On an update the setup page opens at `#move` with its one action, **Move to Google Drive**
(unlock with the master password if locked, sign in to Google, upload). Until moved it stays usable, shows
**Only in this browser** (popup chip, Options row) and is never deleted automatically; its **Delete**
keeps the guard (a copy downloaded in the last hour, the master password).

## 5. Unlock

### 5.1 Master password

Typed only in extension pages: the popup's form, the in-page unlock frame (`src/unlock/frame.html`, an
extension-origin iframe inside the menu's closed shadow root, as today), the passkey cards' unlock (the
same frame), and `src/unlock/window.html` (for `unlock` requests that come with no popup open).

Flow in browser mode: the page sends `popup.unlock-password` to the background as today. `LocalBackend`
reads the vault file, `BrowserAgent` runs `Vault::unlock` (the KDF through the throwaway instance,
section 3.5), stores `export_vault_key()` in `storage.session`, saves the session, schedules a sync, and
answers `{ locked: false }`. The password is dropped right after the call; it is never stored or logged.
A wrong password answers `wrong_password` after the full KDF, which is the rate limit (offline guessing
against a copied file is the real threat either way, and Argon2id is its defence).

### 5.2 Quick unlock with a passkey (WebAuthn PRF)

Without the Windows app there is no Windows Hello integration of our own, but the browser offers the
platform's authenticator through WebAuthn, and the **PRF extension** turns a passkey into a key:

* **Set up** (Options → Vault → Quick unlock, while unlocked): an extension page calls
  `navigator.credentials.create` with `rp: { id: <extension id>, name: "Passyble in this browser" }`,
  `authenticatorSelection: { residentKey: "required", userVerification: "required" }` and
  `extensions: { prf: {} }`. If the result says `prf.enabled`, a `get` with
  `prf: { eval: { first: <32 random bytes> } }` returns a 32-byte secret. pass-wasm derives a wrapping key
  with HKDF-SHA256 (`info = "pass/browser-prf/v1"`) and wraps the vault key with XChaCha20-Poly1305 (AAD
  `"pass/browser-prf/v1:" + vault_id + ":" + credential_id`). Stored: credential id, salt, wrapped key.
  The secret itself is never stored.
* **Unlock**: **Unlock with passkey** runs the `get` (user verification required), passes the PRF output
  to pass-wasm, which unwraps the vault key and calls `unlock_with_key`. No Argon2.
* **Policy**: like the desktop's "Ask for the master password every N days" (default 30), quick unlock
  stops working until the master password was used once in that period; a master password change keeps
  it (same vault key); "Lock completely" and a key rotation (`rotate_key`) delete it.
* **Support** (verify at implementation, it moves fast): Chromium has the PRF extension; PRF works with
  Google Password Manager passkeys, most FIDO2 security keys (hmac-secret), phones over hybrid, iCloud
  Keychain on macOS, and Windows Hello on recent Windows 11 builds. The UI offers quick unlock only when
  `PublicKeyCredential.getClientCapabilities()` reports `extension:prf` **and** the created credential
  actually returned `prf.enabled`; otherwise it says "This browser or device can't unlock Passyble with a
  passkey" and the master password remains.
* **Main risk, to settle in a Phase B spike**: WebAuthn from a `chrome-extension://` origin with the
  extension id as RP ID (Chromium supports extension RP IDs; Firefox's `moz-extension://` support is
  unclear). If a browser doesn't allow it, quick unlock isn't offered there. Running the ceremony on a
  Passyble web page instead is rejected: it would put unlocking on a website and need the network.
* A synced passkey (Google Password Manager, iCloud) gives the same PRF output on every device, but the
  wrapped key exists only in this browser's IndexedDB, so it unlocks only this browser's copy.

### 5.3 A PIN? No.

A short PIN that wraps the vault key locally can be guessed offline from a copied profile (a million
six-digit PINs, each one Argon2id run, is days on one core and hours on a GPU), and the browser has no
hardware-backed attempt counter to offer. The safe "PIN" is the authenticator's own: Windows Hello's PIN,
a security key's PIN, a phone's lock screen, all through 5.2, where the hardware limits attempts.

### 5.4 Recovery code

Same as the apps (ARCHITECTURE.md §1, `Core/core/src/recovery.rs`): Options → Vault → Recovery code makes one
(`create_recovery_code`, shown once, with "Print" and "Copy"); the popup's **Forgot master password?**
takes the code (`unlock_with_recovery_code`), then asks for a new master password
(`change_master_password`) and offers a new code. Phase B (the core code exists; it is UI work).

## 6. Sync in browser mode

### 6.1 Sans-IO sync in the core

`webdav_sync`, `gdrive_sync` and the Passyble Server calls are written against ureq. The algorithms
(conditional `GET`/`PUT` with ETags, the 412 retry, weak ETags, Drive's version check and twin merging,
the server's sign-in and 2FA steps) are the valuable part and must not be rewritten in JavaScript. Phase
B turns each into a **sans-IO state machine** in pass-core:

```rust
pub struct HttpRequest  { pub method: String, pub url: String, pub headers: Vec<(String, String)>, pub body: Vec<u8> }
pub struct HttpResponse { pub status: u16, pub headers: Vec<(String, String)>, pub body: Vec<u8> }
pub enum   Step<T>      { Send(HttpRequest), Done(T) }

let (mut sync, first) = WebDavSync::start(vault, config)?;   // -> Step::Send(request)
loop { match step { Step::Send(req) => step = sync.on_response(transport(req)?)?, Step::Done(r) => break r } }
```

The native `webdav_sync` becomes this loop around ureq (same signature, same tests in `tests/webdav.rs`
and `gdrive/tests.rs`); pass-wasm exposes the machine; `LocalBackend` drives it with `fetch`. Transport
errors are classified in JavaScript into the same `PassError::Network` messages (`net.rs`'s texts move to
a function that takes a failure kind). Cost: M for WebDAV, M for Drive, M for the server calls.

(Considered and not chosen: async Rust with `wasm-bindgen-futures`, which would make core async for
Android and the desktop too; WebAssembly JSPI, which lets synchronous Rust wait on `fetch` but is not in
every browser yet; replaying the sync from a transcript, which is clever and fragile.)

**As built for Google Drive (2026-11-08).** Not hand-written state machines: `Core/core/src/http.rs` has
`HttpRequest`, `HttpResponse`, `FetchFailure`, `Step`, `Exchange` and a `Transport` trait, and
`Core/core/src/gdrive.rs` writes the Drive sync (version check, twins, merge, rename), the list, the download,
the delete and the account lookup once, as `async` functions over a `Transport`. The async is internal:
the public API stays blocking for Android and Windows (`gdrive_sync` and the others, same signatures and
tests). Their ureq transport answers inside `send`, so the future is ready at its first poll (`block_on`,
no executor). The extension drives the same futures request by request through an `Exchange`
(`gdrive_sync_exchange`, `gdrive_list_exchange`, `gdrive_download_exchange`, `gdrive_account_exchange`),
which parks at each request (`Step::Send`) until the host's `fetch` answers. No `wasm-bindgen-futures`,
no async in UniFFI. WebDAV and the server calls are not converted yet.

### 6.2 Google Drive

* `chrome.identity.launchWebAuthFlow` (Chrome, Edge, Brave; Firefox has `browser.identity` with the same
  call) with a Google OAuth client of type **Web application**, redirect URI
  `https://<extension id>.chromiumapp.org/` (one per extension id: Chrome Web Store, Edge Add-ons, the
  pinned unpacked id; Firefox's `identity.getRedirectURL()` when Firefox comes), scope
  `https://www.googleapis.com/auth/drive.appdata`.
* **The client must be in the same Google Cloud project as the Android and Windows clients**
  (`pass-511304`): Drive's `appDataFolder` belongs to the project, so only then does the browser see the
  same `pass-<vault id>.vault` files.
* Recommended flow: the **token flow** (`response_type=token`, a 1-hour access token, no client secret,
  no refresh token). Renewal is silent (`interactive: false`, `prompt=none`, `login_hint`) as long as the
  browser profile has a Google session, which the first interactive sign-in creates; otherwise the popup
  shows "Sign in to Google again" and sync waits. The token lives in `storage.session` only. The
  alternative, code flow with PKCE, needs the Web client's secret in the package and a stored refresh
  token (sealed with the vault key): more durable, more to protect. Decision 4: the token flow.
* `chrome.identity.getAuthToken` is not used: Chrome only, needs a signed-in Chrome profile, and doesn't
  exist in Edge or Brave.
* Everything else is `gdrive.rs` as is (file naming, `appProperties`, twins, the version check).

**As built (2026-11-08, `src/background/local/google.js`, `drive.js`).**

* Why the token flow: Google's code exchange for a *Web application* client requires the client secret
  even with PKCE, and an extension can't keep a secret. So `response_type=token`: a 1-hour access token,
  no refresh token, no secret.
* Scopes `openid email https://www.googleapis.com/auth/drive.appdata`. Consent left without the Drive
  box: `auth_required` with reason `drive_scope`. The account e-mail comes from Drive's `about.get`
  through pass-core.
* Silent renewal: `interactive: false`, `prompt=none`, `login_hint` = the vault's account,
  `abortOnLoadForNonInteractive`, `timeoutMsForNonInteractive` 10 s. If Google wants the user, the vault
  says "Sign in to Google again" and sync waits. A token of another account than the vault's: reason
  `drive_other_account`.
* The token and its e-mail live in `chrome.storage.session` only (key `passGoogleToken`). Sign out
  revokes at `https://oauth2.googleapis.com/revoke`, best effort.
* The client id is build-time configuration, never committed (docs/GOOGLE_DRIVE.md, "Browser
  extension"). Without it the Drive buttons say "Google Drive isn't set up in this build."
* Files: the apps' layout, one encrypted `pass-<vault id>.vault` with `appProperties` `pass_vault_id` and
  `pass_vault_name`, so the Windows and Android apps list a vault the browser made, and the other way
  round.
* Requests: `fetch` from the service worker (`credentials: "omit"`, `cache: "no-store"`, 60 s timeout).
  The steps come from pass-wasm's `DriveCall` (section 15); JavaScript only moves bytes.

### 6.3 WebDAV

* `fetch` from the service worker. The extension already holds `<all_urls>` as a host permission, and
  extension requests to permitted hosts are exempt from CORS, so a Nextcloud, ownCloud or other WebDAV
  server needs no CORS configuration. Firefox MV3 treats host permissions as opt-in: the Sync card asks
  for the server's origin with `permissions.request` when the user saves it.
* The core's rule stays: plain `http://` only for this device or a private network
  (`check_plain_http`). Browsers may add their own checks for requests to local addresses (Chromium's
  Local Network Access); test against a LAN NAS in Phase B.
* The app password is kept in the sealed `local` blob (4.1), never in `storage.local`.
* Requests carry `Origin: chrome-extension://…`; a server that rejects unknown origins on WebDAV is rare,
  and the error says so.

### 6.4 Passyble Server

* Same protocol (PROTOCOL.md §3): pairing links (`pass+server://`, parsed by core's
  `parse_server_link`), sign-in with the HKDF auth key (`server_auth_key`, Argon2id through 3.5), 2FA, the
  device list, WebDAV under `/dav/`. The pass-server API needs nothing new: it already answers JSON with
  `X-Pass-Error` codes, and extension requests can read every response header.
* **Certificate pinning (`pin=`) can't be done from a browser**: `fetch` validates TLS with the system's
  trust store and offers no hook. A pinned link is accepted only if the server's certificate is also
  publicly trusted; a self-signed server needs plain `http://` on the LAN, a public certificate (Let's
  Encrypt), or the Windows app. The pairing screen explains this instead of failing obscurely.
* Today "Add Passyble Server" in the popup hands the link to the desktop app. In browser mode the same
  form configures the extension's own sync.

### 6.5 Not possible: a cloud folder

The browser can't watch a OneDrive, Dropbox or Syncthing folder. The File System Access API (Chromium
only) can keep a handle to a file, but it needs a visible page and a user gesture to regain permission in
each session, and doesn't run in the service worker. Not offered; "Upload a vault file" (into Google
Drive) and "Download a copy" cover the occasional transfer.

### 6.6 Triggers, merge, accounts

* Triggers as on the desktop (ARCHITECTURE.md §10): at unlock, ~10 s after the last edit (a timer while
  the service worker is up, an alarm as a backstop), when the popup opens and the last check is older than
  5 min, every 30 min while unlocked and used, and **Sync now**; backoff 30 s doubling to 1 h; never while
  locked.
* **As built for Google Drive (2026-11-08, `DriveSync` in `drive.js`).** At unlock; 2 s after a saved
  change (debounced); every 5 min while unlocked; when the popup opens and the last sync is older than
  5 min; on **Sync now**; and before a lock (a flush of pending changes, up to 5 s for the Lock button, 3 s
  for the computer locking or the last window closing). Never while locked or in app mode. A failure never
  loses a change: the vault record gets `pending: true` in the same IndexedDB write as the change, "Not
  synced" shows, and the sync retries at 30 s doubling to 15 min (the alarm `pass-drive-sync` wakes a
  stopped service worker). A token Drive refuses (401) is renewed once silently. A sign-in Google won't
  renew silently waits for the user (`syncError: "sign_in"`, no retry loop).
* Conflicts: `Vault::merge_remote` as everywhere. The browser is one more device with its own
  `device_id` ("Chrome on macOS"), so concurrent edits merge per item.
* Passyble Cloud (Phase 2 of the account service) is pass-server in cloud mode with device tokens, so it works with
  6.4 once the account sign-in exists. **The sign-in exists** (2026-11-06, section 13.8): `launchWebAuthFlow`
  like Drive, client `passyble-extension`. **Cloud storage does not exist yet** (2026-11-08): nothing lets a
  client with an account token store a vault. Missing server side: pass-server's cloud mode (`[cloud]`
  config, the internal listener and API, `CloudAccount`, per-owner quota, read-only and suspended checks,
  `DELETE /dav` for the owner); pass-account's `POST /v1/cloud/devices` (a `pst_` device token for
  `cloud.passyble.com`), its internal client and real entitlements in `/v1/me` (it says `cloud_state:
  "none"`); device sign-out; the client in `Core/core/src/account.rs`; deployment (pass-server is not deployed
  for it yet). Until then **Sign in** in setup says "Passyble Cloud storage is coming soon." and
  offers **Use Google Drive**. No prices or plans anywhere.

## 7. Features in browser mode

Same: identical behavior (the shared agent code). Reduced: works with a limitation. App-only: needs the
Windows app.

| feature | browser mode | notes |
|---|---|---|
| Inline menu, autofill, the username rule, frames, opaque origins | Same | Content scripts unchanged |
| URL binding checks on fills, 2FA codes, passkeys | Same | The agent's Rust code |
| Save / update prompts, `logins.save_check`, "Never for this site" | Same | Stored passwords still compared inside the agent (now in wasm) |
| Password generator, generate and save at once, the generated-password callout | Same | |
| Username generator, plus addressing, catch-all | Same | |
| E-mail alias services (SimpleLogin, addy.io, ...) | Reduced, Phase C | `alias.rs` makes ureq calls; needs the sans-IO treatment |
| 2FA codes: fill, the next-page chain, toast, copy | Same | |
| The desktop's always-on-top TOTP window | App-only | The in-page toast covers it |
| QR scan of a 2FA code on the page | Reduced, Phase C | `import-qr` builds for wasm; ships in the import module to keep the main module small |
| Cards and identities | Same | Card fill confirmation in an extension frame (3.3) |
| Popup search, login editor | Same | |
| Full vault management (all item kinds, notes, trash, tags, history) | Phase B | A new full-tab extension page (decision 7: reuse the desktop UI views) |
| Passkeys: create and sign in on websites | Same, Phase B | Keys stored in the vault as today, signed in wasm (`passkey_create`, `passkey_assert`); the cards decide consent; the UV flag only after a real verification within the request (master password, or a passkey assertion with user verification) |
| Passkey provider for native apps (Windows plugin authenticator) | App-only | A browser extension can't register with the OS |
| Lock, auto-lock, soft lock | Same, reduced | Soft lock lasts until the browser closes (4.2) |
| Windows Hello | App-only, replaced | PRF quick unlock (5.2), which can itself use Windows Hello |
| "Require verification before each fill" | Reduced, Phase B | Master password or passkey assertion (3.3) |
| Clipboard copy, cleared after 45 s | Reduced | Same 45 s alarm and offscreen clearing as today. **A browser can't mark a copy as excluded from Windows clipboard history or cloud clipboard**, which the app does. The UI doesn't say so (owner review 2026-11-06: less text); this document and the README do |
| Auto-type into other apps (global hotkey) | App-only | |
| Breach check (Have I Been Pwned) | Same, Phase C | `hibp_prefix` / `hibp_match` in wasm; `fetch` of `https://api.pwnedpasswords.com/range/<5 hex>` with `Add-Padding: true`, only when the user runs a check; only the 5-character prefix leaves |
| Password health (weak, reused, old, insecure sites, 2FA available) | Same, Phase C | `health_report` is pure core |
| Website icons | Reduced, Phase C | `fetch` of the site's icon (the core's candidate rules), resized with `OffscreenCanvas`, cached sealed (4.1). Same privacy note as the apps: the request goes to the site itself and carries only the host name. Off switch in Options |
| Import (CSV, Bitwarden, 1Password, KeePass, Proton, Aegis, 2FAS, ...) | Same, Phase C | All parsers build for wasm (probe); file picked in an extension page |
| Export (encrypted, JSON, CSV) | Same, Phase C | Download from an extension page (`<a download>`, no `downloads` permission); the same "plain export" warning |
| A copy of the vault file ("Download a copy") | Same, Phase A | 4.5 |
| Recovery code | Same, Phase B | 5.4 |
| Multiple vaults | Reduced, Phase C | One active at a time, a switcher in the popup's ⋯ menu; IndexedDB is already keyed by vault id |
| Sync: Google Drive | Same, built (15) | 6.2 |
| Sync: WebDAV, Passyble Server | Same, Phase B | 6.3, 6.4 |
| Sync: cloud folder | App-only | 6.5 |
| Certificate-pinned self-signed server | App-only | 6.4 |
| Passyble Cloud | Later | 6.6 |

## 8. Security and threat model

### 8.1 What changes compared with app mode

In app mode the browser only ever holds the one value being filled. In browser mode the browser **is**
the vault: while unlocked, the decrypted vault sits in the extension's service worker (wasm memory) and
the vault key in `storage.session`. The desktop app runs as its own process with Windows-specific
protections (DPAPI, Windows Hello, clipboard exclusion); the extension shares the browser's processes and
the browser's update channel.

| threat | app mode | browser mode |
|---|---|---|
| A web page (XSS, a malicious site) | Isolated: closed shadow roots, extension frames, URL binding in the agent | **Unchanged**: same content scripts and the same agent checks, now in wasm. The page can't reach `storage.session`, IndexedDB of the extension origin, or the wasm instance |
| Another, malicious extension | Can read page DOM (filled values), as with any password manager | Same. It can't read our storage or memory, can't message our `popup.*` / `vault.*` handlers (they check `sender` is our own extension page), and `chrome.debugger` can't attach to another extension's pages |
| The browser profile copied (malware, a stolen disk, a backup) | No vault data in the profile | **The encrypted vault file only**, protected by Argon2id like any synced copy; the quick-unlock blob needs the authenticator; device-local secrets are sealed with the vault key; `storage.session` was never on disk. Same exposure as the vault file on Google Drive |
| Malware running as the user while unlocked | Can read the desktop app's memory | Can read the browser's memory: the vault key in `storage.session` and the decrypted vault in the service worker. Equivalent; neither defends against a compromised account. Locking on the computer locking and the inactivity timer bound the window |
| Memory after lock | Keys zeroized by core | Core zeroizes keys it holds; the wasm instance and `storage.session` entries are dropped; item plaintext in freed wasm memory is gone when the service worker stops (it is not zeroed item by item; the same as the desktop's heap) |
| A malicious or hijacked extension update | Can only ask the agent, which enforces its rules | Can read the vault when it is next unlocked. Mitigations: 2-step verification and few people on the store accounts, reproducible builds from this repository, the store's review; documented as the trust the user places in the store channel |
| A compromised extension page (XSS in the popup or options) | Could call `popup.*` handlers | Could call `vault.*` handlers too. Mitigations: CSP without inline script and without `unsafe-eval`, no `innerHTML` (icons via `createElementNS` already), Trusted Types for extension pages (`require-trusted-types-for 'script'`) as a Phase C hardening, no third-party code, no remote content in extension pages |
| The sync host | Sees ciphertext and metadata | Same (the same file, the same merge rules that keep a host from rewriting history, ARCHITECTURE.md §1) |
| The network | The app's TLS with optional pinning | The browser's TLS; no pinning (6.4); plain `http://` only to private networks (core rule) |
| The browser vendor's sync | Not involved | Not involved: nothing vault-related goes into `chrome.storage.sync` |

### 8.2 Rules that carry over unchanged

* Opaque origins, frames, `sender.url` as the only source of a page's URL, trusted and visible clicks,
  the 500 ms visibility rule, layering on top of modals: content-script code, unchanged.
* MAIN-world WebAuthn interception: unchanged. Passkey RP ID checks and the UV rule move with the agent.
* No secret in logs: the agent's timing traces and error logging carry codes only, in both builds.

### 8.3 The client-secrets rules, updated

The rules of the client-secrets audit (docs/TESTING.md item 87, ARCHITECTURE.md §7) become:

1. **Passwords and every other secret are processed only on the device**: in the Windows app, the
   Android app, or the browser extension's own vault. The extension in app mode still holds only the
   value it is filling.
2. **Only encrypted data is synced**: the vault file (and nothing else) goes to Google Drive, WebDAV or
   Passyble Server. Settings and tokens that the browser vault needs locally are sealed with the vault key
   and never uploaded.
3. Plain `http://` WebDAV and server addresses only for this device or a private network, in every client
   (the core's rule).
4. Exports default to encrypted; plain exports carry the warning, in every client.
5. Copied secrets are cleared after 45 s in every client; only the apps can also keep them out of Windows
   clipboard history (documented, not repeated in the extension's UI).
6. Website icon requests go to the site itself with only the host name, can be turned off, and are
   disclosed in setup, in every client.
7. Breach checks send only a 5-character hash prefix, only when the user runs a check.

The account service design's invariant 5 ("The browser extension keeps making no network requests of its own") becomes:
in app mode, none; in browser mode, only to the sync target the user set up, Have I Been Pwned range
queries when the user runs a check, website icons while that setting is on, and alias services the user
configured. Never to Sensyble.

## 9. Stores

**Chrome Web Store and Edge Add-ons**

* WebAssembly is allowed when it ships in the package (no remotely hosted code) and is not obfuscated. The
  source is public (AGPL); link it in the listing and the privacy policy.
* Single purpose: still "a password manager". Both modes serve it.
* Permission justifications to add: `idle` ("lock the vault when the computer locks"), `unlimitedStorage`
  ("store the encrypted vault locally without eviction"), `identity` ("sign in to Google Drive to sync the
  encrypted vault"). None of them adds an install warning in Chrome.
* Privacy practices: declare "Authentication information", "Personally identifiable information"
  (identities) and "Financial and payment information" (cards) as handled; state that they are stored
  encrypted on the device, never sold or used for anything else, and leave the device only end-to-end
  encrypted to storage the user chooses. Update the privacy policy accordingly (the "the extension stores
  nothing" sentences change). Expect a longer review for the update that adds this.
* Listing text in every locale (`extName` / `extDescription` and the long description): mention that
  Passyble works on its own in the browser, on Windows, macOS, Linux and ChromeOS, and that uninstalling
  deletes changes not yet in Google Drive.
* Edge Add-ons: the same package; `launchWebAuthFlow` is supported; its redirect URI is the Edge store
  id's `chromiumapp.org` address. Brave installs from the Chrome Web Store; check `launchWebAuthFlow` there
  in Phase B.

**Firefox (addons.mozilla.org), Phase C**

* Generated code (wasm from Rust) requires a **source code submission** with build instructions (Rust
  version, `wasm-bindgen` version, `build-wasm.mjs`) for every upload.
* `data_collection_permissions`: today `required: ["none"]`. With browser-mode sync and breach checks the
  extension transmits data, encrypted, to services the user picks. Recommended: keep `required: ["none"]`
  and declare the matching categories as **optional** (`authenticationInfo`, `personallyIdentifyingInfo`,
  `financialAndPaymentInfo`), requested with `permissions.request` when the user turns on sync (open
  question 9).
* API differences: `browser.*` (the existing `src/shared/api.js` shim), an event page instead of a service
  worker (it has a DOM, so no offscreen document is needed for the clipboard, as today), `storage.session`
  from Firefox 115, `browser.identity.launchWebAuthFlow` with `identity.getRedirectURL()`, opt-in host
  permissions. WebAuthn PRF from `moz-extension://` to be verified.
* `scripts/make-firefox-manifest.mjs` keeps generating the variant (it adds the CSP key unchanged).

## 10. Phased plan

Sizes as in the account service plan: rough calendar estimates for one developer working with agents. S under a week,
M 1-3 weeks, L 3-6 weeks, XL over 6 weeks.

### Phase A: wasm core, portable agent, a local vault with the everyday features (L)

| part | size | files |
|---|---|---|
| pass-core wasm readiness: clock, randomness features, `pass_kdf` host import on wasm, sealing helpers, wasm check | S | `Core/core/Cargo.toml`, `Core/core/src/lib.rs`, `Core/core/src/crypto.rs`, new `Core/core/src/local_seal.rs`, `Extension/package.json` |
| Portable pass-agent: `native` feature, `web-time`, `VaultStore`, tick-driven save delay, session snapshot, per-host `features` | M to L | `Core/agent/Cargo.toml`, `src/lib.rs`, `src/agent.rs`, `src/protocol.rs`, `src/otp_history.rs`, `src/kept_list.rs`, `src/timing.rs`, `tests/protocol.rs` (also run against a `VaultStore` in memory) |
| pass-wasm crate: `BrowserAgent`, browser `Ui`, `vault.*` functions (create, unlock, backup), the KDF module, build script, size budget | M | `Core/wasm/Cargo.toml`, `Core/wasm/src/{lib,ui,store,vault}.rs`, `Core/wasm/kdf/`, `Extension/scripts/build-wasm.mjs`, `Cargo.toml` (workspace member), `Extension/package.json` |
| LocalBackend: wasm host, IndexedDB store, `storage.session` key and snapshot, rehydrate, auto-lock alarms, `chrome.idle`, effects, `unlock` window | M | new `Extension/src/background/backend.js`, `Extension/src/background/local/{local-backend,vault-store,session,kdf,effects}.js`, `Extension/src/unlock/window.html`, `Extension/src/background.js` (`agent()` routes through `backend()`) |
| UI: first-run choice, create / open file / backup, popup in browser mode (unlock, no vault, status line), Options "Where your vault is" and "Vault" cards, translations (9 locales) | M | `Extension/src/welcome/*`, `Extension/src/popup/*`, `Extension/src/options/*`, `Extension/src/unlock/frame.js`, `Extension/_locales/*/messages.json`, `Extension/manifest.json` |
| Tests: node tests with the real wasm in Node (crypto included), `cargo test -p pass-wasm`, e2e (Playwright Chromium) for create, unlock, fill, save, lock, service-worker restart | M | `Extension/test/local-*.test.js`, `Extension/test/e2e/local-vault.e2e.mjs`, `Core/wasm/tests/` |
| Docs | S | this file, `Extension/README.md`, `docs/PROTOCOL.md` (extension notes, `vault.*`), `docs/ARCHITECTURE.md` §7 and §8, `docs/TESTING.md` (manual items), the account service design (invariant 5), `docs/GUIDE.md` |

Features at the end of Phase A: inline menu and autofill, save and update prompts, password and username
generators, 2FA codes, cards and identities, popup search and login editor, lock and auto-lock, backup
and restore of the vault file. No sync yet (the "Not backed up" chip pushes the backup file).

### Phase B: sync, passkeys, quick unlock, a full vault page (L)

| part | size | files |
|---|---|---|
| Sans-IO sync in core (WebDAV, Drive, server calls), native drivers over ureq, unchanged tests | L | `Core/core/src/webdav.rs`, `Core/core/src/gdrive.rs`, `Core/core/src/server.rs`, `Core/core/src/net.rs`, new `Core/core/src/http.rs` |
| fetch driver, Google sign-in (`identity`), WebDAV and Passyble Server settings, triggers and backoff, "Open my vault from ..." in setup | M | `Extension/src/background/local/{sync,google}.js`, `Extension/src/ui/server-pair.js`, options Sync card, welcome |
| Passkeys in browser mode (the agent's methods via wasm; UV rule; verification grant) | S to M | `Core/wasm/src/ui.rs`, `Extension/src/background/local/verify.js` |
| PRF quick unlock (spike first: extension-origin WebAuthn in Chrome, Edge, Brave) | M | `Extension/src/options/quick-unlock.js`, `Extension/src/unlock/*`, `Core/wasm/src/quick.rs` |
| Recovery code, change master password | S | options Vault card, popup "Forgot master password?" |
| Full vault page (all item kinds, trash, tags, password history), reusing the desktop UI views behind an `invoke` shim (decision 7) | M to L | new `Extension/src/vault/`, shim `Extension/src/vault/invoke.js`, shared views from `Core/desktop-app/ui/views/` |

### Phase C: the rest, and Firefox (M to L)

Import and export UI (all core formats, a separate import wasm module with QR), password health and HIBP,
website icons, e-mail alias services (sans-IO `alias.rs`), multiple vaults, moving a vault between the app
and the browser (a new native method that hands the encrypted file to the app, which asks for the master
password; and the reverse), Trusted Types, Firefox standalone (event page host, AMO source submission,
data collection declarations), store listing updates.

### What the owner has to do

1. **Google OAuth (needed now, section 15):** in project `pass-511304`, create a client of type *Web
   application* ("Passyble browser extension") with the redirect URI
   `https://bmjmlhhgfbpcbfbkbndlmmockkbdcaoo.chromiumapp.org/` (the pinned unpacked id), later also the
   Chrome Web Store and Edge Add-ons ids' `chromiumapp.org` addresses; no JavaScript origins. On the
   consent screen keep `drive.appdata` and add `openid` and `email`; add test users while in Testing. Put
   the client id in `PASS_GOOGLE_WEB_CLIENT_ID` (environment or `Extension/google-oauth.env`). No client
   secret. Steps: docs/GOOGLE_DRIVE.md, "Browser extension".
2. **Store listings (at the Phase A release):** new permission justifications, privacy practices, the
   privacy policy text, listing descriptions in every locale (section 9).
3. **Test machines:** a Mac, a Linux desktop and a Chromebook (or a ChromeOS Flex VM) for Phase A and B
   manual tests; a security key and an Android phone for PRF.
4. ~~Answer the open questions.~~ Done on 2026-11-06: every recommendation approved (section 11).

## 11. Decisions

The owner approved every recommendation of the open questions on 2026-11-06 ("go with the
recommendations"). They are decisions now:

1. **One mode per browser profile**, switchable in Options (2.3). The same vault in both places is what
   sync is for.
2. **On a Windows PC without the app, setup offers both with equal weight**: "Get the Windows app" is one
   more row next to "Continue with Google Drive" and "Sign in" (2026-11-08; before: "Create a vault" and
   "Open a vault file"), titles only. It doesn't push the download.
3. **Quick unlock is a passkey (PRF) only, no PIN** (5.3). A local PIN would be the weakest point of the
   vault.
4. **Google Drive sign-in starts with the token flow** (no client secret in the package, nothing
   long-lived stored); code flow with PKCE only if silent renewal turns out unreliable in Edge or Brave.
5. **Firefox gets the browser vault in Phase C**, after Chrome, Edge and Brave are stable; app mode keeps
   working in Firefox meanwhile.
6. **Browser mode is free**, like the apps and Google Drive sync. Passyble Cloud (paid) comes later
   through the account, the same as in the apps.
7. **The full vault page reuses the desktop app's UI**: `Core/desktop-app/ui/views/` (about 10,600 lines, 143
   Tauri commands) in an extension page behind an `invoke()` shim that maps the commands browser mode
   supports to `vault.*` messages.
8. ~~**Setup doesn't force a backup or sync, it nudges**: the backup step at the end of setup (skippable),
   the "Not backed up" chip, and the delete guard (4.5).~~ Replaced on 2026-11-08: **a vault in the
   browser always lives in Google Drive** (or, later, Passyble Cloud). No backup step, no "Not backed up"
   chip; "Not synced" shows changes not in Drive yet (4.5).
9. **Firefox data collection declaration**: keep `required: ["none"]` and declare the encrypted sync and
   breach-check transmissions as optional categories, requested when the user turns them on.
10. **Website icons in browser mode are on by default**, as in the apps, with the same disclosure in setup
    and the off switch.
11. **`nativeMessaging` stays a required permission.** Its warning is mild, and making it optional would
    add a prompt for every Windows user who later installs the app.
12. **Self-signed Passyble Servers with certificate pins stay app-only** (6.4): such servers need a public
    certificate or the Windows app in the browser, and the pairing screen says so.
13. **A browser vault moves into the Windows app through sync first** (no new protocol, works once Phase B
    ships); the direct hand-over over native messaging comes in Phase C for people without any sync.

**2026-11-08, the owner:** *"let's not allow vaults to be created in extension, as it is not safe. the
vaults need desktop app or google drive login or account".* So: no vault only in the browser (2.1);
Google Drive pulled forward from Phase B (section 15); decisions 2 and 8 changed as noted; a Passyble
account offers Cloud storage once the server side exists (6.6). Decision 4 holds (the token flow).

Still to do by the owner (not decisions, they need the owner's accounts or hands):

* Now: the Google OAuth *Web application* client in project `pass-511304` with its redirect URIs (item 1
  of "What the owner has to do"; decision 4 means no client secret is needed).
* Before the Firefox release (Phase C): check decision 9 against AMO's policy text at that time.
* At the Phase A release: the store listings and the privacy policy (item 2 there, section 9).
* For the Phase A and B manual tests: the test machines (item 3 there).

## 12. When implementing, also update

* `Extension/README.md`: the intro ("the vault stays in the desktop agent"), Security model and
  limitations, Code layout, Publishing (the wasm build), Development.
* `docs/ARCHITECTURE.md`: the diagram, §7 ("The browser extension never stores secrets" becomes per
  mode), §8 (repository layout: `Core/wasm/`), §10 (the browser as a sync client).
* `docs/PROTOCOL.md` §2: `status.features` `vault.browser`, `unlock.options.passkey`, the
  `verification_required` and `no_vault` codes, and the extension-internal `vault.*` / `sync.*` methods.
* The account service design (not public): invariant 5 (8.3).
* `docs/TESTING.md`: manual tests for both modes, the first-run detection, service-worker restarts while
  unlocked, lock on the computer locking, browser exit, extension update, PRF on each platform, and item 87
  per 8.3.
* The help center (help.passyble.com, written in the admin panel): a "Passyble without the app" article.
* `docs/GOOGLE_DRIVE.md`: the Web client and its redirect URIs.
* Store listings and the privacy policy (section 9).

## 13. Phase A: what was built

Branch `feature/extension-vault`. Steps 1 and 2, the Rust side, are sections 13.1 to 13.7; step 3, the
JavaScript side that uses the API in section 14, is section 13.8. Native behaviour is unchanged: the desktop agent keeps its files, its save
thread and std's clocks (the types are std's own on every target but `wasm32-unknown-unknown`), and every
existing test of pass-core, pass-agent, pass-native-host and pass-desktop passes as before.

### 13.1 pass-core

* `src/clock.rs`: `now_ms()` reads std natively and `js_sys::Date::now()` on `wasm32-unknown-unknown`. It
  is the only clock on the paths the extension uses (`icons`, with its `Instant`, stays off).
* `Cargo.toml`, for `cfg(all(target_arch = "wasm32", target_os = "unknown"))` only: getrandom 0.2 with
  `js` (rand's `OsRng`: keys, nonces, salts, generators), uuid with `js` (vault and item ids) and js-sys.
* `pass_core::set_argon2id_runner(Option<Argon2idRunner>)`, `type Argon2idRunner = fn(secret: &[u8],
  salt: &[u8], m_kib: u32, t: u32, p: u32) -> Option<[u8; 32]>`: when set, every Argon2id run of the core
  (creating, unlocking and re-keying a vault, recovery codes, encrypted exports, the Passyble Server key)
  goes to it, after the core checked the parameters the same way as for its own run. This replaces the
  planned raw host import `pass_kdf`: the core stays free of wasm-bindgen, and a native test can plug in
  the module's Rust function. Unset (every app), nothing changes.
* The three sync-only helpers that warned without `webdav` are allowed as dead code there. The core builds
  for `wasm32-unknown-unknown` with `--no-default-features --features import-kdbx,import-pgp,import-qr`
  (a check to run) and has no thread or file access on those paths.
* Not built yet: the sealing helpers for device-local secrets (4.1, needed first by sync in Phase B) and
  the quick-unlock wrapping (5.2, Phase B).

### 13.2 pass-agent: the portable agent

* Feature **`native`** (default on): local IPC (`ipc`, the `interprocess` dependency), the Windows passkey
  provider's ceremonies (`platform_passkey`), `store::FileStore` and `Agent::new`, the DPAPI kept list on
  disk, the 2FA outcome history file, the timing log (file and stderr) and the save-delay thread. The
  Windows app and the native host build pass-agent with `default-features = false`, so they now name
  `native`. Without it the request handlers build for `wasm32-unknown-unknown`, and natively (check
  both).
* **Clock** (`src/clock.rs`): a `Clock` trait (`now() -> Instant`, `unix_ms()`), `SystemClock`, and
  `ManualClock` (moves only with `advance`, for tests). `clock::Instant` and `SystemTime` are std natively
  and `web-time` (`performance.now()`, `Date.now()`) in WebAssembly. Every timer of the agent reads the
  agent's clock: the auto-lock, the pending 2FA window, rate limits, edit, search and generated-password
  grants, the delete undo window, the kept list's throttle, usage counts, 2FA codes (`Agent::now_secs`)
  and the 2FA outcome history. A trait as well as `web-time`, because tests (and the identical-answers
  test below) must be able to move time.
* **Storage** (`src/store.rs`): a `VaultStore` trait with `read`, `exists`, `write` (all or nothing),
  `stamp` (changes when the file is replaced: the modification time on disk), `remove` and `siblings`
  (the files next to it). Every file access of the agent goes through it: unlock, saves, the `-unsaved-`
  copy when a save fails, `reload_if_changed`, the conflict-copy merge and `vault_file_id`. These methods
  rather than the planned `load` / `save` / `changed_since`, so the conflict copies, the stash and the
  reload work exactly as before on disk and the same way in memory. `FileStore` is the previous file code
  (temporary file, rename with retries). `MemoryStore` keeps files in memory with a version number as the
  stamp; the host puts a file in with `put` and takes what the agent wrote with `take_written`.
* **Timers** (`Timers::Thread` / `Timers::Host`): with `Host`, `save_soon` only records when the save is
  due (the first call sets it, as the thread does); `Agent::tick` writes it once due, and
  `Agent::next_tick()` says when the host should call `tick` (the save or the auto-lock, whichever comes
  first; `None` while locked with nothing pending). `Agent::set_idle_for(d)` carries the time without use
  over a restart. It is kept as an offset, not as an earlier `Instant`: WebAssembly's monotonic clock
  starts near zero with each service worker, so it can't go back 15 minutes (the WebAssembly tests found
  this).
* **Hosts**: `AgentHost { store, clock, timers }`, `AgentHost::native()` (what `Agent::new` uses),
  `AgentHost::hosted(store)`, `Agent::with_host(config, ui, host)`, and `AgentConfig::new(path, device,
  auto_lock)` for a configuration without sync fields whatever the features.
* **Decisions that travel with the request** (3.3): `Verification::Required`, which a `Ui` that can't
  ask during a request returns; the agent then answers the new code `verification_required` (also for a
  passkey that demands user verification, instead of `not_supported`). The new code `no_vault` (answered
  by pass-wasm). `Ui::host_features()` adds to `status.features` (`vault.browser`). The desktop `Ui` never
  returns `Required`, so nothing changes there.
* The kept list is written to disk only with `native` on Windows; a soft lock's list in memory works
  everywhere.

### 13.3 pass-wasm and pass-wasm-kdf

* `Core/wasm/` (`pass-wasm`) and `Core/wasm/kdf/` (`pass-wasm-kdf`): workspace members, not
  default members. pass-wasm uses pass-agent and pass-core with no default features: no sync, icons, QR,
  KeePass or PGP import in Phase A, for the smallest module.
* `BrowserHost` (`src/host.rs`, plain Rust, tested natively): the agent on a `MemoryStore` (the file under
  the key `passyble/pass.vault`), `Timers::Host`, the system clock, and `BrowserUi`.
* `BrowserUi` (`src/ui.rs`), the answers of section 3.3: `request_unlock` is `false` (the extension opens
  its popup itself, so a plain `unlock` answers `cancelled`); passkey consent without the card's decision
  is declined and the pickers cancel; `totp.popup`, `app.show_item` and `server.pair` are `not_supported`;
  per-fill verification is `Allowed` unless `verify_each_fill` is on, then `verification_required` until
  the request carries a grant; a site that demands user verification needs a grant; cross-site and card
  fills need `confirmed: true` (else `cancelled`); copies, lock changes and vault changes are effects.
* Grants: 32 random bytes (43 base64url characters), kept only as a hash, good for one request within
  120 s, at most 8, all dropped on lock. `create`, `unlock` and `verifyPassword` hand them out.
* The Argon2id module exports only `memory`, `kdf_alloc(len)` and `kdf_argon2id(secret, secret_len, salt,
  salt_len, m_kib, t, p, out) -> 0 | 1`. `kdf.js` (`loadKdf`) compiles it once and instantiates it for each
  run, then zeroes all of its memory. An instance can't be used again after that (its allocator's state is
  zeroed too), which is the point.
* Secrets at the boundary: passwords and request lines are cleared in WebAssembly memory after use, and
  the strings that can carry a secret out (`handle`, `takeEffects`) are cleared once JavaScript has its
  copy; the copy of the secret and the key that cross to the Argon2id function are zeroed right after. The
  agent's own JSON values are not cleared one by one (as on the desktop).

### 13.4 The build

`npm run wasm` in `Extension/` (`node scripts/build-wasm.mjs [--no-install] [--no-opt] [--out <dir>]`):

1. `cargo build --profile wasm-release --target wasm32-unknown-unknown -p pass-wasm` (`wasm-release` is
   `release` with `opt-level = "z"`) and `cargo build --release --target wasm32-unknown-unknown -p
   pass-wasm-kdf` (speed matters there), through `scripts\cargo-low.cmd` on Windows.
2. The wasm-bindgen CLI of exactly the crate's version (`wasm-bindgen = "=0.2.129"` in
   `Core/wasm/Cargo.toml`): if it is missing or another version, `cargo install wasm-bindgen-cli
   --version 0.2.129 --locked` (`--no-install` prints that command and stops). Then `wasm-bindgen --target
   web --no-typescript`.
3. `wasm-opt -Oz` (main) and `-O3` (Argon2id) when Binaryen is on the PATH; otherwise the modules ship as
   rustc made them.
4. Writes `Extension/src/wasm/` (git-ignored): `pass_wasm.js`, `pass_wasm_bg.wasm`, `pass_wasm_kdf.wasm`,
   `kdf.js` and `build.json` (versions, sizes). Fails if `pass_wasm_bg.wasm` is over 1.5 MiB gzipped.

`scripts/package.mjs` ships `src/wasm/` (without `build.json`) and never `wasm/` (the Rust sources).
`npm run package` doesn't build the WebAssembly itself; since step 3 it requires it (section 13.8).

### 13.5 Sizes and timing (2026-11-06, rustc 1.99, wasm-bindgen 0.2.129, no wasm-opt)

| file | size | gzipped |
|---|---|---|
| `pass_wasm_bg.wasm` (pass-agent's handlers and pass-core, Phase A features) | 2,393,945 bytes (2.28 MiB) | 725,453 bytes (708 KiB) |
| `pass_wasm.js` (wasm-bindgen glue) | 26,857 bytes | 5,468 bytes |
| `pass_wasm_kdf.wasm` (Argon2id) | 38,547 bytes | 14,445 bytes |

Argon2id with the vault defaults (64 MiB, t = 3, p = 1) in a fresh instance of the module, Node 26.2:
**129 to 140 ms per run** (170 to 260 ms while the PC's CPU was 84 % busy with other work; the probe
measured 114 ms in a long-lived instance), of which 0.1 ms is the instantiation and 5 to 9 ms the zeroing
of the 65 MiB. The same key as pass-core's.

### 13.6 Tests

* pass-core: `clock.rs` (std milliseconds), the runner (taken over, same key, parameters refused before it).
* pass-agent: `clock.rs` and `store.rs` unit tests (both stores behave like files, `take_written` once,
  `put` changes the stamp, `FileStore` leaves no temporary file); `tests/hosted.rs`: a `MemoryStore` agent
  never touches the disk, saves a use only on a due `tick`, auto-locks on the host's clock, carries the
  idle time over a restart, merges a file put in while unlocked, and **answers a scripted session of 37
  requests exactly as the desktop agent does** (locked requests, wrong and right master password, saves,
  `save_check`, fills, a cross-site fill refused, `totp.set` and the pending code, `otp.outcome`, create,
  search, edit, copy, checks, generators, cards, identities, `passkey.find`, delete and undo, lock, the
  soft-locked list, unlock and fill again; new ids, 2FA codes and timestamps normalized). The existing
  protocol, passkey and timing tests need `native` and run as before.
* pass-wasm (`tests/host.rs`, natively and as WebAssembly in Node through `wasm-bindgen-test-runner`):
  no vault (`no_vault`, `status.vault`), create, fill, URL binding, soft and full lock, unlock; a vault
  file the desktop's core made (`tests/fixtures/native.vault`) opens and comes back out **byte for byte**
  (locked, and unlocked without edits), an edited one opens and merges in the desktop's core; restart
  with the kept key and the idle time; per-fill verification with grants (forged, reused, expired, after
  lock); confirmations for cross-site and card fills; copies as effects; the desktop-only windows;
  options. `tests/kdf.rs`: vaults made through `pass-wasm-kdf` open with the core's own Argon2id and the
  other way round. `tests/web.rs` (WebAssembly only): the `BrowserAgent` exports and `setKdf` (arguments,
  a wrong-length key and a throwing function refused, back to the module's own Argon2id).
* `Extension/test/wasm-agent.test.js`: the built `src/wasm/` in Node, with the real Argon2id module and
  `kdf.js` (create, fill, lock, restart with the key, unlock, timing); skipped when not built.
  `Extension/test/package.test.js`: `src/wasm/` ships only when built, `wasm/` never; the CLI pin.
* Checks to run by hand: the wasm32 checks and clippy of core, agent and pass-wasm,
  `cargo test -p pass-wasm -p pass-wasm-kdf`, the same tests in Node, the build with its size budget and
  the Node test of the built modules.

### 13.7 Not done yet in the Rust side, for later steps

* The session snapshot (4.2: `session_snapshot()` / `restore_session()`): after a service-worker
  restart the pending 2FA windows, the search, edit and generated-password grants and the rate-limit
  counters start empty. The auto-lock schedule does carry over (`idleMs`, `unlockWithKey(key, idleMs)`).
* The 2FA outcome history (`otp.outcome`, `skips_2fa`) is memory only in the browser.
* The sealing helpers (4.1) and quick-unlock wrapping (5.2), with Phase B.
* `wasm-opt` was not run here (Binaryen isn't installed); with it the main module should shrink further.

### 13.8 Step 3: the JavaScript side

What the extension does with the API of section 14. `Extension/README.md` ("The vault in this browser") is the
reader's summary; the manual tests are docs/TESTING.md items 92 to 95. Since 2026-11-08 the setup choices, the
backup step, "Not backed up" and `vault.create` / `vault.open-file` below are replaced by Google Drive (section 15).

**Passyble account (2026-11-06).** Optional, for people who have one: **Sign in** is the first choice of the setup
page and a row in Options → About; nothing uses the account yet (Passyble Cloud is Phase 2 of the account service) and the UI
says nothing about plans or prices. `src/background/account.js`: in browser mode the background opens the
website's sign-in in `chrome.identity.launchWebAuthFlow` (permission `identity`) with client `passyble-extension`,
authorization code + PKCE S256, redirect `https://<extension id>.chromiumapp.org/` (the account service accepts
exactly that form, or only the ids in its `[apps] extension_ids`), checks `state` and `iss`, and exchanges the
code at `/oauth/token` itself. The refresh token and the account's e-mail go into the extension's IndexedDB
`passyble-account` (not `storage.local`: content scripts can read that area, and restricting it would cut them
off the settings); the access token into `storage.session` (trusted contexts). Pages get `{ signed_in, email }`
only. Sign out revokes (`/oauth/revoke`) and forgets both. Firefox (2026-11-08): the same flow with its
`https://<sha1 of the add-on id>.extensions.allizom.org/` redirect (`src/background/web-auth.js`; the service must
accept it, Firefox/README.md), after Firefox's data consent. App mode (the desktop app owns the account) and a
browser without a redirect (Safari): Sign in opens `https://account.passyble.com/sign-in` in a tab, no token. A
dev override of the service (`devAccountBase` in `storage.local`) works in an unpacked extension only.

**Less text (owner review, 2026-11-06).** Every page keeps to titles and buttons: no helper paragraphs under
rows, no footnotes at the bottom of cards, (i) tooltips of one short sentence (none where the label says it).
Setup: a heading and the choices as rows without descriptions; the how-to cards are replaced by one link to
the help center, https://help.passyble.com/. "Uninstalling Passyble deletes this vault" is said once, at the backup step.
Options' **Where your vault is** is one row under the heading **Vault** (where, the lock state, the switch button), with the vault's settings below it under the same heading. The safety checks stay,
shorter: the master password can't be reset (create), the delete guard (backup in the last hour, master
password), the other-site fill confirmation.

**Modes (2.2 to 2.4).** `vaultMode` in `storage.local` (`src/shared/vault-mode.js`); unset behaves as app mode,
so updating users see no change. `runtime.onInstalled` with `install` sends one `status` to the native host (20 s
timeout): an answer or `agent_unavailable` without "host not found" sets `app`; "host not found" sets nothing and
records `vaultHostSeen: "missing"`. The setup guide (`src/welcome/`) asks then (`vault.state`, which waits for the
detection), titles only: **Create a vault**, **Open a vault file**, and on Windows **Get the Windows app**
(decision 2). The sync sources are not shown until they exist. `#browser`, `#create`,
`#open` open that part from Options and the popup. Options gets **Where your vault is** (shown as the **Vault** heading's first row; always, where the browser
vault is offered) and **Vault in this browser** (browser mode with a vault); the popup gets the app tip of 2.4 (the
native host is looked for at most once a day as the popup opens, only where the first run found none; it stops once
found). Firefox (2026-11-08) has browser mode too: `browserVaultSupported()` checks WebAssembly and
`storage.session` instead of the browser's name (Firefox/README.md).

**Routing.** `agent()` in background.js goes to `localAgent()` in browser mode, else to `NativeClient` as before.
`LocalBackend` (`src/background/local/local-backend.js`) has NativeClient's surface (`request`, `on`, `connected`)
and does, after every call, what section 14 asks: `takeSave()` to IndexedDB (`vault-store.js`: database `passyble`,
store `vaults` with `file` and `prev`, store `meta` with the active vault id), `takeEffects()` (`lock_state`: the key
to or from `storage.session` and the `lock_state` event; `copy`; `vault_changed`), and `nextTickMs()` as a timer plus
the `pass-vault-tick` alarm. Calls run one at a time. A save IndexedDB refused is kept and written after the next call.

**Save safety (sync-safety audit, 2026-11-21).** Only the service worker writes the vault: every page and content
script reaches it through `runtime.sendMessage`, and `LocalBackend` runs one call at a time, so two pages saving at
the same moment both land, in order, and an older copy is never written after a newer one. Each change is in
IndexedDB before its request is answered: one `readwrite` transaction per save (the new `file`, the old one as
`prev` and the `meta` pointer together or not at all), opened with `durability: "strict"` so the answer comes only
once the data is on disk (browsers may default to relaxed durability; browsers without the option ignore it). A
file IndexedDB refuses (a full disk, an IndexedDB error) has already been answered as saved, so it is kept: in
memory, and in `storage.session` as `passBrowserVaultUnsaved: { vaultId, file (base64url), fields }` (the encrypted
file only, so a service worker the browser stops still has it); it is written again after every call, on a timer (1 s
doubling to 30 s) and from the `pass-vault-tick` alarm, which stays set while it waits. A rebuilt instance (a
restart of the service worker, or browser mode again after app mode) opens that kept file instead of the older one in
IndexedDB, so an edit made then is saved on top of the newest copy. The kept copy goes once IndexedDB holds it, and
with **Delete**; a lock keeps it. It does not survive the browser exiting while IndexedDB still refuses. Not
covered: a use (usage count) waiting for the agent's 2 s save delay when the browser stops the service worker inside
those 2 s (locks and the timer write it otherwise). Tests: `Extension/test/local-backend-durability.test.js`.

**The key (4.2).** `session.js`: `passBrowserVault: { key (base64url), vaultId, lastUseAt }` in `storage.session` with
`setAccessLevel({ accessLevel: "TRUSTED_CONTEXTS" })`. A rebuilt instance (the service worker was stopped) loads the
file and calls `unlockWithKey(key, now - lastUseAt)`, then `tick()` at once, so an auto-lock that fell due meanwhile
happens before any request; this restore changes nothing the pages know, so no `lock_state` event. Restoring a
small vault this way takes about 1 ms in V8 (`local-wasm.test.js`); a 1000-item vault was not measured yet.

**Asking the user (3.3).** `askUser(kind)` in background.js, one question at a time: `unlock` (the desktop prompt's
place: the popup's form), `verify` ("Confirm each fill": `verification_required` → the master password →
`verifyPassword` → the same request once more with the grant), `card` (a card fill from the page: "Fill <card> on
<site>?" → `confirmed: true`) and `cross` (another site's login: "Fill a login of another site?" →
`confirmed: true`; the agent also wants a grant then when per-fill verification is on). An open popup holds a port
(`passyble-popup`) and gets `vault.ask`; otherwise `action.openPopup()`, else a small window `popup.html?ask=1`. The
popup reads the question with `popup.ask-get` and answers with `popup.ask-answer` (by token); a popup that showed it
and closes cancels it; after 3 minutes it is cancelled. `popup.unlock-password` in browser mode calls `unlock()`, and
its grant is kept for the one login the unlock was for (`for`), so "Confirm each fill" doesn't ask twice. The popup's
own card copy counts as the user's yes (`confirmed`). `grant` and `confirmed` are only ever set by the background.

**Copies (7).** `logins.copy`, `generate.copy` and card copies release a `copy` effect; the background writes it
through the offscreen document (`clipboard.write`, `execCommand('copy')`) before it answers, and the existing alarm
clears it after 45 s. Windows clipboard history can't be avoided (not repeated in the UI).

**Locking (4.3).** The agent's own auto-lock (`auto_lock_secs` from Options: 1, 5, 15 default, 30, 60 minutes, or
"only when the browser closes", which is 365 days for the agent: the browser clears the key on exit), a soft lock
on `idle.onStateChanged` `locked` (Options can turn it off), on the last window closing, and on browser exit and
extension update or reload (`storage.session` cleared by the browser).

**Unlock UI (5.1).** The popup's existing form and the in-page menu's existing frame (`src/unlock/frame.html`) send
`popup.unlock-password`; in browser mode the in-page menu and the popup offer neither Windows Hello nor "Open
Passyble" (`unlock.options` and `popup.state` say `browser: true`). Creating a vault: the setup guide's form, with
the Windows app's own strength rules (`masterStrength`, the desktop's `signin.js` `strength`, at least 8
characters), the repeat and the "can't reset" warning. Argon2id runs in the service worker (kdf.js, a fresh
instance per run; the pages are other processes and stay responsive); no offscreen document is needed.

**Backup (4.5).** `vault.export` (Options, the setup's backup step, the popup's ⋯ menu and its chip lead there)
returns the encrypted file; the page saves it as `Passyble-<yyyy-mm-dd>.vault` with an `<a download>` of a Blob (no
`downloads` permission) and `backedUpAt` is recorded. "Not backed up" shows until a backup from the last 30 days
(sync counts from Phase B). `vault.open-file` checks the file and its master password in a fresh instance before
anything is stored. `vault.delete` needs a backup from the last hour and the master password.

**Passkeys.** Not cheap enough for Phase A (consent, UV and grants through the cards): in browser mode
`passkey.find`, `passkey.create_options`, `passkey.get`, `passkey.create` and `passkey.start_app` answer
`not_supported` with reason `passkeys_need_app`; the card says "Passkeys need the Passyble app for now" and offers
**Use another device**. Phase B.

**Manifest (3.6).** `idle` and `unlimitedStorage` (no install warning), `content_security_policy.extension_pages`
`script-src 'self' 'wasm-unsafe-eval'; object-src 'self'`; `identity` waits for Phase B; `web_accessible_resources`
unchanged.

**Packaging, decided.** The background imports the glue statically (an MV3 service worker can't `import()` later),
so an extension without `src/wasm/` doesn't start in either mode. Hence `npm run package` requires the built
modules and stops with a message otherwise, and `npm run release` builds and packages. App mode still never fetches or compiles the WebAssembly: only the 27 KB glue is parsed.

**Strings.** About 95 new messages in all 9 extension locales (setup, popup, Options, errors, the passkey card).

**Tests.** `local-backend.test.js` (LocalBackend on the test stand-in `test/helpers/fake-wasm.js`: saves, effects,
timers, grants, restart with the key and with the auto-lock overdue, a wrong key, open file, backup, delete,
reset, a failed save, ordering), `local-wasm.test.js` (the same backend on the real modules: create, save, fill,
lock, unlock, back up, delete, open the backup; restart without Argon2id; `unlock`, `totp.popup`, `app.show_item`,
`server.pair`; grants used up, forged; `logins.fill_cross` only after a search and with `confirmed`; copies; the
auto-lock choices), `background-vault.test.js` (first run without the app, detection with the app, routing without
native ports, popup state, copies through the offscreen document, card and verify questions in the window and the
open popup, a popup closed without answering, unlock from a page's fill, passkeys, computer lock, the alarm after a
restart, restart with the key, the delete guard, switching both ways), `popup-vault.test.js`, `welcome-vault.test.js`,
`options-vault.test.js`, and additions to the content tests (no "Open Passyble", the passkey card). Under `npm test`
`test/helpers/wasm-hooks.js` resolves `src/wasm/` to the stand-in where it isn't built (a checkout without the wasm build).
`test/e2e/browser-vault.e2e.mjs` runs browser mode in Chromium with a throwaway profile and a `connectNative` that
always answers "host not found" (so no native host on the PC is ever started): setup, a login saved from the save
prompt and filled from the menu, Options, a backup download, lock, unlock, a service worker stopped over CDP that
comes back unlocked, delete and open the backup.

**Not done in Phase A (Phase B and later, as planned).** Sync, passkeys, PRF quick unlock, recovery code, changing
the master password, the full vault page (creating cards and identities, notes, trash), import and export, website
icons, multiple vaults, Firefox. pass-wasm has no session snapshot (13.7), so after a service worker restart a pending
2FA code, grants, the vault search's grants (`logins.fill_cross` needs a new search), rate limits and the 2FA outcome
history start empty, and a soft lock becomes a full lock. `navigator.storage.persist()` is not called
(`unlimitedStorage` already keeps the data from eviction).

## 14. The pass-wasm API

What the extension's `LocalBackend` calls. The vault functions answer the protocol's envelope without an
id: `{"result": …}` or `{"error": {"code", "message"}}`, with the codes of PROTOCOL.md §2 plus
`no_vault` and `verification_required`. Bytes cross as `Uint8Array`.

```js
import init, { BrowserAgent, setKdf } from '../wasm/pass_wasm.js';
import { loadKdf } from '../wasm/kdf.js';

await init({ module_or_path: new URL('../wasm/pass_wasm_bg.wasm', import.meta.url) });
setKdf(await loadKdf(new URL('../wasm/pass_wasm_kdf.wasm', import.meta.url)));
const agent = new BrowserAgent(JSON.stringify({ device_id }));      // throws on a bad config
const file = await idb.get(vaultId);                                // the encrypted vault file
if (file) agent.load(file);
const key = (await chrome.storage.session.get('key')).key;          // after a service-worker restart
if (key) agent.unlockWithKey(new Uint8Array(key), idleMs);
```

| call | in | out (`result`) | errors and notes |
|---|---|---|---|
| `setKdf(fn)` | `fn(secret, salt, mKib, t, p) -> Uint8Array(32)` (from `loadKdf`), or `undefined` | | Every Argon2id run goes to `fn`; `undefined`: run in this module (fallback, keeps ~84 MiB) |
| `new BrowserAgent(config)` | `{"device_id", "auto_lock_secs"?: 900, "keep_list"?: true, "verify_each_fill"?: false}` | | Throws on unknown keys or an empty `device_id` |
| `hasVault()` | | `bool` | |
| `load(file)` | the vault file (`Uint8Array`) | `{"vault_id"}` | `invalid_state` while unlocked (lock first), `invalid_params` if not a vault file. Becomes this browser's vault |
| `checkMasterPassword(password, names)` (free function) | a new master password, a JSON array of names (e-mail address, vault name) | `{"ok", "score", "label", "entropy_bits", "issues", "name", "min_length"}` (plain JSON, no envelope) | The core's master password rule (ARCHITECTURE.md §7); `issues`: `too_short`, `common`, `contains_name`, `pattern`, `guessable`, in the order to show them. Needs no `BrowserAgent` |
| `siteSuggestions(query, limit)`, `siteNameFor(url)` (free functions) | what is typed in an editor (a name or website), at most how many (capped at 50); a URL or host | `[{"name", "domain"}]` (plain JSON, no envelope); the site's name or `undefined` | Popular sites (pass-core `site_suggestions`, `site_for_domain`): a new login's website suggested from its name and its name from its website, also before any vault exists (`sites.suggest` and `sites.name_for` once there is one). Nothing leaves the device. Needs no `BrowserAgent` |
| `create(password)` | master password | `{"vault_id", "grant"}` | `invalid_state` if there is a vault, `invalid_params` for an empty password or one that fails the master password rule (`checkMasterPassword`). Default Argon2id parameters. Store `takeSave()` |
| `unlock(password)` | master password | `{"locked": false, "grant"}` | `wrong_password`, `rate_limited` (5 a minute), `no_vault`. The agent's `unlock.password` |
| `unlockWithKey(key, idleMs)` | the 32-byte key from `storage.session`, ms without use so far | `{"locked": false}` | `wrong_password` if the key doesn't open the vault, `no_vault` |
| `vaultKey()` | | `Uint8Array(32)` or `undefined` (locked) | For `storage.session` right after an unlock or create |
| `verifyPassword(password)` | master password, while unlocked | `{"grant"}` | `wrong_password`, `locked` |
| `lock(completely)` | `false`: soft lock (the list stays for the menus while `keep_list`), `true`: everything | `{"locked": true}` | Saves first; grants are dropped. Store `takeSave()` |
| `setOptions(json)` | `{"auto_lock_secs"?, "keep_list"?, "verify_each_fill"?}` | `{}` | `invalid_params` on unknown keys. The vault stays open |
| `handle(line)` | a PROTOCOL.md §2 request line, optionally with `"grant": "<token>"` and `"confirmed": true` next to `params` | the response line (`{"id", "result"}` / `{"id", "error"}`) | See below |
| `tick()` | | | Runs a due save and the auto-lock |
| `nextTickMs()` | | ms until `tick` has work, or `undefined` | Ask after every call; an alarm or timer then calls `tick` |
| `idleMs()` | | ms since the last use | Keep it with the key for `unlockWithKey` |
| `takeEffects()` | | JSON array: `{"type": "copy", "text"}`, `{"type": "lock_state", "locked"}`, `{"type": "vault_changed"}` | Take after every call; copy texts are secrets (clipboard, cleared after 45 s) |
| `takeSave()` | | the encrypted vault file (`Uint8Array`) if the agent wrote it since the last call, else `undefined` | Write it to IndexedDB after every call that may change the vault (and after `tick`) |
| `exportVault()` | | the encrypted vault file now, `undefined` without a vault | Saves first while unlocked: the backup download |
| `driveSync(token, vaultName)` | a Google access token, the vault's name (kept with the Drive file) | a `DriveCall` | Throws while locked. Once done the merged vault is saved if it is still the agent's vault (`result.current`): store `takeSave()`, apply `takeEffects()` (`vault_changed` when it merged items). Section 15 |
| `DriveCall.list(token)`, `DriveCall.download(token, fileId)`, `DriveCall.account(token)` (static) | | a `DriveCall` | `list`: `[{file_id, vault_id, name, modified, size}]`; `download`: the bytes with `takeBytes()`; `account`: `{email, display_name}` |
| `call.begin()`, `call.respond(status, headersJson, body)`, `call.fail(kind)` | an HTTP answer (any status), or no answer (`"bad_address"`, else unreachable) | a step: `{"send": {method, url, headers}}` (its body: `takeBody()`) or `{"done": {"result"}}` / `{"done": {"error": {code, message}}}` | Codes: `auth_required`, `network`, `conflict`, `not_found`, `corrupt`, `locked`, `internal`. `free()` when done |

`handle` in browser mode, compared with the native wire:

* Every method except `status` answers `no_vault` while there is no vault; `status` adds `"vault": bool`
  and its `features` include `vault.browser` (and never `unlock.hello_browser`, `totp.from_image` or
  `icons.get` in this build).
* `"grant"` (from `create`, `unlock` or `verifyPassword`) counts the request as verified: per-fill
  verification with `verify_each_fill` on, and passkeys that demand user verification (UV flag). Without
  one those answer `verification_required`; verify the user in an extension page and send the request
  once more with the new grant. A grant is used up by the request it comes with, even a failing one.
* `"confirmed": true` is the user's yes, in an extension page, to `logins.fill_cross` (the popup) and
  `cards.fill` (the in-page confirmation frame or the popup's pick). Without it they answer `cancelled`.
  Only the background may set `grant` and `confirmed`, never from a content script's message.
* `unlock` answers `cancelled` (open the popup or the unlock window instead and resolve when the vault is
  open); `totp.popup`, `app.show_item` and `server.pair` answer `not_supported`.
* `passkey.create` without the card's `consent` and `passkey.get` without a picked passkey answer
  `cancelled` (Phase B).

## 15. Phase B for Google Drive: what was built

Branch `feature/extension-drive` (2026-11-08), for the owner's request in 2.1: a vault in the browser always
comes from the desktop app, the user's Google Drive, or (later) a Passyble account. The rest of Phase B is
not in it.

**Rust.**

* `Core/core/src/http.rs` (new): `HttpRequest`, `HttpResponse`, `FetchFailure`, `Step`, `Exchange`, a `Transport`
  trait. `Core/core/src/gdrive.rs`: the Drive sync, list, download, delete and account written once as async
  functions over a `Transport` (6.1). The apps keep the blocking `gdrive_sync` and the others; the extension
  uses `gdrive_sync_exchange`, `gdrive_list_exchange`, `gdrive_download_exchange`, `gdrive_account_exchange`.
* Features: `gdrive-core` (the sans-IO Drive code, no network stack; pass-wasm uses it), `sync-core` (the
  vault's sync bookkeeping and `SyncResult`, implied by `webdav` and `gdrive-core`); `gdrive` = `webdav` +
  `gdrive-core`.
* pass-wasm: `src/drive.rs` (`DriveCall`) and `BrowserAgent.driveSync` in `src/bindings.rs` (section 14). A
  finished sync saves the merged vault if it is still the agent's vault and pushes `vault_changed` when it
  merged items.

**JavaScript** (`Extension/src/`).

* `background/local/google.js`: Google sign-in (6.2). `background/local/drive.js`: `driveFetch` and
  `DriveSync`, the triggers and retries (6.6).
* `LocalBackend`: `drive(make, send)` runs a `DriveCall` in turn with the other calls; `driveSync(token, name,
  send)`; `setMeta(fields)`; `create` and `openFile` take record fields; `info()` returns `source`, `name`,
  `account`, `pending`, `syncedAt`, `syncError`; it emits `changed` for a saved user change of a Drive vault.
  `vault-store.js`: records may carry `source` (`"drive"` or none), `name`, `account`, `pending`, `syncedAt`,
  `syncError`; `save(id, file, now, fields)`.
* `background.js`: the `drive.*` page messages (docs/PROTOCOL.md, extension notes); `vault.create` and
  `vault.open-file` removed; `vault.delete` only for a legacy vault; `vault.state` and `popup.state` report
  the Drive state. On `runtime.onInstalled` with `update`, a legacy vault opens setup at `#move` (4.5).
* Client id: `scripts/google-config.mjs` (`npm run google-config`) writes the git-ignored
  `src/google-client.json`; `scripts/package.mjs` writes it into the packages (docs/GOOGLE_DRIVE.md).
* Error codes `auth_required`, `network`; reasons `drive_not_set_up`, `drive_scope`, `drive_other_account`,
  `not_synced` (`src/shared/errors.js`).

**UI.** Setup: 2.2 (Drive, Sign in, the Windows app); Ready says "In Google Drive (email)"; no backup step.
Popup and Options: 2.5. Strings in all 9 locales.

**Tests** (no network). `Core/wasm/tests/drive.rs` (two browser vaults sharing one Drive vault; refused
tokens, no answer, a locked vault); core's Drive tests unchanged, plus the same sync through an `Exchange`.
`Extension/test/drive-sync.test.js` against a fake Google (`test/helpers/fake-drive.js`: stubbed
`chrome.identity`, a fake Drive v3): sign-in, list, create, download, upload, conflict, offline queue,
retry, 401 renewal, sign-in states, flush before lock, restart. Also `background-vault`, `welcome-vault`,
`options-vault`, `popup-vault`, `account-ui`, `package.test.js` (client id config), `local-wasm.test.js`
(the real wasm Drive, skipped when `src/wasm/` isn't built); the stand-in `test/helpers/fake-wasm.js` has a
`DriveCall`. Manual: docs/TESTING.md items 96 to 108.

**Not done yet.** WebDAV and Passyble Server sync in the browser; Passyble Cloud (6.6); PRF quick unlock;
passkeys; Firefox (no `chromiumapp.org` redirect, so no Google sign-in there yet); the rest of Phase B and C.

## 16. Shared vaults, policies and secure send (`Core/wasm/src/teams.rs`)

Teams and Family in the browser (ARCHITECTURE.md §15 to §17), in the same module. Plain Rust in `teams.rs` with JSON
at the boundary (tested natively and in Node by `Core/wasm/tests/teams.rs`), exported in `bindings.rs`. Functions that
answer the envelope say `{"result": …}` / `{"error": {"code", "message"}}`; those that hand over bytes return an
object and throw. The JSON shapes are the core's records (PROTOCOL.md §1) with snake_case names and enums as
snake_case strings (`"edit"`, `"org"`).

| call | in | out (`result`) | notes |
|---|---|---|---|
| `agent.ensureKeyset(account)` | the account id on the backend that hosts the shared vaults (Cloud `acc_…`, or the user name on a self-hosted server) | `{"public_keys", "fingerprint"}` | Makes the keyset in this browser's vault if missing (one keyset for every backend: the same keys, signed for this id); publish `public_keys` there, store `takeSave()` |
| `agent.homeSummaries()` | | `VaultSummaries` of this browser's vault | For the calls across vaults |
| `agent.homeStamp()` | | a string, `undefined` while locked | The same while `homeSummaries()` would give the same list: keep the list (and a `SearchIndex`) until it changes |
| `agent.openShared(file, account)` | a shared vault's file, the account id | a `SharedVault` (throws) | The vault must be unlocked (its keyset opens the shared vault). The accepted members list is remembered in this browser's vault: store `takeSave()` |
| `shared.info()` | | `SharedInfo` | Members, roles, `role`, `anchored`, `signer_fingerprint` |
| `shared.summaries()` | | `VaultSummaries` | Keep it for the menus and the soft lock |
| `shared.item(id)` | | the item JSON with its secrets, or `null` | A secret: fill-only (`can_reveal` false) fills but never shows or copies |
| `shared.upsert(json)`, `shared.delete(id)` | an item | `{"id"}`, `{}` | `invalid_params` for a viewer or fill-only member |
| `shared.merge(file)` | a downloaded copy | `{"added", "updated", "deleted", "unchanged", "dirty", "notice"}` | Upload `save()` when `dirty`; `notice` as `takeNotice`; store `agent.takeSave()` |
| `shared.save()` | | the encrypted file (`Uint8Array`) | Store it and upload it |
| `shared.changeMembers(json)` | `[{"op": "add", "keys", "role", "group"?}, {"op": "set_role", "account", "role"}, {"op": "set_group", "account", "group"}, {"op": "replace_keys", "keys"}, {"op": "remove", "account"}]` | `SharedInfo` | A manager only |
| `shared.leave()` | | `{}` | A manager while another remains; upload `save()`, then delete the file |
| `shared.takeNotice()` | | `MembersNotice` or `null` | Lost member changes applied again or dropped, a key replaced after a manager left |
| `shared.transfer(id, direction, remove)` | `"to_home"` or `"from_home"`, `true` to move | `{"id"}` of the new item | Store both files |
| `multiSearch(groups, query)`, `multiForUrl(groups, url)` | `groups`: a JSON array of `VaultSummaries` | `[{"vault_id", "summary"}]` | One order across vaults |
| `new SearchIndex(groups)`: `search(query)`, `searchPositions(query)`, `forUrl(url)`, `free()` | as `multiSearch` | as `multiSearch`; `searchPositions`: a `Uint32Array` of places in the groups' summaries, one after the other | The lists read once for many keystrokes and pages; build it when they change, `free()` the old one |
| `multiDefaultSaveVault(groups, url?, preferred?)` | | `{"vault_id"}` (`null`: none editable) | The save banner's default |
| `policyCheck(policy, local)` | the account service's policy JSON, `{"master_password_score"?, "auto_lock_secs"?, "two_step_enabled"}` | `[{"rule", "message"}]` | Rules `master_password_strength`, `auto_lock`, `two_step` |
| `policyAllows(policy?, chosenAutoLockSecs?)` | | `{"export", "sharing_outside", "auto_lock_secs"}` | `undefined` policy: no organisation |
| `publicKeysCheck(keys)` | public keys JSON | `{"valid", "fingerprint"}` | Show the fingerprint before adding someone |
| `sendSeal(data, options)` | bytes, `{"kind": "text" or "file", "name"?, "mime"?, "expires_at", "max_views"?, "password"?}` | `{ciphertext: Uint8Array, meta, key, password_auth}` (throws) | Upload `ciphertext` and `meta` (and `password_auth`); `key` goes in the link's fragment only |
| `sendOpen(ciphertext, meta, key, password?)` | | `{kind, name, mime, data: Uint8Array}` (throws) | The secure-send open page: `key` from `location.hash` |
| `sendInfo(meta)` | | `{"expires_at", "max_views", "size", "has_password"}` | Before opening |
| `sendPasswordAuth(meta, password)` | | `{"auth"}` | Sent to the service before the download |
| `sendLink(base, id, key)`, `sendParseLink(link)` | | `{"link"}`, `{"send_id", "key"}` | |

The secure-send open page needs only the `send*` functions: no `BrowserAgent`, no vault. With a password it runs
Argon2id (the vault defaults, 64 MiB); a page can hand that to `pass-wasm-kdf` with `setKdf` as the extension does.

## 17. One Passyble password in the browser (`Core/wasm/src/account.rs`)

The cryptography is in ARCHITECTURE.md §18. App mode is unchanged: the Passyble app on the computer holds the account key and the
extension asks nothing. In browser mode a vault linked to a Passyble account (file version 3) opens with the
account key (AK), never with a master password; the browser gets AK from the Passyble password and the Secret Key
(the service's password wrap, after a sign-in signature, then from the copy kept in the browser, offline), or from
another device of the account that approves this browser as a new device (its QR, or the 6-digit code). Argon2id of
the password runs where every other run does: through `setKdf`'s runner, a fresh `pass-wasm-kdf` instance per run
(§3.5). The keys stay in WebAssembly memory as objects the extension frees once used; what crosses is the
account service's blobs (base64url JSON), a Secret Key's text (to keep in the extension's IndexedDB) and, only if
the extension wants it, AK's 32 bytes (`toBytes`).

| call | in | out | notes |
|---|---|---|---|
| `vaultFileAccess(file)` | a vault file | `{"result": {"kind", "account", "ak_id", "account_recovery"}}` | `kind`: `"password"`, `"account"` (linked), `"members"`; without opening it |
| `agent.vaultAccess()` | | the same for this browser's vault | `no_vault` without one |
| `agent.unlockWithAccountKey(ak)` | an `AccountKey` | `{"result": {"locked": false, "grant"}}` | `invalid_params` for another account or another key of it, `wrong_password` if the slot doesn't open |
| `agent.verifyAccountKey(ak)` | an `AccountKey`, while unlocked | `{"result": {"grant"}}` | "Confirm each fill" with the Passyble password: the key must be the vault's |
| `secretKeyText(text)` | typed or pasted (case, spaces, dashes and the `P1` don't matter) | `{"result": {"text"}}` (`P1-XXXXX-...`) | `invalid_params` with the core's reason (a recovery code is named as such) |
| `parseKitQr(text)` | the Emergency Kit's setup QR | `{"result": {"email", "account", "secret_key"}}` | |
| `qrSvgPath(text)` | | `{"result": {"size", "path"}}` | One SVG path in a `size` square, quiet zone included (error correction M, as the desktop draws QR codes) |
| `new AccountPassword(password, secretKey, salt, kdfJson)` | prelogin's `salt` and `kdf` (`{"alg", "m_kib", "t", "p"}`) | an object: `authPub()`, `signIn(email, nonce, deviceName, platform)`, `salt()`, `kdf()`, `openAccountKey(account, akId, wrapJson)` | One Argon2id run. Throws `"invalid_params: ..."` below the client bounds or for a Secret Key that doesn't read; `openAccountKey` throws `"wrong_password: ..."`. Sign exactly the address and device name the service normalizes (trimmed, lower case; control characters dropped, 64 characters) |
| `AccountKey.fromBytes(account, bytes, akId)`, `AccountKey.openPrf(account, akId, prfOutput, credentialId, wrapJson)` (static) | | an `AccountKey`: `account()`, `akId()`, `fingerprint()`, `toBytes()`, `akSignPub()`, `signRequest(nonce, method, path, body)`, `passwordWrap(accountPassword)`, `secretKeyWrap(text)`, `openSecretKey(wrapJson)`, `prfWrap(prfOutput, credentialId)` | `signRequest` is `X-Pass-Key-Sig` over the exact body bytes. The PRF calls are there for the per-browser quick unlock (§5.2), which is not built yet |
| `new DeviceApprovalKeys()`, `DeviceApprovalKeys.restore(secret)` | | `secret()`, `encPub()`, `commitment()`, `reveal()`, `approvalQr(requestId)`, `code(requestId, account, rA)`, `open(requestId, account, akId, rA, sealedJson)`, `invitationMac(qr)`, `openInvitation(invitationId, account, akId, sealedJson)` | `open` gives an `ApprovedKeys`: `accountKey()`, `secretKey()`. Keep `secret()` in `storage.session` while the request waits |

Errors of the object methods are thrown as `Error("<code>: <message>")` so the extension can tell
`wrong_password` from the rest. Tests: `Core/wasm/tests/account.rs` (natively: a linked vault in `BrowserHost`, the
password blobs as JSON, an approval round trip, the Secret Key and QR helpers, and `fixtures/linked.vault`, a vault
linked to the account key of `core/tests/account_key_vectors.json`), and `Extension/test/account-keys-wasm.test.js`
(the real module in Node: the vectors' Secret Key, sign-in key, signature, password wrap, request signature,
`sk_wrap`, PRF wrap and kit QR, and the fixture opened through the extension's code).

The extension side (`Extension/src/background/account-keys.js`, the popup's unlock form, `src/account/account.html`):
the Secret Key is asked once per browser profile and kept in the extension's IndexedDB unless "This is a shared
computer" is ticked; beside it the address, `ak_id`, salt, parameters and the password wrap, so the password opens
the vault offline. Online it is `POST /v1/account-key/unlock` when the browser is signed in to that account, else
`POST /v1/prelogin` and `POST /v1/session/password`, which also signs the browser in. A new device asks with `POST
/v1/account-key/requests` without a session and polls with `X-Pass-Request-Token`. AK is used for the one unlock
and freed. Password change, the Secret Key, the recovery code and resets stay in the apps (design decision 5).

**Not built yet**: the per-browser PRF quick unlock (§5.2 was never built for master-password vaults either; when it
is, it wraps AK for linked vaults with `prfWrap` / `openPrf` and needs the WebAuthn spike from an extension origin),
a vault made linked in the browser (the apps link vaults), approving another device from the browser (the browser
is only ever the new device), and reading the Emergency Kit's QR with a camera.
