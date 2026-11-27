# Passyble for Windows (desktop app)

The Tauri v2 app around the headless agent (`Core/agent`). Users see it as **Passyble** (window
titles, tray, Start menu, Apps & features, installers: `productName` in `tauri.conf.json`). It was
called "Pass" first and "SenPass" after that, and everything an existing install depends on keeps
the "Pass" name: the executable `Pass.exe` (`mainBinaryName`; the autostart value, URL scheme, native messaging manifests and the
passkey package point at it), the `identifier` `com.sensyble.pass`, the native messaging host
`com.sensyble.pass`, `pass+server://`, the data folders `%APPDATA%\Pass` and `%LOCALAPPDATA%\Pass`,
the Credential Manager targets and the "Pass" autostart value. It provides:

* the vault UI: onboarding, a list of vaults with unlock (master password or Windows Hello), search, item details with a
  live 2FA code (shown as dots until revealed), the editor with a password generator, and settings; after an
  auto-lock the list stays on screen without secrets ([soft lock](#locking-and-the-list-kept-on-screen));
  logins, notes, [cards and identities](#cards-identities-custom-fields-and-tags) with custom fields and tags,
  a [Trash](#trash), [Export](#export) and [Password health](#password-health)
* first-run help: a [Get started checklist](#get-started-checklist) for a new vault, a
  [browser extension setup guide](#browser-extension-setup-guide) (the extension ships with the installer)
  and [Help with short tutorials](#help-and-tutorials) in Settings
* the browser extension's back end: the agent's IPC server, which `pass-native-host.exe`
  relays Native Messaging to
* **global keyboard shortcuts** ([below](#global-keyboard-shortcuts)): **Quick Access** search, **Scan QR code on
  screen** for a 2FA code, the **auto-type** hotkey for native Windows apps, and more
* a **TOTP popup** by the tray for 2FA prompts that can't be filled
* the **passkey consent** and **passkey picker** dialogs, for the Windows passkey provider and for older
  extensions: the extension answers a page's passkey requests in the page itself (its cards: "Sign in with your
  passkey?", "Save a passkey for <site> in Passyble?", with **Use another device**), so a request from the browser
  comes with the passkey picked or the save consented (`passkey.get` with `id`, `passkey.create` with `consent`) and
  no Passyble window opens; only Windows Hello's own dialog, over the browser, when the vault's policy asks for it
* optionally, a **Windows 11 system passkey provider** (`webauthn.dll` plugin authenticator), so
  every browser and native app can use Passyble passkeys through Windows' own passkey dialogs
* a tray icon (Open, Lock, Lock completely, Sync now, Generate password, Quit), close-to-tray and a single instance
* a per-user NSIS installer with signed in-app updates (Settings → About), and a per-machine MSI for
  IT deployment

```
Core/desktop-app/
  src-tauri/            Rust crate `pass-desktop` (binary `Pass.exe`)
    src/main.rs         setup, plugins, window events, command registration
    src/state.rs        AppState, agent lifecycle, IPC server start, prompt registry
    src/ui.rs           `pass_agent::Ui` implementation (blocking prompts, unlock requests)
    src/commands.rs     Tauri commands used by the windows
    src/vaults.rs       vault list: switching the agent between vaults, rename/remove/show in folder
    src/server.rs       Connect to Passyble Server: pairing links, QR codes, connection check, connect
    src/signin.rs       Sign in to Passyble Server (password), change / adopt password, invite and reset links
    src/sizes.rs        file sizes for Settings ("84 KB · 132 items"), one formatter for the vault file and the remote copy
    src/devices.rs      Passyble Server: Settings → This vault → Signed-in devices (list, sign out), "signed out" sync state
    src/twofactor.rs    Passyble Server: two-factor sign-in (status, turn on with a QR code, recovery codes, turn off),
                        Recent security activity
    src/trash.rs        Trash: list, restore, delete for good, empty
    src/export.rs       Export… (encrypted, Passyble JSON, CSV) through the save dialog
    src/health.rs       Password health and the optional breach check (Have I Been Pwned, k-anonymity)
    src/google_oauth.rs Google sign-in for Drive backup: loopback + PKCE, token endpoint, Credential Manager
    src/gdrive.rs       Google Drive backup: sign-in, restore, turn on / off, background sync
    src/autotype.rs     hotkey → foreground window → match → SendInput / quick-pick
    src/shortcuts.rs    the global keyboard shortcuts: settings, validation, one registration per action
    src/quick_access.rs Quick Access (search every unlocked vault, copy)
    src/screen_qr.rs    Scan QR code on screen: monitors in memory (GDI), QR decode, the "Add two-factor
                        code" session, the editor's scan
    src/platform/       OS integration: win32.rs maps it onto pass-windows (Windows/platform, the
                        Win32/WinRT code), stub.rs for other OSes
    src/hello.rs        Windows Hello unlock (vault key bound to a Windows Hello key) + hello/ (keywrap, policy)
    src/clipboard.rs    copy with auto-clear + clipboard-history exclusion
    src/native_messaging.rs   browser host manifests + HKCU registration
    src/setup_guide.rs  Get started checklist state, browser extension setup guide (browsers, bundled
                        extension, "is it connected?"), downloads page link
    src/background.rs   auto-lock tick, folder reload, sync scheduler (WebDAV / Passyble Server / Google Drive)
    src/tray.rs, popups.rs, settings.rs
    src/updates.rs      in-app updates: daily check, "Update and restart" (tauri-plugin-updater)
    src/app_versions.rs forced and recommended updates: the version requirements check, its cache
    src/read_only.rs    read-only mode below the minimum version: which window commands still run
    src/applog.rs       rolling log file %LOCALAPPDATA%\Pass\logs\pass.log
    src/i18n.rs         UI language: the catalogs (ui/i18n), tr!/trn!, Windows' display language
    src/autostart.rs    "Start with Windows" (HKCU Run key)
    src/passkey_provider.rs   Windows 11 passkey provider: settings glue, credential metadata sync
    src/passkey_provider/     ctap.rs (CTAP2 CBOR), win.rs (webauthn.dll FFI, COM server), logo.svg
    capabilities/default.json per-window permissions
    tauri.conf.json, tauri.bundle.conf.json (adds the native host sidecar and the bundled browser
    extension for installers),
    tauri.release.conf.json (adds updater artifacts; release builds only)
    tauri.macos.conf.json (merged by Tauri on macOS only: .app and .dmg, icon.icns, Info.plist and
    entitlements from ../macOS/bundle); the Mac and Linux installer configs live in their own
    repositories and are passed with --config (macOS/bundle/tauri.bundle.conf.json,
    Linux/installer/tauri.linux.conf.json), like tauri.bundle.conf.json on Windows
  ui/                   plain HTML/CSS/ES modules, no build step
    i18n.js + i18n/     texts: t/tn/tx, number and date formats; one catalog per language (see Translations)
    index.html + main.js + views/   main window (views/items-model.js: the pure part of cards, tags, trash,
                        health and security activity, tested in test/items-model.test.mjs)
    prompt.html/js      passkey consent and choice, Windows Hello unlock / per-fill confirmation
    totp.html/js        TOTP popup
    quickpick.html/js   auto-type quick-pick
    quickaccess.html/js Quick Access (views/quickaccess-model.js)
    qrscan.html/js      "Add two-factor code" after a screen scan (views/qrscan-model.js)
    styles.css + fonts/ the look of every window (docs/BRAND.md tokens) and the bundled Space Grotesk
  scripts/              stage-extension.mjs (the bundled browser extension), make-icons.mjs,
                        brand/ (logo sources)

Windows/installer/      the Windows-only installer parts (see Windows/README.md):
  installer-hooks.nsh   NSIS install/uninstall hooks (install folder, move from SenPass / Pass,
                        native host, clean-up)
  nsis-lang/            the NSIS setup's texts: Passyble.nsh (the hooks' texts), Hindi.nsh and
                        Indonesian.nsh (Tauri's texts, which Tauri doesn't ship for those two)
  passkey-cleanup.wxs   MSI custom action that removes the passkey provider on uninstall
  before-bundle.ps1, build-native-host.ps1   beforeBuildCommand of tauri.bundle.conf.json
  packaging/            sparse MSIX (package identity) for the passkey provider: AppxManifest.xml,
                        build-sparse-package.ps1 (stages <install>\package\, signs Passyble.msix)
```

## Building on Windows

Prerequisites:

* Rust (MSVC toolchain): `rustup default stable-x86_64-pc-windows-msvc`
* Visual Studio Build Tools with the "Desktop development with C++" workload (MSVC + Windows SDK)
* WebView2 runtime. Windows 10/11 already have it; the installer bootstraps it otherwise.
* Tauri CLI: `cargo install tauri-cli --version "^2"`

Development run (from `Core/desktop-app/src-tauri`, its own Cargo workspace with its own `Cargo.lock` and
`target\`; it needs PassybleWindows and Passyble-macOS cloned next to PassybleCore):

```powershell
cargo tauri dev            # or: cargo run -p pass-desktop
```

In a dev run, auto-registration points the browsers at `pass-native-host.exe` next to `Pass.exe`
(`target\debug\`), so build it too: `cargo build -p pass-native-host` in Core's root workspace, then copy it
from `Core\target\debug\` (or give both workspaces one `CARGO_TARGET_DIR`).

Installers (`bundle.targets`: NSIS and MSI; Tauri downloads NSIS and the WiX toolset on first use):

```powershell
cd Core\desktop-app\src-tauri
cargo tauri build --config tauri.bundle.conf.json
# -> target\release\bundle\nsis\Passyble_<version>_x64-setup.exe   per user, no admin rights
# -> target\release\bundle\msi\Passyble_<version>_x64_en-US.msi    per machine (admin), IT deployment
```

* **NSIS setup** (what users download, and what the in-app updater installs): installs to
  `%LOCALAPPDATA%\Programs\Passyble` with a Start menu shortcut "Passyble"; silent install / uninstall:
  `Passyble_<version>_x64-setup.exe /S`, `"%LOCALAPPDATA%\Programs\Passyble\uninstall.exe" /S`. An install
  under an earlier name (`%LOCALAPPDATA%\Programs\SenPass` or `Programs\Pass`, Apps & features "SenPass" /
  "Pass") is uninstalled first, keeping vaults, settings, "Start with Windows" and its Start menu / desktop
  shortcut (now "Passyble"; `Windows/installer/installer-hooks.nsh`). The uninstaller also
  removes the browser registrations, the URL scheme and the autostart entry, and keeps vaults and
  settings unless **Delete the application data** is ticked (even then vault files stay).
* **MSI** (per machine): `msiexec /i Passyble_<version>_x64_en-US.msi /qn` installs to
  `C:\Program Files\Passyble` with a Start menu shortcut for all users; `msiexec /x` (or Apps & features)
  removes what it installed. Each user's browser registration is made by the app at its first start
  (HKCU, manifests in `%LOCALAPPDATA%\Pass\native-messaging` since Program Files isn't writable). The
  app doesn't update itself there (Settings → About: "Managed install. Update with the new MSI");
  deploy the next version's MSI, which upgrades in place (fixed `upgradeCode`).
* **Languages:** the NSIS setup follows the Windows display language (English, Spanish, French,
  German, Chinese Simplified, Japanese, Korean, Hindi, Indonesian; else English; no language
  dialog). The MSI stays `en-US`: it is for IT deployment. To add a language to the NSIS setup, add
  it to `bundle.windows.nsis.languages` and to `Windows/installer/nsis-lang/Passyble.nsh`
  ([docs/TRANSLATING.md](../docs/TRANSLATING.md#the-windows-installer)).

Release builds and their signing keys are handled by Sensyble's release process, outside this repository.

`tauri.bundle.conf.json` runs `Windows/installer/build-native-host.ps1` first. The script builds
`pass-native-host` and `passyble-mcp` (the connector for AI tools, [docs/AI_TOOLS.md](../docs/AI_TOOLS.md)) in
release mode (honouring `CARGO_TARGET_DIR`) and copies them to the git-ignored
`src-tauri/binaries/<name>-<triple>.exe`.
It also adds the files as `bundle.externalBin` sidecars, which the installer places next to `Pass.exe`
as `pass-native-host.exe` and `passyble-mcp.exe`. That config is kept separate because Tauri refuses to build (even
`cargo check`) while a declared sidecar file is missing.

**Bundled browser extension.** The extension isn't in the browser stores yet, so the installer ships it
for the [setup guide](#browser-extension-setup-guide). `Windows/installer/before-bundle.ps1` runs
`scripts/stage-extension.mjs` (Node, no dependencies), which stages two `bundle.resources` of
`tauri.bundle.conf.json`, both git-ignored:

* `src-tauri/extension/` → `<install>\extension\`: the unpacked extension for **Load unpacked** in Chrome,
  Edge and Brave, with the repo's `manifest.json` **including its `key`**, so the browser gives it the ID
  `CHROMIUM_EXTENSION_IDS` allows (any other ID gets "The browser can't reach Passyble"). The files are those of
  `Extension/dist/pass-chromium-unpacked.zip`: `buildPackages` of `Extension/scripts/package.mjs` (`src/`,
  `icons/`, `_locales/`, `THIRD_PARTY_NOTICES.md`; no tests, scripts, `node_modules`, `dist` or dotfiles). The
  script refuses a manifest without `key`.
* `src-tauri/extension-firefox.zip` → `<install>\extension-firefox.zip`: the Firefox package
  (`pass-firefox.zip`) for **Load Temporary Add-on…**.

The browser reads an unpacked extension from that folder, so an app update (which replaces the folder's
files) also updates the extension: the browser picks the new files up when it restarts, or with
**Reload** on its extensions page. Uninstalling Passyble removes the folder, and the browser then reports
the extension as missing. Debug builds (no installer) point the guide at the repo's `Extension/` folder
and `Extension/dist/pass-firefox.zip` (after `npm run package`).

**No console window.** `Pass.exe` is a Windows GUI program in debug builds too
(`#![windows_subsystem = "windows"]`); `pass-native-host.exe` stays a console program because it talks
to the browser over stdio. Diagnostics (start-up, hotkey and browser registration errors, passkey
provider, URL scheme, update checks, panics; never vault contents or secrets) go to
`%LOCALAPPDATA%\Pass\logs\pass.log` (rotated to `pass.old.log` at 512 KB) and to stderr when there is
one (`cargo run`). Settings → About → Log file → **Open folder**.

**Updates** (`src/updates.rs`). Settings → About shows the state under the version: "Up
to date", "Version X available" with **What's new** (the release page) and **Update and restart**, which
downloads with a progress bar, saves and locks the vault, runs the installer in passive mode (small
progress window), and Passyble starts again with its window open. With **Check for updates automatically**
on (default), release builds check about a minute after start and then daily; a found update only puts
a dot on the Settings button (never a dialog). Downloads must carry a minisign signature matching
`plugins.updater.pubkey`. Debug builds check only on **Check now**, unless `update_endpoints` is set. A **managed install** (built
for the MSI, or running from Program Files) never installs updates and doesn't check by itself;
Settings → About says "Managed install. Update with the new MSI" (`updates::managed_install`).

Which copies update themselves (`updates::install_kind`, `updates::UpdateWay`, unit-tested in `updates.rs`):

| install | how it is told apart | what a newer version leads to |
| --- | --- | --- |
| Windows NSIS (per user) | not the MSI bundle, not under Program Files | **Update and restart** |
| Windows MSI (per machine) | `bundle_type()` is `msi`, or `Pass.exe` under Program Files | "Your administrator installs Passyble updates", no automatic checks |
| Linux AppImage | `$APPIMAGE` and `$APPDIR` (`pass_linux::connector::appimage`), not a .deb/.rpm bundle | **Update and restart** (the `.AppImage` file is replaced, Linux/README.md "Updates") |
| Linux .deb, .rpm | anything else on Linux | "Version X available" and **Download page** (https://www.passyble.com/download), never an install |
| macOS | always | without the `macos-updater` feature (the default): no feed checks, **Download page**; with it, **Update and restart** (macOS/README.md "Updates") |

`update_status` says which (`way`: `in_app`, `download` or `managed`; `self_update`; `enabled` false when this
copy doesn't read the feed at all). Below the App versions minimum the "Update required" screen's **Update**
installs in the app when `self_update` is true and opens the download page otherwise.

**One update feed for every platform.** All desktop copies ask the same
`https://github.com/sensyble/pass-releases/releases/latest/download/latest.json` and pick their entry from its
`platforms`: `windows-x86_64` (the NSIS `-setup.exe`), `linux-x86_64` and `linux-aarch64` (the `.AppImage`),
`darwin-aarch64` and `darwin-x86_64` (`Passyble.app.tar.gz`, only once the macOS updater is on). It has one
`version` for all of them, so every platform of a release is built and added to the one file before it is
published; a platform missing from it sees "There's no update for this ... yet" on each check. Each build adds
its entry with `node ../scripts/release-feed.mjs` (Passyble-Core `scripts/`, tested by
`scripts/test/release-feed.test.mjs`), which verifies the signature as the installed apps do (Ed25519 by the
key that signs this release over the file's bytes, and the trusted comment naming that file and version), and that
each platform points at its own kind of file. The key that signs a release is `signWith` in
`scripts/updater-signing.json`: `"current"` is `plugins.updater.pubkey`; `"previous"` is `previousPubkey`, the key
the installed apps still trust, for the first release that embeds a new public key:

```sh
node scripts/release-feed.mjs --feed latest.json --version 0.2.0 --platform windows-x86_64   --file desktop-app/src-tauri/target/release/bundle/nsis/Passyble_0.2.0_x64-setup.exe --notes "Passyble 0.2.0."
node scripts/release-feed.mjs --feed latest.json --version 0.2.0 --platform linux-x86_64   --file <target>/release/bundle/appimage/Passyble_0.2.0_amd64.AppImage
```

Upload `latest.json` last, after every file it names. The admin panel's Releases page can read the same URL for
`windows`, `linux` and `macos` (`[releases]` in pass-admin.toml): a platform without an entry in it shows "no download
for this platform" instead of the others' version.

**Forced and recommended updates** (`src/app_versions.rs`, `src/read_only.rs`, `ui/views/app-versions.js`,
docs/PROTOCOL.md §4.5). The owner sets a minimum and a recommended version per platform (`windows`, `linux`,
`macos`) in the admin console.

* The check is an anonymous `GET https://account.passyble.com/api/app-versions`: no cookies, no account, device,
  vault or version data, 10 s timeout, no redirects. It follows **Check for updates automatically**: on (default),
  release builds ask at start and every 6 hours (30 minutes after a failure); off, only **Check now** asks. Debug
  builds ask by themselves only with `app_versions_endpoint` set.
* The last good answer is kept with its time in `%LOCALAPPDATA%\Pass\app-versions.json` (`pass_agent::app_versions::Cache`)
  and used when a fetch fails or before the first one; with nothing ever fetched nothing is blocked. Malformed values
  count as no requirement.
* Below the minimum: a full-window **Update required** screen with the admin's message (as text), **Update** (the
  in-app updater when this copy updates itself, else https://www.passyble.com/download) and **View my passwords**,
  which leaves the screen for the vault with a bar on top: "Update required. Passyble is read-only until you update."
  (its **Update** brings the screen back). Read-only mode is enforced in the agent (`Agent::set_update_required`:
  browser fills, saves, edits and passkeys answer `update_required`, the Windows passkey provider is refused,
  auto-type finds nothing, no sync, no use counts) and for the window commands by `read_only::gate`, which lets
  only the commands in `read_only::ALLOWED` through (unlock, lock, view, copy, export, settings, updates); a test
  checks every registered command is listed as allowed or blocked. The agent starts read-only from the cached
  answer, before its first request. After an update the new version is compared at once, so the block lifts at
  start even offline.
* Below the recommended version: an **Update available** bar with **Update** and **Dismiss**, closed per
  recommended version (kept in the same file).

**When Passyble talks to the sync server** (`src/background.rs`, `src/sync_schedule.rs`, docs/ARCHITECTURE.md §10):
right after unlock and on "Sync now"; about 2 s after the last edit if the vault has changes the server hasn't
seen. Google Drive vaults also check for other devices' changes every 20 s while a Passyble window has focus or the
vault was used in the last 2 minutes, every 2 minutes while the user is active on the PC (keyboard or mouse in the
last 15 minutes), and every 15 minutes when idle, all with +-20 % jitter; and right away on window focus, wake from
sleep and when the browser extension asks for logins, if the last check is over 20 s old. One check of an
unchanged Drive vault is one small `files.get` (3 requests a minute while in use; docs/GOOGLE_DRIVE.md has the
quota estimate). WebDAV and Passyble Server vaults check when a window gets focus or the PC wakes, if the last check
is over 5 minutes old, and every 30 minutes while the vault was used in the last 30 minutes; a check of an unchanged
vault is one conditional `GET` answered `304` with no body, an edit adds one `PUT`. Never while locked. Failures back
off (30 s doubling with jitter, up to 15 minutes for Google Drive, 1 h otherwise); a Drive rate limit also slows
the 20 s checks to 2 minutes for an hour and is counted in the log (`sync: Google Drive rate limit #n`). Settings →
Sync shows "Synced just now" / "Synced 5 min ago" or "Changes pending" (or "Not synced" with the error), with
**Sync now** / **Retry** / **Sign in…**; background checks don't flash "Syncing…".

**File sizes** (`src/sizes.rs`). Settings → This vault → **Vault file** shows the size of the vault file on disk and
its item count ("84 KB · 132 items"; also while soft-locked, from the kept list; only the size when locked
completely). Settings → Sync → **Backup on Google Drive / Passyble Server / WebDAV** shows the size of the remote
copy as the last sync saw it: `SyncResult.remote_bytes` (what was uploaded, what was downloaded, the Drive
metadata's `size`, or, for a `304`, the size recorded in the vault's local sync state), kept in `SyncStatus`. No
request is made just to show it; before the first sync that knew it, the row says "Size shows after the next sync".

**Footer.** "Created for the community by Sensyble" (small, muted) links to https://www.sensyble.net at the bottom
of Settings, the welcome screen and the unlock screen. It calls `open_sensyble_site`, which opens that one address
and nothing else.

**Usage counts** ("most used first"): auto-typing a login, copying its password or 2FA code (main window
or TOTP popup) and typing a code from the popup count as a use, saved in the vault file but never a reason to sync: they go up
with the next sync for any reason, or after 6 hours at most. The list's **Filter** menu has **Most used**: the used items, most used first.

WebDAV addresses: `https://`, or plain `http://` only for this PC or a private network (the core's
`check_plain_http`, the same rule as Android and Passyble Server addresses); Settings → Sync refuses a public
`http://` address with the core's explanation, and the core's WebDAV calls refuse one saved by an older version.

Cargo features: `webdav` (on by default) enables WebDAV sync (`ureq`/`rustls`); `gdrive` (on by default,
needs `webdav`) enables Google Drive backup. Use `--no-default-features` to leave out sync. `ring` (rustls'
crypto, and the Windows Hello signature check) needs a C compiler for the target (MSVC on Windows).

**Google Drive** needs a Google OAuth *Desktop app* client at build time, else the Google options are
hidden: set `PASS_GOOGLE_CLIENT_ID` and `PASS_GOOGLE_CLIENT_SECRET` in the environment, or put both lines
(`NAME=value`) in the git-ignored `src-tauri/google-oauth.env`. A Desktop client's secret is not
confidential (Google's own words for installed apps). Setting up the Google Cloud project:
docs/GOOGLE_DRIVE.md.

Icons in `src-tauri/icons/` (app, tray and installer), `ui/logo.svg`, the passkey provider logo, the extension
icons and the Android launcher / notification icons are generated from one logo definition
(`node scripts/make-icons.mjs`): the wordmark's "y", a key derived from the Sensyble mark, in lime with a thin dark lime
edge on transparent, no tile (see `scripts/brand/README.md` and `docs/BRAND.md`, "Logo").
The UI icons are [Lucide](https://lucide.dev) outline icons (ISC license), vendored as data in
`ui/icons.js` (only those in use; the extension has the same file); see `THIRD_PARTY_NOTICES.md`.
The look follows `docs/BRAND.md` (neutral greys with a hint of lime, soft radii, light/dark from the
system), all in `ui/styles.css`. The UI font is Space Grotesk (variable, SIL OFL 1.1), bundled as woff2
in `ui/fonts/` (latin, latin-ext, vietnamese; licence in `ui/fonts/OFL.txt`), so nothing is fetched.

## First run and settings

Settings live in `%APPDATA%\Pass\settings.json`:

| key | default | |
|---|---|---|
| `vaults` | [] | the vaults added on this PC (see below) |
| `active_vault` | none | `id` of the vault the agent points at (the last one opened) |
| `auto_lock_minutes` | 15 | minutes without use; each use starts it again (sliding, see below). Also locks on Win+L / sleep (all vaults) |
| `hotkey` | `Ctrl+Alt+P` | auto-type hotkey; `""` when cleared |
| `shortcuts` | {} | the other global shortcuts by action id (`quick_access`, `scan_qr`, `show_app`, `lock`, `generate_password`, `new_note`): the keys, or `""` for none; a missing action has its default (see [Global keyboard shortcuts](#global-keyboard-shortcuts)) |
| `start_minimized` | false | start in the tray |
| `device_id` | random UUID | identifies this PC in vault merges (shared by all vaults) |
| `extra_extension_ids` | [] | extra Chromium extension IDs allowed to use the native host (unpacked dev builds) |
| `passkey_provider` | false | register Passyble as the Windows 11 system passkey provider (registers its Windows package, then one restart; see "Windows passkey provider") |
| `defaults_version` | 1 | which changed defaults were applied (1: Windows Hello password interval 14 → 30 days, see Policy) |
| `last_server_url`, `last_server_user`, `last_server_pins` | none | the last Passyble Server sign-in, to prefill the form |
| `google_oauth` | none | `{client_id, client_secret}`: a Google OAuth Desktop client instead of the one compiled in (development) |
| `update_auto_check` | true | Settings → About → Check for updates automatically |
| `update_endpoints` | [] | `latest.json` URLs to use instead of the built-in one (testing; the signature check stays) |
| `app_versions_endpoint` | none | the version requirements URL to use instead of `https://account.passyble.com/api/app-versions` (testing; also turns on automatic checks in debug builds) |
| `show_site_icons` | true | Settings → Display → Show website icons (see [Website icons](#website-icons)) |
| `keep_list_when_locked` | true | Settings → Unlock → Keep list visible when locked (see [Locking](#locking-and-the-list-kept-on-screen)) |
| `extension_connected` | false | a browser extension has connected on this PC (or "Mark as done" in the [setup guide](#browser-extension-setup-guide)): ticks the Get started checklist's browser step |

"Start with Windows" isn't in this file: it is the `Pass` value under
`HKCU\Software\Microsoft\Windows\CurrentVersion\Run` (`"…\Pass.exe" --background`).

Each entry of `vaults`:

| key | |
|---|---|
| `id` | random UUID; names the vault's Windows Hello blob and Credential Manager entry |
| `name` | shown in the vault list ("Personal", "Work", ...) |
| `path` | the vault file; put it in a OneDrive/Dropbox/Syncthing folder to sync between PCs |
| `webdav` | optional `{url, username}`, plus `pins` and `server_device` when connected through a Passyble Server pairing link; the password (Passyble Server: the device token) is in Windows Credential Manager (service `com.sensyble.pass.webdav`, user `<vault id>:<username>@<url>`) |
| `google_drive` | optional `{account_email}` (plus `sign_in_needed: true` while Google wants a new sign-in), instead of `webdav`: backed up to that Google account's Drive app folder. The refresh token is in Windows Credential Manager (target `Pass/GoogleDrive/<e-mail>`, one per account, shared by its vaults) |
| `windows_hello` | Windows Hello unlock for this vault |
| `hello_policy` | `{ password_interval: "never"\|"1d"\|"7d"\|"14d"\|"30d"\|"restart", verify_each_fill, fill_grace_minutes }` (default `30d`, off, 1) |
| `hello_offer_dismissed` | "Not now" on the "Unlock with Windows Hello next time?" card |
| `master_password_weak` | the master password last typed to unlock this vault here is below the master password rule (only this yes or no; see [Password health](#password-health), master password tip) |
| `master_password_tip_dismissed` | "Dismiss" on that tip; both are cleared when the master password is changed here |
| `get_started` | the [Get started checklist](#get-started-checklist) shows for this vault: set when the vault is added on this PC, cleared by Hide or once every step is done |
| `last_opened_ms` | last successful unlock, shown in the list |

**Migration.** Older builds kept one vault in `vault_path` / `webdav` / `windows_hello`. On the first
start of a multi-vault build that vault becomes the first list entry (named after the file, "Personal"
for `pass.vault`), the old file is kept once as `settings.json.pre-vaults`, `hello.bin` moves to the
vault's own blob, and the old WebDAV credential (`<username>@<url>`) is copied to the vault's entry on
first use. An untouched default path whose file was never created is not migrated. Passyble keeps writing
the active vault into the old keys, so an older build started on the same profile still opens the
vault in use (it ignores the list).

### Vault list

Every new master password (a new vault, Change master password, a new one after a recovery code, a newly
chosen Passyble Server password) must pass the core's master password rule (docs/ARCHITECTURE.md §7): the
`master_password_check` command checks it a moment after each keystroke and the field lists why it is refused
(too short, a common password, built from the e-mail address, user name or vault name, a repeated pattern or
keyboard walk, too easy to guess) or says it is strong enough (`ui/views/master-password-model.js`,
`masterPasswordMeter` in `signin.js`); the commands that set it check the rule again. Existing master
passwords are never checked, so a vault with an older, weaker one opens as before.

Onboarding offers two big choices: **Use on this PC** (a new vault: just the master password, twice; the
name and the location, e.g. a OneDrive folder, are under **More options**; tagged "New to Passyble? Start
here." for whoever isn't sure which to pick) and **Sign in to Passyble Server**
(see below), plus **Open an existing vault file**. Restoring from WebDAV and a Passyble Server pairing link are
under **More options**. Restoring downloads the file, checks the master password, keeps a local copy and
keeps syncing. Each of them adds the vault to the list (an optional name; the file name is used otherwise)
and opens it. Every password field has a show/hide toggle and a Caps Lock warning; Enter submits.

Whenever Passyble is locked completely (at start-up without a list kept from the last run, "Lock
completely", after "Switch vault", or any lock with "Keep list visible when locked" off) the main window
shows the unlock form; at start-up with a kept list, and after an ordinary lock,
the list stays on screen instead ([below](#locking-and-the-list-kept-on-screen)). With a single vault that's all it shows (plus **Add vault**). With
several, it shows **Your vaults**: every vault with its name, location (path, or WebDAV host) and when it
was last opened, and the unlock form (master password, or Windows Hello if it is on for that vault) for the
selected one. The last used vault is selected.

**Add vault** (the vault switcher at the bottom of the sidebar, shown also with a single vault, and the
unlock screens) opens one chooser with every way in: **Create a vault**, **Create a vault in your Passyble
account**, **Open a vault file**, **Google Drive**, **Passyble Server**, and under **More options** WebDAV
and a pairing link. While a vault is open it stays open until the new one is set up; **Back** returns to it.
There is no page that only lists vaults.

**Create a vault in your Passyble account** (`src/account_vaults.rs`): signed out, the account's sign-in
comes first. The vault gets the account's empty home slot on Passyble Cloud (`<u>/personal`) or a new one
(`POST /api/v1/vaults`, `<u>/v-…`), a local copy under `%LOCALAPPDATA%\Pass\vaults` and its first upload;
it opens with the Passyble password when the account has one, else with a master password of its own. The
plan's vault limit ("Your plan hosts up to N vaults…") shows under the form.

Each vault's own menu (right-click or ⋯ on its row in the vault switcher and on **Your vaults**; the same
rows in **Settings → This vault** for the open vault) has **Rename…**, **Show in folder**, **Remove from
this computer** and, for a vault of the signed-in account's own on Passyble Cloud (never its home vault,
never a Team or Family vault), **Delete vault from your account**: the vault's name typed to confirm,
**Export first…** for the open vault, then `DELETE /api/v1/vaults/<u>/<vault>` (owner only) and the vault
and its local copy go from this computer. Another device whose sync is then refused (`no_vault_access`)
checks `whoami`; when the vault is gone from the account it takes it off its list (the file stays) and says
so. Removing from this computer happens at once with an **Undo** toast
(the entry, its WebDAV password and its Windows Hello unlock come back in place; `src/undo.rs`), never
deletes the file, and after the undo window deletes only that vault's Windows Hello blob and key on this
PC (its WebDAV password right away; a copy stays in memory for Undo). With no vaults, onboarding shows
instead.

**Undo instead of "Are you sure?".** Deleting an item moves it to the [Trash](#trash) at once; the toast's
**Undo** takes it out again (it then returns on every device after sync). Questions remain only for what
can't be undone (emptying the trash or deleting an item from it for good, starting a new empty vault after
a reset, discarding unsaved edits).

**Errors** are plain sentences with what to do next, one mapping for every command
(`src/errors.rs`, `friendlyError` in `ui/errors.js`): "Can't reach pass.example.com. Check the address and
your internet connection…", "Too many attempts. Wait 15 minutes…", "The server's certificate changed…",
"Wrong master password. Check Caps Lock…". **Sync problems** never open a dialog: a quiet **Sync paused ·
Retry** pill appears next to the vault name (tooltip: the reason); Passyble keeps retrying in the background.
Users never see technical text: OS and library errors, HTTP codes, HRESULTs and the like go to the log
(`errors::logged`, `%LOCALAPPDATA%Passlogspass.log`) and the window shows what happened and what to do;
anything unmapped that still looks technical becomes "Something went wrong. Try again." (`ui/errors.js`).
Features this copy can't offer (Google Drive without an OAuth client, sync without the `webdav` feature,
updates without an updater key, Windows passkeys without a registrable package) are hidden or say "Not
available in this version of Passyble".

**Import by drag and drop.** Drop an export file (CSV, JSON, ZIP, 1PUX, a Google Authenticator QR
screenshot) anywhere on the unlocked main window: the Import preview opens. The path comes from the
window's native drag-and-drop event and stays in Rust (`import_dropped`). Shortcuts are listed on the empty
pane and in every button's tooltip ("Lock (Ctrl+L)").

**Keys and the Mac's menu bar.** The window's own keys are one table (`ui/views/app-keys.js`): Ctrl on
Windows and Linux, Cmd on a Mac (shown as ⌘ ⇧ ⌥ ⌃), where Control stays Control. Search Ctrl+F, New login
Ctrl+N, Edit Ctrl+E, Save Ctrl+S (the editor), Settings Ctrl+, , Lock Ctrl+L, Lock completely Ctrl+Shift+L,
Move to Trash Delete in the list (Cmd+Backspace on a Mac), Esc to go back; a Mac adds Close Window Cmd+W
(Esc's job in a dialog or page, else the window hides) and Quit Cmd+Q. `ui/main.js` runs them, and Help →
Keyboard shortcuts lists this OS's. A Mac also gets a menu bar (`app_menu.rs`; Windows and Linux have none):
Passyble (About, Settings, Services, Hide, Quit), File (New Item, Lock, Lock completely, Close Window),
Edit (Undo, Redo, Cut, Copy, Paste, Select All: without it these keys do nothing in a web view's text
fields), View (Search, Full Screen), Window (Minimize, Zoom, Bring All to Front) and Help, with the same
keys; its commands reach the window as `menu-command`.

Only one vault is unlocked at a time. There is one agent, and unlocking a vault from the list points it
at that vault (`Agent::reconfigure`, which saves and locks the previous one first). The browser
extension, auto-type and the Windows passkey provider always use the active vault. A switch resets the
WebDAV sync status, the sync scheduler and 30-second folder reload follow the new vault, and Windows'
passkey list is emptied and refilled from the new vault once it is unlocked. Auto-lock, hotkey and the
other app-wide settings are shared. In the unlocked app, the vault name at the top of the sidebar and
Settings → This vault → Switch vault → **Switch…** lock the vault completely and return to the list.

### Locking and the list kept on screen

Every ordinary lock is soft. **Lock** (Ctrl+L, the lock button, tray **Lock**), **auto-lock**, **Win+L** and **sleep** are a *soft lock*
while Settings → Unlock → **Keep list visible when locked** is on (the default, `keep_list_when_locked`,
applied with `Agent::set_keep_list`): the agent forgets the vault key and every secret, but keeps the list
of items without secrets (`pass_core::ItemSummary`: titles, usernames, websites, linked apps, passkey
account names, has-password / has-2FA / has-notes / has-fields flags, tags, a card's holder, brand, last four
digits and expiry, an identity's name, e-mail and company) in memory (`Agent::summaries`,
`pass_agent::LockKind::Soft`). The main window stays on the vault view: search, filters, selection and
website icons (from the cache; nothing new is fetched until the next unlock) keep working, a **Locked**
pill sits next to the vault name, and the item pane shows the username and websites with the password,
the 2FA code and the notes as dots and **Unlock to view**. **Nothing asks to unlock by itself** (no
Windows Hello when the window is shown or focused). Copying a username works as is. Anything that needs a
secret or changes the vault (copy password or code, show password / code / notes, Edit, favorite,
duplicate, delete, New, Import, Settings, Sync) opens the vault's unlock form in a dialog over the list,
with Windows Hello starting right away when it is set up, and then finishes that action: one click.
**Cancel** (or Esc) leaves it locked, without an error. Auto-type, the browser extension and the
Windows passkey provider ask for an unlock as before (Windows Hello in the prompt window; the master
password in that dialog when Hello is declined or not set up).

On a soft lock the window drops every secret it held: a revealed password or code, the editor (an
unsaved edit is discarded, with a toast), an import preview, the TOTP popup and the quick-pick. On
unlock the list and the open item are reloaded with their real data; search and selection stay.

**Lock completely** (Ctrl+Shift+L, tray **Lock completely**, or the lock button's menu: right-click the
button, or click it while soft-locked; "Also hides the list until you unlock") is the only lock that also
drops the list and shows the unlock screen, without starting Windows Hello right away. The plain lock button
never does: while soft-locked it only opens that menu. Switching or removing a vault and adding a Passyble
Server vault take the list off the screen too (another vault is shown next). Quitting, restarting and
installing an update drop it from memory but keep the copy on disk below, so the next start is soft-locked. With the setting off, every lock is complete and turning it off drops a list kept right now.

The list is also kept between runs (`pass_agent` kept_list.rs): `%LOCALAPPDATA%\Pass\kept-lists\<vault
id>.bin`, sealed with DPAPI for this Windows user, no secrets (never a card number, security code, PIN or
custom field value; files from before tags, cards and identities still open and gain those keys at the next
write, so the Cards / Identities filters and the Tags section work while soft-locked). At start-up the agent loads it and starts
soft-locked, so the browser extension lists the logins before the first unlock (picking one unlocks,
then fills) and the window shows the list with the Locked pill. Quitting, restarting, updating and
switching vaults keep it; **Lock completely** (`lock` with `forget: true`, tray **Lock completely**),
removing the vault, this device being signed out of Passyble Server and turning the setting off (every
vault's) delete it.

Behind it (`commands.rs`): `status` has `soft_locked` (and `keep_list`); `list_items`, `search` and
`get_item` answer from the kept list while soft-locked (rows and items marked `locked: true`; `get_item`
then carries no password, 2FA secret, notes or custom fields, only `has_password` / `has_totp` / `has_notes` /
`has_fields`), and `copy_field` copies what the list holds: a username, a card's holder and expiry, an
identity's name, e-mail and company. Every other command that needs the vault answers
"The vault is locked" (`state::VAULT_LOCKED`), which the window recognises (`isLockedError`) to unlock and
retry. The `lock` command takes `full: true` for a complete lock, plus `forget: true` for Lock
completely chosen by the user (the kept copy goes too). The `lock-state` event and the
extension's `lock_state` notification carry `{ locked, soft }`.

**Settings** (`ui/views/settings.js`) is grouped like the Android app: **This vault** (name, file with
Move… / Locate…, Change password, Signed-in devices for Passyble Server vaults, Password health, Trash, Switch
vault) · **Passyble Server** (Passyble Server vaults: two-factor sign-in, recovery codes, Recent security
activity) · **Unlock** (Windows Hello, Ask for master password, Auto-lock, Keep list visible when locked, More
security options) · **Autofill** (browser extension, Windows passkeys; developer options only in debug builds or once extra extension IDs are set) ·
**Keyboard shortcuts** (every global shortcut with a recorder, Clear and Reset to default; applied at once) ·
**Sync** (Google Drive, Passyble Server, WebDAV, and a status row with its one action) · **Import and export**
(Import, Find duplicates, Export…) · **Startup** · **Help** ([below](#help-and-tutorials)) · **About** (version and updates, log file, device ID). Every row comes from `settingsRow` / `settingsGroup` in `ui/lib.js` (the counterpart
of Android's `Rows.kt`): an outline icon, a one-line title, one line of state under it, the explanation
behind (i), and a switch, drop-down or button at the end. Rows with a chevron open a page of their own
(**More security options**: Confirm each fill, After confirming; **Signed-in devices**; **Recent security
activity**) with a back arrow
(Esc). **Save settings** stays at the bottom of the pane while it scrolls.

Settings → **This vault** manages the active vault's name and file; its WebDAV account is under Sync and
its Windows Hello switch under Unlock. Changes to the vault path, WebDAV account and auto-lock time apply
immediately, without a restart (`Agent::reconfigure`). A new vault path or WebDAV account first saves the
vault to the old place, then locks it, so you unlock again against the new configuration. Moving the
vault copies the current file to the new place and keeps the old one.

`Pass.exe --background` starts with no window, in the tray only. The native host uses this flag when the
extension needs the agent and Passyble isn't running, and so does the start with Windows (the Run key). Such a
start never asks for Windows Hello: the vault stays locked, quietly, until you open Passyble or the browser or
auto-type asks for something you did (`startup.rs`). The "show the window on the next start" marker a restart or
an update leaves counts for 5 minutes only, so a stale one can't open the window at the next Windows sign-in.
A second launch only brings up the existing window.

### Get started checklist

`ui/views/getstarted.js`, `src/setup_guide.rs` (`get_started`, `get_started_show`). A card above the vault view's
empty pane (where the shortcuts are) for a vault **added on this PC**: a new one ("Use on this PC", Create new
vault), or one opened, restored or signed in to. Right after Create vault it is there behind the "Create a recovery
code?" offer and ticks that step once the offer closes. "Get started", "2 of 5 done" with a progress bar, and the
steps, each with its button (the first open step's is the primary one) and a done state Passyble can see:

| step | button | done when |
|---|---|---|
| Connect your browser | **Set up…**: the [extension setup guide](#browser-extension-setup-guide) | an extension has connected on this PC (`extension_connected`, or one is connected now), or **Mark as done** in the guide |
| Bring your passwords over | **Import…** | the vault has items |
| Save a recovery code | **Create…**: the [recovery code](#recovery-code) dialog | the vault has a recovery code |
| Use on your phone and other PCs | **Show me how**: the sync tutorial, whose **Sync settings** opens Settings at Sync | the vault syncs: Passyble Server, WebDAV, Google Drive, or its file is in a OneDrive / Dropbox (or Google Drive, iCloud, Syncthing) folder |
| Unlock with Windows Hello (only where Windows Hello is set up) | **Turn on** (`enable_hello`, one Windows Hello prompt) | Windows Hello is on for the vault |

While the checklist is on, the sidebar's "Unlock with Windows Hello next time?" stays away (`status.offer_hello`), so
two cards never ask the same thing. **Hide** hides it for this vault ("Show it again in Settings → Help"); once every
step is done it hides itself (`get_started_show(false)`), with "You're all set" if that happened on screen. It
looks again whenever the empty pane comes back (closing Import, Settings…), after the guide or the recovery dialog
closes, and after an unlock (not while soft-locked: the recovery code needs the vault). **Who gets it:** the
vault's `get_started` flag is set only by `Settings::add_vault` for a new entry, so vaults listed by an earlier
version (and a migrated single-vault file) never show it: no checklist for people who have used Passyble for
long. **Settings → Help → Get started checklist → Show again** brings it back.

### Help and tutorials

Settings → **Help and tutorials** (a page of its own, `ui/views/settings.js` `helpPage`, `ui/views/help.js`):

* **Get started checklist**: on the start page / Hidden, **Show again** (closes Settings and shows it).
* **Set up the browser extension**: the [guide](#browser-extension-setup-guide).
* **How to**: short tutorials in a dialog, numbered steps plus a button to the setting or flow they are about:
  Fill passwords in your browser (opens the guide) · Auto-type into Windows apps (the hotkey in use, the
  `windows:<exe>` website trick, the 2FA popup's Type it; Autofill settings) · 2FA codes (paste the setup key into
  the editor's two-factor field, the extension fills the code after the password, its Scan QR on this page, importing
  from authenticator apps; Import…) · Passkeys (the extension, the browser's own dialog as fallback, Windows
  passkeys; Autofill settings) · Sync with your phone and other PCs (Passyble Server sign-in, Google Drive when this
  build has Google sign-in, a OneDrive / Dropbox folder, WebDAV, the Android app, the downloads page; Sync settings,
  Downloads page) · Import from another password manager (Import…) · Recovery code and a forgotten master password
  (Create a recovery code…) · Keyboard shortcuts (the main window's, the auto-type hotkey, the extension's
  Ctrl+Shift+L / Alt+Shift+P / Alt+Shift+K). The texts name the app's own labels through placeholders
  (`{path}` = "Settings → Sync → WebDAV" in the UI's language), so they match the screen in every language.
  Options a build doesn't have (Google Drive, sync) are left out.
* **Downloads**: opens https://github.com/sensyble/pass-releases/releases/latest (`open_releases_page`, that one
  address only): the Windows setup and release notes, for installing Passyble on other PCs.

## Sign in to Passyble Server

When the Passyble Server admin created your account (`pass-server user add`), you don't create or pick a vault
file on the PC: you sign in (`src/signin.rs`, `ui/views/signin.js`, docs/PROTOCOL.md §3.4).

* **Where.** First start, or the vault list's **Sign in to Passyble Server** button (also under Add existing
  vault). A sign-in link or a plain server address from the browser extension (`server.pair`) opens the
  same form (in a dialog over an unlocked vault, which stays unlocked until the sign-in finishes).
* **Input.** One **Server** field takes the address (`pass.example.com`, `host:8443`, `https://host/prefix/`,
  spaces and a trailing `/` are fine; `https://` is assumed) or any `pass+server://` link (pasted, also
  with text around it, or read with the picture / clipboard QR buttons next to the field). An invite link
  fills in the server, user name and certificate pin. Then **User name or e-mail** (sent as typed; the
  server decides) and the password. The last server and user are remembered, so next time the cursor
  starts in the password. A pasted pairing link (with a token) switches to the pairing flow below.
* **Trust on first use.** A server whose certificate isn't publicly trusted and that came without a link
  (so without a pin): Passyble fetches its certificate pin without trusting it (`pass_core::fetch_server_pin`)
  and asks **Trust this server?**, showing the fingerprint in groups of four characters (the same
  characters `pass-server status` prints after `sha256:`). Only after **Trust this server** is the pin used
  and kept with the account; a different certificate later is reported as changed.
* **Choose your own password.** If the admin set the password, Passyble asks for a new one (twice, with a strength
  hint), in one sentence: the admin gave you a temporary password, so pick your own; only you will know it. It changes it on the server before anything else; until
  then the server doesn't let this device touch the vault.
* **The vault.** The server has none: Passyble creates it with your password and uploads it. It has one: Passyble
  downloads it and opens it with the same password. If that fails because the admin reset your password,
  Passyble asks once for your **previous password**, re-encrypts the vault with the new one and uploads it.
* **Storage.** The local copy is a cache Passyble manages at `%LOCALAPPDATA%\Pass\vaults\<vault id>.vault`
  (merged with an older cache of the same vault if one is there); the list shows the vault as
  `<user>@<host>`. The device token goes to Credential Manager, the pins and device name ("Pass on
  <COMPUTERNAME>") to the vault's `webdav` entry, as for pairing. Unlocking later works like any vault
  (master password = your Passyble Server password, or Windows Hello).
* **Change password.** Settings → This vault → Change password → **Change…** (Passyble Server vaults): current password
  (checked against the vault first), new password twice. Order: server first, then the vault is re-wrapped,
  saved and uploaded. If the upload fails, background sync retries it; a device signing in meanwhile asks
  for the previous password and repairs the vault. If the old password was set by the admin, the vault key
  is replaced too. The server signs out the account's **other devices** (Passyble says "Your other devices were
  signed out"); they sign in again with the new password. **Changed on another device?** in the same
  dialog: enter the new password; Passyble checks it with the server (`server_verify_password`) and re-wraps
  this (unlocked) vault without the old password. When that change signed this device out (the usual
  case), Passyble signs in with the new password instead (`server_login`), keeps the new device token, then
  re-wraps and syncs. Also the way back in when the old password is forgotten but this PC still has the
  vault unlocked.
* **Change password (other vaults).** For a vault that isn't on Passyble Server (local file, folder, WebDAV, Google
  Drive) Settings → This vault → Change password → **Change…** asks for the current password (checked against
  the open vault with `Vault::check_password`, which replaces nothing), then the new one twice with the strength
  hint (`change_master_password`, main window only). Order: the vault key is re-wrapped
  (`Vault::change_master_password`), saved through the agent, then synced if the vault has a sync account (a failed
  upload is a warning; background sync retries). The dialog says that other devices ask for the new password the
  next time they unlock after receiving the change. The vault key doesn't change, so **Windows Hello keeps working**:
  its blob holds the vault key, not the password (`Vault::unlock_with_key`).
* **Two-factor sign-in.** When the account has it on ([below](#two-factor-sign-in-and-security-activity)),
  signing in, Choose your own password, Change password, Sign in again and setting a password with an invite
  or reset link answer `{step: "two_factor"}` instead of an error (`signin.rs`; `otp` on each command). The
  form then asks for the 6-digit code from the authenticator app (**Use a recovery code** switches the field)
  and sends the same request again with it; a wrong or used code says "That code is wrong or was already
  used…". A link's one-time code is used up only when the password is set; since that uses up the two-factor
  code too, the sign-in after it asks for the next code (`server_code_signin`). `errors.rs` words any
  `2fa_required:` / `2fa_invalid:` error that gets past these flows.
* **Signed out.** When the server refuses this device's token (the password was changed on another device,
  or the device was signed out from a device list), sync stops retrying: the vault view shows **Signed out ·
  Sign in again** and Settings → Sync says "Not synced · Signed out of Passyble Server" with **Sign in…**. Clicking it asks for the
  Passyble Server password only (same command as Changed on another device?: a new token, and a re-wrap if the
  password changed). "Sync now" still tries once.
* **Signed-in devices.** Settings → This vault → **Signed-in devices** (Passyble Server vaults; its own page) lists the account's devices
  (`server_list_devices`): name, when it signed in and was last used, **This device**, and **Must change
  password** for one signed in with an admin-set password. **Sign out** (after a confirmation;
  `server_revoke_device`) stops that device at once. Signing out this PC forgets its token and opens the
  sign-in dialog. Older servers say they can't list devices.
* **Password changed elsewhere.** Unlocking with the new password fails on the local copy, so Passyble downloads
  the server's copy, opens it with that password, merges the local copy into it (unsynced edits are kept)
  and replaces the local file. Windows Hello keeps working unless the vault key was replaced; then unlock
  with the password once.

### Invite and reset links (e-mail)

With e-mail set up on the server (Server/README.md), accounts can be created without a password and
users can reset theirs (docs/PROTOCOL.md §3.5).

* **The `pass+server` URL scheme.** Passyble registers itself for `pass+server://` links (Tauri deep-link
  plugin: the NSIS installer writes `HKCU\Software\Classes\pass+server`, the MSI the same key under HKLM, from `plugins.deep-link` in
  `tauri.conf.json`; **debug builds register themselves at every start**, pointing the scheme at the dev
  `Pass.exe`, so run the installed build once to point it back). Clicking the **Open in Passyble** button on the
  e-mailed page, or the `pass+server://` link in the e-mail, starts Passyble or hands the link to the running
  instance (single-instance plugin with its `deep-link` feature) and opens the matching form. Pasting the
  link into the **Server** field of Sign in to Passyble Server does the same. A link only fills in a form.
* **Invite** (`…&invite=…`): **Choose your password** (twice, strength hint) → Passyble sets it with the
  one-time code, signs in and creates the vault (or opens the one on the server).
* **Reset** (`…&reset=…`): **Reset your password** → Passyble sets the new password with the code. The server
  signs out every device, so Passyble signs in again right away and stores the new token. Then the vault, which
  the server can't re-encrypt:
  1. the account's vault is **unlocked** in Passyble: re-encrypted with the new password at once (the link
     opens in a dialog over the open vault instead of locking it);
  2. it is in the vault list with **Windows Hello**: **Unlock with Windows Hello** re-encrypts it;
  3. else the server's copy: if another device re-encrypted it already, it opens; otherwise **Unlock your
     vault** asks for the previous password;
  4. **Start a new empty vault…** (on that screen, after an explicit confirmation): a new vault with the new
     password replaces the old one on the server (which keeps it as a version); local copies of the old
     vault stay in the list as "<name> (before reset)" (`signin.before_reset_suffix`, in the app's language),
     no longer synced.
* **Forgot password?** on the sign-in form: server address and user name (or e-mail address) → the server
  e-mails a reset link if the account has an address (the answer never says whether it exists). A server
  without e-mail says so ("ask your Passyble Server administrator").
* An expired or used link says so and suggests Forgot password? / the admin.

### 2FA links (`otpauth://`)

A link on a web page or in another app (or a QR code a scanner app opens) reaches Passyble as `Pass.exe "otpauth://..."`,
and starts adding that 2FA code. The link is untrusted input from anyone: **nothing is ever added without the user's
choice**, and it doesn't unlock anything by itself.

* **Who opens these links.** The NSIS installer's `PASS_REGISTER_OTPAUTH` (`Windows/installer/installer-hooks.nsh`) writes
  `HKCU\Software\Classes\otpauth` (`URL Protocol`, `shell\open\command`) **only when nothing handles
  `otpauth` yet** (it reads the merged `HKCR` view, so a per-machine handler counts). Uninstalling removes the key if it
  points at this install (not during an update). Another authenticator's handler is never overwritten silently:
  **Settings → Startup → Open otpauth links with Passyble** (`otpauth_handler.rs`, no admin rights) shows who has them and
  claims them on request. When Windows' own default-app choice (`UserChoice`) prefers another app, the row sends the
  user to Windows' settings instead, because only the user can change that. All registry access goes through the
  `Registry` trait; the tests use a fake and never touch the real keys. The MSI (per machine) registers nothing at
  install; the Settings button still works for the user, and an MSI uninstall doesn't remove a key claimed that way.
  `otpauth` is deliberately **not** in `plugins.deep-link`: that would make the NSIS template overwrite any handler,
  and debug builds re-register at every start.
* **The arguments** (`otpauth.rs`, `link_argument`). A link counts only as the first argument, and the rest of the
  command line is joined back into it, so a crafted link can't add flags such as `--background` (Windows pastes the
  link into `"%1"` without encoding quotes); a link launch honours no flags. A second `Pass.exe` hands the link to the
  running one through the single-instance plugin, which splits on `|`: the receiver joins it back.
* **Reading it.** `pass_core::otpauth_parse_link`: at most 2048 characters, `totp` only (`hotp` gets a plain message,
  Passyble doesn't do counter codes), no user info, port, fragment, repeated parameters or control characters; a labelled
  error that never echoes the link. Only the clean link rebuilt from the parsed values is stored.
* **Holding it.** `otpauth::Inbox` keeps the newest link in memory (zeroized when dropped, 10 minutes at most), never on
  disk or in the log or `PASSYBLE_TIMING_LOG`. The window gets the details only, never the secret, and answers with the
  link's id, so a newer link can't swap in under an open dialog. A first start also wipes the link from the process's
  copy of the command line (`scrub_command_line`); Tauri's own copy of the arguments lives as long as the process, and
  process-creation audit tools can still see the argument.
* **The flow** (`ui/views/otpauth.js`, `otpauth-model.js`). The main window shows up. Locked: the unlock screen says
  what's waiting and has a **Cancel** that drops the link; **Windows Hello isn't started by itself** for it. Then a dialog
  shows service, account, digits, period and algorithm as plain text, the matching logins (`otpauth_matches`: by website,
  name and account; a login with a 2FA code is never preselected and only replaced after saying so) and **A new login**.
  Cancel leaves nothing behind.
* **`otpauth-migration://`** isn't registered on Windows: an export is a set of many secrets, better brought in on
  purpose with Import (paste the links, or import screenshots).

## Connect to Passyble Server (pairing link, advanced)

[Passyble Server](https://github.com/sensyble/PassybleServer) also hands out `pass+server://` pairing links with a device token (`pass-server pair <user> --device
"<name>"`, printed with a QR code). Passyble turns a link into the vault's sync account (docs/PROTOCOL.md §3,
`src/server.rs`, `ui/views/server.js`):

* **Where.** Vault list → **Add existing vault → From Passyble Server** (also on first start: **Connect to Passyble
  Server**) adds the server's vault, or creates a new one there. **Settings → This vault → Use Passyble
  Server…** connects the open vault.
* **Input.** Paste the link, or **Read QR from picture…** (PNG/JPEG screenshot or photo, decoded with the
  core's `import-qr` decoder) or **Read QR from clipboard** (a Win+Shift+S snip of the terminal; the
  clipboard image goes through the same decoder as RGBA).
* **Check before saving.** The link is parsed with `pass_core::parse_pairing_link` and the connection is
  tested (`webdav_exists`, a HEAD on the vault file with the link's pin). The dialog shows the server
  (host:port), account, this device's name, the certificate status ("Pinned self-signed certificate" with
  the start of the pin, or "Trusted certificate" for a publicly trusted one, or a warning for
  `scheme=http`) and whether the server already has the vault. Errors are spelled out: wrong or revoked
  token, unreachable server, or a certificate that doesn't match the pin.
* **From Passyble Server.** If the server has the vault, Passyble downloads it, asks for its master password
  (checked before anything is written), keeps a local copy and syncs it (the WebDAV restore flow). If
  not, the form asks for a new master password, creates the vault locally and uploads it right away.
* **Use Passyble Server (open vault)** (Settings → Sync → Passyble Server → **Connect…**). Passyble syncs the unlocked vault with the server: an empty server gets
  this vault, a server holding a copy of this vault is merged. Only then is the account saved, and the
  vault stays unlocked (`Agent::set_webdav`). If the server holds a different vault, nothing changes and
  the dialog offers **Add as a separate vault…** (locks this vault and opens From Passyble Server).
* **Storage.** The token is stored like a WebDAV password (Credential Manager, per vault); the pins and
  the device name go to `settings.json` with the vault's `webdav` entry. Editing the WebDAV URL by hand
  keeps the pins only while the scheme and host:port stay the same. Pairing again replaces the token.
* **Certificate changed.** If the server's key no longer matches the pin (`PassError::CertificateChanged`),
  sync says the server's certificate changed (a quiet pill, with what to do); pair again with a new link.
* **From the browser extension.** The agent method `server.pair { link }` (docs/PROTOCOL.md §2) stores
  the link, brings up the main window and shows the same dialog prefilled: for the open vault when
  unlocked, the From Passyble Server form when locked. Nothing is applied without the user confirming there.

## Google Drive backup

Like WhatsApp backups (docs/GOOGLE_DRIVE.md): the encrypted vault file in the hidden app folder of the
user's Google Drive (scope `drive.appdata` only). Google never gets the master password or anything it
can decrypt; every choice shows "Google only stores your encrypted vault in a hidden folder for Passyble. It
can't read it: your master password stays the key."

* **Sign-in** (`src/google_oauth.rs`): OAuth for installed apps. Passyble listens once on
  `http://127.0.0.1:<random port>/`, opens the system browser at Google's consent page (PKCE `S256`,
  random `state`, `access_type=offline`), and the window shows "Finish signing in with Google in your
  browser" with **Cancel** (gives up after 5 minutes). The browser tab ends on "You can close this tab
  and return to Pass", and Passyble comes to the front. The code is exchanged for tokens; the account e-mail
  comes from Drive's `about.get`.
* **Tokens.** The refresh token goes to Windows Credential Manager once a vault uses the account; access
  tokens stay in memory and are refreshed shortly before they expire, and once more when Drive refuses
  one. When Google refuses the refresh token (`invalid_grant`: access removed, the 7-day expiry of an app
  in Testing, too many tokens), the credential is deleted and the account's vaults are marked "Sign in to
  Google again": background sync skips them and the vault view shows a quiet **Sign in to Google again**
  pill instead of retrying.
* **Use on this PC → Back up to Google Drive**: sign in, then the vault is created and uploaded (a failed
  upload is a warning; background sync retries).
* **Restore from Google Drive** (welcome screen, and **Add existing vault**): sign in → the vaults on
  that account → master password (checked before anything is written) → a local copy at
  `%LOCALAPPDATA%\Pass\vaults\<vault id>.vault`, listed as "Google Drive · <e-mail>".
* **Settings → Sync → Back up to Google Drive → Back up…**: syncs the open vault with the account
  (uploads it, or merges a copy already there) and only then saves the account; it replaces a plain
  WebDAV account (not offered for Passyble Server vaults). Then: the account, the status row with **Sync now**
  / **Sign in…**, and **Turn off backup** (optionally deleting the copy on Drive; Passyble's access is revoked when
  no other vault uses the account).
* **Sync** follows the same schedule as WebDAV (above); an unchanged vault costs one small metadata
  request (`Agent::sync_gdrive` → `pass_core::gdrive_sync`).

**Password history.** An item that kept earlier passwords (`Item::password_history`, up to 20, newest first)
shows **Password history (N)** in its detail pane (not while soft-locked): one row per entry with the date it was
replaced, the password as dots, **Show** and **Copy**. The item (`ItemDto`) carries only the dates
(`password_history_at`); a password is fetched when shown (`password_history_entry`, keyed by item id + index, plus
the entry's date to refuse a shifted index) and copied in Rust (`copy_history_password`, cleared after 45 s, not
a use of the item), and it is dropped from the page when hidden or the pane re-renders.

**Item list menu** (`ui/views/vault.js`): right-click (or Shift+F10 / the menu key, or the ⋯ button on a row) opens
Copy username / password / 2FA code (cards: card number / security code; identities: name / e-mail;
`copy_field`, clipboard cleared after 45 s), Edit, favorite, Duplicate and Move to Trash (with the Undo toast). The agent's `show-item` event ("Open in Passyble" in the extension) selects that item
(`main.js` keeps it until the vault is unlocked).

## Browser extension (native messaging)

At every start, Passyble writes two host manifests next to `Pass.exe`, or to
`%LOCALAPPDATA%\Pass\native-messaging\` if the install folder is read-only:

* `com.sensyble.pass.json` for Chrome, Edge, Brave and Chromium (`allowed_origins` are `CHROMIUM_EXTENSION_IDS` in
  `native_messaging.rs`, currently the unpacked ID pinned by the extension's manifest `key`, plus
  `extra_extension_ids`; the Opera Add-ons ID is in `OPERA_STORE_EXTENSION_IDS`; the Chrome Web Store and Edge Add-ons lists are empty until those IDs are assigned)
* `com.sensyble.pass.firefox.json` for Firefox (`allowed_extensions: ["pass@sensyble.com"]`)

Both point at `pass-native-host.exe` beside `Pass.exe`. Passyble then sets the default value of these keys to
the manifest path:

```
HKCU\Software\Google\Chrome\NativeMessagingHosts\com.sensyble.pass
HKCU\Software\Microsoft\Edge\NativeMessagingHosts\com.sensyble.pass
HKCU\Software\BraveSoftware\Brave-Browser\NativeMessagingHosts\com.sensyble.pass
HKCU\Software\Chromium\NativeMessagingHosts\com.sensyble.pass
HKCU\Software\Mozilla\NativeMessagingHosts\com.sensyble.pass
```

Each Chromium browser reads only its own key: without the Brave key, Brave reports the host as
not found.

Settings → Autofill → Browser extension shows each registration (its (i) has the host and manifest paths; a missing host
exe is called out) and **Set up…**, which opens the [setup guide](#browser-extension-setup-guide). Registration is
idempotent and heals itself if the install folder moves. The
uninstaller deletes those three keys when they point at the installed copy, and the manifests.

### Browser extension setup guide

`ui/views/extension.js`, `src/setup_guide.rs`. Opened from the Get started checklist, Settings → Help and
Settings → Autofill → Browser extension → **Set up…**. The extension isn't in the browser stores yet, so it is
loaded from the copy the installer ships ([Bundled browser extension](#building-on-windows)).

* **Browser.** Chrome, Edge, Brave and Firefox as a segmented choice. Preselected: the browser whose extension is
  connected right now, else the default browser (the https ProgId under `UserChoiceLatest` / `UserChoice` in
  `HKCU\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https`), else the first one found.
  A browser is found through `App Paths` (HKCU, HKLM, WOW6432Node), else its usual folder under Program Files or
  LocalAppData; one that isn't found is greyed and its **Open** button disabled ("Open it yourself").
* **Chrome, Edge, Brave:** 1. **Open the extensions page**: **Open Chrome** starts the browser
  (`extension_open_browser` takes only an id of `BROWSERS` and passes that browser's fixed page address, nothing
  else) and copies `chrome://extensions` / `edge://extensions` / `brave://extensions`, because Chromium browsers
  don't open their own pages from the command line: the user pastes it; **Copy address**. 2. **Turn on Developer
  mode**. 3. **Load Passyble**: Load unpacked, then paste the folder path into the folder window's address bar; the
  path is shown, with **Copy folder path** and **Show folder** (Explorer). 4. **Pin it to the toolbar**.
  5. **Check the connection** (below).
* **Firefox:** a warning that until Passyble is on addons.mozilla.org, Firefox loads it only as a temporary add-on
  and removes it when it closes. 1. **Open Firefox** at `about:debugging#/runtime/this-firefox` (the address is
  copied too). 2. **Load Temporary Add-on…** with the path of `extension-firefox.zip` (**Copy file path**, **Show
  file**). 3. Pin. 4. Check.
* **Live check.** While the guide is open it asks `extension_connected` every 2 s. The browser starts
  `pass-native-host.exe` when the extension talks to Passyble and keeps it running while its port is open, so a
  process snapshot (Toolhelp) finds a running host and, up its parent chain (Chrome starts it through `cmd.exe`),
  the browser: "Connected: Chrome and Passyble are talking to each other", with how to try it. Nothing is asked
  of the extension, so this works with every extension version. A detection also sets `extension_connected`
  in settings.json. **Mark as done** ticks the checklist step without it (e.g. when the popup wasn't opened).
  Copied paths and addresses are plain clipboard text (no secret, not cleared).
* Missing extension files (a build without them) show a warning with **Downloads page**; a missing host exe or a
  registration error show the same banners as Settings → Autofill.

## Global keyboard shortcuts

Settings → Keyboard shortcuts lists every action with its shortcut (`src/shortcuts.rs`,
`ui/views/shortcuts-model.js`). Each is registered on its own with the global shortcut plugin, so changing
or clearing one never touches the others, and a change applies at once (no "Save settings", no restart).

| Action | Default | |
|---|---|---|
| Quick Access | `Ctrl+Shift+Space` | as in 1Password |
| Scan QR code on screen | `Ctrl+Alt+Shift+Q` | Windows only; used by no common app, and AltGr+Shift+Q types nothing in the usual layouts |
| Auto-type | `Ctrl+Alt+P` | kept in `hotkey` as before |
| Show Passyble, Lock now, Sync now, Generate password and copy, New secure note | none | |

* **The recorder**: click a box and press the keys. A shortcut needs Ctrl, Alt or Win (Shift alone would take
  capitals from every app), and two actions can't share one (checked in the window and again in Rust,
  whatever the spelling). While the box has the focus Passyble lets go of its own shortcuts
  (`shortcuts_recording`; back when the focus goes, or after 60 s), so pressing one reaches the box. When
  Windows refuses a shortcut (another app registered it first), the old one stays and the row says why; at
  start-up such an action has no shortcut and its row shows the error, the others still work.
* **Quick Access**: a small, always-on-top window high on the monitor under the cursor. Locked (also
  soft-locked), it asks to unlock first, like auto-type (Windows Hello when it is on). It searches every
  unlocked vault by title, username and website (`search`; the most used items while the box is empty).
  Up, Down and Enter copy the password; Ctrl+C the username; Ctrl+Shift+C the one-time code; Ctrl+O (or
  Shift+Enter) opens the item in the main window; Enter on a note, card or identity opens it; Esc closes, and
  so does clicking elsewhere. Copies go through `copy_field` (the value never passes through the window, and
  fill-only members can't copy passwords) and clear after 45 s.
* **Scan QR code on screen** (`src/screen_qr.rs`): every monitor is copied into memory with GDI (`BitBlt`,
  `GetDIBits`), its QR codes are read (`pass_core::qr_decode_rgba`) and the pixels are wiped and dropped
  right away: never written to disk, logged or sent. Passyble's windows are excluded from captures, so the
  QR code must show in another window (and an open Passyble window never hides it). Only
  `otpauth://totp` links count, read as strictly as a link opened from outside
  (`pass_core::otpauth_parse_link`); a Google Authenticator export (`otpauth-migration://`) opens the
  import preview in the main window; other QR codes are ignored. With a code found, the vault unlocks if
  needed and **Add two-factor code for <issuer> (<account>)** opens: the best matching login preselected
  (`pass_core::otpauth_matches`: website, title, then username; never one that already has a code), any
  other login by search, or **Create new login** (in the home vault). Logins in vaults the user may not edit
  are never offered, and adding to one is refused. Several codes: pick one first, the rest wait. None: "No QR
  code found on screen. Make sure the QR code is visible and not covered." with **Scan again**. The links
  stay in Rust; the window gets issuer, account and settings only, and the session goes when the window
  closes, the vault locks, or after 10 minutes. The item editor's two-factor field has the same scan
  (**Scan QR code on screen**, `qr_scan_screen`), which fills the field.
* **Sync now** is the [Sync button](#sync-now-everywhere)'s sync.
* **Generate password and copy** is the tray's Generate password; **New secure note** opens the editor in
  the main window (after an unlock); **Lock now** is the tray's Lock.

Window commands: `shortcuts_state`, `set_shortcut`, `shortcuts_recording` (Settings),
`quick_access_open` (Quick Access), `qrscan_state`, `qrscan_review`, `qrscan_commit`, `qrscan_again`,
`qrscan_import` (the QR scan window), `qr_scan_screen` (the editor). In read-only mode
(`read_only.rs`) adding a scanned code and importing it are refused.

## Sync now everywhere

The vault screen's toolbar always has a **Sync** button (`ui/views/sync-model.js`): "Sync now" as its tooltip, it
turns while syncing, then says "Synced just now" (later "Synced 5 min ago") or, after a failure, the reason, and a toast
says what the sync did. Double clicks are one sync. With no vault that has sync set up it offers **Set up sync**
(Settings → Sync). The tray menu has **Sync now**, and so has Settings → Keyboard shortcuts (no default); with no
vault that has sync they open Settings → Sync. The browser extension's Sync button in app mode asks the agent
(`sync.now`, docs/PROTOCOL.md "Sync now in app mode").

All of them run `background::sync_all` (window command `sync_all`, `Ui::sync_now`): the home vault's Google Drive,
WebDAV or Passyble Server account through the same path as Settings → Sync → Sync now, and every shared vault of
Teams and Family; vaults without sync are skipped. The answer is `{ synced, failed: [{ vault, reason }], no_sync }`
(the window command adds the home vault's `changes`). It needs the vault unlocked (the tray and the shortcut ask
to unlock first) and is refused in read-only mode.

## Auto-type hotkey

Press `Ctrl+Alt+P` in any app's sign-in window. Passyble:

1. reads the foreground window's title and process (`GetForegroundWindow`, `GetWindowTextW`,
   `QueryFullProcessImageNameW`) and asks the agent for matches (`Agent::match_window`). A login
   matches when one of its "websites" is `windows:<exe>` (for example `windows:putty.exe`; best), when
   its title appears in the window title, or when its site name does (`github` in "Sign in to GitHub").
2. With **exactly one match** by `windows:<exe>` or by title, it waits for you to release the hotkey's
   modifiers, then types `username ⇥ password ↵` with `SendInput` `KEYEVENTF_UNICODE` packets. This works
   with any keyboard layout and any character. If the login has a 2FA secret, the TOTP popup appears
   next, because the code prompt usually follows.
3. With **none or several matches**, or one that matched only by a site name (a chat channel called
   "#github-alerts" is not GitHub's sign-in), it opens the quick-pick with the matches first: a search
   over the vault, where Enter types the selected login into the original window.
4. The quick-pick's last row is **Generate new password** (with no match it is the only row and
   selected, so Enter picks it; after a search that found nothing it is not preselected). For a sign-up
   or change-password field in a native app: `quickpick_generate` → `autotype::type_generated`
   generates a password with the agent's `generate` defaults (20 characters, all classes, no
   look-alikes), **saves a new login first** (title = the window title, or the program name; website
   `windows:<exe>` so the next hotkey press in that app finds it, except in browsers; no username; note
   "Created by the Passyble password generator."), copies the password (cleared after 45 s) and types it
   into the focused field, without Tab or Enter. For the confirmation field, press the hotkey again:
   the new login matches the app and is typed (`password ↵`, as it has no username). "Require Windows
   Hello before each fill" applies, and so do the window checks below; the login and the clipboard copy
   stay even when typing is refused. The toast ("Saved to Passyble as …") shows in the main window.
   The password never passes through the webview.

Before typing, Passyble checks that the target window still belongs to the same program and still shows the
same title (after an unlock or the quick-pick, a browser may have moved to another tab), brings it back
to the foreground and checks that it is really there. If not, nothing is typed. While typing, every
key is only sent while the target is still the foreground window; if something else takes the focus,
typing stops. If the vault is locked (also soft-locked), the hotkey first asks to unlock (Windows Hello in
the prompt window, or the master password).

## TOTP popup

This is the fallback for 2FA prompts that can't be filled (native apps, custom widgets, or when the
extension asks for it with `totp.popup`). A small frameless, always-on-top card appears at the
bottom-right of the work area. It shows without taking focus (`SW_SHOWNOACTIVATE`) and holds the item
title, the live code with a countdown ring, **Copy** and **Type it**. **Type it** types the code into the
window that had focus when the popup appeared. The popup hides after 3 minutes, on Esc or with ×.

**2FA codes are hidden by default**, here and in the item pane: they show as `••• •••` while the
countdown keeps running. The eye button reveals the code (and hides it again); hovering over the code, or
pressing and holding it, shows it for as long as the pointer stays. **Copy** and **Type it** never need it
revealed. The digits are only in the page while shown, and the reveal resets with every new popup and
when another item is opened (`maskedCode` in `ui/lib.js`).

## Windows Hello unlock

Right after a master-password unlock (or creating a vault, or signing in) of a vault without Windows Hello,
the item list shows a card **Unlock with Windows Hello next time?** (not while the vault's [Get started
checklist](#get-started-checklist) is on: that has its own Windows Hello step): **Turn on** sets it up with one Windows
Hello prompt (`enable_hello`), **Not now** hides the card for that vault for good. Settings → **Unlock** has the same switch, per vault (it needs Hello set up in Windows: face, fingerprint or PIN). Once set
up, Windows Hello is the default everywhere Passyble needs to be unlocked:

* **Main window**: the unlock screen shows "Unlock with Windows Hello" with "Use master password instead"
  below it, and starts the Hello prompt by itself for the active vault only when you just opened the window:
  the tray icon or its **Open**, the Start menu or a second launch, the window of a start without
  `--background` (also right after a restart or an update you chose), **Open in Passyble** from the browser.
  `popups::open_main` gives the window a one-time grant for that (`startup::AutoHello`, good for 90 s, so a
  Hello that reports itself ready only after Windows sign-in still starts), which the unlock screen takes with
  `take_auto_hello` (only while the window is on screen: shown and not minimized). Nothing else starts it: not
  the hidden window of a start with Windows (`--background`; its webview reports itself visible all the same,
  so the page never decides by itself), not Windows sign-in or resume from sleep, not a lock of any kind
  (auto-lock, Win+L, sleep, Lock completely, Switch vault: a lock or unlock drops the grant, and so does hiding
  the window), and not `hello-available` (Windows Hello turning available a few seconds after sign-in), which
  only offers it. `unlock_hello` itself refuses to show Windows Hello for a main window that isn't on screen.
  After a soft lock the list stays and Hello starts only when you ask for a secret. While
  Hello is up the master password field shows too ("Confirm with Windows Hello, or type your master
  password."): typing into it, Unlock or "Use master password instead" cancels the pending Hello operation
  (`cancel_hello_unlock`, also when no Hello dialog ever showed up) and the password goes in. Cancelling
  switches to the password form; Hello stays one click away.
* **Browser extension's own unlock** (`unlock.hello`: a login picked in the in-page menu while locked, the
  menu opened by the user on a fully locked vault, or the popup opened on a locked vault; the extension starts
  it by itself, see Extension/README.md): no Passyble window opens. Windows' Hello dialog shows over the browser
  window that asked, owned by it (`platform::browser_window`: the foreground window, if its process started
  the native messaging host; Chrome and Edge start it through `cmd.exe`, Firefox directly), and is pushed to
  the foreground as below. Cancel in Hello's dialog answers `cancelled` and the extension offers its own
  master-password form; the extension's "Use master password instead" sends `unlock.cancel`, which cancels
  the pending Hello operation. If no Hello dialog shows up within 10 s the operation is cancelled and the
  extension is told "Windows Hello didn't open. Enter your master password instead." (`not_supported`).
  When the browser window isn't in front any more, Hello shows without an owner.
* **Older extensions (`unlock`), auto-type hotkey and quick-pick, TOTP popup, Windows passkey provider**: an
  unlock request no longer opens the main window first. The small prompt window ("Unlock *vault*") comes
  to the front and Windows' Hello dialog opens over it right away, as a modal window owned by it (no
  taskbar button of its own) and with the keyboard focus (PIN field, face, fingerprint); see "Keeping the
  Hello dialog in front" below. After Hello the request continues
  (a fill from the extension while locked: Hello → filled, no master password). If Hello is cancelled the
  prompt offers **Try again**, **Use master password instead** (opens the main window's unlock form for
  that request) and **Cancel**. When Hello can't unlock (master password due, key gone) the main window's
  password form opens directly. One Hello prompt is shown at a time; concurrent requests wait for it.
* The Windows passkey provider doesn't ask for Hello a second time right after Hello unlocked Passyble for
  the same request (a one-shot credit valid for 30 s).

### How the key is bound to Windows Hello

Each vault gets its own Windows Hello key, `Pass-<vault entry id>`, created with
`KeyCredentialManager.RequestCreateForWindowAsync` (`RequestCreateAsync` before Windows 11 24H2; RSA 2048 in the TPM, or Microsoft's software key storage on
PCs without one; Windows only uses it after a Hello gesture). Beside the blob Passyble stores a random
32-byte challenge. Enrollment (after a master-password unlock, or when the setting is turned on while
unlocked) creates the key if needed, signs the challenge once with `RequestSignForWindowAsync` and verifies the
signature as RSASSA-PKCS1-v1_5 / SHA-256 against the key's public key
(`RetrievePublicKey(Pkcs1RsaPublicKey)`, checked with `ring`, no prompt). PKCS#1 v1.5 is deterministic, so a
valid signature is one the key will reproduce on every unlock. Fallback: if the public key can't be read
or the signature doesn't verify, Passyble signs a second time and compares, as older builds did. Then:

```
wrap key = HKDF-SHA256(ikm = signature, salt = challenge, info = "com.sensyble.pass/hello/v2/wrap-key/" || vault id)
sealed   = nonce(24) || XChaCha20-Poly1305(wrap key, vault key, aad = "…/vault-key/" || vault id)
blob     = DPAPI(sealed)    (CryptProtectData, current user, app entropy; the old layer, kept as the outer one)
```

written to `%LOCALAPPDATA%\Pass\hello\<vault entry id>.bin` (`version: 2`, `mode: "key_credential"`,
`challenge`, `blob`, `password_unlock_ms`). Unlock = Hello prompt via `RequestSignForWindowAsync(challenge)` →
DPAPI decrypt → derive → open → `Agent::unlock_with_key`. Enrollment shows one Hello prompt for the
signature, plus Windows' own prompt when the vault's Hello key is created (once per vault and PC; three
only on the fallback path); unlocking shows one.

### Keeping the Hello dialog in front

Every Windows Hello prompt (unlock from the prompt window or the main window, per-fill checks, key
creation, the passkey provider's fallback) runs through `run_prompt` in `src/platform/win32.rs`, with
the timing and the window finder in `src/hello/focus.rs` (unit-tested with a fake window list):

1. **Owner window.** The dialog is requested *for* the window the user looks at (the prompt
   window, the main window for its own unlock, or the browser window for the extension's `unlock.hello`
   and per-fill checks the browser asked for): `KeyCredential.RequestSignForWindowAsync` /
   `KeyCredentialManager.RequestCreateForWindowAsync` (UniversalApiContract 19, Windows 11 24H2; SDK
   10.0.26100 `windows.security.credentials.idl`, declared in `Windows/platform/src/hello.rs` because the `windows` crate
   0.62 predates them; the HWND becomes a `Windows.UI.WindowId` with `GetWindowIdFromWindow` from
   Windows.UI.dll) and `IUserConsentVerifierInterop::RequestVerificationForWindowAsync` for the plain
   presence prompt. Windows then makes "Credential Dialog Xaml Host" (in `CredentialUIBroker.exe`) an
   owned, modal, topmost window of that Passyble window: centered on it, no taskbar button of its own, the
   Passyble window disabled while it is up. There is no `IKeyCredentialManagerInterop`; the window-aware
   methods are the WinRT ones above. On older Windows (no contract 19) Passyble falls back to
   `RequestSignAsync` / `RequestCreateAsync`, whose dialog is a separate window.
2. **Foreground first.** Passyble moves the owner to the foreground before the request
   (`force_foreground`): `SetForegroundWindow`; then with its thread input attached to the foreground
   window's thread (`AttachThreadInput`, `BringWindowToTop`, `SetFocus`); then after an empty
   `SendInput` mouse event; and only as a last resort an ALT tap. The native host's
   `AllowSetForegroundWindow` makes the first step work for browser requests; the others cover the
   hotkey, the TOTP popup and the passkey provider (a COM server can't grant itself
   `CoAllowSetForegroundWindow`; that is the caller's call). Windows' own window passed by the passkey
   provider, like the browser window of an extension request, is used as the owner but never moved.
3. **Dialog to the foreground.** While the operation runs, a thread of its own (`follow_dialog`) polls
   the top-level windows every 50 ms for the dialog (class + `CredentialUIBroker.exe`, owned by our
   window, or new since the request) and calls `force_foreground` on it (at most every 150 ms; the ALT
   tap once, after 1 s) until it is the foreground window, then stops. The thread waiting for the
   operation does nothing else, so it goes on the moment Windows completes it, never after one of
   `force_foreground`'s 20 ms sleeps.
4. **Fallback after 2 s.** If no dialog appeared, or it didn't get the foreground within 2 s
   (`HelloFocus::NotShown` / `Unfocused`, logged), the prompt window switches to "Windows Hello didn't
   open" (shown in front, with **Use Windows Hello**, **Use master password instead**, **Cancel**) or
   "Windows Hello is waiting in the Windows Security window. Click it". Those buttons and Esc (also on
   the per-fill "Confirm it's you" prompt) call `IAsyncOperation::Cancel` on the pending operation
   (`hello::focus::cancel`) and the request goes on without it. Requests shown over the browser window
   have no prompt window: there the dialog gets 10 s to show up before the operation is cancelled (the
   extension then asks for the master password; a per-fill check counts as declined), and
   `unlock.cancel` cancels it on the user's request.

Measured on Windows 11 build 26300 with a window of another process in front and Passyble without the
right to take the foreground: the owner came to the front with `AttachThreadInput`, the dialog appeared
after ~0.15 s, was owned by the Passyble window (no `WS_EX_APPWINDOW`, owner disabled) and was the
foreground window after ~0.3-0.55 s, for both `RequestVerificationForWindowAsync` and
`RequestCreateForWindowAsync` (`RequestSignForWindowAsync` uses the same mechanism; it needs an existing
key, so it was checked for presence only). Without an owner (`RequestSignAsync`) the dialog stayed
behind the other app and had its own taskbar button. **Cancel caveat:** on that build
`IAsyncOperation::Cancel` completes the operation for Passyble at once, but Windows leaves its dialog on
screen until the user closes it (Passyble can't close it: it belongs to a protected process). Passyble ignores
whatever happens in it then. That's why Passyble only cancels on the user's request (or when no dialog showed up),
never on its own timeout. The manual test `hello_dialog_comes_to_front` (ignored by default,
`win32.rs`) repeats the measurement; see docs/TESTING.md.

### Timing the fill path (`PASSYBLE_TIMING_LOG`)

To see where the time goes between picking a login and the filled page (with or without Windows Hello),
set the user environment variable `PASSYBLE_TIMING_LOG` to a file path, for example
`setx PASSYBLE_TIMING_LOG "%TEMP%\passyble-timing.log"`, then quit and start Passyble and the browser
again (the native host inherits the browser's environment). `Pass.exe` (`app`) and
`pass-native-host.exe` (`host`) then append one line per step to that file; debug builds also print them
to stderr. Without the variable nothing is formatted or written. The code is `pass_agent::timing`
(`Core/agent/src/timing.rs`). A line:

```text
2026-10-24T09:12:03.418Z app #7 hello: dialog answered +912.4ms (+880.1ms)
```

UTC time, process, trace number (one per request), step, time since the request reached that process,
time since the previous step of the same request. Steps are fixed names: no secret, username, URL or
item name is ever written. A request that fails ends with its error code, never its message:
`passkey.find: answered with an error (locked)` (`app`), `host: passkey.find: error sent to the browser
(locked)` (`host`), and `host: passkey.get: error sent to the browser (agent_unavailable)` for a request the
host answered itself because the desktop app wasn't running. Only a plain code (lower-case letters and `_`) is
written, anything else as `(other)`. Traced requests: `status`, `unlock`, `unlock.options`, `unlock.password`,
`unlock.hello`, `unlock.cancel`, `logins.fill`, `logins.fill_cross`, `logins.copy`, `totp.get`,
`totp.popup`, `cards.fill`, `passkey.find`, `passkey.create_options`, `passkey.create` and `passkey.get`. A login
picked while the vault is locked (Windows Hello) writes, in order:

| Process | Steps |
| --- | --- |
| host | per request `host: <method>: request from the browser`, `host: sent to the agent`, later `host: <method>: answer sent to the browser`; `host: lock_state: event sent to the browser` for the unlock |
| app | `status: request received`, `status: answered`, `unlock.options: request received`, `unlock.options: answered` (the in-page menu's check; both sent at once) |
| app | `unlock.hello: request received`, `hello: request received`, `hello: availability checked`, `hello: prompt slot taken`, `hello: owner window found`, `hello: vault file checked`, `hello: key opened`, `hello: dialog requested`, `hello: dialog shown`, `hello: dialog focused`, `hello: dialog answered`, `hello: key derived`, `unlock: vault file read`, `unlock: vault opened`, `unlock: conflict copies checked`, `unlock: saved`, `unlock done` (the windows and the extension have been told), `unlock: kept list written`, `unlock.hello: answered` |
| app | `logins.fill: request received`, `fill: verified`, `logins.fill: answered` |

With "Confirm each fill" and the vault unlocked the fill is one request: `logins.fill: request received`,
`verify: hello needed`, `hello: owner window found`, `hello: dialog requested`, `hello: dialog shown`,
`hello: dialog focused`, `hello: dialog answered`, `verify: done`, `fill: verified`,
`logins.fill: answered`. A passkey sign-in from the extension's card writes `passkey.get: request received`,
`passkey: matched`, `passkey: picked in the browser` (an older extension: `passkey: chooser window answered`,
the desktop app's window), then the verification (`verify: no per-fill policy`, `verify: no Windows Hello needed
(grace period or unlock)`, or `verify: hello needed`, the `hello: …` steps of the dialog over the browser and
`verify: done`; `userVerification: "required"`: `verify: required, …`), `passkey: verified`, `passkey: signed`,
`passkey.get: answered`. A save: `passkey.create: request received`, `passkey: request checked`,
`passkey: consent given in the browser` (or `passkey: consent window answered`), the verification,
`passkey: verified`, `passkey: created`, `passkey: saved`, `passkey.create: answered`. A request that fails ends
with `<method>: answered with an error`. The lag
before the dialog is the time up to `hello: dialog requested` plus Windows' own time to
`hello: dialog shown`; the lag after it is the time from `hello: dialog answered` to
`logins.fill: answered` (then the host's answer line). From `hello: dialog focused` to
`hello: dialog answered` is the user (and, for the unlock, the TPM signing the challenge).

**Fallback.** If `KeyCredentialManager.IsSupportedAsync` is false or the signatures aren't deterministic, the
vault key is stored with DPAPI only (as before) and Settings → Unlock says so under Windows Hello; the Hello prompt is then
only a presence check. **Migration.** Blobs from older builds (`version` 1, DPAPI only) are migrated at
the next master-password unlock or at the next Hello unlock (where the Hello key's signature replaces
the presence prompt); if that's cancelled the old blob keeps working and is migrated next time.

### Policy (Settings → Unlock)

* **Ask for the master password**: never / every day / 7 / 14 / 30 days (default) / after each start of
  Passyble. Vaults that still had the old 14-day default move to 30 days once (`defaults_version` 1; the
  per-vault policy shipped only shortly before, and every save wrote the default, so a stored 14 days
  can't be told apart from a choice); an interval chosen afterwards is kept. Passyble records the last master-password unlock in the blob; once the interval has passed, Hello
  doesn't unlock until the master password is used once (the unlock screen says why). A clock turned
  back by more than a day also counts as due.
* **After confirming** (the grace period of Confirm each fill: every time, 1 or 5 minutes): sliding. Each
  credential use while it runs (a fill, copy, 2FA code, passkey sign-in or auto-type that went through;
  `Ui::credential_used` → `FillGate::used`) starts it again from that use, so it ends that long after the last
  fill, never later; once it has run out the next fill asks again, and locking forgets it.
* **Confirm each fill** (More security options; off by default): even while unlocked, each extension fill
  (`logins.fill`), 2FA code for a login that wasn't just filled (`totp.get` / `totp.popup`), extension
  passkey use (`passkey.create` / `passkey.get`) and auto-type asks for Hello first (for the extension,
  Windows' Hello dialog over the browser window; for auto-type, the prompt window "Confirm it's you", where
  Hello starts at once with "Use master password instead" below the reason: when Hello doesn't confirm it, or
  on that link, the prompt asks for the master password, typed into Passyble's own window and checked
  against the open vault (`Vault::check_password`, changes nothing, the text is dropped right after), with
  "Use Windows Hello" to try Hello again; 5 wrong passwords refuse the request). **After confirming**: every time, or not again for 1 or 5 minutes. The unlock that a
  request triggered counts for that request. The 2FA code of the login just filled continues that fill
  and doesn't ask again. The Windows passkey provider always verifies with Windows Hello anyway.
  **Every time** is strict about logins: every login fill asks, a second fill of the same login too. The
  only exceptions: the login picked while locked (the extension names it, `for`; the unlock is that one
  fill's check, so one prompt, not two; an unlock in the main window or for nothing in particular counts
  for no login fill), and the 2FA codes of the login whose fill was just confirmed, for 2 minutes
  (`hello::policy::OTP_AFTER_FILL`, as often as needed; another login's code, and the code after that, ask).
  Copying a password or code to the clipboard keeps its rule (asks, and an unlock moments ago counts for it
  once). See `FillGate::without_prompt_for` and docs/PROTOCOL.md, "Every time and 2FA codes".
* Auto-lock (and Win+L / sleep) still drops the vault key from memory; Hello unlocks it again.

### Threat model

* The blob never roams (LOCALAPPDATA) or syncs with the vault. DPAPI ties it to your Windows account on
  this PC; the Hello key never leaves the TPM / NGC key store.
* **Cryptographically bound**: a program running as you can strip the DPAPI layer, but not open the
  sealed key without the Hello key's signature, and Windows produces that only after a Hello gesture.
  (Before this, any program running as you could decrypt the vault key with no prompt at all.) Such a
  program can still ask Windows for a signature itself, which shows an unexpected Hello prompt, and
  anything that can read Passyble's memory gets the key while the vault is unlocked.
* Someone who knows your Windows PIN passes Windows Hello.
* Resetting Windows Hello (new PIN or reset of the key container) deletes or replaces the key: Passyble
  discards the blob, asks for the master password once and sets Hello up again.
* The interval and per-fill policy are enforced by Passyble, not by cryptography (a program running as you
  could edit the timestamp).
* Turning the setting off or removing the vault deletes the blob and the Hello key. Changing the master
  password doesn't change the vault key, so the blob stays valid. See `src/hello.rs` and
  `src/hello/keywrap.rs`.

## Passyble password (one password for the account and its linked vaults)

A Passyble account can have one Passyble password that signs in to the account and opens every vault
linked to it (`src/account_keys.rs` with `api.rs`, `device.rs`, `approval.rs`; `ui/views/account-keys.js`;
the cryptography is in docs/ARCHITECTURE.md §18). Nothing changes for a vault
without an account. Every cryptographic step is Core's; the account service never receives the password,
the Secret Key, the account key (AK) or a vault key.

* **On this PC**: the Secret Key in Credential Manager (`Pass/PassybleSecretKey/<account id>`, no
  gesture: it is useless without the password), AK under Windows Hello (key `Pass-account-<account id>`,
  blob `%LOCALAPPDATA%\Pass\hello\account-<account id>.bin`, the scheme of [Windows Hello
  unlock](#windows-hello-unlock), bound to `ak:<account>:<ak_id>`), or with DPAPI only when Settings
  says "Remember on this PC" (off by default; without usable Hello keys AK is otherwise not kept), and
  an offline cache of the password's salt, parameters and wraps and the recovery wrap
  (`%LOCALAPPDATA%\Pass\accounts\<account id>.json`; nothing in it opens without the password and the
  Secret Key, or the recovery code).
* **Set up** (Settings → Sync, under the account row, and offered right after a sign-in of an account
  without one): the master password rule and the breach check through `GET /v1/pwned/<prefix>` (fail
  open), then this PC makes AK, the Secret Key and the recovery code and uploads `POST /v1/account-key`
  signed with the new `ak_sign`. The **Emergency Kit** shows once: e-mail, sign-in address, Secret Key,
  the setup QR, a blank for the password and the recovery code; printed or saved as a PDF by the
  webview's print, confirmed by typing the code's last group. A sign-in older than 10 minutes
  (`reauth_required`) opens the browser sign-in first and the step runs again.
* **Unlock** of a linked vault (file version 3; `vault_access` reads the file, the list keeps
  `linked_account`): Windows Hello opens the kept AK; else the Passyble password opens the cached wrap
  offline, or the service's after a sign-in signature (`/v1/account-key/unlock`, or a password sign-in
  `/v1/session/password` when this PC isn't signed in, which also signs it in). The Secret Key is asked
  once when this PC has none, the address when it knows none. AK stays in memory while a vault is
  unlocked (switching to another linked vault of the account needs no prompt); every lock drops it. A
  linked file opened from onboarding joins the list and shows this form.
* **Link**: the vault view offers it once for an open personal vault ("Not now" is kept); its master
  password is typed once, then `link_to_account`, the account's recovery copy goes into the header and
  its own Windows Hello blob goes. A new vault can be linked from the start. "Use a separate password"
  (`unlink_from_account` with a new vault key, the organisation's minimum strength, then a vault recovery
  code offer) is refused for the vault holding the sharing keys, unless its Team requires a second
  password ("Set a second password", below); in a Team that uses one password it is refused for every vault.
* **Settings**: change the password (the old one signs, other devices signed out by default), show the
  kit again (Windows Hello or the password; without the recovery code), a new Secret Key (a new kit), a
  new recovery code (the headers of the linked vaults on this PC updated; others at their next open),
  "Forgot" (this PC's kept AK with Windows Hello plus a fresh sign-in, or the recovery code plus a fresh
  sign-in), how AK is kept here, the key's fingerprint.
* **Changing a vault's password** (`src/password_change.rs`, `ui/views/password-change.js`; audit H4, design D5):
  every change (Settings, Change password; a recovery code or admin recovery; a Passyble Server sign-in that
  re-encrypts) gives the vault a new key and re-encrypts it, so old copies never open what is saved from then on.
  On Passyble Server the old versions are dropped once the new file is uploaded (`server_purge_versions`, owner
  only; an older server keeps them until they expire); for Google Drive and WebDAV the window says their old
  copies still open with the old password. The dropped recovery code is replaced at once (no password asked
  again), emergency grants are renewed, admin recovery of the vault is joined again only on the member's yes,
  and Windows Hello is set up for the new key. Another device on the old key gets "password changed on another
  device" on sync; unlocking there with the new password takes the synced copy and merges its own in
  (`signin::refresh_from_server`, `password_change::refresh_from_sync`).
* **Adding a device** (design D4): "Add a device" shows an invitation QR for a phone and lists the requests of
  other devices with their name; a request from a PC is accepted, the new PC shows six digits and the user types
  them here (`account_device_approve` `code`; this PC never shows them, so a tap approves nothing; "Didn't start
  this? Deny it"), then sealed, and this PC shows its account key fingerprint. A new PC asks from the account row
  or the unlock form ("Approve from another device", no session needed), shows its QR and then the six digits;
  when sealed it gets a session, AK and the Secret Key, kept only after the user checked their fingerprint with
  the other device's Settings (`state: "check"`, then `account_device_request_confirm`; "doesn't match" drops
  them). Admin recovery of the account key checks the fingerprint the same way (`account_admin_recovery_finish`
  `fingerprint`, `matches`).
* **E-mail reset** (`account_keys/reset.rs`, `ui/views/account-reset.js`; design 5.6): "Forgot" lists
  this PC, the recovery code and an admin first, then "Start fresh": a fresh sign-in starts the 72-hour
  wait (`POST /v1/account-key/reset`), a waiting screen shows the release time, and when it is over
  this PC makes a whole new key set as a setup does (`/reset/complete`, signed with the new `ak_sign`)
  and shows the new Emergency Kit. The old set stays on this PC (`old_keys` in the cache, its Secret
  Key as `Pass/PassybleSecretKey/<account id>/<old ak_id>`, its Windows Hello blob moved to
  `account-<account id>.old-<old ak_id>.bin`, never overwritten). Settings shows a waiting reset with
  "Cancel the reset" (this PC's key signs it, or the recovery code).
* **Locked vaults**: a linked vault whose key id is an old one shows "Locked, from before your reset"
  (`account_key_locked`); Unlock opens the old key with this PC's kept old key (Windows Hello), the old
  password and old Secret Key (this PC's cached wrap offline, else `.../locked/<id>/open` after a
  signature by the old sign-in key), or the old recovery code (the vault header's copy offline, else
  the service's wrap), then every vault of that set on this PC is relinked under the current key
  (`link_to_account`, with the current recovery copy). A set no vault here needs can be deleted
  (signed with the current key). Settings → Locked key sets lists them all.
* **Key watch** (design 7.3 c): after each unlock (at most once a minute) `GET /v1/account-key` is
  compared with this PC's cache. A reset another device started shows a warning with "Cancel the
  reset"; a changed key id without a step here shows "Your account key changed on <date>" (the date
  of the locked set) and keeps the old key set and the vaults as they are. The tray and the windows
  show the push texts (`account_keys.push_account_key_reset_*`); the desktop has no push channel of
  its own, so the next status check stands in for it.
* **Admin recovery of the account key** (`account_keys/admin.rs`; design 5.7): Teams and Families →
  Admin-assisted recovery enrols AK (`ak:<ak_id>`) after the plain warning, offers "Turn on again"
  after the key changed (and re-enrols by itself after a reset made here), and keeps a Team's required
  enrolment (`required` in the overview: asked after an unlock and after joining). "Ask your Team or
  Family admin" sends a request naming the current or a locked key; the approval opens AK here, then
  a new password, a new Secret Key and a new Emergency Kit (current key) or the old vaults relinked
  (locked key). Family admins approve account key requests like Team admins.
* **Emergency access for the account** (`teams_send.rs`; design 5.8): setting up a trusted contact
  grants every vault linked to the account on this PC (each opened with the account key) and, when
  the owner ticks it, the open vault with a separate password: one core grant per vault, sent with
  `vault_id` and its Passyble Cloud name (`cloud_vault`: `personal`, a `v-` name or none). The grants
  made here are kept in the account cache; each vault's next open renews a missing or stale grant
  (`emergency_grant_current`; the contact's fingerprint must still be the confirmed one) and drops the
  grants of vaults this PC granted that are gone (no list entry, no file). The service wants a fresh
  sign-in for a grant, so a refused renewal shows "Update now" on Emergency access. The contact opens
  every released vault on Passyble Cloud (`.../vault?vault_id=`), a handed-over copy of one kept
  elsewhere ("Open a copy"), and with full access may keep one as a vault of their own, relinked to
  their Passyble password ("Keep as my vault").
* Not in this version: passkey PRF unlock, a new device scanning an invitation, making an
  organisation's recovery key on the desktop (only iOS makes one), restoring a linked vault from
  WebDAV or Google Drive in onboarding, the "update Passyble on your other devices first" check before
  linking, and a per-account password interval (the Windows Hello default, 30 days, applies).

## Recovery code

An optional code for a forgotten master password when no device has the vault unlocked
(`ui/views/recovery.js`, `src/recovery.rs`; format and security in docs/ARCHITECTURE.md §1, "Recovery
code"). It looks like `7K3QD-…` (six groups of five letters and digits, a checksum catches typos) and
unlocks the vault on any device that has a copy of the vault file. Passyble shows it once and never keeps
it; the vault file keeps the vault key wrapped by a key derived from it.

* **Settings → This vault → Recovery code**: "None: a forgotten master password can't be recovered"
  (warning) with **Create…**, or "Made <date>" with **Replace…** and **Remove…**. Create / Replace explain
  what the code is, ask for the master password (`recovery_code_create`), then show the code with **Copy**
  (`copy_secret`, cleared after 45 s), **Save as a text file…** (`recovery_code_save`, through the save
  dialog), **Print…** (the window's print dialog with a sheet that shows only the code and how to use it)
  and **Done** only after "I printed or saved my recovery code" (Esc doesn't close that step). Remove asks
  for the master password (`recovery_code_remove`). Each saves and syncs at once (a failed upload is a
  warning). Whether there is a code, and since when, comes with `get_settings` (`recovery_code`).
* **After "Create vault"** (onboarding and the vault list's Create new vault): **Create a recovery
  code?** over the new vault, **Skip** closes it. No password asked again: `setup_create` allows one
  `recovery_code_create` without it for 10 minutes.
* **Unlock screen → Forgot password? Use your recovery code** (under the password form, also in the
  unlock dialog over a soft-locked list): the code (dashes, spaces and case don't matter;
  `recovery_unlock`). A typo, a code of another vault or a replaced one, and a vault without a code each
  get their own message. The local file is tried first; for a WebDAV / Passyble Server vault whose local
  copy doesn't know the code yet (made on another device since the last sync), the server's copy is
  downloaded, opened with the code, merged with the local one and saved. The agent is unlocked with the
  vault key (as with Windows Hello), the window moves on to the vault, and the dialog stays over it until a
  new master password is chosen (with the usual strength hint; `recovery_set_password`, allowed without
  the old password for 30 minutes after the recovery) or the vault is locked again (**Lock vault**). After
  the new password: Windows Hello is set up or kept as after a password unlock (the vault key is the same,
  so an existing Hello setup keeps working), the vault is saved and synced, and **Make a new recovery
  code?** offers to replace the code that was just used (no password asked again).
* **Passyble Server vaults** use the server account's password as the master password (see "Sign in to
  Passyble Server"), so whoever forgot one forgot both. The code unlocks the vault, but a vault-only
  password would be undone by the next sign-in on another device (it re-wraps the vault with the account
  password), so `recovery_set_password` refuses and the dialog explains that the server account needs its
  own reset: **E-mail me a reset link** (`recovery_server_reset`, the server's "Forgot password?") or paste
  a reset link from the admin. Opened on this PC while the vault stays unlocked, the link sets the new
  password on the server and re-encrypts the unlocked vault with it (the existing reset flow, "Invite and
  reset links"); afterwards the dialog offers a new recovery code.
* **Replacing the vault key** (a Passyble Server password the admin knew) removes the code, which wraps the
  old key: make a new one afterwards. Removing or replacing a code doesn't lock out copies of the vault file
  saved before; see docs/ARCHITECTURE.md §1.

Manual checks (Windows):

1. A new vault: "Create a recovery code?" appears after Create vault; Skip closes it; Create shows the code
   without asking for the password; Copy, Save as a text file… (file content, CRLF) and Print… (only the
   sheet prints) work; Done stays disabled until the box is ticked; Esc does nothing on that step.
2. Settings → This vault → Recovery code shows "Made <today>"; Replace… with a wrong password says so;
   with the right one shows a new code; Remove… asks for the password and the row then shows "None".
3. Lock completely → Forgot password? → a code with one character changed: "has a typo"; another vault's
   code: "doesn't open this vault"; the right code typed in lower case without dashes: the vault opens
   behind the dialog, which asks for a new master password (strength hint, mismatch error); Lock vault locks
   again; after setting it the old password fails and the new one works; Windows Hello (if set up) still
   unlocks; "Make a new recovery code?" → a new code, and the old one no longer opens the vault.
4. A vault without a code: Forgot password? → "This vault has no recovery code…".
5. Two PCs syncing one vault (WebDAV or a shared folder): a code made on PC A opens the vault on PC B
   after a sync, and also before PC B synced (WebDAV: the server's copy is used).
6. A Passyble Server vault: the code unlocks it; the dialog explains the separate server password; E-mail me
   a reset link sends the e-mail (or shows the server's reason); the link opened on this PC while unlocked
   sets the new password and re-encrypts the vault; a new code is offered; another device signs in with the
   new password.
7. Settings → change the master password: the code still works afterwards.

## Windows passkey provider

Off by default. With it on, Windows' own passkey dialogs (Edge, Chrome or Firefox without the
extension, and native apps) can save passkeys to Passyble and sign in with them, through the Windows 11
passkey plugin API. Design and details: `src-tauri/src/passkey_provider.rs` and
`src-tauri/src/passkey_provider/package.rs`.

### Turning it on

1. **Passyble → Settings → Autofill → Windows passkeys**: turn it on, then **Save settings**.
   Passyble registers its Windows package (see below). If the row says "Needs Developer Mode or a
   signed build", click **Open** next to "Turn on Developer Mode", switch on **Developer Mode** in
   Windows Settings → System → For developers, come back and turn the switch on again.
2. Click **Restart** next to "Restart to finish". Passyble restarts once, now with its package
   identity, registers itself with Windows and opens Windows Settings → Accounts → Passkeys →
   Advanced options.
3. In that Windows page, switch **Passyble** on (Windows may ask for Windows Hello). Back in
   Passyble the row shows three green dots: Package registered, Plugin registered, On in Windows.
   If the page didn't open, click **Open** next to "Switch Passyble on in Windows".

Turning the setting off removes Passyble from Windows' list, empties Windows' metadata cache and
unregisters the package (Windows finishes that when Passyble exits). Uninstalling Passyble does the
same.

After the restart Passyble runs with package identity. Windows Hello unlock keeps working: a
Passyble with identity still finds the vaults' existing Hello keys (checked on Windows 11 build
26300 with `--passkey-setup hello-key`). Should a Windows version scope them per package, Passyble
asks for the master password once and sets Windows Hello up again, as after a Windows Hello reset.

Requirements:

* Windows 11 24H2 or 25H2 with the November 2025 update or later (build 26100.6725 / 26200.6725+;
  `webauthn.dll` must export `WebAuthNPluginAddAuthenticator`). Passyble loads the API at run time,
  so it still starts on older Windows; the setting then explains why it's unavailable.
* Passyble installed with its installer (the package files ship in `<install>\package\`), and either
  **Developer Mode** on or a **signed release** (one built with the code-signing certificate, which
  ships a signed `Passyble.msix`).

### How it works

The plugin API only accepts packaged callers, and Windows activates the provider through a
packaged COM server. Passyble is a normal Win32 install, so it uses a *package with external
location* (sparse package):

* **Identity in every build.** `build.rs` embeds an `<msix>` element (package name
  `Sensyble.Passyble`, publisher, application id `Pass`) in `Pass.exe`'s manifest. While that package
  isn't registered, Windows ignores it and `Pass.exe` runs as a plain Win32 app.
* **Package files.** `Windows/installer/packaging/AppxManifest.xml` declares `Pass.exe` and its `windows.comServer`
  extension (CLSID `2ced63f3-59c6-4471-88dd-ee8d8822ad81`, started as `Pass.exe --passkey-provider`).
  `Windows/installer/packaging/build-sparse-package.ps1` (run by `Windows/installer/before-bundle.ps1`, the installer build's
  `beforeBuildCommand`) stages it with the logos into `src-tauri/package`, checks it with MakeAppx
  (`pack /nv`) and, with a signing certificate, packs and signs `Passyble.msix`. Both installers
  ship the folder as `<install>\package\` (`tauri.bundle.conf.json` resources).
* **Registration** (turning the setting on), with `Windows.Management.Deployment.PackageManager`
  for the current user and the install folder as `ExternalLocationUri`: `AddPackageByUriAsync` with
  `Passyble.msix` when it's there, else, with Developer Mode, `RegisterPackageByUriAsync` with the
  loose `AppxManifest.xml` (`DeveloperMode`). Identity is fixed at process start, hence the restart.
  Unsigned packages (`AllowUnsigned`) are no way around Developer Mode: they need an OID in the
  publisher, and Windows refuses to start an exe whose `<msix>` publisher contains one.
* **At start with identity**: Passyble starts the COM server (`CoRegisterClassObject`), calls
  `WebAuthNPluginAddAuthenticator` (name "Passyble", logo, AAGUID `pass_core::AAGUID`) and keeps
  Windows' credential-metadata cache in sync (`WebAuthNPluginAuthenticatorAddCredentials`: rp id /
  name, user, credential id; never keys). Requests must carry a valid signature from Windows'
  operation-signing key, otherwise they're refused. Create shows Passyble's usual "Save a passkey?"
  prompt, sign-in shows the picker only when several passkeys match, and both end with Windows Hello
  (`WebAuthNPluginPerformUserVerification`). When the setting is off, Passyble never calls the
  plugin API.
* **Uninstall**: the NSIS hook (`Windows/installer/installer-hooks.nsh`) and the MSI custom action
  (`Windows/installer/passkey-cleanup.wxs`) run `Pass.exe --passkey-setup remove` (not on updates).

The package identity (`PASSYBLE_PACKAGE_NAME`, `PASSYBLE_PACKAGE_PUBLISHER`,
`PASSYBLE_PASSKEY_CLSID`) is read from the environment by both `build.rs` and the staging script,
defaulting to `Sensyble.Passyble`, `CN=Sensyble` and the CLSID above. A release build sets the
publisher to the code-signing certificate's subject.

### Command line (support and tests)

`Pass.exe --passkey-setup <action>` runs before anything else (no window, no hand-over to a running
Passyble) and prints JSON: `status`, `register-package`, `add-authenticator` (needs identity, so run
it after registering), `remove`, `hello-key <vault-id>` (whether this process sees that vault's
Windows Hello key; never creates one). Pass.exe is a GUI program, so capture the output with
`Start-Process -Wait -RedirectStandardOutput out.json`.

To try a development build next to an installed Passyble, build it with another package name and
CLSID so the two registrations don't collide, stage its package files next to it and register them:

```powershell
$env:PASSYBLE_PACKAGE_NAME = "Sensyble.Passyble.Test"
$env:PASSYBLE_PASSKEY_CLSID = "07666742-c5e2-4cd9-a625-15f74c1351cd"
cargo build -p pass-desktop --release
powershell -ExecutionPolicy Bypass -File Windows/installer/packaging\build-sparse-package.ps1 -Out target\release\package
target\release\Pass.exe --passkey-setup register-package   # Developer Mode
```

Remove it again with `target\release\Pass.exe --passkey-setup remove`.

### Testing it

1. Turn it on as above (installed Passyble, or a dev build started from its folder).
2. In Edge or Chrome **with the Passyble extension disabled**, open <https://webauthn.io>, enter a user
   name, **Register**. In Windows' dialog choose Passyble, approve Passyble's "Save a passkey?" prompt,
   then Windows Hello. The passkey appears on a login for webauthn.io in Passyble.
3. **Authenticate** on webauthn.io: pick the passkey in Windows' dialog, then Windows Hello. Lock
   Passyble first to check the unlock path (Passyble asks you to unlock, then continues).
4. Delete the passkey's login in Passyble: within ~10 s it disappears from Windows' list
   (credential metadata sync). Turning the setting off removes Passyble from Advanced options.

Troubleshooting: Settings → About → Log file → **Open folder** (`pass.log`) for `passkey provider: …`
lines. "refusing request" means a request without a valid Windows signature. `Pass.exe
--passkey-setup status` shows the package registration (`package_registered`, `package_elsewhere`
when it points at another folder) and whether the process has identity (`package_identity`).
## Cards, identities, custom fields and tags

**New** (bottom of the list) opens a menu: **Login**, **Note**, **Card**, **Identity** (Ctrl+N is a new login;
a new item made while the list is filtered by a tag gets that tag). The editor (`ui/views/editor.js`) has the
same kind switch at the top and keeps what was typed for the other kinds.

* **Cards**: cardholder, number (masked with a show toggle; the brand and whether the number passes the
  Luhn check show as you type, `card_info`, which stores nothing), expiry month and year, security code and
  PIN. Saved without a title, a card is called "Visa •••• 1111" (`Vault::upsert`). The list shows the brand,
  the last four digits and the expiry; the avatar is a card icon. The detail view shows the number as
  `•••• •••• •••• 1111` and the security code and PIN as dots: **Show** fetches one from Rust
  (`item_secret`), **Copy** copies it in Rust (`copy_field`, cleared after 45 s), and the expiry gets an
  **Expired** chip when it has passed.
* **Identities**: title, first / middle / last name; e-mail, phone; three address lines, city, region,
  postal code, country; company, birth date, in those groups in the editor and the detail view, each value
  with Copy (the address as one block). Saved without a title, an identity is called by its name. The list
  shows the person's name (or e-mail) and their initials as the avatar.
* **Custom fields** (every kind): name, value and type (**Text**, **Hidden**, **Web address**), with **Add
  field**, move up / down and remove in the editor. The detail view shows text, hides a hidden field's value
  as dots (Show / Copy as for card codes) and opens a web address in the browser (`open_item_url`: only
  `http(s)` addresses read from the vault, never a file or another scheme; the login's websites have the
  same button).
* **Tags** (every kind): chips in the editor with suggestions from the vault's tags (`vault_tags`); Enter,
  comma or Tab adds one, Backspace removes the last; `/` nests them (`Work/Clients`). The **Tags** section
  under the list's Filter button lists every tag with its count, nested ones indented under their parent
  (collapsible, remembered on this PC); a click filters the list by that tag and the tags under it (the
  Filter button shows it as `#work`, its × clears it), as does a tag chip in the item pane. The search also
  takes `tag:work` or `#work`.
* **Filter** (over the list): one button, no chip rows. It reads **Filter** while the list shows everything,
  else what it is narrowed to ("Engineering · 2FA · #work"), with an × that shows everything again. It opens
  one menu: **Vaults** (with several vaults open: All vaults, the home vault, the pinned vaults in pin order
  with a pin at the row's end, then the rest, as in every vault list) and **Show** (All, Favorites, Logins,
  2FA, Passkeys, Cards, Notes, Identities, Most used), the chosen ones checked (radio items for screen
  readers), then **Clear filter** while something is chosen. Arrow keys, Home and End move, ArrowRight
  reaches a vault's pin, Esc or Tab closes it and the focus goes back to the button.

**What reaches the window.** `get_item` (the detail view's copy, marked `partial`) carries no card number,
security code or PIN and no hidden field value, only `has_number` / `has_security_code` / `has_pin` /
`has_value` and the last four digits; a revealed value lives in the page only while shown and goes on any
re-render with a newer version, on another item and on lock. The editor gets the whole item
(`get_item_for_edit`), as it gets the password; `save_item` refuses a `partial` copy (saving it would erase
those values), and the star toggle uses `set_favorites`. Duplicate copies the whole item in the same way.

## Trash

Deleting (the item pane, the list menu, the selection bar) moves items to the Trash (`Vault::delete`) with
the Undo toast; they stay there for 30 days and the core removes them after that
(`pass_core::TRASH_RETENTION_MS`). The trash syncs like any edit. **⋯ → Trash** (or Settings → This vault →
Trash) lists them without secrets, most recently deleted first, with when each is removed for good
(`trash_list`); **Restore** takes one out (`trash_restore`), **Delete for good** (`trash_delete`) and **Empty
trash** (`trash_empty`) ask first ("This can't be undone"). The trash needs the vault unlocked.

## Export

Settings → Import and export → **Export…** (or ⋯ → Export…) opens a dialog (`ui/views/export.js`,
`src/export.rs`) that warns that an export holds every password, then offers:

* **Encrypted** (recommended): Passyble JSON encrypted with a password chosen for the export (typed twice,
  at least 8 characters; Argon2id + XChaCha20-Poly1305, `pass_core::export_encrypted_json`).
* **Passyble JSON**: everything (cards, identities, custom fields, tags, passkeys with their private keys,
  password history), unencrypted.
* **CSV**: Bitwarden's columns, unencrypted. The dialog says what CSV can't hold: passkeys, password
  history, more than one tag per item, which fields are hidden; cards and identities become notes.

Unencrypted formats need the master password typed again (`Vault::check_password`, which changes nothing)
and "I understand the file isn't encrypted". Rust then shows the save dialog (`passyble-export-<date>.json` /
`.csv`) and writes the file itself, so the export never passes through the webview; items in the trash are
left out. Locking closes the dialog.

**Importing a password-protected export**: Import → Choose file (or a dropped file) recognises it
(`pass_core::import_encryption`: Passyble's encrypted export, Bitwarden "Password protected" JSON, encrypted Aegis
and 2FAS backups, PGP-encrypted Proton Pass exports, KeePass `.kdbx` databases, encrypted ZIP files) and asks for
its password; for a KeePass database **Choose key file…** (`import_key_file`, a Rust file dialog; the key file's
bytes stay in Rust) adds a key file. `import_with_password` opens it with `pass_core::import_parse_with_key_file`
and shows the usual preview. A wrong password can be tried again; neither the password nor the decrypted file is
kept.

## Password health

**⋯ → Password health** (or Settings → This vault → Password health; `ui/views/health.js`, `src/health.rs`)
shows how many passwords were checked, how many look fine and how many to fix, then one section per check
that found something (a title with the count, a plain explanation, the items, an action), password problems
first, and at the end the checks that found nothing ("All good"). Order and counts come from
`ui/views/health-model.js` (unit-tested in `ui/test/health-model.test.mjs`).

- **Found in data breaches** (after a breach check, below), **Weak** (score 0-1, with the strength in words),
  **Reused** (grouped by the shared password), **Unsecured websites** (a saved `http://` address to a public
  site; local and private addresses are left out), **Contains your name or the site's**, **Old** (unchanged
  for over a year): each item with **Edit**, which opens it in the editor. Unsecured websites also offer
  **Change to https** where that is safe (a domain name without a port): a confirmation shows the new
  addresses, then `health_use_https` saves them.
- **Two-factor sign-in available** (the site offers a second step, from the core's bundled 2FA Directory, and
  the login has no 2FA code or passkey), with the methods as chips and **How to turn it on**
  (`health_open_guide`, the directory's link for the item's site, opened in the browser; the window never
  passes a URL), **Logins without a password**, **Saved more than once** (with **Review and merge**, which
  opens Find duplicates) and **Passkeys available** (with **How to add one**).

"Look fine" is the report's `healthy` (no password problem; the account checks don't lower it) less the
items a breach check found that it counted as fine. The window gets titles, usernames, domains, addresses,
scores, methods and guide links only (`password_health`); nothing is looked up online except by the breach
check.

**Check for breaches** is optional and only runs on that click. The first click shows a short notice: only the
first 5 characters of each password's SHA-1 fingerprint go to Have I Been Pwned (api.pwnedpasswords.com, run by
Troy Hunt, with padding), never a password, a full hash, an e-mail address, a username or a website, and HIBP
sees the PC's IP address like any website; "Don't show this again" is kept in the settings
(`breach_notice_hidden`, `health_breach_notice`), and "About the breach check" shows it again. Rust hashes every
distinct password at once (the passwords are dropped) and asks the range API once per distinct prefix
(`pass_core::hibp_range`), one request after the other.

The check is a job of the app (`health.rs`, `BreachJob`), not of the pane: leaving the pane, switching sections
or closing the window (the app stays in the tray) never stops it. Only **Cancel** (`health_breach_cancel`, in
the pane or the tray menu's "Cancel breach check", which shows "Checking N of M passwords" while it runs), the
vault locking ("Check stopped: The vault locked", finished results go too) or quitting stop it. Progress goes
to every window as `health-breach` events; the pane asks `health_breach_status` when it opens, so it shows the
live progress, the result or "Check stopped" with the reason. The tray (tooltip, and a toast in the open
windows) says when it finished. Nothing is stored: after quitting or a lock the next check starts over, so no
hash outlives the unlocked vault. The tray parts are the same on macOS (the menu bar item's menu); a Linux
start without a tray has the pane's Cancel only. Passyble never checks by itself.

**Master password tip.** A master password set before the master password rule (`pass_core::master_password_check`,
Core/core/src/password_check.rs) still unlocks; unlocking never checks it. So each successful unlock with the
master password the user typed (the unlock form, the browser extension's unlock form, opening or restoring a
vault from a file, WebDAV, Google Drive or Passyble Server, a Passyble Server sign-in) runs the rule on that
password with the names this PC knows for the vault (its name, server or WebDAV user, Google account) and keeps
only the answer: `master_password_weak` in the vault's entry in `settings.json` (this PC only, never synced,
gone with the entry when the vault is removed from the list). Windows Hello and recovery code unlocks leave it
as it is; a password changed on another device clears it at the next unlock here. While it is set, Password
health shows a calm note at the top (the info banner, not a warning) with **Change master password** (the same
dialog as Settings → This vault, the Passyble Server account's for a server vault) and **Dismiss**
(`master_password_tip_dismiss`, `master_password_tip_dismissed`, allowed in read-only mode like the Windows
Hello offer's "Not now"). Changing the master password here clears both. `password_health` answers
`master_password_tip` (weak and not dismissed) and `master_password_server`; nothing on the unlock screen, no
toast. Tested in `src/settings.rs`, `src/health.rs` and `ui/test/health-model.test.mjs`.

**While editing.** The editor checks a login's password as it is typed (after a pause of about 350 ms), when
it opens with a password and when the username, websites or title change: `password_check` (`src/health.rs`,
`pass_core::password_issues`) compares it on this PC with the most common passwords, the vault's other
logins (the item's own password doesn't count), its earlier passwords, the username and the site. The
problems show under the field in a sentence each ("You use this password for 2 other logins."), with **Use
a strong password instead** (the generator with its remembered options) for the serious ones, or a quiet
"Strong" when there is nothing to say. It is only a warning: saving is never blocked. Nothing is sent
anywhere, the answer holds no secrets and the window keeps no copy of the password beyond the field; the
texts come from `ui/views/password-issues-model.js` (unit-tested in `ui/test/password-issues-model.test.mjs`).

## Two-factor sign-in and security activity

Settings → **Passyble Server** (Passyble Server vaults; `ui/views/twofactor.js`, `src/twofactor.rs`, docs/PROTOCOL.md
§3.7, §3.8):

* **Two-factor sign-in** shows On since <date> / Off / Set up but not confirmed / Not offered by this server
  (`server_2fa_status`). **Turn on…**: the account password (`server_2fa_setup`) → a QR code of the
  `otpauth://` URI, drawn locally (Rust's `qrcode` crate returns the module grid as one SVG path; nothing goes
  to a web service) plus the secret in groups of four with Copy key → the first code (`server_2fa_confirm`) →
  the 10 recovery codes, shown once, with **Copy**, **Save to a file…** (`server_2fa_save_codes`, through the
  save dialog) and **Done** only after "I saved my recovery codes" (Esc doesn't close that step). Nothing of
  this is stored on the PC. **Turn off…** asks for the password and a current code or a recovery code
  (`server_2fa_disable`).
* **Recovery codes**: how many are left, as a warning at 3 or fewer (turn it off and on again for new ones).
* **Recent security activity** (its own page, `server_security_events`): the account's newest events in
  plain words ("Signed in · with an authenticator code", "Failed sign-in · wrong two-factor code", "Password
  changed · 2 other devices signed out", …; unknown events by name), with the device, IP address and time,
  **This device** and an **Admin** chip for the admin's actions; failed attempts and turned-off protection in
  the warning colour.

A refused device token puts the vault into the "signed out" state, as everywhere else (`devices.rs`).

## Filling payment cards (browser extension)

When the extension fills a card into a page, or copies a card number or security code from its popup, the
agent asks the app first (`Ui::confirm_card_fill`, `src/ui.rs`): the prompt window shows "Fill a payment
card?" with the card ("<title> (Visa •••• 1111)") and the page's host, plus "inside a page on <host>" and a
note when the form is in another site's frame (payment providers), or "Copy card details?" for the popup.
**Cancel** is the default button; closing the prompt or its 2-minute timeout counts as no. A copy from the
popup (`cards.fill` with `purpose: "copy"` and a `field`) is then made by the app itself, like every copy of a
secret: kept out of Windows clipboard history and the cloud clipboard and cleared after 45 s
(`src/clipboard.rs`); the card value never goes to the browser.

## Import

Settings → Import → **Import from another app**, the sidebar's import button, or dropping a file on the window opens the import pane (`ui/views/import.js`, commands in `src-tauri/src/import.rs`):

1. **Choose file…** (CSV, JSON, ZIP, `.1pux`, `.2fas`, a Passyble export, also an encrypted one, which asks
   for its password first, or a PNG/JPEG screenshot of Google Authenticator's export QR code), or paste
   `otpauth-migration://` / `otpauth://` links.
2. The preview shows the detected format and counts (new, merged, skipped, can't import), warnings
   (e.g. passkeys that can't be imported, a Google Authenticator export split over several QR codes of
   which only some were imported). The webview gets titles, usernames, websites, which fields differ and
   opaque choice ids only; passwords, TOTP secrets and passkey keys stay in Rust.
3. **Review clashes (N)**: entries that are the same account as a vault login (same website and username), or
   several rows of the file for one account, come as cards: site initial, username, website, what differs
   (chips: *Password differs*, *2FA differs*, *Websites*, *Notes*, *Passkeys*, *Title*) and a **Merge** switch,
   on by default. On: identical entries are skipped, the rest merge into one item (websites, notes, passkeys
   united); when the passwords (or 2FA secrets) differ, **Keep password: Existing · From import (date)** picks
   which one stays and the other goes to the item's password history. Off: kept as separate items. The
   **Merge duplicates** switch above the cards sets them all (and the groups over the 2000-card cap); its line
   says how many merge. The tiles and the line next to **Import** count live ("12 new · 3 merged · 2 skipped").
   Entries that clash with nothing are listed under **New**.
4. **Import** adds the items to the currently unlocked vault with those decisions (`import_commit`), saves it
   and starts a sync. Locking the vault or switching to another one drops a pending import.

**Find duplicates** (Settings → Import, or the button on the import page) shows the same review for logins
already saved twice in the vault (same website and username, or same website and password without a
username; `find_duplicates`). **Merge N** merges the groups left on into their most recently changed item and
deletes the other copies (`merge_duplicates`); the review then runs again.

How to export from each app: see [Importing](../README.md#importing) in the main README. The QR
image decoder is the core's `import-qr` feature (`image` with PNG/JPEG only + `rqrr`), enabled in
`src-tauri/Cargo.toml`.

## Website icons

Logins show their website's own icon instead of the first letter of the title (the core's `icons`
feature, `src-tauri/src/site_icons.rs`; how the icon is found and the cache rules:
[ARCHITECTURE.md §11](../docs/ARCHITECTURE.md)). The domain comes from the login's first URL with a
public host name; notes, app links (`windows:`, `android://`), IP addresses and intranet names keep the
letter and are never fetched.

* **Where.** One file per domain in `%LOCALAPPDATA%\Pass\icons` (named by the SHA-256 of the domain),
  never in the vault and never synced. The browser extension's popup reads the same cache through the
  agent (`icons.get`); it never fetches.
* **When.** Only for avatars on screen (vault list, item detail, auto-type quick-pick, passkey chooser), only while the
  vault is unlocked and the setting is on: a cached icon shows at once, a missing or stale one is fetched
  in the background (at most 4 at a time, each domain at most once per 6 hours per run) and swapped in
  when it arrives (`site-icon` event). Locking empties the queue.
* **Setting.** Settings → Display → Show website icons (`show_site_icons`, this PC only, on by default).
  Turning it off stops the queue, deletes the cached icons and turns `icons.get` off; the avatars go back
  to letters right away.
* **Privacy.** A fetch is an anonymous HTTPS GET to the site itself that carries only its host name, no
  cookies or other vault data. It still lets that site (its CDN, and anyone watching the network or DNS)
  see that this PC asked for its icon, i.e. that you probably have a login there; the setting's (i) says
  so, and so does a small note under the choices of the first-run welcome screen (`onboarding.icons_note`,
  with the path to the setting).

## Clipboard

Copied secrets carry the `ExcludeClipboardContentFromMonitorProcessing`,
`CanIncludeInClipboardHistory = 0` and `CanUploadToCloudClipboard = 0` formats, so they stay out of Win+V
history and cloud clipboard. They are cleared after 45 s if the clipboard still holds them, and right
away when Passyble quits (the timer doesn't outlive the process).

## Security notes for the UI

* Each window gets only the commands it needs (`capabilities/default.json`; command permissions are
  generated in `build.rs`). For example, the prompt window can only list and answer prompts.
* Passkey private keys never reach the webview. Items cross the bridge as `ItemDto`, whose passkeys
  carry metadata only. Copy buttons use `copy_field`, so the password needn't be in the DOM. A card's number,
  security code and PIN and hidden custom fields aren't in the detail view's copy at all; Show fetches one
  (`item_secret`) and only the editor gets them (`get_item_for_edit`).
* Strict CSP (`script-src 'self'`, no inline script or style), `freezePrototype`, and DOM built with
  `textContent` (no `innerHTML` with vault data).
* **No screen capture.** Every window (main, prompt with its unlock and consent dialogs, TOTP popup, quick
  pick) is built with `content_protected` (`popups::CAPTURE_PROTECTED`, also `contentProtected` in
  tauri.conf.json): Windows leaves it out of screenshots, the Snipping Tool, recordings, Teams / Zoom
  sharing and taskbar / Alt+Tab previews (`WDA_EXCLUDEFROMCAPTURE`; black instead before Windows 10 2004),
  macOS likewise (`NSWindowSharingNone`). Always on, with no setting, as on Android (`FLAG_SECURE`). Linux
  can't do this (X11 lets any program read the screen; on Wayland the compositor asks the user before a
  capture). System dialogs (file pickers, the Windows Hello prompt) are the system's own windows and not
  covered; a photo of the screen never is.
* **Process hardening** (release builds; `PASSYBLE_HARDEN=1` turns it on in a debug build). `main` first
  calls `pass_agent::harden::harden_process` (Core/agent/src/harden.rs), the native host too: no Windows Error
  Reporting dumps, and a process DACL that lets the user's other programs (without administrator rights)
  only wait for, query and end Passyble, not read or write its memory, inject a thread, duplicate its
  handles or attach a debugger. macOS: no core dumps and `PT_DENY_ATTACH`. Linux: no core dumps only (see
  harden.rs for why not `PR_SET_DUMPABLE`). The vault keys are in RAM that is never paged out
  (`pass_core::key_memory_locked`). The log's start line says what took effect (`start: hardened yes, ...`).
  None of this stops an administrator or the kernel.
* An open item detail refreshes its 2FA code only while you're using the window, so it doesn't keep
  the vault from auto-locking.
* **What counts as use** for the auto-lock (sliding: each use starts it again at the chosen time, never
  more): the user's actions in the windows (commands that read or change the vault: `AppState::vault`),
  fills, copies, codes and passkeys from the extension once they went through, auto-type that typed, the TOTP
  popup's Copy / Type and a Windows passkey sign-in. Not: sync, the window reloading after a sync or an edit
  from the extension (`list_items` / `search` / `get_item` with `quiet`), codes the TOTP popup and the merge
  view show again each period (`totp` with `quiet`), the health and live password checks, the setup checklist,
  the auto-type hotkey or quick-pick alone (`Agent::peek_vault`). Settings → Auto-lock's (i) says so.
* The recovery code is made and checked in Rust; the window shows it once and passes it back only for
  Save as a text file… (which checks it is a code). A new master password without the old one is allowed
  only right after a recovery of that vault (`recovery_set_password`), and a code without the password only
  right after the vault was created or got a new password.

## Teams and Family

Shared vaults of a Passyble Team or Family, direct shares and the admin screens (docs/ARCHITECTURE.md §15 to §17,
docs/PROTOCOL.md §2 "Linked vaults"). Nothing of it shows for a user without a Passyble account and without a
shared vault on the active vault's Passyble Server.

* **Backends** (`src/teams.rs`): the active vault's self-hosted Passyble Server (account id: the server user name)
  and Passyble Cloud through the Passyble account (`src/account.rs`: OAuth 2.0 for native apps with PKCE and a
  loopback redirect, client `passyble-windows`; the refresh token and the Cloud device token in Credential Manager,
  the access token in memory only). One HTTP client for both services, `src/teams_api.rs`.
* **The browser extension in app mode** shows this account (`account.status`: signed in or not and the e-mail
  address, never a token) and hands its buttons to the app (`app.show_account`, docs/PROTOCOL.md §2 "The Passyble
  account in app mode"): Sign in brings the window up and starts the same sign-in as Settings' Sign in button
  (`account::show_from_extension`, a toast says how it went); Sign out opens Settings on the account row, where the
  user confirms it.
* **The browser extension in browser mode** has a sign-in of its own, and the two sign each other in on the same
  computer (`account.peer`, `account.handoff_*`, `account.sign_out`, `account.peer_signed_out`, docs/PROTOCOL.md
  §2 "The Passyble account in browser mode"; `src/account.rs`, "the same-computer sign-in handoff"). The signed-in
  side asks the service for a sign-in code for the other (`POST /v1/session/handoff`), bound to a PKCE verifier only
  the other side holds (the app's lives in memory for 60 seconds, single use): a session of its own for each, no
  token copied, no key moved. Toasts say when the extension signed the app in or out, or the app signed the
  extension in. Settings' Sign out asks "Also sign out of the browser extension on this computer" (ticked; shown
  when an extension asked in the last 30 days): ticked, the extension signs out of the same address at its next
  check; unticked, it stays signed in and doesn't sign the app in again until the user signs in here
  (`settings.json` `account_handoff`, no token).
* **Self-hosted**: a Passyble Server whose `features.create_vault` is on takes new shared vaults and direct shares
  (`POST /api/v1/vaults`, `server_vault_create`, `direct_share_start` without a Passyble Cloud organisation); the
  owner deletes one for everyone (`server_vault_delete`).
* **Device approval and holds**: a new Cloud device that waits for another device's approval (`403
  device_approval_required`) shows a waiting card with the e-mail fallback (`device_approval_email`); the other
  devices list it with Approve and "This wasn't me" (`device_approvals`, `device_approval_answer`). Vaults held by
  a sign-in rule or "SSO required" show as notices.
* **Kept lists**: with "Keep list visible when locked", each open shared vault's list is kept for the next start
  beside the home vault's (DPAPI, `kept_list.rs`, one file per shared vault with its kind and role) and deleted
  with it, and when the vault leaves the list.
* **Emergency access**: the trusted contact accepts with the e-mail's link (`emergency_accept`); the owner compares
  the contact's fingerprint and grants (`emergency_contact_keys`, `emergency_grant`). An opened vault shows in the
  vault view until the next lock (`Agent::add_session_vault`, kind `emergency`, read-only).
* **Export**: Settings, Export can export one open shared vault (`export_choices`, `export_vault` `vault_id`) when
  the user's role shows its passwords and the policy allows exports.
* **Linking** (`src/teams_vaults.rs`): after an unlock, a sign-in and on Refresh, the app reads `whoami` `vaults[]`,
  makes the keyset in the home vault and publishes its public keys, hands the agent the shared vaults
  (`Agent::set_linked_vaults`; local copies in `%LOCALAPPDATA%\Pass\shared\<hash>.vault`) and syncs them. The
  scheduler uploads a changed shared vault at the next tick and syncs them all with the home vault's sync. The
  item list, search, auto-type, the Windows passkey provider and the browser extension see every open vault.
* **Roles**: view and fill members can't edit (`errors.teams_read_only`); a fill member's login never comes to the
  window with its password, history or hidden fields (`password_hidden`), and copies of them are refused
  (`errors.teams_fill_only`); 2FA codes and passkeys work. Move or copy an item between vaults (`item_share`).
* **Member features**: Shared with me, invitations, who has access, rename (a name on this PC), leave, the
  unanchored-list check with the manager's fingerprint (`shared_trust_confirm`), notifications (server
  notifications, and for Passyble Cloud the vaults that came or went), members notices (lost member changes
  applied again or dropped, a new key after a manager left), policies (strength of a new master password, the
  longest auto-lock, export), secure send, emergency access and admin-assisted recovery (Teams, opt-in;
  `src/teams_send.rs`).
* **Pinned contact keys** (`src/contact_pins.rs`, Core docs/ARCHITECTURE.md §15.16): a vault key or the account
  key is wrapped only to people whose fingerprint this user compared, kept as pins in the home vault (synced,
  sealed). The account service's "confirmed" flag counts for nothing. Access changes (`org_confirm`,
  `org_vault_create`, `org_vault_access`, `org_department_member`) add or re-key only pinned people and return the
  others as `needs_compare` (`not_verified`, or `changed` with a loud warning); `org_members` marks each member's
  `pin`. A direct share and a new self-hosted vault compare first, then wrap (`direct_share_start`,
  `server_vault_create` answer `needs_compare` and make nothing until called again with the compared
  `fingerprint`, which pins). Admin recovery enrolment (`admin_recovery_enroll`, `account_admin_recovery_enroll`)
  first pins the admin who made the recovery key. Nothing joins admin recovery again on its own: after an e-mail
  reset (`rejoin` of `account_reset_complete`) and on "Turn on again" the member is asked "Join <org>'s admin
  recovery again?" with that admin's fingerprint. A recovery request answers its comparison `code`
  (`recovery_request_code`, from the request made on this device), shown big on the waiting screen for the member
  to read out on a call; the admin types it to approve (`org_admin_recovery_approve` `code`), so a request whose key
  the service swapped is refused. A shared vault shows whether the manager who signed its members list is
  verified (`signer_status` of `teams_overview` and `shared_vault_info`; `shared_signer_pin` pins them after a
  compare); keys that changed are a loud notice.
* **Admin and family manager** (`src/teams_admin.rs`): members and roles, invite one or from CSV, resend or
  withdraw, confirm a person's keys after comparing the fingerprint (they are then pinned and added to every shared
  vault of the organisation they should be in that this user manages), departments, new shared vaults and their access
  matrix (members lists follow it, removals rotate the key), remove someone (rotation, the list of passwords they
  could see, a successor), policies (the service's `policy_settings`, with the Team switches for single sign-on,
  device approval, secure send, emergency access and admin recovery, and the Team's "Passwords" rule), a
  member's own "Passwords" rule (`org_member_password_mode`: the team's rule or one of the three), activity,
  seats, recovery approvals, owner transfer (`org_transfer_owner`) and leaving (`org_leave`). Billing opens the
  website.
* **Password mode** (`src/password_mode.rs`, Core docs/ARCHITECTURE.md §17): a Team's `policy.password_mode`
  (the member's own), `choice`, `second_password` or `one_password`; `second_password` wins over
  `one_password` across organisations. This PC "has a second password" when a vault of its list opens with
  its own password (the file says, read when it changed) while signed in to an account in a Team; the answer
  goes to `PUT /v1/me/second-password` after a refresh when it changed for this session.
  * Sharing in a Team (Move or Copy into its vaults, "Share with a person" there) only outside
    `second_password`, without a second password here and while the organisation's `sharing_blocked` is
    false: those vaults are left out of the dialog, the action goes when nothing is left, the Teams screen
    says why, and `item_share` and `direct_share_start` refuse it too. Family and self-hosted server shares
    are unchanged.
  * `second_password` while the open vault still opens with the Passyble password: the Team's vaults are
    handed to the agent as not writable (read, fill, copy and sync down; no edit, new item, delete, restore,
    move or copy into them), member, access and vault changes of that Team are refused (`org_confirm`,
    `org_offboard`, `org_department_member`, `org_vault_create`, `org_vault_access`, `org_vault_delete`, a
    manager leaving), and the vault view, the Teams screen and each of its vaults show "Your team requires a
    second password" with "Set a second password" (the separate password flow for the home vault, the only
    time it is offered). The extension gets the same through `vaults.list` `password_policy`.
  * `one_password`: "Use a separate password" is gone; each vault with its own password shows "Your team
    uses one password" in Settings, This vault and on the Teams screen, with "Use Passyble password" (the
    link flow; another vault is unlocked first and opens in its Settings).
* **Tray**: "Teams and Family" when visible; new "shared with you", "confirm this person" and "removed" show as a
  toast in the open windows and in the tray tooltip.
* The UI is `ui/views/teams*.js`, `admin-model.js` and `account.js`; its strings are under `teams.`, `admin.`,
  `share.`, `send.`, `emergency.`, `recoveryadmin.`, `policy.` and `teams_rs.` in `ui/i18n`.

## Help and support

Code: `src-tauri/src/support.rs`, `ui/views/support.js` and `support-model.js` (rules the UI tests cover).

* **Entry points**: Settings, "Help and support"; "Report this problem" on an error toast (the error code is
  quoted in a new ticket); `passyble://support` links (the browser extension's help button, a guest ticket's app
  link); the tray, when a staff reply is waiting.
* **Guest flow** (no Passyble account): a new ticket needs an e-mail address. The service e-mails a link with a
  one-time code. The `passyble://support/app?r=&c=` link opens the app on a "Confirm" page that shows only the
  ticket reference; the code is held in memory and submitted only after the Confirm click, never by the link
  itself (a web page could otherwise fire links to use up the code's 5 tries). The code can also be typed or the
  link pasted in. Several guest tickets at once; removing one revokes its token. Signed in to an account, tickets
  belong to the account and need no code.
* **Diagnostics**: optional, off unless ticked, shown in full before sending. Only the allowed fields (app, version,
  platform, OS version, sync type, recent error codes, language), filtered again in Rust. Never vault data, names,
  addresses, URLs or paths.
* **Reply polling**: the desktop has no push, so a background poll (first after 2 minutes, then every 15 minutes,
  only while there are tickets to follow) looks for staff replies and shows them in the tray tooltip and as a toast.

## Memory and open speed

Passyble mostly sits in the tray, so what its hidden windows hold matters more than what an open
window uses; but the main window and the popups (unlock, fill and passkey consent, the 2FA code, the
quick pick) must still open at once. The choice (`src-tauri/src/webview_memory.rs`):

* **The four windows stay built and warm.** Building a WebView2 and loading its page takes several
  hundred ms, far over the ~150 ms an open from the tray may take, so no window is destroyed on close
  (Close hides it, Quit lives in the tray) and none is created on demand.
* **A hidden window rests.** The prompt, the TOTP popup and the quick pick are suspended 2 s after
  they hide (WebView2 `TrySuspend`, which also sets the memory target to low); the main window too
  while the vault is locked. The main window of an unlocked vault is only trimmed (memory target
  low): its page must keep running to drop the list and any revealed secret on `lock-state`, and it
  is suspended once the vault locks. The windows built at start-up rest 10 s after start, once their
  pages have loaded. The webview's `IsVisible` follows the window, so a hidden page knows it is
  hidden (no animation frames or paint work, `document.hidden`).
* **Opening wakes it first.** Every show resumes the webview and makes it visible before the window
  appears (`popups.rs`, all on the UI thread), and every event that fills a popup (`prompts-changed`,
  `totp-popup`, `quickpick`) wakes it before it is sent. The main window and the prompt also ask for
  their state again when they come back on screen (`onShown` in `ui/lib.js`), in case an event came
  while they slept.
* **One renderer process for all windows** (`--renderer-process-limit=1`, with wry's own WebView2
  arguments): they are all Passyble's own pages, so one renderer instead of four.
* **Language catalogs:** Rust parses only English and the active language (all nine came to several
  MB), and the windows get English once: as the catalog or as the fallback, not both.
* **The unlock password** is wiped from the app's memory when the unlock is done. Argon2's 64 MiB
  and the decrypted vault are the agent's (`Core/agent`, `Core/core`).
* macOS (WKWebView) and Linux (WebKitGTK) have no suspend or memory-target API: there the windows
  only stay warm.

Expected effect (estimates from the design; the owner's measurements replace them):

| State | Before | Expected now |
| --- | --- | --- |
| Started to tray | 4 renderers running, ~300 to 400 MB working set in all | 1 renderer, all pages suspended: about half |
| Window open | as above plus the main page drawing | about +40 to 60 MB over the tray state |
| Closed to tray | unchanged from window open | back to the tray state within ~2 s (locked) |
| After unlock (in the tray) | unchanged | main window trimmed, not suspended: slightly over the locked tray state until the vault locks |
| After the popups | each popup kept its memory | back to the tray state 2 s after each closes |
| Open latency (show to first frame) | already warm | under 150 ms: a resume takes tens of ms |

**Measuring** (Windows, an installed build, a demo vault):
`powershell -ExecutionPolicy Bypass -File desktop-app\scripts\measure-memory.ps1`. It starts Pass.exe
tray-only with `PASSYBLE_PERF=1`, walks through the five states, sums the working set and private
bytes of Pass.exe and its `msedgewebview2.exe` processes in each, and prints the open latencies Pass
logged (`perf: <window> painted N ms after show` in `%LOCALAPPDATA%\Pass\logs\pass.log`: the time
from the show to the window's first painted frame). Without `PASSYBLE_PERF=1` nothing is logged.

If a window turns out slow to wake or a page misbehaves while suspended, the rest policy is
`rest_for` in `webview_memory.rs` (`Rest::Trim` for a window keeps it running) and the shared renderer
is `BROWSER_ARGS` beside it.

## Translations

Guide for translators (all four apps: formats, glossary, `node scripts/i18n-check.mjs`): [docs/TRANSLATING.md](../docs/TRANSLATING.md).

Every text the app shows comes from a catalog, the windows' and Rust's alike (errors, tray menu,
toasts, notifications, Windows Hello prompts, file dialogs, the Google sign-in page, the text
files it saves). Log messages stay English.

* **Catalogs:** `ui/i18n/<locale>.json`, one file per language; `en.json` is the source. The file
  name is the language tag (`de`, `fr`, `zh-CN`, `pt-BR`). Rust embeds every file at build time
  (`build.rs` lists the folder; `src/i18n.rs`) and hands the active catalog and English to the
  windows (`i18n_state`, `ui/i18n.js`), so both always use the same language.
* **Format:** a flat JSON object. `"_meta": { "name": "German", "native": "Deutsch" }` names the
  language (Settings → Language lists it by its native name). Every other key is dotted
  (`trash.empty_confirm_title`) and maps to a text, or to a plural object.
* **Placeholders** are named and keep their braces: `"Can't reach {host}."`. Keep every
  placeholder of the English text (the test checks the sets are the same), move them as the
  sentence needs. Brand names (Passyble, Passyble Server, Windows Hello, Google Drive, WebDAV),
  file names, URLs and commands stay as they are.
* **Key names** in shortcuts are translated as the Windows keyboard of the language names them
  (`keys.*`: German `Strg+Umschalt+L`). Only the display: `keyLabel` / `withShortcut` in
  `ui/lib.js` turn "Ctrl+Shift+L" into it; the hotkey stored in `settings.json` and the keyboard
  handling stay English.
* **Plurals** are objects keyed by CLDR category: `{ "one": "{count} item", "other": "{count}
  items" }`, filled with `{count}`. Give the categories your language uses (`Intl.PluralRules`;
  e.g. `one`/`other` for German, `one`/`many`/`other` for French and Spanish, only `other` for
  Chinese, Japanese, Korean and Indonesian); a missing category falls back to `other`. Texts that
  say something different for exactly one (`"The item is back."`) are separate keys, not plurals.
* **Labels inside sentences:** `vault.show_field` ("Show {field}") gets the field's label in lower
  case except in German (`inSentence` in `ui/i18n.js`).
* **Missing texts** fall back to English, then to the key itself (with a console warning), so a
  partial catalog works.
* **Language choice:** Settings → Display → Language (`settings.json` `language`; "System
  default" leaves it out). The default is Windows' display language
  (`GetUserPreferredUILanguages`, then the user locale), matched to the catalogs: the exact tag,
  Chinese by script (`zh-Hans`/`zh-CN`/`zh-SG` → `zh-CN`; `zh-Hant`/`zh-TW`/`zh-HK` only with a
  `zh-TW` catalog), old codes (`in` → `id`), else the base language (`hi-IN` → `hi`), else English.
  Changing it relabels the tray, and every window reloads in the new language (Settings opens
  again). The language also goes to Passyble Server (`Accept-Language`, and the account's
  language for its e-mails).
* **In code:** `t("key", { name })`, `tn("key", count, { name })` and `tx("key", { name: node })`
  (placeholders that are DOM nodes) in the windows, `formatNumber` / `formatDate` /
  `formatDateTime` / `formatTime` for numbers and dates; `data-i18n="key"` and
  `data-i18n-attr="title:key"` for static markup. In Rust `tr!("key", name = value)` and
  `trn!("key", count, name = value)`. The desktop agent (`pass-agent`) gives its "Confirm it's you"
  prompts a typed `pass_agent::Reason` (its `Display` is English, for logs); `src/ui.rs`
  (`reason_text`) maps each one to a `reason.*` key.
* **Adding a language:** copy `en.json` to `ui/i18n/<tag>.json`, set `_meta`, translate the
  values (never the keys), rebuild. `node --test Core/desktop-app/ui/test/*.test.mjs` checks that
  every key the code uses exists in `en.json`, that other catalogs have no unknown keys, the same
  placeholders and valid plural objects, and lists what is still untranslated.

The UI tolerates longer texts (labels and button rows wrap). Latin text is in Space Grotesk; Chinese,
Japanese, Korean and Hindi fall back to the Windows UI fonts after it (`styles.css`, by `<html lang>`).

## Limits

* Auto-type can't type into elevated (admin) windows from a non-elevated Passyble (UIPI), and some games or
  anti-cheat protected apps ignore injected input. The sequence is always `{USERNAME}{TAB}{PASSWORD}{ENTER}`.
* Windows can still refuse to bring the unlock or passkey window to the front in edge cases (full-screen games,
  another app holding `LockSetForegroundWindow`); the prompt window is always-on-top as a fallback.
* The agent's pipe accepts only `pass-native-host.exe` beside `Pass.exe` and `Pass.exe` itself. That stops casual
  misuse by other programs, but malware running as you can still start the real native host or inject into it.
* The Windows passkey provider offers ES256 only and lists no extensions (see "Windows passkey provider").
