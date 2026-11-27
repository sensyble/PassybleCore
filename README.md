# Passyble

One password manager for Android and Windows that fills **passwords, 2FA codes and passkeys** without
you switching apps or picking up your phone.

**New to Passyble?** The [help center](https://help.passyble.com/) sets it up in 10 minutes and has step-by-step tutorials
for the Windows app, the browser extension, Android, sync and importing. Download Passyble for Windows from the
[releases page](https://github.com/sensyble/pass-releases/releases/latest).

* **Passwords**: Android autofill (including keyboard suggestion chips), browser extension inline menu on
  Windows, and a global hotkey that auto-types into native Windows apps.
* **2FA (TOTP)**: the code is stored with the login and filled right after the password. When it can't be
  filled directly, Android shows a persistent notification with the live code and a **Copy** button (like
  Shizuku's pairing notification), and Windows shows a small popup (in the browser or by the tray). A 2FA link or
  QR code (`otpauth://`) from a camera app, a web page or another app opens Passyble, which asks before adding it.
* **Passkeys**: Passyble is a Credential Manager provider on Android 14+, and on Windows the extension handles
  `navigator.credentials` for sites. Passkeys sync, so one created on the phone works on the laptop. Your
  phone also serves them to any PC over the standard QR/Bluetooth flow.
* **Sync**: the vault is one end-to-end-encrypted file, kept on a WebDAV server you control (e.g.
  Nextcloud) or in a OneDrive/Dropbox/Syncthing folder. There's no Passyble cloud and no account. If you
  want a turnkey host, run the optional self-hosted [Passyble Server](https://github.com/sensyble/PassybleServer) (QR pairing, per-device tokens,
  version history, backups).
* **Most used first**: every app counts how often you use each login (fills, auto-type, copied passwords,
  passkey sign-ins) and suggests the most used first. The counts are encrypted inside the vault file like
  everything else and sync with it, without causing extra syncs. See docs/ARCHITECTURE.md §13.
* **More than logins**: payment **cards** and **identities** (name, address, contact details for forms), **custom
  fields** (plain or hidden), **tags** (folders; `/` nests them, `tag:work` or `#work` in search), a **trash** (Delete
  moves an item there; restore it, or it is purged after 30 days) and a **password health** check (weak, reused and
  old passwords, passwords that contain the username or site name, unsecured `http://` websites with "Change to
  https", sites that offer two-factor sign-in or passkeys the login doesn't use yet, from offline copies of the 2FA
  Directory and the Passkeys Directory, logins without a password and duplicates, plus an optional breach check that
  sends only a 5-character hash prefix). When a password is about to be saved or is being edited (save prompts and
  editors in every app), Passyble also says what is wrong with it: one of the most common passwords, easy to guess,
  reused on other logins, contains the username or the site's name, too short; checked on the device only, nothing is
  sent anywhere (docs/ARCHITECTURE.md §6). These are in the core and
  the vault format; vaults stay readable by older Passyble versions, which show a card or identity as a secure note
  (docs/ARCHITECTURE.md §2). The Windows and Android screens for them are still in progress.
* **Username and e-mail generator**: next to the password generator, a random username (`Swift-Otter`,
  `Otter4821` or random characters) or an e-mail address for each sign-up: a plus address of your own
  (`you+k3vq9tmz@example.com`), a catch-all address at your domain, or a new alias at your own SimpleLogin, addy.io,
  Firefox Relay, DuckDuckGo Email Protection, Fastmail (masked e-mail) or Forward Email account. Usernames and plus or
  catch-all addresses are made on the device. An alias service is contacted only if you set it up with your API token
  (kept encrypted in the vault and synced with it), and only when you create an alias or test the token; the website
  goes along only if you tick "Mention the website". See docs/ARCHITECTURE.md §14.
* **AI tools**: Claude Code, Codex and other MCP clients can run commands with secrets from the items you mark
  "Available to AI tools", through the connector `passyble-mcp`. You see the exact command and approve it; the AI never
  sees the value (output is masked), and showing it a value asks every time. See [docs/AI_TOOLS.md](docs/AI_TOOLS.md).
* **Import and export**: bring logins, cards, identities, custom fields, 2FA secrets and passkeys over from
  Chrome/Edge/Brave, Firefox, Safari, Proton Pass, 1Password, Bitwarden, KeePass/KeePassXC (`.kdbx` databases too),
  LastPass, Dashlane, Google Authenticator, Aegis and 2FAS. **Password-protected exports** open with their password:
  Bitwarden "Password protected" JSON, encrypted Aegis vaults and 2FAS backups, PGP-encrypted Proton Pass exports,
  KeePass databases (password and/or key file) and encrypted ZIP files. You see a preview first; existing logins are
  merged instead of duplicated. See
  [Importing](#importing). Export as Bitwarden-compatible CSV, Passyble JSON or password-encrypted JSON. See
  [Exporting](#exporting).
* **Languages**: English, Spanish, French, German, Simplified Chinese, Japanese, Korean, Hindi and Indonesian in all
  four apps (Windows follows the Windows display language, Android its per-app language, the extension the browser's
  language; Passyble Server e-mails use each account's language). Adding a language needs no code change: see
  [docs/TRANSLATING.md](docs/TRANSLATING.md).

**Names.** The apps are called **Passyble** (Windows: Start menu, Apps & features, installers; Android:
launcher; also the browser extension and the self-hosted **Passyble Server**). The product was called
"Pass" first, then "SenPass"; internal names keep "Pass" on purpose so existing installs, vaults,
browser pairing and updates keep working: the Windows executable `Pass.exe`, data folders
`%APPDATA%\Pass` / `%LOCALAPPDATA%\Pass`, the app id and native messaging host `com.sensyble.pass`, the
`pass+server://` links, the server binary `pass-server` with its config files and paths, and crate
names. The Passyble setup replaces an installed SenPass or Pass.

## Repository

Code shared by every Passyble product: the Rust core (`core/`, pass-core), the desktop agent (`agent/`), the browser native-messaging host (`native-host/`), the connector for AI tools (`mcp/`), the browser vault's WebAssembly (`wasm/`), the Tauri desktop app shared by Windows, macOS and Linux (`desktop-app/`), and the cross-product docs (`docs/`).

This is one of the Passyble repositories (Core, Windows, macOS, Linux, iOS, Android, Extension, Firefox, Safari, Server, Website). They are cloned side by side into one folder, each under its own name, so the relative paths between them (`../Core/core`, `../../Extension`, ...) work.

It builds and tests on its own.

Optional:

* [PassybleWindows](https://github.com/sensyble/PassybleWindows): the desktop app (desktop-app/src-tauri, its own Cargo workspace) depends on ../../../Windows/platform
* [Passyble-macOS](https://github.com/sensyble/Passyble-macOS): the desktop app depends on ../../../macOS/platform
* [PassybleExtension](https://github.com/sensyble/PassybleExtension): the browser vault's module build and tests, the i18n check and its tests, and the desktop app's extension staging
* [Passyble-Android](https://github.com/sensyble/Passyble-Android): the i18n check and its tests (scripts/test)
* [PassybleServer](https://github.com/sensyble/PassybleServer): the i18n check and its tests (scripts/test)

```sh
# One folder for all Passyble repositories, for example ~/src/Passyble
mkdir Passyble && cd Passyble
git clone https://github.com/sensyble/PassybleCore.git Core
# optional:
git clone https://github.com/sensyble/PassybleWindows.git Windows
git clone https://github.com/sensyble/Passyble-macOS.git macOS
git clone https://github.com/sensyble/PassybleLinux.git Linux
git clone https://github.com/sensyble/PassybleExtension.git Extension
git clone https://github.com/sensyble/Passyble-Android.git Android
git clone https://github.com/sensyble/PassybleServer.git Server
```

Test (from this repository's root):

```sh
cargo test                                   # pass-core, pass-agent, pass-native-host, passyble-mcp (default members)
cargo test -p pass-wasm -p pass-wasm-kdf     # the browser vault's crates
node --test desktop-app/ui/test/*.test.mjs   # desktop UI
# The desktop app is its own workspace (needs ../Windows, ../macOS and ../Linux; on Windows, WebView2):
cd desktop-app/src-tauri && cargo test
node scripts/i18n-check.mjs                  # translations of the sibling apps (docs/TRANSLATING.md)
node --test scripts/test/*.test.mjs          # the i18n check's own tests
node scripts/check-no-emdash.mjs
```

On Windows, run cargo at idle priority through `scripts\cargo-low.cmd` (for example `scripts\cargo-low.cmd test`); see CONTRIBUTING.md.

## Layout

Passyble is split into one repository per product, cloned side by side (see [Repository](#repository)).
Code that more than one product uses lives here, in Passyble-Core; each product repository holds only what is
specific to it. Crate names did not change with the split (`pass-core`, `pass-agent`, `pass-wasm`, ...), so
`cargo -p <crate>` works as before.

| path | what | status |
|---|---|---|
| [`core/`](core) | Rust `pass-core`: vault format + crypto, TOTP, WebAuthn authenticator, matching, merge, WebDAV, Google Drive, import, export, password health; UniFFI for Android | tested |
| [`agent/`](agent) | Rust `pass-agent`: unlocked session, auto-lock, browser protocol over named pipe / Unix socket | tested |
| [`native-host/`](native-host) | Rust `pass-native-host`: browser Native Messaging to agent relay | tested |
| [`mcp/`](mcp) | Rust `passyble-mcp`: the connector for AI tools, an MCP server over stdio that runs commands with secrets from the vault ([docs/AI_TOOLS.md](docs/AI_TOOLS.md)) | tested |
| [`wasm/`](wasm) | Rust `pass-wasm`, `pass-wasm-kdf`: the browser extension's own vault (pass-agent and pass-core as WebAssembly) | tested |
| [`desktop-app/`](desktop-app) | Rust `pass-desktop`: the Tauri v2 desktop app and its `ui/`, shared by Windows, macOS and Linux (cfg dispatch to the platform crates in Passyble-Windows, Passyble-macOS and Passyble-Linux); `src-tauri` is a Cargo workspace of its own, the only part of this repository that needs those three. Cargo loads every path dependency whatever the target, so all three must be cloned | see its README |
| [`docs/`](docs) | design, protocol, testing, translating, brand, user guide | |
| [`scripts/`](scripts) | `cargo-low.cmd`, the i18n check of all apps, the em dash check, site list refresh | |

The other repositories:

| repository | what | status |
|---|---|---|
| [PassybleWindows](https://github.com/sensyble/PassybleWindows) | Windows only: `platform/` (crate `pass-windows`: Win32 and WinRT system code), `installer/` (NSIS / MSI config, installer scripts, passkey provider package) and the release steps | see its README |
| [Passyble-macOS](https://github.com/sensyble/Passyble-macOS) | macOS app: `pass-macos` crate, bundle config | in progress |
| [Passyble-iOS](https://github.com/sensyble/Passyble-iOS) | iPhone app and AutoFill extension | in progress |
| [Passyble-Android](https://github.com/sensyble/Passyble-Android) | Kotlin/Compose app: autofill, OTP notification, passkey provider | see its README |
| [PassybleExtension](https://github.com/sensyble/PassybleExtension) | MV3 browser extension source shared by Chrome, Edge, Firefox and Safari | see its README |
| [PassybleFirefox](https://github.com/sensyble/PassybleFirefox), [Passyble-Safari](https://github.com/sensyble/Passyble-Safari) | browser-specific packaging of the extension | in progress |
| [PassybleServer](https://github.com/sensyble/PassybleServer) | Rust `pass-server`: optional self-hosted vault host (WebDAV subset, device tokens, versions, backups, optional two-factor sign-in, audit log, metrics) | tested |
| [Passyble-Website](https://github.com/sensyble/PassybleLanding) | the passyble.com website (static site) | see its README |

Translating the apps: [docs/TRANSLATING.md](docs/TRANSLATING.md). Testing status and checklist: [docs/TESTING.md](docs/TESTING.md). Design: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Interfaces (core API and extension protocol):
[docs/PROTOCOL.md](docs/PROTOCOL.md).

## Importing

Windows: Settings → **Import…** → choose the export file (or paste Google Authenticator links) → check the
preview → **Import**. Android uses the same core (`import_parse`, see [docs/PROTOCOL.md](docs/PROTOCOL.md)).
Passyble reads the file locally; nothing is uploaded. Delete the export file afterwards.
Password-protected exports are opened with their password, which Passyble asks for and doesn't keep
(`import_encryption`, `import_parse_with_password`; KeePass key files with `import_parse_with_key_file`): Passyble's
own encrypted export, Bitwarden "Password protected" JSON, encrypted Aegis vaults and 2FAS backups, Proton Pass
exports with PGP encryption, KeePass `.kdbx` databases and ZIP files with encrypted members. Bitwarden's "Account
restricted" export can only be opened by Bitwarden: export again with a file password. Files asking for unusually
heavy key derivation settings are refused instead of freezing the app (docs/ARCHITECTURE.md §6).

How to export from each app:

| from | how | file |
|---|---|---|
| Google Authenticator | ⋮ → Transfer accounts → Export accounts. Screenshot each QR code and import the image (Windows), or scan it (Android / any QR reader) and paste the `otpauth-migration://` link | PNG/JPEG or link |
| Chrome / Edge / Brave | Password Manager → Settings → Export passwords | CSV |
| Firefox | `about:logins` → ⋯ → Export passwords | CSV |
| Apple Passwords / Safari | Passwords app (or Safari) → File → Export All Passwords | CSV |
| Proton Pass | Settings → Export → ZIP, with or without PGP encryption (or CSV) | ZIP / CSV |
| 1Password | File → Export → account → **1PUX** (or CSV) | `.1pux` / CSV |
| Bitwarden | Tools → Export vault → **.json** (plain, or ".json (Encrypted)" with "Password protected") or .csv | JSON / CSV |
| KeePass / KeePassXC | import the `.kdbx` database itself (password and/or key file), or Database → Export → CSV File | KDBX / CSV |
| LastPass | Account options → Advanced → Export | CSV |
| Dashlane | Settings → Export data → CSV | ZIP of CSVs / CSV |
| Aegis | Settings → Import & Export → Export → JSON, encrypted or not | JSON |
| 2FAS | Settings → 2FAS Backup → Export to file, with or without a password | `.2fas` |
| other authenticators | export or copy the `otpauth://` links | text, one per line |
| Passyble | an export from [Exporting](#exporting): JSON, or encrypted JSON (Passyble asks for its password) | JSON |

What comes across: logins (title, websites, username/email, password, notes, favourite), secure notes, **payment
cards** and **identities** (Bitwarden JSON, Proton Pass, 1Password `.1pux`, LastPass secure notes of type Credit Card
and Address, Dashlane `payments.csv` and `personalInfo.csv`), **custom fields** (kept as fields, hidden ones stay
hidden; Bitwarden CSV can't mark them), **folders, collections and groups as tags** (KeePassXC and LastPass nested
folders stay nested), TOTP secrets (`otpauth://` or base32) and Bitwarden passkeys (their ES256 private keys are
exported). Cards and identities in a Bitwarden CSV, aliases, HOTP/Steam codes, SSH keys and items in the source app's
trash/archive are listed as skipped. Proton Pass and 1Password don't export usable passkey keys, so those passkeys are
skipped with a warning (register a new passkey on the site).

## Exporting

The core exports the unlocked vault in three formats (`export_csv`, `export_json`, `export_encrypted_json`; see
[docs/PROTOCOL.md](docs/PROTOCOL.md)). The Windows and Android screens for it are still in progress. Items in the
trash are not exported.

| format | holds | for |
|---|---|---|
| Bitwarden-compatible CSV | logins, notes, cards and identities (as notes with their details in the `fields` column), custom fields, the first tag as folder; no passkeys, password history or hidden-field marks | importing into another manager |
| Passyble JSON | everything, passkey private keys and password history included | a backup or moving to another vault; Passyble imports it again |
| Encrypted Passyble JSON | the same, sealed with a password you choose (Argon2id, XChaCha20-Poly1305) | a backup you can keep somewhere less safe; importing it needs the password |

Every export is readable by anyone who has the file (the encrypted one: and its password), so keep it somewhere safe and
delete it when you are done.

## Build & test

See [Repository](#repository) for this repository's tests. The other products are tested in their own
repositories (`cargo test -p pass-server` in PassybleServer, `npm install && npm test` in PassybleExtension, ...).

The Windows app (`desktop-app`) needs WebView2 and is built on Windows with `cargo tauri build`, which makes
both installers: `Passyble_<version>_x64-setup.exe` (per user, updates itself) and
`Passyble_<version>_x64_en-US.msi` (per machine, for IT deployment). The Android app needs the Android
SDK/NDK and `cargo-ndk`. See their READMEs.

## Security model, briefly

* Argon2id (64 MiB, t=3) derives the key that wraps a random vault key. Every item is sealed with
  XChaCha20-Poly1305 and bound to its vault and item id, so ciphertexts can't be swapped or moved.
* Secrets are decrypted only inside the Android app process or the desktop app. The browser extension
  receives one credential at a time, and only for an item that matches the tab's URL. The desktop agent
  checks that binding on every request.
* Passkeys: the RP ID is validated against the origin (and against Digital Asset Links for native Android
  apps). Passkeys use ES256, `none` attestation and the backup-eligible flag.
* Not yet audited. Treat it as pre-release software.

## Reporting a security issue

Please don't open a public issue for a vulnerability. How to report one privately, what to include and how
fast we aim to answer are in [SECURITY.md](SECURITY.md), also published at
https://passyble.com/vulnerability-disclosure/.

Dependencies are checked for known vulnerabilities on every push and pull request and every Monday
(`.github/workflows/dependency-audit.yml`: cargo deny (`deny.toml`) and cargo audit (`.cargo/audit.toml`)), and Dependabot (`.github/dependabot.yml`)
proposes updates weekly.

## Licence

Copyright (C) 2026 Sensyble LLC

This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General
Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option)
any later version. This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See [LICENSE](LICENSE)
for the full text.

Third-party parts keep their own licences: [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). Contributions
are welcome under a Contributor License Agreement ([CONTRIBUTING.md](CONTRIBUTING.md)). The Passyble and
Sensyble names and logos are trademarks of Sensyble LLC ([TRADEMARKS.md](TRADEMARKS.md)).
