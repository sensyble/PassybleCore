# Passyble: test handoff

What's verified, what isn't, how to build each part, and what to test on real devices first.

## 1. Purpose and state of each component

Passyble is one password manager for Android and Windows that fills **passwords, TOTP codes and passkeys**
everywhere, so you don't switch apps or pick up your phone for a code. When a TOTP code can't be filled
directly, Android shows an ongoing notification with the live code + Copy, and Windows shows a popup (in
the page or by the tray). The vault is one end-to-end-encrypted file synced via WebDAV or a cloud folder.

| component | path | state |
|---|---|---|
| Core (vault, crypto, TOTP, passkey authenticator, matching, merge, WebDAV, cards / identities / fields / tags / trash, import and export, password health) | `Core/core/` | **Tested**: ~100 tests incl. RFC 6238 vectors, passkey signatures verified like an RP, merge convergence, record/header authentication (v1 files still open, forged tombstones and replayed headers are not merged), KDF bounds, older-client compatibility of cards, tags and the trash (`Core/core/tests/items.rs`), export round trips, WebDAV against a local server. Passing on Linux and Windows. |
| Desktop agent + native host | `Core/agent`, `Core/native-host` | **Tested**: ~30 tests incl. full protocol, passkey register/sign-in (origin refusal, UV flag only after verification, `id` restriction), cloud-folder reload, conflict copies (each kind merged and removed, manual backups left alone), unsaved-copy stash and merge, the `lock` method, `logins.find` not counting as activity, sliding auto-lock (background methods never count, a cancelled or failed fill doesn't, uses restart it at the chosen time without adding up, a fill waiting for Windows Hello holds the lock off; `tests/protocol.rs` activity tests and `agent.rs` `auto_lock_due`), IPC round trip (unix socket). Built and tested on Windows. The named-pipe path (including the client and server process checks) has **not** been exercised by a test. |
| Windows app (Tauri v2) | `Core/desktop-app` | **Builds**: `cargo tauri build --config tauri.bundle.conf.json` builds the release app and both unsigned Passyble installers (NSIS setup and MSI). Run on a dev PC; the NSIS setup was silently installed (also over an old "Pass" install) and uninstalled there (items 33, 43); the MSI was built but never installed. |
| Browser extension (MV3) | `Extension/` | **1540 jsdom tests pass**. The 2FA chain also runs end to end in Playwright's Chromium (`npm run test:e2e`, opt-in): the real extension with a mock agent behind a stubbed `connectNative`, 31 checks on local 2FA pages (incl. a site that skips 2FA). Passkeys run end to end too (`passkey.e2e.mjs`, 17 checks, also in Brave): register and sign in against the **real agent** (`e2e_agent` harness) with every response verified like a relying party. Not yet run against the real native host in Chrome/Edge/Brave/Firefox. |
| Android app | `Android/` | **Builds**: `gradle assembleDebug` passes (Rust core via cargo-ndk, UniFFI bindings, Kotlin/Compose). **Never installed on a device.** |
| Account service (`account.passyble.com`) | separate repository | **Tested** there. Live at `account.passyble.com`; the apps use it for the optional Passyble account. |

## 2. Not verified yet: needs real hardware

Windows 11 desktop app: everything at runtime. That covers window creation, onboarding, unlock, tray,
the `Ctrl+Alt+P` auto-type (SendInput, focus restore), the TOTP popup (always-on-top, must not steal
focus, "Type it"), passkey consent/chooser prompt, Windows Hello unlock (Hello-key bound, DPAPI outer layer), lock on Win+L/sleep,
clipboard clear and clipboard-history exclusion, native messaging registration (HKCU keys + manifests),
and the named pipe `\\.\pipe\pass-agent-<user>`.

Windows hardening from the security pass (item 36): saving while a sync client locks the vault file, auto-type
focus checks and elevated windows, the native host's check of the pipe's server, the passkey UV flag with
per-fill verification.

Browser extension: real Chrome/Edge/Firefox loading, native messaging handshake, inline menu
positioning on real sites, React/Vue field filling, the OTP-on-next-page flow on real sites with the real agent (the same flow passes in Chromium against local look-alike pages and a mock agent), save banner,
passkey create/get on real RPs (webauthn.io, github.com, google.com), and fallback to the browser's
WebAuthn when Passyble declines.

Android (14+ for passkeys): autofill in apps and in Chrome/Brave (native, "Autofill using another service"), Gboard inline chips,
dataset auth + OTP fill, the OTP notification (code, countdown, Copy, auto-dismiss), Quick Settings tile,
the Credential Manager provider (create/get passkeys and passwords, privileged-browser origin
handling, Digital Asset Links for native apps), biometric unlock, QR scanning, WebDAV sync worker, and which
apps may name a website to autofill (item 34), unlock/sign-in against a replaced server vault (item 35),
website logins suggested for apps (item 46) and no save offer on system credential screens (item 75).

Cross-device: the same vault on phone + PC via WebDAV (Nextcloud) and via a OneDrive folder (PC side).
Passkey created on one device signs in on the other.

Account service: tracked in its own (private) repository.

## 3. Build and install

### Windows (PowerShell, from the Passyble-Core root; the desktop app needs Windows, macOS and Linux cloned next to it)

Prereqs: Rust (MSVC toolchain), Visual Studio Build Tools (C++), WebView2 (ships with Win 11), Node 22,
`cargo install tauri-cli --version "^2"`.

```powershell
cargo test                                   # core, agent, native host
cargo build -p pass-native-host --release    # dev runs need the host beside Pass.exe
cd desktop-app\src-tauri
cargo tauri dev                              # dev run (or: cargo run -p pass-desktop)
cargo tauri build --config tauri.bundle.conf.json   # installers; bundle pass-native-host as a sidecar
# -> target\release\bundle\nsis\Passyble_<version>_x64-setup.exe (per-user, %LOCALAPPDATA%\Programs\Passyble)
# -> target\release\bundle\msi\Passyble_<version>_x64_en-US.msi   (per-machine, C:\Program Files\Passyble)
```

`Pass.exe` opens no console window, in debug builds too; its diagnostics are in
`%LOCALAPPDATA%\Pass\logs\pass.log` (Settings → About → Log file → Open folder), and on stderr under `cargo run`.

For a dev run, copy `target\release\pass-native-host.exe` (Core's root workspace) next to the `Pass.exe` you run
(`desktop-app\src-tauri\target\debug\` for `cargo tauri dev`; the desktop app is its own workspace). Passyble registers the native host for Chrome, Edge and Firefox in HKCU on
every start.

### Extension

```powershell
cd ..\Extension; npm install; npm test
# optional, real Chromium: the 2FA chain end to end against local pages and a mock agent
# (needs Playwright's Chromium: npx playwright install chromium)
npm i --no-save playwright; npm run test:e2e   # HEADED=1 to watch
```
* Chrome/Edge: `chrome://extensions` → Developer mode → Load unpacked → `Extension/`. The manifest `key`
  pins the ID to `bmjmlhhgfbpcbfbkbndlmmockkbdcaoo`, which Passyble already registers for native messaging.
  Store IDs must be added to `CHROME_STORE_EXTENSION_IDS` and `EDGE_STORE_EXTENSION_IDS` once assigned.
* Firefox 128+: `node scripts/make-firefox-manifest.mjs --dist dist/firefox`, then `about:debugging` →
  Load Temporary Add-on → `dist/firefox/manifest.json`.

### Android

Prereqs: Android Studio (SDK 35, NDK), JDK 17, Rust + targets
`rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android`, `cargo install cargo-ndk`.
There's no Gradle wrapper JAR in the repo: open `Android/` in Android Studio, or run `gradle wrapper --gradle-version 8.10.2`
once.

```powershell
cd ..\Android
.\gradlew assembleDebug     # builds the Rust core via cargo-ndk, generates UniFFI bindings, builds the APK
.\gradlew installDebug
```

## 4. Known limits

* The extension clears the clipboard 45 s after a Passyble copy without reading it first (no `clipboardRead`), so
  something else copied within those 45 s is cleared too.
* A live TOTP shown in the Windows UI doesn't keep the vault unlocked (by design).
* Windows passkey provider: ES256 only, no extensions (credBlob, largeBlob, PRF; desktop-app/README.md says why PRF
  isn't offered there); without a code-signing certificate for the release build it needs Developer Mode on the
  user's PC. The WebAuthn PRF extension itself works with the browser extension (through the desktop app), Android
  and iOS: core/src/prf.rs, tests in core/tests/passkey_prf.rs.
* Android keeps a pending OTP session (the secret for Copy) in memory only; after process death Copy is gone, but the
  hint still ranks the right item first.

## 5. Test checklist (priority order)

1. **Windows app launches**: `cargo tauri dev` opens, create a vault, lock/unlock, add a login with a
   TOTP secret (e.g. `JBSWY3DPEHPK3PXP`), the code matches another authenticator app.
2. **Native messaging**: load the extension unpacked (ID must be `bmjmlhhgfbpcbfbkbndlmmockkbdcaoo`). The popup
   shows unlocked state and matches for the tab. Check the three HKCU keys exist. Unlock from the browser while
   Passyble is in the background: the prompt should come to the front, not just flash in the taskbar. A random
   process opening `\.\pipe\pass-agent-<user>` should be rejected, and so should the reverse case (item 36).
3. **Password fill in browser**: on github.com/login, use the inline menu to fill. Then the 2FA page: the code
   fills on its own (Options → **Auto-fill 2FA code**, on by default; off: the menu opens with the code first).
   Test the toast fallback on a site without a detectable OTP field. Item 45 has the full 2FA list.
4. **Passkeys in browser**: webauthn.io: register (the extension's "Save a passkey for webauthn.io in Passyble?"
   card appears in the page, item gets a passkey), then authenticate (the card's **Sign in**). **Cancel** once: the
   page reports a cancelled request (`NotAllowedError`). A site that accepts no ES256 key, or **Use another device**
   in the card, falls back to the browser's dialog (item 85). UV flag and
   sandboxed frames: items 36 and 37.
5. **Android install + autofill**: create or restore vault, enable autofill service, fill a login in Chrome
   and in a native app. Check Gboard chips.
6. **Android OTP notification**: fill a TOTP login where the 2FA screen has no detectable field.
   The notification shows the live code and Copy works. By default (Settings → Autofill → 2FA notification → **Keep until dismissed**) it stays and
   keeps refreshing until dismissed or copied; the older 30-second behaviour is the other choice (item 66).
   **Collapsed (not expanded)** it already shows the site, the big code, a count-down and a Copy button;
   expanded it adds Copy / Dismiss. Switch to another app and wait across a period boundary (30 s) on a
   Samsung phone: the code and count-down refresh at the boundary and the time never goes negative (while it runs, "Passyble" is listed under active apps).
   With "Require biometrics before each fill" it shows "Code hidden" and the collapsed Copy asks first.
   Android 13 or older, or when the service is refused: the notification vanishes at the end of the period
   instead of going negative. Check dark and light theme and a large font size.
7. **Android passkeys (14+)**: enable Passyble as passkey provider. On webauthn.io in Chrome, create and
   sign in. Also try the QR/hybrid flow from the Windows PC to the phone.
8. **Sync**: the same vault on PC and phone over WebDAV. Edit on both sides, sync, and check both changes
   survive. A passkey made on the phone signs in on the PC through the extension.
9. **Windows auto-type**: `Ctrl+Alt+P` in a native app login (add `windows:<app>.exe` to the item's
   URLs). It types into the right window, and the TOTP popup appears and "Type it" works. A login that matches
   only by a site name in the title (a chat channel "#github-alerts") opens the quick-pick instead of typing;
   safety checks: item 36.
10. **Windows Hello unlock, Win+L auto-lock, clipboard clear after 45 s (app and extension, also right when Passyble quits), cloud-folder conflict copies.** Auto-lock: with the extension installed, keep a tab with a login form open and
    idle: the vault still locks after the timeout (page scans via `logins.find` and `status` aren't activity); a fill resets it.
    **Sliding expiry** (automated: the agent's activity tests, `hello/policy.rs` `fill_gate_grace_slides_with_use_up_to_the_setting`,
    Android `LockTimersTest`; by hand, auto-lock 1 minute): fill a login every 40 s for 3 minutes, the vault stays unlocked; stop,
    it locks about a minute after the last fill (not later). Cancel Windows Hello on a fill ("Confirm each fill"
    on) when the minute is nearly up: the vault locks right after. Leave a sign-in page open, reload it, focus its
    fields, open the extension's welcome page, run a health check, let a sync bring changes: none of it keeps the
    vault unlocked. With "Confirm each fill" on and After confirming 1 minute: fills every 40 s don't ask again;
    after a 70 s pause the next fill asks. Android (auto-lock 1 minute): fill from autofill or the passkey sheet
    every 40 s, the vault stays unlocked; only focusing login fields in an app for 2 minutes locks it; with
    "Require biometrics before each fill" and 1 minute, fills every 40 s ask once. "Ask for master password every
    N days" still asks on its day however much the vault is used.
11. **Live settings**: change auto-lock time, vault path and WebDAV account without restarting; path/account change locks.
12. **Android notification swipe**: swipe the OTP notification, it comes back silently; Dismiss removes it.
13. **Windows 11 passkey provider**: follow "Windows passkey provider" in `Core/desktop-app/README.md` (turn on in
    Passyble, restart, enable in Settings → Accounts → Passkeys → Advanced options, then webauthn.io with the
    extension disabled).
14. **Windows multi-vault**: start a build of this version on a profile from an older build. The single vault
    shows up as the first entry of "Your vaults" (named "Personal" or after its file), unlocks with the same master
    password, keeps its WebDAV sync and Windows Hello, and `settings.json.pre-vaults` holds the old file. Then:
    "Create new vault" (name it "Work") and "Add existing vault" (a second file, or WebDAV restore) both append to
    the list and open the new vault. Switch vault (the vault name at the top of the sidebar; Ctrl+L only soft-locks): the vault list comes
    back with the last used vault selected and shows each vault's location and last-opened time. Unlock the
    other vault: the extension, the auto-type hotkey and (if enabled) Windows' passkey list now show only its
    items; WebDAV sync and cloud-folder reload follow it. Turn Windows Hello on for one vault only and check the
    other still asks for its master password. Row menu: rename (also F2), "Show in folder" opens Explorer on the
    file, "Remove from list" (also Del) removes it at once with an **Undo** toast (Undo puts it back in place, with its
    WebDAV password and Windows Hello) and leaves the file on disk; removing the last vault shows
    onboarding. Restart Passyble: the list and the last used vault are remembered.
15. **Extension: strong-password suggestion + save after sign-up**: on any sign-up page (a field with
    `autocomplete="new-password"`, or a form whose button says "Create account" / "Sign up"), click or Tab
    into the password field: the Passyble menu opens on its own with **Generate strong password** first
    (masked preview, **Show** reveals it, "Very strong · 20 characters"). Pick it: password and confirmation are
    filled. Submit: **Save login to Passyble?** appears (also when the site submits with fetch and stays on the same
    URL, and when it redirects to its login page). Repeat with the desktop app quit (the password is generated in
    the browser; start Passyble before submitting) and with the vault locked (the banner's Save asks to unlock). Check
    it does **not** open on a sign-in password field, does not reopen after Esc or typing, and stays closed with
    options → "Suggest strong passwords" off (generator still behind the Passyble icon / ↓).
16. **Android: generate in autofill + save**: in Chrome and in a native app's sign-up screen, focus the new
    password field: **Generate strong password** is offered (dropdown and Gboard chip). Picking it fills password +
    confirmation with a new 20-character password. Type the e-mail/username and submit: Android shows "Save to
    Passyble?" and the login is saved with the generated password (locked vault: the unlock sheet says "Unlock to save
    the generated password for …"). On Android 11+ try a two-page sign-up (e-mail page, then password page): the
    saved login carries the e-mail from the first page (FLAG_DELAY_SAVE). Note: Android normally shows the save prompt
    only when at least one value was typed (e.g. the username), not for purely autofilled forms.
17. **Windows: Connect to Passyble Server**: run `pass-server init --public-url https://<PC IP>:8443`, `user add`,
    `pair <user> --device "This PC"`, `serve` (self-signed TLS). In Passyble: Add existing vault → From Passyble Server,
    paste the link (also try Read QR from picture…, and Read QR from clipboard with a Win+Shift+S snip of the terminal
    QR). The check shows host, account, device and "Pinned self-signed certificate"; with no vault on the server,
    create one and check `pass-server versions` after the next edit. Pair a second device: From Passyble Server on it
    downloads the vault after the master password; Settings → This vault → Use Passyble Server… on a different vault
    reports "different vault" and changes nothing. Delete `data_dir/tls/` and restart the server: sync reports
    "The server's certificate changed since this device connected…" (what to do, no raw TLS error). From the extension, `server.pair` opens the same dialog
    prefilled (unlocked: for the open vault; locked: the From Passyble Server form).
18. **Android multi-vault**: install this build over the single-vault build with a vault, WebDAV sync and
    biometrics set up. Passyble shows **Your vaults** with one entry "Personal" (location "This device · WebDAV
    <host>"); it unlocks with the same master password and the same fingerprint, and Settings → Sync still has the
    WebDAV account and last sync time. Switch vault or add one → **Add a vault** → **Use on this phone** (More
    options → name it "Work"), lock, then **Add a vault** → **Open a vault file** with a `.vault` copied from the PC
    (keep More options → "Keep using this file" on): both
    appear in the list with location and "Opened …". Unlock "Work": autofill, the Credential Manager sheet and the
    QS tile only offer Work's items; an OTP notification of the previous vault disappears on the switch. Turn
    biometrics on for one vault only: the other asks for its master password. In an autofill unlock sheet, the
    drop-down picks the vault to unlock. Row menu: Rename; Remove from list on a device-only vault needs the
    "Delete permanently" tick; a synced/file vault disappears with an **Undo** snackbar (Undo brings it back; after
    a few seconds it is gone, the server copy / file stays). Removing the last vault asks first and then shows
    onboarding. For the file vault, edit on the PC (Syncthing/cloud folder) and then on the phone: the phone
    merges the external change before writing (both edits survive).
19. **Android import**: Settings → Import from another app. (a) Export file: a Bitwarden JSON, a Chrome CSV, an Aegis
    JSON. The preview shows the format, "N new · M merged · K already in the vault", warnings, "Can't import" with
    reasons and one row per entry (New / Merge "Adds 2FA to …" / Separate / Already there). Import, then the
    vault list has the items, and the red card offers **Delete <file>** (Downloads / local storage; asks first).
    Importing the same file again shows everything as "Already there". (b) Scan QR codes (Google Authenticator):
    export 3+ accounts so the export spans several QR codes, scan each (counter goes up, haptic tick; a random QR
    shows "isn't a Google Authenticator export"), Done → preview → Import; codes match Google Authenticator.
    Scanning only some of the codes shows the core's "only part of the export" warning. (c) Paste
    `otpauth://totp/…` lines; after import "Clear clipboard" works. Lock the vault while the preview is open: the
    preview is dropped.
20. **Android: Connect to Passyble Server**: with the server from item 17, `pass-server pair <user> --device "Pixel"`.
    Lock screen → Add a vault → More options → **Use a Passyble Server pairing link** → **Scan QR code** on
    the terminal QR (or Paste link): the card
    shows server, account, device "Pixel", "Pinned sha256:…" and "Connected. The server has a vault here." →
    master password → Download vault. Edit on the phone and on the PC: both sync. In another vault: Settings →
    Sync → Connect to Passyble Server with a fresh pairing for an empty server vault → **Upload this vault**
    (`pass-server versions` shows it); with the first vault's link → "Sync this vault with it" fails with "different
    master password or another vault" and nothing is saved, "Add as a separate vault" downloads it and switches to
    it. Replace the server's certificate (delete `data_dir/tls/`, restart): Settings → Sync → Sync now says the
    certificate doesn't match the pairing link; "Pair again with a new link" fixes it. A link with `scheme=http`
    shows the unencrypted-HTTP warning.
21. **Extension: Add Passyble Server**: with the server from item 17, `pass-server pair <user> --device "Browser PC"`.
    Popup → server icon in the header (or Options → Passyble Server): paste the link (also try dragging the terminal
    line onto the form). The preview shows server, account, device "Browser PC", "Self-signed, verified
    by this link" and "Sign-in key: Included (hidden)"; a `v=2` or `https://` link shows why it is refused (in plain words,
    no parameter names) and can't be sent.
    **Send to Passyble**: the field clears, the popup says "Check the Passyble window to finish connecting", and the desktop
    app shows "Connect to Passyble Server" prefilled (unlocked: for the open vault; locked: the From Passyble Server form);
    confirm there and check sync works. Quit Passyble and send again: Passyble starts in the background and shows the dialog;
    with the native host unregistered it says "Pass isn't running. Install and start…". With an
    older desktop build: "Update Pass". Check the token isn't in `chrome://extensions` → service worker console, nor
    in the extension's storage (DevTools → Application → Extension storage). Remove `&token=…` from a link and paste
    it: the preview says "Invite: you'll sign in in the Passyble app" (no token row), and after sending the desktop app
    asks for the account's password.
22. **Android biometric autofill and unlock policy**: on a phone with a fingerprint, Settings → Unlock → turn on
    Biometric unlock (one prompt). Lock the vault, focus a login field in Chrome and in a native app: the dropdown
    and the Gboard chip read "Unlock with fingerprint" (no titles/usernames while locked); tapping it opens the
    fingerprint prompt at once, and after it the logins are offered. "Use master password" puts the cursor in the
    password field. Same with no extra tap for: opening Passyble, the Credential Manager sheet ("Unlock Passyble with
    fingerprint"), the QS tile picker and the locked save sheet. Turn the screen off and on (auto-lock): the next
    fill unlocks with one fingerprint. **Policy**: set "Ask for the master password" to Every day and move the phone's
    date 2 days ahead (or set it to "After the phone restarts" and reboot): the lock screen and the autofill sheet
    say why and offer only the password; after entering it, the fingerprint works again. Setting the date back before
    the last password entry also asks for the password. Updating from an older build asks for the master password
    once. Enroll another fingerprint: the next unlock says biometric unlock was reset, the password works, and
    Settings says why it's off. **Each fill**: More security options → turn on "Confirm each fill" (After confirming: Every time).
    While unlocked, picking a login (dropdown or chip) asks for the fingerprint before filling; OTP suggestions
    don't show the code in their label; a Credential Manager password asks too (on Android 15 the system shows the
    prompt as you tap the entry and Passyble doesn't prompt again); the OTP notification says "Code hidden" and Copy
    asks before copying. Unlocking from a locked field then picking a login prompts only once. With "Not again for
    1 minute" a second fill within the minute doesn't ask. **Passkeys on Android 15**: tapping a passkey entry shows
    the system fingerprint prompt and signs in without a second Passyble prompt. **No strong biometric** (remove the
    fingerprints, face unlock only or PIN only, Android 11+): Settings → Biometric unlock says "Face unlock is too
    weak" and its (i) explains why; turn on "Allow screen lock" (More security options), then Biometric unlock: the prompt asks for the PIN and unlocks the
    vault. On Android 9 and 10 "Allow screen lock" isn't shown.
23. **Windows Hello bound to a Hello key (desktop)**: with a profile from an older build that has Hello on,
    start this build and unlock with Hello: one or two extra Hello prompts (key creation, signature check) and
    `%LOCALAPPDATA%\Pass\hello\<id>.bin` now has `"version":2,"mode":"key_credential"` and a `challenge`;
    Settings → Unlock → Windows Hello says "On · key bound to this PC". Lock (Ctrl+L): the main
    window starts Hello by itself; cancel it: the password form shows with "Unlock with Windows Hello" still
    offered. With Passyble locked and in the tray: (a) extension inline menu → fill a login: the small "Unlock …"
    window comes to the front with Windows' Hello dialog over it (check it is in front, not behind the browser,
    centered on the "Unlock …" window, with no separate "Windows Security" button on the taskbar, and that the PIN
    field has the cursor / the camera or fingerprint reader is active without clicking); after Hello the login is
    filled, no master password typed. Repeat from the hotkey (Notepad in front), the TOTP popup, the passkey provider
    and the main window's own unlock: same, the dialog is owned by the window that asked. Esc on the "Confirm it's
    you" prompt (per-fill check) while no dialog is up gives up the fill. If the dialog doesn't show within 2 s the
    prompt says "Windows Hello didn't open" with **Use Windows Hello** / **Use master password instead** / Cancel
    (`%LOCALAPPDATA%\Pass\logs\pass.log`: "Windows Hello: NotShown after 2 s"). Automated part (shows a real
    dialog and cancels it; no `Pass-*` key is touched): build `hellofocus` or any exe that opens a window of class
    `PassybleFocusTestBlocker` when started with `blocker`, then `set HELLO_FOCUS_BLOCKER=<exe>` and
    `set HELLO_FOCUS_KIND=verify` (or `create`, throwaway key `PassybleFocusTest`, deleted afterwards), and
    `cargo test -p pass-desktop -- --ignored --nocapture hello_dialog_comes_to_front`: it prints "owned by our
    window true, own taskbar button false, foreground is the dialog true". (b) Cancel Hello: **Try again** works; **Use master
    password instead** opens the main window's password form and the fill continues after it. (c) `Ctrl+Alt+P` in
    a native app and the quick-pick: same Hello prompt, then it types. (d) With the Windows passkey provider on,
    sign in on webauthn.io while locked: one Hello prompt only (unlock), not two. Settings → Unlock →
    "Ask for the master password: Every day", then set the clock 2 days ahead (or edit `password_unlock_ms` in the
    `.bin` to an old value): Hello isn't offered, the unlock screen says the master password is due; after one
    password unlock Hello works again. "After each start of Pass": quit and restart Passyble, Hello needs the password
    once. Turn on **Require Windows Hello before each fill** with "Every time": each extension fill and each
    auto-type asks ("Confirm it's you" prompt), the 2FA code on the next page of a just-filled login doesn't; with
    "Not again for 1 minute" a second fill within the minute doesn't ask; a fill right after a Hello unlock asks
    only once. Reset Windows Hello (Settings → Accounts → Sign-in options → PIN → "I forgot my PIN", or remove the
    PIN and add it again): the next Hello unlock says Windows Hello changed and opens the password form; after the
    password unlock Hello is set up again (new key). Turn Hello off: the `.bin` is deleted (and the `Pass-<id>` key;
    `certutil -csp "Microsoft Passport Key Storage Provider" -key` lists the remaining ones). On a PC without
    Hello keys the card reports the DPAPI-only fallback.
24. **Sync only when needed (desktop, Android, Passyble Server)**: run `pass-server` with `RUST_LOG=pass_server=debug`
    and a synced vault on the PC and the phone. Leave both unlocked and idle: the server log shows at most an
    occasional `304: not modified` line (desktop: one per 30 min while you use Passyble, plus one when a Passyble window
    gets focus after 5 min; Android: on unlock, on opening the app at most every 5 min), never `vault stored`.
    Settings → Sync (desktop) says "Synced … ago". Edit a login on the PC: Settings shows "Changes pending",
    about 10 s later one `vault stored` line and back to "Synced just now". Edit on the phone, bring Passyble on the PC to
    the front: the change appears (one download). Restart Passyble and unlock: one `304`, no upload. Stop the
    server and edit: the status shows the failure and Passyble retries at growing intervals (30 s, 1 min, 2 min, …),
    not every 5 s; start the server: "Sync now" or the next retry uploads. Lock the vault: no requests at all
    while locked.
25. **Passyble Server accounts: sign in with a password (desktop)**: `pass-server init --public-url https://<PC IP>:8443`,
    `pass-server user add alice --email alice@example.com --initial-password` (type `temporary1` twice), `pass-server invite alice`,
    `pass-server serve`. `pass-server user list` shows `password: must change`; `state.json` doesn't contain
    `temporary1`. In Passyble (first start, or the vault list's **Sign in to Passyble Server**): paste the invite link
    (also try the Read the QR code buttons, from a picture / the clipboard): server and user fill in and "Pinned self-signed certificate" shows;
    a wrong password says "Wrong user name, e-mail or password. Check Caps Lock…" (and after 10 tries: "Too many
    attempts. Wait 15 minutes…").
    Password `temporary1` → **Choose your password** (too short / mismatch are refused) → `only alice knows` → the
    vault opens, empty, listed as `alice@<IP>` with no file dialog; `%LOCALAPPDATA%\Pass\vaults\<uuid>.vault`
    exists, `pass-server versions alice/personal` shows the upload. On a second Windows profile or PC: sign in with
    `only alice knows` → the vault downloads and opens directly (no "choose" step). While the first PC had only
    signed in with `temporary1` (before choosing), `curl -u alice:<token> .../dav/alice/personal.vault` gives 403.
    **Change password** (Settings → This vault): wrong current password is refused and nothing changes; with the
    right one, lock the other PC's vault and unlock it with the new password (it downloads the server copy), the
    old password fails. **Reset**: `pass-server user reset-password alice` (`temporary2`); sign in on a third
    profile with `temporary2` → choose `alice again` → "Unlock your vault" asks for the previous password; a wrong
    one says so, `only alice knows` opens it, and a fourth sign-in with `alice again` opens it directly. On a PC
    that still had the vault unlocked during the reset: Change password → **Changed on another device?** with
    `alice again` re-wraps it (a wrong password: "That isn't your Passyble Server password"). `pass-server user add bob
    --no-force-change` fails with "--no-force-change is no longer supported: a password you set for someone must
    always be replaced at their first sign-in…" and creates nothing (the app's vault-key rotation for an
    admin-known password only applies to accounts an older server made that way). Admins never get a password from
    the server: `pass-server user add boss --admin --password-stdin` is refused, `pass-server user add boss --admin`
    prints a one-time setup link, and `pass-server user reset-password boss` is refused with a pointer to
    `pass-server user reset boss`; `PASS_ADMIN_PASSWORD=x pass-server setup` fails with "PASS_ADMIN_PASSWORD
    environment variable is no longer supported…" before writing anything. Extension: send the invite link (`server.pair`): Passyble opens Sign in to Passyble Server prefilled.
    `user add carol < /dev/null` (no terminal) fails with a hint instead of hanging; `--no-password` creates a
    pairing-only account (`pair` as before).
26. **Android: sign in to Passyble Server**: with the server and accounts from item 25 (`alice` with a fresh
    `user add`, password `temporary1`). (a) Fresh install: the welcome screen's **Sign in to Passyble Server** → the scan
    icon in "Server address or invite link" on the `pass-server invite alice` QR: server, user and "Pinned
    self-signed certificate" fill in; the device name (More options) defaults to the phone model. Wrong password: "Wrong user name or password". `temporary1` → **Choose
    your password** (strength hint; < 8 characters or a mismatch refused) → the vault opens, listed as
    `alice@<IP>`, no file picker; `pass-server versions alice/personal` shows the upload and `pass-server` lists the
    device by the phone's model. Turn on biometric unlock, lock, unlock with the fingerprint (same policy as other
    vaults: "Ask for the master password" still applies). (b) Open the invite link from a browser or e-mail app
    (e.g. `adb shell am start -a android.intent.action.VIEW -d '<pass+server://… link>'`, quote it): Passyble opens the
    sign-in form prefilled, also while a vault is unlocked; a `pass+server://` pairing link (with `token=`) opens the
    pairing flow instead (Settings' Connect to Passyble Server when unlocked, Add a vault → pairing link when locked).
    (c) Settings → This vault: "Passyble Server account" shows "alice · <phone model>". **Change password**: a wrong current
    password is refused and nothing changes; with the right one, the PC's copy then unlocks only with the new
    password (it downloads the server's copy). With the PC's vault unlocked during the change, use **Changed on
    another device?** there. On the phone: change the password on the PC, then lock the phone and unlock with the
    new password: it downloads the server's copy and opens it; unsynced phone edits survive. (d) **Signed out**:
    `pass-server revoke <the phone's device id>`; the next sync (unlock, or Sync now) marks the vault **Signed out:
    sign in again** on the lock screen (row and button), in a banner on the item list and in Settings; the vault
    still unlocks offline and autofill works, and no sync retries hit the server. **Sign in again** (prefilled) with
    the current password: the same entry syncs again (no second vault in the list). **Admin reset**:
    `pass-server user reset-password alice` (`temporary2`; this signs out all of alice's devices, which sign in again). Remove the vault from the
    phone's list (or use a second phone) and sign in with `temporary2` → choose a new password → "Unlock your vault"
    asks for the previous password (a wrong one says so); the right one re-encrypts and uploads it. Repeat with the
    vault still in the list with biometrics on: the fingerprint prompt appears at once and replaces the previous
    password. (e) If the Core/core/server issue one-time codes
    (`invite=` / `reset=` links): an invite link goes straight to **Choose your password** and creates and uploads
    the vault; a reset link to **Choose a new password**: with the vault unlocked on the phone it is re-encrypted
    without the old password; locked with biometrics on, the fingerprint opens it; else the previous password;
    **Start a new empty vault…** needs the "I understand" tick, replaces the server's vault (the old one becomes a
    version) and keeps the phone's old copy as "<name> (before reset)" without sync. Opening the same link again says it was
    already used. Check `adb logcat` never shows a token, a code or a password.
27. **Passyble Server e-mail: invites, resets, URL scheme (server + Windows)**: add to the item 25 config an
    `[email]` section for a real mailbox (e.g. Gmail with an app password, Server/README.md) or a local sink
    (`python -m aiosmtpd -n -l 127.0.0.1:1025`, then `smtp_host = "127.0.0.1"`, `smtp_port = 1025`,
    `security = "none"`), restart `serve`. (a) `pass-server email test you@example.com` arrives (text and
    HTML); a wrong password or host gives a clear error; `security = "none"` with a remote host is refused at
    start. (b) **Invite**: `pass-server user add dave --email you@example.com` prints both links and a QR code
    and the e-mail arrives; `user list` says `none (invite pending)`; `state.json` has no `psc_` code. Open the
    e-mailed https link in a browser (accept the self-signed warning, or use `email.public_url`): the page shows
    dave, the expiry, **Open in Passyble**, a QR code and the link as text; DevTools shows no script, the CSP and
    `Referrer-Policy: no-referrer`; reloading doesn't use the code. **Open in Passyble** (installed build, or a
    debug run, which registers the scheme itself): Passyble comes to the front (also when it was closed or only in
    the tray) with **Choose your password** for dave@host → set it → the vault is created and uploaded. The same
    link again: "expired or was already used"; its page now says so too. `user invite dave` refuses (has a
    password); `user add erin --invite` only prints. (c) **Reset with the vault unlocked**: with dave's vault
    open, click a reset link (`pass-server user reset dave --email`): a dialog opens over the vault (not
    locked) → new password → "Password reset. Your vault now uses the new password"; lock and unlock with the
    new password; `pass-server devices dave` lists only the new device (the old token was revoked) and other
    PCs show a sign-in error on sync. (d) **Reset with Windows Hello**: dave's vault locked, Hello on →
    **Unlock with Windows Hello** → re-encrypted, items intact. (e) **Previous password**: on a second Windows
    profile without the vault, "Forgot password?" on the sign-in form (server + `dave` or the address) →
    "Check your e-mail"; an unknown user gives the same answer and no e-mail; the 4th request within an hour
    sends nothing; open the link → new password → "Unlock your vault" → the previous password re-encrypts it.
    (f) **Start a new empty vault…** from that screen needs the tick, replaces the server's vault
    (`pass-server versions dave/personal` lists the old one), and a local copy of the old vault stays as
    "<name> (before reset)" without sync. (g) Notifications: "password was changed" after each reset; with
    `notify_new_device = true`, "New sign-in" with the device name. A server without `[email]`: Forgot
    password? says to ask the admin. Server logs never contain a `psc_` code.
28. **Android: easier to use**: (a) Fresh install: two big choices, **Use on this phone** and **Sign in to Passyble
    Server**, plus **Open a vault file**; WebDAV and pairing links under More options. Use on this phone: the cursor
    is in the password field with the keyboard up, Next → Repeat it → Done creates the vault; no name needed
    ("Personal"). The item list offers **Unlock with your fingerprint next time?** → Turn on (one prompt) → lock →
    the fingerprint prompt comes up by itself; Settings → Unlock → "Ask for master password" says every 30
    days. On a second vault, **Not now** hides the card for good (Settings still has the switch). With one vault,
    the lock screen is only the unlock form and "Switch vault or add one". (b) Sign in: type ` HTTPS://<IP>:8443// `
    (spaces, slashes) with a server that has its own self-signed certificate and no link: **Trust this server?**
    shows the host and a fingerprint like `Xk3v 9QpL aZ0r …`; compare with the pin `pass-server status` prints
    (the same characters after `sha256:`) → Trust → the sign-in goes on and "You trusted the certificate of …" shows; Cancel connects
    nothing. Paste an invite link into the same field: it fills in server and user and shows only the address.
    Sign in with the account's e-mail address if the server accepts it. Next time the sign-in form starts with the
    last server and user name, cursor in the password. (c) Errors in plain words: a typo in the host ("Can't find
    that server…"), the wrong port ("Can't reach the server…"), a wrong master password ("Wrong master password.
    Check Caps Lock…"), a broken link ("That link is incomplete…"). (d) Delete an item: no question, back on the list
    **Deleted · Undo** → Undo brings it back (also on the PC after sync). (e) Airplane mode, edit, Sync now: the list
    shows "Not synced: … · Retry" (no dialog); back online, Retry clears it. (f) Share a Bitwarden CSV / 1Password
    `.1pux` / a screenshot of a Google Authenticator export QR from Files or Photos to Passyble: locked → "Unlock to
    import <file>" → unlock → the Import preview opens; nothing is imported before Import. A screenshot without a
    QR code says so. "Open with" on a CSV in Files works the same; images are not offered there. (g) Settings:
    "Allow screen lock" and "Confirm each fill" are on the More security options page; "Finish setting up Pass" on
    the list has Not now. See also item 38.
29. **Windows: easier to use (desktop)**: (a) Fresh profile (rename `%APPDATA%\Pass`): the welcome screen has two
    big choices, **Use on this PC** and **Sign in to Passyble Server**, plus **Open an existing vault file**; WebDAV and
    pairing links are under More options. Use on this PC: the cursor is in the master password, Tab → Repeat →
    Enter creates the vault (name and location under More options; default "Personal" in `%APPDATA%\Pass`). Both
    password fields have an eye toggle and say "Caps Lock is on" when it is. (b) Right after that (and after any
    master-password unlock of a vault without Windows Hello) the item list shows **Unlock with Windows Hello next
    time?** → **Turn on**: exactly one Windows Hello prompt (plus Windows' own prompt if the vault's Hello key is
    created for the first time), then "Windows Hello is on"; Lock completely (Ctrl+Shift+L), close the window and
    open it from the tray: Hello starts by itself (never right after the lock itself, item 78). **Not now** on
    another vault hides the card for good (Settings still has the switch). Settings → Unlock: "Ask for
    the master password" says Every 30 days on new vaults and on vaults that had the old 14-day default
    (`settings.json` gets `"defaults_version": 1`; an explicit 14 days chosen afterwards stays). (c) With one vault,
    the locked window is just its unlock form with **Switch vault or add another** (which opens the list). (d) Sign
    in: type ` HTTPS://<IP>:8443// ` (spaces, slashes) for a server with a self-signed certificate and no invite
    link: **Trust this server?** shows the host and the fingerprint in groups of four; compare with the pin
    `pass-server status` prints (the same characters after `sha256:`) → **Trust this server** → the sign-in goes on;
    Cancel signs in to nothing. Sign in with the account's e-mail address if the server accepts it. Next time the
    form starts with the last server and user (cursor in the password) and doesn't ask to trust again. Paste an
    invite link into the same Server field: server and user fill in; a pairing link opens Connect to Passyble Server.
    From the browser extension, Add Passyble Server with a plain address (`pass.example.com:8443/`) opens the same
    form (in a dialog over an unlocked vault, nothing locked until it's done). (e) Errors in plain words: a typo in
    the host ("Can't reach <host>. Check the address…"), a wrong master password ("Wrong master password. Check
    Caps Lock…"), replace the server certificate after trusting it ("The server's certificate changed…").
    (f) Delete an item: no question; the toast **Deleted "<title>" · Undo** brings it back (also on the other
    devices after sync); locking forgets what can be undone. (g) Stop the server and edit: a quiet **Sync paused ·
    Retry** pill appears next to the vault name (tooltip with the reason), never a dialog; start the server and
    click it: the pill goes away. (h) Drag a Bitwarden JSON / Chrome CSV from Explorer anywhere onto the unlocked
    window: "Drop to import into Pass" shows while dragging, then the Import preview; nothing is imported before
    Import. Dropped while locked: "Unlock a vault first…". (i) Icons: the sidebar's Import / Settings / Lock and
    all other icons are thin Lucide outline icons, with tooltips that include the shortcut ("Lock (Ctrl+L)"), in
    light and dark mode; the window, taskbar and tray show the new shield-and-keyhole logo (rebuild needed).
30. **Extension: easier to use**: (a) Quit Passyble, open the popup: "Pass isn't running" with **Start Passyble**. Click
    it: "Starting Passyble…", Passyble starts in the background (≤ ~10 s), and the popup shows the locked or unlocked
    state. With Pass.exe renamed or missing: after the wait, "Open Passyble from the Start menu. If it's already open,
    open Passyble → Settings → Browser to check the connection." (b) Remove the native host registration
    (registry key or manifest) and reload the extension: the popup says the browser can't reach Passyble and to open
    Passyble → Settings → Browser to register it, with **Try again** and no Start Passyble; Options → Check
    connection shows the same text. (c) Popup → server icon → type `pass.example.com:8443/` → Enter: the desktop
    app opens "Sign in to Passyble Server" with that address, and the popup says "Pass opened the sign-in window.
    Finish there." Also try `https://host/prefix/`, `http://192.168.x.y:8080`, `Server: https://host/` pasted from
    a mail, `alice@example.com` (e-mail hint, nothing sent) and `host/?x` (refused). Paste
    `Link: <pass+server://…>.` from an invite mail: the link is picked out and sent unchanged. With an older
    desktop build, an address gives "Update the Passyble desktop app to add a server by address, or paste the
    pass+server:// link instead." (d) Icons: the popup, options page, inline menu, OTP toast, notice and save
    banner use thin outline icons with hover backgrounds and tooltips, in light and dark mode.
31. **Android: Google Drive backup and restore** (docs/GOOGLE_DRIVE.md): set up a Google Cloud project with the
    Drive API, the `drive.appdata` scope, your account as a test user and an Android OAuth client for
    `com.sensyble.passyble` + the debug keystore SHA-1. Build with `-PpassGoogleDrive=true`. (a) Without the property,
    or on an emulator image without Play services, no Google options appear anywhere. (b) Fresh install → **Use on
    this phone** → switch on **Back up to Google Drive** → master password twice → **Sign in with Google and
    create**: Google's account picker and consent sheet ("See, create, and delete its own configuration data in
    your Google Drive"), then the vault opens. Settings → Sync shows Google Drive with your account
    ((i) has the zero-knowledge note) and "Synced … ago". Drive web → Settings → Manage apps → Passyble shows hidden app data
    of a few KB. (c) Add an item: about 10 s later the "Synced …" row updates (one metadata request and one upload).
    (d) Second phone (or clear data): **Restore from Google Drive** → sign in → the vault is listed by name, date
    and size → master password → the items are there. A wrong master password gives "Wrong master password".
    Edit on both phones and **Sync now** on each: both edits are on both. (e) Rename the vault on one phone and
    sync: the restore list on another device shows the new name. (f) In Google Account → Security → Third-party
    access, remove Passyble. Edit and wait: the status says "Sign in to Google again to keep backing up this vault"
    with no retry loop and no notifications. Settings → Sync: the status row's **Sign in** → consent → synced.
    (g) **Turn off backup** with "Also delete the copy on Google Drive": Manage apps shows no Passyble data (or 0 bytes); the
    vault stays on the phone. (h) A vault on Passyble Server has no Google option in Settings → Sync. (i) Airplane
    mode: "Can't reach …" in the quiet status line; it syncs on reconnect. Windows: step 32.
32. **Windows: Google Drive backup and restore** (docs/GOOGLE_DRIVE.md): in the same Google Cloud project add a
    *Desktop app* OAuth client and build with `PASS_GOOGLE_CLIENT_ID` / `PASS_GOOGLE_CLIENT_SECRET` set (or
    `Core/desktop-app/src-tauri/google-oauth.env`). (a) Built without them: no Google option anywhere (welcome screen,
    Add existing vault, Settings → Sync). (b) Fresh profile → **Use on this PC** → master password twice
    → switch on **Back up to Google Drive** (the zero-knowledge note appears, the button says **Sign in with Google
    and create**) → the default browser opens Google's account picker and consent ("See, create, and delete its own
    configuration data in your Google Drive"); Passyble shows "Finish signing in with Google in your browser" with
    **Cancel**. After consent the tab says "You can close this tab and return to Pass", Passyble comes to the front and
    the vault opens. Settings → Sync shows "Google Drive · <you>". Credential Manager (Windows
    Credentials → Generic) has `Pass/GoogleDrive/<you>`; `settings.json` has only `google_drive.account_email`, no
    token. (c) Start again and press **Cancel** while the browser waits: nothing is created and the form is usable
    again; deny on the consent screen: "Google sign-in was cancelled in the browser…"; untick the Drive permission:
    "Pass needs permission to use its own folder…". (d) Add an item: ~10 s later Settings → Sync shows
    "Synced just now". (e) The Android phone from step 31 (same account): **Restore from Google Drive** lists this vault; edits
    on both sides meet after **Sync now**. On a second Windows profile or PC: **Restore from Google Drive** → sign
    in → list (name, date, size) → master password (a wrong one: "Wrong master password…", nothing written) → the
    vault opens from `%LOCALAPPDATA%\Pass\vaults\<id>.vault`; the vault list says "Google Drive · <you>".
    (f) An existing local vault (or one on plain WebDAV) → Settings → **Back up to Google Drive…** → signed in →
    "Backed up to Google Drive"; the WebDAV fields are gone and its Credential Manager entry deleted. A Passyble Server
    vault doesn't offer it. (g) Google Account → Security → Third-party access → remove Passyble; edit and wait: the
    vault view shows a quiet **Sign in to Google again** pill, no retry loop. Click it → browser (account
    preselected) → synced, the pill is gone. Also after a restart of Passyble (the flag is in `settings.json`).
    (h) **Turn off** with "Also delete the copy on Google Drive": Drive → Manage apps shows no Passyble data, the
    credential is gone and Passyble's access is removed from the Google Account; the vault stays on this PC.
    (i) Disconnect the network: "Can't reach …" in the pill tooltip, retries back off; it syncs on reconnect.
33. **Windows: installer, updates, log, shorter Settings**. Verified so far: the NSIS installer
    builds (`cargo tauri build --config tauri.bundle.conf.json`, 4.5 MB; also signed with the updater key through
    `tauri.release.conf.json`, which writes the `.sig`), and a silent per-user install / uninstall (`/S`) on a
    dev PC: files in `%LOCALAPPDATA%\Programs\Pass` (Pass.exe, pass-native-host.exe, uninstall.exe), Start menu and
    desktop shortcut, Apps entry, `pass+server` URL scheme; the uninstaller removed all of them and left
    `%LOCALAPPDATA%\Pass` (hello, vaults) alone. The installed app was not started. Still to check:
    (a) Interactive install: no admin prompt, the folder page shows `…\AppData\Local\Programs\Passyble`, the finish
    page starts Passyble; no console window appears (also for `target\debug\Pass.exe`). Passyble registers the browsers
    from the install folder: Settings → Autofill → Browser extension shows Chrome / Edge / Firefox green; the extension connects.
    (b) Settings: every section has short labels with an icon; hover or Tab to each (i): the bubble is readable in
    light and dark and doesn't toggle the switch next to it. Everything still saves (vault name, Move… / Locate…,
    Windows Hello and its policy, auto-lock, Google Drive / Passyble Server / WebDAV, hotkey, Windows passkeys, extra
    extension IDs). **Start with Windows** on → `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` has `Pass` =
    `"…\Pass.exe" --background`; sign out and in: Passyble is in the tray. Off removes the value.
    (c) Settings → About → Log file → **Open folder** opens Explorer on `%LOCALAPPDATA%\Pass\logs`; `pass.log` has a
    "Passyble <version> started" line per start and no secrets; it rotates to `pass.old.log` past 512 KB.
    (d) Updates, with a local manifest: install N, serve N+1
    signed + `latest.json`, set `update_endpoints`. Within ~1 minute of starting Passyble a dot appears on the Settings
    button (tooltip "version … is ready to install"), no dialog, and an unlocked vault stays as it is. Settings →
    About, under the version: "Version N+1 available", **What's new** (GitHub endpoints only), **Update and restart**: a
    progress bar, then the installer's small progress window (no questions), and Passyble N+1 starts with its window
    open; the vault was saved and locked. Tamper with the `.sig` (or sign with another key): "The download didn't
    have Passyble's signature, so it wasn't installed." Offline: "Can't reach the update server…" and the next
    automatic try is an hour later. **Check for updates automatically** off: no dot after restart; **Check now**
    still works. While the browser holds `pass-native-host.exe` (extension connected), the update closes it and the
    extension reconnects on its next request.
    (e) Uninstall from Settings → Apps: Passyble, shortcuts, the URL scheme, the `Run` value and the three
    `NativeMessagingHosts\com.sensyble.pass` keys (when they point at the installed copy) are gone; vaults, settings
    and Windows Hello data stay. Again with **Delete the application data** ticked: `settings.json`, `logs` and
    `hello` go, `*.vault` files (also `%LOCALAPPDATA%\Pass\vaults`) stay.
    (f) GitHub: create `sensyble/pass-releases` (public, with a README), set up the release PC, tag `v0.1.1` and publish the installer, `.sig` and `latest.json` by hand; an installed 0.1.0 finds it. Without
    a code-signing certificate the downloaded installer shows SmartScreen's "Windows protected your PC" (More info → Run
    anyway); updates through the app don't.
    (g) Linux (Linux/README.md "Updates"), with a `latest.json` built by `scripts/release-feed.mjs` that has the
    `windows-x86_64` and `linux-x86_64` entries: the AppImage N, started from a folder the user can write, finds N+1,
    **Update and restart** replaces the `.AppImage` file (same name and mode) and N+1 starts. The `.deb` (and `.rpm`)
    N shows "Version N+1 available. Get the new version from the download page." with **Download page** (opens
    https://www.passyble.com/download) and never asks for a password or installs anything. With the App versions
    minimum for `linux` above N, **Update** on "Update required" installs for the AppImage and opens the download page
    for the `.deb`. macOS: macOS/TESTING.md §10.
34. **Android: autofill trust (which apps may name a website)**: Passyble fills a website's logins only for browsers it
    knows (allowlisted package **and** signing certificate), or compatibility-mode browsers listed in
    `res/xml/autofill_service.xml`; any other app is matched by its own package + certificate. Add a login for
    `https://example.com` (and one for a native app's package). (a) **Chrome**, native autofill: focus the login
    field on example.com: dropdown and Gboard chip offer the login. Chrome must use native autofill: Chrome → Settings → Autofill services → "Autofill using another service"
    (Chrome 135+), and `adb shell dumpsys autofill` shows `COMPAT_MODE=0` for the Chrome session (it is not in the
    compatibility list). Same for **Brave** and **Vivaldi** (their Autofill services setting) and for **Samsung
    Internet**; a Brave session with `COMPAT_MODE=1` / `NUM_DATASETS=-1` means a package crept back into the list. (b) **Firefox**
    and **Samsung Internet**: the login is offered on example.com if the browser is allowlisted or in the
    compatibility list (check which list each is on; a browser on neither gets no website logins). (c) **WebView
    app**: an app that shows example.com in its own WebView (any test app, or a mail app's in-app browser): the
    website login is **not** offered, only logins whose Android app entry matches that app's package and cert;
    saving from it creates an item for the app, not for example.com. (d) **Cross-origin iframe**: a test page on
    example.com with an `<iframe src="https://other.example.net/login">` containing a login form: in Chrome, the
    iframe's fields get no example.com login (and `other.example.net`'s logins only if one exists for it), the
    main page's fields are still filled. (e) Passkey and password entries in the Credential Manager sheet follow
    the same rule: an unresolved caller or a foreign RP ID gets no entries.
35. **Android: unlock and sign-in against a server vault replaced after a reset**: with the Passyble Server setup of
    item 26, have an Android vault `alice@<IP>` synced. On the server, replace alice's vault with a new one
    (`pass-server user reset-password alice`, then on a PC sign in and **Start a new empty vault…**, so the
    vault id differs). On the phone, unlock the old vault (and run Sync now): the local vault is **not** overwritten
    by the server's; the unlock says the password belongs to the vault now on Passyble Server, which isn't this vault
    any more, and the phone's items are still there. Sign in again with the new password: the old vault stays in
    the list as "<name> (before reset)" without sync, and the server's new vault is added and opens; its items
    are the new vault's. Repeat with biometrics on for the old vault. Cancel the sign-in half way: nothing local
    is replaced.
36. **Windows: save failures, auto-type safety, pipe check, passkey UV**. (a) **Save while OneDrive / Dropbox locks
    the file**: put the vault in a OneDrive or Dropbox folder, unlocked. Make the file unwritable (a second
    process holding it open exclusively, e.g. a PowerShell `[IO.File]::Open(path,'Open','Read','None')`), edit a
    login in Passyble: the save fails (error in `pass.log`) and the edit stays in the open vault; release the file and edit again
    (or wait): the earlier edit is saved too. Repeat but lock Passyble (Ctrl+L) while the file is still held: the vault
    locks, `<vault>-unsaved-<ms>.vault` appears beside it; release the file, unlock: both the edit and the file's
    contents are there, the unsaved copy is gone. Same on auto-lock, Switch vault and quit. (b) **Auto-type**:
    `Ctrl+Alt+P` on a login window, then switch to another window while it types (click another app, or Alt+Tab):
    typing stops with "another window took the focus", nothing continues into the other app. In a browser with
    two tabs, press the hotkey on tab A, let the quick-pick or Hello prompt appear, switch tab: "that window
    changed", nothing typed. Run a test app **as administrator** (Notepad via "Run as administrator" with a login
    entry `windows:notepad.exe`): auto-type refuses with the toast (typing stops because Windows refuses input from
    Passyble), no password is typed. A title match that only mentions a site name opens the quick-pick. (c) **Native
    host and pipe**: quit Passyble, then from another user session or a script create `\.\pipe\pass-agent-<user>`
    first and serve it (a small PowerShell `NamedPipeServerStream`): open the extension popup: the host does not
    send anything to it (the popup says Passyble isn't running / unavailable) and the fake pipe receives no
    request; no passwords reach it when you save a login. Start the real Passyble: the host connects again. A copy of
    `pass-native-host.exe` run from another folder, with a real Passyble running, is also refused. (d) **Passkey UV
    flag**: on webauthn.io, run the registration and authentication with *User verification: required* (and then
    *discouraged*). Settings → Unlock → More security options → "Confirm each fill" **on**: each ceremony shows a
    Windows Hello prompt and succeeds, the debugger on webauthn.io shows flags with `UV` set. With it **off** and
    the vault already unlocked: *required* fails (the response only has user presence, `UP`) while *preferred*
    / *discouraged* succeed; if the request itself had to unlock the vault (locked Passyble, unlock with password or
    Hello), UV is set. A consent click alone never sets UV. (e) A non-web origin: a `file://` page or a
    `data:` URL calling `navigator.credentials` falls to the browser (no Passyble dialog).
37. **Extension: sandboxed iframes and origin hints**: host a test page that embeds
    `<iframe sandbox="allow-scripts allow-forms" srcdoc=...>` and another iframe of a site you have a passkey for
    served with `Content-Security-Policy: sandbox allow-scripts` (any local server). (a) A passkey request
    (`navigator.credentials.get` with a valid RP ID) from the sandboxed document falls back to the browser
    (the browser's own error or dialog), Passyble shows no consent dialog or chooser, and the Passyble inline menu doesn't
    appear on its login fields; the agent log has no request for it. (b) The same page in a normal frame: Passyble
    handles it. (c) A same-origin iframe nested in a cross-origin one (A > B > A): the passkey request falls to the
    browser too (the extension reports a cross-origin ancestor). (d) With Passyble running, use a site whose
    RP rejects ES256 (`pubKeyCredParams` with only RS256): the agent answers `not_supported` and the browser's
    WebAuthn dialog appears instead of an error.
38. **Android: shorter Settings and screens** (Galaxy S25 Ultra or any phone, light and dark theme). (a) Settings
    shows the groups This vault · Unlock · Autofill · Sync · Import · About; every row has an icon and a one-line
    title, with a second line only for state ("On", "Every 30 days", the account, "Synced 5 minutes ago"). Rows
    that open a page end with a chevron; switches toggle by tapping anywhere on the row. (b) Each (i) opens a dialog
    with the explanation (Biometric unlock, Ask for master password, Allow screen lock, Confirm each fill,
    Autofill group, Google Drive, Passyble Server, WebDAV, Change password on a server vault); OK closes it. (c) More
    security options opens its own page (top bar "More security options"); system Back and the arrow return to
    Settings, and the row there shows what's on ("Screen lock allowed · Confirm each fill"). "Allow screen lock"
    reads *Less secure* in red. (d) Ask for master password, Auto-lock and After confirming open a drop-down with a
    check on the current choice. (e) Sync: with nothing set up, Connect to Passyble Server, Back up to Google Drive and
    a WebDAV row that expands its form; Airplane mode + Retry shows "Not synced" with the error under it. (f)
    TalkBack: each (i) reads "About <title>", a switch row reads its title, state and "Switch"; every icon-only
    button has a label. (g) An empty vault shows "No items yet" with **Add a login** and **Import from another
    app**; an item with nothing in it shows "Nothing saved here yet" with **Edit**. (h) Import, Add a vault, Sign in
    to Passyble Server, Signed-in devices and the Google Drive note show short text, with details behind (i).
39. **Windows: Settings and screens like Android's** (980×680 and the 720×520 minimum, light and dark). (a) Settings
    shows the groups This vault · Unlock · Autofill · Sync · Import · Startup · About as accent titles over cards;
    every row has an outline icon, a one-line title and at most one line of state ("Every 30 days", "On · key bound
    to this PC", the account, "Synced 5 min ago", "Version 0.3.0 available"); long paths and names end in "…" with
    the full text on hover. Switch rows toggle when clicked anywhere; each (i) bubble (hover, Tab or click) stays
    inside the window at 720×520 and doesn't toggle the row. (b) Windows Hello off: Ask for master password is
    hidden. **More security options** (chevron) opens its own page with a back arrow: Confirm each fill, and After
    confirming only while that is on; Esc or the arrow returns with focus on the row, which then says "Confirm each
    fill". Tab reaches every row, button and (i), each with a visible focus ring; Enter or Space opens a chevron row.
    (c) Save settings / Close stay at the bottom while scrolling and save everything as before (name, Move… /
    Locate…, Windows Hello and policy, auto-lock, hotkey, Windows passkeys, extra extension IDs, WebDAV). (d) Sync:
    the WebDAV row expands its fields (open by default when WebDAV is set up); the status row shows **Sync now**,
    **Retry** with the error after a failure, or **Sign in…** for Google / a signed-out Passyble Server vault. A Passyble
    Server vault has Change password and **Signed-in devices** (own page, the server's name as its title) in This
    vault. (e) About: the version row shows the update state with **Check now** or **Update and restart** (a
    progress bar while downloading). (f) The item editor's Save / Cancel stay visible while scrolling; at 720×520
    username and password stack. Dialogs (Change password, Connect to Passyble Server, Trust this server?) keep their
    buttons visible at 720×520. With no item selected the pane shows "Choose an item" (or "Add your first login")
    and the shortcuts. (g) Prompt window: Windows Hello failed shows "Use master password instead" as a link under
    the message and Cancel / Try again with "1 of 2" when two requests wait; the passkey chooser's list fills the
    window. (h) Faint text (hints, dates, "Opened …") is readable in light mode.
40. **Android: what is offered after a login submit** (Chrome and one native app; vault unlocked, then locked). Save
    `ann@example.com` / `pw1` for a site first. (a) Sign in again with the saved login (autofilled, or typed by
    hand): no "Save" sheet from Passyble, or, if Android shows its own "Save to Passyble?" sheet because the values were
    typed, tapping Save shows nothing more and nothing changes (no toast, one login). (b) Sign in as
    `ANN@Example.com ` (other case, trailing space) with `pw2`: after Save, the toast says "Password updated"; the item
    keeps its username and has `pw2`. (c) Sign in as `ann.new@example.com` with `pw2` (the password of exactly one
    saved login): after Save the sheet "Update username/email?" appears with both names; **Update** changes that
    login's username (toast "Username updated"), **Save as new** adds a second login, Cancel saves nothing. With two
    saved logins sharing `pw2` there is no such question, the login is saved as new. (d) A new username and a new
    password: "Saved to Passyble", a new login. (e) Vault locked: the same cases after the system's Save go through the
    unlock sheet first; case (a) unlocks and finishes without a toast. (f) Android 14+: save a password through
    Credential Manager (a site that uses it) with the saved username and password: the sheet closes without a
    change; with a new username and a saved password: "Update username/email?".
41. **Browser extension: edit logins from the popup** (Chrome and Firefox; Passyble running, vault unlocked; a page
    with a saved login, e.g. github.com/login). (a) The popup lists the login with a pencil; **Edit** opens the
    editor in the popup: username, password dots (eye shows/hides; dice generates and shows), 2FA with the current
    code, websites, notes. Change the username and password, add `gist.github.com`, **Save**: "Saved", the list
    shows the new username and the desktop app's list updates by itself; **Fill** fills the new password. (b) With
    Windows Hello "Confirm each fill" on: Edit asks Windows Hello once; Save doesn't ask again; Cancel there shows
    "Cancelled." and keeps the form. (c) **Add 2FA** → paste `JBSWY3DPEHPK3PXP`: a code appears ("New · saved on
    Save"), Save, the card shows the 2FA badge and the same code as an authenticator app. Open a page showing a 2FA
    QR code (e.g. a TOTP test generator), Edit → Remove 2FA → Add 2FA → **Scan QR on this page**: the issuer and
    account appear; Save. A page without a QR code says "No 2FA QR code on this page."; a Google Authenticator
    export QR says to import it in the Passyble app. (d) **Add login** on a site with no logins: title is the site,
    website the page's origin; Save adds it (badge count goes up). (e) **Delete**: back to the list with "Deleted
    GitHub · Undo"; **Undo** brings it back with its password and 2FA; after a minute (or after locking) Undo says
    it's too late. (f) **Open in Passyble** brings up the desktop window. (g) Close the popup with the editor open,
    reopen: the list shows, nothing of the edit remains; chrome://extensions → Passyble → Inspect views → Application →
    Storage holds no password. (h) With an older Passyble desktop app, Edit says "Update Passyble to edit logins here."
42. **Browser extension: what the save banner offers** (vault unlocked, then locked; a site with `ann@example.com` /
    `pw1` saved). (a) Sign in with the saved login (typed, or filled by Passyble and submitted): no banner. (b)
    `ANN@Example.com ` with `pw2`: "Update password in Passyble?"; Update changes only the password. (c)
    `ann.new@example.com` with the saved password: "Update username in Passyble?"; Update changes only the username
    (desktop list updates). With two saved logins sharing that password: "Save login to Passyble?" instead. (d) A new
    username and password: "Save login to Passyble?". (e) Locked: see step 77. (f) **Subdomains** (automated:
    `another_subdomains_login_is_never_updated` in `Core/agent/tests/protocol.rs`, `logins_to_update_are_the_page_hosts_only`
    in `Core/core/tests/vault.rs`): with `ann@example.com` / `pw1` saved for `https://example.test` only, sign in on
    `https://www.example.test/` with `pw2`: "Update password in Passyble?" (the same host). On `https://app.example.test/`
    with `pw2` (the saved login is offered for filling there): "Save login to Passyble?", and Save adds a second login for
    `https://app.example.test` while the `example.test` login keeps `pw1`. Sign in there again with `pw3`: "Update
    password" now updates the `app.example.test` login only. A password change form on `https://b.example.test/` after
    filling the `example.test` login, and the dice button there: a new login for `b.example.test`, never the
    `example.test` one changed. Android (autofill save and Credential Manager save) behaves the same.
    (g) **Canonical host** (extension only; automated: `a_canonical_host_of_the_same_site_shares_its_login` in
    `Core/agent/tests/protocol.rs`, `canonical_hosts_of_the_same_site_only` in `Core/core/src/matching.rs`, the canonical tests
    in `Extension/test/background.test.js` and `Extension/test/content-username.test.js`): with `ann@example.test` / `pw1`
    saved for `https://example.test` only, serve the sign-in page on `https://app.example.test/` with
    `<link rel="canonical" href="https://example.test/login">` in its head and sign in with `pw2`: "Update password in
    Passyble?", and Update changes the `example.test` login, which now lists `https://app.example.test` too. Without the
    link: "Save login to Passyble?". With the link pointing to another site (`https://other.test/`), on a plain-`http`
    copy of the page, from a sign-in form inside an iframe, or with a link added by script after the submit: "Save login
    to Passyble?", nothing shared. On `https://alice.github.io/` with a canonical link to `https://bob.github.io/`: never
    shared (a public suffix). Android has no canonical host (autofill sees only the web domain).
43. **Windows: Passyble name, NSIS setup and MSI**.
    Verified for the SenPass rename (0.1.0): a silent `SenPass_0.1.0_x64-setup.exe /S` over an old "Pass"
    install (`%LOCALAPPDATA%\Programs\Pass`, Apps entry "Pass", Start menu `Pass.lnk`, Run value `Pass` set)
    removed `Programs\Pass`, the "Pass" Apps entry, `Pass.lnk` and `HKCU\Software\Sensyble\Pass`, kept
    `%APPDATA%\Pass` / `%LOCALAPPDATA%\Pass`, and pointed `pass+server` and the Run value `Pass` at the new
    folder; `uninstall.exe /S` removed the files, shortcuts, Apps entry, `pass+server` and the Run value.
    Verified for Passyble: `cargo tauri build --config tauri.bundle.conf.json` makes
    `Passyble_0.1.0_x64-setup.exe` and `Passyble_0.1.0_x64_en-US.msi`; `Pass.exe` in them has ProductName /
    FileDescription "Passyble"; the MSI's ProductName is "Passyble", Manufacturer Sensyble, same UpgradeCode.
    Still to check (on a PC or VM where closing the installed app is fine): (a) Silent upgrade:
    `Passyble_<v>_x64-setup.exe /S` over an installed SenPass (`%LOCALAPPDATA%\Programs\SenPass`, Apps
    entry "SenPass", Start menu `SenPass.lnk`, Run value `Pass` set): SenPass is closed, `Programs\SenPass`,
    the "SenPass" Apps entry, `SenPass.lnk` and `HKCU\Software\Sensyble\SenPass` are gone;
    `Programs\Passyble` has Pass.exe, pass-native-host.exe, uninstall.exe; Apps entry "Passyble" (Sensyble);
    `Passyble.lnk` in the Start menu; `pass+server` and the Run value `Pass` point at
    `Programs\Passyble\Pass.exe`; no empty `%LOCALAPPDATA%\Passyble`; `%APPDATA%\Pass`, `%LOCALAPPDATA%\Pass`
    untouched. The same over an old "Pass" install. (b) Interactive Passyble setup over a running SenPass: it
    asks to close SenPass, then installs; the Start menu shows only Passyble; at first start the browsers are
    registered from `Programs\Passyble` (Settings → Autofill → Browser extension green) and vaults, settings,
    Windows Hello unlock all still work. (c) In-app update from an installed SenPass N to a signed Passyble
    N+1: Passyble N+1 starts from `Programs\Passyble` with its
    window open, `Passyble.lnk` is in the Start menu, "Start with Windows" stays on. (d) Names: window
    titles, tray tooltip "Passyble (locked)", tray menu Open / Quit Passyble, Windows Hello prompt "Unlock
    Passyble", Settings → About "Passyble <version>", Task Manager shows "Passyble". (e) MSI, as admin on a test
    PC or VM: `msiexec /i Passyble_<v>_x64_en-US.msi /qn` → `C:\Program Files\Passyble`, Start menu "Passyble"
    for every user, Apps entry Passyble; each user's first start registers the browsers (manifests in
    `%LOCALAPPDATA%\Pass\native-messaging`), the extension connects, `pass+server://` links open the app.
    Settings → About has no "Check for updates automatically" row and says "Managed install. Update with the
    new MSI."; **Check now** may show a newer version but no **Update and restart**, and no dot on Settings.
    A newer MSI upgrades in place (one Apps entry). `msiexec /x` removes the folder, shortcut, Apps entry and
    `HKLM\Software\Classes\pass+server`; vaults and settings stay. (f) The Passyble MSI over an installed
    SenPass MSI (same UpgradeCode): replaces it, now in `C:\Program Files\Passyble`, one Apps entry
    "Passyble". (g) Android: the launcher, autofill and passkey prompts say Passyble ("Unlock Passyble", "Save passkey in Passyble").
44. **Windows: item context menu and "Open in Passyble"** (vault unlocked with a login that has a username, password
    and 2FA, and a secure note). (a) Right-click a login in the list: Copy username, Copy password, Copy 2FA code,
    Edit, Add to / Remove from favorites, Duplicate, Delete; the note only has Edit, favorites, Duplicate, Delete.
    The same menu opens with Shift+F10 or the menu key on the list, and from the ⋯ button that appears when you
    hover a row. Arrow keys / Home / End move, Enter chooses, Esc closes and focus returns to the row; a click
    elsewhere, scrolling the list or switching windows closes it; near the bottom or right edge it stays inside
    the window. Right-click in a text field (search, editor) still shows the normal Windows menu. (b) Copy
    password: paste it, and after 45 s the clipboard is cleared. Duplicate adds "<title> (copy)" (no passkeys)
    and opens it. Delete shows the Undo toast. Right-clicking a row while editing another item does not
    discard the edit until you choose Edit / Delete (Discard prompt). (c) With the browser extension, **Open in
    Passyble** on a site's login brings Passyble forward and shows that item (clearing search and filters, and
    leaving Settings / Import); with the vault locked, Passyble shows the unlock form and opens the item after
    unlocking (within 5 minutes). There is no "Open website" entry: the app has no command for opening links.
45. **Extension: 2FA codes** (Chrome or Brave and Firefox; Passyble running, unlocked; a login with a 2FA secret for a
    site that asks for it, e.g. github.com; Options → **Auto-fill 2FA code** on, the default). (a) Fill the login
    with the inline menu, sign in: on the 2FA page the code is filled without a click and the form is not submitted
    for you (sites that submit on the 6th digit do that themselves). (b) A sign-in that shows the code field in
    the same page without a new URL (script swaps the form, as many SPAs do): same result. (c) Turn auto-fill off: the menu
    opens on the code field with the code first; Enter or a click fills it; typing the code yourself closes the
    menu. (d) A code field Passyble doesn't recognise: click into it within 3 minutes of the fill, the menu offers
    the code. (e) Alt+Shift+K in a focused text field fills the current code (for the pending login, else the
    site's login with 2FA, which may ask for Windows Hello). (f) No code field at all (push approval page):
    after about 8 s the toast shows the code with Copy. (g) The popup shows the code with a countdown and a
    copy button for the current site. (h) Another site, or a cross-origin iframe, never gets the code on its own.
    (i) No 2FA menu where no code belongs: sign in to Google with Passyble (a login with 2FA), then within 3 minutes
    open Gmail with mails such as "Your verification code" or "2-Step Verification" in the inbox. Compose: the
    Subject box shows no Passyble icon and no 2FA menu when clicked, nor does the search box; no 2FA toast
    appears. The same any time later (no fill moments ago). (j) A site's search box on a help page about
    2-step verification: no icon, no menu. (k) A shop's coupon / promo / gift card code field (checkout): no 2FA
    menu, no code filled. (l) A real 2FA page still works: a code page whose only box is unnamed ("Enter the code
    from your authenticator app" above it) gets the code; a sign-in where the code page is a separate page of the
    same site (password page, then code page) still fills or offers the pending code.
46. **Android: website logins suggested for apps** (vault unlocked; Discord installed from Google Play; a login
    for `https://www.discord.com` that lists no Android app; nothing else for Discord). (a) Open Discord's sign-in
    screen: the dropdown and the Gboard chip show **Suggested: discord.com** with the username and a link icon
    (at most three suggestions, best first; none when a login already lists the app). (b) Tap it: the sheet
    **Use your discord.com login in Discord?** shows Discord's icon, name, `com.discord · from Google Play`, the
    website, the login and the "matched by its name" warning. Cancel fills nothing. **Fill and remember** asks for
    the fingerprint / screen lock (even though the vault is unlocked), fills username and password, and the login
    now lists `com.discord` with a 64-character certificate digest (item details; synced to the PC). Next time the
    login is offered directly, not as a suggestion. (c) Do (b) first with **Fill once** (on another app,
    or before remembering): it fills but stores nothing, and the suggestion comes back next time. (d) Sideload an app (e.g. `adb install` an APK, or install it from a file
    manager) whose name and package mention a site in the vault: no suggestion, only "Search vault…". The same
    with `adb install -i com.android.vending`. (e) Edit the login and change one character of the digest
    after `com.discord` (Android apps field): Discord gets no fill and no suggestion for it, but **App signature
    changed · Not filling Discord**; tapping it explains and fills nothing. (f) Android 12+: an app with verified
    App Links (`adb shell pm get-app-links <package>` shows `verified` for its domain) is offered a login for that
    domain directly, as a normal login, without the sheet. (g) The X app (`com.twitter.android`) is offered
    `x.com` and `twitter.com` logins; an unrelated app gets no suggestions for them.
47. **Android: Switch vault shows the vault list, not biometrics** (biometric unlock on for the open vault; try with one
    vault and with two). Settings > This vault > **Switch vault**: the lock screen shows "Switch vault" with the list of
    vaults (also with a single vault) and Add vault / Passyble Server, and no fingerprint prompt and no password field. Tapping
    a vault row opens its unlock form and, when biometric unlock is on for that vault, the prompt comes up then (also when
    you pick the vault you came from). Add vault from the list and backing out returns to the list. With one vault,
    the lock screen's **Switch vault or add one** link replaces the form by the list. An ordinary lock (the lock button,
    auto-lock, screen off, app restart) still shows the unlock form with the biometric prompt straight away.
48. **Import clashes and Find duplicates** (Windows and Android; a vault with GitHub `alice` / password A and
    GitLab `bob`; a CSV with: GitHub `alice` / A (identical), GitLab `Bob` / a new password + a note, two rows for
    `example.com` `carol` with different passwords, one new login). Import → the preview shows **Review clashes (3)**:
    GitHub "Identical · Already in your vault: skipped", GitLab "Password differs" (and Notes, Websites for what is new) with
    **Keep password: Existing · From import**, Example "2 entries in this file". Every **Merge** switch is on; the
    line reads "2 new · 2 merged · 1 skipped". Turn the master **Merge duplicates** off: all switches go off and the
    line becomes "5 new · 0 merged · 0 skipped"; turn one back on: "1 of 3 merged". With the defaults, Import: one
    GitLab item keeps its password, gains the website and the note; one Example item; nothing else doubled. Import
    the same file again: everything is Identical/skipped, nothing changes. Repeat on a fresh vault choosing **From
    import** for GitLab: the new password is used (the old one is in the item's history, not shown in the UI yet).
    Switch GitLab off: a second GitLab item appears. No password or 2FA value appears anywhere in the review.
    Then save two logins for the same site and username with different passwords: Settings → Import → **Find
    duplicates** lists them ("2 copies", Keep password with each item's title and date); **Merge 1** leaves one
    item (the most recently changed, with both websites) and the review shows **No duplicates**. Sync to the other
    device: the merged item and the deletion arrive.
49. **Sites that don't always ask for 2FA** (a login with 2FA; a site that offers "Don't ask again on this
    device", e.g. GitHub or Google). (a) Browser: sign in with Passyble where the site asks for the code: it fills
    as before (or the toast, for a 2FA step without a field). Tick "don't ask again", sign out, sign in again
    with Passyble: once the site lands on its signed-in page there is no menu and no toast, and the code is never
    fetched from the desktop app. After a second such sign-in, the agent treats
    the site as "skips 2FA": a 2FA page without a code field shows no toast, but a real code field still gets
    the code. `%LOCALAPPDATA%\Pass\otp-history.json` holds only hex keys and letters (no domain). (b) Android
    (same site in Chrome, or an app that remembers the device): when the app asks, the notification appears
    on the 2FA screen (not before it); when it doesn't, no notification at all, and the code is still in the
    keyboard / dropdown suggestions if a code field appears. (c) Android: the notification disappears by itself
    30 s after it appeared (also while the screen is on and the app is in the background); Copy works until
    then; swiping it within the 30 s brings it back silently, Dismiss removes it.
50. **Website icons** (Windows, Android, extension; a vault with logins for github.com, google.com, a site
    without icons, an `android://` app link and a `192.168.x.x` router). (a) Unlocked, the vault list, item
    detail header, Windows quick-pick (`Ctrl+Alt+P` with two matches) and the Windows passkey chooser
    (webauthn.io with two passkeys) show the sites' own icons in the avatar shape within a few seconds; the
    others keep their letter, and the app link and router address make no request (check with a proxy such as
    Fiddler / HTTP Toolkit: only `GET https://<host>/…` with `User-Agent: Passyble-icon/1`, no cookies, no
    Referer). (b) Restart and unlock again: icons appear at once from the cache (`%LOCALAPPDATA%\Pass\icons`,
    Android `cacheDir/icons`: file names are SHA-256 hashes, not site names). (c) Lock: no new requests until
    the next unlock. (d) Settings → Display → **Show website icons** off: letters right away, the icon folder
    is emptied, no more requests; the (i) explains that sites and the network can see which sites you have
    logins for. Back on: the icons are fetched again. (e) Extension popup on github.com with the Windows app
    unlocked: the matching login shows the GitHub icon (only that page's logins); with the setting off, or
    the vault locked, letters and no unlock prompt; with an older desktop app, letters and no error. (f)
    Android autofill dropdown: logins whose icon is already cached show it; nothing is fetched from autofill.
    (g) Dark and light theme: icons sit on a white tile with the same corners as the letter avatar.
51. **Generate a password and save it at once** (Android, Windows). (a) Android, Chrome: open a sign-up page
    (e.g. a test form with email + "new password" + "confirm"), type the email, tap the password field and
    pick **Generate strong password**: both password fields fill and "Saved to Passyble" appears; the vault
    has a new login for the site with that email, the generated password and the note "Created by the
    Passyble password generator.". Pick Generate again: still one login, with the newer password. Submit:
    no second login and no "Save login?" from Passyble (Android's own sheet may still ask when the email was
    typed by hand; Save there changes nothing visible). Type over the generated password before submitting:
    the login ends up with the typed one ("Password updated"). Leave the page without submitting: the login
    stays. Sign up with an email that is already saved for the site: the existing login gets the new password
    and the generated login is gone. A native app's sign-up screen: the login lists the app (package +
    certificate) and is offered the next time. A change-password screen (current + new) of a site with a
    saved login: Generate only fills; after the submit that login's password is updated, no new login.
    With the vault locked by timeout before picking Generate: the unlock sheet comes first; dismissing it
    still fills. (b) Windows: in a native app's sign-up window with no saved login, press `Ctrl+Alt+P`:
    the quick-pick shows **Generate new password** selected; Enter types a password into the focused
    field (no Tab, no Enter), the main window (if open) shows "Saved to Passyble as …", the clipboard holds
    it for 45 s, and the vault has a login titled after the window with website `windows:<exe>` and no
    username. Press the hotkey in the confirmation field: the new login is typed (password + Enter). With
    "Require Windows Hello before each fill" on, Hello comes first; cancelling it types and saves nothing.
    In a browser window the login gets no `windows:` website. A search that finds nothing doesn't
    preselect Generate (Enter does nothing).
52. **Browser extension: generate + save, editable banner, vault search** (Chrome/Edge and Firefox with the
    Windows app; automated: `Extension/test/content-draft.test.js`, `popup-search.test.js`, `options-page.test.js`,
    `background.test.js`, `test/e2e/draft.e2e.mjs`, agent `Core/agent/tests/protocol.rs`). (a) Sign-up page
    (email + password + confirm): click into the password field; besides the menu, a small dice button sits
    left of the Passyble icon. Click it: both fields fill, "Saved to Passyble · Undo" appears, and the desktop app
    has a login for the site (title = site, the email if typed). Click it again: same login, new password.
    Submit with another email: that login gets the email and final password, no "Save login?" banner, no
    second login. Undo (before submitting) removes the login. With the vault locked: the unlock window first;
    with "Require Windows Hello before each fill" on: Hello first, Cancel saves nothing (the fields stay
    filled). (b) Change-password form of a saved login: the button saves "<site> (new password)"; after
    submit the banner offers "Update password", and Update leaves one login (the draft is deleted). (c)
    Right-click a password field → **Generate password**: filled and saved (other fields no longer offer it:
    item 53 (e)). Inside an iframe login form: the iframe's field gets it. Also
    in Firefox (right-click menu shows Passyble → Fill with Passyble / Generate password). (d) Save banner after a
    sign-in with a typo in the username: the banner shows Username and Password fields (password masked, eye
    toggles); fix the username and Save: the login is saved/updated with the corrected values. After a
    redirect to another origin the password field is empty ("Keep the password you typed"). The page's own
    scripts can't click Save (untrusted clicks ignored). (e) Popup on a site, type 2+ letters of another
    site's login: an "In your vault" list appears (title, username, site, 2FA badge, icons when enabled), ↑/↓
    and Enter work. Copy password / 2FA code: the desktop app copies (Windows clipboard history doesn't keep
    it, gone after 45 s; Hello first if the per-fill policy is on); nothing secret in the popup. **Fill on this
    page**: the desktop app asks "Fill a login from another site?" with Cancel focused; Cancel fills nothing;
    Fill once fills that one time. **Open in Passyble** shows it in the app. One letter: no search. With an
    older desktop app: the old filter and "Look up logins for <site>" only. (f) Options page: Autofill,
    Passkeys, Shortcuts, Passyble Server, About; each setting one line with an (i) that opens its details; every
    switch still takes effect (e.g. Suggest strong passwords off: no menu on its own, the dice button stays).
53. **Browser extension: the clean redesign** (Chrome/Edge and Firefox, light and dark system theme, with the
    Windows app; automated: `Extension/test/popup-*.test.js`, `options-page.test.js`, `content-generate.test.js`,
    `content-draft.test.js`, `content-ui-guard.test.js`, `background.test.js`, `test/e2e/*.e2e.mjs`). (a) Popup on
    a site with 2-3 logins: header is only logo, "Passyble", the Unlocked/Locked chip and ⋯ (Add Passyble Server,
    Settings); no site name or extension ID. Rows show avatar/icon, title, username; a click fills. Hover or Tab
    onto a row: Copy username, Copy password, ⋯ (Edit, Copy 2FA code, Open in Passyble); Esc or a click outside
    closes ⋯. A login with 2FA has a code pill with a ring under the username; a click copies the code. No
    password generator and no length slider anywhere in the popup. (b) A site with no logins: one line and **Add
    login**. A browser page (new tab, `chrome://extensions`): "Nothing to fill here" and **Search vault**, which
    finds logins of any site (a row copies the password through the desktop app). (c) Edit login: labels over
    fields, show/generate inside the password field, Cancel/Save at the bottom while scrolling, Open in Passyble
    and Delete login in the header's ⋯. (d) In-page: click into an empty email/username or password field on a
    sign-in page with saved logins: the menu opens on its own, nothing highlighted (Enter submits the page's form
    as usual; ↓ then Enter fills). Typing or Esc closes it, it doesn't come back for that field until reload, a
    page that focuses the field by script doesn't open it, a site without logins opens nothing. Options →
    **Open suggestions automatically** off: only ↓ or the icon opens it. (e) Right-click: a password field (and
    a new-password field) shows **Generate password**; a plain text field, textarea or rich-text box doesn't
    (only "Fill with Passyble"). Right-click a text field, then quickly a password field: the item shows for the
    password field (if a very fast right-click shows a stale menu, picking the item on a non-password field does
    nothing). Generate on a password field still fills, saves and shows "Saved to Passyble · Undo" on one line.
    (f) Save banner after a sign-in: a small card with the question, "<user> on <site>", Edit, Not now, Save;
    Edit unfolds Username/Password (and stops the 45 s auto-dismiss). (g) The 2FA toast is one line (code,
    ring, Copy, the "show on desktop" icon, close). (h) Options: grouped rows with one icon each, (i) details,
    switches; all text readable (AA) in light and dark.
54. **Soft lock: the list stays, secrets ask to unlock** (Windows app with the extension, and Android; automated:
    `Core/agent/tests/protocol.rs`, `commands.rs` / `site_icons.rs` / `tray.rs` / `ui.rs` unit tests,
    `Extension/test/popup-softlock.test.js`, `background.test.js`, Android `SoftLockTest`, `FillLabelsTest`,
    `PasskeyAllowListTest`; ARCHITECTURE.md section 12). (a) Windows, Settings → Unlock → **Keep list visible when
    locked** on (default): unlock, open an item, wait for the auto-lock (set 1 minute). The window keeps the
    list, search, filters and website icons, a **Locked** pill next to the vault name, and the item with its
    username and websites; password, 2FA code and notes are dots with "Unlock to view". Windows Hello does not
    start by itself, also not when the window is minimised and restored or shown from the tray. Copy username
    works without unlocking. Copy password: the unlock dialog over the list (Hello at once when set up), then
    the password is on the clipboard, one click. Same for show password, show / copy 2FA code, notes, Edit,
    favorite, duplicate, delete, New, Import, Settings and Sync; Cancel or Esc leaves it locked without an
    error. (b) Win+L, sleep, Ctrl+L and tray **Lock** do the same. An open editor is closed on lock ("unsaved
    changes were discarded"); a revealed password or code is hidden again. (c) Clicking the lock button while
    soft-locked only opens its menu (also right-click while unlocked): **Lock completely**, "Also hides the list
    until you unlock". It (or tray **Lock completely**, Ctrl+Shift+L), Switch vault and removing the vault show
    the unlock screen, no list. Quit and start again, or restart for an update: soft-locked with the list again,
    unless Lock completely came first. Turning the setting off while soft-locked drops the list at once; with it off every
    lock is complete. The tray tooltip says "locked, list visible" while soft-locked. (d) Extension while the app
    is soft-locked: the popup and the in-page menu still show the site's logins (titles, usernames, icons) and
    the vault search; filling, copying a password or code, Edit and the save banner's Update ask to unlock (the
    app's prompt) and then complete; copy username works without it. (e) Auto-type hotkey while soft-locked:
    unlock prompt first, then the quick-pick or the typed login. (f) Android, **Keep list visible when locked**
    on: after the auto-lock, the screen turning off or the Lock icon, the app shows the list with a lock icon and
    "Locked" line, search works, no BiometricPrompt on resume. An item shows dots for password, code and notes;
    the eye, copy, edit, delete, star, delete passkey, add, Settings and Import bring up the unlock sheet and
    then finish. ⋮ → **Lock completely** shows the lock screen. (g) Android autofill while soft-locked: the
    dropdown / Gboard chips list the matching accounts by title and username (no "Unlock Passyble" only row);
    picking one unlocks (biometric) and fills it in the same step, including the 2FA code row. Credential
    Manager (Android 14+): the sheet lists the passwords and passkeys by account; picking one unlocks, then
    signs in. The "Update password?" save sheet says "Unlock to update the password for ..." when the login
    exists. (h) Kill the app process while soft-locked, or after Switch vault without picking another vault:
    the next start (or an autofill request) is soft-locked with the list again. After ⋮ → Lock completely it
    shows the lock screen.
55. **2FA codes hidden by default** (Windows and Android). (a) Windows item pane: the code shows as "••• •••"
    with the countdown running; hovering over it or pressing and holding shows it while the pointer stays; the
    eye button shows / hides it; Copy works without showing it. Opening another item hides it again. The TOTP
    popup: dots too, eye, Copy and Type it work without revealing; each new popup starts hidden. (b) Android item
    details: dots with the countdown; the eye shows / hides, holding the card shows it while held, a tap or Copy
    copies without showing. Autofill 2FA rows show only the item's name, never the code. The one-time-code
    notification shows dots with **Show** / Hide and Copy; Copy works without Show.
56. **Windows passkey provider, one switch** (installed Passyble, Windows 11 26100.6725+). (a) Without Developer
    Mode and with an unsigned build: Settings → Autofill → Windows passkeys says "Needs Developer Mode or a signed
    build", the switch is off and disabled, **Open** goes to Windows Settings → System → For developers. (b) With
    Developer Mode (or a signed release): turn it on, Save: the note says to restart; the row shows "Restart to
    finish". **Restart**: Passyble comes back, Windows Settings → Accounts → Passkeys → Advanced options opens, the
    row shows Package registered and Plugin registered green. Switch Passyble on there; reopen Passyble's
    Settings: On in Windows green. `Get-AppxPackage Sensyble.Passyble` lists the package (InstallLocation
    `<install>\package`). (c) webauthn.io with the extension disabled: register and sign in through Windows'
    dialog (README "Testing it"). (d) A vault with Windows Hello: after the restart, Hello unlock still works (a
    process with identity saw the existing Hello key on build 26300). (e) Turn it off, Save: Passyble disappears from
    Advanced options; after quitting Passyble, `Get-AppxPackage Sensyble.Passyble` is empty. Turning it on again
    in the same session asks for a restart first. (f) Uninstall (NSIS and MSI) with it on: Passyble disappears from
    Advanced options and the package is gone; an update (in-app or a newer MSI) keeps it registered and working.
57. **Passkeys in the extension, end to end** (automated: `Extension/test/e2e/passkey.e2e.mjs` against the real
    agent harness `cargo build -p pass-agent --example e2e_agent`, in Playwright's Chromium and, with
    `BROWSER=<brave.exe>`, Brave; `test/webauthn-main.test.js`). By hand, in Brave with the extension reloaded
    (brave://extensions, the Passyble card's reload arrow) and the installed Passyble unlocked: (a) webauthn.io,
    default settings: type a username, Register: Passyble's "Save a passkey?" window comes up (not Windows'
    dialog), Save: "Success! Now try to authenticate..."; Authenticate (with and without the username): Passyble's
    chooser, then the profile page. (b) Reload webauthn.io and click the username field: the Passyble menu lists
    the passkey; picking it signs in (conditional UI). (c) Register the same username again: "The authenticator
    was previously registered" (InvalidStateError). (d) Advanced settings, User Verification **Required**: with
    Windows Hello set up, Hello asks and it works; without Hello the browser's own dialog takes over (by design:
    Passyble can't verify the user). (e) A tab left open across an extension reload: Register there still gets an
    answer (Passyble or the browser), nothing hangs. (f) Passyble quit: Register shows the browser's own dialog.
58. **Most used logins first** (Windows with the extension, Android, two devices on one synced vault; automated:
    `Core/core/tests/usage.rs`, `usage_rides_along_with_the_next_sync` in `Core/core/tests/webdav.rs`, agent protocol tests,
    `pass-desktop` background/commands tests, Android `UsageOrderTest`). (a) Two logins for one site: fill the
    second one a few times; the extension's in-page menu and popup list it first (favorites still come before it).
    Also when the other login was imported from a browser with the sign-in page's path (`https://site/login`) and
    the used one has only the origin, on that very page; a login of another subdomain stays below the site's own.
    Same for Windows auto-type (two `windows:<exe>` logins, quick-pick order), Android autofill rows and Credential
    Manager entries (password and passkey). (b) A use is no edit: the item's "modified" time doesn't change, and no
    sync starts within 10 s (sync status stays without pending changes); the counts go up with the next sync for any
    other reason (unlock, focus, an edit, "Sync now") and reach the other device, whose lists then reorder. (c)
    Offline on both devices: fill a login on one while editing it on the other, then sync both: the edit survives,
    no duplicate or conflict copy appears, and both counts add up. (d) Windows vault list: the **Most used** chip lists
    used logins by use; Android vault list menu: **Sort by most used** (persists across restarts). (e) Copying a
    username doesn't count; copying a password or 2FA code (also the popup's 2FA copy and a code picked in the in-page
    menu), a passkey sign-in and the code notification's Copy do.
    (f) An older build of the app opening the same synced vault still works; after it saves, the counts come back
    with the next sync of an updated device.
59. **E-mail sign-in fields** (Bootstrap-style `<input type="email" name="username" autofocus>` + password, no
    autocomplete attributes; automated: `Extension/test/e2e/email.e2e.mjs`, `test/content-email.test.js`, the e-mail
    cases in `test/detect.test.js`, Android `EmailFieldClassificationTest`). (a) Extension, a page whose e-mail field
    has focus on load (autofocus): the Passyble menu opens for it without a click, nothing preselected; ArrowDown +
    Enter fills the e-mail field with the username and the password field with the password. Same with an "Email
    address" label (sr-only or floating), without `name`, with `autocomplete="email"` or `"username"`. (b) Identifier-
    first (e-mail, Next, then password): the first step gets the username only, the second the password. (c) A
    newsletter e-mail box gets no icon. (d) Android, Chrome and Firefox on the same pages: the e-mail field offers
    the logins and fills the username there; a native app with an e-mail keyboard field too. (e) Windows auto-type
    into a native app whose username is an e-mail address: `alice@example.com` arrives as typed (any keyboard layout).
60. **Cards, identities, custom fields, tags and the trash** (core; the Windows and Android screens are in progress, so
    most of this is automated until they land: `Core/core/tests/items.rs`, the compatibility tests in `Core/core/src/vault.rs`,
    `Core/core/src/import/tests.rs`). (a) Older clients: open a vault that holds a card, an identity, a tagged item with a
    custom field and a trashed item with a build from before this feature (or a copy of it). It opens (no "vault file
    is corrupt"); the card and identity are secure notes with their title and notes, tags and custom fields are not
    shown, the trashed item is listed as a normal item, and `password_changed_at` is ignored (modified time stands
    in). Edit and save the "note" of the card in the old build, then open the file in the new build: that item lost its
    card data (documented), every item the old build did not touch is intact, and a sync between both builds converges.
    (b) Current Windows and Android builds: Delete an item (Undo on Windows brings it back; on a synced vault the item is
    gone on the other device too); there is no trash screen, so nothing to restore yet. After 30 days it is purged
    (`purge_expired_trash`, run at unlock and save; the unit test changes the date). (c) When the screens land: a card
    typed as `4111 1111 1111 1111` is saved as digits, shows Visa and the last four digits in the list, the title
    defaults to "Visa •••• 1111", a two-digit year becomes 20xx, a month over 12 is refused; in the soft-locked list, in the
    search and in the kept-list file on disk (Windows) there is never the full number, security code, PIN or a hidden
    field value (search for the middle digits of the number: no hit; search the last four digits or a tag: hit). Tags:
    `Work/Clients` is found by `tag:work`, `#work` and `tag:work/clients`, not by `tag:workshop`; the tag list counts
    exact tags. Hidden custom fields are masked until revealed and are not found by search; plain ones are. Trash: restore,
    purge, empty trash; a trashed item is in no list, search, autofill, passkey lookup or export, and is not matched by
    an import; trash on one device, edit on the other: the later edit wins like any edit. Reading a vault written by a
    newer client with an unknown item kind shows it as a note instead of failing.
61. **Export** (core; the screens are in progress; automated: `passyble_json_export_round_trips`,
    `encrypted_export_round_trips`, `bitwarden_csv_export_round_trips_logins` in `Core/core/tests/items.rs`). By hand with a
    vault holding every kind, a passkey, a custom field, a tag and a trashed item: (a) **Passyble JSON**: starts with
    `"format": "passyble-export"`, has every live item incl. passkey private keys and password history, not the trashed
    one; importing it into a new empty vault gives the same items (nothing skipped, no duplicates when imported twice).
    (b) **Encrypted JSON**: `"format": "passyble-export-encrypted"`, no password or note of the vault appears in the file
    as text (search it for one); `export_is_encrypted` is true; a wrong password is "invalid password", an empty password
    for the export is refused; change `kdf.t` (or any KDF value) by hand and decryption fails; a `m_kib` of 8 GiB is refused
    at once (no allocation); `import_parse_with_password` imports it, plain `import_parse` says to enter its password.
    (c) **CSV**: import the file into Bitwarden's web vault (Tools → Import data → Bitwarden (csv)): folders from the
    first tag, logins with all websites and 2FA secrets, cards and identities as secure notes with their details in the
    custom fields; Passyble reads its own CSV back as logins and notes. No passkeys, history or hidden marks in it
    (documented). (d) Say so in the app text: every export is readable by whoever has the file.
62. **Password health and the breach check** (core, Windows and Android; automated: `password_health_report`,
    the strength and HIBP tests in `Core/core/src/health.rs`). (a) A vault with `password1` and `qwerty123` (weak), the
    same password on three logins (one reused group of 3; passwords that differ only in case are not reused), a login
    whose password was changed over a year ago (old; with the date known, i.e. saved by this version, a title-only edit
    leaves it old and a password change makes it not old; an item from an older client has no date and falls back to its modified
    time, which any edit moves; an imported login uses the source's modified date), a trashed login with a weak password (in no
    list) and a strong random password (healthy). `checked` counts live items with a password, notes and cards
    without one are not counted. (b) The breach check sends only a 5-character prefix: run `hibp_check` through a
    logging proxy (or watch the connection) and confirm one `GET https://api.pwnedpasswords.com/range/XXXXX` with
    `Add-Padding: true` and nothing of the password, for `password` a count in the millions, for a random 20-character
    password 0; offline gives a network error, not a crash. Nothing is requested unless the user asks.
    (c) **The other checks** (automated: `the_report_finds_every_problem`, `http_addresses_to_public_sites_are_unsecured`,
    `passwords_with_the_username_or_site_name` and the `sites::tests` in core, `health_use_https_changes_only_what_is_safe`,
    `Core/desktop-app/ui/test/health-model.test.mjs`, Android `HealthChecksTest`). Add logins for `http://shop.example.com`
    (Unsecured websites, with Change to https), `http://shop.example.com:8080` (listed, no Change to https),
    `http://192.168.1.1`, `http://nas.local` and `http://localhost:3000` (not listed), `https://github.com` without
    a 2FA code (Two-factor sign-in available with "Authenticator app" and How to turn it on, which opens GitHub's
    help page; adding a 2FA code or a passkey removes it), `https://accounts.google.com` (found through the
    registrable domain), user `marianne` with password `Marianne#9vQz!Lw` (Contains your name), a login with only a
    username (Logins without a password; one with only a 2FA code or a passkey is not listed) and the same site and
    username twice (Saved more than once; Review and merge opens Find duplicates). Change to https asks first, shows
    the new address, saves it and the login leaves the list; the summary's "look good" count drops for unsecured and
    named passwords but not for two-factor, passkey, duplicate or no-password findings, and drops by the breached
    items after a breach check. Watch the network: nothing is requested for these checks (the site lists are in the
    app); How to turn it on opens only the link from the bundled list.
63. **Passyble Server two-factor sign-in** (server and core client, automated in `Server/tests/two_factor.rs`; the
    Windows and Android screens are in progress, so drive it with a small `pass-core` client or the tests, and any
    authenticator app such as Aegis or 2FAS; `Server/README.md` "Two-factor sign-in"). (a) **Enroll**:
    `server_two_factor_status` says off and available; `server_two_factor_setup` with a wrong password fails, with the right
    one returns a secret and an `otpauth://totp/` URI (scan it: the issuer is the server's name, 6 digits, 30 s) and
    status shows pending, still no code needed to sign in; `server_two_factor_confirm` with a wrong code fails, with the
    first code turns it on and returns 10 recovery codes (`xxxx-xxxx-xxxx`), shown once. `pass-server user list` says
    `2fa: on`, `/api/v1/info` has `features.two_factor`, `whoami` has `two_factor: true`, the audit log has
    `2fa_setup_started` and `2fa_enabled`. (b) **Sign in with a code**: `server_login` without a code fails with
    `2fa_required` and registers no device, adds no failure (twenty tries do not lock anything out); `server_login_2fa` with
    a wrong code fails with `2fa_invalid` and counts like a wrong password (after the configured number of failures, 10 by default: 429, and the slow-down e-mail when e-mail is set up); with
    the current code it signs in (audit `sign_in`, detail `totp`). Devices that were already signed in keep syncing
    without any code. (c) **Replay refused**: use a code to sign in, then send the same code again within its 30 seconds:
    `2fa_invalid`; so is the previous step's code after a newer one was used; the next code works. Two sign-ins racing
    with one code: exactly one succeeds. (d) **Recovery code**: sign in with one typed in capitals and without dashes;
    audit `sign_in` with detail `recovery_code` and `2fa_recovery_code_used` with `count` 9; status says 9 left; the same
    code again is `2fa_invalid`. (e) **Password change needs a code**: `server_change_password` without one fails with
    `2fa_required` (the password is not changed), with `server_change_password_2fa` it works. (f) **Reset link needs a
    code**: `pass-server user reset alice` (or "Forgot password?"), use the link with `server_set_password_with_code`:
    `2fa_required`; the same link still works afterwards with `server_set_password_with_code_2fa` and a code (a wrong code:
    `2fa_invalid`, link still valid); after success every device of the account is signed out and the link is used up.
    `pass-server user reset-password alice` leaves two-factor on and says so. (g) **Admin reset**: `pass-server user 2fa-reset
    alice`: the next sign-in needs the password only, the existing devices stay signed in, the audit log has `2fa_reset`
    (actor admin, detail `was_on`); run it again: "doesn't use two-factor sign-in". `pass-server pair alice` gives a device
    token without any code. (h) **Turn off**: `server_two_factor_disable` needs the password and a code (missing code:
    `2fa_required`); turning on again gives new recovery codes. `[auth] two_factor = false`: setup is refused (`2fa_unavailable`),
    accounts that already use it keep it, `/info` says `two_factor: false`. A limited device (admin-set password not
    changed) gets 403 on all of it. Older server: the client says it doesn't support two-factor sign-in.
64. **Passyble Server metrics: who may read them** (`Server/tests/metrics_audit.rs`; Server/README.md "Metrics").
    (a) Default config: `curl http://127.0.0.1:<port>/metrics` is 404. (b) `[metrics] enabled = true`, no token: from the
    server itself 200 with `passyble_*` lines; the same request with `X-Forwarded-For: 203.0.113.9` (or `X-Real-IP`,
    `Forwarded`) is 401, and so is any request from another machine or through a reverse proxy that adds one of those
    headers; behind a proxy that adds none the proxy's connection looks local, so set a token or don't route `/metrics`.
    (c) With `token` (at least 16 characters; a shorter one stops the server from starting): `Authorization: Bearer <token>`
    is 200 from anywhere, no or a wrong token is 401 with `WWW-Authenticate: Bearer realm="Passyble Server metrics"`.
    (d) `listen = "127.0.0.1:9464"`: `/metrics` answers there on plain HTTP and is 404 on the main listener, nothing else
    is served on the metrics port; `0.0.0.0:9464` without a token refuses to start, with a token the bearer is required.
    (e) Content: after a few requests the counters have route templates (`/dav/{owner}/{file}`), never account or vault
    names; a wrong code adds to `passyble_sign_in_failures_total{kind="2fa"}`, a wrong password to `kind="password"`, a
    rejected token to `kind="token"`; `passyble_accounts_two_factor`, `passyble_vault_bytes`, the backup gauges and
    `passyble_build_info` look right; a Prometheus job with the README's `scrape_configs` shows the target up.
65. **Passyble Server audit log and security events** (`Server/tests/metrics_audit.rs`). (a) Do each of these and run
    `pass-server audit --user alice --since 1h`: sign in (with and without a second factor), a wrong password, a wrong
    two-factor code, a lock-out (`account_slowed_down` with the failure count), a device added (`pair`) and signed
    out (by the user, by `revoke`), a password change (how it was authorized and how many devices were signed out), a
    reset request, setup, enable, disable and recovery-code use, `2fa-reset`, `user add`, `set-email`, `invite`,
    `reset-password`. Each line has actor, device, IP and a qualifier where it should. (b) Nothing secret: search
    `<data_dir>/audit.log` for the password, a code, a recovery code and a device token: no hit; a password typed into
    the user-name field of a failed sign-in is logged as `(unknown)`, not as typed. (c) `--event sign_in_failed --event
    2fa_disabled`, `--limit 3`, `--limit 0`, `--json` (the stored lines) and `--since 2026-10-01` filter as described.
    (d) Rotation: `max_bytes = 2000`, `keep = 2`: `audit.log`, `.1`, `.2` appear, the oldest is dropped; the CLI writing
    while the server writes does not corrupt lines. (e) What a user sees (`server_security_events`): only their own account,
    newest first, the calling device marked `current`, `limit` of 1 to 200 (0 is 50, 500 gives 200); an old device signed out
    by a reset and still syncing does not flood it with `token_rejected`; the admin's actions on the account show with
    actor `admin`. (f) `[audit] enabled = false`: no log is written, `/api/v1/security-events` is 404 and the client says the
    server keeps no events, `/info` says `security_events: false`, and `pass-server audit` says it is turned off.
66. **Android: the 2FA notification setting and syncing while locked** (`OtpTimingTest`, `WebLinksTest`; Android/README.md).
    (a) Settings → Autofill → **2FA notification**. **Keep until dismissed** (default): fill a login with a 2FA secret on a
    site whose 2FA screen shows up; the notification stays past 30 seconds and keeps refreshing the live code at each
    period change (also after about 3 minutes, when Android 14 ends the foreground service: it may blink and come back
    on phones that freeze background apps). Tap **Dismiss** or swipe it away: it is gone and stays gone. Copy the code: it stays
    until that code's period ends, then goes. Let autofill fill the code field (or a login fill whose form has the code
    field): it goes. Lock the vault with the Lock button, Switch vault or by the screen turning off: it goes at once (the
    inactivity auto-lock lets a running code finish its 30 seconds). Otherwise it is gone after 10 minutes at the
    latest. **Remove after 30 seconds**: it goes after 30 seconds, Copy works until then, a swipe within them is
    undone. The choice applies to the next notification (a running one keeps its end). In both: the code is hidden
    until Show, the lock screen never shows it. (b) **Sync while locked**: a vault on WebDAV (and again on Passyble Server
    and Google Drive) with the soft-locked list, edited on another device (add a login, change a title). Lock Passyble
    and let the periodic sync run: with a debuggable build `adb shell run-as com.sensyble.passyble ls cache/locked_sync` shows
    the downloaded encrypted file; the vault's sync status (last sync, errors) and the server's version list/ETag do not
    change: nothing was uploaded; the soft-locked list shows no new item yet. Unlock with the master password, again
    with biometrics, from the autofill unlock sheet, from the Credential Manager sheet and from the 2FA code
    notification's unlock: each time the other device's edit is there at once, merged with the local state, and the cache
    file is gone. A cache that belongs to another vault (a server vault replaced after a password reset), a damaged one
    or one that `mergeRemote` refuses is deleted and never blocks the unlock; a vault without a sync account, signed out of
    Passyble Server or needing a Google sign-in downloads nothing; removing the vault deletes the cache. Offline: the run does nothing and
    the unlock is unaffected. (c) Item details: a website opens in the browser on tap (`http(s)` and bare hosts as
    `https://` only: a `windows:` entry or an app link does nothing), long-press copies it; **Password history (N)** (after
    merging two logins with different passwords) opens a sheet with each password masked, Show and Copy per entry
    (auto-cleared), the date it was replaced, and hides again when closed or when the vault locks.
67. **Browser extension: Lock, Never for this site, Alt+Shift+P** (Chrome/Edge/Brave and Firefox with the Windows app;
    automated: `Extension/test/background-lock-never.test.js`, `popup-lock-passkey.test.js`,
    `options-never-save.test.js`, `manifest.test.js`, `content-draft.test.js`, and the `lock` tests in
    `Core/agent/tests/protocol.rs`). (a) **Lock**: while unlocked the popup header has a Lock button. Click: the popup
    shows the unlock form (or the soft-locked list when "Keep list visible when locked" is on, the default; with it off a
    complete lock), the badge changes at once, the inline menu in open tabs stops offering logins, and the app shows its
    Locked pill / unlock screen. Edits made just before (a login saved through the banner, an edit in the app) are
    there after unlocking, also when the vault file was held by a sync client (an `-unsaved-` copy appears and the next unlock
    merges it). With the popup left open, Lock after the app was locked another way (tray Lock) just shows the locked popup, no error.
    With an older desktop app the popup says "Update the Passyble desktop app"; with the app not running "Passyble isn't
    running". A web page cannot lock the vault (the message is popup-only). (b) **Never for this site**: submit a new login form
    on a test site: the banner has a small **Never for this site** link under Not now / Save. Click: the banner goes, the
    password is not kept, and the site is listed in Options → **Sites without save prompts** (an origin such as
    `https://accounts.example.com`). Submitting new, changed and update-worthy logins there shows no banner any more; filling
    still works. `www.example.com` and `accounts.example.com`, and `http` and `https` of one host, are separate entries and
    separate decisions. A login form inside an iframe of another origin adds the iframe's origin, not the page's.
    **Remove** in Options brings the banner back for that site. The list holds origins only; it survives a browser restart. A
    generated password's auto-saved draft still works on such a site. (c) **Alt+Shift+P** opens the popup (Control+Shift+P on
    macOS); on an existing install the key is only suggested on first install, so set it at `chrome://extensions/shortcuts` (or
    Firefox's Manage Extension Shortcuts) or reinstall; Ctrl+Shift+P stays the private window. (d) A login that has a passkey
    shows a **Passkey** tag after its title in the popup and the inline menu, and the vault search results show the 2FA and
    Passkey tags.
68. **Windows: change the master password of any vault, password history, manual backups** (`Core/agent/tests/protocol.rs`,
    `pass-desktop` command tests; Core/desktop-app/README.md). (a) Settings → This vault → **Change password…** on a local file vault, a
    WebDAV, a folder and a Google Drive vault (a Passyble Server vault keeps its own change-password flow). A wrong
    current password and an invalid or mismatching new one are refused with a message; a good change toasts "Master
    password changed" (and a warning if saving or syncing failed); lock and unlock with the new password, the old one is
    refused; Windows Hello still unlocks (it keeps the vault key); the extension's unlock form
    works with the new password. A second device on the same vault (WebDAV or the shared folder) asks for the new password at
    its next unlock after the change arrived, and its edits made meanwhile are kept. (b) **Password history**: merge two logins
    for one site that have different passwords (Merge, or Import → Keep/Merge); the kept login's detail shows
    **Password history (N)** with "Replaced <date>" rows, each masked with Show and Copy; Show fetches the password only when
    clicked and hides it again on another item, a re-render or lock; Copy puts it on the clipboard, cleared after 45 s;
    soft-locked: no history. (c) **Manual backups are left alone**: next to `pass.vault` in a synced folder put copies
    named `pass-backup.vault`, `pass (old).vault` and `pass-2024-01-01.vault` made earlier (with an item the current
    vault no longer has). Edit in the app, lock, unlock: all three files are still there, unchanged, and the old item did
    not come back. Real conflict copies are still merged in and deleted at the next unlock: `pass-DESKTOP-1.vault` and
    `pass-LAPTOP.vault` (OneDrive: upper-case computer name), `pass (Bob's conflicted copy 2026-10-14).vault` (Dropbox),
    `pass.sync-conflict-20261014-101500-ABCDEFG.vault` (Syncthing), `pass (1).vault` (Google Drive) and
    `pass-unsaved-<ms>.vault` (the app's own stash after a failed save); give each a different new item (copy of the same
    vault, edited elsewhere) and check they all arrive. A file with such a name that is not a copy of this vault stays
    where it is.
69. **Extension: "isn't running" only when Passyble really isn't** (Windows app with the extension; automated:
    `cargo test -p pass-native-host`, `Extension/test/native-client.test.js`, `background.test.js`, `content-main.test.js`,
    `content-menu-recheck.test.js`, `bridge.test.js`, `content-generate.test.js`). (a) Quit Passyble, start the browser, open a site with a saved login
    (the badge may say "not running"). Start Passyble 20 s later, from the Start menu. Without clicking **Start Passyble**,
    within a few seconds the badge counts the logins again and the inline menu and the popup work. (b) Turn on Windows Hello
    for each fill, fill a login from the inline menu and leave the Hello prompt open for 45 s, then confirm: the login
    fills, and nothing said "Passyble isn't running" meanwhile (the badge too). Leave it open over 3 minutes: the page says
    "Passyble didn't answer in time. Check for an open Passyble window, then try again." with no Start Passyble. (c) Reload
    or update the extension at `chrome://extensions` with a sign-in page open, then, without reloading the page, click its
    username field and pick a login: it fills (the extension injects its scripts again), and the page never says "Passyble
    isn't running". Where a page can't be reached again, it says "Passyble was updated. Reload this page to use it." (d) **A click reopens the menu**: on
    a sign-in page with saved logins, click the username field (the menu opens), press Esc, click again: it opens again,
    nothing preselected (Enter submits the page). Fill a login, then click the field again: all the site's logins are
    listed, not just the filled one; typing filters them. Selecting the field's text by dragging opens nothing. On a
    sign-up form, Esc the generator, click the empty password field: it is back. A site without saved logins (unlocked):
    a click opens nothing. (e) **Started by the browser, Pass stays**: quit Passyble, open a sign-in page in Brave (and
    in Chrome), click the username field's Passyble icon: the host starts Passyble. Leave the browser idle for 2 minutes
    (the service worker and its host go away), check in Task Manager that Pass is still running, then click the field
    again: the menu lists the logins, never "isn't running". Quit the browser: Pass keeps running. (f) **A restart in
    between**: with a sign-in page open, quit Passyble from the tray and start it again from the Start menu, then at once
    click the username field: the logins show (perhaps after a moment), not "isn't running". (g) **The menu catches
    up**: quit Passyble, click the username field's icon ("Passyble isn't running"), leave the menu open and start
    Passyble: within a few seconds the same menu shows the logins, with no "Loading" flicker before. The same on a
    sign-up form's password field (the generator stays, the note goes) and on a card field. Close the menu while it says
    "isn't running", then start Passyble: no menu comes back on its own. (h) **A slow service worker**: in
    Brave, leave a sign-in page idle for 5 minutes, then click its username field: the menu opens (it may take up to
    ~2 s), never "isn't running" while Passyble runs.
70. **Windows: Get started checklist, extension setup guide, Help** (Core/desktop-app/README.md "Get started checklist",
    "Browser extension setup guide", "Help and tutorials"; automated: `cargo test -p pass-desktop` (setup_guide.rs,
    settings.rs), `node --test Core/desktop-app/ui/test/*.test.mjs`). Install from the NSIS setup built with
    `tauri.bundle.conf.json`: `<install>\extension\manifest.json` (with `key`) and `<install>\extension-firefox.zip`
    exist. (a) A profile with an older vault: no checklist. Create a new vault: Skip the recovery offer; the empty pane
    shows "Get started" with "0 of 5 done" (4 steps without Windows Hello; the browser step is already ticked if an extension connected on this PC before) and no "Unlock with Windows Hello next time?" card.
    (b) **Set up…** → the guide preselects the default browser; **Open Chrome** starts Chrome and the address is in the
    clipboard; Developer mode, Load unpacked with the pasted folder path loads the extension with ID
    `bmjmlhhgfbpcbfbkbndlmmockkbdcaoo`; clicking its toolbar icon turns the check green within a few seconds
    ("Connected: Chrome…"); the same in Edge and Brave. Firefox: the temporary add-on warning, **Load Temporary
    Add-on…** with the copied zip path loads it and the check turns green. A browser that isn't installed is greyed
    and can't be opened. **Mark as done** ticks the step without a connection. (c) Import a CSV, create a recovery code,
    connect a sync account (or move the file into OneDrive), turn on Windows Hello from the checklist: each step ticks
    when its flow closes; after the last one the card disappears with "You're all set". (d) **Hide** on a new vault:
    gone after a restart too; Settings → Help and tutorials → Get started checklist → **Show again** brings it back.
    (e) Every tutorial opens, its buttons lead to the right place (Sync settings scrolls Settings to Sync), the
    auto-type tutorial shows the hotkey set in Settings, and Downloads opens the GitHub releases page. Check (b) and the
    tutorials once in German and Japanese for text that doesn't fit.
71. **Password-protected exports of other apps** (Windows and Android; automated: `Core/core/src/import/tests_encrypted.rs`,
    which makes each format itself: correct and wrong password, damaged data, account-restricted Bitwarden, key
    derivation beyond the bounds, garbage input). By hand with real exports: (a) **Bitwarden** Tools → Export vault →
    ".json (Encrypted)" + "Password protected", once with PBKDF2 and once with Argon2id on the account: Import asks for
    the file password, a wrong one says "Wrong password for this export" and asks again, the right one shows the usual
    preview. An "Account restricted" export says to export again with a file password. (b) **Aegis** encrypted export
    and **2FAS** backup with a password: same. (c) **Proton Pass** Settings → Export with PGP encryption (ZIP with
    `data.pgp`): asks for the passphrase. (d) **KeePassXC** `.kdbx` (KDBX 4, Argon2) and a KeePass 2.x KDBX 3.1 file,
    one with a key file: Choose key file…, a wrong key file says "Wrong password or key file"; groups become tags, the
    recycle bin is skipped, attachments are listed in a warning, TOTP comes across. (e) A ZIP made with 7-Zip (AES-256,
    and ZipCrypto) around a Chrome CSV: asks for the ZIP password. (f) A KeePass database set to 2 GiB Argon2 memory:
    refused at once with "unusually heavy key derivation settings", no freeze. Neither the password nor the decrypted
    file is written anywhere (check `%APPDATA%\Pass` / the app's files and the logs).
72. **Windows Hello within the browser** (Windows app with Windows Hello on for the vault, Chrome or Edge and Firefox;
    automated: `cargo test -p pass-agent` (`unlock.cancel`, `unlock.hello_browser`), `cargo test -p pass-desktop`
    (`started_by`); docs/PROTOCOL.md "Unlocking from the extension"). Lock Passyble (also soft-locked). (a) On a sign-in
    page pick a login in the in-page menu: Windows' Hello dialog opens over the browser window, centred on it and with
    the keyboard focus (PIN field, face, fingerprint), and no Passyble window opens (no prompt window, no main window, no
    new taskbar button). Confirm: the login fills. Repeat by opening the popup (Hello starts by itself, see 73). (b) Lock again, pick a
    login, press **Cancel** in Hello's dialog: the extension offers the master password; type it: unlocked, the login
    fills. (c) Lock again, pick a login and, while Hello is starting, choose **Use master password instead** in the
    menu: the pending Hello closes (Windows may leave a dialog that was already up until you close it; the browser must
    not stay disabled after that) and the password form is there. (d) Turn on **Confirm each fill**, unlock, fill: the
    "Confirm it's you" Hello dialog also opens over the browser without a Passyble window; Cancel refuses the fill.
    Auto-type with the same policy still shows the prompt window. (e) Click another app right after picking the login:
    Hello still comes up (without an owner, in front). (f) An older Passyble without `unlock.hello_browser` still shows
    its "Unlock *vault*" prompt window. (g) **Master password in the menu** (automated: `Extension/test/content-unlock-frame.test.js`,
    `unlock-frame-page.test.js`): with Hello off for the vault, pick a login: the menu shows a **Master password** field
    with **Unlock** and "Only Passyble sees what you type here, not this website." right away, with the focus in it. A
    wrong password says so in the menu and clears the field; the right one unlocks and the login fills, the focus back in
    the page. In DevTools on the page, `document.querySelector('pass-menu').shadowRoot` is `null` and the iframe's
    document can't be reached from the console of the page. Esc in the field closes the menu. Firefox: the same. On a
    page with a strict `frame-src` CSP, or after the page covers the menu with a modal `<dialog>`, the field gives way
    to **Enter master password** (the popup) within a few seconds.
73. **One action to unlock, in all three apps** (automated: `Extension/test/content-menu-unlock.test.js` (a pick, ↓,
    a click into the field start Windows Hello once; openings on their own and lock changes don't; Cancel then the
    password; no new start right after a cancel), `popup-unlock.test.js` (the popup starts Hello as it opens, typing
    the password calls it off, no restart after a cancel, not for "Enter master password" or the unlock-only
    window), `background-unlock.test.js` (one Hello shared by the menu and the popup, 30 s quiet after a no); Android
    `BiometricAutoStartTest`). Windows app with Windows Hello on and set up for the vault, master password not due.
    (a) **Extension, fully locked** (Lock completely): on a sign-in page click once into the username field: Windows
    Hello opens at once over the browser, the menu says "Unlock Passyble to see your logins. Confirm with Windows
    Hello…" with **Use master password instead**. Confirm: the site's logins show with the first one highlighted;
    Enter fills it. Repeat with the Passyble icon and with ↓, and with Ctrl+Shift+L. (b) Fully locked again: reload
    a page whose username field has `autofocus`, and open a page that focuses the field by script: no Windows Hello,
    no menu. (c) Click into the field, press **Cancel** in Windows Hello: the menu shows the master password field
    with the focus in it and **Unlock with Windows Hello**. Press Esc and click the field again within 30 s: the
    choices, no Windows Hello; it starts again on a click after 30 s. (d) **Soft-locked**: one click on a login in
    the menu: Windows Hello at once; confirm: the login fills (one click in total). (e) **Popup**: lock, click the
    toolbar icon: Windows Hello starts at once (Chrome closes the popup as Hello takes the focus: that is expected);
    confirm, open the popup again: unlocked, the list. Lock, open the popup, Cancel in Hello, open the popup again:
    the master password field has the focus, no Windows Hello on its own; **Use Windows Hello** starts it. In
    Firefox (the popup may stay open) type into the master password field while Hello is starting: Hello is called
    off. Soft-locked: click a login in the popup: Hello at once, then it fills. (f) **Windows app**: Lock completely
    with the window open, then click the tray icon: Windows Hello starts once by itself, the master password field
    shows under "Confirm with Windows Hello, or type your master password."; Cancel: the password field has the
    focus. Restart Passyble: Hello starts exactly once (no double prompt). Auto-type hotkey while
    locked: the "Unlock *vault*" prompt opens with Hello over it at once and **Use master password instead**
    (opens the main window's form with the focus in the field). With **Confirm each fill** on, auto-type: "Confirm
    it's you" with Hello at once; Cancel in Hello: the prompt asks for the master password in its own window; a
    wrong one says so, the right one types the login; **Use Windows Hello** tries Hello again; 5 wrong ones refuse.
    (g) **Android** (biometric unlock on): lock, reopen the app: the fingerprint prompt at once; "Use master
    password": the field is focused with the keyboard up; rotate: no new prompt. Cancel by tapping outside: no
    loop; Home and back: the prompt once. Autofill: tap the locked suggestion in another app: the sheet opens with
    the prompt already up; a fingerprint fills. Credential Manager (passkey or password sign-in, Passyble chosen
    while locked): the same. Master password due (Settings → Unlock, "after the phone restarts", then restart): the
    field is focused, no prompt. Fail the fingerprint 5 times: the lockout message under the focused field, no
    loop.

74. **Extension: the in-page UI on top of a site's sign-in modal** (Chrome/Edge/Brave and Firefox 125+; automated:
    `Extension/test/content-layering.test.js` in jsdom). Make two local test pages (any static server, e.g.
    `npx http-server`): (1) a sign-in form (e-mail and password) inside `<dialog>`, opened by a button with
    `dialog.showModal()`, with `::backdrop { background: rgba(0,0,0,.5) }`; (2) the same form inside a
    `position: fixed; inset: 0; z-index: 2147483647` overlay `<div>` appended to `<html>` after the page loaded,
    its card with `transform: translateZ(0)`. Save a login for the test host first. On each: (a) open the modal,
    click into the e-mail field: the Passyble icon is in the field and the dropdown opens below it, in front of the
    modal and its backdrop (not dimmed, not cut off at the dialog's edge); a click on the login fills both
    fields and the modal stays open. (b) Fully locked: the master password field in the dropdown takes the focus
    and typing works. (c) Submit (page 1: the dialog closes; keep it open once by preventing the submit's default):
    the "Save login?" banner is in front and **Edit**, typing into its fields, **Save** work, also while the
    dialog is still open. (d) With the menu open, let the page open a second modal dialog that doesn't contain the
    field (e.g. `setTimeout(() => other.showModal(), 2000)`): the icon and menu disappear; close it: they come
    back. (e) A page without modals and a page with a dark-mode extension (Dark Reader, filter mode): the
    menu still shows below the field and clicks fill. (f) Sub-frame: the same form in a same-site `<iframe>`
    inside page 1's dialog: the menu shows inside the frame over its content.
75. **Android: no save offer on system screens, PIN pads and lone password fields** (Samsung Galaxy with One UI,
    Android 11+; automated: `Android/app/src/test/.../autofill/SaveRulesTest.kt`; rules in Android/README.md
    "When Passyble offers to save"). Passyble is the autofill service, the vault unlocked, a login saved for one
    native app (e.g. Discord) and none for a second app with a sign-in. (a) **Secure Folder**: open it and unlock
    with its PIN, then switch it to a password and unlock again: no Passyble dropdown or chip on the field, and no
    "Save to Passyble?" afterwards. (b) **Lock screen**: lock the phone, unlock with the PIN / password: no
    dropdown, no save sheet (also with the vault locked). (c) **Settings PIN confirm**: Settings -> Lock screen ->
    Screen lock type (asks for the current PIN / password), and Settings -> Biometrics -> Fingerprints: nothing
    from Passyble on the confirm screen. (d) **Wi-Fi password**: Settings -> Connections -> Wi-Fi -> a network
    with a password, type it and connect; also from the quick panel's Wi-Fi tile: no dropdown, no save sheet.
    (e) **SIM PIN** (if a SIM with a PIN is at hand: Settings -> Security -> Other security settings -> Set up SIM
    card lock): nothing from Passyble. (f) **Real app sign-in still saves**: in the second app, sign in with a
    username and a password typed by hand: "Save to Passyble?" appears and the login is saved with the app; sign
    in again with the saved login picked from the dropdown and unchanged: no sheet. Typing only a password with
    the username field left empty: no sheet. (g) **Sign-up saves**: create an account in an app (username or
    e-mail and new password, or "Generate strong password"): saved; an identifier-first app (username on one
    screen, password on the next): saved with the username. (h) **Lone password field**: an app screen that asks
    only for a password (re-auth, an app's own lock) for an app without a saved login: no sheet; for the app
    with the saved login, a changed password there offers "Save" and updates that login. (i) **PIN pads in
    apps**: a banking or app-lock screen with a number pad and no username: no sheet, and no dropdown unless a
    login for exactly that app is saved (then only that login). (j) **Never for this app**: in the second app,
    submit another login and tap **Never** on Android's sheet: the toast says Passyble won't offer to save there;
    submitting again shows no sheet, filling still works. Settings -> Autofill -> **Never save** lists the app;
    remove it and the sheet comes back. With the vault locked, the unlock sheet after "Save" has **Never for this
    app**, which does the same without unlocking. In Chrome, **Never** on a site's sheet lists the site
    (registrable domain) instead of Chrome. (k) **Websites unchanged**: a site's sign-in in Chrome or Samsung
    Internet still offers to save with a password only (username on an earlier page).
76. **Password checks before saving, on the device only** (Windows app, extension with the Windows app, Android;
    automated: `password_check::tests` in core (each issue, reuse without the edited item and the trash, locked and
    empty vault), `password_check_*` in `Core/agent/tests/protocol.rs` (codes, locked and soft-locked, input limits,
    rate limit, not activity), `Extension/test/background.test.js` ("password check" tests: codes only, the banner's
    token, not reachable from content scripts), `Extension/test/content-banner-issues.test.js`,
    `Extension/test/popup-editor.test.js` ("password check"), `Core/desktop-app/ui/test/password-issues-model.test.mjs`,
    Android `PasswordIssueMessagesTest`). Watch the network (a logging proxy, or Resource Monitor on Windows and
    `adb shell dumpsys netstats` or a proxy on Android) during all of it: no request is made for these checks.
    (a) **Windows editor**: open a login and type `password`: after a short pause "This is one of the most common
    passwords." with **Use a strong password instead**; `Xk9#qv`: "Short: use at least 12 characters."; the password
    of another saved login: "You use this password for 1 other login." (opening that other login itself does not count
    its own password); the username or the site's name from Websites inside the password: "This password contains your
    username." / "This password contains the site's name.", gone a moment after the username or websites change; a
    previous password of this login: "You used this password before for this login."; **Use a strong password
    instead** fills a generated password, shown in clear, and the list turns into a small green "Strong"; an empty
    field shows nothing; a login with a weak password shows the warning as the editor opens; saving a weak password
    works (warning only); typing fast and pausing always shows the latest text's result.
    (b) **Extension banner**: sign in on a test site with `github123` (or the password of another saved login): the
    **Save login?** / **Update password?** banner lists the problems under its question, in its closed shadow root (the
    page's DOM has neither the password nor the texts; check with DevTools Elements), with no "use a strong password"
    (the site already has it). **Edit**, change the password: the list follows 350 ms after typing stops; a strong
    random one: the list goes away. Update password: the login being updated does not count as reuse. Locked: the
    banner still lists the password-only problems (no reuse line) and Save unlocks as before. With an older Passyble
    desktop app (no `password.check` in `status.features`) the banner looks as before.
    (c) **Extension popup editor**: Edit a login: the same lines under the password as in (a), debounced while typing,
    **Use a strong password instead** fills a generated one, "Strong" when all is well; the vault soft-locked: no unlock
    prompt for the check.
    (d) **Android editor**: as (a) under the password field (about 300 ms after the last change of password,
    username, websites, apps or title); the fix uses the generator dialog's starting options (20 characters).
    (e) **Android save sheets**: lock the vault, sign in on a site with a weak password and tap Android's "Save to
    Passyble?": the unlock sheet lists the password-only problems above "Never for this site" (no reuse, no fix);
    saving still works after unlocking. "Update username/email?" (a saved password with a new username, autofill and
    Credential Manager on Android 14+): the problems under the text, without a fix. Unlocked, a new login with a weak
    password: the "Saved to Passyble" toast has the main problem on a second line. Android's own system save prompt
    is unchanged. In logcat the password never appears.
77. **No save offer for a login that is already saved** (Windows app with the extension in Chrome/Edge and Firefox,
    Android; a test site with `ann@example.com` / `pw1` saved for `https://example.test`, "Keep list visible when
    locked" on unless said otherwise; automated: `Core/agent/tests/protocol.rs` (`save_check_never_offers_a_login_saved_as_is`,
    `save_writes_nothing_for_a_login_saved_as_is`, `save_check_change_form_without_username_updates_the_login_it_changes`),
    `Extension/test/background-save-locked.test.js`, `Extension/test/content-save-recheck.test.js`,
    `Android/.../SaveDecisionTest.kt`).
    (a) **Unlocked, typed by hand**: sign in with `ann@example.com` / `pw1`, then with ` ANN@Example.com ` / `pw1`:
    no banner. On `https://www.example.test/login` and `https://accounts.example.test/`: no banner. On the plain
    `http://example.test/` page: no banner (and the login is not filled there). `pw2`: "Update password?". Another
    username with `pw1`: "Update username?". Another username and password: "Save login?".
    (b) **Identifier-first**: enter the e-mail on one page, the password `pw1` on the next: no banner; reload the
    password page directly (the e-mail step not seen) and submit `pw1`: no banner.
    (c) **Soft-locked**: lock (soft), sign in with `ann@example.com` / `pw1`: no banner. Unlock within 5 minutes
    (Windows Hello, the desktop app or the extension's unlock form): still no banner. Lock, sign in with
    `ann@example.com` / `pw-new`: no banner yet; unlock: "Update password?" appears on that tab. Lock, sign in with
    a username the site doesn't have: "Save login?" at once; Save unlocks and saves.
    (d) **Fully locked** (Lock fully, or "Keep list visible when locked" off): sign in with `ann@example.com` / `pw1`:
    "Save login?" shows (nothing can be checked); unlock from the desktop app while it is on screen: the banner
    goes away by itself. Again, and press Save instead: it asks to unlock, then says "Already saved in Passyble";
    the desktop list has no second login and the login's "Modified" time is unchanged.
    (e) **Trash**: move the login to the trash, sign in with it: "Save login?" (saved as a new login); restore the
    trashed one: no banner for it any more.
    (f) **Android**: unlocked, pick the Passyble suggestion and sign in unchanged: no system sheet, no toast. Type the
    same login by hand: Android's own "Save to Passyble?" sheet shows (a platform limit, see Android/README.md "Already
    saved unchanged"); tap Save: no toast, nothing changes (the item's modified time stays). Locked: the unlock sheet
    comes first, then nothing happens. `pw-new`: "Password updated". On a plain `http://` page in a browser with
    the login saved for `https`: nothing saved. Credential Manager's save-password (Android 14+) with the saved
    login: succeeds silently.
78. **No Windows Hello on its own: boot, sign-in, resume** (Windows laptop with Windows Hello on for the vault,
    "Start with Windows" on, Brave (or Chrome) set to start with Windows and to continue where you left off, with
    tabs open on a sign-in page with saved logins, a page that asks for a passkey as it loads (e.g. a "verify it's
    you" passkey page) and a page with a 2FA code toast; automated: `Core/desktop-app/src-tauri/src/startup.rs` tests,
    `Core/desktop-app/ui/test/unlock-model.test.mjs`,
    `Core/agent/tests/protocol.rs` (`requests_the_extension_sends_on_its_own_never_prompt`,
    `a_page_passkey_request_while_locked_answers_locked_without_an_unlock_prompt`),
    `Extension/test/bridge.test.js`, `Extension/test/background.test.js`, `Extension/test/content-main.test.js`,
    `Extension/test/popup-unlock.test.js`).
    (a) **Reboot**: sign in to Windows and wait a minute without touching anything: Passyble is in the tray
    (locked), Brave restores its tabs, and no Windows Hello dialog (Passyble's or Windows' own Security dialog for
    Passyble) appears at all. The restored passkey page falls back to the browser's own passkey dialog or does
    nothing, without a Passyble prompt.
    (b) **Open Passyble from the tray** (icon click or Open): the unlock screen starts Windows Hello once. Cancel it:
    the password form, Hello one click away. Close the window and open it again from the tray: Hello once more. Same
    from the Start menu (a second launch). Right after sign-in, while Windows Hello still reports itself
    unavailable for a few seconds: the window shows the password form and switches to Windows Hello by itself
    when it becomes ready (within about 30 s).
    (c) **Resume from sleep / Win+L** with the window open and with it in the tray, "Keep list visible when locked"
    on and off: sign in again; no Windows Hello prompt by itself; a 2FA code toast that was on a page is gone. The
    window shows the list (soft lock) or the unlock form with the Windows Hello button, nothing started.
    (d) **Auto-lock** with the window open (set 1 minute, "Keep list visible when locked" off): the unlock form
    shows, Windows Hello does not start until you click it (or open the window from the tray).
    (e) **The user's own actions still start it**: in the browser, pick a login in the in-page menu while locked,
    or open the toolbar popup: Windows Hello over the browser; a site's "Sign in with a passkey" button: the
    unlock prompt, then the passkey; the auto-type hotkey: Windows Hello in Passyble's prompt window.
79. **No developer text for users** (Windows app, Android; automated: `Core/desktop-app/ui/test/errors.test.mjs`,
    `Core/desktop-app/src-tauri/src/errors.rs` tests, `Core/core/src/i18n_tests.rs` `english_has_no_developer_text`,
    android `UiStringsTest.noDeveloperTextInAnyLanguage`, `FriendlyErrorTextTest`, `CoreNetworkErrorsTest`).
    No message, label or tip may show raw OS or library text, HTTP status codes or bodies, HRESULTs, file paths of
    the app, build or config words ("this build", OAuth client, Developer Mode, MSIX) or `pass-server` commands;
    the detail goes to the log (`%LOCALAPPDATA%\Pass\logs\pass.log`, Android logcat).
    (a) **Build without Google sign-in** (no `google-oauth.env`, no `PASS_GOOGLE_CLIENT_ID`): no Google option on
    the welcome screen, in Add vault, in Settings → Sync, in the Get started checklist or the sync tutorial. A vault
    that was backed up to Drive by another build shows "Not available in this version of Passyble" with Turn off
    only (no delete-the-copy box), and its sync pill says the same in plain words, never a sign-in request.
    (b) **Android release build whose signing SHA-1 isn't registered** with Google: Back up to Google Drive shows
    "Google sign-in isn't working in Passyble right now..." with other options; logcat (tag `PassGoogleDrive`) has
    `DEVELOPER_ERROR`.
    (c) **Errors in plain words**: vault file on a removed USB drive (save, unlock), export to a read-only folder,
    a server that answers 500 or 418, a self-signed server, a wrong pairing link, Windows passkeys on a copy that
    can't register its package (shows "Not available in this version of Passyble", no Developer Mode button), the
    auto-type hotkey taken by another program. Each says what happened and what to do; `pass.log` has the detail.
    (d) **Developer options** (Settings → Autofill: extra extension IDs, helper paths, Developer Mode for Windows
    passkeys) only show in debug builds or once extension IDs were added to `settings.json`.
80. **Android: the setup checklist names the default browser** (phone with Passyble's Autofill still off, so the
    "Finish setting up Passyble" card shows; repeat with Autofill on and Passkeys or Code notifications still off).
    Set the default under Android Settings → Apps → Default apps → Browser app, return to Passyble (no restart: the
    row is re-read when the screen resumes) and check the **Using ...?** row, its icon and button, and Settings →
    Autofill → **Autofill in ...**. (a) **Chrome**: "Using Chrome?", Chrome's steps (Settings → Autofill services →
    Autofill using another service, then restart), **Open Chrome** opens Chrome's autofill page. (b) **Brave**:
    "Using Brave?" with Brave's own name and icon, the generic wording ("turn on autofill with another service in
    its settings (if it has the option), then restart it"), **Open Brave** starts Brave; confirm in Brave whether
    the option exists and what it is called there. (c) **Samsung Internet** and (d) **Firefox**: "<Browser> uses
    Passyble automatically once autofill is on.", no button, and the row disappears from the card once Autofill is
    on (it stays in Settings). Fill a login in each. (e) **No default** (clear it, or a fresh phone where links ask
    "Open with"): "Using a browser?" with the short generic hint and no button. (f) An unlisted browser (e.g. Kiwi
    or Opera): its name and icon with the generic wording and **Open ...**. Dark theme and a long browser name:
    the row wraps, the button stays on one line.
81. **The login fills right after the unlock** (Windows app with Windows Hello on for the vault, Brave or Chrome and
    Firefox; automated: `cargo test -p pass-agent` (`a_fill_right_after_an_unlock_goes_straight_through`,
    `requests_dont_wait_for_a_slow_vault_write`, `locking_saves_a_use_that_was_still_waiting`), `cargo test -p
    pass-desktop` (`the_fill_right_after_an_unlock_does_not_ask_again`), `Extension/test/content-menu-unlock.test.js`,
    `content-unlock-frame.test.js`, `popup-unlock.test.js`, `background-unlock.test.js` (the fill is the next request
    after the unlock answers, with no timer)). Soft-lock Passyble, pick a login in the in-page menu: (a) confirm
    Windows Hello: the login is filled the moment the Hello dialog closes, with no pause you can notice. (b) Cancel
    Hello and type the master password in the menu: the login fills as soon as the key derivation is done (about as
    long as the main window's own unlock takes), not later. (c) The same from the popup (a soft-locked login, Windows
    Hello and then the master password) and with **Open Passyble**. (d) Fully locked: after Hello the site's logins
    show at once. (e) Turn on **Confirm each fill** with After confirming **Every time**, lock, pick a login and
    unlock with Hello, then once more with the master password: no second Windows Hello dialog for that fill; the
    next fill asks as usual. With After confirming 1 minute: fills within the minute after the unlock don't ask.
    (f) Vault in a OneDrive folder with a sync account (WebDAV, Google Drive or Passyble Server): unlock from the
    menu several times; the fill never waits for the sync that starts with the unlock. (g) After a password unlock
    that sets Windows Hello up again (its blob was removed), the login fills first and Windows Hello's set-up dialog
    follows. The fill counts as a use: the login moves up in the list a moment later, also after locking at once.
82. **Where the time goes around Windows Hello** (Windows app, Brave or Chrome; automated: `cargo test -p pass-agent`
    (`timing::tests`), `cargo test -p pass-desktop` (`host_browser_pairs_are_remembered_exactly`)). Run
    `setx PASSYBLE_TIMING_LOG "%TEMP%\passyble-timing.log"`, quit and start Passyble and the browser again, then (a)
    soft-lock and pick a login in the in-page menu, confirm Windows Hello; (b) with **Confirm each fill** on and
    **Every time**, fill a login while unlocked and confirm. `%TEMP%\passyble-timing.log` gets one line per step of
    each request (`app` and `host`, see Core/desktop-app/README.md, "Timing the fill path"): note the time from
    `unlock.hello: request received` (or `logins.fill: request received`) to `hello: dialog requested` and to
    `hello: dialog shown` (before the dialog), and from `hello: dialog answered` to `logins.fill: answered` and the
    host's `logins.fill: answer sent to the browser` (after it). The file never holds a URL, username, item name or
    secret. `setx PASSYBLE_TIMING_LOG ""` and a restart of both turn it off.
83. **Confirm each fill, Every time: logins always ask, the confirmed login's 2FA code doesn't** (Windows app with
    Windows Hello, the extension; automated: `cargo test -p pass-desktop` (`every_time_*` in `hello/policy.rs`),
    `cargo test -p pass-agent` (`an_unlock_for_a_fill_names_its_login`, `fills_and_codes_are_checked_per_login`),
    `Extension/test/background-unlock.test.js` ("an unlock for a login picked while locked says which one")).
    Settings → Unlock → Confirm each fill on, After confirming **Every time**. (a) Lock, unlock in the main window,
    then within 30 s fill a login from the in-page menu: Windows Hello asks for that fill. (b) Lock, pick a login
    in the in-page menu: one Windows Hello dialog (the unlock), the login fills; the same with the master password
    in the menu's field, with the popup's form (soft-locked fill, copy of a password, copy of a 2FA code) and with
    **Open Passyble**. (c) Right after a confirmed fill of a login with 2FA, its code on the next page (or picked
    again from the menu because it was wrong, several times) fills without asking for 2 minutes; after that it
    asks. (d) The 2FA code of another login asks, and filling the same login's password again asks. (e) With
    After confirming 1 minute everything is as before: fills within the minute after an unlock (any unlock) or a
    confirmation don't ask, and the pending code never asks. (f) Copying a password or 2FA code from the popup's
    search results (the desktop app copies it) asks as before; right after an unlock it doesn't, once.
84. **Passkey sign-in offered on its own** (Windows app, the extension in Chrome, Edge and Brave; automated:
    `Extension/test/content-passkey-prompt.test.js`, `bridge.test.js` and `background.test.js` ("passkey.find"),
    `cargo test -p pass-agent` (`passkey_find_*`, `a_passkey_picked_in_the_browser_*`, `use_another_device_*`),
    `cargo test -p pass-desktop` (`every_time_a_passkey_sign_in_*`, `the_passkey_prompt_answers`)). A passkey for
    webauthn.io in Passyble (item 4). (a) Open webauthn.io (it asks for passkey autofill as it loads): the
    "Sign in with your passkey?" card shows at the top right with the account; **Sign in** signs in at once, with
    no "Sign in with a passkey" window (Windows Hello only under Confirm each fill). (b) Reload, **Not now**: the
    card goes and stays away on that page, the username field still offers the passkey in the Passyble menu and
    the browser's own passkey autofill still works; reload: it is back. (c) Two passkeys for the site: the card lists
    both, a click on the second signs in with it. (d) Lock (soft, "Keep list visible"), reload: the card says
    Passyble is locked and offers **Unlock and sign in**: one Windows Hello dialog (also with Every time), then
    signed in; the same with the master password field in the card after Cancel in Windows Hello. Lock completely,
    reload: "Sign in with a Passyble passkey?" with **Unlock** and no account; it unlocks the same way, then the
    passkeys (one: signed in). (e) A site's own "Sign in with a passkey" button (modal `get()`): the card in the page lists
    the passkeys, no desktop window (item 85); **Use another device** shows the browser's own dialog (QR code,
    security key). (f) A page
    with a modal dialog open over the form: the card is above it and clickable; a page that draws over the card
    or makes it see-through: clicks do nothing. (g) Options → **Offer passkey sign-in** off: no card, the menu
    entry stays. (h) A site without a passkey in Passyble, and a page that never calls `get()`: no card.
85. **A page's own passkey requests answered in the page** (Windows app, the extension in Brave, Chrome and Edge;
    automated: `Extension/test/content-passkey-modal.test.js`, `bridge.test.js` ("a page's own get() waits for the
    card", "create() saved from the card", "Use another device", "older desktop app"), `test/e2e/passkey.e2e.mjs`
    (every registration and sign-in clicks the card; "Use another device" with a stand-in for the browser's own
    WebAuthn), `cargo test -p pass-agent` (`passkey_create_options_*`, `a_passkey_saved_in_the_browser_*`,
    `a_declined_check_keeps_*`)). (a) webauthn.io **Register**: "Save a passkey for webauthn.io in Passyble?" at the
    top right with the account; **Save with** lists the site's logins and **New login**; **Save passkey** saves it,
    no Passyble window; with **Confirm each fill** only Windows Hello's own dialog over Brave. With two vaults the
    card names the open one. (b) **Authenticate** (modal `get()`): "Sign in with your passkey?" with the account;
    **Sign in** signs in, no "Sign in with a passkey" window. Two passkeys: pick one. (c) **Use another device**:
    Brave's own (or Windows') passkey dialog, Passyble out of it; **Cancel**, the close button, Esc: the page reports
    it was cancelled. (d) Soft-lock, Authenticate: the card lists the accounts and **Unlock and sign in**: one Windows
    Hello dialog over Brave (also with **Every time**), then signed in; Cancel in Windows Hello: the master password
    field inside the card ("Only Passyble sees what you type here"), **Unlock** signs in. Lock completely: the card
    ("Sign in with a Passyble passkey?") shows no account, **Unlock** unlocks the same way, then signs in (several passkeys: the list). The same
    for **Register** (**Unlock and save**). (e) With Passyble also on as the Windows passkey provider (Settings →
    Passkeys): Windows' "Choose where to save your passkey" / sign-in dialog does not show for these requests, only
    after **Use another device**; a passkey saved from the card is offered in Windows' dialog for a native app (or
    in a browser without the extension) within a few seconds. (f) Without the extension (or with Options →
    **Use Passyble for passkeys** off) the browser and Windows behave as before. (g) With `PASSYBLE_TIMING_LOG`
    (item 82) the log shows `passkey.get: request received`, `passkey: picked in the browser`, the `verify:` and
    `hello:` steps, `passkey: signed`; a save `passkey: consent given in the browser` … `passkey: saved`.
86. **A passkey request never goes to Windows on its own** (Windows app, the extension in Brave, Chrome and Edge;
    automated: `Extension/test/content-passkey-modal.test.js` ("fully locked", "no passkey", "not running",
    "errors", "frame", "Use another device"), `content-passkey-prompt.test.js` ("fully locked" conditional card),
    `bridge.test.js` ("answers the card decided never go to the browser", "starts the content script"),
    `background.test.js` ("passkey.start_app"), `test/e2e/passkey.e2e.mjs` (mock agent: locked after boot, no
    passkey, not running; the browser's own WebAuthn is a stand-in and never runs), `cargo test -p pass-agent`
    (`timing_log`), `cargo test -p pass-native-host` (`timing_lines_name_an_answers_error_code_never_its_message`)).
    With `PASSYBLE_TIMING_LOG` set (item 82): (a) restart the PC (or quit Passyble and start it again, vault
    locked, nothing kept), open a site with a Passyble passkey that asks as it loads, or click its "Sign in with a
    passkey": "Sign in with a Passyble passkey?" with **Unlock**, no Windows Security dialog; **Unlock**: Windows
    Hello (or the master password field in the card), then signed in (several: the list). The log has
    `passkey.find: answered with an error (locked)` and no `passkey.get` before the unlock. (b) A site whose
    passkey lives in Windows Hello or on a phone (not in Passyble): "No Passyble passkey for this site";
    **Use another device**: the browser's own dialog (Windows Security in Brave), only then. Cancel: the page says
    it was cancelled, no dialog. (c) Quit Passyble, click a site's passkey sign-in: "Passyble isn't running";
    **Open Passyble**: "Opening Passyble…", then the card goes on (locked: **Unlock**). The log has
    `host: passkey.find: error sent to the browser (agent_unavailable)`. (d) A site's "Create a passkey" while
    locked: the save card with **Unlock and save**, Windows' "Choose where to save" only after **Use another
    device**. (e) Options → Passkeys → **Use Passyble for passkeys** off: no card, the browser's own
    dialog as without Passyble; on again: the card. (f) The log never holds a site, username or message: only codes
    such as `(locked)`, `(not_found)`, `(agent_unavailable)`.
87. **Client secrets audit decisions** (Android phone with a lock screen and, if you have one, a paired watch;
    Windows app; extension; automated: `cargo test -p pass-core` (`plain_http_only_on_local_networks` in
    `server.rs` and `tests/webdav.rs`), Android unit tests `WebDavAddressTest`, `OtpNotificationPolicyTest`,
    `ExportChoiceTest`, `ClipClearRuleTest`, `LogsTest`). (a) WebDAV over plain http: Android Settings → Sync →
    WebDAV (and Add a vault → WebDAV) with `http://cloud.example.com/dav/pass.vault`: the explanation shows under
    the address while typing, Save & sync is off, nothing is saved; `http://192.168.1.10/dav/pass.vault`,
    `http://nas.local/...`, `http://nas.lan/...` and any `https://` address are accepted. The Windows app's
    Settings → Sync refuses the public `http://` address with the core's explanation. An `http://` public address
    saved by an older version: the sync status shows the same explanation and nothing is sent. (b) 2FA
    notification: with Settings (Android) → Notifications → lock screen set to **show all content**, lock the
    phone while the notification is up: the lock screen shows "One-time code ready / Unlock your device to see
    it", never the code or the site; unlock: the full notification with Copy and Show. The paired watch shows no
    Passyble 2FA notification. After updating from an older build, Android's app notification settings list the
    new "One-time codes" category only (the old one counts as deleted). (c) Export: the screen opens on
    **Encrypted (recommended)**; Passyble JSON or CSV shows the warning (anyone and any app with the file can read
    every password; not to a cloud app such as Google Drive, Dropbox or OneDrive) and Export stays off until "I
    understand ..." is ticked; switching format clears the tick. The exported files are as before. (d) Clipboard:
    copy a password in the Android app, then force-stop Passyble (Settings → Apps → Passyble → Force stop) or let
    Android kill it: within about a minute the clipboard is empty. Copy a password, then within 45 s copy some text
    in another app while Passyble is in front (split screen) or comes back to the front: that text stays.
    `adb logcat` of a release build shows no debug or info lines from Passyble, and its warnings name only an
    exception class (no addresses, names or messages). (e) Website icons in setup: the first-run screens of the
    Windows app and Android say that icons are downloaded directly from each website and where to turn them off
    (every language). The extension shows the app's icons and doesn't repeat it (owner review 2026-11-06). (f) Passyble Server first admin: see item 25.
88. **A generated password shows once, with Copy; a filled login never shows** (the extension in Chrome, Edge and
    Brave; automated: `Extension/test/content-reveal.test.js`, `background-generate.test.js`, `options-page.test.js`,
    `Core/agent/tests/protocol.rs`). (a) On a site with a saved login, fill it from the inline menu, the popup,
    the keyboard shortcut, the context menu's "Fill with Passyble", a pick that unlocked Passyble first (Windows
    Hello or the master password in the menu) and "Fill on this page": no callout, the field shows dots, and
    Options → Autofill has no "Show the filled password" row. (b) On a sign-up form, pick **Generate strong password**
    in the menu (its preview stays masked until the eye is clicked): the menu closes and a small "Generated password"
    callout under the confirmation field shows the password in the field's font size (digits and symbols in
    colour) with a **Copy** button; the fields still show dots. The same with the generate button beside the Passyble
    icon and the context menu's **Generate password**. (c) The callout goes at once on: Tab or a click into another
    field, a click on the page or the submit button, any key in the field (a lone Shift does not), Enter, Alt+Tab to
    another window, switching tabs, scrolling the field out of view, Passyble locking (popup **Lock**, Win+L,
    auto-lock), and after 30 s while the field keeps the focus. Clicking into the field itself keeps it. Coming back
    to the field shows nothing again, and clicks on the callout beside the button go to the page. (d) **Copy**, at
    least half a second after it appeared: the button says "Copied" for a moment, the callout stays, the field keeps
    the focus and the form is not submitted. Paste it into Notepad: the same password. It is not in Windows clipboard
    history (Win+V) and is gone from the clipboard after 45 s. Quit Passyble (or use a desktop app from before
    `generate.copy`) and repeat: Copy still works through the browser and the clipboard is still cleared after 45 s.
    (e) A sign-up form in a cross-origin iframe: the callout shows only in that frame, by the field; the other frames
    show nothing. (f) DevTools on the page: the Elements panel shows a `pass-reveal` element with a closed shadow root
    and nothing else new; `document.body.innerText`, `window.find('<first characters of the password>')` and the
    console show nothing of the password. `document.querySelector('pass-reveal').click()` copies nothing. A stored
    `revealFilled` from an earlier version changes nothing and is gone after the update.

89. **2FA links open Passyble** (Android phone; Windows with the NSIS installer, Chrome or Edge; demo data only; automated:
    `Core/core/src/otpauth_tests.rs`, `Core/desktop-app/src-tauri/src/otpauth.rs` and `otpauth_handler.rs`,
    `Core/desktop-app/ui/test/otpauth-model.test.mjs`, `Android/app/src/test/.../ui/otpauth/OtpauthRulesTest.kt`).
    **Android.** (a) With the app closed and the vault locked:
    `adb shell am start -a android.intent.action.VIEW -d "otpauth://totp/Demo:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Demo"`. (adb's remote shell cuts the link at `&`; the
    label still names Demo.) The lock screen says "Unlock to add the 2FA code for Demo", with Cancel. Cancel: the link is gone, and unlocking
    later shows nothing about it. Again, then unlock: **Add 2FA code** shows Demo, alice@example.com and "6 digits, every 30 s,
    SHA1". (b) Back and Cancel: no item was added. (c) With a login "Demo" (or website demo.example.com) already there: it's
    preselected as **Best match**; **A new login** is also offered. Add: the item opens with the code. (d) Open the link again:
    that login says it already has a 2FA code, isn't preselected, and picking it shows the warning and **Replace 2FA code**.
    (e) With the app running, on any screen and soft-locked: the same command asks to unlock in the sheet; dismissing it
    drops the link. While the confirmation is up, let the app soft-lock: it goes back and asks again. (f) Recents shows only
    Passyble's normal, blank (`FLAG_SECURE`) card, nothing for the link; reopening from Recents doesn't bring the
    confirmation back after Add or Cancel. `adb shell dumpsys activity activities | findstr JBSWY3` finds nothing, and
    `adb logcat -d | findstr JBSWY3` shows nothing. (g) Each gets a plain message and no screen: `otpauth://hotp/Demo?secret=JBSWY3DPEHPK3PXP&counter=1`,
    `otpauth://totp/Demo` (no secret), `otpauth://totp/Demo?secret=not-base32!`,
    `otpauth://totp/Demo?secret=JBSWY3DPEHPK3PXP&algorithm=MD5`. (h) With no vault yet: a message, nothing else. (i) A demo
    export link `otpauth-migration://offline?data=...` opens Import's preview after the unlock. (j) A QR code of the demo
    link, opened from a scanner app or the camera, does the same as (a). In every language, the new texts read properly.
    **Windows.** Save this demo page as a file and open it in the browser:
    `<a href="otpauth://totp/Demo:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Demo">Add Demo</a>`.
    (k) On a PC with no other handler, install: `HKCU\Software\Classes\otpauth\shell\open\command` points at
    `Pass.exe "%1"`, and Settings shows Passyble has the links. With another handler registered first (a fake
    `HKCU\Software\Classes\otpauth`, command `notepad.exe "%1"`), install: it's untouched, and Settings says another app has them
    and offers the button, which then takes them over without an admin prompt. If Windows' default apps prefer another app, the row
    goes to Windows' settings instead. (l) Click the link with Passyble closed, then with it running in the tray: the main
    window shows up. Locked: the unlock screen says what's waiting with Cancel, and Windows Hello doesn't start by itself.
    After the unlock: the same details and choices as on Android; Cancel leaves nothing, Add saves. The secret is nowhere
    in the window's page (dev tools), the log or `PASSYBLE_TIMING_LOG`. (m) A hostile link gets a plain message, and adds no flags:
    `otpauth://totp/x?secret=JBSWY3DPEHPK3PXP" --background "` and a label with `<img src=x onerror=alert(1)>` (shown as plain
    text or refused). (n) Uninstall: the key is gone if it pointed at this install, and another app's key stays. An update
    leaves it. `otpauth-migration://` isn't registered on Windows on purpose (use Import). **Extension:** nothing of its own;
    clicking the link goes to the browser's external protocol prompt and then Passyble; **Scan QR on this page** still works.
90. **Menus and fills only on login fields** (the extension in Chrome, Edge and Brave; Android phone; demo data only; automated:
    `Extension/test/detect-username.test.js`, `content-username.test.js`, `Android/app/src/test/.../autofill/UsernameEvidenceTest.kt`).
    Save a demo login for the page's site first (a local test page, any address), and save each form below as a local page served
    from `http://localhost`. **Extension.** (a) A CMS-like editor: `<form><label>Title <input name="post_title"></label><textarea></textarea>
    <label>Publish <input name="publish"></label><label>Password <input type="password" name="post_password"></label><button>Publish</button></form>`.
    Click, Tab into and press the down arrow in Publish and Title: no icon, no menu. Tab into the password: the icon, no menu. Click it:
    the logins; pick one: only the password fills, Publish and Title stay as they were. Lock Passyble fully and click it again: nothing starts
    (no Windows Hello); the icon or the down arrow still asks. (b) With the focus in Publish: the fill shortcut, the context menu's fill and the
    popup's Fill don't change any field. With the focus in the password: they fill it, alone. (c) Type a password in (a) and press Publish: no
    save banner. (d) An unlabelled classic login form, `<form><input name="f1"><input type="password" name="f2"><button>Sign in</button></form>`:
    the menu opens on both fields, the pick fills both, and typing and submitting offers to save with that username. Same with `name="login"`,
    `type="email"`, `autocomplete="username"`, a phone field, and on github.com and accounts.google.com (both steps of Google's sign-in).
    (e) A username-only step, then a password-only step: the second fills only the password, and typing it there saves with the first
    step's username. (f) A password-only page with a stray text field elsewhere: the menu on the password fills only it, and typing and
    submitting offers to save with an empty username you can fill in. (g) A settings page with name, e-mail, phone, website, a bio box and
    "Current password": no icon on the e-mail field; the current password opens and fills alone. A sign-up form with many fields keeps its e-mail as
    the username, and the generator opens on its own; a change-password form too. (h) A page with a search box, filters and a form-less
    password field: the search and filter boxes get nothing. (i) 2FA fields and card and address forms behave as before. **Android**
    (Chrome with Passyble as its autofill service, or Passyble's own autofill in a browser that reports forms). (j) The page of (a): the dropdown on
    Publish offers no login username; a login picked on the password field fills only the password. (k) The page of (d): the login fills both
    fields, and the save prompt names the username. A native app's sign-in with an unlabelled text field and a password keeps working.
91. **Paste with no vault yet** (Android phone with Gboard, and Samsung Keyboard if you have one; a test profile or fresh install with no
    vault; demo data only; automated: `Android/app/src/test/.../ui/components/NoImeLearningTest.kt`). Copy
    `https://cloud.example.com/remote.php/dav/files/demo/pass.vault` in another app and open Passyble. (a) Add a vault with WebDAV (under More
    options): the keyboard isn't in incognito mode on the address field and offers the clipboard; tap it and the address is in the field.
    Opening the screen shows no "pasted from your clipboard" notice. (b) Clear the field and tap its Paste icon: the same address, and the notice
    now. (c) The user name field, and the vault name under More options: no incognito either. (d) WebDAV password and master password:
    incognito as before; their Paste icon fills them, masked, and nothing shows the value until you tap show. (e) Sign in to Passyble Server: the
    address and user name fields offer the clipboard. Copy a demo pairing link (`pass+server://` from a demo server) and paste it with the keyboard's suggestion:
    it opens the pairing flow, and the clipboard is empty afterwards. The same with the Paste icon. (f) Add a vault, Pairing link (under More
    options): that field stays in incognito; "Paste link" works and clears the clipboard, and so does a long-press paste followed by Use.
    (g) Create a demo vault and lock it, then Add a vault with WebDAV: the address field is in incognito now, the Paste icon still
    works. New item, notes, search: incognito, as before. (h) Remove the demo vault: with no vault left, (a) works again.
92. **The vault in this browser: first run, create, a copy** (Chrome, Edge and Brave on Windows, plus a Mac, a Linux desktop and a
    Chromebook or ChromeOS Flex when you have them; a fresh browser profile with no Passyble app for that browser; a Google test
    account; demo data only; automated: `Extension/test/background-vault.test.js`, `welcome-vault.test.js`, `local-wasm.test.js`,
    and `test/e2e/browser-vault.e2e.mjs` in Chromium). Load the unpacked extension (with `src/wasm/` built and the Google client id
    set: `npm run google-config`, docs/GOOGLE_DRIVE.md "Browser extension"). (a) The setup guide's choices: item 96. (b) Continue with
    Google Drive, Create a vault: under 8 characters says too short, the hint follows the Windows app's (Weak / Good / Strong),
    different repeats are refused, the "can't reset" warning is there; no backup step. (c) The popup: logins of the page, the lock
    button, no chip while synced; its tooltip says "vault in this browser"; the ⋯ menu has "Google Drive" and no "Add Passyble
    Server". (d) Options → Download a copy saves `Passyble-<date>.vault`; it opens in the Windows app (as a vault file) with the same
    master password. (e) Chrome's own extension storage: DevTools of the service worker → Application → IndexedDB `passyble` holds
    the encrypted file; Storage → Session holds only `passBrowserVault` (a key, a vault id, a time) while unlocked and
    `passGoogleToken` (a token, its expiry, the account); nothing in Sync storage.
93. **The vault in this browser: everyday use** (as in 92; demo sites or the test pages of `Extension/test/e2e/pages.mjs`).
    (a) Sign in on a site: the save prompt saves into the browser vault; the in-page menu lists and fills the login; the 2FA code
    of a login with 2FA fills on the next step. (b) Generate a password in a sign-up form, the username generator, a login edited
    in the popup, the popup's vault search and "Fill on this page" for another site's login (the popup asks "Fill a login of
    another site?" first). (c) Copy a password in the popup: pasted elsewhere it works; after 45 s the clipboard is empty; on
    Windows it may show in Win+V (expected, Options says so). (d) A card of a vault made in the Windows app (opened from Google Drive):
    the in-page menu's card fill asks "Fill this card?" in the popup or a small window; Cancel fills nothing. (e) A passkey sign-in
    or registration on webauthn.io: the card says passkeys need the Passyble app for now; "Use another device" opens the
    browser's own dialog. (f) No "Open Passyble", no Windows Hello anywhere in browser mode.
94. **The vault in this browser: locking and the service worker** (as in 92). (a) Lock in the popup: the in-page menu offers only
    the master password field; the popup's form unlocks; a wrong password says so; five wrong ones in a minute say to wait.
    (b) Options → Vault → Lock after 1 min: unused for a minute, it locks (also with the browser idle and its service worker
    stopped: `chrome://serviceworker-internals` → Stop, then wait). (c) Unlocked, stop the service worker there and fill again: still
    unlocked, no master password asked. (d) Lock the computer (Win+L, macOS Ctrl+Cmd+Q): locked afterwards; with "Lock when the
    computer locks" off, not. (e) Close the browser and open it again; reload or update the extension: locked each time.
    (f) "Confirm each fill" on: each fill or password copy asks for the master password in the popup or a small window; picking
    a login while locked asks once (the unlock counts for that fill); closing the popup cancels the fill.
95. **Where the vault is: switching, and the delete guard** (Windows with the Passyble app installed, a second Chrome profile).
    (a) A fresh profile on a PC with the app: the first run picks the app silently (the app may start), the guide shows the app
    checklist with "Use Google Drive instead". (b) Options → Vault → Use Google Drive: the setup's vault part; after opening or
    creating one in Drive the extension fills from it and never starts or asks the app. (c) Switch back to the app: the browser
    vault is locked and kept; "Use the vault in this browser" returns to it, locked. (d) A Drive vault has no Delete vault in
    Options (Sign out forgets the copy, item 105). A legacy vault (item 106): Delete vault refused until a copy downloaded in the
    last hour, then it needs the master password; afterwards the popup says "No vault yet" with "Continue with Google Drive" and
    "Sign in", and Upload a vault file puts the copy into Drive with all logins. (e) A browser-mode profile on
    a PC where the app was installed later: the popup shows the tip once (dismissed: never again); nothing switches by itself.
    (f) Firefox: app mode only, nothing about a browser vault.
96. **The vault in Google Drive: setup choices** (as in 92; automated: `welcome-vault.test.js`, `popup-vault.test.js`). (a) A
    fresh profile without the app: titles only, "Continue with Google Drive", "Sign in", and on Windows "Get the Windows app";
    no "Create a vault" or "Open a vault file" of their own, no backup step. (b) The popup says "No vault yet" with "Continue with
    Google Drive" and "Sign in". (c) Continue with Google Drive on an account with no vault in Drive goes straight to Create a
    vault (name "Personal"); with vaults, "Choose a vault" lists them by name and change date, with "Create a vault" and "Upload a
    vault file". (d) In app mode with a browser vault kept here, the choices add "Use the vault in this browser".
97. **Google sign-in in Chrome, Edge and Brave** (`launchWebAuthFlow`; automated: `drive-sync.test.js`). In each browser, also
    one not signed in to a Google profile: Continue with Google Drive opens Google's own window with the account picker; after
    consent the vault list shows. Closing the window comes back to the choices with nothing changed. Ready says "In Google Drive
    (email)".
98. **Consent without the Drive permission** (a test account that never consented, or access removed at
    myaccount.google.com → Security → Third-party apps). Untick the Drive box on Google's consent screen: "Allow Passyble to use
    Google Drive, then try again.", nothing is created. Again with the box ticked: it works.
99. **Created in the browser, seen in the apps** (a Google test account on the Windows app and an Android phone). Create a vault
    "Browser test" in Drive, save a demo login. Windows: Add a vault → Restore from Google Drive lists "Browser test"; it opens
    with the same master password and has the login. Android: the same with Restore from Google Drive.
100. **Made in the app, opened in the browser** (as in 99). A vault the Windows app keeps in Drive: Choose a vault lists it, a
     wrong master password says so, the right one opens it with all logins. Upload a vault file: a `.vault` file and its master
     password go into Drive and show in the apps' lists.
101. **Two browsers, one vault** (Chrome and Edge, or two profiles, on the same Drive vault; automated:
     `Core/wasm/tests/drive.rs`, `drive-sync.test.js`). Edit a different login in each and the same login in both, a minute
     apart. After Sync now (or the popup opening after 5 min) both have every change; the same login keeps the later edit; the
     Windows app shows the same after its sync. Nothing is duplicated.
102. **Offline changes wait** (automated: `drive-sync.test.js`). Turn off Wi-Fi (or the service worker's DevTools → Network →
     Offline). Save a login: the popup shows "Not synced", Options' Google Drive row "Not synced". Stop the service worker
     (`chrome://serviceworker-internals`) and wait: the change is still there. Back online: within a few minutes (retries from 30 s
     up to 15 min) or with Sync now, "Synced <time>", and the apps see the login.
103. **Token expiry** (unlocked for over an hour, or remove `passGoogleToken` in the service worker's DevTools → Storage →
     Session). A change, or Sync now: synced without Google's window (silent renewal). With the browser signed out of Google
     (google.com → Sign out): "Sign in to Google again", no retry loop; Sign in again shows Google's window, then it syncs.
104. **Testing-status consent after 7 days** (Google Cloud app in Testing; a consent older than 7 days). The extension says "Sign
     in to Google again"; changes stay "Not synced" until Sign in again in Options, then they sync.
105. **Sign out with pending changes** (automated: `background-vault.test.js`, `options-vault.test.js`). Offline, save a login,
     Options → Sign out: "Changes not in Google Drive yet will be lost." with Sign out anyway and Cancel. Cancel keeps everything.
     Online, Sign out: no warning; the popup says "No vault yet"; Continue with Google Drive lists the vault again with the login.
106. **A vault kept only in this browser, on update** (a profile with a vault from a build before Google Drive). Load the new
     build over it (or reload): the setup guide opens at "Move your vault to Google Drive"; the popup shows "Only in this
     browser", Options an "Only in this browser" row. It still fills. Move to Google Drive asks for the master password when
     locked, signs in to Google and uploads; then the chip is gone and the apps list it. Never deleted by itself.
107. **A build without the Google client id** (`npm run google-config` with nothing set, then reload; automated:
     `package.test.js`). Continue with Google Drive says "Google Drive isn't set up in this build."; `npm run package` warns and
     still builds.
108. **Sign in to a Passyble account** (automated: `account-ui.test.js`). Setup → Sign in: the account's sign-in window, then
     "Passyble Cloud storage is coming soon." and Use Google Drive, which goes to item 96 (c). No prices or plans anywhere.

## 6. Performance on low-end phones

Target: a low-end Android phone (2 to 3 GB RAM, 4 slow cores, Android 10 to 16), taken as **10 times slower
per core than the dev PC** (the upper end of 6 to 10). Phone figures below are PC figures times 10.

### How to run

- **Guards** (every `cargo test -p pass-core`): `core/src/perf_tests.rs`, `perf_guard_*`. Debug build, limits about
  20 times what they take, so they fail on work that grows out of proportion (a save that re-seals every item, a
  keystroke that parses every site), not on a busy PC. The same file checks that the kept work answers exactly as
  before: `search_index_answers_as_the_calls_without_it`, `vault_search_is_the_same_with_kept_fields_and_follows_edits`,
  `lookalike_checks_are_the_same_with_kept_sites_and_follow_edits`, `search_shortcuts_change_no_result`,
  `url_match_shortcut_agrees_with_the_suffix_list`. The agent: `search_follows_changes_between_keystrokes`.
- **Benchmarks** (manual, optimized, one test at a time; profile `perf` is `release` without LTO, so it builds in a
  few minutes; numbers are within about 10 % of a release build):
  `cargo test -p pass-core --profile perf --lib perf_bench -- --ignored --nocapture --test-threads=1`
  Demo vaults of 50, 1 000 and 5 000 items (76 % logins with password history, 10 % with a passkey, notes, cards,
  identities, tags), three shared vaults of 500 items. Memory: a counting allocator in the test build, on only
  while a memory figure is taken (it would slow down the decrypting threads); timings stop before what was made is
  freed.
- **Extension WebAssembly** (Node): `npm test` in Extension runs `test/perf-wasm.test.js` (2 000 made-up summaries)
  when `src/wasm/` is built. For the 5 000-item vault: write it with
  `PASS_PERF_OUT=<dir> cargo test -p pass-core --profile perf --lib perf_write_wasm_fixture -- --ignored`, then
  `PASS_PERF_VAULT=<dir>/demo-5000.vault npm test`.

### Measured (2026-11-23, 5 000 items plus 3 shared vaults of 500 where it says "all vaults")

| what | budget on the phone | before: PC / phone | after: PC / phone |
|---|---|---|---|
| unlock with the master password (Argon2id 64 MiB, t=3, p=1) | 1.5 s, 96 MB | 142 ms / 1.4 s, peak 74 MB | 111 ms / 1.1 s, peak 74 MB |
| unlock with the device key (biometric) | 300 ms | 43 ms / 430 ms **missed** | 19.5 ms / 195 ms, peak 28 MB |
| open one shared vault (500 items) | 100 ms | 3 to 4 ms / 32 to 42 ms | 2.8 to 3.3 ms / 28 to 33 ms |
| one edit, then save | 200 ms | 7.4 ms / 74 ms | 6.2 ms / 62 ms (only the edited item is sealed again) |
| merge two copies (10 % edited elsewhere) | - | 17 ms / 174 ms | 15.5 ms / 155 ms |
| sync fingerprint | - | 0.17 ms / 1.7 ms | 0.2 ms / 2 ms |
| kept list (`vault_summaries`) | - | 12 ms / 120 ms | 5.8 ms / 58 ms |
| Android list search per keystroke (was `summaries_search_with_notes`, now `SearchIndex.search_positions`) | 16 ms | 31 ms / 307 ms **missed** | 0.9 to 1.2 ms / 9 to 12 ms |
| `multi_search` per keystroke, all vaults (no index) | 16 ms | 28 ms / 280 ms **missed** | 22 ms / 222 ms (callers that search per keystroke use `SearchIndex`) |
| `SearchIndex::new`, all vaults (once per change of the lists) | - | - | 26 to 32 ms / 260 to 320 ms, holds 10.7 MB (3.5 MB of it the summaries; 15.9 MB before the fields were packed) |
| `Vault::search` per keystroke (desktop) | 16 ms | 22 ms / 216 ms | 2.5 ms / 25 ms (most of it copying the matching items) |
| autofill unlocked: `Vault::find_for_url` | 16 ms | 2.3 ms / 23 ms **missed** | 1.4 ms / 14 ms |
| autofill and Credential Manager soft-locked: `summaries_for_url` with the list copied in / `KeptMatcher` | 16 ms | 3 ms / 30 ms **missed** | `for_url` 0.02 ms / 0.2 ms, `for_android_app` 0.01 ms; made once per soft lock in 4 to 6 ms / 41 to 61 ms, holds 0.8 MB |
| `multi_for_url`, all vaults / `SearchIndex::for_url` | 16 ms | 7.3 ms / 73 ms | 6.4 ms / 64 ms; with the index 0.04 ms / 0.4 ms |
| lookalike check, a login on a page (`lookalike_for_url`) | 5 ms | 2.6 ms / 26 ms **missed** | 0.003 ms (sites read once per change) |
| lookalike check on save (`lookalike_for_save`) | 5 ms | 5.5 ms / 55 ms **missed** | 0.18 to 0.24 ms / 1.8 to 2.4 ms |
| password health report | - | 387 ms / 3.9 s | 305 ms / 3.0 s (in the background) |
| breach check: hash and group every password | - | 30 ms / 300 ms | 21 ms / 210 ms (in the background) |

Extension (Node on the PC, the 5 000-item vault): unlock 265 to 222 ms; `logins.search` per keystroke 57 to 0.9 ms;
`logins.find` per page 19.5 to 2.9 ms; browser-mode Teams search per keystroke (home list plus `multiSearch`) about
140 ms to about 2 ms (`homeStamp` and a kept `SearchIndex`, `searchPositions`).

### What changed

- Core: search fields read once per item and kept (`SearchIndex`, `Vault::search`), characters the item lacks rule it
  out before any typo table; lookalike sites read once per vault change (`KnownSites`); page matching skips the Public
  Suffix List for hosts that can't share a site; a large vault's records are decrypted on up to 4 threads (not in
  WebAssembly) and their strings moved, not copied; the vault file is parsed once, and each item with its merge
  metadata in one pass (`item_and_meta`); title sorts compute each key once. A `SearchIndex` keeps each item's fields in
  one buffer. Page matching against kept lists reads each website entry once (`MatchUrl`), and `KeptMatcher` holds only
  what matching the soft-locked list needs. Argon2id parameters are unchanged.
- Agent (desktop and extension): `logins.search` and `logins.find` keep the lists between requests while no vault
  changes (`Vault::list_generation`), dropped with the search hits on a full lock.
- Android: the vault list searches through a kept `SearchIndex` (dropped on any lock); reading every item and summary
  after an edit, sync or use runs off the main thread; so does collecting the passwords for the breach check.
  Soft-locked autofill, its save sheet and the Credential Manager match through a `KeptMatcher` of the kept list
  (`KeptMatch`: made on the first request after a soft lock, dropped at a full lock and at the unlock), and matching an
  app against the websites that verified it remembers each site's registrable domain for that list.

### Still open

- Device-key unlock is within budget (195 ms estimated), so decrypting behind the kept list was not needed. If a real
  phone shows otherwise: show the kept list at once and decrypt behind it, a fill waiting for its item only.
- `SearchIndex` holds about 1.6 KB per item (half of it the summaries it answers with).
- On the phone itself: measure FFI copies, Compose list rendering and the master-password unlock (estimated
  1.1 s; Argon2id alone about 0.9 s) on a real 2 GB device.
