# Google Drive backup and sync

Passyble can keep each vault in the user's Google Drive, in the hidden app folder (`appDataFolder`), the
way WhatsApp keeps its backups. The vault then syncs between every device signed in to the same
Google account, and a new phone gets it back with "Restore from Google Drive".

Signing in with Google **only authorizes Drive access**. It doesn't replace the master password and
gives Google nothing it can decrypt:

- The file on Drive is the normal vault file (docs/ARCHITECTURE.md §1), already encrypted with the
  vault key, which is wrapped by the master password (Argon2id). Biometric / Windows Hello unlock
  works as before; it is local to each device.
- The access scope is `https://www.googleapis.com/auth/drive.appdata`. Passyble sees only its own hidden
  folder, not the user's files, and the user can't see or edit the folder in the Drive UI (Drive →
  Settings → Manage apps shows its size and can delete it).
- What Google can see: the account, that Passyble stores N files, their sizes and change times, and per file
  the vault id (a random UUID) and the vault's name ("Personal", "Work"). The name is stored readable so
  that a new device can list vaults before anything is unlocked (otherwise people could not tell which
  master password belongs to which vault); the apps say so where the name is asked for. A file with no
  name shows as "Unnamed vault" and the id's first characters. Everything else (item counts, titles,
  URLs, settings and secrets) is inside the encrypted file, and the name is kept out of logs.
  `src/gdrive/tests.rs` (`google_drive_never_sees_a_vault_secret`) checks every request and every stored
  byte for canaries, with the vault's name as the one allowed cleartext value, asserted explicitly.
- Losing the Google account means losing that copy, not the vault: every device keeps a full local
  copy. Losing the master password still means losing the vault; Google can't help.

## How it works

| piece | where |
|---|---|
| Drive v3 REST client and sync algorithm | `Core/core/src/gdrive.rs` (feature `gdrive`, on by default; same ureq + rustls stack as WebDAV) |
| Tests against a fake Drive | `Core/core/src/gdrive/tests.rs` |
| Android sign-in and tokens | `Android/.../vault/GoogleDrive.kt` (Google Identity Services `AuthorizationClient`) |
| Android flows | `VaultRepository` (restore / enable / disable / sync), `ui/vaults/AddVaultScreen.kt`, Settings → Sync |
| Desktop sign-in and tokens | `Core/desktop-app/src-tauri/src/google_oauth.rs` (loopback + PKCE, token endpoint, Credential Manager); tests against a fake token endpoint in `google_oauth/tests.rs` |
| Desktop flows | `Core/desktop-app/src-tauri/src/gdrive.rs` (sign-in, restore, enable / disable, background sync), `ui/views/google.js`, `onboarding.js`, `settings.js` |
| Browser extension | none of its own: Google Drive sync needs the Passyble app on the same computer, and the extension uses the app's vaults (see [Browser extension](#browser-extension)) |

**Files.** One file per vault, `pass-<vault id>.vault`, created in `appDataFolder` with
`appProperties` `pass_vault_id` and `pass_vault_name` (the vault's name, readable; rewritten by a sync when
the vault is renamed, one metadata `PATCH`). The vault id comes from the vault itself, so every device
finds the same file.

**Tokens.** The platform passes an OAuth access token on every core call (`GDriveConfig.access_token`).
The core never stores tokens and never sees refresh tokens or Google passwords. A token Drive refuses
(401, or 403 for a scope the user didn't grant) is `PassError::AuthRequired` (Kotlin
`PassException.AuthRequired`). The platform then gets a new token, or asks the user to sign in again.

**What one sync costs** (`gdrive_sync`). The local sync state (kept in the local vault file, never
uploaded) records the Drive file id, its `version`, its `md5Checksum` and a fingerprint of the remote
item versions:

| situation | requests |
|---|---|
| nothing changed anywhere | `files.get?fields=id,version,md5Checksum,…` (a few hundred bytes). 1 request. |
| local edit only | that, then `PATCH upload/…?uploadType=media&keepRevisionForever=true`, then `revisions.list` and unpinning the previous revision (`revisions.update`). 4 requests. |
| another device changed it | metadata, `alt=media` download, merge, `revisions.list` (to merge pinned revisions besides the head, usually none). If this device also has something new: metadata again (changed during the merge? then merge that too), then upload as above. |
| only the name changed (this device renamed the vault, or another device did) | metadata (version moved, same MD5): no download |
| first sync on a device | `files.list` by name; then download + merge, or create (multipart, 1 request) and list again to catch a twin |
| file created less than 7 days ago | also lists by name (1 small request), to catch a twin the first listing didn't show yet: every sync in the file's first hour, then at most every 10 min per file and app run |
| file > 5 MB | resumable upload (session + `PUT`) instead of `media` / `multipart` |

### How often it syncs

An edit reaches another device that is in use within about half a minute (about 15 s on average): this device uploads ~2 s after the last
edit (a burst of edits is one upload), and the other device's next check (every 20 s +-20 % while in use) sees the
new `version` and downloads. Change detection is the `files.get` above on the vault's own file id, so a device
downloads only when the version or MD5 changed. (The Changes API, `changes.list?spaces=appDataFolder`, would also
be one request per check, but needs a page token per account and reports every vault's file in the folder; the file
id is already known, so `files.get` is as cheap and simpler.)

| state | desktop (`desktop-app/src-tauri/src/sync_schedule.rs`) | Android (`vault/SyncSchedule.kt`) | Drive requests per minute, unchanged vault |
|---|---|---|---|
| in use | a Passyble window has focus, or the vault was used (window, extension fill) in the last 2 min: every 20 s | app in the foreground and unlocked: every 20 s | 3 |
| active | the user touched keyboard or mouse in the last 15 min (Windows `GetLastInputInfo`, macOS CoreGraphics; Linux: the vault's own use): every 2 min | n/a | 0.5 |
| idle | every 15 min | background: every 1 h (WorkManager, battery not low, skipped in battery saver) | 0.07 desktop, 0.02 Android |
| locked | nothing | the hourly run lists the app folder (1 request) and downloads only a changed file | 0 desktop, 0.02 Android |
| after a rate limit | in use: every 2 min for an hour | foreground: every 2 min for an hour | 0.5 |

Right away as well, when the last check is older than 20 s (30 s for autofill on Android): on unlock, window focus,
wake from sleep, the browser extension asking for logins; on Android on app open, autofill or the Credential Manager
being asked, and the network coming back. All intervals get +-20 % jitter. Nothing is checked while the vault isn't
backed up to Drive, while Google wants a new sign-in, or while locked on the desktop; offline checks fail without
reaching Google and back off.

On top of the checks: an edit costs about 3 more requests (upload, `revisions.list`, unpinning the previous
revision), receiving another device's change about 2 (download, `revisions.list`), and in the file's first hour every
check also lists by name (+1). Refreshing the access token (about hourly) goes to Google's OAuth endpoint, not to
the Drive API quota.

**Quota.** The Drive API project quota is about 12,000 requests per minute, shared by every user (per-user limits
are separate and far above a few requests a minute). Every device in use costs 3 requests a minute, so about 4,000
devices can be in use at the same moment. A more realistic mix of online devices (10 % in use, 30 % active, 60 %
idle or in the background) averages about 0.5 requests per device per minute: about 25,000 online devices. Locked
desktops cost nothing. If Google answers 403 `rateLimitExceeded` / `userRateLimitExceeded` or 429, the device backs
off (30 s doubling with jitter, at most 15 min; never a tight loop) and checks every 2 min instead of every 20 s for
the next hour; the count goes to the app log (desktop) or logcat (Android) and to "Report this problem"
(`sync.gdrive_rate_limited`). Ask Google for a higher quota (Google Cloud console, Drive API, Quotas) before the
number of devices in use at once nears 4,000.

**Concurrency.** Drive v3 has no conditional upload (no `If-Match`). The `version` field only promises
to increase, not to grow by exactly 1, so it can't detect a lost write either. Passyble handles this in
four ways:

1. **Narrow window.** When both sides changed, the version is checked again right before the upload.
   A write that landed during the download and merge is merged first instead of overwritten.
2. **Pinned revisions catch the remaining race.** Every upload asks Drive to keep its revision forever
   (`keepRevisionForever=true`), and right after uploading, the device lists the file's revisions
   (`settle` in `gdrive.rs`). A pinned revision other than its own that it doesn't already hold is
   another device's write that landed in the last moment before ours and was overwritten. The device
   downloads that revision (`revisions.get?alt=media`; Drive serves pinned blob revisions), merges it
   and uploads again. A revision is unpinned only once its contents are in a later upload that is
   pinned itself, so at every moment each write is in the head, in a pinned revision, or still on the
   device that made it, and normally only the head is pinned. If the check is interrupted (no
   connection), the local sync state says so (`unverified`) and the next sync does it; and any device
   that downloads a changed file also merges the pinned revisions besides the head, so the write
   survives even if both devices go away. If Drive refuses to pin (at most 200 pinned revisions per
   file), the upload is sent again without the pin. Tested in
   `an_overwritten_write_is_merged_by_the_device_that_overwrote_it`,
   `an_interrupted_check_runs_on_the_next_sync` and
   `an_overwritten_write_survives_when_both_devices_go_away`.
3. **Merge-by-item covers older clients.** A version without pins (or a write Drive won't serve)
   still loses only timing: the overwritten device keeps its changes locally, sees a newer version on
   its next sync, merges ours, finds its own items missing remotely and uploads them again. Merging is
   per item (field by field for concurrent edits of one item, ARCHITECTURE.md §1), and deletions are
   tombstones, so nothing is lost or resurrected.
   Tested in `an_older_clients_overwritten_write_comes_back_on_its_next_sync`.
4. **Twins.** Two devices creating the file at the same moment get two files. The oldest
   (`createdTime`, then id) is canonical. A device that sees several merges them all, uploads the
   union to the canonical file and deletes the others, but only those unchanged since it merged them
   (a twin written to meanwhile is kept and merged again on the next sync, flag `twins` in the local
   sync state). Right after a create, `files.list` may not show the other device's file yet, so while
   the file is less than 7 days old every sync looks it up by name again.

A rename (`appProperties`) moves the version too. Its new version is taken for "unchanged" only if the
MD5 is still the one this device knows, so an upload that lands just before it is still
downloaded on the next sync (`a_rename_right_after_another_upload_does_not_hide_it`).

## Google Cloud setup (step by step)

You need one Google Cloud project for all platforms. The UI is at <https://console.cloud.google.com>;
the OAuth pages are under **Google Auth Platform** (formerly "APIs & Services → OAuth consent
screen").

1. **Create a project**: project picker → *New project*, e.g. "Pass".
2. **Enable the Drive API**: *APIs & Services → Library → Google Drive API → Enable*. Without this,
   every call fails with "the Google Drive API is not enabled for this app's Google Cloud project".
3. **Branding**: *Google Auth Platform → Branding*: app name "Pass", user support e-mail, logo
   (optional, but needs verification if set), app home page, privacy policy link, authorized domain(s)
   for those links, developer contact e-mail.
4. **Audience**: user type **External**. While the app is in **Testing**, add up to 100 **test users**
   (the Google accounts you test with). Others get "access blocked".
5. **Data access (scopes)**: *Add or remove scopes* → add
   `https://www.googleapis.com/auth/drive.appdata` ("See, create, and delete its own configuration data
   in your Google Drive"). Google classifies it as **non-sensitive**. The apps need nothing else; Passyble
   gets the account e-mail from Drive's `about.get`, which this scope allows. (The browser extension asks
   for nothing: it never signs in to Google, see [Browser extension](#browser-extension).)
6. **Android client**: *Clients → Create client → Android*:
   - package name `com.sensyble.passyble` (before 2026-10-17 the app id was `com.sensyble.pass`: a client
     made for that package doesn't work for the current app);
   - SHA-1 of the signing certificate. Debug builds are all signed with the debug
     keystore committed at `Android/debug.keystore` (non-secret, password `android`, alias
     `androiddebugkey`; see Android/README.md), so they share one SHA-1:
     `50:37:A8:35:B6:0B:C7:09:69:A0:34:38:B7:11:73:41:B7:4E:88:20`
     (`keytool -list -v -keystore Android/debug.keystore -storepass android`). Don't register
     the per-machine `~/.android/debug.keystore`. Release: your release key's SHA-1. Builds installed
     from Google Play are re-signed by Google, so also add the **app signing key** SHA-1 from Play
     Console → *Test and release → App integrity*.
   - Create one Android client per SHA-1 (debug, release / upload, Play app signing). No Web client is
     needed: Passyble doesn't ask for a server auth code.
7. **Desktop client** (for the Windows app): *Clients → Create client → Desktop app*.
   Note the client ID and client secret. For installed apps the secret is **not confidential**
   (Google's own words), but the token endpoint usually still wants it, so ship it with the app.

### Registered clients (project `pass-511304`, "Sensyble Pass")

| client | type | identifies the app by |
|---|---|---|
| "Passyble Android (debug key)" | Android | package `com.sensyble.passyble` + SHA-1 `50:37:A8:35:B6:0B:C7:09:69:A0:34:38:B7:11:73:41:B7:4E:88:20` (the committed `Android/debug.keystore`, used by debug builds) |
| Older "Sensyble Pass Android (...)" clients | Android | earlier debug keystores (shared, local, CI); harmless to keep |
| "Passyble Android (upload key)" | Android | package `com.sensyble.passyble` + the upload key's SHA-1 `88:77:E4:E4:F4:6B:7C:D2:60:B2:5C:30:B9:9B:F1:67:87:DF:2A:31` (sideloaded release builds) |
| "Passyble Android (Play app signing key)" | Android | package `com.sensyble.passyble` + Play's app signing SHA-1 `C0:4C:43:A1:47:4F:4E:D2:58:51:D2:D3:D0:F8:D0:EB:5B:B9:8A:71` (installs from Google Play) |
| "Passyble iOS" | iOS | bundle id `com.sensyble.passyble`; its ID is committed in `iOS/Config/Base.xcconfig` |
| "Passyble Account" | Web application | Android's "Continue with Google" uses it as Credential Manager `serverClientId` (`passGoogleWebClientId` in `Android/gradle.properties`); it is safelisted in the Firebase project `passyble` (Authentication, Google, "Safelist client IDs from external projects"). Don't delete it. |
| "Sensyble Pass for Windows" | Desktop app | client ID + secret compiled into the Windows, Linux and macOS builds |

Google allows one Android OAuth client per package + SHA-1 across all projects. Don't add the SHA-1s to the
Firebase project `passyble` (only the SHA-256s): Firebase would create its own Android client there and block
the one Drive needs here.

The Windows client's ID and secret live in the git-ignored `Core/desktop-app/src-tauri/google-oauth.env`
(or in the environment of the release PC for release builds). Never commit that file. A debug APK built
with the committed debug keystore gets Google sign-in without any other local setup.

### Where the IDs go

- **Android**: nothing is compiled in. Google recognizes the app by package name and signing
  certificate. Turn the feature on with the Gradle property `passGoogleDrive=true`, which sets
  `BuildConfig.GOOGLE_DRIVE`. Put it in `Android/gradle.properties` for everyone,
  `~/.gradle/gradle.properties` for your machine, or pass `-PpassGoogleDrive=true` for one build. Without it, or on phones without Google Play services,
  the Google options are hidden. If the property is on but the Android client is missing or has the
  wrong SHA-1, sign-in fails with "Google sign-in isn't working in Passyble right now" (status
  `DEVELOPER_ERROR`, logged to logcat with the tag `PassGoogleDrive`; the user only sees the plain message and
  other backup options).
- **Desktop**: the Desktop client's ID and secret are compiled in. Set them for the build in the
  environment, or put them in the git-ignored `Core/desktop-app/src-tauri/google-oauth.env`
  (`build.rs` reads it):

  ```powershell
  $env:PASS_GOOGLE_CLIENT_ID = "1234567890-abc.apps.googleusercontent.com"
  $env:PASS_GOOGLE_CLIENT_SECRET = "GOCSPX-..."
  cargo build -p pass-desktop      # or cargo tauri build ...
  ```

  ```
  # Core/desktop-app/src-tauri/google-oauth.env
  PASS_GOOGLE_CLIENT_ID=1234567890-abc.apps.googleusercontent.com
  PASS_GOOGLE_CLIENT_SECRET=GOCSPX-...
  ```

  The environment wins over the file; changing either rebuilds. For a quick test without rebuilding,
  `%APPDATA%\Pass\settings.json` may set `"google_oauth": { "client_id": "…", "client_secret": "…" }`
  (restart Passyble). No client ID means no Google option anywhere, as on Android. The secret of a Desktop
  client is **not confidential**: Google says so for installed apps ("the client secret is obviously
  not treated as a secret"), PKCE protects the code exchange, and anyone can extract it from the binary.
  So it is fine in release builds; it isn't a credential of anyone's account. Without
  `client_secret` Google's token endpoint answers `invalid_request`, so set both.
- **Released Windows builds**: the release PC sets
  `PASS_GOOGLE_CLIENT_ID` and `PASS_GOOGLE_CLIENT_SECRET` for the build.
  Set both or the installer ships without the Google option; the build
  doesn't fail without them (it prints a warning), but it does fail if only the ID is set. The Android release build is separate (Gradle
  property above).

### Publishing (leaving "Testing")

- **Testing** status: only test users can sign in, and Google **expires their authorization 7 days
  after consent**, refresh tokens included. On Android, sync then pauses with "Sign in to Google again
  to keep backing up this vault" until the user taps *Sign in to Google again* in Settings → Sync.
  That is fine for development, not for real users.
- **In production** (*Audience → Publish app*): `drive.appdata` is non-sensitive, so only the basic
  **brand verification** applies. That means a verified home page and privacy policy on domains you
  own (verified in Search Console), and an app name and logo that match. There is no sensitive-scope
  review, no demo video and no CASA security assessment (those are for sensitive and restricted scopes,
  such as full `drive`).
- Google limits refresh tokens to 100 per Google account per client ID; older ones are silently
  invalidated (only relevant to the desktop flow).
- The privacy policy should state: Passyble stores only the encrypted vault file, its random id and the vault's name in
  the app's hidden Drive folder; Passyble can't access other Drive files; Google can't read the vault.

## Android

- `Identity.getAuthorizationClient(context).authorize(AuthorizationRequest.builder().setRequestedScopes(listOf(Scope(drive.appdata))))`.
  On explicit sign-in, `setPrompt(Prompt.SELECT_ACCOUNT)` shows Google's account picker. When the
  result `hasResolution()`, its `PendingIntent` is launched (`StartIntentSenderForResult`) for
  consent, and `getAuthorizationResultFromIntent` gets the token. The account e-mail comes from
  `gdriveAccount(token)` (Drive `about.get`). Only the e-mail is stored per vault (plain prefs, not a
  secret). Tokens are memory-only.
- Every sync run asks for a token silently with `setAccount(Account(email, "com.google"))`. Play
  services caches and refreshes it. On `AuthRequired` the token is dropped (`clearToken`) and asked
  for once more. If Google needs the user (`hasResolution()`, e.g. access revoked or Testing-mode
  expiry), the vault is marked "Sign in to Google again": sync pauses (`SyncManager` skips it, the
  worker doesn't retry) and the quiet status line says so. Settings → Sync → *Sign in to Google
  again* launches the consent UI.
- UX:
  - **Welcome / Add a vault**: *Use on this phone* has a **Back up to Google Drive** switch. When it is
    on, *Create* first runs Google sign-in, then creates the vault with the backup on. *Restore from
    Google Drive* is a peer of *Sign in to Passyble Server*: sign in → list of vaults on that account
    (name, last backup, size) → master password → restore.
  - **Settings → Sync** (vaults that don't use Passyble Server): *Back up to Google Drive…*. Once on, it
    shows the account, *Sync now* and *Turn off* (optionally deleting the copy on Drive). Google Drive
    replaces WebDAV for that vault; one sync account per vault.
- Dependency: `com.google.android.gms:play-services-auth:21.6.0` (minSdk 23, AAR metadata has no
  compileSdk or AGP floor, so it fits AGP 8.7.3 / compileSdk 36). 22.0.0 (Aug 2026) removes the old
  Google Sign-In APIs, which Passyble doesn't use; move to it with the next AGP / compileSdk bump.

## Desktop (Windows)

The same core calls (`gdrive_sync`, `gdrive_list_vaults`, `gdrive_download`, `gdrive_delete`,
`gdrive_account`) with the same UX as Android:

- **Welcome / Add a vault**: *Use on this PC* has a **Back up to Google Drive** switch (with the
  zero-knowledge note). Create then signs in with Google first ("Finish signing in with Google in your
  browser", with Cancel), creates the vault with the backup on and uploads it; a failed upload is a
  warning and background sync retries. *Restore from Google Drive* is a peer of *Sign in to Passyble
  Server* (also under *Add existing vault*): sign in → the vaults on that account (name, last backup,
  size; "already on this PC") → master password → restore. The local copy is
  `%LOCALAPPDATA%\Pass\vaults\<vault id>.vault` (no location to choose, like a Passyble Server vault),
  listed as "Google Drive · <e-mail>".
- **Settings → Sync → Google Drive → Back up…** (not for Passyble Server vaults; it replaces
  plain WebDAV, which moves under *WebDAV*). It signs in, syncs with that account
  (uploads, or merges a copy already there) and only then saves the account. Once on: the account,
  the note, *Sync now* (or *Sign in to Google again*) and *Turn off* (dialog with *Also delete the copy
  on Google Drive*).
- **Sign in to Google again**: when Google refuses the refresh token, every vault of that account is
  marked `sign_in_needed` in `settings.json`. Background sync skips them (no retry loop); the vault
  view shows a quiet **Sign in to Google again** pill (click: sign in for that account, then sync) and
  Settings says "Paused: Google needs you to sign in again."
- Settings: the vault entry gets `"google_drive": { "account_email": "…" }` instead of `webdav`
  (one sync account per vault), plus `"sign_in_needed": true` while paused. Older builds ignore it.

The OAuth flow for installed apps (<https://developers.google.com/identity/protocols/oauth2/native-app>),
as implemented in `google_oauth.rs`:

1. **Loopback + PKCE.** Bind `127.0.0.1:0` (an ephemeral port). Create a `code_verifier` of 43-128
   random URL-safe characters, `code_challenge = base64url(SHA-256(verifier))`, and a random `state`.
   Open the **system browser** (Google blocks embedded WebViews) at
   `https://accounts.google.com/o/oauth2/v2/auth?client_id=…&redirect_uri=http://127.0.0.1:<port>/&response_type=code&scope=https://www.googleapis.com/auth/drive.appdata&code_challenge=…&code_challenge_method=S256&state=…&access_type=offline&prompt=select_account%20consent`
   (`access_type=offline` + `prompt=consent` guarantee a refresh token; *Sign in to Google again*
   adds `login_hint=<email>` and drops `select_account`). Send `code_challenge_method=S256`
   explicitly, because the default is `plain`. Passyble asks for nothing but `drive.appdata`; the e-mail
   comes from `gdrive_account` (Drive `about.get`).
2. The loopback listener waits for the request with the right `state` (others, e.g. a favicon or a
   stale tab, get a 404/400 and are ignored), reads `code` (or `error`), answers with a small "You can
   close this tab and return to Pass" page and closes. It gives up after 5 minutes or on Cancel.
3. **Exchange** with `POST https://oauth2.googleapis.com/token` (form-encoded): `client_id`,
   `client_secret`, `code`, `code_verifier`, `grant_type=authorization_code`, `redirect_uri` (identical
   to step 1). The response has `access_token`, `expires_in`, `refresh_token`, `scope`. Check that
   `scope` contains `drive.appdata`.
4. **Store the refresh token in Windows Credential Manager** (generic credential, target
   `Pass/GoogleDrive/<email>`, through the `keyring` crate like the WebDAV passwords), one per
   account; several vaults share it. It is written only once a vault uses the account (a sign-in for
   the restore list that goes nowhere stays in memory). Never written to settings files or logs.
   Access tokens are in memory only. The e-mail (from `gdrive_account`) is stored in the vault's
   settings, as Android does.
5. **Refresh** with `POST https://oauth2.googleapis.com/token`, `grant_type=refresh_token`, before
   `expires_in` runs out or after an `AuthRequired`. `invalid_grant` means the user revoked access,
   the 7-day Testing expiry hit, or the token was evicted by the 100-per-account limit. In that case,
   delete the credential and mark the vault "Sign in to Google again" (quiet status, no retries,
   background sync skips it). Only then: a network error, a Google outage (5xx), a Credential
   Manager that can't be read right now, or Drive refusing a token Google has just refreshed keep
   the sign-in, and the sync tries again later. A refused token is deleted only while Credential
   Manager still holds that very token, so a "Sign in to Google again" that lands while a
   background sync refreshes the old token is kept. Storing the token reads it back, so a write
   that didn't stick fails at once instead of an hour later.
6. **Turn off**: forget the account for that vault. If no other vault uses it, revoke with
   `POST https://oauth2.googleapis.com/revoke` (`token=<refresh token>`, form-encoded) and delete the
   credential. Optionally delete the Drive copy (`gdrive_delete`). Removing a vault from the list
   deletes the credential after the undo window if no other vault uses the account (no revoke).
   Revoking ends the grant of that Google account for the whole project: other PCs and the Android
   app using the same OAuth project then get `invalid_grant` too and ask to sign in again.
7. Sync triggers: as for WebDAV in `Core/desktop-app/src-tauri/src/background.rs`. The agent
   (`Agent::sync_gdrive`) calls `gdrive_sync` with a fresh access token and persists the vault
   afterwards; on `AuthRequired` the app refreshes the token once and tries again.

## Browser extension

The browser extension (Chrome, Edge, Brave, Opera, Firefox; Safari ships inside the macOS and iOS apps) has no
Google Drive code and no Google sign-in of its own. **Google Drive sync in the extension requires the Passyble
desktop app on the same computer**: the app signs in to Google and syncs (see [Desktop](#desktop-windows)), and
the extension fills from the app's vaults over native messaging (app mode), as it does for every other vault of
the app. There is no Google OAuth client for the extension, no `identity` use for Google (the permission stays
for the optional Passyble account sign-in) and nothing to register for it in the Google Cloud project.

What the extension shows (`Extension/src/welcome/`, popup, Options):

- **Setup guide, "Google Drive sync"** (also the popup's menu, **Set up sync** and **Use Google Drive** under
  Sign in): "Google Drive sync needs the Passyble app on this computer", with **Download the Passyble app**
  (https://www.passyble.com/download) and **Check again**, which looks for the app on a fresh native connection.
  Found: **Use the app** switches the extension to the app. The app checklist then says where Drive is turned
  on: "For Google Drive sync, open Settings in the Passyble app, then Sync, and turn on Google Drive."
- **A vault kept only in the browser** (the extension's own vault, browser mode): it has no sync, so the
  extension shows "This vault is only on this device" when it is created and as a dismissible reminder above
  the popup's list (**Set up sync** leads to the screen above; **Not now** hides it for 30 days for that vault).
  To move such a vault into the app: Options → **Download a copy**, then open the `.vault` file in the
  Passyble app and turn on Google Drive there.
- **A vault record from older extension builds that synced Drive themselves** (`source: 'drive'` in the
  extension's IndexedDB; no released build had Drive set up): it keeps opening and saving in the browser,
  nothing syncs, and the extension shows "Google Drive sync needs the Passyble app" for it. Its copy on Drive is
  untouched; the Passyble app can restore it from Drive.

`Core/wasm` still builds the core's Drive sync (feature `gdrive-core`, `DriveCall`) into the WebAssembly the
extension loads; the extension doesn't call it.

## Checklist when it doesn't work

| symptom | cause |
|---|---|
| Google options not shown (Android) | `passGoogleDrive` not set, or no Google Play services on the phone |
| Google options not shown (Windows) | built without `PASS_GOOGLE_CLIENT_ID` (env or `google-oauth.env`), or `--no-default-features` |
| "Google sign-in isn't working in Passyble right now" (Windows; `pass.log` says `invalid_client`) | wrong client ID / secret, or the client isn't of type *Desktop app* |
| browser shows "redirect_uri_mismatch" (Windows) | the client isn't a *Desktop app* client (Web clients need registered redirect URIs) |
| "Google sign-in isn't working in Passyble right now" (Android; logcat `PassGoogleDrive` says `DEVELOPER_ERROR`) | no Android OAuth client for this package + SHA-1 (debug vs release vs Play signing) |
| "access blocked: app not verified / not a test user" | app in Testing and the account isn't a test user |
| "Google Drive isn't available right now" every time | the Drive API isn't enabled for the project (step 2) |
| works for a week, then "Sign in to Google again" | Testing status (7-day expiry); publish the app |
| "Sign in to Google again" soon after Turn off on another device or the phone | Turn off revokes the account's grant for the whole project (step 6) |
| "Sign in to Google again" and you don't know why (Windows) | set `PASSYBLE_TIMING_LOG` to a file path and restart Passyble: the lines below say which step it was |
| "Pass wasn't allowed to use its app folder" | the user unticked the Drive permission on the consent screen |
| "Google Drive sync needs the Passyble app on this computer" (extension) | expected: the extension syncs only through the desktop app. Install it, turn on Google Drive in it, then **Check again** |
| **Check again** still says the app isn't there (extension) | the app's native messaging host isn't registered for this browser: open Passyble, Settings, Autofill to register it |

Timing-log lines of the Windows Google sign-in (`PASSYBLE_TIMING_LOG`, codes only, never a token,
an e-mail or Google's text; `pass.log` gets Google's reason for an `invalid_grant`, such as "Token
has been expired or revoked."):

- `gdrive: signed in (kept in memory until a vault uses it)`, `gdrive: token stored`,
  `gdrive: store failed (<code>)` (`platform`, `no_storage_access`, `not_read_back`, ...);
- `gdrive: token refreshed`, `gdrive: refresh failed (network)`, `(http <status>)` or
  `(<Google's error code>)`;
- `gdrive: credential read failed (<code>)`: Credential Manager didn't answer, the sign-in is kept;
- `gdrive: drive refused the access token (refreshing)`, `gdrive: drive refused a fresh token (401,
  sign-in kept)`;
- `gdrive: signed out (invalid_grant)`, `gdrive: signed out (no stored sign-in)`, then
  `gdrive: vault paused (sign in to Google again)`;
- `gdrive: sign-in removed (turned off, revoking at Google)`, `gdrive: sign-in removed (no vault
  uses it)`, `gdrive: access revoked`, `gdrive: revoke failed`.
