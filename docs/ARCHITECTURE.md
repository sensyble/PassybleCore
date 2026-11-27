# Passyble: architecture

One vault, used the same way on Android and Windows: passwords, TOTP codes and
passkeys sit in one item, so a single tap or click fills a whole sign-in, including the 2FA step
and the passkey ceremony. No phone-for-codes, laptop-for-passwords split.

```
                        ┌─────────────────────── Core/core/ (Rust, pass-core) ───────────────────────────┐
                        │ vault format & crypto · items · TOTP · passkeys (WebAuthn authenticator)        │
                        │ URL / Android-app matching · password generator · merge · WebDAV sync           │
                        └───────────────┬─────────────────────────────────────────────┬──────────────────┘
                              UniFFI (Kotlin)                                    Rust crate dependency
                                        │                                             │
  ┌─────────────── Android/ ───────────┴───────────┐        ┌────────── Core/ (desktop, Windows first) ────────────┐
  │ AutofillService    passwords + OTP inline,     │        │ desktop-app/ (Tauri v2): unlock, vault UI, tray,     │
  │                    keyboard (inline) chips     │        │      global hotkey auto-type for native apps, TOTP   │
  │ OtpNotifier        persistent notification w/  │        │      popup, passkey consent dialog                   │
  │                    live code + Copy when no    │        │ agent/ (lib): unlocked session, auto-lock, IPC       │
  │                    OTP field is fillable       │        │      server (named pipe / unix socket), protocol     │
  │ CredentialProvider passkeys + passwords for    │        │ native-host/ (bin): browser Native Messaging bridge  │
  │ (Android 14+)      Credential Manager; also    │        └──────────────────────────┬───────────────────────────┘
  │                    hybrid (QR) for Windows     │                                   │ Native Messaging (stdio)
  │ Compose UI, biometric unlock (Keystore)        │        ┌──────────── Extension/ (MV3: Chrome, Edge, Firefox) ──┐
  └────────────────────────────────────────────────┘        │ form detection + inline menu, OTP fill / OTP toast,   │
                                                            │ navigator.credentials interception (passkeys), popup  │
                                                            └───────────────────────────────────────────────────────┘
```

Sync is end-to-end encrypted: the encrypted vault file sits in storage you control (a WebDAV server such
as Nextcloud, a folder kept in sync by OneDrive, Dropbox or Syncthing, or the hidden Passyble folder in your
Google Drive, §10). There is no Passyble cloud service;
the optional self-hosted [Passyble Server](https://github.com/sensyble/PassybleServer) (§9) is one more WebDAV host that adds per-device tokens,
version history and backups. Every device merges by item. WebDAV and Passyble Server addresses take plain
`http://` only for this device or a private network (loopback, RFC 1918, link-local, 100.64.0.0/10, IPv6
unique-local and link-local, `*.local`, `*.lan`, `*.internal`, `*.home.arpa`): one rule in the core
(`plain_http_refused`, `check_plain_http`), checked by the apps' forms and again by every `webdav_*` call, so a
WebDAV app password never crosses the internet unencrypted.

## 1. Vault format (v1)

A personal vault, opened with its master password. Shared vaults (Family, Teams, direct shares) use version 2
of the same file, whose key is wrapped for each member instead (§15). A personal vault linked to a Passyble
account uses version 3, whose key is wrapped by the account key and opens with the Passyble password (§18).

* **KDF**: Argon2id, default `m = 64 MiB, t = 3, p = 1`, 16-byte random salt → 32-byte key-encryption key (KEK).
* **Vault key (VK)**: 32 random bytes, generated once per vault. Stored *wrapped* by the KEK with
  XChaCha20-Poly1305 (24-byte random nonce, AAD = `"pass/vk/v1:" + vault_id`).
  **Changing the master password always replaces the VK** (`change_password(old, new)`,
  `change_master_password`, design D5 of the server breach audit): a copy of the file from before the change
  (a server's version history, Google Drive's revisions, a backup) opens only with the old password, and
  cracking it gives only the old VK, which reads nothing written later. Every item and the key check are
  re-encrypted on the next save, and each earlier VK is kept in `previous_keys` (sealed with the new VK, AAD =
  `"pass/prevkey/v1:" + vault_id`), so copies still encrypted with an older key (another device's unsynced
  file, a cloud conflict copy, an old server version) merge in. A header wrapping an older VK is never
  adopted by a merge. Devices still holding only the old VK can't merge the new file: they unlock it with
  the new password.
* **Device unlock**: platforms may keep their own copy of the VK wrapped by a hardware key
  (Android Keystore with biometric auth; on Windows a key derived from a Windows Hello key's
  deterministic signature, inside DPAPI, see `Core/desktop-app/README.md`). `Vault::export_vault_key` /
  `Vault::unlock_with_key` support this. A device-wrapped VK never leaves the device.
* **Recovery code** (optional, `recovery` in the header; `Core/core/src/recovery.rs`): for a forgotten master
  password with no unlocked device. `Vault::create_recovery_code` draws a 128-bit secret from the OS RNG and
  returns it once as 30 characters of Crockford base32 in six groups of five (`7K3QD-…`): the 128 bits plus a
  22-bit checksum (the first bits of `SHA-256("pass/recovery-code/v1:" + secret)`), so a typo is reported
  before any key derivation (case, spaces and dashes don't matter; `O`/`I`/`L` read as `0`/`1`/`1`). A
  recovery KEK is derived from the secret with Argon2id (the vault's parameters, fresh salt, the same
  bounds) and wraps the VK with XChaCha20-Poly1305, AAD `"pass/recovery-vk/v1:" + vault_id + ":" + id`.
  The code itself is never stored. `Vault::unlock_with_recovery_code` opens the vault with it (same VK, so
  device unlock keeps working); the app then sets a new master password with `change_master_password` (no
  old password needed) and offers a new code. One code per vault: a new one replaces it.
  * **Authentication.** The block carries its own `auth`: the VK seals an empty message with AAD
    `"pass/recovery/v1:" + vault_id + ":" + JSON[header_updated_at, id, created_at, kdf, wrapped_key]`.
    Only a holder of the VK can add or change a block, and a block is valid only next to the header
    version it was sealed for, so an old block (a replaced or removed code) can't be put back next to a
    newer header. `header_auth` deliberately does **not** cover the block (its AAD is unchanged): clients
    from before recovery codes verify it as before and keep adopting password changes. A block that
    doesn't verify is dropped on unlock and never adopted by a merge.
  * **Merge.** The block is part of the header: making or removing a code bumps `header_updated_at` and
    re-seals the header, and every header change re-seals the block's `auth` (a password change keeps the
    code). A newer header that is adopted brings its block, or none. With the same `header_updated_at`, a
    valid block this copy lacks is taken over (two codes made in the same millisecond: the greater `id`),
    and `remote_is_behind` re-uploads a copy that lacks this vault's block. The recovery `id` is part of the
    sync fingerprint (only when there is a block, so older sync states stay valid).
  * **Older clients** ignore the unknown field when they read the file and drop it when they write it. They
    still open, merge and adopt headers of vaults with a code. A copy written back by an older client has the
    same header without the block: devices that have the code keep it and upload it again (once per such
    write). A password change *on an older client* writes a newer header without the block, which ends the
    code everywhere (Settings then shows none; make a new one).
  * **What the file's host can do**: strip the block (devices that haven't got it yet adopt the header
    without it; the device that has it restores it with its next upload; denying recovery is no more than
    withholding the file, which a host can always do), or keep an old copy. It can't plant a block of its
    own (no VK, and its `auth` fails), swap fields, or revive a replaced code next to a newer header.
  * **Limits.** Removing or replacing a code doesn't revoke it for copies of the file saved before (an old
    backup, a server's version history, the host's copy): they hold the same VK wrapped by the old code. A
    code that may have leaked is revoked for good only by replacing the vault key: a password change drops the
    recovery block (it can't be re-wrapped without the code, and nothing derived
    from the old key may unlock the new one); make a new code afterwards. Anyone with the code and a copy of
    the file can open the vault, so it belongs offline, not next to the file.
* **Items**: each item is serialised as JSON (§2 lists the fields and how older clients treat the newer ones) and encrypted with the VK using XChaCha20-Poly1305. Metadata
  needed to merge (`id`, `updated_at`, `deleted`, `device_id`) stays in cleartext; titles, URLs and usernames
  are encrypted. The cleartext version is authenticated by the **item AAD v2**:
  `"pass/item/v2:" + JSON[vault_id, item_id, updated_at, device_id, deleted]`, so whoever stores the file
  (a WebDAV host, a cloud folder) can't mark an item deleted, or give an old ciphertext a newer timestamp,
  without the VK. A tombstone seals an *empty* message under the same AAD, which authenticates the deletion.
  Records written by older clients use the **v1 AAD** `"pass/item/v1:" + vault_id + ":" + item_id` (binds
  vault and item, not the version; tombstones without a tag). They are still read, never written: the next
  save re-seals them as v2.
* **Header authentication** (`header_auth`, optional): the VK seals an empty message with AAD
  `"pass/header/v1:" + vault_id + ":" + JSON[header_updated_at, kdf, wrapped_key]`. Files without it (older
  clients) open as before, but a merge never adopts their header, and the header is authenticated at the next unlock with the master password
  (the wrapped key was just opened with it).
* **KDF bounds** (`KdfParams::check`, applied when a vault is created, unlocked with the master password or a
  recovery code, re-keyed, a recovery code is made or a header is merged): `alg = "argon2id"` only, `m_kib` ≤ 1 GiB (1 048 576), `t` 1..=20, `p` 1..=16. The header is
  cleartext from synced files, so without a cap a damaged or hostile copy could make every unlock allocate
  gigabytes (on Android an allocation failure aborts the app). Violations are `Corrupt`.
* **File**: UTF-8 JSON

```jsonc
{
  "format": "pass-vault", "version": 1, "vault_id": "uuid",
  "header_updated_at": 1730000000000,
  "kdf": { "alg": "argon2id", "m_kib": 65536, "t": 3, "p": 1, "salt": "b64" },
  "wrapped_key": { "nonce": "b64", "ct": "b64" },
  "key_check": { "nonce": "b64", "ct": "b64" },
  "header_auth": { "nonce": "b64", "ct": "b64" },          // optional, see above
  "recovery": { "id": "uuid", "created_at": 1730000000000,  // optional: the recovery code, see above
                "kdf": { "alg": "argon2id", "m_kib": 65536, "t": 3, "p": 1, "salt": "b64" },
                "wrapped_key": { "nonce": "b64", "ct": "b64" }, "auth": { "nonce": "b64", "ct": "b64" } },
  "items": [ { "id": "uuid", "updated_at": 1730000000000, "device_id": "…", "deleted": false,
               "nonce": "b64", "ct": "b64" },
             { "id": "uuid", "updated_at": 1730000000500, "device_id": "…", "deleted": true,
               "nonce": "b64", "ct": "b64" /* tombstone: sealed empty message */ } ],
  "settings": { "updated_at": 1730000000900, "device_id": "…",   // optional: vault settings, see below
                "nonce": "b64", "ct": "b64" }
}
```

* **Local sync state**: the copy saved on a device may carry one more cleartext field,
  `"sync": { "url": "<hash of the WebDAV URL>", "etag": "…", "fingerprint": "<hash of the item versions>" }`,
  which records what the server's copy looked like after the last successful sync (§10). It is never
  uploaded, reveals nothing the cleartext metadata doesn't, and older clients ignore it.
* **Usage counts** (optional `usage` array): how often each login was used, one sealed blob per device, outside
  the item records (§13). Older clients ignore it.
* **Vault settings** (optional `settings`; `Core/core/src/settings.rs`): settings that must be encrypted and should
  follow the vault to every device, today the username and e-mail generator's (§14): the e-mail alias services'
  API tokens and options, the default service, and the user's own address and catch-all domain; and the pinned
  vaults (`ui.pinned_vaults`, a JSON array of vault ids in pin order, at most five). Never in an
  app's plain settings file. One blob sealed with the VK, AAD `"pass/settings/v1:" + JSON[vault_id, updated_at,
  device_id]`, outside the item records (a settings change never touches an item's version, and settings are no
  items: no list, search, export or count shows them). Inside, every key has its own version
  (`updated_at`, `device_id`) and keys merge last-writer-wins one by one, so two devices that each set up a
  different service between syncs both keep theirs; a removed key stays as a tombstone so the removal syncs.
  The merged blob keeps the version of the copy that already had everything, or gets a new one when each copy
  had keys the other lacked. Its version is mixed into the sync fingerprint (only when there is a blob, so older
  sync states stay valid), `remote_is_behind` re-uploads a copy that lacks it, a key rotation re-seals it, and a
  damaged or forged blob is ignored like usage. **Older clients** ignore the field and drop it when they write
  the file; the devices that have it keep their copy and upload it again with their next sync.
* **Merge** (`Vault::merge_remote`): per item id. Two live versions that both carry merge metadata are
  merged **field by field** (below); otherwise (a tombstone on either side, or a version without metadata)
  the record with the greater `(updated_at, device_id)` wins. Deletions are tombstones (`deleted: true`, a
  sealed empty ciphertext), so a deletion propagates and is not undone by an older copy. Two rules keep the
  file's host from rewriting history:
  * A record whose version is not authenticated (a v1 record, or a tombstone without a tag) may add an item
    this vault has never seen, but never replaces or deletes one it has; the next sync uploads this vault's
    version over it. A newer-looking copy that fails authentication for an item the vault has (an old
    ciphertext with a bumped timestamp) is ignored the same way.
  * The header (KDF + wrapped VK) with the greater `header_updated_at` wins, which spreads master-password
    changes, but only if the VK is the same, its `kdf` passes the bounds above and its `header_auth`
    verifies. Otherwise it is not adopted, so a replayed or swapped wrapped key can't lock every device out
    of the master password.

  * **Deletions don't eat unseen edits.** A tombstone's version is the deleted record's plus one
    millisecond, not the current time (`Inner::tombstone`). It replaces the version it deletes and every
    older copy, but an edit that another device made to that version without having seen the deletion (a
    restore from the trash, a new password) is newer and wins: the item comes back with the edit. This
    covers the automatic trash purge too: a laptop opened again after a month purges its trash at unlock,
    before it syncs, and must not delete an item a phone restored and kept using meanwhile.
  * **Concurrent edits of one item are merged field by field** (`core/src/vault/field_merge.rs`). Every
    item version this client writes carries **merge metadata**, sealed with the item inside its ciphertext
    under the key `merge`:

    ```jsonc
    "merge": {
      "v": [1730000000500, "phone-id"],          // the version this metadata belongs to
      "d": [1730000000000, "laptop-id"],         // the stamp of every part not listed in "f"
      "f": { "notes": [1730000000500, "phone-id"] },   // parts set by other writes
      "s": { "laptop-id": 1730000000000, "phone-id": 1730000000500 }   // version vector
    }
    ```

    A *part* is a top-level field of the item (`title`, `username`, `notes`, `urls`, `totp`, `kind`, …), each
    field of `card` and `identity` on its own (`card.number`, `identity.email`), and the password together
    with `password_changed_at` and `password_history`. Its *stamp* is the `(updated_at, device_id)` of the
    `upsert` that set its value: `upsert` gives the new version's stamp to every part that differs from the
    version it replaces and keeps the others' stamps. `s` holds, for each device, the newest of its writes to
    this item that the version includes. That is all a three-way merge needs, without the common ancestor's
    values: when two versions differ in a part, the side with the newer stamp changed it, and its `s` tells
    whether it had seen the other side's value.
    * A later edit made on top of the other value (the newer side has seen the older stamp) replaces it.
    * Both sides changed different parts: each keeps its change, so the phone's note and the laptop's new
      username both survive.
    * Both changed the same part concurrently (neither had seen the other's value): the newer value is
      kept and the other stays reachable. A **password** goes into the history (both histories are joined
      too, newest first, at most 20; histories are joined whenever two versions differ, even after a later
      edit, since no client removes a history entry: that also keeps the password of one of two processes
      of a device, an app and its AutoFill extension, which share a device id, so their context can't
      tell a stale copy's edit from a later one). **Lists** (websites, Android apps, passkeys by credential id, tags,
      custom fields) are joined: what either side added stays. `favorite` and `trashed_at` keep the newer
      value. **Any other field** (title, username, notes, 2FA secret, kind, a card or identity field) keeps
      the newer value, and the version that lost is kept as a **conflict copy**: a new item titled
      "… (conflict)" (not translated: every device makes the same copy, so it can't depend on the device's
      language), with an id derived from the item's id and the losing version, so every device that sees the
      conflict makes the same copy and makes it once. It usually has the same site and username as the item,
      so Settings → Find duplicates and the Merge sheet offer to fold it in; "Merge with…" works for any.
      Deleting it syncs like any delete, and an old copy of the vault merged later doesn't bring it back (the
      copy's tombstone is newer).
    * A value a merge makes (two histories or lists joined) gets a stamp of its own (device id U+0001 and 16
      hex digits of a hash of the value, recorded in `s`), so a later edit made without having seen it is
      concurrent with it and is joined with it in turn instead of dropping what the merge added.
    * The merged version has `updated_at` one more than the newer of the two (an editor that loaded either
      sees that the item changed) and the device id U+0001 followed by 16 hex digits of a hash of its
      contents and metadata: two devices that make the same merge make the same version, the same contents
      under two versions settle on the greater, and at the same `updated_at` it sorts before every real
      device id, so a deletion of an input deletes the merge too. When one side already has everything the
      other has, that side's version is kept as it is (no new version).
    * The merged item keeps the shape `upsert` gives (a card only on a card item, an identity only on an
      identity), which is also the shape that reads back the same from the file; a card or identity field
      dropped that way (one device changed the kind while another edited the card) is a conflict like the
      others.

    **Where the common ancestor comes from.** A three-way merge needs to know, per field, which side changed
    it since the common ancestor. Two other places for that were considered. A sealed copy of each item's
    base values in the file would about double its size, keep old values (a password or note the user
    replaced stays in the file until the next edit), and know only one step back, so a third device's edit
    on top of a merged version would have no matching base. A local last-synced snapshot kept beside the sync
    state would cost the file nothing, but it exists only per device and per server, not for a cloud-folder
    conflict copy, an old Google Drive revision or a copy written by a device this one never synced with, and
    every platform would need storage for it. The stamps and version vector chosen instead travel inside the
    file, so a cloud folder, WebDAV, Passyble Server and Google Drive (and their conflict copies and old
    revisions) merge alike, for any number of devices and in any order (merging is commutative, associative
    and idempotent on the parts). They keep no old values, and cost a few hundred bytes per item: one entry
    per device that edited it, one per part changed since it was made, plus one per conflict a merge joined.

    **The whole-item rule** still applies when either version has no valid metadata: a tombstone, a legacy
    (v1) record, a version an **older client** wrote, a conflict copy, or metadata that names another
    version than its record's. Older clients read items with `merge` as before (serde ignores the unknown
    key), keep it on the items they don't touch (their cached ciphertext), and drop it from an item they edit
    (they re-seal it from their own `Item`), so their edit has none. A client that re-sealed the JSON as it
    found it under a new version of its own would carry metadata naming the old version: it is ignored, as
    trusting it would take that client's changes for unchanged fields and drop them. Then the later version
    of the whole item wins, and one part of the other is still never lost: its **passwords**. A password of
    the losing version that the winner shows no sign of having seen (neither its password nor in its history;
    an edit made on top of a version always shows that version's passwords, since `upsert` moves a replaced
    password into the history) is added to the winner's `password_history` (`unseen_passwords`, filed under
    when it was set). The merge writes that as a *rescue version*: the winner's `updated_at`, and the winner's
    `device_id` with U+0000 added, which is the very next version after the winner's. It beats the winner and
    nothing else, so any edit made on top of the winner, a deletion of it, or a concurrent version that wins
    the tie still wins over it (and gets the rescued passwords in turn), and every device that sees the same
    versions makes the same rescue (its metadata, when the winner has some, gives the password part a stamp
    of its own, like a joined value). A full history (20) drops its oldest entries, so a password older than
    every entry still kept is not brought back. An edit made on a current client on top of a version without
    metadata counts that version as one write that set every part, so its next concurrent edits merge field
    by field again.

  Merging is idempotent and commutative, and every order of syncing converges: all devices end with the same
  records, and no edit of any device is lost unless a later edit made with it in view replaced it, or a
  deletion took the item. The order can still decide a few things: which version lost a conflict (and so
  which conflict copies exist; a copy is made of the losing version as the merging device has it), the
  rescued history of the whole-item rule, and a deletion racing concurrent edits (a deletion newer than a
  concurrent edit wins over it, but a device that first merged the edit into another version keeps it).
  `core/tests/merge_safety.rs` checks these properties over random three-device histories (edits of the same
  and of different fields, trash, restores, deletes, partial syncs), with a model of what each device knew
  to tell a lost edit from a replaced one.
* **Mixed-version rollout**: a client from before item AAD v2 can't authenticate the v2 records an
  upgraded device writes (the AAD differs) and treats them as corruption, so once an upgraded device has
  saved the vault, **older clients can neither unlock that file nor merge it** ("vault file is corrupt").
  Their own local copy and its unsynced edits are untouched; after upgrading, its v1 records open, are
  re-sealed as v2 on the next save, and merge by their timestamps. Upgrade every device together (no
  release has shipped with the v1-only reader, so this only affects test installs).

## 2. Item model

A **Login** carries everything needed for one account. That is what makes "fill everything in one go"
possible:

| field | purpose |
|---|---|
| `title`, `username`, `password`, `notes`, `favorite` | the usual |
| `urls[]` | websites; matched by registrable domain (eTLD+1, Public Suffix List), exact host or exact origin |
| `url_rules[]` | `{url, rule}` for websites whose rule isn't the default: `subdomains` (default: the site and its subdomains, the registrable domain as above), `host` (that host only, and its port when the entry names one), `never` (never suggested, filled or offered on its own; still searchable, filled when picked by hand, and still counted by the save banner so a hand-filled login isn't saved twice). Keyed by the entry, not its place; joined per website by the field merge. Lookalike warnings count every website whatever its rule |
| `android_apps[]` | `{package, cert_sha256?, never_show?}`. A native Android app matches only if the package matches **and** (when stored) the signing-cert digest matches; `never_show` is the app's `never` |
| `totp` | `otpauth://` URI or a bare base32 secret |
| `passkeys[]` | WebAuthn credentials (ES256 / P-256) for this account |

`Note` items hold free-form secure notes. **Card** (`card`: cardholder, number, expiry month and year, security
code, PIN, brand) and **Identity** (`identity`: name, e-mail, phone, address lines, city, region, postal code,
country, company, birth date) items hold the details for filling forms; they have no website matching (the URL
and app finders return logins only). Every item can also carry:

| field | purpose |
|---|---|
| `fields[]` | custom fields `{name, value, kind}`; `kind` is `text`, `hidden` (masked, never in summaries or search) or `url`; an unknown kind reads as `hidden` |
| `tags[]` | folders; `/` nests them (`Work/Clients`). `Vault::upsert` trims, drops empty segments and case-insensitive duplicates. `tag:work` or `#work` in a search (and `items_with_tag`) matches `Work` and `Work/Clients` |
| `trashed_at` | set while the item is in the **trash** (below) |
| `password_changed_at` | when the password was last set or changed; `Vault::upsert` sets it to now when the password differs from the stored one. Unknown (0) for older items: `updated_at` stands in. Feeds the "old password" check |
| `password_history[]` | earlier passwords, newest first, at most 20 (filled by merging duplicates) |

`Vault::upsert` normalizes: a card number keeps its digits only, the brand comes from the number (`card_brand`:
visa, mastercard, amex, discover, diners, jcb, unionpay, maestro, mir), a two-digit expiry year becomes 20xx, an
untitled card is titled "Visa •••• 1111", card and identity data exist only on their own kind.

**Compatibility with older clients.** The vault file stays version 1. The new fields are optional in the sealed item JSON
and left out when empty, so an item that uses none of them is byte-for-byte what an older client wrote. A Card or
Identity is sealed with `"kind": "note"` plus its `card` / `identity` object (`Item::stored_json`, read back by
`from_stored_json`), because an older client rejects an unknown kind and would refuse the whole vault. What an older
client does with the newer data: it opens the vault and shows a card or identity as a **secure note** (title and notes;
the card or identity data are in the file but not shown); it ignores tags, custom fields and `password_changed_at`
(`updated_at` stands in); and it lists a trashed item as an ordinary item (it doesn't know `trashed_at`). If it edits
and saves an item it re-seals it without every field it doesn't know, so that item loses its card or identity data,
tags and custom fields, and a trashed item comes back out of the trash; items it doesn't touch are merged as they are
(the merge of §1 takes the newer whole record of an item an older client edited, since that version carries no
merge metadata; it keeps the passwords of the other). This version reads a kind it doesn't know (from a newer
client) as a `Note`. The sealed item JSON also carries this client's merge metadata (`merge`, §1), which older
clients ignore in the same way. Upgrade every device before using cards, tags, fields or the trash on a shared vault.

**Trash.** `Vault::delete` doesn't delete: it sets `trashed_at` to now (an ordinary edit, so it syncs and merges like one).
A trashed item is left out of `items`, `get`, `summaries`, search, the URL / app / passkey finders,
export, import matching, duplicate detection and password health; `trashed_items` / `trash_summaries` list it, `restore` brings it back
(`upsert` of a copy without `trashed_at` does the same: the apps' Undo). `purge`, `empty_trash` and `delete_permanently`
write a tombstone (§1). **Auto-purge**: an item trashed 30 days ago (`TRASH_RETENTION_MS`) is purged by `Vault::unlock`
and `serialize` (`purge_expired_trash`). Every device does the same, so the tombstones converge whichever writes first.
A tombstone is versioned just after the version it deletes (§1, "Deletions don't eat unseen edits"), so a restore or
edit made elsewhere in the meantime wins over a purge (automatic or manual) by a device that hadn't seen it.
Tombstones are never purged themselves: they keep old copies (a backup, a conflict copy, an old Google Drive revision)
from bringing a deleted item back.
Merging duplicates (`merge_items`, `merge_pair`) deletes the folded items for good, since the kept item holds what they
had. The current Windows and Android apps call `delete`, so their Delete already goes to the trash, but they have no trash
screen yet: until it lands a deleted item stays in the file (encrypted, hidden) for 30 days and is then purged.

**Summaries** (`ItemSummary`, the soft-lock list, §12) carry the tags, a card's brand, last four digits, cardholder and
expiry, an identity's name, e-mail and company, and `has_fields`. They never hold a full card number, security code, PIN,
custom field value or password. Search over summaries sees the same, so a card is found by its last four digits and never
by the rest of its number; unlocked search also covers custom field names and the values that aren't hidden.

## 3. TOTP everywhere: the fallback chain

Goal: **you never pick up a second device for a code.** When a login with a TOTP secret is filled:

1. **Same form has an OTP field** (`autocomplete="one-time-code"`, Android `AUTOFILL_HINT_SMS_OTP` /
   `2FA_APP_OTP`, or heuristics) → the code is filled along with the password.
2. **The OTP field appears on the next screen** (most sites) → the fill is remembered for 3 minutes
   ("pending OTP" for that domain or app). When an OTP field shows up for the same domain or app, the code is
   offered *first* (Android: top dataset + keyboard chip; browser: the inline menu opens on its own and fills
   with one click, or with no click if auto-fill-OTP is enabled).
3. **No OTP field can be detected** (custom widgets, canvas, native apps that hide hints):
   * **Android**: a high-priority *ongoing* notification, in the style of Shizuku's pairing notification:
     `GitHub · 123 456 · 17s`, with **Copy** and **Dismiss** actions. It refreshes each period and
     removes itself after 30 seconds. Copying marks the clipboard sensitive and clears it after 45 s.
   * **Windows (browser)**: a small, non-intrusive toast in the page (Shadow DOM, bottom-right) with the live
     code and Copy, plus the extension popup always shows the current code for the tab.
   * **Windows (native app)**: an always-on-top Passyble popup by the tray with the code, Copy and
     **Type it** (auto-types into the window that had focus).
4. **The site doesn't ask this time** (a remembered device, "don't ask again for 30 days", risk-based
   checks) → nothing is shown. Steps 2-3 only happen once the 2FA step is detected (a code field, or 2FA wording
   with an input); a signed-in screen instead (browser: ~10 s after the navigation no code field, no 2FA
   wording, no password field and no sign-in URL; Android: the next screen has neither a login nor a code field,
   or nothing within 2 minutes) is a "skipped" 2FA step. The last 5 outcomes per site are kept on the device
   (desktop agent `otp.outcome`, Android `OtpHistoryStore`; hashed domains): after two skipped sign-ins in a
   row, Passyble only fills a code field that actually shows up and never pops up a notification or toast on its own.

## 4. Autofill per platform

* **Android**: `AutofillService` (API 26+). It parses the `AssistStructure` (autofill hints, `inputType`, HTML
  attributes reported by browsers, id/hint text heuristics), matches by `webDomain` (browsers) or by
  calling package + signing cert (apps), and returns datasets that need authentication while the vault is
  locked. On Android 11+ it also returns **inline suggestions**, so Gboard and other keyboards show the logins
  as chips above the keys ("keyboard autocomplete"). `onSaveRequest` offers to save new logins.
* **Windows / browsers**: MV3 extension → Native Messaging → desktop agent. Field detection, inline
  icon + dropdown, and "save this login?" on submit. Decryption happens only in the desktop agent. The
  extension gets just the one credential it asked for, and only after the agent checks that the item matches
  the requesting tab's URL. Without the desktop app the extension can keep its own vault (browser mode,
  docs/EXTENSION_VAULT.md); whenever the app is installed on the computer the extension uses it instead and offers
  to move the browser's items in once (`items.import`, EXTENSION_VAULT.md §2.6).
* **Windows / native apps**: Windows has no system autofill API, so Passyble uses a global hotkey
  (`Ctrl+Alt+P` by default) that matches the foreground window title and process against items and auto-types
  `username ⇥ password ↵` with `SendInput` (KeePass-style). Ambiguous matches open a quick-pick search.

## 5. Passkeys

The core is a complete software WebAuthn authenticator: ES256 key generation, `none` attestation,
authenticator data with flags `UP | UV | BE | BS` (+`AT` at creation; assertions take `UV` as an argument), and a
sign count fixed at 0, which is the norm for synced passkeys. The desktop agent keeps `UV` only after real
verification (§7). The AAGUID is Passyble's own. Passkeys live inside the vault and sync like
everything else, so a passkey made on the phone works on the laptop and the other way round.

* **Android 14+**: `CredentialProviderService` for Credential Manager. Passyble appears in the system passkey
  sheet for both apps and browsers. Origin: privileged browsers supply `origin` (checked against a
  privileged-apps allowlist). Native apps use `android:apk-key-hash:<b64url(sha256 cert)>`. Because Passyble is a
  credential provider, Android also serves its passkeys over **hybrid (QR / Bluetooth)** to any Windows
  PC, without the extension.
* **Windows, in the browser**: the extension wraps `navigator.credentials.create/get` in the page's main
  world. If the vault has a matching passkey, or the user picks "Save in Pass", the ceremony runs in the
  desktop agent after a consent dialog (Windows Hello when available). Otherwise it falls back to the
  browser's own implementation (security keys, Windows Hello, phone).
* **Windows, natively** (opt-in setting): the Windows 11 plugin passkey manager API (`webauthn.dll` plugin
  authenticator) makes Passyble a system-wide provider for browsers and native apps. `Pass.exe` serves
  `IPluginAuthenticator` as an out-of-process COM server, decodes the CTAP2 requests, checks Windows'
  request signature and calls the agent's `clientDataHash` variants of create/assert
  (`Agent::platform_passkey_create` / `platform_passkey_get`), with the same consent prompt and Windows
  Hello. It needs package identity, supplied by a sparse MSIX (`Windows/installer/packaging/`). See
  `Core/desktop-app/src-tauri/src/passkey_provider.rs`.

**WebAuthn PRF extension** (`Core/core/src/prf.rs`): what apps like WhatsApp use to derive the key of an end-to-end
encrypted backup from a passkey. Every passkey Passyble makes gets a random 32-byte secret (CTAP2 `credRandom`) at
creation; the PRF is `HMAC-SHA-256(secret, SHA-256("WebAuthn PRF" || 0x00 || input))`, the same with or without user
verification. The secret is kept as an attribute of the passkey's PKCS#8 private key (OID
2.25.6552552139013998651363784758755423571), not as a new item key or a custom field: every client of every version
keeps `private_key_pkcs8` byte for byte and signs with a decoder that skips attributes, so an older client that
edits the login can't drop it, and it goes exactly where the private key goes (sync, the Passyble JSON and encrypted
exports; never the CSV). `Vault::upsert` and sync merges (the whole-item rule and the field-level join, its
conflict copies included) never let a passkey's key (and so its secret) be replaced. In a shared vault the secret
stays inside the item like the key: a fill-only member signs in with the passkey, PRF included (the site gets the
PRF's output), and never sees either, since no app shows, copies or exports a fill-only member's passkey keys.
Passkeys made before have no PRF and never get one later. Answered by Android (Credential Manager JSON), iOS 18+
(the AutoFill extension) and the browser extension (through the desktop agent); not yet by the Windows plugin
authenticator (desktop-app/README.md).

## 6. Import and export (`Core/core/src/import/`, `Core/core/src/export.rs`)

Offline, platform-independent import of other apps' exports, in two steps so every client can show a
preview:

1. **Parse** (`parse_import` / UniFFI `import_parse`): bytes + file name (+ optional explicit format) →
   `ImportReport { format, items, skipped, warnings }`. The format is detected from the content (ZIP, PNG/JPEG,
   KDBX magic; JSON keys; CSV header row; `otpauth` links); the file name is only a hint. Parsers:
   `otp_formats.rs` (otpauth lists, Google Authenticator's `otpauth-migration` protobuf, Aegis, 2FAS),
   `csv_formats.rs` (one header-driven reader for Chrome/Firefox/Safari/Proton/1Password/Bitwarden/
   KeePassXC/LastPass/Dashlane CSVs), `json_formats.rs` (Bitwarden JSON incl. passkeys, Proton Pass
   `data.json`, 1Password `export.data`, Passyble JSON via `export.rs`), `archive.rs` (ZIP: `.1pux`, Proton, Dashlane), `qr.rs` (QR codes in
   images; cargo feature `import-qr`, enabled by the desktop app only, since Android scans with the camera).
   **Password-protected exports** are opened with their password: `import_encryption(data, file_name)` tells the apps
   that a file needs one (and whether it can take a KeePass key file), then `import_parse_with_password` /
   `import_parse_with_key_file` decrypts and parses it in one call (see *Encrypted exports* below). Without a password,
   `import_parse` answers `InvalidInput` saying that the file is encrypted with a password.

**Encrypted exports** (`encrypted.rs`, `kdbx.rs`, `pgp.rs`, `archive.rs`). Pure Rust, offline, in the core:

| format | key derivation | cipher | status |
|---|---|---|---|
| Passyble encrypted JSON | Argon2id (`m_kib` ≤ 1 GiB, `t` ≤ 20, `p` ≤ 16) | XChaCha20-Poly1305 | supported (Export below) |
| Bitwarden JSON, "Password protected" (`encrypted` + `passwordProtected`) | PBKDF2-HMAC-SHA256 (`kdfType` 0) or Argon2id (`kdfType` 1; salt = SHA-256 of `salt`), then HKDF-Expand-SHA256 `enc` / `mac` | EncString type 2: AES-256-CBC + HMAC-SHA256 (constant-time check); `encKeyValidation_DO_NOT_EDIT` proves the password, `data` is the plain Bitwarden JSON | supported |
| Bitwarden JSON, "Account restricted" (`encrypted` without `passwordProtected`) | the Bitwarden account's user key, not in the file | | refused: "export again as Password protected (or plain)" |
| Aegis encrypted vault | scrypt per password slot (`n`, `r`, `p`, `salt`) wrapping the master key with AES-256-GCM | AES-256-GCM over `db` | supported (biometric-only vaults: refused, no password slot) |
| 2FAS encrypted backup (`servicesEncrypted`, `reference`) | PBKDF2-HMAC-SHA256, 10 000 iterations, per-part salt | AES-256-GCM (`<ct+tag>:<salt>:<iv>`, base64); `reference` checked first | supported |
| KeePass `.kdbx` 3.1 and 4 (and KeePass 1 `.kdb`), password and/or key file | AES-KDF, Argon2d / Argon2id (outer header read and bounded here first) | AES-256-CBC, ChaCha20, Twofish (outer); Salsa20 / ChaCha20 (protected values) | supported (feature `import-kdbx`, `keepass` crate) |
| Proton Pass encrypted export (`Proton Pass/data.pgp` in the ZIP), or any passphrase-encrypted OpenPGP file (armored or binary) holding an export | OpenPGP S2K: iterated and salted (OpenPGP.js uses SHA-256, count byte 255) or Argon2 (bounded) | SEIPD v1 (MDC) or v2 (AEAD); unprotected SED is refused | supported (feature `import-pgp`, rPGP); messages encrypted to a public key: refused |
| ZIP with encrypted members (WinZip AES-128/192/256, ZipCrypto) | PBKDF2-HMAC-SHA1, 1000 (AES); ZipCrypto keys | AES-CTR + HMAC-SHA1 (AE-1/AE-2) / ZipCrypto | supported (each member read with the password; a member may itself be an encrypted export with the same password) |
| Dashlane secure archive (`.dash`), Enpass encrypted backups, NordPass, RoboForm, Keeper encrypted exports | proprietary or undocumented | | not supported: their plain CSV / JSON exports are (Dashlane, the generic CSV reader) |
| 1Password `.1pux` | | not encrypted | plain import |

Safety rules for all of them: the key derivation parameters come from the file, so they are checked *before*
anything is derived (`encrypted.rs`: PBKDF2 ≤ 5 000 000 iterations, Argon2 ≤ 1 GiB, ≤ 100 passes, ≤ 64 lanes and
memory × passes ≤ 16 GiB, scrypt 128·r·N ≤ 1 GiB and N·r·p ≤ 2^26, AES-KDF ≤ 300 000 000 rounds, OpenPGP Argon2 S2K
≤ 2^20 KiB); a file asking for more gets "this … export asks for unusually heavy key derivation settings" instead of
a hang or an out-of-memory crash. A wrong password is `PassError::InvalidPassword` (the apps say "Wrong password for
this export", and offer another try); a damaged file is `InvalidInput` ("this … export is damaged"), never a panic.
Passwords, derived keys and decrypted plaintext are held in `Zeroizing` buffers where the code owns them, never
logged, never written to disk; the apps keep the encrypted file in memory only until it is opened or the import is
cancelled. Decrypted OpenPGP data and ZIP members are read through the usual 50 MB cap. Known limit: the `keepass`
crate inflates a KDBX payload fully in memory, so a hostile database that its sender also gave you the password of
could exhaust memory; the input itself is capped at 50 MB.
2. **Commit** (`ImportBatch::preview` / `commit`, `apply.rs`): a pure planner compares each item with the
   vault and with the items before it in the same file. Logins match on normalised host (lowercase, no
   `www.`) + username (case-insensitive); authenticator-only entries (TOTP, no password/URL) match a login
   whose domain label or title equals the issuer and whose username equals the account; logins without
   URLs match on title + username; notes on title + contained text. Matching entries form **clash groups**
   (`ImportGroup`): `Identical` (a vault item, nothing new: skipped by default), `Differs` (a vault item,
   something differs: merged by default) or `InFileDuplicate` (several entries of the file: merged into one
   by default). Each group takes a decision (`ImportDecision`: Skip / Merge with which password, 2FA and
   title to keep / Keep both); `merge.rs` unites websites, notes, passkeys (by credential id) and Android
   apps, keeps one password (by default the newest known) and moves the others to the item's
   `password_history`; a replaced 2FA secret is noted in the notes. So nothing is lost, and importing a
   file twice is a no-op. The preview carries no secrets (titles, usernames, first URL, flags, action,
   which fields differ, opaque choice ids with source and date). `find_duplicates` / `merge_items`
   (`duplicates.rs`) apply the same merge to logins already saved twice in the vault (same host + username,
   or same host + password without a username).
   `pair.rs` merges two items the user picked (the list's multi-select, "Merge with…", and the suggestions
   that pair an authenticator entry with its login): every single-value field from A or B, the rest
   united, the other item deleted with an in-memory `MergeUndo` for the Undo button.

**What an import keeps** (`Draft` → `Item`): logins, secure notes, **cards and identities**, **custom fields** (kept as fields
with a kind, no longer appended to the notes: `hidden` where the source marks a secret), **folders, collections, groups and
categories as tags**, 2FA secrets, passkeys. Per source:

* *Bitwarden JSON*: logins, notes, cards (brand, number, expiry, code), identities (name, contact, address, company; the
  user name, social security, passport and licence numbers become custom fields, the last three hidden), custom fields
  (type hidden → hidden), passkeys; folders and collections become tags. Trash and SSH keys are skipped.
* *Bitwarden CSV*: folder (or collections) becomes a tag, the `fields` column custom fields (all plain text: the CSV
  doesn't mark hidden ones); only login and note rows: card, identity and other rows are skipped as "<type> items
  aren't supported".
* *Proton Pass JSON/ZIP*: logins, notes, cards (incl. PIN), identities (the main fields; work, social and ID details
  and extra sections as custom fields), custom fields (hidden and 2FA-type extra fields hidden); with more than one
  vault each item is tagged with its vault's name. Aliases and trashed items are skipped.
* *1Password 1PUX*: logins, passwords, notes, cards, identities, concealed fields as hidden custom fields, the item's
  tags (plus the vault name when the export has several vaults); archived and trashed items and other categories are skipped.
* *KeePassXC CSV*: the group path becomes a nested tag (the `Root/` prefix dropped); the recycle bin is skipped.
* *KeePass `.kdbx`*: title, user name, password, URL (plus KeePassXC's `KP2A_URL*` extra URLs), notes, TOTP (KeePassXC's
  `otp` URI, KeePass 2.47+'s `TimeOtp-*` fields, the older `TOTP Seed` / `TOTP Settings`; Steam codes are reported as
  unsupported), KeePassXC passkeys (`KPEX_PASSKEY_*`), every other string field as a custom field (hidden when KeePass
  protects it), the group path below the root and the entry's tags as tags, creation and modification times. The
  recycle bin is skipped; attachments are not imported and listed in a warning; entry history and icons are dropped.
  *LastPass CSV*: the folder becomes a tag (`\` → `/`); secure notes of type Credit Card and Address become a card and an
  identity.
* *Dashlane*: `payments.csv` gives cards (bank accounts become notes with custom fields, account number hidden),
  `personalInfo.csv` one identity "Dashlane personal info" (further values of a kind as custom fields). In the login
  CSVs a `tags` or `category` column also becomes tags.
* *Chrome, Edge, Brave, Firefox, Apple Passwords, Aegis, 2FAS, Google Authenticator*: no folders or card data in those
  exports, so as before.
* *Passyble JSON* (`PassybleJson`, below): everything it holds, nothing skipped except items that were in the trash.

Still skipped (and listed): Bitwarden CSV cards and identities, aliases, HOTP and Steam codes, SSH keys and items in the
source's trash or archive. Matching against the vault: a **card** matches a vault card with the same number (cards without
a number match by title); an **identity** matches by title, full name and e-mail; both merge by filling fields the vault's
item leaves empty (`merge::absorb_details`; tags and custom fields with a different name or value are added), and a
clash where only these differ is `Differs`, so a re-import of the same file is still a no-op. An imported item keeps the
source's creation date, and its password date (`password_changed_at`) is the source's modified date when it has one.

**Export** (`Core/core/src/export.rs`, `export_*` in PROTOCOL.md §1): live items only, never the trash. Every export is readable
by whoever has the file (the encrypted one by whoever also has its password), so the apps say so and suggest deleting it.
* **Bitwarden-compatible CSV** (`export_csv`): `folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp`. The
  folder is the item's first tag; type is `login` or `note`; cards and identities are notes whose details are `Name: value`
  lines in `fields` (as are custom fields); several websites and `androidapp://<package>` entries are comma-separated in
  `login_uri`. Not in the CSV: passkeys, password history, further tags and whether a field is hidden.
* **Passyble JSON** (`export_json`): `{ "format": "passyble-export", "version": 1, "exported_at": <ms>, "items": [...] }`,
  each item as its JSON record (snake_case keys, kinds `login | note | card | identity`, passkey binary values in standard
  base64): everything, including passkey private keys, custom fields, tags and password history. `import_parse` detects it by
  the `format` key.
* **Encrypted JSON** (`export_encrypted_json`): `{ "format": "passyble-export-encrypted", "version": 1, "kdf": { "alg":
  "argon2id", "m_kib": 65536, "t": 3, "p": 1, "salt": "<b64, 16 random bytes>" }, "nonce": "<b64, 24 bytes>", "ct": "<b64>" }`
  (standard base64 with padding). `key = Argon2id(password, salt; m_kib, t, p)` (32 bytes); `ct = XChaCha20-Poly1305(key,
  nonce, plaintext = the Passyble JSON, AAD = "passyble/export/v1:" + JSON(kdf))` where `JSON(kdf)` is the file's `kdf` object
  as serialized, keys in the order alg, m_kib, t, p, salt: the KDF parameters are authenticated, so changing them fails.
  `export_decrypt` applies the vault's KDF bounds (argon2id only, `m_kib` ≤ 1 GiB, `t` 1..=20, `p` 1..=16) before doing any
  work, refuses a newer `version`, and answers `InvalidPassword` for a wrong password. `export_is_encrypted` tells the
  file apart; `import_parse_with_password` decrypts and imports in one call.

**Password health** (`Core/core/src/health.rs`, offline, no secrets in the report): over live items with a password,
**weak** = strength score ≤ 1 (`password_strength`: an entropy estimate in bits from the cheapest split into common
passwords and words, also capitalised or in leetspeak, runs, sequences, keyboard rows, years and single characters;
< 28 bits 0, < 36 1, < 60 2, < 80 3, else 4), **reused** = the exact same password on two or more live items, **old** =
unchanged for more than 365 days (`password_changed_at`, else `updated_at`), **contains a name** = the password contains
the username (or an email address's local part) or the site's name (the first label of the registrable domain), at least 4
characters, case and leetspeak ignored, weak ones left out, and **unsecured website** = a saved `http://` address to a
public host. Local and private hosts are left out, where plain http is normal: `localhost`, single-label names, `.local`,
`.lan`, `.home.arpa`, `.home`, `.internal`, `.intranet`, `.localdomain`, `.localhost`, `.test`, `.example`, `.invalid`,
loopback, 10/8, 172.16/12, 192.168/16, link-local, 100.64/10 and IPv6 unique-local addresses. "Change to https"
(`health_use_https`) only rewrites the scheme, and only of addresses that are domain names without a port (an IP
address or a port usually has no certificate for https); after it, an https login is never filled into the http page
(`matching.rs`), so the user is told to change it back in the editor if the site has no https.

Two account checks use **offline directories** compiled into the core (`Core/core/src/sites.rs`): `Core/core/data/2fa-directory.tsv`
(the [2FA Directory](https://2fa.directory), MIT, about 2 450 sites, 160 KB) and `Core/core/data/passkeys-directory.tsv` (the
[Passkeys Directory](https://passkeys.2fa.directory), CC BY 4.0, about 400 sites, 27 KB), one `domain TAB codes TAB link`
line per site, refreshed with `node scripts/update-site-security.mjs` (downloads the directories' JSON APIs and reduces them;
commit the result). Nothing is looked up at runtime. A website matches by its host, then each parent domain down to its
registrable domain (`signin.aws.amazon.com` finds `aws.amazon.com` before `amazon.com`), then any entry with the same
registrable domain, shortest first (the directory lists Google only by subdomains). **Two-factor sign-in**: a checked item
whose site offers a second step and that has no TOTP secret and no passkey (it may be on with SMS or another app: the apps
say so); the report carries the methods and the directory's "how to turn it on" link. **Passkeys**: a checked item whose
site supports passkeys and that has none, a suggestion. Over every live login: **no password** (a username or website,
but no password, passkey or TOTP secret) and **duplicates** (the groups of Find duplicates, `import/duplicates.rs`; the
apps link to the merge).

**Healthy** (the "N of M passwords look good" summary) counts the checked items with none of the password problems:
weak, reused, old, contains a name, unsecured website; after a breach check the apps also count breached items as not
healthy. Missing two-factor sign-in, a possible passkey, duplicates and logins without a password are listed but don't
lower it: they are about the account, not the password, and two-factor sign-in may already be on without Passyble
knowing. The optional breach check uses Have I Been
Pwned's range API with k-anonymity: `hibp_prefix` splits the uppercase hex SHA-1 of a password into 5 + 35 characters, only
the 5-character prefix is ever sent (`https://api.pwnedpasswords.com/range/<prefix>`, `Add-Padding: true`), and `hibp_match`
looks for the suffix in the answer. Nothing is checked unless an app asks.

**Checking one password before it is saved** (`Core/core/src/password_check.rs`, `password_issues`). The save prompts
(the extension's **Save login?** / **Update password?** banner, Android's own save sheets, or the "Saved" toast when Android
saves without one) and the item
editors (Windows app, popup, Android) say, short and plain, what is wrong with the password about to be saved, as a
warning that never blocks saving: on the bundled common-passwords list (`Core/core/data/common-passwords.txt`, about 1 300
entries written for Passyble, also matched capitalised, in leetspeak and with up to 4 digits and 2 symbols added), easy
to guess (strength score ≤ 1, as Weak above), reused by other live logins (exact match; the item being edited or
updated doesn't count, the trash is ignored), used before on the same login (its password history), contains the
username (or an e-mail's local part, or a piece of it) or the site's or app's name (≥ 4 characters, case and
leetspeak ignored), shorter than 12 characters. Each issue has a severity (high, medium, low) and what the message
needs (a count, the name found, the minimum length); the editors show a subtle "Strong" when there is nothing to say
and offer "Use a strong password instead" when an issue is more than a hint (not in the save prompts: the site already
has that password). **All of it runs on the device**: the password, its hash or any part of it is never sent anywhere,
logged, cached or stored, and the Have I Been Pwned check is not used for it. The Windows app calls the core through
its `password_check` command; the extension asks the desktop agent (`password.check`, PROTOCOL.md §2), which runs the
same core function on the PC and answers with codes only; Android calls it through UniFFI. Locked (the agent's vault,
or a sheet shown before unlock), only the checks of the password itself run.

Untrusted input: 50 MB file cap (also per decompressed ZIP member and in total, read through a bounded
reader whatever the ZIP header claims), 10 000 ZIP members, 100 000 entries, images ≤ 8000 px a side, a
bounded protobuf reader, serde_json's recursion limit, and the third-party QR decoder runs under
`catch_unwind`. Every TOTP value is validated with `totp_parse` and every passkey key is parsed as a
P-256 PKCS#8 key before it's accepted.

## 7. Security notes

* **The master password rule.** A copied vault file is protected by its master password alone (offline
  guessing, slowed by Argon2id with 64 MiB, t = 3, p = 1), so a *new* master password must pass one rule,
  defined only in the core (`Core/core/src/password_check.rs`, `master_password_check`) and used by every app
  wherever one is chosen: a new vault, Change master password, a new one after a recovery code, a newly chosen
  Passyble Server password (which is also the vault's), the browser's own vault. At least 12 characters, not a
  common password (also with capitals, leetspeak, digits or symbols added), and a strength estimate of at least
  "good" (60 bits) where the user's e-mail address, user name, vault name and the word `passyble` count as known
  to the attacker; repeated characters or blocks, sequences and keyboard walks (`1qaz2wsx`) are cheap in the
  estimate (`health.rs`). The apps show the reasons live as the password is typed and refuse it until it passes;
  the commands that set it check again. Only new passwords are judged: unlocking, signing in with an existing
  server password and opening a file never check the rule, so older, weaker master passwords keep working. The
  encrypted export's file password keeps its own, separate minimum.
* Decrypted secrets exist only in the unlocked process (Android app process, desktop app). The browser
  extension never stores secrets, and its message channel is scoped per request.
* **Keys in locked memory** (`Core/core/src/secmem.rs`). The vault key, earlier vault keys and the
  key-encryption key live in one 16 KiB region per process that is locked in RAM (`VirtualLock`, `mlock`),
  so the system never writes them to swap or the Windows pagefile, and left out of crash dumps
  (`WerRegisterExcludedMemoryBlock` on Windows, `MADV_DONTDUMP` on Linux and Android). Best effort: if the
  system refuses, keys still work (unlocking never fails over it), and they are zeroized on drop either
  way. Decrypted item fields are ordinary (zeroized where the core can) heap memory; the hibernation file
  holds all of RAM, locked or not.
* **Desktop process hardening** (`Core/agent/src/harden.rs`, release builds; debug builds with
  `PASSYBLE_HARDEN=1`), in the app and the native messaging host:
  * Windows: no Windows Error Reporting dump (`SEM_NOGPFAULTERRORBOX`), and a process DACL that leaves the
    user's other processes only `SYNCHRONIZE`, the two query rights and `PROCESS_TERMINATE` (no memory read
    or write, remote threads, handle duplication or debugging; `OWNER RIGHTS` takes away the implicit
    `WRITE_DAC`; SYSTEM keeps full access). The IPC peer check, the installer's running-app check and
    Task Manager keep working.
  * macOS: `RLIMIT_CORE` 0 and `ptrace(PT_DENY_ATTACH)`, on top of the hardened runtime.
  * Linux: `RLIMIT_CORE` 0. Not `PR_SET_DUMPABLE` 0: it hides `/proc/<pid>/exe`, which the IPC peer check
    reads in both directions. Same-user ptrace is left to Yama (`ptrace_scope` 1 on most distributions).
  * Residual risk: an administrator, the kernel, malware already inside the process (an injected DLL) or
    the WebView processes that draw the windows (separate processes with default protection, holding what
    is on screen) are not covered. A password manager can't defend against a compromised machine.
* **Screen capture.** Every desktop window (main, prompt, TOTP popup, quick pick) is excluded from
  screenshots, recordings, screen sharing and window previews (`WDA_EXCLUDEFROMCAPTURE` on Windows,
  `NSWindowSharingNone` on macOS), always, like Android's `FLAG_SECURE` (no setting on either). Linux has
  no equivalent (X11 lets any client read the screen; Wayland asks the user through the portal). iOS covers
  the app switcher with a privacy screen.
* The agent rechecks URL ↔ item matching for every `logins.fill`, `totp.get` and passkey call, so a
  compromised page cannot ask for another site's credential by item id.
* Passkey RP ID checks: `rp_id` must equal the origin's host or be a registrable-domain suffix of it
  (WebAuthn §5.1.3), never a public suffix, and only `https` (or `http://localhost`) origins are accepted.
  The desktop agent also requires the request's `origin` to be an exact http(s) tuple origin
  (`https://host[:port]`): an opaque origin (`"null"`, a sandboxed frame), another scheme or a URL with a
  path is `url_mismatch` (PROTOCOL.md §2).
* The UV flag of a desktop passkey response is set only after real user verification (Windows Hello, or the
  unlock the request itself triggered). A consent click is user presence (UP) only.
* Auto-lock after inactivity (default 15 min) and on OS lock; by default a *soft lock* that keeps a list of
  the items without secrets on screen (§12). Clipboard is cleared after 45 s. The auto-lock and the per-fill
  verification grace period ("Require Windows Hello / biometrics before each fill") are **sliding**: each
  credential use (a fill, a copied password, username or 2FA code, a passkey sign-in, auto-type) starts them
  again at the full time the user chose, never more, and only once the use went through (a cancelled or
  refused fill extends nothing). What runs on its own never counts: in the desktop agent the requests the
  extension sends by itself (`status`, `logins.find`, the save banner's checks, `password.check`, icons, 2FA
  outcome reports; PROTOCOL.md §2, "Activity"), the app's sync, health checks and window refreshes; on Android
  autofill looking at a focused field and the Credential Manager sheet listing accounts. Edits and searches
  count for the auto-lock, not for the grace period. "Ask for the master password every N days" is a policy and
  never slides; locking on Win+L, sleep and the screen turning off is unchanged.
* Android's auto-lock **"On every restart"** (no timer, not on screen off) keeps the vault unlocked until the
  phone restarts, also when the app is closed or Android ends its process: the vault key is kept on the phone
  wrapped by an AES-256-GCM Keystore key that needs no user authentication but works only while the phone is
  unlocked (`setUnlockedDeviceRequired`), together with the boot it was saved in (`BOOT_COUNT` and the
  monotonic clock, bound into the encryption). Another boot, another auto-lock choice, an organisation's
  maximum auto-lock, any lock, signing out, removing the vault, a due master password, changed biometrics and
  a biometric lockout delete it (Android README, "Auto-lock"). Trade-off: anyone using the unlocked phone, and
  code running as Passyble on it, can open the vault without a prompt until the phone restarts; a locked or
  restarted phone can't. The setting says so where it is chosen.
* Website icons (§11) are the only requests that go to sites the user has logins for: an anonymous
  HTTPS GET of the site's public page and icon, carrying only the host name. They can be turned off per
  device ("Show website icons"), which also deletes the cached icons.
* E-mail alias services (§14) are contacted only after the user set one up with their own API token, and
  only when they create an alias or press Test. The token is kept encrypted in the vault, never logged or put
  in a URL or an error message; the site's name goes along only when the user ticks "Mention the website".
* A desktop save that fails (a sync client or antivirus holding the file) is retried by the next save; when
  the vault locks with unsaved edits they are written to `<vault>-unsaved-<ms>.vault` beside it, which the
  next unlock merges in like a conflict copy, so locking never discards edits. The agent merges and removes only
  files it recognises as such: its own `-unsaved-` stashes and the conflict copies of OneDrive, Dropbox, Syncthing and
  Google Drive (name patterns in PROTOCOL.md §2, "Conflict copies"). A user's manual backup next to the vault, such as
  `pass-backup.vault`, is never read, merged or deleted.
* **Lookalike sites** (`Core/core/src/lookalike.rs`). Autofill only offers the logins of the page's own site,
  so a phishing copy on another domain gets nothing by itself; the gap is a login the user picks by hand. The
  core says whether a page (or an Android app, as `androidapp://<package>` read backwards as a domain) looks
  like one of the user's sites without being it (`lookalike_of`, `Vault::lookalike_for_url` for one login,
  `Vault::lookalike_for_save` for every login): the same name to the eye once look-alike characters are folded
  (Cyrillic, Greek and Armenian letters, accents, `0`/`o`, `1`/`l`, `rn`/`m`, `vv`/`w`, a hand-picked part of
  Unicode TR #39's confusables, no new dependency), an `xn--` or mixed-script name one or two letters away,
  one typo (added, missing, changed or swapped letter) in a name of 5 to 8 letters or two in a longer one, the
  whole domain inside another site's address (`paypal.com.example.net`, `paypal.com-secure.net`) or path, and
  the name as one hyphenated word (`paypal-login.com`). It never warns for the same registrable domain (any
  subdomain), a site of any login in the vault (including domains linked to the same login), the same name
  under another public suffix (`amazon.de` for `amazon.com`), names shorter than 5 letters for typos, IP
  addresses or single-label hosts. Where it is asked:
  * the browser extension's popup search (`logins.search` with the tab's `url` marks each result with
    `lookalike`): a red "Lookalike site" tag, and filling (`logins.fill_cross`: the desktop prompt's red
    banner, or the browser vault's own question) or copying the password or 2FA code asks first, Cancel
    focused. The in-page menu lists the page's own logins, and on a page without any its "Similar sites"
    (below), which never include a lookalike;
  * the save banner (`logins.save_check` answers `save_new` with `lookalike`): a red note above Save;
  * Android's autofill "Search vault" picker and the iOS AutoFill list (All logins, search): a warning
    before a login of another site is filled (on Android before "Always suggest" links it, too).
  International (`xn--`) addresses that look like none of the user's sites only get a quiet note in the
  popup and the save banner ("International address"); most are real sites. Credential Manager on Android
  offers matching logins only, and desktop auto-type knows window titles, not addresses, so neither has a
  hand-picked login on a page to check.
* **Similar sites** (`Core/core/src/similar.rs`, `similar_logins`). A page without a saved login is often a site
  the user has a login for under another address. The core finds a few such logins for it: a website with the
  page's name (its registrable domain without the public suffix, the Public Suffix List as everywhere) under
  another suffix or subdomain (`amazon.de` or `amazon.co.uk` for `amazon.com`, `login.acme.io` for `acme.com`;
  names of 2 letters or more), else a title that holds the name (as a word for names of 3 or 4 letters, anywhere
  for longer ones). Never a login of the page's own registrable domain, never another site under a shared
  suffix (`bob.github.io` for `alice.github.io`: two names), and never a login whose site the page looks like
  (the lookalike check above): lookalikes only show in an explicit search, with their warning. The browser
  extension offers them under "Similar sites" (`logins.similar`), and a pick is a cross-site fill with the
  desktop app's prompt like any search result. After such a fill the extension offers "Use this login on
  <site> too?": `logins.add_url` adds the page's origin to the login with the fill's one-time token (future
  fills there are automatic, no prompt), or the existing save path stores a separate copy.

### What leaves your device, and how

Everything you keep in Passyble (titles, user names, passwords, websites, notes, 2FA secrets, passkeys,
cards, identities, custom fields, password history, tags, settings such as e-mail alias tokens, usage counts,
the keys you share vaults with) leaves a device only inside the encrypted vault file, or sealed for a person
(emergency access, admin recovery), or sealed for a link (secure send). The vault key never leaves a device
unencrypted, and nobody who stores the file can read or change items without it. What travels in the clear is
the bookkeeping needed to store, merge and route the file, listed below. Tests that put a recognisable
"canary" in every field and search every request and every stored byte for it (plain, base64, hex, JSON or
percent escaped, gzip): `core/src/gdrive/tests.rs` (`google_drive_never_sees_a_vault_secret`),
`core/tests/no_plaintext.rs` (files, exports, account service uploads, lookups, error messages),
`wasm/tests/drive.rs` (the browser's own vault) and the Server repository's `tests/no_plaintext.rs` (a real
Passyble Server, self-hosted and in cloud mode, every byte through a relay, its disk and its log).

**Google Drive** (only if you turn on the backup)

| Google sees | Encrypted |
|---|---|
| your Google account, one file per vault in Passyble's hidden folder, its size and change times | everything in the vault |
| the file name `pass-<vault id>.vault` and the vault id (a random UUID) | |
| **the vault's name, readable** (the one cleartext value) | |
| the vault file's bookkeeping, as for a server (below) | |

The vault's name is stored readable on Google Drive (file property `pass_vault_name`) so that a new device can list your vaults
by name before anything is unlocked; otherwise people could not tell which master password belongs to which vault. The apps
say so where the name is asked for. Everything else stays encrypted, and the name is kept out of logs and debug output.

**Passyble Server or WebDAV** (Nextcloud, a NAS, your own server)

| The server sees | Encrypted |
|---|---|
| your user name, the devices you signed in (their names), your IP address, when you sync and the file's size | everything in the vault |
| the vault file's bookkeeping: vault id, file version, when the master password changed, the key derivation's parameters and salt, and per item its random id, when it changed, which device changed it (a random id) and whether it is deleted | the vault key (wrapped with your master password) |
| whether a recovery code exists (its id and date), how many devices recorded usage, older keys' count | the recovery code's copy of the key |
| on a Passyble Server: your password verifier (never the password), your two-step secret, the security log | |
| shared vaults: the members list (account names, roles, public keys, group ids, who added whom and when), the names an admin gives vaults and groups | each member's copy of the vault key |

A WebDAV host sees the same file at the address you chose, and your WebDAV user name.

**Passyble Cloud** (a Passyble account: Teams, Family, sharing)

| The service sees | Encrypted |
|---|---|
| everything a Passyble Server sees (it hosts the vault files) | everything in the vaults |
| your e-mail address, your devices' names, your organisation's name, the names of its departments and shared vaults, who is invited and their roles | |
| your public sharing keys and their fingerprint | your private keys (in your own vault) |
| emergency access: owner, contact, view or full, the waiting period | the vault key, sealed for the contact and locked by a release secret the service keeps |
| admin recovery: that you opted in, the team, the approving admin | your vault key, sealed for the team's recovery key |
| secure send: when it expires, how many views, its size, a proof of the password if there is one (it keeps a hash) | the text or file and its name; the key is only in the link |

**Have I Been Pwned** (Password health, "Check for breaches")

| The service sees | Never sent |
|---|---|
| the first 5 characters of each password's SHA-1 hash, padded answers, your IP address | the password, the rest of its hash, the item, which site it is for |

**Website icons** (the "Show website icons" setting, on by default, off per device)

| The website sees | Never sent |
|---|---|
| an anonymous HTTPS request for its own page and icon, the host name only, your IP address | the item, your user name, cookies, any other site |

**Support tickets** (only when you send one)

| Passyble support sees | Never sent |
|---|---|
| the subject and text you write, your e-mail address (without an account) | anything from the vault |
| optional diagnostics, shown in full before sending: app, version, platform, system version, sync type, recent error codes, language | names, addresses, URLs or file paths in the diagnostics |

E-mail alias services (§14) get your own API token and, only if you tick it, the site's name, when you create
an alias. Every request goes over HTTPS, or plain HTTP only to a loopback or private address (§9).

## 8. Repository layout

```
Core/core/                 pass-core: vault, shared vaults, crypto, totp, passkey, matching, generators, alias services, merge, webdav, import, export, health, icons
Core/agent/        pass-agent: session, IPC server, request handlers (headless, tested)
Core/native-host/  pass-native-host: Native Messaging ⇄ agent IPC bridge
Core/desktop-app/          Tauri v2 app (Windows): UI, tray, hotkey auto-type, TOTP popup, consent
Extension/            MV3 browser extension (plain ES modules, no build step)
Android/              Android app (Kotlin, Compose); uses pass-core via UniFFI + cargo-ndk
Server/               pass-server: optional self-hosted vault host (WebDAV subset, versions, backups)
docs/                 this file, PROTOCOL.md
```

## 9. Passyble Server (optional, self-hosted)

`Server/` (crate `pass-server`) stores vault files for people who do not want to run Nextcloud. It is
zero-knowledge: it only ever handles the encrypted vault file and never sees a master password or vault
key.

```
 devices (pass-core webdav_sync)        pass-server (tokio + hyper/axum, rustls)
 ── GET  /dav/<owner>/<vault>.vault ──▶ auth: Basic user:token / Bearer → SHA-256 lookup in state.json
 ◀── 200 + ETag                         per-IP failed-auth limiter (429)
 ── PUT + If-Match / If-None-Match ──▶  body ≤ 64 MiB → tmp file → fsync → lock vault → check ETag (412)
 ◀── 201/204 + ETag                     → hard-link old file into versions/ → rename → fsync dir → prune
                                        backup scheduler → tar.gz → OpenDAL (fs, s3, ftp, webdav, sftp)
                                                                   or scp / rclone binaries
```

* **Protocol**: exactly what `Core/core/src/webdav.rs` uses: `GET` (with `Cache-Control: no-cache`, and
  `If-None-Match: <etag>` once synced, answered `304` from a cached ETag without reading the file), `PUT`
  with `If-None-Match: *` (first upload) or `If-Match: <etag>`, HTTP Basic auth, 404 for "no remote yet",
  412 for "someone else wrote first", 401/403 for auth errors. ETags are strong and content-derived. So
  existing clients sync with it unchanged. See [PROTOCOL.md §3](PROTOCOL.md#3-pass-server).
* **Accounts and devices**: `state.json` maps accounts to devices (random 256-bit tokens, stored as
  SHA-256) and vaults to owners and members. The admin CLI edits it under a file lock; the server reloads it
  when it changes, so `pair` and `revoke` apply immediately.
* **Account passwords, zero-knowledge** ([PROTOCOL.md §3.4](PROTOCOL.md#34-accounts-and-passwords-sign-in-zero-knowledge)):
  the admin creates a user with an initial password (`pass-server user add`); the user signs in from the app
  with server, user name and password, and must replace an admin-set password before the device may touch
  the vault. One password is both the sign-in and the vault's master password, yet the server can't open
  the vault:
  * The client sends only `auth_key = HKDF(Argon2id(password, account salt))`. The server stores
    SHA-256(`auth_key`). Neither the password nor the vault key ever reaches the server.
  * The vault's KEK is Argon2id over the same password but with the **vault file's own salt**, so
    `auth_key` is useless for unwrapping it. From what the server holds (verifier, salts, parameters,
    encrypted vault), the only way in is guessing the password at Argon2id cost per guess, exactly as
    before accounts existed, since the server always had the encrypted vault. Clients refuse KDF parameters
    below Argon2id 64 MiB / t = 3 (what every client sets), so a hostile server can't downgrade that cost.
  * An admin-set password is replaced before the vault exists (the client creates the vault only after the
    user chose their own password), so the admin never knows a password that encrypts it. The replacement
    is always forced (the old `--no-force-change` is refused); for an account an older version created
    with it (`password_admin_known`), the user's first password change also rotates the vault key.
    An admin `reset-password` doesn't touch the vault: the user's devices re-wrap it after the user proves the
    previous password (or from a device where it is still unlocked); the admin can't recover a vault. It
    revokes the account's device tokens, like a reset link.
  * **Invites** (no admin-known password at all): with e-mail configured, `pass-server user add --email`
    creates the account without a verifier and e-mails a one-time code; the user chooses the password on
    their device, which then creates the vault. The admin never knows any password of that account.
  * **Admin accounts only through such links**: the first admin (`pass-server setup`) and every
    `user add --admin` get a one-time setup (invite) link, never a password typed on the server; the
    admin chooses it in a Passyble app, so the server CLI never processes an admin's password.
    `user reset-password` refuses admins (they get a reset link). The removed `--admin-password-stdin`,
    `PASS_ADMIN_PASSWORD` and `--no-force-change` fail with an explanation of the setup link.
* **E-mail and password resets** ([PROTOCOL.md §3.5](PROTOCOL.md#35-e-mail-invites-and-password-resets)):
  lettre over SMTP (rustls), templates compiled in and overridable. One-time codes (128-bit, SHA-256
  stored, single use, 7 days / 1 hour) arrive as an HTTPS page plus a `pass+server://…&invite=|reset=` link;
  the Windows app registers that URL scheme. `POST /api/v1/reset/request` answers `202` for everything and
  works in the background (no enumeration through content or timing), with per-IP / per-account / per-address
  quotas; links are built from configured URLs only (no `Host`-header poisoning). Zero-knowledge consequence:
  **a reset recovers the account, not the vault.** The server can only replace the password verifier and
  revoke every device token; the vault still opens only with the old password. The client re-wraps it from
  a device where it is unlocked (or unlockable with Windows Hello / biometrics, which wrap the vault key
  itself), or with the previous password; otherwise the user starts a new, empty vault that replaces the old
  one on the server (`webdav_replace`), which keeps the old file as a version in case the password turns up.
  Someone who takes over the user's mailbox can therefore take over the *account* (and is announced by the
  "password changed" notification), but gets no items.
  * What a malicious server *can* do is unchanged: withhold or roll back the encrypted file (versions make
    that visible to devices that merge), and phish the password through a modified client, which is out of scope,
    as for any hosted password manager.
* **Two-factor sign-in, audit log, metrics** ([PROTOCOL.md §3.7-§3.9](PROTOCOL.md#37-two-factor-sign-in-totp)). A user can
  turn on TOTP for their account (RFC 6238, 10 single-use recovery codes). It guards password sign-ins and password
  changes (reset and invite links included, so a mailbox alone can't take over the account), not tokens that already
  exist; codes are checked ±1 step and once only, and wrong ones count like wrong passwords. The admin turns it off per
  account (`user 2fa-reset`). This stays zero-knowledge: the TOTP secret is readable in `state.json`, but it signs in
  nobody without the password, which the server never has. Security events (sign-ins, failures, devices, password and
  two-factor changes, admin commands; never a secret) go to a rotated JSON-lines `audit.log`, which `pass-server audit`
  reads and users see for their own account (`GET /api/v1/security-events`). `GET /metrics` (Prometheus, off by default)
  needs a bearer token, or comes only from the machine itself without a proxy header, or is served on its own listener.
* **Pairing**: `pass-server pair` prints a `pass+server://host/path?v=1&user=..&token=..&pin=..` link and a
  terminal QR code; `pass-server invite` prints a token-less sign-in link (`pass+server://host/?v=1&user=..&pin=..`). `pin` is the SHA-256 of the self-signed certificate's public key; clients need a
  pinning verifier for it (PROTOCOL.md §3.2).
* **TLS**: rustls with a provided certificate, an auto-generated self-signed certificate (rcgen) that
  clients pin, or plain HTTP on loopback behind a reverse proxy (refused elsewhere unless
  `insecure_http`).
* **Versions and backups**: every accepted upload keeps the previous file (retention by count and age).
  Backups bundle the encrypted files into one checksummed archive per run, upload it to each target, read
  it back, and apply per-target retention; status is in `/status`.

## 10. Sync: what is stored where, and when clients talk to the server

**Stored on each device**: the whole vault, encrypted (§1): logins, notes, TOTP secrets and passkeys
are all items in the one vault file, so autofill, TOTP codes and passkey sign-ins work offline and
never wait for a server. Desktop: the `.vault` file chosen in Settings (optionally in a cloud folder).
Android: app-private storage (`filesDir`), plus the picked document for SAF vaults. Unlocking needs the
master password or a device-wrapped vault key (§1); the server is not involved.

**Stored on the server** (WebDAV or Passyble Server): the same encrypted file, as uploaded by the last
device that had something new. The server never sees the master password, the vault key or any
plaintext item.

**When clients talk to the server.** Only when there is a reason, and an idle check is cheap:

| trigger | desktop (`Core/desktop-app/src-tauri/src/background.rs`, `sync_schedule.rs`) | Android (`SyncManager`, `SyncSchedule`) |
|---|---|---|
| unlock | sync at once | sync at once |
| local edit | ~2 s after the last edit (debounced) | unique work, 2 s initial delay, replaced by every edit |
| usage counts only (§13) | never on their own: uploaded with the next sync, or after 6 h | same |
| app / window comes back | window focus or wake from sleep, if the last check is > 20 s old (Google Drive) or > 5 min old (WebDAV, Passyble Server) | Google Drive: the foreground checks below start at once when the last check is older than their interval; others: `ProcessLifecycleOwner` ON_START, at most every 5 min |
| periodic, Google Drive | every 20 s while a window has focus or the vault was used in the last 2 min; every 2 min while the user is active on the PC (last 15 min); every 15 min when idle | every 20 s while the app is in the foreground and unlocked; every 1 h in the background (battery not low, skipped in battery saver) |
| periodic, WebDAV / Passyble Server | every 30 min, only while unlocked *and* used in the last 30 min | every 1 h (network connected, battery not low) |
| periodic, Passyble Cloud (paid plans only) | every 60 s while in use, every 5 min when idle; the browser extension checks on a 1 min alarm. Failures back off from 30 s up to 10 min; a 429 sets the interval to 5 min for 1 h | every 60 s in the foreground, every 15 min in the background; the same backoff and 429 rule |
| about to be used, Google Drive | the browser extension asks for logins (`logins.find`, `logins.search`) and the last check is > 20 s old | autofill or the Credential Manager is asked and the last check is > 30 s old (queued work; the fill never waits) |
| network back, Google Drive | (a failed check backs off; the next one after it) | `registerDefaultNetworkCallback`, if the last check is > 20 s old |
| "Sync now" | yes | yes |
| locked | never (merging needs the vault key) | the run only downloads the remote file for the next unlock |
| failures | backoff 30 s doubling with +-20 % jitter, up to 15 min (Google Drive) or 1 h | checks: the same backoff; uploads: WorkManager exponential backoff |
| rate limit (Drive 403 `rateLimitExceeded` / `userRateLimitExceeded`, 429) | the backoff above, and the focused interval is 2 min for the next hour; counted in the log and "Report this problem" (`sync.gdrive_rate_limited`) | same (`SyncSchedule`, logcat `PassSync`) |

Every periodic interval gets +-20 % jitter, so devices that woke together drift apart. A background check with
nothing to upload doesn't show "Syncing..." (the status line just says "Synced just now" afterwards), and takes the
shared vaults of Teams and Family (one conditional request each to Passyble Server) along at most every 5 min.
Google Drive's request budget for these intervals is in docs/GOOGLE_DRIVE.md, "How often it syncs".

**What one sync costs** (`webdav_sync`). The vault keeps, in the local file, the remote ETag and a
fingerprint (hash of `header_updated_at` and every record's `(id, updated_at, device_id)`) of the
server's copy as of the last successful sync. `Vault::sync_pending()` = the local fingerprint differs
(or never synced).

| situation | requests |
|---|---|
| nothing changed anywhere | `GET` + `If-None-Match` → `304`, no body. 1 request. |
| local edit only | `304`, then `PUT` + `If-Match`. 2 requests. |
| another device changed it | `GET` → `200` + file, merge. Plus a `PUT` only if this device also has something new. |
| lost race (`412` on `PUT`) | full `GET`, merge, `PUT` again (up to 4 attempts) |
| first sync / other URL | `GET` (404 → `PUT` + `If-None-Match: *`; 200 → merge, `PUT` if needed) |

Servers that ignore `If-None-Match` answer `200`; the client recognises the copy it already merged
(same fingerprint), skips the merge and doesn't upload, so such servers cost one download per check.
Before this change every sync downloaded the full file (and Android rewrote the local file each
time), every 5 min on desktop and every hour on Android, whether or not anything had changed.

With a typical day (a handful of edits, the app opened a few times) a WebDAV or Passyble Server device makes on
the order of tens of requests per day, almost all of them bodiless `304`s. A Google Drive device checks more often
while in use (every 20 s), each check one small metadata request (docs/GOOGLE_DRIVE.md).

**What a merge keeps.** Every transport (WebDAV, Passyble Server, Google Drive, a cloud folder and its
conflict copies, the desktop agent's dirty check, the phones' saves) ends in the same `Vault::merge_remote`,
which merges items field by field (§1, "Concurrent edits of one item"): two devices that edit different fields
of one item before they sync both keep their edits, and when both changed the same field the newer value is
kept and the other stays reachable (password history, joined lists, or a "… (conflict)" copy). What it needs
travels inside the encrypted file, so no transport keeps any merge state of its own.

Cloud-folder sync (OneDrive, Dropbox, Syncthing) does not involve these requests: the desktop agent
re-reads the vault file when its modification time changes (checked every 30 s, a local `stat`).
Every save is a dirty check (`Agent::save`, `VaultStore::replace` in `Core/agent/src/store.rs`): the agent
merges the file if it changed since it was last read (modification time and length), encrypts, writes a
temporary file and flushes it to disk, and renames it over the vault only if the file still has the stamp
it merged (checked again before each rename attempt; on Unix the folder is flushed after the rename). A copy
a sync client put in place meanwhile makes the save merge it and try again (up to 4 times, then the edit
stays in memory for the next save, and locking keeps it beside the file as `<name>-unsaved-<ms>.vault`). The
stamp of the file as written is taken before the rename, and an unlock keeps the stamp from before it read
the file, so a copy that lands right after either is merged, never taken for the agent's own.

### Google Drive (`Core/core/src/gdrive.rs`, docs/GOOGLE_DRIVE.md)

A third sync backend, besides WebDAV and Passyble Server, for people who want "it just works like
WhatsApp". Each vault is one file, `pass-<vault id>.vault`, in the user's Drive **app folder**
(`appDataFolder`, scope `drive.appdata`): hidden from the Drive UI and from other apps, and Passyble
can't see the user's other files. The platform signs in with Google (Android: Google Identity
Services `AuthorizationClient`; desktop: loopback + PKCE, refresh token in Windows Credential Manager)
and passes a fresh access token on every call. The core never stores tokens.

| situation | requests |
|---|---|
| nothing changed anywhere | `files.get?fields=id,version,md5Checksum,…`. 1 small request. |
| local edit only | that, then `PATCH …?uploadType=media&keepRevisionForever=true`, `revisions.list`, unpin the previous revision. 4 requests. |
| another device changed it | metadata, `alt=media` download, merge, `revisions.list`; if this device has something new too: metadata again, then upload |
| another device renamed it | metadata only (version moved, same MD5) |
| first sync on a device | `files.list` by name, then download + merge or create (+ a list to catch a twin) |

The sync state (file id, `version`, MD5, fingerprint) sits in the same local-only `SyncState` as
for WebDAV. Drive v3 has **no conditional upload**, and `version` only promises to increase, so a
write that lands in the last moment before ours is overwritten. To make the window small, the version
is checked again right before an upload that follows a merge. What still slips through is caught
with pinned revisions: every upload sets `keepRevisionForever`, and the uploader then lists the
revisions; a pinned one it doesn't hold is an overwritten write, which it downloads, merges and
uploads again before unpinning anything (docs/GOOGLE_DRIVE.md, "Concurrency"). An interrupted check is
redone on the next sync, and any device that downloads a changed file merges stray pinned revisions
too, so the write survives even if both devices go away. Older clients don't pin; their overwritten
writes come back the old way, because merging is per item: the overwritten device still has its
changes, sees a newer version on its next sync, merges it, finds its own items missing remotely and
uploads them again. Two devices creating the file at once leave twins; the oldest wins, and the
others are merged into it and deleted once unchanged since the merge. While the file is less than 7
days old, every sync looks it up by name, so a twin the first listing missed is still found.

**Threat model.** Google sign-in authorizes storage only; it is not a key. Google (or anyone with
the Google account) gets the encrypted vault file and can attempt an offline guess of the master
password against the Argon2id-wrapped key, exactly like a WebDAV host could. Google can't read items.
It can see the file's size, change times and the random vault id (`appProperties`, so a new phone can
list vaults before unlocking) and the vault's name, readable for the same reason (§7, "What leaves your device, and how"). It can delete or roll back the
file. Every device keeps a full local copy, and merging never accepts an older item version, so a
rollback can't undo newer local items: they are uploaded again. A malicious file that isn't this
vault (different vault id or key) fails to merge and is reported, never adopted. Access tokens live
only in memory. On Android, Play services holds the refresh credentials; on desktop, the refresh
token is in Windows Credential Manager. Only the account e-mail is stored in Passyble's settings.

## 11. Website icons (`Core/core/src/icons/`)

Item avatars show the site's own icon instead of the first letter when one can be found. The core does the
fetching and keeps the cache rules, so Windows and Android behave the same:

* **Which host.** `site_icon_domain(url)` takes the item's first http(s) URL: lower-case host, without
  `www.` and the port. App links (`android://`), IP addresses, `localhost`, intranet names (`.local`,
  `.internal`, …) and hosts under no known public suffix get no icon (no request at all).
* **Resolution** (`fetch_site_icon`), on `https://<host>/` and then on its registrable domain: the web app
  manifest (`<link rel="manifest">`, else `/manifest.json`, `/site.webmanifest`) and its 192×192 icon, then
  512×512, then the closest of at least 128 px; `<link rel="apple-touch-icon">` (180 px first); `<link
  rel="icon">` of at least 128 px; `/apple-touch-icon.png`; the smaller `<link rel="icon">`s, largest first;
  `/favicon.ico`. SVG is skipped. The first candidate that decodes as a raster image (PNG, JPEG, ICO/BMP,
  WebP, GIF) of at least 16 px wins, and it is re-encoded as a PNG of at most 128 px: nothing the site sent is
  shown as is.
* **Privacy and safety.** Requests are plain anonymous GETs: no cookies, no `Authorization`, no `Referer`,
  `User-Agent: Passyble-icon/1`; only the host name comes from the vault. HTTPS only, at most 3 redirects and
  only to HTTPS, host names only, and DNS answers in private, loopback, link-local or CGNAT ranges are refused
  (a public name can't aim the fetch into the local network). Timeouts: 3 s to connect, 5 s per request,
  20 s and 16 requests per domain. Caps: 256 KB of HTML (the `<head>` comes first), 128 KB per manifest,
  512 KB per image, 4096 px per side when decoding. What the fetch reveals: each site (and its CDN, and
  anyone watching the network or DNS) can see that this device asked for its icon, i.e. that the user
  probably has a login there. That is why the setting exists, and its (i) says so.
* **Cache** (`site_icon_cache_*`): one file per domain in the app's cache directory (Windows
  `%LOCALAPPDATA%\Pass\icons`, Android `cacheDir/icons`), named by the hex SHA-256 of the domain so a
  directory listing doesn't spell out the sites (a guess can still be confirmed by hashing it). An icon is
  refreshed after 30 days (and shown meanwhile), "this site has none" is retried after 7 days, an unreachable
  site after a day; a failed refresh never drops a cached icon. Icons aren't secrets and aren't encrypted;
  they never enter the vault or sync.
* **When.** The apps fetch lazily in the background when an item is shown, at most 4 at a time, only while
  the vault is unlocked and the setting is on; turning it off stops the queue and clears the cache. The
  desktop agent only reads the app's cache (`icons.get`, PROTOCOL.md) for the extension popup, and only for
  logins that match the current page; the extension and Android's autofill service never fetch.

## 12. Soft lock: the list stays, the secrets go

Locking used to hide everything; now an auto-lock keeps the vault *list* on screen, and only using a secret asks
to unlock. Same model on Windows (desktop agent + app), Android and, through the agent, the browser extension.

* **What stays in memory.** After the first successful unlock in a session, locking softly keeps a list of the
  items without secrets: `pass_core::ItemSummary` (PROTOCOL.md §1): id, kind, title, username, websites and
  linked Android apps (for matching a page or an app and for site icons), the primary domain, `has_password` /
  `has_totp` / `has_notes`, passkey account names, RP ids and (public) credential ids, favourite, timestamps.
  Also its tags, a card's brand, last four digits, cardholder and expiry, an identity's name, e-mail and company, and
  `has_fields` (§2). Never a password, 2FA secret, note, password history, custom field value, full card number, security
  code, PIN, passkey private key or user handle. The vault key, the
  decrypted vault and every other secret are dropped exactly as before. The list is built from the vault right
  before it locks; it is never in saved state, logs or sync.
* **Kept across restarts (Windows).** So the browser extension can list the logins right after Passyble starts
  (Windows sign-in, restart, update, crash), the agent also keeps the same list on disk
  (`Core/agent/src/kept_list.rs`): `%LOCALAPPDATA%\Pass\kept-lists\<vault id>.bin`, sealed with DPAPI
  (`CryptProtectData`, current user, app-specific entropy), with the vault file's id. Written at unlock, at
  every lock (soft or full) and at most every 10 s while the vault changes; read at start-up, when the agent then
  starts soft-locked. Ignored and deleted if it doesn't open for this user, is damaged, or the vault file now
  holds another vault; not read while the vault file can't be read. Deleted by "Lock completely", turning
  "Keep list visible when locked" off (every vault's), removing the vault, and this device being signed out of
  Passyble Server (nothing is written again until the next unlock). Quitting, restarting, updating and
  switching vaults drop the list from memory but keep the file, so they behave as soft locks across the restart. Android keeps its own encrypted copy
  (Android/README "Soft lock: the list stays").
* **Soft by default, full only on request.** Every automatic lock and every ordinary "Lock" is soft: auto-lock
  (timeout), OS lock (Win+L / screen off), sleep, the plain "Lock" (Ctrl+L, the window's lock button, tray, the
  Android lock button), and quitting, restarting, updating or process death, which keep the list on disk so the
  next start is soft-locked (Windows; Android likewise restores it in a new process). Going to the background is
  no lock. The one user action that hides the list is the clearly labelled **Lock completely** ("Also hides the
  list until you unlock": Windows tray, Ctrl+Shift+L and the lock button's menu, which opens on right-click or on
  a click while soft-locked; Android ⋮ on the list); it also deletes the copy on disk. Switching to another vault
  takes the list off the screen (another vault is shown) but keeps its copy on disk; removing the vault, this
  device being signed out of Passyble Server, and turning "Keep list visible when locked" off drop it for good.
  That setting (default on, per device, on both apps) makes every lock a full lock when off. The extension has no
  lock action of its own.
* **While soft-locked.** Lists, search, titles, usernames and site icons stay visible (Windows vault view,
  Android vault list, the extension popup and in-page menu; Android autofill and Credential Manager label their
  entries with the real titles and usernames). Copying a username needs no unlock (it is in the list). Anything
  that needs a secret or changes the vault (fill, auto-type, copy or reveal a password or 2FA code, notes,
  edit / save / delete, "Update password" from the save banner, passkey use) first shows the normal unlock
  (Windows Hello / biometric / master password per the vault's policy) and then completes that action; nothing
  asks to unlock on its own (no Windows Hello / BiometricPrompt when the window or app comes back). A full lock, or
  a fresh start without a kept list, shows the unlock screen as before.
* **Threat model.** The soft lock protects secrets, not the list. Someone at an unlocked PC or phone after an
  auto-lock can see *which* accounts exist (titles, usernames, websites), the same as glancing at the window
  before it locked, but cannot get a password, code, note or passkey without the master password, Windows Hello
  or the device biometric. Memory forensics of a running soft-locked process can recover the list but no key
  material. The kept copy on disk tells the same list to anyone who can act as this Windows user (malware
  running as the user, or the disk together with the user's Windows credentials), never a secret; another
  user or a disk alone can't open it. Users who don't want the list visible use "Lock completely" or turn the
  setting off.
* **Windows** (`Core/desktop-app`, README "Locking and the list kept on screen"). The main window stays on the vault
  view with a **Locked** pill; `list_items`, `search`, `get_item` and copying a username answer from
  `Agent::summaries()` (items marked `locked`, with `has_password` / `has_totp` / `has_notes` instead of the
  secrets); every other vault command answers "The vault is locked", and the window then opens the vault's
  unlock form in a dialog over the list (Windows Hello at once when set up, since the user just asked for
  something) and runs the action again. `save_item` refuses a copy read while locked, so a race with an unlock
  can't wipe a password. The `lock-state` event and the extension's `lock_state` carry `soft`; the unlock
  screen's automatic Windows Hello is disarmed for a soft lock. Tray **Lock**, Ctrl+L and the lock button are
  soft (also while already soft-locked: the button then opens its menu); **Lock completely** (tray, Ctrl+Shift+L,
  the lock button's menu) is full. Auto-type, the extension and the Windows passkey provider ask for an unlock as before.
  Website icons show from the cache only; nothing is fetched until the next unlock (also on Android).
* **Android** (Android/README "Soft lock: the list stays"). `VaultState.SoftLocked` keeps the list's screens
  (list and item details; editors, Settings and import close). Secret actions go through `UnlockGate`, a sheet
  with the usual unlock panel that completes the action after unlocking; nothing prompts on resume. Autofill
  answers a soft-locked request with the real rows, matched over the list (`summaries_for_url` /
  `summaries_for_android_app`, verified app domains), each a placeholder with dataset authentication
  (`DatasetAuthActivity` unlocks, then fills that login, or its fresh 2FA code, in the same step). Credential
  Manager lists the passwords and passkeys from the list the same way; the get activities unlock, check the
  caller against the unlocked vault as for an unlocked request, and hand out the credential.
  Android is the one exception to "memory only": Android kills background apps freely and autofill then runs in
  a new process, so with the setting on the list is also saved encrypted (AES-256-GCM, a non-auth-bound,
  device-bound Keystore key, `noBackupFilesDir`, `KeptListStore`), deleted by Lock completely, removing or
  replacing the vault and turning the setting off (switching vaults leaves it, `LockRules.keepsSavedList`), and a
  new process restores it as soft-locked. Process death is therefore not a full lock there.
* **2FA codes are masked** in the apps' item views and popups (••• •••, with the countdown): Windows' item pane
  and TOTP popup show them on hover, press-and-hold or the eye toggle; Android's item details on the eye or
  while held, its one-time-code notification on **Show**. Copying never needs revealing. Autofill code rows
  (Android) show the item's name, never the code. The lists and the quick-pick don't show codes at all.


## 13. Usage counts: the most used logins first (`Core/core/src/usage.rs`)

Every client counts how often each login is used and suggests the most used first: the extension's in-page
menu and popup, Windows auto-type, Android autofill and Credential Manager.

* **What counts as a use** (`Vault::record_use(item_id, now_ms)`): a login actually handed out for a
  sign-in. Filling it (extension `logins.fill` / `logins.fill_cross`, Android autofill dataset), auto-typing it,
  copying its password or 2FA code from an app or the popup, a password picked in Credential Manager, a passkey
  sign-in (extension, Windows passkey provider, Credential Manager). Not: finding, listing, viewing, copying a
  username, creating or editing. Uses of the same item within a minute count once (one sign-in may fill and
  then copy the code).
* **What is stored.** Per device, per item: a count and the time of the last use. Each device's counts are one
  JSON object sealed with the vault key (XChaCha20-Poly1305, AAD `"pass/usage/v1:" + JSON[vault_id, device_id,
  updated_at]`), kept in the vault file's optional `usage` array:
  `"usage": [ { "device_id": "…", "updated_at": 1730000000000, "nonce": "b64", "ct": "b64" } ]`.
  Zero-knowledge like the items: the file's host (Drive, WebDAV, Passyble Server, a cloud folder) sees only how
  many devices recorded usage and when each last changed its counts, never which items or how often. Counts of
  at most 16 devices are kept: the ones that wrote theirs last, by the same rule on every device (a device that
  records a use is the latest). A device drops its counts for deleted items when it next writes them.
* **Why next to the items, not inside them.** Item records merge last-writer-wins on their cleartext version
  (§1). If a use changed the item, a fill on one device would win over a real edit made on another device in
  the meantime, and every fill would change "modified" times and look like an edit to sync. So a use never
  touches the item, its version, `updated_at` or `Vault::revision`.
* **Merge** (in `Vault::merge_remote`): a grow-only counter. Only a device writes its own blob; when two copies
  of a device's blob differ, the one holding everything the other has is kept (the newer if both hold the same),
  and if each has counts the other lacks (a copy restored from an old file and used again) they are merged, per
  item the larger count and the later use, into a new version. Commutative, idempotent, never loses a use, and
  never an update, an added item or a conflict copy in the merge stats. A damaged or forged blob (wrong AAD) is
  ignored; usage is never a reason to refuse a file.
* **Ranking** (`ItemUsage::rank`, `ItemSummary::rank`): a frecency. Over every device, the count on a log scale
  (`log2(1 + count)`: 1 use = 1, 3 = 2, 7 = 3) halved every 30 days since that device last used the item. Every
  device's term decays at the same rate, so the order doesn't change as time passes, and `rank` stores it as a
  time: the last use, moved later by 30 days per doubling of the weighted count (0 = never used). Order where
  logins are suggested: match quality first (the matching rules are unchanged; for web pages the same host is one
  tier whether or not a stored path matches too, so an imported login saved with its sign-in page's path doesn't
  outrank the most used login of the host, while other subdomains of the site still come after), then favorites,
  then rank, then title (`find_for_url`, `find_for_android_app`, the `summaries_*` finders, auto-type). Search
  (`Vault::search`, `summaries_search`, `logins.search`, `Core/core/src/search.rs`): fuzzy match quality first, then favorites,
  rank, then title.
  Passkeys: most used first, then account name. Vault lists keep their title order unless a "Most used" sort is
  picked (`summaries_most_used`).
* **Sync.** A use marks the vault dirty (saved locally soon, the desktop agent at once) but is no reason to
  sync: `Vault::sync_pending()` covers items and the header only, the revision doesn't change, so no "edited"
  debounce sync starts. The fingerprint in the local sync state (§10) is the items' fingerprint followed by
  `|` and a hash of the usage blobs' versions (unchanged for a vault without usage, so existing sync states stay
  valid), so any sync for another reason (unlock, an edit, focus, the periodic check, "Sync now") uploads the
  counts along, and `Vault::usage_sync_pending()` says some are waiting. `Vault::usage_sync_due(now)` turns
  true once they have waited 6 hours (from the first unsynced use, or from the unlock after a restart), and the
  schedulers then sync for them alone.
* **Older clients** ignore the `usage` field and drop it when they write the file. Nothing else is lost: the
  devices that recorded the uses still have them and upload them again with their next sync.

## 14. Username and e-mail generator (`Core/core/src/generator.rs`, `Core/core/src/alias.rs`)

Next to the password generator, every app generates usernames and e-mail addresses for new logins (Windows: the
editor's username field; Android: the item editor and the generator; extension: the popup editor's username field,
through the desktop app).

* **Usernames** (`generate_username`, local, OS CSPRNG): two words (`Swift-Otter`, an adjective and a noun from
  word lists written for Passyble in `Core/core/src/words.rs`, about 15 bits; options: capitalize, a 4-digit number,
  separator `-`, `_`, `.` or none), word and number (`Otter4821`) or random lowercase letters and digits (4 to 64,
  starting with a letter). Usernames aren't secrets: the point is a different one per site.
* **Plus addressing and catch-all** (`generate_email`, local): `alex+k3vq9tmz@example.com` from the user's own
  address, or `k3vq9tmz@mydomain.com` for a domain of theirs that accepts any address. The tag is 8 random
  characters, or with "Mention the website" the site's name (`github`). Nothing leaves the device.
* **E-mail alias services** (network, optional): a new alias at the user's own account, over the service's
  official HTTPS API. Set up in Settings (Windows: This vault, Username and e-mail generator; Android: Settings)
  with the account's API token and a Test button. The configs, the default service and the user's address and
  domain are kept in the vault's settings blob (§1, "Vault settings"): encrypted with the vault key, synced with
  the vault, never in a plain settings file; the Windows window gets back only whether a token is saved. The
  browser extension never holds a token or an address: it asks the desktop app (`generate.email`, PROTOCOL.md §2)
  and gets the alias.

### Network connections of the alias services

A service is contacted only when the user has set it up, and only when they create an alias or press Test.
Nothing is sent in the background, at startup or on sync. Every request uses the core's one HTTP stack (ureq with
rustls), 10 s to connect and 30 s per request, no redirects (so a token can't be forwarded elsewhere), and carries
the token only in a header. Tokens never appear in URLs, logs, `Debug` output or error messages. Without "Mention
the website" (off by default, never remembered by the Windows app) a request says nothing about the site.

| Service | Create (what is sent) | Test (makes no alias) |
|---|---|---|
| SimpleLogin (`app.simplelogin.io`, or a self-hosted `https://` server) | `POST /api/alias/random/new`, header `Authentication: <API key>`; with the site: `?hostname=<host>` and body `{ "note": "Website: <host>" }`, else `{}`. Answer: `alias` (or `email`) | `GET /api/user_info` |
| addy.io (`app.addy.io`, or self-hosted) | `POST /api/v1/aliases`, `Authorization: Bearer <token>`, `X-Requested-With: XMLHttpRequest`, body `{ "domain": <alias domain, default anonaddy.me> }` plus `"description": "Website: <host>"` with the site. Answer: `data.email` | `GET /api/v1/account-details` |
| Firefox Relay (`relay.firefox.com`) | `POST /api/v1/relayaddresses/`, `Authorization: Token <API key>`, body `{ "enabled": true }` plus `"generated_for"` and `"description": <host>` with the site. Answer: `full_address` | `GET /api/v1/profiles/` |
| DuckDuckGo Email Protection (`quack.duckduckgo.com`) | `POST /api/email/addresses`, `Authorization: Bearer <token>`, no body: the site is never sent. Answer: `address` + `@duck.com` | none exists: Test makes an address and says so |
| Fastmail masked e-mail (`api.fastmail.com`, JMAP) | `GET /jmap/session` (Bearer token with the Masked Email scope; the account for `https://www.fastmail.com/dev/maskedemail`), then `POST` to the session's `apiUrl` (only one on `api.fastmail.com`, else `/jmap/api/`) with `MaskedEmail/set` creating `{ "state": "enabled", "description": "" }` plus `"forDomain": "https://<host>"` with the site. Answer: `created.<id>.email` | `GET /jmap/session` (and the scope is there) |
| Forward Email (`api.forwardemail.net`) | `POST /v1/domains/<domain>/aliases`, HTTP Basic with the token as user name, body `{}` (a random name) plus `"labels"` and `"description"` with the site. Answer: `name` + `@` + `domain.name` | `GET /v1/domains/<domain>` |

Answers: 401 (or 403 without a message) is "didn't accept the API token", 429 "too many requests", other 4xx show
the service's own message, 5xx "has a problem (HTTP n)", an unreadable answer "sent an answer Passyble doesn't
understand"; every message names the service. The desktop agent allows the extension at most 10 new aliases a
minute. The tests (`Core/core/src/alias.rs`) check every request and answer against canned responses, with no network.

## 15. Shared vaults: Family, Teams and direct shares (`Core/core/src/share/`, `Core/core/src/vault/shared.rs`)

This section is the format and the rules as the core builds them, including department vaults, direct shares,
the fill-only role and the certificate chain.
The core holds the cryptography and the file format. Who may download or upload a vault, invitations, seats and
groups belong to the account service and the server; the apps turn their lists into member changes.

### 15.1 Model

* An **organisation** (a family or a team) has any number of **shared vaults**. Access is per vault and per
  account, with a role: `manage`, `edit`, `view` or `fill` (§15.7).
* A **department** is a group of accounts kept by the account service. It is not a key holder: the members list
  of a vault always names accounts, and a manager's app expands a group into its members when it signs the list.
  Each entry records the group it came through (`group`, optional), so the apps can show "via Engineering" and a
  manager's app can bring the vault in line when the group changes (`Vault::sync_group`).
* A **direct share** ("Shared with Bob") is a small shared vault of two or a few members in the same format, made
  with kind `direct` instead of `org`, so the apps word it as a share rather than a department vault. Sharing one
  item means moving or copying it into such a vault (§15.8). Direct shares work between any two accounts of the
  same Passyble Server or Passyble Cloud, also outside an organisation, unless the organisation's policy "sharing
  outside the team (or family)" forbids it: the app asks `policy_allows_share(policy, recipient_in_org)` (§17)
  before it creates the share or adds someone from outside.
* Every member keeps their own personal vault. The one they joined from is their **home vault**: it holds their
  keyset and what their devices remember about each shared vault.

### 15.2 User keys (`share/keys.rs`)

* A **keyset** is an X25519 key pair (vault keys are wrapped for it) and an Ed25519 key pair (members lists are
  signed with it), made on the device from the OS random number generator.
* The private keys are a setting of the home vault (§1, "Vault settings"): key `account.keys.v1.` followed by the
  first 32 hex digits of SHA-256(account id), value `{"v":1,"account","created_at","enc_sk","sig_sk"}`. Sealed
  with the home vault's key, synced with it, never in an item, never in a plain file, never in a shared vault.
  `Vault::ensure_user_keyset` makes one when there is none.
* **Public keys** for the account service: `{account, enc_pub, sig_pub, created_at, sig}`, where `sig` is the
  Ed25519 signature, by the keyset's own signing key, of the bytes `"pass/userkeys/v1:" + account id + enc_pub
  (32 bytes) + sig_pub (32 bytes) + created_at (8 bytes, big-endian)`. Everything after the account id has a fixed
  length, so the concatenation is unambiguous. `PublicKeys::verify` checks it.
* **Account ids are per backend.** On Passyble Cloud the id is the account service's `acc_…`; on a self-hosted
  Passyble Server it is the user's name there (the server accepts only public keys whose `account` is the publishing
  user's name, and checks the self-signature itself). One person keeps **one keyset** and publishes it under each
  backend's id: `Vault::publish_keys_for(account)` (or `UserKeyset::public_keys_for`) gives the same keys with a
  self-signature for that id, and a signature for one id never verifies for another. The home vault stores the
  keyset once per account id (`ensure_user_keyset` reuses the keys already kept for another id), and the members list
  of a shared vault names each member by the id of the backend that hosts that vault; the app opens it with that id.
* **Fingerprint**: the first 150 bits of SHA-256(`"pass/userkeys-fp/v1:"` + enc_pub + sig_pub) as six groups of
  five characters in the recovery code's alphabet (Crockford's base32): `7K3QD-…`. 150 bits fill
  the six groups the apps already show for recovery codes.
* Crypto suite: HPKE (RFC 9180) base mode with DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and ChaCha20-Poly1305
  (crate `hpke` 0.12.0); Ed25519 with strict verification (crate `ed25519-dalek` 2.2.0). Nothing else is new:
  the commitments are HMAC-SHA256 and the digests SHA-256.

### 15.3 File format (version 2)

A shared vault is a vault file with `"version": 2`. Items (with item AAD v2 and merge metadata), the settings blob,
usage blobs, `key_check` and `previous_keys` are exactly those of §1; the header differs:

```jsonc
{
  "format": "pass-vault", "version": 2, "vault_id": "uuid", "header_updated_at": 1730000000000,
  "access": "members",
  "kdf": { "alg": "none", "m_kib": 0, "t": 0, "p": 0, "salt": "" },   // placeholders, see "Older clients"
  "wrapped_key": { "nonce": "", "ct": "" },
  "key_check": { "nonce": "b64", "ct": "b64" },                      // as v1, sealed with the current key
  "genesis": { "created_by": "acc_…", "sig_pub": "b64", "created_at": 1730000000000,
               "kind": "org" | "direct", "org": "org_…" /* optional */, "sig": "b64" },
  "members": {
    "cert": { "epoch": 7, "key_epoch": 3, "prev": "b64" /* absent at epoch 1 */,
              "managers": [ { "account": "acc_…", "sig_pub": "b64" } ],
              "entries_digest": "b64", "vk_commitment": "b64", "signed_by": "acc_…", "sig": "b64" },
    "entries": [ { "account": "acc_…", "role": "manage" | "edit" | "view" | "fill",
                   "enc_pub": "b64", "sig_pub": "b64", "group": "grp_…" /* optional */,
                   "wrapped_key": { "enc": "b64", "ct": "b64" }, "added_by": "acc_…", "added_at": 1730000000000 } ],
    "chain": [ { /* the cert of epoch 6 */ }, { /* epoch 5 */ }, … ]   // newest first, at most 64
  },
  "previous_keys": [ … ], "items": [ … ], "settings": { … }, "usage": [ … ]
}
```

* **Genesis**: signed by the creator over `"pass/genesis/v1:" + JSON[vault_id, created_by, sig_pub, created_at,
  kind, org]`. Its digest, SHA-256(`"pass/genesis-digest/v1:"` + that message + `sig`), goes into every list's
  signed message, so a list can't be moved to another vault, even one made under the same id. The genesis never
  changes; a merge refuses a copy with another one.
* **Entries** are sorted by account, one per account, at most 1000.
* **Wrapped key**: HPKE seal of the 32-byte vault key to `enc_pub`, `info` = `"pass/member-vk/v1:" + JSON[vault_id,
  account, key_epoch]`, empty AAD. A wrapped key opens only for that vault, that member and that key epoch
  (JSON keeps an account id with a colon unambiguous).
* **Certificate** (the signed part): `entries_digest` = SHA-256(`"pass/members-entries/v1:"` + JSON(entries)),
  `managers` = the entries with role `manage` (sorted, with their signing keys), `vk_commitment` =
  HMAC-SHA256(vault key, `"pass/vk-commit/v1:" + JSON[vault_id, key_epoch]`), `prev` = the digest of the
  certificate it replaces. `sig` is Ed25519 by `signed_by` over `"pass/members/v1:" + JSON[vault_id,
  genesis_digest, epoch, key_epoch, prev, managers, entries_digest, vk_commitment, signed_by]`. A certificate's
  digest is SHA-256(`"pass/members-digest/v1:"` + that message + `sig`).
* **Chain**: the certificates of the lists before, newest first, linked by `prev`, epochs one apart, key epochs
  never going down. A writer keeps the last 64. Without entries they stay small (a few hundred bytes each).
* Signed messages and digests are made from the parsed fields with serde_json, like the AADs of §1. A field this
  version doesn't know would be dropped by that, so a list with fields of a later version fails to verify instead
  of being half understood: a change to the list's fields needs a new `pass/members/v2` prefix.
* No `header_auth` and no `recovery`: the members signature authenticates the header, and no password or code
  opens a shared vault. A reader drops either block if a file has one.

### 15.4 Verifying a members list

A list is genuine when every step is signed by someone allowed to sign it:

1. The entries are well-formed and match the certificate (digest, managers, at least one manager).
2. The chain is followed as far back as it links up.
3. An **anchor** is found. With a trust record (below): the newest certificate of the list or its chain that this
   device accepted before. On a first open: the oldest certificate in the file, which must be the epoch-1 list
   signed by the genesis creator. Only when the vault has had more changes than the chain keeps (epoch above 65)
   can the oldest be later; it is then taken on first use (signed by one of its own managers), and
   `SharedInfo::anchored` is `false`, so the app shows who signed the list (`signed_by`) and the fingerprint of
   that manager's keys (`SharedInfo::signer_fingerprint`), for the member to compare with the manager before relying
   on it. When the signer has left the list (a manager who left, §15.6) the fingerprint is `None` and the app shows
   the current managers' fingerprints (`members`) instead. A younger list whose chain doesn't reach the genesis was
   cut and is refused.
4. Every certificate after the anchor must be signed by a manager **of the certificate before it**, with the
   signing key that certificate lists. A key in the new list never vouches for itself.

**Trust record** (`ShareTrust`: the vault id, the genesis digest and the path of accepted certificates, the newest
last, at most 64) is kept in the home vault (`share.trust.v1.` + 32 hex digits of SHA-256(vault id)), so the
user's devices share it; `Vault::open_shared_with_home` reads and updates it, `Vault::share_trust` gives the
current one after a merge. Opening refuses another genesis under the remembered id (`Conflict`), a list older
than the newest accepted one (`Conflict`, "older than one your devices already opened": a rollback), and a newer
list that can't be tied to the path because more than 64 changes happened since (`Crypto`, ask a manager; the app
may `forget_share_trust` after the user confirmed the signer's fingerprint with them).

**Which list wins**: of two genuine lists, the one later in the order (key epoch, epoch, digest). Along a chain
both epochs only grow, so a list always beats the ones it was built on, and of two lists made at the same time
from the same one every device picks the same. The key epoch comes first so that a removal (which rotates the key)
is never undone by a concurrent change that didn't rotate it.

### 15.5 Merging two copies

`merge_remote` of a shared vault looks at the members list first, then merges items, settings and usage exactly as
for a personal vault (§1):

* The remote list is ignored unless it verifies against this copy's accepted path (§15.4). An ignored list's key
  is not trusted either: its items merge only if they are encrypted with a key this copy knows.
* A genuine list that wins is adopted. If it has a new key, the device opens its own wrapped key, checks it
  against `vk_commitment` and the file's `key_check`, and re-keys: the old current key and every earlier key
  (this copy's and the remote's) become `previous_keys` sealed with the new one, and everything is re-encrypted
  on the next save. Unsynced local edits are kept.
* A genuine list that loses but has a key of its own (a rotation on a branch that lost) gives that key to this
  copy as an earlier key, so the items written with it merge and are re-encrypted with the winner's key.
* If the winning list no longer names this device's account, the merge stops with "you no longer have access",
  and with another key for it, "shared with other keys of your account".
* Two managers changing members at once: one list wins everywhere. The losing manager's device notices (its own
  lists are remembered until another copy carries them in its chain) and **applies the lost changes
  again** on top of the winner, signed anew, when each still makes sense and the account still manages the vault:
  an `Add` of someone not in the winner, a `SetRole`, `SetGroup` or `ReplaceKeys` of someone still there, a
  `Remove` of someone still there. A change the winner already made is neither; one that no longer makes sense (the
  person was removed meanwhile, or added with other keys), or any change once the account no longer manages the
  vault, is dropped. `Vault::take_members_notice` reports both (`MembersNotice { reapplied, dropped,
  rotated_after_leave }`), so the app can say "Your change to Engineering was applied again" or "... couldn't be
  applied". Save and upload after a merge with a notice. The unconfirmed changes survive a restart: the home
  vault keeps them in its local file only (`local_members`, sealed with the home vault's key, never in the uploaded
  copy, like the WebDAV sync state), written by `Vault::remember_trust_of` (call it after every member change and
  every sync, then save the home vault) and taken back by `Vault::open_shared_with_home`. On that open, changes the
  opened list was built on are confirmed, the change that made the current list stays unconfirmed, and any other
  change lost to a list merged in before the restart is applied again at once (with its notice).
* The members certificate's signature is mixed into the sync fingerprint, and `remote_is_behind` re-uploads a
  copy with another list.

### 15.6 Changing members (`Vault::change_members_pinned`, `Vault::change_members`)

A manager's device makes a new list (epoch + 1) signed with its keyset; several changes go into one list
(`MemberChange::Add`, `SetRole`, `SetGroup`, `ReplaceKeys`, `Remove`). Changes that wrap the vault key to keys not
yet in the list (`Add`, `ReplaceKeys`) go through `change_members_pinned(changes, home)`, which refuses keys the
user hasn't pinned (§15.16); `change_members` takes the others and refuses those two.

* **Add**: the account service hands out `PublicKeys`; the core checks the self-signature, and the app shows the
  fingerprint to compare with the person and pins it (§15.16). The vault key is wrapped for the
  new entry.
* **Remove** and **ReplaceKeys** (a member set up new keys after losing their home vault) rotate the key: a new
  vault key, key epoch + 1, wrapped for every remaining member, the old key kept in `previous_keys` so remaining
  members still merge older copies (the key replacement of §1). `rotate_shared_key` does the same without a
  change. The account service also revokes the server access at once; the removed member keeps what their devices
  had downloaded, and the app offers to change those passwords.
* A list always keeps a manager. A manager may **leave** (`Vault::leave_shared`, a `Remove` of their own account)
  while another manager remains: a new list without them, with a new key wrapped for everyone else (it has to be
  made by the leaving device, which re-encrypts the vault for the upload). Since the one who left knows that key,
  the first remaining manager whose device opens or merges a list signed by someone no longer in it replaces the
  key once more (`MembersNotice::rotated_after_leave`). Until then items saved by others are readable with the
  leaver's key, by the leaver with the host's help. A member who doesn't manage the vault leaves through the account
  service, which revokes their server access; a manager's app then removes them (`sync_group` or `remove_member`).
  A manager can't re-key themselves (`ReplaceKeys` of their own account: another manager does).
* **Groups**: `sync_group(group, members, home)` adds the group's missing members (recording the group), updates the role
  of those it added, and removes those who left the group. Members added directly or through another group are
  left alone: a member in two groups is listed once, under the group that added them, so an app that maps several
  groups to one vault passes their union.
* The core never talks to the account service or the server; the app uploads the vault and asks the account
  service to update the server's access list.

### 15.7 Roles: what enforces what

| Role | May | Enforced by |
|---|---|---|
| manage | edit, sign members lists | the members signature (cryptographic): every device checks it |
| edit | add, change, delete items | the server's access list (who may upload at all) |
| view | read and copy everything, change nothing | the server refuses a viewer's upload; the core refuses edits, deletes and trash purges. The viewer holds the vault key, so this is server-enforced, not cryptographic |
| fill | fill logins, 2FA codes and passkeys, never see or copy a password | the apps only. The core exports nothing from such a vault, refuses copying items out of it and answers `can_reveal_secrets() == false`; the apps hide Reveal, Copy, the password history and Export. The device still holds the vault key and the items, so a modified app could read everything: fill-only keeps honest people from seeing a password, it does not keep a secret from someone who wants it |

Unknown roles in a list (from a later version) read as `fill`, the least access.

### 15.8 Moving and copying items between vaults

`Vault::copy_item_to(id, target)` and `move_item_to(id, target)` work between any two vaults (personal to shared,
shared to personal, shared to shared). The item gets a new id in the target and keeps everything else: password
history, passkeys, custom fields, tags, its creation date and the date its password was set. A move then deletes
the original for good (a tombstone, which syncs), so it doesn't linger in a shared vault's trash. Copying needs a
role that may see secrets; moving needs edit in the source; both need edit in the target. A copied passkey exists
twice (same credential id) and works from both vaults; usage counts stay with the original.

### 15.9 Older clients

Clients that predate sharing read the whole file into their v1 structure before they look at the version, so a
file without `kdf` and `wrapped_key` would make them say "not a Passyble vault". Version 2 files therefore carry
placeholders for both (`alg: "none"`), and those clients say "this vault was made by a newer version of Passyble.
Update Passyble to open it". This reader now looks at `format` and `version` first, so a later version is reported
the same way whatever else it changes. A shared vault's file never opens with a master password, a device key or a
recovery code ("it opens with your Passyble account").

### 15.10 Attacks considered

| Attack | What stops it | Test (`core/src/vault/shared_tests.rs`) |
|---|---|---|
| The host or account service swaps a member's public key in the file, so the next rotation wraps the key for it | the entries digest and the manager's signature; rotations wrap for the keys of the verified list | `the_host_cannot_swap_a_members_public_key` |
| The host serves an older list (a removed member back, the old key) | the trust record: older than the newest accepted is refused, and a merge never adopts a list that doesn't win | `an_older_members_list_is_not_accepted_again` |
| A removed member uses their old key | key rotation; the old wrapped key is bound to the old key epoch; their copy can't follow the new list | `a_removed_member_can_open_neither_the_new_file_nor_its_key` |
| A viewer (who holds the vault key) signs a list making themselves a manager, or cuts the chain for a newcomer | a step must be signed by a manager of the step before; a young list must reach the genesis | `a_viewer_cannot_forge_a_members_list` |
| A wrapped key moved from another vault, member or epoch | the HPKE info | `the_wrapped_key_is_bound_to_its_vault`, `share::keys` tests |
| Another vault presented under a known id | the genesis digest in the trust record and in every signature | `another_genesis_under_the_same_id_is_refused` |
| Two managers change members at once | the order of §15.4; the losing manager's device applies its lost changes again, or drops and reports them | `two_managers_changing_members_at_once_converge`, `a_removal_wins_over_a_concurrent_change_and_no_item_is_lost`, `two_concurrent_removals_keep_both_keys_and_every_item`, `a_lost_member_change_is_applied_again_and_reported`, `a_lost_change_that_no_longer_makes_sense_is_dropped`, `a_lost_change_is_dropped_when_its_manager_no_longer_manages`, `a_change_built_on_is_not_applied_twice`, `a_lost_member_change_is_applied_again_after_a_restart`, `a_change_lost_before_the_restart_is_applied_again_on_open`, `a_confirmed_change_is_not_applied_again_on_open` |
| A manager who left keeps reading what is added later (they made the key their leave rotated to) | the next remaining manager replaces the key; a lost leave is applied again | `a_manager_can_leave_and_the_next_manager_replaces_the_key`, `a_lost_leave_is_applied_again` |
| A first open of a list that can't reach the genesis | `anchored: false` and the signer's fingerprint to compare | `a_list_from_beyond_the_remembered_chain_is_not_trusted_blindly`, `the_signer_and_their_fingerprint_are_shown` |
| Many random changes and syncs | the same order everywhere | `members_and_items_converge_for_random_histories` |

### 15.11 Limits

* **First open.** A device that opens a vault for the first time trusts the genesis it finds (trust on first use).
  The genesis creator's account and the signer's fingerprint are in `SharedInfo` for the app to show; the account
  service can say which vaults the account was invited to. A host that makes a whole fake vault can show it, but
  can't put anything into the real one.
* **A removed manager with a colluding host** could still sign a list on a branch from before their removal; the
  account service revokes their server access when they are removed, and uploads to the server are conditional
  (`If-Match`), so this needs the host's help.
* **The trust record merges last-writer-wins** like every vault setting; two of the user's devices that accepted
  different lists keep the one written last, which is still a genuine list.
* **What a member downloaded stays theirs.** Removal stops future access only.
* **Lost member changes are kept in the home vault's local file** (§15.5): a device whose home vault file is lost
  (a new device) can't apply its own unconfirmed changes again; the change is then simply not in the list.
* Bindings: UniFFI (Android, iOS) and the WebAssembly module export the API (§15.15).

### 15.12 Emergency access (`share/emergency.rs`, `vault/teams.rs`)

The owner of a personal vault (Personal or Family plan) names a **trusted contact**: another Passyble account, whose
public keys the owner's app gets from the account service and whose fingerprint the owner confirms. If the contact
asks for access, the account service waits the **waiting period** the owner chose (1 hour to 90 days); unless the
owner refuses in that time, the contact gets **view** or **full** access, as the owner chose.

* **Grant** (`Vault::emergency_grant(owner, contact, access, wait_hours)`): the vault key is sealed twice. Inside,
  HPKE (§15.2's suite) to the contact's X25519 key, `info` = `"pass/emergency-vk/v1:" + JSON[grant_id, vault_id,
  owner, contact]`, the plaintext `{"v":1, grant_id, vault_id, owner, contact, access, vk}`. Around that,
  XChaCha20-Poly1305 with the key HKDF-SHA256(salt `"pass/emergency-release/v1"`, ikm = a fresh 32-byte **release
  secret**, info = the grant id), AAD `"pass/emergency/v1:" + JSON[grant_id, vault_id, owner, contact,
  contact_fingerprint, access, wait_hours, created_at, key_check]`. `key_check` = HMAC-SHA256(vault key,
  `"pass/emergency-key/v1:" + JSON[grant_id, vault_id]`). The app sends the grant (`EmergencyGrant`, its `blob`
  base64 `nonce || ciphertext`) and the release secret to the account service and keeps neither. Nothing in the
  vault changes.
* **Request, refusal, release**: the account service's (W3b). The contact asks; the service notifies the owner and
  waits; a refusal ends the request; after the wait it hands the contact the grant and the release secret.
* **Takeover** (`Vault::open_emergency(file, grant, release_secret, contact_keyset, device_id)`): opens both layers,
  checks the payload against the grant and the `key_check`, then the vault file's key check. View access opens the
  vault read-only (`Vault::is_read_only`: no edits, settings, new master password or recovery code); full access opens
  it for everything, and a new master password (`change_master_password`) takes it over. The owner's keyset is a
  setting of the vault, so full access also reaches the owner's shared vaults once the account service lets the
  contact download them.
* **Revoke**: the service deletes the grant and its secret; nothing in the vault is rotated. **Stale grants**: a new
  vault key (any `change_password`) leaves the grants holding the old key; `emergency_grant_current`
  says so, and `open_emergency` refuses ("the owner changed their vault's key"). The app sets them up again. After a
  takeover, the owner (if still there) cuts the contact off the same way, with a new key.
* **Trust model**: the service alone can't open a grant (it lacks the contact's private key) and the contact alone
  can't open it before the release (they lack the release secret). The service and the contact together can, at any
  time: the waiting period and the owner's refusal are the service's promise, not cryptography. A view-only contact
  holds the vault key on their device, like a shared vault's viewer: "view" is kept by the apps and by the server
  (which refuses the contact's uploads), not by the key. Only personal vaults: a shared vault's members already
  have it, and the core refuses (`emergency.personal_only`).
* Tests: `share::emergency` unit tests (`the_contact_opens_a_released_grant_and_nobody_else_does`,
  `the_service_cannot_change_what_the_owner_chose`, `grants_check_their_inputs`) and `core/tests/teams.rs`
  (`emergency_access_opens_after_release_with_the_access_the_owner_chose`).

### 15.13 Admin-assisted recovery (`share/org_recovery.rs`, `vault/teams.rs`)

A team or family member who forgot their password can get their vaults back with an admin's help, if they opted
in. **Off by default, per member.** Families were refused until 2026-11-23; the owner then allowed them (one
Passyble password design, decision 2), opt-in per member with the warning that the admins can then open every
linked vault. A member with a Passyble account enrolls the **account key** instead of the home vault key (§18.7).

* **The team's recovery key** (`org_recovery_create(admin, org, kind, admins)`): a new X25519 key pair; the
  public key, its id (base64 of the first 16 bytes of SHA-256(`"pass/org-recovery-id/v1:"` + public key)) and the
  creator are signed by the creating admin (`"pass/org-recovery/v1:" + JSON[org, key_id, recovery_pub, created_by,
  created_at]`); the private key exists only wrapped with HPKE for each admin's keyset (`info`
  `"pass/org-recovery-sk/v1:" + JSON[org, key_id, admin]`). `org_recovery_rewrap` wraps it for new admins. Removing
  an admin doesn't take back what they knew: a new key (`org_recovery_create` again, a new id), and members enroll
  again.
* **Opt-in** (`Vault::admin_recovery_enroll(key, creator, account, kind)`): the member's app checks the key's
  signature against the creating admin's public keys, which the member must have pinned (§15.16: compared the
  admin's fingerprint when joining; a recovery key the service planted is never enrolled), and never enrols again
  by itself after an e-mail reset or a new organisation key: it asks the member first and HPKE-wraps the home vault key to the recovery public key (`info` `"pass/org-recovery-vk/v1:" +
  JSON[org, key_id, account, vault_id]`), with a `key_check` (HMAC with the vault key). The enrollment goes to the
  account service; the vault records it (`admin_recovery_enrollments`). Opting out (`admin_recovery_withdraw`)
  forgets it here and asks the service to delete its copy; a new key makes any kept copy useless.
* **Recovery**: the member's new device makes a request with a one-time X25519 key pair
  (`admin_recovery_request(org, account, vault_id)`, the private half kept in the device's secure storage).
  **Comparison code** (design D3 of the server breach audit): the member's device shows
  `recovery_request_code(request)`, the first 80 bits of SHA-256(`"pass/org-recovery-code/v1:" + JSON[request_id,
  org, account, vault_id, enc_pub, created_at]`) in Crockford base32 (`7K3Q-D2MX-…`, four groups of four). The admin
  calls the member, who reads it out, and types it: `admin_recovery_approve(key, admin, enrollment, request, code)`
  refuses any other code (`recovery.code_mismatch`). Whoever holds the member's account can make a request, and a
  breached service could swap the request's one-time key for its own; either way the admin's request then has
  another code than the member's screen. 80 bits keep the service from trying keys until one gives the member's
  code. The approval opens the recovery private key and the enrollment,
  wraps the vault key to the request key (`info` `"pass/org-recovery-grant/v1:" + JSON[org, request_id, account,
  vault_id, approved_by, approved_at]`) and **signs** the approval (`"pass/org-recovery-use/v1:" + JSON[org, key_id,
  request_id, account, vault_id, request_enc_pub, approved_by, approved_at, key_check, enc, ct]`).
  `Vault::unlock_with_admin_recovery(file, approval, secret, approver, device_id)` checks the signature against the
  approving admin's public keys, opens the key, and **records the use in the vault** (`admin_recovery_log`:
  organisation, request, admin, the admin's fingerprint, when), which the member's other devices show after the
  sync. The member then sets a new master password.
* **Trust model**: opting in means any admin of the team can read the member's home vault whenever they like, with
  the member's enrollment and a copy of the vault file. Uses through the member's device are signed and recorded in
  the vault; the account service logs every approval in the member's activity. An admin who misuses the key with a
  copy of the file, outside the service, leaves no trace in either. The vault key is the same after a recovery
  (like a recovery code): the member may also choose a new key (any `change_password`), which then
  needs a new enrollment.
* Tests: `share::org_recovery` unit tests (`a_family_can_never_set_up_admin_recovery`,
  `an_enrolled_member_is_recovered_by_any_admin_and_the_use_is_signed`,
  `approvals_check_who_asks_and_who_approves`) and `core/tests/teams.rs`
  (`admin_assisted_recovery_restores_a_teams_member_and_shows_who_did_it`).

### 15.14 Several open vaults (`multi.rs`)

The personal vault and every shared vault are open side by side; the apps search, fill and save across them.

* `Vault::vault_summaries()` gives one vault's list (`VaultSummaries`: vault id, shared kind, this device's role,
  `can_edit`, `can_reveal`, the item summaries of §12). The apps keep one per vault, also for the soft lock (the
  list stays per vault, the secrets go with each vault's key).
* `multi_search`, `multi_for_url`, `multi_for_android_app`, `multi_with_passkeys` run the single-vault query over
  all lists as one, so the order across vaults is the order within one, and return each result with its `vault_id`
  (the same item copied into two vaults is two results).
* `multi_default_save_vault(groups, url, preferred)`: where a new login is saved unless the user picks another: the
  vault that already has a login for the site (if this device may edit it), else the user's preferred vault if
  editable, else the first personal vault, else the first editable shared vault, else none.
* Tests: `multi` unit tests and `core/tests/teams.rs` (`search_and_save_across_open_vaults_keep_the_vault`).

### 15.15 Bindings

Everything of §15 to §17 is exported through UniFFI (Android, iOS; PROTOCOL.md §1) and through the WebAssembly
module for the browser extension and the secure-send open page (EXTENSION_VAULT.md §16). The keyset is an object in
both (its private keys never cross into Kotlin, Swift or JavaScript); the trust record stays in the home vault
(`Vault::remember_trust_of` after each sync).

### 15.16 Pinned contact keys (`share/contacts.rs`, `vault/contacts.rs`)

The account service hands out everyone's public keys and says whose keys an admin confirmed. Its self-signature
proves only that whoever made a keyset holds it, so a breached service could hand out a keyset of its own under a
member's name, swap a member's keys, or mark an attacker "confirmed", and an app that wraps to what it is given hands
the service the vault. So the apps wrap a vault key, a recovery key or an account key only to keys the user
verified, and the record of what was verified lives where the service can't reach it: the user's home vault.

* **A pin** (`ContactPin`): account, scope, fingerprint, both public keys, when, how (`Compared`, later `KeyMove`)
  and the fingerprint it replaced. A sealed setting of the home vault, `contacts.pin.v1.` + the first 40 hex digits
  of SHA-256(account, 0, scope): sealed with the vault key, synced to the user's devices, last writer wins per
  pin, never seen by the service. Only a personal vault keeps pins.
* **Making one**: `pin_contact(keys, scope, compared)` after the user compared the fingerprint with the person (on
  a call, side by side). The typed text must be these keys' fingerprint (dashes, case and the Crockford look-alikes
  `O`, `I`, `L` don't matter), so a slip never pins the wrong keys. A pin of other keys is replaced only this way,
  and keeps the old fingerprint as `previous_fingerprint`. `unpin_contact` forgets one.
* **Checking**: `contact_pin_status(keys, scope)` is `Pinned` (the compared keys, or the user's own keyset),
  `NotPinned`, or `Changed { pinned_fingerprint }` (the service offers keys the user never compared: the apps warn
  loudly). `unpinned_changes(changes)` lists the `Add` and `ReplaceKeys` of a members change that aren't pinned,
  for the app to show with their fingerprints.
* **Enforced by the core**, not by each app: `change_members_pinned`, `add_member` and `sync_group` take the home
  vault and refuse (`Crypto`, `share.keys_not_verified` or `share.keys_changed`, naming the account) any key that
  isn't pinned, and change nothing; plain `change_members` refuses `Add` and `ReplaceKeys`
  (`share.needs_verified_keys`). The service's `keys.confirmed` flag counts for nothing here: an admin's app adds
  only people whose keys that admin compared, so with two admins each compares once (signed confirmations that a
  second admin could accept from a pinned first admin are a later step). Admin recovery is held to the same rule:
  `admin_recovery_enroll` (vault and account key) needs the recovery key's creator pinned, so a recovery key signed
  by a keyset the service made is never enrolled (the member pins an admin by comparing when joining), and
  `org_recovery_create` and `org_recovery_rewrap` wrap the recovery private key only to pinned admins.
* **First open of a shared vault**: `home.shared_signer_status(shared)` says whether the manager who signed the
  list is pinned; the apps show "Shared by Alice, 7K3QD-…" with "verified", "not verified yet, compare with Alice",
  or a warning when Alice's pinned keys are others (a fake vault in her name).
* **No adoption of existing members.** Keys already in a members list are not pinned automatically: an old app
  may have added them on the service's word alone, and pinning them would spread a planted key to every new vault.
  Roles, removals and rotations need no pin (they wrap nothing to new keys), so existing vaults keep working; adding
  an existing member to another vault asks the admin to compare once.
* **Scopes and key moves (personal plus Team design).** `scope` is `personal` today. A Team's work keyset publishes
  public keys v2 for scope `org:<group id>`, and the pins are per scope, so a work keyset never inherits trust from
  the personal keys by accident. When a member moves to a work keyset, their key move statement
  (`"pass/userkeys-move/v1:" + JSON[account, org, old_fingerprint, new_fingerprint, at]`) is signed by the personal
  keys: an app that has the personal keys pinned checks the statement against that pin and pins the new keys for
  `org:<group id>` with source `KeyMove` (a core function to add with the v2 keys). Without a personal pin it asks
  for a comparison as for anyone else. Team vault changes then check the `org:` scope.
* **Later**: a public key log the apps check (key transparency), so a key the service shows one person and not
  another is caught without a call.
* Tests: `vault/shared_tests.rs` (`a_server_that_swaps_a_members_keys_gets_no_wrap`,
  `a_server_that_adds_a_confirmed_member_gets_no_wrap`, `a_first_open_shows_whether_the_signer_is_verified`,
  `pins_follow_the_home_vault_and_refuse_a_wrong_comparison`), `share/org_recovery.rs`
  (`a_planted_recovery_key_is_never_enrolled`, `a_recovery_key_is_wrapped_only_to_verified_admins`).

## 16. Secure send (`Core/core/src/send.rs`)

A text or a small file (at most 10 MiB) shared through a one-time, expiring link, end-to-end encrypted.

* `send_seal(content, options)` makes a fresh 32-byte **link key** `K`; with a password, `P` = Argon2id(password,
  16-byte salt, the vault defaults). The content key is HKDF-SHA256(salt `"pass/send/v1"`, ikm `K || P`, info
  `"content"`); the ciphertext is `nonce (24) || XChaCha20-Poly1305(content key, nonce, AAD, plaintext)` with AAD
  `"pass/send/v1:" + JSON[v, expires_at, max_views, size, kdf]` and plaintext `u32 big-endian header length ||
  {"kind", "name", "mime"} || data`. The cleartext metadata for the service is `{"v":1, "expires_at", "max_views",
  "size", "kdf"?}` (the salt base64url in `kdf`); the AAD binds it, so the service can't change it unnoticed.
* The link is `<base>/<send id>#<K base64url>` (`send_link`, `send_parse_link`): the key only in the fragment,
  which browsers never send to a server. The service stores the ciphertext and the metadata, counts the views and
  deletes the send at expiry or after the last view.
* With a password, `password_auth` = HKDF-SHA256(salt `"pass/send-auth/v1"`, ikm `P`, info `"auth"`) lets the
  service refuse a download (and not count a view) without the password (`send_password_auth` on the open page);
  it keeps a hash of it. It doesn't help decrypt: `K` is missing.
* `send_open(ciphertext, meta, key, password)` decrypts; `send_info(meta)` tells the page what to ask for.
* Limits: expiry in the future and at most 30 days away, a file name without path separators or control characters,
  text in UTF-8. The service enforces expiry and views; the core doesn't refuse an expired send (clocks differ).
* **Test vectors** (`core/tests/send_vectors.json`): fixed link keys, nonces, salts and small Argon2id parameters,
  with the ciphertext, metadata and password proof they give. The core's test checks they still come out byte for
  byte (`PASS_WRITE_SEND_VECTORS=1` writes them again after a deliberate change); the WebAssembly test opens them
  (`wasm/tests/teams.rs`), so the open page and the apps agree.
* Trust: whoever gets the link (and the password, if any) can open it until the views run out; the service sees
  the sizes, times and the number of views, never the content or the file name.

## 17. Organisation policies (`Core/core/src/policy.rs`)

What a team or family requires of its members' apps, as JSON from the account service (`whoami`):

```jsonc
{ "master_password_min_strength": "good",   // or 0 to 4: very weak, weak, fair, good, strong
  "max_auto_lock_minutes": 15, "export_allowed": false, "sharing_outside_allowed": false,
  "require_two_step": true }
```

Every key is optional and a missing key requires nothing; unknown keys are ignored; an unknown strength label reads
as the strictest.

* `policy_parse`, `policy_strictest` (a member of several organisations: the strictest of each rule).
* `policy_violations(policy, local)` checks the device (`LocalSecurity`: the master password's strength measured
  when it was last typed, the auto-lock, whether the account signs in with a passkey or a second step) and returns
  each broken rule with a message; `policy_check_master_password` checks a new master password before it is set.
* `policy_auto_lock_secs` shortens the user's auto-lock to the maximum; `policy_allows_export` and
  `policy_allows_share(policy, recipient_in_org)` say whether Export and a share with someone outside are allowed
  (`policy_blocked_message` for the text).
* The core only evaluates: the apps enforce (ask for a new master password, cap the auto-lock, hide Export, refuse
  the share), and the account service enforces what it can on its side (2-step sign-in).
* **Password mode** (a Team only; not part of `OrgPolicy`, the apps read it from the organisation JSON):
  `policy.password_mode` is the caller's effective mode, the member's override else the team's default
  (`policy_settings.password_mode`), one of `choice` (default), `second_password`, `one_password`; a missing key
  reads as `choice`. Several organisations: `second_password` if any says so, else `one_password` if any.
  * `choice`: as before; the home vault keeps the Passyble password (§18.5).
  * `second_password`: the home vault, whose keyset opens the team's vaults, must open with its own password. Until
    it does, the team's vaults stay readable on that device but nothing in them changes (no new, edit, delete,
    move or copy in, no member or access change, no sharing), and the apps offer "Set a second password", the one
    case where the home vault may unlink (§18.5), with the team's minimum strength.
  * `one_password`: no vault offers "Use a separate password"; each vault that still has its own password gets a
    notice to link it to the account (`Vault::link_to_account`), never done silently.
  * Sharing in a team is offered only while the effective mode is not `second_password`, no vault on the device has
    its own password, and the organisation's `sharing_blocked` is false. Each app session reports its device's
    answer (`PUT /v1/me/second-password`), so the account service refuses new direct shares and new access too.
    Copying an item into an existing shared vault is a file upload the server can't read, so that check is the
    apps' only.

## 18. One Passyble password: the Secret Key, the account key and linked vaults (`Core/core/src/account_key.rs`, `Core/core/src/vault/account.rs`)

A paid user has one Passyble password. It signs in to the account and opens every vault linked to the account,
end to end encrypted. Beside it each device holds a random 128-bit **Secret Key** (two-secret key derivation, as
1Password). The account service never sees the password, the Secret Key, the keys they derive, the account key
or any vault key, receives no password-equivalent at sign-in, and holds nothing it could test a guess against.
This section is what Core implements. Free use without an account is unchanged (§1).

### 18.1 From the password and the Secret Key

```text
salt, kdf  = per account, from the account service's prelogin (16 random bytes; Argon2id m 64 MiB, t 3, p 1)
sk         = Secret Key, 16 random bytes made on the device at sign-up, never sent
pw_key     = Argon2id(NFC(password) as UTF-8, salt, m, t, p)                                  32 bytes
master     = HKDF-SHA256(ikm = pw_key, salt = sk, info = "passyble-account-master/v1")
auth_seed  = HKDF-SHA256(master, info = "passyble-account-auth/v1") -> Ed25519; the service keeps auth_pub
wrap_key   = HKDF-SHA256(master, info = "passyble-account-wrap/v1")                            never sent
sign-in    : Ed25519 signature over "pass/sign-in/v1:" + JSON[email, nonce, device_name, platform]
```

* `SecretKey` (`generate`, `parse`, `text`): written `P1-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX`, the recovery code's
  Crockford base32 and 22-bit checksum (§1) in a checksum domain of its own (`"pass/secret-key/v1:"`), so a Secret
  Key and a recovery code are never taken for each other (typing a recovery code where the Secret Key goes says
  so). Kept in the OS keychain without a gesture (useless without the password) and on the service only under AK
  (`sk_wrap`, 18.2).
* `AccountPassword::new(password, secret_key, salt, kdf)` derives both keys (one Argon2id run); `with_new_salt` for
  a new password. `auth_pub()` is what the service keeps, `sign_in(email, nonce, device_name, platform)` the
  sign-in proof over the service's single-use nonce (no SRP: with the Secret Key the service's value is
  unguessable either way, and a signature over a fresh nonce is never replayable). Passwords are normalized to
  NFC and hold 1 to 128 characters; the apps check the rules with `master_password_check` and the breach check
  through the service's prefix proxy (`hibp_prefix`, `hibp_match`).
* **Client bounds**: `AccountKdf` refuses m below 64 MiB or above 1 GiB, t below 3 or above 20, p above 16, and a
  salt outside 16 to 64 bytes.

### 18.2 The account key and its wraps

`AccountKey` (AK) is 32 random bytes made on the device at sign-up. `ak_id` = base64url of the first 16 bytes of
HMAC-SHA256(AK, `"pass/ak-id/v1:" + account`); Settings shows `fingerprint()`. AK is kept on the device under
Windows Hello, the Android Keystore or the iOS Keychain (`to_bytes`; `from_bytes` checks `ak_id`). The service
stores it only wrapped (XChaCha20-Poly1305 unless said otherwise, base64url):

| Wrap | Key | AAD or HPKE `info` |
|---|---|---|
| password (`password_wrap`, `AccountPassword::open_account_key`) | `wrap_key` | `"pass/ak-pw/v1:" + JSON[account, ak_id, salt, kdf]` |
| passkey (`prf_wrap`, `account_key_open_prf`) | HKDF(PRF output, `"pass/ak-prf/v1"`) | `"pass/ak-prf/v1:" + JSON[account, ak_id, credential_id]` |
| recovery (`new_recovery`, `account_key_open_recovery`) | HKDF(code secret, `"pass/ak-recovery/v1"`) | `"pass/ak-recovery/v1:" + JSON[account, ak_id, rec_id]` |
| admin (`admin_recovery_enroll`, `account_key_from_admin_recovery`) | HPKE to the org recovery key | `"pass/org-recovery-ak/v1:" + JSON[org, key_id, account, ak_id]` |
| device approval, code or new device's QR (`approve_device`, `DeviceApprovalKeys::open`) | HPKE to the new device's one-time key; AK and the Secret Key | `"pass/approve-ak/v1:" + JSON[request_id, account, enc_pub, r_n, r_a]` |
| device approval, invitation QR (`approve_invitation`, `open_invitation`) | the same | `"pass/add-ak/v1:" + JSON[invitation, account, enc_pub]` |

Two values derived from AK tie the rest together:

* `sk_wrap` (`secret_key_wrap`, `open_secret_key`): the Secret Key under HKDF(AK, `"pass/sk-wrap/v1"`), AAD
  `"pass/sk-wrap/v1:" + JSON[account, ak_id]`. Every path that yields AK (passkey, recovery code, admin) also
  yields the Secret Key, so the password works on that device later.
* `ak_sign` (`ak_sign_pub`, `sign_request`): an Ed25519 key from HKDF(AK, `"pass/ak-sign/v1"`). Every request that
  adds, replaces or deletes a key blob carries its signature over `"pass/ak-sign/v1:" + JSON[account, nonce,
  METHOD, path, base64url(SHA-256(body))]` with a fresh nonce from the service, so a session alone (a taken-over
  mailbox) can't swap in a wrap of a key it controls.

Symmetric wraps can't be forged by the service (a substituted blob fails to open); every opening also checks
`ak_id`. HPKE is base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305, as in §15.

### 18.3 Recovery code and Emergency Kit

The account recovery code has the format of vault recovery codes (§1). `AccountKey::new_recovery` returns the code
(shown once), a `rec_id`, the AK wrap and `verify_pub`, the public half of an Ed25519 key whose seed is
HKDF(secret, `"pass/recovery-sign/v1"`). To reset a forgotten password the app signs the service's challenge,
`"pass/recovery-challenge/v1:" + JSON[account, rec_id, challenge]` (`account_recovery_sign`); the service checks
it against `verify_pub` before it releases the recovery wrap. The code itself is never stored.

`emergency_kit(email, account, secret_key, recovery_code)` gives the content of the one-page Emergency Kit each app
prints to PDF on the device: e-mail, sign-in address, Secret Key, a setup QR (`passyble:kit/v1?e=<email>&a=<account>
&k=<Secret Key>`, never the password and never the recovery code) and the recovery code in its own box.
`parse_kit_qr` reads the QR ("Scan your Emergency Kit").

### 18.4 Linked vault file (version 3)

```jsonc
{ "format": "pass-vault", "version": 3, "vault_id": "uuid", "header_updated_at": 1730000000000,
  "access": "account",
  "kdf": { "alg": "none", "m_kib": 0, "t": 0, "p": 0, "salt": "" }, "wrapped_key": { "nonce": "", "ct": "" },
  "account": { "account": "acc_...", "ak_id": "...", "wrapped_key": { "nonce": "b64", "ct": "b64" } },
  "account_recovery": { "rec_id": "uuid", "wrapped_ak": { "nonce": "b64", "ct": "b64" } },     // optional
  "key_check": { ... }, "header_auth": { ... }, "previous_keys": [ ... ], "items": [ ... ], ... }
```

* VK under AK: AAD `"pass/account-vk/v1:" + JSON[vault_id, account, ak_id]`.
* `header_auth` v3: VK seals an empty message with AAD `"pass/header/v3:" + JSON[vault_id, header_updated_at,
  "account", account, account_recovery]`: the file's host can't swap or strip either slot.
* `account_recovery` is the same ciphertext as the service's recovery wrap: the recovery code and a copy of the file
  open the vault without Sensyble (`Vault::unlock_with_recovery_code` handles both versions;
  `account_key_from_vault_file` gives AK).
* No password slot and no vault recovery code: a stolen linked file holds nothing to guess. Items, `key_check`,
  `previous_keys`, settings and usage are exactly v1. Clients before version 3 refuse it with "made by a newer
  version of Passyble"; `vault_file_access` tells the apps which unlock screen a file needs.

### 18.5 Linking, unlinking, merges, emergency access

* `Vault::link_to_account(ak)` writes the v3 header, drops the password slot and the vault recovery code, keeps the
  VK (no item is re-encrypted; device-wrapped VKs and emergency grants keep working). Linking again with another AK
  (a replaced key, an unlocked vault from before an e-mail reset, a contact's full-access takeover) rewraps the slot
  and drops the old recovery copy. `Vault::create_for_account` makes a vault linked from the start;
  `Vault::unlock_with_account_key` opens one.
* `Vault::set_account_recovery(rec_id, wrap)` / `remove_account_recovery` keep the header copy current; compare
  `account_link().recovery_id` with the account's.
* `Vault::unlink_from_account(new_password)` ("Use a separate password"): back to a v1 header with the
  vault default Argon2id parameters and a new VK, so AK, an admin
  enrollment, an emergency grant or an old device copy can't read anything written later (grants then show stale
  through `emergency_grant_current` and are renewed). The vault holding the sharing keys (§15.2) keeps them and
  still opens the shared vaults with its new password. The apps offer this for the home vault only when the
  member's team requires a second password (§17, password mode); otherwise it keeps the Passyble password
  (`Vault::holds_sharing_keys` tells them which vault that is).
* Merges: the newer authenticated header wins, v1 or v3. A linked vault refuses master password operations.
* Emergency access (§15.12) works unchanged on linked vaults: the grant seals the VK, never AK. With full access
  the contact may link the vault to their own account.

### 18.6 Adding a device: QR or code

The new device N makes `DeviceApprovalKeys` (a one-time X25519 pair and a random `r_n`) and sends `enc_pub` and
`commitment = SHA-256("pass/approve-commit/v1:" + enc_pub + r_n)`. Then one of:

* **N shows a QR** (`approval_qr`: `passyble:approve/v1?id=<request>&k=<enc_pub>&r=<r_n>`), the approving device A
  scans it (`parse_approval_qr`), checks that the request on the service carries that `enc_pub`, and approves with
  `r_n` from the QR and its own `r_a` (`approve_device_qr`): the camera authenticated the key.
* **A shows a QR** (`DeviceInvitation`: a token `t` the service keeps hashed and a MAC key `s` that is only in the
  QR, `passyble:add/v1?inv=<id>&t=<t>&s=<s>`, 2 minutes, once). N scans it (`parse_invitation_qr`) and sends
  `enc_pub` with HMAC-SHA256(s, `"pass/add/v1:" + inv + enc_pub`) (`invitation_mac`); A checks it
  (`approve_invitation`).
* **No camera**: A sends `r_a` (`device_approval_nonce`), N reveals `r_n`, A checks the commitment, and both show
  the 6-digit code: the first 8 bytes of SHA-256(`"pass/approve-sas/v1:" + JSON[request_id, account, enc_pub,
  r_n, r_a]`) modulo one million (`device_approval_code`, `DeviceApprovalKeys::code`). The commitment stops a
  service from grinding a key that matches the code. **Number matching** (design D4 of the server breach audit): N
  shows the code and the user types it on A; `approve_device(…, typed_code)` refuses any other
  (`account_key.approval_code_mismatch`). A request can be started with an e-mail address alone and reaches every
  device, so a tap must never approve one: its code is on the screen of whoever started it.

A seals AK and the Secret Key to `enc_pub`; N opens them (`ApprovedKeys`) and checks `ak_id`. Before N keeps the
keys it shows `ApprovedKeys::fingerprint()` (the account key's fingerprint, as Settings shows it on A): a breached
service that played A and sealed an account key of its own to N would pass the `ak_id` check (it gave N that id
too) but not this one, and N drops the keys when the user says the fingerprints differ. N can keep its keys across a
restart (`secret`, `restore`).

### 18.7 Admin recovery of the account key

`AccountKey::admin_recovery_enroll(key, creator, kind)` makes a §15.13 enrollment whose `vault_id` is
`"ak:" + ak_id`. The request is `admin_recovery_request(org, account, "ak:" + ak_id)`; the admin approves it as any
other; `account_key_from_admin_recovery(approval, secret, approver)` checks the signature and opens AK. The member
then opens the Secret Key (`sk_wrap`), picks a new password and gets a new Secret Key and Emergency Kit. Every
admin of the organisation can open every linked vault of the member (vaults with a separate password stay out).

### 18.8 Vectors

`Core/core/tests/account_key_vectors.json` pins the Secret Key text, every derivation (with NFC cases), the sign-in
and request signatures, every wrap (with fixed nonces), the recovery code's key and signature, the vault slot, the
device approval code, the QR payloads and the invitation MAC; `account_key.rs`'s tests check them and the account
service follows them. `PASS_WRITE_VECTORS=1` rewrites the file, only when the construction changes on purpose.
