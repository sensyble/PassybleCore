# Passyble: interfaces

## 1. Core API (`pass-core`, exported to Kotlin through UniFFI)

Kotlin package: `uniffi.pass_core`. Bytes are `ByteArray`, `i64` timestamps are Unix **milliseconds**
unless the name says `_secs`.

Vault files seal each record under an AAD that binds vault id, item id, version (`updated_at`, `device_id`) and
the deleted flag (item AAD v2; a tombstone seals an empty message), and carry an optional `header_auth` over the
header and an optional `recovery` block (a recovery code, authenticated on its own). Files from older clients (v1
records, no `header_auth`) still open, and older clients open and merge files with a `recovery` block. `create`, `unlock`, `change_password`
and header merges reject a KDF outside the bounds (`argon2id`, `m_kib` ≤ 1 GiB, `t` 1..=20, `p` 1..=16) with
`PassError::Corrupt`. Format: ARCHITECTURE.md §1.

```rust
// Errors: PassError { InvalidPassword, Corrupt(msg), Crypto(msg), InvalidInput(msg), NotFound(msg), Network(msg), Conflict(msg),
//                    CertificateChanged(msg) /* pinned server presented another key: pair again (§3.2) */,
//                    AuthRequired(msg) /* Google Drive refused the access token: get a new one / sign in again */ }
// Language of the core's texts (Core/core/locales/<tag>.json, docs/TRANSLATING.md): error messages, import warnings, skip
// reasons and format names, merge descriptions. The `msg` kind prefixes ("invalid input: ", "network error: ", ...)
// stay English; apps strip them. Apps tell core messages apart with core_message_is, never by English words.
fn set_language(language: Option<String>)   // Kotlin setLanguage; "de", "zh-CN" ("zh-Hans", "in" work); None/unknown → English.
                                            // Process-wide, from then on; call at start-up and when the app's language changes.
fn core_message_is(message: String, key: String) -> bool   // message is the core's text `key` ("gdrive.*": a family), any language
fn core_message_arg(message: String, key: String, name: String) -> Option<String>   // its placeholder `name` (e.g. "count")

#[derive(uniffi::Record)] struct AndroidApp { package: String, cert_sha256: Option<String> }   // hex, upper or lower, ':' allowed
#[derive(uniffi::Enum)]   enum ItemKind { Login, Note, Card, Identity }
    // A Card or Identity is sealed in the vault file as "kind": "note" plus its `card` / `identity` object, so clients
    // from before these kinds still open the vault (they show it as a secure note, ARCHITECTURE.md §2). A kind a newer
    // client invents reads as Note instead of failing the vault.
#[derive(uniffi::Record)] struct Passkey {
    credential_id: Vec<u8>, rp_id: String, rp_name: Option<String>, user_handle: Vec<u8>,
    user_name: String, user_display_name: String, private_key_pkcs8: Vec<u8>,
    sign_count: u32, discoverable: bool, created_at: i64 }
#[derive(uniffi::Enum)]   enum FieldKind { Text, Hidden /* masked; never in summaries or search */, Url }   // unknown → Hidden
#[derive(uniffi::Record)] struct CustomField { name: String, value: String, kind: FieldKind /* no Kotlin default: FieldKind.TEXT */ }
#[derive(uniffi::Record)] struct CardData {                  // all Kotlin-default "" / 0; sealed with the item
    cardholder_name: String, number: String /* digits only once saved */, expiry_month: u32 /* 1..=12, 0 unknown */,
    expiry_year: u32 /* 4 digits (27 → 2027), 0 unknown */, security_code: String /* CVV / CVC */, pin: String,
    brand: String /* derived from the number on upsert (card_brand); "" unknown */ }
#[derive(uniffi::Record)] struct IdentityData {              // all Kotlin-default ""
    honorific: String, first_name: String, middle_name: String, last_name: String, email: String, phone: String,
    address1: String, address2: String, address3: String, city: String, region: String, postal_code: String,
    country: String, company: String, birth_date: String /* YYYY-MM-DD when known */ }
#[derive(uniffi::Record)] struct PasswordHistoryEntry { password: String, replaced_at: i64 }
#[derive(uniffi::Record)] struct Item {
    id: String,                 // empty string → new item, id assigned on upsert
    kind: ItemKind, title: String, username: String, password: String,
    urls: Vec<String>, android_apps: Vec<AndroidApp>,
    totp: Option<String>,       // otpauth:// URI or base32 secret
    passkeys: Vec<Passkey>, notes: String, favorite: bool,
    created_at: i64, updated_at: i64,
    password_history: Vec<PasswordHistoryEntry>,   // earlier passwords, newest first, at most MAX_PASSWORD_HISTORY (20); upsert adds the one an edit replaces
    // Newer than the first format: Kotlin defaults (None / [] / 0), left out of the sealed JSON when empty.
    card: Option<CardData>,         // Some on a Card item (upsert creates an empty one), None on every other kind
    identity: Option<IdentityData>, // likewise for Identity
    fields: Vec<CustomField>,       // custom fields in display order; upsert drops those with no name and no value
    tags: Vec<String>,              // folders; "/" nests ("Work/Clients"); upsert trims, drops empty and case-insensitive duplicates
    trashed_at: Option<i64>,        // Some: in the trash since then (below); None: live
    password_changed_at: i64,       // maintained by upsert; 0 unknown (items from older clients: updated_at stands in)
    url_rules: Vec<UrlRule> }       // how websites match pages, only those not Subdomains (below); upsert drops the rest
#[derive(uniffi::Enum)] enum UrlMatch { Subdomains /* default: the site and its subdomains, as before */,
    Host /* that host only, and its port when the entry names one */, Never /* never suggested or filled on its own */ }
#[derive(uniffi::Record)] struct UrlRule { url: String /* an entry of urls, exactly */, rule: UrlMatch }
// AndroidApp has `never_show: bool` (Kotlin default false): the app's Never. In JSON a rule is "subdomains", "host" or
// "never"; an unknown one (a newer client's) reads as "subdomains". Old items have no url_rules: every website matches as
// before. A client from before rules ignores the keys (and drops them only if it edits and saves that item).

#[derive(uniffi::Object)] struct Vault;    // thread-safe; methods take &self
impl Vault {
    #[constructor] fn create(master_password: String, device_id: String) -> Result<Arc<Vault>>;
    #[constructor] fn unlock(file: Vec<u8>, master_password: String, device_id: String) -> Result<Arc<Vault>>;
    #[constructor] fn unlock_with_key(file: Vec<u8>, vault_key: Vec<u8>, device_id: String) -> Result<Arc<Vault>>;
    #[constructor] fn unlock_with_recovery_code(file: Vec<u8>, recovery_code: String, device_id: String) -> Result<Arc<Vault>>;
        // A forgotten master password (ARCHITECTURE.md §1, "Recovery code"). Err(InvalidInput) for a code that isn't
        // well-formed (typo), Err(NotFound) if the file has no recovery code, Err(InvalidPassword) for a well-formed code
        // that doesn't open it (another vault's, or replaced). Same vault key: a biometric / Hello copy keeps working.
        // Then: change_master_password(new) (no old password needed), serialize, sync; offer create_recovery_code().
    fn vault_id(&self) -> String;
    fn export_vault_key(&self) -> Vec<u8>;                // 32 bytes; wrap it with a hardware key
    fn serialize(&self) -> Result<Vec<u8>>;               // encrypted vault file (this device's copy: includes the local sync state)
    fn is_dirty(&self) -> bool;                           // changed since last serialize()
    fn sync_pending(&self) -> bool;                       // has changes the sync server hasn't seen (or never synced); cheap.
                                                          // Items and header only: usage counts never make it true
    fn usage_sync_pending(&self) -> bool;                 // usage counts the server hasn't seen (any sync uploads them along)
    fn usage_sync_due(&self, now_ms: i64) -> bool;        // ...and they have waited 6 h: time to sync for them alone
    fn record_use(&self, item_id: String, now_ms: i64) -> Result<()>;
        // One use of a login on this device (fill, auto-type, copied password / 2FA code, passkey sign-in); uses of
        // one item within 60 s count once. Never an edit: the item, its version, updated_at, revision() and
        // sync_pending() stay as they are; only is_dirty() (save it, don't sync for it). Err(NotFound) if not live.
        // ARCHITECTURE.md §13.
    fn usage(&self, id: String) -> ItemUsage;             // over every device; zeros if never used
    fn revision(&self) -> u64;                            // changes with every edit / merge (debouncing); not persisted
    fn change_master_password(&self, new_password: String) -> Result<()>;   // a new vault key too; no old password needed (unlocked)
    fn check_password(&self, password: String) -> Result<bool>;             // one Argon2id run, changes nothing
    fn change_password(&self, old_password: String, new_password: String) -> Result<()>;
        // Err(InvalidPassword) if old_password is wrong. Always a new vault key (ARCHITECTURE.md §1, design D5),
        // every item re-encrypted on save; the old key is kept in the file sealed with the new one (`previous_keys`)
        // so older copies still merge. Other devices get Crypto on their next merge and unlock with the new
        // password. The recovery code goes (it wraps the old key): offer a new one. On a Passyble Server, after
        // uploading, drop the old versions (server_purge_versions).
    // Recovery code (ARCHITECTURE.md §1): one per vault, in the header (synced and merged with it). The apps ask for
    // the master password before making or removing one; save and sync afterwards.
    fn create_recovery_code(&self) -> Result<String>;     // a new code, returned only now ("XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX",
                                                          // 30 base32 chars: 128 random bits + checksum); replaces any earlier one.
                                                          // One Argon2id run (the vault's parameters)
    fn remove_recovery_code(&self) -> Result<()>;         // no change without one
    fn has_recovery_code(&self) -> bool;
    fn recovery_code_created_at(&self) -> Option<i64>;   // None without one
    fn items(&self) -> Vec<Item>;                         // live items (not deleted, not in the trash), sorted by title
    fn summaries(&self) -> Vec<ItemSummary>;              // the same items without secrets (the soft-lock list, below)
    fn get(&self, id: String) -> Option<Item>;            // live only: None for a deleted or trashed item
    fn upsert(&self, item: Item) -> Result<Item>;         // assigns id/created_at, bumps updated_at
        // Normalizes: card number digits only (spaces, dashes, dots dropped), brand derived from it, two-digit expiry year
        // → 20xx, a blank card title → "Visa •••• 1111", card / identity kept only on their own kind, tags cleaned,
        // empty custom fields dropped. Err(InvalidInput) for an expiry month over 12 or a year over 9999, or a bad totp.
        // password_changed_at: now when the password differs from the stored one (unless the caller set another time),
        // 0 when the password is cleared, else kept. An item with trashed_at set goes to / stays in the trash; upserting
        // a trashed item's copy without trashed_at restores it (the apps' Undo).
    // Trash (ARCHITECTURE.md §2). A trashed item is an ordinary edit (`trashed_at`), so it syncs and merges like one.
    // It is left out of items(), get(), summaries(), search, the finders, export and password health.
    fn delete(&self, id: String) -> Result<()>;           // moves a live item to the trash; Err(NotFound) if unknown, deleted or already trashed
    fn restore(&self, id: String) -> Result<Item>;        // out of the trash; Err(NotFound) unless trashed
    fn purge(&self, id: String) -> Result<()>;            // a trashed item for good (tombstone); Err(NotFound) unless trashed
    fn delete_permanently(&self, id: String) -> Result<()>; // live or trashed, for good (tombstone, syncs as a deletion)
    fn empty_trash(&self) -> u32;                         // purges every trashed item; how many
    fn purge_expired_trash(&self, now_ms: i64) -> u32;    // purges items trashed ≥ TRASH_RETENTION_MS (30 d) before now_ms; unlock()
                                                          // and serialize() do this themselves
    fn trashed_items(&self) -> Vec<Item>;                 // most recently trashed first
    fn trash_summaries(&self) -> Vec<ItemSummary>;        // the same without secrets; trashed_at set (purged at trashed_at + 30 d)
    fn tags(&self) -> Vec<TagCount>;                      // every tag of the live items with its count, by name; exact tags only
    fn items_with_tag(&self, tag: String) -> Vec<Item>;   // the tag or any tag nested under it ("Work" finds "Work/Clients"), by title
    fn search(&self, query: String) -> Vec<Item>;         // fuzzy search (below), notes too; "" = items()
    fn find_for_url(&self, url: String) -> Vec<Item>;     // live logins only; same host first (a matching stored path doesn't rank higher), then other subdomains; within each favorites, most used (rank), title
    fn find_for_save(&self, url: String) -> Vec<Item>;    // the logins a submit on the page may update: find_for_url's saved for the page's own host (`www.` = bare domain; ports and paths ignored), same order; never another subdomain's
    fn logins_of_page(&self, url: String) -> Vec<Item>;   // find_for_url without the website rules: what a pick by hand may fill there, and what "saved as is" compares
    fn logins_of_android_app(&self, package: String, cert_sha256: Option<String>) -> Vec<Item>; // likewise for find_for_android_app (hidden apps too)
    fn find_for_android_app(&self, package: String, cert_sha256: Option<String>) -> Vec<Item>;
    fn find_passkeys(&self, rp_id: String, allow_credential_ids: Vec<Vec<u8>>) -> Vec<PasskeyMatch>; // most used, then user_name
    fn add_passkey(&self, item_id: Option<String>, passkey: Passkey, url: Option<String>) -> Result<Item>; // None → new Login item
    fn merge_remote(&self, remote_file: Vec<u8>) -> Result<MergeStats>;
        // Per item, two live versions with merge metadata (sealed in the item, key "merge") merge field by field:
        // different fields both kept; the same field changed on both, the newer value kept and the other in the
        // password history, a joined list, or a new "<title> (conflict)" item (counted in `added`); otherwise
        // the greater (updated_at, device_id) wins with the loser's passwords kept in the history
        // (ARCHITECTURE.md §1, "Concurrent edits of one item"). A record whose version isn't authenticated (written
        // by a client before item AAD v2) only adds unseen items, never replaces or deletes one; a newer header is
        // adopted only if its `header_auth` verifies and its KDF is within bounds (ARCHITECTURE.md §1), with its
        // recovery block if that verifies (else none); at the same header version a valid recovery block is taken over.
}
fn recovery_code_valid_format(code: String) -> bool;   // length, characters and checksum (case, spaces, dashes ignored;
                                                        // O/I/L read as 0/1/1), for checking as the user types; no vault needed
#[derive(uniffi::Record)] struct PasskeyMatch { item_id: String, item_title: String, passkey: Passkey }
#[derive(uniffi::Record)] struct ItemUsage { count: u64 /* every device */, last_used: i64 /* 0: never */,
    rank: i64 /* frecency as a time, higher first, 0: never used; the order is stable over time */ }
fn usage_frecency(rank: i64, now_ms: i64) -> f64;       // the weighted, decayed count behind a rank
// consts: USAGE_HALF_LIFE_MS (30 d), USAGE_SYNC_INTERVAL_MS (6 h), USE_DEDUPE_MS (60 s), MAX_USAGE_DEVICES (16)

// Soft lock (ARCHITECTURE.md, "Soft lock"): what a locked app keeps on screen. No password, 2FA secret, notes,
// password history, custom field values, full card number, security code, PIN or passkey key/user handle. Kept between
// runs only device-bound and encrypted (Windows: DPAPI, pass-agent kept_list.rs; Android: a Keystore key); never synced
// or logged.
#[derive(uniffi::Record)] struct ItemSummary {
    id: String, kind: ItemKind, title: String, username: String,
    urls: Vec<String>, url_rules: Vec<UrlRule>, android_apps: Vec<AndroidApp>, // matching a page / an app, site icons
    domain: String,                                        // registrable domain (or host) of the first website, "" if none
    has_password: bool, has_totp: bool, has_notes: bool,
    passkeys: Vec<PasskeySummary>, favorite: bool, created_at: i64, updated_at: i64,
    use_count: u64, last_used: i64, rank: i64,              // ItemUsage (Kotlin defaults 0)
    tags: Vec<String>,                                     // Kotlin default []; the rest below too
    card: Option<CardSummary>, identity: Option<IdentitySummary>,
    has_fields: bool,                                      // custom fields exist (their names and values are not here)
    trashed_at: Option<i64> }                              // only in trash_summaries()
#[derive(uniffi::Record)] struct CardSummary { cardholder_name: String, brand: String, last4: String /* "" without a number */,
    expiry_month: u32, expiry_year: u32 }
#[derive(uniffi::Record)] struct IdentitySummary { full_name: String, email: String, company: String }
#[derive(uniffi::Record)] struct TagCount { tag: String, count: u32 }
#[derive(uniffi::Record)] struct PasskeySummary { rp_id: String, user_name: String, user_display_name: String,
    credential_id: Vec<u8> /* public */ }
fn summaries_tags(index: Vec<ItemSummary>) -> Vec<TagCount>;                             // = Vault::tags
fn summaries_with_tag(index: Vec<ItemSummary>, tag: String) -> Vec<ItemSummary>;         // = Vault::items_with_tag
fn summaries_for_url(index: Vec<ItemSummary>, url: String) -> Vec<ItemSummary>;          // = Vault::find_for_url
fn url_suggests_host_only(url: String) -> bool;  // a site on a shared hosting platform: the editor suggests UrlMatch::Host
fn summaries_for_android_app(index: Vec<ItemSummary>, package: String, cert_sha256: Option<String>) -> Vec<ItemSummary>;
                                                                                        // = Vault::find_for_android_app
fn summaries_search(index: Vec<ItemSummary>, query: String) -> Vec<ItemSummary>;         // = Vault::search, no notes
fn summaries_search_with_notes(index: Vec<ItemSummary>, notes: HashMap<String, String>, query: String)
    -> Vec<ItemSummary>;                                  // notes too (item id -> notes, only while unlocked)
fn items_search(items: Vec<Item>, query: String) -> Vec<Item>;  // the same over full items (pickers); "" = unchanged
// Fuzzy search (Core/core/src/search.rs): every whitespace-separated word of the query must match (AND) the title,
// username (an email's local part and domain too), a website (registrable domain, host, its labels, path), another
// entry, a linked app, a passkey name, a tag, a card's cardholder / brand / last four digits (never more of the number),
// an identity's name / email / company or (unlocked) the notes and custom fields (names, and values unless Hidden);
// case- and diacritic-insensitive. A word `tag:<name>` or `#<name>` is a filter instead: only items with that tag or one
// nested under it ("tag:work" finds "Work/Clients"); filters alone list the matches by title. Per word: whole
// field > word > start of a word > substring > a typo (distance 1 for 4+ letters, 2 for 8+) > letters in order.
// Titles and domains weigh most, notes least. Best total first, then favorites, rank, title; "" = by title.
fn summaries_with_passkeys(index: Vec<ItemSummary>, rp_id: String) -> Vec<ItemSummary>;  // items with a passkey for rp_id,
                                                                                        // most used first
fn summaries_suggested(index: Vec<ItemSummary>) -> Vec<ItemSummary>;   // favorites, then rank, then title
fn summaries_most_used(index: Vec<ItemSummary>) -> Vec<ItemSummary>;   // a "Most used" sort: rank, then title
#[derive(uniffi::Record)] struct MergeStats { added: u32, updated: u32, deleted: u32, unchanged: u32 }

// TOTP
#[derive(uniffi::Enum)]   enum TotpAlgorithm { Sha1, Sha256, Sha512 }
#[derive(uniffi::Record)] struct TotpConfig { secret: Vec<u8>, algorithm: TotpAlgorithm, digits: u32, period: u32, issuer: Option<String>, account: Option<String> }
#[derive(uniffi::Record)] struct TotpCode { code: String, period: u32, remaining_secs: u32 }
fn totp_parse(input: String) -> Result<TotpConfig>;
fn totp_generate(input: String, unix_secs: i64) -> Result<TotpCode>;

// Passkeys (software authenticator)
#[derive(uniffi::Record)] struct PasskeyCreation {
    passkey: Passkey, credential_id: Vec<u8>, attestation_object: Vec<u8>,
    authenticator_data: Vec<u8>, public_key_spki: Vec<u8>, public_key_algorithm: i64 /* -7 */ }
#[derive(uniffi::Record)] struct PasskeyAssertion {
    credential_id: Vec<u8>, authenticator_data: Vec<u8>, signature: Vec<u8> /* DER */, user_handle: Vec<u8> }
fn passkey_create(rp_id: String, rp_name: Option<String>, user_handle: Vec<u8>, user_name: String,
                  user_display_name: String, client_data_hash: Vec<u8>, algorithms: Vec<i64>) -> Result<PasskeyCreation>;
                  // Err(InvalidInput) if -7 is not among algorithms (empty list = default [-7, -257])
fn passkey_assert(passkey: Passkey, client_data_hash: Vec<u8>, user_verified: bool) -> Result<PasskeyAssertion>;
// WebAuthn PRF extension (core/src/prf.rs). Every passkey made by passkey_create has a PRF: a random 32-byte secret
// (credRandom) kept as a PKCS#8 attribute inside private_key_pkcs8, so it syncs and survives exactly like the key.
// Passkeys made before have none (no results; never one added later). Output = HMAC-SHA-256(secret,
// SHA-256("WebAuthn PRF" || 0x00 || input)), the same with or without user verification.
#[derive(uniffi::Record)] struct PrfValues { first: Vec<u8>, second: Option<Vec<u8>> }
fn passkey_prf_available(passkey: Passkey) -> bool;
fn passkey_prf_eval(passkey: Passkey, first: Vec<u8>, second: Option<Vec<u8>>) -> Option<PrfValues>; // raw inputs
// WebAuthn JSON for apps: prf_json = the request's extensions.prf (AuthenticationExtensionsPRFInputsJSON).
fn webauthn_prf_create_error(prf_json: String) -> Option<String>;   // "NotSupportedError" (evalByCredential) | "SyntaxError"
fn webauthn_prf_create_output(prf_json: String, passkey: Passkey) -> Result<String>; // {"enabled":bool,"results"?:{first,second?}}
fn webauthn_prf_get_error(prf_json: String, allow_credentials: Vec<Vec<u8>>) -> Option<String>; // spec §10.1.4 steps 1-2
fn webauthn_prf_get_output(prf_json: String, allow_credentials: Vec<Vec<u8>>, passkey: Passkey) -> Result<String>; // {} | {"results":…}
fn client_data_json(kind: String /* "webauthn.create" | "webauthn.get" */, challenge: Vec<u8>,
                    origin: String, cross_origin: bool, android_package: Option<String>) -> String;
fn sha256(data: Vec<u8>) -> Vec<u8>;
fn android_origin(cert_sha256: Vec<u8>) -> String;        // "android:apk-key-hash:<b64url>"
fn rp_id_valid_for_origin(rp_id: String, origin: String) -> bool;   // web origins only; false for android: origins
fn assetlinks_allows(json: String, package_name: String, cert_sha256: Vec<u8>) -> bool;
    // Digital Asset Links check for native Android callers: json = https://<rp_id>/.well-known/assetlinks.json

// Matching / misc
fn registrable_domain(host_or_url: String) -> Option<String>;
#[derive(uniffi::Record)] struct PasswordOptions { length: u32, lowercase: bool, uppercase: bool, digits: bool, symbols: bool, avoid_ambiguous: bool }
fn generate_password(options: PasswordOptions) -> Result<String>;
fn generate_passphrase(words: u32, separator: String) -> String;
fn b64url_encode(data: Vec<u8>) -> String;  fn b64url_decode(s: String) -> Result<Vec<u8>>;

// Username and e-mail generator (ARCHITECTURE.md §14). Local, OS CSPRNG, no network.
#[derive(uniffi::Enum)]   enum UsernameKind { Words /* "Swift-Otter" */, WordNumber /* "Otter4821" */, Characters /* "k3vq9tmz2c" */ }
#[derive(uniffi::Record)] struct UsernameOptions { kind: UsernameKind, capitalize: bool, include_number: bool /* Words: + 4 digits */,
    separator: String /* Words: "", "-", "_" or "." (USERNAME_SEPARATORS) */, length: u32 /* Characters: 4..=64 */ }
fn generate_username(options: UsernameOptions) -> Result<String>;   // InvalidInput: separator or length
#[derive(uniffi::Enum)]   enum EmailKind { PlusAddress /* alex+tag@example.com */, CatchAll /* tag@mydomain.com */ }
#[derive(uniffi::Record)] struct EmailOptions { kind: EmailKind, address: String /* PlusAddress; an existing +tag is replaced */,
    domain: String /* CatchAll; a leading "@" is fine */, website: Option<String> /* tag = the site's name ("github"); None: 8 random [a-z0-9] */ }
fn generate_email(options: EmailOptions) -> Result<String>;         // InvalidInput (alias.*/generator.* texts) for a bad address or domain

// E-mail alias services: the user's own account, over the service's HTTPS API (ARCHITECTURE.md §14 lists every request).
#[derive(uniffi::Enum)]   enum AliasService { SimpleLogin, AddyIo, FirefoxRelay, DuckDuckGo, Fastmail, ForwardEmail }
    // ids (settings, JSON, the extension): simplelogin, addy_io, firefox_relay, duckduckgo, fastmail, forwardemail
#[derive(uniffi::Record)] struct AliasConfig { service: AliasService, token: String /* a secret: show masked, never log */,
    base_url: String /* "" or https:// self-hosted server: SimpleLogin, addy.io only */,
    domain: String /* addy.io: alias domain ("" = anonaddy.me); Forward Email: the user's domain (required) */ }   // Debug hides the token
#[derive(uniffi::Record)] struct EmailGeneratorSettings { address: String, domain: String }   // "" = not set
fn alias_service_name(service: AliasService) -> String;               // "SimpleLogin", "addy.io", … (brands, not translated)
fn alias_generate(config: AliasConfig, website: Option<String>) -> Result<String>;  // a new alias with an unsaved config (blocking)
fn alias_check(config: AliasConfig) -> Result<Option<String>>;
    // Settings' "Test": checks the token (and Forward Email's domain) without making an alias. DuckDuckGo has no such check:
    // it makes one and returns it (Some), so the app can say so. Errors (all with the service's name): InvalidInput
    // alias.bad_token (401/403), alias.refused (4xx with the service's message), alias.not_found, alias.fastmail_no_masked_email;
    // Network alias.rate_limited (429), alias.server_error (5xx), alias.cant_reach, alias.unexpected_answer.
impl Vault {
    // Kept in the vault's sealed settings blob (ARCHITECTURE.md §1, "Vault settings"), synced and merged per key.
    // Each change marks the vault dirty: save (and sync) as after an edit.
    fn email_generator_settings(&self) -> EmailGeneratorSettings;
    fn set_email_generator_settings(&self, settings: EmailGeneratorSettings) -> Result<()>;   // trimmed; InvalidInput if not "" or valid
    fn alias_configs(&self) -> Vec<AliasConfig>;                       // every set-up service, in enum order
    fn alias_config(&self, service: AliasService) -> Option<AliasConfig>;
    fn set_alias_config(&self, config: AliasConfig) -> Result<()>;     // validated and normalized; the first one becomes the default
    fn remove_alias_config(&self, service: AliasService) -> Result<()>;  // with its token; the default moves to another set-up one
    fn alias_default_service(&self) -> Option<AliasService>;           // the chosen default if set up, else the first set-up one
    fn set_alias_default_service(&self, service: Option<AliasService>) -> Result<()>;  // NotFound if not set up
    fn generate_alias(&self, service: Option<AliasService>, website: Option<String>) -> Result<String>;
        // feature webdav, blocking. None: the default service. `website` (URL or host) goes to the service as the alias's
        // note/label: pass it only when the user asked ("Mention the website", off by default). NotFound if nothing is set up.
    fn check_alias_service(&self, service: AliasService) -> Result<Option<String>>;   // alias_check with the saved config
}

// Pinned vaults (the home vault's settings, key "ui.pinned_vaults": a JSON array of vault ids in pin order; synced and
// merged like the other settings, so the pins follow the user to every device). The ids are vault_id()s: the home
// vault's, shared vaults' and, on the desktop, the other vault files' on that PC. Readers skip ids they don't list;
// writers drop ids of vaults the user can no longer see before they save (the agent's `vaults.set_pins` does).
const MAX_PINNED_VAULTS: usize = 5;
impl Vault {
    fn pinned_vaults(&self) -> Vec<String>;                            // in pin order; duplicates and malformed ids skipped
    fn set_pinned_vaults(&self, ids: Vec<String>) -> Result<Vec<String>>;
        // Saves them in this order (trimmed, duplicates dropped; empty removes the setting) and returns what was saved.
        // InvalidInput for an id with spaces or control characters, empty or over 128 bytes ("settings.bad_vault_id"),
        // or more than MAX_PINNED_VAULTS ("settings.too_many_pins"). Marks the vault dirty: save (and sync) as after an edit.
}

// Sync (WebDAV / Passyble Server; blocking; call from a background thread)
#[derive(uniffi::Record)] struct WebDavConfig {
    url: String /* full file URL, e.g. https://cloud/remote.php/dav/files/me/pass.vault */, username: String, password: String,
    pins: Vec<String> /* §3.2 certificate pins "sha256:<b64url>"; Kotlin default listOf() = normal CA validation */ }
#[derive(uniffi::Record)] struct SyncResult { stats: MergeStats, uploaded: bool, created_remote: bool, remote_bytes: Option<u64> }
fn webdav_sync(vault: Arc<Vault>, config: WebDavConfig) -> Result<SyncResult>;
    // Conditional (ARCHITECTURE.md §10): GET with If-None-Match: <ETag of the last sync>. 304 and nothing
    // pending → done (1 request, no body). 304 + pending → PUT If-Match. 200 → merge, PUT only if the remote
    // lacks something. The ETag and a fingerprint of the remote's item versions live in the local vault file
    // (persist it when is_dirty() after a sync).
fn webdav_download(config: WebDavConfig) -> Result<Vec<u8>>;  // first-time setup on a new device
fn webdav_exists(config: WebDavConfig) -> Result<bool>;       // connection test (HEAD): false = 404, no vault yet
fn webdav_replace(config: WebDavConfig, vault: Arc<Vault>) -> Result<()>;
    // Intentional overwrite of the remote vault with this (different) vault, no merge: "Start a new empty vault"
    // after a password reset (§3.5). HEAD for the current ETag, then PUT If-Match (If-None-Match: * without a
    // file); 412 → again (4 attempts, then Conflict). Never blind. Pins as above. Passyble Server keeps the replaced
    // file as a version. Records the sync state like webdav_sync (persist the vault afterwards).
    // With pins, a server key matching none of them fails with CertificateChanged (not Network).
    // Malformed pins (not "sha256:" + 43 base64url chars) are InvalidInput.

// Google Drive (feature "gdrive", on by default; docs/GOOGLE_DRIVE.md). Blocking. The platform passes a fresh OAuth
// access token (scope https://www.googleapis.com/auth/drive.appdata) on every call; the core stores none.
#[derive(uniffi::Record)] struct GDriveConfig {
    access_token: String,
    vault_name: String /* Kotlin default ""; kept in the file's appProperties for the restore list; "" = leave as is */ }
#[derive(uniffi::Record)] struct GDriveVault { file_id: String, vault_id: String, name: String /* "" if never named */,
    modified: i64 /* Unix ms, 0 = unknown */, size: u64 }
#[derive(uniffi::Record)] struct GDriveAccount { email: String, display_name: String }
fn gdrive_sync(vault: Arc<Vault>, config: GDriveConfig) -> Result<SyncResult>;
    // File "pass-<vault.vault_id()>.vault" in appDataFolder. Unchanged + clean: 1 metadata request (files.get
    // fields=id,version,md5Checksum,…). Local edit: + PATCH uploadType=media (resumable above 5 MB). Remote changed:
    // download (alt=media), merge; if this device has more: re-check the version, upload. Missing: files.list by
    // name, then create (multipart). Twins from simultaneous creation are merged into the oldest and deleted.
    // File id / version / MD5 + fingerprint live in the local sync state (persist when is_dirty()). No If-Match in
    // Drive v3: a write in the last moment before ours is overwritten and re-uploaded by its device on its next sync
    // (merge by item; ARCHITECTURE.md §10). A refused token (401, 403 scope) is AuthRequired.
fn gdrive_list_vaults(access_token: String) -> Result<Vec<GDriveVault>>;   // restore list, newest first, one per vault id
fn gdrive_download(access_token: String, file_id: String) -> Result<Vec<u8>>; // then Vault::unlock; NotFound if gone
fn gdrive_delete(access_token: String, file_id: String) -> Result<()>;        // permanent (app-folder files have no trash)
fn gdrive_account(access_token: String) -> Result<GDriveAccount>;             // Drive about.get: the account to display

// Passyble Server links (§3.1)
#[derive(uniffi::Record)] struct PairingLink {
    url: String /* https://host:port/path, the WebDavConfig url */, host: String /* "host[:port]" for display */,
    username: String, token: String /* secret: the WebDavConfig password */, device_name: Option<String>,
    pins: Vec<String>, https: bool /* false = scheme=http: warn */ }
fn parse_pairing_link(link: String) -> Result<PairingLink>;    // Err(InvalidInput(msg)), msg user-facing; a sign-in
                                                               // link (no token) is InvalidInput("…sign in with your … password")
fn pairing_webdav_config(link: PairingLink) -> WebDavConfig;  // { url, username, password: token, pins }
#[derive(uniffi::Record)] struct ServerLink {                  // either kind of pass+server:// link
    server_url: String /* base URL for the account API, e.g. https://host:8443 (+ proxy prefix) */,
    host: String, username: String, pins: Vec<String>, https: bool,
    pairing: Option<PairingLink> /* Some = pairing link with a token */,
    code: Option<String>, code_kind: Option<String> /* "invite" | "reset": one-time code from an e-mailed link (§3.5) */ }
fn parse_server_link(link: String) -> Result<ServerLink>;     // accepts pairing and sign-in links

// Passyble Server accounts (§3.4; blocking, pins as in WebDavConfig). One password = server sign-in + vault password.
#[derive(uniffi::Record)] struct ServerKdf { alg: String /* "argon2id" */, m_kib: u32, t: u32, p: u32 }
#[derive(uniffi::Record)] struct ServerPrelogin { kdf: ServerKdf, salt: String /* b64url */ }
#[derive(uniffi::Record)] struct ServerSession {
    server_url: String, username: String, token: String /* secret: device token */, device_id: String, device_name: String,
    vault_url: Option<String> /* None: account has no vault */, vault_exists: bool,
    must_change_password: bool /* admin-set: server_change_password first; the token can't touch the vault until then */,
    password_admin_known: bool, pins: Vec<String> }
#[derive(uniffi::Record)] struct ServerAccount {
    username: String, device_id: String, device_name: String, vault_url: Option<String>, vault_exists: bool,
    has_password: bool, must_change_password: bool, password_admin_known: bool, limited: bool }
fn normalize_server_url(input: String) -> Result<String>;    // "host:8443" → "https://host:8443"; Err(InvalidInput)
    // Err(InvalidInput) for http:// unless the host is loopback/private (§3.1)
fn server_prelogin(server_url: String, username: String, pins: Vec<String>) -> Result<ServerPrelogin>;
    // Err(Crypto) if the server asks for parameters below Argon2id m=64 MiB, t=3 (or absurdly high ones)
fn server_auth_key(password: String, salt: String, kdf: ServerKdf) -> Result<String>;   // b64url auth_key (vectors)
fn server_login(server_url: String, username: String, password: String, device_name: String, pins: Vec<String>)
    -> Result<ServerSession>;   // Err(InvalidPassword) wrong user/password; Err(Network("…too many…")) rate-limited
fn server_session_webdav_config(session: ServerSession) -> Result<WebDavConfig>;  // Err(NotFound) without a vault
fn server_purge_versions(server_url: String, username: String, token: String, vault_url: String,
    pins: Vec<String>) -> Result<Option<u64>>
    // DELETE …/versions for the vault at vault_url (…/dav/<owner>/<name>.vault): Some(n) dropped, None: an older
    // server without the call; InvalidInput server.not_vault_owner for a vault this account doesn't own.
fn server_change_password(server_url: String, username: String, token: String, old_password: String,
    new_password: String, pins: Vec<String>) -> Result<()>;
    // old_password "" = set the first password of a token-only account. Err(InvalidPassword) wrong old password.
    // Server only: re-wrap the vault yourself (Vault::change_password), save, webdav_sync. Server FIRST (§3.4).
fn server_set_password_with_code(server_url: String, username: String, code: String, new_password: String,
    pins: Vec<String>) -> Result<()>;   // invite/reset link (ServerLink.code); Err(InvalidPassword) = link expired or
    // used. A reset code signs out every device of the account: then server_login and fix the vault (§3.5)
fn server_request_reset(server_url: String, user_or_email: String, pins: Vec<String>) -> Result<()>;
    // "Forgot password?": POST /api/v1/reset/request. Ok = "if such an account has an e-mail address, a link is on
    // its way" (the server answers the same for every account). Err(Network(msg)): the server can't send e-mail
    // (ask the admin), too many requests, or a server without resets. Err(InvalidInput) for an empty input.
fn server_verify_password(server_url: String, username: String, token: String, password: String,
    pins: Vec<String>) -> Result<bool>;  // adopt a password changed elsewhere: true → vault.change_master_password(it)
fn server_account(server_url: String, username: String, token: String, pins: Vec<String>) -> Result<ServerAccount>;
#[derive(uniffi::Record)] struct ServerDevice { id: String, name: String, created_at: i64 /* unix ms */,
    last_used_at: Option<i64> /* ±5 min; None = not used since tracked */, current: bool /* this device */, limited: bool }
fn server_list_devices(server_url: String, username: String, token: String, pins: Vec<String>) -> Result<Vec<ServerDevice>>;
    // §3.3 GET /api/v1/devices. Err(Network) limited device / old server / token signed out
fn server_revoke_device(server_url: String, username: String, token: String, device_id: String, pins: Vec<String>) -> Result<()>;
    // §3.3 DELETE /api/v1/devices/<id>; own device allowed (then forget the token). Err(NotFound) unknown/already signed out
// `username` everywhere above may be typed in any case or be the account's e-mail address (§3.4, Account names);
// the session's `username` is the account's real name: use that one afterwards.
fn fetch_server_pin(url: String) -> Result<String>;
    // Trust on first use (§3.2): "sha256:<b64url>" of the leaf certificate's SPKI the server presents, read WITHOUT
    // verifying the certificate (the handshake signature is still checked). Proves nothing by itself: show it, keep it
    // as a pin only after the user confirms it against `pass-server status`. Err(InvalidInput) bad address or
    // http:// (nothing to pin), Err(Network) can't connect / not TLS. Blocking.
#[derive(uniffi::Record)] struct ServerInfo { name: String, version: String, public_url: Option<String>,
    email: bool, password_reset: bool, signup: String /* "closed" | "invite" | "open" */, username_or_email: bool }
fn server_info(server_url: String, pins: Vec<String>) -> Result<ServerInfo>;
    // GET /api/v1/info, no account: "Connect to <name>?". Err(NotFound) not a Passyble Server (or one without /info);
    // a self-signed server without pins fails with Err(Network(certificate …)): fetch_server_pin, confirm, retry.
#[derive(uniffi::Record)] struct ServerSignup { username: Option<String> /* open: the new account */,
    check_email: bool /* invite: an invite link is on its way */ }
fn server_signup(server_url: String, username: String, email: String, password: String, pins: Vec<String>)
    -> Result<ServerSignup>;
    // §3.6, when ServerInfo.signup allows it. "invite": email (+ optional wished-for username), password ignored;
    // "open": username + password (8+ chars), then server_login. Err(Network("sign-up is closed…")),
    // Err(Conflict) name taken, Err(InvalidInput) bad name/address, Err(Network("…try again…")) rate-limited.

// Two-factor sign-in (TOTP) and security events (§3.7, §3.8). Blocking, pins as above. `otp` / `code` is the authenticator's
// 6-digit code or a recovery code (xxxx-xxxx-xxxx, any case, dashes optional); trimmed, empty = none. A server's JSON error
// {"error","message"} (§3.7) maps like this: 401 "2fa_required" / "2fa_invalid" → Err(InvalidInput("2fa_required: <message>"))
// / Err(InvalidInput("2fa_invalid: <message>")) (Rust consts TWO_FACTOR_REQUIRED / TWO_FACTOR_INVALID; Kotlin: e is
// PassException.InvalidInput && e.message.contains("2fa_required")), 409 → Err(Conflict(message)), other JSON errors →
// Err(Network("<action>: <message>")); a 404/405 from a server without the endpoint → Err(Network("…doesn't support…")).
fn server_login_2fa(server_url: String, username: String, password: String, device_name: String, otp: Option<String>,
    pins: Vec<String>) -> Result<ServerSession>;
    // server_login + otp. Flow: call with None; on 2fa_required ask for the code and call again (nothing was registered yet;
    // the password is checked again); 2fa_invalid = wrong, expired or already used code (each code works once): ask again.
    // A code for an account without two-factor sign-in is ignored. server_login is this with None and fails with
    // 2fa_required for such an account.
fn server_change_password_2fa(server_url: String, username: String, token: String, old_password: String,
    new_password: String, otp: Option<String>, pins: Vec<String>) -> Result<()>;   // server_change_password + otp
fn server_set_password_with_code_2fa(server_url: String, username: String, code: String, new_password: String,
    otp: Option<String>, pins: Vec<String>) -> Result<()>;
    // server_set_password_with_code + otp: a reset link alone doesn't take over a two-factor account. The one-time `code`
    // is used up only when the whole request succeeds, so 2fa_required / 2fa_invalid leave the link working: ask for the
    // code and call again. Lost authenticator and recovery codes: only the server's admin can help (`user 2fa-reset`).
#[derive(uniffi::Record)] struct ServerTwoFactorStatus { enabled: bool, pending: bool /* set up, not confirmed */,
    enabled_at: Option<i64>, recovery_codes_left: u32 /* 0 when off */, available: bool /* the server lets users turn it on */ }
#[derive(uniffi::Record)] struct ServerTwoFactorSetup { secret: String /* base32, a secret: don't log or store */,
    otpauth_uri: String /* show as a QR code */, issuer: String, account: String, digits: u32, period: u32 }
fn server_two_factor_status(server_url: String, username: String, token: String, pins: Vec<String>)
    -> Result<ServerTwoFactorStatus>;                    // GET /api/v1/2fa
fn server_two_factor_setup(server_url: String, username: String, token: String, password: String, pins: Vec<String>)
    -> Result<ServerTwoFactorSetup>;
    // POST /api/v1/2fa/setup with the account password (auth_key derived like server_login): a new authenticator secret,
    // not active yet. Err(InvalidPassword) wrong password, Err(Conflict) already on / account without a password,
    // Err(Network) turned off by the admin.
fn server_two_factor_confirm(server_url: String, username: String, token: String, code: String, pins: Vec<String>)
    -> Result<Vec<String>>;
    // POST /api/v1/2fa/confirm with the first code: turns it on, returns the 10 recovery codes (show once, never store).
    // Err(InvalidInput("2fa_invalid: …")) wrong code, Err(Conflict) no setup pending, Err(InvalidInput) empty code.
fn server_two_factor_disable(server_url: String, username: String, token: String, password: String, code: String,
    pins: Vec<String>) -> Result<()>;
    // POST /api/v1/2fa/disable with the password and a current code or recovery code ("" only to drop a setup that was never
    // confirmed). Err(InvalidPassword), Err(InvalidInput("2fa_required: …" | "2fa_invalid: …")), Err(Conflict) not on.
#[derive(uniffi::Record)] struct ServerSecurityEvent { at: i64 /* unix ms */, event: String /* sign_in, sign_in_failed,
    account_slowed_down, device_added, device_revoked, password_changed, password_reset_requested, 2fa_setup_started,
    2fa_enabled, 2fa_disabled, 2fa_recovery_code_used, 2fa_reset, invite_issued, reset_link_issued, signup, user_added,
    email_changed, admin_password_reset; newer servers may add more: show unknown ones generically */,
    actor: String /* user | admin | server | anonymous */, device_id: Option<String>, device_name: Option<String>,
    ip: Option<String>, detail: Option<String> /* qualifier, e.g. sign_in_failed: password | 2fa */,
    count: Option<u64> /* devices signed out, failures, recovery codes left */, current: bool /* this device */ }
fn server_security_events(server_url: String, username: String, token: String, limit: u32, pins: Vec<String>)
    -> Result<Vec<ServerSecurityEvent>>;
    // GET /api/v1/security-events[?limit=]: newest first; limit 1..=200 (0 = the server's default, 50; larger is capped).
    // Err(Network) from a server without the endpoint or with its audit log off, or for a limited device.

// Cards (Core/core/src/model.rs)
fn card_brand(number: String) -> String;        // "visa" | "mastercard" | "amex" | "discover" | "diners" | "jcb" | "unionpay"
                                                // | "maestro" | "mir" from the leading digits (spaces, dashes ignored), else ""
fn card_brand_name(brand: String) -> String;    // "amex" → "American Express"; unknown ids capitalised; "" stays ""
fn card_number_valid(number: String) -> bool;   // Luhn check, 12 to 19 digits (spaces and dashes allowed)
const TRASH_RETENTION_MS: i64;                  // 30 days

// Export (Core/core/src/export.rs; formats in ARCHITECTURE.md §6). Live items only, never the trash. Every export holds
// secrets: say so and suggest deleting the file afterwards. Only the encrypted one runs Argon2id (blocking).
fn export_csv(vault: Arc<Vault>) -> String;     // Bitwarden-compatible CSV (UTF-8)
fn export_json(vault: Arc<Vault>) -> String;    // Passyble JSON: every kind, custom fields, tags, passkeys with private keys, password history
fn export_encrypted_json(vault: Arc<Vault>, password: String) -> Result<Vec<u8>>;
    // export_json sealed under `password` (Argon2id 64 MiB / t=3 / p=1 + XChaCha20-Poly1305); Err(InvalidInput) for ""
fn export_is_encrypted(data: Vec<u8>) -> bool;  // an encrypted Passyble export: ask for its password
fn export_decrypt(data: Vec<u8>, password: String) -> Result<Vec<u8>>;   // the Passyble JSON inside; Err(InvalidPassword) wrong
    // password, Err(InvalidInput) not an encrypted export / a newer version / KDF parameters out of bounds

// Password health (Core/core/src/health.rs). Offline; no secrets in the results.
#[derive(uniffi::Record)] struct PasswordStrength { score: u32 /* 0 very weak … 4 strong */, entropy_bits: f64 }
#[derive(uniffi::Record)] struct HealthItem { item_id: String, title: String, username: String, domain: String,
    score: u32, password_changed_at: i64 /* updated_at when unknown */, reuse_count: u32 /* live items sharing the password */ }
#[derive(uniffi::Record)] struct ReusedGroup { items: Vec<HealthItem> }               // 2 or more, by title
#[derive(uniffi::Record)] struct DuplicateSet { items: Vec<HealthItem> }              // 2 or more, most recently changed first
#[derive(uniffi::Record)] struct InsecureItem { item: HealthItem, urls: Vec<String> /* its http:// addresses to public sites */,
    can_use_https: bool /* all are domain names without a port: health_use_https may change them */ }
#[derive(uniffi::Record)] struct SiteItem { item: HealthItem, methods: Vec<String> /* as SiteSecurity */, docs_url: String /* "" if none */ }
#[derive(uniffi::Record)] struct HealthReport { checked: u32 /* live items with a password */,
    weak: Vec<HealthItem> /* score ≤ 1, weakest first */, reused: Vec<ReusedGroup> /* largest group first */,
    old: Vec<HealthItem> /* unchanged > OLD_PASSWORD_MS (365 d), oldest first */,
    healthy: u32 /* checked, and not weak, reused, old, contains_name or insecure */,
    contains_name: Vec<HealthItem> /* password contains the username or site name (≥ 4 chars; not weak ones) */,
    insecure: Vec<InsecureItem> /* http:// to a public host (not localhost, single labels, .local, .lan, .home.arpa, private IPs …) */,
    no_two_factor: Vec<SiteItem> /* the 2FA Directory lists the site; no TOTP secret, no passkey */,
    passkeys: Vec<SiteItem> /* the Passkeys Directory lists the site; no passkey */,
    no_password: Vec<HealthItem> /* live logins with a username or website, no password, passkey or TOTP; not in checked */,
    duplicates: Vec<DuplicateSet> /* as find_duplicates */ }   // the lists after old: by title
fn password_health(vault: Arc<Vault>) -> HealthReport;       // = health_report(&vault.items(), now) (the Rust-only fn takes any items)
fn health_use_https(vault: Arc<Vault>, item_id: String) -> Result<u32>;  // "Change to https": the item's http:// addresses that
                                                             // can_use_https allows become https:// (upsert; the caller saves); how many
                                                             // changed; Err(NotFound) no such live item
// Offline site directories (Core/core/src/sites.rs, Core/core/data/*.tsv from scripts/update-site-security.mjs): matched by host, its parent
// domains down to the registrable domain, then any entry with the same registrable domain.
#[derive(uniffi::Record)] struct SiteSecurity { two_factor: Vec<String> /* totp, security_key, sms, call, email, app, device */,
    two_factor_docs: String, passkeys: Vec<String> /* passwordless, mfa */, passkey_docs: String }   // docs: https:// links or ""
fn site_security(url: String) -> Option<SiteSecurity>;       // None: in neither directory
// Popular sites (Core/core/src/popular_sites.rs, Core/core/data/popular-sites.txt, about 1,600 sites, most popular first): a new
// login's website suggested from the name being typed and its name from the website. Offline; no query leaves the device. Only
// suggestions: they never decide which logins a page or app is offered.
#[derive(uniffi::Record)] struct SiteSuggestion { name: String /* the site's name, or the other name matched: "Gmail" */,
    domain: String /* bare domain: the one the query matched, else the main one */ }
fn site_suggestions(query: String, limit: u32) -> Vec<SiteSuggestion>;  // name or other name (Twitter, Gmail), case, accents and
                                                             // punctuation ignored, or domain (https:// and www. left out); whole match,
                                                             // then start of name or domain, then start of a later word; popular first;
                                                             // limit capped at 50 (MAX_SITE_SUGGESTIONS); empty query: []
fn site_for_domain(domain: String) -> Option<String>;        // URL or host: its name ("AWS" for signin.aws.amazon.com), by host then
                                                             // parent domains down to the registrable domain; None for unknown sites,
                                                             // IP addresses, single labels, shared hosting (alice.github.io)
fn site_for_android_app(package: String) -> Option<SiteSuggestion>;  // com.netflix.mediaclient: Netflix, netflix.com; only for naming
fn password_strength(password: String) -> PasswordStrength;  // offline estimate: common passwords/words (also leetspeak), runs, sequences,
                                                             // keyboard rows and years are cheap pieces, other characters cost
                                                             // log2(classes used); a password on Core/core/data/common-passwords.txt (also
                                                             // capitalised, leetspeak, + up to 4 digits and 2 symbols) costs at most
                                                             // 16 bits; score < 28 bits 0, < 36 1, < 60 2, < 80 3, else 4
// Checking one password before it is saved (Core/core/src/password_check.rs): save prompts and editors. On the device only: the
// password, its hash or any part of it is never sent anywhere (the breach check below is separate and user-started).
#[derive(uniffi::Record)] struct PasswordContext { username: String, urls: Vec<String> /* web addresses */,
    android_apps: Vec<String> /* package names; androidapp:// ok */, title: String,
    item_id: String /* the item being edited, "" for a new one: its own password is not "reused" */ }
#[derive(uniffi::Enum)]   enum PasswordIssueKind { Common, Weak, Reused, UsedBefore, ContainsUsername, ContainsSite, Short }
#[derive(uniffi::Enum)]   enum IssueSeverity { High, Medium, Low }
#[derive(uniffi::Record)] struct PasswordIssue { kind: PasswordIssueKind, severity: IssueSeverity,
    count: u32 /* Reused: other live logins with it */, name: String /* ContainsUsername/ContainsSite: the name found, lower case */,
    min_length: u32 /* Short: PASSWORD_MIN_LENGTH */ }
#[derive(uniffi::Record)] struct PasswordCheck { score: u32 /* as PasswordStrength; 0 when Common */, entropy_bits: f64,
    label: String /* very_weak, weak, fair, good, strong; "" for "" */, issues: Vec<PasswordIssue> /* severity, then kind order */,
    vault_checked: bool /* a vault was given: Reused and UsedBefore were checked */ }
fn password_issues(vault: Option<Arc<Vault>>, password: String, context: PasswordContext) -> PasswordCheck;
    // None (locked): only the checks of the password itself. Checks and thresholds:
    //   Common (High): on the bundled list (as password_strength); Weak (High): score <= 1, not with Common;
    //   Reused (High): other live items with exactly this password, item_id left out, trash ignored;
    //   UsedBefore (Medium): in item_id's password history but not its current password;
    //   ContainsUsername (Medium): the username, an e-mail's local part or its pieces (. _ - + space), >= 4 chars,
    //   case and leetspeak ignored; ContainsSite (Medium): a website's registrable-domain label, an Android package's
    //   distinctive labels, a one-word title, >= 4 chars; Short: < 12 characters (High < 8, Low when score >= 3, else
    //   Medium). An empty password: no issues. Only the first 4096 characters count; the copies are zeroized.
const PASSWORD_MIN_LENGTH: u32 = 12;
    // The Windows app's editor calls it through the Tauri command `password_check { password, username?, urls?, title?, id? }`
    // (main window), which answers with the same JSON as the agent's `password.check` (§2).
// Breach check (Have I Been Pwned range API, k-anonymity): only the first 5 hex characters of the password's SHA-1 may leave the device.
#[derive(uniffi::Record)] struct HibpQuery { prefix: String /* 5 chars of the uppercase hex SHA-1 */, suffix: String /* the other 35: keep in memory */ }
fn hibp_prefix(password: String) -> HibpQuery;
    // GET https://api.pwnedpasswords.com/range/<prefix> (header `Add-Padding: true`), then:
fn hibp_match(range_response: String, suffix: String) -> u64;   // how often the suffix appears in the response (SUFFIX:COUNT lines); 0: not found
fn hibp_check(password: String) -> Result<u64>;                 // both steps with one request (feature webdav, blocking); Err(Network)

// Import from other apps (offline). Parse → preview → commit; the parsed items stay in Rust inside ImportBatch.
#[derive(uniffi::Enum)] enum ImportFormat {
    GoogleAuthenticator, OtpauthUris, Aegis, TwoFas, ChromeCsv, FirefoxCsv, AppleCsv, ProtonPass, ProtonPassCsv,
    OnePassword, OnePasswordCsv, BitwardenJson, BitwardenCsv, KeepassxcCsv, LastpassCsv, DashlaneCsv, GenericCsv,
    PassybleJson /* export_json; an encrypted one is opened with the password first */,
    Keepass /* .kdbx / .kdb, opened with its password and/or key file */ }
#[derive(uniffi::Enum)]   enum ImportAction { Add, Merge, Conflict /* kept as a separate item (Keep both) */,
    Duplicate /* nothing new */, Skip /* left out by a Skip decision although it differs */ }
#[derive(uniffi::Record)] struct ImportSkip { entry: String, reason: String }
#[derive(uniffi::Record)] struct ImportEntry {          // one parsed entry; no secrets
    kind: ItemKind, title: String, username: String, url: Option<String> /* first website */,
    has_password: bool, has_totp: bool, passkeys: u32, has_notes: bool,
    action: ImportAction /* with its group's default decision */,
    target_id: Option<String>, target_title: Option<String> /* the vault item (or first entry) it merges into */,
    adds: Vec<String> /* Merge: e.g. ["2FA", "passkey", "website", "new password"] */,
    group: Option<String> /* its ImportGroup.id when it clashes */ }
// Clash groups: entries that are the same account as a vault item (site + username, as for dedupe) or as
// each other. No secrets: which fields differ, and opaque choice ids for which password / 2FA / title to keep.
#[derive(uniffi::Enum)] enum ClashKind { Identical /* matches a vault item, nothing new (title aside): default Skip */,
    Differs /* matches a vault item, something differs: default Merge */,
    InFileDuplicate /* 2+ entries of the file, none in the vault: default Merge into one */ }
#[derive(uniffi::Enum)] enum ClashField { Title, Password, Totp, Urls, Notes, Passkeys }
#[derive(uniffi::Enum)] enum MergeSource { Existing, Import, Vault }
#[derive(uniffi::Record)] struct MergeChoice { id: String /* "existing" | "import#<n>" (entry n) | an item id */,
    source: MergeSource, label: String /* title it comes from */, modified_at: i64 /* ms, 0 unknown */, is_default: bool }
#[derive(uniffi::Enum)] enum ImportDecision {          // JSON (desktop): {"type":"skip"|"merge"|"keep_both", …}
    Skip, KeepBoth,
    Merge { password_from: Option<String>, totp_from: Option<String>, title_from: Option<String> } } // MergeChoice ids; None = default
#[derive(uniffi::Record)] struct ImportGroup { id: String /* stable for the same file + vault */, kind: ClashKind,
    title: String, username: String, url: Option<String>, existing_id: Option<String>, existing_title: Option<String>,
    entries: Vec<u32> /* indices into ImportPreview.entries */, differs: Vec<ClashField>,
    password_choices: Vec<MergeChoice> /* 2+ when the passwords differ, else empty */, totp_choices: Vec<MergeChoice>,
    title_choices: Vec<MergeChoice>, default_decision: ImportDecision }
#[derive(uniffi::Record)] struct ImportGroupDecision { group_id: String, decision: ImportDecision }
#[derive(uniffi::Record)] struct ImportPreview {
    format: ImportFormat, format_name: String, entries: Vec<ImportEntry>,
    to_add: u32 /* new items, incl. conflicts */, to_merge: u32 /* entries merged */, conflicts: u32, duplicates: u32,
    clashes: u32, groups: Vec<ImportGroup> /* counts and actions assume each group's default decision */,
    skipped: Vec<ImportSkip> /* entries of the file that can't be imported */, warnings: Vec<String> }
#[derive(uniffi::Record)] struct ImportResult { added: u32 /* incl. conflicts */, merged: u32 /* entries merged */,
    conflicts: u32 /* kept both */, skipped: u32 /* duplicates + skipped groups + unreadable */ }
#[derive(uniffi::Object)] struct ImportBatch;
fn import_parse(data: Vec<u8>, file_name: String, format: Option<ImportFormat>) -> Result<Arc<ImportBatch>>;
    // format None = detect. Err(InvalidInput(msg)) for unknown/encrypted/oversized (> 50 MB) files; msg is user-facing.
    // Accepts otpauth-migration:// and otpauth:// links as text (one or many). Images (PNG/JPEG QR codes)
    // need the `import-qr` feature, which the Android build leaves off: scan with the camera, pass the link text.
#[derive(uniffi::Record)] struct ImportEncryption {
    source: String /* "Bitwarden (JSON)", "KeePass (KDBX)", "Aegis", "2FAS", "Proton Pass", "Passyble (JSON)", "PGP", "ZIP" */,
    format: Option<ImportFormat> /* None for a PGP file or an encrypted ZIP: known once opened */,
    key_file: bool /* a KeePass database: may take a key file with or instead of the password */ }
fn import_encryption(data: Vec<u8>, file_name: String) -> Option<ImportEncryption>;
    // Some for a password-protected export this build can open: an encrypted Passyble export, Bitwarden
    // "password protected" JSON, an encrypted Aegis vault or 2FAS backup, a KeePass .kdbx/.kdb, a Proton Pass ZIP with
    // data.pgp or any passphrase-encrypted OpenPGP file, a ZIP with encrypted members. None for anything else
    // (including Bitwarden's account-restricted export, which import_parse explains). Ask for the password, then:
fn import_parse_with_password(data: Vec<u8>, file_name: String, password: String) -> Result<Arc<ImportBatch>>;
fn import_parse_with_key_file(data: Vec<u8>, file_name: String, password: String, key_file: Option<Vec<u8>>)
    -> Result<Arc<ImportBatch>>;
    // Open a password-protected export (docs/ARCHITECTURE.md §6, Encrypted exports) and parse it; anything else is
    // parsed as import_parse(data, file_name, None). Err(InvalidPassword) for a wrong password (or key file);
    // Err(InvalidInput) for a damaged file or one whose key derivation settings are beyond the bounds ("unusually
    // heavy settings"). key_file is for KeePass (an empty password with a key file = key file only).
    // import_parse alone on such a file is Err(InvalidInput) saying it is encrypted with a password.
impl ImportBatch {
    fn format(&self) -> ImportFormat;
    fn item_count(&self) -> u32;
    fn preview(&self, vault: Arc<Vault>) -> ImportPreview;          // dry run against the vault as it is now
    fn commit(&self, vault: Arc<Vault>) -> Result<ImportResult>;    // = commit_with(vault, []): every group's default
    fn commit_with(&self, vault: Arc<Vault>, decisions: Vec<ImportGroupDecision>) -> Result<ImportResult>;
        // re-plans against the current vault with these decisions (missing → default, unknown ids ignored, a choice id
        // not in the group → default), then upserts; the caller serializes/saves and syncs afterwards
}
// Duplicates already in the vault (Settings → Import → Find duplicates): logins sharing a website (normalised host)
// and the same username, or, both without a username, the same password. No secrets.
#[derive(uniffi::Record)] struct DuplicateGroup { id: String, kind: ClashKind /* Identical | Differs */, title: String,
    username: String, url: Option<String>, item_ids: Vec<String> /* most recently changed first; the first is kept */,
    items: Vec<MergeChoice>, differs: Vec<ClashField>, password_choices: Vec<MergeChoice> /* ids = item ids */,
    totp_choices: Vec<MergeChoice>, title_choices: Vec<MergeChoice>, default_decision: ImportDecision /* Merge */ }
fn find_duplicates(vault: Arc<Vault>) -> Vec<DuplicateGroup>;
fn merge_items(vault: Arc<Vault>, ids: Vec<String>, decision: ImportDecision) -> Result<Option<Item>>;
    // Merge: folds ids[1..] into ids[0] (kept, returned) and deletes them for good (not to the trash: the kept item holds
    // what they had); Skip / KeepBoth: nothing, None.
    // Err(NotFound) unknown id, Err(InvalidInput) fewer than 2 items or a login with a note. Caller saves + syncs.
// Merging two items the user picked (Core/core/src/import/pair.rs): every single-value field from A or B.
#[derive(uniffi::Enum)] enum MergeSide { A, B }
#[derive(uniffi::Enum)] enum MergeNotes { A, B, Both /* the kept item's notes, a blank line, the other's */ }
#[derive(uniffi::Record)] struct MergePicks { primary, title, username, password, totp: Option<MergeSide>,
    notes: Option<MergeNotes> }   // None = default: the side that has a value; both differ: the newer one;
    // otherwise the primary. primary (the id that stays) defaults to the item with a password (A if both / neither)
#[derive(uniffi::Record)] struct MergePlan { fields: Vec<MergeFieldPlan { field: MergeField /* Title | Username |
    Password | Totp | Notes */, state: MergeFieldState /* Empty | Same | OnlyA | OnlyB | Differs */ }>,
    default_primary: MergeSide, urls: u32, android_apps: u32, passkeys: u32 /* of the result, both united */ }
#[derive(uniffi::Record)] struct MergePreview { plan: MergePlan, picks: MergePicks /* all resolved */,
    item: Item /* the merged item: holds secrets */, history_added: u32, totp_noted: bool }
fn merge_preview(a: Item, b: Item, picks: MergePicks) -> Result<MergePreview>;   // pure, nothing saved
fn merge_pair(vault: Arc<Vault>, a_id: String, b_id: String, picks: MergePicks) -> Result<MergeOutcome>;
    // MergeOutcome { item, removed_id, undo: Arc<MergeUndo> }: the primary keeps its id; websites, Android apps,
    // passkeys (unchanged: credential id, rp id, user handle) of both; the password not kept goes to the history
    // (both histories united, newest first, at most 20); a 2FA secret not kept is noted in the notes; favorite if
    // either; tags and custom fields of both; the other item is deleted for good (not to the trash) and this device's
    // usage counts get its uses (Vault::move_usage).
    // Err(InvalidInput) same item twice or a login with a note. Caller saves + syncs.
#[derive(uniffi::Object)] struct MergeUndo;   // memory only (secrets); drop on lock
    fn kept_id(&self) -> String; fn removed_id(&self) -> String; fn kept_title(&self) -> String;
    fn restore(&self, vault: Arc<Vault>) -> Result<Item>;   // both items back (newer versions), usage moved back;
        // once only; Err(InvalidInput) for another vault. Usage already synced may stay a little high (grow-only).
fn merge_suggestions(vault: Arc<Vault>) -> Vec<MergeSuggestion>;
    // MergeSuggestion { login_id, login_title, otp_id, otp_title, username, url }: an authenticator entry (2FA,
    // no password, no passkey) and a login (password; no 2FA or the same secret) with the same website / domain,
    // the issuer naming the login's site or title, or the same title; same username or one empty. Each item once.
fn merge_candidates(vault: Arc<Vault>, id: String) -> Vec<MergeCandidate { id: String, score: u32 }>;
    // "Merge with…": every other item of the same kind, likeliest first (score 0: no sign of the same account)
```

**Merging** (import groups and vault duplicates alike, `Core/core/src/import/merge.rs`): the first version (the
vault item, or the first entry) is the base and keeps its id and username. Websites, notes (appended after a
blank line unless already contained), passkeys (by credential id) and linked Android apps are united. One
password is kept: the chosen one, by default the most recently modified (an export without dates never beats
the vault's known date, so it keeps the vault's password); every other distinct password goes to the item's
**`password_history`** (`Vec<PasswordHistoryEntry { password, replaced_at }>`, newest first, at most 20, sealed
with the item; omitted from the item JSON when empty, so items without history are byte-identical to before;
older clients ignore the field and drop it only if they re-save that item). Tags and custom fields the base lacks
(same name and value) are added, and card / identity fields the base leaves empty are filled from the others (its own
values stay); a group where only these differ counts as `Differs`, not `Identical`. One 2FA secret is kept the same
way; a replaced one is appended to the notes as `Previous 2FA secret (replaced YYYY-MM-DD): <value>`. A
password already in the base's history, or a 2FA secret already in its notes, is not a difference, so
re-importing the same file after a merge is Identical (skipped).

Kotlin: `importParse(data, fileName, null)` → `batch.preview(vault)` → show it (plain entries + `groups`) →
`batch.commitWith(vault, decisions)` (or `batch.commit(vault)` for the defaults) → save the vault file and sync as
after any edit → `batch.close()`. Dedupe rules: see ARCHITECTURE.md §6.

Website icons (feature `icons`, on in the default build and for Android; ARCHITECTURE.md §11). Blocking
calls make network requests: run them off the UI thread.

```rust
#[derive(uniffi::Record)] struct SiteIcon { bytes: Vec<u8> /* PNG, ≤ 128 px a side */, mime: String /* "image/png" */,
    width: u32, height: u32, source_url: String }
#[derive(uniffi::Record)] struct CachedSiteIcon { png: Option<Vec<u8>> /* None: the site has no icon */,
    fetched_at_ms: i64, needs_refresh: bool /* fetch again; png stays usable meanwhile */ }
fn site_icon_domain(url_or_host: String) -> Option<String>;   // cache key: lower-case host, no www./port;
                                                              // None: no icon (app link, IP, localhost, intranet)
fn fetch_site_icon(domain: String) -> Result<SiteIcon>;       // NotFound: no usable icon; Network: unreachable
fn site_icon_cache_read(cache_dir: String, domain: String) -> Option<CachedSiteIcon>;  // None: not cached yet
fn site_icon_cache_refresh(cache_dir: String, domain: String) -> Result<Option<Vec<u8>>>; // fetch + store; domain
                                                              // must come from site_icon_domain; returns the PNG to show
fn site_icon_cache_clear(cache_dir: String) -> Result<u32>;   // deletes the cache's own files only
fn site_icon_cache_file_name(domain: String) -> String;       // hex SHA-256(domain) + ".icon"
```

Cache file: `SPI1`, a status byte (1 icon, 0 none, 2 fetch failed), the fetch time (i64 Unix ms, little
endian), then the PNG for status 1. Refreshed after 30 days (icon), 7 days (none) or 1 day (failed).

Shared vaults, emergency access, admin-assisted recovery, several open vaults, secure send and policies
(ARCHITECTURE.md §15 to §17). Exported through UniFFI (Kotlin and Swift names in camelCase; `UserKeyset` and
`Vault` are objects, the rest records and enums) and, as JSON, through the WebAssembly module (EXTENSION_VAULT.md
§16). Version 2 files open only with `open_shared_with_home` (or `open_shared`); `unlock`, `unlock_with_key` and
`unlock_with_recovery_code` refuse them with `InvalidInput` ("it opens with your Passyble account"). Edits in a
vault where this device's role is `view` or `fill`, or in a vault opened read-only (emergency view access), are
`InvalidInput`.

```rust
// Keys. UserKeyset is an object: its private keys never leave the core.
object UserKeyset { constructor new(account: &str) -> Result<UserKeyset>;   // Rust also: UserKeyset::generate
                    fn account_id() -> String; fn created_at() -> i64; fn public_keys() -> PublicKeys;
                    fn fingerprint() -> String /* "7K3QD-…", six groups of five */;
                    fn public_keys_for(account: &str) -> Result<PublicKeys> /* same keys, signed for another backend's id */ }
record PublicKeys { account: String, enc_pub: String /* b64 X25519 */, sig_pub: String /* b64 Ed25519 */,
                    created_at: i64, sig: String /* self-signature */ }
fn public_keys_verify(keys: PublicKeys) -> Result<()>
fn public_keys_fingerprint(keys: PublicKeys) -> String
enum MemberRole { Manage, Edit, View, Fill }
enum SharedKind { Org /* department or family vault */, Direct /* "Shared with Bob" */ }
record MemberInfo { account, role: MemberRole, group: Option<String> /* "via Engineering" */, fingerprint, added_by, added_at }
record SharedInfo { vault_id, kind, org: Option<String>, created_by, created_at, epoch: u64, key_epoch: u64, signed_by,
                    account /* this device's */, role, members: Vec<MemberInfo>,
                    anchored: bool /* false: first use, show the signer */,
                    signer_fingerprint: Option<String> /* of signed_by; None when they left the list */ }
enum MemberChange { Add { keys: PublicKeys, role, group: Option<String> }, SetRole { account, role },
                    SetGroup { account, group }, ReplaceKeys { keys } /* rotates */, Remove { account } /* rotates */ }
record GroupMember { keys: PublicKeys, role: MemberRole }
record MembersNotice { reapplied: Vec<MemberChange>, dropped: Vec<MemberChange>, rotated_after_leave: bool }

// Home vault (a personal vault): the keyset and the trust records, as vault settings.
fn Vault::ensure_user_keyset(account: &str) -> Result<UserKeyset>      // made (or the keys of another id reused); save after
fn Vault::publish_keys_for(account: &str) -> Result<PublicKeys>         // the backend's own account id: Cloud acc_…, server user name
fn Vault::user_keyset(account: &str) -> Result<Option<UserKeyset>>
fn Vault::store_user_keyset(keyset: &UserKeyset) -> Result<()>
fn Vault::remember_trust_of(shared: &Vault) -> Result<bool>   // after each sync of and member change in `shared`; save the home vault
    // also keeps `shared`'s unconfirmed member changes in the home vault's local file (never uploaded), which
    // open_shared_with_home takes back, so a change that loses to a concurrent one after a restart is applied again
fn Vault::forget_share_trust(vault_id: &str) -> Result<()>     // after the user confirmed the signer
// Rust only: stored_share_trust(vault_id) -> Option<ShareTrust>, remember_share_trust(&ShareTrust) -> Result<bool>,
// Vault::open_shared(&[u8], &UserKeyset, Option<&ShareTrust>, &str), Vault::share_trust() -> Option<ShareTrust>.

// Shared vaults.
constructor Vault::create_shared(keyset: &UserKeyset, kind: SharedKind, org: Option<String>, device_id: &str) -> Result<Vault>
constructor Vault::open_shared_with_home(file: Vec<u8>, home: &Vault, account: &str, device_id: &str) -> Result<Vault>
    // Crypto: list not signed by a manager / not a member / other keys / can't be tied to what this device knows;
    // Conflict: an older list than this user's devices accepted (download again), or another vault under this id
fn Vault::is_shared() -> bool
fn Vault::shared_info() -> Option<SharedInfo>
fn Vault::shared_role() -> Option<MemberRole>
fn Vault::can_edit() -> bool                 // true in a personal vault (false when opened read-only)
fn Vault::can_reveal_secrets() -> bool       // false for fill-only: hide Reveal, Copy, history, Export
fn Vault::change_members_pinned(changes: Vec<MemberChange>, home: &Vault) -> Result<SharedInfo>
    // a manager; one new signed list; every Add / ReplaceKeys key pinned in home (§15.16), else Crypto
fn Vault::change_members(changes: Vec<MemberChange>) -> Result<SharedInfo>   // roles, groups, removals only
fn Vault::add_member(keys: PublicKeys, role: MemberRole, group: Option<String>, home: &Vault) -> Result<SharedInfo>
fn Vault::set_member_role(account: &str, role: MemberRole) -> Result<SharedInfo>
fn Vault::remove_member(account: &str) -> Result<SharedInfo>              // rotates the key
fn Vault::leave_shared() -> Result<()>       // a manager while another remains; upload, then delete the copy
fn Vault::rotate_shared_key() -> Result<SharedInfo>
fn Vault::sync_group(group: &str, members: Vec<GroupMember>, home: &Vault) -> Result<Option<SharedInfo>>
fn Vault::take_members_notice() -> Option<MembersNotice>   // after merge_remote / open: lost changes applied again
fn Vault::copy_item_to(id: &str, target: &Vault) -> Result<Item>   // new id; history, passkeys, dates kept
fn Vault::move_item_to(id: &str, target: &Vault) -> Result<Item>   // then deletes the original for good

// Pinned contact keys, in the home vault (ARCHITECTURE.md §15.16). scope: "personal" or "org:<group id>".
enum PinSource { Compared, KeyMove }
enum PinStatus { Pinned, NotPinned, Changed { pinned_fingerprint } }
record ContactPin { account, scope, fingerprint, enc_pub, sig_pub, pinned_at: i64, source: PinSource,
                    previous_fingerprint: Option<String> }
record PinProblem { account, fingerprint, status: PinStatus }
fn Vault::pin_contact(keys: PublicKeys, scope: &str, compared: &str) -> Result<ContactPin>  // Crypto: not its fingerprint
fn Vault::unpin_contact(account: &str, scope: &str) -> Result<()>
fn Vault::contact_pins() -> Vec<ContactPin>
fn Vault::contact_pin(account: &str, scope: &str) -> Option<ContactPin>
fn Vault::contact_pin_status(keys: PublicKeys, scope: &str) -> Result<PinStatus>   // own keys: Pinned
fn Vault::unpinned_changes(changes: Vec<MemberChange>) -> Vec<PinProblem>       // show these, compare first
fn Vault::shared_signer_status(shared: &Vault) -> Option<PinStatus>            // first open: "Shared by Alice"

// Emergency access (personal vaults; ARCHITECTURE.md §15.12).
enum EmergencyAccess { View, Full }
record EmergencyGrant { grant_id, vault_id, owner, contact, contact_fingerprint, access, wait_hours: u32 /* 1..=2160 */,
                        created_at: i64, key_check, blob /* opaque */ }
record EmergencyGrantCreated { grant: EmergencyGrant, release_secret: String /* for the service only */ }
fn Vault::emergency_grant(owner: &str, contact: PublicKeys, access: EmergencyAccess, wait_hours: u32) -> Result<EmergencyGrantCreated>
fn Vault::emergency_grant_current(grant: EmergencyGrant) -> bool    // false after a new vault key: set it up again
constructor Vault::open_emergency(file: Vec<u8>, grant: EmergencyGrant, release_secret: &str, contact: &UserKeyset,
                                  device_id: &str) -> Result<Vault>  // View: read-only; Full: may set a new master password
fn Vault::is_read_only() -> bool

// Admin-assisted recovery (Teams only, opt-in; ARCHITECTURE.md §15.13). Every call refuses OrgKind::Family.
enum OrgKind { Team, Family }
record AdminWrap { admin, enc, ct }
record OrgRecoveryKey { org, key_id, recovery_pub, created_by, created_at, sig, wraps: Vec<AdminWrap> }
record RecoveryEnrollment { org, key_id, account, vault_id, created_at, key_check, enc, ct }
record RecoveryRequestPublic { request_id, org, account, vault_id, enc_pub, created_at }
record RecoveryRequest { request: RecoveryRequestPublic, secret: String /* keep in secure storage until approved */ }
record RecoveryApproval { org, key_id, request_id, account, vault_id, request_enc_pub, approved_by, approved_at,
                          key_check, enc, ct, sig }
record AdminRecoveryUse { org, request_id, approved_by, approver_fingerprint, approved_at, completed_at }
record AdminRecoveryStatus { org, key_id, enrolled_at }
fn org_recovery_create(admin: &UserKeyset, org: &str, kind: OrgKind, admins: Vec<PublicKeys>, home: &Vault)
    -> Result<OrgRecoveryKey>   // admins pinned in home
fn org_recovery_rewrap(key: OrgRecoveryKey, admin: &UserKeyset, new_admins: Vec<PublicKeys>, home: &Vault)
    -> Result<OrgRecoveryKey>
fn org_recovery_verify(key: OrgRecoveryKey, creator: PublicKeys) -> Result<()>
fn Vault::admin_recovery_enroll(key: OrgRecoveryKey, creator: PublicKeys, account: &str, kind: OrgKind) -> Result<RecoveryEnrollment>
    // creator pinned in this (home) vault, else Crypto
fn Vault::admin_recovery_enrollments() -> Vec<AdminRecoveryStatus>
fn Vault::admin_recovery_withdraw(org: &str) -> Result<()>
fn Vault::admin_recovery_enrollment_current(enrollment: RecoveryEnrollment) -> bool
fn admin_recovery_request(org: &str, account: &str, vault_id: &str) -> Result<RecoveryRequest>
fn recovery_request_code(request: RecoveryRequestPublic) -> Result<String>   // member shows it, reads it out
fn admin_recovery_approve(key: OrgRecoveryKey, admin: &UserKeyset, enrollment: RecoveryEnrollment,
                          request: RecoveryRequestPublic, code: &str) -> Result<RecoveryApproval>
    // code: what the member read out; Crypto recovery.code_mismatch otherwise
constructor Vault::unlock_with_admin_recovery(file: Vec<u8>, approval: RecoveryApproval, secret: &str,
                                              approver: PublicKeys, device_id: &str) -> Result<Vault>
    // then change_master_password; the use is recorded in the vault:
fn Vault::admin_recovery_log() -> Vec<AdminRecoveryUse>

// Several open vaults (ARCHITECTURE.md §15.14).
record VaultSummaries { vault_id, shared: Option<SharedKind>, role: Option<MemberRole>, can_edit: bool, can_reveal: bool,
                        summaries: Vec<ItemSummary> }
record VaultItemSummary { vault_id, summary: ItemSummary }
fn Vault::vault_summaries() -> VaultSummaries          // keep one per vault for the soft lock
fn multi_vault_summaries(vaults: Vec<Vault>) -> Vec<VaultSummaries>
fn multi_search(groups: Vec<VaultSummaries>, query: String) -> Vec<VaultItemSummary>
fn multi_for_url(groups: Vec<VaultSummaries>, url: String) -> Vec<VaultItemSummary>
fn multi_for_android_app(groups: Vec<VaultSummaries>, package: String, cert_sha256: Option<String>) -> Vec<VaultItemSummary>
fn multi_with_passkeys(groups: Vec<VaultSummaries>, rp_id: String) -> Vec<VaultItemSummary>
fn multi_default_save_vault(groups: Vec<VaultSummaries>, url: Option<String>, preferred: Option<String>) -> Option<String>
// The lists read once, for many keystrokes and pages (TESTING.md §6): the same answers as multi_search
// (with notes: summaries_search_with_notes), multi_for_url and multi_for_android_app. Build it when the
// lists change; search_positions gives places in the summaries given (all groups one after the other).
object SearchIndex { constructor(groups: Vec<VaultSummaries>, notes: HashMap<String, String>); search(query) -> Vec<VaultItemSummary>;
                     search_positions(query) -> Vec<u32>; for_url(url) -> Vec<VaultItemSummary>;
                     for_android_app(package, cert_sha256: Option<String>) -> Vec<VaultItemSummary>; len() -> u32 }
// The soft-locked list read once for autofill and the Credential Manager: only what matching needs (under 1 MB for
// 5 000 items). Answers are places in the list given, in the order of summaries_for_url, summaries_for_android_app
// and summaries_with_passkeys. Make it once per soft lock, free it at a full lock.
object KeptMatcher { constructor(summaries: Vec<ItemSummary>); for_url(url) -> Vec<u32>;
                     for_android_app(package, cert_sha256: Option<String>) -> Vec<u32>; with_passkeys(rp_id) -> Vec<u32>; len() -> u32 }

// Secure send (ARCHITECTURE.md §16).
enum SendKind { Text, File }
record SendContent { kind, name, mime, data: Vec<u8> }        // at most SEND_MAX_BYTES (10 MiB)
record SendOptions { expires_at: i64 /* at most SEND_MAX_DAYS (30) away */, max_views: u32 /* 0: no limit */,
                     password: Option<String> }
record SealedSend { ciphertext: Vec<u8>, meta: String /* JSON for the service */, key: String /* fragment only */,
                    password_auth: Option<String> }
record SendInfo { expires_at, max_views, size: u64, has_password: bool }
record SendLink { send_id, key }
fn send_seal(content: SendContent, options: SendOptions) -> Result<SealedSend>
fn send_open(ciphertext: Vec<u8>, meta: String, key: String, password: Option<String>) -> Result<SendContent>
fn send_info(meta: String) -> Result<SendInfo>
fn send_password_auth(meta: String, password: String) -> Result<String>
fn send_link(base: &str, send_id: &str, key: &str) -> Result<String>   // "<base>/<id>#<key>"
fn send_parse_link(link: &str) -> Result<SendLink>

// Organisation policies (ARCHITECTURE.md §17).
record OrgPolicy { min_master_password_score: u32, max_auto_lock_secs: Option<u64>, export_allowed: bool,
                   sharing_outside_allowed: bool, require_two_step: bool }
record LocalSecurity { master_password_score: Option<u32>, auto_lock_secs: Option<u64>, two_step_enabled: bool }
enum PolicyRule { MasterPasswordStrength, AutoLock, TwoStep }
record PolicyViolation { rule: PolicyRule, message: String }
enum PolicyBlock { Export, SharingOutside }
fn policy_parse(json: &str) -> Result<OrgPolicy>
fn policy_strictest(policies: Vec<OrgPolicy>) -> OrgPolicy
fn policy_violations(policy: OrgPolicy, local: LocalSecurity) -> Vec<PolicyViolation>
fn policy_check_master_password(policy: OrgPolicy, password: String) -> Option<PolicyViolation>
fn policy_auto_lock_secs(policy: OrgPolicy, chosen: Option<u64>) -> Option<u64>
fn policy_allows_export(policy: Option<OrgPolicy>) -> bool
fn policy_allows_share(policy: Option<OrgPolicy>, recipient_in_org: bool) -> bool
fn policy_blocked_message(rule: PolicyBlock) -> String
```

`merge_remote` (and every sync built on it) merges a shared vault's members list first: a newer genuine list is
adopted with its key; `Crypto` "you no longer have access" when the winning list doesn't name this account. After
the items it applies again this device's member changes that lost to a concurrent list, and replaces the key after a
manager left; `take_members_notice` says what happened (save and upload when it did).

Passyble Server's shared vault and Passyble Cloud error codes (`X-Pass-Error`)
come back from every server call and from WebDAV sync (`webdav_sync`, `webdav_download`, `webdav_replace`) as
`Network` with the core's own words, so apps tell them apart with `core_message_is(message, "server.<code>")`
instead of reading a plain "authentication failed": `read_only_member` (a view or fill member's upload),
`subscription_inactive` (the organisation's plan ended: read-only), `account_suspended`, `cloud_managed` (a
self-hosted route on Passyble Cloud), `no_vault_access` (no longer a member), `not_vault_manager`,
`member_via_group` (access through a department). `SHARED_VAULT_ERRORS` (Rust) lists them.

## 2. Desktop agent IPC (agent ⇄ native host ⇄ extension)

### Transport

* **Extension ⇄ native host**: Chrome/Firefox Native Messaging. Each message is a 32-bit **native-endian**
  length followed by UTF-8 JSON. Host name: `com.sensyble.pass`.
* **Native host ⇄ agent**: local IPC. On Windows the named pipe `\\.\pipe\pass-agent-<username>`; on
  Unix the socket `$XDG_RUNTIME_DIR/pass-agent.sock` (fallback `/tmp/pass-agent-<uid>.sock`). Framing:
  newline-delimited JSON (one message per line).
* The native host is a dumb relay. If the agent isn't running, the host answers requests with error
  `agent_unavailable`. On Windows it tries to start `Pass.exe --background` once, when it is spawned and finds
  no agent, and waits up to ~15 s for it. After that it tries to connect again before each request, without
  starting the app again: once Passyble is up (autostart after the browser, a slow restart after an update), the
  request that finds it is relayed and the host works as usual. The app is started detached from the host (null
  stdio, its own process group, on Windows `CREATE_BREAKAWAY_FROM_JOB` when the host's job allows it), so it keeps
  running when the browser ends the host. When the port closes with requests unanswered (the host exited), the
  extension rejects them as `agent_unavailable` but sends read-only ones (`status`, `logins.find`, `cards.list`,
  ...) once more on a fresh port; the host's own `agent_unavailable` answer is final. The extension's "Start Pass" closes the native
  port and sends `status` again, so a fresh host starts the app. A browser without the host registered reports "Specified native messaging host not
  found." (Chrome/Edge) or "No such native application …" (Firefox); the extension then says to open Passyble →
  Settings → Autofill instead of offering Start Passyble.

### Envelope

```jsonc
// request
{ "id": 7, "method": "logins.find", "params": { "url": "https://github.com/login" } }
// success
{ "id": 7, "result": { … } }
// failure
{ "id": 7, "error": { "code": "locked", "message": "Vault is locked" } }
// unsolicited event (no id)
{ "event": "lock_state", "data": { "locked": true, "soft": true } }   // soft: the list is kept (see "Soft lock")
```

Error codes: `locked`, `not_found`, `url_mismatch`, `cancelled`, `invalid_state` (WebAuthn `InvalidStateError`:
an excluded credential is already in the vault), `not_supported` (e.g. the RP accepts no ES256; the extension
falls back to the browser), `invalid_params`, `agent_unavailable`, `internal`, `rate_limited` (too many edits,
QR scans or save checks in a minute; the extension says "Too many changes. Wait a minute."; for `unlock.password`
"Too many attempts. Wait a minute, then try again."), `wrong_password` (`unlock.password`: the master password
didn't open the vault; the message is the desktop app's "Wrong master password. Check Caps Lock and try again."),
`update_required` (the desktop app is below the minimum version the owner set and is read-only: see "Update
required" below; the extension says "Update the Passyble app to keep filling").
The extension has two more codes of its own, never on the wire: `timeout` (no answer within the method's time,
e.g. a Windows Hello prompt left open; "Passyble didn't answer in time", not "not running") and
`extension_reloaded` (a content script whose extension was updated or reloaded; "Reload this page").
The vault kept in the browser (docs/EXTENSION_VAULT.md, the same agent compiled to WebAssembly, never on
the native wire either) adds `no_vault` (no vault in this browser yet) and `verification_required` (verify
the user in an extension page, then send the request again with a grant; EXTENSION_VAULT.md §14), and its
`status` advertises `vault.browser`. Its Google Drive messages add `auth_required` and `network` (extension
notes below). The desktop agent never answers them.

Binary values are **base64url without padding**.

### Methods

| method | params | result |
|---|---|---|
| `status` | `{}` | `{ "locked": bool, "soft_locked": bool, "version": "0.1.0", "features": ["edit", "totp.from_image"] }`. `features` names what this agent can do beyond the original methods: `edit` (the editing methods below), `totp.from_image` (QR decoding, builds with `import-qr`), `icons.get` (website icons, builds with `icons`), `logins.search` (vault search from the popup, with `logins.copy` and `logins.fill_cross`), `logins.similar` (similar sites for a page without logins), `logins.add_url` (after a cross fill, its page added to the login), `locked.list` (soft lock: `soft_locked` below), `unlock.inline` (`unlock.options`, `unlock.password`, `unlock.hello`: the extension's own unlock form), `unlock.hello_browser` (`unlock.hello` shows Windows Hello over the browser window without a Passyble window, and `unlock.cancel` exists; Windows desktop app only), `lock` (the popup's Lock button), `generate.username` and `generate.email` (with `generate.options`: the username and e-mail generator), `password.check` (local checks of a password about to be saved), `sites.suggest` (`sites.suggest` and `sites.name_for`: popular sites for the editors), `url_rules` (the editor's websites carry their rules: `url_rules` in `logins.get_for_edit` and `logins.update`, and `sites.rule_hint`), `sync.now` (the popup's Sync button, "Sync now in app mode"), `items.favorite` (`favorite` on the items of `logins.find`, `logins.search`, `logins.similar`, `cards.list` and `identities.list`), `notes.list` (`notes.list` and `notes.get`: the popup's secure notes), `notes.create` (the popup's New note), `notes.append` (the context menu's "Save selection to Passyble note"). `soft_locked`: `true` while the vault is locked but the agent kept its list (see "Soft lock"); missing in older builds. `update_required: true` only while the desktop app is read-only (below the minimum version; "Update required" below), absent otherwise. Desktop builds from before have no `features` and answer `invalid_params` "unknown method …" to new methods; the extension shows "Update Passyble to edit logins here." |
| `unlock` | `{ for? }` | brings up the unlock prompt (Windows Hello when it is on for the vault, else the master-password window), resolves `{ "locked": false }` after unlock, or error `cancelled`. `for` (also on `unlock.hello` and `unlock.password`): the id of the login whose fill waits for this unlock; with "Confirm each fill: Every time" the unlock is that one fill's verification (see "Per-fill verification"). Anything that isn't a string of 1 to 128 characters is ignored |
| `lock` | `{}` | `{ "locked": true }`: same as the app's tray **Lock**. Saves first, then locks softly or completely according to "Keep list visible when locked" (the `lock_state` event follows; it never forces "Lock completely"). Idempotent: when already locked it answers `{ "locked": true }` again, without a new event. If the vault file can't be written the edits go to a `-unsaved-` copy (below) and it still answers `{ "locked": true }`; error `internal` ("Passyble is locked, but your latest changes could not be saved: …") only when even that copy couldn't be written, so the edits are lost, though the vault is locked either way. Advertised as `lock` in `status.features`; older desktop apps answer "unknown method" (the extension shows "Update the Passyble desktop app") |
| `unlock.options` | `{}` | `{ "locked": bool, "password": true, "hello": bool }`: what the extension's own unlock form may offer. `hello`: Windows Hello can unlock the active vault right now (turned on and set up for it, available on this PC, and the vault's policy doesn't ask for the master password first, e.g. "every 7 days"); always `false` while unlocked. Not activity; never prompts |
| `unlock.password` | `{ password, for? }` | `{ "locked": false }`: unlocks the active vault with the master password typed into the extension's unlock form, exactly like the desktop app's own unlock form (Windows Hello policy bookkeeping and setup, a Passyble Server password changed on another device). Already unlocked: `{ "locked": false }` without checking. Answers as soon as the vault is open (only the key derivation takes time): the bookkeeping after it (the Windows Hello file, a Windows Hello set-up with its own prompt, the vault list's last-opened time, a toast) runs afterwards on a thread of its own. Errors: `wrong_password`, `rate_limited` (more than 5 attempts a minute, right or wrong), `invalid_params` (missing, empty or over 1024 characters), `internal` (the desktop app's sentence). The password is used once and never logged or kept, by the agent or the extension |
| `unlock.hello` | `{ for? }` | `{ "locked": false }`: Windows Hello for the active vault, answered the moment Windows Hello confirms and the vault is open (the vault list's last-opened time is written afterwards). With `unlock.hello_browser` the desktop app opens no window of its own: Windows' Hello dialog shows over the browser window that sent the request (the foreground window, if its process started the native messaging host; otherwise without an owner) and is pushed to the foreground. One Hello prompt at a time; a request waits for the one before. If no Hello dialog shows up within 10 s the operation is cancelled and the answer is `not_supported` ("Windows Hello didn't open. Enter your master password instead."). Desktop apps without `unlock.hello_browser` (and calls that don't come from the browser) show the unlock prompt window with Windows Hello over it, pushed to the foreground over the browser (as for `unlock`); its "Use master password instead" answers `not_supported`. Errors: `cancelled` (cancelled in Hello's dialog, or by `unlock.cancel`), `not_supported` (Hello off or not set up for this vault, the master password is due, or no Hello dialog: the message says why; the extension then offers the password form), `internal` (Hello failed: the message says why) |
| `unlock.cancel` | `{}` | `{ "cancelled": bool }`: the user chose the master password while `unlock.hello` was pending (the extension's "Use master password instead"). Cancels that Windows Hello operation (and any `unlock.hello` still waiting for its turn), which then answers `cancelled`; `cancelled: false` when none was pending. Windows may leave a dialog that was already up on screen until the user closes it. Answers at once; not activity, never prompts. Only with `unlock.hello_browser`; older desktop apps answer "unknown method" |
| `logins.find` | `{ url }` | `{ "items": [ { "id", "title", "username", "has_totp", "has_passkey", "favorite" } ], "pending_otp": { "id", "title", "skips_2fa" } \| null, "locked": bool }` (`skips_2fa`: see `otp.outcome`). Items in suggestion order: the same host first, then other subdomains of the site (a stored path the page matches doesn't rank higher, so an imported login saved with its sign-in page's path can't hide the most used one); within each, favorites, then the most used (ARCHITECTURE.md §13), then by title. Soft-locked: the same items from the kept list, `locked: true`, `pending_otp: null`; fully locked: error `locked`. Doesn't count as activity for auto-lock (the extension sends it on every page with a login form), nor does `status`; see **Activity** below |
| `logins.fill` | `{ url, id }` | `{ "username", "password", "totp": { "code", "period", "remaining_secs" } \| null, "skips_2fa": bool }` and starts a 3-minute pending-OTP window for that registrable domain (and, with a `totp`, an `otp.outcome` attempt). Counts as a use of the login (`Vault::record_use`, no sync), as do `logins.fill_cross`, `logins.copy` of a password or code and `passkey.get`. The use is written to the vault file about 2 s later on a thread of its own (`Agent::save_soon`, `USE_SAVE_DELAY`; a lock writes it at once), so the answer never waits for the disk. `skips_2fa`: see `otp.outcome` (always `false` without a `totp`) |
| `totp.get` | `{ url, id? }` | `{ "id", "title", "code", "period", "remaining_secs" }`. With no `id`, the pending-OTP item for the URL is used. Error `not_found` if there is none. With an `id` (a code the user picked: copied from the popup, chosen in the menu) it counts as a use of the login (ARCHITECTURE.md §13); the pending code belongs to the fill that counted already |
| `totp.popup` | `{ url, id }` | `{}`; the desktop app shows its TOTP popup (Windows fallback) |
| `otp.outcome` | `{ url, outcome }` | `{ "recorded": bool, "skips_2fa": bool }`. How the 2FA step went after the last `logins.fill` of a login with a 2FA secret on that registrable domain: `"asked"` (the 2FA step showed up), `"skipped"` (signed in without it) or `"used"` (the code was filled or copied). Each fill opens one attempt for 5 minutes, which keeps its strongest outcome (`used` > `asked` > `skipped`; a code field that appears after a "skipped" still counts); outcomes without an open attempt are not recorded (`recorded: false`). The agent keeps the last 5 outcomes per site and answers `skips_2fa: true` when the last two were `skipped`, also in `logins.find`'s `pending_otp` and in `logins.fill`. Kept in memory and in `%LOCALAPPDATA%\Pass\otp-history.json` (device-local, never synced; at most 500 sites): keys are the hex SHA-256 of the registrable domain (with a fixed prefix), values only outcome letters and a time; no URLs, item ids or codes. Works while locked; not activity for auto-lock. Errors: `invalid_params` (another `outcome`). Older desktop apps answer "unknown method", which the extension ignores |
| `logins.save_check` | `{ url, username, password, kind?, filled_id?, ignore_id?, canonical_url? }` | What the save banner should offer after a form submit, decided by comparing with the site's saved logins in the agent (stored passwords never go to the browser): `{ "action": "none" \| "update_password" \| "update_username" \| "save_new", "id"?, "title"? }`. Rules, in order: the password of `filled_id` (the login Passyble just filled on that tab, if it is one of this site's) or a login saved **as is** → `none` (no banner); the same username (trimmed, case-insensitive; user names and e-mail addresses alike) → `update_password`; `kind: "change"` (password change form) → `update_password` for `filled_id` or the host's only login (`none` if that login has this password already); another username but the password of **exactly one** login → `update_username`; otherwise `save_new`, with `lookalike: { "domain", "host", "reason" }` (as in `logins.search`) when the page looks like the site of a saved login without being it (`Vault::lookalike_for_save`), so the banner warns. **Only a login of the page's own host is ever updated** (`Vault::find_for_save`): the host compared case-insensitively, `www.` the same as the bare domain (`www.example.com` = `example.com`), ports and paths ignored. A login saved for another subdomain of the site (`example.com` on `app.example.com`, `app.example.com` on `example.com`, `a.example.com` on `b.example.com`) is never offered for `update_password` or `update_username`, also not as `filled_id` or the only login of a change form: the answer is `save_new`, a login for this subdomain. It is still filled there (`logins.find`), and the same username and password saved for another subdomain still count as saved as is (`none`). **Canonical host** (`canonical_url`, browser extension only): the page's `<link rel="canonical" href>` as the extension read it. When it names another host of the page's own site, the two hosts are one for saving: the logins of either may be updated (the page's host first). The agent checks this itself and never takes the extension's word for it (pass-core `canonical_save_origin`): the page and the link must both be `https`, both hosts domain names (no IP addresses) of the same registrable domain by the Public Suffix List (`app.example.com` and `example.com` yes; `evil.com` claiming `bank.com` no; `alice.github.io` and `bob.github.io` no, `github.io` being a public suffix), and another host than the page's (`www.` or not); anything else is ignored as if absent. Android never has a canonical host: autofill gets only the page's web domain, not its markup, so there the page's own host is the only one. Saved as is: a login of the site (the logins `logins.find` lists: any path, `www.` and other subdomains of the registrable domain, `http` and `https`, and for a plain-`http` page also the logins saved for its `https` address, which are never filled there) with the same username and the same password; without a username (a password-only page, the second step of an identifier-first sign-in whose first step wasn't captured), any login of the site with this password, except on a change form with a login to change. Passwords are compared exactly (no trimming, case counts) and in constant time. Logins in the trash don't count (`save_new`: a new login is offered and the trashed one stays restorable until the trash is emptied). Locked (soft or full): `locked`; the extension then decides as described under "Extension notes" (the save banner). `ignore_id`: a login left out of the comparison (the extension's auto-saved draft of a password it generated on that page, which would otherwise always answer `none`). Doesn't count as activity; `rate_limited` after 30 a minute. Older desktop apps: "unknown method", and the extension falls back to "same username → update, else save" from `logins.find` |
| `logins.save` | `{ url, username, password, id?, update?, canonical_url? }` | `{ "id", "unchanged"? }` (updates the password if `id` is given or a login of the page's host (`Vault::find_for_save`) with the same username exists; an `id` of another subdomain's login is ignored and a new login is saved for this host, never that login's password or username changed; with an accepted `canonical_url` (as in `logins.save_check`) a login of the canonical host is updated too and gets the page's origin added to its websites, and a new login is saved with both origins, the canonical one first, so both hosts share it; a login saved as is, by the rules of `logins.save_check`, writes nothing and answers `unchanged: true`, so a banner shown while locked or a second Save never adds a duplicate). `update: "username"` with `id` (the banner's "Update username?") sets that login's username and keeps its password. An updated password isn't dropped: the old one goes to the login's `password_history` (`Vault::upsert`, as for every edit), and the login as it was before is kept in memory like a deleted one, so `logins.restore` from a page of the same site undoes the update within the same window (the extension's Undo on "Password updated in Passyble" after it saved a password it generated). If the vault file can't be written (a sync client or antivirus holds it), the call fails and the edit stays in memory: the next save retries it, and if the vault locks first the edits go to `<vault>-unsaved-<ms>.vault` beside the file, which the next unlock merges in like a conflict copy |
| `password.check` | `{ password, username?, url?, id?, title? }` | `{ "score": 0-4, "label": "very_weak" \| "weak" \| "fair" \| "good" \| "strong" \| "", "entropy_bits", "issues": [ { "code", "severity": "high" \| "medium" \| "low", "count"?, "name"?, "min_length"? } ], "vault_checked": bool }`: what is wrong with a password the extension is about to save (the save banner, the popup's editor), from pass-core `password_issues` (§1). Codes: `common`, `weak`, `reused` (`count`: other live logins with this password; login `id`, the one being updated or edited, doesn't count), `used_before` (login `id` had it before), `contains_username`, `contains_site` (`name`: the part found), `short` (`min_length`: 12); most important first, none when all is well. `url` is the page (the extension takes it from the browser). Everything is checked in the agent, on this PC: nothing goes online, and the password is not kept, logged or cached. Locked or soft-locked: only the password itself (`vault_checked: false`), no unlock prompt. Not activity for auto-lock. Errors: `invalid_params` (missing password, a value too long: password 4096, username 512, url 2048, title 256, id 128), `rate_limited` (more than 120 a minute). Advertised as `password.check`; older desktop apps answer "unknown method" and the extension shows nothing |
| `generate` | `{ length?, symbols? }` | `{ "password" }`. `symbols: false`: letters and digits only (upper, lower and digits, no special characters, the same length; the extension's and Android's "Letters and numbers only" for sites that reject symbols). Older agents ignore it and add symbols: the extension then generates the password itself |
| `generate.copy` | `{ password }` | `{ "copied": true }`: Copy beside a password just generated in a page (the extension's callout under the field). The desktop app copies it to the clipboard as a secret (`Ui::copy_to_clipboard`: cleared after 45 s, kept out of clipboard history and the cloud clipboard). Only a password `generate` returned in the last 10 minutes (the last 16; the agent keeps their SHA-256, never the passwords), so this writes nothing else to the clipboard: `not_found` otherwise, also for a password the extension generated itself because the agent was slow or missing. It isn't in the vault, so it works while locked, without verification, and counts as no use of a login. `not_supported`: a UI without a clipboard. `rate_limited` after 30 a minute. Older desktop apps answer "unknown method". For any of these errors the extension copies with the browser's clipboard API instead and clears that copy after 45 s |
| `generate.username` | `{ kind?: "words" \| "word_number" \| "characters", capitalize?, include_number?, separator?: "" \| "-" \| "_" \| ".", length?: 4..64 }` | `{ "username" }`: a random username (pass-core `generate_username`; defaults: words, capitalized, `-`, no number, so `Swift-Otter`). Local, works while locked. Errors: `invalid_params` (unknown kind, bad separator or length). Advertised as `generate.username` in `status.features` |
| `generate.options` | `{}` | `{ "plus": bool, "catch_all": bool, "aliases": [ { "id", "name", "default": bool } ] }`: what `generate.email` can offer (an address for plus addressing, a catch-all domain, the alias services set up in the desktop app's Settings, all kept in the vault). Never an address, a domain or a token. Error `locked` (also while soft-locked) |
| `generate.email` | `{ kind: "plus" \| "catch_all" \| "alias", url?, website?: bool, service? }` | `{ "email" }`. `plus` / `catch_all`: from the address or domain kept in the vault, with a random tag, or with `website: true` the name of `url`'s site (local). `alias`: a new alias at the user's alias service (`service`: an id from `generate.options`; missing: the default), over the network (up to about a minute: the extension waits 90 s); with `website: true` the host of `url` goes to the service as the alias's note or label, which the extension sends only when the user ticked "Mention this website" (off by default). DuckDuckGo never gets the site. Errors: `locked`, `not_found` (that address or service isn't set up), `invalid_params` and `internal` (the core's sentence, e.g. "SimpleLogin didn't accept the API token: check it in Settings"), `rate_limited` (more than 10 aliases a minute), `not_supported` (a build without network). Advertised as `generate.email` |
| `passkey.create` | see below | see below |
| `passkey.get` | see below | see below |
| `passkey.find` | `{ origin, rpId?, allowCredentials?: [ { id } ] }` | `{ "rp_id", "items": [ { "id", "title", "user_name", "user_display_name", "credential_id" } ], "locked": bool }`: the passkeys for a page's pending passkey request, one entry per passkey (`id`: its login; `credential_id`: b64url, public), most used first, so the extension can offer them on its own ("Sign in with your passkey?"). `origin` and the RP ID follow the rules of `passkey.get` (**Origin** below; `url_mismatch` otherwise) and `allowCredentials` narrows the list the same way (`invalid_params` for an id that isn't b64url). Names and titles only, never a key or user handle. Soft-locked: the same list from the kept summaries (`PasskeySummary`), `locked: true` (signing in unlocks first); fully locked: error `locked`. A background method: never a prompt, never activity. Older desktop apps answer "unknown method" (the extension then offers nothing on its own) |
| `passkey.create_options` | `{ origin, rpId?, userName?, excludeCredentials?: [ { id } ] }` | `{ "rp_id", "locked": bool, "excluded": bool, "candidates": [ { "id", "title", "username" } ], "suggested": id \| null, "vault": name \| null }`: what the extension's own "Save a passkey for <site> in Passyble?" card offers for a page's `create()`, so the desktop app's consent window isn't needed. `candidates`: the site's logins the passkey can be kept with (the consent window's list: logins of `https://<rp_id>`); `suggested`: the one whose username is `userName` (case-insensitive), else `null` ("New login"); `excluded`: a credential of `excludeCredentials` is already in the vault for that RP ID (the extension then fails the request with `InvalidStateError` at once, as `passkey.create` would); `vault`: the open vault's name when the desktop app has several vaults (`Ui::vault_name`), else `null`. The RP ID rules of `passkey.create` (`url_mismatch`), `invalid_params` for an id that isn't b64url. Soft-locked: from the kept summaries, `locked: true` (saving unlocks first); fully locked: error `locked`. Titles and usernames only; a background method: never a prompt, never activity. Older desktop apps answer "unknown method" (the extension then sends `passkey.create` as before and the desktop app asks in its window) |
| `server.pair` | `{ link }` | `{ "shown": true, "host", "user", "sign_in": bool }` (plus `"address": true` for an address). `link` is a `pass+server://` link (§3.1) **or a plain Passyble Server address** (`pass.example.com`, `host:8443`, `https://host[:port][/prefix]`; normalized like pass-core's `normalize_server_url`: no scheme means `https://`, trailing `/` dropped, credentials, query, fragment and spaces refused). A device pairing link opens the desktop app's "Connect to Passyble Server" dialog prefilled; a sign-in link without a token (`sign_in: true`, from `pass-server invite`) or a plain address (`sign_in: true`, `user: null`, `address: true`) opens "Sign in to Passyble Server" with the address filled in, where the desktop app handles a self-signed certificate (trust on first use, §3.2). Nothing is saved until the user confirms there. Works while locked; returns once the dialog is up, not when the user finishes. Errors: `invalid_params` (neither a valid link nor a valid address, or over 4096 characters; desktop builds from before addresses were accepted answer `invalid_params` to an address, which the extension shows as "update Passyble, or paste the link"), `not_supported` (a Passyble build without the dialog) |

**Conflict copies.** When the vault file sits in a cloud folder, the agent merges in and deletes the copies a sync client
leaves beside it, at the next unlock, but only files it recognises (`is_conflict_copy` in `Core/agent/src/agent.rs`),
for a vault file `<stem>.vault`: its own `<stem>-unsaved-<ms>.vault` stashes; OneDrive's `<stem>-<COMPUTERNAME>.vault` and
`<stem>-<COMPUTERNAME>-<n>.vault` (upper-case letters and digits with at least one letter, so `pass-backup.vault` and
`pass-2024-01-01.vault` are not one); Dropbox's `<stem> (<name>'s conflicted copy <date>).vault` (also with a trailing
` (<n>)`); Syncthing's `<stem>.sync-conflict-<YYYYMMDD>-<HHMMSS>-<ID>.vault`; Google Drive's `<stem> (<n>).vault`. Anything
else (a manual `pass-backup.vault`, `pass (old).vault`) is the user's file and is never read, merged or removed. A
recognised file is removed only after it merged (`merge_remote` accepted it as a copy of this vault).

**Soft lock.** Every automatic lock (timeout, Win+L, sleep) and every plain "Lock" drop the vault key and every secret but keep a
list of the items without secrets in the agent's memory (`pass_core::ItemSummary`, built from the vault right
before it goes), while the desktop app's "Keep list visible when locked" is on (the default; off, every lock is
a full lock). "Lock completely" (the only user action meant to hide the list), another vault, removing the
vault, sign-out and quitting drop the list from memory too; quitting, restarting, updating and another vault
keep its copy on disk, so they come back soft-locked. The agent also keeps the list on disk, sealed with DPAPI for the Windows user (ARCHITECTURE.md
§12, "Kept across restarts"), so after the app starts it is soft-locked with that list before the first unlock
and the extension lists the logins at once; "Lock completely", removing the vault, sign-out and turning the
setting off delete that copy. While soft-locked `status` answers `locked: true, soft_locked: true`
and the `lock_state` event carries `soft: true`; these answer from the list, with `locked: true`, without asking
to unlock and without counting as activity: `logins.find`, `logins.search`, `logins.similar`, `icons.get`, `app.show_item` (the
app shows the item with its secrets hidden) and `logins.copy` with `field: "username"` (same page / search-hit
rules as unlocked). Everything that needs a secret or changes the vault (`logins.fill`, `logins.fill_cross`,
`totp.get`, `totp.popup`, `logins.copy` of a password or code, `logins.get_for_edit`, `logins.update` / `create`
/ `delete` / `restore`, `logins.save`, `logins.save_check`, `totp.set`, `passkey.create` / `passkey.get`) answers
`locked`; the extension then unlocks (its own unlock form with desktop apps that have `unlock.inline`, see
"Unlocking from the extension"; otherwise `unlock`, the app's Windows Hello / master-password prompt) and repeats
the request once, so the user's click completes after the unlock. Search hits survive a soft lock (they are ids
from the list), so a copy started from a search works after unlocking for it; a full lock forgets them.
Pending OTPs, edit grants and undo copies are dropped on any lock. Older extensions treat the soft-locked
`logins.find` answer like an unlocked one and hit `locked` on fill, which their unlock-and-retry already handles.

**Unlocking from the extension** (`status.features` contains `unlock.inline`). The popup shows its own
unlock form while Passyble is locked: a master-password field (`type="password"`, `autocomplete="off"`: it is
Passyble's own master password, not a site's), Unlock, "Use Windows Hello" when `unlock.options` says `hello`,
and "Open Passyble" (the desktop app's own prompt, `unlock`) as the fallback. With `unlock.hello_browser` Windows Hello
is asked within the browser: `unlock.hello` makes Windows' Hello dialog appear over the browser window, and no
Passyble window opens. Unlocking takes one action: the extension starts Windows Hello by itself (when
`unlock.options` offers `hello`) as soon as the user picks a login while soft-locked, opens the in-page menu on a
fully locked vault with their own click, tap or key (the field, the Passyble icon, ArrowDown, the browser's shortcut
or context menu; never a menu that opened on its own or for the page), or opens the popup on a locked vault, and
offers "Use master password instead" beside it, which sends `unlock.cancel` and shows its own master-password form
(in the popup the field is right there; typing into it calls Hello off). Cancel in Hello's dialog (`cancelled`) and
a dialog that never showed up (`not_supported`) also lead to the password form. The background runs one
`unlock.hello` at a time and lets the menu and the popup join the one in progress; after a `cancelled`,
`not_supported` or `unlock.cancel` it doesn't start Windows Hello by itself for 30 s (it stays one click away), so a
popup that Hello closed doesn't start it again when the user reopens it to type the password. A fill, copy or edit that meets
a locked vault (popup requests carry `inline: true`, so the background answers `locked` instead of calling
`unlock`) shows the form and runs again once unlocked. Windows Hello takes the focus, which closes the browser's
popup, so a fill the popup was unlocking for is finished by the background. The in-page menu never takes the
master password into the page itself (the page could read it): picking a login from a soft-locked list starts
Windows Hello as above, or, when Hello isn't offered (and after Cancel), shows the unlock choices inside the menu;
a fully locked vault, once unlocked from the menu, lists the site's logins with the first one preselected. The
choices: a master-password field
that is an extension page in an iframe (`src/unlock/frame.html`, another origin, so the page can't read it), "Unlock
with Windows Hello" (when offered) and "Open Passyble". Where that frame can't load within 3 s or the page covers
the menu, "Enter master password" takes its place: the extension's popup with the form first
(`action.openPopup`, or where that isn't allowed, Firefox for one, a small window of the same page in unlock-only
mode). The picked login fills once Passyble is unlocked, however that happened (the background tells the tab's frames
`lock_state` at once; the agent's `lock_state` event follows), and at once: the fill is the next request, with no
timer, re-check or `unlock` call before it, and a fully locked vault's logins show the same way. Not running: the usual "Passyble isn't running"
view. Desktop apps without `unlock.inline` keep the old behaviour (their prompt, then the retry).

**Nothing asks for Windows Hello on its own.** Windows Hello (and any unlock prompt) only follows something the
user just did. The requests the extension sends by itself (at browser start too: restored tabs reloading, a field
the page focuses, the toolbar badge, the save banner's checks, password checks, icons, 2FA outcome reports, the
pending 2FA code) never call the desktop app's unlock or verification hooks: locked, they answer `locked` (the
background methods above, and `totp.get` without `id`; covered by `requests_the_extension_sends_on_its_own_never_prompt`
in Core/agent/tests/protocol.rs). The extension sends `unlock` / `unlock.hello`, or retries after `unlock`, only
for a user action: a pick or a menu the user opened (a trusted click, tap or key within 5 s), the popup the user
opened (not popup.html loaded as a tab, e.g. restored at browser start), a fill, copy, save or edit the user asked
for. Not for the 2FA toast's next code or a late code offered as the page loads (`totp.get` with
`automatic: true`: `locked` back, and a lock closes the toast), and not for a page's passkey request nobody started:
the isolated-world bridge reads the frame's user activation (`navigator.userActivation`, transient or sticky; the
page can't fake it) and passes `userActivated`; without it a locked vault gets `locked` back and no prompt. That
direct path is only for a request no content script took (see "Extension notes"): a page's own `get()` /
`create()` gets the extension's card in the page first, also locked and also without user activation (a sign-in
page restored at browser start that asks for a passkey as it loads: "Sign in with a Passyble passkey?" with
**Unlock**, which unlocks only on the user's click there). Conditional
mediation sends only `passkey.find` (names, no prompt) until the user picks a passkey in the Passyble menu or the
extension's passkey card, and a page's own `get()` / `create()` only `passkey.find` / `passkey.create_options` until
the user decides in the extension's card in the page (its "Unlock and sign in" / "Unlock and save" unlocks there,
Windows Hello or the master password frame, never the desktop app's unlock window). The desktop app's own window starts
Windows Hello only when the user opened it (Core/desktop-app/README.md, "Windows Hello unlock"); a start with Windows
(`--background`), Windows sign-in and resume from sleep never do.

**Activity.** The auto-lock ("Auto-lock" in the desktop app's settings) runs from the last *use* of the unlocked
vault and is sliding: each use starts it again at the full time the user chose, never more (uses don't add up),
so someone using Passyble isn't locked out mid-use and an idle Passyble still locks on time (`Agent::tick`,
`auto_lock_due`). What counts:

* **Never** (the background methods, `pass_agent::BACKGROUND_METHODS`, sent by the extension on its own: page
  loads, field focus, the toolbar badge, the save banner, menus opening): `status`, `logins.find`,
  `logins.similar`, `logins.save_check`, `password.check`, `icons.get`, `otp.outcome`, `cards.list`, `cards.save_check`,
  `identities.list`, `notes.list`, `generate`, `generate.options`, `unlock.options`, `unlock.cancel`, `passkey.find`,
  `passkey.create_options`, `vaults.list`, `account.status`, and the sign-in handoff's `account.peer`,
  `account.handoff_to_extension`, `account.handoff_begin`, `account.handoff_finish`, `account.sign_out`,
  `account.peer_signed_out`. Nor the desktop app's sync, health and live password
  checks, the setup checklist, a window reloading after a sync, and codes the TOTP popup or the merge view show
  again each period.
* **Once it succeeds**: every other method. A request refused (`cancelled`: Windows Hello or a prompt declined),
  failed (`url_mismatch`, `not_found`, `locked`, ...) or rate limited leaves the timer where it was. While such a
  request is in progress the auto-lock waits for it (at most 5 minutes past the timeout; prompts give up after
  2), so a fill isn't cut off by a lock while its Windows Hello dialog is up; declined after the timeout, the
  vault locks at the next tick.
* **Credential use** (`Agent::note_use`, also part of `Agent::record_use`): a successful `logins.fill`,
  `logins.fill_cross`, `logins.copy` (username too), `totp.get` (the pending code too), `cards.fill`,
  `identities.fill`, `passkey.get`, and in the desktop app auto-type, the TOTP popup's Copy / Type, a copy in
  the main window and a Windows passkey sign-in. Besides the auto-lock, this starts the per-fill grace period
  again (`Ui::credential_used`, below). Searching the soft lock's kept list, or a username copied from it, is
  nothing (no vault is unlocked).

The "Ask for master password every N days" interval is a policy, not a timer of use: it never slides.

**Per-fill verification.** When the vault's "Require Windows Hello before each fill" policy is on (desktop app,
Settings → Unlock), `logins.fill`, `passkey.create`, `passkey.get`, and `totp.get` / `totp.popup` for a
login other than the one just filled on that site (the pending OTP) first ask for Windows Hello
(`Ui::verify_user`). Declining returns `cancelled`. No new methods or fields; `logins.find` and `status` are
never gated. For a request from the browser the desktop app shows Windows' Hello dialog over the browser window
that asked, without its prompt window (no dialog within 10 s counts as declined); its own fills (auto-type) and
the Windows passkey provider keep the "verify" prompt window with Hello over it. For passkeys the answer also decides the WebAuthn **UV flag** (below).
The grace period ("After confirming", 0, 1 or 5 minutes; up to 60 in settings.json) is sliding too: each
credential use while it runs (see **Activity**) starts it again from that use, so it ends that many minutes after
the last fill, never later; once it has run out the next fill asks, and a use doesn't bring it back
(`FillGate::used`). "Every time" (0) asks for every login fill (below). Locking forgets it.
An unlock is a verification: Windows Hello or the master password, from the extension's unlock form, the in-page
menu, the prompt window or the main window. The desktop app counts it as the vault opens (`Ui::notify_lock_state`,
before the `lock_state` event and the unlock's answer go out), so the fill the extension sends right after it (the
login picked while locked) never asks for Windows Hello again: within the grace period like any verification
(whoever asked for the unlock), and with "Every time" only the fill the unlock was asked for, once, within 30 s
(`FillGate`'s unlock credit, `UNLOCK_CREDIT`). The extension names that login with `for` on `unlock`,
`unlock.hello` or `unlock.password` (`Agent::unlock_requested_for`, read as the vault opens); an unlock in the main
window, or one the browser asked for nothing in particular, lets no login fill through with "Every time".

**"Every time" and 2FA codes.** The agent checks a login's password and 2FA codes with `Ui::verify_item` (the item
id, and `ItemSecret::Password` or `Code { follows_fill }`, `follows_fill` meaning the pending OTP of that site). With
"Every time" every `logins.fill` / `logins.fill_cross` asks (the one-step unlock above excepted), a second fill of
the same login too. The only thing that doesn't ask is a 2FA code (`totp.get`, `totp.popup`) of the login whose fill
was just confirmed, within `OTP_AFTER_FILL` (2 minutes) of that fill, as often as needed (a wrong code picked
again); another login's code asks, and so does the code after the 2 minutes. Without "Every time" a pending code
goes through without asking, as before. Copying a password or code to the clipboard (`logins.copy`) keeps its rule:
it asks under the per-fill policy as before, and the unlock moments ago counts for it once, whoever asked for the
unlock. The popup's password copy (`popup.copy`) is a `logins.fill`, so it follows the fill rule. A passkey
sign-in (`passkey.get`, `ItemSecret::Passkey`) asks every time too; the unlock moments ago counts for it once when
it was asked for that login (a passkey picked while locked: `for` its login) or for no login in particular (a
page's passkey request on a locked vault, which can't know the login before the unlock), never when it was asked
for another login's fill. It is no password fill: no 2FA code follows it without asking.

**Saving without holding requests up.** A save writes the vault file while holding only the agent's file lock: the
agent's state is held just to encrypt the vault, so a sync's save (one starts right after every unlock), the app's
periodic save or an edit never makes a fill, `logins.find` or `status` wait for the disk (a sync client or
antivirus holding the file can make a write take a second). A change on disk during that write is the write itself
and is not read back.

**Editing from the popup** (`status.features` contains `edit`). Only the extension's own pages call these
(`popup.*` handlers in the background; content scripts can't), and `url` is always the active tab's URL as the
browser reports it (`tabs.get`). Like fills, a login can only be read or changed from a page it belongs to
(`url_mismatch` otherwise, `not_found` for an unknown id). The vault must be unlocked (`locked`; the extension
unlocks and retries). The first two rows release or change secrets and ask `Ui::verify_user` (per-fill
policy); opening a login in the editor (`logins.get_for_edit`) covers saving, deleting and 2FA changes of that
login for 10 minutes. Edits share a limit of 30 a minute, QR scans 10 a minute (`rate_limited`). After every
change the agent saves the vault and calls `Ui::vault_changed` (the desktop app emits `vault-changed`).

| method | params | result |
|---|---|---|
| `logins.get_for_edit` | `{ url, id }` (`item_id` accepted) | `{ "id", "title", "username", "password", "notes", "urls": [websites], "url_rules": [{ "url", "rule" }] (`status.features` contains `url_rules`; only websites whose rule isn't `subdomains`), "totp": { "issuer", "account", "digits", "period", "algorithm", "code", "remaining_secs" } \| null, "has_passkey" }`. The 2FA **secret** never leaves the vault. `urls` lists the websites (`http(s)://…` and bare hosts); other entries (`windows:<exe>` for auto-type) are not shown and are kept on update |
| `logins.update` | `{ url, id, fields }` | changes the given `fields` (others kept): `title` (≤ 256), `username` (≤ 512), `password` (≤ 4096), `notes` (≤ 20000 characters, pass-core's `check_notes_length`: a login whose stored notes are already longer saves them unchanged or shorter), `urls` (≤ 32, each an http(s) address ≤ 2048, no credentials; no scheme means `https://`; a bare origin is stored without `/`), `totp` (`otpauth://totp/…` or base32 secret of at least 80 bits, stored upper-case without spaces; `null` or `""` removes it), `url_rules` (with `url_rules` in `status.features`: `[{ "url", "rule": "subdomains" \| "host" \| "never" }]`, each `url` a website as sent in `urls`, stored the same way; replaces the rules of every website, those of entries the editor doesn't show are kept; without it each website kept keeps its rule). Single-line fields refuse control characters; unknown fields are `invalid_params` (an older agent refuses `url_rules`, so the extension sends it only when advertised). Result: `{ "id", "title", "username", "has_totp", "has_passkey" }` |
| `sites.rule_hint` | `{ url }` | `{ "suggested": "host" \| null }`: the rule the editor suggests in a website's menu, `"host"` for a site on a shared hosting platform (`alice.github.io`, `shop.web.app`: a private-section suffix of the Public Suffix List, pass-core `url_suggests_host_only`). Only a suggestion: the rule stays as the user set it. Needs no vault |
| `sites.suggest` | `{ query, limit? }` | `{ "sites": [{ "name", "domain" }] }`: popular sites for a name or website being typed in an editor (`status.features` contains `sites.suggest`), best match first, at most `limit` (default 8, capped at 50). A name finds its website (`netf`: Netflix, `netflix.com`; other names too: `gmail` gives `{ "name": "Gmail", "domain": "google.com" }`), case, accents and punctuation ignored; a website finds its name (`amazon.de`: Amazon, `amazon.de`). `query` ≤ 256 bytes (`invalid_params`); empty: `[]`. From the list compiled into pass-core (`site_suggestions`): the query never leaves the device. Needs no unlocked vault |
| `sites.name_for` | `{ url }` | `{ "name": "GitHub" \| null }`: the popular site's name for a website typed in an editor (a URL or host; pass-core `site_for_domain`: its host, then parent domains down to the registrable domain, so `signin.aws.amazon.com` is `AWS`), `null` for a site not in the list, an IP address or a site on a shared hosting platform (`alice.github.io`). `url` ≤ 2048. Needs no unlocked vault |
| `logins.create` | `{ url, fields }` | a new login with those fields; `urls` defaults to the page's origin, `title` to its site (`github.com`). Same result |
| `logins.delete` | `{ url, id }` | deletes it (tombstone) and keeps a copy in memory for 60 s, dropped on lock: `{ "undo_secs": 60 }` |
| `logins.restore` | `{ url, id }` | Undo: writes that copy back (of a `logins.delete`, or the login as it was before a password update by `logins.save`), only from a page of the same site (registrable domain) it was deleted or saved on; `not_found` after the window. Same result as `logins.update` |
| `totp.set` | `{ url, id?, totp }` (`otpauth` / `secret` accepted) | with `id`: sets (or with `null` / `""` removes) that login's 2FA, result as `logins.update` plus `"totp": {…}` settings and code. Without `id`: only checks the value and returns its settings and current code (the editor's preview); nothing stored. `otpauth-migration:` (Google Authenticator export) is `invalid_params` ("Import it in the Passyble app") |
| `totp.from_image` | `{ url, id?, image }` (`png` accepted) | `image`: PNG or JPEG (base64url, ≤ 8 MiB) of the visible tab, captured by the background (`tabs.captureVisibleTab`). The agent reads its QR codes (pass-core `qr_decode_image`, feature `import-qr`) and takes the first `otpauth://totp/…`. With `id`: attached like `totp.set`. Without: `{ "totp": "<otpauth link>", "issuer", "account", "digits", "period", "algorithm", "code", "remaining_secs" }` for the editor to save (the link came from the page, not the vault). `not_found`: no (2FA) QR code; `not_supported`: a build without `import-qr` |
| `notes.create` | `{ fields: { title, notes? }, vault? }` | the popup's **New note** (`status.features` contains `notes.create`): a new secure note (kind `note`, no website, bound to no page) in `vault` (an id from a `vaults` table; default the vault a new login would go into). `title` is required (≤ 256, one line, trimmed), `notes` ≤ 20000 (line breaks and tabs kept, other control characters refused); unknown fields are `invalid_params`. Like `logins.save` it only adds, so it asks nothing (no `Ui::verify_user`). Counts against the edit limit. Result: `{ "id", "title", "kind": "note", "vault" }` |
| `notes.append` | `{ id, text }` | the context menu's **Save selection to Passyble note** (`status.features` contains `notes.append`): adds `text` as a new line at the end of secure note `id` (a live note of any open vault, as `notes.list` lists them); what the note holds is never replaced or reordered. `text` is trimmed and must not be empty, line breaks and tabs kept, other control characters refused; a note that already ends with a line break gets no blank line, an empty note gets no leading one. The note with the new line must stay within the notes cap (20000 characters, pass-core's `check_notes_length`, checked before anything is asked and again by `Vault::upsert`); otherwise nothing is added (`invalid_params` "Notes can be up to 20,000 characters.", or "the text is too long" for a text over the cap by itself). Unknown fields are `invalid_params`. A change to an item, so verified like `logins.update` (`Ui::verify_user` "Save changes to {title}", unless the item's edit was verified moments ago; declined: `cancelled`; the browser vault: `verification_required`); the note is read again after the prompt, so a change made meanwhile is kept. `not_found`: no such note (not a note, or in the trash); `read_only` in a vault the user can't change (also a fill-only member's note); `locked` while locked (also soft-locked). Counts against the edit limit and as a use of the note; `update_required` in read-only mode. Result: `{ "id", "title", "kind": "note", "vault" }`, never the text. Older agents answer "unknown method" |
| `items.move` | `{ id, vault }` | `{ "id", "title", "kind", "moved_from", "vault": VaultRef }`: the popup editor's "Vault": moves item `id` (any kind) into open vault `vault` (`Vault::move_item_to`): it gets a new `id` there and leaves the vault it was in for good (`moved_from` is the old id). Both vaults must be ones the user can edit (`read_only` otherwise, also for a fill-only member's item); the same vault is `invalid_params`, an item or vault that isn't open `not_found`. Moving into a shared vault shows the item to its members, so it is verified like an edit (`Ui::verify_user` "Save changes to <title>", unless the item's edit was verified already; `cancelled` if declined); the popup confirms such a move first. Counts against the edit limit; `locked`, `update_required` in read-only mode. Advertised as `items.move` in `status.features`; the browser vault's build doesn't (its shared vaults are opened by the extension) |
| `app.show_item` | `{ url, id }` | "Open in Passyble": `Ui::show_item` brings up the main window and emits `show-item` `{ id }` to it. `{ "shown": true }`, or `not_supported`. Also for a login of another site that a recent `logins.search` returned |

**Moving the browser's vault in** (`status.features` contains `items.import`; docs/EXTENSION_VAULT.md §2.6). When
the extension finds the Passyble app on a computer where it kept its own vault (browser mode), it switches to the
app and offers to move that vault's items in. The extension opens its vault with the master password the user typed
(or the Passyble password for a vault linked to an account), then sends the encrypted vault file and its vault key;
the agent opens the file in memory (never written anywhere) and adds its items. Like `logins.save` it only adds, so
it asks nothing (no `Ui::verify_user`). Refused in read-only mode; counts once against the edit limit.

| method | params | result |
|---|---|---|
| `items.import` | `{ file, key, vault? }` | `file`: the browser vault file (base64url, at most 6 MiB decoded), `key`: its vault key (base64url). Every live item goes into `vault` (an id from a `vaults` table; default the home vault) as a new item, with everything it has: the password, 2FA secret, passkeys, notes, custom fields, tags and password history; secure notes, cards and identities too. **Exact duplicates are skipped**: a login when a login here has the same site (a website host in common, `www.` and case ignored; both without a website: the same title), the same username (case-insensitive) and the same password, and the incoming one brings nothing that one lacks (another 2FA secret, a passkey, other notes); any other item when one of the same kind has the same content (ignoring id, times, favorite, tags and password history). Result: `{ "total", "added", "skipped", "failed_count", "failed": [ { "title", "kind", "message" } ] (at most 50), "vault": VaultRef }`. Errors: `wrong_password` (the key doesn't open the file), `invalid_params` (not a vault file, a shared vault's file, more than 20000 items, unknown fields), `not_found` (the vault isn't open), `read_only`, `locked`, `rate_limited`. The browser vault's own build doesn't advertise it |

**Favorites** (`status.features` contains `items.favorite`). The items of `logins.find`, `logins.search`,
`logins.similar`, `cards.list` (`{ "id", "title", "cardholder_name", "brand", "last4", "expiry_month", "expiry_year",
"favorite", "vault_id" }`) and `identities.list` (`{ "id", "title", "full_name", "email", "company", "favorite",
"vault_id" }`) carry `favorite`: the item is marked as a favorite (pass-core `ItemSummary::favorite`), so the popup's
Favorites filter can show them. Older agents leave it out (read as `false`), and the extension then offers no
Favorites filter.

**Secure notes** (`status.features` contains `notes.list`). The popup's Notes filter lists the vault's secure notes
(kind `note`) and opens one in a small viewer. A note belongs to no site and may hold recovery codes, so the list
has titles only (`query` matches titles, never the text) and the text leaves the vault only through `notes.get`,
which is checked like a copy of a password the popup's search found: the vault unlocked (soft-locked: `locked`, the
kept list has no text; the extension unlocks and asks again), never a fill-only member's note (`fill_only`), and
`Ui::verify_user` every time (`Reason::ShowNote`, "Show your {title} note", or `Reason::CopyNote`; the per-fill
policy decides whether it prompts; declined: `cancelled`; the browser vault: `verification_required`). `notes.list`
is a background method (no activity); a `notes.get` is a use of the note. Both work in read-only mode. Older desktop
apps answer "unknown method", and the extension shows no Notes filter without the feature.

| method | params | result |
|---|---|---|
| `notes.list` | `{ query?, limit? }` | `{ "items": [ { "id", "title", "favorite", "updated", "vault_id" } ], "truncated": bool, "locked": bool, "vaults": [ VaultRef ] }`. Every open vault's live notes (trash left out) in suggestion order: favorites, the most used, then by title. `updated`: when the note last changed (Unix milliseconds). `query`: words the title must hold, in any order, case ignored (at most 128 characters, else `invalid_params`; empty or missing: every note). `limit` default 100, clamped to 1-200; `truncated` when more matched. Never the text. Soft-locked: from the kept lists, `locked: true`; fully locked: `locked`. `rate_limited` after 120 a minute |
| `notes.get` | `{ id, copy? }` | `{ "id", "title", "notes", "favorite", "updated", "vault": VaultRef }`: the note's text, after the checks above. `copy: true`: the app copies the text itself (`Ui::copy_to_clipboard`: cleared after 45 s, kept out of clipboard history and the cloud clipboard) and answers `{ "copied": true }` without it (`{ "copied": false }` for a note without text; `not_supported` for a UI without a clipboard). `not_found`: no such note (or the item is not a note, or is in the trash). `rate_limited` after 30 a minute |

**Saving cards** (`status.features` contains `cards.save`). After a checkout form with a card number was
submitted on a secure page (`https://`, or `http://` on this device), the extension asks whether the card is saved
already and offers **Save card to Passyble?** or **Update card expiry?** (Extension/README.md, "Save cards"). As with
`logins.save_check`, the typed number is compared with the saved cards in the agent (digits only, in constant time,
every open vault, trash left out), so a saved number never goes to the browser; answers carry only the brand and
last four digits of the typed number and the saved card's title, expiry and vault. The security code is never
taken: a `security_code` sent along is ignored and nothing is stored for it (the user can type it into the card in
Passyble). Neither method asks the user anything (no `Ui::verify_user`: nothing leaves the vault). `cards.save_check`
is a background method; both are refused in read-only mode, and while locked (soft or fully) both answer `locked`
(the extension's **Save** unlocks first, then checks again).

| method | params | result |
|---|---|---|
| `cards.save_check` | `{ url, number, expiry_month?, expiry_year? }` | `{ "action": "none" \| "update_expiry" \| "save_new", "brand", "last4" }`. `number`: 12 to 19 digits passing the Luhn check (spaces and dashes allowed), else `invalid_params`; `expiry_month` 1-12, `expiry_year` two or four digits (`29` is 2029; either missing: no expiry). `none`: a card with this number has this expiry, or no expiry was typed, or the number is saved only in vaults the user can't edit (it fills from there); with `id`, `title`, `vault`, `saved_expiry_month`, `saved_expiry_year` of that card. `update_expiry`: the number is saved with another expiry (or none) in a vault where `can_edit`; the same fields, for that card. `save_new`: no card has this number; adds `vaults` (where a new card can go: `can_edit`, the home vault first) and `default_vault` (the home vault). Errors: `url_mismatch` (not a secure page), `invalid_params`, `locked`, `rate_limited` (30 a minute) |
| `cards.save` | `{ url, number, expiry_month?, expiry_year?, cardholder_name?, title?, id?, vault? }` | `{ "id", "title", "vault", "brand", "last4" }` plus `"updated": true` (an expiry was set) or `"unchanged": true` (saved as is, nothing written). With `id` (from `update_expiry`): that card's expiry is set, and its cardholder name when it has none; the card must have this `number` (else `not_found`) and be in a vault the user can edit (else `read_only`). Without `id` it is checked again as `cards.save_check` would answer, so a late second Save adds no duplicate: saved as is, `unchanged`; the number with another expiry in an editable vault, that card's expiry is updated; otherwise a new card goes into `vault` (default the home vault; `read_only`, `not_found` as for `logins.save`) with the number, expiry, cardholder name (one line, at most 256 characters) and `title` (one line, at most 256; empty: "Visa •••• 4242"), never a security code. Counts against the edit limit (30 a minute) |

**Website icons** (`status.features` contains `icons.get`). The popup's avatars show the site's icon instead of
the first letter. The agent only **reads** the desktop app's icon cache (pass-core `site_icon_cache_read`, §1; the
app sets the directory with `Agent::set_icon_cache_dir` while its "Show website icons" setting is on and fills it);
neither the agent nor the extension ever fetches an icon. Not counted as activity for auto-lock.

| method | params | result |
|---|---|---|
| `icons.get` | `{ url?, domains?, ids? }` | `{ "icons": { "<domain>": "data:image/png;base64,…" }, "items": { "<item id>": "<domain>" } }`. Only for the logins `logins.find` returns for `url`, or, with `ids` (at most 50, instead of `url`), for those of them that a recent `logins.search` returned (others silently skipped) (no enumeration of the cache, so it reveals nothing `logins.find` / `logins.search` don't). Neither `url` nor `ids`, or over 50 ids: `invalid_params`. each login's domain is `site_icon_domain` of its first URL that has one, at most 32 domains, optionally only those in `domains`. `icons` holds the domains with a cached icon (a PNG of at most 64 KB; all data URLs together at most 512 KB, under native messaging's 1 MB), `items` maps each of those logins to its domain; a login or domain without an icon is left out (show the letter). **Never prompts**: while locked, or with the setting off (no cache directory), the answer is `{ "icons": {}, "items": {} }`, not `locked`. `not_supported`: a build without `icons`; older desktop apps answer "unknown method" |

**Searching the vault from the popup** (`status.features` contains `logins.search`). The popup's search box finds
logins of any site; unlike every other method these reach logins that don't belong to the page, so each step is
bound to the one before. `logins.search` returns no secrets and remembers the ids it returned for 10 minutes (at
most 500, dropped on lock); only those can be copied from, cross-filled or named in `icons.get` `ids` /
`app.show_item`. The vault must be unlocked (`locked`); these count as activity.

| method | params | result |
|---|---|---|
| `logins.search` | `{ query, limit?, url? }` | `{ "items": [ { "id", "title", "username", "domain", "has_totp", "favorite", "vault_id", "lookalike"? } ], "truncated": bool, "vaults": [ VaultRef ] }`. `vault_id`: the vault the login is in (the home vault or a shared one; the search covers every open vault); `vaults`: one `VaultRef` for each vault that appears in the results, the home vault first (see "Vaults in answers"). `url`: the tab's page (http(s) only, anything else is ignored); a result whose site the page looks like without being it gets `lookalike: { "domain", "host", "reason" }` (pass-core `LookalikeCheck`, ARCHITECTURE.md §7 "Lookalike sites": `domain` the login's site, `host` the page's, `reason` one of `homograph`, `domain_in_subdomain`, `typo`, `domain_in_path`, `name_in_domain`), never when the page is a site of any login in the vault; the extension then warns before a fill or a copy of the password or code. Older agents ignore `url`. Logins (never notes) found by the core's fuzzy search (`summaries_search`: every word of `query` somewhere, typos allowed) over their title, username and websites (`http(s)://…` or bare-host URL entries; `windows:` entries and linked apps skipped). The best matches first, then favorites, the most used (ARCHITECTURE.md §13), then by title. `domain`: registrable domain (or host) of the first website, `""` if none. `query` must be 2–128 characters (`invalid_params`: no listing the vault with an empty or one-letter query); `limit` default 20, clamped to 1–50; `truncated` when more matched. Never a password, notes, URLs or 2FA secret. `rate_limited` after 120 a minute |
| `logins.copy` | `{ id, field, url? }` | `{ "copied": true, "field" }`: the desktop app copies `field` (`"username"`, `"password"` or `"totp"`, the current code; else `invalid_params`) to the clipboard as a secret (`Ui::copy_to_clipboard`: cleared after 45 s, kept out of clipboard history and the cloud clipboard). The value is never in the answer. `id` must be a recent search hit, or a login of `url` (`url_mismatch` otherwise, `not_found` for an unknown id). `password` and `totp` are verified first (declined → `cancelled`): for a login of `url` as its fill would be (`Ui::verify_item`: `Password`, or `Code` with `follows_fill` for the login just filled there, as `totp.get`), for a search hit of another site with `Ui::verify_user` (per-fill policy) every time; `username` isn't (the search showed it). The extension uses it for every copy of a secret it can (the popup's own logins with `own: true`, the OTP toast's `totp.copy`), so secrets go to the clipboard from the desktop app, out of clipboard history and the cloud clipboard, never through the browser's clipboard API. `not_found`: no password / no 2FA secret; `not_supported`: a UI without a clipboard. `rate_limited` after 30 a minute |
| `logins.fill_cross` | `{ url, id }` | `{ "username", "password", "totp": { "code", "period", "remaining_secs" } \| null, "skips_2fa", "cross": bool }`. `url`: the tab's http(s) page (`url_mismatch` otherwise). A login of that page: exactly `logins.fill` (pending OTP and all), `cross: false`, no extra prompt. Another site's login: must be a recent search hit (`url_mismatch`); the agent asks `Ui::confirm_cross_fill` ("Fill a login from another site?", the desktop app's `fill-cross` prompt, Cancel by default; `CrossFillRequest::lookalike` is set when the page looks like the login's site without being it, `Vault::lookalike_for_url`, and the prompt then says so in a red banner), then `Ui::verify_user`; `cross: true`, `skips_2fa: false`, and **no** pending OTP for the page. A cross fill's answer also has `title` and `domain` (the login's title and site), `lookalike` (as in `logins.search`) when the page looks like the login's site, and `add_url_token`: a one-time token (random, 32 characters) for `logins.add_url` of exactly this login and this page's origin, valid 10 minutes, dropped on lock. The extension keeps it in its background and never hands it to a page or content script. Errors: `cancelled` (declined), `not_supported` (a UI without the prompt), `not_found` (unknown id). `rate_limited` after 10 a minute |
| `logins.similar` | `{ url, limit? }` | `{ "items": [ { "id", "title", "username", "domain", "has_totp", "favorite", "vault_id", "reason" } ], "name": "amazon" \| null, "locked": bool, "vaults": [ VaultRef ] }`. For a page without logins of its own (the extension asks when `logins.find` found none): a few logins of other sites it may be, decided by pass-core `similar_logins` (ARCHITECTURE.md §7 "Similar sites"). `reason`: `same_name` (a website with the page's name, its registrable domain without the public suffix, under another suffix or subdomain: `amazon.de` for `amazon.co.uk`, `login.acme.io` for `acme.com`) or `title` (the title holds the name); those first, then favorites, the most used, then by title. Never a login of the page's own registrable domain, never another site under a shared public suffix (`bob.github.io` for `alice.github.io`), never a login whose site the page looks like (`LookalikeCheck`; lookalikes only show in `logins.search`, marked). `name`: the page's name, for the extension's "Search Passyble…" (`null` for a page that has none: an IP address, `localhost`). `url`: http(s) only (`url_mismatch`). `limit` default 3, clamped to 1–10. The results count as search hits (a copy or `logins.fill_cross`, with its prompt, may follow). No secrets. Soft-locked: from the kept list, `locked: true`. A background method (no activity); `rate_limited` after 60 a minute |
| `logins.add_url` | `{ id, url, token }` | `{ "added": bool, "id", "title", "vault": VaultRef }`. "Add <site> to this login" after a cross fill: the origin of `url` becomes a website of login `id` (no path; `added: false` when the login is one of that page's already). Only with the `add_url_token` of a `logins.fill_cross` of exactly that login into a page of that origin (scheme, host and port), within 10 minutes; one use, a token that doesn't match is used up as well, and a lock drops them all. No further prompt: the user said yes to the cross fill in the desktop app moments ago. From then on the login is the page's own (filled without the cross prompt). Errors: `locked`, `url_mismatch` (not a web page), `not_found` (no such fill or item), `read_only` (a vault this user may not change), `rate_limited` after 10 a minute |

`passkey.create` params (WebAuthn `PublicKeyCredentialCreationOptions`, binary fields b64url):

```jsonc
{ "origin": "https://example.com", "rp": { "id": "example.com", "name": "Example" },
  "user": { "id": "b64url", "name": "alice", "displayName": "Alice" },
  "challenge": "b64url", "pubKeyCredParams": [ { "type": "public-key", "alg": -7 } ],
  "excludeCredentials": [ { "id": "b64url" } ], "crossOrigin": false,
  "extensions": { "prf": { "eval": { "first": "b64url", "second": "b64url" } } } }
```
result:
```jsonc
{ "credentialId": "b64url", "clientDataJSON": "b64url", "attestationObject": "b64url",
  "authenticatorData": "b64url", "publicKey": "b64url(SPKI DER)", "publicKeyAlgorithm": -7,
  "transports": ["internal", "hybrid"],
  "clientExtensionResults": { "prf": { "enabled": true, "results": { "first": "b64url" } } } }
```

**WebAuthn PRF extension** (`extensions.prf`, WebAuthn JSON, optional; `status` lists the feature `passkey.prf`).
`passkey.create`: `prf: {}` or `prf: { eval }` answers `clientExtensionResults.prf = { "enabled": true }`, plus
`results` (`first`, `second` when given) when `eval` was given, as platform authenticators do; `evalByCredential`
is `not_supported` before any prompt (the extension then hands the request to the browser, which reports the
`NotSupportedError`). `passkey.get`: `eval`, `evalByCredential` (keys: b64url credential ids, each one of
`allowCredentials`, else `invalid_params`; non-empty without `allowCredentials`: `not_supported`) and `second`;
the entry of the chosen credential wins over `eval`; answers `prf: {}` or `prf: { "results": { "first", "second"? } }`.
A passkey from before PRF support gets `enabled: false` / no `results`. Without `extensions.prf` the result has
`clientExtensionResults: {}`. Older desktop apps ignore `extensions` and send no `clientExtensionResults` (the
extension then reports `prf: { enabled: false }` / `prf: {}`).
Errors: `cancelled` if the user declines (→ `NotAllowedError`), `invalid_state` if an excluded credential is
already in the vault (→ `InvalidStateError`), `not_supported` if ES256 isn't acceptable (→ fall back to the browser),
`url_mismatch` if the RP ID isn't valid for the origin or `origin` isn't an exact http(s) tuple origin (→ `SecurityError`).

`consent` (optional): `{ "itemId": id | null }` (`item_id` accepted) when the user already said yes in the extension's
own card in the page ("Save a passkey for <site> in Passyble?", a real click on Passyble's UI; the extension sends it
only from there). The agent then skips `Ui::confirm_passkey_create` (the desktop app's consent window) and keeps
the passkey with login `itemId`, which must be one of the site's logins (`passkey.create_options`' `candidates`;
another site's or an unknown item is `url_mismatch`, nothing is saved), or, with `null`, as the window's "Create a
new login" (the site's login with that username, else a new one). The excluded check, the per-fill check
(`Ui::verify_user`, `userVerification: "required"`: `Ui::require_verification`) and the UV flag are as without
it. Without `consent` (older extensions, the content script not running in that frame) the desktop app asks in its
window as before. After a save the agent calls `Ui::vault_changed`: open windows reload and the desktop app brings
the Windows passkey provider's list of passkeys up to date at once, so a passkey saved in the browser is also offered
to native apps through Windows.

**Origin.** For both passkey methods `origin` must be the serialised tuple origin of an `http` or `https` page
(`https://host[:port]`, nothing else: no path, credentials or default-port variants). An opaque origin (`"null"`,
a sandboxed frame), another scheme or a URL that isn't already in that form is `url_mismatch`, whatever the RP ID.
The RP ID rules of ARCHITECTURE.md §7 apply on top.

**UV flag.** `Ui::verify_user` answers `Verified` (the user just proved who they are: Windows Hello, or the master
password / Windows Hello unlock this very request asked for), `Allowed` (no per-fill policy, or within its grace
period) or `Refused` (→ `cancelled`). The authenticator data's UV flag is set only for `Verified`, in `passkey.create`
(also inside the attestation object) and in `passkey.get`; consent in the dialog alone is user presence (UP).
Per-fill verification therefore matters to relying parties that require `userVerification: "required"`.

`passkey.get` params: `{ "origin", "id"?, "credentialId"?, "rpId", "challenge", "allowCredentials": [ { "id" } ], "userVerification", "crossOrigin", "extensions"? }`
result: `{ "credentialId", "clientDataJSON", "authenticatorData", "signature", "userHandle", "clientExtensionResults" }`
(`extensions.prf`: see **WebAuthn PRF extension** above).
`id` (an item id) is set when the user already picked a login in the extension's inline menu or its passkey card
(a real click on Passyble's own UI): the choice is restricted to that login's passkeys, and `credentialId` (b64url,
from `passkey.find`) to that one passkey. When that leaves exactly one, the agent signs with it without its
"Sign in with a passkey" window (the pick was the choice); the per-fill check still applies (below). The extension
does this for a page's own `get()` too: its card in the page lists the passkeys (`passkey.find`) with **Use another
device** (the browser's own WebAuthn, without asking the agent) and Cancel, and sends `passkey.get` only for the
passkey picked there. Otherwise (an older extension, a frame where the content script doesn't run, nothing picked)
`Ui::choose_passkey_for_browser` asks in that window, which also offers
**Use another device**: the agent then answers `not_found` and the extension hands the request to the browser's
own WebAuthn (a phone, a security key, the browser's passkeys); Cancel is `cancelled` (`NotAllowedError`). Error
`not_found` when the vault holds no matching passkey (or none on that login). The extension then falls back to the
browser's native WebAuthn. The per-fill check is `Ui::verify_item` with `ItemSecret::Passkey` and the login of the
chosen passkey (`userVerification: "required"`: `Ui::require_verification`, as before).

### Linked vaults (Teams, Family, direct shares)

`status.features` contains `vaults` when the agent can hold shared vaults beside the user's own. Unlocking the
home vault (the personal vault the desktop app has open, the only one with a master password) also opens every
shared vault its Passyble account can open (the desktop app tells the agent which: Passyble Server `whoami`
`vaults[]`, Passyble Cloud's `POST /v1/cloud/devices` `shared[]`); locking locks them all, and a soft lock keeps
each one's list (ARCHITECTURE.md §15.14). Only the home vault's list is also kept on disk across a restart, so
right after a start the soft-locked lists show the home vault's logins only. Agents without the feature answer as
before and know nothing of shared vaults.

**Vaults in answers.** Every answer that lists items (`logins.find`, `logins.search`, `passkey.find`,
`passkey.create_options` candidates, `cards.list`, `identities.list`, `notes.list`) gives each item `vault_id`, and the answer a
`vaults` table: one `VaultRef` for each vault that appears in it, the home vault first. Every answer about one item
(`logins.fill`, `logins.fill_cross`, `totp.get`, `passkey.get`, `logins.get_for_edit`, `logins.update`,
`logins.create`, `logins.save`, `logins.restore`, `totp.set` with `id`) gives `vault`, its `VaultRef`:

```jsonc
{ "id": "<vault id>", "name": "Engineering",            // the home vault: the desktop app's name for it
  "home": false,                                          // true only for the home vault
  "kind": "personal" | "org" | "direct" | "emergency",    // org: a Team's or Family's vault; direct: shared with one
                                                          // person; emergency: someone's vault opened through emergency
                                                          // access, until the next lock (never editable)
  "role": null | "manage" | "edit" | "view" | "fill",     // null in the home vault
  "can_edit": bool,                                       // false for view and fill members
  "can_reveal": bool }                                    // false for fill members
```

Item ids are UUIDs and unique across the open vaults, so requests keep naming items by `id` alone; the agent finds
the vault that holds it. With one vault open the extension shows no vault names.

**Roles.** The agent enforces them; the extension words them:

* `fill` members: their logins are filled (`logins.fill`, `logins.fill_cross`, the menu's codes `totp.get` and
  `totp.popup`, `passkey.get`), never shown or copied. `logins.copy` with `field: "password"`, `cards.fill` with
  `purpose: "copy"` and `logins.get_for_edit` answer error **`fill_only`** ("This login can be filled but not shown
  or copied"). A fill's answer carries the password only for the page: the extension never shows it, copies it or
  keeps it after the fill, and the popup's own password copy (`popup.copy`, a `logins.fill`) is not offered for an
  item with `can_reveal: false`. Usernames and 2FA codes may be copied.
* `view` and `fill` members change nothing: `logins.update`, `logins.delete`, `logins.restore`, `totp.set` and
  `totp.from_image` with an `id`, `logins.save` of an existing login, `passkey.create` with one of their logins,
  and `logins.create` / `logins.save` / `passkey.create` with `vault` set to such a vault answer error
  **`read_only`** ("You can use this vault's logins but not change them"). `logins.get_for_edit` for a view member
  answers as usual plus `"read_only": true` (the editor shows the login without Save or Delete).
* A vault the server stopped accepting uploads for (an organisation whose plan ended, `subscription_inactive`) is
  `can_edit: false` too until it is live again.
* A Team that requires a second password the device doesn't have yet (`password_policy` `mode:
  "second_password"`, `action_needed: true`): the app hands the team's shared vaults over as not writable
  (`LinkedVaultConfig::writable`), so they are `can_edit: false` in `vaults.list` and every `VaultRef`, every
  editing method on them answers `read_only`, and they still open, fill, copy and sync down (nothing is uploaded).
  Once the rule is met they are editable again for the roles that allow it.

**Saving.**

| method | change |
|---|---|
| `logins.save_check` | `none` when any open vault has the login as is. `update_password` / `update_username` only for a login in a vault where `can_edit`; a matching login only in read-only vaults gives `save_new`. The answer adds `vault` (the login to update's `VaultRef`) for the update actions, and for `save_new` `vaults` (the vaults a new login can go to: `can_edit`, the home vault first) and `default_vault` (pass-core `multi_default_save_vault`: the vault that already holds most of the site's logins, else the home vault) |
| `logins.save` | `{ ..., vault? }`: a new login goes into `vault` (an id from `vaults`; default `default_vault`); `read_only` for a vault the user can't edit, `not_found` for an unknown one. An update stays in the login's own vault |
| `logins.create` | `{ url, fields, vault? }`: the same rule |
| `cards.save_check`, `cards.save` | the same rules for cards: `update_expiry` only for a card in a vault where `can_edit` (one saved only in read-only vaults is `none`), `save_new` offers `vaults` and `default_vault`, and `cards.save` puts a new card into `vault` (`read_only` for a vault the user can't edit) |
| `passkey.create_options` | adds `vaults` (editable, home first) and `default_vault`; each candidate has `vault_id` (candidates in read-only vaults are left out) |
| `passkey.create` | `consent: { itemId, vault? }`: with `itemId: null` the new login goes into `vault` (default `default_vault`) |

**New methods.**

| method | params | result |
|---|---|---|
| `vaults.list` | `{}` | `{ "vaults": [ VaultRef & { "items": n, "open": bool, "error": null \| { "code", "message" }, "last_sync": unix ms \| null } ], "teams": { "invites": n, "to_confirm": n, "notices": n } \| null, "password_policy": null \| { "mode": "second_password" \| "one_password", "action_needed": bool, "title": string, "message": string } }`: the home vault and every shared vault, for the popup's vault filter and its "Shared with me" line. `open: false` with `error` for a shared vault that couldn't be opened (codes as `teams_errors` below). `teams`: what waits for the user in the desktop app (from `Ui::teams_summary`), `null` without an account. `password_policy`: a Team's password rule for this device (from `Ui::password_policy`, ARCHITECTURE.md §17 "Password mode"), `null` without a Team or when the Team leaves it to the member (`choice`); `action_needed`: the rule isn't met on this device; `title` and `message` in the app's language, for the popup's "Shared with me" area with a button that calls `app.show_teams {}` (the Teams screen shows the same notice and the fix). Older extensions ignore it. Soft-locked: from the kept lists, `open: false` and no `error`. A background method: no prompt, no activity. Fully locked: `{ "vaults": [], "teams": …, "password_policy": … }` |
| `vaults.pins` | `{}` | `{ "pins": [vault id], "max": 5 }`: the pinned vaults in pin order (`Vault::pinned_vaults` of the home vault), for the popup's vault filter and its vault switcher (each lists the current vault first, then the pinned ones). An id may name a vault the caller doesn't list: skip it. `locked` while locked (also soft-locked). A background method: no prompt, no activity. Advertised as `vaults.pins` in `status.features`; older agents answer "unknown method" |
| `vaults.set_pins` | `{ ids, known? }` | `{ "pins", "max" }`: saves `ids` as the pins, in this order (send the whole list from `vaults.pins` with the change, so pins of vaults this caller can't see stay), saves the vault and syncs it like an edit. Ids of vaults the user can't see are dropped: known are the open vaults, the listed shared vaults (`vaults.list`), the app's own vaults with a `vault_id` (`vaults.own`) and `known` (ids the caller lists beside the agent's: in browser mode, the shared vaults the extension opens itself). While a listed shared vault hasn't been opened yet in this session (its id unknown), a pin saved before stays, unless that makes more than five. More than five known ids: `invalid_params` ("you can pin up to 5 vaults"); the popup says so before it asks. `locked`, `rate_limited` (the edit limit), `update_required` in read-only mode |
| `vaults.own` | `{}` | `{ "vaults": [ { "id", "vault_id": string \| null, "name", "location", "active": bool } ] }`: the user's own vaults on this device (the desktop app's vault list, `Ui::own_vaults`), for the popup's vault switcher. `id` is the app's id for the vault (what `vaults.switch` takes), `vault_id` its vault id once it was opened on this device (the pins use it), `location` the file, "Google Drive · <account>" or the server's host, `active` the one the app has open (or would unlock next). Team and Family vaults are not in it: they open with the home vault. `not_supported` on a host with one vault (always the browser vault). Works locked; a background method |
| `vaults.switch` | `{ id }` | `{ "switching": bool }`: the desktop app opens own vault `id` instead (`Ui::switch_vault`), as its own vault switcher does: unlocked, the main window comes up with the other vault's unlock in a dialog over the open vault, which stays open until the other one unlocks (Windows Hello or the master password, in the app; the extension never handles that password); locked, the app makes it the active vault and shows its unlock. Returns at once; the extension waits for the lock state to change. `switching: false`: it is the open vault already. Errors: `not_found`, `not_supported` |
| `app.show_teams` | `{ section? }` | `{ "shown": true }`: brings up the desktop app's Teams and Family screen (`section`: `"shared"`, `"invites"`, `"confirm"`, `"members"`, `"notices"`; anything else opens the overview), or `not_supported`. Works while locked (the screen asks to unlock) |

**Error codes** added: `read_only`, `fill_only` (above). Shared vault status codes in `vaults.list` (`teams_errors`):
`no_keyset` (the account's keys aren't in this home vault: set up sharing on this device first), `not_a_member`
(removed from the vault), `keys_mismatch` (shared with other keys of this account), `untrusted` (a members list
this device can't check: compare the manager's fingerprint in the desktop app), `rollback` (an older list than this
device accepted), `read_only_member`, `subscription_inactive`, `account_suspended`, `network`, `internal`.
Older extensions treat unknown error codes as a failed request, which is what they are.

**Other methods across vaults.** `logins.find`, `logins.search`, `passkey.find`, `icons.get`, `cards.list`,
`identities.list` span every open vault (and every kept list while soft-locked), in the order of pass-core
`multi_for_url` / `multi_search` (ARCHITECTURE.md §15.14); `logins.fill`, `logins.fill_cross`, `logins.copy`,
`totp.get`, `totp.popup`, `passkey.get`, `app.show_item`, `cards.fill`, `identities.fill` and the editing methods
take an item of any open vault. `logins.save_check` compares with the logins of every open vault;
`password.check` (`reused`) with the home vault's. The URL and search-hit rules are the same in every vault.

### The Passyble account in app mode

In app mode the desktop app owns the Passyble account (account.passyble.com, its own client, §4.2); the extension
only shows it and never holds its token. Both methods work while locked and never ask to unlock.

| method | params | result |
|---|---|---|
| `account.status` | `{}` | `{ "signed_in": bool, "email": string \| null }`: the app's account (from `Ui::account_summary`), the e-mail address only while signed in. No token, no account id, nothing else. A background method: no prompt, no activity. `not_supported` from a UI without accounts; older desktop apps answer "unknown method" |
| `app.show_account` | `{ sign_in?: bool }` | `{ "shown": true }`: brings up the desktop app's Passyble account (Settings, its account row). With `sign_in: true` the app also starts its own account sign-in in the system browser, as its Sign in button does (a sign-in already waiting is replaced), and answers at once; the outcome is a toast in the app. `not_supported` from a UI without accounts |

### Sync now in app mode

The popup's Sync button. The desktop app syncs every open vault that has sync set up and skips the others, exactly
as its own Sync button, tray item and shortcut do (`Ui::sync_now`; a UI without one leaves it to the agent, which
syncs the home vault's WebDAV or Passyble Server account and the shared vaults: `Agent::sync_report`).

| method | params | result |
|---|---|---|
| `sync.now` | `{}` | `{ "synced": n, "failed": [ { "vault": name, "reason": text } ], "no_sync": bool }`: `synced` the vaults that synced (the home vault and shared vaults; Google Drive, WebDAV or Passyble Server), `failed` each vault that didn't with the reason in the user's language, `no_sync: true` when no open vault has sync set up (nothing was tried; the extension can offer "Set up sync", which the app does in Settings → Sync). Blocks until the sync is done (a few seconds at most for an unchanged vault). `locked` while locked (also soft-locked: unlock first); `update_required` in read-only mode. Not a background method: it counts as activity. Advertised as the `sync.now` feature in `status`; older desktop apps answer "unknown method" |

The extension asks `account.status` for its Options and setup pages and polls it for a while after "Sign in" or
"Sign out" handed over to the app (`app.show_account`; Sign out happens in the app, after its own confirmation). When
the app can't answer (no native host, not running, an error, an older app) the extension signs in itself, as in
browser mode ("Extension notes").

### The Passyble account in browser mode: the same-computer sign-in handoff

In browser mode the extension has its own sign-in (client `passyble-extension`) and the desktop app its own
(`passyble-windows`). When one of them is signed in and the other isn't, the signed-in one signs the other in, and a
sign-out on one side may sign the other out too, so the person signs in and out once. The extension always drives
(on its account pages, its periodic alarm and after its own sign-in, at most about every 30 seconds, never from a
content script); the desktop app only answers. The service side is `POST /v1/session/handoff`:
the signed-in client asks, with its own access token, for a sign-in code for the other
client, bound to the S256 challenge of a verifier only the receiving side ever held; the receiving side redeems it
at `/oauth/token` exactly like a browser sign-in's code (`grant_type=authorization_code`, its own `client_id`, its
verifier, `redirect_uri=urn:passyble:handoff`).

All six are background methods (no prompt, no activity; they work while locked and in read-only mode) and never
log a code, a token or a verifier. A UI without a Passyble account answers `not_supported` (`Ui::account_peer` and
the other hooks' defaults); older desktop apps answer "unknown method"; either way the extension does nothing.
States that don't fit are `invalid_state`; a service that refuses or can't be reached is `internal`, with the
reason in the user's language.

| method | params | result |
|---|---|---|
| `account.peer` | `{}` | `{ "signed_in": bool, "email": string \| null, "accepts_handoff": bool, "sign_out_extension": bool }` (`Ui::account_peer`). `email`: the account's address while signed in; while signed out, only with `sign_out_extension` (the address the app signed out of), else `null`. `accepts_handoff`: the extension may sign the app in (`account.handoff_begin`); `false` after the user signed out of the app with "Also sign out of the browser extension" unticked (until the user signs in to the app again, any way), and while `sign_out_extension` is set (so a sign-out on purpose is never undone by an extension of another address). `sign_out_extension`: the user signed out of the app with that box ticked: an extension signed in to `email` signs out (as its own sign-out does), then sends `account.peer_signed_out`; it lasts 7 days at most, ends with `account.peer_signed_out` or the next sign-in in the app, and is never `true` while the app is signed in. The app notes when an extension last asked (for its Sign out confirmation) |
| `account.handoff_to_extension` | `{ code_challenge, device_name? }` | `{ "code": "pac_...", "email": string }`: the app is signed in, the extension isn't. The app calls `POST /v1/session/handoff` with `client_id: "passyble-extension"`, the challenge and the device name, with its own access token (refreshed as usual); the extension redeems the code (60 s, single use) with its verifier. `code_challenge`: 43 base64url characters (`invalid_params` otherwise); `device_name`: the extension's name for the device list (trimmed, control characters dropped, at most 64 characters; empty: the service names it). `invalid_state` while the app is signed out; `internal` when the service refuses (`handoff_client`, `account_disabled`, `too_many_requests`: 20 an hour per account) or can't be reached. The app shows a toast: "Signed in to the browser extension as <email>" |
| `account.handoff_begin` | `{}` | `{ "code_challenge": string, "device_name": string }`: the app is signed out and `accepts_handoff`. It makes a fresh PKCE verifier (32 random bytes, base64url), keeps it in memory only for 60 seconds (a new begin replaces it) and answers its S256 challenge and its own device name ("Passyble on <PC>"). The extension then calls `POST /v1/session/handoff` with `client_id: "passyble-windows"` and its own access token, and sends the code with `account.handoff_finish`. `invalid_state` while signed in or not accepting |
| `account.handoff_finish` | `{ code }` | `{ "signed_in": true, "email": string }`: takes the waiting verifier (single use: gone after this call whatever its outcome), redeems the code at `/oauth/token` (client `passyble-windows`, `redirect_uri=urn:passyble:handoff`) and keeps the new session as any sign-in does (refresh token in the credential store, the account in `settings.json`, Teams and shared vaults refreshed). `invalid_params` for an empty code or one with spaces or control characters; `invalid_state` without a waiting verifier, after 60 seconds, or when the app got signed in meanwhile; `internal` when the service refuses the code (expired, used, another verifier). Toast: "Signed in as <email> through the browser extension" |
| `account.sign_out` | `{}` | `{ "signed_out": true }`: the extension's sign-out with "Also sign out of the Passyble app on this computer" ticked (the user confirmed there, so the app doesn't ask again). The app signs out exactly as its own Sign out (revokes its refresh token, forgets its tokens and the Passyble Cloud device, closes the shared vaults), without setting `sign_out_extension`. Already signed out: the same answer, nothing done. Toast: "Signed out of your Passyble account from the browser extension" |
| `account.peer_signed_out` | `{}` | `{}`: the extension signed itself out because of `sign_out_extension`; the app forgets that request |

The desktop app's Sign out (Settings, its account row) confirms first; when an extension asked `account.peer` in the
last 30 days, the confirmation offers "Also sign out of the browser extension on this computer", ticked by default
(otherwise hidden and counted as ticked). Ticked: `sign_out_extension` with the address, for the extension's next
check. Unticked: `accepts_handoff: false` until the user signs in to the app again. Both are kept in `settings.json`
(`account_handoff`, no token), so they outlast a restart; the verifier of `account.handoff_begin` never leaves
memory.

Safety:

* Never a token copy: each side gets a session of its own from the service, on the device list and revocable on
  its own.
* The code is bound to a verifier only the receiving side ever held, lives 60 seconds, is single use (a second use
  revokes the session it made), is redeemed only with `urn:passyble:handoff` (which `/oauth/authorize` never
  accepts), and is never logged.
* The native messaging host answers only the extension ids in its manifest (`allowed_origins`), as the same OS
  user; software running as that user could already read either side's stored refresh token, so the channel adds
  no exposure. Content scripts never reach these methods.
* No keys: the handoff gives a session only. Opening the account key still needs the Passyble password with the
  Secret Key, or a device approval with number matching, whose checks are untouched; the new session keeps the
  original's `authenticated_at`, so it never passes a "signed in within 10 minutes" check the original couldn't.
* Both sides tell the user when a handoff signed them in or out (a toast in the app, a note in the extension), and
  the service sends its usual "new sign-in" e-mail.

### Update required (read-only mode)

When the desktop app is below the minimum version the owner set for its platform (§4.5), it is read-only until it is
updated (`pass_agent` `read_only.rs`, `Agent::set_update_required`). Nobody is locked out of their passwords:

* Still answered: `status` (with `"update_required": true`), `unlock`, `unlock.options`, `unlock.password`,
  `unlock.hello`, `unlock.cancel`, `lock`, `logins.search`, `logins.copy`, `cards.list`, `identities.list`,
  `notes.list`, `notes.get`, `cards.fill` only as the popup's copy (`purpose: "copy"` with a `field`), `app.show_item`, `icons.get`,
  `password.check`, `generate`, `generate.options`, `generate.username`, `generate.copy`,
  `vaults.list`, `app.show_teams`, `account.status`, `app.show_account` and the sign-in handoff (`account.peer`,
  `account.handoff_to_extension`, `account.handoff_begin`, `account.handoff_finish`, `account.sign_out`,
  `account.peer_signed_out`) (`pass_agent::READ_ONLY_METHODS`). Shared vaults aren't synced either.
* Every other method, one added later included, answers `{ "code": "update_required", "message": "Update the
  Passyble app to keep filling" }`: `logins.find`, `logins.fill`, `logins.fill_cross`, `logins.save`,
  `logins.save_check`, `logins.get_for_edit`, `logins.update`, `logins.create`, `logins.delete`, `logins.restore`,
  `totp.get`, `totp.popup`, `totp.set`, `totp.from_image`, `otp.outcome`, `cards.fill` (a fill), `identities.fill`,
  `passkey.find`, `passkey.create_options`, `passkey.create`, `passkey.get`, `server.pair`, `generate.email`, `sync.now`. The
  extension stops filling and saving, hands passkey requests to the browser's own WebAuthn, and says "Update the
  Passyble app to keep filling".
* Outside the protocol the agent also refuses the Windows passkey provider (`platform_passkey_create`,
  `platform_passkey_get`: `UpdateRequired`), finds nothing for auto-type (`match_window`), counts no uses and does no
  WebDAV or Google Drive sync (`sync`, `sync_gdrive` answer `Ok(None)`). The desktop app's own windows can still
  unlock, view, copy and export; their edits, imports, deletes, merges, sync set-up and auto-type are refused with
  "Passyble is read-only until you update." (`desktop-app/src-tauri/src/read_only.rs`).

### Connector for AI tools (`ai.*`)

`passyble-mcp` (`Core/mcp`, docs/AI_TOOLS.md) is an MCP server that Claude Code, Codex and other MCP clients start
over stdio. It reaches the agent over the same pipe or socket, with the same envelope (no `jsonrpc` key; one request
per connection). The app starts the IPC server with `ipc::Server::start_restricted_with_ai`: a connection from the
`passyble-mcp` beside `Pass.exe` may send `ai.*` and nothing else, gets no unsolicited events and no
`ipc::request_client_pid`; the native host and the app may not send `ai.*` (`invalid_params`, "unknown method"). The
connector checks the server with `ipc::server_is_allowed` against the `Pass.exe` beside it. A server started with
`Server::start` (tests) routes by method name.

Only items marked "Available to AI tools" exist for these methods (`pass_core::AiAccess`: the custom field
`Passyble: available to AI tools` = `Ask every time` / `Allow without asking`; items in the trash never). An item
reference is an item id, or a title that exactly one shared item has (case-insensitive); anything else, shared or
not, is `not_found` with the same message. None of them counts as activity for the auto-lock. `ai.list`, `ai.run` and
`ai.reveal` share a limit of 30 a minute (`rate_limited`). While the vault is locked they ask `Ui::request_unlock`
first; still locked: `locked`.

`client` (every method but `ai.status` and `ai.run_done`): `{ "name", "title", "version" }` from MCP `clientInfo`,
plus `"process"`, the file name of the program that started the connector (shells skipped), found by the connector
from the OS. Grants are bound to `name|process` (lower case); prompts and the log name the client "Claude Code
(claude.exe)".

Fields, as `ai.list` names them and `ai.run` / `ai.reveal` take them: `username`, `password`, `totp` (the current
2FA code), `notes`, `website` (the first URL), for cards `card_number`, `card_security_code`, `card_pin`,
`card_expiry` (`MM/YYYY`), `cardholder_name`, then custom fields by name (`custom:<name>` when a built-in has that
name), each only when it has a value; the mark itself never.

Linked vaults: marked items of every open vault take part (an id is unique across them; a title must be unique across
all of them). A shared vault's item always asks (`access: "ask"`, whatever the mark says: another member may have set
it). A fill-only member's item (`can_reveal: false`) has no `password`, `totp`, `card_number`, `card_security_code`,
`card_pin` or hidden custom field; naming one answers `fill_only`. A vault opened through emergency access, and a shared
vault `Ui::ai_allows_vault` refuses (the desktop app: while the organisations' policy has `export_allowed: false`),
don't exist for these methods. A vault that was locked, reopened or closed while a prompt waited answers `locked`. In
read-only mode (update required) `ai.run` and `ai.reveal` answer `update_required`.

| method | params | result |
|---|---|---|
| `ai.status` | none | `{ "locked", "version" }`. Never prompts. |
| `ai.list` | `{ client }` | `{ "items": [ { "id", "title", "kind", "websites", "username", "fields": [names], "access": "ask" \| "allow", "vault"? } ] }`. No values. `vault` (`{ "name", "kind", "shared", "fill_only" }`) only while more than one vault is open. |
| `ai.run` | `{ client, "env": [ { "name", "item", "field" (default `password`) } ], "command", "program", "args", "cwd", "timeout_secs"? }` | `{ "request", "approval", "timeout_secs", "env": { NAME: value } }` |
| `ai.run_done` | `{ "request", "outcome": "finished" \| "timed_out" \| "cancelled" \| "failed", "exit_code"? }` | `{}`; `not_found` unless `request` is a running command |
| `ai.reveal` | `{ client, "item", "field" (default `password`), "reason"? }` | `{ "field", "value" }` |

`ai.run`: `command` is what the AI gave, `program` the file the connector resolved it to (in `PATH`, never the
working directory; `PATHEXT` on Windows), `cwd` absolute; the prompt shows `program` with `args` quoted for display
and `cwd`. Checked before anything else (`invalid_params`): 1 to 32 variables, names `[A-Za-z_][A-Za-z0-9_]*` up to
128 characters, unique ignoring case, not `PATH`, `PATHEXT`, `COMSPEC`, `SYSTEMROOT`, `WINDIR`, `LD_*` or `DYLD_*`;
at most 256 arguments and 64 KiB of them, no NUL; every item shared and every field with a value. `timeout_secs`
defaults to 60, clamped to 1..600. When an item is "Ask every time" and this client has no grant for it,
`Ui::confirm_ai_run` asks (one prompt at a time; up to 3 more requests wait, then `rate_limited`): `Deny` →
`cancelled`; `UntilLock` adds a grant per such item, kept until the next lock of any kind or `reconfigure` to
another vault (a lock during the prompt grants nothing, and the request answers `locked`). `approval`: `once`,
`until_lock`, `grant` (covered by an earlier grant) or `without_asking` (every item "Allow without asking"). After 3
denials of one client within 2 minutes its prompts are refused (`cancelled`) without asking for 2 minutes. The agent
clears its response line from memory once written.

`ai.reveal` asks `Ui::confirm_ai_reveal` every time, whatever the item's setting and any grant. `reason` (at most
500 characters, the AI's own words) is shown as such.

The log (`Agent::ai_log`, newest first, at most 200 entries, memory only): `{ "id", "at" (unix ms), "client",
"action": "list" | "run" | "reveal", "items": [titles], "command", "cwd", "approval"?, "outcome": "listed" | "denied" |
"locked" | "running" | "finished" | "timed_out" | "cancelled" | "failed" | "revealed", "exit_code"? }`. Never a
value. `Agent::ai_grants` / `ai_revoke(item_id, client_key)` / `ai_clear_log` serve Settings → AI tools.

The MCP side (stdio, newline-delimited JSON-RPC 2.0, protocol versions 2025-11-25, 2025-06-18, 2025-03-26 and
2024-11-05): `initialize` (server `passyble`, capability `tools`, `instructions`), `ping`, `tools/list`,
`tools/call`, `notifications/initialized` and `notifications/cancelled` (stops a running command). Tools
`run_with_secret` (`{ command, args?, env: { NAME: { item, field? } }, cwd?, timeout_secs? }`), `list_items` and
`reveal_secret` (`{ item, field?, reason }`). Agent errors, denials and timeouts are tool results with
`isError: true` and a sentence for the AI; an unknown tool is JSON-RPC error -32602.

Desktop app commands for Settings → AI tools (Tauri `invoke`, main window; not on the wire): `ai_tools_state` →
`{ locked, installed, path, appimage, setup: { claude_code, codex, json }, shared: [ { id, title, kind, access } ],
grants, log }`, `ai_tools_revoke { itemId, clientKey }`, `ai_tools_clear_log`, `ai_tools_copy { what:
"claude_code" | "codex" | "json" | "path" }`; event `ai-activity`. Prompt kinds `ai-run` (answer `{ decision: "deny" |
"once" | "until_lock" }`) and `ai-reveal` (answer `{ reveal: true }`). The item DTO's `ai_access` is `"ask"`,
`"allow"` or `null`, and its `fields` leave the mark out.

### Extension notes (`Extension/src`, not on the wire)

* **The vault in this browser** (browser mode, docs/EXTENSION_VAULT.md §13.8): the same messages go to the
  extension's own BrowserAgent instead of the native host. Since 2026-11-08 that vault always lives in the
  user's Google Drive (EXTENSION_VAULT.md §15); `vault.create` and `vault.open-file` are gone. Extension pages
  only (never a content script):
  `vault.state` → `{ mode, supported, host, app_tip, has_vault, locked, source: "drive" | null, browser_only,
  name, backed_up_at, created_at, settings, drive: { configured, account, vault: { email, pending, synced_at,
  syncing, error, locked } | null } }` (`browser_only`: a legacy vault kept only in this browser; `drive.configured`:
  this build has a Google client id; `drive.account`: the Google account signed in for this session; `error`:
  `offline`, `sign_in` or `error`; no `backup_due`),
  `vault.set-mode { mode: "app" | "browser" }` (the user's switch; to the browser only with a vault there),
  `vault.export` → `{ file: <base64url>, name }` ("Download a copy"), `vault.delete { password }` (a legacy vault
  only: `invalid_state` for a Drive vault, and with reason `backup_first` without a copy downloaded in the last
  hour), `vault.settings { settings }`, `vault.dismiss-tip`. Google Drive: `drive.sign-in` → `{ email }` (Google's
  page), `drive.list` → `{ email, vaults: [{ file_id, vault_id, name, modified, size }] }`, `drive.open { file_id,
  name, password }` → `{ vault_id }`, `drive.create { password, name }` and `drive.upload-file { file: <base64url>,
  password, name? }` → `{ vault_id, synced }` (in Drive at once, or as soon as it can be reached), `drive.move
  { password? }` (a legacy vault into Drive; the password unlocks it first), `drive.sync-now` (Google's page may
  show), and `drive.sign-out { discard? }` (tries a sync first; changes still not in Drive: `invalid_state` with
  reason `not_synced` until the page sends `discard: true` after "Sign out anyway"; then the copy here and the
  Google token are forgotten). `drive.move`, `drive.sync-now` and `drive.sign-out` answer like `vault.state`. Errors of
  their own: `auth_required` (sign in to Google again; reasons `drive_scope`: the Drive permission was unticked,
  `drive_other_account`: another account than the vault's), `network` (Drive can't be reached; the change waits),
  `not_supported` with reason `drive_not_set_up` (no client id in this build). `popup.state` in browser mode adds
  `not_synced` and `browser_only` (no `backup_due`). The optional Passyble account (account.passyble.com, client
  `passyble-extension`):
  `account.status` → `{ signed_in, email, app_mode, app_reachable? }`, `account.sign-in` (browser mode: the website in
  `identity.launchWebAuthFlow`, authorization code with PKCE S256, redirect `https://<extension id>.chromiumapp.org/`,
  or Firefox's `https://<hash>.extensions.allizom.org/`, the code exchanged at `/oauth/token` by the background; a
  browser without such a redirect (Safari): `https://account.passyble.com/sign-in` in a tab, no token) and
  `account.sign-out` (`/oauth/revoke`, then the tokens are forgotten). App mode: the desktop app's account
  (`account.status` above, `app_reachable: true`, no token here); Sign in and Sign out answer `in_app: true` after
  `app.show_account` (the page polls `account.status` for a while). When the app can't be reached (`app_reachable:
  false`: no native host, not running, an error, an older app) the extension's own account shows and Sign in is the
  browser mode one, with Firefox's data consent asked on the click. No token ever leaves
  the background, and the popup's side of the background's questions: `popup.ask-get` → `{ token, kind:
  "unlock" | "verify" | "card" | "cross", host?, title?, domain?, card? }` or null, `popup.ask-answer { token,
  cancel? | password? | yes? }` (a `vault.ask` message tells an open popup that one waits). The background alone
  adds `grant` and `confirmed` to a request (§14 of EXTENSION_VAULT.md). In browser mode the passkey messages
  answer `not_supported` with reason `passkeys_need_app`, and `unlock.options` / `popup.state` carry `browser: true`.
* With the extension's card (a page's own `get()` / `create()`, below) the browser's own WebAuthn runs only after
  **Use another device** there, a real click: an error from the agent never hands the request over by itself.
  The card says what happened instead: `locked` (also fully locked right after the PC starts) "Sign in with a
  Passyble passkey?" / the save card with **Unlock**; nothing for the site (`passkey.find` empty, or `not_found`
  from `passkey.get`) "No Passyble passkey for this site"; `agent_unavailable` "Passyble isn't running" with
  **Open Passyble**; a cross-origin frame (`not_found` from the background) "Passyble can't answer here"; any
  other error a plain message with **Try again**; each with **Use another device** and Cancel. `url_mismatch` is
  reported to the page (`SecurityError`); `not_supported` from `passkey.find` (an older desktop app) sends the
  request as it came, and the desktop app asks. bridge.js marks every answer the card decided (`final: true`,
  cancel and errors included), and webauthn-main.js never falls back on one.
* Without the card (a request no content script took: none started within 15 s, a frame where it doesn't run,
  Options → **Use Passyble for passkeys in this browser** off), `not_supported` (like `not_found`,
  `agent_unavailable`, `invalid_params`, `internal` and `locked` after one unlock attempt, and the extension's
  own `timeout` and `extension_reloaded`) from the agent makes the extension fall back to the browser's own
  WebAuthn. `cancelled`, `invalid_state` and `url_mismatch` are reported to the page (`NotAllowedError`,
  `InvalidStateError`, `SecurityError`). With the option off every request goes to the browser at once.
  Requests Passyble can't serve go to the browser at once, without a card: `mediation: "silent"` or
  `"immediate"`, `create()` with conditional mediation, no ES256 among `pubKeyCredParams`, an
  `authenticatorAttachment: "cross-platform"` `create()`, options that aren't `publicKey` only or can't be read.
* Requests from **opaque-origin documents** (a sandboxed iframe, a page served with `Content-Security-Policy:
  sandbox`) are refused: the content scripts don't start there, passkey requests are left to the browser, and the
  background rejects any content-script request whose `sender.origin` is `"null"` or differs from the origin of
  `sender.url`. A sub-frame's URL never falls back to the tab's URL.
* A page's own `get()` / `create()` (not conditional) is parked in bridge.js while the content script shows its
  card (`src/content/passkey-flow.js`, `passkey-prompt.js`): nothing goes to the agent but `passkey.find` /
  `passkey.create_options` until a real, visible click there. A pick or Save sends `passkey.get` with `id` and
  `credentialId`, or `passkey.create` with `consent`, plus `inPage: true` (internal message to the background): on a
  `locked` answer the background doesn't call the desktop app's `unlock` (desktop apps with `unlock.inline`), the card
  unlocks in the page (Windows Hello at once, or the master password frame) and sends again. **Use another device**
  hands the request to the browser's own WebAuthn, Cancel (close, Esc) fails it with `NotAllowedError`. Nothing in
  Passyble for the site, Passyble not running, fully locked (with or without user activation) and errors show
  their card (above), never the browser's dialog by themselves. After an unlock in the card with no passkey for the
  site: "No Passyble passkey for this site". "Open Passyble" (`passkey.start_app`, internal message: a fresh
  native host starts the desktop app, at most once in 15 s) asks again once it runs. The request waits for the
  page's `timeout` (60 s to 10 min, 5 min by default); one made while the page is still loading waits up to 15 s
  for the content script, and bridge.js starts the content script itself when the page has finished loading
  without it (the browser runs it at `document_idle`, which can come late). An older desktop app ("unknown method"
  for `passkey.find` / `passkey.create_options`): the request is sent as it came.
* Since the extension answers in the page, the browser never hands such a request to Windows: with Passyble also
  registered as a Windows passkey provider, Windows' passkey dialog shows only after **Use another device** (or for a
  site Passyble has nothing for), as the browser's own dialog, never for the same request as the card.
* `passkey.create` / `passkey.get` params may carry `crossOrigin: true`. The extension also sends a hint
  `crossOriginAncestor` (internal message from bridge.js to the background) when any ancestor frame has another
  origin (A > B > A nesting, which the top frame alone doesn't reveal); it can only make the request stricter:
  cross-origin frames fall through to the browser, which alone can check the `publickey-credentials-*` permissions
  policy.

* The popup's unlock form uses `popup.unlock-options` (`{ inline, locked, hello }`), `popup.unlock-password`
  (`{ password, for? }`: checked to be 1-1024 characters, sent once as `unlock.password`, never stored or logged) and
  `popup.unlock-hello` (`{ then?: { fill: { tabId, id } }, for? }`: a fill to finish after Windows Hello; `for`: the
  login the form stands in for, passed on as `unlock.*`'s `for`); `popup.state`
  adds `can_unlock_inline`, `unlock_hello` and `ask_unlock` (the in-page menu opened the popup to unlock for that
  tab). The in-page menu uses `unlock.options` (`{ for? }`: the login it fills once unlocked; the tab's next
  `unlock.hello`, `unlock` or master password frame unlock then says `for` it), `unlock.hello`, `unlock.cancel` (`{ cancelled }`; `{ cancelled:
  false }` from a desktop app without it) and `unlock.open-form` (content scripts; never a password). Its master
  password field is the extension page `src/unlock/frame.html` in an iframe inside the menu (web-accessible; an
  extension page, so it reaches the background as one and uses `popup.unlock-password` like the popup's form). It
  tells the menu only `postMessage({ passybleUnlock: "ready" | "unlocked" | "escape", height })`, which the
  content script accepts only from that iframe's window with the extension's origin; the menu may send it
  `{ passybleUnlock: "focus" }`. After an unlock from the extension the background sends
  `{ type: "lock_state", locked: false }` to the active tabs' frames, where a login picked while locked fills.
  "unknown method" from an older desktop app becomes `not_supported`.
* The popup's login editor uses `popup.edit-get` / `popup.edit-save` (update with an `id`, else create) /
  `popup.edit-delete` / `popup.edit-restore` / `popup.totp-check` (`totp.set` without `id`) / `popup.totp-scan` /
  `popup.show-item`. The background takes the URL from `tabs.get(tabId)`, checks field types and lengths again,
  and turns "unknown method" from an older agent into `not_supported`. For `popup.totp-scan` it captures the tab
  only if it is the active tab of its window and an http(s) page (PNG; JPEG if the PNG is over 7 MiB, the native
  host's limit being 8 MiB). Nothing passing through is stored.
* Popup avatars: after showing the matching logins (or a looked-up site's), the popup asks `popup.icons` when
  `status.features` has `icons.get`; the background calls `icons.get` with the tab's URL from `tabs.get` (or the
  looked-up site's). Each avatar whose login has an icon becomes an `<img>` of that `data:image/png` URL (other
  values are ignored); errors, a locked vault or a broken image keep the letter. The in-page inline menu keeps
  letters: a `data:` image there would be subject to the page's CSP (and its violation reports).
* 2FA after a fill (`otp.context`, `otp.outcome`): nothing is shown for a pending OTP unless the 2FA step is
  detected (a code field, or 2FA wording on a page that has an input or a sign-in URL; the toast only for the
  latter). The top frame reports `skipped` when, about 10 s after the page load / navigation / form submission,
  there is no code field, no 2FA wording, no password field and the URL path no longer looks like a sign-in step
  (`login`, `signin`, `auth`, `2fa`, `verify`, `session`, …); the content script reports `asked` once per page
  when the step shows up; the background reports `used` for `otp.consumed` and `fill.done` with `otp: true`. With
  `skips_2fa` (or after a `skipped` on this sign-in, kept per tab in memory), `otp.context` answers `quiet: true`:
  the code goes only into a code field that actually shows up, never the toast. After the agent's 3-minute
  window, the login filled in that tab is still offered (`late: true`, menu only, never auto-filled) when a code
  field of its site shows up within 5 minutes of the fill.
* **Password check** (`password.check`): `save.query`'s answer has `check` (`{ score, label, issues: [{ code,
  severity, count?, min_length? }], vault_checked }` or `null`) for the captured password, with the login being
  updated as `id`; the banner shows it in its closed shadow root. Its **Edit** fields are an extension page in a frame inside the
  banner (`src/save/edit.html`): it asks `save.edit-get { token }` (that page in a frame of the tab only; the
  captured password only when the tab shows the form's origin) and stores edits with `save.edit-set { token,
  username, password }`, which answers their check; the banner's `save.check { token }` and `save.commit
  { token }` then use the stored edits (older banners sent `username` / `password` there; still accepted). The popup's
  editor sends `popup.password-check { tabId, password, username, title, id? }` (debounced 350 ms; the URL is the
  tab's from `tabs.get`; no unlock prompt). The background passes only those fields on and drops anything else in
  the answer; content scripts have no handler that asks for a check of an arbitrary password. Nothing is cached.
* The save banner asks `logins.save_check` once per captured submit (with `filled_id` when the tab's last fill
  was under 10 minutes ago) and shows nothing for `none`, "Update password in Passyble?" for `update_password`,
  "Update username in Passyble?" for `update_username` (commit: `logins.save` with `id` and `update: "username"`),
  "Save login to Passyble?" for `save_new`. While locked (`locked`) the agent can't compare passwords: when
  soft-locked and the kept list (`logins.find`, `locked: true`, usernames only) has a login of the site with
  the submitted username, the one just filled, or any login when no username was submitted, the background
  holds the capture back and shows nothing (it may well be saved already; a password change form is never held).
  Otherwise (no such login, or fully locked: no list) it shows "Save login"; Save unlocks, asks again, and
  writes nothing for `none` ("Already saved in Passyble"). Once the vault is unlocked (the agent's `lock_state`
  event, or the extension's own unlock form) within the 5 minutes the capture is kept, the background sends
  `save.recheck` to the top frame of each tab with such a capture; it asks `save.query { recheck: true }`,
  which decides with `logins.save_check`: `none` drops it (a banner shown while locked gets `{ close: true }`
  and goes away), a held capture gets its banner now ("Update password?" for a changed password), a banner
  already on screen otherwise stays. Each capture is checked again once. The banner has editable Username / Password fields: `save.query` returns
  `editable: true` and the captured `password` only to a top frame of the origin it was typed on (otherwise the
  field starts empty and means "keep it"). `save.commit { token, username?, password? }`: edited values that
  differ from the capture are checked (lengths) and decided again with `logins.save_check` before `logins.save`;
  the answer carries the `action` taken.
* **Usernames and e-mail addresses** (`generate.*`, only when `status.features` lists them; with an older app
  the popup button and the context-menu items don't appear, and "unknown method" becomes `not_supported`). The
  popup editor's username field has a generate button: "Random username" (`generate.username {}`, the agent's
  defaults), then from `generate.options` "Plus address", "Catch-all address" and "E-mail alias (<name>)" per
  service (default first), and a "Mention this website" checkbox (the local setting `mentionWebsite`, off by
  default, shared with the context menu). `locked` from `generate.options` is no error: only "Random username"
  is offered, without an unlock prompt. The context menu has "Generate username" and "Generate e-mail alias" on
  username and e-mail fields (never password fields; the alias item only when a service is set up, from
  `generate.options` cached 30 s); the background sends `cmd.generate-username-here { kind }` to the frame, which
  fills the field (nothing is saved). `generate.email`: `url` is always the tab's (popup) or the frame's (context
  menu) URL, never one from a message; `website: true` only with `mentionWebsite`; `service` only from the popup's
  per-service items (the context menu uses the default service); timeout 90 s; `locked` unlocks first. A content
  script's `generate.email` is accepted only right after a click on "Generate e-mail alias" in that frame (60 s,
  one alias per click), so a page can't make aliases. `not_found` shows the extension's "set it up in Passyble →
  Settings", `rate_limited` "Too many new aliases"; other messages are the agent's (user-facing English). The
  extension keeps no token or address, only the generated value.
* **Drafts** (generated passwords saved at once: the generate button in new-password fields and the context
  menu's "Generate password", which the background sends as `cmd.generate-here` to the right-clicked frame).
  The content script sends `draft.save { username, password, kind: "signup" | "change" }`; the background
  calls `logins.create { url: <frame URL>, fields: { username, password[, title: "<host> (new password)"] } }`
  (unlocking first; "unknown method" → `not_supported`) and keeps `{ id, origin }` per tab in memory for 30
  minutes; another `draft.save` from that tab and origin is `logins.update` of the same id. `draft.undo` →
  `logins.delete`. On submit (`save.capture`) with a draft of the same origin: `signup` / `login` → `logins.update
  { id, fields: { password, username? } }` without unlocking, and no banner if that worked; `change` → the banner as
  usual with `logins.save_check { …, ignore_id: <draft> }`, and the draft is deleted after the commit (or when the
  answer is `none`).
* **Vault search** (popup, when `status.features` has `logins.search`): `popup.search { query }` →
  `logins.search { query, limit: 20 }` (2–128 characters, checked first); `popup.copy-item { tabId, id, field }`
  → `logins.copy { id, field, url: <tab URL> }`; `popup.icons { ids }` → `icons.get { ids }`; `popup.show-item`
  unchanged (the agent accepts search hits). `popup.fill-cross { tabId, id }` records `{ id }` for that tab (2
  minutes, one use) and sends `cmd.fill-cross { id }` to the frame that last had a login field focused; that
  frame's content script sends `logins.fill_cross { id }`, which the background only forwards (with the frame's
  own URL) when it matches the recorded request.
* **Favorites and Notes** (popup type filter, when `status.features` has `items.favorite` and `notes.list`;
  without them those chips aren't shown): Favorites narrows the site's logins, similar sites and search results to
  `favorite: true` and shows the favorite cards, addresses and notes without a search; Notes shows the notes
  (`popup.notes` → `notes.list { limit: 200 }`, narrowed by title in the popup). A note opens in a small viewer
  (`popup.note-get { id }` → `notes.get`, unlocking first as other copies do); its Copy and a row's Copy send
  `copy: true`, so the desktop app copies the text itself. The text stays in the viewer's DOM only and is dropped
  when it closes, the vault locks or the popup goes away.
* **Save selection to Passyble note** (context menu on selected text of `http(s)` pages, `contexts: ["selection"]`):
  the click keeps the browser's `info.selectionText` (line breaks as `\n`, control characters dropped, trimmed; the
  page itself is never read) in the background's memory under a one-time token and opens a small popup window,
  `src/clip/clip.html?clip=<token>` (the token only, never the text; `windows.create`, so it works the same in
  Chrome, Edge, Firefox and Opera). The window takes the selection once (`clip.take`) and keeps it in its own memory;
  `clip.state` asks `status` and, with `notes.append`, `notes.list { limit: 200 }` (titles only, the most recently
  changed first, a note of a vault the user can't change shown but not offered). Choosing a note sends `clip.append
  { id, text }` → `notes.append`; **New note** (title prefilled with the page title, else the site; editable) sends
  `clip.create { title, text }` → `notes.create`. "Add the page address" (off by default) puts the page's address on
  the line after the selection. Both unlock first when the vault is locked (`withUnlock`); fully locked, the window
  shows Unlock (`clip.unlock` → `unlock`). Without `notes.append` the window says "Update the Passyble app to add to
  a note" and still offers New note when `notes.create` is advertised; without either, only the update message.
  The selection goes to the agent only: it is not stored, logged or put in a URL. `clip.append` and `clip.create`
  are refused below the minimum extension version, and the menu does nothing then.
* **Similar sites** (in-page menu, when `status.features` has `logins.similar`): on a sign-in field of a page
  where `logins.find` found nothing, the menu sends `menu.similar`; the background asks `logins.similar { url:
  <frame URL>, limit: 3 }` and keeps the ids it got for that tab and frame (5 minutes). Their rows (title,
  username, site) show under "Similar sites", nothing preselected; a pick sends `logins.fill_cross { id, similar:
  true }` from that frame, forwarded only for an id offered to it (the desktop app asks as for any cross fill).
  "Search Passyble…" (`menu.search`) opens the popup (`action.openPopup`) with its vault search started for
  `name` (else the page's host); where the browser doesn't allow that, the menu says to click the toolbar
  button, and the popup opened within a minute starts with that search. The popup's empty state ("No logins for
  <site>") lists the same similar sites (`popup.state` `similar`) above the focused search field.
* **After a cross fill** (from the popup or the menu, `cross: true`): the background keeps the fill for that tab
  (10 minutes: the login, the page's URL, the agent's `add_url_token`, the username and password for a copy, a
  hash of the password) and has the top frame show "Use this login on <site> too?" (`cross.query`, once per
  page; its card has a one-time token of its own). A form submitted with the filled username and password shows
  this card again on the next page instead of the save banner, until it is answered. **Add <site> to this
  login** (`cross.add { token }`) → `logins.add_url { id, url, token: <add_url_token> }`; **Save a copy for
  <site>** (`cross.copy { token }`) → `logins.save { url, username, password }` (a new login); **Not now**
  (`cross.dismiss { token }`) forgets the secrets and the save banner for that submit. The content script only
  ever has its card's token; the agent's token and the password stay in the background. On a page that looks
  like the login's site (the fill's `lookalike`) the card repeats the warning.
* **Changed before signing in** ("Update this login?"): the background keeps what the tab's last fill put into
  the page (`logins.fill`, or `logins.fill_cross`; 10 minutes, dropped on `lock_state` locked, taken by the
  next submit): the login's id, the frame's origin, the username, the password only as a SHA-256 with that
  origin, and the fill's `vault.can_edit` / `vault.can_reveal`. A plain sign-in submitted on that origin with
  another username (trimmed, any case) or another password is decided by `logins.save_check` as usual
  (`filled_id` set); the card shows instead of the banner when the answer is `none` for the filled login (its
  password with a new username), `update_username` for it, or `save_new`. Any other answer keeps the usual
  banner (another saved login of the site, or `update_password` of the filled login: the "Update password?"
  banner). The card names what changed, never the password, and has a one-time token of its own. **Update
  login** (`changed.update { token }`) → `logins.update { url, id, fields }` with only the changed fields (the
  agent checks the login belongs to the page and is in a vault where `can_edit`, and verifies as for any edit,
  `Reason::SaveChanges`); a cross fill's login first gets the page added (`logins.add_url` with that fill's
  `add_url_token`), so it can be changed from the page. **Save as new login** (`changed.save { token }`) →
  `logins.save { url, username, password }` without an id. **Not now** (`changed.dismiss { token }`). No
  Update for a vault where `can_edit` is false; no card at all for a fill-only login (`can_reveal: false`) with
  only the username changed (its password never goes into a new login). After a cross fill this card stands in
  for "Use this login on <site> too?" (one card), until that one is answered. No agent method of its own: the
  browser vault runs the same `logins.update`.

### Platform passkey API (Rust only, not on the wire)

The Windows passkey provider (`Core/desktop-app/src-tauri/src/passkey_provider.rs`) calls the agent directly with
requests Windows has already validated, so they carry a `clientDataHash` instead of an origin and challenge:

```rust
impl Agent {
    // Unlock if needed → exclude list → Ui::confirm_passkey_create → verify_user(user_name) → store.
    fn platform_passkey_create(&self, req: PlatformCreateRequest, verify_user: &dyn Fn(&str) -> bool)
        -> Result<PlatformCreated, RpcError>;          // credential_id, authenticator_data, attestation_object
    // Unlock if needed → Ui::choose_passkey only when several match (most used first) → verify_user → sign;
    // counts as a use of the login (record_use) once signed. Neither call is activity before it succeeds.
    fn platform_passkey_get(&self, req: PlatformGetRequest, verify_user: &dyn Fn(&str) -> bool)
        -> Result<PlatformAssertion, RpcError>;        // + user_handle, user_name, user_display_name
    // Metadata of every passkey (no keys) for Windows' autofill cache; None while locked.
    fn passkey_metadata(&self) -> Option<Vec<PasskeyMetadata>>;
    // Usage (ARCHITECTURE.md §13), for the app's own fills, auto-type and copies: records, saves about 2 s later
    // on a thread of its own (save_soon; a lock saves at once), never syncs.
    fn record_use(&self, item_id: &str);
    fn save_soon(&self);                               // a save on a background thread, USE_SAVE_DELAY from now
    fn usage_sync_due(&self) -> bool;                  // the sync scheduler's 6-hour rule
}
```
Errors use the same codes: `cancelled` (declined, unlock or user verification cancelled), `invalid_state`
(excluded credential), `not_supported` (no ES256), `not_found`, `invalid_params`.

### Desktop app commands for import (Tauri `invoke`, main window only; not on the wire)

| command | args | result |
|---|---|---|
| `import_file` | – | opens a file dialog, reads and parses the file in Rust, previews it against the unlocked vault and keeps it pending. `null` if cancelled, else `{ "source": file name, "preview": ImportPreview (snake_case JSON, ≤ 2000 entries), "hidden_rows": n }` |
| `import_text` | `{ text }` | same for pasted links / text (`source` is empty) |
| `import_commit` | `{ decisions?: [{ group_id, decision: { type: "merge", password_from?, totp_from?, title_from? } \| { type: "keep_both" } \| { type: "skip" } }], restKeepBoth?: bool }` | applies the pending import to the vault it was previewed against with those decisions (groups without one: their default, or Keep both when `restKeepBoth`, for groups over the preview cap while "Merge duplicates" is off), saves, kicks a sync, emits `vault-changed`; `ImportResult` as JSON. The preview JSON caps `groups` at 2000 too (`hidden_groups`) |
| `import_cancel` | – | drops the pending import (also dropped on lock) |
| `import_dropped` | – | previews the file last dropped on the main window, like `import_file` (`null` if none). The path comes from the window's native drag-and-drop event and stays in Rust; the window only gets an `import-dropped` event |
| `find_duplicates` | – | `{ "groups": [DuplicateGroup] }` for the unlocked vault (no secrets) |
| `merge_duplicates` | `{ merges: [{ ids: [item id], decision }] }` | `merge_items` for each; saves, kicks a sync and emits `vault-changed` if any merged: `{ merged, removed }`. An error only when nothing merged |
| `merge_preview` | `{ a, b, picks? }` (item ids; `MergePicks` as snake_case JSON, sides `"a"` / `"b"`, notes also `"both"`) | `{ plan, picks, history_added, totp_noted, a, b, result }` (`ItemDto`s; no passkey keys) |
| `merge_pair` | `{ a, b, picks? }` | `merge_pair`; saves, emits `vault-changed`, keeps the undo for 60 s (dropped on lock): `{ item, removed_id, undo_secs }` |
| `undo_merge` | `{ id }` (the kept item) | both items back; saves, emits `vault-changed`: the kept item (`ItemDto`) |
| `merge_suggestions` | – | `{ "suggestions": [MergeSuggestion] }` (no secrets) |
| `merge_candidates` | `{ id }` | `{ "candidates": [{ id, score }] }` |

### Desktop app commands for undo and Windows Hello (Tauri `invoke`, main window only; not on the wire)

| command | args | result |
|---|---|---|
| `take_auto_hello` | none | `true` once after the user opened the main window (tray, Start menu, a second launch, the start-up window of a start without `--background`, "Open in Passyble"), within 90 s and while the window is on screen (shown, not minimized): the unlock screen may start Windows Hello by itself. `false` for a window nobody opened (a start with Windows), after a lock or unlock, or once the window was hidden. The window hears `main-opened` when the user opens it |
| `cancel_hello_unlock` | none | the unlock screen's Windows Hello is called off (typing the master password, "Use master password instead"): `true` if one was pending |
| `delete_item` | `{ id }` | deletes (tombstones) the item and keeps a copy in memory for 60 s, dropped on lock: `{ undo_secs }` |
| `restore_item` | `{ id }` | Undo: writes that copy back (a newer version than the deletion, so it returns everywhere after sync); the item DTO. Error after the window |
| `delete_items` | `{ ids }` | the list's selection: deletes each item still there, one save, copies kept as for `delete_item`: `{ deleted, undo_secs }` |
| `restore_items` | `{ ids }` | Undo of `delete_items`: writes back every copy still kept, one save; the item DTOs. Error when none is left |
| `set_favorites` | `{ ids, favorite }` | stars or unstars each item (read from the unlocked vault, never a locked copy), one save: `{ changed }` |
| `remove_vault` | `{ id }` | takes the vault off the list; its WebDAV password / device token is held in memory and its Windows Hello blob and key are deleted only after 20 s: `{ undo_secs }`. If Pass exits within those 20 s, a `<id>.removed` marker next to the blob has the next start delete them (a blob is never deleted only because its vault is missing from the list) |
| `undo_remove_vault` | `{ id }` | Undo: puts the entry back at its place (active again if it was), with its password/token |
| `vault_pins` | – | `{ pins, max }`: the open vault's pins (`Agent::pinned_vaults`), for the "Switch vault" menu, the "All vaults" filter and Teams and Family (each lists the open vault first, then the pinned ones) |
| `set_vault_pins` | `{ ids }` | as the agent's `vaults.set_pins` (without `known`): saves and syncs them, `{ pins, max }` |
| `switch-vault` (event) | `{ id }` | the browser extension's `vaults.switch`: the vault view opens that vault's unlock over the open one (its "Switch vault" menu's way); a locked window shows the vault now active |

Each `status.vaults` entry also has `vault_id`: the vault id inside the file, recorded at each unlock on this PC
(`null` until then). The pins name vaults by it.
| `enable_hello` | – | "Unlock with Windows Hello next time?" → Turn on: enrolls the unlocked active vault (one Windows Hello prompt: the signature is checked against the key's PKCS#1 public key; it signs a second time only if that can't be read) and turns Windows Hello on; nothing saved if cancelled. `{ warning }` |
| `dismiss_hello_offer` | – | "Not now": don't offer Windows Hello again for the active vault |

`status` also returns `offer_hello` (unlocked active vault without Windows Hello, Hello available, unlocked
with its master password in this run, not dismissed), `last_server_url` / `last_server_user` /
`last_server_pins` (the last Passyble Server sign-in, to prefill the form) and `sync` (as in `sync-status`).
Errors from every command are plain sentences with what to do next (`Core/desktop-app/src-tauri/src/errors.rs`):
"Can't reach <host>. Check the address…", "Too many attempts. Wait N minutes…", "The server's certificate
changed…", "Wrong master password. Check Caps Lock…".

Errors are plain strings (`"The vault is locked"`, the parser's message, …).

### Desktop app commands and events for website icons (Tauri; main, quick-pick and prompt windows; not on the wire)

| command / event | args / payload | result / meaning |
|---|---|---|
| `site_icons` | `{ domains: [string] }` (the `site` field of item summaries and items: `site_icon_domain` of the login's first URL with one) | `[{ domain, icon }]`, `icon` a `data:image/png;base64,…` URL or `null`. Reads `%LOCALAPPDATA%\Pass\icons` and queues a background fetch (`site_icon_cache_refresh`, at most 4 at a time, deduplicated, each domain at most once per 6 h per run) for domains not cached yet or due for a refresh. All `null`, without touching the disk, while locked or with "Show website icons" off. At most 500 domains per call; anything that isn't a normalised host name is answered `null` |
| `site-icon` (event) | `{ domain, icon }` | a queued fetch finished (`icon` `null`: the site has none); only emitted while unlocked |
| `site-icons-enabled` (event) | `{ enabled }` | the setting changed: drop the icons shown; when on, ask again |

`get_settings` returns `show_site_icons` and `site_icons_supported` (a build with the `icons` feature);
`set_settings { update: { show_site_icons } }` turns it on or off (off: stops the queue, deletes the cache and calls
`Agent::set_icon_cache_dir(None)`, which empties `icons.get`). The passkey chooser prompt's data carries
`site` (the icon domain of the `rp_id`).

### Agent → UI hooks (desktop app implements `pass_agent::Ui`)

```rust
trait Ui: Send + Sync {
    fn request_unlock(&self) -> bool;                                        // blocks until unlocked / cancelled
    // The extension's own unlock form (`unlock.options` / `unlock.password` / `unlock.hello` / `unlock.cancel`). Defaults: no
    // Windows Hello; `None` = the agent unlocks with the password itself; Hello `Unavailable`.
    fn unlock_options(&self) -> UnlockOptions { UnlockOptions::default() }   // UnlockOptions { hello: bool }
    fn unlock_with_password(&self, password: &str) -> Option<UnlockAttempt> { None }
    fn unlock_with_hello(&self) -> UnlockAttempt { UnlockAttempt::Unavailable(..) }
    // `unlock.cancel`: cancel a pending in-browser `unlock_with_hello`; true if one was pending. Never prompts.
    fn cancel_unlock(&self) -> bool { false }
    // Hello over the browser window, no window of its own, and `cancel_unlock` works: `status` then
    // advertises `unlock.hello_browser`.
    fn hello_in_browser(&self) -> bool { false }
    // UnlockAttempt::{Unlocked, WrongPassword, Cancelled, Unavailable(reason), Failed(message)}
    fn confirm_passkey_create(&self, rp_id: &str, user_name: &str) -> Consent;   // Consent::{Approve{item_id: Option<String>}, Deny}
    fn choose_passkey(&self, rp_id: &str, options: &[PasskeyChoice]) -> Option<usize>;
    fn show_totp_popup(&self, item_id: &str, title: &str);
    fn notify_lock_state(&self, locked: bool);
    fn show_server_pairing(&self, link: &str) -> bool { false }   // `server.pair`; true = dialog shown
    // Before a secret leaves the vault for the browser (copies, passkey use, cards): the desktop
    // app shows Windows Hello when the vault's per-fill policy is on. Refused → `cancelled`. Only Verified sets the
    // passkey UV flag. Default: Allowed.
    fn verify_user(&self, reason: &str) -> Verification { Verification::Allowed }
    // A login's password or 2FA code (fills, `totp.get` / `totp.popup`), with its item id: "Every time" counts an
    // unlock only for the login it was asked for (`for`) and lets the confirmed login's codes through for 2 minutes.
    // Default: a pending code (`follows_fill`) is Allowed, anything else is `verify_user`.
    fn verify_item(&self, reason: &Reason, item_id: &str, secret: ItemSecret) -> Verification;
    fn vault_changed(&self) {}                                    // the extension edited the vault: reload windows
    fn credential_used(&self) {}                                  // a use went through (Agent::note_use): slide the per-fill grace period
    fn show_item(&self, item_id: &str) -> bool { false }          // `app.show_item`; false → `not_supported`
    fn copy_to_clipboard(&self, text: &str) -> bool { false }     // `logins.copy`, `generate.copy`: copy as a secret (45 s); false → `not_supported`
    // `logins.fill_cross` for another site's login: Some(true) fill once, Some(false) → `cancelled`, None → `not_supported`.
    fn confirm_cross_fill(&self, request: &CrossFillRequest) -> Option<bool> { None }
    // `vaults.list` `teams`: invitations, people to confirm, unseen notices; None without a Passyble account.
    fn teams_summary(&self) -> Option<TeamsSummary> { None }
    // `vaults.list` `password_policy`: a Team's password rule (mode, action_needed, title, message); None without
    // one. While a required second password is missing the app also hands the team's vaults over as not writable.
    fn password_policy(&self) -> Option<PasswordPolicy> { None }
    // `app.show_teams`: the Teams and Family screen on `section` ("" = the overview); false → `not_supported`.
    fn show_teams(&self, section: &str) -> bool { false }
    // `account.status`: the app's Passyble account (signed in, e-mail; no token); None → `not_supported`.
    fn account_summary(&self) -> Option<AccountSummary> { None }
    // `app.show_account`: the account screen; `sign_in` starts the app's own sign-in too; false → `not_supported`.
    fn show_account(&self, sign_in: bool) -> bool { false }
    // The sign-in handoff with the extension in browser mode: `account.peer` (None → `not_supported`), a code for
    // the extension, the app's challenge, redeeming the extension's code (answers the e-mail address), the
    // extension's sign-out of both, and the extension following the app's sign-out. Default: `NotSupported`.
    fn account_peer(&self) -> Option<AccountPeer> { None }
    fn handoff_to_extension(&self, code_challenge: &str, device_name: &str) -> Result<HandoffCode, AccountError>;
    fn handoff_begin(&self) -> Result<HandoffRequest, AccountError>;
    fn handoff_finish(&self, code: &str) -> Result<String, AccountError>;
    fn sign_out_from_extension(&self) -> Result<(), AccountError>;
    fn peer_signed_out(&self) -> Result<(), AccountError>;
    // `sync.now`: sync every open vault with sync set up; None → the agent syncs by itself (`Agent::sync_report`).
    fn sync_now(&self) -> Option<SyncReport> { None }

    // The connector for AI tools (below, "Connector for AI tools"). A command with secrets of items marked "Ask
    // every time" without a grant: Deny / Once / UntilLock (closed or 2 min without an answer: Deny); None →
    // `not_supported`. A reveal: asked every time; Some(true) only for an explicit yes. The desktop app follows a yes
    // with Windows Hello or the master password (commands: when the per-fill policy is on; reveals: always).
    fn confirm_ai_run(&self, request: &AiRunRequest) -> Option<AiDecision> { None }
    fn confirm_ai_reveal(&self, request: &AiRevealRequest) -> Option<bool> { None }
    fn ai_activity(&self) {}                                      // the AI log or grants changed: refresh Settings → AI tools
    fn ai_allows_vault(&self, vault: &VaultRef) -> bool { true }  // a shared vault for AI tools at all (desktop: the export policy)
}
struct CrossFillRequest { item_id: String, title: String, username: String, item_domain: String, page_host: String }
enum Verification { Verified /* just verified: Windows Hello, or the unlock this request triggered */,
                    Allowed  /* no verification needed now: user presence only, no UV */,
                    Refused }
```

Locking (`pass_agent::Agent`, see "Soft lock" above): `lock()` / `save_and_lock()` lock softly while
`set_keep_list(true)` (the default; the app's "Keep list visible when locked"), else fully; `lock_as(LockKind)` /
`save_and_lock_as(LockKind)` pick (`LockKind::Full` for "Lock completely"); `tick()` (auto-lock) uses the
default; `reconfigure` to another vault file or account is always full. `is_locked()` is true for both;
`is_soft_locked()`; `summaries() -> Option<Arc<Vec<ItemSummary>>>` (the unlocked vault's, the kept list, or `None`
when fully locked; not activity). `notify_lock_state(true)` also fires when a soft lock becomes a full one
(the windows switch to the unlock screen); the app reads `is_soft_locked()` there. Kept between runs
(`AgentConfig::kept_list`, a path per vault; Windows only, no-op elsewhere): written at unlock, at each lock and
from `tick()` while the vault changes (at most every 10 s); `restore_kept_list()` at start-up loads it (soft
lock) if it opens and the vault file holds the same vault; `forget_kept_list()` ("Lock completely", sign-out)
deletes it until the next unlock; `set_keep_list(false)` deletes it.

Linked vaults (`agent/src/linked.rs`, "Linked vaults" above): the app hands over the shared vaults its account can
open with `set_linked_vaults(Vec<LinkedVaultConfig>)` (`key` "<owner>/<vault>", `name`, `account` (the backend's
account id), `path` of the local copy, `webdav` (URL, device token, pins), `writable` (whoami), `org`), after every
unlock and refresh; the agent opens each local copy through the home vault (`Vault::open_shared_with_home`) when
the home vault unlocks or the list changes, locks them with it (a soft lock keeps their lists in memory only),
writes them beside it on every save (`save()` also writes changed shared vaults, and the home vault's trust records
and unconfirmed member changes of them first), and forgets them when `reconfigure` moves to another vault.
`linked_status()` (per vault: `vault: Option<VaultRef>`, `open`, `items`, `error` with a `teams_errors` code,
`last_sync_ms`, `writable`), `open_vaults()` (home first), `home_ref()`, `shared_vault(vault_id)` (members
changes; then `save_shared(vault_id)`), `vault_of_item(id)`, `all_summaries()`, `default_save_vault(url)`,
`add_shared(config, vault)` (a vault made with `Vault::create_shared`), `open_shared_file(key, bytes)` (a first
download), `remove_shared(key, delete_file)`, `transfer_item(id, target_vault_id, remove)` (move or copy, saves
both), `sync_linked()` / `sync_shared(key)` (`webdav_sync` for vaults the account may change, otherwise download
and merge only; a members list that changed on this device's behalf is uploaded at once; not in read-only mode),
`take_linked_notices()` (`MembersNotice` per vault, once), `linked_sync_pending()`. Auto-type (`match_window`),
the platform passkey provider (`platform_passkey_*`, `passkey_metadata`) and use counts span every open vault; a
use in a vault the account can't upload to stays on this device.

### Desktop app commands for Passyble Server (Tauri `invoke`, main window only; not on the wire)

| command | args | result |
|---|---|---|
| `server_link_check` | `{ link }` | parses the link and tests the connection (HEAD with the pins): `{ host, url, username, device_name, https, pinned, pins, exists: bool or null, error: string or null }` (never the token) |
| `server_qr_from_file` | – | file dialog for a PNG/JPEG of the pairing QR code → the link, or `null` if cancelled |
| `server_qr_from_clipboard` | – | the link from a QR code in the clipboard image (Win+Shift+S) |
| `setup_server_connect` | `{ link, create, path, password, name? }` | vault list → Add existing vault → From Passyble Server. `create: false` downloads the server's vault to `path` and unlocks it with its master password; `create: true` (the server has none) creates a vault at `path` and uploads it. Same result as `setup_create` |
| `server_use_for_vault` | `{ link }` | Settings → Use Passyble Server for the unlocked vault: syncs with the server (uploads if it has no vault, merges a copy of this vault) and keeps the account. `{ connected: true, created_remote, uploaded, added, updated, deleted }`, or `{ different_vault: true }` with nothing saved |
| `server_pair_take` | – | the link from the last `server.pair`, once (`null` if none) |
| `server_signin_link` | `{ link }` | parses a pasted/scanned link for the sign-in form: `{ server_url, host, username, pins, pinned, https, pairing, code_kind }` (`pairing: true` = has a token, use the pairing flow; `code_kind: "invite" \| "reset"` = an e-mailed link, show "Choose your password"; never the token or the code) |
| `server_code_set_password` | `{ link, newPassword }` | §3.5: sets the password with the link's one-time code, signs in again, then the vault: invite → create/download; reset → re-wrap the unlocked vault here (`{ step: "done", rewrapped: true }`), or `{ step: "unlock_local", vault_id, vault_name, hello: true }`, or the server's copy (`{ step: "previous_password", reset: true }` if it needs the old password), or `{ step: "done", warning }` |
| `server_reset_hello` | `{ vaultId, password }` | after `unlock_local`: Windows Hello unlocks that vault, which is re-wrapped with `password`, saved and uploaded with the new token |
| `server_signin_new_vault` | `{ password }` | after a reset with no way to decrypt the old vault: a new empty vault replaces it on the server (`webdav_replace`; the old file stays as a version), local copies of the old vault become plain local vaults "(before reset)". `{ step: "done", new_vault: true, warning }` |
| `server_request_reset` | `{ serverUrl, userOrEmail, pins }` | "Forgot password?": `server_request_reset`. `{ sent: true }`, or `{ step: "trust", … }` like `server_signin`; error text when the server can't send e-mail or rate-limits |
| `server_signin` | `{ serverUrl, username, password, pins }` | §3.4 sign-in. `{ step: "choose_password", username, vault_exists }`, `{ step: "previous_password" }`, or `{ step: "done", warning }` (vault created/downloaded, listed as `<user>@<host>`, unlocked). The token stays in Rust between steps. `serverUrl` is what the user typed (address or the link's server); `username` may be the user name or the account's e-mail address, sent as typed. Without pins, a certificate that isn't publicly trusted answers `{ step: "trust", server_url, host, pin }` (pin from `fetch_server_pin`): the window shows "Trust this server?" with the pin's characters in groups of four and, if confirmed, calls again with `pins: [pin]` (§3.2). A successful sign-in remembers the server, user and pins as `last_server_*` |
| `server_signin_set_password` | `{ current, newPassword }` | replaces the admin-set password, then continues like `server_signin` |
| `server_signin_previous` | `{ previous, password }` | the server's vault still uses `previous`: unlock with it, re-wrap with `password`, upload. `{ step: "done", warning }` |
| `server_signin_cancel` | – | forgets the pending sign-in (the device stays registered on the server) |
| `server_change_password` | `{ current, newPassword }` | Settings → This vault → Change password (unlocked Passyble Server vault): checks `current` against the vault, changes the server password, re-wraps (rotating the key if the old password was admin-set), saves, uploads. `{ warning, rotated, others_signed_out }`; `others_signed_out` is true when the account already had a password, i.e. the server signed the account's other devices out (setting the first password of a token-only account signs out nobody) |
| `server_adopt_password` | `{ password }` | "Changed on another device?" and "Sign in again": the server checks the password (`server_verify_password` with this device's token). If the token was revoked (another device changed the password, or this device was signed out) or is gone, it signs in again with the password (`server_login`: the account's real name and this device's name; an admin-set password is refused), stores the new token and leaves the signed-out state. It re-wraps the unlocked vault with the password only if the vault doesn't already use it. `{ warning, unchanged, signed_in }`, or `{ unchanged: true }` when the token still worked and the password is the vault's |
| `server_devices` | – | Settings → Signed-in devices: the active Passyble Server vault's devices (`server_list_devices`). `{ signed_out: false, devices: [ServerDevice] }` with `ServerDevice { id, name, created_at, last_used_at, current, limited }` (times in unix ms; `last_used_at` may be `null`; `current` = this device; `limited` = signed in with an admin-set password not changed yet), or `{ signed_out: true }` when this device has no token or the server refused it |
| `server_sign_out_device` | `{ deviceId }` | "Sign out" on a device in that list (`server_revoke_device`). `{ current }`: true when it was this device, whose token is then deleted and the vault marked signed out ("Sign in again" → `server_adopt_password`). Error "That device was already signed out." if the server doesn't know it |

`sync-status` / `SyncStatus` (`status.sync`) is `{ last_sync_ms, last_error, running, pending, sign_in_needed, signed_out }`.
`signed_out` (Passyble Server) is set when the server refuses this device's token (a WebDAV or account-API
401/403 "authentication failed": the password was changed on another device, or this device was signed
out from the device list, or `server_sign_out_device` ran for it) and cleared when a new token is stored or
the server accepts the token again. While it is set, background sync stops retrying and `last_error` is
"Signed out of Passyble Server. Sign in again…"; the vault view shows "Signed out · Sign in again". A sync that
fails for another reason (offline, say) leaves the flag as it was. When Passyble Server answers 507 (per-account
storage quota), the error reads "Your Passyble Server storage is full…" with the server's message.

`pass+server://` links clicked anywhere (registered URL scheme, §3.1) arrive like `server.pair` links: the
main window takes them with `server_pair_take`. Links with a one-time code open the code flow; while a vault
is unlocked they open in a dialog without locking it (so a reset can re-wrap that vault).

`unlock` of a Passyble Server vault whose local copy rejects the password downloads the server's copy and, if
that opens with the password (it was changed on another device), merges the local copy into it, replaces
the local file and unlocks (`signin::refresh_from_server`).

The token goes to Windows Credential Manager like a WebDAV password; the pins and the device name are
stored with the vault's `webdav` settings.

### Desktop app commands for Teams and Family (Tauri `invoke`, main window only; not on the wire)

`desktop-app/src-tauri/src/{account,teams,teams_vaults,teams_admin,teams_send}.rs`; `desktop-app/README.md`, "Teams
and Family". Account: `account_status`, `account_sign_in`, `account_sign_in_cancel`, `account_sign_out` (`signOutExtension`:
the Sign out confirmation's browser extension box). Member:
`teams_overview` (`visible: false` for a user without an account in a Team or Family and without a shared vault),
`teams_refresh`, `teams_publish_keys`, `teams_invite_answer`, `shared_vault_info`, `shared_vault_rename`,
`shared_vault_leave`, `shared_trust_confirm`, `item_share` (`mode`: `move` | `copy`), `direct_share_start`,
`vault_items_vaults`, `teams_notifications_seen`, `teams_notices_dismiss`, `policy_status`. Secure send, emergency
access, admin recovery: `send_create`, `send_list`, `send_revoke`, `send_pick_file`, `emergency_status`,
`emergency_add`, `emergency_remove`, `emergency_request`, `emergency_answer`, `emergency_open`, `emergency_items`,
`admin_recovery_status`, `admin_recovery_enroll`, `admin_recovery_withdraw`, `admin_recovery_request`,
`admin_recovery_finish`. Admin: `org_overview`, `org_members`, `org_invite`, `org_invite_csv`, `org_invite_resend`,
`org_invite_cancel`, `org_confirm` (checks the fingerprint, then adds the person to every shared vault they should
be in that this user manages), `org_set_role`, `org_offboard` (rotations and the "change the passwords they could
see" list), `org_departments`, `org_department_create`, `org_department_rename`, `org_department_delete`,
`org_department_member`, `org_vault_create`, `org_vault_access`, `org_vault_delete`, `org_policies`,
`org_policies_set`, `org_member_password_mode` (a Team member's own password mode, or the team's),
`org_activity`, `org_admin_recovery_requests`, `org_admin_recovery_approve`, `org_billing_open`.
The item commands (`list_items`, `search`, `get_item`, `save_item` with `vault_id`, ...) span every open vault
and add `vault_id` / `vault` (`VaultRef`) when several are open; a fill-only member's item comes with
`password_hidden: true` and without its password, history and hidden field values.

## 3. Passyble Server

[Passyble Server](https://github.com/sensyble/PassybleServer) is an optional self-hosted host for the encrypted vault file. To clients it is a
WebDAV server: `webdav_sync` / `webdav_download` / `webdav_exists` work with
`WebDavConfig { url, username, password, pins }`. Devices get those four fields in one of two ways:

* **Sign in with the account password** (§3.4): the admin creates the account with an initial password
  the user must replace (`pass-server user add`; never for admin accounts, which, like invited users,
  choose their password through a one-time link, §3.5), the user signs in with server address + user name + password (or a sign-in link
  from `pass-server invite`) → `server_login` → `server_session_webdav_config` (§1). The same password is the
  vault's master password; the server never learns it.
* **Pairing link** with a device token (`pass-server pair`): `parse_pairing_link(link)` →
  `pairing_webdav_config(parsed)` (§1). Kept for token-only accounts and advanced setups.

With e-mail configured, the admin can create the account **without** a password: the user gets an invite
link with a one-time code and chooses the password themselves; "Forgot password?" e-mails a reset link
(§3.5).

### 3.1 `pass+server://` links: pairing and sign-in

Two kinds of link share the scheme and are told apart by `token`:

* **Pairing link** (with `token`): printed with a QR code by `pass-server pair <user> --device <name>`.
  The device can sync right away. Specified below.
* **Sign-in link** (no `token`): printed with a QR code by `pass-server invite <user>`. Only says where the
  server is, who signs in and which certificate to pin; the user then enters the account password (§3.4).
  It holds no secret.

```text
pass+server://<host>[:<port>][<base path>]/?v=1&user=<user>[&pin=<pin>]...[&scheme=http]

pass+server://pass.example.com:8443/?v=1&user=alice&pin=sha256:novcWsacBi2IRLwBIN7QCQVpLOAGPBXRFHKFijjSE-g
```

Sign-in link rules: same `v`, `user` (required), `pin` and `scheme` as below; the path (may be empty, `/`,
or a reverse-proxy prefix like `/pass/`) is the server's base path: `server_url = <scheme>://<host>[:<port>]`
+ the path without its trailing `/`. `token` must be absent (an empty `token=` is an error). `name` is
ignored. `invite=<code>` or `reset=<code>` (at most one, non-empty, never together with `token`) carries a
one-time code that sets the account password without the old one (`POST /api/v1/password` with `code`,
§3.4); these links come from invite and reset e-mails and from `pass-server user invite` / `user reset`
(§3.5). Clients parse it (`ServerLink.code`, `code_kind`) and show "Choose your password" instead of the
sign-in form. Clients that see a link without `token` must not reject it: show the sign-in form (the browser
extension hands it to the desktop app with `server.pair`, which opens that form).

```text
pass+server://pass.example.com:8443/?v=1&user=alice&invite=psc_3q2-7wQx_VJmL0n1o2p3qA&pin=sha256:novcWsacBi2IRLwBIN7QCQVpLOAGPBXRFHKFijjSE-g
```

**URL scheme registration.** The Windows app registers `pass+server` (HKCU `Software\Classes\pass+server`,
by the NSIS/MSI installer from `plugins.deep-link` in `tauri.conf.json`, and at start-up by debug builds), so
clicking such a link (in an e-mail, or the "Open in Pass" button of the §3.5 page) opens Passyble, or hands the
link to the running instance (single-instance plugin), with the matching form filled in. A link never
changes anything by itself: the user confirms in the form. Android should declare an intent filter for the
scheme (`<data android:scheme="pass+server" />`) and treat a received link exactly like a scanned one.

**Pairing links** follow. Android scans them; the Windows app and the browser extension accept them pasted.

```text
pass+server://<host>[:<port>]<path>?v=1&user=<user>&token=<token>[&name=<device name>][&pin=<pin>]...[&scheme=http]

pass+server://pass.example.com:8443/dav/alice/personal.vault?v=1&user=alice&token=pst_kr3RuvCRcaQ29nq0oGvtM8RWx1_YAaPvx1qy-J047Hw&name=Pixel%209&pin=sha256:novcWsacBi2IRLwBIN7QCQVpLOAGPBXRFHKFijjSE-g
```

| part | required | meaning |
|---|---|---|
| `pass+server://` | yes | scheme (RFC 3986 allows `+`) |
| `<host>[:<port>]` | yes | URL authority exactly as in the HTTPS URL: DNS name, IPv4, or `[IPv6]`; default port 443 |
| `<path>` | yes | absolute, percent-encoded path of the vault file, e.g. `/dav/alice/personal.vault` (may carry a reverse-proxy prefix: `/pass/dav/...`) |
| `v` | yes | link format version, `1`. Reject other values |
| `user` | yes | HTTP Basic username (the account) |
| `token` | yes (pairing) | HTTP Basic password: `pst_` + 43 base64url chars (32 random bytes). A secret. Absent = sign-in link (above) |
| `name` | no | the device name registered on the server (UTF-8, display only) |
| `pin` | no, repeatable | `sha256:` + base64url without padding (43 chars) of SHA-256 of the server certificate's DER **SubjectPublicKeyInfo**. Present when the server uses its self-signed certificate |
| `scheme` | no | `https` (default) or `http`. `http` only for servers on loopback or a private/VPN network. pass-core refuses `http://` server addresses (`InvalidInput`) unless the host is `localhost`/`*.localhost`, `*.local`, `*.home.arpa`, or an IP in 127/8, 10/8, 172.16/12, 192.168/16, 169.254/16, 100.64/10, ::1, fc00::/7 or fe80::/10 |

Query values are percent-encoded UTF-8 (`%20` for space, never `+`); `:` may appear unencoded. Unknown
parameters are ignored, so later versions can add optional ones. A fragment, if any, is ignored.

Client algorithm:

1. Check the prefix `pass+server://` and `v=1`; require `user`, `token` and a path.
2. `url = <scheme or "https">://<host>[:<port>]<path>` (keep the path's percent-encoding as is).
3. Store `WebDavConfig { url, username: user, password: token }` and the pins with the sync settings
   (the token and pins in the platform's secure storage).
4. With pins: connect with pin verification (§3.2) instead of normal certificate validation. Without:
   normal validation (publicly trusted certificate, e.g. Let's Encrypt or a reverse proxy).
5. Show the host and device name and ask the user to confirm before saving; then run `webdav_download`
   (new device) or `webdav_sync`. `GET /api/v1/whoami` can be used as a connection test.

In Rust and Kotlin use pass-core's `parse_pairing_link` / `parse_server_link` (§1), which implement exactly
this and are tested against the vectors in `Core/core/tests/pairing_vectors.json` (`expect` = pairing link,
`signin` = sign-in link, both null = rejected) together with the server's reference parsers
(`pass_server::pairing::PairingLink::parse` / `ServerLink::parse`). The browser extension hands a link to the desktop app with `server.pair` (§2).

Parsing tips: Kotlin `android.net.Uri.parse(link)` handles it (`host`, `port`, `encodedPath`,
`getQueryParameters("pin")`). In JavaScript, `new URL(link.replace(/^pass\+server:/, "https:"))` gives
`host`, `pathname` and `searchParams` consistently across browsers. In Rust, `url::Url::parse` works, and
`pass_server::pairing::PairingLink::parse` is the reference implementation (with tests).

QR codes contain the link itself (byte mode, error correction L).

### 3.2 Certificate pinning (`pin=`)

A pinned connection accepts the server if and only if the SHA-256 of the **leaf certificate's
SubjectPublicKeyInfo** (DER) equals one of the pins. Chain, host name and validity dates are not checked
(the certificate is self-signed), but the TLS handshake signature **must** still be verified against
that certificate's key, which proves the server holds the pinned private key. When pins are present they
replace CA validation entirely (a CA-issued certificate with another key is rejected).

**Implemented in pass-core** (`Core/core/src/pinning.rs`, used by `Core/core/src/webdav.rs`), on `ureq` 2.12 with
its rustls 0.23 (ring). Without pins the server is validated against the webpki-roots trust store as
before (a self-signed server is rejected). With pins:

* `WebDavConfig.pins: Vec<String>` (UniFFI field with default `[]`); the desktop app stores it with the
  vault's WebDAV settings, Android with its sync settings.
* `Core/core/Cargo.toml`: a direct `rustls = { version = "0.23", default-features = false, features = ["ring",
  "std", "tls12"] }` (the same instance ureq uses, enabled by the `webdav` feature) and `sha2`.
* When `pins` is non-empty, the client builds
  `rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
  .with_safe_default_protocol_versions()?.dangerous().with_custom_certificate_verifier(Arc::new(PinVerifier{..}))
  .with_no_client_auth()` and passes it to `ureq::AgentBuilder::tls_config`. `PinVerifier` implements
  `rustls::client::danger::ServerCertVerifier`: `verify_server_cert` extracts the SPKI from the end-entity
  DER and compares `"sha256:" + b64url(SHA-256(spki))` with the pins; `verify_tls12_signature` /
  `verify_tls13_signature` delegate to `rustls::crypto::verify_tls12_signature` /
  `verify_tls13_signature` with the provider's `signature_verification_algorithms`;
  `supported_verify_schemes` returns that list's schemes. The SPKI comes from a 40-line DER walk
  (`spki_from_cert`, the same as in `Server/src/tls.rs`); `pass_core::spki_pin(cert_der)` computes a pin.
* A pin mismatch is `PassError::CertificateChanged` ("server certificate changed, pair this device
  again: …", naming the pin the server presented), not a generic network error.
* Browser extension: page JavaScript cannot pin certificates. Sync through the desktop app/agent (which
  uses pass-core), or use a publicly trusted certificate.
* **Trust on first use** (desktop sign-in by address, no link): when the sign-in fails because the certificate
  isn't publicly trusted and no pin was given, the app fetches the server's pin without trusting it
  (`pass_core::fetch_server_pin`), shows it ("Trust this server?", the base64url characters after `sha256:` in
  groups of four, the same characters `pass-server status` prints) and pins it only after the user confirms.
  From then on the pin is used like one from a link; a different key later is `CertificateChanged`.

### 3.3 HTTP API

Authentication: `Authorization: Basic base64(user:token)` (what WebDAV clients send) or
`Authorization: Bearer <token>`. A Basic username must be the token's account (in any case) or the
account's e-mail address. Failures return 401 with
`WWW-Authenticate: Basic realm="Passyble Server"`. After `max_failures` failures from one IP within
`window_secs`, every request from it gets 429 with `Retry-After` for `lockout_secs`.

Wrong passwords (`login`, `password`, `verify`) also count per account from any IP: after
`account_max_failures` (10) within `account_window_secs` (900), each further attempt for that account waits
(429 + `Retry-After`): 1 min, doubling per further failure, at most `account_max_backoff_secs` (900). The wait
is checked before the password, so a right password gets the same 429. It is forgotten after
`account_window_secs` without failures or after a successful sign-in, so there is no permanent lockout.
Unknown account names are treated alike. Wrong two-factor codes (§3.7) count exactly like wrong passwords in all three limiters; a request that merely lacks the code does not. With `[email]` and an address, the account gets one
`failed_sign_ins` notice per hour at most.

| method and path | auth | result |
|---|---|---|
| `GET /dav/<owner>/<vault>.vault` | device | 200 + bytes + `ETag`; 304 if `If-None-Match` matches; 404 before the first upload |
| `HEAD /dav/<owner>/<vault>.vault` | device | as GET without body |
| `PUT /dav/<owner>/<vault>.vault` | device | 201 created / 204 replaced, with the new `ETag`; 412 if a precondition fails (with the current `ETag`) |
| `OPTIONS /dav/...` | none | `Allow: OPTIONS, GET, HEAD, PUT`, `DAV: 1` |
| other methods on `/dav/...` | | 405 |
| `GET /healthz` | none | `ok` |
| `GET /api/v1/info` | none | `{ "service": "pass-server", "name", "version", "api": 1, "public_url", "features": { "password_login", "username_or_email", "email", "password_reset", "signup": "closed"\|"invite"\|"open", "versions", "two_factor" (`[auth] two_factor`: users may turn on two-factor sign-in, §3.7), "security_events" (the audit log is on, §3.8) } }`. Nothing about accounts. `Cache-Control: no-store`, `Access-Control-Allow-Origin: *`. For "Connect to *name*?" before trusting a server (§3.2, trust on first use) |
| `POST /api/v1/signup` | none | §3.6 |
| `GET /status` | admin account's device | JSON: version, uptime, TLS mode and pin, user/device counts, vaults (size, modified, versions), backup schedule, targets and last results |
| `GET /api/v1/whoami` | device | `{ "user", "device_id", "device_name", "admin", "vaults": [ { "vault": "alice/personal", "path": "/dav/alice/personal.vault" } ] }` |
| `GET /api/v1/devices` | full device | `{ "user", "devices": [ { "id", "name", "created_at", "last_used_at" (unix ms or null, ±5 min), "current", "limited" } ] }`, oldest first; `Cache-Control: no-store`; 403 for a limited device |
| `DELETE /api/v1/devices/<id>` | full device | signs out one of the caller's account's devices (the caller itself too): `{ "revoked", "name", "current" }`; 404 `no such device` for unknown ids and other accounts' devices; DELETE needs a CORS preflight |
| `GET /api/v1/vaults/<owner>/<vault>/versions` | device | `{ "vault", "versions": [ { "id", "replaced_at" (unix ms), "size" } ] }`, newest first |
| `GET /api/v1/vaults/<owner>/<vault>/versions/<id>` | device | the version's bytes |
| `DELETE /api/v1/vaults/<owner>/<vault>/versions` | device (owner) | `{ "removed": n }`: every previous version deleted, the live file kept. For after a password change rotated the key (`server_purge_versions`). Owner only (403 `not_vault_owner`, 403 `read_only_member`); needs `Content-Type: application/json` (415 otherwise) |
| `POST /api/v1/vaults/<owner>/<vault>/versions/<id>/restore` | device | `{ "etag", "previous_version" }`; the replaced file becomes a version. Needs `Content-Type: application/json` (the body is empty; 415 otherwise); 507 if the owner's quota is exceeded |
| `GET /api/v1/2fa` | full device | §3.7: `{ "enabled", "pending", "enabled_at", "recovery_codes_left", "available" }` |
| `POST /api/v1/2fa/setup`, `/confirm`, `/disable` | full device (+ password or code) | §3.7: turn two-factor sign-in on and off |
| `GET /api/v1/security-events[?limit=N]` | full device | §3.8: the account's newest audit-log events |
| `GET /metrics` | metrics token, or this machine | §3.9: Prometheus text; only with `[metrics] enabled` |
| `POST /api/v1/prelogin` | none | §3.4: `{ "kdf": { "alg", "m_kib", "t", "p" }, "salt" }` |
| `POST /api/v1/login` | password (`auth_key`) | §3.4: a new device token |
| `POST /api/v1/password` | device + old `auth_key`, or a one-time code | §3.4: sets the account password |
| `POST /api/v1/verify` | device | §3.4: `{ "ok": bool }` |
| `POST /api/v1/reset/request` | none | §3.5: e-mails a reset link; always `202 { "accepted": true }` |
| `GET /link/invite/<code>`, `GET /link/reset/<code>` | the code | §3.5: HTML page behind e-mailed links; 404 page if unknown/expired/used |

* A device may use a vault its account owns or was granted (`pass-server vault grant`); otherwise 403
  (also for vaults that do not exist). A **limited** device (signed in with an admin-set password that was
  not changed yet, §3.4) gets 403 on `/dav/`, the versions API and `/status`; `whoami` (with
  `"limited": true`), `password` and `verify` work. `whoami` also returns `vault_path`, `vault_exists`,
  `has_password`, `must_change_password`, `password_admin_known` and `two_factor` (the account has two-factor sign-in on, §3.7).
* **ETags** are strong, derived from content: `"` + first 32 hex digits of SHA-256(file) + `"`.
  Identical bytes have identical ETags across restarts, restores and backups.
* **PUT preconditions** (RFC 9110 §13.2): `If-None-Match: *` creates only if absent; `If-Match: <etag>`
  replaces only if the current file has that strong ETag (`W/` tags never match; `If-Match: *` requires an
  existing file). Without either header the PUT is unconditional. The core client sends
  `If-None-Match: *` for a new remote and `If-Match` with the last ETag it saw (GET, 304 or its own PUT)
  otherwise, and on 412 downloads, merges and retries (4 attempts).
* **Conditional GET**: the core client sends `If-None-Match: <etag>` once it has synced; an unchanged
  vault costs one `304` with no body. The server answers it from an ETag cached by file metadata (a
  `stat`, no read or hash). See ARCHITECTURE.md §10 for when clients ask at all.
* PUT bodies must be at most `max_vault_bytes` (default 64 MiB; 413) and, unless
  `require_vault_format = false`, a JSON object with `"format": "pass-vault"` (400), and fit the owner's
  storage quota `max_account_bytes` (default 256 MiB, current files + versions of all vaults it owns): over
  it, the owner's oldest versions are deleted (as a last resort the replaced file isn't kept as a version);
  if the current files alone exceed it, 507 Insufficient Storage with a `text/plain` message (also for
  version restore). pass-core reports it as `Network("upload: storage quota reached: <message>")`. Version
  retention default: `keep_last` 20, `keep_days` 90. Bodies must arrive within 300 s (408). Writes are atomic
  (temp file, fsync, rename) and serialized per vault.
* **Errors** carry a short message: `text/plain`, or JSON `{ "error": <code>, "message" }` for the
  two-factor answers (§3.7). The message is for people and is in the request's language (§3.10): the
  account's language when the request is signed in (device token, or the right password or one-time code),
  else the best match for `Accept-Language`, else `[server] default_language`; `Content-Language` names it.
  Every such error also has a stable code in the `X-Pass-Error` header (for JSON errors the same as
  `error`): `too_many_sign_ins`, `too_many_resets`, `too_many_signups`, `password_change_required` (a limited
  device), `no_vault_access`, `vault_not_uploaded`, `quota_exceeded` (507), `email_unavailable`,
  `enter_user_or_email`, `signup_closed`, `invalid_user_name`, `enter_email`, `choose_user_name`,
  `choose_password`, `user_name_taken`, `invalid_device_name`, `kdf_unsupported`, `kdf_out_of_range`,
  `unknown_language`, `no_such_device`, `not_found`, `internal_error`, `wrong_password`,
  `authentication_required`, `invalid_credentials`, `invalid_request` (followed by an English detail). They
  are the `[api]` keys of `Server/locales/en/strings.toml`. **Clients match the status, the code or the JSON
  `error`, never the message text**: every message, including `password_change_required`,
  `no_such_device` and `email_unavailable`, is in the request's language. Status codes, `WWW-Authenticate`, `Retry-After` and the
  other headers don't depend on the language. Messages only a client bug can cause (415, 413, 408, malformed
  headers) and admin-only answers (`/status`, `/metrics`) stay English and have no code.
  pass-core reads `X-Pass-Error` and words the answers apps act on itself, in the app's language
  (`set_language`, §1): `password_change_required` → `Network(server.password_change_required)`,
  `email_unavailable` → `Network(server.cant_send_email)`, `unknown_language` →
  `Network(server.unknown_language)` (with the server's message as detail), `no_such_device` →
  `NotFound(server.no_such_device)`; apps match these keys with `core_message_is`, not text. Older
  servers without the header still work through their English text.
* JSON endpoints (`POST /api/v1/...`, including version restore) require `Content-Type: application/json`
  (415 otherwise): a web page can't send that cross-site without a CORS preflight, which the server doesn't
  answer. IPv6 clients are rate-limited per /64. A successful sign-in no longer resets the IP's failure
  count (only the account's and the (account, IP) pair's). `pass-server user remove` moves the account's
  files to `<data_dir>/removed/` instead of deleting them. Changing an account's e-mail address cancels
  its pending invite or reset code.

### 3.4 Accounts and passwords (sign in, zero-knowledge)

One password per user is both the Passyble Server sign-in and the vault's master password. The admin creates
the account and its first password; the user replaces it in the app. The server never receives the
password, nothing derived with the vault's salt, or the vault key.

**Derivation** (client; `pass_core::server_auth_key`, `pass_server::password`; vectors in
`Core/core/tests/server_auth_vectors.json`, checked by both):

```text
master   = Argon2id(password UTF-8, salt, m_kib, t, p, 32 bytes)      salt, params: per account, public
auth_key = HKDF-SHA256(IKM = master, salt = (none: 32 zero bytes), info = "pass-server-auth", L = 32)
server stores verifier = hex SHA-256(auth_key) + salt + params        (state.json, users.<name>.password)
```

Defaults are the vault's: Argon2id m = 65536 KiB, t = 3, p = 1, 16-byte random salt. Clients and server
refuse parameters outside m 19456..=1048576 KiB, t 2..=20, p 1..=16 (a hostile server can't make clients
derive a cheap, brute-forceable `auth_key`, nor make them allocate gigabytes). The verifier is SHA-256, not
a slow hash: `auth_key` is a uniformly random 256-bit value, so a stolen `state.json` only lets an attacker
test password guesses at full Argon2id cost per guess, the same cost as attacking the vault file the server
already stores. Comparisons are constant-time.

The vault's KEK uses the vault file's own random salt (ARCHITECTURE.md §1), so `auth_key` and `master`
reveal nothing about the vault key; going from `auth_key` to the vault requires guessing the password.

**Endpoints** (JSON bodies ≤ 16 KiB; errors are `text/plain`):

| request | auth | answer |
|---|---|---|
| `POST /api/v1/prelogin` `{ "user" }` | none | `{ "kdf": { "alg": "argon2id", "m_kib", "t", "p" }, "salt": "<b64url>" }`. Unknown users and users without a password get the default parameters and a fake salt = first 16 bytes of HMAC-SHA256(server secret, "prelogin:" + user), stable across requests and restarts (the secret is in `state.json`), so the answer doesn't reveal whether the account exists |
| `POST /api/v1/login` `{ "user", "auth": "<b64url auth_key>", "device_name", "otp"? }` | password (+ `otp` with two-factor, §3.7) | 200 `{ "user", "token", "device_id", "device_name", "vault", "vault_path", "vault_exists", "must_change_password", "password_admin_known" }`: a new device (same token mechanism as `pass-server pair`, HTTP Basic for WebDAV). `vault_path`: the user's `personal` vault, else the first owned, else the first shared one (`null` if none). While `must_change_password`, the device is **limited** (§3.3). 401 `wrong user name or password` (no `WWW-Authenticate`), for an account with two-factor sign-in and a right password 401 JSON `2fa_required` / `2fa_invalid` (§3.7), 429 + `Retry-After` when locked out, 400 bad request |
| `POST /api/v1/password` `{ "old_auth"?, "user"?, "code"?, "new_salt", "new_kdf", "new_auth", "sign_out_other_devices"?, "otp"? }` | device token + `old_auth` (or + `code`); or no token + `user` + `code` | 200 `{ "must_change_password": false, "devices_revoked": n }`. Sets the verifier from `new_auth` (32 bytes), `new_salt` (16–64 bytes), `new_kdf` (bounds above; 400 otherwise); clears `must_change_password` and `password_admin_known`, lifts the limit on the account's devices, consumes any one-time code. Authorized by a **reset** code, it also revokes **every** device token of the account, the caller's included (`devices_revoked`). Authorized by a device token and `old_auth`, it revokes every **other** device of the account (`devices_revoked`; the caller stays signed in) unless `"sign_out_other_devices": false` (default `true`); setting the first password of an account without one revokes nothing. An account without a password (pairing only) may set its first one with the device token alone. 401 wrong old password / code (unknown, expired or already used; checked again under the state lock, so a code works exactly once). For an account with two-factor sign-in the request also needs `otp` whichever way it is authorized, including a reset or invite `code`: 401 JSON `2fa_required` / `2fa_invalid` (§3.7), and the one-time `code` is not used up by such an answer |
| `POST /api/v1/verify` `{ "auth" }` | device | `{ "ok": bool }`. For a device whose vault is unlocked after the password was changed elsewhere |

Failed `login`, `password` and `verify` attempts (and wrong two-factor codes, §3.7) count against the per-IP limiter of §3.3, a per-(account, IP)
limiter with the same `[auth]` settings, and the per-account backoff of §3.3; any of them answers 429.

**Account names** are case-insensitive: stored lowercase (`[a-z0-9_-]`, 1-64 characters), and every
request that names an account (`prelogin`, `login`, `password` with `user` + `code`, `reset/request`, the
Basic user name) trims and lowercases it first. A name containing `@` is looked up as an e-mail address
(case-insensitive); it resolves when exactly one account has that address, otherwise it is treated as
unknown (stable fake `prelogin` answer keyed on what was typed, 401 on `login`). `login` returns the real
account name in `user`; clients use that afterwards. Older `state.json` files with mixed-case names are
renamed on start (vault directories too); names that would collide stop the server with a message naming
them.

**One-time codes** (e-mail invites and password resets, §3.5): `State::issue_password_code(user,
"invite"|"reset", ttl)` stores SHA-256 of a `psc_…` code (16 random bytes, base64url) with an expiry, and
replaces any earlier code of the account; `POST /api/v1/password` with `user` + `code` sets the password once.
Links carry it as `invite=` / `reset=` (§3.1). Accounts have an optional `email` (`pass-server user add
--email`, `user set-email`).

**Client flows** (Windows app: `Core/desktop-app/src-tauri/src/signin.rs`):

1. *Sign in*: `server_prelogin` → derive → `server_login`; if it answers `2fa_required`, ask for the authenticator or recovery code and call `server_login_2fa` (§3.7). If `must_change_password`: ask for a new password
   ("your admin won't know it") → `server_change_password(old = initial, new)`; continue with the new one.
2. *Vault*: `vault_exists == false` → `Vault::create(password)` → `webdav_sync` (uploads, `If-None-Match: *`).
   Otherwise `webdav_download` → `Vault::unlock(password)`; `InvalidPassword` means the vault still uses an
   older password (admin `reset-password`): ask for the previous password → `Vault::unlock(previous)` →
   `vault.change_password(previous, new, rotate_key = false)` → `webdav_sync`. The vault is created only after
   the user chose their own password, so the admin never knows a password that encrypts it.
3. *Change password* (unlocked): `vault.check_password(old)` → `server_account` → `server_change_password`
   (**server first**) → `vault.change_password(old, new, rotate_key = password_admin_known)` → save →
   `webdav_sync`. If the upload fails it is retried by background sync; a device signing in meanwhile gets
   `InvalidPassword` from the vault and asks for the previous password (step 2), which repairs it. The
   opposite order could leave a vault on a password the server rejects, with no way to sign in to fix it.
   `rotate_key` when the old password was the admin's (`password_admin_known`: an account an older server
   created with the since removed `--no-force-change`): the admin could otherwise read later items with the
   old key from an old version of the file. Current servers always force an admin-set password to be
   replaced before the vault exists, so new accounts never reach this case.
4. *Password changed elsewhere*: unlocking with the new password fails on the local copy → download the
   server's copy, unlock it, merge the local copy (same key, or an older key listed in `previous_keys`),
   replace the local file. A password change signs out the other devices, so a device that is still unlocked gets 401 "…signed out" on its next request: `server_login(new)` (store the new token) → `vault.change_master_password(new)` → sync. `server_verify_password(new)` remains for devices whose token still works (`sign_out_other_devices: false`). Changing the vault password this way needs no old password (the device holds the vault key); this is also
   the recovery path when the old password is forgotten.

**Admin CLI**: `pass-server setup` (guided first configuration and first account; Server/README.md),
`pass-server status`, `pass-server doctor`; `pass-server user add <name or e-mail address> [--email E]
[--password-stdin] | --no-password` (an address alone derives the name and sends an
invite; every command that takes a user also accepts the account's address and any case), `pass-server user reset-password <name> [--password-stdin]`,
`pass-server invite <name>` (sign-in link + QR). The CLI derives the verifier itself (random salt, default
parameters), so the initial password is never written anywhere, and the user must always replace it
(`must_change`) at the first sign-in. Without a terminal and without
`--password-stdin`, `user add` fails rather than hang. `user reset-password` also **revokes all device
tokens** of the account (like a reset code): devices sign in again with the new password.

**Admin accounts never get a password from the server.** The first admin (`setup --admin`, `PASS_ADMIN`)
and every `user add --admin` are created without a verifier and with a one-time invite code (§3.5), which
the CLI prints as a setup link (and e-mails with e-mail set up); the admin chooses the password in a
Passyble app, so only the client-derived `auth_key` reaches the server. `user add --admin` refuses
`--password-stdin` / `--initial-password`, and `user reset-password` refuses admin accounts (`user reset`
issues a reset code instead). The removed `setup --admin-password-stdin` flag, the `PASS_ADMIN_PASSWORD`
environment variable and `--no-force-change` are rejected with an error that explains the setup link (a
`serve` whose config already exists only warns about a leftover `PASS_ADMIN_PASSWORD`). E-mail commands:
§3.5.

### 3.5 E-mail: invites and password resets

Optional (`[email]` in the server config: SMTP over STARTTLS / implicit TLS / plain to a local relay; links
point to `server.public_url`, the pages may use `email.public_url`). The server sends:

* **invite** (`pass-server user add <name> --email E` creates the account without a password;
  `pass-server user invite <name> [--resend]`): a one-time `invite` code, valid `invite_ttl_hours` (7 days);
* **reset** (`POST /api/v1/reset/request`, `pass-server user reset <name> --email`): a one-time `reset`
  code, valid `reset_ttl_minutes` (60). An account without a password gets an `invite` code instead;
* notifications: password changed (default on; not for the first password), new device signed in with the
  password (default off), failed sign-ins (default on, `notify_failed_sign_ins`; when the per-account backoff
  starts, at most once an hour per account).

The CLI prints the links (and a QR code) as well, so invites and resets work without e-mail too
(`--no-email`, `user add --invite`, `user reset` without `--email`).

Each code e-mail carries two links:

```text
https://pass.example.com:8443/link/invite/psc_3q2-7wQx_VJmL0n1o2p3qA                         (page)
pass+server://pass.example.com:8443/?v=1&user=alice&invite=psc_3q2-7wQx_VJmL0n1o2p3qA&pin=…   (app link, §3.1)
```

| request | auth | answer |
|---|---|---|
| `POST /api/v1/reset/request` `{ "user" }` or `{ "email" }` (a `user` containing `@` is an address) | none | `202 { "accepted": true }` for every well-formed request, sent before any lookup: the answer and its timing don't depend on the account. In the background: for the account (or every account with that address, case-insensitive, at most 5) that has an address, issue a `reset` code (replacing earlier codes) and e-mail it. At most `reset_max_per_hour` e-mails per account and per address and hour (more are dropped silently); `reset_max_per_hour_per_ip` requests per IP and hour, then 429 + `Retry-After`. 400 empty; 503 `text/plain` when the server has no `[email]` |
| `GET /link/invite/<code>`, `GET /link/reset/<code>` | the code | 200 HTML: account, server, expiry, an **Open in Passyble** button (the app link), the app link as an inline-SVG QR code and as text, next steps (install, open/scan, choose password; for resets what a reset can recover). Does **not** use the code (mail scanners prefetch links). Unknown, expired, used, or the other kind: 404 HTML page, counted as a failure for the IP (`[auth]` limits, 429 when locked out). Headers: `Content-Security-Policy: default-src 'none'; style-src 'sha256-…'; img-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'` (no scripts), `Referrer-Policy: no-referrer`, `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY` |

* The code sits in the page's URL path: acceptable because it is single-use and short-lived, and the page
  sends no referrer; it may remain in browser history and reverse-proxy logs. Passyble Server never logs codes.
* E-mailed links are built from the configured URLs, never from the request's `Host` (no reset-link
  poisoning). The app link carries the self-signed certificate's pin when `server.public_url` is used.
* Using a **reset** code revokes every device token of the account (§3.4); an **invite** code doesn't.

**Zero-knowledge consequence.** The server can't decrypt or re-encrypt the vault. A reset restores the
account, not the vault's encryption: the vault on the server still opens only with the old password. Client
flow after the user chose the new password (`server_set_password_with_code`, or `server_set_password_with_code_2fa` after a `2fa_required` answer, §3.7):

1. `server_login(new)` (the reset signed out this device too) → a new token; store it with the sync settings.
2. *Invite*: `vault_exists == false` → `Vault::create(new)` → `webdav_sync` (uploads). Otherwise as §3.4 step 2.
3. *Reset*, in order:
   1. this device has the account's vault **unlocked** → `vault.change_master_password(new)` (no old password
      needed), save, `webdav_sync` with the new token;
   2. it has a local copy that **biometrics / Windows Hello** can unlock (the vault key is wrapped by the
      platform) → unlock it that way → as 3.1;
   3. download the server's copy → `Vault::unlock(new)` (another device may have re-wrapped it already) →
      done; `InvalidPassword` → ask for the **previous password** → `Vault::unlock(previous)` →
      `vault.change_password(previous, new, rotate_key = false)` → `webdav_sync`;
   4. nothing works: offer **Start a new empty vault**, with a clear warning that the current items are
      lost unless the old password turns up → `Vault::create(new)` → `webdav_replace(config, vault)`. The old
      vault stays on the server as a version (`GET /api/v1/vaults/<owner>/<vault>/versions`, restorable); the
      Windows app also keeps its local copy as a plain local vault "(before reset)".
4. Other devices get 401 on their next sync ("authentication failed … signed out") → ask the user to sign in
   again with the new password; if their vault is still unlocked, `vault.change_master_password(new)` after
   signing in (or §3.4 step 4).

Windows: `Core/desktop-app/src-tauri/src/signin.rs` (`server_code_set_password`, `server_reset_hello`,
`server_signin_new_vault`, `server_request_reset`) and `Core/desktop-app/ui/views/signin.js`.

**Android needs** (UniFFI, §1): `parse_server_link` (the `code` / `code_kind` fields),
`server_set_password_with_code`, `server_login`, `server_request_reset` ("Forgot password?" on the sign-in
screen: server address + user name or e-mail), `webdav_download` / `Vault::unlock` / `change_password` /
`change_master_password`, `webdav_sync`, and `webdav_replace` (instead of a Kotlin re-implementation of
pinning for overwrites). Link handling: an intent filter for `pass+server` (VIEW, BROWSABLE, DEFAULT) so
taps on the e-mailed app link open the app, the QR scanner accepting code links, and the flow above, with
the biometric-wrapped vault key as step 3.2. Show `InvalidPassword` from `server_set_password_with_code` as
"this link has expired or was already used".

### 3.6 Self sign-up and server info

`server.signup` in the config: `"closed"` (default), `"invite"` (needs `[email]`) or `"open"`. Clients read
it from `GET /api/v1/info` (`features.signup`) and offer "Create an account" only when it isn't `closed`.

| request | mode | answer |
|---|---|---|
| `POST /api/v1/signup` any body | `closed` | 403 `text/plain` "sign-up is closed on this server; ask its administrator for an invite" |
| `{ "email", "user"? }` | `invite` | `202 { "accepted": true, "check_email": true }` for every well-formed address, sent before any lookup. In the background: unless an account already has that address (then nothing happens), create the account (not admin; vault `personal`; `user` if valid and free, else derived from the address: local part before `+`, lowercase, other characters → `-`, made unique with a number), store the address, issue an `invite` code (§3.4, `invite_ttl_hours`) and e-mail it like an admin invite. The account is marked `signup_pending`; if the invite expires unused it is removed (at the next sign-up request). 400 invalid address / name |
| `{ "user", "new_salt", "new_kdf", "new_auth" }` | `open` | `201 { "user", "created": true }`: the account with that password (the user's own: not `must_change`), vault `personal`; then `POST /api/v1/login`. A `user` with `@` only serves to derive the name (no address is stored: it would be unverified). 409 name taken, 400 invalid name / password parameters (same rules as `POST /api/v1/password`) |

All modes: at most `server.signup_max_per_hour` requests per IP and hour (default 5) and 20 times that in
total, then 429 + `Retry-After`; `invite` also shares the per-address e-mail quota of §3.5.

**Trust on first use with `/info`** (a server typed by address, no link): `server_info(url, [])`; on a
certificate error, `fetch_server_pin(url)` and show the pin, asking the user to compare it with what
`pass-server status` prints (nothing the server says can be trusted before that); once confirmed,
`server_info(url, [pin])` → "Connect to *name*?" → `server_login(url, user, password, device, [pin])`, and
store the pin with the sync settings.

### 3.7 Two-factor sign-in (TOTP)

Optional per account (`[auth] two_factor`, default `true`: `false` stops new setups, accounts that already use it keep it).
With it on, a **password** sign-in (`login`) and every **password change** (`POST /api/v1/password`: with the old
password, with a reset code, or with an invite code) also need a second factor in `otp`: the 6-digit code of an
authenticator app (RFC 6238: HMAC-SHA1, 6 digits, 30 s, 20-byte secret) or a **recovery code**. Devices that already
exist keep syncing with their token: the second factor guards sign-ins, not every request. `pass-server pair` (the
admin, on the server) issues a device token without a code, as before. An account needs a password to set it up (an
account without one can't use two-factor sign-in yet).

* **TOTP codes**: accepted for the current 30-second step and one step either side (clock drift), and only for a step
  **after** the last one accepted for the account: a used code or any older one is refused, even within its 30 seconds
  (no replay). The secret is kept readable in `state.json` (and in backups with `include_state`); it signs in nobody
  without the password, which the server never has.
* **Recovery codes**: 10, shown once when it is turned on, `xxxx-xxxx-xxxx` (60 random bits, base32 lower case; typed in
  any case, dashes and spaces optional). Stored as SHA-256, each works once and is removed. A request value of 6 digits
  is tried as a TOTP code, anything else as a recovery code.
* **Errors**: 401 with a JSON body `{ "error": "2fa_required" | "2fa_invalid", "message": "…" }` and
  `Cache-Control: no-store` (the only JSON error shape on the account endpoints; everything else is `text/plain`).
  `error` (also in `X-Pass-Error`) never changes; `message` is in the request's language (§3.3), so clients
  match `error` only.
  `2fa_required`: the password (or reset code) was right and the account uses two-factor sign-in, but the request had no
  `otp`. It is checked after the password, so it tells a guesser nothing, and it is **not** counted as a failure: the
  client asks for the code and sends the same request again. `2fa_invalid`: a wrong, expired or already used code; it
  **counts like a wrong password** (per IP, per account and IP, and the per-account slowdown with its e-mail notice,
  §3.3), and 429 + `Retry-After` answers while locked out. A code is checked again under the state lock when it is used,
  so two racing requests can't both use it. `pass_core` maps both to `PassError::InvalidInput("2fa_required: …")` /
  `("2fa_invalid: …")` (§1). A client that doesn't know the code field just sees a 401 and a failed sign-in; nothing is signed in
  without the code.
* **Reset links**: using a `reset=` or `invite=` link (`POST /api/v1/password` with `user` + `code`) on a two-factor account
  still needs `otp`. The one-time code is only used when the whole request succeeds, so `2fa_required` / `2fa_invalid`
  leave the link working. Someone who reads the user's mail can't take over the account with the link alone. An
  admin `user reset-password` and reset links leave two-factor sign-in on.
* **Lost authenticator and recovery codes**: only the admin can help: `pass-server user 2fa-reset <name>` turns it off
  (audit event `2fa_reset`; their devices stay signed in; `pass-server user list` shows `2fa: on`).

| request | auth | answer |
|---|---|---|
| `GET /api/v1/2fa` | full device | `{ "enabled", "pending" (set up, not confirmed), "enabled_at" (unix ms or null), "recovery_codes_left" (0 when off), "available" (`[auth] two_factor`, or already on) }`; `Cache-Control: no-store` |
| `POST /api/v1/2fa/setup` `{ "auth": "<b64url auth_key>" }` | full device + the account password | 200 `{ "secret": "<base32>", "otpauth_uri", "issuer", "account", "algorithm": "SHA1", "digits": 6, "period": 30 }`: a new secret (replacing an unconfirmed one), **not active yet**; show the URI as a QR code. The issuer is the server's name (without a `:port`). Wrong password: 401 `text/plain` like `login` and counted. 409 JSON `2fa_already_enabled` (turn it off first to change the authenticator) / `no_password`; 403 JSON `2fa_unavailable` (`[auth] two_factor = false`) |
| `POST /api/v1/2fa/confirm` `{ "code" }` | full device | the first code of the new authenticator turns it on: 200 `{ "enabled": true, "recovery_codes": [10 codes] }` (shown once, never stored in clear). Wrong code: 401 `2fa_invalid` (counted). 409 `2fa_not_pending` |
| `POST /api/v1/2fa/disable` `{ "auth", "code"? }` | full device + password + a current code | 200 `{ "enabled": false }`. `code` is a TOTP or recovery code (a never-confirmed setup is dropped without a code). Wrong password 401 text (counted), missing code 401 `2fa_required`, wrong code 401 `2fa_invalid` (counted). 409 `2fa_not_enabled`. Turning it off and on again is also how a user gets new recovery codes |

A limited device (an admin-set password not changed yet, §3.3) gets 403 on all of these. Client: `server_login_2fa`,
`server_change_password_2fa`, `server_set_password_with_code_2fa`, `server_two_factor_status|setup|confirm|disable` (§1).
Audit events: `2fa_setup_started`, `2fa_enabled`, `2fa_disabled`, `2fa_recovery_code_used` (`count` = codes left),
`2fa_reset`, and `sign_in` with `detail` `totp` | `recovery_code` (§3.8).

### 3.8 Security events and audit log

`[audit]` (on by default) writes `<data_dir>/audit.log`: one JSON object per line, append-only, rotated by size
(`max_bytes`, default 10 MiB, `0` = never; `keep` = 5 rotated files `audit.log.1` …). The server and the admin CLI both append
to it (under a lock file). A line: `{ "ts" (unix ms), "time" (RFC 3339), "event", "actor", "user"?, "device_id"?,
"device_name"?, "ip"?, "detail"?, "count"? }`. `actor`: `user` (the account's device or password), `admin` (the CLI),
`server` (on its own, e.g. a reset e-mail), `anonymous` (no valid credentials, e.g. a wrong password). Events: `sign_in`,
`sign_in_failed` (`detail` `password` | `2fa`), `token_rejected`, `account_slowed_down` (`count` = failures),
`device_added` (`pair`), `device_revoked`, `password_changed` (`detail` `old_password` | `first_password` |
`reset_code` | `invite_code`; `count` = devices signed out), `password_reset_requested`, `2fa_setup_started`,
`2fa_enabled`, `2fa_disabled`, `2fa_recovery_code_used`, `2fa_reset`, `signup`, and the admin commands `user_added`,
`user_removed`, `email_changed`, `admin_password_reset`, `invite_issued`, `reset_link_issued`. **Never** passwords,
`auth_key`s, tokens, one-time or two-factor codes or anything derived from them; a name typed for an account that doesn't
exist is logged as `(unknown)`. Admin side: `pass-server audit [--user U] [--since 7d|date] [--event E]... [--limit N]
[--json]` (oldest first of the newest N, default 200, `0` = all).

| request | auth | answer |
|---|---|---|
| `GET /api/v1/security-events[?limit=N]` | full device | `{ "user", "events": [ { "ts", "event", "actor", "device_id", "device_name", "ip", "detail", "count", "current" } ] }`, the caller's **own** account, newest first, `limit` 1..=200 (default 50). `current`: the event was made by the calling device. `token_rejected` is left out (an old device signed out by a reset produces it on every sync). `Cache-Control: no-store`. 404 `text/plain` when `[audit] enabled = false` (`/info` then says `"security_events": false`), 403 for a limited device |

Client: `server_security_events` (§1) for a "Recent activity" screen; show unknown `event` names generically.

### 3.9 Metrics

`[metrics] enabled = true` (off by default) serves `GET /metrics` in the Prometheus text format
(`text/plain; version=0.0.4`, `Cache-Control: no-store`): `passyble_http_requests_total{route,method,status}` (route
**templates** such as `/dav/{owner}/{file}`, never account or file names), `passyble_sign_in_failures_total{kind="password"|"2fa"|"token"}`,
`passyble_backoff_triggers_total{limiter="ip"|"account_ip"|"account"}`, `passyble_sign_ins_total{method="password",second_factor="none"|"totp"|"recovery_code"}`,
gauges `passyble_accounts`, `passyble_accounts_two_factor`, `passyble_devices`, `passyble_vaults`, `passyble_vault_bytes`,
`passyble_vault_versions`, `passyble_vault_version_bytes`, `passyble_backup_last_run_timestamp_seconds`,
`passyble_backup_last_run_ok`, `passyble_backup_last_success_timestamp_seconds{target}`, `passyble_uptime_seconds` and
`passyble_build_info{version}`. Nothing in it names an account or holds a secret.

**Access** (not the device tokens of §3.3):

* `token` set (at least 16 characters): `Authorization: Bearer <token>` (compared in constant time); otherwise 401
  `metrics: authentication required` with `WWW-Authenticate: Bearer realm="Passyble Server metrics"`.
* No `token`, `/metrics` on the main listener: only requests from the server's own machine (loopback peer) that did not
  pass through a proxy, i.e. none of `X-Forwarded-For`, `X-Real-IP`, `Forwarded`; everything else is 401 as above.
  Behind a reverse proxy that adds none of these headers the proxy's own connection would look local: set a `token` (or
  don't route `/metrics`).
* `listen = "127.0.0.1:9464"`: `/metrics` is served on its own plain-HTTP listener (nothing else is served there) and
  **not** on the main one (404). A non-loopback address is refused at start unless a `token` is also set; with a token
  the listener requires it too.

### 3.10 Languages

E-mails, their subjects and the server's link pages (invite, reset, expired link) are translated. Built-in languages are
the `Server/locales/<tag>/` directories (`en` is the source); `[server] default_language` (default `en`) is used when
nothing else decides. Server tags are BCP 47 (`zh-CN`, `id`); requests are matched loosely (`zh-Hans` → `zh-CN`,
`in` → `id`, `hi-IN` → `hi`, else the base language) and Accept-Language q-values are respected.

* Each account has an optional `language` (state.json). E-mails use it, else the default. Landing pages use the
  account's language when the link identifies the account, else Accept-Language, else the default.
* It is set by `POST /api/v1/signup` (`language`, else Accept-Language), `POST /api/v1/password` (an explicit
  `language` always; with an invite or reset code, Accept-Language only when the account has none), and
  `POST /api/v1/login` (Accept-Language fills in a missing language, never replaces one).
* `GET /api/v1/language` / `POST /api/v1/language {"language": "de" | null}` (device token) return
  `{language, default_language, languages: [{tag, name}]}`; an unavailable language is 400 listing the available ones.
  `whoami` carries `language`; `info` carries `features.language`, `default_language` and `languages`.
* CLI: `pass-server user set-language <user> <locale>` (or `--clear`), `user add … --language <locale>`.
* Core: `set_server_language(Option<String>)` (process-wide; sent as `Accept-Language` on every server request; call at
  start-up and when the app language changes) and `server_set_language(server_url, username, token, language, pins)`
  for accounts already signed in. The apps pass the same language to `set_language` (§1), which translates the core's
  own messages.

* API error messages (§3.3) are translated too: the signed-in account's language, else Accept-Language, else the
  default. Their codes (`X-Pass-Error`, JSON `error`) are the same in every language; clients match those.

Admin CLI output, logs, `/status` and `/metrics` stay English. See Server/README.md "Languages" for the file layout and
how to add a language.

## 4. Passyble account (`account.passyble.com`)

The optional account service (its source is not public). It is only for Passyble Cloud, Family and Teams; no
free feature uses it. Base URL `https://account.passyble.com` (staging hosts use their own). All times are Unix
**milliseconds**, all ids are opaque strings. Phase 1 (this section) has no billing and no Cloud devices yet.

Status: the service is built; the apps don't use it yet and must keep the account UI behind a development flag until
Phase 2. Sign-up is closed unless the owner allow-lists an address (`GET /v1/info` gives `sign_up_open`); existing
accounts can always sign in.

### 4.1 Discovery

`GET /v1/info` (no authentication):

```json
{ "service": "pass-account", "version": "0.x.y", "api": 1, "sign_up_open": false,
  "methods": { "email": true, "passkey": true, "google": true },
  "authorize_url": "https://account.passyble.com/oauth/authorize",
  "token_url": "https://account.passyble.com/oauth/token",
  "revoke_url": "https://account.passyble.com/oauth/revoke" }
```

`GET /healthz` answers `ok`. `/.well-known/assetlinks.json` lists the Android app (`com.sensyble.passyble`) once the
operator has configured its signing-certificate fingerprints, else `[]`.

### 4.2 App sign-in (OAuth 2.0 for native apps)

Authorization code flow with PKCE (RFC 6749, 7636, 8252), issuer identification in the redirect (RFC 9207) and token
revocation (RFC 7009). The apps are **public clients** (no client secret):

| `client_id` | Allowed `redirect_uri` (compared as exact strings) |
|---|---|
| `passyble-windows` | `http://127.0.0.1:<port>/` or `http://[::1]:<port>/`: any port 1-65535, path exactly `/`, no query, fragment or user info, in canonical form (no default port, no leading zeros, nothing after the `/`). `localhost` is refused. |
| `passyble-android` | one of the operator's list (`[apps] android_redirect_uris`); default `https://account.passyble.com/app/android/callback` (App Link) and `com.sensyble.passyble:/oauth/callback` (custom scheme) |
| `passyble-extension` | `https://<id>.chromiumapp.org/` (the `chrome.identity.launchWebAuthFlow` redirect): `<id>` exactly 32 lowercase characters `a-p`, https, no port, path exactly `/`, no query, fragment or user info, in canonical form. Firefox: `https://<hash>.extensions.allizom.org/` (`identity.getRedirectURL()`), `<hash>` exactly 40 lowercase hex characters, same form rules. Any well-formed id, or only the ids and hashes in the operator's list `[apps] extension_ids` when it is not empty (default empty) |

Until the operator has put the app's certificate fingerprints into `[apps] android_cert_sha256` (so App Links verify),
Android should use the custom scheme.

**1. Prepare.** Generate `state` (random, 1-512 characters; 32 random bytes in base64url are fine), a `code_verifier`
(43-128 characters of `A-Z a-z 0-9 - . _ ~`; 32 random bytes in base64url give 43) and
`code_challenge = BASE64URL-NOPAD(SHA-256(ASCII(code_verifier)))` (always 43 characters). Windows: bind a loopback
listener first (`127.0.0.1`, port 0) and build `redirect_uri` from the port it got.

**2. Open the system browser** (Windows: the default browser; Android: a Custom Tab, never a WebView) at:

```text
GET /oauth/authorize?client_id=passyble-windows&redirect_uri=http%3A%2F%2F127.0.0.1%3A53682%2F
    &response_type=code&code_challenge=<43 chars>&code_challenge_method=S256&state=<state>
    &device_name=<the device's name, for example "Laptop" or "Pixel 9">
```

`device_name` is optional: trimmed, control characters dropped, cut at 64 characters; empty means `Windows` or
`Android`. It is shown on the consent page, in the device list and in the "new sign-in" e-mail. The browser then shows,
as needed: the sign-in page (e-mail code, passkey or Google, and sign-up for new accounts), a fresh sign-in when the
browser's last sign-in is more than 10 minutes old, and the consent page ("Sign in to the Passyble app?") with **Sign
in** and **Cancel**.

**3. The redirect.** The browser is sent (`303`) to the `redirect_uri` with query parameters added:

* success: `?code=pac_<43 chars>&state=<state>&iss=https%3A%2F%2Faccount.passyble.com`
* refused: `?error=access_denied&state=<state>&iss=...` (the user pressed Cancel), `error=invalid_request` (a missing
  or too long `state`, a `code_challenge` that isn't 43 valid characters, a method other than `S256`) or
  `error=unsupported_response_type`. `state` is echoed when it was valid.

The app must check that `state` equals the one it sent and `iss` equals the service origin (of the authorize URL), and
ignore the redirect otherwise. Windows: answer the loopback request with a short "You can close this window" page and
close the listener. If `client_id` or `redirect_uri` is not allowed there is **no redirect**: the browser shows an error
page (`400`, `X-Pass-Error: invalid_client`). So the app needs a Cancel button and should stop waiting after a while
(for example 10 minutes).

**4. Exchange the code** (within 60 seconds; codes are single use):

```text
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=pac_...&code_verifier=<verifier>&client_id=passyble-windows
&redirect_uri=http%3A%2F%2F127.0.0.1%3A53682%2F
```

`redirect_uri` must be the identical string from step 2. Answer `200` (with `Cache-Control: no-store`):

```json
{ "access_token": "pat_...", "token_type": "Bearer", "expires_in": 900,
  "refresh_token": "prt_...", "refresh_token_expires_in": 31536000,
  "session_id": "aps_...", "account": { "id": "acc_...", "email": "alex@example.com" } }
```

The account gets a "New sign-in to your Passyble account" e-mail naming the device. A code presented a second time is
refused **and** signs out the app session that the first exchange created (the code may have been intercepted).

**5. Refresh** when the access token has expired (or will within a minute):

```text
POST /oauth/token
grant_type=refresh_token&refresh_token=prt_...&client_id=passyble-windows
```

Same answer shape with a **new** refresh token; the old one is dead from this moment. Presenting a refresh token that
was already rotated signs the whole app session out (`invalid_grant`; audit event `refresh_token_reused`). So: store
the new refresh token before using the new access token, never refresh from two threads at once, and treat
`invalid_grant` as signed out (show "Sign in again"). The session stays valid for `refresh_token_expires_in` seconds
(365 days) after the **last** refresh; each refresh extends it. A refresh must use the `client_id` the session was
created with.

**6. Sign out this device:**

```text
POST /oauth/revoke
token=<the refresh token or a current access token>&client_id=passyble-windows
```

Always `200 {}` (RFC 7009), also for unknown tokens (`client_id` is optional; when sent it must match). It ends the app
session: its refresh and access tokens stop working at once. Delete the stored tokens either way.

**Token endpoint errors** (`/oauth/token`, `/oauth/revoke`): JSON `{ "error": code, "error_description": text }`
(RFC 6749 section 5.2), the code also in `X-Pass-Error`, `Cache-Control: no-store`. The description is English and
meant for logs; match the code.

| Status | `error` | When |
|---|---|---|
| 400 | `invalid_request` | not a form body, `code` missing, `code_verifier` not 43-128 valid characters, `refresh_token` missing |
| 401 | `invalid_client` | `client_id` is not `passyble-windows`, `passyble-android` or `passyble-extension` |
| 400 | `invalid_grant` | unknown, expired, already used or mismatched code (other `client_id` or `redirect_uri`, wrong verifier); unknown, revoked, expired, rotated or other-client refresh token; disabled account |
| 400 | `unsupported_grant_type` | `grant_type` is not `authorization_code` or `refresh_token` |
| 429 | `too_many_requests` | 20 failed token or bearer requests from one IP (IPv6: one /64) within an hour lock that address out for 15 minutes; `Retry-After` gives the seconds |

Lifetimes: code 60 s, access token 900 s (`expires_in`, an operator setting), app session 365 days, sliding. Tokens
are opaque (`pac_`, `pat_`, `prt_` + 43 base64url characters); the service stores only their SHA-256. Apps keep the
refresh token in OS-protected storage (Windows: DPAPI or Credential Manager; Android: Keystore-backed encryption), keep
the access token in memory, and never log either.

### 4.3 Account API (`/v1`)

Apps send `Authorization: Bearer pat_...`. (The account pages call the same endpoints with their session cookie; then
every request other than `GET` also needs `Origin: https://account.passyble.com` and the page's `X-CSRF-Token`.)
Request bodies are JSON (`Content-Type: application/json`). Answers carry `Cache-Control: no-store`.

Errors: `{ "error": code, "message": text }`, the code also in `X-Pass-Error`. `message` is translated (the account's
language, else `Accept-Language`, else English); apps match `error` only.

| Status | `error` | When |
|---|---|---|
| 401 | `invalid_token` | the access token is unknown, expired or its session was signed out (`WWW-Authenticate: Bearer error="invalid_token"`): refresh, and if that fails, sign in again |
| 401 | `sign_in_required` | no token and no session cookie |
| 403 | `reauth_required` | the endpoint needs a recent sign-in (below) |
| 404 | `no_such_session` | `DELETE /v1/sessions/<id>` for an id that isn't an active session of this account |
| 400 | `confirmation_mismatch` | `POST /v1/account/delete` with a `confirm` that isn't the account's address |
| 429 | `too_many_requests` | the failure lockout of section 4.2 (bad bearer tokens count as failures); `Retry-After` |
| 403 | `bad_origin`, `bad_csrf` | cookie callers only: missing or foreign `Origin`, missing or wrong CSRF token |

**Recent sign-in.** Sign out everywhere and deleting the account need a sign-in within the last 10 minutes. For an app
session that is the browser sign-in behind its code, so these requests work for about 10 minutes after step 4 of
section 4.2. Later, run the sign-in flow again (the browser asks the user to confirm it's them if needed), use the new
tokens for the request, keep them as the device's tokens and revoke the old refresh token (section 4.2 step 6).

| Request | Answer |
|---|---|
| `GET /v1/me` | `200` the account (below) |
| `GET /v1/sessions` | `200 { "sessions": [Session] }`: the account's active web and app sessions |
| `DELETE /v1/sessions/<id>` | `204`: signs that browser (`ses_...`) or app (`aps_...`) out, the caller's own included; `404 no_such_session` |
| `POST /v1/sessions/revoke-all` | `204`: signs out every browser and app of the account, the caller too, and e-mails a notice. Recent sign-in |
| `GET /v1/activity?limit=N` | `200 { "events": [Event] }`, newest first; `limit` 1-500, default 50 |
| `GET /v1/account/export` | `200` the account record as JSON (`Content-Disposition: attachment; filename="passyble-account.json"`) |
| `POST /v1/account/delete` `{ "confirm": "<the account's e-mail address>" }` | `204`: deletes the account at once (below). Recent sign-in |

`GET /v1/me`:

```json
{ "id": "acc_...", "email": "alex@example.com", "created_at": 1793545500000, "locale": "en",
  "methods": {
    "email": { "address": "alex@example.com", "removable": false },
    "passkeys": [ { "id": "pk_...", "name": "Windows Hello on Laptop", "created_at": 1793545500000,
                    "last_used_at": null, "backup_eligible": true, "backup_state": true,
                    "transports": ["internal"] } ],
    "google": { "email_at_link": "alex@gmail.com", "linked_at": 1793545500000, "last_used_at": null } },
  "entitlements": { "cloud_state": "none", "quota_bytes": 0, "orgs": [] } }
```

`locale` and `google` may be `null`. `entitlements` is fixed in Phase 1 (`cloud_state: "none"`); Phase 2 fills it from
the subscription and adds fields, so clients ignore unknown fields everywhere.

`Session`: `{ "id", "kind": "web" | "app", "platform": "web" | "windows" | "android", "name", "created_at",
"last_seen_at", "current" }`. `name` is the app's `device_name` or a browser summary such as "Chrome on Windows";
`last_seen_at` has a resolution of one hour; `current` marks the caller's own session.

`Event`: `{ "ts", "event", "actor", "session_id", "ip", "detail" }`, where `actor` is `user`, `system` or
`admin:<name>`. The `ip` is cleared after 30 days and events are removed after 180 days. Event names: `account_created`,
`sign_in` (`detail.method`: `email`, `passkey` or `google`), `sign_out`, `email_code_sent`, `passkey_added`,
`passkey_removed`, `passkey_counter_regression`, `google_linked`, `google_unlinked`, `app_signed_in` (`detail.client`,
`detail.device`), `session_revoked` (`detail.revoked`), `sign_out_everywhere` (`detail.sessions`),
`refresh_token_reused`, `oauth_code_reused`, `admin_disabled`, `admin_enabled`, `admin_sign_out_everywhere`,
`account_deleted`. More may be added; show unknown names generically.

Export (`format: "passyble-account-export"`, `version: 1`): `exported_at`, `account` (`id`, `email`,
`email_verified_at`, `terms_accepted_at`, `created_at`, `locale`, `status`), `passkeys` (as in `/v1/me`, plus
`credential_id` in base64url), `google` (adds `sub`), `sessions`, `activity`. No tokens or codes.

**Deleting the account** removes at once the account, its e-mail address, passkeys, Google link, every web and app
session and every pending code, and e-mails a confirmation. Security events stay (without the address) for up to 180
days. The address can later sign up again as a new account. Vaults on the devices are not touched. The apps show the
same summary as the web page before calling it, and sign out locally afterwards.

### 4.4 Web pages

The apps may open these in the system browser: `/account` (methods, devices, activity, export, sign out everywhere),
`/delete` (account deletion; also the public deletion URL for Google Play) and `/sign-in`. In Phase 1 sign-in methods
are managed only on the web pages. The pages use same-origin form posts and `fetch` calls with the session cookie
(`__Host-pa_session`, Secure, HttpOnly, SameSite=Lax) and a CSRF token, and load no third-party resources.

| Page or endpoint | Purpose |
|---|---|
| `GET /sign-in`, `POST /sign-in/email`, `GET`/`POST /sign-in/code`, `GET`/`POST /sign-in/link?t=` | e-mail code or link (a link signs in only the browser that asked for it, and only after a button press) |
| `GET`/`POST /sign-up` | new accounts: accept the terms and the privacy policy |
| `GET /auth/google/start`, `GET /auth/google/callback` | Google sign-in and, with `?link=1`, connecting Google |
| `POST /webauthn/login/{options,verify}`, `POST /webauthn/register/{options,verify}` | passkeys (JSON, used by `static/passkey.js`) |
| `POST /account/passkeys/<id>/remove`, `POST /account/google/remove`, `POST /account/sessions/<id>/revoke`, `POST /account/sign-out-everywhere`, `GET /account/export`, `POST /delete`, `POST /sign-out` | account page forms |

Page answers are HTML. Refused form posts show an error page with the code in `X-Pass-Error` (`bad_origin`, `bad_csrf`,
`too_many_requests`). Passkeys use RP ID `account.passyble.com`, discoverable credentials and user verification.

### 4.5 App versions (forced and recommended updates)

`GET /api/app-versions`: no authentication, no cookies, and the apps send no account, device, vault or version data
(the answer lists every platform). `Cache-Control: public, max-age=300`, `Access-Control-Allow-Origin: *`. Unlike
the rest of §4, every app uses it, free ones included. The owner sets the values in the admin console.

```json
{ "v": 1,
  "platforms": {
    "windows": { "minimum": "0.1.0", "recommended": "0.1.2", "message": "Optional plain text, max 280 chars" },
    "linux":   { "minimum": null, "recommended": null },
    "macos": {}, "ios": {}, "android": {},
    "extension-chrome": {}, "extension-edge": {}, "extension-firefox": {}, "extension-opera": {} } }
```

* A missing platform, a missing field or `null` is no requirement. Versions are `MAJOR.MINOR.PATCH`, compared
  numerically; a `-prerelease` or `+build` suffix is ignored on both sides. A malformed value is ignored, never a
  block. A document whose `v` isn't 1 is not used. `message` is plain text, shown as text and cut to 280 characters.
* The apps ask at start and every 6 hours while running (10 s timeout), keep the last good answer with its time, use
  it when a fetch fails, and never block without one. The desktop app (`pass_agent::app_versions`,
  `desktop-app/src-tauri/src/app_versions.rs`) reads `windows`, `linux` or `macos`, keeps the answer in
  `%LOCALAPPDATA%\Pass\app-versions.json` and asks automatically only while "Check for updates automatically" is on
  (and on "Check for updates"). The extension reads `extension-chrome` (Brave and other Chromium browsers too),
  `extension-edge`, `extension-firefox` or `extension-opera`; the Safari extension follows `macos` / `ios`.
* Below `minimum`: the "Update required" screen and read-only mode (§2 "Update required"). Below `recommended`: a
  dismissible "Update available" banner, closed per recommended version.
* The server never sends update URLs: each app has its destination built in (the in-app updater,
  `https://www.passyble.com/download`, or the browser's store page).
