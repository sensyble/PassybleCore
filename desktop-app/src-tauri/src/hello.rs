//! Windows Hello unlock, cryptographically bound to a Windows Hello key.
//!
//! Each vault gets its own Hello key, `Pass-<vault entry id>` (`KeyCredentialManager`: RSA in the
//! TPM, or in software without one; Windows signs only after a Hello gesture). After a
//! master-password unlock the vault key is sealed with a key derived from that key's signature over
//! a random per-vault challenge, wrapped with DPAPI and written to
//! `%LOCALAPPDATA%\Pass\hello\<vault entry id>.bin` (construction in [`keywrap`]). Unlocking asks
//! Windows to sign the challenge again, which shows the Hello prompt.
//!
//! Threat model:
//! * The blob never roams or syncs. DPAPI binds it to this Windows user and PC; the Hello key never
//!   leaves the TPM / NGC key store.
//! * Code running as this user can decrypt the DPAPI layer but not the sealed key inside: that needs
//!   the Hello signature. Such code can still trigger a Hello prompt or read the key from memory
//!   while the vault is unlocked; Hello does not protect against that.
//! * Anyone who knows the Windows PIN passes Windows Hello.
//! * A Hello reset deletes or replaces the key: the blob is discarded and the master password is
//!   asked once, then Hello is set up again.
//! * If Hello keys are unavailable or don't sign deterministically, the vault key is stored with
//!   DPAPI only and the prompt is just a presence check ([`Readiness::note`] tells the user).
//! * The per-vault policy (password every N days, Hello before each fill) is enforced by Pass, not
//!   by cryptography: code running as the user could edit the timestamps.
//! * Turning the setting off or removing the vault deletes the blob and the Hello key. Changing the
//!   master password does not change the vault key, so the blob stays valid.
//!
//! Version 1 blobs (DPAPI only) are migrated at the next master-password or Hello unlock.

pub mod focus;
mod keywrap;
pub mod policy;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use pass_agent::Agent;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub use self::keywrap::HelloKeyError;
use self::keywrap::{Enrolled, HelloKey, OpenError, Protector};
pub use self::policy::HelloPolicy;
use crate::i18n::tr;
use crate::platform;
use crate::settings::local_dir;

const VERSION: u32 = 2;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Mode {
    /// DPAPI only: version 1 files, and PCs whose Hello keys can't be used.
    #[default]
    Dpapi,
    /// Sealed with a key derived from the Hello key's signature, inside DPAPI.
    KeyCredential,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct HelloFile {
    version: u32,
    /// The vault this key belongs to, to refuse a stale blob without prompting.
    vault_id: String,
    #[serde(default)]
    mode: Mode,
    /// The challenge the Hello key signs (base64url), `KeyCredential` mode only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    challenge: Option<String>,
    /// DPAPI blob, base64url.
    blob: String,
    /// Last master-password unlock of this vault on this PC (Unix ms), for the password interval.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    password_unlock_ms: Option<i64>,
    /// Why this vault uses DPAPI only, for the settings page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    note: Option<String>,
    /// File modification time; stands in for `password_unlock_ms` in version 1 files, which
    /// were rewritten at every master-password unlock.
    #[serde(skip)]
    modified_ms: Option<i64>,
}

impl HelloFile {
    fn new(enrolled: Enrolled, vault_id: &str, password_unlock_ms: Option<i64>) -> Self {
        let (mode, challenge, blob, note) = match enrolled {
            Enrolled::Bound { challenge, blob } => (
                Mode::KeyCredential,
                Some(pass_core::b64url_encode(challenge)),
                blob,
                None,
            ),
            Enrolled::DpapiOnly { blob, reason } => (Mode::Dpapi, None, blob, Some(reason)),
        };
        Self {
            version: VERSION,
            vault_id: vault_id.to_string(),
            mode,
            challenge,
            blob: pass_core::b64url_encode(blob),
            password_unlock_ms,
            note,
            modified_ms: None,
        }
    }

    fn legacy(&self) -> bool {
        self.version < VERSION
    }

    fn last_password_ms(&self) -> Option<i64> {
        self.password_unlock_ms.or(if self.legacy() {
            self.modified_ms
        } else {
            None
        })
    }
}

fn now_ms() -> i64 {
    crate::vaults::now_ms()
}

/// `None`: no file. `Some(Err)`: unreadable.
fn read(file: &Path) -> Option<Result<HelloFile, ()>> {
    let bytes = fs::read(file).ok()?;
    Some(
        serde_json::from_slice::<HelloFile>(&bytes)
            .map(|mut f| {
                f.modified_ms = fs::metadata(file)
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_millis() as i64);
                f
            })
            .map_err(|_| ()),
    )
}

fn write(file: &Path, hello: &HelloFile) -> Result<(), String> {
    if let Some(dir) = file.parent() {
        fs::create_dir_all(dir).map_err(not_written)?;
    }
    let tmp = file.with_extension("bin.tmp");
    fs::write(&tmp, serde_json::to_vec(hello).map_err(not_written)?).map_err(not_written)?;
    fs::rename(&tmp, file).map_err(not_written)
}

fn not_written(e: impl std::fmt::Display) -> String {
    crate::errors::logged(tr!("errors.hello_seal_failed"), "Windows Hello file", e)
}

struct WinKey {
    name: String,
    owner: Option<isize>,
}

impl WinKey {
    fn new(vault: &str, owner: Option<isize>) -> Self {
        Self {
            name: key_name(vault),
            owner,
        }
    }
}

impl HelloKey for WinKey {
    fn supported(&self) -> bool {
        platform::hello_key_supported()
    }
    fn ensure(&self) -> Result<(), HelloKeyError> {
        platform::hello_key_ensure(&self.name, self.owner)
    }
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, HelloKeyError> {
        platform::hello_key_sign(&self.name, data, self.owner)
    }
    fn verify_presence(&self, message: &str) -> Result<bool, String> {
        platform::hello_verify(self.owner, message)
    }
    fn verify(&self, data: &[u8], signature: &[u8]) -> Option<bool> {
        let public_key = platform::hello_key_public(&self.name)?;
        Some(keywrap::rsa_pkcs1_sha256_verify(
            &public_key,
            data,
            signature,
        ))
    }
}

struct Dpapi;

impl Protector for Dpapi {
    fn protect(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        platform::dpapi_protect(data)
    }
    fn unprotect(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        platform::dpapi_unprotect(data)
    }
}

/// The Windows Hello key of list entry `vault` (also checked by `Pass.exe --passkey-setup
/// hello-key <vault>`, passkey_provider.rs).
pub(crate) fn key_name(vault: &str) -> String {
    format!("Pass-{vault}")
}

pub fn path(vault: &str) -> PathBuf {
    local_dir().join("hello").join(format!("{vault}.bin"))
}

fn legacy_path() -> PathBuf {
    local_dir().join("hello.bin")
}

/// Settings migration: the vault taking over the old single-vault settings also takes over the old blob.
pub fn adopt_legacy(vault: &str) {
    let legacy = legacy_path();
    let target = path(vault);
    if !legacy.exists() || target.exists() {
        return;
    }
    if let Some(dir) = target.parent() {
        let _ = fs::create_dir_all(dir);
    }
    let _ = fs::rename(legacy, target);
}

pub fn enrolled(vault: &str) -> bool {
    path(vault).exists()
}

/// Marks a vault removed from the list; its Hello data is deleted once the undo window is over.
pub fn removed_marker(vault: &str) -> PathBuf {
    local_dir().join("hello").join(format!("{vault}.removed"))
}

pub fn mark_removed(vault: &str) {
    if !enrolled(vault) {
        return;
    }
    let marker = removed_marker(vault);
    if let Some(dir) = marker.parent() {
        let _ = fs::create_dir_all(dir);
    }
    let _ = fs::write(marker, b"");
}

pub fn unmark_removed(vault: &str) {
    let _ = fs::remove_file(removed_marker(vault));
}

pub fn remove(vault: &str) {
    let _ = fs::remove_file(path(vault));
    unmark_removed(vault);
    platform::hello_key_delete(&key_name(vault));
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Readiness {
    pub enrolled: bool,
    /// The blob is bound to a Windows Hello key (not DPAPI only / not migrated yet).
    pub bound: bool,
    pub ready: bool,
    /// Why not, or why DPAPI only.
    pub note: Option<String>,
}

fn readiness_of(file: &Path, policy: &HelloPolicy, password_this_run: bool, now: i64) -> Readiness {
    match read(file) {
        None => Readiness::default(),
        // Unlock reports the damage (and removes the file).
        Some(Err(())) => Readiness {
            enrolled: true,
            ready: true,
            ..Default::default()
        },
        Some(Ok(f)) => {
            let due = policy::password_required(
                policy.password_interval,
                f.last_password_ms(),
                now,
                password_this_run,
            );
            Readiness {
                enrolled: true,
                bound: f.mode == Mode::KeyCredential && !f.legacy(),
                ready: !due,
                note: if due {
                    password_due_message(policy)
                } else {
                    f.note.clone()
                },
            }
        }
    }
}

pub fn readiness(vault: &str, policy: &HelloPolicy) -> Readiness {
    readiness_of(
        &path(vault),
        policy,
        policy::password_this_run(vault),
        now_ms(),
    )
}

/// Why the master password is needed now; `None` for an interval that is never due.
fn password_due_message(policy: &HelloPolicy) -> Option<String> {
    let interval = policy.password_interval.describe()?;
    Some(tr!("hello.password_due", interval = interval))
}

fn enroll_error(e: HelloKeyError) -> String {
    match e {
        HelloKeyError::Cancelled => tr!("errors.hello_cancelled"),
        other => other.to_string(),
    }
}

fn enroll_file(
    file: &Path,
    key: &dyn HelloKey,
    protector: &dyn Protector,
    vault_key: &[u8],
    vault_id: &str,
    now: i64,
) -> Result<Option<String>, String> {
    let enrolled = keywrap::enroll(key, protector, vault_key, vault_id).map_err(enroll_error)?;
    let hello = HelloFile::new(enrolled, vault_id, Some(now));
    write(file, &hello)?;
    Ok(hello.note)
}

/// After a master-password unlock: a valid blob only gets the new timestamp (no prompt); a missing,
/// stale or version 1 blob is (re-)enrolled, which shows Hello. If cancelled, a version 1 blob is kept.
fn password_unlocked_file(
    file: &Path,
    key: &dyn HelloKey,
    protector: &dyn Protector,
    vault_key: &[u8],
    vault_id: &str,
    now: i64,
) -> Result<Option<String>, String> {
    let existing = read(file).and_then(Result::ok);
    if let Some(mut hello) = existing.clone() {
        if hello.vault_id == vault_id && !hello.legacy() {
            hello.password_unlock_ms = Some(now);
            write(file, &hello)?;
            return Ok(None);
        }
    }
    match enroll_file(file, key, protector, vault_key, vault_id, now) {
        Ok(note) => Ok(note),
        Err(e) => {
            if let Some(mut legacy) = existing.filter(|h| h.vault_id == vault_id && h.legacy()) {
                legacy.password_unlock_ms = Some(now);
                let _ = write(file, &legacy);
            }
            Err(e)
        }
    }
}

/// After a master-password unlock: records the unlock time and sets up or migrates the Hello blob.
/// Returns a note for the user (DPAPI-only fallback); an error means Hello isn't (newly) set up.
pub fn after_password_unlock(
    agent: &Agent,
    vault: &str,
    owner: Option<isize>,
) -> Result<Option<String>, String> {
    // Embedded in "Windows Hello unlock could not be set up: {error}", so the text, not the sentinel.
    let unlocked = agent.vault().ok_or_else(|| tr!("errors.vault_locked"))?;
    let vault_key = Zeroizing::new(unlocked.export_vault_key());
    password_unlocked_file(
        &path(vault),
        &WinKey::new(vault, owner),
        &Dpapi,
        &vault_key,
        &unlocked.vault_id(),
        now_ms(),
    )
}

pub fn enroll(agent: &Agent, vault: &str, owner: Option<isize>) -> Result<Option<String>, String> {
    let unlocked = agent.vault().ok_or(crate::state::VAULT_LOCKED)?;
    let vault_key = Zeroizing::new(unlocked.export_vault_key());
    enroll_file(
        &path(vault),
        &WinKey::new(vault, owner),
        &Dpapi,
        &vault_key,
        &unlocked.vault_id(),
        now_ms(),
    )
}

#[derive(Debug, PartialEq, Eq)]
enum HelloError {
    NotSetUp,
    Damaged,
    OtherVault,
    PasswordDue(String),
    Cancelled,
    Invalidated,
    Failed(String),
}

impl std::fmt::Display for HelloError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotSetUp => f.write_str(&tr!("errors.hello_not_enrolled")),
            Self::Damaged => f.write_str(&tr!("errors.hello_damaged")),
            Self::OtherVault => f.write_str(&tr!("errors.hello_other_vault")),
            Self::PasswordDue(message) => f.write_str(message),
            Self::Cancelled => f.write_str(&tr!("errors.hello_verification_cancelled")),
            Self::Invalidated => f.write_str(&tr!("errors.hello_invalidated")),
            Self::Failed(message) => f.write_str(message),
        }
    }
}

/// The vault key from a blob, plus the file to write once it really unlocked (migration) and a note.
struct Opened {
    key: Zeroizing<Vec<u8>>,
    migrated: Option<HelloFile>,
    note: Option<String>,
}

fn open_error(file: &Path, e: OpenError) -> HelloError {
    match e {
        OpenError::Key(HelloKeyError::Cancelled) => HelloError::Cancelled,
        OpenError::Key(HelloKeyError::NotFound) | OpenError::KeyChanged => {
            let _ = fs::remove_file(file);
            HelloError::Invalidated
        }
        OpenError::Key(HelloKeyError::Unsupported) => {
            HelloError::Failed(tr!("errors.hello_keys_unavailable"))
        }
        OpenError::Key(HelloKeyError::Failed(e)) => HelloError::Failed(e),
        OpenError::Damaged(_) => {
            let _ = fs::remove_file(file);
            HelloError::Damaged
        }
    }
}

fn open_file(
    file: &Path,
    key: &dyn HelloKey,
    protector: &dyn Protector,
    expected_vault_id: Option<&str>,
    policy: &HelloPolicy,
    password_this_run: bool,
    now: i64,
) -> Result<Opened, HelloError> {
    let hello = match read(file) {
        None => return Err(HelloError::NotSetUp),
        Some(Err(())) => {
            let _ = fs::remove_file(file);
            return Err(HelloError::Damaged);
        }
        Some(Ok(hello)) => hello,
    };
    if expected_vault_id.is_some_and(|id| id != hello.vault_id) {
        let _ = fs::remove_file(file);
        return Err(HelloError::OtherVault);
    }
    if policy::password_required(
        policy.password_interval,
        hello.last_password_ms(),
        now,
        password_this_run,
    ) {
        if let Some(message) = password_due_message(policy) {
            return Err(HelloError::PasswordDue(message));
        }
    }
    let Ok(blob) = pass_core::b64url_decode(hello.blob.clone()) else {
        let _ = fs::remove_file(file);
        return Err(HelloError::Damaged);
    };
    if hello.legacy() {
        let (vault_key, enrolled) =
            keywrap::unlock_legacy(key, protector, &blob, &hello.vault_id, &tr!("hello.prompt"))
                .map_err(|e| open_error(file, e))?;
        let migrated =
            enrolled.map(|e| HelloFile::new(e, &hello.vault_id, hello.last_password_ms()));
        let note = migrated.as_ref().and_then(|m| m.note.clone());
        return Ok(Opened {
            key: vault_key,
            migrated,
            note,
        });
    }
    let vault_key = match hello.mode {
        Mode::KeyCredential => {
            let challenge = hello
                .challenge
                .clone()
                .and_then(|c| pass_core::b64url_decode(c).ok())
                .filter(|c| !c.is_empty());
            let Some(challenge) = challenge else {
                let _ = fs::remove_file(file);
                return Err(HelloError::Damaged);
            };
            keywrap::unwrap_bound(key, protector, &challenge, &blob, &hello.vault_id)
        }
        Mode::Dpapi => keywrap::unlock_dpapi_only(key, protector, &blob, &tr!("hello.prompt")),
    }
    .map_err(|e| open_error(file, e))?;
    Ok(Opened {
        key: vault_key,
        migrated: None,
        note: None,
    })
}

/// Windows Hello prompt, then unwrap, then unlock. Blocking. `vault` must be the list entry the agent
/// points at; the prompt is brought in front of `owner`.
pub fn unlock(
    agent: &Arc<Agent>,
    vault: &str,
    owner: Option<isize>,
    policy: &HelloPolicy,
) -> Result<Option<String>, String> {
    unlock_attempt(agent, vault, owner, policy).map_err(|f| f.message)
}

/// Why [`unlock_attempt`] didn't unlock: the sentence for the user, and whether the Windows Hello
/// prompt was cancelled (by the user in its dialog, or by [`focus::cancel`]).
#[derive(Debug)]
pub struct UnlockFailure {
    pub message: String,
    pub cancelled: bool,
}

pub fn unlock_attempt(
    agent: &Arc<Agent>,
    vault: &str,
    owner: Option<isize>,
    policy: &HelloPolicy,
) -> Result<Option<String>, UnlockFailure> {
    let file = path(vault);
    // The vault id from the vault file's cleartext header only (the rest is decoded once, by
    // the unlock).
    let vault_id = agent.vault_file_id();
    pass_agent::timing::mark("hello: vault file checked");
    let opened = open_file(
        &file,
        &WinKey::new(vault, owner),
        &Dpapi,
        vault_id.as_deref(),
        policy,
        policy::password_this_run(vault),
        now_ms(),
    )
    .map_err(|e| UnlockFailure {
        cancelled: matches!(e, HelloError::Cancelled),
        message: e.to_string(),
    })?;
    pass_agent::timing::mark("hello: key derived");
    agent
        .unlock_with_key(opened.key.to_vec())
        .map_err(|e| UnlockFailure {
            cancelled: false,
            message: match e {
                pass_core::PassError::InvalidPassword => {
                    let _ = fs::remove_file(&file);
                    tr!("errors.hello_key_stale")
                }
                other => other.to_string(),
            },
        })?;
    if let Some(migrated) = &opened.migrated {
        let _ = write(&file, migrated);
    }
    Ok(opened.note)
}

// A Passyble account key (AK) is kept like a vault key: one Hello key per account,
// `Pass-account-<account id>`, and `%LOCALAPPDATA%\Pass\helloccount-<account id>.bin`, the AK sealed
// under that key's signature inside DPAPI and bound to `ak:<account>:<ak_id>` (a replaced account key
// is refused without a prompt). Without usable Hello keys the AK is kept only when the user turned
// on "Remember on this PC", which uses DPAPI only and needs no gesture.

pub(crate) fn account_entry(account: &str) -> String {
    let safe: String = account
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .take(80)
        .collect();
    format!("account-{safe}")
}

pub(crate) fn account_binding(account: &str, ak_id: &str) -> String {
    format!("ak:{account}:{ak_id}")
}

/// How an account key is kept: `(true, binding)` with Hello, `(false, binding)` DPAPI only; `None` not kept.
pub(crate) fn account_kept(account: &str) -> Option<(bool, String)> {
    match read(&path(&account_entry(account)))? {
        Ok(f) => Some((f.mode == Mode::KeyCredential, f.vault_id)),
        Err(()) => None,
    }
}

pub(crate) fn account_readiness(account: &str, policy: &HelloPolicy) -> Readiness {
    readiness(&account_entry(account), policy)
}

fn account_store_file(
    file: &Path,
    key: &dyn HelloKey,
    protector: &dyn Protector,
    account_key: &[u8],
    binding: &str,
    remember: bool,
    now: i64,
) -> Result<(), String> {
    let enrolled = if remember {
        keywrap::dpapi_only(protector, account_key, &tr!("account_keys.remembered"))
            .map_err(enroll_error)?
    } else {
        match keywrap::enroll(key, protector, account_key, binding).map_err(enroll_error)? {
            Enrolled::DpapiOnly { reason, .. } => return Err(reason),
            bound => bound,
        }
    };
    write(file, &HelloFile::new(enrolled, binding, Some(now)))
}

/// Keeps `account_key` on this PC under Hello (a prompt), or under DPAPI only with `remember`.
/// An error leaves nothing written.
pub(crate) fn account_store(
    account: &str,
    account_key: &[u8],
    binding: &str,
    owner: Option<isize>,
    remember: bool,
) -> Result<(), String> {
    let entry = account_entry(account);
    account_set_aside(account, binding);
    account_store_file(
        &path(&entry),
        &WinKey::new(&entry, owner),
        &Dpapi,
        account_key,
        binding,
        remember,
        now_ms(),
    )
}

fn account_open_file(
    file: &Path,
    key: &dyn HelloKey,
    protector: &dyn Protector,
    binding: &str,
    policy: &HelloPolicy,
    password_this_run: bool,
    now: i64,
) -> Result<Zeroizing<Vec<u8>>, HelloError> {
    match read(file) {
        Some(Ok(f)) if f.mode == Mode::Dpapi && f.vault_id == binding => {
            if policy::password_required(policy.password_interval, f.last_password_ms(), now, password_this_run) {
                if let Some(message) = password_due_message(policy) {
                    return Err(HelloError::PasswordDue(message));
                }
            }
            let blob = pass_core::b64url_decode(f.blob.clone()).map_err(|_| HelloError::Damaged)?;
            protector
                .unprotect(&blob)
                .map(Zeroizing::new)
                .map_err(|_| {
                    let _ = fs::remove_file(file);
                    HelloError::Damaged
                })
        }
        _ => open_file(file, key, protector, Some(binding), policy, password_this_run, now).map(|o| o.key),
    }
}

/// The kept account key after the Hello prompt. A blob for a key other than `binding` is removed without a prompt.
pub(crate) fn account_open(
    account: &str,
    binding: &str,
    owner: Option<isize>,
    policy: &HelloPolicy,
) -> Result<Zeroizing<Vec<u8>>, UnlockFailure> {
    let entry = account_entry(account);
    // A blob of another key is left as it is (never removed: it may be the current key while the
    // vault asked for is from before a reset, or an old key still opening such vaults); it moves
    // aside only when a new key is kept (`account_store`) or the key change is known.
    if account_kept(account).is_some_and(|(_, kept)| kept != binding) {
        return Err(UnlockFailure {
            cancelled: false,
            message: HelloError::OtherVault.to_string(),
        });
    }
    account_open_file(
        &path(&entry),
        &WinKey::new(&entry, owner),
        &Dpapi,
        binding,
        policy,
        policy::password_this_run(&entry),
        now_ms(),
    )
    .map_err(|e| UnlockFailure {
        cancelled: matches!(e, HelloError::Cancelled),
        message: e.to_string(),
    })
}

pub(crate) fn account_password_used(account: &str) {
    let entry = account_entry(account);
    policy::mark_password_unlock(&entry);
    let file = path(&entry);
    if let Some(Ok(mut f)) = read(&file) {
        f.password_unlock_ms = Some(now_ms());
        let _ = write(&file, &f);
    }
}

pub(crate) fn account_forget(account: &str) {
    let entry = account_entry(account);
    if account_old_kept(account).is_empty() {
        remove(&entry);
    } else {
        let _ = fs::remove_file(path(&entry));
        unmark_removed(&entry);
    }
}

// When the account key is replaced, the old key's blob moves to
// `account-<account id>.old-<old ak_id>.bin` (same Hello key), so this PC can still open vaults
// linked to the old key and relink them.

fn binding_ak_id<'a>(account: &str, binding: &'a str) -> Option<&'a str> {
    binding
        .strip_prefix("ak:")
        .and_then(|rest| rest.strip_prefix(account))
        .and_then(|rest| rest.strip_prefix(':'))
        .filter(|id| !id.is_empty())
}

fn file_safe(text: &str) -> String {
    text.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .take(64)
        .collect()
}

fn account_old_path_in(dir: &Path, account: &str, ak_id: &str) -> PathBuf {
    dir.join(format!("{}.old-{}.bin", account_entry(account), file_safe(ak_id)))
}

fn account_old_path(account: &str, ak_id: &str) -> PathBuf {
    account_old_path_in(&local_dir().join("hello"), account, ak_id)
}

fn account_set_aside_in(dir: &Path, account: &str, binding: &str) {
    let current = dir.join(format!("{}.bin", account_entry(account)));
    let Some(Ok(f)) = read(&current) else { return };
    if f.vault_id == binding {
        return;
    }
    match binding_ak_id(account, &f.vault_id) {
        Some(old) => {
            let _ = fs::rename(&current, account_old_path_in(dir, account, old));
        }
        None => {
            let _ = fs::remove_file(&current);
        }
    }
}

pub(crate) fn account_set_aside(account: &str, binding: &str) {
    account_set_aside_in(&local_dir().join("hello"), account, binding);
}

fn account_old_kept_in(dir: &Path, account: &str) -> Vec<String> {
    let prefix = format!("{}.old-", account_entry(account));
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out: Vec<String> = entries
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().into_string().ok())
        .filter_map(|name| {
            name.strip_prefix(&prefix)
                .and_then(|rest| rest.strip_suffix(".bin"))
                .map(str::to_string)
        })
        .filter(|ak_id| matches!(read(&account_old_path_in(dir, account, ak_id)), Some(Ok(_))))
        .collect();
    out.sort();
    out
}

pub(crate) fn account_old_kept(account: &str) -> Vec<String> {
    account_old_kept_in(&local_dir().join("hello"), account)
}

/// An older account key kept on this PC. No password interval applies.
pub(crate) fn account_open_old(account: &str, ak_id: &str, owner: Option<isize>) -> Result<Zeroizing<Vec<u8>>, UnlockFailure> {
    let entry = account_entry(account);
    let policy = HelloPolicy {
        password_interval: policy::PasswordInterval::Never,
        ..HelloPolicy::default()
    };
    account_open_file(
        &account_old_path(account, ak_id),
        &WinKey::new(&entry, owner),
        &Dpapi,
        &account_binding(account, ak_id),
        &policy,
        true,
        now_ms(),
    )
    .map_err(|e| UnlockFailure {
        cancelled: matches!(e, HelloError::Cancelled),
        message: e.to_string(),
    })
}

pub(crate) fn account_forget_old(account: &str, ak_id: &str) {
    let _ = fs::remove_file(account_old_path(account, ak_id));
    if account_old_kept(account).is_empty() && account_kept(account).is_none() {
        remove(&account_entry(account));
    }
}

#[cfg(test)]
mod tests {
    use super::keywrap::fake::{FakeDpapi, FakeKey};
    use super::policy::PasswordInterval;
    use super::*;

    #[test]
    fn an_older_account_key_is_kept_aside_and_still_opens() {
        let file = tmp_file("account-old");
        let dir = file.parent().unwrap().to_path_buf();
        let key = FakeKey::default();
        let dpapi = FakeDpapi(3);
        let p = policy(PasswordInterval::Never);
        let old = account_binding("acc_1", "OLD_id");
        let current = dir.join(format!("{}.bin", account_entry("acc_1")));
        account_store_file(&current, &key, &dpapi, &KEY, &old, false, NOW).unwrap();
        account_set_aside_in(&dir, "acc_1", &old);
        assert!(current.exists());
        account_set_aside_in(&dir, "acc_1", &account_binding("acc_1", "NEW_id"));
        assert!(!current.exists());
        assert_eq!(account_old_kept_in(&dir, "acc_1"), ["OLD_id"]);
        assert!(account_old_kept_in(&dir, "acc_2").is_empty());
        let aside = account_old_path_in(&dir, "acc_1", "OLD_id");
        let opened = account_open_file(&aside, &key, &dpapi, &old, &p, false, NOW).unwrap();
        assert_eq!(opened.as_slice(), &KEY);
        assert_eq!(binding_ak_id("acc_1", &old), Some("OLD_id"));
        assert_eq!(binding_ak_id("acc_2", &old), None);
        let _ = fs::remove_dir_all(&dir);
    }

    const KEY: [u8; 32] = [9u8; 32];
    const DAY: i64 = 24 * 60 * 60 * 1000;
    const NOW: i64 = 1_800_000_000_000;

    fn tmp_file(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("pass-hello-test-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir.join("vault.bin")
    }

    fn policy(interval: PasswordInterval) -> HelloPolicy {
        HelloPolicy {
            password_interval: interval,
            ..Default::default()
        }
    }

    #[test]
    fn enroll_unlock_and_password_interval() {
        let file = tmp_file("interval");
        let key = FakeKey::default();
        let dpapi = FakeDpapi(3);
        let p14 = policy(PasswordInterval::FourteenDays);
        assert_eq!(
            enroll_file(&file, &key, &dpapi, &KEY, "vid", NOW).unwrap(),
            None
        );
        let r = readiness_of(&file, &p14, false, NOW + DAY);
        assert!(r.enrolled && r.bound && r.ready && r.note.is_none());

        let opened = open_file(&file, &key, &dpapi, Some("vid"), &p14, false, NOW + DAY)
            .ok()
            .unwrap();
        assert_eq!(opened.key.as_slice(), KEY);
        assert!(opened.migrated.is_none());

        let signs = key.signs.get();
        let late = NOW + 14 * DAY;
        assert!(matches!(
            open_file(&file, &key, &dpapi, Some("vid"), &p14, false, late)
                .err()
                .unwrap(),
            HelloError::PasswordDue(_)
        ));
        assert_eq!(key.signs.get(), signs);
        let r = readiness_of(&file, &p14, false, late);
        assert!(!r.ready && r.note.unwrap().contains("every 14 days"));
        password_unlocked_file(&file, &key, &dpapi, &KEY, "vid", late).unwrap();
        assert_eq!(key.signs.get(), signs);
        assert!(open_file(&file, &key, &dpapi, Some("vid"), &p14, false, late + 1).is_ok());

        let restart = policy(PasswordInterval::AfterRestart);
        assert!(matches!(
            open_file(&file, &key, &dpapi, Some("vid"), &restart, false, late)
                .err()
                .unwrap(),
            HelloError::PasswordDue(_)
        ));
        assert!(open_file(&file, &key, &dpapi, Some("vid"), &restart, true, late).is_ok());
        let never = policy(PasswordInterval::Never);
        assert!(open_file(
            &file,
            &key,
            &dpapi,
            Some("vid"),
            &never,
            false,
            late + 400 * DAY
        )
        .is_ok());
    }

    #[test]
    fn stale_or_invalidated_blobs_are_discarded() {
        let file = tmp_file("invalid");
        let key = FakeKey::default();
        let dpapi = FakeDpapi(3);
        let p = HelloPolicy::default();
        enroll_file(&file, &key, &dpapi, &KEY, "vid", NOW).unwrap();

        key.cancel.set(true);
        assert_eq!(
            open_file(&file, &key, &dpapi, Some("vid"), &p, false, NOW)
                .err()
                .unwrap(),
            HelloError::Cancelled
        );
        key.cancel.set(false);
        assert!(file.exists());

        let signs = key.signs.get();
        assert_eq!(
            open_file(&file, &key, &dpapi, Some("other"), &p, false, NOW)
                .err()
                .unwrap(),
            HelloError::OtherVault
        );
        assert_eq!(key.signs.get(), signs);
        assert!(!file.exists());
        assert_eq!(
            open_file(&file, &key, &dpapi, Some("vid"), &p, false, NOW)
                .err()
                .unwrap(),
            HelloError::NotSetUp
        );

        enroll_file(&file, &key, &dpapi, &KEY, "vid", NOW).unwrap();
        key.exists.set(false);
        assert_eq!(
            open_file(&file, &key, &dpapi, Some("vid"), &p, false, NOW)
                .err()
                .unwrap(),
            HelloError::Invalidated
        );
        assert!(!file.exists());
        password_unlocked_file(&file, &key, &dpapi, &KEY, "vid", NOW).unwrap();
        assert_eq!(key.creates.get(), 2);
        assert!(readiness_of(&file, &p, false, NOW).bound);

        fs::write(&file, b"not json").unwrap();
        assert_eq!(
            open_file(&file, &key, &dpapi, Some("vid"), &p, false, NOW)
                .err()
                .unwrap(),
            HelloError::Damaged
        );
        assert!(!file.exists());
    }

    #[test]
    fn account_keys_need_windows_hello_unless_remembered() {
        let file = tmp_file("account");
        let key = FakeKey::default();
        let dpapi = FakeDpapi(5);
        let p = HelloPolicy::default();
        let binding = account_binding("acc_demo", "AKID");
        account_store_file(&file, &key, &dpapi, &KEY, &binding, false, NOW).unwrap();
        assert_eq!(read(&file).unwrap().unwrap().mode, Mode::KeyCredential);
        let signs = key.signs.get();
        let opened = account_open_file(&file, &key, &dpapi, &binding, &p, false, NOW).unwrap();
        assert_eq!(opened.as_slice(), KEY);
        assert!(key.signs.get() > signs, "the gesture signs");
        let signs = key.signs.get();
        let other = account_binding("acc_demo", "NEW");
        assert_eq!(
            account_open_file(&file, &key, &dpapi, &other, &p, false, NOW).unwrap_err(),
            HelloError::OtherVault
        );
        assert_eq!(key.signs.get(), signs);
        assert!(!file.exists());

        let unsupported = FakeKey {
            supported: false,
            ..Default::default()
        };
        assert!(account_store_file(&file, &unsupported, &dpapi, &KEY, &binding, false, NOW).is_err());
        assert!(!file.exists());
        account_store_file(&file, &unsupported, &dpapi, &KEY, &binding, true, NOW).unwrap();
        let opened = account_open_file(&file, &unsupported, &dpapi, &binding, &p, false, NOW).unwrap();
        assert_eq!(opened.as_slice(), KEY);
        assert_eq!(unsupported.presence_prompts.get(), 0, "remembered: no gesture");
        let due = policy(PasswordInterval::SevenDays);
        assert!(matches!(
            account_open_file(&file, &unsupported, &dpapi, &binding, &due, false, NOW + 8 * DAY),
            Err(HelloError::PasswordDue(_))
        ));
    }

    fn write_legacy(file: &Path, dpapi: &FakeDpapi) {
        let legacy = serde_json::json!({
            "version": 1,
            "vault_id": "vid",
            "blob": pass_core::b64url_encode(dpapi.protect(&KEY).unwrap()),
        });
        fs::write(file, legacy.to_string()).unwrap();
    }

    #[test]
    fn version_1_blob_migrates_at_hello_unlock() {
        let file = tmp_file("migrate-hello");
        let dpapi = FakeDpapi(3);
        write_legacy(&file, &dpapi);
        let key = FakeKey::default();
        let p = HelloPolicy::default();
        let r = readiness_of(&file, &p, false, now_ms());
        assert!(r.enrolled && !r.bound && r.ready, "{r:?}");

        let opened = open_file(&file, &key, &dpapi, Some("vid"), &p, false, now_ms())
            .ok()
            .unwrap();
        assert_eq!(opened.key.as_slice(), KEY);
        let migrated = opened.migrated.expect("migration");
        assert_eq!(migrated.version, VERSION);
        assert_eq!(migrated.mode, Mode::KeyCredential);
        assert!(migrated.password_unlock_ms.is_some());
        write(&file, &migrated).unwrap();

        let r = readiness_of(&file, &p, false, now_ms());
        assert!(r.bound && r.ready);
        let opened = open_file(&file, &key, &dpapi, Some("vid"), &p, false, now_ms())
            .ok()
            .unwrap();
        assert_eq!(opened.key.as_slice(), KEY);
        assert!(opened.migrated.is_none());
    }

    #[test]
    fn version_1_blob_migrates_at_password_unlock() {
        let file = tmp_file("migrate-password");
        let dpapi = FakeDpapi(3);
        write_legacy(&file, &dpapi);

        let cancelling = FakeKey::default();
        cancelling.cancel.set(true);
        assert!(password_unlocked_file(&file, &cancelling, &dpapi, &KEY, "vid", NOW).is_err());
        let kept = read(&file).unwrap().unwrap();
        assert!(kept.legacy());
        assert_eq!(kept.password_unlock_ms, Some(NOW));

        let key = FakeKey::default();
        assert_eq!(
            password_unlocked_file(&file, &key, &dpapi, &KEY, "vid", NOW).unwrap(),
            None
        );
        let hello = read(&file).unwrap().unwrap();
        assert_eq!(hello.mode, Mode::KeyCredential);
        assert!(!hello.legacy());

        let file = tmp_file("migrate-unsupported");
        write_legacy(&file, &dpapi);
        let unsupported = FakeKey {
            supported: false,
            ..Default::default()
        };
        let note = password_unlocked_file(&file, &unsupported, &dpapi, &KEY, "vid", NOW).unwrap();
        assert_eq!(note.as_deref(), Some(keywrap::not_supported().as_str()));
        let r = readiness_of(&file, &HelloPolicy::default(), false, NOW);
        assert!(!r.bound && r.ready && r.note.is_some());
        let opened = open_file(
            &file,
            &unsupported,
            &dpapi,
            Some("vid"),
            &HelloPolicy::default(),
            false,
            NOW,
        )
        .ok()
        .unwrap();
        assert_eq!(opened.key.as_slice(), KEY);
        assert_eq!(unsupported.presence_prompts.get(), 1);
    }
}
