//! What this PC keeps for a Passyble account's keys:
//!
//! * the **Secret Key** in Credential Manager (`Pass/PassybleSecretKey/<account id>`), without a
//!   gesture: it is useless without the password, and typed at most once per PC;
//! * the **account key** (AK) under Windows Hello, or with "Remember on this PC" under DPAPI only
//!   (`hello.rs`, `Pass-account-<account id>`);
//! * an **offline cache** of the password's salt, parameters and wrap (`pw_wrap`), the Secret
//!   Key's wrap (`sk_wrap`) and the recovery wrap, so the Passyble password opens linked vaults
//!   without network: `%LOCALAPPDATA%\Pass\accounts\<account id>.json`. Nothing in it opens
//!   without the password and the Secret Key, or the recovery code.

use std::fs;
use std::path::{Path, PathBuf};

use pass_core::{AccountKdf, AccountWrap};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::api::KeyBlobs;
use crate::i18n::tr;
use crate::vaults::now_ms;

/// How the account key is kept on this PC (Settings → Passyble password).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceKey {
    /// Under Windows Hello where it can be used; else not kept.
    #[default]
    Hello,
    /// DPAPI only, no gesture ("Remember on this PC", off by default).
    Remember,
    /// Not kept: the Passyble password every time.
    Off,
}

/// The account's current recovery wrap (the same bytes in every linked vault's header).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryCopy {
    pub rec_id: String,
    pub wrap: AccountWrap,
}

/// A key set of the account that an e-mail reset replaced, as this PC last knew it: what may still
/// open the vaults linked to it and when this PC learned of the change.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct OldKeySet {
    pub ak_id: String,
    pub salt: String,
    pub kdf: Option<AccountKdf>,
    pub pw_wrap: Option<AccountWrap>,
    pub sk_wrap: Option<AccountWrap>,
    pub recovery: Option<RecoveryCopy>,
    /// When the key was replaced (the service's `locked_at`), else when this PC noticed.
    pub replaced_at: i64,
    /// The reset ran on this PC: no "your account key changed" warning.
    pub here: bool,
    /// The user read the warning.
    pub dismissed: bool,
}

/// An emergency access grant this PC made: the record, the vault and the core's grant
/// (no secret: the vault key in it is sealed to the contact and under the release secret), so the
/// next open of the vault can tell a grant gone stale (`Vault::emergency_grant_current`).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct KeptGrant {
    pub record: String,
    pub vault_id: String,
    pub grant: serde_json::Value,
    /// The vault's file on this PC when it was granted.
    pub path: String,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Cache {
    pub account: String,
    pub email: String,
    pub ak_id: String,
    pub salt: String,
    pub kdf: Option<AccountKdf>,
    pub pw_wrap: Option<AccountWrap>,
    pub sk_wrap: Option<AccountWrap>,
    pub recovery: Option<RecoveryCopy>,
    pub device_key: DeviceKey,
    /// "Not now" on "Use your Passyble password for this vault?", per vault id.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub link_declined: Vec<String>,
    /// Key sets an e-mail reset replaced, newest last.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub old_keys: Vec<OldKeySet>,
    /// `reset_started_at` of the e-mail reset this PC started (no warning for it).
    pub reset_started_here: Option<i64>,
    /// `reset_started_at` of the waiting reset this PC already warned about.
    pub reset_seen: Option<i64>,
    /// Emergency access grants made here.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub emergency: Vec<KeptGrant>,
    /// A grant couldn't be renewed without a fresh sign-in: Emergency access says so.
    pub emergency_pending: bool,
}

impl Cache {
    /// The password's parameters and wrap are here: the password opens AK offline.
    pub fn offline_ready(&self) -> bool {
        !self.ak_id.is_empty() && !self.salt.is_empty() && self.kdf.is_some() && self.pw_wrap.is_some()
    }

    /// Takes what the service handed out for a proved password (or a new password).
    pub fn take_blobs(&mut self, blobs: &KeyBlobs) {
        if self.ak_id != blobs.ak_id {
            // Another account key (an e-mail reset elsewhere): the old set is kept for the vaults
            // linked to it, and the recovery copy wrapped the old key.
            self.retire(now_ms(), false);
            self.recovery = None;
        }
        self.ak_id = blobs.ak_id.clone();
        self.salt = blobs.salt.clone();
        self.kdf = blobs.kdf.clone();
        self.pw_wrap = blobs.pw_wrap.clone();
        if blobs.sk_wrap.is_some() {
            self.sk_wrap = blobs.sk_wrap.clone();
        }
    }

    /// Moves the current key set to [`Cache::old_keys`] (once per key id) and clears it: the
    /// account has another key now. `replaced_at`: when; `here`: this PC made the change.
    pub fn retire(&mut self, replaced_at: i64, here: bool) {
        if self.ak_id.is_empty() {
            return;
        }
        if !self.old_keys.iter().any(|o| o.ak_id == self.ak_id) {
            self.old_keys.push(OldKeySet {
                ak_id: self.ak_id.clone(),
                salt: std::mem::take(&mut self.salt),
                kdf: self.kdf.take(),
                pw_wrap: self.pw_wrap.take(),
                sk_wrap: self.sk_wrap.take(),
                recovery: self.recovery.take(),
                replaced_at,
                here,
                dismissed: here,
            });
        }
        self.ak_id.clear();
        self.salt.clear();
        self.kdf = None;
        self.pw_wrap = None;
        self.sk_wrap = None;
        self.recovery = None;
    }

    /// The waiting reset is this PC's own only when the service accepted this PC's start
    /// (`started_now`). One already waiting (`reset_already`) may be someone else's, so it is never
    /// marked as this PC's and its warning stays.
    pub fn after_reset_start(&mut self, started_at: Option<i64>, started_now: bool) {
        if let Some(started) = started_at {
            if started_now && self.reset_started_here != Some(started) {
                self.reset_started_here = Some(started);
                self.reset_seen = Some(started);
            }
        }
    }

    /// After a reset made here whose answer got lost was found: the replaced key set was this PC's step.
    pub fn after_staged_reset(&mut self, old_ak_id: &str) {
        if let Some(o) = self.old_keys.iter_mut().find(|o| o.ak_id == old_ak_id) {
            o.here = true;
            o.dismissed = true;
        }
    }

    pub fn old_key(&self, ak_id: &str) -> Option<&OldKeySet> {
        self.old_keys.iter().find(|o| o.ak_id == ak_id)
    }
}

pub fn dir() -> PathBuf {
    crate::settings::local_dir().join("accounts")
}

/// `acc_...` with only the characters a file name may hold.
fn file_name(account: &str) -> String {
    let safe: String = account
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .take(80)
        .collect();
    format!("{safe}.json")
}

pub fn load_in(dir: &Path, account: &str) -> Cache {
    fs::read(dir.join(file_name(account)))
        .ok()
        .and_then(|b| serde_json::from_slice::<Cache>(&b).ok())
        .filter(|c| c.account == account)
        .unwrap_or_else(|| Cache {
            account: account.to_string(),
            ..Default::default()
        })
}

pub fn save_in(dir: &Path, cache: &Cache) -> Result<(), String> {
    let not_saved = |e: std::io::Error| crate::errors::logged(tr!("errors.account_not_stored"), "account keys cache", e);
    fs::create_dir_all(dir).map_err(not_saved)?;
    let path = dir.join(file_name(&cache.account));
    let tmp = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(cache).unwrap_or_default();
    fs::write(&tmp, bytes).map_err(not_saved)?;
    fs::rename(&tmp, &path).map_err(not_saved)
}

pub fn load(account: &str) -> Cache {
    load_in(&dir(), account)
}

pub fn save(cache: &Cache) -> Result<(), String> {
    save_in(&dir(), cache)
}

pub fn update(account: &str, f: impl FnOnce(&mut Cache)) -> Result<Cache, String> {
    let mut cache = load(account);
    f(&mut cache);
    save(&cache)?;
    Ok(cache)
}

fn secret_key_name(account: &str) -> String {
    format!("Pass/PassybleSecretKey/{account}")
}

/// The account's Secret Key on this PC (`P1-...`), if it has one.
pub fn secret_key(account: &str) -> Option<Zeroizing<String>> {
    crate::account::store()
        .get(&secret_key_name(account))
        .filter(|s| pass_core::secret_key_valid_format(s.to_string()))
}

pub fn keep_secret_key(account: &str, secret_key: &pass_core::SecretKey) -> Result<(), String> {
    let text = Zeroizing::new(secret_key.text());
    crate::account::store().set(&secret_key_name(account), &text)
}

fn old_secret_key_name(account: &str, ak_id: &str) -> String {
    format!("Pass/PassybleSecretKey/{account}/{ak_id}")
}

/// The account's Secret Key of an older key set (kept when the key was replaced), if any.
pub fn old_secret_key(account: &str, ak_id: &str) -> Option<Zeroizing<String>> {
    crate::account::store()
        .get(&old_secret_key_name(account, ak_id))
        .filter(|s| pass_core::secret_key_valid_format(s.to_string()))
}

/// The account's key `ak_id` was replaced: this PC's Secret Key (that key set's) is kept under the
/// old key's name, and the next password unlock asks for the new one.
pub fn retire_secret_key(account: &str, ak_id: &str) {
    if ak_id.is_empty() {
        return;
    }
    let store = crate::account::store();
    if let Some(text) = secret_key(account) {
        if store.set(&old_secret_key_name(account, ak_id), &text).is_ok() {
            store.delete(&secret_key_name(account));
        }
    }
}

/// Keeps a typed old Secret Key (it opened its key set) for the other vaults of that set.
pub fn keep_old_secret_key(account: &str, ak_id: &str, secret_key: &pass_core::SecretKey) -> Result<(), String> {
    let text = Zeroizing::new(secret_key.text());
    crate::account::store().set(&old_secret_key_name(account, ak_id), &text)
}

/// A reset finished here whose answer got lost left its Secret Key staged under the new key's id
/// (`new_ak_id`): it becomes this PC's current one. False when nothing was staged.
pub fn promote_staged_secret_key(account: &str, new_ak_id: &str) -> bool {
    let Some(text) = old_secret_key(account, new_ak_id) else {
        return false;
    };
    let store = crate::account::store();
    if store.set(&secret_key_name(account), &text).is_err() {
        return false;
    }
    store.delete(&old_secret_key_name(account, new_ak_id));
    true
}

pub fn forget_old_secret_key(account: &str, ak_id: &str) {
    crate::account::store().delete(&old_secret_key_name(account, ak_id));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("pass-account-cache-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn the_cache_round_trips_and_a_new_key_drops_the_recovery_copy() {
        let dir = tmp("roundtrip");
        let mut cache = load_in(&dir, "acc_demo");
        assert_eq!(cache.account, "acc_demo");
        assert!(!cache.offline_ready());
        let wrap = AccountWrap { nonce: "N".into(), ct: "C".into() };
        cache.take_blobs(&KeyBlobs {
            ak_id: "AK1".into(),
            salt: "S".into(),
            kdf: Some(AccountKdf::default()),
            pw_wrap: Some(wrap.clone()),
            sk_wrap: Some(wrap.clone()),
        });
        cache.recovery = Some(RecoveryCopy { rec_id: "r1".into(), wrap: wrap.clone() });
        assert!(cache.offline_ready());
        save_in(&dir, &cache).unwrap();
        assert_eq!(load_in(&dir, "acc_demo"), cache);
        // Another account's name never reads this file.
        assert_eq!(load_in(&dir, "acc_other").ak_id, "");

        // The same key keeps the recovery copy; a new one drops it.
        cache.take_blobs(&KeyBlobs { ak_id: "AK1".into(), salt: "S2".into(), sk_wrap: None, ..Default::default() });
        assert!(cache.recovery.is_some() && cache.sk_wrap.is_some());
        cache.take_blobs(&KeyBlobs { ak_id: "AK2".into(), ..Default::default() });
        assert!(cache.recovery.is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_replaced_key_set_moves_to_the_old_keys_once() {
        let wrap = AccountWrap { nonce: "N".into(), ct: "C".into() };
        let mut cache = Cache { account: "acc_demo".into(), ..Default::default() };
        cache.retire(1, false);
        assert!(cache.old_keys.is_empty(), "nothing to retire without a key");
        cache.take_blobs(&KeyBlobs {
            ak_id: "AK1".into(),
            salt: "S".into(),
            kdf: Some(AccountKdf::default()),
            pw_wrap: Some(wrap.clone()),
            sk_wrap: Some(wrap.clone()),
        });
        cache.recovery = Some(RecoveryCopy { rec_id: "r1".into(), wrap: wrap.clone() });
        cache.retire(42, false);
        assert!(cache.ak_id.is_empty() && cache.pw_wrap.is_none() && cache.recovery.is_none());
        let old = cache.old_key("AK1").unwrap();
        assert_eq!(old.replaced_at, 42);
        assert!(!old.here && !old.dismissed);
        assert_eq!(old.salt, "S");
        assert!(old.pw_wrap.is_some() && old.recovery.is_some());
        // The same key again (a second notice) adds nothing.
        cache.take_blobs(&KeyBlobs { ak_id: "AK1".into(), ..Default::default() });
        cache.retire(43, true);
        assert_eq!(cache.old_keys.len(), 1);
        assert_eq!(cache.old_keys[0].replaced_at, 42);
        // A reset made here needs no warning.
        cache.take_blobs(&KeyBlobs { ak_id: "AK2".into(), ..Default::default() });
        cache.retire(50, true);
        assert!(cache.old_key("AK2").unwrap().dismissed);
    }

    #[test]
    fn file_names_keep_only_safe_characters() {
        assert_eq!(file_name("acc_1-a"), "acc_1-a.json");
        assert_eq!(file_name("..\\x/y"), "xy.json");
    }
}
