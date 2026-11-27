//! Pinned contact keys: a vault key is wrapped only to keys this user compared with the person, kept as pins in
//! the home vault. The account service's own "confirmed" flag counts for nothing here. Every place that wraps a
//! key to someone else first asks this module:
//!
//! * [`split_pinned`]: the planned members changes that go ahead, and the people left out until compared ([`ToCompare`]).
//! * [`check`]: one person's keys, pinned on the spot when the user just compared their fingerprint, or the
//!   [`ToCompare`] to show.
//! * [`member_pin`]: what the pins say about a listed fingerprint, for the window only; the core enforces the pins.

use pass_core::{MemberChange, PinStatus, PublicKeys, SharedInfo, Vault, PERSONAL_SCOPE};
use serde::Serialize;

/// A person left out of a key wrap until the user compared their fingerprint with them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ToCompare {
    pub account: String,
    /// The fingerprint of the keys the service offers: the one to compare.
    pub fingerprint: String,
    /// `not_verified` (never compared) or `changed` (other keys than the ones compared, or new
    /// keys for someone already in the vault: a loud warning).
    pub status: &'static str,
    /// The fingerprint compared before (or the one in the vault's members list), when changed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pinned_fingerprint: Option<String>,
    /// The name the user typed for the person (a server user name, an e-mail address), when it
    /// isn't the account id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub person: Option<String>,
}

pub const NOT_VERIFIED: &str = "not_verified";
pub const CHANGED: &str = "changed";
pub const PINNED: &str = "pinned";

/// `pinned`, `not_verified` or `changed`, and the pinned fingerprint when changed.
pub fn status_words(status: &PinStatus) -> (&'static str, Option<String>) {
    match status {
        PinStatus::Pinned => (PINNED, None),
        PinStatus::NotPinned => (NOT_VERIFIED, None),
        PinStatus::Changed { pinned_fingerprint } => (CHANGED, Some(pinned_fingerprint.clone())),
    }
}

pub fn to_compare(keys: &PublicKeys, status: &PinStatus) -> Option<ToCompare> {
    let (words, pinned_fingerprint) = status_words(status);
    (words != PINNED).then(|| ToCompare {
        account: keys.account.clone(),
        fingerprint: pass_core::public_keys_fingerprint(keys.clone()),
        status: words,
        pinned_fingerprint,
        person: None,
    })
}

pub fn status_of(home: &Vault, keys: &PublicKeys) -> PinStatus {
    home.contact_pin_status(keys.clone(), PERSONAL_SCOPE)
        .unwrap_or(PinStatus::NotPinned)
}

/// Splits `changes` planned for the vault `info` describes into the ones that go ahead and the people to compare
/// first. An `Add` or `ReplaceKeys` goes ahead only when its keys are pinned in `home` (or are the user's own); new
/// keys for someone already in the vault that aren't pinned are always `changed`. Roles, groups and removals
/// wrap nothing new and always go ahead.
pub fn split_pinned(
    home: &Vault,
    info: &SharedInfo,
    changes: Vec<MemberChange>,
) -> (Vec<MemberChange>, Vec<ToCompare>) {
    let mut apply = Vec::new();
    let mut compare = Vec::new();
    for change in changes {
        let (keys, replacing) = match &change {
            MemberChange::Add { keys, .. } => (keys, false),
            MemberChange::ReplaceKeys { keys } => (keys, true),
            _ => {
                apply.push(change);
                continue;
            }
        };
        let status = status_of(home, keys);
        match to_compare(keys, &status) {
            None => apply.push(change),
            Some(mut c) => {
                if replacing {
                    c.status = CHANGED;
                    if c.pinned_fingerprint.is_none() {
                        c.pinned_fingerprint = info
                            .members
                            .iter()
                            .find(|m| m.account == keys.account)
                            .map(|m| m.fingerprint.clone());
                    }
                }
                compare.push(c);
            }
        }
    }
    (apply, compare)
}

pub fn merge(list: &mut Vec<ToCompare>, more: Vec<ToCompare>) {
    for c in more {
        match list.iter_mut().find(|x| x.account == c.account) {
            Some(x) if x.status != CHANGED && c.status == CHANGED => *x = c,
            Some(_) => {}
            None => list.push(c),
        }
    }
}

/// One person's keys before something is wrapped to them: with `compared` (the fingerprint the user compared) they
/// are pinned in `home` first (a fingerprint that isn't theirs is refused). `Ok(None)` when pinned, else the
/// [`ToCompare`] to show. `pinned` is set when a new pin was made (save the home vault).
pub fn check(
    home: &Vault,
    keys: &PublicKeys,
    compared: Option<&str>,
    pinned: &mut bool,
) -> Result<Option<ToCompare>, String> {
    if let Some(text) = compared.map(str::trim).filter(|t| !t.is_empty()) {
        home.pin_contact(keys.clone(), PERSONAL_SCOPE, text)
            .map_err(crate::commands::pass_err)?;
        *pinned = true;
    }
    Ok(to_compare(keys, &status_of(home, keys)))
}

/// A fingerprint as compared: no `sha256:` prefix, letters and digits only, upper case.
fn norm(fp: &str) -> String {
    let fp = fp.trim();
    let fp = if fp.len() > 7 && fp[..7].eq_ignore_ascii_case("sha256:") {
        &fp[7..]
    } else {
        fp
    };
    fp.chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

/// Whether two fingerprints are the same (an empty one never matches).
pub fn same_fingerprint(a: &str, b: &str) -> bool {
    let a = norm(a);
    !a.is_empty() && a == norm(b)
}

/// What the pins in `home` say about `account`'s keys with `fingerprint` (as the service lists
/// it): `pinned` (or the user's own keys), `not_verified`, or `changed` with the pinned one.
pub fn member_pin(home: &Vault, account: &str, fingerprint: &str) -> (&'static str, Option<String>) {
    let own = home
        .user_keyset(account)
        .ok()
        .flatten()
        .is_some_and(|k| same_fingerprint(&k.fingerprint(), fingerprint));
    if own {
        return (PINNED, None);
    }
    match home.contact_pin(account, PERSONAL_SCOPE) {
        Some(pin) if same_fingerprint(&pin.fingerprint, fingerprint) => (PINNED, None),
        Some(pin) => (CHANGED, Some(pin.fingerprint)),
        None => (NOT_VERIFIED, None),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use pass_core::{MemberRole, SharedKind, UserKeyset};

    pub(crate) fn home() -> std::sync::Arc<Vault> {
        let kdf = pass_core::KdfParams {
            m_kib: 64,
            t: 1,
            p: 1,
            ..Default::default()
        };
        Vault::create_with_kdf("demo master", "home", kdf).unwrap()
    }

    pub(crate) fn pin(home: &Vault, keys: &PublicKeys) {
        let fp = pass_core::public_keys_fingerprint(keys.clone());
        home.pin_contact(keys.clone(), PERSONAL_SCOPE, &fp).unwrap();
    }

    fn add(keys: &PublicKeys) -> MemberChange {
        MemberChange::Add {
            keys: keys.clone(),
            role: MemberRole::Edit,
            group: None,
        }
    }

    fn accounts(changes: &[MemberChange]) -> Vec<String> {
        changes
            .iter()
            .map(|c| match c {
                MemberChange::Add { keys, .. } | MemberChange::ReplaceKeys { keys } => {
                    keys.account.clone()
                }
                MemberChange::SetRole { account, .. }
                | MemberChange::SetGroup { account, .. }
                | MemberChange::Remove { account } => account.clone(),
            })
            .collect()
    }

    #[test]
    fn only_pinned_people_are_added() {
        let home = home();
        let alice = UserKeyset::generate("acc_alice").unwrap();
        let vault = Vault::create_shared(&alice, SharedKind::Org, None, "alice").unwrap();
        let info = vault.shared_info().unwrap();
        let bob = UserKeyset::generate("acc_bob").unwrap().public_keys();
        let carol = UserKeyset::generate("acc_carol").unwrap().public_keys();
        pin(&home, &bob);
        let (apply, compare) = split_pinned(&home, &info, vec![add(&bob), add(&carol)]);
        assert_eq!(accounts(&apply), ["acc_bob"]);
        assert_eq!(compare.len(), 1);
        assert_eq!(compare[0].account, "acc_carol");
        assert_eq!(compare[0].status, NOT_VERIFIED);
        assert_eq!(
            compare[0].fingerprint,
            pass_core::public_keys_fingerprint(carol.clone())
        );
        vault.change_members_pinned(apply, &home).unwrap();
    }

    /// A breached service marks an account it controls "confirmed" and hands out its keys: the
    /// admin never compared them, so nothing is wrapped to them.
    #[test]
    fn attack_a_confirmed_flag_from_the_service_gives_no_access() {
        let home = home();
        let alice = UserKeyset::generate("acc_alice").unwrap();
        let vault = Vault::create_shared(&alice, SharedKind::Org, None, "alice").unwrap();
        let info = vault.shared_info().unwrap();
        let mallory = UserKeyset::generate("acc_mallory").unwrap().public_keys();
        let (apply, compare) = split_pinned(&home, &info, vec![add(&mallory)]);
        assert!(apply.is_empty());
        assert_eq!(compare[0].status, NOT_VERIFIED);
        assert!(vault
            .change_members_pinned(vec![add(&mallory)], &home)
            .is_err());
        assert!(vault.shared_info().unwrap().members.len() == 1);
    }

    /// A breached service swaps a member's keys for its own, under the member's account: the new
    /// keys are not the pinned ones, so they are left out and shown loudly as changed; a role
    /// change and a removal in the same plan still go ahead.
    #[test]
    fn attack_swapped_keys_of_a_pinned_member_are_left_out() {
        let home = home();
        let alice = UserKeyset::generate("acc_alice").unwrap();
        let vault = Vault::create_shared(&alice, SharedKind::Org, None, "alice").unwrap();
        let bob = UserKeyset::generate("acc_bob").unwrap().public_keys();
        let dan = UserKeyset::generate("acc_dan").unwrap().public_keys();
        pin(&home, &bob);
        pin(&home, &dan);
        vault
            .change_members_pinned(vec![add(&bob), add(&dan)], &home)
            .unwrap();
        let info = vault.shared_info().unwrap();
        let fake_bob = UserKeyset::generate("acc_bob").unwrap().public_keys();
        let plan = vec![
            MemberChange::ReplaceKeys {
                keys: fake_bob.clone(),
            },
            MemberChange::SetRole {
                account: "acc_bob".into(),
                role: MemberRole::View,
            },
            MemberChange::Remove {
                account: "acc_dan".into(),
            },
        ];
        let (apply, compare) = split_pinned(&home, &info, plan);
        assert_eq!(accounts(&apply), ["acc_bob", "acc_dan"]);
        assert!(matches!(apply[0], MemberChange::SetRole { .. }));
        assert_eq!(compare.len(), 1);
        assert_eq!(compare[0].status, CHANGED);
        assert_eq!(
            compare[0].pinned_fingerprint.as_deref(),
            Some(pass_core::public_keys_fingerprint(bob.clone()).as_str())
        );
        vault.change_members_pinned(apply, &home).unwrap();
        let after = vault.shared_info().unwrap();
        let in_vault = after.members.iter().find(|m| m.account == "acc_bob").unwrap();
        assert_eq!(
            in_vault.fingerprint,
            pass_core::public_keys_fingerprint(bob.clone())
        );
        let other = Vault::create_shared(&alice, SharedKind::Org, None, "alice").unwrap();
        let (apply, compare) =
            split_pinned(&home, &other.shared_info().unwrap(), vec![add(&fake_bob)]);
        assert!(apply.is_empty());
        assert_eq!(compare[0].status, CHANGED);
    }

    #[test]
    fn new_keys_the_admin_compared_go_ahead() {
        let home = home();
        let alice = UserKeyset::generate("acc_alice").unwrap();
        let vault = Vault::create_shared(&alice, SharedKind::Org, None, "alice").unwrap();
        let bob = UserKeyset::generate("acc_bob").unwrap().public_keys();
        pin(&home, &bob);
        vault.change_members_pinned(vec![add(&bob)], &home).unwrap();
        let bob2 = UserKeyset::generate("acc_bob").unwrap().public_keys();
        pin(&home, &bob2);
        let plan = vec![MemberChange::ReplaceKeys { keys: bob2 }];
        let (apply, compare) = split_pinned(&home, &vault.shared_info().unwrap(), plan);
        assert!(compare.is_empty());
        vault.change_members_pinned(apply, &home).unwrap();
    }

    #[test]
    fn check_pins_only_the_compared_fingerprint() {
        let home = home();
        let bob = UserKeyset::generate("acc_bob").unwrap().public_keys();
        let fp = pass_core::public_keys_fingerprint(bob.clone());
        let mut pinned = false;
        let c = check(&home, &bob, None, &mut pinned).unwrap().unwrap();
        assert_eq!(c.status, NOT_VERIFIED);
        assert!(!pinned);
        let other = UserKeyset::generate("acc_bob").unwrap().public_keys();
        let wrong = pass_core::public_keys_fingerprint(other.clone());
        assert!(check(&home, &bob, Some(&wrong), &mut pinned).is_err());
        assert!(!pinned);
        assert!(check(&home, &bob, Some(&fp.to_lowercase()), &mut pinned)
            .unwrap()
            .is_none());
        assert!(pinned);
        let mut again = false;
        let c = check(&home, &other, None, &mut again).unwrap().unwrap();
        assert_eq!(c.status, CHANGED);
        assert_eq!(c.pinned_fingerprint.as_deref(), Some(fp.as_str()));
        assert!(check(&home, &other, Some(&wrong), &mut again)
            .unwrap()
            .is_none());
    }

    #[test]
    fn member_rows_say_pinned_not_verified_or_changed() {
        let home = home();
        let me = home.ensure_user_keyset("acc_me").unwrap();
        assert_eq!(member_pin(&home, "acc_me", &me.fingerprint()).0, PINNED);
        let bob = UserKeyset::generate("acc_bob").unwrap().public_keys();
        let fp = pass_core::public_keys_fingerprint(bob.clone());
        assert_eq!(member_pin(&home, "acc_bob", &fp).0, NOT_VERIFIED);
        pin(&home, &bob);
        assert_eq!(member_pin(&home, "acc_bob", &format!("sha256:{fp}")).0, PINNED);
        let other = UserKeyset::generate("acc_bob").unwrap().public_keys();
        let (status, pinned) =
            member_pin(&home, "acc_bob", &pass_core::public_keys_fingerprint(other));
        assert_eq!(status, CHANGED);
        assert_eq!(pinned.as_deref(), Some(fp.as_str()));
    }

    #[test]
    fn merged_lists_keep_one_entry_per_person_and_the_loudest() {
        let entry = |account: &str, status| ToCompare {
            account: account.into(),
            fingerprint: "F".into(),
            status,
            pinned_fingerprint: None,
            person: None,
        };
        let mut list = vec![entry("acc_bob", NOT_VERIFIED)];
        merge(
            &mut list,
            vec![entry("acc_bob", CHANGED), entry("acc_carol", NOT_VERIFIED)],
        );
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].status, CHANGED);
        merge(&mut list, vec![entry("acc_bob", NOT_VERIFIED)]);
        assert_eq!(list[0].status, CHANGED);
    }
}
