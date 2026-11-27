//! "Undo" instead of "Are you sure?" for actions that can be taken back:
//!
//! * Deleting an item keeps a copy (in memory, never on disk) for a short while, so the toast's Undo puts it back
//!   (`restore_item`). The vault itself only stores a tombstone; restoring writes the item again with a newer timestamp,
//!   which wins on every device after sync. Copies are dropped when the vault locks; `delete_items` keeps all of them.
//! * Merging two items keeps both as they were (`pass_core::MergeUndo`, in memory) for `undo_merge`.
//! * Removing a vault from the list keeps the entry (and its WebDAV password or device token, in memory) for
//!   [`VAULT_UNDO_WINDOW`]; its Windows Hello blob and key are deleted only after that window. A Pass that exits within
//!   the window leaves the blob behind with a removal marker; [`sweep_removed_hello`] removes it at the next start.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use pass_core::{Item, MergeUndo};
use zeroize::Zeroizing;

use crate::settings::VaultEntry;

pub const ITEM_UNDO_WINDOW: Duration = Duration::from_secs(60);
pub const VAULT_UNDO_WINDOW: Duration = Duration::from_secs(20);
const MAX_ITEMS: usize = 20;

struct DeletedItem {
    vault: String,
    item: Item,
    at: Instant,
}

pub struct RemovedVault {
    pub entry: VaultEntry,
    pub index: usize,
    pub was_active: bool,
    pub secret: Option<Zeroizing<String>>,
    at: Instant,
}

struct Merge {
    vault: String,
    undo: Arc<MergeUndo>,
    at: Instant,
}

static ITEMS: Mutex<Vec<DeletedItem>> = Mutex::new(Vec::new());
static MERGES: Mutex<Vec<Merge>> = Mutex::new(Vec::new());
static VAULT: Mutex<Option<RemovedVault>> = Mutex::new(None);

fn items() -> std::sync::MutexGuard<'static, Vec<DeletedItem>> {
    ITEMS.lock().unwrap_or_else(|p| p.into_inner())
}

fn vault() -> std::sync::MutexGuard<'static, Option<RemovedVault>> {
    VAULT.lock().unwrap_or_else(|p| p.into_inner())
}

pub fn item_deleted(vault_id: &str, item: Item) {
    items_deleted(vault_id, vec![item]);
}

/// Keeps copies of `deleted` (one deletion of several items, e.g. the list's selection). The
/// oldest copies go past [`MAX_ITEMS`], never those of this deletion.
pub fn items_deleted(vault_id: &str, deleted: Vec<Item>) {
    let mut list = items();
    list.retain(|d| {
        d.at.elapsed() < ITEM_UNDO_WINDOW && !deleted.iter().any(|i| i.id == d.item.id)
    });
    let keep = MAX_ITEMS.max(deleted.len());
    let at = Instant::now();
    list.extend(deleted.into_iter().map(|item| DeletedItem {
        vault: vault_id.to_string(),
        item,
        at,
    }));
    let excess = list.len().saturating_sub(keep);
    list.drain(..excess);
}

pub fn take_item(vault_id: &str, id: &str) -> Option<Item> {
    let mut list = items();
    list.retain(|d| d.at.elapsed() < ITEM_UNDO_WINDOW);
    let index = list
        .iter()
        .position(|d| d.vault == vault_id && d.item.id == id)?;
    Some(list.remove(index).item)
}

fn merges() -> std::sync::MutexGuard<'static, Vec<Merge>> {
    MERGES.lock().unwrap_or_else(|p| p.into_inner())
}

pub fn item_merged(vault_id: &str, undo: Arc<MergeUndo>) {
    let mut list = merges();
    let kept = undo.kept_id();
    list.retain(|m| m.at.elapsed() < ITEM_UNDO_WINDOW && m.undo.kept_id() != kept);
    list.push(Merge {
        vault: vault_id.to_string(),
        undo,
        at: Instant::now(),
    });
    let excess = list.len().saturating_sub(MAX_ITEMS);
    list.drain(..excess);
}

pub fn take_merge(vault_id: &str, kept_id: &str) -> Option<Arc<MergeUndo>> {
    let mut list = merges();
    list.retain(|m| m.at.elapsed() < ITEM_UNDO_WINDOW);
    let index = list
        .iter()
        .position(|m| m.vault == vault_id && m.undo.kept_id() == kept_id)?;
    Some(list.remove(index).undo)
}

pub fn clear_items() {
    items().clear();
    merges().clear();
}

/// Remembers a vault taken off the list. Returns the one it replaces (its undo window is over:
/// the caller cleans it up now).
pub fn vault_removed(
    entry: VaultEntry,
    index: usize,
    was_active: bool,
    secret: Option<String>,
) -> Option<RemovedVault> {
    vault().replace(RemovedVault {
        entry,
        index,
        was_active,
        secret: secret.map(Zeroizing::new),
        at: Instant::now(),
    })
}

pub fn take_vault(id: &str) -> Option<RemovedVault> {
    let mut slot = vault();
    if slot.as_ref().is_some_and(|r| {
        r.entry.id == id && r.at.elapsed() < VAULT_UNDO_WINDOW + Duration::from_secs(5)
    }) {
        slot.take()
    } else {
        None
    }
}

/// The removed vault `id` once its undo window is over (to clean up), `None` if it was put back
/// or replaced by a later removal (which cleaned it up).
pub fn expire_vault(id: &str) -> Option<RemovedVault> {
    let mut slot = vault();
    if slot.as_ref().is_some_and(|r| r.entry.id == id) {
        slot.take()
    } else {
        None
    }
}

/// Deletes the Windows Hello blobs and keys of vaults removed from the list while Pass was closing (marked by
/// `hello::mark_removed`). A blob is never deleted just because its vault is missing from the list: the settings file
/// may have been reset or replaced, and deleting the blob and the Hello key would ask for the master password and a
/// new Windows Hello setup once that vault is listed again.
pub fn sweep_removed_hello(listed: &[String]) {
    for id in removed_marks(&crate::settings::local_dir().join("hello")) {
        if listed.contains(&id) {
            crate::hello::unmark_removed(&id);
        } else {
            crate::hello::remove(&id);
        }
    }
}

fn removed_marks(dir: &std::path::Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|entry| {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("removed") {
                return None;
            }
            let id = path.file_stem()?.to_str()?;
            let valid = !id.is_empty()
                && id
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
            valid.then(|| id.to_string())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The deleted copies are global: one test at a time touches them.
    static SERIAL: Mutex<()> = Mutex::new(());

    #[test]
    fn deleted_items_come_back_once() {
        let _serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
        clear_items();
        let item = Item {
            id: "i1".into(),
            title: "GitHub".into(),
            ..Default::default()
        };
        item_deleted("v1", item.clone());
        assert!(take_item("v2", "i1").is_none(), "other vault");
        assert_eq!(take_item("v1", "i1").unwrap().title, "GitHub");
        assert!(take_item("v1", "i1").is_none(), "only once");
        item_deleted("v1", item);
        clear_items();
        assert!(take_item("v1", "i1").is_none(), "cleared on lock");
    }

    #[test]
    fn a_large_deletion_keeps_every_copy() {
        let _serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
        clear_items();
        item_deleted(
            "v1",
            Item {
                id: "old".into(),
                ..Default::default()
            },
        );
        let many: Vec<Item> = (0..MAX_ITEMS + 5)
            .map(|n| Item {
                id: format!("i{n}"),
                ..Default::default()
            })
            .collect();
        items_deleted("v1", many);
        assert!(
            take_item("v1", "old").is_none(),
            "the oldest copy made room"
        );
        for n in 0..MAX_ITEMS + 5 {
            assert!(take_item("v1", &format!("i{n}")).is_some(), "i{n}");
        }
        clear_items();
    }

    #[test]
    fn removed_vault_slot() {
        let entry = VaultEntry {
            id: "abc".into(),
            ..Default::default()
        };
        assert!(vault_removed(entry.clone(), 0, false, Some("t".into())).is_none());
        assert!(take_vault("other").is_none());
        let back = take_vault("abc").unwrap();
        assert_eq!(back.secret.as_deref().map(String::as_str), Some("t"));
        assert!(expire_vault("abc").is_none(), "already put back");
        vault_removed(entry.clone(), 0, false, None);
        let replaced = vault_removed(
            VaultEntry {
                id: "def".into(),
                ..Default::default()
            },
            0,
            false,
            None,
        );
        assert_eq!(replaced.unwrap().entry.id, "abc");
        assert!(expire_vault("def").is_some());
    }

    #[test]
    fn only_marked_removals_are_swept() {
        let dir = std::env::temp_dir().join(format!("pass-undo-sweep-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for name in [
            "kept.bin",
            "gone.bin",
            "gone.removed",
            "bad id.removed",
            "x.bin.tmp",
        ] {
            std::fs::write(dir.join(name), b"").unwrap();
        }
        // An unlisted blob without a marker ("kept") is not a removal.
        assert_eq!(removed_marks(&dir), vec!["gone".to_string()]);
        assert!(removed_marks(&dir.join("missing")).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
