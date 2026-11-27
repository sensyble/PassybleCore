//! File sizes for Settings: "84 KB · 132 items" for this vault's file, "Backup on Google Drive:
//! 84 KB" for the remote copy. One formatter so the two always read the same.

use std::path::Path;

use crate::i18n::{tr, trn};

/// `1536` becomes "1.5 KB". Binary units (1 KB = 1024 B) with the unit's own digits kept short:
/// whole bytes below 1 KB, one decimal below 10 (dropped when it would be ".0"), none above.
pub fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        return tr!("size.bytes", size = bytes);
    }
    const UNITS: [&str; 3] = ["size.kb", "size.mb", "size.gb"];
    let mut value = bytes as f64 / 1024.0;
    let mut unit = 0;
    loop {
        // Rounded the way it will be shown, so 1023.96 KB reads "1 MB", not "1024 KB".
        let shown = if value < 10.0 {
            (value * 10.0).round() / 10.0
        } else {
            value.round()
        };
        if shown >= 1024.0 && unit + 1 < UNITS.len() {
            value /= 1024.0;
            unit += 1;
            continue;
        }
        let number = if shown.fract() == 0.0 {
            format!("{shown:.0}")
        } else {
            format!("{shown:.1}").replace('.', &tr!("size.decimal_separator"))
        };
        return tr!(UNITS[unit], size = number);
    }
}

pub fn item_count_text(items: usize) -> String {
    trn!("common.items", items)
}

/// The "Vault file" row: "84 KB · 132 items". The item count is unknown while the vault is
/// locked completely; no file size (the file is gone) leaves nothing to show.
pub fn vault_file_text(bytes: Option<u64>, items: Option<usize>) -> Option<String> {
    let parts: Vec<String> = [bytes.map(format_size), items.map(item_count_text)]
        .into_iter()
        .flatten()
        .collect();
    (!parts.is_empty()).then(|| parts.join(" · "))
}

pub fn file_bytes(path: &Path) -> Option<u64> {
    std::fs::metadata(path)
        .ok()
        .filter(|m| m.is_file())
        .map(|m| m.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_sizes_are_bytes() {
        assert_eq!(format_size(0), "0 B");
        assert_eq!(format_size(1), "1 B");
        assert_eq!(format_size(1023), "1023 B");
    }

    #[test]
    fn kilobytes_keep_one_decimal_below_ten() {
        assert_eq!(format_size(1024), "1 KB");
        assert_eq!(format_size(1536), "1.5 KB");
        assert_eq!(format_size(9 * 1024 + 512), "9.5 KB");
        assert_eq!(format_size(10 * 1024), "10 KB");
        assert_eq!(format_size(84 * 1024 + 300), "84 KB");
        assert_eq!(format_size(1023 * 1024), "1023 KB");
    }

    #[test]
    fn megabytes_and_rounding_up_across_units() {
        assert_eq!(format_size(1024 * 1024), "1 MB");
        assert_eq!(format_size(1024 * 1024 + 1024 * 200), "1.2 MB");
        assert_eq!(format_size(25 * 1024 * 1024), "25 MB");
        // 1023.96 KB would print as "1024 KB".
        assert_eq!(format_size(1024 * 1024 - 40), "1 MB");
        assert_eq!(format_size(3 * 1024 * 1024 * 1024), "3 GB");
    }

    #[test]
    fn the_vault_file_row() {
        assert_eq!(
            vault_file_text(Some(84 * 1024), Some(132)).as_deref(),
            Some("84 KB · 132 items")
        );
        assert_eq!(
            vault_file_text(Some(2048), Some(1)).as_deref(),
            Some("2 KB · 1 item")
        );
        assert_eq!(vault_file_text(Some(2048), None).as_deref(), Some("2 KB"));
        assert_eq!(vault_file_text(None, Some(0)).as_deref(), Some("0 items"));
        assert_eq!(vault_file_text(None, None), None);
    }

    #[test]
    fn file_bytes_reads_the_size_on_disk() {
        let dir = std::env::temp_dir().join(format!("pass-sizes-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("a.vault");
        std::fs::write(&file, vec![0u8; 3000]).unwrap();
        assert_eq!(file_bytes(&file), Some(3000));
        assert_eq!(file_bytes(&dir.join("missing.vault")), None);
        assert_eq!(file_bytes(&dir), None);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
