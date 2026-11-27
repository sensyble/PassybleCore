//! UI text in the user's language: catalogs in `ui/i18n/<locale>.json` (en.json is the source), embedded
//! at build time and shared with the windows (`ui/i18n.js`, via [`i18n_state`]).
//!
//! * Keys are flat and dotted (`errors.item_not_found`); `_meta` holds the language's names.
//! * Placeholders are named (`{host}`), filled by [`tr!`].
//! * Plurals are objects keyed by CLDR category, chosen by [`plural_category`] and filled by [`trn!`].
//! * A missing key falls back to English, then to the key itself.
//!
//! The language is Settings → Language, else Windows' display language ([`resolve`]). Logs stay English.

use std::fmt::Display;
use std::sync::{OnceLock, RwLock};

use serde_json::{json, Map, Value};

// `CATALOGS: &[(&str, &str)]`: (locale, JSON text) of every ui/i18n/*.json, from build.rs.
include!(concat!(env!("OUT_DIR"), "/i18n_catalogs.rs"));

pub const SOURCE: &str = "en";

/// A text in the active language, with `{name}` placeholders filled.
macro_rules! tr {
    ($key:expr) => {
        $crate::i18n::text($key, &[])
    };
    ($key:expr, $($name:ident = $value:expr),+ $(,)?) => {
        $crate::i18n::text($key, &[$((stringify!($name), &$value as &dyn ::std::fmt::Display)),+])
    };
}

/// A plural text for `count` in the active language, with `{count}` and other placeholders filled.
macro_rules! trn {
    ($key:expr, $count:expr) => {
        $crate::i18n::plural($key, $count as i64, &[])
    };
    ($key:expr, $count:expr, $($name:ident = $value:expr),+ $(,)?) => {
        $crate::i18n::plural($key, $count as i64, &[$((stringify!($name), &$value as &dyn ::std::fmt::Display)),+])
    };
}

pub(crate) use {tr, trn};

struct Catalog {
    code: &'static str,
    entries: Map<String, Value>,
}

/// A language there is a catalog for. Only English and the active language are parsed (all nine came to
/// several MB of maps).
struct Slot {
    code: &'static str,
    text: &'static str,
    name: String,
    native: String,
    parsed: OnceLock<Catalog>,
}

#[derive(serde::Deserialize)]
struct MetaOnly {
    #[serde(rename = "_meta", default)]
    meta: Map<String, Value>,
}

fn slots() -> &'static [Slot] {
    static SLOTS: OnceLock<Vec<Slot>> = OnceLock::new();
    SLOTS.get_or_init(|| {
        let mut list: Vec<Slot> = CATALOGS
            .iter()
            .filter_map(
                |(code, text)| match serde_json::from_str::<MetaOnly>(text) {
                    Ok(MetaOnly { meta }) => {
                        let mut meta = meta;
                        // A platform overlay may name the language too.
                        if let Some(Value::Object(own)) = overlays()
                            .iter()
                            .find(|(c, _)| c == code)
                            .and_then(|(_, o)| o.get("_meta"))
                        {
                            meta.extend(own.clone());
                        }
                        let field = |f: &str| {
                            meta.get(f)
                                .and_then(Value::as_str)
                                .unwrap_or(code)
                                .to_string()
                        };
                        Some(Slot {
                            code,
                            text,
                            name: field("name"),
                            native: field("native"),
                            parsed: OnceLock::new(),
                        })
                    }
                    Err(_) => {
                        crate::applog::plog!("i18n: the catalog {code}.json is not a JSON object");
                        None
                    }
                },
            )
            .collect();
        // English first, then by code (the order of the Language list is the window's).
        list.sort_by_key(|s| (s.code != SOURCE, s.code));
        list
    })
}

fn overlays() -> &'static [(&'static str, Map<String, Value>)] {
    static PARSED: OnceLock<Vec<(&'static str, Map<String, Value>)>> = OnceLock::new();
    PARSED.get_or_init(|| {
        OVERLAYS
            .iter()
            .filter_map(|(code, text)| match serde_json::from_str::<Value>(text) {
                Ok(Value::Object(entries)) => Some((*code, entries)),
                _ => {
                    crate::applog::plog!("i18n: the overlay {code}.json is not a JSON object");
                    None
                }
            })
            .collect()
    })
}

fn parse(code: &'static str, text: &str) -> Catalog {
    let entries = match serde_json::from_str::<Value>(text) {
        Ok(Value::Object(entries)) => entries,
        _ => Map::new(),
    };
    let mut catalog = Catalog { code, entries };
    apply_overlays(std::slice::from_mut(&mut catalog), overlays());
    catalog
}

/// Merges per-platform wording over the catalogs. A key the English overlay changes but this language's overlay
/// lacks is removed, so it falls back to the English platform text instead of the other platform's words.
fn apply_overlays(list: &mut [Catalog], overlays: &[(&str, Map<String, Value>)]) {
    let english: Vec<&String> = overlays
        .iter()
        .find(|(code, _)| *code == SOURCE)
        .map(|(_, entries)| entries.keys().collect())
        .unwrap_or_default();
    for catalog in list.iter_mut() {
        let own = overlays
            .iter()
            .find(|(code, _)| *code == catalog.code)
            .map(|(_, entries)| entries);
        if catalog.code != SOURCE {
            for key in &english {
                if !own.is_some_and(|own| own.contains_key(*key)) {
                    catalog.entries.remove(*key);
                }
            }
        }
        for (key, value) in own.into_iter().flatten() {
            catalog.entries.insert(key.clone(), value.clone());
        }
    }
}

fn catalog(code: &str) -> Option<&'static Catalog> {
    let slot = slots().iter().find(|s| s.code == code)?;
    Some(slot.parsed.get_or_init(|| parse(slot.code, slot.text)))
}

#[cfg(test)]
fn parsed_count() -> usize {
    slots().iter().filter(|s| s.parsed.get().is_some()).count()
}

static ACTIVE: RwLock<&'static str> = RwLock::new(SOURCE);
static PREFERENCE: RwLock<Option<String>> = RwLock::new(None);

pub fn locale() -> &'static str {
    *ACTIVE.read().unwrap_or_else(|e| e.into_inner())
}

pub fn apply_preference(preference: Option<&str>) -> &'static str {
    let preference = preference.map(str::trim).filter(|p| !p.is_empty());
    let code = resolve(preference);
    *PREFERENCE.write().unwrap_or_else(|e| e.into_inner()) =
        preference.and_then(match_tag).map(str::to_string);
    *ACTIVE.write().unwrap_or_else(|e| e.into_inner()) = code;
    code
}

/// The Settings choice if there is a catalog, else the first preferred display language with one, else English.
pub fn resolve(preference: Option<&str>) -> &'static str {
    if let Some(code) = preference.and_then(match_tag) {
        return code;
    }
    system_languages()
        .iter()
        .find_map(|tag| match_tag(tag))
        .unwrap_or(SOURCE)
}

/// The catalog for a BCP 47 / Windows language tag: exact (`zh-CN`), Chinese by script (Traditional only with a
/// `zh-TW` catalog), old codes (`in` → `id`), else the base language (`hi-IN` → `hi`).
pub fn match_tag(tag: &str) -> Option<&'static str> {
    let tag = tag.trim().replace('_', "-");
    if tag.is_empty() {
        return None;
    }
    let lower = tag.to_ascii_lowercase();
    let find = |code: &str| {
        slots()
            .iter()
            .find(|c| c.code.eq_ignore_ascii_case(code))
            .map(|c| c.code)
    };
    if let Some(code) = find(&lower) {
        return Some(code);
    }
    let parts: Vec<&str> = lower.split('-').collect();
    let base = match parts[0] {
        "in" => "id",
        "iw" => "he",
        "ji" => "yi",
        other => other,
    };
    if base == "zh" {
        let traditional = parts[1..]
            .iter()
            .any(|p| matches!(*p, "hant" | "tw" | "hk" | "mo"));
        return if traditional {
            find("zh-TW")
        } else {
            find("zh-CN").or_else(|| find("zh"))
        };
    }
    find(base).or_else(|| {
        slots()
            .iter()
            .find(|c| c.code.split('-').next().unwrap_or("") == base)
            .map(|c| c.code)
    })
}

#[cfg(windows)]
fn system_languages() -> Vec<String> {
    use windows::Win32::Globalization::{
        GetUserDefaultLocaleName, GetUserPreferredUILanguages, MUI_LANGUAGE_NAME,
    };
    let mut tags = Vec::new();
    let (mut count, mut len) = (0u32, 0u32);
    // SAFETY: the first call only asks for the buffer length; the second gets a buffer of it.
    unsafe {
        if GetUserPreferredUILanguages(MUI_LANGUAGE_NAME, &mut count, None, &mut len).is_ok()
            && len > 0
        {
            let mut buf = vec![0u16; len as usize];
            if GetUserPreferredUILanguages(
                MUI_LANGUAGE_NAME,
                &mut count,
                Some(windows::core::PWSTR(buf.as_mut_ptr())),
                &mut len,
            )
            .is_ok()
            {
                tags.extend(
                    buf.split(|c| *c == 0)
                        .filter(|s| !s.is_empty())
                        .map(String::from_utf16_lossy),
                );
            }
        }
        let mut name = [0u16; 85];
        let n = GetUserDefaultLocaleName(&mut name);
        if n > 1 {
            tags.push(String::from_utf16_lossy(&name[..n as usize - 1]));
        }
    }
    tags
}

/// macOS: the preferred languages, then the environment (apps started from Finder usually have no `LANG`).
#[cfg(target_os = "macos")]
fn system_languages() -> Vec<String> {
    let mut tags = pass_macos::locale::preferred_languages();
    tags.extend(env_languages());
    tags
}

#[cfg(not(any(windows, target_os = "macos")))]
fn system_languages() -> Vec<String> {
    env_languages()
}

/// `LANGUAGE` / `LC_ALL` / `LC_MESSAGES` / `LANG` elsewhere (`de_DE.UTF-8`).
#[cfg(not(windows))]
fn env_languages() -> Vec<String> {
    ["LANGUAGE", "LC_ALL", "LC_MESSAGES", "LANG"]
        .iter()
        .filter_map(|v| std::env::var(v).ok())
        .flat_map(|v| {
            v.split(':')
                .map(|t| t.split(['.', '@']).next().unwrap_or("").to_string())
                .collect::<Vec<_>>()
        })
        .filter(|t| !t.is_empty() && t != "C" && t != "POSIX")
        .collect()
}

/// The CLDR plural category of the integer `n` in `locale`: `one`, `many` or `other`.
pub fn plural_category(locale: &str, n: i64) -> &'static str {
    let n = n.unsigned_abs();
    let base = locale.split('-').next().unwrap_or(locale);
    match base {
        // No plural forms.
        "id" | "ja" | "ko" | "zh" | "th" | "vi" | "ms" | "my" => "other",
        // 0 and 1 are singular.
        "fr" | "hi" | "bn" | "fa" | "gu" | "kn" | "zu" | "am" => match n {
            0 | 1 => "one",
            _ if base == "fr" && n.is_multiple_of(1_000_000) => "many",
            _ => "other",
        },
        "es" | "it" | "pt" | "ca" => match n {
            1 => "one",
            _ if n != 0 && n.is_multiple_of(1_000_000) => "many",
            _ => "other",
        },
        _ => {
            if n == 1 {
                "one"
            } else {
                "other"
            }
        }
    }
}

fn lookup(key: &str) -> Option<&'static Value> {
    let usable = |v: &&Value| v.is_string() || v.get("other").is_some_and(Value::is_string);
    catalog(locale())
        .and_then(|c| c.entries.get(key))
        .filter(usable)
        .or_else(|| {
            catalog(SOURCE)
                .and_then(|c| c.entries.get(key))
                .filter(usable)
        })
}

fn fill(template: &str, args: &[(&str, &dyn Display)]) -> String {
    let mut out = String::with_capacity(template.len() + 16);
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        let close = after.find('}');
        let name = close.map(|c| &after[..c]);
        match name.and_then(|name| args.iter().find(|(n, _)| *n == name)) {
            Some((_, value)) => {
                out.push_str(&value.to_string());
                rest = &after[close.unwrap_or(0) + 1..];
            }
            None => {
                out.push('{');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// The text for `key` in the active language, placeholders filled. Use [`tr!`].
pub fn text(key: &str, args: &[(&str, &dyn Display)]) -> String {
    match lookup(key) {
        Some(Value::String(s)) => fill(s, args),
        Some(v) => fill(v["other"].as_str().unwrap_or(key), args),
        None => {
            crate::applog::plog!("i18n: missing text for {key}");
            key.to_string()
        }
    }
}

/// The plural text for `key` and `count`. Use [`trn!`].
pub fn plural(key: &str, count: i64, args: &[(&str, &dyn Display)]) -> String {
    let template = match lookup(key) {
        Some(Value::String(s)) => s.as_str(),
        Some(v) => v
            .get(plural_category(locale(), count))
            .and_then(Value::as_str)
            .or_else(|| v["other"].as_str())
            .unwrap_or(key),
        None => {
            crate::applog::plog!("i18n: missing text for {key}");
            key
        }
    };
    let mut all: Vec<(&str, &dyn Display)> = vec![("count", &count)];
    all.extend_from_slice(args);
    fill(template, &all)
}

pub fn languages() -> Value {
    Value::Array(
        slots()
            .iter()
            .map(|s| json!({ "code": s.code, "name": s.name, "native": s.native }))
            .collect(),
    )
}

/// The windows' start-up call: active language, Settings choice, catalogs and language list.
#[tauri::command]
pub fn i18n_state() -> Value {
    let code = locale();
    let preference = PREFERENCE.read().unwrap_or_else(|e| e.into_inner()).clone();
    let entries = |code: &str| {
        catalog(code)
            .map(|c| Value::Object(c.entries.clone()))
            .unwrap_or_else(|| json!({}))
    };
    json!({
        "locale": code,
        "preference": preference,
        "catalog": entries(code),
        // English is sent once: as the catalog, or as the fallback (ui/i18n.js).
        "source": if code == SOURCE { Value::Null } else { entries(SOURCE) },
        "languages": languages(),
    })
}

#[cfg(test)]
fn keys(code: &str) -> std::collections::HashMap<String, Value> {
    catalog(code)
        .map(|c| c.entries.clone().into_iter().collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object(value: Value) -> Map<String, Value> {
        match value {
            Value::Object(map) => map,
            _ => panic!("not an object"),
        }
    }

    #[test]
    fn overlays_replace_and_never_leave_the_other_platforms_words() {
        let mut list = vec![
            Catalog {
                code: "en",
                entries: object(json!({"a": "Windows Hello", "b": "Lock", "c": "PC"})),
            },
            Catalog {
                code: "de",
                entries: object(json!({"a": "Windows Hello (de)", "b": "Sperren", "c": "PC (de)"})),
            },
            Catalog {
                code: "fr",
                entries: object(json!({"a": "Windows Hello (fr)", "b": "Verrouiller"})),
            },
        ];
        let overlays = vec![
            (
                "en",
                object(json!({"a": "Touch ID", "c": "Mac", "new": "Keychain"})),
            ),
            ("de", object(json!({"a": "Touch ID (de)"}))),
        ];
        apply_overlays(&mut list, &overlays);
        let text = |i: usize, key: &str| list[i].entries.get(key).cloned();
        assert_eq!(text(0, "a"), Some(json!("Touch ID")));
        assert_eq!(text(0, "b"), Some(json!("Lock")));
        assert_eq!(text(0, "new"), Some(json!("Keychain")));
        assert_eq!(text(1, "a"), Some(json!("Touch ID (de)")));
        assert_eq!(text(1, "b"), Some(json!("Sperren")));
        // Not translated for the Mac yet: falls back to the English Mac text, not "PC (de)".
        assert_eq!(text(1, "c"), None);
        assert_eq!(text(2, "a"), None);
        assert_eq!(text(2, "b"), Some(json!("Verrouiller")));
        // No overlays (Windows, Linux): nothing changes.
        let before = list[2].entries.clone();
        apply_overlays(&mut list, &[]);
        assert_eq!(list[2].entries, before);
    }

    fn placeholder_names(value: &Value) -> std::collections::BTreeSet<String> {
        let mut found = std::collections::BTreeSet::new();
        let texts: Vec<&str> = match value {
            Value::String(s) => vec![s.as_str()],
            Value::Object(forms) => forms.values().filter_map(Value::as_str).collect(),
            _ => Vec::new(),
        };
        for text in texts {
            let mut rest = text;
            while let Some(start) = rest.find('{') {
                rest = &rest[start + 1..];
                if let Some(end) = rest.find('}') {
                    let name = &rest[..end];
                    if !name.is_empty()
                        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                    {
                        found.insert(name.to_string());
                    }
                    rest = &rest[end + 1..];
                }
            }
        }
        found
    }

    #[test]
    fn macos_overlays_fit_the_catalogs() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let read = |path: std::path::PathBuf| -> Map<String, Value> {
            let text = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
            // Built from code points so this file has no literal em dash.
            for (code, name) in [(0x2014, "em dash"), (0x2013, "en dash")] {
                let dash = char::from_u32(code).unwrap();
                assert!(!text.contains(dash), "{}: {name}", path.display());
            }
            object(serde_json::from_str(&text).unwrap())
        };
        let dir = root.join("../../../macOS/i18n");
        let english = read(dir.join("en.json"));
        let base = read(root.join("../ui/i18n/en.json"));
        for (key, value) in &english {
            if key.starts_with("macos.") {
                continue;
            }
            let original = base
                .get(key)
                .unwrap_or_else(|| panic!("macOS/i18n/en.json: {key} is not in ui/i18n/en.json"));
            assert_eq!(
                placeholder_names(value),
                placeholder_names(original),
                "en {key}"
            );
        }
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            let code = path.file_stem().unwrap().to_string_lossy().to_string();
            if code == "en" || path.extension().is_none_or(|x| x != "json") {
                continue;
            }
            assert!(
                CATALOGS.iter().any(|(c, _)| *c == code),
                "macOS/i18n/{code}.json has no ui/i18n/{code}.json"
            );
            for (key, value) in read(path) {
                let english = english
                    .get(&key)
                    .unwrap_or_else(|| panic!("macOS/i18n/{code}.json: {key} is not in en.json"));
                assert_eq!(
                    placeholder_names(&value),
                    placeholder_names(english),
                    "{code} {key}"
                );
            }
        }
    }

    /// The Linux wording files (`Linux/i18n`) fit the catalogs: a key is the catalog's (same placeholders) or Linux's own
    /// (`linux.`). Skipped when the Linux repository isn't cloned beside Core.
    #[test]
    fn linux_overlays_fit_the_catalogs() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        if !root.join("../../../Linux/i18n/en.json").is_file() {
            eprintln!("Linux/i18n is not beside Core; skipped");
            return;
        }
        let read = |path: std::path::PathBuf| -> Map<String, Value> {
            let text = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
            // Built from code points so this file has no literal em dash.
            for (code, name) in [(0x2014, "em dash"), (0x2013, "en dash")] {
                let dash = char::from_u32(code).unwrap();
                assert!(!text.contains(dash), "{}: {name}", path.display());
            }
            object(serde_json::from_str(&text).unwrap())
        };
        let dir = root.join("../../../Linux/i18n");
        let english = read(dir.join("en.json"));
        let base = read(root.join("../ui/i18n/en.json"));
        for (key, value) in &english {
            if key.starts_with("linux.") {
                continue;
            }
            let original = base
                .get(key)
                .unwrap_or_else(|| panic!("Linux/i18n/en.json: {key} is not in ui/i18n/en.json"));
            assert_eq!(
                placeholder_names(value),
                placeholder_names(original),
                "en {key}"
            );
        }
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            let code = path.file_stem().unwrap().to_string_lossy().to_string();
            if code == "en" || path.extension().is_none_or(|x| x != "json") {
                continue;
            }
            assert!(
                CATALOGS.iter().any(|(c, _)| *c == code),
                "Linux/i18n/{code}.json has no ui/i18n/{code}.json"
            );
            for (key, value) in read(path) {
                let english = english
                    .get(&key)
                    .unwrap_or_else(|| panic!("Linux/i18n/{code}.json: {key} is not in en.json"));
                assert_eq!(
                    placeholder_names(&value),
                    placeholder_names(english),
                    "{code} {key}"
                );
            }
        }
    }

    #[test]
    fn plural_rules() {
        assert_eq!(plural_category("en", 1), "one");
        assert_eq!(plural_category("en", 0), "other");
        assert_eq!(plural_category("en", 2), "other");
        assert_eq!(plural_category("de", 1), "one");
        assert_eq!(plural_category("fr", 0), "one");
        assert_eq!(plural_category("fr", 1), "one");
        assert_eq!(plural_category("fr", 2), "other");
        assert_eq!(plural_category("fr", 1_000_000), "many");
        assert_eq!(plural_category("es", 0), "other");
        assert_eq!(plural_category("es", 2_000_000), "many");
        assert_eq!(plural_category("hi", 0), "one");
        assert_eq!(plural_category("zh-CN", 1), "other");
        assert_eq!(plural_category("ja", 1), "other");
        assert_eq!(plural_category("ko", 5), "other");
        assert_eq!(plural_category("id", 1), "other");
    }

    #[test]
    fn placeholders() {
        let host = "pass.example.com";
        assert_eq!(
            fill("Can't reach {host}.", &[("host", &host)]),
            "Can't reach pass.example.com."
        );
        assert_eq!(fill("{a}{b} {c}", &[("a", &1), ("b", &2)]), "12 {c}");
        assert_eq!(fill("no { brace", &[]), "no { brace");
    }

    #[test]
    fn source_catalog_is_complete() {
        let en = keys(SOURCE);
        assert!(en.contains_key("_meta"));
        for (key, value) in &en {
            if key == "_meta" {
                continue;
            }
            match value {
                Value::String(_) => {}
                Value::Object(forms) => {
                    assert!(forms.contains_key("other"), "{key}: plural without 'other'");
                    for (category, text) in forms {
                        assert!(
                            matches!(
                                category.as_str(),
                                "zero" | "one" | "two" | "few" | "many" | "other"
                            ),
                            "{key}: unknown plural category {category}"
                        );
                        assert!(text.is_string(), "{key}.{category}");
                    }
                }
                _ => panic!("{key}: neither a text nor a plural"),
            }
        }
        // English is the default in tests (the app sets the language at start-up).
        assert_eq!(locale(), SOURCE);
        assert_eq!(trn!("time.minutes_ago", 1), "1 min ago");
    }

    #[test]
    fn the_language_list_reads_the_names_without_keeping_the_catalogs() {
        let list = languages();
        let list = list.as_array().unwrap();
        assert_eq!(list[0]["code"], SOURCE);
        assert_eq!(list.len(), slots().len());
        for entry in list {
            let code = entry["code"].as_str().unwrap();
            let full = catalog(code).unwrap();
            let meta = &full.entries["_meta"];
            assert_eq!(entry["name"], meta["name"], "{code}");
            assert_eq!(entry["native"], meta["native"], "{code}");
        }
        assert!(parsed_count() <= slots().len());
    }

    #[test]
    fn a_catalog_is_parsed_once_and_kept() {
        let first = catalog(SOURCE).unwrap() as *const Catalog;
        let again = catalog(SOURCE).unwrap() as *const Catalog;
        assert_eq!(first, again);
        assert!(catalog("xx-unknown").is_none());
    }

    #[test]
    fn matching_language_tags() {
        assert_eq!(match_tag("en-US"), Some("en"));
        assert_eq!(match_tag("EN_gb"), Some("en"));
        assert_eq!(match_tag(""), None);
        let has = |code: &str| catalog(code).is_some();
        if has("zh-CN") {
            assert_eq!(match_tag("zh-Hans-CN"), Some("zh-CN"));
            assert_eq!(match_tag("zh-SG"), Some("zh-CN"));
            assert_eq!(match_tag("zh"), Some("zh-CN"));
        }
        if !has("zh-TW") {
            assert_eq!(match_tag("zh-TW"), None);
            assert_eq!(match_tag("zh-Hant-HK"), None);
        }
        if has("id") {
            assert_eq!(match_tag("in"), Some("id"));
            assert_eq!(match_tag("id-ID"), Some("id"));
        }
        if has("hi") {
            assert_eq!(match_tag("hi-IN"), Some("hi"));
        }
    }
}
