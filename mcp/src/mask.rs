//! Conceals secret values in a command's output before it goes back to the AI.
//!
//! Each value is looked for as it is and in the encodings a command is likely to print it in:
//! base64 (standard and URL-safe, with or without padding, and at every byte alignment, so a value
//! inside a longer encoded string such as `base64("user:" + token)` is still found), hexadecimal
//! (lower and upper case), URL encoding (`%2F` and `%2f`, `+` or `%20` for spaces), a JSON string
//! and UTF-16LE. Every match becomes [`MASK`].
//!
//! This catches the accidents (a tool that echoes its configuration, a debug log, an error that
//! repeats the request) but not a command written to leak: one that reverses, splits or encrypts the
//! value, or sends it somewhere. That is why the approval prompt shows the exact command.

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine as _;
use zeroize::Zeroizing;

/// What a concealed value reads as.
pub const MASK: &str = "<concealed by Passyble>";

/// Encoded forms shorter than this aren't looked for (they would match ordinary output); the value
/// itself always is.
const MIN_ENCODED: usize = 6;

/// The patterns to conceal, longest first.
pub struct Masker {
    patterns: Vec<Zeroizing<Vec<u8>>>,
}

impl Masker {
    pub fn new<S: AsRef<str>>(secrets: &[S]) -> Masker {
        let mut patterns: Vec<Zeroizing<Vec<u8>>> = Vec::new();
        for secret in secrets {
            for pattern in variants(secret.as_ref().as_bytes()) {
                if !pattern.is_empty() && !patterns.iter().any(|p| **p == *pattern) {
                    patterns.push(pattern);
                }
            }
        }
        patterns.sort_by_key(|p| std::cmp::Reverse(p.len()));
        Masker { patterns }
    }

    /// The longest pattern: a reader that caps output keeps this many bytes more, so a value cut
    /// at the cap is still found whole.
    pub fn longest(&self) -> usize {
        self.patterns.first().map_or(0, |p| p.len())
    }

    /// `data` with every occurrence of every pattern replaced by [`MASK`] (overlapping matches
    /// become one).
    pub fn mask(&self, data: &[u8]) -> Vec<u8> {
        let mut ranges: Vec<(usize, usize)> = Vec::new();
        for pattern in &self.patterns {
            for start in memchr::memmem::find_iter(data, pattern.as_slice()) {
                ranges.push((start, start + pattern.len()));
            }
        }
        if ranges.is_empty() {
            return data.to_vec();
        }
        ranges.sort_unstable();
        let mut merged: Vec<(usize, usize)> = Vec::new();
        for (start, end) in ranges {
            match merged.last_mut() {
                Some(last) if start <= last.1 => last.1 = last.1.max(end),
                _ => merged.push((start, end)),
            }
        }
        let mut out = Vec::with_capacity(data.len());
        let mut at = 0;
        for (start, end) in merged {
            out.extend_from_slice(&data[at..start]);
            out.extend_from_slice(MASK.as_bytes());
            at = end;
        }
        out.extend_from_slice(&data[at..]);
        out
    }
}

/// The forms of `secret` to look for: itself, then its encodings (only those of at least
/// [`MIN_ENCODED`] bytes).
fn variants(secret: &[u8]) -> Vec<Zeroizing<Vec<u8>>> {
    if secret.is_empty() {
        return Vec::new();
    }
    let mut out = vec![Zeroizing::new(secret.to_vec())];
    let mut encoded: Vec<Vec<u8>> = vec![
        hex(secret, false),
        hex(secret, true),
        url_encoded(secret, true, false),
        url_encoded(secret, false, false),
        url_encoded(secret, true, true),
        url_encoded(secret, false, true),
        STANDARD.encode(secret).into_bytes(),
        URL_SAFE.encode(secret).into_bytes(),
        STANDARD_NO_PAD.encode(secret).into_bytes(),
        URL_SAFE_NO_PAD.encode(secret).into_bytes(),
    ];
    if let Ok(text) = std::str::from_utf8(secret) {
        if let Ok(json) = serde_json::to_string(text) {
            // Without the quotes.
            encoded.push(json.as_bytes()[1..json.len() - 1].to_vec());
        }
        let utf16: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
        encoded.push(utf16);
    }
    // Base64 of the value inside something longer: the characters that only the value's own bits
    // decide, for each of the three alignments it can start at.
    for engine in [&STANDARD_NO_PAD, &URL_SAFE_NO_PAD] {
        for offset in 0..3usize {
            let mut input = vec![0u8; offset];
            input.extend_from_slice(secret);
            let text = engine.encode(&input);
            let first = (8 * offset).div_ceil(6);
            let end = (8 * (offset + secret.len())) / 6;
            if end > first {
                encoded.push(text.as_bytes()[first..end].to_vec());
            }
            zeroize::Zeroize::zeroize(&mut input);
        }
    }
    for e in encoded {
        let e = Zeroizing::new(e);
        if e.len() >= MIN_ENCODED && *e != *secret {
            out.push(e);
        }
    }
    out
}

fn hex(data: &[u8], upper: bool) -> Vec<u8> {
    let digits: &[u8; 16] = if upper {
        b"0123456789ABCDEF"
    } else {
        b"0123456789abcdef"
    };
    data.iter()
        .flat_map(|b| [digits[(b >> 4) as usize], digits[(b & 15) as usize]])
        .collect()
}

/// Percent-encoding of everything but the unreserved characters (RFC 3986), with upper or lower
/// case hex digits; `plus`: spaces as `+` (forms).
fn url_encoded(data: &[u8], upper: bool, plus: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() * 3);
    for &b in data {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b);
        } else if plus && b == b' ' {
            out.push(b'+');
        } else {
            out.push(b'%');
            out.extend_from_slice(&hex(&[b], upper));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn masked(secret: &str, output: &str) -> String {
        String::from_utf8(Masker::new(&[secret]).mask(output.as_bytes())).unwrap()
    }

    #[test]
    fn conceals_the_value_and_its_encodings() {
        let s = "s3cr3t/Tok+en value";
        let enc = [
            s.to_string(),
            STANDARD.encode(s),
            STANDARD_NO_PAD.encode(s),
            URL_SAFE.encode(s),
            String::from_utf8(hex(s.as_bytes(), false)).unwrap(),
            String::from_utf8(hex(s.as_bytes(), true)).unwrap(),
            String::from_utf8(url_encoded(s.as_bytes(), true, false)).unwrap(),
            String::from_utf8(url_encoded(s.as_bytes(), false, true)).unwrap(),
        ];
        for e in enc {
            let out = masked(s, &format!("before {e} after"));
            assert_eq!(out, format!("before {MASK} after"), "{e}");
        }
    }

    #[test]
    fn conceals_base64_inside_longer_strings() {
        let token = "ghp_abcdefghijklmnop1234";
        for prefix in ["", "u:", "user:", "x-access-token:"] {
            let basic = STANDARD.encode(format!("{prefix}{token}"));
            let out = masked(token, &format!("Authorization: Basic {basic}"));
            assert!(out.contains(MASK), "{prefix}: {out}");
            // Only the prefix's characters and a few at the edges are left visible.
            let rest = out
                .trim_start_matches("Authorization: Basic ")
                .replace(MASK, "");
            assert!(rest.len() <= prefix.len() * 4 / 3 + 6, "{prefix}: {out}");
        }
    }

    #[test]
    fn json_and_utf16() {
        let s = "a\"b\\c/d\u{e9}";
        let json = serde_json::to_string(s).unwrap();
        let out = masked(s, &format!("{{\"k\":{json}}}"));
        assert_eq!(out, format!("{{\"k\":\"{MASK}\"}}"));
        let utf16: Vec<u8> = "secret-value"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let out = Masker::new(&["secret-value"]).mask(&utf16);
        assert_eq!(out, MASK.as_bytes());
    }

    #[test]
    fn short_values_and_overlaps() {
        // A short value is concealed as it is, but its short encodings aren't looked for.
        assert_eq!(masked("ab", "xabx 6162"), format!("x{MASK}x 6162"));
        // Overlapping matches of two values make one mask.
        let m = Masker::new(&["abcdef", "defghi"]);
        assert_eq!(m.mask(b"_abcdefghi_"), format!("_{MASK}_").into_bytes());
        assert_eq!(Masker::new::<&str>(&[]).mask(b"plain"), b"plain");
        assert_eq!(Masker::new(&[""]).mask(b"plain"), b"plain");
        assert!(Masker::new(&["abcdef"]).longest() >= 12);
    }

    #[test]
    fn binary_output() {
        let mut data = vec![0xff, 0x00];
        data.extend_from_slice(b"topsecret");
        data.push(0xfe);
        let out = Masker::new(&["topsecret"]).mask(&data);
        let mut want = vec![0xff, 0x00];
        want.extend_from_slice(MASK.as_bytes());
        want.push(0xfe);
        assert_eq!(out, want);
    }
}
