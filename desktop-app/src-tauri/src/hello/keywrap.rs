//! The cryptographic core of Windows Hello unlock, written against two small traits so it is
//! unit-tested with a fake signer and a fake DPAPI.
//!
//! A per-vault Windows Hello key (`KeyCredentialManager`, an RSA key in the TPM / NGC key store
//! that only signs after a Hello gesture) signs a fixed random challenge stored beside the blob.
//! Its RSASSA-PKCS1-v1_5 signature is deterministic, so it works as a secret that only exists
//! after the user passed Windows Hello:
//!
//! ```text
//! wrap key = HKDF-SHA256(ikm = signature, salt = challenge, info = INFO || vault id)
//! inner    = nonce(24) || XChaCha20-Poly1305(wrap key, nonce, vault key, aad = AAD || vault id)
//! blob     = DPAPI(inner)          (user scope: binds the file to this Windows user)
//! ```
//!
//! Enrollment signs once and checks the signature against the key's public key as
//! RSASSA-PKCS1-v1_5 / SHA-256 (deterministic). Otherwise it signs a second time and compares; if the
//! two differ (non-deterministic signer) the vault key is stored with DPAPI only, with the reason.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroizing;

pub use crate::platform::HelloKeyError;

pub const CHALLENGE_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const INFO: &[u8] = b"com.sensyble.pass/hello/v2/wrap-key/";
const AAD: &[u8] = b"com.sensyble.pass/hello/v2/vault-key/";

pub trait HelloKey {
    fn supported(&self) -> bool;
    fn ensure(&self) -> Result<(), HelloKeyError>;
    /// Signs `data` after a Windows Hello prompt. `NotFound` once the key is gone (Hello reset).
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, HelloKeyError>;
    fn verify_presence(&self, message: &str) -> Result<bool, String>;
    /// Checks `signature` over `data` as RSASSA-PKCS1-v1_5 / SHA-256, without a prompt. `None` if there is no public key.
    fn verify(&self, data: &[u8], signature: &[u8]) -> Option<bool>;
}

/// RSASSA-PKCS1-v1_5 / SHA-256 verification with a PKCS#1 `RSAPublicKey` (DER).
pub fn rsa_pkcs1_sha256_verify(public_key_der: &[u8], data: &[u8], signature: &[u8]) -> bool {
    ring::signature::UnparsedPublicKey::new(
        &ring::signature::RSA_PKCS1_2048_8192_SHA256,
        public_key_der,
    )
    .verify(data, signature)
    .is_ok()
}

pub trait Protector {
    fn protect(&self, data: &[u8]) -> Result<Vec<u8>, String>;
    fn unprotect(&self, data: &[u8]) -> Result<Vec<u8>, String>;
}

#[derive(Debug, PartialEq, Eq)]
pub enum Enrolled {
    /// Bound to the Hello key: `blob` = DPAPI(sealed vault key), `challenge` to sign on unlock.
    Bound { challenge: Vec<u8>, blob: Vec<u8> },
    /// DPAPI only (like older builds), with the reason for the user.
    DpapiOnly { blob: Vec<u8>, reason: String },
}

pub fn not_supported() -> String {
    crate::i18n::tr!("hello.not_supported")
}
pub fn not_deterministic() -> String {
    crate::i18n::tr!("hello.not_deterministic")
}

pub fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut extract =
        <Hmac<Sha256> as Mac>::new_from_slice(salt).expect("HMAC accepts any key length");
    extract.update(ikm);
    let prk = Zeroizing::new(extract.finalize().into_bytes());
    let mut expand =
        <Hmac<Sha256> as Mac>::new_from_slice(&prk).expect("HMAC accepts any key length");
    expand.update(info);
    expand.update(&[1]);
    Zeroizing::new(expand.finalize().into_bytes().into())
}

pub fn derive_wrap_key(signature: &[u8], challenge: &[u8], vault_id: &str) -> Zeroizing<[u8; 32]> {
    let info = [INFO, vault_id.as_bytes()].concat();
    hkdf_sha256(challenge, signature, &info)
}

pub fn random_challenge() -> Vec<u8> {
    let mut challenge = vec![0u8; CHALLENGE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut challenge);
    challenge
}

pub fn seal(wrap_key: &[u8; 32], vault_key: &[u8], vault_id: &str) -> Result<Vec<u8>, String> {
    let cipher = XChaCha20Poly1305::new(wrap_key.into());
    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let aad = [AAD, vault_id.as_bytes()].concat();
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: vault_key,
                aad: &aad,
            },
        )
        .map_err(|_| crate::i18n::tr!("errors.hello_seal_failed"))?;
    Ok([nonce.as_slice(), &ciphertext].concat())
}

pub fn open(wrap_key: &[u8; 32], sealed: &[u8], vault_id: &str) -> Option<Zeroizing<Vec<u8>>> {
    if sealed.len() < NONCE_LEN {
        return None;
    }
    let (nonce, ciphertext) = sealed.split_at(NONCE_LEN);
    let aad = [AAD, vault_id.as_bytes()].concat();
    XChaCha20Poly1305::new(wrap_key.into())
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .ok()
        .map(Zeroizing::new)
}

/// Seals `vault_key` with a signature the caller already has (`first`) once it is known to be
/// deterministic: a valid PKCS#1 v1.5 signature under the key's public key (no prompt), or else
/// (fallback) equal to a second signature (another prompt).
fn bind(
    key: &dyn HelloKey,
    protector: &dyn Protector,
    vault_key: &[u8],
    vault_id: &str,
    challenge: Vec<u8>,
    first: Zeroizing<Vec<u8>>,
) -> Result<Enrolled, HelloKeyError> {
    if first.is_empty() {
        return dpapi_only(protector, vault_key, &not_deterministic());
    }
    if key.verify(&challenge, &first) != Some(true) {
        let second = Zeroizing::new(key.sign(&challenge)?);
        if *first != *second {
            return dpapi_only(protector, vault_key, &not_deterministic());
        }
    }
    let wrap_key = derive_wrap_key(&first, &challenge, vault_id);
    let sealed = seal(&wrap_key, vault_key, vault_id).map_err(HelloKeyError::Failed)?;
    let blob = protector.protect(&sealed).map_err(HelloKeyError::Failed)?;
    Ok(Enrolled::Bound { challenge, blob })
}

pub fn dpapi_only(
    protector: &dyn Protector,
    vault_key: &[u8],
    reason: &str,
) -> Result<Enrolled, HelloKeyError> {
    Ok(Enrolled::DpapiOnly {
        blob: protector
            .protect(vault_key)
            .map_err(HelloKeyError::Failed)?,
        reason: reason.to_string(),
    })
}

/// Enrolls `vault_key`: creates the Hello key if needed, signs a new challenge and seals the key. Falls back
/// to DPAPI only when Hello keys are unsupported or not deterministic. Errors leave nothing written.
pub fn enroll(
    key: &dyn HelloKey,
    protector: &dyn Protector,
    vault_key: &[u8],
    vault_id: &str,
) -> Result<Enrolled, HelloKeyError> {
    if !key.supported() {
        return dpapi_only(protector, vault_key, &not_supported());
    }
    match key.ensure() {
        Ok(()) => {}
        Err(HelloKeyError::Unsupported) => {
            return dpapi_only(protector, vault_key, &not_supported())
        }
        Err(e) => return Err(e),
    }
    let challenge = random_challenge();
    let first = Zeroizing::new(key.sign(&challenge)?);
    bind(key, protector, vault_key, vault_id, challenge, first)
}

#[derive(Debug, PartialEq, Eq)]
pub enum OpenError {
    /// The Hello key failed or was cancelled (`NotFound`: Hello was reset, the key is gone).
    Key(HelloKeyError),
    Damaged(String),
    /// The signature no longer opens the blob (the Hello key was replaced).
    KeyChanged,
}

pub fn unwrap_bound(
    key: &dyn HelloKey,
    protector: &dyn Protector,
    challenge: &[u8],
    blob: &[u8],
    vault_id: &str,
) -> Result<Zeroizing<Vec<u8>>, OpenError> {
    let signature = Zeroizing::new(key.sign(challenge).map_err(OpenError::Key)?);
    let sealed = Zeroizing::new(protector.unprotect(blob).map_err(OpenError::Damaged)?);
    open(
        &derive_wrap_key(&signature, challenge, vault_id),
        &sealed,
        vault_id,
    )
    .ok_or(OpenError::KeyChanged)
}

/// Migration of a DPAPI-only blob at a Hello unlock: the Hello signature over a new challenge is the
/// presence check, then the legacy blob gives the vault key. Returns a re-enrollment the caller writes
/// only after the key really unlocked the vault. Without Hello keys, the plain prompt is the check.
pub fn unlock_legacy(
    key: &dyn HelloKey,
    protector: &dyn Protector,
    legacy_blob: &[u8],
    vault_id: &str,
    message: &str,
) -> Result<(Zeroizing<Vec<u8>>, Option<Enrolled>), OpenError> {
    let usable = key.supported()
        && match key.ensure() {
            Ok(()) => true,
            Err(HelloKeyError::Unsupported) => false,
            Err(e) => return Err(OpenError::Key(e)),
        };
    if !usable {
        if !key
            .verify_presence(message)
            .map_err(|e| OpenError::Key(HelloKeyError::Failed(e)))?
        {
            return Err(OpenError::Key(HelloKeyError::Cancelled));
        }
        let vault_key = Zeroizing::new(
            protector
                .unprotect(legacy_blob)
                .map_err(OpenError::Damaged)?,
        );
        let enrolled = dpapi_only(protector, &vault_key, &not_supported()).ok();
        return Ok((vault_key, enrolled));
    }
    let challenge = random_challenge();
    let first = Zeroizing::new(key.sign(&challenge).map_err(OpenError::Key)?);
    let vault_key = Zeroizing::new(
        protector
            .unprotect(legacy_blob)
            .map_err(OpenError::Damaged)?,
    );
    // A failed or cancelled second signature keeps the legacy blob (migrated next time).
    let enrolled = bind(key, protector, &vault_key, vault_id, challenge, first).ok();
    Ok((vault_key, enrolled))
}

pub fn unlock_dpapi_only(
    key: &dyn HelloKey,
    protector: &dyn Protector,
    blob: &[u8],
    message: &str,
) -> Result<Zeroizing<Vec<u8>>, OpenError> {
    if !key
        .verify_presence(message)
        .map_err(|e| OpenError::Key(HelloKeyError::Failed(e)))?
    {
        return Err(OpenError::Key(HelloKeyError::Cancelled));
    }
    Ok(Zeroizing::new(
        protector.unprotect(blob).map_err(OpenError::Damaged)?,
    ))
}

#[cfg(test)]
pub(crate) mod fake {
    use std::cell::{Cell, RefCell};

    use sha2::Digest;

    use super::*;

    /// A deterministic "RSA" stand-in: HMAC-like hash of a secret and the data. `random` makes
    /// every signature different (like RSA-PSS); `secret` changes model a replaced key.
    pub struct FakeKey {
        pub supported: bool,
        pub exists: Cell<bool>,
        pub secret: RefCell<Vec<u8>>,
        pub random: bool,
        pub cancel: Cell<bool>,
        pub presence: bool,
        pub signs: Cell<u32>,
        pub creates: Cell<u32>,
        pub presence_prompts: Cell<u32>,
        pub verifiable: bool,
    }

    impl Default for FakeKey {
        fn default() -> Self {
            Self {
                supported: true,
                exists: Cell::new(false),
                secret: RefCell::new(b"tpm-secret".to_vec()),
                random: false,
                cancel: Cell::new(false),
                presence: true,
                signs: Cell::new(0),
                creates: Cell::new(0),
                presence_prompts: Cell::new(0),
                verifiable: true,
            }
        }
    }

    impl FakeKey {
        fn signature(&self, data: &[u8], counter: u32) -> Vec<u8> {
            let mut h = sha2::Sha256::new();
            h.update(&*self.secret.borrow());
            h.update(data);
            if self.random {
                h.update(counter.to_le_bytes());
            }
            h.finalize().to_vec()
        }
    }

    impl HelloKey for FakeKey {
        fn supported(&self) -> bool {
            self.supported
        }
        fn ensure(&self) -> Result<(), HelloKeyError> {
            if !self.supported {
                return Err(HelloKeyError::Unsupported);
            }
            if !self.exists.get() {
                if self.cancel.get() {
                    return Err(HelloKeyError::Cancelled);
                }
                self.creates.set(self.creates.get() + 1);
                self.exists.set(true);
            }
            Ok(())
        }
        fn sign(&self, data: &[u8]) -> Result<Vec<u8>, HelloKeyError> {
            if !self.exists.get() {
                return Err(HelloKeyError::NotFound);
            }
            if self.cancel.get() {
                return Err(HelloKeyError::Cancelled);
            }
            self.signs.set(self.signs.get() + 1);
            Ok(self.signature(data, self.signs.get()))
        }
        fn verify(&self, data: &[u8], signature: &[u8]) -> Option<bool> {
            // Like PKCS#1 v1.5 verification: only the deterministic signature is valid.
            (self.verifiable && self.exists.get())
                .then(|| !self.random && self.signature(data, 0) == signature)
        }
        fn verify_presence(&self, _message: &str) -> Result<bool, String> {
            self.presence_prompts.set(self.presence_prompts.get() + 1);
            Ok(self.presence && !self.cancel.get())
        }
    }

    pub struct FakeDpapi(pub u8);

    impl Protector for FakeDpapi {
        fn protect(&self, data: &[u8]) -> Result<Vec<u8>, String> {
            let mut out = vec![self.0];
            out.extend(data.iter().map(|b| b ^ self.0));
            Ok(out)
        }
        fn unprotect(&self, data: &[u8]) -> Result<Vec<u8>, String> {
            match data.split_first() {
                Some((tag, rest)) if *tag == self.0 => {
                    Ok(rest.iter().map(|b| b ^ self.0).collect())
                }
                _ => Err("CryptUnprotectData failed: wrong user".into()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::{FakeDpapi, FakeKey};
    use super::*;

    const KEY: [u8; 32] = [7u8; 32];

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn hkdf_matches_rfc5869_case_1() {
        let ikm = [0x0bu8; 22];
        let salt: Vec<u8> = (0x00..=0x0c).collect();
        let info: Vec<u8> = (0xf0..=0xf9).collect();
        assert_eq!(
            hex(&*hkdf_sha256(&salt, &ikm, &info)),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        );
    }

    #[test]
    fn seal_open_binds_key_signature_and_vault() {
        let wrap = derive_wrap_key(b"signature", b"challenge", "vault-1");
        let sealed = seal(&wrap, &KEY, "vault-1").unwrap();
        assert_eq!(open(&wrap, &sealed, "vault-1").unwrap().as_slice(), KEY);
        let other = derive_wrap_key(b"signaturf", b"challenge", "vault-1");
        assert!(open(&other, &sealed, "vault-1").is_none());
        let other = derive_wrap_key(b"signature", b"challengf", "vault-1");
        assert!(open(&other, &sealed, "vault-1").is_none());
        assert!(open(&wrap, &sealed, "vault-2").is_none());
        assert!(open(&wrap, &sealed[..10], "vault-1").is_none());
        assert_ne!(sealed, seal(&wrap, &KEY, "vault-1").unwrap());
    }

    #[test]
    fn enroll_then_unlock_with_fake_signer() {
        let key = FakeKey::default();
        let dpapi = FakeDpapi(0x5a);
        let Enrolled::Bound { challenge, blob } = enroll(&key, &dpapi, &KEY, "v").unwrap() else {
            panic!("expected a bound key");
        };
        assert_eq!(key.creates.get(), 1);
        assert_eq!(
            key.signs.get(),
            1,
            "one prompt: the signature is checked against the public key"
        );
        assert_eq!(challenge.len(), CHALLENGE_LEN);
        let inner = dpapi.unprotect(&blob).unwrap();
        assert!(!inner.windows(KEY.len()).any(|w| w == KEY));

        let opened = unwrap_bound(&key, &dpapi, &challenge, &blob, "v").unwrap();
        assert_eq!(opened.as_slice(), KEY);
        assert_eq!(key.signs.get(), 2);

        enroll(&key, &dpapi, &KEY, "v").unwrap();
        assert_eq!(key.creates.get(), 1);
    }

    #[test]
    fn without_the_public_key_enrollment_signs_twice() {
        let key = FakeKey {
            verifiable: false,
            ..Default::default()
        };
        let dpapi = FakeDpapi(0x5a);
        let Enrolled::Bound { challenge, blob } = enroll(&key, &dpapi, &KEY, "v").unwrap() else {
            panic!("expected a bound key");
        };
        assert_eq!(key.signs.get(), 2, "fallback: sign twice and compare");
        assert_eq!(
            unwrap_bound(&key, &dpapi, &challenge, &blob, "v")
                .unwrap()
                .as_slice(),
            KEY
        );
    }

    #[test]
    fn rsa_pkcs1_verification() {
        // `openssl genrsa 2048`; public key as PKCS#1 RSAPublicKey DER; `openssl dgst -sha256 -sign`.
        let public = pass_core::b64url_decode(RSA_PUBLIC.into()).unwrap();
        let signature = pass_core::b64url_decode(RSA_SIGNATURE.into()).unwrap();
        let message = b"pass-hello-test-challenge";
        assert!(rsa_pkcs1_sha256_verify(&public, message, &signature));
        assert!(!rsa_pkcs1_sha256_verify(
            &public,
            b"another challenge",
            &signature
        ));
        let mut bad = signature.clone();
        bad[10] ^= 1;
        assert!(!rsa_pkcs1_sha256_verify(&public, message, &bad));
        assert!(!rsa_pkcs1_sha256_verify(b"not a key", message, &signature));
    }

    const RSA_PUBLIC: &str = "MIIBCgKCAQEA9af9F6lWJQnPPXVDDW8g7pTF_lBfz5hqxEvnktWiSoEYrFZw8haKC_GV1t0rUGiGoBBH0ocNujSVJCucuifNeKhTvtf9f2GZuNZFxg5DKQTtUBjL_nWr6jatr7fukorbunIqZZvpEntpxu_yXsSdbsMdbDWMkwT5xinF5e8orzrZA3Ye3L8tImjFBTl669oShBujzcfkAhXWFiwDQ_kzT4lKkSZCD1yiGl7JcWsf33YEj7CoYMTq8dTqdfVMGyKL9CFQWpCrmQrGdrAHLmxsjm9ZkYmcy2BQTwBQ9utOor2Noyq3StxfsbsMo4KrHZyZxMVwkY-yxAdiUqxDbvGcFQIDAQAB";
    const RSA_SIGNATURE: &str = "bu09XVdyMbnb_GIhGZ2lhFWEAGChWPr0sTco9pcgYnW97JI17_1LcxQ4Yelag42DWL5KnPEW60h53kYO5SKVJHT-6_x-NShhemLZdaLNBCyaVYa6pHzXz2kbxcsiisCjX4yP6fTuHNTnI_G8-MBDmHvY3033FEwNc05_WhTQFJzl6Mb8O7_ZYjrhZtzrQ-NbinUgB37gtfB-dZW4xPlejjvLpZEfcsLQGlN-yaDVxA1STdvGw6iRhrpfgYAGGs1LnZcrP843u5OAG2g9oPpKPKjS8BNGmivKpLNvudCtoSTEwPSIWbSWwldTvbG4oIntp7LYIFV4CJE0esui7Nz1FA";

    #[test]
    fn unlock_failures() {
        let key = FakeKey::default();
        let dpapi = FakeDpapi(0x5a);
        let Enrolled::Bound { challenge, blob } = enroll(&key, &dpapi, &KEY, "v").unwrap() else {
            panic!("expected a bound key");
        };
        key.cancel.set(true);
        assert_eq!(
            unwrap_bound(&key, &dpapi, &challenge, &blob, "v").unwrap_err(),
            OpenError::Key(HelloKeyError::Cancelled)
        );
        key.cancel.set(false);
        assert!(matches!(
            unwrap_bound(&key, &FakeDpapi(1), &challenge, &blob, "v").unwrap_err(),
            OpenError::Damaged(_)
        ));
        let inner = dpapi.unprotect(&blob).unwrap();
        let guess = derive_wrap_key(&[], &challenge, "v");
        assert!(open(&guess, &inner, "v").is_none());
        *key.secret.borrow_mut() = b"new-tpm-secret".to_vec();
        assert_eq!(
            unwrap_bound(&key, &dpapi, &challenge, &blob, "v").unwrap_err(),
            OpenError::KeyChanged
        );
        key.exists.set(false);
        assert_eq!(
            unwrap_bound(&key, &dpapi, &challenge, &blob, "v").unwrap_err(),
            OpenError::Key(HelloKeyError::NotFound)
        );
    }

    #[test]
    fn falls_back_to_dpapi_when_unsupported_or_not_deterministic() {
        let dpapi = FakeDpapi(0x5a);
        let unsupported = FakeKey {
            supported: false,
            ..Default::default()
        };
        match enroll(&unsupported, &dpapi, &KEY, "v").unwrap() {
            Enrolled::DpapiOnly { blob, reason } => {
                assert_eq!(reason, not_supported());
                assert_eq!(dpapi.unprotect(&blob).unwrap(), KEY);
                let key = unlock_dpapi_only(&unsupported, &dpapi, &blob, "Unlock").unwrap();
                assert_eq!(key.as_slice(), KEY);
                assert_eq!(unsupported.presence_prompts.get(), 1);
            }
            other => panic!("expected DPAPI only, got {other:?}"),
        }
        let random = FakeKey {
            random: true,
            ..Default::default()
        };
        match enroll(&random, &dpapi, &KEY, "v").unwrap() {
            Enrolled::DpapiOnly { reason, .. } => assert_eq!(reason, not_deterministic()),
            other => panic!("expected DPAPI only, got {other:?}"),
        }
        let cancelling = FakeKey::default();
        cancelling.cancel.set(true);
        assert_eq!(
            enroll(&cancelling, &dpapi, &KEY, "v").unwrap_err(),
            HelloKeyError::Cancelled
        );
        let refusing = FakeKey {
            presence: false,
            ..Default::default()
        };
        let blob = dpapi.protect(&KEY).unwrap();
        assert_eq!(
            unlock_dpapi_only(&refusing, &dpapi, &blob, "Unlock").unwrap_err(),
            OpenError::Key(HelloKeyError::Cancelled)
        );
    }

    #[test]
    fn legacy_blob_migrates_at_hello_unlock() {
        let dpapi = FakeDpapi(0x5a);
        let legacy = dpapi.protect(&KEY).unwrap();
        let key = FakeKey::default();
        let (vault_key, enrolled) = unlock_legacy(&key, &dpapi, &legacy, "v", "Unlock").unwrap();
        assert_eq!(vault_key.as_slice(), KEY);
        assert_eq!(
            key.presence_prompts.get(),
            0,
            "the signature is the presence check"
        );
        let Some(Enrolled::Bound { challenge, blob }) = enrolled else {
            panic!("expected a migration to a bound key");
        };
        assert_eq!(
            unwrap_bound(&key, &dpapi, &challenge, &blob, "v")
                .unwrap()
                .as_slice(),
            KEY
        );

        let unsupported = FakeKey {
            supported: false,
            ..Default::default()
        };
        let (vault_key, enrolled) =
            unlock_legacy(&unsupported, &dpapi, &legacy, "v", "Unlock").unwrap();
        assert_eq!(vault_key.as_slice(), KEY);
        assert_eq!(unsupported.presence_prompts.get(), 1);
        assert!(matches!(enrolled, Some(Enrolled::DpapiOnly { .. })));

        let cancelling = FakeKey::default();
        cancelling.cancel.set(true);
        assert_eq!(
            unlock_legacy(&cancelling, &dpapi, &legacy, "v", "Unlock").unwrap_err(),
            OpenError::Key(HelloKeyError::Cancelled)
        );
    }
}
