//! Windows side of the passkey provider: `webauthn.dll` plugin API (loaded at run time, so
//! `Pass.exe` still starts on Windows versions without it), the `IPluginAuthenticator` COM
//! class and its class factory, and request-signature verification with CNG.
//!
//! Every struct below mirrors `webauthnplugin.h` / `pluginauthenticator.h` from the Windows SDK
//! 10.0.26100 exactly (sizes are asserted at compile time against values measured with MSVC).

#![allow(non_snake_case, non_camel_case_types, clippy::upper_case_acronyms)]

use std::cell::Cell;
use std::collections::VecDeque;
use std::ffi::c_void;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{mpsc, Condvar, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use pass_agent::{ErrorCode, PasskeyMetadata, RpcError};
use windows::core::{implement, interface, s, w, Interface, Ref, BOOL, GUID, HRESULT, PCWSTR};
use windows::Win32::Foundation::{
    APPMODEL_ERROR_NO_PACKAGE, CLASS_E_NOAGGREGATION, ERROR_BUSY, ERROR_CANCELLED,
    ERROR_INSUFFICIENT_BUFFER, E_FAIL, E_INVALIDARG, E_OUTOFMEMORY, E_POINTER, E_UNEXPECTED,
    NTE_BAD_SIGNATURE, NTE_EXISTS, NTE_INVALID_PARAMETER, NTE_NOT_FOUND, NTE_NOT_SUPPORTED,
    NTE_USER_CANCELLED, S_OK,
};
use windows::Win32::Security::Cryptography::{
    NCryptFreeObject, NCryptImportKey, NCryptOpenStorageProvider, NCryptVerifySignature,
    BCRYPT_PSS_PADDING_INFO, BCRYPT_PUBLIC_KEY_BLOB, BCRYPT_RSAPUBLIC_MAGIC,
    BCRYPT_SHA256_ALGORITHM, MS_KEY_STORAGE_PROVIDER, NCRYPT_FLAGS, NCRYPT_HANDLE,
    NCRYPT_KEY_HANDLE, NCRYPT_PAD_PSS_FLAG, NCRYPT_PROV_HANDLE,
};
use windows::Win32::Storage::Packaging::Appx::GetCurrentPackageFullName;
use windows::Win32::System::Com::{
    CoInitializeEx, CoRegisterClassObject, CoRevokeClassObject, CoTaskMemAlloc, CoUninitialize,
    IClassFactory, IClassFactory_Impl, CLSCTX_LOCAL_SERVER, COINIT_MULTITHREADED,
    REGCLS_MULTIPLEUSE,
};
use windows::Win32::System::LibraryLoader::{
    GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32,
};

use super::ctap;

pub const CLSID: GUID = GUID::from_u128(parse_guid(super::CLSID));

/// `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` to its 128-bit value, at compile time (build.rs
/// already checked the format).
const fn parse_guid(text: &str) -> u128 {
    let bytes = text.as_bytes();
    let mut value = 0u128;
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        let digit = match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            b'-' => None,
            _ => panic!("invalid CLSID"),
        };
        if let Some(d) = digit {
            value = (value << 4) | d as u128;
        }
        i += 1;
    }
    value
}

const PLUGIN_RP_ID: PCWSTR = w!("pass.sensyble.com");

const AUTHENTICATOR_STATE_ENABLED: i32 = 1;

#[repr(C)]
struct WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_OPTIONS {
    pwszAuthenticatorName: PCWSTR,
    /// `REFCLSID` (a C++ reference, so a pointer in the ABI).
    rclsid: *const GUID,
    pwszPluginRpId: PCWSTR,
    pwszLightThemeLogoSvg: PCWSTR,
    pwszDarkThemeLogoSvg: PCWSTR,
    cbAuthenticatorInfo: u32,
    pbAuthenticatorInfo: *const u8,
    cSupportedRpIds: u32,
    ppwszSupportedRpIds: *const PCWSTR,
}

#[repr(C)]
struct WEBAUTHN_PLUGIN_UPDATE_AUTHENTICATOR_DETAILS {
    pwszAuthenticatorName: PCWSTR,
    /// `REFCLSID`: the registered class.
    rclsid: *const GUID,
    /// `REFCLSID`: the class from now on (the same one: the registration stays).
    rclsidNew: *const GUID,
    /// Null removes the logo.
    pwszLightThemeLogoSvg: PCWSTR,
    pwszDarkThemeLogoSvg: PCWSTR,
    cbAuthenticatorInfo: u32,
    pbAuthenticatorInfo: *const u8,
    cSupportedRpIds: u32,
    ppwszSupportedRpIds: *const PCWSTR,
}

#[repr(C)]
struct WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_RESPONSE {
    cbOpSignPubKey: u32,
    pbOpSignPubKey: *mut u8,
}

#[repr(C)]
struct WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS {
    cbCredentialId: u32,
    pbCredentialId: *const u8,
    pwszRpId: PCWSTR,
    pwszRpName: PCWSTR,
    cbUserId: u32,
    pbUserId: *const u8,
    pwszUserName: PCWSTR,
    pwszUserDisplayName: PCWSTR,
}

#[repr(C)]
struct WEBAUTHN_PLUGIN_USER_VERIFICATION_REQUEST {
    hwnd: *mut c_void,
    rguidTransactionId: *const GUID,
    pwszUsername: PCWSTR,
    pwszDisplayHint: PCWSTR,
}

const WEBAUTHN_PLUGIN_REQUEST_TYPE_CTAP2_CBOR: i32 = 1;
const PLUGIN_LOCKED: i32 = 0;
const PLUGIN_UNLOCKED: i32 = 1;

#[repr(C)]
pub struct WEBAUTHN_PLUGIN_OPERATION_REQUEST {
    hWnd: *mut c_void,
    transactionId: GUID,
    cbRequestSignature: u32,
    pbRequestSignature: *mut u8,
    requestType: i32,
    cbEncodedRequest: u32,
    pbEncodedRequest: *mut u8,
}

#[repr(C)]
pub struct WEBAUTHN_PLUGIN_OPERATION_RESPONSE {
    cbEncodedResponse: u32,
    pbEncodedResponse: *mut u8,
}

#[repr(C)]
pub struct WEBAUTHN_PLUGIN_CANCEL_OPERATION_REQUEST {
    transactionId: GUID,
    cbRequestSignature: u32,
    pbRequestSignature: *mut u8,
}

// sizeof() / offsetof() from MSVC x64 with the 10.0.26100 SDK headers.
#[cfg(target_pointer_width = "64")]
const _: () = {
    assert!(size_of::<WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_OPTIONS>() == 72);
    assert!(size_of::<WEBAUTHN_PLUGIN_UPDATE_AUTHENTICATOR_DETAILS>() == 72);
    assert!(std::mem::offset_of!(WEBAUTHN_PLUGIN_UPDATE_AUTHENTICATOR_DETAILS, rclsidNew) == 16);
    assert!(
        std::mem::offset_of!(
            WEBAUTHN_PLUGIN_UPDATE_AUTHENTICATOR_DETAILS,
            cbAuthenticatorInfo
        ) == 40
    );
    assert!(
        std::mem::offset_of!(
            WEBAUTHN_PLUGIN_UPDATE_AUTHENTICATOR_DETAILS,
            ppwszSupportedRpIds
        ) == 64
    );
    assert!(size_of::<WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_RESPONSE>() == 16);
    assert!(size_of::<WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS>() == 64);
    assert!(size_of::<WEBAUTHN_PLUGIN_USER_VERIFICATION_REQUEST>() == 32);
    assert!(size_of::<WEBAUTHN_PLUGIN_OPERATION_REQUEST>() == 56);
    assert!(std::mem::offset_of!(WEBAUTHN_PLUGIN_OPERATION_REQUEST, requestType) == 40);
    assert!(std::mem::offset_of!(WEBAUTHN_PLUGIN_OPERATION_REQUEST, pbEncodedRequest) == 48);
    assert!(size_of::<WEBAUTHN_PLUGIN_OPERATION_RESPONSE>() == 16);
    assert!(size_of::<WEBAUTHN_PLUGIN_CANCEL_OPERATION_REQUEST>() == 32);
    assert!(
        std::mem::offset_of!(WEBAUTHN_PLUGIN_CANCEL_OPERATION_REQUEST, pbRequestSignature) == 24
    );
};

#[interface("d26bcf6f-b54c-43ff-9f06-d5bf148625f7")]
unsafe trait IPluginAuthenticator: windows::core::IUnknown {
    fn MakeCredential(
        &self,
        request: *const WEBAUTHN_PLUGIN_OPERATION_REQUEST,
        response: *mut WEBAUTHN_PLUGIN_OPERATION_RESPONSE,
    ) -> HRESULT;
    fn GetAssertion(
        &self,
        request: *const WEBAUTHN_PLUGIN_OPERATION_REQUEST,
        response: *mut WEBAUTHN_PLUGIN_OPERATION_RESPONSE,
    ) -> HRESULT;
    fn CancelOperation(&self, request: *const WEBAUTHN_PLUGIN_CANCEL_OPERATION_REQUEST) -> HRESULT;
    fn GetLockStatus(&self, lock_status: *mut i32) -> HRESULT;
}

type FnAddAuthenticator = unsafe extern "system" fn(
    *const WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_OPTIONS,
    *mut *mut WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_RESPONSE,
) -> HRESULT;
type FnFreeAddResponse = unsafe extern "system" fn(*mut WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_RESPONSE);
type FnUpdateDetails =
    unsafe extern "system" fn(*const WEBAUTHN_PLUGIN_UPDATE_AUTHENTICATOR_DETAILS) -> HRESULT;
type FnClsid = unsafe extern "system" fn(*const GUID) -> HRESULT;
type FnGetState = unsafe extern "system" fn(*const GUID, *mut i32) -> HRESULT;
type FnCredentials = unsafe extern "system" fn(
    *const GUID,
    u32,
    *const WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS,
) -> HRESULT;
type FnGetKey = unsafe extern "system" fn(*const GUID, *mut u32, *mut *mut u8) -> HRESULT;
type FnFreeBytes = unsafe extern "system" fn(*mut u8);
type FnPerformUv = unsafe extern "system" fn(
    *const WEBAUTHN_PLUGIN_USER_VERIFICATION_REQUEST,
    *mut u32,
    *mut *mut u8,
) -> HRESULT;

struct Api {
    add_authenticator: FnAddAuthenticator,
    free_add_response: FnFreeAddResponse,
    /// Optional: without it the provider still works, only with the details first registered.
    update_details: Option<FnUpdateDetails>,
    remove_authenticator: FnClsid,
    get_state: FnGetState,
    add_credentials: FnCredentials,
    remove_all_credentials: FnClsid,
    get_operation_signing_key: FnGetKey,
    free_public_key: FnFreeBytes,
    perform_uv: FnPerformUv,
    free_uv_response: FnFreeBytes,
}

fn api() -> Option<&'static Api> {
    static API: OnceLock<Option<Api>> = OnceLock::new();
    API.get_or_init(|| unsafe {
        let module = LoadLibraryExW(w!("webauthn.dll"), None, LOAD_LIBRARY_SEARCH_SYSTEM32).ok()?;
        macro_rules! load {
            ($ty:ty, $name:literal) => {
                std::mem::transmute::<unsafe extern "system" fn() -> isize, $ty>(GetProcAddress(
                    module,
                    s!($name),
                )?)
            };
        }
        Some(Api {
            add_authenticator: load!(FnAddAuthenticator, "WebAuthNPluginAddAuthenticator"),
            free_add_response: load!(
                FnFreeAddResponse,
                "WebAuthNPluginFreeAddAuthenticatorResponse"
            ),
            update_details: GetProcAddress(module, s!("WebAuthNPluginUpdateAuthenticatorDetails"))
                .map(|f| {
                    std::mem::transmute::<unsafe extern "system" fn() -> isize, FnUpdateDetails>(f)
                }),
            remove_authenticator: load!(FnClsid, "WebAuthNPluginRemoveAuthenticator"),
            get_state: load!(FnGetState, "WebAuthNPluginGetAuthenticatorState"),
            add_credentials: load!(FnCredentials, "WebAuthNPluginAuthenticatorAddCredentials"),
            remove_all_credentials: load!(
                FnClsid,
                "WebAuthNPluginAuthenticatorRemoveAllCredentials"
            ),
            get_operation_signing_key: load!(
                FnGetKey,
                "WebAuthNPluginGetOperationSigningPublicKey"
            ),
            free_public_key: load!(FnFreeBytes, "WebAuthNPluginFreePublicKeyResponse"),
            perform_uv: load!(FnPerformUv, "WebAuthNPluginPerformUserVerification"),
            free_uv_response: load!(FnFreeBytes, "WebAuthNPluginFreeUserVerificationResponse"),
        })
    })
    .as_ref()
}

fn unsupported() -> String {
    crate::i18n::tr!("errors.pp_unsupported")
}

pub fn supported() -> bool {
    api().is_some()
}

pub fn has_package_identity() -> bool {
    let mut len = 0u32;
    let result = unsafe { GetCurrentPackageFullName(&mut len, None) };
    result != APPMODEL_ERROR_NO_PACKAGE && (result == ERROR_INSUFFICIENT_BUFFER || len > 0)
}

pub fn package_full_name() -> Option<String> {
    let mut len = 0u32;
    let result = unsafe { GetCurrentPackageFullName(&mut len, None) };
    if result != ERROR_INSUFFICIENT_BUFFER || len == 0 {
        return None;
    }
    let mut buffer = vec![0u16; len as usize];
    let result = unsafe {
        GetCurrentPackageFullName(&mut len, Some(windows::core::PWSTR(buffer.as_mut_ptr())))
    };
    if result.0 != 0 {
        return None;
    }
    let end = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
    Some(String::from_utf16_lossy(&buffer[..end]))
}

fn hr_text(hr: HRESULT) -> String {
    format!("{} (0x{:08X})", hr.message(), hr.0 as u32)
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// `Ok(Some(enabled))` when registered, `Ok(None)` when not registered.
pub fn authenticator_state() -> Result<Option<bool>, String> {
    let api = api().ok_or_else(unsupported)?;
    let mut state = 0i32;
    let hr = unsafe { (api.get_state)(&CLSID, &mut state) };
    if hr == NTE_NOT_FOUND {
        Ok(None)
    } else if hr.is_ok() {
        Ok(Some(state == AUTHENTICATOR_STATE_ENABLED))
    } else {
        Err(format!(
            "WebAuthNPluginGetAuthenticatorState: {}",
            hr_text(hr)
        ))
    }
}

struct WideDetails {
    name: Vec<u16>,
    light_logo: Vec<u16>,
    dark_logo: Vec<u16>,
    info: Vec<u8>,
}

impl WideDetails {
    fn new(details: &super::Details) -> WideDetails {
        WideDetails {
            name: wide(&details.name),
            light_logo: wide(&details.light_logo),
            dark_logo: wide(&details.dark_logo),
            info: details.info.clone(),
        }
    }

    fn add_options(&self) -> WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_OPTIONS {
        WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_OPTIONS {
            pwszAuthenticatorName: PCWSTR(self.name.as_ptr()),
            rclsid: &CLSID,
            pwszPluginRpId: PLUGIN_RP_ID,
            pwszLightThemeLogoSvg: PCWSTR(self.light_logo.as_ptr()),
            pwszDarkThemeLogoSvg: PCWSTR(self.dark_logo.as_ptr()),
            cbAuthenticatorInfo: self.info.len() as u32,
            pbAuthenticatorInfo: self.info.as_ptr(),
            cSupportedRpIds: 0,
            ppwszSupportedRpIds: std::ptr::null(),
        }
    }

    fn update_options(&self) -> WEBAUTHN_PLUGIN_UPDATE_AUTHENTICATOR_DETAILS {
        WEBAUTHN_PLUGIN_UPDATE_AUTHENTICATOR_DETAILS {
            pwszAuthenticatorName: PCWSTR(self.name.as_ptr()),
            rclsid: &CLSID,
            rclsidNew: &CLSID,
            pwszLightThemeLogoSvg: PCWSTR(self.light_logo.as_ptr()),
            pwszDarkThemeLogoSvg: PCWSTR(self.dark_logo.as_ptr()),
            cbAuthenticatorInfo: self.info.len() as u32,
            pbAuthenticatorInfo: self.info.as_ptr(),
            cSupportedRpIds: 0,
            ppwszSupportedRpIds: std::ptr::null(),
        }
    }
}

/// Registers Pass with Windows unless it already is. When it is and the name, logo or authenticator info
/// differ from the ones Windows last took, they are updated in place, never removed and added again (that
/// would switch Passyble off in Windows' passkey settings).
pub fn register() -> Result<(), String> {
    let api = api().ok_or_else(unsupported)?;
    if !has_package_identity() {
        return Err(crate::i18n::tr!("errors.pp_no_identity"));
    }
    let failed = |e: String| {
        crate::errors::logged(
            crate::i18n::tr!("errors.pp_register_failed"),
            "passkey provider",
            e,
        )
    };
    let details = super::Details::current();
    let digest = details.digest();
    let wide = WideDetails::new(&details);
    if authenticator_state().map_err(failed)?.is_some() {
        if super::details_changed(&digest) {
            update_details(api, &wide, &digest);
        }
        return Ok(());
    }
    let options = wide.add_options();
    let mut response = std::ptr::null_mut();
    let hr = unsafe { (api.add_authenticator)(&options, &mut response) };
    if !response.is_null() {
        // The operation-signing key is fetched per request instead of being stored.
        unsafe { (api.free_add_response)(response) };
    }
    if hr.is_err() {
        return Err(failed(format!(
            "WebAuthNPluginAddAuthenticator: {}",
            hr_text(hr)
        )));
    }
    super::remember_details(&digest);
    Ok(())
}

/// Hands Windows this build's details for the existing registration. A failure only leaves the old name or logo (passkeys keep working); tried again at the next start.
fn update_details(api: &Api, wide: &WideDetails, digest: &str) {
    let result: Result<(), String> = match api.update_details {
        None => Err("WebAuthNPluginUpdateAuthenticatorDetails is missing from webauthn.dll".into()),
        Some(update) => {
            let options = wide.update_options();
            let hr = unsafe { update(&options) };
            if hr.is_ok() {
                Ok(())
            } else {
                Err(format!(
                    "WebAuthNPluginUpdateAuthenticatorDetails: {}",
                    hr_text(hr)
                ))
            }
        }
    };
    match result {
        Ok(()) => {
            super::remember_details(digest);
            crate::applog::plog!(
                "passkey provider: updated the name, logo and authenticator info Windows shows"
            );
        }
        Err(e) => crate::applog::plog!(
            "passkey provider: Windows keeps the old name and logo, trying again at the next start: {e}"
        ),
    }
}

pub fn unregister() -> Result<(), String> {
    let api = api().ok_or_else(unsupported)?;
    unsafe {
        let _ = (api.remove_all_credentials)(&CLSID);
        let hr = (api.remove_authenticator)(&CLSID);
        if hr.is_err() && hr != NTE_NOT_FOUND {
            return Err(crate::errors::logged(
                crate::i18n::tr!("errors.pp_unregister_failed"),
                "passkey provider",
                format!("WebAuthNPluginRemoveAuthenticator: {}", hr_text(hr)),
            ));
        }
    }
    Ok(())
}

pub fn sync_credentials(list: &[PasskeyMetadata]) -> Result<(), String> {
    let api = api().ok_or_else(unsupported)?;
    let strings: Vec<[Vec<u16>; 4]> = list
        .iter()
        .map(|m| {
            [
                wide(&m.rp_id),
                wide(&m.rp_name),
                wide(&m.user_name),
                wide(&m.user_display_name),
            ]
        })
        .collect();
    let details: Vec<WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS> = list
        .iter()
        .zip(&strings)
        .map(|(m, s)| WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS {
            cbCredentialId: m.credential_id.len() as u32,
            pbCredentialId: m.credential_id.as_ptr(),
            pwszRpId: PCWSTR(s[0].as_ptr()),
            pwszRpName: PCWSTR(s[1].as_ptr()),
            cbUserId: m.user_handle.len() as u32,
            pbUserId: m.user_handle.as_ptr(),
            pwszUserName: PCWSTR(s[2].as_ptr()),
            pwszUserDisplayName: PCWSTR(s[3].as_ptr()),
        })
        .collect();
    unsafe {
        let hr = (api.remove_all_credentials)(&CLSID);
        if hr.is_err() && hr != NTE_NOT_FOUND {
            return Err(format!(
                "WebAuthNPluginAuthenticatorRemoveAllCredentials: {}",
                hr_text(hr)
            ));
        }
        if !details.is_empty() {
            let hr = (api.add_credentials)(&CLSID, details.len() as u32, details.as_ptr());
            if hr.is_err() {
                return Err(format!(
                    "WebAuthNPluginAuthenticatorAddCredentials: {}",
                    hr_text(hr)
                ));
            }
        }
    }
    Ok(())
}

struct NcryptHandle(NCRYPT_HANDLE);

impl Drop for NcryptHandle {
    fn drop(&mut self) {
        if self.0 .0 != 0 {
            unsafe {
                let _ = NCryptFreeObject(self.0);
            }
        }
    }
}

/// Checks a signature from Windows' plugin operation-signing key: SHA-256 over `data`, verified with the
/// `BCRYPT_PUBLIC_KEY_BLOB` key (RSA-PSS with a 32-byte salt, or ECDSA), as Microsoft's PasskeyManager sample does.
pub fn verify_signature(key_blob: &[u8], data: &[u8], signature: &[u8]) -> Result<(), String> {
    if key_blob.len() < 8 {
        return Err("operation signing key is too short".into());
    }
    let hash = pass_core::sha256(data.to_vec());
    unsafe {
        let mut provider = NCRYPT_PROV_HANDLE::default();
        NCryptOpenStorageProvider(&mut provider, MS_KEY_STORAGE_PROVIDER, 0)
            .map_err(|e| format!("NCryptOpenStorageProvider: {e}"))?;
        let _provider = NcryptHandle(NCRYPT_HANDLE(provider.0));
        let mut key = NCRYPT_KEY_HANDLE::default();
        NCryptImportKey(
            provider,
            None,
            BCRYPT_PUBLIC_KEY_BLOB,
            None,
            &mut key,
            key_blob,
            NCRYPT_FLAGS(0),
        )
        .map_err(|e| format!("NCryptImportKey: {e}"))?;
        let _key = NcryptHandle(NCRYPT_HANDLE(key.0));
        let magic = u32::from_le_bytes([key_blob[0], key_blob[1], key_blob[2], key_blob[3]]);
        let pss = BCRYPT_PSS_PADDING_INFO {
            pszAlgId: BCRYPT_SHA256_ALGORITHM,
            cbSalt: 32,
        };
        let (padding, flags) = if magic == BCRYPT_RSAPUBLIC_MAGIC.0 {
            (
                Some(&pss as *const BCRYPT_PSS_PADDING_INFO as *const c_void),
                NCRYPT_PAD_PSS_FLAG,
            )
        } else {
            (None, NCRYPT_FLAGS(0))
        };
        NCryptVerifySignature(key, padding, &hash, signature, flags)
            .map_err(|e| format!("request signature is invalid: {e}"))
    }
}

fn operation_signing_key() -> Result<Vec<u8>, String> {
    let api = api().ok_or_else(unsupported)?;
    let mut len = 0u32;
    let mut ptr = std::ptr::null_mut();
    let hr = unsafe { (api.get_operation_signing_key)(&CLSID, &mut len, &mut ptr) };
    if hr.is_err() || ptr.is_null() || len == 0 {
        return Err(format!(
            "WebAuthNPluginGetOperationSigningPublicKey: {}",
            hr_text(if hr.is_err() { hr } else { E_FAIL })
        ));
    }
    let key = unsafe { std::slice::from_raw_parts(ptr, len as usize) }.to_vec();
    unsafe { (api.free_public_key)(ptr) };
    Ok(key)
}

/// Requests come from Windows' WebAuthn service, which signs them. Any local process could
/// activate our CLSID, so an unsigned or wrongly signed request is refused.
fn verify_request(data: &[u8], signature: &[u8]) -> Result<(), String> {
    if signature.is_empty() {
        return Err("request is not signed".into());
    }
    verify_signature(&operation_signing_key()?, data, signature)
}

/// Windows Hello through the plugin API, falling back to the plain Hello prompt. `false` means cancelled or failed.
fn verify_user(hwnd: *mut c_void, transaction: &GUID, user_name: &str) -> bool {
    if let Some(api) = api() {
        let user = wide(user_name);
        let hint = wide("Passyble");
        let request = WEBAUTHN_PLUGIN_USER_VERIFICATION_REQUEST {
            hwnd,
            rguidTransactionId: transaction,
            pwszUsername: PCWSTR(user.as_ptr()),
            pwszDisplayHint: PCWSTR(hint.as_ptr()),
        };
        let mut len = 0u32;
        let mut ptr = std::ptr::null_mut();
        let hr = unsafe { (api.perform_uv)(&request, &mut len, &mut ptr) };
        if !ptr.is_null() {
            unsafe { (api.free_uv_response)(ptr) };
        }
        if hr.is_ok() {
            return true;
        }
        if hr == NTE_USER_CANCELLED || hr == ERROR_CANCELLED.to_hresult() {
            return false;
        }
        crate::applog::plog!(
            "WebAuthNPluginPerformUserVerification failed ({}), using Windows Hello directly",
            hr_text(hr)
        );
    }
    crate::platform::hello_verify(
        (!hwnd.is_null()).then_some(hwnd as isize),
        &crate::i18n::tr!("hello.passkey_prompt", user = user_name),
    )
    .unwrap_or(false)
}

/// How long a new operation waits for the one before it to end. Windows shows one passkey dialog at a time,
/// so a new request means the previous one is over for Windows even if Passyble is still winding it down.
const TAKEOVER_WAIT: Duration = Duration::from_secs(5);
/// How often prompts are closed again while a cancelled operation is still running: a prompt it
/// opens just after the cancel would otherwise wait for its full timeout.
const CANCEL_REPEAT: Duration = Duration::from_millis(250);
const CANCEL_FOLLOW: Duration = Duration::from_secs(10);
const REMEMBERED_CANCELS: usize = 8;

#[derive(Default)]
struct Slot {
    current: Option<(GUID, bool)>,
    /// `CancelOperation` for transactions that weren't current: one that arrives before its
    /// operation got here (signature check) must not be lost.
    cancelled: VecDeque<GUID>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refused {
    Cancelled,
    Busy,
}

struct Transactions {
    slot: Mutex<Slot>,
    ended: Condvar,
}

struct Transaction<'a> {
    owner: &'a Transactions,
    id: GUID,
}

impl Transactions {
    const fn new() -> Self {
        Transactions {
            slot: Mutex::new(Slot {
                current: None,
                cancelled: VecDeque::new(),
            }),
            ended: Condvar::new(),
        }
    }

    fn slot(&self) -> std::sync::MutexGuard<'_, Slot> {
        self.slot.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn begin(
        &self,
        id: GUID,
        cancel_prompts: &dyn Fn(),
        wait: Duration,
    ) -> Result<Transaction<'_>, Refused> {
        let deadline = Instant::now() + wait;
        let mut slot = self.slot();
        loop {
            if slot.cancelled.contains(&id) {
                return Err(Refused::Cancelled);
            }
            match &mut slot.current {
                None => {
                    slot.current = Some((id, false));
                    return Ok(Transaction { owner: self, id });
                }
                Some((current, _)) if *current == id => return Err(Refused::Busy),
                Some((_, cancelled)) => *cancelled = true,
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(Refused::Busy);
            }
            drop(slot);
            cancel_prompts();
            slot = self.slot();
            if slot.current.is_some() {
                let pause = CANCEL_REPEAT.min(deadline - now);
                slot = self
                    .ended
                    .wait_timeout(slot, pause)
                    .unwrap_or_else(|p| p.into_inner())
                    .0;
            }
        }
    }

    /// `CancelOperation`: `true` when `id` is being served. Otherwise the cancel is remembered, in case its operation only starts now.
    fn cancel(&self, id: GUID) -> bool {
        let mut slot = self.slot();
        match &mut slot.current {
            Some((current, cancelled)) if *current == id => {
                *cancelled = true;
                true
            }
            _ => {
                if !slot.cancelled.contains(&id) {
                    if slot.cancelled.len() == REMEMBERED_CANCELS {
                        slot.cancelled.pop_front();
                    }
                    slot.cancelled.push_back(id);
                }
                false
            }
        }
    }

    fn is_cancelled(&self, id: GUID) -> bool {
        self.slot().current == Some((id, true))
    }
}

impl Drop for Transaction<'_> {
    fn drop(&mut self) {
        let mut slot = self.owner.slot();
        if slot.current.is_some_and(|(id, _)| id == self.id) {
            slot.current = None;
        }
        drop(slot);
        self.owner.ended.notify_all();
    }
}

static TRANSACTIONS: Transactions = Transactions::new();

thread_local! {
    static SERVING: Cell<Option<(GUID, isize)>> = const { Cell::new(None) };
}

struct Serving;

impl Serving {
    fn enter(id: GUID, window: *mut c_void) -> Serving {
        SERVING.set(Some((id, window as isize)));
        Serving
    }
}

impl Drop for Serving {
    fn drop(&mut self) {
        SERVING.set(None);
    }
}

pub fn serving() -> Option<Option<isize>> {
    SERVING
        .get()
        .map(|(_, window)| (window != 0).then_some(window))
}

pub fn serving_cancelled() -> bool {
    SERVING
        .get()
        .is_some_and(|(id, _)| TRANSACTIONS.is_cancelled(id))
}

/// Keeps closing prompts while the cancelled transaction `id` is still running (a prompt opened
/// right after the cancel), for up to [`CANCEL_FOLLOW`].
fn follow_cancel(id: GUID) {
    let spawned = thread::Builder::new()
        .name("pass-passkey-cancel".into())
        .spawn(move || {
            let started = Instant::now();
            while started.elapsed() < CANCEL_FOLLOW {
                thread::sleep(CANCEL_REPEAT);
                if !TRANSACTIONS.is_cancelled(id) {
                    return;
                }
                super::cancel_prompts();
            }
        });
    if let Err(e) = spawned {
        crate::applog::plog!("passkey provider: no thread to follow a cancel: {e}");
    }
}

fn rpc_hresult(e: &RpcError) -> HRESULT {
    match e.code {
        ErrorCode::Cancelled | ErrorCode::Locked => NTE_USER_CANCELLED,
        ErrorCode::NotFound => NTE_NOT_FOUND,
        ErrorCode::InvalidState => NTE_EXISTS,
        ErrorCode::NotSupported => NTE_NOT_SUPPORTED,
        ErrorCode::InvalidParams => NTE_INVALID_PARAMETER,
        _ => E_FAIL,
    }
}

/// The name of an HRESULT this module returns, for the log (`webauthn.h` maps NTE_USER_CANCELLED, NTE_NOT_FOUND
/// and ERROR_CANCELLED to NotAllowedError, NTE_EXISTS to InvalidStateError, anything else to UnknownError).
fn hresult_name(hr: HRESULT) -> &'static str {
    const NAMES: [(HRESULT, &str); 13] = [
        (S_OK, "S_OK"),
        (NTE_USER_CANCELLED, "NTE_USER_CANCELLED"),
        (NTE_NOT_FOUND, "NTE_NOT_FOUND"),
        (NTE_EXISTS, "NTE_EXISTS"),
        (NTE_NOT_SUPPORTED, "NTE_NOT_SUPPORTED"),
        (NTE_INVALID_PARAMETER, "NTE_INVALID_PARAMETER"),
        (NTE_BAD_SIGNATURE, "NTE_BAD_SIGNATURE"),
        (E_FAIL, "E_FAIL"),
        (E_POINTER, "E_POINTER"),
        (E_INVALIDARG, "E_INVALIDARG"),
        (E_OUTOFMEMORY, "E_OUTOFMEMORY"),
        (E_UNEXPECTED, "E_UNEXPECTED"),
        (HRESULT(0x8007_00AA_u32 as i32), "ERROR_BUSY"),
    ];
    NAMES
        .iter()
        .find(|(code, _)| *code == hr)
        .map_or("HRESULT", |(_, name)| name)
}

fn hresult_label(hr: HRESULT) -> String {
    format!("{} (0x{:08X})", hresult_name(hr), hr.0 as u32)
}

#[derive(Clone, Copy, Debug)]
enum Operation {
    MakeCredential,
    GetAssertion,
}

unsafe fn bytes<'a>(ptr: *const u8, len: u32) -> &'a [u8] {
    if ptr.is_null() || len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(ptr, len as usize)
    }
}

/// What an operation's log line says besides its result. Never the site, the user or key data.
#[derive(Default)]
struct Note {
    transaction: Option<GUID>,
    locked: Option<bool>,
    unlocked: Option<bool>,
    options: Option<ctap::Options>,
    list: Option<usize>,
    detail: Option<String>,
}

fn short_id(id: &GUID) -> String {
    format!("{:08x}", id.data1)
}

fn outcome_line(kind: Operation, hr: HRESULT, note: &Note, took: Duration) -> String {
    let mut line = format!("passkey provider: {kind:?}");
    if let Some(id) = &note.transaction {
        line.push(' ');
        line.push_str(&short_id(id));
    }
    line.push_str(&format!(
        " -> {} after {:.1} s",
        hresult_label(hr),
        took.as_secs_f64()
    ));
    match (note.locked, note.unlocked) {
        (Some(true), Some(true)) => line.push_str(", vault locked, unlocked for it"),
        (Some(true), _) => line.push_str(", vault locked"),
        (Some(false), _) => line.push_str(", vault unlocked"),
        (None, _) => {}
    }
    if let Some(n) = note.list {
        let list = match kind {
            Operation::MakeCredential => "exclude list",
            Operation::GetAssertion => "allow list",
        };
        line.push_str(&format!(", {list} {n}"));
    }
    if let Some(options) = &note.options {
        for (name, value) in [("rk", options.rk), ("up", options.up), ("uv", options.uv)] {
            if let Some(value) = value {
                line.push_str(&format!(", {name}={value}"));
            }
        }
    }
    if let Some(detail) = &note.detail {
        line.push_str(": ");
        line.push_str(detail);
    }
    line
}

/// Runs one operation, writes the CBOR response (CoTaskMemAlloc'd, owned by the caller) and logs how it ended.
unsafe fn operation(
    kind: Operation,
    request: *const WEBAUTHN_PLUGIN_OPERATION_REQUEST,
    response: *mut WEBAUTHN_PLUGIN_OPERATION_RESPONSE,
) -> HRESULT {
    let started = Instant::now();
    let mut note = Note::default();
    let hr = serve(kind, request, response, &mut note);
    crate::applog::plog!("{}", outcome_line(kind, hr, &note, started.elapsed()));
    hr
}

unsafe fn serve(
    kind: Operation,
    request: *const WEBAUTHN_PLUGIN_OPERATION_REQUEST,
    response: *mut WEBAUTHN_PLUGIN_OPERATION_RESPONSE,
    note: &mut Note,
) -> HRESULT {
    if request.is_null() || response.is_null() {
        return E_POINTER;
    }
    let request = &*request;
    let id = request.transactionId;
    note.transaction = Some(id);
    if request.requestType != WEBAUTHN_PLUGIN_REQUEST_TYPE_CTAP2_CBOR {
        note.detail = Some(format!("request type {}", request.requestType));
        return NTE_NOT_SUPPORTED;
    }
    let encoded = bytes(request.pbEncodedRequest, request.cbEncodedRequest).to_vec();
    let signature = bytes(request.pbRequestSignature, request.cbRequestSignature);
    if let Err(e) = verify_request(&encoded, signature) {
        note.detail = Some(format!("refusing request: {e}"));
        return NTE_BAD_SIGNATURE;
    }
    let _transaction = match TRANSACTIONS.begin(id, &super::cancel_prompts, TAKEOVER_WAIT) {
        Ok(transaction) => transaction,
        Err(Refused::Cancelled) => {
            note.detail = Some("cancelled by Windows before it started".into());
            return NTE_USER_CANCELLED;
        }
        Err(Refused::Busy) => {
            note.detail = Some("the previous passkey request did not end in time".into());
            return ERROR_BUSY.to_hresult();
        }
    };
    let _serving = Serving::enter(id, request.hWnd);
    let Some(agent) = super::agent() else {
        note.detail = Some("no vault is set up".into());
        return NTE_NOT_FOUND;
    };
    let locked = agent.is_locked();
    note.locked = Some(locked);
    // The user just chose Passyble in Windows' dialog: a Cancel in an earlier unlock prompt doesn't count.
    super::forget_hello_cancel();
    let hwnd = request.hWnd;
    // An unlock Pass just did for this request already verified the user. Once Windows cancelled, nothing is verified.
    let verify = |user: &str| {
        !TRANSACTIONS.is_cancelled(id)
            && (super::take_unlock_credit() || verify_user(hwnd, &id, user))
    };
    let result = match kind {
        Operation::MakeCredential => match ctap::parse_make_credential(&encoded) {
            Ok(mc) => {
                note.list = Some(mc.request.exclude_credentials.len());
                note.options = Some(mc.options);
                agent
                    .platform_passkey_create(mc.request, &verify)
                    .map(|created| {
                        super::kick_sync();
                        ctap::encode_make_credential_response(&created.authenticator_data)
                    })
            }
            Err(e) => Err(RpcError::new(ErrorCode::InvalidParams, e.to_string())),
        },
        Operation::GetAssertion => match ctap::parse_get_assertion(&encoded) {
            Ok(ga) => {
                note.list = Some(ga.request.allow_credentials.len());
                note.options = Some(ga.options);
                agent
                    .platform_passkey_get(ga.request, &verify)
                    .map(|assertion| ctap::encode_get_assertion_response(&assertion))
            }
            Err(e) => Err(RpcError::new(ErrorCode::InvalidParams, e.to_string())),
        },
    };
    if locked {
        note.unlocked = Some(!agent.is_locked());
    }
    let out = match result {
        Ok(out) => out,
        Err(e) => {
            // Windows (or a newer request) cancelled it: whatever failed failed because of that.
            if TRANSACTIONS.is_cancelled(id) {
                note.detail = Some(format!("cancelled by Windows ({})", e.message));
                return NTE_USER_CANCELLED;
            }
            note.detail = Some(format!("{}: {}", e.code.as_str(), e.message));
            return rpc_hresult(&e);
        }
    };
    let buffer = CoTaskMemAlloc(out.len()) as *mut u8;
    if buffer.is_null() {
        return E_OUTOFMEMORY;
    }
    std::ptr::copy_nonoverlapping(out.as_ptr(), buffer, out.len());
    (*response).cbEncodedResponse = out.len() as u32;
    (*response).pbEncodedResponse = buffer;
    S_OK
}

/// A panic must never unwind into COM.
fn guarded(f: impl FnOnce() -> HRESULT) -> HRESULT {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or(E_UNEXPECTED)
}

#[implement(IPluginAuthenticator)]
struct PluginAuthenticator;

impl IPluginAuthenticator_Impl for PluginAuthenticator_Impl {
    unsafe fn MakeCredential(
        &self,
        request: *const WEBAUTHN_PLUGIN_OPERATION_REQUEST,
        response: *mut WEBAUTHN_PLUGIN_OPERATION_RESPONSE,
    ) -> HRESULT {
        guarded(|| unsafe { operation(Operation::MakeCredential, request, response) })
    }

    unsafe fn GetAssertion(
        &self,
        request: *const WEBAUTHN_PLUGIN_OPERATION_REQUEST,
        response: *mut WEBAUTHN_PLUGIN_OPERATION_RESPONSE,
    ) -> HRESULT {
        guarded(|| unsafe { operation(Operation::GetAssertion, request, response) })
    }

    unsafe fn CancelOperation(
        &self,
        request: *const WEBAUTHN_PLUGIN_CANCEL_OPERATION_REQUEST,
    ) -> HRESULT {
        guarded(|| {
            if request.is_null() {
                return E_INVALIDARG;
            }
            let id = unsafe { (*request).transactionId };
            if !TRANSACTIONS.cancel(id) {
                // Kept: its operation may only be getting here now (request signature check).
                crate::applog::plog!(
                    "passkey provider: CancelOperation {}: not being served",
                    short_id(&id)
                );
                return NTE_NOT_FOUND;
            }
            crate::applog::plog!("passkey provider: CancelOperation {}", short_id(&id));
            super::cancel_prompts();
            follow_cancel(id);
            S_OK
        })
    }

    unsafe fn GetLockStatus(&self, lock_status: *mut i32) -> HRESULT {
        guarded(|| {
            if lock_status.is_null() {
                return E_POINTER;
            }
            let unlocked = super::agent().is_some_and(|a| !a.is_locked());
            unsafe {
                *lock_status = if unlocked {
                    PLUGIN_UNLOCKED
                } else {
                    PLUGIN_LOCKED
                }
            };
            S_OK
        })
    }
}

#[implement(IClassFactory)]
struct Factory;

impl IClassFactory_Impl for Factory_Impl {
    fn CreateInstance(
        &self,
        outer: Ref<windows::core::IUnknown>,
        iid: *const GUID,
        object: *mut *mut c_void,
    ) -> windows::core::Result<()> {
        if object.is_null() {
            return Err(E_POINTER.into());
        }
        unsafe { *object = std::ptr::null_mut() };
        if outer.is_some() {
            return Err(CLASS_E_NOAGGREGATION.into());
        }
        let instance: IPluginAuthenticator = PluginAuthenticator.into();
        unsafe { instance.query(iid, object).ok() }
    }

    fn LockServer(&self, _lock: BOOL) -> windows::core::Result<()> {
        Ok(())
    }
}

static SERVER: Mutex<Option<mpsc::Sender<()>>> = Mutex::new(None);

/// Registers the class factory (`CoRegisterClassObject`, `REGCLS_MULTIPLEUSE`) on a dedicated
/// MTA thread, so calls arrive on COM's thread pool and may block on prompts. Idempotent.
pub fn start_com_server() -> Result<(), String> {
    let mut server = SERVER.lock().unwrap_or_else(|p| p.into_inner());
    if server.is_some() {
        return Ok(());
    }
    let (ready_tx, ready_rx) = mpsc::channel::<Result<(), String>>();
    let (stop_tx, stop_rx) = mpsc::channel::<()>();
    thread::Builder::new()
        .name("pass-passkey-com".into())
        .spawn(move || unsafe {
            let hr = CoInitializeEx(None, COINIT_MULTITHREADED);
            if hr.is_err() {
                let _ = ready_tx.send(Err(format!("CoInitializeEx: {}", hr_text(hr))));
                return;
            }
            let factory: IClassFactory = Factory.into();
            match CoRegisterClassObject(&CLSID, &factory, CLSCTX_LOCAL_SERVER, REGCLS_MULTIPLEUSE) {
                Ok(cookie) => {
                    let _ = ready_tx.send(Ok(()));
                    let _ = stop_rx.recv();
                    let _ = CoRevokeClassObject(cookie);
                }
                Err(e) => {
                    let _ = ready_tx.send(Err(format!("CoRegisterClassObject: {e}")));
                }
            }
            drop(factory);
            CoUninitialize();
        })
        .map_err(|e| e.to_string())?;
    ready_rx
        .recv()
        .map_err(|_| "the COM server thread exited".to_string())??;
    *server = Some(stop_tx);
    Ok(())
}

pub fn stop_com_server() {
    SERVER.lock().unwrap_or_else(|p| p.into_inner()).take();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plugin_api_is_present_on_this_windows() {
        eprintln!("webauthn.dll plugin API present: {}", supported());
        eprintln!("package identity: {}", has_package_identity());
    }

    fn text(p: PCWSTR) -> String {
        unsafe { p.to_string() }.unwrap()
    }

    #[test]
    fn update_options_keep_the_class_and_carry_every_detail() {
        let details = super::super::Details::current();
        let wide = WideDetails::new(&details);
        let update = wide.update_options();
        assert_eq!(unsafe { *update.rclsid }, CLSID);
        assert_eq!(unsafe { *update.rclsidNew }, CLSID);
        assert_eq!(text(update.pwszAuthenticatorName), "Passyble");
        assert_eq!(text(update.pwszLightThemeLogoSvg), details.light_logo);
        assert_eq!(text(update.pwszDarkThemeLogoSvg), details.dark_logo);
        let info = unsafe {
            std::slice::from_raw_parts(
                update.pbAuthenticatorInfo,
                update.cbAuthenticatorInfo as usize,
            )
        };
        assert_eq!(info, &details.info[..]);
        assert_eq!(update.cSupportedRpIds, 0);
        assert!(update.ppwszSupportedRpIds.is_null());
        let add = wide.add_options();
        assert_eq!(unsafe { *add.rclsid }, CLSID);
        assert_eq!(text(add.pwszAuthenticatorName), "Passyble");
        assert_eq!(text(add.pwszLightThemeLogoSvg), details.light_logo);
        assert_eq!(text(add.pwszDarkThemeLogoSvg), details.dark_logo);
        assert_eq!(add.cbAuthenticatorInfo, update.cbAuthenticatorInfo);
        assert_eq!(add.pbAuthenticatorInfo, update.pbAuthenticatorInfo);
        assert_eq!(text(add.pwszPluginRpId), "pass.sensyble.com");
        assert_eq!(add.cSupportedRpIds, 0);
    }

    #[test]
    fn rejects_garbage_signatures() {
        assert!(verify_signature(&[], b"data", b"sig").is_err());
        assert!(verify_signature(&[0u8; 64], b"data", b"sig").is_err());
    }

    /// `BCRYPT_ECCPUBLIC_BLOB` for P-256 ECDSA: magic "ECS1", key length, X, Y.
    fn ecc_blob(key: &p256::ecdsa::VerifyingKey) -> Vec<u8> {
        let point = key.to_sec1_point(false);
        let mut blob = 0x3153_4345u32.to_le_bytes().to_vec();
        blob.extend_from_slice(&32u32.to_le_bytes());
        blob.extend_from_slice(point.x().unwrap());
        blob.extend_from_slice(point.y().unwrap());
        blob
    }

    #[test]
    fn verifies_ecdsa_request_signatures_with_cng() {
        use p256::ecdsa::signature::Signer;
        let key = p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap();
        let blob = ecc_blob(key.verifying_key());
        let request: &[u8] = &[0xa2, 0x01, 0x6b, b'e', b'x', b'a', b'm', b'p', b'l', b'e'];
        // CNG wants the raw r || s form (IEEE P1363), as Windows produces it.
        let signature: p256::ecdsa::Signature = key.sign(request);
        let raw = signature.to_bytes();
        verify_signature(&blob, request, &raw).unwrap();
        assert!(verify_signature(&blob, b"tampered", &raw).is_err());
        let other = p256::ecdsa::SigningKey::from_slice(&[8u8; 32]).unwrap();
        assert!(verify_signature(&ecc_blob(other.verifying_key()), request, &raw).is_err());
    }

    const NO_WAIT: Duration = Duration::ZERO;

    #[test]
    fn transactions_are_exclusive() {
        let t = Transactions::new();
        let a = GUID::from_u128(1);
        let first = t.begin(a, &|| {}, NO_WAIT).unwrap();
        assert_eq!(t.begin(a, &|| {}, NO_WAIT).err(), Some(Refused::Busy));
        assert!(!t.is_cancelled(a));
        assert_eq!(
            t.begin(GUID::from_u128(2), &|| {}, NO_WAIT).err(),
            Some(Refused::Busy)
        );
        assert!(t.is_cancelled(a));
        drop(first);
        assert!(!t.is_cancelled(a));
        assert!(t.begin(a, &|| {}, NO_WAIT).is_ok());
    }

    #[test]
    fn a_new_request_takes_over_from_one_windows_gave_up_on() {
        let t = std::sync::Arc::new(Transactions::new());
        let old = GUID::from_u128(10);
        let (started_tx, started_rx) = mpsc::channel();
        let (cancel_tx, cancel_rx) = mpsc::channel::<()>();
        let runner = {
            let t = t.clone();
            thread::spawn(move || {
                let running = t.begin(old, &|| {}, NO_WAIT).unwrap();
                started_tx.send(()).unwrap();
                cancel_rx.recv_timeout(Duration::from_secs(10)).unwrap();
                let cancelled = t.is_cancelled(old);
                drop(running);
                cancelled
            })
        };
        started_rx.recv().unwrap();
        let closed = Mutex::new(0);
        let cancel_prompts = || {
            *closed.lock().unwrap() += 1;
            let _ = cancel_tx.send(());
        };
        let new = GUID::from_u128(11);
        let serving = t
            .begin(new, &cancel_prompts, Duration::from_secs(5))
            .unwrap();
        assert!(
            runner.join().unwrap(),
            "the old operation saw it was cancelled"
        );
        assert!(*closed.lock().unwrap() >= 1);
        assert!(!t.is_cancelled(new));
        drop(serving);
    }

    #[test]
    fn a_cancel_before_the_operation_is_kept() {
        let t = Transactions::new();
        let early = GUID::from_u128(20);
        assert!(!t.cancel(early));
        assert_eq!(
            t.begin(early, &|| {}, NO_WAIT).err(),
            Some(Refused::Cancelled)
        );
        let other = GUID::from_u128(21);
        let running = t.begin(other, &|| {}, NO_WAIT).unwrap();
        assert!(t.cancel(other));
        assert!(t.is_cancelled(other));
        drop(running);
        for n in 0..REMEMBERED_CANCELS as u128 + 1 {
            t.cancel(GUID::from_u128(100 + n));
        }
        assert!(t.begin(GUID::from_u128(100), &|| {}, NO_WAIT).is_ok());
    }

    #[test]
    fn the_serving_thread_is_marked() {
        assert!(serving().is_none());
        let id = GUID::from_u128(30);
        {
            let _serving = Serving::enter(id, 0x1234 as *mut c_void);
            assert_eq!(serving(), Some(Some(0x1234)));
            assert!(!serving_cancelled());
            assert!(thread::spawn(|| serving().is_none()).join().unwrap());
        }
        assert!(serving().is_none());
        let _serving = Serving::enter(id, std::ptr::null_mut());
        assert_eq!(serving(), Some(None));
    }

    #[test]
    fn agent_errors_map_to_quiet_hresults() {
        let hr = |code| rpc_hresult(&RpcError::new(code, "x"));
        assert_eq!(hr(ErrorCode::Cancelled), NTE_USER_CANCELLED);
        assert_eq!(hr(ErrorCode::Locked), NTE_USER_CANCELLED);
        assert_eq!(hr(ErrorCode::NotFound), NTE_NOT_FOUND);
        assert_eq!(hr(ErrorCode::InvalidState), NTE_EXISTS);
        assert_eq!(hr(ErrorCode::NotSupported), NTE_NOT_SUPPORTED);
        assert_eq!(hr(ErrorCode::InvalidParams), NTE_INVALID_PARAMETER);
        assert_eq!(hr(ErrorCode::Internal), E_FAIL);
    }

    #[test]
    fn log_lines_name_the_result() {
        assert_eq!(hresult_name(ERROR_BUSY.to_hresult()), "ERROR_BUSY");
        assert_eq!(hresult_label(NTE_NOT_FOUND), "NTE_NOT_FOUND (0x80090011)");
        assert_eq!(hresult_label(E_UNEXPECTED), "E_UNEXPECTED (0x8000FFFF)");
        assert_eq!(hresult_name(HRESULT(0x1234)), "HRESULT");
        let note = Note {
            transaction: Some(GUID::from_u128(0x1a2b3c4d_0000_0000_0000_000000000000)),
            locked: Some(true),
            unlocked: Some(true),
            list: Some(1),
            options: Some(ctap::Options {
                rk: None,
                up: Some(true),
                uv: Some(false),
            }),
            detail: Some("not_found: no passkey for this site in Passyble".into()),
        };
        assert_eq!(
            outcome_line(
                Operation::GetAssertion,
                NTE_NOT_FOUND,
                &note,
                Duration::from_millis(1250)
            ),
            "passkey provider: GetAssertion 1a2b3c4d -> NTE_NOT_FOUND (0x80090011) after 1.2 s, \
             vault locked, unlocked for it, allow list 1, up=true, uv=false: not_found: no \
             passkey for this site in Passyble"
        );
        let bare = outcome_line(
            Operation::MakeCredential,
            S_OK,
            &Note::default(),
            Duration::ZERO,
        );
        assert_eq!(
            bare,
            "passkey provider: MakeCredential -> S_OK (0x00000000) after 0.0 s"
        );
    }

    #[test]
    fn class_factory_hands_out_the_authenticator() {
        let factory: IClassFactory = Factory.into();
        let instance: IPluginAuthenticator =
            unsafe { factory.CreateInstance(None::<&windows::core::IUnknown>) }.unwrap();
        let mut status = -1;
        assert_eq!(unsafe { instance.GetLockStatus(&mut status) }, S_OK);
        assert_eq!(status, PLUGIN_LOCKED);
        let mut payload = ctap::authenticator_info(&pass_core::AAGUID);
        let request = WEBAUTHN_PLUGIN_OPERATION_REQUEST {
            hWnd: std::ptr::null_mut(),
            transactionId: GUID::from_u128(3),
            cbRequestSignature: 0,
            pbRequestSignature: std::ptr::null_mut(),
            requestType: WEBAUTHN_PLUGIN_REQUEST_TYPE_CTAP2_CBOR,
            cbEncodedRequest: payload.len() as u32,
            pbEncodedRequest: payload.as_mut_ptr(),
        };
        let mut response = WEBAUTHN_PLUGIN_OPERATION_RESPONSE {
            cbEncodedResponse: 0,
            pbEncodedResponse: std::ptr::null_mut(),
        };
        assert_eq!(
            unsafe { instance.MakeCredential(&request, &mut response) },
            NTE_BAD_SIGNATURE
        );
        assert!(response.pbEncodedResponse.is_null());
        let cancel = WEBAUTHN_PLUGIN_CANCEL_OPERATION_REQUEST {
            transactionId: GUID::from_u128(3),
            cbRequestSignature: 0,
            pbRequestSignature: std::ptr::null_mut(),
        };
        assert_eq!(unsafe { instance.CancelOperation(&cancel) }, NTE_NOT_FOUND);
    }
}
