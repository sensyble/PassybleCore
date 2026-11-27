//! The package with external location ("sparse package") that gives `Pass.exe` package identity.
//!
//! Every build names the package in its embedded manifest (`build.rs`: an `<msix>` element with
//! [`PACKAGE_NAME`](super::PACKAGE_NAME) / [`PACKAGE_PUBLISHER`](super::PACKAGE_PUBLISHER)); installers
//! ship the package files in `<install>\package\`. Turning the passkey provider on registers it for the
//! current user with the install folder as external location (`PackageManager`):
//! * `package\Passyble.msix` present (signed release builds): `AddPackageByUriAsync`. No Developer Mode.
//! * otherwise, with Developer Mode on: `RegisterPackageByUriAsync` on the loose `AppxManifest.xml`.
//! * otherwise: an error asking for Developer Mode or a signed build.
//!
//! Identity is fixed when a process starts, so Passyble restarts once after registering. Unsigned
//! packages (`AllowUnsigned`) are not an option: they need the
//! `OID.2.25.311729368913984317654407730594956997722=1` publisher marker, and Windows refuses to start an
//! exe whose manifest `<msix>` publisher contains an OID (side-by-side error).

use std::path::{Path, PathBuf};

use windows::core::HSTRING;
use windows::Foundation::Uri;
use windows::Management::Deployment::{
    AddPackageOptions, DeploymentProgress, DeploymentResult, PackageManager,
    RegisterPackageOptions, RemovalOptions,
};
use windows_future::IAsyncOperationWithProgress;

use super::{CLSID, PACKAGE_NAME, PACKAGE_PUBLISHER};

pub const SIGNED_PACKAGE: &str = "Passyble.msix";
const MANIFEST: &str = "AppxManifest.xml";

pub fn needs_developer_mode() -> String {
    crate::i18n::tr!("errors.pp_needs_dev_mode")
}

#[derive(Debug, Clone)]
pub struct Registered {
    pub full_name: String,
    pub version: String,
    pub external: Option<PathBuf>,
    pub development_mode: bool,
}

pub fn exe_dir() -> Result<PathBuf, String> {
    let unknown = || crate::i18n::tr!("errors.pp_no_folder");
    let exe = std::env::current_exe()
        .map_err(|e| crate::errors::logged(unknown(), "passkey provider", e))?;
    let exe = dunce_canonical(&exe);
    exe.parent().map(Path::to_path_buf).ok_or_else(unknown)
}

/// `canonicalize` without the `\\?\` prefix (PackageManager and file URIs don't want it).
fn dunce_canonical(path: &Path) -> PathBuf {
    let Ok(canonical) = path.canonicalize() else {
        return path.to_path_buf();
    };
    let text = canonical.to_string_lossy();
    match text.strip_prefix(r"\\?\") {
        Some(rest) if !rest.starts_with("UNC\\") => PathBuf::from(rest),
        _ => canonical,
    }
}

pub fn files_dir() -> Result<PathBuf, String> {
    Ok(exe_dir()?.join("package"))
}

/// Developer Mode (Settings → System → For developers) allows registering the loose manifest.
pub fn developer_mode() -> bool {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    winreg::RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey(r"SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock")
        .and_then(|k| k.get_value::<u32, _>("AllowDevelopmentWithoutDevLicense"))
        .is_ok_and(|v| v == 1)
}

fn xml_attr(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// The staged `AppxManifest.xml` must describe the package this exe's manifest names, with this
/// build's COM class; otherwise registration "works" but Pass.exe never gets identity.
pub fn check_manifest(text: &str) -> Result<(), String> {
    let expect = [
        ("name", format!("Name=\"{}\"", xml_attr(PACKAGE_NAME))),
        (
            "publisher",
            format!("Publisher=\"{}\"", xml_attr(PACKAGE_PUBLISHER)),
        ),
        ("COM class", format!("Id=\"{CLSID}\"")),
        ("executable", "Executable=\"Pass.exe\"".to_string()),
    ];
    for (what, needle) in expect {
        if !text.contains(&needle) {
            return Err(crate::errors::logged(
                crate::i18n::tr!("errors.pp_manifest_mismatch"),
                "passkey provider",
                format!("the staged manifest has a different {what} (expected {needle})"),
            ));
        }
    }
    Ok(())
}

pub struct Files {
    pub manifest: bool,
    pub signed: bool,
    pub error: Option<String>,
}

pub fn files() -> Files {
    let Ok(dir) = files_dir() else {
        return Files {
            manifest: false,
            signed: false,
            error: Some(crate::i18n::tr!("errors.pp_no_folder")),
        };
    };
    let manifest = std::fs::read_to_string(dir.join(MANIFEST)).ok();
    let error = match &manifest {
        None => Some(crate::i18n::tr!("errors.pp_files_missing")),
        Some(text) => check_manifest(text).err(),
    };
    Files {
        manifest: manifest.is_some() && error.is_none(),
        signed: dir.join(SIGNED_PACKAGE).is_file(),
        error,
    }
}

fn file_uri(path: &Path) -> Result<Uri, String> {
    let text = path.to_string_lossy().replace('\\', "/");
    let mut encoded = String::with_capacity(text.len() + 8);
    for c in text.chars() {
        match c {
            ' ' => encoded.push_str("%20"),
            '#' => encoded.push_str("%23"),
            '%' => encoded.push_str("%25"),
            _ => encoded.push(c),
        }
    }
    Uri::CreateUri(&HSTRING::from(format!("file:///{encoded}")))
        .map_err(|e| registration_failed(format!("{}: {e}", path.display())))
}

pub fn same_dir(a: &Path, b: &Path) -> bool {
    let norm = |p: &Path| {
        dunce_canonical(p)
            .to_string_lossy()
            .trim_end_matches('\\')
            .to_lowercase()
    };
    norm(a) == norm(b)
}

fn package_manager() -> Result<PackageManager, String> {
    PackageManager::new().map_err(|e| check_failed(format!("PackageManager: {e}")))
}

pub fn find() -> Result<Vec<Registered>, String> {
    let manager = package_manager()?;
    let packages = manager
        .FindPackagesByUserSecurityIdNamePublisher(
            &HSTRING::new(),
            &HSTRING::from(PACKAGE_NAME),
            &HSTRING::from(PACKAGE_PUBLISHER),
        )
        .map_err(|e| check_failed(format!("FindPackages: {e}")))?;
    let mut found = Vec::new();
    for package in packages {
        let Ok(id) = package.Id() else { continue };
        let full_name = id.FullName().map(|n| n.to_string()).unwrap_or_default();
        let version = id
            .Version()
            .map(|v| format!("{}.{}.{}.{}", v.Major, v.Minor, v.Build, v.Revision))
            .unwrap_or_default();
        let external = package
            .EffectiveExternalPath()
            .ok()
            .map(|p| p.to_string())
            .filter(|p| !p.is_empty())
            .map(PathBuf::from);
        found.push(Registered {
            full_name,
            version,
            external,
            development_mode: package.IsDevelopmentMode().unwrap_or(false),
        });
    }
    Ok(found)
}

pub fn registered_here() -> Result<Option<Registered>, String> {
    let dir = exe_dir()?;
    Ok(find()?
        .into_iter()
        .find(|r| r.external.as_deref().is_some_and(|e| same_dir(e, &dir))))
}

fn check_failed(detail: String) -> String {
    crate::errors::logged(
        crate::i18n::tr!("errors.pp_package_check_failed"),
        "passkey provider",
        detail,
    )
}

fn registration_failed(detail: impl std::fmt::Display) -> String {
    crate::errors::logged(
        crate::i18n::tr!("errors.pp_register_failed"),
        "passkey provider",
        detail,
    )
}

fn removal_failed(detail: impl std::fmt::Display) -> String {
    crate::errors::logged(
        crate::i18n::tr!("errors.pp_unregister_failed"),
        "passkey provider",
        detail,
    )
}

fn deploy(
    what: &str,
    op: windows::core::Result<IAsyncOperationWithProgress<DeploymentResult, DeploymentProgress>>,
) -> Result<(), String> {
    let op = op.map_err(|e| format!("{what}: {e}"))?;
    let joined = op.join();
    let detail = op.GetResults().ok().and_then(|r| {
        let code = r.ExtendedErrorCode().ok()?;
        code.is_err().then(|| {
            let text = r.ErrorText().map(|t| t.to_string()).unwrap_or_default();
            format!("{} (0x{:08X})", text.trim(), code.0 as u32)
        })
    });
    match (joined, detail) {
        (_, Some(detail)) => Err(format!("{what}: {detail}")),
        (Err(e), None) => Err(format!("{what}: {e}")),
        (Ok(_), None) => Ok(()),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Signed,
    DeveloperMode,
}

/// Registers the package for the current user with this exe's folder as external location, first
/// removing a registration for another folder (one user can only have one).
pub fn register() -> Result<Method, String> {
    let dir = exe_dir()?;
    let files_dir = dir.join("package");
    let manifest_path = files_dir.join(MANIFEST);
    let manifest = std::fs::read_to_string(&manifest_path).map_err(|e| {
        crate::errors::logged(
            crate::i18n::tr!("errors.pp_files_missing"),
            "passkey provider",
            format!("{}: {e}", manifest_path.display()),
        )
    })?;
    check_manifest(&manifest)?;

    for other in find()? {
        if !other.external.as_deref().is_some_and(|e| same_dir(e, &dir)) {
            remove(&other.full_name, false)?;
        }
    }

    let manager = package_manager()?;
    let external = file_uri(&dir)?;
    let mut errors = Vec::new();
    let msix = files_dir.join(SIGNED_PACKAGE);
    if msix.is_file() {
        let result = (|| {
            let options = AddPackageOptions::new().map_err(registration_failed)?;
            options
                .SetExternalLocationUri(&external)
                .and_then(|_| options.SetForceUpdateFromAnyVersion(true))
                .and_then(|_| options.SetDeferRegistrationWhenPackagesAreInUse(true))
                .map_err(registration_failed)?;
            deploy(
                "install Passyble.msix",
                manager.AddPackageByUriAsync(&file_uri(&msix)?, &options),
            )
            .map_err(registration_failed)
        })();
        match result {
            Ok(()) => return Ok(Method::Signed),
            Err(e) => errors.push(e),
        }
    }
    if developer_mode() {
        let options = RegisterPackageOptions::new().map_err(registration_failed)?;
        options
            .SetExternalLocationUri(&external)
            .and_then(|_| options.SetDeveloperMode(true))
            .and_then(|_| options.SetForceUpdateFromAnyVersion(true))
            .and_then(|_| options.SetDeferRegistrationWhenPackagesAreInUse(true))
            .map_err(registration_failed)?;
        deploy(
            "register the loose package",
            manager.RegisterPackageByUriAsync(&file_uri(&manifest_path)?, &options),
        )
        .map_err(registration_failed)?;
        return Ok(Method::DeveloperMode);
    }
    // The signed package was there but Windows refused it (the reason is in the log), or this
    // copy can't register one at all.
    Err(errors
        .into_iter()
        .next()
        .unwrap_or_else(needs_developer_mode))
}

/// Unregisters `full_name`. `defer`: when a process of the package is running (Passyble itself),
/// Windows removes it once that process exits instead of closing it.
fn remove(full_name: &str, defer: bool) -> Result<(), String> {
    let manager = package_manager()?;
    let options = if defer {
        RemovalOptions::DeferRemovalWhenPackagesAreInUse
    } else {
        RemovalOptions::None
    };
    deploy(
        "remove the package",
        manager.RemovePackageWithOptionsAsync(&HSTRING::from(full_name), options),
    )
    .map_err(removal_failed)
}

/// Unregisters every registration of the package for this user. `Ok(true)` if there was one. Deferred while Passyble runs with identity.
pub fn unregister() -> Result<bool, String> {
    let found = find()?;
    for package in &found {
        remove(&package.full_name, true)?;
    }
    Ok(!found.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn staged_manifest_must_match_the_build() {
        let template = include_str!("../../../../../Windows/installer/packaging/AppxManifest.xml");
        if PACKAGE_NAME == "Sensyble.Passyble" && PACKAGE_PUBLISHER == "CN=Sensyble" {
            assert_eq!(CLSID, super::super::DEFAULT_CLSID);
            check_manifest(template).unwrap();
        }
        let other = template.replace("Executable=\"Pass.exe\"", "Executable=\"Other.exe\"");
        assert!(check_manifest(&other).is_err());
        assert!(check_manifest("").is_err());
    }

    #[test]
    fn file_uris_escape_spaces() {
        let uri = file_uri(Path::new(
            r"C:\Program Files\Passyble\package\AppxManifest.xml",
        ))
        .unwrap();
        let text = uri.AbsoluteUri().unwrap().to_string();
        assert_eq!(
            text,
            "file:///C:/Program%20Files/Passyble/package/AppxManifest.xml"
        );
    }

    #[test]
    fn exe_dir_is_absolute() {
        let dir = exe_dir().unwrap();
        assert!(dir.is_absolute());
        assert!(!dir.to_string_lossy().starts_with(r"\\?\"));
        eprintln!("developer mode: {}", developer_mode());
        eprintln!("registrations: {:?}", find());
    }
}
