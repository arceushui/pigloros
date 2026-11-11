#![cfg(windows)]
#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use pos_owner_bridge::{BridgeError, UnavailableCode};
use pos_owner_bridge_windows::{create_private_directory, verify_private_directory};

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Result<Self, std::io::Error> {
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "piglor-private-dir-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(std::io::Error::other)?
                .as_nanos(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root)?;
        Ok(Self(root))
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _removed = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn private_directory_is_current_sid_only_and_rejects_weakened_acl_and_links() -> TestResult {
    let fixture = Fixture::new()?;
    let path = fixture.0.join("private");
    create_private_directory(&path)
        .map_err(|error| format!("create private directory: {error}"))?;
    verify_private_directory(&path)
        .map_err(|error| format!("verify initial directory: {error}"))?;
    assert_eq!(
        create_private_directory(&path.join("child\0suffix")),
        Err(BridgeError::Unavailable(
            UnavailableCode::InterfaceUnavailable
        ))
    );
    assert!(std::fs::read_dir(&path)?.next().is_none());
    verify_private_directory(&path)
        .map_err(|error| format!("verify directory after rejected path: {error}"))?;
    assert!(create_private_directory(&path).is_err());
    assert!(create_private_directory(std::path::Path::new("relative")).is_err());
    assert!(verify_private_directory(std::path::Path::new("relative")).is_err());
    assert!(verify_private_directory(&fixture.0.join("missing")).is_err());
    assert!(create_private_directory(&fixture.0.join("missing/child")).is_err());
    let file = fixture.0.join("ordinary-file");
    std::fs::write(&file, b"not a directory")?;
    assert!(verify_private_directory(&file).is_err());

    let output = Command::new("powershell.exe")
        .env_remove("PSModulePath")
        .args(["-NoProfile", "-NonInteractive", "-Command", r"
            $ErrorActionPreference = 'Stop'
            $acl = Get-Acl -LiteralPath $env:PIGLOR_DIRECTORY_FIXTURE
            $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
            if (-not $acl.AreAccessRulesProtected) { throw 'DACL inherits' }
            if ($acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value -ne $sid) { throw 'wrong owner' }
            $rules = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
            if ($rules.Count -ne 1 -or $rules[0].IdentityReference.Value -ne $sid) { throw 'additional principal' }
            if ($rules[0].AccessControlType -ne 'Allow' -or $rules[0].FileSystemRights -ne 'FullControl') { throw 'wrong rights' }
            if ($rules[0].InheritanceFlags -ne 'ContainerInherit, ObjectInherit') { throw 'children are not private' }
        "])
        .env("PIGLOR_DIRECTORY_FIXTURE", &path)
        .output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let broadened = Command::new("icacls.exe")
        .arg(&path)
        .args(["/grant", "*S-1-1-0:(RX)"])
        .output()?;
    assert!(broadened.status.success());
    assert!(verify_private_directory(&path).is_err());
    let restored = Command::new("icacls.exe")
        .arg(&path)
        .args(["/remove:g", "*S-1-1-0"])
        .output()?;
    assert!(restored.status.success());
    verify_private_directory(&path).map_err(|error| format!("verify restored ACL: {error}"))?;

    let junction = fixture.0.join("junction");
    let linked = Command::new("cmd.exe")
        .args(["/d", "/c", "mklink", "/J"])
        .arg(&junction)
        .arg(&path)
        .output()?;
    assert!(linked.status.success());
    assert!(verify_private_directory(&junction).is_err());
    assert!(create_private_directory(&junction.join("escaped")).is_err());
    assert!(!path.join("escaped").exists());
    Ok(())
}
