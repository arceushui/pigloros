#![cfg(windows)]
#![forbid(unsafe_code)]

use std::os::windows::ffi::OsStrExt;
use std::process::Command;

use pos_owner_bridge::{ProbeResult, ProcessProbe};
use pos_owner_bridge_codec::ImagePathSha256;
use pos_owner_bridge_windows::{process_identity, WindowsProcessProbe};
use sha2::{Digest, Sha256};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn current_process_identity_matches_independent_os_observations() -> TestResult {
    let pid = std::process::id();
    let identity = process_identity(pid)?;
    let script = format!("(Get-Process -Id {pid}).StartTime.ToFileTimeUtc().ToString([System.Globalization.CultureInfo]::InvariantCulture)");
    let output = Command::new("powershell.exe")
        .env_remove("PSModulePath")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()?;
    assert!(output.status.success());
    let created: u64 = String::from_utf8(output.stdout)?.trim().parse()?;
    let mut digest = Sha256::new();
    for unit in std::env::current_exe()?.as_os_str().encode_wide() {
        digest.update(unit.to_le_bytes());
    }
    assert_eq!(identity.browser_pid, pid);
    assert_eq!(identity.creation_filetime, created);
    assert_eq!(
        identity.image_path_sha256,
        ImagePathSha256::from_bytes(digest.finalize().into())
    );
    let mut probe = WindowsProcessProbe;
    assert_eq!(
        probe.probe(pid, created, &identity.image_path_sha256),
        ProbeResult::Present
    );
    assert_eq!(
        probe.probe(pid, created + 1, &identity.image_path_sha256),
        ProbeResult::Absent
    );
    assert_eq!(
        probe.probe(pid, created, &ImagePathSha256::from_bytes([0; 32])),
        ProbeResult::Absent
    );
    Ok(())
}

#[test]
fn missing_process_is_absent_but_invalid_or_denied_inspection_is_indeterminate() {
    let mut probe = WindowsProcessProbe;
    let image = ImagePathSha256::from_bytes([0; 32]);
    assert_eq!(probe.probe(u32::MAX, 1, &image), ProbeResult::Absent);
    assert_eq!(probe.probe(0, 1, &image), ProbeResult::Indeterminate);
    // The Windows System process rejects user-mode OpenProcess queries.
    assert_eq!(probe.probe(4, 1, &image), ProbeResult::Indeterminate);
    assert!(process_identity(0).is_err());
    assert!(process_identity(u32::MAX).is_err());
}
