//! The SPI1 provider installation and its runtime key, read through the
//! public seam at their fixed paths (ADR-069 R11 §4, #1358).
//!
//! The test runs as root in the isolated container, where `/var/lib` is a
//! fresh tmpfs, so it writes the real `/var/lib/pigloros/sandbox` tree.
#![cfg(target_os = "linux")]

use std::error::Error;
use std::fs;
use std::net::Ipv4Addr;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::Path;
use std::process::Command;

use ed25519_dalek::SigningKey;
use pos_sandboxd::{
    EgressProbe, ProviderInstallation, ProviderInstallationError, RuntimeKey, StagingLimits,
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

/// R11 §11 SPI1-A.
const SPI1_A: &str = "828764535049310184440a5800001650fd7069676c6f72000000000000000000187782440a59fffc199c401a40000000851901f41903e81905dc190bb8191388781b72756e74696d652d6174746573746174696f6e2e6564323535313958209d057c99cd949ef52cdcbeb13d26fd43f747d80ab26d539a11a31dd72e972003";
const KEY_FILE: &str = "runtime-attestation.ed25519";
const SEED: [u8; 32] = [7; 32];
const ROOT: &str = "/var/lib/pigloros/sandbox";

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap_or_default())
        .collect()
}

/// Run `name` again as root in the isolated container, or report that this
/// process already is that run.
fn in_isolated_root(name: &str) -> TestResult<bool> {
    if std::env::var_os("PIGLOROS_PRIVILEGED_COMPOSITION_TEST").is_some() {
        return Ok(true);
    }
    let runner = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/run-isolated-test.sh");
    let output = Command::new(runner)
        .arg(std::env::current_exe()?)
        .arg(name)
        .output()?;
    assert!(
        output.status.success(),
        "isolated test {name} failed: {:?}\n{}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(false)
}

/// Write `bytes` to `path` with `mode`.
fn write_file(path: &Path, bytes: &[u8], mode: u32) -> TestResult {
    fs::write(path, bytes)?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

/// The artifact root with SPI1-A and its key file.
fn install() -> TestResult {
    let root = Path::new(ROOT);
    fs::create_dir_all(root)?;
    for directory in ["/var/lib/pigloros", ROOT] {
        fs::set_permissions(directory, fs::Permissions::from_mode(0o755))?;
    }
    write_file(
        &root.join("provider-installation.cbor"),
        &hex(SPI1_A),
        0o400,
    )?;
    fs::create_dir(root.join("provider-keys"))?;
    fs::set_permissions(
        root.join("provider-keys"),
        fs::Permissions::from_mode(0o700),
    )?;
    write_file(&root.join("provider-keys").join(KEY_FILE), &SEED, 0o400)
}

#[test]
fn the_fixed_installation_yields_its_values_and_admitted_key() -> TestResult {
    if !in_isolated_root("the_fixed_installation_yields_its_values_and_admitted_key")? {
        return Ok(());
    }
    assert_eq!(fs::metadata("/var/lib")?.uid(), 0);
    // Nothing is installed yet.
    assert_eq!(
        ProviderInstallation::open().err(),
        Some(ProviderInstallationError::UnsafeFile)
    );
    install()?;
    let installation = ProviderInstallation::open()?;
    assert_eq!(installation.attempt_range().slots(), 256);
    assert_eq!(
        installation.egress_probe(),
        EgressProbe::new(Ipv4Addr::new(10, 89, 255, 252), 40000)?
    );
    assert_eq!(
        installation.staging_limits(),
        StagingLimits {
            aggregate_bytes: 1 << 30
        }
    );
    assert!(format!("{:?}", installation.cleanup_budget()).starts_with("CleanupBudget"));
    assert_eq!(installation.runtime_key_file(), KEY_FILE);
    // The key file holds the admitted key, and only that key is kept.
    let expected = SigningKey::from_bytes(&SEED).verifying_key();
    let key = RuntimeKey::open(&installation)?;
    assert_eq!(key.verifying_key(), expected);
    let key = key.require_admitted(&expected)?;
    let other = SigningKey::from_bytes(&[8; 32]).verifying_key();
    assert_eq!(
        key.require_admitted(&other).err(),
        Some(ProviderInstallationError::KeyMismatch)
    );
    // A group-writable ancestor, then a symlinked one, are refused.
    for (directory, mode) in [("/var/lib/pigloros", 0o775), (ROOT, 0o757)] {
        fs::set_permissions(directory, fs::Permissions::from_mode(mode))?;
        assert_eq!(
            ProviderInstallation::open().err(),
            Some(ProviderInstallationError::UnsafeFile)
        );
        fs::set_permissions(directory, fs::Permissions::from_mode(0o755))?;
    }
    fs::rename(ROOT, "/var/lib/pigloros/held")?;
    symlink("held", ROOT)?;
    assert_eq!(
        ProviderInstallation::open().err(),
        Some(ProviderInstallationError::UnsafeFile)
    );
    Ok(())
}
