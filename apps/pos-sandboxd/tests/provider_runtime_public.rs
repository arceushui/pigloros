//! The provider runtime's startup authority through the public seam
//! (ADR-069 R11 §5.1 steps 2 and 3, #1358).
//!
//! As root in the isolated container, the signed test installation is staged
//! at its fixed path. This test binary is not the admitted provider binary,
//! so a startup that admits SIC1 always stops at the self-binding; the later
//! steps are exercised in the crate's own tests.
#![cfg(target_os = "linux")]

use std::error::Error;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

use pos_reference::provider_admission::test_support::StagedInstallation;
use pos_reference::selector::installation::SANDBOX_ARTIFACT_ROOT;
use pos_reference::selector::SelectorBoundaryError;
use pos_sandboxd::{start_runtime_authority, ProviderStartupError};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

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

#[test]
fn startup_refuses_a_missing_or_pending_installation_and_a_foreign_executable() -> TestResult {
    if !in_isolated_root(
        "startup_refuses_a_missing_or_pending_installation_and_a_foreign_executable",
    )? {
        return Ok(());
    }
    // Step 2: no SIC1.
    assert!(matches!(
        start_runtime_authority(),
        Err(ProviderStartupError::Installation(_))
    ));
    let staged = StagedInstallation::stage()?;
    // Step 3: SIC1 is admitted, but this process does not run its binary.
    assert_eq!(
        start_runtime_authority().err(),
        Some(ProviderStartupError::SelfBinding)
    );
    // SIR1 pending: SIC1 itself is refused, before any other step.
    let pending = Path::new(SANDBOX_ARTIFACT_ROOT).join("installation-update.cbor");
    fs::write(&pending, b"pending")?;
    fs::set_permissions(&pending, fs::Permissions::from_mode(0o400))?;
    assert_eq!(
        start_runtime_authority().err(),
        Some(ProviderStartupError::Installation(
            SelectorBoundaryError::ArtifactInvalid
        ))
    );
    drop(staged);
    Ok(())
}
