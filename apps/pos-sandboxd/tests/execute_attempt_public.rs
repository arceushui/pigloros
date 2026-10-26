//! #441 admitted-attempt facts through the real public chain.
//!
//! As root in the isolated container, the signed test installation is staged at
//! its fixed path, admitted through `ProviderImageSnapshot::open` and
//! `admit_held_image()`, and reserved. The execute path then takes the entry's
//! facts only together with a directory that was prepared for the same attempt
//! and image. The rest of the composition is exercised with ports in the
//! crate's own tests, because a rechecked root needs a real attached mount
//! (ADR-087 section 5, #444).
#![cfg(target_os = "linux")]

use std::{
    error::Error,
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
    process::Command,
};

use pos_reference::provider_admission::{test_support::StagedInstallation, ProviderImageSnapshot};
use pos_sandboxd::{
    AdmittedAttempt, ExecuteError, PlannedAttemptIntent, StagingLedger, StagingLimits,
    SystemdAttemptRegistry,
};

type BoxError = Box<dyn Error + Send + Sync>;
type TestResult = Result<(), BoxError>;

const PRIVILEGED_COMPOSITION_TEST: &str = "PIGLOROS_PRIVILEGED_COMPOSITION_TEST";

fn run_isolated(test_name: &str) -> TestResult {
    let runner = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/run-isolated-test.sh");
    let output = Command::new(runner)
        .arg(std::env::current_exe()?)
        .arg(test_name)
        .output()?;
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "isolated test {test_name} failed with {}:\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
    .into())
}

fn fixed_registry() -> TestResult {
    for component in [
        "/run/pigloros",
        "/run/pigloros/sandbox",
        "/run/pigloros/sandbox/registry",
        "/run/pigloros/sandbox/attempts",
    ] {
        fs::create_dir(component)?;
        fs::set_permissions(component, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn require_isolated_root(test_name: &str) -> Result<bool, BoxError> {
    if std::env::var_os(PRIVILEGED_COMPOSITION_TEST).is_none() {
        run_isolated(test_name)?;
        return Ok(false);
    }
    if fs::metadata("/proc/self")?.uid() != 0 {
        return Err("the isolated child is not root".into());
    }
    Ok(true)
}

#[test]
fn the_entry_facts_need_the_directory_prepared_for_the_same_attempt() -> TestResult {
    if !require_isolated_root("the_entry_facts_need_the_directory_prepared_for_the_same_attempt")? {
        return Ok(());
    }
    let staged = StagedInstallation::stage().map_err(|error| error.to_string())?;
    let snapshot = ProviderImageSnapshot::open(staged.request())?;
    let request = snapshot.request();
    let ledger = StagingLedger::new(StagingLimits {
        aggregate_bytes: 0,
        queued_requests: 0,
        concurrent_attempts: 1,
    });
    let entry = ledger.reserve_entry(snapshot.admit_held_image()?)?;
    fixed_registry()?;
    let registry = SystemdAttemptRegistry::open()?;
    let own = registry
        .commit_planned(&PlannedAttemptIntent::new(
            request.attempt_id,
            request.authority.sim1_digest,
        )?)?
        .prepare_directory()?;
    let foreign = registry
        .commit_planned(&PlannedAttemptIntent::new(
            [0x77; 16],
            request.authority.sim1_digest,
        )?)?
        .prepare_directory()?;

    let attempt = AdmittedAttempt::from_entry(&entry, &own)?;
    assert_eq!(attempt.attempt_id(), request.attempt_id);
    assert_eq!(attempt.unit_name(), own.intent().unit_name());
    assert_eq!(attempt.mode(), snapshot.launch_policy().execution_mode);
    assert_eq!(
        attempt.launcher_source().as_str(),
        snapshot.provider_binary().path()
    );
    let filter = attempt.system_call_filter();
    assert_eq!(
        filter.requested_property(),
        (true, snapshot.syscall_set().requested_names.clone())
    );
    filter.verify_readback(&(
        true,
        snapshot.syscall_set().expected_effective_names.clone(),
    ))?;
    assert!(matches!(
        AdmittedAttempt::from_entry(&entry, &foreign),
        Err(ExecuteError::DirectoryIdentity)
    ));
    Ok(())
}

#[test]
fn a_directory_for_another_image_is_rejected() -> TestResult {
    if !require_isolated_root("a_directory_for_another_image_is_rejected")? {
        return Ok(());
    }
    let staged = StagedInstallation::stage().map_err(|error| error.to_string())?;
    let snapshot = ProviderImageSnapshot::open(staged.request())?;
    let request = snapshot.request();
    let ledger = StagingLedger::new(StagingLimits {
        aggregate_bytes: 0,
        queued_requests: 0,
        concurrent_attempts: 1,
    });
    let entry = ledger.reserve_entry(snapshot.admit_held_image()?)?;
    fixed_registry()?;
    let other_image = SystemdAttemptRegistry::open()?
        .commit_planned(&PlannedAttemptIntent::new(request.attempt_id, [0x78; 32])?)?
        .prepare_directory()?;
    assert!(matches!(
        AdmittedAttempt::from_entry(&entry, &other_image),
        Err(ExecuteError::DirectoryIdentity)
    ));
    Ok(())
}
