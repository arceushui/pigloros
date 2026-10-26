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

#[path = "support/staged_execution.rs"]
pub mod staged_execution;

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

use pos_reference::provider_admission::execution::{
    PreparedProviderExecution, StagingError, StagingUsage,
};
use std::{
    io::{Read as _, Write as _},
    os::unix::net::UnixStream,
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
    let staged = StagedInstallation::stage_execution().map_err(|error| error.to_string())?;
    let snapshot = ProviderImageSnapshot::open(staged.request())?;
    let request = snapshot.request();
    let ledger = StagingLedger::new(StagingLimits {
        aggregate_bytes: 512 * 1024 * 1024,
    });
    let (_staging, verified) = staged_execution::verified_input(&staged, &ledger)?;
    let entry = verified.entry();
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
    let staged = StagedInstallation::stage_execution().map_err(|error| error.to_string())?;
    let snapshot = ProviderImageSnapshot::open(staged.request())?;
    let request = snapshot.request();
    let ledger = StagingLedger::new(StagingLimits {
        aggregate_bytes: 512 * 1024 * 1024,
    });
    let (_staging, verified) = staged_execution::verified_input(&staged, &ledger)?;
    let entry = verified.entry();
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

fn source_pair(
    staged: &StagedInstallation,
    ledger: &StagingLedger,
) -> Result<(PreparedProviderExecution, UnixStream, UnixStream), BoxError> {
    let (mut provider, mut selector) = UnixStream::pair()?;
    staged.write_source(&mut selector)?;
    let prepared = PreparedProviderExecution::receive(&mut provider, ledger)?;
    Ok((prepared, provider, selector))
}

fn frame(writer: &mut impl std::io::Write, bytes: &[u8]) -> TestResult {
    writer.write_all(&u32::try_from(bytes.len())?.to_be_bytes())?;
    writer.write_all(bytes)?;
    Ok(())
}

#[test]
fn altered_source_and_same_fixture_budget_fail_before_grant_or_attempt_reservation() -> TestResult {
    if !require_isolated_root(
        "altered_source_and_same_fixture_budget_fail_before_grant_or_attempt_reservation",
    )? {
        return Ok(());
    }
    let staged = StagedInstallation::stage_execution().map_err(|error| error.to_string())?;
    let ledger = StagingLedger::new(StagingLimits {
        aggregate_bytes: 512 * 1024 * 1024,
    });
    let changed = [
        staged.changed_request(|request| request.request.request_id[0] ^= 1),
        staged.changed_request(|request| request.attempt_id[15] ^= 1),
        staged.changed_request(|request| request.authority.cpf1_digest[0] ^= 1),
        staged.changed_request(|request| request.authority.cfb1_digest[0] ^= 1),
        staged.changed_request(|request| request.authority.fixture_contract_digest[0] ^= 1),
        staged.changed_request(|request| request.authority.execution_profile_digest[0] ^= 1),
        staged.changed_request(|request| request.capability_ids.clear()),
        staged.changed_case_request(|attempt| attempt.watchdog_ms += 1),
        staged.changed_case_request(|attempt| attempt.budget.memory_bytes += 1),
    ];
    for request in changed {
        let request = request.map_err(|error| error.to_string())?;
        let (mut provider, mut selector) = UnixStream::pair()?;
        frame(&mut selector, staged.evaluation())?;
        frame(&mut selector, &request)?;
        assert!(matches!(
            PreparedProviderExecution::receive(&mut provider, &ledger),
            Err(StagingError::InvalidSource)
        ));
        assert_eq!(ledger.usage(), StagingUsage::default());
    }
    for records in [
        vec![staged.request()],
        vec![staged.evaluation()],
        vec![staged.evaluation(), staged.evaluation()],
        vec![staged.evaluation(), staged.request(), staged.request()],
        vec![],
    ] {
        let (mut provider, mut selector) = UnixStream::pair()?;
        for record in records {
            frame(&mut selector, record)?;
        }
        selector.shutdown(std::net::Shutdown::Write)?;
        assert!(PreparedProviderExecution::receive(&mut provider, &ledger).is_err());
        assert_eq!(ledger.usage(), StagingUsage::default());
    }
    let tiny = StagingLedger::new(StagingLimits { aggregate_bytes: 1 });
    assert!(source_pair(&staged, &tiny).is_err());
    assert_eq!(tiny.usage(), StagingUsage::default());
    Ok(())
}

#[test]
fn grant_and_input_are_single_use_and_bound_to_the_original_connection() -> TestResult {
    if !require_isolated_root(
        "grant_and_input_are_single_use_and_bound_to_the_original_connection",
    )? {
        return Ok(());
    }
    let staged = StagedInstallation::stage_execution().map_err(|error| error.to_string())?;
    let ledger = StagingLedger::new(StagingLimits {
        aggregate_bytes: 512 * 1024 * 1024,
    });
    let (mut prepared, mut provider, _selector) = source_pair(&staged, &ledger)?;
    let (mut foreign, _peer) = UnixStream::pair()?;
    assert!(matches!(
        prepared.send_grant(&mut foreign, |message| Ok(StagedInstallation::sign_grant(
            message
        ))),
        Err(StagingError::ConnectionChanged)
    ));
    assert!(matches!(
        prepared.send_grant(&mut provider, |_| Ok([1; 64])),
        Err(StagingError::InvalidSignature)
    ));
    assert!(matches!(
        prepared.send_grant(&mut provider, |_| Err(std::io::Error::other(
            "signer unavailable"
        ))),
        Err(StagingError::InvalidSignature)
    ));
    assert!(matches!(
        prepared.send_grant(&mut provider, |_| Ok([0; 64])),
        Err(StagingError::InvalidSignature)
    ));
    prepared.send_grant(&mut provider, |message| {
        Ok(StagedInstallation::sign_grant(message))
    })?;
    assert!(matches!(
        prepared.send_grant(&mut provider, |message| Ok(StagedInstallation::sign_grant(
            message
        ))),
        Err(StagingError::GrantAlreadyIssued)
    ));
    let directory = tempfile::tempdir()?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
    let held = fs::File::open(directory.path())?;
    let staging = pos_sandboxd::StagingDirectory::from_held_directory(
        held.try_clone()?,
        held.metadata()?.uid(),
    )?;
    assert!(matches!(
        staging
            .create_input([1; 16], prepared)?
            .receive(&mut foreign),
        Err(StagingError::ConnectionChanged)
    ));
    assert_eq!(ledger.usage(), StagingUsage::default());
    let (prepared, mut provider, _selector) = source_pair(&staged, &ledger)?;
    assert!(matches!(
        staging
            .create_input([2; 16], prepared)?
            .receive(&mut provider),
        Err(StagingError::GrantRequired)
    ));
    assert_eq!(ledger.usage(), StagingUsage::default());
    Ok(())
}

#[test]
fn incomplete_foreign_corrupt_or_duplicate_input_never_mints_an_entry() -> TestResult {
    if !require_isolated_root("incomplete_foreign_corrupt_or_duplicate_input_never_mints_an_entry")?
    {
        return Ok(());
    }
    let staged = StagedInstallation::stage_execution().map_err(|error| error.to_string())?;
    let ledger = StagingLedger::new(StagingLimits {
        aggregate_bytes: 512 * 1024 * 1024,
    });
    let mut complete = Vec::new();
    staged
        .write_input(&mut complete)
        .map_err(|error| error.to_string())?;
    let mut corrupt = complete.clone();
    if let Some(last) = corrupt.last_mut() {
        *last ^= 1;
    }
    let mut duplicate = complete.clone();
    duplicate.extend_from_slice(&complete);
    let mut foreign = Vec::new();
    frame(&mut foreign, staged.request())?;
    for bytes in [Vec::new(), foreign, corrupt, duplicate] {
        let (mut prepared, mut provider, mut selector) = source_pair(&staged, &ledger)?;
        prepared.send_grant(&mut provider, |message| {
            Ok(StagedInstallation::sign_grant(message))
        })?;
        selector.write_all(&bytes)?;
        selector.shutdown(std::net::Shutdown::Write)?;
        let directory = tempfile::tempdir()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let held = fs::File::open(directory.path())?;
        let staging = pos_sandboxd::StagingDirectory::from_held_directory(
            held.try_clone()?,
            held.metadata()?.uid(),
        )?;
        assert!(staging
            .create_input([1; 16], prepared)?
            .receive(&mut provider)
            .is_err());
        assert_eq!(ledger.usage(), StagingUsage::default());
    }
    Ok(())
}

#[test]
fn verified_input_retains_policy_and_one_attempt_until_output_is_dropped() -> TestResult {
    if !require_isolated_root(
        "verified_input_retains_policy_and_one_attempt_until_output_is_dropped",
    )? {
        return Ok(());
    }
    let staged = StagedInstallation::stage_execution().map_err(|error| error.to_string())?;
    let ledger = StagingLedger::new(StagingLimits {
        aggregate_bytes: 512 * 1024 * 1024,
    });
    let (_directory, input) = staged_execution::verified_input(&staged, &ledger)?;
    let policy = input.entry().policy().clone();
    assert_eq!(input.len(), staged.input().len() as u64);
    assert!(!input.is_empty());
    let mut readback = vec![0; staged.input().len()];
    input.read_exact_at(&mut readback, 0)?;
    assert_eq!(readback, staged.input());
    assert!(input.read_exact_at(&mut [0], input.len()).is_err());
    assert_eq!(policy.effective_limits().len(), 17);
    assert_ne!(policy.effective_limits_digest(), [0; 32]);
    assert_ne!(policy.expected_readback_digest(), [0; 32]);
    assert!(matches!(
        input.reserve_output(u64::MAX),
        Err(StagingError::OutputTooLarge)
    ));
    let output = input.reserve_output(1)?;
    assert!(matches!(
        input.reserve_output(0),
        Err(StagingError::OutputAlreadyReserved)
    ));
    assert_eq!(ledger.usage().queued_inputs, 0);
    assert_eq!(ledger.usage().attempts, 1);
    drop(input);
    assert_eq!(ledger.usage().attempts, 1);
    drop(output);
    assert_eq!(ledger.usage(), StagingUsage::default());
    Ok(())
}

#[test]
fn a_floor_raised_by_a_slow_signer_is_rechecked_before_any_grant_bytes() -> TestResult {
    if !require_isolated_root(
        "a_floor_raised_by_a_slow_signer_is_rechecked_before_any_grant_bytes",
    )? {
        return Ok(());
    }
    let staged = StagedInstallation::stage_execution().map_err(|error| error.to_string())?;
    let ledger = StagingLedger::new(StagingLimits {
        aggregate_bytes: 512 * 1024 * 1024,
    });
    let (mut prepared, mut provider, mut selector) = source_pair(&staged, &ledger)?;
    let error = prepared.send_grant(&mut provider, |message| {
        ledger.raise_floor(pos_sandboxd::ControlFloor {
            revocation_epoch: u64::MAX,
            policy_epoch: u64::MAX,
        });
        Ok(StagedInstallation::sign_grant(message))
    });
    assert!(matches!(error, Err(StagingError::BelowControlFloor)));
    drop((prepared, provider));
    assert_eq!(selector.read(&mut [0])?, 0);
    assert_eq!(ledger.usage().attempts, 0);
    assert_eq!(ledger.usage().reserved_bytes, 0);
    Ok(())
}

#[test]
fn extra_source_after_preparation_is_refused_before_any_grant_bytes() -> TestResult {
    if !require_isolated_root("extra_source_after_preparation_is_refused_before_any_grant_bytes")? {
        return Ok(());
    }
    let staged = StagedInstallation::stage_execution().map_err(|error| error.to_string())?;
    let ledger = StagingLedger::new(StagingLimits {
        aggregate_bytes: 512 * 1024 * 1024,
    });
    let (mut prepared, mut provider, mut selector) = source_pair(&staged, &ledger)?;
    frame(&mut selector, staged.request())?;
    assert!(matches!(
        prepared.send_grant(&mut provider, |message| Ok(StagedInstallation::sign_grant(
            message
        ))),
        Err(StagingError::InvalidSource)
    ));
    drop((prepared, provider));
    assert!(match selector.read(&mut [0]) {
        Ok(length) => length == 0,
        Err(error) => error.kind() == std::io::ErrorKind::ConnectionReset,
    });
    assert_eq!(ledger.usage(), StagingUsage::default());
    Ok(())
}

#[test]
fn a_pending_installation_update_is_rechecked_after_signing_before_grant_output() -> TestResult {
    if !require_isolated_root(
        "a_pending_installation_update_is_rechecked_after_signing_before_grant_output",
    )? {
        return Ok(());
    }
    let staged = StagedInstallation::stage_execution().map_err(|error| error.to_string())?;
    let ledger = StagingLedger::new(StagingLimits {
        aggregate_bytes: 512 * 1024 * 1024,
    });
    let (mut prepared, mut provider, mut selector) = source_pair(&staged, &ledger)?;
    let recovery = Path::new(pos_reference::selector::installation::SANDBOX_ARTIFACT_ROOT)
        .join("installation-update.cbor");
    let result = prepared.send_grant(&mut provider, |message| {
        fs::write(&recovery, b"pending installation transaction")?;
        Ok(StagedInstallation::sign_grant(message))
    });
    assert!(matches!(result, Err(StagingError::Source(_))));
    drop((prepared, provider));
    assert_eq!(selector.read(&mut [0])?, 0);
    assert_eq!(ledger.usage(), StagingUsage::default());
    Ok(())
}

#[test]
fn admission_charges_actual_retained_bytes_and_no_hard_cap_maximum() -> TestResult {
    if !require_isolated_root("admission_charges_actual_retained_bytes_and_no_hard_cap_maximum")? {
        return Ok(());
    }
    let staged = StagedInstallation::stage_execution().map_err(|error| error.to_string())?;
    let case = pos_reference::adapter_transport::read_attempt(staged.input())?;
    let mut expected = staged.evaluation().len() as u64
        + staged.request().len() as u64
        + staged.input().len() as u64
        + case.case_id.len() as u64
        + case.schema.bytes.len() as u64
        + case.payload.bytes.len() as u64;
    for artifact in &case.auxiliary {
        expected += artifact.bytes.len() as u64;
    }
    for capability in &case.capability_ids {
        expected += capability.len() as u64;
    }
    let ledger = StagingLedger::new(StagingLimits {
        aggregate_bytes: expected,
    });
    let exchange = source_pair(&staged, &ledger)?;
    assert_eq!(ledger.usage().reserved_bytes, expected);
    assert_eq!(ledger.usage().attempts, 1);
    drop(exchange);
    assert_eq!(ledger.usage(), StagingUsage::default());
    let short = StagingLedger::new(StagingLimits {
        aggregate_bytes: expected.checked_sub(1).ok_or("empty fixture")?,
    });
    assert!(
        matches!(source_pair(&staged, &short), Err(error) if error.downcast_ref::<StagingError>().is_some_and(|error| matches!(error, StagingError::AggregateExceeded)))
    );
    assert_eq!(short.usage(), StagingUsage::default());
    Ok(())
}

#[test]
fn private_staging_descriptor_exhaustion_releases_the_prepared_exchange() -> TestResult {
    if !require_isolated_root(
        "private_staging_descriptor_exhaustion_releases_the_prepared_exchange",
    )? {
        return Ok(());
    }
    let staged = StagedInstallation::stage_execution().map_err(|error| error.to_string())?;
    let ledger = StagingLedger::new(StagingLimits {
        aggregate_bytes: 512 * 1024 * 1024,
    });
    let (prepared, _provider, _selector) = source_pair(&staged, &ledger)?;
    let temporary = tempfile::tempdir()?;
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))?;
    let held = fs::File::open(temporary.path())?;
    let staging = pos_sandboxd::StagingDirectory::from_held_directory(
        held.try_clone()?,
        held.metadata()?.uid(),
    )?;
    let original = rustix::process::getrlimit(rustix::process::Resource::Nofile);
    rustix::process::setrlimit(
        rustix::process::Resource::Nofile,
        rustix::process::Rlimit {
            current: Some(0),
            maximum: original.maximum,
        },
    )?;
    let result = staging.create_input([0x41; 16], prepared);
    rustix::process::setrlimit(rustix::process::Resource::Nofile, original)?;
    assert!(matches!(result, Err(StagingError::Io(_))));
    assert_eq!(ledger.usage(), StagingUsage::default());
    assert_eq!(fs::read_dir(temporary.path())?.count(), 0);
    Ok(())
}
