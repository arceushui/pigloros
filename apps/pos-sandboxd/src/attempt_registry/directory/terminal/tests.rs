//! Intent-last terminal cleanup through the live owner's public seam.

use std::fs::{self, File};
use std::os::unix::fs::MetadataExt;

use super::super::super::tests::{in_lock_test_process, with_io_fault};
use super::super::super::RegistryDirectory;
use super::super::tests::{fixture, intent};
use super::*;
use crate::{SystemdAttemptRecovery, SystemdAttemptRegistry};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const UNSUBMITTED: AttemptUnitTermination<'static> = AttemptUnitTermination::Unsubmitted;

#[test]
fn eight_lifecycles_delete_each_intent_last_and_a_restarted_owner_opens_empty() -> TestResult {
    if !in_lock_test_process(
        "attempt_registry::directory::terminal::tests::eight_lifecycles_delete_each_intent_last_and_a_restarted_owner_opens_empty",
    )? {
        return Ok(());
    }
    let (runtime, registry) = fixture()?;
    let mut prepared = Vec::new();
    for id in 1..=8 {
        prepared.push(
            registry
                .commit_planned(&intent(id)?)?
                .prepare_fixture_directory()?,
        );
    }
    for (id, directory) in (1..=8).zip(prepared) {
        let planned = intent(id)?;
        let key = planned.unit_name().attempt_component();
        let ownership = directory.execution_ownership();
        let completed = directory.finish_terminal_cleanup(UNSUBMITTED, None)?;
        assert_eq!(completed.intent(), &planned);
        assert!(!runtime.path().join("attempts").join(key).exists());
        assert!(!runtime.path().join("registry").join(key).exists());
        assert_eq!(
            fs::read_dir(runtime.path().join("registry"))?.count(),
            9 - usize::from(id)
        );
        assert_eq!(
            fs::read_dir(runtime.path().join("attempts"))?.count(),
            8 - usize::from(id)
        );
        // Cleanup consumed the start permission of every surviving clone.
        assert!(ownership.claim().is_err());
    }
    // Completed cleanup leaves a clean owner open for the next attempt.
    registry
        .commit_planned(&intent(9)?)?
        .prepare_fixture_directory()?
        .finish_terminal_cleanup(UNSUBMITTED, None)?;
    drop(registry);
    let parent = File::open(runtime.path())?;
    let restarted =
        SystemdAttemptRegistry::from_runtime_directory(&parent, parent.metadata()?.uid())?;
    restarted.commit_planned(&intent(10)?)?;
    Ok(())
}

#[test]
fn missing_unit_or_root_evidence_removes_nothing_and_closes_commits() -> TestResult {
    for case in 0..4 {
        let (runtime, registry) = fixture()?;
        let planned = intent(1)?;
        let key = planned.unit_name().attempt_component();
        let directory = registry
            .commit_planned(&planned)?
            .prepare_fixture_directory()?;
        match case {
            // The claimed execution requested its unit start.
            0 => {
                let ownership = directory.execution_ownership();
                ownership.claim()?;
                ownership.submit()?;
            }
            // Its bound cgroup still needs stop evidence.
            1 => {
                let ownership = directory.execution_ownership();
                ownership.claim()?;
                ownership.submit()?;
                ownership.bind_cgroup((1, 2));
            }
            // mountfsd may have created loop/dm resources for this tree.
            2 => directory.begin_activation(),
            _ => {
                directory.begin_activation();
                directory.begin_activation();
            }
        }
        let record = runtime.path().join("registry").join(key);
        let bytes = fs::read(&record)?;
        let result = directory.finish_terminal_cleanup(UNSUBMITTED, None);
        assert!(
            matches!(result, Err(SystemdAttemptRegistryError::CleanupEvidence)),
            "case {case}: {result:?}"
        );
        assert!(runtime
            .path()
            .join("attempts")
            .join(key)
            .join("root")
            .exists());
        assert_eq!(fs::read(&record)?, bytes);
        assert!(registry.commit_planned(&intent(2)?).is_err());
    }
    Ok(())
}

#[test]
fn an_attempt_whose_unit_start_was_never_requested_is_fenced_and_cleaned() -> TestResult {
    // Unclaimed, claimed but not yet submitted, and closed by abandonment.
    for case in 0..3 {
        let (runtime, registry) = fixture()?;
        let planned = intent(1)?;
        let key = planned.unit_name().attempt_component();
        let directory = registry
            .commit_planned(&planned)?
            .prepare_fixture_directory()?;
        let ownership = directory.execution_ownership();
        match case {
            0 => {}
            1 => ownership.claim()?,
            _ => ownership.close(),
        }
        directory.finish_terminal_cleanup(UNSUBMITTED, None)?;
        assert!(!runtime.path().join("registry").join(key).exists());
        // A claimed execution can no longer request its unit start.
        assert!(ownership.submit().is_err(), "case {case}");
        assert!(ownership.claim().is_err(), "case {case}");
        registry.commit_planned(&intent(2)?)?;
    }
    Ok(())
}

#[test]
fn changed_record_or_tree_is_refused_before_intent_deletion() -> TestResult {
    for case in 0..3 {
        let (runtime, registry) = fixture()?;
        let planned = intent(1)?;
        let key = planned.unit_name().attempt_component();
        let directory = registry
            .commit_planned(&planned)?
            .prepare_fixture_directory()?;
        let attempt = runtime.path().join("attempts").join(key);
        let record = runtime.path().join("registry").join(key);
        match case {
            0 => {
                let mut changed = fs::read(&record)?;
                changed[52] ^= 1;
                fs::write(&record, changed)?;
            }
            1 => fs::write(attempt.join("root/unexpected"), b"retained")?,
            _ => fs::write(attempt.join("unexpected"), b"retained")?,
        }
        let bytes = fs::read(&record)?;
        assert!(
            directory
                .finish_terminal_cleanup(UNSUBMITTED, None)
                .is_err(),
            "case {case}"
        );
        assert!(attempt.join("root").exists(), "case {case}");
        assert_eq!(fs::read(&record)?, bytes);
        assert!(registry.commit_planned(&intent(2)?).is_err());
    }
    Ok(())
}

#[test]
fn every_terminal_io_failure_leaves_a_recoverable_frontier() -> TestResult {
    if !in_lock_test_process(
        "attempt_registry::directory::terminal::tests::every_terminal_io_failure_leaves_a_recoverable_frontier",
    )? {
        return Ok(());
    }
    let operation_count = {
        let (_runtime, registry) = fixture()?;
        let prepared = registry
            .commit_planned(&intent(1)?)?
            .prepare_fixture_directory()?;
        let (result, count) =
            with_io_fault(None, || prepared.finish_terminal_cleanup(UNSUBMITTED, None));
        result?;
        count
    };
    // Root present; root removed with attempt present; both removed with the
    // record present; record unlinked before its parent fsync.
    let mut frontiers = [false; 4];
    for fail_at in 0..operation_count {
        let (runtime, registry) = fixture()?;
        let planned = intent(1)?;
        let key = planned.unit_name().attempt_component();
        let directory = registry
            .commit_planned(&planned)?
            .prepare_fixture_directory()?;
        let attempt = runtime.path().join("attempts").join(key);
        let record = runtime.path().join("registry").join(key);
        let bytes = fs::read(&record)?;
        let (result, count) = with_io_fault(Some(fail_at), || {
            directory.finish_terminal_cleanup(UNSUBMITTED, None)
        });
        assert!(
            matches!(result, Err(SystemdAttemptRegistryError::Io(_))),
            "boundary {fail_at}: {result:?}"
        );
        assert_eq!(count, fail_at + 1);
        assert!(registry.commit_planned(&intent(2)?).is_err());
        let frontier = if attempt.join("root").exists() {
            0
        } else if attempt.exists() {
            1
        } else if record.exists() {
            2
        } else {
            3
        };
        frontiers[frontier] = true;
        if frontier < 3 {
            assert_eq!(fs::read(&record)?, bytes);
        }
        drop(registry);
        let parent = File::open(runtime.path())?;
        let held = RegistryDirectory::from_runtime_directory(&parent, parent.metadata()?.uid())?;
        let recovery = SystemdAttemptRecovery::from_directory(held)?;
        assert_eq!(recovery.entries().len(), usize::from(frontier < 3));
        let inventory = recovery.inventory_unmounted_directories()?;
        inventory.verify_unchanged()?;
        assert_eq!(inventory.directories().len(), usize::from(frontier < 2));
    }
    assert_eq!(frontiers, [true; 4]);
    Ok(())
}

#[test]
fn quarantine_is_kept_and_poisoned_ownership_never_deletes_intent() -> TestResult {
    for poisoned in [false, true] {
        let (runtime, registry) = fixture()?;
        let planned = intent(1)?;
        let key = planned.unit_name().attempt_component();
        let directory = registry
            .commit_planned(&planned)?
            .prepare_fixture_directory()?;
        if poisoned {
            assert!(std::panic::catch_unwind(|| {
                let _guard = registry.state.lock();
                std::panic::resume_unwind(Box::new(()));
            })
            .is_err());
        } else {
            registry
                .state
                .lock()
                .map_err(|_| "poisoned fixture")?
                .failed = true;
        }
        let result = directory.finish_terminal_cleanup(UNSUBMITTED, None);
        assert_eq!(
            matches!(
                result,
                Err(SystemdAttemptRegistryError::ReconciliationRequired)
            ),
            poisoned
        );
        assert_eq!(result.is_ok(), !poisoned);
        assert_eq!(runtime.path().join("registry").join(key).exists(), poisoned);
        assert_eq!(runtime.path().join("attempts").join(key).exists(), poisoned);
        assert!(registry.commit_planned(&intent(2)?).is_err());
    }
    Ok(())
}
