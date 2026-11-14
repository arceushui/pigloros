//! Restart removal of every recognized pre-launch crash state, intent last.

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod cases {
    use std::fs::{self, File};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::Path;

    use super::super::super::super::tests::{in_lock_test_process, with_io_fault};
    use super::super::super::super::RegistryDirectory;
    use super::super::*;
    use crate::restart::RootsReleased;
    use crate::{SystemdAttemptRegistry, SystemdAttemptUnitAbsenceObservation};

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    /// The recorded attempt whose PAI3 root facts are committed.
    const ROOT_ATTEMPT: [u8; 16] = [7; 16];

    fn intent(id: u8) -> TestResult<PlannedAttemptIntent> {
        Ok(PlannedAttemptIntent::new([id; 16], [2; 32])?)
    }

    fn private_directory(path: &Path) -> TestResult {
        fs::create_dir(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        Ok(())
    }

    fn temporary(runtime: &Path, id: u8, bytes: &[u8]) -> TestResult {
        let key = intent(id)?.unit_name().attempt_component().to_owned();
        let path = runtime.join("registry").join(format!(".planned-{key}-1-1"));
        fs::write(&path, bytes)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        Ok(())
    }

    /// Every pre-launch crash state, one attempt each:
    /// 1 planned only; 2 attempt directory before its root; 3 both directories
    /// before the identity extension; 4 the recorded tree; 5 its root removed but
    /// its attempt directory present (#721); 6 both removed, record present;
    /// 7 a recorded PAI3 root, unmounted; 8 an interrupted temporary write;
    /// 9 a complete temporary write that was never renamed. Beside them, the
    /// owner's activation marker and an interrupted write of its replacement.
    fn seed() -> TestResult<tempfile::TempDir> {
        let runtime = tempfile::tempdir()?;
        fs::set_permissions(runtime.path(), fs::Permissions::from_mode(0o700))?;
        private_directory(&runtime.path().join("registry"))?;
        private_directory(&runtime.path().join("attempts"))?;
        let parent = File::open(runtime.path())?;
        let registry =
            SystemdAttemptRegistry::from_runtime_directory(&parent, parent.metadata()?.uid())?;
        let attempts = runtime.path().join("attempts");
        for id in 1..=7 {
            let committed = registry.commit_planned(&intent(id)?)?;
            let attempt = attempts.join(intent(id)?.unit_name().attempt_component());
            match id {
                1 => {}
                2 => private_directory(&attempt)?,
                3 => {
                    private_directory(&attempt)?;
                    private_directory(&attempt.join("root"))?;
                }
                7 => {
                    let prepared = committed.prepare_fixture_directory()?;
                    let identity = crate::test_fixtures::recorded_identity(&prepared)?;
                    prepared.record_root(&identity, || Ok(()))?;
                }
                _ => {
                    drop(committed.prepare_fixture_directory()?);
                    if id >= 5 {
                        fs::remove_dir(attempt.join("root"))?;
                    }
                    if id == 6 {
                        fs::remove_dir(&attempt)?;
                    }
                }
            }
        }
        drop(registry);
        temporary(runtime.path(), 8, &intent(8)?.encode()[..30])?;
        temporary(runtime.path(), 9, &intent(9)?.encode())?;
        let marker = runtime.path().join("registry/.activation-1-2");
        fs::write(&marker, b"PAA1")?;
        fs::set_permissions(marker, fs::Permissions::from_mode(0o600))?;
        Ok(runtime)
    }

    fn recovery(runtime: &Path) -> TestResult<SystemdAttemptRecovery> {
        let parent = File::open(runtime)?;
        let held = RegistryDirectory::from_runtime_directory(&parent, parent.metadata()?.uid())?;
        Ok(SystemdAttemptRecovery::from_directory(held)?)
    }

    /// Exact unit absence for every entry, as restart reconciliation proves it.
    fn absences(recovery: &SystemdAttemptRecovery) -> Vec<SystemdAttemptUnitAbsenceObservation> {
        recovery
            .entries()
            .iter()
            .map(|entry| SystemdAttemptUnitAbsenceObservation::for_test(entry.unit_name().clone()))
            .collect()
    }

    /// Released-root evidence for exactly `attempt_ids`.
    fn released(attempt_ids: &[[u8; 16]]) -> RootsReleased {
        RootsReleased::for_test(attempt_ids.to_vec())
    }

    fn count(path: &Path) -> TestResult<usize> {
        Ok(fs::read_dir(path)?.count())
    }

    #[test]
    fn every_pre_launch_crash_state_is_removed_with_its_intent_last() -> TestResult {
        if !in_lock_test_process(
        "attempt_registry::recovery::removal::tests::cases::every_pre_launch_crash_state_is_removed_with_its_intent_last",
    )? {
        return Ok(());
    }
        let runtime = seed()?;
        let recovery = recovery(runtime.path())?;
        assert_eq!(recovery.entries().len(), 9);
        let attempts =
            recovery.remove_reconciled(&absences(&recovery), &released(&[ROOT_ATTEMPT]))?;
        // The committed intents, in canonical order; temporary writes are not
        // committed ownership.
        let expected = (1..=7).map(intent).collect::<Result<Vec<_>, _>>()?;
        assert_eq!(attempts, expected);
        // Only the committed activation marker is kept.
        assert_eq!(count(&runtime.path().join("registry"))?, 1);
        assert!(runtime.path().join("registry/activation").is_file());
        assert_eq!(count(&runtime.path().join("attempts"))?, 0);
        drop(recovery);
        let parent = File::open(runtime.path())?;
        SystemdAttemptRegistry::from_runtime_directory(&parent, parent.metadata()?.uid())?
            .commit_planned(&intent(10)?)?;
        Ok(())
    }

    #[test]
    fn missing_unit_or_root_evidence_removes_nothing() -> TestResult {
        if !in_lock_test_process(
        "attempt_registry::recovery::removal::tests::cases::missing_unit_or_root_evidence_removes_nothing",
    )? {
        return Ok(());
    }
        let runtime = seed()?;
        let recovery = recovery(runtime.path())?;
        let mut partial = absences(&recovery);
        partial.remove(0);
        // A missing unit; no released root; only another attempt's root.
        for (units, roots) in [
            (partial, released(&[ROOT_ATTEMPT])),
            (absences(&recovery), released(&[])),
            (absences(&recovery), released(&[[1; 16]])),
        ] {
            assert!(matches!(
                recovery.remove_reconciled(&units, &roots),
                Err(SystemdAttemptRegistryError::CleanupEvidence)
            ));
            recovery.verify_unchanged()?;
            assert_eq!(count(&runtime.path().join("attempts"))?, 5);
        }
        Ok(())
    }

    #[test]
    fn an_unknown_attempt_directory_is_refused_before_removal() -> TestResult {
        if !in_lock_test_process(
        "attempt_registry::recovery::removal::tests::cases::an_unknown_attempt_directory_is_refused_before_removal",
    )? {
        return Ok(());
    }
        let runtime = seed()?;
        private_directory(
            &runtime
                .path()
                .join("attempts")
                .join(intent(11)?.unit_name().attempt_component()),
        )?;
        let recovery = recovery(runtime.path())?;
        assert!(recovery
            .remove_reconciled(&absences(&recovery), &released(&[ROOT_ATTEMPT]))
            .is_err());
        assert_eq!(count(&runtime.path().join("registry"))?, 11);
        assert_eq!(count(&runtime.path().join("attempts"))?, 6);
        Ok(())
    }

    #[test]
    fn a_crash_at_every_removal_step_is_reconciled_by_the_next_restart() -> TestResult {
        if !in_lock_test_process(
        "attempt_registry::recovery::removal::tests::cases::a_crash_at_every_removal_step_is_reconciled_by_the_next_restart",
    )? {
        return Ok(());
    }
        let operations = {
            let runtime = seed()?;
            let recovery = recovery(runtime.path())?;
            let evidence = absences(&recovery);
            let (result, count) = with_io_fault(None, || {
                recovery.remove_reconciled(&evidence, &released(&[ROOT_ATTEMPT]))
            });
            result?;
            count
        };
        for fail_at in 0..operations {
            let runtime = seed()?;
            let interrupted = recovery(runtime.path())?;
            let evidence = absences(&interrupted);
            let (result, _) = with_io_fault(Some(fail_at), || {
                interrupted.remove_reconciled(&evidence, &released(&[ROOT_ATTEMPT]))
            });
            assert!(result.is_err(), "step {fail_at}");
            drop(interrupted);
            // The restarted owner inventories whatever survived and finishes it.
            let restarted = recovery(runtime.path())?;
            restarted.remove_reconciled(&absences(&restarted), &released(&[ROOT_ATTEMPT]))?;
            assert_eq!(
                count(&runtime.path().join("registry"))?,
                1,
                "step {fail_at}"
            );
            assert_eq!(
                count(&runtime.path().join("attempts"))?,
                0,
                "step {fail_at}"
            );
        }
        Ok(())
    }
}
