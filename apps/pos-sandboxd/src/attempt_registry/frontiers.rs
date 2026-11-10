//! Pre-launch crash frontiers of the registry and attempt directories.
//!
//! The live lifecycle of one attempt is replayed with an injected failure at
//! each registry I/O step in turn: every temporary write, fsync, rename, mkdir,
//! PAI2 and PAI3 extension, directory removal and the intent-last unlink. The
//! failed process state is then abandoned, as a crash would leave it, and a
//! restarted recovery owner must remove whatever survived. At every step the
//! intent must still exist while any attempt directory remains.
//!
//! Scope: only registry and directory frontiers before any unit exists. The
//! restart's unit, network and device proofs are given here as evidence; their
//! gating of removal is covered by the `restart` tests. Unit and mount
//! transitions are not reconciled positively yet (remaining #1200).

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod cases {
    use std::collections::BTreeSet;
    use std::fs::{self, File};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::Path;

    use super::super::tests::{in_lock_test_process, with_io_fault};
    use super::super::{
        AttemptUnitTermination, PlannedAttemptIntent, RegistryDirectory, SystemdAttemptRecovery,
        SystemdAttemptRegistry,
    };
    use crate::restart::RootsReleased;
    use crate::SystemdAttemptUnitAbsenceObservation;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    const ATTEMPT: [u8; 16] = [3; 16];

    /// What a crash left: a temporary write, the committed stage, the root and
    /// attempt directories.
    type Frontier = (bool, Option<[u8; 4]>, bool, bool);

    fn intent() -> TestResult<PlannedAttemptIntent> {
        Ok(PlannedAttemptIntent::new(ATTEMPT, [2; 32])?)
    }

    fn runtime() -> TestResult<tempfile::TempDir> {
        let runtime = tempfile::tempdir()?;
        for path in [
            runtime.path().to_path_buf(),
            runtime.path().join("registry"),
            runtime.path().join("attempts"),
        ] {
            fs::create_dir_all(&path)?;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        }
        Ok(runtime)
    }

    fn registry(runtime: &Path) -> TestResult<SystemdAttemptRegistry> {
        let parent = File::open(runtime)?;
        Ok(SystemdAttemptRegistry::from_runtime_directory(
            &parent,
            parent.metadata()?.uid(),
        )?)
    }

    /// Commit, extend with the tree, record the root, release it and finish.
    async fn lifecycle(registry: &SystemdAttemptRegistry) -> TestResult {
        let prepared = registry.commit_planned(&intent()?)?.prepare_directory()?;
        let identity = crate::test_fixtures::recorded_identity(&prepared)?;
        prepared.record_root(&identity, || Ok(()))?;
        let released = crate::test_fixtures::released_root(&prepared).await?;
        prepared.finish_terminal_cleanup(AttemptUnitTermination::Unsubmitted, Some(released))?;
        Ok(())
    }

    fn run(fail_at: Option<usize>, runtime: &Path) -> TestResult<(TestResult, usize)> {
        let tokio = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()?;
        let registry = registry(runtime)?;
        let observed = with_io_fault(fail_at, || tokio.block_on(lifecycle(&registry)));
        Ok(observed)
    }

    fn frontier(runtime: &Path) -> TestResult<Frontier> {
        let key = intent()?.unit_name().attempt_component().to_owned();
        let mut temporary = false;
        for entry in fs::read_dir(runtime.join("registry"))? {
            temporary |= entry?
                .file_name()
                .to_string_lossy()
                .starts_with(".planned-");
        }
        let record = runtime.join("registry").join(&key);
        let stage = record
            .exists()
            .then(|| fs::read(&record))
            .transpose()?
            .and_then(|bytes| bytes.get(..4).and_then(|tag| tag.try_into().ok()));
        let attempt = runtime.join("attempts").join(&key);
        Ok((
            temporary,
            stage,
            attempt.join("root").exists(),
            attempt.exists(),
        ))
    }

    /// Restart with its proofs given: exact unit absence for every entry and
    /// the recorded root's devices released. `restart` tests cover how those
    /// proofs gate removal.
    fn reconcile(runtime: &Path) -> TestResult {
        let parent = File::open(runtime)?;
        let held = RegistryDirectory::from_runtime_directory(&parent, parent.metadata()?.uid())?;
        let recovery = SystemdAttemptRecovery::from_directory(held)?;
        let absent = recovery
            .entries()
            .iter()
            .map(|entry| SystemdAttemptUnitAbsenceObservation::for_test(entry.unit_name().clone()))
            .collect::<Vec<_>>();
        recovery.remove_reconciled(&absent, &RootsReleased::for_test(vec![ATTEMPT]))?;
        Ok(())
    }

    /// Whether the intent outlives the directories: a surviving attempt
    /// directory, with or without its root, always has its committed record.
    const fn intent_covers_directories(frontier: Frontier) -> bool {
        frontier.1.is_some() || !frontier.3
    }

    #[test]
    fn a_crash_at_every_registry_step_leaves_a_pre_launch_frontier_restart_removes() -> TestResult {
        if !in_lock_test_process(
        "attempt_registry::frontiers::cases::a_crash_at_every_registry_step_leaves_a_pre_launch_frontier_restart_removes",
    )? {
        return Ok(());
    }
        let steps = {
            let runtime = runtime()?;
            let (result, steps) = run(None, runtime.path())?;
            result?;
            assert_eq!(frontier(runtime.path())?, (false, None, false, false));
            steps
        };
        let mut frontiers = BTreeSet::new();
        for fail_at in 0..steps {
            let runtime = runtime()?;
            let (result, _) = run(Some(fail_at), runtime.path())?;
            assert!(result.is_err(), "step {fail_at}");
            let crashed = frontier(runtime.path())?;
            assert!(
                intent_covers_directories(crashed),
                "step {fail_at}: {crashed:?}"
            );
            frontiers.insert(crashed);
            reconcile(runtime.path())?;
            assert_eq!(
                frontier(runtime.path())?,
                (false, None, false, false),
                "step {fail_at}"
            );
            // Only the owner's activation marker is kept.
            assert_eq!(fs::read_dir(runtime.path().join("registry"))?.count(), 1);
            // Admission reopens over the reconciled registry.
            registry(runtime.path())?.commit_planned(&intent()?)?;
        }
        for expected in [
            // An interrupted first write, then the planned-only intent.
            (true, None, false, false),
            (false, Some(*b"PAI1"), false, false),
            // mkdir of the attempt, then of its root, before the PAI2 extension.
            (false, Some(*b"PAI1"), false, true),
            (false, Some(*b"PAI1"), true, true),
            // The extended tree, an interrupted PAI3 write, and the PAI3 tree.
            (false, Some(*b"PAI2"), true, true),
            (true, Some(*b"PAI2"), true, true),
            (false, Some(*b"PAI3"), true, true),
            // Root removed with the attempt present (#721), then both removed.
            (false, Some(*b"PAI3"), false, true),
            (false, Some(*b"PAI3"), false, false),
            // The record unlinked before its registry fsync.
            (false, None, false, false),
        ] {
            assert!(
                frontiers.contains(&expected),
                "{expected:?} in {frontiers:?}"
            );
        }
        Ok(())
    }
}
