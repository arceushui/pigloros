//! Bounded terminal cleanup composed over the real unit transport and registry.

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod cases {
    use std::fs::{self, File};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::time::Duration;

    use super::super::*;
    use crate::test_fixtures::{
        attached_fixture_root, release_fake_root, TeardownFixture, TeardownReset, TeardownStop,
    };
    use crate::{PlannedAttemptIntent, SystemdAttemptRegistry};

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    /// A fixture root released through the controller's root port.
    struct FakeRootRelease(crate::test_fixtures::FakeRootRelease);

    impl RootRelease for FakeRootRelease {
        fn release(
            self,
            directory: &PreparedAttemptDirectory,
            deadline: Instant,
        ) -> impl Future<Output = Result<ReleasedAttemptRoot, ImageActivationError>> + Send + '_
        {
            release_fake_root(self.0, directory, deadline)
        }
    }

    /// A root release that never completes.
    struct HangingRelease;

    impl RootRelease for HangingRelease {
        fn release(
            self,
            _directory: &PreparedAttemptDirectory,
            _deadline: Instant,
        ) -> impl Future<Output = Result<ReleasedAttemptRoot, ImageActivationError>> + Send + '_
        {
            std::future::pending()
        }
    }

    /// A fake root release; unless `absent`, the device-absence probe fails.
    fn fake_root_release(
        directory: &PreparedAttemptDirectory,
        absent: bool,
    ) -> TestResult<FakeRootRelease> {
        Ok(FakeRootRelease(crate::test_fixtures::fake_root_release(
            directory, absent,
        )?))
    }

    /// One prepared attempt keyed by `[1; 16]` in a private runtime tree.
    struct Attempt {
        runtime: tempfile::TempDir,
        registry: SystemdAttemptRegistry,
        directory: PreparedAttemptDirectory,
    }

    impl Attempt {
        fn new() -> TestResult<Self> {
            let runtime = tempfile::tempdir()?;
            fs::set_permissions(runtime.path(), fs::Permissions::from_mode(0o700))?;
            for child in ["registry", "attempts"] {
                fs::create_dir(runtime.path().join(child))?;
                fs::set_permissions(
                    runtime.path().join(child),
                    fs::Permissions::from_mode(0o700),
                )?;
            }
            let parent = File::open(runtime.path())?;
            let registry =
                SystemdAttemptRegistry::from_runtime_directory(&parent, parent.metadata()?.uid())?;
            let directory = registry
                .commit_planned(&PlannedAttemptIntent::new([1; 16], [9; 32])?)?
                .prepare_fixture_directory()?;
            Ok(Self {
                runtime,
                registry,
                directory,
            })
        }

        /// Record that this attempt's execution submitted its unit and bound `cgroup`.
        fn submitted(&self, cgroup: &BoundAttemptCgroup) -> TestResult {
            let ownership = self.directory.execution_ownership();
            ownership.claim()?;
            ownership.submit()?;
            ownership.bind_cgroup(cgroup.identity());
            Ok(())
        }

        fn record(&self) -> std::path::PathBuf {
            self.runtime
                .path()
                .join("registry")
                .join(self.directory.intent().unit_name().attempt_component())
        }
    }

    /// Shutdown ends at 300 ms, the unit is absent by 500 ms, the root by 700 ms.
    fn deadlines() -> TestResult<AttemptCleanupDeadlines> {
        let now = Instant::now();
        let at = |millis| now + Duration::from_millis(millis);
        Ok(AttemptCleanupDeadlines::new(
            AttemptShutdownDeadlines::new(at(100), at(200), at(300))?,
            at(500),
            at(700),
        )?)
    }

    /// After a refused cleanup: the intent is kept and the registry closed.
    fn assert_retained(record: &std::path::Path, registry: &SystemdAttemptRegistry) -> TestResult {
        assert!(record.exists());
        assert!(registry
            .commit_planned(&PlannedAttemptIntent::new([2; 16], [9; 32])?)
            .is_err());
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn a_stopped_unit_and_its_released_root_let_the_intent_go_last() -> TestResult {
        let attempt = Attempt::new()?;
        let fixture = TeardownFixture::new(1, TeardownStop::Empty, TeardownReset::Unload).await?;
        attempt.submitted(&fixture.bound)?;
        let root = fake_root_release(&attempt.directory, true)?;
        let record = attempt.record();
        let calls = fixture.calls();
        let completed = finish_with(
            &fixture.transport,
            attempt.directory,
            Some(fixture.bound),
            Some(root),
            deadlines()?,
        )
        .await?;
        assert_eq!(completed.intent().attempt_id(), [1; 16]);
        assert!(!record.exists());
        // Stop, failed-state reset and the fresh absence lookup.
        assert_eq!(calls.count()?, 3);
        attempt
            .registry
            .commit_planned(&PlannedAttemptIntent::new([2; 16], [9; 32])?)?;
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn an_attempt_without_a_unit_start_is_fenced_and_cleaned() -> TestResult {
        let attempt = Attempt::new()?;
        let fixture = TeardownFixture::new(1, TeardownStop::Empty, TeardownReset::Unload).await?;
        let ownership = attempt.directory.execution_ownership();
        // A claimed execution that failed before requesting its unit start.
        ownership.claim()?;
        let record = attempt.record();
        finish_with(
            &fixture.transport,
            attempt.directory,
            None,
            None::<FakeRootRelease>,
            deadlines()?,
        )
        .await?;
        assert!(!record.exists());
        assert!(ownership.submit().is_err());
        assert_eq!(fixture.calls().count()?, 0);
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn unmatched_or_missing_stop_evidence_touches_nothing_and_quarantines() -> TestResult {
        // A cancelled execution lost its cgroup after requesting the unit start;
        // a cgroup this execution never bound is never stopped.
        for cancelled in [true, false] {
            let attempt = Attempt::new()?;
            let fixture =
                TeardownFixture::new(1, TeardownStop::Empty, TeardownReset::Unload).await?;
            let ownership = attempt.directory.execution_ownership();
            ownership.claim()?;
            ownership.submit()?;
            let root = fake_root_release(&attempt.directory, true)?;
            let record = attempt.record();
            let calls = fixture.calls();
            let result = finish_with(
                &fixture.transport,
                attempt.directory,
                (!cancelled).then_some(fixture.bound),
                Some(root),
                deadlines()?,
            )
            .await;
            assert!(
                matches!(
                    result,
                    Err(AttemptCleanupError::Registry(
                        SystemdAttemptRegistryError::CleanupEvidence
                    ))
                ),
                "cancelled {cancelled}: {result:?}"
            );
            assert_eq!(calls.count()?, 0);
            assert_retained(&record, &attempt.registry)?;
        }
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn a_requested_start_without_its_cgroup_is_refused_before_the_root() -> TestResult {
        let attempt = Attempt::new()?;
        let fixture = TeardownFixture::new(1, TeardownStop::Empty, TeardownReset::Unload).await?;
        let ownership = attempt.directory.execution_ownership();
        ownership.claim()?;
        ownership.submit()?;
        let record = attempt.record();
        // A root release that never completes: the fence refusal must come
        // first, so the root is never touched.
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            finish_with(
                &fixture.transport,
                attempt.directory,
                None,
                Some(HangingRelease),
                deadlines()?,
            ),
        )
        .await;
        assert!(
            matches!(
                result,
                Ok(Err(AttemptCleanupError::Registry(
                    SystemdAttemptRegistryError::CleanupEvidence
                )))
            ),
            "{result:?}"
        );
        assert_retained(&record, &attempt.registry)?;
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn a_unit_that_is_not_removed_in_time_keeps_its_root_and_intent() -> TestResult {
        let attempt = Attempt::new()?;
        let fixture = TeardownFixture::new(1, TeardownStop::Empty, TeardownReset::Hang).await?;
        attempt.submitted(&fixture.bound)?;
        let root = fake_root_release(&attempt.directory, true)?;
        let record = attempt.record();
        let result = finish_with(
            &fixture.transport,
            attempt.directory,
            Some(fixture.bound),
            Some(root),
            deadlines()?,
        )
        .await;
        assert!(
            matches!(
                result,
                Err(AttemptCleanupError::Unit(
                    SystemdAttemptUnitTeardownError::DeadlineElapsed
                ))
            ),
            "{result:?}"
        );
        // The root was never detached under a unit that may still run.
        assert!(attempt
            .runtime
            .path()
            .join("attempts")
            .join(record.file_name().ok_or("record name")?)
            .join("root")
            .exists());
        assert_retained(&record, &attempt.registry)?;
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn a_root_whose_devices_are_not_observed_absent_keeps_the_intent() -> TestResult {
        let attempt = Attempt::new()?;
        let fixture = TeardownFixture::new(1, TeardownStop::Empty, TeardownReset::Unload).await?;
        attempt.submitted(&fixture.bound)?;
        let root = fake_root_release(&attempt.directory, false)?;
        let record = attempt.record();
        let result = finish_with(
            &fixture.transport,
            attempt.directory,
            Some(fixture.bound),
            Some(root),
            deadlines()?,
        )
        .await;
        assert!(
            matches!(
                result,
                Err(AttemptCleanupError::Root(
                    ImageActivationError::ResourceAbsenceUnverified
                ))
            ),
            "{result:?}"
        );
        assert_retained(&record, &attempt.registry)?;
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn the_real_host_contradicting_a_root_refuses_through_the_public_entry() -> TestResult {
        let attempt = Attempt::new()?;
        let fixture = TeardownFixture::new(1, TeardownStop::Empty, TeardownReset::Unload).await?;
        attempt.submitted(&fixture.bound)?;
        let root = attached_fixture_root(&attempt.directory)?;
        let record = attempt.record();
        // The host kernel observes a regular file, not the verified mount.
        let result = finish_attempt(
            &fixture.transport,
            attempt.directory,
            Some(fixture.bound),
            Some(root),
            deadlines()?,
        )
        .await;
        assert!(
            matches!(
                result,
                Err(AttemptCleanupError::Root(
                    ImageActivationError::EvidenceMismatch
                ))
            ),
            "{result:?}"
        );
        assert_retained(&record, &attempt.registry)?;
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn an_unproved_activation_is_refused_by_the_terminal_predicate() -> TestResult {
        let attempt = Attempt::new()?;
        let fixture = TeardownFixture::new(1, TeardownStop::Empty, TeardownReset::Unload).await?;
        // mountfsd was asked for a root that never became verified evidence.
        attempt.directory.begin_activation();
        let record = attempt.record();
        let result = finish_with(
            &fixture.transport,
            attempt.directory,
            None,
            None::<FakeRootRelease>,
            deadlines()?,
        )
        .await;
        assert!(
            matches!(
                result,
                Err(AttemptCleanupError::Registry(
                    SystemdAttemptRegistryError::CleanupEvidence
                ))
            ),
            "{result:?}"
        );
        assert_retained(&record, &attempt.registry)?;
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn dropping_an_unfinished_cleanup_quarantines_the_attempt() -> TestResult {
        let attempt = Attempt::new()?;
        let fixture = TeardownFixture::new(1, TeardownStop::Empty, TeardownReset::Hang).await?;
        attempt.submitted(&fixture.bound)?;
        let record = attempt.record();
        let cleanup = finish_with(
            &fixture.transport,
            attempt.directory,
            Some(fixture.bound),
            None::<FakeRootRelease>,
            deadlines()?,
        );
        // The reset hangs; give up on the cleanup before its deadline.
        let abandoned = tokio::time::timeout(Duration::from_millis(400), cleanup).await;
        assert!(abandoned.is_err());
        assert_retained(&record, &attempt.registry)?;
        Ok(())
    }

    /// Eight full lifecycles joined on one paused current-thread runtime. This
    /// checks that the attempts' cleanups stay independent when interleaved;
    /// it is not a concurrency stress test.
    #[tokio::test(start_paused = true)]
    async fn eight_joined_lifecycles_each_end_with_their_intent_deleted_last() -> TestResult {
        let runtime = tempfile::tempdir()?;
        fs::set_permissions(runtime.path(), fs::Permissions::from_mode(0o700))?;
        for child in ["registry", "attempts"] {
            fs::create_dir(runtime.path().join(child))?;
            fs::set_permissions(
                runtime.path().join(child),
                fs::Permissions::from_mode(0o700),
            )?;
        }
        let parent = File::open(runtime.path())?;
        let registry =
            SystemdAttemptRegistry::from_runtime_directory(&parent, parent.metadata()?.uid())?;
        let mut attempts = Vec::new();
        for id in 1..=8 {
            let directory = registry
                .commit_planned(&PlannedAttemptIntent::new([id; 16], [9; 32])?)?
                .prepare_fixture_directory()?;
            let fixture =
                TeardownFixture::new(id, TeardownStop::Empty, TeardownReset::Unload).await?;
            let ownership = directory.execution_ownership();
            ownership.claim()?;
            ownership.submit()?;
            ownership.bind_cgroup(fixture.bound.identity());
            let root = fake_root_release(&directory, true)?;
            attempts.push((fixture, directory, root));
        }
        let deadlines = deadlines()?;
        // Each cleanup keeps its fake manager alive while it runs.
        let finished = futures_util::future::join_all(attempts.into_iter().map(
            |(fixture, directory, root)| async move {
                // Using the whole fixture first captures all of it, so its fake
                // manager outlives the cleanup.
                let calls = fixture.calls();
                let completed = finish_with(
                    &fixture.transport,
                    directory,
                    Some(fixture.bound),
                    Some(root),
                    deadlines,
                )
                .await;
                (completed, calls)
            },
        ))
        .await;
        for (id, (completed, calls)) in (1..=8).zip(finished) {
            assert_eq!(completed?.intent().attempt_id(), [id; 16]);
            // Stop, failed-state reset and the fresh absence lookup.
            assert_eq!(calls.count()?, 3);
        }
        // Only the owner's activation marker is left in the registry.
        assert_eq!(fs::read_dir(runtime.path().join("registry"))?.count(), 1);
        assert_eq!(fs::read_dir(runtime.path().join("attempts"))?.count(), 0);
        registry.commit_planned(&PlannedAttemptIntent::new([9; 16], [9; 32])?)?;
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn dropping_a_cleanup_during_root_release_quarantines_the_attempt() -> TestResult {
        let attempt = Attempt::new()?;
        let fixture = TeardownFixture::new(1, TeardownStop::Empty, TeardownReset::Unload).await?;
        attempt.submitted(&fixture.bound)?;
        let record = attempt.record();
        let calls = fixture.calls();
        let cleanup = finish_with(
            &fixture.transport,
            attempt.directory,
            Some(fixture.bound),
            Some(HangingRelease),
            deadlines()?,
        );
        // The unit stops at once; give up on the root release that follows.
        let abandoned = tokio::time::timeout(Duration::from_millis(600), cleanup).await;
        assert!(abandoned.is_err());
        // The unit step had completed: stop, failed-state reset and absence.
        assert_eq!(calls.count()?, 3);
        assert_retained(&record, &attempt.registry)?;
        Ok(())
    }

    #[test]
    fn cleanup_phases_must_be_strictly_increasing() -> TestResult {
        let now = Instant::now();
        let at = |millis| now + Duration::from_millis(millis);
        let shutdown = AttemptShutdownDeadlines::new(at(1), at(2), at(3))?;
        for (unit_absent, released, valid) in [(4, 5, true), (3, 5, false), (4, 4, false)] {
            assert_eq!(
                AttemptCleanupDeadlines::new(shutdown, at(unit_absent), at(released)).is_ok(),
                valid,
                "{unit_absent} {released}"
            );
        }
        Ok(())
    }
}
