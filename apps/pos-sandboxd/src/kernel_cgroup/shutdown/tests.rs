//! Public shutdown-operation tests with real retained files and virtual time.

// The pinned complexity scanner parses each file independently. Retain an
// explicit test-only scope here as well as on the parent module declaration.
#[cfg(test)]
mod cases {
    use std::{
        error::Error,
        fs::{self, File},
        path::PathBuf,
        sync::Mutex,
    };

    use tokio::time::sleep;
    use zbus::OwnedObjectPath;

    use super::super::*;
    use crate::{CgroupRoot, TransientServiceUnitName, TransientUnitRequest, UnitKiller};

    type TestResult = Result<(), Box<dyn Error>>;

    struct Fixture {
        _root: tempfile::TempDir,
        directory: PathBuf,
        unit: TransientServiceUnitName,
        bound: BoundAttemptCgroup,
    }

    impl Fixture {
        fn new(id: u8) -> Result<Self, Box<dyn Error>> {
            let root = tempfile::tempdir()?;
            let directory = root.path().join("attempt");
            fs::create_dir(&directory)?;
            fs::write(directory.join("cgroup.events"), b"populated 1\n")?;
            fs::write(directory.join("cgroup.kill"), b"0")?;
            let unit = TransientServiceUnitName::from_attempt_id([id; 16])?;
            let bound = BoundAttemptCgroup::open(
                CgroupRoot::for_test(File::open(root.path())?),
                unit.clone(),
                OwnedObjectPath::try_from("/org/freedesktop/systemd1/unit/attempt")?,
                "/attempt".to_owned(),
            )?;
            Ok(Self {
                _root: root,
                directory,
                unit,
                bound,
            })
        }

        fn host(&self, stop: Action, kill: Action) -> Host {
            Host {
                directory: self.directory.clone(),
                stop,
                kill,
                calls: Mutex::new(Vec::new()),
            }
        }
    }

    #[derive(Clone, Copy)]
    enum Action {
        Ack,
        Fail,
        Hang,
        Empty,
        Replace,
        Malformed,
        RemoveKill,
        LateEmpty(Duration),
        Delete,
        Move,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct Call {
        operation: &'static str,
        unit: TransientServiceUnitName,
        kernel_command: Vec<u8>,
    }

    struct Host {
        directory: PathBuf,
        stop: Action,
        kill: Action,
        calls: Mutex<Vec<Call>>,
    }

    impl Host {
        fn calls(&self) -> Result<Vec<Call>, std::io::Error> {
            self.calls
                .lock()
                .map(|calls| calls.clone())
                .map_err(|_| std::io::Error::other("poisoned test call log"))
        }

        async fn act(
            &self,
            operation: &'static str,
            unit: TransientServiceUnitName,
            action: Action,
        ) -> Result<(), std::io::Error> {
            self.calls
                .lock()
                .map_err(|_| std::io::Error::other("poisoned test call log"))?
                .push(Call {
                    operation,
                    unit,
                    kernel_command: fs::read(self.directory.join("cgroup.kill"))?,
                });
            match action {
                Action::Ack => Ok(()),
                Action::Fail => Err(std::io::Error::other("injected manager failure")),
                Action::Hang => std::future::pending().await,
                Action::Empty => fs::write(self.directory.join("cgroup.events"), b"populated 0\n"),
                Action::Replace => {
                    fs::rename(&self.directory, self.directory.with_file_name("original"))?;
                    fs::create_dir(&self.directory)?;
                    fs::write(self.directory.join("cgroup.kill"), b"0")
                }
                Action::Malformed => {
                    fs::write(self.directory.join("cgroup.events"), b"populated 2\n")
                }
                Action::RemoveKill => fs::remove_file(self.directory.join("cgroup.kill")),
                Action::Delete => fs::remove_dir_all(&self.directory),
                Action::Move => {
                    fs::rename(&self.directory, self.directory.with_file_name("original"))
                }
                Action::LateEmpty(delay) => {
                    // Model the controller being descheduled across its deadlines.
                    fs::write(self.directory.join("cgroup.events"), b"populated 0\n")?;
                    tokio::time::advance(delay).await;
                    Ok(())
                }
            }
        }
    }

    struct UnusedKiller;

    impl UnitKiller for UnusedKiller {
        async fn kill(self, _unit: TransientServiceUnitName) {}
    }

    impl UnitHost for Host {
        type Started = ();
        type Cgroup = BoundAttemptCgroup;
        type Error = std::io::Error;
        type Killer = UnusedKiller;

        fn killer(&self) -> UnusedKiller {
            UnusedKiller
        }

        async fn start(
            &self,
            _unit: TransientServiceUnitName,
            _request: TransientUnitRequest,
        ) -> Result<(), Self::Error> {
            Err(std::io::Error::other("shutdown must not start a unit"))
        }

        async fn bind_cgroup(&self, _started: &()) -> Result<BoundAttemptCgroup, Self::Error> {
            Err(std::io::Error::other("shutdown must not rebind a cgroup"))
        }

        async fn stop(&self, unit: TransientServiceUnitName) -> Result<(), Self::Error> {
            self.act("stop", unit, self.stop).await
        }

        async fn kill(&self, unit: TransientServiceUnitName) -> Result<(), Self::Error> {
            self.act("kill", unit, self.kill).await
        }
    }

    fn deadlines() -> Result<AttemptShutdownDeadlines, AttemptShutdownError> {
        let now = Instant::now();
        AttemptShutdownDeadlines::new(
            now + Duration::from_millis(100),
            now + Duration::from_millis(200),
            now + Duration::from_millis(500),
        )
    }

    #[tokio::test(start_paused = true)]
    async fn graceful_stop_returns_exact_kernel_evidence_without_escalation() -> TestResult {
        let mut fixture = Fixture::new(1)?;
        let host = fixture.host(Action::Empty, Action::Fail);
        let empty = fixture.bound.stop_processes(&host, deadlines()?).await?;
        assert_eq!(empty.unit_name(), &fixture.unit);
        assert_eq!(empty.unit_path(), "/org/freedesktop/systemd1/unit/attempt");
        assert_eq!(empty.control_group(), "/attempt");
        assert_eq!(empty.basis(), AttemptCgroupEmptyBasis::Events);
        assert_eq!(empty.raw_events(), Some(b"populated 0\n".as_slice()));
        assert_eq!(
            host.calls()?,
            vec![Call {
                operation: "stop",
                unit: fixture.unit,
                kernel_command: b"0".to_vec(),
            }]
        );
        assert_eq!(fs::read(fixture.directory.join("cgroup.kill"))?, b"0");
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn initially_empty_present_cgroup_still_requests_stop() -> TestResult {
        let mut fixture = Fixture::new(2)?;
        fs::write(fixture.directory.join("cgroup.events"), b"populated 0\n")?;
        let host = fixture.host(Action::Ack, Action::Fail);
        fixture.bound.stop_processes(&host, deadlines()?).await?;
        assert_eq!(host.calls()?.len(), 1);
        assert_eq!(host.calls()?[0].operation, "stop");
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn grace_allows_independent_empty_observation_after_stop_error() -> TestResult {
        let mut fixture = Fixture::new(3)?;
        let host = fixture.host(Action::Fail, Action::Fail);
        let events = fixture.directory.join("cgroup.events");
        let limits = deadlines()?;
        let (result, write) = tokio::join!(fixture.bound.stop_processes(&host, limits), async {
            sleep(Duration::from_millis(30)).await;
            fs::write(events, b"populated 0\n")
        });
        write?;
        result?;
        assert_eq!(host.calls()?.len(), 1);
        assert_eq!(fs::read(fixture.directory.join("cgroup.kill"))?, b"0");
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_stop_escalates_unit_first_then_exact_kernel_command() -> TestResult {
        let mut fixture = Fixture::new(4)?;
        let host = fixture.host(Action::Hang, Action::Empty);
        let limits = deadlines()?;
        fixture.bound.stop_processes(&host, limits).await?;
        assert!(Instant::now() >= limits.grace);
        assert!(Instant::now() < limits.unit_kill);
        assert_eq!(
            host.calls()?,
            vec![
                Call {
                    operation: "stop",
                    unit: fixture.unit.clone(),
                    kernel_command: b"0".to_vec(),
                },
                Call {
                    operation: "kill",
                    unit: fixture.unit,
                    kernel_command: b"0".to_vec(),
                },
            ]
        );
        assert_eq!(fs::read(fixture.directory.join("cgroup.kill"))?, b"1");
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn failed_or_stalled_unit_kill_preserves_kernel_and_observation_budget() -> TestResult {
        for kill in [Action::Fail, Action::Hang] {
            let mut fixture = Fixture::new(5)?;
            let host = fixture.host(Action::Ack, kill);
            let limits = deadlines()?;
            let directory = fixture.directory.clone();
            let (result, write) =
                tokio::join!(fixture.bound.stop_processes(&host, limits), async {
                    sleep(Duration::from_millis(250)).await;
                    assert_eq!(fs::read(directory.join("cgroup.kill"))?, b"1");
                    fs::write(directory.join("cgroup.events"), b"populated 0\n")
                });
            write?;
            result?;
            assert_eq!(host.calls()?.len(), 2);
            assert!(Instant::now() < limits.overall);
        }
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn command_acknowledgements_never_prove_emptiness_or_reset_deadline() -> TestResult {
        let mut fixture = Fixture::new(6)?;
        let host = fixture.host(Action::Ack, Action::Ack);
        let limits = deadlines()?;
        let error = fixture
            .bound
            .stop_processes(&host, limits)
            .await
            .err()
            .ok_or("populated cgroup was accepted")?;
        assert_eq!(
            error.to_string(),
            "attempt process-shutdown deadline elapsed"
        );
        assert!(Instant::now() >= limits.overall);
        assert!(Instant::now() <= limits.overall + EMPTY_POLL);
        assert_eq!(host.calls()?.len(), 2);
        assert_eq!(fs::read(fixture.directory.join("cgroup.kill"))?, b"1");
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn empty_at_or_after_final_deadline_is_not_timely_evidence() -> TestResult {
        for delay in [500, 510] {
            let mut fixture = Fixture::new(7)?;
            let host = fixture.host(Action::Ack, Action::Ack);
            let limits = deadlines()?;
            let events = fixture.directory.join("cgroup.events");
            let (result, write) =
                tokio::join!(fixture.bound.stop_processes(&host, limits), async {
                    sleep(Duration::from_millis(delay)).await;
                    fs::write(events, b"populated 0\n")
                });
            write?;
            assert_eq!(
                result
                    .err()
                    .ok_or("late emptiness was accepted")?
                    .to_string(),
                "attempt process-shutdown deadline elapsed"
            );
            // Later observation is a separate fact and cannot repair the deadline.
            fixture.bound.observe_empty()?;
        }
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn scheduler_delay_cannot_turn_late_empty_state_into_success() -> TestResult {
        for delay in [200, 250, 500] {
            let mut fixture = Fixture::new(14)?;
            let host = fixture.host(
                Action::LateEmpty(Duration::from_millis(delay)),
                Action::Empty,
            );
            let error = fixture
                .bound
                .stop_processes(&host, deadlines()?)
                .await
                .err()
                .ok_or("late manager completion was accepted")?;
            assert_eq!(
                error.to_string(),
                "attempt process-shutdown deadline elapsed"
            );
            assert_eq!(host.calls()?.len(), 1);
            // Kernel escalation remains a fail-safe, not repair of the missed phase.
            assert_eq!(fs::read(fixture.directory.join("cgroup.kill"))?, b"1");
            fixture.bound.observe_empty()?;
        }
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn invalid_or_expired_phase_budgets_issue_no_commands() -> TestResult {
        let now = Instant::now();
        let later = now + Duration::from_secs(1);
        for (grace, kill, overall) in [
            (now, now, later),
            (later, now, later),
            (now, later, later),
            (now, later, now),
        ] {
            let error = AttemptShutdownDeadlines::new(grace, kill, overall)
                .err()
                .ok_or("invalid ordering was accepted")?;
            assert_eq!(
                error.to_string(),
                "attempt shutdown deadlines must be strictly increasing"
            );
        }
        let mut fixture = Fixture::new(8)?;
        let host = fixture.host(Action::Empty, Action::Empty);
        let limits = deadlines()?;
        tokio::time::advance(Duration::from_millis(100)).await;
        assert_eq!(Instant::now(), limits.grace);
        assert!(fixture.bound.stop_processes(&host, limits).await.is_err());
        assert!(host.calls()?.is_empty());
        assert_eq!(fs::read(fixture.directory.join("cgroup.kill"))?, b"0");
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn identity_and_events_are_checked_before_any_unit_command() -> TestResult {
        let mut fixture = Fixture::new(9)?;
        let host = fixture.host(Action::Empty, Action::Empty);
        fs::write(fixture.directory.join("cgroup.events"), b"populated 2\n")?;
        assert!(fixture
            .bound
            .stop_processes(&host, deadlines()?)
            .await
            .is_err());
        assert!(host.calls()?.is_empty());
        fs::write(fixture.directory.join("cgroup.events"), b"populated 1\n")?;
        fs::rename(
            &fixture.directory,
            fixture.directory.with_file_name("original"),
        )?;
        fs::create_dir(&fixture.directory)?;
        fs::write(fixture.directory.join("cgroup.kill"), b"0")?;
        assert!(fixture
            .bound
            .stop_processes(&host, deadlines()?)
            .await
            .is_err());
        assert!(host.calls()?.is_empty());
        assert_eq!(fs::read(fixture.directory.join("cgroup.kill"))?, b"0");
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn changed_path_or_events_during_grace_never_authorize_escalation() -> TestResult {
        for action in [Action::Replace, Action::Malformed] {
            let mut fixture = Fixture::new(10)?;
            let host = fixture.host(action, Action::Empty);
            assert!(fixture
                .bound
                .stop_processes(&host, deadlines()?)
                .await
                .is_err());
            assert_eq!(host.calls()?.len(), 1);
            assert_eq!(fs::read(fixture.directory.join("cgroup.kill"))?, b"0");
        }
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn changed_path_during_unit_kill_cannot_target_replacement() -> TestResult {
        let mut fixture = Fixture::new(11)?;
        let host = fixture.host(Action::Ack, Action::Replace);
        assert!(fixture
            .bound
            .stop_processes(&host, deadlines()?)
            .await
            .is_err());
        assert_eq!(host.calls()?.len(), 2);
        assert_eq!(fs::read(fixture.directory.join("cgroup.kill"))?, b"0");
        assert_eq!(
            fs::read(
                fixture
                    .directory
                    .with_file_name("original")
                    .join("cgroup.kill")
            )?,
            b"0"
        );
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn missing_kernel_control_cannot_be_replaced_by_manager_acknowledgement() -> TestResult {
        let mut fixture = Fixture::new(12)?;
        let host = fixture.host(Action::Ack, Action::RemoveKill);
        let error = fixture
            .bound
            .stop_processes(&host, deadlines()?)
            .await
            .err()
            .ok_or("missing kernel control was accepted")?;
        assert!(error.to_string().contains("cgroup.kill"));
        assert!(std::error::Error::source(&error).is_some());
        assert_eq!(host.calls()?.len(), 2);
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn control_open_deletion_race_requires_timely_original_deletion_proof() -> TestResult {
        let mut fixture = Fixture::new(17)?;
        let deadline = deadlines()?.overall;
        // Narrow fault-boundary injection: ENOENT after the synchronous retained-
        // path check cannot be scheduled deterministically through UnitHost. The
        // recovery boundary still uses real held descriptors and the real probe.
        // A present empty scope cannot stand in for deletion of the original inode.
        fs::write(fixture.directory.join("cgroup.events"), b"populated 0\n")?;
        assert!(fixture
            .bound
            .observe_deleted_after_missing_control(deadline)
            .is_err());
        fs::remove_dir_all(&fixture.directory)?;
        let empty = fixture
            .bound
            .observe_deleted_after_missing_control(deadline)?;
        assert_eq!(empty.basis(), AttemptCgroupEmptyBasis::Deleted);
        assert_eq!(empty.unit_name(), &fixture.unit);
        assert_eq!(empty.raw_events(), None);
        let expired = fixture
            .bound
            .observe_deleted_after_missing_control(Instant::now())
            .err()
            .ok_or("late deletion was accepted")?;
        assert_eq!(
            expired.to_string(),
            "attempt process-shutdown deadline elapsed"
        );
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn deletion_during_manager_kill_requires_the_original_retained_inode_to_be_unlinked(
    ) -> TestResult {
        let mut fixture = Fixture::new(15)?;
        let host = fixture.host(Action::Ack, Action::Delete);
        let empty = fixture.bound.stop_processes(&host, deadlines()?).await?;
        assert_eq!(empty.basis(), AttemptCgroupEmptyBasis::Deleted);
        assert_eq!(empty.unit_name(), &fixture.unit);
        assert_eq!(host.calls()?.len(), 2);
        assert!(!fixture.directory.exists());
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn a_moved_original_is_not_proven_deleted_when_the_kill_target_is_missing() -> TestResult
    {
        let mut fixture = Fixture::new(16)?;
        let host = fixture.host(Action::Ack, Action::Move);
        let error = fixture
            .bound
            .stop_processes(&host, deadlines()?)
            .await
            .err()
            .ok_or("a moved live cgroup was accepted as deleted")?;
        assert_eq!(
            error.to_string(),
            "the attempt cgroup path disappeared without proven deletion"
        );
        assert_eq!(host.calls()?.len(), 2);
        assert_eq!(
            fs::read(
                fixture
                    .directory
                    .with_file_name("original")
                    .join("cgroup.kill")
            )?,
            b"0"
        );
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn proven_original_deletion_returns_process_evidence_without_signalling_a_reused_unit(
    ) -> TestResult {
        let mut fixture = Fixture::new(13)?;
        let host = fixture.host(Action::Fail, Action::Fail);
        fs::remove_dir_all(&fixture.directory)?;
        let empty = fixture.bound.stop_processes(&host, deadlines()?).await?;
        assert_eq!(empty.basis(), AttemptCgroupEmptyBasis::Deleted);
        assert_eq!(empty.raw_events(), None);
        assert_eq!(empty.unit_name(), &fixture.unit);
        assert!(host.calls()?.is_empty());
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn eight_concurrent_shutdowns_keep_each_unit_and_cgroup_bound() -> TestResult {
        let limits = deadlines()?;
        let mut tasks = Vec::new();
        for id in 1..=8 {
            let mut fixture = Fixture::new(id)?;
            tasks.push(tokio::spawn(async move {
                let host = fixture.host(Action::Ack, Action::Empty);
                let empty = fixture.bound.stop_processes(&host, limits).await?;
                assert_eq!(empty.unit_name(), &fixture.unit);
                assert_eq!(host.calls()?.len(), 2);
                assert!(host.calls()?.iter().all(|call| call.unit == fixture.unit));
                assert_eq!(fs::read(fixture.directory.join("cgroup.kill"))?, b"1");
                Ok::<_, Box<dyn Error + Send + Sync>>(empty.cgroup_identity())
            }));
        }
        let mut identities = std::collections::HashSet::new();
        for task in tasks {
            let identity = task.await?.map_err(|error| error.to_string())?;
            assert!(identities.insert(identity));
        }
        assert_eq!(identities.len(), 8);
        Ok(())
    }
}
