//! Exact transport ordering and retained-kernel observations at the public seam.

#[cfg(test)]
mod cases {
    use std::{
        error::Error,
        fs::{self, File},
        num::NonZeroU32,
        path::PathBuf,
        sync::{Arc, Mutex},
        time::Duration,
    };

    use futures_util::{future::join_all, StreamExt};
    use tokio::time::{advance, sleep, Instant};
    use zbus::{
        fdo,
        message::{Header, Type},
        object_server::SignalEmitter,
        BoxDBusError, MessageStream, OwnedObjectPath,
    };

    use crate::{
        system_bus::{test_support::peer_connections, ManagerProxy},
        AttemptCgroupEmptyBasis, AttemptShutdownDeadlines, AttemptShutdownError,
        BoundAttemptCgroup, CgroupRoot, SystemdAttemptUnitTeardownError,
        SystemdTransientUnitTransport, SystemdTransientUnitTransportError,
        TransientServiceUnitName,
    };

    type TestResult<T = ()> = Result<T, Box<dyn Error>>;

    #[derive(Clone, Copy)]
    enum Stop {
        Empty,
        LeavesPopulated,
    }

    #[derive(Clone, Copy)]
    enum Reset {
        Unload,
        Missing,
        KeepLoaded,
        Denied,
        NearMatch,
        Hang,
        Delayed(Duration),
    }

    #[derive(Clone, Copy)]
    enum Lookup {
        Unchanged,
        Repopulate,
        Replace,
        Denied,
    }

    #[derive(Debug, PartialEq)]
    enum Call {
        Stop(String, String),
        Kill(String, String, i32),
        Reset(String, Option<Vec<u8>>),
        Get(String),
    }

    struct State {
        subscribed: bool,
        loaded: bool,
        lookup: Lookup,
        calls: Vec<Call>,
        reset_serial: Option<NonZeroU32>,
        get_serial: Option<NonZeroU32>,
    }

    struct Manager {
        state: Arc<Mutex<State>>,
        directory: PathBuf,
        stop: Stop,
        reset: Reset,
    }

    #[derive(Debug, zbus::DBusError)]
    #[zbus(prefix = "org.freedesktop.systemd1")]
    enum ManagerError {
        NoSuchUnit(String),
        NoSuchUnitExtra(String),
    }

    #[zbus::interface(name = "org.freedesktop.systemd1.Manager", spawn = false)]
    impl Manager {
        fn subscribe(&self) -> fdo::Result<()> {
            self.state.lock().map_err(failed)?.subscribed = true;
            Ok(())
        }

        async fn stop_unit(
            &self,
            name: String,
            mode: String,
            #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
        ) -> fdo::Result<OwnedObjectPath> {
            self.state
                .lock()
                .map_err(failed)?
                .calls
                .push(Call::Stop(name.clone(), mode));
            if matches!(self.stop, Stop::Empty) {
                fs::write(self.directory.join("cgroup.events"), b"populated 0\n")
                    .map_err(failed)?;
            }
            let job =
                OwnedObjectPath::try_from("/org/freedesktop/systemd1/job/442").map_err(failed)?;
            Self::job_removed(&emitter, 442, job.clone(), name, "done".to_owned())
                .await
                .map_err(failed)?;
            Ok(job)
        }

        fn kill_unit(&self, name: String, whom: String, signal: i32) -> fdo::Result<()> {
            self.state
                .lock()
                .map_err(failed)?
                .calls
                .push(Call::Kill(name, whom, signal));
            fs::write(self.directory.join("cgroup.events"), b"populated 0\n").map_err(failed)
        }

        async fn reset_failed_unit(
            &self,
            name: String,
            #[zbus(header)] header: Header<'_>,
        ) -> Result<(), BoxDBusError> {
            {
                let mut state = self.state.lock().map_err(failed)?;
                state.calls.push(Call::Reset(
                    name,
                    fs::read(self.directory.join("cgroup.events")).ok(),
                ));
                state.reset_serial = Some(header.primary().serial_num());
                drop(state);
            }
            let misleading = "org.freedesktop.systemd1.NoSuchUnit".to_owned();
            match self.reset {
                Reset::Missing => return Err(Box::new(ManagerError::NoSuchUnit(misleading))),
                Reset::Denied => return Err(fdo::Error::AccessDenied(misleading).into()),
                Reset::NearMatch => {
                    return Err(Box::new(ManagerError::NoSuchUnitExtra(misleading)));
                }
                Reset::KeepLoaded => return Ok(()),
                Reset::Hang => return std::future::pending().await,
                Reset::Delayed(delay) => sleep(delay).await,
                Reset::Unload => {}
            }
            self.state.lock().map_err(failed)?.loaded = false;
            Ok(())
        }

        fn get_unit(
            &self,
            name: String,
            #[zbus(header)] header: Header<'_>,
        ) -> Result<OwnedObjectPath, BoxDBusError> {
            let (loaded, lookup) = {
                let mut state = self.state.lock().map_err(failed)?;
                state.calls.push(Call::Get(name));
                state.get_serial = Some(header.primary().serial_num());
                let observed = (state.loaded, state.lookup);
                drop(state);
                observed
            };
            drop(header);
            match lookup {
                Lookup::Repopulate => {
                    fs::write(self.directory.join("cgroup.events"), b"populated 1\n")
                        .map_err(failed)?;
                }
                Lookup::Replace => {
                    fs::rename(&self.directory, self.directory.with_file_name("original"))
                        .map_err(failed)?;
                    fs::create_dir(&self.directory).map_err(failed)?;
                    fs::write(self.directory.join("cgroup.events"), b"populated 0\n")
                        .map_err(failed)?;
                }
                Lookup::Denied => {
                    return Err(fdo::Error::AccessDenied("query denied".to_owned()).into());
                }
                Lookup::Unchanged => {}
            }
            if loaded {
                OwnedObjectPath::try_from("/org/freedesktop/systemd1/unit/attempt")
                    .map_err(|error| failed(error).into())
            } else {
                Err(Box::new(ManagerError::NoSuchUnit("not loaded".to_owned())))
            }
        }

        #[zbus(signal)]
        async fn job_removed(
            emitter: &SignalEmitter<'_>,
            id: u32,
            job: OwnedObjectPath,
            unit: String,
            result: String,
        ) -> zbus::Result<()>;
    }

    fn failed(error: impl std::fmt::Display) -> fdo::Error {
        fdo::Error::Failed(error.to_string())
    }

    struct Fixture {
        _root: tempfile::TempDir,
        _server: zbus::Connection,
        directory: PathBuf,
        unit: TransientServiceUnitName,
        bound: BoundAttemptCgroup,
        transport: SystemdTransientUnitTransport,
        state: Arc<Mutex<State>>,
    }

    impl Fixture {
        async fn new(id: u8, stop: Stop, reset: Reset) -> TestResult<Self> {
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
            let state = Arc::new(Mutex::new(State {
                subscribed: false,
                loaded: true,
                lookup: Lookup::Unchanged,
                calls: Vec::new(),
                reset_serial: None,
                get_serial: None,
            }));
            let manager = Manager {
                state: Arc::clone(&state),
                directory: directory.clone(),
                stop,
                reset,
            };
            let (server, client) =
                peer_connections(|server| server.serve_at("/org/freedesktop/systemd1", manager))
                    .await?;
            let transport = SystemdTransientUnitTransport::from_connection(client).await?;
            assert!(state.lock().map_err(|_| "poisoned fixture")?.subscribed);
            Ok(Self {
                _root: root,
                _server: server,
                directory,
                unit,
                bound,
                transport,
                state,
            })
        }
    }

    fn budgets() -> TestResult<(AttemptShutdownDeadlines, Instant)> {
        let now = Instant::now();
        Ok((
            AttemptShutdownDeadlines::new(
                now + Duration::from_millis(100),
                now + Duration::from_millis(200),
                now + Duration::from_millis(300),
            )?,
            now + Duration::from_millis(500),
        ))
    }

    #[tokio::test(start_paused = true)]
    async fn stop_empty_reset_and_fresh_absence_are_ordered_for_the_exact_bound_name() -> TestResult
    {
        let mut fixture = Fixture::new(1, Stop::Empty, Reset::Unload).await?;
        let (shutdown, deadline) = budgets()?;
        let observed = fixture
            .transport
            .stop_attempt_unit(&mut fixture.bound, shutdown, deadline)
            .await?;
        assert_eq!(observed.unit_absence().unit_name(), &fixture.unit);
        assert_eq!(observed.cgroup_empty().unit_name(), &fixture.unit);
        assert_eq!(
            observed.cgroup_empty().basis(),
            AttemptCgroupEmptyBasis::Events
        );
        assert_eq!(
            observed.cgroup_empty().raw_events(),
            Some(b"populated 0\n".as_slice())
        );
        let name = fixture.unit.as_str().to_owned();
        assert_eq!(
            fixture.state.lock().map_err(|_| "poisoned fixture")?.calls,
            vec![
                Call::Stop(name.clone(), "replace".to_owned()),
                Call::Reset(name.clone(), Some(b"populated 0\n".to_vec())),
                Call::Get(name),
            ]
        );
        assert_eq!(fs::read(fixture.directory.join("cgroup.kill"))?, b"0");
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn escalation_finishes_before_reset_and_unit_removal() -> TestResult {
        let mut fixture = Fixture::new(2, Stop::LeavesPopulated, Reset::Unload).await?;
        let (shutdown, deadline) = budgets()?;
        let observed = fixture
            .transport
            .stop_attempt_unit(&mut fixture.bound, shutdown, deadline)
            .await?;
        assert_eq!(observed.cgroup_empty().unit_name(), &fixture.unit);
        let name = fixture.unit.as_str().to_owned();
        assert_eq!(
            fixture.state.lock().map_err(|_| "poisoned fixture")?.calls,
            vec![
                Call::Stop(name.clone(), "replace".to_owned()),
                Call::Kill(name.clone(), "all".to_owned(), 9),
                Call::Reset(name.clone(), Some(b"populated 0\n".to_vec())),
                Call::Get(name),
            ]
        );
        assert_eq!(fs::read(fixture.directory.join("cgroup.kill"))?, b"1");
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn reset_missing_unit_still_requires_fresh_manager_absence() -> TestResult {
        for loaded in [false, true] {
            let mut fixture = Fixture::new(3, Stop::Empty, Reset::Missing).await?;
            fixture.state.lock().map_err(|_| "poisoned fixture")?.loaded = loaded;
            let (shutdown, deadline) = budgets()?;
            let result = fixture
                .transport
                .stop_attempt_unit(&mut fixture.bound, shutdown, deadline)
                .await;
            if loaded {
                assert!(matches!(
                    result,
                    Err(SystemdAttemptUnitTeardownError::DeadlineElapsed)
                ));
            } else {
                assert_eq!(result?.unit_absence().unit_name(), &fixture.unit);
            }
            assert!(fixture
                .state
                .lock()
                .map_err(|_| "poisoned fixture")?
                .calls
                .iter()
                .any(|call| matches!(call, Call::Get(name) if name == fixture.unit.as_str())));
        }
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn reset_and_lookup_errors_never_establish_joint_absence() -> TestResult {
        for (reset, lookup) in [
            (Reset::Denied, Lookup::Unchanged),
            (Reset::NearMatch, Lookup::Unchanged),
            (Reset::Unload, Lookup::Denied),
        ] {
            let mut fixture = Fixture::new(4, Stop::Empty, reset).await?;
            fixture.state.lock().map_err(|_| "poisoned fixture")?.lookup = lookup;
            let (shutdown, deadline) = budgets()?;
            let error = fixture
                .transport
                .stop_attempt_unit(&mut fixture.bound, shutdown, deadline)
                .await
                .err()
                .ok_or("manager rejection was accepted")?;
            assert!(error.source().is_some());
            if matches!(lookup, Lookup::Denied) {
                assert!(matches!(
                    error,
                    SystemdAttemptUnitTeardownError::Transport(
                        SystemdTransientUnitTransportError::UnitLookup(_)
                    )
                ));
            } else {
                assert!(matches!(
                    error,
                    SystemdAttemptUnitTeardownError::ResetFailed(_)
                ));
                assert_eq!(
                    fixture
                        .state
                        .lock()
                        .map_err(|_| "poisoned fixture")?
                        .calls
                        .len(),
                    2
                );
            }
        }
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn loaded_units_and_stalled_resets_exhaust_the_original_final_budget() -> TestResult {
        for reset in [
            Reset::KeepLoaded,
            Reset::Hang,
            Reset::Delayed(Duration::from_millis(501)),
        ] {
            let mut fixture = Fixture::new(5, Stop::Empty, reset).await?;
            let (shutdown, deadline) = budgets()?;
            let result = fixture
                .transport
                .stop_attempt_unit(&mut fixture.bound, shutdown, deadline)
                .await;
            assert!(matches!(
                result,
                Err(SystemdAttemptUnitTeardownError::DeadlineElapsed)
            ));
            assert_eq!(Instant::now(), deadline);
        }
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn reset_latency_consumes_the_original_budget_without_restarting_it() -> TestResult {
        let mut fixture =
            Fixture::new(6, Stop::Empty, Reset::Delayed(Duration::from_millis(400))).await?;
        let (shutdown, deadline) = budgets()?;
        let observed = fixture
            .transport
            .stop_attempt_unit(&mut fixture.bound, shutdown, deadline)
            .await?;
        assert!(Instant::now() < deadline);
        assert_eq!(observed.unit_absence().unit_name(), &fixture.unit);
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn manager_absence_cannot_replace_the_final_kernel_identity_and_empty_check() -> TestResult
    {
        for lookup in [Lookup::Repopulate, Lookup::Replace] {
            let mut fixture = Fixture::new(7, Stop::Empty, Reset::Unload).await?;
            fixture.state.lock().map_err(|_| "poisoned fixture")?.lookup = lookup;
            let (shutdown, deadline) = budgets()?;
            let result = fixture
                .transport
                .stop_attempt_unit(&mut fixture.bound, shutdown, deadline)
                .await;
            assert!(matches!(
                result,
                Err(SystemdAttemptUnitTeardownError::Shutdown(
                    AttemptShutdownError::Cgroup(_)
                ))
            ));
            assert_eq!(
                fixture
                    .state
                    .lock()
                    .map_err(|_| "poisoned fixture")?
                    .calls
                    .len(),
                3
            );
        }
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn unsafe_process_state_prevents_all_manager_commands() -> TestResult {
        let mut fixture = Fixture::new(8, Stop::Empty, Reset::Unload).await?;
        fs::write(fixture.directory.join("cgroup.events"), b"populated 2\n")?;
        let (shutdown, deadline) = budgets()?;
        let result = fixture
            .transport
            .stop_attempt_unit(&mut fixture.bound, shutdown, deadline)
            .await;
        assert!(matches!(
            result,
            Err(SystemdAttemptUnitTeardownError::Shutdown(_))
        ));
        assert!(fixture
            .state
            .lock()
            .map_err(|_| "poisoned fixture")?
            .calls
            .is_empty());
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn invalid_and_expired_budgets_issue_no_commands() -> TestResult {
        let mut fixture = Fixture::new(9, Stop::Empty, Reset::Unload).await?;
        let (shutdown, _) = budgets()?;
        for deadline in [
            shutdown.overall(),
            shutdown.overall() - Duration::from_millis(1),
        ] {
            assert!(matches!(
                fixture
                    .transport
                    .stop_attempt_unit(&mut fixture.bound, shutdown, deadline)
                    .await,
                Err(SystemdAttemptUnitTeardownError::InvalidDeadlines)
            ));
        }
        let now = Instant::now();
        let expired = AttemptShutdownDeadlines::new(
            now - Duration::from_millis(3),
            now - Duration::from_millis(2),
            now - Duration::from_millis(1),
        )?;
        for late_by in [0, 1] {
            advance(Duration::from_millis(late_by)).await;
            assert!(matches!(
                fixture
                    .transport
                    .stop_attempt_unit(&mut fixture.bound, expired, now)
                    .await,
                Err(SystemdAttemptUnitTeardownError::DeadlineElapsed)
            ));
        }
        // A successful later wire reply is a barrier for all earlier requests
        // on this ordered manager, including a wrongly issued expired command.
        let barrier = TransientServiceUnitName::from_attempt_id([99; 16])?;
        let proxy = ManagerProxy::new(&fixture.transport.connection).await?;
        drop(proxy.get_unit(barrier.as_str().to_owned()).await?);
        assert_eq!(
            fixture.state.lock().map_err(|_| "poisoned fixture")?.calls,
            vec![Call::Get(barrier.as_str().to_owned())]
        );
        assert_eq!(fs::read(fixture.directory.join("cgroup.kill"))?, b"0");
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn original_cgroup_deletion_still_requires_exact_unit_absence() -> TestResult {
        let mut fixture = Fixture::new(10, Stop::Empty, Reset::Missing).await?;
        fs::remove_dir_all(&fixture.directory)?;
        fixture.state.lock().map_err(|_| "poisoned fixture")?.loaded = false;
        let (shutdown, deadline) = budgets()?;
        let observed = fixture
            .transport
            .stop_attempt_unit(&mut fixture.bound, shutdown, deadline)
            .await?;
        assert_eq!(
            observed.cgroup_empty().basis(),
            AttemptCgroupEmptyBasis::Deleted
        );
        let name = fixture.unit.as_str().to_owned();
        assert_eq!(
            fixture.state.lock().map_err(|_| "poisoned fixture")?.calls,
            vec![Call::Reset(name.clone(), None), Call::Get(name)]
        );
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn ready_replies_cannot_cross_phase_or_final_acceptance_deadlines() -> TestResult {
        for inspect_reset in [true, false] {
            for late_by in [0, 1] {
                let mut fixture = Fixture::new(11, Stop::Empty, Reset::Unload).await?;
                let mut messages = MessageStream::from(&fixture.transport.connection);
                let (shutdown, deadline) = budgets()?;
                let mut operation = std::pin::pin!(fixture.transport.stop_attempt_unit(
                    &mut fixture.bound,
                    shutdown,
                    deadline
                ));
                loop {
                    let reply = tokio::time::timeout_at(deadline, async {
                        tokio::select! {
                            biased;
                            message = messages.next() => Ok::<_, Box<dyn Error>>(message.ok_or("reply stream ended")??),
                            result = operation.as_mut() => Err(format!("operation finished before reply inspection: {result:?}").into()),
                        }
                    }).await??;
                    let serial = {
                        let state = fixture.state.lock().map_err(|_| "poisoned fixture")?;
                        let serial = if inspect_reset {
                            state.reset_serial
                        } else {
                            state.get_serial
                        };
                        drop(state);
                        serial
                    };
                    if serial.is_some() && reply.header().reply_serial() == serial {
                        assert_eq!(
                            reply.message_type(),
                            if inspect_reset {
                                Type::MethodReturn
                            } else {
                                Type::Error
                            }
                        );
                        break;
                    }
                }
                assert!(Instant::now() < deadline);
                advance(
                    deadline.saturating_duration_since(Instant::now())
                        + Duration::from_millis(late_by),
                )
                .await;
                assert!(matches!(
                    operation.await,
                    Err(SystemdAttemptUnitTeardownError::DeadlineElapsed)
                ));
                if inspect_reset {
                    let barrier = TransientServiceUnitName::from_attempt_id([98; 16])?;
                    let proxy = ManagerProxy::new(&fixture.transport.connection).await?;
                    drop(
                        proxy
                            .get_unit(barrier.as_str().to_owned())
                            .await
                            .err()
                            .ok_or("unloaded fixture unexpectedly stayed loaded")?,
                    );
                    let state = fixture.state.lock().map_err(|_| "poisoned fixture")?;
                    assert_eq!(
                        state
                            .calls
                            .iter()
                            .filter(|call| matches!(call, Call::Get(_)))
                            .collect::<Vec<_>>(),
                        vec![&Call::Get(barrier.as_str().to_owned())]
                    );
                    drop(state);
                }
            }
        }
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn eight_concurrent_attempts_keep_unit_and_kernel_observations_bound() -> TestResult {
        let mut fixtures = Vec::new();
        for id in 1..=8 {
            fixtures.push(Fixture::new(id, Stop::Empty, Reset::Unload).await?);
        }
        let (shutdown, deadline) = budgets()?;
        let results = join_all(fixtures.iter_mut().map(|fixture| {
            fixture
                .transport
                .stop_attempt_unit(&mut fixture.bound, shutdown, deadline)
        }))
        .await;
        for (fixture, result) in fixtures.iter().zip(results) {
            let observed = result?;
            assert_eq!(observed.unit_absence().unit_name(), &fixture.unit);
            assert_eq!(observed.cgroup_empty().unit_name(), &fixture.unit);
            assert_eq!(
                fixture
                    .state
                    .lock()
                    .map_err(|_| "poisoned fixture")?
                    .calls
                    .len(),
                3
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn impossible_proxy_construction_failure_is_not_unit_removal() -> TestResult {
        // Inject only the otherwise unreachable generated-proxy construction
        // failure; all normal cases drive the public operation over real peers.
        let result = super::super::remove_with_proxy(
            Err(zbus::Error::Failure("injected proxy failure".to_owned())),
            TransientServiceUnitName::from_attempt_id([12; 16])?,
            Instant::now() + Duration::from_secs(1),
        )
        .await;
        assert!(matches!(
            result,
            Err(SystemdAttemptUnitTeardownError::Transport(
                SystemdTransientUnitTransportError::Proxy(_)
            ))
        ));
        Ok(())
    }
}
