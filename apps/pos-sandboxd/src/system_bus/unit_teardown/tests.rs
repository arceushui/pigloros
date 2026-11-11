//! Exact transport ordering and retained-kernel observations at the public seam.

#[cfg(test)]
pub(super) mod cases {
    use std::{
        collections::VecDeque,
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
    /// How the fake manager's stop job affects the cgroup.
    pub enum Stop {
        Empty,
        LeavesPopulated,
    }

    #[derive(Clone, Copy)]
    /// How the fake manager answers the failed-state reset.
    pub enum Reset {
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
        /// The manager collects the unit after this lookup.
        Collect,
    }

    #[derive(Debug, PartialEq)]
    enum Call {
        Stop(String, String),
        Kill(String, String, i32),
        Reset(String, Option<Vec<u8>>),
        Get(String),
        ByCgroup(String),
    }

    struct State {
        subscribed: bool,
        loaded: bool,
        lookup: Lookup,
        calls: Vec<Call>,
        reset_serial: Option<NonZeroU32>,
        get_serial: Option<NonZeroU32>,
        /// Successive `ControlGroup` reads; the last one repeats.
        control_groups: VecDeque<String>,
        /// The unit's `ActiveState`, or a read failure.
        activity: Option<String>,
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
                Lookup::Collect => self.state.lock().map_err(failed)?.loaded = false,
                Lookup::Unchanged => {}
            }
            if loaded {
                OwnedObjectPath::try_from("/org/freedesktop/systemd1/unit/attempt")
                    .map_err(|error| failed(error).into())
            } else {
                Err(Box::new(ManagerError::NoSuchUnit("not loaded".to_owned())))
            }
        }

        #[zbus(name = "GetUnitByControlGroup")]
        fn get_unit_by_control_group(&self, cgroup: String) -> fdo::Result<OwnedObjectPath> {
            self.state
                .lock()
                .map_err(failed)?
                .calls
                .push(Call::ByCgroup(cgroup));
            OwnedObjectPath::try_from(UNIT_PATH).map_err(failed)
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

    const UNIT_PATH: &str = "/org/freedesktop/systemd1/unit/attempt";

    /// A listed object that is not the manager's current attempt unit.
    const OTHER_PATH: &str = "/org/freedesktop/systemd1/unit/other";

    /// An attempt unit's service object, reporting the fixture's cgroups.
    struct Service(Arc<Mutex<State>>);

    #[zbus::interface(name = "org.freedesktop.systemd1.Service", spawn = false)]
    impl Service {
        #[zbus(property, name = "ControlGroup")]
        fn control_group(&self) -> fdo::Result<String> {
            let mut state = self.0.lock().map_err(failed)?;
            let read = if state.control_groups.len() > 1 {
                state.control_groups.pop_front()
            } else {
                state.control_groups.front().cloned()
            };
            read.ok_or_else(|| fdo::Error::Failed("no ControlGroup".to_owned()))
        }
    }

    /// An attempt unit's unit object, reporting the fixture's state.
    struct Unit(Arc<Mutex<State>>);

    #[zbus::interface(name = "org.freedesktop.systemd1.Unit", spawn = false)]
    impl Unit {
        #[zbus(property, name = "ActiveState")]
        fn active_state(&self) -> fdo::Result<String> {
            self.0
                .lock()
                .map_err(failed)?
                .activity
                .clone()
                .ok_or_else(|| fdo::Error::AccessDenied("ActiveState denied".to_owned()))
        }
    }

    fn failed(error: impl std::fmt::Display) -> fdo::Error {
        fdo::Error::Failed(error.to_string())
    }

    /// A fake systemd manager peer and one retained attempt cgroup.
    pub struct Fixture {
        cgroups: tempfile::TempDir,
        _server: zbus::Connection,
        directory: PathBuf,
        unit: TransientServiceUnitName,
        /// The retained attempt cgroup.
        pub bound: BoundAttemptCgroup,
        /// The transport connected to the fake manager.
        pub transport: SystemdTransientUnitTransport,
        state: Arc<Mutex<State>>,
    }

    /// Counts the manager calls one fixture records, after its cgroup moved.
    pub struct ManagerCalls(Arc<Mutex<State>>);

    impl ManagerCalls {
        /// The number of manager calls recorded so far.
        ///
        /// # Errors
        /// Returns a poisoned fixture lock.
        pub fn count(&self) -> TestResult<usize> {
            Ok(self.0.lock().map_err(|_| "poisoned fixture")?.calls.len())
        }
    }

    impl Fixture {
        /// The bound attempt cgroup's directory.
        #[must_use]
        pub fn cgroup_directory(&self) -> &std::path::Path {
            &self.directory
        }

        /// A counter of this fixture's manager calls.
        #[must_use]
        pub fn calls(&self) -> ManagerCalls {
            ManagerCalls(Arc::clone(&self.state))
        }

        /// A fake manager for the attempt `[id; 16]` and its cgroup.
        ///
        /// # Errors
        /// Returns a fixture setup failure.
        ///
        /// # Panics
        /// Panics if the transport did not subscribe to manager signals.
        pub async fn new(id: u8, stop: Stop, reset: Reset) -> TestResult<Self> {
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
                control_groups: VecDeque::from(["/attempt".to_owned()]),
                activity: Some("active".to_owned()),
            }));
            let manager = Manager {
                state: Arc::clone(&state),
                directory: directory.clone(),
                stop,
                reset,
            };
            let (server, client) = peer_connections(|server| {
                server
                    .serve_at("/org/freedesktop/systemd1", manager)
                    .serve_at(UNIT_PATH, Service(Arc::clone(&state)))
                    .serve_at(UNIT_PATH, Unit(Arc::clone(&state)))
                    .serve_at(OTHER_PATH, Service(Arc::clone(&state)))
                    .serve_at(OTHER_PATH, Unit(Arc::clone(&state)))
            })
            .await?;
            let transport = SystemdTransientUnitTransport::from_connection(client).await?;
            assert!(state.lock().map_err(|_| "poisoned fixture")?.subscribed);
            Ok(Self {
                cgroups: root,
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

    /// A prepared attempt in a fresh private runtime tree, keyed by `[id; 16]`.
    fn prepared_attempt(
        id: u8,
    ) -> TestResult<(
        tempfile::TempDir,
        crate::SystemdAttemptRegistry,
        crate::PreparedAttemptDirectory,
    )> {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let runtime = tempfile::tempdir()?;
        fs::set_permissions(runtime.path(), fs::Permissions::from_mode(0o700))?;
        for directory in ["registry", "attempts"] {
            let path = runtime.path().join(directory);
            fs::create_dir(&path)?;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        }
        let parent = File::open(runtime.path())?;
        let registry = crate::SystemdAttemptRegistry::from_runtime_directory(
            &parent,
            parent.metadata()?.uid(),
        )?;
        let prepared = registry
            .commit_planned(&crate::PlannedAttemptIntent::new([id; 16], [9; 32])?)?
            .prepare_fixture_directory()?;
        Ok((runtime, registry, prepared))
    }

    /// Record that `prepared`'s execution submitted its unit and bound `cgroup`.
    fn submitted(
        prepared: &crate::PreparedAttemptDirectory,
        cgroup: &BoundAttemptCgroup,
    ) -> TestResult {
        let ownership = prepared.execution_ownership();
        ownership.claim()?;
        ownership.submit()?;
        ownership.bind_cgroup(crate::UnitCgroup::identity(cgroup));
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn only_the_exact_stopped_unit_lets_terminal_cleanup_delete_intent() -> TestResult {
        // The bound cgroup of this attempt's execution, an unrecorded cgroup,
        // and another unit's cgroup recorded as if this execution bound it.
        for (unit_id, recorded) in [(1, true), (1, false), (2, true)] {
            let mut fixture = Fixture::new(unit_id, Stop::Empty, Reset::Unload).await?;
            let (shutdown, deadline) = budgets()?;
            let observed = fixture
                .transport
                .stop_attempt_unit(&mut fixture.bound, shutdown, deadline)
                .await?;
            let (runtime, registry, prepared) = prepared_attempt(1)?;
            let ownership = prepared.execution_ownership();
            if recorded {
                submitted(&prepared, &fixture.bound)?;
            }
            let key = prepared.intent().unit_name().attempt_component().to_owned();
            let result = prepared
                .finish_terminal_cleanup(crate::AttemptUnitTermination::Stopped(&observed), None);
            let exact = unit_id == 1 && recorded;
            assert_eq!(result.is_ok(), exact, "unit {unit_id}: {result:?}");
            assert_eq!(runtime.path().join("registry").join(&key).exists(), !exact);
            assert_eq!(runtime.path().join("attempts").join(&key).exists(), !exact);
            assert_eq!(
                registry
                    .commit_planned(&crate::PlannedAttemptIntent::new([3; 16], [9; 32])?)
                    .is_ok(),
                exact
            );
            // Stop evidence closes an unclaimed start permission either way.
            assert!(ownership.claim().is_err());
        }
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn a_stopped_unit_still_needs_the_released_root_of_its_activated_tree() -> TestResult {
        // The exact unit with its root, the exact unit without its root, and
        // another unit's evidence beside this tree's correct root.
        for (unit_id, released) in [(1, true), (1, false), (2, true)] {
            let mut fixture = Fixture::new(unit_id, Stop::Empty, Reset::Unload).await?;
            let (shutdown, deadline) = budgets()?;
            let observed = fixture
                .transport
                .stop_attempt_unit(&mut fixture.bound, shutdown, deadline)
                .await?;
            let (runtime, registry, prepared) = prepared_attempt(1)?;
            submitted(&prepared, &fixture.bound)?;
            let root = crate::test_fixtures::released_root(&prepared).await?;
            let key = prepared.intent().unit_name().attempt_component().to_owned();
            let result = prepared.finish_terminal_cleanup(
                crate::AttemptUnitTermination::Stopped(&observed),
                released.then_some(root),
            );
            let exact = unit_id == 1 && released;
            assert_eq!(result.is_ok(), exact, "unit {unit_id}: {result:?}");
            assert_eq!(runtime.path().join("registry").join(&key).exists(), !exact);
            assert_eq!(runtime.path().join("attempts").join(&key).exists(), !exact);
            assert_eq!(
                registry
                    .commit_planned(&crate::PlannedAttemptIntent::new([3; 16], [9; 32])?)
                    .is_ok(),
                exact
            );
        }
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn a_listed_unit_is_bound_through_its_listing_before_it_is_stopped() -> TestResult {
        let fixture = Fixture::new(5, Stop::Empty, Reset::Unload).await?;
        let (shutdown, deadline) = budgets()?;
        let listed = OwnedObjectPath::try_from(UNIT_PATH)?;
        let root = CgroupRoot::for_test(File::open(fixture.cgroups.path())?);
        fixture
            .transport
            .stop_listed_with_root(&fixture.unit, &listed, Ok(root), (shutdown, deadline))
            .await?;
        let name = fixture.unit.as_str().to_owned();
        let cgroup = "/attempt".to_owned();
        assert_eq!(
            fixture.state.lock().map_err(|_| "poisoned fixture")?.calls,
            vec![
                Call::Get(name.clone()),
                Call::ByCgroup(cgroup.clone()),
                Call::ByCgroup(cgroup),
                Call::Get(name.clone()),
                Call::Stop(name.clone(), "replace".to_owned()),
                Call::Reset(name.clone(), Some(b"populated 0\n".to_vec())),
                Call::Get(name),
            ]
        );
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn an_unbindable_listed_unit_is_never_stopped() -> TestResult {
        // The cgroup hierarchy cannot be opened, or the listed object is not
        // the manager's current unit.
        for substituted in [false, true] {
            let fixture = Fixture::new(6, Stop::Empty, Reset::Unload).await?;
            let (shutdown, deadline) = budgets()?;
            let (listed, root) = if substituted {
                (
                    OwnedObjectPath::try_from(OTHER_PATH)?,
                    Ok(CgroupRoot::for_test(File::open(fixture.cgroups.path())?)),
                )
            } else {
                (
                    OwnedObjectPath::try_from(UNIT_PATH)?,
                    Err(crate::AttemptCgroupError::WrongFilesystem),
                )
            };
            let result = fixture
                .transport
                .stop_listed_with_root(&fixture.unit, &listed, root, (shutdown, deadline))
                .await;
            let refused = matches!(
                (substituted, &result),
                (
                    true,
                    Err(SystemdAttemptUnitTeardownError::Transport(
                        SystemdTransientUnitTransportError::CgroupUnitMismatch
                    ))
                ) | (
                    false,
                    Err(SystemdAttemptUnitTeardownError::Transport(
                        SystemdTransientUnitTransportError::CgroupKernel(_)
                    ))
                )
            );
            assert!(refused, "{result:?}");
            let calls = fixture.state.lock().map_err(|_| "poisoned fixture")?;
            assert!(!calls
                .calls
                .iter()
                .any(|call| matches!(call, Call::Stop(..) | Call::Kill(..) | Call::Reset(..))));
            drop(calls);
            assert_eq!(
                fs::read(fixture.directory.join("cgroup.events"))?,
                b"populated 1\n"
            );
        }
        Ok(())
    }

    /// Whether a refused stop failed as expected.
    type Refusal = fn(&Result<(), SystemdAttemptUnitTeardownError>) -> bool;
    /// A cgroupless unit's state, its successive cgroups, its listed path and
    /// the expected refusal.
    type CgrouplessCase = (
        Option<&'static str>,
        Vec<&'static str>,
        &'static str,
        Refusal,
    );

    /// A listed unit without a cgroup in `state`.
    async fn cgroupless(
        id: u8,
        state: Option<&str>,
        control_groups: &[&str],
        lookup: Lookup,
    ) -> TestResult<Fixture> {
        let fixture = Fixture::new(id, Stop::Empty, Reset::Unload).await?;
        {
            let mut fake = fixture.state.lock().map_err(|_| "poisoned fixture")?;
            fake.activity = state.map(str::to_owned);
            fake.control_groups = control_groups
                .iter()
                .map(|&cgroup| cgroup.to_owned())
                .collect();
            fake.lookup = lookup;
        }
        Ok(fixture)
    }

    async fn stop_listed(
        fixture: &Fixture,
        path: &str,
    ) -> TestResult<Result<(), SystemdAttemptUnitTeardownError>> {
        let (shutdown, deadline) = budgets()?;
        let listed = OwnedObjectPath::try_from(path)?;
        let root = CgroupRoot::for_test(File::open(fixture.cgroups.path())?);
        Ok(fixture
            .transport
            .stop_listed_with_root(&fixture.unit, &listed, Ok(root), (shutdown, deadline))
            .await)
    }

    #[tokio::test(start_paused = true)]
    async fn an_inactive_or_failed_unit_without_a_cgroup_is_removed() -> TestResult {
        // Owner decision A: no cgroup and inactive or failed proves emptiness.
        for (state, lookup) in [("failed", Lookup::Unchanged), ("inactive", Lookup::Collect)] {
            let fixture = cgroupless(7, Some(state), &[""], lookup).await?;
            stop_listed(&fixture, UNIT_PATH).await??;
            let name = fixture.unit.as_str().to_owned();
            let expected = if state == "failed" {
                vec![
                    Call::Get(name.clone()),
                    Call::Reset(name.clone(), Some(b"populated 1\n".to_vec())),
                    Call::Get(name),
                ]
            } else {
                vec![Call::Get(name.clone()), Call::Get(name)]
            };
            assert_eq!(
                fixture.state.lock().map_err(|_| "poisoned fixture")?.calls,
                expected,
                "{state}"
            );
        }
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn any_other_unit_without_a_cgroup_is_never_removed() -> TestResult {
        let mismatch = |result: &Result<(), SystemdAttemptUnitTeardownError>| {
            matches!(
                result,
                Err(SystemdAttemptUnitTeardownError::Transport(
                    SystemdTransientUnitTransportError::CgroupUnitMismatch
                ))
            )
        };
        let active = |result: &Result<(), SystemdAttemptUnitTeardownError>| {
            matches!(
                result,
                Err(SystemdAttemptUnitTeardownError::Transport(
                    SystemdTransientUnitTransportError::CgrouplessUnitActive
                ))
            )
        };
        let unread = |result: &Result<(), SystemdAttemptUnitTeardownError>| {
            matches!(
                result,
                Err(SystemdAttemptUnitTeardownError::Transport(
                    SystemdTransientUnitTransportError::PropertyReadback {
                        property: "ActiveState",
                        ..
                    }
                ))
            )
        };
        let mut cases: Vec<CgrouplessCase> = ["active", "activating", "deactivating", "reloading"]
            .into_iter()
            .map(|state| (Some(state), vec![""], UNIT_PATH, active as Refusal))
            .collect();
        cases.extend([
            // The state cannot be read.
            (None, vec![""], UNIT_PATH, unread as Refusal),
            // A cgroup appeared after the state was read.
            (
                Some("failed"),
                vec!["", "/attempt"],
                UNIT_PATH,
                mismatch as Refusal,
            ),
            // The listed object is not the manager's current unit.
            (Some("failed"), vec![""], OTHER_PATH, mismatch as Refusal),
        ]);
        for (state, cgroups, path, refused) in cases {
            let fixture = cgroupless(8, state, &cgroups, Lookup::Unchanged).await?;
            let result = stop_listed(&fixture, path).await?;
            assert!(refused(&result), "{state:?} {cgroups:?} {path}: {result:?}");
            let calls = fixture.state.lock().map_err(|_| "poisoned fixture")?;
            assert!(!calls
                .calls
                .iter()
                .any(|call| matches!(call, Call::Stop(..) | Call::Kill(..) | Call::Reset(..))));
            drop(calls);
        }
        Ok(())
    }
}
