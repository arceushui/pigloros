#[cfg(test)]
mod cases {
    use std::{
        collections::{BTreeMap, VecDeque},
        error::Error,
        future::pending,
        sync::{Arc, Mutex},
        time::Duration,
    };

    use futures_util::future::join_all;
    use tokio::time::{advance, sleep, Instant};
    use zbus::{
        connection::{socket::channel::Channel, Builder},
        fdo, BoxDBusError, Guid, OwnedObjectPath,
    };

    use super::super::wait_with_proxy;
    use crate::{
        SystemdAttemptUnitAbsenceObservation, SystemdTransientUnitTransport,
        SystemdTransientUnitTransportError, TransientServiceUnitName,
    };

    type TestResult<T = ()> = Result<T, Box<dyn Error>>;

    #[derive(Clone, Copy)]
    enum Reply {
        Loaded,
        Absent(&'static str),
        Denied,
        UnknownObject,
        ServiceUnknown,
        MissingOwner,
        NearMatch,
        DelayedAbsent(Duration),
        Hang,
    }

    #[derive(Debug, zbus::DBusError)]
    #[zbus(prefix = "org.freedesktop.systemd1")]
    enum ManagerError {
        NoSuchUnit(String),
        NoSuchUnitExtra(String),
    }

    struct State {
        calls: Vec<String>,
        scripts: BTreeMap<String, VecDeque<Reply>>,
    }

    struct Manager(Arc<Mutex<State>>);

    #[zbus::interface(name = "org.freedesktop.systemd1.Manager")]
    impl Manager {
        fn subscribe(&self) {}

        async fn get_unit(&self, name: String) -> Result<OwnedObjectPath, BoxDBusError> {
            let reply = {
                let mut state = self
                    .0
                    .lock()
                    .map_err(|_| fdo::Error::Failed("poisoned fixture".to_owned()))?;
                // Record the attempt before any fallible script lookup.
                state.calls.push(name.clone());
                let script = state
                    .scripts
                    .get_mut(&name)
                    .ok_or_else(|| fdo::Error::AccessDenied("unexpected unit name".to_owned()))?;
                let reply = script
                    .front()
                    .copied()
                    .ok_or_else(|| fdo::Error::Failed("empty script".to_owned()))?;
                if script.len() > 1 {
                    let _previous = script.pop_front();
                }
                reply
            };
            let misleading = "org.freedesktop.systemd1.NoSuchUnit: not loaded".to_owned();
            match reply {
                Reply::Loaded => {
                    OwnedObjectPath::try_from("/org/freedesktop/systemd1/unit/still_loaded")
                        .map_err(|error| fdo::Error::Failed(error.to_string()).into())
                }
                Reply::Absent(detail) => Err(Box::new(ManagerError::NoSuchUnit(detail.to_owned()))),
                Reply::Denied => Err(fdo::Error::AccessDenied(misleading).into()),
                Reply::UnknownObject => Err(fdo::Error::UnknownObject(misleading).into()),
                Reply::ServiceUnknown => Err(fdo::Error::ServiceUnknown(misleading).into()),
                Reply::MissingOwner => Err(fdo::Error::NameHasNoOwner(misleading).into()),
                Reply::NearMatch => Err(Box::new(ManagerError::NoSuchUnitExtra(misleading))),
                Reply::DelayedAbsent(delay) => {
                    sleep(delay).await;
                    Err(Box::new(ManagerError::NoSuchUnit("unloaded".to_owned())))
                }
                Reply::Hang => pending().await,
            }
        }
    }

    async fn fixture(
        plans: Vec<(TransientServiceUnitName, Vec<Reply>)>,
    ) -> TestResult<(
        SystemdTransientUnitTransport,
        zbus::Connection,
        Arc<Mutex<State>>,
    )> {
        let state = Arc::new(Mutex::new(State {
            calls: Vec::new(),
            scripts: plans
                .into_iter()
                .map(|(unit, replies)| (unit.as_str().to_owned(), replies.into()))
                .collect(),
        }));
        let guid = Guid::generate();
        let (server_socket, client_socket) = Channel::pair();
        let server = Builder::authenticated_socket(server_socket, guid.clone())
            .p2p()
            .serve_at("/org/freedesktop/systemd1", Manager(Arc::clone(&state)))?
            .build();
        let client = Builder::authenticated_socket(client_socket, guid)
            .p2p()
            .build();
        let (server, client) = tokio::join!(server, client);
        let server = server?;
        let transport = SystemdTransientUnitTransport::from_connection(client?).await?;
        Ok((transport, server, state))
    }

    fn unit(id: u8) -> TestResult<TransientServiceUnitName> {
        Ok(TransientServiceUnitName::from_attempt_id([id; 16])?)
    }

    fn deadline_error(
        result: Result<SystemdAttemptUnitAbsenceObservation, SystemdTransientUnitTransportError>,
    ) {
        assert!(matches!(
            result,
            Err(SystemdTransientUnitTransportError::UnitAbsenceDeadlineElapsed)
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn exact_error_name_returns_the_queried_attempt_without_parsing_description() -> TestResult
    {
        for detail in ["", "unrelated human-readable text"] {
            let name = unit(1)?;
            let (transport, _server, state) =
                fixture(vec![(name.clone(), vec![Reply::Absent(detail)])]).await?;
            let observed: SystemdAttemptUnitAbsenceObservation = transport
                .wait_for_attempt_unit_absence(
                    name.clone(),
                    Instant::now() + Duration::from_millis(100),
                )
                .await?;
            assert_eq!(observed.unit_name(), &name);
            assert_eq!(
                state.lock().map_err(|_| "poisoned fixture")?.calls,
                vec![name.as_str()]
            );
        }
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn any_loaded_object_remains_present_until_the_original_deadline() -> TestResult {
        let name = unit(2)?;
        let (transport, _server, state) =
            fixture(vec![(name.clone(), vec![Reply::Loaded])]).await?;
        let started = Instant::now();
        deadline_error(
            transport
                .wait_for_attempt_unit_absence(name.clone(), started + Duration::from_millis(95))
                .await,
        );
        assert_eq!(started.elapsed(), Duration::from_millis(95));
        let state = state.lock().map_err(|_| "poisoned fixture")?;
        assert!(state.calls.len() > 1);
        assert!(state.calls.iter().all(|called| called == name.as_str()));
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn fresh_exact_queries_wait_for_the_loaded_unit_to_disappear() -> TestResult {
        let name = unit(3)?;
        let (transport, _server, state) = fixture(vec![(
            name.clone(),
            vec![Reply::Loaded, Reply::Loaded, Reply::Absent("unloaded")],
        )])
        .await?;
        let observed = transport
            .wait_for_attempt_unit_absence(
                name.clone(),
                Instant::now() + Duration::from_millis(100),
            )
            .await?;
        assert_eq!(observed.unit_name(), &name);
        assert_eq!(
            state.lock().map_err(|_| "poisoned fixture")?.calls,
            vec![name.as_str(); 3]
        );
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn other_errors_and_near_match_names_cannot_substitute_for_absence() -> TestResult {
        for reply in [
            Reply::Denied,
            Reply::UnknownObject,
            Reply::ServiceUnknown,
            Reply::MissingOwner,
            Reply::NearMatch,
        ] {
            let name = unit(4)?;
            let (transport, _server, state) = fixture(vec![(name.clone(), vec![reply])]).await?;
            let result = transport
                .wait_for_attempt_unit_absence(
                    name.clone(),
                    Instant::now() + Duration::from_millis(100),
                )
                .await;
            assert!(matches!(
                result,
                Err(SystemdTransientUnitTransportError::UnitLookup(_))
            ));
            assert_eq!(
                state.lock().map_err(|_| "poisoned fixture")?.calls,
                vec![name.as_str()]
            );
        }
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn expired_and_exact_start_budgets_issue_no_queries() -> TestResult {
        let name = unit(5)?;
        let (transport, _server, state) =
            fixture(vec![(name.clone(), vec![Reply::Absent("unloaded")])]).await?;
        let deadline = Instant::now();
        deadline_error(
            transport
                .wait_for_attempt_unit_absence(name.clone(), deadline)
                .await,
        );
        advance(Duration::from_millis(1)).await;
        deadline_error(
            transport
                .wait_for_attempt_unit_absence(name, deadline)
                .await,
        );
        assert!(state
            .lock()
            .map_err(|_| "poisoned fixture")?
            .calls
            .is_empty());
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn only_a_response_strictly_before_the_deadline_can_succeed() -> TestResult {
        for delay in [80, 100, 101] {
            let name = unit(6)?;
            let (transport, _server, _state) = fixture(vec![(
                name.clone(),
                vec![Reply::DelayedAbsent(Duration::from_millis(delay))],
            )])
            .await?;
            let result = transport
                .wait_for_attempt_unit_absence(
                    name.clone(),
                    Instant::now() + Duration::from_millis(100),
                )
                .await;
            if delay < 100 {
                assert_eq!(result?.unit_name(), &name);
            } else {
                deadline_error(result);
            }
        }
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn a_stalled_query_cannot_outlive_the_caller_budget() -> TestResult {
        let name = unit(7)?;
        let (transport, _server, state) = fixture(vec![(name.clone(), vec![Reply::Hang])]).await?;
        let started = Instant::now();
        deadline_error(
            transport
                .wait_for_attempt_unit_absence(name.clone(), started + Duration::from_millis(100))
                .await,
        );
        assert_eq!(started.elapsed(), Duration::from_millis(100));
        assert_eq!(
            state.lock().map_err(|_| "poisoned fixture")?.calls,
            vec![name.as_str()]
        );
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn repeated_queries_do_not_reset_the_original_deadline() -> TestResult {
        let name = unit(8)?;
        let (transport, _server, state) = fixture(vec![(
            name.clone(),
            vec![
                Reply::Loaded,
                Reply::DelayedAbsent(Duration::from_millis(95)),
            ],
        )])
        .await?;
        let started = Instant::now();
        deadline_error(
            transport
                .wait_for_attempt_unit_absence(name.clone(), started + Duration::from_millis(100))
                .await,
        );
        assert_eq!(started.elapsed(), Duration::from_millis(100));
        assert_eq!(
            state.lock().map_err(|_| "poisoned fixture")?.calls,
            vec![name.as_str(); 2]
        );
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn an_earlier_absence_is_not_cached_when_the_name_is_loaded_again() -> TestResult {
        let name = unit(9)?;
        let (transport, _server, state) = fixture(vec![(
            name.clone(),
            vec![Reply::Absent("unloaded"), Reply::Loaded],
        )])
        .await?;
        let observed = transport
            .wait_for_attempt_unit_absence(
                name.clone(),
                Instant::now() + Duration::from_millis(100),
            )
            .await?;
        assert_eq!(observed.unit_name(), &name);
        deadline_error(
            transport
                .wait_for_attempt_unit_absence(
                    name.clone(),
                    Instant::now() + Duration::from_millis(50),
                )
                .await,
        );
        assert!(state.lock().map_err(|_| "poisoned fixture")?.calls.len() > 1);
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn eight_concurrent_attempts_query_only_their_exact_names() -> TestResult {
        let names = (1..=8).map(unit).collect::<TestResult<Vec<_>>>()?;
        let plans = names
            .iter()
            .map(|name| (name.clone(), vec![Reply::Loaded, Reply::Absent("unloaded")]))
            .collect();
        let (transport, _server, state) = fixture(plans).await?;
        let deadline = Instant::now() + Duration::from_millis(100);
        let results = join_all(
            names
                .iter()
                .map(|name| transport.wait_for_attempt_unit_absence(name.clone(), deadline)),
        )
        .await;
        for (name, observed) in names.iter().zip(results) {
            assert_eq!(observed?.unit_name(), name);
        }
        let state = state.lock().map_err(|_| "poisoned fixture")?;
        assert_eq!(state.calls.len(), 16);
        for name in names {
            assert_eq!(
                state
                    .calls
                    .iter()
                    .filter(|called| *called == name.as_str())
                    .count(),
                2
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn proxy_construction_failure_is_not_absence() -> TestResult {
        // The fixed generated manager path cannot fail construction through
        // the public method; inject only this framework-construction boundary.
        let result = wait_with_proxy(
            Err(zbus::Error::Failure("injected proxy failure".to_owned())),
            unit(1)?,
        )
        .await;
        assert!(matches!(
            result,
            Err(SystemdTransientUnitTransportError::Proxy(_))
        ));
        Ok(())
    }
}
