use piglor_gateway::{router, ActionPrincipal, AppState, Gateway, LedgerWriteMode};
use piglor_ledger::LedgerView;
use pos_core::{Capability, EntityId, Kind, Plugin, PluginId, TimelineId, WallTime};
use pos_experiment::{Experiment, ExperimentConfig, StopCondition, TickOutcome};
use pos_plugin_agent::{
    AgentAction, AgentContext, AgentDriver, AgentPlugin, AgentPolicy, AgentReducer,
    RoundRobinPolicy, EVENT_TYPE_ACTION,
};
use pos_plugin_society::{
    draft_signal, SocietyDimension, SocietyPlugin, SocietyReducer, SocietySignal,
};
use pos_runtime::{Driver, ObservationView, ProjectionKey, RuntimeError, StepOutput};
use pos_state::{EntityStateProjection, ProjectionRegistry};
use pos_store::{open_store, SeqRange, StoreConfig};
use serde_json::{json, Value};
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc, Arc, Mutex,
    },
    time::Duration,
};
use tokio::{sync::oneshot, task::JoinHandle};

trait TestResultExt<T, E> {
    fn test_ok(self) -> Result<T, Box<dyn std::error::Error + Send + Sync>>;
}

impl<T, E: std::fmt::Debug> TestResultExt<T, E> for Result<T, E> {
    fn test_ok(self) -> Result<T, Box<dyn std::error::Error + Send + Sync>> {
        self.map_err(|error| format!("unexpected error: {error:?}").into())
    }
}

trait TestOptionExt<T> {
    fn test_ok(self) -> Result<T, Box<dyn std::error::Error + Send + Sync>>;
}

impl<T> TestOptionExt<T> for Option<T> {
    fn test_ok(self) -> Result<T, Box<dyn std::error::Error + Send + Sync>> {
        self.ok_or_else(|| "expected a value".into())
    }
}

struct FixturePlugin {
    id: PluginId,
    name: &'static str,
    has_driver: bool,
    has_reducer: bool,
}

impl FixturePlugin {
    fn new(name: &'static str, has_driver: bool, has_reducer: bool) -> Self {
        Self {
            id: PluginId::new(),
            name,
            has_driver,
            has_reducer,
        }
    }
}

impl Plugin for FixturePlugin {
    fn id(&self) -> PluginId {
        self.id
    }

    fn name(&self) -> &'static str {
        self.name
    }

    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: Vec::new(),
            owned_entity_kinds: Vec::new(),
            has_driver: self.has_driver,
            has_reducer: self.has_reducer,
        }
    }
}

struct ObservationProbeDriver {
    subscriptions: Vec<ProjectionKey>,
    log: Arc<Mutex<Vec<u64>>>,
}

impl Driver for ObservationProbeDriver {
    fn name(&self) -> &'static str {
        "observation-probe"
    }

    fn subscriptions(&self) -> &[ProjectionKey] {
        &self.subscriptions
    }

    fn tick_interval(&self) -> Duration {
        Duration::from_millis(100)
    }

    fn step(
        &mut self,
        _timeline: TimelineId,
        observations: ObservationView<'_>,
    ) -> Result<StepOutput, RuntimeError> {
        let count = observations
            .state_for(&self.subscriptions[0])
            .and_then(|state| state.get("event_count"))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let Ok(mut log) = self.log.lock() else {
            return Err(RuntimeError::InvalidPayload {
                event_type: "observation-probe".to_owned(),
                reason: "probe log lock is poisoned".to_owned(),
            });
        };
        if log.len() < 3 {
            log.push(count);
        }
        drop(log);
        Ok(StepOutput::empty())
    }
}

struct CountingPolicy {
    inner: RoundRobinPolicy,
    decisions: Arc<AtomicUsize>,
}

impl AgentPolicy for CountingPolicy {
    fn name(&self) -> &'static str {
        "counting-round-robin"
    }

    fn decide(&mut self, context: &AgentContext) -> AgentAction {
        self.decisions.fetch_add(1, Ordering::SeqCst);
        self.inner.decide(context)
    }
}

struct BarrierPolicy {
    inner: RoundRobinPolicy,
    decisions: Arc<AtomicUsize>,
    snapshot_ready: Option<mpsc::Sender<()>>,
    release: Mutex<mpsc::Receiver<()>>,
}

impl AgentPolicy for BarrierPolicy {
    fn name(&self) -> &'static str {
        "barrier-round-robin"
    }

    fn decide(&mut self, context: &AgentContext) -> AgentAction {
        self.decisions.fetch_add(1, Ordering::SeqCst);
        if context.tick == 1 {
            let ready = self.snapshot_ready.take();
            assert!(ready.is_some(), "fast policy signals readiness once");
            if let Some(ready) = ready {
                assert!(
                    ready.send(()).is_ok(),
                    "snapshot readiness receiver is alive"
                );
            }
            let release = self.release.lock();
            assert!(release.is_ok(), "policy release lock is healthy");
            if let Ok(release) = release {
                assert!(release.recv().is_ok(), "policy release sender is alive");
            }
        }
        self.inner.decide(context)
    }
}

struct HttpResponse {
    status: u16,
    body: Value,
}

async fn request_http(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> Result<HttpResponse, Box<dyn std::error::Error + Send + Sync>> {
    let method = method.to_owned();
    let path = path.to_owned();
    tokio::task::spawn_blocking(move || request_http_blocking(address, &method, &path, body))
        .await
        .test_ok()?
}

fn request_http_blocking(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> Result<HttpResponse, Box<dyn std::error::Error + Send + Sync>> {
    let payload = body
        .map_or_else(|| Ok(Vec::new()), |value| serde_json::to_vec(&value))
        .test_ok()?;
    let mut stream = TcpStream::connect(address).test_ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .test_ok()?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .test_ok()?;
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: {address}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        payload.len()
    )
    .test_ok()?;
    stream.write_all(&payload).test_ok()?;
    stream.flush().test_ok()?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response).test_ok()?;
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .test_ok()?;
    let headers = std::str::from_utf8(&response[..header_end]).test_ok()?;
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .test_ok()?;
    let body = serde_json::from_slice(&response[header_end + 4..]).test_ok()?;
    Ok(HttpResponse { status, body })
}

struct FixtureGuard {
    policy_release: Option<mpsc::Sender<()>>,
    server_shutdown: Option<oneshot::Sender<()>>,
    server: Option<JoinHandle<std::io::Result<()>>>,
}

impl FixtureGuard {
    fn release_policy(&mut self) {
        if let Some(release) = self.policy_release.take() {
            match release.send(()) {
                Ok(()) | Err(_) => {}
            }
        }
    }

    async fn shutdown(mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.release_policy();
        if let Some(shutdown) = self.server_shutdown.take() {
            match shutdown.send(()) {
                Ok(()) | Err(()) => {}
            }
        }
        if let Some(mut server) = self.server.take() {
            let Ok(joined) = tokio::time::timeout(Duration::from_secs(5), &mut server).await else {
                server.abort();
                drop(server.await);
                return Err("Gateway server did not shut down within five seconds".into());
            };
            let joined = joined.test_ok()?;
            joined.test_ok()?;
        }
        Ok(())
    }
}

impl Drop for FixtureGuard {
    fn drop(&mut self) {
        self.release_policy();
        if let Some(shutdown) = self.server_shutdown.take() {
            match shutdown.send(()) {
                Ok(()) | Err(()) => {}
            }
        }
        if let Some(server) = self.server.take() {
            server.abort();
        }
    }
}

fn replay_registry() -> ProjectionRegistry {
    let mut registry = ProjectionRegistry::new();
    registry.register("observation", Box::new(EntityStateProjection));
    registry.register("society", Box::new(SocietyReducer));
    registry.register("agent", Box::new(AgentReducer));
    registry
}

fn snapshot_json(
    registry: &ProjectionRegistry,
) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
    serde_json::to_value(registry.state_snapshot()).test_ok()
}

fn state_u64(
    registry: &ProjectionRegistry,
    reducer: &str,
    entity: EntityId,
    key: &str,
) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
    registry
        .state_for_reducer(reducer, &entity)
        .and_then(|state| state.get(key))
        .and_then(Value::as_u64)
        .test_ok()
}

struct MultiRateScenario {
    _database: tempfile::NamedTempFile,
    path: String,
    address: SocketAddr,
    timeline: TimelineId,
    human_body: EntityId,
    human_entity: EntityId,
    society_entity: EntityId,
    fast_entity: EntityId,
    slow_entity: EntityId,
    fast_decisions: Arc<AtomicUsize>,
    slow_decisions: Arc<AtomicUsize>,
    probe_log: Arc<Mutex<Vec<u64>>>,
    snapshot_ready: Option<mpsc::Sender<()>>,
    ready_rx: Option<mpsc::Receiver<()>>,
    release_rx: Option<mpsc::Receiver<()>>,
    guard: FixtureGuard,
}

async fn create_scenario() -> Result<MultiRateScenario, Box<dyn std::error::Error + Send + Sync>> {
    let database = tempfile::NamedTempFile::new().test_ok()?;
    let path = database.path().to_str().test_ok()?.to_owned();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .test_ok()?;
    let address = listener.local_addr().test_ok()?;
    let human_body = EntityId::new();
    let human_entity = EntityId::new();
    let state = AppState {
        gateway: Gateway::new_with_world_bodies_and_principal(
            open_store(StoreConfig::Sqlite { path: path.clone() }).test_ok()?,
            [human_body],
            ActionPrincipal::new(human_entity, [Kind::new("world.action.submit")]),
        ),
        ledger_view: LedgerView::default(),
        ledger_write: LedgerWriteMode::Disabled,
    };
    let (server_shutdown, shutdown_rx) = oneshot::channel();
    let server = tokio::spawn(async move {
        axum::serve(listener, router(state))
            .with_graceful_shutdown(async {
                match shutdown_rx.await {
                    Ok(()) | Err(_) => {}
                }
            })
            .await
    });
    let (snapshot_ready, ready_rx) = mpsc::channel();
    let (policy_release, release_rx) = mpsc::channel();
    let guard = FixtureGuard {
        policy_release: Some(policy_release),
        server_shutdown: Some(server_shutdown),
        server: Some(server),
    };
    let created = request_http(
        address,
        "POST",
        "/v1/timelines",
        Some(json!({"name": "multi-rate-e2e"})),
    )
    .await?;
    assert_eq!(created.status, 201);
    let timeline_text = created.body["id"].as_str().test_ok()?;
    let timeline = TimelineId::from_ulid(ulid::Ulid::from_string(timeline_text).test_ok()?);
    let society_entity = EntityId::new();
    let fast_entity = EntityId::new();
    let slow_entity = EntityId::new();
    let signal = request_http(
        address,
        "POST",
        &format!("/v1/timelines/{timeline}/signals"),
        Some(json!({
            "entity_id": society_entity.to_string(),
            "dimension": "trust",
            "value": 0.75,
            "subject": null,
            "object": null,
        })),
    )
    .await?;
    assert_eq!(signal.status, 201);
    Ok(MultiRateScenario {
        _database: database,
        path,
        address,
        timeline,
        human_body,
        human_entity,
        society_entity,
        fast_entity,
        slow_entity,
        fast_decisions: Arc::new(AtomicUsize::new(0)),
        slow_decisions: Arc::new(AtomicUsize::new(0)),
        probe_log: Arc::new(Mutex::new(Vec::new())),
        snapshot_ready: Some(snapshot_ready),
        ready_rx: Some(ready_rx),
        release_rx: Some(release_rx),
        guard,
    })
}

fn register_experiment(
    scenario: &mut MultiRateScenario,
) -> Result<Experiment, Box<dyn std::error::Error + Send + Sync>> {
    let observation = FixturePlugin::new("observation", false, true);
    let society = SocietyPlugin::new();
    let fast = AgentPlugin::new();
    let probe = FixturePlugin::new("observation-probe", true, false);
    let slow = AgentPlugin::new();
    let mut experiment = Experiment::new(ExperimentConfig {
        name: "multi-rate-host".to_owned(),
        stop: StopCondition::MaxTicks(10),
        store_config: StoreConfig::Sqlite {
            path: scenario.path.clone(),
        },
    });
    experiment
        .register(&observation, Some(Box::new(EntityStateProjection)), None)
        .test_ok()?;
    experiment
        .register(&society, Some(Box::new(SocietyReducer)), None)
        .test_ok()?;
    experiment
        .register(
            &fast,
            Some(Box::new(AgentReducer)),
            Some(Box::new(AgentDriver::new(
                scenario.fast_entity,
                Box::new(BarrierPolicy {
                    inner: RoundRobinPolicy::new(vec!["fast".to_owned()]),
                    decisions: Arc::clone(&scenario.fast_decisions),
                    snapshot_ready: Some(scenario.snapshot_ready.take().test_ok()?),
                    release: Mutex::new(scenario.release_rx.take().test_ok()?),
                }),
                vec!["fast".to_owned()],
            ))),
        )
        .test_ok()?;
    experiment
        .register(
            &probe,
            None,
            Some(Box::new(ObservationProbeDriver {
                subscriptions: vec![ProjectionKey::new(scenario.human_entity)],
                log: Arc::clone(&scenario.probe_log),
            })),
        )
        .test_ok()?;
    experiment
        .register(
            &slow,
            Some(Box::new(AgentReducer)),
            Some(Box::new(
                AgentDriver::new(
                    scenario.slow_entity,
                    Box::new(CountingPolicy {
                        inner: RoundRobinPolicy::new(vec!["slow".to_owned()]),
                        decisions: Arc::clone(&scenario.slow_decisions),
                    }),
                    vec!["slow".to_owned()],
                )
                .with_tick_interval(Duration::from_millis(200)),
            )),
        )
        .test_ok()?;
    Ok(experiment)
}

async fn run_tick_boundaries(
    scenario: &mut MultiRateScenario,
    mut session: pos_experiment::ExperimentSession,
) -> Result<(pos_experiment::ExperimentSession, WallTime), Box<dyn std::error::Error + Send + Sync>>
{
    let pinned_wall_time = WallTime::from_micros(u64::try_from(i64::MAX).test_ok()?);
    let mut pending_store = open_store(StoreConfig::Sqlite {
        path: scenario.path.clone(),
    })
    .test_ok()?;
    let pending = pending_store
        .append(
            scenario.timeline,
            &[draft_signal(
                scenario.fast_entity,
                &SocietySignal {
                    dimension: SocietyDimension::Trust,
                    value: 0.25,
                    subject: None,
                    object: None,
                },
            )
            .with_wall_time(pinned_wall_time)],
        )
        .test_ok()?;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].seq.as_u64(), 2);
    drop(pending_store);
    assert_eq!(
        session.step_cadenced(0).test_ok()?,
        TickOutcome::Advanced {
            folded_events: 3,
            emitted_events: 2,
        }
    );
    let session_task = tokio::task::spawn_blocking(move || {
        let result = session.step_cadenced(100_000_000);
        (session, result)
    });
    let ready_rx = scenario.ready_rx.take().test_ok()?;
    tokio::task::spawn_blocking(move || ready_rx.recv_timeout(Duration::from_secs(5)).test_ok())
        .await
        .test_ok()?
        .test_ok()?;
    let human = request_http(
        scenario.address,
        "POST",
        &format!("/v1/timelines/{}/actions", scenario.timeline),
        Some(json!({
            "entity_id": scenario.human_entity.to_string(),
            "event_type": "world.action",
            "capability": "world.action.submit",
            "payload": {
                "actor_entity_id": scenario.human_entity.to_string(),
                "body_entity_id": scenario.human_body.to_string(),
                "action_kind": "impulse",
                "params": [1],
                "action_scope": 0,
                "catalogue_version": 1,
                "tick": 1
            },
        })),
    )
    .await?;
    assert_eq!(human.status, 201);
    scenario.guard.release_policy();
    let (mut session, boundary_at_100_ms) = session_task.await.test_ok()?;
    assert_eq!(
        boundary_at_100_ms.test_ok()?,
        TickOutcome::Advanced {
            folded_events: 2,
            emitted_events: 1,
        }
    );
    assert_eq!(
        session.step_cadenced(200_000_000).test_ok()?,
        TickOutcome::Advanced {
            folded_events: 2,
            emitted_events: 2,
        }
    );
    Ok((session, pinned_wall_time))
}

async fn poll_events(
    address: SocketAddr,
    timeline: TimelineId,
) -> Result<Vec<Value>, Box<dyn std::error::Error + Send + Sync>> {
    let mut polled = Vec::new();
    let mut from_seq = 0_u64;
    let mut pages = 0_u8;
    loop {
        pages += 1;
        assert!(pages <= 5, "polling must terminate within five pages");
        let page = request_http(
            address,
            "GET",
            &format!("/v1/timelines/{timeline}/events?from_seq={from_seq}&limit=2"),
            None,
        )
        .await?;
        assert_eq!(page.status, 200);
        polled.extend(page.body["events"].as_array().test_ok()?.iter().cloned());
        let Some(next) = page.body["next_from_seq"].as_u64() else {
            break;
        };
        assert!(next > from_seq, "poll cursor must advance");
        from_seq = next;
    }
    assert_eq!(polled.len(), 8);
    Ok(polled)
}

fn assert_event_order(
    human_entity: EntityId,
    fast_entity: EntityId,
    slow_entity: EntityId,
    polled: &[Value],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    for (index, event) in polled.iter().enumerate() {
        assert_eq!(
            event["seq"].as_u64().test_ok()?,
            u64::try_from(index + 1).test_ok()?
        );
    }
    let human_seq = polled
        .iter()
        .find(|event| {
            event["event_type"] == "world.action" && event["entity"] == human_entity.to_string()
        })
        .and_then(|event| event["seq"].as_u64())
        .test_ok()?;
    let blocked_fast_seq = polled
        .iter()
        .filter(|event| {
            event["event_type"] == EVENT_TYPE_ACTION && event["entity"] == fast_entity.to_string()
        })
        .filter_map(|event| event["seq"].as_u64())
        .find(|seq| *seq > human_seq)
        .test_ok()?;
    assert!(human_seq < blocked_fast_seq);
    let agent_order = polled
        .iter()
        .filter(|event| event["event_type"] == EVENT_TYPE_ACTION)
        .map(
            |event| -> Result<_, Box<dyn std::error::Error + Send + Sync>> {
                Ok((
                    event["seq"].as_u64().test_ok()?,
                    event["entity"].as_str().test_ok()?.to_owned(),
                ))
            },
        )
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        agent_order,
        vec![
            (3, fast_entity.to_string()),
            (4, slow_entity.to_string()),
            (6, fast_entity.to_string()),
            (7, fast_entity.to_string()),
            (8, slow_entity.to_string()),
        ]
    );
    Ok(())
}

fn assert_projection_state(
    scenario: &MultiRateScenario,
    session: &pos_experiment::ExperimentSession,
) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
    let live = session.projections().test_ok()?;
    assert_eq!(
        state_u64(live, "observation", scenario.human_entity, "event_count")?,
        1
    );
    assert_eq!(
        state_u64(live, "observation", scenario.fast_entity, "event_count")?,
        4
    );
    assert_eq!(
        state_u64(live, "observation", scenario.slow_entity, "event_count")?,
        2
    );
    assert_eq!(
        state_u64(live, "society", scenario.society_entity, "signals")?,
        1
    );
    assert_eq!(
        state_u64(live, "society", scenario.fast_entity, "signals")?,
        1
    );
    assert_eq!(
        state_u64(live, "agent", scenario.fast_entity, "action_count")?,
        3
    );
    assert_eq!(
        state_u64(live, "agent", scenario.slow_entity, "action_count")?,
        2
    );
    assert_eq!(
        live.state_for_reducer("society", &scenario.society_entity)
            .and_then(|state| state.get("mean.trust"))
            .and_then(Value::as_f64),
        Some(0.75)
    );
    assert_eq!(
        live.state_for_reducer("society", &scenario.fast_entity)
            .and_then(|state| state.get("mean.trust"))
            .and_then(Value::as_f64),
        Some(0.25)
    );
    assert_eq!(
        live.state_for_reducer("observation", &scenario.fast_entity)
            .and_then(|state| state.get("last_event_type"))
            .and_then(Value::as_str),
        Some(EVENT_TYPE_ACTION)
    );
    snapshot_json(live)
}

fn assert_replay(
    scenario: &MultiRateScenario,
    live_snapshot: &Value,
    pinned_wall_time: WallTime,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let first_store = open_store(StoreConfig::Sqlite {
        path: scenario.path.clone(),
    })
    .test_ok()?;
    let stored = first_store
        .read(scenario.timeline, SeqRange::all())
        .test_ok()?;
    assert_eq!(stored.len(), 8);
    assert_eq!(stored[1].seq.as_u64(), 2);
    assert_eq!(stored[2].seq.as_u64(), 3);
    assert_eq!(stored[1].wall_time, pinned_wall_time);
    assert!(
        stored[1].wall_time > stored[2].wall_time,
        "sequence order must deliberately conflict with wall-clock order"
    );
    let mut first_replay = replay_registry();
    pos_time::replay(first_store.as_ref(), scenario.timeline, &mut first_replay).test_ok()?;
    let second_store = open_store(StoreConfig::Sqlite {
        path: scenario.path.clone(),
    })
    .test_ok()?;
    let mut second_replay = replay_registry();
    pos_time::replay(second_store.as_ref(), scenario.timeline, &mut second_replay).test_ok()?;
    assert_eq!(snapshot_json(&first_replay)?, *live_snapshot);
    assert_eq!(snapshot_json(&second_replay)?, *live_snapshot);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn multi_rate_human_ai_replay_is_deterministic() {
    let result = multi_rate_human_ai_replay_is_deterministic_impl().await;
    assert!(result.is_ok(), "multi-rate replay failed: {result:?}");
}

async fn multi_rate_human_ai_replay_is_deterministic_impl(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut scenario = create_scenario().await?;
    let experiment = register_experiment(&mut scenario)?;
    let session = experiment.resume(scenario.timeline).test_ok()?;
    let (session, pinned_wall_time) = run_tick_boundaries(&mut scenario, session).await?;
    let polled = poll_events(scenario.address, scenario.timeline).await?;
    assert_event_order(
        scenario.human_entity,
        scenario.fast_entity,
        scenario.slow_entity,
        &polled,
    )?;

    let live_snapshot = assert_projection_state(&scenario, &session)?;
    assert_eq!(*scenario.probe_log.lock().test_ok()?, vec![0, 0, 1]);
    assert_eq!(scenario.fast_decisions.load(Ordering::SeqCst), 3);
    assert_eq!(scenario.slow_decisions.load(Ordering::SeqCst), 2);
    assert_replay(&scenario, &live_snapshot, pinned_wall_time)?;
    scenario.guard.shutdown().await?;
    Ok(())
}
