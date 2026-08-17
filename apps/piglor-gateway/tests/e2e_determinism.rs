use piglor_gateway::{router, AppState, Gateway, LedgerWriteMode};
use piglor_ledger::LedgerView;
use pos_core::{Capability, EntityId, EventStore, Plugin, PluginId, TimelineId, WallTime};
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
use pos_store::{sqlite::SqliteStore, SeqRange, StoreConfig};
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
        let mut log = self.log.lock().expect("probe log lock is healthy");
        if log.len() < 3 {
            log.push(count);
        }
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
            self.snapshot_ready
                .take()
                .expect("fast policy signals readiness once")
                .send(())
                .expect("snapshot readiness receiver is alive");
            self.release
                .lock()
                .expect("policy release lock is healthy")
                .recv()
                .expect("policy release sender is alive");
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
) -> HttpResponse {
    let method = method.to_owned();
    let path = path.to_owned();
    tokio::task::spawn_blocking(move || request_http_blocking(address, &method, &path, body))
        .await
        .expect("HTTP helper joins")
}

fn request_http_blocking(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> HttpResponse {
    let payload = body.map_or_else(Vec::new, |value| {
        serde_json::to_vec(&value).expect("JSON request serialization succeeds")
    });
    let mut stream = TcpStream::connect(address).expect("Gateway TCP listener accepts requests");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout is configured");
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .expect("write timeout is configured");
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: {address}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        payload.len()
    )
    .expect("HTTP request headers are written");
    stream
        .write_all(&payload)
        .expect("HTTP request body is written");
    stream.flush().expect("HTTP request is flushed");

    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .expect("complete HTTP response is read");
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("HTTP response contains a header terminator");
    let headers = std::str::from_utf8(&response[..header_end]).expect("HTTP headers are UTF-8");
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .expect("HTTP response contains a numeric status");
    let body = serde_json::from_slice(&response[header_end + 4..])
        .expect("HTTP response contains a JSON body");
    HttpResponse { status, body }
}

struct FixtureGuard {
    policy_release: Option<mpsc::Sender<()>>,
    server_shutdown: Option<oneshot::Sender<()>>,
    server: Option<JoinHandle<std::io::Result<()>>>,
}

impl FixtureGuard {
    fn release_policy(&mut self) {
        if let Some(release) = self.policy_release.take() {
            let _ = release.send(());
        }
    }

    async fn shutdown(mut self) {
        self.release_policy();
        if let Some(shutdown) = self.server_shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(mut server) = self.server.take() {
            match tokio::time::timeout(Duration::from_secs(5), &mut server).await {
                Ok(joined) => joined
                    .expect("Gateway server task joins")
                    .expect("Gateway server shuts down cleanly"),
                Err(_) => {
                    server.abort();
                    let _ = server.await;
                    panic!("Gateway server did not shut down within five seconds");
                }
            }
        }
    }
}

impl Drop for FixtureGuard {
    fn drop(&mut self) {
        self.release_policy();
        if let Some(shutdown) = self.server_shutdown.take() {
            let _ = shutdown.send(());
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

fn snapshot_json(registry: &ProjectionRegistry) -> Value {
    serde_json::to_value(registry.state_snapshot()).expect("projection state serializes")
}

fn state_u64(registry: &ProjectionRegistry, reducer: &str, entity: EntityId, key: &str) -> u64 {
    registry
        .state_for_reducer(reducer, &entity)
        .and_then(|state| state.get(key))
        .and_then(Value::as_u64)
        .expect("expected integer projection field exists")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn multi_rate_human_ai_replay_is_deterministic() {
    let database = tempfile::NamedTempFile::new().expect("temporary SQLite file is created");
    let path = database
        .path()
        .to_str()
        .expect("database path is UTF-8")
        .to_owned();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback listener binds");
    let address = listener
        .local_addr()
        .expect("listener address is available");
    let gateway = Gateway::new(Box::new(
        SqliteStore::open(&path).expect("Gateway SQLite connection opens"),
    ));
    let state = AppState {
        gateway,
        ledger_view: LedgerView::default(),
        ledger_write: LedgerWriteMode::Disabled,
    };
    let (server_shutdown, shutdown_rx) = oneshot::channel();
    let server = tokio::spawn(async move {
        axum::serve(listener, router(state))
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await
    });
    let (snapshot_ready, ready_rx) = mpsc::channel();
    let (policy_release, release_rx) = mpsc::channel();
    let mut guard = FixtureGuard {
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
    .await;
    assert_eq!(created.status, 201);
    let timeline_text = created.body["id"]
        .as_str()
        .expect("created Timeline response has id");
    let timeline =
        TimelineId::from_ulid(ulid::Ulid::from_string(timeline_text).expect("Timeline id parses"));
    let society_entity = EntityId::new();
    let human_entity = EntityId::new();
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
    .await;
    assert_eq!(signal.status, 201);

    let fast_decisions = Arc::new(AtomicUsize::new(0));
    let slow_decisions = Arc::new(AtomicUsize::new(0));
    let probe_log = Arc::new(Mutex::new(Vec::new()));
    let observation = FixturePlugin::new("observation", false, true);
    let society = SocietyPlugin::new();
    let fast = AgentPlugin::new();
    let probe = FixturePlugin::new("observation-probe", true, false);
    let slow = AgentPlugin::new();
    let mut experiment = Experiment::new(ExperimentConfig {
        name: "multi-rate-host".to_owned(),
        stop: StopCondition::MaxTicks(10),
        store_config: StoreConfig::Sqlite { path: path.clone() },
    });
    experiment
        .register(&observation, Some(Box::new(EntityStateProjection)), None)
        .expect("observation reducer registers");
    experiment
        .register(&society, Some(Box::new(SocietyReducer)), None)
        .expect("Society reducer registers");
    experiment
        .register(
            &fast,
            Some(Box::new(AgentReducer)),
            Some(Box::new(AgentDriver::new(
                fast_entity,
                Box::new(BarrierPolicy {
                    inner: RoundRobinPolicy::new(vec!["fast".to_owned()]),
                    decisions: Arc::clone(&fast_decisions),
                    snapshot_ready: Some(snapshot_ready),
                    release: Mutex::new(release_rx),
                }),
                vec!["fast".to_owned()],
            ))),
        )
        .expect("fast Agent registers");
    experiment
        .register(
            &probe,
            None,
            Some(Box::new(ObservationProbeDriver {
                subscriptions: vec![ProjectionKey::new(human_entity)],
                log: Arc::clone(&probe_log),
            })),
        )
        .expect("observation probe registers");
    experiment
        .register(
            &slow,
            Some(Box::new(AgentReducer)),
            Some(Box::new(
                AgentDriver::new(
                    slow_entity,
                    Box::new(CountingPolicy {
                        inner: RoundRobinPolicy::new(vec!["slow".to_owned()]),
                        decisions: Arc::clone(&slow_decisions),
                    }),
                    vec!["slow".to_owned()],
                )
                .with_tick_interval(Duration::from_millis(200)),
            )),
        )
        .expect("slow Agent registers");

    let mut session = experiment
        .resume(timeline)
        .expect("Experiment opens a second SQLite connection");
    let pinned_wall_time = WallTime::from_micros(
        u64::try_from(i64::MAX).expect("positive SQLite integer limit fits u64"),
    );
    let mut pending_store =
        SqliteStore::open(&path).expect("pending-ingress SQLite connection opens");
    let pending = pending_store
        .append(
            timeline,
            &[draft_signal(
                fast_entity,
                &SocietySignal {
                    dimension: SocietyDimension::Trust,
                    value: 0.25,
                    subject: None,
                    object: None,
                },
            )
            .with_wall_time(pinned_wall_time)],
        )
        .expect("externally pending signal commits through EventStore");
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].seq.as_u64(), 2);
    drop(pending_store);
    assert_eq!(
        session
            .step_cadenced(0)
            .expect("zero-time boundary succeeds"),
        TickOutcome::Advanced {
            folded_events: 3,
            emitted_events: 2,
        }
    );
    let session_task = tokio::task::spawn_blocking(move || {
        let result = session.step_cadenced(100_000_000);
        (session, result)
    });
    tokio::task::spawn_blocking(move || {
        ready_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("fast policy reaches the immutable-snapshot barrier");
    })
    .await
    .expect("snapshot readiness wait joins");
    let human = request_http(
        address,
        "POST",
        &format!("/v1/timelines/{timeline}/actions"),
        Some(json!({
            "entity_id": human_entity.to_string(),
            "event_type": "world.action",
            "payload": {"command": "intervene"},
        })),
    )
    .await;
    assert_eq!(human.status, 201);
    guard.release_policy();
    let (mut session, middle) = session_task.await.expect("cadenced session task joins");
    assert_eq!(
        middle.expect("100 ms boundary succeeds"),
        TickOutcome::Advanced {
            folded_events: 2,
            emitted_events: 1,
        }
    );
    assert_eq!(
        session
            .step_cadenced(200_000_000)
            .expect("200 ms boundary succeeds"),
        TickOutcome::Advanced {
            folded_events: 2,
            emitted_events: 2,
        }
    );

    assert_eq!(
        *probe_log.lock().expect("probe log lock is healthy"),
        vec![0, 0, 1]
    );
    assert_eq!(fast_decisions.load(Ordering::SeqCst), 3);
    assert_eq!(slow_decisions.load(Ordering::SeqCst), 2);

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
        .await;
        assert_eq!(page.status, 200);
        polled.extend(
            page.body["events"]
                .as_array()
                .expect("event page contains an array")
                .iter()
                .cloned(),
        );
        let Some(next) = page.body["next_from_seq"].as_u64() else {
            break;
        };
        assert!(next > from_seq, "poll cursor must advance");
        from_seq = next;
    }
    assert_eq!(polled.len(), 8);
    for (index, event) in polled.iter().enumerate() {
        assert_eq!(
            event["seq"].as_u64().expect("event sequence is numeric"),
            u64::try_from(index + 1).expect("fixture sequence fits u64")
        );
    }
    let human_seq = polled
        .iter()
        .find(|event| {
            event["event_type"] == "world.action" && event["entity"] == human_entity.to_string()
        })
        .and_then(|event| event["seq"].as_u64())
        .expect("human action is present");
    let blocked_fast_seq = polled
        .iter()
        .filter(|event| {
            event["event_type"] == EVENT_TYPE_ACTION && event["entity"] == fast_entity.to_string()
        })
        .filter_map(|event| event["seq"].as_u64())
        .find(|seq| *seq > human_seq)
        .expect("blocked fast action follows human ingress");
    assert!(human_seq < blocked_fast_seq);
    let agent_order = polled
        .iter()
        .filter(|event| event["event_type"] == EVENT_TYPE_ACTION)
        .map(|event| {
            (
                event["seq"].as_u64().expect("agent sequence is numeric"),
                event["entity"]
                    .as_str()
                    .expect("agent entity is a string")
                    .to_owned(),
            )
        })
        .collect::<Vec<_>>();
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

    let live = session.projections().expect("live session is healthy");
    assert_eq!(
        state_u64(live, "observation", human_entity, "event_count"),
        1
    );
    assert_eq!(
        state_u64(live, "observation", fast_entity, "event_count"),
        4
    );
    assert_eq!(
        state_u64(live, "observation", slow_entity, "event_count"),
        2
    );
    assert_eq!(state_u64(live, "society", society_entity, "signals"), 1);
    assert_eq!(state_u64(live, "society", fast_entity, "signals"), 1);
    assert_eq!(state_u64(live, "agent", fast_entity, "action_count"), 3);
    assert_eq!(state_u64(live, "agent", slow_entity, "action_count"), 2);
    assert_eq!(
        live.state_for_reducer("society", &society_entity)
            .and_then(|state| state.get("mean.trust"))
            .and_then(Value::as_f64),
        Some(0.75)
    );
    assert_eq!(
        live.state_for_reducer("society", &fast_entity)
            .and_then(|state| state.get("mean.trust"))
            .and_then(Value::as_f64),
        Some(0.25)
    );
    assert_eq!(
        live.state_for_reducer("observation", &fast_entity)
            .and_then(|state| state.get("last_event_type"))
            .and_then(Value::as_str),
        Some(EVENT_TYPE_ACTION)
    );
    let live_snapshot = snapshot_json(live);

    let first_store = SqliteStore::open(&path).expect("first replay connection opens");
    let stored = first_store
        .read(timeline, SeqRange::all())
        .expect("sequence-ordered history reads");
    assert_eq!(stored.len(), 8);
    assert_eq!(stored[1].seq.as_u64(), 2);
    assert_eq!(stored[2].seq.as_u64(), 3);
    assert_eq!(stored[1].wall_time, pinned_wall_time);
    assert!(
        stored[1].wall_time > stored[2].wall_time,
        "sequence order must deliberately conflict with wall-clock order"
    );
    let mut first_replay = replay_registry();
    pos_time::replay(&first_store, timeline, &mut first_replay).expect("first replay succeeds");
    let second_store = SqliteStore::open(&path).expect("second replay connection opens");
    let mut second_replay = replay_registry();
    pos_time::replay(&second_store, timeline, &mut second_replay).expect("second replay succeeds");
    assert_eq!(snapshot_json(&first_replay), live_snapshot);
    assert_eq!(snapshot_json(&second_replay), live_snapshot);

    guard.shutdown().await;
}
