use crate::{
    gateway_with_erasure_host_and_authorization, router, AppState, Gateway, GatewayAuthorization,
    LedgerWriteMode, LocalAuthenticationAdapter,
};
use piglor_ledger::LedgerView;
use pos_core::{
    AssuranceLevelV1, AuthenticatedPrincipalDraftV1, AuthenticatedPrincipalResultV1,
    AuthorityGranteeV1, AuthorityPersistenceHostV1, AuthorityPersistenceStateV1,
    AuthorityRegistrySnapshotV1, AuthorityRoleV1, CanonicalBytes, Capability,
    CapabilityGrantDraftV1, CapabilityGrantV1, CapabilityScopeDraftV1, CapabilityScopeV1,
    ConsentAuthority, ConsentGrantedV1, EntityId, ErasureContainmentGateV1, Event, EventDraft,
    Hash, Kind, Plugin, PluginId, PrincipalRefV1, Seq, TimelineId, WallTime,
};
use pos_experiment::{Experiment, ExperimentConfig, StopCondition, TickOutcome};
use pos_plugin_agent::{
    AgentAction, AgentContext, AgentDriver, AgentPlugin, AgentPolicy, AgentReducer,
    RoundRobinPolicy, EVENT_TYPE_ACTION,
};
use pos_plugin_society::{
    draft_signal, SocietyDimension, SocietyPlugin, SocietyReducer, SocietySignal,
};
use pos_plugin_world::{encode_actuator_pair_v1, ActionKindV1, WorldActionV1};
use pos_runtime::{
    Driver, ErasureExecutionHostV1, InstalledOutputPolicySourceV1, ObservationView,
    OutputPolicyBindingV1, ProjectionKey, RuntimeError, StepOutput,
};
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
    owned_event_types: Vec<Kind>,
}

impl FixturePlugin {
    fn new(name: &'static str, has_driver: bool, has_reducer: bool) -> Self {
        Self {
            id: PluginId::new(),
            name,
            has_driver,
            has_reducer,
            owned_event_types: Vec::new(),
        }
    }

    fn with_owned_event_type(mut self, event_type: Kind) -> Self {
        self.owned_event_types.push(event_type);
        self
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
            owned_event_types: self.owned_event_types.clone(),
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

fn agent_output_binding(
    plugin: &AgentPlugin,
) -> Result<OutputPolicyBindingV1, Box<dyn std::error::Error + Send + Sync>> {
    Ok(OutputPolicyBindingV1::from_installed_source(
        plugin,
        InstalledOutputPolicySourceV1::Generated,
        &[],
        "deterministic-local-v1",
    )?)
}

fn owned_event_type_binding<P: Plugin>(
    plugin: &P,
) -> Result<OutputPolicyBindingV1, Box<dyn std::error::Error + Send + Sync>> {
    Ok(OutputPolicyBindingV1::from_installed_source(
        plugin,
        InstalledOutputPolicySourceV1::Generated,
        &[],
        "deterministic-local-v1",
    )?)
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

struct HumanActionDriver {
    entity: EntityId,
    payload: CanonicalBytes,
    steps: u8,
}

impl Driver for HumanActionDriver {
    fn name(&self) -> &'static str {
        "human-action"
    }

    fn step(
        &mut self,
        _timeline: TimelineId,
        _observations: ObservationView<'_>,
    ) -> Result<StepOutput, RuntimeError> {
        let emit = self.steps == 1;
        self.steps = self.steps.saturating_add(1);
        if emit {
            Ok(StepOutput::new(vec![EventDraft::new(
                self.entity,
                Kind::new("world.action.v1"),
                self.payload.clone(),
            )]))
        } else {
            Ok(StepOutput::empty())
        }
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
    request_http_with_actor(address, method, path, body, None).await
}

async fn request_http_with_actor(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: Option<Value>,
    actor: Option<EntityId>,
) -> Result<HttpResponse, Box<dyn std::error::Error + Send + Sync>> {
    let method = method.to_owned();
    let path = path.to_owned();
    tokio::task::spawn_blocking(move || {
        request_http_blocking_with_actor(address, &method, &path, body, actor)
    })
    .await
    .test_ok()?
}

fn request_http_blocking_with_actor(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: Option<Value>,
    actor: Option<EntityId>,
) -> Result<HttpResponse, Box<dyn std::error::Error + Send + Sync>> {
    let payload = body
        .map_or_else(|| Ok(Vec::new()), |value| serde_json::to_vec(&value))
        .test_ok()?;
    let actor_header = actor.map_or_else(String::new, |actor| {
        format!("x-piglor-actor-entity: {actor}\r\n")
    });
    let mut stream = TcpStream::connect(address).test_ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .test_ok()?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .test_ok()?;
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: {address}\r\n{actor_header}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
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
    let mut registry = ProjectionRegistry::new()
        .with_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()));
    registry.register("observation", Box::new(EntityStateProjection));
    registry.register("society", Box::new(SocietyReducer));
    registry.register("agent", Box::new(AgentReducer));
    registry
}

fn snapshot_json(
    registry: &ProjectionRegistry,
    timeline: TimelineId,
) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
    serde_json::to_value(registry.state_snapshot(timeline).test_ok()?).test_ok()
}

fn state_u64(
    state: &pos_core::State,
    key: &str,
) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
    state.get(key).and_then(Value::as_u64).test_ok()
}

fn gateway_authorization_for(
    actor: EntityId,
) -> Result<GatewayAuthorization, Box<dyn std::error::Error + Send + Sync>> {
    let principal = PrincipalRefV1::try_new([1; 16], "gateway.test").test_ok()?;
    let authenticated =
        AuthenticatedPrincipalResultV1::try_from_draft(AuthenticatedPrincipalDraftV1 {
            principal: principal.clone(),
            adapter_id: "fixture".to_owned(),
            assurance: AssuranceLevelV1::try_new(1).test_ok()?,
            issued_at: WallTime::from_micros(1),
            expires_at: WallTime::from_micros(u64::MAX),
            binding_digest: Hash::from_bytes([2; 32]),
        })
        .test_ok()?;
    let authority_timeline = TimelineId::new();
    let registry_digest = Hash::from_bytes([3; 32]);
    let policy_revision = Hash::from_bytes([4; 32]);
    let scope = CapabilityScopeV1::try_from_draft(CapabilityScopeDraftV1 {
        resources: vec!["timeline.events".to_owned(), "world.action.v1".to_owned()],
        actions: vec!["read".to_owned(), "world.action.v1.submit".to_owned()],
        purposes: vec!["action".to_owned(), "read".to_owned()],
        audiences: vec!["gateway".to_owned()],
        actor_entity_ids: vec![actor],
        subject_ids: Vec::new(),
        participant_ids: Vec::new(),
        plugin_id: None,
        principal_roles: vec![AuthorityRoleV1::Actor],
        max_uses: 1,
        budget: 1,
        environment_constraints: Vec::new(),
    })
    .test_ok()?;
    let grant = CapabilityGrantV1::try_from_draft(CapabilityGrantDraftV1 {
        grant_id: Hash::from_bytes([5; 32]),
        grantor: principal.clone(),
        grantee: AuthorityGranteeV1::Principal(principal),
        trust_domain: "gateway.test".to_owned(),
        scope,
        valid_from_position: Seq::from_u64(1),
        valid_until_position: Seq::from_u64(50),
        parent_grant_id: None,
        delegation_depth: 0,
        max_delegation_depth: 0,
        permitted_delegate_classes: Vec::new(),
        consent_references: Vec::new(),
        policy_revision,
        issuance_timeline: authority_timeline,
        issuance_seq: Seq::from_u64(1),
        revocation_epoch: 0,
        revocation_fence: None,
        authority_registry_digest: registry_digest,
    })
    .test_ok()?;
    let registry = AuthorityRegistrySnapshotV1::try_new(
        registry_digest,
        vec![authenticated.registry_binding_digest()],
        vec![grant.binding_digest().test_ok()?],
        Vec::new(),
    )
    .test_ok()?;
    let host = AuthorityPersistenceHostV1::new(&registry);
    let mut state = AuthorityPersistenceStateV1::new();
    state
        .issue_grant(host.authorize_grant(&grant).test_ok()?, grant.clone())
        .test_ok()?;
    let authority = state.view(grant.grant_id()).test_ok()?;
    Ok(GatewayAuthorization::new(
        Arc::new(LocalAuthenticationAdapter::new(authenticated)),
        authority,
        registry,
    ))
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
    pinned_wall_time: WallTime,
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
    let society_entity = EntityId::new();
    let fast_entity = EntityId::new();
    let slow_entity = EntityId::new();
    let pinned_wall_time = WallTime::from_micros(u64::try_from(i64::MAX).test_ok()?);
    let mut host = ErasureExecutionHostV1::open_verified_empty(
        StoreConfig::Sqlite { path: path.clone() },
        pos_core::ErasureRecoveryLimitsV1::compiled_maximum(),
    )
    .test_ok()?;
    let timeline = {
        let mut sender = host.command_sender().test_ok()?;
        let timeline = sender.create_timeline("multi-rate-e2e").test_ok()?;
        let first = draft_signal(
            society_entity,
            &SocietySignal {
                dimension: SocietyDimension::Trust,
                value: 0.75,
                subject: None,
                object: None,
            },
        );
        let pending = draft_signal(
            fast_entity,
            &SocietySignal {
                dimension: SocietyDimension::Trust,
                value: 0.25,
                subject: None,
                object: None,
            },
        )
        .with_wall_time(pinned_wall_time);
        let seeded = sender.append(timeline.id(), &[first, pending]).test_ok()?;
        assert_eq!(seeded.len(), 2);
        assert_eq!(seeded[1].seq.as_u64(), 2);
        timeline.id()
    };
    let state = AppState {
        gateway: gateway_with_erasure_host_and_authorization(
            host,
            [human_body],
            gateway_authorization_for(human_entity)?,
        )?,
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
        pinned_wall_time,
        fast_decisions: Arc::new(AtomicUsize::new(0)),
        slow_decisions: Arc::new(AtomicUsize::new(0)),
        probe_log: Arc::new(Mutex::new(Vec::new())),
        snapshot_ready: Some(snapshot_ready),
        ready_rx: Some(ready_rx),
        release_rx: Some(release_rx),
        guard,
    })
}

fn human_action_payload(
    scenario: &MultiRateScenario,
) -> Result<CanonicalBytes, Box<dyn std::error::Error + Send + Sync>> {
    WorldActionV1 {
        actor_entity_id: scenario.human_entity,
        body_entity_id: scenario.human_body,
        action_kind: ActionKindV1::Impulse,
        params_cbor: encode_actuator_pair_v1(1.0, 0.0).test_ok()?,
        action_scope: 0,
        catalogue_version: 1,
        tick: 1,
    }
    .encode()
    .test_ok()
}

fn register_reducer_plugins(
    experiment: &mut Experiment,
    observation: &FixturePlugin,
    society: &SocietyPlugin,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let observation_binding = owned_event_type_binding(observation)?;
    let society_binding = owned_event_type_binding(society)?;
    experiment
        .register_with_verified_output_policy(
            observation,
            observation_binding,
            Some(Box::new(EntityStateProjection)),
            None,
        )
        .test_ok()?;
    experiment
        .register_with_verified_output_policy(
            society,
            society_binding,
            Some(Box::new(SocietyReducer)),
            None,
        )
        .test_ok()?;
    Ok(())
}

fn register_probe(
    experiment: &mut Experiment,
    scenario: &MultiRateScenario,
    probe: &FixturePlugin,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    experiment
        .register_with_verified_output_policy(
            probe,
            owned_event_type_binding(probe)?,
            None,
            Some(Box::new(ObservationProbeDriver {
                subscriptions: vec![ProjectionKey::new(scenario.human_entity)],
                log: Arc::clone(&scenario.probe_log),
            })),
        )
        .test_ok()?;
    Ok(())
}

fn register_experiment(
    scenario: &mut MultiRateScenario,
) -> Result<
    (
        Experiment,
        pos_core::ConsentCapabilityToken,
        ConsentAuthority,
    ),
    Box<dyn std::error::Error + Send + Sync>,
> {
    let observation = FixturePlugin::new("observation", false, true);
    let society = SocietyPlugin::new();
    let human = FixturePlugin::new("human-action", true, false)
        .with_owned_event_type(Kind::new("world.action.v1"));
    let human_action = human_action_payload(scenario)?;
    let fast = AgentPlugin::new();
    let probe = FixturePlugin::new("observation-probe", true, false);
    let slow = AgentPlugin::new();
    let human_binding = owned_event_type_binding(&human)?;
    let fast_binding = agent_output_binding(&fast)?;
    let slow_binding = agent_output_binding(&slow)?;
    let mut experiment = Experiment::new(ExperimentConfig {
        name: "multi-rate-host".to_owned(),
        stop: StopCondition::MaxTicks(10),
        store_config: StoreConfig::Sqlite {
            path: scenario.path.clone(),
        },
    });
    register_reducer_plugins(&mut experiment, &observation, &society)?;
    experiment
        .register_with_verified_output_policy(
            &human,
            human_binding,
            None,
            Some(Box::new(HumanActionDriver {
                entity: scenario.human_entity,
                payload: human_action,
                steps: 0,
            })),
        )
        .test_ok()?;
    experiment
        .register_with_verified_output_policy(
            &fast,
            fast_binding,
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
    register_probe(&mut experiment, scenario, &probe)?;
    experiment
        .register_with_verified_output_policy(
            &slow,
            slow_binding,
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
    let authority = ConsentAuthority::new();
    let grant = ConsentGrantedV1 {
        subject_id: scenario.human_entity,
        grantee_id: EntityId::new(),
        purpose: "multi-rate-projection-observation".to_owned(),
        modalities: 0,
        min_geo_resolution: 0,
        fork_permitted: false,
        export_permitted: false,
        retention_days: 0,
        expiry_secs: 0,
        grant_seq: 1,
    };
    let token = authority.record_grant_on_timeline(scenario.timeline, &grant);
    Ok((
        experiment.with_consent_authority(authority.clone()),
        token,
        authority,
    ))
}

async fn run_tick_boundaries(
    scenario: &mut MultiRateScenario,
    mut session: pos_experiment::ExperimentSession,
) -> Result<(pos_experiment::ExperimentSession, WallTime), Box<dyn std::error::Error + Send + Sync>>
{
    assert_eq!(
        session
            .step_cadenced(0)
            .test_ok()
            .map_err(|error| std::io::Error::other(format!("first tick: {error}")))?,
        TickOutcome::Advanced {
            folded_events: 2,
            emitted_events: 2,
        }
    );
    // The Experiment host has committed since the Gateway host opened. Its
    // independent protected append must fail closed; the HumanActionDriver
    // emits the simulated human Event inside the Experiment host instead.
    let human = request_http(
        scenario.address,
        "POST",
        &format!("/v1/timelines/{}/actions", scenario.timeline),
        Some(json!({
            "entity_id": scenario.human_entity.to_string(),
            "event_type": "world.action.v1",
            "capability": "world.action.v1.submit",
            "payload": {
                "actor_entity_id": scenario.human_entity.to_string(),
                "body_entity_id": scenario.human_body.to_string(),
                "action_kind": "impulse",
                "params": [1.0, 0.0],
                "action_scope": 0,
                "catalogue_version": 1,
                "tick": 1
            },
        })),
    )
    .await
    .map_err(|error| std::io::Error::other(format!("human action request: {error}")))?;
    assert_eq!(human.status, 503);
    let session_task = tokio::task::spawn_blocking(move || {
        let result = session.step_cadenced(100_000_000);
        (session, result)
    });
    let ready_rx = scenario.ready_rx.take().test_ok()?;
    tokio::task::spawn_blocking(move || ready_rx.recv_timeout(Duration::from_secs(5)).test_ok())
        .await
        .test_ok()
        .map_err(|error| std::io::Error::other(format!("readiness join: {error}")))?
        .map_err(|error| std::io::Error::other(format!("readiness receive: {error}")))?;
    scenario.guard.release_policy();
    let (mut session, boundary_at_100_ms) = session_task
        .await
        .test_ok()
        .map_err(|error| std::io::Error::other(format!("second tick join: {error}")))?;
    assert_eq!(
        boundary_at_100_ms
            .test_ok()
            .map_err(|error| std::io::Error::other(format!("second tick: {error}")))?,
        TickOutcome::Advanced {
            folded_events: 2,
            emitted_events: 2,
        }
    );
    assert_eq!(
        session
            .step_cadenced(200_000_000)
            .test_ok()
            .map_err(|error| std::io::Error::other(format!("third tick: {error}")))?,
        TickOutcome::Advanced {
            folded_events: 2,
            emitted_events: 2,
        }
    );
    Ok((session, scenario.pinned_wall_time))
}

async fn read_session_events_after_gateway_fail_closed(
    address: SocketAddr,
    timeline: TimelineId,
    actor: EntityId,
    session: &pos_experiment::ExperimentSession,
) -> Result<Vec<Event>, Box<dyn std::error::Error + Send + Sync>> {
    let page = request_http_with_actor(
        address,
        "GET",
        &format!("/v1/timelines/{timeline}/events?from_seq=0&limit=2"),
        None,
        Some(actor),
    )
    .await?;
    assert_eq!(page.status, 503);
    let events = session.source_events().test_ok()?;
    assert_eq!(events.len(), 8);
    Ok(events)
}

fn assert_event_order(
    human_entity: EntityId,
    fast_entity: EntityId,
    slow_entity: EntityId,
    events: &[Event],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    for (index, event) in events.iter().enumerate() {
        assert_eq!(event.seq.as_u64(), u64::try_from(index + 1).test_ok()?);
    }
    let human_seq = events
        .iter()
        .find(|event| {
            event.event_type.as_str() == "world.action.v1" && event.entity == human_entity
        })
        .map(|event| event.seq.as_u64())
        .test_ok()?;
    let blocked_fast_seq = events
        .iter()
        .filter(|event| {
            event.event_type.as_str() == EVENT_TYPE_ACTION && event.entity == fast_entity
        })
        .map(|event| event.seq.as_u64())
        .find(|seq| *seq > human_seq)
        .test_ok()?;
    assert!(human_seq < blocked_fast_seq);
    let agent_order = events
        .iter()
        .filter(|event| event.event_type.as_str() == EVENT_TYPE_ACTION)
        .map(|event| (event.seq.as_u64(), event.entity.to_string()))
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
    Ok(())
}

type LiveProjectionState = (&'static str, EntityId, pos_core::State);

fn assert_projection_state(
    scenario: &MultiRateScenario,
    session: &pos_experiment::ExperimentSession,
    authority: &ConsentAuthority,
) -> Result<Vec<LiveProjectionState>, Box<dyn std::error::Error + Send + Sync>> {
    let read_state = |reducer: &str, subject: EntityId| {
        let token = authority.record_grant_on_timeline(
            scenario.timeline,
            &ConsentGrantedV1 {
                subject_id: subject,
                grantee_id: EntityId::new(),
                purpose: "multi-rate-projection-read".to_owned(),
                modalities: 0,
                min_geo_resolution: 0,
                fork_permitted: false,
                export_permitted: false,
                retention_days: 0,
                expiry_secs: 0,
                grant_seq: 2,
            },
        );
        session
            .projection_state_for_reducer(reducer, subject, &token, 0)
            .test_ok()?
            .test_ok()
    };
    let observation_human = read_state("observation", scenario.human_entity)?;
    let observation_fast = read_state("observation", scenario.fast_entity)?;
    let observation_slow = read_state("observation", scenario.slow_entity)?;
    let society = read_state("society", scenario.society_entity)?;
    let society_fast = read_state("society", scenario.fast_entity)?;
    let agent_fast = read_state("agent", scenario.fast_entity)?;
    let agent_slow = read_state("agent", scenario.slow_entity)?;
    assert_eq!(state_u64(&observation_human, "event_count")?, 1);
    assert_eq!(state_u64(&observation_fast, "event_count")?, 4);
    assert_eq!(state_u64(&observation_slow, "event_count")?, 2);
    assert_eq!(state_u64(&society, "signals")?, 1);
    assert_eq!(state_u64(&society_fast, "signals")?, 1);
    assert_eq!(state_u64(&agent_fast, "action_count")?, 3);
    assert_eq!(state_u64(&agent_slow, "action_count")?, 2);
    assert_eq!(
        society.get("mean.trust").and_then(Value::as_f64),
        Some(0.75)
    );
    assert_eq!(
        society_fast.get("mean.trust").and_then(Value::as_f64),
        Some(0.25)
    );
    assert_eq!(
        observation_fast
            .get("last_event_type")
            .and_then(Value::as_str),
        Some(EVENT_TYPE_ACTION)
    );
    Ok(vec![
        ("observation", scenario.human_entity, observation_human),
        ("observation", scenario.fast_entity, observation_fast),
        ("observation", scenario.slow_entity, observation_slow),
        ("society", scenario.society_entity, society),
        ("society", scenario.fast_entity, society_fast),
        ("agent", scenario.fast_entity, agent_fast),
        ("agent", scenario.slow_entity, agent_slow),
    ])
}

fn assert_replay(
    scenario: &MultiRateScenario,
    live_states: &[LiveProjectionState],
    pinned_wall_time: WallTime,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let first_store = open_store(StoreConfig::Sqlite {
        path: scenario.path.clone(),
    })
    .test_ok()?;
    let mut first_store = first_store;
    first_store
        .bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))
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
    first_replay.fold_events(scenario.timeline, &stored);
    let replayed_states = first_replay.state_snapshot(scenario.timeline).test_ok()?;
    for (reducer, entity, live_state) in live_states {
        let replayed_state = replayed_states
            .get(*reducer)
            .and_then(|states| states.get(entity))
            .test_ok()?;
        assert_eq!(replayed_state, live_state, "{reducer} live/replay mismatch");
    }
    let second_store = open_store(StoreConfig::Sqlite {
        path: scenario.path.clone(),
    })
    .test_ok()?;
    let mut second_store = second_store;
    second_store
        .bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))
        .test_ok()?;
    let mut second_replay = replay_registry();
    let second_events = second_store
        .read(scenario.timeline, SeqRange::all())
        .test_ok()?;
    second_replay.fold_events(scenario.timeline, &second_events);
    assert_eq!(
        snapshot_json(&second_replay, scenario.timeline)?,
        snapshot_json(&first_replay, scenario.timeline)?
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn multi_rate_simulated_human_and_ai_replay_is_deterministic() {
    let result = multi_rate_simulated_human_and_ai_replay_is_deterministic_impl().await;
    assert!(result.is_ok(), "multi-rate replay failed: {result:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn host_backed_http_action_and_poll_succeed_without_a_competing_writer(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let scenario = create_scenario().await?;
    let action = request_http(
        scenario.address,
        "POST",
        &format!("/v1/timelines/{}/actions", scenario.timeline),
        Some(json!({
            "entity_id": scenario.human_entity.to_string(),
            "event_type": "world.action.v1",
            "capability": "world.action.v1.submit",
            "payload": {
                "actor_entity_id": scenario.human_entity.to_string(),
                "body_entity_id": scenario.human_body.to_string(),
                "action_kind": "impulse",
                "params": [1.0, 0.0],
                "action_scope": 0,
                "catalogue_version": 1,
                "tick": 1
            },
        })),
    )
    .await?;
    assert_eq!(action.status, 201);
    let page = request_http_with_actor(
        scenario.address,
        "GET",
        &format!(
            "/v1/timelines/{}/events?from_seq=0&limit=10",
            scenario.timeline
        ),
        None,
        Some(scenario.human_entity),
    )
    .await?;
    assert_eq!(page.status, 200);
    let events = page.body["events"].as_array().test_ok()?;
    assert_eq!(events.len(), 3);
    assert_eq!(events[2]["event_type"], "world.action.v1");
    scenario.guard.shutdown().await?;
    Ok(())
}

async fn multi_rate_simulated_human_and_ai_replay_is_deterministic_impl(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut scenario =
        create_scenario()
            .await
            .map_err(|error| -> Box<dyn std::error::Error + Send + Sync> {
                format!("create_scenario: {error}").into()
            })?;
    let (experiment, token, authority) = register_experiment(&mut scenario).map_err(
        |error| -> Box<dyn std::error::Error + Send + Sync> {
            format!("register_experiment: {error}").into()
        },
    )?;
    let session = experiment
        .resume(scenario.timeline)
        .test_ok()
        .map_err(|error| -> Box<dyn std::error::Error + Send + Sync> {
            format!("resume: {error}").into()
        })?
        .with_protected_token(token.clone());
    let (session, pinned_wall_time) = run_tick_boundaries(&mut scenario, session).await.map_err(
        |error| -> Box<dyn std::error::Error + Send + Sync> {
            format!("run_tick_boundaries: {error}").into()
        },
    )?;
    let events = read_session_events_after_gateway_fail_closed(
        scenario.address,
        scenario.timeline,
        scenario.human_entity,
        &session,
    )
    .await
    .map_err(|error| -> Box<dyn std::error::Error + Send + Sync> {
        format!("read_session_events_after_gateway_fail_closed: {error}").into()
    })?;
    assert_event_order(
        scenario.human_entity,
        scenario.fast_entity,
        scenario.slow_entity,
        &events,
    )?;

    let live_states = assert_projection_state(&scenario, &session, &authority).map_err(
        |error| -> Box<dyn std::error::Error + Send + Sync> {
            format!("assert_projection_state: {error}").into()
        },
    )?;
    assert_eq!(*scenario.probe_log.lock().test_ok()?, vec![0, 0, 1]);
    assert_eq!(scenario.fast_decisions.load(Ordering::SeqCst), 3);
    assert_eq!(scenario.slow_decisions.load(Ordering::SeqCst), 2);
    assert_replay(&scenario, &live_states, pinned_wall_time).map_err(
        |error| -> Box<dyn std::error::Error + Send + Sync> {
            format!("assert_replay: {error}").into()
        },
    )?;
    scenario.guard.shutdown().await.map_err(
        |error| -> Box<dyn std::error::Error + Send + Sync> { format!("shutdown: {error}").into() },
    )?;
    assert_recovered_http_events(
        &scenario.path,
        scenario.timeline,
        scenario.human_body,
        scenario.human_entity,
        &events,
    )
    .await?;
    Ok(())
}

async fn assert_recovered_http_events(
    path: &str,
    timeline: TimelineId,
    human_body: EntityId,
    human_entity: EntityId,
    events: &[Event],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .test_ok()?;
    let address = listener.local_addr().test_ok()?;
    let state = AppState {
        gateway: gateway_with_erasure_host_and_authorization(
            ErasureExecutionHostV1::open_verified_empty(
                StoreConfig::Sqlite {
                    path: path.to_owned(),
                },
                pos_core::ErasureRecoveryLimitsV1::compiled_maximum(),
            )
            .test_ok()?,
            [human_body],
            gateway_authorization_for(human_entity)?,
        )?,
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
    let guard = FixtureGuard {
        policy_release: None,
        server_shutdown: Some(server_shutdown),
        server: Some(server),
    };
    let mut from_seq = 0;
    for (page_index, expected_page) in events.chunks(2).enumerate() {
        let page = request_http_with_actor(
            address,
            "GET",
            &format!("/v1/timelines/{timeline}/events?from_seq={from_seq}&limit=2"),
            None,
            Some(human_entity),
        )
        .await?;
        assert_eq!(page.status, 200);
        let actual_page = page.body["events"].as_array().test_ok()?;
        assert_eq!(actual_page.len(), expected_page.len());
        for (actual, expected) in actual_page.iter().zip(expected_page) {
            assert_eq!(actual["seq"], expected.seq.as_u64());
            assert_eq!(actual["event_type"], expected.event_type.as_str());
            assert_eq!(actual["entity"], expected.entity.to_string());
        }
        let next = page.body["next_from_seq"].as_u64();
        assert_eq!(
            next,
            events
                .get((page_index + 1) * 2)
                .map(|event| event.seq.as_u64())
        );
        if let Some(next) = next {
            from_seq = next;
        }
    }
    guard.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn gateway_shutdown_drains_an_empty_executor(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let host = ErasureExecutionHostV1::open_verified_empty(
        StoreConfig::Memory,
        pos_core::ErasureRecoveryLimitsV1::compiled_maximum(),
    )
    .test_ok()?;
    let gateway = Gateway::new_with_erasure_host(host)?;
    gateway.shutdown().await.test_ok()?;
    drop(gateway);
    Ok(())
}
