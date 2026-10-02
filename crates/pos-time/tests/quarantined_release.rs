//! While the staged executor is quarantined, protected Replay and Compare
//! fail closed before any premise read (ADR-113 §5, acceptance case 24).
//!
//! Quarantine closes protected release for the whole process, so this
//! binary holds exactly one test.

use pos_core::retention::{
    WorldRetentionLeaseInputV1, WorldRetentionLeaseV1, WorldRetentionPolicyInputV1,
    WorldRetentionPolicyV1,
};
use pos_core::staged_install::ProjectionSourceV1;
use pos_core::trusted_clock::{
    open_release_guard, reserve_trusted_clock, ExpiryPremisesV1, ReleaseGuardV1,
    ScriptedGuardMonotonicSourceV1, SystemGuardMonotonicSourceV1, SystemTrustedWallSourceV1,
    TrustedWallSourceV1, WaitBudgetV1,
};
use pos_core::trusted_clock_fixture::TrustedClockFixtureV1;
use pos_core::{
    AssuranceLevelV1, AuthenticatedPrincipalDraftV1, AuthenticatedPrincipalResultV1,
    CanonicalBytes, Capability, EntityId, ErasureReferenceV1, ErasureReplayClaimV1, Event,
    EventDraft, Hash, Kind, Plugin, PluginId, PrincipalRefV1, Reducer, Seq, State, TimelineId,
    WallTime, WorldReplayClosureV1,
};
use pos_runtime::{
    ErasureCoordinatorCompositionV1, ErasureExecutionHostV1, ExecutorHealthV1, GuardedFoldWindowV1,
    HostProjectionProviderV1, InstalledPluginFactoryV1, InstalledPluginProductV1,
    NoActionApproverV1, StagedFoldErrorV1, StagedFoldExecutorV1, StagedFoldPlanV1,
    VerifiedWorldReplayV1, WorldReplayUseV1, WorldReplayVerificationErrorV1, WorldReplayVerifierV1,
};
use pos_state::{ProjectionRegistry, ProtectedProjectionProviderV1};
use pos_store::StoreConfig;
use pos_time::{ProtectedFoldV1, ProtectedReleaseV1, ReleaseHealthV1};
use std::{
    fmt::Debug,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

const DAY: u64 = 86_400_000_000;

fn test_ok<T, E: Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| {
        std::panic::resume_unwind(Box::new(format!("unexpected fixture error: {error:?}")))
    })
}

/// Waits until the test releases it before each `apply`.
struct BlockingReducer(Arc<AtomicBool>);

impl Reducer for BlockingReducer {
    fn initial(&self) -> State {
        State::new()
    }

    fn apply(&self, state: &mut State, _event: &Event) {
        while !self.0.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(1));
        }
        state.set("seen", serde_json::json!(true));
    }
}

struct BlockingPlugin {
    id: PluginId,
}

impl Plugin for BlockingPlugin {
    fn id(&self) -> PluginId {
        self.id
    }

    fn name(&self) -> &'static str {
        "count"
    }

    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: Vec::new(),
            owned_entity_kinds: Vec::new(),
            has_driver: false,
            has_reducer: true,
        }
    }
}

impl InstalledPluginFactoryV1 for BlockingPlugin {
    type Configuration = Arc<AtomicBool>;
    type Plugin = Self;
    type Approver = NoActionApproverV1;

    fn configuration_details(_configuration: &Self::Configuration) -> Vec<u8> {
        b"count".to_vec()
    }

    fn build(
        configuration: &Self::Configuration,
    ) -> InstalledPluginProductV1<Self, NoActionApproverV1> {
        InstalledPluginProductV1 {
            plugin: Self {
                id: PluginId::new(),
            },
            reducer: Some(Box::new(BlockingReducer(Arc::clone(configuration)))),
            approver: NoActionApproverV1,
        }
    }
}

/// Counts every verification: a premise read.
struct CountingVerifier(Arc<AtomicUsize>);

impl WorldReplayVerifierV1 for CountingVerifier {
    fn verify(
        &self,
        closure: &WorldReplayClosureV1,
        requested_use: &WorldReplayUseV1,
        inventory_generation: ErasureReferenceV1,
    ) -> Result<VerifiedWorldReplayV1, WorldReplayVerificationErrorV1> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(pos_runtime::world_replay::test_verified_world_replay(
            closure,
            requested_use,
            inventory_generation,
            ErasureReplayClaimV1::Exact,
        ))
    }
}

fn guarded(port: &mut TrustedClockFixtureV1) -> ReleaseGuardV1<'_> {
    let mut store = port.clone();
    let mut wait = WaitBudgetV1::new();
    let reservation = test_ok(reserve_trusted_clock(
        &mut store,
        &mut SystemTrustedWallSourceV1,
        &mut SystemGuardMonotonicSourceV1,
        &mut wait,
        None,
    ));
    test_ok(open_release_guard(
        port,
        reservation,
        &mut wait,
        &mut SystemGuardMonotonicSourceV1,
    ))
}

fn release<'p>(
    port: &'p mut TrustedClockFixtureV1,
    health: &'p ReleaseHealthV1,
) -> ProtectedReleaseV1<'p> {
    let guard = guarded(port);
    let far = test_ok(SystemTrustedWallSourceV1.sample()).as_micros() + 1_000 * DAY;
    let policy = test_ok(WorldRetentionPolicyV1::new(WorldRetentionPolicyInputV1 {
        policy_revision: 1,
        purpose: "world".to_owned(),
        audience_policy_hash: Hash::from_bytes([7; 32]),
        minimum_post_admission_days: 90,
        maximum_active_days: 30,
        maximum_total_days: 120,
    }));
    let lease = test_ok(WorldRetentionLeaseV1::new(
        &policy,
        WorldRetentionLeaseInputV1 {
            timeline_id: TimelineId::new(),
            policy_hash: policy.digest(),
            started_at_micros: far - 120 * DAY,
            admission_closes_at_micros: far - 90 * DAY,
            retention_deadline_micros: far,
        },
    ));
    let access = test_ok(AuthenticatedPrincipalResultV1::try_from_draft(
        AuthenticatedPrincipalDraftV1 {
            principal: test_ok(PrincipalRefV1::try_new([1; 16], "operators")),
            adapter_id: "test-passkey".to_owned(),
            assurance: test_ok(AssuranceLevelV1::try_new(2)),
            issued_at: WallTime::from_micros(1),
            expires_at: WallTime::from_micros(far),
            binding_digest: Hash::from_bytes([7; 32]),
        },
    ));
    let premises = ExpiryPremisesV1 {
        retention_leases: &[lease],
        consent_grants: &[],
        consent_references: &[],
        access: Some(&access),
    };
    let expiries = test_ok(guard.applicable_expiries(&premises));
    ProtectedReleaseV1 {
        guard,
        expiries,
        health,
    }
}

#[test]
fn protected_release_fails_closed_before_any_premise_read_while_quarantined() {
    let released = Arc::new(AtomicBool::new(false));
    let mut provider = HostProjectionProviderV1::default();
    let consumer =
        test_ok(provider.admit_fixture::<BlockingPlugin>(Arc::new(Arc::clone(&released))));
    let provider = Arc::new(provider);
    let executor = test_ok(StagedFoldExecutorV1::acquire());

    // Abandon one fold at its deadline.
    let mut port = TrustedClockFixtureV1::new();
    let guard = guarded(&mut port);
    let window = GuardedFoldWindowV1::new(&guard);
    let mut late = ScriptedGuardMonotonicSourceV1::new([Duration::from_millis(26_500)]);
    let draft_event = Event {
        id: pos_core::EventId::new(),
        entity: EntityId::new(),
        event_type: Kind::new("test.tick"),
        payload: CanonicalBytes::from_vec(Vec::new()),
        wall_time: WallTime::from_micros(1),
        seq: Seq::from_u64(1),
        causation_id: None,
        correlation_id: None,
        schema_version: pos_core::SchemaVersion::V1,
        signature: None,
        signature_identity: None,
        origin: None,
        payload_hash: Hash::from_bytes([0; 32]),
    };
    let source = ProjectionSourceV1::bound(TimelineId::new(), None);
    let plan = StagedFoldPlanV1::new(vec![consumer], vec![draft_event], source);
    let shared: Arc<dyn ProtectedProjectionProviderV1 + Send + Sync> = provider.clone();
    let abandoned = executor.fold(&window, &mut late, shared, plan);
    assert_eq!(abandoned.err(), Some(StagedFoldErrorV1::DeadlineExceeded));
    assert_eq!(ExecutorHealthV1::current(), ExecutorHealthV1::Quarantined);
    drop(window);
    drop(guard);

    let premise_reads = Arc::new(AtomicUsize::new(0));
    let composition = ErasureCoordinatorCompositionV1::closed()
        .with_world_replay_verifier(Arc::new(CountingVerifier(Arc::clone(&premise_reads))));
    let mut host = test_ok(ErasureExecutionHostV1::open_with_authority(
        StoreConfig::Memory,
        &composition,
        pos_core::ErasureRecoveryLimitsV1::compiled_maximum(),
    ));
    let gate = host.containment_gate();
    let timeline = {
        let mut commands = test_ok(host.command_sender());
        let timeline = test_ok(commands.create_timeline("quarantined")).id();
        let draft = EventDraft::new(
            EntityId::new(),
            Kind::new("test.tick"),
            CanonicalBytes::from_vec(Vec::new()),
        );
        test_ok(commands.append(timeline, &[draft]));
        timeline
    };
    let closure = test_ok(WorldReplayClosureV1::test_fixture_for_timeline_consumer(
        timeline,
        Hash::from_bytes([3; 32]),
        "count",
    ));
    let consumers = [consumer];
    let fold = ProtectedFoldV1 {
        executor: &executor,
        provider: &provider,
        consumers: &consumers,
    };
    let mut registry = ProjectionRegistry::new().with_erasure_gate(Arc::clone(&gate));
    test_ok(registry.register_installed_reducer(
        consumer.plugin_id(),
        "count",
        Box::new(BlockingReducer(Arc::new(AtomicBool::new(true)))),
    ));
    let mut other = ProjectionRegistry::new().with_erasure_gate(gate);
    test_ok(other.register_installed_reducer(
        consumer.plugin_id(),
        "count",
        Box::new(BlockingReducer(Arc::new(AtomicBool::new(true)))),
    ));
    let mut reads = test_ok(host.read_sender());

    let health = ReleaseHealthV1::new();
    let mut port = TrustedClockFixtureV1::new();
    let replayed = pos_time::replay(
        &mut reads,
        timeline,
        &mut registry,
        &closure,
        release(&mut port, &health),
        &fold,
    );
    assert!(matches!(
        replayed,
        Err(pos_core::CoreError::ArtifactUnavailable)
    ));
    let mut port = TrustedClockFixtureV1::new();
    let compared = pos_time::compare(
        &mut reads,
        [timeline, timeline],
        Seq::from_u64(1),
        [&mut registry, &mut other],
        [&closure, &closure],
        release(&mut port, &health),
        [&fold, &fold],
    );
    assert!(matches!(
        compared,
        Err(pos_core::CoreError::ArtifactUnavailable)
    ));
    assert_eq!(premise_reads.load(Ordering::SeqCst), 0);
    assert_eq!(health.guard_release_late(), None);

    released.store(true, Ordering::SeqCst);
}
