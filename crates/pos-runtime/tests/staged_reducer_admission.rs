#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
//! Staged Reducer admission and fresh per-candidate builds (ADR-113 §1;
//! acceptance cases 1, 14 and 25).
//!
//! The provider under test is standalone: it is not yet bound to the live
//! `PluginRegistry`, so case 14 compares two independent folds of the same
//! Event range rather than a candidate opened from the live registry.

use pos_core::staged_install::ProjectionSourceV1;
use pos_core::{
    clock::{Seq, WallTime},
    crypto::Hash,
    event::{CanonicalBytes, Event, Kind, SchemaVersion},
    ids::{EntityId, EventId, TimelineId},
    ActionApprover, ActionRejected, Capability, ConsentAuthority, ConsentGrantedV1,
    ConsentRevokedV1, ErasureContainmentGateV1, Plugin, PluginId, ProposedAction, Reducer, State,
    EVENT_TYPE_CONSENT_REVOKED_V1, GEOGRAPHIC_EVENT_TYPE, HOST_CONSENT_CLOSED_EVENT_TYPE,
};
use pos_runtime::{
    fold_detached_candidate_v1, is_reviewed_staged_factory, HostProjectionProviderV1,
    InstalledPluginFactoryV1, InstalledPluginProductV1, NoActionApproverV1, PluginRegistry,
    StagedReducerAdmissionErrorV1, MAX_STAGED_CALLBACK_BOUND_V1,
};
use pos_state::{
    EntityStateProjection, InitialStateV1, ProjectionCandidateErrorV1,
    ProtectedProjectionProviderV1, RecordedConsumerV1,
};
use std::{
    fmt::Debug,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
};

const COUNTED: &str = "staged.counted";
const REJECTED: &str = "staged.rejected";

fn test_ok<T, E: Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| {
        std::panic::resume_unwind(Box::new(format!("unexpected fixture error: {error:?}")))
    })
}

fn event(entity: EntityId, event_type: &str, seq: u64) -> Event {
    Event {
        id: EventId::new(),
        entity,
        event_type: Kind::new(event_type),
        payload: CanonicalBytes::from_static(b"staged"),
        wall_time: WallTime::from_micros(seq),
        seq: Seq::from_u64(seq),
        causation_id: None,
        correlation_id: None,
        schema_version: SchemaVersion::V1,
        signature: None,
        signature_identity: None,
        origin: None,
        payload_hash: Hash::from_bytes([0; 32]),
    }
}

/// Counts every projected Event and rejects one Event type (ADR-090).
struct CountingReducer;

impl Reducer for CountingReducer {
    fn initial(&self) -> State {
        State::new()
    }

    fn projects_event(&self, event: &Event) -> bool {
        event.event_type.as_str() != REJECTED
    }

    fn apply(&self, state: &mut State, _event: &Event) {
        let count = state
            .get("count")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        state.set("count", serde_json::json!(count + 1));
    }
}

/// A reducer with an external effect: it writes to a shared counter.
struct SharedCounterReducer(Arc<AtomicU64>);

impl Reducer for SharedCounterReducer {
    fn initial(&self) -> State {
        self.0.fetch_add(1, Ordering::SeqCst);
        State::new()
    }

    fn apply(&self, _state: &mut State, _event: &Event) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

/// Fixture Plugin whose factory is implemented on the Plugin type itself,
/// as every reviewed staged factory is, but which is not reviewed.
struct CountingPlugin {
    id: PluginId,
}

impl Plugin for CountingPlugin {
    fn id(&self) -> PluginId {
        self.id
    }

    fn name(&self) -> &'static str {
        "staged-counting"
    }

    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: vec![Kind::new(COUNTED)],
            owned_entity_kinds: Vec::new(),
            has_driver: false,
            has_reducer: true,
        }
    }
}

/// Frozen fixture configuration that observes every factory build.
#[derive(Default)]
struct FixtureConfiguration {
    builds: Arc<AtomicUsize>,
    details: Vec<u8>,
    /// Number of builds that still yield a reducer; `None` means all do.
    reducer_builds: Option<usize>,
    fixed_id: Option<PluginId>,
}

impl FixtureConfiguration {
    fn builds(&self) -> usize {
        self.builds.load(Ordering::SeqCst)
    }
}

impl InstalledPluginFactoryV1 for CountingPlugin {
    type Configuration = FixtureConfiguration;
    type Plugin = Self;
    type Approver = NoActionApproverV1;

    fn configuration_details(configuration: &FixtureConfiguration) -> Vec<u8> {
        configuration.details.clone()
    }

    fn build(
        configuration: &FixtureConfiguration,
    ) -> InstalledPluginProductV1<Self, NoActionApproverV1> {
        let previous = configuration.builds.fetch_add(1, Ordering::SeqCst);
        let yields_reducer = configuration
            .reducer_builds
            .is_none_or(|limit| previous < limit);
        let reducer: Option<Box<dyn Reducer>> = if yields_reducer {
            Some(Box::new(CountingReducer))
        } else {
            None
        };
        InstalledPluginProductV1 {
            plugin: Self {
                id: configuration.fixed_id.unwrap_or_default(),
            },
            reducer,
            approver: NoActionApproverV1,
        }
    }
}

/// Fixture Plugin that carries the bare, non-admitted `EntityStateProjection`.
struct EntityStatePlugin {
    id: PluginId,
}

impl Plugin for EntityStatePlugin {
    fn id(&self) -> PluginId {
        self.id
    }

    fn name(&self) -> &'static str {
        "staged-entity-state"
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

impl InstalledPluginFactoryV1 for EntityStatePlugin {
    type Configuration = ();
    type Plugin = Self;
    type Approver = NoActionApproverV1;

    fn configuration_details(_configuration: &()) -> Vec<u8> {
        Vec::new()
    }

    fn build(_configuration: &()) -> InstalledPluginProductV1<Self, NoActionApproverV1> {
        InstalledPluginProductV1 {
            plugin: Self {
                id: PluginId::new(),
            },
            reducer: Some(Box::new(EntityStateProjection)),
            approver: NoActionApproverV1,
        }
    }
}

fn admitted_fixture(
    configuration: FixtureConfiguration,
) -> (
    HostProjectionProviderV1,
    RecordedConsumerV1,
    Arc<AtomicUsize>,
) {
    let builds = Arc::clone(&configuration.builds);
    let mut provider = HostProjectionProviderV1::default();
    let consumer = test_ok(provider.admit_fixture::<CountingPlugin>(Arc::new(configuration)));
    (provider, consumer, builds)
}

fn source() -> ProjectionSourceV1 {
    ProjectionSourceV1::bound(TimelineId::new(), None)
}

fn test_some<T>(value: Option<T>) -> T {
    value.unwrap_or_else(|| std::panic::resume_unwind(Box::new("missing fixture value")))
}

fn count_of(state: Option<&State>) -> Option<u64> {
    state
        .and_then(|state| state.get("count"))
        .and_then(serde_json::Value::as_u64)
}

#[test]
fn reviewed_admission_rejects_unreviewed_factories_before_any_build() {
    let configuration = Arc::new(FixtureConfiguration::default());
    let mut provider = HostProjectionProviderV1::default();

    assert_eq!(
        provider.admit::<CountingPlugin>(Arc::clone(&configuration)),
        Err(StagedReducerAdmissionErrorV1::NotReviewed)
    );
    assert_eq!(
        provider.admit::<EntityStatePlugin>(Arc::new(())),
        Err(StagedReducerAdmissionErrorV1::NotReviewed)
    );
    assert_eq!(configuration.builds(), 0);
    let counting = std::any::type_name::<CountingPlugin>();
    assert!(!is_reviewed_staged_factory(counting));
    assert!(is_reviewed_staged_factory("pos_plugin_world::WorldPlugin"));
}

#[test]
fn every_candidate_builds_fresh_reducer_internals() {
    let (provider, consumer, builds) = admitted_fixture(FixtureConfiguration::default());
    assert_eq!(builds.load(Ordering::SeqCst), 1);

    let mut folded = test_ok(provider.open_candidate(&[consumer], InitialStateV1::Empty, source()));
    let fresh = test_ok(provider.open_candidate(&[consumer], InitialStateV1::Empty, source()));
    assert_eq!(builds.load(Ordering::SeqCst), 3);

    let entity = EntityId::new();
    fold_detached_candidate_v1(&mut folded, &[event(entity, COUNTED, 1)]);
    let folded_count = count_of(folded.state_for(consumer.plugin_id(), &entity));
    assert_eq!(folded_count, Some(1));
    assert!(fresh.state_for(consumer.plugin_id(), &entity).is_none());
    assert_eq!(fresh.consumers(), vec![consumer]);
}

#[test]
fn admission_record_is_bound_to_the_exact_recorded_identity() {
    let (provider, consumer, _) = admitted_fixture(FixtureConfiguration::default());
    let record = test_some(provider.admission(&consumer));
    let stale = RecordedConsumerV1::new(consumer.plugin_id(), Hash::from_bytes([9; 32]));

    assert_eq!(record.callback_bound(), MAX_STAGED_CALLBACK_BOUND_V1);
    assert_eq!(record.growth_bound().per_payload_byte(), 6);
    assert_eq!(record.growth_bound().constant_bytes(), 4096);
    assert_eq!(provider.admission(&stale), None);
}

#[test]
fn reducer_identity_binds_configuration_but_not_the_built_plugin_identity() {
    let details = |bytes: &[u8]| FixtureConfiguration {
        details: bytes.to_vec(),
        ..FixtureConfiguration::default()
    };
    let (_, first, _) = admitted_fixture(details(b"same"));
    let (_, second, _) = admitted_fixture(details(b"same"));
    let (_, other, _) = admitted_fixture(details(b"other"));

    assert_ne!(first.plugin_id(), second.plugin_id());
    assert_eq!(first.reducer_identity(), second.reducer_identity());
    assert_ne!(first.reducer_identity(), other.reducer_identity());
}

#[test]
fn inexact_consumer_sets_are_rejected_before_any_build() {
    let (provider, consumer, builds) = admitted_fixture(FixtureConfiguration::default());
    let stale = RecordedConsumerV1::new(consumer.plugin_id(), Hash::from_bytes([7; 32]));
    let unknown = RecordedConsumerV1::new(PluginId::new(), consumer.reducer_identity());

    let rejection = |plan: &[RecordedConsumerV1]| {
        provider
            .open_candidate(plan, InitialStateV1::Empty, source())
            .err()
    };
    let mismatch = Some(ProjectionCandidateErrorV1::ConsumerSetMismatch);

    assert_eq!(rejection(&[]), mismatch);
    assert_eq!(rejection(&[consumer, consumer]), mismatch);
    assert_eq!(rejection(&[stale]), mismatch);
    assert_eq!(
        rejection(&[consumer, unknown]),
        Some(ProjectionCandidateErrorV1::NotAdmitted)
    );
    assert_eq!(builds.load(Ordering::SeqCst), 1);
}

#[test]
fn factories_that_build_no_reducer_are_never_folded() {
    let mut provider = HostProjectionProviderV1::default();
    let without = Arc::new(FixtureConfiguration {
        reducer_builds: Some(0),
        ..FixtureConfiguration::default()
    });
    assert_eq!(
        provider.admit_fixture::<CountingPlugin>(without),
        Err(StagedReducerAdmissionErrorV1::MissingReducer)
    );

    let (provider, consumer, builds) = admitted_fixture(FixtureConfiguration {
        reducer_builds: Some(1),
        ..FixtureConfiguration::default()
    });
    assert_eq!(
        provider
            .open_candidate(&[consumer], InitialStateV1::Empty, source())
            .err(),
        Some(ProjectionCandidateErrorV1::PluginMismatch)
    );
    assert_eq!(builds.load(Ordering::SeqCst), 2);
}

#[test]
fn one_plugin_identity_is_admitted_once() {
    let fixed_id = PluginId::new();
    let fixed = || FixtureConfiguration {
        fixed_id: Some(fixed_id),
        ..FixtureConfiguration::default()
    };
    let mut provider = HostProjectionProviderV1::default();
    let consumer = test_ok(provider.admit_fixture::<CountingPlugin>(Arc::new(fixed())));
    let other = Arc::new(FixtureConfiguration::default());
    let distinct = test_ok(provider.admit_fixture::<CountingPlugin>(other));

    assert_eq!(
        provider.admit_fixture::<CountingPlugin>(Arc::new(fixed())),
        Err(StagedReducerAdmissionErrorV1::DuplicatePlugin)
    );
    let candidate =
        test_ok(provider.open_candidate(&[distinct, consumer], InitialStateV1::Empty, source()));
    assert_eq!(candidate.consumers(), vec![distinct, consumer]);
}

/// Acceptance case 1: a reducer registered outside the catalogue is not
/// admitted, and the plan fails before any callback. The admitted consumer
/// comes first in the plan, so an unchanged build counter proves the whole
/// plan is resolved before any factory is built for the candidate.
#[test]
fn effectful_reducer_registered_outside_the_catalogue_is_not_admitted() {
    let counter = Arc::new(AtomicU64::new(0));
    let outside = CountingPlugin {
        id: PluginId::new(),
    };
    let mut registry = PluginRegistry::new();
    test_ok(registry.register_generated(
        &outside,
        Some(Box::new(SharedCounterReducer(Arc::clone(&counter)))),
        None,
    ));
    let (provider, consumer, builds) = admitted_fixture(FixtureConfiguration::default());
    let plan = [
        consumer,
        RecordedConsumerV1::new(outside.id, consumer.reducer_identity()),
    ];
    assert_eq!(builds.load(Ordering::SeqCst), 1);

    assert_eq!(
        provider
            .open_candidate(&plan, InitialStateV1::Empty, source())
            .err(),
        Some(ProjectionCandidateErrorV1::NotAdmitted)
    );
    assert_eq!(counter.load(Ordering::SeqCst), 0);
    assert_eq!(builds.load(Ordering::SeqCst), 1);
    assert_eq!(registry.len(), 1);
}

/// Acceptance case 25: `EntityStateProjection` is never admitted.
///
/// `HostProjectionProviderV1` is standalone in this change: it is not yet
/// linked to the live `PluginRegistry`, so registering the bare projection
/// there cannot admit it. The evidence is the provider's own reviewed
/// admission list, which refuses the factory carrying the projection, and
/// the resulting `NotAdmitted` when a plan names its Plugin.
#[test]
fn entity_state_projection_is_not_admitted() {
    let bare = EntityStatePlugin {
        id: PluginId::new(),
    };
    let mut registry = PluginRegistry::new();
    test_ok(registry.register_generated(&bare, Some(Box::new(EntityStateProjection)), None));
    let (mut provider, consumer, _) = admitted_fixture(FixtureConfiguration::default());
    let named = RecordedConsumerV1::new(bare.id, consumer.reducer_identity());

    assert_eq!(
        provider.admit::<EntityStatePlugin>(Arc::new(())),
        Err(StagedReducerAdmissionErrorV1::NotReviewed)
    );
    assert_eq!(
        provider
            .open_candidate(&[named], InitialStateV1::Empty, source())
            .err(),
        Some(ProjectionCandidateErrorV1::NotAdmitted)
    );
}

fn grant(subject_id: EntityId) -> ConsentGrantedV1 {
    ConsentGrantedV1 {
        subject_id,
        grantee_id: EntityId::new(),
        purpose: "staged-candidate-parity".to_owned(),
        modalities: pos_core::MODALITY_LOCATION,
        min_geo_resolution: 0,
        fork_permitted: false,
        export_permitted: false,
        retention_days: 1,
        expiry_secs: 0,
        grant_seq: 1,
    }
}

fn revocation(subject: EntityId, seq: u64) -> Event {
    let mut revoked = event(subject, EVENT_TYPE_CONSENT_REVOKED_V1, seq);
    revoked.payload = test_ok(
        ConsentRevokedV1 {
            subject_id: subject,
            grantee_id: EntityId::new(),
            grant_seq: 1,
            fence_seq: seq,
        }
        .encode(),
    );
    revoked
}

/// One live `PluginRegistry::fold_events` over `events`, read for `subject`
/// through the consent-authorized projection path.
///
/// A default registry keeps its erasure containment fail-closed, so the
/// fixture binds the open test gate before any projection read.
fn live_fold_state(timeline: TimelineId, subject: EntityId, events: &[Event]) -> Option<State> {
    let authority = ConsentAuthority::new();
    let token = authority.record_grant_on_timeline(timeline, &grant(subject));
    let mut live = PluginRegistry::new()
        .with_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))
        .with_consent_authority(authority);
    let plugin = CountingPlugin {
        id: PluginId::new(),
    };
    test_ok(live.register_generated(&plugin, Some(Box::new(CountingReducer)), None));
    live.fold_events(timeline, events);
    let head = Seq::from_u64(u64::try_from(events.len()).unwrap_or(u64::MAX));
    let projections =
        test_ok(live.into_authorized_projections(timeline, head, 1, Some(&token), None));
    test_ok(projections.state_for_reducer(timeline, plugin.name(), &subject))
}

/// Acceptance case 14: a candidate folded through the host fold equals
/// `PluginRegistry::fold_events` on the same range, across every filtering
/// branch: a host consent-closed marker, a non-revocation consent Event, a
/// geographic Event, an Event the reducer's `projects_event` rejects, and a
/// `consent.revoked.v1` for a subject that already holds State.
#[test]
fn candidate_fold_matches_the_live_plugin_registry_fold() {
    let timeline = TimelineId::new();
    let (kept, revoked) = (EntityId::new(), EntityId::new());
    let (provider, consumer, _) = admitted_fixture(FixtureConfiguration::default());
    let events = [
        event(kept, COUNTED, 1),
        event(revoked, COUNTED, 2),
        event(revoked, COUNTED, 3),
        event(kept, REJECTED, 4),
        event(kept, GEOGRAPHIC_EVENT_TYPE, 5),
        event(kept, HOST_CONSENT_CLOSED_EVENT_TYPE, 6),
        event(kept, "consent.granted.v1", 7),
        revocation(revoked, 8),
        event(kept, COUNTED, 9),
    ];

    let mut candidate =
        test_ok(provider.open_candidate(&[consumer], InitialStateV1::Empty, source()));
    fold_detached_candidate_v1(&mut candidate, &events);
    let expected_kept = live_fold_state(timeline, kept, &events);
    let expected_revoked = live_fold_state(timeline, revoked, &events);

    assert_eq!(count_of(expected_kept.as_ref()), Some(2));
    assert_eq!(expected_revoked, None);
    assert_eq!(
        candidate.state_for(consumer.plugin_id(), &kept),
        expected_kept.as_ref()
    );
    assert_eq!(
        candidate.state_for(consumer.plugin_id(), &revoked),
        expected_revoked.as_ref()
    );
    let prefix = &events[..3];
    let mut before_revocation =
        test_ok(provider.open_candidate(&[consumer], InitialStateV1::Empty, source()));
    fold_detached_candidate_v1(&mut before_revocation, prefix);
    let revoked_prior = live_fold_state(timeline, revoked, prefix);
    assert_eq!(count_of(revoked_prior.as_ref()), Some(2));
    assert_eq!(
        before_revocation.state_for(consumer.plugin_id(), &revoked),
        revoked_prior.as_ref()
    );
}

#[test]
fn no_action_approver_rejects_every_proposal() {
    let proposal = ProposedAction::new(
        Kind::new(COUNTED),
        EntityId::new(),
        CanonicalBytes::from_static(b"proposal"),
        Kind::new("staged.capability"),
    );

    assert_eq!(
        NoActionApproverV1.approve(&proposal).err(),
        Some(ActionRejected::UnknownEventType)
    );
}
