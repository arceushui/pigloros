//! ADR-021 Revision 4 Decision 3 runtime pass fencing (#499).
//!
//! Every runtime `PluginInput` pass entry point fences the host-supplied Fork
//! ancestry, and the host read seam fences stitched effects over the same
//! chain.

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use pos_core::{
    fork_ancestry, CanonicalBytes, ConsentAuthority, ConsentCapabilityToken, ConsentGrantedV1,
    EntityId, ErasureContainmentErrorV1, ErasureContainmentGateV1, ErasureHostErrorV1,
    ErasureProtectedOperationV1, ErasureRecoveryLimitsV1, EventDraft, EventStore, Kind,
    SchemaVersion, Seq, TimelineId, TimelineMeta,
};
use pos_runtime::{
    Driver, ErasureExecutionHostV1, ObservationView, PluginRegistry, RuntimeError, StepOutput,
    TickScheduler,
};
use pos_store::{memory::MemoryStore, sqlite::SqliteStore, StoreConfig};

trait TestOk<T> {
    fn test_ok(self) -> T;
}

impl<T, E: std::fmt::Debug> TestOk<T> for Result<T, E> {
    fn test_ok(self) -> T {
        self.unwrap_or_else(|error| {
            std::panic::resume_unwind(Box::new(format!("unexpected fixture error: {error:?}")))
        })
    }
}

struct CountingDriver(Arc<AtomicUsize>);

impl Driver for CountingDriver {
    fn name(&self) -> &'static str {
        "inherited-scope-counting"
    }

    fn step(&mut self, _: TimelineId, _: ObservationView<'_>) -> Result<StepOutput, RuntimeError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(StepOutput::empty())
    }
}

fn draft() -> EventDraft {
    EventDraft {
        entity: EntityId::new(),
        event_type: Kind::new("world.test"),
        payload: CanonicalBytes::from_vec(vec![3]),
        wall_time: None,
        causation_id: None,
        correlation_id: None,
        schema_version: SchemaVersion::V1,
    }
}

fn grant(timeline: TimelineId, authority: &ConsentAuthority) -> ConsentCapabilityToken {
    authority.record_grant_on_timeline(
        timeline,
        &ConsentGrantedV1 {
            subject_id: EntityId::new(),
            grantee_id: EntityId::new(),
            purpose: "inherited-scope".to_owned(),
            modalities: pos_core::MODALITY_PERSONA,
            min_geo_resolution: 0,
            fork_permitted: false,
            export_permitted: false,
            retention_days: 1,
            expiry_secs: 0,
            grant_seq: 1,
        },
    )
}

/// A root with two Events, its Fork at Seq 2, and an unrelated root, all
/// behind one open gate shared by the store and the registry.
struct Fixture {
    store: Box<dyn EventStore>,
    gate: Arc<ErasureContainmentGateV1>,
    registry: PluginRegistry,
    steps: Arc<AtomicUsize>,
    token: ConsentCapabilityToken,
    root: TimelineId,
    child: TimelineId,
    unrelated: TimelineId,
}

impl Fixture {
    fn new(mut store: Box<dyn EventStore>) -> Self {
        let gate = Arc::new(ErasureContainmentGateV1::new_test_open());
        store.bind_erasure_gate(Arc::clone(&gate)).test_ok();
        let root = store.create_timeline("root").test_ok().id();
        store.append(root, &[draft(), draft()]).test_ok();
        let child = store.fork(root, Seq::from_u64(2), "child").test_ok().id();
        let unrelated = store.create_timeline("unrelated").test_ok().id();
        let authority = ConsentAuthority::new();
        let token = grant(child, &authority);
        let steps = Arc::new(AtomicUsize::new(0));
        let mut registry = PluginRegistry::new()
            .with_consent_authority(authority)
            .with_erasure_gate(gate.clone());
        registry.register_test_driver(Box::new(CountingDriver(Arc::clone(&steps))));
        registry.compose_non_participant_drivers().test_ok();
        Self {
            store,
            gate,
            registry,
            steps,
            token,
            root,
            child,
            unrelated,
        }
    }

    fn ancestry(&self, timeline: TimelineId) -> Vec<TimelineMeta> {
        fork_ancestry(self.store.as_ref(), timeline).test_ok()
    }
}

fn stores() -> Vec<(&'static str, Box<dyn EventStore>)> {
    vec![
        ("memory", Box::new(MemoryStore::new())),
        ("sqlite", Box::new(SqliteStore::open(":memory:").test_ok())),
    ]
}

type PassResult = Result<Vec<EventDraft>, RuntimeError>;

/// Run every `PluginInput` pass entry point once on `timeline`, aborting any
/// staged step after each, and return the labelled results.
fn every_pass(
    registry: &mut PluginRegistry,
    timeline: TimelineId,
    ancestry: &[TimelineMeta],
    token: &ConsentCapabilityToken,
) -> Vec<(&'static str, PassResult)> {
    let head = Seq::from_u64(2);
    let passes: [(&'static str, PassFn<'_>); 9] = [
        ("step_all", &|registry| {
            registry.step_all(timeline, ancestry)
        }),
        ("tick_cadenced", &|registry| {
            registry.tick_cadenced(timeline, ancestry, 0)
        }),
        ("step_all_anchored", &|registry| {
            registry.step_all_anchored(timeline, ancestry, head)
        }),
        ("step_all_anchored_with_events", &|registry| {
            registry.step_all_anchored_with_events(timeline, ancestry, head, &[])
        }),
        ("step_all_anchored_protected", &|registry| {
            registry.step_all_anchored_protected(timeline, ancestry, head, token.clone(), 0, &[])
        }),
        ("tick_cadenced_anchored", &|registry| {
            registry.tick_cadenced_anchored(timeline, ancestry, 0, head)
        }),
        ("tick_cadenced_anchored_with_events", &|registry| {
            registry.tick_cadenced_anchored_with_events(timeline, ancestry, 0, head, &[])
        }),
        ("tick_cadenced_anchored_protected", &|registry| {
            registry.tick_cadenced_anchored_protected(
                timeline,
                ancestry,
                0,
                head,
                token.clone(),
                0,
                &[],
            )
        }),
        ("tick_scheduler", &|registry| {
            let gate = registry.clone_erasure_gate().test_ok_some();
            TickScheduler::new(PluginRegistry::new().with_erasure_gate(gate))
                .tick(timeline, ancestry, 0)
        }),
    ];
    passes
        .into_iter()
        .map(|(label, pass)| {
            let result = pass(registry);
            registry.abort_step();
            (label, result)
        })
        .collect()
}

type PassFn<'a> = &'a dyn Fn(&mut PluginRegistry) -> PassResult;

trait TestSome<T> {
    fn test_ok_some(self) -> T;
}

impl<T> TestSome<T> for Option<T> {
    fn test_ok_some(self) -> T {
        self.unwrap_or_else(|| std::panic::resume_unwind(Box::new("missing fixture value")))
    }
}

const fn is_frozen(result: &PassResult) -> bool {
    matches!(
        result,
        Err(RuntimeError::ErasureContainment(
            ErasureContainmentErrorV1::AccessFrozen
        ))
    )
}

#[test]
fn every_pass_entry_point_admits_an_open_fork_ancestry() {
    for (name, store) in stores() {
        let mut fixture = Fixture::new(store);
        let ancestry = fixture.ancestry(fixture.child);
        let token = fixture.token.clone();
        for (label, result) in every_pass(&mut fixture.registry, fixture.child, &ancestry, &token) {
            // The fence admitted the pass; any later outcome is not erasure's.
            assert!(
                !matches!(result, Err(RuntimeError::ErasureContainment(_))),
                "{name}/{label}: {result:?}"
            );
        }
        assert!(fixture.steps.load(Ordering::SeqCst) > 0, "{name}");
    }
}

#[test]
fn a_frozen_ancestor_fails_every_pass_closed_before_any_driver_runs() {
    for (name, store) in stores() {
        let mut fixture = Fixture::new(store);
        // Fork ancestry is immutable, so the host computes it before the
        // fence; the freeze lands after the chain was read.
        let ancestry = fixture.ancestry(fixture.child);
        fixture.gate.freeze_timeline_for_test(fixture.root);
        let token = fixture.token.clone();
        for (label, result) in every_pass(&mut fixture.registry, fixture.child, &ancestry, &token) {
            assert!(is_frozen(&result), "{name}/{label}: {result:?}");
        }
        assert_eq!(fixture.steps.load(Ordering::SeqCst), 0, "{name}");
        // Nothing was left staged: an unrelated pass still stages and commits.
        let unrelated = fixture.ancestry(fixture.unrelated);
        assert!(fixture
            .registry
            .step_all_anchored(fixture.unrelated, &unrelated, Seq::ZERO)
            .is_ok());
        fixture.registry.commit_step_at(Seq::ZERO, 0).test_ok();
        assert_eq!(fixture.steps.load(Ordering::SeqCst), 1, "{name}");
    }
}

#[test]
fn the_registry_rejects_an_empty_wrongly_rooted_or_broken_chain() {
    for (name, store) in stores() {
        let mut fixture = Fixture::new(store);
        let child_chain = fixture.ancestry(fixture.child);
        let root_chain = fixture.ancestry(fixture.root);
        let unrelated_chain = fixture.ancestry(fixture.unrelated);
        let token = fixture.token.clone();
        let broken = [child_chain[0].clone(), unrelated_chain[0].clone()];
        let unterminated = [child_chain[0].clone()];
        let chains: [&[TimelineMeta]; 4] = [&[], &root_chain, &broken, &unterminated];
        for chain in chains {
            for (label, result) in every_pass(&mut fixture.registry, fixture.child, chain, &token) {
                assert!(
                    matches!(
                        result,
                        Err(RuntimeError::ErasureContainment(
                            ErasureContainmentErrorV1::RecoveryUnavailable
                        ))
                    ),
                    "{name}/{label}: {result:?}"
                );
            }
        }
        assert_eq!(fixture.steps.load(Ordering::SeqCst), 0, "{name}");
    }
}

#[test]
fn snapshot_and_refold_fence_the_inherited_ancestry() {
    for (name, store) in stores() {
        let mut fixture = Fixture::new(store);
        let ancestry = fixture.ancestry(fixture.child);
        let events = fixture
            .store
            .read(fixture.child, pos_core::SeqRange::all())
            .test_ok();
        fixture
            .registry
            .refold_projection_events(fixture.child, &ancestry, &events, None)
            .test_ok();
        fixture.gate.freeze_timeline_for_test(fixture.root);
        assert!(
            fixture
                .registry
                .refold_projection_events(fixture.child, &ancestry, &events, None)
                .is_err(),
            "{name}"
        );
        let projection = fixture.registry.projection_state_for_reducer(
            fixture.child,
            &ancestry,
            Seq::from_u64(2),
            0,
            &fixture.token,
            "missing",
            fixture.token.subject_id(),
        );
        assert!(
            matches!(
                projection,
                Err(RuntimeError::ErasureContainment(
                    ErasureContainmentErrorV1::AccessFrozen
                ))
            ),
            "{name}: {projection:?}"
        );
    }
}

#[test]
fn a_completed_ancestor_erasure_keeps_every_pass_closed() {
    for (name, store) in stores() {
        let mut fixture = Fixture::new(store);
        let ancestry = fixture.ancestry(fixture.child);
        fixture
            .gate
            .complete_timeline_erasure_for_test(fixture.root)
            .test_ok();
        let token = fixture.token.clone();
        for (label, result) in every_pass(&mut fixture.registry, fixture.child, &ancestry, &token) {
            assert!(is_frozen(&result), "{name}/{label}: {result:?}");
        }
        assert_eq!(fixture.steps.load(Ordering::SeqCst), 0, "{name}");
    }
}

fn hosts() -> Vec<(&'static str, StoreConfig)> {
    vec![
        ("memory", StoreConfig::Memory),
        ("sqlite", StoreConfig::SqliteInMemory),
    ]
}

#[test]
fn the_host_read_seam_fences_stitched_effects_over_the_fork_ancestry() {
    for (name, config) in hosts() {
        let mut host = ErasureExecutionHostV1::open_verified_empty(
            config,
            ErasureRecoveryLimitsV1::compiled_maximum(),
        )
        .test_ok();
        let (root, child, unrelated) = {
            let mut commands = host.command_sender().test_ok();
            let root = commands.create_timeline("root").test_ok().id();
            commands.append(root, &[draft(), draft()]).test_ok();
            let child = commands
                .fork_timeline(root, Seq::from_u64(2), "child")
                .test_ok()
                .id();
            let unrelated = commands.create_timeline("unrelated").test_ok().id();
            (root, child, unrelated)
        };
        let mut runs = 0;
        {
            let mut reads = host.read_sender().test_ok();
            assert_eq!(
                reads
                    .fork_ancestry(child)
                    .test_ok()
                    .iter()
                    .map(|meta| meta.id)
                    .collect::<Vec<_>>(),
                [child, root],
                "{name}"
            );
            reads
                .with_protected_ancestry_fence(
                    child,
                    ErasureProtectedOperationV1::Snapshot,
                    &mut |_| runs += 1,
                )
                .test_ok();
        }
        assert_eq!(runs, 1, "{name}");

        host.freeze_timeline_for_test(root);
        let mut reads = host.read_sender().test_ok();
        assert_eq!(
            reads.fork_ancestry(child).map(|chain| chain.len()),
            Err(ErasureHostErrorV1::AccessFrozen),
            "{name}"
        );
        for operation in [
            ErasureProtectedOperationV1::Read,
            ErasureProtectedOperationV1::Export,
            ErasureProtectedOperationV1::Snapshot,
        ] {
            assert_eq!(
                reads.with_protected_ancestry_fence(child, operation, &mut |_| runs += 1),
                Err(ErasureHostErrorV1::AccessFrozen),
                "{name}"
            );
        }
        reads
            .with_protected_ancestry_fence(
                unrelated,
                ErasureProtectedOperationV1::Snapshot,
                &mut |_| runs += 1,
            )
            .test_ok();
        assert_eq!(runs, 2, "{name}");
    }
}
