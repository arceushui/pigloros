//! Legal imported ancestry, publication cuts and nonempty atomic installs.
//!
//! Every intermediate import is published at its inherited cut. Only the
//! source host signs Events; the destination imports code-2 evidence and never
//! obtains signing or append authority from it.

use crate::imported_fork_replay_tests::fixture::{pin_policy, Fallible, Port, Shape, Spec, World};
use crate::test_support::{with_release, ProtectedFixture};
use pos_core::{
    geo_admission::{
        GeoLocationAdmissionFenceV1, GeoLocationAdmissionInputV1, GeoLocationAdmissionRequestV1,
        GeoLocationAdmissionStore,
    },
    store::{EventStore, SeqRange},
    CanonicalBytes, CoreError, EntityId, ErasureContainmentGateV1, ErasureGate,
    ErasureRecoveryLimitsV1, ErasureReferenceV1, ErasureReplayClaimV1, Event, EventReadBounds, Hash,
    OwnTracksEnrollmentRequestV1, OwnTracksEnrollmentStore, Reducer, Seq, State, TimelineId,
    WorldReplayClosureV1,
};
use pos_runtime::{
    ErasureCoordinatorCompositionV1, ErasureExecutionHostV1, VerifiedWorldReplayV1,
    WorldReplayForkSourceV1, WorldReplayUseV1, WorldReplayVerificationErrorV1,
    WorldReplayVerifierV1,
};
use pos_state::ProjectionRegistry;
use pos_store::{
    memory::MemoryStore, sqlite::SqliteStore, ForkAttributionAuthorityImportRequestV1,
    ForkReplayReadLimitsV1, ForkReplayRequirementV1, StoreConfig,
};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};

static FOLDED: AtomicUsize = AtomicUsize::new(0);

struct Count;

impl Reducer for Count {
    fn initial(&self) -> State {
        let mut state = State::new();
        state.set("n", serde_json::json!(0));
        state
    }

    fn apply(&self, state: &mut State, _: &Event) {
        FOLDED.fetch_add(1, Ordering::SeqCst);
        let n = state
            .get("n")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        state.set("n", serde_json::json!(n + 1));
    }
}

fn count() -> Box<dyn Reducer> {
    Box::new(Count)
}

#[derive(Clone, Copy)]
enum Consumer {
    Replay,
    ReplayAtInherited,
    ReplayAtOwn,
    Compare,
}

impl Consumer {
    const fn arms(self) -> usize {
        if matches!(self, Self::Compare) {
            2
        } else {
            1
        }
    }

    const fn folded(self) -> usize {
        match self {
            Self::Replay => 8,
            Self::ReplayAtInherited => 2,
            Self::ReplayAtOwn => 5,
            Self::Compare => 12,
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Fault {
    None,
    OmitAncestor,
    DuplicateAncestor,
    ForeignAncestor,
    OmitRequirement,
    WrongInheritedHead,
    ExtraRequirement,
    FinalSources,
    FinalProfile,
    ArmDepthShort,
    HiddenCommonRoot,
}

impl Fault {
    const fn is_final(self) -> bool {
        matches!(self, Self::FinalSources | Self::FinalProfile)
    }
}

#[derive(Clone, Copy)]
struct Scenario {
    consumer: Consumer,
    fault: Fault,
    target: usize,
}

struct NestedVerifier {
    sources: [Vec<WorldReplayForkSourceV1>; 2],
    scenario: Mutex<Option<Scenario>>,
    admissions: AtomicUsize,
}

fn classify_fault(
    sources: &mut Vec<WorldReplayForkSourceV1>,
    fault: Fault,
    final_phase: bool,
) -> Result<(), WorldReplayVerificationErrorV1> {
    match fault {
        Fault::OmitAncestor => {
            sources.remove(1);
        }
        Fault::FinalSources if final_phase => {
            sources.remove(1);
        }
        Fault::DuplicateAncestor => sources.insert(2, sources[1].clone()),
        Fault::ForeignAncestor => {
            sources[1] = WorldReplayForkSourceV1::new(TimelineId::new(), None)?;
        }
        Fault::WrongInheritedHead => {
            let ancestor = sources[1]
                .required_attribution()
                .ok_or(WorldReplayVerificationErrorV1::EvidenceUnavailable)?;
            let changed = ForkReplayRequirementV1::new(
                ancestor.child_timeline_id(),
                Seq::from_u64(5),
                ancestor.signed_manifest_record_id(),
                ancestor.authority_origin_digest(),
            )
            .map_err(|_| WorldReplayVerificationErrorV1::EvidenceUnavailable)?;
            sources[1] = WorldReplayForkSourceV1::new(ancestor.child_timeline_id(), Some(changed))?;
        }
        _ => (),
    }
    Ok(())
}

impl WorldReplayVerifierV1 for NestedVerifier {
    fn verify(
        &self,
        closure: &WorldReplayClosureV1,
        requested: &WorldReplayUseV1,
        generation: ErasureReferenceV1,
    ) -> Result<VerifiedWorldReplayV1, WorldReplayVerificationErrorV1> {
        let scenario = self
            .scenario
            .lock()
            .map_err(|_| WorldReplayVerificationErrorV1::EvidenceUnavailable)?
            .ok_or(WorldReplayVerificationErrorV1::EvidenceUnavailable)?;
        let arm = self
            .sources
            .iter()
            .position(|sources| {
                sources
                    .first()
                    .is_some_and(|source| source.timeline_id() == requested.timeline_id())
            })
            .ok_or(WorldReplayVerificationErrorV1::EvidenceUnavailable)?;
        let phase = self.admissions.fetch_add(1, Ordering::SeqCst);
        let final_phase = phase >= scenario.consumer.arms();
        let fault = if scenario.target == arm {
            scenario.fault
        } else {
            Fault::None
        };
        let mut sources = self.sources[arm].clone();
        classify_fault(&mut sources, fault, final_phase)?;
        let mut required: Vec<_> = sources
            .iter()
            .filter_map(WorldReplayForkSourceV1::required_attribution)
            .collect();
        if fault == Fault::OmitRequirement {
            required.remove(1);
        } else if fault == Fault::ExtraRequirement {
            required.push(required[0]);
        }
        let arm_depth = if fault == Fault::ArmDepthShort { 1 } else { 8 };
        let bounds = EventReadBounds::new_with_total_bytes_and_elapsed(
            1_024,
            128,
            arm_depth,
            64,
            64 * 1_024,
            30_000_000,
        );
        let limits =
            ForkReplayReadLimitsV1::new(8, 65_536, 1_048_576, 256 * 1_024 * 1_024, 30_000_000)
                .map_err(|_| WorldReplayVerificationErrorV1::EvidenceUnavailable)?;
        let verified = pos_runtime::world_replay::test_verified_world_replay_with_fields_and_bounds(
            closure.digest(),
            closure.timeline_id(),
            closure.source_head(),
            requested.clone(),
            generation,
            ErasureReplayClaimV1::Exact,
            bounds,
        );
        let profile = if fault == Fault::FinalProfile && final_phase {
            0xc9
        } else {
            0xc8
        };
        Ok(
            pos_runtime::world_replay::test_verified_world_replay_with_fork_attribution(
                verified,
                Some(Hash::from_bytes([profile; 32])),
                sources,
                required,
                limits,
            ),
        )
    }
}

fn world(depth: usize) -> Fallible<World> {
    let mut world = World::new(Shape::EmptyUnclassified, false)?;
    for level in 2..depth {
        let parent = world.child_at(level - 2)?.id;
        let shape = if level % 2 == 0 {
            Shape::EmptyClassified
        } else {
            Shape::EmptyUnclassified
        };
        world.add_child_at(parent, Seq::from_u64(4), shape)?;
    }
    let parent = world.child_at(depth - 2)?.id;
    world.add_child_at(parent, Seq::from_u64(4), Shape::Mixed)?;
    world.add_child_at(parent, Seq::from_u64(4), Shape::EmptyClassified)?;
    Ok(world)
}

fn import_spec(index: usize, destroyed: bool) -> Fallible<Spec> {
    let lane = u8::try_from(index)?;
    Ok(Spec {
        child: index,
        import_seed: 0x11 + lane,
        binding_seed: 0x21 + lane,
        principal_seed: 0x41 + lane,
        admission_seed: 0x31 + lane,
        registration_seed: 0x61 + lane,
        publication_seed: 0x91 + lane,
        operations_seed: 0xa0 + 4 * lane,
        destroyed_key: destroyed,
        ..Spec::default()
    })
}

fn populate<S: Port>(
    store: &mut S,
    world: &World,
    destroyed: bool,
) -> Fallible<Vec<ForkReplayRequirementV1>> {
    world.seed_destination(store)?;
    let mut required = Vec::new();
    for (index, child) in world.children.iter().enumerate() {
        let built = world.build(&import_spec(index, destroyed)?)?;
        pin_policy(store, &built.policy)?;
        store.import_verified(&ForkAttributionAuthorityImportRequestV1 {
            envelope_bytes: &built.bytes,
            expected_issuer_policy_digest: built.policy.digest(),
            parent_timeline_id: child.parent,
            trust_anchors: &world.anchors,
        })?;
        let head = child.parent_cut + child.shape.events();
        let committed = store.read_committed(child.id, head)?;
        required.push(ForkReplayRequirementV1::new(
            child.id,
            Seq::from_u64(head),
            committed.record_id,
            committed.authority_origin_digest,
        )?);
    }
    Ok(required)
}

fn verifier(world: &World, required: &[ForkReplayRequirementV1]) -> Fallible<Arc<NestedVerifier>> {
    let depth = required.len() - 1;
    let sources_for = |leaf: usize| -> Fallible<Vec<WorldReplayForkSourceV1>> {
        let mut sources = vec![WorldReplayForkSourceV1::new(
            world.child_at(leaf)?.id,
            Some(required[leaf]),
        )?];
        for index in (0..depth - 1).rev() {
            assert_eq!(required[index].publication_logical_head(), Seq::from_u64(4));
            sources.push(WorldReplayForkSourceV1::new(
                world.child_at(index)?.id,
                Some(required[index]),
            )?);
        }
        sources.push(WorldReplayForkSourceV1::new(world.root, None)?);
        Ok(sources)
    };
    Ok(Arc::new(NestedVerifier {
        sources: [sources_for(depth - 1)?, sources_for(depth)?],
        scenario: Mutex::new(None),
        admissions: AtomicUsize::new(0),
    }))
}

fn invoke(
    host: &mut ErasureExecutionHostV1,
    registries: [&mut ProjectionRegistry; 2],
    closures: [&WorldReplayClosureV1; 2],
    fixture: &ProtectedFixture,
    consumer: Consumer,
    timelines: [TimelineId; 2],
) -> Result<Option<crate::ForkDiff>, CoreError> {
    let mut reads = host.read_sender().map_err(crate::host_error_to_core)?;
    let [a, b] = registries;
    with_release(|release| match consumer {
        Consumer::Replay => crate::replay(
            &mut reads,
            timelines[0],
            a,
            closures[0],
            release,
            &fixture.fold(),
        )
        .map(|()| None),
        Consumer::ReplayAtInherited | Consumer::ReplayAtOwn => {
            let cut = if matches!(consumer, Consumer::ReplayAtInherited) {
                2
            } else {
                5
            };
            crate::replay_at(
                &mut reads,
                timelines[0],
                Seq::from_u64(cut),
                a,
                closures[0],
                release,
                &fixture.fold(),
            )
            .map(|()| None)
        }
        Consumer::Compare => crate::compare(
            &mut reads,
            timelines,
            Seq::from_u64(4),
            [a, b],
            closures,
            release,
            [&fixture.fold(), &fixture.fold()],
        )
        .map(Some),
    })
}

fn seeded_registry(
    fixture: &ProtectedFixture,
    gate: Arc<dyn ErasureGate>,
    world: &World,
    timeline: TimelineId,
    seed: &Event,
) -> Fallible<ProjectionRegistry> {
    let mut registry = fixture.registry(gate);
    registry.bind_fork_ancestry(timeline, &pos_core::fork_ancestry(&world.source, timeline)?)?;
    registry.apply_event(timeline, seed);
    registry.apply_event(timeline, seed);
    let snapshot = registry.state_snapshot(timeline)?;
    assert_eq!(snapshot["count"].len(), 1);
    assert_eq!(
        snapshot["count"]
            .get(&seed.entity)
            .and_then(|state| state.get("n")),
        Some(&serde_json::json!(2)),
    );
    Ok(registry)
}

fn assert_success(
    world: &World,
    consumer: Consumer,
    timelines: [TimelineId; 2],
    registries: [&ProjectionRegistry; 2],
    diff: Option<crate::ForkDiff>,
) -> Fallible<()> {
    if matches!(consumer, Consumer::Compare) {
        let diff = diff.ok_or("missing Compare result")?;
        assert_eq!(diff.fork_seq, Seq::from_u64(4));
        let mut expected: Vec<_> = world
            .child_at(world.children.len() - 2)?
            .export
            .events
            .iter()
            .map(|event| event.entity)
            .collect();
        expected.sort_unstable();
        assert_eq!(diff.diverged_entities, expected);
        assert_eq!(
            registries[1].state_snapshot(timelines[1])?["count"].len(),
            4
        );
    } else {
        assert!(diff.is_none());
    }
    let installed = registries[0].state_snapshot(timelines[0])?;
    let expected = if matches!(consumer, Consumer::Compare) {
        8
    } else {
        consumer.folded()
    };
    assert_eq!(installed["count"].len(), expected);
    assert!(installed["count"]
        .entries()
        .all(|(_, state)| state.get("n") == Some(&serde_json::json!(1))));
    Ok(())
}

fn exercise(
    host: &mut ErasureExecutionHostV1,
    world: &World,
    verifier: &NestedVerifier,
    fixture: &ProtectedFixture,
    seed: &Event,
    scenario: Scenario,
) -> Fallible<()> {
    *verifier.scenario.lock().map_err(|_| "scenario poisoned")? = Some(scenario);
    verifier.admissions.store(0, Ordering::SeqCst);
    let timelines = verifier
        .sources
        .each_ref()
        .map(|sources| sources[0].timeline_id());
    let gate = host.containment_gate();
    let generation = Hash::from_bytes(gate.inventory_generation()?.digest());
    let closures = timelines
        .map(|timeline| {
            WorldReplayClosureV1::test_fixture_for_timeline_with_inventory_generation(
                timeline, generation,
            )
        })
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    let mut a = seeded_registry(fixture, Arc::clone(&gate), world, timelines[0], seed)?;
    let mut b = seeded_registry(fixture, gate, world, timelines[1], seed)?;
    let before_a = a.state_snapshot(timelines[0])?;
    let before_b = b.state_snapshot(timelines[1])?;
    FOLDED.store(0, Ordering::SeqCst);
    let result = invoke(
        host,
        [&mut a, &mut b],
        [&closures[0], &closures[1]],
        fixture,
        scenario.consumer,
        timelines,
    );
    let supported_depth = verifier.sources[0].len() <= 9;
    let succeeds = supported_depth && scenario.fault == Fault::None;
    if succeeds {
        assert_success(world, scenario.consumer, timelines, [&a, &b], result?)?;
        if scenario.consumer.arms() == 1 {
            assert_eq!(b.state_snapshot(timelines[1])?, before_b);
        }
    } else {
        assert_eq!(
            result.map(|_| ()).map_err(|error| error.to_string()),
            Err(CoreError::ArtifactUnavailable.to_string()),
        );
        assert_eq!(a.state_snapshot(timelines[0])?, before_a);
        assert_eq!(b.state_snapshot(timelines[1])?, before_b);
    }
    let folds = if supported_depth && (succeeds || scenario.fault.is_final()) {
        scenario.consumer.folded()
    } else {
        0
    };
    assert_eq!(FOLDED.load(Ordering::SeqCst), folds);
    let phases = if scenario.fault == Fault::HiddenCommonRoot {
        // The public ancestry/privacy barrier runs before either verifier,
        // staged fold or contextual native-lineage read.
        0
    } else if succeeds || (supported_depth && scenario.fault.is_final()) {
        2
    } else {
        1
    };
    assert_eq!(
        verifier.admissions.load(Ordering::SeqCst),
        phases * scenario.consumer.arms(),
    );
    Ok(())
}

fn run_cases(
    mut host: ErasureExecutionHostV1,
    world: &World,
    verifier: &NestedVerifier,
) -> Fallible<()> {
    let fixture = ProtectedFixture::new("count", count);
    let seed = world
        .source
        .read(world.root, SeqRange::all())?
        .into_iter()
        .next()
        .ok_or("root seed")?;
    for consumer in [
        Consumer::Replay,
        Consumer::ReplayAtInherited,
        Consumer::ReplayAtOwn,
        Consumer::Compare,
    ] {
        for fault in [
            Fault::None,
            Fault::OmitAncestor,
            Fault::DuplicateAncestor,
            Fault::ForeignAncestor,
            Fault::OmitRequirement,
            Fault::WrongInheritedHead,
            Fault::ExtraRequirement,
            Fault::FinalSources,
            Fault::FinalProfile,
            Fault::ArmDepthShort,
        ] {
            if verifier.sources[0].len() > 9 && fault != Fault::None {
                continue;
            }
            for target in 0..consumer.arms() {
                if fault == Fault::None && target != 0 {
                    continue;
                }
                // A successful second operation starts a fresh ledger; it
                // cannot reuse the first operation's admissions or counters.
                for _ in 0..if fault == Fault::None { 2 } else { 1 } {
                    exercise(
                        &mut host,
                        world,
                        verifier,
                        &fixture,
                        &seed,
                        Scenario {
                            consumer,
                            fault,
                            target,
                        },
                    )?;
                }
            }
        }
    }
    Ok(())
}

/// Admit a legal later root Event without changing any imported child.
/// Every child still inherits only the root prefix through sequence four.
fn hide_common_root<S>(store: &mut S, root: TimelineId) -> Fallible<()>
where
    S: EventStore + OwnTracksEnrollmentStore + GeoLocationAdmissionStore,
{
    assert_eq!(store.protected_logical_head(root)?, Seq::from_u64(4));
    let entity = EntityId::new();
    let consent = ([0x41; 32], 8, [0x42; 32]);
    store.pair_owntracks_enrollment(OwnTracksEnrollmentRequestV1::new(
        root,
        entity,
        GeoLocationAdmissionFenceV1::new(7, consent, (1, false, 9)),
        [0x43; 32],
    ))?;
    let admitted = store.admit_geo_location(GeoLocationAdmissionRequestV1::from_input(
        GeoLocationAdmissionInputV1::new(
            root,
            entity,
            CanonicalBytes::from_static(b"late root geographic admission"),
            7,
            consent,
            (1, false, 10),
            ([0x44; 32], [0x45; 32]),
        ),
    ))?;
    assert!(admitted.is_accepted());
    assert_eq!(store.protected_logical_head(root)?, Seq::from_u64(5));
    assert!(store.get_timeline(root)?.is_none());
    Ok(())
}

fn run_hidden_common_root_cases(
    mut host: ErasureExecutionHostV1,
    world: &World,
    verifier: &NestedVerifier,
) -> Fallible<()> {
    let fixture = ProtectedFixture::new("count", count);
    let seed = world
        .source
        .read(world.root, SeqRange::all())?
        .into_iter()
        .next()
        .ok_or("root seed")?;
    for consumer in [
        Consumer::Replay,
        Consumer::ReplayAtInherited,
        Consumer::ReplayAtOwn,
        Consumer::Compare,
    ] {
        exercise(
            &mut host,
            world,
            verifier,
            &fixture,
            &seed,
            Scenario {
                consumer,
                fault: Fault::HiddenCommonRoot,
                target: 0,
            },
        )?;
    }
    Ok(())
}

fn late_common_root_sqlite(
    path: &str,
    also_run_read_only: bool,
    world: &World,
    verifier: &NestedVerifier,
    composition: &ErasureCoordinatorCompositionV1,
) -> Fallible<()> {
    let mut store = SqliteStore::open(path)?;
    store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
    hide_common_root(&mut store, world.root)?;
    drop(store);
    let host = ErasureExecutionHostV1::open_with_authority(
        StoreConfig::Sqlite {
            path: path.to_owned(),
        },
        composition,
        ErasureRecoveryLimitsV1::compiled_maximum(),
    )?;
    run_hidden_common_root_cases(host, world, verifier)?;
    if also_run_read_only {
        let host = ErasureExecutionHostV1::open_read_only_with_authority(
            path,
            composition,
            ErasureRecoveryLimitsV1::compiled_maximum(),
        )?;
        run_hidden_common_root_cases(host, world, verifier)?;
    }
    Ok(())
}

#[test]
fn imported_nested_and_max_depth_histories_keep_exact_cuts_and_atomic_public_consumers(
) -> Fallible<()> {
    for depth in [2, 8, 9] {
        for destroyed in [false, true] {
            let world = world(depth)?;
            let mut memory = MemoryStore::new();
            let required = populate(&mut memory, &world, destroyed)?;
            let verifier = verifier(&world, &required)?;
            let composition = ErasureCoordinatorCompositionV1::closed()
                .with_world_replay_verifier(verifier.clone());
            let host = ErasureExecutionHostV1::recover_memory_fixture_with_authority(
                memory,
                &composition,
                ErasureRecoveryLimitsV1::compiled_maximum(),
            )?;
            run_cases(host, &world, &verifier)?;
            if depth <= 8 {
                let mut memory = MemoryStore::new();
                assert_eq!(populate(&mut memory, &world, destroyed)?, required);
                hide_common_root(&mut memory, world.root)?;
                let host = ErasureExecutionHostV1::recover_memory_fixture_with_authority(
                    memory,
                    &composition,
                    ErasureRecoveryLimitsV1::compiled_maximum(),
                )?;
                run_hidden_common_root_cases(host, &world, &verifier)?;
            }
            // Existing URI support lets the normal host recover imported rows
            // in memory without adding a test-only public transfer seam. This
            // is named shared memory, not the private SqliteInMemory variant.
            let uri = format!(
                "file:pigloros-561-nested-{}?mode=memory&cache=shared",
                TimelineId::new(),
            );
            let keeper = SqliteStore::open(&uri)?;
            let mut sqlite = SqliteStore::open(&uri)?;
            assert_eq!(populate(&mut sqlite, &world, destroyed)?, required);
            drop(sqlite);
            let host = ErasureExecutionHostV1::open_with_authority(
                StoreConfig::Sqlite { path: uri.clone() },
                &composition,
                ErasureRecoveryLimitsV1::compiled_maximum(),
            )?;
            // The gate-unbound keeper issues no command or transaction while
            // the host owns the recovered adapter and protected read interval.
            run_cases(host, &world, &verifier)?;
            if depth <= 8 {
                late_common_root_sqlite(&uri, false, &world, &verifier, &composition)?;
            }
            drop(keeper);
            let directory = tempfile::tempdir()?;
            let path = directory.path().join("nested-imported.sqlite");
            let path = path.to_str().ok_or("utf-8 path")?;
            let mut sqlite = SqliteStore::open(path)?;
            assert_eq!(populate(&mut sqlite, &world, destroyed)?, required);
            drop(sqlite);
            let host = ErasureExecutionHostV1::open_with_authority(
                StoreConfig::Sqlite {
                    path: path.to_owned(),
                },
                &composition,
                ErasureRecoveryLimitsV1::compiled_maximum(),
            )?;
            run_cases(host, &world, &verifier)?;
            let host = ErasureExecutionHostV1::open_read_only_with_authority(
                path,
                &composition,
                ErasureRecoveryLimitsV1::compiled_maximum(),
            )?;
            run_cases(host, &world, &verifier)?;
            if depth <= 8 {
                late_common_root_sqlite(path, true, &world, &verifier, &composition)?;
            }
        }
    }
    Ok(())
}
