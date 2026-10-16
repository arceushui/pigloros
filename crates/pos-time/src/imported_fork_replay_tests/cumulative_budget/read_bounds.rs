//! A finite Event allowance is distinct from the complete authority budget.

use super::super::{
    fixture::{Built, Fallible, Port, Shape, Spec, World},
    Fault, ImportedVerifier,
};
use super::{compare::import_arm, count};
use crate::test_support::{with_release, ProtectedFixture};
use pos_core::{
    store::{EventStore, SeqRange},
    CoreError, ErasureRecoveryLimitsV1, ErasureReferenceV1, Hash,
    ImportedForkAttributionAdmissionV1, Seq, TimelineId, WorldReplayClosureV1,
};
use pos_runtime::{
    ErasureCoordinatorCompositionV1, ErasureExecutionHostV1, VerifiedWorldReplayV1,
    WorldReplayUseV1, WorldReplayVerificationErrorV1, WorldReplayVerifierV1,
};
use pos_store::{memory::MemoryStore, sqlite::SqliteStore, StoreConfig};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

#[derive(Clone, Copy, Eq, PartialEq)]
enum Access {
    Memory,
    SqliteReadWrite,
    SqliteReadOnly,
    SqliteHeldMemory,
}

const ACCESSES: [Access; 4] = [
    Access::Memory,
    Access::SqliteReadWrite,
    Access::SqliteReadOnly,
    Access::SqliteHeldMemory,
];

struct EventBoundVerifier {
    owner: ImportedVerifier,
    limited: Option<TimelineId>,
}

impl WorldReplayVerifierV1 for EventBoundVerifier {
    fn read_profile(
        &self,
        closure: &WorldReplayClosureV1,
        intent: &pos_runtime::WorldReplayReadIntentV1,
        generation: ErasureReferenceV1,
    ) -> Result<
        (pos_core::EventReadBounds, pos_store::ForkReplayReadLimitsV1),
        WorldReplayVerificationErrorV1,
    > {
        self.owner
            .read_profile(closure, intent, generation)
            .map(|(bounds, limits)| {
                let count = if self.limited == Some(intent.timeline_id()) {
                    3
                } else {
                    bounds.max_events()
                };
                (
                    pos_core::EventReadBounds::new_with_total_bytes_and_elapsed(
                        bounds.max_payload_bytes(),
                        bounds.max_event_type_bytes(),
                        bounds.max_fork_depth(),
                        count,
                        bounds.max_total_bytes(),
                        bounds.max_elapsed_micros(),
                    ),
                    limits,
                )
            })
    }

    fn verify(
        &self,
        closure: &WorldReplayClosureV1,
        requested: &WorldReplayUseV1,
        generation: ErasureReferenceV1,
    ) -> Result<VerifiedWorldReplayV1, WorldReplayVerificationErrorV1> {
        self.owner.verify_with_max_events(
            closure,
            requested,
            generation,
            (self.limited == Some(requested.timeline_id())).then_some(3),
        )
    }
}

fn install<S: Port>(
    store: &mut S,
    world: &World,
    built: &[Built],
    limited: Option<TimelineId>,
) -> Fallible<Arc<EventBoundVerifier>> {
    world.seed_destination(store)?;
    let requirements = built
        .iter()
        .enumerate()
        .map(|(index, built)| {
            let admission = ImportedForkAttributionAdmissionV1::from_envelope(&built.envelope, 1)?;
            import_arm(store, world, built, &admission, index)
        })
        .collect::<Fallible<Vec<_>>>()?;
    let first = *requirements.first().ok_or("first imported arm")?;
    Ok(Arc::new(EventBoundVerifier {
        owner: ImportedVerifier {
            child: first.child_timeline_id(),
            parent: world.root,
            requirement: first,
            secondary: requirements
                .get(1)
                .map(|required| (required.child_timeline_id(), *required)),
            fault: Fault::None,
            fault_target: None,
            limits_override: None,
            admissions: AtomicUsize::new(0),
        },
        limited,
    }))
}

/// Retain the directory/idle keeper until the owned host has been consumed.
/// Direct RO recovery is never preceded by a writable Runtime host.
fn with_host(
    access: Access,
    world: &World,
    built: &[Built],
    limited: Option<TimelineId>,
    run: impl FnOnce(ErasureExecutionHostV1, &EventBoundVerifier) -> Fallible<()>,
) -> Fallible<()> {
    let recovery = ErasureRecoveryLimitsV1::compiled_maximum();
    if access == Access::Memory {
        let mut store = MemoryStore::new();
        let verifier = install(&mut store, world, built, limited)?;
        let composition =
            ErasureCoordinatorCompositionV1::closed().with_world_replay_verifier(verifier.clone());
        let host = ErasureExecutionHostV1::recover_memory_fixture_with_authority(
            store,
            &composition,
            recovery,
        )?;
        return run(host, &verifier);
    }
    let directory = (access != Access::SqliteHeldMemory)
        .then(tempfile::tempdir)
        .transpose()?;
    let path = match &directory {
        Some(directory) => directory
            .path()
            .join("imported-event-bounds.sqlite")
            .to_str()
            .ok_or("UTF-8 path")?
            .to_owned(),
        None => format!(
            "file:pigloros-561-read-bounds-{}?mode=memory&cache=shared",
            TimelineId::new(),
        ),
    };
    let keeper = if access == Access::SqliteHeldMemory {
        Some(SqliteStore::open(&path)?)
    } else {
        None
    };
    let mut store = SqliteStore::open(&path)?;
    let verifier = install(&mut store, world, built, limited)?;
    drop(store);
    let composition =
        ErasureCoordinatorCompositionV1::closed().with_world_replay_verifier(verifier.clone());
    let host = if access == Access::SqliteReadOnly {
        ErasureExecutionHostV1::open_read_only_with_authority(&path, &composition, recovery)?
    } else {
        ErasureExecutionHostV1::open_with_authority(
            StoreConfig::Sqlite { path },
            &composition,
            recovery,
        )?
    };
    run(host, &verifier)?;
    drop(keeper);
    Ok(())
}

#[test]
fn imported_event_allowance_refuses_full_replay_but_admits_its_exact_cut() -> Fallible<()> {
    let world = World::new(Shape::EmptyUnclassified, false)?;
    let built = [world.build(&Spec::default())?];
    let child = world.child_at(0)?.id;
    let root = world.source.read(world.root, SeqRange::all())?;
    assert_eq!(root.len(), 4);
    let seed = root.first().ok_or("root seed")?;
    for access in ACCESSES {
        for (limited, cut, succeeds, folded) in [
            (None, None, true, 4),
            (Some(child), None, false, 0),
            (Some(child), Some(Seq::from_u64(3)), true, 3),
            (Some(child), Some(Seq::from_u64(4)), false, 0),
        ] {
            with_host(access, &world, &built, limited, |mut host, verifier| {
                let fixture = ProtectedFixture::new("count", count);
                let gate = host.containment_gate();
                let generation = Hash::from_bytes(gate.inventory_generation()?.digest());
                let closure =
                    WorldReplayClosureV1::test_fixture_for_timeline_with_inventory_generation(
                        child, generation,
                    )?;
                let mut registry = fixture.registry(gate);
                registry
                    .bind_fork_ancestry(child, &pos_core::fork_ancestry(&world.source, child)?)?;
                for _ in 0..2 {
                    registry.apply_event(child, seed);
                }
                let before = registry.state_snapshot(child)?;
                assert_eq!(before["count"].len(), 1);
                assert_eq!(
                    before["count"]
                        .get(&seed.entity)
                        .and_then(|state| state.get("n")),
                    Some(&serde_json::json!(2)),
                );
                let mut reads = host.read_sender()?;
                let result = with_release(|release| match cut {
                    None => crate::replay(
                        &mut reads,
                        child,
                        &mut registry,
                        &closure,
                        release,
                        &fixture.fold(),
                    ),
                    Some(cut) => crate::replay_at(
                        &mut reads,
                        child,
                        cut,
                        &mut registry,
                        &closure,
                        release,
                        &fixture.fold(),
                    ),
                });
                assert_eq!(
                    verifier.owner.admissions.load(Ordering::SeqCst),
                    if succeeds { 2 } else { 1 },
                );
                if succeeds {
                    result?;
                    let after = registry.state_snapshot(child)?;
                    assert_eq!(after["count"].len(), folded);
                    for event in root.iter().take(folded) {
                        assert_eq!(
                            after["count"]
                                .get(&event.entity)
                                .and_then(|state| state.get("n")),
                            Some(&serde_json::json!(1)),
                        );
                    }
                } else {
                    // Complete imported authority is valid; the requested
                    // Event count exceeds the owner's finite allowance.
                    assert_eq!(
                        result.map_err(|error| error.to_string()),
                        Err(CoreError::ArtifactUnavailable.to_string()),
                    );
                    assert_eq!(registry.state_snapshot(child)?, before);
                }
                Ok(())
            })?;
        }
    }
    Ok(())
}

#[test]
fn imported_compare_preserves_both_states_when_either_event_allowance_is_short() -> Fallible<()> {
    let mut world = World::new(Shape::EmptyUnclassified, false)?;
    world.add_child(Shape::EmptyUnclassified)?;
    let built = [
        world.build(&Spec::default())?,
        world.build(&Spec::distinct(1))?,
    ];
    let timelines = [world.child_at(0)?.id, world.child_at(1)?.id];
    let root = world.source.read(world.root, SeqRange::all())?;
    assert_eq!(root.len(), 4);
    let seed = root.first().ok_or("root seed")?;
    for access in ACCESSES {
        for limited in [None, Some(timelines[0]), Some(timelines[1])] {
            with_host(access, &world, &built, limited, |mut host, verifier| {
                let fixture = ProtectedFixture::new("count", count);
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
                let mut a = fixture.registry(Arc::clone(&gate));
                let mut b = fixture.registry(gate);
                for (index, (registry, timeline)) in
                    [&mut a, &mut b].into_iter().zip(timelines).enumerate()
                {
                    registry.bind_fork_ancestry(
                        timeline,
                        &pos_core::fork_ancestry(&world.source, timeline)?,
                    )?;
                    for _ in 0..(index + 2) {
                        registry.apply_event(timeline, seed);
                    }
                    let before = registry.state_snapshot(timeline)?;
                    assert_eq!(before["count"].len(), 1);
                    assert_eq!(
                        before["count"]
                            .get(&seed.entity)
                            .and_then(|state| state.get("n")),
                        Some(&serde_json::json!(index + 2)),
                    );
                }
                let before = [
                    a.state_snapshot(timelines[0])?,
                    b.state_snapshot(timelines[1])?,
                ];
                let mut reads = host.read_sender()?;
                let result = with_release(|release| {
                    crate::compare(
                        &mut reads,
                        timelines,
                        Seq::from_u64(4),
                        [&mut a, &mut b],
                        [&closures[0], &closures[1]],
                        release,
                        [&fixture.fold(), &fixture.fold()],
                    )
                });
                assert_eq!(
                    verifier.owner.admissions.load(Ordering::SeqCst),
                    if limited.is_none() { 4 } else { 2 },
                );
                if limited.is_none() {
                    let diff = result?;
                    assert_eq!(diff.fork_seq, Seq::from_u64(4));
                    assert!(diff.diverged_entities.is_empty());
                    for (registry, timeline) in [&a, &b].into_iter().zip(timelines) {
                        let after = registry.state_snapshot(timeline)?;
                        assert_eq!(after["count"].len(), 4);
                        for event in &root {
                            assert_eq!(
                                after["count"]
                                    .get(&event.entity)
                                    .and_then(|state| state.get("n")),
                                Some(&serde_json::json!(1)),
                            );
                        }
                    }
                } else {
                    // Both native classifications were accepted. Refusal is
                    // the first or second complete Event read, before folding.
                    assert_eq!(
                        result.map(|_| ()).map_err(|error| error.to_string()),
                        Err(CoreError::ArtifactUnavailable.to_string()),
                    );
                    assert_eq!(a.state_snapshot(timelines[0])?, before[0]);
                    assert_eq!(b.state_snapshot(timelines[1])?, before[1]);
                }
                Ok(())
            })?;
        }
    }
    Ok(())
}
