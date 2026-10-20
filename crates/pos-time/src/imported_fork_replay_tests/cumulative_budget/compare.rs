//! Two imported arms share one ledger through all four validation phases.

use super::super::{
    fixture::{pin_policy, request_for, Built, Fallible, Shape, Spec, World},
    Fault, ImportedVerifier,
};
use super::{count, whole_memory_budget};
use crate::test_support::{with_release, ProtectedFixture};
use pos_core::{
    store::{EventStore, SeqRange},
    CoreError, ErasureRecoveryLimitsV1, Hash, ImportedForkAttributionAdmissionV1, Seq,
    WorldReplayClosureV1,
};
use pos_runtime::{ErasureCoordinatorCompositionV1, ErasureExecutionHostV1};
use pos_store::{
    memory::MemoryStore, ForkAttributionAuthorityImportPortV1, ForkManifestPublicationPortV1,
    ForkReplayReadLimitsV1, ForkReplayRequirementV1,
};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

pub(super) fn import_arm<S>(
    store: &mut S,
    world: &World,
    built: &Built,
    admission: &ImportedForkAttributionAdmissionV1,
    index: usize,
) -> Fallible<ForkReplayRequirementV1>
where
    S: EventStore + ForkAttributionAuthorityImportPortV1 + ForkManifestPublicationPortV1,
{
    pin_policy(store, &built.policy)?;
    let imported = store.import_verified(&request_for(world, built))?;
    assert_eq!(&imported.admission, admission);
    let child = world.child_at(index)?.id;
    let committed = store.read_committed(child, 4)?;
    assert!(committed.authority_origin_digest.is_some());
    Ok(ForkReplayRequirementV1::new(
        child,
        Seq::from_u64(4),
        committed.record_id,
        committed.authority_origin_digest,
    )?)
}

pub(super) fn exercise(
    mut host: ErasureExecutionHostV1,
    world: &World,
    verifier: &ImportedVerifier,
    succeeds: bool,
) -> Fallible<()> {
    let timelines = [world.child_at(0)?.id, world.child_at(1)?.id];
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
    let root = world.source.read(world.root, SeqRange::all())?;
    let seed = root.first().ok_or("root seed")?;
    for (index, (registry, timeline)) in [&mut a, &mut b].into_iter().zip(timelines).enumerate() {
        registry
            .bind_fork_ancestry(timeline, &pos_core::fork_ancestry(&world.source, timeline)?)?;
        for _ in 0..(index + 2) {
            registry.apply_event(timeline, seed);
        }
        let before = registry.state_snapshot(timeline)?;
        assert_eq!(before["count"].len(), 1);
        assert_eq!(
            before["count"]
                .get(&seed.entity)
                .and_then(|state| state.get("n")),
            Some(&serde_json::json!(index + 2))
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
    // Both final admissions occur after both folds, before final native work.
    assert_eq!(verifier.admissions.load(Ordering::SeqCst), 4);
    if succeeds {
        let diff = result?;
        assert_eq!(diff.fork_seq, Seq::from_u64(4));
        assert!(diff.diverged_entities.is_empty());
        for (registry, timeline) in [&a, &b].into_iter().zip(timelines) {
            let after = registry.state_snapshot(timeline)?;
            assert_eq!(after["count"].len(), 4);
            assert!(after["count"]
                .entries()
                .all(|(_, state)| state.get("n") == Some(&serde_json::json!(1))));
        }
    } else {
        assert_eq!(
            result.map(|_| ()).map_err(|error| error.to_string()),
            Err(CoreError::ArtifactUnavailable.to_string())
        );
        assert_eq!(a.state_snapshot(timelines[0])?, before[0]);
        assert_eq!(b.state_snapshot(timelines[1])?, before[1]);
    }
    Ok(())
}

#[test]
fn imported_memory_compare_shares_one_exact_budget_across_both_arms() -> Fallible<()> {
    let mut world = World::new(Shape::EmptyUnclassified, false)?;
    world.add_child(Shape::EmptyUnclassified)?;
    assert_eq!(world.children.len(), 2);
    let built = [
        world.build(&Spec::default())?,
        world.build(&Spec::distinct(1))?,
    ];
    let admissions = [
        ImportedForkAttributionAdmissionV1::from_envelope(&built[0].envelope, 1)?,
        ImportedForkAttributionAdmissionV1::from_envelope(&built[1].envelope, 1)?,
    ];
    // Each arm really scans both imported admission rows; no cache/refund is
    // assumed across arms or phases. Both arms fold the same four root Events.
    let left = whole_memory_budget(&world, &built[0], &admissions[0], 0, 4)?;
    let right = whole_memory_budget(&world, &built[1], &admissions[1], 1, 4)?;
    let (bytes, rows, visits) = (left.0 + right.0, left.1 + right.1, left.2 + right.2);
    assert_eq!((rows, visits), (162, 54));
    for (bytes, rows, visits, succeeds) in [
        (bytes, rows, visits, true),
        (bytes + 1, rows, visits, true),
        (bytes, rows + 1, visits, true),
        (bytes, rows, visits + 1, true),
        (bytes - 1, rows, visits, false),
        (bytes, rows - 1, visits, false),
        (bytes, rows, visits - 1, false),
    ] {
        let mut store = MemoryStore::new();
        world.seed_destination(&mut store)?;
        let requirements = [
            import_arm(&mut store, &world, &built[0], &admissions[0], 0)?,
            import_arm(&mut store, &world, &built[1], &admissions[1], 1)?,
        ];
        let verifier = Arc::new(ImportedVerifier {
            child: requirements[0].child_timeline_id(),
            parent: world.root,
            requirement: requirements[0],
            secondary: Some((requirements[1].child_timeline_id(), requirements[1])),
            fault: Fault::None,
            fault_target: None,
            limits_override: Some(ForkReplayReadLimitsV1::new(
                8, visits, rows, bytes, 30_000_000,
            )?),
            admissions: AtomicUsize::new(0),
        });
        let composition =
            ErasureCoordinatorCompositionV1::closed().with_world_replay_verifier(verifier.clone());
        let host = ErasureExecutionHostV1::recover_memory_fixture_with_authority(
            store,
            &composition,
            ErasureRecoveryLimitsV1::compiled_maximum(),
        )?;
        exercise(host, &world, &verifier, succeeds)?;
    }
    Ok(())
}
