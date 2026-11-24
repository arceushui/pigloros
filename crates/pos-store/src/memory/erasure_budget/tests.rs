//! The erasure-budget counters against the full recount (ADR-129 revision
//! 13, R13.1(1)-(2); I130 and I131 in the store, the closure parity of
//! I130/I132 in pos-runtime).

use std::sync::Arc;

use pos_core::community_lifecycle::CommunityLifecycleErrorV1 as Error;
use pos_core::store::EventStore;
use pos_core::{
    ArtifactDataClassV1, EntityId, ErasureContainmentGateV1, Hash, KeyIdentityV1,
    KeyRegistrationV1, KeyRegistryStateV1, KeyRoleV1, OwnerIdV1, Seq, TimelineId, TimelineMeta,
};
use ulid::Ulid;

use super::MemoryStore;
use crate::erasure_budget_rows::{community_rows, erasure_row, Fallible};

type TestResult = Fallible<()>;

const fn entity(byte: u8) -> EntityId {
    EntityId::from_ulid(Ulid::from_bytes([byte; 16]))
}

const fn id(byte: u8) -> TimelineId {
    TimelineId::from_ulid(Ulid::from_bytes([byte; 16]))
}

/// The actors: A owns the root and its Fork; B owns a Fork of that Fork
/// and its own root.
const A: EntityId = entity(0xa1);
const B: EntityId = entity(0xb1);

/// A's root R, its Fork C1, C1's Fork C2 (B's), B's root S and an unowned
/// root U.
const R: TimelineId = id(1);
const C1: TimelineId = id(2);
const C2: TimelineId = id(3);
const S: TimelineId = id(4);
const U: TimelineId = id(5);

fn timeline(
    store: &mut MemoryStore,
    timeline: TimelineId,
    owner: Option<EntityId>,
    parent: Option<TimelineId>,
) -> TestResult {
    store.create_timeline_with_meta(TimelineMeta {
        id: timeline,
        owner,
        fork_point: parent.map(|parent| (parent, Seq::ZERO)),
        ..TimelineMeta::root("budget")
    })?;
    Ok(())
}

fn subject_key(actor: EntityId, epoch: u64) -> Fallible<KeyIdentityV1> {
    let owner =
        pos_crypto::subject_key::subject_owner_id(actor).map_err(|error| format!("{error:?}"))?;
    Ok(KeyIdentityV1::from_parts(
        OwnerIdV1::new(owner).map_err(|error| format!("{error:?}"))?,
        KeyRoleV1::SubjectDataEncryption,
        epoch,
    ))
}

/// The store of the module doc, with every kind of row the closure counts
/// or skips and two rows bound to two Timelines each.
fn store() -> Fallible<MemoryStore> {
    let mut store = MemoryStore::new();
    store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
    timeline(&mut store, R, Some(A), None)?;
    timeline(&mut store, C1, Some(A), Some(R))?;
    timeline(&mut store, C2, Some(B), Some(C1))?;
    timeline(&mut store, S, Some(B), None)?;
    timeline(&mut store, U, None, None)?;
    let mut registry = KeyRegistryStateV1::new();
    for (material, identity) in (0x81..).zip([
        subject_key(A, 1)?,
        subject_key(A, 2)?,
        subject_key(B, 1)?,
        // A role-7 key under A's subject owner is no role-0 subject key.
        KeyIdentityV1::from_parts(
            subject_key(A, 1)?.owner_id,
            KeyRoleV1::CommunityArtifactEncryption,
            3,
        ),
    ]) {
        registry
            .register_key(KeyRegistrationV1::new(
                identity,
                Hash::from_bytes([material; 32]),
                None,
            ))
            .map_err(|error| format!("{error:?}"))?;
    }
    store.key_registry = Some(registry);
    let mut on_r = community_rows(1, 3)?;
    on_r.push(erasure_row(
        "budget-owner",
        ArtifactDataClassV1::ConsentedSharedData,
        0,
        10,
    )?);
    on_r.push(erasure_row(
        "budget-owner",
        ArtifactDataClassV1::PrivateSubjectData,
        0,
        11,
    )?);
    on_r.push(erasure_row(
        "other-owner",
        ArtifactDataClassV1::PrivateSubjectData,
        2,
        12,
    )?);
    store.bind_erasure_rows_for_test(R, on_r);
    let mut on_c1 = community_rows(20, 2)?;
    on_c1.extend(community_rows(1, 1)?);
    store.bind_erasure_rows_for_test(C1, on_c1);
    let mut on_c2 = community_rows(30, 1)?;
    on_c2.extend(community_rows(20, 1)?);
    store.bind_erasure_rows_for_test(C2, on_c2);
    let mut on_s = community_rows(40, 1)?;
    on_s.extend(community_rows(30, 1)?);
    store.bind_erasure_rows_for_test(S, on_s);
    store.bind_erasure_rows_for_test(U, community_rows(50, 1)?);
    Ok(store)
}

/// Every actor's counted `targets(A)` and `rows(U)` equal the recount.
fn assert_parity(store: &MemoryStore, actors: &[EntityId]) {
    for actor in actors {
        let (targets, rows) = store.erasure_recount_for_test(*actor);
        assert_eq!(store.erasure_targets_for_test(*actor), targets, "{actor:?}");
        for (timeline, count) in rows {
            assert_eq!(store.erasure_counts_for_test(timeline).0, count);
        }
    }
}

#[test]
fn the_counters_equal_the_closure_recount_for_every_actor_in_scope() -> TestResult {
    // I130: two Fork generations, another owner's rows of both classes, a
    // private row without a key, role-0 keys of two subjects and rows bound
    // to two Timelines.
    let store = store()?;
    assert_parity(&store, &[A, B, entity(0xc1)]);
    // A: store, three payloads, two role-0 keys; on R three community rows,
    // the keyless private row and the other owner's two-key row; on C1 two
    // more (its copy of R's first row counts once); on C2 one more.
    assert_eq!(
        store.erasure_targets_for_test(A),
        1 + 3 + 2 + (6 + 1 + 3) + 4 + 2
    );
    // B: store, C2 and S, one role-0 key, C2's two rows, S's one more.
    assert_eq!(store.erasure_targets_for_test(B), 1 + 2 + 1 + 4 + 2);
    // The consented and keyless rows count in rows(R), not in targets.
    assert_eq!(store.erasure_counts_for_test(R), (6, 6 + 1 + 3));
    let (actors, rows) = store.community_erasure_scope(C2)?;
    assert_eq!(
        actors,
        [
            (A, 22, [R, C1, C2].into_iter().collect()),
            (B, 10, [C2, S].into_iter().collect())
        ]
    );
    assert_eq!(
        rows,
        [(R, 6), (C1, 3), (C2, 2), (S, 2)].into_iter().collect()
    );
    // R's scope is A alone; an unowned root has none.
    assert_eq!(store.community_erasure_scope(R)?.0.len(), 1);
    let (actors, rows) = store.community_erasure_scope(U)?;
    assert!(actors.is_empty());
    assert!(rows.is_empty());
    Ok(())
}

#[test]
fn one_community_row_costs_two_targets_once_per_scope() -> TestResult {
    // I131: a new row raises targets(A) by exactly 2; binding it to another
    // affected Timeline adds a row there but no target; binding it into B's
    // scope costs B its two targets.
    let mut store = store()?;
    let [a, b] = [A, B].map(|actor| store.erasure_targets_for_test(actor));
    let row = community_rows(60, 1)?;
    store.bind_erasure_rows_for_test(R, row.clone());
    assert_eq!(store.erasure_targets_for_test(A), a + 2);
    assert_eq!(store.erasure_targets_for_test(B), b);
    store.bind_erasure_rows_for_test(C1, row.clone());
    assert_eq!(store.erasure_targets_for_test(A), a + 2);
    assert_eq!(store.erasure_counts_for_test(C1).0, 4);
    store.bind_erasure_rows_for_test(S, row.clone());
    assert_eq!(store.erasure_targets_for_test(A), a + 2);
    assert_eq!(store.erasure_targets_for_test(B), b + 2);
    // An existing binding is not counted again.
    store.bind_erasure_rows_for_test(S, row);
    assert_eq!(store.erasure_counts_for_test(S).0, 3);
    assert_parity(&store, &[A, B]);
    Ok(())
}

#[test]
fn a_topology_the_store_cannot_walk_gives_12() -> TestResult {
    // R13.1(1): an unknown Timeline, a Fork of a missing parent and a
    // lineage loop.
    let mut store = store()?;
    assert_eq!(
        store.community_erasure_scope(id(9)).err(),
        Some(Error::EvidenceUnavailable)
    );
    let fork = |store: &mut MemoryStore, timeline, parent| {
        if let Some(state) = store.timelines.get_mut(&timeline) {
            state.timeline.meta.fork_point = Some((parent, Seq::ZERO));
        }
    };
    fork(&mut store, S, id(9));
    assert_eq!(
        store.community_erasure_scope(S).err(),
        Some(Error::EvidenceUnavailable)
    );
    fork(&mut store, R, C1);
    assert_eq!(
        store.community_erasure_scope(C2).err(),
        Some(Error::EvidenceUnavailable)
    );
    Ok(())
}

#[test]
fn a_nil_owner_has_no_subject_keys() -> TestResult {
    // The ADR-091 subject owner of a nil entity does not exist, so the
    // closure has no role-0 key for it.
    let mut store = store()?;
    let nil = EntityId::from_ulid(Ulid::nil());
    timeline(&mut store, id(6), Some(nil), None)?;
    assert_eq!(store.erasure_targets_for_test(nil), 2);
    assert_parity(&store, &[nil]);
    Ok(())
}

#[test]
fn a_row_bound_to_three_affected_timelines_counts_once() -> TestResult {
    // I131: the three bindings sum six targets; the shared index takes
    // 2 x (3 - 1) back, so A pays the row's two targets once. B's scope
    // holds only C2 of them.
    let mut store = store()?;
    let [a, b] = [A, B].map(|actor| store.erasure_targets_for_test(actor));
    let summed = |store: &MemoryStore| -> u64 {
        [R, C1, C2]
            .iter()
            .map(|timeline| store.erasure_counts_for_test(*timeline).1)
            .sum()
    };
    let before = summed(&store);
    let row = community_rows(70, 1)?;
    for timeline in [R, C1, C2] {
        store.bind_erasure_rows_for_test(timeline, row.clone());
    }
    assert_eq!(summed(&store), before + 3 * 2);
    assert_eq!(store.erasure_targets_for_test(A), a + 2);
    assert_eq!(store.erasure_targets_for_test(B), b + 2);
    assert_parity(&store, &[A, B]);
    Ok(())
}
