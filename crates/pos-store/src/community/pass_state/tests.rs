//! The Memory domain's pass read port: what each read serves from the
//! domain's pass state, the per-generation counted set of ADR-129
//! revision 14 (RN.1(1)), the pending-reservation ledger of revision 13
//! (R13.1(4)) and the per-Timeline `F_q^rows` of revision 14 (RN.3).

use std::collections::BTreeMap;
use std::sync::Arc;

use pos_core::community_lifecycle::{
    CommunityGraphCountsV1, CommunityLifecycleErrorV1 as Error, CommunityNativeNodeReferenceV1,
    CommunityPassGraphTermsV1, CommunityScopeMemberV1, CommunitySharedCountsV1,
    CommunityTypedInputRefV1,
};
use pos_core::store::EventStore;
use pos_core::{
    EntityId, ErasureArtifactClassV1, ErasureContainmentGateV1, Hash, Seq, TimelineId, TimelineMeta,
};
use ulid::Ulid;

use super::{CommunityGenerationCountsV1, CommunityPassStateV1, EMPTY_GRAPH};
use crate::community::erasure_budget::{
    CommunityErasureBudgetPortV1, CommunityPendingReservationV1,
};
use crate::community::pass_planner::CommunityPassReadPortV1;
use crate::community::MemoryCommunityDomainV1;
use crate::memory::MemoryStore;
use crate::MemoryTrustedClockAuthorityV1;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const GENERATION: [u8; 16] = [0x20; 16];
const OTHER_GENERATION: [u8; 16] = [0x21; 16];

fn id(byte: u8) -> TimelineId {
    TimelineId::from_ulid(Ulid::from_bytes([byte; 16]))
}

fn actor(byte: u8) -> EntityId {
    EntityId::from_ulid(Ulid::from_bytes([byte; 16]))
}

const fn hash(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
}

/// A store holding T (`id(1)`) and its Fork child (`id(2)`) owned by the
/// second actor, and an unrelated Timeline (`id(3)`) of that actor. The
/// first actor owns T.
fn store() -> Result<MemoryStore, Box<dyn std::error::Error>> {
    let mut store = MemoryStore::new();
    store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
    store.create_timeline_with_meta(TimelineMeta {
        id: id(1),
        ..TimelineMeta::root_owned("t", actor(10))
    })?;
    store.create_timeline_with_meta(TimelineMeta {
        id: id(2),
        owner: Some(actor(11)),
        fork_point: Some((id(1), Seq::ZERO)),
        ..TimelineMeta::root("child")
    })?;
    store.create_timeline_with_meta(TimelineMeta {
        id: id(3),
        ..TimelineMeta::root_owned("other", actor(11))
    })?;
    Ok(store)
}

/// A domain over [`store`].
fn domain() -> Result<MemoryCommunityDomainV1, Box<dyn std::error::Error>> {
    Ok(MemoryCommunityDomainV1::new(
        store()?,
        [0x5a; 16],
        MemoryTrustedClockAuthorityV1::new(),
    )?)
}

fn state() -> CommunityPassStateV1 {
    CommunityPassStateV1 {
        generation: GENERATION,
        profile_digest: hash(31),
        head: hash(30),
        counters: CommunitySharedCountsV1 {
            nodes: 1,
            edges: 2,
            declared_inputs: 3,
            encoded_record_bytes: 4,
        },
        graph: CommunityGraphCountsV1 {
            registrations: 5,
            edges: 6,
            keys: 7,
            maximum_depth: 8,
            registration_bytes: 9,
            artifact_bytes: 10,
        },
        closure: std::iter::once(hash(1)).collect(),
        observations: BTreeMap::new(),
        scope_rows: BTreeMap::new(),
        generations: BTreeMap::new(),
        highest_pass_ordinal: 0,
        retained: BTreeMap::new(),
    }
}

fn artifact(byte: u8) -> CommunityTypedInputRefV1<'static> {
    CommunityTypedInputRefV1::Artifact {
        owner_reference: hash(20),
        artifact_class: ErasureArtifactClassV1::TimelineReplay,
        artifact_digest: hash(byte),
        registration_address: hash(22),
        source_scope_binding_digest: hash(23),
    }
}

fn reference() -> CommunityNativeNodeReferenceV1 {
    CommunityNativeNodeReferenceV1 {
        store_incarnation: [0x5a; 16],
        producer_ordinal: 3,
        node_ordinal: 1,
        node_digest: hash(9),
    }
}

/// The reads of a Timeline with no pass state serve nothing.
#[test]
fn a_timeline_without_state_serves_empty_reads() -> TestResult {
    let domain = domain()?;
    assert!(domain.recorded_set_counters(id(1)) == CommunitySharedCountsV1::default());
    assert_eq!(domain.retained_pass_outcomes(id(1), GENERATION), 0);
    assert_eq!(domain.control_operations(id(1), GENERATION), 0);
    assert_eq!(domain.selected_graph(id(1)), EMPTY_GRAPH);
    assert!(!domain.event_source_in_closure(id(1), hash(1)));
    assert_eq!(
        domain.observation_graph(id(1), reference()),
        CommunityPassGraphTermsV1::default()
    );
    let metadata = artifact(2);
    assert_eq!(
        domain.scope_rows(id(1), metadata).err(),
        Some(Error::EvidenceUnavailable)
    );
    assert_eq!(domain.live_keys(), 0);
    Ok(())
}

/// R10.3(6), R10.4(4), R11.3 and R11.4(3): each read serves its Timeline's
/// state, and the counts of one generation are not another's.
#[test]
fn the_reads_serve_the_timelines_state() -> TestResult {
    let mut domain = domain()?;
    let mut held = state();
    let terms = CommunityPassGraphTermsV1 {
        registrations: 2,
        edges: 3,
        keys: 4,
        registration_bytes: 5,
        artifact_bytes: 6,
    };
    held.observations.insert(reference(), terms);
    let row = CommunityScopeMemberV1 {
        scope_reference: hash(1),
        source_timeline: id(1),
        owner_reference: hash(2),
        retention_lease_reference: hash(3),
        not_after_micros: 4,
    };
    let metadata = artifact(2);
    held.scope_rows.insert(metadata.digest(), vec![row]);
    held.generations.insert(
        GENERATION,
        CommunityGenerationCountsV1 {
            outcomes: 11,
            materializations: 3,
            annotations: 4,
        },
    );
    domain.pass_states.insert(id(1), held);

    assert!(domain.recorded_set_counters(id(1)) == state().counters);
    assert!(domain.recorded_set_counters(id(2)) == CommunitySharedCountsV1::default());
    assert_eq!(domain.selected_graph(id(1)), state().graph);
    assert_eq!(domain.selected_graph(id(2)), EMPTY_GRAPH);
    assert!(domain.event_source_in_closure(id(1), hash(1)));
    assert!(!domain.event_source_in_closure(id(1), hash(2)));
    assert_eq!(domain.observation_graph(id(1), reference()), terms);
    let other = CommunityNativeNodeReferenceV1 {
        producer_ordinal: 4,
        ..reference()
    };
    assert_eq!(
        domain.observation_graph(id(1), other),
        CommunityPassGraphTermsV1::default()
    );
    let rows = domain.scope_rows(id(1), metadata)?;
    assert!(rows.len() == 1 && rows[0] == row);
    let missing = artifact(3);
    assert_eq!(
        domain.scope_rows(id(1), missing).err(),
        Some(Error::EvidenceUnavailable)
    );

    assert_eq!(domain.retained_pass_outcomes(id(1), GENERATION), 11);
    assert_eq!(domain.retained_pass_outcomes(id(1), OTHER_GENERATION), 0);
    assert_eq!(domain.retained_pass_outcomes(id(2), GENERATION), 0);
    // RN.1(1): exactly the materializations and the Annotation CPN1s.
    assert_eq!(domain.control_operations(id(1), GENERATION), 7);
    assert_eq!(domain.control_operations(id(1), OTHER_GENERATION), 0);
    assert_eq!(domain.control_operations(id(2), GENERATION), 0);
    Ok(())
}

/// R14, RN.1(1): a generation's control operations are the sum of the two
/// counted kinds and saturate instead of wrapping.
#[test]
fn the_counted_set_is_the_materializations_and_the_annotations() {
    let counts = |materializations, annotations| CommunityGenerationCountsV1 {
        outcomes: 100,
        materializations,
        annotations,
    };
    assert_eq!(counts(0, 0).control_operations(), 0);
    assert_eq!(counts(5, 0).control_operations(), 5);
    assert_eq!(counts(0, 6).control_operations(), 6);
    assert_eq!(counts(u64::MAX, 1).control_operations(), u64::MAX);
}

/// R13.1(4): an actor's pending demand is the ledger entries on its
/// affected Timelines: its own and its Fork descendants'.
#[test]
fn the_pending_demand_follows_each_actors_scope() -> TestResult {
    let mut domain = domain()?;
    let entry = |targets, rows| CommunityPendingReservationV1 { targets, rows };
    domain
        .pending_reservations
        .insert((id(1), [1; 16]), entry(10, 3));
    domain
        .pending_reservations
        .insert((id(1), [2; 16]), entry(5, 2));
    domain
        .pending_reservations
        .insert((id(2), [3; 16]), entry(7, 1));
    domain
        .pending_reservations
        .insert((id(3), [4; 16]), entry(100, 50));

    // The first actor owns T and, through the Fork, its child.
    let first = domain.pending_erasure_demand(actor(10));
    assert_eq!(first.targets, 22);
    assert_eq!(first.rows, BTreeMap::from([(id(1), 5), (id(2), 1)]));
    // The second owns the child and the unrelated Timeline.
    let second = domain.pending_erasure_demand(actor(11));
    assert_eq!(second.targets, 107);
    assert_eq!(second.rows, BTreeMap::from([(id(2), 1), (id(3), 50)]));
    let none = domain.pending_erasure_demand(actor(12));
    assert_eq!((none.targets, none.rows.len()), (0, 0));
    Ok(())
}

/// ADR-129 revision 14, RN.3 and O10: the budget carries each Timeline's
/// unspent `SetReason` rows, half its unspent `F_q` targets: `4n` per
/// context, less one row per `(member, reason)` pair spent.
#[test]
fn the_budget_holds_the_unspent_quarantine_rows_per_timeline() -> TestResult {
    let mut domain = domain()?;
    domain.count_erasure_context(id(1), 3);
    domain.count_erasure_context(id(2), 1);
    let rows = domain.erasure_budget(id(1))?.quarantine_rows;
    assert_eq!(rows, BTreeMap::from([(id(1), 12), (id(2), 4)]));
    // Two active pairs spent two targets and one row each.
    domain.count_quarantine_pairs(id(1), 0, 2);
    let rows = domain.erasure_budget(id(1))?.quarantine_rows;
    assert_eq!(rows, BTreeMap::from([(id(1), 10), (id(2), 4)]));
    // A Timeline of the scope with no context holds none.
    domain.erasure_contexts.remove(&id(2));
    let rows = domain.erasure_budget(id(1))?.quarantine_rows;
    assert_eq!(rows, BTreeMap::from([(id(1), 10)]));
    Ok(())
}
