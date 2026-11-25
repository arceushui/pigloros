//! The Reserve, Commit and Abort transitions: their writer re-checks in the
//! R10.7 step-5j order, the counted set of ADR-129 revision 14 and the
//! pending ledger of revision 13 (R13.1(4)).

use std::collections::BTreeMap;
use std::sync::Arc;

use pos_core::community_lifecycle::{
    CommunityGraphCountsV1, CommunityLifecycleErrorV1 as Error, CommunityNativeNodeReferenceV1,
    CommunityPassGraphTermsV1, CommunityPassKeyV1, CommunityQuarantineReasonEvidenceV1,
    CommunityQuarantineReasonV1, CommunityReservationInputV1, CommunityScopeMemberV1,
    CommunitySharedCountsV1, COMMUNITY_CONTROL_OPERATIONS_V1,
    COMMUNITY_DECISION_DEADLINE_MICROS_V1, COMMUNITY_ERASURE_ROW_LIMIT_V1,
    COMMUNITY_ERASURE_TARGET_LINE_V1, COMMUNITY_RETAINED_PASS_OUTCOMES_V1,
};
use pos_core::store::EventStore;
use pos_core::{
    AuthorityTrustRootSealV1, EntityId, ErasureContainmentGateV1, Hash, Seq, TimelineId,
    TimelineMeta,
};
use ulid::Ulid;

use super::super::erasure_budget::CommunityErasureBudgetPortV1;
use super::super::erasure_budget::{
    CommunityErasureActorV1, CommunityErasureBudgetV1, CommunityPendingErasureV1,
    CommunityPendingReservationV1,
};
use super::super::pass_planner::{trace_room, CommunityPassReadPortV1};
use super::super::pass_record::{CommunityPassStatusV1, CommunityReservedPassV1};
use super::super::pass_state::{CommunityGenerationCountsV1, CommunityPassStateV1};
use super::super::quarantine::QuarantineLedgerV1;
use super::{
    add_counts, CommunityCommitInputV1, CommunityMintedObservationV1, CommunityReserveInputV1,
};
use crate::community::MemoryCommunityDomainV1;
use crate::memory::MemoryStore;
use crate::MemoryTrustedClockAuthorityV1;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const SEAL: AuthorityTrustRootSealV1 = AuthorityTrustRootSealV1::for_composition_root();
const GENERATION: [u8; 16] = [0x20; 16];
const OPERATION: [u8; 16] = [0x30; 16];
const SAMPLE: u64 = 1_000;
/// A recording horizon one microsecond past the decision bound.
const RECORDING: u64 = SAMPLE + COMMUNITY_DECISION_DEADLINE_MICROS_V1 + 1;

fn id(byte: u8) -> TimelineId {
    TimelineId::from_ulid(Ulid::from_bytes([byte; 16]))
}

fn actor(byte: u8) -> EntityId {
    EntityId::from_ulid(Ulid::from_bytes([byte; 16]))
}

const fn hash(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
}

const fn counts(base: u64) -> CommunitySharedCountsV1 {
    CommunitySharedCountsV1 {
        nodes: base,
        edges: base + 1,
        declared_inputs: base + 2,
        encoded_record_bytes: base + 3,
    }
}

/// T (`id(1)`, the first actor's) with a Fork child (`id(2)`, the second
/// actor's), both inside the first actor's affected scope.
fn domain() -> Result<MemoryCommunityDomainV1, Box<dyn std::error::Error>> {
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
    let mut domain =
        MemoryCommunityDomainV1::new(store, [0x5a; 16], MemoryTrustedClockAuthorityV1::new())?;
    domain.pass_states.insert(id(1), pass_state());
    Ok(domain)
}

/// T's state: generation, head and counters the inputs name.
fn pass_state() -> CommunityPassStateV1 {
    CommunityPassStateV1 {
        generation: GENERATION,
        head: hash(30),
        counters: counts(100),
        graph: CommunityGraphCountsV1 {
            registrations: 1,
            edges: 2,
            keys: 3,
            maximum_depth: 4,
            registration_bytes: 5,
            artifact_bytes: 6,
        },
        closure: std::iter::once(hash(1)).collect(),
        observations: BTreeMap::new(),
        scope_rows: BTreeMap::new(),
        generations: BTreeMap::new(),
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

const TERMS: CommunityPassGraphTermsV1 = CommunityPassGraphTermsV1 {
    registrations: 2,
    edges: 3,
    keys: 4,
    registration_bytes: 5,
    artifact_bytes: 6,
};

fn scope_row() -> CommunityScopeMemberV1 {
    CommunityScopeMemberV1 {
        scope_reference: hash(1),
        source_timeline: id(1),
        owner_reference: hash(2),
        retention_lease_reference: hash(3),
        not_after_micros: 4,
    }
}

fn minted() -> CommunityMintedObservationV1 {
    CommunityMintedObservationV1 {
        reference: reference(),
        graph: TERMS,
        additions: counts(10),
        rows: 6,
        scope_reference: hash(40),
        scope: vec![scope_row()],
    }
}

/// A Reserve of 24 pass rows with `F_p` of 4 targets, minting.
fn input() -> Result<CommunityReserveInputV1, Error> {
    Ok(CommunityReserveInputV1 {
        timeline: id(1),
        generation: GENERATION,
        reservation_operation_id: OPERATION,
        selected_head: hash(30),
        prior_shared_counts: counts(100),
        roster_quarantine_keys: vec![hash(50), hash(51)],
        recording_not_after_micros: RECORDING,
        reservation_sample_micros: SAMPLE,
        pass_rows: 24,
        failure_reserve: 4,
        minted: Some(minted()),
        pass: reserved_pass()?,
    })
}

/// A pass key of a nonzero coordinate.
fn pass_key(
    timeline: TimelineId,
    generation: [u8; 16],
    ordinal: u64,
) -> Result<CommunityPassKeyV1, Error> {
    CommunityPassKeyV1::new(timeline, generation, ordinal)
}

/// The record facts of the pass `input()?` reserves: ordinal 7, whose
/// predecessor is the head T selects.
fn reserved_pass() -> Result<CommunityReservedPassV1, Error> {
    let reservation = CommunityReservationInputV1 {
        pass_key: pass_key(id(1), GENERATION, 7)?,
        request_digest: hash(80),
        native_producer_ordinal: 5,
        predecessor_head_digest: hash(30),
        roster_digest: hash(81),
        prepared_input_set_digest: hash(82),
        profile_digest: hash(83),
        evidence_not_after_micros: 9_000,
    };
    Ok(CommunityReservedPassV1 {
        reservation,
        cbq1_digest: hash(84),
        quote_maxima: [1, 2, 3],
        trace_rows: 6,
        generation_horizon_micros: 9_000,
        outcome_horizon_micros: 8_000,
    })
}

fn reuse() -> Result<CommunityReserveInputV1, Error> {
    Ok(CommunityReserveInputV1 {
        minted: None,
        ..input()?
    })
}

/// A second operation of T: another identity and pass key, over the head
/// and counters the domain holds now.
fn other_operation(
    domain: &MemoryCommunityDomainV1,
) -> Result<CommunityReserveInputV1, Box<dyn std::error::Error>> {
    let state = domain.pass_states.get(&id(1)).ok_or("state")?;
    let mut other = input()?;
    other.selected_head = state.head;
    other.prior_shared_counts = state.counters;
    other.reservation_operation_id = [0x77; 16];
    other.pass.reservation.pass_key = pass_key(id(1), GENERATION, 8)?;
    other.pass.reservation.predecessor_head_digest = state.head;
    Ok(other)
}

/// The record facts a caller binds to what it planned over: the input's
/// Timeline, generation and head.
fn bound(mut call: CommunityReserveInputV1) -> Result<CommunityReserveInputV1, Error> {
    call.pass.reservation.pass_key = pass_key(call.timeline, call.generation, 7)?;
    call.pass.reservation.predecessor_head_digest = call.selected_head;
    Ok(call)
}

fn pending(domain: &MemoryCommunityDomainV1) -> Option<(u64, u64)> {
    domain
        .pending_reservations
        .get(&(id(1), OPERATION))
        .map(|entry| (entry.targets, entry.rows))
}

fn commit_input() -> CommunityCommitInputV1 {
    CommunityCommitInputV1 {
        timeline: id(1),
        reservation_operation_id: OPERATION,
        selected_head: hash(31),
        graph: CommunityGraphCountsV1 {
            registrations: 11,
            edges: 12,
            keys: 13,
            maximum_depth: 14,
            registration_bytes: 15,
            artifact_bytes: 16,
        },
        additions: counts(1000),
        annotations: 3,
        closure: vec![hash(60), hash(61)],
        observation: Some(reference()),
        bound_rows: 20,
        scope_rows: vec![(hash(70), vec![scope_row()])],
    }
}

const fn sum(a: CommunitySharedCountsV1, b: CommunitySharedCountsV1) -> CommunitySharedCountsV1 {
    add_counts(a, b)
}

/// A minting Reserve applied: R10.3(6) adds the materialization's
/// additions, R14 counts one control operation and one retained outcome,
/// and R13.1(4) holds only the remainder and `F_p` as the pending entry.
#[test]
fn a_minting_reserve_advances_the_state_and_the_ledger() -> TestResult {
    let mut domain = domain()?;
    let staged = domain.stage_reserve(input()?)?;
    // Staging changes nothing.
    assert_eq!(pending(&domain), None);
    assert_eq!(domain.retained_pass_outcomes(id(1), GENERATION), 0);

    domain.apply_reserve(&SEAL, staged)?;
    // 24 rows, 6 of them the materialization's: 18 pass rows, 2 targets
    // each, and `F_p` of 4 targets and 2 rows.
    assert_eq!(pending(&domain), Some((40, 20)));
    assert_eq!(domain.retained_pass_outcomes(id(1), GENERATION), 1);
    assert_eq!(domain.control_operations(id(1), GENERATION), 1);
    assert!(domain.recorded_set_counters(id(1)) == sum(counts(100), counts(10)));
    assert_eq!(domain.recorded_set_counters(id(1)).nodes, 110);
    assert_eq!(domain.observation_graph(id(1), reference()), TERMS);
    let state = domain.pass_states.get(&id(1)).ok_or("state")?;
    let rows = state.scope_rows.get(&hash(40)).ok_or("scope rows")?;
    assert!(rows.len() == 1 && rows[0] == scope_row());
    let demand = domain.pending_erasure_demand(actor(10));
    assert_eq!(demand.targets, 40);
    assert_eq!(demand.rows, BTreeMap::from([(id(1), 20)]));
    // Another generation's counts are untouched.
    assert_eq!(domain.retained_pass_outcomes(id(1), [0x21; 16]), 0);
    Ok(())
}

/// R10.4(4): a reused observation needs no control operation and adds
/// nothing to the counters, and its pending entry holds every row.
#[test]
fn a_reusing_reserve_counts_an_outcome_only() -> TestResult {
    let mut domain = domain()?;
    let staged = domain.stage_reserve(reuse()?)?;
    domain.apply_reserve(&SEAL, staged)?;
    assert_eq!(pending(&domain), Some((52, 26)));
    assert_eq!(domain.retained_pass_outcomes(id(1), GENERATION), 1);
    assert_eq!(domain.control_operations(id(1), GENERATION), 0);
    assert!(domain.recorded_set_counters(id(1)) == counts(100));
    let state = domain.pass_states.get(&id(1)).ok_or("state")?;
    assert!(state.observations.is_empty() && state.scope_rows.is_empty());
    Ok(())
}

/// The counters add every field and saturate like every counter.
#[test]
fn counters_add_field_by_field_and_saturate() {
    let fields = |counters: CommunitySharedCountsV1| {
        (
            counters.nodes,
            counters.edges,
            counters.declared_inputs,
            counters.encoded_record_bytes,
        )
    };
    assert_eq!(fields(add_counts(counts(1), counts(10))), (11, 13, 15, 17));
    let top = CommunitySharedCountsV1 {
        nodes: u64::MAX,
        edges: u64::MAX,
        declared_inputs: u64::MAX,
        encoded_record_bytes: u64::MAX,
    };
    assert_eq!(fields(add_counts(top, counts(1))), fields(top));
}

/// Composition preconditions come first: no pass state is unavailable
/// evidence, a materialization binding more rows than the pass is a bad
/// binding, and a reservation identity already recorded is a conflict.
#[test]
fn a_reserve_needs_state_a_fitting_materialization_and_a_new_identity() -> TestResult {
    let mut domain = domain()?;
    let elsewhere = CommunityReserveInputV1 {
        timeline: id(2),
        ..input()?
    };
    assert_eq!(
        domain.stage_reserve(bound(elsewhere)?).err(),
        Some(Error::EvidenceUnavailable)
    );
    let exact = CommunityReserveInputV1 {
        pass_rows: 6,
        ..input()?
    };
    assert!(domain.stage_reserve(exact).is_ok());
    let over = CommunityReserveInputV1 {
        pass_rows: 5,
        ..input()?
    };
    assert_eq!(
        domain.stage_reserve(over).err(),
        Some(Error::InvalidBinding)
    );
    let staged = domain.stage_reserve(input()?)?;
    domain.apply_reserve(&SEAL, staged)?;
    assert_eq!(domain.stage_reserve(input()?).err(), Some(Error::Conflict));
    Ok(())
}

/// R10.7 step 5j: the generation (5), then the head, the counters and
/// the budget (6), then the quarantine (9), then the caps (14), then the
/// recording horizon (19). Each stale value is shown first, then fixed.
#[test]
fn the_writer_refuses_in_the_step_5j_order() -> TestResult {
    let mut domain = domain()?;
    domain.quarantine_index.insert(
        hash(50),
        QuarantineLedgerV1 {
            head: hash(41),
            ordinal: 1,
            reasons: vec![CommunityQuarantineReasonEvidenceV1 {
                reason: CommunityQuarantineReasonV1::Trapped,
                failure_evidence_digest: hash(42),
            }],
            evidence_not_after_micros: RECORDING,
        },
    );
    domain.pass_states.entry(id(1)).and_modify(|state| {
        state.generations.insert(
            GENERATION,
            CommunityGenerationCountsV1 {
                outcomes: COMMUNITY_RETAINED_PASS_OUTCOMES_V1,
                ..CommunityGenerationCountsV1::default()
            },
        );
    });
    let mut every = CommunityReserveInputV1 {
        generation: [0x21; 16],
        selected_head: hash(99),
        prior_shared_counts: counts(7),
        pass_rows: u64::MAX / 4,
        recording_not_after_micros: SAMPLE,
        ..input()?
    };
    let refusal = |domain: &MemoryCommunityDomainV1, input: &CommunityReserveInputV1| {
        bound(input.clone()).map_or_else(Some, |call| domain.stage_reserve(call).err())
    };
    assert_eq!(refusal(&domain, &every), Some(Error::StaleGeneration));
    every.generation = GENERATION;
    assert_eq!(refusal(&domain, &every), Some(Error::StaleFrontier));
    every.selected_head = hash(30);
    assert_eq!(refusal(&domain, &every), Some(Error::StaleFrontier));
    every.prior_shared_counts = counts(100);
    assert_eq!(refusal(&domain, &every), Some(Error::StaleFrontier));
    every.pass_rows = 24;
    assert_eq!(refusal(&domain, &every), Some(Error::Quarantined));
    domain.quarantine_index.clear();
    assert_eq!(refusal(&domain, &every), Some(Error::CapacityExhausted));
    domain.pass_states.entry(id(1)).and_modify(|state| {
        state.generations.clear();
    });
    assert_eq!(refusal(&domain, &every), Some(Error::RecordingUnavailable));
    every.recording_not_after_micros = RECORDING;
    assert!(refusal(&domain, &every).is_none());
    Ok(())
}

/// R10.7 5j: a quarantine row with no active reason is not a refusal, and
/// any roster member's active reason is.
#[test]
fn only_an_active_reason_quarantines() -> TestResult {
    let mut domain = domain()?;
    let ledger = |reasons| QuarantineLedgerV1 {
        head: hash(41),
        ordinal: 1,
        reasons,
        evidence_not_after_micros: RECORDING,
    };
    domain.quarantine_index.insert(hash(50), ledger(Vec::new()));
    assert!(domain.stage_reserve(input()?).is_ok());
    domain.quarantine_index.insert(
        hash(51),
        ledger(vec![CommunityQuarantineReasonEvidenceV1 {
            reason: CommunityQuarantineReasonV1::Revoked,
            failure_evidence_digest: hash(42),
        }]),
    );
    assert_eq!(
        domain.stage_reserve(input()?).err(),
        Some(Error::Quarantined)
    );
    Ok(())
}

fn set_counts(
    domain: &mut MemoryCommunityDomainV1,
    outcomes: u64,
    materializations: u64,
    annotations: u64,
) {
    domain.pass_states.entry(id(1)).and_modify(|state| {
        state.generations.insert(
            GENERATION,
            CommunityGenerationCountsV1 {
                outcomes,
                materializations,
                annotations,
            },
        );
    });
}

/// R10.4(4): the control-operation cap refuses only a minting Reserve, and
/// only at the cap; the outcome cap refuses either.
#[test]
fn the_control_operation_cap_refuses_a_minting_reserve_at_the_cap() -> TestResult {
    let mut domain = domain()?;
    let below = COMMUNITY_RETAINED_PASS_OUTCOMES_V1 - 1;
    // One below the cap: both counted kinds make up the count.
    set_counts(&mut domain, below, 1, COMMUNITY_CONTROL_OPERATIONS_V1 - 2);
    assert!(domain.stage_reserve(input()?).is_ok());
    set_counts(&mut domain, below, 1, COMMUNITY_CONTROL_OPERATIONS_V1 - 1);
    assert_eq!(
        domain.stage_reserve(input()?).err(),
        Some(Error::CapacityExhausted)
    );
    // A reused observation needs no control operation.
    assert!(domain.stage_reserve(reuse()?).is_ok());
    set_counts(&mut domain, COMMUNITY_RETAINED_PASS_OUTCOMES_V1, 0, 0);
    assert_eq!(
        domain.stage_reserve(reuse()?).err(),
        Some(Error::CapacityExhausted)
    );
    Ok(())
}

/// R10.4(3): the recording horizon must pass `t_r` plus the decision
/// deadline; the writer shares the planner's check.
#[test]
fn the_recording_horizon_is_judged_at_the_writer() -> TestResult {
    let domain = domain()?;
    let base = input()?;
    let at = |recording_not_after_micros| CommunityReserveInputV1 {
        recording_not_after_micros,
        ..base.clone()
    };
    assert_eq!(
        domain.stage_reserve(at(RECORDING - 1)).err(),
        Some(Error::RecordingUnavailable)
    );
    assert!(domain.stage_reserve(at(RECORDING)).is_ok());
    Ok(())
}

/// R13.1(4): the writer re-reads the budget with every other pending
/// reservation counted, and a misfit is 6. The targets line is exact.
#[test]
fn the_writer_rereads_the_target_line_with_the_pending_ledger() -> TestResult {
    let mut domain = domain()?;
    let committed = domain
        .erasure_budget(id(1))?
        .actors
        .iter()
        .map(|actor| actor.targets)
        .max()
        .ok_or("T has an actor")?;
    // 24 rows at two targets each and `F_p` of 4 targets are 52 targets.
    let room = COMMUNITY_ERASURE_TARGET_LINE_V1 - committed - 52;
    let held = |targets| CommunityPendingReservationV1 { targets, rows: 0 };
    domain
        .pending_reservations
        .insert((id(2), [1; 16]), held(room));
    assert!(domain.stage_reserve(input()?).is_ok());
    domain
        .pending_reservations
        .insert((id(2), [1; 16]), held(room + 1));
    assert_eq!(
        domain.stage_reserve(input()?).err(),
        Some(Error::StaleFrontier)
    );
    Ok(())
}

/// R13.1(3)-(4): the rows line of T holds with its pending rows, the
/// pass's rows and `F_p`'s rows; another Timeline's pending rows are its
/// own line.
#[test]
fn the_writer_rereads_the_rows_line_of_t() -> TestResult {
    let mut domain = domain()?;
    // 24 rows and `F_p`'s 2 rows are 26 on T.
    let room = COMMUNITY_ERASURE_ROW_LIMIT_V1 - 26;
    let held = |rows| CommunityPendingReservationV1 { targets: 0, rows };
    // The child's pending rows fill the child's line, which this pass does
    // not add to.
    domain
        .pending_reservations
        .insert((id(2), [1; 16]), held(COMMUNITY_ERASURE_ROW_LIMIT_V1));
    assert!(domain.stage_reserve(input()?).is_ok());
    domain.pending_reservations.clear();
    domain
        .pending_reservations
        .insert((id(1), [1; 16]), held(room));
    assert!(domain.stage_reserve(input()?).is_ok());
    domain
        .pending_reservations
        .insert((id(1), [1; 16]), held(room + 1));
    assert_eq!(
        domain.stage_reserve(input()?).err(),
        Some(Error::StaleFrontier)
    );
    Ok(())
}

/// R13.1(4): a Commit replaces the entry by the rows it binds, and R14
/// counts each Annotation CPN1 once. The counters, graph, head and closure
/// advance, and the materialization's records are in the closure.
#[test]
fn a_commit_replaces_the_entry_and_advances_the_state() -> TestResult {
    let mut domain = domain()?;
    let staged = domain.stage_reserve(input()?)?;
    domain.apply_reserve(&SEAL, staged)?;

    let staged = domain.stage_commit(commit_input())?;
    // Staging changes nothing.
    assert_eq!(pending(&domain), Some((40, 20)));
    domain.apply_commit(&SEAL, staged)?;
    assert_eq!(pending(&domain), None);
    assert_eq!(domain.control_operations(id(1), GENERATION), 1 + 3);
    assert_eq!(domain.retained_pass_outcomes(id(1), GENERATION), 1);
    let expected = sum(sum(counts(100), counts(10)), counts(1000));
    assert!(domain.recorded_set_counters(id(1)) == expected);
    assert_eq!(domain.selected_graph(id(1)), commit_input().graph);
    assert!(domain.event_source_in_closure(id(1), hash(60)));
    assert!(domain.event_source_in_closure(id(1), hash(61)));
    assert!(domain.event_source_in_closure(id(1), hash(1)));
    assert_eq!(
        domain.observation_graph(id(1), reference()),
        CommunityPassGraphTermsV1::default()
    );
    let state = domain.pass_states.get(&id(1)).ok_or("state")?;
    assert_eq!(state.head, hash(31));
    assert!(state.scope_rows.contains_key(&hash(70)));
    assert!(state.scope_rows.contains_key(&hash(40)));
    assert!(domain.pending_erasure_demand(actor(10)).rows.is_empty());
    Ok(())
}

/// A Commit with no observation to retire leaves the observation terms
/// alone.
#[test]
fn a_commit_without_an_observation_keeps_the_other_terms() -> TestResult {
    let mut domain = domain()?;
    let staged = domain.stage_reserve(input()?)?;
    domain.apply_reserve(&SEAL, staged)?;
    let commit = CommunityCommitInputV1 {
        observation: None,
        annotations: 0,
        ..commit_input()
    };
    let staged = domain.stage_commit(commit)?;
    domain.apply_commit(&SEAL, staged)?;
    assert_eq!(domain.observation_graph(id(1), reference()), TERMS);
    assert_eq!(domain.control_operations(id(1), GENERATION), 1);
    Ok(())
}

/// R13.1(4): a Commit never binds more rows than its entry holds, and
/// needs an entry.
#[test]
fn a_commit_is_bounded_by_its_pending_entry() -> TestResult {
    let mut domain = domain()?;
    assert_eq!(
        domain.stage_commit(commit_input()).err(),
        Some(Error::InvalidBinding)
    );
    let staged = domain.stage_reserve(input()?)?;
    domain.apply_reserve(&SEAL, staged)?;
    let rows = |bound_rows| CommunityCommitInputV1 {
        bound_rows,
        ..commit_input()
    };
    assert!(domain.stage_commit(rows(20)).is_ok());
    assert_eq!(
        domain.stage_commit(rows(21)).err(),
        Some(Error::InvalidBinding)
    );
    let elsewhere = CommunityCommitInputV1 {
        timeline: id(2),
        ..commit_input()
    };
    assert_eq!(
        domain.stage_commit(elsewhere).err(),
        Some(Error::EvidenceUnavailable)
    );
    Ok(())
}

/// R13.1(4)-(5): an Abort replaces the entry by the rows it registers, at
/// most the entry. The retained outcome, the materialization's counters and
/// control operation, and its closure terms stay, so the next pass reuses
/// the records; no cap or budget refuses it.
#[test]
fn an_abort_leaves_the_materialization_counted_and_reusable() -> TestResult {
    let mut domain = domain()?;
    let staged = domain.stage_reserve(input()?)?;
    domain.apply_reserve(&SEAL, staged)?;
    // Every cap is full: an Abort is still allowed.
    set_counts(
        &mut domain,
        COMMUNITY_RETAINED_PASS_OUTCOMES_V1,
        COMMUNITY_CONTROL_OPERATIONS_V1,
        0,
    );
    assert_eq!(
        domain.stage_abort(id(1), OPERATION, 21).err(),
        Some(Error::InvalidBinding)
    );
    let staged = domain.stage_abort(id(1), OPERATION, 20)?;
    assert_eq!(pending(&domain), Some((40, 20)));
    domain.apply_abort(&SEAL, &staged)?;
    assert_eq!(pending(&domain), None);
    assert_eq!(
        domain.retained_pass_outcomes(id(1), GENERATION),
        COMMUNITY_RETAINED_PASS_OUTCOMES_V1
    );
    assert_eq!(
        domain.control_operations(id(1), GENERATION),
        COMMUNITY_CONTROL_OPERATIONS_V1
    );
    assert!(domain.recorded_set_counters(id(1)) == sum(counts(100), counts(10)));
    assert_eq!(domain.observation_graph(id(1), reference()), TERMS);
    // The same identity has no entry now, and another Timeline no state.
    assert_eq!(
        domain.stage_abort(id(1), OPERATION, 0).err(),
        Some(Error::InvalidBinding)
    );
    assert_eq!(
        domain.stage_abort(id(2), OPERATION, 0).err(),
        Some(Error::EvidenceUnavailable)
    );
    Ok(())
}

/// A refused Reserve leaves the domain as it was.
#[test]
fn a_refused_reserve_changes_nothing() -> TestResult {
    let domain = domain()?;
    let stale = CommunityReserveInputV1 {
        selected_head: hash(99),
        ..input()?
    };
    assert_eq!(
        domain.stage_reserve(bound(stale)?).err(),
        Some(Error::StaleFrontier)
    );
    assert_eq!(pending(&domain), None);
    assert_eq!(domain.retained_pass_outcomes(id(1), GENERATION), 0);
    assert!(domain.recorded_set_counters(id(1)) == counts(100));
    Ok(())
}

/// R10.7 5j: a moved head and moved counters each give 6 on their own.
#[test]
fn the_head_and_the_counters_are_each_compared() -> TestResult {
    let domain = domain()?;
    let head = CommunityReserveInputV1 {
        selected_head: hash(99),
        ..input()?
    };
    assert_eq!(
        domain.stage_reserve(bound(head)?).err(),
        Some(Error::StaleFrontier)
    );
    let moved = CommunityReserveInputV1 {
        prior_shared_counts: counts(101),
        ..input()?
    };
    assert_eq!(
        domain.stage_reserve(moved).err(),
        Some(Error::StaleFrontier)
    );
    Ok(())
}

/// R13.1(4): every actor of T's scope must fit, not only one. For the
/// Fork child the scope is its owner and its parent's: pending rows on the
/// parent's Timeline fill only the parent's owner's line.
#[test]
fn every_actor_of_the_scope_must_fit() -> TestResult {
    let mut domain = domain()?;
    domain.pass_states.insert(id(2), pass_state());
    let child = CommunityReserveInputV1 {
        timeline: id(2),
        ..input()?
    };
    let child = bound(child)?;
    assert!(domain.stage_reserve(child.clone()).is_ok());
    domain.pending_reservations.insert(
        (id(1), [1; 16]),
        CommunityPendingReservationV1 {
            targets: COMMUNITY_ERASURE_TARGET_LINE_V1,
            rows: 0,
        },
    );
    assert_eq!(
        domain.stage_reserve(child).err(),
        Some(Error::StaleFrontier)
    );
    Ok(())
}

/// What a refused apply must leave alone. `CommunitySharedCountsV1` has no
/// `Debug`, so the four counters are compared as a tuple.
#[derive(Debug, PartialEq)]
struct Snapshot {
    pending: Vec<(TimelineId, [u8; 16], u64, u64)>,
    records: Vec<(TimelineId, [u8; 16], CommunityPassStatusV1)>,
    outcomes: u64,
    control_operations: u64,
    counters: (u64, u64, u64, u64),
    observations: usize,
    scope_rows: usize,
}

/// The pending ledger, the pass-record index with every status, the
/// retained counts, the four recorded-set counters and the observation and
/// scope-row terms of T.
fn snapshot(domain: &MemoryCommunityDomainV1) -> Result<Snapshot, Box<dyn std::error::Error>> {
    let state = domain.pass_states.get(&id(1)).ok_or("state")?;
    let counters = domain.recorded_set_counters(id(1));
    Ok(Snapshot {
        pending: domain
            .pending_reservations
            .iter()
            .map(|((timeline, operation), entry)| {
                (*timeline, *operation, entry.targets, entry.rows)
            })
            .collect(),
        records: domain
            .pass_records
            .iter()
            .map(|((timeline, operation), record)| (*timeline, *operation, record.status))
            .collect(),
        outcomes: domain.retained_pass_outcomes(id(1), GENERATION),
        control_operations: domain.control_operations(id(1), GENERATION),
        counters: (
            counters.nodes,
            counters.edges,
            counters.declared_inputs,
            counters.encoded_record_bytes,
        ),
        observations: state.observations.len(),
        scope_rows: state.scope_rows.len(),
    })
}

/// The composition preconditions are judged in a fixed order: a bad
/// binding, then a recorded identity, then a Timeline with no state.
#[test]
fn the_preconditions_are_judged_in_order() -> TestResult {
    let mut domain = domain()?;
    // T2 has no state, an identity already recorded, and a minted row count
    // above its pass rows.
    domain.pending_reservations.insert(
        (id(2), OPERATION),
        CommunityPendingReservationV1::for_pass(0, 0),
    );
    let mut every = CommunityReserveInputV1 {
        timeline: id(2),
        pass_rows: 5,
        ..input()?
    };
    let refusal = |domain: &MemoryCommunityDomainV1, input: &CommunityReserveInputV1| {
        bound(input.clone()).map_or_else(Some, |call| domain.stage_reserve(call).err())
    };
    assert_eq!(refusal(&domain, &every), Some(Error::InvalidBinding));
    every.pass_rows = 24;
    assert_eq!(refusal(&domain, &every), Some(Error::Conflict));
    domain.pending_reservations.clear();
    assert_eq!(refusal(&domain, &every), Some(Error::EvidenceUnavailable));
    Ok(())
}

/// R13.1(2): a Timeline whose lineage the store cannot walk fails the
/// budget read, and the writer passes that error on (12).
#[test]
fn an_unwalkable_topology_is_unavailable_evidence() -> TestResult {
    let mut domain = domain()?;
    // A pass state for a Timeline the store does not hold.
    domain.pass_states.insert(id(9), pass_state());
    let lost = CommunityReserveInputV1 {
        timeline: id(9),
        ..input()?
    };
    assert_eq!(
        domain.stage_reserve(bound(lost)?).err(),
        Some(Error::EvidenceUnavailable)
    );
    Ok(())
}

/// The one pass-entry formula: two targets a row plus `F_p`, and half of
/// `F_p` as rows, saturating.
#[test]
fn a_pass_entry_is_two_targets_a_row_plus_the_reserve() {
    let entry = CommunityPendingReservationV1::for_pass(5, 4);
    assert_eq!((entry.targets, entry.rows), (14, 7));
    let top = CommunityPendingReservationV1::for_pass(u64::MAX, u64::MAX);
    assert_eq!((top.targets, top.rows), (u64::MAX, u64::MAX));
}

/// A token staged twice applies once: the second finds the identity
/// pending (Reserve) or the entry gone (Commit, Abort).
#[test]
fn a_token_staged_twice_applies_once() -> TestResult {
    let mut domain = domain()?;
    let first = domain.stage_reserve(input()?)?;
    let second = domain.stage_reserve(input()?)?;
    domain.apply_reserve(&SEAL, first)?;
    let before = snapshot(&domain)?;
    assert_eq!(
        domain.apply_reserve(&SEAL, second).err(),
        Some(Error::Conflict)
    );
    assert_eq!(snapshot(&domain)?, before);
    assert_eq!(domain.retained_pass_outcomes(id(1), GENERATION), 1);

    let first = domain.stage_commit(commit_input())?;
    let second = domain.stage_commit(commit_input())?;
    domain.apply_commit(&SEAL, first)?;
    assert_eq!(
        domain.apply_commit(&SEAL, second).err(),
        Some(Error::InvalidBinding)
    );
    // The Commit counted its annotations once.
    assert_eq!(domain.control_operations(id(1), GENERATION), 1 + 3);

    let next = bound(CommunityReserveInputV1 {
        reservation_operation_id: [0x31; 16],
        prior_shared_counts: domain.recorded_set_counters(id(1)),
        selected_head: hash(31),
        minted: None,
        ..input()?
    })?;
    let staged = domain.stage_reserve(next)?;
    domain.apply_reserve(&SEAL, staged)?;
    let first = domain.stage_abort(id(1), [0x31; 16], 0)?;
    let second = domain.stage_abort(id(1), [0x31; 16], 0)?;
    domain.apply_abort(&SEAL, &first)?;
    assert_eq!(
        domain.apply_abort(&SEAL, &second).err(),
        Some(Error::InvalidBinding)
    );
    Ok(())
}

/// A token applied after its pass state is gone, or after its entry shrank
/// below the rows it binds, is refused and changes nothing.
#[test]
fn a_stale_token_is_refused_at_the_apply() -> TestResult {
    let mut domain = domain()?;
    let reserve = domain.stage_reserve(input()?)?;
    let state = domain.pass_states.remove(&id(1)).ok_or("state")?;
    assert_eq!(
        domain.apply_reserve(&SEAL, reserve).err(),
        Some(Error::EvidenceUnavailable)
    );
    assert_eq!(pending(&domain), None);
    domain.pass_states.insert(id(1), state);
    let reserve = domain.stage_reserve(input()?)?;
    domain.apply_reserve(&SEAL, reserve)?;

    let commit = domain.stage_commit(commit_input())?;
    let abort = domain.stage_abort(id(1), OPERATION, 20)?;
    domain.pending_reservations.insert(
        (id(1), OPERATION),
        CommunityPendingReservationV1::for_pass(0, 0),
    );
    assert_eq!(
        domain.apply_commit(&SEAL, commit).err(),
        Some(Error::InvalidBinding)
    );
    assert_eq!(
        domain.apply_abort(&SEAL, &abort).err(),
        Some(Error::InvalidBinding)
    );
    assert_eq!(pending(&domain), Some((0, 0)));
    let commit = domain.stage_commit(CommunityCommitInputV1 {
        bound_rows: 0,
        ..commit_input()
    })?;
    let abort = domain.stage_abort(id(1), OPERATION, 0)?;
    domain.pass_states.remove(&id(1));
    assert_eq!(
        domain.apply_commit(&SEAL, commit).err(),
        Some(Error::EvidenceUnavailable)
    );
    assert_eq!(
        domain.apply_abort(&SEAL, &abort).err(),
        Some(Error::EvidenceUnavailable)
    );
    Ok(())
}

/// The retained counts saturate like every counter instead of wrapping.
#[test]
fn the_retained_counts_saturate() -> TestResult {
    let mut domain = domain()?;
    let reserve = domain.stage_reserve(input()?)?;
    set_counts(&mut domain, u64::MAX, u64::MAX, 0);
    domain.apply_reserve(&SEAL, reserve)?;
    assert_eq!(domain.retained_pass_outcomes(id(1), GENERATION), u64::MAX);
    assert_eq!(domain.control_operations(id(1), GENERATION), u64::MAX);
    let commit = domain.stage_commit(commit_input())?;
    set_counts(&mut domain, 0, 0, u64::MAX);
    domain.apply_commit(&SEAL, commit)?;
    assert_eq!(domain.control_operations(id(1), GENERATION), u64::MAX);
    Ok(())
}

/// R8.1(7): the Reserve that applies indexes its pass by `(T, O)` with
/// the CPR1 fields, the quote facts and the status Reserved, live.
#[test]
fn a_reserve_indexes_its_pass_reserved_and_live() -> TestResult {
    let mut domain = domain()?;
    assert_eq!(domain.pass_status(id(1), OPERATION), None);
    assert!(!domain.pass_is_live(id(1), OPERATION));
    assert!(domain.pass_reservation(id(1), OPERATION).is_none());
    assert!(domain.pass_counters(id(1), OPERATION).is_none());
    let staged = domain.stage_reserve(input()?)?;
    assert!(domain.unresolved_pass(id(1)).is_none());
    domain.apply_reserve(&SEAL, staged)?;

    assert_eq!(
        domain.pass_status(id(1), OPERATION),
        Some(CommunityPassStatusV1::Reserved)
    );
    assert!(domain.pass_is_live(id(1), OPERATION));
    let reservation = domain.pass_reservation(id(1), OPERATION).ok_or("cpr1")?;
    assert!(reservation == reserved_pass()?.reservation);
    let counters = domain.pass_counters(id(1), OPERATION).ok_or("counts")?;
    assert!(counters.prior == counts(100));
    assert!(counters.materialization.ok_or("additions")? == counts(10));
    let record = domain.pass_record(id(1), OPERATION).ok_or("record")?;
    assert!(record.reserved == reserved_pass()?);
    assert!(domain.unresolved_pass(id(1)).is_some());
    assert!(domain.unresolved_pass(id(2)).is_none());

    domain.end_live_call(&SEAL, id(1), OPERATION);
    assert!(!domain.pass_is_live(id(1), OPERATION));
    // Ending a call of an unknown pass changes nothing.
    domain.end_live_call(&SEAL, id(1), [0x01; 16]);
    Ok(())
}

/// A reused observation records no additions.
#[test]
fn a_reusing_reserve_records_no_additions() -> TestResult {
    let mut domain = domain()?;
    let staged = domain.stage_reserve(reuse()?)?;
    domain.apply_reserve(&SEAL, staged)?;
    let counters = domain.pass_counters(id(1), OPERATION).ok_or("counts")?;
    assert!(counters.materialization.is_none());
    Ok(())
}

/// The record names the Timeline, generation and head the call planned
/// over (R10.7 5j), and a replay or a second unresolved pass is refused
/// (R8.1(7), code 7).
#[test]
fn the_index_refuses_replays_and_a_second_unresolved_pass() -> TestResult {
    let mut domain = domain()?;
    let mut elsewhere = input()?;
    elsewhere.pass.reservation.pass_key = pass_key(id(2), GENERATION, 7)?;
    assert_eq!(
        domain.stage_reserve(elsewhere).err(),
        Some(Error::InvalidBinding)
    );
    let mut regenerated = input()?;
    regenerated.pass.reservation.pass_key = pass_key(id(1), [0x21; 16], 7)?;
    assert_eq!(
        domain.stage_reserve(regenerated).err(),
        Some(Error::InvalidBinding)
    );
    let mut moved = input()?;
    moved.pass.reservation.predecessor_head_digest = hash(99);
    assert_eq!(
        domain.stage_reserve(moved).err(),
        Some(Error::InvalidBinding)
    );

    let staged = domain.stage_reserve(input()?)?;
    domain.apply_reserve(&SEAL, staged)?;
    assert_eq!(
        domain.stage_reserve(other_operation(&domain)?).err(),
        Some(Error::PassUnresolved)
    );
    // A Sealed pass is unresolved too.
    assert!(domain.set_pass_status(id(1), OPERATION, CommunityPassStatusV1::Sealed));
    assert_eq!(
        domain.stage_reserve(other_operation(&domain)?).err(),
        Some(Error::PassUnresolved)
    );

    let abort = domain.stage_abort(id(1), OPERATION, 0)?;
    domain.apply_abort(&SEAL, &abort)?;
    assert_eq!(
        domain.pass_status(id(1), OPERATION),
        Some(CommunityPassStatusV1::Aborted)
    );
    assert!(!domain.pass_is_live(id(1), OPERATION));
    // The resolved identity is a replay; a new one reserves.
    assert_eq!(domain.stage_reserve(input()?).err(), Some(Error::Conflict));
    assert!(domain.stage_reserve(other_operation(&domain)?).is_ok());
    Ok(())
}

/// A Commit resolves the pass for good, from Sealed: no transition leaves
/// a terminal status, only Reserved reaches Sealed, and Seal keeps the
/// call live.
#[test]
fn a_commit_resolves_the_pass_and_statuses_only_move_forward() -> TestResult {
    let mut domain = domain()?;
    let staged = domain.stage_reserve(input()?)?;
    domain.apply_reserve(&SEAL, staged)?;
    assert!(!domain.set_pass_status(id(1), OPERATION, CommunityPassStatusV1::Reserved));
    assert!(!domain.set_pass_status(id(1), [0x01; 16], CommunityPassStatusV1::Sealed));
    assert!(domain.set_pass_status(id(1), OPERATION, CommunityPassStatusV1::Sealed));
    assert!(domain.pass_is_live(id(1), OPERATION));
    assert!(!domain.set_pass_status(id(1), OPERATION, CommunityPassStatusV1::Sealed));

    let commit = domain.stage_commit(commit_input())?;
    domain.apply_commit(&SEAL, commit)?;
    assert_eq!(
        domain.pass_status(id(1), OPERATION),
        Some(CommunityPassStatusV1::Committed)
    );
    assert!(domain.unresolved_pass(id(1)).is_none());
    assert!(!domain.pass_is_live(id(1), OPERATION));
    for status in [
        CommunityPassStatusV1::Aborted,
        CommunityPassStatusV1::Sealed,
        CommunityPassStatusV1::Committed,
    ] {
        assert!(!domain.set_pass_status(id(1), OPERATION, status));
    }
    // The committed identity is a replay (4); a new one reserves.
    assert_eq!(domain.stage_reserve(input()?).err(), Some(Error::Conflict));
    assert!(domain.stage_reserve(other_operation(&domain)?).is_ok());
    Ok(())
}

/// Reserved goes straight to Committed or Aborted, the transitions the
/// writer takes before a Seal exists; each is terminal.
#[test]
fn an_unsealed_pass_commits_or_aborts() -> TestResult {
    let mut committed = domain()?;
    let staged = committed.stage_reserve(input()?)?;
    committed.apply_reserve(&SEAL, staged)?;
    let commit = committed.stage_commit(commit_input())?;
    committed.apply_commit(&SEAL, commit)?;
    assert_eq!(
        committed.pass_status(id(1), OPERATION),
        Some(CommunityPassStatusV1::Committed)
    );
    assert_eq!(
        committed.stage_reserve(input()?).err(),
        Some(Error::Conflict)
    );

    let mut aborted = domain()?;
    let staged = aborted.stage_reserve(input()?)?;
    aborted.apply_reserve(&SEAL, staged)?;
    let abort = aborted.stage_abort(id(1), OPERATION, 0)?;
    aborted.apply_abort(&SEAL, &abort)?;
    assert_eq!(
        aborted.pass_status(id(1), OPERATION),
        Some(CommunityPassStatusV1::Aborted)
    );
    // The token cannot apply twice, and a terminal pass has no entry.
    assert_eq!(
        aborted.apply_abort(&SEAL, &abort).err(),
        Some(Error::InvalidBinding)
    );
    assert_eq!(
        aborted.stage_commit(commit_input()).err(),
        Some(Error::InvalidBinding)
    );
    Ok(())
}

/// An apply never overwrites a recorded pass, and an entry with no
/// unresolved record resolves nothing.
#[test]
fn an_apply_over_a_record_or_a_bare_entry_fails_loudly() -> TestResult {
    let mut domain = domain()?;
    let first = domain.stage_reserve(input()?)?;
    let second = domain.stage_reserve(input()?)?;
    domain.apply_reserve(&SEAL, first)?;
    let abort = domain.stage_abort(id(1), OPERATION, 0)?;
    domain.apply_abort(&SEAL, &abort)?;
    // The entry is gone but the record stays: the second token conflicts.
    assert_eq!(
        domain.apply_reserve(&SEAL, second).err(),
        Some(Error::Conflict)
    );
    assert_eq!(
        domain.pass_status(id(1), OPERATION),
        Some(CommunityPassStatusV1::Aborted)
    );

    // A pending entry with no record belongs to no unresolved pass.
    domain.pending_reservations.insert(
        (id(1), [0x55; 16]),
        CommunityPendingReservationV1::for_pass(0, 0),
    );
    assert_eq!(
        domain.stage_abort(id(1), [0x55; 16], 0).err(),
        Some(Error::InvalidBinding)
    );
    Ok(())
}

/// R13.1(4) and code 7: at most one reservation of T is pending, so a
/// second Reserve staged before the first applied is refused at the apply,
/// whatever its identity sorts to; another Timeline's entry does not count.
#[test]
fn a_second_pending_reservation_of_t_refuses_the_apply() -> TestResult {
    let mut domain = domain()?;
    let base = input()?;
    let other = |byte: u8| CommunityReserveInputV1 {
        reservation_operation_id: [byte; 16],
        ..base.clone()
    };
    // Another Timeline's entry is not T's.
    domain.pending_reservations.insert(
        (id(2), [0x40; 16]),
        CommunityPendingReservationV1::for_pass(0, 0),
    );
    let first = domain.stage_reserve(other(0x40))?;
    let second = domain.stage_reserve(other(0x41))?;
    domain.apply_reserve(&SEAL, first)?;
    let before = snapshot(&domain)?;
    assert_eq!(
        domain.apply_reserve(&SEAL, second).err(),
        Some(Error::PassUnresolved)
    );
    assert_eq!(snapshot(&domain)?, before);
    // The bounds of the identity range hold: the lowest and highest
    // identities of T are T's too.
    for edge in [[0; 16], [u8::MAX; 16]] {
        let mut domain = self::domain()?;
        let staged = domain.stage_reserve(other(0x42))?;
        domain
            .pending_reservations
            .insert((id(1), edge), CommunityPendingReservationV1::for_pass(0, 0));
        assert_eq!(
            domain.apply_reserve(&SEAL, staged).err(),
            Some(Error::PassUnresolved)
        );
    }
    Ok(())
}

/// R13.1(3): the budget sums saturate instead of overflowing, so a count
/// near `u64::MAX` is a misfit, not a panic.
#[test]
fn the_budget_sums_saturate() {
    let actor = |targets, quarantine_reserve| CommunityErasureActorV1 {
        actor: actor(10),
        targets,
        quarantine_reserve,
    };
    let budget = |rows| CommunityErasureBudgetV1 {
        actors: Vec::new(),
        rows: BTreeMap::from([(id(1), rows)]),
        quarantine_rows: BTreeMap::new(),
    };
    let pending = |targets, rows| CommunityPendingErasureV1 {
        targets,
        rows: BTreeMap::from([(id(1), rows)]),
    };
    let none = CommunityPendingErasureV1::default();
    // Every target term at the top.
    assert_eq!(
        trace_room(&budget(0), &actor(u64::MAX, 0), &none, id(1), 0, 0),
        None
    );
    assert_eq!(
        trace_room(&budget(0), &actor(0, u64::MAX), &none, id(1), 0, 0),
        None
    );
    assert_eq!(
        trace_room(&budget(0), &actor(1, 1), &pending(u64::MAX, 0), id(1), 0, 0),
        None
    );
    assert_eq!(
        trace_room(&budget(0), &actor(1, 1), &none, id(1), u64::MAX, 0),
        None
    );
    // Every row term at the top, with the targets fitting.
    let fits = actor(0, 0);
    assert_eq!(
        trace_room(&budget(u64::MAX), &fits, &none, id(1), 1, 0),
        None
    );
    assert_eq!(
        trace_room(&budget(1), &fits, &pending(0, u64::MAX), id(1), 1, 0),
        None
    );
    let held = CommunityErasureBudgetV1 {
        quarantine_rows: BTreeMap::from([(id(1), u64::MAX)]),
        ..budget(1)
    };
    assert_eq!(trace_room(&held, &fits, &none, id(1), 1, 0), None);
}
