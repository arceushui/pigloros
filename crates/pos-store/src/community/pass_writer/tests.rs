//! The Reserve, Commit and Abort transitions: their writer re-checks in the
//! R10.7 step-5j order, the counted set of ADR-129 revision 14 and the
//! pending ledger of revision 13 (R13.1(4)).

use std::collections::BTreeMap;
use std::sync::Arc;

use pos_core::community_lifecycle::{
    community_prepared_input_set_digest_v1, CommunityGenerationIdsV1, CommunityGraphCountsV1,
    CommunityLifecycleErrorV1 as Error, CommunityNativeNodeReferenceV1, CommunityPassGraphTermsV1,
    CommunityPassKeyV1, CommunityProfileRetentionV1, CommunityQuarantineReasonEvidenceV1,
    CommunityQuarantineReasonV1, CommunityReservationInputV1, CommunityReservationRequestInputV1,
    CommunityReservationRequestV1, CommunityScopeMemberV1, CommunitySelectionInputV1,
    CommunitySelectionV1, CommunitySharedCountsV1, CommunityTimelineFloorV1,
    CommunityTimelineFloorsV1, COMMUNITY_CONTROL_OPERATIONS_V1,
    COMMUNITY_DECISION_DEADLINE_MICROS_V1, COMMUNITY_ERASURE_ROW_LIMIT_V1,
    COMMUNITY_ERASURE_TARGET_LINE_V1, COMMUNITY_RETAINED_PASS_OUTCOMES_V1,
};
use pos_core::store::EventStore;
use pos_core::{
    AuthorityTrustRootSealV1, CanonicalBytes, EntityId, ErasureContainmentGateV1, EventDraft, Hash,
    Kind, Seq, TimelineId, TimelineMeta,
};
use ulid::Ulid;

use super::super::erasure_budget::CommunityErasureBudgetPortV1;
use super::super::erasure_budget::{
    CommunityErasureActorV1, CommunityErasureBudgetV1, CommunityPendingErasureV1,
    CommunityPendingReservationV1,
};
use super::super::pass_install::{CommunityHorizonPolicyV1, CommunityOwnerHorizonsV1};
use super::super::pass_planner::{trace_room, CommunityPassReadPortV1};
use super::super::pass_record::{CommunityPassMemberDigestsV1, CommunityPassStatusV1};
use super::super::pass_state::{
    CommunityGenerationCountsV1, CommunityPassStateV1, CommunityRetainedObservationV1,
};
use super::super::quarantine::QuarantineLedgerV1;
use super::{
    add_counts, community_reserve_selection_v1, CommunityCommitInputV1,
    CommunityMintedObservationV1, CommunityObservationCutV1, CommunityReserveInputV1,
    CommunityReservePassFactsV1, CommunityStagedReserveV1,
};
use crate::community::MemoryCommunityDomainV1;
use crate::memory::MemoryStore;
use crate::MemoryTrustedClockAuthorityV1;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const SEAL: AuthorityTrustRootSealV1 = AuthorityTrustRootSealV1::for_composition_root();
const GENERATION: [u8; 16] = [0x20; 16];
const OPERATION: [u8; 16] = [0x30; 16];
const SAMPLE: u64 = 1_000;
/// The native producer ordinal the fixture's materialization carries and
/// the burned counter stands at (R10.7 5h burned it just before the Reserve).
const BURNED: u64 = 3;
/// The recovery window: 60 s, so `H_r` is `SAMPLE` + 60 s.
const WINDOW: u64 = 60_000_000;
/// `generation_not_after`, and so `H_g`: 100 s.
const GENERATION_HORIZON: u64 = 100_000_000;
/// `H_r` at `SAMPLE`.
const OUTCOME: u64 = SAMPLE + WINDOW;
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
    Ok(store)
}

/// The chain hash at sequence 0 of T, the genesis of its chain.
fn genesis() -> Result<Hash, Box<dyn std::error::Error>> {
    Ok(store()?.chain_hash_at(id(1), Seq::ZERO)?)
}

/// The cut of an observation of no Events: T and its Fork child at 0.
fn cut() -> Result<CommunityObservationCutV1, Box<dyn std::error::Error>> {
    let store = store()?;
    Ok(CommunityObservationCutV1 {
        through_seq: 0,
        chain_heads: vec![
            (id(1), 0, store.chain_hash_at(id(1), Seq::ZERO)?),
            (id(2), 0, store.chain_hash_at(id(2), Seq::ZERO)?),
        ],
    })
}

/// The domain over [`store`], with T's state, the observation a Reserve
/// minted earlier (`reference()`, retained to `GENERATION_HORIZON`) and installed
/// horizons that make `H_g` `GENERATION_HORIZON` and `H_r` `OUTCOME` at
/// `SAMPLE`.
fn domain() -> Result<MemoryCommunityDomainV1, Box<dyn std::error::Error>> {
    let mut domain =
        MemoryCommunityDomainV1::new(store()?, [0x5a; 16], MemoryTrustedClockAuthorityV1::new())?;
    let mut state = pass_state();
    state.retained.insert(
        reference(),
        CommunityRetainedObservationV1 {
            generation: GENERATION,
            not_after_micros: GENERATION_HORIZON,
            cut: cut()?,
        },
    );
    domain.pass_states.insert(id(1), state);
    domain.pass_horizons = Some(domain_policy());
    domain.native_producer_ordinal = BURNED;
    domain.burned_materialization = Some(BURNED);
    Ok(domain)
}

/// The installed horizons of [`domain`].
fn domain_policy() -> CommunityHorizonPolicyV1 {
    CommunityHorizonPolicyV1 {
        retention: CommunityProfileRetentionV1 {
            generation_not_after_micros: GENERATION_HORIZON,
            recovery_window_micros: WINDOW,
            quarantine_not_after_micros: 2 * GENERATION_HORIZON,
            metadata_not_after_micros: 2 * GENERATION_HORIZON,
            recording_not_after_micros: RECORDING,
        },
        owners: CommunityOwnerHorizonsV1 {
            recording_micros: RECORDING,
            metadata_micros: 2 * GENERATION_HORIZON,
            evidence_micros: 2 * GENERATION_HORIZON,
        },
        profile_digest: hash(83),
        roster_len: 2,
    }
}

/// Set the installed owner evidence horizon.
fn set_evidence(
    domain: &mut MemoryCommunityDomainV1,
    micros: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    domain
        .pass_horizons
        .as_mut()
        .ok_or("horizons")?
        .owners
        .evidence_micros = micros;
    Ok(())
}

/// Set the installed recording horizon.
fn set_recording(
    domain: &mut MemoryCommunityDomainV1,
    micros: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    domain
        .pass_horizons
        .as_mut()
        .ok_or("horizons")?
        .retention
        .recording_not_after_micros = micros;
    Ok(())
}

/// T's state: generation, head and counters the inputs name.
fn pass_state() -> CommunityPassStateV1 {
    CommunityPassStateV1 {
        generation: GENERATION,
        profile_digest: hash(83),
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
        highest_pass_ordinal: 0,
        retained: BTreeMap::new(),
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

fn minted(cut: CommunityObservationCutV1) -> CommunityMintedObservationV1 {
    CommunityMintedObservationV1 {
        reference: reference(),
        graph: TERMS,
        additions: counts(10),
        rows: 6,
        scope_reference: hash(40),
        scope: vec![scope_row()],
        not_after_micros: GENERATION_HORIZON,
        cut,
    }
}

/// A Reserve of 24 pass rows with `F_p` of 4 targets, minting.
fn input() -> Result<CommunityReserveInputV1, Box<dyn std::error::Error>> {
    cut().map(|cut| CommunityReserveInputV1 {
        timeline: id(1),
        generation: GENERATION,
        reservation_operation_id: OPERATION,
        selected_head: hash(30),
        prior_shared_counts: counts(100),
        roster_quarantine_keys: vec![hash(50), hash(51)],
        reservation_sample_micros: SAMPLE,
        pass_rows: 24,
        failure_reserve: 4,
        minted: Some(minted(cut)),
        reused: None,
        request: request_input(),
        pass: facts(),
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

/// The prepared input set identity of `[cmb1, cin1]` pairs; a zero digest,
/// which no check accepts, if they are not a valid set.
fn input_set(pairs: &[(Hash, Hash)]) -> Hash {
    community_prepared_input_set_digest_v1(pairs).unwrap_or(Hash::zero())
}

/// The CRI1 fields of the pass `input()?` reserves.
fn request_input() -> CommunityReservationRequestInputV1 {
    CommunityReservationRequestInputV1 {
        timeline: id(1),
        generation: GENERATION,
        reservation_operation_id: OPERATION,
        expected_head_digest: hash(30),
        prepared_input_set_digest: input_set(&[(hash(85), hash(86))]),
        roster_digest: hash(81),
        profile_digest: hash(83),
        authority_request_digest: hash(88),
        source_closure_digest: hash(89),
        requested_evidence_horizon: OUTCOME,
    }
}

/// The record facts of the pass `input()?` reserves.
fn facts() -> CommunityReservePassFactsV1 {
    CommunityReservePassFactsV1 {
        cbq1_digest: hash(84),
        quote_maxima: [1, 2, 3],
        trace_rows: 2,
        members: vec![CommunityPassMemberDigestsV1 {
            roster_index: 0,
            cmb1_digest: hash(85),
            cin1_digest: hash(86),
            trust_policy_snapshot_digest: hash(87),
        }],
        metadata_key: [0x61; 16],
        failure_cohort_key: [0x62; 16],
    }
}

/// The CPR1 the writer mints for `input()?` as pass `ordinal`, with the
/// native producer ordinal `native`: `H_r` is `OUTCOME` at `SAMPLE`.
fn expected_reservation(
    ordinal: u64,
    native: u64,
) -> Result<CommunityReservationInputV1, Box<dyn std::error::Error>> {
    Ok(CommunityReservationInputV1 {
        pass_key: pass_key(id(1), GENERATION, ordinal)?,
        request_digest: CommunityReservationRequestV1::new(request_input())?.digest(),
        native_producer_ordinal: native,
        predecessor_head_digest: hash(30),
        roster_digest: hash(81),
        prepared_input_set_digest: input_set(&[(hash(85), hash(86))]),
        profile_digest: hash(83),
        evidence_not_after_micros: OUTCOME,
    })
}

fn reuse() -> Result<CommunityReserveInputV1, Box<dyn std::error::Error>> {
    input().map(|call| CommunityReserveInputV1 {
        minted: None,
        reused: Some(reference()),
        ..call
    })
}

/// A second operation of T: another identity and pass key, over the head
/// and counters the domain holds now, burning its materialization's ordinal.
fn other_operation(
    domain: &mut MemoryCommunityDomainV1,
) -> Result<CommunityReserveInputV1, Box<dyn std::error::Error>> {
    let mut other = other_call(domain)?;
    // A new materialization carries the ordinal burned for it just now.
    let burned = domain.burn_materialization_ordinal(&SEAL)?;
    if let Some(minted) = other.minted.as_mut() {
        minted.reference.producer_ordinal = burned;
    }
    Ok(other)
}

/// A second operation of T over the head and counters the domain holds now,
/// with no burn: its materialization still carries `reference()`'s ordinal.
fn other_call(
    domain: &MemoryCommunityDomainV1,
) -> Result<CommunityReserveInputV1, Box<dyn std::error::Error>> {
    let state = domain.pass_states.get(&id(1)).ok_or("state")?;
    let mut other = input()?;
    other.selected_head = state.head;
    other.prior_shared_counts = state.counters;
    other.reservation_operation_id = [0x77; 16];
    bound(other).map_err(Box::<dyn std::error::Error>::from)
}

/// Stage a second operation of T after burning its materialization's ordinal.
fn stage_other(
    domain: &mut MemoryCommunityDomainV1,
) -> Result<Result<CommunityStagedReserveV1, Error>, Box<dyn std::error::Error>> {
    let call = other_operation(domain)?;
    Ok(domain.stage_reserve(call))
}

/// The record facts a caller binds to what it planned over: the input's
/// Timeline, generation and head.
fn bound(mut call: CommunityReserveInputV1) -> Result<CommunityReserveInputV1, Error> {
    call.request.timeline = call.timeline;
    call.request.generation = call.generation;
    call.request.reservation_operation_id = call.reservation_operation_id;
    call.request.expected_head_digest = call.selected_head;
    CommunityReservationRequestV1::new(call.request)?;
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
        ..input()?
    };
    set_recording(&mut domain, SAMPLE)?;
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
    set_recording(&mut domain, RECORDING)?;
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
        reused: Some(reference()),
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
    assert!(reservation == expected_reservation(1, BURNED + 1)?);
    let counters = domain.pass_counters(id(1), OPERATION).ok_or("counts")?;
    assert!(counters.prior == counts(100));
    assert!(counters.materialization.ok_or("additions")? == counts(10));
    let record = domain.pass_record(id(1), OPERATION).ok_or("record")?;
    assert_eq!(record.reserved.cbq1_digest, hash(84));
    assert_eq!(record.reserved.quote_maxima, [1, 2, 3]);
    assert_eq!(record.reserved.trace_rows, 2);
    assert!(record.reserved.members == facts().members);
    assert_eq!(record.reserved.metadata_key, [0x61; 16]);
    assert_eq!(record.reserved.failure_cohort_key, [0x62; 16]);
    assert_eq!(
        record.reserved.generation_horizon_micros,
        GENERATION_HORIZON
    );
    assert_eq!(record.reserved.outcome_horizon_micros, OUTCOME);
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
    elsewhere.request.timeline = id(2);
    assert_eq!(
        domain.stage_reserve(elsewhere).err(),
        Some(Error::InvalidBinding)
    );
    let mut regenerated = input()?;
    regenerated.request.generation = [0x21; 16];
    assert_eq!(
        domain.stage_reserve(regenerated).err(),
        Some(Error::InvalidBinding)
    );
    let mut moved = input()?;
    moved.request.expected_head_digest = hash(99);
    assert_eq!(
        domain.stage_reserve(moved).err(),
        Some(Error::InvalidBinding)
    );

    let mut renamed = input()?;
    renamed.request.reservation_operation_id = [0x78; 16];
    assert_eq!(
        domain.stage_reserve(renamed).err(),
        Some(Error::InvalidBinding)
    );

    let staged = domain.stage_reserve(input()?)?;
    domain.apply_reserve(&SEAL, staged)?;
    assert_eq!(stage_other(&mut domain)?.err(), Some(Error::PassUnresolved));
    // A Sealed pass is unresolved too.
    assert!(domain.set_pass_status(id(1), OPERATION, CommunityPassStatusV1::Sealed));
    assert_eq!(stage_other(&mut domain)?.err(), Some(Error::PassUnresolved));

    let abort = domain.stage_abort(id(1), OPERATION, 0)?;
    domain.apply_abort(&SEAL, &abort)?;
    assert_eq!(
        domain.pass_status(id(1), OPERATION),
        Some(CommunityPassStatusV1::Aborted)
    );
    assert!(!domain.pass_is_live(id(1), OPERATION));
    // The resolved identity is a replay; a new one reserves.
    assert_eq!(domain.stage_reserve(input()?).err(), Some(Error::Conflict));
    assert!(stage_other(&mut domain)?.is_ok());
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
    assert!(stage_other(&mut domain)?.is_ok());
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
    let mut second = domain.stage_reserve(input()?)?;
    domain.apply_reserve(&SEAL, first)?;
    let abort = domain.stage_abort(id(1), OPERATION, 0)?;
    domain.apply_abort(&SEAL, &abort)?;
    // The entry is gone but the record stays: the second token conflicts,
    // though its ordinals are the next ones again, so only the recorded
    // identity can refuse it.
    let floor = domain
        .pass_states
        .get(&id(1))
        .ok_or("state")?
        .highest_pass_ordinal;
    second.native_ordinal = domain.native_producer_ordinal + 1;
    second.pass_ordinal = floor + 1;
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
    let other = |byte: u8| {
        let mut call = base.clone();
        call.reservation_operation_id = [byte; 16];
        bound(call)
    };
    // Another Timeline's entry is not T's.
    domain.pending_reservations.insert(
        (id(2), [0x40; 16]),
        CommunityPendingReservationV1::for_pass(0, 0),
    );
    let first = domain.stage_reserve(other(0x40)?)?;
    let second = domain.stage_reserve(other(0x41)?)?;
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
        let staged = domain.stage_reserve(other(0x42)?)?;
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

/// R9.7 step 6: a minting Reserve's Logical Head and chain compare gives 12
/// with nothing committed, before the generation compare (R10.7 5j), and
/// the writer derives the cuts it needs from the topology.
#[test]
fn the_writer_compares_the_logical_head_and_the_chains() -> TestResult {
    let domain = domain()?;
    let genesis = genesis()?;
    let with_cut = |through_seq: u64,
                    chain_heads: Vec<(TimelineId, u64, Hash)>|
     -> Result<CommunityReserveInputV1, Box<dyn std::error::Error>> {
        let mut call = input()?;
        if let Some(minted) = call.minted.as_mut() {
            minted.cut = CommunityObservationCutV1 {
                through_seq,
                chain_heads,
            };
        }
        Ok(call)
    };
    let refused = |call: CommunityReserveInputV1| domain.stage_reserve(call).err();
    // T's chain at its cut.
    assert!(domain
        .stage_reserve(with_cut(0, vec![(id(1), 0, genesis)])?)
        .is_ok());
    // An observation of one Event that T does not have: no head and no chain.
    assert_eq!(
        refused(with_cut(1, vec![(id(1), 1, genesis)])?),
        Some(Error::EvidenceUnavailable)
    );
    // A chain hash that differs.
    assert_eq!(
        refused(with_cut(0, vec![(id(1), 0, hash(99))])?),
        Some(Error::EvidenceUnavailable)
    );
    // No entry, an entry at another seq, and an entry of another Timeline
    // are each no observation of T's cut.
    for heads in [
        Vec::new(),
        vec![(id(1), 1, genesis)],
        vec![(id(3), 0, genesis)],
        vec![(id(9), 0, genesis)],
    ] {
        assert_eq!(
            refused(with_cut(0, heads)?),
            Some(Error::EvidenceUnavailable)
        );
    }
    // An entry beyond the required ones is inert: it is never compared.
    assert!(domain
        .stage_reserve(with_cut(
            0,
            vec![(id(1), 0, genesis), (id(9), 7, hash(99))]
        )?)
        .is_ok());
    // The 12 comes before a stale generation (5), and nothing is recorded.
    let mut both = with_cut(1, Vec::new())?;
    both.generation = [0x21; 16];
    assert_eq!(refused(bound(both)?), Some(Error::EvidenceUnavailable));
    assert_eq!(domain.pass_status(id(1), OPERATION), None);
    Ok(())
}

/// The Logical Head alone: T grew past the cut while its chain hash at the
/// cut is still the observed one, so only the head compare can refuse. A
/// minted cut and a reused cut are both judged.
#[test]
fn a_timeline_that_grew_past_the_cut_is_refused_by_the_head_alone() -> TestResult {
    let mut domain = domain()?;
    assert!(domain.stage_reserve(input()?).is_ok());
    assert!(domain.stage_reserve(reuse()?).is_ok());
    let draft = EventDraft::new(
        EntityId::new(),
        Kind::new("world.action"),
        CanonicalBytes::from_vec(vec![0]),
    );
    domain.store.append(id(1), &[draft])?;
    // The chain hash at seq 0 is unchanged.
    assert_eq!(domain.store.chain_hash_at(id(1), Seq::ZERO)?, genesis()?);
    assert_eq!(
        domain.stage_reserve(input()?).err(),
        Some(Error::EvidenceUnavailable)
    );
    assert_eq!(
        domain.stage_reserve(reuse()?).err(),
        Some(Error::EvidenceUnavailable)
    );
    Ok(())
}

/// A Fork child's cut also observes its source Timeline at the Fork cut,
/// which the writer finds from the topology (R9.7, R9.10).
#[test]
fn a_fork_prefix_source_must_be_observed() -> TestResult {
    let mut domain = domain()?;
    domain.pass_states.insert(id(2), pass_state());
    let source = genesis()?;
    let child = store()?.chain_hash_at(id(2), Seq::ZERO)?;
    let with_heads = |chain_heads: Vec<(TimelineId, u64, Hash)>| {
        let mut call = input()?;
        call.timeline = id(2);
        if let Some(minted) = call.minted.as_mut() {
            minted.cut = CommunityObservationCutV1 {
                through_seq: 0,
                chain_heads,
            };
        }
        bound(call).map_err(Box::<dyn std::error::Error>::from)
    };
    assert!(domain
        .stage_reserve(with_heads(vec![(id(1), 0, source), (id(2), 0, child)])?)
        .is_ok());
    // Without the source's entry, or with its hash changed, the prefix is
    // not observed.
    assert_eq!(
        domain
            .stage_reserve(with_heads(vec![(id(2), 0, child)])?)
            .err(),
        Some(Error::EvidenceUnavailable)
    );
    assert_eq!(
        domain
            .stage_reserve(with_heads(vec![(id(1), 0, hash(99)), (id(2), 0, child)])?)
            .err(),
        Some(Error::EvidenceUnavailable)
    );
    // The child's own entry is required too.
    assert_eq!(
        domain
            .stage_reserve(with_heads(vec![(id(1), 0, source)])?)
            .err(),
        Some(Error::EvidenceUnavailable)
    );
    Ok(())
}

/// A store with a chain of `forks` Forks below a root: the root is
/// `id(100)`, each child `id(100 + i)` forks the previous at sequence 0.
fn fork_chain(forks: u8) -> Result<MemoryStore, Box<dyn std::error::Error>> {
    let mut store = MemoryStore::new();
    store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
    store.create_timeline_with_meta(TimelineMeta {
        id: id(100),
        ..TimelineMeta::root_owned("root", actor(10))
    })?;
    for index in 1..=forks {
        store.create_timeline_with_meta(TimelineMeta {
            id: id(100 + index),
            owner: Some(actor(10)),
            fork_point: Some((id(99 + index), Seq::ZERO)),
            ..TimelineMeta::root("fork")
        })?;
    }
    Ok(store)
}

/// The cut compare walks at most the history read bounds' Fork depth, the
/// same bound the materialization reads under: 64 Forks pass, 65 refuse.
#[test]
fn the_cut_compare_walks_the_history_forks_depth() -> TestResult {
    for (forks, holds) in [(64_u8, true), (65, false)] {
        let store = fork_chain(forks)?;
        let leaf = id(100 + forks);
        let chain_heads = (0..=forks)
            .map(|index| {
                store
                    .chain_hash_at(id(100 + index), Seq::ZERO)
                    .map(|hash| (id(100 + index), 0, hash))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut domain =
            MemoryCommunityDomainV1::new(store, [0x5a; 16], MemoryTrustedClockAuthorityV1::new())?;
        domain.native_producer_ordinal = BURNED;
        domain.burned_materialization = Some(BURNED);
        domain.pass_states.insert(leaf, pass_state());
        domain.pass_horizons = Some(domain_policy());
        let mut call = input()?;
        call.timeline = leaf;
        if let Some(minted) = call.minted.as_mut() {
            minted.cut = CommunityObservationCutV1 {
                through_seq: 0,
                chain_heads,
            };
        }
        let staged = domain.stage_reserve(bound(call)?);
        if holds {
            assert!(staged.is_ok());
        } else {
            assert_eq!(staged.err(), Some(Error::EvidenceUnavailable));
        }
    }
    Ok(())
}

/// T's retained observation `reference()`, for a test to change.
fn retained_of(
    domain: &mut MemoryCommunityDomainV1,
) -> Result<&mut CommunityRetainedObservationV1, &'static str> {
    domain
        .pass_states
        .get_mut(&id(1))
        .and_then(|state| state.retained.get_mut(&reference()))
        .ok_or("retained")
}

/// R9.2, R10.7 5j: a reused observation is named by the call; the domain
/// holds its cut and horizon. Its cut is compared with the store like a
/// minted one (12), it is of the same generation, and its horizon must
/// reach `H_g`, which the State records that depend on it live to: one
/// microsecond short gives 6, equal passes.
#[test]
fn a_reused_observation_is_judged_from_what_the_domain_retained() -> TestResult {
    let mut domain = domain()?;
    assert!(domain.stage_reserve(reuse()?).is_ok());
    // A reference no Reserve minted.
    let mut unknown = reuse()?;
    unknown.reused = Some(CommunityNativeNodeReferenceV1 {
        producer_ordinal: 4,
        ..reference()
    });
    assert_eq!(
        domain.stage_reserve(unknown).err(),
        Some(Error::EvidenceUnavailable)
    );
    retained_of(&mut domain)?.not_after_micros = GENERATION_HORIZON - 1;
    assert_eq!(
        domain.stage_reserve(reuse()?).err(),
        Some(Error::StaleFrontier)
    );
    // Another generation's observation is not reused, whatever its horizon.
    {
        let observation = retained_of(&mut domain)?;
        observation.not_after_micros = GENERATION_HORIZON;
        observation.generation = [0x21; 16];
    }
    assert_eq!(
        domain.stage_reserve(reuse()?).err(),
        Some(Error::StaleFrontier)
    );
    {
        let observation = retained_of(&mut domain)?;
        observation.generation = GENERATION;
        observation.cut.through_seq = 1;
    }
    // The cut moved on, so T's Logical Head is no longer where it was.
    assert_eq!(
        domain.stage_reserve(reuse()?).err(),
        Some(Error::EvidenceUnavailable)
    );
    Ok(())
}

/// The writer computes `H_g` and `H_r` from its own sample and the installed
/// owner horizons (R13.4(2)) and records them, the CPR1's included; the
/// request names the installed profile; a reused observation is named
/// exactly when none is minted.
#[test]
fn the_writer_computes_the_horizons_and_binds_the_observation_use() -> TestResult {
    let mut domain = domain()?;
    let staged = domain.stage_reserve(input()?)?;
    domain.apply_reserve(&SEAL, staged)?;
    let record = domain.pass_record(id(1), OPERATION).ok_or("record")?;
    assert_eq!(
        record.reserved.generation_horizon_micros,
        GENERATION_HORIZON
    );
    assert_eq!(record.reserved.outcome_horizon_micros, OUTCOME);
    assert_eq!(
        record.reserved.reservation.evidence_not_after_micros,
        OUTCOME
    );
    // A later sample moves `H_r` until it passes `H_g`, which clamps it.
    for (sample, outcome) in [
        (SAMPLE + 500, OUTCOME + 500),
        (GENERATION_HORIZON - WINDOW, GENERATION_HORIZON),
        (GENERATION_HORIZON - WINDOW + 500, GENERATION_HORIZON),
    ] {
        let mut fresh = self::domain()?;
        set_recording(
            &mut fresh,
            sample + COMMUNITY_DECISION_DEADLINE_MICROS_V1 + 1,
        )?;
        let mut call = input()?;
        call.reservation_sample_micros = sample;
        let staged = fresh.stage_reserve(call)?;
        fresh.apply_reserve(&SEAL, staged)?;
        let record = fresh.pass_record(id(1), OPERATION).ok_or("record")?;
        assert_eq!(record.reserved.outcome_horizon_micros, outcome);
        assert_eq!(
            record.reserved.reservation.evidence_not_after_micros,
            outcome
        );
        assert_eq!(
            record.reserved.generation_horizon_micros,
            GENERATION_HORIZON
        );
    }

    let fresh = self::domain()?;
    let mut profile = input()?;
    profile.request.profile_digest = hash(99);
    assert_eq!(
        fresh.stage_reserve(profile).err(),
        Some(Error::InvalidBinding)
    );
    // A call that names both or neither of a minted and a reused
    // observation.
    let mut both = input()?;
    both.reused = Some(reference());
    assert_eq!(fresh.stage_reserve(both).err(), Some(Error::InvalidBinding));
    let mut neither = reuse()?;
    neither.reused = None;
    assert_eq!(
        fresh.stage_reserve(neither).err(),
        Some(Error::InvalidBinding)
    );

    // Without installed horizons there is nothing to compute from.
    let mut bare = self::domain()?;
    bare.pass_horizons = None;
    assert_eq!(
        bare.stage_reserve(input()?).err(),
        Some(Error::EvidenceUnavailable)
    );
    Ok(())
}

/// R13.2(5), annex §4: the State records of a pass live to `H_g`, which must
/// outlast the pass's decision bound (`t_r` plus the 27 s deadline): equal
/// gives 13, one microsecond more passes.
#[test]
fn the_state_horizon_must_outlast_the_decision_bound() -> TestResult {
    let mut domain = domain()?;
    let bound = SAMPLE + COMMUNITY_DECISION_DEADLINE_MICROS_V1;
    set_evidence(&mut domain, bound)?;
    assert_eq!(
        domain.stage_reserve(input()?).err(),
        Some(Error::EvidenceExpired)
    );
    set_evidence(&mut domain, bound + 1)?;
    assert!(domain.stage_reserve(input()?).is_ok());
    Ok(())
}

/// R10.4(3): the recording horizon the writer judges is the installed one,
/// never the call's: it must pass `t_r` plus the decision deadline.
#[test]
fn the_recording_horizon_is_the_installed_one() -> TestResult {
    let mut domain = domain()?;
    set_recording(&mut domain, RECORDING - 1)?;
    assert_eq!(
        domain.stage_reserve(input()?).err(),
        Some(Error::RecordingUnavailable)
    );
    set_recording(&mut domain, RECORDING)?;
    assert!(domain.stage_reserve(input()?).is_ok());
    Ok(())
}

/// R15.3(2), R15.5: the store re-checks every binding the pass facts hold:
/// one digest row per due member in ascending roster order, `n_due + 1`
/// trace rows, `F_p` of two targets each and two distinct key IDs.
#[test]
fn the_pass_facts_must_agree_with_each_other() -> TestResult {
    let domain = domain()?;
    let member = |roster_index: usize, cmb1: u8| CommunityPassMemberDigestsV1 {
        roster_index,
        cmb1_digest: hash(cmb1),
        cin1_digest: hash(86),
        trust_policy_snapshot_digest: hash(87),
    };
    // A call whose members, trace rows, `F_p` and prepared input set agree
    // with each other, so that a case fails only on the term it changes.
    let with_members = |members: Vec<CommunityPassMemberDigestsV1>| {
        let mut call = input()?;
        let rows = members.len() as u64 + 1;
        let mut pairs: Vec<(Hash, Hash)> = members
            .iter()
            .map(|member| (member.cmb1_digest, member.cin1_digest))
            .collect();
        pairs.sort_by_key(|pair| pair.0);
        call.request.prepared_input_set_digest = input_set(&pairs);
        call.pass.members = members;
        call.pass.trace_rows = rows;
        call.failure_reserve = 2 * rows;
        Ok::<_, Box<dyn std::error::Error>>(call)
    };
    let refused = |call: CommunityReserveInputV1| domain.stage_reserve(call).err();
    // Two members in order, one trace row and two targets more each.
    assert!(domain
        .stage_reserve(with_members(vec![member(0, 100), member(1, 101)])?)
        .is_ok());
    // No due member, with the trace rows, `F_p` and set of an empty pass.
    assert_eq!(
        refused(with_members(Vec::new())?),
        Some(Error::InvalidBinding)
    );
    // Roster indices that repeat or descend, with distinct member digests.
    for indices in [[1, 1], [1, 0]] {
        assert_eq!(
            refused(with_members(vec![
                member(indices[0], 100),
                member(indices[1], 101)
            ])?),
            Some(Error::InvalidBinding)
        );
    }
    // A member row beyond the installed roster.
    assert_eq!(
        refused(with_members(vec![member(2, 100)])?),
        Some(Error::InvalidBinding)
    );
    // Trace rows, `F_p` and the key IDs, each alone.
    let mut rows = input()?;
    rows.pass.trace_rows = 3;
    rows.failure_reserve = 6;
    assert_eq!(refused(rows), Some(Error::InvalidBinding));
    let mut reserve = input()?;
    reserve.failure_reserve = 5;
    assert_eq!(refused(reserve), Some(Error::InvalidBinding));
    let mut keys = input()?;
    keys.pass.failure_cohort_key = keys.pass.metadata_key;
    assert_eq!(refused(keys), Some(Error::InvalidBinding));
    // A key list that is short or long for the installed roster.
    for count in [1_usize, 3] {
        let mut call = input()?;
        call.roster_quarantine_keys = (0..count).map(|_| hash(50)).collect();
        assert_eq!(refused(call), Some(Error::InvalidBinding));
    }
    Ok(())
}

/// A minted observation is retained for reuse with its generation, horizon
/// and cut, and stays retained when its Commit closes it into the selected
/// closure.
#[test]
fn a_minted_observation_stays_reusable_after_its_commit() -> TestResult {
    let mut domain = domain()?;
    let mut call = input()?;
    if let Some(minted) = call.minted.as_mut() {
        minted.not_after_micros = GENERATION_HORIZON + 500;
    }
    let staged = domain.stage_reserve(call)?;
    domain.apply_reserve(&SEAL, staged)?;
    let commit = domain.stage_commit(commit_input())?;
    domain.apply_commit(&SEAL, commit)?;
    let state = domain.pass_states.get(&id(1)).ok_or("state")?;
    let retained = state.retained.get(&reference()).ok_or("retained")?;
    assert_eq!(retained.not_after_micros, GENERATION_HORIZON + 500);
    assert_eq!(retained.generation, GENERATION);
    assert_eq!(retained.cut.through_seq, 0);
    assert!(!state.observations.contains_key(&reference()));
    Ok(())
}

/// T was initialized under one profile, and a Reserve naming the installed
/// profile of another is refused (3) whatever has been reinstalled since.
#[test]
fn a_reserve_names_the_profile_the_timeline_was_initialized_under() -> TestResult {
    let mut domain = domain()?;
    domain
        .pass_states
        .get_mut(&id(1))
        .ok_or("state")?
        .profile_digest = hash(99);
    assert_eq!(
        domain.stage_reserve(input()?).err(),
        Some(Error::InvalidBinding)
    );
    Ok(())
}

/// R10.7 5j order: a short `H_g` gives 13 before a stale generation (5), and
/// a moved cut gives 12 before the 13.
#[test]
fn the_decision_bound_and_the_cut_come_before_the_generation_compare() -> TestResult {
    let mut domain = domain()?;
    let bound_micros = SAMPLE + COMMUNITY_DECISION_DEADLINE_MICROS_V1;
    set_evidence(&mut domain, bound_micros)?;
    let mut stale = input()?;
    stale.generation = [0x21; 16];
    assert_eq!(
        domain.stage_reserve(bound(stale.clone())?).err(),
        Some(Error::EvidenceExpired)
    );
    if let Some(minted) = stale.minted.as_mut() {
        minted.cut.through_seq = 1;
    }
    assert_eq!(
        domain.stage_reserve(bound(stale)?).err(),
        Some(Error::EvidenceUnavailable)
    );
    Ok(())
}

/// A Reserve of a minted materialization whose nodes carry `ordinal`.
fn minting(ordinal: u64) -> Result<CommunityReserveInputV1, Box<dyn std::error::Error>> {
    let mut call = input()?;
    if let Some(minted) = call.minted.as_mut() {
        minted.reference.producer_ordinal = ordinal;
    }
    Ok(call)
}

/// R9.7 step 4, annex §4: a Reserve allocates its native producer ordinal
/// and its pass ordinal in its own transaction, the next of the burned
/// counter and of T's floor; an Abort decrements neither.
#[test]
fn a_reserve_allocates_both_ordinals_in_its_transaction() -> TestResult {
    let mut domain = domain()?;
    let burned = domain.burn_materialization_ordinal(&SEAL)?;
    assert_eq!(burned, BURNED + 1);
    let staged = domain.stage_reserve(minting(burned)?)?;
    // Staging allocates nothing.
    assert_eq!(domain.native_producer_ordinal, burned);
    assert_eq!(
        domain
            .pass_states
            .get(&id(1))
            .map(|state| state.highest_pass_ordinal),
        Some(0)
    );
    domain.apply_reserve(&SEAL, staged)?;
    assert_eq!(domain.native_producer_ordinal, burned + 1);
    assert_eq!(
        domain
            .pass_states
            .get(&id(1))
            .map(|state| state.highest_pass_ordinal),
        Some(1)
    );
    let first = domain.pass_reservation(id(1), OPERATION).ok_or("cpr1")?;
    assert!(first == expected_reservation(1, burned + 1)?);

    let abort = domain.stage_abort(id(1), OPERATION, 0)?;
    domain.apply_abort(&SEAL, &abort)?;
    let staged = stage_other(&mut domain)??;
    domain.apply_reserve(&SEAL, staged)?;
    let second = domain.pass_reservation(id(1), [0x77; 16]).ok_or("cpr1")?;
    assert_eq!(second.native_producer_ordinal, burned + 3);
    assert_eq!(second.pass_key.ordinal(), 2);
    assert_eq!(domain.native_producer_ordinal, burned + 3);
    Ok(())
}

/// A refusal before the apply burns nothing in the Reserve; the burn of a
/// minted materialization stays burned (R10.7 step 5h).
#[test]
fn a_refused_reserve_burns_nothing_and_a_burn_stays_burned() -> TestResult {
    let mut domain = domain()?;
    let burned = domain.burn_materialization_ordinal(&SEAL)?;
    let mut stale = minting(burned)?;
    stale.generation = [0x21; 16];
    assert_eq!(
        domain.stage_reserve(bound(stale)?).err(),
        Some(Error::StaleGeneration)
    );
    assert_eq!(domain.native_producer_ordinal, burned);
    assert_eq!(
        domain
            .pass_states
            .get(&id(1))
            .map(|state| state.highest_pass_ordinal),
        Some(0)
    );
    Ok(())
}

/// R10.7 5h: a minted materialization carries the ordinal the burn made
/// last and nothing has consumed. The burned counter's value without a burn,
/// a later burn's, an ordinal never burned and one already consumed are
/// refused (3); a reused observation names no new materialization.
#[test]
fn a_minted_observation_carries_the_ordinal_just_burned() -> TestResult {
    let mut domain = domain()?;
    // The fixture burned the ordinal 3, which the observation carries.
    assert!(domain.stage_reserve(input()?).is_ok());
    // The counter stands at 3 but nothing is burned: not an allocation.
    domain.burned_materialization = None;
    assert_eq!(
        domain.stage_reserve(input()?).err(),
        Some(Error::InvalidBinding)
    );
    let burned = domain.burn_materialization_ordinal(&SEAL)?;
    assert_eq!(
        domain.stage_reserve(input()?).err(),
        Some(Error::InvalidBinding)
    );
    assert_eq!(
        domain.stage_reserve(minting(burned + 1)?).err(),
        Some(Error::InvalidBinding)
    );
    assert!(domain.stage_reserve(reuse()?).is_ok());
    // The Reserve consumes the burn.
    let staged = domain.stage_reserve(minting(burned)?)?;
    domain.apply_reserve(&SEAL, staged)?;
    assert_eq!(domain.burned_materialization, None);
    // A second minted Reserve (after an Abort, which code 7 would precede)
    // that carries the consumed ordinal is refused and burns nothing.
    let abort = domain.stage_abort(id(1), OPERATION, 0)?;
    domain.apply_abort(&SEAL, &abort)?;
    let mut again = other_call(&domain)?;
    if let Some(minted) = again.minted.as_mut() {
        minted.reference.producer_ordinal = burned;
    }
    assert_eq!(
        domain.stage_reserve(again).err(),
        Some(Error::InvalidBinding)
    );
    assert_eq!(domain.burned_materialization, None);
    assert_eq!(domain.native_producer_ordinal, burned + 1);
    Ok(())
}

/// Neither ordinal wraps: at the top the burn and the Reserve give 14 and
/// change nothing.
#[test]
fn the_ordinals_have_no_next_value_at_the_top() -> TestResult {
    let mut domain = domain()?;
    domain.native_producer_ordinal = u64::MAX;
    assert_eq!(
        domain.burn_materialization_ordinal(&SEAL).err(),
        Some(Error::CapacityExhausted)
    );
    assert_eq!(domain.native_producer_ordinal, u64::MAX);
    assert_eq!(
        domain.stage_reserve(reuse()?).err(),
        Some(Error::CapacityExhausted)
    );
    domain.native_producer_ordinal = BURNED;
    domain
        .pass_states
        .get_mut(&id(1))
        .ok_or("state")?
        .highest_pass_ordinal = u64::MAX;
    assert_eq!(
        domain.stage_reserve(input()?).err(),
        Some(Error::CapacityExhausted)
    );
    Ok(())
}

/// A token whose ordinals are no longer the next ones is stale at the
/// apply, whichever counter moved.
#[test]
fn a_token_is_stale_when_an_ordinal_moved_before_its_apply() -> TestResult {
    let mut burned = domain()?;
    let staged = burned.stage_reserve(input()?)?;
    burned.burn_materialization_ordinal(&SEAL)?;
    assert_eq!(
        burned.apply_reserve(&SEAL, staged).err(),
        Some(Error::Conflict)
    );
    assert_eq!(burned.pass_status(id(1), OPERATION), None);
    assert_eq!(burned.native_producer_ordinal, BURNED + 1);

    let mut passed = domain()?;
    let staged = passed.stage_reserve(input()?)?;
    passed
        .pass_states
        .get_mut(&id(1))
        .ok_or("state")?
        .highest_pass_ordinal = 1;
    assert_eq!(
        passed.apply_reserve(&SEAL, staged).err(),
        Some(Error::Conflict)
    );
    assert_eq!(passed.pass_status(id(1), OPERATION), None);
    assert_eq!(passed.native_producer_ordinal, BURNED);
    Ok(())
}

/// The CRI1 is validated with the other bindings and every refusal is 3: a
/// zero digest, a requested horizon of 0 or past `i64::MAX`, and an `H_r`
/// the CPR1 cannot hold (R10.4(2): a `run_pass` refusal never gives 2).
#[test]
fn an_invalid_request_or_reservation_is_refused_with_3() -> TestResult {
    let mut domain = domain()?;
    let mut zero = input()?;
    zero.request.roster_digest = Hash::zero();
    assert_eq!(
        domain.stage_reserve(zero).err(),
        Some(Error::InvalidBinding)
    );
    for horizon in [0, i64::MAX as u64 + 1] {
        let mut call = input()?;
        call.request.requested_evidence_horizon = horizon;
        assert_eq!(
            domain.stage_reserve(call).err(),
            Some(Error::InvalidBinding)
        );
    }
    // Horizons at the top: `H_r` is the sample plus the window, past the
    // trusted range, which the CPR1 refuses.
    let top = u64::MAX;
    {
        let policy = domain.pass_horizons.as_mut().ok_or("horizons")?;
        policy.retention.generation_not_after_micros = top;
        policy.retention.metadata_not_after_micros = top;
        policy.retention.recording_not_after_micros = top;
        policy.owners.evidence_micros = top;
    }
    let mut call = input()?;
    call.reservation_sample_micros = i64::MAX as u64;
    if let Some(minted) = call.minted.as_mut() {
        minted.not_after_micros = top;
    }
    assert_eq!(
        domain.stage_reserve(call).err(),
        Some(Error::InvalidBinding)
    );
    Ok(())
}

/// The CSI1 a Reserve commits carries the burned native ordinal and T's new
/// pass floor, and nothing else changes.
#[test]
fn the_selection_successor_carries_the_new_floors() -> TestResult {
    let floor = |timeline: TimelineId, highest_pass_ordinal: u64| CommunityTimelineFloorV1 {
        timeline,
        highest_pass_ordinal,
        active_generation: Some(GENERATION),
        closed_generations: CommunityGenerationIdsV1::from_ids(&[]),
        selected_head: Some(hash(30)),
        closed: false,
    };
    let floors = [floor(id(1), 4), floor(id(2), 9)];
    let current = CommunitySelectionV1::new(CommunitySelectionInputV1 {
        store_incarnation: [0x5a; 16],
        installed_catalogue_digest: hash(1),
        native_profile_digest: hash(2),
        highest_native_producer_ordinal: 6,
        timeline_floors: CommunityTimelineFloorsV1::from_floors(&floors),
        metadata_not_after_micros: 20_000,
    })?
    .to_canonical_cbor();

    let next = community_reserve_selection_v1(&current, id(1), GENERATION, 7, 5)?;
    let decoded = CommunitySelectionV1::from_canonical_cbor(&next)?;
    let fields = decoded.as_input();
    assert_eq!(fields.store_incarnation, [0x5a; 16]);
    assert_eq!(fields.installed_catalogue_digest, hash(1));
    assert_eq!(fields.native_profile_digest, hash(2));
    assert_eq!(fields.highest_native_producer_ordinal, 7);
    assert_eq!(fields.metadata_not_after_micros, 20_000);
    let rows = fields
        .timeline_floors
        .iter()
        .collect::<Result<Vec<_>, Error>>()?;
    assert_eq!(rows.len(), 2);
    assert!(rows[0] == floor(id(1), 5));
    assert!(rows[1] == floor(id(2), 9));

    // Ordinals that are not above the CSI1's, or not the next floor.
    for (native, pass) in [(6, 5), (7, 4), (7, 6)] {
        assert_eq!(
            community_reserve_selection_v1(&current, id(1), GENERATION, native, pass).err(),
            Some(Error::InvalidBinding)
        );
    }
    // A Timeline with no floor row, and a record that is no CSI1.
    assert_eq!(
        community_reserve_selection_v1(&current, id(3), GENERATION, 7, 1).err(),
        Some(Error::EvidenceUnavailable)
    );
    assert_eq!(
        community_reserve_selection_v1(&[0x80], id(1), GENERATION, 7, 5).err(),
        Some(Error::EvidenceUnavailable)
    );
    // A floor closed to new allocation, and another generation's Reserve.
    let closed_floors = [CommunityTimelineFloorV1 {
        closed: true,
        ..floor(id(1), 4)
    }];
    let closed = CommunitySelectionV1::new(CommunitySelectionInputV1 {
        store_incarnation: [0x5a; 16],
        installed_catalogue_digest: hash(1),
        native_profile_digest: hash(2),
        highest_native_producer_ordinal: 6,
        timeline_floors: CommunityTimelineFloorsV1::from_floors(&closed_floors),
        metadata_not_after_micros: 20_000,
    })?
    .to_canonical_cbor();
    assert_eq!(
        community_reserve_selection_v1(&closed, id(1), GENERATION, 7, 5).err(),
        Some(Error::ContextClosed)
    );
    assert_eq!(
        community_reserve_selection_v1(&current, id(1), [0x21; 16], 7, 5).err(),
        Some(Error::StaleGeneration)
    );
    Ok(())
}

/// A minted observation's records must reach `H_g`, like a reused one's:
/// one microsecond short gives 6, equal passes.
#[test]
fn a_minted_observation_must_reach_the_state_horizon() -> TestResult {
    let domain = domain()?;
    let minting = |not_after_micros: u64| {
        let mut call = input()?;
        if let Some(minted) = call.minted.as_mut() {
            minted.not_after_micros = not_after_micros;
        }
        Ok::<_, Box<dyn std::error::Error>>(call)
    };
    assert!(domain.stage_reserve(minting(GENERATION_HORIZON)?).is_ok());
    assert_eq!(
        domain.stage_reserve(minting(GENERATION_HORIZON - 1)?).err(),
        Some(Error::StaleFrontier)
    );
    Ok(())
}

/// The request names the pass facts' members: its prepared input set is the
/// digest of their `[cmb1, cin1]` pairs strictly ordered by member digest,
/// whatever their roster order (parent annex, prepared input set preimage).
#[test]
fn the_request_must_name_the_pass_members() -> TestResult {
    let domain = domain()?;
    let mut other = input()?;
    other.request.prepared_input_set_digest = hash(1);
    assert_eq!(
        domain.stage_reserve(other).err(),
        Some(Error::InvalidBinding)
    );
    let mut changed = input()?;
    changed.pass.members = vec![CommunityPassMemberDigestsV1 {
        cin1_digest: hash(99),
        ..facts().members[0]
    }];
    assert_eq!(
        domain.stage_reserve(changed).err(),
        Some(Error::InvalidBinding)
    );
    // Roster order and digest order differ: the set is ordered by digest.
    let member = |roster_index: usize, cmb1: u8| CommunityPassMemberDigestsV1 {
        roster_index,
        cmb1_digest: hash(cmb1),
        cin1_digest: hash(86),
        trust_policy_snapshot_digest: hash(87),
    };
    let mut two = input()?;
    two.pass.members = vec![member(0, 120), member(1, 110)];
    two.pass.trace_rows = 3;
    two.failure_reserve = 6;
    two.request.prepared_input_set_digest =
        input_set(&[(hash(110), hash(86)), (hash(120), hash(86))]);
    assert!(domain.stage_reserve(two.clone()).is_ok());
    // The roster order (120, 110) is accepted only because the writer sorts
    // by member digest first. A set naming one member, and members that
    // share a digest, are refused.
    two.request.prepared_input_set_digest = input_set(&[(hash(110), hash(86))]);
    assert_eq!(
        domain.stage_reserve(two.clone()).err(),
        Some(Error::InvalidBinding)
    );
    two.pass.members = vec![member(0, 110), member(1, 110)];
    two.request.prepared_input_set_digest = input_set(&[(hash(110), hash(86))]);
    assert_eq!(domain.stage_reserve(two).err(), Some(Error::InvalidBinding));
    Ok(())
}
