//! Seal: the R10.3(7) compares, annotation admission in selection order and
//! the CPS1 and CPD1 trace fields (ADR-129 revisions 14 and 15).

use std::collections::BTreeMap;
use std::sync::Arc;

use pos_core::community_lifecycle::{
    CommunityAnnotationCandidateV1 as Candidate, CommunityAnnotationContextV1 as Context,
    CommunityAnnotationOmissionV1 as Omission, CommunityAnnotationOmissionsV1 as Omissions,
    CommunityAnnotationRecordsV1 as Records, CommunityDigestListV1 as Digests,
    CommunityGraphCountsV1, CommunityLifecycleErrorV1 as Error,
    CommunityNativeNodeReferenceV1 as Reference, CommunityPassKeyV1, CommunityReservationInputV1,
    CommunitySharedCountsV1, CommunityTypedInputRefV1 as Typed, COMMUNITY_CONTROL_OPERATIONS_V1,
    COMMUNITY_CUMULATIVE_RECORD_LIMITS_V1, COMMUNITY_SHARED_RECORD_LIMITS_V1,
};
use pos_core::store::EventStore;
use pos_core::{
    AuthorityTrustRootSealV1, ErasureContainmentGateV1, Hash, TimelineId, TimelineMeta,
};
use ulid::Ulid;

use super::super::pass_record::{
    CommunityPassRecordV1, CommunityPassStatusV1, CommunityReservedPassV1,
};
use super::super::pass_state::{CommunityGenerationCountsV1, CommunityPassStateV1};
use super::{CommunitySealCandidateV1, CommunitySealInputV1, CommunitySealInvocationV1};
use crate::community::MemoryCommunityDomainV1;
use crate::memory::MemoryStore;
use crate::MemoryTrustedClockAuthorityV1;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const SEAL: AuthorityTrustRootSealV1 = AuthorityTrustRootSealV1::for_composition_root();
const GENERATION: [u8; 16] = [0x20; 16];
const OPERATION: [u8; 16] = [0x30; 16];
const INCARNATION: [u8; 16] = [0x5a; 16];
const HORIZON: u64 = 9_000;

const fn hash(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
}

fn id() -> TimelineId {
    TimelineId::from_ulid(Ulid::from_bytes([1; 16]))
}

static STEPS: [Hash; 1] = [hash(0x71)];
static REVISIONS: [Hash; 1] = [hash(0x72)];
static PROGRESS: [Hash; 1] = [hash(0x73)];
static REQUIRED: [Hash; 2] = [hash(0x74), hash(0x75)];

const fn counts(base: u64) -> CommunitySharedCountsV1 {
    CommunitySharedCountsV1 {
        nodes: base,
        edges: base + 1,
        declared_inputs: base + 2,
        encoded_record_bytes: base + 3,
    }
}

fn pass_key() -> Result<CommunityPassKeyV1, Error> {
    CommunityPassKeyV1::new(id(), GENERATION, 7)
}

fn domain(operations: u64) -> Result<MemoryCommunityDomainV1, Box<dyn std::error::Error>> {
    let mut store = MemoryStore::new();
    store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
    store.create_timeline_with_meta(TimelineMeta {
        id: id(),
        ..TimelineMeta::root_owned(
            "t",
            pos_core::EntityId::from_ulid(Ulid::from_bytes([10; 16])),
        )
    })?;
    let mut domain =
        MemoryCommunityDomainV1::new(store, INCARNATION, MemoryTrustedClockAuthorityV1::new())?;
    domain.pass_states.insert(id(), pass_state(operations));
    domain
        .pass_records
        .insert((id(), OPERATION), record(1_000)?);
    Ok(domain)
}

/// T's state, with `operations` counted control operations in G.
fn pass_state(operations: u64) -> CommunityPassStateV1 {
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
        closure: std::collections::BTreeSet::new(),
        observations: BTreeMap::new(),
        scope_rows: BTreeMap::new(),
        generations: BTreeMap::from([(
            GENERATION,
            CommunityGenerationCountsV1 {
                outcomes: 1,
                materializations: operations,
                annotations: 0,
            },
        )]),
        retained: BTreeMap::new(),
    }
}

/// A Reserved pass with a materialization of `counts(10)` over `counts(100)`.
fn record(trace_rows: u64) -> Result<CommunityPassRecordV1, Error> {
    Ok(CommunityPassRecordV1 {
        reserved: CommunityReservedPassV1 {
            reservation: CommunityReservationInputV1 {
                pass_key: pass_key()?,
                request_digest: hash(80),
                native_producer_ordinal: 5,
                predecessor_head_digest: hash(30),
                roster_digest: hash(81),
                prepared_input_set_digest: hash(82),
                profile_digest: hash(83),
                evidence_not_after_micros: HORIZON,
            },
            cbq1_digest: hash(84),
            quote_maxima: [u64::MAX; 3],
            trace_rows,
            members: Vec::new(),
            metadata_key: [0x90; 16],
            failure_cohort_key: [0x91; 16],
            generation_horizon_micros: 10_000,
            outcome_horizon_micros: HORIZON,
        },
        prior_shared_counts: counts(100),
        materialization: Some(counts(10)),
        status: CommunityPassStatusV1::Reserved,
        sealed_result_digest: None,
        live: true,
    })
}

fn candidate() -> CommunitySealCandidateV1<'static> {
    CommunitySealCandidateV1 {
        invocation_step_digests: Digests::from_digests(&STEPS),
        event_draft_vector_digest: hash(0x60),
        event_draft_manifest_digest: hash(0x61),
        new_revision_digests: Digests::from_digests(&REVISIONS),
        new_member_progress_digests: Digests::from_digests(&PROGRESS),
        candidate_head_digest: hash(0x62),
        replay_recording_digest: hash(0x63),
        graph_root_digest: hash(0x64),
        factual_binding: None,
        required_node_digests: Digests::from_digests(&REQUIRED),
        additions: counts(1_000),
        graph_counts: CommunityGraphCountsV1 {
            registrations: 1,
            edges: 2,
            keys: 3,
            maximum_depth: 4,
            registration_bytes: 5,
            artifact_bytes: 6,
        },
    }
}

fn input(invocations: Vec<CommunitySealInvocationV1<'_>>) -> CommunitySealInputV1<'_> {
    CommunitySealInputV1 {
        timeline: id(),
        reservation_operation_id: OPERATION,
        candidate: candidate(),
        invocations,
    }
}

const fn native(producer: u64) -> Reference {
    Reference {
        store_incarnation: INCARNATION,
        producer_ordinal: producer,
        node_ordinal: 1,
        node_digest: hash(0x40),
    }
}

fn context(member: u8) -> Result<Context, Error> {
    Ok(Context {
        pass_key: pass_key()?,
        member_binding_digest: hash(member),
        invocation_step_digest: hash(5),
        step: native(10),
        producer_ordinal: 1_000,
        node_ordinal: u32::from(member),
        scope_binding_digest: hash(6),
        authorization_digest: hash(7),
        provenance_digest: hash(8),
        evidence_not_after_micros: HORIZON,
    })
}

fn refs(producers: std::ops::Range<u64>) -> Vec<Typed<'static>> {
    producers
        .map(|producer| Typed::Native(native(producer)))
        .collect()
}

const fn item<'a>(inputs: &'a [Typed<'a>]) -> Candidate<'a> {
    Candidate {
        guest_index: 0,
        claim_bytes: b"claim",
        inputs,
    }
}

fn invocation(
    member: u8,
    items: Vec<Candidate<'_>>,
) -> Result<CommunitySealInvocationV1<'_>, Error> {
    Ok(CommunitySealInvocationV1 {
        context: context(member)?,
        omissions: Omissions::none(),
        items,
    })
}

const fn only(reason: Omission) -> Omissions {
    Omissions::none().with_reason(reason)
}

#[test]
fn a_pass_without_annotations_seals_and_latches_its_result() -> TestResult {
    let mut domain = domain(1)?;
    let staged = domain.stage_seal(&input(Vec::new()))?;
    let sealed = staged.sealed().clone();
    assert!(sealed.annotation_manifest_digest.is_none() && sealed.trace_root.is_none());
    assert!(sealed.shared_counts == counts(1_000));
    assert_eq!(sealed.annotation.rows, 0);
    domain.apply_seal(&SEAL, &staged)?;
    assert_eq!(
        domain.pass_status(id(), OPERATION),
        Some(CommunityPassStatusV1::Sealed)
    );
    let latched = domain
        .pass_record(id(), OPERATION)
        .and_then(|record| record.sealed_result_digest);
    assert_eq!(latched, Some(sealed.result_digest));
    assert!(domain.pass_is_live(id(), OPERATION));
    Ok(())
}

#[test]
fn a_replayed_seal_is_the_same_result_and_a_different_one_conflicts() -> TestResult {
    let mut domain = domain(1)?;
    let original = domain.stage_seal(&input(Vec::new()))?;
    let digest = original.sealed().result_digest;
    let mut other = input(Vec::new());
    other.candidate.candidate_head_digest = hash(0x66);
    let different = domain.stage_seal(&other)?;
    domain.apply_seal(&SEAL, &original)?;
    let replay = domain.stage_seal(&input(Vec::new()))?;
    assert_eq!(replay.sealed().result_digest, digest);
    domain.apply_seal(&SEAL, &replay)?;
    assert!(matches!(domain.stage_seal(&other), Err(Error::Conflict)));
    assert!(matches!(
        domain.apply_seal(&SEAL, &different),
        Err(Error::Conflict)
    ));
    Ok(())
}

#[test]
fn only_a_recorded_unresolved_pass_seals() -> TestResult {
    let mut domain = domain(1)?;
    let staged = domain.stage_seal(&input(Vec::new()))?;
    let mut unknown = input(Vec::new());
    unknown.reservation_operation_id = [0x31; 16];
    assert!(matches!(
        domain.stage_seal(&unknown),
        Err(Error::EvidenceUnavailable)
    ));
    assert!(domain.set_pass_status(id(), OPERATION, CommunityPassStatusV1::Aborted));
    assert!(matches!(
        domain.stage_seal(&input(Vec::new())),
        Err(Error::InvalidBinding)
    ));
    assert!(matches!(
        domain.apply_seal(&SEAL, &staged),
        Err(Error::InvalidBinding)
    ));
    Ok(())
}

/// Replace the quote maxima and the counters the pass was quoted over.
fn quoted(domain: &mut MemoryCommunityDomainV1, maxima: [u64; 3], prior: CommunitySharedCountsV1) {
    domain
        .pass_records
        .entry((id(), OPERATION))
        .and_modify(|record| {
            record.reserved.quote_maxima = maxima;
            record.prior_shared_counts = prior;
        });
}

#[test]
fn the_totals_without_annotations_are_at_most_the_quote() -> TestResult {
    // The materialization's `counts(10)` and the candidate's `counts(1000)`.
    let totals = [1_010, 1_012, 1_016];
    let mut domain = domain(1)?;
    quoted(&mut domain, totals, counts(100));
    assert!(domain.stage_seal(&input(Vec::new())).is_ok());
    for position in [0_usize, 1, 2] {
        let mut under = totals;
        under[position] -= 1;
        quoted(&mut domain, under, counts(100));
        assert!(matches!(
            domain.stage_seal(&input(Vec::new())),
            Err(Error::CapacityExhausted)
        ));
    }
    Ok(())
}

#[test]
fn the_totals_are_within_p() -> TestResult {
    let domain = domain(1)?;
    let [nodes, edges, bytes] = COMMUNITY_SHARED_RECORD_LIMITS_V1;
    let mut over_nodes = input(Vec::new());
    over_nodes.candidate.additions.nodes = nodes - 9;
    let mut over_edges = input(Vec::new());
    over_edges.candidate.additions.edges = edges - 10;
    let mut over_bytes = input(Vec::new());
    over_bytes.candidate.additions.encoded_record_bytes = bytes - 12;
    for over in [over_nodes, over_edges, over_bytes] {
        assert!(matches!(
            domain.stage_seal(&over),
            Err(Error::CapacityExhausted)
        ));
    }
    let mut at_nodes = input(Vec::new());
    at_nodes.candidate.additions.nodes = nodes - 10;
    assert!(domain.stage_seal(&at_nodes).is_ok());
    Ok(())
}

#[test]
fn the_counters_are_within_c() -> TestResult {
    let [nodes, edges, _] = COMMUNITY_CUMULATIVE_RECORD_LIMITS_V1;
    let mut domain = domain(1)?;
    // The pass adds 1,010 nodes and 1,012 edges.
    for (prior, within) in [
        (
            CommunitySharedCountsV1 {
                nodes: nodes - 1_010,
                ..counts(0)
            },
            true,
        ),
        (
            CommunitySharedCountsV1 {
                nodes: nodes - 1_009,
                ..counts(0)
            },
            false,
        ),
        (
            CommunitySharedCountsV1 {
                edges: edges - 1_012,
                ..counts(0)
            },
            true,
        ),
        (
            CommunitySharedCountsV1 {
                edges: edges - 1_011,
                ..counts(0)
            },
            false,
        ),
    ] {
        quoted(&mut domain, [u64::MAX; 3], prior);
        assert_eq!(domain.stage_seal(&input(Vec::new())).is_ok(), within);
    }
    Ok(())
}

#[test]
fn an_annotation_is_staged_charged_and_bound_in_both_records() -> TestResult {
    let domain = domain(1)?;
    let inputs = refs(11..13);
    let items = vec![item(&inputs)];
    let expected = Records::stage(&context(1)?, &items)?.ok_or("records")?;
    let staged = domain.stage_seal(&input(vec![invocation(1, items)?]))?;
    let sealed = staged.sealed();
    let charge = expected.charge();
    assert_eq!(sealed.annotation, charge);
    assert_eq!(
        sealed.annotation_manifest_digest,
        Some(expected.manifest_digest())
    );
    assert_eq!(sealed.trace_root, Some(expected.node().node_digest));
    assert!(sealed.omissions == [Omissions::none()]);
    assert_eq!(sealed.shared_counts.nodes, 1_000 + charge.nodes);
    assert_eq!(sealed.shared_counts.edges, 1_001 + charge.edges);
    assert_eq!(sealed.shared_counts.declared_inputs, 1_002);
    assert_eq!(
        sealed.shared_counts.encoded_record_bytes,
        1_003 + charge.bytes
    );
    let plain = domain.stage_seal(&input(Vec::new()))?;
    assert_ne!(plain.sealed().result_digest, sealed.result_digest);
    assert_ne!(
        plain.sealed().dependency_bundle_digest,
        sealed.dependency_bundle_digest
    );
    Ok(())
}

#[test]
fn the_control_operation_cap_omits_annotations_and_the_pass_still_seals() -> TestResult {
    // The pass's own materialization is counted: 8,191 before it, 8,192 now.
    let inputs = refs(11..13);
    for (operations, retained) in [
        (COMMUNITY_CONTROL_OPERATIONS_V1 - 1, true),
        (COMMUNITY_CONTROL_OPERATIONS_V1, false),
    ] {
        let domain = domain(operations)?;
        let staged = domain.stage_seal(&input(vec![invocation(1, vec![item(&inputs)])?]))?;
        let sealed = staged.sealed();
        assert_eq!(sealed.trace_root.is_some(), retained);
        let expected = if retained {
            Omissions::none()
        } else {
            only(Omission::AnnotationBudget)
        };
        assert!(sealed.omissions[0] == expected);
    }
    Ok(())
}

#[test]
fn the_trace_room_is_the_held_share_of_rows() -> TestResult {
    let inputs = refs(11..13);
    for (rows, retained) in [(1, false), (2, true)] {
        let mut domain = domain(1)?;
        domain
            .pass_records
            .entry((id(), OPERATION))
            .and_modify(|record| record.reserved.trace_rows = rows);
        let staged = domain.stage_seal(&input(vec![invocation(1, vec![item(&inputs)])?]))?;
        assert_eq!(staged.sealed().trace_root.is_some(), retained);
    }
    Ok(())
}

#[test]
fn a_misfit_is_omitted_and_selection_continues() -> TestResult {
    let domain = domain(1)?;
    let [_, edges, _] = COMMUNITY_SHARED_RECORD_LIMITS_V1;
    // k = 257 is over the cap; k = 2 fits after it.
    let too_many = refs(11..267);
    let small = refs(11..12);
    let mut call = input(vec![invocation(1, vec![item(&too_many), item(&small)])?]);
    let staged = domain.stage_seal(&call)?;
    let expected = Records::stage(&context(1)?, &[item(&small)])?.ok_or("records")?;
    assert_eq!(
        staged.sealed().annotation_manifest_digest,
        Some(expected.manifest_digest())
    );
    assert!(staged.sealed().omissions[0] == only(Omission::AnnotationBudget));
    // The edges leave room for k = 2 only: k = 5 is a misfit under P.
    let larger = refs(11..15);
    call = input(vec![invocation(1, vec![item(&larger), item(&small)])?]);
    call.candidate.additions.edges = edges - 11 - 2;
    let staged = domain.stage_seal(&call)?;
    assert_eq!(
        staged.sealed().annotation_manifest_digest,
        Some(expected.manifest_digest())
    );
    assert!(staged.sealed().omissions[0] == only(Omission::AnnotationBudget));
    Ok(())
}

#[test]
fn only_the_first_annotating_invocation_keeps_its_items() -> TestResult {
    let domain = domain(1)?;
    let first = refs(11..12);
    let second = refs(12..13);
    let staged = domain.stage_seal(&input(vec![
        invocation(1, vec![item(&first)])?,
        invocation(2, vec![item(&second)])?,
    ]))?;
    let expected = Records::stage(&context(1)?, &[item(&first)])?.ok_or("records")?;
    let sealed = staged.sealed();
    assert_eq!(
        sealed.annotation_manifest_digest,
        Some(expected.manifest_digest())
    );
    assert_eq!(sealed.trace_root, Some(expected.node().node_digest));
    assert!(sealed.omissions == [Omissions::none(), only(Omission::AnnotationPolicy)]);
    Ok(())
}

#[test]
fn a_later_invocation_keeps_its_items_when_the_first_keeps_none() -> TestResult {
    let domain = domain(1)?;
    let too_many = refs(11..267);
    let second = refs(12..13);
    let staged = domain.stage_seal(&input(vec![
        invocation(1, vec![item(&too_many)])?,
        invocation(2, vec![item(&second)])?,
    ]))?;
    let expected = Records::stage(&context(2)?, &[item(&second)])?.ok_or("records")?;
    let sealed = staged.sealed();
    assert_eq!(
        sealed.annotation_manifest_digest,
        Some(expected.manifest_digest())
    );
    assert!(sealed.omissions == [only(Omission::AnnotationBudget), Omissions::none()]);
    Ok(())
}

#[test]
fn earlier_omission_reasons_are_kept() -> TestResult {
    let domain = domain(1)?;
    let mut first = invocation(1, Vec::new())?;
    first.omissions = only(Omission::InvalidClaim);
    let staged = domain.stage_seal(&input(vec![first]))?;
    assert!(staged.sealed().omissions == [only(Omission::InvalidClaim)]);
    assert!(staged.sealed().trace_root.is_none());
    Ok(())
}

#[test]
fn an_item_that_is_not_an_annotation_of_its_invocation_is_refused() -> TestResult {
    let domain = domain(1)?;
    let inputs = refs(11..12);
    let backwards = Candidate {
        guest_index: 0,
        claim_bytes: b"claim",
        inputs: &inputs,
    };
    let after = Candidate {
        guest_index: 1,
        ..backwards
    };
    assert!(matches!(
        domain.stage_seal(&input(vec![invocation(1, vec![after, backwards])?])),
        Err(Error::InvalidBinding)
    ));
    Ok(())
}

#[test]
fn the_dependency_bundle_and_the_reservation_must_be_valid() -> TestResult {
    let mut domain = domain(1)?;
    let mut no_nodes = input(Vec::new());
    no_nodes.candidate.required_node_digests = Digests::from_digests(&[]);
    assert!(matches!(
        domain.stage_seal(&no_nodes),
        Err(Error::BoundsExceeded)
    ));
    let mut no_head = input(Vec::new());
    no_head.candidate.candidate_head_digest = Hash::zero();
    assert!(matches!(
        domain.stage_seal(&no_head),
        Err(Error::InvalidBinding)
    ));
    domain
        .pass_records
        .entry((id(), OPERATION))
        .and_modify(|record| record.reserved.reservation.roster_digest = Hash::zero());
    assert!(matches!(
        domain.stage_seal(&input(Vec::new())),
        Err(Error::InvalidBinding)
    ));
    Ok(())
}
