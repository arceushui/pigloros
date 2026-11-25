//! Seal: the R10.3(7) compares, annotation admission in selection order and
//! the CPS1 and CPD1 trace fields (ADR-129 revisions 14 and 15).

use std::collections::BTreeMap;
use std::sync::Arc;

use pos_core::community_lifecycle::{
    CommunityAnnotationCandidateV1 as Candidate, CommunityAnnotationContextV1 as Context,
    CommunityAnnotationOmissionV1 as Omission, CommunityAnnotationOmissionsV1 as Omissions,
    CommunityAnnotationRecordsV1 as Records, CommunityArtifactKindV1, CommunityArtifactOperationV1,
    CommunityArtifactPurposeV1, CommunityDependencyBundleInputV1, CommunityDependencyBundleV1,
    CommunityDigestListV1 as Digests, CommunityEvidenceRootsV1, CommunityGraphCountsV1,
    CommunityKeyIntentInputV1, CommunityLifecycleErrorV1 as Error, CommunityMemberSlotsV1,
    CommunityNativeNodeReferenceV1 as Reference, CommunityPassKeyV1, CommunityRecordKindsV1,
    CommunityReservationInputV1, CommunityReservationV1, CommunitySealedResultInputV1,
    CommunitySealedResultV1, CommunitySharedCountsV1, CommunityTypedInputRefV1 as Typed,
    COMMUNITY_CONTROL_OPERATIONS_V1, COMMUNITY_CUMULATIVE_RECORD_LIMITS_V1,
    COMMUNITY_MAXIMUM_ROSTER_V1, COMMUNITY_MAXIMUM_STORE_KEYS_V1,
    COMMUNITY_SHARED_RECORD_LIMITS_V1, MAX_COMMUNITY_DIRECT_INPUTS_V1,
    MAX_COMMUNITY_EXPANDED_INPUTS_V1, MAX_COMMUNITY_OBJECT_BINDINGS_V1,
};
use pos_core::store::EventStore;
use pos_core::{
    AuthorityTrustRootSealV1, ErasureContainmentGateV1, Hash, TimelineId, TimelineMeta,
};
use ulid::Ulid;

use super::super::erasure_budget::CommunityPendingReservationV1;
use super::super::pass_record::{
    CommunityPassMemberDigestsV1, CommunityPassRecordV1, CommunityPassStatusV1,
    CommunityReservedPassV1,
};
use super::super::pass_state::{CommunityGenerationCountsV1, CommunityPassStateV1};
use super::super::vault::VaultKeyV1;
use super::{
    CommunityAnnotationPlanV1, CommunitySealCandidateV1, CommunitySealInputV1,
    CommunitySealInvocationV1, CommunityStagedSealV1, SealRoom,
};
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

static STEPS: [Hash; 2] = [hash(0x71), hash(0x72)];
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
        profile_digest: hash(31),
        highest_pass_ordinal: 0,
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

fn member(index: u8) -> CommunityPassMemberDigestsV1 {
    CommunityPassMemberDigestsV1 {
        roster_index: usize::from(index),
        cmb1_digest: hash(index),
        cin1_digest: hash(0xa0 + index),
        trust_policy_snapshot_digest: hash(0xb0 + index),
    }
}

/// A Reserved pass with a materialization of `counts(10)` over `counts(100)`.
fn record(trace_rows: u64) -> Result<CommunityPassRecordV1, Error> {
    Ok(CommunityPassRecordV1 {
        reserved: CommunityReservedPassV1 {
            reservation: CommunityReservationInputV1 {
                pass_key: pass_key()?,
                request_digest: hash(80),
                native_producer_ordinal: 1_000,
                predecessor_head_digest: hash(30),
                roster_digest: hash(81),
                prepared_input_set_digest: hash(82),
                profile_digest: hash(83),
                evidence_not_after_micros: HORIZON,
            },
            cbq1_digest: hash(84),
            quote_maxima: [u64::MAX; 3],
            trace_rows,
            members: vec![member(1), member(2)],
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

/// Plan, then Seal once with a CRR1 digest, as the pipeline does.
fn seal(
    domain: &MemoryCommunityDomainV1,
    input: &CommunitySealInputV1<'_>,
) -> Result<CommunityStagedSealV1, Error> {
    domain
        .plan_annotations(input)
        .and_then(|plan| domain.stage_seal(input, hash(0x63), &plan))
}

fn candidate() -> CommunitySealCandidateV1<'static> {
    CommunitySealCandidateV1 {
        invocation_step_digests: Digests::from_digests(&STEPS),
        event_draft_vector_digest: hash(0x60),
        event_draft_manifest_digest: hash(0x61),
        new_revision_digests: Digests::from_digests(&REVISIONS),
        new_member_progress_digests: Digests::from_digests(&PROGRESS),
        candidate_head_digest: hash(0x62),
        graph_root_digest: hash(0x64),
        factual_binding: None,
        required_node_digests: Digests::from_digests(&REQUIRED),
        additions: counts(1_000),
        graph_counts: graph_counts(),
    }
}

const fn graph_counts() -> CommunityGraphCountsV1 {
    CommunityGraphCountsV1 {
        registrations: 1,
        edges: 2,
        keys: 3,
        maximum_depth: 4,
        registration_bytes: 5,
        artifact_bytes: 6,
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

/// The invocation step: a node of the pass's producer, before the
/// Annotation CPN1s (node ordinals 1 and 2).
const fn step() -> Reference {
    Reference {
        producer_ordinal: 1_000,
        node_ordinal: 0,
        ..native(10)
    }
}

fn context(member: u8) -> Result<Context, Error> {
    Ok(Context {
        pass_key: pass_key()?,
        member_binding_digest: hash(member),
        invocation_step_digest: hash(0x70 + member),
        step: step(),
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
    let staged = seal(&domain, &input(Vec::new()))?;
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
    let original = seal(&domain, &input(Vec::new()))?;
    let digest = original.sealed().result_digest;
    let mut other = input(Vec::new());
    other.candidate.candidate_head_digest = hash(0x66);
    let different = seal(&domain, &other)?;
    domain.apply_seal(&SEAL, &original)?;
    let replay = seal(&domain, &input(Vec::new()))?;
    assert_eq!(replay.sealed().result_digest, digest);
    domain.apply_seal(&SEAL, &replay)?;
    assert!(matches!(seal(&domain, &other), Err(Error::Conflict)));
    assert!(matches!(
        domain.apply_seal(&SEAL, &different),
        Err(Error::Conflict)
    ));
    Ok(())
}

#[test]
fn only_a_recorded_unresolved_pass_seals() -> TestResult {
    let mut domain = domain(1)?;
    let staged = seal(&domain, &input(Vec::new()))?;
    let mut unknown = input(Vec::new());
    unknown.reservation_operation_id = [0x31; 16];
    assert!(matches!(
        seal(&domain, &unknown),
        Err(Error::EvidenceUnavailable)
    ));
    assert!(domain.set_pass_status(id(), OPERATION, CommunityPassStatusV1::Aborted));
    assert!(matches!(
        seal(&domain, &input(Vec::new())),
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
    assert!(seal(&domain, &input(Vec::new())).is_ok());
    for position in [0_usize, 1, 2] {
        let mut under = totals;
        under[position] -= 1;
        quoted(&mut domain, under, counts(100));
        assert!(matches!(
            seal(&domain, &input(Vec::new())),
            Err(Error::InvalidBinding)
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
        assert!(matches!(seal(&domain, &over), Err(Error::InvalidBinding)));
    }
    let mut at_nodes = input(Vec::new());
    at_nodes.candidate.additions.nodes = nodes - 10;
    assert!(seal(&domain, &at_nodes).is_ok());
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
        assert_eq!(seal(&domain, &input(Vec::new())).is_ok(), within);
    }
    Ok(())
}

#[test]
fn an_annotation_is_staged_charged_and_bound_in_both_records() -> TestResult {
    let domain = domain(1)?;
    let inputs = refs(11..13);
    let items = vec![item(&inputs)];
    let expected = Records::stage(&context(1)?, &items)?.ok_or("records")?;
    let staged = seal(&domain, &input(vec![invocation(1, items)?]))?;
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
    let plain = seal(&domain, &input(Vec::new()))?;
    assert_ne!(plain.sealed().result_digest, sealed.result_digest);
    assert_ne!(
        plain.sealed().dependency_bundle_digest,
        sealed.dependency_bundle_digest
    );
    Ok(())
}

#[test]
fn the_control_operation_cap_omits_annotations_and_the_pass_still_seals() -> TestResult {
    // The count read at Seal already includes this pass's materialization
    // (R14, RN.1(6)): 8,191 leaves room for the one Annotation CPN1 and 8,192
    // does not. A pass that read 8,191 before its Reserve reads 8,192 here.
    let inputs = refs(11..13);
    for (operations, retained) in [
        (COMMUNITY_CONTROL_OPERATIONS_V1 - 1, true),
        (COMMUNITY_CONTROL_OPERATIONS_V1, false),
    ] {
        let domain = domain(operations)?;
        let staged = seal(&domain, &input(vec![invocation(1, vec![item(&inputs)])?]))?;
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
        let staged = seal(&domain, &input(vec![invocation(1, vec![item(&inputs)])?]))?;
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
    let staged = seal(&domain, &call)?;
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
    let staged = seal(&domain, &call)?;
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
    let staged = seal(
        &domain,
        &input(vec![
            invocation(1, vec![item(&first)])?,
            invocation(2, vec![item(&second)])?,
        ]),
    )?;
    let expected = Records::stage(&context(1)?, &[item(&first)])?.ok_or("records")?;
    let sealed = staged.sealed();
    assert_eq!(
        sealed.annotation_manifest_digest,
        Some(expected.manifest_digest())
    );
    assert_eq!(sealed.trace_root, Some(expected.node().node_digest));
    assert!(sealed.omissions == [Omissions::none(), only(Omission::AnnotationPolicy)]);
    assert_eq!(sealed.retained, [vec![0], Vec::new()]);
    Ok(())
}

#[test]
fn a_later_invocation_keeps_its_items_when_the_first_keeps_none() -> TestResult {
    let domain = domain(1)?;
    let too_many = refs(11..267);
    let second = refs(12..13);
    let staged = seal(
        &domain,
        &input(vec![
            invocation(1, vec![item(&too_many)])?,
            invocation(2, vec![item(&second)])?,
        ]),
    )?;
    let expected = Records::stage(&context(2)?, &[item(&second)])?.ok_or("records")?;
    let sealed = staged.sealed();
    assert_eq!(
        sealed.annotation_manifest_digest,
        Some(expected.manifest_digest())
    );
    assert!(sealed.omissions == [only(Omission::AnnotationBudget), Omissions::none()]);
    assert_eq!(sealed.retained, [Vec::new(), vec![0]]);
    Ok(())
}

#[test]
fn earlier_omission_reasons_are_kept() -> TestResult {
    let domain = domain(1)?;
    let mut first = invocation(1, Vec::new())?;
    first.omissions = only(Omission::InvalidClaim);
    let staged = seal(&domain, &input(vec![first]))?;
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
        seal(
            &domain,
            &input(vec![invocation(1, vec![after, backwards])?])
        ),
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
        seal(&domain, &no_nodes),
        Err(Error::BoundsExceeded)
    ));
    let mut no_head = input(Vec::new());
    no_head.candidate.candidate_head_digest = Hash::zero();
    assert!(matches!(
        seal(&domain, &no_head),
        Err(Error::InvalidBinding)
    ));
    domain
        .pass_records
        .entry((id(), OPERATION))
        .and_modify(|record| record.reserved.reservation.roster_digest = Hash::zero());
    assert!(matches!(
        seal(&domain, &input(Vec::new())),
        Err(Error::InvalidBinding)
    ));
    Ok(())
}

#[test]
fn a_trace_needs_one_more_live_key() -> TestResult {
    let inputs = refs(11..13);
    let records = Records::stage(&context(1)?, &[item(&inputs)])?.ok_or("records")?;
    for (keys, fits) in [
        (COMMUNITY_MAXIMUM_STORE_KEYS_V1 - 1, true),
        (COMMUNITY_MAXIMUM_STORE_KEYS_V1, false),
    ] {
        let room = SealRoom {
            prior: counts(100),
            materialization: counts(10),
            quote: [u64::MAX; 3],
            operations: 0,
            trace_rows: 2,
            graph: graph_counts(),
            keys,
        };
        assert_eq!(room.admits(counts(1_000), &records), fits);
    }
    Ok(())
}

#[test]
fn the_trace_closure_must_fit_the_graph_maxima() -> TestResult {
    let domain = domain(1)?;
    let inputs = refs(11..13);
    let records = Records::stage(&context(1)?, &[item(&inputs)])?.ok_or("records")?;
    // The profile-1 maximum of edges is 8,192.
    for (edges, retained) in [
        (8_192 - records.graph().edges, true),
        (8_193 - records.graph().edges, false),
    ] {
        let mut call = input(vec![invocation(1, vec![item(&inputs)])?]);
        call.candidate.graph_counts.edges = edges;
        let staged = seal(&domain, &call)?;
        assert_eq!(staged.sealed().trace_root.is_some(), retained);
    }
    Ok(())
}

#[test]
fn the_trace_objects_stay_below_the_object_maximum() -> TestResult {
    // The largest roster, each member with its 7 State objects and 2 per
    // `InputIndex` group at the most groups, CED1 and CEB1, the `2n + 1`
    // recording objects and the staged trace records (R11.4(4)).
    let inputs = refs(11..12);
    let trace = Records::stage(&context(1)?, &[item(&inputs)])?
        .ok_or("records")?
        .charge()
        .rows;
    let groups = (MAX_COMMUNITY_EXPANDED_INPUTS_V1 / MAX_COMMUNITY_DIRECT_INPUTS_V1) as u64;
    let roster = COMMUNITY_MAXIMUM_ROSTER_V1 as u64;
    let objects = roster * (7 + 2 * groups) + 2 + (2 * roster + 1) + trace;
    assert_eq!(objects, 128);
    assert!(objects <= MAX_COMMUNITY_OBJECT_BINDINGS_V1 as u64);
    Ok(())
}

/// CPD1 and CPS1 rebuilt from the record and the candidate through the
/// public codecs: the digests Seal must bind.
fn expected_digests(
    domain: &MemoryCommunityDomainV1,
    shared_counts: CommunitySharedCountsV1,
    trace_root: Option<Hash>,
    manifest: Option<Hash>,
) -> Result<(Hash, Hash), Box<dyn std::error::Error>> {
    let reservation = domain.pass_reservation(id(), OPERATION).ok_or("record")?;
    let bundle = CommunityDependencyBundleV1::new(CommunityDependencyBundleInputV1 {
        pass_key: reservation.pass_key,
        native_producer_ordinal: reservation.native_producer_ordinal,
        graph_root_digest: hash(0x64),
        factual_binding: None,
        required_node_digests: Digests::from_digests(&REQUIRED),
        optional_evidence_roots: CommunityEvidenceRootsV1 {
            presentation_trace: trace_root,
            replay_recording: Some(hash(0x63)),
        },
        shared_counts,
        graph_counts: graph_counts(),
        evidence_not_after_micros: HORIZON,
    })?;
    let result = CommunitySealedResultV1::new(CommunitySealedResultInputV1 {
        pass_key: reservation.pass_key,
        reservation_digest: CommunityReservationV1::new(reservation)?.digest(),
        invocation_step_digests: Digests::from_digests(&STEPS),
        event_draft_vector_digest: hash(0x60),
        event_draft_manifest_digest: hash(0x61),
        new_revision_digests: Digests::from_digests(&REVISIONS),
        new_member_progress_digests: Digests::from_digests(&PROGRESS),
        candidate_head_digest: hash(0x62),
        dependency_bundle_digest: bundle.digest(),
        annotation_manifest_digest: manifest,
        replay_recording_digest: hash(0x63),
        evidence_not_after_micros: HORIZON,
    })?;
    Ok((bundle.digest(), result.digest()))
}

#[test]
fn the_sealed_digests_equal_independently_built_records() -> TestResult {
    let domain = domain(1)?;
    let plain = seal(&domain, &input(Vec::new()))?;
    let (bundle, result) = expected_digests(&domain, counts(1_000), None, None)?;
    assert_eq!(plain.sealed().dependency_bundle_digest, bundle);
    assert_eq!(plain.sealed().result_digest, result);
    let inputs = refs(11..13);
    let items = vec![item(&inputs)];
    let records = Records::stage(&context(1)?, &items)?.ok_or("records")?;
    let charge = records.charge();
    let annotated = seal(&domain, &input(vec![invocation(1, items)?]))?;
    let (bundle, result) = expected_digests(
        &domain,
        CommunitySharedCountsV1 {
            nodes: 1_000 + charge.nodes,
            edges: 1_001 + charge.edges,
            declared_inputs: 1_002,
            encoded_record_bytes: 1_003 + charge.bytes,
        },
        Some(records.node().node_digest),
        Some(records.manifest_digest()),
    )?;
    assert_eq!(annotated.sealed().dependency_bundle_digest, bundle);
    assert_eq!(annotated.sealed().result_digest, result);
    Ok(())
}

#[test]
fn annotations_beyond_the_quote_slack_still_seal() -> TestResult {
    let mut domain = domain(1)?;
    // The quote holds exactly the totals without annotations.
    quoted(&mut domain, [1_010, 1_012, 1_016], counts(100));
    let inputs = refs(11..13);
    let staged = seal(&domain, &input(vec![invocation(1, vec![item(&inputs)])?]))?;
    assert!(staged.sealed().trace_root.is_some());
    Ok(())
}

#[test]
fn a_reused_observation_counts_no_materialization_in_the_cap() -> TestResult {
    // No materialization of this pass is counted: 8,191 operations leave
    // room for the one Annotation CPN1, and 8,192 do not.
    let inputs = refs(11..13);
    for (operations, retained) in [
        (COMMUNITY_CONTROL_OPERATIONS_V1 - 1, true),
        (COMMUNITY_CONTROL_OPERATIONS_V1, false),
    ] {
        let mut domain = domain(operations)?;
        domain
            .pass_records
            .entry((id(), OPERATION))
            .and_modify(|record| record.materialization = None);
        let staged = seal(&domain, &input(vec![invocation(1, vec![item(&inputs)])?]))?;
        assert_eq!(staged.sealed().trace_root.is_some(), retained);
    }
    Ok(())
}

#[test]
fn a_cat1_keeps_1024_items_and_omits_the_next_with_reason_3() -> TestResult {
    let domain = domain(1)?;
    let inputs = refs(11..12);
    let items: Vec<Candidate<'_>> = (0..1_025).map(|_| item(&inputs)).collect();
    let staged = seal(&domain, &input(vec![invocation(1, items)?]))?;
    assert_eq!(
        staged.sealed().retained[0],
        (0..1_024).collect::<Vec<usize>>()
    );
    assert!(staged.sealed().omissions[0] == only(Omission::AnnotationBudget));
    Ok(())
}

#[test]
fn an_abort_after_seal_still_fits_the_pending_entry() -> TestResult {
    let mut domain = domain(1)?;
    let entry = CommunityPendingReservationV1::for_pass(10, 4);
    domain.pending_reservations.insert((id(), OPERATION), entry);
    let inputs = refs(11..13);
    let before = domain.pending_reservations.get(&(id(), OPERATION)).copied();
    let staged = seal(&domain, &input(vec![invocation(1, vec![item(&inputs)])?]))?;
    domain.apply_seal(&SEAL, &staged)?;
    // Seal leaves the entry as the Reserve held it: pass rows plus `F_p`.
    assert_eq!(
        domain.pending_reservations.get(&(id(), OPERATION)).copied(),
        before
    );
    assert!(domain.stage_abort(id(), OPERATION, 12).is_ok());
    assert!(matches!(
        domain.stage_abort(id(), OPERATION, 13),
        Err(Error::InvalidBinding)
    ));
    Ok(())
}

#[test]
fn an_invocation_context_must_match_the_pass() -> TestResult {
    let domain = domain(1)?;
    let inputs = refs(11..13);
    let base = context(1)?;
    let contexts = [
        Context {
            pass_key: CommunityPassKeyV1::new(id(), GENERATION, 8)?,
            ..base
        },
        Context {
            producer_ordinal: 999,
            ..base
        },
        Context {
            evidence_not_after_micros: HORIZON + 1,
            ..base
        },
        Context {
            member_binding_digest: hash(9),
            ..base
        },
        Context {
            invocation_step_digest: hash(0x79),
            ..base
        },
        // Another member's CPI1, which is in the candidate.
        Context {
            invocation_step_digest: hash(0x72),
            ..base
        },
        Context {
            step: Reference {
                store_incarnation: [1; 16],
                ..step()
            },
            ..base
        },
        Context {
            step: Reference {
                producer_ordinal: 999,
                ..step()
            },
            ..base
        },
    ];
    for context in contexts {
        let mut call = invocation(1, vec![item(&inputs)])?;
        call.context = context;
        assert!(matches!(
            seal(&domain, &input(vec![call])),
            Err(Error::InvalidBinding)
        ));
    }
    Ok(())
}

#[test]
fn the_invocations_must_be_in_roster_order() -> TestResult {
    let domain = domain(1)?;
    for members in [[2, 1], [1, 1]] {
        let calls = members
            .into_iter()
            .map(|member| invocation(member, Vec::new()))
            .collect::<Result<Vec<_>, _>>()?;
        assert!(matches!(
            seal(&domain, &input(calls)),
            Err(Error::InvalidBinding)
        ));
    }
    Ok(())
}

#[test]
fn a_defect_of_the_trusted_input_refuses_the_seal_and_is_not_a_budget() -> TestResult {
    let domain = domain(1)?;
    let inputs = refs(11..12);
    let over = refs(11..267);
    let mut no_horizon = invocation(1, vec![item(&inputs)])?;
    no_horizon.context.evidence_not_after_micros = 0;
    let far = Candidate {
        guest_index: 64,
        ..item(&inputs)
    };
    let low = Candidate {
        guest_index: 0,
        ..item(&over)
    };
    let high = Candidate {
        guest_index: 2,
        ..item(&inputs)
    };
    for call in [
        no_horizon,
        invocation(1, vec![far])?,
        invocation(1, vec![high, low])?,
    ] {
        assert!(matches!(
            seal(&domain, &input(vec![call])),
            Err(Error::InvalidBinding)
        ));
    }
    Ok(())
}

#[test]
fn the_plan_is_what_seal_binds_and_a_different_plan_is_refused() -> TestResult {
    let domain = domain(1)?;
    let inputs = refs(11..13);
    let call = input(vec![invocation(1, vec![item(&inputs)])?]);
    let plan = domain.plan_annotations(&call)?;
    assert_eq!(plan.retained, [vec![0]]);
    assert!(plan.omissions == [Omissions::none()]);
    let staged = domain.stage_seal(&call, hash(0x63), &plan)?;
    assert_eq!(staged.sealed().retained, plan.retained);
    assert!(staged.sealed().omissions == plan.omissions);
    // The recording digest is bound into the result.
    let other_recording = domain.stage_seal(&call, hash(0x64), &plan)?;
    assert_ne!(
        other_recording.sealed().result_digest,
        staged.sealed().result_digest
    );
    assert_ne!(
        other_recording.sealed().dependency_bundle_digest,
        staged.sealed().dependency_bundle_digest
    );
    let mut changed: CommunityAnnotationPlanV1 = plan;
    changed.omissions[0] = only(Omission::AnnotationBudget);
    assert!(matches!(
        domain.stage_seal(&call, hash(0x63), &changed),
        Err(Error::InvalidBinding)
    ));
    let none = domain.plan_annotations(&input(Vec::new()))?;
    assert!(none.records.is_none());
    assert!(matches!(
        domain.stage_seal(&call, hash(0x63), &none),
        Err(Error::InvalidBinding)
    ));
    Ok(())
}

/// A provisioned Control key, as bootstrap makes one.
fn provisioned_key(byte: u8) -> Result<VaultKeyV1, Error> {
    VaultKeyV1::provision(CommunityKeyIntentInputV1 {
        protection_operation_id: [byte; 16],
        parent_operation: CommunityArtifactOperationV1::Control([0x50; 16]),
        timeline: id(),
        generation: GENERATION,
        purpose: CommunityArtifactPurposeV1::LifecycleControl,
        scope_set_digest: hash(0x42),
        evidence_not_after_micros: HORIZON,
        allowed_record_kinds: CommunityRecordKindsV1::empty()
            .with(CommunityArtifactKindV1::LifecycleControl),
        member_slots: CommunityMemberSlotsV1::empty(),
        material_fingerprint: Hash::zero(),
        authority_request_digest: hash(0x43),
    })
}

#[test]
fn the_room_reads_the_store_wide_live_key_count() -> TestResult {
    let mut domain = domain(1)?;
    domain.keys.insert([0x40; 16], provisioned_key(0x40)?);
    domain.keys.insert([0x41; 16], provisioned_key(0x41)?);
    let record = domain.pass_record(id(), OPERATION).ok_or("record")?;
    assert_eq!(domain.seal_room(record, graph_counts()).keys, 2);
    Ok(())
}
