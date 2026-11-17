//! Extractor checks that need records no assembled graph contains.
//!
//! Every record is protected under a real key, so it authenticates and
//! reaches the check it targets. [`Spec::BASE`] forges one complete
//! single-member initialization graph that the extractor admits; each
//! refusal case changes exactly one fact of it.

use pos_core::community_lifecycle::{
    ArtifactRefV1, CommunityArtifactKindV1 as Kind, CommunityArtifactOperationV1 as Operation,
    CommunityArtifactPurposeV1 as Purpose, CommunityContentReferenceV1, CommunityGraphCountsV1,
    CommunityGraphRootInputV1, CommunityGraphRootV1, CommunityInitializationProducerInputV1,
    CommunityInitializationProducerV1, CommunityInputIndexV1, CommunityLifecycleErrorV1 as Error,
    CommunityLocatorProducerV1, CommunityMemberHeadV1, CommunityMemberHeadsV1,
    CommunityMemberSlotsV1, CommunityMetadataLocatorV1, CommunityMetadataSchemaV1,
    CommunityNativeNodeInputV1, CommunityNativeNodeKindV1, CommunityNativeNodeReferenceV1,
    CommunityNativeNodeReferencesV1, CommunityNativeNodeV1, CommunityPassFrontierV1,
    CommunityPassKeyV1, CommunityRecordKindsV1, CommunitySelectedHeadInputV1,
    CommunitySelectedHeadV1, CommunityStateContentV1, CommunityStateProducerV1,
    CommunityStateRevisionInputV1, CommunityStateRevisionV1, CommunityTypedInputRefV1,
    CommunityTypedInputRefsV1,
};
use pos_core::{
    ArtifactChildEdgeV1, AuthorityTrustRootSealV1, ErasureArtifactClassV1, Hash,
    RecordedDependencyClassV1, Seq, TimelineId,
};
use std::collections::BTreeSet;
use ulid::Ulid;

use super::super::protection::{
    CommunityArtifactProtectorV1, CommunityProtectedRecordV1, CommunityProtectionCohortV1,
    CommunityRecordEvidenceV1,
};
use super::{
    extract, heights, prepare_community_artifact_batch_v1, read_root, resolve_children,
    CommunityArtifactBatchInputV1, CommunityArtifactRecordInputV1,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Fallible<T> = Result<T, Box<dyn std::error::Error>>;

const SEAL: AuthorityTrustRootSealV1 = AuthorityTrustRootSealV1::for_composition_root();
const INCARNATION: [u8; 16] = [0x5a; 16];
const GENERATION: [u8; 16] = [0x20; 16];
const OPERATION: [u8; 16] = [0x10; 16];
const HORIZON: u64 = 900;
const PROFILE: Hash = Hash::from_bytes([0x30; 32]);
const COB: Hash = Hash::from_bytes([0x40; 32]);
const CPV: Hash = Hash::from_bytes([0x41; 32]);
const SCOPE_COVER: Hash = Hash::from_bytes([0x42; 32]);
const MEMBER: Hash = Hash::from_bytes([5; 32]);
const AUTHORIZATION: ArtifactRefV1 = ArtifactRefV1 {
    schema_id: 0x4341_0002,
    byte_length: 41,
    digest: [0x51; 32],
};
const SOME_ROOT: [CommunityNativeNodeReferenceV1; 1] = [CommunityNativeNodeReferenceV1 {
    store_incarnation: INCARNATION,
    producer_ordinal: 1,
    node_ordinal: 1,
    node_digest: Hash::from_bytes([9; 32]),
}];

const fn hash(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
}

const fn timeline() -> TimelineId {
    TimelineId::from_ulid(Ulid::from_bytes([0x0e; 16]))
}

fn adr_h(m: &str, bytes: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(format!("PiglorOS.Community.{m}.v1\0").as_bytes());
    hasher.update(bytes);
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

fn protector(generation: [u8; 16]) -> Fallible<CommunityArtifactProtectorV1> {
    Ok(CommunityArtifactProtectorV1::provision(
        &SEAL,
        CommunityProtectionCohortV1 {
            parent_operation: Operation::Initialization(OPERATION),
            timeline: timeline(),
            generation,
            purpose: Purpose::ExecutionState,
            scope_set_digest: hash(0x43),
            scope_cover_digest: SCOPE_COVER,
            evidence_not_after_micros: HORIZON,
            allowed_record_kinds: CommunityRecordKindsV1::empty()
                .with(Kind::StateContent)
                .with(Kind::StateRevisionOrHead)
                .with(Kind::PreparedInvocation)
                .with(Kind::ExecutionProvenance)
                .with(Kind::ClassificationProof),
            member_slots: CommunityMemberSlotsV1::new(&[0])?,
            authority_request_digest: hash(0x44),
        },
    )?)
}

fn edges(children: &[&CommunityProtectedRecordV1]) -> Vec<ArtifactChildEdgeV1> {
    let mut edges: Vec<ArtifactChildEdgeV1> = children
        .iter()
        .map(|child| ArtifactChildEdgeV1 {
            artifact_class: ErasureArtifactClassV1::TimelineReplay,
            artifact_digest: child.registration().fields().artifact_digest,
            registration_address: child.registration().address(),
            required: true,
        })
        .collect();
    edges.sort_by_key(|edge| (edge.artifact_digest, edge.registration_address));
    edges
}

fn protect_owned(
    protector: &mut CommunityArtifactProtectorV1,
    kind: Kind,
    plaintext: &[u8],
    children: &[&CommunityProtectedRecordV1],
    owner: Hash,
) -> Fallible<CommunityProtectedRecordV1> {
    Ok(protector.protect(
        kind,
        plaintext,
        CommunityRecordEvidenceV1 {
            owner_binding_digest: owner,
            host_provenance_digest: CPV,
            children: &edges(children),
        },
    )?)
}

fn protect(
    protector: &mut CommunityArtifactProtectorV1,
    kind: Kind,
    plaintext: &[u8],
    children: &[&CommunityProtectedRecordV1],
) -> Fallible<CommunityProtectedRecordV1> {
    protect_owned(protector, kind, plaintext, children, COB)
}

/// A CSH1 over `members` and the CGR1 that selects it with `roots` and
/// `counts`.
fn head_and_root(
    members: &[Hash],
    roots: &[CommunityNativeNodeReferenceV1],
    counts: CommunityGraphCountsV1,
) -> Fallible<(Vec<u8>, Vec<u8>)> {
    let heads: Vec<CommunityMemberHeadV1> = members
        .iter()
        .map(|member| CommunityMemberHeadV1 {
            member_binding_digest: *member,
            member_progress_digest: hash(2),
        })
        .collect();
    let head = CommunitySelectedHeadV1::new(CommunitySelectedHeadInputV1 {
        timeline: timeline(),
        generation: GENERATION,
        frontier: CommunityPassFrontierV1::Initial,
        member_heads: CommunityMemberHeadsV1::from_members(&heads),
        event_logical_head: Seq::ZERO,
        profile_digest: PROFILE,
        host_progress_digest: hash(3),
    })?
    .to_canonical_cbor()
    .to_vec();
    let root = CommunityGraphRootV1::new(CommunityGraphRootInputV1 {
        store_incarnation: INCARNATION,
        timeline: timeline(),
        generation: GENERATION,
        profile_digest: PROFILE,
        selected_head_digest: adr_h("CSH1", &head),
        roots: CommunityNativeNodeReferencesV1::from_references(roots),
        graph_counts: counts,
        evidence_not_after_micros: HORIZON,
    })?
    .to_canonical_cbor()
    .to_vec();
    Ok((head, root))
}

/// Exact ARD1-graph counts of `records`, all reachable, at depth 3, or at
/// depth `records.len()` for a smaller refusal graph: a CGR1 refuses a
/// depth above its registration count, so the record under test must reach
/// the extractor through a CGR1 that decodes.
fn counts(records: &[&CommunityProtectedRecordV1]) -> CommunityGraphCountsV1 {
    let keys: BTreeSet<_> = records
        .iter()
        .flat_map(|record| &record.registration().fields().key_dependencies)
        .map(|key| key.identity)
        .collect();
    let sum = |field: fn(&CommunityProtectedRecordV1) -> usize| {
        records.iter().map(|record| field(record)).sum::<usize>() as u64
    };
    CommunityGraphCountsV1 {
        registrations: records.len() as u64,
        edges: sum(|record| record.registration().fields().child_artifacts.len()),
        keys: keys.len() as u64,
        maximum_depth: 3.min(records.len() as u64),
        registration_bytes: sum(|record| record.registration().canonical_cbor().len()),
        artifact_bytes: sum(|record| record.object().len()),
    }
}

fn inputs<'a>(
    records: &[&'a CommunityProtectedRecordV1],
) -> Vec<CommunityArtifactRecordInputV1<'a>> {
    records
        .iter()
        .map(|record| CommunityArtifactRecordInputV1 {
            object: record.object(),
            registration: record.registration(),
        })
        .collect()
}

fn batch<'a>(
    records: &'a [CommunityArtifactRecordInputV1<'a>],
    head: &'a [u8],
    root: &'a [u8],
) -> CommunityArtifactBatchInputV1<'a> {
    CommunityArtifactBatchInputV1 {
        store_incarnation: INCARNATION,
        profile_digest: PROFILE,
        operation_id: OPERATION,
        authorization_ref: AUTHORIZATION,
        owner_binding_digest: COB,
        records,
        graph_root: root,
        selected_head: head,
        current_head: None,
        expected_prior_head: None,
    }
}

/// Prepare `records` under `key` against a CSH1 over `members` and a CGR1
/// with `roots` and the exact counts of `records`.
fn prepare(
    records: &[&CommunityProtectedRecordV1],
    members: &[Hash],
    roots: &[CommunityNativeNodeReferenceV1],
    key: &CommunityArtifactProtectorV1,
) -> Fallible<Result<(), Error>> {
    prepare_counted(records, members, roots, counts(records), key)
}

/// Prepare `records` under `key` against a CSH1 over `members` and a CGR1
/// with `roots` and `graph_counts`.
fn prepare_counted(
    records: &[&CommunityProtectedRecordV1],
    members: &[Hash],
    roots: &[CommunityNativeNodeReferenceV1],
    graph_counts: CommunityGraphCountsV1,
    key: &CommunityArtifactProtectorV1,
) -> Fallible<Result<(), Error>> {
    let (head, root) = head_and_root(members, roots, graph_counts)?;
    let records = inputs(records);
    Ok(
        prepare_community_artifact_batch_v1(&SEAL, batch(&records, &head, &root), &[key])
            .map(|_| ()),
    )
}

/// Authenticate and read each of `records` on its own, stopping before any
/// cross-record check. The CGR1 roots resolve to none of them, so only a
/// whole batch would also refuse at the closure walk; a refusal here comes
/// from the record's own checks.
fn extract_each(
    records: &[&CommunityProtectedRecordV1],
    key: &CommunityArtifactProtectorV1,
) -> Fallible<Result<(), Error>> {
    let (head, root) = head_and_root(&[MEMBER], &SOME_ROOT, counts(records))?;
    let records = inputs(records);
    let batch = batch(&records, &head, &root);
    let root = read_root(&batch)?;
    Ok(records
        .iter()
        .try_for_each(|record| extract(*record, &batch, &root, &[key]).map(|_| ())))
}

/// Extract every one of `records`, which must succeed, and resolve their
/// children, stopping before the shape checks and the closure walk.
fn resolve(
    records: &[&CommunityProtectedRecordV1],
    key: &CommunityArtifactProtectorV1,
) -> Fallible<Result<(), Error>> {
    let (head, root) = head_and_root(&[MEMBER], &SOME_ROOT, counts(records))?;
    let records = inputs(records);
    let batch = batch(&records, &head, &root);
    let root = read_root(&batch)?;
    let extracted = records
        .iter()
        .map(|record| extract(*record, &batch, &root, &[key]))
        .collect::<Result<Vec<_>, Error>>()?;
    Ok(resolve_children(&extracted).map(|_| ()))
}

fn state(bytes: &[u8]) -> Fallible<Vec<u8>> {
    Ok(CommunityStateContentV1::new(hash(0x22), bytes)?
        .to_canonical_cbor()
        .to_vec())
}

fn producer(
    state: &[u8],
    request: Hash,
    member: Hash,
) -> Fallible<CommunityInitializationProducerV1> {
    Ok(CommunityInitializationProducerV1::new(
        CommunityInitializationProducerInputV1 {
            generation_request_digest: request,
            member_binding_digest: member,
            initializer_ref: ArtifactRefV1 {
                schema_id: 0x4353_0001,
                byte_length: state.len() as u64,
                digest: *adr_h("CSC1", state).as_bytes(),
            },
            state_content_digest: adr_h("CSC1", state),
            scope_binding_digest: SCOPE_COVER,
            evidence_not_after_micros: HORIZON,
        },
    )?)
}

/// A CSR1 from `origin` for `member` over `state` and `producer`, bound to
/// `owner`.
#[derive(Clone, Copy)]
struct Revision {
    origin: CommunityStateProducerV1,
    member: Hash,
    state: Hash,
    producer: Hash,
    owner: Hash,
}

fn revision(revision: Revision) -> Fallible<Vec<u8>> {
    Ok(
        CommunityStateRevisionV1::new(CommunityStateRevisionInputV1 {
            producer_origin: revision.origin,
            member_binding_digest: revision.member,
            predecessor_revision_digest: match revision.origin {
                CommunityStateProducerV1::Initialization { .. } => None,
                CommunityStateProducerV1::Pass(_) => Some(hash(6)),
            },
            state_content_digest: revision.state,
            producer_digest: revision.producer,
            protected_owner_binding_digest: revision.owner,
            evidence_not_after_micros: HORIZON,
        })?
        .to_canonical_cbor()
        .to_vec(),
    )
}

const INITIALIZATION: CommunityStateProducerV1 = CommunityStateProducerV1::Initialization {
    generation_request_digest: Hash::from_bytes([4; 32]),
    operation_id: OPERATION,
};

const fn cmb1(
    operation: [u8; 16],
    record_role: u16,
    slot: u16,
    envelope: u8,
) -> CommunityTypedInputRefV1<'static> {
    CommunityTypedInputRefV1::Metadata {
        schema: CommunityMetadataSchemaV1::Cmb1,
        locator: CommunityMetadataLocatorV1 {
            timeline: timeline(),
            generation: GENERATION,
            producer: CommunityLocatorProducerV1::Control(operation),
            record_role,
            slot,
        },
        envelope_address: Hash::from_bytes([envelope; 32]),
        private_record_digest: MEMBER,
    }
}

/// One CPN1 at `(producer, ordinal)` over `content` with `index`, bound to
/// the test cohort except for `incarnation` and `authorization`.
#[derive(Clone, Copy)]
struct Node<'a> {
    kind: CommunityNativeNodeKindV1,
    producer: u64,
    ordinal: u32,
    content: CommunityContentReferenceV1,
    index: CommunityInputIndexV1<'a>,
    incarnation: [u8; 16],
    authorization: Hash,
}

impl<'a> Node<'a> {
    /// An `InitialState` node at `(producer, ordinal)` over the CIS1
    /// `initializer`, bound to the test cohort.
    const fn initial(
        producer: u64,
        ordinal: u32,
        initializer: Hash,
        index: CommunityInputIndexV1<'a>,
    ) -> Self {
        Self {
            kind: CommunityNativeNodeKindV1::InitialState,
            producer,
            ordinal,
            content: content(*b"CIS1", initializer),
            index,
            incarnation: INCARNATION,
            authorization: Hash::from_bytes(AUTHORIZATION.digest),
        }
    }
}

fn node(node: Node<'_>) -> Fallible<(Vec<u8>, CommunityNativeNodeReferenceV1)> {
    let built = CommunityNativeNodeV1::new(CommunityNativeNodeInputV1 {
        store_incarnation: node.incarnation,
        timeline: timeline(),
        generation: GENERATION,
        producer_ordinal: node.producer,
        node_ordinal: node.ordinal,
        kind: node.kind,
        content: node.content,
        dependency_class: node
            .kind
            .fixed_class()
            .unwrap_or(RecordedDependencyClassV1::EndogenousRecomputed),
        input_index: node.index,
        scope_binding_digest: SCOPE_COVER,
        authorization_digest: node.authorization,
        provenance_digest: CPV,
        evidence_not_after_micros: HORIZON,
    })?;
    Ok((built.to_canonical_cbor().to_vec(), built.reference()))
}

const fn content(record_magic: [u8; 4], logical_digest: Hash) -> CommunityContentReferenceV1 {
    CommunityContentReferenceV1 {
        record_magic,
        logical_digest,
    }
}

const fn direct<'a>(refs: &'a [CommunityTypedInputRefV1<'a>]) -> CommunityInputIndexV1<'a> {
    CommunityInputIndexV1::Direct(CommunityTypedInputRefsV1::from_references(refs))
}

/// How the CSC1's CAR1 binds its content.
#[derive(Clone, Copy, Eq, PartialEq)]
enum Proof {
    Exact,
    OtherPlaintext,
    OtherEnvelope,
}

/// An extra record beside the graph.
#[derive(Clone, Copy, Eq, PartialEq)]
enum Extra {
    None,
    /// An `InitialState` node of another producer ordinal.
    OtherProducer,
    /// An `InitialState` node at the same coordinate, citing another CMB1
    /// envelope.
    SameOrdinal,
    /// A CSC1 that no record cites, so no root reaches it.
    Unreachable,
}

/// How a case rewrites the exact CGR1 counts of its records.
type Recount = fn(CommunityGraphCountsV1) -> CommunityGraphCountsV1;

/// Every fact of the forged single-member graph a case may change.
#[derive(Clone, Copy)]
struct Spec {
    proof: Proof,
    car1_owner: Hash,
    csr_owner: Hash,
    cis_member: Hash,
    csr_member: Hash,
    head_member: Hash,
    authorization: Hash,
    initial_inputs: [Option<CommunityTypedInputRefV1<'static>>; 2],
    initial_ordinal: u32,
    initial_cites_other_producer: bool,
    revision_producer: u64,
    revision_ordinal: u32,
    /// The node ordinal the `StateRevision` cites, if not the real one.
    cited_ordinal: Option<u32>,
    extra: Extra,
    root_is_initial: bool,
    recount: Recount,
}

impl Spec {
    const BASE: Self = Self {
        proof: Proof::Exact,
        car1_owner: COB,
        csr_owner: COB,
        cis_member: MEMBER,
        csr_member: MEMBER,
        head_member: MEMBER,
        authorization: Hash::from_bytes(AUTHORIZATION.digest),
        initial_inputs: [Some(cmb1(OPERATION, 11, 0, 0x60)), None],
        initial_ordinal: 0,
        initial_cites_other_producer: false,
        revision_producer: 1,
        revision_ordinal: 1,
        cited_ordinal: None,
        extra: Extra::None,
        root_is_initial: false,
        recount: std::convert::identity,
    };
}

/// The CSC1 record `spec` describes.
fn state_record(
    key: &mut CommunityArtifactProtectorV1,
    spec: &Spec,
    state_bytes: &[u8],
) -> Fallible<CommunityProtectedRecordV1> {
    if spec.proof == Proof::Exact {
        return protect_owned(key, Kind::StateContent, state_bytes, &[], spec.car1_owner);
    }
    let claimed: &[u8] = if spec.proof == Proof::OtherPlaintext {
        b"other"
    } else {
        state_bytes
    };
    Ok(key.protect_with_mismatched_proof(
        Kind::StateContent,
        state_bytes,
        claimed,
        spec.proof == Proof::OtherEnvelope,
        CommunityRecordEvidenceV1 {
            owner_binding_digest: COB,
            host_provenance_digest: CPV,
            children: &[],
        },
    )?)
}

/// The producer ordinal and CMB1 envelope of the extra `InitialState` node
/// `extra` adds beside the graph, if any.
const fn extra_coordinate(extra: Extra) -> Option<(u64, u8)> {
    match extra {
        Extra::None | Extra::Unreachable => None,
        Extra::OtherProducer => Some((2, 0x60)),
        Extra::SameOrdinal => Some((1, 0x61)),
    }
}

/// A CSC1 over other state, citing nothing.
fn spare_record(key: &mut CommunityArtifactProtectorV1) -> Fallible<CommunityProtectedRecordV1> {
    protect(key, Kind::StateContent, &state(b"spare")?, &[])
}

/// The extra record `spec` adds beside the graph, if any.
fn extra_record(
    key: &mut CommunityArtifactProtectorV1,
    spec: &Spec,
    initializer: Hash,
    producer_record: &CommunityProtectedRecordV1,
) -> Fallible<Option<CommunityProtectedRecordV1>> {
    if spec.extra == Extra::Unreachable {
        return spare_record(key).map(Some);
    }
    let Some((producer_ordinal, envelope)) = extra_coordinate(spec.extra) else {
        return Ok(None);
    };
    let metadata = [cmb1(OPERATION, 11, 0, envelope)];
    let (bytes, _) = node(Node::initial(
        producer_ordinal,
        0,
        initializer,
        direct(&metadata),
    ))?;
    Ok(Some(protect(
        key,
        Kind::ExecutionProvenance,
        &bytes,
        &[producer_record],
    )?))
}

/// A protected CPN1 and its reference.
type ProtectedNode = (CommunityProtectedRecordV1, CommunityNativeNodeReferenceV1);

/// The plain CSC1, CIS1, other CIS1 and CSR1 `spec` describes.
struct Plain {
    state_bytes: Vec<u8>,
    initializer: CommunityInitializationProducerV1,
    other_initializer: CommunityInitializationProducerV1,
    revision_bytes: Vec<u8>,
}

fn plain(spec: &Spec) -> Fallible<Plain> {
    let state_bytes = state(b"state")?;
    let initializer = producer(&state_bytes, hash(4), spec.cis_member)?;
    let other_initializer = producer(&state_bytes, hash(14), spec.cis_member)?;
    let revision_bytes = revision(Revision {
        origin: INITIALIZATION,
        member: spec.csr_member,
        state: adr_h("CSC1", &state_bytes),
        producer: initializer.digest(),
        owner: spec.csr_owner,
    })?;
    Ok(Plain {
        state_bytes,
        initializer,
        other_initializer,
        revision_bytes,
    })
}

/// The protected records of [`Plain`].
struct Protected {
    state: CommunityProtectedRecordV1,
    producer: CommunityProtectedRecordV1,
    other_producer: CommunityProtectedRecordV1,
    revision: CommunityProtectedRecordV1,
}

fn protect_plain(
    key: &mut CommunityArtifactProtectorV1,
    spec: &Spec,
    plain: &Plain,
) -> Fallible<Protected> {
    let state = state_record(key, spec, &plain.state_bytes)?;
    let producer = protect(
        key,
        Kind::ExecutionProvenance,
        &plain.initializer.to_canonical_cbor(),
        &[],
    )?;
    let other_producer = protect(
        key,
        Kind::ExecutionProvenance,
        &plain.other_initializer.to_canonical_cbor(),
        &[],
    )?;
    let revision = protect(
        key,
        Kind::StateRevisionOrHead,
        &plain.revision_bytes,
        &[&state, &producer],
    )?;
    Ok(Protected {
        state,
        producer,
        other_producer,
        revision,
    })
}

/// The protected `InitialState` node `spec` describes.
fn initial_node(
    key: &mut CommunityArtifactProtectorV1,
    spec: &Spec,
    plain: &Plain,
    protected: &Protected,
) -> Fallible<ProtectedNode> {
    let (initializer, child) = if spec.initial_cites_other_producer {
        (plain.other_initializer.digest(), &protected.other_producer)
    } else {
        (plain.initializer.digest(), &protected.producer)
    };
    let inputs: Vec<CommunityTypedInputRefV1<'static>> =
        spec.initial_inputs.iter().flatten().copied().collect();
    let (bytes, reference) = node(Node {
        authorization: spec.authorization,
        ..Node::initial(1, spec.initial_ordinal, initializer, direct(&inputs))
    })?;
    Ok((
        protect(key, Kind::ExecutionProvenance, &bytes, &[child])?,
        reference,
    ))
}

/// The protected `StateRevision` node `spec` describes, citing `initial`.
fn revision_node(
    key: &mut CommunityArtifactProtectorV1,
    spec: &Spec,
    plain: &Plain,
    protected: &Protected,
    initial: &ProtectedNode,
) -> Fallible<ProtectedNode> {
    let cited = CommunityNativeNodeReferenceV1 {
        node_ordinal: spec.cited_ordinal.unwrap_or(initial.1.node_ordinal),
        ..initial.1
    };
    let native = [CommunityTypedInputRefV1::Native(cited)];
    let (bytes, reference) = node(Node {
        kind: CommunityNativeNodeKindV1::StateRevision,
        producer: spec.revision_producer,
        ordinal: spec.revision_ordinal,
        content: content(*b"CSR1", adr_h("CSR1", &plain.revision_bytes)),
        index: direct(&native),
        incarnation: INCARNATION,
        authorization: spec.authorization,
    })?;
    Ok((
        protect(
            key,
            Kind::ExecutionProvenance,
            &bytes,
            &[&protected.revision, &protected.state, &initial.0],
        )?,
        reference,
    ))
}

/// The `InitialState` and `StateRevision` nodes `spec` describes.
fn nodes(
    key: &mut CommunityArtifactProtectorV1,
    spec: &Spec,
    plain: &Plain,
    protected: &Protected,
) -> Fallible<(ProtectedNode, ProtectedNode)> {
    let initial = initial_node(key, spec, plain, protected)?;
    let revision = revision_node(key, spec, plain, protected, &initial)?;
    Ok((initial, revision))
}

/// Add the extra record `spec` describes and prepare the forged graph.
fn prepare_forged(
    key: &mut CommunityArtifactProtectorV1,
    spec: &Spec,
    plain: &Plain,
    protected: &Protected,
    (initial, revision): (&ProtectedNode, &ProtectedNode),
) -> Fallible<Result<(), Error>> {
    let extra = extra_record(key, spec, plain.initializer.digest(), &protected.producer)?;
    let mut records = vec![
        &protected.state,
        &protected.producer,
        &protected.revision,
        &initial.0,
        &revision.0,
    ];
    if spec.initial_cites_other_producer {
        records.push(&protected.other_producer);
    }
    records.extend(extra.as_ref());
    let root = if spec.root_is_initial {
        initial.1
    } else {
        revision.1
    };
    let graph_counts = (spec.recount)(counts(&records));
    prepare_counted(&records, &[spec.head_member], &[root], graph_counts, key)
}

/// Forge the graph `spec` describes and prepare it.
fn forge(spec: &Spec) -> Fallible<Result<(), Error>> {
    let mut key = protector(GENERATION)?;
    let plain = plain(spec)?;
    let protected = protect_plain(&mut key, spec, &plain)?;
    let (initial, revision) = nodes(&mut key, spec, &plain, &protected)?;
    prepare_forged(&mut key, spec, &plain, &protected, (&initial, &revision))
}

#[test]
fn the_forged_base_graph_is_admitted() -> TestResult {
    assert_eq!(forge(&Spec::BASE)?, Ok(()));
    Ok(())
}

/// Review M1 on #1180: note 22661, items 1 to 3, one fact at a time.
#[test]
fn every_node_shape_violation_is_refused() -> TestResult {
    let base = Spec::BASE;
    let earlier = CommunityTypedInputRefV1::Native(CommunityNativeNodeReferenceV1 {
        store_incarnation: INCARNATION,
        producer_ordinal: 1,
        node_ordinal: 0,
        node_digest: hash(9),
    });
    let cases = [
        // `InitialState`: a second input, another role, slot or operation,
        // or a native input.
        Spec {
            initial_inputs: [
                Some(cmb1(OPERATION, 11, 0, 0x60)),
                Some(cmb1(OPERATION, 11, 1, 0x61)),
            ],
            ..base
        },
        Spec {
            initial_inputs: [Some(cmb1(OPERATION, 12, 0, 0x60)), None],
            ..base
        },
        Spec {
            initial_inputs: [Some(cmb1(OPERATION, 11, 1, 0x60)), None],
            ..base
        },
        Spec {
            initial_inputs: [Some(cmb1([0x11; 16], 11, 0, 0x60)), None],
            ..base
        },
        Spec {
            initial_inputs: [Some(earlier), None],
            initial_ordinal: 2,
            revision_ordinal: 3,
            ..base
        },
        // `StateRevision`: not right after its input, an even ordinal, or
        // another producer ordinal.
        Spec {
            revision_ordinal: 3,
            ..base
        },
        Spec {
            revision_ordinal: 2,
            ..base
        },
        Spec {
            revision_producer: 2,
            ..base
        },
        // Another authorization than the CGI1 `authorization_ref`.
        Spec {
            authorization: hash(0x52),
            ..base
        },
        // Two producer ordinals, or two nodes at one ordinal.
        Spec {
            extra: Extra::OtherProducer,
            ..base
        },
        Spec {
            extra: Extra::SameOrdinal,
            ..base
        },
        // A `StateRevision` 2·slot+1 citing the `InitialState`'s digest at
        // another ordinal than the node's own.
        Spec {
            revision_ordinal: 3,
            cited_ordinal: Some(2),
            ..base
        },
        // The `InitialState` cites another CIS1 than the CSR1's producer.
        Spec {
            initial_cites_other_producer: true,
            ..base
        },
    ];
    for (index, case) in cases.into_iter().enumerate() {
        assert_eq!(forge(&case)?, Err(Error::InvalidBinding), "case {index}");
    }
    Ok(())
}

/// Review L3 and L5 on #1180: members, owner bindings, the CAR1 content
/// binding, and a root that is not a `StateRevision` node.
#[test]
fn every_member_owner_proof_and_root_mismatch_is_refused() -> TestResult {
    let base = Spec::BASE;
    let cases = [
        Spec {
            cis_member: hash(6),
            ..base
        },
        Spec {
            head_member: hash(7),
            ..base
        },
        Spec {
            csr_owner: hash(0x48),
            ..base
        },
        Spec {
            car1_owner: hash(0x49),
            ..base
        },
        Spec {
            proof: Proof::OtherPlaintext,
            ..base
        },
        Spec {
            proof: Proof::OtherEnvelope,
            ..base
        },
        Spec {
            root_is_initial: true,
            ..base
        },
    ];
    for (index, case) in cases.into_iter().enumerate() {
        assert_eq!(forge(&case)?, Err(Error::InvalidBinding), "case {index}");
    }
    Ok(())
}

#[test]
fn a_pass_revision_and_unsupported_or_malformed_records_are_refused() -> TestResult {
    let mut key = protector(GENERATION)?;
    let pass = revision(Revision {
        origin: CommunityStateProducerV1::Pass(CommunityPassKeyV1::new(timeline(), GENERATION, 1)?),
        member: MEMBER,
        state: hash(7),
        producer: hash(8),
        owner: COB,
    })?;
    let refused = [
        (Kind::StateRevisionOrHead, pass, Error::InvalidBinding),
        (
            Kind::PreparedInvocation,
            b"invocation".to_vec(),
            Error::InvalidBinding,
        ),
        (
            Kind::StateContent,
            b"not a CSC1".to_vec(),
            Error::InvalidEncoding,
        ),
        (
            Kind::StateRevisionOrHead,
            b"not a CSR1".to_vec(),
            Error::InvalidEncoding,
        ),
        (
            Kind::ExecutionProvenance,
            vec![0x88, 0x44, b'C', b'I', b'S', b'1'],
            Error::InvalidEncoding,
        ),
        (
            Kind::ExecutionProvenance,
            b"not a CPN1".to_vec(),
            Error::InvalidEncoding,
        ),
    ];
    for (index, (kind, plaintext, error)) in refused.into_iter().enumerate() {
        let record = protect(&mut key, kind, &plaintext, &[])?;
        assert_eq!(extract_each(&[&record], &key)?, Err(error), "case {index}");
    }
    Ok(())
}

#[test]
fn unsupported_node_forms_are_refused() -> TestResult {
    let mut key = protector(GENERATION)?;
    let artifact = [CommunityTypedInputRefV1::Artifact {
        owner_reference: hash(1),
        artifact_class: ErasureArtifactClassV1::TimelineReplay,
        artifact_digest: hash(2),
        registration_address: hash(3),
        source_scope_binding_digest: hash(4),
    }];
    let metadata = [cmb1(OPERATION, 11, 0, 0x60)];
    let nodes = [
        // A kind outside the initialization profile.
        Node {
            kind: CommunityNativeNodeKindV1::Observation,
            ..Node::initial(1, 0, hash(7), direct(&metadata))
        },
        // An `InitialState` over a CSR1.
        Node {
            content: content(*b"CSR1", hash(7)),
            ..Node::initial(1, 0, hash(7), direct(&metadata))
        },
        // Another store incarnation.
        Node {
            incarnation: [0x5b; 16],
            ..Node::initial(1, 0, hash(7), direct(&metadata))
        },
        // No direct input index, or an artifact input.
        Node::initial(1, 0, hash(7), CommunityInputIndexV1::Empty),
        Node::initial(1, 0, hash(7), direct(&artifact)),
    ];
    for (index, spec) in nodes.into_iter().enumerate() {
        let (bytes, _) = node(spec)?;
        let record = protect(&mut key, Kind::ExecutionProvenance, &bytes, &[])?;
        assert_eq!(
            extract_each(&[&record], &key)?,
            Err(Error::InvalidBinding),
            "node {index}"
        );
    }
    Ok(())
}

#[test]
fn a_record_of_another_generation_is_refused() -> TestResult {
    let mut key = protector([0x21; 16])?;
    let record = protect(&mut key, Kind::StateContent, &state(b"state")?, &[])?;
    assert_eq!(extract_each(&[&record], &key)?, Err(Error::InvalidBinding));
    Ok(())
}

#[test]
fn duplicate_identities_and_missing_or_unlisted_children_are_refused() -> TestResult {
    let mut key = protector(GENERATION)?;
    let state_bytes = state(b"state")?;
    let first = protect(&mut key, Kind::StateContent, &state_bytes, &[])?;
    let second = protect(&mut key, Kind::StateContent, &state_bytes, &[])?;
    assert_eq!(
        resolve(&[&first, &second], &key)?,
        Err(Error::InvalidBinding)
    );

    // A CSR1 whose ARD1 omits its CSC1 and CIS1.
    let initializer = producer(&state_bytes, hash(4), MEMBER)?;
    let producer_record = protect(
        &mut key,
        Kind::ExecutionProvenance,
        &initializer.to_canonical_cbor(),
        &[],
    )?;
    let revision_bytes = revision(Revision {
        origin: INITIALIZATION,
        member: MEMBER,
        state: adr_h("CSC1", &state_bytes),
        producer: initializer.digest(),
        owner: COB,
    })?;
    let unlisted = protect(&mut key, Kind::StateRevisionOrHead, &revision_bytes, &[])?;
    assert_eq!(
        resolve(&[&first, &producer_record, &unlisted], &key)?,
        Err(Error::InvalidBinding)
    );

    // A `StateRevision` node whose CSR1 is absent: the node's lookup of its
    // CSR1 refuses.
    let revision_record = protect(
        &mut key,
        Kind::StateRevisionOrHead,
        &revision_bytes,
        &[&first, &producer_record],
    )?;
    let metadata = [cmb1(OPERATION, 11, 0, 0x60)];
    let (initial_bytes, initial_reference) =
        node(Node::initial(1, 0, initializer.digest(), direct(&metadata)))?;
    let initial = protect(
        &mut key,
        Kind::ExecutionProvenance,
        &initial_bytes,
        &[&producer_record],
    )?;
    let native = [CommunityTypedInputRefV1::Native(initial_reference)];
    let (revision_node, _) = node(Node {
        kind: CommunityNativeNodeKindV1::StateRevision,
        ordinal: 1,
        content: content(*b"CSR1", adr_h("CSR1", &revision_bytes)),
        ..Node::initial(1, 1, hash(7), direct(&native))
    })?;
    let revision_node_record = protect(
        &mut key,
        Kind::ExecutionProvenance,
        &revision_node,
        &[&revision_record, &first, &initial],
    )?;
    assert_eq!(
        resolve(
            &[&first, &producer_record, &initial, &revision_node_record],
            &key
        )?,
        Err(Error::InvalidBinding)
    );
    // A `StateRevision` node whose CSR1 is present but whose CSC1 is absent.
    // The node comes first in the batch, so its lookup of the CSC1 its CSR1
    // names refuses before the CSR1's own children are resolved.
    assert_eq!(
        resolve(
            &[
                &revision_node_record,
                &producer_record,
                &revision_record,
                &initial
            ],
            &key
        )?,
        Err(Error::InvalidBinding)
    );
    Ok(())
}

/// Review L on #1180 at ddd9b488d: a graph that passes every other check
/// is refused when a CGR1 count is wrong or a record is unreachable.
#[test]
fn a_closure_that_is_not_exactly_the_batch_is_refused() -> TestResult {
    let recounts: [Recount; 6] = [
        |counts| CommunityGraphCountsV1 {
            registrations: counts.registrations + 1,
            ..counts
        },
        |counts| CommunityGraphCountsV1 {
            edges: counts.edges + 1,
            ..counts
        },
        |counts| CommunityGraphCountsV1 {
            keys: counts.keys + 1,
            ..counts
        },
        |counts| CommunityGraphCountsV1 {
            maximum_depth: counts.maximum_depth + 1,
            ..counts
        },
        |counts| CommunityGraphCountsV1 {
            registration_bytes: counts.registration_bytes + 1,
            ..counts
        },
        |counts| CommunityGraphCountsV1 {
            artifact_bytes: counts.artifact_bytes + 1,
            ..counts
        },
    ];
    for (index, recount) in recounts.into_iter().enumerate() {
        let case = Spec {
            recount,
            ..Spec::BASE
        };
        assert_eq!(forge(&case)?, Err(Error::InvalidBinding), "count {index}");
    }
    let unreachable = Spec {
        extra: Extra::Unreachable,
        ..Spec::BASE
    };
    assert_eq!(forge(&unreachable)?, Err(Error::InvalidBinding));
    Ok(())
}

/// Review M2 on #1180: a cycle refuses; a shared child does not.
#[test]
fn the_closure_walk_refuses_a_cycle() {
    assert_eq!(
        heights(&[0], &[vec![1], vec![0]]),
        Err(Error::InvalidBinding)
    );
    assert_eq!(heights(&[0], &[vec![0]]), Err(Error::InvalidBinding));
    let diamond = heights(&[0], &[vec![1, 2], vec![3], vec![3], vec![]]);
    assert_eq!(
        diamond.map(|heights| heights.into_iter().collect::<Vec<_>>()),
        Ok(vec![(0, 3), (1, 2), (2, 2), (3, 1)])
    );
}

/// One member of the two-member graph: its protected CSC1, CIS1 and CSR1,
/// its CSR1 bytes and its protected `InitialState` node.
struct PairMember {
    state: CommunityProtectedRecordV1,
    producer: CommunityProtectedRecordV1,
    revision: CommunityProtectedRecordV1,
    revision_bytes: Vec<u8>,
    initial: ProtectedNode,
}

/// The plain CSC1, CIS1 and CSR1 of the member in `slot`.
fn pair_plain(
    slot: u16,
    member: Hash,
) -> Fallible<(Vec<u8>, CommunityInitializationProducerV1, Vec<u8>)> {
    let state_bytes = state(&[b'a' + u8::try_from(slot)?])?;
    let initializer = producer(&state_bytes, hash(4), member)?;
    let revision_bytes = revision(Revision {
        origin: INITIALIZATION,
        member,
        state: adr_h("CSC1", &state_bytes),
        producer: initializer.digest(),
        owner: COB,
    })?;
    Ok((state_bytes, initializer, revision_bytes))
}

/// The protected CSC1, CIS1 and CSR1 of one member.
fn pair_records(
    key: &mut CommunityArtifactProtectorV1,
    state_bytes: &[u8],
    initializer: &CommunityInitializationProducerV1,
    revision_bytes: &[u8],
) -> Fallible<[CommunityProtectedRecordV1; 3]> {
    let state = protect(key, Kind::StateContent, state_bytes, &[])?;
    let producer = protect(
        key,
        Kind::ExecutionProvenance,
        &initializer.to_canonical_cbor(),
        &[],
    )?;
    let revision = protect(
        key,
        Kind::StateRevisionOrHead,
        revision_bytes,
        &[&state, &producer],
    )?;
    Ok([state, producer, revision])
}

/// The protected `InitialState` node of the member in `slot`.
fn pair_initial(
    key: &mut CommunityArtifactProtectorV1,
    slot: u16,
    initializer: Hash,
    producer_record: &CommunityProtectedRecordV1,
) -> Fallible<ProtectedNode> {
    let metadata = [cmb1(OPERATION, 11, slot, 0x60 + u8::try_from(slot)?)];
    let (bytes, reference) = node(Node::initial(
        1,
        u32::from(slot) * 2,
        initializer,
        direct(&metadata),
    ))?;
    Ok((
        protect(key, Kind::ExecutionProvenance, &bytes, &[producer_record])?,
        reference,
    ))
}

fn pair_member(
    key: &mut CommunityArtifactProtectorV1,
    slot: u16,
    member: Hash,
) -> Fallible<PairMember> {
    let (state_bytes, initializer, revision_bytes) = pair_plain(slot, member)?;
    let [state, producer, revision] =
        pair_records(key, &state_bytes, &initializer, &revision_bytes)?;
    let initial = pair_initial(key, slot, initializer.digest(), &producer)?;
    Ok(PairMember {
        state,
        producer,
        revision,
        revision_bytes,
        initial,
    })
}

fn pair_members(
    key: &mut CommunityArtifactProtectorV1,
    members: [Hash; 2],
) -> Fallible<Vec<PairMember>> {
    let mut pair = Vec::new();
    for slot in 0..2_u16 {
        pair.push(pair_member(key, slot, members[usize::from(slot)])?);
    }
    Ok(pair)
}

/// The protected `StateRevision` node of the member in `slot`, citing the
/// other member's `InitialState` digest at its own ordinal with `swap`.
fn pair_revision_node(
    key: &mut CommunityArtifactProtectorV1,
    swap: bool,
    pair: &[PairMember],
    slot: usize,
) -> Fallible<ProtectedNode> {
    let target = if swap { 1 - slot } else { slot };
    let member = &pair[slot];
    let cited = CommunityNativeNodeReferenceV1 {
        node_ordinal: member.initial.1.node_ordinal,
        ..pair[target].initial.1
    };
    let native = [CommunityTypedInputRefV1::Native(cited)];
    let (bytes, reference) = node(Node {
        kind: CommunityNativeNodeKindV1::StateRevision,
        ordinal: member.initial.1.node_ordinal + 1,
        content: content(*b"CSR1", adr_h("CSR1", &member.revision_bytes)),
        ..Node::initial(1, 0, hash(7), direct(&native))
    })?;
    Ok((
        protect(
            key,
            Kind::ExecutionProvenance,
            &bytes,
            &[&member.revision, &member.state, &pair[target].initial.0],
        )?,
        reference,
    ))
}

fn pair_revision_nodes(
    key: &mut CommunityArtifactProtectorV1,
    swap: bool,
    pair: &[PairMember],
) -> Fallible<Vec<ProtectedNode>> {
    let mut revision_nodes = Vec::new();
    for slot in 0..pair.len() {
        revision_nodes.push(pair_revision_node(key, swap, pair, slot)?);
    }
    Ok(revision_nodes)
}

/// Prepare both members' records against a CSH1 over the distinct
/// `members`, rooted at both `StateRevision` nodes.
fn prepare_pair(
    key: &CommunityArtifactProtectorV1,
    members: [Hash; 2],
    pair: &[PairMember],
    revision_nodes: &[ProtectedNode],
) -> Fallible<Result<(), Error>> {
    let mut records = Vec::new();
    for (member, (revision_record, _)) in pair.iter().zip(revision_nodes) {
        records.extend([
            &member.state,
            &member.producer,
            &member.revision,
            &member.initial.0,
            revision_record,
        ]);
    }
    let mut head_members = members.to_vec();
    head_members.sort();
    head_members.dedup();
    let mut roots: Vec<CommunityNativeNodeReferenceV1> = revision_nodes
        .iter()
        .map(|(_, reference)| *reference)
        .collect();
    roots.sort();
    prepare(&records, &head_members, &roots, key)
}

/// Forge a two-member graph, slots 0 and 1. With `swap`, each
/// `StateRevision` cites the other member's `InitialState` digest at its
/// own `InitialState`'s ordinal. With `same_member`, both members' CIS1 and
/// CSR1 name one member.
fn forge_pair(swap: bool, same_member: bool) -> Fallible<Result<(), Error>> {
    let mut key = protector(GENERATION)?;
    let members = if same_member {
        [MEMBER, MEMBER]
    } else {
        [MEMBER, hash(6)]
    };
    let pair = pair_members(&mut key, members)?;
    let revision_nodes = pair_revision_nodes(&mut key, swap, &pair)?;
    prepare_pair(&key, members, &pair, &revision_nodes)
}

/// Review M on #1180 at 5c0311385: two members cannot swap their
/// `InitialState` nodes or share one member binding.
#[test]
fn two_members_cannot_swap_initial_nodes_or_share_a_member() -> TestResult {
    assert_eq!(forge_pair(false, false)?, Ok(()));
    // The swap is also refused by the existing producer check: each swapped
    // `InitialState` cites the other member's CIS1. It therefore does not
    // isolate the full-reference comparison; the single-member mis-cite case
    // (`revision_ordinal: 3, cited_ordinal: Some(2)`) in
    // `every_node_shape_violation_is_refused` is the one that guards it.
    assert_eq!(forge_pair(true, false)?, Err(Error::InvalidBinding));
    assert_eq!(forge_pair(false, true)?, Err(Error::InvalidBinding));
    Ok(())
}
