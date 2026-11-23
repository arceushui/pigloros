//! ADR-128 §3 / ADR-129 §4 community native extractor and root.
//!
//! [`prepare_community_artifact_batch_v1`] is the sealed community
//! counterpart of the MRM1 preparer: it does not extend that preparer by
//! guessing COW1 magic. Before any ARD1 registration can be published it
//!
//! 1. checks the current head: the CSI1 selection must still be the CGI1's
//!    expected prior head (owner decision on #560, note 22661, item 8);
//! 2. authenticates every COW1 and its CAR1 under the current qualified key
//!    handle of its `ProtectArtifacts` suboperation;
//! 3. validates each plain record's schema and re-derives its exact ARD1,
//!    including the purpose's optionality and transition rule (note 22649);
//! 4. derives each record's ARD1 children from its own content (note 22661,
//!    item 4) and requires the CAR1 to list exactly those;
//! 5. checks the note-22661 node shape (items 1 to 3): each `InitialState`
//!    node 2·slot cites only its CMB1 locator, each `StateRevision` node
//!    2·slot+1 cites only that node, every node shares one producer
//!    ordinal and carries the CGI1 `authorization_ref`, and each CSR1, CIS1
//!    and CSH1 member agree;
//! 6. resolves every CGR1 root to a `StateRevision` CPN1 (item 5), walks
//!    the complete required closure, refusing a cycle or any record outside
//!    it, and re-derives the CGR1 counts over the ARD1 graph (item 6).
//!
//! This first profile admits the code-0 initialization graph: CSC1, CIS1,
//! CSR1 and the `InitialState` and `StateRevision` CPN1s.
//!
//! The control-record form (ADR-129 revision 9 R9.9(5)) admits
//! `LifecycleControl` COW1s with no CGR1 and no selected head: today the
//! pre-execution CFO1 of a `SetReason`. Its current head must still be the
//! CQC1 expected head, and each record must decode as a pre-execution CFO1
//! with no `PassKey` and no CFI1, so its ARD1 has no children. Any other
//! family or form is refused until its extractor is admitted.

use std::collections::{BTreeMap, BTreeSet};

use pos_core::community_lifecycle::{
    ArtifactRefV1, CommunityArtifactHeaderInputV1, CommunityArtifactKindV1,
    CommunityArtifactOperationV1, CommunityClassificationProofV1, CommunityEncryptedEnvelopeV1,
    CommunityGraphRootV1, CommunityInitializationProducerV1, CommunityInputIndexV1,
    CommunityLifecycleErrorV1 as Error, CommunityLocatorProducerV1, CommunityMetadataSchemaV1,
    CommunityNativeNodeKindV1, CommunityNativeNodeReferenceV1, CommunityNativeNodeV1,
    CommunityPassFailureV1, CommunityProtectedObjectV1, CommunitySelectedHeadV1,
    CommunityStateContentV1, CommunityStateProducerV1, CommunityStateRevisionV1,
    CommunityTypedInputRefV1,
};
use pos_core::{
    ArtifactChildEdgeV1, ArtifactRegistrationV1, AuthorityTrustRootSealV1, Hash, TimelineId,
};
use zeroize::Zeroizing;

use super::private_hash::{plaintext_commitment, private_digest};
use super::protection::{
    derive_registration, CommunityArtifactProtectorV1, CommunityProtectedRecordV1,
};

/// The variant-3 `record_role` of a CMB1, its ADR-129 §3 whitelist index
/// (owner decision on #560, note 22661, item 1).
const CMB1_RECORD_ROLE: u16 = 11;

/// One COW1 and the ARD1 its caller proposes for it.
#[derive(Clone, Copy)]
pub struct CommunityArtifactRecordInputV1<'a> {
    /// The exact canonical COW1 bytes.
    pub object: &'a [u8],
    /// The ARD1 to be published for those bytes.
    pub registration: &'a ArtifactRegistrationV1,
}

/// One candidate initialization graph, the admitted request facts it must
/// bind and the current head it must extend.
#[derive(Clone, Copy)]
pub struct CommunityArtifactBatchInputV1<'a> {
    /// The protected store incarnation.
    pub store_incarnation: [u8; 16],
    /// The CDP1 the graph is selected under.
    pub profile_digest: Hash,
    /// The CGI1 `operation_id` every CMB1 locator names.
    pub operation_id: [u8; 16],
    /// The CGI1 `authorization_ref` every CPN1 carries (note 22661, item 3).
    pub authorization_ref: ArtifactRefV1,
    /// The COB1 commitment every CAR1 and CSR1 binds.
    pub owner_binding_digest: Hash,
    /// Every COW1 of the candidate closure.
    pub records: &'a [CommunityArtifactRecordInputV1<'a>],
    /// The canonical CGR1 execution root.
    pub graph_root: &'a [u8],
    /// The canonical CSH1 the root selects.
    pub selected_head: &'a [u8],
    /// The CSI1 row's current `selected_head_or_null`.
    pub current_head: Option<Hash>,
    /// The CGI1's `expected_prior_head_or_null`.
    pub expected_prior_head: Option<Hash>,
}

/// One control-record batch (ADR-129 revision 9 R9.9(5)): `LifecycleControl`
/// COW1s of one Control operation, with no CGR1 and no selected head.
#[derive(Clone, Copy)]
pub struct CommunityControlBatchInputV1<'a> {
    /// The Timeline every record's key and header names.
    pub timeline: TimelineId,
    /// The generation every record's key and header names.
    pub generation: [u8; 16],
    /// The COB1 commitment every CAR1 binds.
    pub owner_binding_digest: Hash,
    /// Every COW1 of the batch, at least one.
    pub records: &'a [CommunityArtifactRecordInputV1<'a>],
    /// A CGR1, which a control batch must not carry.
    pub graph_root: Option<&'a [u8]>,
    /// The CSI1 row's current `selected_head_or_null`.
    pub current_head: Option<Hash>,
    /// The CQC1's `expected_state_head_digest`.
    pub expected_head: Option<Hash>,
}

/// The two batch forms of the one sealed extractor (R9.9(5), N8(a)).
#[derive(Clone, Copy)]
pub enum CommunityArtifactBatchFormV1<'a> {
    /// A CGR1 closure, such as the initialization graph.
    Closure(CommunityArtifactBatchInputV1<'a>),
    /// A `LifecycleControl` control-record batch.
    Control(CommunityControlBatchInputV1<'a>),
}

/// An owner-verified complete community closure or control batch, ready
/// for the atomic commit. It grants no read; COA1 and current authority
/// come after.
pub struct CommunityArtifactBatchV1 {
    #[cfg(target_os = "linux")]
    timeline: TimelineId,
    #[cfg(target_os = "linux")]
    generation: [u8; 16],
    records: Vec<CommunityProtectedRecordV1>,
    graph_root_digest: Option<Hash>,
}

impl CommunityArtifactBatchV1 {
    /// Every verified COW1 with its ARD1, in input order.
    #[must_use]
    pub fn records(&self) -> &[CommunityProtectedRecordV1] {
        &self.records
    }

    /// The Timeline and generation of the verified root, whose
    /// artifact-catalogue owner owns every record's ARD1.
    #[cfg(target_os = "linux")]
    pub(crate) const fn coordinates(&self) -> (TimelineId, [u8; 16]) {
        (self.timeline, self.generation)
    }

    /// `H(CGR1)` of the verified root, or `None` for a control batch.
    #[must_use]
    pub const fn graph_root_digest(&self) -> Option<Hash> {
        self.graph_root_digest
    }
}

/// A logical record a COW1's ARD1 must list as a child.
#[derive(Clone, Copy)]
enum Child {
    /// The record with this magic and logical digest.
    Record([u8; 4], Hash),
    /// The CSR1 with this logical digest and its CSC1: a `StateRevision`
    /// node's content and result materialization.
    Revision(Hash),
}

/// The facts one authenticated record contributes to the graph.
struct Extracted {
    magic: [u8; 4],
    logical: Hash,
    /// A CSR1's or CIS1's member binding; zero otherwise.
    member: Hash,
    /// A CSR1's CSC1; zero otherwise.
    state: Hash,
    /// A CSR1's producer CIS1, or an `InitialState` node's content CIS1;
    /// zero otherwise.
    producer: Hash,
    node: Option<(CommunityNativeNodeKindV1, CommunityNativeNodeReferenceV1)>,
    /// A `StateRevision` node's cited `InitialState` reference.
    cited: Option<CommunityNativeNodeReferenceV1>,
    children: Vec<Child>,
    record: CommunityProtectedRecordV1,
}

/// The decoded CGR1 and CSH1 facts every record is checked against.
struct Root {
    timeline: TimelineId,
    generation: [u8; 16],
    roots: Vec<CommunityNativeNodeReferenceV1>,
    members: BTreeSet<Hash>,
    counts: [u64; 6],
    digest: Hash,
}

/// Verify one candidate community graph or control batch and prepare its
/// batch.
///
/// Only the trusted composition root, which holds the
/// [`AuthorityTrustRootSealV1`], prepares a batch:
///
/// ```compile_fail,E0061
/// use pos_store::community::{
///     prepare_community_artifact_batch_v1, CommunityArtifactBatchFormV1,
///     CommunityArtifactProtectorV1,
/// };
/// fn forge(input: CommunityArtifactBatchFormV1<'_>, keys: &[&CommunityArtifactProtectorV1]) {
///     let _ = prepare_community_artifact_batch_v1(input, keys);
/// }
/// ```
///
/// # Errors
/// Returns `StaleFrontier` when the current head is not the expected prior
/// head; `EvidenceUnavailable` when no supplied key handle owns a record's
/// operation or an envelope does not authenticate; the codec refusal for a
/// malformed COW1, record, CGR1 or CSH1; and `InvalidBinding` for any
/// header, key, CAR1, ARD1, owner-binding, record-schema, node-shape, child,
/// member, root, cycle, closure, count or head-binding mismatch, and for a
/// control batch with a CGR1, no record or a record other than a
/// pre-execution `LifecycleControl` CFO1.
pub fn prepare_community_artifact_batch_v1(
    _seal: &'static AuthorityTrustRootSealV1,
    form: CommunityArtifactBatchFormV1<'_>,
    keys: &[&CommunityArtifactProtectorV1],
) -> Result<CommunityArtifactBatchV1, Error> {
    match form {
        CommunityArtifactBatchFormV1::Closure(input) => prepare_closure(&input, keys),
        CommunityArtifactBatchFormV1::Control(input) => prepare_control(input, keys),
    }
}

/// The CGR1 closure form.
fn prepare_closure(
    input: &CommunityArtifactBatchInputV1<'_>,
    keys: &[&CommunityArtifactProtectorV1],
) -> Result<CommunityArtifactBatchV1, Error> {
    if input.current_head != input.expected_prior_head {
        return Err(Error::StaleFrontier);
    }
    let root = read_root(input)?;
    let extracted = input
        .records
        .iter()
        .map(|record| extract(*record, input, &root, keys))
        .collect::<Result<Vec<_>, Error>>()?;
    let edges = resolve_children(&extracted)?;
    check_shape(&extracted, &edges, &root)?;
    check_closure(&extracted, &edges, &root)?;
    Ok(CommunityArtifactBatchV1 {
        #[cfg(target_os = "linux")]
        timeline: root.timeline,
        #[cfg(target_os = "linux")]
        generation: root.generation,
        records: extracted.into_iter().map(|record| record.record).collect(),
        graph_root_digest: Some(root.digest),
    })
}

/// The control-record form (R9.9(5)): the head must be the CQC1 expected
/// head, there is no CGR1, and every record is a `LifecycleControl` COW1
/// holding a pre-execution CFO1 (no `PassKey`, no CFI1), whose ARD1 therefore
/// has no children.
fn prepare_control(
    input: CommunityControlBatchInputV1<'_>,
    keys: &[&CommunityArtifactProtectorV1],
) -> Result<CommunityArtifactBatchV1, Error> {
    if input.current_head != input.expected_head {
        return Err(Error::StaleFrontier);
    }
    if input.graph_root.is_some() || input.records.is_empty() {
        return Err(Error::InvalidBinding);
    }
    let binding = BatchBinding {
        timeline: input.timeline,
        generation: input.generation,
        owner_binding_digest: input.owner_binding_digest,
    };
    input
        .records
        .iter()
        .map(|record| {
            authenticate(*record, binding, keys).and_then(|authenticated| {
                let pre_execution = authenticated.header.record_kind
                    == CommunityArtifactKindV1::LifecycleControl
                    && authenticated
                        .record
                        .registration()
                        .fields()
                        .child_artifacts
                        .is_empty()
                    && CommunityPassFailureV1::from_canonical_cbor(&authenticated.plaintext)
                        .is_ok_and(|failure| {
                            let failure = failure.as_input();
                            failure.pass_key.is_none()
                                && failure.invocation_evidence_digests.is_empty()
                        });
                if pre_execution {
                    Ok(authenticated.record)
                } else {
                    Err(Error::InvalidBinding)
                }
            })
        })
        .collect::<Result<Vec<_>, Error>>()
        .map(|records| CommunityArtifactBatchV1 {
            #[cfg(target_os = "linux")]
            timeline: input.timeline,
            #[cfg(target_os = "linux")]
            generation: input.generation,
            records,
            graph_root_digest: None,
        })
}

/// Decode CGR1 and its CSH1 and check that they name each other and this
/// store and profile. Decoding already validated every root row.
fn read_root(input: &CommunityArtifactBatchInputV1<'_>) -> Result<Root, Error> {
    let root = CommunityGraphRootV1::from_canonical_cbor(input.graph_root)?;
    let head = CommunitySelectedHeadV1::from_canonical_cbor(input.selected_head)?;
    let fields = root.as_input();
    let selected = head.as_input();
    let bound = fields.store_incarnation == input.store_incarnation
        && fields.profile_digest == input.profile_digest
        && fields.selected_head_digest
            == private_digest(b"PiglorOS.Community.CSH1.v1", &[input.selected_head])
        && selected.timeline == fields.timeline
        && selected.generation == fields.generation
        && selected.profile_digest == input.profile_digest;
    if !bound {
        return Err(Error::InvalidBinding);
    }
    let counts = fields.graph_counts;
    Ok(Root {
        timeline: fields.timeline,
        generation: fields.generation,
        roots: fields.roots.iter().flatten().collect(),
        members: selected
            .member_heads
            .iter()
            .map(|head| head.member_binding_digest)
            .collect(),
        counts: [
            counts.registrations,
            counts.edges,
            counts.keys,
            counts.maximum_depth,
            counts.registration_bytes,
            counts.artifact_bytes,
        ],
        digest: root.digest(),
    })
}

/// The coordinates and owner binding every record of one batch must bind.
#[derive(Clone, Copy)]
struct BatchBinding {
    timeline: TimelineId,
    generation: [u8; 16],
    owner_binding_digest: Hash,
}

/// One COW1 authenticated under its suboperation key, with its plain
/// record, its header, its CAR1 provenance and its re-derived ARD1.
struct Authenticated {
    header: CommunityArtifactHeaderInputV1,
    provenance: Hash,
    plaintext: Zeroizing<Vec<u8>>,
    record: CommunityProtectedRecordV1,
}

/// Authenticate one COW1 and re-derive its ARD1.
///
/// The COW1 codec already checks both envelopes and that the proof header
/// is the content header with kind 8, so neither is decoded twice here.
fn authenticate(
    input: CommunityArtifactRecordInputV1<'_>,
    binding: BatchBinding,
    keys: &[&CommunityArtifactProtectorV1],
) -> Result<Authenticated, Error> {
    let object = CommunityProtectedObjectV1::from_canonical_cbor(input.object)?;
    CommunityEncryptedEnvelopeV1::from_canonical_cbor(object.content_envelope()).and_then(
        |content| {
            let header = *content.header().as_input();
            let key = keys
                .iter()
                .find(|key| {
                    header.operation
                        == CommunityArtifactOperationV1::Control(
                            key.key_intent().as_input().protection_operation_id,
                        )
                })
                .ok_or(Error::EvidenceUnavailable)?;
            // `protect` refuses to seal under a key whose intent does not
            // allow ClassificationProof, so every authenticated record's key
            // allows its kind-8 proof.
            let intent = key.key_intent().as_input();
            let kinds = intent.allowed_record_kinds;
            let bound = header.timeline == intent.timeline
                && header.generation == intent.generation
                && header.timeline == binding.timeline
                && header.generation == binding.generation
                && header.purpose == intent.purpose
                && header.evidence_not_after_micros == intent.evidence_not_after_micros
                && kinds.contains(header.record_kind);
            if !bound {
                return Err(Error::InvalidBinding);
            }
            let plaintext = key.open_envelope(object.content_envelope())?;
            let proof = key.open_envelope(object.proof_envelope())?;
            CommunityClassificationProofV1::from_canonical_cbor(&proof, content.header()).and_then(
                |car1| {
                    let car1 = car1.as_input();
                    let children: Vec<ArtifactChildEdgeV1> = car1.children.iter().collect();
                    derive_registration(
                        key.key_intent(),
                        input.object,
                        &children,
                        content.header().key_identity(),
                    )
                    .and_then(|registration| {
                        if car1.envelope_address != content.address()
                            || car1.plaintext_commitment
                                != plaintext_commitment(header.record_kind, &plaintext)
                            || car1.owner_binding_digest != binding.owner_binding_digest
                            || registration != *input.registration
                        {
                            return Err(Error::InvalidBinding);
                        }
                        Ok(Authenticated {
                            header,
                            provenance: car1.host_provenance_digest,
                            record: CommunityProtectedRecordV1::from_parts(
                                Zeroizing::new(input.object.to_vec()),
                                object.address(),
                                registration,
                                car1.owner_binding_digest,
                                header.scope_cover_digest,
                                header.evidence_not_after_micros,
                            ),
                            plaintext,
                        })
                    })
                },
            )
        },
    )
}

/// Authenticate one closure COW1 and read its plain record.
fn extract(
    input: CommunityArtifactRecordInputV1<'_>,
    batch: &CommunityArtifactBatchInputV1<'_>,
    root: &Root,
    keys: &[&CommunityArtifactProtectorV1],
) -> Result<Extracted, Error> {
    authenticate(
        input,
        BatchBinding {
            timeline: root.timeline,
            generation: root.generation,
            owner_binding_digest: batch.owner_binding_digest,
        },
        keys,
    )
    .and_then(|authenticated| {
        read_record(
            &authenticated.header,
            authenticated.provenance,
            &authenticated.plaintext,
            batch,
            authenticated.record,
        )
    })
}

/// Validate the plain record's schema and derive its logical identity, its
/// graph facts and the logical children its ARD1 must list.
fn read_record(
    header: &CommunityArtifactHeaderInputV1,
    provenance: Hash,
    plaintext: &[u8],
    batch: &CommunityArtifactBatchInputV1<'_>,
    record: CommunityProtectedRecordV1,
) -> Result<Extracted, Error> {
    let extracted = |magic, logical, children| Extracted {
        magic,
        logical,
        member: Hash::zero(),
        state: Hash::zero(),
        producer: Hash::zero(),
        node: None,
        cited: None,
        children,
        record,
    };
    match header.record_kind {
        CommunityArtifactKindV1::StateContent => {
            CommunityStateContentV1::from_canonical_cbor(plaintext).map(|_| {
                let logical = private_digest(b"PiglorOS.Community.CSC1.v1", &[plaintext]);
                extracted(*b"CSC1", logical, Vec::new())
            })
        }
        CommunityArtifactKindV1::StateRevisionOrHead => {
            let revision = CommunityStateRevisionV1::from_canonical_cbor(plaintext)?;
            let fields = revision.as_input();
            if !matches!(
                fields.producer_origin,
                CommunityStateProducerV1::Initialization { .. }
            ) || fields.protected_owner_binding_digest != batch.owner_binding_digest
            {
                return Err(Error::InvalidBinding);
            }
            let logical = private_digest(b"PiglorOS.Community.CSR1.v1", &[plaintext]);
            Ok(Extracted {
                member: fields.member_binding_digest,
                state: fields.state_content_digest,
                producer: fields.producer_digest,
                ..extracted(
                    *b"CSR1",
                    logical,
                    vec![
                        Child::Record(*b"CSC1", fields.state_content_digest),
                        Child::Record(*b"CIS1", fields.producer_digest),
                    ],
                )
            })
        }
        CommunityArtifactKindV1::ExecutionProvenance
            if plaintext.get(2..6) == Some(b"CIS1".as_slice()) =>
        {
            CommunityInitializationProducerV1::from_canonical_cbor(plaintext).map(|producer| {
                Extracted {
                    member: producer.as_input().member_binding_digest,
                    ..extracted(*b"CIS1", producer.digest(), Vec::new())
                }
            })
        }
        CommunityArtifactKindV1::ExecutionProvenance => read_node(
            header, provenance, plaintext, batch,
        )
        .map(|(node, producer, cited, children)| Extracted {
            producer,
            node: Some(node),
            cited,
            ..extracted(*b"CPN1", node.1.node_digest, children)
        }),
        // `check_shape` identifies a CSR1 as the record without a node that
        // has exactly two resolved children. A new record family admitted
        // here must not have that shape unless `check_shape` is revisited.
        _ => Err(Error::InvalidBinding),
    }
}

/// A CPN1's kind and reference, its content CIS1 (for `InitialState`), the
/// node it cites (for `StateRevision`) and its logical children.
type NodeFacts = (
    (CommunityNativeNodeKindV1, CommunityNativeNodeReferenceV1),
    Hash,
    Option<CommunityNativeNodeReferenceV1>,
    Vec<Child>,
);

/// Validate one CPN1 against its envelope, the request and the note-22661
/// shape (items 1 to 3): `InitialState` node 2·slot over CIS1 cites only
/// its CMB1 locator; `StateRevision` node 2·slot+1 over CSR1 cites only
/// node 2·slot of the same producer.
fn read_node(
    header: &CommunityArtifactHeaderInputV1,
    provenance: Hash,
    plaintext: &[u8],
    batch: &CommunityArtifactBatchInputV1<'_>,
) -> Result<NodeFacts, Error> {
    let node = CommunityNativeNodeV1::from_canonical_cbor(plaintext)?;
    let fields = node.as_input();
    let content = fields.content;
    let CommunityInputIndexV1::Direct(inputs) = fields.input_index else {
        return Err(Error::InvalidBinding);
    };
    // Decoding already validated every row.
    let inputs: Vec<CommunityTypedInputRefV1<'_>> = inputs.iter().flatten().collect();
    let control = CommunityLocatorProducerV1::Control(batch.operation_id);
    let shape = match (fields.kind, inputs.as_slice()) {
        (
            CommunityNativeNodeKindV1::InitialState,
            [CommunityTypedInputRefV1::Metadata {
                schema: CommunityMetadataSchemaV1::Cmb1,
                locator,
                ..
            }],
        ) => (content.record_magic == *b"CIS1"
            && locator.timeline == header.timeline
            && locator.generation == header.generation
            && locator.producer == control
            && locator.record_role == CMB1_RECORD_ROLE
            && u32::from(locator.slot) * 2 == fields.node_ordinal)
            .then(|| vec![Child::Record(*b"CIS1", content.logical_digest)]),
        (CommunityNativeNodeKindV1::StateRevision, [CommunityTypedInputRefV1::Native(initial)]) => {
            (content.record_magic == *b"CSR1"
                && fields.node_ordinal % 2 == 1
                && initial.producer_ordinal == fields.producer_ordinal
                && fields.node_ordinal.checked_sub(1) == Some(initial.node_ordinal))
            .then(|| {
                vec![
                    Child::Revision(content.logical_digest),
                    Child::Record(*b"CPN1", initial.node_digest),
                ]
            })
        }
        _ => None,
    };
    let scope_cover = header.scope_cover_digest;
    let bound = fields.store_incarnation == batch.store_incarnation
        && fields.timeline == header.timeline
        && fields.generation == header.generation
        && fields.scope_binding_digest == scope_cover
        && fields.authorization_digest == Hash::from_bytes(batch.authorization_ref.digest)
        && fields.provenance_digest == provenance
        && fields.evidence_not_after_micros == header.evidence_not_after_micros;
    match shape {
        Some(children) if bound => {
            let (producer, cited) = match inputs.as_slice() {
                [CommunityTypedInputRefV1::Native(initial)] => (Hash::zero(), Some(*initial)),
                _ => (content.logical_digest, None),
            };
            Ok(((fields.kind, node.reference()), producer, cited, children))
        }
        _ => Err(Error::InvalidBinding),
    }
}

/// Resolve every record's logical children to records and require its ARD1
/// to list exactly their required edges. A record's resolved children keep
/// the order of its logical children: a CSR1 lists `[CSC1, CIS1]` and a
/// `StateRevision` node `[CSR1, CSC1, InitialState]`.
///
/// Members that start from one catalogue State each protect their own CSC1
/// of that one logical record (note 22661, item 4), so a logical identity
/// may name several records. A child resolves to the one such record whose
/// registration its parent's ARD1 lists; none or several refuse.
fn resolve_children(extracted: &[Extracted]) -> Result<Vec<Vec<usize>>, Error> {
    let mut by_identity: BTreeMap<([u8; 4], Hash), Vec<usize>> = BTreeMap::new();
    for (index, record) in extracted.iter().enumerate() {
        by_identity
            .entry((record.magic, record.logical))
            .or_default()
            .push(index);
    }
    extracted
        .iter()
        .map(|record| {
            let listed = &record.record.registration().fields().child_artifacts;
            let find = |magic: [u8; 4], digest: Hash| {
                let mut found = by_identity
                    .get(&(magic, digest))
                    .into_iter()
                    .flatten()
                    .copied()
                    .filter(|candidate| {
                        let address = extracted[*candidate].record.registration().address();
                        listed
                            .iter()
                            .any(|edge| edge.registration_address == address)
                    });
                match (found.next(), found.next()) {
                    (Some(index), None) => Ok(index),
                    _ => Err(Error::InvalidBinding),
                }
            };
            let mut children = Vec::with_capacity(3);
            for child in &record.children {
                match *child {
                    Child::Record(magic, digest) => children.push(find(magic, digest)?),
                    Child::Revision(digest) => {
                        let revision = find(*b"CSR1", digest)?;
                        children.push(revision);
                        children.push(find(*b"CSC1", extracted[revision].state)?);
                    }
                }
            }
            let mut expected: Vec<ArtifactChildEdgeV1> = children
                .iter()
                .map(|child| {
                    let registration = extracted[*child].record.registration();
                    ArtifactChildEdgeV1 {
                        artifact_class: registration.fields().artifact_class,
                        artifact_digest: registration.fields().artifact_digest,
                        registration_address: registration.address(),
                        required: true,
                    }
                })
                .collect();
            expected.sort_by_key(|edge| {
                (
                    edge.artifact_class,
                    edge.artifact_digest,
                    edge.registration_address,
                )
            });
            if expected == record.record.registration().fields().child_artifacts {
                Ok(children)
            } else {
                Err(Error::InvalidBinding)
            }
        })
        .collect()
}

/// Check the cross-record shape (note 22661, items 2 and 3): every node
/// shares one producer ordinal at a distinct node ordinal; each
/// `StateRevision` node's CSC1 is its CSR1's own CSC1 and its
/// `InitialState` input is exactly the cited node
/// and cites the CIS1 its CSR1 names; each CSR1 names its CIS1's member;
/// and the CSR1 members are exactly the CSH1 members.
///
/// A `StateRevision` input sits at an even ordinal, where only an
/// `InitialState` node can, so its kind needs no separate check. Likewise
/// a CSR1 is the only record without a node that has children (CSC1 and
/// CIS1 have none), so its two resolved children identify it. That holds
/// only because `read_record`'s match is closed: every other record kind
/// refuses there.
fn check_shape(extracted: &[Extracted], edges: &[Vec<usize>], root: &Root) -> Result<(), Error> {
    let nodes: Vec<CommunityNativeNodeReferenceV1> = extracted
        .iter()
        .filter_map(|record| record.node.map(|(_, reference)| reference))
        .collect();
    let producers: BTreeSet<u64> = nodes.iter().map(|node| node.producer_ordinal).collect();
    let ordinals: BTreeSet<u32> = nodes.iter().map(|node| node.node_ordinal).collect();
    let mut members = BTreeSet::new();
    let mut linked = true;
    for (record, children) in extracted.iter().zip(edges) {
        match (record.node, children.as_slice()) {
            (Some((CommunityNativeNodeKindV1::StateRevision, _)), [revision, state, initial]) => {
                // The node's CSC1 is the very record its CSR1 lists, not
                // another member's CSC1 of the same logical State, and the
                // resolved node is exactly the cited one, coordinates
                // included, not just a node with the cited digest.
                linked &= (
                    edges[*revision].first(),
                    extracted[*initial].producer,
                    extracted[*initial].node.map(|(_, reference)| reference),
                ) == (Some(state), extracted[*revision].producer, record.cited);
            }
            (None, [_, producer]) => {
                linked &=
                    extracted[*producer].member == record.member && members.insert(record.member);
            }
            _ => {}
        }
    }
    if producers.len() <= 1 && ordinals.len() == nodes.len() && linked && members == root.members {
        Ok(())
    } else {
        Err(Error::InvalidBinding)
    }
}

/// Resolve every CGR1 root to a `StateRevision` CPN1, walk the complete
/// closure and require it to be exactly the batch with exactly the CGR1
/// counts.
fn check_closure(extracted: &[Extracted], edges: &[Vec<usize>], root: &Root) -> Result<(), Error> {
    let roots = root
        .roots
        .iter()
        .map(|reference| {
            extracted
                .iter()
                .position(|record| {
                    record.node == Some((CommunityNativeNodeKindV1::StateRevision, *reference))
                })
                .ok_or(Error::InvalidBinding)
        })
        .collect::<Result<Vec<usize>, Error>>()?;
    let heights = heights(&roots, edges)?;
    let keys: BTreeSet<_> = extracted
        .iter()
        .flat_map(|record| &record.record.registration().fields().key_dependencies)
        .map(|key| key.identity)
        .collect();
    let sum = |field: fn(&Extracted) -> usize| extracted.iter().map(field).sum::<usize>() as u64;
    let counts = [
        extracted.len() as u64,
        sum(|record| record.record.registration().fields().child_artifacts.len()),
        keys.len() as u64,
        heights.values().copied().max().unwrap_or(0),
        sum(|record| record.record.registration().canonical_cbor().len()),
        sum(|record| record.record.object().len()),
    ];
    if heights.len() == extracted.len() && counts == root.counts {
        Ok(())
    } else {
        Err(Error::InvalidBinding)
    }
}

/// The height of every record reachable from `roots`, counting a leaf as
/// one, by an iterative depth-first walk. A child still on the current path
/// is a cycle and refuses.
fn heights(roots: &[usize], edges: &[Vec<usize>]) -> Result<BTreeMap<usize, u64>, Error> {
    let mut heights: BTreeMap<usize, u64> = BTreeMap::new();
    let mut visiting = BTreeSet::new();
    let mut stack: Vec<(usize, bool)> = roots.iter().map(|index| (*index, false)).collect();
    while let Some((index, expanded)) = stack.pop() {
        if expanded {
            visiting.remove(&index);
            let height = 1 + edges[index]
                .iter()
                .map(|child| heights.get(child).copied().unwrap_or(0))
                .max()
                .unwrap_or(0);
            heights.insert(index, height);
        } else if visiting.contains(&index) {
            return Err(Error::InvalidBinding);
        } else if !heights.contains_key(&index) {
            visiting.insert(index);
            stack.push((index, true));
            stack.extend(edges[index].iter().map(|child| (*child, false)));
        }
    }
    Ok(heights)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
