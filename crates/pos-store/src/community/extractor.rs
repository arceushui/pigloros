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
//! 5. resolves every CGR1 root to a `StateRevision` CPN1 (item 5), walks
//!    the complete required closure and re-derives the CGR1 counts over the
//!    ARD1 graph (item 6), refusing any record outside the closure.
//!
//! This first profile admits the code-0 initialization graph: CSC1, CIS1,
//! CSR1 and the `InitialState` and `StateRevision` CPN1s. Any other family
//! or form is refused until its extractor is admitted.

use std::collections::{BTreeMap, BTreeSet};

use pos_core::community_lifecycle::{
    CommunityArtifactHeaderInputV1, CommunityArtifactKindV1, CommunityArtifactOperationV1,
    CommunityClassificationProofV1, CommunityEncryptedEnvelopeV1, CommunityGraphRootV1,
    CommunityInitializationProducerV1, CommunityInputIndexV1, CommunityLifecycleErrorV1 as Error,
    CommunityNativeNodeKindV1, CommunityNativeNodeReferenceV1, CommunityNativeNodeV1,
    CommunityProtectedObjectV1, CommunitySelectedHeadV1, CommunityStateContentV1,
    CommunityStateProducerV1, CommunityStateRevisionV1, CommunityTypedInputRefV1,
};
use pos_core::{
    ArtifactChildEdgeV1, ArtifactRegistrationV1, AuthorityTrustRootSealV1, Hash, TimelineId,
};
use zeroize::Zeroizing;

use super::private_hash::{plaintext_commitment, private_digest};
use super::protection::{
    derive_registration, CommunityArtifactProtectorV1, CommunityProtectedRecordV1,
};

/// One COW1 and the ARD1 its caller proposes for it.
#[derive(Clone, Copy)]
pub struct CommunityArtifactRecordInputV1<'a> {
    /// The exact canonical COW1 bytes.
    pub object: &'a [u8],
    /// The ARD1 to be published for those bytes.
    pub registration: &'a ArtifactRegistrationV1,
}

/// One candidate graph and the current head it must extend.
#[derive(Clone, Copy)]
pub struct CommunityArtifactBatchInputV1<'a> {
    /// The protected store incarnation.
    pub store_incarnation: [u8; 16],
    /// The CDP1 the graph is selected under.
    pub profile_digest: Hash,
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

/// An owner-verified complete community closure, ready for the atomic
/// commit. It grants no read; COA1 and current authority come after.
pub struct CommunityArtifactBatchV1 {
    records: Vec<CommunityProtectedRecordV1>,
    graph_root_digest: Hash,
}

impl CommunityArtifactBatchV1 {
    /// Every verified COW1 with its ARD1, in input order.
    #[must_use]
    pub fn records(&self) -> &[CommunityProtectedRecordV1] {
        &self.records
    }

    /// `H(CGR1)` of the verified root.
    #[must_use]
    pub const fn graph_root_digest(&self) -> Hash {
        self.graph_root_digest
    }
}

/// A logical record a COW1's ARD1 must list as a child.
#[derive(Clone, Copy)]
enum Child {
    /// The record with this magic and logical digest.
    Record([u8; 4], Hash),
    /// The CSC1 of the CSR1 with this logical digest: a `StateRevision`
    /// node's result materialization.
    StateOf(Hash),
}

/// The facts one authenticated record contributes to the graph.
struct Extracted {
    magic: [u8; 4],
    logical: Hash,
    state: Option<Hash>,
    node: Option<(CommunityNativeNodeKindV1, CommunityNativeNodeReferenceV1)>,
    children: Vec<Child>,
    record: CommunityProtectedRecordV1,
}

/// The decoded CGR1 facts every record is checked against.
struct Root {
    timeline: TimelineId,
    generation: [u8; 16],
    roots: Vec<CommunityNativeNodeReferenceV1>,
    counts: [u64; 6],
    digest: Hash,
}

/// Verify one candidate community graph and prepare its batch.
///
/// Only the trusted composition root, which holds the
/// [`AuthorityTrustRootSealV1`], prepares a batch:
///
/// ```compile_fail,E0061
/// use pos_store::community::{
///     prepare_community_artifact_batch_v1, CommunityArtifactBatchInputV1,
///     CommunityArtifactProtectorV1,
/// };
/// fn forge(input: CommunityArtifactBatchInputV1<'_>, keys: &[&CommunityArtifactProtectorV1]) {
///     let _ = prepare_community_artifact_batch_v1(input, keys);
/// }
/// ```
///
/// # Errors
/// Returns `StaleFrontier` when the current head is not the expected prior
/// head; `EvidenceUnavailable` when no supplied key handle owns a record's
/// operation or an envelope does not authenticate; the codec refusal for a
/// malformed COW1, envelope, CAR1, record, CGR1 or CSH1; and
/// `InvalidBinding` for any header, key, CAR1, ARD1, record-schema, child,
/// root, closure, count or head-binding mismatch.
pub fn prepare_community_artifact_batch_v1(
    _seal: &'static AuthorityTrustRootSealV1,
    input: CommunityArtifactBatchInputV1<'_>,
    keys: &[&CommunityArtifactProtectorV1],
) -> Result<CommunityArtifactBatchV1, Error> {
    if input.current_head != input.expected_prior_head {
        return Err(Error::StaleFrontier);
    }
    let root = read_root(&input)?;
    let extracted = input
        .records
        .iter()
        .map(|record| extract(*record, &input, &root, keys))
        .collect::<Result<Vec<_>, Error>>()?;
    let edges = resolve_children(&extracted)?;
    check_closure(&extracted, &edges, &root)?;
    Ok(CommunityArtifactBatchV1 {
        records: extracted.into_iter().map(|record| record.record).collect(),
        graph_root_digest: root.digest,
    })
}

/// Decode CGR1 and its CSH1 and check that they name each other and this
/// store and profile.
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
        roots: fields.roots.iter().collect::<Result<_, Error>>()?,
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

/// Authenticate one COW1, re-derive its ARD1 and read its plain record.
///
/// The COW1 codec already checks both envelopes and that the proof header
/// is the content header with kind 8, so neither is decoded twice here.
fn extract(
    input: CommunityArtifactRecordInputV1<'_>,
    batch: &CommunityArtifactBatchInputV1<'_>,
    root: &Root,
    keys: &[&CommunityArtifactProtectorV1],
) -> Result<Extracted, Error> {
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
            let intent = key.key_intent().as_input();
            let bound = header.timeline == intent.timeline
                && header.generation == intent.generation
                && header.timeline == root.timeline
                && header.generation == root.generation
                && header.purpose == intent.purpose
                && header.evidence_not_after_micros == intent.evidence_not_after_micros
                && intent.allowed_record_kinds.contains(header.record_kind);
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
                            || registration != *input.registration
                        {
                            return Err(Error::InvalidBinding);
                        }
                        let record = CommunityProtectedRecordV1::from_parts(
                            Zeroizing::new(input.object.to_vec()),
                            object.address(),
                            registration,
                            car1.owner_binding_digest,
                            header.scope_cover_digest,
                            header.evidence_not_after_micros,
                        );
                        read_record(
                            &header,
                            car1.host_provenance_digest,
                            &plaintext,
                            batch,
                            record,
                        )
                    })
                },
            )
        },
    )
}

/// Validate the plain record's schema and derive its logical identity and
/// the logical children its ARD1 must list.
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
        state: None,
        node: None,
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
            ) {
                return Err(Error::InvalidBinding);
            }
            let logical = private_digest(b"PiglorOS.Community.CSR1.v1", &[plaintext]);
            let mut record = extracted(
                *b"CSR1",
                logical,
                vec![
                    Child::Record(*b"CSC1", fields.state_content_digest),
                    Child::Record(*b"CIS1", fields.producer_digest),
                ],
            );
            record.state = Some(fields.state_content_digest);
            Ok(record)
        }
        CommunityArtifactKindV1::ExecutionProvenance
            if plaintext.get(2..6) == Some(b"CIS1".as_slice()) =>
        {
            CommunityInitializationProducerV1::from_canonical_cbor(plaintext)
                .map(|producer| extracted(*b"CIS1", producer.digest(), Vec::new()))
        }
        CommunityArtifactKindV1::ExecutionProvenance => {
            read_node(header, provenance, plaintext, batch).map(|(node, children)| {
                let mut record = extracted(*b"CPN1", node.1.node_digest, children);
                record.node = Some(node);
                record
            })
        }
        _ => Err(Error::InvalidBinding),
    }
}

/// A CPN1's node facts and logical children: its content record, every
/// native input node and, for a `StateRevision`, the CSC1 of its CSR1.
type NodeFacts = (
    (CommunityNativeNodeKindV1, CommunityNativeNodeReferenceV1),
    Vec<Child>,
);

fn read_node(
    header: &CommunityArtifactHeaderInputV1,
    provenance: Hash,
    plaintext: &[u8],
    batch: &CommunityArtifactBatchInputV1<'_>,
) -> Result<NodeFacts, Error> {
    let node = CommunityNativeNodeV1::from_canonical_cbor(plaintext)?;
    let fields = node.as_input();
    let content = fields.content;
    let content_matches = match fields.kind {
        CommunityNativeNodeKindV1::InitialState => content.record_magic == *b"CIS1",
        CommunityNativeNodeKindV1::StateRevision => content.record_magic == *b"CSR1",
        _ => false,
    };
    let scope_cover = header.scope_cover_digest;
    let bound = content_matches
        && fields.store_incarnation == batch.store_incarnation
        && fields.timeline == header.timeline
        && fields.generation == header.generation
        && fields.scope_binding_digest == scope_cover
        && fields.provenance_digest == provenance
        && fields.evidence_not_after_micros == header.evidence_not_after_micros;
    let CommunityInputIndexV1::Direct(inputs) = fields.input_index else {
        return Err(Error::InvalidBinding);
    };
    if !bound {
        return Err(Error::InvalidBinding);
    }
    let mut children = vec![Child::Record(content.record_magic, content.logical_digest)];
    if fields.kind == CommunityNativeNodeKindV1::StateRevision {
        children.push(Child::StateOf(content.logical_digest));
    }
    for input in inputs.iter() {
        match input? {
            // A metadata source is CNE1-resident and has no ARD1.
            CommunityTypedInputRefV1::Metadata { .. } => {}
            CommunityTypedInputRefV1::Native(reference) => {
                children.push(Child::Record(*b"CPN1", reference.node_digest));
            }
            _ => return Err(Error::InvalidBinding),
        }
    }
    Ok(((fields.kind, node.reference()), children))
}

/// Resolve every record's logical children to records and require its ARD1
/// to list exactly their required edges.
fn resolve_children(extracted: &[Extracted]) -> Result<Vec<Vec<usize>>, Error> {
    let mut by_identity = BTreeMap::new();
    for (index, record) in extracted.iter().enumerate() {
        if by_identity
            .insert((record.magic, record.logical), index)
            .is_some()
        {
            return Err(Error::InvalidBinding);
        }
    }
    let find = |magic: [u8; 4], digest: Hash| {
        by_identity
            .get(&(magic, digest))
            .copied()
            .ok_or(Error::InvalidBinding)
    };
    extracted
        .iter()
        .map(|record| {
            let children = record
                .children
                .iter()
                .map(|child| match *child {
                    Child::Record(magic, digest) => find(magic, digest),
                    Child::StateOf(revision) => find(*b"CSR1", revision).and_then(|index| {
                        extracted[index]
                            .state
                            .ok_or(Error::InvalidBinding)
                            .and_then(|state| find(*b"CSC1", state))
                    }),
                })
                .collect::<Result<Vec<usize>, Error>>()?;
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

/// Resolve every CGR1 root to a `StateRevision` CPN1, walk the complete
/// closure and require it to be exactly the batch with exactly the CGR1
/// counts. Child edges name content digests, so they cannot form a cycle.
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
    let mut heights: BTreeMap<usize, u64> = BTreeMap::new();
    let mut stack: Vec<(usize, bool)> = roots.iter().map(|index| (*index, false)).collect();
    while let Some((index, expanded)) = stack.pop() {
        if expanded {
            let height = 1 + edges[index]
                .iter()
                .map(|child| heights.get(child).copied().unwrap_or(0))
                .max()
                .unwrap_or(0);
            heights.insert(index, height);
        } else if !heights.contains_key(&index) {
            stack.push((index, true));
            stack.extend(edges[index].iter().map(|child| (*child, false)));
        }
    }
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

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
