//! The records Seal stages for a pass's annotations, and their charge
//! (ADR-129 revision 15, R15.6).
//!
//! A V1 pass retains at most one CAT1 and one Annotation CPN1, those of one
//! invocation. [`CommunityAnnotationRecordsV1::stage`] is the one pure
//! function over the invocation's step and its included items: Seal's
//! admission and Commit's counter update both call it, so the two cannot
//! drift. It stages the exact records, so the charge is their measured
//! plaintext encoding and the digests are the ones Seal binds.

use std::collections::BTreeMap;

use super::{
    CommunityAnnotationItemV1, CommunityAnnotationManifestInputV1, CommunityAnnotationManifestV1,
    CommunityContentReferenceV1, CommunityDigestListV1, CommunityInputIndexV1,
    CommunityLifecycleErrorV1 as Error, CommunityNativeNodeInputV1, CommunityNativeNodeKindV1,
    CommunityNativeNodeReferenceV1, CommunityNativeNodeV1, CommunityPassKeyV1,
    CommunityTypedInputRefV1, CommunityTypedInputRefsV1, Result, MAX_COMMUNITY_DIRECT_INPUTS_V1,
};
use crate::{Hash, RecordedDependencyClassV1};

/// One validated annotation item: its GCA1 and the typed references its
/// resolved inputs encode (R15.6(1)).
#[derive(Clone, Copy)]
pub struct CommunityAnnotationCandidateV1<'a> {
    /// Guest annotation index, nondecreasing across an invocation's items.
    pub guest_index: u64,
    /// Exact preferred GCA1 claim bytes.
    pub claim_bytes: &'a [u8],
    /// The item's resolved inputs as typed references, in any order.
    pub inputs: &'a [CommunityTypedInputRefV1<'a>],
}

/// What sizes and binds one invocation's annotation records.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityAnnotationContextV1 {
    /// The original reserved CPK1.
    pub pass_key: CommunityPassKeyV1,
    /// The annotating member's CMB1.
    pub member_binding_digest: Hash,
    /// The invocation's CPI1.
    pub invocation_step_digest: Hash,
    /// The invocation's `InvocationStep` CPN1, the node's first input.
    pub step: CommunityNativeNodeReferenceV1,
    /// The Annotation CPN1's producer ordinal.
    pub producer_ordinal: u64,
    /// The Annotation CPN1's node ordinal within that producer.
    pub node_ordinal: u32,
    /// The Annotation CPN1's scope binding identity.
    pub scope_binding_digest: Hash,
    /// The Annotation CPN1's authorization identity.
    pub authorization_digest: Hash,
    /// The Annotation CPN1's provenance identity.
    pub provenance_digest: Hash,
    /// The fixed horizon of both records.
    pub evidence_not_after_micros: u64,
}

/// What a retained annotation set adds (R15.6(2), (3)).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CommunityAnnotationChargeV1 {
    /// Distinct direct inputs `k` of the Annotation CPN1.
    pub inputs: u64,
    /// Recorded nodes: the Annotation CPN1.
    pub nodes: u64,
    /// Recorded edges: one per direct input.
    pub edges: u64,
    /// Plaintext record bytes: the CAT1 and the Annotation CPN1.
    pub bytes: u64,
    /// ARD1 rows and trace objects: the CAT1 and the Annotation CPN1.
    pub rows: u64,
}

/// The staged CAT1 and Annotation CPN1 of one invocation's included items.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityAnnotationRecordsV1 {
    charge: CommunityAnnotationChargeV1,
    manifest_digest: Hash,
    node: CommunityNativeNodeReferenceV1,
}

impl CommunityAnnotationRecordsV1 {
    /// Stage the records of `items`, or none for no item.
    ///
    /// The node's inputs are the distinct union of the invocation's step and
    /// every item's resolved inputs, keyed by the digest of the encoded typed
    /// reference (R15.6(1)).
    ///
    /// # Errors
    /// Returns `BoundsExceeded` for more than 256 distinct inputs, and the
    /// CAT1 and CPN1 construction errors: `BoundsExceeded` for a CAT1 over
    /// its item, byte or claim bounds, and `InvalidBinding` for a decreasing
    /// guest index, a zero link, a native input that does not precede the
    /// node, or two native inputs of one coordinate.
    pub fn stage(
        context: &CommunityAnnotationContextV1,
        items: &[CommunityAnnotationCandidateV1<'_>],
    ) -> Result<Option<Self>> {
        if items.is_empty() {
            return Ok(None);
        }
        let references = distinct_inputs(context, items);
        if references.len() > MAX_COMMUNITY_DIRECT_INPUTS_V1 {
            return Err(Error::BoundsExceeded);
        }
        let digests: Vec<Vec<Hash>> = items.iter().map(resolved_digests).collect();
        manifest(context, items, &digests).and_then(|manifest| {
            let manifest_digest = manifest.digest();
            node(context, manifest_digest, &references).map(|(node, node_len)| {
                let inputs = references.len() as u64;
                Some(Self {
                    charge: CommunityAnnotationChargeV1 {
                        inputs,
                        nodes: 1,
                        edges: inputs,
                        bytes: (manifest.to_canonical_cbor().len() + node_len) as u64,
                        rows: 2,
                    },
                    manifest_digest,
                    node,
                })
            })
        })
    }

    /// What the records add to the cumulative counters.
    #[must_use]
    pub const fn charge(&self) -> CommunityAnnotationChargeV1 {
        self.charge
    }

    /// The CAT1 identity, CPS1's `annotation_manifest_digest`.
    #[must_use]
    pub const fn manifest_digest(&self) -> Hash {
        self.manifest_digest
    }

    /// The Annotation CPN1 reference, whose digest is CPD1's
    /// `PresentationTrace` root.
    #[must_use]
    pub const fn node(&self) -> CommunityNativeNodeReferenceV1 {
        self.node
    }
}

/// The step and every item's inputs, once each, in canonical input order.
fn distinct_inputs<'a>(
    context: &CommunityAnnotationContextV1,
    items: &[CommunityAnnotationCandidateV1<'a>],
) -> Vec<CommunityTypedInputRefV1<'a>> {
    let step = CommunityTypedInputRefV1::Native(context.step);
    let mut distinct = BTreeMap::new();
    distinct.insert(step.digest(), step);
    items
        .iter()
        .flat_map(|item| item.inputs.iter().copied())
        .for_each(|reference| {
            distinct.insert(reference.digest(), reference);
        });
    let mut references: Vec<_> = distinct.into_values().collect();
    references.sort_by_cached_key(canonical_key);
    references
}

/// The order key of a typed reference: its encoding after the array head.
fn canonical_key(reference: &CommunityTypedInputRefV1<'_>) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(reference.encoded_len());
    reference.encode(&mut encoded);
    encoded.split_off(1)
}

/// An item's resolved input digests, strictly ascending.
fn resolved_digests(item: &CommunityAnnotationCandidateV1<'_>) -> Vec<Hash> {
    let mut row: Vec<Hash> = item
        .inputs
        .iter()
        .map(|reference| reference.digest())
        .collect();
    row.sort_unstable();
    row.dedup();
    row
}

fn manifest<'a>(
    context: &CommunityAnnotationContextV1,
    items: &'a [CommunityAnnotationCandidateV1<'a>],
    digests: &'a [Vec<Hash>],
) -> Result<CommunityAnnotationManifestV1<'a>> {
    CommunityAnnotationManifestV1::new(CommunityAnnotationManifestInputV1 {
        pass_key: context.pass_key,
        member_binding_digest: context.member_binding_digest,
        invocation_step_digest: context.invocation_step_digest,
        items: items
            .iter()
            .zip(digests)
            .map(|(item, row)| CommunityAnnotationItemV1 {
                guest_index: item.guest_index,
                claim_bytes: item.claim_bytes,
                resolved_input_digests: CommunityDigestListV1::from_digests(row),
            })
            .collect(),
        evidence_not_after_micros: context.evidence_not_after_micros,
    })
}

/// The Annotation CPN1 over the CAT1 and its plaintext length.
fn node(
    context: &CommunityAnnotationContextV1,
    manifest_digest: Hash,
    references: &[CommunityTypedInputRefV1<'_>],
) -> Result<(CommunityNativeNodeReferenceV1, usize)> {
    CommunityNativeNodeV1::new(CommunityNativeNodeInputV1 {
        store_incarnation: context.step.store_incarnation,
        timeline: context.pass_key.timeline(),
        generation: context.pass_key.generation(),
        producer_ordinal: context.producer_ordinal,
        node_ordinal: context.node_ordinal,
        kind: CommunityNativeNodeKindV1::Annotation,
        content: CommunityContentReferenceV1 {
            record_magic: *b"CAT1",
            logical_digest: manifest_digest,
        },
        dependency_class: RecordedDependencyClassV1::PresentationOnly,
        input_index: CommunityInputIndexV1::Direct(CommunityTypedInputRefsV1::from_references(
            references,
        )),
        scope_binding_digest: context.scope_binding_digest,
        authorization_digest: context.authorization_digest,
        provenance_digest: context.provenance_digest,
        evidence_not_after_micros: context.evidence_not_after_micros,
    })
    .map(|node| (node.reference(), node.to_canonical_cbor().len()))
}
