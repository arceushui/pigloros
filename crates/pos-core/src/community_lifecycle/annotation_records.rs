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
    validate_horizon, CommunityAnnotationItemV1, CommunityAnnotationManifestInputV1,
    CommunityAnnotationManifestV1, CommunityContentReferenceV1, CommunityDigestListV1,
    CommunityGraphCountsV1, CommunityInputIndexV1, CommunityLifecycleErrorV1 as Error,
    CommunityNativeNodeInputV1, CommunityNativeNodeKindV1, CommunityNativeNodeReferenceV1,
    CommunityNativeNodeV1, CommunityPassGraphTermsV1, CommunityPassKeyV1,
    CommunityProtectionSizesV1, CommunityTypedInputRefV1, CommunityTypedInputRefsV1, Result,
    MAX_COMMUNITY_ANNOTATION_GUEST_INDEX_V1, MAX_COMMUNITY_DIRECT_INPUTS_V1,
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
    /// The invocation's `InvocationStep` CPN1. The Annotation CPN1 takes it
    /// as one of its direct inputs, and its store incarnation is the node's.
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
    graph: CommunityPassGraphTermsV1,
}

impl CommunityAnnotationRecordsV1 {
    /// Stage the records of `items`, or none for no item.
    ///
    /// The node's inputs are the distinct union of the invocation's step and
    /// every item's resolved inputs, keyed by the digest of the encoded typed
    /// reference (R15.6(1)).
    ///
    /// # Errors
    /// Returns `InvalidBinding` for a defect of the trusted input: an invalid
    /// horizon, a guest index over 63 or below the previous item's, a zero
    /// link, a native input that does not precede the node, or two native
    /// inputs of one coordinate. These are checked before any bound, so a
    /// defect is never mistaken for a budget misfit.
    ///
    /// Returns `BoundsExceeded` only for a budget: more than 256 distinct
    /// inputs, more than 1,024 items, over 1 MiB of claim bytes or a CAT1
    /// over 2 MiB.
    pub fn stage(
        context: &CommunityAnnotationContextV1,
        items: &[CommunityAnnotationCandidateV1<'_>],
    ) -> Result<Option<Self>> {
        if items.is_empty() {
            return Ok(None);
        }
        validate(context, items)?;
        let references = distinct_inputs(context, items);
        if references.len() > MAX_COMMUNITY_DIRECT_INPUTS_V1 {
            return Err(Error::BoundsExceeded);
        }
        let digests: Vec<Vec<Hash>> = items.iter().map(resolved_digests).collect();
        manifest(context, items, &digests).and_then(|manifest| {
            let (manifest_digest, manifest_len) = manifest.identity();
            node(context, manifest_digest, &references).and_then(|(node, node_len)| {
                CommunityProtectionSizesV1::new(
                    context.pass_key.timeline(),
                    context.pass_key.generation(),
                )
                .map(|sizes| {
                    let inputs = references.len() as u64;
                    Some(Self {
                        charge: CommunityAnnotationChargeV1 {
                            inputs,
                            nodes: 1,
                            edges: inputs,
                            bytes: (manifest_len + node_len) as u64,
                            rows: 2,
                        },
                        manifest_digest,
                        node,
                        graph: trace_graph(&sizes, manifest_len, node_len, &references),
                    })
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

    /// What the two records add to an ARD1 closure (R15.6(6)): the CAT1 with
    /// no child, the Annotation CPN1 with its CAT1, its step and its other
    /// mode-0 and mode-2 inputs, and the trace cohort's key.
    #[must_use]
    pub const fn graph(&self) -> CommunityPassGraphTermsV1 {
        self.graph
    }

    /// Whether the closure of the two records on top of `selected` stays
    /// within every graph maximum. The Annotation CPN1 is one level above its
    /// step, which is at most as deep as the selected graph.
    #[must_use]
    pub fn fits_graph(&self, selected: CommunityGraphCountsV1) -> bool {
        CommunityGraphCountsV1 {
            registrations: selected
                .registrations
                .saturating_add(self.graph.registrations),
            edges: selected.edges.saturating_add(self.graph.edges),
            keys: selected.keys.saturating_add(self.graph.keys),
            maximum_depth: selected.maximum_depth.saturating_add(1),
            registration_bytes: selected
                .registration_bytes
                .saturating_add(self.graph.registration_bytes),
            artifact_bytes: selected
                .artifact_bytes
                .saturating_add(self.graph.artifact_bytes),
        }
        .within_maxima()
        .is_ok()
    }
}

/// The trace closure's additions: the CAT1 has no ARD1 child, and the node's
/// children are its CAT1, its step and its other registered inputs.
fn trace_graph(
    sizes: &CommunityProtectionSizesV1,
    manifest_len: usize,
    node_len: usize,
    references: &[CommunityTypedInputRefV1<'_>],
) -> CommunityPassGraphTermsV1 {
    let registered = references
        .iter()
        .filter(|reference| {
            matches!(
                reference,
                CommunityTypedInputRefV1::Native(_) | CommunityTypedInputRefV1::Artifact { .. }
            )
        })
        .count() as u64;
    // The step is one registered input and one child already.
    sizes
        .record(manifest_len as u64, 0)
        .plus(sizes.record(node_len as u64, 1 + registered))
        .plus(CommunityPassGraphTermsV1 {
            keys: 1,
            ..CommunityPassGraphTermsV1::default()
        })
}

/// The trusted input's own defects: the horizon and the guest indices, which
/// are never a budget.
fn validate(
    context: &CommunityAnnotationContextV1,
    items: &[CommunityAnnotationCandidateV1<'_>],
) -> Result<()> {
    validate_horizon(context.evidence_not_after_micros)
        .map_err(|_| Error::InvalidBinding)
        .and_then(|()| {
            items
                .iter()
                .try_fold(0, |floor, item| {
                    if item.guest_index > MAX_COMMUNITY_ANNOTATION_GUEST_INDEX_V1
                        || item.guest_index < floor
                    {
                        Err(Error::InvalidBinding)
                    } else {
                        Ok(item.guest_index)
                    }
                })
                .map(drop)
        })
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
