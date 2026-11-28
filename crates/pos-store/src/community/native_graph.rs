//! ADR-129 §2/§4 native-graph assembly of one code-0 initialization.
//!
//! The installed owner mints every record of a new generation's initial
//! graph from the admitted CGI1, CDP1, CMB1s and catalogue initializer
//! State (ADR-129 revision 6, R6.1), in the annex §2 digest order:
//!
//! - per member, in roster order: CSC1, CIS1, CSR1, the `InitialState` and
//!   `StateRevision` CPN1s, each protected as a COW1 with its unpublished ARD1;
//! - per member, its initial CMS1;
//! - the initial CST1, the CSH1 that selects them, the CGR1 root and CGA1.
//!
//! The graph shape follows the owner decisions on #560, note 22661, which
//! fill the ADR-129 gaps for initialization (items 1 to 6; the item-7 CMI1
//! builder lands with its first caller, the 2c commit). Nothing here
//! publishes a registration, commits a record or selects a head: the
//! community extractor and the atomic commit do that (#560 A3c-2b′-2, 2c).

use std::collections::BTreeSet;

use pos_core::community_lifecycle::{
    community_initializer_set_ref_v1, CommunityArtifactKindV1, CommunityArtifactOperationV1,
    CommunityArtifactPurposeV1, CommunityCarriedEventsV1, CommunityContentReferenceV1,
    CommunityDurableProfileV1, CommunityGenerationAdmissionInputV1, CommunityGenerationAdmissionV1,
    CommunityGraphCountsV1, CommunityGraphRootInputV1, CommunityGraphRootV1,
    CommunityHostProgressV1, CommunityInitializationProducerInputV1,
    CommunityInitializationProducerV1, CommunityInitializationRequestV1,
    CommunityInitializationSourceV1, CommunityInputIndexV1, CommunityLifecycleErrorV1 as Error,
    CommunityLocatorProducerV1, CommunityMemberBindingV1, CommunityMemberHeadV1,
    CommunityMemberHeadsV1, CommunityMemberProgressInputV1, CommunityMemberProgressV1,
    CommunityMetadataLocatorV1, CommunityMetadataSchemaV1, CommunityNativeNodeInputV1,
    CommunityNativeNodeKindV1, CommunityNativeNodeReferenceV1, CommunityNativeNodeReferencesV1,
    CommunityNativeNodeV1, CommunityPassFrontierV1, CommunityProgressReferenceV1,
    CommunitySelectedHeadInputV1, CommunitySelectedHeadV1, CommunityStateProducerV1,
    CommunityStateRevisionInputV1, CommunityStateRevisionV1, CommunityTypedInputRefV1,
    CommunityTypedInputRefsV1,
};
use pos_core::community_lifecycle::{
    CommunityMaterializationInputV1, CommunityMaterializationReferenceV1,
    CommunityMaterializationV1, CommunityProducerBindingV1,
};
use pos_core::{
    ArtifactChildEdgeV1, AuthorityTrustRootSealV1, Hash, RecordedDependencyClassV1, Seq, TimelineId,
};
use zeroize::Zeroizing;

use super::initializer::CommunityInitializerOwnerV1;
use super::private_hash::private_digest;
use super::protection::{
    CommunityArtifactProtectorV1, CommunityProtectedRecordV1, CommunityRecordEvidenceV1,
};

/// The variant-3 `record_role` of a CMB1: its index in the ADR-129 §3
/// metadata whitelist (owner decision on #560, note 22661, item 1).
const CMB1_RECORD_ROLE: u16 = 11;

/// The record kinds an initialization's `ExecutionState` key must allow.
const INITIAL_KINDS: [CommunityArtifactKindV1; 3] = [
    CommunityArtifactKindV1::StateContent,
    CommunityArtifactKindV1::StateRevisionOrHead,
    CommunityArtifactKindV1::ExecutionProvenance,
];

/// One roster member of the initialization.
#[derive(Clone, Copy)]
pub struct CommunityInitializationMemberV1<'a> {
    /// The member's admitted CMB1.
    pub binding: &'a CommunityMemberBindingV1<'a>,
    /// Physical address of the CNE1 that holds that CMB1, which the
    /// member's `InitialState` CPN1 cites (R6.1(6)).
    pub binding_envelope_address: Hash,
}

/// The admitted facts one initialization graph is minted from.
#[derive(Clone, Copy)]
pub struct CommunityInitializationGraphInputV1<'a> {
    /// The protected store incarnation.
    pub store_incarnation: [u8; 16],
    /// The native producer ordinal the initialization allocated under its
    /// control ID (ADR-129 §4).
    pub producer_ordinal: u64,
    /// The admitted code-0 CGI1.
    pub request: &'a CommunityInitializationRequestV1<'a>,
    /// The CDP1 the request names.
    pub profile: &'a CommunityDurableProfileV1<'a>,
    /// One entry per roster row, in roster order; the index is the slot.
    pub members: &'a [CommunityInitializationMemberV1<'a>],
    /// The COB1 owner-binding commitment.
    pub owner_binding_digest: Hash,
    /// The CPV1 original-provenance commitment.
    pub host_provenance_digest: Hash,
    /// The Timeline's existing Event logical head, for CSH1.
    pub event_logical_head: Seq,
}

/// Coordinates shared by every record of one initialization.
#[derive(Clone, Copy)]
struct Context {
    store_incarnation: [u8; 16],
    timeline: TimelineId,
    generation: [u8; 16],
    request_digest: Hash,
    scope_binding_digest: Hash,
    evidence_not_after_micros: u64,
}

/// One protected logical record of the graph.
pub struct CommunityAssembledRecordV1 {
    record_magic: [u8; 4],
    logical_digest: Hash,
    plaintext_length: u64,
    producer: CommunityProducerBindingV1,
    height: u64,
    protected: CommunityProtectedRecordV1,
}

impl CommunityAssembledRecordV1 {
    /// The record's plaintext length, the encoded size the CBQ1 counts.
    #[cfg(target_os = "linux")]
    pub(super) const fn plaintext_length(&self) -> u64 {
        self.plaintext_length
    }

    /// The owning record's four-byte magic.
    #[must_use]
    pub const fn record_magic(&self) -> [u8; 4] {
        self.record_magic
    }

    /// Its COW1 and unpublished ARD1.
    #[must_use]
    pub const fn protected(&self) -> &CommunityProtectedRecordV1 {
        &self.protected
    }

    /// This record's CMI1 (ADR-129 §4; owner decision on #560, note 22661,
    /// item 7), with the COA1 address its caller derived.
    ///
    /// It covers the COW1 families only. Its logical identity is the owning
    /// record's `H(M, record)`, and its producer binding is the native node
    /// that produced it (CIS1: the `InitialState` node; CSC1 and CSR1: the
    /// `StateRevision` node) or, for each CPN1, the initialization's control
    /// request `H(CGI1)`. Scope and horizon are the protected record's.
    pub(super) fn materialization(
        &self,
        store_incarnation: [u8; 16],
        timeline: TimelineId,
        generation: [u8; 16],
        attestation_address: Hash,
    ) -> Result<CommunityMaterializationV1, Error> {
        let registration = self.protected.registration();
        CommunityMaterializationV1::new(CommunityMaterializationInputV1 {
            store_incarnation,
            timeline,
            generation,
            record_magic: self.record_magic,
            logical_record_digest: self.logical_digest,
            plaintext_length: self.plaintext_length,
            materialization: CommunityMaterializationReferenceV1 {
                owner_reference: registration.fields().owner_reference,
                artifact_class: registration.fields().artifact_class,
                object_address: self.protected.object_address(),
                artifact_digest: registration.fields().artifact_digest,
                registration_address: registration.address(),
                attestation_address,
            },
            producer: self.producer,
            scope_binding_digest: self.protected.scope_cover_digest(),
            evidence_not_after_micros: self.protected.evidence_not_after_micros(),
        })
    }

    /// The exact required ARD1 child edge naming this record.
    const fn child_edge(&self) -> ArtifactChildEdgeV1 {
        let registration = self.protected.registration();
        ArtifactChildEdgeV1 {
            artifact_class: registration.fields().artifact_class,
            artifact_digest: registration.fields().artifact_digest,
            registration_address: registration.address(),
            required: true,
        }
    }
}

/// The complete initial graph of one generation, ready for the extractor.
pub struct CommunityInitializationGraphV1 {
    request_digest: Hash,
    records: Vec<CommunityAssembledRecordV1>,
    member_progress: Vec<Zeroizing<Vec<u8>>>,
    host_progress: Vec<u8>,
    selected_head: Zeroizing<Vec<u8>>,
    selected_head_digest: Hash,
    graph_root: Zeroizing<Vec<u8>>,
    #[cfg(target_os = "linux")]
    graph_counts: CommunityGraphCountsV1,
    /// Each member's CMB1 digest, in slot (roster) order.
    #[cfg(target_os = "linux")]
    member_bindings: Vec<Hash>,
    generation_admission: Zeroizing<Vec<u8>>,
}

/// One record to protect: its kind, plaintext, magic, the indices of its
/// earlier ARD1 children, its logical identity and its producer binding.
struct Step<'p> {
    kind: CommunityArtifactKindV1,
    plaintext: &'p [u8],
    record_magic: [u8; 4],
    children: &'static [usize],
    logical_digest: Hash,
    producer: CommunityProducerBindingV1,
}

/// One member's plaintext records, minted before any encryption.
struct MemberPlan<'a> {
    state: &'a [u8],
    state_digest: Hash,
    producer: Zeroizing<Vec<u8>>,
    producer_digest: Hash,
    revision: Zeroizing<Vec<u8>>,
    revision_digest: Hash,
    initial_node: Zeroizing<Vec<u8>>,
    initial_reference: CommunityNativeNodeReferenceV1,
    revision_node: Zeroizing<Vec<u8>>,
    revision_reference: CommunityNativeNodeReferenceV1,
    member_binding_digest: Hash,
}

impl CommunityInitializationGraphV1 {
    /// Mint the initial graph of `input` and protect each COW1 record with
    /// `protector`, the initialization's one `ExecutionState` cohort.
    ///
    /// Every input check and every plaintext record is built before the
    /// first encryption, so a refused graph burns no credit.
    ///
    /// Only the trusted composition root, which holds the
    /// [`AuthorityTrustRootSealV1`], assembles a graph:
    ///
    /// ```compile_fail,E0061
    /// use pos_store::community::{
    ///     CommunityArtifactProtectorV1, CommunityInitializationGraphInputV1,
    ///     CommunityInitializationGraphV1, CommunityInitializerOwnerV1,
    /// };
    /// fn forge(
    ///     input: CommunityInitializationGraphInputV1<'_>,
    ///     owner: &CommunityInitializerOwnerV1,
    ///     protector: &mut CommunityArtifactProtectorV1,
    /// ) {
    ///     let _ = CommunityInitializationGraphV1::assemble(input, owner, protector);
    /// }
    /// ```
    ///
    /// # Errors
    /// Returns `InvalidBinding` when the request is not a code-0
    /// initialization of this CDP1 with its R6.1(7) initializer set; the
    /// members, roster and CGI1 list differ in length or order; a CMB1's
    /// initializer State or COB1 differs from its row or input, or the
    /// installed owner does not hold that State; the protector's cohort is
    /// not this initialization's `ExecutionState` cohort over every slot with
    /// the needed record kinds and a horizon within the request's; or a
    /// commitment, envelope address or producer ordinal is zero. Returns
    /// `CapacityExhausted` once the protector's credits are spent.
    pub fn assemble(
        _seal: &'static AuthorityTrustRootSealV1,
        input: CommunityInitializationGraphInputV1<'_>,
        initializer: &CommunityInitializerOwnerV1,
        protector: &mut CommunityArtifactProtectorV1,
    ) -> Result<Self, Error> {
        check_input(&input, initializer, protector).and_then(|context| {
            input
                .members
                .iter()
                .zip(0_u16..)
                .map(|(member, slot)| plan_member(&input, context, slot, member, initializer))
                .collect::<Result<Vec<_>, Error>>()
                .and_then(|plans| {
                    plans
                        .iter()
                        .map(|plan| protect_member(plan, &input, context.request_digest, protector))
                        .collect::<Result<Vec<_>, Error>>()
                        .and_then(|members| finish(&input, context, &plans, members))
                })
        })
    }

    /// `H(CGI1)` of the request this graph was minted from.
    #[must_use]
    pub const fn request_digest(&self) -> Hash {
        self.request_digest
    }

    /// The index in [`Self::records`] of the CSR1 of the member whose CMB1
    /// digest is `member_binding`: the CSR1 of its slot.
    #[cfg(target_os = "linux")]
    pub(super) fn state_revision_index(&self, member_binding: Hash) -> Option<usize> {
        let magics: Vec<[u8; 4]> = self
            .records
            .iter()
            .map(|record| record.record_magic)
            .collect();
        state_revision_slot(&self.member_bindings, &magics, member_binding)
    }

    /// Every protected record: per slot, CSC1, CIS1, CSR1 and the
    /// `InitialState` and `StateRevision` CPN1s.
    #[must_use]
    pub fn records(&self) -> &[CommunityAssembledRecordV1] {
        &self.records
    }

    /// Each member's canonical initial CMS1, in slot order.
    #[must_use]
    pub fn member_progress(&self) -> impl ExactSizeIterator<Item = &[u8]> + '_ {
        self.member_progress.iter().map(|record| record.as_slice())
    }

    /// The canonical initial CST1.
    #[must_use]
    pub fn host_progress(&self) -> &[u8] {
        &self.host_progress
    }

    /// The canonical CSH1 that selects the initial generation.
    #[must_use]
    pub fn selected_head(&self) -> &[u8] {
        &self.selected_head
    }

    /// `H(CSH1)`, the selection a CSI1 row names.
    #[must_use]
    pub const fn selected_head_digest(&self) -> Hash {
        self.selected_head_digest
    }

    /// The canonical CGR1 execution root.
    #[must_use]
    pub fn graph_root(&self) -> &[u8] {
        &self.graph_root
    }

    /// The CGR1 `graph_counts`: the selected closure of the initial
    /// frontier (ADR-129 revision 11, R11.3(1)).
    #[cfg(target_os = "linux")]
    pub(super) const fn graph_counts(&self) -> CommunityGraphCountsV1 {
        self.graph_counts
    }

    /// The canonical CGA1 original generation result.
    #[must_use]
    pub fn generation_admission(&self) -> &[u8] {
        &self.generation_admission
    }
}

/// Check every fact the graph depends on, before any plaintext is built.
fn check_input(
    input: &CommunityInitializationGraphInputV1<'_>,
    initializer: &CommunityInitializerOwnerV1,
    protector: &CommunityArtifactProtectorV1,
) -> Result<Context, Error> {
    let request = input.request.as_input();
    let profile = input.profile.as_input();
    let roster = profile.roster;
    let cohort = protector.cohort();
    let listed: Vec<Hash> = request.member_binding_digests.iter().collect();
    let slots: Vec<u16> = cohort.member_slots.iter().collect();
    let code_zero = matches!(
        request.initial_source,
        CommunityInitializationSourceV1::Initializer(reference)
            if reference == community_initializer_set_ref_v1(input.profile)
    );
    let members_match = input.members.len() == roster.len()
        && listed.len() == roster.len()
        && input
            .members
            .iter()
            .zip(roster)
            .zip(&listed)
            .all(|((member, row), listed)| {
                let binding = member.binding.as_input();
                let state = Hash::from_bytes(row.initializer().digest);
                member.binding.digest() == *listed
                    && binding.stable_entry == row.stable_entry()
                    && binding.initial_state_content_digest == state
                    && binding.protected_owner_binding_digest == input.owner_binding_digest
                    && initializer.state(state).is_some()
                    && member.binding_envelope_address != Hash::zero()
            });
    let cohort_match = cohort.parent_operation
        == CommunityArtifactOperationV1::Initialization(request.operation_id)
        && cohort.timeline == request.timeline
        && cohort.generation == request.generation
        && cohort.purpose == CommunityArtifactPurposeV1::ExecutionState
        && INITIAL_KINDS
            .iter()
            .all(|kind| cohort.allowed_record_kinds.contains(*kind))
        && slots.len() == roster.len()
        && slots
            .iter()
            .enumerate()
            .all(|(index, slot)| usize::from(*slot) == index)
        && cohort.evidence_not_after_micros <= request.evidence_not_after_micros;
    let valid = code_zero
        && request.profile_digest == input.profile.digest()
        && initializer.catalogue_digest() == profile.authority_catalogue_digest
        && members_match
        && cohort_match
        && input.owner_binding_digest != Hash::zero()
        && input.host_provenance_digest != Hash::zero()
        && input.producer_ordinal != 0;
    if valid {
        Ok(Context {
            store_incarnation: input.store_incarnation,
            timeline: request.timeline,
            generation: request.generation,
            request_digest: input.request.digest(),
            scope_binding_digest: cohort.scope_cover_digest,
            evidence_not_after_micros: cohort.evidence_not_after_micros,
        })
    } else {
        Err(Error::InvalidBinding)
    }
}

/// Mint one member's CIS1, CSR1 and two CPN1s (note 22661, items 2 and 3).
///
/// `check_input` already proved every link these records need, so no codec
/// refusal below is reachable from a checked input.
fn plan_member<'a>(
    input: &CommunityInitializationGraphInputV1<'_>,
    context: Context,
    slot: u16,
    member: &CommunityInitializationMemberV1<'_>,
    initializer: &'a CommunityInitializerOwnerV1,
) -> Result<MemberPlan<'a>, Error> {
    let request = input.request.as_input();
    let binding = member.binding.as_input();
    let member_binding_digest = member.binding.digest();
    let state_digest = binding.initial_state_content_digest;
    let row = &input.profile.as_input().roster[usize::from(slot)];
    let producer_input = CommunityInitializationProducerInputV1 {
        generation_request_digest: context.request_digest,
        member_binding_digest,
        initializer_ref: row.initializer(),
        state_content_digest: state_digest,
        scope_binding_digest: context.scope_binding_digest,
        evidence_not_after_micros: context.evidence_not_after_micros,
    };
    let revision_input = |producer_digest: Hash| CommunityStateRevisionInputV1 {
        producer_origin: CommunityStateProducerV1::Initialization {
            generation_request_digest: context.request_digest,
            operation_id: request.operation_id,
        },
        member_binding_digest,
        predecessor_revision_digest: None,
        state_content_digest: state_digest,
        producer_digest,
        protected_owner_binding_digest: binding.protected_owner_binding_digest,
        evidence_not_after_micros: context.evidence_not_after_micros,
    };
    let cmb1 = [member_binding_ref(
        context.timeline,
        context.generation,
        request.operation_id,
        slot,
        member.binding_envelope_address,
        member_binding_digest,
    )];
    let initial_kind = (u32::from(slot) * 2, CommunityNativeNodeKindV1::InitialState);
    let revision_kind = (
        u32::from(slot) * 2 + 1,
        CommunityNativeNodeKindV1::StateRevision,
    );
    let plan = |state: &'a [u8], producer: CommunityInitializationProducerV1| {
        let producer_digest = producer.digest();
        CommunityStateRevisionV1::new(revision_input(producer_digest)).and_then(|revision| {
            let revision = revision.to_canonical_cbor();
            let revision_digest = record_digest(b"PiglorOS.Community.CSR1.v1", &revision);
            let producer_content = content(*b"CIS1", producer_digest);
            node(
                input,
                context,
                initial_kind,
                producer_content,
                direct(&cmb1),
            )
            .and_then(|(initial_node, initial_reference)| {
                let initial = [CommunityTypedInputRefV1::Native(initial_reference)];
                let revision_content = content(*b"CSR1", revision_digest);
                node(
                    input,
                    context,
                    revision_kind,
                    revision_content,
                    direct(&initial),
                )
                .map(|(revision_node, revision_reference)| MemberPlan {
                    state,
                    state_digest,
                    producer: producer.to_canonical_cbor(),
                    producer_digest,
                    revision,
                    revision_digest,
                    initial_node,
                    initial_reference,
                    revision_node,
                    revision_reference,
                    member_binding_digest,
                })
            })
        })
    };
    initializer
        .state(state_digest)
        .ok_or(Error::InvalidBinding)
        .and_then(|state| {
            CommunityInitializationProducerV1::new(producer_input)
                .and_then(|producer| plan(state, producer))
        })
}

/// The variant-3 typed ref of slot `slot`'s CMB1 in its initialization
/// (R6.1(6); owner decision on #560, note 22661, item 1): the locator names
/// the initialization's control ID, the CMB1 whitelist index and the slot.
pub(super) const fn member_binding_ref<'a>(
    timeline: TimelineId,
    generation: [u8; 16],
    operation_id: [u8; 16],
    slot: u16,
    envelope_address: Hash,
    member_binding_digest: Hash,
) -> CommunityTypedInputRefV1<'a> {
    CommunityTypedInputRefV1::Metadata {
        schema: CommunityMetadataSchemaV1::Cmb1,
        locator: CommunityMetadataLocatorV1 {
            timeline,
            generation,
            producer: CommunityLocatorProducerV1::Control(operation_id),
            record_role: CMB1_RECORD_ROLE,
            slot,
        },
        envelope_address,
        private_record_digest: member_binding_digest,
    }
}

const fn content(record_magic: [u8; 4], logical_digest: Hash) -> CommunityContentReferenceV1 {
    CommunityContentReferenceV1 {
        record_magic,
        logical_digest,
    }
}

const fn direct<'a>(references: &'a [CommunityTypedInputRefV1<'a>]) -> CommunityInputIndexV1<'a> {
    CommunityInputIndexV1::Direct(CommunityTypedInputRefsV1::from_references(references))
}

/// One CPN1 of the initialization's producer (note 22661, items 2 and 3):
/// scope is the CSB1 commitment, authorization the CGI1 `authorization_ref`
/// and provenance the CPV1 commitment.
fn node(
    input: &CommunityInitializationGraphInputV1<'_>,
    context: Context,
    (node_ordinal, kind): (u32, CommunityNativeNodeKindV1),
    logical: CommunityContentReferenceV1,
    input_index: CommunityInputIndexV1<'_>,
) -> Result<(Zeroizing<Vec<u8>>, CommunityNativeNodeReferenceV1), Error> {
    CommunityNativeNodeV1::new(CommunityNativeNodeInputV1 {
        store_incarnation: context.store_incarnation,
        timeline: context.timeline,
        generation: context.generation,
        producer_ordinal: input.producer_ordinal,
        node_ordinal,
        kind,
        content: logical,
        dependency_class: RecordedDependencyClassV1::EndogenousRecomputed,
        input_index,
        scope_binding_digest: context.scope_binding_digest,
        authorization_digest: Hash::from_bytes(input.request.as_input().authorization_ref.digest),
        provenance_digest: input.host_provenance_digest,
        evidence_not_after_micros: context.evidence_not_after_micros,
    })
    .map(|node| (node.to_canonical_cbor(), node.reference()))
}

/// Protect one member's five records in dependency order, with the ARD1
/// children of note 22661, item 4, all required.
fn protect_member(
    plan: &MemberPlan<'_>,
    input: &CommunityInitializationGraphInputV1<'_>,
    request_digest: Hash,
    protector: &mut CommunityArtifactProtectorV1,
) -> Result<Vec<CommunityAssembledRecordV1>, Error> {
    let initial = CommunityProducerBindingV1::Native(plan.initial_reference);
    let revision = CommunityProducerBindingV1::Native(plan.revision_reference);
    let control = CommunityProducerBindingV1::Control(request_digest);
    let steps: [Step<'_>; 5] = [
        // CSC1 and CIS1 have no children.
        Step {
            kind: CommunityArtifactKindV1::StateContent,
            plaintext: plan.state,
            record_magic: *b"CSC1",
            children: &[],
            logical_digest: plan.state_digest,
            producer: revision,
        },
        Step {
            kind: CommunityArtifactKindV1::ExecutionProvenance,
            plaintext: plan.producer.as_slice(),
            record_magic: *b"CIS1",
            children: &[],
            logical_digest: plan.producer_digest,
            producer: initial,
        },
        // CSR1 -> CSC1, CIS1.
        Step {
            kind: CommunityArtifactKindV1::StateRevisionOrHead,
            plaintext: plan.revision.as_slice(),
            record_magic: *b"CSR1",
            children: &[0, 1],
            logical_digest: plan.revision_digest,
            producer: revision,
        },
        // `InitialState` CPN1 -> CIS1.
        Step {
            kind: CommunityArtifactKindV1::ExecutionProvenance,
            plaintext: plan.initial_node.as_slice(),
            record_magic: *b"CPN1",
            children: &[1],
            logical_digest: plan.initial_reference.node_digest,
            producer: control,
        },
        // `StateRevision` CPN1 -> CSR1, CSC1, `InitialState` CPN1.
        Step {
            kind: CommunityArtifactKindV1::ExecutionProvenance,
            plaintext: plan.revision_node.as_slice(),
            record_magic: *b"CPN1",
            children: &[2, 0, 3],
            logical_digest: plan.revision_reference.node_digest,
            producer: control,
        },
    ];
    steps.into_iter().try_fold(
        Vec::with_capacity(5),
        |mut records: Vec<CommunityAssembledRecordV1>, step: Step<'_>| {
            let children = step.children;
            let mut edges: Vec<ArtifactChildEdgeV1> = children
                .iter()
                .map(|child| records[*child].child_edge())
                .collect();
            edges.sort_by_key(|edge| {
                (
                    edge.artifact_class,
                    edge.artifact_digest,
                    edge.registration_address,
                )
            });
            let height = 1 + children
                .iter()
                .map(|child| records[*child].height)
                .max()
                .unwrap_or(0);
            protector
                .protect(
                    step.kind,
                    step.plaintext,
                    CommunityRecordEvidenceV1 {
                        owner_binding_digest: input.owner_binding_digest,
                        host_provenance_digest: input.host_provenance_digest,
                        children: &edges,
                    },
                )
                .map(|protected| {
                    records.push(CommunityAssembledRecordV1 {
                        record_magic: step.record_magic,
                        logical_digest: step.logical_digest,
                        plaintext_length: step.plaintext.len() as u64,
                        producer: step.producer,
                        height,
                        protected,
                    });
                    records
                })
        },
    )
}

/// A fresh member's CMS1: no step, nothing forwarded or carried, and no
/// step chain or history yet, as the registry registers a Driver.
fn initial_progress(plan: &MemberPlan<'_>) -> Result<Zeroizing<Vec<u8>>, Error> {
    CommunityMemberProgressV1::new(CommunityMemberProgressInputV1 {
        member_binding_digest: plan.member_binding_digest,
        state_revision_digest: plan.revision_digest,
        last_step_simulation_time: None,
        forwarded_cursor: Seq::ZERO,
        carried_events: CommunityCarriedEventsV1::from_events(&[]),
        step_chain: CommunityProgressReferenceV1::None,
        history_input: CommunityProgressReferenceV1::None,
    })
    .map(|progress| progress.to_canonical_cbor())
}

/// Mint the CMS1s, CST1, CSH1, CGR1 and CGA1 over the protected records.
fn finish(
    input: &CommunityInitializationGraphInputV1<'_>,
    context: Context,
    plans: &[MemberPlan<'_>],
    members: Vec<Vec<CommunityAssembledRecordV1>>,
) -> Result<CommunityInitializationGraphV1, Error> {
    let profile_digest = input.request.as_input().profile_digest;
    let records: Vec<CommunityAssembledRecordV1> = members.into_iter().flatten().collect();
    // Item 5: one `StateRevision` root per member. Slot order is native
    // order: every root shares the producer ordinal and node 2·slot+1
    // ascends with the slot.
    let roots: Vec<CommunityNativeNodeReferenceV1> =
        plans.iter().map(|plan| plan.revision_reference).collect();
    let graph_counts = counts(&records);
    plans
        .iter()
        .map(initial_progress)
        .collect::<Result<Vec<_>, Error>>()
        .and_then(|member_progress| {
            let mut heads: Vec<CommunityMemberHeadV1> = plans
                .iter()
                .zip(&member_progress)
                .map(|(plan, progress)| CommunityMemberHeadV1 {
                    member_binding_digest: plan.member_binding_digest,
                    member_progress_digest: record_digest(b"PiglorOS.Community.CMS1.v1", progress),
                })
                .collect();
            heads.sort_by_key(|head| head.member_binding_digest);
            CommunityHostProgressV1::new(context.timeline, context.generation, None, None)
                .and_then(|host| {
                    CommunitySelectedHeadV1::new(CommunitySelectedHeadInputV1 {
                        timeline: context.timeline,
                        generation: context.generation,
                        frontier: CommunityPassFrontierV1::Initial,
                        member_heads: CommunityMemberHeadsV1::from_members(&heads),
                        event_logical_head: input.event_logical_head,
                        profile_digest,
                        host_progress_digest: host.digest(),
                    })
                    .map(|head| (host, head.to_canonical_cbor()))
                })
                .and_then(|(host, selected_head)| {
                    let selected_head_digest =
                        record_digest(b"PiglorOS.Community.CSH1.v1", &selected_head);
                    CommunityGraphRootV1::new(CommunityGraphRootInputV1 {
                        store_incarnation: context.store_incarnation,
                        timeline: context.timeline,
                        generation: context.generation,
                        profile_digest,
                        selected_head_digest,
                        roots: CommunityNativeNodeReferencesV1::from_references(&roots),
                        graph_counts,
                        evidence_not_after_micros: context.evidence_not_after_micros,
                    })
                    .and_then(|graph_root| {
                        CommunityGenerationAdmissionV1::new(CommunityGenerationAdmissionInputV1 {
                            generation_request_digest: context.request_digest,
                            timeline: context.timeline,
                            generation: context.generation,
                            initial_selected_head_digest: selected_head_digest,
                            graph_root_ref: graph_root.digest(),
                            evidence_not_after_micros: context.evidence_not_after_micros,
                        })
                        .map(|admission| CommunityInitializationGraphV1 {
                            request_digest: context.request_digest,
                            records,
                            member_progress,
                            host_progress: host.to_canonical_cbor(),
                            selected_head,
                            selected_head_digest,
                            graph_root: graph_root.to_canonical_cbor(),
                            #[cfg(target_os = "linux")]
                            graph_counts,
                            #[cfg(target_os = "linux")]
                            member_bindings: plans
                                .iter()
                                .map(|plan| plan.member_binding_digest)
                                .collect(),
                            generation_admission: admission.to_canonical_cbor(),
                        })
                    })
                })
        })
}

/// The index of the CSR1 of the slot of `member_binding` among `magics`, the
/// record magics in graph order: `bindings` lists each slot's CMB1 digest,
/// and every slot has exactly one CSR1, in slot order.
#[cfg(target_os = "linux")]
fn state_revision_slot(
    bindings: &[Hash],
    magics: &[[u8; 4]],
    member_binding: Hash,
) -> Option<usize> {
    bindings
        .iter()
        .position(|digest| *digest == member_binding)
        .and_then(|slot| {
            magics
                .iter()
                .enumerate()
                .filter(|(_, magic)| **magic == *b"CSR1")
                .nth(slot)
                .map(|(index, _)| index)
        })
}

/// Item 6: exact ARD1-graph counts of the closure, which is every record.
/// Each registration counts once; edges, keys and bytes follow the existing
/// distinct-registration definitions, and depth counts the root as one.
fn counts(records: &[CommunityAssembledRecordV1]) -> CommunityGraphCountsV1 {
    let keys: BTreeSet<_> = records
        .iter()
        .flat_map(|record| &record.protected.registration().fields().key_dependencies)
        .map(|key| key.identity)
        .collect();
    let sum = |field: fn(&CommunityAssembledRecordV1) -> usize| {
        records.iter().map(field).sum::<usize>() as u64
    };
    CommunityGraphCountsV1 {
        registrations: records.len() as u64,
        edges: sum(|record| {
            record
                .protected
                .registration()
                .fields()
                .child_artifacts
                .len()
        }),
        keys: keys.len() as u64,
        maximum_depth: records
            .iter()
            .map(|record| record.height)
            .max()
            .unwrap_or(0),
        registration_bytes: sum(|record| record.protected.registration().canonical_cbor().len()),
        artifact_bytes: sum(|record| record.protected.object().len()),
    }
}

/// `H(M, record)` of a record whose portable codec withholds its digest.
fn record_digest(domain: &[u8], record: &[u8]) -> Hash {
    private_digest(domain, &[record])
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
