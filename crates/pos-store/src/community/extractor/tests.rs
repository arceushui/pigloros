//! Extractor refusals that need records no assembled graph contains: a
//! pass-produced CSR1, unsupported kinds and node forms, a foreign
//! generation, duplicate identities, unlisted children and a root that is
//! not a `StateRevision` node.
//!
//! Each forged record is protected under a real key, so it authenticates
//! and reaches the check it targets.

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
use ulid::Ulid;

use super::super::protection::{
    CommunityArtifactProtectorV1, CommunityProtectedRecordV1, CommunityProtectionCohortV1,
    CommunityRecordEvidenceV1,
};
use super::{
    prepare_community_artifact_batch_v1, CommunityArtifactBatchInputV1,
    CommunityArtifactRecordInputV1,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Fallible<T> = Result<T, Box<dyn std::error::Error>>;

const SEAL: AuthorityTrustRootSealV1 = AuthorityTrustRootSealV1::for_composition_root();
const INCARNATION: [u8; 16] = [0x5a; 16];
const GENERATION: [u8; 16] = [0x20; 16];
const HORIZON: u64 = 900;
const PROFILE: Hash = Hash::from_bytes([0x30; 32]);
const COB: Hash = Hash::from_bytes([0x40; 32]);
const CPV: Hash = Hash::from_bytes([0x41; 32]);
const SCOPE_COVER: Hash = Hash::from_bytes([0x42; 32]);

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
            parent_operation: Operation::Initialization([0x10; 16]),
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

fn protect(
    protector: &mut CommunityArtifactProtectorV1,
    kind: Kind,
    plaintext: &[u8],
    children: &[&CommunityProtectedRecordV1],
) -> Fallible<CommunityProtectedRecordV1> {
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
    Ok(protector.protect(
        kind,
        plaintext,
        CommunityRecordEvidenceV1 {
            owner_binding_digest: COB,
            host_provenance_digest: CPV,
            children: &edges,
        },
    )?)
}

/// A CSH1 and the CGR1 that selects it, with `roots`.
fn head_and_root(roots: &[CommunityNativeNodeReferenceV1]) -> Fallible<(Vec<u8>, Vec<u8>)> {
    let heads = [CommunityMemberHeadV1 {
        member_binding_digest: hash(1),
        member_progress_digest: hash(2),
    }];
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
        graph_counts: CommunityGraphCountsV1 {
            registrations: 2,
            edges: 1,
            keys: 1,
            maximum_depth: 2,
            registration_bytes: 1,
            artifact_bytes: 1,
        },
        evidence_not_after_micros: HORIZON,
    })?
    .to_canonical_cbor()
    .to_vec();
    Ok((head, root))
}

const ROOT: CommunityNativeNodeReferenceV1 = CommunityNativeNodeReferenceV1 {
    store_incarnation: INCARNATION,
    producer_ordinal: 1,
    node_ordinal: 1,
    node_digest: Hash::from_bytes([9; 32]),
};

fn prepare(
    records: &[&CommunityProtectedRecordV1],
    roots: &[CommunityNativeNodeReferenceV1],
    key: &CommunityArtifactProtectorV1,
) -> Fallible<Option<Error>> {
    let (head, root) = head_and_root(roots)?;
    let records: Vec<CommunityArtifactRecordInputV1<'_>> = records
        .iter()
        .map(|record| CommunityArtifactRecordInputV1 {
            object: record.object(),
            registration: record.registration(),
        })
        .collect();
    Ok(prepare_community_artifact_batch_v1(
        &SEAL,
        CommunityArtifactBatchInputV1 {
            store_incarnation: INCARNATION,
            profile_digest: PROFILE,
            records: &records,
            graph_root: &root,
            selected_head: &head,
            current_head: None,
            expected_prior_head: None,
        },
        &[key],
    )
    .err())
}

fn state(bytes: &[u8]) -> Fallible<Vec<u8>> {
    Ok(CommunityStateContentV1::new(hash(0x22), bytes)?
        .to_canonical_cbor()
        .to_vec())
}

fn producer(state: &[u8]) -> Fallible<CommunityInitializationProducerV1> {
    Ok(CommunityInitializationProducerV1::new(
        CommunityInitializationProducerInputV1 {
            generation_request_digest: hash(4),
            member_binding_digest: hash(5),
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

fn revision(origin: CommunityStateProducerV1, state: Hash, producer: Hash) -> Fallible<Vec<u8>> {
    Ok(
        CommunityStateRevisionV1::new(CommunityStateRevisionInputV1 {
            producer_origin: origin,
            member_binding_digest: hash(5),
            predecessor_revision_digest: match origin {
                CommunityStateProducerV1::Initialization { .. } => None,
                CommunityStateProducerV1::Pass(_) => Some(hash(6)),
            },
            state_content_digest: state,
            producer_digest: producer,
            protected_owner_binding_digest: COB,
            evidence_not_after_micros: HORIZON,
        })?
        .to_canonical_cbor()
        .to_vec(),
    )
}

const INITIALIZATION: CommunityStateProducerV1 = CommunityStateProducerV1::Initialization {
    generation_request_digest: Hash::from_bytes([4; 32]),
    operation_id: [0x10; 16],
};

const CMB1: CommunityTypedInputRefV1<'static> = CommunityTypedInputRefV1::Metadata {
    schema: CommunityMetadataSchemaV1::Cmb1,
    locator: CommunityMetadataLocatorV1 {
        timeline: timeline(),
        generation: GENERATION,
        producer: CommunityLocatorProducerV1::Control([0x10; 16]),
        record_role: 11,
        slot: 0,
    },
    envelope_address: Hash::from_bytes([0x60; 32]),
    private_record_digest: Hash::from_bytes([5; 32]),
};

/// One CPN1 over `content` with `index`, bound to the test cohort except
/// for `incarnation`.
fn node(
    kind: CommunityNativeNodeKindV1,
    content: CommunityContentReferenceV1,
    index: CommunityInputIndexV1<'_>,
    incarnation: [u8; 16],
) -> Fallible<(Vec<u8>, CommunityNativeNodeReferenceV1)> {
    let node = CommunityNativeNodeV1::new(CommunityNativeNodeInputV1 {
        store_incarnation: incarnation,
        timeline: timeline(),
        generation: GENERATION,
        producer_ordinal: 1,
        node_ordinal: 0,
        kind,
        content,
        dependency_class: kind
            .fixed_class()
            .unwrap_or(RecordedDependencyClassV1::EndogenousRecomputed),
        input_index: index,
        scope_binding_digest: SCOPE_COVER,
        authorization_digest: hash(0x51),
        provenance_digest: CPV,
        evidence_not_after_micros: HORIZON,
    })?;
    Ok((node.to_canonical_cbor().to_vec(), node.reference()))
}

const fn content(record_magic: [u8; 4], logical_digest: Hash) -> CommunityContentReferenceV1 {
    CommunityContentReferenceV1 {
        record_magic,
        logical_digest,
    }
}

#[test]
fn a_pass_revision_and_unsupported_kinds_are_refused() -> TestResult {
    let mut key = protector(GENERATION)?;
    let pass = CommunityStateProducerV1::Pass(CommunityPassKeyV1::new(timeline(), GENERATION, 1)?);
    let cases = [
        (Kind::StateRevisionOrHead, revision(pass, hash(7), hash(8))?),
        (Kind::PreparedInvocation, b"invocation".to_vec()),
    ];
    for (kind, plaintext) in cases {
        let record = protect(&mut key, kind, &plaintext, &[])?;
        assert_eq!(
            prepare(&[&record], &[ROOT], &key)?,
            Some(Error::InvalidBinding)
        );
    }
    // A StateContent record that is not a canonical CSC1.
    let record = protect(&mut key, Kind::StateContent, b"not a CSC1", &[])?;
    assert!(prepare(&[&record], &[ROOT], &key)?.is_some());
    Ok(())
}

#[test]
fn unsupported_node_forms_are_refused() -> TestResult {
    let mut key = protector(GENERATION)?;
    let initializer = content(*b"CIS1", hash(7));
    let artifact = [CommunityTypedInputRefV1::Artifact {
        owner_reference: hash(1),
        artifact_class: ErasureArtifactClassV1::TimelineReplay,
        artifact_digest: hash(2),
        registration_address: hash(3),
        source_scope_binding_digest: hash(4),
    }];
    let metadata = [CMB1];
    let direct =
        |refs| CommunityInputIndexV1::Direct(CommunityTypedInputRefsV1::from_references(refs));
    let nodes = [
        // A kind outside the initialization profile.
        node(
            CommunityNativeNodeKindV1::Observation,
            initializer,
            direct(&metadata),
            INCARNATION,
        )?,
        // An `InitialState` over a CSR1.
        node(
            CommunityNativeNodeKindV1::InitialState,
            content(*b"CSR1", hash(7)),
            direct(&metadata),
            INCARNATION,
        )?,
        // Another store incarnation.
        node(
            CommunityNativeNodeKindV1::InitialState,
            initializer,
            direct(&metadata),
            [0x5b; 16],
        )?,
        // No direct input index.
        node(
            CommunityNativeNodeKindV1::InitialState,
            initializer,
            CommunityInputIndexV1::Empty,
            INCARNATION,
        )?,
        // An artifact input.
        node(
            CommunityNativeNodeKindV1::InitialState,
            initializer,
            direct(&artifact),
            INCARNATION,
        )?,
    ];
    for (index, (node, _)) in nodes.iter().enumerate() {
        let record = protect(&mut key, Kind::ExecutionProvenance, node, &[])?;
        assert_eq!(
            prepare(&[&record], &[ROOT], &key)?,
            Some(Error::InvalidBinding),
            "node {index}"
        );
    }
    Ok(())
}

#[test]
fn a_record_of_another_generation_is_refused() -> TestResult {
    let mut key = protector([0x21; 16])?;
    let record = protect(&mut key, Kind::StateContent, &state(b"state")?, &[])?;
    assert_eq!(
        prepare(&[&record], &[ROOT], &key)?,
        Some(Error::InvalidBinding)
    );
    Ok(())
}

#[test]
fn duplicate_identities_and_unlisted_children_are_refused() -> TestResult {
    let mut key = protector(GENERATION)?;
    let state_bytes = state(b"state")?;
    let first = protect(&mut key, Kind::StateContent, &state_bytes, &[])?;
    let second = protect(&mut key, Kind::StateContent, &state_bytes, &[])?;
    assert_eq!(
        prepare(&[&first, &second], &[ROOT], &key)?,
        Some(Error::InvalidBinding)
    );

    // A CSR1 whose ARD1 omits its CSC1 and CIS1.
    let initializer = producer(&state_bytes)?;
    let producer_record = protect(
        &mut key,
        Kind::ExecutionProvenance,
        &initializer.to_canonical_cbor(),
        &[],
    )?;
    let revision_bytes = revision(
        INITIALIZATION,
        adr_h("CSC1", &state_bytes),
        initializer.digest(),
    )?;
    let unlisted = protect(&mut key, Kind::StateRevisionOrHead, &revision_bytes, &[])?;
    assert_eq!(
        prepare(&[&first, &producer_record, &unlisted], &[ROOT], &key)?,
        Some(Error::InvalidBinding)
    );
    Ok(())
}

#[test]
fn a_root_must_name_a_state_revision_node() -> TestResult {
    let mut key = protector(GENERATION)?;
    let state_bytes = state(b"state")?;
    let initializer = producer(&state_bytes)?;
    let producer_record = protect(
        &mut key,
        Kind::ExecutionProvenance,
        &initializer.to_canonical_cbor(),
        &[],
    )?;
    let metadata = [CMB1];
    let (initial, reference) = node(
        CommunityNativeNodeKindV1::InitialState,
        content(*b"CIS1", initializer.digest()),
        CommunityInputIndexV1::Direct(CommunityTypedInputRefsV1::from_references(&metadata)),
        INCARNATION,
    )?;
    let node_record = protect(
        &mut key,
        Kind::ExecutionProvenance,
        &initial,
        &[&producer_record],
    )?;
    // Both records resolve, but the root is the `InitialState` node.
    assert_eq!(
        prepare(&[&producer_record, &node_record], &[reference], &key)?,
        Some(Error::InvalidBinding)
    );
    Ok(())
}
