//! Native-graph assembly of one code-0 initialization (ADR-129 §2/§4,
//! #560 A3c-2b′) through its public seam: the per-member COW1 records and
//! their ARD1 children, the initial CMS1/CST1/CSH1, the CGR1 root and
//! counts, the CGA1 result, the CMI1 builder and every input refusal.
//!
//! The graph shape is the owner decision on #560, note 22661. Every
//! expected digest is computed independently with `blake3` from the ADR
//! formula `H(M, bytes)`, and CST1 is written out with `ciborium`.

use std::error::Error as StdError;

use ciborium::Value;
use pos_core::community_lifecycle::{
    community_initializer_set_ref_v1, ArtifactRefV1, CommunityArtifactKindV1 as Kind,
    CommunityArtifactOperationV1 as Operation, CommunityArtifactPurposeV1 as Purpose,
    CommunityDigestListV1, CommunityDurableBackendV1, CommunityDurableProfileInputV1,
    CommunityDurableProfileV1, CommunityGenerationAdmissionV1, CommunityGraphRootV1,
    CommunityInitializationRequestInputV1, CommunityInitializationRequestV1,
    CommunityInitializationSourceV1 as Source, CommunityLifecycleErrorV1 as Error,
    CommunityMaterializationV1, CommunityMemberBindingInputV1, CommunityMemberBindingV1,
    CommunityMemberProgressV1, CommunityMemberSlotsV1, CommunityNativeNodeReferenceV1,
    CommunityPassFrontierV1, CommunityProducerBindingV1, CommunityProfileMemberV1,
    CommunityProfileRetentionV1, CommunityProgressReferenceV1, CommunityRecordKindsV1,
    CommunitySelectedHeadV1, CommunityStateContentV1,
};
use pos_core::{
    ArtifactChildEdgeV1, ArtifactOptionalityV1, ArtifactTransitionRuleV1, AuthorityTrustRootSealV1,
    ErasureArtifactClassV1 as Class, Hash, ImplementationKeyV1, Seq, TimelineId,
};
use pos_store::community::{
    CommunityArtifactProtectorV1, CommunityAssembledRecordV1, CommunityInitializationGraphInputV1,
    CommunityInitializationGraphV1, CommunityInitializationMemberV1, CommunityInitializerOwnerV1,
    CommunityProtectionCohortV1,
};
use ulid::Ulid;
use zeroize::Zeroizing;

type Fallible<T> = Result<T, Box<dyn StdError>>;
type TestResult = Fallible<()>;

const SEAL: AuthorityTrustRootSealV1 = AuthorityTrustRootSealV1::for_composition_root();
const INCARNATION: [u8; 16] = [0x5a; 16];
const OPERATION: [u8; 16] = [0x10; 16];
const GENERATION: [u8; 16] = [0x20; 16];
const PRODUCER: u64 = 7;
const HORIZON: u64 = 900;
const REQUEST_HORIZON: u64 = 1_000;
const SCHEMA: Hash = Hash::from_bytes([0x22; 32]);
const CATALOGUE: Hash = Hash::from_bytes([9; 32]);
const COB: Hash = Hash::from_bytes([0x40; 32]);
const CPV: Hash = Hash::from_bytes([0x41; 32]);
const SCOPE_COVER: Hash = Hash::from_bytes([0x42; 32]);
const ENTRIES: [&str; 2] = ["Entry-A_1", "Entry-B_1"];

const fn hash(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
}

const fn timeline() -> TimelineId {
    TimelineId::from_ulid(Ulid::from_bytes([0x0e; 16]))
}

/// `H(M, bytes)`: BLAKE3 of `PiglorOS.Community.<M>.v1`, a zero byte and
/// the bytes.
fn adr_h(m: &str, bytes: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(format!("PiglorOS.Community.{m}.v1\0").as_bytes());
    hasher.update(bytes);
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

fn encode(value: &Value) -> Fallible<Vec<u8>> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out)?;
    Ok(out)
}

/// The fixed inputs every graph of these tests is assembled from.
struct Fixture {
    implementation: ImplementationKeyV1,
    states: [Vec<u8>; 2],
}

impl Fixture {
    fn new() -> Fallible<Self> {
        Ok(Self {
            implementation: ImplementationKeyV1::new("plugin-a".into(), "host-v1".into(), hash(3))?,
            states: [
                CommunityStateContentV1::new(SCHEMA, b"state-a")?
                    .to_canonical_cbor()
                    .to_vec(),
                CommunityStateContentV1::new(SCHEMA, b"state-b")?
                    .to_canonical_cbor()
                    .to_vec(),
            ],
        })
    }

    /// P8 `[0x4353_0001, len(CSC1), H(CSC1)]` of slot `slot`'s State.
    fn initializer(&self, slot: usize) -> ArtifactRefV1 {
        ArtifactRefV1 {
            schema_id: 0x4353_0001,
            byte_length: self.states[slot].len() as u64,
            digest: *adr_h("CSC1", &self.states[slot]).as_bytes(),
        }
    }

    fn rows(&self) -> Fallible<Vec<CommunityProfileMemberV1<'_>>> {
        (0..2)
            .map(|slot| {
                Ok(CommunityProfileMemberV1::new(
                    ENTRIES[slot],
                    &self.implementation,
                    hash(4),
                    SCHEMA,
                    hash(6),
                    self.initializer(slot),
                )?)
            })
            .collect()
    }

    fn owner(
        &self,
        profile: &CommunityDurableProfileV1<'_>,
    ) -> Fallible<CommunityInitializerOwnerV1> {
        Ok(CommunityInitializerOwnerV1::new(
            &SEAL,
            profile,
            self.states
                .iter()
                .map(|state| Zeroizing::new(state.clone()))
                .collect(),
        )?)
    }

    fn bindings(&self) -> Fallible<Vec<CommunityMemberBindingV1<'_>>> {
        (0..2)
            .map(|slot| {
                Ok(CommunityMemberBindingV1::new(
                    CommunityMemberBindingInputV1 {
                        stable_entry: ENTRIES[slot],
                        implementation: &self.implementation,
                        pmf1_digest: hash(4),
                        state_schema_digest: SCHEMA,
                        negotiated_tuple_digest: hash(6),
                        initial_state_content_digest: adr_h("CSC1", &self.states[slot]),
                        protected_owner_binding_digest: COB,
                    },
                )?)
            })
            .collect()
    }
}

fn profile<'a>(
    roster: &'a [CommunityProfileMemberV1<'a>],
) -> Fallible<CommunityDurableProfileV1<'a>> {
    Ok(CommunityDurableProfileV1::new(
        CommunityDurableProfileInputV1 {
            backend: CommunityDurableBackendV1::RetainedMemory,
            execution_profile_digest: hash(1),
            roster,
            source_catalogue_digest: hash(2),
            authority_catalogue_digest: CATALOGUE,
            retention: CommunityProfileRetentionV1 {
                generation_not_after_micros: 1_000,
                recovery_window_micros: 1,
                quarantine_not_after_micros: 1_000,
                metadata_not_after_micros: 1_000,
            },
        },
    )?)
}

fn request_input<'a>(
    profile: &CommunityDurableProfileV1<'_>,
    digests: &'a [Hash],
) -> CommunityInitializationRequestInputV1<'a> {
    CommunityInitializationRequestInputV1 {
        operation_id: OPERATION,
        timeline: timeline(),
        generation: GENERATION,
        expected_prior_generation: None,
        expected_prior_head_digest: None,
        profile_digest: profile.digest(),
        member_binding_digests: CommunityDigestListV1::from_digests(digests),
        initial_source: Source::Initializer(community_initializer_set_ref_v1(profile)),
        principal_ref: ArtifactRefV1 {
            schema_id: 0x4341_0003,
            byte_length: 40,
            digest: [0x50; 32],
        },
        authorization_ref: ArtifactRefV1 {
            schema_id: 0x4341_0002,
            byte_length: 41,
            digest: [0x51; 32],
        },
        evidence_not_after_micros: REQUEST_HORIZON,
    }
}

fn cohort() -> Fallible<CommunityProtectionCohortV1> {
    Ok(CommunityProtectionCohortV1 {
        parent_operation: Operation::Initialization(OPERATION),
        timeline: timeline(),
        generation: GENERATION,
        purpose: Purpose::ExecutionState,
        scope_set_digest: hash(0x43),
        scope_cover_digest: SCOPE_COVER,
        evidence_not_after_micros: HORIZON,
        allowed_record_kinds: CommunityRecordKindsV1::empty()
            .with(Kind::StateContent)
            .with(Kind::StateRevisionOrHead)
            .with(Kind::ExecutionProvenance)
            .with(Kind::ClassificationProof),
        member_slots: CommunityMemberSlotsV1::new(&[0, 1])?,
        authority_request_digest: hash(0x44),
    })
}

fn members<'a>(
    bindings: &'a [CommunityMemberBindingV1<'a>],
) -> Vec<CommunityInitializationMemberV1<'a>> {
    bindings
        .iter()
        .zip([0x60, 0x61])
        .map(|(binding, address)| CommunityInitializationMemberV1 {
            binding,
            binding_envelope_address: hash(address),
        })
        .collect()
}

const fn graph_input<'a>(
    request: &'a CommunityInitializationRequestV1<'a>,
    profile: &'a CommunityDurableProfileV1<'a>,
    members: &'a [CommunityInitializationMemberV1<'a>],
) -> CommunityInitializationGraphInputV1<'a> {
    CommunityInitializationGraphInputV1 {
        store_incarnation: INCARNATION,
        producer_ordinal: PRODUCER,
        request,
        profile,
        members,
        owner_binding_digest: COB,
        host_provenance_digest: CPV,
        event_logical_head: Seq::from_u64(12),
    }
}

const fn edge(record: &CommunityAssembledRecordV1) -> ArtifactChildEdgeV1 {
    let registration = record.protected().registration();
    ArtifactChildEdgeV1 {
        artifact_class: Class::TimelineReplay,
        artifact_digest: registration.fields().artifact_digest,
        registration_address: registration.address(),
        required: true,
    }
}

fn sorted(mut edges: Vec<ArtifactChildEdgeV1>) -> Vec<ArtifactChildEdgeV1> {
    edges.sort_by_key(|edge| {
        (
            edge.artifact_class,
            edge.artifact_digest,
            edge.registration_address,
        )
    });
    edges
}

/// The assembled two-member graph and the inputs it was built from.
fn assembled(
    fixture: &Fixture,
) -> Fallible<(CommunityInitializationGraphV1, Vec<Hash>, Hash, Hash)> {
    let rows = fixture.rows()?;
    let profile = profile(&rows)?;
    let owner = fixture.owner(&profile)?;
    let bindings = fixture.bindings()?;
    let digests: Vec<Hash> = bindings
        .iter()
        .map(CommunityMemberBindingV1::digest)
        .collect();
    let request = CommunityInitializationRequestV1::new(request_input(&profile, &digests))?;
    let members = members(&bindings);
    let mut protector = CommunityArtifactProtectorV1::provision(&SEAL, cohort()?)?;
    let graph = CommunityInitializationGraphV1::assemble(
        &SEAL,
        graph_input(&request, &profile, &members),
        &owner,
        &mut protector,
    )?;
    let request_digest = request.digest();
    Ok((graph, digests, profile.digest(), request_digest))
}

/// Per slot: CSC1, CIS1, CSR1, `InitialState` CPN1, `StateRevision` CPN1,
/// with the required ARD1 children of note 22661, item 4.
fn check_records(records: &[CommunityAssembledRecordV1]) {
    assert_eq!(records.len(), 10);
    for (slot, member) in records.chunks(5).enumerate() {
        let magics: Vec<[u8; 4]> = member
            .iter()
            .map(CommunityAssembledRecordV1::record_magic)
            .collect();
        assert_eq!(
            magics,
            [*b"CSC1", *b"CIS1", *b"CSR1", *b"CPN1", *b"CPN1"],
            "slot {slot}"
        );
        // Note 22661, item 4: every child is required.
        let expected: [Vec<ArtifactChildEdgeV1>; 5] = [
            Vec::new(),
            Vec::new(),
            sorted(vec![edge(&member[0]), edge(&member[1])]),
            vec![edge(&member[1])],
            sorted(vec![edge(&member[2]), edge(&member[0]), edge(&member[3])]),
        ];
        for (record, children) in member.iter().zip(expected) {
            let fields = record.protected().registration().fields();
            assert_eq!(fields.child_artifacts, children);
            assert_eq!(fields.artifact_class, Class::TimelineReplay);
            assert_eq!(fields.optionality, ArtifactOptionalityV1::Required);
            assert_eq!(fields.transition_rule, ArtifactTransitionRuleV1::Remove);
        }
    }
}

/// The initial CST1, CMS1s and the CSH1 that selects them.
fn check_progress(
    graph: &CommunityInitializationGraphV1,
    digests: &[Hash],
    profile_digest: Hash,
) -> TestResult {
    // Initial CST1: `[0]` before any boundary.
    let cst1 = encode(&Value::Array(vec![
        Value::Bytes(b"CST1".to_vec()),
        Value::Integer(1.into()),
        Value::Bytes(Ulid::from_bytes([0x0e; 16]).to_bytes().to_vec()),
        Value::Bytes(GENERATION.to_vec()),
        Value::Array(vec![Value::Integer(0.into())]),
        Value::Array(vec![Value::Integer(0.into())]),
    ]))?;
    assert_eq!(graph.host_progress(), cst1.as_slice());

    // Initial CMS1 per member.
    let progress: Vec<&[u8]> = graph.member_progress().collect();
    assert_eq!(progress.len(), 2);
    for (cms1, digest) in progress.iter().zip(digests) {
        let decoded = CommunityMemberProgressV1::from_canonical_cbor(cms1)?;
        let fields = decoded.as_input();
        assert_eq!(fields.member_binding_digest, *digest);
        assert_eq!(fields.last_step_simulation_time, None);
        assert_eq!(fields.forwarded_cursor, Seq::ZERO);
        assert!(fields.carried_events.is_empty());
        assert!(fields.step_chain == CommunityProgressReferenceV1::None);
        assert!(fields.history_input == CommunityProgressReferenceV1::None);
    }

    // CSH1 selects the initial frontier and every member's CMS1.
    let head = CommunitySelectedHeadV1::from_canonical_cbor(graph.selected_head())?;
    let fields = head.as_input();
    assert!(fields.frontier == CommunityPassFrontierV1::Initial);
    assert_eq!(fields.timeline, timeline());
    assert_eq!(fields.generation, GENERATION);
    assert_eq!(fields.event_logical_head, Seq::from_u64(12));
    assert_eq!(fields.profile_digest, profile_digest);
    assert_eq!(fields.host_progress_digest, adr_h("CST1", &cst1));
    let mut expected_heads: Vec<(Hash, Hash)> = digests
        .iter()
        .zip(&progress)
        .map(|(digest, cms1)| (*digest, adr_h("CMS1", cms1)))
        .collect();
    expected_heads.sort();
    let heads: Vec<(Hash, Hash)> = fields
        .member_heads
        .iter()
        .map(|head| (head.member_binding_digest, head.member_progress_digest))
        .collect();
    assert_eq!(heads, expected_heads);
    assert_eq!(
        graph.selected_head_digest(),
        adr_h("CSH1", graph.selected_head())
    );
    Ok(())
}

/// CGR1: one `StateRevision` root per member, exact ARD1-graph counts.
fn check_root(
    graph: &CommunityInitializationGraphV1,
    profile_digest: Hash,
) -> Fallible<Vec<CommunityNativeNodeReferenceV1>> {
    let records = graph.records();
    let root = CommunityGraphRootV1::from_canonical_cbor(graph.graph_root())?;
    let fields = root.as_input();
    assert_eq!(fields.store_incarnation, INCARNATION);
    assert_eq!(fields.timeline, timeline());
    assert_eq!(fields.generation, GENERATION);
    assert_eq!(fields.profile_digest, profile_digest);
    assert_eq!(fields.selected_head_digest, graph.selected_head_digest());
    assert_eq!(fields.evidence_not_after_micros, HORIZON);
    let roots: Vec<CommunityNativeNodeReferenceV1> =
        fields.roots.iter().collect::<Result<_, _>>()?;
    assert_eq!(roots.len(), 2);
    for (root, ordinal) in roots.iter().zip([1, 3]) {
        assert_eq!(root.store_incarnation, INCARNATION);
        assert_eq!(root.producer_ordinal, PRODUCER);
        assert_eq!(root.node_ordinal, ordinal);
    }
    let counts = fields.graph_counts;
    assert_eq!(counts.registrations, 10);
    assert_eq!(counts.edges, 12);
    assert_eq!(counts.keys, 1);
    assert_eq!(counts.maximum_depth, 3);
    assert_eq!(
        counts.registration_bytes,
        records
            .iter()
            .map(|record| record.protected().registration().canonical_cbor().len() as u64)
            .sum::<u64>()
    );
    assert_eq!(
        counts.artifact_bytes,
        records
            .iter()
            .map(|record| record.protected().object().len() as u64)
            .sum::<u64>()
    );
    Ok(roots)
}

/// CGA1 binds the request, head and root.
fn check_admission(graph: &CommunityInitializationGraphV1, request_digest: Hash) -> TestResult {
    let admission =
        CommunityGenerationAdmissionV1::from_canonical_cbor(graph.generation_admission())?;
    let fields = admission.as_input();
    assert_eq!(fields.generation_request_digest, request_digest);
    assert_eq!(fields.timeline, timeline());
    assert_eq!(fields.generation, GENERATION);
    assert_eq!(
        fields.initial_selected_head_digest,
        graph.selected_head_digest()
    );
    assert_eq!(fields.graph_root_ref, adr_h("CGR1", graph.graph_root()));
    assert_eq!(fields.evidence_not_after_micros, HORIZON);
    Ok(())
}

/// CMI1 fields and producer bindings (note 22661, item 7).
fn check_materializations(
    fixture: &Fixture,
    records: &[CommunityAssembledRecordV1],
    roots: &[CommunityNativeNodeReferenceV1],
    request_digest: Hash,
) -> TestResult {
    for (slot, member) in records.chunks(5).enumerate() {
        let state_revision = CommunityProducerBindingV1::Native(roots[slot]);
        let control = CommunityProducerBindingV1::Control(request_digest);
        for (index, record) in member.iter().enumerate() {
            let cmi1 = record.materialization(&SEAL, hash(0x70))?;
            let decoded =
                CommunityMaterializationV1::from_canonical_cbor(&cmi1.to_canonical_cbor())?;
            let fields = decoded.as_input();
            let registration = record.protected().registration();
            assert_eq!(fields.store_incarnation, INCARNATION);
            assert_eq!(fields.record_magic, record.record_magic());
            assert_eq!(fields.scope_binding_digest, SCOPE_COVER);
            assert_eq!(fields.evidence_not_after_micros, HORIZON);
            assert_eq!(
                fields.materialization.object_address,
                record.protected().object_address()
            );
            assert_eq!(
                fields.materialization.artifact_digest,
                registration.fields().artifact_digest
            );
            assert_eq!(
                fields.materialization.registration_address,
                registration.address()
            );
            assert_eq!(fields.materialization.attestation_address, hash(0x70));
            assert_eq!(
                fields.materialization.owner_reference,
                registration.fields().owner_reference
            );
            match index {
                0 => {
                    assert!(fields.producer == state_revision);
                    assert_eq!(
                        fields.logical_record_digest,
                        adr_h("CSC1", &fixture.states[slot])
                    );
                    assert_eq!(fields.plaintext_length, fixture.states[slot].len() as u64);
                }
                1 => assert!(matches!(
                    fields.producer,
                    CommunityProducerBindingV1::Native(node)
                        if node.producer_ordinal == PRODUCER && node.node_ordinal == roots[slot].node_ordinal - 1
                )),
                2 => assert!(fields.producer == state_revision),
                _ => assert!(fields.producer == control),
            }
        }
        // The StateRevision CPN1's logical digest is its root's node digest.
        let cmi1 = member[4].materialization(&SEAL, hash(0x70))?;
        assert_eq!(
            cmi1.as_input().logical_record_digest,
            roots[slot].node_digest
        );
    }
    assert_eq!(
        records[0].materialization(&SEAL, Hash::zero()).err(),
        Some(Error::InvalidBinding)
    );
    Ok(())
}

#[test]
fn assembles_the_initial_graph_of_every_member() -> TestResult {
    let fixture = Fixture::new()?;
    let (graph, digests, profile_digest, request_digest) = assembled(&fixture)?;
    check_records(graph.records());
    check_progress(&graph, &digests, profile_digest)?;
    let roots = check_root(&graph, profile_digest)?;
    check_admission(&graph, request_digest)?;
    check_materializations(&fixture, graph.records(), &roots, request_digest)
}

/// One input mutation that must refuse with `InvalidBinding`.
#[derive(Clone, Copy)]
enum Case {
    PriorStateSource,
    ForeignInitializerSet,
    ForeignProfileDigest,
    ForeignCatalogue,
    MissingMember,
    SwappedRequestOrder,
    SwappedMembers,
    ForeignState,
    ForeignOwnerBinding,
    ZeroEnvelope,
    ForeignParent,
    ForeignTimeline,
    ForeignGeneration,
    TracePurpose,
    MissingKind,
    MissingSlot,
    ShiftedSlots,
    LongHorizon,
    ZeroOwnerBinding,
    ZeroProvenance,
    ZeroProducer,
}

const CASES: [Case; 21] = [
    Case::PriorStateSource,
    Case::ForeignInitializerSet,
    Case::ForeignProfileDigest,
    Case::ForeignCatalogue,
    Case::MissingMember,
    Case::SwappedRequestOrder,
    Case::SwappedMembers,
    Case::ForeignState,
    Case::ForeignOwnerBinding,
    Case::ZeroEnvelope,
    Case::ForeignParent,
    Case::ForeignTimeline,
    Case::ForeignGeneration,
    Case::TracePurpose,
    Case::MissingKind,
    Case::MissingSlot,
    Case::ShiftedSlots,
    Case::LongHorizon,
    Case::ZeroOwnerBinding,
    Case::ZeroProvenance,
    Case::ZeroProducer,
];

fn refusal(case: Case) -> Fallible<Option<Error>> {
    let fixture = Fixture::new()?;
    let rows = fixture.rows()?;
    let profile = profile(&rows)?;
    let owner = match case {
        // An owner installed for the same roster under another catalogue.
        Case::ForeignCatalogue => {
            let other = profile_with_catalogue(&rows, hash(0x77))?;
            fixture.owner(&other)?
        }
        _ => fixture.owner(&profile)?,
    };
    let mut bindings = fixture.bindings()?;
    match case {
        Case::SwappedMembers => bindings.swap(0, 1),
        Case::ForeignState | Case::ForeignOwnerBinding => {
            let (state, cob) = if matches!(case, Case::ForeignState) {
                (hash(0x71), COB)
            } else {
                (adr_h("CSC1", &fixture.states[0]), hash(0x72))
            };
            bindings[0] = CommunityMemberBindingV1::new(CommunityMemberBindingInputV1 {
                stable_entry: ENTRIES[0],
                implementation: &fixture.implementation,
                pmf1_digest: hash(4),
                state_schema_digest: SCHEMA,
                negotiated_tuple_digest: hash(6),
                initial_state_content_digest: state,
                protected_owner_binding_digest: cob,
            })?;
        }
        _ => {}
    }
    let mut digests: Vec<Hash> = bindings
        .iter()
        .map(CommunityMemberBindingV1::digest)
        .collect();
    if matches!(case, Case::SwappedRequestOrder) {
        digests.swap(0, 1);
    }
    let mut input = request_input(&profile, &digests);
    match case {
        Case::PriorStateSource => input.initial_source = Source::PriorState(hash(0x73)),
        Case::ForeignInitializerSet => {
            input.initial_source = Source::Initializer(fixture.initializer(0));
        }
        Case::ForeignProfileDigest => input.profile_digest = hash(0x74),
        _ => {}
    }
    let request = CommunityInitializationRequestV1::new(input)?;
    let mut members = members(&bindings);
    match case {
        Case::MissingMember => {
            members.pop();
        }
        Case::ZeroEnvelope => members[1].binding_envelope_address = Hash::zero(),
        _ => {}
    }
    let mut cohort = cohort()?;
    match case {
        Case::ForeignParent => cohort.parent_operation = Operation::Initialization([0x11; 16]),
        Case::ForeignTimeline => {
            cohort.timeline = TimelineId::from_ulid(Ulid::from_bytes([0x0f; 16]));
        }
        Case::ForeignGeneration => cohort.generation = [0x21; 16],
        Case::TracePurpose => {
            cohort.purpose = Purpose::PresentationTrace;
            cohort.allowed_record_kinds = CommunityRecordKindsV1::empty()
                .with(Kind::TraceAnnotation)
                .with(Kind::ClassificationProof);
        }
        Case::MissingKind => {
            cohort.allowed_record_kinds = CommunityRecordKindsV1::empty()
                .with(Kind::StateContent)
                .with(Kind::ExecutionProvenance)
                .with(Kind::ClassificationProof);
        }
        Case::MissingSlot => cohort.member_slots = CommunityMemberSlotsV1::new(&[0])?,
        Case::ShiftedSlots => cohort.member_slots = CommunityMemberSlotsV1::new(&[0, 2])?,
        Case::LongHorizon => cohort.evidence_not_after_micros = REQUEST_HORIZON + 1,
        _ => {}
    }
    let mut protector = CommunityArtifactProtectorV1::provision(&SEAL, cohort)?;
    let mut input = graph_input(&request, &profile, &members);
    match case {
        Case::ZeroOwnerBinding => input.owner_binding_digest = Hash::zero(),
        Case::ZeroProvenance => input.host_provenance_digest = Hash::zero(),
        Case::ZeroProducer => input.producer_ordinal = 0,
        _ => {}
    }
    Ok(CommunityInitializationGraphV1::assemble(&SEAL, input, &owner, &mut protector).err())
}

fn profile_with_catalogue<'a>(
    roster: &'a [CommunityProfileMemberV1<'a>],
    catalogue: Hash,
) -> Fallible<CommunityDurableProfileV1<'a>> {
    let base = profile(roster)?;
    Ok(CommunityDurableProfileV1::new(
        CommunityDurableProfileInputV1 {
            authority_catalogue_digest: catalogue,
            ..*base.as_input()
        },
    )?)
}

#[test]
fn refuses_inputs_that_break_the_graph_bindings() -> TestResult {
    for (index, case) in CASES.into_iter().enumerate() {
        assert_eq!(refusal(case)?, Some(Error::InvalidBinding), "case {index}");
    }
    Ok(())
}

/// The initializer owner must hold each member's State, not only one with
/// the same catalogue.
#[test]
fn refuses_states_the_initializer_owner_does_not_hold() -> TestResult {
    let fixture = Fixture::new()?;
    let rows = fixture.rows()?;
    let profile = profile(&rows)?;
    // An owner of the same catalogue installed for other States.
    let other_states = Fixture {
        implementation: ImplementationKeyV1::new("plugin-a".into(), "host-v1".into(), hash(3))?,
        states: [
            CommunityStateContentV1::new(SCHEMA, b"other-a")?
                .to_canonical_cbor()
                .to_vec(),
            CommunityStateContentV1::new(SCHEMA, b"other-b")?
                .to_canonical_cbor()
                .to_vec(),
        ],
    };
    let other_rows = other_states.rows()?;
    let other_profile = self::profile(&other_rows)?;
    let owner = other_states.owner(&other_profile)?;
    let bindings = fixture.bindings()?;
    let digests: Vec<Hash> = bindings
        .iter()
        .map(CommunityMemberBindingV1::digest)
        .collect();
    let request = CommunityInitializationRequestV1::new(request_input(&profile, &digests))?;
    let members = members(&bindings);
    let mut protector = CommunityArtifactProtectorV1::provision(&SEAL, cohort()?)?;
    assert_eq!(
        CommunityInitializationGraphV1::assemble(
            &SEAL,
            graph_input(&request, &profile, &members),
            &owner,
            &mut protector,
        )
        .err(),
        Some(Error::InvalidBinding)
    );
    Ok(())
}
