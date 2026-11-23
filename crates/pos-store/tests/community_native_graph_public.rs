//! Native-graph assembly of one code-0 initialization (ADR-129 §2/§4,
//! #560 A3c-2b′) through its public seam: the per-member COW1 records and
//! their ARD1 children, the initial CMS1/CST1/CSH1, the CGR1 root and
//! counts, the CGA1 result and every input refusal; and the community
//! extractor `prepare_community_artifact_batch_v1` over that graph.
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
    CommunityDurableProfileV1, CommunityGenerationAdmissionV1, CommunityGraphCountsV1,
    CommunityGraphRootInputV1, CommunityGraphRootV1, CommunityInitializationRequestInputV1,
    CommunityInitializationRequestV1, CommunityInitializationSourceV1 as Source,
    CommunityLifecycleErrorV1 as Error, CommunityMemberBindingInputV1, CommunityMemberBindingV1,
    CommunityMemberProgressV1, CommunityMemberSlotsV1, CommunityNativeNodeReferenceV1,
    CommunityNativeNodeReferencesV1, CommunityPassFrontierV1, CommunityProfileMemberV1,
    CommunityProfileRetentionV1, CommunityProgressReferenceV1, CommunityProtectedObjectV1,
    CommunityRecordKindsV1, CommunitySelectedHeadV1, CommunityStateContentV1,
};
use pos_core::{
    ArtifactChildEdgeV1, ArtifactOptionalityV1, ArtifactTransitionRuleV1, AuthorityTrustRootSealV1,
    ErasureArtifactClassV1 as Class, Hash, ImplementationKeyV1, Seq, TimelineId,
};
use pos_store::community::{
    prepare_community_artifact_batch_v1, CommunityArtifactBatchInputV1,
    CommunityArtifactProtectorV1, CommunityArtifactRecordInputV1, CommunityAssembledRecordV1,
    CommunityInitializationGraphInputV1, CommunityInitializationGraphV1,
    CommunityInitializationMemberV1, CommunityInitializerOwnerV1, CommunityProtectionCohortV1,
    CommunityRecordEvidenceV1,
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
const AUTHORIZATION: ArtifactRefV1 = ArtifactRefV1 {
    schema_id: 0x4341_0002,
    byte_length: 41,
    digest: [0x51; 32],
};

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
        Self::with_seed(0)
    }

    /// Fixture States `state-a`/`state-b` followed by `seed`.
    fn with_seed(seed: u8) -> Fallible<Self> {
        Ok(Self {
            implementation: ImplementationKeyV1::new("plugin-a".into(), "host-v1".into(), hash(3))?,
            states: [
                CommunityStateContentV1::new(SCHEMA, &[b"state-a".as_slice(), &[seed]].concat())?
                    .to_canonical_cbor()
                    .to_vec(),
                CommunityStateContentV1::new(SCHEMA, &[b"state-b".as_slice(), &[seed]].concat())?
                    .to_canonical_cbor()
                    .to_vec(),
            ],
        })
    }

    /// The first fixture whose CMB1 digests descend in roster order, so the
    /// CSH1's digest order differs from roster order.
    fn descending() -> Fallible<Self> {
        for seed in 0..=u8::MAX {
            let fixture = Self::with_seed(seed)?;
            let bindings = fixture.bindings()?;
            if bindings[0].digest() > bindings[1].digest() {
                return Ok(fixture);
            }
        }
        Err("no seed gives descending member digests".into())
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
                    10,
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
                recording_not_after_micros: 1_000,
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
        authorization_ref: AUTHORIZATION,
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
/// An assembled two-member graph, the facts it binds and the protector
/// whose key handle the extractor authenticates it with.
struct Assembled {
    graph: CommunityInitializationGraphV1,
    digests: Vec<Hash>,
    profile_digest: Hash,
    request_digest: Hash,
    protector: CommunityArtifactProtectorV1,
}

fn assembled(fixture: &Fixture) -> Fallible<Assembled> {
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
    Ok(Assembled {
        graph,
        digests: digests.clone(),
        profile_digest: profile.digest(),
        request_digest: request.digest(),
        protector,
    })
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
    // The fixture's member digests descend in roster order, so CSH1's
    // digest order is not roster order.
    assert_eq!(heads[0].0, digests[1]);
    assert_eq!(
        graph.selected_head_digest(),
        adr_h("CSH1", graph.selected_head())
    );
    Ok(())
}

/// CGR1: one `StateRevision` root per member, exact ARD1-graph counts.
fn check_root(graph: &CommunityInitializationGraphV1, profile_digest: Hash) -> TestResult {
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
    Ok(())
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

#[test]
fn assembles_the_initial_graph_of_every_member() -> TestResult {
    let fixture = Fixture::descending()?;
    let assembled = assembled(&fixture)?;
    let graph = &assembled.graph;
    check_records(graph.records());
    check_progress(graph, &assembled.digests, assembled.profile_digest)?;
    check_root(graph, assembled.profile_digest)?;
    check_admission(graph, assembled.request_digest)
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

/// The extractor input for an assembled graph's own records and root.
fn batch_records(
    graph: &CommunityInitializationGraphV1,
) -> Vec<CommunityArtifactRecordInputV1<'_>> {
    graph
        .records()
        .iter()
        .map(|record| CommunityArtifactRecordInputV1 {
            object: record.protected().object(),
            registration: record.protected().registration(),
        })
        .collect()
}

fn batch_input<'a>(
    assembled: &'a Assembled,
    records: &'a [CommunityArtifactRecordInputV1<'a>],
    graph_root: &'a [u8],
) -> CommunityArtifactBatchInputV1<'a> {
    CommunityArtifactBatchInputV1 {
        store_incarnation: INCARNATION,
        profile_digest: assembled.profile_digest,
        operation_id: OPERATION,
        authorization_ref: AUTHORIZATION,
        owner_binding_digest: COB,
        records,
        graph_root,
        selected_head: assembled.graph.selected_head(),
        current_head: None,
        expected_prior_head: None,
    }
}

/// A CGR1 equal to `graph`'s except for its roots and counts.
fn root_with(
    graph: &CommunityInitializationGraphV1,
    roots: &[CommunityNativeNodeReferenceV1],
    counts: CommunityGraphCountsV1,
) -> Fallible<Vec<u8>> {
    let root = CommunityGraphRootV1::from_canonical_cbor(graph.graph_root())?;
    Ok(CommunityGraphRootV1::new(CommunityGraphRootInputV1 {
        roots: CommunityNativeNodeReferencesV1::from_references(roots),
        graph_counts: counts,
        ..*root.as_input()
    })?
    .to_canonical_cbor()
    .to_vec())
}

fn roots_and_counts(
    graph: &CommunityInitializationGraphV1,
) -> Fallible<(Vec<CommunityNativeNodeReferenceV1>, CommunityGraphCountsV1)> {
    let root = CommunityGraphRootV1::from_canonical_cbor(graph.graph_root())?;
    Ok((
        root.as_input().roots.iter().collect::<Result<_, _>>()?,
        root.as_input().graph_counts,
    ))
}

#[test]
fn the_extractor_admits_the_assembled_initial_graph() -> TestResult {
    let assembled = assembled(&Fixture::new()?)?;
    let graph = &assembled.graph;
    let records = batch_records(graph);
    let batch = prepare_community_artifact_batch_v1(
        &SEAL,
        batch_input(&assembled, &records, graph.graph_root()),
        &[&assembled.protector],
    )?;
    assert_eq!(batch.graph_root_digest(), adr_h("CGR1", graph.graph_root()));
    assert_eq!(batch.records().len(), 10);
    for (verified, record) in batch.records().iter().zip(graph.records()) {
        let record = record.protected();
        assert_eq!(verified.object(), record.object());
        assert_eq!(verified.object_address(), record.object_address());
        assert_eq!(verified.registration(), record.registration());
        // The verified record carries the same COA1 bindings.
        let verified_admission = verified.admission(&SEAL, 3, hash(0x75))?;
        let admission = record.admission(&SEAL, 3, hash(0x75))?;
        assert!(verified_admission.as_input() == admission.as_input());
    }
    Ok(())
}

/// Each refusal of a well-formed but unadmissible batch.
#[test]
fn the_extractor_refuses_a_stale_head_or_a_missing_key() -> TestResult {
    let assembled = assembled(&Fixture::new()?)?;
    let graph = &assembled.graph;
    let records = batch_records(graph);
    let input = batch_input(&assembled, &records, graph.graph_root());
    let prepare = |input, keys: &[&CommunityArtifactProtectorV1]| {
        prepare_community_artifact_batch_v1(&SEAL, input, keys).err()
    };
    // Note 22661, item 8: the current head must be the expected prior head.
    let stale = CommunityArtifactBatchInputV1 {
        current_head: Some(hash(0x76)),
        ..input
    };
    assert_eq!(
        prepare(stale, &[&assembled.protector]),
        Some(Error::StaleFrontier)
    );
    let moved = CommunityArtifactBatchInputV1 {
        expected_prior_head: Some(hash(0x76)),
        ..input
    };
    assert_eq!(
        prepare(moved, &[&assembled.protector]),
        Some(Error::StaleFrontier)
    );
    // Matching non-null heads extend the selection.
    let extended = CommunityArtifactBatchInputV1 {
        current_head: Some(hash(0x76)),
        expected_prior_head: Some(hash(0x76)),
        ..input
    };
    assert_eq!(prepare(extended, &[&assembled.protector]), None);
    // No key handle, or only another suboperation's, owns the records.
    assert_eq!(prepare(input, &[]), Some(Error::EvidenceUnavailable));
    let other = CommunityArtifactProtectorV1::provision(&SEAL, cohort()?)?;
    assert_eq!(prepare(input, &[&other]), Some(Error::EvidenceUnavailable));
    assert_eq!(prepare(input, &[&other, &assembled.protector]), None);
    Ok(())
}

#[test]
fn the_extractor_refuses_tampered_records() -> TestResult {
    let assembled = assembled(&Fixture::new()?)?;
    let graph = &assembled.graph;
    let prepare = |records: &[CommunityArtifactRecordInputV1<'_>]| {
        prepare_community_artifact_batch_v1(
            &SEAL,
            batch_input(&assembled, records, graph.graph_root()),
            &[&assembled.protector],
        )
        .err()
    };
    let object = graph.records()[0].protected().object();
    let cow1 = CommunityProtectedObjectV1::from_canonical_cbor(object)?;
    let flip = |envelope: &[u8]| {
        let mut envelope = envelope.to_vec();
        let last = envelope.len() - 1;
        envelope[last] ^= 1;
        envelope
    };
    // A flipped tag in the content or proof envelope does not authenticate.
    let content = flip(cow1.content_envelope());
    let proof = flip(cow1.proof_envelope());
    for (content, proof) in [
        (content.as_slice(), cow1.proof_envelope()),
        (cow1.content_envelope(), proof.as_slice()),
    ] {
        let tampered = CommunityProtectedObjectV1::new(content, proof)?.to_canonical_cbor();
        let mut records = batch_records(graph);
        records[0].object = &tampered;
        assert_eq!(prepare(&records), Some(Error::EvidenceUnavailable));
    }
    // A COW1 that does not decode.
    let mut records = batch_records(graph);
    records[0].object = &object[..object.len() - 1];
    assert_eq!(prepare(&records), Some(Error::InvalidEncoding));
    // Another record's ARD1, or the ARD1 of an altered child list.
    let mut records = batch_records(graph);
    records[0].registration = graph.records()[1].protected().registration();
    assert_eq!(prepare(&records), Some(Error::InvalidBinding));
    Ok(())
}

#[test]
fn the_extractor_refuses_an_incomplete_or_extended_closure() -> TestResult {
    let mut assembled = assembled(&Fixture::new()?)?;
    let extra = assembled.protector.protect(
        Kind::StateContent,
        &CommunityStateContentV1::new(SCHEMA, b"extra")?.to_canonical_cbor(),
        CommunityRecordEvidenceV1 {
            owner_binding_digest: COB,
            host_provenance_digest: CPV,
            children: &[],
        },
    )?;
    let graph = &assembled.graph;
    let prepare = |records: &[CommunityArtifactRecordInputV1<'_>], root: &[u8]| {
        prepare_community_artifact_batch_v1(
            &SEAL,
            batch_input(&assembled, records, root),
            &[&assembled.protector],
        )
        .err()
    };
    let root = graph.graph_root();
    // A missing child: slot 0's CSC1 is absent.
    let records = batch_records(graph);
    assert_eq!(prepare(&records[1..], root), Some(Error::InvalidBinding));
    // An authenticated record outside the closure.
    let mut records = batch_records(graph);
    records.push(CommunityArtifactRecordInputV1 {
        object: extra.object(),
        registration: extra.registration(),
    });
    assert_eq!(prepare(&records, root), Some(Error::InvalidBinding));
    // A root set that leaves slot 1 unreached, even with matching counts.
    let records = batch_records(graph);
    let (roots, counts) = roots_and_counts(graph)?;
    let one_root = root_with(graph, &roots[..1], counts)?;
    assert_eq!(prepare(&records, &one_root), Some(Error::InvalidBinding));
    // A root that names no `StateRevision` node.
    let unknown = CommunityNativeNodeReferenceV1 {
        node_digest: hash(0x77),
        ..roots[0]
    };
    let unknown_root = root_with(graph, &[unknown, roots[1]], counts)?;
    assert_eq!(
        prepare(&records, &unknown_root),
        Some(Error::InvalidBinding)
    );
    // Item 6: every count must be the exact ARD1-graph count.
    for index in 0..6 {
        let mut values = [
            counts.registrations,
            counts.edges,
            counts.keys,
            counts.maximum_depth,
            counts.registration_bytes,
            counts.artifact_bytes,
        ];
        values[index] += 1;
        let altered = CommunityGraphCountsV1 {
            registrations: values[0],
            edges: values[1],
            keys: values[2],
            maximum_depth: values[3],
            registration_bytes: values[4],
            artifact_bytes: values[5],
        };
        let wrong = root_with(graph, &roots, altered)?;
        assert_eq!(
            prepare(&records, &wrong),
            Some(Error::InvalidBinding),
            "count {index}"
        );
    }
    Ok(())
}

#[test]
fn the_extractor_refuses_another_store_profile_head_or_request() -> TestResult {
    let other = assembled(&Fixture::with_seed(1)?)?;
    let assembled = assembled(&Fixture::new()?)?;
    let graph = &assembled.graph;
    let records = batch_records(graph);
    let input = batch_input(&assembled, &records, graph.graph_root());
    let prepare =
        |input| prepare_community_artifact_batch_v1(&SEAL, input, &[&assembled.protector]).err();
    let cases = [
        CommunityArtifactBatchInputV1 {
            store_incarnation: [0x5b; 16],
            ..input
        },
        CommunityArtifactBatchInputV1 {
            profile_digest: hash(0x78),
            ..input
        },
        // A valid CSH1 that this CGR1 does not select.
        CommunityArtifactBatchInputV1 {
            selected_head: other.graph.selected_head(),
            ..input
        },
        // Another COB1 than every CAR1 and CSR1 binds.
        CommunityArtifactBatchInputV1 {
            owner_binding_digest: hash(0x79),
            ..input
        },
        // Note 22661, items 1 and 3: another CGI1 operation or authorization.
        CommunityArtifactBatchInputV1 {
            operation_id: [0x11; 16],
            ..input
        },
        CommunityArtifactBatchInputV1 {
            authorization_ref: ArtifactRefV1 {
                digest: [0x52; 32],
                ..AUTHORIZATION
            },
            ..input
        },
    ];
    for (index, case) in cases.into_iter().enumerate() {
        assert_eq!(prepare(case), Some(Error::InvalidBinding), "case {index}");
    }
    // Bytes that are not a CSH1.
    let not_a_head = CommunityArtifactBatchInputV1 {
        selected_head: graph.host_progress(),
        ..input
    };
    assert_eq!(prepare(not_a_head), Some(Error::InvalidEncoding));
    Ok(())
}
