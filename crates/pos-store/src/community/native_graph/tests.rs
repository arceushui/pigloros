//! The encrypted records of an initialization graph decrypt to the exact
//! CSC1, CIS1, CSR1 and CPN1s of the owner decision on #560, note 22661, and
//! a refused graph burns no encryption credit.
//!
//! Decryption has no public API, so these checks live beside the key. Every
//! expected digest is computed with `blake3` from the ADR formula
//! `H(M, bytes)`, not through the production helpers.

use pos_core::community_lifecycle::{
    community_initializer_set_ref_v1, ArtifactRefV1, CommunityArtifactKindV1 as Kind,
    CommunityArtifactOperationV1 as Operation, CommunityArtifactPurposeV1 as Purpose,
    CommunityContentReferenceV1, CommunityDigestListV1, CommunityDurableBackendV1,
    CommunityDurableProfileInputV1, CommunityDurableProfileV1, CommunityGraphRootV1,
    CommunityInitializationProducerV1, CommunityInitializationRequestInputV1,
    CommunityInitializationRequestV1, CommunityInitializationSourceV1, CommunityInputIndexV1,
    CommunityLifecycleErrorV1, CommunityLocatorProducerV1, CommunityMemberBindingInputV1,
    CommunityMemberBindingV1, CommunityMemberProgressV1, CommunityMemberSlotsV1,
    CommunityMetadataLocatorV1, CommunityMetadataSchemaV1, CommunityNativeNodeKindV1,
    CommunityNativeNodeReferenceV1, CommunityNativeNodeV1, CommunityProducerBindingV1,
    CommunityProfileMemberV1, CommunityProfileRetentionV1, CommunityProtectedObjectV1,
    CommunityRecordKindsV1, CommunitySharedCountsV1, CommunityStateContentV1,
    CommunityStateProducerV1, CommunityStateRevisionV1, CommunityTypedInputRefV1,
};
use pos_core::{
    AuthorityTrustRootSealV1, Hash, ImplementationKeyV1, RecordedDependencyClassV1, Seq, TimelineId,
};
use ulid::Ulid;
use zeroize::Zeroizing;

use super::super::initializer::CommunityInitializerOwnerV1;
use super::super::pass_state::CommunityPassStateV1;
use super::super::protection::{CommunityArtifactProtectorV1, CommunityProtectionCohortV1};
use super::{
    CommunityInitializationGraphInputV1, CommunityInitializationGraphV1,
    CommunityInitializationMemberV1,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const SEAL: AuthorityTrustRootSealV1 = AuthorityTrustRootSealV1::for_composition_root();
const INCARNATION: [u8; 16] = [0x5a; 16];
const OPERATION: [u8; 16] = [0x10; 16];
const GENERATION: [u8; 16] = [0x20; 16];
const PRODUCER: u64 = 7;
const HORIZON: u64 = 900;
const SCHEMA: Hash = Hash::from_bytes([0x22; 32]);
const COB: Hash = Hash::from_bytes([0x40; 32]);
const CPV: Hash = Hash::from_bytes([0x41; 32]);
const SCOPE_COVER: Hash = Hash::from_bytes([0x42; 32]);
const AUTHORIZATION: [u8; 32] = [0x51; 32];
const ENTRIES: [&str; 2] = ["Entry-A_1", "Entry-B_1"];

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

fn initializer(state: &[u8]) -> ArtifactRefV1 {
    ArtifactRefV1 {
        schema_id: 0x4353_0001,
        byte_length: state.len() as u64,
        digest: *adr_h("CSC1", state).as_bytes(),
    }
}

/// The outcome of assembling the two-member graph: the graph or its
/// refusal, the decrypted records, the facts the checks compare against and
/// the credits the protector burned.
struct Assembled {
    graph: Result<CommunityInitializationGraphV1, CommunityLifecycleErrorV1>,
    plaintexts: Vec<Zeroizing<Vec<u8>>>,
    states: [Vec<u8>; 2],
    member_digests: Vec<Hash>,
    request_digest: Hash,
    burned: u32,
}

fn profile<'a>(
    rows: &'a [CommunityProfileMemberV1<'a>],
) -> Result<CommunityDurableProfileV1<'a>, CommunityLifecycleErrorV1> {
    CommunityDurableProfileV1::new(CommunityDurableProfileInputV1 {
        backend: CommunityDurableBackendV1::RetainedMemory,
        execution_profile_digest: hash(1),
        roster: rows,
        source_catalogue_digest: hash(2),
        authority_catalogue_digest: hash(9),
        retention: CommunityProfileRetentionV1 {
            generation_not_after_micros: 1_000,
            recovery_window_micros: 1,
            quarantine_not_after_micros: 1_000,
            metadata_not_after_micros: 1_000,
            recording_not_after_micros: 1_000,
        },
    })
}

fn request<'a>(
    profile: &CommunityDurableProfileV1<'_>,
    digests: &'a [Hash],
) -> Result<CommunityInitializationRequestV1<'a>, CommunityLifecycleErrorV1> {
    CommunityInitializationRequestV1::new(CommunityInitializationRequestInputV1 {
        operation_id: OPERATION,
        timeline: timeline(),
        generation: GENERATION,
        expected_prior_generation: None,
        expected_prior_head_digest: None,
        profile_digest: profile.digest(),
        member_binding_digests: CommunityDigestListV1::from_digests(digests),
        initial_source: CommunityInitializationSourceV1::Initializer(
            community_initializer_set_ref_v1(profile),
        ),
        principal_ref: ArtifactRefV1 {
            schema_id: 0x4341_0003,
            byte_length: 40,
            digest: [0x50; 32],
        },
        authorization_ref: ArtifactRefV1 {
            schema_id: 0x4341_0002,
            byte_length: 41,
            digest: AUTHORIZATION,
        },
        evidence_not_after_micros: 1_000,
    })
}

fn protector() -> Result<CommunityArtifactProtectorV1, CommunityLifecycleErrorV1> {
    CommunityMemberSlotsV1::new(&[0, 1]).and_then(|member_slots| {
        CommunityArtifactProtectorV1::provision(
            &SEAL,
            CommunityProtectionCohortV1 {
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
                member_slots,
                authority_request_digest: hash(0x44),
            },
        )
    })
}

fn states() -> Result<[Vec<u8>; 2], CommunityLifecycleErrorV1> {
    Ok([
        CommunityStateContentV1::new(SCHEMA, b"state-a")?
            .to_canonical_cbor()
            .to_vec(),
        CommunityStateContentV1::new(SCHEMA, b"state-b")?
            .to_canonical_cbor()
            .to_vec(),
    ])
}

fn rows<'a>(
    implementation: &'a ImplementationKeyV1,
    states: &[Vec<u8>; 2],
) -> Result<Vec<CommunityProfileMemberV1<'a>>, CommunityLifecycleErrorV1> {
    (0..2)
        .map(|slot| {
            CommunityProfileMemberV1::new(
                ENTRIES[slot],
                implementation,
                hash(4),
                SCHEMA,
                hash(6),
                initializer(&states[slot]),
                10,
            )
        })
        .collect()
}

fn bindings<'a>(
    implementation: &'a ImplementationKeyV1,
    states: &[Vec<u8>; 2],
) -> Result<Vec<CommunityMemberBindingV1<'a>>, CommunityLifecycleErrorV1> {
    (0..2)
        .map(|slot| {
            CommunityMemberBindingV1::new(CommunityMemberBindingInputV1 {
                stable_entry: ENTRIES[slot],
                implementation,
                pmf1_digest: hash(4),
                state_schema_digest: SCHEMA,
                negotiated_tuple_digest: hash(6),
                initial_state_content_digest: adr_h("CSC1", &states[slot]),
                protected_owner_binding_digest: COB,
            })
        })
        .collect()
}

/// Decrypt every record of an assembled graph; a refused graph has none.
fn open_records(
    graph: &Result<CommunityInitializationGraphV1, CommunityLifecycleErrorV1>,
    protector: &CommunityArtifactProtectorV1,
) -> Result<Vec<Zeroizing<Vec<u8>>>, CommunityLifecycleErrorV1> {
    graph.as_ref().map_or_else(
        |_| Ok(Vec::new()),
        |graph| {
            graph
                .records()
                .iter()
                .map(|record| {
                    CommunityProtectedObjectV1::from_canonical_cbor(record.protected().object())
                        .and_then(|object| protector.open_envelope(object.content_envelope()))
                })
                .collect()
        },
    )
}

fn assemble(producer_ordinal: u64) -> Result<Assembled, Box<dyn std::error::Error>> {
    let implementation = ImplementationKeyV1::new("plugin-a".into(), "host-v1".into(), hash(3))?;
    let states = states()?;
    let rows = rows(&implementation, &states)?;
    let profile = profile(&rows)?;
    assemble_profile(producer_ordinal, &implementation, &profile, states)
}

/// Bind both members of `profile` to one request and assemble its graph.
fn assemble_profile(
    producer_ordinal: u64,
    implementation: &ImplementationKeyV1,
    profile: &CommunityDurableProfileV1<'_>,
    states: [Vec<u8>; 2],
) -> Result<Assembled, Box<dyn std::error::Error>> {
    let bindings = bindings(implementation, &states)?;
    let member_digests: Vec<Hash> = bindings
        .iter()
        .map(CommunityMemberBindingV1::digest)
        .collect();
    let request = request(profile, &member_digests)?;
    let members: Vec<CommunityInitializationMemberV1<'_>> = bindings
        .iter()
        .zip([0x60, 0x61])
        .map(|(binding, address)| CommunityInitializationMemberV1 {
            binding,
            binding_envelope_address: hash(address),
        })
        .collect();
    let input = CommunityInitializationGraphInputV1 {
        store_incarnation: INCARNATION,
        producer_ordinal,
        request: &request,
        profile,
        members: &members,
        owner_binding_digest: COB,
        host_provenance_digest: CPV,
        event_logical_head: Seq::from_u64(12),
    };
    let (graph, plaintexts, burned) = assemble_input(input, profile, &states)?;
    Ok(Assembled {
        graph,
        plaintexts,
        states,
        member_digests: member_digests.clone(),
        request_digest: request.digest(),
        burned,
    })
}

/// The graph `input` assembles or its refusal, its decrypted records and
/// the credits the protector burned.
type AssembledInput = (
    Result<CommunityInitializationGraphV1, CommunityLifecycleErrorV1>,
    Vec<Zeroizing<Vec<u8>>>,
    u32,
);

fn assemble_input(
    input: CommunityInitializationGraphInputV1<'_>,
    profile: &CommunityDurableProfileV1<'_>,
    states: &[Vec<u8>; 2],
) -> Result<AssembledInput, CommunityLifecycleErrorV1> {
    let owner = CommunityInitializerOwnerV1::new(
        &SEAL,
        profile,
        states
            .iter()
            .map(|state| Zeroizing::new(state.clone()))
            .collect(),
    )?;
    let mut protector = protector()?;
    let graph = CommunityInitializationGraphV1::assemble(&SEAL, input, &owner, &mut protector);
    let plaintexts = open_records(&graph, &protector)?;
    Ok((graph, plaintexts, protector.burned_credits()))
}

/// One member's decrypted records and the facts they must bind.
struct Member<'a> {
    slot: u16,
    state: &'a [u8],
    binding_digest: Hash,
    request_digest: Hash,
    state_record: &'a [u8],
    producer_record: &'a [u8],
    revision_record: &'a [u8],
    initial: &'a [u8],
    revision: &'a [u8],
}

/// CSC1 is the initializer State; CIS1 and CSR1 bind it to the request.
fn check_state_records(member: &Member<'_>) -> TestResult {
    assert_eq!(member.state_record, member.state);
    let producer = CommunityInitializationProducerV1::from_canonical_cbor(member.producer_record)?;
    let fields = producer.as_input();
    assert_eq!(fields.generation_request_digest, member.request_digest);
    assert_eq!(fields.member_binding_digest, member.binding_digest);
    assert_eq!(fields.initializer_ref, initializer(member.state));
    assert_eq!(fields.state_content_digest, adr_h("CSC1", member.state));
    assert_eq!(fields.scope_binding_digest, SCOPE_COVER);
    assert_eq!(fields.evidence_not_after_micros, HORIZON);

    let state_revision = CommunityStateRevisionV1::from_canonical_cbor(member.revision_record)?;
    let fields = state_revision.as_input();
    assert!(
        fields.producer_origin
            == CommunityStateProducerV1::Initialization {
                generation_request_digest: member.request_digest,
                operation_id: OPERATION,
            }
    );
    assert_eq!(fields.member_binding_digest, member.binding_digest);
    assert_eq!(fields.predecessor_revision_digest, None);
    assert_eq!(fields.state_content_digest, adr_h("CSC1", member.state));
    assert_eq!(
        fields.producer_digest,
        adr_h("CIS1", member.producer_record)
    );
    assert_eq!(fields.protected_owner_binding_digest, COB);
    assert_eq!(fields.evidence_not_after_micros, HORIZON);
    Ok(())
}

fn direct_inputs<'a>(
    node: &CommunityNativeNodeV1<'a>,
) -> Result<Vec<CommunityTypedInputRefV1<'a>>, Box<dyn std::error::Error>> {
    let CommunityInputIndexV1::Direct(inputs) = node.as_input().input_index else {
        return Err("a direct input index".into());
    };
    Ok(inputs.iter().collect::<Result<_, _>>()?)
}

/// Note 22661, items 1 to 3: node 2·slot is the `InitialState` over CIS1,
/// citing the CMB1 by variant 3; node 2·slot+1 is the `StateRevision` over
/// CSR1, citing node 2·slot. Returns the `StateRevision` reference.
fn check_nodes(
    member: &Member<'_>,
) -> Result<CommunityNativeNodeReferenceV1, Box<dyn std::error::Error>> {
    let ordinal = u32::from(member.slot) * 2;
    let node = CommunityNativeNodeV1::from_canonical_cbor(member.initial)?;
    let fields = node.as_input();
    assert_eq!(fields.store_incarnation, INCARNATION);
    assert_eq!(fields.producer_ordinal, PRODUCER);
    assert_eq!(fields.node_ordinal, ordinal);
    assert!(fields.kind == CommunityNativeNodeKindV1::InitialState);
    assert!(fields.content == content(*b"CIS1", adr_h("CIS1", member.producer_record)));
    assert_eq!(
        fields.dependency_class,
        RecordedDependencyClassV1::EndogenousRecomputed
    );
    assert!(
        direct_inputs(&node)?
            == [CommunityTypedInputRefV1::Metadata {
                schema: CommunityMetadataSchemaV1::Cmb1,
                locator: CommunityMetadataLocatorV1 {
                    timeline: timeline(),
                    generation: GENERATION,
                    producer: CommunityLocatorProducerV1::Control(OPERATION),
                    record_role: 11,
                    slot: member.slot,
                },
                envelope_address: hash(0x60 + u8::try_from(member.slot)?),
                private_record_digest: member.binding_digest,
            }]
    );
    assert_eq!(fields.scope_binding_digest, SCOPE_COVER);
    assert_eq!(fields.authorization_digest, Hash::from_bytes(AUTHORIZATION));
    assert_eq!(fields.provenance_digest, CPV);
    assert_eq!(fields.evidence_not_after_micros, HORIZON);
    let initial_reference = reference(ordinal, member.initial);

    let node = CommunityNativeNodeV1::from_canonical_cbor(member.revision)?;
    let fields = node.as_input();
    assert_eq!(fields.node_ordinal, ordinal + 1);
    assert!(fields.kind == CommunityNativeNodeKindV1::StateRevision);
    assert!(fields.content == content(*b"CSR1", adr_h("CSR1", member.revision_record)));
    assert!(direct_inputs(&node)? == [CommunityTypedInputRefV1::Native(initial_reference)]);
    assert_eq!(fields.authorization_digest, Hash::from_bytes(AUTHORIZATION));
    Ok(reference(ordinal + 1, member.revision))
}

const fn content(record_magic: [u8; 4], logical_digest: Hash) -> CommunityContentReferenceV1 {
    CommunityContentReferenceV1 {
        record_magic,
        logical_digest,
    }
}

fn reference(node_ordinal: u32, node: &[u8]) -> CommunityNativeNodeReferenceV1 {
    CommunityNativeNodeReferenceV1 {
        store_incarnation: INCARNATION,
        producer_ordinal: PRODUCER,
        node_ordinal,
        node_digest: adr_h("CPN1", node),
    }
}

#[test]
fn records_decrypt_to_the_decided_initial_graph() -> TestResult {
    let assembled = assemble(PRODUCER)?;
    let graph = assembled.graph?;
    assert_eq!(graph.request_digest(), assembled.request_digest);
    // Five records per member, two credits each.
    assert_eq!(assembled.plaintexts.len(), 10);
    assert_eq!(assembled.burned, 20);
    let root = CommunityGraphRootV1::from_canonical_cbor(graph.graph_root())?;
    let roots: Vec<CommunityNativeNodeReferenceV1> =
        root.as_input().roots.iter().collect::<Result<_, _>>()?;
    let progress: Vec<&[u8]> = graph.member_progress().collect();

    for (slot, records) in (0_u16..).zip(assembled.plaintexts.chunks(5)) {
        let index = usize::from(slot);
        let [state_record, producer_record, revision_record, initial, revision] = records else {
            return Err("five records per member".into());
        };
        let member = Member {
            slot,
            state: &assembled.states[index],
            binding_digest: assembled.member_digests[index],
            request_digest: assembled.request_digest,
            state_record,
            producer_record,
            revision_record,
            initial,
            revision,
        };
        check_state_records(&member)?;
        // Item 5: the root is the `StateRevision` node; CMS1 names its CSR1.
        assert!(roots[index] == check_nodes(&member)?);
        let member_progress = CommunityMemberProgressV1::from_canonical_cbor(progress[index])?;
        assert_eq!(
            member_progress.as_input().state_revision_digest,
            adr_h("CSR1", revision_record)
        );
    }
    Ok(())
}

#[test]
fn a_refused_graph_burns_no_credit() -> TestResult {
    let assembled = assemble(0)?;
    assert_eq!(
        assembled.graph.err(),
        Some(CommunityLifecycleErrorV1::InvalidBinding)
    );
    assert_eq!(assembled.burned, 0);
    Ok(())
}

/// Owner decision on #560, note 22661, item 7, rebuilt for the 2c planner:
/// the crate-private CMI1 builder takes the COA1 address from its caller,
/// covers the COW1 families only, and binds CIS1 to its `InitialState`
/// node, CSC1 and CSR1 to the `StateRevision` node and each CPN1 to the
/// control request `H(CGI1)`.
#[test]
fn each_record_materializes_with_its_decided_producer() -> TestResult {
    let assembled = assemble(PRODUCER)?;
    let graph = assembled.graph?;
    let records = graph.records();
    assert_eq!(records.len(), assembled.plaintexts.len());
    for (index, (record, plaintext)) in records.iter().zip(&assembled.plaintexts).enumerate() {
        let slot = u16::try_from(index / 5)?;
        let member = &assembled.plaintexts[index - index % 5..][..5];
        let ordinal = u32::from(slot) * 2;
        let initial = CommunityProducerBindingV1::Native(reference(ordinal, &member[3]));
        let revision = CommunityProducerBindingV1::Native(reference(ordinal + 1, &member[4]));
        let (magic, producer) = match index % 5 {
            0 => (*b"CSC1", revision),
            1 => (*b"CIS1", initial),
            2 => (*b"CSR1", revision),
            _ => (
                *b"CPN1",
                CommunityProducerBindingV1::Control(assembled.request_digest),
            ),
        };
        let attestation = hash(0x90 + u8::try_from(index)?);
        let materialization =
            record.materialization(INCARNATION, timeline(), GENERATION, attestation)?;
        let fields = materialization.as_input();
        assert_eq!(fields.store_incarnation, INCARNATION);
        assert_eq!(fields.timeline, timeline());
        assert_eq!(fields.generation, GENERATION);
        assert_eq!(fields.record_magic, magic);
        let domain = std::str::from_utf8(&magic)?;
        assert_eq!(fields.logical_record_digest, adr_h(domain, plaintext));
        assert_eq!(fields.plaintext_length, plaintext.len() as u64);
        let registration = record.protected().registration();
        let reference = fields.materialization;
        assert_eq!(
            reference.owner_reference,
            registration.fields().owner_reference
        );
        assert_eq!(
            reference.artifact_class,
            pos_core::ErasureArtifactClassV1::TimelineReplay
        );
        assert_eq!(
            reference.object_address,
            record.protected().object_address()
        );
        assert_eq!(
            reference.artifact_digest,
            registration.fields().artifact_digest
        );
        assert_eq!(reference.registration_address, registration.address());
        assert_eq!(reference.attestation_address, attestation);
        assert!(fields.producer == producer);
        assert_eq!(fields.scope_binding_digest, SCOPE_COVER);
        assert_eq!(fields.evidence_not_after_micros, HORIZON);
    }
    Ok(())
}

/// ADR-129 revision 10, R10.3(6) and revision 11, R11.3(1): the seeded
/// counters are the history's plus the initialization's own additions (its
/// four CPN1 nodes, two per member, and as many edges, its records' plaintext bytes), and the
/// selected graph is the CGR1's `graph_counts`.
#[test]
fn the_initial_pass_state_adds_the_initialization_to_the_history() -> TestResult {
    let assembled = assemble(PRODUCER)?;
    let graph = assembled.graph?;
    let history = CommunitySharedCountsV1 {
        nodes: 10,
        edges: 20,
        declared_inputs: 30,
        encoded_record_bytes: 40,
    };
    let state = CommunityPassStateV1::initialized([0x20; 16], history, &graph);
    assert_eq!(state.generation, [0x20; 16]);
    assert_eq!(state.head, graph.selected_head_digest());
    let bytes: u64 = assembled
        .plaintexts
        .iter()
        .map(|plaintext| plaintext.len() as u64)
        .sum();
    assert!(
        state.counters
            == CommunitySharedCountsV1 {
                nodes: 14,
                edges: 24,
                declared_inputs: 30,
                encoded_record_bytes: 40 + bytes,
            }
    );
    assert_eq!(state.graph, graph.graph_counts());
    assert_eq!(state.graph.registrations, 10);
    assert!(state.closure.is_empty() && state.generations.is_empty());
    Ok(())
}
