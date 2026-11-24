//! The pass CBQ1 quote and dueness through their public seams (ADR-129
//! revision 10, R10.1, R10.3 and R10.4(1); I85, I89 and I91).
//!
//! Every expected quote is rebuilt independently: the test mints each record
//! the R10.3(5) table names through its own public constructor, with every
//! unallocated ordinal, unknown count and unknown horizon at its widest
//! value, and sums the actual encoded lengths.

use pos_core::community_lifecycle::{
    community_member_due_v1, ArtifactRefV1, CommunityAnnotationOmissionV1 as Omission,
    CommunityAnnotationOmissionsV1, CommunityArtifactChildrenV1, CommunityArtifactHeaderInputV1,
    CommunityArtifactHeaderV1, CommunityArtifactKindV1 as ArtifactKind,
    CommunityArtifactOperationV1, CommunityArtifactPurposeV1, CommunityClassificationProofInputV1,
    CommunityClassificationProofV1, CommunityContentReferenceV1, CommunityEncryptedEnvelopeV1,
    CommunityEventDraftFragmentInputV1, CommunityEventDraftFragmentReferenceV1,
    CommunityEventDraftFragmentV1, CommunityEventDraftManifestInputV1,
    CommunityEventDraftManifestV1, CommunityGraphCountsV1, CommunityInputGroupInputV1,
    CommunityInputGroupV1, CommunityInputIndexV1, CommunityInvocationEvidenceInputV1,
    CommunityInvocationEvidenceV1, CommunityInvocationStepV1, CommunityLifecycleErrorV1 as Error,
    CommunityMaterializationReferenceV1, CommunityMemberBindingInputV1, CommunityMemberBindingV1,
    CommunityNativeNodeInputV1, CommunityNativeNodeKindV1 as Kind, CommunityNativeNodeReferenceV1,
    CommunityNativeNodeReferencesV1, CommunityNativeNodeV1, CommunityOutputUsageV1,
    CommunityPassDomainV1, CommunityPassGraphTermsV1, CommunityPassKeyV1,
    CommunityPassObservationV1, CommunityPassQuoteInputV1, CommunityPassQuoteMemberV1,
    CommunityPassQuoteV1, CommunityPassTermsV1, CommunityPreparedInvocationInputV1,
    CommunityPreparedInvocationV1, CommunityProtectedObjectV1, CommunityProtectionSizesV1,
    CommunityReplayMemberBindingV1, CommunityReplayMemberV1, CommunityReplayRecordingInputV1,
    CommunityReplayRecordingV1, CommunitySharedCountsV1, CommunitySourceClosureInputV1,
    CommunitySourceClosureV1, CommunityStateContentV1, CommunityStateProducerV1,
    CommunityStateRevisionInputV1, CommunityStateRevisionV1, CommunityTypedInputRefV1 as TypedRef,
    CommunityTypedInputRefsV1, MeteringV1, TimelinePositionV1,
    COMMUNITY_CUMULATIVE_RECORD_LIMITS_V1, COMMUNITY_ERASURE_TARGET_LINE_V1,
    COMMUNITY_MAXIMUM_STORE_KEYS_V1, COMMUNITY_SHARED_RECORD_LIMITS_V1,
};
use pos_core::{
    ArtifactChildEdgeV1, ArtifactDataClassV1, ArtifactKeyDependencyV1, ArtifactOptionalityV1,
    ArtifactRegistrationFieldsV1, ArtifactRegistrationV1, ArtifactTransitionRuleV1,
    ErasureArtifactClassV1, Hash, ImplementationKeyV1, KeyRoleV1, RecordedDependencyClassV1,
    TimelineId,
};

type Fallible<T> = Result<T, Box<dyn std::error::Error>>;
type TestResult = Fallible<()>;

const T: TimelineId = TimelineId::from_ulid(ulid::Ulid::from_bytes([1; 16]));
const G: [u8; 16] = [2; 16];
const INCARNATION: [u8; 16] = [3; 16];
const HORIZON: u64 = u64::MAX / 2;
const SCHEMA: Hash = hash(5);
const STATE_LIMIT: u64 = 4096;
/// The minted observation's node ordinal and terms in the fixtures.
const OBSERVATION: CommunityPassObservationV1 = CommunityPassObservationV1 {
    terms: CommunityPassTermsV1 {
        nodes: 1,
        edges: 1,
        bytes: 700,
    },
    node_ordinal: 0,
};

const fn hash(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
}

fn indexed(index: usize) -> Hash {
    let mut bytes = [9; 32];
    bytes[..8].copy_from_slice(&(index as u64).to_be_bytes());
    Hash::from_bytes(bytes)
}

fn key() -> Fallible<ImplementationKeyV1> {
    Ok(ImplementationKeyV1::new(
        "plugin-a".into(),
        "host-v1".into(),
        hash(4),
    )?)
}

fn pass_key() -> Fallible<CommunityPassKeyV1> {
    Ok(CommunityPassKeyV1::new(T, G, u64::MAX)?)
}

/// `count` committed artifact refs in canonical order.
fn artifact_refs(count: usize) -> Vec<TypedRef<'static>> {
    (0..count)
        .map(|index| TypedRef::Artifact {
            owner_reference: hash(10),
            artifact_class: ErasureArtifactClassV1::TimelineReplay,
            artifact_digest: indexed(index),
            registration_address: hash(11),
            source_scope_binding_digest: hash(12),
        })
        .collect()
}

const fn reference(index: u32) -> ArtifactRefV1 {
    ArtifactRefV1 {
        schema_id: index,
        byte_length: 40,
        digest: [7; 32],
    }
}

fn invocation(member: Hash, payload: &[u8]) -> CommunityPreparedInvocationInputV1<'_> {
    CommunityPreparedInvocationInputV1 {
        member_binding_digest: member,
        invocation_id: [8; 16],
        timeline_position: TimelinePositionV1 {
            timeline_id: T.inner().to_bytes(),
            seq: 300,
            tick: 7,
            scheduler_position: 2,
        },
        output_base_ordinal: 2,
        principal_ref: reference(0x4341_0003),
        authorization_ref: reference(0x4341_0002),
        observation_snapshot_ref: reference(9),
        observation_bytes: payload,
        prior_state_schema_digest: *SCHEMA.as_bytes(),
        prior_state_bytes: &payload[..payload.len() / 2],
        execution_profile_digest: [13; 32],
        trust_policy_snapshot_digest: [14; 32],
        deterministic_budget_id: "budget-a",
        deterministic_random_domain: [15; 32],
        provenance_root: [16; 32],
        simulation_time: 1_000,
        watchdog_epochs: 3,
    }
}

fn binding<'a>(
    key: &'a ImplementationKeyV1,
    entry: &'a str,
) -> Fallible<CommunityMemberBindingV1<'a>> {
    Ok(CommunityMemberBindingV1::new(
        CommunityMemberBindingInputV1 {
            stable_entry: entry,
            implementation: key,
            pmf1_digest: hash(20),
            state_schema_digest: SCHEMA,
            negotiated_tuple_digest: hash(21),
            initial_state_content_digest: hash(22),
            protected_owner_binding_digest: hash(23),
        },
    )?)
}

fn node(
    ordinal: u32,
    kind: Kind,
    magic: [u8; 4],
    class: RecordedDependencyClassV1,
    index: CommunityInputIndexV1<'_>,
) -> Fallible<usize> {
    Ok(CommunityNativeNodeV1::new(CommunityNativeNodeInputV1 {
        store_incarnation: INCARNATION,
        timeline: T,
        generation: G,
        producer_ordinal: u64::MAX,
        node_ordinal: ordinal,
        kind,
        content: CommunityContentReferenceV1 {
            record_magic: magic,
            logical_digest: hash(30),
        },
        dependency_class: class,
        input_index: index,
        scope_binding_digest: hash(31),
        authorization_digest: hash(32),
        provenance_digest: hash(33),
        evidence_not_after_micros: HORIZON,
    })?
    .to_canonical_cbor()
    .len())
}

const fn native(producer: u64, ordinal: u32) -> CommunityNativeNodeReferenceV1 {
    CommunityNativeNodeReferenceV1 {
        store_incarnation: INCARNATION,
        producer_ordinal: producer,
        node_ordinal: ordinal,
        node_digest: hash(34),
    }
}

/// The independently rebuilt `InvocationStep` and `StateRevision` rows of one
/// member whose complete CIR1 is `inputs`.
fn rebuilt_state(
    member: &CommunityMemberBindingV1<'_>,
    payload: &[u8],
    inputs: &[TypedRef<'_>],
) -> Fallible<CommunityPassTermsV1> {
    rebuilt_member(member, payload, inputs).map(|(terms, _)| terms)
}

/// The number of a ref list's mode-0 and mode-2 refs, each an ARD1 edge.
fn registered(inputs: &[TypedRef<'_>]) -> u64 {
    inputs
        .iter()
        .filter(|input| matches!(input, TypedRef::Native(_) | TypedRef::Artifact { .. }))
        .count() as u64
}

/// The rebuilt CIB1 groups and `InputIndex` CPN1s of a step with more than
/// 256 inputs, appended to `records`; their native references.
fn rebuilt_groups(
    inputs: &[TypedRef<'_>],
    records: &mut Vec<(u64, u64)>,
) -> Fallible<Vec<CommunityNativeNodeReferenceV1>> {
    let mut groups = Vec::new();
    if inputs.len() <= 256 {
        return Ok(groups);
    }
    for (chunk, ordinal) in inputs.chunks(256).zip(u32::MAX - 40..) {
        let leaves = CommunityTypedInputRefsV1::from_references(chunk);
        let group = CommunityInputGroupV1::new(CommunityInputGroupInputV1 {
            timeline: T,
            generation: G,
            consumer_content: CommunityContentReferenceV1 {
                record_magic: *b"CPI1",
                logical_digest: hash(37),
            },
            leaves,
        })?;
        records.push((group.to_canonical_cbor().len() as u64, 0));
        let index = node(
            ordinal,
            Kind::InputIndex,
            *b"CIB1",
            RecordedDependencyClassV1::EndogenousRecomputed,
            CommunityInputIndexV1::Direct(leaves),
        )?;
        records.push((index as u64, 1 + registered(chunk)));
        groups.push(native(u64::MAX, ordinal));
    }
    Ok(groups)
}

/// The member's rebuilt R10.3(5) rows and its R11.2(1) closure records as
/// `(plaintext bytes, ARD1 children)`.
fn rebuilt_member(
    member: &CommunityMemberBindingV1<'_>,
    payload: &[u8],
    inputs: &[TypedRef<'_>],
) -> Fallible<(CommunityPassTermsV1, Vec<(u64, u64)>)> {
    let key = pass_key()?;
    let prepared = CommunityPreparedInvocationV1::new(invocation(member.digest(), payload))?;
    let step = CommunityInvocationStepV1::new(key, member, &prepared, hash(35), HORIZON)?;
    let closure = CommunitySourceClosureV1::new(CommunitySourceClosureInputV1 {
        timeline: T,
        generation: G,
        inputs: CommunityTypedInputRefsV1::from_references(inputs),
        source_scope_union_digest: hash(36),
    })?;
    let endogenous = RecordedDependencyClassV1::EndogenousRecomputed;
    let length = |bytes: usize| bytes as u64;
    let mut records = vec![
        (length(closure.to_canonical_cbor().len()), 0),
        (length(prepared.to_canonical_cbor().len()), 1),
        (length(step.to_canonical_cbor().len()), 1),
    ];
    let groups = rebuilt_groups(inputs, &mut records)?;
    let (index, children) = match inputs.len() {
        0 => (CommunityInputIndexV1::Empty, 0),
        1..=256 => (
            CommunityInputIndexV1::Direct(CommunityTypedInputRefsV1::from_references(inputs)),
            registered(inputs),
        ),
        total => (
            CommunityInputIndexV1::Grouped {
                groups: CommunityNativeNodeReferencesV1::from_references(&groups),
                total_leaf_count: total as u64,
            },
            groups.len() as u64,
        ),
    };
    let step_node = node(
        u32::MAX - 1,
        Kind::InvocationStep,
        *b"CPI1",
        endogenous,
        index,
    )?;
    records.push((length(step_node), 1 + children));
    let revision = CommunityStateRevisionV1::new(CommunityStateRevisionInputV1 {
        producer_origin: CommunityStateProducerV1::Pass(key),
        member_binding_digest: member.digest(),
        predecessor_revision_digest: Some(hash(38)),
        state_content_digest: hash(39),
        producer_digest: step.digest(),
        protected_owner_binding_digest: hash(23),
        evidence_not_after_micros: HORIZON,
    })?;
    let single = [TypedRef::Native(native(u64::MAX, u32::MAX - 1))];
    let revision_node = node(
        u32::MAX,
        Kind::StateRevision,
        *b"CSR1",
        endogenous,
        CommunityInputIndexV1::Direct(CommunityTypedInputRefsV1::from_references(&single)),
    )?;
    let state = vec![0; usize::try_from(STATE_LIMIT)?];
    let content = CommunityStateContentV1::new(SCHEMA, &state)?;
    records.push((length(content.to_canonical_cbor().len()), 0));
    records.push((length(revision.to_canonical_cbor().len()), 3));
    records.push((length(revision_node), 3));
    let bytes = records[..records.len() - 3]
        .iter()
        .map(|(bytes, _)| bytes)
        .sum::<u64>()
        + length(revision.to_canonical_cbor().len())
        + STATE_LIMIT
        + length(revision_node);
    Ok((
        CommunityPassTermsV1 {
            nodes: 2 + groups.len() as u64,
            edges: (inputs.len() + groups.len() + 1) as u64,
            bytes,
        },
        records,
    ))
}

fn rebuilt_evidence(member: Hash) -> Fallible<CommunityInvocationEvidenceV1> {
    Ok(CommunityInvocationEvidenceV1::new(
        CommunityInvocationEvidenceInputV1 {
            pass_key: pass_key()?,
            member_binding_digest: member,
            invocation_id: [8; 16],
            negotiated_tuple_digest: hash(21),
            prepared_invocation_digest: hash(40),
            validated_output_digest: hash(41),
            metering: MeteringV1 {
                startup_fuel: u64::MAX,
                call_fuel: u64::MAX,
                memory_bytes: u64::MAX,
                host_calls: u64::MAX,
            },
            output_usage: CommunityOutputUsageV1 {
                event_count: u64::MAX,
                event_payload_bytes: u64::MAX,
                state_bytes: u64::MAX,
            },
            validated_annotation_count: u64::MAX,
            next_state_content_digest: hash(42),
            event_draft_vector_digest: hash(43),
        },
    )?)
}

/// The rebuilt recording rows of `members`: one Measurement CPN1 with its
/// CIV1 per member, and the CRR1 with every count and reason at its widest.
fn rebuilt_recording(members: &[Hash]) -> Fallible<CommunityPassTermsV1> {
    let mut sorted = members.to_vec();
    sorted.sort_by_key(|digest| *digest.as_bytes());
    let evidence = sorted
        .iter()
        .map(|member| rebuilt_evidence(*member))
        .collect::<Fallible<Vec<_>>>()?;
    let single = [TypedRef::Native(native(u64::MAX, u32::MAX - 1))];
    let mut bytes = 0;
    for record in &evidence {
        bytes += record.to_canonical_cbor().len()
            + node(
                u32::MAX,
                Kind::Measurement,
                *b"CIV1",
                RecordedDependencyClassV1::PresentationOnly,
                CommunityInputIndexV1::Direct(CommunityTypedInputRefsV1::from_references(&single)),
            )?;
    }
    let roster: Vec<_> = sorted
        .iter()
        .map(|member| CommunityReplayMemberBindingV1 {
            member_binding_digest: *member,
            negotiated_tuple_digest: hash(21),
        })
        .collect();
    let all = [
        Omission::UnsupportedClaimSchema,
        Omission::InvalidClaim,
        Omission::UnresolvedAnnotationInput,
        Omission::AnnotationBudget,
        Omission::AnnotationPolicy,
    ]
    .into_iter()
    .fold(
        CommunityAnnotationOmissionsV1::none(),
        CommunityAnnotationOmissionsV1::with_reason,
    );
    let replay: Vec<_> = evidence
        .iter()
        .map(|invocation| CommunityReplayMemberV1 {
            invocation,
            retained_annotation_count: u64::MAX - 1,
            omissions: all,
        })
        .collect();
    bytes += CommunityReplayRecordingV1::new(CommunityReplayRecordingInputV1 {
        pass_key: pass_key()?,
        due_roster: &roster,
        members: &replay,
        evidence_not_after_micros: HORIZON,
    })?
    .to_canonical_cbor()
    .len();
    Ok(CommunityPassTermsV1 {
        nodes: members.len() as u64,
        edges: members.len() as u64,
        bytes: bytes as u64,
    })
}

/// The rebuilt CED1 and CEB1 of the empty draft vector.
fn rebuilt_drafts() -> Fallible<u64> {
    let key = pass_key()?;
    let fragment = CommunityEventDraftFragmentV1::new(CommunityEventDraftFragmentInputV1 {
        pass_key: key,
        byte_offset: 0,
        total_plaintext_bytes: 1,
        fragment_bytes: &[0x80],
    })?;
    let manifest = CommunityEventDraftManifestV1::new(CommunityEventDraftManifestInputV1 {
        pass_key: key,
        fragments: vec![CommunityEventDraftFragmentReferenceV1 {
            byte_offset: 0,
            fragment_length: 1,
            fragment_digest: fragment.digest(),
            materialization: CommunityMaterializationReferenceV1 {
                owner_reference: hash(44),
                artifact_class: ErasureArtifactClassV1::TimelineReplay,
                object_address: hash(45),
                artifact_digest: hash(46),
                registration_address: hash(47),
                attestation_address: hash(48),
            },
        }],
        total_plaintext_bytes: 1,
        draft_count: 0,
        draft_vector_digest: hash(49),
    })?;
    Ok((manifest.to_canonical_cbor().len() + fragment.to_canonical_cbor().len()) as u64)
}

const fn add(left: CommunityPassTermsV1, right: CommunityPassTermsV1) -> CommunityPassTermsV1 {
    CommunityPassTermsV1 {
        nodes: left.nodes + right.nodes,
        edges: left.edges + right.edges,
        bytes: left.bytes + right.bytes,
    }
}

/// One fixture member: its CMB1 and its committed step inputs.
struct Fixture {
    key: ImplementationKeyV1,
    entries: Vec<String>,
    payload: Vec<u8>,
}

impl Fixture {
    fn new(members: usize) -> Fallible<Self> {
        Ok(Self {
            key: key()?,
            entries: (0..members)
                .map(|index| format!("entry-{index:02}"))
                .collect(),
            payload: vec![6; 300],
        })
    }

    fn bindings(&self) -> Fallible<Vec<CommunityMemberBindingV1<'_>>> {
        self.entries
            .iter()
            .map(|entry| binding(&self.key, entry))
            .collect()
    }
}

fn quote_member<'a>(
    member: &CommunityMemberBindingV1<'_>,
    payload: &'a [u8],
    inputs: &'a [TypedRef<'a>],
    minted: bool,
) -> CommunityPassQuoteMemberV1<'a> {
    CommunityPassQuoteMemberV1 {
        member_binding_digest: member.digest(),
        negotiated_tuple_digest: hash(21),
        state_limit_bytes: STATE_LIMIT,
        prepared_invocation: invocation(member.digest(), payload),
        step_inputs: inputs,
        consumes_minted_observation: minted,
    }
}

const fn quote_input<'a>(
    members: &'a [CommunityPassQuoteMemberV1<'a>],
    minted: Option<CommunityPassObservationV1>,
) -> CommunityPassQuoteInputV1<'a> {
    CommunityPassQuoteInputV1 {
        timeline: T,
        generation: G,
        profile_digest: hash(50),
        prior_shared_counts: CommunitySharedCountsV1 {
            nodes: 11,
            edges: 12,
            declared_inputs: 13,
            encoded_record_bytes: 14,
        },
        members,
        minted_observation: minted,
    }
}

#[test]
fn a_one_member_quote_equals_the_rebuilt_table_for_every_input_shape() -> TestResult {
    let fixture = Fixture::new(1)?;
    let bindings = fixture.bindings()?;
    let member = &bindings[0];
    let drafts = rebuilt_drafts()?;
    let recording = rebuilt_recording(&[member.digest()])?;
    for committed in [0, 1, 255, 256, 257, 4095, 4096] {
        let refs = artifact_refs(committed);
        for minted in [false, true] {
            if minted && committed == 4096 {
                continue;
            }
            let mut complete = Vec::new();
            if minted {
                complete.push(TypedRef::Native(native(u64::MAX, 0)));
            }
            complete.extend(refs.iter().copied());
            let state = rebuilt_state(member, &fixture.payload, &complete)?;
            let observation = if minted {
                OBSERVATION.terms
            } else {
                CommunityPassTermsV1::default()
            };
            let expected_state = add(
                add(state, observation),
                CommunityPassTermsV1 {
                    nodes: 0,
                    edges: 0,
                    bytes: drafts,
                },
            );
            let members = [quote_member(member, &fixture.payload, &refs, minted)];
            let quote =
                CommunityPassQuoteV1::new(quote_input(&members, minted.then_some(OBSERVATION)))?;
            assert_eq!(quote.state_terms(), expected_state, "{committed} {minted}");
            let total = add(expected_state, recording);
            assert_eq!(quote.total_terms(), total);
            let cbq1 = quote.quote().as_input();
            assert_eq!(
                [
                    cbq1.maximum_required_nodes,
                    cbq1.maximum_required_edges,
                    cbq1.maximum_required_bytes
                ],
                [total.nodes, total.edges, total.bytes]
            );
            assert_eq!(cbq1.prior_shared_counts.nodes, 11);
            assert_eq!(cbq1.profile_digest, hash(50));
            assert_eq!(cbq1.due_members.len(), 1);
            assert_eq!(cbq1.due_members[0].member_binding_digest, member.digest());
            assert_eq!(cbq1.due_members[0].negotiated_tuple_digest, hash(21));
        }
    }
    Ok(())
}

#[test]
fn multi_member_quotes_sum_the_member_rows_in_roster_order() -> TestResult {
    for count in [2, 64] {
        let fixture = Fixture::new(count)?;
        let bindings = fixture.bindings()?;
        let refs = artifact_refs(3);
        let mut complete = vec![TypedRef::Native(native(u64::MAX, 0))];
        complete.extend(refs.iter().copied());
        let members: Vec<_> = bindings
            .iter()
            .map(|member| quote_member(member, &fixture.payload, &refs, true))
            .collect();
        let quote = CommunityPassQuoteV1::new(quote_input(&members, Some(OBSERVATION)))?;
        let mut state = add(
            OBSERVATION.terms,
            CommunityPassTermsV1 {
                nodes: 0,
                edges: 0,
                bytes: rebuilt_drafts()?,
            },
        );
        for member in &bindings {
            state = add(state, rebuilt_state(member, &fixture.payload, &complete)?);
        }
        let digests: Vec<_> = bindings
            .iter()
            .map(CommunityMemberBindingV1::digest)
            .collect();
        assert_eq!(quote.state_terms(), state);
        assert_eq!(
            quote.total_terms(),
            add(state, rebuilt_recording(&digests)?)
        );
        let rows: Vec<_> = quote
            .quote()
            .as_input()
            .due_members
            .iter()
            .map(|row| row.member_binding_digest)
            .collect();
        assert_eq!(rows, digests);
    }
    Ok(())
}

#[test]
fn quote_inputs_outside_the_pinned_shapes_are_refused() -> TestResult {
    let fixture = Fixture::new(1)?;
    let bindings = fixture.bindings()?;
    let member = &bindings[0];
    let full = artifact_refs(4096);
    let over = artifact_refs(4097);
    for (refs, minted) in [(&over[..], false), (&full[..], true)] {
        let members = [quote_member(member, &fixture.payload, refs, minted)];
        assert_eq!(
            CommunityPassQuoteV1::new(quote_input(&members, Some(OBSERVATION))).err(),
            Some(Error::CapacityExhausted)
        );
    }
    let members = [quote_member(member, &fixture.payload, &[], true)];
    assert_eq!(
        CommunityPassQuoteV1::new(quote_input(&members, None)).err(),
        Some(Error::InvalidBinding)
    );
    let mut invalid = quote_member(member, &fixture.payload, &[], false);
    invalid.prepared_invocation.member_binding_digest = Hash::zero();
    assert_eq!(
        CommunityPassQuoteV1::new(quote_input(&[invalid], None)).err(),
        Some(Error::InvalidBinding)
    );
    assert_eq!(
        CommunityPassQuoteV1::new(quote_input(&[], None)).err(),
        Some(Error::BoundsExceeded)
    );
    Ok(())
}

#[test]
fn state_demand_over_a_limit_is_capacity_and_recording_overflow_is_recording() -> TestResult {
    // R10.4(1)-(2) and I91: State demand first (14), then State plus
    // recording demand (19), at every per-record and cumulative boundary.
    let fixture = Fixture::new(1)?;
    let bindings = fixture.bindings()?;
    let member = quote_member(&bindings[0], &fixture.payload, &[], false);
    let base = CommunityPassQuoteV1::new(quote_input(&[member], None))?;
    base.require_fit()?;
    let state = base.state_terms();
    let total = base.total_terms();
    let recording = total.bytes - state.bytes;
    let [_, _, bytes_limit] = COMMUNITY_SHARED_RECORD_LIMITS_V1;
    let [nodes_limit, edges_limit, declared_limit] = COMMUNITY_CUMULATIVE_RECORD_LIMITS_V1;
    let fit = |limit: u64, prior: CommunitySharedCountsV1| -> Fallible<Option<Error>> {
        let mut changed = member;
        changed.state_limit_bytes = STATE_LIMIT + limit;
        let mut input = quote_input(std::slice::from_ref(&changed), None);
        input.prior_shared_counts = prior;
        Ok(CommunityPassQuoteV1::new(input)?.require_fit().err())
    };
    let zero = CommunitySharedCountsV1::default();
    // Bytes: State exactly at P fits as State; the recording then overflows.
    let at_limit = bytes_limit - state.bytes;
    assert_eq!(fit(at_limit, zero)?, Some(Error::RecordingUnavailable));
    assert_eq!(fit(at_limit + 1, zero)?, Some(Error::CapacityExhausted));
    assert_eq!(fit(at_limit - recording, zero)?, None);
    assert_eq!(
        fit(at_limit - recording + 1, zero)?,
        Some(Error::RecordingUnavailable)
    );
    // Cumulative nodes and edges: the recording adds one of each.
    for (nodes, edges) in [(true, false), (false, true)] {
        let prior = |slack: u64| CommunitySharedCountsV1 {
            nodes: if nodes {
                nodes_limit - total.nodes + slack
            } else {
                0
            },
            edges: if edges {
                edges_limit - total.edges + slack
            } else {
                0
            },
            ..zero
        };
        assert_eq!(fit(0, prior(0))?, None);
        assert_eq!(fit(0, prior(1))?, Some(Error::RecordingUnavailable));
        assert_eq!(fit(0, prior(2))?, Some(Error::CapacityExhausted));
    }
    // Declared inputs: a V1 pass adds none, so only the prior counts.
    let declared = |value| CommunitySharedCountsV1 {
        declared_inputs: value,
        ..zero
    };
    assert_eq!(fit(0, declared(declared_limit))?, None);
    assert_eq!(
        fit(0, declared(declared_limit + 1))?,
        Some(Error::CapacityExhausted)
    );
    // Saturating prior counts never wrap into a fit.
    let saturated = CommunitySharedCountsV1 {
        nodes: u64::MAX,
        ..zero
    };
    assert_eq!(fit(0, saturated)?, Some(Error::CapacityExhausted));
    assert_eq!(
        fit(u64::MAX - STATE_LIMIT, zero)?,
        Some(Error::CapacityExhausted)
    );
    Ok(())
}

#[test]
fn per_record_node_and_edge_limits_split_state_from_recording() -> TestResult {
    // 64 members each with 4,095 committed inputs and the minted observation
    // exceed the 65,536-node and 262,144-edge per-record limits only through
    // the State rows, so the result is 14, not 19.
    let fixture = Fixture::new(64)?;
    let bindings = fixture.bindings()?;
    let refs = artifact_refs(4095);
    let members: Vec<_> = bindings
        .iter()
        .map(|member| quote_member(member, &fixture.payload, &refs, true))
        .collect();
    let quote = CommunityPassQuoteV1::new(quote_input(&members, Some(OBSERVATION)))?;
    assert!(quote.state_terms().edges > COMMUNITY_SHARED_RECORD_LIMITS_V1[1]);
    assert_eq!(quote.require_fit().err(), Some(Error::CapacityExhausted));
    Ok(())
}

#[test]
fn dueness_follows_the_committed_step_and_the_cadence_interval() {
    // R10.1(2) and I85.
    for simulation_time in [0, 1, u64::MAX] {
        assert!(community_member_due_v1(None, 10, simulation_time));
    }
    assert!(!community_member_due_v1(Some(100), 10, 100));
    assert!(!community_member_due_v1(Some(100), 10, 109));
    assert!(community_member_due_v1(Some(100), 10, 110));
    assert!(community_member_due_v1(Some(100), 10, 111));
    assert!(!community_member_due_v1(Some(u64::MAX), 1, u64::MAX));
    assert!(!community_member_due_v1(Some(1), u64::MAX, u64::MAX));
    assert!(community_member_due_v1(Some(0), u64::MAX, u64::MAX));
}

#[test]
fn minted_observation_terms_count_against_the_per_record_node_limit() -> TestResult {
    // The materialization's terms are State demand (R10.3(5)), so an
    // observation that alone exhausts the node limit gives 14.
    let fixture = Fixture::new(1)?;
    let bindings = fixture.bindings()?;
    let members = [quote_member(&bindings[0], &fixture.payload, &[], true)];
    let base = CommunityPassQuoteV1::new(quote_input(&members, Some(OBSERVATION)))?;
    let [nodes_limit, _, _] = COMMUNITY_SHARED_RECORD_LIMITS_V1;
    let spare = nodes_limit - base.total_terms().nodes;
    let observation = |extra: u64| CommunityPassObservationV1 {
        terms: CommunityPassTermsV1 {
            nodes: OBSERVATION.terms.nodes + extra,
            ..OBSERVATION.terms
        },
        ..OBSERVATION
    };
    let fit = |extra| -> Fallible<Option<Error>> {
        Ok(
            CommunityPassQuoteV1::new(quote_input(&members, Some(observation(extra))))?
                .require_fit()
                .err(),
        )
    };
    assert_eq!(fit(spare)?, None);
    assert_eq!(fit(spare + 1)?, Some(Error::RecordingUnavailable));
    assert_eq!(fit(spare + 2)?, Some(Error::CapacityExhausted));
    Ok(())
}

fn header(kind: ArtifactKind) -> Fallible<CommunityArtifactHeaderV1> {
    Ok(CommunityArtifactHeaderV1::new(
        CommunityArtifactHeaderInputV1 {
            timeline: T,
            generation: G,
            purpose: CommunityArtifactPurposeV1::ExecutionState,
            operation: CommunityArtifactOperationV1::Control([1; 16]),
            record_kind: kind,
            scope_cover_digest: hash(60),
            evidence_not_after_micros: HORIZON,
        },
    )?)
}

fn children(count: usize) -> Vec<ArtifactChildEdgeV1> {
    (0..count)
        .map(|index| ArtifactChildEdgeV1 {
            artifact_class: ErasureArtifactClassV1::TimelineReplay,
            artifact_digest: indexed(index),
            registration_address: indexed(index),
            required: true,
        })
        .collect()
}

/// A fresh random COE1 nonce: the sizes never depend on its bytes.
fn random_nonce() -> Fallible<[u8; 12]> {
    let mut nonce = getrandom::u64()?.to_le_bytes().to_vec();
    nonce.extend(getrandom::u32()?.to_le_bytes());
    Ok(nonce.try_into().map_err(|_| "a 12-byte nonce")?)
}

/// The actual protected COW1 and ARD1 sizes of a `plaintext`-byte record
/// with `count` children, through the real envelope, CAR1, COW1 and ARD1
/// constructors.
fn protected_sizes(plaintext: usize, count: usize) -> Fallible<(u64, u64)> {
    let edges = children(count);
    let ciphertext = vec![0; plaintext + 16];
    let content = CommunityEncryptedEnvelopeV1::new(
        header(ArtifactKind::StateContent)?,
        random_nonce()?,
        &ciphertext,
    )?
    .to_canonical_cbor();
    let parsed = CommunityEncryptedEnvelopeV1::from_canonical_cbor(&content)?;
    let proof = CommunityClassificationProofV1::new(CommunityClassificationProofInputV1 {
        header: parsed.header(),
        owner_binding_digest: hash(61),
        plaintext_commitment: hash(62),
        envelope_address: parsed.address(),
        children: CommunityArtifactChildrenV1::from_children(&edges),
        host_provenance_digest: hash(63),
    })?
    .to_canonical_cbor();
    let sealed = vec![0; proof.len() + 16];
    let proof = CommunityEncryptedEnvelopeV1::new(
        header(ArtifactKind::ClassificationProof)?,
        random_nonce()?,
        &sealed,
    )?
    .to_canonical_cbor();
    let object = CommunityProtectedObjectV1::new(&content, &proof)?.to_canonical_cbor();
    let registration = ArtifactRegistrationV1::new(ArtifactRegistrationFieldsV1 {
        artifact_class: ErasureArtifactClassV1::TimelineReplay,
        artifact_digest: hash(64),
        owner_reference: hash(65),
        data_class: ArtifactDataClassV1::PrivateSubjectData,
        optionality: ArtifactOptionalityV1::Required,
        transition_rule: ArtifactTransitionRuleV1::Remove,
        required_key_roles: vec![KeyRoleV1::CommunityArtifactEncryption],
        key_dependencies: vec![ArtifactKeyDependencyV1 {
            identity: parsed.header().key_identity(),
            material_digest: hash(66),
            private_material_required: true,
        }],
        child_artifacts: edges,
    })?;
    Ok((
        object.len() as u64,
        registration.canonical_cbor().len() as u64,
    ))
}

#[test]
fn protection_sizes_equal_the_actual_protected_records() -> TestResult {
    // Revision 11, R11.3(2) and I109.
    let sizes = CommunityProtectionSizesV1::new(T, G)?;
    for plaintext in [0, 1, 23, 24, 1 << 20, 3 << 20] {
        for count in [0, 1, 23, 24, 2048] {
            let (object, registration) = protected_sizes(plaintext, count)?;
            assert_eq!(sizes.object_len(plaintext as u64, count as u64), object);
            assert_eq!(sizes.registration_len(count as u64), registration);
            assert_eq!(
                sizes.record(plaintext as u64, count as u64),
                CommunityPassGraphTermsV1 {
                    registrations: 1,
                    edges: count as u64,
                    keys: 0,
                    registration_bytes: registration,
                    artifact_bytes: object,
                }
            );
        }
    }
    assert_eq!(
        CommunityProtectionSizesV1::new(T, [0; 16]).err(),
        Some(Error::InvalidBinding)
    );
    Ok(())
}

const SELECTED: CommunityGraphCountsV1 = CommunityGraphCountsV1 {
    registrations: 10,
    edges: 12,
    keys: 2,
    maximum_depth: 3,
    registration_bytes: 1000,
    artifact_bytes: 2000,
};

const OBSERVATION_GRAPH: CommunityPassGraphTermsV1 = CommunityPassGraphTermsV1 {
    registrations: 2,
    edges: 1,
    keys: 1,
    registration_bytes: 100,
    artifact_bytes: 200,
};

const fn domain(selected: CommunityGraphCountsV1, live_keys: u64) -> CommunityPassDomainV1 {
    CommunityPassDomainV1 {
        selected_graph: selected,
        live_keys,
        observation_graph: OBSERVATION_GRAPH,
        observation_keys: 2,
        observation_rows: 3,
    }
}

fn graph_of(
    sizes: &CommunityProtectionSizesV1,
    records: &[(u64, u64)],
) -> CommunityPassGraphTermsV1 {
    records.iter().fold(
        CommunityPassGraphTermsV1::default(),
        |total, (bytes, children)| total.plus(sizes.record(*bytes, *children)),
    )
}

const fn with(
    counts: CommunityGraphCountsV1,
    terms: CommunityPassGraphTermsV1,
    depth: u64,
) -> CommunityGraphCountsV1 {
    CommunityGraphCountsV1 {
        registrations: counts.registrations + terms.registrations,
        edges: counts.edges + terms.edges,
        keys: counts.keys + terms.keys,
        maximum_depth: depth,
        registration_bytes: counts.registration_bytes + terms.registration_bytes,
        artifact_bytes: counts.artifact_bytes + terms.artifact_bytes,
    }
}

#[test]
fn the_demand_adds_the_rebuilt_records_to_the_selected_closure() -> TestResult {
    // Revision 11, R11.1(6), R11.3(1)-(5) and R11.4(4); I110 and I113.
    let sizes = CommunityProtectionSizesV1::new(T, G)?;
    for committed in [2, 300] {
        let fixture = Fixture::new(2)?;
        let bindings = fixture.bindings()?;
        let refs = artifact_refs(committed);
        let mut complete = vec![TypedRef::Native(native(u64::MAX, 0))];
        complete.extend(refs.iter().copied());
        let members: Vec<_> = bindings
            .iter()
            .map(|member| quote_member(member, &fixture.payload, &refs, true))
            .collect();
        let quote = CommunityPassQuoteV1::new(quote_input(&members, Some(OBSERVATION)))?;
        let demand = quote.demand(domain(SELECTED, 5))?;
        let mut additions = OBSERVATION_GRAPH.plus(CommunityPassGraphTermsV1 {
            keys: 1,
            ..CommunityPassGraphTermsV1::default()
        });
        let mut objects = 2;
        let groups: u64 = if committed > 255 { 2 } else { 0 };
        for member in &bindings {
            let (_, records) = rebuilt_member(member, &fixture.payload, &complete)?;
            assert_eq!(records.len() as u64, 7 + 2 * groups);
            additions = additions.plus(graph_of(&sizes, &records));
            objects += 7 + 2 * groups;
        }
        let e = registered(&complete);
        assert_eq!(additions.registrations, 2 + 2 * (7 + 2 * groups));
        assert_eq!(additions.edges, 1 + 2 * (e + 2 * groups + 9));
        let state = with(SELECTED, additions, 6);
        assert_eq!(demand.graph()[0], state);
        let digests: Vec<_> = bindings
            .iter()
            .map(CommunityMemberBindingV1::digest)
            .collect();
        let civ1 = rebuilt_evidence(digests[0])?.to_canonical_cbor().len() as u64;
        let single = [TypedRef::Native(native(u64::MAX, u32::MAX - 1))];
        let measurement = node(
            u32::MAX,
            Kind::Measurement,
            *b"CIV1",
            RecordedDependencyClassV1::PresentationOnly,
            CommunityInputIndexV1::Direct(CommunityTypedInputRefsV1::from_references(&single)),
        )? as u64;
        let crr1 = rebuilt_recording(&digests)?.bytes - 2 * (civ1 + measurement);
        let recording = graph_of(
            &sizes,
            &[
                (civ1, 0),
                (civ1, 0),
                (measurement, 2),
                (measurement, 2),
                (crr1, 4),
            ],
        )
        .plus(CommunityPassGraphTermsV1 {
            keys: 2,
            ..CommunityPassGraphTermsV1::default()
        });
        assert_eq!(recording.registrations, 1 + 2 * 2);
        assert_eq!(recording.edges, 4 * 2);
        assert_eq!(demand.graph()[1], with(state, recording, 7));
        // R13.2(3) and I141: the pass provisions four State keys, the H_g
        // and H_r cohorts among them, and the recording one more.
        assert_eq!(demand.keys(), [5 + 4 + 2, 5 + 4 + 2 + 1]);
        // R13.1(3): the State rows are the objects and the materialization's
        // 3 rows; the recording adds 2n + 1; F_p is 2(n + 1).
        assert_eq!(
            demand.erasure_rows(),
            [objects + 3, objects + 3 + 2 * 2 + 1]
        );
        assert_eq!(demand.failure_reserve(), 2 * (2 + 1));
        assert_eq!(demand.objects(), [objects, objects + 2 * 2 + 1]);
        demand.require_keys()?;
        demand.require_graph()?;
        demand.require_objects()?;
    }
    Ok(())
}

#[test]
fn the_state_depth_bound_is_three_above_the_selected_depth_or_three() -> TestResult {
    // R11.3(4): max(D, 3 + max(D, 3)); the Replay closure adds one.
    let fixture = Fixture::new(1)?;
    let bindings = fixture.bindings()?;
    let members = [quote_member(&bindings[0], &fixture.payload, &[], false)];
    let quote = CommunityPassQuoteV1::new(quote_input(&members, None))?;
    for (selected, expected) in [(0, 6), (3, 6), (4, 7), (10, 13)] {
        let demand = quote.demand(domain(
            CommunityGraphCountsV1 {
                maximum_depth: selected,
                ..SELECTED
            },
            0,
        ))?;
        assert_eq!(demand.graph()[0].maximum_depth, expected);
        assert_eq!(demand.graph()[1].maximum_depth, expected + 1);
    }
    Ok(())
}

#[test]
fn key_graph_and_object_demand_split_state_from_recording() -> TestResult {
    // R11.5(1), I107, I112 and I116: State over a limit gives 14; State
    // within with the recording over gives 19.
    let fixture = Fixture::new(1)?;
    let bindings = fixture.bindings()?;
    let members = [quote_member(&bindings[0], &fixture.payload, &[], false)];
    let quote = CommunityPassQuoteV1::new(quote_input(&members, None))?;
    let base = quote.demand(domain(SELECTED, 0))?;
    let [state_keys, _] = base.keys();
    let spare = COMMUNITY_MAXIMUM_STORE_KEYS_V1 - state_keys;
    let keys = |live| -> Fallible<Option<Error>> {
        Ok(quote.demand(domain(SELECTED, live))?.require_keys().err())
    };
    assert_eq!(keys(spare - 1)?, None);
    assert_eq!(keys(spare)?, Some(Error::RecordingUnavailable));
    assert_eq!(keys(spare + 1)?, Some(Error::CapacityExhausted));
    let [state, recording] = base.graph();
    let added = recording.registrations - state.registrations;
    let graph = |registrations: u64, depth: u64| -> Fallible<Option<Error>> {
        Ok(quote
            .demand(domain(
                CommunityGraphCountsV1 {
                    registrations,
                    maximum_depth: depth,
                    ..SELECTED
                },
                0,
            ))?
            .require_graph()
            .err())
    };
    let free = 4096 - (state.registrations - SELECTED.registrations);
    assert_eq!(graph(free - added, 3)?, None);
    assert_eq!(
        graph(free - added + 1, 3)?,
        Some(Error::RecordingUnavailable)
    );
    assert_eq!(graph(free, 3)?, Some(Error::RecordingUnavailable));
    assert_eq!(graph(free + 1, 3)?, Some(Error::CapacityExhausted));
    // Depth: 3 + D for the State, one more for the Replay closure.
    assert_eq!(graph(10, 4092)?, None);
    assert_eq!(graph(10, 4093)?, Some(Error::RecordingUnavailable));
    assert_eq!(graph(10, 4094)?, Some(Error::CapacityExhausted));
    Ok(())
}

#[test]
fn the_object_bound_counts_every_pass_cow1() -> TestResult {
    // R11.4(4) and I116: 9n + 2 sum(g) + 3 objects against 2,048 bindings.
    let fixture = Fixture::new(64)?;
    let bindings = fixture.bindings()?;
    let grouped = artifact_refs(4096);
    let objects = |groups_of: usize| -> Fallible<Option<Error>> {
        let members: Vec<_> = bindings
            .iter()
            .enumerate()
            .map(|(index, member)| {
                let refs: &[TypedRef<'_>] = if index < groups_of { &grouped } else { &[] };
                quote_member(member, &fixture.payload, refs, false)
            })
            .collect();
        let quote = CommunityPassQuoteV1::new(quote_input(&members, None))?;
        Ok(quote.demand(domain(SELECTED, 0))?.require_objects().err())
    };
    // 64 x 7 + 2 x 16 x 45 + 2 = 1,890 and 2,019 with the recording.
    assert_eq!(objects(45)?, None);
    // 64 x 7 + 2 x 16 x 48 + 2 = 1,986, and 2,115 with the recording.
    assert_eq!(objects(48)?, Some(Error::RecordingUnavailable));
    // 64 x 7 + 2 x 16 x 50 + 2 = 2,050.
    assert_eq!(objects(50)?, Some(Error::CapacityExhausted));
    Ok(())
}

#[test]
fn minted_observation_terms_count_against_the_per_record_edge_limit() -> TestResult {
    // R10.4(1): the per-record edge limit is exactly 262,144. State edges at
    // the limit fit; the recording's one Measurement edge then gives 19; one
    // more State edge gives 14.
    let fixture = Fixture::new(1)?;
    let bindings = fixture.bindings()?;
    let members = [quote_member(&bindings[0], &fixture.payload, &[], true)];
    let base = CommunityPassQuoteV1::new(quote_input(&members, Some(OBSERVATION)))?;
    let [_, edges_limit, _] = COMMUNITY_SHARED_RECORD_LIMITS_V1;
    assert_eq!(edges_limit, 262_144);
    let spare = edges_limit - base.total_terms().edges;
    let observation = |extra: u64| CommunityPassObservationV1 {
        terms: CommunityPassTermsV1 {
            edges: OBSERVATION.terms.edges + extra,
            ..OBSERVATION.terms
        },
        ..OBSERVATION
    };
    let quote = |extra| CommunityPassQuoteV1::new(quote_input(&members, Some(observation(extra))));
    let fitting = quote(spare)?;
    assert_eq!(fitting.total_terms().edges, 262_144);
    assert_eq!(fitting.require_fit().err(), None);
    let over = quote(spare + 1)?;
    assert_eq!(over.total_terms().edges, 262_145);
    assert_eq!(over.require_fit().err(), Some(Error::RecordingUnavailable));
    assert_eq!(
        quote(spare + 2)?.require_fit().err(),
        Some(Error::CapacityExhausted)
    );
    Ok(())
}

/// One R13.3 capacity column: `contexts` lockstep contexts on one affected
/// scope, `fixed` targets held before the first pass (store, payloads,
/// initialization rows and every `F_q`), `reserves` of the contexts' `F_p`
/// pending at the last check of a round, and the materialization rows and
/// closure additions of each 0-based pass.
struct Column {
    contexts: u64,
    fixed: u64,
    reserves: u64,
    observation: fn(u64) -> (u64, CommunityPassGraphTermsV1),
}

/// A materialization's closure additions: `registrations` records and
/// `edges` edges, at a nominal size.
const fn additions(registrations: u64, edges: u64) -> CommunityPassGraphTermsV1 {
    CommunityPassGraphTermsV1 {
        registrations,
        edges,
        keys: 1,
        registration_bytes: 100 * registrations,
        artifact_bytes: 200 * registrations,
    }
}

/// No new Event: the first pass mints the empty cut (COV1, Observation
/// CPN1 and CPE1), later passes reuse it.
fn no_new_event(pass: u64) -> (u64, CommunityPassGraphTermsV1) {
    if pass == 0 {
        (3, additions(2, 1))
    } else {
        (0, CommunityPassGraphTermsV1::default())
    }
}

/// One new Event a pass: each pass mints an observation of every Event so
/// far, with one new CES1 and an Observation CPN1 naming all of them.
const fn one_new_event(pass: u64) -> (u64, CommunityPassGraphTermsV1) {
    (4, additions(3, 2 + pass))
}

/// The first pass of a Fork column with a one-Event prefix.
fn prefix_of_one(pass: u64) -> (u64, CommunityPassGraphTermsV1) {
    if pass == 0 {
        (4, additions(3, 2))
    } else {
        (0, CommunityPassGraphTermsV1::default())
    }
}

/// The first pass of a Fork column with a 500-Event prefix: 500 CES1s in
/// two CIB1 groups of 256 and 244.
fn prefix_of_500(pass: u64) -> (u64, CommunityPassGraphTermsV1) {
    if pass == 0 {
        (500 + 3 + 2 * 2, additions(500 + 2 + 2 * 2, 3 + 257 + 245))
    } else {
        (0, CommunityPassGraphTermsV1::default())
    }
}

/// The passes each context commits before the first 14, from the real
/// demand of an `n`-member pass: the R11.3 graph demand over the closure the
/// earlier passes selected, then the R13.1 budget.
fn passes_before_14(members: u64, column: &Column) -> Fallible<u64> {
    let fixture = Fixture::new(usize::try_from(members)?)?;
    let bindings = fixture.bindings()?;
    // e = 2: the prior StateRevision and the observation (I142).
    let inputs = artifact_refs(2);
    let rows: Vec<_> = bindings
        .iter()
        .map(|member| quote_member(member, &fixture.payload, &inputs, false))
        .collect();
    let quote = CommunityPassQuoteV1::new(quote_input(&rows, None))?;
    let mut selected = CommunityGraphCountsV1 {
        registrations: 5 * members,
        edges: 6 * members,
        ..SELECTED
    };
    let mut targets = column.fixed;
    let mut passes = 0;
    loop {
        let (rows, graph) = (column.observation)(passes);
        let demand = quote.demand(CommunityPassDomainV1 {
            selected_graph: selected,
            live_keys: 0,
            observation_graph: graph,
            observation_keys: 0,
            observation_rows: rows,
        })?;
        let [_, total] = demand.erasure_rows();
        let committed = column.contexts * 2 * total;
        if demand.require_graph().is_err()
            || targets + committed + column.reserves * demand.failure_reserve()
                > COMMUNITY_ERASURE_TARGET_LINE_V1
        {
            return Ok(passes);
        }
        selected = demand.graph()[0];
        targets += committed;
        passes += 1;
    }
}

#[test]
fn the_capacity_table_follows_from_the_pass_demand() -> TestResult {
    // Revision 13, R13.3 and I142 (the demand part; the planner part runs
    // over the Memory counters in pos-store). n = 9 exceeds the roster
    // maximum, so only the demand can show its row. At n = 1 with one new
    // Event a pass the closure's edges bind first.
    for (members, expected) in [
        (1_u64, [164, 116, 81, 39]),
        (3, [64, 57, 32, 15]),
        (9, [22, 21, 10, 4]),
    ] {
        let one = 2 + 10 * members + 8 * members;
        let fork = 3 + 10 * members + 2 * 8 * members;
        let column = |contexts, fixed, observation| Column {
            contexts,
            fixed,
            reserves: contexts,
            observation,
        };
        let columns = [
            column(1, one, no_new_event),
            column(1, one, one_new_event),
            column(2, fork, prefix_of_one),
            column(2, fork, prefix_of_500),
        ];
        let observed = columns
            .iter()
            .map(|column| passes_before_14(members, column))
            .collect::<Fallible<Vec<_>>>()?;
        assert_eq!(observed, expected, "n = {members}");
    }
    // With one pending F_p at a time only n = 9, E = 500 changes, to 5.
    for (members, expected) in [(9, 5), (3, 15)] {
        let single = Column {
            contexts: 2,
            fixed: 3 + 10 * members + 2 * 8 * members,
            reserves: 1,
            observation: prefix_of_500,
        };
        assert_eq!(passes_before_14(members, &single)?, expected);
    }
    Ok(())
}
