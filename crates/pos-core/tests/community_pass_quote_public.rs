//! The pass CBQ1 quote and dueness through their public seams (ADR-129
//! revision 10, R10.1, R10.3 and R10.4(1); I85, I89 and I91).
//!
//! Every expected quote is rebuilt independently: the test mints each record
//! the R10.3(5) table names through its own public constructor, with every
//! unallocated ordinal, unknown count and unknown horizon at its widest
//! value, and sums the actual encoded lengths.

use pos_core::community_lifecycle::{
    community_member_due_v1, ArtifactRefV1, CommunityAnnotationOmissionV1 as Omission,
    CommunityAnnotationOmissionsV1, CommunityContentReferenceV1,
    CommunityEventDraftFragmentInputV1, CommunityEventDraftFragmentReferenceV1,
    CommunityEventDraftFragmentV1, CommunityEventDraftManifestInputV1,
    CommunityEventDraftManifestV1, CommunityInputGroupInputV1, CommunityInputGroupV1,
    CommunityInputIndexV1, CommunityInvocationEvidenceInputV1, CommunityInvocationEvidenceV1,
    CommunityInvocationStepV1, CommunityLifecycleErrorV1 as Error,
    CommunityMaterializationReferenceV1, CommunityMemberBindingInputV1, CommunityMemberBindingV1,
    CommunityNativeNodeInputV1, CommunityNativeNodeKindV1 as Kind, CommunityNativeNodeReferenceV1,
    CommunityNativeNodeReferencesV1, CommunityNativeNodeV1, CommunityOutputUsageV1,
    CommunityPassKeyV1, CommunityPassObservationV1, CommunityPassQuoteInputV1,
    CommunityPassQuoteMemberV1, CommunityPassQuoteV1, CommunityPassTermsV1,
    CommunityPreparedInvocationInputV1, CommunityPreparedInvocationV1,
    CommunityReplayMemberBindingV1, CommunityReplayMemberV1, CommunityReplayRecordingInputV1,
    CommunityReplayRecordingV1, CommunitySharedCountsV1, CommunitySourceClosureInputV1,
    CommunitySourceClosureV1, CommunityStateProducerV1, CommunityStateRevisionInputV1,
    CommunityStateRevisionV1, CommunityTypedInputRefV1 as TypedRef, CommunityTypedInputRefsV1,
    MeteringV1, TimelinePositionV1, COMMUNITY_CUMULATIVE_RECORD_LIMITS_V1,
    COMMUNITY_SHARED_RECORD_LIMITS_V1,
};
use pos_core::{
    ErasureArtifactClassV1, Hash, ImplementationKeyV1, RecordedDependencyClassV1, TimelineId,
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
    let mut bytes = step.to_canonical_cbor().len()
        + prepared.to_canonical_cbor().len()
        + closure.to_canonical_cbor().len();
    let mut groups = Vec::new();
    for (chunk, ordinal) in inputs.chunks(256).zip(u32::MAX - 40..) {
        if inputs.len() <= 256 {
            break;
        }
        let leaves = CommunityTypedInputRefsV1::from_references(chunk);
        bytes += CommunityInputGroupV1::new(CommunityInputGroupInputV1 {
            timeline: T,
            generation: G,
            consumer_content: CommunityContentReferenceV1 {
                record_magic: *b"CPI1",
                logical_digest: hash(37),
            },
            leaves,
        })?
        .to_canonical_cbor()
        .len();
        bytes += node(
            ordinal,
            Kind::InputIndex,
            *b"CIB1",
            endogenous,
            CommunityInputIndexV1::Direct(leaves),
        )?;
        groups.push(native(u64::MAX, ordinal));
    }
    let index = match inputs.len() {
        0 => CommunityInputIndexV1::Empty,
        1..=256 => {
            CommunityInputIndexV1::Direct(CommunityTypedInputRefsV1::from_references(inputs))
        }
        total => CommunityInputIndexV1::Grouped {
            groups: CommunityNativeNodeReferencesV1::from_references(&groups),
            total_leaf_count: total as u64,
        },
    };
    bytes += node(
        u32::MAX - 1,
        Kind::InvocationStep,
        *b"CPI1",
        endogenous,
        index,
    )?;
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
    bytes += revision.to_canonical_cbor().len()
        + usize::try_from(STATE_LIMIT)?
        + node(
            u32::MAX,
            Kind::StateRevision,
            *b"CSR1",
            endogenous,
            CommunityInputIndexV1::Direct(CommunityTypedInputRefsV1::from_references(&single)),
        )?;
    Ok(CommunityPassTermsV1 {
        nodes: 2 + groups.len() as u64,
        edges: (inputs.len() + groups.len() + 1) as u64,
        bytes: bytes as u64,
    })
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
