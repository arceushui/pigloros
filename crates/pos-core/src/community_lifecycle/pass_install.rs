//! The R10.4(5) installation check of a CDP1 (ADR-129 revision 10, R10.4(5);
//! revision 11, R11.5(3)).
//!
//! A CDP1 is rejected at installation unless its **minimum required pass**
//! fits every 5g check with zero prior counts: every roster member due at its
//! CNT1 State limit `S_m`, with an empty observation and an `S_m`-byte prior
//! State, two step inputs (the prior `StateRevision` and the minted
//! Observation), an empty-cut observation minted, and every other value at its
//! R10.3(3) widest width. Its base is the initialization closure of journal
//! 22661: `5n` registrations, `6n` edges and the 2 initialization keys.
//!
//! The pass CSB1/CPV1 bounds hold by construction for that pass (`n + 1`
//! distinct refs and an empty scope). The R13.3 minimum-lifetime floor is a
//! static assertion of the profile at the roster maximum: its target,
//! registration and edge sums depend on `n` alone, and the check returns them
//! (ADR-129 revision 13, R13.3, I145). The R11.1(5) encryption bound is a
//! static assertion too.

use super::native_node::{quoted_node_len, widest_node_reference};
use super::pass_graph::{CommunityPassGraphTermsV1, CommunityProtectionSizesV1};
use super::pass_quote::state_content_len;
use super::{
    ArtifactRefV1, CommunityDurableProfileV1, CommunityGraphCountsV1, CommunityInputIndexV1,
    CommunityLifecycleErrorV1 as Error, CommunityLocatorProducerV1, CommunityMetadataLocatorV1,
    CommunityMetadataSchemaV1, CommunityNativeNodeKindV1, CommunityObservationSourceInputV1,
    CommunityObservationSourceV1, CommunityObservationValueInputV1, CommunityObservationValueV1,
    CommunityPassDemandV1, CommunityPassDomainV1, CommunityPassObservationV1,
    CommunityPassQuoteInputV1, CommunityPassQuoteMemberV1, CommunityPassQuoteV1,
    CommunityPassTermsV1, CommunityPreparedInvocationInputV1, CommunityReducerBindingV1,
    CommunitySharedCountsV1, CommunityStateProducerV1, CommunityStateRevisionInputV1,
    CommunityStateRevisionV1, CommunityTypedInputRefV1, CommunityTypedInputRefsV1, Result,
    TimelinePositionV1, COMMUNITY_MAXIMUM_ROSTER_V1, COMMUNITY_QUARANTINE_RESERVE_PER_MEMBER_V1,
    MAX_COMMUNITY_COVERAGE_ROWS_V1, MAX_COMMUNITY_RECORDED_CONSUMERS_V1,
    MAX_COMMUNITY_STATE_BYTES_V1, WIDEST_HORIZON_MICROS,
};
use crate::{Hash, TimelineId};

// The minimum pass has one prior-State ref per member and the shared
// Observation: at most 10 distinct refs, far below the CSB1 bound, and an
// empty scope (R11.4(1)-(3)).
const _: () = assert!(COMMUNITY_MAXIMUM_ROSTER_V1 < MAX_COMMUNITY_COVERAGE_ROWS_V1);

/// A nonzero fixed-width placeholder digest.
const PLACEHOLDER: Hash = Hash::from_bytes([0xff; 32]);

/// The CIS1 encoding maximum (record annex), an initialization record.
const CIS1_BYTES: u64 = 1024;

/// The initialization's keys: its metadata key and its `ExecutionState`
/// cohort.
const INITIALIZATION_KEYS: u64 = 2;

/// The empty-cut materialization's store keys: its metadata key and its
/// union cohort (R11.1(4)).
const OBSERVATION_KEYS: u64 = 2;

/// The empty-cut materialization's ARD1 rows: COV1, Observation CPN1 and
/// CPE1 (R13.3).
const OBSERVATION_ROWS: u64 = 3;

/// `P_min`, the passes the floor repeats (R13.3).
const MINIMUM_PASSES: u64 = 64;

/// The erasure targets fixed for one affected Timeline: the store target and
/// its `timeline-payload` (R13.1(1)).
const FIXED_TARGETS: u64 = 2;

/// The minimum required pass of an installed CDP1 (R10.4(5)).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommunityPassInstallationV1 {
    /// Its CBQ1 State demand, then with the recording.
    pub quote: [CommunityPassTermsV1; 2],
    /// Its key, graph, object and erasure demands over the initialization
    /// base.
    pub demand: CommunityPassDemandV1,
    /// The R13.3 floor sums of the pass repeated 64 times.
    pub lifetime: CommunityPassLifetimeV1,
}

/// The R13.3 minimum-lifetime sums on one affected Timeline: the
/// initialization base, the first pass's empty-cut observation and 64
/// minimum passes, with every reserve held.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommunityPassLifetimeV1 {
    /// Erasure targets: `2 + 10n + 8n + 6 + 64 (18n + 6) + 2(n + 1)`.
    pub targets: u64,
    /// CGR1 registrations: `5n + 2 + 64 x 7n`.
    pub registrations: u64,
    /// CGR1 edges: `6n + 1 + 64 x 11n`.
    pub edges: u64,
}

/// Check that `profile`'s minimum required pass fits (R10.4(5), R11.5(3)).
///
/// This check does **not** enforce the R10.4(3) installation rule that
/// `recording_not_after_micros` is at most the recording owner's admitted
/// `ReplayRecording` policy horizon: no input here carries that owner
/// horizon. A4c's installation wiring must supply the owner horizon and
/// enforce that rule alongside this check.
///
/// `state_limit_bytes` is each roster row's CNT1 State limit, in roster
/// order, as for the planners.
///
/// # Errors
/// Returns `InvalidBinding` when the State limits do not cover the roster;
/// `BoundsExceeded` for a State limit over 1 MiB; and the 14 or 19 of the
/// first R10.4(2) or R11.5(1) check the minimum pass fails. Any error
/// rejects the CDP1.
pub fn check_community_pass_installation_v1(
    profile: &CommunityDurableProfileV1<'_>,
    state_limit_bytes: &[u64],
) -> Result<CommunityPassInstallationV1> {
    let roster = profile.as_input().roster;
    if state_limit_bytes.len() != roster.len() {
        return Err(Error::InvalidBinding);
    }
    // Each limit as a payload length, at most 1 MiB.
    let lengths: Option<Vec<usize>> = state_limit_bytes
        .iter()
        .map(|limit| {
            usize::try_from(*limit)
                .ok()
                .filter(|length| *length <= MAX_COMMUNITY_STATE_BYTES_V1)
        })
        .collect();
    lengths
        .ok_or(Error::BoundsExceeded)
        .and_then(|lengths| minimum_pass(profile, state_limit_bytes, &lengths))
}

/// The minimum required pass of `profile` checked over its initialization
/// base.
fn minimum_pass(
    profile: &CommunityDurableProfileV1<'_>,
    state_limit_bytes: &[u64],
    lengths: &[usize],
) -> Result<CommunityPassInstallationV1> {
    let timeline = TimelineId::from_ulid(ulid::Ulid::from_bytes([0xff; 16]));
    let generation = [0xff; 16];
    let prior = vec![0; MAX_COMMUNITY_STATE_BYTES_V1];
    let inputs = [CommunityTypedInputRefV1::Native(widest_node_reference())];
    let members: Vec<_> = profile
        .as_input()
        .roster
        .iter()
        .zip(state_limit_bytes.iter().zip(lengths))
        .zip(1_u8..)
        .map(
            |((row, (limit, length)), slot)| CommunityPassQuoteMemberV1 {
                member_binding_digest: Hash::from_bytes([slot; 32]),
                negotiated_tuple_digest: row.digests()[2],
                state_limit_bytes: *limit,
                prepared_invocation: widest_invocation(timeline, &prior[..*length]),
                step_inputs: &inputs,
                consumes_minted_observation: true,
            },
        )
        .collect();
    CommunityProtectionSizesV1::new(timeline, generation).and_then(|sizes| {
        minimum_observation(&sizes, timeline, generation).and_then(|(observation, graph)| {
            CommunityPassQuoteV1::new(CommunityPassQuoteInputV1 {
                timeline,
                generation,
                profile_digest: profile.digest(),
                prior_shared_counts: CommunitySharedCountsV1::default(),
                members: &members,
                minted_observation: Some(observation),
            })
            .and_then(|quote| {
                initialization_base(&sizes, timeline, generation, state_limit_bytes).and_then(
                    |base| {
                        check_minimum(
                            &quote,
                            CommunityPassDomainV1 {
                                selected_graph: base,
                                live_keys: INITIALIZATION_KEYS,
                                observation_graph: graph,
                                observation_keys: OBSERVATION_KEYS,
                                observation_rows: OBSERVATION_ROWS,
                            },
                        )
                    },
                )
            })
        })
    })
}

/// The R11.5(3) checks of a minimum pass over `domain`, in the R11.5(1)
/// order: the CBQ1, then the keys, the graph and the objects.
fn check_minimum(
    quote: &CommunityPassQuoteV1,
    domain: CommunityPassDomainV1,
) -> Result<CommunityPassInstallationV1> {
    quote
        .require_fit()
        .and_then(|()| quote.demand(domain))
        .and_then(|demand| {
            demand
                .require_keys()
                .and_then(|()| demand.require_graph())
                .and_then(|()| demand.require_objects())
                .map(|()| CommunityPassInstallationV1 {
                    quote: [quote.state_terms(), quote.total_terms()],
                    demand,
                    lifetime: lifetime(
                        quote.quote().as_input().due_members.len() as u64,
                        &demand,
                        domain,
                    ),
                })
        })
}

/// The R13.3 sums of the `members`-member `demand` over `domain`, repeated
/// [`MINIMUM_PASSES`] times. The first pass mints the observation; the later
/// ones reuse it.
fn lifetime(
    members: u64,
    demand: &CommunityPassDemandV1,
    domain: CommunityPassDomainV1,
) -> CommunityPassLifetimeV1 {
    let [state, _] = demand.graph();
    let base = domain.selected_graph;
    let observation = domain.observation_graph;
    let [_, rows] = demand.erasure_rows();
    let repeated = |total: u64, fixed: u64| total + (MINIMUM_PASSES - 1) * (total - fixed);
    CommunityPassLifetimeV1 {
        targets: FIXED_TARGETS
            + 2 * base.registrations
            + COMMUNITY_QUARANTINE_RESERVE_PER_MEMBER_V1 * members
            + 2 * domain.observation_rows
            + MINIMUM_PASSES * 2 * (rows - domain.observation_rows)
            + demand.failure_reserve(),
        registrations: repeated(
            state.registrations,
            base.registrations + observation.registrations,
        ),
        edges: repeated(state.edges, base.edges + observation.edges),
    }
}

/// A CIN1 with an empty observation, `prior` as its prior State and every
/// other value at its widest encoding.
const fn widest_invocation(
    timeline: TimelineId,
    prior: &[u8],
) -> CommunityPreparedInvocationInputV1<'_> {
    let reference = ArtifactRefV1 {
        schema_id: u32::MAX,
        byte_length: u64::MAX,
        digest: [0xff; 32],
    };
    CommunityPreparedInvocationInputV1 {
        member_binding_digest: PLACEHOLDER,
        invocation_id: [0xff; 16],
        timeline_position: TimelinePositionV1 {
            timeline_id: timeline.inner().to_bytes(),
            seq: u64::MAX,
            tick: u64::MAX,
            scheduler_position: u32::MAX,
        },
        output_base_ordinal: u32::MAX,
        principal_ref: reference,
        authorization_ref: reference,
        observation_snapshot_ref: reference,
        observation_bytes: &[],
        prior_state_schema_digest: [0xff; 32],
        prior_state_bytes: prior,
        execution_profile_digest: [0xff; 32],
        trust_policy_snapshot_digest: [0xff; 32],
        deterministic_budget_id: WIDEST_BUDGET_ID,
        deterministic_random_domain: [0xff; 32],
        provenance_root: [0xff; 32],
        simulation_time: u64::MAX,
        watchdog_epochs: u32::MAX,
    }
}

/// A 128-byte ADR-061 identifier, the widest deterministic budget ID.
const WIDEST_BUDGET_ID: &str = concat!(
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
);

/// The empty-cut materialization: an empty COV1, a CPE1 with the widest
/// consumer set and no rows, and an Observation CPN1 with one variant-4
/// ref. Its closure records are the COV1 and the Observation CPN1 → COV1,
/// under the one union cohort (R11.2(4), R11.1(4)).
fn minimum_observation(
    sizes: &CommunityProtectionSizesV1,
    timeline: TimelineId,
    generation: [u8; 16],
) -> Result<(CommunityPassObservationV1, CommunityPassGraphTermsV1)> {
    let genesis = [CommunityTypedInputRefV1::SourceGenesis {
        timeline,
        genesis_chain_hash: PLACEHOLDER,
    }];
    let node = quoted_node_len(
        timeline,
        generation,
        CommunityNativeNodeKindV1::Observation,
        CommunityInputIndexV1::Direct(CommunityTypedInputRefsV1::from_references(&genesis)),
    ) as u64;
    CommunityObservationValueV1::new(CommunityObservationValueInputV1 {
        timeline,
        generation,
        operation_id: [0xff; 16],
        observation_artifact_ref: ArtifactRefV1 {
            schema_id: u32::MAX,
            byte_length: 0,
            digest: [0xff; 32],
        },
        observation_bytes: &[],
    })
    .and_then(|value| {
        let value = value.to_canonical_cbor().len() as u64;
        empty_proof(timeline, generation).map(|proof| {
            (
                CommunityPassObservationV1 {
                    terms: CommunityPassTermsV1 {
                        nodes: 1,
                        edges: 1,
                        bytes: value + proof + node,
                    },
                    node_ordinal: 0,
                },
                sizes.record(value, 0).plus(sizes.record(node, 1)).plus(
                    CommunityPassGraphTermsV1 {
                        keys: 1,
                        ..CommunityPassGraphTermsV1::default()
                    },
                ),
            )
        })
    })
}

/// W(CPE1) of an empty cut with the widest consumer set.
fn empty_proof(timeline: TimelineId, generation: [u8; 16]) -> Result<u64> {
    CommunityObservationSourceV1::new(CommunityObservationSourceInputV1 {
        operation_id: [0xff; 16],
        timeline,
        generation,
        through_seq: 0,
        event_rows: Vec::new(),
        reducer_policy_bindings: (1_u8..)
            .take(MAX_COMMUNITY_RECORDED_CONSUMERS_V1)
            .map(|consumer| {
                let mut identity = [0xff; 32];
                identity[0] = consumer;
                CommunityReducerBindingV1 {
                    consumer_identity_digest: Hash::from_bytes(identity),
                    schema_digest: PLACEHOLDER,
                    reducer_digest: PLACEHOLDER,
                    configuration_digest: PLACEHOLDER,
                    admission_evidence_digest: PLACEHOLDER,
                    minimization_policy_digest: PLACEHOLDER,
                }
            })
            .collect(),
        observation_value_digest: PLACEHOLDER,
        scope_union_digest: PLACEHOLDER,
        authority_request_digest: PLACEHOLDER,
        evidence_not_after_micros: WIDEST_HORIZON_MICROS,
    })
    .map(|proof| proof.to_canonical_cbor().len() as u64)
}

/// The initialization closure (journal 22661): per member CSC1, CIS1,
/// CSR1 → CSC1, CIS1, the `InitialState` CPN1 → CIS1 and the
/// `StateRevision` CPN1 → CSR1, CSC1, `InitialState`; `5n` registrations,
/// `6n` edges, 2 keys and depth 3, at widest widths.
fn initialization_base(
    sizes: &CommunityProtectionSizesV1,
    timeline: TimelineId,
    generation: [u8; 16],
    state_limit_bytes: &[u64],
) -> Result<CommunityGraphCountsV1> {
    let member = CommunityTypedInputRefV1::Metadata {
        schema: CommunityMetadataSchemaV1::Cmb1,
        locator: CommunityMetadataLocatorV1 {
            timeline,
            generation,
            producer: CommunityLocatorProducerV1::Control([0xff; 16]),
            record_role: u16::MAX,
            slot: u16::MAX,
        },
        envelope_address: PLACEHOLDER,
        private_record_digest: PLACEHOLDER,
    };
    let initial = [member];
    let revision = [CommunityTypedInputRefV1::Native(widest_node_reference())];
    let node = |kind, inputs| {
        quoted_node_len(
            timeline,
            generation,
            kind,
            CommunityInputIndexV1::Direct(CommunityTypedInputRefsV1::from_references(inputs)),
        ) as u64
    };
    let initial_node = node(CommunityNativeNodeKindV1::InitialState, &initial);
    let revision_node = node(CommunityNativeNodeKindV1::StateRevision, &revision);
    CommunityStateRevisionV1::new(CommunityStateRevisionInputV1 {
        producer_origin: CommunityStateProducerV1::Initialization {
            generation_request_digest: PLACEHOLDER,
            operation_id: [0xff; 16],
        },
        member_binding_digest: PLACEHOLDER,
        predecessor_revision_digest: None,
        state_content_digest: PLACEHOLDER,
        producer_digest: PLACEHOLDER,
        protected_owner_binding_digest: PLACEHOLDER,
        evidence_not_after_micros: WIDEST_HORIZON_MICROS,
    })
    .map(|record| {
        let state_revision = record.to_canonical_cbor().len() as u64;
        let additions = state_limit_bytes.iter().fold(
            CommunityPassGraphTermsV1 {
                keys: INITIALIZATION_KEYS,
                ..CommunityPassGraphTermsV1::default()
            },
            |total, limit| {
                total
                    .plus(sizes.record(state_content_len(*limit), 0))
                    .plus(sizes.record(CIS1_BYTES, 0))
                    .plus(sizes.record(state_revision, 2))
                    .plus(sizes.record(initial_node, 1))
                    .plus(sizes.record(revision_node, 3))
            },
        );
        CommunityGraphCountsV1 {
            registrations: additions.registrations,
            edges: additions.edges,
            keys: additions.keys,
            maximum_depth: 3,
            registration_bytes: additions.registration_bytes,
            artifact_bytes: additions.artifact_bytes,
        }
    })
}

#[cfg(test)]
mod tests;
