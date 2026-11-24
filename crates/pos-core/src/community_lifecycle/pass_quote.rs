//! The pass CBQ1 quote of `run_pass` (ADR-129 revision 10, R10.3 and
//! R10.4(1)).
//!
//! The quote counts every COW1-placed record and every CPN1 that a V1 pass's
//! successful outcome mints, at its encoded width under R10.3(3):
//!
//! - a value known at quote time counts exactly (CIN1 payloads, the minted
//!   observation's records);
//! - a fixed-width digest, address or identifier counts at its fixed width;
//! - an unallocated producer ordinal counts at its widest form, 9 bytes;
//! - every other value unknown at quote time counts at the widest encoding
//!   its codec admits: metering, usage, annotation counts and omission sets,
//!   evidence horizons (`i64::MAX`) and the pass's node ordinals, which Seal
//!   assigns (`u32::MAX`);
//! - CSC1 counts at the member's CNT1 State limit `S_m`.
//!
//! The pinned V1 shapes (R10.3(4)) are: the `InvocationStep` CPN1 takes the
//! member's CIR1 refs, grouped by CIB1 above 256; the `StateRevision` and
//! Measurement CPN1s each take only the step. The Measurement CPN1 with its
//! CIV1, and the CRR1, are the recording demand; everything else is State
//! demand. Annotations are never quoted.
//!
//! The quote reads no store and checks no authority. The key, encryption and
//! graph demands of R10.4(2) and the R10.4(6) format bounds are not part of
//! this quote.

use super::input_group::quoted_group_len;
use super::native_node::{quoted_node_len, widest_node_reference};
use super::prepared::quoted_invocation_len;
use super::recording::quoted_recording_len;
use super::source_closure::quoted_closure_len;
use super::step::quoted_step_len;
use super::{
    widest_pass_key, CommunityBudgetQuoteInputV1, CommunityBudgetQuoteV1,
    CommunityDueMemberBudgetV1, CommunityEventDraftFragmentInputV1,
    CommunityEventDraftFragmentReferenceV1, CommunityEventDraftFragmentV1,
    CommunityEventDraftManifestInputV1, CommunityEventDraftManifestV1, CommunityInputIndexV1,
    CommunityInvocationEvidenceInputV1, CommunityInvocationEvidenceV1,
    CommunityLifecycleErrorV1 as Error, CommunityMaterializationReferenceV1,
    CommunityNativeNodeKindV1, CommunityNativeNodeReferenceV1, CommunityNativeNodeReferencesV1,
    CommunityOutputUsageV1, CommunityPassKeyV1, CommunityPreparedInvocationInputV1,
    CommunitySharedCountsV1, CommunityStateProducerV1, CommunityStateRevisionInputV1,
    CommunityStateRevisionV1, CommunityTypedInputRefV1, CommunityTypedInputRefsV1, MeteringV1,
    Result, COMMUNITY_CUMULATIVE_RECORD_LIMITS_V1, COMMUNITY_SHARED_RECORD_LIMITS_V1,
    MAX_COMMUNITY_DIRECT_INPUTS_V1, MAX_COMMUNITY_EXPANDED_INPUTS_V1, WIDEST_HORIZON_MICROS,
};
use crate::{ErasureArtifactClassV1, Hash, TimelineId};

/// A nonzero fixed-width placeholder digest for records that validate one.
const PLACEHOLDER: Hash = Hash::from_bytes([0xff; 32]);

/// `[nodes, edges, bytes]` terms of one quote row or the quoted totals.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CommunityPassTermsV1 {
    /// Nodes the row adds.
    pub nodes: u64,
    /// Edges the row adds.
    pub edges: u64,
    /// Encoded record bytes the row adds.
    pub bytes: u64,
}

impl CommunityPassTermsV1 {
    const fn plus(self, other: Self) -> Self {
        Self {
            nodes: self.nodes.saturating_add(other.nodes),
            edges: self.edges.saturating_add(other.edges),
            bytes: self.bytes.saturating_add(other.bytes),
        }
    }

    /// One node with one direct input, the pass's `StateRevision` and
    /// Measurement shape, plus `bytes`.
    const fn single(bytes: usize) -> Self {
        Self {
            nodes: 1,
            edges: 1,
            bytes: bytes as u64,
        }
    }

    /// R10.4(1): each maximum is at most its shared per-record limit `P`,
    /// and the prior counts plus these nodes and edges, and the prior
    /// declared inputs, are at most the cumulative limits `C`.
    const fn fits(self, prior: CommunitySharedCountsV1) -> bool {
        let [nodes, edges, bytes] = COMMUNITY_SHARED_RECORD_LIMITS_V1;
        let [total_nodes, total_edges, declared] = COMMUNITY_CUMULATIVE_RECORD_LIMITS_V1;
        self.nodes <= nodes
            && self.edges <= edges
            && self.bytes <= bytes
            && prior.nodes.saturating_add(self.nodes) <= total_nodes
            && prior.edges.saturating_add(self.edges) <= total_edges
            && prior.declared_inputs <= declared
    }
}

/// The observation terms of a call that mints its observation.
///
/// They are the R10.3(5) last row: the materialization preparer's exact
/// COV1, CPE1, new CES1, CIB1 and CPN1 sizes, with the unallocated producer
/// ordinal at 9 bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommunityPassObservationV1 {
    /// The row's `[nodes, edges, bytes]`: `1 + g(r')`, `r' + g(r')` and the
    /// record bytes.
    pub terms: CommunityPassTermsV1,
    /// The Observation CPN1's node ordinal in the materialization producer,
    /// which a consuming step's CIR1 ref names.
    pub node_ordinal: u32,
}

/// One due member's quote inputs, in roster order.
#[derive(Clone, Copy)]
pub struct CommunityPassQuoteMemberV1<'a> {
    /// The member's CMB1 digest, the CBQ1 due row's first field.
    pub member_binding_digest: Hash,
    /// The member's CNT1 digest, the CBQ1 due row's second field.
    pub negotiated_tuple_digest: Hash,
    /// `S_m`, the member's CNT1 State limit: the CSC1 term.
    pub state_limit_bytes: u64,
    /// The member's exact CIN1 fields. The provenance root is ignored: it
    /// is a fixed-width digest of a CIR1 that may not exist yet.
    pub prepared_invocation: CommunityPreparedInvocationInputV1<'a>,
    /// The member's assembled CIR1 refs, except a ref to an observation this
    /// call mints.
    pub step_inputs: &'a [CommunityTypedInputRefV1<'a>],
    /// Whether the member's CIR1 also names the Observation CPN1 this call
    /// mints; that ref's producer ordinal is unallocated.
    pub consumes_minted_observation: bool,
}

/// The pass quote's inputs.
#[derive(Clone, Copy)]
pub struct CommunityPassQuoteInputV1<'a> {
    /// Execution Timeline T.
    pub timeline: TimelineId,
    /// T's active generation G.
    pub generation: [u8; 16],
    /// The installed CDP1 digest.
    pub profile_digest: Hash,
    /// T's recorded-set counters, read under the guard (R10.3(6)).
    pub prior_shared_counts: CommunitySharedCountsV1,
    /// The due members in roster order, 1..=64.
    pub members: &'a [CommunityPassQuoteMemberV1<'a>],
    /// The observation terms when this call mints its observation; `None`
    /// when it reuses one.
    pub minted_observation: Option<CommunityPassObservationV1>,
}

/// One pass CBQ1 with its State-only maxima.
pub struct CommunityPassQuoteV1 {
    quote: CommunityBudgetQuoteV1,
    state: CommunityPassTermsV1,
    total: CommunityPassTermsV1,
}

impl CommunityPassQuoteV1 {
    /// Build the R10.3 quote: the CBQ1's maxima are the column sums of the
    /// whole R10.3(5) table, and the State maxima omit its recording rows.
    ///
    /// # Errors
    /// Returns `CapacityExhausted` for a member with more than 4,096 step
    /// inputs (R10.3(4)); `InvalidBinding` for a member that consumes a
    /// minted observation when none is minted; the CIN1 errors of a member's
    /// prepared invocation; and the CBQ1 errors of the due rows.
    pub fn new(input: CommunityPassQuoteInputV1<'_>) -> Result<Self> {
        let key = widest_pass_key(input.timeline, input.generation);
        let fixed = FixedLengths::new(key)?;
        input
            .members
            .iter()
            .try_fold(
                (
                    CommunityPassTermsV1::default(),
                    CommunityPassTermsV1::default(),
                ),
                |(state, recording), member| {
                    member_state(&input, fixed, member).map(|terms| {
                        (
                            state.plus(terms),
                            recording.plus(CommunityPassTermsV1::single(fixed.measurement)),
                        )
                    })
                },
            )
            .and_then(|(state, recording)| {
                let state = state
                    .plus(CommunityPassTermsV1 {
                        nodes: 0,
                        edges: 0,
                        bytes: fixed.drafts as u64,
                    })
                    .plus(
                        input
                            .minted_observation
                            .map_or_else(CommunityPassTermsV1::default, |minted| minted.terms),
                    );
                let total = state.plus(recording).plus(CommunityPassTermsV1 {
                    nodes: 0,
                    edges: 0,
                    bytes: quoted_recording_len(key, input.members.len()) as u64,
                });
                Self::budget_quote(&input, total).map(|quote| Self {
                    quote,
                    state,
                    total,
                })
            })
    }

    fn budget_quote(
        input: &CommunityPassQuoteInputV1<'_>,
        total: CommunityPassTermsV1,
    ) -> Result<CommunityBudgetQuoteV1> {
        CommunityBudgetQuoteV1::new(CommunityBudgetQuoteInputV1 {
            timeline: input.timeline,
            generation: input.generation,
            profile_digest: input.profile_digest,
            prior_shared_counts: input.prior_shared_counts,
            due_members: input
                .members
                .iter()
                .map(|member| CommunityDueMemberBudgetV1 {
                    member_binding_digest: member.member_binding_digest,
                    negotiated_tuple_digest: member.negotiated_tuple_digest,
                })
                .collect(),
            maximum_required_nodes: total.nodes,
            maximum_required_edges: total.edges,
            maximum_required_bytes: total.bytes,
        })
    }

    /// The pass CBQ1, whose maxima include the recording demand.
    #[must_use]
    pub const fn quote(&self) -> &CommunityBudgetQuoteV1 {
        &self.quote
    }

    /// The State demand `Q_s`: the R10.3(5) table without its recording
    /// rows.
    #[must_use]
    pub const fn state_terms(&self) -> CommunityPassTermsV1 {
        self.state
    }

    /// The full demand `Q_s + R`, equal to the CBQ1 maxima.
    #[must_use]
    pub const fn total_terms(&self) -> CommunityPassTermsV1 {
        self.total
    }

    /// The R10.4(2) CBQ1 check: State demand first, then State plus
    /// recording demand, each under the R10.4(1) fit rule.
    ///
    /// # Errors
    /// Returns `CapacityExhausted` when the State demand does not fit, and
    /// `RecordingUnavailable` when it fits but the full demand does not.
    pub const fn require_fit(&self) -> Result<()> {
        let prior = self.quote.as_input().prior_shared_counts;
        if !self.state.fits(prior) {
            Err(Error::CapacityExhausted)
        } else if self.total.fits(prior) {
            Ok(())
        } else {
            Err(Error::RecordingUnavailable)
        }
    }
}

/// Quoted lengths that depend only on T and G.
#[derive(Clone, Copy)]
struct FixedLengths {
    /// W(CPI1).
    step: usize,
    /// W(CSR1) plus its one-input `StateRevision` CPN1.
    revision: usize,
    /// W(CIV1) plus its one-input Measurement CPN1.
    measurement: usize,
    /// W(CED1) plus W(CEB1) for the empty draft vector.
    drafts: usize,
}

impl FixedLengths {
    fn new(key: CommunityPassKeyV1) -> Result<Self> {
        let timeline = key.timeline();
        let generation = key.generation();
        let step = [CommunityTypedInputRefV1::Native(widest_node_reference())];
        let single = |kind| {
            quoted_node_len(
                timeline,
                generation,
                kind,
                CommunityInputIndexV1::Direct(CommunityTypedInputRefsV1::from_references(&step)),
            )
        };
        let revision = revision_len(key)?;
        let evidence = evidence_len(key)?;
        drafts_len(key).map(|drafts| Self {
            step: quoted_step_len(key),
            revision: revision + single(CommunityNativeNodeKindV1::StateRevision),
            measurement: evidence + single(CommunityNativeNodeKindV1::Measurement),
            drafts,
        })
    }
}

/// W(CSR1): a pass origin with the widest key, a required predecessor and
/// the widest horizon.
fn revision_len(key: CommunityPassKeyV1) -> Result<usize> {
    CommunityStateRevisionV1::new(CommunityStateRevisionInputV1 {
        producer_origin: CommunityStateProducerV1::Pass(key),
        member_binding_digest: PLACEHOLDER,
        predecessor_revision_digest: Some(PLACEHOLDER),
        state_content_digest: PLACEHOLDER,
        producer_digest: PLACEHOLDER,
        protected_owner_binding_digest: PLACEHOLDER,
        evidence_not_after_micros: WIDEST_HORIZON_MICROS,
    })
    .map(|record| record.to_canonical_cbor().len())
}

/// W(CIV1): every count unknown before the guest runs at `u64::MAX`.
fn evidence_len(key: CommunityPassKeyV1) -> Result<usize> {
    CommunityInvocationEvidenceV1::new(CommunityInvocationEvidenceInputV1 {
        pass_key: key,
        member_binding_digest: PLACEHOLDER,
        invocation_id: [0xff; 16],
        negotiated_tuple_digest: PLACEHOLDER,
        prepared_invocation_digest: PLACEHOLDER,
        validated_output_digest: PLACEHOLDER,
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
        next_state_content_digest: PLACEHOLDER,
        event_draft_vector_digest: PLACEHOLDER,
    })
    .map(|record| record.to_canonical_cbor().len())
}

/// W(CED1) + W(CEB1) for the zero-Event pass: the empty draft vector is
/// the one byte `0x80` in one fragment.
fn drafts_len(key: CommunityPassKeyV1) -> Result<usize> {
    CommunityEventDraftFragmentV1::new(CommunityEventDraftFragmentInputV1 {
        pass_key: key,
        byte_offset: 0,
        total_plaintext_bytes: 1,
        fragment_bytes: &[0x80],
    })
    .and_then(|fragment| {
        manifest_len(key).map(|manifest| manifest + fragment.to_canonical_cbor().len())
    })
}

/// W(CED1) naming the one-byte empty vector's single fragment.
fn manifest_len(key: CommunityPassKeyV1) -> Result<usize> {
    CommunityEventDraftManifestV1::new(CommunityEventDraftManifestInputV1 {
        pass_key: key,
        fragments: vec![CommunityEventDraftFragmentReferenceV1 {
            byte_offset: 0,
            fragment_length: 1,
            fragment_digest: PLACEHOLDER,
            materialization: CommunityMaterializationReferenceV1 {
                owner_reference: PLACEHOLDER,
                artifact_class: ErasureArtifactClassV1::TimelineReplay,
                object_address: PLACEHOLDER,
                artifact_digest: PLACEHOLDER,
                registration_address: PLACEHOLDER,
                attestation_address: PLACEHOLDER,
            },
        }],
        total_plaintext_bytes: 1,
        draft_count: 0,
        draft_vector_digest: PLACEHOLDER,
    })
    .map(|manifest| manifest.to_canonical_cbor().len())
}

/// One due member's State rows: the `InvocationStep` row and the
/// `StateRevision` row (R10.3(5)).
fn member_state(
    input: &CommunityPassQuoteInputV1<'_>,
    fixed: FixedLengths,
    member: &CommunityPassQuoteMemberV1<'_>,
) -> Result<CommunityPassTermsV1> {
    step_inputs(input, member).and_then(|inputs| {
        quoted_invocation_len(member.prepared_invocation).map(|invocation| {
            step_terms(input.timeline, input.generation, &inputs)
                .plus(CommunityPassTermsV1 {
                    nodes: 0,
                    edges: 0,
                    bytes: (fixed.step + invocation) as u64,
                })
                .plus(CommunityPassTermsV1 {
                    nodes: 1,
                    edges: 1,
                    bytes: member
                        .state_limit_bytes
                        .saturating_add(fixed.revision as u64),
                })
        })
    })
}

/// The member's complete step inputs: its committed refs and, when it
/// consumes the minted observation, that Observation CPN1's ref with the
/// unallocated producer ordinal at its widest form.
fn step_inputs<'a>(
    input: &CommunityPassQuoteInputV1<'_>,
    member: &CommunityPassQuoteMemberV1<'a>,
) -> Result<Vec<CommunityTypedInputRefV1<'a>>> {
    let minted = match (member.consumes_minted_observation, input.minted_observation) {
        (false, _) => Ok(None),
        (true, Some(minted)) => Ok(Some(CommunityTypedInputRefV1::Native(
            CommunityNativeNodeReferenceV1 {
                node_ordinal: minted.node_ordinal,
                ..widest_node_reference()
            },
        ))),
        (true, None) => Err(Error::InvalidBinding),
    };
    minted.and_then(|minted| {
        let inputs: Vec<_> = member.step_inputs.iter().copied().chain(minted).collect();
        if inputs.len() > MAX_COMMUNITY_EXPANDED_INPUTS_V1 {
            Err(Error::CapacityExhausted)
        } else {
            Ok(inputs)
        }
    })
}

/// The `InvocationStep` row without CPI1 and CIN1: `1 + g(k)` nodes,
/// `k + g(k)` edges, and W(CIR1) plus every CIB1 and CPN1 of the step.
fn step_terms(
    timeline: TimelineId,
    generation: [u8; 16],
    inputs: &[CommunityTypedInputRefV1<'_>],
) -> CommunityPassTermsV1 {
    let closure = quoted_closure_len(timeline, generation, inputs);
    let node = |kind, index| quoted_node_len(timeline, generation, kind, index);
    let refs = CommunityTypedInputRefsV1::from_references(inputs);
    let (groups, bytes) = match inputs.len() {
        0 => (
            0,
            node(
                CommunityNativeNodeKindV1::InvocationStep,
                CommunityInputIndexV1::Empty,
            ),
        ),
        1..=MAX_COMMUNITY_DIRECT_INPUTS_V1 => (
            0,
            node(
                CommunityNativeNodeKindV1::InvocationStep,
                CommunityInputIndexV1::Direct(refs),
            ),
        ),
        total => {
            let chunks = inputs.chunks(MAX_COMMUNITY_DIRECT_INPUTS_V1);
            let groups = vec![widest_node_reference(); chunks.len()];
            let grouped = CommunityInputIndexV1::Grouped {
                groups: CommunityNativeNodeReferencesV1::from_references(&groups),
                total_leaf_count: total as u64,
            };
            let members: usize = chunks
                .map(|chunk| {
                    quoted_group_len(timeline, generation, chunk)
                        + node(
                            CommunityNativeNodeKindV1::InputIndex,
                            CommunityInputIndexV1::Direct(
                                CommunityTypedInputRefsV1::from_references(chunk),
                            ),
                        )
                })
                .sum();
            (
                groups.len(),
                members + node(CommunityNativeNodeKindV1::InvocationStep, grouped),
            )
        }
    };
    CommunityPassTermsV1 {
        nodes: 1 + groups as u64,
        edges: (inputs.len() + groups) as u64,
        bytes: (closure + bytes) as u64,
    }
}
