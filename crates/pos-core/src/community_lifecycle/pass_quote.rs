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
//! The quote reads no store and checks no authority. From the same records,
//! [`CommunityPassQuoteV1::demand`] derives the revision 11 key, ARD1 graph
//! and object demands (R11.1, R11.3 and R11.4(4)).

use super::input_group::quoted_group_len;
use super::native_node::{quoted_node_len, widest_node_reference};
use super::pass_graph::{CommunityPassGraphTermsV1, CommunityProtectionSizesV1};
use super::prepared::quoted_invocation_len;
use super::recording::quoted_recording_len;
use super::source_closure::quoted_closure_len;
use super::step::quoted_step_len;
use super::{
    head_len, widest_pass_key, CommunityBudgetQuoteInputV1, CommunityBudgetQuoteV1,
    CommunityDueMemberBudgetV1, CommunityEventDraftFragmentInputV1,
    CommunityEventDraftFragmentReferenceV1, CommunityEventDraftFragmentV1,
    CommunityEventDraftManifestInputV1, CommunityEventDraftManifestV1, CommunityGraphCountsV1,
    CommunityInputIndexV1, CommunityInvocationEvidenceInputV1, CommunityInvocationEvidenceV1,
    CommunityLifecycleErrorV1 as Error, CommunityMaterializationReferenceV1,
    CommunityNativeNodeKindV1, CommunityNativeNodeReferenceV1, CommunityNativeNodeReferencesV1,
    CommunityOutputUsageV1, CommunityPassKeyV1, CommunityPreparedInvocationInputV1,
    CommunitySharedCountsV1, CommunityStateProducerV1, CommunityStateRevisionInputV1,
    CommunityStateRevisionV1, CommunityTypedInputRefV1, CommunityTypedInputRefsV1, MeteringV1,
    Result, COMMUNITY_CUMULATIVE_RECORD_LIMITS_V1, COMMUNITY_MAXIMUM_STORE_KEYS_V1,
    COMMUNITY_SHARED_RECORD_LIMITS_V1, MAX_COMMUNITY_DIRECT_INPUTS_V1,
    MAX_COMMUNITY_EXPANDED_INPUTS_V1, MAX_COMMUNITY_OBJECT_BINDINGS_V1, WIDEST_HORIZON_MICROS,
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

/// One pass CBQ1 with its State-only maxima and the quoted records the
/// revision 11 demands are derived from.
pub struct CommunityPassQuoteV1 {
    quote: CommunityBudgetQuoteV1,
    state: CommunityPassTermsV1,
    total: CommunityPassTermsV1,
    fixed: FixedLengths,
    members: Vec<MemberRecords>,
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
        FixedLengths::new(key).and_then(|fixed| {
            input
                .members
                .iter()
                .map(|member| MemberRecords::new(&input, member))
                .collect::<Result<Vec<_>>>()
                .and_then(|members| Self::from_records(&input, fixed, members))
        })
    }

    fn from_records(
        input: &CommunityPassQuoteInputV1<'_>,
        fixed: FixedLengths,
        members: Vec<MemberRecords>,
    ) -> Result<Self> {
        let state = members
            .iter()
            .fold(CommunityPassTermsV1::default(), |state, member| {
                state.plus(member.state_terms(fixed))
            })
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
        let count = members.len() as u64;
        let total = state.plus(CommunityPassTermsV1 {
            nodes: count,
            edges: count,
            bytes: (fixed.measurement() * members.len() + fixed.recording(members.len())) as u64,
        });
        Self::budget_quote(input, total).map(|quote| Self {
            quote,
            state,
            total,
            fixed,
            members,
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
        split(self.state.fits(prior), self.total.fits(prior))
    }

    /// The revision 11 key, ARD1 graph and object demands of this pass over
    /// the domain's counts (R11.1(6), R11.3 and R11.4(4)).
    ///
    /// # Errors
    /// Returns `InvalidBinding` for a zero Timeline or generation.
    pub fn demand(&self, domain: CommunityPassDomainV1) -> Result<CommunityPassDemandV1> {
        let input = self.quote.as_input();
        CommunityProtectionSizesV1::new(input.timeline, input.generation)
            .map(|sizes| CommunityPassDemandV1::new(self, &sizes, domain))
    }
}

/// The domain counts the revision 11 demands start from, read under the
/// guard.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommunityPassDomainV1 {
    /// The selected CGR1's `graph_counts` (the initialization CGR1's for an
    /// Initial frontier), the State base (R11.3(1)).
    pub selected_graph: CommunityGraphCountsV1,
    /// The domain's live key count: CKP1 keys not Tombstoned (R11.1(6)).
    pub live_keys: u64,
    /// What the pass's materialization adds to the closure: a minted one,
    /// or a reused one not yet in the closure (R11.3(3)); zero otherwise.
    /// Its `keys` are its cohorts whose records join the closure.
    pub observation_graph: CommunityPassGraphTermsV1,
    /// The store keys a minted materialization provisions: its metadata
    /// key, one CES1 cohort per owning Timeline with a new CES1 and its
    /// union cohort when distinct (R11.1(4)); zero when reused.
    pub observation_keys: u64,
    /// The ARD1 rows a minted materialization binds to T: its new CES1s,
    /// COV1, Observation and `InputIndex` CPN1s, CIB1s and CPE1 (ADR-129
    /// revision 13, R13.1(3)); zero when reused, whose rows are bound.
    pub observation_rows: u64,
}

/// A pass's key, ARD1 graph, object and erasure demands, State first and
/// then with the recording (R11.5(1), R13.1(3)).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommunityPassDemandV1 {
    keys: [u64; 2],
    graph: [CommunityGraphCountsV1; 2],
    objects: [u64; 2],
    erasure_rows: [u64; 2],
    failure_reserve: u64,
}

/// The pass's own store keys: the metadata key, the `ExecutionState` `H_g`
/// cohort, the CED1/CEB1 `H_r` cohort (ADR-129 revision 13, R13.2(3)) and
/// the Measurement cohort, counted apart before Reserve (R11.1(3), (6)).
const PASS_STATE_KEYS: u64 = 4;

/// The pass's per-pass objects outside its members: CED1 and CEB1.
const PASS_STATE_OBJECTS: u64 = 2;

impl CommunityPassDemandV1 {
    fn new(
        quote: &CommunityPassQuoteV1,
        sizes: &CommunityProtectionSizesV1,
        domain: CommunityPassDomainV1,
    ) -> Self {
        let fixed = quote.fixed;
        let count = quote.members.len() as u64;
        let additions = quote
            .members
            .iter()
            .fold(domain.observation_graph, |total, member| {
                total.plus(member.graph(sizes, fixed))
            })
            .plus(CommunityPassGraphTermsV1 {
                keys: 1,
                ..CommunityPassGraphTermsV1::default()
            });
        let state = add_graph(
            domain.selected_graph,
            additions,
            state_depth(domain.selected_graph),
        );
        let recording = add_graph(
            state,
            fixed.recording_graph(sizes, quote.members.len()),
            state.maximum_depth.saturating_add(1),
        );
        let state_keys = domain
            .live_keys
            .saturating_add(PASS_STATE_KEYS)
            .saturating_add(domain.observation_keys);
        let state_objects = quote
            .members
            .iter()
            .map(MemberRecords::objects)
            .sum::<u64>()
            .saturating_add(PASS_STATE_OBJECTS);
        let state_rows = state_objects.saturating_add(domain.observation_rows);
        Self {
            keys: [state_keys, state_keys.saturating_add(1)],
            graph: [state, recording],
            objects: [state_objects, state_objects + 2 * count + 1],
            erasure_rows: [state_rows, state_rows + 2 * count + 1],
            failure_reserve: 2 * (count + 1),
        }
    }

    /// The live key count after the State keys, then with the recording key.
    #[must_use]
    pub const fn keys(&self) -> [u64; 2] {
        self.keys
    }

    /// The CGR1 State demand, then the Replay closure bound (R11.3(5)).
    #[must_use]
    pub const fn graph(&self) -> [CommunityGraphCountsV1; 2] {
        self.graph
    }

    /// The pass's COW1 objects without, then with, the recording objects
    /// (R11.4(4)).
    #[must_use]
    pub const fn objects(&self) -> [u64; 2] {
        self.objects
    }

    /// The ARD1 rows the pass binds to T, State then with the recording
    /// (R13.1(3)): the R11.2 per-member records, a minted materialization's
    /// rows, CED1 and CEB1; then the `2n + 1` CIV1, Measurement and CRR1
    /// rows. Each costs two erasure targets.
    #[must_use]
    pub const fn erasure_rows(&self) -> [u64; 2] {
        self.erasure_rows
    }

    /// `F_p = 2(n_due + 1)`: the targets of one CFI1 per due member and one
    /// CFO1 that a failed pass may register (R13.1(5)).
    #[must_use]
    pub const fn failure_reserve(&self) -> u64 {
        self.failure_reserve
    }

    /// R11.1(6): the live key count plus the State keys, then plus the
    /// recording key, is at most the `owner_policy_bytes` maximum.
    ///
    /// # Errors
    /// `CapacityExhausted`, then `RecordingUnavailable`.
    pub const fn require_keys(&self) -> Result<()> {
        let [state, total] = self.keys;
        split(
            state <= COMMUNITY_MAXIMUM_STORE_KEYS_V1,
            total <= COMMUNITY_MAXIMUM_STORE_KEYS_V1,
        )
    }

    /// R11.3(6): the State graph demand, then the Replay closure bound, is
    /// within every `graph_policy_bytes` maximum.
    ///
    /// # Errors
    /// `CapacityExhausted`, then `RecordingUnavailable`.
    pub fn require_graph(&self) -> Result<()> {
        let [state, total] = self.graph;
        split(state.within_maxima().is_ok(), total.within_maxima().is_ok())
    }

    /// R11.4(4): all of the pass's COW1 objects are at most the 2,048 CAU1
    /// object bindings.
    ///
    /// # Errors
    /// `CapacityExhausted` when they do not fit without the recording
    /// objects, then `RecordingUnavailable`.
    pub const fn require_objects(&self) -> Result<()> {
        let [state, total] = self.objects;
        let limit = MAX_COMMUNITY_OBJECT_BINDINGS_V1 as u64;
        split(state <= limit, total <= limit)
    }
}

/// The 14/19 split of R10.4(2): State fit first, then the full fit.
const fn split(state: bool, total: bool) -> Result<()> {
    if !state {
        Err(Error::CapacityExhausted)
    } else if total {
        Ok(())
    } else {
        Err(Error::RecordingUnavailable)
    }
}

/// The R11.3(4) State depth bound `max(D, 3 + max(D, 3))`.
const fn state_depth(selected: CommunityGraphCountsV1) -> u64 {
    let base = if selected.maximum_depth > 3 {
        selected.maximum_depth
    } else {
        3
    };
    base.saturating_add(3)
}

/// `counts` plus `additions`, at depth `depth`.
const fn add_graph(
    counts: CommunityGraphCountsV1,
    additions: CommunityPassGraphTermsV1,
    depth: u64,
) -> CommunityGraphCountsV1 {
    CommunityGraphCountsV1 {
        registrations: counts.registrations.saturating_add(additions.registrations),
        edges: counts.edges.saturating_add(additions.edges),
        keys: counts.keys.saturating_add(additions.keys),
        maximum_depth: depth,
        registration_bytes: counts
            .registration_bytes
            .saturating_add(additions.registration_bytes),
        artifact_bytes: counts
            .artifact_bytes
            .saturating_add(additions.artifact_bytes),
    }
}

/// Quoted lengths that depend only on T and G.
#[derive(Clone, Copy)]
struct FixedLengths {
    /// W(CPI1).
    step: usize,
    /// W(CSR1).
    revision: usize,
    /// Its one-input `StateRevision` CPN1.
    revision_node: usize,
    /// W(CIV1).
    evidence: usize,
    /// Its one-input Measurement CPN1.
    measurement_node: usize,
    /// W(CED1) plus W(CEB1) for the empty draft vector.
    drafts: usize,
    /// The widest pass key, for W(CRR1).
    key: CommunityPassKeyV1,
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
        revision_len(key).and_then(|revision| {
            evidence_len(key).and_then(|evidence| {
                drafts_len(key).map(|drafts| Self {
                    step: quoted_step_len(key),
                    revision,
                    revision_node: single(CommunityNativeNodeKindV1::StateRevision),
                    evidence,
                    measurement_node: single(CommunityNativeNodeKindV1::Measurement),
                    drafts,
                    key,
                })
            })
        })
    }

    /// One member's recording rows: W(CIV1) and its Measurement CPN1.
    const fn measurement(&self) -> usize {
        self.evidence + self.measurement_node
    }

    /// W(CRR1) for `members` due members.
    fn recording(&self, members: usize) -> usize {
        quoted_recording_len(self.key, members)
    }

    /// The R11.3(5) recording additions over the State demand: CRR1 with
    /// `2n` children, `n` CIV1s and `n` Measurement CPN1s with two children
    /// each, and the `ReplayRecording` and Measurement keys.
    fn recording_graph(
        &self,
        sizes: &CommunityProtectionSizesV1,
        members: usize,
    ) -> CommunityPassGraphTermsV1 {
        let count = members as u64;
        let per_member = sizes
            .record(self.evidence as u64, 0)
            .plus(sizes.record(self.measurement_node as u64, 2));
        (0..members)
            .fold(
                sizes.record(self.recording(members) as u64, 2 * count),
                |total, _| total.plus(per_member),
            )
            .plus(CommunityPassGraphTermsV1 {
                keys: 2,
                ..CommunityPassGraphTermsV1::default()
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

/// One input group of a step: W(CIB1) as `index`, W of its `InputIndex` CPN1, and the
/// number of its mode-0/2 leaves.
#[derive(Clone, Copy)]
struct Group {
    index: usize,
    node: usize,
    registered: usize,
}

/// One due member's quoted records (R10.3(5), R11.2(1)).
struct MemberRecords {
    /// `k_m`, every step input.
    inputs: usize,
    /// `e_m`, the step's mode-0/2 inputs, each an ARD1 edge.
    registered: usize,
    /// W(CIN1).
    invocation: usize,
    /// W(CIR1).
    closure: usize,
    /// W of the `InvocationStep` CPN1.
    step: usize,
    /// The CIB1 groups, empty for 256 inputs or fewer.
    groups: Vec<Group>,
    /// `S_m`.
    state_limit: u64,
}

impl MemberRecords {
    fn new(
        input: &CommunityPassQuoteInputV1<'_>,
        member: &CommunityPassQuoteMemberV1<'_>,
    ) -> Result<Self> {
        step_inputs(input, member).and_then(|inputs| {
            quoted_invocation_len(member.prepared_invocation).map(|invocation| {
                let (groups, step) = step_nodes(input.timeline, input.generation, &inputs);
                Self {
                    inputs: inputs.len(),
                    registered: registered(&inputs),
                    invocation,
                    closure: quoted_closure_len(input.timeline, input.generation, &inputs),
                    step,
                    groups,
                    state_limit: member.state_limit_bytes,
                }
            })
        })
    }

    /// The member's R10.3(5) State rows: the `InvocationStep` row with
    /// `1 + g` nodes and `k + g` edges, and the `StateRevision` row.
    fn state_terms(&self, fixed: FixedLengths) -> CommunityPassTermsV1 {
        let groups = self.groups.len();
        let group_bytes: usize = self
            .groups
            .iter()
            .map(|group| group.index + group.node)
            .sum();
        CommunityPassTermsV1 {
            nodes: 1 + groups as u64,
            edges: (self.inputs + groups) as u64,
            bytes: (fixed.step + self.invocation + self.closure + group_bytes + self.step) as u64,
        }
        .plus(CommunityPassTermsV1 {
            nodes: 1,
            edges: 1,
            bytes: self
                .state_limit
                .saturating_add((fixed.revision + fixed.revision_node) as u64),
        })
    }

    /// The member's `7 + 2g` State objects (R11.4(4)).
    const fn objects(&self) -> u64 {
        7 + 2 * self.groups.len() as u64
    }

    /// The member's R11.3(3) closure additions under the R11.2(1) child
    /// lists: CIR1, CIN1 → CIR1, CPI1 → CIN1, the step → CPI1 and its
    /// direct inputs or groups, each CIB1 and `InputIndex` CPN1 → its CIB1
    /// and leaves, CSC1, CSR1 → three, and the `StateRevision` CPN1 → three.
    fn graph(
        &self,
        sizes: &CommunityProtectionSizesV1,
        fixed: FixedLengths,
    ) -> CommunityPassGraphTermsV1 {
        let step_children = if self.groups.is_empty() {
            self.registered
        } else {
            self.groups.len()
        };
        let content = state_content_len(self.state_limit);
        self.groups.iter().fold(
            sizes
                .record(self.closure as u64, 0)
                .plus(sizes.record(self.invocation as u64, 1))
                .plus(sizes.record(fixed.step as u64, 1))
                .plus(sizes.record(self.step as u64, 1 + step_children as u64))
                .plus(sizes.record(content, 0))
                .plus(sizes.record(fixed.revision as u64, 3))
                .plus(sizes.record(fixed.revision_node as u64, 3)),
            |total, group| {
                total
                    .plus(sizes.record(group.index as u64, 0))
                    .plus(sizes.record(group.node as u64, 1 + group.registered as u64))
            },
        )
    }
}

/// The canonical CSC1 size at the State limit: prefix, schema digest and
/// the State bstr.
pub(super) const fn state_content_len(state_limit: u64) -> u64 {
    state_limit
        .saturating_add(head_len(state_limit) as u64)
        .saturating_add(7 + 34)
}

/// The number of mode-0 (native) and mode-2 (artifact) refs: those with an
/// ARD1 registration (R11.2(1)).
fn registered(inputs: &[CommunityTypedInputRefV1<'_>]) -> usize {
    inputs
        .iter()
        .filter(|input| {
            matches!(
                input,
                CommunityTypedInputRefV1::Native(_) | CommunityTypedInputRefV1::Artifact { .. }
            )
        })
        .count()
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

/// The step's CIB1 groups and W of its `InvocationStep` CPN1.
fn step_nodes(
    timeline: TimelineId,
    generation: [u8; 16],
    inputs: &[CommunityTypedInputRefV1<'_>],
) -> (Vec<Group>, usize) {
    let node = |kind, index| quoted_node_len(timeline, generation, kind, index);
    let step = |index| node(CommunityNativeNodeKindV1::InvocationStep, index);
    match inputs.len() {
        0 => (Vec::new(), step(CommunityInputIndexV1::Empty)),
        1..=MAX_COMMUNITY_DIRECT_INPUTS_V1 => (
            Vec::new(),
            step(CommunityInputIndexV1::Direct(
                CommunityTypedInputRefsV1::from_references(inputs),
            )),
        ),
        total => {
            let groups: Vec<Group> = inputs
                .chunks(MAX_COMMUNITY_DIRECT_INPUTS_V1)
                .map(|chunk| Group {
                    index: quoted_group_len(timeline, generation, chunk),
                    node: node(
                        CommunityNativeNodeKindV1::InputIndex,
                        CommunityInputIndexV1::Direct(CommunityTypedInputRefsV1::from_references(
                            chunk,
                        )),
                    ),
                    registered: registered(chunk),
                })
                .collect();
            let references = vec![widest_node_reference(); groups.len()];
            let grouped = CommunityInputIndexV1::Grouped {
                groups: CommunityNativeNodeReferencesV1::from_references(&references),
                total_leaf_count: total as u64,
            };
            (groups, step(grouped))
        }
    }
}
