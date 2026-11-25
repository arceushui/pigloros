//! The Memory pass Seal: the CPS1 and CPD1 a pass binds, the R10.3(7)
//! compares and annotation admission (#560 A4d; ADR-129 revisions 10, 14
//! and 15).
//!
//! Like the writer's transitions, Seal has two halves.
//! [`MemoryCommunityDomainV1::stage_seal`] reads the pass record under the
//! guard and refuses without changing anything.
//! [`MemoryCommunityDomainV1::apply_seal`], which only the trusted composition
//! root can call, latches the sealed result and moves the pass from Reserved
//! to Sealed. The candidate is a trusted-code input (journal 23071, item 8):
//! Seal re-checks the facts the record binds, namely the counts, the caps and
//! the trace room, and builds the two records that carry them.
//!
//! The compares are R10.3(7) in R14's reading:
//! - the CPD1 additions without annotations, plus the materialization's,
//!   are at most the CBQ1 maxima;
//! - with the annotations' charge they are within `P`, and with the prior
//!   counters within `C.nodes` and `C.edges`.
//!
//! R10.3(7) says only that Seal refuses a pass that fails them and that an
//! Abort resolves it. This module refuses with `InvalidBinding` (3): the
//! path is reachable only when the trusted actual counts exceed a quote that
//! already fitted at Reserve, a host defect. The code is pending an erratum.
//!
//! Annotations never refuse a pass (parent section 5). The invocations are
//! taken in selection order and the first with an included item keeps the
//! pass's one CAT1 and Annotation CPN1 (R15.6(6)); an item that does not fit
//! is omitted with reason 3 and selection continues, and every item of a
//! later invocation is omitted with reason 4.
//!
//! The admission is a separate step. [`MemoryCommunityDomainV1::plan_annotations`]
//! returns the retained items and the omission reasons of every invocation,
//! which is what a CRR1 coverage row (the retained count and the omission
//! set) and Commit need. The pipeline plans first, builds CRR1 from the
//! plan, and then calls [`MemoryCommunityDomainV1::stage_seal`] once with
//! the CRR1 digest and the plan. Seal recomputes the plan and refuses a
//! plan that differs, so the recording cannot be built over another
//! admission.
//!
//! What the admission re-derives, and what it does not:
//! - `P` and `C` on the actual counts, the 8,192 control operations and the
//!   trace room of `n_due + 1` rows, the `F_p` share of the pending entry
//!   (R15.5). The writer checks that `reserved.trace_rows` is `n_due + 1`
//!   and Seal relies on it.
//! - The graph maxima over the candidate's selected graph, with the trace
//!   closure on top (R11.3(5)). The bound is per pass, not cumulative: the
//!   Annotation CPN1 and the CAT1 are outside the CGR1 closure (R15.6(6)),
//!   records outside it are not charged to the CGR1 graph counts (R11.2(5)),
//!   and Commit selects the new CGR1's counts, from which the next pass's
//!   demand starts. So the up to 257 edges of one annotated pass do not
//!   add up across passes. Counting the trace on top of the selected counts
//!   over-counts, since the step's ancestry is already in them, and it bites
//!   only when the selected graph is within the trace's terms of a maximum.
//! - R11.1(6): one more live key against the store-wide 65,536. The row cap
//!   of R13 is per Timeline, so about a hundred contexts at their floor
//!   could reach the store-wide limit. The pass record does not say whether
//!   the trace cohort's key was provisioned at Reserve, so Seal counts one
//!   more and may omit an annotation that a later accounting would admit.
//!   An erratum should record the gap.
//! - The trace objects (R11.4(4)) are not re-derived: a pass of the largest
//!   roster binds at most 128 of the 2,048 object bindings, which a test
//!   pins.
//!
//! What Seal re-checks of the trusted input (journal 23071, item 8): the
//! invocations' context facts it can bind to the pass record, namely the
//! CPK1, the native producer ordinal, the evidence horizon (at most the
//! outcome horizon), the member's CMB1, the CPI1 and the store incarnation,
//! and that the invocations are in roster order. The Annotation CPN1's node
//! ordinal and its scope, authorization and provenance digests stay trusted,
//! as the CPN1 codec says. A defect of the input, including a guest index
//! out of order, refuses the Seal with `InvalidBinding`: it is not an
//! annotation outcome, so section 5's rule that annotations never refuse a
//! pass does not apply to it.
//!
//! The Reserve pipeline (A4c-3) supplies the candidate and A5 supplies the
//! annotation context and charges the same records at Commit, reusing the
//! staged encodings. The domain is
//! single-writer: a pass is staged and applied under one guard, so a pass
//! that is Sealed is resolved by its Commit or Abort and a Seal replayed
//! after either gives `InvalidBinding`. Only the digest of the sealed result
//! is latched. No CPS1, CPD1, CAT1 or CPN1 bytes are persisted, so
//! reconciling a Sealed pass later has to rebuild them.

use pos_core::community_lifecycle::{
    CommunityAnnotationCandidateV1, CommunityAnnotationChargeV1, CommunityAnnotationContextV1,
    CommunityAnnotationOmissionV1, CommunityAnnotationOmissionsV1, CommunityAnnotationRecordsV1,
    CommunityDependencyBundleInputV1, CommunityDependencyBundleV1, CommunityDigestListV1,
    CommunityEvidenceRootsV1, CommunityFactualBindingV1, CommunityGraphCountsV1,
    CommunityLifecycleErrorV1 as Error, CommunityReservationV1, CommunitySealedResultInputV1,
    CommunitySealedResultV1, CommunitySharedCountsV1, COMMUNITY_CONTROL_OPERATIONS_V1,
    COMMUNITY_CUMULATIVE_RECORD_LIMITS_V1, COMMUNITY_MAXIMUM_STORE_KEYS_V1,
    COMMUNITY_SHARED_RECORD_LIMITS_V1,
};
use pos_core::{AuthorityTrustRootSealV1, Hash, TimelineId};

use super::memory_domain::MemoryCommunityDomainV1;
use super::pass_planner::CommunityPassReadPortV1;
use super::pass_record::{CommunityPassRecordV1, CommunityPassStatusV1};

/// One invocation's validated annotation items, in selection order.
#[derive(Clone)]
pub struct CommunitySealInvocationV1<'a> {
    /// What sizes and binds the invocation's CAT1 and Annotation CPN1.
    pub context: CommunityAnnotationContextV1,
    /// The omission reasons the earlier validation of its member recorded.
    pub omissions: CommunityAnnotationOmissionsV1,
    /// The items that passed validation, in the guest's order.
    pub items: Vec<CommunityAnnotationCandidateV1<'a>>,
}

/// The sealed candidate: CPS1 and CPD1 fields except the trace fields and
/// the CPD1 identity, which Seal derives.
#[derive(Clone)]
pub struct CommunitySealCandidateV1<'a> {
    /// The CPI1 producers of the due invocations.
    pub invocation_step_digests: CommunityDigestListV1<'a>,
    /// The Event-draft vector identity, the empty vector included.
    pub event_draft_vector_digest: Hash,
    /// The CED1 identity.
    pub event_draft_manifest_digest: Hash,
    /// The new CSR1 identities in the admitted member order.
    pub new_revision_digests: CommunityDigestListV1<'a>,
    /// The new CMS1 identities.
    pub new_member_progress_digests: CommunityDigestListV1<'a>,
    /// The complete candidate CSH1.
    pub candidate_head_digest: Hash,
    /// CPD1: the selected CGR1 identity.
    pub graph_root_digest: Hash,
    /// CPD1: the factual binding of a nonempty pass.
    pub factual_binding: Option<CommunityFactualBindingV1>,
    /// CPD1: the required native nodes in native coordinate order.
    pub required_node_digests: CommunityDigestListV1<'a>,
    /// CPD1: the pass's own additions without its annotations' charge.
    pub additions: CommunitySharedCountsV1,
    /// CPD1: the selected graph counts.
    pub graph_counts: CommunityGraphCountsV1,
}

/// One Seal's writer inputs.
#[derive(Clone)]
pub struct CommunitySealInputV1<'a> {
    /// T.
    pub timeline: TimelineId,
    /// The reservation being sealed.
    pub reservation_operation_id: [u8; 16],
    /// The sealed candidate.
    pub candidate: CommunitySealCandidateV1<'a>,
    /// The due invocations' annotation items in selection order.
    pub invocations: Vec<CommunitySealInvocationV1<'a>>,
}

/// What Seal bound for a pass.
#[derive(Clone)]
pub struct CommunitySealedPassV1 {
    /// `H(CPS1)`, the sealed result.
    pub result_digest: Hash,
    /// `H(CPD1)`, CPS1's `dependency_bundle_digest`.
    pub dependency_bundle_digest: Hash,
    /// `H(CAT1)`, or `None` when no item was retained.
    pub annotation_manifest_digest: Option<Hash>,
    /// The digest of the Annotation CPN1, CPD1's `PresentationTrace` root.
    pub trace_root: Option<Hash>,
    /// What the retained annotations add to the counters; zero when none.
    pub annotation: CommunityAnnotationChargeV1,
    /// CPD1's `shared_counts`: the candidate's additions and the charge.
    pub shared_counts: CommunitySharedCountsV1,
    /// Each invocation's omission reasons, in the input's order.
    pub omissions: Vec<CommunityAnnotationOmissionsV1>,
    /// Each invocation's retained items, as indices into its `items`: the
    /// CRR1 `retained_annotation_count` is the length. Only one invocation
    /// retains any.
    pub retained: Vec<Vec<usize>>,
}

/// A Seal that passed every re-check and awaits its apply.
pub struct CommunityStagedSealV1 {
    key: (TimelineId, [u8; 16]),
    sealed: CommunitySealedPassV1,
}

impl CommunityStagedSealV1 {
    /// What the Seal bound.
    #[must_use]
    pub const fn sealed(&self) -> &CommunitySealedPassV1 {
        &self.sealed
    }
}

/// What the compares and the admission read from the pass and the domain.
struct SealRoom {
    prior: CommunitySharedCountsV1,
    materialization: CommunitySharedCountsV1,
    quote: [u64; 3],
    operations: u64,
    trace_rows: u64,
    graph: CommunityGraphCountsV1,
    keys: u64,
}

impl SealRoom {
    /// The `[nodes, edges, bytes]` the pass adds: the candidate's
    /// additions, the materialization's and the annotations' charge.
    fn totals(
        &self,
        additions: CommunitySharedCountsV1,
        charge: CommunityAnnotationChargeV1,
    ) -> [u64; 3] {
        [
            [self.materialization.nodes, additions.nodes, charge.nodes],
            [self.materialization.edges, additions.edges, charge.edges],
            [
                self.materialization.encoded_record_bytes,
                additions.encoded_record_bytes,
                charge.bytes,
            ],
        ]
        .map(|terms| {
            terms
                .iter()
                .fold(0_u64, |sum, term| sum.saturating_add(*term))
        })
    }

    /// R10.3(7), first compare: without annotations, at most the CBQ1.
    fn within_quote(&self, additions: CommunitySharedCountsV1) -> bool {
        self.totals(additions, CommunityAnnotationChargeV1::default())
            .iter()
            .zip(self.quote)
            .all(|(total, maximum)| *total <= maximum)
    }

    /// R10.3(7), second compare, the counted set and the trace room: the
    /// totals with `charge` are within `P`, the counters within `C`, the
    /// Annotation CPN1 within the 8,192 control operations and its rows
    /// within the held share.
    fn fits(
        &self,
        additions: CommunitySharedCountsV1,
        charge: CommunityAnnotationChargeV1,
    ) -> bool {
        let total = self.totals(additions, charge);
        let [nodes, edges, _] = COMMUNITY_CUMULATIVE_RECORD_LIMITS_V1;
        total
            .iter()
            .zip(COMMUNITY_SHARED_RECORD_LIMITS_V1)
            .all(|(total, limit)| *total <= limit)
            && self.prior.nodes.saturating_add(total[0]) <= nodes
            && self.prior.edges.saturating_add(total[1]) <= edges
            && self.operations.saturating_add(charge.nodes) <= COMMUNITY_CONTROL_OPERATIONS_V1
            && charge.rows <= self.trace_rows
    }

    /// Whether the staged annotation records fit beside the pass: the
    /// counted bounds, one more live key and the graph maxima.
    fn admits(
        &self,
        additions: CommunitySharedCountsV1,
        records: &CommunityAnnotationRecordsV1,
    ) -> bool {
        self.fits(additions, records.charge())
            && self.keys.saturating_add(records.graph().keys) <= COMMUNITY_MAXIMUM_STORE_KEYS_V1
            && records.fits_graph(self.graph)
    }
}

/// The admitted annotations of a pass: the one retained set, every
/// invocation's omission reasons and its retained items.
#[derive(Clone, Eq, PartialEq)]
pub struct CommunityAnnotationPlanV1 {
    /// The staged CAT1 and Annotation CPN1, or `None` when no item fits.
    pub records: Option<CommunityAnnotationRecordsV1>,
    /// Each invocation's omission reasons, in the input's order: its earlier
    /// reasons and the reasons 3 and 4 of the admission.
    pub omissions: Vec<CommunityAnnotationOmissionsV1>,
    /// Each invocation's retained items, as indices into its `items`: the
    /// CRR1 `retained_annotation_count` is the length. Only one invocation
    /// retains any.
    pub retained: Vec<Vec<usize>>,
}

/// R14 RN.1(6) and R15.6(6): items in selection order, each kept only if
/// the set it joins still fits; the first invocation that keeps an item owns
/// the pass's annotations.
///
/// Each trial stages the whole set again, so an invocation of `m` items
/// costs `m` stagings of up to 1,024 items. That is quadratic in the item
/// count, bounded by the CAT1 limits, under the guard.
fn admit(
    room: &SealRoom,
    additions: CommunitySharedCountsV1,
    invocations: &[CommunitySealInvocationV1<'_>],
) -> Result<CommunityAnnotationPlanV1, Error> {
    let mut admission = CommunityAnnotationPlanV1 {
        records: None,
        omissions: invocations
            .iter()
            .map(|invocation| invocation.omissions)
            .collect(),
        retained: vec![Vec::new(); invocations.len()],
    };
    let mut owner = None;
    for (index, invocation) in invocations.iter().enumerate() {
        for (position, item) in invocation.items.iter().enumerate() {
            if owner.is_some_and(|owner| owner != index) {
                admission.omissions[index] = admission.omissions[index]
                    .with_reason(CommunityAnnotationOmissionV1::AnnotationPolicy);
                continue;
            }
            let mut trial: Vec<_> = admission.retained[index]
                .iter()
                .map(|kept| invocation.items[*kept])
                .collect();
            trial.push(*item);
            match CommunityAnnotationRecordsV1::stage(&invocation.context, &trial) {
                Ok(Some(records)) if room.admits(additions, &records) => {
                    owner = Some(index);
                    admission.retained[index].push(position);
                    admission.records = Some(records);
                }
                Ok(_) | Err(Error::BoundsExceeded) => {
                    admission.omissions[index] = admission.omissions[index]
                        .with_reason(CommunityAnnotationOmissionV1::AnnotationBudget);
                }
                Err(error) => return Err(error),
            }
        }
    }
    Ok(admission)
}

impl MemoryCommunityDomainV1 {
    /// Admit the annotations of a pass: the compares, the context checks
    /// and the selection of items, without building any record of the Seal.
    ///
    /// The result is a pure function of the pass record and the input, so
    /// the pipeline builds CRR1 from it and [`Self::stage_seal`] recomputes
    /// it.
    ///
    /// # Errors
    /// Returns `EvidenceUnavailable` for a reservation with no pass record
    /// and `InvalidBinding` for a Committed or Aborted pass. Then
    /// `InvalidBinding` when the candidate's additions and the
    /// materialization's exceed a CBQ1 maximum or `P` or `C` without any
    /// annotation (R10.3(7) names no code; the pass is resolved by an
    /// Abort), for an invocation context that does not match the pass and
    /// for a defect of the trusted input that an item staging finds.
    pub fn plan_annotations(
        &self,
        input: &CommunitySealInputV1<'_>,
    ) -> Result<CommunityAnnotationPlanV1, Error> {
        let record = self.unresolved_record(input.timeline, input.reservation_operation_id)?;
        let room = self.seal_room(record, input.candidate.graph_counts);
        let additions = input.candidate.additions;
        if !(room.within_quote(additions)
            && room.fits(additions, CommunityAnnotationChargeV1::default()))
        {
            return Err(Error::InvalidBinding);
        }
        self.check_contexts(record, &input.candidate, &input.invocations)
            .and_then(|()| admit(&room, additions, &input.invocations))
    }

    /// The pass reserved under `(T, reservation_operation_id)`, which must
    /// be Reserved or Sealed.
    fn unresolved_record(
        &self,
        timeline: TimelineId,
        reservation_operation_id: [u8; 16],
    ) -> Result<&CommunityPassRecordV1, Error> {
        let record = self
            .pass_record(timeline, reservation_operation_id)
            .ok_or(Error::EvidenceUnavailable)?;
        if record.status.unresolved() {
            Ok(record)
        } else {
            Err(Error::InvalidBinding)
        }
    }

    /// Re-check a Seal against its pass record and stage it.
    ///
    /// `replay_recording_digest` is the CRR1 the pipeline built from
    /// `planned`, the result of [`Self::plan_annotations`]. Seal plans again
    /// to verify `planned`, so the admission, which is quadratic in the item
    /// count, runs twice in a pipeline.
    ///
    /// A Seal of a Sealed pass is a replay: it stages the same result again
    /// and is refused only for a different one. A replay is also a fresh
    /// read of the store-wide live key count, so one that comes after the
    /// count grew to its limit can be refused with `Conflict` (fail
    /// closed). The clean fix is a flag on the pass record saying whether
    /// the trace key was provisioned at Reserve (R11.1(6)).
    ///
    /// # Errors
    /// Returns the errors of [`Self::plan_annotations`], `InvalidBinding`
    /// for a `planned` that is not the plan Seal computes, the CPD1 and CPS1
    /// construction errors and, for a Sealed pass, `Conflict` for a result
    /// other than the latched one.
    pub fn stage_seal(
        &self,
        input: &CommunitySealInputV1<'_>,
        replay_recording_digest: Hash,
        planned: &CommunityAnnotationPlanV1,
    ) -> Result<CommunityStagedSealV1, Error> {
        let key = (input.timeline, input.reservation_operation_id);
        let record = self.unresolved_record(key.0, key.1)?;
        self.plan_annotations(input)
            .and_then(|plan| {
                if plan == *planned {
                    seal_pass(record, &input.candidate, replay_recording_digest, plan)
                } else {
                    Err(Error::InvalidBinding)
                }
            })
            .and_then(|sealed| {
                if record.status == CommunityPassStatusV1::Sealed
                    && record.sealed_result_digest != Some(sealed.result_digest)
                {
                    Err(Error::Conflict)
                } else {
                    Ok(CommunityStagedSealV1 { key, sealed })
                }
            })
    }

    /// What a Seal binds of each invocation's annotation context to the
    /// pass (journal 23071, item 8): the invocations are in roster order,
    /// and each names this pass's CPK1, native producer (its own and its
    /// step's: the pass producer mints both), store incarnation, member and
    /// the CPI1 at the member's position, and a horizon within the outcome
    /// horizon (R13.2(4a): the trace horizon is at most `H_r`).
    fn check_contexts(
        &self,
        record: &CommunityPassRecordV1,
        candidate: &CommunitySealCandidateV1<'_>,
        invocations: &[CommunitySealInvocationV1<'_>],
    ) -> Result<(), Error> {
        let reserved = &record.reserved;
        let reservation = reserved.reservation;
        invocations
            .iter()
            .try_fold(None, |previous: Option<usize>, invocation| {
                let context = &invocation.context;
                let position = reserved
                    .members
                    .iter()
                    .position(|member| member.cmb1_digest == context.member_binding_digest);
                let producer = reservation.native_producer_ordinal;
                let same_pass = context.pass_key == reservation.pass_key;
                // Both lists are in due-roster order: the member's CPI1 is the
                // one at its own position.
                let named_step = position
                    .and_then(|at| candidate.invocation_step_digests.iter().nth(at))
                    == Some(context.invocation_step_digest);
                let bound = same_pass
                    && context.producer_ordinal == producer
                    && context.evidence_not_after_micros <= reserved.outcome_horizon_micros
                    && context.step.store_incarnation == self.store_incarnation
                    && context.step.producer_ordinal == producer
                    && named_step
                    && position > previous;
                if bound {
                    Ok(position)
                } else {
                    Err(Error::InvalidBinding)
                }
            })
            .map(drop)
    }

    /// The counts a pass's Seal compares against, read under the guard.
    fn seal_room(&self, record: &CommunityPassRecordV1, graph: CommunityGraphCountsV1) -> SealRoom {
        let reservation = record.reserved.reservation;
        SealRoom {
            prior: record.prior_shared_counts,
            materialization: record.materialization.unwrap_or_default(),
            quote: record.reserved.quote_maxima,
            operations: self.control_operations(
                reservation.pass_key.timeline(),
                reservation.pass_key.generation(),
            ),
            trace_rows: record.reserved.trace_rows,
            graph,
            keys: self.live_keys(),
        }
    }

    /// Apply a staged Seal in the guarded step: the pass is Sealed and its
    /// result digest is latched. Applying the same Seal again changes
    /// nothing.
    ///
    /// # Errors
    /// Returns `InvalidBinding` for a pass that is missing or resolved, and
    /// `Conflict` for a Sealed pass whose latched result differs.
    pub fn apply_seal(
        &mut self,
        _seal: &'static AuthorityTrustRootSealV1,
        staged: &CommunityStagedSealV1,
    ) -> Result<(), Error> {
        let digest = staged.sealed.result_digest;
        match self.pass_status(staged.key.0, staged.key.1) {
            Some(CommunityPassStatusV1::Reserved) => {
                self.set_pass_status(staged.key.0, staged.key.1, CommunityPassStatusV1::Sealed);
                self.pass_records
                    .entry(staged.key)
                    .and_modify(|record| record.sealed_result_digest = Some(digest));
                Ok(())
            }
            Some(CommunityPassStatusV1::Sealed) => {
                let latched = self
                    .pass_records
                    .get(&staged.key)
                    .and_then(|record| record.sealed_result_digest);
                if latched == Some(digest) {
                    Ok(())
                } else {
                    Err(Error::Conflict)
                }
            }
            _ => Err(Error::InvalidBinding),
        }
    }
}

/// Build the CPD1 and the CPS1 over the admitted annotations.
fn seal_pass(
    record: &CommunityPassRecordV1,
    candidate: &CommunitySealCandidateV1<'_>,
    replay_recording_digest: Hash,
    plan: CommunityAnnotationPlanV1,
) -> Result<CommunitySealedPassV1, Error> {
    let reservation = record.reserved.reservation;
    let annotation = plan
        .records
        .as_ref()
        .map(CommunityAnnotationRecordsV1::charge);
    let charge = annotation.unwrap_or_default();
    let shared_counts = CommunitySharedCountsV1 {
        nodes: candidate.additions.nodes.saturating_add(charge.nodes),
        edges: candidate.additions.edges.saturating_add(charge.edges),
        declared_inputs: candidate.additions.declared_inputs,
        encoded_record_bytes: candidate
            .additions
            .encoded_record_bytes
            .saturating_add(charge.bytes),
    };
    let trace_root = plan
        .records
        .as_ref()
        .map(|records| records.node().node_digest);
    let manifest_digest = plan
        .records
        .as_ref()
        .map(CommunityAnnotationRecordsV1::manifest_digest);
    CommunityDependencyBundleV1::new(CommunityDependencyBundleInputV1 {
        pass_key: reservation.pass_key,
        native_producer_ordinal: reservation.native_producer_ordinal,
        graph_root_digest: candidate.graph_root_digest,
        factual_binding: candidate.factual_binding,
        required_node_digests: candidate.required_node_digests,
        optional_evidence_roots: CommunityEvidenceRootsV1 {
            presentation_trace: trace_root,
            replay_recording: Some(replay_recording_digest),
        },
        shared_counts,
        graph_counts: candidate.graph_counts,
        evidence_not_after_micros: reservation.evidence_not_after_micros,
    })
    .map(|bundle| bundle.digest())
    .and_then(|dependency_bundle_digest| {
        CommunityReservationV1::new(reservation)
            .and_then(|reserved| {
                CommunitySealedResultV1::new(CommunitySealedResultInputV1 {
                    pass_key: reservation.pass_key,
                    reservation_digest: reserved.digest(),
                    invocation_step_digests: candidate.invocation_step_digests,
                    event_draft_vector_digest: candidate.event_draft_vector_digest,
                    event_draft_manifest_digest: candidate.event_draft_manifest_digest,
                    new_revision_digests: candidate.new_revision_digests,
                    new_member_progress_digests: candidate.new_member_progress_digests,
                    candidate_head_digest: candidate.candidate_head_digest,
                    dependency_bundle_digest,
                    annotation_manifest_digest: manifest_digest,
                    replay_recording_digest,
                    evidence_not_after_micros: reservation.evidence_not_after_micros,
                })
            })
            .map(|sealed| CommunitySealedPassV1 {
                result_digest: sealed.digest(),
                dependency_bundle_digest,
                annotation_manifest_digest: manifest_digest,
                trace_root,
                annotation: charge,
                shared_counts,
                omissions: plan.omissions,
                retained: plan.retained,
            })
    })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
