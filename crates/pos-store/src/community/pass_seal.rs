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
//! Annotations never refuse a pass (parent section 5). The invocations are
//! taken in selection order and the first with an included item keeps the
//! pass's one CAT1 and Annotation CPN1 (R15.6(6)); an item that does not fit
//! is omitted with reason 3 and selection continues, and every item of a
//! later invocation is omitted with reason 4. The trace room is `n_due + 1`
//! rows, the `F_p` share of the pending entry (R15.5). `P` and `C` are the
//! only trace bounds Seal re-derives: R13's row bound caps a Timeline far
//! below the V1 key, graph and object maxima, so a trace never reaches them.

use pos_core::community_lifecycle::{
    CommunityAnnotationCandidateV1, CommunityAnnotationChargeV1, CommunityAnnotationContextV1,
    CommunityAnnotationOmissionV1, CommunityAnnotationOmissionsV1, CommunityAnnotationRecordsV1,
    CommunityDependencyBundleInputV1, CommunityDependencyBundleV1, CommunityDigestListV1,
    CommunityEvidenceRootsV1, CommunityFactualBindingV1, CommunityGraphCountsV1,
    CommunityLifecycleErrorV1 as Error, CommunityReservationV1, CommunitySealedResultInputV1,
    CommunitySealedResultV1, CommunitySharedCountsV1, COMMUNITY_CONTROL_OPERATIONS_V1,
    COMMUNITY_CUMULATIVE_RECORD_LIMITS_V1, COMMUNITY_SHARED_RECORD_LIMITS_V1,
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
    /// The mandatory CRR1 Replay root.
    pub replay_recording_digest: Hash,
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
}

/// The admitted annotations: the one retained set and every invocation's
/// omission reasons.
struct Admission {
    records: Option<CommunityAnnotationRecordsV1>,
    omissions: Vec<CommunityAnnotationOmissionsV1>,
}

/// R14 RN.1(6) and R15.6(6): items in selection order, each kept only if
/// the set it joins still fits; the first invocation that keeps an item owns
/// the pass's annotations.
fn admit(
    room: &SealRoom,
    additions: CommunitySharedCountsV1,
    invocations: &[CommunitySealInvocationV1<'_>],
) -> Result<Admission, Error> {
    let mut admission = Admission {
        records: None,
        omissions: invocations
            .iter()
            .map(|invocation| invocation.omissions)
            .collect(),
    };
    let mut owner = None;
    for (index, invocation) in invocations.iter().enumerate() {
        let mut included = Vec::new();
        for item in &invocation.items {
            if owner.is_some_and(|owner| owner != index) {
                admission.omissions[index] = admission.omissions[index]
                    .with_reason(CommunityAnnotationOmissionV1::AnnotationPolicy);
                continue;
            }
            let mut trial = included.clone();
            trial.push(*item);
            match CommunityAnnotationRecordsV1::stage(&invocation.context, &trial) {
                Ok(Some(records)) if room.fits(additions, records.charge()) => {
                    included = trial;
                    owner = Some(index);
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
    /// Re-check a Seal against its pass record and stage it.
    ///
    /// A Seal of a Sealed pass is a replay: it stages the same result again
    /// and is refused only for a different one.
    ///
    /// # Errors
    /// Returns `EvidenceUnavailable` for a reservation with no pass record
    /// and `InvalidBinding` for a Committed or Aborted pass. Then
    /// `CapacityExhausted` when the candidate's additions and the
    /// materialization's exceed a CBQ1 maximum or `P` or `C` without any
    /// annotation (R10.3(7): the pass is resolved by an Abort), the staging
    /// errors of an item that is not an annotation of its invocation
    /// (`InvalidBinding`), the CPD1 and CPS1 construction errors and, for a
    /// Sealed pass, `Conflict` for a result other than the latched one.
    pub fn stage_seal(
        &self,
        input: &CommunitySealInputV1<'_>,
    ) -> Result<CommunityStagedSealV1, Error> {
        let key = (input.timeline, input.reservation_operation_id);
        let record = self
            .pass_record(key.0, key.1)
            .ok_or(Error::EvidenceUnavailable)?;
        if !record.status.unresolved() {
            return Err(Error::InvalidBinding);
        }
        let room = self.seal_room(record);
        let additions = input.candidate.additions;
        if !(room.within_quote(additions)
            && room.fits(additions, CommunityAnnotationChargeV1::default()))
        {
            return Err(Error::CapacityExhausted);
        }
        admit(&room, additions, &input.invocations)
            .and_then(|admission| seal_pass(record, &input.candidate, admission))
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

    /// The counts a pass's Seal compares against, read under the guard.
    fn seal_room(&self, record: &CommunityPassRecordV1) -> SealRoom {
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
    admission: Admission,
) -> Result<CommunitySealedPassV1, Error> {
    let reservation = record.reserved.reservation;
    let annotation = admission.records.map(|records| records.charge());
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
    let trace_root = admission.records.map(|records| records.node().node_digest);
    let manifest_digest = admission.records.map(|records| records.manifest_digest());
    CommunityDependencyBundleV1::new(CommunityDependencyBundleInputV1 {
        pass_key: reservation.pass_key,
        native_producer_ordinal: reservation.native_producer_ordinal,
        graph_root_digest: candidate.graph_root_digest,
        factual_binding: candidate.factual_binding,
        required_node_digests: candidate.required_node_digests,
        optional_evidence_roots: CommunityEvidenceRootsV1 {
            presentation_trace: trace_root,
            replay_recording: Some(candidate.replay_recording_digest),
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
                    replay_recording_digest: candidate.replay_recording_digest,
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
                omissions: admission.omissions,
            })
    })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
