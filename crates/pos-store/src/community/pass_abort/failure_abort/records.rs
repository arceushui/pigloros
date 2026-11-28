//! The records a failure Abort derives (ADR-129 R15.1 and R15.3(2) step 6,
//! (4)): the protected CFO1 and CFI1s and their control batch, the
//! in-Abort `SetReason` records, and the CAV1, CAU1 and CMI1 that bind them.
//!
//! Nothing here reads a clock or commits: each function maps its inputs to
//! bytes and digests.

use pos_core::community_lifecycle::{
    community_recipient_identity_digest_v1, CommunityArtifactKindV1, CommunityArtifactOperationV1,
    CommunityAuthorityEvidenceInputV1, CommunityAuthorityEvidenceV1, CommunityClockBoundV1,
    CommunityCurrentViewV1, CommunityKeyIntentV1, CommunityLifecycleErrorV1 as Error,
    CommunityMaterializationInputV1, CommunityMaterializationReferenceV1,
    CommunityMaterializationV1, CommunityObjectBindingV1, CommunityPassKeyV1,
    CommunityProducerBindingV1, CommunityQuarantineControlInputV1,
    CommunityQuarantineControlKindV1, CommunityQuarantineControlV1, CommunityQuarantineDeltaRowV1,
    CommunityQuarantineDispositionV1, CommunityQuarantineKeyV1, CommunityQuarantineOutcomeInputV1,
    CommunityQuarantineOutcomeV1, CommunityQuarantineReasonEvidenceV1, CommunityQuarantineReasonV1,
    CommunityQuarantineReasonsV1, CommunityQuarantineRevisionInputV1,
    CommunityQuarantineRevisionV1,
};
use pos_core::{ArtifactChildEdgeV1, AuthorityTrustRootSealV1, Hash, TimelineId};
use zeroize::Zeroizing;

use super::super::super::current_view_head::CommunityViewRowsV1;
use super::super::super::extractor::{
    prepare_community_pass_control_batch_v1, CommunityArtifactBatchV1,
    CommunityArtifactRecordInputV1, CommunityPassControlBatchInputV1,
};
use super::super::super::lifecycle_authority::CommunityLifecycleAuthorityV1;
use super::super::super::memory_domain::MemoryCommunityDomainV1;
use super::super::super::pass_record::{CommunityPassMemberDigestsV1, CommunityPassRecordV1};
use super::super::super::protection::{
    CommunityArtifactProtectorV1, CommunityProtectedRecordV1, CommunityRecordEvidenceV1,
};
use super::super::super::quarantine::{
    ledger_states, CommunityQuarantineContextV1, CommunityQuarantineReceiptV1, QuarantineLedgerV1,
    QuarantineReasonStateV1, SetReasonBoundV1,
};
use super::super::super::store_domain::CommunityStoreDomainV1;
use super::super::failure::{CommunityObservedFailureV1, DerivedFailureV1};
use super::super::operator::{decision_row, MetadataWriteV1};

/// The trusted-clock reservation of one failure Abort: its identity, its
/// sample `t_a` and its decision bound.
#[derive(Clone, Copy)]
pub(super) struct ClockV1 {
    pub(super) reservation_id: u64,
    pub(super) sample_micros: u64,
    pub(super) bound_micros: u64,
}

/// Protect the CFI1s and then the CFO1 listing them, all under the failure
/// cohort key, in that order (R15.4(4a)).
pub(super) fn protect_failure(
    protector: &mut CommunityArtifactProtectorV1,
    derived: &DerivedFailureV1,
    commitments: (Hash, Hash),
) -> Result<Vec<CommunityProtectedRecordV1>, Error> {
    let evidence = |children| CommunityRecordEvidenceV1 {
        owner_binding_digest: commitments.0,
        host_provenance_digest: commitments.1,
        children,
    };
    let mut records = derived
        .invocations
        .iter()
        .map(|invocation| {
            protector.protect(
                CommunityArtifactKindV1::LifecycleControl,
                &invocation.bytes,
                evidence(&[]),
            )
        })
        .collect::<Result<Vec<_>, Error>>()?;
    let edges = child_edges(&records);
    protector
        .protect(
            CommunityArtifactKindV1::LifecycleControl,
            &derived.failure,
            evidence(&edges),
        )
        .map(|outcome| {
            records.push(outcome);
            records
        })
}

/// The CFO1's child edges: one required edge per CFI1, in the strict
/// `(class, digest, address)` order.
fn child_edges(records: &[CommunityProtectedRecordV1]) -> Vec<ArtifactChildEdgeV1> {
    let mut edges: Vec<ArtifactChildEdgeV1> = records
        .iter()
        .map(|record| {
            let registration = record.registration();
            ArtifactChildEdgeV1 {
                artifact_class: registration.fields().artifact_class,
                artifact_digest: registration.fields().artifact_digest,
                registration_address: registration.address(),
                required: true,
            }
        })
        .collect();
    edges.sort_by_key(|edge| {
        (
            edge.artifact_class,
            edge.artifact_digest,
            edge.registration_address,
        )
    });
    edges
}

/// The facts of a pass control batch.
#[derive(Clone, Copy)]
pub(super) struct BatchFactsV1 {
    pub(super) pass_key: CommunityPassKeyV1,
    pub(super) owner_binding_digest: Hash,
    pub(super) scope_cover_digest: Hash,
    pub(super) head: Hash,
}

/// The extractor's pass control batch over `records`.
pub(super) fn control_batch(
    seal: &'static AuthorityTrustRootSealV1,
    protector: &CommunityArtifactProtectorV1,
    records: &[CommunityProtectedRecordV1],
    facts: BatchFactsV1,
) -> Result<CommunityArtifactBatchV1, Error> {
    let inputs: Vec<CommunityArtifactRecordInputV1<'_>> = records
        .iter()
        .map(|record| CommunityArtifactRecordInputV1 {
            object: record.object(),
            registration: record.registration(),
        })
        .collect();
    prepare_community_pass_control_batch_v1(
        seal,
        CommunityPassControlBatchInputV1 {
            pass_key: facts.pass_key,
            owner_binding_digest: facts.owner_binding_digest,
            scope_cover_digest: facts.scope_cover_digest,
            records: &inputs,
            current_head: facts.head,
            expected_head: facts.head,
        },
        &[protector],
    )
}

/// What the in-Abort `SetReason` of one failure stages.
pub(super) struct QuarantineApplyV1 {
    pub(super) key: Hash,
    pub(super) control_operation_id: [u8; 16],
    pub(super) request: Zeroizing<Vec<u8>>,
    pub(super) revision: Zeroizing<Vec<u8>>,
    pub(super) outcome: Zeroizing<Vec<u8>>,
    pub(super) delta: CommunityQuarantineDeltaRowV1,
    pub(super) ledger: QuarantineLedgerV1,
    pub(super) bound: SetReasonBoundV1,
    pub(super) receipt: CommunityQuarantineReceiptV1,
}

/// The facts every in-Abort `SetReason` shares (R15.3(4)).
#[derive(Clone, Copy)]
pub(super) struct QuarantineFactsV1<'a> {
    pub(super) context: CommunityQuarantineContextV1<'a>,
    pub(super) timeline: TimelineId,
    pub(super) generation: [u8; 16],
    pub(super) head: Hash,
    pub(super) failure_digest: Hash,
    pub(super) horizon: u64,
    pub(super) bound_micros: u64,
}

/// One failure's observed fields, its member and its CFI1's provenance.
pub(super) struct FailedMemberV1<'a> {
    pub(super) failure: &'a CommunityObservedFailureV1<'a>,
    pub(super) member: &'a CommunityPassMemberDigestsV1,
    pub(super) provenance: Hash,
}

impl MemoryCommunityDomainV1 {
    /// The CQC1, CQR1 and CQO1 of the failure's mapped reason, appended to
    /// its member's CQK1 ledger (R15.3(4)): the expected ledger is the
    /// domain-private index's head, and the reason is new (no active reason
    /// can exist while the pass is unresolved).
    pub(super) fn quarantine_apply(
        &self,
        facts: &QuarantineFactsV1<'_>,
        failed: &FailedMemberV1<'_>,
        (control_operation_id, reason): ([u8; 16], CommunityQuarantineReasonV1),
    ) -> Result<QuarantineApplyV1, Error> {
        facts
            .context
            .profile
            .as_input()
            .roster
            .get(failed.member.roster_index)
            .ok_or(Error::InvalidBinding)
            .and_then(|row| {
                CommunityQuarantineKeyV1::new(
                    facts.timeline,
                    row.stable_entry(),
                    row.implementation(),
                )
            })
            .and_then(|key| {
                let digest = key.digest();
                let current = self.quarantine_index.get(&digest);
                let expected = current.map(|ledger| ledger.head);
                set_reason_request(facts, failed, (key, control_operation_id, reason, expected))
                    .and_then(|(request, request_digest)| {
                        appended(
                            facts,
                            (key, current),
                            (control_operation_id, reason),
                            request_digest,
                        )
                        .map(|appended| {
                            apply_of(
                                (facts, failed),
                                (digest, control_operation_id, reason),
                                (request, request_digest),
                                (appended, expected),
                                current,
                            )
                        })
                    })
            })
    }

    /// The CAV1 of the failure Abort, read inside its guard (R15.1(5)):
    /// T's current selection (its frontier and the head ref of the first
    /// roster member's CSR1, R16.5(4)), no scope rows, the metadata chain's
    /// authority row, the roster's trust rows, both pass keys and the clock
    /// latch.
    pub(super) fn failure_view(
        &self,
        context: CommunityQuarantineContextV1<'_>,
        lifecycle: &CommunityLifecycleAuthorityV1,
        record: &CommunityPassRecordV1,
        write: &MetadataWriteV1,
        keys: &[&CommunityKeyIntentV1],
    ) -> Result<CommunityCurrentViewV1, Error> {
        let pass_key = record.reserved.reservation.pass_key;
        self.head_view(
            pass_key.timeline(),
            vec![],
            (write.leaf_grant_id, &write.request),
        )
        .and_then(|head| {
            self.abort_trust_rows(context, lifecycle.trust_scope(), record)
                .map(|trust_rows| (head, trust_rows))
        })
        .and_then(|(head, trust_rows)| {
            self.current_view(
                head,
                CommunityViewRowsV1 {
                    coordinates: (
                        pass_key.timeline(),
                        pass_key.generation(),
                        CommunityStoreDomainV1::inventory_generation(self),
                    ),
                    trust_rows,
                    keys,
                },
            )
        })
    }
}

/// The CQR1 and CQO1 that append a reason to a ledger, and the ledger.
struct AppendedV1 {
    revision: Zeroizing<Vec<u8>>,
    head: Hash,
    outcome: Zeroizing<Vec<u8>>,
    outcome_digest: Hash,
    ordinal: u64,
    horizon: u64,
    reasons: Vec<CommunityQuarantineReasonEvidenceV1>,
}

/// The CQR1 and CQO1 that append `reason` to the ledger `current` of `key`
/// under the request `request_digest`, with the horizon `min(current ledger
/// horizon, failure horizon)`.
fn appended(
    facts: &QuarantineFactsV1<'_>,
    (key, current): (CommunityQuarantineKeyV1<'_>, Option<&QuarantineLedgerV1>),
    (control_operation_id, reason): ([u8; 16], CommunityQuarantineReasonV1),
    request_digest: Hash,
) -> Result<AppendedV1, Error> {
    let expected = current.map(|ledger| ledger.head);
    let mut reasons = current.map_or_else(Vec::new, |ledger| ledger.reasons.clone());
    reasons.push(CommunityQuarantineReasonEvidenceV1 {
        reason,
        failure_evidence_digest: facts.failure_digest,
    });
    reasons.sort_by_key(|row| row.reason.code());
    let horizon = current.map_or(facts.horizon, |ledger| {
        ledger.evidence_not_after_micros.min(facts.horizon)
    });
    let ordinal = current.map_or(0, |ledger| ledger.ordinal) + 1;
    CommunityQuarantineRevisionV1::new(CommunityQuarantineRevisionInputV1 {
        key,
        ledger_ordinal: ordinal,
        predecessor_ledger_digest: expected,
        active_reasons: CommunityQuarantineReasonsV1::from_reasons(&reasons),
        control_request_digest: request_digest,
        evidence_not_after_micros: horizon,
    })
    .and_then(|revision| {
        CommunityQuarantineOutcomeV1::new(CommunityQuarantineOutcomeInputV1 {
            control_operation_id,
            control_request_digest: request_digest,
            prior_ledger_digest: expected,
            selected_ledger_digest: revision.digest(),
            disposition: CommunityQuarantineDispositionV1::Applied,
            evidence_not_after_micros: horizon,
        })
        .map(|outcome| AppendedV1 {
            revision: revision.to_canonical_cbor(),
            head: revision.digest(),
            outcome: outcome.to_canonical_cbor(),
            outcome_digest: outcome.digest(),
            ordinal,
            horizon,
            reasons: reasons.clone(),
        })
    })
}

/// The staged in-Abort `SetReason` of one failure.
fn apply_of(
    (facts, failed): (&QuarantineFactsV1<'_>, &FailedMemberV1<'_>),
    (key, control_operation_id, reason): (Hash, [u8; 16], CommunityQuarantineReasonV1),
    (request, request_digest): (Zeroizing<Vec<u8>>, Hash),
    (appended, expected): (AppendedV1, Option<Hash>),
    current: Option<&QuarantineLedgerV1>,
) -> QuarantineApplyV1 {
    QuarantineApplyV1 {
        key,
        control_operation_id,
        request,
        revision: appended.revision,
        outcome: appended.outcome.clone(),
        delta: CommunityQuarantineDeltaRowV1 {
            quarantine_key_digest: key,
            ledger_digest: appended.head,
            outcome_digest: appended.outcome_digest,
        },
        ledger: QuarantineLedgerV1 {
            head: appended.head,
            ordinal: appended.ordinal,
            reasons: appended.reasons,
            evidence_not_after_micros: appended.horizon,
            states: ledger_states(
                current,
                reason.code(),
                QuarantineReasonStateV1 {
                    evidence_not_after_micros: facts.horizon,
                    share_spent: false,
                },
            ),
        },
        bound: SetReasonBoundV1 {
            key,
            expected_ledger: expected,
            reason: reason.code(),
            host_failure: failed.failure.host_failure,
            trust_policy_snapshot_digest: failed.member.trust_policy_snapshot_digest,
            expected_generation: facts.generation,
            expected_head: facts.head,
        },
        receipt: CommunityQuarantineReceiptV1 {
            timeline: facts.timeline,
            control_operation_id,
            request_digest,
            selected_ledger_digest: appended.head,
            already_quarantined: false,
            outcome: appended.outcome,
        },
    }
}

/// The CQC1 of one in-Abort `SetReason` and its digest (R15.3(4)): the
/// expected ledger, the one mapped reason with the Abort's CFO1, the member's
/// trust snapshot, the predecessor head, no principal and the call's bound.
fn set_reason_request(
    facts: &QuarantineFactsV1<'_>,
    failed: &FailedMemberV1<'_>,
    (key, control_operation_id, reason, expected): (
        CommunityQuarantineKeyV1<'_>,
        [u8; 16],
        CommunityQuarantineReasonV1,
        Option<Hash>,
    ),
) -> Result<(Zeroizing<Vec<u8>>, Hash), Error> {
    let bound = [CommunityQuarantineReasonEvidenceV1 {
        reason,
        failure_evidence_digest: facts.failure_digest,
    }];
    CommunityQuarantineControlV1::new(CommunityQuarantineControlInputV1 {
        control_operation_id,
        key,
        expected_ledger_digest: expected,
        operation: CommunityQuarantineControlKindV1::SetReason,
        bound_reasons: CommunityQuarantineReasonsV1::from_reasons(&bound),
        trust_snapshot_digest: failed.member.trust_policy_snapshot_digest,
        expected_generation: facts.generation,
        expected_state_head_digest: facts.head,
        principal_ref: None,
        authorization_ref: None,
        authorization_not_after_micros: facts.bound_micros,
        host_decision_provenance_digest: failed.provenance,
    })
    .map(|request| (request.to_canonical_cbor(), request.digest()))
}

/// The facts of the CAU1.
pub(super) struct EvidenceFactsV1<'a> {
    pub(super) store_incarnation: [u8; 16],
    pub(super) lifecycle: &'a CommunityLifecycleAuthorityV1,
    pub(super) record: &'a CommunityPassRecordV1,
    pub(super) write: &'a MetadataWriteV1,
    pub(super) clock: ClockV1,
    pub(super) abort_digest: Hash,
    pub(super) view_digest: Hash,
    pub(super) inventory_generation: u64,
}

/// The CAU1 of the failure Abort (R15.1(5)): Pass, H(CAB1), one object row
/// per registered COW1 and exactly the metadata `write` decision.
pub(super) fn failure_evidence(
    facts: &EvidenceFactsV1<'_>,
    records: &[CommunityProtectedRecordV1],
) -> Result<(Zeroizing<Vec<u8>>, Hash), Error> {
    let pass_key = facts.record.reserved.reservation.pass_key;
    let mut object_bindings: Vec<CommunityObjectBindingV1> = records
        .iter()
        .map(|record| CommunityObjectBindingV1 {
            object_address: record.object_address(),
            artifact_digest: record.registration().fields().artifact_digest,
            registration_address: record.registration().address(),
        })
        .collect();
    object_bindings.sort_unstable();
    let write = facts.write;
    CommunityAuthorityEvidenceV1::new(CommunityAuthorityEvidenceInputV1 {
        store_incarnation: facts.store_incarnation,
        timeline: pass_key.timeline(),
        generation: pass_key.generation(),
        operation: CommunityArtifactOperationV1::Pass(pass_key),
        input_identity: facts.abort_digest,
        object_bindings,
        inventory_generation: facts.inventory_generation,
        current_premise_digest: facts.view_digest,
        decision_rows: vec![decision_row(
            &write.request,
            write.decision_digest,
            write.leaf_grant_id,
        )],
        recipient_identity_digest: community_recipient_identity_digest_v1(
            facts.lifecycle.member_recipient(),
        ),
        clock_bound: CommunityClockBoundV1 {
            reservation_id: facts.clock.reservation_id,
            reservation_sample_micros: facts.clock.sample_micros,
            decision_bound_micros: facts.clock.bound_micros,
        },
        evidence_not_after_micros: facts.record.reserved.generation_horizon_micros,
    })
    .map(|evidence| (evidence.to_canonical_cbor(), evidence.digest()))
}

/// One COW1's CMI1 inputs: its record magic, logical digest and length.
pub(super) struct NamedRecordV1 {
    pub(super) magic: [u8; 4],
    pub(super) logical_digest: Hash,
    pub(super) length: usize,
}

/// The CFI1s then the CFO1, named in the order [`protect_failure`] protects
/// them.
pub(super) fn named_records(derived: &DerivedFailureV1) -> Vec<NamedRecordV1> {
    derived
        .invocations
        .iter()
        .map(|invocation| NamedRecordV1 {
            magic: *b"CFI1",
            logical_digest: invocation.digest,
            length: invocation.bytes.len(),
        })
        .chain(std::iter::once(NamedRecordV1 {
            magic: *b"CFO1",
            logical_digest: derived.failure_digest,
            length: derived.failure.len(),
        }))
        .collect()
}

/// The CMI1 of one COW1: producer `[1, H(CAB1)]`, its CSB1 cover and the
/// COA1 address (R15.1(5)).
pub(super) fn materialization(
    store_incarnation: [u8; 16],
    (timeline, generation): (TimelineId, [u8; 16]),
    abort_digest: Hash,
    name: &NamedRecordV1,
    (record, attestation_address): (&CommunityProtectedRecordV1, Hash),
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let registration = record.registration();
    let pass = registration.fields();
    CommunityMaterializationV1::new(CommunityMaterializationInputV1 {
        store_incarnation,
        timeline,
        generation,
        record_magic: name.magic,
        logical_record_digest: name.logical_digest,
        plaintext_length: name.length as u64,
        materialization: CommunityMaterializationReferenceV1 {
            owner_reference: pass.owner_reference,
            artifact_class: pass.artifact_class,
            object_address: record.object_address(),
            artifact_digest: pass.artifact_digest,
            registration_address: registration.address(),
            attestation_address,
        },
        producer: CommunityProducerBindingV1::Control(abort_digest),
        scope_binding_digest: record.scope_cover_digest(),
        evidence_not_after_micros: record.evidence_not_after_micros(),
    })
    .map(|materialization| materialization.to_canonical_cbor())
}
