//! The records one `SetReason` stages (ADR-129 revision 9 R9.9(1)–(5), (8)).
//!
//! An already active reason keeps its evidence and horizon: the operation
//! persists only its CQC1 and its `AlreadyQuarantined` CQO1 under a fresh
//! metadata key. A new reason stages, in the annex digest order:
//!
//! 1. the pre-execution CFO1, then the CQC1 binding it, the CQR1 with the
//!    set union and the `Applied` CQO1;
//! 2. the one-row CBQ1, the empty-scope CSB1 and CPV1;
//! 3. the CFO1 COW1 under a `LifecycleControl` cohort key whose scope cover
//!    is the CSB1, verified by the extractor's control-record form;
//! 4. the metadata CKP1, the CAV1 read now, the CAU1 (Control, H(CQC1),
//!    the metadata `write` row), the COA1 and the CMI1;
//! 5. every metadata record sealed under the metadata key, the CQO1 last.

use pos_core::community_lifecycle::{
    community_recipient_identity_digest_v1, CommunityArtifactAdmissionV1, CommunityArtifactKindV1,
    CommunityArtifactOperationV1, CommunityArtifactPurposeV1, CommunityAuthorityEvidenceInputV1,
    CommunityAuthorityEvidenceV1, CommunityBudgetQuoteInputV1, CommunityBudgetQuoteV1,
    CommunityClockBoundV1, CommunityCopyHolderV1, CommunityCopyInventoryInputV1,
    CommunityCopyInventoryV1, CommunityCopyStateV1, CommunityCurrentViewInputV1,
    CommunityCurrentViewV1, CommunityDecisionRowV1, CommunityDueMemberBudgetV1,
    CommunityKeyIntentInputV1, CommunityKeyIntentV1, CommunityLifecycleErrorV1 as Error,
    CommunityMaterializationInputV1, CommunityMaterializationReferenceV1,
    CommunityMaterializationV1, CommunityMemberSlotsV1, CommunityMetadataSchemaV1,
    CommunityMetadataScopeInputV1, CommunityMetadataScopeV1, CommunityObjectBindingV1,
    CommunityOriginalProvenanceInputV1, CommunityOriginalProvenanceV1, CommunityProducerBindingV1,
    CommunityQuarantineDispositionV1, CommunityQuarantineKeyV1, CommunityQuarantineOutcomeInputV1,
    CommunityQuarantineOutcomeV1, CommunityQuarantineReasonEvidenceV1,
    CommunityQuarantineReasonsV1, CommunityQuarantineRevisionInputV1,
    CommunityQuarantineRevisionV1, CommunityRecordKindsV1, CommunityScopeBindingInputV1,
    CommunityScopeBindingV1, CommunityScopeCoverageRowsV1, CommunityScopeMembersV1,
    CommunitySharedCountsV1, CommunityTrustViewRowV1, CommunityTypedInputRefsV1,
};
use pos_core::{AuthorityTrustRootSealV1, Hash};
use zeroize::Zeroizing;

use super::super::extractor::{
    prepare_community_artifact_batch_v1, CommunityArtifactBatchFormV1, CommunityArtifactBatchV1,
    CommunityArtifactRecordInputV1, CommunityControlBatchInputV1,
};
use super::super::lifecycle_authority::CommunityLifecycleAuthorityV1;
use super::super::memory_domain::MemoryCommunityDomainV1;
use super::super::planner::key_rows;
use super::super::private_hash::scope_set_digest;
use super::super::protection::{
    CommunityArtifactProtectorV1, CommunityProtectedRecordV1, CommunityProtectionCohortV1,
    CommunityRecordEvidenceV1,
};
use super::super::sealer::SealedMetadataV1;
use super::super::store_domain::CommunityStoreDomainV1;
use super::super::vault::{fresh_identity, VaultKeyV1};
use super::{
    control_request, failure_record, ledger_states, CommittedQuarantineControlV1,
    CommunityQuarantineReceiptV1, OperationV1, QuarantineLedgerV1, QuarantineReasonStateV1,
    RetainedControlV1, RetainedSetReasonV1, SealedControlV1, SetReasonBoundV1, StagedSetReasonV1,
};

/// Preferred CBOR encoding of the empty scope-member array.
const EMPTY_SCOPE_ROWS: [u8; 1] = [0x80];

/// The CFO1 encoding bound, the one-row CBQ1 byte maximum (R9.9(3)).
const CFO1_BYTES: u64 = 16_384;

/// The control batch of a new reason, published at the commit.
pub(in super::super) struct StagedEvidenceV1 {
    pub(in super::super) batch: CommunityArtifactBatchV1,
}

/// The CFO1, CQC1 and CQR1 of one new reason, and its ledger.
struct LedgerRecordsV1 {
    failure: Zeroizing<Vec<u8>>,
    failure_digest: Hash,
    request: Zeroizing<Vec<u8>>,
    request_digest: Hash,
    revision: Zeroizing<Vec<u8>>,
    ledger: QuarantineLedgerV1,
}

/// The CBQ1, CSB1 and CPV1 of the CFO1 (R9.9(3)).
struct ScopeRecordsV1 {
    quote: Zeroizing<Vec<u8>>,
    scope: Zeroizing<Vec<u8>>,
    scope_digest: Hash,
    provenance: Zeroizing<Vec<u8>>,
    provenance_digest: Hash,
}

/// The records of one new reason before its CFO1 is protected.
struct AppliedV1 {
    ledger: LedgerRecordsV1,
    scope: ScopeRecordsV1,
    outcome: Zeroizing<Vec<u8>>,
    receipt: CommunityQuarantineReceiptV1,
}

/// The CFO1 COW1 with its batch, cohort key and key-vault copy.
struct ProtectedV1 {
    record: CommunityProtectedRecordV1,
    batch: CommunityArtifactBatchV1,
    cohort_key: VaultKeyV1,
    cohort_copy: CommunityCopyInventoryV1,
}

/// The CAU1, COA1 and CMI1 of the CFO1.
struct AdmittedV1 {
    evidence: Zeroizing<Vec<u8>>,
    admission: CommunityArtifactAdmissionV1,
    materialization: Zeroizing<Vec<u8>>,
}

impl MemoryCommunityDomainV1 {
    /// Stage the records of `operation`: an `AlreadyQuarantined` outcome
    /// when its reason is active, otherwise a new revision.
    pub(super) fn stage_set_reason(
        &self,
        seal: &'static AuthorityTrustRootSealV1,
        lifecycle: &CommunityLifecycleAuthorityV1,
        operation: &OperationV1<'_>,
    ) -> Result<StagedSetReasonV1, Error> {
        let reason = operation.call.reason;
        self.quarantine_index
            .get(&operation.key)
            .filter(|ledger| ledger.reasons.iter().any(|row| row.reason == reason))
            .map_or_else(
                || {
                    if operation.authority.bound.as_micros() > operation.failure_horizon {
                        Err(Error::EvidenceExpired)
                    } else {
                        self.stage_applied(seal, lifecycle, operation)
                    }
                },
                |ledger| self.stage_already(operation, ledger),
            )
    }

    /// An active reason keeps its evidence and horizon (annex): only the
    /// CQC1 and the `AlreadyQuarantined` CQO1 naming the existing CQR1 are
    /// persisted, with the CCI1 key copy, under a fresh metadata key, as one
    /// inventory step (owner 2026-11-21, #560). No CFO1 is written, so the
    /// CFO1 and quarantine horizons bind nothing here and are not checked:
    /// the CQC1's CFO1 digest commits to the request content and is not a
    /// pointer to a stored CFO1 (owner 2026-11-21, #560).
    fn stage_already(
        &self,
        operation: &OperationV1<'_>,
        ledger: &QuarantineLedgerV1,
    ) -> Result<StagedSetReasonV1, Error> {
        failure_record(
            operation.member.member_binding_digest,
            operation.call.failure.0.host_failure,
            operation.authority.trust_snapshot_digest,
            operation.failure_horizon,
        )
        .and_then(|(_, failure_digest, provenance)| {
            control_request(operation, failure_digest, provenance)
        })
        .and_then(|(request, request_digest)| {
            outcome(
                operation,
                request_digest,
                Some(ledger.head),
                ledger.head,
                CommunityQuarantineDispositionV1::AlreadyQuarantined,
                ledger.evidence_not_after_micros,
            )
            .and_then(|(outcome, receipt)| {
                let plaintexts = [
                    (CommunityMetadataSchemaV1::Cqc1, request.as_slice()),
                    (CommunityMetadataSchemaV1::Cqo1, outcome.as_slice()),
                ];
                self.seal_all(operation, None, &plaintexts)
                    .map(|(key, records)| {
                        self.staged(operation, (key, None), records, None, None, receipt)
                    })
            })
        })
    }

    /// A new reason: one revision with the set union (annex), its CFO1 COW1
    /// and every evidence record.
    fn stage_applied(
        &self,
        seal: &'static AuthorityTrustRootSealV1,
        lifecycle: &CommunityLifecycleAuthorityV1,
        operation: &OperationV1<'_>,
    ) -> Result<StagedSetReasonV1, Error> {
        self.ledger_records(operation)
            .and_then(|ledger| {
                outcome(
                    operation,
                    ledger.request_digest,
                    operation.call.expected_ledger_digest,
                    ledger.ledger.head,
                    CommunityQuarantineDispositionV1::Applied,
                    ledger.ledger.evidence_not_after_micros,
                )
                .and_then(|(outcome, receipt)| {
                    scope_records(self.store_incarnation, operation, ledger.request_digest).map(
                        |scope| AppliedV1 {
                            ledger,
                            scope,
                            outcome,
                            receipt,
                        },
                    )
                })
            })
            .and_then(|applied| {
                protect(seal, operation, &applied).and_then(|protected| {
                    self.finish_quarantine(seal, lifecycle, operation, applied, protected)
                })
            })
    }

    /// The CFO1, the CQC1 binding it and the CQR1 that appends the reason
    /// to the current set (or starts it, with the first-use proof), with a
    /// positive ordinal one past its predecessor's and a horizon no later
    /// than any active reason's.
    fn ledger_records(&self, operation: &OperationV1<'_>) -> Result<LedgerRecordsV1, Error> {
        let current = self.quarantine_index.get(&operation.key);
        failure_record(
            operation.member.member_binding_digest,
            operation.call.failure.0.host_failure,
            operation.authority.trust_snapshot_digest,
            operation.failure_horizon,
        )
        .and_then(|(failure, failure_digest, provenance)| {
            control_request(operation, failure_digest, provenance).and_then(
                |(request, request_digest)| {
                    let mut reasons =
                        current.map_or_else(Vec::new, |ledger| ledger.reasons.clone());
                    reasons.push(CommunityQuarantineReasonEvidenceV1 {
                        reason: operation.call.reason,
                        failure_evidence_digest: failure_digest,
                    });
                    reasons.sort_by_key(|row| row.reason.code());
                    let ordinal = current.map_or(0, |ledger| ledger.ordinal) + 1;
                    let horizon = current.map_or(operation.failure_horizon, |ledger| {
                        ledger
                            .evidence_not_after_micros
                            .min(operation.failure_horizon)
                    });
                    revision(operation, ordinal, &reasons, request_digest, horizon).map(
                        |(revision, head)| LedgerRecordsV1 {
                            failure,
                            failure_digest,
                            request,
                            request_digest,
                            revision,
                            ledger: QuarantineLedgerV1 {
                                head,
                                ordinal,
                                reasons,
                                evidence_not_after_micros: horizon,
                                states: ledger_states(
                                    current,
                                    operation.call.reason.code(),
                                    QuarantineReasonStateV1 {
                                        evidence_not_after_micros: operation.failure_horizon,
                                        share_spent: true,
                                    },
                                ),
                            },
                        },
                    )
                },
            )
        })
    }

    /// The metadata key, the CAV1, CAU1, COA1 and CMI1, every metadata
    /// record sealed and the staged commit.
    fn finish_quarantine(
        &self,
        seal: &'static AuthorityTrustRootSealV1,
        lifecycle: &CommunityLifecycleAuthorityV1,
        operation: &OperationV1<'_>,
        applied: AppliedV1,
        protected: ProtectedV1,
    ) -> Result<StagedSetReasonV1, Error> {
        let AppliedV1 {
            ledger,
            scope,
            outcome,
            receipt,
        } = applied;
        metadata_key(operation).and_then(|key| {
            self.admit_failure(seal, lifecycle, operation, &ledger, &key, &protected)
                .and_then(|admitted| {
                    let cohort_copy = protected.cohort_copy.to_canonical_cbor();
                    let plaintexts = [
                        (CommunityMetadataSchemaV1::Cbq1, scope.quote.as_slice()),
                        (CommunityMetadataSchemaV1::Csb1, scope.scope.as_slice()),
                        (CommunityMetadataSchemaV1::Cpv1, scope.provenance.as_slice()),
                        (
                            CommunityMetadataSchemaV1::Cau1,
                            admitted.evidence.as_slice(),
                        ),
                        (
                            CommunityMetadataSchemaV1::Cmi1,
                            admitted.materialization.as_slice(),
                        ),
                        (CommunityMetadataSchemaV1::Cci1, cohort_copy.as_slice()),
                        (CommunityMetadataSchemaV1::Cqc1, ledger.request.as_slice()),
                        (CommunityMetadataSchemaV1::Cqr1, ledger.revision.as_slice()),
                        (CommunityMetadataSchemaV1::Cqo1, outcome.as_slice()),
                    ];
                    self.seal_all(operation, Some(key), &plaintexts)
                        .map(|(key, records)| {
                            let mut staged = self.staged(
                                operation,
                                (key, Some(protected.cohort_key)),
                                records,
                                Some(StagedEvidenceV1 {
                                    batch: protected.batch,
                                }),
                                Some(admitted.admission),
                                receipt,
                            );
                            staged.ledger = Some((operation.key, ledger.ledger));
                            staged
                        })
                })
        })
    }

    /// The CAV1 read now, the CAU1 (Control, H(CQC1), the CFO1 object row,
    /// the metadata `write` row), the COA1 binding it and the CMI1 with
    /// producer `[1, H(CQC1)]` (R9.9(4), (8)).
    fn admit_failure(
        &self,
        seal: &'static AuthorityTrustRootSealV1,
        lifecycle: &CommunityLifecycleAuthorityV1,
        operation: &OperationV1<'_>,
        ledger: &LedgerRecordsV1,
        key: &VaultKeyV1,
        protected: &ProtectedV1,
    ) -> Result<AdmittedV1, Error> {
        let inventory_generation = CommunityStoreDomainV1::inventory_generation(self);
        let keys: [&CommunityKeyIntentV1; 2] = [key.intent(), protected.cohort_key.intent()];
        self.view(lifecycle, operation, &keys, inventory_generation)
            .and_then(|view| {
                authority_evidence(
                    self.store_incarnation,
                    lifecycle,
                    operation,
                    ledger.request_digest,
                    &protected.record,
                    view.digest(),
                    inventory_generation,
                )
            })
            .and_then(|(evidence, evidence_digest)| {
                protected
                    .record
                    .admission(seal, inventory_generation, evidence_digest)
                    .and_then(|admission| {
                        materialization(
                            self.store_incarnation,
                            operation,
                            ledger,
                            &protected.record,
                            admission.digest(),
                        )
                        .map(|materialization| AdmittedV1 {
                            evidence,
                            admission,
                            materialization,
                        })
                    })
            })
    }

    /// The CAV1 of the `SetReason`, read inside its guard (R9.9(4)): T's
    /// current selection (its frontier and the head ref of the first roster
    /// member's CSR1, R16.5(4)), no scope rows, the metadata chain's
    /// authority row, the member's trust row, both key rows and the clock
    /// latch.
    fn view(
        &self,
        lifecycle: &CommunityLifecycleAuthorityV1,
        operation: &OperationV1<'_>,
        keys: &[&CommunityKeyIntentV1],
        inventory_generation: u64,
    ) -> Result<CommunityCurrentViewV1, Error> {
        let authority = &operation.authority;
        CommunityStoreDomainV1::clock_latch(self)
            .and_then(|clock_latch| {
                self.head_view(
                    operation.timeline(),
                    vec![],
                    (authority.leaf_grant_id, &authority.request),
                )
                .map(|head| (clock_latch, head))
            })
            .and_then(|(clock_latch, head)| {
                self.trust_row(lifecycle.trust_scope(), operation)
                    .and_then(|trust_row| {
                        CommunityCurrentViewV1::new(CommunityCurrentViewInputV1 {
                            store_incarnation: self.store_incarnation,
                            timeline: operation.timeline(),
                            generation: operation.member.generation,
                            inventory_generation,
                            frontier: head.frontier,
                            selected_head: head.selected_head,
                            scope_rows: vec![],
                            authority_rows: head.authority_rows,
                            trust_rows: vec![trust_row],
                            key_rows: key_rows(keys),
                            clock_latch,
                        })
                    })
            })
    }

    /// The member's CAV1 trust row (R6.5), read now from this domain's own
    /// registry. Its active release must be the member's.
    fn trust_row(
        &self,
        scope: &str,
        operation: &OperationV1<'_>,
    ) -> Result<CommunityTrustViewRowV1, Error> {
        let implementation = operation.call.failure.0.implementation;
        let plugin_id = implementation.plugin_id();
        CommunityStoreDomainV1::plugin_trust_policy(self, scope).and_then(|policy| {
            CommunityStoreDomainV1::active_release(self, scope, plugin_id).and_then(|active| {
                u64::try_from(policy.highest_trusted_utc_second().unwrap_or(0))
                    .ok()
                    .zip(active)
                    // Only the PMF1 is compared. The active release digest is
                    // field 27 of that PMF1, and initialize admitted this
                    // member's IMK1 release digest against the same active
                    // PMF1, so a matching PMF1 already fixes the release; a
                    // re-signed PMF1 with the same release digest differs.
                    .filter(|(_, active)| {
                        active.pmf1_digest() == *operation.member.pmf1_digest.as_bytes()
                    })
                    .map(|(utc, active)| CommunityTrustViewRowV1 {
                        scope: scope.to_owned(),
                        plugin_id: plugin_id.to_owned(),
                        policy_digest: Hash::from_bytes(policy.tps1_digest()),
                        policy_floor: policy.ptr1_floor().map_or(0, |(floor, _)| floor),
                        release_floor: policy.prv1_floor().map_or(0, |(floor, _)| floor),
                        highest_trusted_utc_second: utc,
                        active_manifest_digest: Hash::from_bytes(active.pmf1_digest()),
                        active_release_digest: Hash::from_bytes(active.release_digest()),
                    })
                    .ok_or(Error::EvidenceUnavailable)
            })
        })
    }

    /// Provision the metadata key when `key` is `None`, seal `plaintexts`
    /// and each key's CCI1 under it, and close it.
    fn seal_all(
        &self,
        operation: &OperationV1<'_>,
        key: Option<VaultKeyV1>,
        plaintexts: &[(CommunityMetadataSchemaV1, &[u8])],
    ) -> Result<(VaultKeyV1, Vec<SealedMetadataV1>), Error> {
        key.map_or_else(|| metadata_key(operation), Ok)
            .and_then(|mut key| {
                metadata_scope(self.store_incarnation, operation, &key).and_then(|scope| {
                    key_copy(operation, &key).and_then(|copy| {
                        let copy = copy.to_canonical_cbor();
                        std::iter::once((CommunityMetadataSchemaV1::Cci1, copy.as_slice()))
                            .chain(plaintexts.iter().copied())
                            .map(|(schema, plaintext)| key.seal(&scope, schema, plaintext))
                            .collect::<Result<Vec<_>, Error>>()
                            .map(|records| {
                                key.close();
                                (key, records)
                            })
                    })
                })
            })
    }

    /// The staged commit around `records` and `receipt`, retaining the
    /// metadata key that sealed them and the CFO1 cohort key, if any.
    fn staged(
        &self,
        operation: &OperationV1<'_>,
        (metadata, cohort): (VaultKeyV1, Option<VaultKeyV1>),
        records: Vec<SealedMetadataV1>,
        evidence: Option<StagedEvidenceV1>,
        admission: Option<CommunityArtifactAdmissionV1>,
        receipt: CommunityQuarantineReceiptV1,
    ) -> StagedSetReasonV1 {
        let call = operation.call;
        let failure = &call.failure.0;
        let metadata_key = metadata.intent().as_input().protection_operation_id;
        let keys: Vec<VaultKeyV1> = std::iter::once(metadata).chain(cohort).collect();
        StagedSetReasonV1 {
            key: (failure.timeline, call.control_operation_id),
            committed: CommittedQuarantineControlV1 {
                kind: RetainedControlV1::SetReason(RetainedSetReasonV1 {
                    bound: SetReasonBoundV1 {
                        key: operation.key,
                        expected_ledger: call.expected_ledger_digest,
                        reason: call.reason.code(),
                        host_failure: failure.host_failure,
                        trust_policy_snapshot_digest: failure.trust_policy_snapshot_digest,
                        expected_generation: call.expected_generation,
                        expected_head: call.expected_state_head_digest,
                    },
                    generation: operation.member.generation,
                    sealed: SealedControlV1 {
                        metadata_key,
                        records,
                    },
                    admission,
                }),
                receipt,
            },
            keys,
            evidence,
            ledger: None,
            read_selection: operation.member.selection_address,
            inventory_generation: CommunityStoreDomainV1::inventory_generation(self),
        }
    }
}

/// Protect the CFO1 under its `LifecycleControl` cohort key and verify
/// it through the extractor's control-record form (R9.9(2), (5)).
fn protect(
    seal: &'static AuthorityTrustRootSealV1,
    operation: &OperationV1<'_>,
    applied: &AppliedV1,
) -> Result<ProtectedV1, Error> {
    let scope = &applied.scope;
    CommunityArtifactProtectorV1::provision(seal, cohort(operation, scope.scope_digest)).and_then(
        |mut protector| {
            protector
                .protect(
                    CommunityArtifactKindV1::LifecycleControl,
                    &applied.ledger.failure,
                    CommunityRecordEvidenceV1 {
                        owner_binding_digest: operation.member.owner_binding_digest,
                        host_provenance_digest: scope.provenance_digest,
                        children: &[],
                    },
                )
                .and_then(|record| {
                    let inputs = [CommunityArtifactRecordInputV1 {
                        object: record.object(),
                        registration: record.registration(),
                    }];
                    prepare_community_artifact_batch_v1(
                        seal,
                        CommunityArtifactBatchFormV1::Control(CommunityControlBatchInputV1 {
                            timeline: operation.timeline(),
                            generation: operation.member.generation,
                            owner_binding_digest: operation.member.owner_binding_digest,
                            records: &inputs,
                            graph_root: None,
                            current_head: Some(operation.member.head),
                            expected_head: Some(operation.call.expected_state_head_digest),
                        }),
                        &[&protector],
                    )
                    .map(|batch| (record, batch))
                })
                .map(|(record, batch)| {
                    let (mut cohort_key, cohort_copy) = protector.into_parts();
                    cohort_key.close();
                    ProtectedV1 {
                        record,
                        batch,
                        cohort_key,
                        cohort_copy,
                    }
                })
        },
    )
}

/// The CQR1 with `reasons`, and its digest.
fn revision(
    operation: &OperationV1<'_>,
    ordinal: u64,
    reasons: &[CommunityQuarantineReasonEvidenceV1],
    request_digest: Hash,
    horizon: u64,
) -> Result<(Zeroizing<Vec<u8>>, Hash), Error> {
    let failure = &operation.call.failure.0;
    CommunityQuarantineKeyV1::new(
        failure.timeline,
        failure.stable_entry,
        failure.implementation,
    )
    .and_then(|key| {
        CommunityQuarantineRevisionV1::new(CommunityQuarantineRevisionInputV1 {
            key,
            ledger_ordinal: ordinal,
            predecessor_ledger_digest: operation.call.expected_ledger_digest,
            active_reasons: CommunityQuarantineReasonsV1::from_reasons(reasons),
            control_request_digest: request_digest,
            evidence_not_after_micros: horizon,
        })
        .map(|revision| (revision.to_canonical_cbor(), revision.digest()))
    })
}

/// The CQO1 and the receipt that carries it.
fn outcome(
    operation: &OperationV1<'_>,
    request_digest: Hash,
    prior: Option<Hash>,
    selected: Hash,
    disposition: CommunityQuarantineDispositionV1,
    horizon: u64,
) -> Result<(Zeroizing<Vec<u8>>, CommunityQuarantineReceiptV1), Error> {
    CommunityQuarantineOutcomeV1::new(CommunityQuarantineOutcomeInputV1 {
        control_operation_id: operation.call.control_operation_id,
        control_request_digest: request_digest,
        prior_ledger_digest: prior,
        selected_ledger_digest: selected,
        disposition,
        evidence_not_after_micros: horizon,
    })
    .map(|outcome| {
        let bytes = outcome.to_canonical_cbor();
        (
            bytes.clone(),
            CommunityQuarantineReceiptV1 {
                timeline: operation.timeline(),
                control_operation_id: operation.call.control_operation_id,
                request_digest,
                selected_ledger_digest: selected,
                already_quarantined: disposition
                    == CommunityQuarantineDispositionV1::AlreadyQuarantined,
                outcome: bytes,
            },
        )
    })
}

/// The one-row CBQ1 (the member's `[CMB1, CNT1]`, zero prior counts, no
/// node or edge and the CFO1 bound), the empty-scope CSB1 and the CPV1
/// with no source root (R9.9(3)).
fn scope_records(
    store_incarnation: [u8; 16],
    operation: &OperationV1<'_>,
    request_digest: Hash,
) -> Result<ScopeRecordsV1, Error> {
    let profile = operation.context.profile;
    let fields = profile.as_input();
    let generation = operation.member.generation;
    let control = CommunityArtifactOperationV1::Control(operation.call.control_operation_id);
    CommunityBudgetQuoteV1::new(CommunityBudgetQuoteInputV1 {
        timeline: operation.timeline(),
        generation,
        profile_digest: profile.digest(),
        prior_shared_counts: CommunitySharedCountsV1 {
            nodes: 0,
            edges: 0,
            declared_inputs: 0,
            encoded_record_bytes: 0,
        },
        due_members: vec![CommunityDueMemberBudgetV1 {
            member_binding_digest: operation.member.member_binding_digest,
            negotiated_tuple_digest: operation.member.negotiated_tuple_digest,
        }],
        maximum_required_nodes: 0,
        maximum_required_edges: 0,
        maximum_required_bytes: CFO1_BYTES,
    })
    .and_then(|quote| {
        CommunityScopeBindingV1::new(CommunityScopeBindingInputV1 {
            store_incarnation,
            timeline: operation.timeline(),
            generation,
            operation: control,
            input_identity: request_digest,
            coverage_rows: CommunityScopeCoverageRowsV1::from_rows(&[]),
            scope_members: CommunityScopeMembersV1::from_members(&[]),
            policy_revision: fields.source_catalogue_digest,
            evidence_not_after_micros: operation.failure_horizon,
        })
        .and_then(|scope| {
            let scope_digest = scope.digest();
            CommunityOriginalProvenanceV1::new(CommunityOriginalProvenanceInputV1 {
                store_incarnation,
                timeline: operation.timeline(),
                generation,
                operation: control,
                input_identity: request_digest,
                scope_binding_digest: scope_digest,
                source_root_refs: CommunityTypedInputRefsV1::from_references(&[]),
                rule_bundle_digest: fields.execution_profile_digest,
                budget_identity: quote.digest(),
                evidence_not_after_micros: operation.failure_horizon,
            })
            .map(|provenance| ScopeRecordsV1 {
                quote: quote.to_canonical_cbor(),
                scope: scope.to_canonical_cbor(),
                scope_digest,
                provenance_digest: provenance.digest(),
                provenance: provenance.to_canonical_cbor(),
            })
        })
    })
}

/// The CFO1 cohort (R9.9(2)): parent Control, `LifecycleControl` with kind
/// 6 and its kind-8 proofs, empty scope, the CFO1 horizon and the metadata
/// `write` decision's request digest.
fn cohort(operation: &OperationV1<'_>, scope_cover_digest: Hash) -> CommunityProtectionCohortV1 {
    CommunityProtectionCohortV1 {
        parent_operation: CommunityArtifactOperationV1::Control(
            operation.call.control_operation_id,
        ),
        timeline: operation.timeline(),
        generation: operation.member.generation,
        purpose: CommunityArtifactPurposeV1::LifecycleControl,
        scope_set_digest: scope_set_digest(&EMPTY_SCOPE_ROWS),
        scope_cover_digest,
        evidence_not_after_micros: operation.failure_horizon,
        allowed_record_kinds: CommunityRecordKindsV1::empty()
            .with(CommunityArtifactKindV1::LifecycleControl)
            .with(CommunityArtifactKindV1::ClassificationProof),
        member_slots: CommunityMemberSlotsV1::empty(),
        authority_request_digest: operation.authority.decision.request_digest(),
    }
}

/// The metadata CKP1 (R9.9(2)): parent Control, `LifecycleControl`, the
/// CQK1 T and the expected generation, empty scope, the metadata horizon
/// and the metadata `write` decision's request digest.
fn metadata_key(operation: &OperationV1<'_>) -> Result<VaultKeyV1, Error> {
    fresh_identity().and_then(|protection_operation_id| {
        VaultKeyV1::provision(CommunityKeyIntentInputV1 {
            protection_operation_id,
            parent_operation: CommunityArtifactOperationV1::Control(
                operation.call.control_operation_id,
            ),
            timeline: operation.timeline(),
            generation: operation.member.generation,
            purpose: CommunityArtifactPurposeV1::LifecycleControl,
            scope_set_digest: scope_set_digest(&EMPTY_SCOPE_ROWS),
            evidence_not_after_micros: operation.metadata_horizon(),
            allowed_record_kinds: CommunityRecordKindsV1::empty()
                .with(CommunityArtifactKindV1::LifecycleControl),
            member_slots: CommunityMemberSlotsV1::empty(),
            material_fingerprint: Hash::zero(),
            authority_request_digest: operation.authority.decision.request_digest(),
        })
    })
}

/// The CSM1 cover of every metadata record: the domain's metadata anchor,
/// the metadata key's protection ID and the empty scope.
fn metadata_scope(
    store_incarnation: [u8; 16],
    operation: &OperationV1<'_>,
    key: &VaultKeyV1,
) -> Result<CommunityMetadataScopeV1<'static>, Error> {
    CommunityMetadataScopeV1::new(CommunityMetadataScopeInputV1 {
        store_incarnation,
        metadata_anchor_timeline: operation.member.anchor.0,
        metadata_anchor_generation: operation.member.anchor.1,
        protection_operation_id: key.intent().as_input().protection_operation_id,
        scope_members: CommunityScopeMembersV1::from_members(&[]),
        metadata_not_after_micros: operation.metadata_horizon(),
    })
}

/// The CCI1 key-vault copy of the metadata key's material.
fn key_copy(
    operation: &OperationV1<'_>,
    key: &VaultKeyV1,
) -> Result<CommunityCopyInventoryV1, Error> {
    fresh_identity().and_then(|copy_id| {
        CommunityCopyInventoryV1::new(CommunityCopyInventoryInputV1 {
            copy_id,
            revision: 1,
            predecessor: None,
            parent_operation: CommunityArtifactOperationV1::Control(
                operation.call.control_operation_id,
            ),
            timeline: operation.timeline(),
            generation: operation.member.generation,
            holder: CommunityCopyHolderV1::KeyVault,
            holder_digest: key.intent().digest(),
            purpose: CommunityArtifactPurposeV1::LifecycleControl,
            scope_set_digest: scope_set_digest(&EMPTY_SCOPE_ROWS),
            object_commitment: None,
            state: CommunityCopyStateV1::Owned,
            deadline_micros: operation.metadata_horizon(),
        })
    })
}

/// The CAU1 of the `SetReason` and its digest (R9.9(4)).
fn authority_evidence(
    store_incarnation: [u8; 16],
    lifecycle: &CommunityLifecycleAuthorityV1,
    operation: &OperationV1<'_>,
    request_digest: Hash,
    record: &CommunityProtectedRecordV1,
    view: Hash,
    inventory_generation: u64,
) -> Result<(Zeroizing<Vec<u8>>, Hash), Error> {
    let authority = &operation.authority;
    CommunityAuthorityEvidenceV1::new(CommunityAuthorityEvidenceInputV1 {
        store_incarnation,
        timeline: operation.timeline(),
        generation: operation.member.generation,
        operation: CommunityArtifactOperationV1::Control(operation.call.control_operation_id),
        input_identity: request_digest,
        object_bindings: vec![CommunityObjectBindingV1 {
            object_address: record.object_address(),
            artifact_digest: record.registration().fields().artifact_digest,
            registration_address: record.registration().address(),
        }],
        inventory_generation,
        current_premise_digest: view,
        decision_rows: vec![metadata_decision_row(operation)],
        recipient_identity_digest: community_recipient_identity_digest_v1(
            lifecycle.member_recipient(),
        ),
        clock_bound: CommunityClockBoundV1 {
            reservation_id: authority.reservation_id,
            reservation_sample_micros: authority.sampled_at.as_micros(),
            decision_bound_micros: authority.bound.as_micros(),
        },
        evidence_not_after_micros: operation.failure_horizon,
    })
    .map(|evidence| (evidence.to_canonical_cbor(), evidence.digest()))
}

/// The CAU1 decision row of the metadata `write` decision (N14(a)).
pub(super) fn metadata_decision_row(operation: &OperationV1<'_>) -> CommunityDecisionRowV1 {
    let authority = &operation.authority;
    let request = &authority.request;
    CommunityDecisionRowV1 {
        decision_digest: authority.decision_digest,
        request_digest: request.binding_digest(),
        leaf_grant_id: authority.leaf_grant_id,
        authority_timeline: request.authority_timeline(),
        head_seq: request.at_position().as_u64(),
        revocation_epoch: request.revocation_epoch(),
        policy_revision: request.capability_policy_revision(),
    }
}

/// The CMI1 of the CFO1 COW1: producer `[1, H(CQC1)]`, its CSB1 cover and
/// the COA1 address.
fn materialization(
    store_incarnation: [u8; 16],
    operation: &OperationV1<'_>,
    ledger: &LedgerRecordsV1,
    record: &CommunityProtectedRecordV1,
    attestation_address: Hash,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let registration = record.registration();
    CommunityMaterializationV1::new(CommunityMaterializationInputV1 {
        store_incarnation,
        timeline: operation.timeline(),
        generation: operation.member.generation,
        record_magic: *b"CFO1",
        logical_record_digest: ledger.failure_digest,
        plaintext_length: ledger.failure.len() as u64,
        materialization: CommunityMaterializationReferenceV1 {
            owner_reference: registration.fields().owner_reference,
            artifact_class: registration.fields().artifact_class,
            object_address: record.object_address(),
            artifact_digest: registration.fields().artifact_digest,
            registration_address: registration.address(),
            attestation_address,
        },
        producer: CommunityProducerBindingV1::Control(ledger.request_digest),
        scope_binding_digest: record.scope_cover_digest(),
        evidence_not_after_micros: record.evidence_not_after_micros(),
    })
    .map(|materialization| materialization.to_canonical_cbor())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
