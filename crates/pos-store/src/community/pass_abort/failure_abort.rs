//! The failure Abort of an unresolved pass, reasons 1 to 3 (#560 A4e-2b;
//! ADR-129 R15.1 and R15.3).
//!
//! [`MemoryCommunityDomainV1::abort_pass_failure`] runs, in the A5.5 order:
//!
//! 1. the shape (3): reason 1, 2 or 3, the failures, host codes, guest
//!    errors and control identities of R15.3(2) step 1;
//! 2. one trusted-clock reservation, `D = t_a + 32 s`, with no principal;
//! 3. the metadata `write` decision and the authority refusals (12): reason
//!    3 and reason 2 code 1 give 12 in V1;
//! 4. the retry lookup by `(T, reservation_operation_id)`: 12 for a pass
//!    nobody reserved, 4 for a Committed pass or other bound content, the
//!    original CAB1 for an equal retry (13 at or after `H_r`);
//! 5. the first-Abort preconditions: the pass is Reserved with its call live
//!    (3 otherwise), no control identity is already in the retry index (4),
//!    then the CDP1, generation, head and metadata-horizon fences;
//! 6. the records: the pass CSB1, CPV1 and CBQ1 the call carries, the CFI1s
//!    and CFO1 under the failure cohort key, one `SetReason` per failure that
//!    maps to a quarantine reason, the CAB1, CAV1 and CAU1, and one COA1
//!    and CMI1 per COW1, all sealed under the pass metadata key, which the
//!    Abort then closes with the cohort key;
//! 7. the writer's bound check, then one commit.

mod records;

use pos_core::community_lifecycle::{
    community_catalogue_owner_v1, community_quarantine_delta_digest_v1,
    community_quarantine_reason_v1, CommunityAbortReasonV1, CommunityArtifactAdmissionV1,
    CommunityArtifactOperationV1, CommunityBudgetQuoteV1, CommunityGenerationAdmissionV1,
    CommunityLifecycleErrorV1 as Error, CommunityMetadataSchemaV1, CommunityMetadataScopeInputV1,
    CommunityMetadataScopeV1, CommunityOriginalProvenanceV1, CommunityOwnerBindingV1,
    CommunityQuarantineDeltaRowV1, CommunityScopeBindingV1, CommunityScopeMembersV1,
};
use pos_core::trusted_clock::TrustedClockReservationV1;
use pos_core::{
    ArtifactRegistrationPersistencePortV1, AuthorityTrustRootSealV1, Hash, TimelineId, WallTime,
};
use zeroize::Zeroizing;

use self::records::{
    control_batch, failure_evidence, materialization, named_records, protect_failure, BatchFactsV1,
    ClockV1, EvidenceFactsV1, FailedMemberV1, QuarantineApplyV1, QuarantineFactsV1,
};
use super::super::extractor::CommunityArtifactBatchV1;
use super::super::lifecycle_authority::CommunityLifecycleAuthorityV1;
use super::super::memory_domain::MemoryCommunityDomainV1;
use super::super::metadata_authority::CommunityMetadataAuthorityV1;
use super::super::pass_record::CommunityPassRecordV1;
use super::super::protection::{CommunityArtifactProtectorV1, CommunityProtectedRecordV1};
use super::super::quarantine::{CommittedQuarantineControlV1, CommunityQuarantineContextV1};
use super::super::sealer::SealedMetadataV1;
use super::super::store_domain::CommunityStoreDomainV1;
use super::super::vault::VaultKeyV1;
use super::failure::{
    check_roster_order, check_shape, derive_failure, CommunityPassAbortFailureInputV1,
    CommunityPassAbortFailureV1, DerivedFailureV1,
};
use super::operator::{CommunityPassAbortReceiptV1, MetadataWriteV1};
use super::{
    abort_record, first_failure_abort, AbortFieldsV1, CommittedPassAbortV1, FencedV1,
    PassAbortBoundV1, PassAbortLookupV1,
};

/// The pass CSB1, CPV1 and CBQ1 the live `run_pass` call holds.
///
/// The Reserve commits none of them (R15.1(4)): the first outcome that
/// needs them, a failure Abort or the Commit, does. The store checks them
/// against the pass record and uses `H(CSB1)` as the COH1 cover.
#[derive(Clone, Copy)]
pub struct CommunityPassAbortScopeV1<'a> {
    /// The canonical CSB1.
    pub csb1: &'a [u8],
    /// The canonical CPV1.
    pub cpv1: &'a [u8],
    /// The canonical CBQ1.
    pub cbq1: &'a [u8],
}

/// One failure Abort call: the sealed failure and the pass scope bytes.
#[derive(Clone, Copy)]
pub struct CommunityPassAbortFailureCallV1<'a> {
    /// The installed failure producer's sealed failure.
    pub failure: &'a CommunityPassAbortFailureV1<'a>,
    /// The pass scope bytes of the live call.
    pub scope: CommunityPassAbortScopeV1<'a>,
}

/// The schema and canonical bytes of each record an Abort seals, in order.
type PlaintextsV1 = Vec<(CommunityMetadataSchemaV1, Zeroizing<Vec<u8>>)>;

/// The COA1s of an Abort's COW1s and the plaintexts that precede its
/// quarantine records.
type AdmittedRecordsV1 = (Vec<CommunityArtifactAdmissionV1>, PlaintextsV1);

/// Everything one failure Abort commits, staged before the writer.
struct StagedFailureAbortV1 {
    key: (TimelineId, [u8; 16]),
    committed: CommittedPassAbortV1,
    scope: CommunityMetadataScopeV1<'static>,
    plaintexts: PlaintextsV1,
    batch: CommunityArtifactBatchV1,
    quarantine: Vec<QuarantineApplyV1>,
    /// The index of the first quarantine record among `plaintexts`.
    quarantine_base: usize,
    cohort_key: [u8; 16],
    /// The pending entry's rows the Abort registers: the CFO1 and its CFI1s.
    rows: u64,
    read_selection: Hash,
    inventory_generation: u64,
}

/// The outcome of every step before the writer.
enum PreparedFailureV1 {
    /// A retry's original receipt.
    Original(CommunityPassAbortReceiptV1),
    /// A new Abort, the clock reservation and its bound.
    Staged(
        Box<StagedFailureAbortV1>,
        TrustedClockReservationV1,
        WallTime,
    ),
}

/// The facts every staging step reads.
struct FailureFactsV1<'a> {
    context: CommunityQuarantineContextV1<'a>,
    input: CommunityPassAbortFailureInputV1<'a>,
    record: CommunityPassRecordV1,
    derived: DerivedFailureV1,
    write: MetadataWriteV1,
    clock: ClockV1,
    horizon: u64,
    fenced: FencedV1,
    bound: PassAbortBoundV1,
    /// `H(CSB1)`, `H(CPV1)` and the COB1 digest.
    commitments: (Hash, Hash, Hash),
    scope: CommunityPassAbortScopeV1<'a>,
}

impl MemoryCommunityDomainV1 {
    /// Abort an unresolved pass for a validated invocation failure (reason
    /// 1), an admission refusal (reason 2) or a protected-use refusal
    /// (reason 3), or return the original outcome of a retry.
    ///
    /// Reason 3 and reason 2 code 1 give 12 until key destruction and the
    /// `Expired` registry confirmation land (ADR-129 R15.3(3)).
    ///
    /// # Errors
    /// In the A5.5 order: `InvalidBinding` for the shape refusals, for a
    /// pass that is not Reserved with its call live, for scope bytes that do
    /// not match the pass and for a CDP1 other than the one the pass was
    /// reserved under; `EvidenceUnavailable` for a clock or authority
    /// failure, reason 3, reason 2 code 1, a pass nobody reserved, a missing
    /// or mismatched failure cohort key, an unbootstrapped domain and a
    /// writer at or after the bound; `Conflict` for a Committed pass, a retry
    /// with other bound content and a control identity already used;
    /// `EvidenceExpired` for a retry at or after `H_r` and a decision bound
    /// after the metadata horizon; `StaleGeneration` and `StaleFrontier` for
    /// a moved generation or head; and the codec refusals.
    pub fn abort_pass_failure(
        &mut self,
        seal: &'static AuthorityTrustRootSealV1,
        context: CommunityQuarantineContextV1<'_>,
        lifecycle: &mut CommunityLifecycleAuthorityV1,
        metadata: &mut CommunityMetadataAuthorityV1,
        call: CommunityPassAbortFailureCallV1<'_>,
    ) -> Result<CommunityPassAbortReceiptV1, Error> {
        match self.prepare_failure_abort(seal, context, lifecycle, metadata, call)? {
            PreparedFailureV1::Original(receipt) => Ok(receipt),
            PreparedFailureV1::Staged(staged, reservation, bound) => lifecycle
                .check_control_bound(reservation, bound, self)
                .and_then(|()| self.commit_failure_abort(seal, *staged)),
        }
    }

    /// Every step before the writer.
    fn prepare_failure_abort(
        &mut self,
        seal: &'static AuthorityTrustRootSealV1,
        context: CommunityQuarantineContextV1<'_>,
        lifecycle: &mut CommunityLifecycleAuthorityV1,
        metadata: &mut CommunityMetadataAuthorityV1,
        call: CommunityPassAbortFailureCallV1<'_>,
    ) -> Result<PreparedFailureV1, Error> {
        let input = *call.failure.input();
        check_shape(&input)?;
        let (reservation, write) = lifecycle.reserve_control(self).and_then(|reservation| {
            self.abort_metadata_write(context, metadata)
                .map(|write| (reservation, write))
        })?;
        check_authority(&input)?;
        let bound = reservation
            .decision_bound()
            .min(metadata.owner_expires_at());
        let clock = ClockV1 {
            reservation_id: reservation.reservation_seq(),
            sample_micros: reservation.sampled_at().as_micros(),
            bound_micros: bound.as_micros(),
        };
        let key = (input.timeline, input.reservation_operation_id);
        let record = self
            .pass_record(key.0, key.1)
            .ok_or(Error::EvidenceUnavailable)?
            .clone();
        let horizon = failure_horizon(context, &record);
        let derived =
            check_roster_order(input.failures, &record.reserved.members).and_then(|()| {
                derive_failure(
                    record.reserved.reservation.pass_key,
                    &record.reserved.members,
                    input.failures,
                    horizon,
                )
            })?;
        let abort_bound = PassAbortBoundV1::new(
            input.reason,
            Some(derived.failure_digest),
            input
                .failures
                .iter()
                .filter_map(|failure| failure.control_operation_id)
                .collect(),
        );
        if let PassAbortLookupV1::Original(original) =
            self.lookup_pass_abort_with(key.0, key.1, &abort_bound, first_failure_abort)?
        {
            return self
                .retry_failure_abort(key, original, clock)
                .map(PreparedFailureV1::Original);
        }
        let fenced = self.first_failure_preconditions(context, &record, &input, clock)?;
        let commitments = self.failure_commitments(context, &record, call.scope)?;
        let facts = FailureFactsV1 {
            context,
            input,
            record,
            derived,
            write,
            clock,
            horizon,
            fenced,
            bound: abort_bound,
            commitments,
            scope: call.scope,
        };
        self.stage_failure_abort(seal, lifecycle, &facts)
            .map(|staged| PreparedFailureV1::Staged(Box::new(staged), reservation, bound))
    }

    /// A retry's original receipt: the call's sample must be before the
    /// pass's `H_r` (13) and the retained CAB1 must still open (R15.3(2)
    /// step 4). A failure Abort has no principal to compare.
    fn retry_failure_abort(
        &self,
        key: (TimelineId, [u8; 16]),
        original: &CommittedPassAbortV1,
        clock: ClockV1,
    ) -> Result<CommunityPassAbortReceiptV1, Error> {
        if clock.sample_micros >= original.evidence_not_after_micros {
            Err(Error::EvidenceExpired)
        } else if self.registrations_published(key.0, original) {
            self.open_original_abort(key, original)
        } else {
            Err(Error::EvidenceUnavailable)
        }
    }

    /// Every ARD1 the Abort published still resolves in its generation's
    /// catalogue.
    fn registrations_published(
        &self,
        timeline: TimelineId,
        original: &CommittedPassAbortV1,
    ) -> bool {
        community_catalogue_owner_v1(timeline, original.generation).is_ok_and(|owner| {
            original.admissions.iter().all(|admission| {
                matches!(
                    ArtifactRegistrationPersistencePortV1::read_artifact_registration(
                        &self.store,
                        &owner,
                        admission.as_input().registration_address,
                    ),
                    Ok(Some(_))
                )
            })
        })
    }

    /// R15.3(2) step 5 after the live-call and status rule the lookup ran: no
    /// control identity already in the CQC1 retry index (4), then the CDP1,
    /// generation, head and metadata-horizon fences.
    fn first_failure_preconditions(
        &self,
        context: CommunityQuarantineContextV1<'_>,
        record: &CommunityPassRecordV1,
        input: &CommunityPassAbortFailureInputV1<'_>,
        clock: ClockV1,
    ) -> Result<FencedV1, Error> {
        let used = input.failures.iter().any(|failure| {
            failure
                .control_operation_id
                .is_some_and(|id| self.quarantine_controls.contains_key(&(input.timeline, id)))
        });
        if used {
            Err(Error::Conflict)
        } else {
            self.fence_first_abort(context, record, input.timeline, clock.bound_micros)
        }
    }

    /// The scope bytes the call carries checked against the pass record, and
    /// the digests the records bind: `H(CSB1)` (the COH1 cover), `H(CPV1)`
    /// and the generation's COB1 digest.
    fn failure_commitments(
        &self,
        context: CommunityQuarantineContextV1<'_>,
        record: &CommunityPassRecordV1,
        scope: CommunityPassAbortScopeV1<'_>,
    ) -> Result<(Hash, Hash, Hash), Error> {
        let (cover, provenance) = check_scope(record, scope)?;
        let pass_key = record.reserved.reservation.pass_key;
        self.owner_binding_digest(
            pass_key.timeline(),
            pass_key.generation(),
            context.profile.as_input().roster.len(),
        )
        .map(|owner| (cover, provenance, owner))
    }

    /// The COB1 digest of the generation `(timeline, generation)`
    /// initialization committed, read from its sealed records.
    fn owner_binding_digest(
        &self,
        timeline: TimelineId,
        generation: [u8; 16],
        roster_len: usize,
    ) -> Result<Hash, Error> {
        self.initializations
            .iter()
            .filter(|((initialized, _), _)| *initialized == timeline)
            .find_map(|(_, committed)| {
                self.keys.get(&committed.metadata_key).and_then(|key| {
                    let open = |index: usize| {
                        committed
                            .records
                            .get(index)
                            .and_then(|sealed| key.open(sealed).ok())
                    };
                    committed
                        .records
                        .last()
                        .and_then(|sealed| key.open(sealed).ok())
                        .and_then(|bytes| {
                            CommunityGenerationAdmissionV1::from_canonical_cbor(&bytes).ok()
                        })
                        .filter(|admission| admission.as_input().generation == generation)
                        .and_then(|_| open(roster_len))
                        .and_then(|owner| CommunityOwnerBindingV1::from_canonical_cbor(&owner).ok())
                        .map(|owner| owner.digest())
                })
            })
            .ok_or(Error::EvidenceUnavailable)
    }

    /// Protect the failure records under the retained cohort key and stage
    /// every other record. The key goes back into the domain whether or not
    /// protection succeeds.
    fn stage_failure_abort(
        &mut self,
        seal: &'static AuthorityTrustRootSealV1,
        lifecycle: &CommunityLifecycleAuthorityV1,
        facts: &FailureFactsV1<'_>,
    ) -> Result<StagedFailureAbortV1, Error> {
        let cohort = facts.record.reserved.failure_cohort_key;
        let mut protector = self.cohort_protector(facts)?;
        let batch_facts = BatchFactsV1 {
            pass_key: facts.record.reserved.reservation.pass_key,
            owner_binding_digest: facts.commitments.2,
            scope_cover_digest: facts.commitments.0,
            head: facts.record.reserved.reservation.predecessor_head_digest,
        };
        let protected = protect_failure(
            &mut protector,
            &facts.derived,
            (facts.commitments.2, facts.commitments.1),
        )
        .and_then(|records| {
            control_batch(seal, &protector, &records, batch_facts).map(|batch| (records, batch))
        });
        self.keys.insert(cohort, protector.into_key());
        protected.and_then(|(records, batch)| {
            self.stage_failure_records(seal, lifecycle, facts, (records, batch))
        })
    }

    /// The failure cohort key, taken out of the domain for protection: its
    /// intent must be the failure horizon's and the pass's.
    fn cohort_protector(
        &mut self,
        facts: &FailureFactsV1<'_>,
    ) -> Result<CommunityArtifactProtectorV1, Error> {
        let id = facts.record.reserved.failure_cohort_key;
        let pass_key = facts.record.reserved.reservation.pass_key;
        let fits = self.keys.get(&id).is_some_and(|key| {
            let intent = key.intent().as_input();
            intent.evidence_not_after_micros == facts.horizon
                && intent.parent_operation == CommunityArtifactOperationV1::Pass(pass_key)
        });
        if !fits {
            return Err(Error::EvidenceUnavailable);
        }
        self.keys
            .remove(&id)
            .ok_or(Error::EvidenceUnavailable)
            .and_then(|key| {
                CommunityArtifactProtectorV1::from_retained_key(key, facts.commitments.0)
            })
    }

    /// The CAV1, CAU1, COA1s and CMI1s, and every plaintext the Abort seals
    /// before its quarantine records: the CAB1, CAV1, CAU1, the pass CBQ1,
    /// CSB1 and CPV1, and one CMI1 per COW1.
    fn failure_metadata(
        &self,
        seal: &'static AuthorityTrustRootSealV1,
        lifecycle: &CommunityLifecycleAuthorityV1,
        facts: &FailureFactsV1<'_>,
        (records, (abort, abort_digest)): (
            &[CommunityProtectedRecordV1],
            (&Zeroizing<Vec<u8>>, Hash),
        ),
    ) -> Result<AdmittedRecordsV1, Error> {
        let inventory_generation = CommunityStoreDomainV1::inventory_generation(self);
        let keys = [
            facts.record.reserved.metadata_key,
            facts.record.reserved.failure_cohort_key,
        ]
        .map(|id| self.keys.get(&id).map(VaultKeyV1::intent));
        let intents = keys
            .iter()
            .copied()
            .collect::<Option<Vec<_>>>()
            .ok_or(Error::EvidenceUnavailable)?;
        self.failure_view(
            facts.context,
            lifecycle,
            &facts.record,
            &facts.write,
            &intents,
        )
        .and_then(|view| {
            failure_evidence(
                &EvidenceFactsV1 {
                    store_incarnation: self.store_incarnation,
                    lifecycle,
                    record: &facts.record,
                    write: &facts.write,
                    clock: facts.clock,
                    abort_digest,
                    view_digest: view.digest(),
                    inventory_generation,
                },
                records,
            )
            .map(|(evidence, evidence_digest)| (view, evidence, evidence_digest))
        })
        .and_then(|(view, evidence, evidence_digest)| {
            self.admit_failure_records(
                seal,
                facts,
                records,
                (abort_digest, evidence_digest, inventory_generation),
            )
            .map(|(admissions, mut materializations)| {
                let mut plaintexts = vec![
                    (CommunityMetadataSchemaV1::Cab1, abort.clone()),
                    (CommunityMetadataSchemaV1::Cav1, view.to_canonical_cbor()),
                    (CommunityMetadataSchemaV1::Cau1, evidence),
                    (
                        CommunityMetadataSchemaV1::Cbq1,
                        Zeroizing::new(facts.scope.cbq1.to_vec()),
                    ),
                    (
                        CommunityMetadataSchemaV1::Csb1,
                        Zeroizing::new(facts.scope.csb1.to_vec()),
                    ),
                    (
                        CommunityMetadataSchemaV1::Cpv1,
                        Zeroizing::new(facts.scope.cpv1.to_vec()),
                    ),
                ];
                plaintexts.append(&mut materializations);
                (admissions, plaintexts)
            })
        })
    }

    /// The quarantine records, the CAB1, CAV1, CAU1, COA1s and CMI1s, and
    /// the staged commit around them.
    fn stage_failure_records(
        &self,
        seal: &'static AuthorityTrustRootSealV1,
        lifecycle: &CommunityLifecycleAuthorityV1,
        facts: &FailureFactsV1<'_>,
        (records, batch): (Vec<CommunityProtectedRecordV1>, CommunityArtifactBatchV1),
    ) -> Result<StagedFailureAbortV1, Error> {
        let quarantine = self.quarantine_applies(facts)?;
        failure_abort_record(facts, &quarantine).and_then(|abort| {
            self.finish_failure_records(
                seal,
                lifecycle,
                facts,
                (records, batch),
                (quarantine, abort),
            )
        })
    }

    /// The staged commit around the CAB1, once the quarantine records exist.
    fn finish_failure_records(
        &self,
        seal: &'static AuthorityTrustRootSealV1,
        lifecycle: &CommunityLifecycleAuthorityV1,
        facts: &FailureFactsV1<'_>,
        (records, batch): (Vec<CommunityProtectedRecordV1>, CommunityArtifactBatchV1),
        (quarantine, (abort, abort_digest)): (Vec<QuarantineApplyV1>, (Zeroizing<Vec<u8>>, Hash)),
    ) -> Result<StagedFailureAbortV1, Error> {
        let reservation = facts.record.reserved.reservation;
        let metadata_key = facts.record.reserved.metadata_key;
        let cohort_key = facts.record.reserved.failure_cohort_key;
        let inventory_generation = CommunityStoreDomainV1::inventory_generation(self);
        let (admissions, mut sealed_plaintexts) =
            self.failure_metadata(seal, lifecycle, facts, (&records, (&abort, abort_digest)))?;
        let quarantine_base = sealed_plaintexts.len();
        for apply in &quarantine {
            sealed_plaintexts.push((CommunityMetadataSchemaV1::Cqc1, apply.request.clone()));
            sealed_plaintexts.push((CommunityMetadataSchemaV1::Cqr1, apply.revision.clone()));
            sealed_plaintexts.push((CommunityMetadataSchemaV1::Cqo1, apply.outcome.clone()));
        }
        let anchor = facts.fenced.anchor;
        CommunityMetadataScopeV1::new(CommunityMetadataScopeInputV1 {
            store_incarnation: self.store_incarnation,
            metadata_anchor_timeline: anchor.0,
            metadata_anchor_generation: anchor.1,
            protection_operation_id: metadata_key,
            scope_members: CommunityScopeMembersV1::from_members(&[]),
            metadata_not_after_micros: facts.fenced.metadata_horizon,
        })
        .map(|scope| StagedFailureAbortV1 {
            key: (facts.input.timeline, facts.input.reservation_operation_id),
            committed: CommittedPassAbortV1 {
                bound: facts.bound.clone(),
                abort,
                abort_digest,
                evidence_not_after_micros: reservation.evidence_not_after_micros,
                leaf_grant_id: facts.write.leaf_grant_id,
                metadata_key,
                records: Vec::new(),
                admissions,
                generation: reservation.pass_key.generation(),
            },
            scope,
            plaintexts: sealed_plaintexts,
            batch,
            quarantine,
            quarantine_base,
            cohort_key,
            rows: 1 + facts.derived.invocations.len() as u64,
            read_selection: facts.fenced.selection_address,
            inventory_generation,
        })
    }
}

/// Reason 3 and reason 2 code 1 give 12 in V1 (R15.3(3), owner decision
/// 2026-11-26): no key destruction and no `Expired` confirmation exist.
fn check_authority(input: &CommunityPassAbortFailureInputV1<'_>) -> Result<(), Error> {
    let refused = input.reason == CommunityAbortReasonV1::ProtectedUseRefused
        || input
            .failures
            .iter()
            .any(|failure| failure.host_failure.code() == 1);
    if refused {
        Err(Error::EvidenceUnavailable)
    } else {
        Ok(())
    }
}

/// The failure horizon: `min(quarantine_not_after, H_g)` (R15.2).
fn failure_horizon(
    context: CommunityQuarantineContextV1<'_>,
    record: &CommunityPassRecordV1,
) -> u64 {
    context
        .profile
        .as_input()
        .retention
        .quarantine_not_after_micros
        .min(record.reserved.generation_horizon_micros)
}

/// The pass scope bytes against the pass record (R15.1(4)): `H(CBQ1)` is the
/// record's, the CPV1's budget identity is `H(CBQ1)` and its scope binding is
/// `H(CSB1)`. Returns `H(CSB1)` and `H(CPV1)`.
fn check_scope(
    record: &CommunityPassRecordV1,
    scope: CommunityPassAbortScopeV1<'_>,
) -> Result<(Hash, Hash), Error> {
    let decoded = CommunityScopeBindingV1::from_canonical_cbor(scope.csb1)
        .and_then(|csb1| {
            CommunityOriginalProvenanceV1::from_canonical_cbor(scope.cpv1)
                .map(|cpv1| (csb1.digest(), cpv1))
        })
        .and_then(|(cover, cpv1)| {
            CommunityBudgetQuoteV1::from_canonical_cbor(scope.cbq1)
                .map(|cbq1| (cover, cpv1, cbq1.digest()))
        })
        .map_err(|_| Error::InvalidBinding)?;
    let (cover, cpv1, quote) = decoded;
    let fields = cpv1.as_input();
    if quote == record.reserved.cbq1_digest
        && fields.budget_identity == quote
        && fields.scope_binding_digest == cover
    {
        Ok((cover, cpv1.digest()))
    } else {
        Err(Error::InvalidBinding)
    }
}

/// The CAB1 of the failure Abort: its CFO1 and the delta of its in-Abort
/// `SetReason`s.
fn failure_abort_record(
    facts: &FailureFactsV1<'_>,
    applies: &[QuarantineApplyV1],
) -> Result<(Zeroizing<Vec<u8>>, Hash), Error> {
    quarantine_delta(applies).and_then(|delta| {
        abort_record(&AbortFieldsV1 {
            reservation: facts.record.reserved.reservation,
            sealed_result_digest: facts.record.sealed_result_digest,
            reason: facts.input.reason,
            failure_evidence_digest: Some(facts.derived.failure_digest),
            quarantine_delta_digest: delta,
        })
    })
}

/// The CAB1 `quarantine_delta_digest`: the sorted rows of the in-Abort
/// `SetReason`s, or none.
fn quarantine_delta(applies: &[QuarantineApplyV1]) -> Result<Option<Hash>, Error> {
    let mut rows: Vec<CommunityQuarantineDeltaRowV1> =
        applies.iter().map(|apply| apply.delta).collect();
    rows.sort_unstable();
    if rows.is_empty() {
        Ok(None)
    } else {
        community_quarantine_delta_digest_v1(&rows).map(Some)
    }
}

impl MemoryCommunityDomainV1 {
    /// The in-Abort `SetReason` of each failure that carries a control
    /// identity.
    fn quarantine_applies(
        &self,
        facts: &FailureFactsV1<'_>,
    ) -> Result<Vec<QuarantineApplyV1>, Error> {
        let reservation = facts.record.reserved.reservation;
        let shared = QuarantineFactsV1 {
            context: facts.context,
            timeline: facts.input.timeline,
            generation: reservation.pass_key.generation(),
            head: reservation.predecessor_head_digest,
            failure_digest: facts.derived.failure_digest,
            horizon: facts.horizon,
            bound_micros: facts.clock.bound_micros,
        };
        facts
            .input
            .failures
            .iter()
            .zip(&facts.derived.invocations)
            .filter_map(|(failure, invocation)| {
                failure
                    .control_operation_id
                    .zip(community_quarantine_reason_v1(failure.host_failure))
                    .map(|mapped| (failure, invocation, mapped))
            })
            .map(|(failure, invocation, mapped)| {
                facts
                    .record
                    .reserved
                    .members
                    .iter()
                    .find(|member| member.cmb1_digest == invocation.member)
                    .ok_or(Error::InvalidBinding)
                    .and_then(|member| {
                        self.quarantine_apply(
                            &shared,
                            &FailedMemberV1 {
                                failure,
                                member,
                                provenance: invocation.provenance,
                            },
                            mapped,
                        )
                    })
            })
            .collect()
    }

    /// One COA1 and one CMI1 per COW1 (R15.1(5)), in protection order.
    fn admit_failure_records(
        &self,
        seal: &'static AuthorityTrustRootSealV1,
        facts: &FailureFactsV1<'_>,
        records: &[CommunityProtectedRecordV1],
        (abort_digest, evidence_digest, inventory_generation): (Hash, Hash, u64),
    ) -> Result<AdmittedRecordsV1, Error> {
        let pass_key = facts.record.reserved.reservation.pass_key;
        let coordinates = (pass_key.timeline(), pass_key.generation());
        records
            .iter()
            .zip(named_records(&facts.derived))
            .map(|(record, name)| {
                record
                    .admission(seal, inventory_generation, evidence_digest)
                    .and_then(|admission| {
                        materialization(
                            self.store_incarnation,
                            coordinates,
                            abort_digest,
                            &name,
                            (record, admission.digest()),
                        )
                        .map(|record| (admission, (CommunityMetadataSchemaV1::Cmi1, record)))
                    })
            })
            .collect::<Result<Vec<_>, Error>>()
            .map(|rows| rows.into_iter().unzip())
    }

    /// The atomic failure Abort commit (R15.1(8)): the inventory generation
    /// and the CSI1 are compared, the pending entry is found for the rows
    /// the Abort registers, the records are sealed and the ARD1s published,
    /// and only then does the entry go, the pass become Aborted, both keys
    /// close, and the quarantine and retry indexes and the inventory
    /// generation advance, once.
    ///
    /// # Errors
    /// Returns `EvidenceUnavailable` when either compared value moved or
    /// the pass metadata key is missing, `InvalidBinding` when the pass holds
    /// no pending entry for the rows, `Conflict` for an ARD1 already
    /// catalogued and `CapacityExhausted` when the key cannot seal.
    fn commit_failure_abort(
        &mut self,
        seal: &'static AuthorityTrustRootSealV1,
        mut staged: StagedFailureAbortV1,
    ) -> Result<CommunityPassAbortReceiptV1, Error> {
        self.check_unmoved(staged.inventory_generation, staged.read_selection)?;
        let token = self.stage_abort(staged.key.0, staged.key.1, staged.rows)?;
        let sealed = self.seal_plaintexts(
            staged.committed.metadata_key,
            &staged.scope,
            &staged.plaintexts,
        )?;
        self.store.commit_community_artifact_batch(&staged.batch)?;
        self.apply_abort(seal, &token).map(|()| {
            self.close_pass_metadata_key(staged.committed.metadata_key);
            self.close_pass_metadata_key(staged.cohort_key);
            self.inventory_generation += 1;
            self.retain_quarantine(&mut staged, &sealed);
            staged.committed.records = sealed;
            let receipt = CommunityPassAbortReceiptV1::from_parts(
                staged.key.0,
                staged.key.1,
                staged.committed.abort_digest,
                staged.committed.abort.clone(),
            );
            self.pass_aborts.insert(staged.key, staged.committed);
            receipt
        })
    }

    /// Retain each in-Abort `SetReason`: the ledger in the quarantine index
    /// and the CQC1 in the retry index, with its sealed CQO1 (R15.3(4)). An
    /// in-Abort reason spends no `F_q` share (R15.3(6)), so the erasure
    /// budget's active pairs do not move.
    fn retain_quarantine(
        &mut self,
        staged: &mut StagedFailureAbortV1,
        sealed: &[SealedMetadataV1],
    ) {
        let outcomes = sealed.iter().skip(staged.quarantine_base + 2).step_by(3);
        for (apply, outcome) in std::mem::take(&mut staged.quarantine)
            .into_iter()
            .zip(outcomes)
        {
            self.quarantine_index.insert(apply.key, apply.ledger);
            self.quarantine_controls.insert(
                (staged.key.0, apply.control_operation_id),
                CommittedQuarantineControlV1 {
                    bound: apply.bound,
                    generation: staged.committed.generation,
                    metadata_key: staged.committed.metadata_key,
                    records: vec![SealedMetadataV1 {
                        envelope: outcome.envelope.clone(),
                        address: outcome.address,
                        commitment: outcome.commitment,
                    }],
                    admission: None,
                    receipt: apply.receipt,
                },
            );
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
