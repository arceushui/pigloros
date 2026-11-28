//! The authenticated Abort of an unresolved pass, reasons 0 and 4
//! (#560 A4e-2; ADR-129 R8.3, R15.1 and R15.3).
//!
//! [`MemoryCommunityDomainV1::abort_pass`] runs, in the A5.5 order:
//!
//! 1. the shape (3): reason 0 or 4, and the derived `community.pass.abort.v1`
//!    request, which refuses a zero Timeline or reservation identity;
//! 2. the FAE1, the administrative decision and the one trusted-clock
//!    reservation (12);
//! 3. the metadata `write` decision (12), which every CNE1 read or write
//!    needs, and the retry lookup by `(T, reservation_operation_id)` (12 for a
//!    pass nobody reserved; 4 for a Committed pass, other bound content or
//!    another principal; 13 for a retry at or after the pass's `H_r`) and,
//!    for a first Abort, the live-call refusal (15);
//! 4. for a first Abort, after the live-call refusal (15): the installed
//!    CDP1 must be the Reserve's, that is its digest must equal the pass's
//!    `profile_digest` (3); then the generation (5) and head (6) fences, the
//!    guard that the head is still the initialization head (12, until A5
//!    commits a pass) and the metadata horizon (13);
//! 5. the records: the CAB1, the CAV1 (whose one authority row is the abort
//!    decision's chain) and the CAU1 with the abort decision and the
//!    metadata `write` decision as its two rows (R15.1(5)), all sealed under
//!    the pass's one metadata key, which the Abort then closes;
//! 6. the writer's decision-bound check, then one commit: the pending
//!    erasure entry is replaced (an Abort registers no row), the pass moves
//!    to Aborted and the retry index and the inventory generation advance
//!    once. No producer ordinal is allocated and no CSI1 row changes.

use std::collections::BTreeMap;

use pos_core::community_lifecycle::{
    community_recipient_identity_digest_v1, CommunityAbortReasonV1, CommunityArtifactOperationV1,
    CommunityAuthorityEvidenceInputV1, CommunityAuthorityEvidenceV1, CommunityAuthorityViewRowV1,
    CommunityClockBoundV1, CommunityCurrentViewInputV1, CommunityCurrentViewV1,
    CommunityDecisionRowV1, CommunityKeyIntentV1, CommunityLifecycleErrorV1 as Error,
    CommunityMetadataSchemaV1, CommunityMetadataScopeInputV1, CommunityMetadataScopeV1,
    CommunityPassFrontierV1, CommunityScopeMembersV1, CommunityTrustViewRowV1,
};
use pos_core::{
    AuthorityGranteeV1, AuthorityTrustRootSealV1, AuthorizationRequestV1, Hash, TimelineId,
};
use zeroize::Zeroizing;

use super::super::lifecycle_authority::{
    CommunityAdministrativeOperationV1, CommunityAdministrativeRequestV1,
    CommunityAuthorityAdmissionV1, CommunityAuthorityCallV1, CommunityLifecycleAuthorityV1,
};
use super::super::memory_domain::MemoryCommunityDomainV1;
use super::super::metadata_authority::{CommunityMetadataAuthorityV1, MetadataActionV1};
use super::super::pass_record::CommunityPassRecordV1;
use super::super::planner::key_rows;
use super::super::quarantine::CommunityQuarantineContextV1;
use super::super::sealer::SealedMetadataV1;
use super::super::store_domain::CommunityStoreDomainV1;
use super::{
    abort_record, AbortFieldsV1, CommittedPassAbortV1, PassAbortBoundV1, PassAbortLookupV1,
};

/// One caller's reason-0 or reason-4 Abort (A5.3(0), R8.3(2)).
///
/// It carries its one FAE1 and the untrusted leaf-grant locator of its
/// administrative decision. The caller need not know the CPK1: the host
/// derives every other CAB1 field from the pass record.
#[derive(Clone, Copy)]
pub struct CommunityPassAbortCallV1<'a> {
    /// The call's one canonical FAE1 (R6.2(1)).
    pub credential: &'a [u8],
    /// The aborted pass's Timeline T.
    pub timeline: TimelineId,
    /// The pass's `reservation_operation_id`, which a lost Reserve reply
    /// leaves the caller holding.
    pub reservation_operation_id: [u8; 16],
    /// `AuthenticatedCancellation` or `RetiringGeneration`.
    pub reason: CommunityAbortReasonV1,
    /// The leaf grant of the administrative decision.
    pub administrative_leaf: Hash,
}

/// The original outcome of one committed Abort: its CAB1. A retry returns
/// it unchanged.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommunityPassAbortReceiptV1 {
    timeline: TimelineId,
    reservation_operation_id: [u8; 16],
    abort_digest: Hash,
    abort: Zeroizing<Vec<u8>>,
}

impl CommunityPassAbortReceiptV1 {
    /// The receipt of the Abort of `(timeline, reservation_operation_id)`.
    pub(super) const fn from_parts(
        timeline: TimelineId,
        reservation_operation_id: [u8; 16],
        abort_digest: Hash,
        abort: Zeroizing<Vec<u8>>,
    ) -> Self {
        Self {
            timeline,
            reservation_operation_id,
            abort_digest,
            abort,
        }
    }

    /// The aborted pass's Timeline.
    #[must_use]
    pub const fn timeline(&self) -> TimelineId {
        self.timeline
    }

    /// The aborted pass's `reservation_operation_id`.
    #[must_use]
    pub const fn reservation_operation_id(&self) -> [u8; 16] {
        self.reservation_operation_id
    }

    /// `H(CAB1)`.
    #[must_use]
    pub const fn abort_digest(&self) -> Hash {
        self.abort_digest
    }

    /// The canonical CAB1.
    #[must_use]
    pub fn abort(&self) -> &[u8] {
        &self.abort
    }
}

/// The metadata `write` decision of one Abort.
pub(super) struct MetadataWriteV1 {
    pub(super) request: AuthorizationRequestV1,
    pub(super) decision_digest: Hash,
    pub(super) leaf_grant_id: Hash,
}

/// Everything one Abort commits, staged before the writer.
struct StagedPassAbortV1 {
    key: (TimelineId, [u8; 16]),
    committed: CommittedPassAbortV1,
    scope: CommunityMetadataScopeV1<'static>,
    plaintexts: [(CommunityMetadataSchemaV1, Zeroizing<Vec<u8>>); 3],
    /// The CSI1 the operation read: the swap's expected value.
    read_selection: Hash,
    /// The inventory generation CAU1 read (G5): the swap's expected value.
    inventory_generation: u64,
}

/// The outcome of every step before the writer.
enum PreparedAbortV1 {
    /// A retry's original receipt.
    Original(CommunityPassAbortReceiptV1),
    /// A new Abort and the call whose bound the writer checks.
    Staged(Box<StagedPassAbortV1>, CommunityAuthorityCallV1),
}

/// The facts every staging step reads.
struct StageInputsV1<'a> {
    call: CommunityPassAbortCallV1<'a>,
    bound: PassAbortBoundV1,
    authenticated: &'a CommunityAuthorityCallV1,
    administrative: &'a CommunityAuthorityAdmissionV1,
    write: &'a MetadataWriteV1,
}

/// What a first Abort read from the CSI1 and the CAB1 it derived.
struct StageFactsV1 {
    /// The CMA1 anchor `(T, G)` every metadata record's CSM1 names.
    anchor: (TimelineId, [u8; 16]),
    /// The CNE1 address of the CSI1 read.
    selection_address: Hash,
    /// The NMP1 `metadata_not_after_micros`.
    metadata_horizon: u64,
    /// The canonical CAB1 and `H(CAB1)`.
    abort: (Zeroizing<Vec<u8>>, Hash),
    /// The inventory generation read.
    inventory_generation: u64,
}

impl MemoryCommunityDomainV1 {
    /// Abort an unresolved pass by authenticated cancellation (reason 0) or
    /// before retirement (reason 4), or return the original outcome of a
    /// retry.
    ///
    /// Only the trusted composition root, which holds the
    /// [`AuthorityTrustRootSealV1`], aborts:
    ///
    /// ```compile_fail,E0061
    /// use pos_store::community::{
    ///     CommunityLifecycleAuthorityV1, CommunityMetadataAuthorityV1, CommunityPassAbortCallV1,
    ///     CommunityQuarantineContextV1, MemoryCommunityDomainV1,
    /// };
    /// fn forge(
    ///     domain: &mut MemoryCommunityDomainV1,
    ///     context: CommunityQuarantineContextV1<'_>,
    ///     lifecycle: &mut CommunityLifecycleAuthorityV1,
    ///     metadata: &mut CommunityMetadataAuthorityV1,
    ///     call: CommunityPassAbortCallV1<'_>,
    /// ) {
    ///     let _ = domain.abort_pass(context, lifecycle, metadata, call);
    /// }
    /// ```
    ///
    /// The metadata horizon check compares the call's decision bound, up to
    /// 32 s after its sample, with `metadata_not_after`. An Abort in the last
    /// 32 s before it therefore gives 13 and the pass stays unresolved
    /// (ADR-129 R15 O6; as A4e-1's `SetReason`).
    ///
    /// # Errors
    /// In the A5.5 order: `InvalidBinding` for a reason other than 0 or 4 or
    /// a zero identity or reservation, and for a CDP1 other than the one the
    /// pass was reserved under; `EvidenceUnavailable` for every authority
    /// failure, a pass nobody reserved, an unbootstrapped domain, a Timeline
    /// whose head is not its initialization head, a pass record with no due
    /// member (there is no retained TPS1 digest to use), a missing pass
    /// metadata key and a writer at or after the decision bound; `Conflict`
    /// for a Committed pass, a retry with other bound content or by another
    /// principal; `EvidenceExpired` for a retry at or after the pass's
    /// `H_r`; `OperationActive` while the pass's call is live;
    /// `StaleGeneration` and `StaleFrontier` for a moved generation or head;
    /// `EvidenceExpired` when the decision bound is after the metadata
    /// horizon; `CapacityExhausted` when the pass metadata key cannot seal;
    /// and the codec refusals.
    pub fn abort_pass(
        &mut self,
        seal: &'static AuthorityTrustRootSealV1,
        context: CommunityQuarantineContextV1<'_>,
        lifecycle: &mut CommunityLifecycleAuthorityV1,
        metadata: &mut CommunityMetadataAuthorityV1,
        call: CommunityPassAbortCallV1<'_>,
    ) -> Result<CommunityPassAbortReceiptV1, Error> {
        match self.prepare_pass_abort(context, lifecycle, metadata, call)? {
            PreparedAbortV1::Original(receipt) => Ok(receipt),
            PreparedAbortV1::Staged(staged, authenticated) => {
                lifecycle.check_writer_bound(authenticated, self)?;
                self.commit_pass_abort(seal, *staged)
            }
        }
    }

    /// Every step before the writer: the original outcome of a retry, or
    /// the staged commit with the call whose bound the writer checks.
    fn prepare_pass_abort(
        &mut self,
        context: CommunityQuarantineContextV1<'_>,
        lifecycle: &mut CommunityLifecycleAuthorityV1,
        metadata: &mut CommunityMetadataAuthorityV1,
        call: CommunityPassAbortCallV1<'_>,
    ) -> Result<PreparedAbortV1, Error> {
        check_operator_reason(call.reason)?;
        let request = CommunityAdministrativeRequestV1::derive(
            &CommunityAdministrativeOperationV1::PassAbort {
                timeline: call.timeline,
                reservation_operation_id: call.reservation_operation_id,
            },
        )?;
        let authenticated = lifecycle.authenticate(call.credential, request, self)?;
        let administrative =
            lifecycle.authorize_administrative(&authenticated, self, call.administrative_leaf)?;
        let write = self.abort_metadata_write(context, metadata)?;
        let bound = PassAbortBoundV1::new(call.reason, None, Vec::new());
        let key = (call.timeline, call.reservation_operation_id);
        match self.lookup_pass_abort(key.0, key.1, &bound)? {
            PassAbortLookupV1::Original(original) => self
                .original_abort(key, original, &administrative, &authenticated)
                .map(PreparedAbortV1::Original),
            PassAbortLookupV1::First(record) => self
                .stage_pass_abort(
                    context,
                    lifecycle,
                    record,
                    &StageInputsV1 {
                        call,
                        bound,
                        authenticated: &authenticated,
                        administrative: &administrative,
                        write: &write,
                    },
                )
                .map(|staged| PreparedAbortV1::Staged(Box::new(staged), authenticated)),
        }
    }

    /// The metadata `write` decision of the operation, which alone admits
    /// every CNE1 read or write (A5.4, no latch).
    pub(super) fn abort_metadata_write(
        &self,
        context: CommunityQuarantineContextV1<'_>,
        metadata: &mut CommunityMetadataAuthorityV1,
    ) -> Result<MetadataWriteV1, Error> {
        let policy = context.binding.metadata_policy;
        let leaf_grant_id = policy.as_input().metadata_authority_leaf_grant;
        CommunityStoreDomainV1::load_authority(self, leaf_grant_id)
            .ok()
            .and_then(|persisted| {
                metadata
                    .authorize_request(
                        policy,
                        &persisted,
                        self.store_incarnation,
                        MetadataActionV1::Write,
                    )
                    .ok()
            })
            .and_then(|(request, decision)| {
                decision.encode().ok().map(|aud| MetadataWriteV1 {
                    request,
                    decision_digest: Hash::from_bytes(*blake3::hash(aud.as_slice()).as_bytes()),
                    leaf_grant_id,
                })
            })
            .ok_or(Error::EvidenceUnavailable)
    }

    /// A retry's original receipt: the decision's principal must be the
    /// original leaf grant's grantee (A5.3(6)), the call's sample must be
    /// before the pass's `H_r` (discovery of expired evidence gives 13,
    /// R13.2(4)), and the retained CAB1 must still open under the pass
    /// metadata key as the receipt's.
    fn original_abort(
        &self,
        key: (TimelineId, [u8; 16]),
        original: &CommittedPassAbortV1,
        administrative: &CommunityAuthorityAdmissionV1,
        authenticated: &CommunityAuthorityCallV1,
    ) -> Result<CommunityPassAbortReceiptV1, Error> {
        let grantee = CommunityStoreDomainV1::load_authority(self, original.leaf_grant_id)?
            .chain()
            .grants()
            .last()
            .map(|grant| grant.grantee().clone());
        if grantee
            != Some(AuthorityGranteeV1::Principal(
                administrative.decision().principal().clone(),
            ))
        {
            return Err(Error::Conflict);
        }
        if authenticated.at_time().as_micros() >= original.evidence_not_after_micros {
            return Err(Error::EvidenceExpired);
        }
        self.open_original_abort(key, original)
    }

    /// The original receipt of a retry: the retained CAB1 must still open under
    /// the pass metadata key as the receipt's.
    pub(super) fn open_original_abort(
        &self,
        key: (TimelineId, [u8; 16]),
        original: &CommittedPassAbortV1,
    ) -> Result<CommunityPassAbortReceiptV1, Error> {
        self.keys
            .get(&original.metadata_key)
            .zip(original.records.first())
            .ok_or(Error::EvidenceUnavailable)
            .and_then(|(vault, sealed)| vault.open(sealed))
            .and_then(|opened| {
                if opened.as_slice() == original.abort.as_slice() {
                    Ok(CommunityPassAbortReceiptV1 {
                        timeline: key.0,
                        reservation_operation_id: key.1,
                        abort_digest: original.abort_digest,
                        abort: original.abort.clone(),
                    })
                } else {
                    Err(Error::EvidenceUnavailable)
                }
            })
    }

    /// The fences of a first Abort and its CAB1: the installed CDP1 must be
    /// the Reserve's (3), then the generation (5), the head (6) and the
    /// initialization-head guard (12), then the metadata horizon (13), as
    /// A5.5 step 4 and A4e-1 order them.
    ///
    /// A first Abort at or after the pass's `H_r` still commits its CAB1
    /// (R15.2(3a), N17).
    fn stage_pass_abort(
        &self,
        context: CommunityQuarantineContextV1<'_>,
        lifecycle: &CommunityLifecycleAuthorityV1,
        record: &CommunityPassRecordV1,
        inputs: &StageInputsV1<'_>,
    ) -> Result<StagedPassAbortV1, Error> {
        let reservation = record.reserved.reservation;
        let fenced = self.fence_first_abort(
            context,
            record,
            inputs.call.timeline,
            inputs.authenticated.decision_bound().as_micros(),
        )?;
        let abort = abort_record(&AbortFieldsV1 {
            reservation,
            sealed_result_digest: record.sealed_result_digest,
            reason: inputs.call.reason,
            failure_evidence_digest: None,
            quarantine_delta_digest: None,
        })?;
        self.stage_abort_records(
            context,
            lifecycle,
            record,
            inputs,
            StageFactsV1 {
                anchor: fenced.anchor,
                selection_address: fenced.selection_address,
                metadata_horizon: fenced.metadata_horizon,
                abort,
                inventory_generation: CommunityStoreDomainV1::inventory_generation(self),
            },
        )
    }

    /// Stage the CAB1, CAV1 and CAU1 and the CSM1 that seals them.
    ///
    /// The CSM1 cover is the one the Reserve seals its CNE1 records under:
    /// the CMA1 anchor `(T, G)`, the pass metadata key's protection ID, no
    /// scope members and the NMP1 metadata horizon.
    fn stage_abort_records(
        &self,
        context: CommunityQuarantineContextV1<'_>,
        lifecycle: &CommunityLifecycleAuthorityV1,
        record: &CommunityPassRecordV1,
        inputs: &StageInputsV1<'_>,
        facts: StageFactsV1,
    ) -> Result<StagedPassAbortV1, Error> {
        let metadata_key = record.reserved.metadata_key;
        self.keys
            .get(&metadata_key)
            .ok_or(Error::EvidenceUnavailable)
            .and_then(|vault| {
                self.abort_view(
                    context,
                    lifecycle,
                    record,
                    inputs,
                    vault.intent(),
                    facts.inventory_generation,
                )
            })
            .and_then(|view| {
                abort_evidence(
                    self.store_incarnation,
                    lifecycle,
                    record,
                    inputs,
                    facts.abort.1,
                    &view,
                    facts.inventory_generation,
                )
                .map(|evidence| (view, evidence))
            })
            .and_then(|(view, evidence)| {
                CommunityMetadataScopeV1::new(CommunityMetadataScopeInputV1 {
                    store_incarnation: self.store_incarnation,
                    metadata_anchor_timeline: facts.anchor.0,
                    metadata_anchor_generation: facts.anchor.1,
                    protection_operation_id: metadata_key,
                    scope_members: CommunityScopeMembersV1::from_members(&[]),
                    metadata_not_after_micros: facts.metadata_horizon,
                })
                .map(|scope| StagedPassAbortV1 {
                    key: (inputs.call.timeline, inputs.call.reservation_operation_id),
                    committed: CommittedPassAbortV1 {
                        bound: inputs.bound.clone(),
                        abort: facts.abort.0.clone(),
                        abort_digest: facts.abort.1,
                        evidence_not_after_micros: record
                            .reserved
                            .reservation
                            .evidence_not_after_micros,
                        leaf_grant_id: inputs.administrative.leaf_grant_id(),
                        metadata_key,
                        records: Vec::new(),
                        admissions: Vec::new(),
                        generation: record.reserved.reservation.pass_key.generation(),
                    },
                    scope,
                    plaintexts: [
                        (CommunityMetadataSchemaV1::Cab1, facts.abort.0),
                        (CommunityMetadataSchemaV1::Cav1, view.to_canonical_cbor()),
                        (CommunityMetadataSchemaV1::Cau1, evidence),
                    ],
                    read_selection: facts.selection_address,
                    inventory_generation: facts.inventory_generation,
                })
            })
    }

    /// The CAV1 of the Abort, read inside its guard (R15.1(5)): T's current
    /// selection (the initial frontier with no head ref until A5 commits a
    /// pass), the abort decision's authority row, the trust row of each
    /// roster Plugin, the pass metadata key's row and the clock latch.
    fn abort_view(
        &self,
        context: CommunityQuarantineContextV1<'_>,
        lifecycle: &CommunityLifecycleAuthorityV1,
        record: &CommunityPassRecordV1,
        inputs: &StageInputsV1<'_>,
        key: &CommunityKeyIntentV1,
        inventory_generation: u64,
    ) -> Result<CommunityCurrentViewV1, Error> {
        let pass_key = record.reserved.reservation.pass_key;
        self.authority_rows(inputs).and_then(|authority_rows| {
            self.abort_trust_rows(context, lifecycle.trust_scope(), record)
                .and_then(|trust_rows| {
                    CommunityStoreDomainV1::clock_latch(self).and_then(|clock_latch| {
                        CommunityCurrentViewV1::new(CommunityCurrentViewInputV1 {
                            store_incarnation: self.store_incarnation,
                            timeline: pass_key.timeline(),
                            generation: pass_key.generation(),
                            inventory_generation,
                            frontier: CommunityPassFrontierV1::Initial,
                            selected_head: None,
                            scope_rows: vec![],
                            authority_rows,
                            trust_rows,
                            key_rows: key_rows(&[key]),
                            clock_latch,
                        })
                    })
                })
        })
    }

    /// The administrative decision's authority row, at the head and epoch
    /// its decision read.
    ///
    /// The metadata decision's chain is not a second row. A CAV1 holds
    /// strictly ascending `(authority_timeline, head_seq, epoch)` rows, so
    /// two chains read at one head cannot both be in it. This is the first
    /// operation whose CAU1 decision rows are a strict superset of its CAV1
    /// authority rows: in an initialization the two come from the same list
    /// of decisions, and the metadata `write` decision appears in neither (it
    /// enters through the key's `authority_request_digest`). R15.1(5) puts
    /// the metadata `write` decision in this CAU1's rows, so the CAU1 holds
    /// both decisions and the CAV1 only the abort decision's chain.
    fn authority_rows(
        &self,
        inputs: &StageInputsV1<'_>,
    ) -> Result<Vec<CommunityAuthorityViewRowV1>, Error> {
        let request = inputs.administrative.request();
        CommunityStoreDomainV1::authority_row(self, inputs.administrative.leaf_grant_id(), request)
            .and_then(|row| {
                // The chain cannot move between the decision and this read
                // inside one `&mut self` call, so the filter never refuses
                // today; it pins the decision's head and epoch in the row.
                Some(row)
                    .filter(|row| {
                        (row.head_seq, row.revocation_epoch)
                            == (request.at_position().as_u64(), request.revocation_epoch())
                    })
                    .map(|row| vec![row])
                    .ok_or(Error::EvidenceUnavailable)
            })
    }

    /// One trust row per distinct Plugin of the roster (R6.5(4)).
    ///
    /// A Plugin with an active release has its registry row, read now from
    /// this domain's own registry. One with none has the row its Reserve
    /// retained (owner decision, #560, 2026-11-25): the roster row's admitted
    /// PMF1 and release digest, the recorded TPS1 digest of its due member
    /// (or of the first member) as the policy digest and zero floors and
    /// UTC second. So an operator Abort is never refused for a release the
    /// registry no longer holds, and the CAV1 is never partial. The set is
    /// never empty: a CDP1 roster has at least one row.
    pub(super) fn abort_trust_rows(
        &self,
        context: CommunityQuarantineContextV1<'_>,
        scope: &str,
        record: &CommunityPassRecordV1,
    ) -> Result<Vec<CommunityTrustViewRowV1>, Error> {
        let roster = context.profile.as_input().roster;
        let mut plugins = BTreeMap::new();
        for row in roster {
            plugins
                .entry(row.implementation().plugin_id())
                .or_insert(row);
        }
        let members = &record.reserved.members;
        let first = members.first().ok_or(Error::EvidenceUnavailable)?;
        CommunityStoreDomainV1::plugin_trust_policy(self, scope).and_then(|policy| {
            u64::try_from(policy.highest_trusted_utc_second().unwrap_or(0))
                .ok()
                .ok_or(Error::EvidenceUnavailable)
                .and_then(|utc| {
                    plugins
                        .into_iter()
                        .map(|(plugin_id, row)| {
                            CommunityStoreDomainV1::active_release(self, scope, plugin_id).map(
                                |active| {
                                    active.map_or_else(
                                        || CommunityTrustViewRowV1 {
                                            scope: scope.to_owned(),
                                            plugin_id: plugin_id.to_owned(),
                                            policy_digest: members
                                                .iter()
                                                .find(|member| {
                                                    roster.get(member.roster_index).is_some_and(
                                                        |candidate| {
                                                            candidate.implementation().plugin_id()
                                                                == plugin_id
                                                        },
                                                    )
                                                })
                                                .unwrap_or(first)
                                                .trust_policy_snapshot_digest,
                                            policy_floor: 0,
                                            release_floor: 0,
                                            highest_trusted_utc_second: 0,
                                            active_manifest_digest: row.digests()[0],
                                            active_release_digest: Hash::from_bytes(
                                                *row.implementation().release_digest().as_bytes(),
                                            ),
                                        },
                                        |active| CommunityTrustViewRowV1 {
                                            scope: scope.to_owned(),
                                            plugin_id: plugin_id.to_owned(),
                                            policy_digest: Hash::from_bytes(policy.tps1_digest()),
                                            policy_floor: policy
                                                .ptr1_floor()
                                                .map_or(0, |(floor, _)| floor),
                                            release_floor: policy
                                                .prv1_floor()
                                                .map_or(0, |(floor, _)| floor),
                                            highest_trusted_utc_second: utc,
                                            active_manifest_digest: Hash::from_bytes(
                                                active.pmf1_digest(),
                                            ),
                                            active_release_digest: Hash::from_bytes(
                                                active.release_digest(),
                                            ),
                                        },
                                    )
                                },
                            )
                        })
                        .collect()
                })
        })
    }

    /// The atomic Abort commit (R15.1(8)): the inventory generation and the
    /// CSI1 the operation read are compared, the pending erasure entry is
    /// found, and the records are sealed under the pass metadata key. Only
    /// then is the entry replaced (an Abort registers no row), the retry
    /// index retained, the inventory generation advanced once and the key
    /// closed: every earlier step can still refuse, and a refusal leaves the
    /// pass unresolved with its key open.
    ///
    /// # Errors
    /// Returns `EvidenceUnavailable` when either compared value moved or the
    /// pass metadata key is missing, `InvalidBinding` when the pass holds no
    /// pending entry and `CapacityExhausted` when the key cannot seal.
    fn commit_pass_abort(
        &mut self,
        seal: &'static AuthorityTrustRootSealV1,
        mut staged: StagedPassAbortV1,
    ) -> Result<CommunityPassAbortReceiptV1, Error> {
        self.check_unmoved(staged.inventory_generation, staged.read_selection)?;
        let token = self.stage_abort(staged.key.0, staged.key.1, 0)?;
        staged.committed.records = self.seal_abort_records(&staged)?;
        self.apply_abort(seal, &token).map(|()| {
            self.close_pass_metadata_key(staged.committed.metadata_key);
            self.inventory_generation += 1;
            let receipt = CommunityPassAbortReceiptV1 {
                timeline: staged.key.0,
                reservation_operation_id: staged.key.1,
                abort_digest: staged.committed.abort_digest,
                abort: staged.committed.abort.clone(),
            };
            self.pass_aborts.insert(staged.key, staged.committed);
            receipt
        })
    }

    /// Seal the staged records under the pass metadata key, which stays
    /// open for the caller to close once the Abort commits.
    fn seal_abort_records(
        &mut self,
        staged: &StagedPassAbortV1,
    ) -> Result<Vec<SealedMetadataV1>, Error> {
        self.seal_plaintexts(
            staged.committed.metadata_key,
            &staged.scope,
            &staged.plaintexts,
        )
    }

    /// Seal `plaintexts` in order under the metadata key `metadata_key`.
    pub(super) fn seal_plaintexts(
        &mut self,
        metadata_key: [u8; 16],
        scope: &CommunityMetadataScopeV1<'_>,
        plaintexts: &[(CommunityMetadataSchemaV1, Zeroizing<Vec<u8>>)],
    ) -> Result<Vec<SealedMetadataV1>, Error> {
        self.keys
            .get_mut(&metadata_key)
            .ok_or(Error::EvidenceUnavailable)
            .and_then(|vault| {
                plaintexts
                    .iter()
                    .map(|(schema, plaintext)| vault.seal(scope, *schema, plaintext))
                    .collect()
            })
    }

    /// The compare of the atomic commit: the inventory generation and the
    /// CSI1 the operation read must be unmoved.
    pub(super) fn check_unmoved(
        &self,
        inventory_generation: u64,
        read_selection: Hash,
    ) -> Result<(), Error> {
        let current = self.selection.as_ref().map(|(_, sealed)| sealed.address);
        if self.inventory_generation == inventory_generation && current == Some(read_selection) {
            Ok(())
        } else {
            Err(Error::EvidenceUnavailable)
        }
    }

    /// The pass is terminal: its metadata key never encrypts again.
    pub(super) fn close_pass_metadata_key(&mut self, protection_id: [u8; 16]) {
        if let Some(vault) = self.keys.get_mut(&protection_id) {
            vault.close();
        }
    }
}

/// Step 1: reason 0 `AuthenticatedCancellation` or 4 `RetiringGeneration`.
const fn check_operator_reason(reason: CommunityAbortReasonV1) -> Result<(), Error> {
    match reason {
        CommunityAbortReasonV1::AuthenticatedCancellation
        | CommunityAbortReasonV1::RetiringGeneration => Ok(()),
        CommunityAbortReasonV1::ValidatedInvocationFailure
        | CommunityAbortReasonV1::AdmissionRefused
        | CommunityAbortReasonV1::ProtectedUseRefused => Err(Error::InvalidBinding),
    }
}

/// The CAU1 of the Abort (R15.1(5)): Pass, H(CAB1), no object row and
/// exactly the abort decision and the metadata `write` decision.
fn abort_evidence(
    store_incarnation: [u8; 16],
    lifecycle: &CommunityLifecycleAuthorityV1,
    record: &CommunityPassRecordV1,
    inputs: &StageInputsV1<'_>,
    abort_digest: Hash,
    view: &CommunityCurrentViewV1,
    inventory_generation: u64,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let pass_key = record.reserved.reservation.pass_key;
    let mut decision_rows = vec![
        decision_row(
            inputs.administrative.request(),
            Hash::from_bytes(inputs.administrative.authorization_ref().digest),
            inputs.administrative.leaf_grant_id(),
        ),
        decision_row(
            &inputs.write.request,
            inputs.write.decision_digest,
            inputs.write.leaf_grant_id,
        ),
    ];
    decision_rows.sort_unstable();
    CommunityAuthorityEvidenceV1::new(CommunityAuthorityEvidenceInputV1 {
        store_incarnation,
        timeline: pass_key.timeline(),
        generation: pass_key.generation(),
        operation: CommunityArtifactOperationV1::Pass(pass_key),
        input_identity: abort_digest,
        object_bindings: vec![],
        inventory_generation,
        current_premise_digest: view.digest(),
        decision_rows,
        recipient_identity_digest: community_recipient_identity_digest_v1(
            lifecycle.member_recipient(),
        ),
        clock_bound: CommunityClockBoundV1 {
            reservation_id: inputs.authenticated.reservation_id(),
            reservation_sample_micros: inputs.authenticated.at_time().as_micros(),
            decision_bound_micros: inputs.authenticated.decision_bound().as_micros(),
        },
        evidence_not_after_micros: record.reserved.generation_horizon_micros,
    })
    .map(|evidence| evidence.to_canonical_cbor())
}

/// The CAU1 decision row of `request`'s decision.
pub(super) fn decision_row(
    request: &AuthorizationRequestV1,
    decision_digest: Hash,
    leaf_grant_id: Hash,
) -> CommunityDecisionRowV1 {
    CommunityDecisionRowV1 {
        decision_digest,
        request_digest: request.binding_digest(),
        leaf_grant_id,
        authority_timeline: request.authority_timeline(),
        head_seq: request.at_position().as_u64(),
        revocation_epoch: request.revocation_epoch(),
        policy_revision: request.capability_policy_revision(),
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(super) mod tests;
