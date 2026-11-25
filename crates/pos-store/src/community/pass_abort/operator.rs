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
//!    needs, the retry lookup by `(T, reservation_operation_id)` (12 for a
//!    pass nobody reserved; 4 for a Committed pass, other bound content or
//!    another principal) and, for a first Abort, the live-call refusal (15);
//! 4. the generation (5) and head (6) fences, and the metadata horizon (13);
//! 5. the records: the CAB1, the CAV1 (whose one authority row is the abort
//!    decision's chain) and the CAU1 with the abort decision and the
//!    metadata `write` decision as its two rows (R15.1(5)), all
//!    sealed under the pass's one metadata key, which the Abort then closes;
//! 6. the writer's decision-bound check, then one commit: the pending
//!    erasure entry is replaced (an Abort registers no row), the pass moves
//!    to Aborted and the retry index and the inventory generation advance
//!    once. No producer ordinal is allocated and no CSI1 row changes.

use pos_core::community_lifecycle::{
    community_recipient_identity_digest_v1, CommunityAbortReasonV1, CommunityArtifactOperationV1,
    CommunityAuthorityEvidenceInputV1, CommunityAuthorityEvidenceV1, CommunityAuthorityViewRowV1,
    CommunityClockBoundV1, CommunityCurrentViewInputV1, CommunityCurrentViewV1,
    CommunityDecisionRowV1, CommunityKeyIntentV1, CommunityLifecycleErrorV1 as Error,
    CommunityMetadataSchemaV1, CommunityMetadataScopeInputV1, CommunityMetadataScopeV1,
    CommunityPassFrontierV1, CommunityReservationV1, CommunityScopeMembersV1,
    CommunityTrustViewRowV1,
};
use pos_core::{
    AuthorityGranteeV1, AuthorityTrustRootSealV1, AuthorizationRequestV1, Hash, TimelineId,
};
use std::collections::BTreeSet;
use zeroize::Zeroizing;

use super::super::lifecycle_authority::{
    CommunityAdministrativeOperationV1, CommunityAdministrativeRequestV1,
    CommunityAuthorityAdmissionV1, CommunityAuthorityCallV1, CommunityLifecycleAuthorityV1,
};
use super::super::memory_domain::MemoryCommunityDomainV1;
use super::super::metadata_authority::{CommunityMetadataAuthorityV1, MetadataActionV1};
use super::super::pass_record::{CommunityPassRecordV1, CommunityPassStatusV1};
use super::super::planner::key_rows;
use super::super::private_hash::private_digest;
use super::super::quarantine::{current_floor, CommunityQuarantineContextV1};
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
struct MetadataWriteV1 {
    request: AuthorizationRequestV1,
    decision_digest: Hash,
    leaf_grant_id: Hash,
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
    /// # Errors
    /// In the A5.5 order: `InvalidBinding` for a reason other than 0 or 4 or
    /// a zero identity; `EvidenceUnavailable` for every authority failure, a
    /// pass nobody reserved, an unbootstrapped domain, a pass metadata key
    /// that is missing and a writer at or after the decision bound;
    /// `Conflict` for a Committed pass, a retry with other bound content or
    /// by another principal; `OperationActive` while the pass's call is
    /// live; `StaleGeneration` and `StaleFrontier` for a moved generation or
    /// head; `EvidenceExpired` when the decision bound is after the
    /// metadata horizon; and the codec refusals.
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
            PassAbortLookupV1::Original => self
                .original_abort(key, &administrative)
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
    fn abort_metadata_write(
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
    /// original leaf grant's grantee (A5.3(6)), and the retained CAB1 must
    /// still open under the pass metadata key as the receipt's.
    fn original_abort(
        &self,
        key: (TimelineId, [u8; 16]),
        administrative: &CommunityAuthorityAdmissionV1,
    ) -> Result<CommunityPassAbortReceiptV1, Error> {
        let original = self.pass_aborts.get(&key).ok_or(Error::Conflict)?;
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

    /// Stage the CAB1, CAV1 and CAU1 of a first Abort.
    fn stage_pass_abort(
        &self,
        context: CommunityQuarantineContextV1<'_>,
        lifecycle: &CommunityLifecycleAuthorityV1,
        record: &CommunityPassRecordV1,
        inputs: &StageInputsV1<'_>,
    ) -> Result<StagedPassAbortV1, Error> {
        let metadata_horizon = context
            .binding
            .metadata_policy
            .as_input()
            .metadata_not_after_micros;
        if inputs.authenticated.decision_bound().as_micros() > metadata_horizon {
            return Err(Error::EvidenceExpired);
        }
        let key = (inputs.call.timeline, inputs.call.reservation_operation_id);
        let (anchor, selection, selection_address) = self.read_selection(context)?;
        let (generation, head) = current_floor(&selection, key.0)?;
        let reserved = &record.reserved;
        let pass_key = reserved.reservation.pass_key;
        // A Sealed pass is aborted once Seal's record carries its CPS1
        // digest (A4d); until then it cannot name the sealed result.
        if record.status == CommunityPassStatusV1::Sealed {
            return Err(Error::EvidenceUnavailable);
        }
        if generation != pass_key.generation() {
            return Err(Error::StaleGeneration);
        }
        if head != reserved.reservation.predecessor_head_digest {
            return Err(Error::StaleFrontier);
        }
        let (abort, abort_digest) = CommunityReservationV1::new(reserved.reservation)
            .map(|reservation| {
                private_digest(
                    b"PiglorOS.Community.CPR1.v1",
                    &[reservation.to_canonical_cbor().as_slice()],
                )
            })
            .and_then(|reservation_digest| {
                abort_record(AbortFieldsV1 {
                    pass_key,
                    reservation_digest,
                    sealed_result_digest: None,
                    reason: inputs.call.reason,
                    failure_evidence_digest: None,
                    quarantine_delta_digest: None,
                    evidence_not_after_micros: reserved.reservation.evidence_not_after_micros,
                })
            })?;
        let inventory_generation = CommunityStoreDomainV1::inventory_generation(self);
        let vault = self
            .keys
            .get(&reserved.metadata_key)
            .ok_or(Error::EvidenceUnavailable)?;
        let view = self.abort_view(
            context,
            lifecycle,
            record,
            inputs,
            vault.intent(),
            inventory_generation,
        )?;
        let evidence = abort_evidence(
            self.store_incarnation,
            lifecycle,
            record,
            inputs,
            abort_digest,
            &view,
            inventory_generation,
        )?;
        let scope = CommunityMetadataScopeV1::new(CommunityMetadataScopeInputV1 {
            store_incarnation: self.store_incarnation,
            metadata_anchor_timeline: anchor.0,
            metadata_anchor_generation: anchor.1,
            protection_operation_id: reserved.metadata_key,
            scope_members: CommunityScopeMembersV1::from_members(&[]),
            metadata_not_after_micros: metadata_horizon,
        })?;
        Ok(StagedPassAbortV1 {
            key,
            committed: CommittedPassAbortV1 {
                bound: inputs.bound.clone(),
                abort: abort.clone(),
                abort_digest,
                leaf_grant_id: inputs.administrative.leaf_grant_id(),
                metadata_key: reserved.metadata_key,
                records: Vec::new(),
            },
            scope,
            plaintexts: [
                (CommunityMetadataSchemaV1::Cab1, abort),
                (CommunityMetadataSchemaV1::Cav1, view.to_canonical_cbor()),
                (CommunityMetadataSchemaV1::Cau1, evidence),
            ],
            read_selection: selection_address,
            inventory_generation,
        })
    }

    /// The CAV1 of the Abort, read inside its guard (R15.1(5)): T's current
    /// selection (the initial frontier with no head ref until A5 commits a
    /// pass), the abort decision's authority row, the trust row of each
    /// Plugin a due member runs, the pass metadata key's row and the clock
    /// latch.
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
        let authority_rows = self.authority_rows(inputs)?;
        let trust_rows = self.abort_trust_rows(context, lifecycle.trust_scope(), record)?;
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
    }

    /// The administrative decision's authority row, at the head and epoch
    /// its decision read.
    ///
    /// The metadata decision's chain is not a second row: a CAV1 holds one
    /// row per authority coordinate, and two chains read at one head share
    /// it, so the metadata decision is recorded in the CAU1's decision rows
    /// only, as an initialization records it.
    fn authority_rows(
        &self,
        inputs: &StageInputsV1<'_>,
    ) -> Result<Vec<CommunityAuthorityViewRowV1>, Error> {
        let request = inputs.administrative.request();
        CommunityStoreDomainV1::authority_row(self, inputs.administrative.leaf_grant_id(), request)
            .and_then(|row| {
                Some(row)
                    .filter(|row| {
                        row.head_seq == request.at_position().as_u64()
                            && row.revocation_epoch == request.revocation_epoch()
                    })
                    .map(|row| vec![row])
                    .ok_or(Error::EvidenceUnavailable)
            })
    }

    /// One trust row per distinct Plugin of the pass's due members, read
    /// now from this domain's own registry. A CAV1 needs at least one row
    /// (R6.5(4)); a Plugin with no active release has none, and an Abort
    /// never refuses a Plugin's release for changing since the Reserve.
    fn abort_trust_rows(
        &self,
        context: CommunityQuarantineContextV1<'_>,
        scope: &str,
        record: &CommunityPassRecordV1,
    ) -> Result<Vec<CommunityTrustViewRowV1>, Error> {
        let roster = context.profile.as_input().roster;
        let plugins: BTreeSet<&str> = record
            .reserved
            .members
            .iter()
            .filter_map(|member| roster.get(member.roster_index))
            .map(|row| row.implementation().plugin_id())
            .collect();
        let policy = CommunityStoreDomainV1::plugin_trust_policy(self, scope)?;
        let utc = u64::try_from(policy.highest_trusted_utc_second().unwrap_or(0))
            .map_err(|_| Error::EvidenceUnavailable)?;
        let mut rows = Vec::with_capacity(plugins.len());
        for plugin_id in plugins {
            if let Some(active) = CommunityStoreDomainV1::active_release(self, scope, plugin_id)? {
                rows.push(CommunityTrustViewRowV1 {
                    scope: scope.to_owned(),
                    plugin_id: plugin_id.to_owned(),
                    policy_digest: Hash::from_bytes(policy.tps1_digest()),
                    policy_floor: policy.ptr1_floor().map_or(0, |(floor, _)| floor),
                    release_floor: policy.prv1_floor().map_or(0, |(floor, _)| floor),
                    highest_trusted_utc_second: utc,
                    active_manifest_digest: Hash::from_bytes(active.pmf1_digest()),
                    active_release_digest: Hash::from_bytes(active.release_digest()),
                });
            }
        }
        Ok(rows)
    }

    /// The atomic Abort commit (R15.1(8)): the inventory generation and the
    /// CSI1 the operation read are compared, the pending erasure entry is
    /// replaced (an Abort registers no row), and only then are the CAB1,
    /// CAV1 and CAU1 sealed under the pass metadata key, which closes, the
    /// retry index retained and the inventory generation advanced once.
    ///
    /// # Errors
    /// Returns `EvidenceUnavailable` when either compared value moved or the
    /// pass metadata key is missing, `InvalidBinding` when the pass holds no
    /// pending entry and `CapacityExhausted` when the key cannot seal; each
    /// leaves the pass unresolved.
    fn commit_pass_abort(
        &mut self,
        seal: &'static AuthorityTrustRootSealV1,
        mut staged: StagedPassAbortV1,
    ) -> Result<CommunityPassAbortReceiptV1, Error> {
        let current = self
            .selection
            .as_ref()
            .map(|(_, sealed)| sealed.address)
            .or_else(|| {
                self.bootstrap
                    .as_ref()
                    .map(|record| record.selection.address)
            });
        if self.inventory_generation != staged.inventory_generation
            || current != Some(staged.read_selection)
        {
            return Err(Error::EvidenceUnavailable);
        }
        let token = self.stage_abort(staged.key.0, staged.key.1, 0)?;
        staged.committed.records = self.seal_abort_records(&staged)?;
        self.apply_abort(seal, &token)?;
        self.inventory_generation += 1;
        let receipt = CommunityPassAbortReceiptV1 {
            timeline: staged.key.0,
            reservation_operation_id: staged.key.1,
            abort_digest: staged.committed.abort_digest,
            abort: staged.committed.abort.clone(),
        };
        self.pass_aborts.insert(staged.key, staged.committed);
        Ok(receipt)
    }

    /// Seal the staged records under the pass metadata key and close it:
    /// the pass is terminal, so the key never encrypts again.
    fn seal_abort_records(
        &mut self,
        staged: &StagedPassAbortV1,
    ) -> Result<Vec<SealedMetadataV1>, Error> {
        let vault = self
            .keys
            .get_mut(&staged.committed.metadata_key)
            .ok_or(Error::EvidenceUnavailable)?;
        let sealed = staged
            .plaintexts
            .iter()
            .map(|(schema, plaintext)| vault.seal(&staged.scope, *schema, plaintext))
            .collect::<Result<Vec<_>, Error>>()?;
        vault.close();
        Ok(sealed)
    }
}

/// The facts every staging step reads.
struct StageInputsV1<'a> {
    call: CommunityPassAbortCallV1<'a>,
    bound: PassAbortBoundV1,
    authenticated: &'a CommunityAuthorityCallV1,
    administrative: &'a CommunityAuthorityAdmissionV1,
    write: &'a MetadataWriteV1,
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
fn decision_row(
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
mod tests;
