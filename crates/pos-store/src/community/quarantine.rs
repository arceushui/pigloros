//! The retained-Memory pre-execution quarantine `SetReason` (#560 A4e-1;
//! ADR-129 annex "Durable quarantine", revision 8 R8.5–R8.6 and revision 9
//! R9.9 with the owner erratum of 2026-11-21 on R9.9(7)).
//!
//! A revocation detected before guest execution is a separate idempotent
//! host control operation, not a fake pass: Control `control_operation_id`,
//! with `input_identity` H(CQC1) and no `PassKey`. Its authority is the
//! installed trusted failure producer, which hands the store a sealed
//! [`CommunityPreExecutionFailureV1`]; the principal and authorization refs
//! are null. [`MemoryCommunityDomainV1::set_quarantine_reason`] runs, in
//! the A5.5 order:
//!
//! 1. the shape (3): reason 2 `Revoked` from host code 2 `ArtifactRevoked`
//!    only, a nonzero control identity and a valid CQK1;
//! 2. the one trusted-clock reservation, whose bound is the earlier of
//!    `D = t_r + 32 s` and the installed metadata owner result's expiry
//!    (R9.9(6));
//! 3. the authority (12): the metadata `write` decision (A5.2(1)) and the
//!    re-verification of the sealed failure under the guard against this
//!    domain's own Plugin trust registry, whose `evaluate_current_release`
//!    must report the member's release revoked with the claimed basis, and
//!    whose TPS1 digest must be the claimed one (R9.9(7) erratum);
//! 4. the retry lookup by `(T, control_operation_id)` (identical: the
//!    original CQO1; otherwise 4), the expected generation (5) and head
//!    (6), the first-use proof (R8.6(2)): the CQK1 must name a CMB1 of the
//!    CGA1 of T's current active generation, committed in this domain (12);
//!    the expected ledger against the domain-private quarantine index (4);
//!    and the bound against the CFO1 and quarantine horizons (13);
//! 5. the effects: an already active reason keeps its evidence and horizon
//!    and returns `AlreadyQuarantined`, persisting only its CQC1/CQO1
//!    outcome. Otherwise the CFO1 COW1 under its cohort key, the empty-scope
//!    CSB1/CPV1 and one-row CBQ1, the control batch, CAV1, CAU1 (Control,
//!    H(CQC1), the metadata `write` row), COA1, CMI1 and the CQC1/CQR1/CQO1
//!    are staged;
//! 6. the writer's bound check, then one commit: the ARD1 publication, both
//!    keys, the quarantine index and the retry index, with the inventory
//!    generation compared and advanced once. No producer ordinal is
//!    allocated and no CSI1 row changes.

mod evidence;

use pos_conformance::{PluginTrustBridgeErrorV1, PluginTrustPolicyAnchorV1};
use pos_core::community_lifecycle::{
    community_catalogue_owner_v1, community_decision_provenance_digest_v1,
    community_quarantine_reason_v1, CommunityArtifactAdmissionV1,
    CommunityDecisionProvenanceInputV1, CommunityDigestListV1, CommunityDurableProfileV1,
    CommunityGenerationAdmissionV1, CommunityLifecycleErrorV1 as Error, CommunityMemberBindingV1,
    CommunityMetadataAnchorV1, CommunityOwnerBindingV1, CommunityPassFailureInputV1,
    CommunityPassFailureV1, CommunityPluginHostErrorV1, CommunityQuarantineControlInputV1,
    CommunityQuarantineControlKindV1, CommunityQuarantineControlV1,
    CommunityQuarantineDispositionV1, CommunityQuarantineKeyV1,
    CommunityQuarantineReasonEvidenceV1, CommunityQuarantineReasonV1, CommunityQuarantineReasonsV1,
    CommunitySelectionV1, RevocationBasisV1,
};
use pos_core::trusted_clock::TrustedClockReservationV1;
use pos_core::{
    ArtifactRegistrationPersistencePortV1, AuthorityTrustRootSealV1, AuthorizationDecisionV1,
    AuthorizationRequestV1, Hash, ImplementationKeyV1, TimelineId, WallTime,
};
use pos_crypto::plugin_trust::{
    PluginTrustErrorV1, ValidatedPluginManifestProjectionV1, VerifiedPluginTrustEvidenceV1,
};
use zeroize::Zeroizing;

use super::lifecycle_authority::CommunityLifecycleAuthorityV1;
use super::memory_domain::{CommunityDomainBindingV1, MemoryCommunityDomainV1};
use super::metadata_authority::{CommunityMetadataAuthorityV1, MetadataActionV1};
use super::sealer::SealedMetadataV1;
use super::store_domain::CommunityStoreDomainV1;
use super::vault::VaultKeyV1;
#[cfg(target_os = "linux")]
use crate::plugin_trust_registry::{
    PluginTrustPolicyRegistryErrorV1, PluginTrustPolicyRegistryV1, TrustedUtcSecondV1,
};
use evidence::StagedEvidenceV1;

/// The trust evidence the store re-evaluates on its own registry
/// (R9.9(7) erratum): the same inputs `evaluate_current_release` takes.
#[derive(Clone, Copy)]
pub struct CommunityPreExecutionTrustV1<'a> {
    /// The scope's trust anchor.
    pub anchor: &'a PluginTrustPolicyAnchorV1,
    /// The signed TPS1 bytes.
    pub tps1_bytes: &'a [u8],
    /// The verified PTR1/PRV1 evidence.
    pub evidence: &'a VerifiedPluginTrustEvidenceV1,
    /// The member release's manifest projection.
    pub projection: &'a ValidatedPluginManifestProjectionV1,
    /// The trusted UTC second of the evaluation.
    pub trusted_utc: TrustedUtcSecondV1,
    /// The Tick of the evaluation.
    pub tick: u64,
}

/// The fields of one pre-execution failure (R9.9(7)).
#[derive(Clone, Copy)]
pub struct CommunityPreExecutionFailureInputV1<'a> {
    /// The execution Timeline.
    pub timeline: TimelineId,
    /// The member's admitted stable World entry.
    pub stable_entry: &'a str,
    /// The member's implementation (IMK1).
    pub implementation: &'a ImplementationKeyV1,
    /// The closed host failure the trust gate observed.
    pub host_failure: CommunityPluginHostErrorV1,
    /// The TPS1 digest the trust gate evaluated under.
    pub trust_policy_snapshot_digest: Hash,
    /// The trust evidence the store re-evaluates.
    pub trust: CommunityPreExecutionTrustV1<'a>,
}

/// A sealed pre-execution failure from the installed Runtime trust gate.
///
/// The store accepts it as trusted code only after its own re-checks
/// (R9.9(7), A5.9). Only the composition root, which holds the
/// [`AuthorityTrustRootSealV1`], hands it out:
///
/// ```compile_fail,E0061
/// use pos_store::community::{
///     CommunityPreExecutionFailureInputV1, CommunityPreExecutionFailureV1,
/// };
/// fn forge(input: CommunityPreExecutionFailureInputV1<'_>) {
///     let _ = CommunityPreExecutionFailureV1::new(input);
/// }
/// ```
pub struct CommunityPreExecutionFailureV1<'a>(CommunityPreExecutionFailureInputV1<'a>);

impl<'a> CommunityPreExecutionFailureV1<'a> {
    /// Seal the producer's failure for one `SetReason` call.
    #[must_use]
    pub const fn new(
        _seal: &'static AuthorityTrustRootSealV1,
        input: CommunityPreExecutionFailureInputV1<'a>,
    ) -> Self {
        Self(input)
    }
}

/// The installed composition of one `SetReason`. None of it comes from a
/// caller.
#[derive(Clone, Copy)]
pub struct CommunityQuarantineContextV1<'a> {
    /// The installed CDP1 the generation was initialized under.
    pub profile: &'a CommunityDurableProfileV1<'a>,
    /// The domain's installed metadata policy and CSI1 identities.
    pub binding: CommunityDomainBindingV1<'a>,
}

/// One `SetReason` caller form (A5.3(0)): the CQC1 fields without the
/// host-derived CFO1, trust snapshot, refs, bound and provenance. No API
/// accepts CFO1 or CQC1 bytes (I69).
#[derive(Clone, Copy)]
pub struct CommunitySetReasonCallV1<'a> {
    /// The sealed failure.
    pub failure: &'a CommunityPreExecutionFailureV1<'a>,
    /// The host-selected nonzero control identity, scoped to T.
    pub control_operation_id: [u8; 16],
    /// The bound reason; only `Revoked` before execution.
    pub reason: CommunityQuarantineReasonV1,
    /// The current CQR1 head, or `None` with a first-use proof.
    pub expected_ledger_digest: Option<Hash>,
    /// T's active generation.
    pub expected_generation: [u8; 16],
    /// T's current complete selected head.
    pub expected_state_head_digest: Hash,
}

/// The original outcome of one `SetReason`: its CQO1. A retry returns it
/// unchanged.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommunityQuarantineReceiptV1 {
    timeline: TimelineId,
    control_operation_id: [u8; 16],
    request_digest: Hash,
    selected_ledger_digest: Hash,
    already_quarantined: bool,
    outcome: Zeroizing<Vec<u8>>,
}

impl CommunityQuarantineReceiptV1 {
    /// The quarantine Timeline.
    #[must_use]
    pub const fn timeline(&self) -> TimelineId {
        self.timeline
    }

    /// The control identity.
    #[must_use]
    pub const fn control_operation_id(&self) -> [u8; 16] {
        self.control_operation_id
    }

    /// `H(CQC1)` of the original request.
    #[must_use]
    pub const fn request_digest(&self) -> Hash {
        self.request_digest
    }

    /// The selected CQR1: the new one, or the existing one when the reason
    /// was already active.
    #[must_use]
    pub const fn selected_ledger_digest(&self) -> Hash {
        self.selected_ledger_digest
    }

    /// `Applied` or `AlreadyQuarantined`.
    #[must_use]
    pub const fn disposition(&self) -> CommunityQuarantineDispositionV1 {
        if self.already_quarantined {
            CommunityQuarantineDispositionV1::AlreadyQuarantined
        } else {
            CommunityQuarantineDispositionV1::Applied
        }
    }

    /// The canonical CQO1.
    #[must_use]
    pub fn outcome(&self) -> &[u8] {
        &self.outcome
    }
}

/// The bound content of one `SetReason` (A5.3(5)): the CQK1 and every caller
/// field. The key `(T, control_operation_id)` fixes the rest.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct SetReasonBoundV1 {
    key: Hash,
    expected_ledger: Option<Hash>,
    reason: u8,
    host_failure: CommunityPluginHostErrorV1,
    trust_policy_snapshot_digest: Hash,
    expected_generation: [u8; 16],
    expected_head: Hash,
}

/// One CQK1's current ledger head in the domain-private quarantine index
/// (R8.6(2)), updated only in the CQR1/CQO1 transaction.
#[derive(Clone)]
pub(super) struct QuarantineLedgerV1 {
    pub(super) head: Hash,
    pub(super) ordinal: u64,
    pub(super) reasons: Vec<CommunityQuarantineReasonEvidenceV1>,
    pub(super) evidence_not_after_micros: u64,
}

/// One committed `SetReason`, retained for its retry (A5.3(5)).
pub(super) struct CommittedQuarantineControlV1 {
    pub(super) bound: SetReasonBoundV1,
    /// The generation whose catalogue owner owns the CFO1's ARD1.
    pub(super) generation: [u8; 16],
    /// The protection ID of the metadata key that sealed `records`.
    pub(super) metadata_key: [u8; 16],
    /// Every sealed metadata record; the last is the CQO1.
    pub(super) records: Vec<SealedMetadataV1>,
    /// The CFO1's COA1, absent when the reason was already active.
    pub(super) admission: Option<CommunityArtifactAdmissionV1>,
    pub(super) receipt: CommunityQuarantineReceiptV1,
}

/// The validated CMA1 anchor `(T, G)`, the current CSI1 plaintext and its
/// CNE1 address.
type SelectionReadV1 = ((TimelineId, [u8; 16]), Zeroizing<Vec<u8>>, Hash);

/// The member a `SetReason` names, found in T's current generation.
pub(super) struct MemberV1 {
    pub(super) generation: [u8; 16],
    pub(super) head: Hash,
    pub(super) member_binding_digest: Hash,
    pub(super) negotiated_tuple_digest: Hash,
    pub(super) pmf1_digest: Hash,
    pub(super) owner_binding_digest: Hash,
    pub(super) anchor: (TimelineId, [u8; 16]),
    pub(super) selection_address: Hash,
}

/// The authority of one `SetReason`: the call's reservation and bound, the
/// metadata `write` decision and the TPS1 digest read under the guard.
pub(super) struct AuthorityV1 {
    /// The reservation's CAU1 `reservation_id`.
    pub(super) reservation_id: u64,
    /// The reservation sample `t_r`.
    pub(super) sampled_at: WallTime,
    pub(super) bound: WallTime,
    pub(super) request: AuthorizationRequestV1,
    pub(super) decision: AuthorizationDecisionV1,
    /// BLAKE3 of the decision's canonical AUD1.
    pub(super) decision_digest: Hash,
    pub(super) leaf_grant_id: Hash,
    pub(super) trust_snapshot_digest: Hash,
}

/// The metadata `write` decision of one `SetReason` with the call's
/// reservation identity and bound, before the producer is re-verified.
pub(super) struct MetadataWriteV1 {
    reservation_id: u64,
    sampled_at: WallTime,
    bound: WallTime,
    request: AuthorizationRequestV1,
    decision: AuthorizationDecisionV1,
    decision_digest: Hash,
    leaf_grant_id: Hash,
}

impl MetadataWriteV1 {
    /// The authority once the producer's re-verification read
    /// `trust_snapshot_digest` under the guard.
    fn with_trust(self, trust_snapshot_digest: Hash) -> AuthorityV1 {
        AuthorityV1 {
            reservation_id: self.reservation_id,
            sampled_at: self.sampled_at,
            bound: self.bound,
            request: self.request,
            decision: self.decision,
            decision_digest: self.decision_digest,
            leaf_grant_id: self.leaf_grant_id,
            trust_snapshot_digest,
        }
    }
}

/// The facts every staging step reads.
pub(super) struct OperationV1<'c> {
    pub(super) context: CommunityQuarantineContextV1<'c>,
    pub(super) call: CommunitySetReasonCallV1<'c>,
    pub(super) key: Hash,
    pub(super) member: MemberV1,
    pub(super) authority: AuthorityV1,
    /// The CFO1 horizon: the quarantine and metadata horizons, whichever
    /// ends first.
    pub(super) failure_horizon: u64,
}

impl OperationV1<'_> {
    pub(super) const fn timeline(&self) -> TimelineId {
        self.call.failure.0.timeline
    }

    pub(super) const fn metadata_horizon(&self) -> u64 {
        self.context
            .binding
            .metadata_policy
            .as_input()
            .metadata_not_after_micros
    }
}

/// Everything one `SetReason` commits, staged before the writer.
pub(super) struct StagedSetReasonV1 {
    pub(super) key: (TimelineId, [u8; 16]),
    pub(super) committed: CommittedQuarantineControlV1,
    pub(super) keys: Vec<VaultKeyV1>,
    pub(super) evidence: Option<StagedEvidenceV1>,
    pub(super) ledger: Option<(Hash, QuarantineLedgerV1)>,
    pub(super) read_selection: Hash,
    pub(super) inventory_generation: u64,
}

/// The outcome of every step before the writer.
pub(super) enum SetReasonPreparedV1 {
    /// A retry's original receipt.
    Original(CommunityQuarantineReceiptV1),
    /// A new `SetReason`, the call's reservation and its bound.
    Staged(Box<StagedSetReasonV1>, TrustedClockReservationV1, WallTime),
}

impl MemoryCommunityDomainV1 {
    /// Record a pre-execution quarantine reason (`SetReason`), or return
    /// the original outcome of a retry.
    ///
    /// # Errors
    /// In the A5.5 order: `InvalidBinding` for a reason other than
    /// `Revoked`, a host failure other than `ArtifactRevoked`, a zero
    /// control identity, an invalid CQK1 or a profile other than the
    /// generation's; `EvidenceUnavailable` for a clock failure, a denied
    /// metadata `write`, a release the registry does not report revoked
    /// with the claimed basis, another TPS1 digest, a CQK1 with no CMB1 in
    /// T's current generation and a writer at or after the bound;
    /// `Conflict` for a retry with other bound content or a stale expected
    /// ledger; `StaleGeneration` and `StaleFrontier` for another generation
    /// or head; `EvidenceExpired` when the bound is after the CFO1 or
    /// quarantine horizon; and the codec refusals.
    pub fn set_quarantine_reason(
        &mut self,
        seal: &'static AuthorityTrustRootSealV1,
        context: CommunityQuarantineContextV1<'_>,
        lifecycle: &mut CommunityLifecycleAuthorityV1,
        metadata: &mut CommunityMetadataAuthorityV1,
        call: CommunitySetReasonCallV1<'_>,
    ) -> Result<CommunityQuarantineReceiptV1, Error> {
        match self.prepare_set_reason(seal, context, lifecycle, metadata, call)? {
            SetReasonPreparedV1::Original(receipt) => Ok(receipt),
            SetReasonPreparedV1::Staged(staged, reservation, bound) => lifecycle
                .check_control_bound(reservation, bound, self)
                .and_then(|()| self.commit_set_reason(*staged)),
        }
    }

    /// Every step before the writer.
    pub(super) fn prepare_set_reason(
        &mut self,
        seal: &'static AuthorityTrustRootSealV1,
        context: CommunityQuarantineContextV1<'_>,
        lifecycle: &mut CommunityLifecycleAuthorityV1,
        metadata: &mut CommunityMetadataAuthorityV1,
        call: CommunitySetReasonCallV1<'_>,
    ) -> Result<SetReasonPreparedV1, Error> {
        let failure = &call.failure.0;
        let key = check_shape(&call)?;
        let reservation = lifecycle.reserve_control(self)?;
        let write = self.metadata_write(context, &reservation, metadata)?;
        let bound = SetReasonBoundV1 {
            key,
            expected_ledger: call.expected_ledger_digest,
            reason: call.reason.code(),
            host_failure: failure.host_failure,
            trust_policy_snapshot_digest: failure.trust_policy_snapshot_digest,
            expected_generation: call.expected_generation,
            expected_head: call.expected_state_head_digest,
        };
        if let Some(original) = self
            .quarantine_controls
            .get(&(failure.timeline, call.control_operation_id))
        {
            return if original.bound == bound {
                self.resolve_original(original)
                    .map(SetReasonPreparedV1::Original)
            } else {
                Err(Error::Conflict)
            };
        }
        let trust_snapshot_digest = self.verify_failure(lifecycle.trust_scope(), failure)?;
        let authority = write.with_trust(trust_snapshot_digest);
        let member = self.member(context, &call)?;
        let current = self.quarantine_index.get(&key);
        if current.map(|ledger| ledger.head) != call.expected_ledger_digest {
            return Err(Error::Conflict);
        }
        let retention = context.profile.as_input().retention;
        let operation = OperationV1 {
            context,
            call,
            key,
            member,
            authority,
            failure_horizon: retention.quarantine_not_after_micros.min(
                context
                    .binding
                    .metadata_policy
                    .as_input()
                    .metadata_not_after_micros,
            ),
        };
        let bound = operation.authority.bound;
        self.stage_set_reason(seal, lifecycle, &operation)
            .map(|staged| SetReasonPreparedV1::Staged(Box::new(staged), reservation, bound))
    }

    /// Step 3, after the step-2 reservation: its bound and the metadata
    /// `write` decision, which alone admits original-outcome discovery
    /// (A5.5 step 4).
    fn metadata_write(
        &self,
        context: CommunityQuarantineContextV1<'_>,
        reservation: &TrustedClockReservationV1,
        metadata: &mut CommunityMetadataAuthorityV1,
    ) -> Result<MetadataWriteV1, Error> {
        let policy = context.binding.metadata_policy;
        let bound = reservation
            .decision_bound()
            .min(metadata.owner_expires_at());
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
                    reservation_id: reservation.reservation_seq(),
                    sampled_at: reservation.sampled_at(),
                    bound,
                    request,
                    decision_digest: Hash::from_bytes(*blake3::hash(aud.as_slice()).as_bytes()),
                    decision,
                    leaf_grant_id,
                })
            })
            .ok_or(Error::EvidenceUnavailable)
    }

    /// A retry's original outcome: its retained CQO1 must still open under
    /// its metadata key as the receipt's, and the CFO1's ARD1, when one was
    /// published, must still resolve.
    fn resolve_original(
        &self,
        original: &CommittedQuarantineControlV1,
    ) -> Result<CommunityQuarantineReceiptV1, Error> {
        let receipt = &original.receipt;
        let published = original.admission.as_ref().is_none_or(|admission| {
            community_catalogue_owner_v1(receipt.timeline, original.generation).is_ok_and(|owner| {
                matches!(
                    ArtifactRegistrationPersistencePortV1::read_artifact_registration(
                        &self.store,
                        &owner,
                        admission.as_input().registration_address,
                    ),
                    Ok(Some(_))
                )
            })
        });
        self.keys
            .get(&original.metadata_key)
            .zip(original.records.last())
            .and_then(|(key, sealed)| key.open(sealed).ok())
            .filter(|outcome| published && outcome.as_slice() == receipt.outcome())
            .map(|_| receipt.clone())
            .ok_or(Error::EvidenceUnavailable)
    }

    /// Re-run this domain's own `evaluate_current_release` on the sealed
    /// failure's trust evidence and release (R9.9(7), owner erratum of
    /// 2026-11-21). It writes nothing; a revoked release is one of the
    /// registry's own errors.
    fn evaluate_release(
        &self,
        trust: CommunityPreExecutionTrustV1<'_>,
    ) -> Result<(), PluginTrustPolicyRegistryErrorV1> {
        self.store
            .evaluate_current_release(
                trust.anchor,
                trust.tps1_bytes,
                trust.evidence,
                trust.projection,
                trust.trusted_utc,
                trust.tick,
            )
            .map(drop)
    }

    /// The R9.9(7) re-verification under the guard: the evaluated TPS1 is
    /// the one the installed trust scope retains now (so its anchor is that
    /// scope's), this domain's own registry reports the release revoked with
    /// the claimed basis, and the claimed TPS1 digest is the retained one,
    /// which it returns. The release itself is bound through its PMF1
    /// (whose field 27 is the release digest) against the member's CMB1.
    fn verify_failure(
        &self,
        scope: &str,
        failure: &CommunityPreExecutionFailureInputV1<'_>,
    ) -> Result<Hash, Error> {
        let revoked = revocation_basis(self.evaluate_release(failure.trust))
            .map(|basis| CommunityPluginHostErrorV1::ArtifactRevoked { basis });
        CommunityStoreDomainV1::plugin_trust_policy(self, scope).and_then(|policy| {
            let digest = Hash::from_bytes(policy.tps1_digest());
            if policy.tps1_bytes() == failure.trust.tps1_bytes
                && revoked == Some(failure.host_failure)
                && digest == failure.trust_policy_snapshot_digest
            {
                Ok(digest)
            } else {
                Err(Error::EvidenceUnavailable)
            }
        })
    }

    /// Step 4's premises: T's active generation and head must be the
    /// expected ones, and the CQK1 must name a CMB1 of the CGA1 of that
    /// generation, committed in this domain (R8.6(2)).
    fn member(
        &self,
        context: CommunityQuarantineContextV1<'_>,
        call: &CommunitySetReasonCallV1<'_>,
    ) -> Result<MemberV1, Error> {
        let failure = &call.failure.0;
        self.read_selection(context)
            .and_then(|(anchor, selection, selection_address)| {
                current_floor(&selection, failure.timeline).and_then(|(generation, head)| {
                    match (
                        generation == call.expected_generation,
                        head == call.expected_state_head_digest,
                    ) {
                        (false, _) => Err(Error::StaleGeneration),
                        (true, false) => Err(Error::StaleFrontier),
                        (true, true) => self.admitted_member(
                            context,
                            failure,
                            (generation, head),
                            (anchor, selection_address),
                        ),
                    }
                })
            })
    }

    /// The validated CMA1 anchor and the current CSI1 with its address.
    fn read_selection(
        &self,
        context: CommunityQuarantineContextV1<'_>,
    ) -> Result<SelectionReadV1, Error> {
        self.bootstrap
            .as_ref()
            .and_then(|record| {
                CommunityMetadataAnchorV1::from_canonical_cbor(
                    &record.anchor,
                    context.binding.metadata_policy,
                )
                .ok()
                .zip(Some(record))
            })
            .and_then(|(anchor, record)| {
                let (key, sealed) = self.selection.as_ref().map_or(
                    (record.protection_id, &record.selection),
                    |(key, sealed)| (*key, sealed),
                );
                self.keys
                    .get(&key)
                    .and_then(|key| key.open(sealed).ok())
                    .map(|selection| {
                        let anchor = anchor.as_input();
                        (
                            (anchor.anchor_timeline, anchor.anchor_generation),
                            selection,
                            sealed.address,
                        )
                    })
            })
            .ok_or(Error::EvidenceUnavailable)
    }

    /// The first-use proof: the committed initialization of T whose CGA1
    /// admits `generation`, and the roster row and sealed CMB1 the
    /// failure's entry and IMK1 name, under the generation's own CDP1. The
    /// CMB1's PMF1 must be the re-verified release's. `anchor` and
    /// `selection_address` are the CMA1 anchor and the read CSI1's address.
    fn admitted_member(
        &self,
        context: CommunityQuarantineContextV1<'_>,
        failure: &CommunityPreExecutionFailureInputV1<'_>,
        (generation, head): ([u8; 16], Hash),
        (anchor, selection_address): ((TimelineId, [u8; 16]), Hash),
    ) -> Result<MemberV1, Error> {
        let roster = context.profile.as_input().roster;
        self.initializations
            .iter()
            .filter(|((timeline, _), _)| *timeline == failure.timeline)
            .find_map(|(_, committed)| {
                self.keys
                    .get(&committed.metadata_key)
                    .filter(|key| {
                        committed
                            .records
                            .last()
                            .and_then(|sealed| key.open(sealed).ok())
                            .and_then(|bytes| {
                                CommunityGenerationAdmissionV1::from_canonical_cbor(&bytes).ok()
                            })
                            .is_some_and(|admission| admission.as_input().generation == generation)
                    })
                    .map(|key| (committed, key))
            })
            .ok_or(Error::EvidenceUnavailable)
            .and_then(|(committed, key)| {
                if committed.profile_digest == context.profile.digest() {
                    Ok((committed, key))
                } else {
                    Err(Error::InvalidBinding)
                }
            })
            .and_then(|(committed, key)| {
                roster
                    .iter()
                    .position(|row| {
                        row.stable_entry() == failure.stable_entry
                            && row.implementation() == failure.implementation
                    })
                    .and_then(|slot| {
                        let open = |index: usize| {
                            committed
                                .records
                                .get(index)
                                .and_then(|sealed| key.open(sealed).ok())
                        };
                        open(slot).zip(open(roster.len()))
                    })
                    .and_then(|(member, owner)| {
                        CommunityMemberBindingV1::from_canonical_cbor(
                            &member,
                            failure.implementation,
                        )
                        .ok()
                        .zip(CommunityOwnerBindingV1::from_canonical_cbor(&owner).ok())
                        .map(|(member, owner)| {
                            let fields = member.as_input();
                            MemberV1 {
                                generation,
                                head,
                                member_binding_digest: member.digest(),
                                negotiated_tuple_digest: fields.negotiated_tuple_digest,
                                pmf1_digest: fields.pmf1_digest,
                                owner_binding_digest: owner.digest(),
                                anchor,
                                selection_address,
                            }
                        })
                    })
                    .filter(|member| {
                        member.pmf1_digest.as_bytes() == &failure.trust.projection.pmf1_digest()
                    })
                    .ok_or(Error::EvidenceUnavailable)
            })
    }

    /// The atomic `SetReason` commit (R9.9(8)): the inventory generation and
    /// the CSI1 the operation read are compared, the CFO1 ARD1 is
    /// published, and only then are the keys, records, quarantine index and
    /// retry index retained and the inventory generation advanced once.
    ///
    /// # Errors
    /// Returns `EvidenceUnavailable` when either compared value moved, and
    /// the ARD1 publication refusal; each leaves the domain unchanged.
    pub(super) fn commit_set_reason(
        &mut self,
        staged: StagedSetReasonV1,
    ) -> Result<CommunityQuarantineReceiptV1, Error> {
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
        if let Some(evidence) = &staged.evidence {
            self.store
                .commit_community_artifact_batch(&evidence.batch)?;
        }
        for key in staged.keys {
            self.keys
                .insert(key.intent().as_input().protection_operation_id, key);
        }
        if let Some((key, ledger)) = staged.ledger {
            let before = self
                .quarantine_index
                .get(&key)
                .map_or(0, |current| current.reasons.len() as u64);
            self.count_quarantine_pairs(staged.key.0, before, ledger.reasons.len() as u64);
            self.quarantine_index.insert(key, ledger);
        }
        self.inventory_generation += 1;
        let receipt = staged.committed.receipt.clone();
        self.quarantine_controls
            .insert(staged.key, staged.committed);
        Ok(receipt)
    }
}

/// T's `(active generation, selected head)` in the CSI1 `selection`.
fn current_floor(selection: &[u8], timeline: TimelineId) -> Result<([u8; 16], Hash), Error> {
    CommunitySelectionV1::from_canonical_cbor(selection)
        .ok()
        .and_then(|current| {
            current
                .as_input()
                .timeline_floors
                .iter()
                .flatten()
                .find(|row| row.timeline == timeline)
                .and_then(|row| row.active_generation.zip(row.selected_head))
        })
        .ok_or(Error::EvidenceUnavailable)
}

/// Step 1: reason 2 `Revoked` from host code 2 `ArtifactRevoked` only (the
/// annex mapping and the pre-execution class), a nonzero control identity
/// and a valid CQK1, whose digest is returned.
fn check_shape(call: &CommunitySetReasonCallV1<'_>) -> Result<Hash, Error> {
    let failure = &call.failure.0;
    if call.reason != CommunityQuarantineReasonV1::Revoked
        || community_quarantine_reason_v1(failure.host_failure) != Some(call.reason)
        || call.control_operation_id == [0; 16]
    {
        return Err(Error::InvalidBinding);
    }
    CommunityQuarantineKeyV1::new(
        failure.timeline,
        failure.stable_entry,
        failure.implementation,
    )
    .map(|key| key.digest())
}

/// The revocation basis a registry evaluation reports, or `None` when it
/// reports none (R9.9(7) erratum).
const fn revocation_basis(
    evaluation: Result<(), PluginTrustPolicyRegistryErrorV1>,
) -> Option<RevocationBasisV1> {
    match evaluation {
        Err(PluginTrustPolicyRegistryErrorV1::Trust(PluginTrustErrorV1::ArtifactRevoked)) => {
            Some(RevocationBasisV1::Artifact)
        }
        Err(PluginTrustPolicyRegistryErrorV1::Trust(PluginTrustErrorV1::PublisherKeyRevoked)) => {
            Some(RevocationBasisV1::PublisherKey)
        }
        Err(PluginTrustPolicyRegistryErrorV1::Bridge(
            PluginTrustBridgeErrorV1::TpsArtifactDenied,
        )) => Some(RevocationBasisV1::OperatorDenial),
        _ => None,
    }
}

/// The pre-execution CFO1 (R8.5(3)): no `PassKey`, no CFI1, the host failure
/// and the R8.5(1) provenance with null CPK1 and CIN1, under `horizon`.
pub(super) fn failure_record(
    member_binding_digest: Hash,
    host_failure: CommunityPluginHostErrorV1,
    trust_snapshot_digest: Hash,
    horizon: u64,
) -> Result<(Zeroizing<Vec<u8>>, Hash, Hash), Error> {
    let provenance = community_decision_provenance_digest_v1(CommunityDecisionProvenanceInputV1 {
        pass_key: None,
        member_binding_digest,
        prepared_invocation_digest: None,
        host_failure: Some(host_failure),
        trust_snapshot_digest,
    });
    CommunityPassFailureV1::new(CommunityPassFailureInputV1 {
        pass_key: None,
        invocation_evidence_digests: CommunityDigestListV1::from_digests(&[]),
        host_failure,
        host_decision_provenance_digest: provenance,
        evidence_not_after_micros: horizon,
    })
    .map(|failure| (failure.to_canonical_cbor(), failure.digest(), provenance))
}

/// The CQC1 of `operation` binding the CFO1 `failure_digest`.
pub(super) fn control_request(
    operation: &OperationV1<'_>,
    failure_digest: Hash,
    provenance: Hash,
) -> Result<(Zeroizing<Vec<u8>>, Hash), Error> {
    let failure = &operation.call.failure.0;
    let reasons = [CommunityQuarantineReasonEvidenceV1 {
        reason: operation.call.reason,
        failure_evidence_digest: failure_digest,
    }];
    CommunityQuarantineKeyV1::new(
        failure.timeline,
        failure.stable_entry,
        failure.implementation,
    )
    .and_then(|key| {
        CommunityQuarantineControlV1::new(CommunityQuarantineControlInputV1 {
            control_operation_id: operation.call.control_operation_id,
            key,
            expected_ledger_digest: operation.call.expected_ledger_digest,
            operation: CommunityQuarantineControlKindV1::SetReason,
            bound_reasons: CommunityQuarantineReasonsV1::from_reasons(&reasons),
            trust_snapshot_digest: operation.authority.trust_snapshot_digest,
            expected_generation: operation.member.generation,
            expected_state_head_digest: operation.member.head,
            principal_ref: None,
            authorization_ref: None,
            authorization_not_after_micros: operation.authority.bound.as_micros(),
            host_decision_provenance_digest: provenance,
        })
        .map(|request| (request.to_canonical_cbor(), request.digest()))
    })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
