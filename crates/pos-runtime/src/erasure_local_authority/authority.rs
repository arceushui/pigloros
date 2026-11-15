//! `LocalErasureAuthorityV1`: the verify-only single-host erasure authority
//! (ADR-136 §5).
//!
//! The authority is stateless. Each decision is a pure function of the
//! verified bundle, the composition inputs and the host-built view. It
//! holds no signing key and no write capability.

use pos_core::{
    local_erasure_body_digest_v1, local_erasure_id_v1, local_erasure_request_v1,
    local_erasure_requester_v1, local_erasure_subject_v1, CapabilityGrantV1, EntityId,
    ErasureAcknowledgementProvenanceV1, ErasureAdministrativeResolutionV1,
    ErasureAtomicFreezeResultV1, ErasureAttemptQuotaReservationV1, ErasureAuthorizationDecisionV1,
    ErasureCorrectionProvenanceV1, ErasureDestructionCommandV1, ErasureErrorV1,
    ErasureForkAdmissionInputV1, ErasureForkScopeRequirementV1, ErasureFreezeAdmissionEvidenceV1,
    ErasureFreezeAuthorizationEvidenceV1, ErasureReceiptInputV1, ErasureReferenceV1,
    ErasureRequestV1, ErasureRetryAdmissionV1, ErasureScopeExtensionV1, ErasureStateTransitionV1,
    ErasureVerifiedTopologyObservationV1, Hash, LocalErasureAuthorizationV1, LocalErasureBundleV1,
    LocalErasureIdempotencyV1, LocalErasureRejectionV1, LocalErasureSelectorV1,
    PersistedAuthorityV1, TimelineId, TimelineMeta, LOCAL_ERASURE_ATTEMPT_WINDOW_V1,
};

use super::{LOCAL_ERASURE_POLICY_REFERENCE_V1, LOCAL_ERASURE_STORE_REQUEST_RESERVE_V1};
use crate::erasure_host::{
    local_principal_reference, local_subject_admission, LOCAL_ERASURE_REQUEST_OPERATION,
};
use crate::{ErasureAuthorityReadViewV1, ErasureCoordinatorAuthorityV1};

/// The grant resource of the `erasure.request` operation (ADR-136 §3).
const REQUEST_RESOURCE: &str = "erasure";

/// The single-host Local/Air-Gapped erasure authority over one verified
/// bundle.
pub(super) struct LocalErasureAuthorityV1 {
    pub(super) bundle: LocalErasureBundleV1,
    /// The installed TPS1 `offline_valid_through`, in Unix seconds (UTC).
    pub(super) trust_expiry: u64,
    /// The clock new admissions are checked against, in Unix seconds (UTC).
    pub(super) clock: fn() -> u64,
    /// The Local Principal root grant (owner decision Q2).
    pub(super) principal_grant: Hash,
    /// The authority Timeline the root grant is issued on.
    pub(super) authority_timeline: TimelineId,
}

/// The Local Principal as its recorded root grant chain states it.
struct LocalPrincipalV1 {
    authority: PersistedAuthorityV1,
    grant: CapabilityGrantV1,
    principal_ref: ErasureReferenceV1,
}

impl LocalPrincipalV1 {
    /// Whether the root grant names `erasure.request` and lets the Principal
    /// act as `actor`.
    fn grants_request(&self, actor: EntityId) -> bool {
        let scope = self.grant.scope();
        scope
            .resources()
            .iter()
            .any(|resource| resource == REQUEST_RESOURCE)
            && scope.actor_entity_ids().contains(&actor)
    }

    /// Whether the root-grant chain records a revocation fenced at or before
    /// `position`.
    fn revoked_at_or_before(&self, position: u64) -> bool {
        self.authority
            .revocations()
            .iter()
            .any(|revocation| revocation.fence_position().as_u64() <= position)
    }
}

impl LocalErasureAuthorityV1 {
    /// New admissions close once the installed TPS1 or the bundle has
    /// expired, when `now > expiry`; a bundle `expiry` of 0 never expires
    /// (owner decision Q3). Expiry never changes a committed outcome.
    fn admits_new_work(&self) -> Result<(), ErasureErrorV1> {
        let now = (self.clock)();
        (now <= self.trust_expiry && (self.bundle.expiry == 0 || now <= self.bundle.expiry))
            .then_some(())
            .ok_or(ErasureErrorV1::TrustSnapshotInvalid)
    }

    /// The recorded root grant chain, which must be issued on the composed
    /// authority Timeline under the bundle's registry digest. A root grant is
    /// self-issued, so its grantor is the Principal itself.
    fn principal(
        &self,
        view: &dyn ErasureAuthorityReadViewV1,
    ) -> Result<LocalPrincipalV1, ErasureErrorV1> {
        view.local_principal_authority(self.principal_grant)
            .and_then(|authority| {
                authority
                    .chain()
                    .grants()
                    .last()
                    .cloned()
                    .map(|grant| (authority, grant))
            })
            .filter(|(_, grant)| {
                grant.issuance_timeline() == self.authority_timeline
                    && *grant.authority_registry_digest().as_bytes()
                        == self.bundle.authority_registry_digest.digest()
            })
            .and_then(|(authority, grant)| {
                local_principal_reference(grant.grantor())
                    .ok()
                    .map(|principal_ref| LocalPrincipalV1 {
                        authority,
                        grant,
                        principal_ref,
                    })
            })
            .ok_or(ErasureErrorV1::Unauthorized)
    }

    /// Recompute the ERAZ1 that `request` names against the root grant
    /// chain. A fresh submission binds the chain's current head and
    /// revocation epoch; an admitted request keeps its bound position, and a
    /// later revocation never invalidates it.
    fn verified_authorization(
        &self,
        view: &dyn ErasureAuthorityReadViewV1,
        request: &ErasureRequestV1,
        fresh: bool,
    ) -> Result<(LocalPrincipalV1, LocalErasureAuthorizationV1), ErasureErrorV1> {
        self.principal(view).and_then(|principal| {
            view.retained_object(request.authorization())
                .and_then(|bytes| LocalErasureAuthorizationV1::from_canonical_cbor(&bytes).ok())
                .filter(|authorization| {
                    authorization.principal_ref == principal.principal_ref
                        && authorization.operation == LOCAL_ERASURE_REQUEST_OPERATION
                        && authorization.authority_registry_digest
                            == self.bundle.authority_registry_digest
                        && authorization.authority_chain == self.authority_timeline
                        && authorization.erq1_request == request.reference()
                        && principal.grants_request(authorization.actor_entity)
                        && !principal.revoked_at_or_before(authorization.chain_head_position)
                        && (!fresh
                            || (authorization.chain_head_position
                                == principal.authority.head_position().as_u64()
                                && authorization.revocation_epoch
                                    == principal.authority.revocation_epoch()))
                })
                .map(|authorization| (principal, authorization))
                .ok_or(ErasureErrorV1::Unauthorized)
        })
    }

    /// Whether ERQ1 is exactly the request the host derives for this
    /// Principal, actor and ELIDEM1 (ADR-136 §4): subject, ELSEL1 selector,
    /// requester, compiled policy, ELBODY1 body, `erasure_id` and positions.
    fn binds_request(
        request: &ErasureRequestV1,
        principal_ref: ErasureReferenceV1,
        actor: EntityId,
        idempotency: &LocalErasureIdempotencyV1,
    ) -> bool {
        local_erasure_subject_v1(principal_ref, actor).is_ok_and(|subject| {
            request.subject() == subject
                && LocalErasureSelectorV1 { subject }
                    .reference()
                    .is_ok_and(|selector| request.selectors() == [selector])
        }) && local_erasure_requester_v1(principal_ref)
            .is_ok_and(|requester| request.requester() == requester)
            && request.policy() == LOCAL_ERASURE_POLICY_REFERENCE_V1
            && local_erasure_body_digest_v1(request.scope())
                .is_ok_and(|body| idempotency.body_digest == body)
            && local_erasure_id_v1(principal_ref, actor, idempotency.idempotency_key_digest)
                .and_then(local_erasure_request_v1)
                .is_ok_and(|reference| request.reference() == reference)
            && request.request_position() == 0
            && request.horizon_position() == LOCAL_ERASURE_ATTEMPT_WINDOW_V1
    }
}

impl ErasureCoordinatorAuthorityV1 for LocalErasureAuthorityV1 {
    fn validate_freeze_authorization_with_view(
        &self,
        _view: &dyn ErasureAuthorityReadViewV1,
        _admission: &ErasureFreezeAdmissionEvidenceV1,
        _authorization: &ErasureFreezeAuthorizationEvidenceV1,
    ) -> Result<(), ErasureErrorV1> {
        Err(ErasureErrorV1::ProvenanceMissing)
    }

    fn validate_scope_extension_with_view(
        &self,
        _view: &dyn ErasureAuthorityReadViewV1,
        _extension: &ErasureScopeExtensionV1,
    ) -> Result<(), ErasureErrorV1> {
        Err(ErasureErrorV1::ProvenanceMissing)
    }

    /// Administrative resolution is not served in v1 (owner decision Q4).
    fn validate_administrative_resolution_with_view(
        &self,
        _view: &dyn ErasureAuthorityReadViewV1,
        _resolution: &ErasureAdministrativeResolutionV1,
    ) -> Result<(), ErasureErrorV1> {
        Err(ErasureErrorV1::PolicyConflict)
    }

    /// Before freeze every Timeline is unaffected. Core refuses this
    /// observation for a request with a committed scope, which must bind its
    /// ERSC1 Timelines.
    fn verified_topology_observation(
        &self,
        view: &dyn ErasureAuthorityReadViewV1,
        _request: ErasureReferenceV1,
        manifest_digest: ErasureReferenceV1,
    ) -> Result<Option<ErasureVerifiedTopologyObservationV1>, ErasureErrorV1> {
        Ok(Some(ErasureVerifiedTopologyObservationV1::new(
            manifest_digest,
            Vec::new(),
            view.topology().to_vec(),
        )))
    }

    fn verified_topology_observation_for_candidate(
        &self,
        view: &dyn ErasureAuthorityReadViewV1,
        _request: ErasureReferenceV1,
        manifest_digest: ErasureReferenceV1,
        candidate: &TimelineMeta,
    ) -> Result<Option<ErasureVerifiedTopologyObservationV1>, ErasureErrorV1> {
        let mut unaffected = view.topology().to_vec();
        unaffected.push(candidate.id);
        unaffected.sort_unstable();
        Ok(Some(ErasureVerifiedTopologyObservationV1::new(
            manifest_digest,
            Vec::new(),
            unaffected,
        )))
    }

    /// Recompute ERAZ1, ELSEL1, ELIDEM1 and the requester, then run the
    /// per-subject admission checks, so a root calling the plain
    /// `submit_erasure_request` cannot bypass them.
    fn authenticate(
        &self,
        view: &dyn ErasureAuthorityReadViewV1,
        request: &ErasureRequestV1,
    ) -> Result<(), ErasureErrorV1> {
        self.admits_new_work()
            .and_then(|()| self.verified_authorization(view, request, true))
            .and_then(|(principal, authorization)| {
                view.retained_object(request.provenance())
                    .and_then(|bytes| LocalErasureIdempotencyV1::from_canonical_cbor(&bytes).ok())
                    .filter(|idempotency| {
                        Self::binds_request(
                            request,
                            principal.principal_ref,
                            authorization.actor_entity,
                            idempotency,
                        )
                    })
                    .ok_or(ErasureErrorV1::PolicyConflict)
                    .and_then(|_| {
                        local_subject_admission(
                            view.verified_requests().into_iter(),
                            request.subject(),
                            (
                                view.maximum_requests(),
                                LOCAL_ERASURE_STORE_REQUEST_RESERVE_V1,
                                principal.grant.scope().actor_entity_ids().len(),
                            ),
                        )
                        .map_err(|_| ErasureErrorV1::PolicyConflict)
                    })
            })
    }

    /// An authorization must name the request's own ERAZ1, which must still
    /// verify at its bound position; an authorize-stage rejection must name
    /// a retained ELREJ1 of the request.
    fn admit_authorization(
        &self,
        view: &dyn ErasureAuthorityReadViewV1,
        request: ErasureReferenceV1,
        provenance: ErasureReferenceV1,
        decision: ErasureAuthorizationDecisionV1,
    ) -> Result<(), ErasureErrorV1> {
        match decision {
            ErasureAuthorizationDecisionV1::Authorized => self
                .admits_new_work()
                .and_then(|()| {
                    view.verified_request(request)
                        .map(|state| state.request().clone())
                        .filter(|erq1| erq1.authorization() == provenance)
                        .ok_or(ErasureErrorV1::PolicyConflict)
                })
                .and_then(|erq1| self.verified_authorization(view, &erq1, false).map(drop)),
            ErasureAuthorizationDecisionV1::Rejected => view
                .retained_object(provenance)
                .and_then(|bytes| LocalErasureRejectionV1::from_canonical_cbor(&bytes).ok())
                .filter(|rejection| rejection.request == request)
                .map(drop)
                .ok_or(ErasureErrorV1::PolicyConflict),
        }
    }

    /// Corrected submission is not served in v1 (ADR-136 Q14).
    fn admit_corrected_submission(
        &self,
        _view: &dyn ErasureAuthorityReadViewV1,
        _request: &ErasureRequestV1,
        _correction: &ErasureCorrectionProvenanceV1,
    ) -> Result<(), ErasureErrorV1> {
        Err(ErasureErrorV1::PolicyConflict)
    }

    fn admit_atomic_freeze(
        &self,
        _view: &dyn ErasureAuthorityReadViewV1,
        _request: ErasureReferenceV1,
        _requested: &ErasureStateTransitionV1,
    ) -> Result<ErasureAtomicFreezeResultV1, ErasureErrorV1> {
        Err(ErasureErrorV1::ProvenanceMissing)
    }

    fn admit_scope_extension(
        &self,
        _view: &dyn ErasureAuthorityReadViewV1,
        _extension: &ErasureScopeExtensionV1,
    ) -> Result<(), ErasureErrorV1> {
        Err(ErasureErrorV1::ProvenanceMissing)
    }

    fn admit_fork_scope_extension(
        &self,
        _view: &dyn ErasureAuthorityReadViewV1,
        _extension: &ErasureScopeExtensionV1,
        _input: &ErasureForkAdmissionInputV1,
    ) -> Result<(), ErasureErrorV1> {
        Err(ErasureErrorV1::ProvenanceMissing)
    }

    fn resolve_fork_child_scope(
        &self,
        _view: &dyn ErasureAuthorityReadViewV1,
        _parent: TimelineId,
        _child: &TimelineMeta,
    ) -> Result<ErasureReferenceV1, ErasureErrorV1> {
        Err(ErasureErrorV1::ProvenanceMissing)
    }

    fn resolve_fork_scope_extension(
        &self,
        _view: &dyn ErasureAuthorityReadViewV1,
        _requirement: ErasureForkScopeRequirementV1,
        _input: &ErasureForkAdmissionInputV1,
    ) -> Result<ErasureScopeExtensionV1, ErasureErrorV1> {
        Err(ErasureErrorV1::ProvenanceMissing)
    }

    /// Administrative resolution is not served in v1 (owner decision Q4).
    fn admit_administrative_resolution(
        &self,
        _view: &dyn ErasureAuthorityReadViewV1,
        _resolution: &ErasureAdministrativeResolutionV1,
    ) -> Result<(), ErasureErrorV1> {
        Err(ErasureErrorV1::PolicyConflict)
    }

    /// Every command must go to an owner the bundle names; no side effect
    /// (owner decision Q4: otherwise `ScopeInvalid`).
    fn dispatch_destruction(
        &self,
        _view: &dyn ErasureAuthorityReadViewV1,
        _request: ErasureReferenceV1,
        commands: &[ErasureDestructionCommandV1],
    ) -> Result<(), ErasureErrorV1> {
        commands
            .iter()
            .all(|command| {
                self.bundle
                    .owners
                    .iter()
                    .any(|owner| owner.owner_ref == command.owner)
            })
            .then_some(())
            .ok_or(ErasureErrorV1::ScopeInvalid)
    }

    fn admit_attempt(
        &self,
        _view: &dyn ErasureAuthorityReadViewV1,
        _admission: &ErasureRetryAdmissionV1,
    ) -> Result<ErasureAttemptQuotaReservationV1, ErasureErrorV1> {
        Err(ErasureErrorV1::ProvenanceMissing)
    }

    fn admit_acknowledgement(
        &self,
        _view: &dyn ErasureAuthorityReadViewV1,
        _acknowledgement: &ErasureAcknowledgementProvenanceV1,
    ) -> Result<(), ErasureErrorV1> {
        Err(ErasureErrorV1::ProvenanceMissing)
    }

    fn admit_receipt(
        &self,
        _view: &dyn ErasureAuthorityReadViewV1,
        _input: &ErasureReceiptInputV1,
    ) -> Result<(), ErasureErrorV1> {
        Err(ErasureErrorV1::ProvenanceMissing)
    }
}
