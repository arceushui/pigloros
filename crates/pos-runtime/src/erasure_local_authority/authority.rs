//! `LocalErasureAuthorityV1`: the verify-only single-host erasure authority
//! (ADR-136 §5).
//!
//! The authority is stateless. Each decision is a pure function of the
//! verified bundle, the composition inputs and the host-built view. It
//! holds no signing key and no write capability.

use pos_core::{
    local_erasure_body_digest_v1, local_erasure_fork_admission_v1, local_erasure_fork_scope_v1,
    local_erasure_id_v1, local_erasure_request_v1, local_erasure_requester_v1,
    local_erasure_subject_v1, CapabilityGrantV1, EntityId, ErasureAcknowledgementProvenanceV1,
    ErasureAdministrativeResolutionV1, ErasureAtomicFreezeResultV1,
    ErasureAttemptQuotaReservationV1, ErasureAuthorizationDecisionV1,
    ErasureCorrectionProvenanceV1, ErasureDestructionCommandV1, ErasureErrorV1,
    ErasureForkAdmissionInputV1, ErasureForkScopeRequirementV1, ErasureFreezeAdmissionEvidenceV1,
    ErasureFreezeAuthorizationEvidenceV1, ErasureLifecycleV1, ErasureReceiptInputV1,
    ErasureReceiptV1, ErasureReferenceV1, ErasureRequestV1, ErasureRetryAdmissionV1,
    ErasureScopeExtensionInputV1, ErasureScopeExtensionV1, ErasureScopeV1,
    ErasureStateTransitionV1, ErasureVerifiedStateV1, ErasureVerifiedTopologyObservationV1, Hash,
    LocalErasureAuthorizationV1, LocalErasureBundleV1, LocalErasureIdempotencyV1,
    LocalErasureRejectionV1, LocalErasureSelectorV1, PersistedAuthorityV1, TimelineId,
    TimelineMeta, LOCAL_ERASURE_ATTEMPT_WINDOW_V1,
};

use super::freeze::{extension_admitted, observation, ShortfallV1, LOCAL_FREEZE_POSITION};
use super::{LOCAL_ERASURE_POLICY_REFERENCE_V1, LOCAL_ERASURE_STORE_REQUEST_RESERVE_V1};
use crate::erasure_host::{
    local_principal_reference, local_subject_admission, LocalErasurePreparationV1,
    LOCAL_ERASURE_REQUEST_OPERATION,
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
    /// The installed TPS1 `revoked_key_ids`: a bundle whose root or signer
    /// it names can never sign again (ADR-136 §5, *Compromise*).
    pub(super) revoked_key_ids: Vec<String>,
    /// The clock new admissions are checked against, in Unix seconds (UTC).
    pub(super) clock: fn() -> u64,
    /// The Local Principal root grant (owner decision Q2).
    pub(super) principal_grant: Hash,
    /// The authority Timeline the root grant is issued on.
    pub(super) authority_timeline: TimelineId,
}

/// The Local Principal as its recorded root grant chain states it.
pub(super) struct LocalPrincipalV1 {
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
    pub(super) fn verified_authorization(
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

impl LocalErasureAuthorityV1 {
    /// The parent the view records for an extension's child Timeline.
    fn recorded_parent(
        view: &dyn ErasureAuthorityReadViewV1,
        extension: &ErasureScopeExtensionV1,
    ) -> Option<TimelineId> {
        view.timeline_meta(extension.child_timeline())
            .and_then(|row| row.fork_point)
            .map(|(parent, _)| parent)
    }
}

impl LocalErasurePreparationV1 for LocalErasureAuthorityV1 {
    fn closure_fits(
        &self,
        view: &dyn ErasureAuthorityReadViewV1,
        actor: EntityId,
        scope: ErasureScopeV1,
    ) -> Result<bool, ErasureErrorV1> {
        Self::closure_fits(self, view, actor, scope)
    }

    fn prepare_freeze(
        &self,
        view: &dyn ErasureAuthorityReadViewV1,
        request: ErasureReferenceV1,
    ) -> Result<(ErasureReferenceV1, Vec<Vec<u8>>), ErasureErrorV1> {
        self.admits_new_work()
            .and_then(|()| {
                self.freeze_draft(view, request)
                    .map_err(ErasureErrorV1::from)
            })
            .map(|draft| (draft.body_digest, draft.retained))
    }

    fn holds_subject(
        &self,
        view: &dyn ErasureAuthorityReadViewV1,
        state: &ErasureVerifiedStateV1,
    ) -> bool {
        self.subject_held_by(view, state)
    }
}

impl ErasureCoordinatorAuthorityV1 for LocalErasureAuthorityV1 {
    /// Committed freeze evidence must be a purpose-0 ELS1 over its exact
    /// ERFA1 body by the signer of the bundle it pins, the retained one
    /// after a rotation.
    fn validate_freeze_authorization_with_view(
        &self,
        view: &dyn ErasureAuthorityReadViewV1,
        admission: &ErasureFreezeAdmissionEvidenceV1,
        authorization: &ErasureFreezeAuthorizationEvidenceV1,
    ) -> Result<(), ErasureErrorV1> {
        self.verified_freeze_evidence(view, admission, authorization)
    }

    /// A recovered ERSE1 must recompute from its child's recorded
    /// `fork_point` (decision 4A).
    fn validate_scope_extension_with_view(
        &self,
        view: &dyn ErasureAuthorityReadViewV1,
        extension: &ErasureScopeExtensionV1,
    ) -> Result<(), ErasureErrorV1> {
        extension_admitted(extension, Self::recorded_parent(view, extension))
    }

    /// Administrative resolution is not served in v1 (owner decision Q4).
    fn validate_administrative_resolution_with_view(
        &self,
        _view: &dyn ErasureAuthorityReadViewV1,
        _resolution: &ErasureAdministrativeResolutionV1,
    ) -> Result<(), ErasureErrorV1> {
        Err(ErasureErrorV1::PolicyConflict)
    }

    /// A recovered ERRA1 must still be the attempt ADR-136 §5 derives for
    /// its request, pinning a bundle that resolves, the retained one after
    /// a rotation. The admission-time fences (expiry, the current bundle,
    /// the subject fence) are not re-run.
    fn validate_attempt_with_view(
        &self,
        view: &dyn ErasureAuthorityReadViewV1,
        request: &ErasureRequestV1,
        admission: &ErasureRetryAdmissionV1,
    ) -> Result<(), ErasureErrorV1> {
        self.attempt_verified(view, request, admission)
    }

    /// A recovered owner acknowledgement must carry a purpose-1 ELS1 over
    /// its binding ELO1 by the signer of the bundle it pins, the retained
    /// one after a rotation or a revocation.
    fn validate_acknowledgement_with_view(
        &self,
        view: &dyn ErasureAuthorityReadViewV1,
        acknowledgement: &ErasureAcknowledgementProvenanceV1,
    ) -> Result<(), ErasureErrorV1> {
        self.acknowledgement_verified(view, acknowledgement)
    }

    /// A recovered receipt must issue at its §6 position under a purpose-2
    /// ELS1 over its ERCB1 by the signer of the bundle its attempt pins,
    /// the retained one after a rotation or a revocation.
    fn validate_receipt_with_view(
        &self,
        view: &dyn ErasureAuthorityReadViewV1,
        attempt: &ErasureRetryAdmissionV1,
        receipt: &ErasureReceiptV1,
    ) -> Result<(), ErasureErrorV1> {
        self.receipt_verified(view, attempt, receipt)
    }

    /// Bind every ERSC1 Timeline to the subject and every ERSE1 child to
    /// its Fork scope; every other Timeline is unaffected, so before freeze
    /// all of them are. Core checks the partition against the recovered
    /// record and the adapter topology.
    fn verified_topology_observation(
        &self,
        view: &dyn ErasureAuthorityReadViewV1,
        request: ErasureReferenceV1,
        manifest_digest: ErasureReferenceV1,
    ) -> Result<Option<ErasureVerifiedTopologyObservationV1>, ErasureErrorV1> {
        observation(view, request, manifest_digest, None).map(Some)
    }

    fn verified_topology_observation_for_candidate(
        &self,
        view: &dyn ErasureAuthorityReadViewV1,
        request: ErasureReferenceV1,
        manifest_digest: ErasureReferenceV1,
        candidate: &TimelineMeta,
    ) -> Result<Option<ErasureVerifiedTopologyObservationV1>, ErasureErrorV1> {
        observation(view, request, manifest_digest, Some(candidate.id)).map(Some)
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
                            |state| self.subject_held_by(view, state),
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

    /// Recompute the closure, ERSC1, EROS1 and ERFA1 from the view under
    /// the compiled ELP1 and the bundle (ADR-136 §5). The freeze must name
    /// `AccessFrozen` at position 1, and its provenance must name the
    /// retained purpose-0 ELS1 over the ERFA1 body. A bound overflow, and an
    /// eligible cell without an ELP1 row, commit `Rejected(ScopeInvalid)`
    /// and need no signature.
    fn admit_atomic_freeze(
        &self,
        view: &dyn ErasureAuthorityReadViewV1,
        request: ErasureReferenceV1,
        requested: &ErasureStateTransitionV1,
    ) -> Result<ErasureAtomicFreezeResultV1, ErasureErrorV1> {
        self.admits_new_work()
            .and_then(|()| {
                (requested.lifecycle == ErasureLifecycleV1::AccessFrozen
                    && requested.freeze_position == Some(LOCAL_FREEZE_POSITION))
                .then_some(())
                .ok_or(ErasureErrorV1::PolicyConflict)
            })
            .and_then(|()| {
                self.freeze_draft(view, request)
                    .map(Some)
                    .or_else(ShortfallV1::resolved)
            })
            .and_then(|draft| {
                draft.map_or_else(
                    || {
                        Self::freeze_refusal(view, request)
                            .map(ErasureAtomicFreezeResultV1::Rejected)
                    },
                    |draft| {
                        self.signed_admission(view, draft, requested.provenance)
                            .map(|admission| {
                                ErasureAtomicFreezeResultV1::Admitted(Box::new(admission))
                            })
                    },
                )
            })
    }

    /// A Fork scope extension outside the Fork admission path is admitted
    /// exactly as recovery validates it.
    fn admit_scope_extension(
        &self,
        view: &dyn ErasureAuthorityReadViewV1,
        extension: &ErasureScopeExtensionV1,
    ) -> Result<(), ErasureErrorV1> {
        extension_admitted(extension, Self::recorded_parent(view, extension))
    }

    /// The ERSE1 of an identified Fork must name the child the host
    /// allocated, its `ELFS1` scope and the `ELFX1` provenance of its
    /// parent.
    fn admit_fork_scope_extension(
        &self,
        _view: &dyn ErasureAuthorityReadViewV1,
        extension: &ErasureScopeExtensionV1,
        input: &ErasureForkAdmissionInputV1,
    ) -> Result<(), ErasureErrorV1> {
        (extension.child_timeline() == input.child.id && extension.fork() == input.child_scope)
            .then_some(())
            .ok_or(ErasureErrorV1::ProvenanceMissing)
            .and_then(|()| {
                extension_admitted(extension, input.child.fork_point.map(|(parent, _)| parent))
            })
    }

    /// A Fork child's scope is `ELFS1(child)`: request-independent and
    /// unique per child (decision 4A). The child must be a Fork of `parent`.
    fn resolve_fork_child_scope(
        &self,
        _view: &dyn ErasureAuthorityReadViewV1,
        parent: TimelineId,
        child: &TimelineMeta,
    ) -> Result<ErasureReferenceV1, ErasureErrorV1> {
        (child.fork_point.map(|(fork_parent, _)| fork_parent) == Some(parent))
            .then_some(child.id)
            .ok_or(ErasureErrorV1::ProvenanceMissing)
            .and_then(local_erasure_fork_scope_v1)
    }

    /// The ERSE1 a Fork of an affected parent appends: the child's `ELFS1`
    /// scope and the pure `ELFX1` admission provenance over the request,
    /// parent, child and lineage rule. No key is needed.
    fn resolve_fork_scope_extension(
        &self,
        _view: &dyn ErasureAuthorityReadViewV1,
        requirement: ErasureForkScopeRequirementV1,
        input: &ErasureForkAdmissionInputV1,
    ) -> Result<ErasureScopeExtensionV1, ErasureErrorV1> {
        input
            .child
            .fork_point
            .ok_or(ErasureErrorV1::ProvenanceMissing)
            .and_then(|(parent, _)| {
                local_erasure_fork_admission_v1(
                    requirement.request(),
                    parent,
                    input.child.id,
                    requirement.lineage_rule(),
                )
            })
            .and_then(|admission_provenance| {
                ErasureScopeExtensionV1::new(ErasureScopeExtensionInputV1 {
                    request: requirement.request(),
                    scope_commitment: requirement.scope_commitment(),
                    fork: input.child_scope,
                    child_timeline: input.child.id,
                    lineage_rule: requirement.lineage_rule(),
                    predecessor_extension: requirement.predecessor_extension(),
                    admission_provenance,
                })
            })
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

    /// Recompute ERRA1 (ADR-136 §5): the request's ERAZ1, the ELP1 ERQ1
    /// pins, the retained bundle current at admission and the §6 positions,
    /// within the per-request quota of 64 attempts. It needs no signature.
    /// Attempt 0 continues the frozen request, so it is admitted after
    /// expiry; a retry is a new admission and closes on expiry (owner
    /// decision of 2026-11-16). It is refused while another request of the
    /// subject holds it. Automatic retry up to `auto_retry_max` is the C4
    /// driver's scheduling (§6).
    fn admit_attempt(
        &self,
        view: &dyn ErasureAuthorityReadViewV1,
        admission: &ErasureRetryAdmissionV1,
    ) -> Result<ErasureAttemptQuotaReservationV1, ErasureErrorV1> {
        if admission.attempt_ordinal() == 0 {
            Ok(())
        } else {
            self.admits_new_work()
        }
        .and_then(|()| self.attempt_admitted(view, admission))
    }

    /// The evidence must be a purpose-1 ELS1 over the ELO1 of exactly this
    /// command, obligation, owner and attempt, with the same outcome.
    /// Completing admitted work does not close on expiry.
    fn admit_acknowledgement(
        &self,
        view: &dyn ErasureAuthorityReadViewV1,
        acknowledgement: &ErasureAcknowledgementProvenanceV1,
    ) -> Result<(), ErasureErrorV1> {
        self.acknowledgement_admitted(view, acknowledgement)
    }

    /// The receipt must issue at its §6 position under a purpose-2 ELS1
    /// over its ERCB1. Completing admitted work does not close on expiry.
    fn admit_receipt(
        &self,
        view: &dyn ErasureAuthorityReadViewV1,
        input: &ErasureReceiptInputV1,
    ) -> Result<(), ErasureErrorV1> {
        self.receipt_admitted(view, input)
    }
}
