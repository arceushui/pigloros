//! Host-trusted erasure authority composition.
//!
//! This module contains the smallest concrete authority that can be installed
//! by a deployment without giving the authority access to the durable store.
//! It is deliberately configuration-driven: policy, trust, topology, owners,
//! and retained evidence are supplied by the host and are never inferred from
//! persistence. A deployment that has not supplied a complete configuration
//! must continue using [`super::ClosedErasureCoordinatorAuthorityV1`].

use std::sync::Arc;

use pos_core::{
    destruction_command_reference, CanonicalBytes, ErasureAcknowledgementProvenanceV1,
    ErasureAdministrativeResolutionV1, ErasureApplicabilityDecisionV1,
    ErasureAtomicFreezeAdmissionInputV1, ErasureAtomicFreezeResultV1,
    ErasureAttemptQuotaReservationV1, ErasureAuthorizationDecisionV1,
    ErasureCorrectionProvenanceV1, ErasureDestructionCommandV1, ErasureErrorV1,
    ErasureForkAdmissionInputV1, ErasureForkScopeRequirementV1,
    ErasureFreezeAdmissionEvidenceInputV1, ErasureFreezeAdmissionEvidenceV1,
    ErasureFreezeApplicabilityRowV1, ErasureFreezeAuthorizationEvidenceInputV1,
    ErasureFreezeAuthorizationEvidenceV1, ErasureFreezeAuthorizationVerifierV1,
    ErasureInventoryCategoryV1, ErasureLifecycleV1, ErasureObligationInputV1,
    ErasureObligationSetInputV1, ErasureObligationSetV1, ErasureObligationV1,
    ErasureReceiptInputV1, ErasureRecoveryAuthorizationVerifierV1, ErasureReferenceV1,
    ErasureRequestV1, ErasureRetryAdmissionV1, ErasureScopeCommitmentInputV1,
    ErasureScopeExtensionInputV1, ErasureScopeExtensionV1, ErasureStateTransitionV1,
    ErasureVerifiedTopologyObservationV1, PublicKey, Signature, TimelineId, TimelineMeta,
};

use super::erasure_host::ErasureCoordinatorAuthorityV1;

/// Operation whose host evidence is being checked by an authority provider.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErasureAuthorityEvidenceKindV1 {
    /// Authentication of a complete ERQ1 request.
    Request,
    /// Authentication of a request/manifest topology observation.
    Topology,
    /// Authentication of a lifecycle or external-owner admission.
    Lifecycle,
    /// Authentication of an ERFA1 freeze authorization body.
    Freeze,
}

/// Host-owned evidence verifier used by the concrete authority provider.
///
/// The runtime deliberately does not interpret opaque identity, policy, trust,
/// or proof bytes. A deployment supplies this seam with its independently
/// authenticated identity/policy implementation (for example, a signature or
/// HSM-backed verifier). The provider refuses every admission when no verifier
/// is installed, so equality of opaque references can never become authority.
pub trait ErasureAuthorityEvidenceVerifierV1: std::fmt::Debug + Send + Sync {
    /// Verify evidence for one exact request-bound operation and context.
    ///
    /// # Errors
    /// Returns a closed authorization or provenance error when the host
    /// evidence does not authenticate the supplied context.
    fn verify(
        &self,
        kind: ErasureAuthorityEvidenceKindV1,
        request: &ErasureRequestV1,
        context: &[u8],
        evidence: &[u8],
    ) -> Result<(), ErasureErrorV1>;
}

/// Ed25519 verifier for host authority evidence bundles.
///
/// Evidence is a concatenation of entries, each encoded as a big-endian
/// `u32` context length, the exact context bytes, and a 64-byte Ed25519
/// signature over those context bytes. A deployment can pre-authorize every
/// request/lifecycle context it expects without giving this crate access to a
/// store, key material, or policy engine.
#[derive(Clone, Copy, Debug)]
pub struct Ed25519ErasureAuthorityEvidenceVerifierV1 {
    public_key: PublicKey,
}

impl Ed25519ErasureAuthorityEvidenceVerifierV1 {
    /// Construct a verifier after validating the compressed Ed25519 key.
    ///
    /// # Errors
    /// Returns [`ErasureErrorV1::TrustSnapshotInvalid`] when `public_key` is
    /// not a valid Ed25519 verifying key.
    pub fn new(public_key: PublicKey) -> Result<Self, ErasureErrorV1> {
        pos_crypto::signing::verifying_key_from_public_key(&public_key)
            .map(|_| Self { public_key })
            .map_err(|_| ErasureErrorV1::TrustSnapshotInvalid)
    }
}

impl ErasureAuthorityEvidenceVerifierV1 for Ed25519ErasureAuthorityEvidenceVerifierV1 {
    fn verify(
        &self,
        _kind: ErasureAuthorityEvidenceKindV1,
        _request: &ErasureRequestV1,
        context: &[u8],
        evidence: &[u8],
    ) -> Result<(), ErasureErrorV1> {
        let verifying_key = pos_crypto::signing::verifying_key_from_public_key(&self.public_key)
            .map_err(|_| ErasureErrorV1::TrustSnapshotInvalid)?;
        let mut cursor = 0;
        let mut matched = false;
        let mut matched_valid = false;
        while cursor < evidence.len() {
            let length_end = cursor
                .checked_add(4)
                .ok_or(ErasureErrorV1::InvalidEncoding)?;
            let length_bytes = evidence
                .get(cursor..length_end)
                .ok_or(ErasureErrorV1::InvalidEncoding)?;
            let context_length = usize::try_from(u32::from_be_bytes(
                length_bytes
                    .try_into()
                    .map_err(|_| ErasureErrorV1::InvalidEncoding)?,
            ))
            .map_err(|_| ErasureErrorV1::InvalidEncoding)?;
            cursor = length_end;
            let context_end = cursor
                .checked_add(context_length)
                .ok_or(ErasureErrorV1::InvalidEncoding)?;
            let signature_end = context_end
                .checked_add(64)
                .ok_or(ErasureErrorV1::InvalidEncoding)?;
            let signed_context = evidence
                .get(cursor..context_end)
                .ok_or(ErasureErrorV1::InvalidEncoding)?;
            let signature_bytes = evidence
                .get(context_end..signature_end)
                .ok_or(ErasureErrorV1::InvalidEncoding)?;
            cursor = signature_end;
            if signed_context == context {
                if matched {
                    return Err(ErasureErrorV1::Unauthorized);
                }
                matched = true;
                let signature = Signature::from_bytes(
                    signature_bytes
                        .try_into()
                        .map_err(|_| ErasureErrorV1::InvalidEncoding)?,
                );
                let payload = CanonicalBytes::from_vec(context.to_vec());
                matched_valid =
                    pos_crypto::signing::verify(&verifying_key, &payload, &signature).is_ok();
            }
        }
        matched_valid
            .then_some(())
            .ok_or(ErasureErrorV1::Unauthorized)
    }
}

/// One host-authenticated mapping between a request and a Timeline/Fork.
///
/// `scope = None` marks an unaffected Timeline. `Some` is an opaque resolved
/// scope reference; it must not be derived from the Timeline identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErasureAuthorityTopologyBindingV1 {
    /// ERQ1 to which this topology observation belongs.
    request: ErasureReferenceV1,
    /// Manifest revision for which this observation was authenticated.
    manifest_digest: ErasureReferenceV1,
    /// Timeline/Fork identity observed at the same durable revision.
    timeline: TimelineId,
    /// Resolved affected scope, or `None` for an unaffected Timeline.
    scope: Option<ErasureReferenceV1>,
}

impl ErasureAuthorityTopologyBindingV1 {
    /// Construct one topology binding without deriving scope from identity.
    #[must_use]
    pub const fn new(
        request: ErasureReferenceV1,
        manifest_digest: ErasureReferenceV1,
        timeline: TimelineId,
        scope: Option<ErasureReferenceV1>,
    ) -> Self {
        Self {
            request,
            manifest_digest,
            timeline,
            scope,
        }
    }
}

/// Host-selected freeze policy for every category in a frozen target closure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErasureAuthorityFreezeProfileV1 {
    /// Canonical affected scope members, independent of Timeline IDs.
    scope_members: Vec<ErasureReferenceV1>,
    /// Canonical target closure admitted by policy.
    targets: Vec<pos_core::ErasureRequiredTargetV1>,
    /// Owner identity for Artifact, Key, Replica, and Backup categories.
    owners: [ErasureReferenceV1; 4],
    /// Optional immutable future-Fork lineage rule.
    lineage_rule: Option<ErasureReferenceV1>,
    /// Scope reference assigned to an admitted child Fork.
    child_scope: ErasureReferenceV1,
}

impl ErasureAuthorityFreezeProfileV1 {
    /// Validate and canonicalize one host-owned freeze profile.
    ///
    /// # Errors
    /// Returns [`ErasureErrorV1::ScopeInvalid`] for an empty, duplicate, or
    /// zero-valued scope, target, owner, or lineage reference.
    pub fn new(
        mut scope_members: Vec<ErasureReferenceV1>,
        mut targets: Vec<pos_core::ErasureRequiredTargetV1>,
        owners: [ErasureReferenceV1; 4],
        lineage_rule: Option<ErasureReferenceV1>,
        child_scope: ErasureReferenceV1,
    ) -> Result<Self, ErasureErrorV1> {
        if scope_members.is_empty()
            || targets.is_empty()
            || !references_present(&owners)
            || targets
                .iter()
                .any(|target| !target_references_present(*target))
        {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        scope_members.sort_unstable();
        targets.sort_unstable();
        let mut owner_set = owners.to_vec();
        owner_set.sort_unstable();
        if has_duplicate(&scope_members)
            || has_duplicate(&targets)
            || has_duplicate(&owner_set)
            || !reference_present(child_scope)
            || lineage_rule.is_some_and(|rule| !reference_present(rule))
        {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        Ok(Self {
            scope_members,
            targets,
            owners,
            lineage_rule,
            child_scope,
        })
    }
}

/// Host-authenticated material for one ERQ1 request.
///
/// Keeping the complete request beside its topology and freeze profile makes
/// every later admission request-specific. A non-zero reference alone is never
/// sufficient to select this binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErasureAuthorityRequestBindingV1 {
    /// The exact validated ERQ1 request admitted by the host.
    request: ErasureRequestV1,
    /// Complete topology observations authenticated for this request.
    topology: Vec<ErasureAuthorityTopologyBindingV1>,
    /// Freeze target, scope, and owner profile for this request.
    freeze: ErasureAuthorityFreezeProfileV1,
    /// Principal allowed to perform administrative resolution.
    principal: ErasureReferenceV1,
    /// Host evidence interpreted by the injected verifier.
    authorization_evidence: Vec<u8>,
    /// Provenance used for host-authenticated lifecycle admissions.
    lifecycle_provenance: ErasureReferenceV1,
    /// Whether this request admits pre-freeze rejection decisions.
    allow_rejection: bool,
}

impl ErasureAuthorityRequestBindingV1 {
    /// Validate one request-bound host configuration.
    ///
    /// # Errors
    /// Returns a closed provenance or scope error when request, topology,
    /// identity, evidence, or lifecycle material is incomplete or conflicting.
    pub fn new(
        request: ErasureRequestV1,
        mut topology: Vec<ErasureAuthorityTopologyBindingV1>,
        freeze: ErasureAuthorityFreezeProfileV1,
        principal: ErasureReferenceV1,
        authorization_evidence: Vec<u8>,
        lifecycle_provenance: ErasureReferenceV1,
        allow_rejection: bool,
    ) -> Result<Self, ErasureErrorV1> {
        if !reference_present(request.reference())
            || !reference_present(request.provenance())
            || !reference_present(principal)
            || !reference_present(lifecycle_provenance)
            || authorization_evidence.is_empty()
        {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
        topology.sort_unstable_by_key(|binding| {
            (binding.manifest_digest, binding.timeline, binding.scope)
        });
        if topology.windows(2).any(|pair| {
            pair[0].manifest_digest == pair[1].manifest_digest
                && pair[0].timeline == pair[1].timeline
        }) || topology.iter().any(|binding| {
            binding.request != request.reference()
                || !reference_present(binding.manifest_digest)
                || binding.scope.is_some_and(|scope| !reference_present(scope))
        }) {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        Ok(Self {
            request,
            topology,
            freeze,
            principal,
            authorization_evidence,
            lifecycle_provenance,
            allow_rejection,
        })
    }
}

/// Complete host-trusted material needed by a concrete authority Plugin.
///
/// The values are intentionally opaque references and proof bytes. The
/// runtime never interprets them as persistence-derived authority; the host
/// must obtain them from its policy, trust, identity, and topology boundaries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErasureAuthorityConfigurationV1 {
    /// Policy revision accepted for all admissions.
    policy: ErasureReferenceV1,
    /// Trust revision accepted for all admissions.
    trust: ErasureReferenceV1,
    /// Complete request-specific host bindings.
    requests: Vec<ErasureAuthorityRequestBindingV1>,
}

impl ErasureAuthorityConfigurationV1 {
    /// Validate and canonicalize host configuration.
    ///
    /// # Errors
    /// Returns a closed provenance or scope error when policy, trust, or
    /// request bindings are incomplete or conflicting.
    pub fn new(
        policy: ErasureReferenceV1,
        trust: ErasureReferenceV1,
        mut requests: Vec<ErasureAuthorityRequestBindingV1>,
    ) -> Result<Self, ErasureErrorV1> {
        if !reference_present(policy) || !reference_present(trust) || requests.is_empty() {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
        requests.sort_unstable_by_key(|binding| binding.request.reference());
        if requests
            .windows(2)
            .any(|pair| pair[0].request.reference() == pair[1].request.reference())
            || requests
                .iter()
                .any(|binding| binding.request.policy() != policy)
        {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        Ok(Self {
            policy,
            trust,
            requests,
        })
    }
}

/// Concrete host-trusted authority suitable for production composition.
///
/// This type is a replaceable Plugin implementation, not a policy engine. A
/// deployment constructs it only after independently authenticating the
/// configuration and then injects it into every execution-host composition
/// root. It never reads an `EventStore` and never turns a persisted digest into
/// identity, authorization, or topology truth.
#[derive(Clone, Debug)]
pub struct HostConfiguredErasureCoordinatorAuthorityV1 {
    configuration: ErasureAuthorityConfigurationV1,
    verifier: Arc<dyn ErasureAuthorityEvidenceVerifierV1>,
}

impl HostConfiguredErasureCoordinatorAuthorityV1 {
    /// Construct an authority from independently authenticated host material.
    ///
    /// # Errors
    /// Returns [`ErasureErrorV1::ProvenanceMissing`] when no request binding is
    /// configured. The supplied verifier is invoked for every admission.
    pub fn new(
        configuration: ErasureAuthorityConfigurationV1,
        verifier: Arc<dyn ErasureAuthorityEvidenceVerifierV1>,
    ) -> Result<Self, ErasureErrorV1> {
        if configuration.requests.is_empty() {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
        Ok(Self {
            configuration,
            verifier,
        })
    }

    /// Return the immutable host configuration for composition diagnostics.
    #[must_use]
    pub const fn configuration(&self) -> &ErasureAuthorityConfigurationV1 {
        &self.configuration
    }

    fn binding_for(
        &self,
        request: ErasureReferenceV1,
    ) -> Result<&ErasureAuthorityRequestBindingV1, ErasureErrorV1> {
        self.configuration
            .requests
            .iter()
            .find(|binding| binding.request.reference() == request)
            .ok_or(ErasureErrorV1::ProvenanceMissing)
    }

    fn verify(
        &self,
        kind: ErasureAuthorityEvidenceKindV1,
        binding: &ErasureAuthorityRequestBindingV1,
        context: &[u8],
    ) -> Result<(), ErasureErrorV1> {
        self.verifier.verify(
            kind,
            &binding.request,
            context,
            &binding.authorization_evidence,
        )
    }

    fn check_policy_trust(
        &self,
        policy: ErasureReferenceV1,
        trust: ErasureReferenceV1,
    ) -> Result<(), ErasureErrorV1> {
        (policy == self.configuration.policy && trust == self.configuration.trust)
            .then_some(())
            .ok_or(ErasureErrorV1::PolicyConflict)
    }

    fn check_lifecycle_provenance(
        &self,
        binding: &ErasureAuthorityRequestBindingV1,
        provenance: ErasureReferenceV1,
        context: &[u8],
    ) -> Result<(), ErasureErrorV1> {
        if provenance != binding.lifecycle_provenance {
            return Err(ErasureErrorV1::Unauthorized);
        }
        self.verify(ErasureAuthorityEvidenceKindV1::Lifecycle, binding, context)
    }

    fn build_freeze_admission(
        &self,
        binding: &ErasureAuthorityRequestBindingV1,
        freeze_position: u64,
    ) -> Result<ErasureAtomicFreezeResultV1, ErasureErrorV1> {
        let request = binding.request.reference();
        let targets = binding.freeze.targets.clone();
        let target_closure = pos_core::erasure::target_closure_digest(&targets);
        let mut obligations = Vec::with_capacity(
            targets
                .len()
                .saturating_mul(ErasureInventoryCategoryV1::CANONICAL.len()),
        );
        let mut applicability_matrix = Vec::with_capacity(obligations.capacity());
        for category in ErasureInventoryCategoryV1::CANONICAL {
            let owner = category_owner(binding.freeze.owners, category);
            for (target_index, target) in targets.iter().copied().enumerate() {
                obligations.push(ErasureObligationV1::new(ErasureObligationInputV1 {
                    category,
                    target,
                    owner,
                    command_identity: destruction_command_reference(request, target),
                })?);
                applicability_matrix.push(ErasureFreezeApplicabilityRowV1::new(
                    category,
                    u64::try_from(target_index).map_err(|_| ErasureErrorV1::ScopeInvalid)?,
                    ErasureApplicabilityDecisionV1::Applicable,
                    Some(owner),
                )?);
            }
        }
        obligations.sort_unstable_by_key(ErasureObligationV1::reference);
        let obligation_references = obligations
            .iter()
            .map(ErasureObligationV1::reference)
            .collect::<Vec<_>>();
        obligation_references
            .windows(2)
            .all(|pair| pair[0] < pair[1])
            .then_some(())
            .ok_or(ErasureErrorV1::ScopeInvalid)?;
        let obligation_set = ErasureObligationSetV1::new(ErasureObligationSetInputV1 {
            request,
            obligations: obligation_references,
            policy: self.configuration.policy,
            trust: self.configuration.trust,
        })?;
        let scope = ErasureScopeCommitmentInputV1 {
            request,
            scope_members: binding.freeze.scope_members.clone(),
            target_closure,
            lineage_rule: binding.freeze.lineage_rule,
        };
        let scope_reference = pos_core::ErasureScopeCommitmentV1::new(scope.clone())?.reference();
        let placeholder =
            ErasureFreezeAdmissionEvidenceV1::new(ErasureFreezeAdmissionEvidenceInputV1 {
                request,
                scope_commitment: scope_reference,
                obligation_set: obligation_set.reference(),
                applicability_matrix,
                freeze_position,
                policy: binding.request.policy(),
                trust: self.configuration.trust,
                authorization_provenance: ErasureReferenceV1::from_digest([0; 32]),
            })?;
        let admission_body_digest = placeholder.authorization_body_digest()?;
        let authorization =
            ErasureFreezeAuthorizationEvidenceV1::new(ErasureFreezeAuthorizationEvidenceInputV1 {
                admission_body_digest,
                policy: binding.request.policy(),
                trust: self.configuration.trust,
                evidence: binding.authorization_evidence.clone(),
            })?;
        let admission =
            ErasureFreezeAdmissionEvidenceV1::new(ErasureFreezeAdmissionEvidenceInputV1 {
                authorization_provenance: authorization.reference(),
                ..placeholder_input(&placeholder)
            })?;
        Ok(ErasureAtomicFreezeResultV1::Admitted(Box::new(
            pos_core::ErasureAtomicFreezeAdmissionV1::new(ErasureAtomicFreezeAdmissionInputV1 {
                targets,
                scope,
                obligations,
                obligation_set,
                freeze_position,
                freeze_admission_evidence: admission,
                freeze_authorization_evidence: authorization,
            })?,
        )))
    }
}

impl ErasureFreezeAuthorizationVerifierV1 for HostConfiguredErasureCoordinatorAuthorityV1 {
    fn validate_freeze_authorization(
        &self,
        admission: &ErasureFreezeAdmissionEvidenceV1,
        authorization: &ErasureFreezeAuthorizationEvidenceV1,
    ) -> Result<(), ErasureErrorV1> {
        authorization.verify_admission_body_binding(admission)?;
        let binding = self.binding_for(admission.request())?;
        if authorization.evidence() != binding.authorization_evidence.as_slice() {
            return Err(ErasureErrorV1::Unauthorized);
        }
        self.check_policy_trust(admission.policy(), admission.trust())?;
        self.check_policy_trust(authorization.policy(), authorization.trust())?;
        let context = admission.authorization_body_digest()?.digest();
        self.verify(ErasureAuthorityEvidenceKindV1::Freeze, binding, &context)
    }
}

impl ErasureRecoveryAuthorizationVerifierV1 for HostConfiguredErasureCoordinatorAuthorityV1 {
    fn validate_scope_extension(
        &self,
        extension: &ErasureScopeExtensionV1,
    ) -> Result<(), ErasureErrorV1> {
        let binding = self.binding_for(extension.request())?;
        for reference in [
            extension.scope_commitment(),
            extension.fork(),
            extension.lineage_rule(),
            extension.admission_provenance(),
        ] {
            if !reference_present(reference) {
                return Err(ErasureErrorV1::ProvenanceMissing);
            }
        }
        let context = lifecycle_context(
            b"scope-extension",
            extension.request(),
            extension.reference(),
        );
        self.check_lifecycle_provenance(binding, extension.admission_provenance(), &context)
    }

    fn validate_administrative_resolution(
        &self,
        resolution: &ErasureAdministrativeResolutionV1,
    ) -> Result<(), ErasureErrorV1> {
        self.admit_administrative_resolution(resolution)
    }
}

impl ErasureCoordinatorAuthorityV1 for HostConfiguredErasureCoordinatorAuthorityV1 {
    fn verified_topology_observation(
        &self,
        request: ErasureReferenceV1,
        manifest_digest: ErasureReferenceV1,
    ) -> Result<Option<ErasureVerifiedTopologyObservationV1>, ErasureErrorV1> {
        let binding = self.binding_for(request)?;
        if !reference_present(manifest_digest) {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
        let mut bindings = Vec::new();
        let mut unaffected = Vec::new();
        for entry in binding
            .topology
            .iter()
            .filter(|entry| entry.manifest_digest == manifest_digest)
        {
            match entry.scope {
                Some(scope) => bindings.push((entry.timeline, scope)),
                None => unaffected.push(entry.timeline),
            }
        }
        if bindings.is_empty() && unaffected.is_empty() {
            return Ok(None);
        }
        let observation =
            ErasureVerifiedTopologyObservationV1::new(manifest_digest, bindings, unaffected);
        let context = topology_context(request, manifest_digest, &observation);
        self.verify(ErasureAuthorityEvidenceKindV1::Topology, binding, &context)?;
        Ok(Some(observation))
    }

    fn authenticate(&self, request: &ErasureRequestV1) -> Result<(), ErasureErrorV1> {
        let binding = self.binding_for(request.reference())?;
        if &binding.request != request {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        self.check_policy_trust(request.policy(), self.configuration.trust)?;
        let context = request.to_canonical_cbor()?;
        self.verify(ErasureAuthorityEvidenceKindV1::Request, binding, &context)
    }

    fn admit_authorization(
        &self,
        request: ErasureReferenceV1,
        provenance: ErasureReferenceV1,
        decision: ErasureAuthorizationDecisionV1,
    ) -> Result<(), ErasureErrorV1> {
        let binding = self.binding_for(request)?;
        let context = lifecycle_context(
            b"authorization",
            request,
            ErasureReferenceV1::from_digest([decision_code(decision); 32]),
        );
        self.check_lifecycle_provenance(binding, provenance, &context)?;
        if matches!(decision, ErasureAuthorizationDecisionV1::Rejected) && !binding.allow_rejection
        {
            return Err(ErasureErrorV1::Unauthorized);
        }
        Ok(())
    }

    fn admit_corrected_submission(
        &self,
        request: &ErasureRequestV1,
        correction: &ErasureCorrectionProvenanceV1,
    ) -> Result<(), ErasureErrorV1> {
        self.authenticate(request)?;
        (correction.rejected_request() == request.reference())
            .then_some(())
            .ok_or(ErasureErrorV1::PolicyConflict)?;
        for reference in [
            correction.rejected_terminal_state(),
            correction.correction_reason(),
            correction.authorization_provenance(),
            correction.reference(),
        ] {
            if !reference_present(reference) {
                return Err(ErasureErrorV1::ProvenanceMissing);
            }
        }
        let binding = self.binding_for(request.reference())?;
        let context = lifecycle_context(
            b"corrected-submission",
            request.reference(),
            correction.reference(),
        );
        self.check_lifecycle_provenance(binding, correction.authorization_provenance(), &context)
    }

    fn admit_atomic_freeze(
        &self,
        request: ErasureReferenceV1,
        requested: &ErasureStateTransitionV1,
    ) -> Result<ErasureAtomicFreezeResultV1, ErasureErrorV1> {
        let binding = self.binding_for(request)?;
        if requested.lifecycle != ErasureLifecycleV1::AccessFrozen {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        let freeze_position = requested
            .freeze_position
            .ok_or(ErasureErrorV1::ScopeInvalid)?;
        let context = lifecycle_context(
            b"atomic-freeze",
            request,
            position_reference(freeze_position),
        );
        self.check_lifecycle_provenance(binding, requested.provenance, &context)?;
        self.build_freeze_admission(binding, freeze_position)
    }

    fn admit_scope_extension(
        &self,
        extension: &ErasureScopeExtensionV1,
    ) -> Result<(), ErasureErrorV1> {
        self.validate_scope_extension(extension)
    }

    fn admit_fork_scope_extension(
        &self,
        extension: &ErasureScopeExtensionV1,
        input: &ErasureForkAdmissionInputV1,
    ) -> Result<(), ErasureErrorV1> {
        self.validate_scope_extension(extension)?;
        for reference in [
            input.operation,
            input.expected_inventory_generation,
            input.child_scope,
        ] {
            if !reference_present(reference) {
                return Err(ErasureErrorV1::ProvenanceMissing);
            }
        }
        (extension.fork() == input.child_scope)
            .then_some(())
            .ok_or(ErasureErrorV1::ScopeInvalid)
    }

    fn resolve_fork_child_scope(
        &self,
        parent: TimelineId,
        child: &TimelineMeta,
    ) -> Result<ErasureReferenceV1, ErasureErrorV1> {
        let mut child_scopes = self
            .configuration
            .requests
            .iter()
            .map(|binding| binding.freeze.child_scope);
        let child_scope = child_scopes
            .next()
            .ok_or(ErasureErrorV1::ProvenanceMissing)?;
        if child_scopes.any(|scope| scope != child_scope) {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        match child.fork_point {
            Some((actual_parent, _)) if actual_parent == parent => Ok(child_scope),
            _ => Err(ErasureErrorV1::ScopeInvalid),
        }
    }

    fn resolve_fork_scope_extension(
        &self,
        requirement: ErasureForkScopeRequirementV1,
        input: &ErasureForkAdmissionInputV1,
    ) -> Result<ErasureScopeExtensionV1, ErasureErrorV1> {
        let binding = self.binding_for(requirement.request())?;
        for reference in [
            requirement.scope_commitment(),
            requirement.lineage_rule(),
            input.operation,
            input.expected_inventory_generation,
            input.child_scope,
        ] {
            if !reference_present(reference) {
                return Err(ErasureErrorV1::ProvenanceMissing);
            }
        }
        (input.child_scope == binding.freeze.child_scope)
            .then_some(())
            .ok_or(ErasureErrorV1::ScopeInvalid)?;
        ErasureScopeExtensionV1::new(ErasureScopeExtensionInputV1 {
            request: requirement.request(),
            scope_commitment: requirement.scope_commitment(),
            fork: input.child_scope,
            lineage_rule: requirement.lineage_rule(),
            predecessor_extension: requirement.predecessor_extension(),
            admission_provenance: binding.lifecycle_provenance,
        })
    }

    fn admit_administrative_resolution(
        &self,
        resolution: &ErasureAdministrativeResolutionV1,
    ) -> Result<(), ErasureErrorV1> {
        let binding = self.binding_for(resolution.request())?;
        self.check_policy_trust(resolution.policy(), resolution.trust())?;
        (resolution.principal() == binding.principal)
            .then_some(())
            .ok_or(ErasureErrorV1::Unauthorized)?;
        let context = lifecycle_context(
            b"administrative-resolution",
            resolution.request(),
            resolution.reference(),
        );
        self.check_lifecycle_provenance(binding, resolution.authorization_provenance(), &context)?;
        for reference in [
            resolution.scope_commitment(),
            resolution.reason(),
            resolution.reference(),
        ]
        .into_iter()
        .chain(resolution.affected_digests().iter().copied())
        .chain(resolution.predecessor_resolution())
        {
            if !reference_present(reference) {
                return Err(ErasureErrorV1::ProvenanceMissing);
            }
        }
        Ok(())
    }

    fn dispatch_destruction(
        &self,
        request: ErasureReferenceV1,
        commands: &[ErasureDestructionCommandV1],
    ) -> Result<(), ErasureErrorV1> {
        let binding = self.binding_for(request)?;
        if commands.is_empty() {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        for command in commands {
            let context = lifecycle_context(b"destruction", request, command.command);
            self.check_lifecycle_provenance(binding, command.provenance, &context)?;
            for reference in [command.obligation, command.owner, command.command] {
                if !reference_present(reference) {
                    return Err(ErasureErrorV1::ProvenanceMissing);
                }
            }
            (command.owner == category_owner(binding.freeze.owners, command.category))
                .then_some(())
                .ok_or(ErasureErrorV1::Unauthorized)?;
            binding
                .freeze
                .targets
                .contains(&command.target)
                .then_some(())
                .ok_or(ErasureErrorV1::ScopeInvalid)?;
            let obligation =
                pos_core::ErasureObligationV1::new(pos_core::ErasureObligationInputV1 {
                    category: command.category,
                    target: command.target,
                    owner: command.owner,
                    command_identity: command.command,
                })?;
            (obligation.reference() == command.obligation)
                .then_some(())
                .ok_or(ErasureErrorV1::ProvenanceMissing)?;
            (command.command == destruction_command_reference(request, command.target))
                .then_some(())
                .ok_or(ErasureErrorV1::ProvenanceMissing)?;
        }
        Ok(())
    }

    fn admit_attempt(
        &self,
        admission: &ErasureRetryAdmissionV1,
    ) -> Result<ErasureAttemptQuotaReservationV1, ErasureErrorV1> {
        let binding = self.binding_for(admission.request())?;
        self.check_policy_trust(admission.policy(), admission.trust())?;
        let context = lifecycle_context(b"attempt", admission.request(), admission.reference());
        self.check_lifecycle_provenance(binding, admission.authorization_provenance(), &context)?;
        if admission.unresolved_obligations().len() != admission.command_identities().len() {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        for reference in admission
            .unresolved_obligations()
            .iter()
            .chain(admission.command_identities().iter())
            .copied()
        {
            if !reference_present(reference) {
                return Err(ErasureErrorV1::ProvenanceMissing);
            }
        }
        Ok(ErasureAttemptQuotaReservationV1::new(
            admission.reference(),
            binding.lifecycle_provenance,
        ))
    }

    fn admit_acknowledgement(
        &self,
        acknowledgement: &ErasureAcknowledgementProvenanceV1,
    ) -> Result<(), ErasureErrorV1> {
        let binding = self.binding_for(acknowledgement.request())?;
        self.check_policy_trust(acknowledgement.policy(), acknowledgement.trust())?;
        for reference in [
            acknowledgement.command(),
            acknowledgement.attempt(),
            acknowledgement.obligation(),
            acknowledgement.owner(),
            acknowledgement.scope(),
            acknowledgement.evidence(),
            acknowledgement.reference(),
        ] {
            if !reference_present(reference) {
                return Err(ErasureErrorV1::ProvenanceMissing);
            }
        }
        let context = lifecycle_context(
            b"acknowledgement",
            acknowledgement.request(),
            acknowledgement.reference(),
        );
        self.verify(ErasureAuthorityEvidenceKindV1::Lifecycle, binding, &context)?;
        Ok(())
    }

    fn admit_receipt(&self, input: &ErasureReceiptInputV1) -> Result<(), ErasureErrorV1> {
        let binding = self.binding_for(input.request)?;
        self.check_policy_trust(input.policy, input.trust)?;
        if !matches!(
            input.lifecycle,
            ErasureLifecycleV1::Complete | ErasureLifecycleV1::PartialFailure
        ) {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        let context = lifecycle_context(b"receipt", input.request, input.receipt_digest);
        self.check_lifecycle_provenance(binding, input.provenance, &context)?;
        for reference in [
            input.terminal_state,
            input.coordinator,
            input.provenance,
            input.signature,
        ] {
            if !reference_present(reference) {
                return Err(ErasureErrorV1::ProvenanceMissing);
            }
        }
        Ok(())
    }
}

fn reference_present(reference: ErasureReferenceV1) -> bool {
    reference.digest() != [0; 32]
}

fn references_present(references: &[ErasureReferenceV1]) -> bool {
    references.iter().copied().all(reference_present)
}

fn target_references_present(target: pos_core::ErasureRequiredTargetV1) -> bool {
    [
        target.artifact_digest,
        target.key_digest,
        target.replica_set,
        target.replica_id,
    ]
    .into_iter()
    .all(reference_present)
}

fn has_duplicate<T: PartialEq>(values: &[T]) -> bool {
    values.windows(2).any(|pair| pair[0] == pair[1])
}

const fn category_owner(
    owners: [ErasureReferenceV1; 4],
    category: ErasureInventoryCategoryV1,
) -> ErasureReferenceV1 {
    match category {
        ErasureInventoryCategoryV1::Artifact => owners[0],
        ErasureInventoryCategoryV1::Key => owners[1],
        ErasureInventoryCategoryV1::Replica => owners[2],
        ErasureInventoryCategoryV1::Backup => owners[3],
    }
}

fn lifecycle_context(
    operation: &[u8],
    request: ErasureReferenceV1,
    detail: ErasureReferenceV1,
) -> Vec<u8> {
    let mut context = Vec::with_capacity(operation.len() + 64);
    context.extend_from_slice(operation);
    context.extend_from_slice(&request.digest());
    context.extend_from_slice(&detail.digest());
    context
}

fn position_reference(position: u64) -> ErasureReferenceV1 {
    let mut digest = [0; 32];
    digest[..8].copy_from_slice(&position.to_le_bytes());
    ErasureReferenceV1::from_digest(digest)
}

const fn decision_code(decision: ErasureAuthorizationDecisionV1) -> u8 {
    match decision {
        ErasureAuthorizationDecisionV1::Authorized => 1,
        ErasureAuthorizationDecisionV1::Rejected => 2,
    }
}

fn topology_context(
    request: ErasureReferenceV1,
    manifest_digest: ErasureReferenceV1,
    observation: &ErasureVerifiedTopologyObservationV1,
) -> Vec<u8> {
    let mut context = Vec::with_capacity(64 + observation.bindings().len() * 48);
    context.extend_from_slice(b"topology");
    context.extend_from_slice(&request.digest());
    context.extend_from_slice(&manifest_digest.digest());
    for (timeline, scope) in observation.bindings() {
        context.extend_from_slice(&timeline.inner().to_bytes());
        context.extend_from_slice(&scope.digest());
    }
    for timeline in observation.unaffected() {
        context.extend_from_slice(&timeline.inner().to_bytes());
    }
    context
}

fn placeholder_input(
    admission: &ErasureFreezeAdmissionEvidenceV1,
) -> ErasureFreezeAdmissionEvidenceInputV1 {
    ErasureFreezeAdmissionEvidenceInputV1 {
        request: admission.request(),
        scope_commitment: admission.scope_commitment(),
        obligation_set: admission.obligation_set(),
        applicability_matrix: admission.applicability_matrix().to_vec(),
        freeze_position: admission.freeze_position(),
        policy: admission.policy(),
        trust: admission.trust(),
        authorization_provenance: admission.authorization_provenance(),
    }
}
