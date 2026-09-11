//! Host-trusted erasure authority composition.
//!
//! This module contains the smallest concrete authority that can be installed
//! by a deployment without giving the authority access to the durable store.
//! It is deliberately configuration-driven: policy, trust, topology, owners,
//! and retained evidence are supplied by the host and are never inferred from
//! persistence. A deployment that has not supplied a complete configuration
//! must continue using [`super::ClosedErasureCoordinatorAuthorityV1`].

use pos_core::{
    destruction_command_reference, ErasureAcknowledgementProvenanceV1,
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
    ErasureVerifiedTopologyObservationV1, TimelineId, TimelineMeta,
};

use super::erasure_host::ErasureCoordinatorAuthorityV1;

/// One host-authenticated mapping between a request and a Timeline/Fork.
///
/// `scope = None` marks an unaffected Timeline. `Some` is an opaque resolved
/// scope reference; it must not be derived from the Timeline identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErasureAuthorityTopologyBindingV1 {
    /// ERQ1 to which this topology observation belongs.
    pub request: ErasureReferenceV1,
    /// Timeline/Fork identity observed at the same durable revision.
    pub timeline: TimelineId,
    /// Resolved affected scope, or `None` for an unaffected Timeline.
    pub scope: Option<ErasureReferenceV1>,
}

impl ErasureAuthorityTopologyBindingV1 {
    /// Construct one topology binding without deriving scope from identity.
    #[must_use]
    pub const fn new(
        request: ErasureReferenceV1,
        timeline: TimelineId,
        scope: Option<ErasureReferenceV1>,
    ) -> Self {
        Self {
            request,
            timeline,
            scope,
        }
    }
}

/// Host-selected freeze policy for every category in a frozen target closure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErasureAuthorityFreezeProfileV1 {
    /// Canonical affected scope members, independent of Timeline IDs.
    pub scope_members: Vec<ErasureReferenceV1>,
    /// Canonical target closure admitted by policy.
    pub targets: Vec<pos_core::ErasureRequiredTargetV1>,
    /// Owner identity for Artifact, Key, Replica, and Backup categories.
    pub owners: [ErasureReferenceV1; 4],
    /// Optional immutable future-Fork lineage rule.
    pub lineage_rule: Option<ErasureReferenceV1>,
    /// Scope reference assigned to an admitted child Fork.
    pub child_scope: ErasureReferenceV1,
}

impl ErasureAuthorityFreezeProfileV1 {
    /// Validate and canonicalize one host-owned freeze profile.
    ///
    /// # Errors
    ///
    /// Returns a closed scope error when the scope, target, owner, or child
    /// references are empty, duplicated, or malformed.
    pub fn new(
        mut scope_members: Vec<ErasureReferenceV1>,
        mut targets: Vec<pos_core::ErasureRequiredTargetV1>,
        owners: [ErasureReferenceV1; 4],
        lineage_rule: Option<ErasureReferenceV1>,
        child_scope: ErasureReferenceV1,
    ) -> Result<Self, ErasureErrorV1> {
        if scope_members.is_empty() || targets.is_empty() || !references_present(&owners) {
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

/// Unvalidated input for complete host-trusted authority material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErasureAuthorityConfigurationInputV1 {
    /// Policy revision accepted for all admissions.
    pub policy: ErasureReferenceV1,
    /// Trust revision accepted for all admissions.
    pub trust: ErasureReferenceV1,
    /// Complete host-resolved topology observations.
    pub topology: Vec<ErasureAuthorityTopologyBindingV1>,
    /// Freeze target, scope, and owner profile.
    pub freeze: ErasureAuthorityFreezeProfileV1,
    /// Principal allowed to perform administrative resolution.
    pub principal: ErasureReferenceV1,
    /// Opaque #187 proof material retained in ERFAA1.
    pub authorization_evidence: Vec<u8>,
    /// Provenance used for host-authenticated lifecycle admissions.
    pub lifecycle_provenance: ErasureReferenceV1,
    /// Whether this deployment admits pre-freeze rejection decisions.
    pub allow_rejection: bool,
}

/// Complete host-trusted material needed by a concrete authority Plugin.
///
/// The values are intentionally opaque references and proof bytes. The
/// runtime never interprets them as persistence-derived authority; the host
/// must obtain them from its policy, trust, identity, and topology boundaries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErasureAuthorityConfigurationV1 {
    /// Policy revision accepted for all admissions.
    pub policy: ErasureReferenceV1,
    /// Trust revision accepted for all admissions.
    pub trust: ErasureReferenceV1,
    /// Complete host-resolved topology observations.
    pub topology: Vec<ErasureAuthorityTopologyBindingV1>,
    /// Freeze target, scope, and owner profile.
    pub freeze: ErasureAuthorityFreezeProfileV1,
    /// Principal allowed to perform administrative resolution.
    pub principal: ErasureReferenceV1,
    /// Opaque #187 proof material retained in ERFAA1.
    pub authorization_evidence: Vec<u8>,
    /// Provenance used for host-authenticated lifecycle admissions.
    pub lifecycle_provenance: ErasureReferenceV1,
    /// Whether this deployment admits pre-freeze rejection decisions.
    pub allow_rejection: bool,
}

impl ErasureAuthorityConfigurationV1 {
    /// Validate and canonicalize host configuration.
    ///
    /// # Errors
    ///
    /// Returns a closed provenance or scope error when required host material
    /// is missing or topology bindings are duplicated.
    pub fn new(input: ErasureAuthorityConfigurationInputV1) -> Result<Self, ErasureErrorV1> {
        let ErasureAuthorityConfigurationInputV1 {
            policy,
            trust,
            mut topology,
            freeze,
            principal,
            authorization_evidence,
            lifecycle_provenance,
            allow_rejection,
        } = input;
        if !reference_present(policy)
            || !reference_present(trust)
            || !reference_present(principal)
            || !reference_present(lifecycle_provenance)
            || authorization_evidence.is_empty()
        {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
        topology.sort_unstable_by_key(|binding| (binding.request, binding.timeline));
        if topology
            .windows(2)
            .any(|pair| pair[0].request == pair[1].request && pair[0].timeline == pair[1].timeline)
            || topology.iter().any(|binding| {
                !reference_present(binding.request)
                    || binding.scope.is_some_and(|scope| !reference_present(scope))
            })
        {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        Ok(Self {
            policy,
            trust,
            topology,
            freeze,
            principal,
            authorization_evidence,
            lifecycle_provenance,
            allow_rejection,
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
}

impl HostConfiguredErasureCoordinatorAuthorityV1 {
    /// Construct an authority from independently authenticated host material.
    ///
    /// # Errors
    ///
    /// Returns a closed provenance error when no topology bindings were
    /// supplied.
    pub fn new(configuration: ErasureAuthorityConfigurationV1) -> Result<Self, ErasureErrorV1> {
        if configuration.topology.is_empty() {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
        Ok(Self { configuration })
    }

    /// Return the immutable host configuration for composition diagnostics.
    #[must_use]
    pub const fn configuration(&self) -> &ErasureAuthorityConfigurationV1 {
        &self.configuration
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

    fn check_request_reference(request: ErasureReferenceV1) -> Result<(), ErasureErrorV1> {
        reference_present(request)
            .then_some(())
            .ok_or(ErasureErrorV1::ProvenanceMissing)
    }

    fn check_lifecycle_provenance(
        &self,
        provenance: ErasureReferenceV1,
    ) -> Result<(), ErasureErrorV1> {
        (provenance == self.configuration.lifecycle_provenance)
            .then_some(())
            .ok_or(ErasureErrorV1::Unauthorized)
    }

    fn build_freeze_admission(
        &self,
        request: ErasureReferenceV1,
        freeze_position: u64,
    ) -> Result<ErasureAtomicFreezeResultV1, ErasureErrorV1> {
        let targets = self.configuration.freeze.targets.clone();
        let target_closure = pos_core::erasure::target_closure_digest(&targets);
        let mut obligations = Vec::with_capacity(
            targets
                .len()
                .saturating_mul(ErasureInventoryCategoryV1::CANONICAL.len()),
        );
        let mut applicability_matrix = Vec::with_capacity(obligations.capacity());
        for category in ErasureInventoryCategoryV1::CANONICAL {
            let owner = category_owner(self.configuration.freeze.owners, category);
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
            scope_members: self.configuration.freeze.scope_members.clone(),
            target_closure,
            lineage_rule: self.configuration.freeze.lineage_rule,
        };
        let scope_reference = pos_core::ErasureScopeCommitmentV1::new(scope.clone())?.reference();
        let placeholder =
            ErasureFreezeAdmissionEvidenceV1::new(ErasureFreezeAdmissionEvidenceInputV1 {
                request,
                scope_commitment: scope_reference,
                obligation_set: obligation_set.reference(),
                applicability_matrix,
                freeze_position,
                policy: self.configuration.policy,
                trust: self.configuration.trust,
                authorization_provenance: ErasureReferenceV1::from_digest([0; 32]),
            })?;
        let admission_body_digest = placeholder.authorization_body_digest()?;
        let authorization =
            ErasureFreezeAuthorizationEvidenceV1::new(ErasureFreezeAuthorizationEvidenceInputV1 {
                admission_body_digest,
                policy: self.configuration.policy,
                trust: self.configuration.trust,
                evidence: self.configuration.authorization_evidence.clone(),
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
        self.check_policy_trust(admission.policy(), admission.trust())?;
        self.check_policy_trust(authorization.policy(), authorization.trust())?;
        (authorization.evidence() == self.configuration.authorization_evidence.as_slice())
            .then_some(())
            .ok_or(ErasureErrorV1::Unauthorized)
    }
}

impl ErasureRecoveryAuthorizationVerifierV1 for HostConfiguredErasureCoordinatorAuthorityV1 {
    fn validate_scope_extension(
        &self,
        extension: &ErasureScopeExtensionV1,
    ) -> Result<(), ErasureErrorV1> {
        Self::check_request_reference(extension.request())?;
        for reference in [
            extension.scope_commitment(),
            extension.fork(),
            extension.lineage_rule(),
            extension.admission_provenance(),
        ] {
            Self::check_request_reference(reference)?;
        }
        self.check_lifecycle_provenance(extension.admission_provenance())
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
        Self::check_request_reference(request)?;
        Self::check_request_reference(manifest_digest)?;
        let mut bindings = Vec::new();
        let mut unaffected = Vec::new();
        for entry in self
            .configuration
            .topology
            .iter()
            .filter(|entry| entry.request == request)
        {
            match entry.scope {
                Some(scope) => bindings.push((entry.timeline, scope)),
                None => unaffected.push(entry.timeline),
            }
        }
        if bindings.is_empty() && unaffected.is_empty() {
            return Ok(None);
        }
        Ok(Some(ErasureVerifiedTopologyObservationV1::new(
            manifest_digest,
            bindings,
            unaffected,
        )))
    }

    fn authenticate(&self, request: &ErasureRequestV1) -> Result<(), ErasureErrorV1> {
        Self::check_request_reference(request.reference())?;
        Self::check_request_reference(request.provenance())?;
        self.check_policy_trust(request.policy(), self.configuration.trust)
    }

    fn admit_authorization(
        &self,
        request: ErasureReferenceV1,
        provenance: ErasureReferenceV1,
        decision: ErasureAuthorizationDecisionV1,
    ) -> Result<(), ErasureErrorV1> {
        Self::check_request_reference(request)?;
        self.check_lifecycle_provenance(provenance)?;
        if matches!(decision, ErasureAuthorizationDecisionV1::Rejected)
            && !self.configuration.allow_rejection
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
            Self::check_request_reference(reference)?;
        }
        self.check_lifecycle_provenance(correction.authorization_provenance())
    }

    fn admit_atomic_freeze(
        &self,
        request: ErasureReferenceV1,
        requested: &ErasureStateTransitionV1,
    ) -> Result<ErasureAtomicFreezeResultV1, ErasureErrorV1> {
        Self::check_request_reference(request)?;
        if requested.lifecycle != ErasureLifecycleV1::AccessFrozen {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        let freeze_position = requested
            .freeze_position
            .ok_or(ErasureErrorV1::ScopeInvalid)?;
        self.check_lifecycle_provenance(requested.provenance)?;
        self.build_freeze_admission(request, freeze_position)
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
            Self::check_request_reference(reference)?;
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
        match child.fork_point {
            Some((actual_parent, _)) if actual_parent == parent => {
                Ok(self.configuration.freeze.child_scope)
            }
            _ => Err(ErasureErrorV1::ScopeInvalid),
        }
    }

    fn resolve_fork_scope_extension(
        &self,
        requirement: ErasureForkScopeRequirementV1,
        input: &ErasureForkAdmissionInputV1,
    ) -> Result<ErasureScopeExtensionV1, ErasureErrorV1> {
        Self::check_request_reference(requirement.request())?;
        for reference in [
            requirement.scope_commitment(),
            requirement.lineage_rule(),
            input.operation,
            input.expected_inventory_generation,
            input.child_scope,
        ] {
            Self::check_request_reference(reference)?;
        }
        (input.child_scope == self.configuration.freeze.child_scope)
            .then_some(())
            .ok_or(ErasureErrorV1::ScopeInvalid)?;
        ErasureScopeExtensionV1::new(ErasureScopeExtensionInputV1 {
            request: requirement.request(),
            scope_commitment: requirement.scope_commitment(),
            fork: input.child_scope,
            lineage_rule: requirement.lineage_rule(),
            predecessor_extension: requirement.predecessor_extension(),
            admission_provenance: self.configuration.lifecycle_provenance,
        })
    }

    fn admit_administrative_resolution(
        &self,
        resolution: &ErasureAdministrativeResolutionV1,
    ) -> Result<(), ErasureErrorV1> {
        Self::check_request_reference(resolution.request())?;
        self.check_policy_trust(resolution.policy(), resolution.trust())?;
        (resolution.principal() == self.configuration.principal)
            .then_some(())
            .ok_or(ErasureErrorV1::Unauthorized)?;
        self.check_lifecycle_provenance(resolution.authorization_provenance())?;
        for reference in [
            resolution.scope_commitment(),
            resolution.reason(),
            resolution.reference(),
        ]
        .into_iter()
        .chain(resolution.affected_digests().iter().copied())
        .chain(resolution.predecessor_resolution())
        {
            Self::check_request_reference(reference)?;
        }
        Ok(())
    }

    fn dispatch_destruction(
        &self,
        request: ErasureReferenceV1,
        commands: &[ErasureDestructionCommandV1],
    ) -> Result<(), ErasureErrorV1> {
        Self::check_request_reference(request)?;
        if commands.is_empty() {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        for command in commands {
            self.check_lifecycle_provenance(command.provenance)?;
            for reference in [command.obligation, command.owner, command.command] {
                Self::check_request_reference(reference)?;
            }
            (command.owner == category_owner(self.configuration.freeze.owners, command.category))
                .then_some(())
                .ok_or(ErasureErrorV1::Unauthorized)?;
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
        Self::check_request_reference(admission.request())?;
        self.check_policy_trust(admission.policy(), admission.trust())?;
        self.check_lifecycle_provenance(admission.authorization_provenance())?;
        if admission.unresolved_obligations().len() != admission.command_identities().len() {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        for reference in admission
            .unresolved_obligations()
            .iter()
            .chain(admission.command_identities().iter())
            .copied()
        {
            Self::check_request_reference(reference)?;
        }
        Ok(ErasureAttemptQuotaReservationV1::new(
            admission.reference(),
            self.configuration.lifecycle_provenance,
        ))
    }

    fn admit_acknowledgement(
        &self,
        acknowledgement: &ErasureAcknowledgementProvenanceV1,
    ) -> Result<(), ErasureErrorV1> {
        Self::check_request_reference(acknowledgement.request())?;
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
            Self::check_request_reference(reference)?;
        }
        Ok(())
    }

    fn admit_receipt(&self, input: &ErasureReceiptInputV1) -> Result<(), ErasureErrorV1> {
        Self::check_request_reference(input.request)?;
        self.check_policy_trust(input.policy, input.trust)?;
        if !matches!(
            input.lifecycle,
            ErasureLifecycleV1::Complete | ErasureLifecycleV1::PartialFailure
        ) {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        self.check_lifecycle_provenance(input.provenance)?;
        for reference in [
            input.terminal_state,
            input.coordinator,
            input.provenance,
            input.signature,
        ] {
            Self::check_request_reference(reference)?;
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
