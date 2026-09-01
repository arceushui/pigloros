//! Shared coordinator port for public ADR-060 integration tests.

use pos_core::erasure::{target_closure_digest, ErasureAuthorizationDecisionV1};
use pos_core::{
    ErasureAtomicFreezeAdmissionInputV1, ErasureAtomicFreezeAdmissionV1,
    ErasureAtomicFreezeResultV1, ErasureCoordinatorPortV1, ErasureCoordinatorRecordV1,
    ErasureErrorV1, ErasureFreezeAdmissionEvidenceV1, ErasureFreezeAuthorizationEvidenceV1,
    ErasureFreezeAuthorizationVerifierV1, ErasureInventoryCategoryV1, ErasureObligationInputV1,
    ErasureObligationSetInputV1, ErasureObligationSetV1, ErasureObligationV1,
    ErasurePersistencePortV1, ErasureReceiptInputV1, ErasureReferenceV1, ErasureRequestV1,
    ErasureRequiredTargetV1, ErasureScopeCommitmentInputV1, ErasureScopeCommitmentV1,
    ErasureStateResolverV1, ErasureStateTransitionV1, ErasureStateV1,
};

use crate::erasure_support::freeze_evidence_fixture;

pub struct PublicCoordinatorPortConfig {
    pub targets: Vec<ErasureRequiredTargetV1>,
    pub fail_commits: bool,
    pub policy: ErasureReferenceV1,
    pub trust: ErasureReferenceV1,
    pub scope_member: ErasureReferenceV1,
    pub freeze_evidence: ErasureReferenceV1,
}

pub struct PublicCoordinatorPort {
    records: Vec<ErasureCoordinatorRecordV1>,
    states: Vec<ErasureStateV1>,
    config: PublicCoordinatorPortConfig,
}

impl PublicCoordinatorPort {
    #[must_use]
    pub const fn new(config: PublicCoordinatorPortConfig) -> Self {
        Self {
            records: Vec::new(),
            states: Vec::new(),
            config,
        }
    }
}

impl ErasureStateResolverV1 for PublicCoordinatorPort {
    fn resolve_state(
        &self,
        digest: ErasureReferenceV1,
    ) -> Result<Option<ErasureStateV1>, ErasureErrorV1> {
        Ok(self
            .states
            .iter()
            .find(|state| state.state_digest() == digest)
            .cloned())
    }
}

impl ErasurePersistencePortV1 for PublicCoordinatorPort {
    fn load_record(
        &self,
        request: ErasureReferenceV1,
        verifier: &dyn ErasureFreezeAuthorizationVerifierV1,
    ) -> Result<Option<ErasureCoordinatorRecordV1>, ErasureErrorV1> {
        self.records
            .iter()
            .find(|record| record.request().reference() == request)
            .cloned()
            .map(|record| {
                record
                    .state()
                    .verify_predecessor_chain(self)
                    .and_then(|()| record.verify_recovered_freeze_authorization(verifier))
                    .map(|()| record)
            })
            .transpose()
    }

    fn commit_records(
        &mut self,
        records: &[pos_core::VerifiedErasureCoordinatorRecordV1],
    ) -> Result<(), ErasureErrorV1> {
        if self.config.fail_commits {
            return Err(ErasureErrorV1::ReceiptCommitFailed);
        }
        let mut staged_records = self.records.clone();
        let mut staged_states = self.states.clone();
        for verified in records {
            let record = verified.record();
            if let Some(existing) = staged_records
                .iter()
                .find(|existing| existing.request() == record.request())
            {
                if existing != record {
                    existing.validate_replacement(record)?;
                }
            } else if record.state().previous_state().is_some() {
                return Err(ErasureErrorV1::ProvenanceMissing);
            }
            if let Some(existing) = staged_records
                .iter_mut()
                .find(|existing| existing.request() == record.request())
            {
                *existing = record.clone();
            } else {
                staged_records.push(record.clone());
            }
            staged_states.push(record.state().clone());
        }
        self.records = staged_records;
        self.states = staged_states;
        Ok(())
    }

    fn compare_and_swap_scope_extension(
        &mut self,
        request: ErasureReferenceV1,
        expected_ledger: ErasureReferenceV1,
        record: pos_core::VerifiedErasureCoordinatorRecordV1,
    ) -> Result<(), ErasureErrorV1> {
        let current = self
            .load_record(request, self)?
            .ok_or(ErasureErrorV1::ProvenanceMissing)?;
        if current == *record.record() {
            return Ok(());
        }
        if current.scope_extension_ledger() != Some(expected_ledger) {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        self.commit_record(record)
    }

    fn compare_and_swap_administrative_resolution(
        &mut self,
        request: ErasureReferenceV1,
        expected_head: Option<ErasureReferenceV1>,
        record: pos_core::VerifiedErasureCoordinatorRecordV1,
    ) -> Result<(), ErasureErrorV1> {
        let current = self
            .load_record(request, self)?
            .ok_or(ErasureErrorV1::ProvenanceMissing)?;
        if current == *record.record() {
            return Ok(());
        }
        if current.administrative_resolution_head() != expected_head {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        self.commit_record(record)
    }
}

impl ErasureFreezeAuthorizationVerifierV1 for PublicCoordinatorPort {
    fn validate_freeze_authorization(
        &self,
        admission: &ErasureFreezeAdmissionEvidenceV1,
        authorization: &ErasureFreezeAuthorizationEvidenceV1,
    ) -> Result<(), ErasureErrorV1> {
        (authorization.admission_body_digest() == admission.authorization_body_digest()?)
            .then_some(())
            .ok_or(ErasureErrorV1::Unauthorized)
    }
}

impl ErasureCoordinatorPortV1 for PublicCoordinatorPort {
    fn authenticate(&self, _request: &ErasureRequestV1) -> Result<(), ErasureErrorV1> {
        Ok(())
    }

    fn admit_authorization(
        &self,
        _request: ErasureReferenceV1,
        _provenance: ErasureReferenceV1,
        _decision: ErasureAuthorizationDecisionV1,
    ) -> Result<(), ErasureErrorV1> {
        Ok(())
    }

    fn admit_corrected_submission(
        &self,
        _request: &ErasureRequestV1,
        _correction: &pos_core::ErasureCorrectionProvenanceV1,
    ) -> Result<(), ErasureErrorV1> {
        Ok(())
    }

    fn admit_atomic_freeze(
        &self,
        request: ErasureReferenceV1,
        _requested: &ErasureStateTransitionV1,
    ) -> Result<ErasureAtomicFreezeResultV1, ErasureErrorV1> {
        let mut obligations = self
            .config
            .targets
            .iter()
            .copied()
            .map(|target| {
                ErasureObligationV1::new(ErasureObligationInputV1 {
                    category: ErasureInventoryCategoryV1::Artifact,
                    target,
                    owner: target.replica_id,
                    command_identity: pos_core::destruction_command_reference(request, target),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        obligations.sort_unstable_by_key(ErasureObligationV1::reference);
        let obligation_set = ErasureObligationSetV1::new(ErasureObligationSetInputV1 {
            request,
            obligations: obligations
                .iter()
                .map(ErasureObligationV1::reference)
                .collect(),
            policy: self.config.policy,
            trust: self.config.trust,
        })?;
        let scope = ErasureScopeCommitmentInputV1 {
            request,
            scope_members: vec![self.config.scope_member],
            target_closure: target_closure_digest(&self.config.targets),
            lineage_rule: None,
        };
        let (freeze_admission_evidence, freeze_authorization_evidence) = freeze_evidence_fixture(
            request,
            ErasureScopeCommitmentV1::new(scope.clone())?.reference(),
            &obligation_set,
            &self.config.targets,
            &obligations,
            10,
            &self.config.freeze_evidence.digest(),
        )?;
        ErasureAtomicFreezeAdmissionV1::new(ErasureAtomicFreezeAdmissionInputV1 {
            targets: self.config.targets.clone(),
            scope,
            obligations,
            obligation_set,
            freeze_position: 10,
            freeze_admission_evidence,
            freeze_authorization_evidence,
        })
        .map(Box::new)
        .map(ErasureAtomicFreezeResultV1::Admitted)
    }

    fn dispatch_destruction(
        &self,
        _request: ErasureReferenceV1,
        _commands: &[pos_core::ErasureDestructionCommandV1],
    ) -> Result<(), ErasureErrorV1> {
        Ok(())
    }

    fn admit_attempt(
        &self,
        _admission: &pos_core::ErasureRetryAdmissionV1,
    ) -> Result<(), ErasureErrorV1> {
        Ok(())
    }

    fn admit_acknowledgement(
        &self,
        _acknowledgement: &pos_core::ErasureAcknowledgementProvenanceV1,
    ) -> Result<(), ErasureErrorV1> {
        Ok(())
    }

    fn admit_receipt(&self, _input: &ErasureReceiptInputV1) -> Result<(), ErasureErrorV1> {
        Ok(())
    }

    fn admit_scope_extension(
        &self,
        _extension: &pos_core::ErasureScopeExtensionV1,
    ) -> Result<(), ErasureErrorV1> {
        Ok(())
    }

    fn admit_administrative_resolution(
        &self,
        _resolution: &pos_core::ErasureAdministrativeResolutionV1,
    ) -> Result<(), ErasureErrorV1> {
        Ok(())
    }
}
