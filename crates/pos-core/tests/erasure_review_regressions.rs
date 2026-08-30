//! Public-interface regressions for ADR-060 review findings.

use ciborium::value::Value;
use pos_core::erasure::{target_closure_digest, ErasureAuthorizationDecisionV1};
use pos_core::{
    acknowledgement_inventory_reference, destruction_command_reference,
    erasure_evidence_set_reference, selected_obligations_reference,
    ErasureAcknowledgementOutcomeV1, ErasureAcknowledgementProvenanceInputV1,
    ErasureAcknowledgementProvenanceV1, ErasureAcknowledgementV1, ErasureArtifactClassV1,
    ErasureArtifactTransitionV1, ErasureAtomicFreezeAdmissionInputV1,
    ErasureAtomicFreezeAdmissionV1, ErasureAtomicFreezeResultV1, ErasureAttemptOutcomeInputV1,
    ErasureAttemptOutcomeV1, ErasureCoordinatorPortV1, ErasureCoordinatorRecordV1,
    ErasureCoordinatorStateMachineV1, ErasureErrorV1, ErasureInventoryCategoryV1,
    ErasureInventoryResultV1, ErasureKeyRoleV1, ErasureLifecycleV1, ErasureObligationInputV1,
    ErasureObligationSetInputV1, ErasureObligationSetV1, ErasureObligationV1,
    ErasurePersistencePortV1, ErasureReceiptInputV1, ErasureReceiptInventoriesV1,
    ErasureReceiptProvenanceInputV1, ErasureReceiptProvenanceV1, ErasureReceiptV1,
    ErasureReferenceV1, ErasureReplayClaimV1, ErasureRequestInputV1, ErasureRequestV1,
    ErasureRequiredTargetV1, ErasureRetryAdmissionInputV1, ErasureRetryAdmissionV1,
    ErasureScopeCommitmentInputV1, ErasureScopeV1, ErasureStateResolverV1,
    ErasureStateTransitionV1, ErasureStateV1, ErasureSupportingRecordsInputV1,
    ErasureSupportingRecordsV1, ERASURE_PORTABLE_RECORD_MAX_BYTES,
};

const fn reference(value: u8) -> ErasureReferenceV1 {
    ErasureReferenceV1::from_digest([value; 32])
}

const fn target() -> ErasureRequiredTargetV1 {
    ErasureRequiredTargetV1 {
        artifact_class: ErasureArtifactClassV1::TimelineReplay,
        artifact_digest: reference(10),
        key_role: ErasureKeyRoleV1::DataEncryption,
        key_digest: reference(11),
        replica_set: reference(12),
        replica_id: reference(13),
    }
}

const fn second_target() -> ErasureRequiredTargetV1 {
    ErasureRequiredTargetV1 {
        artifact_class: ErasureArtifactClassV1::TimelineReplay,
        artifact_digest: reference(14),
        key_role: ErasureKeyRoleV1::DataEncryption,
        key_digest: reference(15),
        replica_set: reference(16),
        replica_id: reference(17),
    }
}

fn request() -> Result<ErasureRequestV1, ErasureErrorV1> {
    ErasureRequestV1::new(ErasureRequestInputV1 {
        request: reference(1),
        subject: reference(2),
        scope: ErasureScopeV1::PrivateSubjectData,
        selectors: vec![reference(3)],
        requester: reference(4),
        authorization: reference(5),
        policy: reference(6),
        request_position: 9,
        horizon_position: 10,
        provenance: reference(7),
    })
}

const fn inventory(owner: ErasureReferenceV1) -> ErasureInventoryResultV1 {
    inventory_for_target(target(), owner)
}

const fn inventory_for_target(
    target: ErasureRequiredTargetV1,
    owner: ErasureReferenceV1,
) -> ErasureInventoryResultV1 {
    ErasureInventoryResultV1 {
        category: ErasureInventoryCategoryV1::Artifact,
        target,
        transition: ErasureArtifactTransitionV1 {
            from: ErasureReplayClaimV1::Exact,
            to: ErasureReplayClaimV1::StructuralOnly,
            reason: reference(20),
            owner,
            acknowledgements: reference(21),
            provenance: reference(22),
        },
        retained_disclosure: reference(23),
    }
}

fn acknowledgement(
    owner: ErasureReferenceV1,
    evidence: ErasureReferenceV1,
) -> Result<ErasureAcknowledgementV1, ErasureErrorV1> {
    acknowledgement_for_target(target(), owner, evidence)
}

fn acknowledgement_for_target(
    target: ErasureRequiredTargetV1,
    owner: ErasureReferenceV1,
    evidence: ErasureReferenceV1,
) -> Result<ErasureAcknowledgementV1, ErasureErrorV1> {
    let inventory = inventory_for_target(target, owner);
    let obligation = obligation_for(reference(1), target, owner)?;
    Ok(ErasureAcknowledgementV1 {
        obligation: obligation.reference(),
        target: inventory.target,
        owner,
        evidence,
        outcome: ErasureAcknowledgementOutcomeV1::Acknowledged,
    })
}

fn obligation_for(
    request: ErasureReferenceV1,
    target: ErasureRequiredTargetV1,
    owner: ErasureReferenceV1,
) -> Result<ErasureObligationV1, ErasureErrorV1> {
    ErasureObligationV1::new(ErasureObligationInputV1 {
        category: ErasureInventoryCategoryV1::Artifact,
        target,
        owner,
        command_identity: destruction_command_reference(request, target),
    })
}

fn scope_for(
    request: ErasureReferenceV1,
    targets: &[ErasureRequiredTargetV1],
) -> Result<pos_core::ErasureScopeCommitmentV1, ErasureErrorV1> {
    pos_core::ErasureScopeCommitmentV1::new(ErasureScopeCommitmentInputV1 {
        request,
        scope_members: vec![reference(2)],
        target_closure: target_closure_digest(targets),
        lineage_rule: None,
    })
}

fn obligation_set(
    request: ErasureReferenceV1,
    obligations: &[ErasureObligationV1],
) -> Result<ErasureObligationSetV1, ErasureErrorV1> {
    ErasureObligationSetV1::new(ErasureObligationSetInputV1 {
        request,
        obligations: obligations
            .iter()
            .map(ErasureObligationV1::reference)
            .collect(),
        policy: reference(6),
        trust: reference(7),
    })
}

fn retry_admission(
    request: ErasureReferenceV1,
    obligations: Vec<ErasureReferenceV1>,
    commands: Vec<ErasureReferenceV1>,
) -> Result<ErasureRetryAdmissionV1, ErasureErrorV1> {
    ErasureRetryAdmissionV1::new(ErasureRetryAdmissionInputV1 {
        request,
        attempt_ordinal: 0,
        source_receipt: None,
        unresolved_obligations: obligations,
        command_identities: commands,
        policy: reference(6),
        trust: reference(7),
        admitted_position: 10,
        deadline_position: 20,
        authorization_provenance: reference(8),
    })
}

fn acknowledgement_provenance(
    request: ErasureReferenceV1,
    attempt: ErasureReferenceV1,
    obligation: ErasureReferenceV1,
    command: ErasureReferenceV1,
    owner: ErasureReferenceV1,
    scope: ErasureReferenceV1,
) -> Result<ErasureAcknowledgementProvenanceV1, ErasureErrorV1> {
    ErasureAcknowledgementProvenanceV1::new(ErasureAcknowledgementProvenanceInputV1 {
        request,
        command,
        attempt,
        obligation,
        owner,
        scope,
        outcome: ErasureAcknowledgementOutcomeV1::Acknowledged,
        evidence: reference(24),
        policy: reference(6),
        trust: reference(7),
    })
}

fn active_supporting_records(
    request: ErasureReferenceV1,
) -> Result<ErasureSupportingRecordsV1, ErasureErrorV1> {
    let targets = [target(), second_target()];
    let scope = scope_for(request, &targets)?;
    let mut obligations = vec![
        obligation_for(request, targets[0], reference(34))?,
        obligation_for(request, targets[1], reference(35))?,
    ];
    obligations.sort_unstable_by_key(ErasureObligationV1::reference);
    let obligation_set = obligation_set(request, &obligations)?;
    let admission = retry_admission(
        request,
        obligations
            .iter()
            .map(ErasureObligationV1::reference)
            .collect(),
        obligations
            .iter()
            .map(ErasureObligationV1::command_identity)
            .collect(),
    )?;
    let attempt = admission.reference();
    let mut acknowledgements = obligations
        .iter()
        .map(|obligation| {
            acknowledgement_provenance(
                request,
                attempt,
                obligation.reference(),
                obligation.command_identity(),
                obligation.owner(),
                scope.reference(),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    acknowledgements.sort_unstable_by_key(|acknowledgement| {
        (
            acknowledgement.command(),
            acknowledgement.attempt(),
            acknowledgement.owner(),
            acknowledgement.reference(),
        )
    });
    ErasureSupportingRecordsV1::new(ErasureSupportingRecordsInputV1 {
        scope_commitment: Some(scope),
        obligations: obligations.clone(),
        obligation_set: Some(obligation_set),
        retry_admissions: vec![admission],
        acknowledgement_provenance: acknowledgements,
        ..ErasureSupportingRecordsInputV1::default()
    })
}

fn mutate_acknowledgement_provenance(
    bytes: &[u8],
    mutate: impl FnOnce(&mut Vec<Value>) -> Result<(), ErasureErrorV1>,
) -> Result<Vec<u8>, ErasureErrorV1> {
    let value: Value = ciborium::from_reader(bytes).map_err(|_| ErasureErrorV1::InvalidEncoding)?;
    let Value::Array(mut supporting_fields) = value else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    let provenance = supporting_fields
        .get_mut(5)
        .ok_or(ErasureErrorV1::InvalidEncoding)?;
    let Value::Array(provenance) = provenance else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    mutate(provenance)?;
    let mut changed = Vec::new();
    ciborium::into_writer(&Value::Array(supporting_fields), &mut changed)
        .map_err(|_| ErasureErrorV1::InvalidEncoding)?;
    Ok(changed)
}

fn replace_supporting_record_field(
    bytes: &[u8],
    index: usize,
    replacement: Value,
) -> Result<Vec<u8>, ErasureErrorV1> {
    let value: Value = ciborium::from_reader(bytes).map_err(|_| ErasureErrorV1::InvalidEncoding)?;
    let Value::Array(mut fields) = value else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    let field = fields
        .get_mut(index)
        .ok_or(ErasureErrorV1::InvalidEncoding)?;
    *field = replacement;
    let mut changed = Vec::new();
    ciborium::into_writer(&Value::Array(fields), &mut changed)
        .map_err(|_| ErasureErrorV1::InvalidEncoding)?;
    Ok(changed)
}

#[test]
fn coordinator_decoder_rejects_reordered_or_duplicate_supporting_acknowledgements(
) -> Result<(), ErasureErrorV1> {
    let bytes = active_supporting_records(reference(1))?.to_canonical_cbor()?;

    let reordered = mutate_acknowledgement_provenance(&bytes, |provenance| {
        provenance.reverse();
        Ok(())
    })?;
    assert!(ErasureSupportingRecordsV1::from_canonical_cbor(&reordered).is_err());

    let duplicated = mutate_acknowledgement_provenance(&bytes, |provenance| {
        let first = provenance
            .first()
            .cloned()
            .ok_or(ErasureErrorV1::InvalidEncoding)?;
        provenance.push(first);
        Ok(())
    })?;
    assert!(ErasureSupportingRecordsV1::from_canonical_cbor(&duplicated).is_err());
    Ok(())
}

#[test]
fn supporting_records_roundtrip_canonically_and_reject_trailing_bytes() -> Result<(), ErasureErrorV1>
{
    let records = active_supporting_records(reference(1))?;
    let bytes = records.to_canonical_cbor()?;
    assert_eq!(
        ErasureSupportingRecordsV1::from_canonical_cbor(&bytes)?,
        records
    );

    let mut trailing = bytes;
    trailing.push(0);
    assert_eq!(
        ErasureSupportingRecordsV1::from_canonical_cbor(&trailing),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    Ok(())
}

#[test]
fn public_decoders_reject_malformed_and_oversized_evidence() -> Result<(), ErasureErrorV1> {
    let bytes = active_supporting_records(reference(1))?.to_canonical_cbor()?;
    let malformed = replace_supporting_record_field(&bytes, 1, Value::Bool(false))?;
    assert!(ErasureSupportingRecordsV1::from_canonical_cbor(&malformed).is_err());

    let oversized = vec![0; ERASURE_PORTABLE_RECORD_MAX_BYTES + 1];
    assert_eq!(
        ErasureAcknowledgementProvenanceV1::from_canonical_cbor(&oversized),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    Ok(())
}

#[test]
fn supporting_acknowledgement_must_keep_its_admitted_obligation_command_pair(
) -> Result<(), ErasureErrorV1> {
    let request = reference(1);
    let targets = [target(), second_target()];
    let scope = scope_for(request, &targets)?;
    let mut obligations = vec![
        obligation_for(request, targets[0], reference(54))?,
        obligation_for(request, targets[1], reference(55))?,
    ];
    obligations.sort_unstable_by_key(ErasureObligationV1::reference);
    let first = obligations[0];
    let second = obligations[1];
    let admission = retry_admission(
        request,
        obligations
            .iter()
            .map(ErasureObligationV1::reference)
            .collect(),
        obligations
            .iter()
            .map(ErasureObligationV1::command_identity)
            .collect(),
    )?;
    let attempt = admission.reference();
    let correctly_paired = ErasureSupportingRecordsInputV1 {
        scope_commitment: Some(scope.clone()),
        obligations: obligations.clone(),
        obligation_set: Some(obligation_set(request, &obligations)?),
        retry_admissions: vec![admission],
        acknowledgement_provenance: vec![acknowledgement_provenance(
            request,
            attempt,
            first.reference(),
            first.command_identity(),
            first.owner(),
            scope.reference(),
        )?],
        ..ErasureSupportingRecordsInputV1::default()
    };
    assert!(ErasureSupportingRecordsV1::new(correctly_paired.clone()).is_ok());

    let mismatched_pair = ErasureSupportingRecordsInputV1 {
        acknowledgement_provenance: vec![acknowledgement_provenance(
            request,
            attempt,
            first.reference(),
            second.command_identity(),
            first.owner(),
            scope.reference(),
        )?],
        ..correctly_paired
    };
    assert_eq!(
        ErasureSupportingRecordsV1::new(mismatched_pair),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}

fn receipt_provenance(
    request: ErasureReferenceV1,
    attempt: ErasureReferenceV1,
) -> Result<ErasureReceiptProvenanceV1, ErasureErrorV1> {
    let obligation = obligation_for(request, target(), reference(70))?;
    let scope = scope_for(request, &[target()])?;
    let acknowledgement = acknowledgement_provenance(
        request,
        attempt,
        obligation.reference(),
        obligation.command_identity(),
        obligation.owner(),
        scope.reference(),
    )?;
    ErasureReceiptProvenanceV1::new(ErasureReceiptProvenanceInputV1 {
        request,
        attempt,
        attempt_ordinal: 0,
        predecessor_receipt: None,
        terminal_state: reference(60),
        evidence_set: erasure_evidence_set_reference(&[acknowledgement.reference()]),
        policy: reference(6),
        trust: reference(7),
        issue_position: 20,
    })
}

fn complete_receipt(
    request: ErasureReferenceV1,
    provenance: ErasureReferenceV1,
    owner: ErasureReferenceV1,
) -> Result<ErasureReceiptV1, ErasureErrorV1> {
    let inventory = inventory(owner);
    let obligation = ErasureObligationV1::new(ErasureObligationInputV1 {
        category: ErasureInventoryCategoryV1::Artifact,
        target: inventory.target,
        owner,
        command_identity: destruction_command_reference(request, inventory.target),
    })?;
    ErasureReceiptV1::new(ErasureReceiptInputV1 {
        request,
        terminal_state: reference(60),
        coordinator: reference(62),
        lifecycle: ErasureLifecycleV1::Complete,
        freeze_position: 10,
        frozen_targets: vec![inventory.target],
        acknowledgements: vec![ErasureAcknowledgementV1 {
            obligation: obligation.reference(),
            target: inventory.target,
            owner,
            evidence: reference(24),
            outcome: ErasureAcknowledgementOutcomeV1::Acknowledged,
        }],
        pending_owners: Vec::new(),
        failed_owners: Vec::new(),
        inventories: ErasureReceiptInventoriesV1 {
            artifacts: vec![inventory],
            keys: Vec::new(),
            replicas: Vec::new(),
            backups: Vec::new(),
        },
        replay_claim: ErasureReplayClaimV1::Exact,
        policy: reference(6),
        trust: reference(7),
        provenance,
        issue_position: 20,
        signature: reference(64),
        receipt_digest: reference(0),
    })
}

fn terminal_supporting_records(
    receipt: ErasureReceiptV1,
    receipt_provenance: &ErasureReceiptProvenanceV1,
) -> Result<ErasureSupportingRecordsV1, ErasureErrorV1> {
    let request = reference(1);
    let owner = receipt.acknowledgements()[0].owner;
    let obligation = obligation_for(request, target(), owner)?;
    let scope = scope_for(request, &[target()])?;
    let obligations = vec![obligation];
    let admission = retry_admission(
        request,
        vec![obligation.reference()],
        vec![obligation.command_identity()],
    )?;
    let attempt = admission.reference();
    let acknowledgement = acknowledgement_provenance(
        request,
        attempt,
        obligation.reference(),
        obligation.command_identity(),
        obligation.owner(),
        scope.reference(),
    )?;
    let acknowledgement_reference = acknowledgement.reference();
    ErasureSupportingRecordsV1::new(ErasureSupportingRecordsInputV1 {
        scope_commitment: Some(scope),
        obligations: obligations.clone(),
        obligation_set: Some(obligation_set(request, &obligations)?),
        retry_admissions: vec![admission],
        acknowledgement_provenance: vec![acknowledgement],
        attempt_outcomes: vec![ErasureAttemptOutcomeV1::new(
            ErasureAttemptOutcomeInputV1 {
                request,
                attempt,
                source_receipt: None,
                lifecycle: ErasureLifecycleV1::Complete,
                selected_obligations: selected_obligations_reference(&[obligation.reference()]),
                acknowledgement_inventory: acknowledgement_inventory_reference(&[
                    acknowledgement_reference,
                ]),
                terminal_position: 20,
                policy: reference(6),
                trust: reference(7),
            },
        )?],
        receipts: vec![receipt],
        receipt_provenance: vec![*receipt_provenance],
        ..ErasureSupportingRecordsInputV1::default()
    })
}

#[test]
fn supporting_ledger_binds_each_receipt_to_its_receipt_provenance() -> Result<(), ErasureErrorV1> {
    let owner = reference(70);
    let obligation = obligation_for(reference(1), target(), owner)?;
    let admission = retry_admission(
        reference(1),
        vec![obligation.reference()],
        vec![obligation.command_identity()],
    )?;
    let receipt_provenance = receipt_provenance(reference(1), admission.reference())?;
    let bound_receipt = complete_receipt(reference(1), receipt_provenance.reference(), owner)?;
    assert!(terminal_supporting_records(bound_receipt, &receipt_provenance).is_ok());

    let unbound_receipt = complete_receipt(reference(1), reference(71), owner)?;
    assert_eq!(
        terminal_supporting_records(unbound_receipt, &receipt_provenance),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}

#[test]
fn receipt_accepts_an_inventory_owner_independent_of_the_target_replica(
) -> Result<(), ErasureErrorV1> {
    let owner = reference(80);
    assert_ne!(owner, target().replica_id);
    let receipt = complete_receipt(reference(1), reference(81), owner)?;
    assert_eq!(receipt.acknowledgements()[0].owner, owner);
    assert_eq!(receipt.inventories().artifacts[0].transition.owner, owner);
    Ok(())
}

struct PublicPort {
    records: Vec<ErasureCoordinatorRecordV1>,
    states: Vec<ErasureStateV1>,
    targets: Vec<ErasureRequiredTargetV1>,
    fail_commits: bool,
}

impl ErasureStateResolverV1 for PublicPort {
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

impl ErasurePersistencePortV1 for PublicPort {
    fn load_record(
        &self,
        request: ErasureReferenceV1,
    ) -> Result<Option<ErasureCoordinatorRecordV1>, ErasureErrorV1> {
        Ok(self
            .records
            .iter()
            .find(|record| record.request().reference() == request)
            .cloned())
    }

    fn commit_record(&mut self, record: ErasureCoordinatorRecordV1) -> Result<(), ErasureErrorV1> {
        self.commit_records(std::slice::from_ref(&record))
    }

    fn commit_records(
        &mut self,
        records: &[ErasureCoordinatorRecordV1],
    ) -> Result<(), ErasureErrorV1> {
        if self.fail_commits {
            return Err(ErasureErrorV1::ReceiptCommitFailed);
        }
        let mut staged_records = self.records.clone();
        let mut staged_states = self.states.clone();
        for record in records {
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
        _request: ErasureReferenceV1,
        _expected_ledger: ErasureReferenceV1,
        record: ErasureCoordinatorRecordV1,
    ) -> Result<(), ErasureErrorV1> {
        self.commit_record(record)
    }

    fn compare_and_swap_administrative_resolution(
        &mut self,
        _request: ErasureReferenceV1,
        _expected_head: Option<ErasureReferenceV1>,
        record: ErasureCoordinatorRecordV1,
    ) -> Result<(), ErasureErrorV1> {
        self.commit_record(record)
    }
}

fn public_port(fail_commits: bool) -> PublicPort {
    public_port_with_targets(fail_commits, vec![target()])
}

const fn public_port_with_targets(
    fail_commits: bool,
    targets: Vec<ErasureRequiredTargetV1>,
) -> PublicPort {
    PublicPort {
        records: Vec::new(),
        states: Vec::new(),
        targets,
        fail_commits,
    }
}

impl ErasureCoordinatorPortV1 for PublicPort {
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
        let target = self.targets[0];
        let obligation = ErasureObligationV1::new(ErasureObligationInputV1 {
            category: ErasureInventoryCategoryV1::Artifact,
            target,
            owner: target.replica_id,
            command_identity: destruction_command_reference(request, target),
        })?;
        let obligation_set = ErasureObligationSetV1::new(ErasureObligationSetInputV1 {
            request,
            obligations: vec![obligation.reference()],
            policy: reference(6),
            trust: reference(7),
        })?;
        ErasureAtomicFreezeAdmissionV1::new(ErasureAtomicFreezeAdmissionInputV1 {
            targets: vec![target],
            scope: ErasureScopeCommitmentInputV1 {
                request,
                scope_members: vec![reference(3)],
                target_closure: target_closure_digest(&[target]),
                lineage_rule: None,
            },
            obligations: vec![obligation],
            obligation_set,
            freeze_position: 10,
            host_evidence: reference(90),
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
        _acknowledgement: &ErasureAcknowledgementProvenanceV1,
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

const fn access_freeze_transition() -> ErasureStateTransitionV1 {
    ErasureStateTransitionV1 {
        lifecycle: ErasureLifecycleV1::AccessFrozen,
        freeze_position: Some(10),
        pending_owners: Vec::new(),
        failed_owners: Vec::new(),
        acknowledged_targets: Vec::new(),
        replay_claim: ErasureReplayClaimV1::Exact,
        provenance: reference(90),
    }
}

fn state_after_acknowledgements(
    acknowledgements: &[ErasureAcknowledgementV1; 2],
) -> Result<ErasureStateV1, ErasureErrorV1> {
    let submitted_request = request()?;
    let request_reference = submitted_request.reference();
    let targets = acknowledgements
        .iter()
        .map(|acknowledgement| acknowledgement.target)
        .collect();
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(
        public_port_with_targets(false, targets),
        reference(91),
    );
    coordinator.submit(submitted_request, reference(92))?;
    coordinator.authorize(request_reference, reference(93))?;
    coordinator.freeze_inventory(request_reference, access_freeze_transition())?;
    let admission = ErasureRetryAdmissionV1::new(ErasureRetryAdmissionInputV1 {
        request: request_reference,
        attempt_ordinal: 0,
        source_receipt: None,
        unresolved_obligations: acknowledgements
            .iter()
            .map(|acknowledgement| acknowledgement.obligation)
            .collect(),
        command_identities: acknowledgements
            .iter()
            .map(|acknowledgement| {
                destruction_command_reference(request_reference, acknowledgement.target)
            })
            .collect(),
        policy: reference(6),
        trust: reference(94),
        admitted_position: 9,
        deadline_position: 10,
        authorization_provenance: reference(94),
    })?;
    coordinator.dispatch_attempt(request_reference, &admission)?;
    for acknowledgement in acknowledgements.iter().copied() {
        coordinator.acknowledge(request_reference, acknowledgement)?;
    }
    coordinator
        .existing(request_reference)
        .cloned()
        .ok_or(ErasureErrorV1::ProvenanceMissing)
}

#[test]
fn public_coordinator_rejects_conflicting_retries_and_propagates_commit_failure(
) -> Result<(), ErasureErrorV1> {
    let submitted_request = request()?;
    let request_reference = submitted_request.reference();
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(public_port(false), reference(91));
    coordinator.submit(submitted_request, reference(92))?;
    coordinator.authorize(request_reference, reference(93))?;
    assert_eq!(
        coordinator.authorize(request_reference, reference(99)),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let mut commit_failure =
        ErasureCoordinatorStateMachineV1::new(public_port(true), reference(91));
    assert_eq!(
        commit_failure.submit(request()?, reference(92)),
        Err(ErasureErrorV1::ReceiptCommitFailed)
    );
    Ok(())
}

#[test]
fn coordinator_acknowledgement_arrival_order_does_not_change_ers1_identity(
) -> Result<(), ErasureErrorV1> {
    let first = acknowledgement(reference(95), reference(96))?;
    let second = acknowledgement_for_target(second_target(), reference(97), reference(98))?;
    let forward = state_after_acknowledgements(&[first, second])?;
    let reverse = state_after_acknowledgements(&[second, first])?;
    assert_eq!(forward, reverse);
    assert_eq!(forward.state_digest(), reverse.state_digest());
    Ok(())
}
