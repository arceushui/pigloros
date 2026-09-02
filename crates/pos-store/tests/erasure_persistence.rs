//! Backend parity for the raw ERCRP1 manifest/CAS persistence port.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use pos_core::erasure::{
    destruction_command_reference, target_closure_digest, ErasureAuthorizationDecisionV1,
};
use pos_core::{
    ErasureAcknowledgementOutcomeV1, ErasureAcknowledgementProvenanceV1, ErasureAcknowledgementV1,
    ErasureArtifactClassV1, ErasureArtifactTransitionV1, ErasureAtomicFreezeAdmissionInputV1,
    ErasureAtomicFreezeAdmissionV1, ErasureAtomicFreezeResultV1, ErasureAttemptQuotaReservationV1,
    ErasureCoordinatorPortV1, ErasureCoordinatorStateMachineV1, ErasureDestructionCommandV1,
    ErasureErrorV1, ErasureFreezeAdmissionEvidenceInputV1, ErasureFreezeAdmissionEvidenceV1,
    ErasureFreezeApplicabilityRowV1, ErasureFreezeAuthorizationEvidenceInputV1,
    ErasureFreezeAuthorizationEvidenceV1, ErasureFreezeAuthorizationVerifierV1,
    ErasureIndexInsertV1, ErasureInventoryCategoryV1, ErasureInventoryResultV1, ErasureKeyRoleV1,
    ErasureLifecycleV1, ErasureObligationInputV1, ErasureObligationSetInputV1,
    ErasureObligationSetV1, ErasureObligationV1, ErasurePersistencePortV1, ErasureReceiptInputV1,
    ErasureReceiptInventoriesV1, ErasureReferenceV1, ErasureReplayClaimV1, ErasureRequestInputV1,
    ErasureRequestV1, ErasureRequiredTargetV1, ErasureRetryAdmissionInputV1,
    ErasureRetryAdmissionV1, ErasureScopeCommitmentInputV1, ErasureScopeCommitmentV1,
    ErasureScopeExtensionV1, ErasureScopeV1, ErasureStateResolverV1, ErasureStateTransitionV1,
    ErasureStateV1,
};
use pos_store::memory::MemoryStore;

#[cfg(feature = "sqlite")]
use pos_store::sqlite::SqliteStore;

const fn reference(value: u8) -> ErasureReferenceV1 {
    ErasureReferenceV1::from_digest([value; 32])
}

fn freeze_evidence(
    request: ErasureReferenceV1,
    scope_commitment: ErasureReferenceV1,
    obligation_set: &ErasureObligationSetV1,
    targets: &[ErasureRequiredTargetV1],
    obligations: &[ErasureObligationV1],
    freeze_position: u64,
    evidence: &[u8],
) -> Result<
    (
        ErasureFreezeAdmissionEvidenceV1,
        ErasureFreezeAuthorizationEvidenceV1,
    ),
    ErasureErrorV1,
> {
    let owners = obligations
        .iter()
        .map(|obligation| {
            (
                (obligation.category(), obligation.target()),
                obligation.owner(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut matrix = Vec::with_capacity(targets.len().saturating_mul(4));
    for category in ErasureInventoryCategoryV1::CANONICAL {
        for (target_index, target) in targets.iter().enumerate() {
            let owner = owners.get(&(category, *target)).copied();
            matrix.push(ErasureFreezeApplicabilityRowV1::new(
                category,
                target_index as u64,
                if owner.is_some() {
                    pos_core::ErasureApplicabilityDecisionV1::Applicable
                } else {
                    pos_core::ErasureApplicabilityDecisionV1::Inapplicable
                },
                owner,
            )?);
        }
    }
    let input = ErasureFreezeAdmissionEvidenceInputV1 {
        request,
        scope_commitment,
        obligation_set: obligation_set.reference(),
        applicability_matrix: matrix,
        freeze_position,
        policy: obligation_set.policy(),
        trust: obligation_set.trust(),
        authorization_provenance: reference(0),
    };
    let provisional = ErasureFreezeAdmissionEvidenceV1::new(input.clone())?;
    let authorization =
        ErasureFreezeAuthorizationEvidenceV1::new(ErasureFreezeAuthorizationEvidenceInputV1 {
            admission_body_digest: provisional.authorization_body_digest()?,
            policy: obligation_set.policy(),
            trust: obligation_set.trust(),
            evidence: evidence.to_vec(),
        })?;
    let admission = ErasureFreezeAdmissionEvidenceV1::new(ErasureFreezeAdmissionEvidenceInputV1 {
        authorization_provenance: authorization.reference(),
        ..input
    })?;
    Ok((admission, authorization))
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
        horizon_position: 20,
        provenance: reference(7),
    })
}

fn admission(
    request: ErasureReferenceV1,
    target: ErasureRequiredTargetV1,
) -> Result<ErasureRetryAdmissionV1, ErasureErrorV1> {
    let obligation = ErasureObligationV1::new(ErasureObligationInputV1 {
        category: ErasureInventoryCategoryV1::Artifact,
        target,
        owner: target.replica_id,
        command_identity: destruction_command_reference(request, target),
    })?;
    ErasureRetryAdmissionV1::new(ErasureRetryAdmissionInputV1 {
        request,
        attempt_ordinal: 0,
        source_receipt: None,
        unresolved_obligations: vec![obligation.reference()],
        command_identities: vec![obligation.command_identity()],
        policy: reference(6),
        trust: reference(8),
        admitted_position: 11,
        deadline_position: 20,
        authorization_provenance: reference(12),
    })
}

fn obligation(
    request: ErasureReferenceV1,
    target: ErasureRequiredTargetV1,
) -> Result<ErasureObligationV1, ErasureErrorV1> {
    ErasureObligationV1::new(ErasureObligationInputV1 {
        category: ErasureInventoryCategoryV1::Artifact,
        target,
        owner: target.replica_id,
        command_identity: destruction_command_reference(request, target),
    })
}

const fn inventory(target: ErasureRequiredTargetV1) -> ErasureInventoryResultV1 {
    ErasureInventoryResultV1 {
        category: ErasureInventoryCategoryV1::Artifact,
        target,
        transition: ErasureArtifactTransitionV1 {
            from: ErasureReplayClaimV1::Exact,
            to: ErasureReplayClaimV1::StructuralOnly,
            reason: reference(20),
            owner: target.replica_id,
            acknowledgements: reference(21),
            provenance: reference(22),
        },
        retained_disclosure: reference(23),
    }
}

const fn transition() -> ErasureStateTransitionV1 {
    ErasureStateTransitionV1 {
        lifecycle: ErasureLifecycleV1::AccessFrozen,
        freeze_position: Some(10),
        pending_owners: Vec::new(),
        failed_owners: Vec::new(),
        acknowledged_targets: Vec::new(),
        replay_claim: ErasureReplayClaimV1::Exact,
        provenance: reference(11),
    }
}

struct Host<S> {
    store: Rc<RefCell<S>>,
    targets: Vec<ErasureRequiredTargetV1>,
}

impl<S: ErasurePersistencePortV1> ErasureStateResolverV1 for Host<S> {
    fn resolve_state(
        &self,
        digest: ErasureReferenceV1,
    ) -> Result<Option<ErasureStateV1>, ErasureErrorV1> {
        self.store.borrow().resolve_state(digest)
    }
}

impl<S: ErasurePersistencePortV1> ErasurePersistencePortV1 for Host<S> {
    fn read_manifest(
        &self,
        request: ErasureReferenceV1,
    ) -> Result<Option<pos_core::StoredErasureManifestV1>, ErasureErrorV1> {
        self.store.borrow().read_manifest(request)
    }

    fn read_object(&self, reference: ErasureReferenceV1) -> Result<Vec<u8>, ErasureErrorV1> {
        self.store.borrow().read_object(reference)
    }

    fn read_effect(
        &self,
        manifest: ErasureReferenceV1,
    ) -> Result<pos_core::ErasureCasEffectV1, ErasureErrorV1> {
        self.store.borrow().read_effect(manifest)
    }

    fn effect_manifest(
        &self,
        subject: ErasureReferenceV1,
    ) -> Result<Option<ErasureReferenceV1>, ErasureErrorV1> {
        self.store.borrow().effect_manifest(subject)
    }

    fn attempt_page_ref(
        &self,
        request: ErasureReferenceV1,
        ordinal: u64,
    ) -> Result<Option<ErasureReferenceV1>, ErasureErrorV1> {
        self.store.borrow().attempt_page_ref(request, ordinal)
    }

    fn attempt_index_count(&self, request: ErasureReferenceV1) -> Result<u64, ErasureErrorV1> {
        self.store.borrow().attempt_index_count(request)
    }

    fn scope_node_ref(
        &self,
        request: ErasureReferenceV1,
        ordinal: u64,
    ) -> Result<Option<ErasureReferenceV1>, ErasureErrorV1> {
        self.store.borrow().scope_node_ref(request, ordinal)
    }

    fn scope_index_count(&self, request: ErasureReferenceV1) -> Result<u64, ErasureErrorV1> {
        self.store.borrow().scope_index_count(request)
    }

    fn administrative_resolution_ref(
        &self,
        request: ErasureReferenceV1,
        ordinal: u64,
    ) -> Result<Option<ErasureReferenceV1>, ErasureErrorV1> {
        self.store
            .borrow()
            .administrative_resolution_ref(request, ordinal)
    }

    fn administrative_resolution_index_count(
        &self,
        request: ErasureReferenceV1,
    ) -> Result<u64, ErasureErrorV1> {
        self.store
            .borrow()
            .administrative_resolution_index_count(request)
    }

    fn compare_and_swap(
        &mut self,
        mutation: pos_core::PreparedErasureCasV1,
    ) -> Result<pos_core::ErasureCasOutcomeV1, ErasureErrorV1> {
        self.store.borrow_mut().compare_and_swap(mutation)
    }
}

impl<S: ErasurePersistencePortV1> ErasureFreezeAuthorizationVerifierV1 for Host<S> {
    fn validate_freeze_authorization(
        &self,
        admission: &ErasureFreezeAdmissionEvidenceV1,
        authorization: &ErasureFreezeAuthorizationEvidenceV1,
    ) -> Result<(), ErasureErrorV1> {
        authorization.verify_admission_body_binding(admission)
    }
}

impl<S: ErasurePersistencePortV1> ErasureCoordinatorPortV1 for Host<S> {
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
        requested: &ErasureStateTransitionV1,
    ) -> Result<ErasureAtomicFreezeResultV1, ErasureErrorV1> {
        let mut targets = self.targets.clone();
        targets.sort_unstable();
        let mut obligations = targets
            .iter()
            .copied()
            .map(|target| {
                ErasureObligationV1::new(ErasureObligationInputV1 {
                    category: ErasureInventoryCategoryV1::Artifact,
                    target,
                    owner: target.replica_id,
                    command_identity: destruction_command_reference(request, target),
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
            policy: reference(6),
            trust: reference(8),
        })?;
        let scope = ErasureScopeCommitmentInputV1 {
            request,
            scope_members: vec![reference(9)],
            target_closure: target_closure_digest(&targets),
            lineage_rule: None,
        };
        let scope_reference = ErasureScopeCommitmentV1::new(scope.clone())?.reference();
        let evidence = requested.provenance.digest();
        let freeze_position = requested.freeze_position.unwrap_or(10);
        let (freeze_admission_evidence, freeze_authorization_evidence) = freeze_evidence(
            request,
            scope_reference,
            &obligation_set,
            &targets,
            &obligations,
            freeze_position,
            &evidence,
        )?;
        ErasureAtomicFreezeAdmissionV1::new(ErasureAtomicFreezeAdmissionInputV1 {
            targets,
            scope,
            obligations,
            obligation_set,
            freeze_position,
            freeze_admission_evidence,
            freeze_authorization_evidence,
        })
        .map(Box::new)
        .map(ErasureAtomicFreezeResultV1::Admitted)
    }

    fn admit_scope_extension(
        &self,
        _extension: &ErasureScopeExtensionV1,
    ) -> Result<(), ErasureErrorV1> {
        Ok(())
    }

    fn admit_administrative_resolution(
        &self,
        _resolution: &pos_core::ErasureAdministrativeResolutionV1,
    ) -> Result<(), ErasureErrorV1> {
        Ok(())
    }

    fn dispatch_destruction(
        &self,
        _request: ErasureReferenceV1,
        _commands: &[ErasureDestructionCommandV1],
    ) -> Result<(), ErasureErrorV1> {
        Ok(())
    }

    fn admit_attempt(
        &self,
        admission: &ErasureRetryAdmissionV1,
    ) -> Result<ErasureAttemptQuotaReservationV1, ErasureErrorV1> {
        Ok(ErasureAttemptQuotaReservationV1::new(
            admission.reference(),
            admission.reference(),
        ))
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
}

fn complete<S: ErasurePersistencePortV1>(
    store: S,
) -> Result<
    (
        Rc<RefCell<S>>,
        ErasureRequestV1,
        Vec<(ErasureReferenceV1, pos_core::ErasureCasEffectV1)>,
    ),
    ErasureErrorV1,
> {
    let shared = Rc::new(RefCell::new(store));
    let request = request()?;
    let target = target();
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(
        Host {
            store: Rc::clone(&shared),
            targets: vec![target],
        },
        reference(30),
    );
    coordinator.submit(request.clone(), request.provenance())?;
    coordinator.authorize(request.reference(), reference(31))?;
    coordinator.freeze_inventory(request.reference(), &transition())?;
    let admission = admission(request.reference(), target)?;
    coordinator.dispatch_attempt(request.reference(), &admission)?;
    let mut effects = vec![retained_effect(&shared, request.reference())?];
    assert_eq!(
        effects[0].1,
        pos_core::ErasureCasEffectV1::AttemptAdmission {
            reservation: ErasureAttemptQuotaReservationV1::new(
                admission.reference(),
                admission.reference(),
            ),
            commands: vec![ErasureDestructionCommandV1::from_obligation(
                &obligation(request.reference(), target)?,
                admission.reference(),
            )],
        }
    );
    let obligation = obligation(request.reference(), target)?;
    coordinator.acknowledge(
        request.reference(),
        ErasureAcknowledgementV1 {
            obligation: obligation.reference(),
            target,
            owner: target.replica_id,
            evidence: reference(32),
            outcome: ErasureAcknowledgementOutcomeV1::Acknowledged,
        },
    )?;
    effects.push(retained_effect(&shared, request.reference())?);
    assert!(matches!(
        &effects[1].1,
        pos_core::ErasureCasEffectV1::AcknowledgementAdmission { .. }
    ));
    let receipt = coordinator.finalize(
        request.reference(),
        ErasureReceiptInputV1 {
            request: reference(0),
            terminal_state: reference(0),
            coordinator: reference(0),
            lifecycle: ErasureLifecycleV1::Complete,
            freeze_position: 10,
            acknowledgements: Vec::new(),
            frozen_targets: vec![target],
            pending_owners: Vec::new(),
            failed_owners: Vec::new(),
            inventories: ErasureReceiptInventoriesV1 {
                artifacts: vec![inventory(target)],
                keys: Vec::new(),
                replicas: Vec::new(),
                backups: Vec::new(),
            },
            replay_claim: ErasureReplayClaimV1::Exact,
            policy: reference(0),
            trust: reference(0),
            provenance: reference(0),
            issue_position: 21,
            signature: reference(33),
            receipt_digest: reference(0),
        },
    )?;
    effects.push(retained_effect(&shared, request.reference())?);
    assert_eq!(
        effects[2].1,
        pos_core::ErasureCasEffectV1::ReceiptAdmission {
            receipt: receipt.receipt_digest(),
        }
    );
    Ok((shared, request, effects))
}

fn retained_effect<S: ErasurePersistencePortV1>(
    store: &Rc<RefCell<S>>,
    request: ErasureReferenceV1,
) -> Result<(ErasureReferenceV1, pos_core::ErasureCasEffectV1), ErasureErrorV1> {
    let store = store.borrow();
    let manifest = store
        .read_manifest(request)?
        .ok_or(ErasureErrorV1::ProvenanceMissing)?
        .digest();
    let effect = store.read_effect(manifest)?;
    if let Some(subject) = effect.subject() {
        if store.effect_manifest(subject)? != Some(manifest) {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
    }
    Ok((manifest, effect))
}

fn assert_raw_backend<S: ErasurePersistencePortV1>(
    store: S,
) -> Result<(), Box<dyn std::error::Error>> {
    let (shared, request, _) = complete(store)?;
    let backend = shared.borrow();
    let manifest = backend
        .read_manifest(request.reference())?
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    assert!(!manifest.canonical_cbor().is_empty());
    assert_eq!(backend.attempt_index_count(request.reference())?, 1);
    assert!(backend.attempt_page_ref(request.reference(), 0)?.is_some());
    assert!(backend.read_object(request.reference()).is_ok());
    drop(backend);

    let mut restarted = ErasureCoordinatorStateMachineV1::new(
        Host {
            store: shared,
            targets: vec![target()],
        },
        reference(30),
    );
    let provenance = request.provenance();
    let recovered = restarted.submit(request, provenance)?;
    assert_eq!(recovered.lifecycle(), ErasureLifecycleV1::Complete);
    Ok(())
}

fn assert_stale_head<S: ErasurePersistencePortV1>(
    store: S,
) -> Result<(), Box<dyn std::error::Error>> {
    let shared = Rc::new(RefCell::new(store));
    let request = request()?;
    let mut first = ErasureCoordinatorStateMachineV1::new(
        Host {
            store: Rc::clone(&shared),
            targets: Vec::new(),
        },
        reference(30),
    );
    let mut second = ErasureCoordinatorStateMachineV1::new(
        Host {
            store: shared,
            targets: Vec::new(),
        },
        reference(30),
    );
    first.submit(request.clone(), request.provenance())?;
    second.submit(request.clone(), request.provenance())?;
    first.authorize(request.reference(), reference(34))?;
    assert_eq!(
        second.authorize(request.reference(), reference(35)),
        Err(ErasureErrorV1::PolicyConflict)
    );
    Ok(())
}

#[test]
fn memory_manifest_cas_survives_restart_and_retains_indexes(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_raw_backend(MemoryStore::new())
}

#[test]
fn memory_manifest_cas_rejects_a_stale_head() -> Result<(), Box<dyn std::error::Error>> {
    assert_stale_head(MemoryStore::new())
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_manifest_cas_survives_restart_and_retains_indexes(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_raw_backend(SqliteStore::open_in_memory()?)
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_manifest_cas_rejects_a_stale_head() -> Result<(), Box<dyn std::error::Error>> {
    assert_stale_head(SqliteStore::open_in_memory()?)
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_effect_payloads_survive_file_backed_reopen() -> Result<(), Box<dyn std::error::Error>> {
    let database = tempfile::NamedTempFile::new()?;
    let path = database
        .path()
        .to_str()
        .ok_or(ErasureErrorV1::InvalidEncoding)?;
    let (shared, request, effects) = complete(SqliteStore::open(path)?)?;
    drop(shared);

    let reopened = SqliteStore::open(path)?;
    for (manifest, expected) in effects {
        assert_eq!(reopened.read_effect(manifest)?, expected);
        if let Some(subject) = expected.subject() {
            assert_eq!(reopened.effect_manifest(subject)?, Some(manifest));
        }
    }
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(
        Host {
            store: Rc::new(RefCell::new(reopened)),
            targets: vec![target()],
        },
        reference(30),
    );
    let provenance = request.provenance();
    assert_eq!(
        coordinator.submit(request, provenance)?.lifecycle(),
        ErasureLifecycleV1::Complete
    );
    Ok(())
}

#[test]
fn raw_index_variants_remain_explicitly_named() {
    assert!(matches!(
        ErasureIndexInsertV1::AttemptPage {
            ordinal: 0,
            reference: reference(1),
        },
        ErasureIndexInsertV1::AttemptPage { .. }
    ));
    assert!(matches!(
        ErasureIndexInsertV1::ScopeNode {
            ordinal: 0,
            reference: reference(2),
        },
        ErasureIndexInsertV1::ScopeNode { .. }
    ));
    assert!(matches!(
        ErasureIndexInsertV1::AdministrativeResolution {
            ordinal: 0,
            reference: reference(3),
        },
        ErasureIndexInsertV1::AdministrativeResolution { .. }
    ));
}
