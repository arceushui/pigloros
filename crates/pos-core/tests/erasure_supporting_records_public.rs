//! Public contracts for ADR-060 erasure supporting records.

#[path = "support/erasure.rs"]
pub mod erasure_support;

use ciborium::value::Value;
use erasure_support::freeze_evidence_fixture;
use pos_core::{
    acknowledgement_inventory_reference, destruction_command_reference,
    erasure_evidence_set_reference, selected_obligations_reference,
    ErasureAcknowledgementOutcomeV1, ErasureAcknowledgementProvenanceInputV1,
    ErasureAcknowledgementProvenanceV1, ErasureAcknowledgementV1,
    ErasureAdministrativeResolutionActionV1, ErasureAdministrativeResolutionInputV1,
    ErasureAdministrativeResolutionV1, ErasureApplicabilityDecisionV1, ErasureArtifactClassV1,
    ErasureArtifactTransitionV1, ErasureAttemptOutcomeInputV1, ErasureAttemptOutcomeV1,
    ErasureAuthorizationRejectionInputV1, ErasureAuthorizationRejectionV1,
    ErasureCoordinatorRecordPartsV1, ErasureCoordinatorRecordV1,
    ErasureCorrectionProvenanceInputV1, ErasureCorrectionProvenanceV1, ErasureErrorV1,
    ErasureFreezeAdmissionEvidenceInputV1, ErasureFreezeAdmissionEvidenceV1,
    ErasureFreezeAuthorizationEvidenceInputV1, ErasureFreezeAuthorizationEvidenceV1,
    ErasureFreezeFailureInputV1, ErasureFreezeFailureV1, ErasureFreezeProvenanceInputV1,
    ErasureFreezeProvenanceV1, ErasureInventoryCategoryV1, ErasureInventoryResultV1,
    ErasureKeyRoleV1, ErasureLifecycleV1, ErasureObligationInputV1, ErasureObligationSetInputV1,
    ErasureObligationSetV1, ErasureObligationV1, ErasureReceiptInputV1,
    ErasureReceiptInventoriesV1, ErasureReceiptProvenanceInputV1, ErasureReceiptProvenanceV1,
    ErasureReceiptV1, ErasureReferenceV1, ErasureReplayClaimV1, ErasureRequestInputV1,
    ErasureRequestV1, ErasureRequiredTargetV1, ErasureRetryAdmissionInputV1,
    ErasureRetryAdmissionV1, ErasureScopeCommitmentInputV1, ErasureScopeCommitmentV1,
    ErasureScopeExtensionInputV1, ErasureScopeExtensionLedgerInputV1,
    ErasureScopeExtensionLedgerV1, ErasureScopeExtensionV1, ErasureScopeV1, ErasureStateV1,
    ErasureSupportingRecordsInputV1, ErasureSupportingRecordsV1,
    ERASURE_MAX_ADMINISTRATIVE_RESOLUTIONS, ERASURE_MAX_ATTEMPT_OUTCOMES, ERASURE_MAX_OBLIGATIONS,
    ERASURE_PORTABLE_RECORD_MAX_BYTES, ERASURE_RETRY_ADMISSION_MAX_BYTES,
};

const fn reference(value: u8) -> ErasureReferenceV1 {
    ErasureReferenceV1::from_digest([value; 32])
}

fn roundtrip<T>(
    value: &T,
    encode: impl Fn(&T) -> Result<Vec<u8>, ErasureErrorV1>,
    decode: impl Fn(&[u8]) -> Result<T, ErasureErrorV1>,
) -> Result<T, ErasureErrorV1> {
    let bytes = encode(value)?;
    let decoded = decode(&bytes)?;
    assert_eq!(encode(&decoded)?, bytes);
    Ok(decoded)
}

fn changed_array(bytes: &[u8], change: impl FnOnce(&mut Vec<Value>)) -> Vec<u8> {
    let decoded: Result<Value, _> = ciborium::from_reader(bytes);
    assert!(decoded.is_ok());
    let Value::Array(mut fields) = decoded.unwrap_or(Value::Null) else {
        return Vec::new();
    };
    change(&mut fields);
    let mut changed = Vec::new();
    assert!(ciborium::into_writer(&Value::Array(fields), &mut changed).is_ok());
    changed
}

fn assert_each_field_rejects<T>(
    bytes: &[u8],
    decode: impl Fn(&[u8]) -> Result<T, ErasureErrorV1>,
) -> Result<(), ErasureErrorV1> {
    let decoded: Value =
        ciborium::from_reader(bytes).map_err(|_| ErasureErrorV1::InvalidEncoding)?;
    let Value::Array(fields) = decoded else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    for (index, _) in fields.iter().enumerate() {
        let malformed = changed_array(bytes, |changed| changed[index] = Value::Bool(false));
        assert!(decode(&malformed).is_err(), "field {index} accepted a bool");
    }
    Ok(())
}

const fn required_target() -> ErasureRequiredTargetV1 {
    ErasureRequiredTargetV1 {
        artifact_class: ErasureArtifactClassV1::TimelineReplay,
        artifact_digest: reference(30),
        key_role: ErasureKeyRoleV1::DataEncryption,
        key_digest: reference(31),
        replica_set: reference(32),
        replica_id: reference(33),
    }
}

fn obligation(request: ErasureReferenceV1) -> Result<ErasureObligationV1, ErasureErrorV1> {
    let target = required_target();
    ErasureObligationV1::new(ErasureObligationInputV1 {
        category: ErasureInventoryCategoryV1::Artifact,
        target,
        owner: reference(36),
        command_identity: destruction_command_reference(request, target),
    })
}

fn scope_commitment(
    request: ErasureReferenceV1,
) -> Result<ErasureScopeCommitmentV1, ErasureErrorV1> {
    ErasureScopeCommitmentV1::new(ErasureScopeCommitmentInputV1 {
        request,
        scope_members: vec![reference(2)],
        target_closure: pos_core::erasure::target_closure_digest(&[required_target()]),
        lineage_rule: None,
    })
}

fn freeze_supporting_input(
    request: ErasureReferenceV1,
) -> Result<ErasureSupportingRecordsInputV1, ErasureErrorV1> {
    let scope = scope_commitment(request)?;
    let obligation = obligation(request)?;
    let obligation_set = ErasureObligationSetV1::new(ErasureObligationSetInputV1 {
        request,
        obligations: vec![obligation.reference()],
        policy: reference(4),
        trust: reference(5),
    })?;
    let (freeze_admission_evidence, freeze_authorization_evidence) = freeze_evidence_fixture(
        request,
        scope.reference(),
        &obligation_set,
        &[required_target()],
        &[obligation],
        10,
        &reference(6).digest(),
    )?;
    let freeze = ErasureFreezeProvenanceV1::new(ErasureFreezeProvenanceInputV1 {
        request,
        scope_commitment: scope.reference(),
        obligation_set: obligation_set.reference(),
        freeze_position: 10,
        host_evidence: freeze_admission_evidence.reference(),
    })?;
    Ok(ErasureSupportingRecordsInputV1 {
        scope_commitment: Some(scope),
        freeze_admission_evidence: Some(freeze_admission_evidence),
        freeze_authorization_evidence: Some(freeze_authorization_evidence),
        freeze_provenance: Some(freeze),
        obligations: vec![obligation],
        obligation_set: Some(obligation_set),
        ..ErasureSupportingRecordsInputV1::default()
    })
}

fn acknowledgement(
    request: ErasureReferenceV1,
) -> Result<ErasureAcknowledgementV1, ErasureErrorV1> {
    let obligation = obligation(request)?;
    Ok(ErasureAcknowledgementV1 {
        obligation: obligation.reference(),
        target: required_target(),
        owner: reference(36),
        evidence: reference(34),
        outcome: ErasureAcknowledgementOutcomeV1::Acknowledged,
    })
}

const fn inventory() -> ErasureInventoryResultV1 {
    ErasureInventoryResultV1 {
        category: ErasureInventoryCategoryV1::Artifact,
        target: required_target(),
        transition: ErasureArtifactTransitionV1 {
            from: ErasureReplayClaimV1::Exact,
            to: ErasureReplayClaimV1::StructuralOnly,
            reason: reference(35),
            owner: reference(36),
            acknowledgements: reference(37),
            provenance: reference(38),
        },
        retained_disclosure: reference(39),
    }
}

#[test]
fn portable_scope_and_obligation_records_expose_canonical_public_seams(
) -> Result<(), ErasureErrorV1> {
    let rejection = ErasureAuthorizationRejectionV1::new(ErasureAuthorizationRejectionInputV1 {
        request: reference(1),
        authorization_provenance: reference(2),
    })?;
    let rejection = roundtrip(
        &rejection,
        ErasureAuthorizationRejectionV1::to_canonical_cbor,
        ErasureAuthorizationRejectionV1::from_canonical_cbor,
    )?;
    assert_eq!(rejection.request(), reference(1));
    assert_eq!(rejection.authorization_provenance(), reference(2));
    assert_ne!(rejection.reference(), reference(0));

    let obligation = obligation(reference(1))?;
    let obligation = roundtrip(
        &obligation,
        ErasureObligationV1::to_canonical_cbor,
        ErasureObligationV1::from_canonical_cbor,
    )?;
    assert_eq!(obligation.category(), ErasureInventoryCategoryV1::Artifact);
    assert_eq!(obligation.target(), required_target());
    assert_eq!(obligation.owner(), reference(36));
    assert_eq!(
        obligation.command_identity(),
        destruction_command_reference(reference(1), required_target())
    );
    assert_ne!(obligation.reference(), reference(0));

    let obligation_set = ErasureObligationSetV1::new(ErasureObligationSetInputV1 {
        request: reference(1),
        obligations: vec![obligation.reference()],
        policy: reference(4),
        trust: reference(5),
    })?;
    let obligation_set = roundtrip(
        &obligation_set,
        ErasureObligationSetV1::to_canonical_cbor,
        ErasureObligationSetV1::from_canonical_cbor,
    )?;
    assert_eq!(obligation_set.request(), reference(1));
    assert_eq!(obligation_set.obligations(), &[obligation.reference()]);
    assert_eq!(obligation_set.policy(), reference(4));
    assert_eq!(obligation_set.trust(), reference(5));
    assert_ne!(obligation_set.reference(), reference(0));

    let scope = scope_commitment(reference(1))?;
    let extension = ErasureScopeExtensionV1::new(ErasureScopeExtensionInputV1 {
        request: reference(1),
        scope_commitment: scope.reference(),
        fork: reference(6),
        lineage_rule: reference(7),
        predecessor_extension: None,
        admission_provenance: reference(8),
    })?;
    let extension = roundtrip(
        &extension,
        ErasureScopeExtensionV1::to_canonical_cbor,
        ErasureScopeExtensionV1::from_canonical_cbor,
    )?;
    assert_eq!(extension.request(), reference(1));
    assert_eq!(extension.scope_commitment(), scope.reference());
    assert_eq!(extension.fork(), reference(6));
    assert_eq!(extension.lineage_rule(), reference(7));
    assert_eq!(extension.predecessor_extension(), None);
    assert_eq!(extension.admission_provenance(), reference(8));
    assert_ne!(extension.reference(), reference(0));

    let ledger = ErasureScopeExtensionLedgerV1::new(ErasureScopeExtensionLedgerInputV1 {
        scope_commitment: scope.reference(),
        extensions: vec![extension.reference()],
        head: Some(extension.reference()),
    })?;
    let ledger = roundtrip(
        &ledger,
        ErasureScopeExtensionLedgerV1::to_canonical_cbor,
        ErasureScopeExtensionLedgerV1::from_canonical_cbor,
    )?;
    assert_eq!(ledger.scope_commitment(), scope.reference());
    assert_eq!(ledger.extensions(), &[extension.reference()]);
    assert_eq!(ledger.head(), Some(extension.reference()));
    assert_ne!(ledger.reference(), reference(0));
    Ok(())
}

#[test]
fn supporting_records_reject_conflicting_rejection_and_freeze_evidence(
) -> Result<(), ErasureErrorV1> {
    let request = reference(1);
    let scope = scope_commitment(request)?;
    let rejection = ErasureAuthorizationRejectionV1::new(ErasureAuthorizationRejectionInputV1 {
        request,
        authorization_provenance: reference(7),
    })?;
    let failure = ErasureFreezeFailureV1::new(ErasureFreezeFailureInputV1 {
        request,
        authorization_provenance: reference(7),
        evidence: reference(8),
        error: ErasureErrorV1::AccessFreezeFailed,
    })?;

    let rejected_with_failure = ErasureSupportingRecordsInputV1 {
        authorization_rejection: Some(rejection),
        freeze_failure: Some(failure),
        ..ErasureSupportingRecordsInputV1::default()
    };
    assert_eq!(
        ErasureSupportingRecordsV1::new(rejected_with_failure),
        Err(ErasureErrorV1::PolicyConflict)
    );
    let rejected_with_scope = ErasureSupportingRecordsInputV1 {
        authorization_rejection: Some(rejection),
        scope_commitment: Some(scope.clone()),
        ..ErasureSupportingRecordsInputV1::default()
    };
    assert_eq!(
        ErasureSupportingRecordsV1::new(rejected_with_scope),
        Err(ErasureErrorV1::PolicyConflict)
    );
    let failure_with_scope = ErasureSupportingRecordsInputV1 {
        scope_commitment: Some(scope),
        freeze_failure: Some(failure),
        ..ErasureSupportingRecordsInputV1::default()
    };
    assert_eq!(
        ErasureSupportingRecordsV1::new(failure_with_scope),
        Err(ErasureErrorV1::PolicyConflict)
    );
    Ok(())
}

#[test]
fn supporting_records_require_complete_freeze_commitments() -> Result<(), ErasureErrorV1> {
    let request = reference(1);
    let scope = scope_commitment(request)?;
    let obligation = obligation(request)?;
    let obligation_set = ErasureObligationSetV1::new(ErasureObligationSetInputV1 {
        request,
        obligations: vec![obligation.reference()],
        policy: reference(4),
        trust: reference(5),
    })?;
    let freeze = ErasureFreezeProvenanceV1::new(ErasureFreezeProvenanceInputV1 {
        request,
        scope_commitment: scope.reference(),
        obligation_set: obligation_set.reference(),
        freeze_position: 10,
        host_evidence: reference(6),
    })?;
    let obligations_without_scope = ErasureSupportingRecordsInputV1 {
        obligations: vec![obligation],
        obligation_set: Some(obligation_set.clone()),
        ..ErasureSupportingRecordsInputV1::default()
    };
    assert_eq!(
        ErasureSupportingRecordsV1::new(obligations_without_scope),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    let freeze_without_scope = ErasureSupportingRecordsInputV1 {
        freeze_provenance: Some(freeze),
        obligation_set: Some(obligation_set.clone()),
        obligations: vec![obligation],
        ..ErasureSupportingRecordsInputV1::default()
    };
    assert_eq!(
        ErasureSupportingRecordsV1::new(freeze_without_scope),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    let freeze_without_obligation_set = ErasureSupportingRecordsInputV1 {
        scope_commitment: Some(scope.clone()),
        freeze_provenance: Some(freeze),
        ..ErasureSupportingRecordsInputV1::default()
    };
    assert_eq!(
        ErasureSupportingRecordsV1::new(freeze_without_obligation_set),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    let (admission, authorization) = freeze_evidence_fixture(
        request,
        scope.reference(),
        &obligation_set,
        &[required_target()],
        &[obligation],
        10,
        &reference(6).digest(),
    )?;
    let mismatched_freeze = ErasureFreezeProvenanceV1::new(ErasureFreezeProvenanceInputV1 {
        request,
        scope_commitment: reference(99),
        obligation_set: obligation_set.reference(),
        freeze_position: 10,
        host_evidence: admission.reference(),
    })?;
    let mismatched_freeze = ErasureSupportingRecordsInputV1 {
        scope_commitment: Some(scope),
        freeze_admission_evidence: Some(admission),
        freeze_authorization_evidence: Some(authorization),
        freeze_provenance: Some(mismatched_freeze),
        obligations: vec![obligation],
        obligation_set: Some(obligation_set),
        ..ErasureSupportingRecordsInputV1::default()
    };
    assert_eq!(
        ErasureSupportingRecordsV1::new(mismatched_freeze),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}

#[test]
fn supporting_records_bind_obligation_objects_and_lineage_ledgers() -> Result<(), ErasureErrorV1> {
    let request = reference(1);
    let scope = scope_commitment(request)?;
    let other_obligation = obligation(reference(9))?;
    let obligation = obligation(request)?;
    let obligation_set = ErasureObligationSetV1::new(ErasureObligationSetInputV1 {
        request,
        obligations: vec![obligation.reference()],
        policy: reference(4),
        trust: reference(5),
    })?;
    let missing_obligation_objects = ErasureSupportingRecordsInputV1 {
        scope_commitment: Some(scope.clone()),
        obligation_set: Some(obligation_set.clone()),
        ..ErasureSupportingRecordsInputV1::default()
    };
    assert_eq!(
        ErasureSupportingRecordsV1::new(missing_obligation_objects),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    let wrong_obligation_objects = ErasureSupportingRecordsInputV1 {
        scope_commitment: Some(scope.clone()),
        obligations: vec![other_obligation],
        obligation_set: Some(obligation_set),
        ..ErasureSupportingRecordsInputV1::default()
    };
    assert_eq!(
        ErasureSupportingRecordsV1::new(wrong_obligation_objects),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    let ledger_without_lineage =
        ErasureScopeExtensionLedgerV1::new(ErasureScopeExtensionLedgerInputV1 {
            scope_commitment: scope.reference(),
            extensions: Vec::new(),
            head: None,
        })?;
    let ledger_without_lineage = ErasureSupportingRecordsInputV1 {
        scope_commitment: Some(scope),
        obligations: vec![obligation],
        obligation_set: Some(ErasureObligationSetV1::new(ErasureObligationSetInputV1 {
            request,
            obligations: vec![obligation.reference()],
            policy: reference(4),
            trust: reference(5),
        })?),
        scope_extension_ledgers: vec![ledger_without_lineage],
        ..ErasureSupportingRecordsInputV1::default()
    };
    assert_eq!(
        ErasureSupportingRecordsV1::new(ledger_without_lineage),
        Err(ErasureErrorV1::PolicyConflict)
    );
    Ok(())
}

#[test]
fn supporting_records_bound_and_bind_obligation_evidence() -> Result<(), ErasureErrorV1> {
    let request = reference(1);
    let scope = scope_commitment(request)?;
    let obligation = obligation(request)?;
    let missing_set = ErasureSupportingRecordsInputV1 {
        scope_commitment: Some(scope.clone()),
        obligations: vec![obligation],
        ..ErasureSupportingRecordsInputV1::default()
    };
    assert_eq!(
        ErasureSupportingRecordsV1::new(missing_set),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    let obligation_set = ErasureObligationSetV1::new(ErasureObligationSetInputV1 {
        request,
        obligations: vec![obligation.reference()],
        policy: reference(4),
        trust: reference(5),
    })?;
    let oversized = ErasureSupportingRecordsInputV1 {
        scope_commitment: Some(scope.clone()),
        obligations: vec![obligation; ERASURE_MAX_OBLIGATIONS + 1],
        obligation_set: Some(obligation_set),
        ..ErasureSupportingRecordsInputV1::default()
    };
    assert_eq!(
        ErasureSupportingRecordsV1::new(oversized),
        Err(ErasureErrorV1::ScopeInvalid)
    );

    let wrong_command = ErasureObligationV1::new(ErasureObligationInputV1 {
        category: ErasureInventoryCategoryV1::Artifact,
        target: required_target(),
        owner: reference(36),
        command_identity: reference(99),
    })?;
    let wrong_command_set = ErasureObligationSetV1::new(ErasureObligationSetInputV1 {
        request,
        obligations: vec![wrong_command.reference()],
        policy: reference(4),
        trust: reference(5),
    })?;
    let wrong_command = ErasureSupportingRecordsInputV1 {
        scope_commitment: Some(scope.clone()),
        obligations: vec![wrong_command],
        obligation_set: Some(wrong_command_set),
        ..ErasureSupportingRecordsInputV1::default()
    };
    assert_eq!(
        ErasureSupportingRecordsV1::new(wrong_command),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    let mut duplicate_target = vec![
        obligation,
        ErasureObligationV1::new(ErasureObligationInputV1 {
            category: ErasureInventoryCategoryV1::Artifact,
            target: required_target(),
            owner: reference(37),
            command_identity: destruction_command_reference(request, required_target()),
        })?,
    ];
    duplicate_target.sort_unstable_by_key(ErasureObligationV1::reference);
    let duplicate_set = ErasureObligationSetV1::new(ErasureObligationSetInputV1 {
        request,
        obligations: duplicate_target
            .iter()
            .map(ErasureObligationV1::reference)
            .collect(),
        policy: reference(4),
        trust: reference(5),
    })?;
    let duplicate_target = ErasureSupportingRecordsInputV1 {
        scope_commitment: Some(scope),
        obligations: duplicate_target,
        obligation_set: Some(duplicate_set),
        ..ErasureSupportingRecordsInputV1::default()
    };
    assert_eq!(
        ErasureSupportingRecordsV1::new(duplicate_target),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    Ok(())
}

#[test]
fn supporting_records_validate_lineage_chain_and_ledger_snapshots() -> Result<(), ErasureErrorV1> {
    let request = reference(1);
    let scope = ErasureScopeCommitmentV1::new(ErasureScopeCommitmentInputV1 {
        request,
        scope_members: vec![reference(2)],
        target_closure: reference(3),
        lineage_rule: Some(reference(4)),
    })?;
    let missing_initial_ledger = ErasureSupportingRecordsInputV1 {
        scope_commitment: Some(scope.clone()),
        ..ErasureSupportingRecordsInputV1::default()
    };
    assert_eq!(
        ErasureSupportingRecordsV1::new(missing_initial_ledger),
        Err(ErasureErrorV1::ScopeInvalid)
    );

    let initial = ErasureScopeExtensionLedgerV1::new(ErasureScopeExtensionLedgerInputV1 {
        scope_commitment: scope.reference(),
        extensions: Vec::new(),
        head: None,
    })?;
    let wrong_extension = ErasureScopeExtensionV1::new(ErasureScopeExtensionInputV1 {
        request: reference(9),
        scope_commitment: scope.reference(),
        fork: reference(5),
        lineage_rule: reference(4),
        predecessor_extension: None,
        admission_provenance: reference(6),
    })?;
    let successor = ErasureScopeExtensionLedgerV1::new(ErasureScopeExtensionLedgerInputV1 {
        scope_commitment: scope.reference(),
        extensions: vec![wrong_extension.reference()],
        head: Some(wrong_extension.reference()),
    })?;
    let wrong_extension = ErasureSupportingRecordsInputV1 {
        scope_commitment: Some(scope.clone()),
        scope_extensions: vec![wrong_extension],
        scope_extension_ledgers: vec![initial, successor],
        ..ErasureSupportingRecordsInputV1::default()
    };
    assert_eq!(
        ErasureSupportingRecordsV1::new(wrong_extension),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    let wrong_ledger = ErasureScopeExtensionLedgerV1::new(ErasureScopeExtensionLedgerInputV1 {
        scope_commitment: reference(99),
        extensions: Vec::new(),
        head: None,
    })?;
    let wrong_ledger = ErasureSupportingRecordsInputV1 {
        scope_commitment: Some(scope),
        scope_extension_ledgers: vec![wrong_ledger],
        ..ErasureSupportingRecordsInputV1::default()
    };
    assert_eq!(
        ErasureSupportingRecordsV1::new(wrong_ledger),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}

#[test]
fn scope_ledgers_reject_each_inconsistent_public_chain_shape() {
    for input in [
        ErasureScopeExtensionLedgerInputV1 {
            scope_commitment: reference(1),
            extensions: Vec::new(),
            head: Some(reference(2)),
        },
        ErasureScopeExtensionLedgerInputV1 {
            scope_commitment: reference(1),
            extensions: vec![reference(2)],
            head: None,
        },
        ErasureScopeExtensionLedgerInputV1 {
            scope_commitment: reference(1),
            extensions: vec![reference(2)],
            head: Some(reference(3)),
        },
        ErasureScopeExtensionLedgerInputV1 {
            scope_commitment: reference(1),
            extensions: vec![reference(2), reference(2)],
            head: Some(reference(2)),
        },
    ] {
        assert_eq!(
            ErasureScopeExtensionLedgerV1::new(input),
            Err(ErasureErrorV1::ScopeInvalid)
        );
    }
}

#[test]
fn supporting_records_reject_duplicate_lineage_forks() -> Result<(), ErasureErrorV1> {
    let request = reference(1);
    let scope = ErasureScopeCommitmentV1::new(ErasureScopeCommitmentInputV1 {
        request,
        scope_members: vec![reference(2)],
        target_closure: reference(3),
        lineage_rule: Some(reference(4)),
    })?;
    let first = ErasureScopeExtensionV1::new(ErasureScopeExtensionInputV1 {
        request,
        scope_commitment: scope.reference(),
        fork: reference(5),
        lineage_rule: reference(4),
        predecessor_extension: None,
        admission_provenance: reference(6),
    })?;
    let second = ErasureScopeExtensionV1::new(ErasureScopeExtensionInputV1 {
        request,
        scope_commitment: scope.reference(),
        fork: reference(5),
        lineage_rule: reference(4),
        predecessor_extension: Some(first.reference()),
        admission_provenance: reference(7),
    })?;
    let ledgers = [
        Vec::new(),
        vec![first.reference()],
        vec![first.reference(), second.reference()],
    ]
    .into_iter()
    .map(|extensions| {
        let head = extensions.last().copied();
        ErasureScopeExtensionLedgerV1::new(ErasureScopeExtensionLedgerInputV1 {
            scope_commitment: scope.reference(),
            extensions,
            head,
        })
    })
    .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        ErasureSupportingRecordsV1::new(ErasureSupportingRecordsInputV1 {
            scope_commitment: Some(scope),
            scope_extensions: vec![first, second],
            scope_extension_ledgers: ledgers,
            ..ErasureSupportingRecordsInputV1::default()
        }),
        Err(ErasureErrorV1::PolicyConflict)
    );
    Ok(())
}

fn complete_receipt(
    request: ErasureReferenceV1,
    provenance: ErasureReferenceV1,
) -> Result<ErasureReceiptV1, ErasureErrorV1> {
    ErasureReceiptV1::new(ErasureReceiptInputV1 {
        request,
        terminal_state: reference(40),
        coordinator: reference(41),
        lifecycle: ErasureLifecycleV1::Complete,
        freeze_position: 10,
        frozen_targets: vec![required_target()],
        acknowledgements: vec![acknowledgement(request)?],
        pending_owners: Vec::new(),
        failed_owners: Vec::new(),
        inventories: ErasureReceiptInventoriesV1 {
            artifacts: vec![inventory()],
            keys: Vec::new(),
            replicas: Vec::new(),
            backups: Vec::new(),
        },
        replay_claim: ErasureReplayClaimV1::Exact,
        policy: reference(4),
        trust: reference(5),
        provenance,
        issue_position: 20,
        signature: reference(43),
        receipt_digest: reference(0),
    })
}

#[test]
fn receipt_validates_the_exact_frozen_obligation_identity() -> Result<(), ErasureErrorV1> {
    let request = reference(1);
    let receipt = complete_receipt(request, reference(42))?;
    assert_eq!(
        receipt.validate_frozen_obligations(&[]),
        Err(ErasureErrorV1::ScopeInvalid)
    );

    let different_identity = ErasureObligationV1::new(ErasureObligationInputV1 {
        category: ErasureInventoryCategoryV1::Artifact,
        target: required_target(),
        owner: reference(36),
        command_identity: reference(99),
    })?;
    assert_eq!(
        receipt.validate_frozen_obligations(&[different_identity]),
        Err(ErasureErrorV1::PolicyConflict)
    );
    Ok(())
}

fn initial_admission(
    request: ErasureReferenceV1,
) -> Result<ErasureRetryAdmissionV1, ErasureErrorV1> {
    let obligation = obligation(request)?;
    ErasureRetryAdmissionV1::new(ErasureRetryAdmissionInputV1 {
        request,
        attempt_ordinal: 0,
        source_receipt: None,
        unresolved_obligations: vec![obligation.reference()],
        command_identities: vec![obligation.command_identity()],
        policy: reference(4),
        trust: reference(5),
        admitted_position: 10,
        deadline_position: 20,
        authorization_provenance: reference(6),
    })
}

fn acknowledgement_provenance_input(
    request: ErasureReferenceV1,
    attempt: ErasureReferenceV1,
) -> Result<ErasureAcknowledgementProvenanceInputV1, ErasureErrorV1> {
    let acknowledgement = acknowledgement(request)?;
    let obligation = obligation(request)?;
    Ok(ErasureAcknowledgementProvenanceInputV1 {
        request,
        command: obligation.command_identity(),
        attempt,
        obligation: acknowledgement.obligation,
        owner: acknowledgement.owner,
        scope: scope_commitment(request)?.reference(),
        outcome: ErasureAcknowledgementOutcomeV1::Acknowledged,
        evidence: reference(34),
        policy: reference(4),
        trust: reference(5),
    })
}

fn administrative_resolution(
    request: ErasureReferenceV1,
    scope_commitment: ErasureReferenceV1,
    predecessor_resolution: Option<ErasureReferenceV1>,
) -> Result<ErasureAdministrativeResolutionV1, ErasureErrorV1> {
    ErasureAdministrativeResolutionV1::new(ErasureAdministrativeResolutionInputV1 {
        request,
        affected_digests: vec![reference(48)],
        action: ErasureAdministrativeResolutionActionV1::CloseContainment,
        scope_commitment,
        policy: reference(4),
        trust: reference(5),
        principal: reference(50),
        authorization_provenance: reference(51),
        reason: reference(52),
        issue_position: 21,
        predecessor_resolution,
    })
}

fn complete_supporting_input(
    request: ErasureReferenceV1,
) -> Result<ErasureSupportingRecordsInputV1, ErasureErrorV1> {
    let correction = ErasureCorrectionProvenanceV1::new(ErasureCorrectionProvenanceInputV1 {
        rejected_request: reference(70),
        rejected_terminal_state: reference(71),
        correction_reason: reference(72),
        authorization_provenance: reference(73),
    })?;
    let obligation = obligation(request)?;
    let scope = scope_commitment(request)?;
    let obligation_set = ErasureObligationSetV1::new(ErasureObligationSetInputV1 {
        request,
        obligations: vec![obligation.reference()],
        policy: reference(4),
        trust: reference(5),
    })?;
    let (freeze_admission_evidence, freeze_authorization_evidence) = freeze_evidence_fixture(
        request,
        scope.reference(),
        &obligation_set,
        &[required_target()],
        &[obligation],
        10,
        &reference(6).digest(),
    )?;
    let freeze = ErasureFreezeProvenanceV1::new(ErasureFreezeProvenanceInputV1 {
        request,
        scope_commitment: scope.reference(),
        obligation_set: obligation_set.reference(),
        freeze_position: 10,
        host_evidence: freeze_admission_evidence.reference(),
    })?;
    let admission = initial_admission(request)?;
    let attempt = admission.reference();
    let acknowledgement_provenance = ErasureAcknowledgementProvenanceV1::new(
        acknowledgement_provenance_input(request, attempt)?,
    )?;
    let acknowledgement_reference = acknowledgement_provenance.reference();
    let receipt_provenance = ErasureReceiptProvenanceV1::new(ErasureReceiptProvenanceInputV1 {
        request,
        attempt,
        attempt_ordinal: 0,
        predecessor_receipt: None,
        terminal_state: reference(40),
        evidence_set: erasure_evidence_set_reference(&[acknowledgement_reference]),
        policy: reference(4),
        trust: reference(5),
        issue_position: 20,
    })?;
    let receipt = complete_receipt(request, receipt_provenance.reference())?;
    Ok(ErasureSupportingRecordsInputV1 {
        correction_provenance: Some(correction),
        scope_commitment: Some(scope.clone()),
        freeze_admission_evidence: Some(freeze_admission_evidence),
        freeze_authorization_evidence: Some(freeze_authorization_evidence),
        freeze_provenance: Some(freeze),
        obligations: vec![obligation],
        obligation_set: Some(obligation_set),
        retry_admissions: vec![admission],
        acknowledgement_provenance: vec![acknowledgement_provenance],
        attempt_outcomes: vec![ErasureAttemptOutcomeV1::new(
            ErasureAttemptOutcomeInputV1 {
                request,
                attempt,
                source_receipt: None,
                lifecycle: ErasureLifecycleV1::Complete,
                selected_obligations: selected_obligations_reference(&[
                    acknowledgement(request)?.obligation
                ]),
                acknowledgement_inventory: acknowledgement_inventory_reference(&[
                    acknowledgement_reference,
                ]),
                terminal_position: 20,
                policy: reference(4),
                trust: reference(5),
            },
        )?],
        receipts: vec![receipt],
        receipt_provenance: vec![receipt_provenance],
        administrative_resolutions: vec![administrative_resolution(
            request,
            scope.reference(),
            None,
        )?],
        ..ErasureSupportingRecordsInputV1::default()
    })
}

fn partial_failure_supporting_input(
    request: ErasureReferenceV1,
) -> Result<ErasureSupportingRecordsInputV1, ErasureErrorV1> {
    let obligation = obligation(request)?;
    let scope = scope_commitment(request)?;
    let obligation_set = ErasureObligationSetV1::new(ErasureObligationSetInputV1 {
        request,
        obligations: vec![obligation.reference()],
        policy: reference(4),
        trust: reference(5),
    })?;
    let (freeze_admission_evidence, freeze_authorization_evidence) = freeze_evidence_fixture(
        request,
        scope.reference(),
        &obligation_set,
        &[required_target()],
        &[obligation],
        10,
        &reference(6).digest(),
    )?;
    let freeze = ErasureFreezeProvenanceV1::new(ErasureFreezeProvenanceInputV1 {
        request,
        scope_commitment: scope.reference(),
        obligation_set: obligation_set.reference(),
        freeze_position: 10,
        host_evidence: freeze_admission_evidence.reference(),
    })?;
    let admission = initial_admission(request)?;
    let attempt = admission.reference();
    let receipt_provenance = ErasureReceiptProvenanceV1::new(ErasureReceiptProvenanceInputV1 {
        request,
        attempt,
        attempt_ordinal: 0,
        predecessor_receipt: None,
        terminal_state: reference(40),
        evidence_set: erasure_evidence_set_reference(&[]),
        policy: reference(4),
        trust: reference(5),
        issue_position: 20,
    })?;
    let receipt = ErasureReceiptV1::new(ErasureReceiptInputV1 {
        request,
        terminal_state: reference(40),
        coordinator: reference(41),
        lifecycle: ErasureLifecycleV1::PartialFailure,
        freeze_position: 10,
        frozen_targets: vec![required_target()],
        acknowledgements: Vec::new(),
        pending_owners: vec![obligation.owner()],
        failed_owners: Vec::new(),
        inventories: ErasureReceiptInventoriesV1 {
            artifacts: vec![inventory()],
            keys: Vec::new(),
            replicas: Vec::new(),
            backups: Vec::new(),
        },
        replay_claim: ErasureReplayClaimV1::Exact,
        policy: reference(4),
        trust: reference(5),
        provenance: receipt_provenance.reference(),
        issue_position: 20,
        signature: reference(43),
        receipt_digest: reference(0),
    })?;
    Ok(ErasureSupportingRecordsInputV1 {
        scope_commitment: Some(scope),
        freeze_admission_evidence: Some(freeze_admission_evidence),
        freeze_authorization_evidence: Some(freeze_authorization_evidence),
        freeze_provenance: Some(freeze),
        obligations: vec![obligation],
        obligation_set: Some(obligation_set),
        retry_admissions: vec![admission],
        attempt_outcomes: vec![ErasureAttemptOutcomeV1::new(
            ErasureAttemptOutcomeInputV1 {
                request,
                attempt,
                source_receipt: None,
                lifecycle: ErasureLifecycleV1::PartialFailure,
                selected_obligations: selected_obligations_reference(&[obligation.reference()]),
                acknowledgement_inventory: acknowledgement_inventory_reference(&[]),
                terminal_position: 20,
                policy: reference(4),
                trust: reference(5),
            },
        )?],
        receipts: vec![receipt],
        receipt_provenance: vec![receipt_provenance],
        ..ErasureSupportingRecordsInputV1::default()
    })
}

#[test]
fn correction_provenance_roundtrips_and_rejects_shape_changes() -> Result<(), ErasureErrorV1> {
    let record = ErasureCorrectionProvenanceV1::new(ErasureCorrectionProvenanceInputV1 {
        rejected_request: reference(1),
        rejected_terminal_state: reference(2),
        correction_reason: reference(3),
        authorization_provenance: reference(4),
    })?;
    assert_ne!(record.reference(), reference(0));
    let decoded = roundtrip(
        &record,
        ErasureCorrectionProvenanceV1::to_canonical_cbor,
        ErasureCorrectionProvenanceV1::from_canonical_cbor,
    )?;
    assert_eq!(decoded.rejected_request(), reference(1));
    assert_eq!(decoded.rejected_terminal_state(), reference(2));
    assert_eq!(decoded.correction_reason(), reference(3));
    assert_eq!(decoded.authorization_provenance(), reference(4));
    assert_eq!(decoded.reference(), record.digest());

    let bytes = record.to_canonical_cbor()?;
    let trailing = changed_array(&bytes, |fields| fields.push(Value::Null));
    let wrong_tag = changed_array(&bytes, |fields| {
        fields[0] = Value::Text("ERCP2".to_owned());
    });
    assert_eq!(
        ErasureCorrectionProvenanceV1::from_canonical_cbor(&trailing),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    assert_eq!(
        ErasureCorrectionProvenanceV1::from_canonical_cbor(&wrong_tag),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    Ok(())
}

fn retry_input() -> ErasureRetryAdmissionInputV1 {
    ErasureRetryAdmissionInputV1 {
        request: reference(1),
        attempt_ordinal: 1,
        source_receipt: Some(reference(2)),
        unresolved_obligations: vec![reference(5), reference(3)],
        command_identities: vec![reference(15), reference(13)],
        policy: reference(6),
        trust: reference(7),
        admitted_position: 20,
        deadline_position: 30,
        authorization_provenance: reference(8),
    }
}

#[test]
fn retry_admission_normalizes_pairs_and_preserves_all_identity_fields() -> Result<(), ErasureErrorV1>
{
    let record = ErasureRetryAdmissionV1::new(retry_input())?;
    assert_ne!(record.reference(), reference(0));
    let decoded = roundtrip(
        &record,
        ErasureRetryAdmissionV1::to_canonical_cbor,
        ErasureRetryAdmissionV1::from_canonical_cbor,
    )?;
    assert_eq!(decoded.request(), reference(1));
    assert_eq!(decoded.attempt_ordinal(), 1);
    assert_eq!(decoded.source_receipt(), Some(reference(2)));
    assert_eq!(
        decoded.unresolved_obligations(),
        &[reference(3), reference(5)]
    );
    assert_eq!(
        decoded.command_identities(),
        &[reference(13), reference(15)]
    );
    assert_eq!(decoded.policy(), reference(6));
    assert_eq!(decoded.trust(), reference(7));
    assert_eq!(decoded.admitted_position(), 20);
    assert_eq!(decoded.deadline_position(), 30);
    assert_eq!(decoded.authorization_provenance(), reference(8));
    assert_eq!(decoded.reference(), record.digest());
    Ok(())
}

#[test]
fn retry_admission_rejects_invalid_ordinals_deadlines_and_obligation_sets() {
    let mut first_with_predecessor = retry_input();
    first_with_predecessor.attempt_ordinal = 0;
    assert_eq!(
        ErasureRetryAdmissionV1::new(first_with_predecessor),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let mut later_without_predecessor = retry_input();
    later_without_predecessor.source_receipt = None;
    assert_eq!(
        ErasureRetryAdmissionV1::new(later_without_predecessor),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let mut expired_before_admission = retry_input();
    expired_before_admission.deadline_position = 19;
    assert_eq!(
        ErasureRetryAdmissionV1::new(expired_before_admission),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let mut deadline_at_admission = retry_input();
    deadline_at_admission.deadline_position = deadline_at_admission.admitted_position;
    assert!(ErasureRetryAdmissionV1::new(deadline_at_admission).is_ok());

    let mut ordinal_at_bound = retry_input();
    ordinal_at_bound.attempt_ordinal = ERASURE_MAX_ATTEMPT_OUTCOMES as u64;
    assert_eq!(
        ErasureRetryAdmissionV1::new(ordinal_at_bound),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let mut mismatched_commands = retry_input();
    mismatched_commands.command_identities.pop();
    assert_eq!(
        ErasureRetryAdmissionV1::new(mismatched_commands),
        Err(ErasureErrorV1::ScopeInvalid)
    );

    let mut empty_obligations = retry_input();
    empty_obligations.unresolved_obligations.clear();
    empty_obligations.command_identities.clear();
    assert_eq!(
        ErasureRetryAdmissionV1::new(empty_obligations),
        Err(ErasureErrorV1::ScopeInvalid)
    );

    let mut oversized_obligations = retry_input();
    oversized_obligations.unresolved_obligations = vec![reference(20); ERASURE_MAX_OBLIGATIONS + 1];
    oversized_obligations.command_identities = vec![reference(21); ERASURE_MAX_OBLIGATIONS + 1];
    assert_eq!(
        ErasureRetryAdmissionV1::new(oversized_obligations),
        Err(ErasureErrorV1::ScopeInvalid)
    );

    let mut duplicate_obligations = retry_input();
    duplicate_obligations.unresolved_obligations[1] = reference(5);
    assert_eq!(
        ErasureRetryAdmissionV1::new(duplicate_obligations),
        Err(ErasureErrorV1::ScopeInvalid)
    );

    let mut shared_commands = retry_input();
    shared_commands.command_identities[1] = reference(15);
    assert!(ErasureRetryAdmissionV1::new(shared_commands).is_ok());
}

#[test]
fn acknowledgement_provenance_roundtrips_with_attempt_scoped_identity() -> Result<(), ErasureErrorV1>
{
    let record =
        ErasureAcknowledgementProvenanceV1::new(ErasureAcknowledgementProvenanceInputV1 {
            request: reference(1),
            command: reference(2),
            attempt: reference(3),
            obligation: reference(4),
            owner: reference(5),
            scope: reference(6),
            outcome: ErasureAcknowledgementOutcomeV1::Acknowledged,
            evidence: reference(7),
            policy: reference(8),
            trust: reference(9),
        })?;
    assert_ne!(record.reference(), reference(0));
    let decoded = roundtrip(
        &record,
        ErasureAcknowledgementProvenanceV1::to_canonical_cbor,
        ErasureAcknowledgementProvenanceV1::from_canonical_cbor,
    )?;
    assert_eq!(decoded.request(), reference(1));
    assert_eq!(decoded.command(), reference(2));
    assert_eq!(decoded.attempt(), reference(3));
    assert_eq!(decoded.obligation(), reference(4));
    assert_eq!(decoded.owner(), reference(5));
    assert_eq!(decoded.scope(), reference(6));
    assert_eq!(
        decoded.outcome(),
        ErasureAcknowledgementOutcomeV1::Acknowledged
    );
    assert_eq!(decoded.evidence(), reference(7));
    assert_eq!(decoded.policy(), reference(8));
    assert_eq!(decoded.trust(), reference(9));
    assert_eq!(decoded.reference(), record.digest());

    let bytes = record.to_canonical_cbor()?;
    let unknown_outcome = changed_array(&bytes, |fields| {
        fields[8] = Value::Integer(99.into());
    });
    assert_eq!(
        ErasureAcknowledgementProvenanceV1::from_canonical_cbor(&unknown_outcome),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    Ok(())
}

#[test]
fn attempt_outcome_accepts_only_attempt_terminal_destruction_results() -> Result<(), ErasureErrorV1>
{
    let input = ErasureAttemptOutcomeInputV1 {
        request: reference(1),
        attempt: reference(2),
        source_receipt: Some(reference(3)),
        lifecycle: ErasureLifecycleV1::PartialFailure,
        selected_obligations: reference(4),
        acknowledgement_inventory: reference(5),
        terminal_position: 40,
        policy: reference(6),
        trust: reference(7),
    };
    let record = ErasureAttemptOutcomeV1::new(input)?;
    assert_ne!(record.reference(), reference(0));
    let decoded = roundtrip(
        &record,
        ErasureAttemptOutcomeV1::to_canonical_cbor,
        ErasureAttemptOutcomeV1::from_canonical_cbor,
    )?;
    assert_eq!(decoded.request(), reference(1));
    assert_eq!(decoded.attempt(), reference(2));
    assert_eq!(decoded.source_receipt(), Some(reference(3)));
    assert_eq!(decoded.lifecycle(), ErasureLifecycleV1::PartialFailure);
    assert_eq!(decoded.selected_obligations(), reference(4));
    assert_eq!(decoded.acknowledgement_inventory(), reference(5));
    assert_eq!(decoded.terminal_position(), 40);
    assert_eq!(decoded.policy(), reference(6));
    assert_eq!(decoded.trust(), reference(7));
    assert_eq!(decoded.reference(), record.digest());

    let mut invalid = input;
    invalid.lifecycle = ErasureLifecycleV1::AwaitingAcknowledgements;
    assert_eq!(
        ErasureAttemptOutcomeV1::new(invalid),
        Err(ErasureErrorV1::PolicyConflict)
    );
    assert!(ErasureAttemptOutcomeV1::new(ErasureAttemptOutcomeInputV1 {
        lifecycle: ErasureLifecycleV1::Complete,
        ..input
    })
    .is_ok());
    Ok(())
}

#[test]
fn receipt_provenance_enforces_the_nonbranching_ordinal_shape() -> Result<(), ErasureErrorV1> {
    let input = ErasureReceiptProvenanceInputV1 {
        request: reference(1),
        attempt: reference(2),
        attempt_ordinal: 1,
        predecessor_receipt: Some(reference(3)),
        terminal_state: reference(4),
        evidence_set: reference(5),
        policy: reference(6),
        trust: reference(7),
        issue_position: 50,
    };
    let record = ErasureReceiptProvenanceV1::new(input)?;
    assert_ne!(record.reference(), reference(0));
    let decoded = roundtrip(
        &record,
        ErasureReceiptProvenanceV1::to_canonical_cbor,
        ErasureReceiptProvenanceV1::from_canonical_cbor,
    )?;
    assert_eq!(decoded.request(), reference(1));
    assert_eq!(decoded.attempt(), reference(2));
    assert_eq!(decoded.attempt_ordinal(), 1);
    assert_eq!(decoded.predecessor_receipt(), Some(reference(3)));
    assert_eq!(decoded.terminal_state(), reference(4));
    assert_eq!(decoded.evidence_set(), reference(5));
    assert_eq!(decoded.policy(), reference(6));
    assert_eq!(decoded.trust(), reference(7));
    assert_eq!(decoded.issue_position(), 50);
    assert_eq!(decoded.reference(), record.digest());

    let mut zero_with_predecessor = input;
    zero_with_predecessor.attempt_ordinal = 0;
    assert_eq!(
        ErasureReceiptProvenanceV1::new(zero_with_predecessor),
        Err(ErasureErrorV1::PolicyConflict)
    );
    let mut later_without_predecessor = input;
    later_without_predecessor.predecessor_receipt = None;
    assert_eq!(
        ErasureReceiptProvenanceV1::new(later_without_predecessor),
        Err(ErasureErrorV1::PolicyConflict)
    );
    let mut over_bound = input;
    over_bound.attempt_ordinal = ERASURE_MAX_ATTEMPT_OUTCOMES as u64;
    assert_eq!(
        ErasureReceiptProvenanceV1::new(over_bound),
        Err(ErasureErrorV1::PolicyConflict)
    );
    Ok(())
}

#[test]
fn administrative_resolution_normalizes_evidence_and_rejects_duplicates(
) -> Result<(), ErasureErrorV1> {
    let input = ErasureAdministrativeResolutionInputV1 {
        request: reference(1),
        affected_digests: vec![reference(4), reference(2)],
        action: ErasureAdministrativeResolutionActionV1::RecoverExactEvidence,
        scope_commitment: reference(5),
        policy: reference(6),
        trust: reference(7),
        principal: reference(8),
        authorization_provenance: reference(9),
        reason: reference(10),
        issue_position: 60,
        predecessor_resolution: Some(reference(11)),
    };
    let record = ErasureAdministrativeResolutionV1::new(input.clone())?;
    assert_ne!(record.reference(), reference(0));
    let decoded = roundtrip(
        &record,
        ErasureAdministrativeResolutionV1::to_canonical_cbor,
        ErasureAdministrativeResolutionV1::from_canonical_cbor,
    )?;
    assert_eq!(decoded.request(), reference(1));
    assert_eq!(decoded.affected_digests(), &[reference(2), reference(4)]);
    assert_eq!(
        decoded.action(),
        ErasureAdministrativeResolutionActionV1::RecoverExactEvidence
    );
    assert_eq!(decoded.scope_commitment(), reference(5));
    assert_eq!(decoded.policy(), reference(6));
    assert_eq!(decoded.trust(), reference(7));
    assert_eq!(decoded.principal(), reference(8));
    assert_eq!(decoded.authorization_provenance(), reference(9));
    assert_eq!(decoded.reason(), reference(10));
    assert_eq!(decoded.issue_position(), 60);
    assert_eq!(decoded.predecessor_resolution(), Some(reference(11)));
    assert_eq!(decoded.reference(), record.digest());

    let mut duplicate = input.clone();
    duplicate.affected_digests = vec![reference(2), reference(2)];
    assert_eq!(
        ErasureAdministrativeResolutionV1::new(duplicate),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    let mut empty = input;
    empty.affected_digests.clear();
    assert_eq!(
        ErasureAdministrativeResolutionV1::new(empty),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    assert_eq!(
        ErasureAdministrativeResolutionActionV1::from_code(0)?,
        ErasureAdministrativeResolutionActionV1::CloseContainment
    );
    assert_eq!(
        ErasureAdministrativeResolutionActionV1::from_code(1)?,
        ErasureAdministrativeResolutionActionV1::RecoverExactEvidence
    );
    assert_eq!(
        ErasureAdministrativeResolutionActionV1::from_code(2),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    Ok(())
}

#[test]
fn lifecycle_distinguishes_request_terminality_from_attempt_terminality() {
    assert!(ErasureLifecycleV1::PartialFailure.permits(ErasureLifecycleV1::PartialFailure));
    assert!(ErasureLifecycleV1::PartialFailure.permits(ErasureLifecycleV1::Complete));
    assert!(!ErasureLifecycleV1::PartialFailure.permits(ErasureLifecycleV1::Authorized));
    assert!(!ErasureLifecycleV1::PartialFailure.is_terminal());
    assert!(ErasureLifecycleV1::PartialFailure.is_attempt_terminal());
    assert!(ErasureLifecycleV1::Complete.is_terminal());
    assert!(ErasureLifecycleV1::Rejected.is_terminal());
}

#[test]
fn supporting_record_decoders_enforce_their_public_size_bounds() {
    assert_eq!(ERASURE_PORTABLE_RECORD_MAX_BYTES, 1_048_576);
    assert_eq!(ERASURE_RETRY_ADMISSION_MAX_BYTES, 16_777_216);

    let oversized = vec![0; ERASURE_PORTABLE_RECORD_MAX_BYTES + 1];
    assert_eq!(
        ErasureCorrectionProvenanceV1::from_canonical_cbor(&oversized),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    assert_eq!(
        ErasureAcknowledgementProvenanceV1::from_canonical_cbor(&oversized),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    assert_eq!(
        ErasureAttemptOutcomeV1::from_canonical_cbor(&oversized),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    assert_eq!(
        ErasureReceiptProvenanceV1::from_canonical_cbor(&oversized),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    assert_eq!(
        ErasureAdministrativeResolutionV1::from_canonical_cbor(&oversized),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    let oversized_retry = vec![0; ERASURE_RETRY_ADMISSION_MAX_BYTES + 1];
    assert_eq!(
        ErasureRetryAdmissionV1::from_canonical_cbor(&oversized_retry),
        Err(ErasureErrorV1::ScopeInvalid)
    );
}

#[test]
fn supporting_records_accept_one_active_attempt_and_a_nonbranching_resolution(
) -> Result<(), ErasureErrorV1> {
    let request = reference(1);
    let scope = scope_commitment(request)?;
    let obligation = obligation(request)?;
    let obligation_set = ErasureObligationSetV1::new(ErasureObligationSetInputV1 {
        request,
        obligations: vec![obligation.reference()],
        policy: reference(4),
        trust: reference(5),
    })?;
    let admission = initial_admission(request)?;
    let acknowledgement = ErasureAcknowledgementProvenanceV1::new(
        acknowledgement_provenance_input(request, admission.reference())?,
    )?;
    let resolution = administrative_resolution(request, scope.reference(), None)?;
    let records = ErasureSupportingRecordsV1::new(ErasureSupportingRecordsInputV1 {
        scope_commitment: Some(scope),
        obligations: vec![obligation],
        obligation_set: Some(obligation_set),
        retry_admissions: vec![admission.clone()],
        acknowledgement_provenance: vec![acknowledgement],
        administrative_resolutions: vec![resolution.clone()],
        ..ErasureSupportingRecordsInputV1::default()
    })?;
    assert!(records.correction_provenance().is_none());
    assert_eq!(records.retry_admissions(), &[admission]);
    assert_eq!(records.acknowledgement_provenance(), &[acknowledgement]);
    assert!(records.attempt_outcomes().is_empty());
    assert!(records.receipts().is_empty());
    assert!(records.receipt_provenance().is_empty());
    assert_eq!(records.administrative_resolutions(), &[resolution]);
    let duplicate_arrival = ErasureSupportingRecordsV1::new(ErasureSupportingRecordsInputV1 {
        scope_commitment: records.scope_commitment().cloned(),
        obligations: records.obligations().to_vec(),
        obligation_set: records.obligation_set().cloned(),
        retry_admissions: records.retry_admissions().to_vec(),
        acknowledgement_provenance: vec![
            records.acknowledgement_provenance()[0],
            records.acknowledgement_provenance()[0],
        ],
        administrative_resolutions: records.administrative_resolutions().to_vec(),
        ..ErasureSupportingRecordsInputV1::default()
    });
    assert_eq!(duplicate_arrival, Err(ErasureErrorV1::PolicyConflict));
    Ok(())
}

#[test]
fn complete_supporting_records_expose_every_persisted_collection() -> Result<(), ErasureErrorV1> {
    let records = ErasureSupportingRecordsV1::new(complete_supporting_input(reference(1))?)?;
    assert!(records.correction_provenance().is_some());
    assert_eq!(records.retry_admissions().len(), 1);
    assert_eq!(records.acknowledgement_provenance().len(), 1);
    assert_eq!(records.attempt_outcomes().len(), 1);
    assert_eq!(records.receipts().len(), 1);
    assert_eq!(records.receipt_provenance().len(), 1);
    assert_eq!(records.administrative_resolutions().len(), 1);
    Ok(())
}

#[test]
fn every_portable_decoder_rejects_a_wrong_type_in_every_field() -> Result<(), ErasureErrorV1> {
    let input = complete_supporting_input(reference(1))?;
    let correction = input
        .correction_provenance
        .as_ref()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    assert_each_field_rejects(
        &correction.to_canonical_cbor()?,
        ErasureCorrectionProvenanceV1::from_canonical_cbor,
    )?;
    assert_each_field_rejects(
        &input.retry_admissions[0].to_canonical_cbor()?,
        ErasureRetryAdmissionV1::from_canonical_cbor,
    )?;
    assert_each_field_rejects(
        &input.acknowledgement_provenance[0].to_canonical_cbor()?,
        ErasureAcknowledgementProvenanceV1::from_canonical_cbor,
    )?;
    assert_each_field_rejects(
        &input.attempt_outcomes[0].to_canonical_cbor()?,
        ErasureAttemptOutcomeV1::from_canonical_cbor,
    )?;
    assert_each_field_rejects(
        &input.receipt_provenance[0].to_canonical_cbor()?,
        ErasureReceiptProvenanceV1::from_canonical_cbor,
    )?;
    assert_each_field_rejects(
        &input.administrative_resolutions[0].to_canonical_cbor()?,
        ErasureAdministrativeResolutionV1::from_canonical_cbor,
    )?;
    Ok(())
}

#[test]
fn freeze_record_decoders_reject_a_wrong_type_in_every_field() -> Result<(), ErasureErrorV1> {
    let request = reference(1);
    let rejection = ErasureAuthorizationRejectionV1::new(ErasureAuthorizationRejectionInputV1 {
        request,
        authorization_provenance: reference(2),
    })?;
    assert_each_field_rejects(
        &rejection.to_canonical_cbor()?,
        ErasureAuthorizationRejectionV1::from_canonical_cbor,
    )?;

    let scope = scope_commitment(request)?;
    assert_each_field_rejects(
        &scope.to_canonical_cbor()?,
        ErasureScopeCommitmentV1::from_canonical_cbor,
    )?;
    let obligation = obligation(request)?;
    let obligation_set = ErasureObligationSetV1::new(ErasureObligationSetInputV1 {
        request,
        obligations: vec![obligation.reference()],
        policy: reference(4),
        trust: reference(5),
    })?;
    let (admission, authorization) = freeze_evidence_fixture(
        request,
        scope.reference(),
        &obligation_set,
        &[required_target()],
        &[obligation],
        10,
        &reference(6).digest(),
    )?;
    assert_each_field_rejects(
        &admission.to_canonical_cbor()?,
        ErasureFreezeAdmissionEvidenceV1::from_canonical_cbor,
    )?;
    assert_each_field_rejects(
        &authorization.to_canonical_cbor()?,
        ErasureFreezeAuthorizationEvidenceV1::from_canonical_cbor,
    )?;
    let freeze = ErasureFreezeProvenanceV1::new(ErasureFreezeProvenanceInputV1 {
        request,
        scope_commitment: scope.reference(),
        obligation_set: obligation_set.reference(),
        freeze_position: 10,
        host_evidence: admission.reference(),
    })?;
    assert_each_field_rejects(
        &freeze.to_canonical_cbor()?,
        ErasureFreezeProvenanceV1::from_canonical_cbor,
    )?;

    let failure = ErasureFreezeFailureV1::new(ErasureFreezeFailureInputV1 {
        request,
        error: ErasureErrorV1::ScopeInvalid,
        authorization_provenance: reference(2),
        evidence: reference(6),
    })?;
    assert_each_field_rejects(
        &failure.to_canonical_cbor()?,
        ErasureFreezeFailureV1::from_canonical_cbor,
    )?;
    Ok(())
}

#[test]
fn freeze_admission_and_authorization_roundtrip_through_public_codecs() -> Result<(), ErasureErrorV1>
{
    let input = freeze_supporting_input(reference(1))?;
    let admission = input
        .freeze_admission_evidence
        .clone()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    let authorization = input
        .freeze_authorization_evidence
        .clone()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    let scope_reference = input
        .scope_commitment
        .as_ref()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?
        .reference();
    let obligation_set_reference = input
        .obligation_set
        .as_ref()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?
        .reference();

    let decoded_admission = roundtrip(
        &admission,
        ErasureFreezeAdmissionEvidenceV1::to_canonical_cbor,
        ErasureFreezeAdmissionEvidenceV1::from_canonical_cbor,
    )?;
    assert_eq!(decoded_admission.request(), reference(1));
    assert_eq!(decoded_admission.scope_commitment(), scope_reference);
    assert_eq!(decoded_admission.obligation_set(), obligation_set_reference);
    assert_eq!(decoded_admission.applicability_matrix().len(), 4);
    assert_eq!(
        decoded_admission.applicability_matrix()[0].decision(),
        ErasureApplicabilityDecisionV1::Applicable
    );
    for row in &decoded_admission.applicability_matrix()[1..] {
        assert_eq!(row.decision(), ErasureApplicabilityDecisionV1::Inapplicable);
        assert_eq!(row.owner(), None);
    }
    assert_eq!(decoded_admission.freeze_position(), 10);
    assert_eq!(decoded_admission.policy(), reference(4));
    assert_eq!(decoded_admission.trust(), reference(5));
    assert_eq!(
        decoded_admission.authorization_provenance(),
        authorization.reference()
    );
    assert_eq!(decoded_admission.reference(), admission.reference());

    let decoded_authorization = roundtrip(
        &authorization,
        ErasureFreezeAuthorizationEvidenceV1::to_canonical_cbor,
        ErasureFreezeAuthorizationEvidenceV1::from_canonical_cbor,
    )?;
    assert_eq!(
        decoded_authorization.admission_body_digest(),
        admission.authorization_body_digest()?
    );
    assert_eq!(decoded_authorization.policy(), reference(4));
    assert_eq!(decoded_authorization.trust(), reference(5));
    assert_eq!(decoded_authorization.evidence(), &[6; 32]);
    assert_eq!(decoded_authorization.reference(), authorization.reference());
    Ok(())
}

#[test]
fn freeze_admission_codec_rejects_incomplete_and_noncanonical_matrix() -> Result<(), ErasureErrorV1>
{
    let input = freeze_supporting_input(reference(1))?;
    let admission = input
        .freeze_admission_evidence
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    let bytes = admission.to_canonical_cbor()?;

    let omitted_row = changed_array(&bytes, |fields| {
        if let Value::Array(matrix) = &mut fields[5] {
            matrix.pop();
        }
    });
    assert_eq!(
        ErasureFreezeAdmissionEvidenceV1::from_canonical_cbor(&omitted_row),
        Err(ErasureErrorV1::ScopeInvalid)
    );

    let reordered_row = changed_array(&bytes, |fields| {
        if let Value::Array(matrix) = &mut fields[5] {
            matrix.swap(0, 1);
        }
    });
    assert_eq!(
        ErasureFreezeAdmissionEvidenceV1::from_canonical_cbor(&reordered_row),
        Err(ErasureErrorV1::ScopeInvalid)
    );

    let wrong_decision_owner_form = changed_array(&bytes, |fields| {
        if let Value::Array(matrix) = &mut fields[5] {
            let Value::Array(row) = &mut matrix[0] else {
                return;
            };
            row[2] = Value::Integer(0.into());
        }
    });
    assert_eq!(
        ErasureFreezeAdmissionEvidenceV1::from_canonical_cbor(&wrong_decision_owner_form),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    Ok(())
}

#[test]
fn freeze_supporting_records_bind_erfa1_and_erfaa1_content() -> Result<(), ErasureErrorV1> {
    let input = freeze_supporting_input(reference(1))?;
    let admission = input
        .freeze_admission_evidence
        .clone()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    let authorization = input
        .freeze_authorization_evidence
        .clone()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    let records = ErasureSupportingRecordsV1::new(input.clone())?;
    assert_eq!(records.freeze_admission_evidence(), Some(&admission));
    assert_eq!(
        records.freeze_authorization_evidence(),
        Some(&authorization)
    );
    assert_eq!(
        records
            .freeze_provenance()
            .map(|freeze| freeze.host_evidence()),
        Some(admission.reference())
    );

    let mut wrong_body_digest = input.clone();
    wrong_body_digest.freeze_authorization_evidence = Some(
        ErasureFreezeAuthorizationEvidenceV1::new(ErasureFreezeAuthorizationEvidenceInputV1 {
            admission_body_digest: reference(99),
            policy: authorization.policy(),
            trust: authorization.trust(),
            evidence: authorization.evidence().to_vec(),
        })?,
    );
    assert_eq!(
        ErasureSupportingRecordsV1::new(wrong_body_digest),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    let mut wrong_policy = input.clone();
    wrong_policy.freeze_authorization_evidence = Some(ErasureFreezeAuthorizationEvidenceV1::new(
        ErasureFreezeAuthorizationEvidenceInputV1 {
            admission_body_digest: authorization.admission_body_digest(),
            policy: reference(98),
            trust: authorization.trust(),
            evidence: authorization.evidence().to_vec(),
        },
    )?);
    assert_eq!(
        ErasureSupportingRecordsV1::new(wrong_policy),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    let mut wrong_trust = input;
    wrong_trust.freeze_authorization_evidence = Some(ErasureFreezeAuthorizationEvidenceV1::new(
        ErasureFreezeAuthorizationEvidenceInputV1 {
            admission_body_digest: authorization.admission_body_digest(),
            policy: authorization.policy(),
            trust: reference(97),
            evidence: authorization.evidence().to_vec(),
        },
    )?);
    assert_eq!(
        ErasureSupportingRecordsV1::new(wrong_trust),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}

#[test]
fn freeze_supporting_records_bind_admission_and_host_references() -> Result<(), ErasureErrorV1> {
    let input = freeze_supporting_input(reference(1))?;
    let admission = input
        .freeze_admission_evidence
        .clone()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    let mut wrong_admission_reference = input.clone();
    let mismatched_admission =
        ErasureFreezeAdmissionEvidenceV1::new(ErasureFreezeAdmissionEvidenceInputV1 {
            request: admission.request(),
            scope_commitment: admission.scope_commitment(),
            obligation_set: admission.obligation_set(),
            applicability_matrix: admission.applicability_matrix().to_vec(),
            freeze_position: admission.freeze_position(),
            policy: admission.policy(),
            trust: admission.trust(),
            authorization_provenance: reference(96),
        })?;
    let mismatched_freeze = wrong_admission_reference
        .freeze_provenance
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    wrong_admission_reference.freeze_admission_evidence = Some(mismatched_admission.clone());
    wrong_admission_reference.freeze_provenance = Some(ErasureFreezeProvenanceV1::new(
        ErasureFreezeProvenanceInputV1 {
            request: mismatched_freeze.request(),
            scope_commitment: mismatched_freeze.scope_commitment(),
            obligation_set: mismatched_freeze.obligation_set(),
            freeze_position: mismatched_freeze.freeze_position(),
            host_evidence: mismatched_admission.reference(),
        },
    )?);
    assert_eq!(
        ErasureSupportingRecordsV1::new(wrong_admission_reference),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    let mut wrong_host_evidence = input;
    let freeze = wrong_host_evidence
        .freeze_provenance
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    wrong_host_evidence.freeze_provenance = Some(ErasureFreezeProvenanceV1::new(
        ErasureFreezeProvenanceInputV1 {
            request: freeze.request(),
            scope_commitment: freeze.scope_commitment(),
            obligation_set: freeze.obligation_set(),
            freeze_position: freeze.freeze_position(),
            host_evidence: reference(95),
        },
    )?);
    assert_eq!(
        ErasureSupportingRecordsV1::new(wrong_host_evidence),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}

#[test]
fn obligation_record_decoders_reject_a_wrong_type_in_every_field() -> Result<(), ErasureErrorV1> {
    let request = reference(1);
    let obligation = obligation(request)?;
    assert_each_field_rejects(
        &obligation.to_canonical_cbor()?,
        ErasureObligationV1::from_canonical_cbor,
    )?;
    let set = ErasureObligationSetV1::new(ErasureObligationSetInputV1 {
        request,
        obligations: vec![obligation.reference()],
        policy: reference(4),
        trust: reference(5),
    })?;
    assert_each_field_rejects(
        &set.to_canonical_cbor()?,
        ErasureObligationSetV1::from_canonical_cbor,
    )?;

    let scope = scope_commitment(request)?;
    let extension = ErasureScopeExtensionV1::new(ErasureScopeExtensionInputV1 {
        request,
        scope_commitment: scope.reference(),
        fork: reference(6),
        lineage_rule: reference(7),
        predecessor_extension: None,
        admission_provenance: reference(8),
    })?;
    assert_each_field_rejects(
        &extension.to_canonical_cbor()?,
        ErasureScopeExtensionV1::from_canonical_cbor,
    )?;
    let ledger = ErasureScopeExtensionLedgerV1::new(ErasureScopeExtensionLedgerInputV1 {
        scope_commitment: scope.reference(),
        extensions: vec![extension.reference()],
        head: Some(extension.reference()),
    })?;
    assert_each_field_rejects(
        &ledger.to_canonical_cbor()?,
        ErasureScopeExtensionLedgerV1::from_canonical_cbor,
    )?;
    Ok(())
}

#[test]
fn supporting_decoder_rehydrates_each_optional_freeze_record() -> Result<(), ErasureErrorV1> {
    let request = reference(1);
    let rejection = ErasureAuthorizationRejectionV1::new(ErasureAuthorizationRejectionInputV1 {
        request,
        authorization_provenance: reference(2),
    })?;
    let failure = ErasureFreezeFailureV1::new(ErasureFreezeFailureInputV1 {
        request,
        error: ErasureErrorV1::ScopeInvalid,
        authorization_provenance: reference(2),
        evidence: reference(6),
    })?;
    for input in [
        ErasureSupportingRecordsInputV1 {
            authorization_rejection: Some(rejection),
            ..ErasureSupportingRecordsInputV1::default()
        },
        ErasureSupportingRecordsInputV1 {
            freeze_failure: Some(failure),
            ..ErasureSupportingRecordsInputV1::default()
        },
    ] {
        let records = ErasureSupportingRecordsV1::new(input)?;
        assert_eq!(
            roundtrip(
                &records,
                ErasureSupportingRecordsV1::to_canonical_cbor,
                ErasureSupportingRecordsV1::from_canonical_cbor,
            )?,
            records
        );
    }

    let records = ErasureSupportingRecordsV1::new(freeze_supporting_input(request)?)?;
    assert_eq!(
        roundtrip(
            &records,
            ErasureSupportingRecordsV1::to_canonical_cbor,
            ErasureSupportingRecordsV1::from_canonical_cbor,
        )?,
        records
    );
    Ok(())
}

#[test]
fn portable_reference_decoders_reject_duplicate_entries() -> Result<(), ErasureErrorV1> {
    let input = complete_supporting_input(reference(1))?;
    let retry = input.retry_admissions[0].to_canonical_cbor()?;
    for field in [5, 6] {
        let duplicate = changed_array(&retry, |fields| {
            fields[field] =
                Value::Array(vec![Value::Bytes(vec![9; 32]), Value::Bytes(vec![9; 32])]);
        });
        assert_eq!(
            ErasureRetryAdmissionV1::from_canonical_cbor(&duplicate),
            Err(ErasureErrorV1::ScopeInvalid)
        );
    }
    let resolution = input.administrative_resolutions[0].to_canonical_cbor()?;
    let duplicate = changed_array(&resolution, |fields| {
        fields[3] = Value::Array(vec![Value::Bytes(vec![9; 32]), Value::Bytes(vec![9; 32])]);
    });
    assert_eq!(
        ErasureAdministrativeResolutionV1::from_canonical_cbor(&duplicate),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    Ok(())
}

#[test]
fn portable_decoders_reject_unknown_closed_enum_codes() -> Result<(), ErasureErrorV1> {
    let input = complete_supporting_input(reference(1))?;
    let outcome = changed_array(&input.attempt_outcomes[0].to_canonical_cbor()?, |fields| {
        fields[5] = Value::Integer(99.into());
    });
    assert_eq!(
        ErasureAttemptOutcomeV1::from_canonical_cbor(&outcome),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    let resolution = changed_array(
        &input.administrative_resolutions[0].to_canonical_cbor()?,
        |fields| {
            fields[4] = Value::Integer(99.into());
        },
    );
    assert_eq!(
        ErasureAdministrativeResolutionV1::from_canonical_cbor(&resolution),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    Ok(())
}

fn coordinator_with_correction_provenance() -> Result<ErasureCoordinatorRecordV1, ErasureErrorV1> {
    let correction = ErasureCorrectionProvenanceV1::new(ErasureCorrectionProvenanceInputV1 {
        rejected_request: reference(70),
        rejected_terminal_state: reference(71),
        correction_reason: reference(72),
        authorization_provenance: reference(73),
    })?;
    let request = ErasureRequestV1::new(ErasureRequestInputV1 {
        request: reference(60),
        subject: reference(61),
        scope: ErasureScopeV1::PrivateSubjectData,
        selectors: vec![reference(62)],
        requester: reference(63),
        authorization: reference(64),
        policy: reference(65),
        request_position: 10,
        horizon_position: 20,
        provenance: correction.reference(),
    })?;
    let coordinator = reference(66);
    let state = ErasureStateV1::submitted(request.reference(), coordinator, reference(67))?;
    let supporting_records = ErasureSupportingRecordsV1::new(ErasureSupportingRecordsInputV1 {
        correction_provenance: Some(correction),
        scope_commitment: None,
        freeze_provenance: None,
        freeze_failure: None,
        retry_admissions: Vec::new(),
        acknowledgement_provenance: Vec::new(),
        attempt_outcomes: Vec::new(),
        receipts: Vec::new(),
        receipt_provenance: Vec::new(),
        administrative_resolutions: Vec::new(),
        ..ErasureSupportingRecordsInputV1::default()
    })?;
    ErasureCoordinatorRecordV1::from_parts(
        ErasureCoordinatorRecordPartsV1 {
            request,
            state,
            targets: Vec::new(),
            acknowledgements: Vec::new(),
            receipt: None,
            receipt_input: None,
            authorize_provenance: None,
            freeze_provenance: None,
            dispatch_provenance: None,
            scope_extension_ledger: None,
            administrative_resolution_head: None,
            supporting_records,
        },
        coordinator,
    )
}

fn changed_supporting_records(bytes: &[u8], change: impl FnOnce(&mut Vec<Value>)) -> Vec<u8> {
    changed_array(bytes, |record_fields| {
        let Value::Array(supporting_fields) = &mut record_fields[12] else {
            return;
        };
        change(supporting_fields);
    })
}

#[test]
fn coordinator_decoder_exercises_embedded_correction_path() -> Result<(), ErasureErrorV1> {
    let record = coordinator_with_correction_provenance()?;
    let bytes = record.to_canonical_cbor()?;
    assert!(record.validate_replacement(&record).is_ok());
    assert_eq!(
        ErasureCoordinatorRecordV1::from_canonical_cbor(&bytes)?,
        record
    );
    let malformed = changed_supporting_records(&bytes, |fields| {
        fields[0] = Value::Bool(false);
    });
    assert!(ErasureCoordinatorRecordV1::from_canonical_cbor(&malformed).is_err());

    let malformed = changed_supporting_records(&bytes, |fields| {
        fields[0] = Value::Array(Vec::new());
    });
    assert!(ErasureCoordinatorRecordV1::from_canonical_cbor(&malformed).is_err());
    let wrong_correction = changed_supporting_records(&bytes, |fields| {
        let Value::Array(correction) = &mut fields[0] else {
            return;
        };
        correction[4] = Value::Bytes(vec![99; 32]);
    });
    assert_eq!(
        ErasureCoordinatorRecordV1::from_canonical_cbor(&wrong_correction),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    let malformed_correction = changed_supporting_records(&bytes, |fields| {
        let Value::Array(correction) = &mut fields[0] else {
            return;
        };
        correction[2] = Value::Bool(false);
    });
    assert!(ErasureCoordinatorRecordV1::from_canonical_cbor(&malformed_correction).is_err());
    Ok(())
}

#[test]
fn supporting_attempt_chain_rejects_gaps_and_identity_mismatches() -> Result<(), ErasureErrorV1> {
    let input = complete_supporting_input(reference(1))?;
    assert!(ErasureSupportingRecordsV1::new(input.clone()).is_ok());

    let mut missing_admission = input.clone();
    missing_admission.retry_admissions.clear();
    assert_eq!(
        ErasureSupportingRecordsV1::new(missing_admission),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let mut unequal_lengths = input.clone();
    unequal_lengths.receipt_provenance.clear();
    assert_eq!(
        ErasureSupportingRecordsV1::new(unequal_lengths),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let mut wrong_ordinal = input.clone();
    wrong_ordinal.retry_admissions[0] =
        ErasureRetryAdmissionV1::new(ErasureRetryAdmissionInputV1 {
            attempt_ordinal: 1,
            source_receipt: Some(reference(99)),
            ..retry_input()
        })?;
    assert_eq!(
        ErasureSupportingRecordsV1::new(wrong_ordinal),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    let mut wrong_outcome = input.clone();
    wrong_outcome.attempt_outcomes[0] =
        ErasureAttemptOutcomeV1::new(ErasureAttemptOutcomeInputV1 {
            request: reference(1),
            attempt: reference(99),
            source_receipt: None,
            lifecycle: ErasureLifecycleV1::Complete,
            selected_obligations: reference(45),
            acknowledgement_inventory: reference(46),
            terminal_position: 20,
            policy: reference(4),
            trust: reference(5),
        })?;
    assert_eq!(
        ErasureSupportingRecordsV1::new(wrong_outcome),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    let mut wrong_provenance = input;
    let attempt = wrong_provenance.retry_admissions[0].reference();
    wrong_provenance.receipt_provenance[0] =
        ErasureReceiptProvenanceV1::new(ErasureReceiptProvenanceInputV1 {
            request: reference(1),
            attempt,
            attempt_ordinal: 0,
            predecessor_receipt: None,
            terminal_state: reference(99),
            evidence_set: reference(47),
            policy: reference(4),
            trust: reference(5),
            issue_position: 20,
        })?;
    assert_eq!(
        ErasureSupportingRecordsV1::new(wrong_provenance),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}

#[test]
fn supporting_attempt_chain_links_one_active_retry_to_the_previous_receipt(
) -> Result<(), ErasureErrorV1> {
    let input = partial_failure_supporting_input(reference(1))?;
    let previous_receipt = input.receipts[0].receipt_digest();
    let obligation = input.obligations[0];
    let retry_input = ErasureRetryAdmissionInputV1 {
        request: reference(1),
        attempt_ordinal: 1,
        source_receipt: Some(previous_receipt),
        unresolved_obligations: vec![obligation.reference()],
        command_identities: vec![obligation.command_identity()],
        policy: reference(4),
        trust: reference(5),
        admitted_position: 21,
        deadline_position: 30,
        authorization_provenance: reference(10),
    };
    let mut active_retry = input.clone();
    active_retry
        .retry_admissions
        .push(ErasureRetryAdmissionV1::new(retry_input.clone())?);
    assert!(ErasureSupportingRecordsV1::new(active_retry).is_ok());

    let mut wrong_predecessor = retry_input;
    wrong_predecessor.source_receipt = Some(reference(99));
    let mut invalid_retry = input;
    invalid_retry
        .retry_admissions
        .push(ErasureRetryAdmissionV1::new(wrong_predecessor)?);
    assert_eq!(
        ErasureSupportingRecordsV1::new(invalid_retry),
        Err(ErasureErrorV1::PolicyConflict)
    );
    Ok(())
}

#[test]
fn supporting_ledger_rejects_acknowledgement_and_resolution_forks() -> Result<(), ErasureErrorV1> {
    let input = complete_supporting_input(reference(1))?;
    let attempt = input.retry_admissions[0].reference();
    let mut wrong_command = input.clone();
    wrong_command.acknowledgement_provenance[0] =
        ErasureAcknowledgementProvenanceV1::new(ErasureAcknowledgementProvenanceInputV1 {
            command: reference(99),
            ..acknowledgement_provenance_input(reference(1), attempt)?
        })?;
    assert_eq!(
        ErasureSupportingRecordsV1::new(wrong_command),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    let mut duplicate_identity = input.clone();
    duplicate_identity
        .acknowledgement_provenance
        .push(ErasureAcknowledgementProvenanceV1::new(
            ErasureAcknowledgementProvenanceInputV1 {
                evidence: reference(98),
                ..acknowledgement_provenance_input(reference(1), attempt)?
            },
        )?);
    assert_eq!(
        ErasureSupportingRecordsV1::new(duplicate_identity),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let mut resolution_fork = input;
    resolution_fork.administrative_resolutions[0] = administrative_resolution(
        reference(1),
        scope_commitment(reference(1))?.reference(),
        Some(reference(99)),
    )?;
    assert_eq!(
        ErasureSupportingRecordsV1::new(resolution_fork),
        Err(ErasureErrorV1::PolicyConflict)
    );
    Ok(())
}

#[test]
fn supporting_acknowledgements_fail_closed_at_each_admission_binding() -> Result<(), ErasureErrorV1>
{
    let input = complete_supporting_input(reference(1))?;
    let attempt = input.retry_admissions[0].reference();
    let variants = [
        ErasureAcknowledgementProvenanceInputV1 {
            attempt: reference(99),
            ..acknowledgement_provenance_input(reference(1), attempt)?
        },
        ErasureAcknowledgementProvenanceInputV1 {
            request: reference(99),
            ..acknowledgement_provenance_input(reference(1), attempt)?
        },
        ErasureAcknowledgementProvenanceInputV1 {
            policy: reference(99),
            ..acknowledgement_provenance_input(reference(1), attempt)?
        },
        ErasureAcknowledgementProvenanceInputV1 {
            trust: reference(99),
            ..acknowledgement_provenance_input(reference(1), attempt)?
        },
    ];
    for variant in variants {
        let mut invalid = input.clone();
        invalid.acknowledgement_provenance[0] = ErasureAcknowledgementProvenanceV1::new(variant)?;
        assert_eq!(
            ErasureSupportingRecordsV1::new(invalid),
            Err(ErasureErrorV1::ProvenanceMissing)
        );
    }
    Ok(())
}

#[test]
fn supporting_resolution_chain_accepts_an_exact_predecessor() -> Result<(), ErasureErrorV1> {
    let mut input = complete_supporting_input(reference(1))?;
    let predecessor = input.administrative_resolutions[0].reference();
    input
        .administrative_resolutions
        .push(administrative_resolution(
            reference(1),
            scope_commitment(reference(1))?.reference(),
            Some(predecessor),
        )?);
    assert!(ErasureSupportingRecordsV1::new(input).is_ok());
    Ok(())
}

#[test]
fn supporting_ledger_bounds_each_attempt_scoped_collection() -> Result<(), ErasureErrorV1> {
    let input = complete_supporting_input(reference(1))?;
    let too_many = ERASURE_MAX_ATTEMPT_OUTCOMES + 1;

    let admissions = ErasureSupportingRecordsInputV1 {
        retry_admissions: vec![input.retry_admissions[0].clone(); too_many],
        ..ErasureSupportingRecordsInputV1::default()
    };
    assert_eq!(
        ErasureSupportingRecordsV1::new(admissions),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let outcomes = ErasureSupportingRecordsInputV1 {
        attempt_outcomes: vec![input.attempt_outcomes[0]; too_many],
        ..ErasureSupportingRecordsInputV1::default()
    };
    assert_eq!(
        ErasureSupportingRecordsV1::new(outcomes),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let receipts = ErasureSupportingRecordsInputV1 {
        receipts: vec![input.receipts[0].clone(); too_many],
        ..ErasureSupportingRecordsInputV1::default()
    };
    assert_eq!(
        ErasureSupportingRecordsV1::new(receipts),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let provenance = ErasureSupportingRecordsInputV1 {
        receipt_provenance: vec![input.receipt_provenance[0]; too_many],
        ..ErasureSupportingRecordsInputV1::default()
    };
    assert_eq!(
        ErasureSupportingRecordsV1::new(provenance),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let resolutions = ErasureSupportingRecordsInputV1 {
        administrative_resolutions: vec![
            input.administrative_resolutions[0].clone();
            ERASURE_MAX_ADMINISTRATIVE_RESOLUTIONS + 1
        ],
        ..ErasureSupportingRecordsInputV1::default()
    };
    assert_eq!(
        ErasureSupportingRecordsV1::new(resolutions),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let acknowledgements = ErasureSupportingRecordsInputV1 {
        acknowledgement_provenance: vec![
            input.acknowledgement_provenance[0];
            ERASURE_MAX_OBLIGATIONS + 1
        ],
        ..ErasureSupportingRecordsInputV1::default()
    };
    assert_eq!(
        ErasureSupportingRecordsV1::new(acknowledgements),
        Err(ErasureErrorV1::PolicyConflict)
    );
    Ok(())
}
