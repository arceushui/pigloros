//! Public-boundary coverage for the ADR-060 no-resurrection rejoin seam.

use pos_core::{
    ErasureAcknowledgementOutcomeV1, ErasureAcknowledgementV1, ErasureArtifactClassV1,
    ErasureArtifactTransitionV1, ErasureErrorV1, ErasureInventoryCategoryV1,
    ErasureInventoryResultV1, ErasureKeyRoleV1, ErasureLifecycleV1, ErasureReceiptInputV1,
    ErasureReceiptInventoriesV1, ErasureReceiptV1, ErasureReferenceV1,
    ErasureRejoinAttestationVerifierV1, ErasureRejoinDispositionV1, ErasureRejoinInventoryV1,
    ErasureRejoinProofInputV1, ErasureRejoinProofV1, ErasureReplayClaimV1, ErasureRequiredTargetV1,
    ERASURE_MAX_INVENTORY_RESULTS,
};

const fn reference(value: u8) -> ErasureReferenceV1 {
    ErasureReferenceV1::from_digest([value; 32])
}

const fn target(value: u8) -> ErasureRequiredTargetV1 {
    ErasureRequiredTargetV1 {
        artifact_class: ErasureArtifactClassV1::TimelineReplay,
        artifact_digest: reference(value),
        key_role: ErasureKeyRoleV1::DataEncryption,
        key_digest: reference(value.wrapping_add(1)),
        replica_set: reference(90),
        replica_id: reference(91),
    }
}

const fn inventory(
    category: ErasureInventoryCategoryV1,
    target: ErasureRequiredTargetV1,
    owner: ErasureReferenceV1,
    seed: u8,
) -> ErasureInventoryResultV1 {
    ErasureInventoryResultV1 {
        category,
        target,
        transition: ErasureArtifactTransitionV1 {
            from: ErasureReplayClaimV1::Exact,
            to: ErasureReplayClaimV1::StructuralOnly,
            reason: reference(seed),
            owner,
            acknowledgements: reference(seed.wrapping_add(1)),
            provenance: reference(seed.wrapping_add(2)),
        },
        retained_disclosure: reference(seed.wrapping_add(3)),
    }
}

fn receipt(lifecycle: ErasureLifecycleV1) -> Result<ErasureReceiptV1, ErasureErrorV1> {
    let replica_target = target(10);
    let backup_target = target(20);
    let replica_owner = reference(100);
    let backup_owner = reference(101);
    let inventories = ErasureReceiptInventoriesV1 {
        artifacts: Vec::new(),
        keys: Vec::new(),
        replicas: vec![inventory(
            ErasureInventoryCategoryV1::Replica,
            replica_target,
            replica_owner,
            110,
        )],
        backups: vec![inventory(
            ErasureInventoryCategoryV1::Backup,
            backup_target,
            backup_owner,
            120,
        )],
    };
    let acknowledgements = vec![
        ErasureAcknowledgementV1 {
            obligation: reference(130),
            target: replica_target,
            owner: replica_owner,
            evidence: reference(140),
            outcome: if lifecycle == ErasureLifecycleV1::Complete {
                ErasureAcknowledgementOutcomeV1::Acknowledged
            } else {
                ErasureAcknowledgementOutcomeV1::Negative
            },
        },
        ErasureAcknowledgementV1 {
            obligation: reference(131),
            target: backup_target,
            owner: backup_owner,
            evidence: reference(141),
            outcome: ErasureAcknowledgementOutcomeV1::Acknowledged,
        },
    ];
    let (pending_owners, failed_owners) = if lifecycle == ErasureLifecycleV1::Complete {
        (Vec::new(), Vec::new())
    } else {
        (Vec::new(), vec![replica_owner])
    };
    ErasureReceiptV1::new(ErasureReceiptInputV1 {
        request: reference(1),
        terminal_state: reference(2),
        coordinator: reference(3),
        lifecycle,
        freeze_position: 5,
        acknowledgements,
        frozen_targets: vec![replica_target, backup_target],
        pending_owners,
        failed_owners,
        inventories,
        replay_claim: ErasureReplayClaimV1::StructuralOnly,
        policy: reference(4),
        trust: reference(5),
        provenance: reference(6),
        issue_position: 7,
        signature: reference(8),
        receipt_digest: reference(0),
    })
}

fn partial_receipt_without_backups() -> Result<ErasureReceiptV1, ErasureErrorV1> {
    let replica_target = target(10);
    let replica_owner = reference(100);
    ErasureReceiptV1::new(ErasureReceiptInputV1 {
        request: reference(1),
        terminal_state: reference(2),
        coordinator: reference(3),
        lifecycle: ErasureLifecycleV1::PartialFailure,
        freeze_position: 5,
        acknowledgements: vec![ErasureAcknowledgementV1 {
            obligation: reference(130),
            target: replica_target,
            owner: replica_owner,
            evidence: reference(140),
            outcome: ErasureAcknowledgementOutcomeV1::Negative,
        }],
        frozen_targets: vec![replica_target],
        pending_owners: Vec::new(),
        failed_owners: vec![replica_owner],
        inventories: ErasureReceiptInventoriesV1 {
            artifacts: Vec::new(),
            keys: Vec::new(),
            replicas: vec![inventory(
                ErasureInventoryCategoryV1::Replica,
                replica_target,
                replica_owner,
                110,
            )],
            backups: Vec::new(),
        },
        replay_claim: ErasureReplayClaimV1::StructuralOnly,
        policy: reference(4),
        trust: reference(5),
        provenance: reference(6),
        issue_position: 7,
        signature: reference(8),
        receipt_digest: reference(0),
    })
}

fn proof_for(
    receipt: &ErasureReceiptV1,
    entries: Vec<ErasureRejoinInventoryV1>,
) -> Result<ErasureRejoinProofV1, ErasureErrorV1> {
    ErasureRejoinProofV1::new(proof_input(receipt, entries))
}

fn proof_input(
    receipt: &ErasureReceiptV1,
    entries: Vec<ErasureRejoinInventoryV1>,
) -> ErasureRejoinProofInputV1 {
    ErasureRejoinProofInputV1 {
        request: receipt.request(),
        terminal_receipt: receipt.receipt_digest(),
        replica_set: reference(90),
        replica_id: reference(91),
        inventory_generation: reference(200),
        entries,
        attestation: reference(201),
    }
}

struct TestAttestationVerifier {
    attestation: ErasureReferenceV1,
}

impl ErasureRejoinAttestationVerifierV1 for TestAttestationVerifier {
    fn verify(&self, proof: &ErasureRejoinProofV1) -> Result<(), ErasureErrorV1> {
        if proof.attestation() == self.attestation {
            Ok(())
        } else {
            Err(ErasureErrorV1::Unauthorized)
        }
    }
}

fn proof_entries() -> Vec<ErasureRejoinInventoryV1> {
    vec![
        ErasureRejoinInventoryV1 {
            category: ErasureInventoryCategoryV1::Backup,
            target: target(20),
            owner: reference(101),
            disposition: ErasureRejoinDispositionV1::Unrecoverable,
            evidence: reference(221),
        },
        ErasureRejoinInventoryV1 {
            category: ErasureInventoryCategoryV1::Replica,
            target: target(10),
            owner: reference(100),
            disposition: ErasureRejoinDispositionV1::Tombstoned,
            evidence: reference(220),
        },
    ]
}

fn wire_value(proof: &ErasureRejoinProofV1) -> Result<ciborium::value::Value, ErasureErrorV1> {
    let bytes = proof.to_canonical_cbor()?;
    ciborium::from_reader(bytes.as_slice()).map_err(|_| ErasureErrorV1::InvalidEncoding)
}

fn encode_wire_value(value: &ciborium::value::Value) -> Result<Vec<u8>, ErasureErrorV1> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes).map_err(|_| ErasureErrorV1::InvalidEncoding)?;
    Ok(bytes)
}

fn mutate_wire(
    proof: &ErasureRejoinProofV1,
    mutate: impl FnOnce(&mut Vec<ciborium::value::Value>),
) -> Result<Vec<u8>, ErasureErrorV1> {
    let mut value = wire_value(proof)?;
    let ciborium::value::Value::Array(fields) = &mut value else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    mutate(fields);
    encode_wire_value(&value)
}

fn mutate_entry(
    fields: &mut [ciborium::value::Value],
    index: usize,
    value: ciborium::value::Value,
) {
    if let ciborium::value::Value::Array(entries) = &mut fields[7] {
        if let ciborium::value::Value::Array(entry_fields) = &mut entries[0] {
            entry_fields[index] = value;
        }
    }
}

#[test]
fn complete_receipt_round_trips_and_admits_rejoin() -> Result<(), ErasureErrorV1> {
    let receipt = receipt(ErasureLifecycleV1::Complete)?;
    let proof = proof_for(&receipt, proof_entries())?;
    let verifier = TestAttestationVerifier {
        attestation: reference(201),
    };
    assert_eq!(
        proof.entries()[0].category,
        ErasureInventoryCategoryV1::Replica
    );
    let bytes = proof.to_canonical_cbor()?;
    let decoded = ErasureRejoinProofV1::from_canonical_cbor(&bytes)?;
    assert_eq!(decoded, proof);
    let admission = decoded.admit(&receipt, &verifier)?;
    assert_eq!(admission.request(), receipt.request());
    assert_eq!(admission.terminal_receipt(), receipt.receipt_digest());
    assert_eq!(admission.replica_set(), reference(90));
    assert_eq!(admission.replica_id(), reference(91));
    assert_eq!(decoded.inventory_generation(), reference(200));
    assert_eq!(decoded.attestation(), reference(201));
    assert_eq!(admission.proof(), proof.reference());
    Ok(())
}

#[test]
fn partial_receipt_denies_rejoin_until_backup_deletion_is_complete() -> Result<(), ErasureErrorV1> {
    let receipt = receipt(ErasureLifecycleV1::PartialFailure)?;
    let proof = proof_for(&receipt, proof_entries())?;
    let verifier = TestAttestationVerifier {
        attestation: reference(201),
    };
    assert_eq!(
        proof.admit(&receipt, &verifier),
        Err(ErasureErrorV1::BackupDeletionPending)
    );
    Ok(())
}

#[test]
fn incomplete_inventory_and_mismatched_receipt_are_rejected() -> Result<(), ErasureErrorV1> {
    let receipt = receipt(ErasureLifecycleV1::Complete)?;
    let missing_backup = proof_for(&receipt, vec![proof_entries().remove(1)])?;
    let verifier = TestAttestationVerifier {
        attestation: reference(201),
    };
    assert_eq!(
        missing_backup.admit(&receipt, &verifier),
        Err(ErasureErrorV1::BackupInventoryIncomplete)
    );

    let mismatched = ErasureRejoinProofV1::new(ErasureRejoinProofInputV1 {
        request: reference(9),
        terminal_receipt: receipt.receipt_digest(),
        replica_set: reference(90),
        replica_id: reference(91),
        inventory_generation: reference(200),
        entries: proof_entries(),
        attestation: reference(201),
    })?;
    assert_eq!(
        mismatched.admit(&receipt, &verifier),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}

#[test]
fn proof_digest_mutation_is_rejected() -> Result<(), ErasureErrorV1> {
    let receipt = receipt(ErasureLifecycleV1::Complete)?;
    let proof = proof_for(&receipt, proof_entries())?;
    let mut bytes = proof.to_canonical_cbor()?;
    let last = bytes.len().saturating_sub(1);
    bytes[last] ^= 1;
    assert_eq!(
        ErasureRejoinProofV1::from_canonical_cbor(&bytes),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}

#[test]
fn attestation_verifier_is_required_for_admission() -> Result<(), ErasureErrorV1> {
    let receipt = receipt(ErasureLifecycleV1::Complete)?;
    let proof = proof_for(&receipt, proof_entries())?;
    let verifier = TestAttestationVerifier {
        attestation: reference(202),
    };
    assert_eq!(
        proof.admit(&receipt, &verifier),
        Err(ErasureErrorV1::Unauthorized)
    );
    Ok(())
}

#[test]
fn reordered_wire_entries_are_rejected() -> Result<(), ErasureErrorV1> {
    let receipt = receipt(ErasureLifecycleV1::Complete)?;
    let proof = proof_for(&receipt, proof_entries())?;
    let bytes = proof.to_canonical_cbor()?;
    let mut value: ciborium::value::Value =
        ciborium::from_reader(bytes.as_slice()).map_err(|_| ErasureErrorV1::InvalidEncoding)?;
    if let ciborium::value::Value::Array(fields) = &mut value {
        if let ciborium::value::Value::Array(entries) = &mut fields[7] {
            entries.swap(0, 1);
        }
    }
    let mut reordered = Vec::new();
    ciborium::into_writer(&value, &mut reordered).map_err(|_| ErasureErrorV1::InvalidEncoding)?;
    assert_eq!(
        ErasureRejoinProofV1::from_canonical_cbor(&reordered),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    Ok(())
}

#[test]
fn disposition_codes_are_closed() {
    assert_eq!(ErasureRejoinDispositionV1::Tombstoned.code(), 0);
    assert_eq!(ErasureRejoinDispositionV1::Unrecoverable.code(), 1);
    assert_eq!(
        ErasureRejoinDispositionV1::from_code(2),
        Err(ErasureErrorV1::InvalidEncoding)
    );
}

#[test]
fn proof_construction_rejects_missing_or_invalid_inventory_evidence() -> Result<(), ErasureErrorV1>
{
    let receipt = receipt(ErasureLifecycleV1::Complete)?;
    let valid_entries = proof_entries();
    let mut too_many = vec![valid_entries[0]; ERASURE_MAX_INVENTORY_RESULTS + 1];
    too_many[ERASURE_MAX_INVENTORY_RESULTS] = valid_entries[1];
    assert_eq!(
        ErasureRejoinProofV1::new(proof_input(&receipt, too_many)),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    let mut missing_request = proof_input(&receipt, valid_entries.clone());
    missing_request.request = reference(0);
    assert_eq!(
        ErasureRejoinProofV1::new(missing_request),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    let mut duplicate = valid_entries.clone();
    duplicate.push(valid_entries[0]);
    assert_eq!(
        ErasureRejoinProofV1::new(proof_input(&receipt, duplicate)),
        Err(ErasureErrorV1::ScopeInvalid)
    );

    let mut invalid_category = valid_entries.clone();
    invalid_category[0].category = ErasureInventoryCategoryV1::Artifact;
    assert_eq!(
        ErasureRejoinProofV1::new(proof_input(&receipt, invalid_category)),
        Err(ErasureErrorV1::ScopeInvalid)
    );

    let mut missing_owner = valid_entries.clone();
    missing_owner[0].owner = reference(0);
    assert_eq!(
        ErasureRejoinProofV1::new(proof_input(&receipt, missing_owner)),
        Err(ErasureErrorV1::ScopeInvalid)
    );

    let mut missing_evidence = valid_entries.clone();
    missing_evidence[0].evidence = reference(0);
    assert_eq!(
        ErasureRejoinProofV1::new(proof_input(&receipt, missing_evidence)),
        Err(ErasureErrorV1::ScopeInvalid)
    );

    let mut wrong_target = valid_entries;
    wrong_target[0].target.replica_id = reference(92);
    assert_eq!(
        ErasureRejoinProofV1::new(proof_input(&receipt, wrong_target)),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    Ok(())
}

#[test]
fn malformed_proof_headers_and_fields_are_rejected() -> Result<(), ErasureErrorV1> {
    let receipt = receipt(ErasureLifecycleV1::Complete)?;
    let proof = proof_for(&receipt, proof_entries())?;

    let wrong_tag = mutate_wire(&proof, |fields| {
        fields[0] = ciborium::value::Value::Text("wrong".to_owned());
    })?;
    assert_eq!(
        ErasureRejoinProofV1::from_canonical_cbor(&wrong_tag),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    let wrong_version = mutate_wire(&proof, |fields| {
        fields[1] = ciborium::value::Value::Integer(99.into());
    })?;
    assert_eq!(
        ErasureRejoinProofV1::from_canonical_cbor(&wrong_version),
        Err(ErasureErrorV1::UnsupportedVersion)
    );
    let wrong_length = mutate_wire(&proof, |fields| {
        fields.pop();
    })?;
    assert_eq!(
        ErasureRejoinProofV1::from_canonical_cbor(&wrong_length),
        Err(ErasureErrorV1::InvalidEncoding)
    );

    for index in [2_usize, 3, 4, 5, 6, 8, 9] {
        let malformed = mutate_wire(&proof, |fields| {
            fields[index] = ciborium::value::Value::Null;
        })?;
        assert_eq!(
            ErasureRejoinProofV1::from_canonical_cbor(&malformed),
            Err(ErasureErrorV1::InvalidEncoding),
            "field {index}"
        );
    }
    let missing_entries = mutate_wire(&proof, |fields| {
        fields[7] = ciborium::value::Value::Null;
    })?;
    assert_eq!(
        ErasureRejoinProofV1::from_canonical_cbor(&missing_entries),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    Ok(())
}

#[test]
fn malformed_inventory_entries_are_rejected() -> Result<(), ErasureErrorV1> {
    let receipt = receipt(ErasureLifecycleV1::Complete)?;
    let proof = proof_for(&receipt, proof_entries())?;

    let wrong_tag = mutate_wire(&proof, |fields| {
        mutate_entry(fields, 0, ciborium::value::Value::Text("wrong".to_owned()));
    })?;
    assert_eq!(
        ErasureRejoinProofV1::from_canonical_cbor(&wrong_tag),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    let wrong_version = mutate_wire(&proof, |fields| {
        mutate_entry(fields, 1, ciborium::value::Value::Integer(99.into()));
    })?;
    assert_eq!(
        ErasureRejoinProofV1::from_canonical_cbor(&wrong_version),
        Err(ErasureErrorV1::UnsupportedVersion)
    );
    let malformed_category = mutate_wire(&proof, |fields| {
        mutate_entry(fields, 2, ciborium::value::Value::Null);
    })?;
    assert_eq!(
        ErasureRejoinProofV1::from_canonical_cbor(&malformed_category),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    let unsupported_category = mutate_wire(&proof, |fields| {
        mutate_entry(fields, 2, ciborium::value::Value::Integer(99.into()));
    })?;
    assert_eq!(
        ErasureRejoinProofV1::from_canonical_cbor(&unsupported_category),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    let forbidden_category = mutate_wire(&proof, |fields| {
        mutate_entry(fields, 2, ciborium::value::Value::Integer(0.into()));
    })?;
    assert_eq!(
        ErasureRejoinProofV1::from_canonical_cbor(&forbidden_category),
        Err(ErasureErrorV1::ScopeInvalid)
    );

    for (index, expected) in [
        (3_usize, ErasureErrorV1::InvalidEncoding),
        (4, ErasureErrorV1::InvalidEncoding),
        (5, ErasureErrorV1::InvalidEncoding),
        (6, ErasureErrorV1::InvalidEncoding),
    ] {
        let malformed = mutate_wire(&proof, |fields| {
            mutate_entry(fields, index, ciborium::value::Value::Null);
        })?;
        assert_eq!(
            ErasureRejoinProofV1::from_canonical_cbor(&malformed),
            Err(expected),
            "entry field {index}"
        );
    }
    Ok(())
}

#[test]
fn admission_rejects_proofs_without_receipt_scope() -> Result<(), ErasureErrorV1> {
    let receipt = receipt(ErasureLifecycleV1::Complete)?;
    let mut input = proof_input(&receipt, Vec::new());
    input.replica_set = reference(92);
    input.replica_id = reference(93);
    let proof = ErasureRejoinProofV1::new(input)?;
    let verifier = TestAttestationVerifier {
        attestation: reference(201),
    };
    assert_eq!(
        proof.admit(&receipt, &verifier),
        Err(ErasureErrorV1::BackupInventoryIncomplete)
    );
    Ok(())
}

#[test]
fn partial_receipt_without_backups_has_a_distinct_closed_failure() -> Result<(), ErasureErrorV1> {
    let receipt = partial_receipt_without_backups()?;
    let proof = proof_for(&receipt, proof_entries())?;
    let verifier = TestAttestationVerifier {
        attestation: reference(201),
    };
    assert_eq!(
        proof.admit(&receipt, &verifier),
        Err(ErasureErrorV1::BackupInventoryIncomplete)
    );
    Ok(())
}
