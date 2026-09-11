//! Public-boundary coverage for the ADR-060 no-resurrection rejoin seam.

use pos_core::{
    ErasureAcknowledgementOutcomeV1, ErasureAcknowledgementV1, ErasureArtifactClassV1,
    ErasureArtifactTransitionV1, ErasureErrorV1, ErasureInventoryCategoryV1,
    ErasureInventoryResultV1, ErasureKeyRoleV1, ErasureLifecycleV1, ErasureReceiptInputV1,
    ErasureReceiptInventoriesV1, ErasureReceiptV1, ErasureReferenceV1,
    ErasureRejoinAttestationVerifierV1, ErasureRejoinDispositionV1, ErasureRejoinInventoryV1,
    ErasureRejoinProofInputV1, ErasureRejoinProofV1, ErasureReplayClaimV1, ErasureRequiredTargetV1,
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

fn proof_for(
    receipt: &ErasureReceiptV1,
    entries: Vec<ErasureRejoinInventoryV1>,
) -> Result<ErasureRejoinProofV1, ErasureErrorV1> {
    ErasureRejoinProofV1::new(ErasureRejoinProofInputV1 {
        request: receipt.request(),
        terminal_receipt: receipt.receipt_digest(),
        replica_set: reference(90),
        replica_id: reference(91),
        inventory_generation: reference(200),
        entries,
        attestation: reference(201),
    })
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
