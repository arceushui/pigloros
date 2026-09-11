//! Public-boundary fixtures for the local ADR-060 rejoin adapter.

use pos_core::{
    ErasureAcknowledgementOutcomeV1, ErasureAcknowledgementV1, ErasureArtifactClassV1,
    ErasureArtifactTransitionV1, ErasureCasOutcomeV1, ErasureErrorV1, ErasureInventoryCategoryV1,
    ErasureInventoryResultV1, ErasureKeyRoleV1, ErasureLifecycleV1, ErasureReceiptInputV1,
    ErasureReceiptInventoriesV1, ErasureReceiptV1, ErasureReferenceV1,
    ErasureRejoinAttestationVerifierV1, ErasureRejoinDispositionV1, ErasureRejoinInventoryV1,
    ErasureRejoinProofInputV1, ErasureRejoinProofV1, ErasureReplayClaimV1, ErasureRequiredTargetV1,
};
use pos_store::{memory::MemoryStore, ErasureRejoinPersistencePortV1};

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

struct RejoinFixture {
    receipt: ErasureReceiptV1,
    proof: ErasureRejoinProofV1,
}

fn fixture() -> Result<RejoinFixture, ErasureErrorV1> {
    let replica_target = target(10);
    let backup_target = target(20);
    let replica_owner = reference(100);
    let backup_owner = reference(101);
    let receipt = ErasureReceiptV1::new(ErasureReceiptInputV1 {
        request: reference(1),
        terminal_state: reference(2),
        coordinator: reference(3),
        lifecycle: ErasureLifecycleV1::Complete,
        freeze_position: 5,
        acknowledgements: vec![
            ErasureAcknowledgementV1 {
                obligation: reference(130),
                target: replica_target,
                owner: replica_owner,
                evidence: reference(140),
                outcome: ErasureAcknowledgementOutcomeV1::Acknowledged,
            },
            ErasureAcknowledgementV1 {
                obligation: reference(131),
                target: backup_target,
                owner: backup_owner,
                evidence: reference(141),
                outcome: ErasureAcknowledgementOutcomeV1::Acknowledged,
            },
        ],
        frozen_targets: vec![replica_target, backup_target],
        pending_owners: Vec::new(),
        failed_owners: Vec::new(),
        inventories: ErasureReceiptInventoriesV1 {
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
        },
        replay_claim: ErasureReplayClaimV1::StructuralOnly,
        policy: reference(4),
        trust: reference(5),
        provenance: reference(6),
        issue_position: 7,
        signature: reference(8),
        receipt_digest: reference(0),
    })?;
    let proof = ErasureRejoinProofV1::new(ErasureRejoinProofInputV1 {
        request: receipt.request(),
        terminal_receipt: receipt.receipt_digest(),
        replica_set: reference(90),
        replica_id: reference(91),
        inventory_generation: reference(200),
        entries: vec![
            ErasureRejoinInventoryV1 {
                category: ErasureInventoryCategoryV1::Backup,
                target: backup_target,
                owner: backup_owner,
                disposition: ErasureRejoinDispositionV1::Unrecoverable,
                evidence: reference(221),
            },
            ErasureRejoinInventoryV1 {
                category: ErasureInventoryCategoryV1::Replica,
                target: replica_target,
                owner: replica_owner,
                disposition: ErasureRejoinDispositionV1::Tombstoned,
                evidence: reference(220),
            },
        ],
        attestation: reference(201),
    })?;
    Ok(RejoinFixture { receipt, proof })
}

struct FixtureVerifier;

impl ErasureRejoinAttestationVerifierV1 for FixtureVerifier {
    fn verify(&self, proof: &ErasureRejoinProofV1) -> Result<(), ErasureErrorV1> {
        (proof.attestation() == reference(201))
            .then_some(())
            .ok_or(ErasureErrorV1::Unauthorized)
    }
}

fn exercise_store<S: ErasureRejoinPersistencePortV1>(store: &mut S) -> Result<(), ErasureErrorV1> {
    let RejoinFixture { receipt, proof } = fixture()?;
    assert_eq!(
        store.store_rejoin_proof(&proof)?,
        ErasureCasOutcomeV1::Applied
    );
    assert_eq!(
        store.store_rejoin_proof(&proof)?,
        ErasureCasOutcomeV1::ExactRetry
    );
    let loaded = store
        .load_rejoin_proof(proof.reference())?
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    assert_eq!(loaded, proof);
    let admission = store.admit_rejoin(proof.reference(), &receipt, &FixtureVerifier)?;
    assert_eq!(admission.proof(), proof.reference());
    Ok(())
}

#[test]
fn memory_adapter_persists_idempotently_and_admits_complete_fixture() -> Result<(), ErasureErrorV1>
{
    exercise_store(&mut MemoryStore::new())
}

#[test]
fn missing_proof_is_not_admitted() -> Result<(), ErasureErrorV1> {
    let RejoinFixture { receipt, proof } = fixture()?;
    let store = MemoryStore::new();
    assert_eq!(
        store.admit_rejoin(proof.reference(), &receipt, &FixtureVerifier),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_adapter_survives_restart_and_admits_complete_fixture() -> Result<(), ErasureErrorV1> {
    use pos_store::sqlite::SqliteStore;
    let file = tempfile::NamedTempFile::new().map_err(|_| ErasureErrorV1::ReceiptCommitFailed)?;
    let path = file
        .path()
        .to_str()
        .ok_or(ErasureErrorV1::ReceiptCommitFailed)?;
    {
        let mut store = SqliteStore::open(path).map_err(|_| ErasureErrorV1::ReceiptCommitFailed)?;
        exercise_store(&mut store)?;
    }
    let mut reopened = SqliteStore::open(path).map_err(|_| ErasureErrorV1::ReceiptCommitFailed)?;
    let RejoinFixture { receipt, proof } = fixture()?;
    assert_eq!(
        reopened.store_rejoin_proof(&proof)?,
        ErasureCasOutcomeV1::ExactRetry
    );
    assert!(reopened
        .admit_rejoin(proof.reference(), &receipt, &FixtureVerifier)
        .is_ok());
    Ok(())
}
