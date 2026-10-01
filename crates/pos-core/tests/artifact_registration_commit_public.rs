use pos_core::{
    extract_adapter_admission_registration_v1, extract_adapter_transcript_registration_v1,
    extract_repro_manifest_root_registration_v1, prepare_artifact_registration_batch_v1,
    AdapterAdmissionInputV1, AdapterAdmissionV1, AdapterTranscriptInputV1, AdapterTranscriptV1,
    ArtifactDataClassV1, ArtifactRegistrationFieldsV1, ArtifactRegistrationInputV1,
    ArtifactRegistrationOwnerVerificationErrorV1, ArtifactRegistrationOwnerVerifierV1,
    ArtifactRegistrationPreparationErrorV1, ArtifactRegistrationV1, ArtifactTransitionRuleV1,
    ErasureArtifactClassV1, Hash, OwnerIdV1, ReproManifestRootInputV1,
    ReproManifestRootRegistrationInputV1, ReproManifestRootV1, WorldRecordingReceiptInputV1,
    WorldRecordingReceiptV1, WorldReplayHandleInputV1, WorldReplayHandleV1,
    MAX_ARTIFACT_REGISTRATION_BATCH_BYTES_V1,
};
use ulid::Ulid;

// This fixture exercises structural extraction only. It does not verify an
// actual WorldCut, PluginRegistry roster, owner key, admission row, or recorder.
struct TestOnlyStructuralOwnerVerifier;

impl ArtifactRegistrationOwnerVerifierV1 for TestOnlyStructuralOwnerVerifier {
    fn derive_native_registration(
        &self,
        owner_id: &OwnerIdV1,
        artifact_class: ErasureArtifactClassV1,
        artifact_bytes: &[u8],
    ) -> Result<ArtifactRegistrationV1, ArtifactRegistrationOwnerVerificationErrorV1> {
        if artifact_class != ErasureArtifactClassV1::TimelineReplay
            || WorldRecordingReceiptV1::from_canonical_cbor(artifact_bytes).is_err()
        {
            return Err(ArtifactRegistrationOwnerVerificationErrorV1::Rejected);
        }
        ArtifactRegistrationV1::new(ArtifactRegistrationFieldsV1 {
            artifact_class,
            artifact_digest: ArtifactRegistrationV1::artifact_digest(
                artifact_class,
                artifact_bytes,
            ),
            owner_reference: ArtifactRegistrationV1::owner_reference(owner_id),
            data_class: ArtifactDataClassV1::StructuralAuditMetadata,
            optionality: pos_core::ArtifactOptionalityV1::Required,
            transition_rule: ArtifactTransitionRuleV1::PreserveExact,
            required_key_roles: Vec::new(),
            key_dependencies: Vec::new(),
            child_artifacts: Vec::new(),
        })
        .map_err(|_| ArtifactRegistrationOwnerVerificationErrorV1::Rejected)
    }

    fn verify_committed_artifact(
        &self,
        _owner_id: &OwnerIdV1,
        _artifact_bytes: &[u8],
        _registration: &ArtifactRegistrationV1,
    ) -> Result<(), ArtifactRegistrationOwnerVerificationErrorV1> {
        Ok(())
    }
}

struct RejectingTestOwnerVerifier;

impl ArtifactRegistrationOwnerVerifierV1 for RejectingTestOwnerVerifier {
    fn derive_native_registration(
        &self,
        owner_id: &OwnerIdV1,
        artifact_class: ErasureArtifactClassV1,
        artifact_bytes: &[u8],
    ) -> Result<ArtifactRegistrationV1, ArtifactRegistrationOwnerVerificationErrorV1> {
        TestOnlyStructuralOwnerVerifier.derive_native_registration(
            owner_id,
            artifact_class,
            artifact_bytes,
        )
    }

    fn verify_committed_artifact(
        &self,
        _owner_id: &OwnerIdV1,
        _artifact_bytes: &[u8],
        _registration: &ArtifactRegistrationV1,
    ) -> Result<(), ArtifactRegistrationOwnerVerificationErrorV1> {
        Err(ArtifactRegistrationOwnerVerificationErrorV1::Rejected)
    }
}

fn repro_manifest_closure(
) -> Result<(OwnerIdV1, Hash, Vec<ArtifactRegistrationInputV1>), Box<dyn std::error::Error>> {
    let owner_id = OwnerIdV1::from_static("wave8-local-owner");
    let owner_reference = ArtifactRegistrationV1::owner_reference(&owner_id);
    let operation_id = Hash::from_bytes([0x41; 32]);
    let commit_receipt_digest = Hash::from_bytes([0x42; 32]);
    let recording_receipt = WorldRecordingReceiptV1::new(WorldRecordingReceiptInputV1 {
        binding_hash: Hash::from_bytes([0x43; 32]),
        operation_id,
        actual_commit_receipt_digest: commit_receipt_digest,
        installed_inventory_generation: Hash::from_bytes([0x44; 32]),
    })?;
    let world_handle = WorldReplayHandleV1::new(WorldReplayHandleInputV1 {
        owner_reference,
        timeline_id: pos_core::TimelineId::from_ulid(Ulid::from(1_u128)),
        cut_id: 1,
        commit_receipt_digest,
        recording_receipt_digest: recording_receipt.digest(),
        logical_head: 0,
        stitched_head_hash: Hash::from_bytes([0x45; 32]),
    })?;
    let admission = AdapterAdmissionV1::new(AdapterAdmissionInputV1 {
        owner_reference,
        configuration_generation: 1,
        scope_digest: Hash::from_bytes([0x46; 32]),
        entries: Vec::new(),
    })?;
    let transcript = AdapterTranscriptV1::new(AdapterTranscriptInputV1 {
        owner_reference,
        world_handle,
        run_operation_id: operation_id,
        adapter_admission_digest: admission.digest(),
        calls: Vec::new(),
    })?;
    let root = ReproManifestRootV1::new(ReproManifestRootInputV1 {
        owner_reference,
        world_handle,
        run_operation_id: operation_id,
        plugin_roster_digest: Hash::from_bytes([0x47; 32]),
        adapter_transcript_digest: transcript.digest(),
        created_at_micros: 1,
        label: Some("public reproducibility record".to_owned()),
    })?;

    let admission_bytes = admission.to_canonical_cbor();
    let transcript_bytes = transcript.to_canonical_cbor();
    let recording_bytes = recording_receipt.to_canonical_cbor();
    let root_bytes = root.to_canonical_cbor();
    let admission_registration = extract_adapter_admission_registration_v1(&admission_bytes)?;
    let transcript_registration = extract_adapter_transcript_registration_v1(
        &transcript_bytes,
        &admission_bytes,
        &admission_registration,
    )?;
    let recording_registration = TestOnlyStructuralOwnerVerifier.derive_native_registration(
        &owner_id,
        ErasureArtifactClassV1::TimelineReplay,
        &recording_bytes,
    )?;
    let root_registration =
        extract_repro_manifest_root_registration_v1(ReproManifestRootRegistrationInputV1 {
            root_bytes: &root_bytes,
            recording_receipt_bytes: &recording_bytes,
            recording_registration: &recording_registration,
            transcript_bytes: &transcript_bytes,
            admission_bytes: &admission_bytes,
            admission_registration: &admission_registration,
            transcript_registration: &transcript_registration,
            owner_id: &owner_id,
        })?;
    let root_address = root_registration.address();
    let inputs = [
        (owner_id, admission_bytes, admission_registration),
        (owner_id, transcript_bytes, transcript_registration),
        (owner_id, recording_bytes, recording_registration),
        (owner_id, root_bytes, root_registration),
    ]
    .into_iter()
    .map(
        |(owner_id, artifact_bytes, registration)| ArtifactRegistrationInputV1 {
            owner_id,
            artifact_bytes,
            registration_cbor: registration.canonical_cbor().to_vec(),
        },
    )
    .collect();
    Ok((owner_id, root_address, inputs))
}

#[test]
fn structural_fixture_prepares_only_a_complete_exact_repro_manifest_closure(
) -> Result<(), Box<dyn std::error::Error>> {
    let (owner_id, root, inputs) = repro_manifest_closure()?;
    let prepared = prepare_artifact_registration_batch_v1(
        owner_id,
        root,
        inputs,
        &TestOnlyStructuralOwnerVerifier,
    )?;
    assert_eq!(prepared.owner_id(), &owner_id);
    assert_eq!(prepared.root_registration_address(), root);
    assert_eq!(prepared.records().len(), 4);
    assert!(prepared
        .records()
        .iter()
        .any(|record| record.registration_address() == root));

    let (owner_id, root, mut missing_admission) = repro_manifest_closure()?;
    missing_admission.retain(|candidate| {
        !candidate
            .artifact_bytes
            .get(2..6)
            .is_some_and(|magic| magic == b"MAA1")
    });
    assert_eq!(
        prepare_artifact_registration_batch_v1(
            owner_id,
            root,
            missing_admission,
            &TestOnlyStructuralOwnerVerifier,
        ),
        Err(ArtifactRegistrationPreparationErrorV1::InvalidGraph)
    );
    Ok(())
}

#[test]
fn rejecting_test_owner_does_not_produce_a_batch() -> Result<(), Box<dyn std::error::Error>> {
    let (owner_id, root, inputs) = repro_manifest_closure()?;
    assert_eq!(
        prepare_artifact_registration_batch_v1(owner_id, root, inputs, &RejectingTestOwnerVerifier,),
        Err(ArtifactRegistrationPreparationErrorV1::OwnerRejected)
    );
    Ok(())
}

#[test]
fn exact_artifact_byte_bound_is_256_mib_and_checked_before_parsing() {
    assert_eq!(MAX_ARTIFACT_REGISTRATION_BATCH_BYTES_V1, 256 * 1024 * 1024);
    let owner_id = OwnerIdV1::from_static("wave8-local-owner");
    let root = Hash::from_bytes([0x49; 32]);
    assert_eq!(
        prepare_artifact_registration_batch_v1(
            owner_id,
            root,
            vec![ArtifactRegistrationInputV1 {
                owner_id,
                artifact_bytes: vec![0; MAX_ARTIFACT_REGISTRATION_BATCH_BYTES_V1 + 1],
                registration_cbor: Vec::new(),
            }],
            &TestOnlyStructuralOwnerVerifier,
        ),
        Err(ArtifactRegistrationPreparationErrorV1::BoundExceeded)
    );
}

#[test]
fn unsupported_timeline_replay_class_stays_unavailable() -> Result<(), Box<dyn std::error::Error>> {
    let owner_id = OwnerIdV1::from_static("wave8-local-owner");
    let bytes = b"LCC1 structural bytes are not an accepted local cut".to_vec();
    let class = ErasureArtifactClassV1::TimelineReplay;
    let registration = ArtifactRegistrationV1::new(ArtifactRegistrationFieldsV1 {
        artifact_class: class,
        artifact_digest: ArtifactRegistrationV1::artifact_digest(class, &bytes),
        owner_reference: ArtifactRegistrationV1::owner_reference(&owner_id),
        data_class: ArtifactDataClassV1::StructuralAuditMetadata,
        optionality: pos_core::ArtifactOptionalityV1::Required,
        transition_rule: ArtifactTransitionRuleV1::PreserveExact,
        required_key_roles: Vec::new(),
        key_dependencies: Vec::new(),
        child_artifacts: Vec::new(),
    })?;
    assert_eq!(
        prepare_artifact_registration_batch_v1(
            owner_id,
            registration.address(),
            vec![ArtifactRegistrationInputV1 {
                owner_id,
                artifact_bytes: bytes,
                registration_cbor: registration.canonical_cbor().to_vec(),
            }],
            &TestOnlyStructuralOwnerVerifier,
        ),
        Err(ArtifactRegistrationPreparationErrorV1::OwnerRejected)
    );
    Ok(())
}
