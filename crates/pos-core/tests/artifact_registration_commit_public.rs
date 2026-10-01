use pos_core::{
    extract_adapter_admission_registration_v1, extract_adapter_transcript_registration_v1,
    extract_repro_manifest_root_registration_v1, prepare_artifact_registration_batch_v1,
    validate_artifact_registration_catalog_graph_v1, AdapterAdmissionInputV1, AdapterAdmissionV1,
    AdapterTranscriptInputV1, AdapterTranscriptV1, ArtifactDataClassV1,
    ArtifactRegistrationCatalogRowV1, ArtifactRegistrationFieldsV1, ArtifactRegistrationInputV1,
    ArtifactRegistrationOwnerVerificationErrorV1, ArtifactRegistrationOwnerVerifierV1,
    ArtifactRegistrationPersistenceErrorV1, ArtifactRegistrationPreparationErrorV1,
    ArtifactRegistrationV1, ArtifactTransitionRuleV1, ErasureArtifactClassV1, Hash, OwnerIdV1,
    ReproManifestRootInputV1, ReproManifestRootRegistrationInputV1, ReproManifestRootV1,
    WorldRecordingReceiptInputV1, WorldRecordingReceiptV1, WorldReplayHandleInputV1,
    WorldReplayHandleV1, MAX_ARTIFACT_GRAPH_REGISTRATIONS_V1,
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

struct RejectingNativeDerivationVerifier;

impl ArtifactRegistrationOwnerVerifierV1 for RejectingNativeDerivationVerifier {
    fn derive_native_registration(
        &self,
        _owner_id: &OwnerIdV1,
        _artifact_class: ErasureArtifactClassV1,
        _artifact_bytes: &[u8],
    ) -> Result<ArtifactRegistrationV1, ArtifactRegistrationOwnerVerificationErrorV1> {
        Err(ArtifactRegistrationOwnerVerificationErrorV1::Rejected)
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
        candidate
            .artifact_bytes
            .get(2..6)
            .is_none_or(|magic| magic != b"MAA1")
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

#[test]
fn persisted_registration_rows_reject_each_mismatched_identity_column(
) -> Result<(), Box<dyn std::error::Error>> {
    let (owner_id, root, inputs) = repro_manifest_closure()?;
    let batch = prepare_artifact_registration_batch_v1(
        owner_id,
        root,
        inputs,
        &TestOnlyStructuralOwnerVerifier,
    )?;
    let record = batch
        .records()
        .first()
        .ok_or_else(|| std::io::Error::other("prepared registration was empty"))?;
    let valid = ArtifactRegistrationCatalogRowV1::from_persisted(
        owner_id,
        record.artifact_class(),
        record.artifact_digest(),
        record.registration_address(),
        record.artifact_bytes().to_vec(),
        record.registration().canonical_cbor(),
    )?;
    assert_eq!(valid.artifact_bytes(), record.artifact_bytes());

    assert_eq!(
        ArtifactRegistrationCatalogRowV1::from_persisted(
            owner_id,
            record.artifact_class(),
            record.artifact_digest(),
            record.registration_address(),
            record.artifact_bytes().to_vec(),
            b"not canonical ARD1",
        ),
        Err(ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)
    );
    assert_eq!(
        ArtifactRegistrationCatalogRowV1::from_persisted(
            owner_id,
            record.artifact_class(),
            record.artifact_digest(),
            Hash::from_bytes([0x81; 32]),
            record.artifact_bytes().to_vec(),
            record.registration().canonical_cbor(),
        ),
        Err(ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)
    );
    assert_eq!(
        ArtifactRegistrationCatalogRowV1::from_persisted(
            owner_id,
            ErasureArtifactClassV1::TimelineReplay,
            record.artifact_digest(),
            record.registration_address(),
            record.artifact_bytes().to_vec(),
            record.registration().canonical_cbor(),
        ),
        Err(ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)
    );
    assert_eq!(
        ArtifactRegistrationCatalogRowV1::from_persisted(
            owner_id,
            record.artifact_class(),
            Hash::from_bytes([0x82; 32]),
            record.registration_address(),
            record.artifact_bytes().to_vec(),
            record.registration().canonical_cbor(),
        ),
        Err(ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)
    );
    assert_eq!(
        ArtifactRegistrationCatalogRowV1::from_persisted(
            OwnerIdV1::from_static("another-wave8-owner"),
            record.artifact_class(),
            record.artifact_digest(),
            record.registration_address(),
            record.artifact_bytes().to_vec(),
            record.registration().canonical_cbor(),
        ),
        Err(ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)
    );
    let mut changed_bytes = record.artifact_bytes().to_vec();
    changed_bytes.push(0);
    assert_eq!(
        ArtifactRegistrationCatalogRowV1::from_persisted(
            owner_id,
            record.artifact_class(),
            record.artifact_digest(),
            record.registration_address(),
            changed_bytes,
            record.registration().canonical_cbor(),
        ),
        Err(ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)
    );
    Ok(())
}

#[test]
fn complete_native_catalog_closure_revalidates_through_the_public_port(
) -> Result<(), Box<dyn std::error::Error>> {
    let (owner_id, root, inputs) = repro_manifest_closure()?;
    let batch = prepare_artifact_registration_batch_v1(
        owner_id,
        root,
        inputs,
        &TestOnlyStructuralOwnerVerifier,
    )?;
    let rows: Vec<_> = batch
        .records()
        .iter()
        .map(|record| {
            ArtifactRegistrationCatalogRowV1::from_persisted(
                *record.owner_id(),
                record.artifact_class(),
                record.artifact_digest(),
                record.registration_address(),
                record.artifact_bytes().to_vec(),
                record.registration().canonical_cbor(),
            )
        })
        .collect::<Result<_, _>>()?;
    assert_eq!(rows.len(), 4);
    validate_artifact_registration_catalog_graph_v1(root, &rows)?;
    assert_eq!(
        validate_artifact_registration_catalog_graph_v1(root, &rows[..rows.len() - 1]),
        Err(ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)
    );
    Ok(())
}

#[test]
fn registration_preparation_rejects_invalid_bytes_extraction_and_closure_shapes(
) -> Result<(), Box<dyn std::error::Error>> {
    let (owner_id, root, inputs) = repro_manifest_closure()?;
    assert_eq!(
        prepare_artifact_registration_batch_v1(
            owner_id,
            root,
            Vec::new(),
            &TestOnlyStructuralOwnerVerifier,
        ),
        Err(ArtifactRegistrationPreparationErrorV1::BoundExceeded)
    );
    let repeated_input = inputs
        .first()
        .cloned()
        .ok_or_else(|| std::io::Error::other("MAA1 input was absent"))?;
    assert_eq!(
        prepare_artifact_registration_batch_v1(
            owner_id,
            root,
            vec![repeated_input.clone(); MAX_ARTIFACT_GRAPH_REGISTRATIONS_V1 + 1],
            &TestOnlyStructuralOwnerVerifier,
        ),
        Err(ArtifactRegistrationPreparationErrorV1::BoundExceeded)
    );

    let mut malformed_registration = inputs.clone();
    malformed_registration[0].registration_cbor = b"not ARD1".to_vec();
    assert_eq!(
        prepare_artifact_registration_batch_v1(
            owner_id,
            root,
            malformed_registration,
            &TestOnlyStructuralOwnerVerifier,
        ),
        Err(ArtifactRegistrationPreparationErrorV1::InvalidRegistration)
    );
    let mut mismatched_artifact = inputs.clone();
    mismatched_artifact[0].artifact_bytes.push(0);
    assert_eq!(
        prepare_artifact_registration_batch_v1(
            owner_id,
            root,
            mismatched_artifact,
            &TestOnlyStructuralOwnerVerifier,
        ),
        Err(ArtifactRegistrationPreparationErrorV1::InvalidRegistration)
    );
    let mut mismatched_owner = inputs.clone();
    mismatched_owner[0].owner_id = OwnerIdV1::from_static("another-wave8-owner");
    assert_eq!(
        prepare_artifact_registration_batch_v1(
            owner_id,
            root,
            mismatched_owner,
            &TestOnlyStructuralOwnerVerifier,
        ),
        Err(ArtifactRegistrationPreparationErrorV1::InvalidRegistration)
    );

    let mut tampered_registration = inputs.clone();
    let admission =
        ArtifactRegistrationV1::from_canonical_cbor(&tampered_registration[0].registration_cbor)?;
    let mut fields = (*admission.fields()).clone();
    fields.data_class = ArtifactDataClassV1::StructuralAuditMetadata;
    tampered_registration[0].registration_cbor = ArtifactRegistrationV1::new(fields)?
        .canonical_cbor()
        .to_vec();
    assert_eq!(
        prepare_artifact_registration_batch_v1(
            owner_id,
            root,
            tampered_registration,
            &TestOnlyStructuralOwnerVerifier,
        ),
        Err(ArtifactRegistrationPreparationErrorV1::ExtractionMismatch)
    );

    let mut unsupported_format = inputs.clone();
    let unknown_bytes = b"unsupported ReproManifest native format".to_vec();
    let unknown_registration = ArtifactRegistrationV1::new(ArtifactRegistrationFieldsV1 {
        artifact_class: ErasureArtifactClassV1::ReproManifest,
        artifact_digest: ArtifactRegistrationV1::artifact_digest(
            ErasureArtifactClassV1::ReproManifest,
            &unknown_bytes,
        ),
        owner_reference: ArtifactRegistrationV1::owner_reference(&owner_id),
        data_class: ArtifactDataClassV1::PublicRecord,
        optionality: pos_core::ArtifactOptionalityV1::Required,
        transition_rule: ArtifactTransitionRuleV1::PreserveExact,
        required_key_roles: Vec::new(),
        key_dependencies: Vec::new(),
        child_artifacts: Vec::new(),
    })?;
    unsupported_format.push(ArtifactRegistrationInputV1 {
        owner_id,
        artifact_bytes: unknown_bytes,
        registration_cbor: unknown_registration.canonical_cbor().to_vec(),
    });
    assert_eq!(
        prepare_artifact_registration_batch_v1(
            owner_id,
            root,
            unsupported_format,
            &TestOnlyStructuralOwnerVerifier,
        ),
        Err(ArtifactRegistrationPreparationErrorV1::UnsupportedArtifact)
    );

    let mut duplicate_admission = inputs.clone();
    duplicate_admission.push(repeated_input);
    assert_eq!(
        prepare_artifact_registration_batch_v1(
            owner_id,
            root,
            duplicate_admission,
            &TestOnlyStructuralOwnerVerifier,
        ),
        Err(ArtifactRegistrationPreparationErrorV1::InvalidGraph)
    );

    let mut extra_admission = inputs.clone();
    let other_admission = AdapterAdmissionV1::new(AdapterAdmissionInputV1 {
        owner_reference: ArtifactRegistrationV1::owner_reference(&owner_id),
        configuration_generation: 4,
        scope_digest: Hash::from_bytes([0x83; 32]),
        entries: Vec::new(),
    })?;
    let other_bytes = other_admission.to_canonical_cbor();
    let other_registration = extract_adapter_admission_registration_v1(&other_bytes)?;
    extra_admission.push(ArtifactRegistrationInputV1 {
        owner_id,
        artifact_bytes: other_bytes,
        registration_cbor: other_registration.canonical_cbor().to_vec(),
    });
    assert_eq!(
        prepare_artifact_registration_batch_v1(
            owner_id,
            root,
            extra_admission,
            &TestOnlyStructuralOwnerVerifier,
        ),
        Err(ArtifactRegistrationPreparationErrorV1::InvalidGraph)
    );

    let mut missing_recording = inputs.clone();
    missing_recording.retain(|input| input.artifact_bytes.get(2..6) != Some(&b"WCR1"[..]));
    assert_eq!(
        prepare_artifact_registration_batch_v1(
            owner_id,
            root,
            missing_recording,
            &TestOnlyStructuralOwnerVerifier,
        ),
        Err(ArtifactRegistrationPreparationErrorV1::InvalidGraph)
    );
    let mut missing_transcript = inputs.clone();
    missing_transcript.retain(|input| input.artifact_bytes.get(2..6) != Some(&b"MAT1"[..]));
    assert_eq!(
        prepare_artifact_registration_batch_v1(
            owner_id,
            root,
            missing_transcript,
            &TestOnlyStructuralOwnerVerifier,
        ),
        Err(ArtifactRegistrationPreparationErrorV1::InvalidGraph)
    );
    assert_eq!(
        prepare_artifact_registration_batch_v1(
            owner_id,
            Hash::from_bytes([0x84; 32]),
            inputs.clone(),
            &TestOnlyStructuralOwnerVerifier,
        ),
        Err(ArtifactRegistrationPreparationErrorV1::InvalidGraph)
    );
    assert_eq!(
        prepare_artifact_registration_batch_v1(
            owner_id,
            root,
            inputs,
            &RejectingNativeDerivationVerifier,
        ),
        Err(ArtifactRegistrationPreparationErrorV1::OwnerRejected)
    );
    Ok(())
}
