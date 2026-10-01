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
    WorldReplayHandleV1, MAX_ARTIFACT_GRAPH_REGISTRATION_BYTES_V1,
    MAX_ARTIFACT_GRAPH_REGISTRATIONS_V1, MAX_ARTIFACT_REGISTRATION_BATCH_BYTES_V1,
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

    fn classify_repro_manifest_label(
        &self,
        _owner_id: &OwnerIdV1,
        _label: &str,
    ) -> Result<ArtifactDataClassV1, ArtifactRegistrationOwnerVerificationErrorV1> {
        Ok(ArtifactDataClassV1::PublicRecord)
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

struct WrongLabelClassificationVerifier;

impl ArtifactRegistrationOwnerVerifierV1 for WrongLabelClassificationVerifier {
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

    fn classify_repro_manifest_label(
        &self,
        _owner_id: &OwnerIdV1,
        _label: &str,
    ) -> Result<ArtifactDataClassV1, ArtifactRegistrationOwnerVerificationErrorV1> {
        Ok(ArtifactDataClassV1::AggregateData)
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
    repro_manifest_closure_with_label(Some("public reproducibility record"))
}

fn repro_manifest_closure_with_label(
    label: Option<&str>,
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
        label: label.map(str::to_owned),
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
            label_data_class: label.map(|_| ArtifactDataClassV1::PublicRecord),
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
        inputs.clone(),
        &TestOnlyStructuralOwnerVerifier,
    )?;
    assert_eq!(prepared.owner_id(), &owner_id);
    assert_eq!(prepared.root_registration_address(), root);
    assert_eq!(prepared.records().len(), 4);
    assert!(prepared
        .records()
        .iter()
        .any(|record| record.registration_address() == root));
    let root_registration = prepared
        .records()
        .iter()
        .find(|record| record.registration_address() == root)
        .ok_or_else(|| std::io::Error::other("MRM1 registration was absent"))?
        .registration();
    assert_eq!(
        root_registration.fields().data_class,
        ArtifactDataClassV1::StructuralAuditMetadata
    );

    let (owner_id, root, inputs_without_label) = repro_manifest_closure_with_label(None)?;
    let no_label_batch = prepare_artifact_registration_batch_v1(
        owner_id,
        root,
        inputs_without_label,
        &TestOnlyStructuralOwnerVerifier,
    )?;
    let no_label_root = no_label_batch
        .records()
        .iter()
        .find(|record| record.registration_address() == root)
        .ok_or_else(|| std::io::Error::other("unlabeled MRM1 registration was absent"))?
        .registration();
    assert_eq!(
        no_label_root.fields().data_class,
        ArtifactDataClassV1::StructuralAuditMetadata
    );

    let (owner_id, root, incorrectly_classified_label) = repro_manifest_closure()?;
    assert_eq!(
        prepare_artifact_registration_batch_v1(
            owner_id,
            root,
            incorrectly_classified_label,
            &WrongLabelClassificationVerifier,
        ),
        Err(ArtifactRegistrationPreparationErrorV1::OwnerRejected)
    );

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

    let transcript_input = inputs
        .iter()
        .find(|input| input.artifact_bytes.get(2..6) == Some(&b"MAT1"[..]))
        .cloned()
        .ok_or_else(|| std::io::Error::other("MAT1 input was absent"))?;
    let mut duplicate_transcript = inputs;
    duplicate_transcript.push(transcript_input);
    assert_eq!(
        prepare_artifact_registration_batch_v1(
            owner_id,
            root,
            duplicate_transcript,
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

fn assert_preparation_error(
    owner_id: OwnerIdV1,
    root: Hash,
    inputs: Vec<ArtifactRegistrationInputV1>,
    owner_verifier: &dyn ArtifactRegistrationOwnerVerifierV1,
    expected: ArtifactRegistrationPreparationErrorV1,
) {
    assert_eq!(
        prepare_artifact_registration_batch_v1(owner_id, root, inputs, owner_verifier),
        Err(expected)
    );
}

#[test]
fn registration_preparation_rejects_empty_and_oversized_graphs(
) -> Result<(), Box<dyn std::error::Error>> {
    let (owner_id, root, inputs) = repro_manifest_closure()?;
    assert_preparation_error(
        owner_id,
        root,
        Vec::new(),
        &TestOnlyStructuralOwnerVerifier,
        ArtifactRegistrationPreparationErrorV1::BoundExceeded,
    );
    let repeated_input = inputs
        .first()
        .cloned()
        .ok_or_else(|| std::io::Error::other("MAA1 input was absent"))?;
    assert_preparation_error(
        owner_id,
        root,
        vec![repeated_input; MAX_ARTIFACT_GRAPH_REGISTRATIONS_V1 + 1],
        &TestOnlyStructuralOwnerVerifier,
        ArtifactRegistrationPreparationErrorV1::BoundExceeded,
    );
    Ok(())
}

#[test]
fn registration_preparation_rejects_malformed_and_mismatched_records(
) -> Result<(), Box<dyn std::error::Error>> {
    let (owner_id, root, inputs) = repro_manifest_closure()?;
    let mut malformed_registration = inputs.clone();
    malformed_registration[0].registration_cbor = b"not ARD1".to_vec();
    assert_preparation_error(
        owner_id,
        root,
        malformed_registration,
        &TestOnlyStructuralOwnerVerifier,
        ArtifactRegistrationPreparationErrorV1::InvalidRegistration,
    );
    let mut mismatched_artifact = inputs.clone();
    mismatched_artifact[0].artifact_bytes.push(0);
    assert_preparation_error(
        owner_id,
        root,
        mismatched_artifact,
        &TestOnlyStructuralOwnerVerifier,
        ArtifactRegistrationPreparationErrorV1::InvalidRegistration,
    );
    let mut mismatched_owner = inputs.clone();
    mismatched_owner[0].owner_id = OwnerIdV1::from_static("another-wave8-owner");
    assert_preparation_error(
        owner_id,
        root,
        mismatched_owner,
        &TestOnlyStructuralOwnerVerifier,
        ArtifactRegistrationPreparationErrorV1::InvalidRegistration,
    );

    let mut tampered_registration = inputs;
    let admission =
        ArtifactRegistrationV1::from_canonical_cbor(&tampered_registration[0].registration_cbor)?;
    let mut fields = (*admission.fields()).clone();
    fields.data_class = ArtifactDataClassV1::StructuralAuditMetadata;
    tampered_registration[0].registration_cbor = ArtifactRegistrationV1::new(fields)?
        .canonical_cbor()
        .to_vec();
    assert_preparation_error(
        owner_id,
        root,
        tampered_registration,
        &TestOnlyStructuralOwnerVerifier,
        ArtifactRegistrationPreparationErrorV1::ExtractionMismatch,
    );
    Ok(())
}

#[test]
fn registration_preparation_rejects_unsupported_native_formats(
) -> Result<(), Box<dyn std::error::Error>> {
    let (owner_id, root, mut unsupported_format) = repro_manifest_closure()?;
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
    assert_preparation_error(
        owner_id,
        root,
        unsupported_format,
        &TestOnlyStructuralOwnerVerifier,
        ArtifactRegistrationPreparationErrorV1::UnsupportedArtifact,
    );
    Ok(())
}

#[test]
fn registration_preparation_rejects_duplicate_and_extra_graph_rows(
) -> Result<(), Box<dyn std::error::Error>> {
    let (owner_id, root, inputs) = repro_manifest_closure()?;
    let repeated_input = inputs
        .first()
        .cloned()
        .ok_or_else(|| std::io::Error::other("MAA1 input was absent"))?;
    let mut duplicate_admission = inputs.clone();
    duplicate_admission.push(repeated_input);
    assert_preparation_error(
        owner_id,
        root,
        duplicate_admission,
        &TestOnlyStructuralOwnerVerifier,
        ArtifactRegistrationPreparationErrorV1::InvalidGraph,
    );

    let mut extra_admission = inputs;
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
    assert_preparation_error(
        owner_id,
        root,
        extra_admission,
        &TestOnlyStructuralOwnerVerifier,
        ArtifactRegistrationPreparationErrorV1::InvalidGraph,
    );
    Ok(())
}

#[test]
fn registration_preparation_rejects_incomplete_roots_and_owner_failure(
) -> Result<(), Box<dyn std::error::Error>> {
    let (owner_id, root, inputs) = repro_manifest_closure()?;
    let mut missing_recording = inputs.clone();
    missing_recording.retain(|input| input.artifact_bytes.get(2..6) != Some(&b"WCR1"[..]));
    assert_preparation_error(
        owner_id,
        root,
        missing_recording,
        &TestOnlyStructuralOwnerVerifier,
        ArtifactRegistrationPreparationErrorV1::InvalidGraph,
    );
    let mut missing_transcript = inputs.clone();
    missing_transcript.retain(|input| input.artifact_bytes.get(2..6) != Some(&b"MAT1"[..]));
    assert_preparation_error(
        owner_id,
        root,
        missing_transcript,
        &TestOnlyStructuralOwnerVerifier,
        ArtifactRegistrationPreparationErrorV1::InvalidGraph,
    );
    assert_preparation_error(
        owner_id,
        Hash::from_bytes([0x84; 32]),
        inputs.clone(),
        &TestOnlyStructuralOwnerVerifier,
        ArtifactRegistrationPreparationErrorV1::InvalidGraph,
    );
    assert_preparation_error(
        owner_id,
        root,
        inputs,
        &RejectingNativeDerivationVerifier,
        ArtifactRegistrationPreparationErrorV1::OwnerRejected,
    );
    Ok(())
}

fn fixture_input(
    inputs: &[ArtifactRegistrationInputV1],
    magic: &[u8],
) -> Result<ArtifactRegistrationInputV1, Box<dyn std::error::Error>> {
    inputs
        .iter()
        .find(|input| input.artifact_bytes.get(2..6) == Some(magic))
        .cloned()
        .ok_or_else(|| std::io::Error::other("native fixture input was absent").into())
}

struct NativeRegistrationFixture {
    owner_id: OwnerIdV1,
    admission: ArtifactRegistrationInputV1,
    transcript: ArtifactRegistrationInputV1,
    recording: ArtifactRegistrationInputV1,
    root: ArtifactRegistrationInputV1,
}

fn native_registration_fixture() -> Result<NativeRegistrationFixture, Box<dyn std::error::Error>> {
    let (owner_id, _, inputs) = repro_manifest_closure()?;
    Ok(NativeRegistrationFixture {
        owner_id,
        admission: fixture_input(&inputs, b"MAA1")?,
        transcript: fixture_input(&inputs, b"MAT1")?,
        recording: fixture_input(&inputs, b"WCR1")?,
        root: fixture_input(&inputs, b"MRM1")?,
    })
}

#[test]
fn adapter_registration_extraction_rejects_malformed_and_mismatched_inputs(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = native_registration_fixture()?;
    let admission_registration =
        ArtifactRegistrationV1::from_canonical_cbor(&fixture.admission.registration_cbor)?;
    let wrong_registration =
        ArtifactRegistrationV1::from_canonical_cbor(&fixture.root.registration_cbor)?;
    assert!(extract_adapter_admission_registration_v1(b"not MAA1").is_err());
    assert!(extract_adapter_transcript_registration_v1(
        b"not MAT1",
        &fixture.admission.artifact_bytes,
        &admission_registration,
    )
    .is_err());
    assert!(extract_adapter_transcript_registration_v1(
        &fixture.transcript.artifact_bytes,
        b"not MAA1",
        &admission_registration,
    )
    .is_err());
    assert!(extract_adapter_transcript_registration_v1(
        &fixture.transcript.artifact_bytes,
        &fixture.admission.artifact_bytes,
        &wrong_registration,
    )
    .is_err());

    let transcript = AdapterTranscriptV1::from_canonical_cbor(&fixture.transcript.artifact_bytes)?;
    let mut inconsistent_transcript = transcript.as_input().clone();
    inconsistent_transcript.adapter_admission_digest = Hash::from_bytes([0x85; 32]);
    let inconsistent_bytes = AdapterTranscriptV1::new(inconsistent_transcript)?.to_canonical_cbor();
    assert!(extract_adapter_transcript_registration_v1(
        &inconsistent_bytes,
        &fixture.admission.artifact_bytes,
        &admission_registration,
    )
    .is_err());
    Ok(())
}

#[test]
fn root_registration_extraction_rejects_each_invalid_child(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = native_registration_fixture()?;
    let recording_registration =
        ArtifactRegistrationV1::from_canonical_cbor(&fixture.recording.registration_cbor)?;
    let admission_registration =
        ArtifactRegistrationV1::from_canonical_cbor(&fixture.admission.registration_cbor)?;
    let transcript_registration =
        ArtifactRegistrationV1::from_canonical_cbor(&fixture.transcript.registration_cbor)?;
    let root_registration =
        ArtifactRegistrationV1::from_canonical_cbor(&fixture.root.registration_cbor)?;
    let input = ReproManifestRootRegistrationInputV1 {
        root_bytes: &fixture.root.artifact_bytes,
        recording_receipt_bytes: &fixture.recording.artifact_bytes,
        recording_registration: &recording_registration,
        transcript_bytes: &fixture.transcript.artifact_bytes,
        admission_bytes: &fixture.admission.artifact_bytes,
        admission_registration: &admission_registration,
        transcript_registration: &transcript_registration,
        owner_id: &fixture.owner_id,
        label_data_class: Some(ArtifactDataClassV1::PublicRecord),
    };
    assert!(
        extract_repro_manifest_root_registration_v1(ReproManifestRootRegistrationInputV1 {
            root_bytes: b"not MRM1",
            ..input
        })
        .is_err()
    );
    assert!(
        extract_repro_manifest_root_registration_v1(ReproManifestRootRegistrationInputV1 {
            recording_receipt_bytes: b"not WCR1",
            ..input
        })
        .is_err()
    );
    assert!(
        extract_repro_manifest_root_registration_v1(ReproManifestRootRegistrationInputV1 {
            transcript_bytes: b"not MAT1",
            ..input
        })
        .is_err()
    );
    assert!(
        extract_repro_manifest_root_registration_v1(ReproManifestRootRegistrationInputV1 {
            recording_registration: &admission_registration,
            ..input
        })
        .is_err()
    );
    assert!(
        extract_repro_manifest_root_registration_v1(ReproManifestRootRegistrationInputV1 {
            admission_bytes: b"not MAA1",
            ..input
        })
        .is_err()
    );
    assert!(
        extract_repro_manifest_root_registration_v1(ReproManifestRootRegistrationInputV1 {
            admission_registration: &root_registration,
            ..input
        })
        .is_err()
    );
    assert!(
        extract_repro_manifest_root_registration_v1(ReproManifestRootRegistrationInputV1 {
            transcript_registration: &admission_registration,
            ..input
        })
        .is_err()
    );
    Ok(())
}

#[test]
fn root_registration_extraction_rejects_invalid_label_and_binding(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = native_registration_fixture()?;
    let recording_registration =
        ArtifactRegistrationV1::from_canonical_cbor(&fixture.recording.registration_cbor)?;
    let admission_registration =
        ArtifactRegistrationV1::from_canonical_cbor(&fixture.admission.registration_cbor)?;
    let transcript_registration =
        ArtifactRegistrationV1::from_canonical_cbor(&fixture.transcript.registration_cbor)?;
    let input = ReproManifestRootRegistrationInputV1 {
        root_bytes: &fixture.root.artifact_bytes,
        recording_receipt_bytes: &fixture.recording.artifact_bytes,
        recording_registration: &recording_registration,
        transcript_bytes: &fixture.transcript.artifact_bytes,
        admission_bytes: &fixture.admission.artifact_bytes,
        admission_registration: &admission_registration,
        transcript_registration: &transcript_registration,
        owner_id: &fixture.owner_id,
        label_data_class: Some(ArtifactDataClassV1::PublicRecord),
    };
    let root = ReproManifestRootV1::from_canonical_cbor(&fixture.root.artifact_bytes)?;
    let mut unclassified_label = root.as_input().clone();
    unclassified_label.label = None;
    let unlabeled_bytes = ReproManifestRootV1::new(unclassified_label)?.to_canonical_cbor();
    assert!(
        extract_repro_manifest_root_registration_v1(ReproManifestRootRegistrationInputV1 {
            root_bytes: &unlabeled_bytes,
            label_data_class: Some(ArtifactDataClassV1::PublicRecord),
            ..input
        })
        .is_err()
    );

    let mut mismatched_binding = root.as_input().clone();
    mismatched_binding.adapter_transcript_digest = Hash::from_bytes([0x86; 32]);
    let mismatched_bytes = ReproManifestRootV1::new(mismatched_binding)?.to_canonical_cbor();
    assert!(
        extract_repro_manifest_root_registration_v1(ReproManifestRootRegistrationInputV1 {
            root_bytes: &mismatched_bytes,
            ..input
        })
        .is_err()
    );
    Ok(())
}

fn input_with_trailing_native_byte(
    mut input: ArtifactRegistrationInputV1,
) -> Result<ArtifactRegistrationInputV1, Box<dyn std::error::Error>> {
    input.artifact_bytes.push(0);
    let registration = ArtifactRegistrationV1::from_canonical_cbor(&input.registration_cbor)?;
    let mut fields = registration.fields().clone();
    fields.artifact_digest =
        ArtifactRegistrationV1::artifact_digest(fields.artifact_class, &input.artifact_bytes);
    input.registration_cbor = ArtifactRegistrationV1::new(fields)?
        .canonical_cbor()
        .to_vec();
    Ok(input)
}

#[test]
fn registration_preparation_rejects_noncanonical_supported_native_records(
) -> Result<(), Box<dyn std::error::Error>> {
    let (owner_id, root, inputs) = repro_manifest_closure()?;
    for magic in [&b"MAA1"[..], &b"MAT1"[..], &b"WCR1"[..], &b"MRM1"[..]] {
        let mut malformed = inputs.clone();
        let index = malformed
            .iter()
            .position(|input| input.artifact_bytes.get(2..6) == Some(magic))
            .ok_or_else(|| std::io::Error::other("native fixture input was absent"))?;
        malformed[index] = input_with_trailing_native_byte(malformed[index].clone())?;
        assert_preparation_error(
            owner_id,
            root,
            malformed,
            &TestOnlyStructuralOwnerVerifier,
            ArtifactRegistrationPreparationErrorV1::UnsupportedArtifact,
        );
    }
    Ok(())
}

struct CatalogFixture {
    rows: Vec<ArtifactRegistrationCatalogRowV1>,
}

fn catalog_fixture() -> Result<CatalogFixture, Box<dyn std::error::Error>> {
    let (owner_id, root, inputs) = repro_manifest_closure()?;
    let batch = prepare_artifact_registration_batch_v1(
        owner_id,
        root,
        inputs,
        &TestOnlyStructuralOwnerVerifier,
    )?;
    let rows = batch
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
    Ok(CatalogFixture { rows })
}

fn catalog_row_index(
    rows: &[ArtifactRegistrationCatalogRowV1],
    magic: &[u8],
) -> Result<usize, Box<dyn std::error::Error>> {
    rows.iter()
        .position(|row| row.artifact_bytes().get(2..6) == Some(magic))
        .ok_or_else(|| std::io::Error::other("catalog fixture row was absent").into())
}

fn catalog_row_with_registration(
    row: &ArtifactRegistrationCatalogRowV1,
    registration: &ArtifactRegistrationV1,
) -> Result<ArtifactRegistrationCatalogRowV1, Box<dyn std::error::Error>> {
    let fields = registration.fields();
    Ok(ArtifactRegistrationCatalogRowV1::from_persisted(
        *row.owner_id(),
        fields.artifact_class,
        fields.artifact_digest,
        registration.address(),
        row.artifact_bytes().to_vec(),
        registration.canonical_cbor(),
    )?)
}

fn registration_with_data_class(
    row: &ArtifactRegistrationCatalogRowV1,
    data_class: ArtifactDataClassV1,
) -> Result<ArtifactRegistrationV1, Box<dyn std::error::Error>> {
    let mut fields = row.registration().fields().clone();
    fields.data_class = data_class;
    Ok(ArtifactRegistrationV1::new(fields)?)
}

fn registration_with_child_identity(
    row: &ArtifactRegistrationCatalogRowV1,
    old_address: Hash,
    new_address: Hash,
    new_digest: Hash,
) -> Result<ArtifactRegistrationV1, Box<dyn std::error::Error>> {
    let mut fields = row.registration().fields().clone();
    let edge = fields
        .child_artifacts
        .iter_mut()
        .find(|edge| edge.registration_address == old_address)
        .ok_or_else(|| std::io::Error::other("catalog fixture child was absent"))?;
    edge.registration_address = new_address;
    edge.artifact_digest = new_digest;
    Ok(ArtifactRegistrationV1::new(fields)?)
}

fn unknown_repro_manifest_row(
    row: &ArtifactRegistrationCatalogRowV1,
) -> Result<ArtifactRegistrationCatalogRowV1, Box<dyn std::error::Error>> {
    let artifact_bytes = b"unknown ReproManifest artifact format".to_vec();
    let mut fields = row.registration().fields().clone();
    fields.artifact_digest = ArtifactRegistrationV1::artifact_digest(
        ErasureArtifactClassV1::ReproManifest,
        &artifact_bytes,
    );
    let registration = ArtifactRegistrationV1::new(fields)?;
    Ok(ArtifactRegistrationCatalogRowV1::from_persisted(
        *row.owner_id(),
        ErasureArtifactClassV1::ReproManifest,
        registration.fields().artifact_digest,
        registration.address(),
        artifact_bytes,
        registration.canonical_cbor(),
    )?)
}

#[test]
fn persisted_catalog_rejects_a_semantically_wrong_admission_registration(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = catalog_fixture()?;
    let admission_index = catalog_row_index(&fixture.rows, b"MAA1")?;
    let transcript_index = catalog_row_index(&fixture.rows, b"MAT1")?;
    let root_index = catalog_row_index(&fixture.rows, b"MRM1")?;
    let admission = fixture.rows[admission_index].clone();
    let transcript = fixture.rows[transcript_index].clone();
    let root = fixture.rows[root_index].clone();

    let changed_admission =
        registration_with_data_class(&admission, ArtifactDataClassV1::StructuralAuditMetadata)?;
    fixture.rows[admission_index] = catalog_row_with_registration(&admission, &changed_admission)?;
    let changed_transcript = registration_with_child_identity(
        &transcript,
        admission.registration_address(),
        changed_admission.address(),
        admission.artifact_digest(),
    )?;
    fixture.rows[transcript_index] =
        catalog_row_with_registration(&transcript, &changed_transcript)?;
    let changed_root = registration_with_child_identity(
        &root,
        transcript.registration_address(),
        changed_transcript.address(),
        transcript.artifact_digest(),
    )?;
    fixture.rows[root_index] = catalog_row_with_registration(&root, &changed_root)?;

    assert_eq!(
        validate_artifact_registration_catalog_graph_v1(changed_root.address(), &fixture.rows),
        Err(ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)
    );
    Ok(())
}

#[test]
fn persisted_catalog_rejects_a_semantically_wrong_transcript_registration(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = catalog_fixture()?;
    let transcript_index = catalog_row_index(&fixture.rows, b"MAT1")?;
    let root_index = catalog_row_index(&fixture.rows, b"MRM1")?;
    let transcript = fixture.rows[transcript_index].clone();
    let root = fixture.rows[root_index].clone();

    let changed_transcript =
        registration_with_data_class(&transcript, ArtifactDataClassV1::StructuralAuditMetadata)?;
    fixture.rows[transcript_index] =
        catalog_row_with_registration(&transcript, &changed_transcript)?;
    let changed_root = registration_with_child_identity(
        &root,
        transcript.registration_address(),
        changed_transcript.address(),
        transcript.artifact_digest(),
    )?;
    fixture.rows[root_index] = catalog_row_with_registration(&root, &changed_root)?;

    assert_eq!(
        validate_artifact_registration_catalog_graph_v1(changed_root.address(), &fixture.rows),
        Err(ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)
    );
    Ok(())
}

#[test]
fn persisted_catalog_rejects_an_unknown_repro_manifest_format(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = catalog_fixture()?;
    let admission_index = catalog_row_index(&fixture.rows, b"MAA1")?;
    let transcript_index = catalog_row_index(&fixture.rows, b"MAT1")?;
    let root_index = catalog_row_index(&fixture.rows, b"MRM1")?;
    let admission = fixture.rows[admission_index].clone();
    let transcript = fixture.rows[transcript_index].clone();
    let root = fixture.rows[root_index].clone();

    let unknown_admission = unknown_repro_manifest_row(&admission)?;
    let unknown_admission_address = unknown_admission.registration_address();
    let unknown_admission_digest = unknown_admission.artifact_digest();
    fixture.rows[admission_index] = unknown_admission;
    let changed_transcript = registration_with_child_identity(
        &transcript,
        admission.registration_address(),
        unknown_admission_address,
        unknown_admission_digest,
    )?;
    fixture.rows[transcript_index] =
        catalog_row_with_registration(&transcript, &changed_transcript)?;
    let changed_root = registration_with_child_identity(
        &root,
        transcript.registration_address(),
        changed_transcript.address(),
        transcript.artifact_digest(),
    )?;
    fixture.rows[root_index] = catalog_row_with_registration(&root, &changed_root)?;

    assert_eq!(
        validate_artifact_registration_catalog_graph_v1(changed_root.address(), &fixture.rows),
        Err(ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)
    );
    Ok(())
}


struct RejectingCommitVerifier;

impl ArtifactRegistrationOwnerVerifierV1 for RejectingCommitVerifier {
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

    fn classify_repro_manifest_label(
        &self,
        owner_id: &OwnerIdV1,
        label: &str,
    ) -> Result<ArtifactDataClassV1, ArtifactRegistrationOwnerVerificationErrorV1> {
        TestOnlyStructuralOwnerVerifier.classify_repro_manifest_label(owner_id, label)
    }

    fn verify_committed_artifact(
        &self,
        _: &OwnerIdV1,
        _: &[u8],
        _: &ArtifactRegistrationV1,
    ) -> Result<(), ArtifactRegistrationOwnerVerificationErrorV1> {
        Err(ArtifactRegistrationOwnerVerificationErrorV1::Rejected)
    }
}

struct RejectingSecondNativeDerivationVerifier {
    calls: std::cell::Cell<usize>,
}

impl ArtifactRegistrationOwnerVerifierV1 for RejectingSecondNativeDerivationVerifier {
    fn derive_native_registration(
        &self,
        owner_id: &OwnerIdV1,
        artifact_class: ErasureArtifactClassV1,
        artifact_bytes: &[u8],
    ) -> Result<ArtifactRegistrationV1, ArtifactRegistrationOwnerVerificationErrorV1> {
        let calls = self.calls.get() + 1;
        self.calls.set(calls);
        if calls == 2 {
            return Err(ArtifactRegistrationOwnerVerificationErrorV1::Rejected);
        }
        TestOnlyStructuralOwnerVerifier.derive_native_registration(
            owner_id,
            artifact_class,
            artifact_bytes,
        )
    }

    fn classify_repro_manifest_label(
        &self,
        owner_id: &OwnerIdV1,
        label: &str,
    ) -> Result<ArtifactDataClassV1, ArtifactRegistrationOwnerVerificationErrorV1> {
        TestOnlyStructuralOwnerVerifier.classify_repro_manifest_label(owner_id, label)
    }

    fn verify_committed_artifact(
        &self,
        owner_id: &OwnerIdV1,
        artifact_bytes: &[u8],
        registration: &ArtifactRegistrationV1,
    ) -> Result<(), ArtifactRegistrationOwnerVerificationErrorV1> {
        TestOnlyStructuralOwnerVerifier.verify_committed_artifact(
            owner_id,
            artifact_bytes,
            registration,
        )
    }
}

#[test]
fn persisted_catalog_accepts_the_complete_semantic_closure(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = catalog_fixture()?;
    let root_index = catalog_row_index(&fixture.rows, b"MRM1")?;
    let root = fixture.rows[root_index].registration_address();
    assert_eq!(
        validate_artifact_registration_catalog_graph_v1(root, &fixture.rows),
        Ok(())
    );
    Ok(())
}

#[test]
fn persisted_catalog_rejects_a_semantically_wrong_root_registration(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = catalog_fixture()?;
    let root_index = catalog_row_index(&fixture.rows, b"MRM1")?;
    let root = fixture.rows[root_index].clone();
    let changed =
        registration_with_data_class(&root, ArtifactDataClassV1::StructuralAuditMetadata)?;
    fixture.rows[root_index] = catalog_row_with_registration(&root, &changed)?;
    assert_eq!(
        validate_artifact_registration_catalog_graph_v1(changed.address(), &fixture.rows),
        Err(ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)
    );
    Ok(())
}

#[test]
fn registration_preparation_covers_registration_byte_and_native_owner_failures(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        MAX_ARTIFACT_GRAPH_REGISTRATION_BYTES_V1,
        64 * 1024 * 1024
    );
    let owner_id = OwnerIdV1::from_static("wave8-registration-byte-bound");
    assert_eq!(
        prepare_artifact_registration_batch_v1(
            owner_id,
            Hash::from_bytes([0x91; 32]),
            vec![ArtifactRegistrationInputV1 {
                owner_id,
                artifact_bytes: Vec::new(),
                registration_cbor: vec![0; MAX_ARTIFACT_GRAPH_REGISTRATION_BYTES_V1 + 1],
            }],
            &TestOnlyStructuralOwnerVerifier,
        ),
        Err(ArtifactRegistrationPreparationErrorV1::BoundExceeded)
    );

    let (owner_id, root, inputs) = repro_manifest_closure()?;
    assert_preparation_error(
        owner_id,
        root,
        inputs.clone(),
        &RejectingCommitVerifier,
        ArtifactRegistrationPreparationErrorV1::OwnerRejected,
    );
    assert_preparation_error(
        owner_id,
        root,
        inputs,
        &RejectingSecondNativeDerivationVerifier {
            calls: std::cell::Cell::new(0),
        },
        ArtifactRegistrationPreparationErrorV1::OwnerRejected,
    );
    Ok(())
}

#[test]
fn registration_preparation_rejects_missing_and_duplicate_native_dependencies(
) -> Result<(), Box<dyn std::error::Error>> {
    let (owner_id, root, inputs) = repro_manifest_closure()?;
    let mut missing_admission = inputs.clone();
    missing_admission.retain(|input| input.artifact_bytes.get(2..6) != Some(&b"MAA1"[..]));
    assert_preparation_error(
        owner_id,
        root,
        missing_admission,
        &TestOnlyStructuralOwnerVerifier,
        ArtifactRegistrationPreparationErrorV1::InvalidGraph,
    );

    let mut duplicate_transcript = inputs;
    let repeated_transcript = fixture_input(&duplicate_transcript, b"MAT1")?;
    duplicate_transcript.push(repeated_transcript);
    assert_preparation_error(
        owner_id,
        root,
        duplicate_transcript,
        &TestOnlyStructuralOwnerVerifier,
        ArtifactRegistrationPreparationErrorV1::InvalidGraph,
    );
    Ok(())
}
