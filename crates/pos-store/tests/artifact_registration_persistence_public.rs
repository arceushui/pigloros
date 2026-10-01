use std::fmt::Write as _;

use pos_core::{
    adapter_configuration_digest_v1, close_adapter_recording_v1,
    extract_adapter_admission_registration_v1, extract_adapter_transcript_registration_v1,
    extract_repro_manifest_root_registration_v1, prepare_artifact_registration_batch_v1,
    public_adapter_schema_digest_v1, validate_artifact_registration_catalog_graph_v1,
    validate_closed_adapter_recording_v1, AdapterAdmissionEntryV1, AdapterAdmissionInputV1,
    AdapterAdmissionV1, AdapterCallReservationOutcomeV1, AdapterCallReservationV1,
    AdapterDataClassV1, AdapterEffectModeV1, AdapterInvocationInputV1, AdapterInvocationV1,
    AdapterRecordingSessionV1, AdapterRecordingStoreErrorV1, AdapterRecordingStoreV1,
    AdapterTranscriptCallV1, AdapterTranscriptInputV1, AdapterTranscriptV1, ArtifactDataClassV1,
    ArtifactRegistrationCatalogRowV1, ArtifactRegistrationFieldsV1, ArtifactRegistrationInputV1,
    ArtifactRegistrationOwnerVerificationErrorV1, ArtifactRegistrationOwnerVerifierV1,
    ArtifactRegistrationV1, ArtifactTransitionRuleV1, ErasureArtifactClassV1, Hash, OwnerIdV1,
    PreparedArtifactRegistrationBatchV1, ReproManifestRootInputV1,
    ReproManifestRootRegistrationInputV1, ReproManifestRootV1, WorldRecordingReceiptInputV1,
    WorldRecordingReceiptV1, WorldReplayHandleInputV1, WorldReplayHandleV1,
    MAX_ADAPTER_CALL_BYTES_V1,
};
use pos_store::{
    memory::MemoryStore, open_store, ArtifactRegistrationCommitOutcomeV1,
    ArtifactRegistrationPersistencePortV1, StoreConfig,
};
use ulid::Ulid;

// This fixture isolates the store's transactional port. Its synthetic WCR1
// registration is not Wave 8 owner-verification evidence.
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

fn prepared_repro_manifest() -> Result<
    (
        OwnerIdV1,
        Hash,
        pos_core::PreparedArtifactRegistrationBatchV1,
    ),
    Box<dyn std::error::Error>,
> {
    let owner_id = OwnerIdV1::from_static("wave8-store-owner");
    let owner_reference = ArtifactRegistrationV1::owner_reference(&owner_id);
    let operation_id = Hash::from_bytes([0x51; 32]);
    let commit_receipt_digest = Hash::from_bytes([0x52; 32]);
    let recording = WorldRecordingReceiptV1::new(WorldRecordingReceiptInputV1 {
        binding_hash: Hash::from_bytes([0x53; 32]),
        operation_id,
        actual_commit_receipt_digest: commit_receipt_digest,
        installed_inventory_generation: Hash::from_bytes([0x54; 32]),
    })?;
    let world_handle = WorldReplayHandleV1::new(WorldReplayHandleInputV1 {
        owner_reference,
        timeline_id: pos_core::TimelineId::from_ulid(Ulid::from(2_u128)),
        cut_id: 2,
        commit_receipt_digest,
        recording_receipt_digest: recording.digest(),
        logical_head: 0,
        stitched_head_hash: Hash::from_bytes([0x55; 32]),
    })?;
    let admission = AdapterAdmissionV1::new(AdapterAdmissionInputV1 {
        owner_reference,
        configuration_generation: 1,
        scope_digest: Hash::from_bytes([0x56; 32]),
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
        plugin_roster_digest: admission.as_input().scope_digest,
        adapter_transcript_digest: transcript.digest(),
        created_at_micros: 2,
        label: None,
    })?;
    let admission_bytes = admission.to_canonical_cbor();
    let transcript_bytes = transcript.to_canonical_cbor();
    let recording_bytes = recording.to_canonical_cbor();
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
            label_data_class: None,
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
    let batch = prepare_artifact_registration_batch_v1(
        owner_id,
        root_address,
        inputs,
        &TestOnlyStructuralOwnerVerifier,
    )?;
    Ok((owner_id, root_address, batch))
}

fn close_repro_manifest_recording<R: AdapterRecordingStoreV1 + ?Sized>(
    store: &mut R,
    batch: &PreparedArtifactRegistrationBatchV1,
) -> Result<(), AdapterRecordingStoreErrorV1> {
    let root = batch
        .records()
        .iter()
        .find(|record| record.registration_address() == batch.root_registration_address())
        .and_then(|record| ReproManifestRootV1::from_canonical_cbor(record.artifact_bytes()).ok())
        .ok_or(AdapterRecordingStoreErrorV1::CorruptState)?;
    let admission = batch
        .records()
        .iter()
        .find(|record| record.artifact_bytes().get(2..6) == Some(b"MAA1"))
        .and_then(|record| AdapterAdmissionV1::from_canonical_cbor(record.artifact_bytes()).ok())
        .ok_or(AdapterRecordingStoreErrorV1::CorruptState)?;
    let session = AdapterRecordingSessionV1::new(
        root.as_input().owner_reference,
        root.as_input().world_handle,
        root.as_input().run_operation_id,
        admission,
    )?;
    store.open_adapter_recording_session(session)?;
    store
        .close_adapter_recording_session(
            root.as_input().owner_reference,
            root.as_input().run_operation_id,
        )
        .map(|_| ())
}

fn alternate_root_with_same_operation(
    mut inputs: Vec<ArtifactRegistrationInputV1>,
) -> Result<(Hash, Vec<ArtifactRegistrationInputV1>), Box<dyn std::error::Error>> {
    let root_index = inputs
        .iter()
        .position(|input| input.artifact_bytes.get(2..6) == Some(b"MRM1"))
        .ok_or_else(|| std::io::Error::other("MRM1 root input was not present"))?;
    let root = ReproManifestRootV1::from_canonical_cbor(&inputs[root_index].artifact_bytes)?;
    let mut root_input = (*root.as_input()).clone();
    root_input.label = Some("second immutable root for the same operation".to_owned());
    let alternate = ReproManifestRootV1::new(root_input)?;
    let alternate_bytes = alternate.to_canonical_cbor();
    let stored_registration =
        ArtifactRegistrationV1::from_canonical_cbor(&inputs[root_index].registration_cbor)?;
    let mut fields = (*stored_registration.fields()).clone();
    fields.artifact_digest = ArtifactRegistrationV1::artifact_digest(
        ErasureArtifactClassV1::ReproManifest,
        &alternate_bytes,
    );
    let registration = ArtifactRegistrationV1::new(fields)?;
    let address = registration.address();
    inputs[root_index].artifact_bytes = alternate_bytes;
    inputs[root_index].registration_cbor = registration.canonical_cbor().to_vec();
    Ok((address, inputs))
}

fn adapter_recording_fixture(
    run_operation_id: Hash,
) -> Result<(AdapterRecordingSessionV1, AdapterCallReservationV1), Box<dyn std::error::Error>> {
    let owner_reference = Hash::from_bytes([0x71; 32]);
    let plugin_id = pos_core::PluginId::from_ulid(Ulid::from_bytes([0x71; 16]));
    let configuration = b"adapter-store-test-config".to_vec();
    let schema_digest = public_adapter_schema_digest_v1();
    let admission = AdapterAdmissionV1::new(AdapterAdmissionInputV1 {
        owner_reference,
        configuration_generation: 3,
        scope_digest: Hash::from_bytes([0x72; 32]),
        entries: vec![AdapterAdmissionEntryV1 {
            plugin_id,
            adapter_id: "weather.client".to_owned(),
            provider_id: "fixture.provider".to_owned(),
            operation_id: "read-current".to_owned(),
            protocol_version: 1,
            request_schema_digest: schema_digest,
            response_schema_digest: schema_digest,
            configuration_digest: adapter_configuration_digest_v1(&configuration),
            exact_configuration_bytes: configuration,
            input_data_class: AdapterDataClassV1::PublicRecord,
            output_data_class: AdapterDataClassV1::PublicRecord,
            effect_mode: AdapterEffectModeV1::ReadOnly,
        }],
    })?;
    let world_handle = WorldReplayHandleV1::new(WorldReplayHandleInputV1 {
        owner_reference,
        timeline_id: pos_core::TimelineId::new(),
        cut_id: 3,
        commit_receipt_digest: Hash::from_bytes([0x73; 32]),
        recording_receipt_digest: Hash::from_bytes([0x74; 32]),
        logical_head: 0,
        stitched_head_hash: Hash::from_bytes([0x75; 32]),
    })?;
    let session =
        AdapterRecordingSessionV1::new(owner_reference, world_handle, run_operation_id, admission)?;
    let invocation = AdapterInvocationV1::new(AdapterInvocationInputV1 {
        adapter_id: "weather.client".to_owned(),
        provider_id: "fixture.provider".to_owned(),
        operation_id: "read-current".to_owned(),
        protocol_version: 1,
        request_schema_digest: schema_digest,
        response_schema_digest: schema_digest,
        configuration_digest: adapter_configuration_digest_v1(b"adapter-store-test-config"),
        global_call_index: 0,
        exact_request_payload: b"exact request".to_vec(),
    })?;
    let reservation =
        AdapterCallReservationV1::new(plugin_id, 0, invocation, Hash::from_bytes([0x76; 32]), 123)?;
    Ok((session, reservation))
}

fn exercise_event_store_adapter_recording<S: pos_core::store::EventStore>(
    store: &mut S,
    run_operation_id: Hash,
) -> Result<(), Box<dyn std::error::Error>> {
    let (session, reservation) = adapter_recording_fixture(run_operation_id)?;
    assert_invalid_adapter_recording_arguments(&session, &reservation, run_operation_id)?;
    assert_inactive_adapter_recording_store(store, &session, &reservation, run_operation_id)?;
    open_adapter_recording_session(store, &session, run_operation_id)?;
    assert_invalid_adapter_call_reservations(store, &session, &reservation, run_operation_id)?;
    complete_adapter_recording_call(store, &session, &reservation, run_operation_id)?;
    close_and_abort_adapter_recording(store, &session, &reservation, run_operation_id)
}

fn assert_invalid_adapter_recording_arguments(
    session: &AdapterRecordingSessionV1,
    reservation: &AdapterCallReservationV1,
    run_operation_id: Hash,
) -> Result<(), Box<dyn std::error::Error>> {
    let owner_reference = session.owner_reference();
    assert_eq!(
        AdapterCallReservationV1::new(
            reservation.plugin_id(),
            reservation.per_plugin_call_index(),
            reservation.invocation().clone(),
            Hash::zero(),
            reservation.reserved_at_micros(),
        ),
        Err(AdapterRecordingStoreErrorV1::InvalidCall)
    );
    let invalid_order_call = AdapterTranscriptCallV1 {
        plugin_id: reservation.plugin_id(),
        per_plugin_call_index: 1,
        input: reservation.invocation().clone(),
        exact_output_bytes: b"response".to_vec(),
        recorded_wall_time_micros: reservation.reserved_at_micros(),
    };
    assert_eq!(
        close_adapter_recording_v1(session, vec![invalid_order_call]),
        Err(AdapterRecordingStoreErrorV1::CorruptState)
    );
    let mismatched_contract_call = AdapterTranscriptCallV1 {
        plugin_id: pos_core::PluginId::from_ulid(Ulid::from_bytes([0x72; 16])),
        per_plugin_call_index: 0,
        input: reservation.invocation().clone(),
        exact_output_bytes: b"response".to_vec(),
        recorded_wall_time_micros: reservation.reserved_at_micros(),
    };
    let mismatched_transcript = AdapterTranscriptV1::new(AdapterTranscriptInputV1 {
        owner_reference,
        world_handle: session.world_handle(),
        run_operation_id,
        adapter_admission_digest: session.admission().digest(),
        calls: vec![mismatched_contract_call.clone()],
    })?;
    let mismatched_transcript_bytes = mismatched_transcript.to_canonical_cbor();
    assert_eq!(
        validate_closed_adapter_recording_v1(session, &mismatched_transcript_bytes),
        Err(AdapterRecordingStoreErrorV1::CorruptState)
    );
    assert_eq!(
        close_adapter_recording_v1(session, vec![mismatched_contract_call]),
        Err(AdapterRecordingStoreErrorV1::CorruptState)
    );
    Ok(())
}

fn assert_inactive_adapter_recording_store<S: pos_core::store::EventStore>(
    store: &mut S,
    session: &AdapterRecordingSessionV1,
    reservation: &AdapterCallReservationV1,
    run_operation_id: Hash,
) -> Result<(), Box<dyn std::error::Error>> {
    let owner_reference = session.owner_reference();
    assert_eq!(
        store.adapter_recording_close_session(owner_reference, run_operation_id),
        Err(AdapterRecordingStoreErrorV1::InvalidState)
    );
    assert_eq!(
        store.adapter_recording_reserve_call(
            owner_reference,
            run_operation_id,
            reservation.clone()
        ),
        Err(AdapterRecordingStoreErrorV1::InvalidState)
    );
    assert_eq!(
        store.adapter_recording_complete_call(owner_reference, run_operation_id, 0, Vec::new()),
        Err(AdapterRecordingStoreErrorV1::InvalidState)
    );
    assert_eq!(
        store.adapter_recording_abort_session(owner_reference, run_operation_id),
        Err(AdapterRecordingStoreErrorV1::InvalidState)
    );
    assert_eq!(
        store.adapter_recording_read_closed_session(owner_reference, run_operation_id)?,
        None
    );
    Ok(())
}

fn open_adapter_recording_session<S: pos_core::store::EventStore>(
    store: &mut S,
    session: &AdapterRecordingSessionV1,
    run_operation_id: Hash,
) -> Result<(), Box<dyn std::error::Error>> {
    let owner_reference = session.owner_reference();
    store.adapter_recording_open_session(session.clone())?;
    store.adapter_recording_open_session(session.clone())?;
    let other_handle = WorldReplayHandleV1::new(WorldReplayHandleInputV1 {
        owner_reference,
        timeline_id: pos_core::TimelineId::new(),
        cut_id: 4,
        commit_receipt_digest: Hash::from_bytes([0x77; 32]),
        recording_receipt_digest: Hash::from_bytes([0x78; 32]),
        logical_head: 0,
        stitched_head_hash: Hash::from_bytes([0x79; 32]),
    })?;
    let conflicting_session = AdapterRecordingSessionV1::new(
        owner_reference,
        other_handle,
        run_operation_id,
        session.admission().clone(),
    )?;
    assert_eq!(
        store.adapter_recording_open_session(conflicting_session),
        Err(AdapterRecordingStoreErrorV1::Conflict)
    );
    assert_eq!(
        store.adapter_recording_read_closed_session(owner_reference, run_operation_id)?,
        None
    );
    Ok(())
}

fn assert_invalid_adapter_call_reservations<S: pos_core::store::EventStore>(
    store: &mut S,
    session: &AdapterRecordingSessionV1,
    reservation: &AdapterCallReservationV1,
    run_operation_id: Hash,
) -> Result<(), Box<dyn std::error::Error>> {
    let owner_reference = session.owner_reference();
    let reserved = store.adapter_recording_reserve_call(
        owner_reference,
        run_operation_id,
        reservation.clone(),
    )?;
    assert_eq!(
        reserved,
        AdapterCallReservationOutcomeV1::Reserved {
            reserved_at_micros: 123
        }
    );
    assert_eq!(
        store.adapter_recording_reserve_call(
            owner_reference,
            run_operation_id,
            reservation.clone(),
        )?,
        reserved
    );
    let changed_retry = AdapterCallReservationV1::new(
        reservation.plugin_id(),
        reservation.per_plugin_call_index(),
        reservation.invocation().clone(),
        Hash::from_bytes([0x7a; 32]),
        999,
    )?;
    assert_eq!(
        store.adapter_recording_reserve_call(owner_reference, run_operation_id, changed_retry),
        Err(AdapterRecordingStoreErrorV1::InvalidCall)
    );
    let wrong_plugin_ordinal = AdapterCallReservationV1::new(
        reservation.plugin_id(),
        1,
        reservation.invocation().clone(),
        Hash::from_bytes([0x7b; 32]),
        124,
    )?;
    assert_eq!(
        store.adapter_recording_reserve_call(
            owner_reference,
            run_operation_id,
            wrong_plugin_ordinal,
        ),
        Err(AdapterRecordingStoreErrorV1::InvalidCall)
    );
    let out_of_order_invocation = AdapterInvocationV1::new(AdapterInvocationInputV1 {
        global_call_index: 2,
        ..reservation.invocation().as_input().clone()
    })?;
    let out_of_order = AdapterCallReservationV1::new(
        reservation.plugin_id(),
        2,
        out_of_order_invocation,
        Hash::from_bytes([0x7c; 32]),
        124,
    )?;
    assert_eq!(
        store.adapter_recording_reserve_call(owner_reference, run_operation_id, out_of_order),
        Err(AdapterRecordingStoreErrorV1::InvalidCall)
    );
    assert_eq!(
        store.adapter_recording_complete_call(owner_reference, run_operation_id, 1, Vec::new()),
        Err(AdapterRecordingStoreErrorV1::InvalidCall)
    );
    assert_eq!(
        store.adapter_recording_complete_call(
            owner_reference,
            run_operation_id,
            0,
            vec![0; MAX_ADAPTER_CALL_BYTES_V1 + 1],
        ),
        Err(AdapterRecordingStoreErrorV1::InvalidCall)
    );
    assert_eq!(
        store.adapter_recording_close_session(owner_reference, run_operation_id),
        Err(AdapterRecordingStoreErrorV1::InvalidState)
    );
    Ok(())
}

fn complete_adapter_recording_call<S: pos_core::store::EventStore>(
    store: &mut S,
    session: &AdapterRecordingSessionV1,
    reservation: &AdapterCallReservationV1,
    run_operation_id: Hash,
) -> Result<(), Box<dyn std::error::Error>> {
    let owner_reference = session.owner_reference();
    let output = b"exact response".to_vec();
    store.adapter_recording_complete_call(owner_reference, run_operation_id, 0, output.clone())?;
    store.adapter_recording_complete_call(owner_reference, run_operation_id, 0, output.clone())?;
    assert_eq!(
        store.adapter_recording_complete_call(
            owner_reference,
            run_operation_id,
            0,
            b"conflicting response".to_vec(),
        ),
        Err(AdapterRecordingStoreErrorV1::Conflict)
    );
    let completed_retry = AdapterCallReservationV1::new(
        reservation.plugin_id(),
        reservation.per_plugin_call_index(),
        reservation.invocation().clone(),
        reservation.idempotency_key(),
        999,
    )?;
    assert_eq!(
        store.adapter_recording_reserve_call(owner_reference, run_operation_id, completed_retry)?,
        AdapterCallReservationOutcomeV1::Completed {
            output_bytes: output,
            reserved_at_micros: 123,
        }
    );
    Ok(())
}

fn close_and_abort_adapter_recording<S: pos_core::store::EventStore>(
    store: &mut S,
    session: &AdapterRecordingSessionV1,
    reservation: &AdapterCallReservationV1,
    run_operation_id: Hash,
) -> Result<(), Box<dyn std::error::Error>> {
    let owner_reference = session.owner_reference();
    let transcript = store.adapter_recording_close_session(owner_reference, run_operation_id)?;
    assert_eq!(
        store.adapter_recording_close_session(owner_reference, run_operation_id)?,
        transcript
    );
    assert_eq!(
        store.adapter_recording_read_closed_session(owner_reference, run_operation_id)?,
        Some(transcript)
    );
    assert_eq!(
        store.adapter_recording_open_session(session.clone()),
        Err(AdapterRecordingStoreErrorV1::InvalidState)
    );
    assert_eq!(
        store.adapter_recording_reserve_call(
            owner_reference,
            run_operation_id,
            reservation.clone(),
        ),
        Err(AdapterRecordingStoreErrorV1::InvalidState)
    );
    assert_eq!(
        store.adapter_recording_complete_call(owner_reference, run_operation_id, 0, Vec::new()),
        Err(AdapterRecordingStoreErrorV1::InvalidState)
    );
    assert_eq!(
        store.adapter_recording_abort_session(owner_reference, run_operation_id),
        Err(AdapterRecordingStoreErrorV1::InvalidState)
    );

    let aborted_id = Hash::from_bytes([0x7d; 32]);
    let (aborted_session, _) = adapter_recording_fixture(aborted_id)?;
    store.adapter_recording_open_session(aborted_session)?;
    store.adapter_recording_abort_session(owner_reference, aborted_id)?;
    assert_eq!(
        store.adapter_recording_close_session(owner_reference, aborted_id),
        Err(AdapterRecordingStoreErrorV1::InvalidState)
    );
    assert_eq!(
        store.adapter_recording_abort_session(owner_reference, aborted_id),
        Err(AdapterRecordingStoreErrorV1::InvalidState)
    );
    assert_eq!(
        store.adapter_recording_read_closed_session(owner_reference, aborted_id)?,
        None
    );
    Ok(())
}

#[test]
fn memory_catalog_commits_complete_exact_rows_and_retries_idempotently(
) -> Result<(), Box<dyn std::error::Error>> {
    let (owner_id, root_address, batch) = prepared_repro_manifest()?;
    let mut store = MemoryStore::new();
    close_repro_manifest_recording(&mut store, &batch)?;
    assert_eq!(
        pos_core::store::EventStore::commit_artifact_registration_batch(&mut store, batch)?,
        ArtifactRegistrationCommitOutcomeV1::Applied
    );
    let root =
        pos_core::store::EventStore::read_artifact_registration(&store, &owner_id, root_address)?
            .ok_or_else(|| std::io::Error::other("committed root was not visible"))?;
    assert_eq!(root.registration_address(), root_address);
    assert!(root
        .artifact_bytes()
        .starts_with(&[0x89, 0x44, b'M', b'R', b'M', b'1']));

    for edge in &root.registration().fields().child_artifacts {
        let child = store
            .read_artifact_registration(&owner_id, edge.registration_address)?
            .ok_or_else(|| std::io::Error::other("root child was not visible"))?;
        for grandchild in &child.registration().fields().child_artifacts {
            assert!(store
                .read_artifact_registration(&owner_id, grandchild.registration_address)?
                .is_some());
        }
    }

    let (owner_id, root_address, retry) = prepared_repro_manifest()?;
    assert_eq!(
        store.commit_artifact_registration_batch(retry)?,
        ArtifactRegistrationCommitOutcomeV1::ExactRetry
    );
    assert!(store
        .read_artifact_registration(&OwnerIdV1::from_static("another-owner"), root_address)?
        .is_none());
    assert_eq!(owner_id, *root.owner_id());
    Ok(())
}

#[test]
fn standard_store_factory_exposes_the_artifact_registration_port(
) -> Result<(), Box<dyn std::error::Error>> {
    let (owner_id, root_address, batch) = prepared_repro_manifest()?;
    let mut store = open_store(StoreConfig::Memory)?;
    close_repro_manifest_recording(&mut *store, &batch)?;
    assert_eq!(
        store.commit_artifact_registration_batch(batch)?,
        ArtifactRegistrationCommitOutcomeV1::Applied
    );
    let root = store
        .read_artifact_registration(&owner_id, root_address)?
        .ok_or_else(|| std::io::Error::other("committed root was not visible"))?;
    assert_eq!(root.registration_address(), root_address);
    Ok(())
}

#[test]
fn memory_catalog_rejects_a_root_without_a_closed_same_store_recording(
) -> Result<(), Box<dyn std::error::Error>> {
    let (owner_id, root_address, batch) = prepared_repro_manifest()?;
    let mut store = MemoryStore::new();
    assert_eq!(
        store.commit_artifact_registration_batch(batch),
        Err(pos_core::ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)
    );
    assert!(store
        .read_artifact_registration(&owner_id, root_address)?
        .is_none());
    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_catalog_rejects_a_root_without_a_closed_same_store_recording(
) -> Result<(), Box<dyn std::error::Error>> {
    let database = tempfile::NamedTempFile::new()?;
    let path = database
        .path()
        .to_str()
        .ok_or_else(|| std::io::Error::other("temporary path is not UTF-8"))?;
    let (owner_id, root_address, batch) = prepared_repro_manifest()?;
    let mut store = pos_store::sqlite::SqliteStore::open(path)?;
    assert_eq!(
        store.commit_artifact_registration_batch(batch),
        Err(pos_core::ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)
    );
    assert!(store
        .read_artifact_registration(&owner_id, root_address)?
        .is_none());
    Ok(())
}

#[test]
fn memory_catalog_rejects_a_second_root_for_the_same_operation_atomically(
) -> Result<(), Box<dyn std::error::Error>> {
    let (owner_id, root_address, batch) = prepared_repro_manifest()?;
    let alternate_source: Vec<_> = batch
        .records()
        .iter()
        .map(|record| ArtifactRegistrationInputV1 {
            owner_id: *record.owner_id(),
            artifact_bytes: record.artifact_bytes().to_vec(),
            registration_cbor: record.registration().canonical_cbor().to_vec(),
        })
        .collect();
    let mut store = MemoryStore::new();
    close_repro_manifest_recording(&mut store, &batch)?;
    assert_eq!(
        store.commit_artifact_registration_batch(batch)?,
        ArtifactRegistrationCommitOutcomeV1::Applied
    );

    let (alternate_root, alternate_inputs) = alternate_root_with_same_operation(alternate_source)?;
    let alternate = prepare_artifact_registration_batch_v1(
        owner_id,
        alternate_root,
        alternate_inputs,
        &TestOnlyStructuralOwnerVerifier,
    )?;
    assert_eq!(
        store.commit_artifact_registration_batch(alternate),
        Err(pos_core::ArtifactRegistrationPersistenceErrorV1::Conflict)
    );
    assert!(store
        .read_artifact_registration(&owner_id, root_address)?
        .is_some());
    assert!(store
        .read_artifact_registration(&owner_id, alternate_root)?
        .is_none());
    Ok(())
}

#[test]
fn persisted_graph_rejects_structurally_valid_but_wrong_mrm1_registration_fields(
) -> Result<(), Box<dyn std::error::Error>> {
    let (owner_id, root_address, batch) = prepared_repro_manifest()?;
    let mut rows: Vec<_> = batch
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
    let root_index = rows
        .iter()
        .position(|row| row.registration_address() == root_address)
        .ok_or_else(|| std::io::Error::other("MRM1 root row was not present"))?;
    let root = rows[root_index].clone();
    let mut fields = (*root.registration().fields()).clone();
    fields.data_class = ArtifactDataClassV1::PublicRecord;
    let tampered_registration = ArtifactRegistrationV1::new(fields)?;
    let tampered_address = tampered_registration.address();
    rows[root_index] = ArtifactRegistrationCatalogRowV1::from_persisted(
        owner_id,
        ErasureArtifactClassV1::ReproManifest,
        root.artifact_digest(),
        tampered_address,
        root.artifact_bytes().to_vec(),
        tampered_registration.canonical_cbor(),
    )?;

    assert_eq!(
        validate_artifact_registration_catalog_graph_v1(tampered_address, &rows),
        Err(pos_core::ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)
    );
    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_catalog_is_visible_across_handles_and_after_reopen(
) -> Result<(), Box<dyn std::error::Error>> {
    let database = tempfile::NamedTempFile::new()?;
    let path = database
        .path()
        .to_str()
        .ok_or_else(|| std::io::Error::other("temporary path is not UTF-8"))?;
    let mut writer = pos_store::sqlite::SqliteStore::open(path)?;
    let reader = pos_store::sqlite::SqliteStore::open(path)?;
    let (owner_id, root_address, batch) = prepared_repro_manifest()?;
    close_repro_manifest_recording(&mut writer, &batch)?;
    assert_eq!(
        writer.commit_artifact_registration_batch(batch)?,
        ArtifactRegistrationCommitOutcomeV1::Applied
    );
    assert!(reader
        .read_artifact_registration(&owner_id, root_address)?
        .is_some());
    drop(reader);
    drop(writer);

    let reopened = pos_store::sqlite::SqliteStore::open(path)?;
    assert!(reopened
        .read_artifact_registration(&owner_id, root_address)?
        .is_some());
    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_catalog_rejects_a_second_root_for_the_same_operation_atomically(
) -> Result<(), Box<dyn std::error::Error>> {
    let database = tempfile::NamedTempFile::new()?;
    let path = database
        .path()
        .to_str()
        .ok_or_else(|| std::io::Error::other("temporary path is not UTF-8"))?;
    let mut store = pos_store::sqlite::SqliteStore::open(path)?;
    let (owner_id, root_address, batch) = prepared_repro_manifest()?;
    let alternate_source: Vec<_> = batch
        .records()
        .iter()
        .map(|record| ArtifactRegistrationInputV1 {
            owner_id: *record.owner_id(),
            artifact_bytes: record.artifact_bytes().to_vec(),
            registration_cbor: record.registration().canonical_cbor().to_vec(),
        })
        .collect();
    close_repro_manifest_recording(&mut store, &batch)?;
    assert_eq!(
        store.commit_artifact_registration_batch(batch)?,
        ArtifactRegistrationCommitOutcomeV1::Applied
    );

    let (alternate_root, alternate_inputs) = alternate_root_with_same_operation(alternate_source)?;
    let alternate = prepare_artifact_registration_batch_v1(
        owner_id,
        alternate_root,
        alternate_inputs,
        &TestOnlyStructuralOwnerVerifier,
    )?;
    assert_eq!(
        store.commit_artifact_registration_batch(alternate),
        Err(pos_core::ArtifactRegistrationPersistenceErrorV1::Conflict)
    );
    assert!(store
        .read_artifact_registration(&owner_id, root_address)?
        .is_some());
    assert!(store
        .read_artifact_registration(&owner_id, alternate_root)?
        .is_none());
    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_catalog_reports_a_missing_operation_index_as_corruption(
) -> Result<(), Box<dyn std::error::Error>> {
    let database = tempfile::NamedTempFile::new()?;
    let path = database
        .path()
        .to_str()
        .ok_or_else(|| std::io::Error::other("temporary path is not UTF-8"))?;
    let mut store = pos_store::sqlite::SqliteStore::open(path)?;
    let (owner_id, root_address, batch) = prepared_repro_manifest()?;
    close_repro_manifest_recording(&mut store, &batch)?;
    store.commit_artifact_registration_batch(batch)?;
    drop(store);

    let connection = rusqlite::Connection::open(path)?;
    connection.execute(
        "DELETE FROM artifact_registration_operations WHERE owner_id = ?1",
        [owner_id.as_str()],
    )?;
    drop(connection);

    let mut reopened = pos_store::sqlite::SqliteStore::open(path)?;
    assert_eq!(
        reopened.read_artifact_registration(&owner_id, root_address),
        Err(pos_core::ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)
    );
    let (_, _, retry) = prepared_repro_manifest()?;
    assert_eq!(
        reopened.commit_artifact_registration_batch(retry),
        Err(pos_core::ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)
    );
    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_catalog_reports_modified_artifact_bytes_as_corruption(
) -> Result<(), Box<dyn std::error::Error>> {
    let database = tempfile::NamedTempFile::new()?;
    let path = database
        .path()
        .to_str()
        .ok_or_else(|| std::io::Error::other("temporary path is not UTF-8"))?;
    let mut store = pos_store::sqlite::SqliteStore::open(path)?;
    let (owner_id, root_address, batch) = prepared_repro_manifest()?;
    close_repro_manifest_recording(&mut store, &batch)?;
    store.commit_artifact_registration_batch(batch)?;
    drop(store);

    let connection = rusqlite::Connection::open(path)?;
    connection.execute(
        "UPDATE artifact_registrations SET artifact_bytes = ?1
         WHERE registration_address = ?2",
        rusqlite::params![
            b"corrupt MRM1 bytes".as_slice(),
            root_address.as_bytes().as_slice()
        ],
    )?;
    drop(connection);

    let reopened = pos_store::sqlite::SqliteStore::open(path)?;
    assert_eq!(
        reopened.read_artifact_registration(&owner_id, root_address),
        Err(pos_core::ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)
    );
    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_catalog_rejects_changed_closed_recorder_bytes_on_read(
) -> Result<(), Box<dyn std::error::Error>> {
    let database = tempfile::NamedTempFile::new()?;
    let path = database
        .path()
        .to_str()
        .ok_or_else(|| std::io::Error::other("temporary path is not UTF-8"))?;
    let mut store = pos_store::sqlite::SqliteStore::open(path)?;
    let (owner_id, root_address, batch) = prepared_repro_manifest()?;
    close_repro_manifest_recording(&mut store, &batch)?;
    store.commit_artifact_registration_batch(batch)?;
    drop(store);

    let connection = rusqlite::Connection::open(path)?;
    connection.execute(
        "UPDATE adapter_recording_sessions SET transcript_cbor = ?1
         WHERE owner_reference = ?2 AND run_operation_id = ?3",
        rusqlite::params![
            b"changed closed MAT1".as_slice(),
            ArtifactRegistrationV1::owner_reference(&owner_id)
                .as_bytes()
                .as_slice(),
            [0x51_u8; 32].as_slice(),
        ],
    )?;
    drop(connection);

    let reopened = pos_store::sqlite::SqliteStore::open(path)?;
    assert_eq!(
        reopened.read_artifact_registration(&owner_id, root_address),
        Err(pos_core::ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)
    );
    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_rolls_back_the_entire_closure_when_root_commit_fails(
) -> Result<(), Box<dyn std::error::Error>> {
    let database = tempfile::NamedTempFile::new()?;
    let path = database
        .path()
        .to_str()
        .ok_or_else(|| std::io::Error::other("temporary path is not UTF-8"))?;
    drop(pos_store::sqlite::SqliteStore::open(path)?);
    let (owner_id, root_address, batch) = prepared_repro_manifest()?;
    let connection = rusqlite::Connection::open(path)?;
    let mut root_hex = String::with_capacity(64);
    for byte in root_address.as_bytes() {
        write!(&mut root_hex, "{byte:02x}")?;
    }
    connection.execute_batch(&format!(
        "CREATE TRIGGER fail_root_registration BEFORE INSERT ON artifact_registrations
         WHEN NEW.registration_address = X'{root_hex}'
         BEGIN SELECT RAISE(ABORT, 'injected root commit failure'); END;"
    ))?;
    drop(connection);

    let mut store = pos_store::sqlite::SqliteStore::open(path)?;
    close_repro_manifest_recording(&mut store, &batch)?;
    assert_eq!(
        store.commit_artifact_registration_batch(batch),
        Err(pos_core::ArtifactRegistrationPersistenceErrorV1::StorageFailure)
    );
    assert!(store
        .read_artifact_registration(&owner_id, root_address)?
        .is_none());
    let connection = rusqlite::Connection::open(path)?;
    let row_count: i64 =
        connection.query_row("SELECT COUNT(*) FROM artifact_registrations", [], |row| {
            row.get(0)
        })?;
    assert_eq!(row_count, 0);
    Ok(())
}

#[test]
fn memory_event_store_adapter_recording_port_covers_the_public_state_machine(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut store = MemoryStore::new();
    exercise_event_store_adapter_recording(&mut store, Hash::from_bytes([0x7e; 32]))
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_event_store_adapter_recording_port_covers_the_public_state_machine(
) -> Result<(), Box<dyn std::error::Error>> {
    let database = tempfile::NamedTempFile::new()?;
    let path = database
        .path()
        .to_str()
        .ok_or_else(|| std::io::Error::other("temporary path is not UTF-8"))?;
    let mut store = pos_store::sqlite::SqliteStore::open(path)?;
    exercise_event_store_adapter_recording(&mut store, Hash::from_bytes([0x7f; 32]))
}


#[cfg(feature = "sqlite")]
#[test]
fn sqlite_event_store_exposes_the_artifact_registration_port(
) -> Result<(), Box<dyn std::error::Error>> {
    let database = tempfile::NamedTempFile::new()?;
    let path = database
        .path()
        .to_str()
        .ok_or_else(|| std::io::Error::other("temporary path is not UTF-8"))?;
    let mut store = pos_store::sqlite::SqliteStore::open(path)?;
    let (owner_id, root_address, batch) = prepared_repro_manifest()?;
    close_repro_manifest_recording(&mut store, &batch)?;
    let retry = batch.clone();
    assert_eq!(
        pos_core::store::EventStore::commit_artifact_registration_batch(&mut store, batch)?,
        ArtifactRegistrationCommitOutcomeV1::Applied
    );
    assert_eq!(
        pos_core::store::EventStore::commit_artifact_registration_batch(&mut store, retry)?,
        ArtifactRegistrationCommitOutcomeV1::ExactRetry
    );
    assert!(pos_core::store::EventStore::read_artifact_registration(
        &store,
        &owner_id,
        root_address,
    )?
    .is_some());
    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_catalog_commit_requires_the_complete_schema(
) -> Result<(), Box<dyn std::error::Error>> {
    let database = tempfile::NamedTempFile::new()?;
    let path = database
        .path()
        .to_str()
        .ok_or_else(|| std::io::Error::other("temporary path is not UTF-8"))?;
    let mut store = pos_store::sqlite::SqliteStore::open(path)?;
    let (_, _, batch) = prepared_repro_manifest()?;
    let connection = rusqlite::Connection::open(path)?;
    connection.execute_batch("DROP TABLE artifact_registration_operations")?;
    assert_eq!(
        store.commit_artifact_registration_batch(batch),
        Err(pos_core::ArtifactRegistrationPersistenceErrorV1::StorageFailure)
    );
    Ok(())
}
