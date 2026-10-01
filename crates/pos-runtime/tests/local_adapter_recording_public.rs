use std::sync::{Arc, Mutex};

use pos_core::{
    adapter_configuration_digest_v1, public_adapter_schema_digest_v1, AdapterAdmissionEntryV1,
    AdapterDataClassV1, AdapterEffectModeV1, AdapterInvocationV1, AdapterRecordingStoreV1,
    AdapterTranscriptV1, ArtifactRegistrationV1, Capability, Hash, OwnerIdV1, Plugin, PluginId,
    TimelineId, WorldReplayHandleInputV1, WorldReplayHandleV1,
    MAX_ADAPTER_TRANSCRIPT_CALLS_V1,
};
use pos_runtime::{
    LocalAdapterErrorV1, LocalAdapterIdempotencyKeyV1, LocalAdapterProviderResponseV1,
    LocalAdapterProviderV1, PluginRegistry,
};

struct LocalPlugin {
    id: PluginId,
}

impl Plugin for LocalPlugin {
    fn id(&self) -> PluginId {
        self.id
    }

    fn name(&self) -> &'static str {
        "local-adapter-plugin"
    }

    fn capability(&self) -> Capability {
        Capability::default()
    }
}

type CompletedResponse = (LocalAdapterIdempotencyKeyV1, Vec<u8>);
type TestResult = Result<(), Box<dyn std::error::Error>>;

struct EchoProvider {
    idempotency_keys: Arc<Mutex<Vec<LocalAdapterIdempotencyKeyV1>>>,
    completed_responses: Arc<Mutex<Vec<CompletedResponse>>>,
}

impl LocalAdapterProviderV1 for EchoProvider {
    fn guarantees_external_idempotency(&self) -> bool {
        true
    }

    fn invoke(
        &mut self,
        invocation: &AdapterInvocationV1,
        idempotency_key: LocalAdapterIdempotencyKeyV1,
    ) -> Result<LocalAdapterProviderResponseV1, LocalAdapterErrorV1> {
        let mut completed_responses = self
            .completed_responses
            .lock()
            .map_err(|_| LocalAdapterErrorV1::ProviderRejected)?;
        let cached_response = completed_responses
            .iter()
            .find(|(key, _)| *key == idempotency_key)
            .map(|(_, response)| response.clone());
        let response = cached_response.unwrap_or_else(|| {
            let response: Vec<u8> = invocation
                .as_input()
                .exact_request_payload
                .iter()
                .rev()
                .copied()
                .collect();
            completed_responses.push((idempotency_key, response.clone()));
            response
        });
        drop(completed_responses);
        self.idempotency_keys
            .lock()
            .map_err(|_| LocalAdapterErrorV1::ProviderRejected)?
            .push(idempotency_key);
        Ok(LocalAdapterProviderResponseV1::acknowledged(
            response,
            idempotency_key,
        ))
    }
}

struct RejectingProvider;

impl LocalAdapterProviderV1 for RejectingProvider {
    fn invoke(
        &mut self,
        _: &AdapterInvocationV1,
        _: LocalAdapterIdempotencyKeyV1,
    ) -> Result<LocalAdapterProviderResponseV1, LocalAdapterErrorV1> {
        Err(LocalAdapterErrorV1::ProviderRejected)
    }
}

struct UnacknowledgedProvider;

impl LocalAdapterProviderV1 for UnacknowledgedProvider {
    fn guarantees_external_idempotency(&self) -> bool {
        true
    }

    fn invoke(
        &mut self,
        _: &AdapterInvocationV1,
        _: LocalAdapterIdempotencyKeyV1,
    ) -> Result<LocalAdapterProviderResponseV1, LocalAdapterErrorV1> {
        Ok(LocalAdapterProviderResponseV1::unacknowledged(
            b"response".to_vec(),
        ))
    }
}

struct FailFirstCompletionStore {
    inner: pos_store::memory::MemoryStore,
    fail_next_completion: bool,
}

impl AdapterRecordingStoreV1 for FailFirstCompletionStore {
    fn open_adapter_recording_session(
        &mut self,
        session: pos_core::AdapterRecordingSessionV1,
    ) -> Result<(), pos_core::AdapterRecordingStoreErrorV1> {
        self.inner.open_adapter_recording_session(session)
    }

    fn reserve_adapter_call(
        &mut self,
        owner_reference: Hash,
        run_operation_id: Hash,
        reservation: pos_core::AdapterCallReservationV1,
    ) -> Result<pos_core::AdapterCallReservationOutcomeV1, pos_core::AdapterRecordingStoreErrorV1>
    {
        self.inner
            .reserve_adapter_call(owner_reference, run_operation_id, reservation)
    }

    fn complete_adapter_call(
        &mut self,
        owner_reference: Hash,
        run_operation_id: Hash,
        global_call_index: u64,
        output_bytes: Vec<u8>,
    ) -> Result<(), pos_core::AdapterRecordingStoreErrorV1> {
        if std::mem::replace(&mut self.fail_next_completion, false) {
            return Err(pos_core::AdapterRecordingStoreErrorV1::StorageFailure);
        }
        self.inner.complete_adapter_call(
            owner_reference,
            run_operation_id,
            global_call_index,
            output_bytes,
        )
    }

    fn close_adapter_recording_session(
        &mut self,
        owner_reference: Hash,
        run_operation_id: Hash,
    ) -> Result<Vec<u8>, pos_core::AdapterRecordingStoreErrorV1> {
        self.inner
            .close_adapter_recording_session(owner_reference, run_operation_id)
    }

    fn read_closed_adapter_recording_session(
        &self,
        owner_reference: Hash,
        run_operation_id: Hash,
    ) -> Result<Option<Vec<u8>>, pos_core::AdapterRecordingStoreErrorV1> {
        self.inner
            .read_closed_adapter_recording_session(owner_reference, run_operation_id)
    }

    fn abort_adapter_recording_session(
        &mut self,
        owner_reference: Hash,
        run_operation_id: Hash,
    ) -> Result<(), pos_core::AdapterRecordingStoreErrorV1> {
        self.inner
            .abort_adapter_recording_session(owner_reference, run_operation_id)
    }
}

fn adapter_entry(plugin_id: PluginId) -> AdapterAdmissionEntryV1 {
    let configuration = b"local-provider-config".to_vec();
    AdapterAdmissionEntryV1 {
        plugin_id,
        adapter_id: "weather.client".to_owned(),
        provider_id: "fixture.provider".to_owned(),
        operation_id: "read-current".to_owned(),
        protocol_version: 1,
        request_schema_digest: public_adapter_schema_digest_v1(),
        response_schema_digest: public_adapter_schema_digest_v1(),
        configuration_digest: adapter_configuration_digest_v1(&configuration),
        exact_configuration_bytes: configuration,
        input_data_class: AdapterDataClassV1::PublicRecord,
        output_data_class: AdapterDataClassV1::PublicRecord,
        effect_mode: AdapterEffectModeV1::ReadOnly,
    }
}

fn world_handle(owner_reference: Hash) -> Result<WorldReplayHandleV1, Box<dyn std::error::Error>> {
    Ok(WorldReplayHandleV1::new(WorldReplayHandleInputV1 {
        owner_reference,
        timeline_id: TimelineId::new(),
        cut_id: 4,
        commit_receipt_digest: Hash::from_bytes([11; 32]),
        recording_receipt_digest: Hash::from_bytes([12; 32]),
        logical_head: 7,
        stitched_head_hash: Hash::from_bytes([13; 32]),
    })?)
}

fn registry_with_adapter(
    provider: Box<dyn LocalAdapterProviderV1>,
) -> Result<
    (
        PluginRegistry,
        pos_runtime::AdmittedCompositionV1,
        WorldReplayHandleV1,
    ),
    Box<dyn std::error::Error>,
> {
    registry_with_adapter_mode(provider, AdapterEffectModeV1::ReadOnly)
}

fn registry_with_adapter_mode(
    provider: Box<dyn LocalAdapterProviderV1>,
    effect_mode: AdapterEffectModeV1,
) -> Result<
    (
        PluginRegistry,
        pos_runtime::AdmittedCompositionV1,
        WorldReplayHandleV1,
    ),
    Box<dyn std::error::Error>,
> {
    let plugin = LocalPlugin {
        id: PluginId::new(),
    };
    let owner = OwnerIdV1::from_static("local-adapter-test");
    let owner_reference = ArtifactRegistrationV1::owner_reference(&owner);
    let mut registry = PluginRegistry::new();
    registry.register_local(&plugin, vec!["weather.read".to_owned()], None, None)?;
    let mut entry = adapter_entry(plugin.id());
    entry.effect_mode = effect_mode;
    registry.register_local_adapter(entry, provider)?;
    let handle = world_handle(owner_reference)?;
    let admitted = registry.admit_local_manifest_registration(owner, 2)?;
    Ok((registry, admitted, handle))
}

#[test]
fn local_registry_records_exact_adapter_calls_in_a_closed_transcript() -> TestResult {
    let keys = Arc::new(Mutex::new(Vec::new()));
    let provider = EchoProvider {
        idempotency_keys: Arc::clone(&keys),
        completed_responses: Arc::new(Mutex::new(Vec::new())),
    };
    let (mut registry, admitted, handle) = registry_with_adapter(Box::new(provider))?;
    assert_eq!(admitted.adapter_admission().as_input().entries.len(), 1);
    let mut recorder = pos_store::memory::MemoryStore::new();

    let operation_id = Hash::from_bytes([21; 32]);
    let request = b"exact request".to_vec();
    let mut session =
        registry.begin_local_adapter_session(&admitted, handle, operation_id, &mut recorder)?;
    let response = session.invoke(
        admitted.adapter_admission().as_input().entries[0].plugin_id,
        "weather.client",
        "fixture.provider",
        "read-current",
        1,
        request.clone(),
    )?;
    assert_eq!(response, b"tseuqer tcaxe");
    drop(session);
    let mut retry =
        registry.begin_local_adapter_session(&admitted, handle, operation_id, &mut recorder)?;
    let retried_response = retry.invoke(
        admitted.adapter_admission().as_input().entries[0].plugin_id,
        "weather.client",
        "fixture.provider",
        "read-current",
        1,
        b"exact request".to_vec(),
    )?;
    assert_eq!(retried_response, response);
    let closed = retry.finish()?;
    let transcript = AdapterTranscriptV1::from_canonical_cbor(&closed.transcript_bytes())?;
    assert_eq!(transcript.as_input().calls.len(), 1);
    assert_eq!(
        transcript.as_input().calls[0]
            .input
            .as_input()
            .exact_request_payload,
        request
    );
    assert_eq!(transcript.as_input().calls[0].exact_output_bytes, response);
    assert_eq!(
        transcript.as_input().adapter_admission_digest,
        closed.admission().digest()
    );
    let observed_keys = keys
        .lock()
        .map_err(|_| std::io::Error::other("idempotency key lock was poisoned"))?;
    assert_eq!(observed_keys.len(), 1);
    assert_eq!(
        observed_keys[0].owner_reference(),
        handle.as_input().owner_reference
    );
    assert_eq!(observed_keys[0].run_operation_id(), operation_id);
    assert_eq!(observed_keys[0].global_call_index(), 0);
    drop(observed_keys);
    drop(keys);
    assert_eq!(
        closed.admission_bytes(),
        closed.admission().to_canonical_cbor()
    );
    let closed_bytes = closed.transcript_bytes();
    assert_eq!(
        recorder
            .read_closed_adapter_recording_session(handle.as_input().owner_reference, operation_id)?
            .as_deref(),
        Some(closed_bytes.as_slice())
    );
    Ok(())
}

#[test]
fn local_adapter_session_emits_an_explicit_empty_transcript() -> TestResult {
    let (mut registry, admitted, handle) = registry_with_adapter(Box::new(RejectingProvider))?;
    let mut recorder = pos_store::memory::MemoryStore::new();
    let session = registry.begin_local_adapter_session(
        &admitted,
        handle,
        Hash::from_bytes([22; 32]),
        &mut recorder,
    )?;
    let closed = session.finish()?;
    assert!(closed.transcript().as_input().calls.is_empty());
    Ok(())
}

#[test]
fn failed_local_adapter_session_cannot_produce_a_transcript() -> TestResult {
    let plugin_id = PluginId::new();
    let provider = RejectingProvider;
    let plugin = LocalPlugin { id: plugin_id };
    let owner = OwnerIdV1::from_static("local-adapter-failure-test");
    let owner_reference = ArtifactRegistrationV1::owner_reference(&owner);
    let mut recorder = pos_store::memory::MemoryStore::new();
    let mut registry = PluginRegistry::new();
    registry.register_local(&plugin, vec!["weather.read".to_owned()], None, None)?;
    registry.register_local_adapter(adapter_entry(plugin_id), Box::new(provider))?;
    let admitted = registry.admit_local_manifest_registration(owner, 2)?;
    let mut session = registry.begin_local_adapter_session(
        &admitted,
        world_handle(owner_reference)?,
        Hash::from_bytes([23; 32]),
        &mut recorder,
    )?;
    assert_eq!(
        session.invoke(
            plugin_id,
            "weather.client",
            "fixture.provider",
            "read-current",
            1,
            b"request".to_vec(),
        ),
        Err(LocalAdapterErrorV1::ProviderRejected)
    );
    session.abort()?;
    assert_eq!(
        recorder
            .read_closed_adapter_recording_session(owner_reference, Hash::from_bytes([23; 32]))?,
        None
    );
    Ok(())
}

#[test]
fn externally_idempotent_provider_receives_exact_run_key_and_must_acknowledge_it() -> TestResult {
    let keys = Arc::new(Mutex::new(Vec::new()));
    let completed_responses = Arc::new(Mutex::new(Vec::new()));
    let (mut registry, admitted, handle) = registry_with_adapter_mode(
        Box::new(EchoProvider {
            idempotency_keys: Arc::clone(&keys),
            completed_responses: Arc::clone(&completed_responses),
        }),
        AdapterEffectModeV1::ExternallyIdempotent,
    )?;
    let owner_reference = handle.as_input().owner_reference;
    let operation_id = Hash::from_bytes([24; 32]);
    let mut recorder = pos_store::memory::MemoryStore::new();
    let mut session =
        registry.begin_local_adapter_session(&admitted, handle, operation_id, &mut recorder)?;
    assert_eq!(
        session.invoke(
            admitted.adapter_admission().as_input().entries[0].plugin_id,
            "weather.client",
            "fixture.provider",
            "read-current",
            1,
            b"request".to_vec(),
        ),
        Ok(b"tseuqer".to_vec())
    );
    session.finish()?;
    let observed_keys = keys
        .lock()
        .map_err(|_| std::io::Error::other("idempotency key lock was poisoned"))?;
    assert_eq!(observed_keys.len(), 1);
    assert_eq!(observed_keys[0].owner_reference(), owner_reference);
    assert_eq!(observed_keys[0].run_operation_id(), operation_id);
    assert_eq!(observed_keys[0].global_call_index(), 0);
    drop(observed_keys);
    drop(keys);
    assert_eq!(
        completed_responses
            .lock()
            .map_err(|_| std::io::Error::other("completed response lock was poisoned"))?
            .len(),
        1
    );

    let (mut registry, admitted, handle) = registry_with_adapter_mode(
        Box::new(UnacknowledgedProvider),
        AdapterEffectModeV1::ExternallyIdempotent,
    )?;
    let mut recorder = FailFirstCompletionStore {
        inner: pos_store::memory::MemoryStore::new(),
        fail_next_completion: false,
    };
    let mut session = registry.begin_local_adapter_session(
        &admitted,
        handle,
        Hash::from_bytes([25; 32]),
        &mut recorder,
    )?;
    assert_eq!(
        session.invoke(
            admitted.adapter_admission().as_input().entries[0].plugin_id,
            "weather.client",
            "fixture.provider",
            "read-current",
            1,
            b"request".to_vec(),
        ),
        Err(LocalAdapterErrorV1::ProviderIdempotencyUnacknowledged)
    );
    session.abort()?;
    Ok(())
}

#[test]
fn externally_idempotent_registration_requires_a_provider_deduplication_guarantee() -> TestResult {
    let plugin = LocalPlugin {
        id: PluginId::new(),
    };
    let mut registry = PluginRegistry::new();
    registry.register_local(&plugin, vec!["weather.read".to_owned()], None, None)?;
    let mut entry = adapter_entry(plugin.id());
    entry.effect_mode = AdapterEffectModeV1::ExternallyIdempotent;
    assert_eq!(
        registry.register_local_adapter(entry, Box::new(RejectingProvider)),
        Err(LocalAdapterErrorV1::IdempotencyUnavailable)
    );
    Ok(())
}

#[test]
fn externally_idempotent_retry_reuses_provider_output_after_completion_failure() -> TestResult {
    let keys = Arc::new(Mutex::new(Vec::new()));
    let completed_responses = Arc::new(Mutex::new(Vec::new()));
    let (mut registry, admitted, handle) = registry_with_adapter_mode(
        Box::new(EchoProvider {
            idempotency_keys: Arc::clone(&keys),
            completed_responses: Arc::clone(&completed_responses),
        }),
        AdapterEffectModeV1::ExternallyIdempotent,
    )?;
    let operation_id = Hash::from_bytes([26; 32]);
    let mut recorder = FailFirstCompletionStore {
        inner: pos_store::memory::MemoryStore::new(),
        fail_next_completion: true,
    };
    let mut session =
        registry.begin_local_adapter_session(&admitted, handle, operation_id, &mut recorder)?;
    assert_eq!(
        session.invoke(
            admitted.adapter_admission().as_input().entries[0].plugin_id,
            "weather.client",
            "fixture.provider",
            "read-current",
            1,
            b"request".to_vec(),
        ),
        Err(LocalAdapterErrorV1::RecordingFailed)
    );
    drop(session);

    let mut retry =
        registry.begin_local_adapter_session(&admitted, handle, operation_id, &mut recorder)?;
    assert_eq!(
        retry.invoke(
            admitted.adapter_admission().as_input().entries[0].plugin_id,
            "weather.client",
            "fixture.provider",
            "read-current",
            1,
            b"request".to_vec(),
        ),
        Ok(b"tseuqer".to_vec())
    );
    retry.finish()?;
    assert!(recorder
        .read_closed_adapter_recording_session(handle.as_input().owner_reference, operation_id)
        .map_err(|_| std::io::Error::other("closed-session read failed"))?
        .is_some());

    let observed_keys = keys
        .lock()
        .map_err(|_| std::io::Error::other("idempotency key lock was poisoned"))?;
    assert_eq!(observed_keys.len(), 2);
    assert_eq!(observed_keys[0], observed_keys[1]);
    assert_eq!(
        observed_keys[0].owner_reference(),
        handle.as_input().owner_reference
    );
    assert_eq!(observed_keys[0].run_operation_id(), operation_id);
    assert_eq!(observed_keys[0].global_call_index(), 0);
    drop(observed_keys);
    drop(keys);
    assert_eq!(
        completed_responses
            .lock()
            .map_err(|_| std::io::Error::other("completed response lock was poisoned"))?
            .len(),
        1
    );
    Ok(())
}

struct OversizedProvider;

impl LocalAdapterProviderV1 for OversizedProvider {
    fn invoke(
        &mut self,
        _: &AdapterInvocationV1,
        idempotency_key: LocalAdapterIdempotencyKeyV1,
    ) -> Result<LocalAdapterProviderResponseV1, LocalAdapterErrorV1> {
        Ok(LocalAdapterProviderResponseV1::acknowledged(
            vec![0; pos_core::MAX_ADAPTER_CALL_BYTES_V1 + 1],
            idempotency_key,
        ))
    }
}

struct PanickingProvider;

impl LocalAdapterProviderV1 for PanickingProvider {
    fn invoke(
        &mut self,
        _: &AdapterInvocationV1,
        _: LocalAdapterIdempotencyKeyV1,
    ) -> Result<LocalAdapterProviderResponseV1, LocalAdapterErrorV1> {
        std::panic::resume_unwind(Box::new(
            "provider panic must remain contained by the local recorder",
        ));
    }
}

#[derive(Clone, Copy)]
enum RecorderFailure {
    Open,
    Reserve,
    Close,
    Abort,
}

struct FailingRecordingStore {
    inner: pos_store::memory::MemoryStore,
    failure: RecorderFailure,
}

impl AdapterRecordingStoreV1 for FailingRecordingStore {
    fn open_adapter_recording_session(
        &mut self,
        session: pos_core::AdapterRecordingSessionV1,
    ) -> Result<(), pos_core::AdapterRecordingStoreErrorV1> {
        if matches!(self.failure, RecorderFailure::Open) {
            return Err(pos_core::AdapterRecordingStoreErrorV1::StorageFailure);
        }
        self.inner.open_adapter_recording_session(session)
    }

    fn reserve_adapter_call(
        &mut self,
        owner_reference: Hash,
        run_operation_id: Hash,
        reservation: pos_core::AdapterCallReservationV1,
    ) -> Result<pos_core::AdapterCallReservationOutcomeV1, pos_core::AdapterRecordingStoreErrorV1>
    {
        if matches!(self.failure, RecorderFailure::Reserve) {
            return Err(pos_core::AdapterRecordingStoreErrorV1::StorageFailure);
        }
        self.inner
            .reserve_adapter_call(owner_reference, run_operation_id, reservation)
    }

    fn complete_adapter_call(
        &mut self,
        owner_reference: Hash,
        run_operation_id: Hash,
        global_call_index: u64,
        output_bytes: Vec<u8>,
    ) -> Result<(), pos_core::AdapterRecordingStoreErrorV1> {
        self.inner.complete_adapter_call(
            owner_reference,
            run_operation_id,
            global_call_index,
            output_bytes,
        )
    }

    fn close_adapter_recording_session(
        &mut self,
        owner_reference: Hash,
        run_operation_id: Hash,
    ) -> Result<Vec<u8>, pos_core::AdapterRecordingStoreErrorV1> {
        if matches!(self.failure, RecorderFailure::Close) {
            return Err(pos_core::AdapterRecordingStoreErrorV1::StorageFailure);
        }
        self.inner
            .close_adapter_recording_session(owner_reference, run_operation_id)
    }

    fn read_closed_adapter_recording_session(
        &self,
        owner_reference: Hash,
        run_operation_id: Hash,
    ) -> Result<Option<Vec<u8>>, pos_core::AdapterRecordingStoreErrorV1> {
        self.inner
            .read_closed_adapter_recording_session(owner_reference, run_operation_id)
    }

    fn abort_adapter_recording_session(
        &mut self,
        owner_reference: Hash,
        run_operation_id: Hash,
    ) -> Result<(), pos_core::AdapterRecordingStoreErrorV1> {
        if matches!(self.failure, RecorderFailure::Abort) {
            return Err(pos_core::AdapterRecordingStoreErrorV1::StorageFailure);
        }
        self.inner
            .abort_adapter_recording_session(owner_reference, run_operation_id)
    }
}

#[test]
fn local_adapter_registration_rejects_missing_duplicate_and_sealed_entries() -> TestResult {
    let plugin = LocalPlugin {
        id: PluginId::new(),
    };
    let mut missing = PluginRegistry::new();
    assert_eq!(
        missing.register_local_adapter(adapter_entry(plugin.id()), Box::new(RejectingProvider)),
        Err(LocalAdapterErrorV1::PluginUnavailable)
    );

    let mut registry = PluginRegistry::new();
    registry.register_local(&plugin, vec!["weather.read".to_owned()], None, None)?;
    let entry = adapter_entry(plugin.id());
    registry.register_local_adapter(entry.clone(), Box::new(RejectingProvider))?;
    assert_eq!(
        registry.register_local_adapter(entry.clone(), Box::new(RejectingProvider)),
        Err(LocalAdapterErrorV1::InvalidContract)
    );
    registry
        .admit_local_manifest_registration(OwnerIdV1::from_static("sealed-local-adapter"), 4)?;
    assert_eq!(
        registry.register_local_adapter(entry, Box::new(RejectingProvider)),
        Err(LocalAdapterErrorV1::ManifestSealed)
    );
    Ok(())
}

#[test]
fn local_adapter_session_rejects_stale_unknown_and_terminal_calls() -> TestResult {
    let (mut registry, admitted, handle) = registry_with_adapter(Box::new(RejectingProvider))?;
    let plugin_id = admitted.adapter_admission().as_input().entries[0].plugin_id;
    let owner_reference = handle.as_input().owner_reference;
    let mut recorder = pos_store::memory::MemoryStore::new();

    assert!(matches!(
        registry.begin_local_adapter_session(&admitted, handle, Hash::zero(), &mut recorder),
        Err(LocalAdapterErrorV1::StaleAdmission)
    ));

    let mut session = registry.begin_local_adapter_session(
        &admitted,
        world_handle(owner_reference)?,
        Hash::from_bytes([27; 32]),
        &mut recorder,
    )?;
    assert_eq!(
        session.invoke(
            plugin_id,
            "other.adapter",
            "fixture.provider",
            "read-current",
            1,
            b"request".to_vec(),
        ),
        Err(LocalAdapterErrorV1::UnknownAdapter)
    );
    assert_eq!(
        session.invoke(
            plugin_id,
            "weather.client",
            "fixture.provider",
            "read-current",
            1,
            b"request".to_vec(),
        ),
        Err(LocalAdapterErrorV1::SessionAborted)
    );
    session.abort()?;
    Ok(())
}

#[test]
fn local_adapter_session_contains_provider_output_and_panic_failures() -> TestResult {
    let (mut registry, admitted, handle) = registry_with_adapter(Box::new(OversizedProvider))?;
    let plugin_id = admitted.adapter_admission().as_input().entries[0].plugin_id;
    let mut recorder = pos_store::memory::MemoryStore::new();
    let mut session = registry.begin_local_adapter_session(
        &admitted,
        handle,
        Hash::from_bytes([28; 32]),
        &mut recorder,
    )?;
    assert_eq!(
        session.invoke(
            plugin_id,
            "weather.client",
            "fixture.provider",
            "read-current",
            1,
            b"request".to_vec(),
        ),
        Err(LocalAdapterErrorV1::CallBoundExceeded)
    );
    session.abort()?;

    let (mut registry, admitted, handle) = registry_with_adapter(Box::new(PanickingProvider))?;
    let plugin_id = admitted.adapter_admission().as_input().entries[0].plugin_id;
    let mut recorder = pos_store::memory::MemoryStore::new();
    let mut session = registry.begin_local_adapter_session(
        &admitted,
        handle,
        Hash::from_bytes([29; 32]),
        &mut recorder,
    )?;
    assert_eq!(
        session.invoke(
            plugin_id,
            "weather.client",
            "fixture.provider",
            "read-current",
            1,
            b"request".to_vec(),
        ),
        Err(LocalAdapterErrorV1::ProviderRejected)
    );
    session.abort()?;
    Ok(())
}

#[test]
fn local_adapter_session_maps_recorder_boundaries_to_closed_errors() -> TestResult {
    let (mut registry, admitted, handle) = registry_with_adapter(Box::new(RejectingProvider))?;
    let mut recorder = FailingRecordingStore {
        inner: pos_store::memory::MemoryStore::new(),
        failure: RecorderFailure::Open,
    };
    assert!(matches!(
        registry.begin_local_adapter_session(
            &admitted,
            handle,
            Hash::from_bytes([30; 32]),
            &mut recorder,
        ),
        Err(LocalAdapterErrorV1::RecordingFailed)
    ));

    let (mut registry, admitted, handle) = registry_with_adapter(Box::new(RejectingProvider))?;
    let plugin_id = admitted.adapter_admission().as_input().entries[0].plugin_id;
    let mut recorder = FailingRecordingStore {
        inner: pos_store::memory::MemoryStore::new(),
        failure: RecorderFailure::Reserve,
    };
    let mut session = registry.begin_local_adapter_session(
        &admitted,
        handle,
        Hash::from_bytes([31; 32]),
        &mut recorder,
    )?;
    assert_eq!(
        session.invoke(
            plugin_id,
            "weather.client",
            "fixture.provider",
            "read-current",
            1,
            b"request".to_vec(),
        ),
        Err(LocalAdapterErrorV1::RecordingFailed)
    );
    session.abort()?;

    let (mut registry, admitted, handle) = registry_with_adapter(Box::new(RejectingProvider))?;
    let mut recorder = FailingRecordingStore {
        inner: pos_store::memory::MemoryStore::new(),
        failure: RecorderFailure::Close,
    };
    let session = registry.begin_local_adapter_session(
        &admitted,
        handle,
        Hash::from_bytes([32; 32]),
        &mut recorder,
    )?;
    assert!(matches!(
        session.finish(),
        Err(LocalAdapterErrorV1::RecordingFailed)
    ));

    let (mut registry, admitted, handle) = registry_with_adapter(Box::new(RejectingProvider))?;
    let mut recorder = FailingRecordingStore {
        inner: pos_store::memory::MemoryStore::new(),
        failure: RecorderFailure::Abort,
    };
    let session = registry.begin_local_adapter_session(
        &admitted,
        handle,
        Hash::from_bytes([33; 32]),
        &mut recorder,
    )?;
    assert_eq!(session.abort(), Err(LocalAdapterErrorV1::RecordingFailed));
    Ok(())
}


#[test]
fn local_adapter_session_enforces_public_request_and_call_bounds() -> TestResult {
    let (mut registry, admitted, handle) = registry_with_adapter(Box::new(RejectingProvider))?;
    let plugin_id = admitted.adapter_admission().as_input().entries[0].plugin_id;
    let mut recorder = pos_store::memory::MemoryStore::new();
    let mut oversized = registry.begin_local_adapter_session(
        &admitted,
        handle,
        Hash::from_bytes([34; 32]),
        &mut recorder,
    )?;
    assert_eq!(
        oversized.invoke(
            plugin_id,
            "weather.client",
            "fixture.provider",
            "read-current",
            1,
            vec![0; pos_core::MAX_ADAPTER_CALL_BYTES_V1 + 1],
        ),
        Err(LocalAdapterErrorV1::CallBoundExceeded)
    );
    oversized.abort()?;

    let keys = Arc::new(Mutex::new(Vec::new()));
    let (mut registry, admitted, handle) = registry_with_adapter(Box::new(EchoProvider {
        idempotency_keys: Arc::clone(&keys),
        completed_responses: Arc::new(Mutex::new(Vec::new())),
    }))?;
    let plugin_id = admitted.adapter_admission().as_input().entries[0].plugin_id;
    let mut recorder = pos_store::memory::MemoryStore::new();
    let mut session = registry.begin_local_adapter_session(
        &admitted,
        handle,
        Hash::from_bytes([35; 32]),
        &mut recorder,
    )?;
    for _ in 0..MAX_ADAPTER_TRANSCRIPT_CALLS_V1 {
        assert_eq!(
            session.invoke(
                plugin_id,
                "weather.client",
                "fixture.provider",
                "read-current",
                1,
                b"x".to_vec(),
            ),
            Ok(b"x".to_vec())
        );
    }
    assert_eq!(
        session.invoke(
            plugin_id,
            "weather.client",
            "fixture.provider",
            "read-current",
            1,
            b"x".to_vec(),
        ),
        Err(LocalAdapterErrorV1::CallBoundExceeded)
    );
    session.abort()?;
    Ok(())
}

#[test]
fn local_adapter_registry_orders_multiple_contracts() -> TestResult {
    let low = LocalPlugin {
        id: PluginId::from_ulid(ulid::Ulid::from(1_u128)),
    };
    let high = LocalPlugin {
        id: PluginId::from_ulid(ulid::Ulid::from(2_u128)),
    };
    let mut registry = PluginRegistry::new();
    registry.register_local(&high, vec!["weather.high".to_owned()], None, None)?;
    registry.register_local(&low, vec!["weather.low".to_owned()], None, None)?;
    registry.register_local_adapter(adapter_entry(high.id()), Box::new(RejectingProvider))?;
    registry.register_local_adapter(adapter_entry(low.id()), Box::new(RejectingProvider))?;
    let admitted = registry.admit_local_manifest_registration(
        OwnerIdV1::from_static("ordered-local-adapter-owner"),
        5,
    )?;
    let entries = &admitted.adapter_admission().as_input().entries;
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].plugin_id, low.id());
    assert_eq!(entries[1].plugin_id, high.id());
    Ok(())
}
