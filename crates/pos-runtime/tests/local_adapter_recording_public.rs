use std::sync::{Arc, Mutex};

use pos_core::{
    adapter_configuration_digest_v1, public_adapter_schema_digest_v1, AdapterAdmissionEntryV1,
    AdapterDataClassV1, AdapterEffectModeV1, AdapterInvocationV1, AdapterRecordingStoreV1,
    AdapterTranscriptV1, ArtifactRegistrationV1, Capability, Hash, OwnerIdV1, Plugin, PluginId,
    TimelineId, WorldReplayHandleInputV1, WorldReplayHandleV1,
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

struct EchoProvider {
    idempotency_keys: Arc<Mutex<Vec<LocalAdapterIdempotencyKeyV1>>>,
    completed_responses: Arc<Mutex<Vec<(LocalAdapterIdempotencyKeyV1, Vec<u8>)>>>,
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
            .expect("idempotent response lock should be available");
        let cached_response = completed_responses
            .iter()
            .find(|(key, _)| *key == idempotency_key)
            .map(|(_, response)| response.clone());
        let response = cached_response.unwrap_or_else(|| {
            let response = invocation
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
            .expect("idempotency key lock should be available")
            .push(idempotency_key);
        Ok(LocalAdapterProviderResponseV1::acknowledged(response, idempotency_key))
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
        Ok(LocalAdapterProviderResponseV1::read_only(b"response".to_vec()))
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
    ) -> Result<
        pos_core::AdapterCallReservationOutcomeV1,
        pos_core::AdapterRecordingStoreErrorV1,
    > {
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

fn world_handle(owner_reference: Hash) -> WorldReplayHandleV1 {
    WorldReplayHandleV1::new(WorldReplayHandleInputV1 {
        owner_reference,
        timeline_id: TimelineId::new(),
        cut_id: 4,
        commit_receipt_digest: Hash::from_bytes([11; 32]),
        recording_receipt_digest: Hash::from_bytes([12; 32]),
        logical_head: 7,
        stitched_head_hash: Hash::from_bytes([13; 32]),
    })
    .expect("fixture World Replay handle should be structurally valid")
}

fn registry_with_adapter(
    provider: Box<dyn LocalAdapterProviderV1>,
) -> (
    PluginRegistry,
    pos_runtime::AdmittedCompositionV1,
    WorldReplayHandleV1,
) {
    registry_with_adapter_mode(provider, AdapterEffectModeV1::ReadOnly)
}

fn registry_with_adapter_mode(
    provider: Box<dyn LocalAdapterProviderV1>,
    effect_mode: AdapterEffectModeV1,
) -> (
    PluginRegistry,
    pos_runtime::AdmittedCompositionV1,
    WorldReplayHandleV1,
) {
    let plugin = LocalPlugin {
        id: PluginId::new(),
    };
    let owner = OwnerIdV1::from_static("local-adapter-test");
    let owner_reference = ArtifactRegistrationV1::owner_reference(&owner);
    let mut registry = PluginRegistry::new();
    registry
        .register_local(&plugin, vec!["weather.read".to_owned()], None, None)
        .expect("a local plugin should register without installed EPF1");
    let mut entry = adapter_entry(plugin.id());
    entry.effect_mode = effect_mode;
    registry
        .register_local_adapter(entry, provider)
        .expect("the adapter should bind to an available local plugin");
    let handle = world_handle(owner_reference);
    let admitted = registry
        .admit_local_manifest_registration(owner, 2)
        .expect("the registry should seal the complete local roster");
    (registry, admitted, handle)
}

#[test]
fn local_registry_records_exact_adapter_calls_in_a_closed_transcript() {
    let keys = Arc::new(Mutex::new(Vec::new()));
    let provider = EchoProvider {
        idempotency_keys: Arc::clone(&keys),
        completed_responses: Arc::new(Mutex::new(Vec::new())),
    };
    let (mut registry, admitted, handle) = registry_with_adapter(Box::new(provider));
    assert_eq!(admitted.adapter_admission().as_input().entries.len(), 1);
    let mut recorder = pos_store::memory::MemoryStore::new();

    let operation_id = Hash::from_bytes([21; 32]);
    let request = b"exact request".to_vec();
    let mut session = registry
        .begin_local_adapter_session(&admitted, handle, operation_id, &mut recorder)
        .expect("the sealed local admission should start a run");
    let response = session
        .invoke(
            admitted.adapter_admission().as_input().entries[0].plugin_id,
            "weather.client",
            "fixture.provider",
            "read-current",
            1,
            request.clone(),
        )
        .expect("the registered local provider should run");
    assert_eq!(response, b"tseuqer tcaxe");
    drop(session);
    let mut retry = registry
        .begin_local_adapter_session(&admitted, handle, operation_id, &mut recorder)
        .expect("the same still-open operation should resume");
    let retried_response = retry
        .invoke(
            admitted.adapter_admission().as_input().entries[0].plugin_id,
            "weather.client",
            "fixture.provider",
            "read-current",
            1,
            b"exact request".to_vec(),
        )
        .expect("a committed response should be reused on retry");
    assert_eq!(retried_response, response);
    let closed = retry.finish().expect("the successful run should close");
    let transcript = AdapterTranscriptV1::from_canonical_cbor(&closed.transcript_bytes())
        .expect("the closed transcript should have exact MAT1 bytes");
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
    let keys = keys
        .lock()
        .expect("idempotency key lock should be available");
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].owner_reference(), handle.as_input().owner_reference);
    assert_eq!(keys[0].run_operation_id(), operation_id);
    assert_eq!(keys[0].global_call_index(), 0);
    let closed_bytes = closed.transcript_bytes();
    assert_eq!(
        recorder
            .read_closed_adapter_recording_session(handle.as_input().owner_reference, operation_id)
            .expect("the closed transcript should remain readable")
            .as_deref(),
        Some(closed_bytes.as_slice())
    );
}

#[test]
fn local_adapter_session_emits_an_explicit_empty_transcript() {
    let (mut registry, admitted, handle) = registry_with_adapter(Box::new(RejectingProvider));
    let mut recorder = pos_store::memory::MemoryStore::new();
    let session = registry
        .begin_local_adapter_session(&admitted, handle, Hash::from_bytes([22; 32]), &mut recorder)
        .expect("the sealed local admission should start a run");
    let closed = session
        .finish()
        .expect("a successful empty session should close explicitly");
    assert!(closed.transcript().as_input().calls.is_empty());
}

#[test]
fn failed_local_adapter_session_cannot_produce_a_transcript() {
    let plugin_id = PluginId::new();
    let provider = RejectingProvider;
    let plugin = LocalPlugin { id: plugin_id };
    let owner = OwnerIdV1::from_static("local-adapter-failure-test");
    let owner_reference = ArtifactRegistrationV1::owner_reference(&owner);
    let mut recorder = pos_store::memory::MemoryStore::new();
    let mut registry = PluginRegistry::new();
    registry
        .register_local(&plugin, vec!["weather.read".to_owned()], None, None)
        .expect("a local plugin should register without installed EPF1");
    registry
        .register_local_adapter(adapter_entry(plugin_id), Box::new(provider))
        .expect("the adapter should bind to an available local plugin");
    let admitted = registry
        .admit_local_manifest_registration(owner, 2)
        .expect("the registry should seal the complete local roster");
    let mut session = registry
        .begin_local_adapter_session(
            &admitted,
            world_handle(owner_reference),
            Hash::from_bytes([23; 32]),
            &mut recorder,
        )
        .expect("the sealed local admission should start a run");
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
    session
        .abort()
        .expect("a provider failure can explicitly abort the recorder");
    assert_eq!(
        recorder
            .read_closed_adapter_recording_session(owner_reference, Hash::from_bytes([23; 32]))
            .expect("the aborted recorder should remain readable as unclosed"),
        None
    );
}

#[test]
fn externally_idempotent_provider_receives_exact_run_key_and_must_acknowledge_it() {
    let keys = Arc::new(Mutex::new(Vec::new()));
    let completed_responses = Arc::new(Mutex::new(Vec::new()));
    let (mut registry, admitted, handle) = registry_with_adapter_mode(
        Box::new(EchoProvider {
            idempotency_keys: Arc::clone(&keys),
            completed_responses: Arc::clone(&completed_responses),
        }),
        AdapterEffectModeV1::ExternallyIdempotent,
    );
    let owner_reference = handle.as_input().owner_reference;
    let operation_id = Hash::from_bytes([24; 32]);
    let mut recorder = pos_store::memory::MemoryStore::new();
    let mut session = registry
        .begin_local_adapter_session(&admitted, handle, operation_id, &mut recorder)
        .expect("the admitted provider guarantee should permit the session");
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
    session
        .finish()
        .expect("the acknowledged call should close");
    let keys = keys
        .lock()
        .expect("idempotency key lock should be available");
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].owner_reference(), owner_reference);
    assert_eq!(keys[0].run_operation_id(), operation_id);
    assert_eq!(keys[0].global_call_index(), 0);
    assert_eq!(
        completed_responses
            .lock()
            .expect("idempotent response lock should be available")
            .len(),
        1
    );

    let (mut registry, admitted, handle) = registry_with_adapter_mode(
        Box::new(UnacknowledgedProvider),
        AdapterEffectModeV1::ExternallyIdempotent,
    );
    let mut recorder = FailFirstCompletionStore {
        inner: pos_store::memory::MemoryStore::new(),
        fail_next_completion: false,
    };
    let mut session = registry
        .begin_local_adapter_session(
            &admitted,
            handle,
            Hash::from_bytes([25; 32]),
            &mut recorder,
        )
        .expect("the provider advertises the external guarantee");
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
    session
        .abort()
        .expect("the rejected acknowledgement can abort the pending session");
}

#[test]
fn externally_idempotent_registration_requires_a_provider_deduplication_guarantee() {
    let plugin = LocalPlugin {
        id: PluginId::new(),
    };
    let mut registry = PluginRegistry::new();
    registry
        .register_local(&plugin, vec!["weather.read".to_owned()], None, None)
        .expect("a local plugin should register");
    let mut entry = adapter_entry(plugin.id());
    entry.effect_mode = AdapterEffectModeV1::ExternallyIdempotent;
    assert_eq!(
        registry.register_local_adapter(entry, Box::new(RejectingProvider)),
        Err(LocalAdapterErrorV1::IdempotencyUnavailable)
    );
}

#[test]
fn externally_idempotent_retry_reuses_provider_output_after_completion_failure() {
    let keys = Arc::new(Mutex::new(Vec::new()));
    let completed_responses = Arc::new(Mutex::new(Vec::new()));
    let (mut registry, admitted, handle) = registry_with_adapter_mode(
        Box::new(EchoProvider {
            idempotency_keys: Arc::clone(&keys),
            completed_responses: Arc::clone(&completed_responses),
        }),
        AdapterEffectModeV1::ExternallyIdempotent,
    );
    let operation_id = Hash::from_bytes([26; 32]);
    let mut recorder = FailFirstCompletionStore {
        inner: pos_store::memory::MemoryStore::new(),
        fail_next_completion: true,
    };
    let mut session = registry
        .begin_local_adapter_session(&admitted, handle, operation_id, &mut recorder)
        .expect("the guaranteed provider should start");
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

    let mut retry = registry
        .begin_local_adapter_session(&admitted, handle, operation_id, &mut recorder)
        .expect("the open reservation should resume after completion failure");
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
    retry
        .finish()
        .expect("the deduplicated response should complete and close");
    assert!(recorder
        .read_closed_adapter_recording_session(handle.as_input().owner_reference, operation_id)
        .expect("the wrapper should delegate the closed-session read")
        .is_some());

    let keys = keys
        .lock()
        .expect("idempotency key lock should be available");
    assert_eq!(keys.len(), 2);
    assert_eq!(keys[0], keys[1]);
    assert_eq!(keys[0].owner_reference(), handle.as_input().owner_reference);
    assert_eq!(keys[0].run_operation_id(), operation_id);
    assert_eq!(keys[0].global_call_index(), 0);
    assert_eq!(
        completed_responses
            .lock()
            .expect("idempotent response lock should be available")
            .len(),
        1
    );
}
