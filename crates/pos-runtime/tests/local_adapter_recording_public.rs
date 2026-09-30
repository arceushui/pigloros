use std::sync::{Arc, Mutex};

use pos_core::{
    adapter_configuration_digest_v1, public_adapter_schema_digest_v1, AdapterAdmissionEntryV1,
    AdapterDataClassV1, AdapterEffectModeV1, AdapterInvocationV1, AdapterTranscriptV1,
    ArtifactRegistrationV1, Capability, Hash, OwnerIdV1, Plugin, PluginId, TimelineId,
    WorldReplayHandleInputV1, WorldReplayHandleV1,
};
use pos_runtime::{LocalAdapterErrorV1, LocalAdapterProviderV1, PluginRegistry};

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
    idempotency_keys: Arc<Mutex<Vec<Hash>>>,
}

impl LocalAdapterProviderV1 for EchoProvider {
    fn invoke(
        &mut self,
        invocation: &AdapterInvocationV1,
        idempotency_key: Hash,
    ) -> Result<Vec<u8>, LocalAdapterErrorV1> {
        self.idempotency_keys
            .lock()
            .expect("idempotency key lock should be available")
            .push(idempotency_key);
        Ok(invocation
            .as_input()
            .exact_request_payload
            .iter()
            .rev()
            .copied()
            .collect())
    }
}

struct RejectingProvider;

impl LocalAdapterProviderV1 for RejectingProvider {
    fn invoke(&mut self, _: &AdapterInvocationV1, _: Hash) -> Result<Vec<u8>, LocalAdapterErrorV1> {
        Err(LocalAdapterErrorV1::ProviderRejected)
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
    let plugin = LocalPlugin {
        id: PluginId::new(),
    };
    let owner = OwnerIdV1::from_static("local-adapter-test");
    let owner_reference = ArtifactRegistrationV1::owner_reference(&owner);
    let mut registry = PluginRegistry::new();
    registry
        .register_local(&plugin, vec!["weather.read".to_owned()], None, None)
        .expect("a local plugin should register without installed EPF1");
    registry
        .register_local_adapter(adapter_entry(plugin.id()), provider)
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
    };
    let (mut registry, admitted, handle) = registry_with_adapter(Box::new(provider));
    assert_eq!(admitted.adapter_admission().as_input().entries.len(), 1);

    let operation_id = Hash::from_bytes([21; 32]);
    let request = b"exact request".to_vec();
    let mut session = registry
        .begin_local_adapter_session(&admitted, handle, operation_id)
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
    let closed = session.finish().expect("the successful run should close");
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
    assert_ne!(
        keys.lock()
            .expect("idempotency key lock should be available")[0],
        Hash::zero()
    );

    let mut retry = registry
        .begin_local_adapter_session(&admitted, handle, operation_id)
        .expect("the same operation may be retried under its deterministic key");
    retry
        .invoke(
            admitted.adapter_admission().as_input().entries[0].plugin_id,
            "weather.client",
            "fixture.provider",
            "read-current",
            1,
            b"exact request".to_vec(),
        )
        .expect("the repeated call should reach the provider");
    retry.finish().expect("the retry should also close");
    let keys = keys
        .lock()
        .expect("idempotency key lock should be available");
    assert_eq!(keys.len(), 2);
    assert_eq!(keys[0], keys[1]);
}

#[test]
fn local_adapter_session_emits_an_explicit_empty_transcript() {
    let (mut registry, admitted, handle) = registry_with_adapter(Box::new(RejectingProvider));
    let session = registry
        .begin_local_adapter_session(&admitted, handle, Hash::from_bytes([22; 32]))
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
    assert!(matches!(
        session.finish(),
        Err(LocalAdapterErrorV1::SessionAborted)
    ));
}
