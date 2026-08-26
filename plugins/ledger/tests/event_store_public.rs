use std::sync::{Arc, Mutex};

use ed25519_dalek::SigningKey;
use pos_core::{
    Event, EventDraft, EventStore, Hash, KeyDestructionRequestV1, KeyIdentityV1, KeyRegistrationV1,
    KeyRegistryStateV1, KeyRoleV1, Seq, SeqRange, Timeline, TimelineId,
};
use pos_crypto::{chain::Blake3Hasher, key_roles::key_material_digest};
use pos_plugin_ledger::EventLedgerStore;
use pos_store::memory::MemoryStore;

struct CompleteFailureStore {
    inner: MemoryStore,
}

impl EventStore for CompleteFailureStore {
    fn create_timeline(&mut self, name: &str) -> Result<Timeline, pos_core::CoreError> {
        self.inner.create_timeline(name)
    }

    fn append(
        &mut self,
        timeline: TimelineId,
        drafts: &[EventDraft],
    ) -> Result<Vec<Event>, pos_core::CoreError> {
        self.inner.append(timeline, drafts)
    }

    fn read(
        &self,
        timeline: TimelineId,
        range: SeqRange,
    ) -> Result<Vec<Event>, pos_core::CoreError> {
        self.inner.read(timeline, range)
    }

    fn fork(
        &mut self,
        parent: TimelineId,
        at_seq: Seq,
        name: &str,
    ) -> Result<Timeline, pos_core::CoreError> {
        self.inner.fork(parent, at_seq, name)
    }

    fn list_timelines(&self) -> Result<Vec<Timeline>, pos_core::CoreError> {
        self.inner.list_timelines()
    }

    fn get_timeline(&self, id: TimelineId) -> Result<Option<Timeline>, pos_core::CoreError> {
        self.inner.get_timeline(id)
    }

    fn load_key_registry(&self) -> Result<Option<KeyRegistryStateV1>, pos_core::CoreError> {
        self.inner.load_key_registry()
    }

    fn save_key_registry(
        &mut self,
        registry: &KeyRegistryStateV1,
    ) -> Result<(), pos_core::CoreError> {
        self.inner.save_key_registry(registry)
    }

    fn complete_key_registry_destruction(
        &mut self,
        _request: KeyDestructionRequestV1,
        _deletion_receipt: Hash,
    ) -> Result<(pos_core::KeyDestructionOutcomeV1, KeyRegistryStateV1), pos_core::CoreError> {
        Err(pos_core::CoreError::Storage(
            "final destruction commit failed".to_owned(),
        ))
    }
}

#[test]
fn destruction_propagates_a_final_commit_failure() -> Result<(), Box<dyn std::error::Error>> {
    let signing_key = SigningKey::from_bytes(&[91; 32]);
    let identity = KeyIdentityV1::new("ledger-owner", KeyRoleV1::TimelineIntegritySigning, 1);
    let material_digest = key_material_digest(&signing_key.to_bytes());
    let mut registry = KeyRegistryStateV1::new();
    registry.register_key(KeyRegistrationV1::new(
        identity,
        material_digest,
        Some(pos_crypto::signing::public_key_from_verifying_key(
            &signing_key.verifying_key(),
        )),
    ))?;

    let mut inner = MemoryStore::new();
    let timeline = inner.create_timeline("ledger")?;
    inner.save_key_registry(&registry)?;
    let mut store = EventLedgerStore::new(
        Box::new(CompleteFailureStore { inner }),
        timeline.id(),
        pos_core::EntityId::new(),
        signing_key,
        Arc::new(Mutex::new(registry)),
        identity,
        Box::new(Blake3Hasher),
    )?;

    let request =
        KeyDestructionRequestV1::new(identity, material_digest, Hash::from_bytes([92; 32]));
    let error = match store.destroy_signing_key(request) {
        Ok(outcome) => return Err(format!("unexpected destruction outcome: {outcome:?}").into()),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("final destruction commit failed"));
    Ok(())
}
