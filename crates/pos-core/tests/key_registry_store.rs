#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

use pos_core::{
    CanonicalBytes, CoreError, EntityId, Event, EventDraft, EventId, EventStore, Hash,
    KeyIdentityV1, KeyRegistrationV1, KeyRegistryStateV1, KeyRoleV1, Kind, PublicKey,
    SchemaVersion, Seq, SeqRange, Timeline, TimelineId, TimelineMeta, WallTime,
};

struct RegistryStore {
    registry: Option<KeyRegistryStateV1>,
    timeline: Option<Timeline>,
    committed: bool,
}

impl RegistryStore {
    fn new(registry: Option<KeyRegistryStateV1>) -> Self {
        Self {
            registry,
            timeline: Some(Timeline::new(TimelineMeta::root("registry-test"))),
            committed: false,
        }
    }
}

impl EventStore for RegistryStore {
    fn create_timeline(&mut self, name: &str) -> Result<Timeline, CoreError> {
        Ok(Timeline::new(TimelineMeta::root(name)))
    }

    fn append(
        &mut self,
        _timeline: TimelineId,
        _drafts: &[EventDraft],
    ) -> Result<Vec<Event>, CoreError> {
        Ok(Vec::new())
    }

    fn read(&self, _timeline: TimelineId, _range: SeqRange) -> Result<Vec<Event>, CoreError> {
        Ok(Vec::new())
    }

    fn fork(
        &mut self,
        _parent: TimelineId,
        _at_seq: Seq,
        name: &str,
    ) -> Result<Timeline, CoreError> {
        Ok(Timeline::new(TimelineMeta::root(name)))
    }

    fn list_timelines(&self) -> Result<Vec<Timeline>, CoreError> {
        Ok(self.timeline.clone().into_iter().collect())
    }

    fn get_timeline(&self, id: TimelineId) -> Result<Option<Timeline>, CoreError> {
        Ok(self.timeline.clone().filter(|timeline| timeline.id() == id))
    }

    fn load_key_registry(&self) -> Result<Option<KeyRegistryStateV1>, CoreError> {
        Ok(self.registry.clone())
    }

    fn save_key_registry(&mut self, registry: &KeyRegistryStateV1) -> Result<(), CoreError> {
        self.registry = Some(registry.clone());
        Ok(())
    }

    fn append_committed(
        &mut self,
        _timeline: TimelineId,
        _events: &[Event],
    ) -> Result<(), CoreError> {
        self.committed = true;
        Ok(())
    }
}

fn registered_state() -> (KeyRegistryStateV1, KeyIdentityV1, Hash) {
    let identity = KeyIdentityV1::new(KeyRoleV1::TimelineIntegritySigning, 1);
    let material_digest = Hash::from_bytes([3; 32]);
    let mut registry = KeyRegistryStateV1::new();
    registry
        .register_key(KeyRegistrationV1::new(
            identity,
            material_digest,
            Some(PublicKey::from_bytes([4; 32])),
        ))
        .expect("test registry should accept its first key");
    (registry, identity, material_digest)
}

fn event_at(seq: Seq) -> Event {
    Event {
        id: EventId::new(),
        entity: EntityId::new(),
        event_type: Kind::new("registry.test"),
        payload: CanonicalBytes::from_static(b"payload"),
        wall_time: WallTime::from_micros(1),
        seq,
        causation_id: None,
        correlation_id: None,
        schema_version: SchemaVersion::V1,
        signature: None,
        signature_identity: None,
        payload_hash: Hash::from_bytes([0; 32]),
    }
}

#[test]
fn event_store_key_registry_defaults_are_closed_and_exercised() -> Result<(), CoreError> {
    let mut store = RegistryStore::new(None);
    assert!(store.load_key_registry()?.is_none());
    assert!(matches!(
        store.save_key_registry(&KeyRegistryStateV1::new()),
        Err(CoreError::Storage(_))
    ));

    let mut callback = |_registry: &KeyRegistryStateV1, _seq: Seq| {
        Err::<Event, _>(CoreError::Storage("callback must not run".to_owned()))
    };
    assert!(matches!(
        store.append_signed_authorized(
            TimelineId::new(),
            &KeyRegistryStateV1::new(),
            &mut callback,
        ),
        Err(CoreError::Storage(_))
    ));
    assert!(matches!(
        store.destroy_key_registry(pos_core::KeyDestructionRequestV1::new(
            KeyIdentityV1::new(KeyRoleV1::TimelineIntegritySigning, 1),
            Hash::from_bytes([1; 32]),
            Hash::from_bytes([2; 32]),
        )),
        Err(CoreError::Storage(_))
    ));
    Ok(())
}

#[test]
fn event_store_key_registry_defaults_cover_authorized_paths() -> Result<(), CoreError> {
    let (registry, identity, material_digest) = registered_state();
    let mut store = RegistryStore::new(Some(registry.clone()));
    let timeline = store
        .timeline
        .as_ref()
        .map(Timeline::id)
        .ok_or_else(|| CoreError::Storage("test timeline missing".to_owned()))?;

    let mut callback = |_registry: &KeyRegistryStateV1, seq: Seq| Ok(event_at(seq));
    store.append_signed_authorized(timeline, &registry, &mut callback)?;
    assert!(store.committed);

    let mut mismatch_callback = |_registry: &KeyRegistryStateV1, _seq: Seq| {
        Err::<Event, _>(CoreError::Storage("callback must not run".to_owned()))
    };
    assert!(matches!(
        store.append_signed_authorized(
            timeline,
            &KeyRegistryStateV1::new(),
            &mut mismatch_callback,
        ),
        Err(CoreError::Storage(_))
    ));

    let mut missing_timeline = RegistryStore::new(Some(registry.clone()));
    missing_timeline.timeline = None;
    let mut missing_callback = |_registry: &KeyRegistryStateV1, _seq: Seq| {
        Err::<Event, _>(CoreError::Storage("callback must not run".to_owned()))
    };
    assert!(matches!(
        missing_timeline.append_signed_authorized(timeline, &registry, &mut missing_callback),
        Err(CoreError::TimelineNotFound(_))
    ));

    let mut callback_failure = |_registry: &KeyRegistryStateV1, _seq: Seq| {
        Err::<Event, _>(CoreError::Storage("callback failed".to_owned()))
    };
    assert!(matches!(
        store.append_signed_authorized(timeline, &registry, &mut callback_failure),
        Err(CoreError::Storage(_))
    ));

    let request = pos_core::KeyDestructionRequestV1::new(
        identity,
        material_digest,
        Hash::from_bytes([2; 32]),
    );
    let (_, destroyed) = store.destroy_key_registry(request)?;
    assert!(destroyed.key_record(identity).is_some());
    Ok(())
}
