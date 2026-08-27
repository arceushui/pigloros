#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

use pos_core::{
    deletion_receipt, CanonicalBytes, CoreError, EntityId, Event, EventDraft, EventId, EventStore,
    Hash, KeyDestructionOutcomeV1, KeyDestructionRequestV1, KeyIdentityV1, KeyRegistrationV1,
    KeyRegistryEncryptionPortV1, KeyRegistryPortV1, KeyRegistrySigningPortV1, KeyRegistryStateV1,
    KeyRoleV1, Kind, OwnerIdV1, PublicKey, SchemaVersion, Seq, SeqRange, Signature, Timeline,
    TimelineId, TimelineMeta, WallTime,
};
use std::cell::Cell;

#[test]
fn source_controlled_owner_identifier_preserves_literal_bytes() {
    assert_eq!(
        OwnerIdV1::from_static("mutation-owner").as_str(),
        "mutation-owner"
    );
}

struct RegistryStore {
    registry: Option<KeyRegistryStateV1>,
    timeline: Option<Timeline>,
    committed: bool,
    fail_save: bool,
    fail_delete: bool,
    deleted: Option<TimelineId>,
}

struct MinimalStore {
    timeline: Timeline,
}

impl MinimalStore {
    fn new() -> Self {
        Self {
            timeline: Timeline::new(TimelineMeta::root("minimal-test")),
        }
    }
}

impl EventStore for MinimalStore {
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
        Ok(vec![self.timeline.clone()])
    }

    fn get_timeline(&self, id: TimelineId) -> Result<Option<Timeline>, CoreError> {
        Ok((self.timeline.id() == id).then(|| self.timeline.clone()))
    }
}

impl RegistryStore {
    fn new(registry: Option<KeyRegistryStateV1>) -> Self {
        Self {
            registry,
            timeline: Some(Timeline::new(TimelineMeta::root("registry-test"))),
            committed: false,
            fail_save: false,
            fail_delete: false,
            deleted: None,
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
        if self.fail_save {
            return Err(CoreError::Storage("registry save failed".to_owned()));
        }
        self.registry = Some(registry.clone());
        Ok(())
    }

    fn delete_timeline(&mut self, id: TimelineId) -> Result<(), CoreError> {
        if self.fail_delete {
            return Err(CoreError::Storage("timeline delete failed".to_owned()));
        }
        self.deleted = Some(id);
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

fn registered_state(
) -> Result<(KeyRegistryStateV1, KeyIdentityV1, Hash), Box<dyn std::error::Error>> {
    let identity = KeyIdentityV1::new("test-owner", KeyRoleV1::TimelineIntegritySigning, 1);
    let material_digest = Hash::from_bytes([3; 32]);
    let mut registry = KeyRegistryStateV1::new();
    registry.register_key(KeyRegistrationV1::new(
        identity,
        material_digest,
        Some(PublicKey::from_bytes([4; 32])),
    ))?;
    Ok((registry, identity, material_digest))
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn changed_first_bytes(
    registry: &KeyRegistryStateV1,
    from: [u8; 32],
    to: [u8; 32],
) -> Result<KeyRegistryStateV1, Box<dyn std::error::Error>> {
    fn replace_first_bytes(
        value: &mut ciborium::value::Value,
        from: &[u8; 32],
        to: [u8; 32],
    ) -> bool {
        match value {
            ciborium::value::Value::Bytes(bytes) if bytes.as_slice() == from => {
                *value = ciborium::value::Value::Bytes(to.to_vec());
                true
            }
            ciborium::value::Value::Array(values) => values
                .iter_mut()
                .any(|value| replace_first_bytes(value, from, to)),
            ciborium::value::Value::Map(entries) => entries.iter_mut().any(|(key, value)| {
                replace_first_bytes(key, from, to) || replace_first_bytes(value, from, to)
            }),
            ciborium::value::Value::Tag(_, value) => replace_first_bytes(value, from, to),
            _ => false,
        }
    }
    let mut bytes = Vec::new();
    ciborium::into_writer(registry, &mut bytes)?;
    let mut value: ciborium::value::Value = ciborium::from_reader(bytes.as_slice())?;
    assert!(replace_first_bytes(&mut value, &from, to));
    let mut changed_bytes = Vec::new();
    ciborium::into_writer(&value, &mut changed_bytes)?;
    Ok(ciborium::from_reader(changed_bytes.as_slice())?)
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn changed_tombstone_digest(
    registry: &KeyRegistryStateV1,
) -> Result<KeyRegistryStateV1, Box<dyn std::error::Error>> {
    changed_first_bytes(registry, [3; 32], [9; 32])
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn changed_public_key(
    registry: &KeyRegistryStateV1,
) -> Result<KeyRegistryStateV1, Box<dyn std::error::Error>> {
    changed_first_bytes(registry, [4; 32], [9; 32])
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn replace_first_integer(value: &mut ciborium::value::Value, from: u64, to: u64) -> bool {
    match value {
        ciborium::value::Value::Integer(integer) if u64::try_from(*integer).ok() == Some(from) => {
            *integer = to.into();
            true
        }
        ciborium::value::Value::Array(values) => values
            .iter_mut()
            .any(|value| replace_first_integer(value, from, to)),
        ciborium::value::Value::Map(entries) => entries.iter_mut().any(|(key, value)| {
            replace_first_integer(key, from, to) || replace_first_integer(value, from, to)
        }),
        ciborium::value::Value::Tag(_, value) => replace_first_integer(value, from, to),
        _ => false,
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn edit_state<F>(
    state: &KeyRegistryStateV1,
    edit: F,
) -> Result<KeyRegistryStateV1, Box<dyn std::error::Error>>
where
    F: FnOnce(&mut ciborium::value::Value) -> bool,
{
    let mut encoded = Vec::new();
    ciborium::into_writer(state, &mut encoded)?;
    let mut value: ciborium::value::Value = ciborium::from_reader(encoded.as_slice())?;
    assert!(edit(&mut value));
    let mut changed = Vec::new();
    ciborium::into_writer(&value, &mut changed)?;
    Ok(ciborium::from_reader(changed.as_slice())?)
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn clear_top_level_map(value: &mut ciborium::value::Value, field: &str) -> bool {
    let ciborium::value::Value::Map(entries) = value else {
        return false;
    };
    let Some((_, field_value)) = entries
        .iter_mut()
        .find(|(key, _)| matches!(key, ciborium::value::Value::Text(name) if name == field))
    else {
        return false;
    };
    let ciborium::value::Value::Map(field_entries) = field_value else {
        return false;
    };
    field_entries.clear();
    true
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

fn destroy_registry(
    registry: &mut KeyRegistryStateV1,
    request: KeyDestructionRequestV1,
) -> Result<KeyDestructionOutcomeV1, pos_core::KeyRegistryErrorV1> {
    registry.begin_key_destruction(request)?;
    registry.complete_key_destruction(request, deletion_receipt(&request))
}

fn destroy_store<S: EventStore>(
    store: &mut S,
    request: KeyDestructionRequestV1,
) -> Result<(KeyDestructionOutcomeV1, KeyRegistryStateV1), CoreError> {
    store.begin_key_registry_destruction(request)?;
    store.complete_key_registry_destruction(request, deletion_receipt(&request))
}

#[test]
fn event_store_key_registry_defaults_are_closed_and_exercised() -> Result<(), CoreError> {
    let mut store = MinimalStore::new();
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
        store.begin_key_registry_destruction(pos_core::KeyDestructionRequestV1::new(
            KeyIdentityV1::new("test-owner", KeyRoleV1::TimelineIntegritySigning, 1),
            Hash::from_bytes([1; 32]),
            Hash::from_bytes([2; 32]),
        )),
        Err(CoreError::Storage(_))
    ));
    let request = pos_core::KeyDestructionRequestV1::new(
        KeyIdentityV1::new("test-owner", KeyRoleV1::TimelineIntegritySigning, 1),
        Hash::from_bytes([1; 32]),
        Hash::from_bytes([2; 32]),
    );
    assert!(matches!(
        store.complete_key_registry_destruction(request, deletion_receipt(&request)),
        Err(CoreError::Storage(_))
    ));
    Ok(())
}

#[test]
fn event_store_key_registry_defaults_cover_authorized_paths(
) -> Result<(), Box<dyn std::error::Error>> {
    let (registry, identity, material_digest) = registered_state()?;
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

    let invalid_completion = KeyDestructionRequestV1::new(
        identity,
        Hash::from_bytes([99; 32]),
        Hash::from_bytes([2; 32]),
    );
    assert!(matches!(
        store.complete_key_registry_destruction(
            invalid_completion,
            deletion_receipt(&invalid_completion),
        ),
        Err(CoreError::Storage(_))
    ));

    let request = pos_core::KeyDestructionRequestV1::new(
        identity,
        material_digest,
        Hash::from_bytes([2; 32]),
    );
    let (_, destroyed) = destroy_store(&mut store, request)?;
    assert!(destroyed.key_record(identity).is_some());
    Ok(())
}

#[test]
fn owner_identifiers_round_trip_and_reject_invalid_wire_values(
) -> Result<(), Box<dyn std::error::Error>> {
    let owner = OwnerIdV1::new("用户/ledger")?;
    let encoded = serde_json::to_string(&owner)?;
    assert_eq!(serde_json::from_str::<OwnerIdV1>(&encoded)?, owner);
    assert!(serde_json::from_str::<OwnerIdV1>(r#""""#).is_err());
    let oversized = serde_json::to_string(&"x".repeat(129))?;
    assert!(serde_json::from_str::<OwnerIdV1>(&oversized).is_err());
    Ok(())
}

#[test]
fn event_signature_contract_rejects_incomplete_and_ineligible_bindings() {
    let mut unsigned = event_at(Seq::from_u64(1));
    assert!(pos_core::store::validate_event_signature(&unsigned).is_ok());

    unsigned.signature = Some(Signature::from_bytes([1; 64]));
    assert!(pos_core::store::validate_event_signature(&unsigned).is_err());

    let mut identity_only = event_at(Seq::from_u64(1));
    identity_only.signature_identity = Some(KeyIdentityV1::new(
        "test-owner",
        KeyRoleV1::TimelineIntegritySigning,
        1,
    ));
    assert!(pos_core::store::validate_event_signature(&identity_only).is_err());

    let mut wrong_role = identity_only;
    wrong_role.signature = Some(Signature::from_bytes([1; 64]));
    wrong_role.signature_identity = Some(KeyIdentityV1::new(
        "test-owner",
        KeyRoleV1::SubjectDataEncryption,
        1,
    ));
    assert!(pos_core::store::validate_event_signature(&wrong_role).is_err());

    let mut zero_epoch = wrong_role;
    zero_epoch.signature_identity = Some(KeyIdentityV1::new(
        "test-owner",
        KeyRoleV1::TimelineIntegritySigning,
        0,
    ));
    assert!(pos_core::store::validate_event_signature(&zero_epoch).is_err());

    let mut valid = event_at(Seq::from_u64(1));
    valid.signature = Some(Signature::from_bytes([1; 64]));
    valid.signature_identity = Some(KeyIdentityV1::new(
        "test-owner",
        KeyRoleV1::TimelineIntegritySigning,
        1,
    ));
    assert!(pos_core::store::validate_event_signature(&valid).is_ok());
}

#[test]
fn generic_import_rejects_signed_events_before_stripping_identity() {
    let mut event = event_at(Seq::from_u64(1));
    event.signature = Some(Signature::from_bytes([1; 64]));
    event.signature_identity = Some(KeyIdentityV1::new(
        "test-owner",
        KeyRoleV1::TimelineIntegritySigning,
        1,
    ));
    let export = pos_core::store::TimelineExport {
        timeline: Timeline::new(TimelineMeta::root("signed-import")),
        events: vec![event],
        parent_fork_hash: None,
    };
    assert!(matches!(
        pos_core::store::import_timeline(&mut MinimalStore::new(), export),
        Err(CoreError::Storage(message))
            if message.contains("generic import of signed events is disabled")
    ));
}

#[test]
fn event_store_initialization_defaults_cover_each_state_transition(
) -> Result<(), Box<dyn std::error::Error>> {
    let empty = KeyRegistryStateV1::new();
    let (registry, _, _) = registered_state()?;

    let mut existing = RegistryStore::new(None);
    existing.timeline = Some(Timeline::new(TimelineMeta::root("ledger")));
    let existing_id = existing
        .timeline
        .as_ref()
        .map(Timeline::id)
        .ok_or("existing timeline missing")?;
    let reused = existing.initialize_timeline_with_key_registry("ledger", &empty)?;
    assert_eq!(reused.meta.name.as_deref(), Some("ledger"));
    assert_eq!(reused.id(), existing_id);
    assert_eq!(existing.registry, Some(empty.clone()));

    let mut existing_save_failure = RegistryStore::new(None);
    existing_save_failure.timeline = Some(Timeline::new(TimelineMeta::root("ledger")));
    existing_save_failure.fail_save = true;
    let save_error = existing_save_failure
        .initialize_timeline_with_key_registry("ledger", &empty)
        .err()
        .ok_or("existing-timeline registry save failure was accepted")?;
    assert!(save_error.to_string().contains("registry save failed"));

    let mut persisted = RegistryStore::new(Some(registry.clone()));
    persisted.timeline = None;
    let created_with_registry =
        persisted.initialize_timeline_with_key_registry("ledger", &registry)?;
    assert_eq!(created_with_registry.meta.name.as_deref(), Some("ledger"));

    let mut fresh = RegistryStore::new(None);
    fresh.timeline = None;
    let created_with_new_registry =
        fresh.initialize_timeline_with_key_registry("ledger", &empty)?;
    assert_eq!(
        created_with_new_registry.meta.name.as_deref(),
        Some("ledger")
    );
    assert_eq!(fresh.registry, Some(empty.clone()));

    let mut mismatch = RegistryStore::new(Some(registry));
    let mismatch_error = mismatch
        .initialize_timeline_with_key_registry("ledger", &empty)
        .err()
        .ok_or("registry mismatch was accepted")?;
    assert!(mismatch_error
        .to_string()
        .contains("changed during ledger initialization"));

    let mut rollback = RegistryStore::new(None);
    rollback.timeline = None;
    rollback.fail_save = true;
    let save_error = rollback
        .initialize_timeline_with_key_registry("ledger", &empty)
        .err()
        .ok_or("registry save failure was accepted")?;
    assert!(save_error.to_string().contains("registry save failed"));
    assert!(rollback.deleted.is_some());

    let mut rollback_failure = RegistryStore::new(None);
    rollback_failure.timeline = None;
    rollback_failure.fail_save = true;
    rollback_failure.fail_delete = true;
    let rollback_error = rollback_failure
        .initialize_timeline_with_key_registry("ledger", &empty)
        .err()
        .ok_or("rollback failure was accepted")?;
    assert!(rollback_error.to_string().contains("rollback also failed"));
    Ok(())
}

#[test]
fn replacement_rejects_tombstone_rewrite_at_public_boundary(
) -> Result<(), Box<dyn std::error::Error>> {
    let (registry, identity, material_digest) = registered_state()?;
    let mut store = RegistryStore::new(Some(registry));
    let (_, destroyed) = destroy_store(
        &mut store,
        pos_core::KeyDestructionRequestV1::new(
            identity,
            material_digest,
            Hash::from_bytes([2; 32]),
        ),
    )?;
    assert_eq!(destroyed.validate_replacement(&destroyed), Ok(()));
    let changed_tombstone = changed_tombstone_digest(&destroyed)?;
    assert_eq!(
        destroyed.validate_replacement(&changed_tombstone),
        Err(pos_core::KeyRegistryErrorV1::InvalidState)
    );
    Ok(())
}

#[test]
fn replacement_rejects_a_new_already_destroyed_identity() -> Result<(), Box<dyn std::error::Error>>
{
    let (previous, identity, _) = registered_state()?;
    let next_identity = KeyIdentityV1::new(identity.owner_id, identity.role, identity.epoch + 1);
    let mut next = previous.clone();
    let next_material = Hash::from_bytes([71; 32]);
    next.register_key(KeyRegistrationV1::new(
        next_identity,
        next_material,
        Some(PublicKey::from_bytes([72; 32])),
    ))?;
    destroy_registry(
        &mut next,
        KeyDestructionRequestV1::new(next_identity, next_material, Hash::from_bytes([73; 32])),
    )?;

    assert_eq!(
        previous.validate_replacement(&next),
        Err(pos_core::KeyRegistryErrorV1::InvalidState)
    );
    Ok(())
}

#[test]
fn public_registry_validation_rejects_corrupt_indexes() -> Result<(), Box<dyn std::error::Error>> {
    let (registry, _, _) = registered_state()?;

    let mismatched_record = edit_state(&registry, |value| replace_first_integer(value, 1, 2))?;
    assert_eq!(
        mismatched_record.validate(),
        Err(pos_core::KeyRegistryErrorV1::InvalidState)
    );

    let missing_highest = edit_state(&registry, |value| {
        clear_top_level_map(value, "highest_epoch")
    })?;
    assert_eq!(
        missing_highest.validate(),
        Err(pos_core::KeyRegistryErrorV1::InvalidState)
    );

    let missing_active = edit_state(&registry, |value| clear_top_level_map(value, "active"))?;
    assert_eq!(
        missing_active.validate(),
        Err(pos_core::KeyRegistryErrorV1::InvalidState)
    );
    Ok(())
}

#[test]
fn public_registry_validation_rejects_duplicate_and_pending_material(
) -> Result<(), Box<dyn std::error::Error>> {
    let (registry, identity, material_digest) = registered_state()?;
    let second_identity = KeyIdentityV1::new("test-owner", KeyRoleV1::PluginReleaseSigning, 1);
    let mut two_keys = registry.clone();
    two_keys.register_key(KeyRegistrationV1::new(
        second_identity,
        Hash::from_bytes([5; 32]),
        Some(PublicKey::from_bytes([6; 32])),
    ))?;
    let duplicate_material = changed_first_bytes(&two_keys, [5; 32], [3; 32])?;
    assert_eq!(
        duplicate_material.validate(),
        Err(pos_core::KeyRegistryErrorV1::InvalidState)
    );

    let request =
        KeyDestructionRequestV1::new(identity, material_digest, Hash::from_bytes([7; 32]));
    let mut pending = registry;
    pending.begin_key_destruction(request)?;
    let mismatched_pending = changed_first_bytes(&pending, [3; 32], [9; 32])?;
    assert_eq!(
        mismatched_pending.validate(),
        Err(pos_core::KeyRegistryErrorV1::InvalidState)
    );
    Ok(())
}

#[test]
fn public_registry_traits_and_role_boundaries_are_exercised(
) -> Result<(), Box<dyn std::error::Error>> {
    let role_cases = [
        (0, KeyRoleV1::SubjectDataEncryption, false, true),
        (1, KeyRoleV1::SubjectAttributionSigning, true, false),
        (2, KeyRoleV1::TimelineIntegritySigning, true, false),
        (3, KeyRoleV1::PluginReleaseSigning, true, false),
        (4, KeyRoleV1::ExportRecipientEncryption, false, true),
    ];
    for (code, role, signing, encryption) in role_cases {
        assert_eq!(role.code(), code);
        assert_eq!(KeyRoleV1::from_code(code), Ok(role));
        assert_eq!(role.is_signing(), signing);
        assert_eq!(role.is_encryption(), encryption);
    }
    assert_eq!(
        KeyRoleV1::from_code(5),
        Err(pos_core::KeyRegistryErrorV1::InvalidRoleCode)
    );

    let signing_identity = KeyIdentityV1::new("test-owner", KeyRoleV1::TimelineIntegritySigning, 1);
    let signing_material = Hash::from_bytes([21; 32]);
    let signing_public_key = PublicKey::from_bytes([22; 32]);
    let encryption_identity = KeyIdentityV1::new("test-owner", KeyRoleV1::SubjectDataEncryption, 1);
    let encryption_material = Hash::from_bytes([23; 32]);
    let mut registry = KeyRegistryStateV1::new();

    assert_eq!(
        KeyRegistryPortV1::register_key(
            &mut registry,
            KeyRegistrationV1::new(signing_identity, signing_material, Some(signing_public_key),),
        )?,
        pos_core::KeyRegistrationOutcomeV1::Registered
    );
    assert_eq!(
        KeyRegistryPortV1::register_key(
            &mut registry,
            KeyRegistrationV1::new(encryption_identity, encryption_material, None,),
        )?,
        pos_core::KeyRegistrationOutcomeV1::Registered
    );
    assert_eq!(
        KeyRegistryPortV1::active_key(&registry, &signing_identity.owner_id, signing_identity.role)
            .map(|record| record.identity),
        Some(signing_identity)
    );
    assert_eq!(
        KeyRegistryPortV1::key_record(&registry, signing_identity)
            .ok_or("missing signing record")?
            .identity,
        signing_identity
    );

    assert_eq!(
        KeyRegistrySigningPortV1::with_signing_authorization(
            &mut registry,
            signing_identity,
            signing_material,
            signing_public_key,
            || "signed",
        )?,
        "signed"
    );
    assert_eq!(
        KeyRegistryEncryptionPortV1::with_encryption_authorization(
            &mut registry,
            encryption_identity,
            encryption_material,
            || "encrypted",
        )?,
        "encrypted"
    );

    let destruction_request = pos_core::KeyDestructionRequestV1::new(
        signing_identity,
        signing_material,
        Hash::from_bytes([24; 32]),
    );
    let first = destroy_registry(&mut registry, destruction_request)?;
    let second = destroy_registry(&mut registry, destruction_request)?;
    let first_tombstone = match first {
        KeyDestructionOutcomeV1::Destroyed(tombstone) => tombstone,
        KeyDestructionOutcomeV1::AlreadyDestroyed(tombstone) => {
            return Err(format!("unexpected first destruction: {tombstone:?}").into());
        }
    };
    assert_eq!(first.tombstone(), first_tombstone);
    assert_eq!(
        second,
        KeyDestructionOutcomeV1::AlreadyDestroyed(first_tombstone)
    );
    assert_eq!(second.tombstone(), first_tombstone);
    assert_eq!(
        KeyRegistryPortV1::tombstone(&registry, signing_identity),
        Some(first_tombstone)
    );
    Ok(())
}

#[test]
fn public_registry_covers_destruction_and_replacement_guards(
) -> Result<(), Box<dyn std::error::Error>> {
    let (live, _, _) = registered_state()?;
    let changed_material = changed_tombstone_digest(&live)?;
    assert_eq!(
        live.validate_replacement(&changed_material),
        Err(pos_core::KeyRegistryErrorV1::InvalidState)
    );
    let changed_public_key = changed_public_key(&live)?;
    assert_eq!(
        live.validate_replacement(&changed_public_key),
        Err(pos_core::KeyRegistryErrorV1::InvalidState)
    );

    let signing_identity = KeyIdentityV1::new("test-owner", KeyRoleV1::TimelineIntegritySigning, 1);
    let signing_material = Hash::from_bytes([71; 32]);
    let signing_public_key = PublicKey::from_bytes([72; 32]);
    let signing_request = KeyDestructionRequestV1::new(
        signing_identity,
        signing_material,
        Hash::from_bytes([73; 32]),
    );
    let mut signing_registry = KeyRegistryStateV1::new();
    signing_registry.register_key(KeyRegistrationV1::new(
        signing_identity,
        signing_material,
        Some(signing_public_key),
    ))?;
    destroy_registry(&mut signing_registry, signing_request)?;
    let signing_callback_called = Cell::new(false);
    assert_eq!(
        signing_registry.with_signing_authorization(
            signing_identity,
            signing_material,
            signing_public_key,
            || {
                signing_callback_called.set(true);
                "not called"
            },
        ),
        Err(pos_core::KeyRegistryErrorV1::Destroyed)
    );
    assert!(!signing_callback_called.get());

    let encryption_identity = KeyIdentityV1::new("test-owner", KeyRoleV1::SubjectDataEncryption, 1);
    let encryption_material = Hash::from_bytes([74; 32]);
    let encryption_request = KeyDestructionRequestV1::new(
        encryption_identity,
        encryption_material,
        Hash::from_bytes([75; 32]),
    );
    let mut encryption_registry = KeyRegistryStateV1::new();
    encryption_registry.register_key(KeyRegistrationV1::new(
        encryption_identity,
        encryption_material,
        None,
    ))?;
    destroy_registry(&mut encryption_registry, encryption_request)?;
    let encryption_callback_called = Cell::new(false);
    assert_eq!(
        encryption_registry.with_encryption_authorization(
            encryption_identity,
            encryption_material,
            || {
                encryption_callback_called.set(true);
                "not called"
            },
        ),
        Err(pos_core::KeyRegistryErrorV1::Destroyed)
    );
    assert!(!encryption_callback_called.get());
    assert_eq!(
        encryption_registry.register_key(KeyRegistrationV1::new(
            KeyIdentityV1::new("test-owner", KeyRoleV1::ExportRecipientEncryption, 1),
            encryption_material,
            None,
        )),
        Err(pos_core::KeyRegistryErrorV1::MaterialReuse)
    );

    Ok(())
}

#[test]
fn public_registry_registration_errors_are_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    let signing_identity = KeyIdentityV1::new("test-owner", KeyRoleV1::TimelineIntegritySigning, 1);
    let signing_material = Hash::from_bytes([41; 32]);
    let signing_public_key = PublicKey::from_bytes([42; 32]);
    let encryption_identity = KeyIdentityV1::new("test-owner", KeyRoleV1::SubjectDataEncryption, 1);
    let encryption_material = Hash::from_bytes([43; 32]);
    let mut registry = KeyRegistryStateV1::new();

    assert_eq!(
        registry.register_key(KeyRegistrationV1::new(
            KeyIdentityV1::new("test-owner", KeyRoleV1::TimelineIntegritySigning, 0),
            signing_material,
            Some(signing_public_key),
        )),
        Err(pos_core::KeyRegistryErrorV1::InvalidEpoch)
    );
    assert_eq!(
        registry.register_key(KeyRegistrationV1::new(
            signing_identity,
            signing_material,
            None,
        )),
        Err(pos_core::KeyRegistryErrorV1::MissingPublicVerificationKey)
    );
    assert_eq!(
        registry.register_key(KeyRegistrationV1::new(
            encryption_identity,
            encryption_material,
            Some(signing_public_key),
        )),
        Err(pos_core::KeyRegistryErrorV1::UnexpectedPublicVerificationKey)
    );

    registry.register_key(KeyRegistrationV1::new(
        signing_identity,
        signing_material,
        Some(signing_public_key),
    ))?;
    assert_eq!(
        registry.register_key(KeyRegistrationV1::new(
            signing_identity,
            Hash::from_bytes([44; 32]),
            Some(signing_public_key),
        )),
        Err(pos_core::KeyRegistryErrorV1::IdentityConflict)
    );
    assert_eq!(
        registry.register_key(KeyRegistrationV1::new(
            KeyIdentityV1::new(signing_identity.owner_id, signing_identity.role, 0),
            signing_material,
            Some(signing_public_key),
        )),
        Err(pos_core::KeyRegistryErrorV1::InvalidEpoch)
    );
    registry.register_key(KeyRegistrationV1::new(
        KeyIdentityV1::new(signing_identity.owner_id, signing_identity.role, 2),
        Hash::from_bytes([45; 32]),
        Some(signing_public_key),
    ))?;
    assert_eq!(
        registry.register_key(KeyRegistrationV1::new(
            KeyIdentityV1::new(signing_identity.owner_id, signing_identity.role, 1),
            Hash::from_bytes([46; 32]),
            Some(signing_public_key),
        )),
        Err(pos_core::KeyRegistryErrorV1::StaleEpoch {
            role: signing_identity.role,
            requested: 1,
            active: 2,
        })
    );
    assert_eq!(
        registry.register_key(KeyRegistrationV1::new(
            KeyIdentityV1::new("test-owner", KeyRoleV1::PluginReleaseSigning, 1),
            signing_material,
            Some(signing_public_key),
        )),
        Err(pos_core::KeyRegistryErrorV1::MaterialReuse)
    );

    Ok(())
}

#[test]
fn public_registry_authorization_errors_are_fail_closed() -> Result<(), Box<dyn std::error::Error>>
{
    let signing_identity = KeyIdentityV1::new("test-owner", KeyRoleV1::TimelineIntegritySigning, 1);
    let signing_public_key = PublicKey::from_bytes([42; 32]);
    let mut registry = KeyRegistryStateV1::new();
    registry.register_key(KeyRegistrationV1::new(
        signing_identity,
        Hash::from_bytes([41; 32]),
        Some(signing_public_key),
    ))?;
    registry.register_key(KeyRegistrationV1::new(
        KeyIdentityV1::new(signing_identity.owner_id, signing_identity.role, 2),
        Hash::from_bytes([45; 32]),
        Some(signing_public_key),
    ))?;
    let encryption_identity = KeyIdentityV1::new("test-owner", KeyRoleV1::SubjectDataEncryption, 1);
    let encryption_material = Hash::from_bytes([43; 32]);
    registry.register_key(KeyRegistrationV1::new(
        encryption_identity,
        encryption_material,
        None,
    ))?;

    assert_eq!(
        registry.with_signing_authorization(
            signing_identity,
            Hash::from_bytes([41; 32]),
            signing_public_key,
            || "not called",
        ),
        Err(pos_core::KeyRegistryErrorV1::InactiveKey)
    );
    assert_eq!(
        registry.with_signing_authorization(
            KeyIdentityV1::new("test-owner", KeyRoleV1::PluginReleaseSigning, 1),
            Hash::from_bytes([41; 32]),
            signing_public_key,
            || "not called",
        ),
        Err(pos_core::KeyRegistryErrorV1::NotFound)
    );
    assert_eq!(
        registry.with_signing_authorization(
            KeyIdentityV1::new("test-owner", KeyRoleV1::TimelineIntegritySigning, 2),
            Hash::from_bytes([47; 32]),
            signing_public_key,
            || "not called",
        ),
        Err(pos_core::KeyRegistryErrorV1::SigningKeyMismatch)
    );
    assert_eq!(
        registry.with_encryption_authorization(
            encryption_identity,
            Hash::from_bytes([48; 32]),
            || "not called",
        ),
        Err(pos_core::KeyRegistryErrorV1::EncryptionKeyMismatch)
    );
    assert_eq!(
        registry.with_encryption_authorization(
            KeyIdentityV1::new("test-owner", KeyRoleV1::ExportRecipientEncryption, 1),
            encryption_material,
            || "not called",
        ),
        Err(pos_core::KeyRegistryErrorV1::NotFound)
    );

    Ok(())
}

#[test]
fn public_registry_destruction_pending_errors_are_fail_closed(
) -> Result<(), Box<dyn std::error::Error>> {
    let encryption_identity = KeyIdentityV1::new("test-owner", KeyRoleV1::SubjectDataEncryption, 1);
    let encryption_material = Hash::from_bytes([43; 32]);
    let mut registry = KeyRegistryStateV1::new();
    registry.register_key(KeyRegistrationV1::new(
        encryption_identity,
        encryption_material,
        None,
    ))?;
    let missing = KeyDestructionRequestV1::new(
        KeyIdentityV1::new("test-owner", KeyRoleV1::ExportRecipientEncryption, 1),
        encryption_material,
        Hash::from_bytes([49; 32]),
    );
    assert_eq!(
        registry.begin_key_destruction(missing),
        Err(pos_core::KeyRegistryErrorV1::NotFound)
    );
    assert_eq!(
        registry.begin_key_destruction(KeyDestructionRequestV1::new(
            encryption_identity,
            Hash::from_bytes([50; 32]),
            Hash::from_bytes([51; 32]),
        )),
        Err(pos_core::KeyRegistryErrorV1::MaterialDigestMismatch)
    );
    let mut pending_registry = registry.clone();
    let pending_request = KeyDestructionRequestV1::new(
        encryption_identity,
        encryption_material,
        Hash::from_bytes([52; 32]),
    );
    assert_eq!(
        pending_registry.begin_key_destruction(pending_request),
        Ok(pos_core::KeyDestructionBeginOutcomeV1::Started)
    );
    assert_eq!(
        pending_registry.begin_key_destruction(pending_request),
        Ok(pos_core::KeyDestructionBeginOutcomeV1::AlreadyPending)
    );
    assert_eq!(
        pending_registry.with_encryption_authorization(
            encryption_identity,
            encryption_material,
            || "not called",
        ),
        Err(pos_core::KeyRegistryErrorV1::DestructionPending)
    );
    assert_eq!(
        pending_registry.register_key(KeyRegistrationV1::new(
            encryption_identity,
            encryption_material,
            None,
        )),
        Err(pos_core::KeyRegistryErrorV1::DestructionPending)
    );
    assert_eq!(
        pending_registry.complete_key_destruction(
            KeyDestructionRequestV1::new(
                encryption_identity,
                encryption_material,
                Hash::from_bytes([53; 32]),
            ),
            pos_core::deletion_receipt(&pending_request),
        ),
        Err(pos_core::KeyRegistryErrorV1::DestructionAuthorizationMismatch)
    );
    assert_eq!(
        pending_registry.complete_key_destruction(pending_request, Hash::from_bytes([54; 32])),
        Err(pos_core::KeyRegistryErrorV1::DeletionReceiptMismatch)
    );
    pending_registry.complete_key_destruction(
        pending_request,
        pos_core::deletion_receipt(&pending_request),
    )?;
    Ok(())
}

#[test]
fn public_registry_destruction_tombstone_errors_are_fail_closed(
) -> Result<(), Box<dyn std::error::Error>> {
    let encryption_identity = KeyIdentityV1::new("test-owner", KeyRoleV1::SubjectDataEncryption, 1);
    let encryption_material = Hash::from_bytes([43; 32]);
    let mut registry = KeyRegistryStateV1::new();
    registry.register_key(KeyRegistrationV1::new(
        encryption_identity,
        encryption_material,
        None,
    ))?;
    let destroy_request = KeyDestructionRequestV1::new(
        encryption_identity,
        encryption_material,
        Hash::from_bytes([52; 32]),
    );
    destroy_registry(&mut registry, destroy_request)?;
    assert_eq!(
        registry.complete_key_destruction(destroy_request, Hash::from_bytes([55; 32])),
        Err(pos_core::KeyRegistryErrorV1::DestructionAuthorizationMismatch)
    );
    assert!(matches!(
        registry.complete_key_destruction(
            destroy_request,
            pos_core::deletion_receipt(&destroy_request),
        ),
        Ok(pos_core::KeyDestructionOutcomeV1::AlreadyDestroyed(_))
    ));
    assert_eq!(
        registry.begin_key_destruction(KeyDestructionRequestV1::new(
            encryption_identity,
            Hash::from_bytes([53; 32]),
            Hash::from_bytes([52; 32]),
        )),
        Err(pos_core::KeyRegistryErrorV1::MaterialDigestMismatch)
    );
    assert_eq!(
        registry.begin_key_destruction(KeyDestructionRequestV1::new(
            encryption_identity,
            encryption_material,
            Hash::from_bytes([54; 32]),
        )),
        Err(pos_core::KeyRegistryErrorV1::DestructionAuthorizationMismatch)
    );

    Ok(())
}

#[test]
fn public_registry_success_and_role_gate_paths_are_exercised(
) -> Result<(), Box<dyn std::error::Error>> {
    let signing_identity = KeyIdentityV1::new("test-owner", KeyRoleV1::TimelineIntegritySigning, 1);
    let signing_material = Hash::from_bytes([61; 32]);
    let signing_public_key = PublicKey::from_bytes([62; 32]);
    let registration =
        KeyRegistrationV1::new(signing_identity, signing_material, Some(signing_public_key));
    let mut registry = KeyRegistryStateV1::new();
    assert_eq!(registry.validate(), Ok(()));
    assert_eq!(
        registry.register_key(registration),
        Ok(pos_core::KeyRegistrationOutcomeV1::Registered)
    );
    assert_eq!(
        registry.register_key(registration),
        Ok(pos_core::KeyRegistrationOutcomeV1::AlreadyRegistered)
    );
    assert_eq!(
        registry.active_key(
            &signing_identity.owner_id,
            KeyRoleV1::ExportRecipientEncryption,
        ),
        None
    );
    assert_eq!(
        registry.key_record(KeyIdentityV1::new(
            "test-owner",
            KeyRoleV1::PluginReleaseSigning,
            1,
        )),
        None
    );
    assert_eq!(
        registry.tombstone(KeyIdentityV1::new(
            "test-owner",
            KeyRoleV1::PluginReleaseSigning,
            1,
        )),
        None
    );

    assert_eq!(
        registry.with_signing_authorization(
            KeyIdentityV1::new(signing_identity.owner_id, signing_identity.role, 0),
            signing_material,
            signing_public_key,
            || "not called",
        ),
        Err(pos_core::KeyRegistryErrorV1::InvalidEpoch)
    );
    assert_eq!(
        registry.with_signing_authorization(
            KeyIdentityV1::new("test-owner", KeyRoleV1::SubjectDataEncryption, 1),
            signing_material,
            signing_public_key,
            || "not called",
        ),
        Err(pos_core::KeyRegistryErrorV1::SigningRoleRequired)
    );
    assert_eq!(
        registry.with_encryption_authorization(
            KeyIdentityV1::new(signing_identity.owner_id, signing_identity.role, 1),
            signing_material,
            || "not called",
        ),
        Err(pos_core::KeyRegistryErrorV1::EncryptionRoleRequired)
    );

    let next_identity = KeyIdentityV1::new(signing_identity.owner_id, signing_identity.role, 2);
    let next_registration = KeyRegistrationV1::new(
        next_identity,
        Hash::from_bytes([63; 32]),
        Some(signing_public_key),
    );
    let previous = registry.clone();
    registry.register_key(next_registration)?;
    assert_eq!(previous.validate_replacement(&registry), Ok(()));
    destroy_registry(
        &mut registry,
        KeyDestructionRequestV1::new(
            next_identity,
            Hash::from_bytes([63; 32]),
            Hash::from_bytes([64; 32]),
        ),
    )?;
    assert_eq!(
        registry.register_key(next_registration),
        Err(pos_core::KeyRegistryErrorV1::Destroyed)
    );
    Ok(())
}
