#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

use pos_core::{
    CanonicalBytes, CoreError, EntityId, Event, EventDraft, EventId, EventStore, Hash,
    KeyDestructionOutcomeV1, KeyDestructionPortV1, KeyDestructionRequestV1, KeyIdentityV1,
    KeyRegistrationV1, KeyRegistryEncryptionPortV1, KeyRegistryPortV1, KeyRegistrySigningPortV1,
    KeyRegistryStateV1, KeyRoleV1, Kind, PublicKey, SchemaVersion, Seq, SeqRange, Timeline,
    TimelineId, TimelineMeta, WallTime,
};
use std::cell::Cell;

struct RegistryStore {
    registry: Option<KeyRegistryStateV1>,
    timeline: Option<Timeline>,
    committed: bool,
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

fn registered_state(
) -> Result<(KeyRegistryStateV1, KeyIdentityV1, Hash), Box<dyn std::error::Error>> {
    let identity = KeyIdentityV1::new(KeyRoleV1::TimelineIntegritySigning, 1);
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

    let request = pos_core::KeyDestructionRequestV1::new(
        identity,
        material_digest,
        Hash::from_bytes([2; 32]),
    );
    let (_, destroyed) = store.destroy_key_registry(request)?;
    assert!(destroyed.key_record(identity).is_some());
    Ok(())
}

#[test]
fn replacement_rejects_tombstone_rewrite_at_public_boundary(
) -> Result<(), Box<dyn std::error::Error>> {
    let (registry, identity, material_digest) = registered_state()?;
    let mut store = RegistryStore::new(Some(registry));
    let (_, destroyed) = store.destroy_key_registry(pos_core::KeyDestructionRequestV1::new(
        identity,
        material_digest,
        Hash::from_bytes([2; 32]),
    ))?;
    assert_eq!(destroyed.validate_replacement(&destroyed), Ok(()));
    let changed_tombstone = changed_tombstone_digest(&destroyed)?;
    assert_eq!(
        destroyed.validate_replacement(&changed_tombstone),
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

    let signing_identity = KeyIdentityV1::new(KeyRoleV1::TimelineIntegritySigning, 1);
    let signing_material = Hash::from_bytes([21; 32]);
    let signing_public_key = PublicKey::from_bytes([22; 32]);
    let encryption_identity = KeyIdentityV1::new(KeyRoleV1::SubjectDataEncryption, 1);
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
        KeyRegistryPortV1::active_key(&registry, signing_identity.role)
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
    let first = KeyDestructionPortV1::destroy_key(&mut registry, destruction_request)?;
    let second = KeyDestructionPortV1::destroy_key(&mut registry, destruction_request)?;
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

    let signing_identity = KeyIdentityV1::new(KeyRoleV1::TimelineIntegritySigning, 1);
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
    signing_registry.destroy_key(signing_request)?;
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

    let encryption_identity = KeyIdentityV1::new(KeyRoleV1::SubjectDataEncryption, 1);
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
    encryption_registry.destroy_key(encryption_request)?;
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
            KeyIdentityV1::new(KeyRoleV1::ExportRecipientEncryption, 1),
            encryption_material,
            None,
        )),
        Err(pos_core::KeyRegistryErrorV1::MaterialReuse)
    );

    Ok(())
}

#[test]
fn public_registry_registration_errors_are_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    let signing_identity = KeyIdentityV1::new(KeyRoleV1::TimelineIntegritySigning, 1);
    let signing_material = Hash::from_bytes([41; 32]);
    let signing_public_key = PublicKey::from_bytes([42; 32]);
    let encryption_identity = KeyIdentityV1::new(KeyRoleV1::SubjectDataEncryption, 1);
    let encryption_material = Hash::from_bytes([43; 32]);
    let mut registry = KeyRegistryStateV1::new();

    assert_eq!(
        registry.register_key(KeyRegistrationV1::new(
            KeyIdentityV1::new(KeyRoleV1::TimelineIntegritySigning, 0),
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
            KeyIdentityV1::new(signing_identity.role, 0),
            signing_material,
            Some(signing_public_key),
        )),
        Err(pos_core::KeyRegistryErrorV1::InvalidEpoch)
    );
    registry.register_key(KeyRegistrationV1::new(
        KeyIdentityV1::new(signing_identity.role, 2),
        Hash::from_bytes([45; 32]),
        Some(signing_public_key),
    ))?;
    assert_eq!(
        registry.register_key(KeyRegistrationV1::new(
            KeyIdentityV1::new(signing_identity.role, 1),
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
            KeyIdentityV1::new(KeyRoleV1::PluginReleaseSigning, 1),
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
    let signing_identity = KeyIdentityV1::new(KeyRoleV1::TimelineIntegritySigning, 1);
    let signing_public_key = PublicKey::from_bytes([42; 32]);
    let mut registry = KeyRegistryStateV1::new();
    registry.register_key(KeyRegistrationV1::new(
        signing_identity,
        Hash::from_bytes([41; 32]),
        Some(signing_public_key),
    ))?;
    registry.register_key(KeyRegistrationV1::new(
        KeyIdentityV1::new(signing_identity.role, 2),
        Hash::from_bytes([45; 32]),
        Some(signing_public_key),
    ))?;
    let encryption_identity = KeyIdentityV1::new(KeyRoleV1::SubjectDataEncryption, 1);
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
            KeyIdentityV1::new(KeyRoleV1::PluginReleaseSigning, 1),
            Hash::from_bytes([41; 32]),
            signing_public_key,
            || "not called",
        ),
        Err(pos_core::KeyRegistryErrorV1::NotFound)
    );
    assert_eq!(
        registry.with_signing_authorization(
            KeyIdentityV1::new(KeyRoleV1::TimelineIntegritySigning, 2),
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
            KeyIdentityV1::new(KeyRoleV1::ExportRecipientEncryption, 1),
            encryption_material,
            || "not called",
        ),
        Err(pos_core::KeyRegistryErrorV1::NotFound)
    );

    Ok(())
}

#[test]
fn public_registry_destruction_errors_are_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    let encryption_identity = KeyIdentityV1::new(KeyRoleV1::SubjectDataEncryption, 1);
    let encryption_material = Hash::from_bytes([43; 32]);
    let mut registry = KeyRegistryStateV1::new();
    registry.register_key(KeyRegistrationV1::new(
        encryption_identity,
        encryption_material,
        None,
    ))?;
    let missing = KeyDestructionRequestV1::new(
        KeyIdentityV1::new(KeyRoleV1::ExportRecipientEncryption, 1),
        encryption_material,
        Hash::from_bytes([49; 32]),
    );
    assert_eq!(
        registry.destroy_key(missing),
        Err(pos_core::KeyRegistryErrorV1::NotFound)
    );
    assert_eq!(
        registry.destroy_key(KeyDestructionRequestV1::new(
            encryption_identity,
            Hash::from_bytes([50; 32]),
            Hash::from_bytes([51; 32]),
        )),
        Err(pos_core::KeyRegistryErrorV1::MaterialDigestMismatch)
    );
    let destroy_request = KeyDestructionRequestV1::new(
        encryption_identity,
        encryption_material,
        Hash::from_bytes([52; 32]),
    );
    registry.destroy_key(destroy_request)?;
    assert_eq!(
        registry.destroy_key(KeyDestructionRequestV1::new(
            encryption_identity,
            Hash::from_bytes([53; 32]),
            Hash::from_bytes([52; 32]),
        )),
        Err(pos_core::KeyRegistryErrorV1::MaterialDigestMismatch)
    );
    assert_eq!(
        registry.destroy_key(KeyDestructionRequestV1::new(
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
    let signing_identity = KeyIdentityV1::new(KeyRoleV1::TimelineIntegritySigning, 1);
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
        registry.active_key(KeyRoleV1::ExportRecipientEncryption),
        None
    );
    assert_eq!(
        registry.key_record(KeyIdentityV1::new(KeyRoleV1::PluginReleaseSigning, 1)),
        None
    );
    assert_eq!(
        registry.tombstone(KeyIdentityV1::new(KeyRoleV1::PluginReleaseSigning, 1)),
        None
    );

    assert_eq!(
        registry.with_signing_authorization(
            KeyIdentityV1::new(signing_identity.role, 0),
            signing_material,
            signing_public_key,
            || "not called",
        ),
        Err(pos_core::KeyRegistryErrorV1::InvalidEpoch)
    );
    assert_eq!(
        registry.with_signing_authorization(
            KeyIdentityV1::new(KeyRoleV1::SubjectDataEncryption, 1),
            signing_material,
            signing_public_key,
            || "not called",
        ),
        Err(pos_core::KeyRegistryErrorV1::SigningRoleRequired)
    );
    assert_eq!(
        registry.with_encryption_authorization(
            KeyIdentityV1::new(signing_identity.role, 1),
            signing_material,
            || "not called",
        ),
        Err(pos_core::KeyRegistryErrorV1::EncryptionRoleRequired)
    );

    let next_identity = KeyIdentityV1::new(signing_identity.role, 2);
    let next_registration = KeyRegistrationV1::new(
        next_identity,
        Hash::from_bytes([63; 32]),
        Some(signing_public_key),
    );
    let previous = registry.clone();
    registry.register_key(next_registration)?;
    assert_eq!(previous.validate_replacement(&registry), Ok(()));
    registry.destroy_key(KeyDestructionRequestV1::new(
        next_identity,
        Hash::from_bytes([63; 32]),
        Hash::from_bytes([64; 32]),
    ))?;
    assert_eq!(
        registry.register_key(next_registration),
        Err(pos_core::KeyRegistryErrorV1::Destroyed)
    );
    Ok(())
}
