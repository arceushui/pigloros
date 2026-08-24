use ed25519_dalek::SigningKey;
use std::sync::{Arc, Mutex};

use pos_core::{
    clock::{Seq, WallTime},
    event::{CanonicalBytes, Event, Kind, SchemaVersion},
    hasher::Hasher,
    ids::{EntityId, EventId},
    store::{EventStore, SeqRange},
    CoreError, KeyDestructionOutcomeV1, KeyDestructionRequestV1, KeyIdentityV1, KeyRegistryStateV1,
};
use pos_crypto::{
    key_roles::{key_material_digest, sign_for_registered_role},
    signing::public_key_from_verifying_key,
};

use crate::{
    payload::{decode_outcome, decode_prediction, EVENT_TYPE_OUTCOME, EVENT_TYPE_PREDICTION},
    store::{LedgerStore, NewPrediction, ResolveStatus},
    Ledger, LedgerError, LedgerOutcome, LedgerPrediction,
};

impl From<CoreError> for LedgerError {
    fn from(e: CoreError) -> Self {
        Self::Store(e.to_string())
    }
}

fn to_canonical(value: &impl serde::Serialize) -> CanonicalBytes {
    let mut buf = Vec::new();
    assert!(ciborium::into_writer(value, &mut buf).is_ok());
    CanonicalBytes::from_vec(buf)
}

pub struct EventLedgerStore {
    store: Box<dyn EventStore>,
    timeline_id: pos_core::ids::TimelineId,
    entity: EntityId,
    signing_key: SigningKey,
    key_registry: Arc<Mutex<KeyRegistryStateV1>>,
    signing_identity: KeyIdentityV1,
    hasher: Box<dyn Hasher>,
}

impl EventLedgerStore {
    /// Construct a ledger adapter from an externally owned signing registry.
    ///
    /// The store owns the durable registry snapshot and the adapter keeps the
    /// caller-visible state synchronized with it. Signing and destruction use
    /// the store's atomic registry boundary.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError::Store`] when the supplied registry does not
    /// authorize the signing identity for the supplied key.
    pub fn new(
        mut store: Box<dyn EventStore>,
        timeline_id: pos_core::ids::TimelineId,
        entity: EntityId,
        signing_key: SigningKey,
        key_registry: Arc<Mutex<KeyRegistryStateV1>>,
        signing_identity: KeyIdentityV1,
        hasher: Box<dyn Hasher>,
    ) -> Result<Self, LedgerError> {
        if let Some(persisted_registry) = store.load_key_registry().map_err(LedgerError::from)? {
            *key_registry.lock().map_err(|_| {
                LedgerError::Store("ledger signing registry is unavailable".to_owned())
            })? = persisted_registry;
        } else {
            let initial_registry = key_registry
                .lock()
                .map_err(|_| {
                    LedgerError::Store("ledger signing registry is unavailable".to_owned())
                })?
                .clone();
            store
                .save_key_registry(&initial_registry)
                .map_err(LedgerError::from)?;
        }
        let public_verification_key = public_key_from_verifying_key(&signing_key.verifying_key());
        key_registry
            .lock()
            .map_err(|_| LedgerError::Store("ledger signing registry is unavailable".to_owned()))?
            .with_signing_authorization(
                signing_identity,
                key_material_digest(&signing_key.to_bytes()),
                public_verification_key,
                || (),
            )
            .map_err(|error| {
                LedgerError::Store(format!("ledger signing authorization: {error}"))
            })?;
        Ok(Self {
            store,
            timeline_id,
            entity,
            signing_key,
            key_registry,
            signing_identity,
            hasher,
        })
    }

    /// Irreversibly destroy one signing identity and persist its tombstone.
    ///
    /// The registry lock is held while the store atomically commits the
    /// destruction, so a stale adapter cannot append after the tombstone is
    /// durable.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError::Store`] when the request is invalid or the
    /// durable registry cannot be updated.
    pub fn destroy_signing_key(
        &mut self,
        request: KeyDestructionRequestV1,
    ) -> Result<KeyDestructionOutcomeV1, LedgerError> {
        let mut registry = self
            .key_registry
            .lock()
            .map_err(|_| LedgerError::Store("ledger signing registry is unavailable".to_owned()))?;
        let (outcome, next) = self
            .store
            .destroy_key_registry(request)
            .map_err(LedgerError::from)?;
        *registry = next;
        Ok(outcome)
    }

    #[cfg(test)]
    fn head_seq(&self) -> Result<Seq, LedgerError> {
        self.store
            .get_timeline(self.timeline_id)
            .ok()
            .flatten()
            .map(|tl| tl.head)
            .ok_or_else(|| LedgerError::Store("timeline not found".into()))
    }

    fn append_signed(
        &mut self,
        payload: CanonicalBytes,
        event_type: Kind,
    ) -> Result<(), LedgerError> {
        let payload_hash = self.hasher.hash_payload(&payload);
        let key_registry = self
            .key_registry
            .lock()
            .map_err(|_| LedgerError::Store("ledger signing registry is unavailable".to_owned()))?;
        let signing_key = &self.signing_key;
        let signing_identity = self.signing_identity;
        let entity = self.entity;
        let mut create_event = move |registry: &KeyRegistryStateV1, seq: Seq| {
            let mut registry = registry.clone();
            let signature =
                sign_for_registered_role(&mut registry, signing_key, signing_identity, &payload)
                    .map_err(|error| {
                        CoreError::Storage(format!("ledger signing authorization: {error}"))
                    })?;
            Ok(Event {
                id: EventId::new(),
                entity,
                event_type: event_type.clone(),
                payload: payload.clone(),
                wall_time: WallTime::now(),
                seq,
                causation_id: None,
                correlation_id: None,
                schema_version: SchemaVersion::V1,
                signature: Some(signature),
                signature_identity: Some(signing_identity),
                payload_hash,
            })
        };

        self.store
            .append_signed_authorized(self.timeline_id, &key_registry, &mut create_event)
            .map_err(LedgerError::from)
    }
}

impl LedgerStore for EventLedgerStore {
    fn load(&self, today: &str) -> Result<Ledger, LedgerError> {
        let events = self
            .store
            .read(self.timeline_id, SeqRange::all())
            .map_err(LedgerError::from)?;

        let mut pairs: Vec<(LedgerPrediction, Option<LedgerOutcome>)> = Vec::new();

        for event in &events {
            match event.event_type.as_str() {
                EVENT_TYPE_PREDICTION => {
                    let pred = decode_prediction(event.payload.as_slice())?;
                    pairs.push((pred, None));
                }
                EVENT_TYPE_OUTCOME => {
                    let outcome = decode_outcome(event.payload.as_slice())?;
                    let slot = pairs
                        .iter_mut()
                        .find(|(p, _)| p.prediction_id == outcome.prediction_id)
                        .map(|(_, slot)| slot);
                    match slot {
                        Some(slot) => *slot = Some(outcome),
                        None => return Err(LedgerError::OrphanResolution(outcome.prediction_id)),
                    }
                }
                _ => {}
            }
        }

        Ledger::from_pairs(pairs, today)
    }

    fn register(&mut self, new: NewPrediction) -> Result<String, LedgerError> {
        new.validate()?;
        let prediction = new.into_prediction(ulid::Ulid::generate().to_string());
        let payload = to_canonical(&prediction);

        self.append_signed(payload, Kind::new(EVENT_TYPE_PREDICTION))?;
        Ok(prediction.prediction_id)
    }

    fn find_resolve_status(&self, prediction_id: &str) -> Result<ResolveStatus, LedgerError> {
        let events = self
            .store
            .read(self.timeline_id, SeqRange::all())
            .map_err(LedgerError::from)?;

        let found_prediction = events
            .iter()
            .filter(|e| e.event_type.as_str() == EVENT_TYPE_PREDICTION)
            .filter_map(|e| decode_prediction(e.payload.as_slice()).ok())
            .any(|p| p.prediction_id == prediction_id);

        let already_resolved = events
            .iter()
            .filter(|e| e.event_type.as_str() == EVENT_TYPE_OUTCOME)
            .filter_map(|e| decode_outcome(e.payload.as_slice()).ok())
            .any(|r| r.prediction_id == prediction_id);

        Ok(ResolveStatus {
            found_prediction,
            already_resolved,
        })
    }

    fn persist_resolve(&mut self, outcome: LedgerOutcome) -> Result<(), LedgerError> {
        self.append_signed(to_canonical(&outcome), Kind::new(EVENT_TYPE_OUTCOME))
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::contract;
    use pos_core::{KeyRegistrationV1, KeyRoleV1};
    use pos_crypto::{
        chain::{hash_payload, Blake3Hasher},
        key_roles::verify_for_role,
    };
    use pos_store::memory::MemoryStore;

    fn make_store() -> Result<EventLedgerStore, Box<dyn std::error::Error>> {
        let (sk, _vk) = pos_crypto::signing::generate_keypair();
        let (registry, identity) = registry_for(&sk)?;
        let mut mem = MemoryStore::new();
        let tl = mem.create_timeline("ledger")?;
        Ok(EventLedgerStore::new(
            Box::new(mem),
            tl.id(),
            EntityId::new(),
            sk,
            registry,
            identity,
            Box::new(Blake3Hasher),
        )?)
    }

    fn registry_for(
        signing_key: &SigningKey,
    ) -> Result<(Arc<Mutex<KeyRegistryStateV1>>, KeyIdentityV1), Box<dyn std::error::Error>> {
        let identity = KeyIdentityV1::new(KeyRoleV1::TimelineIntegritySigning, 1);
        let mut registry = KeyRegistryStateV1::new();
        registry.register_key(KeyRegistrationV1::new(
            identity,
            key_material_digest(&signing_key.to_bytes()),
            Some(public_key_from_verifying_key(&signing_key.verifying_key())),
        ))?;
        Ok((Arc::new(Mutex::new(registry)), identity))
    }

    #[test]
    fn constructor_rejects_a_registry_without_active_authority(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (signing_key, _) = pos_crypto::signing::generate_keypair();
        let identity = KeyIdentityV1::new(KeyRoleV1::TimelineIntegritySigning, 1);
        let error = EventLedgerStore::new(
            Box::new(MemoryStore::new()),
            pos_core::ids::TimelineId::new(),
            EntityId::new(),
            signing_key,
            Arc::new(Mutex::new(KeyRegistryStateV1::new())),
            identity,
            Box::new(Blake3Hasher),
        )
        .err()
        .ok_or("expected registry authorization error")?;
        assert!(matches!(error, LedgerError::Store(_)));
        Ok(())
    }

    #[test]
    fn external_registry_destruction_blocks_future_ledger_signing(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (signing_key, _) = pos_crypto::signing::generate_keypair();
        let (registry, identity) = registry_for(&signing_key)?;
        let material_digest = key_material_digest(&signing_key.to_bytes());
        let mut mem = MemoryStore::new();
        let timeline = mem.create_timeline("ledger")?;
        let mut store = EventLedgerStore::new(
            Box::new(mem),
            timeline.id(),
            EntityId::new(),
            signing_key,
            Arc::clone(&registry),
            identity,
            Box::new(Blake3Hasher),
        )?;
        store.destroy_signing_key(pos_core::KeyDestructionRequestV1::new(
            identity,
            material_digest,
            pos_core::Hash::from_bytes([8; 32]),
        ))?;
        let error = store
            .register(crate::contract::sample_new_prediction("2026-08-01"))
            .err()
            .ok_or("expected destroyed-signing error")?;
        assert!(error.to_string().contains("destroyed"));
        Ok(())
    }

    #[test]
    fn destroyed_registry_state_survives_sqlite_reopen() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let db = temp.path().join("ledger.db");
        let (signing_key, _) = pos_crypto::signing::generate_keypair();
        let (registry, identity) = registry_for(&signing_key)?;
        let material_digest = key_material_digest(&signing_key.to_bytes());
        let mut raw_store = pos_store::open_store(pos_store::StoreConfig::Sqlite {
            path: db.to_string_lossy().into_owned(),
        })?;
        let timeline = raw_store.create_timeline("ledger")?;
        let mut store = EventLedgerStore::new(
            raw_store,
            timeline.id(),
            EntityId::new(),
            signing_key.clone(),
            registry,
            identity,
            Box::new(Blake3Hasher),
        )?;
        store.destroy_signing_key(pos_core::KeyDestructionRequestV1::new(
            identity,
            material_digest,
            pos_core::Hash::from_bytes([9; 32]),
        ))?;
        drop(store);

        let reopened = pos_store::open_store(pos_store::StoreConfig::Sqlite {
            path: db.to_string_lossy().into_owned(),
        })?;
        let persisted = reopened
            .load_key_registry()?
            .ok_or("expected persisted registry")?;
        assert!(persisted.tombstone(identity).is_some());
        let error = EventLedgerStore::new(
            reopened,
            timeline.id(),
            EntityId::new(),
            signing_key,
            Arc::new(Mutex::new(KeyRegistryStateV1::new())),
            identity,
            Box::new(Blake3Hasher),
        )
        .err()
        .ok_or("destroyed identity must not authorize after reopen")?;
        assert!(error.to_string().contains("destroyed"));
        Ok(())
    }

    #[test]
    fn stale_sqlite_adapter_cannot_append_after_registry_destruction(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let db = temp.path().join("ledger.db");
        let (signing_key, _) = pos_crypto::signing::generate_keypair();
        let (registry, identity) = registry_for(&signing_key)?;
        let material_digest = key_material_digest(&signing_key.to_bytes());
        let mut first_raw = pos_store::open_store(pos_store::StoreConfig::Sqlite {
            path: db.to_string_lossy().into_owned(),
        })?;
        let timeline = first_raw.create_timeline("ledger")?;
        let mut first = EventLedgerStore::new(
            first_raw,
            timeline.id(),
            EntityId::new(),
            signing_key.clone(),
            registry,
            identity,
            Box::new(Blake3Hasher),
        )?;
        let second_raw = pos_store::open_store(pos_store::StoreConfig::Sqlite {
            path: db.to_string_lossy().into_owned(),
        })?;
        let mut second = EventLedgerStore::new(
            second_raw,
            timeline.id(),
            EntityId::new(),
            signing_key,
            Arc::new(Mutex::new(KeyRegistryStateV1::new())),
            identity,
            Box::new(Blake3Hasher),
        )?;

        first.destroy_signing_key(pos_core::KeyDestructionRequestV1::new(
            identity,
            material_digest,
            pos_core::Hash::from_bytes([10; 32]),
        ))?;
        let error = second
            .register(crate::contract::sample_new_prediction("2026-08-01"))
            .err()
            .ok_or("stale adapter unexpectedly appended after destruction")?;
        assert!(error.to_string().contains("changed during signing"));
        Ok(())
    }

    #[test]
    fn port_contract() -> Result<(), Box<dyn std::error::Error>> {
        contract::run(&mut |_path| Ok(Box::new(make_store()?) as Box<dyn LedgerStore>))?;
        Ok(())
    }

    #[test]
    fn load_empty_ledger() -> Result<(), Box<dyn std::error::Error>> {
        let store = make_store()?;
        let ledger = store.load("2026-07-25")?;
        assert!(ledger.entries().is_empty());
        Ok(())
    }

    #[test]
    fn register_and_load() -> Result<(), Box<dyn std::error::Error>> {
        let mut store = make_store()?;
        let id = store.register(contract::sample_new_prediction("2026-08-01"))?;
        let ledger = store.load("2026-07-25")?;
        assert_eq!(ledger.entries().len(), 1);
        assert_eq!(ledger.entries()[0].prediction.prediction_id, id);
        let events = store.store.read(store.timeline_id, SeqRange::all())?;
        let signature = events[0].signature.as_ref().ok_or("missing signature")?;
        verify_for_role(
            &store.signing_key.verifying_key(),
            KeyRoleV1::TimelineIntegritySigning,
            1,
            &events[0].payload,
            signature,
        )?;
        Ok(())
    }

    #[test]
    fn resolve_and_load() -> Result<(), Box<dyn std::error::Error>> {
        let mut store = make_store()?;
        let id = store.register(contract::sample_new_prediction("2026-08-01"))?;
        store.resolve(LedgerOutcome::try_new(
            id,
            true,
            "2026-07-30T09:00:00Z".to_owned(),
        )?)?;
        let ledger = store.load("2026-07-25")?;
        assert_eq!(ledger.entries().len(), 1);
        assert_eq!(ledger.entries()[0].status.as_str(), "resolved");
        Ok(())
    }

    #[test]
    fn double_resolve_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let mut store = make_store()?;
        let id = store.register(contract::sample_new_prediction("2026-08-01"))?;
        store.resolve(LedgerOutcome::try_new(
            id.clone(),
            true,
            "2026-07-30T09:00:00Z".to_owned(),
        )?)?;
        let err = store
            .resolve(LedgerOutcome::try_new(
                id,
                false,
                "2026-07-31T09:00:00Z".to_owned(),
            )?)
            .err()
            .ok_or("expected error")?;
        assert!(matches!(err, LedgerError::AlreadyResolved(_)));
        Ok(())
    }

    #[test]
    fn unknown_prediction_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let mut store = make_store()?;
        let err = store
            .resolve(LedgerOutcome {
                prediction_id: "01J3B0Y5ZK2J6MGK8D7QW3N0P9".to_owned(),
                outcome: true,
                resolved_at: "2026-07-30T09:00:00Z".to_owned(),
            })
            .err()
            .ok_or("expected error")?;
        assert!(matches!(err, LedgerError::UnknownPrediction(_)));
        Ok(())
    }

    #[test]
    fn events_are_signed() -> Result<(), Box<dyn std::error::Error>> {
        let mut store = make_store()?;
        store.register(contract::sample_new_prediction("2026-08-01"))?;
        let events = store.store.read(store.timeline_id, SeqRange::all())?;
        assert_eq!(events.len(), 1);
        assert!(events[0].signature.is_some(), "event must be signed");
        Ok(())
    }

    #[test]
    fn load_orphan_outcome_returns_error() -> Result<(), Box<dyn std::error::Error>> {
        let mut store = make_store()?;
        let head = store.head_seq()?;
        let outcome = LedgerOutcome::try_new(
            "01J3B0Y5ZK2J6MGK8D7QW3N0P9".to_owned(),
            true,
            "2026-07-30T09:00:00Z".to_owned(),
        )?;
        let payload = to_canonical(&outcome);
        let payload_hash = hash_payload(&payload);
        let event = Event {
            id: EventId::new(),
            entity: store.entity,
            event_type: Kind::new(EVENT_TYPE_OUTCOME),
            payload,
            wall_time: WallTime::now(),
            seq: head.next(),
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            signature_identity: None,
            payload_hash,
        };
        store.store.append_committed(store.timeline_id, &[event])?;
        let err = store.load("2026-07-25").err().ok_or("expected error")?;
        assert!(matches!(err, LedgerError::OrphanResolution(_)));
        Ok(())
    }

    #[test]
    fn load_skips_unknown_event_types() -> Result<(), Box<dyn std::error::Error>> {
        let mut store = make_store()?;
        let head = store.head_seq()?;
        let payload = CanonicalBytes::from_vec(b"some_unrelated_data".to_vec());
        let payload_hash = hash_payload(&payload);
        let event = Event {
            id: EventId::new(),
            entity: store.entity,
            event_type: Kind::new("completely.unrelated"),
            payload,
            wall_time: WallTime::now(),
            seq: head.next(),
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            signature_identity: None,
            payload_hash,
        };
        store.store.append_committed(store.timeline_id, &[event])?;
        let ledger = store.load("2026-07-25")?;
        assert!(ledger.entries().is_empty());
        Ok(())
    }

    #[test]
    fn resolve_skips_decode_error_prediction() -> Result<(), Box<dyn std::error::Error>> {
        let mut store = make_store()?;
        let head = store.head_seq()?;
        let payload = CanonicalBytes::from_vec(b"not cbor".to_vec());
        let payload_hash = hash_payload(&payload);
        let event = Event {
            id: EventId::new(),
            entity: store.entity,
            event_type: Kind::new(EVENT_TYPE_PREDICTION),
            payload,
            wall_time: WallTime::now(),
            seq: head.next(),
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            signature_identity: None,
            payload_hash,
        };
        store.store.append_committed(store.timeline_id, &[event])?;
        let err = store
            .resolve(LedgerOutcome::try_new(
                "01J3B0Y5ZK2J6MGK8D7QW3N0P9".to_owned(),
                true,
                "2026-07-30T09:00:00Z".to_owned(),
            )?)
            .err()
            .ok_or("expected error")?;
        assert!(matches!(err, LedgerError::UnknownPrediction(_)));
        Ok(())
    }

    #[test]
    fn resolve_skips_decode_error_outcome() -> Result<(), Box<dyn std::error::Error>> {
        let mut store = make_store()?;
        let id = store.register(contract::sample_new_prediction("2026-08-01"))?;
        let head = store.head_seq()?;
        let payload = CanonicalBytes::from_vec(b"not cbor".to_vec());
        let payload_hash = hash_payload(&payload);
        let event = Event {
            id: EventId::new(),
            entity: store.entity,
            event_type: Kind::new(EVENT_TYPE_OUTCOME),
            payload,
            wall_time: WallTime::now(),
            seq: head.next(),
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            signature_identity: None,
            payload_hash,
        };
        store.store.append_committed(store.timeline_id, &[event])?;
        let result = store.resolve(LedgerOutcome::try_new(
            id,
            true,
            "2026-07-30T09:00:00Z".to_owned(),
        )?);
        assert!(result.is_ok(), "resolve should succeed: {result:?}");
        Ok(())
    }

    #[test]
    fn resolve_skips_unknown_event_types() -> Result<(), Box<dyn std::error::Error>> {
        let mut store = make_store()?;
        let id = store.register(contract::sample_new_prediction("2026-08-01"))?;
        let head = store.head_seq()?;
        let payload = CanonicalBytes::from_vec(b"irrelevant".to_vec());
        let payload_hash = hash_payload(&payload);
        let event = Event {
            id: EventId::new(),
            entity: store.entity,
            event_type: Kind::new("irrelevant.type"),
            payload,
            wall_time: WallTime::now(),
            seq: head.next(),
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            signature_identity: None,
            payload_hash,
        };
        store.store.append_committed(store.timeline_id, &[event])?;
        store.resolve(LedgerOutcome::try_new(
            id,
            true,
            "2026-07-30T09:00:00Z".to_owned(),
        )?)?;
        Ok(())
    }

    #[test]
    fn load_fails_on_corrupt_prediction_payload() -> Result<(), Box<dyn std::error::Error>> {
        let mut store = make_store()?;
        let head = store.head_seq()?;
        let payload = CanonicalBytes::from_vec(b"not cbor".to_vec());
        let payload_hash = hash_payload(&payload);
        let event = Event {
            id: EventId::new(),
            entity: store.entity,
            event_type: Kind::new(EVENT_TYPE_PREDICTION),
            payload,
            wall_time: WallTime::now(),
            seq: head.next(),
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            signature_identity: None,
            payload_hash,
        };
        store.store.append_committed(store.timeline_id, &[event])?;
        let err = store.load("2026-07-25").err().ok_or("expected error")?;
        assert!(matches!(err, LedgerError::Decode(_)));
        Ok(())
    }

    #[test]
    fn load_fails_on_corrupt_outcome_payload() -> Result<(), Box<dyn std::error::Error>> {
        let mut store = make_store()?;
        let head = store.head_seq()?;
        let payload = CanonicalBytes::from_vec(b"not cbor".to_vec());
        let payload_hash = hash_payload(&payload);
        let event = Event {
            id: EventId::new(),
            entity: store.entity,
            event_type: Kind::new(EVENT_TYPE_OUTCOME),
            payload,
            wall_time: WallTime::now(),
            seq: head.next(),
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            signature_identity: None,
            payload_hash,
        };
        store.store.append_committed(store.timeline_id, &[event])?;
        let err = store.load("2026-07-25").err().ok_or("expected error")?;
        assert!(matches!(err, LedgerError::Decode(_)));
        Ok(())
    }

    #[test]
    fn load_fails_on_missing_timeline() -> Result<(), Box<dyn std::error::Error>> {
        let (sk, _vk) = pos_crypto::signing::generate_keypair();
        let (registry, identity) = registry_for(&sk)?;
        let mem = MemoryStore::new();
        let tl_id = pos_core::ids::TimelineId::new();
        let store = EventLedgerStore::new(
            Box::new(mem),
            tl_id,
            EntityId::new(),
            sk,
            registry,
            identity,
            Box::new(Blake3Hasher),
        )?;
        let err = store.load("2026-07-25").err().ok_or("expected error")?;
        assert!(matches!(err, LedgerError::Store(_)));
        Ok(())
    }

    #[test]
    fn resolve_fails_on_missing_timeline() -> Result<(), Box<dyn std::error::Error>> {
        let (sk, _vk) = pos_crypto::signing::generate_keypair();
        let (registry, identity) = registry_for(&sk)?;
        let mem = MemoryStore::new();
        let tl_id = pos_core::ids::TimelineId::new();
        let mut store = EventLedgerStore::new(
            Box::new(mem),
            tl_id,
            EntityId::new(),
            sk,
            registry,
            identity,
            Box::new(Blake3Hasher),
        )?;
        let err = store
            .resolve(LedgerOutcome::try_new(
                "01J3B0Y5ZK2J6MGK8D7QW3N0P9".to_owned(),
                true,
                "2026-07-30T09:00:00Z".to_owned(),
            )?)
            .err()
            .ok_or("expected error")?;
        assert!(matches!(err, LedgerError::Store(_)));
        Ok(())
    }

    #[test]
    fn store_err_converts_core_error() {
        let core_err = pos_core::CoreError::Storage("test".into());
        let result: LedgerError = core_err.into();
        assert!(matches!(result, LedgerError::Store(_)));
        assert!(result.to_string().contains("store error"));
    }

    #[test]
    fn register_fails_on_missing_timeline() -> Result<(), Box<dyn std::error::Error>> {
        let (sk, _vk) = pos_crypto::signing::generate_keypair();
        let (registry, identity) = registry_for(&sk)?;
        let mem = MemoryStore::new();
        let tl_id = pos_core::ids::TimelineId::new();
        let mut store = EventLedgerStore::new(
            Box::new(mem),
            tl_id,
            EntityId::new(),
            sk,
            registry,
            identity,
            Box::new(Blake3Hasher),
        )?;
        let err = store
            .register(contract::sample_new_prediction("2026-08-01"))
            .err()
            .ok_or("expected error")?;
        assert!(matches!(err, LedgerError::Store(_)));
        Ok(())
    }
}
