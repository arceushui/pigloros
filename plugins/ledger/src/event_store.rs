use ed25519_dalek::SigningKey;

use pos_core::{
    clock::{Seq, WallTime},
    event::{CanonicalBytes, Event, Kind, SchemaVersion},
    ids::{EntityId, EventId},
    store::{EventStore, SeqRange},
};
use pos_crypto::{chain::hash_payload, signing::sign};

use crate::{
    payload::{decode_outcome, decode_prediction, EVENT_TYPE_OUTCOME, EVENT_TYPE_PREDICTION},
    store::{validate_outcome, LedgerStore, NewPrediction},
    Ledger, LedgerError, LedgerOutcome, LedgerPrediction,
};

fn store_err(e: pos_core::CoreError) -> LedgerError {
    LedgerError::Store(e.to_string())
}

pub struct EventLedgerStore {
    store: Box<dyn EventStore>,
    timeline_id: pos_core::ids::TimelineId,
    entity: EntityId,
    signing_key: SigningKey,
}

impl EventLedgerStore {
    #[must_use]
    pub fn new(
        store: Box<dyn EventStore>,
        timeline_id: pos_core::ids::TimelineId,
        entity: EntityId,
        signing_key: SigningKey,
    ) -> Self {
        Self {
            store,
            timeline_id,
            entity,
            signing_key,
        }
    }

    fn head_seq(&self) -> Result<Seq, LedgerError> {
        self.store
            .get_timeline(self.timeline_id)
            .map_err(store_err)?
            .map(|tl| tl.head)
            .ok_or_else(|| LedgerError::Store("timeline not found".into()))
    }

    fn append_signed(
        &mut self,
        payload: CanonicalBytes,
        event_type: Kind,
    ) -> Result<(), LedgerError> {
        let head = self.head_seq()?;
        let payload_hash = hash_payload(&payload);
        let signature = sign(&self.signing_key, &payload);

        let event = Event {
            id: EventId::new(),
            entity: self.entity,
            event_type,
            payload,
            wall_time: WallTime::now(),
            seq: head.next(),
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: Some(signature),
            payload_hash,
        };

        self.store
            .append_committed(self.timeline_id, &[event])
            .map_err(store_err)
    }
}

impl LedgerStore for EventLedgerStore {
    fn load(&self, today: &str) -> Result<Ledger, LedgerError> {
        let events = self
            .store
            .read(self.timeline_id, SeqRange::all())
            .map_err(store_err)?;

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
        let prediction = new.into_prediction(ulid::Ulid::gen().to_string());

        let mut buf = Vec::new();
        ciborium::into_writer(&prediction, &mut buf)
            .expect("ciborium write to Vec<u8> is infallible");
        let payload = CanonicalBytes::from_vec(buf);

        self.append_signed(payload, Kind::new(EVENT_TYPE_PREDICTION))?;
        Ok(prediction.prediction_id)
    }

    fn resolve(
        &mut self,
        prediction_id: &str,
        outcome: bool,
        resolved_at: &str,
    ) -> Result<(), LedgerError> {
        let resolution = LedgerOutcome {
            prediction_id: prediction_id.to_owned(),
            outcome,
            resolved_at: resolved_at.to_owned(),
        };
        validate_outcome(&resolution)?;

        let events = self
            .store
            .read(self.timeline_id, SeqRange::all())
            .map_err(store_err)?;

        let mut found_prediction = false;
        let mut already_resolved = false;

        for event in &events {
            match event.event_type.as_str() {
                EVENT_TYPE_PREDICTION => {
                    if let Ok(pred) = decode_prediction(event.payload.as_slice()) {
                        if pred.prediction_id == prediction_id {
                            found_prediction = true;
                        }
                    }
                }
                EVENT_TYPE_OUTCOME => {
                    if let Ok(res) = decode_outcome(event.payload.as_slice()) {
                        if res.prediction_id == prediction_id {
                            already_resolved = true;
                        }
                    }
                }
                _ => {}
            }
        }

        if !found_prediction {
            return Err(LedgerError::UnknownPrediction(prediction_id.to_owned()));
        }
        if already_resolved {
            return Err(LedgerError::AlreadyResolved(prediction_id.to_owned()));
        }

        let mut buf = Vec::new();
        ciborium::into_writer(&resolution, &mut buf)
            .expect("ciborium write to Vec<u8> is infallible");

        self.append_signed(CanonicalBytes::from_vec(buf), Kind::new(EVENT_TYPE_OUTCOME))
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::contract;
    use pos_store::memory::MemoryStore;

    fn make_store() -> EventLedgerStore {
        let (sk, _vk) = pos_crypto::signing::generate_keypair();
        let mut mem = MemoryStore::new();
        let tl = mem.create_timeline("ledger").unwrap();
        EventLedgerStore::new(Box::new(mem), tl.id(), EntityId::new(), sk)
    }

    #[test]
    fn port_contract() {
        contract::run(&mut |_path| Box::new(make_store()) as Box<dyn LedgerStore>);
    }

    #[test]
    fn load_empty_ledger() {
        let store = make_store();
        let ledger = store.load("2026-07-25").unwrap();
        assert!(ledger.entries().is_empty());
    }

    #[test]
    fn register_and_load() {
        let mut store = make_store();
        let id = store
            .register(contract::sample_new_prediction("2026-08-01"))
            .unwrap();
        let ledger = store.load("2026-07-25").unwrap();
        assert_eq!(ledger.entries().len(), 1);
        assert_eq!(ledger.entries()[0].prediction.prediction_id, id);
    }

    #[test]
    fn resolve_and_load() {
        let mut store = make_store();
        let id = store
            .register(contract::sample_new_prediction("2026-08-01"))
            .unwrap();
        store.resolve(&id, true, "2026-07-30T09:00:00Z").unwrap();
        let ledger = store.load("2026-07-25").unwrap();
        assert_eq!(ledger.entries().len(), 1);
        assert_eq!(ledger.entries()[0].status.as_str(), "resolved");
    }

    #[test]
    fn double_resolve_rejected() {
        let mut store = make_store();
        let id = store
            .register(contract::sample_new_prediction("2026-08-01"))
            .unwrap();
        store.resolve(&id, true, "2026-07-30T09:00:00Z").unwrap();
        let err = store
            .resolve(&id, false, "2026-07-31T09:00:00Z")
            .unwrap_err();
        assert!(matches!(err, LedgerError::AlreadyResolved(_)));
    }

    #[test]
    fn unknown_prediction_rejected() {
        let mut store = make_store();
        let err = store
            .resolve("01J3B0Y5ZK2J6MGK8D7QW3N0P9", true, "2026-07-30T09:00:00Z")
            .unwrap_err();
        assert!(matches!(err, LedgerError::UnknownPrediction(_)));
    }

    #[test]
    fn events_are_signed() {
        let mut store = make_store();
        store
            .register(contract::sample_new_prediction("2026-08-01"))
            .unwrap();
        let events = store
            .store
            .read(store.timeline_id, SeqRange::all())
            .unwrap();
        assert_eq!(events.len(), 1);
        assert!(events[0].signature.is_some(), "event must be signed");
    }

    #[test]
    fn load_orphan_outcome_returns_error() {
        let mut store = make_store();
        let head = store
            .store
            .get_timeline(store.timeline_id)
            .unwrap()
            .unwrap()
            .head;
        let outcome = LedgerOutcome {
            prediction_id: "01J3B0Y5ZK2J6MGK8D7QW3N0P9".to_owned(),
            outcome: true,
            resolved_at: "2026-07-30T09:00:00Z".to_owned(),
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&outcome, &mut buf).unwrap();
        let payload = CanonicalBytes::from_vec(buf);
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
            payload_hash,
        };
        store
            .store
            .append_committed(store.timeline_id, &[event])
            .unwrap();
        let err = store.load("2026-07-25").unwrap_err();
        assert!(matches!(err, LedgerError::OrphanResolution(_)));
    }

    #[test]
    fn load_skips_unknown_event_types() {
        let mut store = make_store();
        let head = store
            .store
            .get_timeline(store.timeline_id)
            .unwrap()
            .unwrap()
            .head;
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
            payload_hash,
        };
        store
            .store
            .append_committed(store.timeline_id, &[event])
            .unwrap();
        let ledger = store.load("2026-07-25").unwrap();
        assert!(ledger.entries().is_empty());
    }

    #[test]
    fn resolve_skips_decode_error_prediction() {
        let mut store = make_store();
        let head = store
            .store
            .get_timeline(store.timeline_id)
            .unwrap()
            .unwrap()
            .head;
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
            payload_hash,
        };
        store
            .store
            .append_committed(store.timeline_id, &[event])
            .unwrap();
        let err = store
            .resolve("01J3B0Y5ZK2J6MGK8D7QW3N0P9", true, "2026-07-30T09:00:00Z")
            .unwrap_err();
        assert!(matches!(err, LedgerError::UnknownPrediction(_)));
    }

    #[test]
    fn resolve_skips_decode_error_outcome() {
        let mut store = make_store();
        let id = store
            .register(contract::sample_new_prediction("2026-08-01"))
            .unwrap();
        let head = store
            .store
            .get_timeline(store.timeline_id)
            .unwrap()
            .unwrap()
            .head;
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
            payload_hash,
        };
        store
            .store
            .append_committed(store.timeline_id, &[event])
            .unwrap();
        let result = store.resolve(&id, true, "2026-07-30T09:00:00Z");
        assert!(result.is_ok(), "resolve should succeed: {result:?}");
    }

    #[test]
    fn resolve_skips_unknown_event_types() {
        let mut store = make_store();
        let id = store
            .register(contract::sample_new_prediction("2026-08-01"))
            .unwrap();
        let head = store
            .store
            .get_timeline(store.timeline_id)
            .unwrap()
            .unwrap()
            .head;
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
            payload_hash,
        };
        store
            .store
            .append_committed(store.timeline_id, &[event])
            .unwrap();
        store.resolve(&id, true, "2026-07-30T09:00:00Z").unwrap();
    }

    #[test]
    fn load_fails_on_missing_timeline() {
        let (sk, _vk) = pos_crypto::signing::generate_keypair();
        let mem = MemoryStore::new();
        let tl_id = pos_core::ids::TimelineId::new();
        let store = EventLedgerStore::new(Box::new(mem), tl_id, EntityId::new(), sk);
        let err = store.load("2026-07-25").unwrap_err();
        assert!(matches!(err, LedgerError::Store(_)));
    }

    #[test]
    fn resolve_fails_on_missing_timeline() {
        let (sk, _vk) = pos_crypto::signing::generate_keypair();
        let mem = MemoryStore::new();
        let tl_id = pos_core::ids::TimelineId::new();
        let mut store = EventLedgerStore::new(Box::new(mem), tl_id, EntityId::new(), sk);
        let err = store
            .resolve("01J3B0Y5ZK2J6MGK8D7QW3N0P9", true, "2026-07-30T09:00:00Z")
            .unwrap_err();
        assert!(matches!(err, LedgerError::Store(_)));
    }

    #[test]
    fn store_err_converts_core_error() {
        let core_err = pos_core::CoreError::Storage("test".into());
        let result = store_err(core_err);
        assert!(matches!(result, LedgerError::Store(_)));
        assert!(result.to_string().contains("store error"));
    }

    #[test]
    fn register_fails_on_missing_timeline() {
        let (sk, _vk) = pos_crypto::signing::generate_keypair();
        let mem = MemoryStore::new();
        let tl_id = pos_core::ids::TimelineId::new();
        let mut store = EventLedgerStore::new(Box::new(mem), tl_id, EntityId::new(), sk);
        let err = store
            .register(contract::sample_new_prediction("2026-08-01"))
            .unwrap_err();
        assert!(matches!(err, LedgerError::Store(_)));
    }
}
