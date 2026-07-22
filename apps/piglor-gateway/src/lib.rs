#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]
//! `piglor-gateway` — Wave 6 local-first HTTP/WebSocket gateway (ADR-014 / #69).
//!
//! JSON HTTP envelope; CBOR payloads into [`EventStore`]. No auth in this slice.
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

mod http;

pub use http::{router, AppState};

use pos_core::{
    clock::Seq,
    event::{CanonicalBytes, Event, EventDraft, Kind},
    ids::{EntityId, TimelineId},
    store::{EventStore, SeqRange},
    timeline::Timeline,
    CoreError,
};
use pos_plugin_society::{draft_signal, SocietyDimension, SocietySignal, EVENT_TYPE_SIGNAL};
use pos_plugin_world::EVENT_TYPE_ACTION;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::{broadcast, Mutex};
use ulid::Ulid;

/// Default broadcast channel capacity for live event fan-out.
pub const EVENT_BUS_CAPACITY: usize = 256;

/// Shared gateway handle (async store mutex + live event bus).
#[derive(Clone)]
pub struct Gateway {
    store: Arc<Mutex<Box<dyn EventStore>>>,
    bus: broadcast::Sender<EventNotice>,
}

/// JSON notice pushed on the event bus / WebSocket.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventNotice {
    pub timeline_id: String,
    pub event_id: String,
    pub entity_id: String,
    pub event_type: String,
    pub seq: u64,
}

/// API / domain errors for the gateway library.
#[derive(Debug, Error)]
pub enum GatewayError {
    /// Malformed ULID path/body field.
    #[error("invalid id: {0}")]
    InvalidId(String),
    /// Unsupported action event type.
    #[error("unsupported action type: {0}")]
    UnsupportedAction(String),
    /// JSON→CBOR / body encode failure.
    #[error("encode error: {0}")]
    Encode(String),
    /// Underlying store failure.
    #[error(transparent)]
    Store(#[from] CoreError),
}

impl Gateway {
    /// Wrap an existing store backend.
    #[must_use]
    pub fn new(store: Box<dyn EventStore>) -> Self {
        let (bus, _) = broadcast::channel(EVENT_BUS_CAPACITY);
        Self {
            store: Arc::new(Mutex::new(store)),
            bus,
        }
    }

    /// Subscribe to live append notices (WebSocket / tests).
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<EventNotice> {
        self.bus.subscribe()
    }

    /// Create a root timeline.
    ///
    /// # Errors
    /// Returns [`GatewayError::Store`] on backend failure.
    pub async fn create_timeline(&self, name: &str) -> Result<Timeline, GatewayError> {
        let mut guard = self.store.lock().await;
        Ok(guard.create_timeline(name)?)
    }

    /// Poll events on a timeline starting at `from_seq` (inclusive).
    ///
    /// # Errors
    /// Returns [`GatewayError::InvalidId`] or [`GatewayError::Store`].
    pub async fn read_events_from(
        &self,
        timeline_id: &str,
        from_seq: u64,
    ) -> Result<Vec<Event>, GatewayError> {
        let id = parse_timeline_id(timeline_id)?;
        let range = SeqRange {
            from: Seq::from_u64(from_seq),
            to: None,
        };
        let guard = self.store.lock().await;
        Ok(guard.read(id, range)?)
    }

    /// Append one `world.action` draft. `payload` is arbitrary JSON → CBOR.
    ///
    /// # Errors
    /// Returns store / id / unsupported-type errors.
    pub async fn append_action(
        &self,
        timeline_id: &str,
        entity_id: &str,
        event_type: &str,
        payload: &serde_json::Value,
    ) -> Result<Event, GatewayError> {
        if event_type != EVENT_TYPE_ACTION {
            return Err(GatewayError::UnsupportedAction(event_type.to_owned()));
        }
        let timeline = parse_timeline_id(timeline_id)?;
        let entity = parse_entity_id(entity_id)?;
        let bytes = json_to_cbor(payload);
        let draft = EventDraft::new(entity, Kind::new(EVENT_TYPE_ACTION), bytes);
        self.append_draft(timeline, draft).await
    }

    /// Append one `society.signal` (fan-out convenience for #71).
    ///
    /// # Errors
    /// Returns encode / store / id errors.
    pub async fn append_signal(
        &self,
        timeline_id: &str,
        entity_id: &str,
        signal: &SocietySignal,
    ) -> Result<Event, GatewayError> {
        let timeline = parse_timeline_id(timeline_id)?;
        let entity = parse_entity_id(entity_id)?;
        let draft = draft_signal(entity, signal);
        debug_assert_eq!(draft.event_type.as_str(), EVENT_TYPE_SIGNAL);
        self.append_draft(timeline, draft).await
    }

    async fn append_draft(
        &self,
        timeline: TimelineId,
        draft: EventDraft,
    ) -> Result<Event, GatewayError> {
        // Release the store lock before bus fan-out so future WS handlers can
        // re-enter the store without deadlocking on the same task.
        let event = {
            let mut guard = self.store.lock().await;
            let mut committed = guard.append(timeline, &[draft])?;
            committed
                .pop()
                .ok_or_else(|| GatewayError::Store(CoreError::Storage("empty append".to_owned())))?
        };
        let notice = EventNotice {
            timeline_id: timeline.to_string(),
            event_id: event.id.to_string(),
            entity_id: event.entity.to_string(),
            event_type: event.event_type.as_str().to_owned(),
            seq: event.seq.as_u64(),
        };
        let _ = self.bus.send(notice);
        Ok(event)
    }
}

fn parse_timeline_id(s: &str) -> Result<TimelineId, GatewayError> {
    Ulid::from_string(s)
        .map(TimelineId::from_ulid)
        .map_err(|e| GatewayError::InvalidId(e.to_string()))
}

fn parse_entity_id(s: &str) -> Result<EntityId, GatewayError> {
    Ulid::from_string(s)
        .map(EntityId::from_ulid)
        .map_err(|e| GatewayError::InvalidId(e.to_string()))
}

fn json_to_cbor(value: &serde_json::Value) -> CanonicalBytes {
    let mut buf = Vec::new();
    // Writing CBOR to Vec<u8> is infallible (same as plugins / pos-crypto).
    ciborium::into_writer(value, &mut buf).expect("ciborium write to Vec<u8> is infallible");
    CanonicalBytes::from_vec(buf)
}

/// Request body for `POST /v1/timelines`.
#[derive(Debug, Deserialize)]
pub struct CreateTimelineRequest {
    pub name: String,
}

/// Request body for `POST /v1/timelines/:id/actions`.
#[derive(Debug, Deserialize)]
pub struct ActionRequest {
    pub entity_id: String,
    /// Must be `world.action` in this MVP slice.
    #[serde(default = "default_action_type")]
    pub event_type: String,
    pub payload: serde_json::Value,
}

fn default_action_type() -> String {
    EVENT_TYPE_ACTION.to_owned()
}

/// Request body for `POST /v1/timelines/:id/signals`.
#[derive(Debug, Deserialize)]
pub struct SignalRequest {
    pub entity_id: String,
    pub dimension: SocietyDimension,
    pub value: f64,
    pub subject: Option<String>,
    pub object: Option<String>,
}

impl SignalRequest {
    fn into_signal(self) -> SocietySignal {
        SocietySignal {
            dimension: self.dimension,
            value: self.value,
            subject: self.subject,
            object: self.object,
        }
    }
}

/// Query for `GET /v1/timelines/:id/events`.
#[derive(Debug, Deserialize)]
pub struct EventsQuery {
    #[serde(default)]
    pub from_seq: u64,
}

/// JSON view of a committed event.
///
/// `payload` is the decoded CBOR body when it round-trips as JSON (actions posted
/// via this gateway). `payload_hex` is always the canonical stored bytes (lowercase hex).
#[derive(Debug, Serialize)]
pub struct EventView {
    pub id: String,
    pub entity: String,
    pub event_type: String,
    pub seq: u64,
    /// Decoded JSON when the stored CBOR payload is JSON-compatible; omitted otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<serde_json::Value>,
    /// Canonical CBOR bytes as lowercase hex (for clients that decode CBOR themselves).
    pub payload_hex: String,
}

impl From<&Event> for EventView {
    fn from(event: &Event) -> Self {
        let bytes = event.payload.as_slice();
        Self {
            id: event.id.to_string(),
            entity: event.entity.to_string(),
            event_type: event.event_type.as_str().to_owned(),
            seq: event.seq.as_u64(),
            payload: decode_cbor_json(bytes),
            payload_hex: hex_encode(bytes),
        }
    }
}

fn decode_cbor_json(bytes: &[u8]) -> Option<serde_json::Value> {
    ciborium::from_reader(bytes).ok()
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use pos_core::{
        clock::{Seq, WallTime},
        crypto::Hash,
        ids::EventId,
        timeline::TimelineMeta,
    };
    use pos_store::{open_store, StoreConfig};
    use std::sync::Arc;
    use tokio::sync::{broadcast, Mutex};

    fn memory_gw() -> Gateway {
        Gateway::new(open_store(StoreConfig::Memory).unwrap())
    }

    #[derive(Clone, Copy)]
    enum ScriptMode {
        FailCreate,
        EmptyAppend,
        FailAppend,
        FailRead,
    }

    struct ScriptedStore {
        mode: ScriptMode,
    }

    impl EventStore for ScriptedStore {
        fn create_timeline(&mut self, name: &str) -> Result<Timeline, CoreError> {
            if matches!(self.mode, ScriptMode::FailCreate) {
                return Err(CoreError::Storage("create failed".into()));
            }
            Ok(Timeline::new(TimelineMeta::root(name)))
        }

        fn append(
            &mut self,
            _timeline: TimelineId,
            drafts: &[EventDraft],
        ) -> Result<Vec<Event>, CoreError> {
            if matches!(self.mode, ScriptMode::FailAppend) {
                return Err(CoreError::Storage("append failed".into()));
            }
            if matches!(self.mode, ScriptMode::EmptyAppend) {
                return Ok(Vec::new());
            }
            Ok(drafts
                .iter()
                .enumerate()
                .map(|(i, d)| Event {
                    id: EventId::new(),
                    entity: d.entity,
                    event_type: d.event_type.clone(),
                    payload: d.payload.clone(),
                    wall_time: d.wall_time.unwrap_or_else(WallTime::now),
                    seq: Seq::from_u64(i as u64 + 1),
                    causation_id: d.causation_id,
                    correlation_id: d.correlation_id,
                    schema_version: d.schema_version,
                    signature: None,
                    payload_hash: Hash::from_bytes([0u8; 32]),
                })
                .collect())
        }

        fn read(&self, _timeline: TimelineId, _range: SeqRange) -> Result<Vec<Event>, CoreError> {
            if matches!(self.mode, ScriptMode::FailRead) {
                return Err(CoreError::Storage("read failed".into()));
            }
            Ok(Vec::new())
        }

        fn fork(
            &mut self,
            _parent: TimelineId,
            _at_seq: Seq,
            _name: &str,
        ) -> Result<Timeline, CoreError> {
            Ok(Timeline::new(TimelineMeta::root("fork")))
        }

        fn list_timelines(&self) -> Result<Vec<Timeline>, CoreError> {
            Ok(Vec::new())
        }

        fn get_timeline(&self, _id: TimelineId) -> Result<Option<Timeline>, CoreError> {
            Ok(None)
        }
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn create_timeline_and_append_action_roundtrip() {
        let gw = memory_gw();
        let tl = gw.create_timeline("demo").await.unwrap();
        let entity = EntityId::new().to_string();
        let event = gw
            .append_action(
                &tl.id().to_string(),
                &entity,
                EVENT_TYPE_ACTION,
                &serde_json::json!({"dx": 1.0, "dy": 0.0}),
            )
            .await
            .unwrap();
        assert_eq!(event.event_type.as_str(), EVENT_TYPE_ACTION);
        let events = gw.read_events_from(&tl.id().to_string(), 0).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id, event.id);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn append_action_rejects_other_types() {
        let gw = memory_gw();
        let tl = gw.create_timeline("demo").await.unwrap();
        let err = gw
            .append_action(
                &tl.id().to_string(),
                &EntityId::new().to_string(),
                "world.observation",
                &serde_json::json!({}),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, GatewayError::UnsupportedAction(_)));
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn append_signal_and_bus_notice() {
        let gw = memory_gw();
        let mut rx = gw.subscribe();
        let tl = gw.create_timeline("society").await.unwrap();
        let signal = SocietySignal {
            dimension: SocietyDimension::Trust,
            value: 0.8,
            subject: None,
            object: None,
        };
        let event = gw
            .append_signal(&tl.id().to_string(), &EntityId::new().to_string(), &signal)
            .await
            .unwrap();
        let notice = rx.try_recv().unwrap();
        assert_eq!(notice.event_id, event.id.to_string());
        assert_eq!(notice.event_type, EVENT_TYPE_SIGNAL);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn invalid_ids_error() {
        let gw = memory_gw();
        let err = gw.read_events_from("not-a-ulid", 0).await.unwrap_err();
        assert!(matches!(err, GatewayError::InvalidId(_)));
        let err = gw
            .append_action(
                "not-a-ulid",
                &EntityId::new().to_string(),
                EVENT_TYPE_ACTION,
                &serde_json::json!({}),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, GatewayError::InvalidId(_)));
        let tl = gw.create_timeline("ids").await.unwrap();
        let err = gw
            .append_action(
                &tl.id().to_string(),
                "not-a-ulid",
                EVENT_TYPE_ACTION,
                &serde_json::json!({}),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, GatewayError::InvalidId(_)));
        let err = gw
            .append_signal(
                &tl.id().to_string(),
                "not-a-ulid",
                &SocietySignal {
                    dimension: SocietyDimension::Trust,
                    value: 0.1,
                    subject: None,
                    object: None,
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, GatewayError::InvalidId(_)));
        let err = gw
            .append_signal(
                "not-a-ulid",
                &EntityId::new().to_string(),
                &SocietySignal {
                    dimension: SocietyDimension::Trust,
                    value: 0.1,
                    subject: None,
                    object: None,
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, GatewayError::InvalidId(_)));
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn store_error_paths() {
        let fail_create = Gateway {
            store: Arc::new(Mutex::new(Box::new(ScriptedStore {
                mode: ScriptMode::FailCreate,
            }))),
            bus: broadcast::channel(EVENT_BUS_CAPACITY).0,
        };
        assert!(matches!(
            fail_create.create_timeline("x").await,
            Err(GatewayError::Store(_))
        ));

        let empty_append = Gateway {
            store: Arc::new(Mutex::new(Box::new(ScriptedStore {
                mode: ScriptMode::EmptyAppend,
            }))),
            bus: broadcast::channel(EVENT_BUS_CAPACITY).0,
        };
        let tl = empty_append.create_timeline("e").await.unwrap();
        let err = empty_append
            .append_action(
                &tl.id().to_string(),
                &EntityId::new().to_string(),
                EVENT_TYPE_ACTION,
                &serde_json::json!({}),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, GatewayError::Store(_)));

        let fail_append = Gateway {
            store: Arc::new(Mutex::new(Box::new(ScriptedStore {
                mode: ScriptMode::FailAppend,
            }))),
            bus: broadcast::channel(EVENT_BUS_CAPACITY).0,
        };
        let tl = fail_append.create_timeline("a").await.unwrap();
        let err = fail_append
            .append_action(
                &tl.id().to_string(),
                &EntityId::new().to_string(),
                EVENT_TYPE_ACTION,
                &serde_json::json!({}),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, GatewayError::Store(_)));

        let fail_read = Gateway {
            store: Arc::new(Mutex::new(Box::new(ScriptedStore {
                mode: ScriptMode::FailRead,
            }))),
            bus: broadcast::channel(EVENT_BUS_CAPACITY).0,
        };
        let err = fail_read
            .read_events_from(&TimelineId::new().to_string(), 0)
            .await
            .unwrap_err();
        assert!(matches!(err, GatewayError::Store(_)));
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn event_view_and_hex() {
        let gw = memory_gw();
        let tl = gw.create_timeline("x").await.unwrap();
        let event = gw
            .append_action(
                &tl.id().to_string(),
                &EntityId::new().to_string(),
                EVENT_TYPE_ACTION,
                &serde_json::json!({"k": "v"}),
            )
            .await
            .unwrap();
        let view = EventView::from(&event);
        assert_eq!(view.event_type, EVENT_TYPE_ACTION);
        assert!(!view.payload_hex.is_empty());
        assert_eq!(view.payload, Some(serde_json::json!({"k": "v"})));
        assert_eq!(hex_encode(&[0x0a, 0xfb]), "0afb");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn decode_cbor_json_roundtrip() {
        let value = serde_json::json!({"n": 1});
        let bytes = json_to_cbor(&value);
        assert_eq!(decode_cbor_json(bytes.as_slice()), Some(value));
        assert!(decode_cbor_json(&[0xff]).is_none());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn signal_request_into_signal() {
        let req = SignalRequest {
            entity_id: EntityId::new().to_string(),
            dimension: SocietyDimension::Opinion,
            value: 0.5,
            subject: Some("a".into()),
            object: None,
        };
        let signal = req.into_signal();
        assert_eq!(signal.dimension, SocietyDimension::Opinion);
        assert!((signal.value - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn gateway_error_display() {
        let e = GatewayError::Encode("boom".into());
        assert!(e.to_string().contains("encode"));
        let e = GatewayError::UnsupportedAction("x".into());
        assert!(e.to_string().contains("unsupported"));
    }
}
