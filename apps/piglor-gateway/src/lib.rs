#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]
//! `piglor-gateway` — Wave 6 local-first HTTP/WebSocket gateway (ADR-014 / #69).
//!
//! JSON HTTP envelope; CBOR payloads into [`EventStore`]. No auth in this slice.
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

mod http;
mod ledger_config;

pub use http::{router, spectator_router, AppState};
pub use ledger_config::{LedgerConfig, LedgerGateway, LedgerWriteMode};

use pos_core::{
    clock::Seq,
    event::{CanonicalBytes, Event, EventDraft, Kind},
    ids::{EntityId, TimelineId},
    store::{
        AppendDedupKey, AppendDedupScope, AppendIdentity, AppendIntent, AppendOrDuplicateOutcome,
        EventReadBounds, EventStore, PurgeOutcome, SeqRange,
    },
    timeline::Timeline,
    CoreError,
};
use pos_plugin_society::{draft_signal, SocietyDimension, SocietySignal, EVENT_TYPE_SIGNAL};
use pos_plugin_world::EVENT_TYPE_ACTION;
use serde::{Deserialize, Serialize};
use std::num::NonZeroUsize;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::{broadcast, Mutex};
use ulid::Ulid;

/// Pre-registered Prediction Ledger entry view (Redmine #58 / OKR KR4.6).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LedgerEntryView {
    pub id: String,
    pub scenario: String,
    pub title: String,
    pub predicted_outcome: String,
    pub confidence: f64,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub brier_score: Option<f64>,
    pub verification_hash: String,
    pub timestamp: String,
}

/// Maximum JSON request body size for HTTP handlers (1 MiB).
pub const MAX_HTTP_BODY_BYTES: usize = 1024 * 1024;

/// Maximum canonical payload accepted for one Gateway-authored Event (256 KiB).
pub const MAX_EVENT_PAYLOAD_BYTES: usize = 256 * 1024;

/// Maximum UTF-8 byte length accepted for imported Event type metadata (64 KiB).
///
/// At JSON's worst-case six-byte escaping expansion this occupies at most
/// 384 KiB. Together with the maximum payload's 512 KiB hex representation
/// and fixed Event fields, it remains below the 1 MiB response envelope.
/// The exact serialized-response check still governs decoded payload expansion.
pub const MAX_EVENT_TYPE_BYTES: usize = 64 * 1024;

/// Maximum number of parent links traversed by one bounded Event poll.
pub const MAX_FORK_DEPTH: usize = 64;

/// Maximum serialized JSON size for one Event polling response (1 MiB).
pub const MAX_EVENTS_RESPONSE_BYTES: usize = 1024 * 1024;

/// Maximum number of Timeline events returned by one poll.
pub const MAX_EVENTS_PER_POLL: usize = 100;

/// Maximum number of root Timelines managed by one local Gateway process.
pub const MAX_TIMELINES: usize = 64;

/// Maximum number of owned events accepted for one Timeline by one Gateway process.
pub const MAX_EVENTS_PER_TIMELINE: u64 = 10_000;

/// Default broadcast channel capacity for live event fan-out.
pub const EVENT_BUS_CAPACITY: usize = 256;

/// Shared Gateway handle (async store mutex + live Event bus).
///
/// The supported local-first write boundary is one `Gateway` instance per store:
/// its mutex makes each owned-Event ceiling check and append one critical section.
/// Concurrent mutation through another process is outside this contract.
#[derive(Clone)]
pub struct Gateway {
    store: Arc<Mutex<Box<dyn EventStore>>>,
    bus: broadcast::Sender<EventNotice>,
    limits: GatewayLimits,
}

/// Resource bounds applied by the local-first Gateway process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct GatewayLimits {
    max_timelines: usize,
    max_events_per_timeline: u64,
}

impl GatewayLimits {
    const LOCAL_DEFAULT: Self = Self {
        max_timelines: MAX_TIMELINES,
        max_events_per_timeline: MAX_EVENTS_PER_TIMELINE,
    };
}

/// A bounded page of Timeline Events.
///
/// `next_from_seq` is the inclusive sequence of the first omitted Event, or
/// `None` only when the requested Timeline is exhausted.
#[derive(Debug, PartialEq)]
pub struct EventPage {
    pub events: Vec<Event>,
    pub next_from_seq: Option<Seq>,
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

/// Result of an identified Gateway append.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentifiedAppend {
    pub event: Event,
    pub duplicate: bool,
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
    /// An ingress identity was reused with a different canonical intent.
    #[error("ingress identity conflicts with retained canonical intent")]
    IngressConflict,
    /// Requested poll page is outside the Gateway bounds.
    #[error("event poll limit must be between 1 and {maximum}")]
    InvalidPageLimit { maximum: usize },
    /// This Gateway process has reached its Timeline bound.
    #[error("timeline limit of {maximum} reached")]
    TimelineLimitReached { maximum: usize },
    /// The Timeline has reached its event bound.
    #[error("event limit of {maximum} reached")]
    EventLimitReached { maximum: u64 },
    /// A Gateway-authored Event payload exceeds the retrievable size budget.
    #[error("event payload exceeds maximum of {maximum} bytes")]
    EventPayloadTooLarge { maximum: usize },
    /// Imported Event metadata exceeds the retrievable size budget.
    #[error("event metadata field {field} exceeds maximum of {maximum} bytes")]
    EventMetadataTooLarge { field: &'static str, maximum: usize },
    /// An imported Fork chain exceeds the bounded polling traversal budget.
    #[error("fork depth exceeds maximum of {maximum}")]
    ForkDepthTooLarge { maximum: usize },
    /// Malformed event polling query.
    #[error("invalid events query: {0}")]
    InvalidEventsQuery(String),
    /// A single stored Event cannot fit in a bounded response.
    #[error("event response exceeds maximum of {maximum} bytes")]
    EventResponseTooLarge { maximum: usize },
    /// The deprecated aggregate-style read would silently truncate Events.
    #[error("compatibility read exceeds its bounded page of {maximum} events")]
    CompatibilityReadTruncated { maximum: usize },
    /// Underlying store failure.
    #[error(transparent)]
    Store(#[from] CoreError),
    /// Ledger domain error.
    #[error(transparent)]
    Ledger(#[from] pos_plugin_ledger::LedgerError),
    /// Ledger prediction write is disabled (feature gate off).
    #[error("ledger write is disabled (set LEDGER_WRITE=1)")]
    LedgerWriteDisabled,
    /// Ledger store is not configured.
    #[error("ledger store not available")]
    LedgerUnavailable,
}

impl Gateway {
    /// Wrap an existing store backend.
    #[must_use]
    pub fn new(store: Box<dyn EventStore>) -> Self {
        let (bus, _) = broadcast::channel(EVENT_BUS_CAPACITY);
        Self {
            store: Arc::new(Mutex::new(store)),
            bus,
            limits: GatewayLimits::LOCAL_DEFAULT,
        }
    }

    /// Subscribe to live append notices (WebSocket / tests).
    ///
    /// Slow subscribers can see [`broadcast::error::RecvError::Lagged`]; resync via
    /// the bounded HTTP poll — the store is authoritative.
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<EventNotice> {
        self.bus.subscribe()
    }

    /// Run one bounded deduplication-maintenance pass.
    ///
    /// The server lifecycle supervisor owns scheduling and readiness; this
    /// method only holds the store lock for the bounded adapter operation.
    ///
    /// # Errors
    /// Returns [`GatewayError::Store`] when the bounded maintenance pass fails.
    pub async fn purge_expired_ingress_identities(
        &self,
        limit: NonZeroUsize,
    ) -> Result<PurgeOutcome, GatewayError> {
        let mut guard = self.store.lock().await;
        Ok(guard.purge_expired_append_identities_bounded(limit)?)
    }

    /// Create a root Timeline.
    ///
    /// Forks and imported child Timelines do not consume the root-Timeline ceiling.
    ///
    /// # Errors
    /// Returns [`GatewayError::Store`] on backend failure.
    pub async fn create_timeline(&self, name: &str) -> Result<Timeline, GatewayError> {
        let mut guard = self.store.lock().await;
        let root_count = guard.root_timeline_count_bounded(self.limits.max_timelines)?;
        if root_count >= self.limits.max_timelines {
            return Err(GatewayError::TimelineLimitReached {
                maximum: self.limits.max_timelines,
            });
        }
        Ok(guard.create_timeline(name)?)
    }

    /// Poll one bounded page of Timeline events, starting at `from_seq` (inclusive).
    ///
    /// The store is read for `limit + 1` Events. `next_from_seq` is `None` when
    /// exhausted; otherwise it is the inclusive sequence of the first omitted Event.
    ///
    /// # Errors
    /// Returns [`GatewayError::InvalidId`], [`GatewayError::InvalidPageLimit`], or
    /// [`GatewayError::Store`].
    ///
    /// ```no_run
    /// # async fn example(gateway: &piglor_gateway::Gateway, timeline: &str)
    /// # -> Result<(), piglor_gateway::GatewayError> {
    /// let page = gateway.read_events_page(timeline, 0, 100).await?;
    /// let _events = page.events;
    /// let _cursor = page.next_from_seq;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn read_events_page(
        &self,
        timeline_id: &str,
        from_seq: u64,
        limit: usize,
    ) -> Result<EventPage, GatewayError> {
        if limit == 0 || limit > MAX_EVENTS_PER_POLL {
            return Err(GatewayError::InvalidPageLimit {
                maximum: MAX_EVENTS_PER_POLL,
            });
        }
        let id = parse_timeline_id(timeline_id)?;
        let first_seq = from_seq.max(1);
        let last_seq = first_seq.saturating_add(limit as u64);
        let range = SeqRange {
            from: Seq::from_u64(first_seq),
            to: Some(Seq::from_u64(last_seq)),
        };
        let guard = self.store.lock().await;
        let bounds = EventReadBounds::new(
            MAX_EVENT_PAYLOAD_BYTES,
            MAX_EVENT_TYPE_BYTES,
            MAX_FORK_DEPTH,
            limit + 1,
        );
        let mut events = match guard.read_bounded(id, range, bounds) {
            Ok(events) => events,
            Err(CoreError::PayloadTooLarge { .. }) => {
                return Err(GatewayError::EventPayloadTooLarge {
                    maximum: MAX_EVENT_PAYLOAD_BYTES,
                })
            }
            Err(CoreError::EventMetadataTooLarge { field, .. }) => {
                return Err(GatewayError::EventMetadataTooLarge {
                    field,
                    maximum: MAX_EVENT_TYPE_BYTES,
                })
            }
            Err(CoreError::ForkDepthTooLarge { .. }) => {
                return Err(GatewayError::ForkDepthTooLarge {
                    maximum: MAX_FORK_DEPTH,
                })
            }
            Err(error) => return Err(GatewayError::Store(error)),
        };
        let next_from_seq = events
            .get(limit)
            .map(|event| Seq::from_u64(event_seq(event)));
        events.truncate(limit);
        Ok(EventPage {
            events,
            next_from_seq,
        })
    }

    /// Compatibility shim for Timelines that fit in one bounded page.
    ///
    /// This method no longer aggregates the Timeline to exhaustion. New callers
    /// must use [`Self::read_events_page`] and follow `next_from_seq`.
    ///
    /// # Errors
    /// Returns [`GatewayError::CompatibilityReadTruncated`] when more than one
    /// bounded page is available, in addition to the errors from
    /// [`Self::read_events_page`].
    #[deprecated(
        since = "0.1.0",
        note = "use read_events_page and follow EventPage::next_from_seq"
    )]
    pub async fn read_events_from(
        &self,
        timeline_id: &str,
        from_seq: u64,
    ) -> Result<Vec<Event>, GatewayError> {
        let page = self
            .read_events_page(timeline_id, from_seq, MAX_EVENTS_PER_POLL)
            .await?;
        if page.next_from_seq.is_some() {
            return Err(GatewayError::CompatibilityReadTruncated {
                maximum: MAX_EVENTS_PER_POLL,
            });
        }
        Ok(page.events)
    }

    /// Append one `world.action` draft. `payload` is bounded JSON → CBOR.
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

    /// Append an action using an opaque external ingress identity.
    ///
    /// The identity is hashed before it crosses the store boundary. The store
    /// owns admission time and compares only the canonical append intent, so
    /// generated Event metadata cannot turn a retry into a conflict.
    ///
    /// # Errors
    /// Returns an ID, payload, unsupported-action, conflict, or store error.
    pub async fn append_identified_action(
        &self,
        timeline_id: &str,
        entity_id: &str,
        event_type: &str,
        payload: &serde_json::Value,
        ingress_id: &str,
    ) -> Result<IdentifiedAppend, GatewayError> {
        if event_type != EVENT_TYPE_ACTION {
            return Err(GatewayError::UnsupportedAction(event_type.to_owned()));
        }
        let timeline = parse_timeline_id(timeline_id)?;
        let entity = parse_entity_id(entity_id)?;
        let draft = EventDraft::new(entity, Kind::new(EVENT_TYPE_ACTION), json_to_cbor(payload));
        if draft.payload.len() > MAX_EVENT_PAYLOAD_BYTES {
            return Err(GatewayError::EventPayloadTooLarge {
                maximum: MAX_EVENT_PAYLOAD_BYTES,
            });
        }
        if draft_event_response_len(&draft) > MAX_EVENTS_RESPONSE_BYTES {
            return Err(GatewayError::EventResponseTooLarge {
                maximum: MAX_EVENTS_RESPONSE_BYTES,
            });
        }
        let identity = ingress_identity(timeline, entity, ingress_id);
        let outcome = {
            let mut guard = self.store.lock().await;
            let timeline_meta = guard
                .get_timeline(timeline)?
                .ok_or(GatewayError::Store(CoreError::TimelineNotFound(timeline)))?;
            let _ = timeline_meta;
            guard
                .append_intent_or_duplicate_bounded(
                    timeline,
                    identity,
                    AppendIntent::new(&draft),
                    self.limits.max_events_per_timeline,
                )?
                .ok_or(GatewayError::EventLimitReached {
                    maximum: self.limits.max_events_per_timeline,
                })?
        };
        let (event, duplicate) = match outcome {
            AppendOrDuplicateOutcome::Appended(event) => (*event, false),
            AppendOrDuplicateOutcome::Duplicate { event_id } => {
                let event = self.read_event_by_id(timeline, event_id).await?;
                (event, true)
            }
            AppendOrDuplicateOutcome::Conflict => return Err(GatewayError::IngressConflict),
        };
        if !duplicate {
            self.publish_notice(timeline, &event);
        }
        Ok(IdentifiedAppend { event, duplicate })
    }

    /// Append one `society.signal` (fan-out convenience for #71).
    ///
    /// # Errors
    /// Returns store / id errors.
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

    /// The owned-Event ceiling uses this Timeline's store head. Logical Events
    /// inherited by a Fork are readable but do not consume the Fork's ceiling.
    async fn append_draft(
        &self,
        timeline: TimelineId,
        draft: EventDraft,
    ) -> Result<Event, GatewayError> {
        if draft.payload.as_slice().len() > MAX_EVENT_PAYLOAD_BYTES {
            return Err(GatewayError::EventPayloadTooLarge {
                maximum: MAX_EVENT_PAYLOAD_BYTES,
            });
        }
        if draft_event_response_len(&draft) > MAX_EVENTS_RESPONSE_BYTES {
            return Err(GatewayError::EventResponseTooLarge {
                maximum: MAX_EVENTS_RESPONSE_BYTES,
            });
        }
        // Release the store lock before bus fan-out so future WS handlers can
        // re-enter the store without deadlocking on the same task.
        let event = {
            let mut guard = self.store.lock().await;
            let timeline_meta = guard
                .get_timeline(timeline)?
                .ok_or(GatewayError::Store(CoreError::TimelineNotFound(timeline)))?;
            if timeline_meta.head.as_u64() >= self.limits.max_events_per_timeline {
                return Err(GatewayError::EventLimitReached {
                    maximum: self.limits.max_events_per_timeline,
                });
            }
            let mut committed = guard.append(timeline, &[draft])?;
            match committed.pop() {
                Some(event) => event,
                None => {
                    return Err(GatewayError::Store(CoreError::Storage(
                        "empty append".to_owned(),
                    )))
                }
            }
        };
        self.publish_notice(timeline, &event);
        Ok(event)
    }

    fn publish_notice(&self, timeline: TimelineId, event: &Event) {
        let notice = EventNotice {
            timeline_id: timeline.to_string(),
            event_id: event.id.to_string(),
            entity_id: event.entity.to_string(),
            event_type: event.event_type.as_str().to_owned(),
            seq: event.seq.as_u64(),
        };
        let _ = self.bus.send(notice);
    }

    async fn read_event_by_id(
        &self,
        timeline: TimelineId,
        event_id: pos_core::ids::EventId,
    ) -> Result<Event, GatewayError> {
        let guard = self.store.lock().await;
        guard
            .read_event_by_id(timeline, event_id)?
            .ok_or(GatewayError::Store(CoreError::Storage(
                "duplicate identity points to a missing Event".to_owned(),
            )))
    }

    #[cfg(test)]
    fn with_bus_capacity(store: Box<dyn EventStore>, capacity: usize) -> Self {
        Self {
            store: Arc::new(Mutex::new(store)),
            bus: broadcast::channel(capacity).0,
            limits: GatewayLimits::LOCAL_DEFAULT,
        }
    }

    #[cfg(test)]
    fn with_limits(store: Box<dyn EventStore>, limits: GatewayLimits) -> Self {
        Self {
            store: Arc::new(Mutex::new(store)),
            bus: broadcast::channel(EVENT_BUS_CAPACITY).0,
            limits,
        }
    }
}

fn ingress_identity(timeline: TimelineId, entity: EntityId, ingress_id: &str) -> AppendIdentity {
    // Derive each persisted digest in an independent BLAKE3 context.  The
    // Gateway never stores the caller's ingress identifier or its preimage;
    // the context strings provide a stable, domain-separated opaque seam
    // without inventing a process-wide secret or configuration value.
    let mut key = blake3::Hasher::new_derive_key("pigloros ingress dedup key v1");
    key.update(b"timeline:");
    key.update(timeline.to_string().as_bytes());
    key.update(b"\nentity:");
    key.update(entity.to_string().as_bytes());
    key.update(b"\ningress:");
    key.update(ingress_id.as_bytes());
    let mut scope = blake3::Hasher::new_derive_key("pigloros ingress dedup scope v1");
    scope.update(b"entity:");
    scope.update(entity.to_string().as_bytes());
    AppendIdentity::new(
        AppendDedupKey::from_keyed_hash(*key.finalize().as_bytes()),
        AppendDedupScope::from_keyed_hash(*scope.finalize().as_bytes()),
    )
}

fn event_seq(event: &Event) -> u64 {
    event.seq.as_u64()
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

/// Serialize the exact wire fields derived from a draft, using the longest
/// possible sequence number and fixed-width ULID placeholders.
fn draft_event_response_len(draft: &EventDraft) -> usize {
    let payload = draft.payload.as_slice();
    let view = EventView {
        id: "0".repeat(26),
        entity: draft.entity.to_string(),
        event_type: draft.event_type.as_str().to_owned(),
        seq: u64::MAX,
        payload: decode_cbor_json(payload),
        payload_hex: hex_encode(payload),
    };
    serde_json::to_vec(&serde_json::json!({
        "events": [view],
        "next_from_seq": u64::MAX,
    }))
    .expect("EventView serialization is infallible")
    .len()
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
    /// Optional external ingress identity for retry-safe append.
    #[serde(default)]
    pub ingress_id: Option<String>,
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

/// Validated query for `GET /v1/timelines/:id/events`.
#[derive(Debug, Deserialize, PartialEq, Eq)]
pub struct EventsQuery {
    pub from_seq: u64,
    pub limit: usize,
}

impl Default for EventsQuery {
    fn default() -> Self {
        Self {
            from_seq: 0,
            limit: MAX_EVENTS_PER_POLL,
        }
    }
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
        store::{export_timeline_own, import_timeline_with_id},
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
        FailList,
        FailGetTimeline,
        EmptyAppend,
        FailAppend,
        FailRead,
        RejectListUse,
        Duplicate,
        DuplicateReadError,
        MissingTimeline,
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
            assert!(
                !matches!(self.mode, ScriptMode::RejectListUse),
                "Gateway root quota must not materialise Timeline lists"
            );
            if matches!(self.mode, ScriptMode::FailList) {
                return Err(CoreError::Storage("list failed".into()));
            }
            Ok(Vec::new())
        }

        fn root_timeline_count_bounded(&self, _maximum: usize) -> Result<usize, CoreError> {
            if matches!(self.mode, ScriptMode::FailList) {
                return Err(CoreError::Storage("root count failed".into()));
            }
            Ok(0)
        }

        fn get_timeline(&self, _id: TimelineId) -> Result<Option<Timeline>, CoreError> {
            if matches!(self.mode, ScriptMode::FailGetTimeline) {
                return Err(CoreError::Storage("get timeline failed".into()));
            }
            if matches!(self.mode, ScriptMode::MissingTimeline) {
                return Ok(None);
            }
            Ok(Some(Timeline::new(TimelineMeta::root("scripted"))))
        }

        fn append_intent_or_duplicate_bounded(
            &mut self,
            _timeline: TimelineId,
            _identity: AppendIdentity,
            _intent: AppendIntent,
            _max_owned_events: u64,
        ) -> Result<Option<AppendOrDuplicateOutcome>, CoreError> {
            if matches!(
                self.mode,
                ScriptMode::Duplicate | ScriptMode::DuplicateReadError
            ) {
                return Ok(Some(AppendOrDuplicateOutcome::Duplicate {
                    event_id: EventId::new(),
                }));
            }
            Err(CoreError::Storage("scripted bounded append failed".into()))
        }

        fn read_event_by_id(
            &self,
            _timeline: TimelineId,
            _event_id: EventId,
        ) -> Result<Option<Event>, CoreError> {
            if matches!(self.mode, ScriptMode::DuplicateReadError) {
                return Err(CoreError::Storage("scripted event lookup failed".into()));
            }
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
        let page = gw
            .read_events_page(&tl.id().to_string(), 0, MAX_EVENTS_PER_POLL)
            .await
            .unwrap();
        assert_eq!(page.events.len(), 1);
        assert_eq!(page.events[0].id, event.id);
        assert_eq!(page.next_from_seq, None);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn gateway_enforces_timeline_and_event_bounds() {
        let timeline_limited = Gateway::with_limits(
            open_store(StoreConfig::Memory).unwrap(),
            GatewayLimits {
                max_timelines: 1,
                max_events_per_timeline: 2,
            },
        );
        timeline_limited.create_timeline("one").await.unwrap();
        let err = timeline_limited.create_timeline("two").await.unwrap_err();
        assert!(matches!(
            err,
            GatewayError::TimelineLimitReached { maximum: 1 }
        ));

        let event_limited = Gateway::with_limits(
            open_store(StoreConfig::Memory).unwrap(),
            GatewayLimits {
                max_timelines: 1,
                max_events_per_timeline: 1,
            },
        );
        let timeline = event_limited.create_timeline("events").await.unwrap();
        let timeline_id = timeline.id().to_string();
        let entity_id = EntityId::new().to_string();
        event_limited
            .append_action(
                &timeline_id,
                &entity_id,
                EVENT_TYPE_ACTION,
                &serde_json::json!({}),
            )
            .await
            .unwrap();
        let err = event_limited
            .append_action(
                &timeline_id,
                &entity_id,
                EVENT_TYPE_ACTION,
                &serde_json::json!({}),
            )
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            GatewayError::EventLimitReached { maximum: 1 }
        ));
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn root_limit_excludes_forks_and_imported_children() {
        let mut store = open_store(StoreConfig::Memory).unwrap();
        let root = store.create_timeline("root").unwrap();
        store.fork(root.id(), Seq::ZERO, "fork").unwrap();
        let imported_child = TimelineMeta::forked_from(root.id(), Seq::ZERO, "imported-child");
        store.create_timeline_with_meta(imported_child).unwrap();

        let gateway = Gateway::with_limits(
            store,
            GatewayLimits {
                max_timelines: 2,
                max_events_per_timeline: 1,
            },
        );
        gateway.create_timeline("second-root").await.unwrap();
        let error = gateway.create_timeline("third-root").await.unwrap_err();
        assert!(matches!(
            error,
            GatewayError::TimelineLimitReached { maximum: 2 }
        ));
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn create_timeline_uses_bounded_root_count_without_listing() {
        let gateway = Gateway::new(Box::new(ScriptedStore {
            mode: ScriptMode::RejectListUse,
        }));
        gateway.create_timeline("root").await.unwrap();
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn child_event_limit_counts_owned_not_inherited_events() {
        let mut store = open_store(StoreConfig::Memory).unwrap();
        let root = store.create_timeline("root").unwrap();
        let root_draft = EventDraft::new(
            EntityId::new(),
            Kind::new(EVENT_TYPE_ACTION),
            json_to_cbor(&serde_json::json!({})),
        );
        store.append(root.id(), &[root_draft]).unwrap();
        let child = store.fork(root.id(), Seq::from_u64(1), "child").unwrap();
        let gateway = Gateway::with_limits(
            store,
            GatewayLimits {
                max_timelines: 1,
                max_events_per_timeline: 1,
            },
        );
        let child_id = child.id().to_string();
        let entity_id = EntityId::new().to_string();
        gateway
            .append_action(
                &child_id,
                &entity_id,
                EVENT_TYPE_ACTION,
                &serde_json::json!({}),
            )
            .await
            .unwrap();
        let error = gateway
            .append_action(
                &child_id,
                &entity_id,
                EVENT_TYPE_ACTION,
                &serde_json::json!({}),
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            GatewayError::EventLimitReached { maximum: 1 }
        ));
        let page = gateway
            .read_events_page(&child_id, 0, MAX_EVENTS_PER_POLL)
            .await
            .unwrap();
        assert_eq!(page.events.len(), 2);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn identified_retry_wins_over_event_capacity() {
        let gateway = Gateway::with_limits(
            open_store(StoreConfig::Memory).unwrap(),
            GatewayLimits {
                max_timelines: 1,
                max_events_per_timeline: 1,
            },
        );
        let timeline = gateway.create_timeline("dedup-capacity").await.unwrap();
        let entity = EntityId::new();
        let first = gateway
            .append_identified_action(
                &timeline.id().to_string(),
                &entity.to_string(),
                EVENT_TYPE_ACTION,
                &serde_json::json!({"value": 1}),
                "device-1:capacity",
            )
            .await
            .unwrap();
        let retry = gateway
            .append_identified_action(
                &timeline.id().to_string(),
                &entity.to_string(),
                EVENT_TYPE_ACTION,
                &serde_json::json!({"value": 1}),
                "device-1:capacity",
            )
            .await
            .unwrap();
        assert!(retry.duplicate);
        assert_eq!(retry.event.id, first.event.id);
        let error = gateway
            .append_identified_action(
                &timeline.id().to_string(),
                &entity.to_string(),
                EVENT_TYPE_ACTION,
                &serde_json::json!({"value": 2}),
                "device-1:new",
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            GatewayError::EventLimitReached { maximum: 1 }
        ));
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn same_ingress_id_is_scoped_to_entity() {
        let gateway = memory_gw();
        let timeline = gateway.create_timeline("entity-scope").await.unwrap();
        let timeline_id = timeline.id().to_string();
        let first = gateway
            .append_identified_action(
                &timeline_id,
                &EntityId::new().to_string(),
                EVENT_TYPE_ACTION,
                &serde_json::json!({"value": 1}),
                "device-1:shared",
            )
            .await
            .unwrap();
        let second_entity = EntityId::new().to_string();
        let second = gateway
            .append_identified_action(
                &timeline_id,
                &second_entity,
                EVENT_TYPE_ACTION,
                &serde_json::json!({"value": 1}),
                "device-1:shared",
            )
            .await
            .unwrap();
        assert!(!second.duplicate);
        assert_ne!(first.event.id, second.event.id);
    }

    #[tokio::test]
    async fn identified_admission_covers_bounds_and_maintenance() {
        let gateway = memory_gw();
        let timeline = gateway.create_timeline("identified-bounds").await.unwrap();
        let timeline_id = timeline.id().to_string();
        let entity_id = EntityId::new().to_string();
        let payload = serde_json::json!({"data": "x".repeat(MAX_EVENT_PAYLOAD_BYTES)});
        assert!(matches!(
            gateway
                .append_identified_action(
                    &timeline_id,
                    &entity_id,
                    EVENT_TYPE_ACTION,
                    &payload,
                    "device-1:oversized",
                )
                .await,
            Err(GatewayError::EventPayloadTooLarge { .. })
        ));
        let high_expansion = serde_json::json!({"data": "\0".repeat(160 * 1024)});
        assert!(matches!(
            gateway
                .append_identified_action(
                    &timeline_id,
                    &entity_id,
                    EVENT_TYPE_ACTION,
                    &high_expansion,
                    "device-1:expanded",
                )
                .await,
            Err(GatewayError::EventResponseTooLarge { .. })
        ));
        assert_eq!(
            gateway
                .purge_expired_ingress_identities(NonZeroUsize::new(1).unwrap())
                .await
                .unwrap()
                .removed,
            0
        );
        assert!(matches!(
            gateway
                .append_identified_action(
                    &timeline_id,
                    &entity_id,
                    "other.event",
                    &serde_json::json!({}),
                    "device-1:unsupported",
                )
                .await,
            Err(GatewayError::UnsupportedAction(_))
        ));
    }

    #[tokio::test]
    async fn identified_admission_fails_closed_for_input_and_append_boundaries() {
        let gateway = memory_gw();
        let timeline = gateway.create_timeline("identified-errors").await.unwrap();
        let valid_timeline = timeline.id().to_string();
        let valid_entity = EntityId::new().to_string();
        let payload = serde_json::json!({});
        assert!(matches!(
            gateway
                .append_identified_action(
                    "bad",
                    &valid_entity,
                    EVENT_TYPE_ACTION,
                    &payload,
                    "device-1:bad-timeline",
                )
                .await,
            Err(GatewayError::InvalidId(_))
        ));
        assert!(matches!(
            gateway
                .append_identified_action(
                    &valid_timeline,
                    "bad",
                    EVENT_TYPE_ACTION,
                    &payload,
                    "device-1:bad-entity",
                )
                .await,
            Err(GatewayError::InvalidId(_))
        ));
        let get_error = Gateway::new(Box::new(ScriptedStore {
            mode: ScriptMode::FailGetTimeline,
        }));
        assert!(matches!(
            get_error
                .append_identified_action(
                    &valid_timeline,
                    &valid_entity,
                    EVENT_TYPE_ACTION,
                    &payload,
                    "device-1:get-error",
                )
                .await,
            Err(GatewayError::Store(_))
        ));
        let missing_timeline = Gateway::new(Box::new(ScriptedStore {
            mode: ScriptMode::MissingTimeline,
        }));
        assert!(matches!(
            missing_timeline
                .append_identified_action(
                    &valid_timeline,
                    &valid_entity,
                    EVENT_TYPE_ACTION,
                    &payload,
                    "device-1:missing-timeline",
                )
                .await,
            Err(GatewayError::Store(_))
        ));
        let append_error = Gateway::new(Box::new(ScriptedStore {
            mode: ScriptMode::RejectListUse,
        }));
        assert!(matches!(
            append_error
                .append_identified_action(
                    &valid_timeline,
                    &valid_entity,
                    EVENT_TYPE_ACTION,
                    &payload,
                    "device-1:append-error",
                )
                .await,
            Err(GatewayError::Store(_))
        ));
    }

    #[tokio::test]
    async fn identified_admission_fails_closed_for_purge_and_duplicate_boundaries() {
        let gateway = memory_gw();
        let timeline = gateway.create_timeline("identified-errors").await.unwrap();
        let valid_timeline = timeline.id().to_string();
        let valid_entity = EntityId::new().to_string();
        let payload = serde_json::json!({});
        let purge_error = Gateway::new(Box::new(ScriptedStore {
            mode: ScriptMode::RejectListUse,
        }));
        assert!(purge_error
            .purge_expired_ingress_identities(NonZeroUsize::new(1).unwrap())
            .await
            .is_err());
        let duplicate_error = Gateway::new(Box::new(ScriptedStore {
            mode: ScriptMode::Duplicate,
        }));
        assert!(matches!(
            duplicate_error
                .append_identified_action(
                    &valid_timeline,
                    &valid_entity,
                    EVENT_TYPE_ACTION,
                    &payload,
                    "device-1:missing-event",
                )
                .await,
            Err(GatewayError::Store(_))
        ));
        let duplicate_read_error = Gateway::new(Box::new(ScriptedStore {
            mode: ScriptMode::DuplicateReadError,
        }));
        assert!(matches!(
            duplicate_read_error
                .append_identified_action(
                    &valid_timeline,
                    &valid_entity,
                    EVENT_TYPE_ACTION,
                    &payload,
                    "device-1:read-error",
                )
                .await,
            Err(GatewayError::Store(_))
        ));
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn sqlite_gateway_serializes_concurrent_limit_checks_and_appends() {
        let gateway = Gateway::with_limits(
            open_store(StoreConfig::Sqlite {
                path: ":memory:".to_owned(),
            })
            .unwrap(),
            GatewayLimits {
                max_timelines: 1,
                max_events_per_timeline: 1,
            },
        );
        let timeline = gateway.create_timeline("sqlite").await.unwrap();
        let timeline_id = timeline.id().to_string();
        let entity_id = EntityId::new().to_string();
        let first = gateway.clone();
        let second = gateway.clone();
        let payload_a = serde_json::json!({"writer": "a"});
        let payload_b = serde_json::json!({"writer": "b"});
        let (a, b) = tokio::join!(
            first.append_action(&timeline_id, &entity_id, EVENT_TYPE_ACTION, &payload_a,),
            second.append_action(&timeline_id, &entity_id, EVENT_TYPE_ACTION, &payload_b,)
        );
        assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
        let rejected = if let Err(error) = a {
            error
        } else {
            b.unwrap_err()
        };
        assert!(matches!(
            rejected,
            GatewayError::EventLimitReached { maximum: 1 }
        ));
        let page = gateway
            .read_events_page(&timeline_id, 0, MAX_EVENTS_PER_POLL)
            .await
            .unwrap();
        assert_eq!(page.events.len(), 1);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn sqlite_bounded_reads_page_forks_and_reject_external_oversize() {
        let mut store = open_store(StoreConfig::Sqlite {
            path: ":memory:".to_owned(),
        })
        .unwrap();
        let root = store.create_timeline("root").unwrap();
        let small = EventDraft::new(
            EntityId::new(),
            Kind::new(EVENT_TYPE_ACTION),
            json_to_cbor(&serde_json::json!({})),
        );
        store
            .append(root.id(), std::slice::from_ref(&small))
            .unwrap();
        let child = store.fork(root.id(), Seq::from_u64(1), "child").unwrap();
        store
            .append(child.id(), std::slice::from_ref(&small))
            .unwrap();
        let gateway = Gateway::new(store);

        let first = gateway
            .read_events_page(&child.id().to_string(), 1, 1)
            .await
            .unwrap();
        assert_eq!(first.events.len(), 1);
        assert_eq!(first.events[0].seq.as_u64(), 1);
        assert_eq!(first.next_from_seq, Some(Seq::from_u64(2)));
        let beyond_head = gateway
            .read_events_page(&child.id().to_string(), 3, 1)
            .await
            .unwrap();
        assert!(beyond_head.events.is_empty());

        let mut external = open_store(StoreConfig::Sqlite {
            path: ":memory:".to_owned(),
        })
        .unwrap();
        let timeline = external.create_timeline("external").unwrap();
        let oversized = EventDraft::new(
            EntityId::new(),
            Kind::new("external.event"),
            CanonicalBytes::from_vec(vec![0; MAX_EVENT_PAYLOAD_BYTES + 1]),
        );
        external.append(timeline.id(), &[oversized]).unwrap();
        let error = Gateway::new(external)
            .read_events_page(&timeline.id().to_string(), 0, 1)
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            GatewayError::EventPayloadTooLarge {
                maximum: MAX_EVENT_PAYLOAD_BYTES
            }
        ));
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn imported_oversized_event_type_returns_actionable_413_on_bundled_stores() {
        let mut source = open_store(StoreConfig::Memory).unwrap();
        let timeline = source.create_timeline("import-source").unwrap();
        source
            .append(
                timeline.id(),
                &[EventDraft::new(
                    EntityId::new(),
                    Kind::new("x".repeat(MAX_EVENT_TYPE_BYTES + 1)),
                    CanonicalBytes::from_static(b"x"),
                )],
            )
            .unwrap();
        let export = export_timeline_own(source.as_ref(), timeline.id()).unwrap();

        let destinations = [
            open_store(StoreConfig::Memory).unwrap(),
            open_store(StoreConfig::Sqlite {
                path: ":memory:".to_owned(),
            })
            .unwrap(),
        ];
        for mut destination in destinations {
            import_timeline_with_id(destination.as_mut(), export.clone()).unwrap();
            let error = Gateway::new(destination)
                .read_events_page(&timeline.id().to_string(), 0, 1)
                .await
                .unwrap_err();
            assert!(matches!(
                error,
                GatewayError::EventMetadataTooLarge {
                    field: "event_type",
                    maximum: MAX_EVENT_TYPE_BYTES
                }
            ));
        }
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn imported_deep_fork_returns_actionable_413() {
        let mut source = open_store(StoreConfig::Memory).unwrap();
        let root = source.create_timeline("root").unwrap();
        let mut timelines = vec![root];
        for depth in 1..=MAX_FORK_DEPTH + 1 {
            let parent = timelines.last().unwrap();
            let child = source
                .fork(parent.id(), Seq::ZERO, &format!("depth-{depth}"))
                .unwrap();
            timelines.push(child);
        }

        let mut destination = open_store(StoreConfig::Memory).unwrap();
        for timeline in &timelines {
            let export = export_timeline_own(source.as_ref(), timeline.id()).unwrap();
            import_timeline_with_id(destination.as_mut(), export).unwrap();
        }
        let deepest = timelines.last().unwrap();
        let response = GatewayError::ForkDepthTooLarge {
            maximum: MAX_FORK_DEPTH,
        }
        .to_string();
        let error = Gateway::new(destination)
            .read_events_page(&deepest.id().to_string(), 0, 1)
            .await
            .unwrap_err();

        assert_eq!(error.to_string(), response);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn gateway_rejects_payloads_that_cannot_fit_bounded_responses() {
        let gateway = memory_gw();
        let timeline = gateway.create_timeline("payload").await.unwrap();
        let payload = serde_json::json!({"data": "x".repeat(MAX_EVENT_PAYLOAD_BYTES)});
        let error = gateway
            .append_action(
                &timeline.id().to_string(),
                &EntityId::new().to_string(),
                EVENT_TYPE_ACTION,
                &payload,
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            GatewayError::EventPayloadTooLarge {
                maximum: MAX_EVENT_PAYLOAD_BYTES
            }
        ));

        let high_expansion = serde_json::json!({"data": "\0".repeat(160 * 1024)});
        let error = gateway
            .append_action(
                &timeline.id().to_string(),
                &EntityId::new().to_string(),
                EVENT_TYPE_ACTION,
                &high_expansion,
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            GatewayError::EventResponseTooLarge {
                maximum: MAX_EVENTS_RESPONSE_BYTES
            }
        ));

        let retrievable = serde_json::json!({"data": "x".repeat(240 * 1024)});
        gateway
            .append_action(
                &timeline.id().to_string(),
                &EntityId::new().to_string(),
                EVENT_TYPE_ACTION,
                &retrievable,
            )
            .await
            .unwrap();
        let page = gateway
            .read_events_page(&timeline.id().to_string(), 0, 1)
            .await
            .unwrap();
        let response = serde_json::json!({
            "events": page.events.iter().map(EventView::from).collect::<Vec<_>>(),
            "next_from_seq": page.next_from_seq,
        });
        assert!(serde_json::to_vec(&response).unwrap().len() <= MAX_EVENTS_RESPONSE_BYTES);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn event_type_bound_reserves_space_for_maximum_payload_hex() {
        let draft = EventDraft::new(
            EntityId::new(),
            Kind::new("\0".repeat(MAX_EVENT_TYPE_BYTES)),
            CanonicalBytes::from_vec(vec![0xff; MAX_EVENT_PAYLOAD_BYTES]),
        );
        assert!(draft_event_response_len(&draft) <= MAX_EVENTS_RESPONSE_BYTES);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn admission_budgets_the_exact_worst_case_cursor_boundary() {
        let entity = EntityId::new();
        let mut boundary = None;
        for length in (MAX_EVENTS_RESPONSE_BYTES / 8 - 128)..=(MAX_EVENTS_RESPONSE_BYTES / 8) {
            let payload = serde_json::json!({"data": "\0".repeat(length)});
            let draft =
                EventDraft::new(entity, Kind::new(EVENT_TYPE_ACTION), json_to_cbor(&payload));
            let view = EventView {
                id: "0".repeat(26),
                entity: entity.to_string(),
                event_type: EVENT_TYPE_ACTION.to_owned(),
                seq: u64::MAX,
                payload: decode_cbor_json(draft.payload.as_slice()),
                payload_hex: hex_encode(draft.payload.as_slice()),
            };
            let null_cursor_len = serde_json::to_vec(&serde_json::json!({
                "events": [view],
                "next_from_seq": null,
            }))
            .unwrap()
            .len();
            let worst_cursor_len = draft_event_response_len(&draft);
            if null_cursor_len <= MAX_EVENTS_RESPONSE_BYTES
                && worst_cursor_len > MAX_EVENTS_RESPONSE_BYTES
            {
                boundary = Some(payload);
                break;
            }
        }
        let payload = boundary.expect("cursor width must cross the exact response boundary");
        let gateway = memory_gw();
        let timeline = gateway.create_timeline("cursor-boundary").await.unwrap();
        let error = gateway
            .append_action(
                &timeline.id().to_string(),
                &entity.to_string(),
                EVENT_TYPE_ACTION,
                &payload,
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            GatewayError::EventResponseTooLarge {
                maximum: MAX_EVENTS_RESPONSE_BYTES
            }
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn events_query_remains_deserializable_for_library_callers() {
        let query: EventsQuery =
            serde_json::from_value(serde_json::json!({"from_seq": 7, "limit": 8})).unwrap();
        assert_eq!(
            query,
            EventsQuery {
                from_seq: 7,
                limit: 8
            }
        );
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn event_page_rejects_zero_limit() {
        let gw = memory_gw();
        let timeline = gw.create_timeline("zero").await.unwrap();
        let err = gw
            .read_events_page(&timeline.id().to_string(), 0, 0)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            GatewayError::InvalidPageLimit {
                maximum: MAX_EVENTS_PER_POLL
            }
        ));
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn empty_event_page_has_no_cursor() {
        let gw = memory_gw();
        let timeline = gw.create_timeline("empty").await.unwrap();
        let page = gw
            .read_events_page(&timeline.id().to_string(), 0, 1)
            .await
            .unwrap();
        assert!(page.events.is_empty());
        assert_eq!(page.next_from_seq, None);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn event_page_cursor_is_first_omitted_sequence_and_none_at_exhaustion() {
        let gateway = memory_gw();
        let timeline = gateway.create_timeline("cursor").await.unwrap();
        let timeline_id = timeline.id().to_string();
        let entity_id = EntityId::new().to_string();
        for value in 0..2 {
            gateway
                .append_action(
                    &timeline_id,
                    &entity_id,
                    EVENT_TYPE_ACTION,
                    &serde_json::json!({ "value": value }),
                )
                .await
                .unwrap();
        }
        let first = gateway.read_events_page(&timeline_id, 0, 1).await.unwrap();
        assert_eq!(first.events.len(), 1);
        assert_eq!(first.next_from_seq, Some(Seq::from_u64(2)));
        let exhausted = gateway.read_events_page(&timeline_id, 2, 1).await.unwrap();
        assert_eq!(exhausted.events.len(), 1);
        assert_eq!(exhausted.next_from_seq, None);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[allow(deprecated)]
    async fn public_page_api_and_compatibility_shim_remain_bounded() {
        let gateway = memory_gw();
        let timeline = gateway.create_timeline("public-api").await.unwrap();
        let drafts: Vec<_> = (0..=MAX_EVENTS_PER_POLL)
            .map(|_| {
                EventDraft::new(
                    EntityId::new(),
                    Kind::new(EVENT_TYPE_ACTION),
                    json_to_cbor(&serde_json::json!({})),
                )
            })
            .collect();
        {
            let mut store = gateway.store.lock().await;
            store.append(timeline.id(), &drafts).unwrap();
        }
        let page: EventPage = gateway
            .read_events_page(&timeline.id().to_string(), 0, MAX_EVENTS_PER_POLL)
            .await
            .unwrap();
        assert_eq!(page.events.len(), MAX_EVENTS_PER_POLL);
        assert_eq!(page.next_from_seq, Some(Seq::from_u64(101)));
        let error = gateway
            .read_events_from(&timeline.id().to_string(), 0)
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            GatewayError::CompatibilityReadTruncated {
                maximum: MAX_EVENTS_PER_POLL
            }
        ));
        let final_event = gateway
            .read_events_from(&timeline.id().to_string(), 101)
            .await
            .unwrap();
        assert_eq!(final_event.len(), 1);
        let invalid = gateway.read_events_from("bad", 0).await.unwrap_err();
        assert!(matches!(invalid, GatewayError::InvalidId(_)));
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn fork_with_more_than_ten_thousand_logical_events_pages_to_exhaustion() {
        let mut store = open_store(StoreConfig::Memory).unwrap();
        let root = store.create_timeline("root").unwrap();
        let drafts: Vec<_> = (0..MAX_EVENTS_PER_TIMELINE)
            .map(|_| {
                EventDraft::new(
                    EntityId::new(),
                    Kind::new(EVENT_TYPE_ACTION),
                    json_to_cbor(&serde_json::json!({})),
                )
            })
            .collect();
        store.append(root.id(), &drafts).unwrap();
        let child = store
            .fork(root.id(), Seq::from_u64(10_000), "child")
            .unwrap();
        let gateway = Gateway::new(store);
        gateway
            .append_action(
                &child.id().to_string(),
                &EntityId::new().to_string(),
                EVENT_TYPE_ACTION,
                &serde_json::json!({}),
            )
            .await
            .unwrap();

        let mut from_seq = 0;
        let mut count = 0;
        loop {
            let page = gateway
                .read_events_page(&child.id().to_string(), from_seq, MAX_EVENTS_PER_POLL)
                .await
                .unwrap();
            count += page.events.len();
            match page.next_from_seq {
                Some(next) => from_seq = next.as_u64(),
                None => break,
            }
        }
        assert_eq!(count, 10_001);
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
        let err = gw.read_events_page("not-a-ulid", 0, 1).await.unwrap_err();
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
            limits: GatewayLimits::LOCAL_DEFAULT,
        };
        assert!(matches!(
            fail_create.create_timeline("x").await,
            Err(GatewayError::Store(_))
        ));

        let fail_list = Gateway {
            store: Arc::new(Mutex::new(Box::new(ScriptedStore {
                mode: ScriptMode::FailList,
            }))),
            bus: broadcast::channel(EVENT_BUS_CAPACITY).0,
            limits: GatewayLimits::LOCAL_DEFAULT,
        };
        assert!(matches!(
            fail_list.create_timeline("x").await,
            Err(GatewayError::Store(_))
        ));

        let empty_append = Gateway {
            store: Arc::new(Mutex::new(Box::new(ScriptedStore {
                mode: ScriptMode::EmptyAppend,
            }))),
            bus: broadcast::channel(EVENT_BUS_CAPACITY).0,
            limits: GatewayLimits::LOCAL_DEFAULT,
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

        let fail_get_timeline = Gateway {
            store: Arc::new(Mutex::new(Box::new(ScriptedStore {
                mode: ScriptMode::FailGetTimeline,
            }))),
            bus: broadcast::channel(EVENT_BUS_CAPACITY).0,
            limits: GatewayLimits::LOCAL_DEFAULT,
        };
        let err = fail_get_timeline
            .append_action(
                &TimelineId::new().to_string(),
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
            limits: GatewayLimits::LOCAL_DEFAULT,
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
            limits: GatewayLimits::LOCAL_DEFAULT,
        };
        let err = fail_read
            .read_events_page(&TimelineId::new().to_string(), 0, 1)
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

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn subscribe_lag_signals_resync() {
        use tokio::sync::broadcast::error::TryRecvError;

        let gw = Gateway::with_bus_capacity(open_store(StoreConfig::Memory).unwrap(), 2);
        let mut rx = gw.subscribe();
        let tl = gw.create_timeline("lag").await.unwrap();
        let entity = EntityId::new().to_string();
        let id = tl.id().to_string();
        for _ in 0..3 {
            gw.append_action(&id, &entity, EVENT_TYPE_ACTION, &serde_json::json!({}))
                .await
                .unwrap();
        }
        assert!(matches!(
            rx.try_recv(),
            Ok(_) | Err(TryRecvError::Lagged(_))
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn gateway_error_display() {
        let e = GatewayError::UnsupportedAction("x".into());
        assert!(e.to_string().contains("unsupported"));
        let e = GatewayError::InvalidId("bad".into());
        assert!(e.to_string().contains("invalid"));
        let e = GatewayError::InvalidPageLimit {
            maximum: MAX_EVENTS_PER_POLL,
        };
        assert!(e.to_string().contains("between"));
        let e = GatewayError::CompatibilityReadTruncated {
            maximum: MAX_EVENTS_PER_POLL,
        };
        assert!(e.to_string().contains("compatibility"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn ingress_identity_is_domain_separated_and_namespaced() {
        let timeline = TimelineId::new();
        let entity = EntityId::new();
        let same = ingress_identity(timeline, entity, "device-1:42");
        assert_eq!(same, ingress_identity(timeline, entity, "device-1:42"));
        assert_ne!(
            same.dedup_key,
            ingress_identity(timeline, entity, "device-1:43").dedup_key
        );
        assert_ne!(
            same.dedup_key,
            ingress_identity(TimelineId::new(), entity, "device-1:42").dedup_key
        );
        assert_ne!(
            same.scope,
            ingress_identity(timeline, EntityId::new(), "device-1:42").scope
        );
        assert_ne!(same.dedup_key.as_bytes(), same.scope.as_bytes());
    }
}
