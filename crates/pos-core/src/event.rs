use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::{
    clock::{Seq, WallTime},
    crypto::{Hash, Signature},
    ids::{CorrelationId, EntityId, EventId},
};

/// Canonical, opaque payload bytes. The kernel never deserializes this.
/// Uses `Bytes` for cheap clone (ref-counted).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CanonicalBytes(#[serde(with = "serde_bytes_wrapper")] Bytes);

impl CanonicalBytes {
    #[must_use]
    pub fn from_vec(v: Vec<u8>) -> Self {
        Self(Bytes::from(v))
    }

    #[must_use]
    pub const fn from_static(b: &'static [u8]) -> Self {
        Self(Bytes::from_static(b))
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub const fn len(&self) -> usize {
        self.0.len()
    }

    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Serde helper: serialize Bytes as byte array, not as a sequence of ints.
mod serde_bytes_wrapper {
    use bytes::Bytes;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(b: &Bytes, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(b)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Bytes, D::Error> {
        let v = serde_bytes::ByteBuf::deserialize(d)?;
        Ok(Bytes::from(v.into_vec()))
    }
}

/// Namespaced event type string, e.g. `"world.observation"`, `"agent.decision"`.
/// Always plugin-owned; the kernel treats this as an opaque string.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Kind(String);

impl Kind {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Kind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Whether an event was produced deterministically or recorded from a nondeterministic source.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Determinism {
    /// Output is fully deterministic given the same inputs.
    Deterministic,
    /// Output was recorded from a nondeterministic source (LLM, sensor, RNG).
    Recorded,
}

/// Execution mode — determines whether nondeterministic plugins produce or replay.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RunMode {
    /// Running live; nondeterministic outputs are produced and recorded.
    Live,
    /// Replaying from recorded events; nondeterministic plugins read from the record.
    Replay,
}

/// Schema version for an event type. Enables upcasting on read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SchemaVersion(u32);

impl SchemaVersion {
    pub const V1: Self = Self(1);

    #[must_use]
    pub const fn new(v: u32) -> Self {
        Self(v)
    }

    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

impl Default for SchemaVersion {
    fn default() -> Self {
        Self::V1
    }
}

/// A fully-formed, signed event in the kernel's event log.
///
/// `payload` is opaque `CanonicalBytes` — the kernel never deserializes it.
/// Only a plugin (via the runtime schema registry) knows the payload structure.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    pub id: EventId,
    pub entity: EntityId,
    pub event_type: Kind,
    pub payload: CanonicalBytes,
    pub wall_time: WallTime,
    pub seq: Seq,
    pub causation_id: Option<EventId>,
    pub correlation_id: Option<CorrelationId>,
    pub schema_version: SchemaVersion,
    pub signature: Option<Signature>,
    pub payload_hash: Hash,
}

/// An unsigned draft event, used before append.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventDraft {
    pub entity: EntityId,
    pub event_type: Kind,
    pub payload: CanonicalBytes,
    pub causation_id: Option<EventId>,
    pub correlation_id: Option<CorrelationId>,
    pub schema_version: SchemaVersion,
    /// Optional wall-clock time override.
    ///
    /// When `Some`, the store backend records this exact timestamp instead of calling
    /// `WallTime::now()`. Set this during deterministic replay to preserve the original
    /// timestamp bit-for-bit.
    pub wall_time: Option<WallTime>,
}

impl EventDraft {
    pub fn new(entity: EntityId, event_type: Kind, payload: CanonicalBytes) -> Self {
        Self {
            entity,
            event_type,
            payload,
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::default(),
            wall_time: None,
        }
    }

    /// Override the wall-clock time that will be stored with this event.
    ///
    /// Use during deterministic replay to re-inject the original timestamp so that
    /// re-appended events are bit-identical to the originals.
    #[must_use]
    pub fn with_wall_time(mut self, t: WallTime) -> Self {
        self.wall_time = Some(t);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::EventId;

    fn sample_event() -> Event {
        Event {
            id: EventId::new(),
            entity: EntityId::new(),
            event_type: Kind::new("test.event"),
            payload: CanonicalBytes::from_vec(b"hello world".to_vec()),
            wall_time: WallTime::from_micros(1_000_000),
            seq: Seq::from_u64(1),
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            payload_hash: Hash::from_bytes([0u8; 32]),
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn event_json_round_trip() {
        let e = sample_event();
        let s = serde_json::to_string(&e).unwrap();
        let back: Event = serde_json::from_str(&s).unwrap();
        assert_eq!(e, back);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn event_cbor_round_trip() {
        let e = sample_event();
        let mut buf = Vec::new();
        ciborium::into_writer(&e, &mut buf).unwrap();
        let back: Event = ciborium::from_reader(buf.as_slice()).unwrap();
        assert_eq!(e, back);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn event_draft_cbor_round_trip() {
        let d = EventDraft::new(
            EntityId::new(),
            Kind::new("agent.decision"),
            CanonicalBytes::from_vec(vec![1, 2, 3]),
        );
        let mut buf = Vec::new();
        ciborium::into_writer(&d, &mut buf).unwrap();
        let back: EventDraft = ciborium::from_reader(buf.as_slice()).unwrap();
        assert_eq!(d, back);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn canonical_bytes_payload_is_opaque() {
        // Kernel round-trips arbitrary bytes unchanged — no interpretation.
        let raw = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xFF, 0x00, 0x01];
        let cb = CanonicalBytes::from_vec(raw.clone());
        let mut buf = Vec::new();
        ciborium::into_writer(&cb, &mut buf).unwrap();
        let back: CanonicalBytes = ciborium::from_reader(buf.as_slice()).unwrap();
        assert_eq!(cb.as_slice(), back.as_slice());
        assert_eq!(back.as_slice(), &raw[..]);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn canonical_bytes_empty_round_trip() {
        let cb = CanonicalBytes::from_vec(vec![]);
        assert!(cb.is_empty());
        let mut buf = Vec::new();
        ciborium::into_writer(&cb, &mut buf).unwrap();
        let back: CanonicalBytes = ciborium::from_reader(buf.as_slice()).unwrap();
        assert!(back.is_empty());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn canonical_bytes_clone_is_cheap() {
        let cb = CanonicalBytes::from_vec(vec![42u8; 1024]);
        let clone = cb.clone();
        assert_eq!(cb.as_slice(), clone.as_slice());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn kind_display() {
        let k = Kind::new("world.observation");
        assert_eq!(k.to_string(), "world.observation");
        assert_eq!(k.as_str(), "world.observation");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn kind_json_round_trip() {
        let k = Kind::new("agent.decision");
        let back: Kind = serde_json::from_str(&serde_json::to_string(&k).unwrap()).unwrap();
        assert_eq!(k, back);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn schema_version_default_is_v1() {
        assert_eq!(SchemaVersion::default(), SchemaVersion::V1);
        assert_eq!(SchemaVersion::V1.as_u32(), 1);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn schema_version_ordering() {
        assert!(SchemaVersion::new(1) < SchemaVersion::new(2));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn determinism_serde() {
        let d = Determinism::Recorded;
        let back: Determinism = serde_json::from_str(&serde_json::to_string(&d).unwrap()).unwrap();
        assert_eq!(d, back);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn run_mode_serde() {
        let m = RunMode::Replay;
        let back: RunMode = serde_json::from_str(&serde_json::to_string(&m).unwrap()).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn event_with_all_optional_fields_round_trip() {
        let e = Event {
            id: EventId::new(),
            entity: EntityId::new(),
            event_type: Kind::new("plugin.custom"),
            payload: CanonicalBytes::from_static(b"data"),
            wall_time: WallTime::from_micros(0),
            seq: Seq::ZERO,
            causation_id: Some(EventId::new()),
            correlation_id: Some(CorrelationId::new()),
            schema_version: SchemaVersion::new(2),
            signature: None,
            payload_hash: Hash::from_bytes([255u8; 32]),
        };
        let s = serde_json::to_string(&e).unwrap();
        let back: Event = serde_json::from_str(&s).unwrap();
        assert_eq!(e, back);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn event_draft_defaults() {
        let entity = EntityId::new();
        let kind = Kind::new("test");
        let payload = CanonicalBytes::from_vec(vec![]);
        let draft = EventDraft::new(entity, kind, payload);
        assert_eq!(draft.schema_version, SchemaVersion::V1);
        assert!(draft.causation_id.is_none());
        assert!(draft.correlation_id.is_none());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn canonical_bytes_len() {
        let cb = CanonicalBytes::from_vec(vec![1, 2, 3, 4, 5]);
        assert_eq!(cb.len(), 5);
        let empty = CanonicalBytes::from_vec(vec![]);
        assert_eq!(empty.len(), 0);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn canonical_bytes_rejects_non_bytes_json() {
        let result: Result<CanonicalBytes, _> = serde_json::from_str("42");
        assert!(result.is_err());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn event_draft_rejects_non_bytes_payload_json() {
        let draft = EventDraft::new(
            EntityId::new(),
            Kind::new("test"),
            CanonicalBytes::from_vec(vec![1, 2, 3]),
        );
        let mut value: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&draft).unwrap()).unwrap();
        value["payload"] = serde_json::json!(42);
        let result: Result<EventDraft, _> = serde_json::from_value(value);
        assert!(result.is_err());
    }
}
