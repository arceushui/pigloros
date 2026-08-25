use bytes::Bytes;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

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

    pub(super) fn serialize<S: Serializer>(b: &Bytes, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(b)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Bytes, D::Error> {
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

/// The sole schema marker emitted by `PiglorOS` V1 events.
///
/// It remains a numeric `1` in serialized Events, but no version ladder or
/// payload-upgrade behavior is supported.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SchemaVersion(u8);

impl SchemaVersion {
    pub const V1: Self = Self(1);

    #[must_use]
    pub const fn as_u32(self) -> u32 {
        1
    }
}

impl Serialize for SchemaVersion {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u8(1)
    }
}

impl<'de> Deserialize<'de> for SchemaVersion {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        u8::deserialize(deserializer).and_then(|value| {
            if value == 1 {
                Ok(Self::V1)
            } else {
                Err(serde::de::Error::custom(
                    "only schema version 1 is supported",
                ))
            }
        })
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
    /// Role and epoch domain used for the signature, when present.
    #[serde(default)]
    pub signature_identity: Option<crate::KeyIdentityV1>,
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
    pub const fn new(entity: EntityId, event_type: Kind, payload: CanonicalBytes) -> Self {
        Self {
            entity,
            event_type,
            payload,
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            wall_time: None,
        }
    }

    /// Override the wall-clock time that will be stored with this event.
    ///
    /// Use during deterministic replay to re-inject the original timestamp so that
    /// re-appended events are bit-identical to the originals.
    #[must_use]
    pub const fn with_wall_time(mut self, t: WallTime) -> Self {
        self.wall_time = Some(t);
        self
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
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
            signature_identity: None,
            payload_hash: Hash::from_bytes([0u8; 32]),
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn event_json_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let e = sample_event();
        let s = serde_json::to_string(&e)?;
        let back: Event = serde_json::from_str(&s)?;
        assert_eq!(e, back);
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn event_cbor_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let e = sample_event();
        let mut buf = Vec::new();
        ciborium::into_writer(&e, &mut buf)?;
        let back: Event = ciborium::from_reader(buf.as_slice())?;
        assert_eq!(e, back);
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn event_draft_cbor_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let d = EventDraft::new(
            EntityId::new(),
            Kind::new("agent.decision"),
            CanonicalBytes::from_vec(vec![1, 2, 3]),
        );
        let mut buf = Vec::new();
        ciborium::into_writer(&d, &mut buf)?;
        let back: EventDraft = ciborium::from_reader(buf.as_slice())?;
        assert_eq!(d, back);
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn canonical_bytes_payload_is_opaque() -> Result<(), Box<dyn std::error::Error>> {
        // Kernel round-trips arbitrary bytes unchanged — no interpretation.
        let raw = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xFF, 0x00, 0x01];
        let cb = CanonicalBytes::from_vec(raw.clone());
        let mut buf = Vec::new();
        ciborium::into_writer(&cb, &mut buf)?;
        let back: CanonicalBytes = ciborium::from_reader(buf.as_slice())?;
        assert_eq!(cb.as_slice(), back.as_slice());
        assert_eq!(back.as_slice(), &raw[..]);
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn canonical_bytes_empty_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let cb = CanonicalBytes::from_vec(vec![]);
        assert!(cb.is_empty());
        let mut buf = Vec::new();
        ciborium::into_writer(&cb, &mut buf)?;
        let back: CanonicalBytes = ciborium::from_reader(buf.as_slice())?;
        assert!(back.is_empty());
        Ok(())
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
    fn kind_json_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let k = Kind::new("agent.decision");
        let back: Kind = serde_json::from_str(&serde_json::to_string(&k)?)?;
        assert_eq!(k, back);
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn schema_version_is_v1_only() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(SchemaVersion::V1.as_u32(), 1);
        assert_eq!(serde_json::to_string(&SchemaVersion::V1)?, "1");
        assert_eq!(
            serde_json::from_str::<SchemaVersion>("1")?,
            SchemaVersion::V1
        );
        assert!(serde_json::from_str::<SchemaVersion>("2").is_err());
        let mut cbor = Vec::new();
        ciborium::into_writer(&2_u8, &mut cbor)?;
        assert!(ciborium::from_reader::<SchemaVersion, _>(cbor.as_slice()).is_err());
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn determinism_serde() -> Result<(), Box<dyn std::error::Error>> {
        let d = Determinism::Recorded;
        let back: Determinism = serde_json::from_str(&serde_json::to_string(&d)?)?;
        assert_eq!(d, back);
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn run_mode_serde() -> Result<(), Box<dyn std::error::Error>> {
        let m = RunMode::Replay;
        let back: RunMode = serde_json::from_str(&serde_json::to_string(&m)?)?;
        assert_eq!(m, back);
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn event_with_all_optional_fields_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let e = Event {
            id: EventId::new(),
            entity: EntityId::new(),
            event_type: Kind::new("plugin.custom"),
            payload: CanonicalBytes::from_static(b"data"),
            wall_time: WallTime::from_micros(0),
            seq: Seq::ZERO,
            causation_id: Some(EventId::new()),
            correlation_id: Some(CorrelationId::new()),
            schema_version: SchemaVersion::V1,
            signature: None,
            signature_identity: None,
            payload_hash: Hash::from_bytes([255u8; 32]),
        };
        let s = serde_json::to_string(&e)?;
        let back: Event = serde_json::from_str(&s)?;
        assert_eq!(e, back);
        Ok(())
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
    fn event_draft_with_wall_time_preserves_timestamp() {
        let t = WallTime::from_micros(42);
        let draft = EventDraft::new(
            EntityId::new(),
            Kind::new("x"),
            CanonicalBytes::from_vec(vec![]),
        )
        .with_wall_time(t);
        assert_eq!(draft.wall_time, Some(t));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn event_draft_json_decode_rejects_bad_payload() -> Result<(), Box<dyn std::error::Error>> {
        let draft = EventDraft::new(
            EntityId::new(),
            Kind::new("test"),
            CanonicalBytes::from_vec(vec![1, 2, 3]),
        );
        let mut value: serde_json::Value = serde_json::from_str(&serde_json::to_string(&draft)?)?;
        value["payload"] = serde_json::json!(42);
        let result: Result<EventDraft, _> = serde_json::from_value(value);
        assert!(result.is_err());
        Ok(())
    }
}
