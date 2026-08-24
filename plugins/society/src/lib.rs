#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

//! `pos-plugin-society` — Wave 6 social-layer metrics scaffold (#71 / ADR-011 slice 2).
//!
//! Owns event type `"society.signal"` and entity kind `"society-aggregate"`.
//! Thin reducer tracks running means for trust / opinion / economy / culture /
//! polarisation dimensions. No driver — signals are appended by hosts or gateway.
//! Successful finite samples update per-dimension `count.*` / `sum.*` / `mean.*` / `last.*`
//! and global `signals`. Bad CBOR and non-finite values are ignored (no counter bump).
//!
//! # Host wiring
//!
//! Register the plugin with a [`SocietyReducer`] (no driver), append
//! [`draft_signal`] drafts onto a timeline, then fold with the reducer.
//! State keys: `mean.trust`, `mean.opinion`, `count.economy`, `last.culture`,
//! `sum.*`, and global `signals`.
//!
//! ```rust
//! use pos_core::{ids::EntityId, state::Reducer};
//! use pos_plugin_society::{
//!     draft_signal, SocietyDimension, SocietyPlugin, SocietyReducer, SocietySignal,
//! };
//! use pos_runtime::registry::PluginRegistry;
//!
//! let mut registry = PluginRegistry::new();
//! let plugin = SocietyPlugin::new();
//! assert!(registry
//!     .register(&plugin, Some(Box::new(SocietyReducer)), None)
//!     .is_ok());
//!
//! let draft = draft_signal(
//!     EntityId::new(),
//!     &SocietySignal {
//!         dimension: SocietyDimension::Trust,
//!         value: 0.8,
//!         subject: None,
//!         object: None,
//!     },
//! );
//! assert_eq!(draft.event_type.as_str(), "society.signal");
//!
//! // Hosts: store.append(timeline, &[draft]) then reducer.apply on committed events.
//! let state = SocietyReducer.initial();
//! assert!(state.get("mean.trust").is_some());
//! assert!(state.get("signals").is_some());
//! ```
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

use pos_core::{
    event::{CanonicalBytes, Event, EventDraft, Kind},
    ids::{EntityId, PluginId},
    plugin::{Capability, Plugin},
    state::{Reducer, State},
};
use serde::{Deserialize, Serialize};

/// Entity kind for society aggregate nodes.
pub const ENTITY_KIND: &str = "society-aggregate";

/// Event type for a social-layer signal sample.
pub const EVENT_TYPE_SIGNAL: &str = "society.signal";

/// Social metric dimensions tracked by the society reducer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SocietyDimension {
    Trust,
    Opinion,
    Economy,
    Culture,
    Polarization,
}

impl SocietyDimension {
    /// Stable string key used in [`State`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Trust => "trust",
            Self::Opinion => "opinion",
            Self::Economy => "economy",
            Self::Culture => "culture",
            Self::Polarization => "polarization",
        }
    }

    /// All dimensions in ADR-011 / #71 scope order.
    #[must_use]
    pub const fn all() -> [Self; 5] {
        [
            Self::Trust,
            Self::Opinion,
            Self::Economy,
            Self::Culture,
            Self::Polarization,
        ]
    }
}

/// CBOR payload for [`EVENT_TYPE_SIGNAL`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SocietySignal {
    /// Which social dimension this sample updates.
    pub dimension: SocietyDimension,
    /// Sample value in `[0.0, 1.0]`. Out-of-range finite values are clamped by the reducer.
    pub value: f64,
    /// Optional subject entity (e.g. trustor / opinion holder).
    pub subject: Option<String>,
    /// Optional object entity (e.g. trustee / opinion target).
    pub object: Option<String>,
}

/// Errors from the society plugin helpers (reserved for host-facing APIs).
#[derive(Debug, thiserror::Error)]
pub enum SocietyError {
    /// CBOR payload could not be decoded.
    #[error("payload decode error: {0}")]
    Decode(String),
}

/// Decode a society signal payload.
///
/// # Errors
/// Returns [`SocietyError::Decode`] if the bytes are not a valid [`SocietySignal`].
pub fn decode_signal(payload: &[u8]) -> Result<SocietySignal, SocietyError> {
    ciborium::from_reader(payload).map_err(|e| SocietyError::Decode(e.to_string()))
}

/// Society plugin descriptor (reducer only).
pub struct SocietyPlugin {
    id: PluginId,
}

impl Default for SocietyPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl SocietyPlugin {
    /// Create a new society plugin.
    #[must_use]
    pub fn new() -> Self {
        Self {
            id: PluginId::new(),
        }
    }
}

impl Plugin for SocietyPlugin {
    fn id(&self) -> PluginId {
        self.id
    }

    fn name(&self) -> &'static str {
        "society"
    }

    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: vec![Kind::new(EVENT_TYPE_SIGNAL)],
            owned_entity_kinds: vec![ENTITY_KIND.to_owned()],
            has_driver: false,
            has_reducer: true,
        }
    }
}

/// Build a [`EVENT_TYPE_SIGNAL`] draft.
///
/// # Panics
/// Never panics in practice — CBOR encode to `Vec<u8>` is infallible for this payload.
#[must_use]
pub fn draft_signal(entity: EntityId, signal: &SocietySignal) -> EventDraft {
    let mut buf = Vec::new();
    assert!(ciborium::into_writer(signal, &mut buf).is_ok());
    EventDraft::new(
        entity,
        Kind::new(EVENT_TYPE_SIGNAL),
        CanonicalBytes::from_vec(buf),
    )
}

/// Tracks per-dimension count, sum, mean, and last value.
pub struct SocietyReducer;

impl SocietyReducer {
    fn dim_key(prefix: &str, dim: SocietyDimension) -> String {
        format!("{prefix}.{}", dim.as_str())
    }
}

impl Reducer for SocietyReducer {
    fn initial(&self) -> State {
        let mut s = State::new();
        let zero = serde_json::json!(0.0);
        for dim in SocietyDimension::all() {
            s.set(
                Self::dim_key("count", dim),
                serde_json::Value::Number(0.into()),
            );
            s.set(Self::dim_key("sum", dim), zero.clone());
            s.set(Self::dim_key("mean", dim), zero.clone());
            s.set(Self::dim_key("last", dim), serde_json::Value::Null);
        }
        s.set("signals", serde_json::Value::Number(0.into()));
        s
    }

    fn apply(&self, state: &mut State, event: &Event) {
        if event.event_type.as_str() != EVENT_TYPE_SIGNAL {
            return;
        }

        let Ok(signal) = ciborium::from_reader::<SocietySignal, _>(event.payload.as_slice()) else {
            return;
        };

        // Bad CBOR / non-finite samples do not bump `signals` or dimension stats.
        if !signal.value.is_finite() {
            return;
        }

        let signals = state
            .get("signals")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        state.set("signals", serde_json::Value::Number((signals + 1).into()));

        // Scaffold contract: samples are clamped to `[0.0, 1.0]`.
        let value = signal.value.clamp(0.0, 1.0);

        let dim = signal.dimension;
        let count = state
            .get(&Self::dim_key("count", dim))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0)
            + 1;
        let sum = state
            .get(&Self::dim_key("sum", dim))
            .and_then(serde_json::Value::as_f64)
            .unwrap_or(0.0)
            + value;
        #[allow(clippy::cast_precision_loss)]
        let mean = sum / (count as f64);

        state.set(
            Self::dim_key("count", dim),
            serde_json::Value::Number(count.into()),
        );
        // `value`/`sum`/`mean` are finite here, so `json!(f64)` always yields a Number.
        state.set(Self::dim_key("sum", dim), serde_json::json!(sum));
        state.set(Self::dim_key("mean", dim), serde_json::json!(mean));
        state.set(Self::dim_key("last", dim), serde_json::json!(value));
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    trait TestValueExt<T> {
        fn test_ok(self) -> T;
    }

    impl<T, E: std::fmt::Debug> TestValueExt<T> for Result<T, E> {
        fn test_ok(self) -> T {
            self.unwrap_or_else(|error| {
                std::panic::resume_unwind(Box::new(format!(
                    "unexpected society fixture error: {error:?}"
                )))
            })
        }
    }

    impl<T> TestValueExt<T> for Option<T> {
        fn test_ok(self) -> T {
            self.unwrap_or_else(|| {
                std::panic::resume_unwind(Box::new("missing society fixture value"))
            })
        }
    }

    use super::*;
    use pos_core::{
        clock::{Seq, WallTime},
        crypto::Hash,
        event::SchemaVersion,
        ids::EventId,
    };

    fn make_signal_event(entity: EntityId, signal: &SocietySignal) -> Event {
        let draft = draft_signal(entity, signal);
        Event {
            id: EventId::new(),
            entity: draft.entity,
            event_type: draft.event_type,
            payload: draft.payload,
            wall_time: WallTime::from_micros(1),
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
    fn plugin_new_and_default() {
        let p1 = SocietyPlugin::new();
        let p2 = SocietyPlugin::default();
        assert_eq!(p1.name(), "society");
        assert_eq!(p2.name(), "society");
        assert_ne!(p1.id(), p2.id());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn plugin_capability() {
        let cap = SocietyPlugin::new().capability();
        assert_eq!(cap.owned_event_types.len(), 1);
        assert_eq!(cap.owned_event_types[0].as_str(), EVENT_TYPE_SIGNAL);
        assert_eq!(cap.owned_entity_kinds, vec![ENTITY_KIND.to_owned()]);
        assert!(!cap.has_driver);
        assert!(cap.has_reducer);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn dimension_keys_cover_all() {
        let keys: Vec<_> = SocietyDimension::all()
            .into_iter()
            .map(SocietyDimension::as_str)
            .collect();
        assert_eq!(
            keys,
            vec!["trust", "opinion", "economy", "culture", "polarization"]
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn draft_signal_roundtrips() {
        let entity = EntityId::new();
        let signal = SocietySignal {
            dimension: SocietyDimension::Trust,
            value: 0.75,
            subject: Some("alice".into()),
            object: Some("bob".into()),
        };
        let draft = draft_signal(entity, &signal);
        assert_eq!(draft.entity, entity);
        assert_eq!(draft.event_type.as_str(), EVENT_TYPE_SIGNAL);
        let decoded: SocietySignal = ciborium::from_reader(draft.payload.as_slice()).test_ok();
        assert_eq!(decoded, signal);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn reducer_tracks_mean_per_dimension() {
        let reducer = SocietyReducer;
        let mut state = reducer.initial();
        let entity = EntityId::new();

        reducer.apply(
            &mut state,
            &make_signal_event(
                entity,
                &SocietySignal {
                    dimension: SocietyDimension::Trust,
                    value: 0.5,
                    subject: None,
                    object: None,
                },
            ),
        );
        reducer.apply(
            &mut state,
            &make_signal_event(
                entity,
                &SocietySignal {
                    dimension: SocietyDimension::Trust,
                    value: 1.0,
                    subject: None,
                    object: None,
                },
            ),
        );

        assert_eq!(
            state.get("signals").and_then(serde_json::Value::as_u64),
            Some(2)
        );
        assert_eq!(
            state.get("count.trust").and_then(serde_json::Value::as_u64),
            Some(2)
        );
        assert_eq!(
            state.get("mean.trust").and_then(serde_json::Value::as_f64),
            Some(0.75)
        );
        assert_eq!(
            state.get("last.trust").and_then(serde_json::Value::as_f64),
            Some(1.0)
        );
        // Other dimensions untouched.
        assert_eq!(
            state
                .get("count.opinion")
                .and_then(serde_json::Value::as_u64),
            Some(0)
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn reducer_ignores_other_event_types() {
        let reducer = SocietyReducer;
        let mut state = reducer.initial();
        let event = Event {
            id: EventId::new(),
            entity: EntityId::new(),
            event_type: Kind::new("other.event"),
            payload: CanonicalBytes::from_vec(vec![]),
            wall_time: WallTime::from_micros(0),
            seq: Seq::ZERO,
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            signature_identity: None,
            payload_hash: Hash::from_bytes([0u8; 32]),
        };
        reducer.apply(&mut state, &event);
        assert_eq!(
            state.get("signals").and_then(serde_json::Value::as_u64),
            Some(0)
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn reducer_skips_non_finite_value() {
        let reducer = SocietyReducer;
        let mut state = reducer.initial();
        let entity = EntityId::new();
        reducer.apply(
            &mut state,
            &make_signal_event(
                entity,
                &SocietySignal {
                    dimension: SocietyDimension::Trust,
                    value: f64::NAN,
                    subject: None,
                    object: None,
                },
            ),
        );
        assert_eq!(
            state.get("signals").and_then(serde_json::Value::as_u64),
            Some(0)
        );
        assert_eq!(
            state.get("count.trust").and_then(serde_json::Value::as_u64),
            Some(0)
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn reducer_clamps_out_of_range_values() {
        let reducer = SocietyReducer;
        let mut state = reducer.initial();
        let entity = EntityId::new();
        reducer.apply(
            &mut state,
            &make_signal_event(
                entity,
                &SocietySignal {
                    dimension: SocietyDimension::Trust,
                    value: 1.5,
                    subject: None,
                    object: None,
                },
            ),
        );
        assert_eq!(
            state.get("last.trust").and_then(serde_json::Value::as_f64),
            Some(1.0)
        );
        reducer.apply(
            &mut state,
            &make_signal_event(
                entity,
                &SocietySignal {
                    dimension: SocietyDimension::Trust,
                    value: -0.25,
                    subject: None,
                    object: None,
                },
            ),
        );
        assert_eq!(
            state.get("last.trust").and_then(serde_json::Value::as_f64),
            Some(0.0)
        );
        assert_eq!(
            state.get("mean.trust").and_then(serde_json::Value::as_f64),
            Some(0.5)
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn reducer_handles_bad_cbor() {
        let reducer = SocietyReducer;
        let mut state = reducer.initial();
        let event = Event {
            id: EventId::new(),
            entity: EntityId::new(),
            event_type: Kind::new(EVENT_TYPE_SIGNAL),
            payload: CanonicalBytes::from_vec(vec![0xFF, 0xFE]),
            wall_time: WallTime::from_micros(0),
            seq: Seq::ZERO,
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            signature_identity: None,
            payload_hash: Hash::from_bytes([0u8; 32]),
        };
        reducer.apply(&mut state, &event);
        assert_eq!(
            state.get("signals").and_then(serde_json::Value::as_u64),
            Some(0)
        );
        assert_eq!(
            state.get("count.trust").and_then(serde_json::Value::as_u64),
            Some(0)
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn decode_signal_ok_and_err() {
        let signal = SocietySignal {
            dimension: SocietyDimension::Economy,
            value: 0.2,
            subject: None,
            object: None,
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&signal, &mut buf).test_ok();
        assert_eq!(decode_signal(&buf).test_ok(), signal);
        assert!(matches!(
            decode_signal(&[0xFF]),
            Err(SocietyError::Decode(_))
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn all_dimensions_update_independently() {
        let reducer = SocietyReducer;
        let mut state = reducer.initial();
        let entity = EntityId::new();
        for (i, dim) in SocietyDimension::all().into_iter().enumerate() {
            let value = (f64::from(u32::try_from(i).test_ok()) + 1.0) / 10.0;
            reducer.apply(
                &mut state,
                &make_signal_event(
                    entity,
                    &SocietySignal {
                        dimension: dim,
                        value,
                        subject: None,
                        object: None,
                    },
                ),
            );
            assert_eq!(
                state
                    .get(&format!("last.{}", dim.as_str()))
                    .and_then(serde_json::Value::as_f64),
                Some(value)
            );
        }
        assert_eq!(
            state.get("signals").and_then(serde_json::Value::as_u64),
            Some(5)
        );
    }
}
