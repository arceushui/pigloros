#![allow(clippy::module_name_repetitions)]

use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::fmt;
use ulid::{Generator, Ulid};

use crate::CoreError;

thread_local! {
    static ULID_GEN: RefCell<Generator> = const { RefCell::new(Generator::new()) };
}

/// Generate a monotonically increasing ULID using the thread-local generator.
fn try_gen_ulid() -> Result<Ulid, CoreError> {
    ULID_GEN.with(|generator| {
        generator
            .borrow_mut()
            .generate()
            .map_err(|_| CoreError::IdGenerationOverflow)
    })
}

/// Preserve the infallible ID API while avoiding a process-wide panic on the
/// generator's extremely rare random-field overflow. Normal generation remains
/// monotonic; the fallback deliberately starts a fresh ULID when that invariant
/// can no longer be maintained by the current generator state.
fn gen_ulid() -> Ulid {
    generated_or_fallback(try_gen_ulid())
}

fn generated_or_fallback(generated: Result<Ulid, CoreError>) -> Ulid {
    generated.unwrap_or_else(|_| Ulid::generate())
}

macro_rules! ulid_newtype {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(Ulid);

        impl $name {
            /// Generate an ID while surfacing a monotonic-generator overflow.
            ///
            /// Prefer this method when the caller must know whether strict
            /// within-thread monotonicity was preserved.
            ///
            /// # Errors
            /// Returns [`CoreError::IdGenerationOverflow`] when the generator's
            /// random field cannot be incremented further in its current state.
            pub fn try_new() -> Result<Self, CoreError> {
                try_gen_ulid().map(Self)
            }

            /// Generate an ID.
            ///
            /// This keeps the longstanding infallible API. On a monotonic
            /// generator overflow it uses a fresh ULID rather than panicking;
            /// callers that require the overflow signal should use
            /// [`Self::try_new`].
            pub fn new() -> Self {
                Self(gen_ulid())
            }

            pub const fn from_ulid(ulid: Ulid) -> Self {
                Self(ulid)
            }

            pub const fn inner(&self) -> Ulid {
                self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self.0)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }
    };
}

ulid_newtype!(EntityId, "Unique identifier for an entity.");
ulid_newtype!(EventId, "Unique identifier for an event.");
ulid_newtype!(TimelineId, "Unique identifier for a timeline.");
ulid_newtype!(
    CorrelationId,
    "Groups related events into a logical transaction."
);
ulid_newtype!(PluginId, "Identifies a registered plugin.");
ulid_newtype!(RelationshipId, "Unique identifier for a relationship.");

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use proptest::{prop_assert, prop_assert_eq};

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn new_ids_are_unique() {
        let a = EntityId::new();
        let b = EntityId::new();
        assert_ne!(a, b);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn try_new_produces_an_id() -> Result<(), Box<dyn std::error::Error>> {
        assert_ne!(EntityId::try_new()?.inner(), Ulid::nil());
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn overflow_fallback_remains_infallible() {
        let id = generated_or_fallback(Err(CoreError::IdGenerationOverflow));
        assert_ne!(id, Ulid::nil());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn ids_are_monotonically_ordered_within_process() {
        let ids: Vec<EntityId> = (0..100).map(|_| EntityId::new()).collect();
        for window in ids.windows(2) {
            assert!(window[0] <= window[1]);
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn id_serde_json_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let id = EventId::new();
        let s = serde_json::to_string(&id)?;
        let back: EventId = serde_json::from_str(&s)?;
        assert_eq!(id, back);
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn id_serde_cbor_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let id = TimelineId::new();
        let mut buf = Vec::new();
        ciborium::into_writer(&id, &mut buf)?;
        let back: TimelineId = ciborium::from_reader(buf.as_slice())?;
        assert_eq!(id, back);
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn all_id_types_are_copy() {
        fn assert_copy<T: Copy>() {}
        assert_copy::<EntityId>();
        assert_copy::<EventId>();
        assert_copy::<TimelineId>();
        assert_copy::<CorrelationId>();
        assert_copy::<PluginId>();
        assert_copy::<RelationshipId>();
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn id_from_ulid_round_trip() {
        let ulid = Ulid::generate();
        let id = EntityId::from_ulid(ulid);
        assert_eq!(id.inner(), ulid);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn id_display_is_ulid_string() {
        let ulid = Ulid::generate();
        let id = EntityId::from_ulid(ulid);
        assert_eq!(id.to_string(), ulid.to_string());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn different_id_types_have_different_debug() {
        let entity = EntityId::new();
        let event = EventId::new();
        assert!(format!("{entity:?}").starts_with("EntityId("));
        assert!(format!("{event:?}").starts_with("EventId("));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn relationship_id_is_unique() {
        let a = RelationshipId::new();
        let b = RelationshipId::new();
        assert_ne!(a, b);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn default_impl_produces_valid_id() {
        // Exercises the Default::default() path generated by ulid_newtype! for each id type.
        let _entity = EntityId::default();
        let _event = EventId::default();
        let _timeline = TimelineId::default();
        let _correlation = CorrelationId::default();
        let _plugin = PluginId::default();
        let _relationship = RelationshipId::default();
        // Two defaults should produce different ids (calls Self::new() each time).
        let a = EntityId::default();
        let b = EntityId::default();
        assert_ne!(a, b);
    }

    proptest::proptest! {
        #[test]
        #[cfg_attr(coverage_nightly, coverage(off))]
        fn ord_is_total_for_entity_ids(a: u128, b: u128) {
            let ia = EntityId::from_ulid(Ulid::from(a));
            let ib = EntityId::from_ulid(Ulid::from(b));
            let lt = ia < ib;
            let eq = ia == ib;
            let gt = ia > ib;
            assert_eq!(u8::from(lt) + u8::from(eq) + u8::from(gt), 1);
        }

        #[test]
        #[cfg_attr(coverage_nightly, coverage(off))]
        fn ord_stable_after_serde(a: u128, b: u128) {
            let ia = EntityId::from_ulid(Ulid::from(a));
            let ib = EntityId::from_ulid(Ulid::from(b));
            let ia_json = serde_json::to_string(&ia);
            prop_assert!(ia_json.is_ok(), "EntityId JSON serialization failed");
            let ib_json = serde_json::to_string(&ib);
            prop_assert!(ib_json.is_ok(), "EntityId JSON serialization failed");
            if let (Ok(ia_json), Ok(ib_json)) = (ia_json, ib_json) {
                let ia2 = serde_json::from_str::<EntityId>(&ia_json);
                let ib2 = serde_json::from_str::<EntityId>(&ib_json);
                prop_assert!(ia2.is_ok(), "EntityId JSON deserialization failed");
                prop_assert!(ib2.is_ok(), "EntityId JSON deserialization failed");
                if let (Ok(ia2), Ok(ib2)) = (ia2, ib2) {
                    prop_assert_eq!(ia.cmp(&ib), ia2.cmp(&ib2));
                }
            }
        }
    }
}
