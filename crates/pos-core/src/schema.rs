use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::event::{CanonicalBytes, Kind, SchemaVersion};

/// Upcast a payload from one schema version to the current one.
pub trait Upcaster: Send + Sync {
    fn event_type(&self) -> &Kind;
    fn source_version(&self) -> SchemaVersion;
    fn target_version(&self) -> SchemaVersion;
    /// Transform the payload bytes from `from_version` to `to_version`.
    /// For the current version, this is the identity function.
    fn upcast(&self, payload: CanonicalBytes) -> CanonicalBytes;
}

/// Registry of upcasters, keyed by `(event_type, from_version)`.
#[derive(Default)]
pub struct UpcasterRegistry {
    // Key: (event_type_str, from_version_u32)
    upcasters: HashMap<(String, u32), Box<dyn Upcaster>>,
}

impl UpcasterRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, upcaster: Box<dyn Upcaster>) {
        let key = (
            upcaster.event_type().as_str().to_owned(),
            upcaster.source_version().as_u32(),
        );
        self.upcasters.insert(key, upcaster);
    }

    /// Iterate over the registered schema-transition topology.
    ///
    /// This exposes only registration metadata. It deliberately does not
    /// expose or compare the opaque upcaster implementations themselves.
    pub fn registrations(&self) -> impl Iterator<Item = (&str, SchemaVersion, SchemaVersion)> {
        self.upcasters.values().map(|upcaster| {
            (
                upcaster.event_type().as_str(),
                upcaster.source_version(),
                upcaster.target_version(),
            )
        })
    }

    /// Upcast `payload` for `event_type` from `from` to `to`, chaining upcasters if needed.
    /// Returns the payload unchanged if no upcaster is registered.
    pub fn upcast(
        &self,
        event_type: &Kind,
        mut from: SchemaVersion,
        to: SchemaVersion,
        mut payload: CanonicalBytes,
    ) -> CanonicalBytes {
        while from < to {
            let key = (event_type.as_str().to_owned(), from.as_u32());
            match self.upcasters.get(&key) {
                Some(up) => {
                    payload = up.upcast(payload);
                    from = up.target_version();
                }
                None => break,
            }
        }
        payload
    }
}

/// A schema-version constant bundle for a plugin's event types.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaVersionMap {
    pub versions: HashMap<String, u32>,
}

impl SchemaVersionMap {
    #[must_use]
    pub fn new() -> Self {
        Self {
            versions: HashMap::new(),
        }
    }

    pub fn set(&mut self, event_type: impl Into<String>, version: u32) {
        self.versions.insert(event_type.into(), version);
    }

    #[must_use]
    pub fn current(&self, event_type: &str) -> SchemaVersion {
        SchemaVersion::new(*self.versions.get(event_type).unwrap_or(&1))
    }
}

impl Default for SchemaVersionMap {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct IdentityUpcaster {
        event_type: Kind,
        from: SchemaVersion,
        to: SchemaVersion,
    }

    impl Upcaster for IdentityUpcaster {
        fn event_type(&self) -> &Kind {
            &self.event_type
        }
        fn source_version(&self) -> SchemaVersion {
            self.from
        }
        fn target_version(&self) -> SchemaVersion {
            self.to
        }
        fn upcast(&self, payload: CanonicalBytes) -> CanonicalBytes {
            payload
        }
    }

    /// Upcaster that appends a marker byte to simulate a real schema migration.
    struct MigratingUpcaster {
        event_type: Kind,
    }

    impl Upcaster for MigratingUpcaster {
        fn event_type(&self) -> &Kind {
            &self.event_type
        }
        fn source_version(&self) -> SchemaVersion {
            SchemaVersion::new(1)
        }
        fn target_version(&self) -> SchemaVersion {
            SchemaVersion::new(2)
        }
        fn upcast(&self, payload: CanonicalBytes) -> CanonicalBytes {
            let mut v = payload.as_slice().to_vec();
            v.push(0xFF); // migration marker
            CanonicalBytes::from_vec(v)
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn identity_upcaster_no_op_for_current_version() {
        let mut reg = UpcasterRegistry::new();
        let kind = Kind::new("test.event");
        reg.register(Box::new(IdentityUpcaster {
            event_type: kind.clone(),
            from: SchemaVersion::V1,
            to: SchemaVersion::V1,
        }));
        let payload = CanonicalBytes::from_vec(b"data".to_vec());
        let result = reg.upcast(&kind, SchemaVersion::V1, SchemaVersion::V1, payload.clone());
        assert_eq!(result.as_slice(), payload.as_slice());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn migrating_upcaster_transforms_v1_to_v2() {
        let mut reg = UpcasterRegistry::new();
        let kind = Kind::new("thing.created");
        reg.register(Box::new(MigratingUpcaster {
            event_type: kind.clone(),
        }));

        let payload = CanonicalBytes::from_vec(b"original".to_vec());
        let result = reg.upcast(&kind, SchemaVersion::new(1), SchemaVersion::new(2), payload);

        assert_eq!(result.as_slice(), b"original\xFF");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn no_upcaster_returns_payload_unchanged() {
        let reg = UpcasterRegistry::new();
        let kind = Kind::new("unknown.event");
        let payload = CanonicalBytes::from_vec(b"unchanged".to_vec());
        let result = reg.upcast(
            &kind,
            SchemaVersion::new(1),
            SchemaVersion::new(2),
            payload.clone(),
        );
        assert_eq!(result.as_slice(), payload.as_slice());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn already_at_current_version_returns_unchanged() {
        let reg = UpcasterRegistry::new();
        let kind = Kind::new("test.event");
        let payload = CanonicalBytes::from_vec(b"current".to_vec());
        let result = reg.upcast(
            &kind,
            SchemaVersion::new(3),
            SchemaVersion::new(3),
            payload.clone(),
        );
        assert_eq!(result.as_slice(), payload.as_slice());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn schema_version_map_returns_default_1_for_unknown() {
        let map = SchemaVersionMap::new();
        assert_eq!(map.current("unknown.event"), SchemaVersion::new(1));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn schema_version_map_returns_registered_version() {
        let mut map = SchemaVersionMap::new();
        map.set("agent.action", 3);
        assert_eq!(map.current("agent.action"), SchemaVersion::new(3));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn schema_version_map_json_round_trip() {
        let mut map = SchemaVersionMap::new();
        map.set("a.b", 2);
        map.set("c.d", 5);
        let back: SchemaVersionMap =
            serde_json::from_str(&serde_json::to_string(&map).unwrap()).unwrap();
        assert_eq!(map, back);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn schema_version_map_default_equals_new() {
        let via_default = SchemaVersionMap::default();
        let via_new = SchemaVersionMap::new();
        assert_eq!(via_default, via_new);
        assert!(via_default.versions.is_empty());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn identity_upcaster_target_version_and_upcast_called() {
        // Exercises IdentityUpcaster::target_version() and upcast() by running a chain
        // where from < to so the loop body actually executes.
        let kind = Kind::new("step.event");
        let mut reg = UpcasterRegistry::new();
        reg.register(Box::new(IdentityUpcaster {
            event_type: kind.clone(),
            from: SchemaVersion::new(1),
            to: SchemaVersion::new(2),
        }));
        let payload = CanonicalBytes::from_vec(b"data".to_vec());
        // from=1, to=2: loop runs, calls upcast() and target_version() on IdentityUpcaster
        let result = reg.upcast(
            &kind,
            SchemaVersion::new(1),
            SchemaVersion::new(2),
            payload.clone(),
        );
        assert_eq!(result.as_slice(), payload.as_slice());
    }
}
