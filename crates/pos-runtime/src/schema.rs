//! Event-type schema registry.
//!
//! Plugins declare the event types they own. The runtime rejects any `EventDraft`
//! whose `event_type` is not registered. Payload validation is intentionally
//! lightweight in Wave 3 — a plugin can provide a JSON Schema string for richer
//! validation in future waves.

use std::collections::HashMap;

use pos_core::event::{EventDraft, Kind};

use crate::error::RuntimeError;

/// Metadata a plugin registers for one of its event types.
#[derive(Clone, Debug)]
pub struct EventTypeSchema {
    /// The namespaced event type string (e.g. `"world.observation"`).
    pub event_type: Kind,
    /// Human-readable description of this event type.
    pub description: String,
    /// Optional JSON Schema string for payload validation (Wave 3: presence check only).
    pub json_schema: Option<String>,
}

/// Registry of all event type schemas declared by loaded plugins.
///
/// Enforces the invariant: every appended event must have a known `event_type`.
#[derive(Default, Debug)]
pub struct SchemaRegistry {
    schemas: HashMap<String, EventTypeSchema>,
}

impl SchemaRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an event type schema.
    ///
    /// Silently overwrites if the same event type is re-registered (last writer wins).
    pub fn register(&mut self, schema: EventTypeSchema) {
        self.schemas.insert(schema.event_type.as_str().to_owned(), schema);
    }

    /// Returns `true` if the event type is registered.
    #[must_use]
    pub fn contains(&self, event_type: &str) -> bool {
        self.schemas.contains_key(event_type)
    }

    /// Validate a draft event against the registry.
    ///
    /// # Errors
    /// Returns [`RuntimeError::UnknownEventType`] if the event type is not registered.
    pub fn validate(&self, draft: &EventDraft) -> Result<(), RuntimeError> {
        if !self.contains(draft.event_type.as_str()) {
            return Err(RuntimeError::UnknownEventType(
                draft.event_type.as_str().to_owned(),
            ));
        }
        Ok(())
    }

    /// Validate a batch of drafts.
    ///
    /// # Errors
    /// Returns the first validation error encountered.
    pub fn validate_batch(&self, drafts: &[EventDraft]) -> Result<(), RuntimeError> {
        for draft in drafts {
            self.validate(draft)?;
        }
        Ok(())
    }

    /// Number of registered event types.
    #[must_use]
    pub fn len(&self) -> usize {
        self.schemas.len()
    }

    /// Returns `true` if no event types are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.schemas.is_empty()
    }

    /// Iterate over all registered schemas.
    pub fn iter(&self) -> impl Iterator<Item = &EventTypeSchema> {
        self.schemas.values()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pos_core::{
        event::{CanonicalBytes, EventDraft, Kind},
        ids::EntityId,
    };

    fn draft(event_type: &str) -> EventDraft {
        EventDraft::new(
            EntityId::new(),
            Kind::new(event_type),
            CanonicalBytes::from_vec(vec![]),
        )
    }

    fn schema(event_type: &str) -> EventTypeSchema {
        EventTypeSchema {
            event_type: Kind::new(event_type),
            description: format!("schema for {event_type}"),
            json_schema: None,
        }
    }

    #[test]
    fn empty_registry_rejects_all() {
        let reg = SchemaRegistry::new();
        let err = reg.validate(&draft("world.observation")).unwrap_err();
        assert!(matches!(err, RuntimeError::UnknownEventType(_)));
    }

    #[test]
    fn registered_type_passes_validation() {
        let mut reg = SchemaRegistry::new();
        reg.register(schema("world.observation"));
        reg.validate(&draft("world.observation")).unwrap();
    }

    #[test]
    fn unregistered_type_fails_validation() {
        let mut reg = SchemaRegistry::new();
        reg.register(schema("world.observation"));
        let err = reg.validate(&draft("agent.action")).unwrap_err();
        assert!(matches!(err, RuntimeError::UnknownEventType(ref t) if t == "agent.action"));
    }

    #[test]
    fn validate_batch_fails_on_first_unknown() {
        let mut reg = SchemaRegistry::new();
        reg.register(schema("a.ok"));
        let drafts = vec![draft("a.ok"), draft("b.unknown"), draft("a.ok")];
        let err = reg.validate_batch(&drafts).unwrap_err();
        assert!(matches!(err, RuntimeError::UnknownEventType(ref t) if t == "b.unknown"));
    }

    #[test]
    fn validate_batch_passes_all_known() {
        let mut reg = SchemaRegistry::new();
        reg.register(schema("a.event"));
        reg.register(schema("b.event"));
        let drafts = vec![draft("a.event"), draft("b.event"), draft("a.event")];
        reg.validate_batch(&drafts).unwrap();
    }

    #[test]
    fn len_and_is_empty() {
        let mut reg = SchemaRegistry::new();
        assert!(reg.is_empty());
        reg.register(schema("x"));
        assert_eq!(reg.len(), 1);
        assert!(!reg.is_empty());
    }

    #[test]
    fn re_register_overwrites() {
        let mut reg = SchemaRegistry::new();
        reg.register(EventTypeSchema {
            event_type: Kind::new("x"),
            description: "first".to_owned(),
            json_schema: None,
        });
        reg.register(EventTypeSchema {
            event_type: Kind::new("x"),
            description: "second".to_owned(),
            json_schema: Some("{}".to_owned()),
        });
        assert_eq!(reg.len(), 1);
        let s = reg.iter().next().unwrap();
        assert_eq!(s.description, "second");
    }

    #[test]
    fn contains_returns_correct_values() {
        let mut reg = SchemaRegistry::new();
        reg.register(schema("known"));
        assert!(reg.contains("known"));
        assert!(!reg.contains("unknown"));
    }
}
