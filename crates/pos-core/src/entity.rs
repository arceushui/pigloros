use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::ids::{EntityId, RelationshipId};

/// The kind/type of an entity, e.g. `"agent"`, `"location"`. Plugin-owned.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EntityKind(String);

impl EntityKind {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for EntityKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The kind/type of a relationship, e.g. `"trusts"`, `"employs"`. Plugin-owned.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RelationshipKind(String);

impl RelationshipKind {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An entity in the simulation. All domain-specific data lives in plugins/events.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entity {
    pub id: EntityId,
    pub kind: EntityKind,
    /// Arbitrary string metadata; plugin-owned key-value pairs.
    pub metadata: HashMap<String, String>,
}

impl Entity {
    #[must_use]
    pub fn new(kind: EntityKind) -> Self {
        Self {
            id: EntityId::new(),
            kind,
            metadata: HashMap::new(),
        }
    }

    #[must_use]
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

/// A directed relationship between two entities.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Relationship {
    pub id: RelationshipId,
    pub source: EntityId,
    pub target: EntityId,
    pub kind: RelationshipKind,
    pub metadata: HashMap<String, String>,
}

impl Relationship {
    #[must_use]
    pub fn new(source: EntityId, target: EntityId, kind: RelationshipKind) -> Self {
        Self {
            id: RelationshipId::new(),
            source,
            target,
            kind,
            metadata: HashMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn entity_has_unique_id() {
        let a = Entity::new(EntityKind::new("agent"));
        let b = Entity::new(EntityKind::new("agent"));
        assert_ne!(a.id, b.id);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn entity_json_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let e = Entity::new(EntityKind::new("location")).with_metadata("name", "Tokyo");
        let s = serde_json::to_string(&e)?;
        let back: Entity = serde_json::from_str(&s)?;
        assert_eq!(e, back);
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn entity_cbor_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let e = Entity::new(EntityKind::new("agent"));
        let mut buf = Vec::new();
        ciborium::into_writer(&e, &mut buf)?;
        let back: Entity = ciborium::from_reader(buf.as_slice())?;
        assert_eq!(e, back);
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn entity_metadata_builder() {
        let e = Entity::new(EntityKind::new("twin"))
            .with_metadata("user", "alice")
            .with_metadata("locale", "ja");
        assert_eq!(
            e.metadata.get("user").map(std::string::String::as_str),
            Some("alice")
        );
        assert_eq!(
            e.metadata.get("locale").map(std::string::String::as_str),
            Some("ja")
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn entity_kind_display() {
        let k = EntityKind::new("world");
        assert_eq!(k.to_string(), "world");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn relationship_json_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let src = EntityId::new();
        let tgt = EntityId::new();
        let r = Relationship::new(src, tgt, RelationshipKind::new("trusts"));
        let s = serde_json::to_string(&r)?;
        let back: Relationship = serde_json::from_str(&s)?;
        assert_eq!(r, back);
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn relationship_cbor_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let src = EntityId::new();
        let tgt = EntityId::new();
        let r = Relationship::new(src, tgt, RelationshipKind::new("employs"));
        let mut buf = Vec::new();
        ciborium::into_writer(&r, &mut buf)?;
        let back: Relationship = ciborium::from_reader(buf.as_slice())?;
        assert_eq!(r, back);
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn relationship_has_unique_id() {
        let src = EntityId::new();
        let tgt = EntityId::new();
        let a = Relationship::new(src, tgt, RelationshipKind::new("trusts"));
        let b = Relationship::new(src, tgt, RelationshipKind::new("trusts"));
        assert_ne!(a.id, b.id);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn entity_kind_json_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let k = EntityKind::new("simulation.agent");
        let back: EntityKind = serde_json::from_str(&serde_json::to_string(&k)?)?;
        assert_eq!(k, back);
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn relationship_kind_json_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let k = RelationshipKind::new("co-located");
        let back: RelationshipKind = serde_json::from_str(&serde_json::to_string(&k)?)?;
        assert_eq!(k, back);
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn entity_kind_as_str() {
        let k = EntityKind::new("agent");
        assert_eq!(k.as_str(), "agent");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn relationship_kind_as_str() {
        let k = RelationshipKind::new("trusts");
        assert_eq!(k.as_str(), "trusts");
    }
}
