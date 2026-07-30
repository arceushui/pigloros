//! Immutable structural descriptions of effective plugin runtime composition.

use pos_core::ids::PluginId;

/// The ordered identity and version of one registered plugin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisteredPlugin {
    pub id: PluginId,
    pub name: String,
    pub version: String,
}

/// Validation-relevant metadata for one effective event schema.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisteredEventSchema {
    pub event_type: String,
    pub json_schema: Option<String>,
}

/// The current schema version registered for an event type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisteredSchemaVersion {
    pub event_type: String,
    pub version: u32,
}

/// One registered schema-transition edge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisteredUpcaster {
    pub event_type: String,
    pub source_version: u32,
    pub target_version: u32,
}

/// Deterministic structural description of a [`crate::PluginRegistry`].
///
/// Plugin registration order is retained because it determines driver
/// execution order. Effective schemas, current schema versions, and upcaster
/// transitions are canonicalized into lexical order. This describes runtime
/// registration topology only; it neither hashes nor attests opaque code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PluginComposition {
    /// Plugins in their actual registration order.
    pub plugins: Vec<RegisteredPlugin>,
    /// Effective schemas in lexical event-type order.
    pub schemas: Vec<RegisteredEventSchema>,
    /// Current schema versions in lexical event-type order.
    pub schema_versions: Vec<RegisteredSchemaVersion>,
    /// Schema-transition registrations in lexical topology order.
    pub upcasters: Vec<RegisteredUpcaster>,
}
