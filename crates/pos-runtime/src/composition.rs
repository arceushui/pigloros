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

/// Deterministic structural description of a [`crate::PluginRegistry`].
///
/// Plugin registration order is retained because it determines driver
/// execution order. Effective schemas are canonicalized into lexical order.
/// This describes runtime registration topology only; it neither hashes nor
/// attests opaque code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PluginComposition {
    /// Plugins in their actual registration order.
    pub plugins: Vec<RegisteredPlugin>,
    /// Effective schemas in lexical event-type order.
    pub schemas: Vec<RegisteredEventSchema>,
}
