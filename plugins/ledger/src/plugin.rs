//! [`LedgerPlugin`] descriptor — schema ownership for the runtime registry.
//!
//! `has_reducer` is `false` on purpose: the ledger folds through the
//! [`crate::LedgerStore`] port, not the `State`/`Reducer` machinery. A
//! `Reducer` wrapper for live world sessions is deferred to the multi-user
//! phase (ADR-017 Decision 2).

use pos_core::{
    event::Kind,
    ids::PluginId,
    plugin::{Capability, Plugin},
};

use crate::payload::{ENTITY_KIND, EVENT_TYPE_OUTCOME, EVENT_TYPE_PREDICTION};

/// Ledger plugin descriptor (schema owner; no reducer/driver).
pub struct LedgerPlugin {
    id: PluginId,
}

impl LedgerPlugin {
    /// Create a new ledger plugin descriptor.
    #[must_use]
    pub fn new() -> Self {
        Self {
            id: PluginId::new(),
        }
    }
}

impl Default for LedgerPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl Plugin for LedgerPlugin {
    fn id(&self) -> PluginId {
        self.id
    }

    fn name(&self) -> &'static str {
        "ledger"
    }

    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: vec![
                Kind::new(EVENT_TYPE_PREDICTION),
                Kind::new(EVENT_TYPE_OUTCOME),
            ],
            owned_entity_kinds: vec![ENTITY_KIND.to_owned()],
            has_driver: false,
            has_reducer: false,
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use pos_runtime::registry::PluginRegistry;

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn plugin_descriptor() {
        let p1 = LedgerPlugin::new();
        let p2 = LedgerPlugin::default();
        assert_eq!(p1.name(), "ledger");
        assert_ne!(p1.id(), p2.id());
        let cap = p1.capability();
        assert_eq!(
            cap.owned_event_types,
            vec![
                Kind::new(EVENT_TYPE_PREDICTION),
                Kind::new(EVENT_TYPE_OUTCOME)
            ]
        );
        assert_eq!(cap.owned_entity_kinds, vec![ENTITY_KIND.to_owned()]);
        assert!(!cap.has_driver);
        assert!(!cap.has_reducer);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn registers_with_runtime_without_reducer() -> Result<(), Box<dyn std::error::Error>> {
        let mut registry = PluginRegistry::new();
        let plugin = LedgerPlugin::new();
        registry.register(&plugin, None, None)?;
        assert!(registry.plugin_names().any(|n| n == "ledger"));
        Ok(())
    }
}
