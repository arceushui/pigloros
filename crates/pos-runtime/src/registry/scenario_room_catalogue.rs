//! The ADR-041 bundled-plugin catalogue of one registry (Redmine #1397).

use super::PluginRegistry;
use crate::composition::PluginRegistrationV1;
use crate::scenario_room::{capability_set_hash_v1, ScenarioRoomCatalogueV1};

impl PluginRegistry {
    /// The Plugins a Scenario Room may name: every entry registered from a
    /// Plugin, by name and version, with its `capability_set_hash` (the
    /// Proposed ADR-041 amendment of #303, A2 and A3). Entries that
    /// `register_driver` added carry no Plugin capability and are left out.
    #[must_use]
    pub fn scenario_room_catalogue_v1(&self) -> ScenarioRoomCatalogueV1 {
        ScenarioRoomCatalogueV1::from_registered(self.plugins.values().filter_map(|entry| {
            entry.capability.as_ref().map(|capability| {
                (
                    entry.name.as_str(),
                    entry.version.as_str(),
                    capability_set_hash_v1(
                        capability,
                        entry.registration.as_ref().map(PluginRegistrationV1::pin),
                        |event_type| self.schemas.json_schema(event_type),
                    ),
                )
            })
        }))
    }
}
