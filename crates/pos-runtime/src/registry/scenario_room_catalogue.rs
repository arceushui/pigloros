//! The ADR-041 bundled-plugin catalogue of one registry (Redmine #1397).

use super::PluginRegistry;
use crate::composition::PluginAvailabilityV1;
use crate::scenario_room::{capability_set_hash_v1, ScenarioRoomCatalogueV1};

impl PluginRegistry {
    /// The Plugins a Scenario Room may name: every entry registered from a
    /// Plugin and available (an unpinned registration, or a pinned one whose
    /// availability is `Available`), by name and version, with its
    /// `capability_set_hash` (the Proposed ADR-041 amendment of #303, A2 and
    /// A3). Entries that `register_driver` added carry no Plugin and are
    /// left out, as are disabled, unavailable, revoked, trapped and
    /// exhausted registrations.
    #[must_use]
    pub fn scenario_room_catalogue_v1(&self) -> ScenarioRoomCatalogueV1 {
        ScenarioRoomCatalogueV1::from_registered(
            self.plugins
                .values()
                .filter(|entry| {
                    entry.from_plugin
                        && entry.registration.as_ref().is_none_or(|registration| {
                            registration.availability() == PluginAvailabilityV1::Available
                        })
                })
                .map(|entry| {
                    (
                        entry.name.as_str(),
                        entry.version.as_str(),
                        capability_set_hash_v1(entry.owned_event_types.iter()),
                    )
                }),
        )
    }
}
