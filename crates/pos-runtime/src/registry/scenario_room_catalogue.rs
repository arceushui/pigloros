//! The ADR-041 bundled-plugin catalogue of one registry (Redmine #1397).

use pos_core::Plugin;

use super::catalogue::{first_broken_link, HostCatalogueEntryV1, InstalledPluginFactoryV1};
use super::PluginRegistry;
use crate::composition::PluginAvailabilityV1;
use crate::error::RuntimeError;
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

impl<F: InstalledPluginFactoryV1> HostCatalogueEntryV1<F> {
    /// The Scenario Room catalogue of this reviewed host catalogue entry
    /// (#303 owner decision of 2026-11-15): the one Plugin its factory
    /// builds from `frozen_configuration`, by name and version, with its
    /// `capability_set_hash`. It builds the reviewed product only to read
    /// its descriptor, after the same Plugin and approver link checks as
    /// registration. It never registers, admits or runs the product, so it
    /// needs no installed EPF1.
    ///
    /// # Errors
    /// Returns the registration's link error when the built Plugin or
    /// approver is not the entry's reviewed product.
    pub fn scenario_room_catalogue_v1(
        &self,
        frozen_configuration: &F::Configuration,
    ) -> Result<ScenarioRoomCatalogueV1, RuntimeError> {
        let product = F::build(frozen_configuration);
        first_broken_link([
            (
                self.spec.accepts_plugin(&product.plugin),
                crate::OutputAdmissionErrorV1::PluginMismatch,
            ),
            (
                self.spec.accepts_approver::<F::Approver>(),
                crate::OutputAdmissionErrorV1::CallbackMismatch { kind: "approver" },
            ),
        ])
        .map(|()| {
            let capability = product.plugin.capability();
            ScenarioRoomCatalogueV1::from_registered(std::iter::once((
                product.plugin.name(),
                product.plugin.version(),
                capability_set_hash_v1(capability.owned_event_types.iter()),
            )))
        })
        .map_err(RuntimeError::from)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use pos_core::{Capability, Kind, PluginId};

    use super::*;
    use crate::scenario_room::RoomPluginRefV1;
    use crate::{InstalledPluginProductV1, NoActionApproverV1};

    struct DescribedPlugin(PluginId);

    impl Plugin for DescribedPlugin {
        fn id(&self) -> PluginId {
            self.0
        }

        fn name(&self) -> &'static str {
            "described-actions"
        }

        fn capability(&self) -> Capability {
            Capability {
                owned_event_types: vec![Kind::new("described.action.v1")],
                ..Capability::default()
            }
        }
    }

    struct DescribedFactory;

    impl InstalledPluginFactoryV1 for DescribedFactory {
        type Configuration = ();
        type Plugin = DescribedPlugin;
        type Approver = NoActionApproverV1;

        fn configuration_details(_configuration: &()) -> Vec<u8> {
            Vec::new()
        }

        fn build(
            _configuration: &(),
        ) -> InstalledPluginProductV1<DescribedPlugin, NoActionApproverV1> {
            InstalledPluginProductV1 {
                plugin: DescribedPlugin(PluginId::new()),
                reducer: None,
                approver: NoActionApproverV1,
            }
        }
    }

    /// An entry whose reviewed source accepts its product describes that
    /// one Plugin, and only it.
    #[test]
    fn an_accepted_entry_describes_its_one_plugin() -> Result<(), RuntimeError> {
        let entry = HostCatalogueEntryV1::<DescribedFactory> {
            spec: crate::output_admission::OutputPolicySourceV1::Generated,
            factory: std::marker::PhantomData,
        };
        let catalogue = entry.scenario_room_catalogue_v1(&())?;
        let reference = |plugin_id: &str| RoomPluginRefV1 {
            plugin_id: plugin_id.to_owned(),
            version: "0.1.0".to_owned(),
        };
        assert_eq!(
            catalogue.resolve(&reference("described-actions")),
            Ok(capability_set_hash_v1(
                [Kind::new("described.action.v1")].iter()
            ))
        );
        assert!(catalogue.resolve(&reference("other")).is_err());
        Ok(())
    }
}
