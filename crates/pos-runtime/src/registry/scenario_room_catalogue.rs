//! Plugin registrations available for use in a Scenario Room.

use pos_core::Plugin;

use super::catalogue::{first_broken_link, HostCatalogueEntryV1, InstalledPluginFactoryV1};
use super::PluginRegistry;
use crate::composition::PluginAvailabilityV1;
use crate::error::RuntimeError;
use crate::scenario_room::{capability_set_hash_v1, ScenarioRoomCatalogueV1};

impl PluginRegistry {
    /// Return Plugin registrations available for use in a Scenario Room.
    ///
    /// Includes unpinned registrations and pinned registrations whose
    /// availability is `Available`. Entries added by `register_driver` and
    /// disabled, unavailable, revoked, trapped, or exhausted registrations
    /// are omitted. Each entry includes its name, version, and hash of owned
    /// event types.
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
    /// Build a Scenario Room catalogue from the reviewed factory's Plugin
    /// product. This checks the Plugin and approver links before reading its
    /// name, version, and capability-set hash. It does not register, admit, or
    /// run the product.
    ///
    /// The factory builds its product before the link checks.
    ///
    /// # Errors
    /// Returns a link error when the built Plugin or approver does not match
    /// the reviewed entry.
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
