//! Owner IDs of the Drivers of a factual Tick (ADR-064 Revision 3, R3.2.4).
//!
//! Every registry entry holds its owner ID from registration on. A slotted
//! entry (registered through `register_local`) is identified by its ADR-088
//! stable manifest slot alone. A slotless entry is identified by its output
//! policy identity, its name, and its rank among the slotless entries that
//! share both, so unrelated registrations never move an ID.

use pos_core::{factual_owner_id, FactualOwnerIdV1, FactualOwnerSourceV1, Hash, PluginId};

use super::{PluginEntry, PluginRegistry, RegistrationOptions};
use crate::{
    composition::ManifestSlotV1,
    output_admission::{OutputAdmissionV1, OutputPolicyClosureV1},
};

impl PluginRegistry {
    /// The owner ID a new entry takes, derived from its slot or from its
    /// closure identity and name.
    ///
    /// Every `PluginEntry` is built after one call to this helper. The struct
    /// literal requires the owner ID field, so an entry cannot be built
    /// without some owner ID, but nothing forces it to come from this helper.
    pub(super) fn factual_owner_id_for(
        &self,
        slot: Option<&ManifestSlotV1>,
        closure: Option<&OutputPolicyClosureV1>,
        name: &str,
    ) -> FactualOwnerIdV1 {
        slot.map_or_else(
            || {
                let policy_identity = closure_identity(closure);
                factual_owner_id(FactualOwnerSourceV1::Slotless {
                    policy_identity,
                    name,
                    rank: self.slotless_rank(policy_identity, name),
                })
            },
            |slot| factual_owner_id(FactualOwnerSourceV1::Slot(slot.as_str())),
        )
    }

    /// The owner ID of the entry a registration with `options` is about to add.
    pub(super) fn owner_id_for_options(
        &self,
        options: &RegistrationOptions,
        name: &str,
    ) -> FactualOwnerIdV1 {
        let admission = options.output_admission.as_ref();
        self.factual_owner_id_for(
            options.manifest_slot.as_ref(),
            admission.and_then(OutputAdmissionV1::closure),
            name,
        )
    }

    /// The number of slotless entries with this policy identity and name.
    fn slotless_rank(&self, policy_identity: Hash, name: &str) -> u32 {
        let twins = self
            .plugins
            .values()
            .filter(|entry| {
                entry.manifest_slot.is_none()
                    && entry.name == name
                    && entry_identity(entry) == policy_identity
            })
            .count();
        u32::try_from(twins).unwrap_or(u32::MAX)
    }

    /// Every registered Plugin with its owner ID in a factual Tick.
    ///
    /// The owner ID is a digest, so this is the way a host or test maps the
    /// owner of a recorded node back to a Plugin.
    #[must_use]
    pub fn factual_owner_ids(&self) -> Vec<(PluginId, FactualOwnerIdV1)> {
        self.plugins
            .iter()
            .map(|(id, entry)| (*id, entry.owner_id.clone()))
            .collect()
    }
}

/// The replay identity of a closure, or the zero digest without one.
fn closure_identity(closure: Option<&OutputPolicyClosureV1>) -> Hash {
    closure.map_or_else(Hash::zero, OutputPolicyClosureV1::replay_identity_digest)
}

pub(super) fn entry_identity(entry: &PluginEntry) -> Hash {
    let admission = entry.output_admission.as_ref();
    closure_identity(admission.and_then(OutputAdmissionV1::closure))
}
