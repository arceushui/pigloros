//! ADR-088 R3: the composition-wide CPU reservation table of locally registered Plugins.
//!
//! [`PluginRegistry::register_local`] builds each Plugin's generated EBP1 before the rest of
//! the composition is known, so that budget first reserves CPU for the registering Plugin
//! alone. Every generated Plugin shares one execution profile, and ADR-088 requires every
//! closure of one admitted profile to carry the same complete reservation table: one row per
//! enabled Plugin. A one-row table per Plugin would make even a roster compared with itself
//! report a conflicting profile.
//!
//! Local admission therefore re-derives, from the complete registered set, each Plugin's EBP1,
//! the EOP1 that names that budget's digest, the OPC1 closure and the native pin that binds the
//! EOP1 digest. Each Plugin keeps its own reservation values; only the table grows. Every entry
//! is re-derived and the catalog built before anything is written, so a failed admission
//! leaves the registry unchanged. The EOP1, EBP1 and OPC1 wire formats do not change.

use pos_core::{
    executable_budget::{
        ExecutableBudgetPolicyInputV1, ExecutableBudgetPolicyV1, PluginCpuReservationV1,
    },
    manifest_owner_link::ManifestAdmissionCatalogRowV1,
    Hash, PluginId,
};

use super::{PluginEntry, PluginRegistry};
use crate::{
    composition::{ManifestRegistrationErrorV1, PluginPinV1, PluginRegistrationV1},
    output_admission::{OutputAdmissionV1, OutputPolicyClosureV1},
};

/// One local entry's pin and admission re-derived for the complete composition, not yet
/// written to the registry.
pub(super) struct SealedLocalEntry {
    plugin_id: PluginId,
    registration: Option<PluginRegistrationV1>,
    admission: OutputAdmissionV1,
}

impl PluginRegistry {
    /// The composition's CPU reservation table: each registered Plugin's own row, sorted by
    /// `PluginId` as EBP1 requires.
    ///
    /// An entry without an output admission contributes no row; admission rejects it anyway.
    pub(super) fn composition_cpu_reservations(&self) -> Vec<PluginCpuReservationV1> {
        let mut table: Vec<PluginCpuReservationV1> = self
            .plugins
            .iter()
            .filter_map(|(plugin_id, entry)| {
                let budget = entry.output_admission.as_ref()?.budget();
                let mut rows = budget.fields().plugin_cpu_reservations.iter();
                rows.find(|row| row.plugin_id == *plugin_id).copied()
            })
            .collect();
        table.sort_unstable_by_key(|row| row.plugin_id);
        table
    }

    /// Re-derive one local entry for the composition table and build its catalog row.
    ///
    /// # Errors
    /// `UnverifiedRegistration` for an entry without a retained closure or an available native
    /// pin that binds its generated policy, `MissingSlot` for an entry registered without a
    /// slot, and `ReservationTable` when the table does not fit one EBP1 (more than 256
    /// Plugins, or reservations beyond the budget's CPU limits).
    pub(super) fn sealed_local_entry(
        plugin_id: PluginId,
        entry: &PluginEntry,
        reservations: &[PluginCpuReservationV1],
    ) -> Result<(ManifestAdmissionCatalogRowV1, SealedLocalEntry), ManifestRegistrationErrorV1>
    {
        let admission = entry
            .output_admission
            .as_ref()
            .ok_or(ManifestRegistrationErrorV1::UnverifiedRegistration)?;
        let closure = admission
            .closure()
            .ok_or(ManifestRegistrationErrorV1::UnverifiedRegistration)?;
        let stable_slot = Self::local_entry_slot(plugin_id, entry)?;
        let (sealed, closure_hash) = resealed_admission(admission, closure, reservations)?;
        let digest = sealed.policy_digest();
        let generated = admission.policy_digest();
        let rebind = |old| resealed_registration(old, generated, digest);
        let registration = entry.registration.as_ref().and_then(rebind);
        let row = ManifestAdmissionCatalogRowV1 {
            stable_slot,
            plugin_id,
            plugin_name: entry.name.clone(),
            plugin_version: entry.version.clone(),
            implementation_hash: sealed.policy().fields().implementation_hash,
            eop1_native_digest: digest,
            closure_hash,
        };
        let pinned = registration.as_ref();
        Self::validate_manifest_parts(&row, entry, pinned, Some(&sealed))?;
        let parts = SealedLocalEntry {
            plugin_id,
            registration,
            admission: sealed,
        };
        Ok((row, parts))
    }

    /// Write every re-derived entry after the whole batch validated.
    ///
    /// Each entry is found by its `PluginId`; the ids were read from this registry and nothing
    /// has been added or removed since.
    pub(super) fn install_sealed_entries(&mut self, sealed: Vec<SealedLocalEntry>) {
        for parts in sealed {
            if let Some(entry) = self.plugins.get_mut(&parts.plugin_id) {
                entry.registration = parts.registration;
                entry.output_admission = Some(parts.admission);
            }
        }
    }
}

/// The generated closure rebuilt around the composition table, admitted for the same Plugin.
///
/// Only the reservation rows change; the EOP1 then names the new EBP1 digest.
///
/// # Errors
/// `ReservationTable` when the table is not a valid EBP1.
fn resealed_admission(
    admission: &OutputAdmissionV1,
    closure: &OutputPolicyClosureV1,
    reservations: &[PluginCpuReservationV1],
) -> Result<(OutputAdmissionV1, Hash), ManifestRegistrationErrorV1> {
    let fields = closure.executable_budget().fields();
    let budget = ExecutableBudgetPolicyV1::new(ExecutableBudgetPolicyInputV1 {
        plugin_cpu_reservations: reservations.to_vec(),
        revision: fields.revision,
        workload_profile: fields.workload_profile,
        cut_budget_family: fields.cut_budget_family,
        max_event_bytes: fields.max_event_bytes,
        fidelity_budgets: fields.fidelity_budgets,
        accounting_semantics: fields.accounting_semantics,
        execution_profile_hash: fields.execution_profile_hash,
        max_pass_wall_duration_us: fields.max_pass_wall_duration_us,
    })?;
    let sealed = closure.with_budget(budget);
    let closure_hash = sealed.manifest_closure_hash();
    Ok((admission.resealed(sealed), closure_hash))
}

/// The same pin and availability, now binding the re-derived EOP1 digest.
///
/// `None` when the registered pin did not bind the generated policy; admission then reports
/// the entry as unverified, exactly as it would have before re-derivation.
fn resealed_registration(
    registration: &PluginRegistrationV1,
    generated: Hash,
    sealed: Hash,
) -> Option<PluginRegistrationV1> {
    let pin = registration.pin();
    let bound = pin.configuration_digest() == generated;
    let roles = pin.roles().to_vec();
    let rebound = PluginPinV1::try_new(pin.implementation_kind(), pin.isolation(), sealed, roles);
    rebound
        .ok()
        .filter(|_| bound)
        .map(|pin| PluginRegistrationV1::new(pin, registration.availability()))
}
