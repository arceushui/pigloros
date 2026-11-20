//! Identity-safe removal of reconciled restart state, deleting each intent last.

use super::super::delete_record;
use super::{
    PlannedAttemptIntent, RegistryRecoveryEntry, RegistryResult, SystemdAttemptRecovery,
    SystemdAttemptRegistryError,
};
use crate::restart::RootsReleased;
use crate::SystemdAttemptUnitAbsenceObservation;

impl SystemdAttemptRecovery {
    /// Remove every recorded attempt and recognized temporary write.
    ///
    /// Each entry's exact unit must have been observed absent, and each PAI3
    /// root's recorded loop/dm generations observed released. Under the held
    /// recovery lock, the registry and every unmounted attempt directory are
    /// inventoried again and must be unchanged. Directories are removed first,
    /// through held parents that are synchronized, then every interrupted
    /// marker write, and then every record is unlinked with the registry
    /// synchronized after each, so intent goes last. The committed activation
    /// marker is kept.
    ///
    /// # Errors
    /// [`SystemdAttemptRegistryError::CleanupEvidence`] for missing unit or
    /// device evidence, before anything is removed. Changed registry state, a
    /// mounted or unknown directory, and any removal, unlink or fsync failure
    /// are also refused; directories or records may already be gone, so the
    /// next restart must inventory the surviving state again.
    pub(crate) fn remove_reconciled(
        &self,
        units_absent: &[SystemdAttemptUnitAbsenceObservation],
        roots_released: &RootsReleased,
    ) -> RegistryResult<Vec<PlannedAttemptIntent>> {
        let inventory = self.inventory_unmounted_directories()?;
        self.entries
            .iter()
            .all(|entry| proven(entry, units_absent, roots_released))
            .then_some(())
            .ok_or(SystemdAttemptRegistryError::CleanupEvidence)
            .and_then(|()| inventory.remove_directories())
            .and_then(|()| self.remove_temporary_markers())
            .and_then(|()| {
                self.entries
                    .iter()
                    .try_for_each(|entry| delete_record(&self.directory, entry.component()))
            })
            .map(|()| {
                self.entries
                    .iter()
                    .filter(|entry| !entry.is_temporary())
                    .filter_map(RegistryRecoveryEntry::intent)
                    .map(|intent| intent.planned().clone())
                    .collect()
            })
    }
}

/// Whether this entry's unit, and any recorded root, were observed released.
fn proven(
    entry: &RegistryRecoveryEntry,
    units_absent: &[SystemdAttemptUnitAbsenceObservation],
    roots_released: &RootsReleased,
) -> bool {
    let unit_proved = units_absent
        .iter()
        .any(|absent| absent.unit_name() == entry.unit_name());
    let root_proved = entry
        .intent()
        .and_then(super::RecoveredAttemptIntent::recorded_generations)
        .is_none()
        || roots_released.contains(entry.attempt_id());
    unit_proved && root_proved
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
