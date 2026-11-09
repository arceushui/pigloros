//! The live owner's terminal cleanup predicate, deleting durable intent last.

use std::sync::atomic::Ordering;

use rustix::fs::{unlinkat, AtFlags};

use super::super::{registry_io, RegistryDirectory};
use super::{PlannedAttemptIntent, PreparedAttemptDirectory, SystemdAttemptRegistryError};
use crate::{ReleasedAttemptRoot, SystemdAttemptUnitTeardownObservation, TransientServiceUnitName};

type TerminalResult<T = ()> = Result<T, SystemdAttemptRegistryError>;

/// How the live owner knows that no attempt process can hold its resources.
#[derive(Clone, Copy, Debug)]
pub enum AttemptUnitTermination<'a> {
    /// No execution was ever claimed. Cleanup consumes the one start
    /// permission atomically, so no later execution can submit the unit.
    Unclaimed,
    /// The exact unit was stopped, observed unloaded, and its retained cgroup
    /// observed empty afterwards. Cleanup closes any unclaimed start permission.
    Stopped(&'a SystemdAttemptUnitTeardownObservation),
}

/// The completed live-owner cleanup of one attempt.
///
/// Every protected step was observed in order and the planned intent was
/// removed with its registry parent synchronized. This records no signature,
/// terminal classification or admission decision; existing registry
/// quarantine and the provider's control-floor checks still govern admission.
#[derive(Debug, Eq, PartialEq)]
pub struct CompletedAttemptCleanup {
    intent: PlannedAttemptIntent,
}

impl CompletedAttemptCleanup {
    /// The exact planned ownership whose resources and intent were removed.
    #[must_use]
    pub const fn intent(&self) -> &PlannedAttemptIntent {
        &self.intent
    }
}

impl PreparedAttemptDirectory {
    /// Finish this attempt's terminal cleanup and delete its intent last.
    ///
    /// The supplied evidence must already cover the earlier ADR-087 §3 steps:
    /// `unit` proves that the exact unit cannot hold processes, and `root`
    /// proves detachment and original loop/dm absence of the single root
    /// activated on this tree. A tree on which no activation began needs no
    /// root evidence; a tree with more than one activation, or one activation
    /// without its released root, is refused. Under registry ownership, this
    /// then verifies the exact record and unmounted tree, removes the root and
    /// attempt directories while synchronizing each held parent, reads the
    /// exact record back, unlinks it and synchronizes the registry parent.
    ///
    /// The lifecycle controller must retain exclusive attempt ownership and
    /// obtain both observations before calling. A quarantined owner may finish
    /// a fully evidenced attempt, but this never clears quarantine or reopens
    /// admission.
    ///
    /// # Errors
    /// [`SystemdAttemptRegistryError::CleanupEvidence`] rejects claimed
    /// execution without stop evidence, evidence for another unit or tree, and
    /// missing or ambiguous root evidence before anything is removed. Changed
    /// records or trees, poisoned ownership and every removal, unlink or fsync
    /// failure are also refused. Every failure closes new commits; directories
    /// or the record may already be gone, so restart reconciliation must
    /// inspect the surviving state rather than treat an error as no change.
    pub fn finish_terminal_cleanup(
        self,
        unit: AttemptUnitTermination<'_>,
        root: Option<ReleasedAttemptRoot>,
    ) -> TerminalResult<CompletedAttemptCleanup> {
        let Ok(mut state) = self.planned.state.lock() else {
            return Err(SystemdAttemptRegistryError::ReconciliationRequired);
        };
        let result = self
            .require_terminal_evidence(unit, root)
            .and_then(|()| self.remove_tree())
            .and_then(|()| self.verify_record())
            .and_then(|()| delete_record(&self.planned.directory, self.intent().unit_name()));
        state.failed |= result.is_err();
        drop(state);
        result.map(|()| CompletedAttemptCleanup {
            intent: self.intent().clone(),
        })
    }

    fn require_terminal_evidence(
        &self,
        unit: AttemptUnitTermination<'_>,
        root: Option<ReleasedAttemptRoot>,
    ) -> TerminalResult {
        let name = self.intent().unit_name();
        let unit_ended = match unit {
            AttemptUnitTermination::Unclaimed => self.execution.claim().is_ok(),
            AttemptUnitTermination::Stopped(observed) => {
                self.execution.close();
                // Teardown takes both observations' name from one bound cgroup.
                observed.unit_absence().unit_name() == name
            }
        };
        let activations = self.activations.load(Ordering::Acquire);
        let root_released = root.map_or(activations == 0, |released| {
            activations <= 1 && released.owner() == &self.execution
        });
        (unit_ended && root_released)
            .then_some(())
            .ok_or(SystemdAttemptRegistryError::CleanupEvidence)
    }
}

fn delete_record(directory: &RegistryDirectory, unit: &TransientServiceUnitName) -> TerminalResult {
    registry_io(|| {
        unlinkat(&directory.file, unit.attempt_component(), AtFlags::empty())
            .map_err(std::io::Error::from)
    })
    .and_then(|()| registry_io(|| directory.file.sync_all()))
    .map_err(Into::into)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
