//! The live owner's terminal cleanup predicate, deleting durable intent last.

use std::sync::atomic::Ordering;

use super::super::delete_record;
use super::{PlannedAttemptIntent, PreparedAttemptDirectory, SystemdAttemptRegistryError};
use crate::{ReleasedAttemptRoot, SystemdAttemptUnitTeardownObservation};

type TerminalResult<T = ()> = Result<T, SystemdAttemptRegistryError>;

/// How the live owner knows that no attempt process can hold its resources.
#[derive(Clone, Copy, Debug)]
pub enum AttemptUnitTermination<'a> {
    /// No unit start was ever requested for this attempt, whether or not an
    /// execution claimed it. Cleanup fences every later start atomically.
    Unsubmitted,
    /// The exact unit was stopped and observed unloaded, then its cgroup empty.
    ///
    /// The cgroup must be the one the claimed execution bound. Cleanup closes
    /// any unclaimed start permission.
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
    /// activated on this tree. A tree on which no activation reached mountfsd
    /// needs no root evidence; a tree with more than one such activation, or
    /// one activation without its released root, is refused. Under registry
    /// ownership, this then verifies the exact record and unmounted tree,
    /// removes the root and attempt directories while synchronizing each held
    /// parent, reads the exact record back, unlinks it and synchronizes the
    /// registry parent.
    ///
    /// The lifecycle controller must retain exclusive attempt ownership and
    /// obtain both observations before calling. A quarantined owner may finish
    /// a fully evidenced attempt, but this never clears quarantine or reopens
    /// admission.
    ///
    /// # Errors
    /// [`SystemdAttemptRegistryError::CleanupEvidence`] rejects a requested
    /// unit start without stop evidence, evidence for another unit, cgroup or
    /// tree, and missing or ambiguous root evidence before anything is
    /// removed. Changed records or trees, poisoned ownership and every
    /// removal, unlink or fsync failure are also refused. Every failure closes
    /// new commits; directories or the record may already be gone, so restart
    /// reconciliation must inspect the surviving state rather than treat an
    /// error as no change.
    ///
    /// # Exclusion from root activation
    /// Cleanup takes the directory by value and every root activation borrows
    /// it, so the activation count read here is final. An activation still in
    /// flight cannot be overtaken by cleanup:
    ///
    /// ```compile_fail,E0505
    /// use pos_reference::provider_admission::HeldImageAdmission;
    /// use pos_sandboxd::{activate_admitted_root, AttemptUnitTermination, PreparedAttemptDirectory};
    ///
    /// async fn overtaken(
    ///     admission: &HeldImageAdmission<'_>,
    ///     directory: PreparedAttemptDirectory,
    ///     unit: AttemptUnitTermination<'_>,
    /// ) {
    ///     let activation = activate_admitted_root(admission, &directory);
    ///     let _cleaned = directory.finish_terminal_cleanup(unit, None);
    ///     let _root = activation.await;
    /// }
    /// ```
    ///
    /// and no activation can begin after cleanup:
    ///
    /// ```compile_fail,E0382
    /// use pos_reference::provider_admission::HeldImageAdmission;
    /// use pos_sandboxd::{activate_admitted_root, AttemptUnitTermination, PreparedAttemptDirectory};
    ///
    /// async fn after(
    ///     admission: &HeldImageAdmission<'_>,
    ///     directory: PreparedAttemptDirectory,
    ///     unit: AttemptUnitTermination<'_>,
    /// ) {
    ///     let _cleaned = directory.finish_terminal_cleanup(unit, None);
    ///     let _root = activate_admitted_root(admission, &directory).await;
    /// }
    /// ```
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
            .and_then(|()| {
                delete_record(
                    &self.planned.directory,
                    self.intent().unit_name().attempt_component(),
                )
            });
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
            AttemptUnitTermination::Unsubmitted => self.execution.fence_unsubmitted(),
            AttemptUnitTermination::Stopped(observed) => {
                self.execution.close();
                // Teardown takes both observations' name from one bound
                // cgroup; each must name this attempt's exact unit, and the
                // cgroup must be the one this attempt's execution bound.
                (
                    observed.unit_absence().unit_name(),
                    observed.cgroup_empty().unit_name(),
                ) == (name, name)
                    && self
                        .execution
                        .bound_cgroup_is(observed.cgroup_empty().cgroup_identity())
            }
        };
        let activations = self.activations.load(Ordering::Acquire);
        // Released-root evidence exists only after an activation reached
        // mountfsd, so it is accepted for exactly one activation.
        let root_released = root.map_or(activations == 0, |released| {
            activations == 1 && released.owner() == &self.execution
        });
        (unit_ended && root_released)
            .then_some(())
            .ok_or(SystemdAttemptRegistryError::CleanupEvidence)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
