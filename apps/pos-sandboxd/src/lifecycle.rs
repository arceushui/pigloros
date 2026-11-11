//! The live owner's bounded terminal cleanup of one attempt (ADR-087 §3).
//!
//! [`finish_attempt`] composes, under one cleanup deadline, the steps that
//! follow an execution's success or failure:
//!
//! 1. the unit is stopped through its retained cgroup, with bounded grace and
//!    escalation, and observed unloaded with that very cgroup empty;
//! 2. only then is the attached root detached and its loop/dm generations
//!    observed absent;
//! 3. the directories are removed and the durable intent is deleted last.
//!
//! Stop evidence is tied to the claimed execution: only the cgroup that this
//! attempt's own execution bound is stopped or accepted. Any refusal, failure
//! or deadline expiry quarantines the registry and retains the intent; so does
//! dropping the cleanup future before it finishes. An execution that was
//! cancelled after requesting its unit start returns no cgroup, so it cannot be
//! proved clean here and is left to restart reconciliation.

use std::future::Future;

use tokio::time::Instant;

use crate::{
    AttemptShutdownDeadlines, AttemptShutdownError, AttemptUnitTermination, BoundAttemptCgroup,
    CompletedAttemptCleanup, ImageActivationError, PreparedAttemptDirectory, ReleasedAttemptRoot,
    SystemdAttemptRegistryError, SystemdAttemptUnitTeardownError,
    SystemdAttemptUnitTeardownObservation, SystemdTransientUnitTransport, UnitCgroup,
    VerifiedRootMount,
};

/// One absolute cleanup deadline, divided into strictly ordered phases.
///
/// The trusted lifecycle controller derives these when an execution returns,
/// whether it succeeded or failed. Process shutdown ends first, the unit must
/// then be observed unloaded, and the root must be released by the final
/// deadline. No default grace period is chosen here.
#[derive(Clone, Copy, Debug)]
pub struct AttemptCleanupDeadlines {
    shutdown: AttemptShutdownDeadlines,
    unit_absent: Instant,
    released: Instant,
}

impl AttemptCleanupDeadlines {
    /// Bound process shutdown, unit absence and root release in that order.
    ///
    /// # Errors
    /// Rejects phases that are not strictly increasing.
    pub fn new(
        shutdown: AttemptShutdownDeadlines,
        unit_absent: Instant,
        released: Instant,
    ) -> Result<Self, AttemptShutdownError> {
        if shutdown.overall() >= unit_absent || unit_absent >= released {
            return Err(AttemptShutdownError::InvalidDeadlines);
        }
        Ok(Self {
            shutdown,
            unit_absent,
            released,
        })
    }
}

/// Why an attempt's terminal cleanup did not complete.
///
/// Every variant leaves the durable intent in place and new registry commits
/// closed; restart reconciliation must inspect the surviving state.
#[derive(Debug, thiserror::Error)]
pub enum AttemptCleanupError {
    /// The unit could not be stopped and observed absent in time.
    #[error(transparent)]
    Unit(#[from] SystemdAttemptUnitTeardownError),
    /// The attached root could not be detached and observed released in time.
    #[error("the attempt root was not released")]
    Root(#[source] ImageActivationError),
    /// The evidence did not match this attempt, or the directories and intent
    /// could not be removed.
    #[error(transparent)]
    Registry(#[from] SystemdAttemptRegistryError),
}

/// Finish one attempt's terminal cleanup within `deadlines`.
///
/// `cgroup` is the cgroup retained from the execution's success or failure,
/// if any, and `root` the attempt's attached root, if one was verified. The
/// controller must still exclusively own the attempt, and must have taken any
/// terminal unit or cgroup state it needs: stopping unloads the unit.
///
/// Without a cgroup, the attempt is fenced so that no unit start can be
/// requested later, and cleanup proceeds only if none was ever requested.
///
/// # Errors
/// [`AttemptCleanupError::Registry`] with
/// [`SystemdAttemptRegistryError::CleanupEvidence`] refuses a cgroup that this
/// attempt's execution did not bind, and a missing cgroup after a unit start
/// was requested, before anything is stopped or detached. Unit, root and
/// registry failures are returned as they occur. Every failure quarantines.
pub async fn finish_attempt(
    transport: &SystemdTransientUnitTransport,
    directory: PreparedAttemptDirectory,
    cgroup: Option<BoundAttemptCgroup>,
    root: Option<VerifiedRootMount>,
    deadlines: AttemptCleanupDeadlines,
) -> Result<CompletedAttemptCleanup, AttemptCleanupError> {
    finish_with(transport, directory, cgroup, root, deadlines).await
}

/// The root step, behind a port so that it can be faked without a kernel.
trait RootRelease: Send {
    /// Detach the root and observe its original loop/dm generations absent.
    fn release(
        self,
        directory: &PreparedAttemptDirectory,
        deadline: Instant,
    ) -> impl Future<Output = Result<ReleasedAttemptRoot, ImageActivationError>> + Send + '_;
}

impl RootRelease for VerifiedRootMount {
    fn release(
        self,
        directory: &PreparedAttemptDirectory,
        deadline: Instant,
    ) -> impl Future<Output = Result<ReleasedAttemptRoot, ImageActivationError>> + Send + '_ {
        self.detach(directory, deadline)
    }
}

/// Quarantines the attempt unless its unit and root steps both succeeded,
/// including when the cleanup future is dropped part-way.
struct Unfinished<'a> {
    directory: &'a PreparedAttemptDirectory,
    finished: bool,
}

impl Drop for Unfinished<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.directory.quarantine();
        }
    }
}

type Evidence = (
    Option<SystemdAttemptUnitTeardownObservation>,
    Option<ReleasedAttemptRoot>,
);

async fn finish_with<R: RootRelease>(
    transport: &SystemdTransientUnitTransport,
    directory: PreparedAttemptDirectory,
    cgroup: Option<BoundAttemptCgroup>,
    root: Option<R>,
    deadlines: AttemptCleanupDeadlines,
) -> Result<CompletedAttemptCleanup, AttemptCleanupError> {
    let evidence = gather(transport, &directory, cgroup, root, deadlines).await;
    evidence.and_then(|(stopped, released)| {
        let unit = stopped.as_ref().map_or(
            AttemptUnitTermination::Unsubmitted,
            AttemptUnitTermination::Stopped,
        );
        directory
            .finish_terminal_cleanup(unit, released)
            .map_err(AttemptCleanupError::from)
    })
}

/// Stop the unit first, then release the root, quarantining on any failure.
async fn gather<R: RootRelease>(
    transport: &SystemdTransientUnitTransport,
    directory: &PreparedAttemptDirectory,
    cgroup: Option<BoundAttemptCgroup>,
    root: Option<R>,
    deadlines: AttemptCleanupDeadlines,
) -> Result<Evidence, AttemptCleanupError> {
    let mut unfinished = Unfinished {
        directory,
        finished: false,
    };
    let stopped = stop_unit(transport, directory, cgroup, deadlines).await;
    let evidence = match stopped {
        Ok(stopped) => release_root(directory, root, deadlines.released)
            .await
            .map(|released| (stopped, released)),
        Err(error) => Err(error),
    };
    unfinished.finished = evidence.is_ok();
    evidence
}

async fn stop_unit(
    transport: &SystemdTransientUnitTransport,
    directory: &PreparedAttemptDirectory,
    cgroup: Option<BoundAttemptCgroup>,
    deadlines: AttemptCleanupDeadlines,
) -> Result<Option<SystemdAttemptUnitTeardownObservation>, AttemptCleanupError> {
    let refused = AttemptCleanupError::Registry(SystemdAttemptRegistryError::CleanupEvidence);
    let Some(mut cgroup) = cgroup else {
        return directory.fence_unsubmitted().then_some(None).ok_or(refused);
    };
    // Never stop a unit through a cgroup this execution did not bind.
    if !directory.bound_cgroup_is(cgroup.identity()) {
        return Err(refused);
    }
    let stopped = transport
        .stop_attempt_unit(&mut cgroup, deadlines.shutdown, deadlines.unit_absent)
        .await
        .map(Some)
        .map_err(AttemptCleanupError::from);
    stopped
}

async fn release_root<R: RootRelease>(
    directory: &PreparedAttemptDirectory,
    root: Option<R>,
    deadline: Instant,
) -> Result<Option<ReleasedAttemptRoot>, AttemptCleanupError> {
    let Some(root) = root else {
        return Ok(None);
    };
    let released = root
        .release(directory, deadline)
        .await
        .map(Some)
        .map_err(AttemptCleanupError::Root);
    released
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
