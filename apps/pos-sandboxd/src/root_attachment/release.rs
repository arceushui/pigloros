//! Bounded owned-root detachment and independent original-device absence.

use std::{future::Future, time::Duration};

use tokio::time::{sleep, timeout_at, Instant};

use super::{AttachmentKernel, HostKernel, ImageActivationError, VerifiedRootMount};
use crate::{ExecutionOwnership, PreparedAttemptDirectory};

const DEVICE_POLL: Duration = Duration::from_millis(10);

/// Evidence that one tree's activated root was detached and its original
/// loop/dm generations were observed absent within the cleanup deadline.
///
/// Only [`VerifiedRootMount::detach`] creates it, bound to the exact prepared
/// directory it verified. It is consumed by
/// [`PreparedAttemptDirectory::finish_terminal_cleanup`] and grants nothing
/// else: no unit absence, directory removal or admission authority.
#[derive(Debug, Eq, PartialEq)]
pub struct ReleasedAttemptRoot {
    owner: ExecutionOwnership,
}

impl ReleasedAttemptRoot {
    /// The prepared tree whose root this evidence released.
    pub(crate) const fn owner(&self) -> &ExecutionOwnership {
        &self.owner
    }
}

impl VerifiedRootMount {
    /// Detach this owned root and prove its original loop/dm generations ended.
    ///
    /// The lifecycle controller must exclusively own the private attempt tree,
    /// stop/remove its unit, prove process emptiness, and close its other
    /// image/mount references first. The supplied absolute deadline must be
    /// the original cleanup deadline, including all preceding shutdown work.
    /// This method never renews it or requires renewed execution admission.
    ///
    /// Durable intent, private parents and fresh mount/image readback must
    /// match the mount node, mapper UUID, loop name and boot-local device
    /// generations retained at activation. After descriptor-bound lazy detach,
    /// the owned mount descriptor closes before fresh sysfs absence checks.
    /// Other references can delay removal; acknowledgement alone cannot pass.
    /// No block-device descriptors are opened while waiting.
    ///
    /// Success proves only point-in-time original device absence in this boot.
    /// It leaves intent and directories unchanged. The returned evidence lets
    /// only this directory's terminal cleanup delete its intent last; it grants
    /// no fencing, terminal-report or admission authority.
    ///
    /// The caller's Tokio runtime must have its time driver enabled. The
    /// deadline gates acceptance of evidence, not a hard wall-clock return:
    /// synchronous kernel/filesystem work and ownership-lock acquisition cannot
    /// be preempted by the timer. Their results are checked on completion, and
    /// work completing at or after the deadline cannot report success.
    ///
    /// # Errors
    /// Changed ownership or mount evidence returns
    /// [`ImageActivationError::EvidenceMismatch`]; a failed detach command
    /// returns [`ImageActivationError::TeardownFailure`]. Unverified device
    /// absence or an exhausted deadline returns
    /// [`ImageActivationError::ResourceAbsenceUnverified`]. Every failure or
    /// cancellation closes new registry commits, even if the future was never
    /// polled. Success never clears existing quarantine. The mount FD closes
    /// on every result or cancellation; retained intent governs recovery.
    pub fn detach(
        self,
        directory: &PreparedAttemptDirectory,
        deadline: Instant,
    ) -> impl Future<Output = Result<ReleasedAttemptRoot, ImageActivationError>> + Send + '_ {
        let release = Release::new(self, directory, deadline);
        async move { release.finish(&HostKernel::system()).await }
    }
}

/// Created before constructing the future, so even unpolled cancellation
/// preserves quarantine. The underlying directory descriptors do not pin the
/// activated mount; the owned mount descriptor is dropped before polling.
pub(super) struct Release<'a> {
    root: VerifiedRootMount,
    guard: CleanupGuard<'a>,
    deadline: Instant,
}

impl<'a> Release<'a> {
    pub(super) const fn new(
        root: VerifiedRootMount,
        directory: &'a PreparedAttemptDirectory,
        deadline: Instant,
    ) -> Self {
        Self {
            root,
            guard: CleanupGuard {
                directory,
                complete: false,
            },
            deadline,
        }
    }

    pub(super) async fn finish(
        self,
        kernel: &impl AttachmentKernel,
    ) -> Result<ReleasedAttemptRoot, ImageActivationError> {
        let Self {
            root,
            mut guard,
            deadline,
        } = self;
        let devices = root.identity.devices();
        before(kernel, deadline)?;
        guard
            .directory
            .with_verified_parent(ImageActivationError::EvidenceMismatch, || {
                before(kernel, deadline)?;
                root.verify_mount(kernel, guard.directory)?;
                before(kernel, deadline)?;
                kernel.detach(root.mount())?;
                before(kernel, deadline)
            })?;
        drop(root);
        loop {
            before(kernel, deadline)?;
            let observed = timeout_at(deadline, kernel.devices_absent(devices))
                .await
                .map_err(|_| ImageActivationError::ResourceAbsenceUnverified)?;
            // Synchronous sysfs work must finish strictly before the deadline,
            // even when it did not yield to the async timeout.
            before(kernel, deadline)?;
            if observed? {
                guard
                    .directory
                    .with_verified_parent(ImageActivationError::EvidenceMismatch, || Ok(()))?;
                before(kernel, deadline)?;
                guard.complete = true;
                return Ok(ReleasedAttemptRoot {
                    owner: guard.directory.execution_ownership(),
                });
            }
            let _wake = timeout_at(deadline, sleep(DEVICE_POLL)).await;
        }
    }
}

struct CleanupGuard<'a> {
    directory: &'a PreparedAttemptDirectory,
    complete: bool,
}

impl Drop for CleanupGuard<'_> {
    fn drop(&mut self) {
        if !self.complete {
            self.directory.quarantine();
        }
    }
}

fn before(kernel: &impl AttachmentKernel, deadline: Instant) -> Result<(), ImageActivationError> {
    (kernel.now() < deadline)
        .then_some(())
        .ok_or(ImageActivationError::ResourceAbsenceUnverified)
}
