//! Bounded owned-root detachment and independent original-device absence.

use std::{future::Future, time::Duration};

use tokio::time::{sleep, timeout_at, Instant};

use super::{AttachmentKernel, HostKernel, ImageActivationError, VerifiedRootMount};
use crate::PreparedAttemptDirectory;

const DEVICE_POLL: Duration = Duration::from_millis(10);

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
    /// It leaves intent and directories unchanged and grants no lifecycle,
    /// fencing, intent-deletion, terminal-evidence or admission authority.
    /// Subsequent directory removal remains with its existing owner.
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
    ) -> impl Future<Output = Result<(), ImageActivationError>> + '_ {
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
    ) -> Result<(), ImageActivationError> {
        let Self {
            root,
            mut guard,
            deadline,
        } = self;
        let devices = root.identity.devices();
        before(deadline)?;
        guard
            .directory
            .with_verified_parent(ImageActivationError::EvidenceMismatch, || {
                before(deadline)?;
                root.verify_mount(kernel, guard.directory)?;
                before(deadline)?;
                kernel.detach(root.mount())?;
                before(deadline)
            })?;
        drop(root);
        loop {
            before(deadline)?;
            let observed = timeout_at(deadline, kernel.devices_absent(devices))
                .await
                .map_err(|_| ImageActivationError::ResourceAbsenceUnverified)?;
            // Synchronous sysfs work must finish strictly before the deadline,
            // even when it did not yield to the async timeout.
            before(deadline)?;
            if observed? {
                guard
                    .directory
                    .with_verified_parent(ImageActivationError::EvidenceMismatch, || Ok(()))?;
                before(deadline)?;
                guard.complete = true;
                return Ok(());
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

fn before(deadline: Instant) -> Result<(), ImageActivationError> {
    (Instant::now() < deadline)
        .then_some(())
        .ok_or(ImageActivationError::ResourceAbsenceUnverified)
}
