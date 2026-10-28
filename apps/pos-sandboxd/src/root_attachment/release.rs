//! Explicit owned-root detachment, separate from complete resource absence.

use super::{AttachmentKernel, HostKernel, ImageActivationError, VerifiedRootMount};
use crate::PreparedAttemptDirectory;

impl VerifiedRootMount {
    /// Recheck and detach this attempt's owned root, closing its mount descriptor.
    ///
    /// The lifecycle controller must exclusively own the private attempt tree
    /// and have stopped/removed its unit and proved process emptiness first.
    /// The durable intent, private parent identities and fresh mount/image
    /// readback must still match. Cleanup uses the retained identity, without
    /// requiring renewed execution admission.
    ///
    /// Success acknowledges descriptor-bound lazy detachment only. Other held
    /// references can delay actual unmount and loop/dm removal. The controller
    /// must close remaining image/directory references and prove exact resource
    /// absence before deleting intent or reopening admission. This operation
    /// leaves the durable intent and directories unchanged.
    ///
    /// # Errors
    /// Returns [`ImageActivationError::EvidenceMismatch`] before detachment for
    /// unsafe/changed ownership, poisoned ownership, or different kernel evidence;
    /// [`ImageActivationError::TeardownFailure`] if the detach command fails.
    /// Either failure closes new registry commits; prior quarantine is retained.
    /// The mount descriptor is closed on either result, so a surviving attachment
    /// must be recovered through the retained intent.
    pub fn detach(self, directory: &PreparedAttemptDirectory) -> Result<(), ImageActivationError> {
        self.detach_with(&HostKernel::system(), directory)
    }

    fn detach_with(
        self,
        kernel: &impl AttachmentKernel,
        directory: &PreparedAttemptDirectory,
    ) -> Result<(), ImageActivationError> {
        directory.with_verified_parent(ImageActivationError::EvidenceMismatch, || {
            self.verify_mount(kernel, directory)
                .and_then(|()| kernel.detach(self.mount()))
        })
    }
}
