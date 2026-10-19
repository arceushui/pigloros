//! ADR-087 §2 steps 3 to 6 (#440): attach the quarantined SIM1 root at the
//! held attempt directory and read its kernel identity back.
//!
//! Before mountfsd is called, the prepared attempt directory is verified
//! again. The kernel command line must also veto systemd's userspace Verity
//! fallback (owner decision Q7.8, ADR-087 amendment, Under Review). One
//! bounded `MountImage` call then activates the admitted image. Its single
//! sealed root mount descriptor is attached by descriptor with `move_mount`
//! onto the held root directory descriptor, so no path is resolved. It is
//! then made private, and detached on rejection, through that descriptor's
//! `/proc/self/fd` link.
//!
//! The readback then requires, by descriptor:
//! - the attempt root path resolves to that mount;
//! - the mount is the private, read-only EROFS root on the held parent;
//! - it sits on a read-only dm-verity device over exactly the admitted root
//!   and root-verity partitions of one loop device;
//! - that loop device is backed read-only, from byte 0, by the held image.
//!
//! The held image is then admitted again. Any failure after attachment
//! detaches the mount before returning, and success grants no admission
//! authority. The live dm-verity table (root hash, salt and
//! `root_hash_sig_key_desc`) is not read at run time; #444 records it (owner
//! decision Q7.8).
//!
//! Kernel operations sit behind the crate-private [`AttachmentKernel`] port.
//! Production uses only the fixed `/proc` and `/sys` host kernel.

mod cmdline;
mod observe;
mod verify;

use std::{
    fs::File,
    future::Future,
    os::fd::{AsFd, BorrowedFd, OwnedFd},
};

use pos_reference::provider_admission::HeldImageAdmission;

use self::{
    observe::{HostKernel, Observations},
    verify::Expected,
};
use crate::{
    ActivatedRootDirectory, ActivationImage, ImageActivationError, ImageActivator,
    MountfsdImageActivator, PreparedAttemptDirectory, QuarantinedRootMount,
};

/// The kernel operations of one attachment.
trait AttachmentKernel {
    /// Whether the kernel command line vetoes systemd's userspace Verity
    /// fallback.
    fn vetoes_userspace_verity(&self) -> bool;
    /// Attach the detached mount onto the held root directory.
    fn attach(&self, mount: BorrowedFd<'_>, root: &File) -> Result<(), ImageActivationError>;
    /// Make the attached mount private.
    fn make_private(&self, mount: BorrowedFd<'_>) -> Result<(), ImageActivationError>;
    /// Read the attached mount's kernel identity back.
    fn observe(&self, mount: BorrowedFd<'_>, attempt: &File, root: &File) -> Observations;
    /// Detach a rejected, attached mount.
    fn detach(&self, mount: BorrowedFd<'_>) -> Result<(), ImageActivationError>;
}

/// The admitted SIM1 root, attached at its attempt path and read back.
///
/// It holds the attached mount's descriptor. Dropping it leaves the mount
/// attached; stopping the unit, detaching and proving loop and dm-verity
/// removal belong to the attempt lifecycle.
#[derive(Debug)]
pub struct VerifiedRootMount {
    mount: OwnedFd,
    mount_id: u64,
    root_directory: ActivatedRootDirectory,
}

impl VerifiedRootMount {
    /// The verified attempt root, the only `RootDirectory` a unit may use.
    #[must_use]
    pub const fn root_directory(&self) -> &ActivatedRootDirectory {
        &self.root_directory
    }

    /// The kernel mount ID read back for the attached root.
    #[must_use]
    pub const fn mount_id(&self) -> u64 {
        self.mount_id
    }

    /// The attached root mount, for rechecking its identity before launch.
    #[must_use]
    pub fn mount(&self) -> BorrowedFd<'_> {
        self.mount.as_fd()
    }
}

/// Activate, attach and verify the admitted SIM1 root of one attempt.
///
/// # Errors
/// Returns [`ImageActivationError::AttachFailure`] when the prepared directory
/// changed or attachment fails, and [`ImageActivationError::HostFeatureUnavailable`]
/// when the kernel command line does not veto userspace Verity. Otherwise it
/// returns the `MountImage` transport's error, or
/// [`ImageActivationError::EvidenceMismatch`] for any readback or re-admission
/// difference. [`ImageActivationError::TeardownFailure`] means a rejected
/// mount could not be detached.
///
/// The caller's Tokio runtime must have its time driver enabled, for the
/// 60 s bound on the mountfsd connection and call.
pub async fn activate_admitted_root(
    admission: &HeldImageAdmission<'_>,
    directory: &PreparedAttemptDirectory,
) -> Result<VerifiedRootMount, ImageActivationError> {
    activate(
        &HostKernel::system(),
        admission,
        directory,
        MountfsdImageActivator::connect,
    )
    .await
}

async fn activate<K, C, F, A>(
    kernel: &K,
    admission: &HeldImageAdmission<'_>,
    directory: &PreparedAttemptDirectory,
    connect: C,
) -> Result<VerifiedRootMount, ImageActivationError>
where
    K: AttachmentKernel + Sync,
    C: FnOnce() -> F + Send,
    F: Future<Output = Result<A, ImageActivationError>> + Send,
    A: ImageActivator + Send,
{
    let prepared = directory
        .verify_directory()
        .map_err(|_| ImageActivationError::AttachFailure)
        .and_then(|()| {
            kernel
                .vetoes_userspace_verity()
                .then_some(())
                .ok_or(ImageActivationError::HostFeatureUnavailable)
        })
        .and_then(|()| {
            let root_directory = ActivatedRootDirectory::for_attempt(
                directory.intent().unit_name().attempt_component(),
            );
            Expected::for_admission(admission, root_directory)
                .zip(ActivationImage::from_admission(admission).ok())
                .ok_or(ImageActivationError::Transport)
        });
    match prepared {
        Ok((expected, image)) => {
            // The connection shares the MountImage bound (owner decision Q7.4).
            let connected = tokio::time::timeout(MountfsdImageActivator::DEADLINE, connect())
                .await
                .unwrap_or(Err(ImageActivationError::Transport));
            let mounted = match connected {
                Ok(activator) => activator.mount_image(image).await,
                Err(error) => Err(error),
            };
            mounted.and_then(|mount| {
                attach_and_verify(kernel, directory, &expected, mount, || {
                    admission
                        .snapshot()
                        .admit_held_image()
                        .map(|_| ())
                        .map_err(|_| ImageActivationError::EvidenceMismatch)
                })
            })
        }
        Err(error) => Err(error),
    }
}

/// Attach the sealed root mount, verify it and re-admit, detaching on any
/// failure after attachment.
fn attach_and_verify<K: AttachmentKernel>(
    kernel: &K,
    directory: &PreparedAttemptDirectory,
    expected: &Expected,
    mount: QuarantinedRootMount,
    recheck: impl FnOnce() -> Result<(), ImageActivationError>,
) -> Result<VerifiedRootMount, ImageActivationError> {
    let mount = mount.into_descriptor();
    let (attempt, root) = directory.held_directories();
    let verified = kernel.attach(mount.as_fd(), root).and_then(|()| {
        kernel
            .make_private(mount.as_fd())
            .and_then(|()| expected.verify(&kernel.observe(mount.as_fd(), attempt, root)))
            .and_then(|mount_id| recheck().map(|()| mount_id))
            .or_else(|error| kernel.detach(mount.as_fd()).and(Err(error)))
    });
    verified.map(|mount_id| VerifiedRootMount {
        mount,
        mount_id,
        root_directory: expected.root_directory.clone(),
    })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
