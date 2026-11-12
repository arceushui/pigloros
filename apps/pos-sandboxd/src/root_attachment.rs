//! ADR-087 §2 steps 3 to 6 (#440): attach the quarantined SIM1 root at the
//! held attempt directory and read its kernel identity back.
//!
//! Before mountfsd is called, the prepared attempt directory is verified
//! again. The kernel command line must also veto systemd's userspace Verity
//! fallback (ADR-087 Part C.3, accepted revision 31; owner decision Q7.8). The
//! registry durably records the request's boot and time (owner decision D2),
//! and one bounded `MountImage` call then activates the admitted image. Its single
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
mod identity;
mod observe;
mod recovered;
mod release;
mod verify;

pub use identity::RootResourceIdentity;
pub use release::ReleasedAttemptRoot;

use std::{
    fs::File,
    future::Future,
    os::fd::{AsFd, BorrowedFd, OwnedFd},
};

use pos_reference::provider_admission::HeldImageAdmission;
use tokio::time::Instant;

use self::{
    observe::{BlockIdentity, HostKernel, Observations},
    verify::{Expected, VerifiedMountIdentity},
};
use crate::{
    ActivatedRootDirectory, ActivationImage, AdmittedAttempt, AdmittedEntry, CheckedRoot,
    ImageActivationError, ImageActivator, MountfsdImageActivator, PreparedAttemptDirectory,
    QuarantinedRootMount, StagingError,
};

/// The kernel operations of one attachment.
trait AttachmentKernel: Sync {
    /// Monotonic time for checks around synchronous kernel/ownership work.
    /// Production shares the Tokio clock used by the original timeout budget.
    fn now(&self) -> Instant {
        Instant::now()
    }

    /// Whether the kernel command line vetoes systemd's userspace Verity
    /// fallback.
    fn vetoes_userspace_verity(&self) -> bool;
    /// Attach the detached mount onto the held root directory.
    fn attach(&self, mount: BorrowedFd<'_>, root: &File) -> Result<(), ImageActivationError>;
    /// Make the attached mount private.
    fn make_private(&self, mount: BorrowedFd<'_>) -> Result<(), ImageActivationError>;
    /// Read the attached mount's kernel identity back.
    fn observe(
        &self,
        mount: BorrowedFd<'_>,
        attempt: &File,
        root: &File,
        executable: &str,
    ) -> Observations;
    /// Whether the bound loop device `loop_name` is backed by a file in the
    /// `images` directory, by the rules of the provider loop sweep. An
    /// unresolvable image directory or an unreadable or empty backing file is
    /// not a provider image.
    fn provider_image(&self, loop_name: &str, images: &std::path::Path) -> bool;
    /// Whether any mount has the mount `mount_id` as its parent; `None` when
    /// the mount table cannot be read completely.
    fn has_submounts(&self, mount_id: u64) -> Option<bool>;
    /// Detach an owned, attached mount.
    fn detach(&self, mount: BorrowedFd<'_>) -> Result<(), ImageActivationError>;
    /// Independently observe whether both original block generations ended.
    fn devices_absent(
        &self,
        devices: [BlockIdentity; 2],
    ) -> impl Future<Output = Result<bool, ImageActivationError>> + Send;
}

/// The admitted SIM1 root, attached at its attempt path and read back.
///
/// It holds the attached mount's descriptor. Dropping it leaves the mount
/// attached. The attempt lifecycle must stop the unit before explicitly calling
/// [`Self::detach`], which also waits for original loop/dm generation absence
/// within the caller's original cleanup deadline.
#[derive(Debug)]
pub struct VerifiedRootMount {
    mount: OwnedFd,
    identity: VerifiedMountIdentity,
    expected: Expected,
}

impl VerifiedRootMount {
    /// The verified attempt root, the only `RootDirectory` a unit may use.
    #[must_use]
    pub const fn root_directory(&self) -> &ActivatedRootDirectory {
        &self.expected.root_directory
    }

    /// The kernel mount ID read back for the attached root.
    #[must_use]
    pub const fn mount_id(&self) -> u64 {
        self.identity.mount.mount_id
    }

    /// The attached root mount, for rechecking its identity before launch.
    #[must_use]
    pub fn mount(&self) -> BorrowedFd<'_> {
        self.mount.as_fd()
    }

    /// Recheck, immediately before `StartTransientUnit`, that current
    /// authority and the attached mount are still the verified ones
    /// (ADR-087 §2 step 7).
    ///
    /// `entry` must hold the admission this root was activated from: the held
    /// image, partitions and executable it names must equal the ones this root
    /// was verified against. The installed authority is then re-read and
    /// compared with the provider control floor through `entry`. The mount,
    /// loop, dm-verity and executable readback is repeated and must name the
    /// same mount node, device-mapper UUID, loop name and boot-local block
    /// device generations retained at activation.
    /// Their exact private activation-intent extension is committed and read
    /// back under registry ownership before a launch token can be returned.
    /// An identical repeat verifies the original record without replacing it.
    /// Current authority is checked again after the filesystem work.
    /// The returned [`CheckedRoot`] is the only `RootDirectory` a launch input
    /// accepts.
    ///
    /// # Errors
    /// [`ImageActivationError::EvidenceMismatch`] for changed authority, a
    /// floor above the admission, any readback difference, or uncertain intent
    /// publication. Failed publication quarantines the registry.
    pub fn recheck(
        &self,
        directory: &PreparedAttemptDirectory,
        entry: &AdmittedEntry<'_>,
    ) -> Result<CheckedRoot, ImageActivationError> {
        self.recheck_with(&HostKernel::system(), directory, entry)
    }

    fn recheck_with(
        &self,
        kernel: &impl AttachmentKernel,
        directory: &PreparedAttemptDirectory,
        entry: &AdmittedEntry<'_>,
    ) -> Result<CheckedRoot, ImageActivationError> {
        let activated =
            Expected::for_admission(&entry.admission(), self.expected.root_directory.clone());
        AdmittedAttempt::from_entry(entry, directory)
            .map_err(|_| ImageActivationError::EvidenceMismatch)
            .and_then(|admitted| {
                recheck(kernel, self, directory, activated.as_ref(), || {
                    entry.recheck()
                })
                .map(|root| CheckedRoot::rechecked(root, admitted))
            })
    }

    fn verify_mount(
        &self,
        kernel: &impl AttachmentKernel,
        directory: &PreparedAttemptDirectory,
    ) -> Result<(), ImageActivationError> {
        let (attempt, held_root) = directory.held_directories();
        (self.expected.root_directory
            == ActivatedRootDirectory::for_attempt(
                directory.intent().unit_name().attempt_component(),
            ))
        .then_some(())
        .ok_or(ImageActivationError::EvidenceMismatch)
        .and_then(|()| {
            self.expected.verify(&kernel.observe(
                self.mount(),
                attempt,
                held_root,
                &self.expected.executable_path,
            ))
        })
        .and_then(|identity| {
            (identity == self.identity)
                .then_some(())
                .ok_or(ImageActivationError::EvidenceMismatch)
        })
    }
}

/// Whether `candidate`, derived from an entry's admission, is exactly what a
/// root was verified against.
fn binds(expected: &Expected, candidate: Option<&Expected>) -> bool {
    candidate == Some(expected)
}

fn recheck<K: AttachmentKernel>(
    kernel: &K,
    root: &VerifiedRootMount,
    directory: &PreparedAttemptDirectory,
    activated: Option<&Expected>,
    mut authority: impl FnMut() -> Result<(), StagingError>,
) -> Result<ActivatedRootDirectory, ImageActivationError> {
    binds(&root.expected, activated)
        .then_some(())
        .ok_or(ImageActivationError::EvidenceMismatch)
        .and_then(|()| authority().map_err(|_| ImageActivationError::EvidenceMismatch))
        .and_then(|()| {
            directory
                .record_root(&root.resource_identity(), || {
                    root.verify_mount(kernel, directory)
                        .map_err(|_| crate::SystemdAttemptRegistryError::InvalidIntent)
                })
                .map_err(|_| ImageActivationError::EvidenceMismatch)
        })
        .and_then(|()| authority().map_err(|_| ImageActivationError::EvidenceMismatch))
        .map(|()| root.expected.root_directory.clone())
}

impl RootResourceIdentity {
    /// Whether the recorded mapper and loop generations of a previous
    /// runtime's root are both absent now, by fresh sysfs observation.
    ///
    /// Restart reconciliation uses this only for a root whose directory is
    /// already unmounted. No block-device descriptor is opened.
    ///
    /// # Errors
    /// [`ImageActivationError::ResourceAbsenceUnverified`] for a contradictory
    /// generation stamp, an unreadable device index or a zero sequence.
    pub(crate) async fn recorded_generations_absent(
        generations: [((u32, u32), u64); 2],
    ) -> Result<bool, ImageActivationError> {
        generations_absent(&HostKernel::system(), generations).await
    }

    /// Whether no loop device is backed by a provider image now, by a fresh
    /// sysfs sweep of every bound loop device's backing file.
    ///
    /// Restart reconciliation uses this after every attempt unit was observed
    /// absent, so a remaining loop over an image belongs to no live attempt,
    /// including one whose activation crashed before its root was recorded.
    /// The sweep runs on a blocking thread so the caller's deadline bounds it.
    /// No block-device descriptor is opened.
    ///
    /// # Errors
    /// [`ImageActivationError::ResourceAbsenceUnverified`] when the image
    /// directory cannot be resolved, or the block class or a bound loop
    /// device's backing file cannot be read.
    pub(crate) async fn provider_loops_absent() -> Result<bool, ImageActivationError> {
        let images = images_directory();
        let swept = tokio::task::spawn_blocking(move || {
            HostKernel::system().provider_loops_absent(&images)
        })
        .await;
        swept
            .ok()
            .flatten()
            .ok_or(ImageActivationError::ResourceAbsenceUnverified)
    }
}

/// The fixed directory of installed provider images.
fn images_directory() -> std::path::PathBuf {
    std::path::Path::new(pos_reference::selector::installation::SANDBOX_ARTIFACT_ROOT)
        .join("images")
}

async fn generations_absent(
    kernel: &HostKernel,
    generations: [((u32, u32), u64); 2],
) -> Result<bool, ImageActivationError> {
    let [mapper, loop_device] = generations.map(|(device, sequence)| {
        std::num::NonZeroU64::new(sequence).map(|diskseq| BlockIdentity { device, diskseq })
    });
    match mapper.zip(loop_device) {
        Some(devices) => kernel.devices_absent(devices.into()).await,
        None => Err(ImageActivationError::ResourceAbsenceUnverified),
    }
}

/// Activate, attach and verify the admitted SIM1 root of one attempt.
///
/// # Errors
/// Returns [`ImageActivationError::AttachFailure`] when the prepared directory
/// changed, records another image than the admission holds, or attachment
/// fails, and [`ImageActivationError::HostFeatureUnavailable`]
/// when the kernel command line does not veto userspace Verity. Otherwise it
/// returns the `MountImage` transport's error, or
/// [`ImageActivationError::EvidenceMismatch`] for any readback or re-admission
/// difference. [`ImageActivationError::TeardownFailure`] means a rejected
/// mount could not be detached.
///
/// The caller's Tokio runtime must have its time driver enabled, for the
/// separate 60 s bounds on the mountfsd connection and on the `MountImage` call.
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
        })
        .and_then(|prepared| recorded_image_is_held(directory, &prepared.0).map(|()| prepared));
    match prepared {
        Ok((expected, image)) => {
            // The connection gets its own 60 s bound, like the call (owner decision Q7.4).
            let connected = tokio::time::timeout(MountfsdImageActivator::DEADLINE, connect())
                .await
                .unwrap_or(Err(ImageActivationError::Transport));
            let mounted = match connected {
                Ok(activator) => send_recorded(directory, activator, image).await,
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

/// The directory's PAI2 record must name exactly the admission's held image.
fn recorded_image_is_held(
    directory: &PreparedAttemptDirectory,
    expected: &Expected,
) -> Result<(), ImageActivationError> {
    (expected.held == directory.image())
        .then_some(())
        .ok_or(ImageActivationError::AttachFailure)
}

/// Durably record the request's boot and time, so a restart can wait it out
/// (owner decision D2), and only then send it.
async fn send_recorded<A: ImageActivator>(
    directory: &PreparedAttemptDirectory,
    activator: A,
    image: ActivationImage,
) -> Result<QuarantinedRootMount, ImageActivationError> {
    match directory.record_activation_request() {
        Ok(()) => {
            // Only a request that reaches mountfsd can leave loop/dm
            // resources, so only it binds intent to a released root.
            directory.begin_activation();
            activator.mount_image(image).await
        }
        Err(_) => Err(ImageActivationError::AttachFailure),
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
            .and_then(|()| {
                expected.verify(&kernel.observe(
                    mount.as_fd(),
                    attempt,
                    root,
                    &expected.executable_path,
                ))
            })
            .and_then(|identity| recheck().map(|()| identity))
            .or_else(|error| kernel.detach(mount.as_fd()).and(Err(error)))
    });
    verified.map(|identity| VerifiedRootMount {
        mount,
        identity,
        expected: expected.clone(),
    })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
#[cfg(test)]
pub use tests::{
    attached_fixture_root, fake_root_release, release_fake_root, FakeRecoveredRoots,
    FakeRootRelease,
};
#[cfg(test)]
pub use tests::{recorded_identity, released_root};
