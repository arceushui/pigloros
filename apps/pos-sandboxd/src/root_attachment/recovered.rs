//! Restart detachment of a previous runtime's still-mounted attempt root
//! (ADR-087 §3).
//!
//! Restart reconciliation calls this only after every attempt unit was
//! stopped and observed absent. The root entry is held through the recorded
//! attempt directory, and a mount on it is read back by descriptor. It is
//! detached only when it is exactly a provider root: the private, read-only
//! EROFS mount at this attempt's fixed root path, on a read-only dm-verity
//! device over two partitions of one read-only, autoclear loop device that is
//! backed by a provider image, by the canonical and device/inode rules of the
//! provider loop sweep. A PAI3 record must also match every recorded mount,
//! mapper, loop and image identity. Anything else is refused and left
//! mounted. After the descriptor-bound lazy detach, the root descriptor closes
//! and the mapper and loop generations read back are awaited absent.

use std::{os::fd::AsFd, path::Path};

use tokio::time::{sleep, timeout_at, Instant};

use super::{
    observe::{BlockIdentity, HostKernel, LoopDevice, Node, Observations, Slave},
    release::{before, DEVICE_POLL},
    verify::{EROFS_MAGIC, VERITY_UUID_PREFIX},
    AttachmentKernel,
};
use crate::{
    attempt_registry::{RecordedRoot, RecordedRootEntry},
    ActivatedRootDirectory, ImageActivationError,
};

/// Detach the previous runtime's root still mounted on `entry`, if any, and
/// observe its mapper and loop generations ended before `deadline`.
///
/// An unmounted root is left to the directory inventory.
///
/// # Errors
/// [`ImageActivationError::EvidenceMismatch`] for a root that cannot be
/// observed or is not exactly a provider root; nothing is detached.
/// [`ImageActivationError::TeardownFailure`] for a failed detach, and
/// [`ImageActivationError::ResourceAbsenceUnverified`] for devices not
/// observed absent before the deadline.
pub async fn detach_recovered_root(
    entry: RecordedRootEntry,
    deadline: Instant,
) -> Result<(), ImageActivationError> {
    let detached = detach_with(
        &HostKernel::system(),
        entry,
        &super::images_directory(),
        deadline,
    )
    .await;
    detached
}

pub(super) async fn detach_with(
    kernel: &impl AttachmentKernel,
    entry: RecordedRootEntry,
    images: &Path,
    deadline: Instant,
) -> Result<(), ImageActivationError> {
    let RecordedRootEntry {
        intent,
        attempt,
        root,
    } = entry;
    // The attempt directory stands in for the covered root: both are on the
    // mount that holds the attempt tree.
    let observed = kernel.observe(root.as_fd(), &attempt, &attempt, "");
    let (mount, parent) = observed
        .mount
        .zip(observed.parent_mount_id)
        .ok_or(ImageActivationError::EvidenceMismatch)?;
    if mount.mount_id == parent {
        return Ok(());
    }
    let root_directory =
        ActivatedRootDirectory::for_attempt(intent.planned().unit_name().attempt_component());
    let devices = provider_root(
        kernel,
        &observed,
        (mount, parent),
        (&root_directory, images),
        intent.recorded_root(),
    )
    .ok_or(ImageActivationError::EvidenceMismatch)?;
    before(kernel, deadline)?;
    kernel.detach(root.as_fd())?;
    drop(root);
    loop {
        before(kernel, deadline)?;
        let absent = timeout_at(deadline, kernel.devices_absent(devices))
            .await
            .map_err(|_| ImageActivationError::ResourceAbsenceUnverified)?;
        before(kernel, deadline)?;
        if absent? {
            return Ok(());
        }
        let _wake = timeout_at(deadline, sleep(DEVICE_POLL)).await;
    }
}

/// The mapper and loop generations of `mount`, mounted on the mount
/// `parent`, when it is exactly a provider root at `root_directory` over an
/// image in `images` that matches `recorded`, if any.
fn provider_root(
    kernel: &impl AttachmentKernel,
    observed: &Observations,
    (mount, parent): (Node, u64),
    (root_directory, images): (&ActivatedRootDirectory, &Path),
    recorded: Option<&RecordedRoot>,
) -> Option<[BlockIdentity; 2]> {
    let entry = observed.entry.as_ref()?;
    let mapper = observed.mapper.as_ref()?;
    let mapper_identity = mapper.identity?;
    let uuid = mapper.uuid.as_deref()?;
    let (loop_name, loop_device) = one_loop(mapper.slaves.as_deref()?)?;
    let loop_identity = loop_device.identity?;
    let private_root = observed.path == Some(mount)
        && observed.filesystem_magic == Some(EROFS_MAGIC)
        && observed.read_only == Some(true)
        && entry.parent_id == parent
        && entry.device == mount.device
        && entry.root == "/"
        && entry.mount_point == root_directory.as_str()
        && entry.options.split(',').next() == Some("ro")
        && entry.filesystem == "erofs"
        // Any shared, master or propagate_from field is propagation.
        && entry.optional.is_empty();
    let verity = mapper_identity.device == mount.device
        && uuid.starts_with(VERITY_UUID_PREFIX)
        && mapper.read_only == Some(1);
    let provider_loop = loop_device.offset == Some(0)
        && loop_device.size_limit == Some(0)
        && loop_device.autoclear == Some(1)
        && loop_device.read_only == Some(1)
        && kernel.provider_image(loop_name, images);
    let as_recorded = recorded.is_none_or(|recorded| {
        recorded.mount_id == mount.mount_id
            && recorded.inode == mount.inode
            && recorded.mapper == (mapper_identity.device, mapper_identity.diskseq.get())
            && recorded.mapper_uuid == uuid
            && recorded.loop_name == loop_name
            && recorded.loop_device == (loop_identity.device, loop_identity.diskseq.get())
            && loop_device.backing == Some(recorded.image)
    });
    (private_root && verity && provider_loop && as_recorded)
        .then_some([mapper_identity, loop_identity])
}

/// The one loop device whose two partitions are the mapper's only slaves.
fn one_loop(slaves: &[Slave]) -> Option<(&str, &LoopDevice)> {
    match slaves {
        [first, second] => first
            .loop_name
            .as_deref()
            .zip(first.loop_device.as_ref())
            .filter(|(name, device)| {
                second.loop_name.as_deref() == Some(*name)
                    && second.loop_device.as_ref().map(|other| other.identity)
                        == Some(device.identity)
            }),
        _ => None,
    }
}
