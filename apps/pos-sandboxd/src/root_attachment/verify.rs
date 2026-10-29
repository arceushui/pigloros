//! The closed comparison of one attached mount's readback with the admission.
//!
//! Every check below must hold; any absent or different fact is an
//! activation evidence mismatch (ADR-087 §2 step 6, §4).

use pos_reference::{
    provider_admission::HeldImageAdmission, sandbox_provider_protocol::PartitionDescriptor,
};

use super::observe::{BlockIdentity, LoopDevice, MountEntry, Node, Observations, Slave};
use crate::{ActivatedRootDirectory, ImageActivationError};

/// `EROFS_SUPER_MAGIC_V1` (Linux `include/uapi/linux/magic.h`).
const EROFS_MAGIC: u64 = 0xE0F5_E1E2;
/// cryptsetup names every dm-verity device's UUID `CRYPT-VERITY-...`.
const VERITY_UUID_PREFIX: &str = "CRYPT-VERITY-";
/// sysfs reports partition extents in 512-byte sectors.
const SECTOR: u64 = 512;

/// One admitted SIM1 partition extent, in bytes.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct Extent {
    pub(super) start: u64,
    pub(super) length: u64,
}

impl Extent {
    const fn of(partition: &PartitionDescriptor) -> Self {
        Self {
            start: partition.start_bytes,
            length: partition.length_bytes,
        }
    }
}

/// What the attached mount must prove, all from one admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Expected {
    pub(super) root_directory: ActivatedRootDirectory,
    pub(super) root: Extent,
    pub(super) verity: Extent,
    pub(super) signature: Extent,
    /// Device and inode of the held, admitted image descriptor.
    pub(super) held: (u64, u64),
    /// The SIM1 executable path and its admitted BLAKE3 digest.
    pub(super) executable_path: String,
    pub(super) executable_digest: [u8; 32],
}

/// The mount and devices accepted together in one complete kernel readback.
/// Rechecks must retain these identities even when another device could also
/// satisfy the admitted image's content and partition requirements.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct VerifiedMountIdentity {
    pub(super) mount: Node,
    mapper_uuid: String,
    mapper: BlockIdentity,
    loop_name: String,
    loop_device: BlockIdentity,
}

impl VerifiedMountIdentity {
    pub(super) const fn devices(&self) -> [BlockIdentity; 2] {
        [self.mapper, self.loop_device]
    }
}

impl Expected {
    /// The admitted SIM1 root and root-verity extents and the held image.
    pub(super) fn for_admission(
        admission: &HeldImageAdmission<'_>,
        root_directory: ActivatedRootDirectory,
    ) -> Option<Self> {
        let manifest = admission.snapshot().image().manifest();
        rustix::fs::fstat(admission).ok().map(|held| Self {
            root_directory,
            // SIM1 validation fixes ordinals 0, 1 and 2 as root, root-verity
            // and root-verity-signature.
            root: Extent::of(&manifest.partitions[0]),
            verity: Extent::of(&manifest.partitions[1]),
            signature: Extent::of(&manifest.partitions[2]),
            held: (held.st_dev, held.st_ino),
            executable_path: manifest.executable_path.clone(),
            executable_digest: manifest.executable_blake3_digest,
        })
    }

    /// Accept exactly the admitted, private, read-only EROFS root.
    pub(super) fn verify(
        &self,
        observed: &Observations,
    ) -> Result<VerifiedMountIdentity, ImageActivationError> {
        observed
            .mount
            .filter(|mount| {
                observed.path == Some(*mount)
                    && observed.parent_mount_id.is_some()
                    && observed.filesystem_magic == Some(EROFS_MAGIC)
                    && observed.read_only == Some(true)
                    && observed
                        .entry
                        .as_ref()
                        .is_some_and(|entry| self.entry_matches(entry, mount, observed))
                    && observed.executable.is_some_and(|executable| {
                        executable.node.mount_id == mount.mount_id
                            && executable.blake3 == self.executable_digest
                    })
            })
            .and_then(|mount| {
                observed.mapper.as_ref().and_then(|mapper| {
                    mapper
                        .identity
                        .filter(|identity| identity.device == mount.device)
                        .map(|identity| (mount, mapper, identity))
                })
            })
            .and_then(|(mount, mapper, identity)| {
                mapper
                    .uuid
                    .as_ref()
                    .filter(|uuid| {
                        uuid.starts_with(VERITY_UUID_PREFIX) && mapper.read_only == Some(1)
                    })
                    .zip(mapper.slaves.as_deref())
                    .and_then(|(uuid, slaves)| {
                        self.verified_loop(slaves).map(|(loop_name, loop_device)| {
                            VerifiedMountIdentity {
                                mount,
                                mapper_uuid: uuid.clone(),
                                mapper: identity,
                                loop_name: loop_name.to_owned(),
                                loop_device,
                            }
                        })
                    })
            })
            .ok_or(ImageActivationError::EvidenceMismatch)
    }

    /// The private EROFS mount at exactly the attempt root, on the held parent.
    fn entry_matches(&self, entry: &MountEntry, mount: &Node, observed: &Observations) -> bool {
        Some(entry.parent_id) == observed.parent_mount_id
            && entry.device == mount.device
            && entry.root == "/"
            && entry.mount_point == self.root_directory.as_str()
            && entry.options.split(',').next() == Some("ro")
            && entry.super_options.split(',').next() == Some("ro")
            && entry.filesystem == "erofs"
            // Any shared, master or propagate_from field is propagation.
            && entry.optional.is_empty()
    }

    /// Exactly the root and root-verity partitions of one loop device that
    /// is backed read-only by the held image.
    fn verified_loop<'a>(&self, slaves: &'a [Slave]) -> Option<(&'a str, BlockIdentity)> {
        match slaves {
            [first, second] => {
                let extents = [first, second].map(extent_of);
                let identity = first
                    .loop_device
                    .as_ref()
                    .and_then(|device| device.identity);
                first
                    .loop_name
                    .as_deref()
                    .zip(second.loop_name.as_deref())
                    .zip(identity)
                    .filter(|((first_name, second_name), identity)| {
                        first_name == second_name
                            && second
                                .loop_device
                                .as_ref()
                                .and_then(|device| device.identity)
                                == Some(*identity)
                            && (extents == [Some(self.root), Some(self.verity)]
                                || extents == [Some(self.verity), Some(self.root)])
                            && [first, second].iter().all(|slave| {
                                slave
                                    .loop_device
                                    .as_ref()
                                    .is_some_and(|device| self.loop_matches(device))
                            })
                    })
                    .map(|((name, _), identity)| (name, identity))
            }
            _ => None,
        }
    }

    /// Owner decision Q7.5: the loop device is the held image, from byte 0,
    /// unbounded, autoclear and read-only. Its partition table is exactly
    /// the admitted SIM1 GPT set (ADR-087 §2 step 6).
    fn loop_matches(&self, device: &LoopDevice) -> bool {
        device.backing == Some(self.held)
            && device.offset == Some(0)
            && device.size_limit == Some(0)
            && device.autoclear == Some(1)
            && device.read_only == Some(1)
            && device
                .partitions
                .as_deref()
                .is_some_and(|partitions| self.partitions_match(partitions))
    }

    fn partitions_match(&self, partitions: &[Option<(u64, u64)>]) -> bool {
        let mut observed: Vec<Option<Extent>> = partitions
            .iter()
            .map(|partition| partition.and_then(|(start, size)| sectors(start, size)))
            .collect();
        let mut admitted = vec![Some(self.root), Some(self.verity), Some(self.signature)];
        observed.sort_unstable();
        admitted.sort_unstable();
        observed == admitted
    }
}

fn extent_of(slave: &Slave) -> Option<Extent> {
    slave
        .start
        .zip(slave.size)
        .and_then(|(start, size)| sectors(start, size))
}

/// A 512-byte-sector extent in bytes; an overflowing extent is absent.
fn sectors(start: u64, size: u64) -> Option<Extent> {
    start
        .checked_mul(SECTOR)
        .zip(size.checked_mul(SECTOR))
        .map(|(start, length)| Extent { start, length })
}
