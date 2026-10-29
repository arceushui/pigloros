//! Value-only handoff of the identities accepted at root activation.

use super::{verify::Expected, VerifiedMountIdentity, VerifiedRootMount};
use crate::ActivatedRootDirectory;

/// Retained activation identities, without resource ownership or fresh evidence.
///
/// Only a [`VerifiedRootMount`] supplies this snapshot. Keeping or cloning it
/// holds no image, mount, directory or admission reference, so it can outlive
/// consuming teardown without delaying resource release. It records the facts
/// accepted together at activation; obtaining it performs no kernel readback.
///
/// Device generations are boot-local. The lifecycle owner must correlate these
/// facts with its attempt, admitted SIM1, current boot and durable intent, and
/// independently verify live identities before acting. This value proves no
/// current presence or absence, shutdown, complete cleanup or restart safety;
/// it grants no lifecycle, intent-deletion or admission authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootResourceIdentity {
    root_directory: ActivatedRootDirectory,
    image: (u64, u64),
    identity: VerifiedMountIdentity,
}

impl VerifiedRootMount {
    /// Copy the exact resource identities retained at activation.
    ///
    /// This does not refresh evidence or retain any owned resource. In
    /// particular, a copy remaining after a failed or cancelled teardown does
    /// not establish absence. See [`RootResourceIdentity`] for its scope.
    #[must_use]
    pub fn resource_identity(&self) -> RootResourceIdentity {
        let Expected {
            root_directory,
            held,
            ..
        } = &self.expected;
        RootResourceIdentity {
            root_directory: root_directory.clone(),
            image: *held,
            identity: self.identity.clone(),
        }
    }
}

impl RootResourceIdentity {
    /// The verified root path, containing the deterministic attempt component.
    #[must_use]
    pub const fn root_directory(&self) -> &ActivatedRootDirectory {
        &self.root_directory
    }

    /// The mount ID accepted for the attached root.
    #[must_use]
    pub const fn mount_id(&self) -> u64 {
        self.identity.mount.mount_id
    }

    /// The root's device major/minor and inode, from the accepted mount node.
    #[must_use]
    pub const fn root_identity(&self) -> ((u32, u32), u64) {
        (self.identity.mount.device, self.identity.mount.inode)
    }

    /// The admitted image descriptor's device and inode, not its SIM1 digest.
    #[must_use]
    pub const fn image_identity(&self) -> (u64, u64) {
        self.image
    }

    /// The exact UUID of the accepted device-mapper device.
    #[must_use]
    pub fn mapper_uuid(&self) -> &str {
        &self.identity.mapper_uuid
    }

    /// The mapper's device major/minor and nonzero, boot-local disk sequence.
    #[must_use]
    pub const fn mapper_generation(&self) -> ((u32, u32), u64) {
        (
            self.identity.mapper.device,
            self.identity.mapper.diskseq.get(),
        )
    }

    /// The exact loop name accepted together with the mapper and backing image.
    #[must_use]
    pub fn loop_name(&self) -> &str {
        &self.identity.loop_name
    }

    /// The loop's device major/minor and nonzero, boot-local disk sequence.
    #[must_use]
    pub const fn loop_generation(&self) -> ((u32, u32), u64) {
        (
            self.identity.loop_device.device,
            self.identity.loop_device.diskseq.get(),
        )
    }
}
