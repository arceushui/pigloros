//! Pidfd identities of processes (ADR-069 LPV1 `provider-pidfd-identity`).
//!
//! The launcher cannot name the provider by uid or pid: with `PrivateUsersEx=self` the provider's
//! root is unmapped in the unit's user namespace, and with `PrivatePIDs=yes` its pid is not
//! visible. A pidfd is neither. Its pidfs inode is the process's identity, the same in every
//! namespace.
//!
//! **Kernel floor: Linux 6.9.** Before 6.9 every pidfd shares one anonymous inode, so the identity
//! would be the same for all processes and the check would only prove that the peer has some
//! pidfd. Both sides therefore refuse such a kernel: the provider records its identity only if it
//! differs from the identity of pid 1 ([`provider_identity`]), and the launcher accepts the peer
//! only if the identity of its own pidfd differs from the provider's (`launcher/barrier.rs`).
//!
//! **Launcher mode must never call [`provider_identity`]**: it opens a pidfd on pid 1, which in
//! the launcher's own pid namespace is the launcher itself (`tests/provider_process_creation_public.rs`
//! checks that no launcher source calls it).
//!
//! The provider records the identity of its own process in LPV1, and the launcher compares it
//! with the identity of the `SO_PEERPIDFD` of the release channel.

use std::os::fd::{AsFd, OwnedFd};

use nix::sys::socket::{getsockopt, sockopt::PeerPidfd};
use pos_reference::sandbox_provider_protocol::FdIdentity;
use rustix::fs::{statx, AtFlags, StatxFlags};
use rustix::process::getpid;
use rustix::process::pidfd_open;
use rustix::process::Pid;
use rustix::process::PidfdFlags;

const MOUNT_ID_REQUEST: StatxFlags = StatxFlags::BASIC_STATS.union(StatxFlags::MNT_ID);

/// The identity `statx` reported, if it reported the mount ID (`mask` says which fields it set).
pub(crate) fn identity_of_stat(mask: u32, mount_id: u64, inode: u64) -> Option<FdIdentity> {
    StatxFlags::from_bits_retain(mask)
        .contains(StatxFlags::MNT_ID)
        .then_some(FdIdentity { mount_id, inode })
}

/// The mount ID and inode of the object `descriptor` holds, if `statx` reported the mount ID.
pub(crate) fn descriptor_identity(descriptor: impl AsFd) -> Option<FdIdentity> {
    statx(descriptor, "", AtFlags::EMPTY_PATH, MOUNT_ID_REQUEST)
        .ok()
        .and_then(|stat| identity_of_stat(stat.stx_mask, stat.stx_mnt_id, stat.stx_ino))
}

/// The identity of the process behind `pidfd`, if the pidfd could be opened.
pub(crate) fn pidfd_identity(pidfd: rustix::io::Result<OwnedFd>) -> Option<FdIdentity> {
    pidfd.ok().and_then(descriptor_identity)
}

/// The identity of this process, from a pidfd that it opens on itself.
pub(crate) fn own_process_identity() -> Option<FdIdentity> {
    pidfd_identity(pidfd_open(getpid(), PidfdFlags::empty()))
}

/// `own`, if it differs from `init`, the identity of another process (pid 1).
///
/// Equal identities mean that the kernel gives every pidfd the same inode, so the identity names
/// no process; a missing one means it could not be read. Either way there is no identity.
pub(crate) fn distinct_from(
    own: Option<FdIdentity>,
    init: Option<FdIdentity>,
) -> Option<FdIdentity> {
    own.filter(|own| init.is_some_and(|init| init != *own))
}

/// The identity of the provider process that LPV1 records: its own pidfd identity, but only on a
/// kernel where it differs from that of pid 1.
pub(crate) fn provider_identity() -> Option<FdIdentity> {
    distinct_from(
        own_process_identity(),
        pidfd_identity(pidfd_open(Pid::INIT, PidfdFlags::empty())),
    )
}

/// The identity of the process at the other end of the connected socket `socket`, from its
/// `SO_PEERPIDFD`. `None` when the kernel gives no pidfd (it does not support the option, or the
/// peer is gone).
pub(crate) fn peer_process_identity(socket: impl AsFd) -> Option<FdIdentity> {
    getsockopt(&socket, PeerPidfd)
        .ok()
        .and_then(descriptor_identity)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
