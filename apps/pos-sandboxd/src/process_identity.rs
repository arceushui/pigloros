//! Pidfd identities of processes (ADR-069 LPV1 `provider-pidfd-identity`).
//!
//! The launcher cannot name the provider by uid or pid: with `PrivateUsersEx=self` the provider's
//! root is unmapped in the unit's user namespace, and with `PrivatePIDs=yes` its pid is not
//! visible. A pidfd is neither. Its pidfs inode is the process's identity (Linux 6.9 or later),
//! the same in every namespace. The provider records the identity of its own process in LPV1, and
//! the launcher compares it with the identity of the `SO_PEERPIDFD` of the release channel.

use std::os::fd::AsFd;

use nix::sys::socket::{getsockopt, sockopt::PeerPidfd};
use pos_reference::sandbox_provider_protocol::FdIdentity;
use rustix::{
    fs::{statx, AtFlags, StatxFlags},
    process::{getpid, pidfd_open, PidfdFlags},
};

const MOUNT_ID_REQUEST: StatxFlags = StatxFlags::BASIC_STATS.union(StatxFlags::MNT_ID);

/// The mount ID and inode of the object `descriptor` holds, if `statx` reported the mount ID.
pub(crate) fn descriptor_identity(descriptor: impl AsFd) -> Option<FdIdentity> {
    statx(descriptor, "", AtFlags::EMPTY_PATH, MOUNT_ID_REQUEST)
        .ok()
        .filter(|stat| StatxFlags::from_bits_retain(stat.stx_mask).contains(StatxFlags::MNT_ID))
        .map(|stat| FdIdentity {
            mount_id: stat.stx_mnt_id,
            inode: stat.stx_ino,
        })
}

/// The identity of this process, from a pidfd that it opens on itself.
pub(crate) fn own_process_identity() -> Option<FdIdentity> {
    pidfd_open(getpid(), PidfdFlags::empty())
        .ok()
        .and_then(descriptor_identity)
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
