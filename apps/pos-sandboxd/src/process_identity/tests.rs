use std::{error::Error, fs::File, process::Command};

use rustix::{
    net::{socketpair, AddressFamily, SocketFlags, SocketType},
    process::{pidfd_open, Pid, PidfdFlags},
};

use super::{
    descriptor_identity, distinct_from, identity_of_stat, own_process_identity,
    peer_process_identity, pidfd_identity, provider_identity,
};
use pos_reference::sandbox_provider_protocol::FdIdentity;

type TestResult = Result<(), Box<dyn Error>>;

#[test]
fn a_process_identity_is_stable_and_one_per_process() -> TestResult {
    let own = own_process_identity().ok_or("no identity of this process")?;
    assert_ne!(own.inode, 0);
    assert_ne!(own.mount_id, 0);
    assert_eq!(own_process_identity(), Some(own));

    let mut child = Command::new("sleep").arg("30").spawn()?;
    let pid = Pid::from_raw(i32::try_from(child.id())?).ok_or("no child pid")?;
    let other = pidfd_open(pid, PidfdFlags::empty()).map(descriptor_identity);
    child.kill()?;
    child.wait()?;
    let other = other?.ok_or("no identity of the child")?;
    assert_ne!(other, own);
    // The identity is that of the pidfs mount, not of a file.
    assert_eq!(other.mount_id, own.mount_id);
    Ok(())
}

#[test]
fn the_peer_of_a_socket_pair_is_the_process_that_made_it() -> TestResult {
    let (left, right) = socketpair(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )?;
    let own = own_process_identity();
    assert!(own.is_some());
    assert_eq!(peer_process_identity(&left), own);
    assert_eq!(peer_process_identity(&right), own);
    // A closed peer still names the process that made the pair; a descriptor that is no socket
    // names nothing.
    drop(right);
    assert_eq!(peer_process_identity(&left), own);
    let file = File::open("/")?;
    assert_eq!(peer_process_identity(&file), None);
    Ok(())
}

const A: FdIdentity = FdIdentity {
    mount_id: 8,
    inode: 100,
};
const B: FdIdentity = FdIdentity {
    mount_id: 8,
    inode: 101,
};

#[test]
fn an_identity_needs_the_mount_id_in_the_statx_mask() {
    let mount = rustix::fs::StatxFlags::MNT_ID.bits();
    assert_eq!(identity_of_stat(mount, 8, 100), Some(A));
    assert_eq!(
        identity_of_stat(mount | rustix::fs::StatxFlags::INO.bits(), 8, 100),
        Some(A)
    );
    assert_eq!(
        identity_of_stat(rustix::fs::StatxFlags::INO.bits(), 8, 100),
        None
    );
    assert_eq!(identity_of_stat(0, 8, 100), None);
}

#[test]
fn a_pidfd_that_could_not_be_opened_has_no_identity() {
    assert_eq!(pidfd_identity(Err(rustix::io::Errno::SRCH)), None);
}

#[test]
fn an_identity_is_only_one_if_it_differs_from_that_of_another_process() {
    assert_eq!(distinct_from(Some(A), Some(B)), Some(A));
    // The same inode for two processes (a kernel before pidfs inodes) names neither.
    assert_eq!(distinct_from(Some(A), Some(A)), None);
    assert_eq!(distinct_from(None, Some(B)), None);
    assert_eq!(distinct_from(Some(A), None), None);
    assert_eq!(distinct_from(None, None), None);
}

#[test]
fn the_provider_identity_is_this_process_on_a_kernel_with_pidfs_inodes() {
    let own = own_process_identity();
    let init = pidfd_identity(rustix::process::pidfd_open(
        rustix::process::Pid::INIT,
        rustix::process::PidfdFlags::empty(),
    ));
    // Whatever the kernel: the probe agrees with the comparison it is built from.
    assert_eq!(provider_identity(), distinct_from(own, init));
}
