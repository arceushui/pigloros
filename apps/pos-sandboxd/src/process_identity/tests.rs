use std::{error::Error, fs::File, process::Command};

use rustix::{
    net::{socketpair, AddressFamily, SocketFlags, SocketType},
    process::{pidfd_open, Pid, PidfdFlags},
};

use super::{descriptor_identity, own_process_identity, peer_process_identity};

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
