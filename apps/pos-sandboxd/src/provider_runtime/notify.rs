//! `READY=1` to the service manager (ADR-069 R11 §5.1 step 8, §9).
//!
//! The notification is one `sendto` on an `AF_UNIX` datagram socket: no
//! `systemd-notify` executable runs. `NOTIFY_SOCKET` must name an absolute
//! path or, with a leading `@`, an abstract name. Any other value, or none,
//! sends nothing; the start job then fails after its 30 s bound.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;

use rustix::net::{
    sendto, socket_with, AddressFamily, SendFlags, SocketAddrUnix, SocketFlags, SocketType,
};

/// The one notification the runtime sends.
const READY: &[u8] = b"READY=1";

/// Send `READY=1` to the manager socket that `notify_socket` names, and
/// report whether the datagram was sent.
pub(super) fn notify_ready(notify_socket: Option<&OsStr>) -> bool {
    notify_socket
        .and_then(manager_address)
        .zip(
            socket_with(
                AddressFamily::UNIX,
                SocketType::DGRAM,
                SocketFlags::CLOEXEC,
                None,
            )
            .ok(),
        )
        .is_some_and(|(address, socket)| {
            sendto(&socket, READY, SendFlags::empty(), &address)
                .is_ok_and(|sent| sent == READY.len())
        })
}

/// The `AF_UNIX` address of `NOTIFY_SOCKET`: an absolute path, or an
/// abstract name after a leading `@`.
fn manager_address(notify_socket: &OsStr) -> Option<SocketAddrUnix> {
    match notify_socket.as_bytes() {
        [b'/', ..] => SocketAddrUnix::new(notify_socket).ok(),
        [b'@', name @ ..] => SocketAddrUnix::new_abstract_name(name).ok(),
        _ => None,
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::error::Error;
    use std::ffi::OsStr;
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::{SocketAddr, UnixDatagram};
    use std::time::Duration;

    use super::notify_ready;

    type TestResult = Result<(), Box<dyn Error>>;

    fn receive(manager: &UnixDatagram) -> Result<Vec<u8>, Box<dyn Error>> {
        manager.set_read_timeout(Some(Duration::from_secs(5)))?;
        let mut datagram = [0; 64];
        let length = manager.recv(&mut datagram)?;
        Ok(datagram[..length].to_vec())
    }

    #[test]
    fn ready_goes_to_an_abstract_or_absolute_manager_socket() -> TestResult {
        let name = format!("pigloros-notify-test-{}", std::process::id());
        let abstract_manager = UnixDatagram::bind_addr(&SocketAddr::from_abstract_name(&name)?)?;
        assert!(notify_ready(Some(OsStr::new(&format!("@{name}")))));
        assert_eq!(receive(&abstract_manager)?, b"READY=1");
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("notify");
        let path_manager = UnixDatagram::bind(&path)?;
        assert!(notify_ready(Some(path.as_os_str())));
        assert_eq!(receive(&path_manager)?, b"READY=1");
        Ok(())
    }

    #[test]
    fn an_invalid_or_absent_manager_socket_gets_nothing() {
        let too_long = format!("/{}", "n".repeat(200));
        for value in [
            None,
            Some(""),
            Some("notify"),
            Some("vsock:2:9"),
            Some("/nonexistent/notify"),
            Some(too_long.as_str()),
        ] {
            assert!(!notify_ready(value.map(OsStr::new)), "{value:?}");
        }
    }
}
