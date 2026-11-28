//! The forbidden operations the #216 probe fixtures attempt.
//!
//! A probe is one operation the sandbox must deny. [`Attempt`] is its result:
//! `Err` when the operation failed (denied), `Ok` when it succeeded, which is
//! an escape. A fixture reports success only when [`contained`] holds for
//! every attempt it made. Each probe takes its target as a parameter so that
//! the host tests can aim it at a place where the answer is known; the
//! fixtures pass the fixed in-sandbox targets.

use std::fs::{File, OpenOptions};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use rustix::mount::{mount, MountFlags};
use rustix::net::{ipproto, socket, AddressFamily, Protocol, SocketType};
use rustix::process::{getpid, test_kill_process, Pid};

/// One probe's result: `Err` is a denied operation.
pub type Attempt = io::Result<()>;

/// How long a network probe waits for an answer.
const NETWORK_WAIT: Duration = Duration::from_millis(300);
/// The highest process ID the foreign-signal probe tries.
pub const LAST_PROBED_PID: u32 = 4096;

/// Every place the probe fixtures aim at.
///
/// [`Targets::GUEST`] holds the fixed in-sandbox places, all of which the
/// sandbox must deny. A host test aims the same fixtures at a temporary
/// directory and a local socket whose answers are known, so that no test
/// touches the real host paths.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Targets<'a> {
    /// Files the adapter must not read (host secrets, the provider's state,
    /// physical memory).
    pub read_denied: [&'a str; 3],
    /// The cgroup file the adapter must not write.
    pub write_denied: &'a str,
    /// The work area: a mount over it is denied, and the work-area fixture
    /// fills it.
    pub work: &'a str,
    /// The read-only root.
    pub root: &'a str,
    /// An address (RFC 5737 documentation) nothing may answer at over TCP.
    pub tcp: SocketAddr,
    /// The loopback stub resolver, over UDP.
    ///
    /// In the guest nothing may listen at the guest's address, and loopback
    /// UDP must not be silently dropped: a datagram that is sent and met only
    /// silence counts as an escape, so a contained adapter needs a refusal.
    pub resolver: SocketAddr,
    /// The system bus socket.
    pub bus: &'a str,
    /// The highest process ID the foreign-signal probe tries.
    pub last_pid: u32,
}

impl Targets<'static> {
    /// The in-sandbox places of the evidence guest.
    pub const GUEST: Self = Self {
        read_denied: ["/etc/shadow", "/run/pigloros/sandbox", "/dev/mem"],
        write_denied: "/sys/fs/cgroup/cgroup.procs",
        work: "/work",
        root: "/",
        tcp: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 9),
        resolver: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 53)), 53),
        bus: "/run/dbus/system_bus_socket",
        last_pid: LAST_PROBED_PID,
    };
}

/// Whether every attempt was denied, and at least one was made.
#[must_use]
pub fn contained(attempts: &[Attempt]) -> bool {
    !attempts.is_empty() && attempts.iter().all(Result::is_err)
}

/// Open `path` for reading.
///
/// # Errors
/// Fails when the operation is denied, which is the expected answer.
pub fn open_read(path: &Path) -> Attempt {
    File::open(path).map(drop)
}

/// Open `path` for writing without creating or truncating it.
///
/// # Errors
/// Fails when the operation is denied, which is the expected answer.
pub fn open_write(path: &Path) -> Attempt {
    OpenOptions::new().write(true).open(path).map(drop)
}

/// Create `path` as a new file.
///
/// # Errors
/// Fails when the operation is denied, which is the expected answer.
pub fn create_file(path: &Path) -> Attempt {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map(drop)
}

/// Create the directory `path`.
///
/// # Errors
/// Fails when the operation is denied, which is the expected answer.
pub fn create_directory(path: &Path) -> Attempt {
    std::fs::create_dir(path)
}

/// Remove the file `path`.
///
/// # Errors
/// Fails when the operation is denied, which is the expected answer.
pub fn remove_file(path: &Path) -> Attempt {
    std::fs::remove_file(path)
}

/// Mount a tmpfs on `target`.
///
/// # Errors
/// Fails when the operation is denied, which is the expected answer.
pub fn mount_tmpfs(target: &Path) -> Attempt {
    mount("none", target, "tmpfs", MountFlags::empty(), None).map_err(io::Error::from)
}

/// Create a socket of this family and type.
///
/// # Errors
/// Fails when the operation is denied, which is the expected answer.
pub fn create_socket(
    family: AddressFamily,
    kind: SocketType,
    protocol: Option<Protocol>,
) -> Attempt {
    socket(family, kind, protocol)
        .map(drop)
        .map_err(io::Error::from)
}

/// Connect a TCP stream to `address`.
///
/// # Errors
/// Fails when the operation is denied, which is the expected answer.
pub fn connect_tcp(address: &SocketAddr) -> Attempt {
    TcpStream::connect_timeout(address, NETWORK_WAIT).map(drop)
}

/// Connect to the Unix socket at `path`.
///
/// # Errors
/// Fails when the operation is denied, which is the expected answer.
pub fn connect_unix(path: &Path) -> Attempt {
    UnixStream::connect(path).map(drop)
}

/// Send one datagram to `address` from an IPv4 socket and wait for a reply.
///
/// A reply, or no reply at all, shows the datagram reached a receiver.
///
/// An IPv6 address cannot be reached from that socket, which is also a denial.
///
/// # Errors
/// Fails when the operation is denied, which is the expected answer.
pub fn udp_exchange(address: &SocketAddr) -> Attempt {
    UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .and_then(|socket| socket.set_read_timeout(Some(NETWORK_WAIT)).map(|()| socket))
        .and_then(|socket| socket.connect(address).map(|()| socket))
        .and_then(|socket| socket.send(b"probe").map(|_| socket))
        .and_then(|socket| answered_or_silent(socket.recv(&mut [0_u8; 16])))
}

/// A datagram that was sent and then answered, or met only silence, reached
/// a receiver: that is an escape. Anything else (a refusal from a closed
/// port, say) is a denial.
fn answered_or_silent(reply: io::Result<usize>) -> Attempt {
    match reply {
        Ok(_) => Ok(()),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) =>
        {
            Ok(())
        }
        Err(error) => Err(error),
    }
}

/// Whether a process other than this one can be signalled with signal 0.
///
/// # Errors
/// Fails when the operation is denied, which is the expected answer.
pub fn signal_foreign(pid: u32) -> Attempt {
    let target = i32::try_from(pid)
        .ok()
        .and_then(Pid::from_raw)
        .filter(|target| *target != getpid());
    target
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))
        .and_then(|target| test_kill_process(target).map_err(io::Error::from))
}

/// The attempts of the filesystem-escape fixture.
#[must_use]
pub fn filesystem_escape(targets: &Targets<'_>) -> Vec<Attempt> {
    let [shadow, state, memory] = targets.read_denied;
    vec![
        open_read(Path::new(shadow)),
        open_read(Path::new(state)),
        open_write(Path::new(targets.write_denied)),
        open_read(Path::new(memory)),
        mount_tmpfs(Path::new(targets.work)),
    ]
}

/// The attempts of the read-only-root-write fixture, below `root`.
#[must_use]
pub fn read_only_root_write(root: &Path) -> Vec<Attempt> {
    vec![
        create_file(&root.join("probe")),
        open_write(&root.join("adapter")),
        create_directory(&root.join("probe-directory")),
        remove_file(&root.join("adapter")),
    ]
}

/// The attempts of the network-escape fixture.
#[must_use]
pub fn network_escape(targets: &Targets<'_>) -> Vec<Attempt> {
    vec![
        create_socket(AddressFamily::INET, SocketType::RAW, Some(ipproto::ICMP)),
        create_socket(AddressFamily::PACKET, SocketType::RAW, None),
        connect_tcp(&targets.tcp),
        udp_exchange(&targets.resolver),
        connect_unix(Path::new(targets.bus)),
    ]
}

/// The attempts of the foreign-signals fixture: every process ID up to
/// [`LAST_PROBED_PID`] other than the adapter's own.
#[must_use]
pub fn foreign_signals(last: u32) -> Vec<Attempt> {
    (1..=last).map(signal_foreign).collect()
}
