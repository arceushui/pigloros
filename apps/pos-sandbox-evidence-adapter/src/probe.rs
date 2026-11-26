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
use rustix::net::{socket, AddressFamily, SocketType};
use rustix::process::{getpid, test_kill_process, Pid};

/// One probe's result: `Err` is a denied operation.
pub type Attempt = io::Result<()>;

/// How long a network probe waits for an answer.
const NETWORK_WAIT: Duration = Duration::from_millis(300);
/// The highest process ID the foreign-signal probe tries.
pub const LAST_PROBED_PID: u32 = 4096;
/// A documentation address (RFC 5737) nothing may answer at.
const UNDECLARED_TCP: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 9);
/// The loopback stub resolver address.
const STUB_RESOLVER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 53)), 53);
/// The system bus socket.
const SYSTEM_BUS: &str = "/run/dbus/system_bus_socket";

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
pub fn create_socket(family: AddressFamily, kind: SocketType) -> Attempt {
    socket(family, kind, None)
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

/// Send one datagram to `address` from an IPv4 socket and wait for any reply.
///
/// An IPv6 address cannot be reached from that socket, which is also a denial.
///
/// # Errors
/// Fails when the operation is denied, which is the expected answer.
pub fn udp_exchange(address: &SocketAddr) -> Attempt {
    UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .and_then(|socket| socket.set_read_timeout(Some(NETWORK_WAIT)).map(|()| socket))
        .and_then(|socket| socket.send_to(b"probe", address).map(|_| socket))
        .and_then(|socket| socket.recv_from(&mut [0_u8; 16]).map(drop))
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
pub fn filesystem_escape() -> Vec<Attempt> {
    vec![
        open_read(Path::new("/etc/shadow")),
        open_read(Path::new("/run/pigloros/sandbox")),
        open_write(Path::new("/sys/fs/cgroup/cgroup.procs")),
        open_read(Path::new("/dev/mem")),
        mount_tmpfs(Path::new("/work")),
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
pub fn network_escape() -> Vec<Attempt> {
    vec![
        create_socket(AddressFamily::INET, SocketType::RAW),
        create_socket(AddressFamily::PACKET, SocketType::RAW),
        connect_tcp(&UNDECLARED_TCP),
        udp_exchange(&STUB_RESOLVER),
        connect_unix(Path::new(SYSTEM_BUS)),
    ]
}

/// The attempts of the foreign-signals fixture: every process ID up to
/// [`LAST_PROBED_PID`] other than the adapter's own.
#[must_use]
pub fn foreign_signals(last: u32) -> Vec<Attempt> {
    (1..=last).map(signal_foreign).collect()
}
