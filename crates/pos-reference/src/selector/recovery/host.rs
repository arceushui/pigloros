//! The selector's own kernel checks of one recovery operation (ADR-069 R12
//! §6 steps 3, 5, 8, 9 and 12, owner decision O8).
//!
//! The port's observations are only as sound as the adapter. These checks
//! are the selector's: a recorded process is absent, a control group is
//! absent from the cgroup2 mount, the recovery leaf is the exact root-owned
//! socket, and the peer that answers is the observed main process.

use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read, Write};
use std::num::NonZeroU64;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::MetadataExt as _;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustix::fs::{
    fstatfs, openat2, statat, unlinkat, AtFlags, FileType, Mode, OFlags, ResolveFlags, Stat,
};
use rustix::net::{connect, socket_with, AddressFamily, SocketAddrUnix, SocketFlags, SocketType};

use super::RecoveryError;
use crate::selector::runtime_lifecycle::CgroupPath;

/// The cgroup2 mount the selector checks control groups against.
const CGROUP_MOUNT: &str = "/sys/fs/cgroup";
/// `CGROUP2_SUPER_MAGIC` from `linux/magic.h`.
const CGROUP2_SUPER_MAGIC: u64 = 0x6367_7270;
/// The recovery leaf's exact mode.
const LEAF_MODE: u32 = 0o600;
/// The retained recovery directory's exact mode.
const DIRECTORY_MODE: u32 = 0o700;

/// The BLAKE3 digest of a process's executable, read at most `length + 1`
/// bytes deep.
pub(crate) type ExecutableDigest =
    fn(NonZeroU64, u64) -> Result<[u8; 32], crate::selector::SelectorBoundaryError>;

/// The cgroup2 path `/proc/<pid>/cgroup` names for a process.
pub(crate) type ProcessControlGroup =
    fn(NonZeroU64) -> Result<String, crate::selector::SelectorBoundaryError>;

/// The selector's clock. Production reads [`Instant::now`]; tests inject one
/// so that every bound is asserted against it, not wall time (R12 I10).
pub(crate) type RecoveryClock = Arc<dyn Fn() -> Instant + Send + Sync>;

/// The kernel and filesystem view one recovery operation checks against.
pub(crate) struct RecoveryHost {
    directory: Arc<File>,
    owner: u32,
    cgroup_mount: PathBuf,
    cgroup2: fn(&File) -> bool,
    executable_digest: ExecutableDigest,
    control_group: ProcessControlGroup,
    clock: RecoveryClock,
}

/// The `(dev, ino)` of one recovery leaf.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct LeafIdentity {
    device: u64,
    inode: u64,
}

impl RecoveryHost {
    /// The production view: the retained fixed recovery directory, root
    /// peers, `/sys/fs/cgroup`, `/proc/<pid>/exe` through
    /// `executable_digest`, `/proc/<pid>/cgroup`, and the monotonic clock.
    pub(crate) fn fixed(directory: Arc<File>, executable_digest: ExecutableDigest) -> Self {
        Self {
            directory,
            owner: 0,
            cgroup_mount: PathBuf::from(CGROUP_MOUNT),
            cgroup2: is_cgroup2,
            executable_digest,
            control_group: crate::selector::runtime_lifecycle::process_control_group,
            clock: Arc::new(Instant::now),
        }
    }

    /// A view over a test directory, owner, cgroup mount and clock.
    #[cfg(test)]
    pub(crate) fn for_test(
        directory: Arc<File>,
        owner: u32,
        (cgroup_mount, cgroup2): (PathBuf, fn(&File) -> bool),
        executable_digest: ExecutableDigest,
        clock: RecoveryClock,
    ) -> Self {
        Self {
            directory,
            owner,
            cgroup_mount,
            cgroup2,
            executable_digest,
            control_group: crate::selector::runtime_lifecycle::process_control_group,
            clock,
        }
    }

    /// The same view, reading each process's control group through
    /// `control_group` instead of `/proc/<pid>/cgroup`.
    #[cfg(test)]
    #[cfg(target_os = "linux")]
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub(crate) fn with_control_group(self, control_group: ProcessControlGroup) -> Self {
        Self {
            control_group,
            ..self
        }
    }

    /// The selector's current time.
    pub(super) fn now(&self) -> Instant {
        (self.clock)()
    }

    /// `bound` after the selector's current time.
    pub(super) fn deadline_after(&self, bound: Duration) -> Result<Instant, RecoveryError> {
        self.now()
            .checked_add(bound)
            .ok_or(RecoveryError::DeadlineExceeded)
    }

    /// R12 §6 step 3: the recorded main process is absent. A live process
    /// with the recorded PID and start ticks fails closed; a recycled PID
    /// (other start ticks) proves the original absent and is never signalled.
    pub(super) fn require_process_absent(
        pid: u64,
        start_time_ticks: u64,
    ) -> Result<(), RecoveryError> {
        std::fs::read_to_string(format!("/proc/{pid}/stat")).map_or_else(
            |error| {
                require(
                    error.kind() == io::ErrorKind::NotFound,
                    RecoveryError::ProcessAlive,
                )
            },
            |stat| {
                stat_start_time_ticks(&stat).and_then(|ticks| {
                    require(ticks != start_time_ticks, RecoveryError::ProcessAlive)
                })
            },
        )
    }

    /// R12 §6 step 3: `control_group` is absent from the cgroup2 mount. A
    /// mount that is not cgroup2 fails closed.
    pub(super) fn require_cgroup_absent(
        &self,
        control_group: &CgroupPath,
    ) -> Result<(), RecoveryError> {
        let relative = control_group.as_str().trim_start_matches('/');
        openat2(
            rustix::fs::CWD,
            &self.cgroup_mount,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS,
        )
        .map(File::from)
        .map_err(|_| RecoveryError::CgroupPresent)
        .and_then(|mount| {
            if (self.cgroup2)(&mount) && !relative.is_empty() {
                Ok(mount)
            } else {
                Err(RecoveryError::CgroupPresent)
            }
        })
        .and_then(
            |mount| match statat(&mount, relative, AtFlags::SYMLINK_NOFOLLOW) {
                Err(rustix::io::Errno::NOENT) => Ok(()),
                _ => Err(RecoveryError::CgroupPresent),
            },
        )
    }

    /// The retained recovery directory is still a directory of the owner with
    /// mode `0700`.
    fn verify_directory(&self) -> Result<(), RecoveryError> {
        self.directory
            .metadata()
            .map_err(leaf_error)
            .and_then(|metadata| {
                require(
                    metadata.is_dir()
                        && metadata.uid() == self.owner
                        && metadata.mode() & 0o7777 == DIRECTORY_MODE,
                    RecoveryError::Leaf,
                )
            })
    }

    /// The leaf's identity when it is a socket of the owner with mode
    /// `0600`; `None` when it is absent.
    fn leaf_identity(&self, leaf: &OsString) -> Result<Option<LeafIdentity>, RecoveryError> {
        self.verify_directory().and_then(|()| {
            match statat(&*self.directory, Path::new(leaf), AtFlags::SYMLINK_NOFOLLOW) {
                Err(rustix::io::Errno::NOENT) => Ok(None),
                stat => stat
                    .map_err(leaf_error)
                    .and_then(|metadata| self.exact_socket(&metadata))
                    .map(Some),
            }
        })
    }

    /// The identity of a node that is a socket of the owner with mode `0600`.
    fn exact_socket(&self, metadata: &Stat) -> Result<LeafIdentity, RecoveryError> {
        require(
            FileType::from_raw_mode(metadata.st_mode) == FileType::Socket
                && metadata.st_uid == self.owner
                && metadata.st_mode & 0o7777 == LEAF_MODE,
            RecoveryError::Leaf,
        )
        .map(|()| LeafIdentity {
            device: metadata.st_dev,
            inode: metadata.st_ino,
        })
    }

    /// The leaf reached through the retained directory descriptor, never
    /// through a pathname that could resolve elsewhere.
    fn leaf_path(&self, leaf: &OsString) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.directory.as_raw_fd())).join(leaf)
    }

    /// R12 §6 step 8: the peer's leaf exists as the exact socket.
    pub(super) fn ready_leaf(&self, endpoint_id: [u8; 16]) -> Result<LeafIdentity, RecoveryError> {
        self.leaf_identity(&leaf_name(endpoint_id))
            .and_then(|identity| identity.ok_or(RecoveryError::Leaf))
    }

    /// R12 §6 step 9 and I8: the leaf still names the socket observed ready.
    pub(super) fn require_same_leaf(
        &self,
        endpoint_id: [u8; 16],
        ready: LeafIdentity,
    ) -> Result<(), RecoveryError> {
        self.ready_leaf(endpoint_id)
            .and_then(|current| require(current == ready, RecoveryError::Leaf))
    }

    /// R12 §6 step 5 (owner decision O3): the exact SIR1 leaf is absent, or
    /// it is removed by [`Self::remove_refusing_leaf`]. Any other node fails
    /// closed and is kept.
    pub(super) fn remove_stale_leaf(&self, endpoint_id: [u8; 16]) -> Result<(), RecoveryError> {
        let leaf = leaf_name(endpoint_id);
        self.leaf_identity(&leaf).and_then(|identity| {
            identity.map_or(Ok(()), |identity| {
                self.remove_refusing_leaf(&leaf, identity)
            })
        })
    }

    /// Remove the leaf probed as `identity`: its `connect()` must fail with
    /// `ECONNREFUSED` and its `(dev, ino)` be unchanged; it is then unlinked
    /// on the retained directory and proven absent. A leaf that is still
    /// there, for whatever reason, fails closed.
    pub(super) fn remove_refusing_leaf(
        &self,
        leaf: &OsString,
        identity: LeafIdentity,
    ) -> Result<(), RecoveryError> {
        crate::selector::runtime_lifecycle::require_refused(&self.leaf_path(leaf))
            .map_err(leaf_error)
            .and_then(|()| self.leaf_identity(leaf))
            .and_then(|current| require(current == Some(identity), RecoveryError::Leaf))
            .and_then(|()| {
                let _unlinked = unlinkat(&*self.directory, Path::new(leaf), AtFlags::empty());
                self.leaf_identity(leaf)
            })
            .and_then(|current| require(current.is_none(), RecoveryError::Leaf))
    }

    /// R12 §6 step 8: the observed main process is the one the kernel
    /// reports, in the observed control group, running the SIR1 binary.
    pub(super) fn verify_peer_process(
        &self,
        pid: NonZeroU64,
        start_time_ticks: u64,
        control_group: &CgroupPath,
        (binary_digest, binary_length): ([u8; 32], u64),
    ) -> Result<(), RecoveryError> {
        let same_process = || {
            crate::selector::runtime_lifecycle::process_start_time_ticks(pid)
                .map_err(peer_binding)
                .and_then(|ticks| require(ticks == start_time_ticks, RecoveryError::PeerBinding))
        };
        same_process()
            .and_then(|()| (self.control_group)(pid).map_err(peer_binding))
            .and_then(|cgroup| {
                require(cgroup == control_group.as_str(), RecoveryError::PeerBinding)
            })
            .and_then(|()| (self.executable_digest)(pid, binary_length).map_err(peer_binding))
            .and_then(|digest| require(digest == binary_digest, RecoveryError::PeerBinding))
            // The same process, not a recycled PID, owned the executable just hashed.
            .and_then(|()| same_process())
    }

    /// R12 §6 step 9: one connection to the peer's leaf, through the
    /// retained directory, whose `SO_PEERCRED` is the owner and the
    /// observed main process.
    pub(super) fn connect_peer(
        &self,
        endpoint_id: [u8; 16],
        pid: NonZeroU64,
    ) -> Result<UnixStream, RecoveryError> {
        connect_now(&self.leaf_path(&leaf_name(endpoint_id))).and_then(|stream| {
            peer_credentials(&stream)
                .and_then(|peer| {
                    require(
                        peer_matches(peer, self.owner, pid),
                        RecoveryError::PeerBinding,
                    )
                })
                .map(|()| stream)
        })
    }

    /// A stream whose every read and write ends by `deadline` on this host's
    /// clock.
    pub(super) const fn clocked<'a>(
        &'a self,
        stream: &'a UnixStream,
        deadline: Instant,
    ) -> ClockedStream<'a> {
        ClockedStream {
            stream,
            deadline,
            host: self,
        }
    }
}

/// One stream bounded by an absolute deadline on the selector's clock.
pub(super) struct ClockedStream<'a> {
    stream: &'a UnixStream,
    deadline: Instant,
    host: &'a RecoveryHost,
}

impl ClockedStream<'_> {
    /// The time left before the deadline, or a timeout once it has passed.
    fn remaining(&self) -> io::Result<Duration> {
        self.deadline
            .checked_duration_since(self.host.now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| io::Error::from(io::ErrorKind::TimedOut))
    }

    /// Whether the deadline has not passed yet.
    pub(super) fn within_deadline(&self) -> bool {
        self.remaining().is_ok()
    }
}

impl Read for ClockedStream<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.remaining()
            .and_then(|remaining| self.stream.set_read_timeout(Some(remaining)))
            .and_then(|()| {
                let mut stream = self.stream;
                stream.read(bytes)
            })
    }
}

impl Write for ClockedStream<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.remaining()
            .and_then(|remaining| self.stream.set_write_timeout(Some(remaining)))
            .and_then(|()| {
                let mut stream = self.stream;
                stream.write(bytes)
            })
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// One connection that completes at once: one that does not is refused,
/// since there is no retry. The stream is then blocking.
fn connect_now(path: &Path) -> Result<UnixStream, RecoveryError> {
    SocketAddrUnix::new(path)
        .map_err(exchange_error)
        .and_then(|address| {
            socket_with(
                AddressFamily::UNIX,
                SocketType::STREAM,
                SocketFlags::CLOEXEC.union(SocketFlags::NONBLOCK),
                None,
            )
            .map_err(exchange_error)
            .and_then(|socket| {
                connect(&socket, &address)
                    .map(|()| socket)
                    .map_err(exchange_error)
            })
        })
        .map(UnixStream::from)
        .and_then(|stream| {
            stream
                .set_nonblocking(false)
                .map(|()| stream)
                .map_err(exchange_error)
        })
}

/// The `SO_PEERCRED` UID and PID of `stream`'s peer.
fn peer_credentials(stream: &UnixStream) -> Result<(u32, u64), RecoveryError> {
    rustix::net::sockopt::socket_peercred(stream)
        .map(|peer| {
            (
                peer.uid.as_raw(),
                u64::try_from(peer.pid.as_raw_nonzero().get()).unwrap_or_default(),
            )
        })
        .map_err(peer_binding)
}

/// Whether the peer credentials `(uid, pid)` are the owner's process `pid`.
pub(super) const fn peer_matches((uid, peer_pid): (u32, u64), owner: u32, pid: NonZeroU64) -> bool {
    uid == owner && peer_pid == pid.get()
}

pub(super) fn leaf_error<T>(_: T) -> RecoveryError {
    RecoveryError::Leaf
}

pub(super) fn peer_binding<T>(_: T) -> RecoveryError {
    RecoveryError::PeerBinding
}

pub(super) fn exchange_error<T>(_: T) -> RecoveryError {
    RecoveryError::Exchange
}

/// `<32 lowercase hex endpoint ID>.sock`.
pub(super) fn leaf_name(endpoint_id: [u8; 16]) -> OsString {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut leaf = String::with_capacity(37);
    for byte in endpoint_id {
        leaf.push(char::from(HEX[usize::from(byte >> 4)]));
        leaf.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    leaf.push_str(".sock");
    OsString::from(leaf)
}

/// The start-time ticks (field 22) of one `/proc/<pid>/stat` record.
pub(super) fn stat_start_time_ticks(stat: &str) -> Result<u64, RecoveryError> {
    stat.rsplit_once(") ")
        .and_then(|(_, fields)| fields.split_ascii_whitespace().nth(19))
        .and_then(|ticks| ticks.parse().ok())
        .ok_or(RecoveryError::ProcessAlive)
}

/// Whether `mount` is a cgroup2 file system.
pub(super) fn is_cgroup2(mount: &File) -> bool {
    fstatfs(mount).is_ok_and(|filesystem| {
        u64::try_from(filesystem.f_type).is_ok_and(|kind| kind == CGROUP2_SUPER_MAGIC)
    })
}

use super::authority::require;
