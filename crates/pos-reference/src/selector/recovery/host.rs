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
use std::os::unix::fs::MetadataExt as _;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustix::fs::{
    fstatfs, openat2, statat, unlinkat, AtFlags, FileType, Mode, OFlags, ResolveFlags,
};
use rustix::net::{connect, socket_with, AddressFamily, SocketAddrUnix, SocketFlags, SocketType};

use super::RecoveryError;
use crate::selector::runtime_lifecycle::CgroupPath;

/// The fixed recovery endpoint directory (ADR-069 §4.1, R12 §7.2).
pub(super) const RECOVERY_DIRECTORY: &str = "/run/pigloros/sandbox-selector-recovery";
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

/// The selector's clock. Production reads [`Instant::now`]; tests inject one
/// so that every bound is asserted against it, not wall time (R12 I10).
pub(crate) type RecoveryClock = Arc<dyn Fn() -> Instant + Send + Sync>;

/// The kernel and filesystem view one recovery operation checks against.
pub(crate) struct RecoveryHost {
    directory: Arc<File>,
    directory_path: PathBuf,
    owner: u32,
    cgroup_mount: PathBuf,
    cgroup2: fn(&File) -> bool,
    executable_digest: ExecutableDigest,
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
    /// `executable_digest`, and the monotonic clock.
    pub(crate) fn fixed(directory: Arc<File>, executable_digest: ExecutableDigest) -> Self {
        Self {
            directory,
            directory_path: PathBuf::from(RECOVERY_DIRECTORY),
            owner: 0,
            cgroup_mount: PathBuf::from(CGROUP_MOUNT),
            cgroup2: is_cgroup2,
            executable_digest,
            clock: Arc::new(Instant::now),
        }
    }

    /// A view over a test directory, owner, cgroup mount and clock.
    #[cfg(test)]
    pub(crate) fn for_test(
        (directory, directory_path): (Arc<File>, PathBuf),
        owner: u32,
        (cgroup_mount, cgroup2): (PathBuf, fn(&File) -> bool),
        executable_digest: ExecutableDigest,
        clock: RecoveryClock,
    ) -> Self {
        Self {
            directory,
            directory_path,
            owner,
            cgroup_mount,
            cgroup2,
            executable_digest,
            clock,
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
            .map_err(|_| RecoveryError::Leaf)
            .and_then(|metadata| {
                if metadata.is_dir()
                    && metadata.uid() == self.owner
                    && metadata.mode() & 0o7777 == DIRECTORY_MODE
                {
                    Ok(())
                } else {
                    Err(RecoveryError::Leaf)
                }
            })
    }

    /// The leaf's identity when it is a socket of the owner with mode
    /// `0600`; `None` when it is absent.
    fn leaf_identity(&self, leaf: &OsString) -> Result<Option<LeafIdentity>, RecoveryError> {
        self.verify_directory().and_then(|()| {
            match statat(&*self.directory, Path::new(leaf), AtFlags::SYMLINK_NOFOLLOW) {
                Err(rustix::io::Errno::NOENT) => Ok(None),
                Err(_) => Err(RecoveryError::Leaf),
                Ok(metadata) => {
                    if FileType::from_raw_mode(metadata.st_mode) == FileType::Socket
                        && metadata.st_uid == self.owner
                        && metadata.st_mode & 0o7777 == LEAF_MODE
                    {
                        Ok(Some(LeafIdentity {
                            device: metadata.st_dev,
                            inode: metadata.st_ino,
                        }))
                    } else {
                        Err(RecoveryError::Leaf)
                    }
                }
            }
        })
    }

    /// R12 §6 step 8: the peer's leaf exists as the exact socket.
    pub(super) fn ready_leaf(&self, endpoint_id: [u8; 16]) -> Result<LeafIdentity, RecoveryError> {
        self.leaf_identity(&leaf_name(endpoint_id))
            .and_then(|identity| identity.ok_or(RecoveryError::Leaf))
    }

    /// R12 §6 steps 9: the leaf still names the socket observed ready.
    pub(super) fn require_same_leaf(
        &self,
        endpoint_id: [u8; 16],
        ready: LeafIdentity,
    ) -> Result<(), RecoveryError> {
        self.ready_leaf(endpoint_id).and_then(|current| {
            if current == ready {
                Ok(())
            } else {
                Err(RecoveryError::Leaf)
            }
        })
    }

    /// R12 §6 step 5 (owner decision O3): the exact SIR1 leaf is absent, or
    /// is a socket of the owner with mode `0600` whose `connect()` fails with
    /// `ECONNREFUSED`; it is then unlinked on the retained directory, after
    /// its `(dev, ino)` is rechecked, and proven absent. Any other node or
    /// outcome fails closed and is kept.
    pub(super) fn remove_stale_leaf(&self, endpoint_id: [u8; 16]) -> Result<(), RecoveryError> {
        let leaf = leaf_name(endpoint_id);
        self.leaf_identity(&leaf).and_then(|identity| {
            identity.map_or(Ok(()), |identity| {
                crate::selector::runtime_lifecycle::require_refused(
                    &self.directory_path.join(&leaf),
                )
                .map_err(|_| RecoveryError::Leaf)
                .and_then(|()| self.leaf_identity(&leaf))
                .and_then(|current| {
                    if current == Some(identity) {
                        unlinkat(&*self.directory, Path::new(&leaf), AtFlags::empty())
                            .map_err(|_| RecoveryError::Leaf)
                    } else {
                        Err(RecoveryError::Leaf)
                    }
                })
                .and_then(|()| match self.leaf_identity(&leaf) {
                    Ok(None) => Ok(()),
                    _ => Err(RecoveryError::Leaf),
                })
            })
        })
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
                .map_err(|_| RecoveryError::PeerBinding)
                .and_then(|ticks| require(ticks == start_time_ticks, RecoveryError::PeerBinding))
        };
        same_process()
            .and_then(|()| {
                crate::selector::runtime_lifecycle::process_control_group(pid)
                    .map_err(|_| RecoveryError::PeerBinding)
            })
            .and_then(|cgroup| {
                require(cgroup == control_group.as_str(), RecoveryError::PeerBinding)
            })
            .and_then(|()| {
                (self.executable_digest)(pid, binary_length).map_err(|_| RecoveryError::PeerBinding)
            })
            .and_then(|digest| require(digest == binary_digest, RecoveryError::PeerBinding))
            // The same process, not a recycled PID, owned the executable just hashed.
            .and_then(|()| same_process())
    }

    /// R12 §6 step 9: one connection to the peer's leaf, whose
    /// `SO_PEERCRED` is the owner and the observed main process. A
    /// connection that does not complete at once is refused: there is no
    /// retry.
    pub(super) fn connect_peer(
        &self,
        endpoint_id: [u8; 16],
        pid: NonZeroU64,
    ) -> Result<UnixStream, RecoveryError> {
        SocketAddrUnix::new(self.directory_path.join(leaf_name(endpoint_id)))
            .map_err(|_| RecoveryError::Exchange)
            .and_then(|address| {
                socket_with(
                    AddressFamily::UNIX,
                    SocketType::STREAM,
                    SocketFlags::CLOEXEC.union(SocketFlags::NONBLOCK),
                    None,
                )
                .map_err(|_| RecoveryError::Exchange)
                .and_then(|socket| {
                    connect(&socket, &address)
                        .map_err(|_| RecoveryError::Exchange)
                        .map(|()| UnixStream::from(socket))
                })
            })
            .and_then(|stream| {
                stream
                    .set_nonblocking(false)
                    .map_err(|_| RecoveryError::Exchange)
                    .map(|()| stream)
            })
            .and_then(|stream| {
                rustix::net::sockopt::socket_peercred(&stream)
                    .map_err(|_| RecoveryError::PeerBinding)
                    .and_then(|peer| {
                        require(
                            peer.uid.as_raw() == self.owner
                                && u64::try_from(peer.pid.as_raw_nonzero().get())
                                    .is_ok_and(|peer_pid| peer_pid == pid.get()),
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

/// `<32 lowercase hex endpoint ID>.sock`.
fn leaf_name(endpoint_id: [u8; 16]) -> OsString {
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

const fn require(condition: bool, error: RecoveryError) -> Result<(), RecoveryError> {
    if condition {
        Ok(())
    } else {
        Err(error)
    }
}
