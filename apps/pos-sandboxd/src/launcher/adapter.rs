//! Opening, checking and identifying the held adapter and launcher images.

use std::{
    fs::File,
    io,
    os::{
        fd::{AsFd, BorrowedFd, OwnedFd},
        unix::fs::FileExt,
    },
};

use pos_reference::sandbox_provider_protocol::{blake3_digest_of, FdIdentity};
use rustix::fs::{openat, statx, AtFlags, Mode, OFlags, StatxFlags};

use super::error::LauncherError;

/// The ELF header bytes needed to classify an executable.
pub(super) const ELF_HEADER_BYTES: usize = 20;
const ELF_MAGIC: &[u8; 4] = b"\x7fELF";
const ELF_CLASS_64: u8 = 2;
const ELF_LITTLE_ENDIAN: u8 = 1;
const ELF_TYPE_EXECUTABLE: u16 = 2;
const ELF_TYPE_DYNAMIC: u16 = 3;
pub(super) const NATIVE_MACHINE: u16 = if cfg!(target_arch = "x86_64") {
    62
} else if cfg!(target_arch = "aarch64") {
    183
} else {
    0
};
// `NONBLOCK` keeps a FIFO or device node from stalling the open; it is inert
// for the regular file that passes the check and the descriptor is closed on exec.
const FILE_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::CLOEXEC)
    .union(OFlags::NONBLOCK)
    .union(OFlags::NOFOLLOW);
const DIRECTORY_FLAGS: OFlags = OFlags::PATH
    .union(OFlags::DIRECTORY)
    .union(OFlags::CLOEXEC)
    .union(OFlags::NOFOLLOW);
const MOUNT_ID_REQUEST: StatxFlags = StatxFlags::BASIC_STATS.union(StatxFlags::MNT_ID);

/// An executable held open, with the digest and identity `ReadyV1` binds.
#[derive(Debug)]
pub(super) struct HeldExecutable {
    pub(super) file: File,
    pub(super) digest: [u8; 32],
    pub(super) identity: FdIdentity,
}

/// Open `path` beneath `root` read-only without following any symlink or
/// magic link and without leaving `root`.
///
/// Every component is opened on its own, relative to the one before, with `O_NOFOLLOW` (a symlink,
/// magic links included, is refused), and `.` and `..` are refused, so the walk cannot leave
/// `root`. `openat2` would do this in one call, but the attempt unit's `RestrictSUIDSGID=yes`
/// makes systemd's seccomp filter answer `openat2` with `ENOSYS`, so the launcher cannot use it.
pub(super) fn open_beneath(root: impl AsFd, path: &str) -> io::Result<File> {
    plain_names(path).and_then(|names| walk(root.as_fd(), &names))
}

/// The names of `path`, if it is a plain relative walk: leading and doubled separators collapse,
/// as in the kernel; a trailing one names a directory and is refused (`openat2` answers it with
/// `ENOTDIR`), and so are `.` and `..`; an empty path has no file to open (see `walk`).
fn plain_names(path: &str) -> io::Result<Vec<&str>> {
    let path = path.trim_start_matches('/');
    let names: Vec<&str> = path.split('/').filter(|name| !name.is_empty()).collect();
    if path.ends_with('/') || names.iter().any(|name| matches!(*name, "." | "..")) {
        Err(io::ErrorKind::InvalidInput.into())
    } else {
        Ok(names)
    }
}

/// Open each parent directory relative to the one before, then the file in the last of them.
fn walk(root: BorrowedFd<'_>, names: &[&str]) -> io::Result<File> {
    let (last, parents) = names.split_last().ok_or(io::ErrorKind::InvalidInput)?;
    let held = parents
        .iter()
        .try_fold(None, |held: Option<OwnedFd>, name| {
            open_in(held.as_ref(), root, name, DIRECTORY_FLAGS).map(Some)
        })?;
    open_in(held.as_ref(), root, last, FILE_FLAGS).map(File::from)
}

/// Open `name` in the directory `held`, or in `root` before any directory is held.
fn open_in(
    held: Option<&OwnedFd>,
    root: BorrowedFd<'_>,
    name: &str,
    flags: OFlags,
) -> io::Result<OwnedFd> {
    openat(held.map_or(root, AsFd::as_fd), name, flags, Mode::empty()).map_err(io::Error::from)
}

/// Hold the adapter: a regular native ELF for this architecture.
///
/// Shebang scripts and every other format are rejected here, before
/// `ReadyV1`. A `PT_INTERP` is allowed by the ADR and covered by the admitted
/// image digest.
pub(super) fn hold_adapter(file: File) -> Result<HeldExecutable, LauncherError> {
    let is_regular = file
        .metadata()
        .is_ok_and(|metadata| std::fs::Metadata::is_file(&metadata));
    let mut header = [0_u8; ELF_HEADER_BYTES];
    if !is_regular || file.read_exact_at(&mut header, 0).is_err() || !native_elf(&header) {
        return Err(LauncherError::Adapter);
    }
    hold(file)
}

/// Hold the launcher's own executable image.
pub(super) fn hold(file: File) -> Result<HeldExecutable, LauncherError> {
    let digest = blake3_digest_of(&file).map_err(|_| LauncherError::Identity)?;
    statx(&file, "", AtFlags::EMPTY_PATH, MOUNT_ID_REQUEST)
        .ok()
        .filter(|stat| StatxFlags::from_bits_retain(stat.stx_mask).contains(StatxFlags::MNT_ID))
        .map(|stat| HeldExecutable {
            file,
            digest,
            identity: FdIdentity {
                mount_id: stat.stx_mnt_id,
                inode: stat.stx_ino,
            },
        })
        .ok_or(LauncherError::Identity)
}

fn native_elf(header: &[u8; ELF_HEADER_BYTES]) -> bool {
    let kind = u16::from_le_bytes([header[16], header[17]]);
    let machine = u16::from_le_bytes([header[18], header[19]]);
    header[..4] == ELF_MAGIC[..]
        && header[4] == ELF_CLASS_64
        && header[5] == ELF_LITTLE_ENDIAN
        && (kind == ELF_TYPE_EXECUTABLE || kind == ELF_TYPE_DYNAMIC)
        && machine == NATIVE_MACHINE
}
