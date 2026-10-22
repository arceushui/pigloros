//! Opening, checking and identifying the held adapter and launcher images.

use std::{
    fs::File,
    io,
    os::{fd::AsFd, unix::fs::FileExt},
};

use pos_reference::sandbox_provider_protocol::{blake3_digest_of, FdIdentity};
use rustix::fs::{openat2, statx, AtFlags, Mode, OFlags, ResolveFlags, StatxFlags};

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
pub(super) fn open_beneath(root: impl AsFd, path: &str) -> io::Result<File> {
    openat2(
        root,
        path.trim_start_matches('/'),
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map(File::from)
    .map_err(io::Error::from)
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
    let identity = statx(&file, "", AtFlags::EMPTY_PATH, MOUNT_ID_REQUEST)
        .ok()
        .filter(|stat| stat.stx_mask & StatxFlags::MNT_ID.bits() != 0 && stat.stx_ino != 0)
        .map(|stat| FdIdentity {
            mount_id: stat.stx_mnt_id,
            inode: stat.stx_ino,
        })
        .ok_or(LauncherError::Identity)?;
    Ok(HeldExecutable {
        file,
        digest,
        identity,
    })
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
