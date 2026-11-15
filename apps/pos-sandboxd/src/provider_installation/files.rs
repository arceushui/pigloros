//! The file rules of SPI1 (rule 1) and of its key file (rule 10).
//!
//! Every open is `openat2` beneath a held directory with
//! `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`, and every
//! check is made on the opened descriptor, never on a path.

use std::fs::File;
use std::os::unix::fs::{FileExt, MetadataExt};

use rustix::fs::{openat2, Mode, OFlags, ResolveFlags};
use zeroize::Zeroizing;

use super::ProviderInstallationError;

/// The path from `/` to the SIC1 artifact root, one component at a time.
const ARTIFACT_ROOT: [&str; 4] = ["var", "lib", "pigloros", "sandbox"];
/// The SPI1 file, beneath the artifact root.
const INSTALLATION_NAME: &str = "provider-installation.cbor";
/// The key directory, beneath the artifact root.
const KEYS_NAME: &str = "provider-keys";
/// The longest SPI1 file.
const INSTALLATION_LIMIT: usize = 4096;
/// The length of a raw Ed25519 seed.
const SEED_BYTES: usize = 32;

const RESOLVE: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_MAGICLINKS);
const DIRECTORY_OPEN: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::CLOEXEC);
// Non-blocking, so a FIFO cannot stall the open before the regular-file
// check.
const KEY_OPEN: OFlags = OFlags::RDONLY
    .union(OFlags::CLOEXEC)
    .union(OFlags::NONBLOCK);
const INSTALLATION_OPEN: OFlags = KEY_OPEN.union(OFlags::NOFOLLOW);

/// Open `/var/lib/pigloros/sandbox` from `/`: every directory on the way is
/// root-owned and writable by neither group nor other.
pub(super) fn open_artifact_root() -> Result<File, ProviderInstallationError> {
    rustix::fs::open("/", DIRECTORY_OPEN, Mode::empty())
        .ok()
        .map(File::from)
        .ok_or(ProviderInstallationError::UnsafeFile)
        .and_then(|filesystem_root| shared_directory(&filesystem_root, 0).map(|()| filesystem_root))
        .and_then(|filesystem_root| {
            ARTIFACT_ROOT
                .into_iter()
                .try_fold(filesystem_root, |parent, name| {
                    open_directory(&parent, name, ProviderInstallationError::UnsafeFile)
                        .and_then(|directory| shared_directory(&directory, 0).map(|()| directory))
                })
        })
}

/// Read the SPI1 file beneath the held artifact `root` once: a singly linked
/// regular file of mode `0400` that `owner` owns, `1..=4096` bytes long,
/// read through its descriptor to exactly its `fstat` length.
pub(super) fn read_installation(
    root: &File,
    owner: u32,
) -> Result<Vec<u8>, ProviderInstallationError> {
    shared_directory(root, owner)?;
    let file = open_file(root, INSTALLATION_NAME, INSTALLATION_OPEN)
        .ok_or(ProviderInstallationError::UnsafeFile)?;
    let length = file
        .metadata()
        .ok()
        .filter(|metadata| {
            metadata.is_file()
                && metadata.uid() == owner
                && metadata.nlink() == 1
                && metadata.mode() & 0o7777 == 0o400
                && (1..=INSTALLATION_LIMIT as u64).contains(&metadata.len())
        })
        .map(|metadata| metadata.len())
        .ok_or(ProviderInstallationError::UnsafeFile)?;
    read_exactly(&file, length).ok_or(ProviderInstallationError::UnsafeFile)
}

/// Read the 32-byte seed of `name` in `provider-keys/` beneath the held
/// artifact `root`. The directory is a `0700` directory and the file a
/// singly linked regular file of mode `0400` or `0600`, both owned by
/// `owner`.
pub(super) fn read_runtime_key(
    root: &File,
    name: &str,
    owner: u32,
) -> Result<Zeroizing<[u8; SEED_BYTES]>, ProviderInstallationError> {
    let directory = open_directory(
        root,
        KEYS_NAME,
        ProviderInstallationError::UnsafeKeyDirectory,
    )
    .and_then(|directory| {
        directory
            .metadata()
            .ok()
            .filter(|metadata| {
                metadata.is_dir() && metadata.uid() == owner && metadata.mode() & 0o7777 == 0o700
            })
            .map(|_| directory)
            .ok_or(ProviderInstallationError::UnsafeKeyDirectory)
    })?;
    let file = open_file(&directory, name, KEY_OPEN)
        .filter(|file| {
            file.metadata().is_ok_and(|metadata| {
                metadata.is_file()
                    && metadata.uid() == owner
                    && metadata.nlink() == 1
                    && matches!(metadata.mode() & 0o7777, 0o400 | 0o600)
                    && metadata.len() == SEED_BYTES as u64
            })
        })
        .ok_or(ProviderInstallationError::UnsafeKeyFile)?;
    let mut seed = Zeroizing::new([0; SEED_BYTES]);
    file.read_exact_at(seed.as_mut_slice(), 0)
        .ok()
        .map(|()| seed)
        .ok_or(ProviderInstallationError::UnsafeKeyFile)
}

/// Open the directory `name` beneath `parent`, or fail with `error`.
fn open_directory(
    parent: &File,
    name: &str,
    error: ProviderInstallationError,
) -> Result<File, ProviderInstallationError> {
    openat2(parent, name, DIRECTORY_OPEN, Mode::empty(), RESOLVE)
        .map(File::from)
        .map_err(|_| error)
}

/// Require `directory` to be a directory that `owner` owns and that no group
/// or other may write.
fn shared_directory(directory: &File, owner: u32) -> Result<(), ProviderInstallationError> {
    directory
        .metadata()
        .ok()
        .filter(|metadata| {
            metadata.is_dir() && metadata.uid() == owner && metadata.mode() & 0o022 == 0
        })
        .map(|_| ())
        .ok_or(ProviderInstallationError::UnsafeFile)
}

/// Open the entry `name` beneath `directory` with `flags`.
fn open_file(directory: &File, name: &str, flags: OFlags) -> Option<File> {
    openat2(directory, name, flags, Mode::empty(), RESOLVE)
        .map(File::from)
        .ok()
}

/// Read `file` from offset zero: exactly `length` bytes, and nothing after
/// them. A failed read ends the read, so it can only refuse the file.
fn read_exactly(file: &File, length: u64) -> Option<Vec<u8>> {
    // One byte more than the limit shows a file that grew after `fstat`.
    let mut bytes = vec![0; INSTALLATION_LIMIT + 1];
    let mut filled = 0;
    loop {
        let read = file
            .read_at(&mut bytes[filled..], filled as u64)
            .unwrap_or(0);
        if read == 0 {
            break;
        }
        filled += read;
    }
    bytes.truncate(filled);
    (filled as u64 == length).then_some(bytes)
}
