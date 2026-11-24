//! Held provider directories, reached only through descriptors the caller
//! already holds and never reopened by path.
//!
//! The provider's restart sweeps (ADR-069 R11 §5.3 and Amendment 1 §5.4)
//! list their directories through those descriptors, and the capture store
//! root is opened or created beneath the held artifact root.

use std::ffi::CString;
use std::fs::File;
use std::io;

use rustix::fs::{fchmod, mkdirat, openat2, Dir, Mode, OFlags, ResolveFlags};
use rustix::io::Errno;

/// The mode of a directory this module creates.
const PRIVATE_MODE: Mode = Mode::RWXU;

/// The names in the held `directory`, without `.` and `..`, in directory
/// order.
///
/// # Errors
/// Returns the I/O error when the descriptor is no directory or an entry
/// cannot be read.
pub fn entry_names(directory: &File) -> io::Result<Vec<CString>> {
    Dir::read_from(directory)
        .and_then(|entries| {
            entries
                .map(|entry| entry.map(|entry| entry.file_name().to_owned()))
                .collect::<Result<Vec<_>, _>>()
        })
        .map(|names| {
            names
                .into_iter()
                .filter(|name| name.to_bytes() != b"." && name.to_bytes() != b"..")
                .collect()
        })
        .map_err(io::Error::from)
}

/// Open the directory `name` beneath the held `parent`, creating it with
/// mode `0700` when absent.
///
/// It is resolved beneath `parent` without crossing a symlink, a magic link
/// or a mount, and opened with `O_NOFOLLOW`. A created directory is then set
/// to exactly `0700`, since the umask may have stripped bits. An existing one
/// is returned as it is: its owner and mode are the caller's to check.
///
/// # Errors
/// Returns the I/O error when it cannot be opened or created, including
/// through a link, a mount crossing or a non-directory.
pub fn open_or_create_beneath(parent: &File, name: &str) -> io::Result<File> {
    let open = || {
        openat2(
            parent,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            ResolveFlags::BENEATH
                | ResolveFlags::NO_SYMLINKS
                | ResolveFlags::NO_MAGICLINKS
                | ResolveFlags::NO_XDEV,
        )
        .map(File::from)
    };
    open()
        .or_else(|error| {
            if error == Errno::NOENT {
                mkdirat(parent, name, PRIVATE_MODE)
                    .and_then(|()| open())
                    .and_then(|created| fchmod(&created, PRIVATE_MODE).map(|()| created))
            } else {
                Err(error)
            }
        })
        .map_err(io::Error::from)
}
