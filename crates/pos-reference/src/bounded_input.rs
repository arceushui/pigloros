//! Fail-closed bounded input primitives shared by the evaluator command and package verification.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

/// An input artifact is not a regular file or cannot be read within its bound.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("an input artifact cannot be read within its bound")]
pub struct BoundedInputError;

impl From<io::Error> for BoundedInputError {
    fn from(_: io::Error) -> Self {
        Self
    }
}

/// Open a path read-only without following links or blocking, and require a regular file.
///
/// # Errors
/// Returns [`BoundedInputError`] when the path cannot be opened, is a link, or does not
/// name a regular file.
pub fn open_regular_file(path: &Path) -> Result<File, BoundedInputError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);
    }
    options
        .open(path)
        .map_err(BoundedInputError::from)
        .and_then(|file| {
            file.metadata()
                .is_ok_and(|metadata| metadata.is_file())
                .then_some(file)
                .ok_or(BoundedInputError)
        })
}

/// Copy a regular file into private immutable storage, refusing more than `maximum` bytes.
///
/// # Errors
/// Returns [`BoundedInputError`] when the path is not a regular file, cannot be copied,
/// or exceeds the bound.
pub fn snapshot_bounded(path: &Path, maximum: u64) -> Result<File, BoundedInputError> {
    open_regular_file(path).and_then(|source| {
        tempfile::tempfile()
            .and_then(|mut snapshot| {
                io::copy(&mut source.take(maximum.saturating_add(1)), &mut snapshot).and_then(
                    |copied| {
                        snapshot
                            .seek(SeekFrom::Start(0))
                            .map(|_| (snapshot, copied))
                    },
                )
            })
            .map_err(BoundedInputError::from)
            .and_then(|(snapshot, copied)| {
                (copied <= maximum)
                    .then_some(snapshot)
                    .ok_or(BoundedInputError)
            })
    })
}

/// Read a regular file completely, refusing more than `maximum` bytes.
///
/// # Errors
/// Returns [`BoundedInputError`] when the path is not a regular file, cannot be read,
/// or exceeds the bound.
pub fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>, BoundedInputError> {
    open_regular_file(path).and_then(|file| read_to_bound(file, maximum))
}

/// Read an already validated file from its start, refusing more than `maximum` bytes.
///
/// # Errors
/// Returns [`BoundedInputError`] when the file cannot be rewound or read, or exceeds the
/// bound.
pub fn read_bounded_file(file: &mut File, maximum: u64) -> Result<Vec<u8>, BoundedInputError> {
    file.seek(SeekFrom::Start(0))
        .map_err(BoundedInputError::from)
        .and_then(|_| read_to_bound(file, maximum))
}

fn read_to_bound(reader: impl Read, maximum: u64) -> Result<Vec<u8>, BoundedInputError> {
    let mut bytes = Vec::new();
    reader
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(BoundedInputError::from)
        .and_then(|_| {
            (bytes.len() as u64 <= maximum)
                .then_some(bytes)
                .ok_or(BoundedInputError)
        })
}

/// Parse exactly 64 lowercase hexadecimal digits into a digest that is not all zero.
#[must_use]
pub fn parse_nonzero_digest(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut digest = [0_u8; 32];
    for (target, pair) in digest.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        *target = hexadecimal_nibble(pair[0])? << 4 | hexadecimal_nibble(pair[1])?;
    }
    (digest != [0; 32]).then_some(digest)
}

const fn hexadecimal_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}
