//! Fail-closed bounded input primitives shared by the evaluator command and package verification.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

/// An input artifact is not a regular file or cannot be read within its bound.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("an input artifact cannot be read within its bound")]
pub struct BoundedInputError;

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
    let file = options.open(path).map_err(|_| BoundedInputError)?;
    if file.metadata().map_err(|_| BoundedInputError)?.is_file() {
        Ok(file)
    } else {
        Err(BoundedInputError)
    }
}

/// Copy a regular file into private immutable storage, refusing more than `maximum` bytes.
///
/// # Errors
/// Returns [`BoundedInputError`] when the path is not a regular file, cannot be copied,
/// or exceeds the bound.
pub fn snapshot_bounded(path: &Path, maximum: u64) -> Result<File, BoundedInputError> {
    let source = open_regular_file(path)?;
    let mut snapshot = tempfile::tempfile().map_err(|_| BoundedInputError)?;
    let copied = io::copy(&mut source.take(maximum.saturating_add(1)), &mut snapshot)
        .map_err(|_| BoundedInputError)?;
    if copied > maximum {
        return Err(BoundedInputError);
    }
    snapshot.seek(SeekFrom::Start(0)).map_err(|_| BoundedInputError)?;
    Ok(snapshot)
}

/// Read a regular file completely, refusing more than `maximum` bytes.
///
/// # Errors
/// Returns [`BoundedInputError`] when the path is not a regular file, cannot be read,
/// or exceeds the bound.
pub fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>, BoundedInputError> {
    read_to_bound(open_regular_file(path)?, maximum)
}

/// Read an already validated file from its start, refusing more than `maximum` bytes.
///
/// # Errors
/// Returns [`BoundedInputError`] when the file cannot be rewound or read, or exceeds the
/// bound.
pub fn read_bounded_file(file: &mut File, maximum: u64) -> Result<Vec<u8>, BoundedInputError> {
    file.seek(SeekFrom::Start(0)).map_err(|_| BoundedInputError)?;
    read_to_bound(file, maximum)
}

fn read_to_bound(reader: impl Read, maximum: u64) -> Result<Vec<u8>, BoundedInputError> {
    let mut bytes = Vec::new();
    reader
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| BoundedInputError)?;
    if bytes.len() as u64 > maximum {
        Err(BoundedInputError)
    } else {
        Ok(bytes)
    }
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
