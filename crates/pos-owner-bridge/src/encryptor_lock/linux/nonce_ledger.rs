#![cfg(any(test, feature = "test-support"))]
//! Bounded ledger byte storage; no parsing, identity or reservation authority.

use std::io::{self, Read as _};

use rustix::fd::OwnedFd;
use rustix::fs::{self, AtFlags, Mode};

use super::{lock_file, open_locked_file, SubjectEncryptorLock, FILE_FLAGS};
use crate::{BridgeError, UnavailableCode};

const LEDGER_NAME: &str = "subject-nonce-ledger.v1";
const TEMPORARY_NAME: &str = "subject-nonce-ledger.v1.tmp";
const MAX_LEDGER_BYTES: usize = 1_048_576;

impl SubjectEncryptorLock {
    /// Read at most 1 MiB from the existing ledger in the held test directory.
    ///
    /// Opens relative to the directory descriptor retained at acquisition,
    /// without creating a missing file. The ledger receives the lock file's
    /// ownership, exact 0600 mode, single-link, no-symlink, nonblocking exclusive
    /// lock and post-lock path-identity checks. Its descriptor closes after the
    /// read; the process-lifetime encryptor lock remains held, even on failure.
    /// Retaining the directory anchors this read; it does not detect directory
    /// replacement or prevent a second lock inode in a recreated leaf.
    ///
    /// These are untrusted bytes. The caller must separately validate SNL1 and
    /// establish registry, root and store identity. This operation never writes,
    /// initializes or repairs state, cleans temporary files, or reserves a nonce.
    /// The remaining ADR-097/E15 owner and production activation gates apply.
    ///
    /// # Errors
    /// Returns `Unavailable(InterfaceUnavailable)` for a missing or unsafe file,
    /// contention, an oversized file, or any I/O failure. No partial bytes, path
    /// or underlying OS error escapes.
    pub fn read_nonce_ledger_bytes(&self) -> Result<Vec<u8>, BridgeError> {
        open_locked_file(&self.directory, LEDGER_NAME, FILE_FLAGS)
            .map_err(io::Error::from)
            .map(std::fs::File::from)
            .and_then(read_bounded)
            .map_err(|_| BridgeError::Unavailable(UnavailableCode::InterfaceUnavailable))
    }
}

fn read_bounded(reader: impl io::Read) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take((MAX_LEDGER_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .and_then(|_| {
            (bytes.len() <= MAX_LEDGER_BYTES)
                .then_some(bytes)
                .ok_or_else(|| io::ErrorKind::InvalidData.into())
        })
}

pub(super) fn remove_stale_temporary(directory: &OwnedFd) -> rustix::io::Result<()> {
    match fs::openat(directory, TEMPORARY_NAME, FILE_FLAGS, Mode::empty()) {
        Ok(file) => remove_opened_temporary(directory, &file),
        Err(error) if error == rustix::io::Errno::NOENT => Ok(()),
        Err(error) => Err(error),
    }
}

fn remove_opened_temporary(directory: &OwnedFd, file: &OwnedFd) -> rustix::io::Result<()> {
    lock_file(directory, TEMPORARY_NAME, file)
        .and_then(|()| fs::unlinkat(directory, TEMPORARY_NAME, AtFlags::empty()))
        .and_then(|()| fs::fsync(directory))
}

mod replace;

#[cfg(test)]
mod tests {
    use super::*;

    struct FaultyReader;

    impl io::Read for FaultyReader {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::ErrorKind::Other.into())
        }
    }

    #[test]
    fn read_failure_propagates_without_returning_partial_bytes() {
        assert_eq!(
            read_bounded(io::Cursor::new(b"partial bytes").chain(FaultyReader))
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::Other)
        );
    }
}
