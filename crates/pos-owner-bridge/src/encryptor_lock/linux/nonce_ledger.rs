#![cfg(any(test, feature = "test-support"))]
//! Bounded transport of existing ledger bytes; no parsing or identity authority.

use std::io::{self, Read as _};

use super::{open_locked_file, SubjectEncryptorLock, FILE_FLAGS};
use crate::{BridgeError, UnavailableCode};

const LEDGER_NAME: &str = "subject-nonce-ledger.v1";
const MAX_LEDGER_BYTES: usize = 1_048_576;

impl SubjectEncryptorLock {
    /// Read at most 1 MiB from the existing ledger in the held test directory.
    ///
    /// Opens relative to the directory descriptor retained at acquisition,
    /// without creating a missing file. The ledger receives the lock file's
    /// ownership, exact 0600 mode, single-link, no-symlink, nonblocking exclusive
    /// lock and post-lock path-identity checks. Its descriptor closes after the
    /// read; the process-lifetime encryptor lock remains held, even on failure.
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
