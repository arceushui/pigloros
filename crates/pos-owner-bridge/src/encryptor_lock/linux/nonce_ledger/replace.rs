#![cfg(any(test, feature = "test-support"))]
//! E16 replacement in an already admitted test directory.

use std::io;

use super::super::commit::{CommitStage, StagedFile};
use super::super::enforce;
use super::{SubjectEncryptorLock, LEDGER_NAME, MAX_LEDGER_BYTES, TEMPORARY_NAME};
use crate::{BridgeError, UnavailableCode};

impl SubjectEncryptorLock {
    /// Durably replace the existing ledger's bytes in the held test directory.
    ///
    /// The caller must supply canonical SNL1 and separately establish registry,
    /// root and store identity. This is bounded byte storage, not validation,
    /// initialization or nonce reservation. A missing ledger is never created.
    ///
    /// Both the old file and the exclusive temporary file receive the strict
    /// E16 file checks and nonblocking locks. The temporary is written and
    /// synchronized, both names are rechecked, then rename and directory sync
    /// complete the replacement. Success is returned only after directory sync.
    /// The global guard remains held on failure. Directory anchoring does not
    /// prevent replacement of the directory or prove global exclusivity.
    ///
    /// # Errors
    /// Returns `Unavailable(InterfaceUnavailable)` on input above 1 MiB, missing
    /// or unsafe state, contention, or any I/O failure. An error may follow
    /// rename: the outcome is unconfirmed. Keep the guard for recovery, never
    /// restore stale counters or use a candidate nonce on this error alone.
    pub fn replace_nonce_ledger_bytes(&self, bytes: &[u8]) -> Result<(), BridgeError> {
        self.replace_observing(bytes, |_| Ok(()))
    }

    fn replace_observing(
        &self,
        bytes: &[u8],
        after: impl FnMut(CommitStage) -> io::Result<()>,
    ) -> Result<(), BridgeError> {
        enforce(bytes.len() <= MAX_LEDGER_BYTES)
            .and_then(|()| StagedFile::open(&self.directory, LEDGER_NAME, TEMPORARY_NAME, true))
            .map_err(io::Error::from)
            .and_then(|staged| staged.commit(bytes, after))
            .map_err(|_| BridgeError::Unavailable(UnavailableCode::InterfaceUnavailable))
    }
}

#[cfg(test)]
mod tests;
