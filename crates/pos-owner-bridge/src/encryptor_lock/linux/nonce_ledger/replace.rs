#![cfg(any(test, feature = "test-support"))]
//! E16 replacement in an already admitted test directory.

use std::fs::File;
use std::io::{self, Write as _};

use rustix::fd::OwnedFd;
use rustix::fs::{self, AtFlags, OFlags};

use super::super::{enforce, validate_file_identity};
use super::{
    open_locked_file, SubjectEncryptorLock, FILE_FLAGS, LEDGER_NAME, MAX_LEDGER_BYTES,
    TEMPORARY_NAME,
};
use crate::{BridgeError, UnavailableCode};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CommitStage {
    Created,
    Written,
    FileSynced,
    Renamed,
    DirectorySynced,
}

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
            .and_then(|()| StagedLedger::open(&self.directory))
            .map_err(io::Error::from)
            .and_then(|staged| staged.commit(bytes, after))
            .map_err(|_| BridgeError::Unavailable(UnavailableCode::InterfaceUnavailable))
    }
}

struct StagedLedger<'directory> {
    directory: &'directory OwnedFd,
    previous: OwnedFd,
    file: File,
}

impl<'directory> StagedLedger<'directory> {
    fn open(directory: &'directory OwnedFd) -> rustix::io::Result<Self> {
        open_locked_file(directory, LEDGER_NAME, FILE_FLAGS).and_then(|previous| {
            open_locked_file(
                directory,
                TEMPORARY_NAME,
                FILE_FLAGS.union(OFlags::CREATE).union(OFlags::EXCL),
            )
            .map(|file| Self {
                directory,
                previous,
                file: File::from(file),
            })
        })
    }

    fn commit(
        mut self,
        bytes: &[u8],
        mut after: impl FnMut(CommitStage) -> io::Result<()>,
    ) -> io::Result<()> {
        after(CommitStage::Created)
            .and_then(|()| self.file.write_all(bytes))
            .and_then(|()| after(CommitStage::Written))
            .and_then(|()| fs::fsync(&self.file).map_err(io::Error::from))
            .and_then(|()| after(CommitStage::FileSynced))
            .and_then(|()| {
                validate_file_identity(self.directory, TEMPORARY_NAME, &self.file)
                    .and_then(|()| {
                        validate_file_identity(self.directory, LEDGER_NAME, &self.previous)
                    })
                    .and_then(|()| {
                        fs::renameat(self.directory, TEMPORARY_NAME, self.directory, LEDGER_NAME)
                    })
                    .map_err(io::Error::from)
            })
            .and_then(|()| after(CommitStage::Renamed))
            .and_then(|()| fs::fsync(self.directory).map_err(io::Error::from))
            .and_then(|()| after(CommitStage::DirectorySynced))
    }
}

impl Drop for StagedLedger<'_> {
    fn drop(&mut self) {
        // A renamed or substituted slot must not be unlinked by this owner.
        drop(
            validate_file_identity(self.directory, TEMPORARY_NAME, &self.file)
                .and_then(|()| fs::unlinkat(self.directory, TEMPORARY_NAME, AtFlags::empty())),
        );
    }
}

#[cfg(test)]
mod tests;
