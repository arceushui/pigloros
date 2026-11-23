#![cfg(any(test, feature = "test-support"))]
//! The E16 temporary-file commit shared by the ledger and subject-key artifacts.

use std::fs::File;
use std::io::{self, Write as _};

use rustix::fd::OwnedFd;
use rustix::fs::{self, AtFlags, OFlags, RenameFlags};

use super::{open_locked_file, validate_file_identity, FILE_FLAGS};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CommitStage {
    Created,
    Written,
    FileSynced,
    Renamed,
    DirectorySynced,
}

/// An exclusively created, locked temporary file awaiting its commit.
///
/// When replacing, the existing target is opened and locked first and its
/// path identity is rechecked before the rename. When creating, the rename
/// refuses any existing target entry. Dropping an uncommitted value unlinks
/// the temporary name only while it still names this owner's inode.
pub(super) struct StagedFile<'a> {
    directory: &'a OwnedFd,
    target: &'a str,
    temporary: &'a str,
    previous: Option<OwnedFd>,
    pub(super) file: File,
}

impl<'a> StagedFile<'a> {
    pub(super) fn open(
        directory: &'a OwnedFd,
        target: &'a str,
        temporary: &'a str,
        replace_existing: bool,
    ) -> rustix::io::Result<Self> {
        replace_existing
            .then(|| open_locked_file(directory, target, FILE_FLAGS))
            .transpose()
            .and_then(|previous| {
                open_locked_file(
                    directory,
                    temporary,
                    FILE_FLAGS.union(OFlags::CREATE).union(OFlags::EXCL),
                )
                .map(|file| Self {
                    directory,
                    target,
                    temporary,
                    previous,
                    file: File::from(file),
                })
            })
    }

    pub(super) fn commit(
        mut self,
        bytes: &[u8],
        mut after: impl FnMut(CommitStage) -> io::Result<()>,
    ) -> io::Result<()> {
        after(CommitStage::Created)
            .and_then(|()| self.file.write_all(bytes))
            .and_then(|()| after(CommitStage::Written))
            .and_then(|()| fs::fsync(&self.file).map_err(io::Error::from))
            .and_then(|()| after(CommitStage::FileSynced))
            .and_then(|()| self.rename().map_err(io::Error::from))
            .and_then(|()| after(CommitStage::Renamed))
            .and_then(|()| fs::fsync(self.directory).map_err(io::Error::from))
            .and_then(|()| after(CommitStage::DirectorySynced))
    }

    fn rename(&self) -> rustix::io::Result<()> {
        validate_file_identity(self.directory, self.temporary, &self.file).and_then(|()| {
            self.previous.as_ref().map_or_else(
                || {
                    fs::renameat_with(
                        self.directory,
                        self.temporary,
                        self.directory,
                        self.target,
                        RenameFlags::NOREPLACE,
                    )
                },
                |previous| {
                    validate_file_identity(self.directory, self.target, previous).and_then(|()| {
                        fs::renameat(self.directory, self.temporary, self.directory, self.target)
                    })
                },
            )
        })
    }
}

impl Drop for StagedFile<'_> {
    fn drop(&mut self) {
        // A renamed or substituted slot must not be unlinked by this owner.
        let _cleanup = validate_file_identity(self.directory, self.temporary, &self.file)
            .and_then(|()| fs::unlinkat(self.directory, self.temporary, AtFlags::empty()));
    }
}
