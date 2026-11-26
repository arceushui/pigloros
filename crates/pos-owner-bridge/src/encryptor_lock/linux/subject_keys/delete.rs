#![cfg(any(test, feature = "test-support"))]
//! ADR-137 P5 durable deletion of one reserved `subject-keys.v1` artifact.

use std::io;

use rustix::fd::OwnedFd;
use rustix::fs::{self, AtFlags, Mode};
use rustix::io::Errno;

use super::super::{
    enforce, lock_file, validate_file_identity, SubjectOwnerExclusiveGuard, FILE_FLAGS,
};
use super::{SubjectEncryptorLock, SubjectKeyArtifactName};
use crate::{BridgeError, UnavailableCode};

/// The points after which a test may interrupt a deletion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DeletionStage {
    /// Both names were checked; nothing is unlinked yet.
    Checked,
    /// Every present name was unlinked and its file synchronized.
    Unlinked,
    /// The directory was synchronized.
    DirectorySynced,
}

impl SubjectEncryptorLock {
    /// Durably delete one reserved wrap or binding under both its canonical
    /// and its `.tmp` name, as ADR-137 P5 deletes an orphan of this store.
    ///
    /// `owner` must be this lock's exclusive session/inventory lock of the
    /// name's owner. The directory is admitted as staging admits it. Before
    /// anything is unlinked, each name must be absent or name a singly linked
    /// regular file owned by the effective UID with mode exactly 0600 that no
    /// other holder locks. Each such file is locked and its path identity is
    /// rechecked just before its unlink. The #206 durable deletion follows:
    /// unlink, file sync, directory sync, then a no-follow lookup must report
    /// both names absent. A name that is absent from the start counts as
    /// deleted, so a repeated call succeeds; the directory is still
    /// synchronized.
    ///
    /// The bytes are neither read nor parsed. The caller decides that P5
    /// applies: the staging record names this store, the identity is absent
    /// from the bound store's registry, and no SNL1 row for it names another
    /// store. This records no #206 receipt; ADR-137 D1 receipts belong to
    /// destruction.
    ///
    /// # Errors
    /// Returns `Unavailable(InterfaceUnavailable)` for a guard of another lock
    /// or owner, an unsafe directory, an entry at either name that is not such
    /// a file, contention, a name present after the directory sync, or any
    /// I/O failure. A refusal before the first unlink leaves both names
    /// untouched. An error after it leaves an unconfirmed outcome that a
    /// repeated call completes.
    pub fn delete_subject_key_artifact(
        &self,
        owner: &SubjectOwnerExclusiveGuard<'_>,
        name: &SubjectKeyArtifactName,
    ) -> Result<(), BridgeError> {
        self.delete_observing(owner, name, |_| Ok(()))
    }

    fn delete_observing(
        &self,
        owner: &SubjectOwnerExclusiveGuard<'_>,
        name: &SubjectKeyArtifactName,
        mut after: impl FnMut(DeletionStage) -> io::Result<()>,
    ) -> Result<(), BridgeError> {
        let names = [name.canonical(), name.temporary()];
        enforce(owner.holds(self, &name.owner_id()))
            .and_then(|()| self.admit_artifact_directory())
            .and_then(|directory| {
                names
                    .iter()
                    .map(|slot| open_present(&directory, slot))
                    .collect::<rustix::io::Result<Vec<_>>>()
                    .map(|opened| (directory, opened))
            })
            .map_err(io::Error::from)
            .and_then(|(directory, opened)| {
                after(DeletionStage::Checked)
                    .and_then(|()| {
                        names
                            .iter()
                            .zip(&opened)
                            .try_for_each(|(slot, file)| {
                                file.as_ref()
                                    .map_or(Ok(()), |file| unlink(&directory, slot, file))
                            })
                            .map_err(io::Error::from)
                    })
                    .and_then(|()| after(DeletionStage::Unlinked))
                    .and_then(|()| fs::fsync(&directory).map_err(io::Error::from))
                    .and_then(|()| after(DeletionStage::DirectorySynced))
                    .and_then(|()| {
                        names
                            .iter()
                            .try_for_each(|slot| confirm_absent(&directory, slot))
                            .map_err(io::Error::from)
                    })
            })
            .map_err(|_| BridgeError::Unavailable(UnavailableCode::InterfaceUnavailable))
    }
}

/// Open and lock the file at `name`, or `None` when no entry has that name.
fn open_present(directory: &OwnedFd, name: &str) -> rustix::io::Result<Option<OwnedFd>> {
    match fs::openat(directory, name, FILE_FLAGS, Mode::empty()) {
        Ok(file) => lock_file(directory, name, &file).map(|()| Some(file)),
        Err(error) if error == Errno::NOENT => Ok(None),
        Err(error) => Err(error),
    }
}

/// Unlink `name` only while it still names the locked `file`, then sync it.
fn unlink(directory: &OwnedFd, name: &str, file: &OwnedFd) -> rustix::io::Result<()> {
    validate_file_identity(directory, name, file)
        .and_then(|()| fs::unlinkat(directory, name, AtFlags::empty()))
        .and_then(|()| fs::fsync(file))
}

/// The #206 confirmed absence: the no-follow lookup reports `ENOENT`.
fn confirm_absent(directory: &OwnedFd, name: &str) -> rustix::io::Result<()> {
    enforce(fs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW).err() == Some(Errno::NOENT))
}

#[cfg(test)]
mod tests;
