#![cfg(any(test, feature = "test-support"))]
//! Deletion interruption points, the pre-unlink identity recheck and the
//! confirmed absence.

use std::fs;
use std::io;
use std::path::PathBuf;

use super::super::{SubjectKeyArtifactKind, DIRECTORY_NAME};
use super::{DeletionStage, SubjectEncryptorLock, SubjectKeyArtifactName};
use crate::encryptor_lock_test_support::{write_private, Sandbox};
use crate::{BridgeError, UnavailableCode};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const UNAVAILABLE: BridgeError = BridgeError::Unavailable(UnavailableCode::InterfaceUnavailable);
const OWNER: &str = "subject:0123456789abcdef0123456789abcdef";
const STAGES: [DeletionStage; 3] = [
    DeletionStage::Checked,
    DeletionStage::Unlinked,
    DeletionStage::DirectorySynced,
];

/// A held lock with an admitted, empty `subject-keys.v1`, and its path.
fn admitted() -> Result<(Sandbox, SubjectEncryptorLock, PathBuf), Box<dyn std::error::Error>> {
    let root = Sandbox::new()?;
    let lock = SubjectEncryptorLock::acquire(&root.0)?;
    lock.admit_artifact_directory()?;
    let directory = root.0.join("pigloros").join(DIRECTORY_NAME);
    Ok((root, lock, directory))
}

fn wrap() -> Result<SubjectKeyArtifactName, &'static str> {
    SubjectKeyArtifactName::new(SubjectKeyArtifactKind::Wrap, OWNER, 4)
        .ok_or("valid fixture name refused")
}

fn fail_at(stop: DeletionStage) -> impl FnMut(DeletionStage) -> io::Result<()> {
    move |stage| {
        if stage == stop {
            Err(io::ErrorKind::Other.into())
        } else {
            Ok(())
        }
    }
}

#[test]
fn every_interruption_leaves_a_state_that_a_repeated_deletion_completes() -> TestResult {
    let (_root, lock, directory) = admitted()?;
    let owner = lock.try_lock_subject_owner_exclusive(OWNER)?;
    let name = wrap()?;
    let (canonical, temporary) = (
        directory.join(name.canonical()),
        directory.join(name.temporary()),
    );
    write_private(&canonical, b"wrap")?;
    write_private(&temporary, b"torn wrap")?;
    let mut observed = Vec::new();
    lock.delete_observing(&owner, &name, |stage| {
        observed.push(stage);
        Ok(())
    })?;
    assert_eq!(observed, STAGES);
    for stop in STAGES {
        write_private(&canonical, b"wrap")?;
        write_private(&temporary, b"torn wrap")?;
        assert_eq!(
            lock.delete_observing(&owner, &name, fail_at(stop)),
            Err(UNAVAILABLE)
        );
        // Every check precedes the first unlink.
        let untouched = stop == DeletionStage::Checked;
        assert_eq!(canonical.exists(), untouched, "{stop:?}");
        assert_eq!(temporary.exists(), untouched, "{stop:?}");
        lock.delete_subject_key_artifact(&owner, &name)?;
        assert!(!canonical.exists() && !temporary.exists());
    }
    Ok(())
}

#[test]
fn a_file_substituted_after_the_checks_is_never_unlinked() -> TestResult {
    let (_root, lock, directory) = admitted()?;
    let owner = lock.try_lock_subject_owner_exclusive(OWNER)?;
    let name = wrap()?;
    let canonical = directory.join(name.canonical());
    let moved = directory.join("moved");
    write_private(&canonical, b"checked")?;
    let result = lock.delete_observing(&owner, &name, |stage| {
        if stage == DeletionStage::Checked {
            fs::rename(&canonical, &moved)?;
            write_private(&canonical, b"substituted")?;
        }
        Ok(())
    });
    assert_eq!(result, Err(UNAVAILABLE));
    assert_eq!(fs::read(&canonical)?, b"substituted");
    assert_eq!(fs::read(&moved)?, b"checked");
    Ok(())
}

#[test]
fn a_name_present_after_the_directory_sync_is_not_confirmed_absent() -> TestResult {
    let (_root, lock, directory) = admitted()?;
    let owner = lock.try_lock_subject_owner_exclusive(OWNER)?;
    let name = wrap()?;
    for reappearing in [name.canonical(), name.temporary()] {
        let path = directory.join(&reappearing);
        let result = lock.delete_observing(&owner, &name, |stage| {
            if stage == DeletionStage::DirectorySynced {
                write_private(&path, b"reappeared")?;
            }
            Ok(())
        });
        assert_eq!(result, Err(UNAVAILABLE), "{reappearing}");
        assert_eq!(fs::read(&path)?, b"reappeared");
        fs::remove_file(&path)?;
    }
    Ok(())
}
