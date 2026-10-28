//! Planned ownership extended with the exact, still-unmounted directory tree.

use rustix::fs::mkdirat;

mod removal;

use super::{
    open_directory, publish_record, read_record_bytes, registry_io, require_empty,
    validate_directory, verify_intent, Arc, CommittedPlannedAttempt, File, MetadataExt, Mode,
    PlannedAttemptIntent, RenameFlags, ResolveFlags, SystemdAttemptRegistryError,
};

const DIRECTORY_RECORD_SIZE: usize = 84;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
}

impl DirectoryIdentity {
    fn read(file: &File) -> Result<Self, SystemdAttemptRegistryError> {
        let metadata = registry_io(|| file.metadata())?;
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
}

/// A durably recorded pair of private, unmounted attempt/root directories.
///
/// This owns the held descriptors and registry lock. It grants no mount or
/// execution authority; current image/control admission is still required.
/// Dropping it leaves the intent and directories for identity-safe recovery.
#[derive(Debug)]
pub struct PreparedAttemptDirectory {
    planned: CommittedPlannedAttempt,
    attempts: File,
    attempt: File,
    root: File,
    identities: [DirectoryIdentity; 2],
}

impl CommittedPlannedAttempt {
    /// Create the unique attempt/root tree and durably extend its planned intent.
    ///
    /// The fixed `attempts` parent must already exist with private permissions.
    /// Each new directory's parent is fsynced before the identity extension is
    /// published. Existing components are never adopted or replaced.
    ///
    /// # Errors
    /// Rejects changed intent, unsafe parents, existing components and uncertain
    /// writes. Any failure closes new commits and leaves owned state for recovery.
    pub fn prepare_directory(
        self,
    ) -> Result<PreparedAttemptDirectory, SystemdAttemptRegistryError> {
        let owner = Arc::clone(&self.state);
        let mut state = owner
            .lock()
            .map_err(|_| SystemdAttemptRegistryError::ReconciliationRequired)?;
        if state.failed {
            return Err(SystemdAttemptRegistryError::ReconciliationRequired);
        }
        let result = state
            .next_sequence
            .checked_add(1)
            .ok_or(SystemdAttemptRegistryError::ReconciliationRequired)
            .and_then(|sequence| {
                state.next_sequence = sequence;
                self.create_directory(sequence)
            });
        state.failed = result.is_err();
        result
    }

    fn create_directory(
        self,
        sequence: u64,
    ) -> Result<PreparedAttemptDirectory, SystemdAttemptRegistryError> {
        verify_intent(&self.directory, &self.intent)?;
        validate_directory(&self.directory.runtime, self.directory.owner, true)?;
        let attempts = open_directory(&self.directory.runtime, "attempts", ResolveFlags::NO_XDEV)?;
        validate_directory(&attempts, self.directory.owner, true)?;
        let attempt = create_private_directory(
            &attempts,
            self.intent.unit_name.attempt_component(),
            self.directory.owner,
        )?;
        let root = create_private_directory(&attempt, "root", self.directory.owner)?;
        let identities = [
            DirectoryIdentity::read(&attempt)?,
            DirectoryIdentity::read(&root)?,
        ];
        let prepared = PreparedAttemptDirectory {
            planned: self,
            attempts,
            attempt,
            root,
            identities,
        };
        prepared.verify_tree()?;
        verify_intent(&prepared.planned.directory, &prepared.planned.intent)?;
        publish_record(
            &prepared.planned.directory,
            &prepared.planned.intent,
            sequence,
            &prepared.record_bytes(),
            RenameFlags::empty(),
        )?;
        prepared.verify_record_and_tree()?;
        Ok(prepared)
    }
}

impl PreparedAttemptDirectory {
    /// The exact original planned ownership, preserved by the extension.
    #[must_use]
    pub const fn intent(&self) -> &PlannedAttemptIntent {
        &self.planned.intent
    }

    /// The held attempt directory and its root directory, for attaching the
    /// quarantined root mount by descriptor.
    pub(crate) const fn held_directories(&self) -> (&File, &File) {
        (&self.attempt, &self.root)
    }

    /// Verify the durable identity extension and the same unmounted directory tree.
    ///
    /// # Errors
    /// Rejects changed records, path substitutions, mounts, nonempty root or
    /// unsafe permissions. A contradiction closes further registry commits.
    pub fn verify_directory(&self) -> Result<(), SystemdAttemptRegistryError> {
        let mut state = self
            .planned
            .state
            .lock()
            .map_err(|_| SystemdAttemptRegistryError::ReconciliationRequired)?;
        let result = self.verify_record_and_tree();
        state.failed |= result.is_err();
        result
    }

    /// Hold registry ownership while verifying the recorded attempt's ancestors
    /// and performing an attached-root operation. The operation must verify the
    /// mount separately: opening `root` with NO_XDEV would reject an attachment.
    /// Cleanup may run after quarantine, but cannot clear it.
    pub(crate) fn with_verified_parent<E>(
        &self,
        rejected: E,
        operation: impl FnOnce() -> Result<(), E>,
    ) -> Result<(), E> {
        let Ok(mut state) = self.planned.state.lock() else {
            return Err(rejected);
        };
        let result = self
            .verify_record()
            .and_then(|()| self.verify_attempt().map(|_| ()))
            .map_err(|_| rejected)
            .and_then(|()| operation());
        state.failed |= result.is_err();
        result
    }

    fn record_bytes(&self) -> [u8; DIRECTORY_RECORD_SIZE] {
        let mut bytes = [0; DIRECTORY_RECORD_SIZE];
        bytes[..52].copy_from_slice(&self.planned.intent.encode());
        // PAI2 is the closed directory stage of this private registry format.
        bytes[..4].copy_from_slice(b"PAI2");
        for (slot, value) in bytes[52..].chunks_exact_mut(8).zip([
            self.identities[0].device,
            self.identities[0].inode,
            self.identities[1].device,
            self.identities[1].inode,
        ]) {
            slot.copy_from_slice(&value.to_le_bytes());
        }
        bytes
    }

    fn verify_record_and_tree(&self) -> Result<(), SystemdAttemptRegistryError> {
        self.verify_record().and_then(|()| self.verify_tree())
    }

    fn verify_record(&self) -> Result<(), SystemdAttemptRegistryError> {
        let observed = read_record_bytes::<DIRECTORY_RECORD_SIZE>(
            &self.planned.directory,
            &self.planned.intent.unit_name,
        )?;
        if observed != self.record_bytes() {
            return Err(SystemdAttemptRegistryError::InvalidIntent);
        }
        Ok(())
    }

    fn verify_tree(&self) -> Result<(), SystemdAttemptRegistryError> {
        let attempt = self.verify_attempt()?;
        let root = open_directory(&attempt, "root", ResolveFlags::NO_XDEV)?;
        validate_directory(&root, self.planned.directory.owner, true)?;
        if DirectoryIdentity::read(&root)? != DirectoryIdentity::read(&self.root)? {
            return Err(SystemdAttemptRegistryError::UnsafeRegistry);
        }
        require_empty(&root)
    }

    fn verify_attempt(&self) -> Result<File, SystemdAttemptRegistryError> {
        let directory = &self.planned.directory;
        validate_directory(&directory.runtime, directory.owner, true)?;
        let attempts = open_directory(&directory.runtime, "attempts", ResolveFlags::NO_XDEV)?;
        validate_directory(&attempts, directory.owner, true)?;
        if DirectoryIdentity::read(&attempts)? != DirectoryIdentity::read(&self.attempts)? {
            return Err(SystemdAttemptRegistryError::UnsafeRegistry);
        }
        let attempt = open_directory(
            &attempts,
            self.planned.intent.unit_name.attempt_component(),
            ResolveFlags::NO_XDEV,
        )?;
        validate_directory(&attempt, directory.owner, true)?;
        if DirectoryIdentity::read(&attempt)? != DirectoryIdentity::read(&self.attempt)? {
            return Err(SystemdAttemptRegistryError::UnsafeRegistry);
        }
        Ok(attempt)
    }
}

fn create_private_directory(
    parent: &File,
    component: &str,
    owner: u32,
) -> Result<File, SystemdAttemptRegistryError> {
    registry_io(|| mkdirat(parent, component, Mode::RWXU).map_err(std::io::Error::from))?;
    registry_io(|| parent.sync_all())?;
    let directory = open_directory(parent, component, ResolveFlags::NO_XDEV)?;
    validate_directory(&directory, owner, true)?;
    require_empty(&directory)?;
    Ok(directory)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::super::tests::{in_lock_test_process, with_io_fault};
    use super::*;
    use crate::SystemdAttemptRegistry;
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    pub(super) fn fixture() -> TestResult<(tempfile::TempDir, SystemdAttemptRegistry)> {
        let (directory, runtime, owner) = super::super::tests::fixture()?;
        fs::create_dir(directory.path().join("attempts"))?;
        fs::set_permissions(
            directory.path().join("attempts"),
            fs::Permissions::from_mode(0o700),
        )?;
        let registry = SystemdAttemptRegistry::from_runtime_directory(&runtime, owner)?;
        Ok((directory, registry))
    }

    pub(super) fn intent(id: u8) -> TestResult<PlannedAttemptIntent> {
        Ok(PlannedAttemptIntent::new([id; 16], [2; 32])?)
    }

    #[test]
    fn prepare_io_boundary_failures_close_owner_and_preserve_recovery_state() -> TestResult {
        if !in_lock_test_process("attempt_registry::directory::tests::prepare_io_boundary_failures_close_owner_and_preserve_recovery_state")? {
            return Ok(());
        }
        let planned = intent(1)?;
        let operation_count = {
            let (_directory, registry) = fixture()?;
            let committed = registry.commit_planned(&planned)?;
            let (result, count) = with_io_fault(None, || committed.prepare_directory());
            result?;
            count
        };
        assert!(operation_count > 0);
        let mut observed_extended = false;
        for fail_at in 0..operation_count {
            let (directory, registry) = fixture()?;
            let committed = registry.commit_planned(&planned)?;
            let (result, observed) = with_io_fault(Some(fail_at), || committed.prepare_directory());
            assert!(matches!(result, Err(SystemdAttemptRegistryError::Io(_))));
            assert_eq!(observed, fail_at + 1);
            assert!(matches!(
                registry.commit_planned(&intent(2)?),
                Err(SystemdAttemptRegistryError::ReconciliationRequired)
            ));
            let key = planned.unit_name().attempt_component();
            let record_path = directory.path().join("registry").join(key);
            let record = fs::read(&record_path)?;
            let attempt = directory.path().join("attempts").join(key);
            let root = attempt.join("root");
            let existed = [attempt.exists(), root.exists()];
            if record.len() == DIRECTORY_RECORD_SIZE {
                observed_extended = true;
                let mut expected = b"PAI2".to_vec();
                expected.extend_from_slice(&[1; 16]);
                expected.extend_from_slice(&[2; 32]);
                for path in [&attempt, &root] {
                    let metadata = fs::metadata(path)?;
                    expected.extend_from_slice(&metadata.dev().to_le_bytes());
                    expected.extend_from_slice(&metadata.ino().to_le_bytes());
                }
                assert_eq!(record, expected);
            } else {
                assert_eq!(record, planned.encode());
            }
            let records = fs::read_dir(directory.path().join("registry"))?.count();
            assert!((1..=2).contains(&records));
            drop(registry);
            assert_eq!(fs::read(record_path)?, record);
            assert_eq!([attempt.exists(), root.exists()], existed);
            assert_eq!(
                fs::read_dir(directory.path().join("registry"))?.count(),
                records
            );
            let parent = File::open(directory.path())?;
            let reopened =
                SystemdAttemptRegistry::from_runtime_directory(&parent, parent.metadata()?.uid());
            assert!(
                matches!(
                    reopened,
                    Err(SystemdAttemptRegistryError::ReconciliationRequired)
                ),
                "reopen after injected prepare I/O failure {fail_at}: {reopened:?}"
            );
        }
        assert!(observed_extended);
        Ok(())
    }

    #[test]
    fn directory_readback_io_boundary_failures_close_owner() -> TestResult {
        let operation_count = {
            let (_directory, registry) = fixture()?;
            let prepared = registry.commit_planned(&intent(1)?)?.prepare_directory()?;
            let (result, count) = with_io_fault(None, || prepared.verify_directory());
            result?;
            count
        };
        assert!(operation_count > 0);
        for fail_at in 0..operation_count {
            let (directory, registry) = fixture()?;
            let planned = intent(1)?;
            let prepared = registry.commit_planned(&planned)?.prepare_directory()?;
            let path = directory
                .path()
                .join("registry")
                .join(planned.unit_name().attempt_component());
            let before = fs::read(&path)?;
            let (result, observed) = with_io_fault(Some(fail_at), || prepared.verify_directory());
            assert!(matches!(result, Err(SystemdAttemptRegistryError::Io(_))));
            assert_eq!(observed, fail_at + 1);
            assert!(matches!(
                registry.commit_planned(&intent(2)?),
                Err(SystemdAttemptRegistryError::ReconciliationRequired)
            ));
            assert_eq!(fs::read(path)?, before);
            assert!(directory
                .path()
                .join("attempts")
                .join(planned.unit_name().attempt_component())
                .join("root")
                .is_dir());
        }
        Ok(())
    }

    #[test]
    fn fixed_public_factory_prepares_and_retains_directory_ownership() -> TestResult {
        if std::env::var_os("PIGLOROS_PRIVILEGED_COMPOSITION_TEST").is_none() {
            let runner = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../scripts/run-isolated-test.sh");
            let output = std::process::Command::new(runner).arg(std::env::current_exe()?)
                .arg("attempt_registry::directory::tests::fixed_public_factory_prepares_and_retains_directory_ownership")
                .output()?;
            assert!(
                output.status.success(),
                "isolated directory test failed: {:?}\n{}\n{}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return Ok(());
        }
        assert!(!std::path::Path::new("/run/pigloros").exists());
        for path in [
            "/run/pigloros",
            "/run/pigloros/sandbox",
            "/run/pigloros/sandbox/registry",
            "/run/pigloros/sandbox/attempts",
        ] {
            fs::create_dir(path)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
        let registry = SystemdAttemptRegistry::open()?;
        let prepared = registry.commit_planned(&intent(1)?)?.prepare_directory()?;
        assert_eq!(prepared.intent(), &intent(1)?);
        prepared.verify_directory()?;
        drop(registry);
        assert!(SystemdAttemptRegistry::open().is_err());
        prepared.verify_directory()?;
        drop(prepared);
        assert!(matches!(
            SystemdAttemptRegistry::open(),
            Err(SystemdAttemptRegistryError::ReconciliationRequired)
        ));
        Ok(())
    }

    #[test]
    fn eight_attempts_publish_exact_extended_directory_identities() -> TestResult {
        let (directory, registry) = fixture()?;
        for id in 1..=8 {
            let intent = intent(id)?;
            let key = intent.unit_name().attempt_component();
            let record = directory.path().join("registry").join(key);
            let path = directory.path().join("attempts").join(key);
            let committed = registry.commit_planned(&intent)?;
            assert!(!path.exists());
            assert_eq!(fs::read(&record)?.len(), 52);
            let prepared = committed.prepare_directory()?;
            prepared.verify_directory()?;
            let bytes = fs::read(record)?;
            let mut expected = b"PAI2".to_vec();
            expected.extend_from_slice(&[id; 16]);
            expected.extend_from_slice(&[2; 32]);
            for path in [&path, &path.join("root")] {
                let metadata = fs::metadata(path)?;
                assert_eq!(metadata.mode() & 0o7777, 0o700);
                expected.extend_from_slice(&metadata.dev().to_le_bytes());
                expected.extend_from_slice(&metadata.ino().to_le_bytes());
            }
            assert_eq!(bytes, expected);
            assert_eq!(fs::read_dir(path.join("root"))?.count(), 0);
        }
        assert_eq!(fs::read_dir(directory.path().join("registry"))?.count(), 8);
        assert_eq!(fs::read_dir(directory.path().join("attempts"))?.count(), 8);
        Ok(())
    }

    #[test]
    fn preexisting_directory_or_symlink_is_never_adopted() -> TestResult {
        for link in [false, true] {
            let (directory, registry) = fixture()?;
            let planned = intent(1)?;
            let component = planned.unit_name().attempt_component();
            let path = directory.path().join("attempts").join(component);
            let committed = registry.commit_planned(&planned)?;
            if link {
                symlink(directory.path(), &path)?;
            } else {
                fs::create_dir(&path)?;
            }
            let before = fs::read(directory.path().join("registry").join(component))?;
            assert!(committed.prepare_directory().is_err());
            assert_eq!(
                fs::read(directory.path().join("registry").join(component))?,
                before
            );
            assert!(!path.join("root").exists());
            assert!(registry.commit_planned(&intent(2)?).is_err());
        }
        Ok(())
    }

    #[test]
    fn invalid_planned_record_or_runtime_parent_prevents_creation() -> TestResult {
        for fault in 0..4 {
            let (directory, registry) = fixture()?;
            let planned = intent(1)?;
            let key = planned.unit_name().attempt_component();
            let committed = registry.commit_planned(&planned)?;
            match fault {
                0 => fs::write(directory.path().join("registry").join(key), b"changed")?,
                1 => fs::remove_dir(directory.path().join("attempts"))?,
                2 => fs::set_permissions(
                    directory.path().join("attempts"),
                    fs::Permissions::from_mode(0o777),
                )?,
                _ => fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o777))?,
            }
            assert!(committed.prepare_directory().is_err());
            assert!(!directory.path().join("attempts").join(key).exists());
            assert!(registry.commit_planned(&intent(2)?).is_err());
        }
        Ok(())
    }

    #[test]
    fn contradictory_record_or_directory_closes_further_commits() -> TestResult {
        for fault in 0..6 {
            let (directory, registry) = fixture()?;
            let planned = intent(1)?;
            let key = planned.unit_name().attempt_component();
            let prepared = registry.commit_planned(&planned)?.prepare_directory()?;
            let attempts = directory.path().join("attempts");
            let attempt = attempts.join(key);
            let root = attempt.join("root");
            match fault {
                0 => {
                    let path = directory.path().join("registry").join(key);
                    let mut bytes = fs::read(&path)?;
                    bytes[52] ^= 1;
                    fs::write(path, bytes)?;
                }
                1 => fs::write(root.join("unexpected"), b"not empty")?,
                2 => fs::set_permissions(&root, fs::Permissions::from_mode(0o755))?,
                3 => {
                    fs::rename(&root, attempt.join("held"))?;
                    fs::create_dir(&root)?;
                    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
                }
                4 => {
                    fs::rename(&attempt, attempts.join("held"))?;
                    fs::create_dir(&attempt)?;
                    fs::set_permissions(&attempt, fs::Permissions::from_mode(0o700))?;
                    fs::create_dir(&root)?;
                    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
                }
                _ => {
                    fs::rename(&attempts, directory.path().join("held"))?;
                    fs::create_dir(&attempts)?;
                    fs::set_permissions(&attempts, fs::Permissions::from_mode(0o700))?;
                }
            }
            assert!(prepared.verify_directory().is_err());
            assert!(registry.commit_planned(&intent(2)?).is_err());
        }
        Ok(())
    }

    #[test]
    fn failed_exhausted_and_poisoned_owners_cannot_prepare() -> TestResult {
        for fault in 0..3 {
            let (_directory, registry) = fixture()?;
            let planned = registry.commit_planned(&intent(1)?)?;
            match fault {
                0 => {
                    registry
                        .state
                        .lock()
                        .map_err(|_| "poisoned fixture")?
                        .failed = true;
                }
                1 => {
                    registry
                        .state
                        .lock()
                        .map_err(|_| "poisoned fixture")?
                        .next_sequence = u64::MAX;
                }
                _ => assert!(std::panic::catch_unwind(|| {
                    let _guard = registry.state.lock();
                    std::panic::resume_unwind(Box::new(()));
                })
                .is_err()),
            }
            assert!(planned.prepare_directory().is_err());
        }
        let (_directory, registry) = fixture()?;
        let prepared = registry.commit_planned(&intent(1)?)?.prepare_directory()?;
        assert!(std::panic::catch_unwind(|| {
            let _guard = registry.state.lock();
            std::panic::resume_unwind(Box::new(()));
        })
        .is_err());
        assert!(prepared.verify_directory().is_err());
        let invoked = std::cell::Cell::new(false);
        assert!(prepared
            .with_verified_parent(SystemdAttemptRegistryError::ReconciliationRequired, || {
                invoked.set(true);
                Ok(())
            })
            .is_err());
        assert!(!invoked.get());
        Ok(())
    }

    #[test]
    fn every_attached_parent_io_failure_prevents_the_operation_and_closes_commits() -> TestResult {
        if !in_lock_test_process("attempt_registry::directory::tests::every_attached_parent_io_failure_prevents_the_operation_and_closes_commits")? {
            return Ok(());
        }
        let operation_count = {
            let (_directory, registry) = fixture()?;
            let prepared = registry.commit_planned(&intent(1)?)?.prepare_directory()?;
            let (result, count) = with_io_fault(None, || {
                prepared
                    .with_verified_parent(SystemdAttemptRegistryError::UnsafeRegistry, || Ok(()))
            });
            result?;
            count
        };
        for fail_at in 0..operation_count {
            let (directory, registry) = fixture()?;
            let prepared = registry.commit_planned(&intent(1)?)?.prepare_directory()?;
            let record = directory
                .path()
                .join("registry")
                .join(prepared.intent().unit_name().attempt_component());
            let bytes = fs::read(&record)?;
            let invoked = std::cell::Cell::new(false);
            let (result, count) = with_io_fault(Some(fail_at), || {
                prepared.with_verified_parent(SystemdAttemptRegistryError::UnsafeRegistry, || {
                    invoked.set(true);
                    Ok(())
                })
            });
            assert!(result.is_err(), "boundary {fail_at}");
            assert_eq!(count, fail_at + 1);
            assert!(!invoked.get());
            assert_eq!(fs::read(record)?, bytes);
            assert!(registry.commit_planned(&intent(2)?).is_err());
        }
        Ok(())
    }
}
